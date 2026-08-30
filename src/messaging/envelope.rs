//! Strict, bounded domain records for durable inter-agent messaging.
//!
//! Authentication credentials are intentionally absent from every type in
//! this module. The broker resolves `sender_role` from the hierarchy ledger
//! before constructing an envelope; replay only restores that effective role.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::Value;
use thiserror::Error;

use crate::hierarchy_ledger::RoleCategory;

pub const MESSAGE_ENVELOPE_VERSION: u32 = 1;
pub const GOVERNED_CHANNEL_VERSION: u32 = 1;
const MAX_MESSAGE_ID_BYTES: usize = 256;
// These private structural ceilings keep hostile in-memory `Value` trees
// finite without changing the persisted/public `MessagingLimits` shape.
const MAX_PAYLOAD_NESTING_DEPTH: usize = 128;
const MAX_PAYLOAD_NODES_HARD_LIMIT: usize = 65_536;
const MAX_PAYLOAD_STRINGS_HARD_LIMIT: usize = 65_536;

/// Explicit resource ceilings for the messaging broker and its durable store.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessagingLimits {
    pub max_credentials: usize,
    pub max_messages: usize,
    pub max_channels: usize,
    pub max_members_per_channel: usize,
    pub max_publishers_per_channel: usize,
    pub max_payload_bytes: usize,
    pub max_identifier_bytes: usize,
    pub max_journal_records: usize,
    pub max_journal_bytes: usize,
    pub max_delivery_attempts: usize,
}

impl Default for MessagingLimits {
    fn default() -> Self {
        Self {
            max_credentials: 4_096,
            max_messages: 100_000,
            max_channels: 1_024,
            max_members_per_channel: 1_024,
            max_publishers_per_channel: 256,
            max_payload_bytes: 1024 * 1024,
            max_identifier_bytes: 256,
            max_journal_records: 1_000_000,
            max_journal_bytes: 256 * 1024 * 1024,
            max_delivery_attempts: 1_024,
        }
    }
}

impl MessagingLimits {
    pub fn validate(&self) -> Result<(), EnvelopeValidationError> {
        for (field, value) in [
            ("max_credentials", self.max_credentials),
            ("max_messages", self.max_messages),
            ("max_channels", self.max_channels),
            ("max_members_per_channel", self.max_members_per_channel),
            (
                "max_publishers_per_channel",
                self.max_publishers_per_channel,
            ),
            ("max_payload_bytes", self.max_payload_bytes),
            ("max_identifier_bytes", self.max_identifier_bytes),
            ("max_journal_records", self.max_journal_records),
            ("max_journal_bytes", self.max_journal_bytes),
            ("max_delivery_attempts", self.max_delivery_attempts),
        ] {
            if value == 0 {
                return Err(EnvelopeValidationError::ZeroLimit { field });
            }
        }
        if self.max_publishers_per_channel > self.max_members_per_channel {
            return Err(EnvelopeValidationError::InvalidLimit {
                reason: "max_publishers_per_channel exceeds max_members_per_channel",
            });
        }
        if self.max_members_per_channel > self.max_credentials {
            return Err(EnvelopeValidationError::InvalidLimit {
                reason: "max_members_per_channel exceeds max_credentials",
            });
        }
        if u32::try_from(self.max_delivery_attempts).is_err() {
            return Err(EnvelopeValidationError::InvalidLimit {
                reason: "max_delivery_attempts exceeds the persisted u32 counter",
            });
        }

        let identifier_slots = self
            .max_members_per_channel
            .checked_add(3)
            .ok_or(EnvelopeValidationError::LimitArithmeticOverflow)?;
        let identifier_bytes = self
            .max_identifier_bytes
            .checked_mul(identifier_slots)
            .ok_or(EnvelopeValidationError::LimitArithmeticOverflow)?;
        let largest_record_bytes = self
            .max_payload_bytes
            .checked_add(identifier_bytes)
            .ok_or(EnvelopeValidationError::LimitArithmeticOverflow)?;
        if largest_record_bytes > self.max_journal_bytes {
            return Err(EnvelopeValidationError::InvalidLimit {
                reason: "max_journal_bytes cannot contain one maximally bounded envelope",
            });
        }
        Ok(())
    }
}

/// Stable caller- or broker-generated identifier for one logical message.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MessageId(String);

impl MessageId {
    pub fn new(value: impl Into<String>) -> Result<Self, EnvelopeValidationError> {
        let value = value.into();
        let limits = MessagingLimits {
            max_identifier_bytes: MAX_MESSAGE_ID_BYTES,
            ..MessagingLimits::default()
        };
        Self::new_with_limits(value, &limits)
    }

    pub fn new_with_limits(
        value: impl Into<String>,
        limits: &MessagingLimits,
    ) -> Result<Self, EnvelopeValidationError> {
        let id = Self(value.into());
        id.validate(limits)?;
        Ok(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self, limits: &MessagingLimits) -> Result<(), EnvelopeValidationError> {
        limits.validate()?;
        validate_identifier("message_id", &self.0, limits)
    }
}

impl AsRef<str> for MessageId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Recipient routing is either one exact agent or one governed channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageAddress {
    Direct { recipient_id: String },
    Channel { channel_id: String },
}

impl MessageAddress {
    pub fn direct(
        recipient_id: impl Into<String>,
        limits: &MessagingLimits,
    ) -> Result<Self, EnvelopeValidationError> {
        let address = Self::Direct {
            recipient_id: recipient_id.into(),
        };
        address.validate(limits)?;
        Ok(address)
    }

    pub fn channel(
        channel_id: impl Into<String>,
        limits: &MessagingLimits,
    ) -> Result<Self, EnvelopeValidationError> {
        let address = Self::Channel {
            channel_id: channel_id.into(),
        };
        address.validate(limits)?;
        Ok(address)
    }

    pub fn identifier(&self) -> &str {
        match self {
            Self::Direct { recipient_id } => recipient_id,
            Self::Channel { channel_id } => channel_id,
        }
    }

    pub fn validate(&self, limits: &MessagingLimits) -> Result<(), EnvelopeValidationError> {
        limits.validate()?;
        match self {
            Self::Direct { recipient_id } => {
                validate_identifier("recipient_id", recipient_id, limits)
            }
            Self::Channel { channel_id } => validate_identifier("channel_id", channel_id, limits),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryGuarantee {
    AtLeastOnce,
}

/// Durable state for one intended recipient of one logical message.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientDeliveryState {
    pub delivery_attempts: u32,
    pub acknowledged: bool,
}

impl RecipientDeliveryState {
    pub const fn pending() -> Self {
        Self {
            delivery_attempts: 0,
            acknowledged: false,
        }
    }

    pub fn validate(&self, limits: &MessagingLimits) -> Result<(), EnvelopeValidationError> {
        limits.validate()?;
        if usize::try_from(self.delivery_attempts)
            .map_or(true, |attempts| attempts > limits.max_delivery_attempts)
        {
            return Err(EnvelopeValidationError::TooManyDeliveryAttempts {
                actual: self.delivery_attempts,
                max: limits.max_delivery_attempts,
            });
        }
        if self.acknowledged && self.delivery_attempts == 0 {
            return Err(EnvelopeValidationError::AcknowledgedWithoutDelivery);
        }
        Ok(())
    }

    /// Records one delivery. Acknowledged messages fail closed instead of
    /// becoming eligible for accidental redelivery.
    pub fn record_delivery_attempt(
        &mut self,
        limits: &MessagingLimits,
    ) -> Result<u32, EnvelopeValidationError> {
        self.validate(limits)?;
        if self.acknowledged {
            return Err(EnvelopeValidationError::AlreadyAcknowledged);
        }
        let next = self
            .delivery_attempts
            .checked_add(1)
            .ok_or(EnvelopeValidationError::DeliveryAttemptOverflow)?;
        if usize::try_from(next).map_or(true, |attempts| attempts > limits.max_delivery_attempts) {
            return Err(EnvelopeValidationError::TooManyDeliveryAttempts {
                actual: next,
                max: limits.max_delivery_attempts,
            });
        }
        self.delivery_attempts = next;
        Ok(next)
    }

    /// Returns `true` for the first acknowledgement and `false` for a safe,
    /// idempotent repeat.
    pub fn acknowledge(&mut self) -> Result<bool, EnvelopeValidationError> {
        if self.acknowledged {
            return Ok(false);
        }
        if self.delivery_attempts == 0 {
            return Err(EnvelopeValidationError::AcknowledgedWithoutDelivery);
        }
        self.acknowledged = true;
        Ok(true)
    }
}

/// Persisted immutable message data plus per-recipient delivery state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageEnvelope {
    pub version: u32,
    pub id: MessageId,
    pub address: MessageAddress,
    pub sender_id: String,
    pub sender_role: RoleCategory,
    pub sequence: u64,
    pub payload: Value,
    pub guarantee: DeliveryGuarantee,
    #[serde(deserialize_with = "deserialize_ordered_recipient_states")]
    pub recipients: BTreeMap<String, RecipientDeliveryState>,
}

impl MessageEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: MessageId,
        address: MessageAddress,
        sender_id: impl Into<String>,
        sender_role: RoleCategory,
        sequence: u64,
        payload: Value,
        recipient_ids: BTreeSet<String>,
        limits: &MessagingLimits,
    ) -> Result<Self, EnvelopeValidationError> {
        let recipients = recipient_ids
            .into_iter()
            .map(|recipient_id| (recipient_id, RecipientDeliveryState::pending()))
            .collect();
        let envelope = Self {
            version: MESSAGE_ENVELOPE_VERSION,
            id,
            address,
            sender_id: sender_id.into(),
            sender_role,
            sequence,
            payload,
            guarantee: DeliveryGuarantee::AtLeastOnce,
            recipients,
        };
        match envelope.validate(limits) {
            Ok(()) => Ok(envelope),
            Err(error) => {
                let Self { payload, .. } = envelope;
                drop_payload_iteratively(payload);
                Err(error)
            }
        }
    }

    pub fn validate(&self, limits: &MessagingLimits) -> Result<(), EnvelopeValidationError> {
        limits.validate()?;
        if self.version != MESSAGE_ENVELOPE_VERSION {
            return Err(EnvelopeValidationError::UnsupportedVersion {
                record: "message_envelope",
                actual: self.version,
                expected: MESSAGE_ENVELOPE_VERSION,
            });
        }
        self.id.validate(limits)?;
        self.address.validate(limits)?;
        validate_identifier("sender_id", &self.sender_id, limits)?;
        if self.sequence == 0 {
            return Err(EnvelopeValidationError::ZeroSequence);
        }
        if self.guarantee != DeliveryGuarantee::AtLeastOnce {
            return Err(EnvelopeValidationError::UnsupportedDeliveryGuarantee);
        }

        validate_payload(&self.payload, limits)?;
        if self.recipients.is_empty() {
            return Err(EnvelopeValidationError::EmptyRecipients);
        }
        if self.recipients.len() > limits.max_members_per_channel {
            return Err(EnvelopeValidationError::TooManyRecipients {
                actual: self.recipients.len(),
                max: limits.max_members_per_channel,
            });
        }
        for (recipient_id, state) in &self.recipients {
            validate_identifier("recipient_id", recipient_id, limits)?;
            state.validate(limits)?;
        }

        if let MessageAddress::Direct { recipient_id } = &self.address {
            if self.recipients.len() != 1 || !self.recipients.contains_key(recipient_id) {
                return Err(EnvelopeValidationError::DirectRecipientMismatch);
            }
        }
        Ok(())
    }

    /// Adds the channel policy checks that cannot be proven from an envelope
    /// in isolation. The exact member set is the durable fan-out contract.
    pub fn validate_for_channel(
        &self,
        channel: &GovernedChannel,
        limits: &MessagingLimits,
    ) -> Result<(), EnvelopeValidationError> {
        self.validate(limits)?;
        channel.validate(limits)?;
        match &self.address {
            MessageAddress::Channel { channel_id } if channel_id == &channel.channel_id => {}
            MessageAddress::Channel { .. } => {
                return Err(EnvelopeValidationError::ChannelAddressMismatch)
            }
            MessageAddress::Direct { .. } => {
                return Err(EnvelopeValidationError::ChannelAddressMismatch)
            }
        }
        if self.recipients.keys().ne(channel.members.iter()) {
            return Err(EnvelopeValidationError::ChannelRecipientMismatch);
        }
        if !channel.permits_publisher(&self.sender_id) {
            return Err(EnvelopeValidationError::ChannelPublisherNotPermitted {
                channel_id: channel.channel_id.clone(),
                sender_id: self.sender_id.clone(),
            });
        }
        Ok(())
    }

    pub fn recipient_state(&self, recipient_id: &str) -> Option<&RecipientDeliveryState> {
        self.recipients.get(recipient_id)
    }

    pub fn record_delivery_attempt(
        &mut self,
        recipient_id: &str,
        limits: &MessagingLimits,
    ) -> Result<u32, EnvelopeValidationError> {
        let state = self.recipients.get_mut(recipient_id).ok_or_else(|| {
            EnvelopeValidationError::UnknownRecipient {
                recipient_id: recipient_id.to_string(),
            }
        })?;
        state.record_delivery_attempt(limits)
    }

    pub fn acknowledge_recipient(
        &mut self,
        recipient_id: &str,
    ) -> Result<bool, EnvelopeValidationError> {
        let state = self.recipients.get_mut(recipient_id).ok_or_else(|| {
            EnvelopeValidationError::UnknownRecipient {
                recipient_id: recipient_id.to_string(),
            }
        })?;
        state.acknowledge()
    }
}

/// Bounded deterministic membership and publication policy for one channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedChannel {
    pub version: u32,
    pub channel_id: String,
    #[serde(deserialize_with = "deserialize_ordered_identifiers")]
    pub members: BTreeSet<String>,
    #[serde(deserialize_with = "deserialize_ordered_identifiers")]
    pub publishers: BTreeSet<String>,
}

impl GovernedChannel {
    pub fn new(
        channel_id: impl Into<String>,
        members: BTreeSet<String>,
        publishers: BTreeSet<String>,
        limits: &MessagingLimits,
    ) -> Result<Self, EnvelopeValidationError> {
        let channel = Self {
            version: GOVERNED_CHANNEL_VERSION,
            channel_id: channel_id.into(),
            members,
            publishers,
        };
        channel.validate(limits)?;
        Ok(channel)
    }

    pub fn validate(&self, limits: &MessagingLimits) -> Result<(), EnvelopeValidationError> {
        limits.validate()?;
        if self.version != GOVERNED_CHANNEL_VERSION {
            return Err(EnvelopeValidationError::UnsupportedVersion {
                record: "governed_channel",
                actual: self.version,
                expected: GOVERNED_CHANNEL_VERSION,
            });
        }
        validate_identifier("channel_id", &self.channel_id, limits)?;
        if self.members.is_empty() {
            return Err(EnvelopeValidationError::EmptyChannelMembers);
        }
        if self.members.len() > limits.max_members_per_channel {
            return Err(EnvelopeValidationError::TooManyChannelMembers {
                actual: self.members.len(),
                max: limits.max_members_per_channel,
            });
        }
        if self.publishers.is_empty() {
            return Err(EnvelopeValidationError::EmptyChannelPublishers);
        }
        if self.publishers.len() > limits.max_publishers_per_channel {
            return Err(EnvelopeValidationError::TooManyChannelPublishers {
                actual: self.publishers.len(),
                max: limits.max_publishers_per_channel,
            });
        }
        for member in &self.members {
            validate_identifier("channel_member", member, limits)?;
        }
        for publisher in &self.publishers {
            validate_identifier("channel_publisher", publisher, limits)?;
            if !self.members.contains(publisher) {
                return Err(EnvelopeValidationError::PublisherNotMember {
                    publisher_id: publisher.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn contains_member(&self, agent_id: &str) -> bool {
        self.members.contains(agent_id)
    }

    pub fn permits_publisher(&self, agent_id: &str) -> bool {
        self.publishers.contains(agent_id)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EnvelopeValidationError {
    #[error("messaging limit {field} must be greater than zero")]
    ZeroLimit { field: &'static str },
    #[error("invalid messaging limits: {reason}")]
    InvalidLimit { reason: &'static str },
    #[error("messaging limit arithmetic overflowed")]
    LimitArithmeticOverflow,
    #[error("{field} must be a non-empty canonical identifier")]
    EmptyIdentifier { field: &'static str },
    #[error("{field} is {actual} bytes and exceeds the {max}-byte limit")]
    IdentifierTooLong {
        field: &'static str,
        actual: usize,
        max: usize,
    },
    #[error("{field} contains non-canonical identifier characters")]
    NonCanonicalIdentifier { field: &'static str },
    #[error("unsupported {record} version {actual}; expected {expected}")]
    UnsupportedVersion {
        record: &'static str,
        actual: u32,
        expected: u32,
    },
    #[error("message sequence must be greater than zero")]
    ZeroSequence,
    #[error("only at-least-once delivery is supported")]
    UnsupportedDeliveryGuarantee,
    #[error("JSON payload serialization failed: {0}")]
    PayloadSerialization(String),
    #[error("payload exceeds the {max}-byte limit (at least {actual} bytes observed)")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("payload nesting exceeds the {max_depth}-level structural limit")]
    PayloadNestingTooDeep { max_depth: usize },
    #[error("payload exceeds the {max_nodes}-node structural limit")]
    PayloadTooManyNodes { max_nodes: usize },
    #[error("payload exceeds the {max_strings}-string structural limit")]
    PayloadTooManyStrings { max_strings: usize },
    #[error("payload size accounting overflowed")]
    PayloadSizeArithmeticOverflow,
    #[error("message must have at least one recipient")]
    EmptyRecipients,
    #[error("message has {actual} recipients and exceeds the {max}-recipient limit")]
    TooManyRecipients { actual: usize, max: usize },
    #[error("direct address must have exactly one matching recipient")]
    DirectRecipientMismatch,
    #[error("message channel address does not match the governed channel")]
    ChannelAddressMismatch,
    #[error("message recipient set does not match governed channel membership")]
    ChannelRecipientMismatch,
    #[error("message sender {sender_id:?} is not permitted to publish to channel {channel_id:?}")]
    ChannelPublisherNotPermitted {
        channel_id: String,
        sender_id: String,
    },
    #[error("channel must have at least one member")]
    EmptyChannelMembers,
    #[error("channel must have at least one publisher")]
    EmptyChannelPublishers,
    #[error("channel has {actual} members and exceeds the {max}-member limit")]
    TooManyChannelMembers { actual: usize, max: usize },
    #[error("channel has {actual} publishers and exceeds the {max}-publisher limit")]
    TooManyChannelPublishers { actual: usize, max: usize },
    #[error("channel publisher {publisher_id:?} is not a channel member")]
    PublisherNotMember { publisher_id: String },
    #[error("acknowledged recipient has no recorded delivery attempt")]
    AcknowledgedWithoutDelivery,
    #[error("acknowledged recipient cannot be delivered again")]
    AlreadyAcknowledged,
    #[error("delivery-attempt counter overflowed")]
    DeliveryAttemptOverflow,
    #[error("delivery attempt count {actual} exceeds the configured maximum {max}")]
    TooManyDeliveryAttempts { actual: u32, max: usize },
    #[error("recipient {recipient_id:?} is not part of this message")]
    UnknownRecipient { recipient_id: String },
}

#[derive(Clone, Copy)]
struct PayloadShapeBounds {
    max_depth: usize,
    max_nodes: usize,
    max_strings: usize,
    max_string_bytes: usize,
}

/// Validates a caller-built JSON value without recursively walking it, then
/// serializes through a writer that refuses the first write beyond the byte
/// ceiling. The returned count is exact only for accepted payloads.
pub(crate) fn validate_payload(
    payload: &Value,
    limits: &MessagingLimits,
) -> Result<usize, EnvelopeValidationError> {
    let bounds = PayloadShapeBounds {
        max_depth: MAX_PAYLOAD_NESTING_DEPTH,
        max_nodes: MAX_PAYLOAD_NODES_HARD_LIMIT.min(limits.max_payload_bytes),
        max_strings: MAX_PAYLOAD_STRINGS_HARD_LIMIT.min(limits.max_payload_bytes),
        max_string_bytes: limits.max_payload_bytes,
    };
    validate_payload_shape(payload, bounds)?;
    serialized_payload_size(payload, limits.max_payload_bytes)
}

/// Avoids recursive `Value` destruction when a caller-built payload is
/// rejected specifically because its nesting is hostile.
pub(crate) fn drop_payload_iteratively(payload: Value) {
    enum Frame {
        Array(std::vec::IntoIter<Value>),
        Object(serde_json::map::IntoIter),
    }

    impl Frame {
        fn next_value(&mut self) -> Option<Value> {
            match self {
                Self::Array(values) => values.next(),
                Self::Object(entries) => entries.next().map(|(_, value)| value),
            }
        }
    }

    let mut current = Some(payload);
    let mut frames = Vec::new();
    loop {
        if let Some(value) = current.take() {
            match value {
                Value::Array(values) => frames.push(Frame::Array(values.into_iter())),
                Value::Object(entries) => frames.push(Frame::Object(entries.into_iter())),
                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
            }
        }

        loop {
            let Some(frame) = frames.last_mut() else {
                return;
            };
            if let Some(value) = frame.next_value() {
                current = Some(value);
                break;
            }
            frames.pop();
        }
    }
}

fn validate_payload_shape(
    payload: &Value,
    bounds: PayloadShapeBounds,
) -> Result<(), EnvelopeValidationError> {
    let mut pending = vec![(payload, 1_usize)];
    let mut nodes = 0_usize;
    let mut strings = 0_usize;

    while let Some((value, depth)) = pending.pop() {
        if depth > bounds.max_depth {
            return Err(EnvelopeValidationError::PayloadNestingTooDeep {
                max_depth: bounds.max_depth,
            });
        }
        nodes = nodes
            .checked_add(1)
            .ok_or(EnvelopeValidationError::PayloadSizeArithmeticOverflow)?;
        if nodes > bounds.max_nodes {
            return Err(EnvelopeValidationError::PayloadTooManyNodes {
                max_nodes: bounds.max_nodes,
            });
        }

        match value {
            Value::String(string) => {
                strings = strings
                    .checked_add(1)
                    .ok_or(EnvelopeValidationError::PayloadSizeArithmeticOverflow)?;
                if strings > bounds.max_strings {
                    return Err(EnvelopeValidationError::PayloadTooManyStrings {
                        max_strings: bounds.max_strings,
                    });
                }
                validate_payload_string_bytes(string, bounds.max_string_bytes)?;
            }
            Value::Array(values) => {
                ensure_child_capacity(nodes, pending.len(), values.len(), bounds.max_nodes)?;
                let child_depth = child_depth(depth, values.is_empty(), bounds.max_depth)?;
                pending.extend(values.iter().rev().map(|value| (value, child_depth)));
            }
            Value::Object(entries) => {
                ensure_child_capacity(nodes, pending.len(), entries.len(), bounds.max_nodes)?;
                strings = strings
                    .checked_add(entries.len())
                    .ok_or(EnvelopeValidationError::PayloadSizeArithmeticOverflow)?;
                if strings > bounds.max_strings {
                    return Err(EnvelopeValidationError::PayloadTooManyStrings {
                        max_strings: bounds.max_strings,
                    });
                }
                let child_depth = child_depth(depth, entries.is_empty(), bounds.max_depth)?;
                for (key, value) in entries {
                    validate_payload_string_bytes(key, bounds.max_string_bytes)?;
                    pending.push((value, child_depth));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}

fn ensure_child_capacity(
    nodes: usize,
    pending: usize,
    children: usize,
    max_nodes: usize,
) -> Result<(), EnvelopeValidationError> {
    let total = nodes
        .checked_add(pending)
        .and_then(|total| total.checked_add(children))
        .ok_or(EnvelopeValidationError::PayloadSizeArithmeticOverflow)?;
    if total > max_nodes {
        return Err(EnvelopeValidationError::PayloadTooManyNodes { max_nodes });
    }
    Ok(())
}

fn child_depth(
    depth: usize,
    empty: bool,
    max_depth: usize,
) -> Result<usize, EnvelopeValidationError> {
    if empty {
        return Ok(depth);
    }
    let child_depth = depth
        .checked_add(1)
        .ok_or(EnvelopeValidationError::PayloadSizeArithmeticOverflow)?;
    if child_depth > max_depth {
        return Err(EnvelopeValidationError::PayloadNestingTooDeep { max_depth });
    }
    Ok(child_depth)
}

fn validate_payload_string_bytes(
    string: &str,
    max_bytes: usize,
) -> Result<(), EnvelopeValidationError> {
    if string.len() > max_bytes {
        return Err(EnvelopeValidationError::PayloadTooLarge {
            actual: string.len(),
            max: max_bytes,
        });
    }
    Ok(())
}

struct CappedPayloadWriter {
    max_bytes: usize,
    bytes_written: usize,
    exceeded_at: Option<usize>,
    arithmetic_overflow: bool,
}

impl CappedPayloadWriter {
    const fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            bytes_written: 0,
            exceeded_at: None,
            arithmetic_overflow: false,
        }
    }
}

impl Write for CappedPayloadWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let Some(next) = self.bytes_written.checked_add(buffer.len()) else {
            self.arithmetic_overflow = true;
            return Err(io::Error::other("payload size accounting overflowed"));
        };
        if next > self.max_bytes {
            self.exceeded_at = Some(next);
            return Err(io::Error::other("payload byte limit exceeded"));
        }
        self.bytes_written = next;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_payload_size(
    payload: &Value,
    max_bytes: usize,
) -> Result<usize, EnvelopeValidationError> {
    let mut writer = CappedPayloadWriter::new(max_bytes);
    match serde_json::to_writer(&mut writer, payload) {
        Ok(()) => Ok(writer.bytes_written),
        Err(error) => {
            if writer.arithmetic_overflow {
                return Err(EnvelopeValidationError::PayloadSizeArithmeticOverflow);
            }
            if let Some(actual) = writer.exceeded_at {
                return Err(EnvelopeValidationError::PayloadTooLarge {
                    actual,
                    max: max_bytes,
                });
            }
            Err(EnvelopeValidationError::PayloadSerialization(
                error.to_string(),
            ))
        }
    }
}

fn deserialize_ordered_identifiers<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OrderedIdentifierVisitor;

    impl<'de> Visitor<'de> for OrderedIdentifierVisitor {
        type Value = BTreeSet<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a strictly ordered array of unique identifiers")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut identifiers = BTreeSet::new();
            let mut previous: Option<String> = None;
            while let Some(identifier) = sequence.next_element::<String>()? {
                if let Some(previous) = previous.as_deref() {
                    match previous.cmp(identifier.as_str()) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => {
                            return Err(de::Error::custom(
                                "deterministic identifier array contains a duplicate",
                            ));
                        }
                        std::cmp::Ordering::Greater => {
                            return Err(de::Error::custom(
                                "deterministic identifier array is out of order",
                            ));
                        }
                    }
                }
                previous = Some(identifier.clone());
                if !identifiers.insert(identifier) {
                    return Err(de::Error::custom(
                        "deterministic identifier array contains a duplicate",
                    ));
                }
            }
            Ok(identifiers)
        }
    }

    deserializer.deserialize_seq(OrderedIdentifierVisitor)
}

fn deserialize_ordered_recipient_states<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, RecipientDeliveryState>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OrderedRecipientVisitor;

    impl<'de> Visitor<'de> for OrderedRecipientVisitor {
        type Value = BTreeMap<String, RecipientDeliveryState>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a strictly ordered map of unique recipient delivery states")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut recipients = BTreeMap::new();
            let mut previous: Option<String> = None;
            while let Some((recipient_id, state)) =
                map.next_entry::<String, RecipientDeliveryState>()?
            {
                if let Some(previous) = previous.as_deref() {
                    match previous.cmp(recipient_id.as_str()) {
                        std::cmp::Ordering::Less => {}
                        std::cmp::Ordering::Equal => {
                            return Err(de::Error::custom(
                                "deterministic recipient map contains a duplicate",
                            ));
                        }
                        std::cmp::Ordering::Greater => {
                            return Err(de::Error::custom(
                                "deterministic recipient map is out of order",
                            ));
                        }
                    }
                }
                previous = Some(recipient_id.clone());
                if recipients.insert(recipient_id, state).is_some() {
                    return Err(de::Error::custom(
                        "deterministic recipient map contains a duplicate",
                    ));
                }
            }
            Ok(recipients)
        }
    }

    deserializer.deserialize_map(OrderedRecipientVisitor)
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    limits: &MessagingLimits,
) -> Result<(), EnvelopeValidationError> {
    if value.is_empty() || value != value.trim() {
        return Err(EnvelopeValidationError::EmptyIdentifier { field });
    }
    if value.len() > limits.max_identifier_bytes {
        return Err(EnvelopeValidationError::IdentifierTooLong {
            field,
            actual: value.len(),
            max: limits.max_identifier_bytes,
        });
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
    }) {
        return Err(EnvelopeValidationError::NonCanonicalIdentifier { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn limits() -> MessagingLimits {
        MessagingLimits {
            max_credentials: 8,
            max_messages: 32,
            max_channels: 4,
            max_members_per_channel: 4,
            max_publishers_per_channel: 2,
            max_payload_bytes: 1_024,
            max_identifier_bytes: 64,
            max_journal_records: 256,
            max_journal_bytes: 64 * 1_024,
            max_delivery_attempts: 3,
        }
    }

    fn channel() -> GovernedChannel {
        GovernedChannel::new(
            "reviewers",
            BTreeSet::from(["agent-a".to_string(), "agent-b".to_string()]),
            BTreeSet::from(["agent-a".to_string()]),
            &limits(),
        )
        .expect("valid governed channel")
    }

    #[test]
    fn direct_envelope_is_strict_bounded_and_role_bearing() {
        let limits = limits();
        let envelope = MessageEnvelope::new(
            MessageId::new_with_limits("message-1", &limits).expect("message id"),
            MessageAddress::direct("agent-b", &limits).expect("direct address"),
            "agent-a",
            RoleCategory::NonDelegatingTerminalWorker,
            1,
            json!({"task": "review"}),
            BTreeSet::from(["agent-b".to_string()]),
            &limits,
        )
        .expect("valid direct envelope");

        assert_eq!(envelope.version, MESSAGE_ENVELOPE_VERSION);
        assert_eq!(envelope.id.as_str(), "message-1");
        assert_eq!(
            envelope.sender_role,
            RoleCategory::NonDelegatingTerminalWorker
        );
        assert_eq!(envelope.guarantee, DeliveryGuarantee::AtLeastOnce);
        assert_eq!(
            envelope.recipients.get("agent-b"),
            Some(&RecipientDeliveryState::pending())
        );

        let encoded = serde_json::to_value(&envelope).expect("serialize envelope");
        assert!(encoded.get("credential").is_none());
        assert!(encoded.get("token").is_none());
        assert!(encoded.get("claimed_role").is_none());
        let mut with_unknown = encoded;
        with_unknown["credential"] = json!("must-not-persist");
        assert!(serde_json::from_value::<MessageEnvelope>(with_unknown).is_err());
    }

    #[test]
    fn direct_recipient_must_exactly_match_address() {
        let limits = limits();
        let error = MessageEnvelope::new(
            MessageId::new("message-1").expect("message id"),
            MessageAddress::direct("agent-b", &limits).expect("direct address"),
            "agent-a",
            RoleCategory::DelegatingCoordinator,
            1,
            json!("payload"),
            BTreeSet::from(["agent-c".to_string()]),
            &limits,
        )
        .expect_err("mis-addressed direct envelope must fail");
        assert_eq!(error, EnvelopeValidationError::DirectRecipientMismatch);
    }

    #[test]
    fn channel_fanout_must_equal_governed_membership() {
        let limits = limits();
        let channel = channel();
        let envelope = MessageEnvelope::new(
            MessageId::new("message-2").expect("message id"),
            MessageAddress::channel("reviewers", &limits).expect("channel address"),
            "agent-a",
            RoleCategory::DelegatingCoordinator,
            2,
            json!({"broadcast": true}),
            channel.members.clone(),
            &limits,
        )
        .expect("valid channel envelope");
        envelope
            .validate_for_channel(&channel, &limits)
            .expect("fan-out agrees with policy");

        let mut omitted = envelope.clone();
        omitted.recipients.remove("agent-b");
        assert_eq!(
            omitted
                .validate_for_channel(&channel, &limits)
                .expect_err("partial fan-out must fail"),
            EnvelopeValidationError::ChannelRecipientMismatch
        );

        let non_publisher = MessageEnvelope::new(
            MessageId::new("message-3").expect("message id"),
            MessageAddress::channel("reviewers", &limits).expect("channel address"),
            "agent-b",
            RoleCategory::NonDelegatingTerminalWorker,
            3,
            json!({"broadcast": true}),
            channel.members.clone(),
            &limits,
        )
        .expect("structurally valid channel envelope");
        assert_eq!(
            non_publisher
                .validate_for_channel(&channel, &limits)
                .expect_err("member outside publisher policy must fail"),
            EnvelopeValidationError::ChannelPublisherNotPermitted {
                channel_id: "reviewers".to_string(),
                sender_id: "agent-b".to_string(),
            }
        );
    }

    #[test]
    fn channel_policy_is_bounded_and_cannot_carry_authority_fields() {
        let limits = limits();
        let error = GovernedChannel::new(
            "reviewers",
            BTreeSet::from(["agent-a".to_string()]),
            BTreeSet::from(["agent-b".to_string()]),
            &limits,
        )
        .expect_err("publisher outside membership must fail");
        assert_eq!(
            error,
            EnvelopeValidationError::PublisherNotMember {
                publisher_id: "agent-b".to_string()
            }
        );

        let mut encoded = serde_json::to_value(channel()).expect("serialize channel");
        encoded["promoted_role"] = json!("delegating_coordinator");
        assert!(serde_json::from_value::<GovernedChannel>(encoded).is_err());
    }

    #[test]
    fn delivery_repeats_until_durable_idempotent_acknowledgement() {
        let limits = limits();
        let mut state = RecipientDeliveryState::pending();
        assert_eq!(state.record_delivery_attempt(&limits), Ok(1));
        assert_eq!(state.record_delivery_attempt(&limits), Ok(2));
        assert_eq!(state.acknowledge(), Ok(true));
        assert_eq!(state.acknowledge(), Ok(false));
        assert_eq!(
            state.record_delivery_attempt(&limits),
            Err(EnvelopeValidationError::AlreadyAcknowledged)
        );
        state
            .validate(&limits)
            .expect("acknowledged state remains valid");
    }

    #[test]
    fn impossible_and_exhausted_delivery_states_fail_closed() {
        let limits = limits();
        let impossible = RecipientDeliveryState {
            delivery_attempts: 0,
            acknowledged: true,
        };
        assert_eq!(
            impossible.validate(&limits),
            Err(EnvelopeValidationError::AcknowledgedWithoutDelivery)
        );

        let mut exhausted = RecipientDeliveryState {
            delivery_attempts: 3,
            acknowledged: false,
        };
        assert_eq!(
            exhausted.record_delivery_attempt(&limits),
            Err(EnvelopeValidationError::TooManyDeliveryAttempts { actual: 4, max: 3 })
        );
    }

    #[test]
    fn zero_sequence_oversized_payload_and_noncanonical_ids_fail() {
        let limits = limits();
        let zero_sequence = MessageEnvelope::new(
            MessageId::new("message-1").expect("message id"),
            MessageAddress::direct("agent-b", &limits).expect("direct address"),
            "agent-a",
            RoleCategory::ReadOnlyResearcher,
            0,
            json!("payload"),
            BTreeSet::from(["agent-b".to_string()]),
            &limits,
        )
        .expect_err("zero sequence must fail");
        assert_eq!(zero_sequence, EnvelopeValidationError::ZeroSequence);

        let mut payload_limits = limits.clone();
        payload_limits.max_payload_bytes = 4;
        let payload_error = MessageEnvelope::new(
            MessageId::new("message-1").expect("message id"),
            MessageAddress::direct("agent-b", &payload_limits).expect("direct address"),
            "agent-a",
            RoleCategory::ReadOnlyResearcher,
            1,
            json!("too large"),
            BTreeSet::from(["agent-b".to_string()]),
            &payload_limits,
        )
        .expect_err("oversized payload must fail");
        assert!(matches!(
            payload_error,
            EnvelopeValidationError::PayloadTooLarge { .. }
        ));

        assert_eq!(
            MessageId::new("bad id"),
            Err(EnvelopeValidationError::NonCanonicalIdentifier {
                field: "message_id"
            })
        );
    }

    #[test]
    fn iterative_payload_preflight_rejects_depth_nodes_and_strings() {
        let limits = limits();
        let mut deeply_nested = Value::Null;
        for _ in 0..(MAX_PAYLOAD_NESTING_DEPTH * 32) {
            deeply_nested = Value::Array(vec![deeply_nested]);
        }
        let deep_error = MessageEnvelope::new(
            MessageId::new("message-deep").expect("message id"),
            MessageAddress::direct("agent-b", &limits).expect("direct address"),
            "agent-a",
            RoleCategory::ReadOnlyResearcher,
            1,
            deeply_nested,
            BTreeSet::from(["agent-b".to_string()]),
            &limits,
        )
        .expect_err("hostile nesting must fail without recursive serialization or drop");
        assert_eq!(
            deep_error,
            EnvelopeValidationError::PayloadNestingTooDeep {
                max_depth: MAX_PAYLOAD_NESTING_DEPTH
            }
        );

        let node_limit = limits.max_payload_bytes;
        let too_many_nodes = Value::Array(vec![Value::Null; node_limit]);
        assert_eq!(
            validate_payload(&too_many_nodes, &limits),
            Err(EnvelopeValidationError::PayloadTooManyNodes {
                max_nodes: node_limit
            })
        );

        let mut string_limits = limits.clone();
        string_limits.max_payload_bytes = 4;
        let too_many_strings = Value::Object(serde_json::Map::from_iter([
            ("a".to_string(), Value::String(String::new())),
            ("b".to_string(), Value::String(String::new())),
            ("c".to_string(), Value::String(String::new())),
        ]));
        assert_eq!(
            validate_payload(&too_many_strings, &string_limits),
            Err(EnvelopeValidationError::PayloadTooManyStrings { max_strings: 4 })
        );
    }

    #[test]
    fn capped_payload_serialization_stops_at_ceiling_and_accepts_normal_json() {
        let limits = limits();
        let normal = json!({"action": "review", "attempt": 2});
        assert_eq!(
            validate_payload(&normal, &limits).expect("normal payload"),
            serde_json::to_vec(&normal)
                .expect("serialize expected payload")
                .len()
        );

        let mut capped_limits = limits;
        capped_limits.max_payload_bytes = 8;
        let escaping_expands_past_cap = Value::String("\n\n\n\n".to_string());
        let error = validate_payload(&escaping_expands_past_cap, &capped_limits)
            .expect_err("escaped JSON must stop at the byte ceiling");
        assert!(matches!(
            error,
            EnvelopeValidationError::PayloadTooLarge { actual, max: 8 } if actual > 8
        ));
    }

    #[test]
    fn limits_reject_zero_relational_and_arithmetic_overflow() {
        let mut invalid = limits();
        invalid.max_messages = 0;
        assert_eq!(
            invalid.validate(),
            Err(EnvelopeValidationError::ZeroLimit {
                field: "max_messages"
            })
        );

        let mut invalid = limits();
        invalid.max_publishers_per_channel = invalid.max_members_per_channel + 1;
        assert!(matches!(
            invalid.validate(),
            Err(EnvelopeValidationError::InvalidLimit { .. })
        ));

        let mut overflowing = limits();
        overflowing.max_credentials = usize::MAX;
        overflowing.max_members_per_channel = usize::MAX;
        overflowing.max_publishers_per_channel = 1;
        assert_eq!(
            overflowing.validate(),
            Err(EnvelopeValidationError::LimitArithmeticOverflow)
        );
    }

    #[test]
    fn serde_rejects_unknown_fields_and_preserves_deterministic_order() {
        let limits = limits();
        let encoded_limits = serde_json::to_value(&limits).expect("serialize limits");
        let mut unknown_limits = encoded_limits;
        unknown_limits["unbounded"] = json!(true);
        assert!(serde_json::from_value::<MessagingLimits>(unknown_limits).is_err());

        let channel = channel();
        assert_eq!(
            serde_json::to_string(&channel.members).expect("serialize members"),
            r#"["agent-a","agent-b"]"#
        );

        let address = json!({
            "kind": "direct",
            "recipient_id": "agent-a",
            "unexpected": true
        });
        assert!(serde_json::from_value::<MessageAddress>(address).is_err());
    }

    #[test]
    fn serde_rejects_duplicate_or_reordered_deterministic_collections() {
        let mut reordered_channel = serde_json::to_value(channel()).expect("serialize channel");
        reordered_channel["members"] = json!(["agent-b", "agent-a"]);
        assert!(serde_json::from_value::<GovernedChannel>(reordered_channel).is_err());

        let mut duplicate_channel = serde_json::to_value(channel()).expect("serialize channel");
        duplicate_channel["publishers"] = json!(["agent-a", "agent-a"]);
        assert!(serde_json::from_value::<GovernedChannel>(duplicate_channel).is_err());

        let envelope = MessageEnvelope::new(
            MessageId::new("message-4").expect("message id"),
            MessageAddress::channel("reviewers", &limits()).expect("channel address"),
            "agent-a",
            RoleCategory::DelegatingCoordinator,
            4,
            json!("payload"),
            channel().members,
            &limits(),
        )
        .expect("valid channel envelope");
        let encoded = serde_json::to_string(&envelope).expect("serialize envelope");
        let ordered = r#""recipients":{"agent-a":{"delivery_attempts":0,"acknowledged":false},"agent-b":{"delivery_attempts":0,"acknowledged":false}}"#;
        let reordered = r#""recipients":{"agent-b":{"delivery_attempts":0,"acknowledged":false},"agent-a":{"delivery_attempts":0,"acknowledged":false}}"#;
        let duplicate = r#""recipients":{"agent-a":{"delivery_attempts":0,"acknowledged":false},"agent-a":{"delivery_attempts":0,"acknowledged":false}}"#;
        assert!(encoded.contains(ordered));
        assert!(
            serde_json::from_str::<MessageEnvelope>(&encoded.replacen(ordered, reordered, 1))
                .is_err()
        );
        assert!(
            serde_json::from_str::<MessageEnvelope>(&encoded.replacen(ordered, duplicate, 1))
                .is_err()
        );
    }
}
