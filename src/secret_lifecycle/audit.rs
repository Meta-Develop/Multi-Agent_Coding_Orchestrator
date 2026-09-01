use super::types::{SecretRef, SecretScope};
use serde::{Deserialize, Serialize};

/// Append-only, serializable access trail. Events never include material.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretAuditTrail {
    events: Vec<SecretAuditEvent>,
}

impl SecretAuditTrail {
    pub fn events(&self) -> &[SecretAuditEvent] {
        &self.events
    }

    pub(crate) fn push(&mut self, event: SecretAuditEvent) {
        self.events.push(event);
    }

    pub(crate) fn len(&self) -> usize {
        self.events.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretAuditEvent {
    unix_ms: u64,
    action: SecretAuditAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<SecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requester: Option<SecretScope>,
    outcome: SecretAuditOutcome,
}

impl SecretAuditEvent {
    pub(crate) fn new(
        unix_ms: u64,
        action: SecretAuditAction,
        secret: Option<SecretRef>,
        requester: Option<SecretScope>,
        outcome: SecretAuditOutcome,
    ) -> Self {
        Self {
            unix_ms,
            action,
            secret,
            requester,
            outcome,
        }
    }

    pub fn unix_ms(&self) -> u64 {
        self.unix_ms
    }

    pub fn action(&self) -> SecretAuditAction {
        self.action
    }

    pub fn secret(&self) -> Option<&SecretRef> {
        self.secret.as_ref()
    }

    pub fn requester(&self) -> Option<&SecretScope> {
        self.requester.as_ref()
    }

    pub fn outcome(&self) -> &SecretAuditOutcome {
        &self.outcome
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretAuditAction {
    Declare,
    BindMaterial,
    Inject,
    Delegate,
    Revoke,
    Rotate,
    Destroy,
    Expire,
    Finish,
    Report,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SecretAuditOutcome {
    Allowed,
    Denied { reason: String },
}

impl SecretAuditOutcome {
    pub(crate) fn denied_kind(kind: &str) -> Self {
        Self::Denied {
            reason: kind.to_string(),
        }
    }
}
