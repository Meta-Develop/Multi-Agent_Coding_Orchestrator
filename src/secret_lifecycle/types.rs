use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current serialized lifecycle envelope version.
pub const SECRET_LIFECYCLE_VERSION: u32 = 1;

pub(crate) const MAX_NAME_BYTES: usize = 128;
pub(crate) const MAX_ENV_KEY_BYTES: usize = 128;
pub(crate) const MAX_SCOPE_ID_BYTES: usize = 256;
pub(crate) const MAX_MATERIAL_BYTES: usize = 64 * 1024;
pub(crate) const MAX_SECRETS: usize = 256;
pub(crate) const MAX_DELEGATES_PER_SECRET: usize = 64;
pub(crate) const MAX_AUDIT_EVENTS: usize = 4096;
pub(crate) const MAX_RESIDUAL_COPIES: usize = 8;

/// Opaque, plan-safe reference to a declared secret. Never carries material.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    name: String,
    generation: u64,
}

impl SecretRef {
    pub(crate) fn new(
        name: impl Into<String>,
        generation: u64,
    ) -> Result<Self, SecretLifecycleError> {
        let name = name.into();
        validate_secret_name(&name)?;
        if generation == 0 {
            return Err(SecretLifecycleError::InvalidDeclaration {
                name,
                reason: "generation must be greater than zero".to_string(),
            });
        }
        Ok(Self { name, generation })
    }

    pub(crate) fn trusted(name: impl Into<String>, generation: u64) -> Self {
        Self {
            name: name.into(),
            generation,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Explicit assignment / worktree / runtime scope. At least one axis is required.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    assignment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worktree_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    runtime_id: Option<String>,
}

impl SecretScope {
    pub fn try_new(
        assignment_id: Option<String>,
        worktree_id: Option<String>,
        runtime_id: Option<String>,
    ) -> Result<Self, SecretLifecycleError> {
        let scope = Self {
            assignment_id: normalize_scope_id("assignment_id", assignment_id)?,
            worktree_id: normalize_scope_id("worktree_id", worktree_id)?,
            runtime_id: normalize_scope_id("runtime_id", runtime_id)?,
        };
        if scope.assignment_id.is_none()
            && scope.worktree_id.is_none()
            && scope.runtime_id.is_none()
        {
            return Err(SecretLifecycleError::Unscoped);
        }
        Ok(scope)
    }

    pub fn assignment(id: impl Into<String>) -> Result<Self, SecretLifecycleError> {
        Self::try_new(Some(id.into()), None, None)
    }

    pub fn worktree(id: impl Into<String>) -> Result<Self, SecretLifecycleError> {
        Self::try_new(None, Some(id.into()), None)
    }

    pub fn runtime(id: impl Into<String>) -> Result<Self, SecretLifecycleError> {
        Self::try_new(None, None, Some(id.into()))
    }

    pub fn assignment_id(&self) -> Option<&str> {
        self.assignment_id.as_deref()
    }

    pub fn worktree_id(&self) -> Option<&str> {
        self.worktree_id.as_deref()
    }

    pub fn runtime_id(&self) -> Option<&str> {
        self.runtime_id.as_deref()
    }
}

/// What may be persisted for a secret. Material persistence is intentionally
/// unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistencePolicy {
    ReferenceOnly,
}

/// Whether a child scope may be granted injection rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationPolicy {
    ExplicitScopes,
    Forbidden,
}

/// Lifecycle state visible in reports. Material is never attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretState {
    Declared,
    Bound,
    Revoked,
    Expired,
    Destroyed,
}

/// Public declaration used by plans. Contains no material field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretDeclaration {
    name: String,
    env_key: String,
    scope: SecretScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_unix_ms: Option<u64>,
    persistence: PersistencePolicy,
    delegation: DelegationPolicy,
}

impl SecretDeclaration {
    pub fn new(
        name: impl Into<String>,
        env_key: impl Into<String>,
        scope: SecretScope,
    ) -> Result<Self, SecretLifecycleError> {
        let name = name.into();
        let env_key = env_key.into();
        validate_secret_name(&name)?;
        validate_env_key(&env_key)?;
        Ok(Self {
            name,
            env_key,
            scope,
            expires_at_unix_ms: None,
            persistence: PersistencePolicy::ReferenceOnly,
            delegation: DelegationPolicy::ExplicitScopes,
        })
    }

    pub fn with_expiry(mut self, expires_at_unix_ms: u64) -> Self {
        self.expires_at_unix_ms = Some(expires_at_unix_ms);
        self
    }

    pub fn with_delegation(mut self, delegation: DelegationPolicy) -> Self {
        self.delegation = delegation;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn env_key(&self) -> &str {
        &self.env_key
    }

    pub fn scope(&self) -> &SecretScope {
        &self.scope
    }

    pub fn expires_at_unix_ms(&self) -> Option<u64> {
        self.expires_at_unix_ms
    }

    pub fn persistence(&self) -> PersistencePolicy {
        self.persistence
    }

    pub fn delegation(&self) -> DelegationPolicy {
        self.delegation
    }
}

/// Plan/artifact binding that supervisors may serialize. No material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPlanBinding {
    pub reference: SecretRef,
    pub env_key: String,
    pub scope: SecretScope,
    pub persistence: PersistencePolicy,
    pub delegation: DelegationPolicy,
}

/// Report row for one declared secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretStatusView {
    pub reference: SecretRef,
    pub env_key: String,
    pub scope: SecretScope,
    pub state: SecretState,
    pub persistence: PersistencePolicy,
    pub delegation: DelegationPolicy,
    pub delegated_scopes: Vec<SecretScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
}

/// Typed fail-closed errors. Display, Debug, and serde omit raw material.
#[derive(Clone, Debug, Error, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretLifecycleError {
    #[error("secret declaration {name} is invalid: {reason}")]
    InvalidDeclaration { name: String, reason: String },
    #[error("secret {name} is already declared")]
    AlreadyDeclared { name: String },
    #[error("secret {name} generation {generation} is not declared")]
    UnknownReference { name: String, generation: u64 },
    #[error("secret {name} has no bound material")]
    NotBound { name: String },
    #[error("secret {name} is not delegated to the requesting scope")]
    NotDelegated { name: String },
    #[error("secret {name} generation {generation} is stale")]
    StaleGeneration { name: String, generation: u64 },
    #[error("secret {name} has been revoked")]
    Revoked { name: String },
    #[error("secret {name} has expired")]
    Expired { name: String },
    #[error("secret {name} has been destroyed")]
    Destroyed { name: String },
    #[error("secret {name} forbids child delegation")]
    DelegationForbidden { name: String },
    #[error("secret scope is empty; at least one axis is required")]
    Unscoped,
    #[error("secret material is invalid: {reason}")]
    InvalidMaterial { reason: String },
    #[error("secret vault capacity exceeded")]
    Capacity,
    #[error("secret audit trail capacity exceeded")]
    AuditCapacity,
    #[error("secret lifecycle clock is unreadable")]
    ClockUnreadable,
}

impl SecretLifecycleError {
    pub fn is_inactive(&self) -> bool {
        matches!(
            self,
            Self::NotBound { .. }
                | Self::Revoked { .. }
                | Self::Expired { .. }
                | Self::Destroyed { .. }
                | Self::StaleGeneration { .. }
        )
    }

    pub(crate) fn kind_name(&self) -> &'static str {
        match self {
            Self::InvalidDeclaration { .. } => "invalid_declaration",
            Self::AlreadyDeclared { .. } => "already_declared",
            Self::UnknownReference { .. } => "unknown_reference",
            Self::NotBound { .. } => "not_bound",
            Self::NotDelegated { .. } => "not_delegated",
            Self::StaleGeneration { .. } => "stale_generation",
            Self::Revoked { .. } => "revoked",
            Self::Expired { .. } => "expired",
            Self::Destroyed { .. } => "destroyed",
            Self::DelegationForbidden { .. } => "delegation_forbidden",
            Self::Unscoped => "unscoped",
            Self::InvalidMaterial { .. } => "invalid_material",
            Self::Capacity => "capacity",
            Self::AuditCapacity => "audit_capacity",
            Self::ClockUnreadable => "clock_unreadable",
        }
    }

    pub fn secret_name(&self) -> Option<&str> {
        match self {
            Self::InvalidDeclaration { name, .. }
            | Self::AlreadyDeclared { name }
            | Self::UnknownReference { name, .. }
            | Self::NotBound { name }
            | Self::NotDelegated { name }
            | Self::StaleGeneration { name, .. }
            | Self::Revoked { name }
            | Self::Expired { name }
            | Self::Destroyed { name }
            | Self::DelegationForbidden { name } => Some(name),
            Self::Unscoped
            | Self::InvalidMaterial { .. }
            | Self::Capacity
            | Self::AuditCapacity
            | Self::ClockUnreadable => None,
        }
    }
}

pub(crate) fn validate_secret_name(name: &str) -> Result<(), SecretLifecycleError> {
    if !is_token(name, MAX_NAME_BYTES, true) {
        return Err(SecretLifecycleError::InvalidDeclaration {
            name: name.to_string(),
            reason: "name must be 1..=128 ASCII alphanumeric characters plus '.', '_', or '-'"
                .to_string(),
        });
    }
    Ok(())
}

pub(crate) fn validate_env_key(env_key: &str) -> Result<(), SecretLifecycleError> {
    if env_key.is_empty() || env_key.len() > MAX_ENV_KEY_BYTES {
        return Err(SecretLifecycleError::InvalidDeclaration {
            name: env_key.to_string(),
            reason: "env key must be 1..=128 bytes".to_string(),
        });
    }
    let bytes = env_key.as_bytes();
    let first_ok = bytes[0].is_ascii_alphabetic() || bytes[0] == b'_';
    let rest_ok = bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    if !first_ok || !rest_ok {
        return Err(SecretLifecycleError::InvalidDeclaration {
            name: env_key.to_string(),
            reason: "env key must match [A-Za-z_][A-Za-z0-9_]*".to_string(),
        });
    }
    Ok(())
}

pub(crate) fn validate_material(material: &str) -> Result<(), SecretLifecycleError> {
    if material.is_empty() {
        return Err(SecretLifecycleError::InvalidMaterial {
            reason: "empty".to_string(),
        });
    }
    if material.len() > MAX_MATERIAL_BYTES {
        return Err(SecretLifecycleError::InvalidMaterial {
            reason: "too_large".to_string(),
        });
    }
    Ok(())
}

fn normalize_scope_id(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, SecretLifecycleError> {
    match value {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => {
            if !is_token(&value, MAX_SCOPE_ID_BYTES, true) {
                return Err(SecretLifecycleError::InvalidDeclaration {
                    name: field.to_string(),
                    reason: format!("{field} is not a valid scope identifier"),
                });
            }
            Ok(Some(value))
        }
    }
}

fn is_token(value: &str, max_bytes: usize, allow_dot_dash: bool) -> bool {
    if value.is_empty() || value.len() > max_bytes {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_alphanumeric()
            || *byte == b'_'
            || (allow_dot_dash && matches!(*byte, b'.' | b'-'))
    })
}
