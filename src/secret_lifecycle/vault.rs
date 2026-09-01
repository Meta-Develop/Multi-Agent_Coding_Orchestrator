use super::{
    audit::{SecretAuditAction, SecretAuditEvent, SecretAuditOutcome, SecretAuditTrail},
    injection::{SecretEnvironment, SecretLease},
    material::SecretBytes,
    types::{
        validate_material, DelegationPolicy, PersistencePolicy, SecretDeclaration,
        SecretLifecycleError, SecretPlanBinding, SecretRef, SecretScope, SecretState,
        SecretStatusView, MAX_AUDIT_EVENTS, MAX_DELEGATES_PER_SECRET, MAX_RESIDUAL_COPIES,
        MAX_SECRETS, SECRET_LIFECYCLE_VERSION,
    },
};
use crate::llm::{RedactedText, Redactor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};

/// In-memory vault. Not serializable: only views, refs, and audit events are.
pub struct SecretVault {
    records: BTreeMap<String, SecretRecord>,
    audit: SecretAuditTrail,
    clock_ms: Option<u64>,
}

struct SecretRecord {
    env_key: String,
    scope: SecretScope,
    generation: u64,
    state: SecretState,
    expires_at_unix_ms: Option<u64>,
    persistence: PersistencePolicy,
    delegation: DelegationPolicy,
    delegated_scopes: BTreeSet<SecretScope>,
    material: Option<SecretBytes>,
    residual: Vec<SecretBytes>,
}

impl SecretVault {
    pub fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            audit: SecretAuditTrail::default(),
            clock_ms: None,
        }
    }

    /// Test/control clock. Production callers omit this and use wall time.
    pub fn at_unix_ms(now_ms: u64) -> Self {
        Self {
            records: BTreeMap::new(),
            audit: SecretAuditTrail::default(),
            clock_ms: Some(now_ms),
        }
    }

    pub fn set_unix_ms(&mut self, now_ms: u64) {
        self.clock_ms = Some(now_ms);
    }

    pub fn declare(
        &mut self,
        declaration: SecretDeclaration,
    ) -> Result<SecretRef, SecretLifecycleError> {
        self.ensure_audit_capacity()?;
        if self.records.len() >= MAX_SECRETS {
            return Err(SecretLifecycleError::Capacity);
        }
        let reference = SecretRef::new(declaration.name(), 1)?;
        if self.records.contains_key(declaration.name()) {
            let error = SecretLifecycleError::AlreadyDeclared {
                name: declaration.name().to_string(),
            };
            self.record_denied(
                SecretAuditAction::Declare,
                Some(reference),
                Some(declaration.scope().clone()),
                &error,
            )?;
            return Err(error);
        }
        self.records.insert(
            declaration.name().to_string(),
            SecretRecord {
                env_key: declaration.env_key().to_string(),
                scope: declaration.scope().clone(),
                generation: 1,
                state: SecretState::Declared,
                expires_at_unix_ms: declaration.expires_at_unix_ms(),
                persistence: declaration.persistence(),
                delegation: declaration.delegation(),
                delegated_scopes: BTreeSet::new(),
                material: None,
                residual: Vec::new(),
            },
        );
        self.record_allowed(
            SecretAuditAction::Declare,
            Some(reference.clone()),
            Some(declaration.scope().clone()),
        )?;
        Ok(reference)
    }

    pub fn bind_material(
        &mut self,
        reference: &SecretRef,
        material: &str,
    ) -> Result<(), SecretLifecycleError> {
        self.ensure_audit_capacity()?;
        if let Err(error) = validate_material(material) {
            self.record_denied(
                SecretAuditAction::BindMaterial,
                Some(reference.clone()),
                None,
                &error,
            )?;
            return Err(error);
        }
        let now = self.now_ms()?;
        self.require_current(reference, SecretAuditAction::BindMaterial, None)?;
        let inactive = self
            .records
            .get_mut(reference.name())
            .map(|record| {
                record.refresh_state(now);
                record.inactive_error(reference.name())
            })
            .ok_or_else(|| unknown_reference(reference))?;
        if let Some(error) = inactive {
            if !matches!(error, SecretLifecycleError::NotBound { .. }) {
                return self.fail(SecretAuditAction::BindMaterial, reference, None, error);
            }
        }
        if let Some(record) = self.records.get_mut(reference.name()) {
            record.push_residual();
            record.material = Some(SecretBytes::from_str(material));
            record.state = SecretState::Bound;
        }
        self.record_allowed(
            SecretAuditAction::BindMaterial,
            Some(reference.clone()),
            None,
        )
    }

    pub fn inject(
        &mut self,
        reference: &SecretRef,
        requester: &SecretScope,
    ) -> Result<SecretLease, SecretLifecycleError> {
        self.ensure_audit_capacity()?;
        let now = self.now_ms()?;
        self.require_current(reference, SecretAuditAction::Inject, Some(requester))?;
        let outcome = {
            let record = self
                .records
                .get_mut(reference.name())
                .ok_or_else(|| unknown_reference(reference))?;
            record.refresh_state(now);
            if let Some(error) = record.inactive_error(reference.name()) {
                Err(error)
            } else if !record.authorized_for(requester) {
                Err(SecretLifecycleError::NotDelegated {
                    name: reference.name().to_string(),
                })
            } else {
                match &record.material {
                    Some(material) => Ok((record.env_key.clone(), material.clone())),
                    None => Err(SecretLifecycleError::NotBound {
                        name: reference.name().to_string(),
                    }),
                }
            }
        };
        match outcome {
            Ok((env_key, material)) => {
                self.record_allowed(
                    SecretAuditAction::Inject,
                    Some(reference.clone()),
                    Some(requester.clone()),
                )?;
                Ok(SecretLease::new(reference.clone(), env_key, material))
            }
            Err(error) => self.fail(SecretAuditAction::Inject, reference, Some(requester), error),
        }
    }

    /// Environment map for one requester. Unauthorized secrets are omitted.
    ///
    /// The returned type redacts values in Debug and serde. Call
    /// [`SecretEnvironment::into_process_env`] only at process spawn.
    pub fn inject_environment(
        &mut self,
        requester: &SecretScope,
    ) -> Result<SecretEnvironment, SecretLifecycleError> {
        let candidates: Vec<SecretRef> = self
            .records
            .iter()
            .filter(|(_, record)| record.authorized_for(requester))
            .map(|(name, record)| SecretRef::trusted(name.clone(), record.generation))
            .collect();
        let mut env = SecretEnvironment::default();
        for reference in candidates {
            match self.inject(&reference, requester) {
                Ok(lease) => env.insert_lease(lease),
                Err(error) if error.is_inactive() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(env)
    }

    pub fn delegate(
        &mut self,
        reference: &SecretRef,
        child: SecretScope,
    ) -> Result<(), SecretLifecycleError> {
        self.ensure_audit_capacity()?;
        self.require_current(reference, SecretAuditAction::Delegate, Some(&child))?;
        let error = {
            let record = self
                .records
                .get_mut(reference.name())
                .ok_or_else(|| unknown_reference(reference))?;
            if record.delegation == DelegationPolicy::Forbidden {
                Some(SecretLifecycleError::DelegationForbidden {
                    name: reference.name().to_string(),
                })
            } else if record.state == SecretState::Destroyed {
                Some(SecretLifecycleError::Destroyed {
                    name: reference.name().to_string(),
                })
            } else if record.delegated_scopes.len() >= MAX_DELEGATES_PER_SECRET
                && !record.delegated_scopes.contains(&child)
            {
                Some(SecretLifecycleError::Capacity)
            } else {
                record.delegated_scopes.insert(child.clone());
                None
            }
        };
        if let Some(error) = error {
            return self.fail(SecretAuditAction::Delegate, reference, Some(&child), error);
        }
        self.record_allowed(
            SecretAuditAction::Delegate,
            Some(reference.clone()),
            Some(child),
        )
    }

    pub fn revoke(&mut self, reference: &SecretRef) -> Result<(), SecretLifecycleError> {
        self.ensure_audit_capacity()?;
        self.require_current(reference, SecretAuditAction::Revoke, None)?;
        let error = {
            let record = self
                .records
                .get_mut(reference.name())
                .ok_or_else(|| unknown_reference(reference))?;
            if record.state == SecretState::Destroyed {
                Some(SecretLifecycleError::Destroyed {
                    name: reference.name().to_string(),
                })
            } else {
                record.state = SecretState::Revoked;
                None
            }
        };
        if let Some(error) = error {
            return self.fail(SecretAuditAction::Revoke, reference, None, error);
        }
        self.record_allowed(SecretAuditAction::Revoke, Some(reference.clone()), None)
    }

    pub fn rotate_material(
        &mut self,
        reference: &SecretRef,
        material: &str,
    ) -> Result<SecretRef, SecretLifecycleError> {
        self.ensure_audit_capacity()?;
        if let Err(error) = validate_material(material) {
            self.record_denied(
                SecretAuditAction::Rotate,
                Some(reference.clone()),
                None,
                &error,
            )?;
            return Err(error);
        }
        let now = self.now_ms()?;
        self.require_current(reference, SecretAuditAction::Rotate, None)?;
        let inactive = self
            .records
            .get_mut(reference.name())
            .map(|record| {
                record.refresh_state(now);
                record.inactive_error(reference.name())
            })
            .ok_or_else(|| unknown_reference(reference))?;
        if let Some(error) = inactive {
            return self.fail(SecretAuditAction::Rotate, reference, None, error);
        }
        let rotated = {
            let record = self
                .records
                .get_mut(reference.name())
                .ok_or_else(|| unknown_reference(reference))?;
            record.push_residual();
            let generation = record
                .generation
                .checked_add(1)
                .ok_or(SecretLifecycleError::Capacity)?;
            record.generation = generation;
            record.material = Some(SecretBytes::from_str(material));
            record.state = SecretState::Bound;
            SecretRef::trusted(reference.name(), generation)
        };
        self.record_allowed(SecretAuditAction::Rotate, Some(rotated.clone()), None)?;
        Ok(rotated)
    }

    pub fn destroy(&mut self, reference: &SecretRef) -> Result<(), SecretLifecycleError> {
        self.ensure_audit_capacity()?;
        self.require_current(reference, SecretAuditAction::Destroy, None)?;
        if let Some(record) = self.records.get_mut(reference.name()) {
            record.push_residual();
            record.material = None;
            record.state = SecretState::Destroyed;
        }
        self.record_allowed(SecretAuditAction::Destroy, Some(reference.clone()), None)
    }

    pub fn destroy_all(&mut self) -> Result<(), SecretLifecycleError> {
        let references: Vec<SecretRef> = self
            .records
            .iter()
            .map(|(name, record)| SecretRef::trusted(name.clone(), record.generation))
            .collect();
        for reference in references {
            let already_destroyed = self
                .records
                .get(reference.name())
                .is_some_and(|record| record.state == SecretState::Destroyed);
            if !already_destroyed {
                self.destroy(&reference)?;
            }
        }
        Ok(())
    }

    /// End-of-run: destroy injection capability and drop residual redaction copies.
    pub fn finish(&mut self) -> Result<(), SecretLifecycleError> {
        self.destroy_all()?;
        for record in self.records.values_mut() {
            record.residual.clear();
            record.material = None;
        }
        self.ensure_audit_capacity()?;
        self.record_allowed(SecretAuditAction::Finish, None, None)
    }

    pub fn plan_bindings(&self) -> Vec<SecretPlanBinding> {
        self.records
            .iter()
            .map(|(name, record)| SecretPlanBinding {
                reference: SecretRef::trusted(name.clone(), record.generation),
                env_key: record.env_key.clone(),
                scope: record.scope.clone(),
                persistence: record.persistence,
                delegation: record.delegation,
            })
            .collect()
    }

    pub fn report(&mut self) -> Result<SecretLifecycleReport, SecretLifecycleError> {
        self.ensure_audit_capacity()?;
        self.record_allowed(SecretAuditAction::Report, None, None)?;
        Ok(SecretLifecycleReport {
            version: SECRET_LIFECYCLE_VERSION,
            secrets: self
                .records
                .iter()
                .map(|(name, record)| SecretStatusView {
                    reference: SecretRef::trusted(name.clone(), record.generation),
                    env_key: record.env_key.clone(),
                    scope: record.scope.clone(),
                    state: record.state,
                    persistence: record.persistence,
                    delegation: record.delegation,
                    delegated_scopes: record.delegated_scopes.iter().cloned().collect(),
                    expires_at_unix_ms: record.expires_at_unix_ms,
                })
                .collect(),
            audit: self.audit.clone(),
        })
    }

    pub fn audit_trail(&self) -> &SecretAuditTrail {
        &self.audit
    }

    /// Extends the existing LLM [`Redactor`] with every live and residual value.
    pub fn redactor(&self) -> Result<Redactor, SecretLifecycleError> {
        let mut redactor = Redactor::new();
        for (name, record) in &self.records {
            if let Some(material) = &record.material {
                redactor = redactor.with_private_value(name, material.as_str()?);
            }
            for residual in &record.residual {
                redactor = redactor.with_private_value(name, residual.as_str()?);
            }
        }
        Ok(redactor)
    }

    pub fn redact_text(&self, input: &str) -> Result<RedactedText, SecretLifecycleError> {
        Ok(self.redactor()?.redact(input))
    }

    pub fn redact_json(&self, value: &Value) -> Result<Value, SecretLifecycleError> {
        let redactor = self.redactor()?;
        Ok(redact_json_with(&redactor, value))
    }

    fn now_ms(&self) -> Result<u64, SecretLifecycleError> {
        if let Some(now) = self.clock_ms {
            return Ok(now);
        }
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SecretLifecycleError::ClockUnreadable)?;
        u64::try_from(elapsed.as_millis()).map_err(|_| SecretLifecycleError::ClockUnreadable)
    }

    fn ensure_audit_capacity(&self) -> Result<(), SecretLifecycleError> {
        if self.audit.len() >= MAX_AUDIT_EVENTS {
            Err(SecretLifecycleError::AuditCapacity)
        } else {
            Ok(())
        }
    }

    fn require_current(
        &mut self,
        reference: &SecretRef,
        action: SecretAuditAction,
        requester: Option<&SecretScope>,
    ) -> Result<(), SecretLifecycleError> {
        match self.records.get(reference.name()) {
            None => self.fail(action, reference, requester, unknown_reference(reference)),
            Some(record) if record.generation != reference.generation() => self.fail(
                action,
                reference,
                requester,
                SecretLifecycleError::StaleGeneration {
                    name: reference.name().to_string(),
                    generation: reference.generation(),
                },
            ),
            Some(_) => Ok(()),
        }
    }

    fn fail<T>(
        &mut self,
        action: SecretAuditAction,
        reference: &SecretRef,
        requester: Option<&SecretScope>,
        error: SecretLifecycleError,
    ) -> Result<T, SecretLifecycleError> {
        self.record_denied(action, Some(reference.clone()), requester.cloned(), &error)?;
        Err(error)
    }

    fn record_allowed(
        &mut self,
        action: SecretAuditAction,
        secret: Option<SecretRef>,
        requester: Option<SecretScope>,
    ) -> Result<(), SecretLifecycleError> {
        let unix_ms = self.now_ms()?;
        self.audit.push(SecretAuditEvent::new(
            unix_ms,
            action,
            secret,
            requester,
            SecretAuditOutcome::Allowed,
        ));
        Ok(())
    }

    fn record_denied(
        &mut self,
        action: SecretAuditAction,
        secret: Option<SecretRef>,
        requester: Option<SecretScope>,
        error: &SecretLifecycleError,
    ) -> Result<(), SecretLifecycleError> {
        let unix_ms = self.now_ms()?;
        self.audit.push(SecretAuditEvent::new(
            unix_ms,
            action,
            secret,
            requester,
            SecretAuditOutcome::denied_kind(error.kind_name()),
        ));
        Ok(())
    }
}

impl Default for SecretVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecretVault {
    fn drop(&mut self) {
        for record in self.records.values_mut() {
            record.material = None;
            record.residual.clear();
        }
        self.records.clear();
    }
}

impl std::fmt::Debug for SecretVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretVault")
            .field(
                "secrets",
                &self
                    .records
                    .iter()
                    .map(|(name, record)| (name.as_str(), record.state, record.generation))
                    .collect::<Vec<_>>(),
            )
            .field("audit_events", &self.audit.len())
            .finish()
    }
}

impl SecretRecord {
    fn authorized_for(&self, requester: &SecretScope) -> bool {
        *requester == self.scope || self.delegated_scopes.contains(requester)
    }

    fn refresh_state(&mut self, now_ms: u64) {
        if matches!(self.state, SecretState::Bound | SecretState::Declared) {
            if let Some(expires_at) = self.expires_at_unix_ms {
                if now_ms >= expires_at {
                    self.state = SecretState::Expired;
                }
            }
        }
    }

    fn inactive_error(&self, name: &str) -> Option<SecretLifecycleError> {
        match self.state {
            SecretState::Declared => Some(SecretLifecycleError::NotBound {
                name: name.to_string(),
            }),
            SecretState::Bound => None,
            SecretState::Revoked => Some(SecretLifecycleError::Revoked {
                name: name.to_string(),
            }),
            SecretState::Expired => Some(SecretLifecycleError::Expired {
                name: name.to_string(),
            }),
            SecretState::Destroyed => Some(SecretLifecycleError::Destroyed {
                name: name.to_string(),
            }),
        }
    }

    fn push_residual(&mut self) {
        if let Some(material) = self.material.take() {
            if self.residual.len() >= MAX_RESIDUAL_COPIES {
                self.residual.remove(0);
            }
            self.residual.push(material);
        }
    }
}

fn unknown_reference(reference: &SecretRef) -> SecretLifecycleError {
    SecretLifecycleError::UnknownReference {
        name: reference.name().to_string(),
        generation: reference.generation(),
    }
}

/// Serializable report. Proven not to contain raw material by construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLifecycleReport {
    pub version: u32,
    pub secrets: Vec<SecretStatusView>,
    pub audit: SecretAuditTrail,
}

fn redact_json_with(redactor: &Redactor, value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(redactor.redact(text).text),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| redact_json_with(redactor, value))
                .collect(),
        ),
        Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, value) in map {
                redacted.insert(redactor.redact(key).text, redact_json_with(redactor, value));
            }
            Value::Object(redacted)
        }
        other => other.clone(),
    }
}
