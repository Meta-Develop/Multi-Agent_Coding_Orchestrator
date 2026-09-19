//! Durable `operation.prepare` records for the account-authority library.
//!
//! This module records prepared intent and durable start/status/cancel state
//! transitions in-library only. It does not advertise `operation.prepare`,
//! `operation.start`, `operation.status`, or `operation.cancel`.
//! Callers pass already-decoded typed fields; this module does not parse JSON.
//!
//! The digest is an integrity join, not a quality certificate or proof of
//! provider containment.
//!
//! ## Canonical binding-digest encoding
//!
//! The digest is the lowercase hex SHA-256 of a versioned preimage (64 ASCII
//! characters). The preimage starts with the ASCII bytes
//! `operation.prepare.binding.v1` followed by a single `0x00` byte.
//!
//! Each following field is encoded as: UTF-8 field name, `0x00`, a 32-bit
//! big-endian value length, then exactly that many UTF-8 bytes. Field order is
//! part of the encoding:
//!
//! 1. `authorityId`
//! 2. `callerIdentity`
//! 3. `providerId`
//! 4. `accountId`
//! 5. `accountIncarnation`
//! 6. `selectionRevision`
//! 7. `operationKind`
//! 8. `modelId`
//! 9. `reasoningEffort`
//! 10. `prompt`
//! 11. `context`
//! 12. `callerPolicyDigest`
//! 13. `admissionRequirements.count`
//! 14. `admissionRequirements.<i>` in request order, `i` starting at `0`
//! 15. `idempotencyKey`
//!
//! `selectionRevision` is the decimal form of the `u64` with no leading zeros
//! (`0` is encoded as `0`). `admissionRequirements.count` is the decimal
//! length. The accepted request fields, authority, caller identity, account
//! incarnation, and selected revision are all bound. Length prefixes make
//! embedded separators in values unable to forge another field layout.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

use super::binding::SelectedAccountBinding;

/// Already-decoded `operation.prepare` fields. Callers must not re-parse JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationPrepareRequest {
    pub binding: SelectedAccountBinding,
    pub operation_kind: String,
    pub model_id: String,
    pub reasoning_effort: String,
    pub prompt: String,
    pub context: String,
    pub caller_policy_digest: String,
    pub admission_requirements: Vec<String>,
    pub idempotency_key: String,
}

/// Authority and authorized caller bound into the digest, supplied after peer
/// authorization. These are not read from the request JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationPrepareIdentity {
    pub authority_id: String,
    pub caller_identity: String,
}

/// Opaque operation handle. Never encodes provider or account identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OperationHandle(String);

/// Recorded operation state for this in-library slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreparedOperationState {
    Prepared,
    Running,
    Cancelled,
}

/// Durable prepared-operation record: opaque handle, binding digest, state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedOperation {
    pub handle: OperationHandle,
    pub digest: String,
    pub state: PreparedOperationState,
}

/// In-process store of prepared-operation rows keyed by idempotency key.
pub struct PreparedOperationStore {
    inner: Mutex<StoreInner>,
}

struct StoreInner {
    by_key: HashMap<String, PreparedOperation>,
    by_handle: HashMap<OperationHandle, String>,
}

impl PreparedOperationStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(StoreInner {
                by_key: HashMap::new(),
                by_handle: HashMap::new(),
            }),
        }
    }

    /// Persist one prepared operation, or replay an identical idempotent request.
    ///
    /// Same key and same bound content return the original handle without a
    /// second row. Same key and different content are refused.
    pub fn prepare(
        &self,
        identity: &OperationPrepareIdentity,
        request: &OperationPrepareRequest,
    ) -> Result<PreparedOperation> {
        validate_prepare(request)?;
        let digest = canonical_binding_digest(identity, request);
        {
            let inner = self.inner.lock().expect("prepared-operation lock");
            if let Some(row) = inner.by_key.get(&request.idempotency_key) {
                return replay_or_refuse(row, &digest, &request.binding.provider_id);
            }
        }

        let handle = new_operation_handle()?;
        let record = PreparedOperation {
            handle,
            digest,
            state: PreparedOperationState::Prepared,
        };
        let mut inner = self.inner.lock().expect("prepared-operation lock");
        if let Some(row) = inner.by_key.get(&request.idempotency_key) {
            return replay_or_refuse(row, &record.digest, &request.binding.provider_id);
        }
        inner
            .by_handle
            .insert(record.handle.clone(), request.idempotency_key.clone());
        inner
            .by_key
            .insert(request.idempotency_key.clone(), record.clone());
        Ok(record)
    }

    /// Transition `prepared` → `running`. Does not launch providers.
    pub fn start(&self, handle: &OperationHandle, digest: &str) -> Result<PreparedOperation> {
        let mut inner = self.inner.lock().expect("prepared-operation lock");
        let row = lookup_row_mut(&mut inner, handle, digest)?;
        match row.state {
            PreparedOperationState::Prepared => {
                row.state = PreparedOperationState::Running;
            }
            PreparedOperationState::Running => {
                return Err(operation_refused(
                    "account-metadata",
                    "operation is already running",
                ));
            }
            PreparedOperationState::Cancelled => {
                return Err(operation_refused(
                    "account-metadata",
                    "operation was cancelled",
                ));
            }
        }
        Ok(row.clone())
    }

    /// Return the durable state for `handle` without inventing execution evidence.
    pub fn status(&self, handle: &OperationHandle, digest: &str) -> Result<PreparedOperationState> {
        let inner = self.inner.lock().expect("prepared-operation lock");
        let row = lookup_row_ref(&inner, handle, digest)?;
        Ok(row.state.clone())
    }

    /// Transition `prepared` or `running` → `cancelled`. Already-cancelled is idempotent.
    pub fn cancel(&self, handle: &OperationHandle, digest: &str) -> Result<PreparedOperation> {
        let mut inner = self.inner.lock().expect("prepared-operation lock");
        let row = lookup_row_mut(&mut inner, handle, digest)?;
        if row.state != PreparedOperationState::Cancelled {
            row.state = PreparedOperationState::Cancelled;
        }
        Ok(row.clone())
    }

    #[cfg(test)]
    fn row_count(&self) -> usize {
        self.inner
            .lock()
            .expect("prepared-operation lock")
            .by_key
            .len()
    }
}

impl Default for PreparedOperationStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Lowercase hex SHA-256 of the canonical prepare binding preimage.
pub fn canonical_binding_digest(
    identity: &OperationPrepareIdentity,
    request: &OperationPrepareRequest,
) -> String {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"operation.prepare.binding.v1\0");
    append_str(&mut preimage, "authorityId", &identity.authority_id);
    append_str(&mut preimage, "callerIdentity", &identity.caller_identity);
    append_str(&mut preimage, "providerId", &request.binding.provider_id);
    append_str(&mut preimage, "accountId", &request.binding.account_id);
    append_str(
        &mut preimage,
        "accountIncarnation",
        &request.binding.account_incarnation,
    );
    append_str(
        &mut preimage,
        "selectionRevision",
        &request.binding.selection_revision.to_string(),
    );
    append_str(&mut preimage, "operationKind", &request.operation_kind);
    append_str(&mut preimage, "modelId", &request.model_id);
    append_str(&mut preimage, "reasoningEffort", &request.reasoning_effort);
    append_str(&mut preimage, "prompt", &request.prompt);
    append_str(&mut preimage, "context", &request.context);
    append_str(
        &mut preimage,
        "callerPolicyDigest",
        &request.caller_policy_digest,
    );
    append_str(
        &mut preimage,
        "admissionRequirements.count",
        &request.admission_requirements.len().to_string(),
    );
    for (index, requirement) in request.admission_requirements.iter().enumerate() {
        append_str(
            &mut preimage,
            &format!("admissionRequirements.{index}"),
            requirement,
        );
    }
    append_str(&mut preimage, "idempotencyKey", &request.idempotency_key);
    hex_lower(Sha256::digest(preimage).as_ref())
}

fn append_str(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn validate_prepare(request: &OperationPrepareRequest) -> Result<()> {
    if request.idempotency_key.is_empty() || request.idempotency_key.len() > 128 {
        return Err(prepare_refused(
            &request.binding.provider_id,
            "idempotency key is missing or too long",
        ));
    }
    Ok(())
}

fn replay_or_refuse(
    row: &PreparedOperation,
    digest: &str,
    provider_id: &str,
) -> Result<PreparedOperation> {
    if row.digest != digest {
        return Err(prepare_refused(
            provider_id,
            "idempotency key was reused with a different operation request",
        ));
    }
    Ok(row.clone())
}

fn new_operation_handle() -> Result<OperationHandle> {
    let mut bytes = [0u8; 24];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| prepare_refused("account-metadata", "operation handle entropy unavailable"))?;
    Ok(OperationHandle(URL_SAFE_NO_PAD.encode(bytes)))
}

fn prepare_refused(provider: &str, reason: impl Into<String>) -> Error {
    Error::ConfigWrite {
        provider: provider.to_string(),
        reason: reason.into(),
    }
}

fn operation_refused(provider: &str, reason: impl Into<String>) -> Error {
    prepare_refused(provider, reason)
}

fn lookup_row_ref<'a>(
    inner: &'a StoreInner,
    handle: &OperationHandle,
    digest: &str,
) -> Result<&'a PreparedOperation> {
    let key = inner
        .by_handle
        .get(handle)
        .ok_or_else(|| operation_refused("account-metadata", "unknown operation handle"))?;
    let row = inner
        .by_key
        .get(key)
        .ok_or_else(|| operation_refused("account-metadata", "unknown operation handle"))?;
    if row.digest != digest {
        return Err(operation_refused(
            "account-metadata",
            "operation handle does not match the supplied binding digest",
        ));
    }
    Ok(row)
}

fn lookup_row_mut<'a>(
    inner: &'a mut StoreInner,
    handle: &OperationHandle,
    digest: &str,
) -> Result<&'a mut PreparedOperation> {
    let key = inner
        .by_handle
        .get(handle)
        .cloned()
        .ok_or_else(|| operation_refused("account-metadata", "unknown operation handle"))?;
    let row = inner
        .by_key
        .get_mut(&key)
        .ok_or_else(|| operation_refused("account-metadata", "unknown operation handle"))?;
    if row.digest != digest {
        return Err(operation_refused(
            "account-metadata",
            "operation handle does not match the supplied binding digest",
        ));
    }
    Ok(row)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::account_authority::protocol::DecodedOperation;
    use crate::account_authority::{
        decode_request, dispatch, AuthorityContext, ErrorCode, SelectedAccountBinding,
        StoredAccountRegistry, ADVERTISED_OPERATIONS, PROTOCOL_VERSION,
    };
    use crate::error::Error;
    use crate::paths::stored_accounts_path;

    const POLICY_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn identity() -> OperationPrepareIdentity {
        OperationPrepareIdentity {
            authority_id: POLICY_DIGEST.to_string(),
            caller_identity: "caller-1".to_string(),
        }
    }

    fn request() -> OperationPrepareRequest {
        OperationPrepareRequest {
            binding: SelectedAccountBinding {
                provider_id: "gemini-cli".to_string(),
                account_id: "work".to_string(),
                account_incarnation: "inc-1".to_string(),
                selection_revision: 1,
            },
            operation_kind: "work-proposal".to_string(),
            model_id: "gemini-2.5-pro".to_string(),
            reasoning_effort: "high".to_string(),
            prompt: "propose the next edit".to_string(),
            context: String::new(),
            caller_policy_digest: POLICY_DIGEST.to_string(),
            admission_requirements: vec!["admit-a".to_string(), "admit-b".to_string()],
            idempotency_key: "prep-1".to_string(),
        }
    }

    fn isolated_registry() -> (tempfile::TempDir, StoredAccountRegistry) {
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).expect("data");
        let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
        (dir, registry)
    }

    fn operation_prepare_body() -> serde_json::Value {
        serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": "prep",
            "operation": "operation.prepare",
            "binding": {
                "providerId": "gemini-cli",
                "accountId": "work",
                "accountIncarnation": "inc-1",
                "selectionRevision": 1
            },
            "operationKind": "work-proposal",
            "modelId": "gemini-2.5-pro",
            "reasoningEffort": "high",
            "prompt": "propose the next edit",
            "context": "",
            "callerPolicyDigest": POLICY_DIGEST,
            "admissionRequirements": ["admit-a", "admit-b"],
            "idempotencyKey": "prep-1"
        })
    }

    #[test]
    fn digest_is_stable_for_identical_fields() {
        let first = canonical_binding_digest(&identity(), &request());
        let second = canonical_binding_digest(&identity(), &request());
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
    }

    type DigestMutation = fn(&mut OperationPrepareIdentity, &mut OperationPrepareRequest);

    #[test]
    fn digest_changes_when_any_bound_field_changes() {
        let baseline = canonical_binding_digest(&identity(), &request());
        let mutations: &[(&str, DigestMutation)] = &[
            ("authorityId", |identity, _| {
                identity.authority_id.push('b');
            }),
            ("callerIdentity", |identity, _| {
                identity.caller_identity.push('x');
            }),
            ("providerId", |_, request| {
                request.binding.provider_id.push('x');
            }),
            ("accountId", |_, request| {
                request.binding.account_id.push('x');
            }),
            ("accountIncarnation", |_, request| {
                request.binding.account_incarnation.push('x');
            }),
            ("selectionRevision", |_, request| {
                request.binding.selection_revision += 1;
            }),
            ("operationKind", |_, request| {
                request.operation_kind.push('x');
            }),
            ("modelId", |_, request| request.model_id.push('x')),
            ("reasoningEffort", |_, request| {
                request.reasoning_effort.push('x');
            }),
            ("prompt", |_, request| request.prompt.push('x')),
            ("context", |_, request| request.context.push('x')),
            ("callerPolicyDigest", |_, request| {
                request.caller_policy_digest =
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
            }),
            ("admission item", |_, request| {
                request.admission_requirements[0].push('x');
            }),
            ("admission order", |_, request| {
                request.admission_requirements.swap(0, 1);
            }),
            ("admission count", |_, request| {
                request.admission_requirements.push("admit-c".to_string());
            }),
            ("idempotencyKey", |_, request| {
                request.idempotency_key.push('x');
            }),
        ];
        for (label, mutate) in mutations {
            let mut identity = identity();
            let mut request = request();
            mutate(&mut identity, &mut request);
            assert_ne!(
                baseline,
                canonical_binding_digest(&identity, &request),
                "{label} must change the binding digest"
            );
        }
    }

    #[test]
    fn idempotent_replay_returns_same_handle_without_second_row() {
        let store = PreparedOperationStore::new();
        let first = store
            .prepare(&identity(), &request())
            .expect("first prepare");
        let second = store
            .prepare(&identity(), &request())
            .expect("idempotent replay");
        assert_eq!(first.handle, second.handle);
        assert_eq!(first.digest, second.digest);
        assert_eq!(first.state, PreparedOperationState::Prepared);
        assert_eq!(second.state, PreparedOperationState::Prepared);
        assert_eq!(store.row_count(), 1);
        assert!(!first.handle.0.contains("gemini-cli"));
        assert!(!first.handle.0.contains("work"));
    }

    #[test]
    fn idempotency_mismatch_is_refused_without_extra_row() {
        let store = PreparedOperationStore::new();
        store
            .prepare(&identity(), &request())
            .expect("first prepare");
        let mut changed = request();
        changed.prompt = "a different prompt".to_string();
        assert!(matches!(
            store.prepare(&identity(), &changed),
            Err(Error::ConfigWrite { reason, .. })
                if reason == "idempotency key was reused with a different operation request"
        ));
        assert_eq!(store.row_count(), 1);
    }

    #[test]
    fn persist_accepts_already_decoded_prepare_fields() {
        let decoded = decode_request(operation_prepare_body().to_string().as_bytes())
            .expect("well-formed prepare decodes");
        let DecodedOperation::OperationPrepare {
            binding,
            operation_kind,
            model_id,
            reasoning_effort,
            prompt,
            context,
            caller_policy_digest,
            admission_requirements,
            idempotency_key,
        } = decoded.operation
        else {
            panic!("expected decoded operation.prepare fields");
        };
        let request = OperationPrepareRequest {
            binding,
            operation_kind,
            model_id,
            reasoning_effort,
            prompt,
            context,
            caller_policy_digest,
            admission_requirements,
            idempotency_key,
        };
        let record = PreparedOperationStore::new()
            .prepare(&identity(), &request)
            .expect("persist decoded fields");
        assert_eq!(record.state, PreparedOperationState::Prepared);
        assert_eq!(
            record.digest,
            canonical_binding_digest(&identity(), &request)
        );
    }

    fn prepared_record() -> PreparedOperation {
        PreparedOperationStore::new()
            .prepare(&identity(), &request())
            .expect("prepare")
    }

    #[test]
    fn start_transitions_prepared_to_running() {
        let store = PreparedOperationStore::new();
        let prepared = store.prepare(&identity(), &request()).expect("prepare");
        let started = store
            .start(&prepared.handle, &prepared.digest)
            .expect("start");
        assert_eq!(started.state, PreparedOperationState::Running);
        assert_eq!(
            store
                .status(&prepared.handle, &prepared.digest)
                .expect("status"),
            PreparedOperationState::Running
        );
    }

    #[test]
    fn cancel_is_idempotent_from_cancelled() {
        let store = PreparedOperationStore::new();
        let prepared = store.prepare(&identity(), &request()).expect("prepare");
        let cancelled = store
            .cancel(&prepared.handle, &prepared.digest)
            .expect("cancel");
        assert_eq!(cancelled.state, PreparedOperationState::Cancelled);
        let again = store
            .cancel(&prepared.handle, &prepared.digest)
            .expect("idempotent cancel");
        assert_eq!(again.state, PreparedOperationState::Cancelled);
    }

    #[test]
    fn cancel_from_running_sets_cancelled() {
        let store = PreparedOperationStore::new();
        let prepared = store.prepare(&identity(), &request()).expect("prepare");
        store
            .start(&prepared.handle, &prepared.digest)
            .expect("start");
        let cancelled = store
            .cancel(&prepared.handle, &prepared.digest)
            .expect("cancel");
        assert_eq!(cancelled.state, PreparedOperationState::Cancelled);
    }

    #[test]
    fn unknown_handle_refused_without_new_row() {
        let store = PreparedOperationStore::new();
        store.prepare(&identity(), &request()).expect("prepare");
        let handle = OperationHandle("missing-handle".to_string());
        let digest = canonical_binding_digest(&identity(), &request());
        assert!(matches!(
            store.start(&handle, &digest),
            Err(Error::ConfigWrite { reason, .. }) if reason == "unknown operation handle"
        ));
        assert_eq!(store.row_count(), 1);
    }

    #[test]
    fn digest_mismatch_refused_without_state_change() {
        let store = PreparedOperationStore::new();
        let prepared = store.prepare(&identity(), &request()).expect("prepare");
        let wrong = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(matches!(
            store.start(&prepared.handle, wrong),
            Err(Error::ConfigWrite { reason, .. })
                if reason == "operation handle does not match the supplied binding digest"
        ));
        assert_eq!(
            store
                .status(&prepared.handle, &prepared.digest)
                .expect("status"),
            PreparedOperationState::Prepared
        );
    }

    #[test]
    fn persist_does_not_advertise_or_dispatch_operation_lifecycle() {
        assert_eq!(ADVERTISED_OPERATIONS.len(), 8);
        for name in [
            "operation.prepare",
            "operation.start",
            "operation.status",
            "operation.cancel",
        ] {
            assert!(!ADVERTISED_OPERATIONS.contains(&name));
        }
        assert!(!ADVERTISED_OPERATIONS
            .iter()
            .any(|name| name.starts_with("operation.")));

        let (_dir, registry) = isolated_registry();
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        let decoded = decode_request(operation_prepare_body().to_string().as_bytes())
            .expect("well-formed prepare decodes");
        let response = dispatch(&ctx, &decoded);
        let error = response.error.expect("dispatch stays unsupported");
        assert_eq!(error.code, ErrorCode::UnsupportedOperation);
        assert_eq!(
            error.message,
            "operation.prepare is not advertised until a provider \
advertises work-proposal tool restrictions"
        );
        assert!(response.result.is_none());

        let prepared = prepared_record();
        for operation in ["operation.start", "operation.status", "operation.cancel"] {
            let body = serde_json::json!({
                "protocolVersion": PROTOCOL_VERSION,
                "requestId": operation,
                "operation": operation,
                "handle": prepared.handle.0,
                "digest": prepared.digest,
            });
            let decoded = decode_request(body.to_string().as_bytes()).expect("decode");
            let response = dispatch(&ctx, &decoded);
            let error = response.error.expect("unsupported");
            assert_eq!(error.code, ErrorCode::UnsupportedOperation);
            assert_eq!(
                error.message,
                format!(
                    "{operation} is not advertised until a provider \
advertises work-proposal tool restrictions"
                )
            );
            assert!(response.result.is_none());
        }
    }
}
