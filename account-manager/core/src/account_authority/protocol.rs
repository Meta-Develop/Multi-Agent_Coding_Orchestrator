//! Versioned headless authority envelope and closed operation dispatch.
//!
//! Framing bounds are compiled here. An operator may only tighten them.
//! This schema is not inherited from the relay, HTTP, SSE, or NDJSON.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::account_authority::{
    AccountObserveRequest, ObservationError, ObservationErrorKind, SelectedAccountBinding,
    StoredAccountRegistry,
};
use crate::error::Error;
use crate::login::{LoginAccountBinding, LoginHandle, LoginStartRequest, LoginStatus};
use crate::model::{AuthKind, StoredAccountState};
use crate::providers::{observe_selected_account, ProviderAdapter};
use crate::storage::CredentialStore;

/// Wire protocol version advertised and accepted by this slice.
pub const PROTOCOL_VERSION: u32 = 1;
/// Maximum UTF-8 JSON request object size, excluding the length prefix.
pub const MAX_REQUEST_BYTES: usize = 65536;
/// Maximum UTF-8 JSON response object size, excluding the length prefix.
pub const MAX_RESPONSE_BYTES: usize = 262144;
/// Deadline for one request's I/O after peer authorization.
pub const REQUEST_IO_DEADLINE: Duration = Duration::from_secs(5);

/// Closed operations this version promises to implement.
pub const ADVERTISED_OPERATIONS: [&str; 8] = [
    "authority.describe",
    "accounts.list",
    "selection.get",
    "selection.set",
    "account.observe",
    "login.start",
    "login.status",
    "login.cancel",
];

/// Closed error codes from the version 1 account-authority contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedVersion,
    AccessDenied,
    UnsupportedOperation,
    UnknownAccount,
    StaleSelection,
    StaleAccount,
    Busy,
    ReauthenticationRequired,
    Unavailable,
    StateUnavailable,
    OutcomeUnknown,
}

/// Wire error object. `code` is closed; `message` must not carry paths or secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
}

/// One versioned response: exactly one of `result` or `error`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityResponse {
    pub protocol_version: u32,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

impl AuthorityResponse {
    pub fn result(request_id: impl Into<String>, result: Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            result: Some(result),
            error: None,
        }
    }

    pub fn error(
        request_id: impl Into<String>,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            result: None,
            error: Some(WireError {
                code,
                message: sanitize_error_message(&message.into()),
            }),
        }
    }

    pub fn from_failure(failure: ProtocolFailure) -> Self {
        Self::error(failure.request_id, failure.code, failure.message)
    }
}

/// Decode or dispatch failure that still has a closed wire shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolFailure {
    pub request_id: String,
    pub code: ErrorCode,
    pub message: String,
}

impl ProtocolFailure {
    fn new(request_id: impl Into<String>, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            code,
            message: sanitize_error_message(&message.into()),
        }
    }
}

/// Operator-visible transport ceilings. Values must not exceed the compiled pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolBounds {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub request_io_deadline: Duration,
}

impl ProtocolBounds {
    pub fn compiled() -> Self {
        Self {
            max_request_bytes: MAX_REQUEST_BYTES,
            max_response_bytes: MAX_RESPONSE_BYTES,
            request_io_deadline: REQUEST_IO_DEADLINE,
        }
    }

    pub fn validate(self) -> Result<Self, ProtocolFailure> {
        if self.max_request_bytes == 0 || self.max_request_bytes > MAX_REQUEST_BYTES {
            return Err(ProtocolFailure::new(
                "",
                ErrorCode::InvalidRequest,
                "maxRequestBytes must be positive and at most the compiled ceiling",
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProtocolFailure::new(
                "",
                ErrorCode::InvalidRequest,
                "maxResponseBytes must be positive and at most the compiled ceiling",
            ));
        }
        if self.request_io_deadline.is_zero() || self.request_io_deadline > REQUEST_IO_DEADLINE {
            return Err(ProtocolFailure::new(
                "",
                ErrorCode::InvalidRequest,
                "request I/O deadline must be positive and at most the compiled ceiling",
            ));
        }
        Ok(self)
    }
}

/// Login seam used by dispatch so the protocol does not own OAuth.
pub trait LoginPort: Send + Sync {
    fn start(&self, request: LoginStartRequest) -> crate::error::Result<LoginStatus>;
    fn status(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> crate::error::Result<LoginStatus>;
    fn cancel(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> crate::error::Result<LoginStatus>;
}

/// Per-listener dispatch state. Adapters are optional; missing lookups use
/// [`crate::providers::find`] when `fallback_find` is true.
pub struct AuthorityContext {
    pub authority_id: String,
    pub registry: StoredAccountRegistry,
    pub login: Option<Arc<dyn LoginPort>>,
    pub adapters: BTreeMap<String, Arc<dyn ProviderAdapter>>,
    pub credential_store: Option<Arc<dyn CredentialStore>>,
    pub bounds: ProtocolBounds,
    pub fallback_find: bool,
}

impl AuthorityContext {
    pub fn new(registry: StoredAccountRegistry) -> Self {
        let authority_id = authority_id_for(registry.metadata_path());
        Self {
            authority_id,
            registry,
            login: None,
            adapters: BTreeMap::new(),
            credential_store: None,
            bounds: ProtocolBounds::compiled(),
            fallback_find: true,
        }
    }

    pub fn with_login(mut self, login: Arc<dyn LoginPort>) -> Self {
        self.login = Some(login);
        self
    }

    pub fn with_adapter(mut self, adapter: Arc<dyn ProviderAdapter>) -> Self {
        self.adapters.insert(adapter.id().to_string(), adapter);
        self
    }

    pub fn without_registry_fallback(mut self) -> Self {
        self.fallback_find = false;
        self
    }

    fn adapter(&self, provider_id: &str) -> crate::error::Result<Arc<dyn ProviderAdapter>> {
        if let Some(adapter) = self.adapters.get(provider_id) {
            return Ok(Arc::clone(adapter));
        }
        if self.fallback_find {
            if let Some(adapter) = crate::providers::find(provider_id) {
                return Ok(Arc::from(adapter));
            }
        }
        Err(Error::UnknownProvider(provider_id.to_string()))
    }
}

/// A decoded, version-1 request ready for [`dispatch`].
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedRequest {
    pub request_id: String,
    pub operation: DecodedOperation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecodedOperation {
    AuthorityDescribe,
    AccountsList {
        provider_id: String,
    },
    SelectionGet {
        provider_id: String,
    },
    SelectionSet {
        provider_id: String,
        account_id: String,
        account_incarnation: String,
        selection_revision: u64,
    },
    AccountObserve {
        authority_id: String,
        request: AccountObserveRequest,
    },
    LoginStart {
        provider_id: String,
        account_id: String,
        label: String,
        auth_kind: AuthKind,
        idempotency_key: String,
    },
    LoginStatus {
        handle: LoginHandle,
        binding: LoginAccountBinding,
    },
    LoginCancel {
        handle: LoginHandle,
        binding: LoginAccountBinding,
    },
    Unsupported {
        operation: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProviderOnlyParams {
    provider_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SelectionSetParams {
    provider_id: String,
    account_id: String,
    account_incarnation: String,
    selection_revision: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObserveParams {
    authority_id: String,
    binding: SelectedAccountBinding,
    categories: Vec<crate::account_authority::ObserveCategory>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginStartParams {
    provider_id: String,
    account_id: String,
    label: String,
    auth_kind: AuthKind,
    idempotency_key: String,
    #[serde(default)]
    account_incarnation: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginHandleParams {
    handle: LoginHandle,
    binding: LoginAccountBinding,
}

/// Opaque hex SHA-256 of the canonical `stored-accounts.json` path.
///
/// The digest is not a filesystem path and must not be treated as one.
pub fn authority_id_for(stored_accounts_path: &Path) -> String {
    let canonical = canonical_stored_accounts_path(stored_accounts_path);
    let mut hasher = Sha256::new();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.update(canonical.as_os_str().as_bytes());
    }
    #[cfg(not(unix))]
    {
        hasher.update(canonical.to_string_lossy().as_bytes());
    }
    hex_lower(&hasher.finalize())
}

fn canonical_stored_accounts_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }
    if let Some(parent) = path.parent() {
        if let (Ok(parent_canonical), Some(name)) = (fs::canonicalize(parent), path.file_name()) {
            return parent_canonical.join(name);
        }
    }
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// Parse one UTF-8 JSON object. Duplicate keys and unknown envelope fields fail.
pub fn decode_request(bytes: &[u8]) -> Result<DecodedRequest, ProtocolFailure> {
    if bytes.is_empty() {
        return Err(ProtocolFailure::new(
            "",
            ErrorCode::InvalidRequest,
            "request body is empty",
        ));
    }
    let value = parse_json_object_deny_duplicates(bytes)?;
    let Value::Object(mut object) = value else {
        return Err(ProtocolFailure::new(
            "",
            ErrorCode::InvalidRequest,
            "request must be one JSON object",
        ));
    };

    let protocol_version = match object.remove("protocolVersion") {
        Some(Value::Number(number)) => match number.as_u64() {
            Some(version) if version <= u64::from(u32::MAX) => version as u32,
            Some(_) => {
                return Err(ProtocolFailure::new(
                    take_request_id(&mut object),
                    ErrorCode::UnsupportedVersion,
                    "protocolVersion is not supported",
                ));
            }
            None => {
                return Err(ProtocolFailure::new(
                    take_request_id(&mut object),
                    ErrorCode::InvalidRequest,
                    "protocolVersion must be an integer",
                ));
            }
        },
        Some(_) => {
            return Err(ProtocolFailure::new(
                take_request_id(&mut object),
                ErrorCode::InvalidRequest,
                "protocolVersion must be an integer",
            ));
        }
        None => {
            return Err(ProtocolFailure::new(
                take_request_id(&mut object),
                ErrorCode::InvalidRequest,
                "protocolVersion is required",
            ));
        }
    };
    let request_id = match object.remove("requestId") {
        Some(Value::String(id)) if !id.is_empty() && id.len() <= 128 => id,
        Some(Value::String(_)) => {
            return Err(ProtocolFailure::new(
                "",
                ErrorCode::InvalidRequest,
                "requestId is empty or too long",
            ));
        }
        Some(_) => {
            return Err(ProtocolFailure::new(
                "",
                ErrorCode::InvalidRequest,
                "requestId must be a string",
            ));
        }
        None => {
            return Err(ProtocolFailure::new(
                "",
                ErrorCode::InvalidRequest,
                "requestId is required",
            ));
        }
    };
    if protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolFailure::new(
            request_id,
            ErrorCode::UnsupportedVersion,
            "protocolVersion is not supported",
        ));
    }
    let operation = match object.remove("operation") {
        Some(Value::String(operation)) if !operation.is_empty() => operation,
        Some(_) => {
            return Err(ProtocolFailure::new(
                request_id,
                ErrorCode::InvalidRequest,
                "operation must be a string",
            ));
        }
        None => {
            return Err(ProtocolFailure::new(
                request_id,
                ErrorCode::InvalidRequest,
                "operation is required",
            ));
        }
    };
    let params = Value::Object(object);
    decode_operation(request_id, operation, params)
}

fn take_request_id(object: &mut Map<String, Value>) -> String {
    match object.remove("requestId") {
        Some(Value::String(id)) => id,
        _ => String::new(),
    }
}

fn decode_operation(
    request_id: String,
    operation: String,
    params: Value,
) -> Result<DecodedRequest, ProtocolFailure> {
    let decoded = match operation.as_str() {
        "authority.describe" => {
            require_empty_params(&request_id, &params)?;
            DecodedOperation::AuthorityDescribe
        }
        "accounts.list" => {
            let parsed: ProviderOnlyParams = parse_params(&request_id, params)?;
            DecodedOperation::AccountsList {
                provider_id: parsed.provider_id,
            }
        }
        "selection.get" => {
            let parsed: ProviderOnlyParams = parse_params(&request_id, params)?;
            DecodedOperation::SelectionGet {
                provider_id: parsed.provider_id,
            }
        }
        "selection.set" => {
            let parsed: SelectionSetParams = parse_params(&request_id, params)?;
            DecodedOperation::SelectionSet {
                provider_id: parsed.provider_id,
                account_id: parsed.account_id,
                account_incarnation: parsed.account_incarnation,
                selection_revision: parsed.selection_revision,
            }
        }
        "account.observe" => {
            let parsed: ObserveParams = parse_params(&request_id, params)?;
            DecodedOperation::AccountObserve {
                authority_id: parsed.authority_id,
                request: AccountObserveRequest {
                    binding: parsed.binding,
                    categories: parsed.categories,
                },
            }
        }
        "login.start" => {
            let parsed: LoginStartParams = parse_params(&request_id, params)?;
            let _ = parsed.account_incarnation;
            DecodedOperation::LoginStart {
                provider_id: parsed.provider_id,
                account_id: parsed.account_id,
                label: parsed.label,
                auth_kind: parsed.auth_kind,
                idempotency_key: parsed.idempotency_key,
            }
        }
        "login.status" => {
            let parsed: LoginHandleParams = parse_params(&request_id, params)?;
            DecodedOperation::LoginStatus {
                handle: parsed.handle,
                binding: parsed.binding,
            }
        }
        "login.cancel" => {
            let parsed: LoginHandleParams = parse_params(&request_id, params)?;
            DecodedOperation::LoginCancel {
                handle: parsed.handle,
                binding: parsed.binding,
            }
        }
        _ => DecodedOperation::Unsupported { operation },
    };
    Ok(DecodedRequest {
        request_id,
        operation: decoded,
    })
}

fn require_empty_params(request_id: &str, params: &Value) -> Result<(), ProtocolFailure> {
    match params {
        Value::Object(object) if object.is_empty() => Ok(()),
        _ => Err(ProtocolFailure::new(
            request_id,
            ErrorCode::InvalidRequest,
            "authority.describe does not accept fields other than the envelope",
        )),
    }
}

fn parse_params<T: for<'de> Deserialize<'de>>(
    request_id: &str,
    params: Value,
) -> Result<T, ProtocolFailure> {
    serde_json::from_value(params).map_err(|error| {
        ProtocolFailure::new(
            request_id,
            ErrorCode::InvalidRequest,
            format!("request fields are invalid: {error}"),
        )
    })
}

/// Dispatch one already-decoded request. Peer authorization happens before this.
pub fn dispatch(ctx: &AuthorityContext, request: &DecodedRequest) -> AuthorityResponse {
    match &request.operation {
        DecodedOperation::AuthorityDescribe => describe(ctx, &request.request_id),
        DecodedOperation::AccountsList { provider_id } => {
            accounts_list(ctx, &request.request_id, provider_id)
        }
        DecodedOperation::SelectionGet { provider_id } => {
            selection_get(ctx, &request.request_id, provider_id)
        }
        DecodedOperation::SelectionSet {
            provider_id,
            account_id,
            account_incarnation,
            selection_revision,
        } => selection_set(
            ctx,
            &request.request_id,
            provider_id,
            account_id,
            account_incarnation,
            *selection_revision,
        ),
        DecodedOperation::AccountObserve {
            authority_id,
            request: observe,
        } => account_observe(ctx, &request.request_id, authority_id, observe),
        DecodedOperation::LoginStart {
            provider_id,
            account_id,
            label,
            auth_kind,
            idempotency_key,
        } => login_start(
            ctx,
            &request.request_id,
            provider_id,
            account_id,
            label,
            *auth_kind,
            idempotency_key,
        ),
        DecodedOperation::LoginStatus { handle, binding } => {
            login_status(ctx, &request.request_id, handle, binding)
        }
        DecodedOperation::LoginCancel { handle, binding } => {
            login_cancel(ctx, &request.request_id, handle, binding)
        }
        DecodedOperation::Unsupported { operation } => AuthorityResponse::error(
            request.request_id.clone(),
            ErrorCode::UnsupportedOperation,
            format!("operation `{operation}` is not advertised"),
        ),
    }
}

fn describe(ctx: &AuthorityContext, request_id: &str) -> AuthorityResponse {
    let transport = serde_json::json!({
        "kind": "unix-socket",
        "maxRequestBytes": ctx.bounds.max_request_bytes,
        "maxResponseBytes": ctx.bounds.max_response_bytes,
        "requestDeadlineMs": ctx.bounds.request_io_deadline.as_millis() as u64,
    });
    AuthorityResponse::result(
        request_id,
        serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "authorityId": ctx.authority_id,
            "operations": ADVERTISED_OPERATIONS,
            "transport": transport,
        }),
    )
}

fn accounts_list(ctx: &AuthorityContext, request_id: &str, provider_id: &str) -> AuthorityResponse {
    if provider_id.is_empty() {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::InvalidRequest,
            "providerId is required",
        );
    }
    let records = match ctx.registry.load() {
        Ok(accounts) => accounts
            .into_iter()
            .filter(|account| account.provider_id == provider_id)
            .collect::<Vec<_>>(),
        Err(error) => return map_core_error(request_id, &error),
    };
    let adapter = match ctx.adapter(provider_id) {
        Ok(adapter) => adapter,
        Err(error) => return map_core_error(request_id, &error),
    };
    let local_observations = match adapter.list_accounts() {
        Ok(accounts) => serde_json::json!({
            "outcome": "observed",
            "accounts": accounts,
        }),
        Err(error) => serde_json::json!({
            "outcome": "failed",
            "error": list_observation_error(&error),
        }),
    };
    AuthorityResponse::result(
        request_id,
        serde_json::json!({
            "records": records,
            "localObservations": local_observations,
        }),
    )
}

fn list_observation_error(error: &Error) -> ObservationError {
    let kind = match error {
        Error::ConfigRead { .. } => ObservationErrorKind::ConfigRead,
        Error::CredentialStoreUnavailable(_) => ObservationErrorKind::CredentialStoreUnavailable,
        _ => ObservationErrorKind::Other,
    };
    ObservationError {
        kind,
        message: sanitize_error_message(&closed_core_message(error).1),
    }
}

fn selection_get(ctx: &AuthorityContext, request_id: &str, provider_id: &str) -> AuthorityResponse {
    if provider_id.is_empty() {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::InvalidRequest,
            "providerId is required",
        );
    }
    let revision = match ctx.registry.selection_revision(provider_id) {
        Ok(revision) => revision,
        Err(error) => return map_core_error(request_id, &error),
    };
    match ctx.registry.selected_binding(provider_id) {
        Ok(Some(binding)) => AuthorityResponse::result(
            request_id,
            serde_json::json!({
                "selected": true,
                "authorityId": ctx.authority_id,
                "providerId": binding.provider_id,
                "accountId": binding.account_id,
                "accountIncarnation": binding.account_incarnation,
                "selectionRevision": binding.selection_revision,
            }),
        ),
        Ok(None) => AuthorityResponse::result(
            request_id,
            serde_json::json!({
                "selected": false,
                "authorityId": ctx.authority_id,
                "providerId": provider_id,
                "selectionRevision": revision,
            }),
        ),
        Err(error) => map_core_error(request_id, &error),
    }
}

fn selection_set(
    ctx: &AuthorityContext,
    request_id: &str,
    provider_id: &str,
    account_id: &str,
    account_incarnation: &str,
    selection_revision: u64,
) -> AuthorityResponse {
    if provider_id.is_empty() || account_id.is_empty() || account_incarnation.is_empty() {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::InvalidRequest,
            "selection.set requires providerId, accountId, and accountIncarnation",
        );
    }
    let account = match ctx.registry.account(provider_id, account_id) {
        Ok(account) => account,
        Err(error) => return map_core_error(request_id, &error),
    };
    if account.account_incarnation != account_incarnation {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::StaleAccount,
            "account incarnation does not match",
        );
    }
    if account.state != StoredAccountState::Complete {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::UnknownAccount,
            "account is not a complete selectable account",
        );
    }
    match ctx
        .registry
        .select_complete_revision(provider_id, account_id, Some(selection_revision))
    {
        Ok(binding) => AuthorityResponse::result(
            request_id,
            serde_json::json!({
                "selected": true,
                "authorityId": ctx.authority_id,
                "providerId": binding.provider_id,
                "accountId": binding.account_id,
                "accountIncarnation": binding.account_incarnation,
                "selectionRevision": binding.selection_revision,
            }),
        ),
        Err(error) => map_core_error(request_id, &error),
    }
}

fn account_observe(
    ctx: &AuthorityContext,
    request_id: &str,
    authority_id: &str,
    request: &AccountObserveRequest,
) -> AuthorityResponse {
    if authority_id != ctx.authority_id {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::AccessDenied,
            "authorityId does not match this authority",
        );
    }
    let adapter = match ctx.adapter(&request.binding.provider_id) {
        Ok(adapter) => adapter,
        Err(error) => return map_core_error(request_id, &error),
    };
    let store = ctx.credential_store.as_deref();
    match observe_selected_account(&ctx.registry, adapter.as_ref(), request.clone(), store) {
        Ok(result) => match serde_json::to_value(result) {
            Ok(value) => AuthorityResponse::result(request_id, value),
            Err(error) => map_core_error(request_id, &Error::from(error)),
        },
        Err(error) => map_core_error(request_id, &error),
    }
}

fn login_start(
    ctx: &AuthorityContext,
    request_id: &str,
    provider_id: &str,
    account_id: &str,
    label: &str,
    auth_kind: AuthKind,
    idempotency_key: &str,
) -> AuthorityResponse {
    if provider_id != "gemini-cli"
        && provider_id != "codex-cli"
        && provider_id != "claude-code"
        && provider_id != "cursor"
    {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::UnsupportedOperation,
            "login.start is implemented for Gemini, Codex, Claude, and Cursor only",
        );
    }
    let Some(login) = ctx.login.as_ref() else {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::Unavailable,
            "login service is not configured",
        );
    };
    match login.start(LoginStartRequest {
        provider_id: provider_id.to_string(),
        account_id: account_id.to_string(),
        label: label.to_string(),
        auth_kind,
        idempotency_key: idempotency_key.to_string(),
    }) {
        Ok(status) => login_status_result(request_id, status),
        Err(error) => map_core_error(request_id, &error),
    }
}

fn login_status(
    ctx: &AuthorityContext,
    request_id: &str,
    handle: &LoginHandle,
    binding: &LoginAccountBinding,
) -> AuthorityResponse {
    let Some(login) = ctx.login.as_ref() else {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::Unavailable,
            "login service is not configured",
        );
    };
    match login.status(handle, binding) {
        Ok(status) => login_status_result(request_id, status),
        Err(error) => map_core_error(request_id, &error),
    }
}

fn login_cancel(
    ctx: &AuthorityContext,
    request_id: &str,
    handle: &LoginHandle,
    binding: &LoginAccountBinding,
) -> AuthorityResponse {
    let Some(login) = ctx.login.as_ref() else {
        return AuthorityResponse::error(
            request_id,
            ErrorCode::Unavailable,
            "login service is not configured",
        );
    };
    match login.cancel(handle, binding) {
        Ok(status) => login_status_result(request_id, status),
        Err(error) => map_core_error(request_id, &error),
    }
}

fn login_status_result(request_id: &str, status: LoginStatus) -> AuthorityResponse {
    match serde_json::to_value(status) {
        Ok(value) => AuthorityResponse::result(request_id, value),
        Err(error) => map_core_error(request_id, &Error::from(error)),
    }
}

/// Map a core error to a closed wire error without paths or secrets.
pub fn map_core_error(request_id: impl Into<String>, error: &Error) -> AuthorityResponse {
    let (code, message) = closed_core_message(error);
    AuthorityResponse::error(request_id, code, message)
}

fn closed_core_message(error: &Error) -> (ErrorCode, String) {
    match error {
        Error::UnknownProvider(_) => (
            ErrorCode::InvalidRequest,
            "provider is not registered".to_string(),
        ),
        Error::UnknownAccount(_) => (
            ErrorCode::UnknownAccount,
            "account is not registered".to_string(),
        ),
        Error::NoSelectedAccount(_) => (
            ErrorCode::UnknownAccount,
            "no complete account is selected".to_string(),
        ),
        Error::StaleSelection { .. } => (
            ErrorCode::StaleSelection,
            "selection revision does not match".to_string(),
        ),
        Error::StaleAccount { .. } => (
            ErrorCode::StaleAccount,
            "account incarnation does not match".to_string(),
        ),
        Error::AccountAuthorityBusy { .. } => {
            (ErrorCode::Busy, "account authority is busy".to_string())
        }
        Error::ProviderNotInstalled { .. } => (
            ErrorCode::Unavailable,
            "provider is not installed".to_string(),
        ),
        Error::CredentialStoreUnavailable(_) => (
            ErrorCode::StateUnavailable,
            "credential store is unavailable".to_string(),
        ),
        Error::ConfigRead { .. } => (
            ErrorCode::StateUnavailable,
            "account state could not be read".to_string(),
        ),
        Error::ConfigWrite { .. } => (ErrorCode::InvalidRequest, "request was refused".to_string()),
        Error::NotImplemented(_) => (
            ErrorCode::UnsupportedOperation,
            "operation is not implemented".to_string(),
        ),
        Error::Io(_) => (
            ErrorCode::Unavailable,
            "a local I/O operation failed".to_string(),
        ),
        Error::Serde(_) => (
            ErrorCode::StateUnavailable,
            "stored metadata could not be interpreted".to_string(),
        ),
    }
}

fn sanitize_error_message(message: &str) -> String {
    let mut sanitized = String::new();
    for token in message.split_whitespace() {
        let piece = if token_looks_sensitive(token) {
            "<redacted>"
        } else {
            token
        };
        if !sanitized.is_empty() {
            sanitized.push(' ');
        }
        sanitized.push_str(piece);
    }
    if sanitized.is_empty() {
        "request failed".to_string()
    } else {
        sanitized
    }
}

fn token_looks_sensitive(token: &str) -> bool {
    token.contains("FAKE-")
        || token.contains("GOCSPX-")
        || token.contains('@')
        || token.contains('/')
        || token.contains('\\')
        || token.contains("stored-accounts")
}

fn parse_json_object_deny_duplicates(bytes: &[u8]) -> Result<Value, ProtocolFailure> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let parsed = StrictValue::deserialize(&mut deserializer).map_err(|error| {
        let code = ErrorCode::InvalidRequest;
        ProtocolFailure::new("", code, format!("request JSON is invalid: {error}"))
    })?;
    deserializer.end().map_err(|error| {
        ProtocolFailure::new(
            "",
            ErrorCode::InvalidRequest,
            format!("request must be one JSON object: {error}"),
        )
    })?;
    if parsed.0.is_object() {
        Ok(parsed.0)
    } else {
        Err(ProtocolFailure::new(
            "",
            ErrorCode::InvalidRequest,
            "request must be one JSON object",
        ))
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::from(value)))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::from(value)))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Ok(StrictValue(
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
        ))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_string())))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<StrictValue>()? {
            items.push(item.0);
        }
        Ok(StrictValue(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate field `{key}`")));
            }
            let value = map.next_value::<StrictValue>()?;
            object.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(object)))
    }
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
