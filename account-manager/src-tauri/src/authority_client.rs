//! Desktop RPC client for the existing headless account authority.
//!
//! Framing matches [`coding_agent_manager_core::account_authority::server`].

#[cfg(not(windows))]
use crate::account_authority::SocketPathError;
use crate::account_authority::StoredAccountRegistry;
use crate::error::{Error, Result};
use crate::providers::{self, ProviderAdapter};

#[cfg(unix)]
use crate::account_authority::resolve_socket_path;
use crate::account_authority::{
    validate_observed_models_for_binding, AccountObserveRequest, AccountObserveResult,
    AuthorityResponse, ErrorCode, SelectedAccountBinding, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION, REQUEST_IO_DEADLINE,
};
use crate::account_authority::{LaunchOperationStatus, OperationHandle};
use crate::login::{LoginAccountBinding, LoginHandle, LoginStartRequest};
use crate::login_ipc::LoginIpcStatus;
use crate::model::{StoredAccountMetadata, StoredAccountState};
use serde_json::{json, Value};
#[cfg(unix)]
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Environment variable naming the headless authority Unix socket path.
#[cfg(not(windows))]
pub const CAM_ACCOUNT_AUTHORITY_SOCKET_ENV: &str = "CAM_ACCOUNT_AUTHORITY_SOCKET";

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Either the in-process registry or a remote authority socket client.
pub enum AccountAuthority {
    // Windows constructors use Remote; Unix retains this in-process fallback.
    #[cfg_attr(windows, allow(dead_code))]
    InProcess(StoredAccountRegistry),
    Remote(AuthorityClient),
}

impl AccountAuthority {
    pub fn in_process_registry(&self) -> Result<&StoredAccountRegistry> {
        match self {
            Self::InProcess(registry) => Ok(registry),
            Self::Remote(_) => Err(external_registry_error()),
        }
    }
}

/// Resolve the installed Windows connection or explicit native Unix override.
pub fn account_authority() -> Result<AccountAuthority> {
    #[cfg(windows)]
    {
        connection::load()
            .map(|record| AccountAuthority::Remote(AuthorityClient::from_connection(record)))
    }
    #[cfg(not(windows))]
    {
        authority_from_environment()
    }
}

#[cfg(not(windows))]
fn authority_from_environment() -> Result<AccountAuthority> {
    match std::env::var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV) {
        Err(_) => Ok(AccountAuthority::InProcess(
            in_process_stored_account_registry()?,
        )),
        Ok(path) if path.trim().is_empty() => Ok(AccountAuthority::InProcess(
            in_process_stored_account_registry()?,
        )),
        Ok(path) => connect_remote_authority(&path),
    }
}

#[cfg(not(windows))]
pub(crate) fn in_process_stored_account_registry() -> Result<StoredAccountRegistry> {
    let dirs = crate::paths::project_dirs().ok_or_else(|| Error::ConfigRead {
        provider: "account-metadata".to_string(),
        reason: "the application data directory could not be resolved".to_string(),
    })?;
    Ok(StoredAccountRegistry::new(
        crate::paths::stored_accounts_path(dirs.data_dir()),
    ))
}

#[cfg(not(windows))]
fn connect_remote_authority(configured: &str) -> Result<AccountAuthority> {
    #[cfg(unix)]
    {
        AuthorityClient::connect(configured).map(AccountAuthority::Remote)
    }
    #[cfg(not(unix))]
    {
        let _ = configured;
        Err(map_socket_path_error(SocketPathError::UnsupportedPlatform))
    }
}

fn external_registry_error() -> Error {
    Error::ConfigRead {
        provider: "account-authority".to_string(),
        reason: "managed account metadata is owned by the configured authority; \
                 use supported authority operations"
            .to_string(),
    }
}

#[cfg(not(windows))]
fn map_socket_path_error(error: SocketPathError) -> Error {
    Error::ConfigRead {
        provider: "account-authority".to_string(),
        reason: error.to_string(),
    }
}

/// Native Unix or installed Windows/WSL RPC client for authority operations.
#[derive(Clone)]
pub struct AuthorityClient {
    #[cfg(unix)]
    path: crate::account_authority::SafeSocketPath,
    #[cfg(windows)]
    connection: connection::ConnectionRecord,
    authority_id: Arc<Mutex<Option<String>>>,
}

pub(crate) enum LaunchRpcError {
    Wire(ErrorCode),
    Unconfirmed(Error),
}

impl LaunchRpcError {
    pub(crate) fn into_error(self) -> Error {
        match self {
            Self::Wire(code) => {
                map_wire_error("launch", code, "authority launch operation refused")
            }
            Self::Unconfirmed(error) => error,
        }
    }
}

impl AuthorityClient {
    pub(crate) fn launch_identity(&self) -> Result<(String, String)> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "authority.describe",
        }))?;
        let result = wire_result(response, "authority.describe")?;
        let authority_id = required_string_field(&result, "authorityId")?;
        let service_id = required_string_field(&result, "launchServiceId")?;
        for operation in ["launch.start", "launch.status", "launch.cancel"] {
            if !result["operations"]
                .as_array()
                .is_some_and(|operations| operations.iter().any(|value| value == operation))
            {
                return Err(Error::NotImplemented("authority launch operations"));
            }
        }
        Ok((authority_id, service_id))
    }

    pub(crate) fn launch_start(
        &self,
        authority_id: &str,
        service_id: &str,
        binding: &SelectedAccountBinding,
        key: &str,
    ) -> std::result::Result<LaunchOperationStatus, LaunchRpcError> {
        self.launch_exchange(
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "requestId": next_request_id(),
                "operation": "launch.start",
                "authorityId": authority_id,
                "serviceId": service_id,
                "binding": binding,
                "idempotencyKey": key,
            }),
            None,
        )
    }

    pub(crate) fn launch_status(
        &self,
        authority_id: &str,
        service_id: &str,
        handle: &OperationHandle,
        cancel: bool,
    ) -> Result<LaunchOperationStatus> {
        self.launch_exchange(
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "requestId": next_request_id(),
                "operation": if cancel { "launch.cancel" } else { "launch.status" },
                "authorityId": authority_id,
                "serviceId": service_id,
                "handle": handle,
            }),
            Some(handle),
        )
        .map_err(LaunchRpcError::into_error)
    }

    fn launch_exchange(
        &self,
        request: Value,
        expected_handle: Option<&OperationHandle>,
    ) -> std::result::Result<LaunchOperationStatus, LaunchRpcError> {
        // exchange validates the shared correlated/exclusive response envelope.
        let response = self.exchange(request).map_err(|_| {
            LaunchRpcError::Unconfirmed(authority_io_error("launch reply unconfirmed; retry Launch to recover a pending start, or Check launch status for a known handle"))
        })?;
        if let Some(error) = response.error {
            return Err(LaunchRpcError::Wire(error.code));
        }
        decode_launch_status(response.result.unwrap_or(Value::Null), expected_handle)
            .map_err(LaunchRpcError::Unconfirmed)
    }

    #[cfg(unix)]
    pub fn connect(configured: impl AsRef<Path>) -> Result<Self> {
        let path = resolve_socket_path(configured.as_ref()).map_err(map_socket_path_error)?;
        Ok(Self {
            path,
            authority_id: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(windows)]
    fn from_connection(connection: connection::ConnectionRecord) -> Self {
        Self {
            connection,
            authority_id: Arc::new(Mutex::new(None)),
        }
    }

    pub fn authority_id(&self) -> Result<String> {
        let mut guard = self
            .authority_id
            .lock()
            .map_err(|_| authority_io_error("authority client lock poisoned"))?;
        if let Some(id) = guard.as_ref() {
            return Ok(id.clone());
        }
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "authority.describe",
        }))?;
        let result = wire_result(response, "authority.describe")?;
        let authority_id = required_string_field(&result, "authorityId")?;
        #[cfg(windows)]
        if authority_id != self.connection.authority_id {
            return Err(authority_io_error("authority identity mismatch"));
        }
        *guard = Some(authority_id.clone());
        Ok(authority_id)
    }

    pub fn accounts_list(&self, provider_id: &str) -> Result<Vec<StoredAccountMetadata>> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "accounts.list",
            "providerId": provider_id,
        }))?;
        let result = wire_result(response, "accounts.list")?;
        let records = result
            .get("records")
            .ok_or_else(|| authority_decode_error("accounts.list result missing records"))?;
        let records: Vec<StoredAccountMetadata> = serde_json::from_value(records.clone())
            .map_err(|_| authority_decode_error("invalid accounts.list records"))?;
        if records
            .iter()
            .any(|record| record.provider_id != provider_id)
        {
            return Err(authority_decode_error(
                "accounts.list provider binding mismatch",
            ));
        }
        Ok(records)
    }

    pub fn selection_revision(&self, provider_id: &str) -> Result<u64> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "selection.get",
            "providerId": provider_id,
        }))?;
        let result = wire_result(response, "selection.get")?;
        result
            .get("selectionRevision")
            .and_then(Value::as_u64)
            .ok_or_else(|| authority_decode_error("selection.get missing selectionRevision"))
    }

    pub fn selected_binding(&self, provider_id: &str) -> Result<Option<SelectedAccountBinding>> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "selection.get",
            "providerId": provider_id,
        }))?;
        let result = wire_result(response, "selection.get")?;
        let selected = result
            .get("selected")
            .and_then(Value::as_bool)
            .ok_or_else(|| authority_decode_error("selection.get missing selected"))?;
        if !selected {
            return Ok(None);
        }
        let binding = parse_selection_binding(&result)?;
        if binding.provider_id != provider_id {
            return Err(authority_decode_error(
                "selection provider binding mismatch",
            ));
        }
        Ok(Some(binding))
    }

    pub fn complete_account(
        &self,
        provider_id: &str,
        account_id: &str,
    ) -> Result<StoredAccountMetadata> {
        self.accounts_list(provider_id)?
            .into_iter()
            .find(|account| account.id == account_id)
            .filter(|account| account.state == StoredAccountState::Complete)
            .ok_or_else(|| Error::UnknownAccount(account_id.to_string()))
    }

    pub fn selection_set(
        &self,
        provider_id: &str,
        account_id: &str,
        account_incarnation: &str,
        selection_revision: Option<u64>,
    ) -> Result<SelectedAccountBinding> {
        let mut payload = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "selection.set",
            "providerId": provider_id,
            "accountId": account_id,
            "accountIncarnation": account_incarnation,
        });
        if let Some(revision) = selection_revision {
            payload
                .as_object_mut()
                .expect("object")
                .insert("selectionRevision".to_string(), json!(revision));
        }
        let response = self.exchange(payload)?;
        let result = wire_result(response, "selection.set")?;
        let binding = parse_selection_binding(&result)?;
        if binding.provider_id != provider_id
            || binding.account_id != account_id
            || binding.account_incarnation != account_incarnation
        {
            return Err(authority_decode_error(
                "selection response binding mismatch",
            ));
        }
        Ok(binding)
    }

    pub fn account_observe(&self, request: AccountObserveRequest) -> Result<AccountObserveResult> {
        let expected_binding = request.binding.clone();
        let authority_id = self.authority_id()?;
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "account.observe",
            "authorityId": authority_id,
            "binding": request.binding,
            "categories": request.categories,
        }))?;
        let result = wire_result(response, "account.observe")?;
        decode_account_observation(result, &expected_binding)
    }

    pub(crate) fn login_start(&self, request: LoginStartRequest) -> Result<LoginIpcStatus> {
        let caller_managed = matches!(
            request.provider_id.as_str(),
            "gemini-cli" | "codex-cli" | "grok-cli" | "cursor"
        );
        let mut payload = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "login.start",
            "providerId": request.provider_id,
            "accountId": request.account_id,
            "label": request.label,
            "authKind": request.auth_kind,
            "idempotencyKey": request.idempotency_key,
        });
        if caller_managed {
            payload
                .as_object_mut()
                .expect("object")
                .insert("browserMode".to_string(), json!("caller-managed"));
        }
        let response = self.exchange(payload)?;
        let result = wire_result(response, "login.start")?;
        serde_json::from_value(result)
            .map_err(|_| authority_decode_error("invalid login.start result"))
    }

    pub(crate) fn login_status(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<LoginIpcStatus> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "login.status",
            "handle": handle,
            "binding": binding,
        }))?;
        let result = wire_result(response, "login.status")?;
        serde_json::from_value(result)
            .map_err(|_| authority_decode_error("invalid login.status result"))
    }

    pub(crate) fn login_cancel(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<LoginIpcStatus> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "login.cancel",
            "handle": handle,
            "binding": binding,
        }))?;
        let result = wire_result(response, "login.cancel")?;
        serde_json::from_value(result)
            .map_err(|_| authority_decode_error("invalid login.cancel result"))
    }

    pub fn select_launch_account(
        &self,
        adapter: &dyn ProviderAdapter,
        account_id: &str,
    ) -> Result<()> {
        let target = self.complete_account(adapter.id(), account_id)?;
        let revision = self.selection_revision(adapter.id())?;
        self.selection_set(
            adapter.id(),
            account_id,
            &target.account_incarnation,
            Some(revision),
        )?;
        Ok(())
    }

    fn exchange(&self, request: Value) -> Result<AuthorityResponse> {
        let body = serde_json::to_vec(&request).map_err(Error::Serde)?;
        if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
            return Err(authority_io_error(
                "authority request exceeds maxRequestBytes",
            ));
        }

        let response_bytes = self.exchange_bytes(&body)?;
        let response = decode_response(
            &response_bytes,
            request
                .get("requestId")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )?;
        #[cfg(windows)]
        if let Some(id) = response.result.as_ref().and_then(|v| v.get("authorityId")) {
            if id.as_str() != Some(self.connection.authority_id.as_str()) {
                return Err(authority_io_error("authority identity mismatch"));
            }
        }
        Ok(response)
    }

    #[cfg(unix)]
    fn exchange_bytes(&self, body: &[u8]) -> Result<Vec<u8>> {
        let mut stream = std::os::unix::net::UnixStream::connect(self.path.as_path())
            .map_err(|_| authority_io_error("failed to connect to authority socket"))?;
        let deadline = std::time::Instant::now() + REQUEST_IO_DEADLINE;
        write_framed(&mut stream, body, deadline)?;
        read_framed(&mut stream, MAX_RESPONSE_BYTES, deadline)
    }

    #[cfg(windows)]
    fn exchange_bytes(&self, body: &[u8]) -> Result<Vec<u8>> {
        connection::exchange(&self.connection, body)
    }

    #[cfg(not(any(unix, windows)))]
    fn exchange_bytes(&self, _body: &[u8]) -> Result<Vec<u8>> {
        Err(map_socket_path_error(SocketPathError::UnsupportedPlatform))
    }
}

pub fn select_launch_account(
    authority: &AccountAuthority,
    adapter: &dyn ProviderAdapter,
    account_id: &str,
) -> Result<()> {
    match authority {
        AccountAuthority::InProcess(registry) => {
            providers::select_launch_account(registry, adapter, account_id)
        }
        AccountAuthority::Remote(client) => client.select_launch_account(adapter, account_id),
    }
}

fn decode_account_observation(
    result: Value,
    expected_binding: &SelectedAccountBinding,
) -> Result<AccountObserveResult> {
    let observation: AccountObserveResult = serde_json::from_value(result)
        .map_err(|_| authority_decode_error("invalid account.observe result"))?;
    if &observation.binding != expected_binding {
        return Err(authority_decode_error(
            "account.observe response binding mismatch",
        ));
    }
    if let Some(content) = observation
        .models
        .as_ref()
        .and_then(|models| models.content.as_ref())
    {
        validate_observed_models_for_binding(content, expected_binding)
            .map_err(|_| authority_decode_error("invalid account.observe model evidence"))?;
    }
    Ok(observation)
}

fn decode_launch_status(
    value: Value,
    expected_handle: Option<&OperationHandle>,
) -> Result<LaunchOperationStatus> {
    // A handle is 24 random bytes encoded as unpadded base64url. Refuse remote
    // strings that could smuggle paths, output, or secret-bearing diagnostics.
    let handle = value.get("handle").and_then(Value::as_str).unwrap_or("");
    if handle.len() != 32
        || !handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(authority_decode_error("invalid launch handle"));
    }
    let status: LaunchOperationStatus = serde_json::from_value(value)
        .map_err(|_| authority_decode_error("invalid launch status"))?;
    if expected_handle.is_some_and(|handle| handle != &status.handle)
        || status.process_id == Some(0)
    {
        return Err(authority_decode_error("launch status binding mismatch"));
    }
    Ok(status)
}

fn parse_selection_binding(result: &Value) -> Result<SelectedAccountBinding> {
    Ok(SelectedAccountBinding {
        provider_id: required_string_field(result, "providerId")?,
        account_id: required_string_field(result, "accountId")?,
        account_incarnation: required_string_field(result, "accountIncarnation")?,
        selection_revision: result
            .get("selectionRevision")
            .and_then(Value::as_u64)
            .ok_or_else(|| authority_decode_error("selection result missing selectionRevision"))?,
    })
}

fn wire_result(response: AuthorityResponse, operation: &str) -> Result<Value> {
    if let Some(error) = response.error {
        return Err(map_wire_error(operation, error.code, &error.message));
    }
    response
        .result
        .ok_or_else(|| authority_decode_error(&format!("authority `{operation}` missing result")))
}

fn map_wire_error(operation: &str, code: ErrorCode, message: &str) -> Error {
    let _ = operation;
    match code {
        ErrorCode::UnknownAccount => Error::UnknownAccount(message.to_string()),
        ErrorCode::StaleSelection => Error::StaleSelection {
            provider: "account-authority".to_string(),
        },
        ErrorCode::StaleAccount => Error::StaleAccount {
            account_id: message.to_string(),
        },
        ErrorCode::Busy => Error::AccountAuthorityBusy {
            reason: message.to_string(),
        },
        ErrorCode::StateUnavailable => Error::CredentialStoreUnavailable(message.to_string()),
        ErrorCode::UnsupportedOperation => Error::NotImplemented("authority socket operation"),
        ErrorCode::InvalidRequest | ErrorCode::AccessDenied | ErrorCode::UnsupportedVersion => {
            Error::ConfigRead {
                provider: "account-authority".to_string(),
                reason: message.to_string(),
            }
        }
        ErrorCode::Unavailable
        | ErrorCode::ReauthenticationRequired
        | ErrorCode::OutcomeUnknown => Error::ConfigRead {
            provider: "account-authority".to_string(),
            reason: message.to_string(),
        },
    }
}

fn required_string_field(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| authority_decode_error(&format!("authority response missing `{field}`")))
}

fn authority_io_error(reason: &str) -> Error {
    Error::ConfigRead {
        provider: "account-authority".to_string(),
        reason: reason.to_string(),
    }
}

fn authority_decode_error(reason: &str) -> Error {
    Error::ConfigRead {
        provider: "account-authority".to_string(),
        reason: reason.to_string(),
    }
}

fn next_request_id() -> String {
    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("cam-desktop-{id}")
}

#[cfg(any(unix, test))]
trait AuthorityStream: std::io::Read + std::io::Write {
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()>;
}

#[cfg(unix)]
impl AuthorityStream for std::os::unix::net::UnixStream {
    fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        Self::set_write_timeout(self, timeout)
    }
}

#[cfg(any(unix, test))]
fn write_framed(
    stream: &mut impl AuthorityStream,
    body: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    // Install both finite timeouts before the peer can reply and close.
    apply_io_deadline(stream, deadline)?;
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|error| authority_io_error(&format!("write authority request length: {error}")))?;
    stream
        .write_all(body)
        .map_err(|error| authority_io_error(&format!("write authority request body: {error}")))?;
    Ok(())
}

#[cfg(any(unix, test))]
fn read_framed(
    stream: &mut impl AuthorityStream,
    max_response_bytes: usize,
    deadline: std::time::Instant,
) -> Result<Vec<u8>> {
    let remaining = remaining_io_time(deadline)?;
    if let Err(error) = stream.set_read_timeout(Some(remaining)) {
        // A finite read timeout is already installed before the request. On
        // macOS a closed peer can make this refresh return EINVAL, even with a
        // complete reply buffered. Retain the earlier bound and let read report
        // the buffered reply or EOF. Other setup errors still fail closed.
        if error.kind() != std::io::ErrorKind::InvalidInput {
            return Err(authority_io_error(&format!(
                "set authority read timeout: {error}"
            )));
        }
    }
    let mut length_bytes = [0u8; 4];
    stream
        .read_exact(&mut length_bytes)
        .map_err(|error| authority_io_error(&format!("read authority response length: {error}")))?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > max_response_bytes || length > MAX_RESPONSE_BYTES {
        return Err(authority_io_error(
            "authority response exceeds maxResponseBytes",
        ));
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .map_err(|error| authority_io_error(&format!("read authority response body: {error}")))?;
    Ok(body)
}

#[cfg(any(unix, test))]
fn apply_io_deadline(stream: &impl AuthorityStream, deadline: std::time::Instant) -> Result<()> {
    let remaining = remaining_io_time(deadline)?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| authority_io_error(&format!("set authority read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|error| authority_io_error(&format!("set authority write timeout: {error}")))?;
    Ok(())
}

#[cfg(any(unix, test))]
fn remaining_io_time(deadline: std::time::Instant) -> Result<std::time::Duration> {
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return Err(authority_io_error("authority request I/O deadline elapsed"));
    }
    Ok(remaining)
}

#[cfg(test)]
#[path = "authority_client_transport_tests.rs"]
mod transport_tests;

fn decode_response(bytes: &[u8], request_id: &str) -> Result<AuthorityResponse> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE_BYTES {
        return Err(authority_decode_error("invalid authority response size"));
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Envelope {
        protocol_version: u32,
        request_id: String,
        result: Option<Value>,
        error: Option<Value>,
    }
    let envelope: Envelope = serde_json::from_slice(bytes)
        .map_err(|_| authority_decode_error("invalid authority response envelope"))?;
    let response = AuthorityResponse {
        protocol_version: envelope.protocol_version,
        request_id: envelope.request_id,
        result: envelope.result,
        error: envelope
            .error
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| authority_decode_error("invalid authority error envelope"))?,
    };
    response
        .validate_for_request(request_id)
        .map_err(|error| authority_decode_error(&error.to_string()))?;
    Ok(response)
}

// The installer writes this non-secret record only after the package is known.
// Neither the webview nor the record can choose a command to execute.
#[cfg(any(windows, test))]
mod connection {
    use super::*;
    use serde::Deserialize;

    pub const LAUNCHER: &str = "/usr/local/libexec/maco-account-authority";
    const MAX_RECORD_BYTES: u64 = 16 * 1024;

    #[derive(Clone, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct ConnectionRecord {
        pub version: u32,
        pub transport: String,
        pub distribution: String,
        pub user: String,
        pub expected_uid: u32,
        pub socket_path: String,
        pub expected_helper: String,
        pub helper_elf_sha256: String,
        pub source_manifest_sha256: String,
        pub authority_id: String,
    }

    fn valid_name(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    }

    fn absolute_linux_path(value: &str) -> bool {
        value.starts_with('/')
            && value.len() <= 4096
            && !value.ends_with('/')
            && value.split('/').skip(1).all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
    }

    fn digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    fn decode(bytes: &[u8]) -> Result<ConnectionRecord> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(authority_io_error(
                "invalid authority connection record size",
            ));
        }
        let record: ConnectionRecord = serde_json::from_slice(bytes)
            .map_err(|_| authority_io_error("invalid authority connection record"))?;
        if record.version != 1
            || record.transport != "wsl"
            || !valid_name(&record.distribution)
            || !valid_name(&record.user)
            || record.user.eq_ignore_ascii_case("root")
            || record.expected_uid == 0
            || !record
                .user
                .as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            || !absolute_linux_path(&record.socket_path)
            || record.socket_path.len() > 107
            || !absolute_linux_path(&record.expected_helper)
            || !record.expected_helper.ends_with("/bin/account-authority")
            || !digest(&record.helper_elf_sha256)
            || !digest(&record.source_manifest_sha256)
            || !digest(&record.authority_id)
        {
            return Err(authority_io_error("invalid authority connection binding"));
        }
        Ok(record)
    }

    fn relay_args(record: &ConnectionRecord) -> Vec<String> {
        [
            "--distribution",
            &record.distribution,
            "--user",
            &record.user,
            "--exec",
            LAUNCHER,
            "--relay",
            "--socket-path",
            &record.socket_path,
            "--expected-uid",
            &record.expected_uid.to_string(),
            "--expected-helper",
            &record.expected_helper,
            "--helper-elf-sha256",
            &record.helper_elf_sha256,
            "--source-manifest-sha256",
            &record.source_manifest_sha256,
            "--authority-id",
            &record.authority_id,
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[cfg(windows)]
    pub fn load() -> Result<ConnectionRecord> {
        let dirs = crate::paths::project_dirs()
            .ok_or_else(|| authority_io_error("application config directory unavailable"))?;
        let path = dirs.config_dir().join("authority-connection.json");
        load_at(&path)
    }

    #[cfg(windows)]
    fn load_at(path: &std::path::Path) -> Result<ConnectionRecord> {
        use std::io::Read;
        // The managed Windows route requires an installed private record.
        // Missing, redirected, unreadable or invalid records never select a
        // different principal through the native Windows registry.
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(authority_io_error(
                    "managed Windows authority connection record is required",
                ))
            }
            Err(_) => {
                return Err(authority_io_error(
                    "cannot inspect authority connection record",
                ))
            }
            Ok(_) => {}
        }
        let mut handles = windows_security::open_chain(path, false)?;
        let file = handles
            .pop()
            .ok_or_else(|| authority_io_error("missing connection record"))?;
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| authority_io_error("cannot read authority connection record"))?;
        decode(&bytes)
    }

    #[cfg(windows)]
    pub fn exchange(record: &ConnectionRecord, body: &[u8]) -> Result<Vec<u8>> {
        use std::io::{Read, Write};
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::sync::mpsc;
        use std::time::Instant;

        let deadline = Instant::now() + REQUEST_IO_DEADLINE;
        let executable = windows_security::wsl_path()?;
        // Keep all executable ancestry handles pinned until the child exits.
        let _executable_handles = windows_security::open_chain(&executable, true)?;
        let mut child = Command::new(&executable)
            .args(relay_args(record))
            .current_dir(executable.parent().expect("system executable parent"))
            .env("WSLENV", "")
            .env_remove("LD_PRELOAD")
            .env_remove("LD_LIBRARY_PATH")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(0x08000000) // CREATE_NO_WINDOW; never steal owner focus.
            .spawn()
            .map_err(|_| authority_io_error("cannot start approved WSL authority relay"))?;
        let job = match windows_security::ChildJob::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        let mut input = child.stdin.take().expect("piped stdin");
        let mut output = child.stdout.take().expect("piped stdout");
        let body = body.to_vec();
        let (sender, receiver) = mpsc::sync_channel(1);
        let io_worker = std::thread::spawn(move || {
            let result = (|| -> std::io::Result<Vec<u8>> {
                input.write_all(&(body.len() as u32).to_be_bytes())?;
                input.write_all(&body)?;
                drop(input);
                let mut length = [0; 4];
                output.read_exact(&mut length)?;
                let length = u32::from_be_bytes(length) as usize;
                if length == 0 || length > MAX_RESPONSE_BYTES {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                let mut response = vec![0; length];
                output.read_exact(&mut response)?;
                // The relay handles exactly one frame; reject any trailing bytes.
                let mut extra = [0];
                if output.read(&mut extra)? != 0 {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                Ok(response)
            })();
            let _ = sender.send(result);
        });
        let result = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        let response = match result {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(_)) => Err(authority_io_error("WSL authority relay protocol failure")),
            Err(_) => Err(authority_io_error("WSL authority relay deadline elapsed")),
        };
        // wait() without an exit observation could wait forever after a valid frame.
        let outcome = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    break if status.success() {
                        response
                    } else {
                        Err(authority_io_error("WSL authority relay failed"))
                    }
                }
                Ok(None) if response.is_ok() && Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(5))
                }
                _ => {
                    job.terminate();
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(authority_io_error("WSL authority relay terminated"));
                }
            }
        };
        // The fixed relay never spawns descendants. Termination closes its pipe
        // handles; joining ensures no detached reader survives a failed RPC.
        job.terminate();
        let _ = io_worker.join();
        outcome
    }

    #[cfg(windows)]
    mod windows_security {
        use super::*;
        use std::ffi::c_void;
        use std::fs::{File, OpenOptions};
        use std::os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        };
        use std::path::{Component, Path, PathBuf};

        type Handle = *mut c_void;
        #[repr(C)]
        struct Acl {
            revision: u8,
            reserved: u8,
            size: u16,
            count: u16,
            reserved2: u16,
        }
        #[repr(C)]
        struct Ace {
            kind: u8,
            flags: u8,
            size: u16,
            mask: u32,
            sid: u32,
        }
        #[repr(C)]
        #[derive(Default)]
        struct BasicJobLimits {
            process_time: i64,
            job_time: i64,
            flags: u32,
            minimum_working_set: usize,
            maximum_working_set: usize,
            active_process_limit: u32,
            affinity: usize,
            priority: u32,
            scheduling: u32,
        }
        #[repr(C)]
        #[derive(Default)]
        struct ExtendedJobLimits {
            basic: BasicJobLimits,
            io_counters: [u64; 6],
            process_memory: usize,
            job_memory: usize,
            peak_process_memory: usize,
            peak_job_memory: usize,
        }
        #[link(name = "advapi32")]
        extern "system" {
            fn GetSecurityInfo(
                handle: Handle,
                object: u32,
                info: u32,
                owner: *mut Handle,
                group: *mut Handle,
                dacl: *mut *mut Acl,
                sacl: *mut Handle,
                descriptor: *mut Handle,
            ) -> u32;
            fn GetAce(acl: *mut Acl, index: u32, ace: *mut Handle) -> i32;
            fn EqualSid(a: Handle, b: Handle) -> i32;
            fn IsWellKnownSid(sid: Handle, kind: u32) -> i32;
            fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
            fn GetTokenInformation(
                token: Handle,
                class: u32,
                info: Handle,
                size: u32,
                needed: *mut u32,
            ) -> i32;
            fn ConvertStringSidToSidW(text: *const u16, sid: *mut Handle) -> i32;
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn LocalFree(memory: Handle) -> Handle;
            fn GetCurrentProcess() -> Handle;
            fn CloseHandle(handle: Handle) -> i32;
            fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
            fn CreateJobObjectW(attributes: Handle, name: *const u16) -> Handle;
            fn SetInformationJobObject(
                job: Handle,
                class: u32,
                information: Handle,
                length: u32,
            ) -> i32;
            fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
            fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
        }

        pub struct ChildJob(Handle);
        impl ChildJob {
            pub fn attach(child: &std::process::Child) -> Result<Self> {
                // SAFETY: an unnamed job, valid repr(C) limits and owned handles.
                unsafe {
                    let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
                    if job.is_null() {
                        return Err(authority_io_error("relay containment unavailable"));
                    }
                    let owner = Self(job);
                    let mut limits = ExtendedJobLimits::default();
                    limits.basic.flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    if SetInformationJobObject(
                        job,
                        9,
                        (&mut limits as *mut ExtendedJobLimits).cast(),
                        std::mem::size_of_val(&limits) as u32,
                    ) == 0
                        || AssignProcessToJobObject(job, child.as_raw_handle()) == 0
                    {
                        return Err(authority_io_error("relay containment unavailable"));
                    }
                    Ok(owner)
                }
            }
            pub fn terminate(&self) {
                // SAFETY: this job is owned exclusively by one relay RPC.
                unsafe {
                    TerminateJobObject(self.0, 1);
                }
            }
        }
        impl Drop for ChildJob {
            fn drop(&mut self) {
                // Closing the job also drains descendants retaining pipe handles.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }

        pub fn wsl_path() -> Result<PathBuf> {
            let mut buffer = vec![0u16; 32768];
            // SAFETY: writable buffer with the supplied length.
            let length =
                unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
            if length == 0 || length >= buffer.len() {
                return Err(authority_io_error(
                    "trusted Windows system directory unavailable",
                ));
            }
            Ok(PathBuf::from(
                String::from_utf16(&buffer[..length])
                    .map_err(|_| authority_io_error("invalid Windows system directory"))?,
            )
            .join("wsl.exe"))
        }

        pub fn open_chain(path: &Path, executable: bool) -> Result<Vec<File>> {
            if !path.is_absolute()
                || !matches!(path.components().next(), Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), std::path::Prefix::Disk(_)))
            {
                return Err(authority_io_error(
                    "authority configuration must use a local absolute path",
                ));
            }
            let mut current = PathBuf::new();
            let mut handles = Vec::new();
            for part in path.components() {
                match part {
                    Component::Prefix(_) => {
                        current.push(part.as_os_str());
                        continue;
                    }
                    Component::ParentDir | Component::CurDir => {
                        return Err(authority_io_error("invalid config ancestry"))
                    }
                    _ => current.push(part.as_os_str()),
                }
                let leaf = current == path;
                let file = OpenOptions::new()
                    .read(true)
                    .access_mode(if leaf { 0x80020000 } else { 0x20080 })
                    .share_mode(if leaf { 1 } else { 3 })
                    .custom_flags(0x00200000 | 0x02000000) // OPEN_REPARSE_POINT | BACKUP_SEMANTICS
                    .open(&current)
                    .map_err(|_| authority_io_error("cannot securely open authority path"))?;
                let metadata = file
                    .metadata()
                    .map_err(|_| authority_io_error("cannot inspect authority path"))?;
                if metadata.file_attributes() & 0x400 != 0
                    || (leaf && !metadata.is_file())
                    || (!leaf && !metadata.is_dir())
                {
                    return Err(authority_io_error(
                        "authority path redirects or has invalid type",
                    ));
                }
                check_acl(&file, leaf, executable)?;
                handles.push(file);
            }
            Ok(handles)
        }

        fn check_acl(file: &File, leaf: bool, executable: bool) -> Result<()> {
            // Security descriptors and token buffers stay alive while SID pointers
            // are used. Every allocation/handle is released on either disposition.
            unsafe {
                let mut owner = std::ptr::null_mut();
                let mut acl = std::ptr::null_mut();
                let mut descriptor = std::ptr::null_mut();
                let status = GetSecurityInfo(
                    file.as_raw_handle(),
                    1,
                    5,
                    &mut owner,
                    std::ptr::null_mut(),
                    &mut acl,
                    std::ptr::null_mut(),
                    &mut descriptor,
                );
                if status != 0 {
                    return Err(authority_io_error("authority path ACL unavailable"));
                }
                let result = (|| {
                    let mut token = std::ptr::null_mut();
                    if OpenProcessToken(GetCurrentProcess(), 8, &mut token) == 0 {
                        return Err(authority_io_error("owner principal unavailable"));
                    }
                    let mut needed = 0;
                    GetTokenInformation(token, 1, std::ptr::null_mut(), 0, &mut needed);
                    // usize alignment suffices for TOKEN_USER's SID pointer.
                    let mut token_user =
                        vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
                    let success = GetTokenInformation(
                        token,
                        1,
                        token_user.as_mut_ptr().cast(),
                        needed,
                        &mut needed,
                    );
                    CloseHandle(token);
                    if success == 0 || token_user.is_empty() {
                        return Err(authority_io_error("owner principal unavailable"));
                    }
                    let user_sid = token_user[0] as Handle;
                    let mut installer_sid = std::ptr::null_mut();
                    let installer_text: Vec<u16> =
                        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\0"
                            .encode_utf16()
                            .collect();
                    if ConvertStringSidToSidW(installer_text.as_ptr(), &mut installer_sid) == 0 {
                        return Err(authority_io_error("installation principal unavailable"));
                    }
                    struct SidAllocation(Handle);
                    impl Drop for SidAllocation {
                        fn drop(&mut self) {
                            unsafe {
                                LocalFree(self.0);
                            }
                        }
                    }
                    let _installer_allocation = SidAllocation(installer_sid);
                    let system = |sid: Handle| {
                        !sid.is_null()
                            && (EqualSid(sid, installer_sid) != 0
                        || IsWellKnownSid(sid, 22) != 0 // LocalSystem
                        || IsWellKnownSid(sid, 26) != 0)
                    }; // BuiltinAdministrators
                    let approved = |sid: Handle| {
                        system(sid)
                            || (!executable && !sid.is_null() && EqualSid(sid, user_sid) != 0)
                    };
                    if leaf && !approved(owner) {
                        return Err(authority_io_error(
                            "connection record owner is not approved",
                        ));
                    }
                    if acl.is_null() {
                        return Err(authority_io_error("authority path has unrestricted ACL"));
                    }
                    for index in 0..(*acl).count {
                        let mut raw = std::ptr::null_mut();
                        if GetAce(acl, u32::from(index), &mut raw) == 0 || raw.is_null() {
                            return Err(authority_io_error("invalid authority path ACL"));
                        }
                        let ace = &*(raw as *const Ace);
                        if ace.flags & 8 != 0 || ace.kind == 1 {
                            continue;
                        } // inherit-only / deny
                        if ace.kind != 0 || usize::from(ace.size) < std::mem::size_of::<Ace>() {
                            return Err(authority_io_error("unsupported authority path ACL"));
                        }
                        // Directory ancestors must not permit replacement/deletion
                        // or ACL ownership changes by another principal.
                        let writes =
                            0x40000000 | 0x10000000 | 0x000d0040 | if leaf { 0x116 } else { 0 };
                        if ace.mask & writes != 0
                            && !approved((&ace.sid as *const u32).cast_mut().cast())
                        {
                            return Err(authority_io_error(
                                "authority path is writable by an unapproved principal",
                            ));
                        }
                        // A connection record is a private owner binding.
                        // Public read access remains valid for system
                        // executables and directory ancestors, never this leaf.
                        let reads = 0x80000000 | 0x00120089; // GENERIC_READ | FILE_GENERIC_READ
                        if leaf
                            && !executable
                            && ace.mask & reads != 0
                            && !approved((&ace.sid as *const u32).cast_mut().cast())
                        {
                            return Err(authority_io_error(
                                "connection record is readable by an unapproved principal",
                            ));
                        }
                    }
                    Ok(())
                })();
                LocalFree(descriptor);
                result
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use std::os::windows::ffi::OsStrExt;
            #[link(name = "advapi32")]
            extern "system" {
                fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text: *const u16,
                    revision: u32,
                    descriptor: *mut Handle,
                    size: *mut u32,
                ) -> i32;
                fn SetFileSecurityW(path: *const u16, information: u32, descriptor: Handle) -> i32;
                fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
            }

            fn set_fixture_dacl(fixture: &tempfile::NamedTempFile, dacl: &str) {
                let name: Vec<u16> = fixture
                    .path()
                    .as_os_str()
                    .encode_wide()
                    .chain(Some(0))
                    .collect();
                let text: Vec<u16> = dacl.encode_utf16().chain(Some(0)).collect();
                let mut descriptor = std::ptr::null_mut();
                // Only an empty owned fixture gets the insecure ACL; never an
                // installed record, executable or surrounding directory.
                unsafe {
                    assert_ne!(
                        ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            text.as_ptr(),
                            1,
                            &mut descriptor,
                            std::ptr::null_mut()
                        ),
                        0
                    );
                    let result = SetFileSecurityW(name.as_ptr(), 4, descriptor);
                    LocalFree(descriptor);
                    assert_ne!(result, 0);
                }
            }

            fn fixture_owner_sid(file: &File) -> String {
                // Only an owned empty fixture is inspected, never an installed
                // record or a credential. The SID remains internal to the test.
                unsafe {
                    let mut owner = std::ptr::null_mut();
                    let mut descriptor = std::ptr::null_mut();
                    assert_eq!(
                        GetSecurityInfo(
                            file.as_raw_handle(),
                            1,
                            1,
                            &mut owner,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            &mut descriptor
                        ),
                        0,
                    );
                    let mut text = std::ptr::null_mut();
                    let success = ConvertSidToStringSidW(owner, &mut text);
                    LocalFree(descriptor);
                    assert_ne!(success, 0);
                    assert!(!text.is_null());
                    let mut length = 0;
                    while *text.add(length) != 0 {
                        length += 1;
                    }
                    let sid = String::from_utf16(std::slice::from_raw_parts(text, length));
                    LocalFree(text.cast());
                    sid.expect("fixture owner SID")
                }
            }

            #[test]
            fn connection_acl_refuses_real_broad_write_grants() {
                let fixture = tempfile::NamedTempFile::new().unwrap();
                set_fixture_dacl(&fixture, "D:P(A;;GA;;;WD)");
                assert!(check_acl(fixture.as_file(), true, false).is_err());
            }

            #[test]
            fn private_connection_leaf_refuses_foreign_read_only_aces() {
                let fixture = tempfile::NamedTempFile::new().unwrap();
                let owner = fixture_owner_sid(fixture.as_file());
                for grant in ["GR", "FR", "0x00000001"] {
                    set_fixture_dacl(
                        &fixture,
                        &format!("D:P(A;;GA;;;{owner})(A;;GA;;;SY)(A;;GA;;;BA)(A;;{grant};;;WD)"),
                    );
                    let error =
                        check_acl(fixture.as_file(), true, false).expect_err("foreign read");
                    assert!(error
                        .to_string()
                        .contains("readable by an unapproved principal"));
                }
            }

            #[test]
            fn private_connection_leaf_accepts_owner_system_and_administrators() {
                let fixture = tempfile::NamedTempFile::new().unwrap();
                let owner = fixture_owner_sid(fixture.as_file());
                set_fixture_dacl(
                    &fixture,
                    &format!("D:P(A;;GA;;;{owner})(A;;GA;;;SY)(A;;GA;;;BA)"),
                );
                check_acl(fixture.as_file(), true, false).expect("approved private principals");
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[cfg(windows)]
        #[test]
        fn missing_managed_connection_record_fails_closed() {
            let fixture = tempfile::tempdir().unwrap();
            let missing = fixture.path().join("authority-connection.json");
            let error = match load_at(&missing) {
                Ok(_) => panic!("missing record must not permit native registry fallback"),
                Err(error) => error,
            };
            assert!(matches!(error, Error::ConfigRead { .. }));
            assert!(error.to_string().contains("connection record is required"));
            assert!(
                !missing.exists(),
                "read-only resolution must not create a record"
            );
        }

        fn record() -> Value {
            json!({"version":1,"transport":"wsl","distribution":"Distribution-1","user":"owner",
                "expectedUid":1000,"socketPath":"/run/user/1000/maco/account-authority.sock",
                "expectedHelper":"/opt/maco/package/bin/account-authority",
                "helperElfSha256":"a".repeat(64),"sourceManifestSha256":"b".repeat(64),"authorityId":"c".repeat(64)})
        }
        #[test]
        fn rejects_unknown_duplicate_missing_and_unsafe_bindings() {
            let original = record();
            for (key, value) in [
                ("version", json!(2)),
                ("transport", json!("command")),
                ("distribution", json!("--exec")),
                ("user", json!("root")),
                ("user", json!("0")),
                ("expectedUid", json!(0)),
                ("socketPath", json!("/run/../tmp/x")),
                ("expectedHelper", json!("/tmp/shell")),
                ("helperElfSha256", json!("A".repeat(64))),
                ("command", json!("sh")),
                ("authorityId", json!("")),
            ] {
                let mut invalid = original.clone();
                invalid[key] = value;
                assert!(
                    decode(&serde_json::to_vec(&invalid).unwrap()).is_err(),
                    "accepted {key}"
                );
            }
            let duplicate = format!("{{\"version\":1,{}", &original.to_string()[1..]);
            assert!(decode(duplicate.as_bytes()).is_err());
            assert!(decode(b"{}").is_err());
            assert!(decode(&vec![b' '; MAX_RECORD_BYTES as usize + 1]).is_err());
        }
        #[test]
        fn only_fixed_launcher_is_executed_and_identity_is_argument_data() {
            let record = decode(&serde_json::to_vec(&record()).unwrap()).unwrap();
            let args = relay_args(&record);
            assert_eq!(
                &args[..7],
                &[
                    "--distribution",
                    "Distribution-1",
                    "--user",
                    "owner",
                    "--exec",
                    LAUNCHER,
                    "--relay"
                ]
            );
            assert!(!args.iter().any(|arg| arg == "sh" || arg == "-c"));
            assert_eq!(args[12], record.expected_helper);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_status_decoding_is_closed_and_bound() {
        let value = json!({
            "handle": "a".repeat(32), "state": "running", "processId": 42,
            "exitCode": null, "failureCode": null,
        });
        let status = decode_launch_status(value.clone(), None).unwrap();
        assert!(decode_launch_status(value.clone(), Some(&status.handle)).is_ok());
        for (field, invalid) in [
            ("handle", json!("b".repeat(32))),
            ("handle", json!("https://secret-sentinel.invalid")),
            ("state", json!("secret-sentinel")),
            ("processId", json!(0)),
            ("failureCode", json!("secret-sentinel")),
            ("output", json!("secret-sentinel")),
        ] {
            let mut invalid_status = value.clone();
            invalid_status[field] = invalid;
            let error = decode_launch_status(invalid_status, Some(&status.handle)).unwrap_err();
            assert!(!error.to_string().contains("secret-sentinel"));
        }
    }

    #[test]
    fn account_observation_refuses_foreign_selection_and_catalog_principal() {
        let binding = SelectedAccountBinding {
            provider_id: "grok-cli".into(),
            account_id: "work".into(),
            account_incarnation: "incarnation-1".into(),
            selection_revision: 7,
        };
        let result = json!({
            "binding": binding,
            "observedAt": "2026-10-03T00:00:00Z",
            "models": {"outcome": {"kind": "observed"}, "content": {
                "models": [{"modelId": "fixture-model", "access": "unknown-access"}]
            }}
        });
        assert!(decode_account_observation(result.clone(), &binding).is_ok());
        for (field, value) in [
            ("providerId", json!("codex-cli")),
            ("accountId", json!("other")),
            ("accountIncarnation", json!("old")),
            ("selectionRevision", json!(8)),
        ] {
            let mut foreign = result.clone();
            foreign["binding"][field] = value;
            assert!(decode_account_observation(foreign, &binding).is_err());
        }
        let mut foreign = result.clone();
        let mut principal = serde_json::to_value(&binding).unwrap();
        principal["accountId"] = json!("other");
        foreign["models"]["content"]["provenance"] = json!({
            "sourceKind": "authenticated-catalog", "fetchedAt": null, "stale": false,
            "principalBinding": principal, "accessBasis": "confirmed-model-entitlement"
        });
        assert!(decode_account_observation(foreign, &binding).is_err());
        let mut unsupported = result;
        unsupported["models"]["content"]["models"][0]["access"] = json!("available");
        assert!(decode_account_observation(unsupported, &binding).is_err());
    }
    #[cfg(not(windows))]
    use std::sync::{Mutex, MutexGuard};

    #[cfg(not(windows))]
    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(not(windows))]
    fn env_test_lock() -> MutexGuard<'static, ()> {
        ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    #[cfg(not(windows))]
    fn unset_env_uses_in_process_registry() {
        let _lock = env_test_lock();
        std::env::remove_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV);
        let authority = authority_from_environment().expect("authority");
        assert!(matches!(authority, AccountAuthority::InProcess(_)));
        authority
            .in_process_registry()
            .expect("in-process registry");
    }

    #[test]
    #[cfg(not(windows))]
    fn empty_env_uses_in_process_registry() {
        let _lock = env_test_lock();
        std::env::set_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV, "   ");
        let authority = authority_from_environment().expect("authority");
        assert!(matches!(authority, AccountAuthority::InProcess(_)));
        std::env::remove_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV);
    }

    #[test]
    fn response_refuses_uncorrelated_ambiguous_unknown_and_secret_decode_errors() {
        let valid = json!({"protocolVersion":1,"requestId":"rpc","result":{}});
        assert!(decode_response(&serde_json::to_vec(&valid).unwrap(), "rpc").is_ok());
        assert!(decode_response(
            br#"{"protocolVersion":1,"requestId":"rpc","error":{"code":"busy","message":"busy"}}"#,
            "rpc"
        )
        .is_ok());
        assert!(decode_response(&serde_json::to_vec(&valid).unwrap(), "").is_err());
        assert!(
            decode_response(br#"{"protocolVersion":1,"requestId":"","result":{}}"#, "").is_err()
        );
        for invalid in [
            json!({"protocolVersion":2,"requestId":"rpc","result":{}}),
            json!({"protocolVersion":1,"requestId":"other","result":{}}),
            json!({"protocolVersion":1,"result":{}}),
            json!({"protocolVersion":1,"requestId":"","result":{}}),
            json!({"protocolVersion":1,"requestId":"rpc"}),
            json!({"protocolVersion":1,"requestId":"rpc","result":{},"error":{"code":"busy","message":"busy"}}),
            json!({"protocolVersion":1,"requestId":"rpc","result":{},"command":"arbitrary"}),
            json!({"protocolVersion":1,"requestId":"rpc","error":{"code":"https://example.invalid/?secret=sentinel","message":"sentinel"}}),
        ] {
            let error = decode_response(&serde_json::to_vec(&invalid).unwrap(), "rpc").unwrap_err();
            assert!(!error.to_string().contains("sentinel"));
            assert!(!error.to_string().contains("https://"));
        }
        assert!(decode_response(&vec![b' '; MAX_RESPONSE_BYTES + 1], "rpc").is_err());
        assert!(decode_response(
            br#"{"protocolVersion":1,"requestId":"rpc","requestId":"rpc","result":{}}"#,
            "rpc"
        )
        .is_err());
    }

    #[cfg(all(not(unix), not(windows)))]
    #[test]
    fn configured_socket_on_unsupported_platform_fails_closed() {
        let _lock = env_test_lock();
        std::env::set_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV, "/tmp/account.sock");
        let error = match authority_from_environment() {
            Ok(_) => panic!("windows socket must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::ConfigRead { .. }));
        assert!(
            error.to_string().contains("unsupported"),
            "unexpected: {error}"
        );
        std::env::remove_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV);
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use crate::account_authority::{
            listen, AuthorityContext, AuthorityServerConfig, StoredAccountRegistry,
        };
        use crate::model::{AuthKind, StoredAccountMaterial};
        use crate::paths::stored_accounts_path;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use std::thread;

        fn private_tempdir() -> (tempfile::TempDir, PathBuf) {
            let dir = tempfile::tempdir().expect("tempdir");
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
            let canonical = fs::canonicalize(dir.path()).expect("canonical");
            (dir, canonical)
        }

        fn isolated_registry() -> (tempfile::TempDir, StoredAccountRegistry) {
            let dir = tempfile::tempdir().expect("tempdir");
            let data = dir.path().join("data");
            fs::create_dir_all(&data).expect("data");
            (dir, StoredAccountRegistry::new(stored_accounts_path(&data)))
        }

        fn listen_fixture(
            registry: StoredAccountRegistry,
        ) -> (
            tempfile::TempDir,
            coding_agent_manager_core::account_authority::AuthorityListener,
        ) {
            let (dir, root) = private_tempdir();
            let socket = root.join("account.sock");
            let path = resolve_socket_path(&socket).expect("safe");
            let ctx = AuthorityContext::new(registry).without_registry_fallback();
            let listener =
                listen(path, AuthorityServerConfig::new(ctx).expect("config")).expect("listen");
            (dir, listener)
        }

        #[test]
        fn configured_env_uses_remote_client_on_unix() {
            let _lock = super::env_test_lock();
            let (_registry_dir, registry) = isolated_registry();
            let (_guard, listener) = listen_fixture(registry);
            let socket_path = listener.path().to_path_buf();
            std::env::set_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV, &socket_path);
            let authority = account_authority().expect("authority");
            assert!(matches!(authority, AccountAuthority::Remote(_)));
            std::env::remove_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV);
        }

        #[test]
        fn exchange_refuses_invalid_envelopes_without_changing_local_selection() {
            let (_registry_dir, registry) = isolated_registry();
            registry
                .begin_add(
                    "codex-cli",
                    "work",
                    "Work",
                    AuthKind::OAuth,
                    StoredAccountMaterial::VendorHome,
                )
                .unwrap();
            registry.complete_add("codex-cli", "work").unwrap();
            registry
                .select_complete_revision("codex-cli", "work", None)
                .unwrap();
            let original = registry.selected_binding("codex-cli").unwrap();
            for case in 0..6 {
                let (_guard, root) = private_tempdir();
                let socket = root.join("authority.sock");
                let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
                let client = AuthorityClient::connect(&socket).unwrap();
                let server = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream.set_nonblocking(false).unwrap();
                    let deadline = std::time::Instant::now() + REQUEST_IO_DEADLINE;
                    apply_io_deadline(&stream, deadline).unwrap();
                    let request = read_framed(&mut stream, MAX_REQUEST_BYTES, deadline).unwrap();
                    let request: Value = serde_json::from_slice(&request).unwrap();
                    assert_eq!(request["operation"], "selection.get");
                    let mut response = json!({"protocolVersion": PROTOCOL_VERSION,
                        "requestId": request["requestId"], "result": {"selected": false}});
                    match case {
                        0 => response["requestId"] = json!("secret-sentinel"),
                        1 => {
                            response.as_object_mut().unwrap().remove("requestId");
                        }
                        2 => response["requestId"] = json!(""),
                        3 => {
                            response["error"] =
                                json!({"code": "busy", "message": "secret-sentinel"});
                        }
                        4 => {
                            response.as_object_mut().unwrap().remove("result");
                        }
                        _ => response["protocolVersion"] = json!(2),
                    }
                    write_framed(
                        &mut stream,
                        &serde_json::to_vec(&response).unwrap(),
                        deadline,
                    )
                    .unwrap();
                });
                let error = client.selected_binding("codex-cli").unwrap_err();
                assert!(!error.to_string().contains("secret-sentinel"));
                assert_eq!(registry.selected_binding("codex-cli").unwrap(), original);
                server.join().unwrap();
            }
        }

        #[test]
        fn client_selection_get_round_trips() {
            let (_registry_dir, registry) = isolated_registry();
            registry
                .begin_add(
                    "codex-cli",
                    "work",
                    "Work",
                    AuthKind::OAuth,
                    StoredAccountMaterial::VendorHome,
                )
                .expect("begin");
            registry
                .complete_add("codex-cli", "work")
                .expect("complete");
            registry
                .select_complete_revision("codex-cli", "work", None)
                .expect("select");
            let (_guard, listener) = listen_fixture(registry);
            let socket_path = listener.path().to_path_buf();
            thread::spawn(move || {
                let _ = listener.accept_once();
            });
            let client = AuthorityClient::connect(&socket_path).expect("client");
            let binding = client
                .selected_binding("codex-cli")
                .expect("selection")
                .expect("selected");
            assert_eq!(binding.account_id, "work");
        }

        #[test]
        fn remote_selection_uses_server_cas_without_local_vendor_home_validation() {
            use crate::providers::codex_cli::CodexCliAdapter;

            let (_registry_dir, registry) = isolated_registry();
            registry
                .begin_add(
                    "codex-cli",
                    "work",
                    "Work",
                    AuthKind::OAuth,
                    StoredAccountMaterial::VendorHome,
                )
                .unwrap();
            registry.complete_add("codex-cli", "work").unwrap();
            let account = registry.account("codex-cli", "work").unwrap();
            let (_guard, root) = private_tempdir();
            let socket = root.join("account.sock");
            let path = resolve_socket_path(&socket).unwrap();
            let adapter = CodexCliAdapter::with_home(root.join("vendor-home"))
                .with_data_dir(root.join("data"));
            let ctx = AuthorityContext::new(registry)
                .without_registry_fallback()
                .with_adapter(std::sync::Arc::new(adapter));
            let listener = listen(path, AuthorityServerConfig::new(ctx).unwrap()).unwrap();
            let client = AuthorityClient::connect(listener.path()).unwrap();
            let server = thread::spawn(move || {
                for _ in 0..6 {
                    listener.accept_once().unwrap();
                }
            });
            // No vendor credentials/home exist on the client. Only the server's
            // complete account, provider/incarnation and CAS revision authorize selection.
            client
                .select_launch_account(
                    &crate::providers::codex_cli::CodexCliAdapter::default(),
                    "work",
                )
                .unwrap();
            assert!(matches!(
                client.selection_set("codex-cli", "work", &account.account_incarnation, Some(0)),
                Err(Error::StaleSelection { .. })
            ));
            assert!(matches!(
                client.selection_set("codex-cli", "work", &"f".repeat(32), Some(1)),
                Err(Error::StaleAccount { .. })
            ));
            assert_eq!(
                client
                    .selected_binding("codex-cli")
                    .unwrap()
                    .unwrap()
                    .account_incarnation,
                account.account_incarnation
            );
            server.join().unwrap();
        }

        #[test]
        fn remote_login_requests_owner_browser_and_preserves_bound_authorization() {
            for provider in ["codex-cli", "cursor"] {
                let (_guard, root) = private_tempdir();
                let socket = root.join("authority.sock");
                let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
                let client = AuthorityClient::connect(&socket).unwrap();
                let binding = json!({"providerId":provider,"accountId":"work","accountIncarnation":"a".repeat(32)});
                let url = if provider == "cursor" {
                    format!("https://cursor.com/loginDeepControl?challenge={}&uuid=01234567-89ab-4cde-8fab-0123456789ab&mode=login&redirectTarget=cli", "A".repeat(43))
                } else {
                    "https://auth.openai.com/authorize?state=test-sentinel".to_string()
                };
                let authorization = json!({"authorizationUrl":url});
                let expected_binding = binding.clone();
                let expected_authorization = authorization.clone();
                let server = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream.set_nonblocking(false).unwrap();
                    let deadline = std::time::Instant::now() + REQUEST_IO_DEADLINE;
                    apply_io_deadline(&stream, deadline).unwrap();
                    let request = read_framed(&mut stream, MAX_REQUEST_BYTES, deadline).unwrap();
                    crate::account_authority::decode_request(&request)
                        .expect("existing strict protocol accepts browserMode");
                    let request: Value = serde_json::from_slice(&request).unwrap();
                    assert_eq!(request["browserMode"], "caller-managed");
                    assert_eq!(request["providerId"], provider);
                    assert_eq!(request["accountId"], "work");
                    assert_eq!(request["authKind"], "oauth");
                    let result = json!({"handle":"test-handle", "binding":binding, "state":"waiting-for-user",
                    "authorization":authorization});
                    let response =
                        AuthorityResponse::result(request["requestId"].as_str().unwrap(), result);
                    write_framed(
                        &mut stream,
                        &serde_json::to_vec(&response).unwrap(),
                        deadline,
                    )
                    .unwrap();
                });
                let status = client
                    .login_start(LoginStartRequest {
                        provider_id: provider.into(),
                        account_id: "work".into(),
                        label: "Work".into(),
                        auth_kind: AuthKind::OAuth,
                        idempotency_key: "test-request".into(),
                    })
                    .unwrap();
                assert_eq!(
                    serde_json::to_value(&status.binding).unwrap(),
                    expected_binding
                );
                assert_eq!(
                    serde_json::to_value(status.authorization.as_ref().unwrap()).unwrap(),
                    expected_authorization
                );
                assert!(!format!("{status:?}").contains("test-sentinel"));
                server.join().unwrap();
            }
        }
    }
}
