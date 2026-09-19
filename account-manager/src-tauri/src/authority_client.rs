//! Desktop client for the headless account-authority Unix socket.
//!
//! Framing matches [`coding_agent_manager_core::account_authority::server`].

use crate::account_authority::{SocketPathError, StoredAccountRegistry};
use crate::error::{Error, Result};
use crate::providers::{self, ProviderAdapter};

#[cfg(unix)]
use crate::account_authority::{
    resolve_socket_path, AccountObserveRequest, AccountObserveResult, AuthorityResponse, ErrorCode,
    SelectedAccountBinding, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
    REQUEST_IO_DEADLINE,
};
#[cfg(unix)]
use crate::login::{LoginAccountBinding, LoginHandle, LoginStartRequest, LoginStatus};
#[cfg(unix)]
use crate::model::{StoredAccountMetadata, StoredAccountState};
#[cfg(unix)]
use serde_json::{json, Value};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::sync::{Arc, Mutex};

/// Environment variable naming the headless authority Unix socket path.
pub const CAM_ACCOUNT_AUTHORITY_SOCKET_ENV: &str = "CAM_ACCOUNT_AUTHORITY_SOCKET";

#[cfg(unix)]
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Either the in-process registry or a remote authority socket client.
pub enum AccountAuthority {
    InProcess(StoredAccountRegistry),
    #[cfg(unix)]
    Remote(AuthorityClient),
}

impl AccountAuthority {
    pub fn in_process_registry(&self) -> Result<&StoredAccountRegistry> {
        match self {
            Self::InProcess(registry) => Ok(registry),
            #[cfg(unix)]
            Self::Remote(_) => Err(external_registry_error()),
        }
    }
}

/// Resolve desktop account authority from the environment.
pub fn account_authority() -> Result<AccountAuthority> {
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

pub(crate) fn in_process_stored_account_registry() -> Result<StoredAccountRegistry> {
    let dirs = crate::paths::project_dirs().ok_or_else(|| Error::ConfigRead {
        provider: "account-metadata".to_string(),
        reason: "the application data directory could not be resolved".to_string(),
    })?;
    Ok(StoredAccountRegistry::new(
        crate::paths::stored_accounts_path(dirs.data_dir()),
    ))
}

fn connect_remote_authority(configured: &str) -> Result<AccountAuthority> {
    #[cfg(unix)]
    {
        let client = AuthorityClient::connect(configured)?;
        return Ok(AccountAuthority::Remote(client));
    }
    #[cfg(not(unix))]
    {
        let _ = configured;
        Err(map_socket_path_error(SocketPathError::UnsupportedPlatform))
    }
}

#[cfg(unix)]
fn external_registry_error() -> Error {
    Error::ConfigRead {
        provider: "account-authority".to_string(),
        reason: "managed account metadata is owned by the headless authority; unset \
                 CAM_ACCOUNT_AUTHORITY_SOCKET or use the authority socket operations"
            .to_string(),
    }
}

fn map_socket_path_error(error: SocketPathError) -> Error {
    Error::ConfigRead {
        provider: "account-authority".to_string(),
        reason: error.to_string(),
    }
}

/// Unix-socket RPC client for advertised authority operations.
#[cfg(unix)]
#[derive(Clone)]
pub struct AuthorityClient {
    path: crate::account_authority::SafeSocketPath,
    authority_id: Arc<Mutex<Option<String>>>,
}

#[cfg(unix)]
impl AuthorityClient {
    pub fn connect(configured: impl AsRef<Path>) -> Result<Self> {
        let path = resolve_socket_path(configured.as_ref()).map_err(map_socket_path_error)?;
        Ok(Self {
            path,
            authority_id: Arc::new(Mutex::new(None)),
        })
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
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
        serde_json::from_value(records.clone())
            .map_err(|error| authority_decode_error(&format!("accounts.list records: {error}")))
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
        Ok(Some(parse_selection_binding(&result)?))
    }

    pub fn selected_metadata(&self, provider_id: &str) -> Result<Option<StoredAccountMetadata>> {
        let Some(binding) = self.selected_binding(provider_id)? else {
            return Ok(None);
        };
        Ok(Some(
            self.complete_account(provider_id, &binding.account_id)?,
        ))
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
        parse_selection_binding(&result)
    }

    pub fn account_observe(&self, request: AccountObserveRequest) -> Result<AccountObserveResult> {
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
        serde_json::from_value(result).map_err(|error| {
            authority_decode_error(&format!(
                "account.observe result could not be decoded: {error}"
            ))
        })
    }

    pub fn login_start(&self, request: LoginStartRequest) -> Result<LoginStatus> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "login.start",
            "providerId": request.provider_id,
            "accountId": request.account_id,
            "label": request.label,
            "authKind": request.auth_kind,
            "idempotencyKey": request.idempotency_key,
        }))?;
        let result = wire_result(response, "login.start")?;
        serde_json::from_value(result)
            .map_err(|error| authority_decode_error(&format!("login.start result: {error}")))
    }

    pub fn login_status(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<LoginStatus> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "login.status",
            "handle": handle,
            "binding": binding,
        }))?;
        let result = wire_result(response, "login.status")?;
        serde_json::from_value(result)
            .map_err(|error| authority_decode_error(&format!("login.status result: {error}")))
    }

    pub fn login_cancel(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<LoginStatus> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "login.cancel",
            "handle": handle,
            "binding": binding,
        }))?;
        let result = wire_result(response, "login.cancel")?;
        serde_json::from_value(result)
            .map_err(|error| authority_decode_error(&format!("login.cancel result: {error}")))
    }

    pub fn select_launch_account(
        &self,
        adapter: &dyn ProviderAdapter,
        account_id: &str,
    ) -> Result<()> {
        let target = self.complete_account(adapter.id(), account_id)?;
        if let Some(current) = self.selected_metadata(adapter.id())? {
            if current.id != target.id {
                let _validated = providers::launch_spec_for(adapter, &current)?;
            }
        }
        let _validated_target = providers::launch_spec_for(adapter, &target)?;
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
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use std::time::Instant;

        let body = serde_json::to_vec(&request).map_err(Error::Serde)?;
        if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
            return Err(authority_io_error(
                "authority request exceeds maxRequestBytes",
            ));
        }

        let mut stream = UnixStream::connect(self.path.as_path()).map_err(|error| {
            authority_io_error(&format!(
                "failed to connect to authority socket `{}`: {error}",
                self.path.as_path().display()
            ))
        })?;

        let deadline = Instant::now() + REQUEST_IO_DEADLINE;
        write_framed(&mut stream, &body, deadline)?;
        let response_bytes = read_framed(&mut stream, MAX_RESPONSE_BYTES, deadline)?;
        let response: AuthorityResponse = serde_json::from_slice(&response_bytes)?;
        if response.protocol_version != PROTOCOL_VERSION {
            return Err(authority_io_error(&format!(
                "authority response protocolVersion {} is not supported",
                response.protocol_version
            )));
        }
        Ok(response)
    }
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn wire_result(response: AuthorityResponse, operation: &str) -> Result<Value> {
    if let Some(error) = response.error {
        return Err(map_wire_error(operation, error.code, &error.message));
    }
    response
        .result
        .ok_or_else(|| authority_decode_error(&format!("authority `{operation}` missing result")))
}

#[cfg(unix)]
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

#[cfg(unix)]
fn required_string_field(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| authority_decode_error(&format!("authority response missing `{field}`")))
}

#[cfg(unix)]
fn authority_io_error(reason: &str) -> Error {
    Error::ConfigRead {
        provider: "account-authority".to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(unix)]
fn authority_decode_error(reason: &str) -> Error {
    Error::ConfigRead {
        provider: "account-authority".to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(unix)]
fn next_request_id() -> String {
    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("cam-desktop-{id}")
}

#[cfg(unix)]
fn write_framed(
    stream: &mut std::os::unix::net::UnixStream,
    body: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    use std::io::Write;
    apply_io_deadline(stream, deadline)?;
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .map_err(|error| authority_io_error(&format!("write authority request length: {error}")))?;
    stream
        .write_all(body)
        .map_err(|error| authority_io_error(&format!("write authority request body: {error}")))?;
    Ok(())
}

#[cfg(unix)]
fn read_framed(
    stream: &mut std::os::unix::net::UnixStream,
    max_response_bytes: usize,
    deadline: std::time::Instant,
) -> Result<Vec<u8>> {
    use std::io::Read;
    apply_io_deadline(stream, deadline)?;
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

#[cfg(unix)]
fn apply_io_deadline(
    stream: &std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
) -> Result<()> {
    use std::time::Instant;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(authority_io_error("authority request I/O deadline elapsed"));
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|error| authority_io_error(&format!("set authority read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|error| authority_io_error(&format!("set authority write timeout: {error}")))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn select_launch_account(
    authority: &AccountAuthority,
    adapter: &dyn ProviderAdapter,
    account_id: &str,
) -> Result<()> {
    match authority {
        AccountAuthority::InProcess(registry) => {
            providers::select_launch_account(registry, adapter, account_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn env_test_lock() -> MutexGuard<'static, ()> {
        ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn unset_env_uses_in_process_registry() {
        let _lock = env_test_lock();
        std::env::remove_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV);
        let authority = account_authority().expect("authority");
        assert!(matches!(authority, AccountAuthority::InProcess(_)));
        authority
            .in_process_registry()
            .expect("in-process registry");
    }

    #[test]
    fn empty_env_uses_in_process_registry() {
        let _lock = env_test_lock();
        std::env::set_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV, "   ");
        let authority = account_authority().expect("authority");
        assert!(matches!(authority, AccountAuthority::InProcess(_)));
        std::env::remove_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV);
    }

    #[cfg(not(unix))]
    #[test]
    fn configured_socket_on_windows_fails_closed() {
        let _lock = env_test_lock();
        std::env::set_var(CAM_ACCOUNT_AUTHORITY_SOCKET_ENV, "/tmp/account.sock");
        let error = match account_authority() {
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
    }
}
