//! Unix-socket client for the headless Coding Agent Manager authority protocol.
//!
//! Framing matches [`coding_agent_manager_lib::account_authority::server`].

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use coding_agent_manager_lib::account_authority::{
    resolve_socket_path, AccountObserveResult, AuthorityResponse, ErrorCode, ObserveCategory,
    SelectedAccountBinding, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PROTOCOL_VERSION,
    REQUEST_IO_DEADLINE,
};
use serde_json::{json, Value};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Authority identity plus observation for one selected account.
#[cfg(target_os = "linux")]
pub(crate) struct ObservedSocketSelection {
    pub authority_id: String,
    pub observation: AccountObserveResult,
}

/// Observe the selected account for `provider_id` via a configured authority socket.
#[cfg(target_os = "linux")]
pub(crate) fn observe_selected_via_authority_socket(
    configured: &Path,
    provider_id: &str,
) -> Result<Option<AccountObserveResult>> {
    Ok(
        observe_selected_authority_via_socket(configured, provider_id)?
            .map(|observed| observed.observation),
    )
}

/// Observe the selected account and return the socket authority identity used.
#[cfg(target_os = "linux")]
pub(crate) fn observe_selected_authority_via_socket(
    configured: &Path,
    provider_id: &str,
) -> Result<Option<ObservedSocketSelection>> {
    let client = connect_authority_socket(configured)?;
    let Some((authority_id, binding)) = client.selection_get(provider_id)? else {
        return Ok(None);
    };
    let observation = client.account_observe(&authority_id, binding).with_context(|| {
        format!(
            "failed to observe selected Coding Agent Manager account for `{provider_id}` via authority socket"
        )
    })?;
    Ok(Some(ObservedSocketSelection {
        authority_id,
        observation,
    }))
}

/// Read the selected binding from a configured authority socket without observing models.
#[cfg(target_os = "linux")]
pub(crate) fn selected_binding_via_authority_socket(
    configured: &Path,
    provider_id: &str,
) -> Result<Option<(String, SelectedAccountBinding)>> {
    connect_authority_socket(configured)?.selection_get(provider_id)
}

#[cfg(target_os = "linux")]
fn connect_authority_socket(configured: &Path) -> Result<AuthoritySocketClient> {
    let path = resolve_socket_path(configured).with_context(|| {
        format!(
            "CAM authority socket path `{}` failed ancestry checks",
            configured.display()
        )
    })?;
    Ok(AuthoritySocketClient { path })
}

#[cfg(target_os = "linux")]
struct AuthoritySocketClient {
    path: coding_agent_manager_lib::account_authority::SafeSocketPath,
}

#[cfg(target_os = "linux")]
impl AuthoritySocketClient {
    fn selection_get(&self, provider_id: &str) -> Result<Option<(String, SelectedAccountBinding)>> {
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
            .ok_or_else(|| anyhow!("selection.get result missing boolean `selected`"))?;
        if !selected {
            return Ok(None);
        }
        let authority_id = required_string_field(&result, "authorityId")?;
        let binding = SelectedAccountBinding {
            provider_id: required_string_field(&result, "providerId")?,
            account_id: required_string_field(&result, "accountId")?,
            account_incarnation: required_string_field(&result, "accountIncarnation")?,
            selection_revision: result
                .get("selectionRevision")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("selection.get result missing `selectionRevision`"))?,
        };
        Ok(Some((authority_id, binding)))
    }

    fn account_observe(
        &self,
        authority_id: &str,
        binding: SelectedAccountBinding,
    ) -> Result<AccountObserveResult> {
        let response = self.exchange(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": next_request_id(),
            "operation": "account.observe",
            "authorityId": authority_id,
            "binding": binding,
            "categories": [
                ObserveCategory::Models,
                ObserveCategory::Quota,
            ],
        }))?;
        let result = wire_result(response, "account.observe")?;
        serde_json::from_value(result).context("account.observe result could not be decoded")
    }

    fn exchange(&self, request: Value) -> Result<AuthorityResponse> {
        use std::os::unix::net::UnixStream;

        let body = serde_json::to_vec(&request).context("encode CAM authority request")?;
        if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
            return Err(anyhow!("CAM authority request exceeds maxRequestBytes"));
        }

        let mut stream = UnixStream::connect(self.path.as_path()).with_context(|| {
            format!(
                "failed to connect to CAM authority socket `{}`",
                self.path.as_path().display()
            )
        })?;

        let deadline = Instant::now() + REQUEST_IO_DEADLINE;
        write_framed(&mut stream, &body, deadline)?;
        let response_bytes = read_framed(&mut stream, MAX_RESPONSE_BYTES, deadline)?;
        let response: AuthorityResponse =
            serde_json::from_slice(&response_bytes).context("decode CAM authority response")?;
        if response.protocol_version != PROTOCOL_VERSION {
            return Err(anyhow!(
                "CAM authority response protocolVersion {} is not supported",
                response.protocol_version
            ));
        }
        Ok(response)
    }
}

#[cfg(target_os = "linux")]
fn wire_result(response: AuthorityResponse, operation: &str) -> Result<Value> {
    if let Some(error) = response.error {
        return Err(anyhow!(
            "CAM authority `{operation}` failed with {}: {}",
            error_code_label(error.code),
            error.message
        ));
    }
    response
        .result
        .ok_or_else(|| anyhow!("CAM authority `{operation}` response missing result"))
}

#[cfg(target_os = "linux")]
fn error_code_label(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidRequest => "invalid-request",
        ErrorCode::UnsupportedVersion => "unsupported-version",
        ErrorCode::AccessDenied => "access-denied",
        ErrorCode::UnsupportedOperation => "unsupported-operation",
        ErrorCode::UnknownAccount => "unknown-account",
        ErrorCode::StaleSelection => "stale-selection",
        ErrorCode::StaleAccount => "stale-account",
        ErrorCode::Busy => "busy",
        ErrorCode::ReauthenticationRequired => "reauthentication-required",
        ErrorCode::Unavailable => "unavailable",
        ErrorCode::StateUnavailable => "state-unavailable",
        ErrorCode::OutcomeUnknown => "outcome-unknown",
    }
}

#[cfg(target_os = "linux")]
fn required_string_field(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("CAM authority response missing `{field}`"))
}

#[cfg(target_os = "linux")]
fn next_request_id() -> String {
    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("maco-cam-{id}")
}

#[cfg(target_os = "linux")]
fn write_framed(
    stream: &mut std::os::unix::net::UnixStream,
    body: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    use std::io::Write;
    apply_io_deadline(stream, deadline)?;
    stream
        .write_all(&(body.len() as u32).to_be_bytes())
        .context("write CAM authority request length")?;
    stream
        .write_all(body)
        .context("write CAM authority request body")?;
    Ok(())
}

#[cfg(target_os = "linux")]
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
        .context("read CAM authority response length")?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > max_response_bytes || length > MAX_RESPONSE_BYTES {
        return Err(anyhow!("CAM authority response exceeds maxResponseBytes"));
    }
    let mut body = vec![0u8; length];
    stream
        .read_exact(&mut body)
        .context("read CAM authority response body")?;
    Ok(body)
}

#[cfg(target_os = "linux")]
fn apply_io_deadline(
    stream: &std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(anyhow!("CAM authority request I/O deadline elapsed"));
    }
    stream
        .set_read_timeout(Some(remaining))
        .context("set CAM authority read timeout")?;
    stream
        .set_write_timeout(Some(remaining))
        .context("set CAM authority write timeout")?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use coding_agent_manager_lib::account_authority::{
        listen, AuthorityContext, AuthorityServerConfig, CategoryObservation, ModelsObservation,
        ObservationOutcome, ObservedModel, StoredAccountRegistry,
    };
    use coding_agent_manager_lib::error::Error as CamError;
    use coding_agent_manager_lib::model::{
        Account, AuthKind, InstallState, Maturity, ProviderDescriptor, StoredAccountMaterial,
        StoredAccountMetadata,
    };
    use coding_agent_manager_lib::paths::stored_accounts_path;
    use coding_agent_manager_lib::providers::ProviderAdapter;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    struct ObserveStubAdapter {
        provider_id: &'static str,
    }

    impl ProviderAdapter for ObserveStubAdapter {
        fn id(&self) -> &'static str {
            self.provider_id
        }

        fn descriptor(&self) -> ProviderDescriptor {
            ProviderDescriptor {
                id: self.provider_id.to_string(),
                display_name: self.provider_id.to_string(),
                vendor: "test".to_string(),
                auth_kinds: vec![AuthKind::OAuth],
                maturity: Maturity::Experimental,
                install_state: InstallState::Unknown,
                capabilities: Vec::new(),
            }
        }

        fn config_paths(&self) -> Vec<PathBuf> {
            Vec::new()
        }

        fn detect(&self) -> InstallState {
            InstallState::Unknown
        }

        fn list_accounts(&self) -> coding_agent_manager_lib::error::Result<Vec<Account>> {
            Ok(Vec::new())
        }

        fn activate_account(
            &self,
            _account_id: &str,
        ) -> coding_agent_manager_lib::error::Result<()> {
            Err(CamError::NotImplemented("activate"))
        }

        fn observe_models_for_account(
            &self,
            _account: &StoredAccountMetadata,
        ) -> coding_agent_manager_lib::error::Result<CategoryObservation<ModelsObservation>>
        {
            Ok(CategoryObservation::observed(ModelsObservation {
                models: vec![ObservedModel {
                    model_id: "frontier-test".to_string(),
                    supported_efforts: None,
                    default_effort: None,
                }],
            }))
        }
    }

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

    fn seed_selected_account(registry: &StoredAccountRegistry) {
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
    }

    fn listen_fixture(
        registry: StoredAccountRegistry,
    ) -> (
        tempfile::TempDir,
        coding_agent_manager_lib::account_authority::AuthorityListener,
    ) {
        let (dir, root) = private_tempdir();
        let socket = root.join("account.sock");
        let path = resolve_socket_path(&socket).expect("safe");
        let mut ctx = AuthorityContext::new(registry).without_registry_fallback();
        ctx.adapters.insert(
            "codex-cli".to_string(),
            Arc::new(ObserveStubAdapter {
                provider_id: "codex-cli",
            }) as Arc<dyn ProviderAdapter>,
        );
        let listener =
            listen(path, AuthorityServerConfig::new(ctx).expect("config")).expect("listen");
        (dir, listener)
    }

    #[test]
    fn framing_helpers_round_trip_payload() {
        use std::os::unix::net::UnixListener;
        use std::time::Instant;

        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("frame.sock");
        let listener = UnixListener::bind(&socket_path).expect("bind");
        let payload = br#"{"protocolVersion":1,"requestId":"t","operation":"authority.describe"}"#;
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let deadline = Instant::now() + REQUEST_IO_DEADLINE;
            let body = read_framed(&mut stream, MAX_RESPONSE_BYTES, deadline).expect("read");
            assert_eq!(body, payload);
            write_framed(&mut stream, br#"{"ok":true}"#, deadline).expect("write");
        });
        let mut client = std::os::unix::net::UnixStream::connect(&socket_path).expect("connect");
        let deadline = Instant::now() + REQUEST_IO_DEADLINE;
        write_framed(&mut client, payload, deadline).expect("write req");
        let response = read_framed(&mut client, MAX_RESPONSE_BYTES, deadline).expect("read resp");
        assert_eq!(response, br#"{"ok":true}"#);
        handle.join().expect("join");
    }

    #[test]
    fn observe_selected_via_socket_returns_none_when_unselected() {
        let (_registry_dir, registry) = isolated_registry();
        let (_guard, listener) = listen_fixture(registry);
        let socket_path = listener.path().to_path_buf();
        thread::spawn(move || {
            let _ = listener.accept_once();
        });
        let result =
            observe_selected_via_authority_socket(&socket_path, "codex-cli").expect("observe");
        assert!(result.is_none());
    }

    #[test]
    fn observe_selected_via_socket_returns_authority_observation() {
        let (_registry_dir, registry) = isolated_registry();
        seed_selected_account(&registry);
        let (_guard, listener) = listen_fixture(registry);
        let socket_path = listener.path().to_path_buf();
        thread::spawn(move || {
            let _ = listener.accept_once();
            let _ = listener.accept_once();
        });
        let observation = observe_selected_via_authority_socket(&socket_path, "codex-cli")
            .expect("observe")
            .expect("selected binding");
        assert_eq!(observation.binding.provider_id, "codex-cli");
        assert_eq!(observation.binding.account_id, "work");
        let models = observation.models.as_ref().expect("models");
        assert_eq!(models.outcome, ObservationOutcome::Observed);
        let quota = observation.quota.as_ref().expect("quota");
        assert_eq!(quota.outcome, ObservationOutcome::Unknown);
        assert!(quota.content.is_none());
    }

    #[test]
    fn missing_socket_endpoint_fails_closed_without_observation() {
        let (dir, root) = private_tempdir();
        let socket_path = root.join("missing.sock");
        let error = observe_selected_via_authority_socket(&socket_path, "codex-cli")
            .expect_err("missing socket must fail closed");
        assert!(
            error.to_string().contains("connect"),
            "unexpected error: {error:#}"
        );
        drop(dir);
    }

    #[test]
    fn observe_selected_authority_returns_stable_authority_identity() {
        let (_registry_dir, registry) = isolated_registry();
        seed_selected_account(&registry);
        let expected_authority =
            coding_agent_manager_lib::account_authority::authority_id_for(registry.metadata_path());
        let (_guard, listener) = listen_fixture(registry);
        let socket_path = listener.path().to_path_buf();
        thread::spawn(move || while listener.accept_once().is_ok() {});
        let observed = observe_selected_authority_via_socket(&socket_path, "codex-cli")
            .expect("observe")
            .expect("selected binding");
        assert_eq!(observed.authority_id, expected_authority);
        assert_eq!(observed.observation.binding.account_id, "work");
        let selected = selected_binding_via_authority_socket(&socket_path, "codex-cli")
            .expect("selection.get")
            .expect("selected");
        assert_eq!(selected.0, expected_authority);
        assert_eq!(selected.1.account_id, "work");
    }
}
