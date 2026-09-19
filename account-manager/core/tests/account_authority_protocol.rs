//! Headless account-authority protocol v1 contract tests.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use coding_agent_manager_lib::account_authority::{
    authority_id_for, decode_request, dispatch, map_core_error, AuthorityContext,
    AuthorityServerConfig, ErrorCode, GeminiLoginPort, LoginPort, StoredAccountRegistry,
    ADVERTISED_OPERATIONS, PROTOCOL_VERSION,
};
#[cfg(not(unix))]
use coding_agent_manager_lib::account_authority::{
    listen, ListenError, SafeSocketPath, SocketPathError,
};
use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::login::{
    LoginAccountBinding, LoginHandle, LoginService, LoginStartRequest, LoginState, LoginStatus,
};
use coding_agent_manager_lib::model::{
    Account, AuthKind, InstallState, Maturity, ProviderDescriptor, StoredAccountMaterial,
};
use coding_agent_manager_lib::paths::stored_accounts_path;
use coding_agent_manager_lib::providers::{
    claude_code::ClaudeCodeAdapter, gemini_cli::GeminiCliAdapter, ProviderAdapter,
};

struct ActivateProbeAdapter {
    activated: Arc<AtomicBool>,
    local_accounts: Vec<Account>,
}

impl ProviderAdapter for ActivateProbeAdapter {
    fn id(&self) -> &'static str {
        "gemini-cli"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: "gemini-cli".to_string(),
            display_name: "Gemini".to_string(),
            vendor: "test".to_string(),
            auth_kinds: vec![AuthKind::OAuth],
            maturity: Maturity::Experimental,
            install_state: InstallState::Unknown,
            capabilities: Vec::new(),
        }
    }

    fn config_paths(&self) -> Vec<std::path::PathBuf> {
        Vec::new()
    }

    fn detect(&self) -> InstallState {
        InstallState::Unknown
    }

    fn list_accounts(&self) -> coding_agent_manager_lib::error::Result<Vec<Account>> {
        Ok(self.local_accounts.clone())
    }

    fn activate_account(&self, _account_id: &str) -> coding_agent_manager_lib::error::Result<()> {
        self.activated.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct FakeLogin {
    starts: Mutex<Vec<LoginStartRequest>>,
    by_key: Mutex<std::collections::HashMap<String, (LoginStartRequest, LoginStatus)>>,
}

impl FakeLogin {
    fn new() -> Self {
        Self {
            starts: Mutex::new(Vec::new()),
            by_key: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl LoginPort for FakeLogin {
    fn start(
        &self,
        request: LoginStartRequest,
    ) -> coding_agent_manager_lib::error::Result<LoginStatus> {
        self.starts.lock().expect("starts").push(request.clone());
        let mut by_key = self.by_key.lock().expect("by_key");
        if let Some((previous, status)) = by_key.get(&request.idempotency_key) {
            if previous != &request {
                return Err(Error::ConfigWrite {
                    provider: request.provider_id,
                    reason: "idempotency key was reused with a different login request".to_string(),
                });
            }
            return Ok(status.clone());
        }
        let status = LoginStatus {
            handle: serde_json::from_str("\"login-handle-1\"").expect("handle"),
            binding: LoginAccountBinding {
                provider_id: request.provider_id.clone(),
                account_id: request.account_id.clone(),
                account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
            },
            state: LoginState::WaitingForUser,
            failure_reason: None,
        };
        by_key.insert(request.idempotency_key.clone(), (request, status.clone()));
        Ok(status)
    }

    fn status(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> coding_agent_manager_lib::error::Result<LoginStatus> {
        let by_key = self.by_key.lock().expect("by_key");
        if let Some((_, status)) = by_key
            .values()
            .find(|(_, status)| status.handle == *handle && status.binding == *binding)
        {
            return Ok(status.clone());
        }
        Ok(LoginStatus {
            handle: handle.clone(),
            binding: binding.clone(),
            state: LoginState::Unknown,
            failure_reason: None,
        })
    }

    fn cancel(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> coding_agent_manager_lib::error::Result<LoginStatus> {
        self.status(handle, binding)
    }
}

fn isolated_registry() -> (tempfile::TempDir, StoredAccountRegistry) {
    let dir = tempfile::tempdir().expect("tempdir");
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).expect("data");
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    (dir, registry)
}

fn local_observation_account() -> Account {
    Account {
        id: "on-disk-local".to_string(),
        provider_id: "gemini-cli".to_string(),
        label: "Local observation".to_string(),
        masked_identity: None,
        auth_kind: AuthKind::OAuth,
        is_active: false,
        is_selected_for_launch: false,
        is_stored: false,
        is_incomplete: false,
        expires_at: None,
    }
}

fn context_with_probe(
    registry: StoredAccountRegistry,
    activated: Arc<AtomicBool>,
) -> AuthorityContext {
    let adapter = Arc::new(ActivateProbeAdapter {
        activated,
        local_accounts: vec![local_observation_account()],
    });
    AuthorityContext::new(registry)
        .without_registry_fallback()
        .with_adapter(adapter)
}

fn seed_complete(registry: &StoredAccountRegistry, account_id: &str) -> String {
    let account = registry
        .begin_add(
            "gemini-cli",
            account_id,
            account_id,
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin");
    registry
        .complete_add("gemini-cli", account_id)
        .expect("complete");
    account.account_incarnation
}

fn dispatch_json(ctx: &AuthorityContext, json: &str) -> serde_json::Value {
    let decoded = decode_request(json.as_bytes()).expect("decode");
    let response = dispatch(ctx, &decoded);
    serde_json::to_value(response).expect("response json")
}

#[cfg(not(unix))]
#[test]
fn unix_authority_listen_is_unsupported_on_this_platform() {
    let (_dir, registry) = isolated_registry();
    let config = AuthorityServerConfig::new(AuthorityContext::new(registry)).expect("config");
    match listen(SafeSocketPath::unsupported_platform(), config) {
        Err(ListenError::SocketPath(SocketPathError::UnsupportedPlatform)) => {}
        Err(error) => panic!("unexpected listen error: {error:?}"),
        Ok(_) => panic!("expected listen to fail on this platform"),
    }
}

#[test]
fn decode_unknown_duplicate_and_version_are_refused() {
    let unknown = decode_request(
        br#"{"protocolVersion":1,"requestId":"r1","operation":"authority.describe","extra":true}"#,
    )
    .expect_err("unknown field");
    assert_eq!(unknown.code, ErrorCode::InvalidRequest);
    assert_eq!(unknown.request_id, "r1");

    let duplicate = decode_request(
        br#"{"protocolVersion":1,"protocolVersion":1,"requestId":"r1","operation":"authority.describe"}"#,
    )
    .expect_err("duplicate");
    assert_eq!(duplicate.code, ErrorCode::InvalidRequest);

    let version = decode_request(
        br#"{"protocolVersion":2,"requestId":"r2","operation":"authority.describe"}"#,
    )
    .expect_err("version");
    assert_eq!(version.code, ErrorCode::UnsupportedVersion);
    assert_eq!(version.request_id, "r2");
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
        "callerPolicyDigest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "admissionRequirements": [],
        "idempotencyKey": "prep-1"
    })
}

#[test]
fn decode_refuses_operation_prepare_without_closed_fields() {
    let error = decode_request(
        br#"{"protocolVersion":1,"requestId":"prep","operation":"operation.prepare"}"#,
    )
    .expect_err("missing prepare fields");
    assert_eq!(error.code, ErrorCode::InvalidRequest);
    assert_eq!(error.request_id, "prep");
}

#[test]
fn dispatch_refuses_well_formed_operation_prepare_until_advertised() {
    let (_dir, registry) = isolated_registry();
    let ctx = AuthorityContext::new(registry).without_registry_fallback();
    let decoded = decode_request(operation_prepare_body().to_string().as_bytes())
        .expect("well-formed prepare decodes");
    let response = serde_json::to_value(dispatch(&ctx, &decoded)).expect("json");
    assert_eq!(response["error"]["code"], "unsupported-operation");
    assert_eq!(
        response["error"]["message"],
        "operation.prepare is not advertised until a provider \
advertises work-proposal tool restrictions"
    );
    assert!(response["result"].is_null());
    assert!(!ADVERTISED_OPERATIONS.contains(&"operation.prepare"));
}

const OPERATION_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn operation_lifecycle_body(operation: &str) -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "requestId": operation,
        "operation": operation,
        "handle": "opaque-handle",
        "digest": OPERATION_DIGEST,
    })
}

#[test]
fn decode_refuses_operation_lifecycle_without_closed_fields() {
    for operation in ["operation.start", "operation.status", "operation.cancel"] {
        let error = decode_request(
            format!(
                r#"{{"protocolVersion":1,"requestId":"{operation}","operation":"{operation}"}}"#
            )
            .as_bytes(),
        )
        .expect_err("missing lifecycle fields");
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert_eq!(error.request_id, operation);
    }
}

#[test]
fn decode_accepts_operation_lifecycle_handle_and_digest() {
    for operation in ["operation.start", "operation.status", "operation.cancel"] {
        decode_request(operation_lifecycle_body(operation).to_string().as_bytes())
            .unwrap_or_else(|_| panic!("well-formed {operation} decodes"));
    }
}

#[test]
fn dispatch_refuses_well_formed_operation_lifecycle_until_advertised() {
    let (_dir, registry) = isolated_registry();
    let ctx = AuthorityContext::new(registry).without_registry_fallback();
    for operation in ["operation.start", "operation.status", "operation.cancel"] {
        let decoded = decode_request(operation_lifecycle_body(operation).to_string().as_bytes())
            .expect("decode");
        let response = serde_json::to_value(dispatch(&ctx, &decoded)).expect("json");
        assert_eq!(response["error"]["code"], "unsupported-operation");
        assert_eq!(
            response["error"]["message"],
            format!(
                "{operation} is not advertised until a provider \
advertises work-proposal tool restrictions"
            )
        );
        assert!(response["result"].is_null());
        assert!(!ADVERTISED_OPERATIONS.contains(&operation));
    }
}

#[test]
fn operation_lifecycle_operations_stay_unadvertised() {
    assert_eq!(ADVERTISED_OPERATIONS.len(), 8);
    for operation in [
        "operation.prepare",
        "operation.start",
        "operation.status",
        "operation.cancel",
    ] {
        assert!(!ADVERTISED_OPERATIONS.contains(&operation));
    }
}

#[test]
fn decode_refuses_operation_prepare_with_unknown_kind_or_digest() {
    let mut kind = operation_prepare_body();
    kind["operationKind"] = serde_json::json!("reset-probe");
    let kind_error = decode_request(kind.to_string().as_bytes()).expect_err("kind");
    assert_eq!(kind_error.code, ErrorCode::InvalidRequest);

    let mut digest = operation_prepare_body();
    digest["callerPolicyDigest"] = serde_json::json!("not-a-digest");
    let digest_error = decode_request(digest.to_string().as_bytes()).expect_err("digest");
    assert_eq!(digest_error.code, ErrorCode::InvalidRequest);
}

#[test]
fn dispatch_refuses_unknown_login_start() {
    let (_dir, registry) = isolated_registry();
    let login = Arc::new(FakeLogin::new());
    let ctx = AuthorityContext::new(registry)
        .without_registry_fallback()
        .with_login(Arc::clone(&login) as Arc<dyn LoginPort>);
    let body = serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "requestId": "login",
        "operation": "login.start",
        "providerId": "not-a-provider",
        "accountId": "work",
        "label": "Work",
        "authKind": "oauth",
        "idempotencyKey": "key-1"
    });
    let response = dispatch_json(&ctx, &body.to_string());
    assert_eq!(response["error"]["code"], "unsupported-operation");
    assert_eq!(
        response["error"]["message"],
        "login.start is implemented for Gemini, Codex, Claude, Grok, Cursor, and GitHub Copilot only"
    );
    assert!(login.starts.lock().expect("starts").is_empty());
}

#[test]
fn dispatch_accepts_claude_and_cursor_login_start() {
    let (_dir, registry) = isolated_registry();
    let login = Arc::new(FakeLogin::new());
    let ctx = AuthorityContext::new(registry)
        .without_registry_fallback()
        .with_login(Arc::clone(&login) as Arc<dyn LoginPort>);
    for provider_id in ["claude-code", "cursor", "github-copilot"] {
        let body = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": "login",
            "operation": "login.start",
            "providerId": provider_id,
            "accountId": "work",
            "label": "Work",
            "authKind": "oauth",
            "idempotencyKey": format!("key-{provider_id}")
        });
        let response = dispatch_json(&ctx, &body.to_string());
        assert!(response["error"].is_null(), "{provider_id}");
        assert_eq!(response["result"]["handle"], "login-handle-1");
        assert_eq!(response["result"]["state"], "waiting-for-user");
        assert_eq!(
            response["result"]["binding"]["providerId"], provider_id,
            "{provider_id}"
        );
    }
    assert_eq!(login.starts.lock().expect("starts").len(), 3);
}

fn write_claude_managed_oauth(home: &std::path::Path) -> std::io::Result<i32> {
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/claude-code/managed-oauth"
    );
    let src = std::path::Path::new(FIXTURE);
    std::fs::copy(
        src.join(".credentials.json"),
        home.join(".credentials.json"),
    )?;
    std::fs::copy(src.join(".claude.json"), home.join(".claude.json"))?;
    Ok(0)
}

#[test]
fn production_login_port_starts_claude_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let data = dir.path().join("data");
    std::fs::create_dir_all(home.join(".claude")).expect("home");
    std::fs::create_dir_all(&data).expect("data");
    let claude = ClaudeCodeAdapter::with_home(&home)
        .with_data_dir(&data)
        .with_login_runner(write_claude_managed_oauth);
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let service = LoginService::new(
        StoredAccountRegistry::new(registry.metadata_path().to_path_buf()),
        runtime.handle().clone(),
    );
    let ctx = AuthorityContext::new(registry).without_registry_fallback();
    let config = AuthorityServerConfig::new(ctx)
        .expect("config")
        .with_login_port(Arc::new(GeminiLoginPort::new(
            service,
            GeminiCliAdapter::default(),
            claude,
        )));
    let body = serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "requestId": "login",
        "operation": "login.start",
        "providerId": "claude-code",
        "accountId": "work",
        "label": "Work",
        "authKind": "oauth",
        "idempotencyKey": "key-claude-code"
    });
    let response = dispatch_json(&config.context, &body.to_string());
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(response["result"]["state"], "waiting-for-user");
    assert_eq!(response["result"]["binding"]["providerId"], "claude-code");
}

#[test]
fn production_login_port_leaves_cursor_and_github_copilot_unimplemented() {
    let (_dir, registry) = isolated_registry();
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let service = LoginService::new(
        StoredAccountRegistry::new(registry.metadata_path().to_path_buf()),
        runtime.handle().clone(),
    );
    let ctx = AuthorityContext::new(registry).without_registry_fallback();
    let config = AuthorityServerConfig::new(ctx)
        .expect("config")
        .with_gemini_login(service, GeminiCliAdapter::default());
    for provider_id in ["cursor", "github-copilot"] {
        let body = serde_json::json!({
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": "login",
            "operation": "login.start",
            "providerId": provider_id,
            "accountId": "work",
            "label": "Work",
            "authKind": "oauth",
            "idempotencyKey": format!("key-{provider_id}")
        });
        let response = dispatch_json(&config.context, &body.to_string());
        assert_eq!(
            response["error"]["code"], "unsupported-operation",
            "{provider_id}"
        );
        assert_eq!(
            response["error"]["message"], "operation is not implemented",
            "{provider_id}"
        );
    }
}

#[test]
fn dispatch_accepts_codex_cli_login_start() {
    let (_dir, registry) = isolated_registry();
    let login = Arc::new(FakeLogin::new());
    let ctx = AuthorityContext::new(registry)
        .without_registry_fallback()
        .with_login(Arc::clone(&login) as Arc<dyn LoginPort>);
    let body = serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "requestId": "login",
        "operation": "login.start",
        "providerId": "codex-cli",
        "accountId": "work",
        "label": "Work",
        "authKind": "oauth",
        "idempotencyKey": "key-1"
    });
    let response = dispatch_json(&ctx, &body.to_string());
    assert!(response["error"].is_null());
    assert_eq!(response["result"]["handle"], "login-handle-1");
    assert_eq!(response["result"]["state"], "waiting-for-user");
    assert_eq!(login.starts.lock().expect("starts").len(), 1);
}

#[test]
fn dispatch_accepts_grok_cli_login_start() {
    let (_dir, registry) = isolated_registry();
    let login = Arc::new(FakeLogin::new());
    let ctx = AuthorityContext::new(registry)
        .without_registry_fallback()
        .with_login(Arc::clone(&login) as Arc<dyn LoginPort>);
    let body = serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "requestId": "login",
        "operation": "login.start",
        "providerId": "grok-cli",
        "accountId": "work",
        "label": "Work",
        "authKind": "oauth",
        "idempotencyKey": "key-1"
    });
    let response = dispatch_json(&ctx, &body.to_string());
    assert!(response["error"].is_null());
    assert_eq!(response["result"]["handle"], "login-handle-1");
    assert_eq!(response["result"]["state"], "waiting-for-user");
    assert_eq!(login.starts.lock().expect("starts").len(), 1);
}

#[test]
fn error_body_has_no_path_or_secret() {
    let response = map_core_error(
        "err",
        &Error::ConfigRead {
            provider: "gemini-cli".to_string(),
            reason: r"failed D:\secrets\stored-accounts.json with FAKE-token".to_string(),
        },
    );
    let json = serde_json::to_string(&response).expect("json");
    assert!(!json.contains("D:"));
    assert!(!json.contains('\\'));
    assert!(!json.contains('/'));
    assert!(!json.contains("stored-accounts"));
    assert!(!json.contains("FAKE-"));
    assert!(!json.contains("secrets"));
    assert_eq!(
        response.error.expect("error").code,
        ErrorCode::StateUnavailable
    );
}

#[test]
fn authority_id_is_stable_hex_and_not_a_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = stored_accounts_path(dir.path());
    let first = authority_id_for(&path);
    let second = authority_id_for(&path);
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
    assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(first, first.to_ascii_lowercase());
    assert!(!first.contains('/'));
    assert!(!first.contains('\\'));
    assert!(!first.contains("stored-accounts"));
    assert!(!first.contains(':'));
}

#[test]
fn describe_lists_closed_operations_and_unselected_revision() {
    let (_dir, registry) = isolated_registry();
    let ctx = AuthorityContext::new(registry).without_registry_fallback();
    let describe = dispatch_json(
        &ctx,
        r#"{"protocolVersion":1,"requestId":"d","operation":"authority.describe"}"#,
    );
    let operations = describe["result"]["operations"]
        .as_array()
        .expect("operations");
    let names: Vec<_> = operations
        .iter()
        .map(|value| value.as_str().expect("op"))
        .collect();
    assert_eq!(names, ADVERTISED_OPERATIONS);
    assert!(!names.iter().any(|name| name.starts_with("operation.")));
    assert!(!names.iter().any(|name| name.contains("reset")));

    let unselected = dispatch_json(
        &ctx,
        r#"{"protocolVersion":1,"requestId":"g","operation":"selection.get","providerId":"gemini-cli"}"#,
    );
    assert_eq!(unselected["result"]["selected"], false);
    assert_eq!(unselected["result"]["authorityId"], ctx.authority_id);
    assert!(unselected["result"]["selectionRevision"].is_number());
}

#[test]
fn selection_set_compares_incarnation_and_does_not_activate() {
    let (_dir, registry) = isolated_registry();
    let incarnation = seed_complete(&registry, "work");
    let activated = Arc::new(AtomicBool::new(false));
    let ctx = context_with_probe(registry, Arc::clone(&activated));

    let stale_incarnation = dispatch_json(
        &ctx,
        &serde_json::json!({
            "protocolVersion": 1,
            "requestId": "stale-inc",
            "operation": "selection.set",
            "providerId": "gemini-cli",
            "accountId": "work",
            "accountIncarnation": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "selectionRevision": 0
        })
        .to_string(),
    );
    assert_eq!(stale_incarnation["error"]["code"], "stale-account");
    assert!(!activated.load(Ordering::SeqCst));

    let stale_revision = dispatch_json(
        &ctx,
        &serde_json::json!({
            "protocolVersion": 1,
            "requestId": "stale-rev",
            "operation": "selection.set",
            "providerId": "gemini-cli",
            "accountId": "work",
            "accountIncarnation": incarnation.clone(),
            "selectionRevision": 99
        })
        .to_string(),
    );
    assert_eq!(stale_revision["error"]["code"], "stale-selection");
    assert!(!activated.load(Ordering::SeqCst));

    let selected = dispatch_json(
        &ctx,
        &serde_json::json!({
            "protocolVersion": 1,
            "requestId": "set",
            "operation": "selection.set",
            "providerId": "gemini-cli",
            "accountId": "work",
            "accountIncarnation": incarnation,
            "selectionRevision": 0
        })
        .to_string(),
    );
    assert_eq!(selected["result"]["selected"], true);
    assert_eq!(selected["result"]["accountId"], "work");
    assert!(!activated.load(Ordering::SeqCst));
}

#[test]
fn list_separates_records_from_local_observations() {
    let (_dir, registry) = isolated_registry();
    let incarnation = seed_complete(&registry, "work");
    let ctx = context_with_probe(registry, Arc::new(AtomicBool::new(false)));
    let listed = dispatch_json(
        &ctx,
        r#"{"protocolVersion":1,"requestId":"list","operation":"accounts.list","providerId":"gemini-cli"}"#,
    );
    let records = listed["result"]["records"].as_array().expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["id"], "work");
    assert_eq!(records[0]["accountIncarnation"], incarnation);
    let local = &listed["result"]["localObservations"];
    assert_eq!(local["outcome"], "observed");
    assert_eq!(local["accounts"][0]["id"], "on-disk-local");
    assert_eq!(local["accounts"][0]["isStored"], false);
    assert_ne!(records[0]["id"], local["accounts"][0]["id"]);
}

#[test]
fn observe_refuses_cross_authority_before_lease_and_keeps_unknown_quota() {
    let (_dir, registry) = isolated_registry();
    let incarnation = seed_complete(&registry, "work");
    let binding = registry
        .select_complete_revision("gemini-cli", "work", None)
        .expect("select");
    assert_eq!(binding.account_incarnation, incarnation);
    let ctx = context_with_probe(registry, Arc::new(AtomicBool::new(false)));

    let cross = dispatch_json(
        &ctx,
        &serde_json::json!({
            "protocolVersion": 1,
            "requestId": "cross",
            "operation": "account.observe",
            "authorityId": "0".repeat(64),
            "binding": binding.clone(),
            "categories": ["quota"]
        })
        .to_string(),
    );
    assert_eq!(cross["error"]["code"], "access-denied");
    let lock_dir = ctx
        .registry
        .metadata_path()
        .parent()
        .expect("parent")
        .join("stored-account-use-locks");
    assert!(
        !lock_dir.exists()
            || std::fs::read_dir(&lock_dir)
                .expect("locks")
                .next()
                .is_none()
    );

    let observed = dispatch_json(
        &ctx,
        &serde_json::json!({
            "protocolVersion": 1,
            "requestId": "obs",
            "operation": "account.observe",
            "authorityId": ctx.authority_id,
            "binding": {
                "providerId": "gemini-cli",
                "accountId": "work",
                "accountIncarnation": incarnation,
                "selectionRevision": binding.selection_revision
            },
            "categories": ["quota"]
        })
        .to_string(),
    );
    let json = observed.to_string();
    assert!(observed["error"].is_null());
    assert_eq!(observed["result"]["quota"]["outcome"]["kind"], "unknown");
    assert!(!json.contains("utilization"));
}

#[test]
fn login_delegates_to_login_service_idempotent_replay() {
    let (_dir, registry) = isolated_registry();
    let login = Arc::new(FakeLogin::new());
    let ctx = AuthorityContext::new(registry)
        .without_registry_fallback()
        .with_login(Arc::clone(&login) as Arc<dyn LoginPort>);
    let body = serde_json::json!({
        "protocolVersion": 1,
        "requestId": "start",
        "operation": "login.start",
        "providerId": "gemini-cli",
        "accountId": "work",
        "label": "Work",
        "authKind": "oauth",
        "idempotencyKey": "same-key"
    });
    let first = dispatch_json(&ctx, &body.to_string());
    let second = dispatch_json(&ctx, &body.to_string());
    assert_eq!(first["result"]["handle"], "login-handle-1");
    assert_eq!(first["result"]["handle"], second["result"]["handle"]);
    assert_eq!(first["result"]["state"], "waiting-for-user");
    assert_eq!(login.starts.lock().expect("starts").len(), 2);
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Instant;

    use std::time::Duration;

    use coding_agent_manager_lib::account_authority::{
        listen, resolve_socket_path, AuthorityServerConfig, ListenError, PeerPolicy,
        MAX_REQUEST_BYTES, REQUEST_IO_DEADLINE,
    };

    fn private_tempdir() -> (tempfile::TempDir, std::path::PathBuf) {
        use std::fs;

        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
        let canonical = fs::canonicalize(dir.path()).expect("canonical");
        (dir, canonical)
    }

    fn serve_once(listener: coding_agent_manager_lib::account_authority::AuthorityListener) {
        serve_n(listener, 1);
    }

    fn serve_n(
        listener: coding_agent_manager_lib::account_authority::AuthorityListener,
        count: usize,
    ) {
        thread::spawn(move || {
            for _ in 0..count {
                let _ = listener.accept_once();
            }
        });
    }

    fn write_frame(stream: &mut UnixStream, body: &[u8]) {
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .expect("len");
        stream.write_all(body).expect("body");
    }

    fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).expect("len");
        let n = u32::from_be_bytes(len) as usize;
        let mut body = vec![0u8; n];
        stream.read_exact(&mut body).expect("body");
        body
    }

    fn exchange(path: &std::path::Path, json: &str) -> serde_json::Value {
        let mut stream = UnixStream::connect(path).expect("connect");
        write_frame(&mut stream, json.as_bytes());
        let body = read_frame(&mut stream);
        serde_json::from_slice(&body).expect("json")
    }

    fn listen_fixture(
        ctx: AuthorityContext,
    ) -> (
        tempfile::TempDir,
        coding_agent_manager_lib::account_authority::AuthorityListener,
    ) {
        let (dir, root) = private_tempdir();
        let socket = root.join("account.sock");
        let path = resolve_socket_path(&socket).expect("safe");
        let listener =
            listen(path, AuthorityServerConfig::new(ctx).expect("config")).expect("listen");
        (dir, listener)
    }

    #[test]
    fn unselected_revision_is_present_for_cas() {
        let (_dir, registry) = isolated_registry();
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        let authority_id = ctx.authority_id.clone();
        let (_guard, listener) = listen_fixture(ctx);
        let path = listener.path().to_path_buf();
        serve_once(listener);
        let response = exchange(
            &path,
            r#"{"protocolVersion":1,"requestId":"g","operation":"selection.get","providerId":"gemini-cli"}"#,
        );
        assert_eq!(response["result"]["selected"], false);
        assert_eq!(response["result"]["authorityId"], authority_id);
        assert!(response["result"]["selectionRevision"].is_number());
    }

    #[test]
    fn describe_lists_the_eight_ops() {
        let (_dir, registry) = isolated_registry();
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        let (_guard, listener) = listen_fixture(ctx);
        let path = listener.path().to_path_buf();
        serve_once(listener);
        let response = exchange(
            &path,
            r#"{"protocolVersion":1,"requestId":"d","operation":"authority.describe"}"#,
        );
        let operations = response["result"]["operations"].as_array().expect("ops");
        assert_eq!(operations.len(), 8);
        let names: Vec<_> = operations
            .iter()
            .map(|value| value.as_str().expect("op"))
            .collect();
        assert_eq!(names, ADVERTISED_OPERATIONS);
    }

    #[test]
    fn peer_mismatch_returns_zero_bytes() {
        let (_dir, registry) = isolated_registry();
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        let (guard, root) = private_tempdir();
        let socket = root.join("account.sock");
        let path = resolve_socket_path(&socket).expect("safe");
        let config = AuthorityServerConfig::new(ctx)
            .expect("config")
            .with_peer_policy(PeerPolicy::DenyAll);
        let listener = listen(path, config).expect("listen");
        let socket_path = listener.path().to_path_buf();
        serve_once(listener);
        let mut stream = UnixStream::connect(&socket_path).expect("connect");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("eof");
        assert!(buf.is_empty());
        drop(guard);
    }

    #[test]
    fn oversized_prefix_is_refused() {
        let (_dir, registry) = isolated_registry();
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        let (_guard, listener) = listen_fixture(ctx);
        let path = listener.path().to_path_buf();
        serve_once(listener);
        let mut stream = UnixStream::connect(&path).expect("connect");
        let oversize = (MAX_REQUEST_BYTES as u32).saturating_add(1).to_be_bytes();
        stream.write_all(&oversize).expect("prefix");
        let body = read_frame(&mut stream);
        let response: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(response["error"]["code"], "invalid-request");
    }

    #[test]
    fn idle_deadline_closes_without_hanging() {
        let (_dir, registry) = isolated_registry();
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        let (guard, root) = private_tempdir();
        let socket = root.join("account.sock");
        let path = resolve_socket_path(&socket).expect("safe");
        let config = AuthorityServerConfig::new(ctx)
            .expect("config")
            .tighten_request_io_deadline(Duration::from_millis(200))
            .expect("tighten");
        let listener = listen(path, config).expect("listen");
        let socket_path = listener.path().to_path_buf();
        let started = Instant::now();
        let joined = thread::spawn(move || listener.accept_once());
        let mut stream = UnixStream::connect(&socket_path).expect("connect");
        joined.join().expect("accept").expect("once");
        assert!(started.elapsed() < REQUEST_IO_DEADLINE);
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        drop(guard);
    }

    #[test]
    fn socket_mode_is_0600() {
        use std::fs;
        let (_dir, registry) = isolated_registry();
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        let (_guard, listener) = listen_fixture(ctx);
        let metadata = fs::symlink_metadata(listener.path()).expect("lstat");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn stale_non_socket_leaf_is_not_unlinked() {
        use std::fs;
        let (guard, root) = private_tempdir();
        let socket = root.join("account.sock");
        fs::write(&socket, b"not-a-socket").expect("file");
        let path = resolve_socket_path(&socket).expect("safe");
        let (_dir, registry) = isolated_registry();
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        match listen(path, AuthorityServerConfig::new(ctx).expect("config")) {
            Err(ListenError::NotASocket) => {}
            Err(error) => panic!("unexpected listen error: {error:?}"),
            Ok(_) => panic!("expected NotASocket"),
        }
        assert_eq!(fs::read(&socket).expect("kept"), b"not-a-socket");
        drop(guard);
    }

    #[test]
    fn login_delegates_over_socket_with_idempotent_replay() {
        let (_dir, registry) = isolated_registry();
        let login = Arc::new(FakeLogin::new());
        let ctx = AuthorityContext::new(registry)
            .without_registry_fallback()
            .with_login(Arc::clone(&login) as Arc<dyn LoginPort>);
        let (_guard, listener) = listen_fixture(ctx);
        let path = listener.path().to_path_buf();
        serve_n(listener, 2);
        let body = serde_json::json!({
            "protocolVersion": 1,
            "requestId": "start",
            "operation": "login.start",
            "providerId": "gemini-cli",
            "accountId": "work",
            "label": "Work",
            "authKind": "oauth",
            "idempotencyKey": "same-key"
        })
        .to_string();
        let first = exchange(&path, &body);
        let second = exchange(&path, &body);
        assert_eq!(first["result"]["handle"], "login-handle-1");
        assert_eq!(second["result"]["handle"], "login-handle-1");
        assert_eq!(login.starts.lock().expect("starts").len(), 2);
    }
}
