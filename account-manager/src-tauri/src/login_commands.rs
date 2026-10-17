//! Thin Tauri IPC over the core's provider-neutral [`LoginPort`] lifecycle.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::State;
use tauri_plugin_opener::OpenerExt;

use crate::account_authority::{GeminiLoginPort, LoginPort};
use crate::error::{Error, Result};
use crate::login::{
    LoginAccountBinding, LoginAuthorization, LoginBrowserMode, LoginHandle, LoginService,
    LoginStartRequest, LoginState, LoginStatus,
};
use crate::model::{AuthKind, ProviderCapability};
use crate::providers::claude_code::ClaudeCodeAdapter;
use crate::providers::gemini_cli::GeminiCliAdapter;

use super::authority_client::AccountAuthority;
use super::authority_client::AuthorityClient;

/// Private GUI response; the core status and public owner action stay bound together.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginIpcStatus {
    #[serde(flatten)]
    pub status: LoginStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<LoginAuthorization>,
}

impl std::ops::Deref for LoginIpcStatus {
    type Target = LoginStatus;
    fn deref(&self) -> &Self::Target {
        &self.status
    }
}

impl std::fmt::Debug for LoginIpcStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LoginIpcStatus")
            .field("status", &self.status)
            .field("authorization_available", &self.authorization.is_some())
            .finish()
    }
}

fn in_process_status(service: &dyn LoginPort, status: LoginStatus) -> Result<LoginIpcStatus> {
    let authorization = service.authorization(&status.handle, &status.binding)?;
    Ok(LoginIpcStatus {
        status,
        authorization,
    })
}

#[derive(Clone)]
enum LoginBackend {
    InProcess(Arc<dyn LoginPort>),
    Remote(AuthorityClient),
}

/// One app-owned login service for the desktop process lifetime.
#[derive(Clone)]
pub struct ManagedLoginService {
    backend: LoginBackend,
}

impl ManagedLoginService {
    fn new(backend: LoginBackend) -> Self {
        Self { backend }
    }

    fn start(&self, request: LoginStartRequest) -> Result<LoginIpcStatus> {
        match &self.backend {
            LoginBackend::InProcess(service) => {
                let mode = if matches!(
                    request.provider_id.as_str(),
                    "gemini-cli" | "codex-cli" | "grok-cli" | "cursor"
                ) {
                    LoginBrowserMode::CallerManaged
                } else {
                    LoginBrowserMode::Automatic
                };
                let status = service.start_with_browser_mode(request, mode)?;
                in_process_status(service.as_ref(), status)
            }
            LoginBackend::Remote(client) => client.login_start(request),
        }
    }

    fn status(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<LoginIpcStatus> {
        match &self.backend {
            LoginBackend::InProcess(service) => {
                in_process_status(service.as_ref(), service.status(handle, binding)?)
            }
            LoginBackend::Remote(client) => client.login_status(handle, binding),
        }
    }

    fn cancel(
        &self,
        handle: &LoginHandle,
        binding: &LoginAccountBinding,
    ) -> Result<LoginIpcStatus> {
        match &self.backend {
            LoginBackend::InProcess(service) => {
                in_process_status(service.as_ref(), service.cancel(handle, binding)?)
            }
            LoginBackend::Remote(client) => client.login_cancel(handle, binding),
        }
    }
}

pub(crate) fn build_managed_login_service(authority: AccountAuthority) -> ManagedLoginService {
    let runtime = tauri::async_runtime::handle().inner().clone();
    let backend = match authority {
        AccountAuthority::InProcess(registry) => {
            LoginBackend::InProcess(Arc::new(GeminiLoginPort::new(
                LoginService::new(registry, runtime),
                GeminiCliAdapter::default(),
                ClaudeCodeAdapter::default(),
            )))
        }
        AccountAuthority::Remote(client) => LoginBackend::Remote(client),
    };
    ManagedLoginService::new(backend)
}

/// Refuse unsupported login attempts before registry or vendor-home work.
pub(crate) fn validate_ipc_login_start(provider_id: &str, auth_kind: AuthKind) -> Result<()> {
    let descriptor = super::adapter_for(provider_id)?.descriptor();
    if auth_kind != AuthKind::OAuth {
        return Err(Error::ConfigWrite {
            provider: provider_id.to_string(),
            reason: "login.start supports OAuth only; use the adapter's separate import flow for other authentication kinds".to_string(),
        });
    }
    if !descriptor.auth_kinds.contains(&auth_kind)
        || !descriptor
            .capabilities
            .contains(&ProviderCapability::AddAccount)
    {
        return Err(Error::NotImplemented("login.start"));
    }
    Ok(())
}

fn login_start_request(
    provider_id: String,
    account_id: String,
    label: String,
    auth_kind: AuthKind,
    idempotency_key: String,
) -> LoginStartRequest {
    LoginStartRequest {
        provider_id,
        account_id,
        label,
        auth_kind,
        idempotency_key,
    }
}

#[tauri::command]
pub(crate) async fn login_start(
    state: State<'_, ManagedLoginService>,
    provider_id: String,
    account_id: String,
    label: String,
    auth_kind: AuthKind,
    idempotency_key: String,
) -> Result<LoginIpcStatus> {
    validate_ipc_login_start(&provider_id, auth_kind)?;
    let request = login_start_request(provider_id, account_id, label, auth_kind, idempotency_key);
    let service = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || service.start(request))
        .await
        .expect("login_start worker")
}

#[tauri::command]
pub(crate) fn login_status(
    state: State<'_, ManagedLoginService>,
    handle: LoginHandle,
    binding: LoginAccountBinding,
) -> Result<LoginIpcStatus> {
    state.status(&handle, &binding)
}

#[tauri::command]
pub(crate) fn login_cancel(
    state: State<'_, ManagedLoginService>,
    handle: LoginHandle,
    binding: LoginAccountBinding,
) -> Result<LoginIpcStatus> {
    state.cancel(&handle, &binding)
}

/// The owner clicks an action for a live login, never supplies an arbitrary URL.
#[tauri::command]
pub(crate) fn login_open_authorization(
    app: tauri::AppHandle,
    state: State<'_, ManagedLoginService>,
    handle: LoginHandle,
    binding: LoginAccountBinding,
) -> Result<()> {
    let view = state.status(&handle, &binding)?;
    let url = current_authorization_url(&view, &handle, &binding)?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| Error::ConfigRead {
            provider: binding.provider_id,
            reason: "the owner browser could not be opened".to_string(),
        })
}

fn current_authorization_url(
    view: &LoginIpcStatus,
    handle: &LoginHandle,
    binding: &LoginAccountBinding,
) -> Result<String> {
    let refused = || Error::ConfigRead {
        provider: binding.provider_id.clone(),
        reason: "live provider authorization instructions are unavailable".to_string(),
    };
    if &view.status.handle != handle
        || &view.status.binding != binding
        || !matches!(
            view.state,
            LoginState::WaitingForUser | LoginState::InProgress
        )
    {
        return Err(refused());
    }
    let authorization = view.authorization.as_ref().ok_or_else(refused)?;
    if let Some(expires_at) = authorization.expires_at_unix_ms {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| refused())?;
        if now.as_millis() >= u128::from(expires_at) {
            return Err(refused());
        }
    }
    crate::login::vendor_authorization_url(&binding.provider_id, &authorization.authorization_url)
        .ok_or_else(refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::login::{LoginState, LoginStatus};
    use crate::paths;
    use crate::providers::StoredAccountRegistry;

    fn login_handle_from_json(value: &str) -> LoginHandle {
        serde_json::from_value(serde_json::Value::String(value.to_string()))
            .expect("login handle serde")
    }

    #[test]
    fn owner_action_requires_live_exact_binding_and_official_unexpired_uri() {
        let handle = login_handle_from_json("opaque-owner-handle");
        let binding = LoginAccountBinding {
            provider_id: "codex-cli".to_string(),
            account_id: "work".to_string(),
            account_incarnation: "incarnation-1".to_string(),
        };
        let url = format!(
            "https://auth.openai.com/oauth/authorize?response_type=code&client_id=FAKE-client&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback&state=FAKE-state&code_challenge_method=S256&code_challenge={}",
            "A".repeat(43),
        );
        let valid = LoginIpcStatus {
            status: LoginStatus {
                handle: handle.clone(),
                binding: binding.clone(),
                state: LoginState::WaitingForUser,
                failure_reason: None,
            },
            authorization: Some(LoginAuthorization {
                authorization_url: url.to_string(),
                expires_at_unix_ms: None,
            }),
        };
        assert!(current_authorization_url(&valid, &handle, &binding).is_ok());
        assert!(
            current_authorization_url(&valid, &login_handle_from_json("stale"), &binding).is_err()
        );
        for changed in [
            LoginAccountBinding {
                provider_id: "grok-cli".into(),
                ..binding.clone()
            },
            LoginAccountBinding {
                account_id: "other".into(),
                ..binding.clone()
            },
            LoginAccountBinding {
                account_incarnation: "old".into(),
                ..binding.clone()
            },
        ] {
            assert!(current_authorization_url(&valid, &handle, &changed).is_err());
        }
        for state in [
            LoginState::Ready,
            LoginState::Cancelled,
            LoginState::Failed,
            LoginState::Unknown,
        ] {
            let mut view = valid.clone();
            view.status.state = state;
            assert!(current_authorization_url(&view, &handle, &binding).is_err());
        }
        for authorization in [
            None,
            Some(LoginAuthorization {
                authorization_url: url.to_string(),
                expires_at_unix_ms: Some(0),
            }),
            Some(LoginAuthorization {
                authorization_url: "https://example.invalid/authorize".into(),
                expires_at_unix_ms: None,
            }),
        ] {
            let mut view = valid.clone();
            view.authorization = authorization;
            let error = current_authorization_url(&view, &handle, &binding).unwrap_err();
            assert!(!format!("{error:?}").contains("https://"));
        }
    }

    #[test]
    fn ipc_accepts_oauth_for_existing_login_adapters_without_starting_login() {
        for provider in [
            "gemini-cli",
            "codex-cli",
            "grok-cli",
            "claude-code",
            "cursor",
        ] {
            validate_ipc_login_start(provider, AuthKind::OAuth)
                .expect("supported OAuth descriptor");
        }
        let error = validate_ipc_login_start("unknown-provider", AuthKind::OAuth)
            .expect_err("unknown provider");
        assert!(matches!(&error, Error::UnknownProvider(_)));
    }

    #[test]
    fn ipc_refuses_non_oauth_login_without_starting_vendor_or_registry_work() {
        for provider_id in ["gemini-cli", "codex-cli", "grok-cli"] {
            let error =
                validate_ipc_login_start(provider_id, AuthKind::ApiKey).expect_err("refuse");
            match &error {
                Error::ConfigWrite { provider, reason } => {
                    assert_eq!(provider, provider_id);
                    assert!(reason.contains("OAuth only"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn login_status_serializes_camel_case_and_kebab_states() {
        let status = LoginStatus {
            handle: login_handle_from_json("opaque-handle"),
            binding: LoginAccountBinding {
                provider_id: "gemini-cli".to_string(),
                account_id: "work".to_string(),
                account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
            },
            state: LoginState::WaitingForUser,
            failure_reason: None,
        };
        let json: serde_json::Value = serde_json::to_value(&status).expect("serialize");
        assert_eq!(json["handle"], "opaque-handle");
        assert_eq!(json["binding"]["providerId"], "gemini-cli");
        assert_eq!(json["binding"]["accountId"], "work");
        assert_eq!(
            json["binding"]["accountIncarnation"],
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(json["state"], "waiting-for-user");
        assert!(json.get("failureReason").is_none());

        let failed = LoginStatus {
            state: LoginState::Failed,
            failure_reason: Some("login provisioning failed: injected".to_string()),
            ..status
        };
        let failed_json: serde_json::Value = serde_json::to_value(&failed).expect("serialize");
        assert_eq!(failed_json["state"], "failed");
        assert_eq!(
            failed_json["failureReason"],
            "login provisioning failed: injected"
        );
        let view = LoginIpcStatus {
            status: failed,
            authorization: Some(LoginAuthorization {
                authorization_url:
                    "https://auth.openai.com/oauth/authorize?state=FAKE-public-fixture".to_string(),
                expires_at_unix_ms: Some(123),
            }),
        };
        let json = serde_json::to_value(&view).expect("private GUI view");
        assert_eq!(json["handle"], "opaque-handle");
        assert_eq!(json["authorization"]["expiresAtUnixMs"], 123);
        let decoded: LoginIpcStatus = serde_json::from_value(json).expect("transport DTO");
        assert_eq!(decoded.status.handle, view.status.handle);
        assert!(!format!("{view:?}").contains("auth.openai.com"));
        assert!(!format!("{view:?}").contains("FAKE-public-fixture"));
    }

    #[test]
    fn managed_service_reuses_one_login_service_instance() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let managed = build_managed_login_service(AccountAuthority::InProcess(
                StoredAccountRegistry::new(paths::stored_accounts_path(dir.path())),
            ));
            let clone = managed.clone();
            drop(clone);
            drop(managed);
        });
    }

    #[test]
    fn ipc_status_rejects_mismatched_binding_for_known_handle() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let home = dir.path().join("home");
            let data = dir.path().join("data");
            let cwd = dir.path().join("workspace");
            std::fs::create_dir_all(home.join(".gemini")).expect("home");
            std::fs::create_dir_all(cwd.join(".gemini")).expect("workspace");
            std::fs::write(
                home.join(".gemini/settings.json"),
                r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
            )
            .expect("settings");
            let adapter = GeminiCliAdapter::with_test_context(
                home,
                data.clone(),
                cwd,
                dir.path().join("system/settings.json"),
                dir.path().join("system/system-defaults.json"),
                None,
            )
            .with_test_oauth_watch_cancel_driver();
            let registry = StoredAccountRegistry::new(paths::stored_accounts_path(&data));
            let managed =
                ManagedLoginService::new(LoginBackend::InProcess(Arc::new(GeminiLoginPort::new(
                    LoginService::new(registry, tauri::async_runtime::handle().inner().clone()),
                    adapter,
                    ClaudeCodeAdapter::default(),
                ))));
            let started = managed
                .start(LoginStartRequest {
                    provider_id: "gemini-cli".to_string(),
                    account_id: "work".to_string(),
                    label: "work".to_string(),
                    auth_kind: AuthKind::OAuth,
                    idempotency_key: "ipc-binding-test".to_string(),
                })
                .expect("start");
            let wrong_binding = LoginAccountBinding {
                provider_id: "gemini-cli".to_string(),
                account_id: "other-account".to_string(),
                account_incarnation: started.binding.account_incarnation.clone(),
            };
            let error = managed
                .status(&started.handle, &wrong_binding)
                .expect_err("binding mismatch");
            match &error {
                Error::ConfigWrite { reason, .. } => {
                    assert!(reason.contains("does not match"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
            let _ = managed.cancel(&started.handle, &started.binding);
        });
    }

    #[test]
    fn cursor_gui_start_requests_caller_managed_and_exposes_only_bound_owner_action() {
        struct InertLogin {
            seen: std::sync::Mutex<Option<(LoginStartRequest, LoginBrowserMode)>>,
            status: LoginStatus,
            authorization: LoginAuthorization,
        }
        impl LoginPort for InertLogin {
            fn start(&self, _request: LoginStartRequest) -> Result<LoginStatus> {
                panic!("GUI must use the mode-aware port");
            }
            fn start_with_browser_mode(
                &self,
                request: LoginStartRequest,
                mode: LoginBrowserMode,
            ) -> Result<LoginStatus> {
                *self.seen.lock().expect("seen") = Some((request, mode));
                Ok(self.status.clone())
            }
            fn authorization(
                &self,
                handle: &LoginHandle,
                binding: &LoginAccountBinding,
            ) -> Result<Option<LoginAuthorization>> {
                assert_eq!(handle, &self.status.handle);
                assert_eq!(binding, &self.status.binding);
                Ok(Some(self.authorization.clone()))
            }
            fn status(
                &self,
                _handle: &LoginHandle,
                _binding: &LoginAccountBinding,
            ) -> Result<LoginStatus> {
                panic!("unused inert fixture port");
            }
            fn cancel(
                &self,
                _handle: &LoginHandle,
                _binding: &LoginAccountBinding,
            ) -> Result<LoginStatus> {
                panic!("unused inert fixture port");
            }
        }
        let status = LoginStatus {
            handle: login_handle_from_json("cursor-owner-handle"),
            binding: LoginAccountBinding {
                provider_id: "cursor".into(),
                account_id: "work".into(),
                account_incarnation: "a".repeat(32),
            },
            state: LoginState::WaitingForUser,
            failure_reason: None,
        };
        let url = format!("https://cursor.com/loginDeepControl?challenge={}&uuid=01234567-89ab-4cde-8fab-0123456789ab&mode=login&redirectTarget=cli", "A".repeat(43));
        let port = Arc::new(InertLogin {
            seen: std::sync::Mutex::new(None),
            status: status.clone(),
            authorization: LoginAuthorization {
                authorization_url: url.clone(),
                expires_at_unix_ms: None,
            },
        });
        let managed = ManagedLoginService::new(LoginBackend::InProcess(port.clone()));
        let request = LoginStartRequest {
            provider_id: "cursor".into(),
            account_id: "work".into(),
            label: "Work".into(),
            auth_kind: AuthKind::OAuth,
            idempotency_key: "cursor-owner-action".into(),
        };
        let view = managed
            .start(request.clone())
            .expect("inert mode-aware start");
        assert_eq!(
            *port.seen.lock().expect("seen"),
            Some((request, LoginBrowserMode::CallerManaged))
        );
        assert_eq!(
            current_authorization_url(&view, &status.handle, &status.binding)
                .expect("validated owner action"),
            url
        );
        let mut stale = status.binding.clone();
        stale.account_incarnation = "b".repeat(32);
        assert!(current_authorization_url(&view, &status.handle, &stale).is_err());
        assert!(current_authorization_url(
            &view,
            &login_handle_from_json("stale"),
            &status.binding
        )
        .is_err());
        let mut expired = view.clone();
        expired
            .authorization
            .as_mut()
            .expect("authorization")
            .expires_at_unix_ms = Some(0);
        assert!(current_authorization_url(&expired, &status.handle, &status.binding).is_err());
        let mut cancelled = view;
        cancelled.status.state = LoginState::Cancelled;
        assert!(current_authorization_url(&cancelled, &status.handle, &status.binding).is_err());
    }
}
