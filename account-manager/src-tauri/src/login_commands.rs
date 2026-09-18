//! Thin Tauri IPC for the core [`LoginService`] lifecycle (Gemini OAuth only).

use std::ops::Deref;
use std::sync::Arc;

use tauri::State;

use crate::error::{Error, Result};
use crate::login::{
    LoginAccountBinding, LoginHandle, LoginService, LoginStartRequest, LoginStatus,
};
use crate::model::AuthKind;
use crate::providers::gemini_cli::GeminiCliAdapter;

/// Provider id allowed through the explicit login IPC surface.
pub const LOGIN_PROVIDER_ID: &str = "gemini-cli";

/// One app-owned login service for the desktop process lifetime.
#[derive(Clone)]
pub struct ManagedLoginService {
    inner: Arc<LoginService>,
}

impl ManagedLoginService {
    pub fn new(service: LoginService) -> Self {
        Self {
            inner: Arc::new(service),
        }
    }
}

impl Deref for ManagedLoginService {
    type Target = LoginService;

    fn deref(&self) -> &LoginService {
        &*self.inner
    }
}

pub(crate) fn build_managed_login_service(
    registry: crate::providers::StoredAccountRegistry,
) -> ManagedLoginService {
    let runtime = tauri::async_runtime::handle().inner().clone();
    ManagedLoginService::new(LoginService::new(registry, runtime))
}

/// Refuse unsupported login attempts before registry or vendor-home work.
pub(crate) fn validate_ipc_login_start(provider_id: &str, auth_kind: AuthKind) -> Result<()> {
    if provider_id != LOGIN_PROVIDER_ID {
        return Err(Error::NotImplemented("login.start"));
    }
    if auth_kind != AuthKind::OAuth {
        return Err(Error::ConfigWrite {
            provider: provider_id.to_string(),
            reason: "only Gemini OAuth login is supported in this release".to_string(),
        });
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
pub async fn login_start(
    state: State<'_, ManagedLoginService>,
    provider_id: String,
    account_id: String,
    label: String,
    auth_kind: AuthKind,
    idempotency_key: String,
) -> Result<LoginStatus> {
    validate_ipc_login_start(&provider_id, auth_kind)?;
    let request = login_start_request(provider_id, account_id, label, auth_kind, idempotency_key);
    let service = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let adapter = GeminiCliAdapter::default();
        service.start(request, &adapter)
    })
    .await
    .expect("login_start worker")
}

#[tauri::command]
pub fn login_status(
    state: State<'_, ManagedLoginService>,
    handle: LoginHandle,
    binding: LoginAccountBinding,
) -> Result<LoginStatus> {
    state.inner().status(&handle, &binding)
}

#[tauri::command]
pub fn login_cancel(
    state: State<'_, ManagedLoginService>,
    handle: LoginHandle,
    binding: LoginAccountBinding,
) -> Result<LoginStatus> {
    state.inner().cancel(&handle, &binding)
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

    fn login_service_for_test(registry: &StoredAccountRegistry) -> LoginService {
        let runtime = tauri::async_runtime::handle().inner().clone();
        LoginService::new(
            StoredAccountRegistry::new(registry.metadata_path().to_path_buf()),
            runtime,
        )
    }

    #[test]
    fn ipc_refuses_non_gemini_provider_before_core() {
        let error = validate_ipc_login_start("codex-cli", AuthKind::OAuth).expect_err("refuse");
        assert!(matches!(&error, Error::NotImplemented(_)));
    }

    #[test]
    fn ipc_refuses_gemini_api_key_login() {
        let error =
            validate_ipc_login_start(LOGIN_PROVIDER_ID, AuthKind::ApiKey).expect_err("refuse");
        match &error {
            Error::ConfigWrite { provider, reason } => {
                assert_eq!(provider, LOGIN_PROVIDER_ID);
                assert!(reason.contains("only Gemini OAuth"));
            }
            other => panic!("unexpected error: {other:?}"),
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
    }

    #[test]
    fn managed_service_reuses_one_login_service_instance() {
        tauri::async_runtime::block_on(async {
            let dir = tempfile::tempdir().expect("tempdir");
            let registry = StoredAccountRegistry::new(paths::stored_accounts_path(dir.path()));
            let managed = ManagedLoginService::new(login_service_for_test(&registry));
            let first = (&*managed) as *const LoginService;
            let clone = managed.clone();
            let second = (&*clone) as *const LoginService;
            assert_eq!(first, second);
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
            let managed = ManagedLoginService::new(login_service_for_test(&registry));
            let started = managed
                .start(
                    LoginStartRequest {
                        provider_id: LOGIN_PROVIDER_ID.to_string(),
                        account_id: "work".to_string(),
                        label: "work".to_string(),
                        auth_kind: AuthKind::OAuth,
                        idempotency_key: "ipc-binding-test".to_string(),
                    },
                    &adapter,
                )
                .expect("start");
            let wrong_binding = LoginAccountBinding {
                provider_id: LOGIN_PROVIDER_ID.to_string(),
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
}
