//! Thin Tauri IPC for core [`observe_selected_account`] (exact binding only).

use crate::account_authority::{AccountObserveRequest, AccountObserveResult};
use crate::error::Result;
use crate::model::StoredAccountMaterial;
use crate::providers::observe_selected_account;
use crate::storage;

use super::{adapter_for, stored_account_registry};

/// Observe only the account named by `request.binding`; never auto-selects or rotates.
#[tauri::command]
pub fn observe_account(request: AccountObserveRequest) -> Result<AccountObserveResult> {
    observe_account_blocking(request)
}

pub(crate) fn observe_account_blocking(
    request: AccountObserveRequest,
) -> Result<AccountObserveResult> {
    let adapter = adapter_for(&request.binding.provider_id)?;
    let registry = stored_account_registry()?;
    let store = registry
        .account(&request.binding.provider_id, &request.binding.account_id)
        .ok()
        .filter(|account| account.material == StoredAccountMaterial::CredentialStore)
        .map(|_| storage::default_store())
        .transpose()?;
    observe_selected_account(
        &registry,
        adapter.as_ref(),
        request,
        store.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::account_authority::{
        AccountObserveRequest, ObservationOutcome, ObserveCategory, SelectedAccountBinding,
        StoredAccountRegistry,
    };
    use crate::error::Error;
    use crate::model::{AuthKind, StoredAccountMaterial};
    use crate::paths::stored_accounts_path;
    use crate::providers::gemini_cli::GeminiCliAdapter;
    use crate::storage::{CredentialStore, Secret, SecretRef};

    use super::*;

    const TEST_KEY: &str = "FAKE-gemini-key-0001";

    struct MemoryStore {
        bytes: Option<Vec<u8>>,
    }

    impl CredentialStore for MemoryStore {
        fn id(&self) -> &'static str {
            "memory"
        }

        fn is_available(&self) -> bool {
            true
        }

        fn put(
            &self,
            _key: &SecretRef,
            _secret: &Secret,
        ) -> crate::error::Result<()> {
            Ok(())
        }

        fn get(&self, _key: &SecretRef) -> crate::error::Result<Option<Secret>> {
            Ok(self
                .bytes
                .as_ref()
                .map(|bytes| Secret::new(bytes.clone())))
        }

        fn delete(&self, _key: &SecretRef) -> crate::error::Result<()> {
            Ok(())
        }
    }

    fn gemini_fixture() -> (tempfile::TempDir, GeminiCliAdapter, StoredAccountRegistry) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let data = dir.path().join("data");
        let cwd = dir.path().join("workspace");
        fs::create_dir_all(home.join(".gemini")).expect("home gemini dir");
        fs::create_dir_all(cwd.join(".gemini")).expect("workspace gemini dir");
        fs::write(
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
            Some(TEST_KEY),
        );
        let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
        (dir, adapter, registry)
    }

    fn stage_gemini_account(registry: &StoredAccountRegistry) -> SelectedAccountBinding {
        registry
            .begin_add(
                "gemini-cli",
                "work",
                "Work",
                AuthKind::ApiKey,
                StoredAccountMaterial::CredentialStore,
            )
            .expect("begin add");
        registry
            .complete_add("gemini-cli", "work")
            .expect("complete add");
        registry
            .select_complete_revision("gemini-cli", "work", None)
            .expect("select")
    }

    #[test]
    fn ipc_observe_request_serializes_camel_case() {
        let request = AccountObserveRequest {
            binding: SelectedAccountBinding {
                provider_id: "gemini-cli".to_string(),
                account_id: "work".to_string(),
                account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
                selection_revision: 1,
            },
            categories: vec![ObserveCategory::Quota],
        };
        let json: serde_json::Value = serde_json::to_value(&request).expect("serialize");
        assert_eq!(json["binding"]["providerId"], "gemini-cli");
        assert_eq!(json["binding"]["selectionRevision"], 1);
        assert_eq!(json["categories"][0], "quota");
    }

    #[test]
    fn ipc_refuses_unknown_provider_before_core() {
        let error = observe_account_blocking(AccountObserveRequest {
            binding: SelectedAccountBinding {
                provider_id: "not-a-provider".to_string(),
                account_id: "work".to_string(),
                account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
                selection_revision: 1,
            },
            categories: vec![ObserveCategory::Auth],
        })
        .expect_err("unknown provider");
        assert!(matches!(
            error,
            Error::UnknownProvider(ref id) if id == "not-a-provider"
        ));
    }

    #[test]
    fn ipc_refuses_empty_categories_fail_closed() {
        let error = observe_account_blocking(AccountObserveRequest {
            binding: SelectedAccountBinding {
                provider_id: "gemini-cli".to_string(),
                account_id: "work".to_string(),
                account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
                selection_revision: 1,
            },
            categories: vec![],
        })
        .expect_err("empty categories");
        assert!(matches!(&error, Error::ConfigRead { reason, .. }
            if reason.contains("at least one category")));
    }

    #[test]
    fn ipc_observe_core_path_without_inventing_utilization() {
        let (_dir, adapter, registry) = gemini_fixture();
        let binding = stage_gemini_account(&registry);
        let store = MemoryStore {
            bytes: Some(TEST_KEY.as_bytes().to_vec()),
        };
        let result = observe_selected_account(
            &registry,
            &adapter,
            AccountObserveRequest {
                binding: binding.clone(),
                categories: vec![
                    ObserveCategory::Auth,
                    ObserveCategory::Models,
                    ObserveCategory::Quota,
                ],
            },
            Some(&store),
        )
        .expect("core observe");
        let json = serde_json::to_string(&result).expect("json");
        assert!(!json.contains("utilization"));
        let quota = result.quota.expect("quota");
        assert_eq!(quota.outcome, ObservationOutcome::Unknown);
    }

    #[test]
    fn ipc_stale_binding_fails_closed_without_auto_select() {
        let (_dir, adapter, registry) = gemini_fixture();
        let binding = stage_gemini_account(&registry);
        let mut stale = binding.clone();
        stale.selection_revision = binding.selection_revision.saturating_sub(1);

        let error = observe_selected_account(
            &registry,
            &adapter,
            AccountObserveRequest {
                binding: stale,
                categories: vec![ObserveCategory::Quota],
            },
            None,
        )
        .expect_err("stale binding");
        assert!(matches!(error, Error::StaleSelection { .. }));
    }
}
