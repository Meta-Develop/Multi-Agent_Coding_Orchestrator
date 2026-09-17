use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use coding_agent_manager_lib::error::{Error, Result};
use coding_agent_manager_lib::model::{
    Account, AuthKind, InstallState, Maturity, ProviderDescriptor, StoredAccountMaterial,
    StoredAccountMetadata, StoredAccountState,
};
use coding_agent_manager_lib::providers::{
    add_managed_account, delete_managed_account, launch_spec_for, select_launch_account,
    spawn_launch, ActivationMechanism, LaunchSpec, ManagedAccountPlan, ProviderAdapter,
    StoredAccountRegistry,
};
use coding_agent_manager_lib::storage::{CredentialStore, Secret, SecretRef};

const FAKE_SECRET: &[u8] = b"FAKE-gemini-key-launch-contract";

#[derive(Default)]
struct FakeStore {
    values: Mutex<HashMap<SecretRef, Vec<u8>>>,
    fail_put: AtomicBool,
    fail_delete: AtomicBool,
}

impl FakeStore {
    fn contains(&self, provider_id: &str, account_id: &str) -> bool {
        self.values
            .lock()
            .expect("fake store lock")
            .contains_key(&SecretRef::for_account(provider_id, account_id))
    }
}

impl CredentialStore for FakeStore {
    fn id(&self) -> &'static str {
        "launch-contract-fake"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn put(&self, key: &SecretRef, secret: &Secret) -> Result<()> {
        if self.fail_put.load(Ordering::SeqCst) {
            return Err(Error::CredentialStoreUnavailable(
                "fixture store refused put".to_string(),
            ));
        }
        self.values
            .lock()
            .expect("fake store lock")
            .insert(key.clone(), secret.expose().to_vec());
        Ok(())
    }

    fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        Ok(self
            .values
            .lock()
            .expect("fake store lock")
            .get(key)
            .cloned()
            .map(Secret::new))
    }

    fn delete(&self, key: &SecretRef) -> Result<()> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(Error::CredentialStoreUnavailable(
                "fixture store refused delete".to_string(),
            ));
        }
        self.values.lock().expect("fake store lock").remove(key);
        Ok(())
    }
}

struct ProbeAdapter {
    provider_id: &'static str,
    spec: LaunchSpec,
    reject_account: Option<String>,
}

impl ProbeAdapter {
    fn new(provider_id: &'static str, spec: LaunchSpec) -> Self {
        Self {
            provider_id,
            spec,
            reject_account: None,
        }
    }

    fn rejecting(provider_id: &'static str, account_id: &str) -> Self {
        Self {
            provider_id,
            spec: LaunchSpec::new("unused"),
            reject_account: Some(account_id.to_string()),
        }
    }
}

impl ProviderAdapter for ProbeAdapter {
    fn id(&self) -> &'static str {
        self.provider_id
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.provider_id.to_string(),
            display_name: "Probe".to_string(),
            vendor: "Fixture".to_string(),
            auth_kinds: vec![AuthKind::ApiKey],
            maturity: Maturity::Experimental,
            install_state: InstallState::Installed,
            capabilities: Vec::new(),
        }
    }

    fn config_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    fn detect(&self) -> InstallState {
        InstallState::Installed
    }

    fn list_accounts(&self) -> Result<Vec<Account>> {
        Ok(Vec::new())
    }

    fn activation_mechanism(&self) -> ActivationMechanism {
        ActivationMechanism::LaunchEnvironment
    }

    fn launch_spec(&self, account: &StoredAccountMetadata) -> Result<LaunchSpec> {
        if self.reject_account.as_deref() == Some(account.id.as_str()) {
            return Err(Error::ConfigWrite {
                provider: self.provider_id.to_string(),
                reason: "fixture launch selection is unavailable".to_string(),
            });
        }
        Ok(self.spec.clone())
    }

    fn activate_account(&self, _account_id: &str) -> Result<()> {
        Err(Error::NotImplemented("probe activate_account"))
    }
}

struct ManagedProbeAdapter {
    provider_id: &'static str,
    plan: ManagedAccountPlan,
    vendor_home: Option<PathBuf>,
}

impl ProviderAdapter for ManagedProbeAdapter {
    fn id(&self) -> &'static str {
        self.provider_id
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.provider_id.to_string(),
            display_name: "Managed probe".to_string(),
            vendor: "Fixture".to_string(),
            auth_kinds: vec![self.plan.auth_kind],
            maturity: Maturity::Experimental,
            install_state: InstallState::Installed,
            capabilities: Vec::new(),
        }
    }

    fn config_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    fn detect(&self) -> InstallState {
        InstallState::Installed
    }

    fn list_accounts(&self) -> Result<Vec<Account>> {
        Ok(Vec::new())
    }

    fn managed_account_plan(&self) -> Option<ManagedAccountPlan> {
        Some(self.plan)
    }

    fn provision_stored_account(&self, _account: &StoredAccountMetadata) -> Result<Option<Secret>> {
        match self.plan.material {
            StoredAccountMaterial::CredentialStore => Ok(Some(Secret::new(FAKE_SECRET.to_vec()))),
            StoredAccountMaterial::VendorHome => {
                let home = self.vendor_home.as_ref().expect("vendor-home path");
                fs::create_dir_all(home).expect("create fake vendor home");
                fs::write(home.join("auth.json"), b"FAKE-vendor-written-auth")
                    .expect("write fake vendor auth");
                Ok(None)
            }
        }
    }

    fn validate_stored_account_delete(&self, _account: &StoredAccountMetadata) -> Result<()> {
        Ok(())
    }

    fn activate_account(&self, _account_id: &str) -> Result<()> {
        Err(Error::NotImplemented("managed probe activate_account"))
    }
}

fn metadata_path(dir: &tempfile::TempDir) -> PathBuf {
    coding_agent_manager_lib::paths::stored_accounts_path(dir.path())
}

fn selected_account(provider_id: &str, material: StoredAccountMaterial) -> StoredAccountMetadata {
    StoredAccountMetadata {
        id: "work".to_string(),
        provider_id: provider_id.to_string(),
        label: "Work".to_string(),
        auth_kind: AuthKind::ApiKey,
        state: StoredAccountState::Complete,
        material,
        is_selected: true,
    }
}

#[test]
fn child_environment_probe() {
    let Some(output) = std::env::var_os("CAM_LAUNCH_PROBE_FILE") else {
        return;
    };
    let document = serde_json::json!({
        "plain": std::env::var("CAM_PLAIN_SELECTION").ok(),
        "secret": std::env::var("CAM_SECRET_SELECTION").ok(),
        "pathWasRemoved": std::env::var_os("PATH").is_none(),
        "cwd": std::env::current_dir().ok(),
    });
    fs::write(output, serde_json::to_vec(&document).expect("probe JSON"))
        .expect("write child probe output");
}

#[test]
fn core_sets_and_removes_exact_child_environment_without_mutating_its_own() {
    let dir = tempfile::tempdir().expect("tempdir");
    let output = dir.path().join("child-environment.json");
    let spec = LaunchSpec::new(std::env::current_exe().expect("current test executable"))
        .current_dir(dir.path())
        .arg("--exact")
        .arg("child_environment_probe")
        .arg("--nocapture")
        .set_plain_env("CAM_LAUNCH_PROBE_FILE", output.as_os_str())
        .set_plain_env("CAM_PLAIN_SELECTION", "selected-home")
        .set_secret_env("CAM_SECRET_SELECTION")
        .remove_env("PATH");
    let adapter = ProbeAdapter::new("gemini-cli", spec);
    let account = selected_account("gemini-cli", StoredAccountMaterial::CredentialStore);
    let store = FakeStore::default();
    store
        .put(
            &SecretRef::for_account("gemini-cli", "work"),
            &Secret::new(FAKE_SECRET.to_vec()),
        )
        .expect("seed fake credential");

    let spec = launch_spec_for(&adapter, &account).expect("validated adapter launch spec");
    assert!(spec.requires_credential());
    let status = spawn_launch(spec, &account, Some(&store))
        .expect("spawn probe")
        .wait()
        .expect("wait for probe");
    assert!(status.success(), "child probe failed: {status}");

    let observed: serde_json::Value =
        serde_json::from_slice(&fs::read(output).expect("read probe output"))
            .expect("parse probe output");
    assert_eq!(observed["plain"], "selected-home");
    assert_eq!(
        observed["secret"],
        std::str::from_utf8(FAKE_SECRET).unwrap()
    );
    assert_eq!(observed["pathWasRemoved"], true);
    let observed_cwd = PathBuf::from(observed["cwd"].as_str().expect("child cwd path"));
    assert!(observed_cwd.is_absolute(), "child cwd must be absolute");
    assert_eq!(
        observed_cwd.canonicalize().expect("canonical child cwd"),
        dir.path().canonicalize().expect("canonical expected cwd")
    );
    assert!(std::env::var_os("CAM_PLAIN_SELECTION").is_none());
    assert!(std::env::var_os("CAM_SECRET_SELECTION").is_none());
    assert!(std::env::var_os("PATH").is_some());
}

#[test]
fn launch_rejects_metadata_for_a_different_adapter() {
    let adapter = ProbeAdapter::new("gemini-cli", LaunchSpec::new("unused"));
    let account = selected_account("grok-cli", StoredAccountMaterial::VendorHome);
    let error = launch_spec_for(&adapter, &account).err().expect("mismatch");
    assert!(matches!(error, Error::UnknownProvider(ref id) if id == "grok-cli"));
}

#[test]
fn selection_is_persisted_only_after_adapter_validation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(metadata_path(&dir));
    registry
        .begin_add(
            "grok-cli",
            "work",
            "Work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin add");
    registry
        .complete_add("grok-cli", "work")
        .expect("complete add");
    let adapter = ProbeAdapter::new("grok-cli", LaunchSpec::new("grok").current_dir(dir.path()));
    select_launch_account(&registry, &adapter, "work").expect("validated selection");
    assert_eq!(
        registry
            .selected("grok-cli")
            .expect("load selection")
            .expect("selected account")
            .id,
        "work"
    );
}

#[test]
fn refused_launch_validation_leaves_previous_selection_intact() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(metadata_path(&dir));
    for id in ["personal", "work"] {
        registry
            .begin_add(
                "grok-cli",
                id,
                id,
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )
            .expect("begin add");
        registry.complete_add("grok-cli", id).expect("complete add");
    }
    registry
        .select_complete("grok-cli", "personal")
        .expect("seed previous selection");

    let error = select_launch_account(
        &registry,
        &ProbeAdapter::rejecting("grok-cli", "work"),
        "work",
    )
    .expect_err("adapter validation must refuse");
    assert!(!error.to_string().contains("FAKE-"));
    assert_eq!(
        registry
            .selected("grok-cli")
            .expect("load selection")
            .expect("previous selection")
            .id,
        "personal"
    );
}

#[test]
fn refused_current_validation_preserves_it_and_refuses_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(metadata_path(&dir));
    for id in ["personal", "work"] {
        registry
            .begin_add(
                "grok-cli",
                id,
                id,
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )
            .expect("begin add");
        registry.complete_add("grok-cli", id).expect("complete add");
    }
    registry
        .select_complete("grok-cli", "personal")
        .expect("seed current selection");

    select_launch_account(
        &registry,
        &ProbeAdapter::rejecting("grok-cli", "personal"),
        "work",
    )
    .expect_err("current selection validation must refuse");
    assert_eq!(
        registry
            .selected("grok-cli")
            .expect("load selection")
            .expect("current selection")
            .id,
        "personal"
    );
}

#[test]
fn metadata_is_versioned_durable_selected_and_contains_no_secret_or_secret_ref() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = metadata_path(&dir);
    let registry = StoredAccountRegistry::new(&path);
    let store = FakeStore::default();
    registry
        .add_with_secret(
            "gemini-cli",
            "work",
            "Work",
            AuthKind::ApiKey,
            &Secret::new(FAKE_SECRET.to_vec()),
            &store,
        )
        .expect("add credential-backed metadata");
    registry
        .select_complete("gemini-cli", "work")
        .expect("select complete account");

    let bytes = fs::read(&path).expect("read metadata");
    let text = String::from_utf8(bytes).expect("metadata UTF-8");
    assert!(text.contains(r#""schemaVersion": 1"#), "{text}");
    assert!(!text.contains("FAKE-"), "metadata serialized a credential");
    assert!(
        !text.contains("gemini-cli/work"),
        "metadata serialized a derived SecretRef"
    );

    let reopened = StoredAccountRegistry::new(&path);
    let account = reopened
        .selected("gemini-cli")
        .expect("load durable selection")
        .expect("selected account");
    assert_eq!(account.state, StoredAccountState::Complete);
    assert_eq!(account.material, StoredAccountMaterial::CredentialStore);
    assert!(!format!("{account:?}").contains("FAKE-"));
}

#[test]
fn core_managed_credential_lifecycle_uses_only_credential_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(metadata_path(&dir));
    let store = FakeStore::default();
    let adapter = ManagedProbeAdapter {
        provider_id: "gemini-cli",
        plan: ManagedAccountPlan {
            auth_kind: AuthKind::ApiKey,
            material: StoredAccountMaterial::CredentialStore,
        },
        vendor_home: None,
    };

    add_managed_account(&registry, &adapter, "work", "Work", Some(&store)).expect("managed add");
    assert!(store.contains("gemini-cli", "work"));
    assert_eq!(
        registry
            .complete("gemini-cli", "work")
            .expect("complete metadata")
            .material,
        StoredAccountMaterial::CredentialStore
    );
    assert!(!fs::read_to_string(metadata_path(&dir))
        .expect("metadata text")
        .contains("FAKE-"));

    delete_managed_account(&registry, &adapter, "work", Some(&store)).expect("managed delete");
    assert!(!store.contains("gemini-cli", "work"));
    assert!(registry.load().expect("metadata after delete").is_empty());
}

#[test]
fn core_managed_delete_forgets_metadata_but_retains_vendor_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(metadata_path(&dir));
    let vendor_home = dir.path().join("accounts/grok-cli/work");
    let adapter = ManagedProbeAdapter {
        provider_id: "grok-cli",
        plan: ManagedAccountPlan {
            auth_kind: AuthKind::OAuth,
            material: StoredAccountMaterial::VendorHome,
        },
        vendor_home: Some(vendor_home.clone()),
    };

    add_managed_account(&registry, &adapter, "work", "Work", None).expect("managed add");
    assert!(vendor_home.join("auth.json").is_file());
    delete_managed_account(&registry, &adapter, "work", None).expect("managed delete");
    assert!(
        vendor_home.join("auth.json").is_file(),
        "generic deletion must retain the vendor-written home"
    );
    assert!(registry.load().expect("metadata after delete").is_empty());
}

#[test]
fn failed_add_is_pending_and_recovery_removes_metadata_and_any_credential() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(metadata_path(&dir));
    let store = FakeStore::default();
    store.fail_put.store(true, Ordering::SeqCst);
    let error = registry
        .add_with_secret(
            "gemini-cli",
            "work",
            "Work",
            AuthKind::ApiKey,
            &Secret::new(FAKE_SECRET.to_vec()),
            &store,
        )
        .expect_err("fixture put must fail");
    assert!(!error.to_string().contains("FAKE-"));
    let accounts = registry.load().expect("load pending metadata");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].state, StoredAccountState::Pending);

    store.fail_put.store(false, Ordering::SeqCst);
    registry.recover(Some(&store)).expect("recover pending add");
    assert!(registry.load().expect("load recovered metadata").is_empty());
    assert!(!store.contains("gemini-cli", "work"));
}

#[test]
fn recovery_preserves_pending_vendor_home_for_provider_specific_validation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(metadata_path(&dir));
    registry
        .begin_add(
            "grok-cli",
            "work",
            "Work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin vendor-home add");
    registry.recover(None).expect("generic recovery");
    let accounts = registry.load().expect("load metadata");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].state, StoredAccountState::Pending);
    assert_eq!(accounts[0].material, StoredAccountMaterial::VendorHome);
}

#[test]
fn failed_delete_is_durable_unselected_and_recovery_finishes_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(metadata_path(&dir));
    let store = FakeStore::default();
    registry
        .add_with_secret(
            "gemini-cli",
            "work",
            "Work",
            AuthKind::ApiKey,
            &Secret::new(FAKE_SECRET.to_vec()),
            &store,
        )
        .expect("add account");
    registry
        .select_complete("gemini-cli", "work")
        .expect("select account");
    store.fail_delete.store(true, Ordering::SeqCst);
    let error = registry
        .delete("gemini-cli", "work", Some(&store))
        .expect_err("fixture delete must fail");
    assert!(!error.to_string().contains("FAKE-"));
    let deleting = registry.load().expect("load deleting metadata");
    assert_eq!(deleting[0].state, StoredAccountState::Deleting);
    assert!(!deleting[0].is_selected);
    assert!(registry
        .selected("gemini-cli")
        .expect("selection")
        .is_none());

    store.fail_delete.store(false, Ordering::SeqCst);
    registry.recover(Some(&store)).expect("recover deletion");
    assert!(registry.load().expect("load recovered metadata").is_empty());
    assert!(!store.contains("gemini-cli", "work"));
}

#[test]
fn newer_metadata_schema_is_refused_without_echoing_document_contents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = metadata_path(&dir);
    fs::write(
        &path,
        br#"{"schemaVersion":2,"accounts":[{"id":"work","providerId":"gemini-cli","label":"FAKE-must-not-echo","authKind":"api-key","state":"complete","material":"credential-store","isSelected":false}]}"#,
    )
    .expect("write newer metadata fixture");
    let error = StoredAccountRegistry::new(path)
        .load()
        .expect_err("newer schema must be refused");
    let message = error.to_string();
    assert!(
        message.contains("unsupported schema version 2"),
        "{message}"
    );
    assert!(!message.contains("FAKE-"), "error echoed document contents");
}
