use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::sync::Mutex;

use coding_agent_manager_lib::error::{Error, Result};
use coding_agent_manager_lib::model::{
    AuthKind, ProviderCapability, StoredAccountMaterial, StoredAccountMetadata, StoredAccountState,
};
use coding_agent_manager_lib::providers::gemini_cli::GeminiCliAdapter;
#[cfg(unix)]
use coding_agent_manager_lib::providers::spawn_launch;
use coding_agent_manager_lib::providers::{
    add_managed_account_for, delete_managed_account, launch_spec_for, select_launch_account,
    ProviderAdapter, StoredAccountRegistry,
};
use coding_agent_manager_lib::storage::{CredentialStore, Secret, SecretRef};

const PROVIDER_ID: &str = "gemini-cli";
const FAKE_KEY_WORK: &str = "FAKE-gemini-key-work-0001";
const FAKE_KEY_PERSONAL: &str = "FAKE-gemini-key-personal-0002";

#[derive(Default)]
struct FakeStore {
    values: Mutex<HashMap<SecretRef, Vec<u8>>>,
}

impl FakeStore {
    fn value(&self, account_id: &str) -> Option<Vec<u8>> {
        self.values
            .lock()
            .expect("store lock")
            .get(&SecretRef::for_account(PROVIDER_ID, account_id))
            .cloned()
    }
}

impl CredentialStore for FakeStore {
    fn id(&self) -> &'static str {
        "gemini-fixture"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn put(&self, key: &SecretRef, secret: &Secret) -> Result<()> {
        self.values
            .lock()
            .expect("store lock")
            .insert(key.clone(), secret.expose().to_vec());
        Ok(())
    }

    fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        Ok(self
            .values
            .lock()
            .expect("store lock")
            .get(key)
            .cloned()
            .map(Secret::new))
    }

    fn delete(&self, key: &SecretRef) -> Result<()> {
        self.values.lock().expect("store lock").remove(key);
        Ok(())
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    config: PathBuf,
    data: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = temp.path().join("config");
        copy_tree(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gemini/config"),
            &config,
        );
        Self {
            data: temp.path().join("manager-data"),
            config,
            _temp: temp,
        }
    }

    fn adapter(&self, key: Option<&str>) -> GeminiCliAdapter {
        GeminiCliAdapter::with_test_context(
            self.config.join("home"),
            self.data.clone(),
            self.config.join("workspace"),
            self.config.join("system/settings.json"),
            self.config.join("system/system-defaults.json"),
            key,
        )
    }

    fn registry(&self) -> StoredAccountRegistry {
        StoredAccountRegistry::new(coding_agent_manager_lib::paths::stored_accounts_path(
            &self.data,
        ))
    }
}

#[test]
fn api_key_accounts_use_credential_store_and_never_touch_gemini_config() {
    let fixture = Fixture::new();
    let registry = fixture.registry();
    let store = FakeStore::default();
    let before = tree_bytes(&fixture.config);

    add_managed_account_for(
        &registry,
        &fixture.adapter(Some(FAKE_KEY_WORK)),
        "work",
        "Work",
        Some(&store),
        Some(AuthKind::ApiKey),
    )
    .expect("add work account");
    add_managed_account_for(
        &registry,
        &fixture.adapter(Some(FAKE_KEY_PERSONAL)),
        "personal",
        "Personal",
        Some(&store),
        Some(AuthKind::ApiKey),
    )
    .expect("add personal account");

    assert_eq!(
        store.value("work").as_deref(),
        Some(FAKE_KEY_WORK.as_bytes())
    );
    assert_eq!(
        store.value("personal").as_deref(),
        Some(FAKE_KEY_PERSONAL.as_bytes())
    );
    let adapter = fixture.adapter(None);
    let accounts = adapter.list_accounts().expect("stored accounts");
    assert_eq!(
        accounts
            .iter()
            .map(|account| account.id.as_str())
            .collect::<Vec<_>>(),
        vec!["personal", "work"]
    );
    assert!(accounts.iter().all(|account| {
        account.is_stored
            && !account.is_active
            && !account.is_selected_for_launch
            && account.masked_identity.is_none()
    }));
    let surfaces = format!(
        "{accounts:?} {}",
        serde_json::to_string(&accounts).expect("accounts json")
    );
    assert!(!surfaces.contains("FAKE-"), "account IPC leaked a key");

    select_launch_account(&registry, &adapter, "work").expect("select work");
    let selected = registry
        .selected(PROVIDER_ID)
        .expect("selected lookup")
        .expect("selected account");
    let _spec = launch_spec_for(&adapter, &selected).expect("prepare launch spec");

    assert_eq!(
        before,
        tree_bytes(&fixture.config),
        "Gemini config sources changed during add, selection, or launch preparation"
    );
    assert!(coding_agent_manager_lib::paths::stored_accounts_path(&fixture.data).is_file());

    let accounts = adapter.list_accounts().expect("selected listing");
    assert!(accounts
        .iter()
        .find(|account| account.id == "work")
        .is_some_and(|account| account.is_selected_for_launch && !account.is_active));

    delete_managed_account(&registry, &adapter, "work", Some(&store)).expect("delete work");
    assert_eq!(store.value("work"), None);
    assert!(registry.account(PROVIDER_ID, "work").is_err());
    assert_eq!(before, tree_bytes(&fixture.config));
}

#[cfg(unix)]
#[test]
fn gemini_adapter_spawn_applies_exact_key_removals_and_cwd() {
    const CHILD_MARKER: &str = "CAM_GEMINI_ADAPTER_SPAWN_CHILD";
    let inherited_before: Vec<_> = [
        "GEMINI_API_KEY",
        "GOOGLE_GENAI_USE_GCA",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_GEMINI_BASE_URL",
        "GOOGLE_API_KEY",
        "CLOUD_SHELL",
        "GEMINI_CLI_USE_COMPUTE_ADC",
    ]
    .into_iter()
    .map(|name| (name, std::env::var_os(name)))
    .collect();

    if std::env::var_os(CHILD_MARKER).is_none() {
        let mut child = Command::new(std::env::current_exe().expect("test executable"));
        child
            .arg("--exact")
            .arg("gemini_adapter_spawn_applies_exact_key_removals_and_cwd")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1");
        for name in [
            "GOOGLE_GENAI_USE_GCA",
            "GOOGLE_GENAI_USE_VERTEXAI",
            "GOOGLE_GEMINI_BASE_URL",
            "GOOGLE_API_KEY",
            "CLOUD_SHELL",
            "GEMINI_CLI_USE_COMPUTE_ADC",
        ] {
            child.env(name, "FAKE-conflicting-parent-selector");
        }
        assert!(child.status().expect("nested test process").success());
        for (name, before) in inherited_before {
            assert_eq!(std::env::var_os(name), before, "parent env changed: {name}");
        }
        return;
    }

    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let probe_program = fixture.config.join("gemini-probe");
    fs::write(
        &probe_program,
        concat!(
            "#!/bin/sh\n",
            "{\n",
            "  printf 'key=%s\\n' \"${GEMINI_API_KEY-unset}\"\n",
            "  printf 'gca=%s\\n' \"${GOOGLE_GENAI_USE_GCA-unset}\"\n",
            "  printf 'vertex=%s\\n' \"${GOOGLE_GENAI_USE_VERTEXAI-unset}\"\n",
            "  printf 'gateway=%s\\n' \"${GOOGLE_GEMINI_BASE_URL-unset}\"\n",
            "  printf 'google-key=%s\\n' \"${GOOGLE_API_KEY-unset}\"\n",
            "  printf 'cloud-shell=%s\\n' \"${CLOUD_SHELL-unset}\"\n",
            "  printf 'adc=%s\\n' \"${GEMINI_CLI_USE_COMPUTE_ADC-unset}\"\n",
            "  printf 'cwd=%s\\n' \"$(pwd)\"\n",
            "} > gemini-launch-probe.txt\n"
        ),
    )
    .expect("write probe program");
    let mut permissions = fs::metadata(&probe_program)
        .expect("probe metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&probe_program, permissions).expect("executable probe");

    let adapter = fixture
        .adapter(Some(FAKE_KEY_WORK))
        .with_test_program(probe_program);
    let registry = fixture.registry();
    let store = FakeStore::default();
    add_managed_account_for(
        &registry,
        &adapter,
        "work",
        "Work",
        Some(&store),
        Some(AuthKind::ApiKey),
    )
    .expect("add work account");
    select_launch_account(&registry, &adapter, "work").expect("select work");
    let selected = registry
        .selected(PROVIDER_ID)
        .expect("selected lookup")
        .expect("selected account");
    let spec = launch_spec_for(&adapter, &selected).expect("Gemini launch spec");
    let mut child = spawn_launch(spec, &selected, Some(&store)).expect("spawn Gemini probe");
    assert!(child.wait().expect("wait for Gemini probe").success());

    let output = fs::read_to_string(fixture.config.join("workspace/gemini-launch-probe.txt"))
        .expect("probe output");
    let expected_cwd = fixture
        .config
        .join("workspace")
        .canonicalize()
        .expect("canonical workspace")
        .to_string_lossy()
        .into_owned();
    let expected = format!(
        "key={FAKE_KEY_WORK}\n\
         gca=unset\n\
         vertex=unset\n\
         gateway=unset\n\
         google-key=unset\n\
         cloud-shell=unset\n\
         adc=unset\n\
         cwd={expected_cwd}\n"
    );
    assert_eq!(output, expected);
}

#[test]
fn effective_settings_require_api_key_mode_at_every_possible_trust_outcome() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter(None);
    let account = complete_account("work");

    // Fixture precedence: system-default OAuth is replaced by user API key,
    // and system enforcement agrees. Both trust outcomes allow.
    assert!(adapter.launch_spec(&account).is_ok());

    write_auth(
        fixture.config.join("home/.gemini/settings.json"),
        "oauth-personal",
    );
    assert!(adapter.launch_spec(&account).is_err(), "user OAuth allowed");

    write_auth(
        fixture.config.join("home/.gemini/settings.json"),
        "gemini-api-key",
    );
    write_auth(
        fixture.config.join("workspace/.gemini/settings.json"),
        "oauth-personal",
    );
    assert!(
        adapter.launch_spec(&account).is_err(),
        "possibly trusted workspace OAuth allowed"
    );

    write_auth(
        fixture.config.join("system/settings.json"),
        "oauth-personal",
    );
    assert!(
        adapter.launch_spec(&account).is_err(),
        "system OAuth allowed"
    );

    // The final system source wins for both trusted and untrusted workspace
    // outcomes, matching the pinned vendor merge order.
    write_auth(
        fixture.config.join("home/.gemini/settings.json"),
        "oauth-personal",
    );
    write_auth(
        fixture.config.join("workspace/.gemini/settings.json"),
        "oauth-personal",
    );
    fs::write(
        fixture.config.join("system/settings.json"),
        r#"{"security":{"auth":{"selectedType":"gemini-api-key","enforcedType":"gemini-api-key","useExternal":false}}}"#,
    )
    .expect("system precedence settings");
    assert!(adapter.launch_spec(&account).is_ok());

    fs::write(
        fixture.config.join("system/settings.json"),
        r#"{"security":{"auth":{"selectedType":"gemini-api-key","enforcedType":"oauth-personal"}}}"#,
    )
    .expect("conflicting enforcement");
    assert!(adapter.launch_spec(&account).is_err());

    fs::write(
        fixture.config.join("system/settings.json"),
        r#"{"security":{"auth":{"selectedType":"gemini-api-key","enforcedType":"gemini-api-key","useExternal":true}}}"#,
    )
    .expect("external auth");
    assert!(adapter.launch_spec(&account).is_err());
}

#[test]
fn malformed_or_unusable_metadata_and_settings_fail_closed() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter(None);

    fs::write(
        fixture.config.join("home/.gemini/settings.json"),
        "{ not-json",
    )
    .expect("malformed settings");
    let error = adapter
        .launch_spec(&complete_account("work"))
        .err()
        .expect("malformed settings must refuse");
    assert!(matches!(error, Error::ConfigRead { .. }));
    assert!(!format!("{error:?} {error}").contains("FAKE-"));

    let fixture = Fixture::new();
    let adapter = fixture.adapter(None);
    let pending = metadata("pending", StoredAccountState::Pending, PROVIDER_ID);
    let deleting = metadata("deleting", StoredAccountState::Deleting, PROVIDER_ID);
    let other = metadata("work", StoredAccountState::Complete, "other-provider");
    assert!(adapter.launch_spec(&pending).is_err());
    assert!(adapter.launch_spec(&deleting).is_err());
    assert!(matches!(
        adapter.launch_spec(&other),
        Err(Error::UnknownProvider(_))
    ));
    assert!(adapter.launch_spec(&complete_account("../escape")).is_err());

    let registry = fixture.registry();
    assert!(matches!(
        select_launch_account(&registry, &adapter, "missing"),
        Err(Error::UnknownAccount(_))
    ));
}

#[test]
fn descriptor_advertises_oauth_default_and_api_key_import() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter(None);
    assert_eq!(
        adapter.descriptor().capabilities,
        vec![
            ProviderCapability::AddAccount,
            ProviderCapability::SwitchAccount,
            ProviderCapability::DeleteAccount,
            ProviderCapability::LaunchTool,
        ]
    );
    let plan = adapter.managed_account_plan().expect("managed plan");
    assert_eq!(plan.auth_kind, AuthKind::OAuth);
    assert_eq!(plan.material, StoredAccountMaterial::VendorHome);
    let api_key = adapter
        .managed_account_plan_for(AuthKind::ApiKey)
        .expect("api-key plan");
    assert_eq!(api_key.auth_kind, AuthKind::ApiKey);
    assert_eq!(api_key.material, StoredAccountMaterial::CredentialStore);
}

#[test]
fn oauth_add_writes_isolated_home_and_delete_retains_it() {
    let fixture = Fixture::new();
    let registry = fixture.registry();
    let before = tree_bytes(&fixture.config);
    let adapter = fixture
        .adapter(None)
        .with_oauth_completer(write_isolated_oauth);
    add_managed_account_for(
        &registry,
        &adapter,
        "work",
        "Work",
        None,
        Some(AuthKind::OAuth),
    )
    .expect("oauth add");
    let managed = fixture.data.join("accounts/gemini-cli/work");
    assert!(managed.join(".gemini/oauth_creds.json").is_file());
    let settings: serde_json::Value = serde_json::from_slice(
        &fs::read(managed.join(".gemini/settings.json")).expect("managed settings"),
    )
    .expect("settings json");
    assert_eq!(
        settings["security"]["auth"]["selectedType"],
        "oauth-personal"
    );
    assert_eq!(before, tree_bytes(&fixture.config));
    let accounts = adapter.list_accounts().expect("list");
    assert_eq!(accounts.len(), 1);
    let masked = accounts[0]
        .masked_identity
        .as_deref()
        .expect("masked identity");
    assert!(masked.contains("***@"));
    assert!(!masked.contains("FAKE-user-0001"));
    assert_eq!(
        accounts[0].expires_at.as_deref(),
        Some("2023-11-14T22:13:20Z")
    );
    let surfaces = format!(
        "{accounts:?} {}",
        serde_json::to_string(&accounts).expect("json")
    );
    assert!(!surfaces.contains("FAKE-"));
    delete_managed_account(&registry, &adapter, "work", None).expect("forget");
    assert!(registry.account(PROVIDER_ID, "work").is_err());
    assert!(
        managed.join(".gemini/oauth_creds.json").is_file(),
        "OAuth delete must retain the isolated home"
    );
    assert_eq!(before, tree_bytes(&fixture.config));
}

fn write_isolated_oauth(home: &Path) -> Result<()> {
    fs::create_dir_all(home.join(".gemini")).expect("oauth dir");
    fs::write(
        home.join(".gemini/oauth_creds.json"),
        br#"{"access_token":"FAKE-gemini-oauth-access-0001","refresh_token":"FAKE-gemini-oauth-refresh-0001","expiry_date":1700000000000,"token_type":"Bearer"}"#,
    )
    .expect("creds");
    fs::write(
        home.join(".gemini/google_accounts.json"),
        br#"{"active":"FAKE-user-0001@example.invalid","old":["FAKE-old-0002@example.invalid"]}"#,
    )
    .expect("accounts");
    Ok(())
}

#[test]
fn live_oauth_is_listed_read_only_and_old_is_not_a_second_account() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter(None);
    let live = fixture.config.join("home/.gemini");
    fs::write(
        live.join("oauth_creds.json"),
        br#"{"access_token":"FAKE-live-oauth-access-0001","expiry_date":1700000000000}"#,
    )
    .expect("live creds");
    fs::write(
        live.join("google_accounts.json"),
        br#"{"active":"FAKE-user-0001@example.invalid","old":["FAKE-old-0002@example.invalid"]}"#,
    )
    .expect("live accounts");
    let before = tree_bytes(&fixture.config);
    let accounts = adapter.list_accounts().expect("list");
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].id, "gemini-cli-on-disk");
    assert!(!accounts[0].is_stored);
    assert!(!accounts[0].is_selected_for_launch);
    assert!(!accounts[0].is_active);
    assert_eq!(accounts[0].expires_at, None);
    let masked = accounts[0]
        .masked_identity
        .as_deref()
        .expect("masked identity");
    assert!(masked.contains("***@"));
    assert!(!masked.contains("FAKE-user-0001"));
    let surfaces = format!(
        "{accounts:?} {}",
        serde_json::to_string(&accounts).expect("json")
    );
    assert!(!surfaces.contains("FAKE-"));
    assert_eq!(before, tree_bytes(&fixture.config));
}

fn complete_account(id: &str) -> StoredAccountMetadata {
    metadata(id, StoredAccountState::Complete, PROVIDER_ID)
}

fn metadata(id: &str, state: StoredAccountState, provider_id: &str) -> StoredAccountMetadata {
    StoredAccountMetadata {
        id: id.to_string(),
        provider_id: provider_id.to_string(),
        label: "Fixture".to_string(),
        auth_kind: AuthKind::ApiKey,
        state,
        material: StoredAccountMaterial::CredentialStore,
        is_selected: false,
        account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
    }
}

fn write_auth(path: PathBuf, selected_type: &str) {
    let document = serde_json::json!({
        "security": {"auth": {"selectedType": selected_type}}
    });
    fs::write(path, serde_json::to_vec_pretty(&document).expect("JSON")).expect("settings write");
}

fn copy_tree(source: PathBuf, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture destination");
    for entry in fs::read_dir(source).expect("read fixture source") {
        let entry = entry.expect("fixture entry");
        let destination = destination.join(entry.file_name());
        if entry.file_type().expect("fixture type").is_dir() {
            copy_tree(entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy fixture file");
        }
    }
}

fn tree_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("read tree")
            .map(|entry| entry.expect("tree entry"))
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            if entry.file_type().expect("tree type").is_dir() {
                visit(root, &path, output);
            } else {
                output.insert(
                    path.strip_prefix(root)
                        .expect("relative path")
                        .to_path_buf(),
                    fs::read(path).expect("tree file"),
                );
            }
        }
    }

    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}
