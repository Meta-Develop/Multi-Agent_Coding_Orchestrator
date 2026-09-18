//! Hermetic `account.observe` contract: unknown quota without live accounts.

#[allow(dead_code)]
mod common;

use coding_agent_manager_lib::account_authority::{
    AccountObserveRequest, ObservationOutcome, StoredAccountRegistry,
};
use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};
use coding_agent_manager_lib::paths::stored_accounts_path;
use coding_agent_manager_lib::providers::codex_cli::CodexCliAdapter;
use coding_agent_manager_lib::providers::cursor::CursorAdapter;
use coding_agent_manager_lib::providers::gemini_cli::GeminiCliAdapter;
use coding_agent_manager_lib::providers::{observe_selected_account, ObserveCategory};
use coding_agent_manager_lib::storage::{CredentialStore, Secret, SecretRef};
use std::fs;
use std::path::Path;

const CURSOR_FIXTURE_HOME: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cursor/home");

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
    ) -> coding_agent_manager_lib::error::Result<()> {
        Ok(())
    }

    fn get(&self, _key: &SecretRef) -> coding_agent_manager_lib::error::Result<Option<Secret>> {
        Ok(self.bytes.as_ref().map(|bytes| Secret::new(bytes.clone())))
    }

    fn delete(&self, _key: &SecretRef) -> coding_agent_manager_lib::error::Result<()> {
        Ok(())
    }
}

fn gemini_fixture() -> (
    tempfile::TempDir,
    GeminiCliAdapter,
    StoredAccountRegistry,
    MemoryStore,
) {
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
    let store = MemoryStore {
        bytes: Some(TEST_KEY.as_bytes().to_vec()),
    };
    (dir, adapter, registry, store)
}

fn cursor_fixture() -> (tempfile::TempDir, CursorAdapter, StoredAccountRegistry) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let data = dir.path().join("data");
    copy_tree(Path::new(CURSOR_FIXTURE_HOME), &home);
    let adapter = CursorAdapter::with_home(&home);
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    (dir, adapter, registry)
}

fn codex_fixture() -> (common::Fixture, CodexCliAdapter, StoredAccountRegistry) {
    let fixture = common::Fixture::materialise();
    let data = fixture.temp.path().join("data");
    fs::create_dir_all(&data).expect("data dir");
    let adapter = CodexCliAdapter::with_home(&fixture.home)
        .with_data_dir(&data)
        .with_tool_running(false);
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    (fixture, adapter, registry)
}

fn seed_codex_selected(
    registry: &StoredAccountRegistry,
) -> coding_agent_manager_lib::account_authority::SelectedAccountBinding {
    registry
        .begin_add(
            "codex-cli",
            "work",
            "Work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin add");
    registry
        .complete_add("codex-cli", "work")
        .expect("complete add");
    registry
        .select_complete_revision("codex-cli", "work", None)
        .expect("select")
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("fixture file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy fixture file");
        }
    }
}

#[test]
fn cursor_observe_reports_unknown_quota_without_invented_utilization() {
    let (_dir, adapter, registry) = cursor_fixture();
    registry
        .begin_add(
            "cursor",
            "work",
            "Work",
            AuthKind::Unknown,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin add");
    registry
        .complete_add("cursor", "work")
        .expect("complete add");
    let binding = registry
        .select_complete_revision("cursor", "work", None)
        .expect("select");

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
        None,
    )
    .expect("observe");

    assert_eq!(result.binding, binding);
    let json = serde_json::to_string(&result).expect("json");
    assert!(!json.contains("utilization"));
    assert!(!json.contains(r#""snapshots":[]"#));

    let quota = result.quota.expect("quota category");
    assert_eq!(quota.outcome, ObservationOutcome::Unknown);
    assert!(quota.content.is_none());

    let models = result.models.expect("models category");
    assert_eq!(models.outcome, ObservationOutcome::Unknown);

    let auth = result.auth.expect("auth category");
    assert_eq!(auth.outcome, ObservationOutcome::Unavailable);
}

#[test]
fn cursor_observe_refuses_stale_binding_without_auto_select() {
    let (_dir, adapter, registry) = cursor_fixture();
    registry
        .begin_add(
            "cursor",
            "work",
            "Work",
            AuthKind::Unknown,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin add");
    registry
        .complete_add("cursor", "work")
        .expect("complete add");
    let binding = registry
        .select_complete_revision("cursor", "work", None)
        .expect("select");

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
    .expect_err("stale binding must fail closed");

    assert!(matches!(error, Error::StaleSelection { .. }));
}

#[test]
fn codex_observe_reports_unknown_quota_without_invented_utilization_or_zeros() {
    let (_fixture, adapter, registry) = codex_fixture();
    let binding = seed_codex_selected(&registry);

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
        None,
    )
    .expect("observe");

    assert_eq!(result.binding, binding);
    let json = serde_json::to_string(&result).expect("json");
    assert!(
        !json.contains("utilization"),
        "Codex observe must not invent utilization: {json}"
    );
    assert!(
        !json.contains("snapshots"),
        "unknown quota must not serialize empty snapshot arrays as invented zeros: {json}"
    );

    let quota = result.quota.expect("quota category");
    assert_eq!(quota.outcome, ObservationOutcome::Unknown);
    assert!(quota.content.is_none());

    let models = result.models.expect("models category");
    assert_eq!(models.outcome, ObservationOutcome::Unknown);
    assert!(models.content.is_none());

    let auth = result.auth.expect("auth category");
    assert_eq!(auth.outcome, ObservationOutcome::Unavailable);
    assert!(auth.content.is_none());
}

#[test]
fn codex_observe_refuses_stale_binding_without_auto_select() {
    let (_fixture, adapter, registry) = codex_fixture();
    let binding = seed_codex_selected(&registry);

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
    .expect_err("stale binding must fail closed");

    assert!(matches!(error, Error::StaleSelection { .. }));
}

#[test]
fn gemini_observe_reports_unknown_quota_and_models_without_invented_zeros() {
    let (_dir, adapter, registry, store) = gemini_fixture();
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
    let binding = registry
        .select_complete_revision("gemini-cli", "work", None)
        .expect("select");

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
    .expect("observe");

    assert_eq!(result.binding, binding);
    let json = serde_json::to_string(&result).expect("json");
    assert!(
        !json.contains("utilization"),
        "Gemini observe must not invent utilization: {json}"
    );
    assert!(
        !json.contains("snapshots"),
        "unknown quota must not serialize empty snapshots as observed zero: {json}"
    );

    let quota = result.quota.expect("quota category");
    assert_eq!(quota.outcome, ObservationOutcome::Unknown);
    assert!(quota.content.is_none());

    let models = result.models.expect("models category");
    assert_eq!(models.outcome, ObservationOutcome::Unknown);

    let auth = result.auth.expect("auth category");
    assert_eq!(auth.outcome, ObservationOutcome::Observed);
}

#[test]
fn gemini_observe_refuses_stale_binding_without_auto_select() {
    let (_dir, adapter, registry, store) = gemini_fixture();
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
    let binding = registry
        .select_complete_revision("gemini-cli", "work", None)
        .expect("select");

    let mut stale = binding.clone();
    stale.selection_revision = binding.selection_revision.saturating_sub(1);

    let error = observe_selected_account(
        &registry,
        &adapter,
        AccountObserveRequest {
            binding: stale,
            categories: vec![ObserveCategory::Quota],
        },
        Some(&store),
    )
    .expect_err("stale binding must fail closed");

    assert!(matches!(error, Error::StaleSelection { .. }));
}
