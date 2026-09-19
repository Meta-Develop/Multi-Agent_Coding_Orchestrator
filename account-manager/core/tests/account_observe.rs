//! Hermetic `account.observe` contract: unknown quota without live accounts.

#[allow(dead_code)]
mod common;

use coding_agent_manager_lib::account_authority::{
    AccountObserveRequest, ObservationOutcome, StoredAccountRegistry,
};
use coding_agent_manager_lib::error::{Error, Result};
use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};
use coding_agent_manager_lib::paths::stored_accounts_path;
use coding_agent_manager_lib::providers::claude_code::ClaudeCodeAdapter;
use coding_agent_manager_lib::providers::codex_cli::CodexCliAdapter;
use coding_agent_manager_lib::providers::cursor::CursorAdapter;
use coding_agent_manager_lib::providers::gemini_cli::GeminiCliAdapter;
use coding_agent_manager_lib::providers::github_copilot::GithubCopilotAdapter;
use coding_agent_manager_lib::providers::grok_cli::GrokCliAdapter;
use coding_agent_manager_lib::providers::{
    add_managed_account, add_managed_account_for, observe_selected_account, ObserveCategory,
};
use coding_agent_manager_lib::storage::{CredentialStore, Secret, SecretRef};
use std::fs;
use std::path::{Path, PathBuf};

const CLAUDE_FIXTURE_ROOT: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/claude-code");
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

fn gemini_oauth_fixture() -> (tempfile::TempDir, GeminiCliAdapter, StoredAccountRegistry) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let data = dir.path().join("data");
    let cwd = dir.path().join("workspace");
    fs::create_dir_all(home.join(".gemini")).expect("home gemini dir");
    fs::create_dir_all(cwd.join(".gemini")).expect("workspace gemini dir");
    fs::write(
        home.join(".gemini/settings.json"),
        r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#,
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
    .with_oauth_completer(write_isolated_oauth);
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    (dir, adapter, registry)
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

fn cursor_file_store_fixture() -> (tempfile::TempDir, CursorAdapter, StoredAccountRegistry) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let data = dir.path().join("data");
    copy_tree(Path::new(CURSOR_FIXTURE_HOME), &home);
    fs::create_dir_all(home.join(".cursor")).expect("cursor dir");
    fs::write(
        home.join(".cursor/auth.json"),
        br#"{"access_token":"FAKE-cursor-file-store-0001"}"#,
    )
    .expect("auth.json");
    let adapter = CursorAdapter::with_home(&home);
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    (dir, adapter, registry)
}

fn github_copilot_fixture() -> (
    tempfile::TempDir,
    GithubCopilotAdapter,
    StoredAccountRegistry,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let data = dir.path().join("data");
    fs::create_dir_all(home.join(".copilot")).expect("home copilot dir");
    fs::write(home.join(".copilot/settings.json"), r"{}").expect("settings");
    let adapter = GithubCopilotAdapter::with_home(&home);
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    (dir, adapter, registry)
}

const GROK_ACCOUNT: &str = "work";

fn grok_fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/grok")
        .join(name)
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

fn fake_grok_login(home: &Path) -> std::io::Result<i32> {
    fs::copy(grok_fixture_path("valid-auth.json"), home.join("auth.json"))?;
    Ok(0)
}

fn grok_fixture() -> (tempfile::TempDir, GrokCliAdapter, StoredAccountRegistry) {
    let dir = tempfile::tempdir().expect("tempdir");
    let user_home = dir.path().join("user-home");
    let data = dir.path().join("data");
    let cwd = dir.path().join("workspace");
    fs::create_dir_all(user_home.join(".grok")).expect("default grok home");
    copy_tree(&grok_fixture_path("default-home"), &user_home.join(".grok"));
    fs::create_dir_all(&cwd).expect("workspace");
    let adapter = GrokCliAdapter::with_home(&user_home)
        .with_data_dir(&data)
        .with_working_directory(&cwd)
        .with_program("/bin/true")
        .with_login_runner(fake_grok_login);
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    add_managed_account(&registry, &adapter, GROK_ACCOUNT, GROK_ACCOUNT, None)
        .expect("provision grok fixture account");
    (dir, adapter, registry)
}

fn claude_fixture() -> (tempfile::TempDir, ClaudeCodeAdapter, StoredAccountRegistry) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let data = dir.path().join("data");
    copy_tree(&Path::new(CLAUDE_FIXTURE_ROOT).join("home"), &home);

    let identity_path = home.join(".claude.json");
    let mut identity: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&identity_path).expect("read .claude.json"))
            .expect("parse .claude.json");
    identity.as_object_mut().expect("identity object").insert(
        "cachedUsageUtilization".to_string(),
        serde_json::json!({ "usedPercent": 0 }),
    );
    fs::write(
        &identity_path,
        serde_json::to_string(&identity).expect("serialize .claude.json"),
    )
    .expect("write .claude.json");

    let adapter = ClaudeCodeAdapter::with_home(&home).with_data_dir(&data);
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
    (dir, adapter, registry)
}

fn add_complete_claude(registry: &StoredAccountRegistry, account_id: &str) {
    registry
        .begin_add(
            "claude-code",
            account_id,
            account_id,
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin add");
    registry
        .complete_add("claude-code", account_id)
        .expect("complete add");
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
fn cursor_observe_does_not_treat_file_store_auth_json_as_observed_auth_or_quota() {
    let (_dir, adapter, registry) = cursor_file_store_fixture();
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
    assert!(!json.contains("access_token"));
    assert!(!json.contains("FAKE-"));

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
fn claude_observe_reports_unknown_quota_without_inventing_zeros_from_local_hints() {
    let (_dir, adapter, registry) = claude_fixture();
    add_complete_claude(&registry, "work");
    let binding = registry
        .select_complete_revision("claude-code", "work", None)
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
    assert!(
        !json.contains("utilization"),
        "observe must not invent numeric quota from local hints: {json}"
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
    assert_eq!(auth.outcome, ObservationOutcome::Unavailable);
}

#[test]
fn claude_observe_refuses_stale_binding_without_auto_select() {
    let (_dir, adapter, registry) = claude_fixture();
    add_complete_claude(&registry, "work");
    let binding = registry
        .select_complete_revision("claude-code", "work", None)
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
fn gemini_oauth_observe_does_not_invent_ai_pro_entitlement_from_local_files() {
    let (_dir, adapter, registry) = gemini_oauth_fixture();
    add_managed_account_for(
        &registry,
        &adapter,
        "work",
        "Work",
        None,
        Some(AuthKind::OAuth),
    )
    .expect("oauth add");
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
        None,
    )
    .expect("observe");

    assert_eq!(result.binding, binding);
    let json = serde_json::to_string(&result).expect("json");
    assert!(
        !json.contains("utilization"),
        "Gemini OAuth observe must not invent utilization: {json}"
    );
    assert!(
        !json.contains("snapshots"),
        "unknown quota must not serialize empty snapshots as observed zero: {json}"
    );
    assert!(
        !json.contains("paidTier"),
        "local OAuth files must not invent paid tier: {json}"
    );
    assert!(
        !json.contains("aiPro"),
        "local OAuth files must not invent AI Pro entitlement: {json}"
    );
    assert!(
        !json.contains("Google AI Pro"),
        "local OAuth files must not invent Google AI Pro: {json}"
    );
    assert!(
        !json.contains("Google AI Ultra"),
        "local OAuth files must not invent Google AI Ultra: {json}"
    );
    assert!(
        !json.contains("FAKE-"),
        "observe output must not leak fixture secrets: {json}"
    );
    assert!(
        !json.contains("FAKE-user-0001@example.invalid"),
        "observe output must not leak fixture email: {json}"
    );
    assert!(
        !json.contains("FAKE-old-0002@example.invalid"),
        "observe output must not leak fixture email: {json}"
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

#[test]
fn grok_observe_reports_unknown_quota_and_models_without_numeric_signals() {
    let (_dir, adapter, registry) = grok_fixture();
    let binding = registry
        .select_complete_revision("grok-cli", GROK_ACCOUNT, None)
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
    assert!(
        !json.contains("utilization"),
        "Grok observe must not invent utilization:0 or other numeric quota"
    );
    assert!(
        !json.contains(r#""snapshots":[]"#),
        "empty quota must be unknown, not an observed empty snapshot list"
    );

    let quota = result.quota.expect("quota category");
    assert_eq!(quota.outcome, ObservationOutcome::Unknown);
    assert!(quota.content.is_none());

    let models = result.models.expect("models category");
    assert_eq!(models.outcome, ObservationOutcome::Unknown);
    assert!(models.content.is_none());

    let auth = result.auth.expect("auth category");
    assert_eq!(auth.outcome, ObservationOutcome::Unavailable);
}

#[test]
fn grok_observe_refuses_stale_binding_without_auto_select() {
    let (_dir, adapter, registry) = grok_fixture();
    let binding = registry
        .select_complete_revision("grok-cli", GROK_ACCOUNT, None)
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
    .expect_err("stale Grok binding must fail closed");

    assert!(matches!(error, Error::StaleSelection { .. }));
}

#[test]
fn github_copilot_observe_reports_unknown_quota_and_models_without_invented_utilization() {
    let (_dir, adapter, registry) = github_copilot_fixture();
    registry
        .begin_add(
            "github-copilot",
            "work",
            "Work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin add");
    registry
        .complete_add("github-copilot", "work")
        .expect("complete add");
    let binding = registry
        .select_complete_revision("github-copilot", "work", None)
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
fn github_copilot_observe_refuses_stale_binding_without_auto_select() {
    let (_dir, adapter, registry) = github_copilot_fixture();
    registry
        .begin_add(
            "github-copilot",
            "work",
            "Work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("begin add");
    registry
        .complete_add("github-copilot", "work")
        .expect("complete add");
    let binding = registry
        .select_complete_revision("github-copilot", "work", None)
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
