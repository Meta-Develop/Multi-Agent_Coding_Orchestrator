//! Integration coverage for Claude Code OAuth add, list, switch, and delete.
//!
//! These tests compile the library without `cfg(test)`, so they drive only the
//! public adapter hooks (`with_home`, `with_data_dir`, `with_login_runner`,
//! `with_tool_running`). Fault injection stays in the unit suite.

use std::fs;
use std::path::Path;

use coding_agent_manager_lib::backup::BackupStore;
use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::model::{AuthKind, ProviderCapability};
use coding_agent_manager_lib::providers::claude_code::ClaudeCodeAdapter;
use coding_agent_manager_lib::providers::ProviderAdapter;

const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/claude-code");
const FAKE_PREFIX: &str = "FAKE-";
const ACCOUNT: &str = "acct-work";

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap_or_else(|error| {
        panic!("create {}: {error}", dst.display());
    });
    for entry in fs::read_dir(src).unwrap_or_else(|error| {
        panic!("read_dir {}: {error}", src.display());
    }) {
        let entry = entry.expect("dirent");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap_or_else(|error| {
                panic!(
                    "copy {} -> {}: {error}",
                    entry.path().display(),
                    to.display()
                );
            });
        }
    }
}

fn staged(name: &str) -> tempfile::TempDir {
    let src = Path::new(FIXTURE_ROOT).join(name);
    let temp = tempfile::tempdir().expect("tempdir");
    copy_tree(&src, temp.path());
    temp
}

fn login_writes_managed_oauth(dir: &Path) -> std::io::Result<i32> {
    copy_tree(&Path::new(FIXTURE_ROOT).join("managed-oauth"), dir);
    Ok(0)
}

fn login_must_not_run(_dir: &Path) -> std::io::Result<i32> {
    panic!("claude auth login must not run");
}

fn assert_no_fake(where_: &str, text: &str) {
    assert!(
        !text.contains(FAKE_PREFIX),
        "{where_} leaked fixture secret material: {text}"
    );
}

fn read_object(path: &Path) -> serde_json::Map<String, serde_json::Value> {
    serde_json::from_str(&fs::read_to_string(path).expect("read")).expect("json object")
}

fn adapter(home: &Path, data: &Path) -> ClaudeCodeAdapter {
    ClaudeCodeAdapter::with_home(home)
        .with_data_dir(data)
        .with_tool_running(false)
        .with_login_runner(login_must_not_run)
}

#[test]
fn add_list_switch_delete_round_trip() {
    let live = staged("switch-live");
    let data = tempfile::tempdir().expect("data");
    let before_identity = read_object(&live.path().join(".claude.json"));
    let before_settings = fs::read(live.path().join(".claude/settings.json")).expect("settings");
    let before_session = fs::read(live.path().join(".claude/projects/keep.json")).expect("session");

    adapter(live.path(), data.path())
        .with_login_runner(login_writes_managed_oauth)
        .add_account(ACCOUNT)
        .expect("add");

    let listed = adapter(live.path(), data.path())
        .list_accounts()
        .expect("list after add");
    let stored = listed
        .iter()
        .find(|account| account.id == ACCOUNT)
        .expect("stored");
    assert!(stored.is_stored);
    assert!(!stored.is_active);
    assert_eq!(stored.auth_kind, AuthKind::OAuth);
    assert_eq!(stored.masked_identity.as_deref(), Some("****0002"));
    assert!(listed
        .iter()
        .any(|account| account.id == "claude-code-on-disk"));
    let json = serde_json::to_string(&listed).expect("json");
    assert!(!json.contains('@'), "email leaked: {json}");
    assert_no_fake("list after add", &json);

    adapter(live.path(), data.path())
        .activate_account(ACCOUNT)
        .expect("switch");

    let after_identity = read_object(&live.path().join(".claude.json"));
    let after_credentials = read_object(&live.path().join(".claude/.credentials.json"));
    let stored_oauth = read_object(
        &data
            .path()
            .join("accounts/claude-code")
            .join(ACCOUNT)
            .join(".credentials.json"),
    );
    let stored_identity = read_object(
        &data
            .path()
            .join("accounts/claude-code")
            .join(ACCOUNT)
            .join(".claude.json"),
    );
    assert_eq!(
        after_credentials.get("claudeAiOauth"),
        stored_oauth.get("claudeAiOauth")
    );
    assert_eq!(
        after_identity.get("oauthAccount"),
        stored_identity.get("oauthAccount")
    );
    for key in [
        "userID",
        "machineID",
        "mcpServers",
        "projects",
        "cachedUsageUtilization",
        "futureIdentityKey",
    ] {
        assert_eq!(before_identity.get(key), after_identity.get(key), "{key}");
    }
    assert_eq!(
        fs::read(live.path().join(".claude/settings.json")).expect("settings after"),
        before_settings
    );
    assert_eq!(
        fs::read(live.path().join(".claude/projects/keep.json")).expect("session after"),
        before_session
    );

    let after_switch = adapter(live.path(), data.path())
        .list_accounts()
        .expect("list after switch");
    let active = after_switch
        .iter()
        .find(|account| account.id == ACCOUNT)
        .expect("active stored");
    assert!(active.is_active);
    assert!(after_switch
        .iter()
        .all(|account| account.id != "claude-code-on-disk"));

    adapter(live.path(), data.path())
        .delete_account(ACCOUNT)
        .expect("delete");
    assert!(fs::symlink_metadata(data.path().join("accounts/claude-code").join(ACCOUNT)).is_err());
    let after_delete = adapter(live.path(), data.path())
        .list_accounts()
        .expect("list after delete");
    assert!(after_delete.iter().all(|account| account.id != ACCOUNT));
    assert!(after_identity.get("oauthAccount").is_some());
}

#[test]
fn descriptor_advertises_oauth_add_switch_and_delete() {
    let home = tempfile::tempdir().expect("home");
    let descriptor = ClaudeCodeAdapter::with_home(home.path()).descriptor();
    assert_eq!(
        descriptor.capabilities,
        vec![
            ProviderCapability::AddAccount,
            ProviderCapability::SwitchAccount,
            ProviderCapability::DeleteAccount,
        ]
    );
    assert_eq!(
        descriptor.auth_kinds,
        vec![AuthKind::OAuth, AuthKind::ApiKey]
    );
}

#[test]
fn list_accounts_restores_a_journaled_pair() {
    let live = staged("switch-live");
    let data = tempfile::tempdir().expect("data");
    let credentials = live.path().join(".claude/.credentials.json");
    let identity = live.path().join(".claude.json");
    let before_credentials = fs::read(&credentials).expect("credentials");
    let before_identity = fs::read(&identity).expect("identity");

    let store = BackupStore::new(data.path().join("backups"));
    let backup = store
        .snapshot(
            "claude-code",
            &[
                credentials.clone(),
                identity.clone(),
                live.path().join(".claude/settings.json"),
            ],
        )
        .expect("snapshot");
    fs::write(
        &credentials,
        r#"{"claudeAiOauth":{"accessToken":"FAKE-partial"}}"#,
    )
    .expect("partial credentials");
    fs::write(&identity, r#"{"oauthAccount":{},"userID":"FAKE-partial"}"#)
        .expect("partial identity");

    let journal = data.path().join("claude-code/switch.journal");
    fs::create_dir_all(journal.parent().expect("journal parent")).expect("journal dir");
    fs::write(
        &journal,
        format!(
            "{{\"schema_version\":1,\"backup_id\":\"{}\"}}\n",
            backup.as_str()
        ),
    )
    .expect("journal");

    let accounts = adapter(live.path(), data.path())
        .list_accounts()
        .expect("recover");
    assert_eq!(
        fs::read(&credentials).expect("restored credentials"),
        before_credentials
    );
    assert_eq!(
        fs::read(&identity).expect("restored identity"),
        before_identity
    );
    assert!(fs::symlink_metadata(&journal).is_err());
    assert!(accounts.iter().any(|account| account.is_active));
    assert_no_fake(
        "integration recover list",
        &serde_json::to_string(&accounts).expect("json"),
    );
}

#[test]
fn activate_account_refuses_an_unsafe_id() {
    let live = staged("switch-live");
    let data = tempfile::tempdir().expect("data");
    let error = adapter(live.path(), data.path())
        .activate_account("../etc")
        .expect_err("unsafe");
    assert!(
        matches!(error, Error::UnknownAccount(ref id) if id == "../etc"),
        "{error:?}"
    );
}
