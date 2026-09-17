use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

use coding_agent_manager_lib::model::{
    AuthKind, StoredAccountMaterial, StoredAccountMetadata, StoredAccountState,
};
use coding_agent_manager_lib::paths::stored_accounts_path;
use coding_agent_manager_lib::providers::grok_cli::GrokCliAdapter;
#[cfg(unix)]
use coding_agent_manager_lib::providers::spawn_launch;
use coding_agent_manager_lib::providers::{
    add_managed_account, delete_managed_account, launch_spec_for, select_launch_account,
    ProviderAdapter, StoredAccountRegistry,
};
use fs2::FileExt;

const ACCOUNT: &str = "work";
const SIBLING: &str = "personal";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/grok")
        .join(name)
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture destination");
    for entry in fs::read_dir(source).expect("read fixture source") {
        let entry = entry.expect("fixture entry");
        let target = destination.join(entry.file_name());
        let kind = entry.file_type().expect("fixture file type");
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            fs::copy(entry.path(), target).expect("copy fixture file");
        } else {
            panic!("fixture contains a non-regular entry");
        }
    }
}

fn tree_bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, current: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(current)
            .expect("read tree")
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("tree entries");
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let kind = entry.file_type().expect("tree file type");
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("relative tree path")
                .to_path_buf();
            if kind.is_dir() {
                visit(root, &entry.path(), out);
            } else if kind.is_file() {
                out.insert(relative, fs::read(entry.path()).expect("read tree file"));
            } else {
                panic!("test tree contains a non-regular entry");
            }
        }
    }

    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}

fn fake_login(home: &Path) -> io::Result<i32> {
    fs::copy(fixture_path("valid-auth.json"), home.join("auth.json"))?;
    Ok(0)
}

fn panic_login(_home: &Path) -> io::Result<i32> {
    panic!("a structurally complete pending home must not run login again")
}

fn empty_login(home: &Path) -> io::Result<i32> {
    fs::write(home.join("auth.json"), b"{}")?;
    Ok(0)
}

fn reserved_only_login(home: &Path) -> io::Result<i32> {
    fs::write(
        home.join("auth.json"),
        br#"{"xai::api_key":{"key":"FAKE-reserved-key"}}"#,
    )?;
    Ok(0)
}

fn malformed_oauth_login(home: &Path) -> io::Result<i32> {
    fs::write(
        home.join("auth.json"),
        br#"{"https://auth.example.invalid::FAKE-client":"FAKE-not-an-object"}"#,
    )?;
    Ok(0)
}

struct Fixture {
    _root: tempfile::TempDir,
    user_home: PathBuf,
    data_dir: PathBuf,
    cwd: PathBuf,
    registry: StoredAccountRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tempdir");
        let user_home = root.path().join("user-home");
        let data_dir = root.path().join("data");
        let cwd = root.path().join("workspace");
        fs::create_dir_all(user_home.join(".grok")).expect("create default home");
        copy_tree(&fixture_path("default-home"), &user_home.join(".grok"));
        fs::create_dir_all(&cwd).expect("create cwd");
        let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
        Self {
            _root: root,
            user_home,
            data_dir,
            cwd,
            registry,
        }
    }

    fn adapter(&self) -> GrokCliAdapter {
        GrokCliAdapter::with_home(&self.user_home)
            .with_data_dir(&self.data_dir)
            .with_working_directory(&self.cwd)
            .with_program("/bin/true")
            .with_login_runner(fake_login)
    }

    fn home(&self, account_id: &str) -> PathBuf {
        self.data_dir
            .join("accounts")
            .join("grok-cli")
            .join(account_id)
    }

    fn add(&self, adapter: &GrokCliAdapter, account_id: &str) {
        add_managed_account(&self.registry, adapter, account_id, account_id, None)
            .expect("add Grok fixture account");
    }
}

fn selected_metadata(account_id: &str) -> StoredAccountMetadata {
    StoredAccountMetadata {
        id: account_id.to_string(),
        provider_id: "grok-cli".to_string(),
        label: account_id.to_string(),
        auth_kind: AuthKind::OAuth,
        state: StoredAccountState::Complete,
        material: StoredAccountMaterial::VendorHome,
        is_selected: true,
    }
}

#[test]
fn activation_and_launch_preparation_leave_default_and_sibling_homes_byte_identical() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture.add(&adapter, SIBLING);
    fixture.add(&adapter, ACCOUNT);
    fs::copy(
        fixture_path("sibling-home/auth.json"),
        fixture.home(SIBLING).join("auth.json"),
    )
    .expect("stage sibling fixture auth");
    fs::write(
        fixture.home(SIBLING).join("sibling-marker"),
        b"FAKE-sibling-state",
    )
    .expect("write sibling marker");

    let default_before = tree_bytes(&fixture.user_home.join(".grok"));
    let sibling_before = tree_bytes(&fixture.home(SIBLING));
    let work_auth_before = fs::read(fixture.home(ACCOUNT).join("auth.json")).expect("work auth");

    select_launch_account(&fixture.registry, &adapter, ACCOUNT).expect("select account");
    let selected = fixture
        .registry
        .selected("grok-cli")
        .expect("read selection")
        .expect("selected metadata");
    launch_spec_for(&adapter, &selected).expect("prepare launch");

    assert_eq!(tree_bytes(&fixture.user_home.join(".grok")), default_before);
    assert_eq!(tree_bytes(&fixture.home(SIBLING)), sibling_before);
    assert_eq!(
        fs::read(fixture.home(ACCOUNT).join("auth.json")).expect("work auth after"),
        work_auth_before
    );
    assert_ne!(
        fs::read(fixture.user_home.join(".grok/auth.json")).expect("default auth"),
        work_auth_before,
        "the managed auth file must not be copied from the default home"
    );
}

#[cfg(unix)]
#[test]
fn launched_child_receives_exact_derived_home_and_absolute_cwd() {
    use std::os::unix::fs::PermissionsExt;

    const CHILD_MARKER: &str = "CAM_GROK_ENV_TEST_CHILD";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let status = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("launched_child_receives_exact_derived_home_and_absolute_cwd")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env("GROK_AUTH_PATH", "FAKE-inherited-override")
            .status()
            .expect("spawn hermetic environment test child");
        assert!(status.success(), "environment test child failed: {status}");
        return;
    }

    let fixture = Fixture::new();
    let output = fixture.data_dir.join("launch-observation.txt");
    let script = fixture.data_dir.join("grok-fixture");
    coding_agent_manager_lib::fsx::create_dir_all_private(&fixture.data_dir).expect("data dir");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s\\n%s\\n%s\\n' \"$GROK_HOME\" \"${{GROK_AUTH_PATH+x}}\" \"$PWD\" > '{}'\n",
            output.display()
        ),
    )
    .expect("write launch fixture");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod fixture");

    let adapter = GrokCliAdapter::with_home(&fixture.user_home)
        .with_data_dir(&fixture.data_dir)
        .with_working_directory(&fixture.cwd)
        .with_program(&script)
        .with_login_runner(fake_login);
    fixture.add(&adapter, ACCOUNT);
    select_launch_account(&fixture.registry, &adapter, ACCOUNT).expect("select account");
    let selected = fixture
        .registry
        .selected("grok-cli")
        .expect("selection")
        .expect("selected");
    let status = spawn_launch(
        launch_spec_for(&adapter, &selected).expect("launch spec"),
        &selected,
        None,
    )
    .expect("spawn Grok fixture")
    .wait()
    .expect("wait for Grok fixture");
    assert!(status.success());

    let observed = fs::read_to_string(output).expect("read observation");
    let lines = observed.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], fixture.home(ACCOUNT).to_string_lossy());
    assert_eq!(
        lines[1], "",
        "inherited GROK_AUTH_PATH must be removed from the actual child"
    );
    let expected_cwd = fixture.cwd.canonicalize().expect("canonical workspace");
    assert_eq!(lines[2], expected_cwd.to_string_lossy());
}

#[test]
fn held_vendor_auth_lock_refuses_selection_launch_and_delete() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture.add(&adapter, ACCOUNT);
    let lock_path = fixture.home(ACCOUNT).join("auth.json.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .expect("open fixture lock");
    lock.lock_exclusive().expect("hold fixture lock");

    assert!(select_launch_account(&fixture.registry, &adapter, ACCOUNT).is_err());
    fixture
        .registry
        .select_complete("grok-cli", ACCOUNT)
        .expect("seed selected metadata without adapter validation");
    let selected = fixture
        .registry
        .selected("grok-cli")
        .expect("selection")
        .expect("selected");
    assert!(launch_spec_for(&adapter, &selected).is_err());
    assert!(delete_managed_account(&fixture.registry, &adapter, ACCOUNT, None).is_err());
    assert!(fixture.home(ACCOUNT).join("auth.json").is_file());
    assert!(fixture.registry.account("grok-cli", ACCOUNT).is_ok());
}

#[test]
fn live_session_refuses_and_definitely_dead_session_allows_selection() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture.add(&adapter, ACCOUNT);
    let sessions = fixture.home(ACCOUNT).join("active_sessions.json");
    fs::write(
        &sessions,
        serde_json::to_vec(&serde_json::json!([{
            "session_id": "FAKE-live-session",
            "pid": std::process::id(),
            "cwd": fixture.cwd,
            "opened_at": "2099-01-01T00:00:00Z"
        }]))
        .expect("live session JSON"),
    )
    .expect("write live session");
    assert!(select_launch_account(&fixture.registry, &adapter, ACCOUNT).is_err());

    #[cfg(target_os = "linux")]
    {
        fs::write(
            &sessions,
            serde_json::to_vec(&serde_json::json!([{
                "session_id": "FAKE-dead-session",
                "pid": 2_000_000_000_u32,
                "cwd": "/tmp/FAKE-dead-session",
                "opened_at": "2099-01-01T00:00:00Z"
            }]))
            .expect("dead session JSON"),
        )
        .expect("write dead session");
        select_launch_account(&fixture.registry, &adapter, ACCOUNT)
            .expect("definitely dead Linux PID is not active");
    }
}

#[test]
fn malformed_session_registry_fails_closed() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture.add(&adapter, ACCOUNT);
    fs::write(
        fixture.home(ACCOUNT).join("active_sessions.json"),
        br#"[{"session_id":"FAKE-missing-fields"}]"#,
    )
    .expect("write malformed session");
    assert!(select_launch_account(&fixture.registry, &adapter, ACCOUNT).is_err());
    assert!(fixture.registry.selected("grok-cli").unwrap().is_none());
}

#[test]
fn parsed_empty_session_array_allows_but_zero_length_file_refuses() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture.add(&adapter, ACCOUNT);
    let sessions = fixture.home(ACCOUNT).join("active_sessions.json");
    fs::write(&sessions, b"[]").expect("write empty session array");
    select_launch_account(&fixture.registry, &adapter, ACCOUNT)
        .expect("parsed empty array has no active sessions");

    fs::write(&sessions, b"").expect("write zero-length session file");
    assert!(launch_spec_for(
        &adapter,
        &fixture
            .registry
            .selected("grok-cli")
            .expect("selection")
            .expect("selected account")
    )
    .is_err());
}

#[test]
fn path_escape_and_non_directory_home_fail_before_launch() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    let escaped = selected_metadata("../escape");
    assert!(launch_spec_for(&adapter, &escaped).is_err());

    fixture
        .registry
        .begin_add(
            "grok-cli",
            ACCOUNT,
            ACCOUNT,
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("pending metadata");
    fixture
        .registry
        .complete_add("grok-cli", ACCOUNT)
        .expect("complete metadata");
    fs::create_dir_all(fixture.home(ACCOUNT).parent().unwrap()).expect("provider parent");
    fs::write(fixture.home(ACCOUNT), b"FAKE-not-a-directory").expect("non-directory home");
    assert!(select_launch_account(&fixture.registry, &adapter, ACCOUNT).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_managed_home_is_refused_without_following_it() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture
        .registry
        .begin_add(
            "grok-cli",
            ACCOUNT,
            ACCOUNT,
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("pending metadata");
    fixture
        .registry
        .complete_add("grok-cli", ACCOUNT)
        .expect("complete metadata");
    let outside = fixture._root.path().join("outside");
    fs::create_dir_all(&outside).expect("outside");
    fs::create_dir_all(fixture.home(ACCOUNT).parent().unwrap()).expect("provider parent");
    symlink(&outside, fixture.home(ACCOUNT)).expect("symlink home");
    assert!(select_launch_account(&fixture.registry, &adapter, ACCOUNT).is_err());
    assert!(tree_bytes(&outside).is_empty());
}

#[test]
fn complete_pending_home_is_revalidated_without_second_login() {
    let fixture = Fixture::new();
    let adapter = GrokCliAdapter::with_home(&fixture.user_home)
        .with_data_dir(&fixture.data_dir)
        .with_working_directory(&fixture.cwd)
        .with_program("/bin/true")
        .with_login_runner(panic_login);
    let pending = fixture
        .registry
        .begin_add(
            "grok-cli",
            ACCOUNT,
            ACCOUNT,
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .expect("pending metadata");
    coding_agent_manager_lib::fsx::create_dir_all_private(&fixture.home(ACCOUNT))
        .expect("pending home");
    fs::copy(
        fixture_path("valid-auth.json"),
        fixture.home(ACCOUNT).join("auth.json"),
    )
    .expect("pending auth");

    assert!(adapter
        .provision_stored_account(&pending)
        .expect("revalidate pending home")
        .is_none());
    assert_eq!(
        fixture
            .registry
            .account("grok-cli", ACCOUNT)
            .expect("pending remains for core")
            .state,
        StoredAccountState::Pending
    );
}

#[test]
fn delete_forgets_metadata_and_retains_vendor_home() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture.add(&adapter, ACCOUNT);
    let before = tree_bytes(&fixture.home(ACCOUNT));

    delete_managed_account(&fixture.registry, &adapter, ACCOUNT, None).expect("forget account");

    assert_eq!(tree_bytes(&fixture.home(ACCOUNT)), before);
    assert!(fixture
        .registry
        .load()
        .expect("metadata after delete")
        .is_empty());
}

#[test]
fn stored_rows_are_never_active_and_selection_is_launch_scoped() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture.add(&adapter, ACCOUNT);
    select_launch_account(&fixture.registry, &adapter, ACCOUNT).expect("select account");

    let accounts = adapter.list_accounts().expect("list accounts");
    let stored = accounts
        .iter()
        .find(|account| account.id == ACCOUNT)
        .expect("stored account row");
    assert!(stored.is_stored);
    assert!(!stored.is_active);
    assert!(stored.is_selected_for_launch);
    assert!(!stored.is_incomplete);
    assert!(accounts
        .iter()
        .filter(|account| !account.is_stored)
        .all(|account| !account.is_selected_for_launch && !account.is_active));
}

#[test]
fn tampered_material_binding_is_incomplete_and_never_launch_selected() {
    let fixture = Fixture::new();
    let adapter = fixture.adapter();
    fixture
        .registry
        .begin_add(
            "grok-cli",
            ACCOUNT,
            ACCOUNT,
            AuthKind::ApiKey,
            StoredAccountMaterial::CredentialStore,
        )
        .expect("write mismatched metadata");
    fixture
        .registry
        .complete_add("grok-cli", ACCOUNT)
        .expect("complete mismatched metadata");
    fixture
        .registry
        .select_complete("grok-cli", ACCOUNT)
        .expect("select mismatched metadata");

    let accounts = adapter.list_accounts().expect("list accounts");
    let stored = accounts
        .iter()
        .find(|account| account.id == ACCOUNT)
        .expect("stored mismatch row");
    assert!(stored.is_stored);
    assert!(stored.is_incomplete);
    assert!(!stored.is_active);
    assert!(!stored.is_selected_for_launch);
}

#[test]
fn provisioning_refuses_empty_reserved_only_and_malformed_oauth_auth_objects() {
    for (account_id, runner) in [
        ("empty", empty_login as fn(&Path) -> io::Result<i32>),
        (
            "reserved",
            reserved_only_login as fn(&Path) -> io::Result<i32>,
        ),
        (
            "malformed",
            malformed_oauth_login as fn(&Path) -> io::Result<i32>,
        ),
    ] {
        let fixture = Fixture::new();
        let adapter = GrokCliAdapter::with_home(&fixture.user_home)
            .with_data_dir(&fixture.data_dir)
            .with_working_directory(&fixture.cwd)
            .with_program("/bin/true")
            .with_login_runner(runner);
        let error = add_managed_account(&fixture.registry, &adapter, account_id, account_id, None)
            .expect_err("non-OAuth auth object must not complete");
        assert!(!error.to_string().contains("FAKE-"));
        let metadata = fixture
            .registry
            .account("grok-cli", account_id)
            .expect("failed provisioning remains recoverable");
        assert_eq!(metadata.state, StoredAccountState::Pending);
        assert!(!metadata.is_selected);
    }
}
