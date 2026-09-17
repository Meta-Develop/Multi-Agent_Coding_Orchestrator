//! Cursor read-only acceptance tests.
//!
//! Every adapter instance is rooted at a `TempDir`. In particular, an injected
//! home with no fixture CLI must not fall back to the host `PATH` and execute a
//! real `cursor-agent` installation.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::model::{AuthKind, InstallState, Maturity};
use coding_agent_manager_lib::providers::cursor::CursorAdapter;
use coding_agent_manager_lib::providers::ProviderAdapter;

const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cursor");

#[test]
fn fixture_install_is_detected_and_lists_without_reading_a_real_home() {
    let home = staged_home();
    let adapter = CursorAdapter::with_home(home.path());
    let before = tree_snapshot(home.path());

    assert_eq!(adapter.detect(), InstallState::Installed);
    let accounts = adapter.list_accounts().expect("read-only listing");
    let expected: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(Path::new(FIXTURE_ROOT).join("expected/accounts.json"))
            .expect("expected accounts"),
    )
    .expect("expected JSON");
    assert_eq!(
        serde_json::to_value(accounts).expect("accounts JSON"),
        expected
    );
    assert_eq!(
        tree_snapshot(home.path()),
        before,
        "listing mutated the fixture"
    );
}

#[test]
fn empty_injected_home_does_not_detect_or_run_the_host_installation() {
    let home = tempfile::tempdir().expect("tempdir");
    let adapter = CursorAdapter::with_home(home.path());

    assert_eq!(adapter.detect(), InstallState::NotInstalled);
    assert!(adapter.list_accounts().expect("empty listing").is_empty());
}

#[test]
fn descriptor_and_methods_advertise_read_only_reality() {
    let home = staged_home();
    let adapter = CursorAdapter::with_home(home.path());
    let descriptor = adapter.descriptor();
    let before = tree_snapshot(home.path());

    assert_eq!(descriptor.maturity, Maturity::Experimental);
    assert_eq!(
        descriptor.auth_kinds,
        vec![AuthKind::Unknown, AuthKind::ApiKey]
    );
    assert!(descriptor.capabilities.is_empty());
    assert!(matches!(
        adapter.add_account("work"),
        Err(Error::NotImplemented(_))
    ));
    assert!(matches!(
        adapter.activate_account("work"),
        Err(Error::NotImplemented("cursor::activate_account"))
    ));
    assert!(matches!(
        adapter.delete_account("work"),
        Err(Error::NotImplemented(_))
    ));
    assert_eq!(
        tree_snapshot(home.path()),
        before,
        "a write stub mutated the fixture"
    );
}

#[test]
fn every_reported_config_path_stays_under_the_injected_home() {
    let home = staged_home();
    let paths = CursorAdapter::with_home(home.path()).config_paths();

    assert_eq!(paths.len(), 2);
    assert!(paths.iter().all(|path| path.starts_with(home.path())));
    assert!(paths.contains(&home.path().join(".config/cursor/cli-config.json")));
    assert!(paths.contains(&home.path().join(".cursor")));
}

fn staged_home() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("tempdir");
    copy_tree(&Path::new(FIXTURE_ROOT).join("home"), temp.path());
    temp
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let destination = destination.join(entry.file_name());
        if entry.file_type().expect("fixture file type").is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("copy fixture file");
        }
    }
}

fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn collect(root: &Path, path: &Path, snapshot: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let relative = path
            .strip_prefix(root)
            .expect("path under root")
            .to_path_buf();
        if path.is_dir() {
            snapshot.insert(relative, None);
            for entry in fs::read_dir(path).expect("read snapshot directory") {
                collect(root, &entry.expect("snapshot entry").path(), snapshot);
            }
        } else {
            snapshot.insert(relative, Some(fs::read(path).expect("read snapshot file")));
        }
    }

    let mut snapshot = BTreeMap::new();
    collect(root, root, &mut snapshot);
    snapshot
}
