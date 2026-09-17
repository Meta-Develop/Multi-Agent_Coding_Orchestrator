//! Cross-process stored-account authority foundation tests.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use coding_agent_manager_lib::account_authority::test_worker::WORKER_ENV;
use coding_agent_manager_lib::account_authority::StoredAccountRegistry;
use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial, StoredAccountState};
use coding_agent_manager_lib::paths::stored_accounts_path;
use coding_agent_manager_lib::storage::{CredentialStore, Secret, SecretRef};

struct FakeStore {
    fail_put: AtomicBool,
}

impl CredentialStore for FakeStore {
    fn id(&self) -> &'static str {
        "fake"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn put(
        &self,
        _key: &SecretRef,
        _secret: &Secret,
    ) -> coding_agent_manager_lib::error::Result<()> {
        if self.fail_put.load(Ordering::SeqCst) {
            return Err(
                coding_agent_manager_lib::error::Error::CredentialStoreUnavailable(
                    "fixture put failure".to_string(),
                ),
            );
        }
        Ok(())
    }

    fn get(&self, _key: &SecretRef) -> coding_agent_manager_lib::error::Result<Option<Secret>> {
        Ok(None)
    }

    fn delete(&self, _key: &SecretRef) -> coding_agent_manager_lib::error::Result<()> {
        Ok(())
    }
}

fn registry_path(dir: &tempfile::TempDir) -> PathBuf {
    stored_accounts_path(dir.path())
}

fn selection_revision_on_disk(path: &PathBuf, provider: &str) -> u64 {
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("read metadata")).expect("json");
    document
        .get("selectionRevisions")
        .and_then(|map| map.get(provider))
        .and_then(|value| value.as_u64())
        .unwrap_or(0)
}

fn seed_v1_fixture(path: &PathBuf) {
    fs::write(
        path,
        concat!(
            r#"{"schemaVersion":1,"accounts":[{"id":"work","providerId":"gemini-cli","label":"Work Account","authKind":"api-key","state":"complete","material":"credential-store","isSelected":true},{"id":"personal","providerId":"gemini-cli","label":"Personal","authKind":"api-key","state":"pending","material":"credential-store","isSelected":false}]}"#,
            "\n"
        ),
    )
    .expect("write v1 fixture");
}

fn add_complete(registry: &StoredAccountRegistry, provider: &str, id: &str) {
    registry
        .begin_add(
            provider,
            id,
            id,
            AuthKind::ApiKey,
            StoredAccountMaterial::CredentialStore,
        )
        .expect("begin");
    registry.complete_add(provider, id).expect("complete");
}

#[test]
fn v1_migration_preserves_identity_without_touching_secrets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = registry_path(&dir);
    seed_v1_fixture(&path);
    let registry = StoredAccountRegistry::new(&path);
    let accounts = registry.load().expect("load migrated");
    assert_eq!(accounts.len(), 2);
    let work = accounts.iter().find(|a| a.id == "work").expect("work");
    assert_eq!(work.label, "Work Account");
    assert_eq!(work.state, StoredAccountState::Complete);
    assert!(work.is_selected);
    assert_eq!(work.account_incarnation.len(), 32);
    let text = fs::read_to_string(&path).expect("migrated json");
    assert!(text.contains(r#""schemaVersion": 2"#));
    assert!(text.contains(r#""selectionRevisions""#));
    assert_eq!(selection_revision_on_disk(&path, "gemini-cli"), 1);
    assert!(!text.contains("FAKE-"));
}

#[test]
fn selected_binding_is_stable_across_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = registry_path(&dir);
    let registry = StoredAccountRegistry::new(&path);
    add_complete(&registry, "gemini-cli", "work");
    let binding = registry
        .select_complete_revision("gemini-cli", "work", None)
        .expect("select");
    let reopened = StoredAccountRegistry::new(&path);
    assert_eq!(
        reopened
            .selected_binding("gemini-cli")
            .expect("binding")
            .expect("selected"),
        binding
    );
}

#[test]
fn changed_selection_stales_old_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(registry_path(&dir));
    add_complete(&registry, "gemini-cli", "work");
    add_complete(&registry, "gemini-cli", "personal");
    let first = registry
        .select_complete_revision("gemini-cli", "work", None)
        .expect("select work");
    registry
        .select_complete_revision("gemini-cli", "personal", None)
        .expect("select personal");
    let error = registry
        .acquire_selected_use(&first)
        .err()
        .expect("stale binding");
    assert!(matches!(error, Error::StaleSelection { .. }));
}

#[test]
fn unrelated_provider_selection_does_not_stale_binding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(registry_path(&dir));
    add_complete(&registry, "gemini-cli", "work");
    add_complete(&registry, "grok-cli", "work");
    let gemini = registry
        .select_complete_revision("gemini-cli", "work", None)
        .expect("select gemini");
    registry
        .select_complete_revision("grok-cli", "work", None)
        .expect("select grok");
    let _lease = registry
        .acquire_selected_use(&gemini)
        .expect("gemini binding still valid");
}

#[test]
fn rejects_unsafe_incarnation_in_v2_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = registry_path(&dir);
    fs::write(
        &path,
        format!(
            concat!(
                r#"{{"schemaVersion":2,"selectionRevisions":{{}},"accounts":[{{"id":"work","providerId":"gemini-cli","label":"Work","authKind":"api-key","state":"complete","material":"credential-store","isSelected":false,"accountIncarnation":"{}"}}]}}"#,
                "\n"
            ),
            "../escape"
        ),
    )
    .expect("write malicious metadata");
    assert!(StoredAccountRegistry::new(&path).load().is_err());
}

#[test]
fn delete_and_recreate_same_id_changes_incarnation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registry = StoredAccountRegistry::new(registry_path(&dir));
    let store = FakeStore {
        fail_put: AtomicBool::new(false),
    };
    registry
        .add_with_secret(
            "gemini-cli",
            "work",
            "Work",
            AuthKind::ApiKey,
            &Secret::new(b"FAKE-not-in-metadata".to_vec()),
            &store,
        )
        .expect("add");
    let first = registry
        .account("gemini-cli", "work")
        .expect("account")
        .account_incarnation;
    registry
        .delete("gemini-cli", "work", Some(&store))
        .expect("delete");
    registry
        .add_with_secret(
            "gemini-cli",
            "work",
            "Work",
            AuthKind::ApiKey,
            &Secret::new(b"FAKE-not-in-metadata".to_vec()),
            &store,
        )
        .expect("re-add");
    let second = registry
        .account("gemini-cli", "work")
        .expect("account")
        .account_incarnation;
    assert_ne!(first, second);
}

#[test]
fn failed_select_does_not_advance_revision() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = registry_path(&dir);
    let registry = StoredAccountRegistry::new(&path);
    add_complete(&registry, "gemini-cli", "work");
    registry
        .select_complete("gemini-cli", "work")
        .expect("initial select");
    let before = selection_revision_on_disk(&path, "gemini-cli");
    assert_eq!(before, 1);
    registry
        .select_complete("gemini-cli", "missing")
        .expect_err("unknown account");
    assert_eq!(selection_revision_on_disk(&path, "gemini-cli"), before);
}

fn batch_account_ids(slot: u8) -> Vec<String> {
    (0..8)
        .map(|index| format!("batch-a{slot}-{index:02}"))
        .collect()
}

fn wait_for_ready_files(paths: &[PathBuf], deadline: Instant) {
    for path in paths {
        while !path.is_file() {
            if Instant::now() > deadline {
                panic!("timed out waiting for child ready at {}", path.display());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn wait_for_children(
    children: &mut [std::process::Child],
    done_paths: &[PathBuf],
    deadline: Instant,
) {
    for path in done_paths {
        while !path.is_file() {
            if Instant::now() > deadline {
                for child in children.iter_mut() {
                    let _ = child.kill();
                }
                panic!(
                    "timed out waiting for child completion at {}",
                    path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    for child in children {
        let status = child.wait().expect("wait for child");
        assert!(status.success(), "child exited with failure: {status}");
    }
}

fn spawn_concurrent_batch_child(
    exe: &std::path::Path,
    test_name: &str,
    path: &PathBuf,
    sync_dir: &PathBuf,
    slot: u8,
) -> std::process::Child {
    Command::new(exe)
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env(WORKER_ENV, "concurrent_batch_add")
        .env("CAM_REGISTRY_PATH", path)
        .env("CAM_PROVIDER_ID", "gemini-cli")
        .env("CAM_SYNC_DIR", sync_dir)
        .env("CAM_WORKER_SLOT", slot.to_string())
        .spawn()
        .expect("spawn concurrent batch child")
}

#[cfg(unix)]
#[test]
fn separate_process_concurrent_selections_both_persist() {
    if coding_agent_manager_lib::account_authority::test_worker::run_from_env() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = registry_path(&dir);
    let sync_dir = dir.path().join("concurrent-sync");
    fs::create_dir_all(&sync_dir).expect("sync dir");
    let ready_paths = [sync_dir.join("ready-0"), sync_dir.join("ready-1")];
    let done_paths = [sync_dir.join("done-0"), sync_dir.join("done-1")];
    let start_barrier = sync_dir.join("start");

    let registry = StoredAccountRegistry::new(&path);
    add_complete(&registry, "gemini-cli", "work");
    add_complete(&registry, "gemini-cli", "personal");
    registry
        .select_complete("gemini-cli", "work")
        .expect("seed selection");
    let baseline_revision = selection_revision_on_disk(&path, "gemini-cli");
    let baseline_selected = registry
        .selected("gemini-cli")
        .expect("selected")
        .expect("seed selected")
        .id
        .clone();
    let work_label = registry.account("gemini-cli", "work").expect("work").label;
    let personal_label = registry
        .account("gemini-cli", "personal")
        .expect("personal")
        .label;

    let exe = std::env::current_exe().expect("test executable");
    let test_name = "separate_process_concurrent_selections_both_persist";
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut children = vec![
        spawn_concurrent_batch_child(&exe, test_name, &path, &sync_dir, 0),
        spawn_concurrent_batch_child(&exe, test_name, &path, &sync_dir, 1),
    ];
    wait_for_ready_files(&ready_paths, deadline);
    fs::write(&start_barrier, b"go").expect("release start barrier");
    wait_for_children(&mut children, &done_paths, deadline);

    let accounts = registry.load().expect("load merged registry");
    assert_eq!(accounts.len(), 2 + 16);
    let mut ids = accounts
        .iter()
        .map(|account| account.id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    assert_eq!(
        ids.len(),
        ids.iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );
    for account in &accounts {
        assert_eq!(account.provider_id, "gemini-cli");
        if account.id == "work" {
            assert_eq!(account.label, work_label);
            assert!(account.is_selected);
            assert_eq!(account.state, StoredAccountState::Complete);
        } else if account.id == "personal" {
            assert_eq!(account.label, personal_label);
            assert!(!account.is_selected);
            assert_eq!(account.state, StoredAccountState::Complete);
        } else {
            assert_eq!(account.state, StoredAccountState::Complete);
            assert!(
                batch_account_ids(0).contains(&account.id)
                    || batch_account_ids(1).contains(&account.id)
            );
        }
    }
    for id in batch_account_ids(0).into_iter().chain(batch_account_ids(1)) {
        assert_eq!(
            accounts.iter().filter(|account| account.id == id).count(),
            1
        );
    }
    assert_eq!(
        registry
            .selected("gemini-cli")
            .expect("selection")
            .expect("selected")
            .id,
        baseline_selected
    );
    assert_eq!(
        selection_revision_on_disk(&path, "gemini-cli"),
        baseline_revision
    );
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read json")).expect("parse json");
    assert_eq!(document["schemaVersion"], 2);
    assert_eq!(
        document["selectionRevisions"]["gemini-cli"].as_u64(),
        Some(baseline_revision)
    );
}

#[cfg(unix)]
#[test]
fn child_held_use_lease_refuses_select_and_delete_until_release() {
    if coding_agent_manager_lib::account_authority::test_worker::run_from_env() {
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let path = registry_path(&dir);
    let signal = dir.path().join("lease-held.txt");
    let registry = StoredAccountRegistry::new(&path);
    add_complete(&registry, "gemini-cli", "work");
    registry
        .select_complete("gemini-cli", "work")
        .expect("select");
    add_complete(&registry, "gemini-cli", "personal");
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("child_held_use_lease_refuses_select_and_delete_until_release")
        .arg("--nocapture")
        .env(WORKER_ENV, "hold_use_lease")
        .env("CAM_REGISTRY_PATH", &path)
        .env("CAM_PROVIDER_ID", "gemini-cli")
        .env("CAM_LEASE_HELD_FILE", &signal)
        .spawn()
        .expect("spawn lease child");
    let deadline = Instant::now() + Duration::from_secs(15);
    while !signal.is_file() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("child never signalled lease held");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(registry.select_complete("gemini-cli", "personal").is_err());
    assert!(registry.begin_delete("gemini-cli", "work").is_err());
    fs::write(&signal, b"release").expect("release child");
    let wait_deadline = Instant::now() + Duration::from_secs(15);
    while child.try_wait().expect("try wait").is_none() {
        if Instant::now() > wait_deadline {
            let _ = child.kill();
            panic!("child did not exit after release");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(child.wait().expect("wait").success());
    registry
        .select_complete("gemini-cli", "personal")
        .expect("select after release");
}
