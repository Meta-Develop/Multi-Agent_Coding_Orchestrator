//! M1 exit criteria, as integration tests against the public API.
//!
//! `docs/ROADMAP.md` makes two claims that this file is entitled to falsify:
//!
//! > A forced failure at any point during a simulated switch leaves the
//! > fixture tree byte-identical to its pre-switch state. No secret appears
//! > in any log, error, or diagnostic under test.
//!
//! There is no `activate_account` implementation yet, and adapters still
//! resolve `$HOME` rather than an injected fixture root, so the switch is
//! simulated from the primitives the milestone actually shipped:
//! [`BackupStore::snapshot`], [`fsx::write_atomic`], [`BackupStore::restore`].
//! Where that is not the same as driving an adapter, the test says so.

mod common;

use std::fs;
use std::path::Path;

use coding_agent_manager_lib::backup::{BackupId, BackupStore};
use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::fsx;
use coding_agent_manager_lib::model::Maturity;
use coding_agent_manager_lib::providers;
use coding_agent_manager_lib::storage::encrypted_file::EncryptedFileStore;
use coding_agent_manager_lib::storage::keychain::KeychainStore;
use coding_agent_manager_lib::storage::{self, CredentialStore, Secret, SecretRef};

use crate::common::{assert_no_fake, sidecar_texts, Fixture, FAKE_PREFIX, SWITCHED_AUTH};

/// Stages of `docs/ARCHITECTURE.md` §5 at which a switch can be forced to fail.
#[derive(Debug, Clone, Copy)]
enum SwitchStage {
    /// Snapshot taken; no managed file has been opened for write.
    AfterSnapshotBeforeWrite,
    /// First of two managed writes succeeded; the second has not started.
    MidMultiFileWrite,
    /// Every intended write landed; the post-write identity check failed.
    AfterWritesAtVerification,
}

struct SwitchAttempt {
    backup_id: BackupId,
}

/// Drive the published switch sequence and inject a failure at `stage`.
///
/// Failure is injected by the test, not by a library hook — the public API
/// has none. Restore is left to the caller so the assertion sits next to the
/// digest comparison rather than inside the helper.
fn forced_failure_switch(fixture: &Fixture, stage: SwitchStage) -> SwitchAttempt {
    let store = fixture.store();
    let paths = fixture.config_paths();
    let backup_id = store
        .snapshot("codex-cli", &paths)
        .expect("snapshot must succeed before a switch starts writing");

    // The ordering property that makes every later restore defensible.
    assert!(
        fixture
            .backups
            .join(backup_id.as_str())
            .join("manifest.json")
            .is_file(),
        "snapshot returned {id} but the backup is not on disk yet",
        id = backup_id.as_str()
    );
    assert_eq!(
        store.list().expect("list after snapshot").len(),
        1,
        "the new backup must be visible to the listing API before any write"
    );

    let writes = fixture.switch_writes();
    match stage {
        SwitchStage::AfterSnapshotBeforeWrite => {}
        SwitchStage::MidMultiFileWrite => {
            let (path, bytes) = writes[0];
            fsx::write_atomic(path, bytes).expect("first managed write");
        }
        SwitchStage::AfterWritesAtVerification => {
            for (path, bytes) in writes {
                fsx::write_atomic(path, bytes).expect("managed write");
            }
        }
    }

    SwitchAttempt { backup_id }
}

/// The oracle itself has to be trusted before it can underwrite NFR-4.
#[test]
fn tree_digest_changes_when_bytes_presence_or_permission_bits_change() {
    let fixture = Fixture::materialise();
    let original_auth = fs::read(&fixture.auth_json).expect("read auth");
    let before = fixture.digest();

    fs::write(&fixture.auth_json, b"{\"mutated\":true}").expect("mutate bytes");
    assert_ne!(
        fixture.digest().content_identity(),
        before.content_identity(),
        "digest ignored a byte change in the credential file"
    );
    fs::write(&fixture.auth_json, &original_auth).expect("restore bytes");
    assert_eq!(
        fixture.digest(),
        before,
        "rewriting original bytes should restore the digest"
    );

    fs::write(&fixture.pending, b"appeared").expect("create absent path");
    assert_ne!(
        fixture.digest().content_identity(),
        before.content_identity(),
        "digest ignored a path appearing"
    );
    fs::remove_file(&fixture.pending).expect("remove");
    assert_eq!(
        fixture.digest(),
        before,
        "removing the extra path should restore the digest"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fixture.auth_json, fs::Permissions::from_mode(0o644)).expect("chmod");
        assert_ne!(
            fixture.digest(),
            before,
            "digest ignored a permission-bit change"
        );
        assert_eq!(
            fixture.digest().content_identity(),
            before.content_identity(),
            "a mode-only change must not look like a content change"
        );
        fs::set_permissions(&fixture.auth_json, fs::Permissions::from_mode(0o600))
            .expect("chmod back");
        assert_eq!(fixture.digest(), before);
    }
}

/// Snapshot is supposed to be a read of the managed tree. If it writes there,
/// every later "restore undoes the switch" claim is standing on sand.
#[test]
fn no_managed_file_is_modified_before_the_backup_exists() {
    let fixture = Fixture::materialise();
    let before = fixture.digest();
    let store = fixture.store();

    let id = store
        .snapshot("codex-cli", &fixture.config_paths())
        .expect("snapshot");

    assert!(
        fixture
            .backups
            .join(id.as_str())
            .join("manifest.json")
            .is_file(),
        "snapshot returned without creating a restorable backup"
    );
    assert_eq!(
        fixture.digest(),
        before,
        "snapshot mutated the managed tree:\n{}",
        before.diff(&fixture.digest())
    );

    let listed = store.list().expect("list");
    assert_eq!(listed.len(), 1, "exactly one backup should exist");
    assert_eq!(listed[0].id, id);
    assert_eq!(listed[0].provider_id, "codex-cli");
    // Directory + auth.json + config.toml + sessions/ + history.jsonl + the
    // captured-absent pending path. If this drifts, restore of "absent" is
    // no longer being exercised.
    assert_eq!(
        listed[0].entry_count, 6,
        "snapshot dropped or invented a path; entry_count={}",
        listed[0].entry_count
    );
}

/// The ROADMAP sentence, as a loop over every stage rather than a single
/// happy-path restore. Each iteration is a fresh fixture so one stage cannot
/// contaminate the next.
#[test]
fn a_forced_failure_at_any_switch_stage_restores_the_fixture_byte_for_byte() {
    let mut permission_mismatches = Vec::new();
    for stage in [
        SwitchStage::AfterSnapshotBeforeWrite,
        SwitchStage::MidMultiFileWrite,
        SwitchStage::AfterWritesAtVerification,
    ] {
        let fixture = Fixture::materialise();
        let before = fixture.digest();
        let sibling_settings = fs::read(&fixture.config_toml).expect("config.toml");
        let session_history = fs::read(&fixture.history).expect("history");
        let attempt = forced_failure_switch(&fixture, stage);

        match stage {
            SwitchStage::AfterSnapshotBeforeWrite => {
                assert_eq!(
                    fixture.digest(),
                    before,
                    "{stage:?}: the tree changed before any write was issued:\n{}",
                    before.diff(&fixture.digest())
                );
            }
            SwitchStage::MidMultiFileWrite | SwitchStage::AfterWritesAtVerification => {
                assert_ne!(
                    fixture.digest().content_identity(),
                    before.content_identity(),
                    "{stage:?} never mutated the tree; the restore check would be vacuous"
                );
                assert_eq!(
                    fs::read(&fixture.auth_json).expect("read switched auth"),
                    SWITCHED_AUTH.as_bytes(),
                    "{stage:?}: first write did not land"
                );
            }
        }
        if matches!(stage, SwitchStage::AfterWritesAtVerification) {
            assert!(
                fixture.pending.is_file(),
                "verification-stage failure must happen after the absent path is created"
            );
        } else {
            assert!(
                !fixture.pending.exists(),
                "{stage:?} must not leave the absent path on disk before restore"
            );
        }
        // Sibling settings and nested session data are not switch targets.
        assert_eq!(
            fs::read(&fixture.config_toml).expect("config.toml"),
            sibling_settings,
            "{stage:?}: switch disturbed the sibling settings file"
        );
        assert_eq!(
            fs::read(&fixture.history).expect("history"),
            session_history,
            "{stage:?}: switch disturbed nested session data"
        );

        fixture
            .store()
            .restore(&attempt.backup_id)
            .expect("restore after forced failure");

        let after = fixture.digest();
        assert_eq!(
            after.content_identity(),
            before.content_identity(),
            "{stage:?}: restore did not return content and presence to the \
             pre-switch state (including the path that did not exist):\n{}",
            before.diff(&after)
        );
        // ROADMAP: "byte-identical", and the oracle counts permission bits.
        // Collected across every stage so a mode-only gap cannot hide a
        // later content failure. If this vector is non-empty while the
        // content check above passed, restore is rewriting files through
        // `fsx::copy_atomic` (always 0600) rather than putting the original
        // mode back. That is a real gap in NFR-4, not a reason to drop the
        // bits from the digest.
        if after != before {
            permission_mismatches.push(format!("{stage:?}:\n{}", before.diff(&after)));
        }
    }
    assert!(
        permission_mismatches.is_empty(),
        "restore left permission bits different at one or more stages:\n\n{}",
        permission_mismatches.join("\n\n")
    );
}

/// NFR-1 / threat T2: fixture secrets stay in the backup payload. They do
/// not belong in errors, listings, or anything the application writes next
/// to that payload.
///
/// This is the Rust-side complement of the `secret-hygiene` CI job, which
/// greps the repository for vendor token shapes (`sk-`, `xai-`, `ghp_`,
/// `AIza`) and does **not** exempt a `FAKE-` prefix — its comment claims
/// otherwise. Fixture values therefore follow `docs/TESTING.md` §3
/// (`FAKE-access-token-0001`) and never embed those prefixes. The CI job
/// also cannot see what the process emits at runtime; that is this test.
#[test]
fn fixture_secrets_never_appear_in_errors_listings_or_sidecar_files() {
    let mut emissions: Vec<(String, String)> = Vec::new();

    let fixture = Fixture::materialise();
    let store = fixture.store();
    let id = store
        .snapshot("codex-cli", &fixture.config_paths())
        .expect("snapshot");

    record_listing(&mut emissions, &store);
    record_sidecars(&mut emissions, &fixture.backups);

    // Missing backup: a restore of an id that names nothing on disk.
    let missing = BackupId::parse("codex-cli-does-not-exist").expect("valid id");
    record_error(
        &mut emissions,
        "restore of a missing backup",
        store.restore(&missing).expect_err("must fail"),
    );

    // Missing source on the atomic-copy primitive the switch uses.
    let missing_source = fixture.temp.path().join("no-such-source");
    let dest = fixture.temp.path().join("copy-dest");
    fs::write(&dest, b"original").expect("seed dest");
    record_error(
        &mut emissions,
        "copy_atomic of a missing source",
        fsx::copy_atomic(&missing_source, &dest).expect_err("must fail"),
    );

    // Corrupt manifest: refuse rather than guess, and do not echo payload.
    let manifest = fixture.backups.join(id.as_str()).join("manifest.json");
    unseal(&manifest);
    fs::write(&manifest, b"{this is not a manifest").expect("corrupt");
    record_error(
        &mut emissions,
        "restore of a corrupt manifest",
        store
            .restore(&id)
            .expect_err("must refuse corrupt manifest"),
    );
    record_error(
        &mut emissions,
        "list with a corrupt manifest",
        store.list().expect_err("list must refuse corrupt manifest"),
    );

    // Unreadable managed file: snapshot must name the path, not the bytes.
    #[cfg(unix)]
    record_unreadable_snapshot(&mut emissions);

    record_unavailable_stores(&mut emissions);

    assert!(
        !emissions.is_empty(),
        "the hygiene test collected no emissions; it is no longer exercising the API"
    );
    for (where_, text) in &emissions {
        assert_no_fake(where_, text);
    }

    // The fixture itself must still contain the prefix, otherwise the grep
    // above is vacuously green.
    let auth = fs::read_to_string(&fixture.auth_json).expect("auth");
    assert!(
        auth.contains(FAKE_PREFIX),
        "fixture auth.json lost its {FAKE_PREFIX} values; the leak grep would be vacuous"
    );
}

/// Adapters still bind to the real home directory. Calling `list_accounts` or
/// `activate_account` from this suite would either no-op or, once implemented,
/// read a real login — both forbidden by `docs/TESTING.md` §4.
///
/// Maturity is the honest public signal that those methods are not ready.
/// The moment an adapter claims `supported`, this suite is incomplete: it
/// must then drive `activate_account` against an injected fixture home.
#[test]
fn adapter_switch_safety_is_unproven_until_activate_account_can_target_a_fixture() {
    for adapter in providers::registry() {
        assert_ne!(
            adapter.descriptor().maturity,
            Maturity::Supported,
            "`{}` claims `supported`, so this suite must drive \
             activate_account against the fixture home through an injected \
             root rather than simulating the switch from primitives",
            adapter.id()
        );
    }
}

fn record_error(out: &mut Vec<(String, String)>, where_: &str, error: Error) {
    out.push((format!("{where_} Display"), error.to_string()));
    out.push((format!("{where_} Debug"), format!("{error:?}")));
    out.push((
        format!("{where_} Serialize"),
        serde_json::to_string(&error).expect("Error serializes as a string"),
    ));
}

fn record_listing(out: &mut Vec<(String, String)>, store: &BackupStore) {
    let listed = store.list().expect("list");
    out.push(("BackupStore::list Debug".to_owned(), format!("{listed:?}")));
    out.push((
        "BackupStore::list Serialize".to_owned(),
        serde_json::to_string(&listed).expect("summaries serialize"),
    ));
}

fn record_sidecars(out: &mut Vec<(String, String)>, backups: &Path) {
    let sidecars = sidecar_texts(backups);
    assert!(
        sidecars
            .iter()
            .any(|(path, _)| path.ends_with("manifest.json")),
        "snapshot wrote no manifest; the sidecar check would be vacuous"
    );
    for (path, text) in sidecars {
        out.push((format!("sidecar {}", path.display()), text));
    }
}

#[cfg(unix)]
fn record_unreadable_snapshot(out: &mut Vec<(String, String)>) {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::materialise();
    let original = fs::metadata(&fixture.auth_json)
        .expect("metadata")
        .permissions();
    fs::set_permissions(&fixture.auth_json, fs::Permissions::from_mode(0o000)).expect("chmod 000");

    // Root (and some mounts) can still read a 000 file. Probe rather than
    // assume, so the test stays honest on those hosts.
    let denied = fs::read(&fixture.auth_json).is_err();
    if denied {
        record_error(
            out,
            "snapshot of an unreadable credential file",
            fixture
                .store()
                .snapshot("codex-cli", &fixture.config_paths())
                .expect_err("unreadable path must fail the snapshot"),
        );
    }

    // Always restore the mode so TempDir can clean up.
    let _ = fs::set_permissions(&fixture.auth_json, original);
    if !denied {
        // Documented gap, not a silent skip of a path we think we covered.
        out.push((
            "unreadable-file probe".to_owned(),
            "owner can still read a 000 file on this host; \
             ConfigRead-on-unreadable-file was not exercised"
                .to_owned(),
        ));
    }
}

fn record_unavailable_stores(out: &mut Vec<(String, String)>) {
    match storage::default_store() {
        Ok(store) => {
            // A live store must not receive fixture secrets (`docs/TESTING.md` §4).
            out.push((
                "default_store".to_owned(),
                format!("selected backend `{}` (not written to)", store.id()),
            ));
        }
        Err(error) => record_error(out, "default_store when nothing is available", error),
    }

    let locked_dir = tempfile::tempdir().expect("locked store dir");
    exercise_unavailable(
        out,
        "EncryptedFileStore",
        &EncryptedFileStore::new(locked_dir.path().join("credentials.enc.json")),
    );
    exercise_unavailable(out, "KeychainStore", &KeychainStore);
}

fn exercise_unavailable(out: &mut Vec<(String, String)>, label: &str, store: &dyn CredentialStore) {
    if store.is_available() {
        // Putting a secret into a reachable OS keychain (or an unlocked
        // encrypted file) would write credential-shaped bytes outside the
        // fixture TempDir.
        out.push((
            format!("{label}::is_available"),
            "true; put/get/delete not called against a live backend".to_owned(),
        ));
        return;
    }

    let key = SecretRef::for_account("codex-cli", "fixture-account");
    let secret = Secret::new(b"FAKE-access-token-0001".to_vec());
    match store.put(&key, &secret) {
        Ok(()) => panic!("{label} reported unavailable but put succeeded"),
        Err(error) => record_error(out, &format!("{label}::put"), error),
    }
    match store.get(&key) {
        Ok(_) => panic!("{label} reported unavailable but get succeeded"),
        Err(error) => record_error(out, &format!("{label}::get"), error),
    }
    match store.delete(&key) {
        Ok(()) => panic!("{label} reported unavailable but delete succeeded"),
        Err(error) => record_error(out, &format!("{label}::delete"), error),
    }
}

/// Manifests are sealed 0400; overwrite needs the bit back.
fn unseal(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("unseal manifest");
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path).expect("manifest metadata").permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).expect("unseal manifest");
    }
}
