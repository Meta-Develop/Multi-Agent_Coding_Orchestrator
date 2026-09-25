use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

const AUTH: &[u8] = include_bytes!("../../../../tests/fixtures/grok/valid-auth.json");

fn no_login(_: &Path) -> io::Result<i32> {
    panic!("setup must never run login")
}

struct Fixture {
    _root: tempfile::TempDir,
    adapter: GrokCliAdapter,
    registry: StoredAccountRegistry,
    ordinary_auth: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let user_home = root.path().join("user");
        let ordinary_auth = user_home.join(".grok/auth.json");
        fsx::create_dir_all_private(ordinary_auth.parent().unwrap()).unwrap();
        fs::write(
            &ordinary_auth,
            b"FAKE-default-home-must-not-be-read-or-copied",
        )
        .unwrap();
        let data = root.path().join("CAM 'data'");
        let registry = StoredAccountRegistry::new(paths::stored_accounts_path(&data));
        let adapter = GrokCliAdapter::with_home(user_home)
            .with_data_dir(data)
            .with_working_directory(root.path())
            .with_program(root.path().join("nonexistent-provider"))
            .with_login_runner(no_login);
        Self {
            _root: root,
            adapter,
            registry,
            ordinary_auth,
        }
    }

    fn prepare(&self, id: &str) -> StoredAccountMetadata {
        execute(&self.adapter, Action::Prepare(id)).unwrap();
        self.registry.account(PROVIDER_ID, id).unwrap()
    }

    fn auth(&self, account: &StoredAccountMetadata) -> PathBuf {
        self.adapter
            .managed_home(account)
            .unwrap()
            .join("auth.json")
    }

    fn seed_auth(&self, account: &StoredAccountMetadata) {
        fsx::write_atomic(&self.auth(account), AUTH).unwrap();
    }

    fn complete(&self, account: &StoredAccountMetadata) -> Result<String> {
        execute(
            &self.adapter,
            Action::Complete {
                id: &account.id,
                incarnation: &account.account_incarnation,
            },
        )
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.registry.metadata_path()).unwrap()
    }
}

#[test]
fn prepare_is_pending_private_no_login_no_default_copy_and_only_owner_instruction() {
    let fixture = Fixture::new();
    let output = execute(&fixture.adapter, Action::Prepare("work")).unwrap();
    let account = fixture.registry.account(PROVIDER_ID, "work").unwrap();
    assert_eq!(account.state, StoredAccountState::Pending);
    assert_eq!(account.material, StoredAccountMaterial::VendorHome);
    assert_eq!(account.auth_kind, AuthKind::OAuth);
    assert!(!account.is_selected);
    let home = fixture.adapter.managed_home(&account).unwrap();
    assert!(fs::read_dir(&home).unwrap().next().is_none());
    assert_eq!(
        fs::metadata(&home).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let quote = format!("'{}'", home.to_str().unwrap().replace('\'', "'\"'\"'"));
    assert_eq!(output, format!("GROK_HOME={quote}\nRun in your own terminal:\nenv -u GROK_AUTH_PATH GROK_HOME={quote} grok login --device-auth\n"));
    assert_eq!(
        fs::read(&fixture.ordinary_auth).unwrap(),
        b"FAKE-default-home-must-not-be-read-or-copied"
    );
}

#[test]
fn missing_auth_keeps_pending_and_previous_selection_unchanged() {
    let fixture = Fixture::new();
    let first = fixture.prepare("first");
    fixture.seed_auth(&first);
    fixture.complete(&first).unwrap();
    let next = fixture.prepare("next");
    let before = fixture.bytes();
    assert!(fixture.complete(&next).is_err());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(
        fixture.registry.selected(PROVIDER_ID).unwrap().unwrap().id,
        "first"
    );
    assert!(!fixture.auth(&next).exists());
}

#[test]
fn valid_vendor_fixture_completes_and_selects_once_without_rewriting_auth() {
    let fixture = Fixture::new();
    let first = fixture.prepare("first");
    fixture.seed_auth(&first);
    fixture.complete(&first).unwrap();
    let next = fixture.prepare("next");
    fixture.seed_auth(&next);
    let revision = fixture.registry.selection_revision(PROVIDER_ID).unwrap();
    fixture.complete(&next).unwrap();
    let selected = fixture
        .registry
        .selected_binding(PROVIDER_ID)
        .unwrap()
        .unwrap();
    assert_eq!(selected.account_id, next.id);
    assert_eq!(selected.account_incarnation, next.account_incarnation);
    assert_eq!(selected.selection_revision, revision + 1);
    assert_eq!(
        fixture.registry.account(PROVIDER_ID, "next").unwrap().state,
        StoredAccountState::Complete
    );
    assert!(
        !fixture
            .registry
            .account(PROVIDER_ID, "first")
            .unwrap()
            .is_selected
    );
    let before = fixture.bytes();
    assert!(fixture.complete(&next).is_err());
    assert_eq!(fixture.bytes(), before);
    assert_eq!(fs::read(fixture.auth(&next)).unwrap(), AUTH);
    assert_eq!(fs::read(fixture.auth(&first)).unwrap(), AUTH);
}

#[test]
fn stale_incarnation_cannot_complete_recreated_same_id() {
    let fixture = Fixture::new();
    let old = fixture.prepare("work");
    fixture.seed_auth(&old);
    fixture.registry.begin_delete(PROVIDER_ID, "work").unwrap();
    fixture.registry.finish_delete(PROVIDER_ID, "work").unwrap();
    let replacement = fixture
        .registry
        .begin_add(
            PROVIDER_ID,
            "work",
            "work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .unwrap();
    assert_ne!(old.account_incarnation, replacement.account_incarnation);
    let before = fixture.bytes();
    assert!(matches!(
        fixture.complete(&old),
        Err(Error::StaleAccount { .. })
    ));
    assert_eq!(fixture.bytes(), before);
    assert!(fixture.registry.selected(PROVIDER_ID).unwrap().is_none());
}

#[test]
fn duplicate_prepare_and_retained_home_are_not_adopted() {
    let fixture = Fixture::new();
    let account = fixture.prepare("work");
    let before = fixture.bytes();
    assert!(execute(&fixture.adapter, Action::Prepare("work")).is_err());
    assert_eq!(fixture.bytes(), before);
    fixture.seed_auth(&account);
    fixture.registry.begin_delete(PROVIDER_ID, "work").unwrap();
    fixture.registry.finish_delete(PROVIDER_ID, "work").unwrap();
    let deleted = fixture.bytes();
    assert!(execute(&fixture.adapter, Action::Prepare("work")).is_err());
    assert_eq!(fixture.bytes(), deleted);
    assert_eq!(fs::read(fixture.auth(&account)).unwrap(), AUTH);
}

#[test]
fn prepare_delete_interleaving_cannot_publish_a_new_incarnation_for_retained_empty_home() {
    let fixture = Fixture::new();
    let data = fixture.adapter.resolved_data_dir().unwrap();
    let home = managed_account_dir(&data, PROVIDER_ID, "work");
    // A pauses immediately after prepare's early absence check.
    assert_eq!(
        fs::symlink_metadata(&home).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    // B prepares the same ID and deletes its metadata, retaining an empty home.
    let old = fixture.prepare("work");
    assert!(fs::read_dir(&home).unwrap().next().is_none());
    let retained = fs::symlink_metadata(&home).unwrap();
    fixture.registry.begin_delete(PROVIDER_ID, "work").unwrap();
    fixture.registry.finish_delete(PROVIDER_ID, "work").unwrap();
    let before = fixture.bytes();
    // Resume A at the real production seam. Its exclusive mkdir must fail,
    // and it must not leave a new pending row pointing at B's retained home.
    assert!(prepare_after_absence_check(&fixture.adapter, &fixture.registry, "work").is_err());
    assert_eq!(fixture.bytes(), before);
    assert!(fixture.registry.load().unwrap().is_empty());
    assert!(metadata_identity_matches(
        &retained,
        &fs::symlink_metadata(&home).unwrap(),
        "retained home"
    )
    .unwrap());
    assert!(fs::read_dir(&home).unwrap().next().is_none());
    // A late vendor write to B's old home still cannot complete either row.
    fixture.seed_auth(&old);
    assert!(fixture.complete(&old).is_err());
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn lease_ambiguous_ids_are_rejected_before_any_filesystem_mutation() {
    for id in ["a__b", "work_", "_", "__", "a___b", "_work_"] {
        let fixture = Fixture::new();
        let data = fixture.adapter.resolved_data_dir().unwrap();
        for tail in [
            vec!["prepare", id],
            vec!["complete", id, "--incarnation", "FAKE-incarnation"],
        ] {
            let mut args = vec!["--data-dir".to_string(), data.to_str().unwrap().to_string()];
            args.extend(tail.into_iter().map(str::to_string));
            assert_eq!(run(&args), Err("invalid arguments; see --help"));
            assert!(
                !data.exists(),
                "rejected ID created data/metadata/lease files"
            );
        }
        assert!(execute(&fixture.adapter, Action::Prepare(id)).is_err());
        assert!(!data.exists());
    }
}

#[test]
fn lease_compatible_underscore_ids_allow_later_authority_mutations() {
    let fixture = Fixture::new();
    for id in ["work_account", "_work"] {
        let account = fixture.prepare(id);
        fixture.seed_auth(&account);
        fixture.complete(&account).unwrap();
        fixture.registry.begin_delete(PROVIDER_ID, id).unwrap();
        fixture.registry.finish_delete(PROVIDER_ID, id).unwrap();
    }
}

#[test]
fn shared_writable_ancestors_are_rejected_before_creating_data_directory() {
    for mode in [0o777, 0o770, 0o720] {
        let fixture = Fixture::new();
        let parent = fixture._root.path().join("shared");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(mode)).unwrap();
        let data = parent.join("new-cam-data");
        let adapter = GrokCliAdapter::with_home(fixture._root.path().join("unused-home"))
            .with_data_dir(&data)
            .with_login_runner(no_login);
        assert!(execute(&adapter, Action::Prepare("work")).is_err());
        assert!(!data.exists());
    }
}

#[test]
fn newly_writable_ancestor_blocks_existing_metadata_and_completion() {
    let fixture = Fixture::new();
    let account = fixture.prepare("work");
    fixture.seed_auth(&account);
    let before = fixture.bytes();
    fs::set_permissions(fixture._root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(execute(&fixture.adapter, Action::Status).is_err());
    assert!(execute(&fixture.adapter, Action::Prepare("next")).is_err());
    assert!(fixture.complete(&account).is_err());
    assert_eq!(fixture.bytes(), before);
    fs::set_permissions(fixture._root.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn pending_login_and_selected_use_leases_block_atomic_completion() {
    let fixture = Fixture::new();
    let account = fixture.prepare("work");
    fixture.seed_auth(&account);
    let lease = fixture
        .registry
        .acquire_pending_login_lease(
            PROVIDER_ID,
            &account.id,
            &account.account_incarnation,
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .unwrap();
    let before = fixture.bytes();
    assert!(matches!(
        fixture.complete(&account),
        Err(Error::AccountAuthorityBusy { .. })
    ));
    assert_eq!(fixture.bytes(), before);
    drop(lease);
    fixture.complete(&account).unwrap();
    let next = fixture.prepare("next");
    fixture.seed_auth(&next);
    let binding = fixture
        .registry
        .selected_binding(PROVIDER_ID)
        .unwrap()
        .unwrap();
    let lease = fixture.registry.acquire_selected_use(&binding).unwrap();
    let before = fixture.bytes();
    assert!(matches!(
        fixture.complete(&next),
        Err(Error::AccountAuthorityBusy { .. })
    ));
    assert_eq!(fixture.bytes(), before);
    drop(lease);
    fixture.complete(&next).unwrap();
}

#[test]
fn vendor_lock_and_ambiguous_session_block_completion_without_partial_selection() {
    let fixture = Fixture::new();
    let account = fixture.prepare("work");
    fixture.seed_auth(&account);
    let home = fixture.adapter.managed_home(&account).unwrap();
    let lock = File::create(home.join("auth.json.lock")).unwrap();
    FileExt::lock_exclusive(&lock).unwrap();
    let before = fixture.bytes();
    assert!(fixture.complete(&account).is_err());
    assert_eq!(fixture.bytes(), before);
    drop(lock);
    // An ambiguous session is also fail-closed; it need not be a live process.
    fs::write(home.join("active_sessions.json"), b"FAKE-invalid-session").unwrap();
    assert!(fixture.complete(&account).is_err());
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn old_selected_home_is_gated_before_explicit_switch() {
    let fixture = Fixture::new();
    let first = fixture.prepare("first");
    fixture.seed_auth(&first);
    fixture.complete(&first).unwrap();
    let next = fixture.prepare("next");
    fixture.seed_auth(&next);
    let lock = File::create(
        fixture
            .adapter
            .managed_home(&first)
            .unwrap()
            .join("active_sessions.lock"),
    )
    .unwrap();
    FileExt::lock_exclusive(&lock).unwrap();
    let before = fixture.bytes();
    assert!(fixture.complete(&next).is_err());
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn malformed_symlink_auth_and_unsafe_home_fail_closed() {
    let fixture = Fixture::new();
    let account = fixture.prepare("work");
    let auth = fixture.auth(&account);
    let before = fixture.bytes();
    for invalid in [
        b"{}".as_slice(),
        b"FAKE-malformed-secret",
        br#"{"xai::api_key":{"key":"FAKE-key"}}"#,
    ] {
        fs::write(&auth, invalid).unwrap();
        assert!(fixture.complete(&account).is_err());
        assert_eq!(fixture.bytes(), before);
    }
    fs::remove_file(&auth).unwrap();
    symlink(&fixture.ordinary_auth, &auth).unwrap();
    assert!(fixture.complete(&account).is_err());
    assert_eq!(fixture.bytes(), before);
    fs::remove_file(&auth).unwrap();
    fixture.seed_auth(&account);
    fs::set_permissions(auth.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(fixture.complete(&account).is_err());
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn status_reads_metadata_only_even_with_unusable_auth() {
    let fixture = Fixture::new();
    assert_eq!(execute(&fixture.adapter, Action::Status).unwrap(), "[]\n");
    assert!(!fixture.adapter.resolved_data_dir().unwrap().exists());
    let account = fixture.prepare("work");
    symlink("/nonexistent/FAKE-must-not-open", fixture.auth(&account)).unwrap();
    let before = fixture.bytes();
    let output = execute(&fixture.adapter, Action::Status).unwrap();
    let rows: Vec<StoredAccountMetadata> = serde_json::from_str(&output).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].account_incarnation, account.account_incarnation);
    assert!(!output.contains("FAKE"));
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn foreign_provider_or_auth_material_cannot_complete() {
    for (provider, kind, material) in [
        ("codex", AuthKind::OAuth, StoredAccountMaterial::VendorHome),
        (
            PROVIDER_ID,
            AuthKind::ApiKey,
            StoredAccountMaterial::VendorHome,
        ),
        (
            PROVIDER_ID,
            AuthKind::OAuth,
            StoredAccountMaterial::CredentialStore,
        ),
    ] {
        let fixture = Fixture::new();
        fsx::create_dir_all_private(&fixture.adapter.resolved_data_dir().unwrap()).unwrap();
        let account = fixture
            .registry
            .begin_add(provider, "work", "work", kind, material)
            .unwrap();
        let before = fixture.bytes();
        assert!(fixture.complete(&account).is_err());
        assert_eq!(fixture.bytes(), before);
    }
}

#[test]
fn unsafe_data_or_metadata_paths_are_rejected_before_registry_reads() {
    let fixture = Fixture::new();
    let data = fixture.adapter.resolved_data_dir().unwrap();
    symlink(fixture.ordinary_auth.parent().unwrap(), &data).unwrap();
    assert!(execute(&fixture.adapter, Action::Status).is_err());
    fs::remove_file(&data).unwrap();
    fsx::create_dir_all_private(&data).unwrap();
    symlink(&fixture.ordinary_auth, fixture.registry.metadata_path()).unwrap();
    assert!(execute(&fixture.adapter, Action::Status).is_err());
    assert_eq!(
        fs::read(&fixture.ordinary_auth).unwrap(),
        b"FAKE-default-home-must-not-be-read-or-copied"
    );
}

#[test]
fn cli_rejects_secret_flags_and_echoes_no_untrusted_diagnostics() {
    let fixture = Fixture::new();
    let data = fixture.adapter.resolved_data_dir().unwrap();
    let prefix = vec!["--data-dir".to_string(), data.to_str().unwrap().to_string()];
    for tail in [
        vec!["prepare", "work", "--token", "FAKE-token"],
        vec!["complete", "work"],
        vec!["prepare", "../bad"],
    ] {
        let mut args = prefix.clone();
        args.extend(tail.into_iter().map(str::to_string));
        assert_eq!(run(&args), Err("invalid arguments; see --help"));
    }
    assert!(!data.exists());
    let account = fixture.prepare("work");
    fs::write(fixture.auth(&account), b"FAKE-malformed-token").unwrap();
    let mut args = prefix;
    args.extend(
        [
            "complete",
            "work",
            "--incarnation",
            &account.account_incarnation,
        ]
        .into_iter()
        .map(str::to_string),
    );
    let error = run(&args).unwrap_err();
    assert!(!error.contains("FAKE"));
    assert!(!error.contains("token"));
}
