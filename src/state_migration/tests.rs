use super::*;
use crate::{semantic_coord::SemanticIntentStore, sync::ClaimToken, sync_store::SyncStore};
use tempfile::TempDir;

const ISSUE33_CLAIMS_V1: &[u8] =
    include_bytes!("../../tests/fixtures/issue33/agent-files-claims-v1.json");
const ISSUE33_CLAIMS_V1_SHA256: &str =
    "58076fb067d6bbc560926628b8930075d0674eae025b945619f0890000995291";

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn repository_with_claims() -> (TempDir, PathBuf, PathBuf) {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("repo");
    let repository = Repository::init(&path).expect("repository");
    let state = repository.commondir().join("maco/state");
    let state_root = SafeRoot::open_or_create(&state).expect("state root");
    let binding = expected_bindings_for(&path).repository_state;
    let mut claims = LegacyClaimsState {
        version: 2,
        checksum: String::new(),
        repository: binding,
        next_token: 2,
        claims: vec![PathClaim {
            token: ClaimToken::from_u64(1),
            agent_id: "migration-test".to_string(),
            paths: vec![PathBuf::from("src")],
        }],
    };
    claims.checksum = stable_checksum(
        &serde_json::to_vec(&(
            claims.version,
            &claims.repository,
            claims.next_token,
            &claims.claims,
        ))
        .expect("claims checksum payload"),
    );
    AtomicStateWriter::write_direct(
        &state_root,
        "claims.json",
        &serde_json::to_vec_pretty(&claims).expect("claims JSON"),
    )
    .expect("claims state");
    KernelStateLock::acquire_direct(&state_root, "claims.lock").expect("claims lock");
    (temp, path, state)
}

fn empty_repository_state() -> (TempDir, PathBuf, SafeRoot) {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("repo");
    let repository = Repository::init(&path).expect("repository");
    let state =
        SafeRoot::open_or_create(repository.commondir().join("maco/state")).expect("state root");
    (temp, path, state)
}

fn repository_with_checksumless_claims_v1() -> (TempDir, PathBuf, PathBuf) {
    let (temp, path, state) = empty_repository_state();
    AtomicStateWriter::write_direct(&state, "claims.json", ISSUE33_CLAIMS_V1)
        .expect("literal checksum-less claims-v1 fixture");
    (temp, path, state.path().to_path_buf())
}

fn repository_with_checksumless_semantic() -> (TempDir, PathBuf, PathBuf, SemanticIntent) {
    let (temp, path, state) = empty_repository_state();
    let intent = SemanticIntent {
        token: SemanticIntentToken::from_u64(1),
        agent_id: "migration-semantic".to_string(),
        paths: vec![PathBuf::from("src/lib.rs")],
        symbols: Vec::new(),
        modules: Vec::new(),
        impacted_files: Vec::new(),
        task_digest: None,
        task_excerpt: None,
        notes: Vec::new(),
        warnings: Vec::new(),
    };
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "version": 1,
        "next_token": 2,
        "intents": [&intent],
    }))
    .expect("checksum-less semantic JSON");
    AtomicStateWriter::write_direct(&state, "semantic_intents.json", &bytes)
        .expect("checksum-less semantic state");
    (temp, path, state.path().to_path_buf(), intent)
}

fn expected_bindings_for(path: &Path) -> ExpectedLegacyBindings {
    let repository = crate::git_repository::open(path).expect("repository");
    let common = SafeRoot::open_existing(repository.commondir()).expect("common root");
    let primary =
        SafeRoot::open_existing(common.path().parent().expect("embedded primary workdir"))
            .expect("primary root");
    ExpectedLegacyBindings {
        repository_state: LegacyRepositoryBinding {
            common_dir_path_checksum: stable_checksum(&filesystem_path_bytes(common.path())),
            common_dir_identity: common.identity().clone(),
        },
        managed_repository: Some(ManagedRepositoryBindingWire {
            common_dir: encode_persisted_path_wire(common.path()).expect("common path"),
            common_dir_identity: common.identity().clone(),
            repository_workdir: encode_persisted_path_wire(primary.path()).expect("primary path"),
            repository_workdir_identity: primary.identity().clone(),
        }),
    }
}

#[cfg(unix)]
fn make_legacy_permissions(state: &Path) {
    fs::set_permissions(state, fs::Permissions::from_mode(0o755)).expect("state mode");
    for name in ["claims.json", "claims.lock"] {
        fs::set_permissions(state.join(name), fs::Permissions::from_mode(0o644))
            .expect("legacy file mode");
    }
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

#[cfg(unix)]
fn owned_directory_attributes(hard_link_count: u64) -> OwnedDirectoryAttributes {
    OwnedDirectoryAttributes {
        is_symlink: false,
        is_directory: true,
        owner: unsafe { libc::geteuid() },
        hard_link_count,
        mode: 0o700,
    }
}

#[cfg(unix)]
#[test]
fn owned_directory_validation_accepts_drvfs_link_count_one_and_rejects_zero() {
    let owner = unsafe { libc::geteuid() };
    assert!(owned_directory_attributes(1).are_safe_for(owner));
    assert!(!owned_directory_attributes(0).are_safe_for(owner));
}

#[test]
fn literal_issue33_claims_v1_fixture_matches_the_pinned_writer_bytes() {
    assert_eq!(ISSUE33_CLAIMS_V1.len(), 524);
    assert_eq!(sha256_hex(ISSUE33_CLAIMS_V1), ISSUE33_CLAIMS_V1_SHA256);
    assert_eq!(
        include_str!("../../tests/fixtures/issue33/agent-files-claims-v1.sha256"),
        format!("{ISSUE33_CLAIMS_V1_SHA256}  agent-files-claims-v1.json\n")
    );

    let decoded =
        decode_checksumless_legacy_claims_state(ISSUE33_CLAIMS_V1).expect("strict fixture");
    assert_eq!(decoded.next_token, 67);
    assert_eq!(
        decoded
            .claims
            .iter()
            .map(|claim| claim.token.get())
            .collect::<Vec<_>>(),
        vec![20, 44, 66]
    );
}

#[test]
fn claims_v1_migration_options_require_a_coherent_lowercase_digest_pair() {
    assert!(validate_migration_options(&StateMigrationOptions {
        acknowledge_unauthenticated_claims_v1: false,
        expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
    })
    .is_err());
    assert!(validate_migration_options(&StateMigrationOptions {
        acknowledge_unauthenticated_claims_v1: true,
        expected_claims_v1_sha256: None,
    })
    .is_err());
    assert!(validate_migration_options(&StateMigrationOptions {
        acknowledge_unauthenticated_claims_v1: true,
        expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_uppercase()),
    })
    .is_err());
    validate_migration_options(&StateMigrationOptions {
        acknowledge_unauthenticated_claims_v1: true,
        expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
    })
    .expect("coherent acknowledgement and lowercase SHA-256");
}

#[test]
fn checksumless_claims_v1_decoder_rejects_noncanonical_or_ambiguous_state() {
    let mut cases = Vec::new();

    let mut low_next_token: serde_json::Value =
        serde_json::from_slice(ISSUE33_CLAIMS_V1).expect("fixture JSON");
    low_next_token["next_token"] = serde_json::json!(66);
    cases.push(("next token", low_next_token));

    let mut duplicate_token: serde_json::Value =
        serde_json::from_slice(ISSUE33_CLAIMS_V1).expect("fixture JSON");
    duplicate_token["claims"][1]["token"] = serde_json::json!(20);
    cases.push(("duplicate token", duplicate_token));

    let mut noncanonical_path: serde_json::Value =
        serde_json::from_slice(ISSUE33_CLAIMS_V1).expect("fixture JSON");
    noncanonical_path["claims"][0]["paths"][0] = serde_json::json!("src/../README.md");
    cases.push(("noncanonical path", noncanonical_path));

    let mut unknown_field: serde_json::Value =
        serde_json::from_slice(ISSUE33_CLAIMS_V1).expect("fixture JSON");
    unknown_field["claims"][0]["unexpected"] = serde_json::json!(true);
    cases.push(("unknown field", unknown_field));

    for (name, value) in cases {
        let bytes = serde_json::to_vec_pretty(&value).expect("case JSON");
        assert!(
            decode_checksumless_legacy_claims_state(&bytes).is_err(),
            "{name} must fail"
        );
    }
}

#[test]
fn legacy_entry_without_provenance_keeps_the_pre_provenance_wire_shape() {
    let legacy = serde_json::json!({
        "store": "claims",
        "file": "claims.json",
        "present": false,
        "size": 0,
        "sha256": null,
        "legacy_checksum": null,
        "file_identity": null
    });
    let entry: LegacyStateEntry =
        serde_json::from_value(legacy.clone()).expect("pre-provenance entry");
    assert_eq!(entry.provenance, None);
    assert_eq!(
        serde_json::to_value(entry).expect("entry serialization"),
        legacy
    );
}

#[cfg(unix)]
#[test]
fn claims_v1_migration_requires_exact_operator_attestation_and_signs_it() {
    let (_temp, path, state) = repository_with_checksumless_claims_v1();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).expect("state mode");
    fs::set_permissions(state.join("claims.json"), fs::Permissions::from_mode(0o644))
        .expect("claims mode");
    let repository = crate::git_repository::open(&path).expect("repository");
    let transaction_root = repository.commondir().join(TRANSACTION_ROOT_NAME);

    let unauthenticated = migrate_repository_state(&path, false)
        .expect_err("checksum-less claims-v1 needs acknowledgement");
    let unauthenticated_message = format!("{unauthenticated:#}");
    assert!(unauthenticated_message.contains("unauthenticated"));
    assert!(unauthenticated_message.contains(ISSUE33_CLAIMS_V1_SHA256));
    assert_eq!(mode(&state), 0o755);
    assert_eq!(mode(&state.join("claims.json")), 0o644);
    assert!(!transaction_root.exists());
    assert!(!state.join(AUTH_KEY_FILE).exists());

    let wrong = StateMigrationOptions {
        acknowledge_unauthenticated_claims_v1: true,
        expected_claims_v1_sha256: Some("0".repeat(64)),
    };
    let mismatch = migrate_repository_state_with_options(&path, false, &wrong)
        .expect_err("wrong digest must fail");
    assert!(mismatch.to_string().contains("SHA-256 mismatch"));
    assert!(!transaction_root.exists());
    assert!(!state.join(AUTH_KEY_FILE).exists());

    let options = StateMigrationOptions {
        acknowledge_unauthenticated_claims_v1: true,
        expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
    };
    let dry =
        migrate_repository_state_with_options(&path, false, &options).expect("attested dry run");
    let claims_entry = dry
        .entries
        .iter()
        .find(|entry| entry.store == "claims")
        .expect("claims entry");
    assert_eq!(dry.status, StateMigrationStatus::Ready);
    assert_eq!(
        claims_entry.sha256.as_deref(),
        Some(ISSUE33_CLAIMS_V1_SHA256)
    );
    assert_eq!(claims_entry.legacy_checksum, None);
    assert_eq!(
        claims_entry.provenance,
        Some(LegacyStateProvenance::OperatorAttestedUnauthenticatedImport)
    );
    assert!(!transaction_root.exists());
    assert!(!state.join(AUTH_KEY_FILE).exists());

    let applied =
        migrate_repository_state_with_options(&path, true, &options).expect("attested apply");
    assert_eq!(applied.status, StateMigrationStatus::Applied);
    assert_eq!(applied.manifest_generation, Some(1));
    assert_eq!(
        applied
            .entries
            .iter()
            .find(|entry| entry.store == "claims")
            .expect("applied claims entry")
            .provenance,
        Some(LegacyStateProvenance::OperatorAttestedUnauthenticatedImport)
    );

    let repeated = migrate_repository_state_with_options(&path, true, &options)
        .expect("idempotent attested apply");
    assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
}

#[cfg(unix)]
#[test]
fn signed_claims_v1_without_attested_provenance_is_refused() {
    let (_temp, path, _state) = repository_with_checksumless_claims_v1();
    let options = StateMigrationOptions {
        acknowledge_unauthenticated_claims_v1: true,
        expected_claims_v1_sha256: Some(ISSUE33_CLAIMS_V1_SHA256.to_string()),
    };
    migrate_repository_state_with_options(&path, true, &options)
        .expect("signed operator-attested migration");

    let authenticator = repository_authenticator_key_only(&path).expect("repository authenticator");
    let mut manifest_store = AuthenticatedSnapshotStore::<
        StateMigrationManifestSpec,
        StateMigrationManifest,
    >::open_instance(authenticator, MANIFEST_INSTANCE_ID)
    .expect("manifest store");
    let mut manifest = manifest_store.current().value.clone();
    manifest
        .entries
        .iter_mut()
        .find(|entry| entry.store == "claims")
        .expect("claims entry")
        .provenance = None;
    manifest_store
        .commit(2, manifest)
        .expect("signed misclassified manifest");
    drop(manifest_store);

    let error = authenticated_legacy_adoption(&path, "claims", "claims.json")
        .expect_err("claims-v1 without provenance must fail closed");
    let chain = format!("{error:#}");
    assert!(
        chain.contains("lacks its operator-attested"),
        "unexpected error: {chain}"
    );
}

#[cfg(unix)]
#[test]
fn migration_preflight_accepts_isolated_legacy_state_directory() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    let repository = crate::git_repository::open(&path).expect("repository");

    let preflight = preflight_legacy_state(
        &path,
        repository.commondir(),
        &state,
        &StateMigrationOptions::default(),
    )
    .expect("isolated legacy state preflight");

    assert_eq!(preflight.state_root.path(), state);
    assert!(preflight.entries.iter().any(|entry| entry.present));
}

#[cfg(unix)]
#[test]
fn dry_run_is_non_mutating_and_apply_is_signed_and_idempotent() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    let repo = crate::git_repository::open(&path).expect("repo");
    let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);

    let dry = migrate_repository_state(&path, false).expect("dry run");
    assert_eq!(dry.status, StateMigrationStatus::Ready);
    assert!(!dry.hardened);
    assert_eq!(mode(&state), 0o755);
    assert_eq!(mode(&state.join("claims.json")), 0o644);
    assert!(!transaction_root.exists());

    let applied = migrate_repository_state(&path, true).expect("apply");
    assert_eq!(applied.status, StateMigrationStatus::Applied);
    assert_eq!(applied.manifest_generation, Some(1));
    assert!(applied
        .entries
        .iter()
        .any(|entry| entry.store == "managed_worktrees" && !entry.present));
    assert_eq!(mode(&state), 0o700);
    for name in [
        "claims.json",
        "claims.lock",
        "semantic_intents.lock",
        "managed_worktrees.lock",
    ] {
        assert_eq!(mode(&state.join(name)), 0o600);
    }
    assert!(transaction_root.join(RECEIPT_FILE).is_file());

    let repeated = migrate_repository_state(&path, true).expect("idempotent apply");
    assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
    assert_eq!(repeated.transaction_phase, Some(MigrationPhase::Completed));
}

#[cfg(unix)]
#[test]
fn registered_authenticated_consumer_roots_and_state_locks_migrate_across_all_modes() {
    let (_temp, path, state) = empty_repository_state();
    let writer = repository_auth_writer(&path).expect("bootstrap repository authentication");
    drop(writer);

    let binding = expected_bindings_for(&path).repository_state;
    let mut claims = LegacyClaimsState {
        version: 2,
        checksum: String::new(),
        repository: binding,
        next_token: 2,
        claims: vec![PathClaim {
            token: ClaimToken::from_u64(1),
            agent_id: "registered-consumer-migration-test".to_string(),
            paths: vec![PathBuf::from("src")],
        }],
    };
    claims.checksum = stable_checksum(
        &serde_json::to_vec(&(
            claims.version,
            &claims.repository,
            claims.next_token,
            &claims.claims,
        ))
        .expect("claims checksum payload"),
    );
    AtomicStateWriter::write_direct(
        &state,
        "claims.json",
        &serde_json::to_vec_pretty(&claims).expect("claims JSON"),
    )
    .expect("claims state");
    KernelStateLock::acquire_direct(&state, "claims.lock").expect("claims lock");

    let sources = crate::artifacts::state_auth::authenticated_state_consumers();
    assert_eq!(sources.len(), 9, "all authenticated consumer sources");
    let registered_roots = sources
        .iter()
        .map(|source| source.root_name)
        .collect::<BTreeSet<_>>();
    for required in [
        "authenticated-field-guide-state-v1",
        "authenticated-megafile-history-v1",
        "authenticated-generated-follow-up-queues-v1",
    ] {
        assert!(
            registered_roots.contains(required),
            "missing authenticated consumer root {required}"
        );
    }
    let registered_state_root_locks = sources
        .iter()
        .flat_map(|source| source.state_root_lock_names.iter().copied())
        .collect::<BTreeSet<_>>();
    for required in [
        ".authenticated-field-guide.lock",
        "field-guide-operation-v1.lock",
        ".authenticated-megafile-history.lock",
        "megafile-history-operation-v1.lock",
        ".generated-follow-up-queues.lock",
    ] {
        assert!(
            registered_state_root_locks.contains(required),
            "missing authenticated consumer state-root lock {required}"
        );
    }

    for source in sources {
        SafeRoot::open_or_create(state.path().join(source.root_name))
            .expect("registered authenticated consumer root");
        for lock_name in source.state_root_lock_names {
            KernelStateLock::acquire_direct(&state, lock_name)
                .expect("registered authenticated consumer state-root lock");
        }
    }
    make_legacy_permissions(state.path());

    let dry = migrate_repository_state(&path, false).expect("registered-source dry run");
    assert_eq!(dry.status, StateMigrationStatus::Ready);
    assert_eq!(dry.mode, StateMigrationMode::DryRun);

    let applied = migrate_repository_state(&path, true).expect("registered-source apply");
    assert_eq!(applied.status, StateMigrationStatus::Applied);
    assert_eq!(applied.mode, StateMigrationMode::Apply);

    let repeated_dry =
        migrate_repository_state(&path, false).expect("registered-source repeated dry run");
    assert_eq!(repeated_dry.status, StateMigrationStatus::AlreadyApplied);
    assert_eq!(repeated_dry.mode, StateMigrationMode::DryRun);

    let repeated_apply =
        migrate_repository_state(&path, true).expect("registered-source repeated apply");
    assert_eq!(repeated_apply.status, StateMigrationStatus::AlreadyApplied);
    assert_eq!(repeated_apply.mode, StateMigrationMode::Apply);
}

#[cfg(unix)]
#[test]
fn publication_transaction_journals_are_inventoried_and_retired_across_all_modes() {
    let (_temp, path, state) = repository_with_claims();
    let journals = state
        .join(LEGACY_PUBLICATION_TRANSACTIONS_DIR)
        .join("legacy");
    fs::create_dir_all(&journals).expect("legacy publication journals");
    let record = journals.join("00000000000000000001.json");
    fs::write(&record, b"legacy plaintext must remain untouched\n").expect("legacy record");
    make_legacy_permissions(&state);

    assert!(
        !legacy_publication_journals_are_retired(&path).expect("pre-migration retirement query"),
        "unsigned leftover journals are not retired"
    );

    let dry = migrate_repository_state(&path, false).expect("publication-journal dry run");
    assert_eq!(dry.status, StateMigrationStatus::Ready);
    assert_eq!(dry.mode, StateMigrationMode::DryRun);
    assert!(
        !legacy_publication_journals_are_retired(&path).expect("dry-run retirement query"),
        "dry-run must not retire leftover journals"
    );

    let applied = migrate_repository_state(&path, true).expect("publication-journal apply");
    assert_eq!(applied.status, StateMigrationStatus::Applied);
    assert_eq!(applied.mode, StateMigrationMode::Apply);
    assert!(
        legacy_publication_journals_are_retired(&path).expect("applied retirement query"),
        "signed migration must retire leftover publication journals"
    );
    assert_eq!(
        fs::read(&record).expect("legacy record remains after apply"),
        b"legacy plaintext must remain untouched\n"
    );

    let repeated_dry =
        migrate_repository_state(&path, false).expect("publication-journal repeated dry run");
    assert_eq!(repeated_dry.status, StateMigrationStatus::AlreadyApplied);
    let repeated_apply =
        migrate_repository_state(&path, true).expect("publication-journal repeated apply");
    assert_eq!(repeated_apply.status, StateMigrationStatus::AlreadyApplied);
    assert!(legacy_publication_journals_are_retired(&path).expect("repeated retirement query"));
    assert_eq!(
        fs::read(&record).expect("legacy record remains after re-verify"),
        b"legacy plaintext must remain untouched\n"
    );
}

#[cfg(unix)]
#[test]
fn checksumless_semantic_requires_offline_manifest_then_adopts_authenticated_snapshot() {
    let (_temp, path, state, expected_intent) = repository_with_checksumless_semantic();
    let repository = crate::git_repository::open(&path).expect("repository");
    let transaction_root = repository.commondir().join(TRANSACTION_ROOT_NAME);

    let direct_error = SemanticIntentStore::open(&path)
        .expect_err("normal runtime must reject unmanifested checksum-less state");
    assert!(direct_error
        .to_string()
        .contains("signed migration manifest"));
    assert!(!state.join(SemanticSnapshotSpec::ROOT_NAME).exists());

    let dry = migrate_repository_state(&path, false).expect("checksum-less dry run");
    assert_eq!(dry.status, StateMigrationStatus::Ready);
    assert_eq!(dry.mode, StateMigrationMode::DryRun);
    assert!(!transaction_root.exists());
    assert!(!state.join(MANIFEST_ROOT_NAME).exists());

    let applied = migrate_repository_state(&path, true).expect("offline migration apply");
    assert_eq!(applied.status, StateMigrationStatus::Applied);
    assert_eq!(applied.manifest_generation, Some(1));

    let store = SemanticIntentStore::open(&path)
        .expect("signed checksum-less state must adopt into authenticated storage");
    assert_eq!(
        store.snapshot().expect("authenticated snapshot"),
        vec![expected_intent]
    );
    assert!(state.join(SemanticSnapshotSpec::ROOT_NAME).is_dir());
    let tombstone: serde_json::Value = serde_json::from_slice(
        &fs::read(state.join("semantic_intents.json")).expect("active tombstone"),
    )
    .expect("tombstone JSON");
    assert_eq!(tombstone["version"], 3);
    assert_eq!(tombstone["phase"], "active");

    let repeated =
        migrate_repository_state(&path, false).expect("post-adoption manifest verification");
    assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
}

#[test]
fn checksumless_semantic_decoder_is_strict_and_bounded() {
    let (_temp, path, state) = empty_repository_state();
    let invalid_states = [
        serde_json::json!({
            "version": 1,
            "next_token": 1,
            "intents": [],
            "unexpected": true,
        }),
        serde_json::json!({
            "version": 1,
            "next_token": 0,
            "intents": [],
        }),
        serde_json::json!({
            "version": 2,
            "next_token": 1,
            "intents": [],
        }),
    ];
    let repository = crate::git_repository::open(&path).expect("repository");
    let transaction_root = repository.commondir().join(TRANSACTION_ROOT_NAME);

    for value in invalid_states {
        AtomicStateWriter::write_direct(
            &state,
            "semantic_intents.json",
            &serde_json::to_vec_pretty(&value).expect("invalid semantic JSON"),
        )
        .expect("replace invalid semantic state");
        assert!(migrate_repository_state(&path, false).is_err());
        assert!(!transaction_root.exists());
        assert!(!state.path().join(MANIFEST_ROOT_NAME).exists());
    }
}

#[test]
fn checksumless_semantic_decoder_rejects_unknown_nested_intent_fields() {
    let (_temp, path, state) = empty_repository_state();
    let intent = serde_json::json!({
        "token": 1,
        "agent_id": "migration-semantic",
        "paths": ["src/lib.rs"],
        "symbols": [],
        "modules": [],
        "impacted_files": [],
        "task_digest": null,
        "task_excerpt": null,
        "notes": [],
        "warnings": [],
        "unexpected": true,
    });
    AtomicStateWriter::write_direct(
        &state,
        "semantic_intents.json",
        &serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "next_token": 2,
            "intents": [intent],
        }))
        .expect("invalid nested semantic JSON"),
    )
    .expect("invalid nested semantic state");

    let error =
        migrate_repository_state(&path, false).expect_err("unknown nested fields must fail closed");
    assert!(error.to_string().contains("strict checksum-less"));
}

#[cfg(unix)]
#[test]
fn post_adoption_dry_run_and_apply_verify_original_manifest_and_active_tombstone() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    migrate_repository_state(&path, true).expect("publish signed migration manifest");

    let store = SyncStore::open(&path).expect("adopt signed legacy claims");
    let claims = store.snapshot().expect("authenticated claims");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].agent_id, "migration-test");
    let tombstone: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("claims.json")).expect("active tombstone"))
            .expect("tombstone JSON");
    assert_eq!(tombstone["version"], 3);
    assert_eq!(tombstone["phase"], "active");

    let dry = migrate_repository_state(&path, false).expect("post-adoption dry run");
    assert_eq!(dry.status, StateMigrationStatus::AlreadyApplied);
    assert_eq!(dry.transaction_phase, Some(MigrationPhase::Completed));
    let repeated = migrate_repository_state(&path, true).expect("post-adoption apply");
    assert_eq!(repeated.status, StateMigrationStatus::AlreadyApplied);
    assert_eq!(repeated.transaction_phase, Some(MigrationPhase::Completed));
}

#[cfg(unix)]
#[test]
fn existing_manifest_refuses_transaction_root_replacement_after_preflight() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    migrate_repository_state(&path, true).expect("publish signed migration manifest");
    let repo = crate::git_repository::open(&path).expect("repo");
    let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);
    let original_root = repo.commondir().join("maco-state-migration-v1.original");
    set_migration_after_preflight_hook({
        let transaction_root = transaction_root.clone();
        let original_root = original_root.clone();
        move || {
            fs::rename(&transaction_root, &original_root).expect("move transaction root");
            fs::create_dir(&transaction_root).expect("replacement transaction root");
            fs::set_permissions(&transaction_root, fs::Permissions::from_mode(0o700))
                .expect("replacement root mode");
            for name in [TRANSACTION_FILE, RECEIPT_FILE, TRANSACTION_LOCK] {
                fs::copy(original_root.join(name), transaction_root.join(name))
                    .expect("copy transaction evidence");
                fs::set_permissions(
                    transaction_root.join(name),
                    fs::Permissions::from_mode(0o600),
                )
                .expect("replacement evidence mode");
            }
        }
    });

    let error = migrate_repository_state(&path, false)
        .expect_err("transaction root replacement must fail closed");
    let chain = format!("{error:#}");
    assert!(
        chain.contains("identity changed")
            || chain.contains("no longer identifies")
            || chain.contains("transaction root"),
        "unexpected error: {chain}"
    );
}

#[cfg(unix)]
#[test]
fn initial_apply_refuses_common_directory_replacement_with_same_state_inode() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    let repository = crate::git_repository::open(&path).expect("repository");
    let common_dir = repository.commondir().to_path_buf();
    let displaced_common = path.join("displaced-common-dir");
    let state_identity = identity_for_path(&state).expect("state identity");
    set_migration_after_preflight_hook({
        let common_dir = common_dir.clone();
        let displaced_common = displaced_common.clone();
        move || {
            fs::rename(&common_dir, &displaced_common).expect("displace original common dir");
            fs::create_dir(&common_dir).expect("replacement common dir");
            fs::set_permissions(&common_dir, fs::Permissions::from_mode(0o700))
                .expect("replacement common mode");
            fs::create_dir(common_dir.join("maco")).expect("replacement state parent");
            fs::set_permissions(common_dir.join("maco"), fs::Permissions::from_mode(0o700))
                .expect("replacement state parent mode");
            fs::rename(
                displaced_common.join("maco/state"),
                common_dir.join("maco/state"),
            )
            .expect("return the same state inode under the replacement common dir");
        }
    });

    let error = migrate_repository_state(&path, true)
        .expect_err("common-directory replacement must fail closed");
    let chain = format!("{error:#}");
    assert!(
        chain.contains("common") || chain.contains("safe root path was replaced"),
        "unexpected error: {chain}"
    );
    assert_eq!(
        identity_for_path(common_dir.join("maco/state")).expect("returned state identity"),
        state_identity
    );
    assert!(!common_dir.join(TRANSACTION_ROOT_NAME).exists());
}

#[cfg(unix)]
#[test]
fn completed_apply_refuses_common_replacement_with_same_state_and_transaction_inodes() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    let repository = crate::git_repository::open(&path).expect("repository");
    let common_dir = repository.commondir().to_path_buf();
    let displaced_common = path.join("post-manifest-displaced-common");
    let state_identity = identity_for_path(&state).expect("state identity");
    let transaction_identity = std::rc::Rc::new(std::cell::RefCell::new(None));
    set_migration_before_final_verification_hook({
        let common_dir = common_dir.clone();
        let displaced_common = displaced_common.clone();
        let transaction_identity = std::rc::Rc::clone(&transaction_identity);
        move || {
            *transaction_identity.borrow_mut() = Some(
                identity_for_path(common_dir.join(TRANSACTION_ROOT_NAME))
                    .expect("transaction identity"),
            );
            fs::rename(&common_dir, &displaced_common).expect("displace original common dir");
            fs::create_dir(&common_dir).expect("replacement common dir");
            fs::set_permissions(&common_dir, fs::Permissions::from_mode(0o700))
                .expect("replacement common mode");
            fs::create_dir(common_dir.join("maco")).expect("replacement state parent");
            fs::set_permissions(common_dir.join("maco"), fs::Permissions::from_mode(0o700))
                .expect("replacement state parent mode");
            fs::rename(
                displaced_common.join("maco/state"),
                common_dir.join("maco/state"),
            )
            .expect("return state inode");
            fs::rename(
                displaced_common.join(TRANSACTION_ROOT_NAME),
                common_dir.join(TRANSACTION_ROOT_NAME),
            )
            .expect("return transaction inode");
        }
    });

    let error = migrate_repository_state(&path, true)
        .expect_err("post-manifest common replacement must fail closed");
    let chain = format!("{error:#}");
    assert!(
        chain.contains("safe root path was replaced") || chain.contains("common"),
        "unexpected error: {chain}"
    );
    assert_eq!(
        identity_for_path(common_dir.join("maco/state")).expect("returned state"),
        state_identity
    );
    assert_eq!(
        identity_for_path(common_dir.join(TRANSACTION_ROOT_NAME)).expect("returned transaction"),
        transaction_identity
            .borrow()
            .clone()
            .expect("captured transaction identity")
    );
    let transaction: MigrationTransaction = serde_json::from_slice(
        &fs::read(
            common_dir
                .join(TRANSACTION_ROOT_NAME)
                .join(TRANSACTION_FILE),
        )
        .expect("completed transaction"),
    )
    .expect("transaction JSON");
    assert_eq!(transaction.phase, MigrationPhase::Completed);
    assert!(common_dir
        .join(TRANSACTION_ROOT_NAME)
        .join(RECEIPT_FILE)
        .is_file());
}

#[cfg(unix)]
#[test]
fn hardening_refuses_child_replacement_without_chmodding_replacement() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    let claims = state.join("claims.json");
    let displaced = state.join("claims.json.displaced");
    set_migration_after_child_bind_hook("claims.json", {
        let claims = claims.clone();
        let displaced = displaced.clone();
        move || {
            fs::rename(&claims, &displaced).expect("displace bound claims file");
            fs::write(&claims, b"replacement").expect("replacement claims file");
            fs::set_permissions(&claims, fs::Permissions::from_mode(0o660))
                .expect("replacement claims mode");
        }
    });

    let error = migrate_repository_state(&path, true)
        .expect_err("child pathname replacement must fail closed");
    let chain = format!("{error:#}");
    assert!(
        chain.contains("binding") || chain.contains("identity"),
        "unexpected error: {chain}"
    );
    assert_eq!(mode(&claims), 0o660);
    assert_eq!(mode(&displaced), 0o644);
    assert!(!state.join(AUTH_KEY_FILE).exists());
}

#[cfg(unix)]
#[test]
fn hardened_state_check_rejects_special_or_unknown_entries() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    set_migration_after_preflight_hook({
        let special = state.join("unexpected-special");
        move || {
            let name =
                std::ffi::CString::new(special.as_os_str().as_bytes()).expect("special path");
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        }
    });

    let error =
        migrate_repository_state(&path, false).expect_err("special state entry must fail closed");
    assert!(error.to_string().contains("unknown entry"));
}

#[cfg(unix)]
#[test]
fn existing_manifest_refuses_legacy_lock_rebind_without_advancing_transaction() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    set_migration_fault(
        MigrationFaultPoint::AfterManifest,
        MigrationFaultAction::Crash,
    );
    migrate_repository_state(&path, true).expect_err("crash after manifest publication");
    let repo = crate::git_repository::open(&path).expect("repo");
    let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);
    assert!(!transaction_root.join(RECEIPT_FILE).exists());
    let lock_path = state.join("claims.lock");
    let original_lock = state.join("claims.lock.preflight-original");
    set_migration_after_preflight_hook({
        let lock_path = lock_path.clone();
        let original_lock = original_lock.clone();
        move || {
            fs::rename(&lock_path, &original_lock).expect("move held legacy lock");
            fs::write(&lock_path, b"").expect("replacement legacy lock");
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                .expect("replacement lock mode");
        }
    });

    let error = migrate_repository_state(&path, true)
        .expect_err("legacy lock rebind must fence manifest completion");
    let chain = format!("{error:#}");
    assert!(
        chain.contains("rebound") || chain.contains("opened descriptor"),
        "unexpected error: {chain}"
    );
    assert!(!transaction_root.join(RECEIPT_FILE).exists());
    let transaction: MigrationTransaction = serde_json::from_slice(
        &fs::read(transaction_root.join(TRANSACTION_FILE)).expect("transaction"),
    )
    .expect("transaction JSON");
    assert_eq!(transaction.phase, MigrationPhase::ManifestPublished);
}

#[cfg(unix)]
#[test]
fn existing_manifest_refuses_tombstone_change_after_preflight_without_rewriting_evidence() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    migrate_repository_state(&path, true).expect("publish manifest");
    drop(SyncStore::open(&path).expect("adopt claims"));
    let repo = crate::git_repository::open(&path).expect("repo");
    let transaction_root = repo.commondir().join(TRANSACTION_ROOT_NAME);
    let transaction_before =
        fs::read(transaction_root.join(TRANSACTION_FILE)).expect("transaction before");
    let receipt_before = fs::read(transaction_root.join(RECEIPT_FILE)).expect("receipt before");
    let tombstone_path = state.join("claims.json");
    set_migration_after_preflight_hook({
        let tombstone_path = tombstone_path.clone();
        move || {
            let mut bytes = fs::read(&tombstone_path).expect("active tombstone");
            bytes.push(b'\n');
            fs::write(&tombstone_path, bytes).expect("change tombstone bytes");
        }
    });

    let error = migrate_repository_state(&path, false)
        .expect_err("post-preflight tombstone change must fail closed");
    assert!(error.to_string().contains("tombstone changed"));
    assert_eq!(
        fs::read(transaction_root.join(TRANSACTION_FILE)).expect("transaction after"),
        transaction_before
    );
    assert_eq!(
        fs::read(transaction_root.join(RECEIPT_FILE)).expect("receipt after"),
        receipt_before
    );
}

#[cfg(unix)]
#[test]
fn signed_nonempty_claims_forward_recover_at_every_retirement_fault() {
    for fault in [
        LegacyRetirementFaultPoint::Sidecar,
        LegacyRetirementFaultPoint::Intent,
        LegacyRetirementFaultPoint::PendingTombstone,
        LegacyRetirementFaultPoint::ActiveTombstone,
    ] {
        let (_temp, path, state) = repository_with_claims();
        make_legacy_permissions(&state);
        migrate_repository_state(&path, true).expect("signed migration manifest");
        set_legacy_retirement_fault(fault);
        let error = SyncStore::open(&path).expect_err("retirement fault");
        assert!(error
            .to_string()
            .contains("injected legacy retirement fault"));

        let bytes = fs::read(state.join("claims.json")).expect("legacy filename");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("state JSON");
        if matches!(
            fault,
            LegacyRetirementFaultPoint::PendingTombstone
                | LegacyRetirementFaultPoint::ActiveTombstone
        ) {
            assert_eq!(value["version"], 3);
            assert!(serde_json::from_slice::<LegacyClaimsState>(&bytes).is_err());
        } else {
            assert_eq!(value["version"], 2);
        }

        let store = SyncStore::open(&path).expect("forward recover signed claims");
        let claims = store.snapshot().expect("recovered claims");
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].agent_id, "migration-test");
        assert_eq!(claims[0].paths, vec![PathBuf::from("src")]);
    }
}

#[cfg(unix)]
#[test]
fn corrupt_checksum_refuses_without_any_change() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    let claims = state.join("claims.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&claims).expect("claims")).expect("JSON");
    value["next_token"] = serde_json::json!(999);
    fs::write(&claims, serde_json::to_vec_pretty(&value).expect("encode"))
        .expect("tamper checksum");
    fs::set_permissions(&claims, fs::Permissions::from_mode(0o644)).expect("mode");

    let error = migrate_repository_state(&path, false).expect_err("checksum mismatch");
    assert!(error.to_string().contains("checksum mismatch"));
    assert_eq!(mode(&state), 0o755);
    let repo = crate::git_repository::open(&path).expect("repo");
    assert!(!repo.commondir().join(TRANSACTION_ROOT_NAME).exists());
}

#[cfg(unix)]
#[test]
fn active_legacy_lock_refuses_without_changes() {
    let (_temp, path, state) = repository_with_claims();
    let root = SafeRoot::open_existing(&state).expect("state root");
    let _held = KernelStateLock::acquire_direct(&root, "claims.lock").expect("held lock");
    let error = migrate_repository_state(&path, false).expect_err("active lock refusal");
    assert!(error.to_string().contains("active"));
    assert_eq!(mode(&state), 0o700);
}

#[cfg(unix)]
#[test]
fn normal_fault_rolls_back_while_crash_fault_recovers_forward() {
    let (_temp, path, state) = repository_with_claims();
    make_legacy_permissions(&state);
    set_migration_fault(
        MigrationFaultPoint::AfterPermissions,
        MigrationFaultAction::Error,
    );
    migrate_repository_state(&path, true).expect_err("normal injected failure");
    assert_eq!(mode(&state), 0o755);
    assert_eq!(mode(&state.join("claims.json")), 0o644);
    assert!(!state.join(AUTH_KEY_FILE).exists());

    set_migration_fault(
        MigrationFaultPoint::AfterPermissions,
        MigrationFaultAction::Crash,
    );
    migrate_repository_state(&path, true).expect_err("crash injected failure");
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&state.join("claims.json")), 0o600);
    let recovered = migrate_repository_state(&path, true).expect("forward recovery");
    assert_eq!(recovered.status, StateMigrationStatus::Applied);
}

#[test]
fn foreign_claims_state_is_refused_even_with_a_valid_checksum() {
    let (_source_temp, _source_path, source_state) = repository_with_claims();
    let (_target_temp, target_path, target_state) = empty_repository_state();
    AtomicStateWriter::write_direct(
        &target_state,
        "claims.json",
        &fs::read(source_state.join("claims.json")).expect("source claims"),
    )
    .expect("copy foreign claims");
    let error = migrate_repository_state(&target_path, false)
        .expect_err("foreign claims binding must fail");
    assert!(error.to_string().contains("repository binding"));
}

#[test]
fn foreign_semantic_state_is_refused_even_with_a_valid_checksum() {
    let (_source_temp, source_path, _source_state) = repository_with_claims();
    let source_binding = expected_bindings_for(&source_path).repository_state;
    let mut foreign = LegacySemanticState {
        version: 2,
        checksum: String::new(),
        repository: source_binding,
        next_token: 1,
        intents: Vec::new(),
    };
    foreign.checksum = stable_checksum(
        &serde_json::to_vec(&(
            foreign.version,
            &foreign.repository,
            foreign.next_token,
            &foreign.intents,
        ))
        .expect("semantic checksum payload"),
    );
    let (_target_temp, target_path, target_state) = empty_repository_state();
    AtomicStateWriter::write_direct(
        &target_state,
        "semantic_intents.json",
        &serde_json::to_vec_pretty(&foreign).expect("semantic state"),
    )
    .expect("write foreign semantic state");
    let error = migrate_repository_state(&target_path, false)
        .expect_err("foreign semantic binding must fail");
    assert!(error.to_string().contains("repository binding"));
}

#[test]
fn foreign_managed_registry_is_refused_even_with_a_valid_checksum() {
    let (_source_temp, source_path, _source_state) = repository_with_claims();
    let source_repository = expected_bindings_for(&source_path)
        .managed_repository
        .expect("managed source binding");
    let mut foreign = ManagedWorktreeRegistryWire {
        version: 2,
        checksum: String::new(),
        repository: source_repository,
        records: BTreeMap::new(),
        operations: BTreeMap::new(),
    };
    foreign.checksum = stable_checksum(
        &serde_json::to_vec(&(
            foreign.version,
            &foreign.repository,
            &foreign.records,
            &foreign.operations,
        ))
        .expect("managed checksum payload"),
    );
    let (_target_temp, target_path, target_state) = empty_repository_state();
    AtomicStateWriter::write_direct(
        &target_state,
        "managed_worktrees.json",
        &serde_json::to_vec_pretty(&foreign).expect("managed state"),
    )
    .expect("write foreign managed registry");
    let error = migrate_repository_state(&target_path, false)
        .expect_err("foreign managed binding must fail");
    assert!(error.to_string().contains("repository binding"));
}
