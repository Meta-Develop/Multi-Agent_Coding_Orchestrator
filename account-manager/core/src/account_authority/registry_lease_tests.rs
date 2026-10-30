use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

const PROVIDER: &str = "lease-fixture";

#[derive(Default)]
struct Store {
    puts: AtomicUsize,
    deletes: AtomicUsize,
}

impl CredentialStore for Store {
    fn id(&self) -> &'static str {
        "lease-fixture"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn put(&self, _: &SecretRef, _: &Secret) -> Result<()> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn get(&self, _: &SecretRef) -> Result<Option<Secret>> {
        Ok(None)
    }
    fn delete(&self, _: &SecretRef) -> Result<()> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn add(registry: &StoredAccountRegistry, store: &Store, id: &str) {
    registry
        .add_with_secret(
            PROVIDER,
            id,
            id,
            AuthKind::ApiKey,
            &Secret::new(b"FAKE-lease-material".to_vec()),
            store,
        )
        .unwrap();
}

#[test]
fn selected_lease_protects_material_while_future_selection_and_other_accounts_change() {
    let directory = tempfile::tempdir().unwrap();
    let registry = StoredAccountRegistry::new(directory.path().join("accounts.json"));
    let store = Store::default();
    add(&registry, &store, "work");
    add(&registry, &store, "other");
    let binding = registry
        .select_complete_revision(PROVIDER, "work", None)
        .unwrap();
    let (lease, frozen) = registry.acquire_selected_use_snapshot(&binding).unwrap();
    let future = registry
        .select_complete_revision(PROVIDER, "other", Some(binding.selection_revision))
        .unwrap();
    assert!(future.selection_revision > binding.selection_revision);
    assert!(frozen.is_selected);
    assert_eq!(frozen.account_incarnation, binding.account_incarnation);
    assert!(!registry.account(PROVIDER, "work").unwrap().is_selected);
    assert!(matches!(
        registry.select_complete_revision(PROVIDER, "work", Some(binding.selection_revision)),
        Err(Error::StaleSelection { .. })
    ));
    assert!(matches!(
        registry.acquire_selected_use(&binding),
        Err(Error::StaleSelection { .. })
    ));
    let before = fs::read(registry.metadata_path()).unwrap();
    for result in [
        registry.begin_delete(PROVIDER, "work"),
        registry.finish_delete(PROVIDER, "work"),
        registry.delete(PROVIDER, "work", Some(&store)),
    ] {
        assert!(matches!(result, Err(Error::AccountAuthorityBusy { .. })));
    }
    assert!(registry
        .add_with_secret(
            PROVIDER,
            "work",
            "Replacement",
            AuthKind::ApiKey,
            &Secret::new(b"FAKE-replacement".to_vec()),
            &store,
        )
        .is_err());
    assert_eq!(store.puts.load(Ordering::SeqCst), 2);
    assert_eq!(store.deletes.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(registry.metadata_path()).unwrap(), before);

    registry.delete(PROVIDER, "other", Some(&store)).unwrap();
    add(&registry, &store, "other");
    registry
        .begin_add(
            PROVIDER,
            "orphan",
            "Orphan",
            AuthKind::ApiKey,
            StoredAccountMaterial::CredentialStore,
        )
        .unwrap();
    registry.recover(Some(&store)).unwrap();
    assert!(registry.account(PROVIDER, "orphan").is_err());
    assert_eq!(store.deletes.load(Ordering::SeqCst), 2);
    assert_eq!(
        registry
            .account(PROVIDER, "work")
            .unwrap()
            .account_incarnation,
        binding.account_incarnation
    );
    assert!(matches!(
        registry.begin_delete(PROVIDER, "work"),
        Err(Error::AccountAuthorityBusy { .. })
    ));
    drop(lease);
    registry.delete(PROVIDER, "work", Some(&store)).unwrap();
    add(&registry, &store, "work");
    assert_ne!(
        registry
            .account(PROVIDER, "work")
            .unwrap()
            .account_incarnation,
        binding.account_incarnation
    );
}

#[test]
fn lease_barrier_matches_exact_incarnation_and_recovery_checks_every_target() {
    let directory = tempfile::tempdir().unwrap();
    let registry = StoredAccountRegistry::new(directory.path().join("accounts.json"));
    let store = Store::default();
    add(&registry, &store, "work");
    let old = registry
        .select_complete_revision(PROVIDER, "work", None)
        .unwrap();
    registry.delete(PROVIDER, "work", Some(&store)).unwrap();
    add(&registry, &store, "work");
    // A retained lease file for an old incarnation must not protect a new row.
    let old_lease = {
        let _lock = RegistryFileLock::acquire(registry.metadata_path()).unwrap();
        SelectedUseLease::acquire_while_registry_held(registry.metadata_path(), &old).unwrap()
    };
    registry.delete(PROVIDER, "work", Some(&store)).unwrap();
    drop(old_lease);

    for id in ["orphan", "login"] {
        registry
            .begin_add(
                PROVIDER,
                id,
                id,
                AuthKind::ApiKey,
                StoredAccountMaterial::CredentialStore,
            )
            .unwrap();
    }
    let pending = registry.account(PROVIDER, "login").unwrap();
    let login = registry
        .acquire_pending_login_lease(
            PROVIDER,
            "login",
            &pending.account_incarnation,
            AuthKind::ApiKey,
            StoredAccountMaterial::CredentialStore,
        )
        .unwrap();
    let before = fs::read(registry.metadata_path()).unwrap();
    assert!(matches!(
        registry.recover(Some(&store)),
        Err(Error::AccountAuthorityBusy { .. })
    ));
    assert_eq!(store.deletes.load(Ordering::SeqCst), 2);
    assert_eq!(fs::read(registry.metadata_path()).unwrap(), before);
    drop(login);
    registry.recover(Some(&store)).unwrap();
    assert_eq!(store.deletes.load(Ordering::SeqCst), 4);
}

#[test]
fn unknown_lease_state_refuses_selection_and_material_mutations() {
    for invalid in [
        "malformed",
        "directory",
        "directory-root",
        #[cfg(unix)]
        "symlink",
        #[cfg(unix)]
        "symlink-root",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let registry = StoredAccountRegistry::new(directory.path().join("accounts.json"));
        let store = Store::default();
        add(&registry, &store, "work");
        add(&registry, &store, "other");
        registry.begin_delete(PROVIDER, "other").unwrap();
        let before = fs::read(registry.metadata_path()).unwrap();
        let locks = super::super::use_lease::use_lock_dir(registry.metadata_path());
        if invalid == "directory-root" {
            fs::write(&locks, b"FAKE-not-a-directory").unwrap();
        } else if invalid == "symlink-root" {
            #[cfg(unix)]
            {
                let target = directory.path().join("real-locks");
                fs::create_dir(&target).unwrap();
                std::os::unix::fs::symlink(target, &locks).unwrap();
            }
        } else {
            fs::create_dir(&locks).unwrap();
            let name = format!("{PROVIDER}__work__{}.lock", "0".repeat(32));
            if invalid == "directory" {
                fs::create_dir(locks.join(name)).unwrap();
            } else if invalid == "symlink" {
                #[cfg(unix)]
                {
                    let target = directory.path().join("real-lock");
                    fs::write(&target, b"").unwrap();
                    std::os::unix::fs::symlink(target, locks.join(name)).unwrap();
                }
            } else {
                fs::write(locks.join(format!("{PROVIDER}__unknown.lock")), b"").unwrap();
            }
        }
        assert!(registry.select_complete(PROVIDER, "work").is_err());
        assert!(registry.delete(PROVIDER, "work", Some(&store)).is_err());
        assert!(registry.finish_delete(PROVIDER, "other").is_err());
        assert!(registry.recover(Some(&store)).is_err());
        assert_eq!(store.deletes.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read(registry.metadata_path()).unwrap(), before);
    }
}
