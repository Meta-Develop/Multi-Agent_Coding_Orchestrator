//! Child custody for an exact, leased stored-account selection.

use std::io;
use std::process::{Child, ExitStatus};

use crate::account_authority::{SelectedAccountBinding, SelectedUseLease, StoredAccountRegistry};
use crate::error::{Error, Result};
use crate::storage::CredentialStore;

use super::{launch_spec_for, spawn_launch, ProviderAdapter};

/// A child and its selected-account use lease, transferred together to a reaper.
///
/// Only a confirmed exit releases the lease. Dropping custody while exit is
/// unknown retains the lease until this application exits, so an unsuccessful
/// reaper cannot permit replacement of material still used by a child.
#[must_use = "the selected-account child must be reaped"]
pub struct LeasedChild {
    child: Child,
    binding: SelectedAccountBinding,
    lease: Option<SelectedUseLease>,
}

impl LeasedChild {
    /// Request termination of this exact child without releasing its use lease.
    pub(crate) fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn binding(&self) -> &SelectedAccountBinding {
        &self.binding
    }

    /// Wait for exit, retaining the lease if the wait fails.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.lease.take();
        Ok(status)
    }

    /// Poll for exit, retaining the lease while alive or if the poll fails.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.lease.take();
        }
        Ok(status)
    }
}

impl Drop for LeasedChild {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            if !matches!(self.child.try_wait(), Ok(Some(_))) {
                // Child::drop does not wait. Keep the active-use barrier even
                // if custody is abandoned or a reaper cannot confirm exit.
                std::mem::forget(lease);
            }
        }
    }
}

/// Validate and lease a frozen binding before adapter or credential resolution.
///
/// The credential-store factory runs only when the adapter requires one, under
/// the same lease as material retrieval and spawn. Any pre-spawn failure drops
/// the lease normally. The returned custody exposes no unleased child handle.
pub fn spawn_selected_launch(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    binding: &SelectedAccountBinding,
    credential_store: impl FnOnce() -> Result<Box<dyn CredentialStore>>,
) -> Result<LeasedChild> {
    spawn_selected_launch_inner(registry, adapter, binding, credential_store, false)
}

/// Service-owned launches have no connection to a requesting client's stdio.
pub(crate) fn spawn_service_launch(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    binding: &SelectedAccountBinding,
    credential_store: impl FnOnce() -> Result<Box<dyn CredentialStore>>,
) -> Result<LeasedChild> {
    spawn_selected_launch_inner(registry, adapter, binding, credential_store, true)
}

fn spawn_selected_launch_inner(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    binding: &SelectedAccountBinding,
    credential_store: impl FnOnce() -> Result<Box<dyn CredentialStore>>,
    detached: bool,
) -> Result<LeasedChild> {
    if binding.provider_id != adapter.id() {
        return Err(Error::UnknownProvider(binding.provider_id.clone()));
    }
    let lease = registry.acquire_selected_use(binding)?;
    let account = registry.complete(adapter.id(), &binding.account_id)?;
    let spec = launch_spec_for(adapter, &account)?;
    let spec = if detached { spec.detach_stdio() } else { spec };
    let store = spec
        .requires_credential()
        .then(credential_store)
        .transpose()?;
    let child = spawn_launch(spec, &account, store.as_deref())?;
    Ok(LeasedChild {
        child,
        binding: binding.clone(),
        lease: Some(lease),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::model::{
        Account, AuthKind, InstallState, ProviderDescriptor, StoredAccountMaterial,
        StoredAccountMetadata,
    };
    use crate::providers::{ActivationMechanism, LaunchSpec};
    use crate::storage::{Secret, SecretRef};

    const PROVIDER: &str = "lease-probe";
    const FAKE_SECRET: &[u8] = b"FAKE-selected-lease-secret";

    struct ProbeAdapter {
        registry: Arc<StoredAccountRegistry>,
        binding: SelectedAccountBinding,
        spec: LaunchSpec,
        declarations: AtomicUsize,
        refuse: bool,
    }

    impl ProviderAdapter for ProbeAdapter {
        fn id(&self) -> &'static str {
            PROVIDER
        }

        fn descriptor(&self) -> ProviderDescriptor {
            unimplemented!("not used by launch fixture")
        }

        fn config_paths(&self) -> Vec<PathBuf> {
            Vec::new()
        }

        fn detect(&self) -> InstallState {
            InstallState::Unknown
        }

        fn list_accounts(&self) -> Result<Vec<Account>> {
            Ok(Vec::new())
        }

        fn activation_mechanism(&self) -> ActivationMechanism {
            ActivationMechanism::LaunchEnvironment
        }

        fn activate_account(&self, _account_id: &str) -> Result<()> {
            Err(Error::NotImplemented("fixture activate"))
        }

        fn launch_spec(&self, account: &StoredAccountMetadata) -> Result<LaunchSpec> {
            self.declarations.fetch_add(1, Ordering::SeqCst);
            assert_eq!(account.id, self.binding.account_id);
            assert_eq!(
                account.account_incarnation,
                self.binding.account_incarnation
            );
            assert_in_use(&self.registry);
            if self.refuse {
                return Err(Error::NotImplemented("fixture launch refusal"));
            }
            Ok(self.spec.clone())
        }
    }

    struct ProbeStore {
        registry: Arc<StoredAccountRegistry>,
        reads: Arc<AtomicUsize>,
        missing: bool,
    }

    impl CredentialStore for ProbeStore {
        fn id(&self) -> &'static str {
            "lease-fixture"
        }

        fn is_available(&self) -> bool {
            true
        }

        fn put(&self, _key: &SecretRef, _secret: &Secret) -> Result<()> {
            unimplemented!("fixture material is synthetic")
        }

        fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
            assert_eq!(*key, SecretRef::for_account(PROVIDER, "work"));
            assert_in_use(&self.registry);
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok((!self.missing).then(|| Secret::new(FAKE_SECRET.to_vec())))
        }

        fn delete(&self, _key: &SecretRef) -> Result<()> {
            unimplemented!("fixture does not delete material")
        }
    }

    fn assert_in_use(registry: &StoredAccountRegistry) {
        assert!(matches!(
            registry.begin_delete(PROVIDER, "work"),
            Err(Error::AccountAuthorityBusy { .. })
        ));
        assert!(matches!(
            registry.select_complete(PROVIDER, "other"),
            Err(Error::AccountAuthorityBusy { .. })
        ));
    }

    fn fixture(directory: &Path) -> ProbeAdapter {
        fixture_with_material(directory, StoredAccountMaterial::CredentialStore)
    }

    fn fixture_with_material(directory: &Path, material: StoredAccountMaterial) -> ProbeAdapter {
        let registry = Arc::new(StoredAccountRegistry::new(directory.join("accounts.json")));
        for account in ["work", "other"] {
            registry
                .begin_add(PROVIDER, account, account, AuthKind::ApiKey, material)
                .unwrap();
            registry.complete_add(PROVIDER, account).unwrap();
        }
        registry.select_complete(PROVIDER, "work").unwrap();
        let binding = registry.selected_binding(PROVIDER).unwrap().unwrap();
        let spec = LaunchSpec::new(std::env::current_exe().unwrap())
            .current_dir(directory)
            .arg("--exact")
            .arg("providers::leased_launch::tests::leased_child_probe")
            .arg("--nocapture")
            .set_plain_env("CAM_LEASE_PROBE_DIRECTORY", directory);
        let spec = if material == StoredAccountMaterial::CredentialStore {
            spec.set_secret_env("CAM_LEASE_PROBE_SECRET")
        } else {
            spec.remove_env("CAM_LEASE_PROBE_SECRET")
        };
        ProbeAdapter {
            registry,
            binding,
            spec,
            declarations: AtomicUsize::new(0),
            refuse: false,
        }
    }

    fn await_file(path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !path.exists() {
            assert!(Instant::now() < deadline, "child barrier timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn release_child(directory: &Path, payload: &[u8]) {
        let pending = directory.join("release.pending");
        fs::write(&pending, payload).unwrap();
        fs::rename(pending, directory.join("release")).unwrap();
    }

    // Test cleanup signals only the child owned by this fixture, even on panic.
    struct TestChild(LeasedChild);

    impl Drop for TestChild {
        fn drop(&mut self) {
            if self.0.lease.is_some() {
                let _ = self.0.child.kill();
                let _ = self.0.wait();
            }
        }
    }

    #[test]
    fn leased_child_probe() {
        let Some(directory) = std::env::var_os("CAM_LEASE_PROBE_DIRECTORY") else {
            return;
        };
        if let Ok(secret) = std::env::var("CAM_LEASE_PROBE_SECRET") {
            assert_eq!(secret.as_bytes(), FAKE_SECRET);
        }
        let directory = PathBuf::from(directory);
        fs::write(directory.join("ready"), b"ready").unwrap();
        await_file(&directory.join("release"));
        match fs::read(directory.join("release")).unwrap().as_slice() {
            b"ok" => {}
            b"nonzero" => panic!("requested nonzero child exit"),
            _ => panic!("invalid child release payload"),
        }
    }

    #[test]
    fn selected_material_is_held_until_confirmed_exit() {
        for nonzero in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let adapter = fixture(directory.path());
            let registry = Arc::clone(&adapter.registry);
            let reads = Arc::new(AtomicUsize::new(0));
            let child = spawn_selected_launch(&registry, &adapter, &adapter.binding, || {
                assert_in_use(&registry);
                Ok(Box::new(ProbeStore {
                    registry: Arc::clone(&registry),
                    reads: Arc::clone(&reads),
                    missing: false,
                }))
            })
            .unwrap();
            let mut child = TestChild(child);
            assert_eq!(child.0.binding(), &adapter.binding);
            assert_eq!(reads.load(Ordering::SeqCst), 1);
            await_file(&directory.path().join("ready"));
            assert!(child.0.try_wait().unwrap().is_none());
            assert_in_use(&registry);
            let reaper = std::thread::spawn(move || child.0.wait());
            assert_in_use(&registry);
            release_child(
                directory.path(),
                if nonzero {
                    b"nonzero".as_slice()
                } else {
                    b"ok"
                },
            );
            let status = reaper.join().unwrap().unwrap();
            assert_eq!(status.success(), !nonzero);
            registry.select_complete(PROVIDER, "other").unwrap();
            registry.begin_delete(PROVIDER, "work").unwrap();
            registry.finish_delete(PROVIDER, "work").unwrap();
            registry
                .begin_add(
                    PROVIDER,
                    "work",
                    "Replacement",
                    AuthKind::ApiKey,
                    StoredAccountMaterial::CredentialStore,
                )
                .unwrap();
            assert_ne!(
                registry
                    .account(PROVIDER, "work")
                    .unwrap()
                    .account_incarnation,
                adapter.binding.account_incarnation
            );
        }
    }

    #[test]
    fn launch_failures_release_selected_use() {
        for failure in ["adapter", "store", "material", "spawn"] {
            let directory = tempfile::tempdir().unwrap();
            let mut adapter = fixture(directory.path());
            adapter.refuse = failure == "adapter";
            if failure == "spawn" {
                adapter.spec.program = directory.path().join("missing-provider-executable");
            }
            let registry = &adapter.registry;
            let error = spawn_selected_launch(registry, &adapter, &adapter.binding, || {
                assert_in_use(registry);
                if failure == "store" {
                    return Err(Error::CredentialStoreUnavailable(
                        "fixture unavailable".into(),
                    ));
                }
                Ok(Box::new(ProbeStore {
                    registry: Arc::clone(registry),
                    reads: Arc::new(AtomicUsize::new(0)),
                    missing: failure == "material",
                }))
            })
            .err()
            .expect("launch must fail");
            assert!(!error
                .to_string()
                .contains(std::str::from_utf8(FAKE_SECRET).unwrap()));
            registry.select_complete(PROVIDER, "other").unwrap();
            registry.begin_delete(PROVIDER, "work").unwrap();
            registry.finish_delete(PROVIDER, "work").unwrap();
        }
    }

    #[test]
    fn vendor_home_poll_releases_only_after_exit() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = fixture_with_material(directory.path(), StoredAccountMaterial::VendorHome);
        let registry = &adapter.registry;
        let mut child = TestChild(
            spawn_selected_launch(registry, &adapter, &adapter.binding, || {
                panic!("vendor-home launch must not resolve a credential store")
            })
            .unwrap(),
        );
        await_file(&directory.path().join("ready"));
        assert!(child.0.try_wait().unwrap().is_none());
        assert_in_use(registry);
        release_child(directory.path(), b"ok");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "child did not exit");
            assert_in_use(registry);
            std::thread::sleep(Duration::from_millis(10));
        }
        registry.begin_delete(PROVIDER, "work").unwrap();
    }

    #[test]
    fn stale_binding_refuses_launch_before_resolution() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = fixture(directory.path());
        let registry = &adapter.registry;
        registry.select_complete(PROVIDER, "other").unwrap();
        let error = spawn_selected_launch(registry, &adapter, &adapter.binding, || {
            panic!("stale selection must not resolve a store")
        })
        .err()
        .unwrap();
        assert!(matches!(error, Error::StaleSelection { .. }));
        registry.begin_delete(PROVIDER, "work").unwrap();
        registry.finish_delete(PROVIDER, "work").unwrap();
        registry
            .begin_add(
                PROVIDER,
                "work",
                "Replacement",
                AuthKind::ApiKey,
                StoredAccountMaterial::CredentialStore,
            )
            .unwrap();
        registry.complete_add(PROVIDER, "work").unwrap();
        registry.select_complete(PROVIDER, "work").unwrap();
        let mut stale = adapter.binding.clone();
        // Even the current revision cannot authorize the old incarnation.
        stale.selection_revision = registry.selection_revision(PROVIDER).unwrap();
        let error = spawn_selected_launch(registry, &adapter, &stale, || {
            panic!("stale incarnation must not resolve a store")
        })
        .err()
        .unwrap();
        assert!(matches!(error, Error::StaleAccount { .. }));
        stale.provider_id = "different-provider".into();
        assert!(matches!(
            spawn_selected_launch(registry, &adapter, &stale, || {
                panic!("provider mismatch must not resolve a store")
            }),
            Err(Error::UnknownProvider(_))
        ));
        assert_eq!(adapter.declarations.load(Ordering::SeqCst), 0);
        registry.begin_delete(PROVIDER, "work").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn wait_error_retains_selected_use() {
        let directory = tempfile::tempdir().unwrap();
        let adapter = fixture(directory.path());
        let registry = &adapter.registry;
        let mut child = spawn_selected_launch(registry, &adapter, &adapter.binding, || {
            Ok(Box::new(ProbeStore {
                registry: Arc::clone(registry),
                reads: Arc::new(AtomicUsize::new(0)),
                missing: false,
            }))
        })
        .unwrap();
        await_file(&directory.path().join("ready"));
        release_child(directory.path(), b"ok");
        // Reap this exact test-owned PID outside Child to force ECHILD. The
        // custody's wait cannot confirm exit and must retain its use barrier.
        let pid = child.id() as libc::pid_t;
        let mut status = 0;
        loop {
            // SAFETY: pid names only this fixture's child, and status is writable.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == pid {
                break;
            }
            assert_eq!(
                io::Error::last_os_error().kind(),
                io::ErrorKind::Interrupted
            );
        }
        assert!(child.wait().is_err());
        assert!(child.try_wait().is_err());
        assert_in_use(registry);
        // Match the reaper's error path: dropping unconfirmed custody must
        // retain the use barrier until application exit.
        drop(child);
        assert!(matches!(
            registry.begin_delete(PROVIDER, "work"),
            Err(Error::AccountAuthorityBusy { .. })
        ));
    }
}
