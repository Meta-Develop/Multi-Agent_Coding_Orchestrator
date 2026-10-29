use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::*;
use crate::model::{
    Account, AuthKind, InstallState, ProviderDescriptor, StoredAccountMaterial,
    StoredAccountMetadata,
};
use crate::providers::{ActivationMechanism, LaunchSpec};
use crate::storage::Secret;

const PROVIDER: &str = "lifecycle-probe";
const SECRET: &[u8] = b"FAKE-lifecycle-selected-material";
const SECRET_ENV: &str = "CAM_LIFECYCLE_SECRET";
const REMOVED_ENV: &str = "CAM_LIFECYCLE_REMOVE";
const CHILD_TEST: &str = "providers::launch_lifecycle::tests::lifecycle_child_probe";

struct Fixture {
    directory: tempfile::TempDir,
    registry: StoredAccountRegistry,
    binding: SelectedAccountBinding,
    spec: LaunchSpec,
    declarations: AtomicUsize,
    refuse: bool,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let registry = StoredAccountRegistry::new(directory.path().join("accounts.json"));
        for name in ["work", "other"] {
            registry
                .begin_add(
                    PROVIDER,
                    name,
                    name,
                    AuthKind::ApiKey,
                    StoredAccountMaterial::CredentialStore,
                )
                .unwrap();
            registry.complete_add(PROVIDER, name).unwrap();
        }
        registry.select_complete(PROVIDER, "work").unwrap();
        let binding = registry.selected_binding(PROVIDER).unwrap().unwrap();
        let spec = LaunchSpec::new(std::env::current_exe().unwrap())
            .current_dir(directory.path())
            .arg("--exact")
            .arg(CHILD_TEST)
            .arg("--nocapture")
            .set_plain_env("CAM_LIFECYCLE_DIRECTORY", directory.path())
            .credential_environment_inputs([SECRET_ENV, REMOVED_ENV])
            .set_secret_env(SECRET_ENV)
            .remove_env(REMOVED_ENV);
        Self {
            directory,
            registry,
            binding,
            spec,
            declarations: AtomicUsize::new(0),
            refuse: false,
        }
    }

    fn guard(&self) -> LaunchLifecycle {
        LaunchLifecycle::new("run-725", "operation-1", self.binding.clone(), None).unwrap()
    }

    fn busy(&self) {
        assert!(matches!(
            self.registry.begin_delete(PROVIDER, "work"),
            Err(Error::AccountAuthorityBusy { .. })
        ));
    }

    fn released(&self) {
        self.registry.select_complete(PROVIDER, "other").unwrap();
        self.registry.begin_delete(PROVIDER, "work").unwrap();
    }
}

impl ProviderAdapter for Fixture {
    fn id(&self) -> &'static str {
        PROVIDER
    }
    fn descriptor(&self) -> ProviderDescriptor {
        unimplemented!()
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
    fn activate_account(&self, _: &str) -> Result<()> {
        unimplemented!()
    }
    fn launch_spec(&self, account: &StoredAccountMetadata) -> Result<LaunchSpec> {
        self.declarations.fetch_add(1, Ordering::SeqCst);
        self.busy();
        assert_eq!(
            account.account_incarnation,
            self.binding.account_incarnation
        );
        if self.refuse {
            return Err(Error::NotImplemented("fixture refusal"));
        }
        Ok(self.spec.clone())
    }
}

// The factory owns only synthetic material, never an OS credential backend.
struct OwnedStore {
    fixture: Arc<Fixture>,
    handle: LaunchLifecycleHandle,
    revoke: bool,
    missing: bool,
    reads: Arc<AtomicUsize>,
}

impl CredentialStore for OwnedStore {
    fn id(&self) -> &'static str {
        "synthetic-lifecycle"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn put(&self, _: &SecretRef, _: &Secret) -> Result<()> {
        unimplemented!()
    }
    fn delete(&self, _: &SecretRef) -> Result<()> {
        unimplemented!()
    }
    fn get(&self, key: &SecretRef) -> Result<Option<Secret>> {
        assert_eq!(*key, SecretRef::for_account(PROVIDER, "work"));
        assert_eq!(self.handle.snapshot().phase, LaunchPhase::Constructing);
        self.fixture.busy();
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.revoke {
            self.handle.revoke_before_spawn().unwrap();
        }
        Ok((!self.missing).then(|| Secret::new(SECRET.to_vec())))
    }
}

fn spawn(
    fixture: &Arc<Fixture>,
    guard: LaunchLifecycle,
    revoke: bool,
    missing: bool,
    reads: Arc<AtomicUsize>,
) -> Result<LeasedChild> {
    let handle = guard.handle();
    guard.spawn(&fixture.registry, fixture.as_ref(), || {
        fixture.busy();
        Ok(Box::new(OwnedStore {
            fixture: Arc::clone(fixture),
            handle,
            revoke,
            missing,
            reads,
        }))
    })
}

fn await_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(Instant::now() < deadline, "child barrier timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn release_child(fixture: &Fixture, payload: &[u8]) {
    let pending = fixture.directory.path().join("release.pending");
    fs::write(&pending, payload).unwrap();
    fs::rename(pending, fixture.directory.path().join("release")).unwrap();
}

struct TestChild(LeasedChild);
impl Drop for TestChild {
    fn drop(&mut self) {
        let _ = self.0.cancel();
    }
}

#[test]
fn lifecycle_child_probe() {
    let Some(directory) = std::env::var_os("CAM_LIFECYCLE_DIRECTORY") else {
        return;
    };
    assert_eq!(std::env::var(SECRET_ENV).unwrap().as_bytes(), SECRET);
    assert!(std::env::var_os(REMOVED_ENV).is_none());
    let directory = PathBuf::from(directory);
    fs::write(directory.join("ready"), b"ready").unwrap();
    await_file(&directory.join("release"));
    if fs::read(directory.join("release")).unwrap() == b"nonzero" {
        panic!("synthetic abnormal exit");
    }
}

#[test]
fn guard_refuses_stale_expired_and_revoked_binding() {
    for refusal in [
        "revision",
        "incarnation",
        "deleted",
        "provider",
        "expiry",
        "revoked",
        "drop",
    ] {
        let fixture = Fixture::new();
        let mut binding = fixture.binding.clone();
        match refusal {
            "revision" => fixture.registry.select_complete(PROVIDER, "other").unwrap(),
            "incarnation" => {
                binding.account_incarnation = "00000000000000000000000000000000".into()
            }
            "deleted" => {
                fixture.registry.begin_delete(PROVIDER, "work").unwrap();
            }
            "provider" => binding.provider_id = "different-provider".into(),
            _ => {}
        }
        let guard = LaunchLifecycle::new(
            "run",
            "operation",
            binding,
            (refusal == "expiry").then(Instant::now),
        )
        .unwrap();
        let handle = guard.handle();
        if refusal == "revoked" {
            handle.revoke_before_spawn().unwrap();
        }
        if refusal == "drop" {
            drop(guard);
        } else {
            assert!(guard
                .spawn(&fixture.registry, &fixture, || {
                    panic!("refused launch must not resolve a store")
                })
                .is_err());
        }
        assert_eq!(
            handle.snapshot().phase,
            LaunchPhase::Finalized(LaunchFinalization::Refused)
        );
        assert_eq!(fixture.declarations.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn guard_finalizes_resolution_and_spawn_failures() {
    for failure in ["adapter", "store", "missing", "spawn"] {
        let mut fixture = Fixture::new();
        fixture.refuse = failure == "adapter";
        if failure == "spawn" {
            fixture.spec.program = fixture.directory.path().join("missing-tool");
        }
        let fixture = Arc::new(fixture);
        let guard = fixture.guard();
        let handle = guard.handle();
        let result = if failure == "store" {
            guard.spawn(&fixture.registry, fixture.as_ref(), || {
                Err(Error::NotImplemented("fixture store"))
            })
        } else {
            spawn(
                &fixture,
                guard,
                false,
                failure == "missing",
                Arc::new(AtomicUsize::new(0)),
            )
        };
        assert!(result.is_err());
        let reason = if failure == "spawn" {
            LaunchFinalization::SpawnFailed
        } else {
            LaunchFinalization::Refused
        };
        assert_eq!(handle.snapshot().phase, LaunchPhase::Finalized(reason));
        assert!(!format!("{:?}", handle.snapshot()).contains(std::str::from_utf8(SECRET).unwrap()));
        fixture.released();
    }
}

#[test]
fn guard_tracks_exit_and_reference_only_metadata() {
    for nonzero in [false, true] {
        let fixture = Arc::new(Fixture::new());
        let guard = fixture.guard();
        let handle = guard.handle();
        let reads = Arc::new(AtomicUsize::new(0));
        let mut child =
            TestChild(spawn(&fixture, guard, false, false, Arc::clone(&reads)).unwrap());
        await_file(&fixture.directory.path().join("ready"));
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        let view = handle.snapshot();
        assert_eq!(view.run_id, "run-725");
        assert_eq!(view.operation_id, "operation-1");
        assert_eq!(view.binding, fixture.binding);
        assert_eq!(
            view.credential,
            Some(SecretRef::for_account(PROVIDER, "work"))
        );
        assert_eq!(
            view.environment,
            vec![
                CredentialEnvironmentInput::SelectedCredential(SECRET_ENV.into()),
                CredentialEnvironmentInput::Removed(REMOVED_ENV.into()),
            ]
        );
        assert_eq!(child.0.lifecycle().snapshot(), view);
        assert!(handle.revoke_before_spawn().is_err());
        assert!(child.0.try_wait().unwrap().is_none());
        fixture.busy();
        release_child(
            &fixture,
            if nonzero {
                b"nonzero".as_slice()
            } else {
                b"ok"
            },
        );
        assert_eq!(child.0.wait().unwrap().success(), !nonzero);
        let finalized = handle.snapshot();
        assert_eq!(
            finalized.phase,
            LaunchPhase::Finalized(if nonzero {
                LaunchFinalization::AbnormalExit
            } else {
                LaunchFinalization::Exited
            })
        );
        child.0.wait().unwrap();
        child.0.try_wait().unwrap();
        child.0.cancel().unwrap();
        drop(child);
        assert_eq!(handle.snapshot(), finalized);
        fixture.released();
    }
}

#[test]
fn guard_cancellation_finalizes_only_confirmed_exit() {
    let fixture = Arc::new(Fixture::new());
    let guard = fixture.guard();
    let handle = guard.handle();
    let mut child =
        TestChild(spawn(&fixture, guard, false, false, Arc::new(AtomicUsize::new(0))).unwrap());
    await_file(&fixture.directory.path().join("ready"));
    fixture.busy();
    child.0.cancel().unwrap();
    assert_eq!(
        handle.snapshot().phase,
        LaunchPhase::Finalized(LaunchFinalization::Cancelled)
    );
    child.0.wait().unwrap();
    drop(child);
    assert_eq!(
        handle.snapshot().phase,
        LaunchPhase::Finalized(LaunchFinalization::Cancelled)
    );
    fixture.released();
}

#[test]
fn guard_rechecks_revocation_after_material_resolution() {
    let fixture = Arc::new(Fixture::new());
    let guard = fixture.guard();
    let handle = guard.handle();
    let reads = Arc::new(AtomicUsize::new(0));
    assert!(spawn(&fixture, guard, true, false, Arc::clone(&reads)).is_err());
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        handle.snapshot().phase,
        LaunchPhase::Finalized(LaunchFinalization::Refused)
    );
    assert!(!fixture.directory.path().join("ready").exists());
    fixture.released();
}

#[test]
fn guard_rejects_unconfined_inherited_credential_inputs() {
    for failure in ["missing", "plain", "case-shadow"] {
        let mut fixture = Fixture::new();
        if failure == "case-shadow" {
            fixture.spec = fixture
                .spec
                .set_plain_env("cam_lifecycle_secret", "public-value");
        } else {
            fixture.spec = fixture
                .spec
                .credential_environment_inputs(["CAM_UNCONFINED"]);
        }
        if failure == "plain" {
            fixture.spec = fixture.spec.set_plain_env("CAM_UNCONFINED", "public-value");
        }
        let guard = fixture.guard();
        let handle = guard.handle();
        assert!(guard
            .spawn(&fixture.registry, &fixture, || panic!(
                "invalid environment must not resolve material"
            ))
            .is_err());
        assert_eq!(
            handle.snapshot().phase,
            LaunchPhase::Finalized(LaunchFinalization::Refused)
        );
        fixture.released();
    }
}

#[test]
fn guard_confines_inherited_synthetic_environment() {
    const MARKER: &str = "CAM_LIFECYCLE_PARENT_PROBE";
    const INHERITED: &str = "FAKE-inherited-material";
    if std::env::var_os(MARKER).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("providers::launch_lifecycle::tests::guard_confines_inherited_synthetic_environment")
            .env(MARKER, "1")
            .env(SECRET_ENV, INHERITED)
            .env(REMOVED_ENV, INHERITED)
            .status().unwrap();
        assert!(status.success());
        return;
    }
    let fixture = Arc::new(Fixture::new());
    let mut child = TestChild(
        spawn(
            &fixture,
            fixture.guard(),
            false,
            false,
            Arc::new(AtomicUsize::new(0)),
        )
        .unwrap(),
    );
    await_file(&fixture.directory.path().join("ready"));
    release_child(&fixture, b"ok");
    assert!(child.0.wait().unwrap().success());
    assert_eq!(std::env::var(SECRET_ENV).unwrap(), INHERITED);
    assert_eq!(std::env::var(REMOVED_ENV).unwrap(), INHERITED);
    fixture.released();
}

#[cfg(unix)]
#[test]
fn guard_retains_custody_when_exit_is_unknown() {
    let fixture = Arc::new(Fixture::new());
    let guard = fixture.guard();
    let handle = guard.handle();
    let mut child = spawn(&fixture, guard, false, false, Arc::new(AtomicUsize::new(0))).unwrap();
    await_file(&fixture.directory.path().join("ready"));
    release_child(&fixture, b"ok");
    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    loop {
        // SAFETY: pid is this fixture's exact child; status points to writable memory.
        if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
            break;
        }
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted
        );
    }
    assert!(child.wait().is_err());
    assert!(child.cancel().is_err());
    assert_eq!(handle.snapshot().phase, LaunchPhase::ExitUnknown);
    fixture.busy();
    drop(child);
    assert_eq!(handle.snapshot().phase, LaunchPhase::ExitUnknown);
    fixture.busy();
}
