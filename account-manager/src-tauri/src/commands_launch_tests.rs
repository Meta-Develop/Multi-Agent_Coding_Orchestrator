use super::*;
use crate::model::{
    Account, AuthKind, ProviderDescriptor, StoredAccountMaterial, StoredAccountMetadata,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const PROVIDER: &str = "desktop-lease-probe";

struct ProbeAdapter {
    directory: PathBuf,
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

    fn detect(&self) -> crate::model::InstallState {
        crate::model::InstallState::Unknown
    }

    fn list_accounts(&self) -> Result<Vec<Account>> {
        Ok(Vec::new())
    }

    fn activation_mechanism(&self) -> ActivationMechanism {
        ActivationMechanism::LaunchEnvironment
    }

    fn launch_spec(&self, _account: &StoredAccountMetadata) -> Result<providers::LaunchSpec> {
        let registry = crate::account_authority::StoredAccountRegistry::new(
            self.directory.join("accounts.json"),
        );
        assert!(matches!(
            registry.begin_delete(PROVIDER, "work"),
            Err(Error::AccountAuthorityBusy { .. })
        ));
        Ok(providers::LaunchSpec::new(std::env::current_exe()?)
            .current_dir(&self.directory)
            .arg("--exact")
            .arg("launch_client::tests::launch_child_probe")
            .arg("--nocapture")
            .set_plain_env("CAM_DESKTOP_LEASE_BARRIER", &self.directory))
    }

    fn activate_account(&self, _account_id: &str) -> Result<()> {
        Err(Error::NotImplemented("fixture activate"))
    }
}

fn await_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(Instant::now() < deadline, "desktop child barrier timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn launch_child_probe() {
    let Some(directory) = std::env::var_os("CAM_DESKTOP_LEASE_BARRIER") else {
        return;
    };
    let directory = PathBuf::from(directory);
    fs::write(directory.join("ready"), b"ready").unwrap();
    await_file(&directory.join("release"));
}

#[test]
fn launch_reaper_retains_exact_selected_use_lease() {
    let directory = tempfile::tempdir().unwrap();
    let adapter = ProbeAdapter {
        directory: directory.path().to_path_buf(),
    };
    let registry = crate::account_authority::StoredAccountRegistry::new(
        directory.path().join("accounts.json"),
    );
    for id in ["work", "other"] {
        registry
            .begin_add(
                PROVIDER,
                id,
                id,
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )
            .unwrap();
        registry.complete_add(PROVIDER, id).unwrap();
    }
    registry.select_complete(PROVIDER, "work").unwrap();
    let expected = registry.selected_binding(PROVIDER).unwrap().unwrap();
    let authority = AccountAuthority::InProcess(registry);
    let service = ManagedLaunchService::new(authority);
    let DesktopLaunch::Local(process) = service.start(&adapter).unwrap() else {
        panic!("expected local launch");
    };
    let registry = service.authority.in_process_registry().unwrap();
    assert_eq!(process.provider_id, expected.provider_id);
    assert_eq!(process.account_id, expected.account_id);
    assert_ne!(process.process_id, 0);
    await_file(&directory.path().join("ready"));
    let future = registry
        .select_complete_revision(PROVIDER, "other", Some(expected.selection_revision))
        .unwrap();
    assert_eq!(future.account_id, "other");
    assert_eq!(process.account_id, expected.account_id);
    registry.begin_delete(PROVIDER, "other").unwrap();
    registry.finish_delete(PROVIDER, "other").unwrap();
    let deletion = registry.begin_delete(PROVIDER, "work");
    // Always release the fixture child before asserting, including on failure.
    fs::write(directory.path().join("release"), b"ok").unwrap();
    assert!(matches!(deletion, Err(Error::AccountAuthorityBusy { .. })));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match registry.begin_delete(PROVIDER, "work") {
            Ok(()) => break,
            Err(Error::AccountAuthorityBusy { .. }) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => panic!("desktop reaper did not release lease: {result:?}"),
        }
    }
    registry.finish_delete(PROVIDER, "work").unwrap();
}
