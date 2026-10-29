use super::*;
use crate::model::StoredAccountMaterial;
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
            .arg("commands::launch_tests::launch_child_probe")
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
    registry
        .begin_add(
            PROVIDER,
            "work",
            "Work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )
        .unwrap();
    registry.complete_add(PROVIDER, "work").unwrap();
    registry.select_complete(PROVIDER, "work").unwrap();
    let expected = registry.selected_binding(PROVIDER).unwrap().unwrap();
    let authority = AccountAuthority::InProcess(registry);
    let process = launch_provider_with_authority(&adapter, &authority).unwrap();
    let registry = authority.in_process_registry().unwrap();
    assert_eq!(process.provider_id, expected.provider_id);
    assert_eq!(process.account_id, expected.account_id);
    assert_ne!(process.process_id, 0);
    await_file(&directory.path().join("ready"));
    assert_eq!(registry.selected_binding(PROVIDER).unwrap(), Some(expected));
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

#[cfg(unix)]
#[test]
fn socket_backed_launch_remains_refused() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("account.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let authority =
        AccountAuthority::Remote(authority_client::AuthorityClient::connect(&socket).unwrap());
    let adapter = ProbeAdapter { directory: root };
    assert!(matches!(
        launch_provider_with_authority(&adapter, &authority),
        Err(Error::NotImplemented("remote launch_provider"))
    ));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
