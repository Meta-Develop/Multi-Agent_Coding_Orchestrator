//! Verified Grok execution binding to CAM `grok-cli` selected-account authority.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use coding_agent_manager_lib::account_authority::SelectedAccountBinding;
use coding_agent_manager_lib::account_authority::SelectedUseLease;
use coding_agent_manager_lib::account_authority::StoredAccountRegistry;
use coding_agent_manager_lib::error::Error as CamError;
use coding_agent_manager_lib::paths::{project_dirs, stored_accounts_path};
use coding_agent_manager_lib::providers::grok_cli::GrokCliAdapter;
use coding_agent_manager_lib::providers::launch_spec_for;

use super::ManagedGrokAccountSelectionEvidence;

pub(crate) const GROK_CLI_PROVIDER_ID: &str = "grok-cli";

/// Frozen CAM selection, active use lease, and managed `GROK_HOME` for one Grok run.
pub(crate) struct GrokLaunchAuthority {
    registry: StoredAccountRegistry,
    binding: SelectedAccountBinding,
    // Held until this launch authority is dropped, including failed runs.
    _selected_use_lease: SelectedUseLease,
    managed_grok_home: PathBuf,
    launch_env_removals: Vec<String>,
}

impl GrokLaunchAuthority {
    #[cfg(test)]
    pub(crate) fn binding(&self) -> &SelectedAccountBinding {
        &self.binding
    }

    pub(crate) fn selection_evidence(&self) -> ManagedGrokAccountSelectionEvidence {
        ManagedGrokAccountSelectionEvidence {
            provider_id: self.binding.provider_id.clone(),
            account_id: self.binding.account_id.clone(),
            account_incarnation: self.binding.account_incarnation.clone(),
            selection_revision: self.binding.selection_revision,
        }
    }

    pub(crate) fn managed_grok_home(&self) -> &Path {
        &self.managed_grok_home
    }

    pub(crate) fn apply_launch_environment(&self, environment: &mut BTreeMap<String, String>) {
        for name in &self.launch_env_removals {
            environment.remove(name);
        }
    }

    /// Re-read the registry before releasing the target process.
    pub(crate) fn verify_binding_unchanged(&self) -> Result<()> {
        let current = self
            .registry
            .selected_binding(GROK_CLI_PROVIDER_ID)
            .context("failed to read Coding Agent Manager Grok selection")?
            .ok_or_else(|| {
                anyhow!(
                    "no complete account is selected for Coding Agent Manager provider `{GROK_CLI_PROVIDER_ID}`"
                )
            })?;
        if current != self.binding {
            return Err(map_binding_drift(&self.binding, &current));
        }
        Ok(())
    }
}

/// Acquire the selected `grok-cli` binding using production CAM install paths.
pub(crate) fn acquire_grok_launch_authority() -> Result<GrokLaunchAuthority> {
    #[cfg(test)]
    {
        let override_result = CAM_GROK_TEST_OVERRIDE.with(|cell| {
            cell.borrow().as_ref().map(|harness| {
                acquire_grok_launch_authority_from(&harness.registry, &harness.adapter)
            })
        });
        if let Some(result) = override_result {
            return result;
        }
    }
    let data_dir = project_dirs()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .context(
            "Coding Agent Manager data directory is unavailable; install or configure the manager",
        )?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
    acquire_grok_launch_authority_from(&registry, &GrokCliAdapter::default())
}

/// Parameterized acquisition for isolated registry/adapter pairs (unit tests).
pub(crate) fn acquire_grok_launch_authority_from(
    registry: &StoredAccountRegistry,
    adapter: &GrokCliAdapter,
) -> Result<GrokLaunchAuthority> {
    let binding = registry
        .selected_binding(GROK_CLI_PROVIDER_ID)
        .context("failed to read Coding Agent Manager Grok selection")?
        .ok_or_else(|| {
            anyhow!(
                "no complete account is selected for Coding Agent Manager provider `{GROK_CLI_PROVIDER_ID}`"
            )
        })?;
    let selected_use_lease = registry
        .acquire_selected_use(&binding)
        .map_err(map_cam_error)?;
    let account = registry
        .complete(GROK_CLI_PROVIDER_ID, &binding.account_id)
        .map_err(map_cam_error)?;
    let launch_spec = launch_spec_for(adapter, &account).map_err(map_cam_error)?;
    let managed_grok_home = grok_home_from_launch_spec(&launch_spec)
        .context("Coding Agent Manager Grok launch spec did not declare GROK_HOME")?;
    let launch_env_removals = launch_spec.environment_removals();
    Ok(GrokLaunchAuthority {
        registry: StoredAccountRegistry::new(registry.metadata_path()),
        binding,
        _selected_use_lease: selected_use_lease,
        managed_grok_home,
        launch_env_removals,
    })
}

fn grok_home_from_launch_spec(
    spec: &coding_agent_manager_lib::providers::LaunchSpec,
) -> Result<PathBuf> {
    for (name, value) in spec.plain_environment() {
        if name == "GROK_HOME" {
            return Ok(PathBuf::from(value));
        }
    }
    Err(anyhow!(
        "Coding Agent Manager Grok launch spec did not set GROK_HOME"
    ))
}

fn map_binding_drift(
    expected: &SelectedAccountBinding,
    current: &SelectedAccountBinding,
) -> anyhow::Error {
    if current.selection_revision != expected.selection_revision {
        return anyhow!("Coding Agent Manager selection for `{GROK_CLI_PROVIDER_ID}` is stale");
    }
    if current.account_incarnation != expected.account_incarnation {
        return anyhow!(
            "Coding Agent Manager account `{expected_account}` no longer matches the requested incarnation",
            expected_account = expected.account_id
        );
    }
    if current.account_id != expected.account_id {
        return anyhow!(
            "Coding Agent Manager account `{expected_account}` is not the selected account",
            expected_account = expected.account_id
        );
    }
    anyhow!("Coding Agent Manager selection for `{GROK_CLI_PROVIDER_ID}` is stale")
}

fn map_cam_error(error: CamError) -> anyhow::Error {
    match error {
        CamError::NoSelectedAccount(provider) => {
            anyhow!("no complete account is selected for Coding Agent Manager provider `{provider}`")
        }
        CamError::StaleSelection { provider } => {
            anyhow!("Coding Agent Manager selection for `{provider}` is stale")
        }
        CamError::StaleAccount { account_id } => anyhow!(
            "Coding Agent Manager account `{account_id}` no longer matches the requested incarnation"
        ),
        CamError::UnknownAccount(account_id) => {
            anyhow!("Coding Agent Manager account `{account_id}` is not registered")
        }
        CamError::AccountAuthorityBusy { reason } => {
            anyhow!("Coding Agent Manager account authority is busy: {reason}")
        }
        CamError::CredentialStoreUnavailable(reason) => {
            anyhow!("Coding Agent Manager credential store is unavailable: {reason}")
        }
        CamError::ConfigRead { provider, reason } => anyhow!(
            "Coding Agent Manager configuration for `{provider}` could not be read: {reason}"
        ),
        CamError::ConfigWrite { provider, reason } => anyhow!(
            "Coding Agent Manager configuration for `{provider}` could not be written: {reason}"
        ),
        CamError::UnknownProvider(provider) => {
            anyhow!("Coding Agent Manager provider `{provider}` is not registered")
        }
        CamError::ProviderNotInstalled { provider } => {
            anyhow!("Coding Agent Manager provider `{provider}` is not installed on this machine")
        }
        CamError::NotImplemented(feature) => {
            anyhow!("Coding Agent Manager does not implement `{feature}` yet")
        }
        CamError::Io(error) => error.into(),
        CamError::Serde(error) => error.into(),
    }
}

#[cfg(test)]
pub(crate) struct CamGrokTestHarness {
    pub(crate) _root: tempfile::TempDir,
    pub(crate) registry: StoredAccountRegistry,
    pub(crate) adapter: GrokCliAdapter,
    pub(crate) user_home: PathBuf,
    pub(crate) data_dir: PathBuf,
}

#[cfg(test)]
pub(crate) struct CamGrokTestGuard {
    previous: Option<CamGrokTestHarness>,
}

#[cfg(test)]
thread_local! {
    static CAM_GROK_TEST_OVERRIDE: std::cell::RefCell<Option<CamGrokTestHarness>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
const CAM_GROK_AUTH_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/account-manager/core/tests/fixtures/grok/valid-auth.json"
);

#[cfg(test)]
pub(crate) fn build_cam_grok_test_harness(
    selected_account: &str,
) -> Result<(
    CamGrokTestHarness,
    PathBuf,
    super::ManagedGrokAccountSelectionEvidence,
)> {
    use std::io;

    use coding_agent_manager_lib::fsx;
    use coding_agent_manager_lib::providers::{add_managed_account, select_launch_account};

    fn fake_login(home: &Path) -> io::Result<i32> {
        std::fs::copy(CAM_GROK_AUTH_FIXTURE, home.join("auth.json"))?;
        Ok(0)
    }

    let root = tempfile::tempdir()?;
    let user_home = root.path().join("cam-user-home");
    let data_dir = root.path().join("cam-data");
    std::fs::create_dir_all(user_home.join(".grok"))?;
    fsx::create_dir_all_private(&data_dir)?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
    let adapter = GrokCliAdapter::with_home(&user_home)
        .with_data_dir(&data_dir)
        .with_login_runner(fake_login);
    for account_id in ["account-a", "account-b"] {
        add_managed_account(&registry, &adapter, account_id, account_id, None)
            .map_err(map_cam_error)?;
    }
    select_launch_account(&registry, &adapter, selected_account).map_err(map_cam_error)?;
    let binding = registry
        .selected_binding(GROK_CLI_PROVIDER_ID)
        .map_err(map_cam_error)?
        .expect("selected binding");
    let managed_home = data_dir
        .join("accounts")
        .join("grok-cli")
        .join(selected_account);
    let evidence = super::ManagedGrokAccountSelectionEvidence {
        provider_id: binding.provider_id,
        account_id: binding.account_id,
        account_incarnation: binding.account_incarnation,
        selection_revision: binding.selection_revision,
    };
    Ok((
        CamGrokTestHarness {
            _root: root,
            registry,
            adapter,
            user_home,
            data_dir,
        },
        managed_home,
        evidence,
    ))
}

#[cfg(test)]
pub(crate) fn activate_cam_grok_test_harness(harness: CamGrokTestHarness) -> CamGrokTestGuard {
    let previous = CAM_GROK_TEST_OVERRIDE.with(|cell| cell.borrow_mut().replace(harness));
    CamGrokTestGuard { previous }
}

#[cfg(test)]
impl Drop for CamGrokTestGuard {
    fn drop(&mut self) {
        CAM_GROK_TEST_OVERRIDE.with(|cell| {
            cell.borrow_mut().take();
            *cell.borrow_mut() = self.previous.take();
        });
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::Path;

    use coding_agent_manager_lib::fsx;
    use coding_agent_manager_lib::providers::{
        add_managed_account, delete_managed_account, select_launch_account,
    };

    use super::*;

    fn create_owner_only_cam_data_dir(data_dir: &Path) {
        fsx::create_dir_all_private(data_dir).expect("owner-only CAM data directory");
    }

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("account-manager/core/tests/fixtures/grok")
            .join(name)
    }

    fn fake_login(home: &Path) -> io::Result<i32> {
        fs::copy(fixture_path("valid-auth.json"), home.join("auth.json"))?;
        Ok(0)
    }

    struct Fixture {
        _root: tempfile::TempDir,
        user_home: PathBuf,
        data_dir: PathBuf,
        registry: StoredAccountRegistry,
        adapter: GrokCliAdapter,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            let user_home = root.path().join("user-home");
            let data_dir = root.path().join("data");
            fs::create_dir_all(user_home.join(".grok")).expect("default grok home");
            create_owner_only_cam_data_dir(&data_dir);
            let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
            let adapter = GrokCliAdapter::with_home(&user_home)
                .with_data_dir(&data_dir)
                .with_login_runner(fake_login);
            Self {
                _root: root,
                user_home,
                data_dir,
                registry,
                adapter,
            }
        }

        fn managed_home(&self, account_id: &str) -> PathBuf {
            self.data_dir
                .join("accounts")
                .join("grok-cli")
                .join(account_id)
        }
    }

    #[test]
    fn launch_spec_plain_environment_exposes_managed_grok_home() -> Result<()> {
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;
        let selected = fixture
            .registry
            .selected(GROK_CLI_PROVIDER_ID)
            .map_err(map_cam_error)?
            .expect("selected account");
        let spec = launch_spec_for(&fixture.adapter, &selected).map_err(map_cam_error)?;
        let home = grok_home_from_launch_spec(&spec)?;
        assert_eq!(home, fixture.managed_home("account-a"));
        assert!(spec
            .environment_removals()
            .contains(&"GROK_AUTH_PATH".to_string()));
        Ok(())
    }

    #[test]
    fn acquire_from_uses_selected_home_not_sibling_managed_home() -> Result<()> {
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        add_managed_account(&fixture.registry, &fixture.adapter, "account-b", "B", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;
        fs::write(
            fixture.managed_home("account-b").join("auth.json"),
            br#"{"marker":"sibling-must-not-win"}"#,
        )?;
        let authority = acquire_grok_launch_authority_from(&fixture.registry, &fixture.adapter)?;
        assert_eq!(
            authority.managed_grok_home(),
            fixture.managed_home("account-a")
        );
        assert_eq!(authority.binding().account_id, "account-a");
        Ok(())
    }

    #[test]
    fn active_use_lease_blocks_selection_and_delete() -> Result<()> {
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        add_managed_account(&fixture.registry, &fixture.adapter, "account-b", "B", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;
        let binding = fixture
            .registry
            .selected_binding(GROK_CLI_PROVIDER_ID)
            .map_err(map_cam_error)?
            .expect("binding");
        let selected_use_lease = fixture
            .registry
            .acquire_selected_use(&binding)
            .map_err(map_cam_error)?;
        assert!(select_launch_account(&fixture.registry, &fixture.adapter, "account-b").is_err());
        assert!(
            delete_managed_account(&fixture.registry, &fixture.adapter, "account-b", None).is_err()
        );
        drop(selected_use_lease);
        select_launch_account(&fixture.registry, &fixture.adapter, "account-b")
            .map_err(map_cam_error)?;
        Ok(())
    }

    #[test]
    fn stale_selected_binding_refuses_use_acquisition() -> Result<()> {
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        add_managed_account(&fixture.registry, &fixture.adapter, "account-b", "B", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;
        let binding_a = fixture
            .registry
            .selected_binding(GROK_CLI_PROVIDER_ID)
            .map_err(map_cam_error)?
            .expect("binding");
        select_launch_account(&fixture.registry, &fixture.adapter, "account-b")
            .map_err(map_cam_error)?;
        assert!(fixture.registry.acquire_selected_use(&binding_a).is_err());
        Ok(())
    }

    #[test]
    fn unselected_complete_account_is_not_pending_and_refuses_acquisition() -> Result<()> {
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        assert!(acquire_grok_launch_authority_from(&fixture.registry, &fixture.adapter).is_err());
        Ok(())
    }

    #[test]
    fn pending_only_registry_refuses_authority_acquisition() -> Result<()> {
        use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};

        let fixture = Fixture::new();
        fixture
            .registry
            .begin_add(
                GROK_CLI_PROVIDER_ID,
                "pending-only",
                "pending-only",
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )
            .map_err(map_cam_error)?;
        assert!(fixture
            .registry
            .selected(GROK_CLI_PROVIDER_ID)
            .map_err(map_cam_error)?
            .is_none());
        assert!(acquire_grok_launch_authority_from(&fixture.registry, &fixture.adapter).is_err());
        Ok(())
    }

    #[test]
    fn nested_cam_grok_test_harness_restores_previous_override() -> Result<()> {
        let fixture_a = Fixture::new();
        add_managed_account(
            &fixture_a.registry,
            &fixture_a.adapter,
            "account-a",
            "A",
            None,
        )
        .map_err(map_cam_error)?;
        select_launch_account(&fixture_a.registry, &fixture_a.adapter, "account-a")
            .map_err(map_cam_error)?;

        let fixture_b = Fixture::new();
        add_managed_account(
            &fixture_b.registry,
            &fixture_b.adapter,
            "account-b",
            "B",
            None,
        )
        .map_err(map_cam_error)?;
        select_launch_account(&fixture_b.registry, &fixture_b.adapter, "account-b")
            .map_err(map_cam_error)?;

        let harness_a = CamGrokTestHarness {
            _root: fixture_a._root,
            registry: fixture_a.registry,
            adapter: fixture_a.adapter,
            user_home: fixture_a.user_home,
            data_dir: fixture_a.data_dir,
        };
        let harness_b = CamGrokTestHarness {
            _root: fixture_b._root,
            registry: fixture_b.registry,
            adapter: fixture_b.adapter,
            user_home: fixture_b.user_home,
            data_dir: fixture_b.data_dir,
        };
        let outer = activate_cam_grok_test_harness(harness_a);
        let inner = activate_cam_grok_test_harness(harness_b);
        assert_eq!(
            acquire_grok_launch_authority()?.binding().account_id,
            "account-b"
        );
        drop(inner);
        assert_eq!(
            acquire_grok_launch_authority()?.binding().account_id,
            "account-a"
        );
        drop(outer);
        Ok(())
    }

    #[test]
    fn thread_local_harness_does_not_leak_to_sibling_threads() -> Result<()> {
        let root = tempfile::tempdir()?;
        let user_home = root.path().join("user-home");
        let data_dir = root.path().join("data");
        fs::create_dir_all(user_home.join(".grok"))?;
        create_owner_only_cam_data_dir(&data_dir);
        let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
        let adapter = GrokCliAdapter::with_home(&user_home)
            .with_data_dir(&data_dir)
            .with_login_runner(fake_login);
        add_managed_account(&registry, &adapter, "account-a", "A", None).map_err(map_cam_error)?;
        select_launch_account(&registry, &adapter, "account-a").map_err(map_cam_error)?;
        let harness = CamGrokTestHarness {
            _root: root,
            registry,
            adapter,
            user_home,
            data_dir,
        };
        let guard = activate_cam_grok_test_harness(harness);
        let sibling = std::thread::spawn(|| acquire_grok_launch_authority().is_err())
            .join()
            .expect("join sibling");
        assert!(sibling);
        let authority = acquire_grok_launch_authority()?;
        assert_eq!(authority.binding().account_id, "account-a");
        drop(guard);
        Ok(())
    }
}
