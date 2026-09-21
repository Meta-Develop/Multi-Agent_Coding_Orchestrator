//! Verified Grok execution binding to CAM `grok-cli` selected-account authority.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use coding_agent_manager_lib::account_authority::authority_id_for;
use coding_agent_manager_lib::account_authority::SelectedAccountBinding;
use coding_agent_manager_lib::account_authority::SelectedUseLease;
use coding_agent_manager_lib::account_authority::StoredAccountRegistry;
use coding_agent_manager_lib::error::Error as CamError;
use coding_agent_manager_lib::paths::{project_dirs, stored_accounts_path};
use coding_agent_manager_lib::providers::grok_cli::GrokCliAdapter;
use coding_agent_manager_lib::providers::launch_spec_for;

pub(crate) use super::GROK_CLI_PROVIDER_ID;
use super::{
    configured_cam_authority_socket, frozen_observed_grok_selection, FrozenGrokSelectedBinding,
    ManagedGrokAccountSelectionEvidence,
};

/// Frozen CAM selection, active use lease, and managed `GROK_HOME` for one Grok run.
pub(crate) struct GrokLaunchAuthority {
    registry: StoredAccountRegistry,
    binding: SelectedAccountBinding,
    authority_id: Option<String>,
    socket_bound: bool,
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
            // Report captured identity even for no-socket local observe-then-launch.
            // `socket_bound` is the revalidation/no-fallback flag, not a hide-identity flag.
            authority_id: self.authority_id.clone(),
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

    /// Re-read the chosen authority before releasing the target process.
    pub(crate) fn verify_binding_unchanged(&self) -> Result<()> {
        if self.socket_bound {
            let socket_path = configured_cam_authority_socket().ok_or_else(|| {
                anyhow!(
                    "Coding Agent Manager authority socket is no longer configured; refusing local fallback"
                )
            })?;
            let live =
                super::selected_binding_via_authority_socket(&socket_path, GROK_CLI_PROVIDER_ID)
                    .context(
                    "failed to revalidate Coding Agent Manager Grok selection via authority socket",
                )?;
            let Some((authority_id, binding)) = live else {
                return Err(anyhow!(
                    "no complete account is selected for Coding Agent Manager provider `{GROK_CLI_PROVIDER_ID}`"
                ));
            };
            if let Some(expected_authority) = &self.authority_id {
                if authority_id != *expected_authority {
                    return Err(anyhow!(
                        "Coding Agent Manager authority identity does not match the frozen selected authority"
                    ));
                }
            }
            if binding != self.binding {
                return Err(map_binding_drift(&self.binding, &binding));
            }
        }
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
        if let Some(expected_authority) = &self.authority_id {
            let actual = authority_id_for(self.registry.metadata_path());
            if actual != *expected_authority {
                return Err(anyhow!(
                    "Coding Agent Manager execution authority does not match the frozen selected authority"
                ));
            }
        }
        Ok(())
    }
}

/// Acquire the selected `grok-cli` binding using production CAM install paths.
pub(crate) fn acquire_grok_launch_authority() -> Result<GrokLaunchAuthority> {
    let frozen = frozen_observed_grok_selection();
    if let Some(socket_path) = configured_cam_authority_socket() {
        let frozen = frozen.ok_or_else(|| {
            anyhow!(
                "no frozen Grok selection binding from Coding Agent Manager authority socket observation"
            )
        })?;
        revalidate_frozen_selection_via_socket(&socket_path, &frozen)?;
        return acquire_from_execution_registry(Some(&frozen), true);
    }
    match frozen.as_ref() {
        Some(frozen) => acquire_from_execution_registry(Some(frozen), false),
        None => acquire_from_execution_registry(None, false),
    }
}

fn revalidate_frozen_selection_via_socket(
    socket_path: &Path,
    frozen: &FrozenGrokSelectedBinding,
) -> Result<()> {
    let expected_authority = frozen.authority_id.as_deref().ok_or_else(|| {
        anyhow!("frozen Grok selection is missing authority identity for the configured CAM socket")
    })?;
    let live = super::selected_binding_via_authority_socket(socket_path, GROK_CLI_PROVIDER_ID)
        .context("failed to revalidate Coding Agent Manager Grok selection via authority socket")?;
    let Some((authority_id, binding)) = live else {
        return Err(anyhow!(
            "no complete account is selected for Coding Agent Manager provider `{GROK_CLI_PROVIDER_ID}` via authority socket"
        ));
    };
    if authority_id != expected_authority {
        return Err(anyhow!(
            "Coding Agent Manager authority identity does not match the frozen selected authority"
        ));
    }
    let expected = frozen.to_selected_binding();
    if binding != expected {
        return Err(map_binding_drift(&expected, &binding));
    }
    Ok(())
}

fn acquire_from_execution_registry(
    frozen: Option<&FrozenGrokSelectedBinding>,
    socket_bound: bool,
) -> Result<GrokLaunchAuthority> {
    #[cfg(test)]
    {
        let override_result = CAM_GROK_TEST_OVERRIDE.with(|cell| {
            cell.borrow().as_ref().map(|harness| {
                acquire_grok_launch_authority_from_bound(
                    &harness.registry,
                    &harness.adapter,
                    frozen,
                    socket_bound,
                )
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
    acquire_grok_launch_authority_from_bound(
        &registry,
        &GrokCliAdapter::default(),
        frozen,
        socket_bound,
    )
}

/// Parameterized acquisition for isolated registry/adapter pairs (unit tests).
#[cfg(test)]
pub(crate) fn acquire_grok_launch_authority_from(
    registry: &StoredAccountRegistry,
    adapter: &GrokCliAdapter,
) -> Result<GrokLaunchAuthority> {
    acquire_grok_launch_authority_from_bound(registry, adapter, None, false)
}

fn acquire_grok_launch_authority_from_bound(
    registry: &StoredAccountRegistry,
    adapter: &GrokCliAdapter,
    frozen: Option<&FrozenGrokSelectedBinding>,
    socket_bound: bool,
) -> Result<GrokLaunchAuthority> {
    let current = registry
        .selected_binding(GROK_CLI_PROVIDER_ID)
        .context("failed to read Coding Agent Manager Grok selection")?
        .ok_or_else(|| {
            anyhow!(
                "no complete account is selected for Coding Agent Manager provider `{GROK_CLI_PROVIDER_ID}`"
            )
        })?;
    let (binding, authority_id) = if let Some(frozen) = frozen {
        require_execution_matches_frozen(frozen, registry, &current)?;
        (frozen.to_selected_binding(), frozen.authority_id.clone())
    } else {
        (current, None)
    };
    finish_grok_launch_authority(registry, adapter, binding, authority_id, socket_bound)
}

fn require_execution_matches_frozen(
    frozen: &FrozenGrokSelectedBinding,
    registry: &StoredAccountRegistry,
    current: &SelectedAccountBinding,
) -> Result<()> {
    if let Some(expected_authority) = &frozen.authority_id {
        let actual = authority_id_for(registry.metadata_path());
        if actual != *expected_authority {
            return Err(anyhow!(
                "Coding Agent Manager execution authority does not match the frozen selected authority"
            ));
        }
    }
    if !frozen.matches_selected_binding(current) {
        return Err(map_binding_drift(&frozen.to_selected_binding(), current));
    }
    Ok(())
}

fn finish_grok_launch_authority(
    registry: &StoredAccountRegistry,
    adapter: &GrokCliAdapter,
    binding: SelectedAccountBinding,
    authority_id: Option<String>,
    socket_bound: bool,
) -> Result<GrokLaunchAuthority> {
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
        authority_id,
        socket_bound,
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
        authority_id: None,
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

    #[cfg(target_os = "linux")]
    fn serve_registry_on_socket(
        registry: StoredAccountRegistry,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::thread::JoinHandle<()>,
    ) {
        use coding_agent_manager_lib::account_authority::{
            listen, resolve_socket_path, AuthorityContext, AuthorityServerConfig,
        };
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("socket tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
        let root = fs::canonicalize(dir.path()).expect("canonical");
        let socket = root.join("account.sock");
        let path = resolve_socket_path(&socket).expect("safe socket path");
        let ctx = AuthorityContext::new(registry).without_registry_fallback();
        let listener =
            listen(path, AuthorityServerConfig::new(ctx).expect("config")).expect("listen");
        let socket_path = listener.path().to_path_buf();
        let handle = std::thread::spawn(move || while listener.accept_once().is_ok() {});
        (dir, socket_path, handle)
    }

    struct SocketEnvGuard {
        previous: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl SocketEnvGuard {
        fn set(path: &Path) -> Self {
            use crate::account_authority::authority_socket_config::CAM_AUTHORITY_SOCKET_ENV;
            let _lock = crate::account_authority::CAM_AUTHORITY_SOCKET_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV);
            std::env::set_var(CAM_AUTHORITY_SOCKET_ENV, path);
            Self { previous, _lock }
        }

        fn unset() -> Self {
            use crate::account_authority::authority_socket_config::CAM_AUTHORITY_SOCKET_ENV;
            let _lock = crate::account_authority::CAM_AUTHORITY_SOCKET_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV);
            std::env::remove_var(CAM_AUTHORITY_SOCKET_ENV);
            Self { previous, _lock }
        }
    }

    impl Drop for SocketEnvGuard {
        fn drop(&mut self) {
            use crate::account_authority::authority_socket_config::CAM_AUTHORITY_SOCKET_ENV;
            match self.previous.take() {
                Some(value) => std::env::set_var(CAM_AUTHORITY_SOCKET_ENV, value),
                None => std::env::remove_var(CAM_AUTHORITY_SOCKET_ENV),
            }
        }
    }

    fn frozen_from_registry(
        registry: &StoredAccountRegistry,
        with_authority_id: bool,
    ) -> super::super::FrozenGrokSelectedBinding {
        use coding_agent_manager_lib::account_authority::authority_id_for;
        let binding = registry
            .selected_binding(GROK_CLI_PROVIDER_ID)
            .expect("read selection")
            .expect("selected");
        super::super::FrozenGrokSelectedBinding::from_selected_binding(
            with_authority_id.then(|| authority_id_for(registry.metadata_path())),
            &binding,
        )
    }

    #[test]
    fn socket_registry_a_and_local_registry_b_refuse_acquisition() -> Result<()> {
        let fixture_a = Fixture::new();
        add_managed_account(
            &fixture_a.registry,
            &fixture_a.adapter,
            "account-a",
            "A",
            None,
        )
        .map_err(map_cam_error)?;
        add_managed_account(
            &fixture_a.registry,
            &fixture_a.adapter,
            "account-b",
            "B",
            None,
        )
        .map_err(map_cam_error)?;
        select_launch_account(&fixture_a.registry, &fixture_a.adapter, "account-a")
            .map_err(map_cam_error)?;

        let fixture_b = Fixture::new();
        add_managed_account(
            &fixture_b.registry,
            &fixture_b.adapter,
            "account-a",
            "A",
            None,
        )
        .map_err(map_cam_error)?;
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

        let listen_registry = StoredAccountRegistry::new(fixture_a.registry.metadata_path());
        let (_socket_dir, socket_path, _server) = serve_registry_on_socket(listen_registry);
        let frozen = frozen_from_registry(&fixture_a.registry, true);
        let _freeze = super::super::FrozenGrokSelectionGuard::pin(Some(frozen));
        let _socket_env = SocketEnvGuard::set(&socket_path);

        let harness_b = CamGrokTestHarness {
            _root: fixture_b._root,
            registry: fixture_b.registry,
            adapter: fixture_b.adapter,
            user_home: fixture_b.user_home,
            data_dir: fixture_b.data_dir,
        };
        let _local = activate_cam_grok_test_harness(harness_b);
        let error = acquire_grok_launch_authority()
            .err()
            .expect("unequal authorities must refuse");
        let message = format!("{error:#}");
        assert!(
            message.contains("does not match the frozen selected authority")
                || message.contains("is not the selected account")
                || message.contains("is stale"),
            "unexpected refusal: {message}"
        );
        Ok(())
    }

    #[test]
    fn matching_socket_and_local_authority_acquires_frozen_binding() -> Result<()> {
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        add_managed_account(&fixture.registry, &fixture.adapter, "account-b", "B", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;

        let listen_registry = StoredAccountRegistry::new(fixture.registry.metadata_path());
        let (_socket_dir, socket_path, _server) = serve_registry_on_socket(listen_registry);
        let frozen = frozen_from_registry(&fixture.registry, true);
        let expected_account = frozen.account_id.clone();
        let expected_authority = frozen.authority_id.clone();
        let _freeze = super::super::FrozenGrokSelectionGuard::pin(Some(frozen));
        let _socket_env = SocketEnvGuard::set(&socket_path);

        let harness = CamGrokTestHarness {
            _root: fixture._root,
            registry: fixture.registry,
            adapter: fixture.adapter,
            user_home: fixture.user_home,
            data_dir: fixture.data_dir,
        };
        let _local = activate_cam_grok_test_harness(harness);
        let authority = acquire_grok_launch_authority()?;
        assert_eq!(authority.binding().account_id, expected_account);
        let evidence = authority.selection_evidence();
        assert_eq!(evidence.account_id, expected_account);
        assert_eq!(evidence.authority_id, expected_authority);
        authority.verify_binding_unchanged()?;
        Ok(())
    }

    #[test]
    fn selection_change_after_observation_refuses_acquisition() -> Result<()> {
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        add_managed_account(&fixture.registry, &fixture.adapter, "account-b", "B", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;

        let frozen = frozen_from_registry(&fixture.registry, true);
        select_launch_account(&fixture.registry, &fixture.adapter, "account-b")
            .map_err(map_cam_error)?;

        let listen_registry = StoredAccountRegistry::new(fixture.registry.metadata_path());
        let (_socket_dir, socket_path, _server) = serve_registry_on_socket(listen_registry);
        let _freeze = super::super::FrozenGrokSelectionGuard::pin(Some(frozen));
        let _socket_env = SocketEnvGuard::set(&socket_path);

        let harness = CamGrokTestHarness {
            _root: fixture._root,
            registry: fixture.registry,
            adapter: fixture.adapter,
            user_home: fixture.user_home,
            data_dir: fixture.data_dir,
        };
        let _local = activate_cam_grok_test_harness(harness);
        let error = acquire_grok_launch_authority()
            .err()
            .expect("changed selection must refuse launch");
        let message = format!("{error:#}");
        assert!(
            message.contains("is stale")
                || message.contains("is not the selected account")
                || message.contains("does not match"),
            "unexpected refusal: {message}"
        );
        Ok(())
    }

    #[test]
    fn missing_frozen_binding_with_socket_configured_refuses_acquisition() -> Result<()> {
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;
        let listen_registry = StoredAccountRegistry::new(fixture.registry.metadata_path());
        let (_socket_dir, socket_path, _server) = serve_registry_on_socket(listen_registry);
        let _freeze = super::super::FrozenGrokSelectionGuard::pin(None);
        let _socket_env = SocketEnvGuard::set(&socket_path);
        let harness = CamGrokTestHarness {
            _root: fixture._root,
            registry: fixture.registry,
            adapter: fixture.adapter,
            user_home: fixture.user_home,
            data_dir: fixture.data_dir,
        };
        let _local = activate_cam_grok_test_harness(harness);
        let error = acquire_grok_launch_authority()
            .err()
            .expect("missing freeze must refuse");
        assert!(
            error
                .to_string()
                .contains("no frozen Grok selection binding"),
            "unexpected refusal: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn no_socket_keeps_local_registry_acquisition() -> Result<()> {
        let _freeze = super::super::FrozenGrokSelectionGuard::pin(None);
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;
        let harness = CamGrokTestHarness {
            _root: fixture._root,
            registry: fixture.registry,
            adapter: fixture.adapter,
            user_home: fixture.user_home,
            data_dir: fixture.data_dir,
        };
        let _local = activate_cam_grok_test_harness(harness);
        let authority = acquire_grok_launch_authority()?;
        assert_eq!(authority.binding().account_id, "account-a");
        assert!(authority.selection_evidence().authority_id.is_none());
        Ok(())
    }

    #[test]
    fn no_socket_observe_then_launch_acquires_matching_local_registry() -> Result<()> {
        let _no_socket = SocketEnvGuard::unset();
        let fixture = Fixture::new();
        add_managed_account(&fixture.registry, &fixture.adapter, "account-a", "A", None)
            .map_err(map_cam_error)?;
        select_launch_account(&fixture.registry, &fixture.adapter, "account-a")
            .map_err(map_cam_error)?;
        let frozen = frozen_from_registry(&fixture.registry, true);
        let expected_account = frozen.account_id.clone();
        let expected_authority = frozen.authority_id.clone();
        assert!(
            expected_authority.is_some(),
            "local observation must freeze authority_id"
        );
        let _freeze = super::super::FrozenGrokSelectionGuard::pin(Some(frozen));
        let harness = CamGrokTestHarness {
            _root: fixture._root,
            registry: fixture.registry,
            adapter: fixture.adapter,
            user_home: fixture.user_home,
            data_dir: fixture.data_dir,
        };
        let _local = activate_cam_grok_test_harness(harness);
        let authority = acquire_grok_launch_authority()?;
        assert_eq!(authority.binding().account_id, expected_account);
        let evidence = authority.selection_evidence();
        assert_eq!(evidence.account_id, expected_account);
        assert_eq!(evidence.authority_id, expected_authority);
        authority.verify_binding_unchanged()?;
        Ok(())
    }
}
