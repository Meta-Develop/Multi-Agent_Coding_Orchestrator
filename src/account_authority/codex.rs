//! Selected CAM Codex authority held through trusted auth capture and process drain.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use coding_agent_manager_lib::account_authority::{
    authority_id_for, SelectedAccountBinding, SelectedUseLease, StoredAccountRegistry,
};
use coding_agent_manager_lib::paths::{project_dirs, stored_accounts_path};
use coding_agent_manager_lib::providers::codex_cli::CodexCliAdapter;
use coding_agent_manager_lib::providers::{launch_spec_for, LaunchSpec};

use super::selected_launch::{LaunchAdmission, SelectedLaunch};
use super::{cam_socket_for_frozen_selection, FrozenCodexSelectedBinding, CODEX_CLI_PROVIDER_ID};

#[cfg(test)]
thread_local! {
    static CODEX_TEST_REGISTRY: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

pub(crate) struct CodexLaunchAuthority {
    registry: StoredAccountRegistry,
    frozen: FrozenCodexSelectedBinding,
    socket_path: Option<PathBuf>,
    _selected_use_lease: SelectedUseLease,
    pub(crate) launch: SelectedLaunch,
    managed_codex_home: PathBuf,
}

impl std::fmt::Debug for CodexLaunchAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodexLaunchAuthority")
            .field("selection", &self.frozen)
            .finish_non_exhaustive()
    }
}

impl CodexLaunchAuthority {
    pub(crate) fn selection_evidence(&self) -> FrozenCodexSelectedBinding {
        self.frozen.clone()
    }

    pub(crate) fn managed_codex_home(&self) -> &Path {
        &self.managed_codex_home
    }

    pub(crate) fn verify_binding_unchanged(&self) -> Result<()> {
        if cam_socket_for_frozen_selection(self.socket_path.as_deref())? != self.socket_path {
            return Err(anyhow!(
                "selected Codex authority socket configuration changed"
            ));
        }
        if let Some(path) = &self.socket_path {
            revalidate_socket(path, &self.frozen)?;
        }
        require_registry_binding(&self.registry, &self.frozen)?;
        let account = self
            .registry
            .complete(CODEX_CLI_PROVIDER_ID, &self.frozen.account_id)
            .context("selected Codex account is no longer complete")?;
        let adapter = adapter_for_registry(&self.registry)?;
        let spec = launch_spec_for(&adapter, &account)
            .context("selected Codex launch declaration is no longer valid")?;
        if codex_home_from_launch_spec(&spec)? != self.managed_codex_home {
            return Err(anyhow!("selected Codex managed home changed"));
        }
        Ok(())
    }
}

pub(crate) fn acquire_codex_launch_authority(
    frozen: &FrozenCodexSelectedBinding,
    admission: Option<LaunchAdmission<'_>>,
) -> Result<CodexLaunchAuthority> {
    let socket_path = cam_socket_for_frozen_selection(frozen.authority_socket.as_deref())?;
    if let Some(path) = &socket_path {
        revalidate_socket(path, frozen)?;
    }
    let registry = execution_registry()?;
    finish_codex_launch_authority(&registry, frozen, socket_path, admission)
}

fn execution_registry() -> Result<StoredAccountRegistry> {
    #[cfg(test)]
    if let Some(path) = CODEX_TEST_REGISTRY.with(|slot| slot.borrow().clone()) {
        return Ok(StoredAccountRegistry::new(path));
    }
    let data_dir = project_dirs().context("Coding Agent Manager data directory is unavailable")?;
    Ok(StoredAccountRegistry::new(stored_accounts_path(
        data_dir.data_dir(),
    )))
}

fn adapter_for_registry(registry: &StoredAccountRegistry) -> Result<CodexCliAdapter> {
    let data_dir = registry
        .metadata_path()
        .parent()
        .context("selected Codex registry has no data directory")?;
    Ok(CodexCliAdapter::default().with_data_dir(data_dir))
}

fn revalidate_socket(path: &Path, frozen: &FrozenCodexSelectedBinding) -> Result<()> {
    let (authority_id, binding) =
        super::selected_binding_via_authority_socket(path, CODEX_CLI_PROVIDER_ID)
            .context("failed to revalidate selected Codex authority socket")?
            .context("selected Codex authority has no complete account")?;
    if authority_id != frozen.authority_id || binding != frozen.to_selected_binding() {
        return Err(anyhow!(
            "selected Codex socket authority or selection changed"
        ));
    }
    Ok(())
}

fn require_registry_binding(
    registry: &StoredAccountRegistry,
    frozen: &FrozenCodexSelectedBinding,
) -> Result<SelectedAccountBinding> {
    if frozen.provider_id != CODEX_CLI_PROVIDER_ID
        || frozen.authority_id != authority_id_for(registry.metadata_path())
    {
        return Err(anyhow!(
            "selected Codex execution authority does not match its frozen binding"
        ));
    }
    let current = registry
        .selected_binding(CODEX_CLI_PROVIDER_ID)
        .context("failed to read selected Codex registry binding")?
        .context("selected Codex registry has no complete account")?;
    if current != frozen.to_selected_binding() {
        return Err(anyhow!(
            "selected Codex account incarnation or selection revision changed"
        ));
    }
    Ok(current)
}

fn finish_codex_launch_authority(
    registry: &StoredAccountRegistry,
    frozen: &FrozenCodexSelectedBinding,
    socket_path: Option<PathBuf>,
    admission: Option<LaunchAdmission<'_>>,
) -> Result<CodexLaunchAuthority> {
    let binding = require_registry_binding(registry, frozen)?;
    let lease = registry
        .acquire_selected_use(&binding)
        .context("failed to acquire selected Codex account use lease")?;
    let (launch, managed_codex_home) = SelectedLaunch::prepare(
        registry,
        &adapter_for_registry(registry)?,
        &binding,
        admission,
        codex_home_from_launch_spec,
    )?;
    // A concurrent mutation before lease acquisition cannot become the captured source.
    require_registry_binding(registry, frozen)?;
    Ok(CodexLaunchAuthority {
        registry: StoredAccountRegistry::new(registry.metadata_path()),
        frozen: frozen.clone(),
        socket_path,
        _selected_use_lease: lease,
        launch,
        managed_codex_home,
    })
}

#[cfg(test)]
pub(crate) fn acquire_from_registry_for_test(
    registry: &StoredAccountRegistry,
) -> Result<CodexLaunchAuthority> {
    let binding = registry
        .selected_binding(CODEX_CLI_PROVIDER_ID)?
        .context("synthetic selection")?;
    let frozen = FrozenCodexSelectedBinding {
        authority_socket: None,
        authority_id: authority_id_for(registry.metadata_path()),
        provider_id: binding.provider_id,
        account_id: binding.account_id,
        account_incarnation: binding.account_incarnation,
        selection_revision: binding.selection_revision,
    };
    finish_codex_launch_authority(registry, &frozen, None, None)
}

fn codex_home_from_launch_spec(spec: &LaunchSpec) -> Result<PathBuf> {
    let env = spec.plain_environment();
    match env.as_slice() {
        [(name, value)]
            if name == "CODEX_HOME"
                && Path::new(value).is_absolute()
                && !spec.requires_credential()
                && spec.environment_removals().is_empty() =>
        {
            Ok(PathBuf::from(value))
        }
        _ => Err(anyhow!(
            "selected Codex launch spec must declare exactly one absolute CODEX_HOME"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};

    #[test]
    fn codex_selected_lifecycle_covers_production_construction_and_exit() -> Result<()> {
        use super::super::selected_launch::tests::{exercise, SCENARIOS};
        let _socket =
            super::super::authority_socket_config::CamAuthoritySocketTestGuard::install(None);
        for scenario in SCENARIOS {
            let (_root, registry, frozen) = selected_fixture();
            let account = registry.complete(CODEX_CLI_PROVIDER_ID, "work")?;
            let home = codex_home_from_launch_spec(&launch_spec_for(
                &adapter_for_registry(&registry)?,
                &account,
            )?)?;
            std::fs::create_dir_all(&home)?;
            std::fs::write(home.join("auth.json"), b"synthetic-lifecycle-material")?;
            exercise(
                &registry,
                CODEX_CLI_PROVIDER_ID,
                scenario,
                |admission| {
                    let authority =
                        finish_codex_launch_authority(&registry, &frozen, None, Some(admission))?;
                    let material = authority.launch.construct(|| {
                        Ok(std::fs::read_to_string(
                            authority.managed_codex_home().join("auth.json"),
                        )?)
                    })?;
                    Ok((authority, material))
                },
                |authority| &authority.launch,
            );
        }
        Ok(())
    }

    fn selected_fixture() -> (
        tempfile::TempDir,
        StoredAccountRegistry,
        FrozenCodexSelectedBinding,
    ) {
        let root = tempfile::tempdir().unwrap();
        let registry = StoredAccountRegistry::new(stored_accounts_path(root.path()));
        for account in ["work", "personal"] {
            registry
                .begin_add(
                    CODEX_CLI_PROVIDER_ID,
                    account,
                    account,
                    AuthKind::OAuth,
                    StoredAccountMaterial::VendorHome,
                )
                .unwrap();
            registry
                .complete_add(CODEX_CLI_PROVIDER_ID, account)
                .unwrap();
        }
        let binding = registry
            .select_complete_revision(CODEX_CLI_PROVIDER_ID, "work", None)
            .unwrap();
        let frozen = FrozenCodexSelectedBinding {
            authority_socket: None,
            authority_id: authority_id_for(registry.metadata_path()),
            provider_id: binding.provider_id,
            account_id: binding.account_id,
            account_incarnation: binding.account_incarnation,
            selection_revision: binding.selection_revision,
        };
        (root, registry, frozen)
    }

    #[test]
    fn codex_registry_rejects_stale_incarnation_revision_and_authority() {
        let (_root, registry, frozen) = selected_fixture();
        require_registry_binding(&registry, &frozen).unwrap();
        for field in ["incarnation", "revision", "authority", "provider"] {
            let mut stale = frozen.clone();
            match field {
                "incarnation" => stale.account_incarnation.push_str("-replaced"),
                "revision" => stale.selection_revision += 1,
                "authority" => stale.authority_id.push_str("-other"),
                _ => stale.provider_id = "grok-cli".to_string(),
            }
            assert!(
                require_registry_binding(&registry, &stale).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn codex_launch_declaration_rejects_missing_relative_duplicate_and_secret_home() {
        assert!(codex_home_from_launch_spec(&LaunchSpec::new("codex")).is_err());
        assert!(codex_home_from_launch_spec(
            &LaunchSpec::new("codex").set_plain_env("CODEX_HOME", "relative")
        )
        .is_err());
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("work");
        let valid = LaunchSpec::new("codex").set_plain_env("CODEX_HOME", home.as_os_str());
        assert_eq!(codex_home_from_launch_spec(&valid).unwrap(), home);
        assert!(codex_home_from_launch_spec(
            &valid.clone().set_plain_env("CODEX_HOME", root.path())
        )
        .is_err());
        assert!(codex_home_from_launch_spec(&valid.set_secret_env("OPENAI_API_KEY")).is_err());
    }

    #[test]
    fn codex_selected_use_lease_blocks_mutation_until_completion_drain() {
        let _socket =
            super::super::authority_socket_config::CamAuthoritySocketTestGuard::install(None);
        let (_root, registry, frozen) = selected_fixture();
        let authority = finish_codex_launch_authority(&registry, &frozen, None, None).unwrap();
        authority.verify_binding_unchanged().unwrap();
        assert!(registry
            .select_complete_revision(CODEX_CLI_PROVIDER_ID, "personal", None)
            .is_err());
        assert!(registry
            .begin_delete(CODEX_CLI_PROVIDER_ID, "work")
            .is_err());
        // Simulate an out-of-band registry writer rather than weakening the lease.
        let original = std::fs::read(registry.metadata_path()).unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&original).unwrap();
        document["selectionRevisions"][CODEX_CLI_PROVIDER_ID] =
            (frozen.selection_revision + 1).into();
        std::fs::write(
            registry.metadata_path(),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        assert!(authority.verify_binding_unchanged().is_err());
        std::fs::write(registry.metadata_path(), original).unwrap();
        authority.verify_binding_unchanged().unwrap();
        drop(authority);
        registry
            .select_complete_revision(CODEX_CLI_PROVIDER_ID, "personal", None)
            .unwrap();
        assert!(require_registry_binding(&registry, &frozen).is_err());
    }

    #[test]
    fn absent_implicit_default_allows_local_codex_launch_authority() {
        use super::super::authority_socket_config::CamAuthoritySocketTestGuard;

        let (root, registry, frozen) = selected_fixture();
        let _socket = CamAuthoritySocketTestGuard::install_default(
            root.path().join("maco/account-authority.sock"),
        );
        struct RestoreRegistry(Option<PathBuf>);
        impl Drop for RestoreRegistry {
            fn drop(&mut self) {
                CODEX_TEST_REGISTRY.with(|slot| slot.replace(self.0.take()));
            }
        }
        let _registry = RestoreRegistry(
            CODEX_TEST_REGISTRY
                .with(|slot| slot.replace(Some(registry.metadata_path().to_path_buf()))),
        );
        let authority = acquire_codex_launch_authority(&frozen, None).unwrap();
        authority.verify_binding_unchanged().unwrap();
        assert_eq!(authority.selection_evidence(), frozen);
    }

    #[test]
    fn frozen_socket_codex_selection_refuses_disappeared_installation() {
        use super::super::authority_socket_config::CamAuthoritySocketTestGuard;
        use std::os::unix::net::UnixListener;

        let (root, _registry, mut frozen) = selected_fixture();
        let socket = root.path().join("maco/account-authority.sock");
        std::fs::create_dir(socket.parent().unwrap()).unwrap();
        let _listener = UnixListener::bind(&socket).unwrap();
        let _socket = CamAuthoritySocketTestGuard::install_default(socket.clone());
        frozen.authority_socket = Some(socket.clone());
        cam_socket_for_frozen_selection(frozen.authority_socket.as_deref()).unwrap();
        std::fs::remove_file(&socket).unwrap();
        // A remaining maco directory still requires the socket and refuses.
        assert!(acquire_codex_launch_authority(&frozen, None).is_err());
        std::fs::remove_dir(socket.parent().unwrap()).unwrap();
        assert!(super::super::configured_cam_authority_socket().is_none());
        let error = acquire_codex_launch_authority(&frozen, None).unwrap_err();
        assert!(format!("{error:#}").contains("refusing local fallback"));
    }

    #[test]
    fn observed_socket_codex_binding_carries_source_and_refuses_disappearance() {
        use super::super::authority_socket_config::CamAuthoritySocketTestGuard;
        use super::super::{
            codex_run_account_binding, record_observed_codex_selection_from_source,
            CodexRunAccountBinding,
        };
        use coding_agent_manager_lib::account_authority::{
            listen, resolve_socket_path, AuthorityContext, AuthorityServerConfig,
        };
        use std::os::unix::fs::PermissionsExt;

        let (root, registry, _) = selected_fixture();
        let parent = root.path().join("maco");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = parent.join("account-authority.sock");
        let safe = resolve_socket_path(&socket).unwrap();
        let context = AuthorityContext::new(registry).without_registry_fallback();
        let listener = listen(safe, AuthorityServerConfig::new(context).unwrap()).unwrap();
        let server = std::thread::spawn(move || listener.accept_once().unwrap());
        let _socket = CamAuthoritySocketTestGuard::install_default(socket.clone());
        let (authority, binding) =
            super::super::selected_binding_via_authority_socket(&socket, CODEX_CLI_PROVIDER_ID)
                .unwrap()
                .unwrap();
        server.join().unwrap();
        record_observed_codex_selection_from_source(
            Some("r9-codex-observed-socket"),
            CODEX_CLI_PROVIDER_ID,
            Some(authority),
            Some(&binding),
            Some(&socket),
        );
        let Some(CodexRunAccountBinding::Selected(frozen)) =
            codex_run_account_binding("r9-codex-observed-socket")
        else {
            panic!("missing socket observation");
        };
        assert_eq!(frozen.authority_socket.as_deref(), Some(socket.as_path()));
        // The listener cleans up its socket on drop. Remove the installation too.
        if socket.symlink_metadata().is_ok() {
            std::fs::remove_file(&socket).unwrap();
        }
        std::fs::remove_dir(parent).unwrap();
        assert!(super::super::configured_cam_authority_socket().is_none());
        let error = acquire_codex_launch_authority(&frozen, None).unwrap_err();
        assert!(format!("{error:#}").contains("refusing local fallback"));
    }

    #[test]
    fn local_codex_selection_refuses_explicit_missing_or_installed_unsafe_default() {
        use super::super::authority_socket_config::CamAuthoritySocketTestGuard;

        let (root, _registry, frozen) = selected_fixture();
        let socket = root.path().join("maco/account-authority.sock");
        {
            let _explicit = CamAuthoritySocketTestGuard::install(Some(socket.as_os_str()));
            assert!(acquire_codex_launch_authority(&frozen, None).is_err());
        }
        std::fs::create_dir(socket.parent().unwrap()).unwrap();
        std::fs::write(&socket, b"not a Unix socket").unwrap();
        let _default = CamAuthoritySocketTestGuard::install_default(socket);
        assert!(acquire_codex_launch_authority(&frozen, None).is_err());
    }
}
