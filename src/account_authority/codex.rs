//! Selected CAM Codex authority held through trusted auth capture and process drain.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use coding_agent_manager_lib::account_authority::{
    authority_id_for, SelectedAccountBinding, SelectedUseLease, StoredAccountRegistry,
};
use coding_agent_manager_lib::paths::{project_dirs, stored_accounts_path};
use coding_agent_manager_lib::providers::codex_cli::CodexCliAdapter;
use coding_agent_manager_lib::providers::{launch_spec_for, LaunchSpec};

use super::{configured_cam_authority_socket, FrozenCodexSelectedBinding, CODEX_CLI_PROVIDER_ID};

pub(crate) struct CodexLaunchAuthority {
    registry: StoredAccountRegistry,
    frozen: FrozenCodexSelectedBinding,
    socket_path: Option<PathBuf>,
    _selected_use_lease: SelectedUseLease,
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
        if configured_cam_authority_socket() != self.socket_path {
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
) -> Result<CodexLaunchAuthority> {
    let data_dir = project_dirs().context("Coding Agent Manager data directory is unavailable")?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(data_dir.data_dir()));
    let socket_path = configured_cam_authority_socket();
    if let Some(path) = &socket_path {
        revalidate_socket(path, frozen)?;
    }
    finish_codex_launch_authority(&registry, frozen, socket_path)
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
) -> Result<CodexLaunchAuthority> {
    let binding = require_registry_binding(registry, frozen)?;
    let lease = registry
        .acquire_selected_use(&binding)
        .context("failed to acquire selected Codex account use lease")?;
    let account = registry
        .complete(CODEX_CLI_PROVIDER_ID, &binding.account_id)
        .context("selected Codex account is not complete")?;
    let spec = launch_spec_for(&adapter_for_registry(registry)?, &account)
        .context("selected Codex adapter refused its launch declaration")?;
    let managed_codex_home = codex_home_from_launch_spec(&spec)?;
    // A concurrent mutation before lease acquisition cannot become the captured source.
    require_registry_binding(registry, frozen)?;
    Ok(CodexLaunchAuthority {
        registry: StoredAccountRegistry::new(registry.metadata_path()),
        frozen: frozen.clone(),
        socket_path,
        _selected_use_lease: lease,
        managed_codex_home,
    })
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
        let authority = finish_codex_launch_authority(&registry, &frozen, None).unwrap();
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
}
