//! Verified Cursor execution binding to CAM selected-account authority.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use coding_agent_manager_lib::account_authority::{
    authority_id_for, SelectedAccountBinding, SelectedUseLease, StoredAccountRegistry,
};
use coding_agent_manager_lib::error::Error as CamError;
use coding_agent_manager_lib::paths::{project_dirs, stored_accounts_path};
use coding_agent_manager_lib::providers::cursor::CursorAdapter;
use coding_agent_manager_lib::providers::launch_spec_for;

use super::{
    FrozenCursorSelectedBinding, ManagedCursorAccountSelectionEvidence, CURSOR_PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CursorAuthIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    length: u64,
}

pub(crate) struct CursorLaunchAuthority {
    registry: StoredAccountRegistry,
    binding: SelectedAccountBinding,
    authority_id: Option<String>,
    socket_path: Option<PathBuf>,
    _selected_use_lease: SelectedUseLease,
    managed_home: PathBuf,
    auth_path: PathBuf,
    auth_file: Arc<File>,
    auth_identity: CursorAuthIdentity,
    launch_env_removals: Vec<String>,
}

impl CursorLaunchAuthority {
    pub(crate) fn selection_evidence(&self) -> ManagedCursorAccountSelectionEvidence {
        ManagedCursorAccountSelectionEvidence {
            provider_id: self.binding.provider_id.clone(),
            account_id: self.binding.account_id.clone(),
            account_incarnation: self.binding.account_incarnation.clone(),
            selection_revision: self.binding.selection_revision,
            authority_id: self.authority_id.clone(),
        }
    }

    pub(crate) fn managed_home(&self) -> &Path {
        &self.managed_home
    }

    pub(crate) fn auth_path(&self) -> &Path {
        &self.auth_path
    }

    pub(crate) fn held_auth_file(&self) -> Arc<File> {
        Arc::clone(&self.auth_file)
    }

    pub(crate) fn apply_launch_environment(&self, environment: &mut BTreeMap<String, String>) {
        for name in &self.launch_env_removals {
            environment.remove(name);
        }
        environment.remove("HOME");
        environment.remove("CURSOR_CONFIG_DIR");
        environment.remove("AGENT_CLI_CREDENTIAL_STORE");
    }

    pub(crate) fn verify_binding_unchanged(&self) -> Result<()> {
        if super::cam_socket_for_frozen_selection(self.socket_path.as_deref())? != self.socket_path
        {
            return Err(anyhow!(
                "selected Cursor authority socket configuration changed"
            ));
        }
        if let Some(socket) = &self.socket_path {
            let live = super::selected_binding_via_authority_socket(socket, CURSOR_PROVIDER_ID)
                .context("failed to revalidate Cursor selection via authority socket")?;
            let Some((authority_id, binding)) = live else {
                return Err(anyhow!(
                    "no complete account is selected for Coding Agent Manager provider `{CURSOR_PROVIDER_ID}`"
                ));
            };
            if self.authority_id.as_deref() != Some(authority_id.as_str())
                || binding != self.binding
            {
                return Err(anyhow!(
                    "Coding Agent Manager Cursor authority binding changed"
                ));
            }
        }
        let current = self
            .registry
            .selected_binding(CURSOR_PROVIDER_ID)
            .context("failed to read Coding Agent Manager Cursor selection")?
            .ok_or_else(|| anyhow!("no complete Cursor account is selected"))?;
        if current != self.binding {
            return Err(anyhow!("Coding Agent Manager Cursor selection is stale"));
        }
        if let Some(expected) = &self.authority_id {
            if authority_id_for(self.registry.metadata_path()) != *expected {
                return Err(anyhow!(
                    "Coding Agent Manager Cursor authority identity changed"
                ));
            }
        }
        verify_auth_identity(&self.auth_path, &self.auth_file, self.auth_identity)
    }
}

pub(crate) fn acquire_cursor_launch_authority(
    carried: Option<&FrozenCursorSelectedBinding>,
) -> Result<CursorLaunchAuthority> {
    let socket = super::cam_socket_for_frozen_selection(
        carried.and_then(|frozen| frozen.authority_socket.as_deref()),
    )?;
    if socket.is_some() && carried.is_none() {
        return Err(anyhow!(
            "no frozen Cursor selection binding from Coding Agent Manager authority observation"
        ));
    }
    if let (Some(socket), Some(frozen)) = (socket.as_ref(), carried) {
        let live = super::selected_binding_via_authority_socket(socket, CURSOR_PROVIDER_ID)
            .context("failed to revalidate frozen Cursor selection via authority socket")?;
        let Some((authority_id, binding)) = live else {
            return Err(anyhow!(
                "no complete Cursor account is selected via authority socket"
            ));
        };
        if frozen.authority_id.as_deref() != Some(authority_id.as_str())
            || frozen.to_selected_binding() != binding
        {
            return Err(anyhow!("frozen Cursor authority binding is stale"));
        }
    }
    let data_dir = project_dirs()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .context("Coding Agent Manager data directory is unavailable")?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
    acquire_from_registry(&registry, &CursorAdapter::default(), carried, socket)
}

fn acquire_from_registry(
    registry: &StoredAccountRegistry,
    adapter: &CursorAdapter,
    frozen: Option<&FrozenCursorSelectedBinding>,
    socket_path: Option<PathBuf>,
) -> Result<CursorLaunchAuthority> {
    let current = registry
        .selected_binding(CURSOR_PROVIDER_ID)
        .context("failed to read Coding Agent Manager Cursor selection")?
        .ok_or_else(|| anyhow!("no complete Cursor account is selected"))?;
    let (binding, authority_id) = match frozen {
        Some(frozen) => {
            if frozen.to_selected_binding() != current {
                return Err(anyhow!("Coding Agent Manager Cursor selection is stale"));
            }
            if let Some(expected) = &frozen.authority_id {
                if authority_id_for(registry.metadata_path()) != *expected {
                    return Err(anyhow!(
                        "Coding Agent Manager Cursor authority identity changed"
                    ));
                }
            }
            (current, frozen.authority_id.clone())
        }
        None => (current, None),
    };
    let selected_use_lease = registry
        .acquire_selected_use(&binding)
        .map_err(map_cam_error)?;
    let account = registry
        .complete(CURSOR_PROVIDER_ID, &binding.account_id)
        .map_err(map_cam_error)?;
    let launch = launch_spec_for(adapter, &account).map_err(map_cam_error)?;
    let managed_home = cursor_home_from_launch_spec(&launch)?;
    let auth_path = managed_home.join(".cursor").join("auth.json");
    let (auth_file, auth_identity) = open_auth_read_only(&auth_path)?;
    Ok(CursorLaunchAuthority {
        registry: StoredAccountRegistry::new(registry.metadata_path()),
        binding,
        authority_id,
        socket_path,
        _selected_use_lease: selected_use_lease,
        managed_home,
        auth_path,
        auth_file: Arc::new(auth_file),
        auth_identity,
        launch_env_removals: launch.environment_removals(),
    })
}

fn cursor_home_from_launch_spec(
    spec: &coding_agent_manager_lib::providers::LaunchSpec,
) -> Result<PathBuf> {
    let environment = spec.plain_environment();
    let home = environment
        .iter()
        .find(|(name, _)| name == "HOME")
        .map(|(_, value)| PathBuf::from(value))
        .context("Cursor launch spec omitted HOME")?;
    let config = environment
        .iter()
        .find(|(name, _)| name == "CURSOR_CONFIG_DIR")
        .map(|(_, value)| PathBuf::from(value))
        .context("Cursor launch spec omitted CURSOR_CONFIG_DIR")?;
    let store = environment
        .iter()
        .find(|(name, _)| name == "AGENT_CLI_CREDENTIAL_STORE")
        .map(|(_, value)| value.to_string_lossy().into_owned())
        .context("Cursor launch spec omitted AGENT_CLI_CREDENTIAL_STORE")?;
    if config != home.join(".cursor") || store != "file" {
        return Err(anyhow!(
            "Cursor launch spec did not select its managed file-store home"
        ));
    }
    Ok(home)
}

fn open_auth_read_only(path: &Path) -> Result<(File, CursorAuthIdentity)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| {
            format!(
                "failed to open managed Cursor auth leaf: {}",
                path.display()
            )
        })?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and reads no Rust memory.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(anyhow!(
            "managed Cursor auth leaf is not an owner-only regular file"
        ));
    }
    let identity = CursorAuthIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        length: metadata.len(),
    };
    verify_auth_identity(path, &file, identity)?;
    Ok((file, identity))
}

fn verify_auth_identity(path: &Path, file: &File, expected: CursorAuthIdentity) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let held = file.metadata()?;
    let live = fs::symlink_metadata(path)?;
    let observed = CursorAuthIdentity {
        device: live.dev(),
        inode: live.ino(),
        owner: live.uid(),
        mode: live.mode(),
        length: live.len(),
    };
    if live.file_type().is_symlink()
        || !live.is_file()
        || observed != expected
        || held.dev() != expected.device
        || held.ino() != expected.inode
        || held.len() != expected.length
    {
        return Err(anyhow!("managed Cursor auth leaf changed after selection"));
    }
    Ok(())
}

fn map_cam_error(error: CamError) -> anyhow::Error {
    anyhow!("Coding Agent Manager Cursor authority refused launch: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn cursor_launch_endpoint_changes_after_acquire_are_refused() -> Result<()> {
        let root = tempfile::tempdir()?;
        let data = root.path().join("data");
        fs::create_dir(&data)?;
        let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
        registry.begin_add(
            CURSOR_PROVIDER_ID,
            "work",
            "Work",
            AuthKind::OAuth,
            StoredAccountMaterial::VendorHome,
        )?;
        registry.complete_add(CURSOR_PROVIDER_ID, "work")?;
        registry.select_complete_revision(CURSOR_PROVIDER_ID, "work", None)?;
        let home = data.join("accounts").join(CURSOR_PROVIDER_ID).join("work");
        let config = home.join(".cursor");
        fs::create_dir_all(&config)?;
        for directory in [&home, &config] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let auth = config.join("auth.json");
        fs::write(&auth, b"synthetic-cursor-auth")?;
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;
        let adapter = CursorAdapter::with_home(root.path())
            .with_data_dir(&data)
            .with_working_directory(root.path());
        super::super::launch_endpoint_tests::assert_endpoint_changes_refused(
            |socket_path| acquire_from_registry(&registry, &adapter, None, socket_path),
            |authority| authority.verify_binding_unchanged(),
        )
    }
}
