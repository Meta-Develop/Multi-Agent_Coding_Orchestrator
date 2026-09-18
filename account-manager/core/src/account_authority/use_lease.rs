//! Cross-process shared leases for active use of a frozen selection binding.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::error::{Error, Result};
use crate::fsx;

use super::binding::SelectedAccountBinding;
use super::document::metadata_write_error;
use super::incarnation::validate_account_incarnation;
use super::lock::{open_file_identity_matches_path, open_regular_lock_file};

/// RAII shared lease on the exact account incarnation named by a selection binding.
pub struct SelectedUseLease {
    file: fs::File,
}

impl SelectedUseLease {
    /// Acquire a shared lease after the caller already holds the registry lock.
    pub(crate) fn acquire_while_registry_held(
        metadata_path: &Path,
        binding: &SelectedAccountBinding,
    ) -> Result<Self> {
        let path = use_lock_path(metadata_path, binding)?;
        if let Some(parent) = path.parent() {
            fsx::create_dir_all_private(parent)?;
        }
        let file = open_or_create_use_lock_file(&path)?;
        FileExt::lock_shared(&file).map_err(|source| {
            if source.kind() == io::ErrorKind::WouldBlock {
                Error::AccountAuthorityBusy {
                    reason: format!(
                        "account `{}` is already mutating under an exclusive authority lock",
                        binding.account_id
                    ),
                }
            } else {
                fsx::io_at(&path, source)
            }
        })?;
        if !open_file_identity_matches_path(&file, &path, "account use lease")? {
            return Err(metadata_write_error(
                &binding.provider_id,
                "account use lease was replaced during acquisition",
            ));
        }
        Ok(Self { file })
    }
}

impl Drop for SelectedUseLease {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn open_or_create_use_lock_file(path: &Path) -> Result<fs::File> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            open_regular_lock_file(path, "account use lease")
        }
        Err(source) => Err(fsx::io_at(path, source)),
    }
}

pub(crate) fn use_lock_path(
    metadata_path: &Path,
    binding: &SelectedAccountBinding,
) -> Result<PathBuf> {
    validate_account_incarnation(&binding.account_incarnation)?;
    if !account_id_is_safe_in_use_lease(&binding.provider_id)
        || !account_id_is_safe_in_use_lease(&binding.account_id)
    {
        return Err(metadata_write_error(
            &binding.provider_id,
            "use lock components are not path-safe",
        ));
    }
    let base = metadata_path
        .parent()
        .map(|parent| parent.join("stored-account-use-locks"))
        .unwrap_or_else(|| PathBuf::from("stored-account-use-locks"));
    let file_name = format!(
        "{}__{}__{}.lock",
        binding.provider_id, binding.account_id, binding.account_incarnation
    );
    if file_name.contains('/') || file_name.contains('\\') {
        return Err(metadata_write_error(
            &binding.provider_id,
            "use lock file name is not path-safe",
        ));
    }
    Ok(base.join(file_name))
}

pub(crate) fn use_lock_dir(metadata_path: &Path) -> PathBuf {
    metadata_path
        .parent()
        .map(|parent| parent.join("stored-account-use-locks"))
        .unwrap_or_else(|| PathBuf::from("stored-account-use-locks"))
}

/// Non-blocking probe: refuse provider-scoped authority mutations while a use lease is held.
pub(crate) fn refuse_provider_authority_mutations(
    metadata_path: &Path,
    provider_id: &str,
) -> Result<()> {
    if !account_id_is_safe_in_use_lease(provider_id) {
        return Err(metadata_write_error(
            provider_id,
            "provider id is not path-safe",
        ));
    }
    let directory = use_lock_dir(metadata_path);
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(fsx::io_at(&directory, error)),
    };
    let prefix = format!("{provider_id}__");
    for entry in entries {
        let entry = entry.map_err(|error| fsx::io_at(&directory, error))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(prefix.as_str()) || !name.ends_with(".lock") {
            continue;
        }
        if !use_lock_name_is_safe(&name, provider_id) {
            return Err(metadata_write_error(
                provider_id,
                "account use lock file name is malformed",
            ));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| fsx::io_at(&path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(metadata_write_error(
                provider_id,
                "account use lock path is not a regular non-symlink file",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|error| fsx::io_at(&path, error))?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => {
                let _ = FileExt::unlock(&file);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(Error::AccountAuthorityBusy {
                    reason: format!("provider `{provider_id}` has an active account-use lease"),
                });
            }
            Err(error) => return Err(fsx::io_at(&path, error)),
        }
    }
    Ok(())
}

fn use_lock_name_is_safe(name: &str, provider_id: &str) -> bool {
    let stem = name.strip_suffix(".lock").unwrap_or(name);
    let mut parts = stem.splitn(3, "__");
    let Some(file_provider) = parts.next() else {
        return false;
    };
    let Some(account_id) = parts.next() else {
        return false;
    };
    let Some(incarnation) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    file_provider == provider_id
        && account_id_is_safe_in_use_lease(account_id)
        && validate_account_incarnation(incarnation).is_ok()
}

pub(crate) fn account_id_is_safe_in_use_lease(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() <= 128
        && !account_id.contains("..")
        && !account_id.contains('/')
        && !account_id.contains('\\')
        && account_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_authority::binding::SelectedAccountBinding;

    #[test]
    fn use_lock_path_rejects_noncanonical_incarnation() {
        let binding = SelectedAccountBinding {
            provider_id: "gemini-cli".to_string(),
            account_id: "work".to_string(),
            account_incarnation: "../escape".to_string(),
            selection_revision: 1,
        };
        assert!(use_lock_path(Path::new("/tmp/stored-accounts.json"), &binding).is_err());
    }
}
