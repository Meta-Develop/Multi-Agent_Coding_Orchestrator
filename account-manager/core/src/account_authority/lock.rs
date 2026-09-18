//! Cross-process registry lock with symlink-safe path identity.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fs2::FileExt;

use crate::error::{Error, Result};
use crate::fsx;

use super::document::metadata_write_error;

/// Exclusive durable lock for stored-account metadata mutations and reads.
pub(crate) struct RegistryFileLock {
    path: PathBuf,
    file: File,
}

impl RegistryFileLock {
    pub(crate) fn acquire(metadata_path: &Path) -> Result<Self> {
        let lock_path = registry_lock_path(metadata_path);
        if let Some(parent) = lock_path.parent() {
            fsx::create_dir_all_private(parent)?;
        }
        let file = open_regular_lock_file(&lock_path, "stored-account registry lock")?;
        FileExt::lock_exclusive(&file).map_err(|error| lock_error(&lock_path, error))?;
        let held = Self {
            path: lock_path,
            file,
        };
        held.validate_identity("stored-account registry lock")?;
        Ok(held)
    }

    fn validate_identity(&self, label: &str) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            metadata_write_error(
                "account-metadata",
                format!("{label} changed while locked ({})", error.kind()),
            )
        })?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(metadata_write_error(
                "account-metadata",
                format!("{label} changed while locked"),
            ));
        }
        if !open_file_identity_matches_path(&self.file, &self.path, label)? {
            return Err(metadata_write_error(
                "account-metadata",
                format!("{label} was replaced while locked"),
            ));
        }
        Ok(())
    }
}

impl Drop for RegistryFileLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub(crate) fn registry_lock_path(metadata_path: &Path) -> PathBuf {
    let file_name = metadata_path
        .file_name()
        .map(|name| format!("{}.lock", name.to_string_lossy()))
        .unwrap_or_else(|| ".stored-accounts.lock".to_string());
    match metadata_path.parent() {
        Some(parent) => parent.join(file_name),
        None => PathBuf::from(file_name),
    }
}

pub(crate) fn open_regular_lock_file(path: &Path, label: &str) -> Result<File> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return create_regular_lock_file(path, label);
        }
        Err(error) => {
            return Err(metadata_write_error(
                "account-metadata",
                format!("{label} cannot be inspected ({})", error.kind()),
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(metadata_write_error(
            "account-metadata",
            format!("{label} is not a regular non-symlink file"),
        ));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| lock_error(path, error))
}

fn create_regular_lock_file(path: &Path, label: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| lock_error(path, error))?;
    if !open_file_identity_matches_path(&file, path, label)? {
        return Err(metadata_write_error(
            "account-metadata",
            format!("{label} was replaced during creation"),
        ));
    }
    Ok(file)
}

pub(crate) fn open_file_identity_matches_path(
    file: &File,
    path: &Path,
    label: &str,
) -> Result<bool> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        metadata_write_error(
            "account-metadata",
            format!("{label} cannot be rechecked ({})", error.kind()),
        )
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(metadata_write_error(
            "account-metadata",
            format!("{label} is not a regular non-symlink file"),
        ));
    }
    #[cfg(not(windows))]
    {
        let handle_metadata = file.metadata().map_err(|error| {
            metadata_write_error(
                "account-metadata",
                format!("{label} identity cannot be read ({})", error.kind()),
            )
        })?;
        Ok(metadata_identity_matches(&path_metadata, &handle_metadata))
    }
    #[cfg(windows)]
    {
        let file_identity = file
            .try_clone()
            .and_then(same_file::Handle::from_file)
            .map_err(|error| {
                metadata_write_error(
                    "account-metadata",
                    format!("{label} identity cannot be read ({})", error.kind()),
                )
            })?;
        let path_identity = same_file::Handle::from_path(path).map_err(|error| {
            metadata_write_error(
                "account-metadata",
                format!("{label} identity cannot be rechecked ({})", error.kind()),
            )
        })?;
        Ok(file_identity == path_identity)
    }
}

#[cfg(not(windows))]
fn metadata_identity_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (left.dev(), left.ino()) == (right.dev(), right.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn lock_error(path: &Path, source: io::Error) -> Error {
    if source.kind() == io::ErrorKind::WouldBlock {
        Error::AccountAuthorityBusy {
            reason: format!("{} is held by another process", path.display()),
        }
    } else {
        fsx::io_at(path, source)
    }
}
