//! Application data-directory identity.
//!
//! The `ProjectDirs` qualifier triple is the installation's name on disk.
//! Backup and the encrypted-file store both live under it, so they share
//! this helper rather than repeating the triple and drifting apart.

use directories::ProjectDirs;
use std::path::{Path, PathBuf};

/// Platform project directories for this application, if the host can
/// resolve a home / data directory.
pub fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("dev", "metadevelop", "coding-agent-manager")
}

/// Versioned, non-secret stored-account metadata under the application data
/// directory. Tests pass an isolated data directory directly.
pub fn stored_accounts_path(data_dir: &Path) -> PathBuf {
    data_dir.join("stored-accounts.json")
}
