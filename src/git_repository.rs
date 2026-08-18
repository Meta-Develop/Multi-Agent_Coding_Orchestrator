//! Central libgit2 repository opening and repository-format extension policy.
//!
//! libgit2 rejects repository-format extensions it does not understand. MACO
//! deliberately opts in to `extensions.relativeWorktrees` because libgit2 can
//! resolve the relative linked-worktree metadata once the extension is
//! accepted. No other caller-defined extension is enabled here, so libgit2
//! continues to reject genuinely unknown extensions.

use git2::{Error, Repository};
use std::{
    path::Path,
    sync::{Once, OnceLock},
};

const SUPPORTED_REPOSITORY_EXTENSIONS: &[&str] = &["relativeworktrees"];

static REGISTER_REPOSITORY_EXTENSIONS: Once = Once::new();
static REPOSITORY_EXTENSION_REGISTRATION_ERROR: OnceLock<String> = OnceLock::new();

/// Registers MACO's deliberately supported repository-format extensions.
///
/// `git2::opts::set_extensions` mutates libgit2 process-global state without
/// internal synchronization. The `Once` makes every MACO registration path
/// share one synchronized mutation. Package binaries call this before Tokio
/// starts; the repository-open functions below also call it so direct library
/// entrypoints cannot bypass the policy.
#[doc(hidden)]
pub fn configure_libgit2_repository_extensions() -> Result<(), Error> {
    REGISTER_REPOSITORY_EXTENSIONS.call_once(|| {
        // SAFETY: `REGISTER_REPOSITORY_EXTENSIONS` serializes and limits this
        // process-global libgit2 mutation to one call. Package binaries invoke
        // this before starting worker threads, and all MACO repository opens
        // pass through this module.
        if let Err(error) = unsafe { git2::opts::set_extensions(SUPPORTED_REPOSITORY_EXTENSIONS) } {
            let _ = REPOSITORY_EXTENSION_REGISTRATION_ERROR.set(format!(
                "failed to register supported Git repository extensions: {error}"
            ));
        }
    });

    match REPOSITORY_EXTENSION_REGISTRATION_ERROR.get() {
        Some(message) => Err(Error::from_str(message)),
        None => Ok(()),
    }
}

pub(crate) fn open(path: impl AsRef<Path>) -> Result<Repository, Error> {
    configure_libgit2_repository_extensions()?;
    Repository::open(path)
}

pub(crate) fn open_bare(path: impl AsRef<Path>) -> Result<Repository, Error> {
    configure_libgit2_repository_extensions()?;
    Repository::open_bare(path)
}

pub(crate) fn discover(path: impl AsRef<Path>) -> Result<Repository, Error> {
    configure_libgit2_repository_extensions()?;
    Repository::discover(path)
}
