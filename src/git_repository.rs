//! Central libgit2 repository-format extension policy.
//!
//! libgit2 rejects repository-format extensions it does not understand. MACO
//! deliberately accepts `extensions.relativeWorktrees` because libgit2 can
//! resolve its relative linked-worktree metadata once the extension is
//! allowed. The allowlist contains no other extension, so unrelated extensions
//! remain rejected. Registration changes only libgit2 process state; it does
//! not write repository configuration.

use std::sync::OnceLock;

const SUPPORTED_REPOSITORY_EXTENSIONS: &[&str] = &["relativeworktrees"];

static REPOSITORY_EXTENSION_REGISTRATION: OnceLock<Result<(), String>> = OnceLock::new();

pub(crate) fn configure_libgit2_repository_extensions() -> Result<(), git2::Error> {
    let registration = REPOSITORY_EXTENSION_REGISTRATION.get_or_init(|| {
        // SAFETY: `OnceLock` serializes this process-global libgit2 mutation
        // and permits exactly one call. `Cli::run` invokes the helper before
        // dispatching any command that can open a repository.
        unsafe { git2::opts::set_extensions(SUPPORTED_REPOSITORY_EXTENSIONS) }
            .map_err(|error| error.to_string())
    });

    match registration {
        Ok(()) => Ok(()),
        Err(message) => Err(git2::Error::from_str(message)),
    }
}
