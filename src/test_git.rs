//! Git commands for test fixture repositories (#979).

use std::path::Path;
use std::process::Command;

/// Variables a MACO-managed Worker exports for its own private Git storage. A test that runs
/// `git` against a fixture repository must not inherit them, or the child acts on the Worker's
/// repository instead of the fixture.
pub(crate) const INHERITED_GIT_REPOSITORY_VARIABLES: [&str; 9] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
];

/// `git` running in `cwd` without the inherited repository-selection variables.
pub(crate) fn fixture_git_command(cwd: &Path) -> Command {
    let mut command = Command::new("git");
    command.current_dir(cwd);
    for key in INHERITED_GIT_REPOSITORY_VARIABLES {
        command.env_remove(key);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn fixture_git_command_removes_inherited_repository_selection() {
        let command = fixture_git_command(Path::new("fixture"));
        assert_eq!(command.get_current_dir(), Some(Path::new("fixture")));
        for key in INHERITED_GIT_REPOSITORY_VARIABLES {
            assert!(
                command
                    .get_envs()
                    .any(|(name, value)| name == OsStr::new(key) && value.is_none()),
                "{key} must be removed"
            );
        }
    }

    #[test]
    fn fixture_git_command_opens_the_fixture_repository() {
        let temp = tempfile::tempdir().expect("tempdir");
        let init = fixture_git_command(temp.path())
            .args(["init", "-q"])
            .status()
            .expect("git init");
        assert!(init.success());
        let output = fixture_git_command(temp.path())
            .args(["rev-parse", "--git-dir"])
            .output()
            .expect("git rev-parse");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), ".git");
    }
}
