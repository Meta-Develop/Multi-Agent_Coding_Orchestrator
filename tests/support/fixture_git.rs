//! Git commands for integration-test fixture repositories (#979).

use std::process::Command;

/// Variables a MACO-managed Worker exports for its own private Git storage. A test that runs
/// `git` against a fixture repository must not inherit them, or the child acts on the Worker's
/// repository instead of the fixture.
#[allow(dead_code)]
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

/// `git` without the inherited repository-selection variables.
#[allow(dead_code)]
pub(crate) fn fixture_git() -> Command {
    let mut command = Command::new("git");
    for key in INHERITED_GIT_REPOSITORY_VARIABLES {
        command.env_remove(key);
    }
    command
}
