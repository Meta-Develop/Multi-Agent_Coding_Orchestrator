//! Build configuration for disposable agent lanes.
//!
//! Agent worktrees are one-shot execution sandboxes. They inherit Cargo's
//! default incremental compilation unless something turns it off, and the
//! resulting `target/debug/incremental` tree is discarded unread when the
//! lane is reaped. The primary developer checkout keeps Cargo's default
//! incremental behavior: this module never writes that tree's
//! `.cargo/config.toml`.
//!
//! The durable split is a Cargo config at the *worktree root* (the parent of
//! each lane), which Cargo discovers by walking up from a lane working
//! directory. An operator who wants incremental compilation in a lane they
//! intend to iterate in can set `CARGO_INCREMENTAL=1` in the process
//! environment; the generated config does not `force` the value.

use anyhow::{Context, Result};
use std::{collections::BTreeMap, ffi::OsStr, fs, io::ErrorKind, path::Path};

/// Cargo environment variable that disables incremental compilation when `"0"`.
pub const CARGO_INCREMENTAL_ENV: &str = "CARGO_INCREMENTAL";

/// Value that turns incremental compilation off. Matches CI.
pub const CARGO_INCREMENTAL_DISABLED: &str = "0";

/// Directory name Cargo walks for config files. Lives as a reserved child of
/// the worktree root, not inside any lane checkout.
pub const LANE_BUILD_CONFIG_DIR: &str = ".cargo";

const LANE_BUILD_CONFIG_FILE: &str = "config.toml";

const LANE_CARGO_CONFIG: &str = "\
# Generated for disposable agent lanes. The primary developer checkout does
# not read this file. Set CARGO_INCREMENTAL=1 in the process environment to
# iterate in a lane.
[build]
incremental = false

[env]
CARGO_INCREMENTAL = \"0\"
";

/// Environment entries the orchestrator should hand to lane workers.
///
/// `CARGO_INCREMENTAL` is set without replacing an existing process value so
/// an operator can turn incremental compilation back on for a lane they
/// intend to iterate in. Callers that inherit-and-set should insert only
/// missing keys.
pub fn lane_build_environment() -> BTreeMap<String, String> {
    let mut environment = BTreeMap::new();
    environment.insert(
        CARGO_INCREMENTAL_ENV.to_string(),
        CARGO_INCREMENTAL_DISABLED.to_string(),
    );
    environment
}

/// True when `name` is the reserved worktree-root Cargo config directory.
pub fn is_lane_build_config_directory(name: impl AsRef<OsStr>) -> bool {
    name.as_ref() == OsStr::new(LANE_BUILD_CONFIG_DIR)
}

/// Exact generated config body. Exposed for tests that assert the durable
/// on-disk contract.
pub fn lane_cargo_config_contents() -> &'static str {
    LANE_CARGO_CONFIG
}

/// Writes the lane Cargo config at `worktree_root/.cargo/config.toml` if it
/// is absent. Existing files are left alone so an operator edit survives.
pub fn ensure_lane_build_configuration(worktree_root: &Path) -> Result<()> {
    let cargo_dir = worktree_root.join(LANE_BUILD_CONFIG_DIR);
    let config_path = cargo_dir.join(LANE_BUILD_CONFIG_FILE);
    match fs::symlink_metadata(&config_path) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect lane Cargo config {}",
                    config_path.display()
                )
            })
        }
    }
    fs::create_dir_all(&cargo_dir).with_context(|| {
        format!(
            "failed to create lane Cargo config directory {}",
            cargo_dir.display()
        )
    })?;
    fs::write(&config_path, LANE_CARGO_CONFIG).with_context(|| {
        format!(
            "failed to write lane Cargo config {}",
            config_path.display()
        )
    })?;
    Ok(())
}

/// Path of the generated config under a worktree root.
pub fn lane_build_config_path(worktree_root: &Path) -> std::path::PathBuf {
    worktree_root
        .join(LANE_BUILD_CONFIG_DIR)
        .join(LANE_BUILD_CONFIG_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn lane_build_environment_disables_incremental_without_forcing() {
        let environment = lane_build_environment();
        assert_eq!(
            environment.get(CARGO_INCREMENTAL_ENV).map(String::as_str),
            Some(CARGO_INCREMENTAL_DISABLED)
        );
        assert!(
            !lane_cargo_config_contents().contains("force"),
            "operator CARGO_INCREMENTAL=1 must still win"
        );
    }

    #[test]
    fn generated_config_disables_incremental_and_is_not_the_primary_config() {
        let contents = lane_cargo_config_contents();
        assert!(contents.contains("incremental = false"));
        assert!(contents.contains("CARGO_INCREMENTAL = \"0\""));
        let primary =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(".cargo/config.toml"))
                .expect("primary cargo config");
        assert!(
            !primary.contains("CARGO_INCREMENTAL"),
            "primary developer builds must keep Cargo's default incremental behavior"
        );
        assert!(
            !primary.contains("incremental = false"),
            "primary developer builds must keep Cargo's default incremental behavior"
        );
    }

    #[test]
    fn ensure_writes_once_and_leaves_operator_edits() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        ensure_lane_build_configuration(root).expect("write");
        let path = lane_build_config_path(root);
        let first = fs::read_to_string(&path).expect("read generated");
        assert_eq!(first, lane_cargo_config_contents());

        fs::write(&path, "# operator override\n[build]\nincremental = true\n")
            .expect("operator edit");
        ensure_lane_build_configuration(root).expect("idempotent");
        let kept = fs::read_to_string(&path).expect("read operator edit");
        assert!(kept.contains("incremental = true"));
        assert!(!is_lane_build_config_directory("agent-lane"));
        assert!(is_lane_build_config_directory(".cargo"));
    }
}
