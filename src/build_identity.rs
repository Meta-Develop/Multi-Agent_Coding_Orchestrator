//! Compile-time identity of this executable.
//!
//! Revision and source state are the values `build.rs` recorded. Resolving
//! them never reads the process current directory or a repository under
//! orchestration. A missing or rejected revision stays unknown.

use serde::{Deserialize, Serialize};

const REVISION_HEX_LEN: usize = 40;

/// Package version recorded from `CARGO_PKG_VERSION` at compile time.
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Source revision recorded by the build script, or empty when unknown.
pub const SOURCE_REVISION: &str = env!("MACO_SOURCE_REVISION");

/// Source state recorded by the build script: `clean`, `dirty`, or `unknown`.
pub const SOURCE_STATE: &str = env!("MACO_SOURCE_STATE");

/// Multi-line identity text. The binary name is not included.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\npackage_version=",
    env!("CARGO_PKG_VERSION"),
    "\nsource_revision=",
    env!("MACO_SOURCE_REVISION"),
    "\nsource_state=",
    env!("MACO_SOURCE_STATE"),
);

/// Whether the recorded source tree matched the recorded revision.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Clean,
    Dirty,
    Unknown,
}

impl SourceState {
    fn as_label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Dirty => "dirty",
            Self::Unknown => "unknown",
        }
    }
}

/// Version, source revision, and optional executable digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableBuildIdentity {
    pub package_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub source_state: SourceState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_sha256: Option<String>,
}

impl ExecutableBuildIdentity {
    /// Identity baked in by the build script. The executable digest is unset.
    pub fn compiled() -> Self {
        resolve_recorded_identity(PACKAGE_VERSION, SOURCE_REVISION, SOURCE_STATE)
    }

    /// Same layout as [`LONG_VERSION`], using this value's normalized fields.
    pub fn long_version_text(&self) -> String {
        let revision = self.source_revision.as_deref().unwrap_or("");
        format!(
            "{}\npackage_version={}\nsource_revision={}\nsource_state={}",
            self.package_version,
            self.package_version,
            revision,
            self.source_state.as_label(),
        )
    }
}

/// Normalizes a recorded package version, revision, and state.
///
/// A 40-digit hex revision is kept in lowercase. `clean` or `dirty` without
/// one becomes `unknown`. Any other state drops the revision. The executable
/// digest is always unset; this function does not read the filesystem.
pub fn resolve_recorded_identity(
    package_version: &str,
    revision: &str,
    state: &str,
) -> ExecutableBuildIdentity {
    let (source_revision, source_state) = normalize_recorded(revision, state);
    ExecutableBuildIdentity {
        package_version: package_version.to_string(),
        source_revision,
        source_state,
        executable_sha256: None,
    }
}

fn canonical_revision(revision: &str) -> Option<String> {
    if revision.len() != REVISION_HEX_LEN {
        return None;
    }
    if !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(revision.to_ascii_lowercase())
}

fn normalize_recorded(revision: &str, state: &str) -> (Option<String>, SourceState) {
    let revision = canonical_revision(revision);
    match (state, revision) {
        ("clean", Some(revision)) => (Some(revision), SourceState::Clean),
        ("dirty", Some(revision)) => (Some(revision), SourceState::Dirty),
        _ => (None, SourceState::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        resolve_recorded_identity, ExecutableBuildIdentity, SourceState, LONG_VERSION,
        PACKAGE_VERSION, SOURCE_REVISION, SOURCE_STATE,
    };

    const PACKAGE: &str = "0.3.0";
    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
    const OTHER_REVISION: &str = "fedcba9876543210fedcba9876543210fedcba98";
    const UPPER_REVISION: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    #[test]
    fn clean_revision_stays_clean() {
        let identity = resolve_recorded_identity(PACKAGE, REVISION, "clean");
        assert_eq!(identity.package_version, PACKAGE);
        assert_eq!(identity.source_state, SourceState::Clean);
        assert_eq!(identity.source_revision.as_deref(), Some(REVISION));
        assert_eq!(identity.executable_sha256, None);
    }

    #[test]
    fn dirty_revision_stays_dirty() {
        let identity = resolve_recorded_identity(PACKAGE, REVISION, "dirty");
        assert_eq!(identity.source_state, SourceState::Dirty);
        assert_eq!(identity.source_revision.as_deref(), Some(REVISION));
        assert_eq!(identity.executable_sha256, None);
    }

    #[test]
    fn unknown_state_drops_revision() {
        let identity = resolve_recorded_identity(PACKAGE, REVISION, "unknown");
        assert_eq!(identity.source_state, SourceState::Unknown);
        assert_eq!(identity.source_revision, None);
        assert_eq!(identity.executable_sha256, None);

        let other = resolve_recorded_identity(PACKAGE, REVISION, "archived");
        assert_eq!(other.source_state, SourceState::Unknown);
        assert_eq!(other.source_revision, None);
    }

    #[test]
    fn clean_or_dirty_without_revision_is_unknown() {
        for state in ["clean", "dirty"] {
            let identity = resolve_recorded_identity(PACKAGE, "", state);
            assert_eq!(identity.source_state, SourceState::Unknown);
            assert_eq!(identity.source_revision, None);
        }
    }

    #[test]
    fn short_sha_and_non_hex_are_unknown() {
        let short = resolve_recorded_identity(PACKAGE, "0123456789abcdef", "clean");
        assert_eq!(short.source_state, SourceState::Unknown);
        assert_eq!(short.source_revision, None);

        let non_hex =
            resolve_recorded_identity(PACKAGE, "0123456789abcdef0123456789abcdef0123456g", "dirty");
        assert_eq!(non_hex.source_state, SourceState::Unknown);
        assert_eq!(non_hex.source_revision, None);

        let words = resolve_recorded_identity(PACKAGE, "not-a-revision", "clean");
        assert_eq!(words.source_state, SourceState::Unknown);
        assert_eq!(words.source_revision, None);
    }

    #[test]
    fn uppercase_revision_is_lowercased() {
        let identity = resolve_recorded_identity(PACKAGE, UPPER_REVISION, "dirty");
        assert_eq!(identity.source_state, SourceState::Dirty);
        assert_eq!(identity.source_revision.as_deref(), Some(REVISION));
    }

    #[test]
    fn same_package_version_with_different_revisions_is_not_equal() {
        let left = resolve_recorded_identity(PACKAGE, REVISION, "clean");
        let right = resolve_recorded_identity(PACKAGE, OTHER_REVISION, "clean");
        assert_eq!(left.package_version, right.package_version);
        assert_ne!(left, right);
    }

    #[test]
    fn compiled_identity_matches_recorded_consts() {
        let compiled = ExecutableBuildIdentity::compiled();
        assert_eq!(compiled.package_version, PACKAGE_VERSION);
        assert_eq!(
            compiled,
            resolve_recorded_identity(PACKAGE_VERSION, SOURCE_REVISION, SOURCE_STATE)
        );
        assert_eq!(LONG_VERSION, compiled.long_version_text());
        assert_eq!(compiled.executable_sha256, None);
    }
}
