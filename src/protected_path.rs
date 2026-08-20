use serde::{de, Deserialize, Deserializer, Serialize};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

const MAX_ROOT_ID_BYTES: usize = 128;
const MAX_RELATIVE_PATH_BYTES: usize = 4 * 1024;
const MAX_RELATIVE_PATH_COMPONENTS: usize = 256;
const SYNTHETIC_GATE_ROOT: &str = "__machine_global__";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtectedPathError {
    #[error(
        "declared root id must contain only ASCII letters, digits, '.', '_' and '-' and may not be empty, '.' or '..'"
    )]
    InvalidRootId,
    #[error("declared path must be a non-empty canonical relative UTF-8 path")]
    InvalidRelativePath,
}

pub type ProtectedPathResult<T> = std::result::Result<T, ProtectedPathError>;

/// Whether a protected path denial is an immutable boundary or can be addressed only through a
/// separately reviewed exact exception.
///
/// This is the shared form of the Issue 32 sandbox-denial retryability vocabulary. The
/// `external_agent` module publicly re-exports it for wire and API compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxDenialRetryability {
    RequiresDeclaredException,
    NotRetryable,
}

/// A privacy-safe path coordinate beneath one explicitly declared root.
///
/// The coordinate never contains the root's host-absolute path. `root_id` identifies reviewed
/// configuration, while `relative` is already canonical and cannot name the root itself, traverse
/// upward, or contain control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredPathCoordinate {
    root_id: String,
    relative: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeclaredPathCoordinate {
    root_id: String,
    relative: PathBuf,
}

impl<'de> Deserialize<'de> for DeclaredPathCoordinate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawDeclaredPathCoordinate::deserialize(deserializer)?;
        Self::new(raw.root_id, raw.relative).map_err(de::Error::custom)
    }
}

impl DeclaredPathCoordinate {
    pub fn new(
        root_id: impl AsRef<str>,
        relative: impl AsRef<Path>,
    ) -> ProtectedPathResult<DeclaredPathCoordinate> {
        let root_id = validate_root_id(root_id.as_ref())?;
        let relative = validate_relative_path(relative.as_ref())?;
        Ok(Self { root_id, relative })
    }

    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    pub fn relative(&self) -> &Path {
        &self.relative
    }

    pub fn intersects(&self, other: &Self) -> bool {
        self.root_id == other.root_id
            && (self.relative.starts_with(&other.relative)
                || other.relative.starts_with(&self.relative))
    }

    /// Returns a prompt-safe repository-relative encoding for legacy GateDenial claim context.
    ///
    /// This is an identity coordinate only. It is never resolved as a repository or host path.
    pub fn synthetic_gate_path(&self) -> PathBuf {
        PathBuf::from(SYNTHETIC_GATE_ROOT)
            .join(&self.root_id)
            .join(&self.relative)
    }

    pub fn validate(&self) -> ProtectedPathResult<()> {
        let validated = Self::new(&self.root_id, &self.relative)?;
        if validated == *self {
            Ok(())
        } else {
            Err(ProtectedPathError::InvalidRelativePath)
        }
    }
}

/// One path protected by an existing safety policy.
///
/// Worktree controls and machine-global cleanup checks share this representation so callers cannot
/// accidentally create a second, stringly-typed protected-path vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPathSpec {
    coordinate: DeclaredPathCoordinate,
    retryability: SandboxDenialRetryability,
}

impl ProtectedPathSpec {
    pub fn new(
        coordinate: DeclaredPathCoordinate,
        retryability: SandboxDenialRetryability,
    ) -> Self {
        Self {
            coordinate,
            retryability,
        }
    }

    pub fn coordinate(&self) -> &DeclaredPathCoordinate {
        &self.coordinate
    }

    pub fn retryability(&self) -> SandboxDenialRetryability {
        self.retryability
    }

    pub fn intersects(&self, coordinate: &DeclaredPathCoordinate) -> bool {
        self.coordinate.intersects(coordinate)
    }

    pub fn validate(&self) -> ProtectedPathResult<()> {
        self.coordinate.validate()
    }
}

fn validate_root_id(root_id: &str) -> ProtectedPathResult<String> {
    if root_id.is_empty()
        || root_id.len() > MAX_ROOT_ID_BYTES
        || matches!(root_id, "." | "..")
        || !root_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return Err(ProtectedPathError::InvalidRootId);
    }
    Ok(root_id.to_string())
}

fn validate_relative_path(path: &Path) -> ProtectedPathResult<PathBuf> {
    let text = path
        .to_str()
        .ok_or(ProtectedPathError::InvalidRelativePath)?;
    if text.is_empty() || text.len() > MAX_RELATIVE_PATH_BYTES || text.chars().any(char::is_control)
    {
        return Err(ProtectedPathError::InvalidRelativePath);
    }

    let mut normalized = PathBuf::new();
    let mut component_count = 0_usize;
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(ProtectedPathError::InvalidRelativePath);
        };
        normalized.push(component);
        component_count = component_count.saturating_add(1);
        if component_count > MAX_RELATIVE_PATH_COMPONENTS {
            return Err(ProtectedPathError::InvalidRelativePath);
        }
    }
    if normalized.as_os_str().is_empty() || normalized.as_os_str() != path.as_os_str() {
        return Err(ProtectedPathError::InvalidRelativePath);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinate_requires_strict_root_id_and_canonical_relative_path() {
        let valid = DeclaredPathCoordinate::new("session-store", "users/a")
            .expect("valid declared coordinate");
        assert_eq!(valid.root_id(), "session-store");
        assert_eq!(valid.relative(), Path::new("users/a"));

        for root_id in ["", ".", "..", " root", "root/name", "root\nname"] {
            assert!(
                DeclaredPathCoordinate::new(root_id, "users/a").is_err(),
                "invalid root id was accepted: {root_id:?}"
            );
        }
        for relative in [
            "",
            ".",
            "..",
            "/absolute",
            "../escape",
            "users/../escape",
            "users/./a",
            "users//a",
            "users/\na",
        ] {
            assert!(
                DeclaredPathCoordinate::new("session-store", relative).is_err(),
                "invalid relative path was accepted: {relative:?}"
            );
        }
    }

    #[test]
    fn coordinate_intersection_uses_root_and_path_components() {
        let root = |relative: &str| {
            DeclaredPathCoordinate::new("state", relative).expect("valid coordinate")
        };
        assert!(root("sessions").intersects(&root("sessions/repair")));
        assert!(!root("sessions").intersects(&root("sessions-old")));
        assert!(!root("state")
            .intersects(&DeclaredPathCoordinate::new("other", "state").expect("other coordinate")));
    }

    #[test]
    fn coordinate_deserialization_revalidates_and_rejects_unknown_fields() {
        let coordinate =
            DeclaredPathCoordinate::new("state", "sessions/a").expect("valid coordinate");
        let json = serde_json::to_string(&coordinate).expect("serialize coordinate");
        assert_eq!(
            serde_json::from_str::<DeclaredPathCoordinate>(&json).expect("round trip"),
            coordinate
        );
        assert!(serde_json::from_str::<DeclaredPathCoordinate>(
            r#"{"root_id":"state","relative":"../escape"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DeclaredPathCoordinate>(
            r#"{"root_id":"state","relative":"sessions/a","absolute":"/secret"}"#
        )
        .is_err());
    }

    #[test]
    fn protected_spec_preserves_coordinate_and_retryability() {
        let coordinate =
            DeclaredPathCoordinate::new("state", "sessions").expect("valid coordinate");
        let protected = ProtectedPathSpec::new(
            coordinate.clone(),
            SandboxDenialRetryability::RequiresDeclaredException,
        );
        assert_eq!(protected.coordinate(), &coordinate);
        assert_eq!(
            protected.retryability(),
            SandboxDenialRetryability::RequiresDeclaredException
        );
        assert!(protected
            .intersects(&DeclaredPathCoordinate::new("state", "sessions/a").expect("descendant")));
        assert!(!protected
            .intersects(&DeclaredPathCoordinate::new("state", "sessions-old").expect("sibling")));
    }
}
