//! Configured Unix socket path resolution with fail-closed ancestry checks.
//!
//! Endpoint traversal rejects symlink components, group- or world-writable
//! ancestors, and inodes owned by neither the caller nor root. Bind/listen is
//! owned by [`super::server`]. Non-Unix platforms return
//! [`SocketPathError::UnsupportedPlatform`] without panicking.
//!
//! A root-owned sticky directory (the usual `/tmp` mode) is the only writable
//! ancestor that is accepted, so a private tempdir can be validated without
//! treating the host temp root as attacker-controlled.

use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::path::Component;

/// Absolute socket path that has already passed ancestry checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeSocketPath(PathBuf);

impl SafeSocketPath {
    /// Borrow the resolved absolute path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Return the resolved absolute path.
    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for SafeSocketPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

#[cfg(not(unix))]
impl SafeSocketPath {
    /// Placeholder so [`super::listen`] can refuse without a Unix ancestry check.
    pub fn unsupported_platform() -> Self {
        Self(PathBuf::from(r"C:\unused\account.sock"))
    }
}

/// Typed failure for a configured socket path that must not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SocketPathError {
    #[error("unix socket transport is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("socket path is empty")]
    Empty,
    #[error("socket path traverses a symlink: {}", .0.display())]
    Symlink(PathBuf),
    #[error("socket path ancestor is group- or world-writable: {}", .0.display())]
    WritableAncestry(PathBuf),
    #[error("socket path component has the wrong owner: {}", .0.display())]
    WrongOwner(PathBuf),
    #[error("socket path component is not a usable directory or endpoint: {}", .0.display())]
    NotDirectory(PathBuf),
    #[error("failed to inspect socket path {}: {kind}", .path.display())]
    Inspect { path: PathBuf, kind: io::ErrorKind },
}

/// Resolve `configured` to an absolute path after Unix ancestry checks.
///
/// The leaf may be absent (it is not bound here). Existing components are
/// inspected with `lstat` one name at a time so intermediate symlinks cannot
/// be followed.
pub fn resolve_socket_path(
    configured: impl AsRef<Path>,
) -> Result<SafeSocketPath, SocketPathError> {
    resolve_socket_path_inner(configured.as_ref())
}

fn resolve_socket_path_inner(configured: &Path) -> Result<SafeSocketPath, SocketPathError> {
    #[cfg(not(unix))]
    {
        let _ = configured;
        Err(SocketPathError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        resolve_unix_socket_path(configured)
    }
}

impl SocketPathError {
    #[cfg(unix)]
    fn inspect(path: &Path, error: io::Error) -> Self {
        Self::Inspect {
            path: path.to_path_buf(),
            kind: error.kind(),
        }
    }
}

#[cfg(unix)]
fn resolve_unix_socket_path(configured: &Path) -> Result<SafeSocketPath, SocketPathError> {
    if configured.as_os_str().is_empty() {
        return Err(SocketPathError::Empty);
    }

    let absolute = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| SocketPathError::inspect(Path::new("."), error))?
            .join(configured)
    };
    let normalized = normalize_lexically(&absolute);
    if normalized.file_name().is_none() {
        return Err(SocketPathError::Empty);
    }

    inspect_components(&normalized)?;
    Ok(SafeSocketPath(normalized))
}

#[cfg(unix)]
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(name) => normalized.push(name),
        }
    }
    normalized
}

#[cfg(unix)]
fn inspect_components(path: &Path) -> Result<(), SocketPathError> {
    use std::fs;

    let mut current = PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        current.push(component.as_os_str());
        let is_leaf = components.peek().is_none();
        match fs::symlink_metadata(&current) {
            Ok(metadata) => inspect_existing(&current, &metadata, is_leaf)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound && is_leaf => {}
            Err(error) => return Err(SocketPathError::inspect(&current, error)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn inspect_existing(
    path: &Path,
    metadata: &std::fs::Metadata,
    is_leaf: bool,
) -> Result<(), SocketPathError> {
    if metadata.file_type().is_symlink() {
        return Err(SocketPathError::Symlink(path.to_path_buf()));
    }
    if is_leaf {
        if metadata.is_dir() {
            return Err(SocketPathError::NotDirectory(path.to_path_buf()));
        }
    } else if !metadata.is_dir() {
        return Err(SocketPathError::NotDirectory(path.to_path_buf()));
    }
    reject_owner_and_mode(path, metadata)
}

#[cfg(unix)]
pub(crate) fn reject_owner_and_mode(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), SocketPathError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    reject_owner_and_mode_values(
        path,
        metadata.uid(),
        metadata.permissions().mode(),
        metadata.is_dir(),
        effective_uid(),
    )
}

#[cfg(unix)]
fn reject_owner_and_mode_values(
    path: &Path,
    uid: u32,
    mode: u32,
    is_dir: bool,
    euid: u32,
) -> Result<(), SocketPathError> {
    if uid != euid && uid != 0 {
        return Err(SocketPathError::WrongOwner(path.to_path_buf()));
    }

    let group_or_world_writable = mode & 0o022 != 0;
    let root_sticky_directory = is_dir && uid == 0 && mode & 0o1000 != 0;
    if group_or_world_writable && !root_sticky_directory {
        return Err(SocketPathError::WritableAncestry(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid is always successful and has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn shared_owner_mode_policy_rejects_foreign_owners_and_only_allows_root_sticky_directories() {
        let path = Path::new("/FAKE-component");
        assert_eq!(
            reject_owner_and_mode_values(path, 1001, 0o700, true, 1000),
            Err(SocketPathError::WrongOwner(path.to_path_buf()))
        );
        assert_eq!(
            reject_owner_and_mode_values(path, 1001, 0o1777, true, 1000),
            Err(SocketPathError::WrongOwner(path.to_path_buf()))
        );
        for (owner, mode, is_dir) in [(1000, 0o1777, true), (0, 0o777, true), (0, 0o1777, false)] {
            assert_eq!(
                reject_owner_and_mode_values(path, owner, mode, is_dir, 1000),
                Err(SocketPathError::WritableAncestry(path.to_path_buf()))
            );
        }
        reject_owner_and_mode_values(path, 0, 0o1777, true, 1000).unwrap();
        reject_owner_and_mode_values(path, 0, 0o755, true, 1000).unwrap();
        reject_owner_and_mode_values(path, 1000, 0o700, true, 1000).unwrap();
    }

    #[cfg(not(unix))]
    #[test]
    fn unix_socket_paths_are_unsupported_on_this_platform() {
        let error = resolve_socket_path(Path::new(r"C:\unused\account.sock")).unwrap_err();
        assert_eq!(error, SocketPathError::UnsupportedPlatform);
    }

    /// Owner-only temporary root plus its canonical path. macOS places
    /// `$TMPDIR` under `/var`, a symlink to `/private/var`, so tests must
    /// build fixture paths from the resolved root or the ancestry check
    /// correctly rejects the symlinked component before reaching the fixture.
    #[cfg(unix)]
    fn private_tempdir() -> (tempfile::TempDir, std::path::PathBuf) {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod tempdir");
        let canonical = fs::canonicalize(dir.path()).expect("canonical tempdir");
        (dir, canonical)
    }

    #[cfg(unix)]
    fn owner_only_dir(path: &Path) {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        fs::create_dir(path).expect("mkdir");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
    }

    #[cfg(unix)]
    #[test]
    fn owner_only_socket_path_is_accepted() {
        let (_guard, root) = private_tempdir();
        let run = root.join("run");
        owner_only_dir(&run);
        let socket = run.join("account.sock");

        let resolved = resolve_socket_path(&socket).expect("safe path");
        assert_eq!(resolved.as_path(), socket.as_path());
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_ancestor_is_rejected() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let (_guard, root) = private_tempdir();
        let open = root.join("open");
        owner_only_dir(&open);
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).expect("chmod 0777");
        let socket = open.join("account.sock");

        let error = resolve_socket_path(&socket).expect_err("world-writable ancestor");
        assert_eq!(error, SocketPathError::WritableAncestry(open));
    }

    #[cfg(unix)]
    #[test]
    fn group_writable_ancestor_is_rejected() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let (_guard, root) = private_tempdir();
        let group = root.join("group");
        owner_only_dir(&group);
        fs::set_permissions(&group, fs::Permissions::from_mode(0o770)).expect("chmod 0770");
        let socket = group.join("account.sock");

        let error = resolve_socket_path(&socket).expect_err("group-writable ancestor");
        assert_eq!(error, SocketPathError::WritableAncestry(group));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_traversal_is_rejected() {
        let (_guard, root) = private_tempdir();
        let real = root.join("real");
        owner_only_dir(&real);
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let socket = link.join("account.sock");

        let error = resolve_socket_path(&socket).expect_err("symlink ancestor");
        assert_eq!(error, SocketPathError::Symlink(link));
    }
}
