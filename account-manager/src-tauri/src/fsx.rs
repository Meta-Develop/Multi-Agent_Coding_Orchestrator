//! Filesystem primitives that are safe by construction.
//!
//! Every write this application performs lands on a file a user depends on for
//! a working login, so the unsafe variants of these operations are not written
//! anywhere else in the tree — callers reach for this module instead.
//!
//! Two guarantees are provided:
//!
//! 1. **Atomic replace.** Content is written to a temporary file in the target
//!    directory, flushed and `fsync`ed, then renamed over the target. A reader
//!    of the target sees either the whole old file or the whole new one, never
//!    a truncated file, even if the process dies mid-write.
//! 2. **Owner-only permissions.** Files that may hold secret material are
//!    created with `0600` on Unix, and the temporary file never widens that
//!    while it exists.
//!
//! Three details carry the first guarantee, and none of them is optional:
//!
//! - The temporary file is a **sibling** of the destination. A rename across
//!   filesystems is not atomic, and a temporary directory is frequently on
//!   another filesystem.
//! - A failure anywhere before the rename leaves the destination untouched,
//!   and the temporary file is removed on the way out, including on an early
//!   return, so a failed write never litters a user's config directory.
//! - On Unix the parent directory is `fsync`ed after the rename, because the
//!   rename is itself a directory update that can outlive a crash unwritten.
//!   Windows has no equivalent handle for a directory; the rename is journalled
//!   by the filesystem instead, so that step is a documented no-op there.
//!
//! Permissions follow the same shape. `0600` and `0700` are applied on every
//! Unix target, macOS included, and at creation time rather than afterwards so
//! a new file is never briefly world-readable. On Windows the calls are no-ops:
//! the control there is the per-user application data directory, whose ACL
//! already excludes other users.
//!
//! This module depends only on `crate::error`.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{Error, Result};

/// Owner-only mode for anything that may hold secret material.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

/// Owner-only mode for a directory that holds such files.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Distinguishes concurrent temporary files within one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Replace `dest` with `bytes`, atomically and owner-only.
pub fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<()> {
    replace_with(dest, |file| file.write_all(bytes))
}

/// Replace `dest` with the contents of `source`, atomically and owner-only.
///
/// The source is streamed rather than read into memory, so a large captured
/// file never sits in the address space of a process that also holds secrets.
pub fn copy_atomic(source: &Path, dest: &Path) -> Result<()> {
    let mut reader = File::open(source).map_err(|error| io_at(source, error))?;
    replace_with(dest, |file| io::copy(&mut reader, file).map(|_| ()))
}

/// Create `path` and every missing parent with owner-only permissions.
///
/// The mode is applied as each level is created, so no intermediate directory
/// is ever briefly group- or world-readable. Existing directories are left
/// alone: widening or narrowing a directory the user already owns is not this
/// function's decision to make.
pub fn create_dir_all_private(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(DIR_MODE);
    }
    builder.create(path).map_err(|error| io_at(path, error))
}

/// Attach a path to an I/O failure so an error is actionable.
///
/// A path is safe to show; a value is not (`NFR-1`). Nothing in this module
/// ever puts file content into an error.
pub(crate) fn io_at(path: &Path, source: io::Error) -> Error {
    Error::Io(io::Error::new(
        source.kind(),
        format!("{}: {source}", path.display()),
    ))
}

/// The one write path: fill a private sibling file, then rename it over `dest`.
///
/// `fill` receives the temporary file and may fail; the destination is only
/// touched once `fill` has succeeded and the content is on the platter.
fn replace_with<F>(dest: &Path, fill: F) -> Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let parent = parent_of(dest);
    let temp = Scratch::create(dest, parent)?;

    let mut file = create_private(&temp.path)?;
    fill(&mut file).map_err(|error| io_at(&temp.path, error))?;
    file.sync_all().map_err(|error| io_at(&temp.path, error))?;
    drop(file);

    fs::rename(&temp.path, dest).map_err(|error| io_at(dest, error))?;
    temp.keep();
    sync_dir(parent)
}

/// The directory a rename must happen within.
///
/// A bare relative file name has no parent component, and the current
/// directory is the right answer for it.
fn parent_of(dest: &Path) -> &Path {
    match dest.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// A temporary file that removes itself unless the rename claimed it.
struct Scratch {
    path: PathBuf,
    keep: bool,
}

impl Scratch {
    fn create(dest: &Path, parent: &Path) -> Result<Self> {
        let name = dest.file_name().ok_or_else(|| {
            io_at(
                dest,
                io::Error::new(io::ErrorKind::InvalidInput, "not a file path"),
            )
        })?;
        let mut file_name = OsString::from(".");
        file_name.push(name);
        file_name.push(format!(
            ".tmp{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        Ok(Self {
            path: parent.join(file_name),
            keep: false,
        })
    }

    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.keep {
            // Best effort: the write already failed, and a removal failure
            // must not mask the error the caller is about to see.
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Create a new file owner-only, failing if the name is already taken.
fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    options.open(path).map_err(|error| io_at(path, error))
}

/// Make the rename itself durable. See the module doc comment for Windows.
fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|handle| handle.sync_all())
            .map_err(|error| io_at(dir, error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn write_atomic_replaces_an_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("config.json");
        write_atomic(&dest, b"first").expect("first write");
        write_atomic(&dest, b"second").expect("second write");

        assert_eq!(fs::read(&dest).expect("read"), b"second");
        assert_eq!(entries(dir.path()), vec!["config.json".to_string()]);
    }

    #[test]
    fn a_failed_write_leaves_the_destination_untouched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("config.json");
        fs::write(&dest, b"original").expect("seed");

        let outcome = replace_with(&dest, |file| {
            // A partial write followed by a failure is the dangerous shape:
            // the destination must still not have been opened at all.
            file.write_all(b"half")?;
            Err(io::Error::other("simulated mid-write failure"))
        });

        assert!(outcome.is_err());
        assert_eq!(fs::read(&dest).expect("read"), b"original");
    }

    #[test]
    fn a_failed_write_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("config.json");
        fs::write(&dest, b"original").expect("seed");

        let outcome = replace_with(&dest, |_| Err(io::Error::other("simulated failure")));

        assert!(outcome.is_err());
        assert_eq!(entries(dir.path()), vec!["config.json".to_string()]);
    }

    #[test]
    fn copy_atomic_copies_bytes_over_an_existing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = dir.path().join("source");
        let dest = dir.path().join("dest");
        fs::write(&source, b"captured bytes").expect("seed source");
        fs::write(&dest, b"stale").expect("seed dest");

        copy_atomic(&source, &dest).expect("copy");

        assert_eq!(fs::read(&dest).expect("read"), b"captured bytes");
        assert_eq!(
            entries(dir.path()),
            vec!["dest".to_string(), "source".to_string()]
        );
    }

    #[test]
    fn copying_a_missing_source_does_not_disturb_the_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("dest");
        fs::write(&dest, b"original").expect("seed");

        assert!(copy_atomic(&dir.path().join("absent"), &dest).is_err());

        assert_eq!(fs::read(&dest).expect("read"), b"original");
        assert_eq!(entries(dir.path()), vec!["dest".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn written_files_are_owner_only_even_over_a_permissive_original() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("config.json");
        fs::write(&dest, b"original").expect("seed");
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o644)).expect("chmod");

        write_atomic(&dest, b"secret material").expect("write");

        assert_eq!(mode_of(&dest), FILE_MODE);
    }

    #[cfg(unix)]
    #[test]
    fn create_dir_all_private_makes_every_level_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf = dir.path().join("backups/claude-code/2026");

        create_dir_all_private(&leaf).expect("create");

        assert_eq!(mode_of(&dir.path().join("backups")), DIR_MODE);
        assert_eq!(mode_of(&dir.path().join("backups/claude-code")), DIR_MODE);
        assert_eq!(mode_of(&leaf), DIR_MODE);
    }

    #[test]
    fn create_dir_all_private_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaf = dir.path().join("backups/claude-code");

        create_dir_all_private(&leaf).expect("create");
        create_dir_all_private(&leaf).expect("create again");

        assert!(leaf.is_dir());
    }
}
