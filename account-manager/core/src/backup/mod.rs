//! Timestamped, restorable backups of managed tool configuration.
//!
//! `NFR-4` requires that every mutation of a managed tool's config take a
//! restorable backup first. This module owns that: it captures the original
//! bytes under an RFC 3339 timestamp before an adapter writes, and it can put
//! them back afterwards.
//!
//! A backup of a credential file *is* a credential file. That is threat T6 in
//! `docs/SECURITY_MODEL.md`, and it dictates three rules:
//!
//! - Backups live in the application data directory, never beside the original
//!   file, so they are not picked up by whatever syncs a user's home directory.
//! - They are created with owner-only (`0600`) permissions on Unix, and are
//!   subject to retention pruning rather than growing without bound.
//! - They are **never** included in a diagnostic bundle.
//!
//! Writes go through [`crate::fsx`] so a backup is itself atomic.
//!
//! # What a snapshot captures
//!
//! A snapshot captures the *state* of every path an adapter listed, which
//! includes the paths that are not there. A path that did not exist is recorded
//! as absent, and restoring it deletes whatever has since appeared at that
//! name. A captured directory is walked in full, and restoring it also removes
//! files added inside it since. Without both of those, a restore would leave
//! the user holding a config they never had — a stale token in a file that was
//! supposed to be gone is exactly the failure `NFR-4` exists to prevent.
//!
//! # What a snapshot refuses
//!
//! Only regular files and directories can be captured faithfully. A symbolic
//! link, a socket, a device node, or a directory that cannot be read **fails
//! the snapshot** with an error naming the path and the reason. The alternative
//! — capturing what it can and carrying on — would hand the caller a backup
//! that silently covers less than the paths it was given, which `NFR-8`
//! forbids. Failing before anything is written is also the safer half of the
//! trade: the adapter never starts a switch it cannot undo.
//!
//! # Immutability
//!
//! A backup is immutable once written (`docs/SECURITY_MODEL.md` §5). No method
//! here writes into an existing backup directory: a snapshot creates a fresh
//! directory or fails, and captured files are set read-only on Unix. Only
//! [`BackupStore::prune`] removes one, whole.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::fsx;

/// Manifest format written by this build.
///
/// A manifest carrying a higher version is refused rather than parsed as best
/// it can be: an older build must never restore a newer build's backup on a
/// guess (`docs/ARCHITECTURE.md` §7).
///
/// File and Directory entries may carry an optional `mode` field. The field
/// is skipped when absent. `schema_version` stays 1: nothing has shipped, no
/// external backup exists, and a mode-less manifest must keep restoring
/// exactly as today (fsx defaults).
const SCHEMA_VERSION: u32 = 1;

const MANIFEST: &str = "manifest.json";
const BLOBS: &str = "files";

/// Opaque handle to one backup.
///
/// The value is also the backup's directory name, which is why it is validated
/// on the way in: an id that arrived over IPC must not be able to name a path
/// outside the backup root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct BackupId(String);

impl BackupId {
    /// Accept an id from outside this module, or reject it.
    pub fn parse(value: &str) -> Result<Self> {
        let plain = !value.is_empty()
            && value.len() <= 128
            && value.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '.')
            })
            && !value.contains("..");
        if plain {
            Ok(Self(value.to_owned()))
        } else {
            Err(invalid(format!("`{value}` is not a backup id")))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One backup, as the UI lists it. Carries no file content.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub id: BackupId,
    pub provider_id: String,
    /// RFC 3339, UTC.
    pub created_at: String,
    /// How many paths the snapshot covered, including absent ones.
    pub entry_count: usize,
}

/// How many backups to keep per provider.
///
/// The most recent backup for a provider is never pruned automatically, so a
/// misconfigured retention setting cannot leave a user with nothing to restore
/// (`docs/SECURITY_MODEL.md` §5).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPolicy {
    pub keep_per_provider: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            keep_per_provider: 10,
        }
    }
}

/// A directory of backups.
///
/// The root is always supplied by the caller so a test never touches a real
/// home or data directory; see [`default_root`] for the production value.
#[derive(Debug, Clone)]
pub struct BackupStore {
    root: PathBuf,
}

impl BackupStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Capture every path in `paths` and return the new backup's id.
    ///
    /// Nothing is written until every path has been classified, so a snapshot
    /// that refuses a path leaves no partial backup behind.
    pub fn snapshot(&self, provider_id: &str, paths: &[PathBuf]) -> Result<BackupId> {
        let mut captured = BTreeMap::new();
        for path in paths {
            capture(provider_id, path, &mut captured)?;
        }

        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| read_failed(provider_id, format!("timestamp: {error}")))?;

        fsx::create_dir_all_private(&self.root)?;
        let id = self.claim_directory(provider_id, &created_at)?;
        let directory = self.directory(&id);

        let written = self.write_backup(&directory, &id, provider_id, &created_at, captured);
        if written.is_err() {
            // A backup without a manifest is not restorable, so it must not be
            // left where `list` could ever see it.
            let _ = fs::remove_dir_all(&directory);
        }
        written.map(|()| id)
    }

    /// Return every captured path to the bytes it held at snapshot time.
    ///
    /// Idempotent: running it twice leaves the same tree, because it restores
    /// state rather than replaying a change.
    pub fn restore(&self, id: &BackupId) -> Result<()> {
        let manifest = self.read_manifest(id)?;
        let blobs = self.directory(id).join(BLOBS);
        let known: HashSet<&Path> = manifest.entries.iter().map(Entry::path).collect();

        // Directories first: entries are ordered by path (see `read_manifest`),
        // so a parent is always re-created before anything that lives inside it.
        // Force an owner-writable working mode here: a captured directory
        // restored to (or surviving at) 0555 would otherwise block
        // `fsx::copy_atomic`'s sibling temp file. The final pass below puts
        // the captured mode back.
        for entry in &manifest.entries {
            if let Entry::Directory { path, .. } = entry {
                clear_conflict(path, true)?;
                fsx::create_dir_all_private(path)?;
                apply_mode(path, Some(0o700))?;
            }
        }

        for entry in &manifest.entries {
            if let Entry::File { path, blob, .. } = entry {
                if let Some(parent) = path.parent() {
                    fsx::create_dir_all_private(parent)?;
                }
                clear_conflict(path, false)?;
                fsx::copy_atomic(&blobs.join(blob), path)?;
            }
        }

        for entry in &manifest.entries {
            if let Entry::Absent { path } = entry {
                remove_path(path)?;
            }
        }

        // Finally, anything that appeared inside a captured directory after the
        // snapshot was taken is not part of the state being restored.
        for entry in &manifest.entries {
            if let Entry::Directory { path, .. } = entry {
                for child in fs::read_dir(path).map_err(|error| fsx::io_at(path, error))? {
                    let child = child.map_err(|error| fsx::io_at(path, error))?.path();
                    if !known.contains(child.as_path()) {
                        remove_path(&child)?;
                    }
                }
            }
        }

        // Modes last: the directories-first pass forced 0700 so writes could
        // proceed; this pass reapplies the captured mode, including 0444 files
        // and 0555 directories. Created-but-uncaptured parents keep the
        // private default from `create_dir_all_private`.
        for entry in &manifest.entries {
            match entry {
                Entry::File { path, mode, .. } | Entry::Directory { path, mode } => {
                    apply_mode(path, *mode)?;
                }
                Entry::Absent { .. } => {}
            }
        }

        Ok(())
    }

    /// Every backup in the store, newest first.
    pub fn list(&self) -> Result<Vec<BackupSummary>> {
        let directories = match fs::read_dir(&self.root) {
            Ok(directories) => directories,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(fsx::io_at(&self.root, error)),
        };

        let mut listed = Vec::new();
        for directory in directories {
            let path = directory
                .map_err(|error| fsx::io_at(&self.root, error))?
                .path();
            // Anything that is not one of our backup directories is not ours to
            // interpret, and a directory without a manifest is an interrupted
            // snapshot rather than a restorable one.
            let Some(id) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| BackupId::parse(name).ok())
                .filter(|_| path.join(MANIFEST).is_file())
            else {
                continue;
            };
            let manifest = self.read_manifest(&id)?;
            let created =
                OffsetDateTime::parse(&manifest.created_at, &Rfc3339).map_err(|error| {
                    read_failed(&manifest.provider_id, format!("timestamp: {error}"))
                })?;
            listed.push((
                created,
                BackupSummary {
                    id,
                    provider_id: manifest.provider_id,
                    created_at: manifest.created_at,
                    entry_count: manifest.entries.len(),
                },
            ));
        }

        // Timestamps are compared as instants, not as strings: RFC 3339 trims
        // trailing subsecond zeroes, so `…00.9Z` sorts after `…00.85Z` textually
        // while being the earlier instant.
        listed.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| right.1.id.cmp(&left.1.id))
        });
        Ok(listed.into_iter().map(|(_, summary)| summary).collect())
    }

    /// Apply `policy`, returning the backups it removed.
    pub fn prune(&self, policy: RetentionPolicy) -> Result<Vec<BackupId>> {
        let keep = policy.keep_per_provider.max(1);
        let mut kept: HashMap<String, usize> = HashMap::new();
        let mut pruned = Vec::new();

        for summary in self.list()? {
            let count = kept.entry(summary.provider_id).or_default();
            *count += 1;
            if *count <= keep {
                continue;
            }
            let directory = self.directory(&summary.id);
            fs::remove_dir_all(&directory).map_err(|error| fsx::io_at(&directory, error))?;
            pruned.push(summary.id);
        }

        Ok(pruned)
    }

    fn directory(&self, id: &BackupId) -> PathBuf {
        self.root.join(&id.0)
    }

    /// Create the backup's own directory, or fail.
    ///
    /// `create_dir` failing on an existing name is what makes a backup
    /// immutable: a second snapshot in the same instant takes a new name rather
    /// than writing into the first one.
    fn claim_directory(&self, provider_id: &str, created_at: &str) -> Result<BackupId> {
        // `:` is not a legal file-name character on Windows, so the timestamp
        // loses its separators here. The manifest keeps the RFC 3339 form.
        let stamp = created_at.replace(':', "");
        let mut candidate = format!("{provider_id}-{stamp}");
        for attempt in 2.. {
            let id = BackupId::parse(&candidate)?;
            let directory = self.directory(&id);
            // `create_dir` failing on an existing name is the immutability
            // rule; the mode is set at creation so a umask cannot leave the
            // backup directory group- or world-readable (T6).
            let created = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new().mode(0o700).create(&directory)
                }
                #[cfg(not(unix))]
                {
                    fs::create_dir(&directory)
                }
            };
            match created {
                Ok(()) => return Ok(id),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    candidate = format!("{provider_id}-{stamp}-{attempt}");
                }
                Err(error) => return Err(fsx::io_at(&directory, error)),
            }
        }
        unreachable!("the candidate name changes on every attempt")
    }

    fn write_backup(
        &self,
        directory: &Path,
        id: &BackupId,
        provider_id: &str,
        created_at: &str,
        captured: BTreeMap<PathBuf, Kind>,
    ) -> Result<()> {
        let blobs = directory.join(BLOBS);
        fsx::create_dir_all_private(&blobs)?;

        let mut entries = Vec::with_capacity(captured.len());
        for (index, (path, kind)) in captured.into_iter().enumerate() {
            entries.push(match kind {
                Kind::File { mode } => {
                    let blob = format!("{index:05}");
                    let target = blobs.join(&blob);
                    fsx::copy_atomic(&path, &target)?;
                    seal(&target)?;
                    Entry::File { path, blob, mode }
                }
                Kind::Directory { mode } => Entry::Directory { path, mode },
                Kind::Absent => Entry::Absent { path },
            });
        }

        let manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            id: id.0.clone(),
            provider_id: provider_id.to_owned(),
            created_at: created_at.to_owned(),
            entries,
        };
        let path = directory.join(MANIFEST);
        fsx::write_atomic(&path, &serde_json::to_vec_pretty(&manifest)?)?;
        seal(&path)
    }

    fn read_manifest(&self, id: &BackupId) -> Result<Manifest> {
        let path = self.directory(id).join(MANIFEST);
        let bytes = fs::read(&path).map_err(|error| fsx::io_at(&path, error))?;

        // The version is read before the body, so a manifest this build cannot
        // understand is refused with that reason rather than a parse error.
        let probe: SchemaProbe = serde_json::from_slice(&bytes)?;
        if probe.schema_version > SCHEMA_VERSION {
            return Err(read_failed(
                &probe.provider_id,
                format!(
                    "backup `{}` uses manifest schema {}, newer than this build understands ({SCHEMA_VERSION})",
                    id.0, probe.schema_version
                ),
            ));
        }
        let mut manifest: Manifest = serde_json::from_slice(&bytes)?;
        // Parent-before-child is a restore invariant, not a property of the
        // bytes on disk. The writer emits BTreeMap order; a shuffled or
        // hand-edited manifest must still restore.
        manifest
            .entries
            .sort_by(|left, right| left.path().cmp(right.path()));
        Ok(manifest)
    }
}

/// Where backups live in a real installation.
///
/// Never called from a constructor: a [`BackupStore`] always takes its root, so
/// no code path can reach a user's data directory by default.
pub fn default_root() -> Option<PathBuf> {
    crate::paths::project_dirs().map(|dirs| dirs.data_dir().join("backups"))
}

/// What a captured path was at snapshot time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum Entry {
    File {
        path: PathBuf,
        blob: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
    },
    Directory {
        path: PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
    },
    Absent {
        path: PathBuf,
    },
}

impl Entry {
    fn path(&self) -> &Path {
        match self {
            Self::File { path, .. } | Self::Directory { path, .. } | Self::Absent { path } => path,
        }
    }
}

/// [`Entry`] before blob names have been assigned.
enum Kind {
    File { mode: Option<u32> },
    Directory { mode: Option<u32> },
    Absent,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    id: String,
    provider_id: String,
    created_at: String,
    entries: Vec<Entry>,
}

/// The part of a manifest that must be readable at every schema version.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SchemaProbe {
    schema_version: u32,
    #[serde(default)]
    provider_id: String,
}

/// Classify `path`, recursing into directories.
///
/// Paths already classified are skipped, so overlapping entries in
/// `config_paths()` cost nothing and cannot capture a file twice.
fn capture(provider_id: &str, path: &Path, out: &mut BTreeMap<PathBuf, Kind>) -> Result<()> {
    if out.contains_key(path) {
        return Ok(());
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            out.insert(path.to_path_buf(), Kind::Absent);
            return Ok(());
        }
        Err(error) => {
            return Err(read_failed(
                provider_id,
                format!("{}: {error}", path.display()),
            ))
        }
    };

    let file_type = metadata.file_type();
    if file_type.is_file() {
        out.insert(
            path.to_path_buf(),
            Kind::File {
                mode: captured_mode(&metadata),
            },
        );
        return Ok(());
    }
    if file_type.is_dir() {
        out.insert(
            path.to_path_buf(),
            Kind::Directory {
                mode: captured_mode(&metadata),
            },
        );
        let children = fs::read_dir(path)
            .map_err(|error| read_failed(provider_id, format!("{}: {error}", path.display())))?;
        for child in children {
            let child = child.map_err(|error| {
                read_failed(provider_id, format!("{}: {error}", path.display()))
            })?;
            capture(provider_id, &child.path(), out)?;
        }
        return Ok(());
    }

    Err(read_failed(
        provider_id,
        format!(
            "{} is a {}, which cannot be backed up faithfully",
            path.display(),
            if file_type.is_symlink() {
                "symbolic link"
            } else {
                "special file"
            }
        ),
    ))
}

/// Remove whatever sits at `path` when it is the wrong kind of thing.
fn clear_conflict(path: &Path, want_directory: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() == want_directory => Ok(()),
        Ok(_) => remove_path(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(fsx::io_at(path, error)),
    }
}

/// Delete a file, a symlink, or a whole directory. Missing is success.
fn remove_path(path: &Path) -> Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(fsx::io_at(path, error)),
    };
    removed.map_err(|error| fsx::io_at(path, error))
}

/// Unix permission bits of a captured file or directory, if this platform
/// has them. Absent on non-Unix, and written as an omitted JSON field so a
/// mode-less manifest stays valid.
fn captured_mode(metadata: &fs::Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(metadata.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// Reapply a captured mode after the path's content is in place.
///
/// A missing `mode` is a no-op: that is the mode-less manifest, which must
/// keep the fsx defaults (`0600` files, `0700` directories created here).
/// Non-Unix is a no-op for the same reason `seal` is.
fn apply_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    let Some(mode) = mode else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| fsx::io_at(path, error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        let _ = mode;
    }
    Ok(())
}

/// Make a written backup file read-only on Unix.
///
/// Removal is governed by the enclosing directory's permissions, so pruning
/// still works. On Windows this is a no-op; the data directory's ACL is the
/// control there.
fn seal(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))
            .map_err(|error| fsx::io_at(path, error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// A backup could not be read. Carries a path and a reason, never a value.
fn read_failed(provider_id: &str, reason: impl Into<String>) -> Error {
    Error::ConfigRead {
        provider: provider_id.to_owned(),
        reason: reason.into(),
    }
}

/// An identifier that did not come from this store.
fn invalid(reason: String) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidInput, reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small tree with a nested directory, a file beside it, and a path that
    /// deliberately does not exist.
    fn fixture(root: &Path) -> Vec<PathBuf> {
        let home = root.join("home");
        fs::create_dir_all(home.join(".claude/agents")).expect("fixture dirs");
        fs::write(home.join(".claude/config.json"), b"{\"active\":\"one\"}").expect("config");
        fs::write(
            home.join(".claude/agents/notes.md"),
            b"FAKE-access-token-0001",
        )
        .expect("nested");
        fs::write(home.join(".claude.json"), b"legacy").expect("sibling");
        vec![
            home.join(".claude"),
            home.join(".claude.json"),
            home.join(".claude-absent.json"),
        ]
    }

    fn store(root: &Path) -> BackupStore {
        BackupStore::new(root.join("backups"))
    }

    fn read(path: &Path) -> Vec<u8> {
        fs::read(path).expect("read")
    }

    #[test]
    fn round_trips_a_nested_tree_byte_for_byte() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());

        let id = store.snapshot("claude-code", &paths).expect("snapshot");
        fs::write(paths[0].join("config.json"), b"{\"active\":\"two\"}").expect("mutate");
        fs::write(&paths[1], b"clobbered").expect("mutate sibling");
        fs::remove_file(paths[0].join("agents/notes.md")).expect("delete nested");

        store.restore(&id).expect("restore");

        assert_eq!(read(&paths[0].join("config.json")), b"{\"active\":\"one\"}");
        assert_eq!(read(&paths[1]), b"legacy");
        assert_eq!(
            read(&paths[0].join("agents/notes.md")),
            b"FAKE-access-token-0001"
        );
    }

    #[test]
    fn restoring_a_path_that_did_not_exist_deletes_what_appeared_since() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());

        let id = store.snapshot("claude-code", &paths).expect("snapshot");
        fs::write(&paths[2], b"written by a failed switch").expect("create");

        store.restore(&id).expect("restore");

        assert!(
            !paths[2].exists(),
            "a path absent at snapshot time must not exist after a restore"
        );
    }

    #[test]
    fn restoring_removes_a_file_added_inside_a_captured_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());

        let id = store.snapshot("claude-code", &paths).expect("snapshot");
        let added = paths[0].join("agents/extra.md");
        fs::write(&added, b"added after the snapshot").expect("create");

        store.restore(&id).expect("restore");

        assert!(!added.exists());
    }

    #[test]
    fn restoring_twice_leaves_the_same_tree() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());

        let id = store.snapshot("claude-code", &paths).expect("snapshot");
        fs::remove_dir_all(&paths[0]).expect("delete everything");

        store.restore(&id).expect("first restore");
        store.restore(&id).expect("second restore");

        assert_eq!(read(&paths[0].join("config.json")), b"{\"active\":\"one\"}");
        assert!(!paths[2].exists());
    }

    #[test]
    fn lists_backups_newest_first() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());

        let older = store.snapshot("claude-code", &paths).expect("older");
        let newer = store.snapshot("codex-cli", &paths).expect("newer");

        let listed = store.list().expect("list");
        assert_eq!(
            listed
                .iter()
                .map(|item| item.id.clone())
                .collect::<Vec<_>>(),
            vec![newer, older]
        );
        assert_eq!(listed[0].provider_id, "codex-cli");
        assert!(OffsetDateTime::parse(&listed[0].created_at, &Rfc3339).is_ok());
    }

    #[test]
    fn retention_never_prunes_the_newest_backup_of_a_provider() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());

        let stale = store.snapshot("claude-code", &paths).expect("stale");
        let newest = store.snapshot("claude-code", &paths).expect("newest");
        let other = store.snapshot("codex-cli", &paths).expect("other provider");

        let pruned = store
            .prune(RetentionPolicy {
                keep_per_provider: 0,
            })
            .expect("prune");

        assert_eq!(pruned, vec![stale]);
        let remaining: Vec<_> = store
            .list()
            .expect("list")
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(remaining, vec![other, newest]);
    }

    #[test]
    fn refuses_a_manifest_from_a_newer_schema_version() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());
        let id = store.snapshot("claude-code", &paths).expect("snapshot");

        let manifest = store.directory(&id).join(MANIFEST);
        let raw = String::from_utf8(read(&manifest)).expect("utf-8");
        fs::remove_file(&manifest).expect("remove sealed manifest");
        fs::write(
            &manifest,
            raw.replace(
                &format!("\"schemaVersion\": {SCHEMA_VERSION}"),
                "\"schemaVersion\": 99",
            ),
        )
        .expect("rewrite");

        let refused = store.restore(&id).expect_err("must refuse");
        assert!(
            refused.to_string().contains("newer than this build"),
            "unexpected error: {refused}"
        );
        assert!(store.list().is_err(), "list must refuse it too");
    }

    /// Symlinks are the portable case of "cannot be captured faithfully"; the
    /// same branch covers sockets and device nodes, which a test cannot create
    /// portably.
    #[cfg(unix)]
    #[test]
    fn a_refused_path_leaves_no_backup_behind() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());

        std::os::unix::fs::symlink(
            temp.path().join("home/.claude.json"),
            temp.path().join("home/.claude/link"),
        )
        .expect("symlink");

        let refused = store
            .snapshot("claude-code", &paths)
            .expect_err("must refuse");
        assert!(refused.to_string().contains("symbolic link"));
        assert_eq!(store.list().expect("list").len(), 0);
    }

    #[test]
    fn a_backup_id_from_outside_cannot_escape_the_root() {
        assert!(BackupId::parse("../../etc").is_err());
        assert!(BackupId::parse("claude-code/2026").is_err());
        assert!(BackupId::parse("").is_err());
        assert!(BackupId::parse("claude-code-2026-08-18T120000.5Z").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn captured_files_are_owner_only_and_read_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());
        let id = store.snapshot("claude-code", &paths).expect("snapshot");

        let directory = store.directory(&id);
        let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode(&store.root), 0o700);
        assert_eq!(mode(&directory), 0o700);
        assert_eq!(mode(&directory.join(BLOBS)), 0o700);
        assert_eq!(mode(&directory.join(MANIFEST)), 0o400);
        for blob in fs::read_dir(directory.join(BLOBS)).expect("blobs") {
            assert_eq!(mode(&blob.expect("blob").path()), 0o400);
        }
    }

    #[cfg(unix)]
    #[test]
    fn restore_reapplies_captured_file_and_directory_modes() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        fs::create_dir_all(&home).expect("home");
        let file = home.join("config.toml");
        fs::write(&file, b"settings").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod file");
        let dir = home.join("sessions");
        fs::create_dir(&dir).expect("dir");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).expect("chmod dir");

        let store = store(temp.path());
        let id = store
            .snapshot("codex-cli", &[file.clone(), dir.clone()])
            .expect("snapshot");

        fs::write(&file, b"clobbered").expect("mutate");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("narrow file");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("narrow dir");

        store.restore(&id).expect("restore");

        let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(read(&file), b"settings");
        assert_eq!(mode(&file), 0o644);
        assert_eq!(mode(&dir), 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn a_manifest_without_mode_still_restores_with_fsx_defaults() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        fs::create_dir_all(&home).expect("home");
        let file = home.join("config.toml");
        fs::write(&file, b"settings").expect("write");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("chmod file");

        let store = store(temp.path());
        let paths = [file.clone()];
        let id = store.snapshot("codex-cli", &paths).expect("snapshot");

        let manifest = store.directory(&id).join(MANIFEST);
        let mut value: serde_json::Value =
            serde_json::from_slice(&read(&manifest)).expect("manifest json");
        let entries = value
            .get_mut("entries")
            .and_then(serde_json::Value::as_array_mut)
            .expect("entries");
        for entry in entries {
            entry.as_object_mut().expect("entry object").remove("mode");
        }
        let stripped = serde_json::to_vec_pretty(&value).expect("rewrite json");
        assert!(
            !String::from_utf8_lossy(&stripped).contains("\"mode\""),
            "mode field must be gone from the rewritten manifest"
        );
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).expect("unseal");
        fs::write(&manifest, stripped).expect("rewrite");

        fs::write(&file, b"clobbered").expect("mutate");
        store.restore(&id).expect("restore");

        let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(read(&file), b"settings");
        assert_eq!(
            mode(&file),
            0o600,
            "a mode-less manifest must keep the fsx default"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_survives_an_owner_read_only_captured_directory_twice() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        let dir = home.join("sessions");
        fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("state.json");
        fs::write(&file, b"captured").expect("write");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).expect("chmod dir");

        let store = store(temp.path());
        let paths = [dir.clone()];
        let id = store.snapshot("codex-cli", &paths).expect("snapshot");

        let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;

        store.restore(&id).expect("first restore");
        assert_eq!(read(&file), b"captured");
        assert_eq!(mode(&dir), 0o555);

        store.restore(&id).expect("second restore");
        assert_eq!(read(&file), b"captured");
        assert_eq!(mode(&dir), 0o555);
    }

    #[test]
    fn restore_accepts_a_manifest_whose_entries_are_shuffled() {
        let temp = tempfile::tempdir().expect("tempdir");
        let paths = fixture(temp.path());
        let store = store(temp.path());
        let id = store.snapshot("claude-code", &paths).expect("snapshot");

        let manifest = store.directory(&id).join(MANIFEST);
        let mut value: serde_json::Value =
            serde_json::from_slice(&read(&manifest)).expect("manifest json");
        let entries = value
            .get_mut("entries")
            .and_then(serde_json::Value::as_array_mut)
            .expect("entries");
        assert!(
            entries.len() > 1,
            "fixture must have more than one entry to shuffle"
        );
        entries.reverse();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).expect("unseal");
        }
        fs::write(
            &manifest,
            serde_json::to_vec_pretty(&value).expect("rewrite json"),
        )
        .expect("rewrite");

        fs::write(paths[0].join("config.json"), b"clobbered").expect("mutate");
        store.restore(&id).expect("restore shuffled");

        assert_eq!(read(&paths[0].join("config.json")), b"{\"active\":\"one\"}");
        assert_eq!(read(&paths[1]), b"legacy");
        assert_eq!(
            read(&paths[0].join("agents/notes.md")),
            b"FAKE-access-token-0001"
        );
    }
}
