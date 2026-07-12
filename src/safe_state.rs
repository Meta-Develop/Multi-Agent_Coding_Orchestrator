//! Filesystem primitives for security-sensitive local state.
//!
//! These helpers deliberately reject filesystem features that cannot be
//! validated without following an attacker-controlled link. State files are
//! regular, single-link files inside an owner-private directory; replacement
//! is atomic and durable; locks use a stable kernel-locked inode.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{
    collections::hash_map::RandomState,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    hash::{BuildHasher, Hash, Hasher},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    io::{AsRawFd, FromRawFd, RawFd},
};

#[cfg(windows)]
use std::os::windows::{
    fs::{MetadataExt, OpenOptionsExt},
    io::AsRawHandle,
};

pub const DEFAULT_MAX_STATE_BYTES: u64 = 8 * 1024 * 1024;
pub const DEFAULT_MAX_TEXT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TREE_DEPTH: usize = 128;
const MAX_TREE_ENTRIES: usize = 1_000_000;
#[cfg(target_os = "linux")]
const ENTRY_QUARANTINE_PREFIX: &str = ".maco-entry-quarantine-";
#[cfg(target_os = "linux")]
const TEMP_QUARANTINE_PREFIX: &str = ".maco-temp-quarantine-";
const LOCK_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(10);

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub device: u64,
    pub file: u64,
}

#[derive(Debug, Clone)]
pub struct SafeRoot {
    path: PathBuf,
    identity: FileIdentity,
    directory: Arc<File>,
    policy: RootPolicy,
}

#[derive(Debug)]
pub struct ReservedDirectory {
    path: PathBuf,
    name: OsString,
    identity: FileIdentity,
    directory: File,
}

impl ReservedDirectory {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn verify(&self, root: &SafeRoot) -> Result<()> {
        root.verify()?;
        #[cfg(unix)]
        {
            let handle = fstat(self.directory.as_raw_fd())?;
            if identity_from_stat(&handle) != self.identity {
                bail!(
                    "reserved directory handle identity changed: {}",
                    self.path.display()
                );
            }
            let name = c_string(&self.name)?;
            let rebound = fstatat_no_follow(root.directory.as_raw_fd(), &name)?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != self.identity
            {
                bail!(
                    "reserved directory name no longer identifies its opened inode: {}",
                    self.path.display()
                );
            }
            Ok(())
        }
        #[cfg(not(unix))]
        bail!("identity-bound directory reservations are unsupported on this platform")
    }

    pub fn is_empty(&self) -> Result<bool> {
        #[cfg(unix)]
        {
            let mut budget = TreeBudget::new();
            Ok(directory_entries(self.directory.as_raw_fd(), &mut budget)?.is_empty())
        }
        #[cfg(not(unix))]
        bail!("handle-relative directory inspection is unsupported on this platform")
    }
}

#[derive(Debug, Clone, Copy)]
enum RootPolicy {
    OwnerPrivate,
    Managed,
}

impl SafeRoot {
    /// Creates or opens an owner-private directory without traversing links.
    pub fn open_or_create(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_or_create_with_policy(path.as_ref(), RootPolicy::OwnerPrivate)
    }

    /// Creates or opens a current-user-owned managed directory. Existing 0700
    /// and 0755-style roots are accepted, but group/world-writable roots are
    /// refused and existing permissions are never changed.
    pub fn open_or_create_managed(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_or_create_with_policy(path.as_ref(), RootPolicy::Managed)
    }

    fn open_or_create_with_policy(path: &Path, policy: RootPolicy) -> Result<Self> {
        let path = absolute_normalized(path)?;
        let directory = secure_create_directory(&path, policy)?;
        let metadata = directory
            .metadata()
            .with_context(|| format!("failed to inspect safe root handle {}", path.display()))?;
        ensure_directory_metadata(&path, &metadata)?;
        ensure_root_policy(&path, &metadata, policy)?;
        let identity = identity_from_metadata(&metadata);
        Ok(Self {
            path,
            identity,
            directory: Arc::new(directory),
            policy,
        })
    }

    /// Opens an existing directory and verifies it without changing it.
    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self> {
        let path = absolute_normalized(path.as_ref())?;
        let directory = open_existing_directory(&path)?;
        let metadata = directory
            .metadata()
            .with_context(|| format!("failed to inspect safe root handle {}", path.display()))?;
        ensure_directory_metadata(&path, &metadata)?;
        ensure_root_policy(&path, &metadata, RootPolicy::Managed)?;
        Ok(Self {
            path,
            identity: identity_from_metadata(&metadata),
            directory: Arc::new(directory),
            policy: RootPolicy::Managed,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn verify(&self) -> Result<()> {
        let handle_metadata = self.directory.metadata().with_context(|| {
            format!(
                "failed to revalidate safe root handle {}",
                self.path.display()
            )
        })?;
        ensure_directory_metadata(&self.path, &handle_metadata)?;
        ensure_root_policy(&self.path, &handle_metadata, self.policy)?;
        let observed = identity_from_metadata(&handle_metadata);
        if observed != self.identity {
            bail!(
                "safe root identity changed at {} (expected {:?}, observed {:?})",
                self.path.display(),
                self.identity,
                observed
            );
        }
        let path_handle = open_existing_directory(&self.path).with_context(|| {
            format!(
                "safe root path is no longer reachable: {}",
                self.path.display()
            )
        })?;
        let path_metadata = path_handle.metadata().with_context(|| {
            format!(
                "failed to inspect safe root path handle {}",
                self.path.display()
            )
        })?;
        ensure_directory_metadata(&self.path, &path_metadata)?;
        ensure_root_policy(&self.path, &path_metadata, self.policy)?;
        let path_identity = identity_from_metadata(&path_metadata);
        if path_identity != self.identity {
            bail!(
                "safe root path was replaced at {} (expected {:?}, observed {:?})",
                self.path.display(),
                self.identity,
                path_identity
            );
        }
        Ok(())
    }

    pub fn direct_child(&self, name: impl AsRef<OsStr>) -> Result<PathBuf> {
        let name = name.as_ref();
        validate_single_component(name)?;
        Ok(self.path.join(name))
    }

    pub fn ensure_direct_child_absent(&self, name: impl AsRef<OsStr>) -> Result<()> {
        let name = name.as_ref();
        validate_single_component(name)?;
        self.verify()?;
        #[cfg(unix)]
        {
            let name_c = c_string(name)?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    self.directory.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                bail!(
                    "managed direct child must not already exist: {}",
                    self.path.join(name).display()
                );
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect direct child {}",
                        self.path.join(name).display()
                    )
                });
            }
            Ok(())
        }
        #[cfg(not(unix))]
        bail!("handle-relative direct-child inspection is unsupported on this platform")
    }

    pub fn direct_child_exists(&self, name: impl AsRef<OsStr>) -> Result<bool> {
        let name = name.as_ref();
        validate_single_component(name)?;
        self.verify()?;
        #[cfg(unix)]
        {
            let name_c = c_string(name)?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::fstatat(
                    self.directory.as_raw_fd(),
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == 0
            {
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(false);
            }
            Err(error).with_context(|| {
                format!(
                    "failed to inspect direct child {}",
                    self.path.join(name).display()
                )
            })
        }
        #[cfg(not(unix))]
        bail!("handle-relative direct-child inspection is unsupported on this platform")
    }

    pub fn reserve_direct_child_directory(
        &self,
        name: impl AsRef<OsStr>,
    ) -> Result<ReservedDirectory> {
        let name = name.as_ref();
        validate_single_component(name)?;
        self.verify()?;
        #[cfg(unix)]
        {
            let name_c = c_string(name)?;
            if unsafe { libc::mkdirat(self.directory.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to reserve managed directory {}",
                        self.path.join(name).display()
                    )
                });
            }
            let directory = openat_directory(self.directory.as_raw_fd(), &name_c).with_context(|| {
                format!(
                    "reserved directory could not be opened safely; preserving it for inspection: {}",
                    self.path.join(name).display()
                )
            })?;
            if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to secure reserved directory {}",
                        self.path.join(name).display()
                    )
                });
            }
            let reserved = self.validate_child_directory(name, directory, true)?;
            reserved.verify(self)?;
            Ok(reserved)
        }
        #[cfg(not(unix))]
        bail!("identity-bound directory reservations are unsupported on this platform")
    }

    pub fn reserve_random_direct_child_directory(
        &self,
        prefix: impl AsRef<OsStr>,
    ) -> Result<ReservedDirectory> {
        let prefix = prefix.as_ref();
        for _ in 0..128 {
            let candidate = random_temp_name(prefix);
            match self.reserve_direct_child_directory(&candidate) {
                Ok(reserved) => return Ok(reserved),
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io_error| {
                            io_error.kind() == std::io::ErrorKind::AlreadyExists
                        }) => {}
                Err(error) => return Err(error),
            }
        }
        bail!("failed to reserve a collision-free random managed directory")
    }

    pub fn random_direct_child_name(&self, prefix: impl AsRef<OsStr>) -> Result<OsString> {
        let prefix = prefix.as_ref();
        for _ in 0..128 {
            let candidate = random_temp_name(prefix);
            match self.ensure_direct_child_absent(&candidate) {
                Ok(()) => return Ok(candidate),
                Err(error) if error.to_string().contains("must not already exist") => {}
                Err(error) => return Err(error),
            }
        }
        bail!("failed to choose a collision-free random managed directory name")
    }

    pub fn bind_existing_direct_child_directory(
        &self,
        name: impl AsRef<OsStr>,
    ) -> Result<ReservedDirectory> {
        let name = name.as_ref();
        validate_single_component(name)?;
        self.verify()?;
        #[cfg(unix)]
        {
            let name_c = c_string(name)?;
            let directory = openat_directory(self.directory.as_raw_fd(), &name_c)?;
            let reserved = self.validate_child_directory(name, directory, true)?;
            reserved.verify(self)?;
            Ok(reserved)
        }
        #[cfg(not(unix))]
        bail!("identity-bound directory binding is unsupported on this platform")
    }

    pub fn bind_existing_managed_direct_child_directory(
        &self,
        name: impl AsRef<OsStr>,
    ) -> Result<ReservedDirectory> {
        let name = name.as_ref();
        validate_single_component(name)?;
        self.verify()?;
        #[cfg(unix)]
        {
            let name_c = c_string(name)?;
            let directory = openat_directory(self.directory.as_raw_fd(), &name_c)?;
            let reserved = self.validate_child_directory(name, directory, false)?;
            reserved.verify(self)?;
            Ok(reserved)
        }
        #[cfg(not(unix))]
        bail!("identity-bound directory binding is unsupported on this platform")
    }

    #[cfg(unix)]
    fn validate_child_directory(
        &self,
        name: &OsStr,
        directory: File,
        require_private: bool,
    ) -> Result<ReservedDirectory> {
        let stat = fstat(directory.as_raw_fd())?;
        let root_stat = fstat(self.directory.as_raw_fd())?;
        if stat.st_dev != root_stat.st_dev || stat.st_uid != unsafe { libc::geteuid() } {
            bail!(
                "reserved directory ownership or filesystem binding is unsafe: {}",
                self.path.join(name).display()
            );
        }
        let mode = stat.st_mode & 0o777;
        if (require_private && mode != 0o700) || (!require_private && mode & 0o022 != 0) {
            bail!(
                "managed child directory has unsafe mode {:04o}: {}",
                mode,
                self.path.join(name).display()
            );
        }
        Ok(ReservedDirectory {
            path: self.path.join(name),
            name: name.to_os_string(),
            identity: identity_from_stat(&stat),
            directory,
        })
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.verify()?;
        #[cfg(unix)]
        {
            let mut budget = TreeBudget::new();
            Ok(directory_entries(self.directory.as_raw_fd(), &mut budget)?.is_empty())
        }
        #[cfg(not(unix))]
        bail!("handle-relative directory inspection is unsupported on this platform")
    }
}

pub struct BoundedRegularReader;

impl BoundedRegularReader {
    pub fn read(path: impl AsRef<Path>, max_bytes: u64) -> Result<Vec<u8>> {
        let path = path.as_ref();
        let mut file = open_regular_no_follow(path, false)?;
        read_bounded_file(&mut file, path, max_bytes)
    }

    pub fn read_utf8(path: impl AsRef<Path>, max_bytes: u64) -> Result<String> {
        let path = path.as_ref();
        let bytes = Self::read(path, max_bytes)?;
        String::from_utf8(bytes)
            .with_context(|| format!("file is not valid UTF-8: {}", path.display()))
    }

    pub fn read_direct(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        root.verify()?;
        let path = root.direct_child(file_name)?;
        let mut file = open_regular_file_at(root, file_name, false)?;
        let contents = read_bounded_file(&mut file, &path, max_bytes)?;
        root.verify()?;
        Ok(contents)
    }

    /// Opens a repository-relative file component-by-component without
    /// following a link in any descendant of `root`.
    pub fn read_relative(
        root: impl AsRef<Path>,
        relative: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Vec<u8>> {
        let root = absolute_normalized(root.as_ref())?;
        let relative = validated_relative_path(relative.as_ref())?;

        #[cfg(unix)]
        {
            let mut file = open_relative_regular_unix(&root, &relative)?;
            read_bounded_file(&mut file, &root.join(&relative), max_bytes)
        }

        #[cfg(not(unix))]
        bail!("bounded no-follow reads are unsupported on this platform")
    }

    pub fn read_relative_utf8(
        root: impl AsRef<Path>,
        relative: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<String> {
        let relative_ref = relative.as_ref();
        let bytes = Self::read_relative(root, relative_ref, max_bytes)?;
        String::from_utf8(bytes).with_context(|| {
            format!(
                "repository-relative file is not valid UTF-8: {}",
                relative_ref.display()
            )
        })
    }

    pub fn identity(path: impl AsRef<Path>) -> Result<FileIdentity> {
        let path = path.as_ref();
        let file = open_regular_no_follow(path, false)?;
        identity_from_file(&file, path)
    }
}

pub struct AtomicStateWriter;

impl AtomicStateWriter {
    pub fn write(path: impl AsRef<Path>, contents: &[u8]) -> Result<()> {
        let path = absolute_normalized(path.as_ref())?;
        let parent = path
            .parent()
            .context("state path must have a parent directory")?;
        let file_name = path
            .file_name()
            .context("state path must have a file name")?;
        validate_single_component(file_name)?;
        let root = SafeRoot::open_or_create(parent)?;
        Self::write_direct(&root, file_name, contents)
    }

    pub fn write_direct(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
        contents: &[u8],
    ) -> Result<()> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        root.verify()?;
        validate_direct_state_target(root, file_name)?;

        let temp_name = random_temp_name(file_name);
        let temp_path = root.direct_child(&temp_name)?;
        let result = (|| -> Result<()> {
            let mut file = open_new_private_file_at(root, &temp_name)?;
            file.write_all(contents).with_context(|| {
                format!("failed to write temporary state {}", temp_path.display())
            })?;
            file.sync_all().with_context(|| {
                format!("failed to flush temporary state {}", temp_path.display())
            })?;
            drop(file);
            root.verify()?;
            atomic_replace_at(root, &temp_name, file_name)?;
            sync_directory(root)?;
            Ok(())
        })();
        // A failed write deliberately leaves its random temporary name for
        // lock-held scavenging. Name-only best-effort unlink here would reopen
        // an ABA window against a concurrent same-UID writer.
        result
    }

    /// Removes bounded crash residue for this exact state-file namespace.
    /// Callers must hold the corresponding stable `KernelStateLock` for the
    /// same `SafeRoot` and ensure every writer has stopped or honors that lock;
    /// otherwise a live same-UID writer could be mistaken for residue.
    pub(crate) fn scavenge_direct_temps(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
    ) -> Result<usize> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        root.verify()?;
        #[cfg(target_os = "linux")]
        {
            let mut prefix = Vec::with_capacity(file_name.as_bytes().len() + 2);
            prefix.push(b'.');
            prefix.extend_from_slice(file_name.as_bytes());
            prefix.push(b'.');
            let quarantine_prefix = temp_quarantine_namespace(file_name);
            let mut budget = TreeBudget {
                remaining_entries: 4096,
            };
            let mut removed = 0usize;
            for entry in directory_entries(root.directory.as_raw_fd(), &mut budget)? {
                let bytes = entry.as_bytes();
                let is_live_temp = bytes.starts_with(&prefix) && bytes.ends_with(b".tmp");
                let is_quarantine = bytes.starts_with(quarantine_prefix.as_bytes());
                if !is_live_temp && !is_quarantine {
                    continue;
                }
                let name = c_string(&entry)?;
                let stat = fstatat_no_follow(root.directory.as_raw_fd(), &name)?;
                if stat.st_mode & libc::S_IFMT != libc::S_IFREG
                    || stat.st_nlink != 1
                    || stat.st_uid != unsafe { libc::geteuid() }
                    || stat.st_mode & 0o777 != 0o600
                {
                    bail!(
                        "unsafe matching state temp residue requires manual inspection: {}",
                        root.path().join(&entry).display()
                    );
                }
                let expected = identity_from_stat(&stat);
                let quarantine = temp_quarantine_name(file_name, &entry, &expected);
                quarantine_regular_file(root, &entry, &quarantine, &expected)?;
                sync_directory(root)?;
                let quarantine_c = c_string(&quarantine)?;
                let rebound = fstatat_no_follow(root.directory.as_raw_fd(), &quarantine_c)?;
                if identity_from_stat(&rebound) != expected
                    || rebound.st_mode & libc::S_IFMT != libc::S_IFREG
                    || rebound.st_nlink != 1
                    || rebound.st_uid != unsafe { libc::geteuid() }
                    || rebound.st_mode & 0o777 != 0o600
                {
                    bail!("state temp quarantine changed immediately before cleanup");
                }
                if unsafe { libc::unlinkat(root.directory.as_raw_fd(), quarantine_c.as_ptr(), 0) }
                    != 0
                {
                    return Err(std::io::Error::last_os_error()).with_context(|| {
                        format!(
                            "failed to remove state temp residue {}",
                            root.path().join(&quarantine).display()
                        )
                    });
                }
                removed = removed.saturating_add(1);
            }
            if removed > 0 {
                sync_directory(root)?;
            }
            Ok(removed)
        }
        #[cfg(not(target_os = "linux"))]
        bail!("safe state temp scavenging is unsupported on this platform")
    }

    pub fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> Result<()> {
        let mut contents = serde_json::to_vec_pretty(value).context("failed to serialize state")?;
        contents.push(b'\n');
        Self::write(path, &contents)
    }
}

/// A stable lock file guarded by the operating system. The file is never
/// unlinked on release, so a waiter cannot lock a different inode by racing a
/// stale-file cleanup path.
#[derive(Debug)]
pub struct KernelStateLock {
    file: File,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy)]
enum KernelLockOperation {
    Shared,
    Exclusive,
}

impl KernelStateLock {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self> {
        let path = absolute_normalized(path.as_ref())?;
        let parent = path
            .parent()
            .context("lock path must have a parent directory")?;
        let file_name = path
            .file_name()
            .context("lock path must have a file name")?;
        validate_single_component(file_name)?;
        let root = SafeRoot::open_or_create(parent)?;
        Self::acquire_direct(&root, file_name)
    }

    pub fn acquire_direct(root: &SafeRoot, file_name: impl AsRef<OsStr>) -> Result<Self> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        root.verify()?;
        let path = root.direct_child(file_name)?;
        let file = open_stable_private_file_at(root, file_name)?;
        lock_file(&file, &path)?;
        root.verify()?;
        Ok(Self { file, path })
    }

    pub(crate) fn try_acquire_shared_direct(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
    ) -> Result<Self> {
        Self::try_acquire_direct_with_operation(
            root,
            file_name.as_ref(),
            KernelLockOperation::Shared,
        )
    }

    pub(crate) fn try_acquire_exclusive_direct(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
    ) -> Result<Self> {
        Self::try_acquire_direct_with_operation(
            root,
            file_name.as_ref(),
            KernelLockOperation::Exclusive,
        )
    }

    fn try_acquire_direct_with_operation(
        root: &SafeRoot,
        file_name: &OsStr,
        operation: KernelLockOperation,
    ) -> Result<Self> {
        validate_single_component(file_name)?;
        root.verify()?;
        let path = root.direct_child(file_name)?;
        let file = open_stable_private_file_at(root, file_name)?;
        try_lock_file(&file, &path, operation)?;
        root.verify()?;
        Ok(Self { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for KernelStateLock {
    fn drop(&mut self) {
        let _ = unlock_file(&self.file);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeLinkPolicy {
    /// Links are unlinked as entries and are never followed.
    UnlinkLinks,
    /// Any symbolic link, reparse point, hard-linked regular file, or special
    /// file observed during the bounded preflight is refused. Every unlink is
    /// rebound to the inspected inode, but a concurrent same-owner writer can
    /// still cause a safe partial deletion followed by refusal.
    RejectLinksAndSpecialFiles,
}

/// Moves an identity-bound direct-child directory to a caller-supplied
/// quarantine name using an atomic no-replace rename. The source process must
/// already be stopped and no writer may mutate the tree during quarantine or
/// cleanup. Linux provides the required `renameat2(RENAME_NOREPLACE)`
/// primitive; other platforms fail closed.
///
/// Recovery is explicit: exactly one of `child_name` and `quarantine_name`
/// must exist. If the source is absent and the quarantine entry has the
/// expected identity, the prior rename is adopted. Both-present, both-absent,
/// and identity-mismatch states are refused.
pub fn quarantine_direct_child_directory(
    root: &SafeRoot,
    child_name: impl AsRef<OsStr>,
    quarantine_name: impl AsRef<OsStr>,
    expected: &FileIdentity,
) -> Result<FileIdentity> {
    let child_name = child_name.as_ref();
    let quarantine_name = quarantine_name.as_ref();
    validate_single_component(child_name)?;
    validate_single_component(quarantine_name)?;
    if child_name == quarantine_name {
        bail!("source and quarantine directory names must differ");
    }
    root.verify()?;

    #[cfg(target_os = "linux")]
    {
        quarantine_direct_child_directory_linux(root, child_name, quarantine_name, expected)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = expected;
        bail!(
            "atomic no-replace directory quarantine is unsupported on this platform; refusing to mutate {}",
            root.path().join(child_name).display()
        )
    }
}

/// Resumably removes an already-durable quarantine directory. Absence of both
/// the durable name and its deterministic cleanup name means cleanup already
/// completed. The stopped-child/no-active-writer precondition from
/// [`quarantine_direct_child_directory`] continues to apply.
pub fn remove_quarantined_direct_child_tree(
    root: &SafeRoot,
    quarantine_name: impl AsRef<OsStr>,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
) -> Result<bool> {
    let quarantine_name = quarantine_name.as_ref();
    validate_single_component(quarantine_name)?;
    root.verify()?;

    #[cfg(target_os = "linux")]
    {
        remove_quarantined_direct_child_tree_linux(root, quarantine_name, expected, policy)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (expected, policy);
        bail!(
            "secure quarantine cleanup is unsupported on this platform; refusing to delete {}",
            root.path().join(quarantine_name).display()
        )
    }
}

/// Atomically replaces an empty reserved final directory with a verified
/// staged directory. Both names are rebound to their opened inodes immediately
/// before and after `renameat`.
pub fn replace_reserved_directory_from(
    final_root: &SafeRoot,
    final_reserved: &ReservedDirectory,
    staging_root: &SafeRoot,
    staged: &ReservedDirectory,
) -> Result<FileIdentity> {
    final_reserved.verify(final_root)?;
    staged.verify(staging_root)?;
    if !final_reserved.is_empty()? {
        bail!(
            "reserved final directory is no longer empty: {}",
            final_reserved.path().display()
        );
    }
    #[cfg(unix)]
    {
        let final_stat = fstat(final_reserved.directory.as_raw_fd())?;
        let staged_stat = fstat(staged.directory.as_raw_fd())?;
        if final_stat.st_dev != staged_stat.st_dev {
            bail!("staged and final worktree directories are on different filesystems");
        }
        let final_name = c_string(&final_reserved.name)?;
        let staged_name = c_string(&staged.name)?;
        if unsafe {
            libc::renameat(
                staging_root.directory.as_raw_fd(),
                staged_name.as_ptr(),
                final_root.directory.as_raw_fd(),
                final_name.as_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to atomically move staged directory {} to {}",
                    staged.path().display(),
                    final_reserved.path().display()
                )
            });
        }
        let rebound = fstatat_no_follow(final_root.directory.as_raw_fd(), &final_name)?;
        let expected = identity_from_stat(&staged_stat);
        if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
            || identity_from_stat(&rebound) != expected
        {
            bail!("final directory binding does not match the staged inode after rename");
        }
        sync_directory(final_root)?;
        sync_directory(staging_root)?;
        Ok(expected)
    }
    #[cfg(not(unix))]
    bail!("handle-relative staged directory replacement is unsupported on this platform")
}

/// Removes one direct child of a previously verified root. The caller must
/// first stop every process that can mutate the tree and hold its coordination
/// lock. Linux deletion first moves the bound inode to a deterministic
/// no-replace quarantine name, verifies the post-rename identity, and then
/// performs a complete no-follow preflight. Platforms without the required
/// atomic quarantine primitive fail closed.
pub fn remove_direct_child_tree(
    root: &SafeRoot,
    child_name: impl AsRef<OsStr>,
    expected: Option<&FileIdentity>,
    policy: TreeLinkPolicy,
) -> Result<()> {
    let child_name = child_name.as_ref();
    validate_single_component(child_name)?;
    root.verify()?;

    #[cfg(target_os = "linux")]
    {
        remove_direct_child_tree_unix(root, child_name, expected, policy)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (expected, policy);
        bail!(
            "secure handle-relative recursive deletion is unsupported on this platform; refusing to delete {}",
            root.path().join(child_name).display()
        );
    }
}

pub fn identity_for_path(path: impl AsRef<Path>) -> Result<FileIdentity> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect identity for {}", path.display()))?;
    ensure_not_link_or_reparse(path, &metadata)?;
    Ok(identity_from_metadata(&metadata))
}

/// Returns a deterministic accidental-corruption checksum. This is not a MAC
/// and must not be treated as attacker-controlled integrity; the security
/// boundary is the owner-private root, no-follow handles, and file identity.
pub fn stable_checksum(bytes: &[u8]) -> String {
    let mut first = 0xcbf29ce484222325_u64;
    let mut second = 0x84222325cbf29ce4_u64;
    for byte in bytes {
        first ^= u64::from(*byte);
        first = first.wrapping_mul(0x100000001b3);
        second ^= u64::from(*byte).rotate_left(1);
        second = second.wrapping_mul(0x9e3779b185ebca87);
    }
    format!("maco-v1-{first:016x}{second:016x}-{}", bytes.len())
}

fn absolute_normalized(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::Normal(segment) => normalized.push(segment),
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("path escapes its filesystem root: {}", path.display());
                }
            }
        }
    }
    Ok(normalized)
}

fn validated_relative_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("path must be a non-empty relative path: {}", path.display());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => normalized.push(segment),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!(
                    "path must not escape or use an absolute prefix: {}",
                    path.display()
                )
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        bail!("path must contain a normal component: {}", path.display());
    }
    Ok(normalized)
}

fn validate_single_component(name: &OsStr) -> Result<()> {
    let path = Path::new(name);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("expected one safe path component: {}", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn secure_create_directory(path: &Path, policy: RootPolicy) -> Result<File> {
    let segments = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(segment) => Some(segment.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut current = open_filesystem_root()?;
    let mut final_created = false;
    for (index, segment) in segments.iter().enumerate() {
        let name = c_string(segment)?;
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        let fd = if fd >= 0 {
            fd
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error).with_context(|| {
                    format!(
                        "failed to open safe directory component {}",
                        segment.to_string_lossy()
                    )
                });
            }
            let result = unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
            let mut created = result == 0;
            if result != 0 {
                let mkdir_error = std::io::Error::last_os_error();
                if mkdir_error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(mkdir_error).with_context(|| {
                        format!(
                            "failed to create safe directory component {}",
                            segment.to_string_lossy()
                        )
                    });
                }
                created = false;
            }
            let opened = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if opened < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to re-open safe directory component {}",
                        segment.to_string_lossy()
                    )
                });
            }
            if index + 1 == segments.len() {
                final_created = created;
            }
            opened
        };
        current = unsafe { File::from_raw_fd(fd) };
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(current.as_raw_fd(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to stat safe directory");
    }
    if stat.st_uid != unsafe { libc::geteuid() } {
        bail!(
            "safe state directory is not owned by the current user: {}",
            path.display()
        );
    }
    let observed_mode = stat.st_mode & 0o777;
    if final_created {
        if unsafe { libc::fchmod(current.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to set private mode on {}", path.display()));
        }
    } else {
        ensure_unix_mode_policy(path, observed_mode, policy)?;
    }
    Ok(current)
}

#[cfg(windows)]
fn secure_create_directory(path: &Path, _policy: RootPolicy) -> Result<File> {
    // std cannot establish or verify a private Windows ACL. Refuse rather
    // than claiming the Unix mode invariant on a platform where it is false.
    let _ = path;
    bail!("owner-private safe-state directories require a verified Windows ACL and are not yet supported")
}

#[cfg(not(any(unix, windows)))]
fn secure_create_directory(path: &Path, _policy: RootPolicy) -> Result<File> {
    let _ = path;
    bail!("owner-private safe-state directories are unsupported on this platform")
}

#[cfg(unix)]
fn open_existing_directory(path: &Path) -> Result<File> {
    open_unix_directory(path)
}

#[cfg(not(unix))]
fn open_existing_directory(path: &Path) -> Result<File> {
    bail!(
        "verified no-follow safe-root handles are unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn open_unix_directory(path: &Path) -> Result<File> {
    let path = absolute_normalized(path)?;
    let mut current = open_filesystem_root()?;
    for component in path.components() {
        let Component::Normal(segment) = component else {
            continue;
        };
        let name = c_string(segment)?;
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to open directory component without following links: {}",
                    segment.to_string_lossy()
                )
            });
        }
        current = unsafe { File::from_raw_fd(fd) };
    }
    Ok(current)
}

#[cfg(unix)]
fn open_filesystem_root() -> Result<File> {
    let cpath = c"/";
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open filesystem root");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn c_string(value: &OsStr) -> Result<std::ffi::CString> {
    std::ffi::CString::new(value.as_bytes()).context("filesystem path contains a NUL byte")
}

fn ensure_directory_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    ensure_not_link_or_reparse(path, metadata)?;
    if !metadata.file_type().is_dir() {
        bail!("safe root is not a directory: {}", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_root_policy(path: &Path, metadata: &fs::Metadata, policy: RootPolicy) -> Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "safe state directory is not owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    ensure_unix_mode_policy(path, mode, policy)
}

#[cfg(unix)]
fn ensure_unix_mode_policy(path: &Path, mode: u32, policy: RootPolicy) -> Result<()> {
    match policy {
        RootPolicy::OwnerPrivate if mode != 0o700 => bail!(
            "safe state directory is not owner-private (expected 0700, observed {:04o}): {}",
            mode,
            path.display()
        ),
        RootPolicy::Managed if mode & 0o022 != 0 => bail!(
            "managed directory is group/world-writable (observed {:04o}): {}",
            mode,
            path.display()
        ),
        _ => Ok(()),
    }
}

#[cfg(not(unix))]
fn ensure_root_policy(path: &Path, _metadata: &fs::Metadata, _policy: RootPolicy) -> Result<()> {
    bail!(
        "safe-root ownership and ACL verification is unsupported on this platform: {}",
        path.display()
    )
}

fn ensure_not_link_or_reparse(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        bail!("refusing symbolic link: {}", path.display());
    }
    #[cfg(windows)]
    if metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        bail!("refusing Windows reparse point: {}", path.display());
    }
    Ok(())
}

fn ensure_regular_single_link_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    ensure_not_link_or_reparse(path, metadata)?;
    if !metadata.file_type().is_file() {
        bail!("state input is not a regular file: {}", path.display());
    }
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        bail!(
            "state input must have exactly one hard link (observed {}): {}",
            metadata.nlink(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn identity_from_metadata(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    }
}

#[cfg(windows)]
fn identity_from_metadata(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.volume_serial_number().unwrap_or(0) as u64,
        file: metadata.file_index().unwrap_or(0),
    }
}

#[cfg(not(any(unix, windows)))]
fn identity_from_metadata(_metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity { device: 0, file: 0 }
}

fn identity_from_file(file: &File, path: &Path) -> Result<FileIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
    ensure_regular_single_link_metadata(path, &metadata)?;
    Ok(identity_from_metadata(&metadata))
}

#[cfg(unix)]
fn open_regular_no_follow(path: &Path, writable: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path).with_context(|| {
        format!(
            "failed to open regular file without following links: {}",
            path.display()
        )
    })?;
    identity_from_file(&file, path)?;
    Ok(file)
}

#[cfg(unix)]
fn open_regular_file_at(root: &SafeRoot, file_name: &OsStr, writable: bool) -> Result<File> {
    let name = c_string(file_name)?;
    let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    if writable {
        flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    }
    let fd = unsafe { libc::openat(root.directory.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to open direct regular file without following links: {}",
                root.path().join(file_name).display()
            )
        });
    }
    let file = unsafe { File::from_raw_fd(fd) };
    identity_from_file(&file, &root.path().join(file_name))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_file_at(root: &SafeRoot, file_name: &OsStr, _writable: bool) -> Result<File> {
    bail!(
        "handle-relative regular file opens are unsupported on this platform: {}",
        root.path().join(file_name).display()
    )
}

#[cfg(windows)]
fn open_regular_no_follow(path: &Path, writable: bool) -> Result<File> {
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).with_context(|| {
        format!(
            "failed to open regular file without following links: {}",
            path.display()
        )
    })?;
    identity_from_file(&file, path)?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_no_follow(path: &Path, _writable: bool) -> Result<File> {
    bail!(
        "no-follow regular file opens are unsupported: {}",
        path.display()
    )
}

fn read_bounded_file(file: &mut File, path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let before = file
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
    ensure_regular_single_link_metadata(path, &before)?;
    if before.len() > max_bytes {
        bail!(
            "file exceeds bounded read limit of {} bytes (observed {}): {}",
            max_bytes,
            before.len(),
            path.display()
        );
    }
    let capacity = usize::try_from(before.len().min(max_bytes))
        .context("bounded read size does not fit in memory address space")?;
    let mut contents = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut contents)
        .with_context(|| format!("failed to read bounded file {}", path.display()))?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > max_bytes {
        bail!(
            "file changed while reading and exceeded the {} byte limit: {}",
            max_bytes,
            path.display()
        );
    }
    let after = file
        .metadata()
        .with_context(|| format!("failed to revalidate opened file {}", path.display()))?;
    ensure_regular_single_link_metadata(path, &after)?;
    if identity_from_metadata(&before) != identity_from_metadata(&after)
        || before.len() != after.len()
    {
        bail!(
            "file identity changed during bounded read: {}",
            path.display()
        );
    }
    Ok(contents)
}

#[cfg(unix)]
fn open_relative_regular_unix(root: &Path, relative: &Path) -> Result<File> {
    let mut directory = open_unix_directory(root)?;
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(segment) = component else {
            bail!("invalid relative component in {}", relative.display());
        };
        let name = c_string(segment)?;
        let is_final = index + 1 == components.len();
        let flags = if is_final {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to open repository-relative component {} without following links",
                    segment.to_string_lossy()
                )
            });
        }
        let opened = unsafe { File::from_raw_fd(fd) };
        if is_final {
            identity_from_file(&opened, &root.join(relative))?;
            return Ok(opened);
        }
        let metadata = opened.metadata().with_context(|| {
            format!(
                "failed to inspect directory component {}",
                segment.to_string_lossy()
            )
        })?;
        if !metadata.file_type().is_dir() {
            bail!(
                "relative path component is not a directory: {}",
                segment.to_string_lossy()
            );
        }
        directory = opened;
    }
    bail!(
        "relative path has no final component: {}",
        relative.display()
    )
}

fn random_temp_name(file_name: &OsStr) -> OsString {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut first = RandomState::new().build_hasher();
    file_name.hash(&mut first);
    counter.hash(&mut first);
    now.hash(&mut first);
    std::process::id().hash(&mut first);
    let mut second = RandomState::new().build_hasher();
    first.finish().hash(&mut second);
    now.rotate_left(17).hash(&mut second);
    OsString::from(format!(
        ".{}.{}-{}.tmp",
        file_name.to_string_lossy(),
        first.finish(),
        second.finish()
    ))
}

#[cfg(unix)]
fn validate_direct_state_target(root: &SafeRoot, file_name: &OsStr) -> Result<()> {
    let name = c_string(file_name)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            root.directory.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        return Err(error).with_context(|| {
            format!(
                "failed to inspect direct state target {}",
                root.path().join(file_name).display()
            )
        });
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
        bail!(
            "state target is not a single-link regular file: {}",
            root.path().join(file_name).display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_direct_state_target(root: &SafeRoot, file_name: &OsStr) -> Result<()> {
    bail!(
        "handle-relative state target validation is unsupported on this platform: {}",
        root.path().join(file_name).display()
    )
}

#[cfg(unix)]
fn open_new_private_file_at(root: &SafeRoot, file_name: &OsStr) -> Result<File> {
    let name = c_string(file_name)?;
    let fd = unsafe {
        libc::openat(
            root.directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to create private temporary file {}",
                root.path().join(file_name).display()
            )
        });
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(not(unix))]
fn open_new_private_file_at(root: &SafeRoot, file_name: &OsStr) -> Result<File> {
    bail!(
        "handle-relative private file creation is unsupported on this platform: {}",
        root.path().join(file_name).display()
    )
}

#[cfg(unix)]
fn open_stable_private_file_at(root: &SafeRoot, file_name: &OsStr) -> Result<File> {
    let name = c_string(file_name)?;
    let exclusive_fd = unsafe {
        libc::openat(
            root.directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    let (fd, created) = if exclusive_fd >= 0 {
        (exclusive_fd, true)
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).with_context(|| {
                format!(
                    "failed to create stable lock file {}",
                    root.path().join(file_name).display()
                )
            });
        }
        let existing_fd = unsafe {
            libc::openat(
                root.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        (existing_fd, false)
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to open stable lock file {}",
                root.path().join(file_name).display()
            )
        });
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    ensure_regular_single_link_metadata(&root.path().join(file_name), &metadata)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "stable lock file is not owned by the current user: {}",
            root.path().join(file_name).display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if created {
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to set private lock mode on {}",
                    root.path().join(file_name).display()
                )
            });
        }
    } else if mode != 0o600 {
        bail!(
            "existing stable lock file has unsafe mode {:04o}; refusing to change it: {}",
            mode,
            root.path().join(file_name).display()
        );
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_stable_private_file_at(root: &SafeRoot, file_name: &OsStr) -> Result<File> {
    bail!(
        "handle-relative stable lock files are unsupported on this platform: {}",
        root.path().join(file_name).display()
    )
}

#[cfg(unix)]
fn lock_file(file: &File, path: &Path) -> Result<()> {
    let deadline = Instant::now() + LOCK_ACQUIRE_TIMEOUT;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error)
                .with_context(|| format!("failed to acquire kernel lock {}", path.display()));
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {} seconds waiting for kernel state lock {}",
                LOCK_ACQUIRE_TIMEOUT.as_secs(),
                path.display()
            );
        }
        thread::sleep(LOCK_RETRY_INTERVAL);
    }
}

#[cfg(unix)]
fn try_lock_file(file: &File, path: &Path, operation: KernelLockOperation) -> Result<()> {
    let operation = match operation {
        KernelLockOperation::Shared => libc::LOCK_SH,
        KernelLockOperation::Exclusive => libc::LOCK_EX,
    };
    if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        bail!("kernel state lock is already held: {}", path.display());
    }
    Err(error).with_context(|| format!("failed to acquire kernel state lock {}", path.display()))
}

#[cfg(not(unix))]
fn try_lock_file(_file: &File, path: &Path, _operation: KernelLockOperation) -> Result<()> {
    bail!(
        "shared/exclusive cooperative kernel locks are unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn unlock_file(file: &File) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to release kernel lock");
    }
    Ok(())
}

#[cfg(windows)]
fn lock_file(file: &File, path: &Path) -> Result<()> {
    use windows_sys::Win32::{
        Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
        System::IO::OVERLAPPED,
    };
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let deadline = Instant::now() + LOCK_ACQUIRE_TIMEOUT;
    loop {
        let result = unsafe {
            LockFileEx(
                file.as_raw_handle() as _,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if result != 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {} seconds waiting for kernel state lock {}",
                LOCK_ACQUIRE_TIMEOUT.as_secs(),
                path.display()
            );
        }
        thread::sleep(LOCK_RETRY_INTERVAL);
    }
}

#[cfg(windows)]
fn unlock_file(file: &File) -> Result<()> {
    use windows_sys::Win32::{Storage::FileSystem::UnlockFileEx, System::IO::OVERLAPPED};
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let result = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as _,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to release kernel lock");
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn lock_file(_file: &File, path: &Path) -> Result<()> {
    bail!("kernel state locks are unsupported: {}", path.display())
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn atomic_replace_at(root: &SafeRoot, source: &OsStr, destination: &OsStr) -> Result<()> {
    let source_name = c_string(source)?;
    let destination_name = c_string(destination)?;
    if unsafe {
        libc::renameat(
            root.directory.as_raw_fd(),
            source_name.as_ptr(),
            root.directory.as_raw_fd(),
            destination_name.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                root.path().join(destination).display(),
                root.path().join(source).display()
            )
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_noreplace_at(root: &SafeRoot, source: &OsStr, destination: &OsStr) -> Result<()> {
    let source_name = c_string(source)?;
    let destination_name = c_string(destination)?;
    if let Err(error) =
        rename_noreplace_fd(root.directory.as_raw_fd(), &source_name, &destination_name)
    {
        return Err(error).with_context(|| {
            format!(
                "failed atomic no-replace quarantine rename from {} to {}",
                root.path().join(source).display(),
                root.path().join(destination).display()
            )
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_noreplace_fd(
    fd: RawFd,
    source: &std::ffi::CStr,
    destination: &std::ffi::CStr,
) -> std::io::Result<()> {
    if unsafe {
        libc::renameat2(
            fd,
            source.as_ptr(),
            fd,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn quarantine_regular_file(
    root: &SafeRoot,
    source: &OsStr,
    quarantine: &OsStr,
    expected: &FileIdentity,
) -> Result<()> {
    let source_name = c_string(source)?;
    let quarantine_name = c_string(quarantine)?;
    let source_stat = fstatat_optional_no_follow(root.directory.as_raw_fd(), &source_name)?;
    let quarantine_stat = fstatat_optional_no_follow(root.directory.as_raw_fd(), &quarantine_name)?;
    match (source_stat, quarantine_stat) {
        (Some(_), Some(_)) => bail!("state temp source and quarantine both exist"),
        (None, None) => bail!("state temp source and quarantine are both absent"),
        (None, Some(stat)) => {
            validate_private_regular_quarantine(&stat, expected)?;
            Ok(())
        }
        (Some(stat), None) => {
            validate_private_regular_quarantine(&stat, expected)?;
            rename_noreplace_at(root, source, quarantine)?;
            let rebound = fstatat_no_follow(root.directory.as_raw_fd(), &quarantine_name)?;
            validate_private_regular_quarantine(&rebound, expected)?;
            if fstatat_optional_no_follow(root.directory.as_raw_fd(), &source_name)?.is_some() {
                bail!("state temp source name reappeared during quarantine");
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_private_regular_quarantine(stat: &libc::stat, expected: &FileIdentity) -> Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o600
        || identity_from_stat(stat) != *expected
    {
        bail!("state temp quarantine is unsafe or changed");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn component_checksum(name: &OsStr) -> String {
    stable_checksum(name.as_bytes())
}

#[cfg(target_os = "linux")]
fn deletion_quarantine_name(name: &OsStr, identity: &FileIdentity) -> OsString {
    OsString::from(format!(
        ".maco-delete-{}-{:016x}-{:016x}",
        component_checksum(name),
        identity.device,
        identity.file
    ))
}

#[cfg(target_os = "linux")]
fn entry_quarantine_name(name: &OsStr, identity: &FileIdentity) -> OsString {
    OsString::from(format!(
        "{ENTRY_QUARANTINE_PREFIX}{}-{:016x}-{:016x}",
        component_checksum(name),
        identity.device,
        identity.file
    ))
}

#[cfg(target_os = "linux")]
fn temp_quarantine_namespace(file_name: &OsStr) -> String {
    format!("{TEMP_QUARANTINE_PREFIX}{}-", component_checksum(file_name))
}

#[cfg(target_os = "linux")]
fn temp_quarantine_name(file_name: &OsStr, source: &OsStr, identity: &FileIdentity) -> OsString {
    OsString::from(format!(
        "{}{}-{:016x}-{:016x}",
        temp_quarantine_namespace(file_name),
        component_checksum(source),
        identity.device,
        identity.file
    ))
}

#[cfg(not(unix))]
fn atomic_replace_at(root: &SafeRoot, source: &OsStr, destination: &OsStr) -> Result<()> {
    let _ = source;
    bail!(
        "handle-relative atomic state replacement is unsupported on this platform: {}",
        root.path().join(destination).display()
    )
}

fn sync_directory(root: &SafeRoot) -> Result<()> {
    root.directory
        .sync_all()
        .with_context(|| format!("failed to flush state directory {}", root.path().display()))
}

#[cfg(target_os = "linux")]
fn quarantine_direct_child_directory_linux(
    root: &SafeRoot,
    child_name: &OsStr,
    quarantine_name: &OsStr,
    expected: &FileIdentity,
) -> Result<FileIdentity> {
    let parent_fd = root.directory.as_raw_fd();
    let source = c_string(child_name)?;
    let quarantine = c_string(quarantine_name)?;
    let source_stat = fstatat_optional_no_follow(parent_fd, &source)?;
    let quarantine_stat = fstatat_optional_no_follow(parent_fd, &quarantine)?;
    match (source_stat, quarantine_stat) {
        (Some(_), Some(_)) => bail!(
            "source and quarantine both exist; refusing ambiguous recovery for {}",
            root.path().join(child_name).display()
        ),
        (None, None) => bail!(
            "source and quarantine are both absent; refusing ambiguous recovery for {}",
            root.path().join(child_name).display()
        ),
        (None, Some(stat)) => {
            validate_private_quarantine_directory(root, quarantine_name, &stat, expected)?;
            Ok(expected.clone())
        }
        (Some(stat), None) => {
            validate_private_quarantine_directory(root, child_name, &stat, expected)?;
            rename_noreplace_at(root, child_name, quarantine_name)?;
            let rebound = fstatat_no_follow(parent_fd, &quarantine)?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != *expected
            {
                bail!(
                    "quarantine identity mismatch after atomic rename for {}",
                    root.path().join(child_name).display()
                );
            }
            if fstatat_optional_no_follow(parent_fd, &source)?.is_some() {
                bail!("source name reappeared during directory quarantine");
            }
            sync_directory(root)?;
            Ok(expected.clone())
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_private_quarantine_directory(
    root: &SafeRoot,
    name: &OsStr,
    stat: &libc::stat,
    expected: &FileIdentity,
) -> Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || identity_from_stat(stat) != *expected
        || stat.st_uid != unsafe { libc::geteuid() }
    {
        bail!(
            "quarantine directory binding is unsafe or changed: {}",
            root.path().join(name).display()
        );
    }
    let cname = c_string(name)?;
    let directory = openat_directory(root.directory.as_raw_fd(), &cname)?;
    let opened = fstat(directory.as_raw_fd())?;
    if identity_from_stat(&opened) != *expected {
        bail!("quarantine directory changed while opening its handle");
    }
    if opened.st_mode & 0o777 != 0o700 {
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to tighten quarantine directory permissions at {}",
                    root.path().join(name).display()
                )
            });
        }
        let tightened = fstat(directory.as_raw_fd())?;
        if identity_from_stat(&tightened) != *expected || tightened.st_mode & 0o777 != 0o700 {
            bail!("quarantine directory did not become owner-private");
        }
        directory
            .sync_all()
            .context("failed to flush owner-private quarantine directory")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_quarantined_direct_child_tree_linux(
    root: &SafeRoot,
    quarantine_name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
) -> Result<bool> {
    let cleanup_name = deletion_quarantine_name(quarantine_name, expected);
    let quarantine = c_string(quarantine_name)?;
    let cleanup = c_string(&cleanup_name)?;
    let source_exists =
        fstatat_optional_no_follow(root.directory.as_raw_fd(), &quarantine)?.is_some();
    let cleanup_exists =
        fstatat_optional_no_follow(root.directory.as_raw_fd(), &cleanup)?.is_some();
    if !source_exists && !cleanup_exists {
        return Ok(false);
    }
    quarantine_direct_child_directory_linux(root, quarantine_name, &cleanup_name, expected)?;
    remove_tree_at_name_linux(root, &cleanup_name, expected, policy)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn remove_direct_child_tree_unix(
    root: &SafeRoot,
    child_name: &OsStr,
    expected: Option<&FileIdentity>,
    policy: TreeLinkPolicy,
) -> Result<()> {
    let expected = match expected {
        Some(expected) => expected.clone(),
        None => {
            let name = c_string(child_name)?;
            let stat = fstatat_no_follow(root.directory.as_raw_fd(), &name)?;
            identity_from_stat(&stat)
        }
    };
    let quarantine_name = deletion_quarantine_name(child_name, &expected);
    quarantine_direct_child_directory_linux(root, child_name, &quarantine_name, &expected)?;
    remove_tree_at_name_linux(root, &quarantine_name, &expected, policy)
}

#[cfg(target_os = "linux")]
fn remove_tree_at_name_linux(
    root: &SafeRoot,
    name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
) -> Result<()> {
    let directory = root.directory.as_ref();
    let root_stat = fstat(directory.as_raw_fd())?;
    let cname = c_string(name)?;
    let child = openat_directory(directory.as_raw_fd(), &cname)?;
    let child_stat = fstat(child.as_raw_fd())?;
    if child_stat.st_dev != root_stat.st_dev {
        bail!(
            "refusing to cross a filesystem boundary while deleting {}",
            root.path().join(name).display()
        );
    }
    let observed = identity_from_stat(&child_stat);
    if expected != &observed {
        bail!(
            "directory identity changed before deletion at {}",
            root.path().join(name).display()
        );
    }
    let mut audit_budget = TreeBudget::new();
    audit_directory_unix(
        child.as_raw_fd(),
        child_stat.st_dev,
        policy,
        0,
        &mut audit_budget,
    )?;
    let mut removal_budget = TreeBudget::new();
    remove_directory_contents_unix(
        child.as_raw_fd(),
        child_stat.st_dev,
        policy,
        0,
        &mut removal_budget,
    )?;
    drop(child);
    let rebound = fstatat_no_follow(directory.as_raw_fd(), &cname)?;
    if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR || identity_from_stat(&rebound) != observed {
        bail!(
            "top-level directory binding changed immediately before removal: {}",
            root.path().join(name).display()
        );
    }
    if unsafe { libc::unlinkat(directory.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to remove verified directory {}",
                root.path().join(name).display()
            )
        });
    }
    sync_directory(root)?;
    root.verify()?;
    Ok(())
}

#[cfg(unix)]
struct TreeBudget {
    remaining_entries: usize,
}

#[cfg(unix)]
impl TreeBudget {
    fn new() -> Self {
        Self {
            remaining_entries: MAX_TREE_ENTRIES,
        }
    }

    fn consume(&mut self) -> Result<()> {
        self.remaining_entries = self
            .remaining_entries
            .checked_sub(1)
            .context("recursive deletion exceeded its global entry budget")?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn audit_directory_unix(
    fd: RawFd,
    device: libc::dev_t,
    policy: TreeLinkPolicy,
    depth: usize,
    budget: &mut TreeBudget,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        bail!("recursive deletion exceeded its maximum depth of {MAX_TREE_DEPTH}");
    }
    for name in directory_entries(fd, budget)? {
        let cname = c_string(&name)?;
        let stat = fstatat_no_follow(fd, &cname)?;
        if stat.st_dev != device {
            bail!(
                "refusing to traverse a mounted filesystem entry: {}",
                name.to_string_lossy()
            );
        }
        let kind = stat.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            let child = openat_directory(fd, &cname)?;
            let opened = fstat(child.as_raw_fd())?;
            if identity_from_stat(&opened) != identity_from_stat(&stat) {
                bail!(
                    "directory entry changed during deletion preflight: {}",
                    name.to_string_lossy()
                );
            }
            audit_directory_unix(
                child.as_raw_fd(),
                device,
                policy,
                depth.saturating_add(1),
                budget,
            )?;
        } else if kind == libc::S_IFLNK {
            if policy == TreeLinkPolicy::RejectLinksAndSpecialFiles {
                bail!(
                    "refusing symbolic link in artifact tree: {}",
                    name.to_string_lossy()
                );
            }
        } else if kind == libc::S_IFREG {
            if policy == TreeLinkPolicy::RejectLinksAndSpecialFiles && stat.st_nlink != 1 {
                bail!(
                    "refusing hard-linked file in artifact tree: {}",
                    name.to_string_lossy()
                );
            }
        } else if policy == TreeLinkPolicy::RejectLinksAndSpecialFiles {
            bail!(
                "refusing special file in artifact tree: {}",
                name.to_string_lossy()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_directory_contents_unix(
    fd: RawFd,
    device: libc::dev_t,
    policy: TreeLinkPolicy,
    depth: usize,
    budget: &mut TreeBudget,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        bail!("recursive deletion exceeded its maximum depth of {MAX_TREE_DEPTH}");
    }
    for name in directory_entries(fd, budget)? {
        let source_name = c_string(&name)?;
        let stat = fstatat_no_follow(fd, &source_name)?;
        if stat.st_dev != device {
            bail!(
                "filesystem entry changed across devices during deletion: {}",
                name.to_string_lossy()
            );
        }
        let expected = identity_from_stat(&stat);
        let quarantine_name = entry_quarantine_name(&name, &expected);
        let quarantine_c = c_string(&quarantine_name)?;
        rename_noreplace_fd(fd, &source_name, &quarantine_c).with_context(|| {
            format!(
                "failed to quarantine child entry {} before deletion",
                name.to_string_lossy()
            )
        })?;
        let rebound = fstatat_no_follow(fd, &quarantine_c)?;
        if identity_from_stat(&rebound) != expected
            || rebound.st_mode & libc::S_IFMT != stat.st_mode & libc::S_IFMT
        {
            bail!(
                "child entry identity changed during quarantine: {}",
                name.to_string_lossy()
            );
        }
        if fstatat_optional_no_follow(fd, &source_name)?.is_some() {
            bail!("child source name reappeared during quarantine");
        }
        let cname = c_string(&quarantine_name)?;
        let quarantined = fstatat_no_follow(fd, &cname)?;
        if identity_from_stat(&quarantined) != expected {
            bail!("quarantined child identity changed before deletion");
        }
        let kind = quarantined.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            let child = openat_directory(fd, &cname)?;
            let opened = fstat(child.as_raw_fd())?;
            if identity_from_stat(&opened) != expected {
                bail!(
                    "directory entry changed during deletion: {}",
                    name.to_string_lossy()
                );
            }
            remove_directory_contents_unix(
                child.as_raw_fd(),
                device,
                policy,
                depth.saturating_add(1),
                budget,
            )?;
            drop(child);
            let rebound = fstatat_no_follow(fd, &cname)?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != expected
            {
                bail!(
                    "child directory binding changed immediately before removal: {}",
                    name.to_string_lossy()
                );
            }
            if unsafe { libc::unlinkat(fd, cname.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to remove child directory {}",
                        name.to_string_lossy()
                    )
                });
            }
        } else {
            if policy == TreeLinkPolicy::RejectLinksAndSpecialFiles
                && (kind == libc::S_IFLNK || kind != libc::S_IFREG || quarantined.st_nlink != 1)
            {
                bail!(
                    "artifact entry changed to an unsafe type: {}",
                    name.to_string_lossy()
                );
            }
            let rebound = fstatat_no_follow(fd, &cname)?;
            if identity_from_stat(&rebound) != expected || rebound.st_mode & libc::S_IFMT != kind {
                bail!(
                    "child entry binding changed immediately before unlink: {}",
                    name.to_string_lossy()
                );
            }
            if unsafe { libc::unlinkat(fd, cname.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to unlink child {}", name.to_string_lossy()));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn directory_entries(fd: RawFd, budget: &mut TreeBudget) -> Result<Vec<OsString>> {
    let dot = c".";
    let stream_fd = unsafe {
        libc::openat(
            fd,
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if stream_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open an independent directory stream handle");
    }
    let directory = unsafe { libc::fdopendir(stream_fd) };
    if directory.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(stream_fd) };
        return Err(error).context("failed to open directory stream");
    }
    let mut entries = Vec::new();
    loop {
        clear_thread_errno()?;
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let errno = std::io::Error::last_os_error();
            unsafe { libc::closedir(directory) };
            if errno.raw_os_error().unwrap_or(0) != 0 {
                return Err(errno).context("failed while reading directory stream");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if let Err(error) = budget.consume() {
            unsafe { libc::closedir(directory) };
            return Err(error);
        }
        entries.push(OsString::from_vec(name.to_bytes().to_vec()));
    }
    entries.sort();
    Ok(entries)
}

#[cfg(target_os = "linux")]
fn clear_thread_errno() -> Result<()> {
    unsafe { *libc::__errno_location() = 0 };
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_thread_errno() -> Result<()> {
    unsafe { *libc::__error() = 0 };
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn clear_thread_errno() -> Result<()> {
    bail!("directory iteration is unsupported for this Unix errno ABI")
}

#[cfg(unix)]
fn openat_directory(fd: RawFd, name: &std::ffi::CStr) -> Result<File> {
    let opened = unsafe {
        libc::openat(
            fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if opened < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open directory entry without following links");
    }
    Ok(unsafe { File::from_raw_fd(opened) })
}

#[cfg(unix)]
fn fstat(fd: RawFd) -> Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to inspect file handle");
    }
    Ok(stat)
}

#[cfg(unix)]
fn fstatat_no_follow(fd: RawFd, name: &std::ffi::CStr) -> Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect directory entry without following links");
    }
    Ok(stat)
}

#[cfg(target_os = "linux")]
fn fstatat_optional_no_follow(fd: RawFd, name: &std::ffi::CStr) -> Result<Option<libc::stat>> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        return Ok(Some(stat));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error).context("failed to inspect optional directory entry without following links")
    }
}

#[cfg(unix)]
fn identity_from_stat(stat: &libc::stat) -> FileIdentity {
    FileIdentity {
        device: stat.st_dev,
        file: stat.st_ino,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn atomic_writer_uses_private_regular_files_and_preserves_lock_inode() {
        let temp = TempDir::new().expect("tempdir");
        let state = temp.path().join("state").join("claims.json");
        AtomicStateWriter::write(&state, b"first\n").expect("first write");
        AtomicStateWriter::write(&state, b"second\n").expect("second write");
        assert_eq!(
            BoundedRegularReader::read_utf8(&state, 32).expect("read"),
            "second\n"
        );

        let lock_path = state.parent().expect("parent").join("claims.lock");
        let first_identity = {
            let lock = KernelStateLock::acquire(&lock_path).expect("lock");
            let identity = identity_for_path(lock.path()).expect("identity");
            drop(lock);
            identity
        };
        let second = KernelStateLock::acquire(&lock_path).expect("relock");
        assert_eq!(
            identity_for_path(second.path()).expect("second identity"),
            first_identity
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_symlink_hardlink_fifo_and_large_file() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("root");
        fs::create_dir(&root).expect("root");
        let regular = root.join("regular");
        fs::write(&regular, b"0123456789").expect("write regular");

        let link = root.join("link");
        symlink(&regular, &link).expect("symlink");
        assert!(BoundedRegularReader::read(&link, 32).is_err());

        let hard = root.join("hard");
        fs::hard_link(&regular, &hard).expect("hard link");
        assert!(BoundedRegularReader::read(&regular, 32).is_err());

        fs::remove_file(&hard).expect("remove hard");
        assert!(BoundedRegularReader::read(&regular, 4).is_err());

        let fifo = root.join("fifo");
        let fifo_name = c_string(fifo.as_os_str()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        assert!(BoundedRegularReader::read(&fifo, 32).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn strict_tree_delete_rejects_link_without_touching_external_target() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("runs")).expect("safe root");
        let external = temp.path().join("external");
        fs::create_dir(&external).expect("external");
        fs::write(external.join("keep"), "keep").expect("external file");
        let run = root.path().join("run-a");
        fs::create_dir(&run).expect("run");
        symlink(&external, run.join("escape")).expect("escape link");
        let identity = identity_for_path(&run).expect("run identity");

        let error = remove_direct_child_tree(
            &root,
            "run-a",
            Some(&identity),
            TreeLinkPolicy::RejectLinksAndSpecialFiles,
        )
        .expect_err("strict delete must refuse link");
        assert!(error.to_string().contains("symbolic link"));
        assert!(external.join("keep").exists());
        assert!(!run.exists());
        let quarantine = root
            .path()
            .join(deletion_quarantine_name(OsStr::new("run-a"), &identity));
        assert_eq!(
            identity_for_path(&quarantine).expect("quarantined identity"),
            identity
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_managed_root_accepts_0755_but_strict_state_root_does_not_chmod_it() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("managed");
        fs::create_dir(&root).expect("root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("mode");

        let error = SafeRoot::open_or_create(&root).expect_err("strict root must refuse 0755");
        assert!(error.to_string().contains("owner-private"));
        assert_eq!(
            fs::symlink_metadata(&root)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        SafeRoot::open_or_create_managed(&root).expect("managed root accepts 0755");
    }

    #[cfg(unix)]
    #[test]
    fn tree_delete_refuses_renamed_substitute_identity() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
        let child = root.path().join("child");
        fs::create_dir(&child).expect("child");
        fs::write(child.join("original"), "keep").expect("original");
        let expected = identity_for_path(&child).expect("identity");
        let moved = root.path().join("moved");
        fs::rename(&child, &moved).expect("rename original");
        fs::create_dir(&child).expect("substitute");

        let error =
            remove_direct_child_tree(&root, "child", Some(&expected), TreeLinkPolicy::UnlinkLinks)
                .expect_err("substitute must not be removed");
        assert!(!error.to_string().is_empty());
        assert!(child.exists());
        assert!(moved.join("original").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn directory_quarantine_adopts_only_one_matching_binding() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
        let source = root.path().join("source");
        let quarantine = root.path().join("quarantine");
        fs::create_dir(&source).expect("source");
        let expected = identity_for_path(&source).expect("identity");

        quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect("initial quarantine");
        assert!(!source.exists());
        assert_eq!(
            identity_for_path(&quarantine).expect("quarantine identity"),
            expected
        );
        assert_eq!(
            fs::symlink_metadata(&quarantine)
                .expect("quarantine metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect("adopt prior rename");

        fs::create_dir(&source).expect("ambiguous source");
        let error = quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect_err("both-present state must fail closed");
        assert!(error.to_string().contains("both exist"));
        assert!(source.exists());
        assert!(quarantine.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quarantined_tree_cleanup_resumes_after_entry_rename_and_partial_delete() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
        let source = root.path().join("source");
        fs::create_dir(&source).expect("source");
        fs::write(source.join("first"), "first").expect("first");
        fs::write(source.join("second"), "second").expect("second");
        let expected = identity_for_path(&source).expect("source identity");
        quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect("durable quarantine");
        let quarantine = root.path().join("quarantine");
        fs::remove_file(quarantine.join("first")).expect("simulate partial cleanup");
        let second = quarantine.join("second");
        let second_identity = identity_for_path(&second).expect("second identity");
        let entry_quarantine = entry_quarantine_name(OsStr::new("second"), &second_identity);
        fs::rename(&second, quarantine.join(&entry_quarantine))
            .expect("simulate crash after child quarantine rename");

        assert!(remove_quarantined_direct_child_tree(
            &root,
            "quarantine",
            &expected,
            TreeLinkPolicy::UnlinkLinks,
        )
        .expect("resume cleanup"));
        assert!(!quarantine.exists());
        assert!(!remove_quarantined_direct_child_tree(
            &root,
            "quarantine",
            &expected,
            TreeLinkPolicy::UnlinkLinks,
        )
        .expect("idempotent completed cleanup"));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn supported_unix_errno_abi_can_be_cleared_explicitly() {
        clear_thread_errno().expect("supported errno ABI");
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(0));
    }

    #[cfg(unix)]
    #[test]
    fn stable_lock_refuses_unsafe_existing_mode_without_changing_it() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
        let lock_path = root.path().join("state.lock");
        fs::write(&lock_path, "").expect("lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).expect("unsafe mode");

        let error = KernelStateLock::acquire(&lock_path).expect_err("unsafe lock must fail");
        assert!(error.to_string().contains("unsafe mode"));
        assert_eq!(
            fs::symlink_metadata(&lock_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn locked_writer_scavenges_only_safe_matching_crash_temps() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
        let _lock = KernelStateLock::acquire_direct(&root, "claims.lock").expect("lock");
        let residue = root.path().join(".claims.json.crashed.tmp");
        fs::write(&residue, "partial").expect("residue");
        fs::set_permissions(&residue, fs::Permissions::from_mode(0o600)).expect("private mode");
        let expected = BoundedRegularReader::identity(&residue).expect("residue identity");
        let quarantine = temp_quarantine_name(
            OsStr::new("claims.json"),
            OsStr::new(".claims.json.crashed.tmp"),
            &expected,
        );
        quarantine_regular_file(
            &root,
            OsStr::new(".claims.json.crashed.tmp"),
            &quarantine,
            &expected,
        )
        .expect("simulate crash after temp quarantine rename");
        assert!(!residue.exists());
        assert!(root.path().join(&quarantine).exists());

        assert_eq!(
            AtomicStateWriter::scavenge_direct_temps(&root, "claims.json").expect("scavenge"),
            1
        );
        assert!(!residue.exists());
        AtomicStateWriter::write_direct(&root, "claims.json", b"complete\n")
            .expect("durable write");
        assert_eq!(
            BoundedRegularReader::read_direct(&root, "claims.json", 32).expect("read"),
            b"complete\n"
        );
    }
}
