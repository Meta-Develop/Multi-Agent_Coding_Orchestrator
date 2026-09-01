//! Filesystem primitives for security-sensitive local state.
//!
//! These helpers deliberately reject filesystem features that cannot be
//! validated without following an attacker-controlled link. State files are
//! regular, single-link files inside an owner-private directory; replacement
//! is atomic and durable; locks use a stable kernel-locked inode.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{
    collections::{hash_map::RandomState, BTreeMap, BTreeSet},
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
#[cfg(unix)]
const TEMP_QUARANTINE_PREFIX: &str = ".maco-temp-quarantine-";
#[cfg(unix)]
const TEMP_QUARANTINE_V2_PREFIX: &str = ".maco-temp-quarantine-v2-";
#[cfg(unix)]
const TEMP_QUARANTINE_V2_DOMAIN: &[u8] = b"MACO\0temp-quarantine\0v2\0";
#[cfg(unix)]
const DELETION_QUARANTINE_PREFIX: &str = ".maco-delete-";
#[cfg(unix)]
const DELETION_QUARANTINE_V2_PREFIX: &str = ".maco-delete-v2-";
#[cfg(unix)]
const DELETION_QUARANTINE_V2_DOMAIN: &[u8] = b"MACO\0deletion-quarantine\0v2\0";
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectChildType {
    SingleLinkRegularFile,
    Directory,
}

#[derive(Debug)]
pub(crate) struct DirectChildBinding {
    name: OsString,
    identity: FileIdentity,
    root_identity: FileIdentity,
    kind: DirectChildType,
    file: File,
}

impl DirectChildBinding {
    pub(crate) fn verify(&self, root: &SafeRoot) -> Result<()> {
        root.verify()?;
        if self.root_identity != *root.identity() {
            bail!("direct child binding was presented with a different root inode");
        }
        #[cfg(unix)]
        {
            let handle = fstat(self.file.as_raw_fd())?;
            validate_owned_direct_child_stat(&handle, &self.identity, self.kind)?;
            let name = c_string(&self.name)?;
            let rebound = fstatat_no_follow(root.directory.as_raw_fd(), &name)?;
            validate_owned_direct_child_stat(&rebound, &self.identity, self.kind)?;
            Ok(())
        }
        #[cfg(not(unix))]
        bail!("identity-bound direct child verification is unsupported on this platform")
    }

    pub(crate) fn set_permissions_fenced(&self, root: &SafeRoot, mode: u32) -> Result<()> {
        self.verify(root)?;
        #[cfg(unix)]
        {
            self.file
                .set_permissions(fs::Permissions::from_mode(mode))
                .with_context(|| {
                    format!(
                        "failed to set permissions on bound direct child {}",
                        root.path().join(&self.name).display()
                    )
                })?;
            let after = fstat(self.file.as_raw_fd())?;
            if unsigned_to_u32(after.st_mode & 0o777) != mode & 0o777 {
                bail!("bound direct child permissions did not reach the requested mode");
            }
            self.verify(root)
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
            bail!("descriptor-relative permission changes are unsupported on this platform")
        }
    }

    pub(crate) fn unlink_fenced(self, root: &SafeRoot) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.verify(root)?;
            let root_stat = fstat(root.directory.as_raw_fd())?;
            validate_owned_direct_child_stat(
                &root_stat,
                root.identity(),
                DirectChildType::Directory,
            )?;
            if root_stat.st_mode & 0o777 != 0o700 {
                bail!("direct child quarantine requires an owner-private root");
            }
            let handle_before = fstat(self.file.as_raw_fd())?;
            if handle_before.st_mode & 0o777 != 0o600 {
                bail!("direct child must be owner-private before quarantine unlink");
            }
            let quarantine_name = entry_quarantine_name(&self.name, &self.identity);
            quarantine_regular_file(root, &self.name, &quarantine_name, &self.identity)?;
            sync_directory(root)?;
            run_direct_child_before_quarantine_unlink_hook();

            let source = c_string(&self.name)?;
            if fstatat_optional_no_follow(root.directory.as_raw_fd(), &source)?.is_some() {
                bail!("direct child source name reappeared after quarantine");
            }
            let quarantine = c_string(&quarantine_name)?;
            let quarantined = fstatat_no_follow(root.directory.as_raw_fd(), &quarantine)?;
            validate_private_regular_quarantine(&quarantined, &self.identity)?;
            if unsafe { libc::unlinkat(root.directory.as_raw_fd(), quarantine.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to unlink quarantined direct child {}",
                        root.path().join(&quarantine_name).display()
                    )
                });
            }
            if fstatat_optional_no_follow(root.directory.as_raw_fd(), &quarantine)?.is_some() {
                bail!("quarantined direct child pathname still exists after unlink");
            }
            if fstatat_optional_no_follow(root.directory.as_raw_fd(), &source)?.is_some() {
                bail!("direct child source name reappeared during quarantine unlink");
            }
            let handle = fstat(self.file.as_raw_fd())?;
            if identity_from_stat(&handle) != self.identity
                || handle.st_mode & libc::S_IFMT != libc::S_IFREG
                || handle.st_uid != unsafe { libc::geteuid() }
                || handle.st_nlink != 0
            {
                bail!("unlinked direct child descriptor changed unexpectedly");
            }
            sync_directory(root)?;
            root.verify()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, root);
            bail!("atomic quarantine direct child unlink is unsupported on this platform")
        }
    }
}

#[cfg(test)]
type DirectChildBeforeQuarantineUnlinkHook = Option<Box<dyn FnOnce()>>;

#[cfg(test)]
thread_local! {
    static DIRECT_CHILD_BEFORE_QUARANTINE_UNLINK_HOOK: std::cell::RefCell<DirectChildBeforeQuarantineUnlinkHook> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_direct_child_before_quarantine_unlink_hook(hook: impl FnOnce() + 'static) {
    DIRECT_CHILD_BEFORE_QUARANTINE_UNLINK_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_direct_child_before_quarantine_unlink_hook() {
    let hook = DIRECT_CHILD_BEFORE_QUARANTINE_UNLINK_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_direct_child_before_quarantine_unlink_hook() {}

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
        #[cfg(windows)]
        let identity = identity_from_open_handle(&directory, &path)?;
        #[cfg(not(windows))]
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
        #[cfg(windows)]
        let identity = identity_from_open_handle(&directory, &path)?;
        #[cfg(not(windows))]
        let identity = identity_from_metadata(&metadata);
        Ok(Self {
            path,
            identity,
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

    /// Returns the Linux mount id shared by the held directory descriptor and its current
    /// pathname binding.
    ///
    /// Bind mounts can preserve device/inode identity while changing the kernel mount domain, so
    /// callers that treat one configured path as a physical authority boundary must retain this
    /// value for the lifetime of the live binding and recheck it as well as [`FileIdentity`].
    pub fn linux_mount_id(&self) -> Result<u64> {
        self.verify()?;
        #[cfg(target_os = "linux")]
        {
            let held = linux_mount_identity_for_fd(self.directory.as_raw_fd())?.mount_id;
            let rebound = open_existing_directory(&self.path).with_context(|| {
                format!(
                    "safe root path is no longer reachable for mount verification: {}",
                    self.path.display()
                )
            })?;
            let rebound_mount = linux_mount_identity_for_fd(rebound.as_raw_fd())?.mount_id;
            if held != rebound_mount {
                bail!(
                    "safe root mount binding changed at {} (descriptor {}, pathname {})",
                    self.path.display(),
                    held,
                    rebound_mount
                );
            }
            self.verify()?;
            Ok(held)
        }
        #[cfg(not(target_os = "linux"))]
        bail!(
            "safe-root mount identity verification requires Linux statx: {}",
            self.path.display()
        )
    }

    /// Verifies that both the held descriptor and rebound pathname remain on `expected_mount_id`.
    pub fn verify_linux_mount_id(&self, expected_mount_id: u64) -> Result<()> {
        let observed = self.linux_mount_id()?;
        if observed != expected_mount_id {
            bail!(
                "safe root mount id changed at {} (expected {}, observed {})",
                self.path.display(),
                expected_mount_id,
                observed
            );
        }
        Ok(())
    }

    /// Returns the mount id of an existing direct child without following a symbolic link.
    ///
    /// `None` denotes an absent child. The statx result is identity-checked against the same
    /// descriptor-relative `fstatat` observation before it is returned.
    pub fn direct_child_linux_mount_id(&self, name: impl AsRef<OsStr>) -> Result<Option<u64>> {
        let name = name.as_ref();
        validate_single_component(name)?;
        let root_mount_id = self.linux_mount_id()?;
        #[cfg(target_os = "linux")]
        {
            let name_c = c_string(name)?;
            let Some(stat) = fstatat_optional_no_follow(self.directory.as_raw_fd(), &name_c)?
            else {
                self.verify_linux_mount_id(root_mount_id)?;
                return Ok(None);
            };
            let mount =
                linux_mount_identity_at(self.directory.as_raw_fd(), &name_c, &stat)?.mount_id;
            self.verify_linux_mount_id(root_mount_id)?;
            Ok(Some(mount))
        }
        #[cfg(not(target_os = "linux"))]
        bail!(
            "direct-child mount identity verification requires Linux statx: {}",
            self.path.join(name).display()
        )
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
        #[cfg(windows)]
        let observed = identity_from_open_handle(&self.directory, &self.path)?;
        #[cfg(not(windows))]
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
        #[cfg(windows)]
        let path_identity = identity_from_open_handle(&path_handle, &self.path)?;
        #[cfg(not(windows))]
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

    pub(crate) fn bind_owned_direct_child(
        &self,
        name: impl AsRef<OsStr>,
        expected_identity: &FileIdentity,
        kind: DirectChildType,
    ) -> Result<DirectChildBinding> {
        let name = name.as_ref();
        validate_single_component(name)?;
        self.verify()?;
        #[cfg(unix)]
        {
            let name_c = c_string(name)?;
            let flags = match kind {
                DirectChildType::SingleLinkRegularFile => {
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
                }
                DirectChildType::Directory => {
                    libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK
                }
            };
            let fd = unsafe { libc::openat(self.directory.as_raw_fd(), name_c.as_ptr(), flags) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to bind direct child without following links: {}",
                        self.path.join(name).display()
                    )
                });
            }
            let binding = DirectChildBinding {
                name: name.to_os_string(),
                identity: expected_identity.clone(),
                root_identity: self.identity.clone(),
                kind,
                file: unsafe { File::from_raw_fd(fd) },
            };
            binding.verify(self)?;
            Ok(binding)
        }
        #[cfg(not(unix))]
        {
            let _ = (expected_identity, kind);
            bail!("identity-bound direct child opens are unsupported on this platform")
        }
    }

    pub(crate) fn set_directory_permissions_fenced(&self, mode: u32) -> Result<()> {
        self.verify()?;
        #[cfg(unix)]
        {
            let before = fstat(self.directory.as_raw_fd())?;
            validate_owned_direct_child_stat(&before, &self.identity, DirectChildType::Directory)?;
            self.directory
                .set_permissions(fs::Permissions::from_mode(mode))
                .with_context(|| {
                    format!(
                        "failed to set permissions on bound directory {}",
                        self.path.display()
                    )
                })?;
            self.verify()?;
            let after = fstat(self.directory.as_raw_fd())?;
            validate_owned_direct_child_stat(&after, &self.identity, DirectChildType::Directory)?;
            if unsigned_to_u32(after.st_mode & 0o777) != mode & 0o777 {
                bail!("bound directory permissions did not reach the requested mode");
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
            bail!(
                "descriptor-relative directory permission changes are unsupported on this platform"
            )
        }
    }

    pub(crate) fn sync_directory_fenced(&self) -> Result<()> {
        self.verify()?;
        self.directory
            .sync_all()
            .with_context(|| format!("failed to flush state directory {}", self.path.display()))?;
        self.verify()
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

    pub(crate) fn remove_empty_reserved_direct_child_directory(
        &self,
        reserved: ReservedDirectory,
    ) -> Result<()> {
        reserved.verify(self)?;
        if !reserved.is_empty()? {
            bail!("refusing to remove a non-empty reserved directory");
        }
        #[cfg(unix)]
        {
            let name = c_string(&reserved.name)?;
            if unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to remove empty reserved directory {}",
                        reserved.path.display()
                    )
                });
            }
            self.verify()
        }
        #[cfg(not(unix))]
        bail!("identity-bound directory removal is unsupported on this platform")
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

    pub(crate) fn direct_child_names_bounded(&self, max_entries: usize) -> Result<Vec<OsString>> {
        self.verify()?;
        if max_entries == 0 {
            bail!("direct child inventory requires a positive entry bound");
        }
        #[cfg(unix)]
        {
            let mut budget = TreeBudget {
                remaining_entries: max_entries.saturating_add(1),
            };
            let entries = directory_entries(self.directory.as_raw_fd(), &mut budget)
                .context("safe root direct child inventory exceeded its bound")?;
            if entries.len() > max_entries {
                bail!("safe root exceeds its bounded direct child count");
            }
            self.verify()?;
            Ok(entries)
        }
        #[cfg(not(unix))]
        bail!("handle-relative directory inventory is unsupported on this platform")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedTreeEntryKind {
    Directory,
    RegularFile,
    Symlink,
    Special,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTreeEntry {
    pub relative_path: PathBuf,
    pub kind: BoundedTreeEntryKind,
    pub size_bytes: u64,
    pub hard_link_count: u64,
    pub unix_mode: u32,
    pub identity: FileIdentity,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub changed_seconds: i64,
    pub changed_nanoseconds: i64,
}

impl BoundedTreeEntry {
    pub fn is_safe_regular_file(&self) -> bool {
        self.kind == BoundedTreeEntryKind::RegularFile
            && self.hard_link_count == 1
            && self.unix_mode & 0o6000 == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedTreeWalkLimits {
    pub max_depth: usize,
    pub max_entries: usize,
    pub max_path_bytes: usize,
    pub max_total_path_bytes: usize,
    pub max_duration: Duration,
    pub same_device: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BoundedTreeWalkOptions {
    pub stop_at_nested_repositories: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundedTreeWalkResult {
    pub entries: Vec<BoundedTreeEntry>,
    pub nested_repository_boundaries: Vec<PathBuf>,
}

impl BoundedTreeWalkLimits {
    fn validate(self) -> Result<Self> {
        if self.max_depth == 0
            || self.max_entries == 0
            || self.max_path_bytes == 0
            || self.max_total_path_bytes == 0
            || self.max_duration.is_zero()
        {
            bail!("bounded tree walk limits must all be greater than zero");
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedTreeWalkAction {
    Skip,
    Record,
    RecordAndDescend,
}

pub struct BoundedTreeWalker;

/// Binds a directory pathname to the exact opened filesystem object.  The
/// descriptor is retained so callers can fence multi-phase, path-based work
/// against a concurrent rename/replacement of the directory. Directory entry
/// churn is allowed because it changes directory timestamps without changing
/// the bound object or its pathname association.
#[derive(Debug)]
pub struct DirectoryBindingGuard {
    path: PathBuf,
    directory: File,
    identity: FileIdentity,
}

/// Retains an opened regular file and its exact bounded contents so a caller
/// can fence pathname-based association metadata (for example Git gitfiles
/// and `commondir`) across a multi-phase operation.
#[derive(Debug)]
pub struct RegularFileBindingGuard {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    generation: fs::Metadata,
    contents: Vec<u8>,
    max_bytes: u64,
}

impl RegularFileBindingGuard {
    pub fn bind(path: impl AsRef<Path>, max_bytes: u64) -> Result<Self> {
        let path = absolute_normalized(path.as_ref())?;
        let mut file = open_regular_no_follow(&path, false)?;
        let contents = read_bounded_file(&mut file, &path, max_bytes)?;
        let generation = file.metadata()?;
        let identity = identity_from_file(&file, &path)?;
        Ok(Self {
            path,
            file,
            identity,
            generation,
            contents,
            max_bytes,
        })
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    pub fn verify(&self) -> Result<()> {
        let held = self.file.metadata()?;
        if identity_from_file(&self.file, &self.path)? != self.identity
            || !same_file_generation(&self.generation, &held)
        {
            bail!("held regular-file binding changed: {}", self.path.display());
        }
        let mut rebound = open_regular_no_follow(&self.path, false).with_context(|| {
            format!(
                "regular-file pathname binding disappeared: {}",
                self.path.display()
            )
        })?;
        let rebound_contents = read_bounded_file(&mut rebound, &self.path, self.max_bytes)?;
        let rebound_generation = rebound.metadata()?;
        if identity_from_file(&rebound, &self.path)? != self.identity
            || !same_file_generation(&self.generation, &rebound_generation)
            || rebound_contents != self.contents
        {
            bail!(
                "regular-file pathname binding changed: {}",
                self.path.display()
            );
        }
        Ok(())
    }
}

impl DirectoryBindingGuard {
    pub fn bind(path: impl AsRef<Path>) -> Result<Self> {
        let path = absolute_normalized(path.as_ref())?;
        #[cfg(unix)]
        {
            let directory = open_unix_directory(&path)?;
            let stat = fstat(directory.as_raw_fd())?;
            if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                bail!(
                    "directory binding target is not a directory: {}",
                    path.display()
                );
            }
            Ok(Self {
                path,
                identity: identity_from_stat(&stat),
                directory,
            })
        }
        #[cfg(windows)]
        {
            let directory = open_windows_directory(&path)?;
            let metadata = directory.metadata().with_context(|| {
                format!("failed to inspect directory binding {}", path.display())
            })?;
            if !metadata.file_type().is_dir() {
                bail!(
                    "directory binding target is not a directory: {}",
                    path.display()
                );
            }
            ensure_not_link_or_reparse(&path, &metadata)?;
            let identity = identity_from_open_handle(&directory, &path)?;
            Ok(Self {
                path,
                identity,
                directory,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            bail!("verified directory pathname bindings are unsupported on this platform")
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub(crate) fn read_relative(&self, relative: &Path, max_bytes: u64) -> Result<Vec<u8>> {
        let relative = validated_relative_path(relative)?;
        #[cfg(target_os = "linux")]
        {
            let mut file =
                open_repository_relative_linux_fd(self.directory.as_raw_fd(), &relative)?;
            read_bounded_file(&mut file, &self.path.join(&relative), max_bytes)
        }
        #[cfg(not(target_os = "linux"))]
        BoundedRegularReader::read_relative(&self.path, relative, max_bytes)
    }

    pub(crate) fn read_relative_optional(
        &self,
        relative: &Path,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        let relative = validated_relative_path(relative)?;
        #[cfg(target_os = "linux")]
        {
            let file =
                match open_repository_relative_linux_fd(self.directory.as_raw_fd(), &relative) {
                    Ok(file) => file,
                    Err(error)
                        if error
                            .root_cause()
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                    {
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                };
            let metadata = file.metadata()?;
            if metadata.is_dir() {
                return Ok(None);
            }
            ensure_regular_single_link_metadata(&self.path.join(&relative), &metadata)?;
            let mut file = file;
            read_bounded_file(&mut file, &self.path.join(&relative), max_bytes).map(Some)
        }
        #[cfg(not(target_os = "linux"))]
        BoundedRegularReader::read_relative_optional(&self.path, relative, max_bytes)
    }

    pub fn verify(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let held = fstat(self.directory.as_raw_fd())?;
            if held.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&held) != self.identity
            {
                bail!("held directory binding changed: {}", self.path.display());
            }
            let rebound_directory = open_unix_directory(&self.path).with_context(|| {
                format!(
                    "directory pathname binding disappeared: {}",
                    self.path.display()
                )
            })?;
            let rebound = fstat(rebound_directory.as_raw_fd())?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != self.identity
            {
                bail!(
                    "directory pathname binding changed: {}",
                    self.path.display()
                );
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            let held = self.directory.metadata().with_context(|| {
                format!(
                    "failed to inspect held directory binding {}",
                    self.path.display()
                )
            })?;
            if !held.file_type().is_dir()
                || identity_from_open_handle(&self.directory, &self.path)? != self.identity
            {
                bail!("held directory binding changed: {}", self.path.display());
            }
            let rebound_directory = open_windows_directory(&self.path).with_context(|| {
                format!(
                    "directory pathname binding disappeared: {}",
                    self.path.display()
                )
            })?;
            let rebound = rebound_directory.metadata().with_context(|| {
                format!(
                    "failed to inspect rebound directory binding {}",
                    self.path.display()
                )
            })?;
            if !rebound.file_type().is_dir()
                || identity_from_open_handle(&rebound_directory, &self.path)? != self.identity
            {
                bail!(
                    "directory pathname binding changed: {}",
                    self.path.display()
                );
            }
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        bail!("verified directory pathname bindings are unsupported on this platform")
    }
}

impl BoundedTreeWalker {
    pub fn walk(
        root: impl AsRef<Path>,
        limits: BoundedTreeWalkLimits,
    ) -> Result<Vec<BoundedTreeEntry>> {
        Self::walk_with(root, limits, |entry| {
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Record
            })
        })
    }

    pub fn walk_with<F>(
        root: impl AsRef<Path>,
        limits: BoundedTreeWalkLimits,
        action: F,
    ) -> Result<Vec<BoundedTreeEntry>>
    where
        F: FnMut(&BoundedTreeEntry) -> Result<BoundedTreeWalkAction>,
    {
        let root = absolute_normalized(root.as_ref())?;
        let root_binding = DirectoryBindingGuard::bind(&root)?;
        Self::walk_bound_with(&root_binding, limits, action)
    }

    pub(crate) fn walk_bound_with<F>(
        root_binding: &DirectoryBindingGuard,
        limits: BoundedTreeWalkLimits,
        action: F,
    ) -> Result<Vec<BoundedTreeEntry>>
    where
        F: FnMut(&BoundedTreeEntry) -> Result<BoundedTreeWalkAction>,
    {
        Self::walk_bound_with_options(
            root_binding,
            limits,
            BoundedTreeWalkOptions::default(),
            action,
        )
    }

    pub(crate) fn walk_bound_with_options<F>(
        root_binding: &DirectoryBindingGuard,
        limits: BoundedTreeWalkLimits,
        options: BoundedTreeWalkOptions,
        action: F,
    ) -> Result<Vec<BoundedTreeEntry>>
    where
        F: FnMut(&BoundedTreeEntry) -> Result<BoundedTreeWalkAction>,
    {
        Ok(Self::walk_bound_with_options_detailed(root_binding, limits, options, action)?.entries)
    }

    pub(crate) fn walk_bound_with_options_detailed<F>(
        root_binding: &DirectoryBindingGuard,
        limits: BoundedTreeWalkLimits,
        options: BoundedTreeWalkOptions,
        mut action: F,
    ) -> Result<BoundedTreeWalkResult>
    where
        F: FnMut(&BoundedTreeEntry) -> Result<BoundedTreeWalkAction>,
    {
        let limits = limits.validate()?;

        #[cfg(unix)]
        {
            let root_stat = fstat(root_binding.directory.as_raw_fd())?;
            #[cfg(target_os = "linux")]
            let root_mount_id = if limits.same_device {
                Some(linux_mount_identity_for_fd(root_binding.directory.as_raw_fd())?.mount_id)
            } else {
                None
            };
            let deadline = Instant::now()
                .checked_add(limits.max_duration)
                .context("bounded tree walk deadline overflowed")?;
            let mut budget = InventoryBudget {
                remaining_entries: limits.max_entries,
                total_path_bytes: 0,
                deadline,
            };
            let mut entries = Vec::new();
            let mut nested_repository_boundaries = Vec::new();
            let mut walker = InventoryWalkState {
                root_device: root_stat.st_dev,
                #[cfg(target_os = "linux")]
                root_mount_id,
                limits,
                options,
                budget: &mut budget,
                action: &mut action,
                entries: &mut entries,
                nested_repository_boundaries: &mut nested_repository_boundaries,
            };
            walker.walk(root_binding.directory.as_raw_fd(), Path::new(""), 0)?;
            budget.ensure_before_deadline("after repository traversal")?;
            root_binding.verify()?;
            nested_repository_boundaries.sort();
            Ok(BoundedTreeWalkResult {
                entries,
                nested_repository_boundaries,
            })
        }

        #[cfg(windows)]
        {
            walk_bound_windows(root_binding, limits, options, action)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (root_binding, limits, &mut action);
            bail!("descriptor-relative bounded tree walks are unsupported on this platform")
        }
    }
}

#[cfg(windows)]
fn walk_bound_windows<F>(
    root_binding: &DirectoryBindingGuard,
    limits: BoundedTreeWalkLimits,
    options: BoundedTreeWalkOptions,
    mut action: F,
) -> Result<BoundedTreeWalkResult>
where
    F: FnMut(&BoundedTreeEntry) -> Result<BoundedTreeWalkAction>,
{
    let limits = limits.validate()?;
    let deadline = Instant::now()
        .checked_add(limits.max_duration)
        .context("bounded tree walk deadline overflowed")?;
    let mut budget = InventoryBudget {
        remaining_entries: limits.max_entries,
        total_path_bytes: 0,
        deadline,
    };
    let mut entries = Vec::new();
    let mut nested_repository_boundaries = Vec::new();
    walk_bound_windows_dir(
        root_binding,
        Path::new(""),
        0,
        root_binding.identity.device,
        limits,
        options,
        &mut budget,
        &mut action,
        &mut entries,
        &mut nested_repository_boundaries,
    )?;
    budget.ensure_before_deadline("after repository traversal")?;
    root_binding.verify()?;
    nested_repository_boundaries.sort();
    Ok(BoundedTreeWalkResult {
        entries,
        nested_repository_boundaries,
    })
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn walk_bound_windows_dir<F>(
    root_binding: &DirectoryBindingGuard,
    relative_directory: &Path,
    depth: usize,
    root_device: u64,
    limits: BoundedTreeWalkLimits,
    options: BoundedTreeWalkOptions,
    budget: &mut InventoryBudget,
    action: &mut F,
    entries: &mut Vec<BoundedTreeEntry>,
    nested_repository_boundaries: &mut Vec<PathBuf>,
) -> Result<()>
where
    F: FnMut(&BoundedTreeEntry) -> Result<BoundedTreeWalkAction>,
{
    budget.ensure_before_deadline("before directory enumeration")?;
    let current_path = if relative_directory.as_os_str().is_empty() {
        root_binding.path.clone()
    } else {
        root_binding.path.join(relative_directory)
    };
    if nested_repository_boundary_enabled(depth, options)
        && windows_nested_repository_marker_exists(&current_path, budget)?
    {
        nested_repository_boundaries.push(relative_directory.to_path_buf());
        return Ok(());
    }
    if depth >= limits.max_depth {
        bail!(
            "repository inventory refused to descend beyond depth {} at {}",
            limits.max_depth,
            relative_directory.display()
        );
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(&current_path).with_context(|| {
        format!(
            "failed to enumerate repository directory {}",
            current_path.display()
        )
    })? {
        budget.ensure_before_deadline("during directory enumeration")?;
        budget.consume_entry()?;
        names.push(entry?.file_name());
    }
    names.sort();
    for name in names {
        budget.ensure_before_deadline("during entry inspection")?;
        let relative = relative_directory.join(&name);
        let entry_depth = depth.saturating_add(1);
        if entry_depth > limits.max_depth {
            bail!(
                "repository inventory exceeded its maximum depth of {} at {}",
                limits.max_depth,
                relative.display()
            );
        }
        budget.consume_path(&relative, limits)?;
        let full_path = root_binding.path.join(&relative);
        let snapshot =
            crate::file_identity::open_windows_path_identity(&full_path).with_context(|| {
                format!("failed to inspect repository entry {}", relative.display())
            })?;
        if limits.same_device && snapshot.identity.device != root_device {
            bail!(
                "repository inventory refused a cross-device entry: {}",
                relative.display()
            );
        }
        let file_type = snapshot.metadata.file_type();
        let reparse = snapshot.metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0;
        let kind =
            if file_type.is_symlink() || (reparse && !file_type.is_dir() && !file_type.is_file()) {
                BoundedTreeEntryKind::Symlink
            } else if file_type.is_dir() && !reparse {
                BoundedTreeEntryKind::Directory
            } else if file_type.is_file() && !reparse {
                BoundedTreeEntryKind::RegularFile
            } else if reparse {
                BoundedTreeEntryKind::Symlink
            } else {
                BoundedTreeEntryKind::Special
            };
        let (modified_seconds, modified_nanoseconds) =
            system_time_parts(snapshot.metadata.modified().ok());
        let (changed_seconds, changed_nanoseconds) =
            system_time_parts(snapshot.metadata.created().ok());
        let entry = BoundedTreeEntry {
            relative_path: relative.clone(),
            kind,
            size_bytes: snapshot.metadata.len(),
            hard_link_count: u64::from(snapshot.number_of_links),
            unix_mode: 0,
            identity: FileIdentity {
                device: snapshot.identity.device,
                file: snapshot.identity.file,
            },
            modified_seconds,
            modified_nanoseconds,
            changed_seconds,
            changed_nanoseconds,
        };
        let decision = (action)(&entry)?;
        budget.ensure_before_deadline("after repository inventory callback")?;
        if matches!(
            decision,
            BoundedTreeWalkAction::Record | BoundedTreeWalkAction::RecordAndDescend
        ) {
            entries.push(entry.clone());
        }
        if decision == BoundedTreeWalkAction::RecordAndDescend {
            if kind != BoundedTreeEntryKind::Directory {
                bail!(
                    "bounded tree walk requested descent through a non-directory: {}",
                    relative.display()
                );
            }
            walk_bound_windows_dir(
                root_binding,
                &relative,
                entry_depth,
                root_device,
                limits,
                options,
                budget,
                action,
                entries,
                nested_repository_boundaries,
            )?;
        }
        let rebound =
            crate::file_identity::open_windows_path_identity(&full_path).with_context(|| {
                format!(
                    "failed to revalidate repository entry after traversal: {}",
                    relative.display()
                )
            })?;
        if (FileIdentity {
            device: rebound.identity.device,
            file: rebound.identity.file,
        }) != entry.identity
        {
            bail!(
                "repository entry changed during bounded traversal: {}",
                relative.display()
            );
        }
    }
    Ok(())
}

fn nested_repository_boundary_enabled(depth: usize, options: BoundedTreeWalkOptions) -> bool {
    options.stop_at_nested_repositories && depth > 0
}

#[cfg(windows)]
fn windows_nested_repository_marker_exists(
    directory: &Path,
    budget: &InventoryBudget,
) -> Result<bool> {
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "failed to probe nested repository directory {}",
            directory.display()
        )
    })? {
        budget.ensure_before_deadline("during nested repository marker probe")?;
        if entry?.file_name().as_os_str() == OsStr::new(".git") {
            return Ok(true);
        }
    }
    budget.ensure_before_deadline("after nested repository marker probe")?;
    Ok(false)
}

#[cfg(windows)]
fn system_time_parts(time: Option<SystemTime>) -> (i64, i64) {
    let Some(time) = time else {
        return (0, 0);
    };
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            i64::from(duration.subsec_nanos()),
        ),
        Err(_) => (0, 0),
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

    /// Reads an arbitrary filesystem path component-by-component while
    /// refusing symbolic links in both ancestors and the final leaf. The
    /// opened descriptor is identity-stable for the full bounded read.
    pub fn read_tree_no_follow(path: impl AsRef<Path>, max_bytes: u64) -> Result<Vec<u8>> {
        let absolute = absolute_normalized(path.as_ref())?;
        #[cfg(unix)]
        {
            let root = Path::new(std::path::MAIN_SEPARATOR_STR);
            let relative = absolute.strip_prefix(root).with_context(|| {
                format!("failed to make path root-relative: {}", absolute.display())
            })?;
            let mut file = open_relative_regular_unix_allow_mounts(root, relative)?;
            read_bounded_file(&mut file, &absolute, max_bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = (absolute, max_bytes);
            bail!("component-wise no-follow reads are unsupported on this platform")
        }
    }

    /// Reads a no-follow tree path while validating metadata from the exact opened descriptor
    /// before and after the bounded read.
    ///
    /// The validator is intended for policy beyond the regular/single-link invariant, such as
    /// current-user ownership and mode checks on security-sensitive configuration.
    pub fn read_tree_no_follow_validated<F>(
        path: impl AsRef<Path>,
        max_bytes: u64,
        mut validate: F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(&fs::Metadata) -> Result<()>,
    {
        let absolute = absolute_normalized(path.as_ref())?;
        #[cfg(unix)]
        {
            let root = Path::new(std::path::MAIN_SEPARATOR_STR);
            let relative = absolute.strip_prefix(root).with_context(|| {
                format!("failed to make path root-relative: {}", absolute.display())
            })?;
            let mut file = open_relative_regular_unix_allow_mounts(root, relative)?;
            read_bounded_file_with_validator_and_hook(
                &mut file,
                &absolute,
                max_bytes,
                &mut validate,
                || {},
            )
        }
        #[cfg(not(unix))]
        {
            let _ = (absolute, max_bytes, &mut validate);
            bail!("component-wise validated no-follow reads are unsupported on this platform")
        }
    }

    /// Reads an arbitrary UTF-8 filesystem input without following symbolic
    /// links in any ancestor or in the final leaf.
    pub fn read_tree_no_follow_utf8(path: impl AsRef<Path>, max_bytes: u64) -> Result<String> {
        let path = path.as_ref();
        let bytes = Self::read_tree_no_follow(path, max_bytes)?;
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

        #[cfg(target_os = "linux")]
        {
            let mut file = open_repository_relative_regular_linux(&root, &relative)?;
            read_bounded_file(&mut file, &root.join(&relative), max_bytes)
        }

        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let mut file = open_relative_regular_unix_allow_mounts(&root, &relative)?;
            read_bounded_file(&mut file, &root.join(&relative), max_bytes)
        }

        #[cfg(not(unix))]
        Self::read(root.join(relative), max_bytes)
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

    /// Reads a repository-relative UTF-8 regular file when it exists. A
    /// missing path or a safely opened directory is represented as `None`, so
    /// callers may retain directory and planned-file scopes without weakening
    /// the no-follow boundary. Links, special files, and multiply-linked
    /// regular files are rejected.
    pub fn read_relative_optional_utf8(
        root: impl AsRef<Path>,
        relative: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Option<String>> {
        let relative = relative.as_ref();
        let Some(bytes) = Self::read_relative_optional(root, relative, max_bytes)? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .with_context(|| {
                format!(
                    "repository-relative file is not valid UTF-8: {}",
                    relative.display()
                )
            })
            .map(Some)
    }

    pub fn read_relative_optional(
        root: impl AsRef<Path>,
        relative: impl AsRef<Path>,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        let root = absolute_normalized(root.as_ref())?;
        let relative = validated_relative_path(relative.as_ref())?;

        #[cfg(target_os = "linux")]
        {
            let Some(mut file) = open_repository_relative_optional_regular_linux(&root, &relative)?
            else {
                return Ok(None);
            };
            read_bounded_file(&mut file, &root.join(&relative), max_bytes).map(Some)
        }

        #[cfg(not(target_os = "linux"))]
        read_relative_optional_portable(&root, &relative, max_bytes)
    }

    pub fn identity(path: impl AsRef<Path>) -> Result<FileIdentity> {
        let path = path.as_ref();
        let file = open_regular_no_follow(path, false)?;
        identity_from_file(&file, path)
    }
}

#[cfg(not(target_os = "linux"))]
fn read_relative_optional_portable(
    root: &Path,
    relative: &Path,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    match BoundedRegularReader::read_relative(root, relative, max_bytes) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => {
            let path = root.join(relative);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() => Ok(None),
                _ => Err(error),
            }
        }
    }
}

pub struct AtomicStateWriter;

impl AtomicStateWriter {
    pub(crate) fn canonical_direct_temp_target(name: &OsStr) -> Result<Option<OsString>> {
        #[cfg(unix)]
        {
            if let Some(target) = canonical_random_temp_target(name) {
                return Ok(Some(target));
            }
            Ok(canonical_temp_quarantine_binding(name)?.map(|binding| binding.target))
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            Ok(None)
        }
    }

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
        Self::write_direct_fenced(root, file_name, contents, || root.verify())
    }

    /// Stages a complete private file, then consults `fence` immediately
    /// before and after the atomic destination replacement. Callers protecting
    /// a state file with a pathname-bound kernel lock use this to prevent a
    /// stale lock domain from committing after its lock name was rebound.
    pub(crate) fn write_direct_fenced<F>(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
        contents: &[u8],
        mut fence: F,
    ) -> Result<()>
    where
        F: FnMut() -> Result<()>,
    {
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
            fence().context("state mutation fence failed before atomic replacement")?;
            atomic_replace_at(root, &temp_name, file_name)?;
            sync_directory(root)?;
            fence().context("state mutation fence failed after atomic replacement")?;
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
        Self::scavenge_direct_temps_bounded(root, file_name, 4096)
    }

    /// Removes crash residue for one exact state-file namespace while allowing
    /// the caller to bind directory-enumeration work to its own finite root
    /// capacity. Large shared authenticated namespaces must not inherit the
    /// legacy 4,096-entry scan ceiling from single-file state stores.
    pub(crate) fn scavenge_direct_temps_bounded(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
        max_root_entries: usize,
    ) -> Result<usize> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        let file_name = file_name.to_os_string();
        Self::scavenge_direct_temp_namespaces_bounded(root, max_root_entries, move |_| {
            Ok(BTreeSet::from([file_name]))
        })
    }

    /// Enumerates a shared state root once, derives every exact state-file
    /// namespace from that immutable entry list, and removes only canonical
    /// atomic-writer temps or resumable quarantines for those namespaces.
    /// Callers must hold the root-wide writer lock for every derived target.
    pub(crate) fn scavenge_direct_temp_namespaces_bounded<F>(
        root: &SafeRoot,
        max_root_entries: usize,
        derive_file_names: F,
    ) -> Result<usize>
    where
        F: FnOnce(&[OsString]) -> Result<BTreeSet<OsString>>,
    {
        if max_root_entries == 0 {
            bail!("state temp scavenging entry budget must be positive");
        }
        root.verify()?;
        #[cfg(target_os = "linux")]
        {
            let mut budget = TreeBudget {
                remaining_entries: max_root_entries,
            };
            let entries = directory_entries(root.directory.as_raw_fd(), &mut budget)?;
            let file_names = derive_file_names(&entries)?;
            for file_name in &file_names {
                validate_single_component(file_name)?;
            }
            let mut removed = 0usize;
            for entry in entries {
                let live_target = canonical_random_temp_target(&entry)
                    .filter(|target| file_names.contains(target));
                let quarantine_binding = canonical_temp_quarantine_binding(&entry)?;
                let quarantine_target = quarantine_binding
                    .as_ref()
                    .map(|binding| &binding.target)
                    .filter(|target| file_names.contains(*target));
                let Some(file_name) = live_target.as_ref().or(quarantine_target) else {
                    continue;
                };
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
                if quarantine_binding
                    .as_ref()
                    .is_some_and(|binding| binding.identity != expected)
                {
                    bail!(
                        "state temp quarantine identity is malformed or changed: {}",
                        root.path().join(&entry).display()
                    );
                }
                let quarantine = temp_quarantine_name(file_name, &entry, &expected);
                quarantine_regular_file(root, &entry, &quarantine, &expected)?;
                sync_directory(root)?;
                if take_temp_scavenge_after_quarantine_fault() {
                    bail!("injected state temp scavenging crash after quarantine");
                }
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

#[cfg(test)]
thread_local! {
    static TEMP_SCAVENGE_AFTER_QUARANTINE_FAULT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_temp_scavenge_after_quarantine_fault() {
    TEMP_SCAVENGE_AFTER_QUARANTINE_FAULT.with(|fault| fault.set(true));
}

#[cfg(test)]
fn take_temp_scavenge_after_quarantine_fault() -> bool {
    TEMP_SCAVENGE_AFTER_QUARANTINE_FAULT.with(|fault| fault.replace(false))
}

#[cfg(not(test))]
fn take_temp_scavenge_after_quarantine_fault() -> bool {
    false
}

/// Distinguishes owner-private state locks from the persistent empty
/// coordination lock used by the live claim board.
///
/// `OwnerPrivate` keeps the exact mode `0600` contract for state payloads and
/// secrets. `EmptyCoordination` still requires no-follow access, current-user
/// ownership, a regular single-link empty file, no group or world write, no
/// setuid/setgid bits, stable inode and `flock` handling, and parent binding.
/// It accepts filesystems that synthesize a non-`0600` mode such as `0755`
/// after a `0600` creation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockFilePolicy {
    OwnerPrivate,
    EmptyCoordination,
}

/// A stable lock file guarded by the operating system. The file is never
/// unlinked on release, so a waiter cannot lock a different inode by racing a
/// stale-file cleanup path.
#[derive(Debug)]
pub struct KernelStateLock {
    file: File,
    path: PathBuf,
    file_name: OsString,
    identity: FileIdentity,
    root_identity: FileIdentity,
    policy: LockFilePolicy,
}

pub(crate) enum ExistingExclusiveLock {
    Missing,
    Busy,
    Acquired(KernelStateLock),
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
        Self::acquire_direct_with_timeout(root, file_name, LOCK_ACQUIRE_TIMEOUT)
    }

    /// Acquires the persistent empty coordination lock used by the live claim
    /// board. This must not be used for state payloads or secrets.
    pub(crate) fn acquire_direct_empty_coordination(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
    ) -> Result<Self> {
        Self::acquire_direct_with_timeout_and_policy(
            root,
            file_name,
            LOCK_ACQUIRE_TIMEOUT,
            LockFilePolicy::EmptyCoordination,
        )
    }

    pub(crate) fn acquire_direct_with_timeout(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
        timeout: Duration,
    ) -> Result<Self> {
        Self::acquire_direct_with_timeout_and_policy(
            root,
            file_name,
            timeout,
            LockFilePolicy::OwnerPrivate,
        )
    }

    fn acquire_direct_with_timeout_and_policy(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
        timeout: Duration,
        policy: LockFilePolicy,
    ) -> Result<Self> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        root.verify()?;
        let path = root.direct_child(file_name)?;
        let file = open_stable_private_file_at(root, file_name, policy)?;
        let identity = verify_open_lock_binding(root, file_name, &file, None, &path, policy)?;
        lock_file(&file, &path, timeout)?;
        run_kernel_lock_after_flock_hook(&path);
        let lock = Self {
            file,
            path,
            file_name: file_name.to_os_string(),
            identity,
            root_identity: root.identity().clone(),
            policy,
        };
        lock.verify_direct_binding(root)?;
        Ok(lock)
    }

    /// Acquires an already-existing stable lock without creating a pathname.
    /// Offline verification paths use this to remain strictly non-mutating.
    pub(crate) fn acquire_existing_direct(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
    ) -> Result<Self> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        root.verify()?;
        let path = root.direct_child(file_name)?;
        let file = open_existing_stable_private_file_at(root, file_name)?.with_context(|| {
            format!("required kernel state lock is missing: {}", path.display())
        })?;
        let identity = verify_open_lock_binding(
            root,
            file_name,
            &file,
            None,
            &path,
            LockFilePolicy::OwnerPrivate,
        )?;
        lock_file(&file, &path, LOCK_ACQUIRE_TIMEOUT)?;
        run_kernel_lock_after_flock_hook(&path);
        let lock = Self {
            file,
            path,
            file_name: file_name.to_os_string(),
            identity,
            root_identity: root.identity().clone(),
            policy: LockFilePolicy::OwnerPrivate,
        };
        lock.verify_direct_binding(root)?;
        Ok(lock)
    }

    /// Attempts an exclusive lock only when the exact pathname already
    /// exists. Missing paths return `None`; no cleanup candidate is created.
    pub(crate) fn try_acquire_existing_exclusive_direct(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
    ) -> Result<ExistingExclusiveLock> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        root.verify()?;
        let path = root.direct_child(file_name)?;
        let Some(file) = open_existing_stable_private_file_at(root, file_name)? else {
            return Ok(ExistingExclusiveLock::Missing);
        };
        let identity = verify_open_lock_binding(
            root,
            file_name,
            &file,
            None,
            &path,
            LockFilePolicy::OwnerPrivate,
        )?;
        if !try_lock_file_if_idle(&file, &path)? {
            return Ok(ExistingExclusiveLock::Busy);
        }
        run_kernel_lock_after_flock_hook(&path);
        let lock = Self {
            file,
            path,
            file_name: file_name.to_os_string(),
            identity,
            root_identity: root.identity().clone(),
            policy: LockFilePolicy::OwnerPrivate,
        };
        lock.verify_direct_binding(root)?;
        Ok(ExistingExclusiveLock::Acquired(lock))
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
        let file = open_stable_private_file_at(root, file_name, LockFilePolicy::OwnerPrivate)?;
        let identity = verify_open_lock_binding(
            root,
            file_name,
            &file,
            None,
            &path,
            LockFilePolicy::OwnerPrivate,
        )?;
        try_lock_file(&file, &path, operation)?;
        run_kernel_lock_after_flock_hook(&path);
        let lock = Self {
            file,
            path,
            file_name: file_name.to_os_string(),
            identity,
            root_identity: root.identity().clone(),
            policy: LockFilePolicy::OwnerPrivate,
        };
        lock.verify_direct_binding(root)?;
        Ok(lock)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    /// Revalidates both the held descriptor and the direct pathname that must
    /// still name it. This check is intentionally usable before and after each
    /// protected state operation, not only during acquisition.
    pub(crate) fn verify_direct_binding(&self, root: &SafeRoot) -> Result<()> {
        if self.root_identity != *root.identity() {
            bail!("kernel state lock was presented with a different root inode");
        }
        let observed = verify_open_lock_binding(
            root,
            &self.file_name,
            &self.file,
            Some(&self.identity),
            &self.path,
            self.policy,
        )?;
        if observed != self.identity {
            bail!(
                "kernel state lock descriptor identity changed unexpectedly: {}",
                self.path.display()
            );
        }
        Ok(())
    }

    /// Unlinks the exact pathname named by this exclusively held descriptor
    /// and durably records the parent-directory change. A rebound pathname is
    /// refused before unlink and the opened inode remains locked until return.
    pub(crate) fn unlink_exact_direct(self, root: &SafeRoot) -> Result<()> {
        self.verify_direct_binding(root)?;
        #[cfg(unix)]
        {
            let name = c_string(&self.file_name)?;
            if unsafe { libc::unlinkat(root.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to unlink inactive state lock {}",
                        self.path.display()
                    )
                });
            }
            sync_directory(root)?;
            let descriptor = fstat(self.file.as_raw_fd())?;
            if descriptor.st_mode & libc::S_IFMT != libc::S_IFREG
                || descriptor.st_uid != unsafe { libc::geteuid() }
                || descriptor.st_nlink != 0
                || identity_from_stat(&descriptor) != self.identity
            {
                bail!("unlinked state lock descriptor changed unexpectedly");
            }
            root.verify()?;
            Ok(())
        }
        #[cfg(not(unix))]
        bail!(
            "identity-bound state lock unlink is unsupported on this platform: {}",
            self.path.display()
        )
    }
}

#[cfg(unix)]
fn verify_open_lock_binding(
    root: &SafeRoot,
    file_name: &OsStr,
    file: &File,
    expected: Option<&FileIdentity>,
    path: &Path,
    policy: LockFilePolicy,
) -> Result<FileIdentity> {
    root.verify()?;
    let descriptor = fstat(file.as_raw_fd())?;
    validate_lock_stat(&descriptor, path, policy)?;
    let name = c_string(file_name)?;
    let pathname = fstatat_no_follow(root.directory.as_raw_fd(), &name)?;
    validate_lock_stat(&pathname, path, policy)?;
    let descriptor_identity = identity_from_stat(&descriptor);
    let pathname_identity = identity_from_stat(&pathname);
    if descriptor_identity != pathname_identity {
        bail!(
            "kernel state lock path does not name its opened descriptor: {}",
            path.display()
        );
    }
    if expected.is_some_and(|expected| expected != &descriptor_identity) {
        bail!(
            "kernel state lock path was rebound while its original inode remained locked: {}",
            path.display()
        );
    }
    root.verify()?;
    Ok(descriptor_identity)
}

#[cfg(not(unix))]
fn verify_open_lock_binding(
    _root: &SafeRoot,
    _file_name: &OsStr,
    _file: &File,
    _expected: Option<&FileIdentity>,
    path: &Path,
    _policy: LockFilePolicy,
) -> Result<FileIdentity> {
    bail!(
        "descriptor/path lock binding verification is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn validate_lock_stat(stat: &libc::stat, path: &Path, policy: LockFilePolicy) -> Result<()> {
    match policy {
        LockFilePolicy::OwnerPrivate => validate_private_lock_stat(stat, path),
        LockFilePolicy::EmptyCoordination => validate_empty_coordination_lock_stat(stat, path),
    }
}

#[cfg(unix)]
fn validate_private_lock_stat(stat: &libc::stat, path: &Path) -> Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o600
    {
        bail!(
            "kernel state lock is not an owner-private single-link regular file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_empty_coordination_lock_stat(stat: &libc::stat, path: &Path) -> Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
    {
        bail!(
            "empty coordination lock is not a current-user single-link regular file: {}",
            path.display()
        );
    }
    let mode = unsigned_to_u32(stat.st_mode & 0o7777);
    if mode & 0o022 != 0 || mode & 0o6000 != 0 {
        bail!(
            "empty coordination lock has group/world write or special bits {:04o}: {}",
            mode,
            path.display()
        );
    }
    if stat.st_size != 0 {
        bail!(
            "empty coordination lock must remain empty: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
type KernelLockAfterFlockHook = Box<dyn FnMut(&Path) -> bool>;

#[cfg(test)]
thread_local! {
    static KERNEL_LOCK_AFTER_FLOCK_HOOK: std::cell::RefCell<Option<KernelLockAfterFlockHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_kernel_lock_after_flock_hook(hook: impl FnMut(&Path) -> bool + 'static) {
    KERNEL_LOCK_AFTER_FLOCK_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_kernel_lock_after_flock_hook(path: &Path) {
    let hook = KERNEL_LOCK_AFTER_FLOCK_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(mut hook) = hook {
        if !hook(path) {
            KERNEL_LOCK_AFTER_FLOCK_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(hook);
            });
        }
    }
}

#[cfg(not(test))]
fn run_kernel_lock_after_flock_hook(_path: &Path) {}

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

#[derive(Debug, Clone, Copy)]
pub(crate) struct PrivateDirectoryScavengeLimits {
    pub max_root_entries: usize,
    pub max_directories: usize,
    pub max_tree_entries: usize,
    pub max_total_bytes: u64,
    pub max_duration: Duration,
}

/// Removes bounded owner-private crash directories created through
/// [`SafeRoot::reserve_random_direct_child_directory`]. The caller must hold
/// `stable_lock_file` for the entire scan and cleanup. The root is validated in
/// two phases before mutation: the stable lock is the only accepted file, and
/// every other entry must be either a canonical random directory for
/// `random_name_seed` or a canonical identity-bound deletion quarantine.
///
/// Live directories are atomically quarantined before recursive deletion.
/// Existing deletion quarantines are resumed in place, so an interrupted
/// cleanup remains recoverable on the next lock-held invocation.
#[cfg(test)]
pub(crate) fn scavenge_private_random_directories(
    root: &SafeRoot,
    stable_lock_file: impl AsRef<OsStr>,
    random_name_seed: impl AsRef<OsStr>,
    limits: PrivateDirectoryScavengeLimits,
) -> Result<usize> {
    if limits.max_duration.is_zero() {
        bail!("private directory scavenging limits must be non-zero");
    }
    let deadline = Instant::now()
        .checked_add(limits.max_duration)
        .context("private directory scavenging deadline overflowed")?;
    scavenge_private_random_directories_until(
        root,
        stable_lock_file,
        random_name_seed,
        limits,
        deadline,
    )
}

pub(crate) fn scavenge_private_random_directories_until(
    root: &SafeRoot,
    stable_lock_file: impl AsRef<OsStr>,
    random_name_seed: impl AsRef<OsStr>,
    limits: PrivateDirectoryScavengeLimits,
    outer_deadline: Instant,
) -> Result<usize> {
    let stable_lock_file = stable_lock_file.as_ref();
    let random_name_seed = random_name_seed.as_ref();
    validate_single_component(stable_lock_file)?;
    validate_single_component(random_name_seed)?;
    root.verify()?;
    let local_deadline = Instant::now()
        .checked_add(limits.max_duration)
        .context("private directory scavenging deadline overflowed")?;
    let deadline = std::cmp::min(local_deadline, outer_deadline);
    ensure_before_deadline(Some(deadline), "before private directory scavenging")?;

    #[cfg(target_os = "linux")]
    {
        scavenge_private_random_directories_linux(
            root,
            stable_lock_file,
            random_name_seed,
            limits,
            deadline,
        )
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = limits;
        bail!(
            "private random-directory scavenging is unsupported on this platform: {}",
            root.path().display()
        )
    }
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

/// Restores an identity-bound direct-child directory from a caller-supplied
/// quarantine name using an atomic no-replace rename.
///
/// Exactly one of `child_name` and `quarantine_name` must exist before the
/// restore. An already-restored source with the expected identity is accepted
/// idempotently. Both-present, both-absent, and identity-mismatch states fail
/// closed. Linux provides the required `renameat2(RENAME_NOREPLACE)` primitive;
/// other platforms refuse without mutating either name.
pub fn restore_quarantined_direct_child_directory(
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
        restore_quarantined_direct_child_directory_linux(
            root,
            child_name,
            quarantine_name,
            expected,
        )
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = expected;
        bail!(
            "atomic no-replace directory restore is unsupported on this platform; refusing to mutate {}",
            root.path().join(quarantine_name).display()
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

/// Returns the deterministic direct-child name used while a durable quarantine tree is audited
/// and removed.
///
/// Callers that gate destructive work must include this coordinate in their complete preflight
/// and reservation set before invoking [`remove_quarantined_direct_child_tree`].
pub fn quarantined_direct_child_cleanup_name(
    quarantine_name: impl AsRef<OsStr>,
    expected: &FileIdentity,
) -> Result<OsString> {
    let quarantine_name = quarantine_name.as_ref();
    validate_single_component(quarantine_name)?;
    #[cfg(unix)]
    {
        Ok(deletion_quarantine_name(quarantine_name, expected))
    }
    #[cfg(not(unix))]
    {
        let _ = expected;
        bail!("secure quarantine cleanup names are unsupported on this platform")
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
    #[cfg(windows)]
    {
        let snapshot = crate::file_identity::open_windows_path_identity(path)
            .with_context(|| format!("failed to open identity handle for {}", path.display()))?;
        ensure_not_link_or_reparse(path, &snapshot.metadata)?;
        Ok(FileIdentity {
            device: snapshot.identity.device,
            file: snapshot.identity.file,
        })
    }
    #[cfg(not(windows))]
    {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect identity for {}", path.display()))?;
        ensure_not_link_or_reparse(path, &metadata)?;
        Ok(identity_from_metadata(&metadata))
    }
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
#[derive(Clone, Copy)]
enum DirectoryOpenIntent {
    /// Search-only ancestor handle. Linux uses `O_PATH` (execute/search), not
    /// `O_RDONLY`, so a directory the caller can traverse but not list is accepted.
    /// World-execute is not required; a symlink or missing search permission fails closed.
    Traverse,
    /// Usable directory handle for the leaf being created or bound.
    Operate,
}

#[cfg(unix)]
fn directory_component_open_flags(intent: DirectoryOpenIntent) -> libc::c_int {
    let mut flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    match intent {
        DirectoryOpenIntent::Operate => flags |= libc::O_RDONLY,
        DirectoryOpenIntent::Traverse => {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                flags |= libc::O_PATH;
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            {
                flags |= libc::O_RDONLY;
            }
        }
    }
    flags
}

#[cfg(unix)]
fn directory_component_intent(is_final: bool) -> DirectoryOpenIntent {
    if is_final {
        DirectoryOpenIntent::Operate
    } else {
        DirectoryOpenIntent::Traverse
    }
}

#[cfg(unix)]
fn open_directory_component_at(
    parent: &File,
    name: &std::ffi::CStr,
    intent: DirectoryOpenIntent,
) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            directory_component_open_flags(intent),
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
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
    let mut walked = PathBuf::from(std::path::MAIN_SEPARATOR_STR);
    let mut final_created = false;
    for (index, segment) in segments.iter().enumerate() {
        walked.push(segment);
        let name = c_string(segment)?;
        let is_final = index + 1 == segments.len();
        let intent = directory_component_intent(is_final);
        match open_directory_component_at(&current, &name, intent) {
            Ok(opened) => {
                current = opened;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let result = unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) };
                let mut created = result == 0;
                if result != 0 {
                    let mkdir_error = std::io::Error::last_os_error();
                    if mkdir_error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(mkdir_error).with_context(|| {
                            format!(
                                "failed to create safe directory component {}",
                                walked.display()
                            )
                        });
                    }
                    created = false;
                }
                current =
                    open_directory_component_at(&current, &name, intent).with_context(|| {
                        format!(
                            "failed to re-open safe directory component {}",
                            walked.display()
                        )
                    })?;
                if is_final {
                    final_created = created;
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to open safe directory component {}",
                        walked.display()
                    )
                });
            }
        }
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
    let observed_mode = unsigned_to_u32(stat.st_mode & 0o777);
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
    let mut walked = PathBuf::from(std::path::MAIN_SEPARATOR_STR);
    let segments = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(segment) => Some(segment),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (index, segment) in segments.iter().enumerate() {
        walked.push(segment);
        let name = c_string(segment)?;
        let intent = directory_component_intent(index + 1 == segments.len());
        current = open_directory_component_at(&current, &name, intent).with_context(|| {
            format!(
                "failed to open directory component without following links: {}",
                walked.display()
            )
        })?;
    }
    Ok(current)
}

#[cfg(windows)]
fn open_windows_directory(path: &Path) -> Result<File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let path = absolute_normalized(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let directory = options.open(&path).with_context(|| {
        format!(
            "failed to open directory without following reparse points: {}",
            path.display()
        )
    })?;
    let metadata = directory
        .metadata()
        .with_context(|| format!("failed to inspect directory {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!(
            "directory open target is not a directory: {}",
            path.display()
        );
    }
    ensure_not_link_or_reparse(&path, &metadata)?;
    Ok(directory)
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

fn ensure_regular_single_link_open_file(
    path: &Path,
    file: &File,
    metadata: &fs::Metadata,
) -> Result<()> {
    ensure_regular_single_link_metadata(path, metadata)?;
    #[cfg(windows)]
    {
        let link_count =
            crate::file_identity::windows_file_link_count(file).with_context(|| {
                format!(
                    "failed to inspect open Windows hard-link count for {}",
                    path.display()
                )
            })?;
        if link_count != 1 {
            bail!(
                "state input must have exactly one hard link (observed {}): {}",
                link_count,
                path.display()
            );
        }
    }
    #[cfg(not(windows))]
    let _ = file;
    Ok(())
}

#[cfg(unix)]
fn identity_from_metadata(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    }
}

#[cfg(not(any(unix, windows)))]
fn identity_from_metadata(_metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity { device: 0, file: 0 }
}

#[cfg(windows)]
fn identity_from_open_handle(file: &File, path: &Path) -> Result<FileIdentity> {
    let identity = crate::file_identity::windows_file_identity(file)
        .with_context(|| format!("failed to inspect file identity for {}", path.display()))?;
    Ok(FileIdentity {
        device: identity.device,
        file: identity.file,
    })
}

fn identity_from_file(file: &File, path: &Path) -> Result<FileIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
    ensure_regular_single_link_open_file(path, file, &metadata)?;
    #[cfg(windows)]
    {
        identity_from_open_handle(file, path)
    }
    #[cfg(not(windows))]
    {
        Ok(identity_from_metadata(&metadata))
    }
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
    read_bounded_file_with_hook(file, path, max_bytes, || {})
}

fn read_bounded_file_with_hook(
    file: &mut File,
    path: &Path,
    max_bytes: u64,
    after_initial_metadata: impl FnOnce(),
) -> Result<Vec<u8>> {
    let mut validate = |_: &fs::Metadata| Ok(());
    read_bounded_file_with_validator_and_hook(
        file,
        path,
        max_bytes,
        &mut validate,
        after_initial_metadata,
    )
}

fn read_bounded_file_with_validator_and_hook(
    file: &mut File,
    path: &Path,
    max_bytes: u64,
    validate: &mut impl FnMut(&fs::Metadata) -> Result<()>,
    after_initial_metadata: impl FnOnce(),
) -> Result<Vec<u8>> {
    let before = file
        .metadata()
        .with_context(|| format!("failed to inspect opened file {}", path.display()))?;
    ensure_regular_single_link_open_file(path, file, &before)?;
    validate(&before)
        .with_context(|| format!("opened file metadata policy rejected {}", path.display()))?;
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
    #[cfg(windows)]
    let before_identity = crate::file_identity::windows_file_identity(file)
        .with_context(|| format!("failed to inspect opened file identity {}", path.display()))?;
    after_initial_metadata();
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
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) != before.len() {
        bail!(
            "file changed or was truncated during bounded read: {}",
            path.display()
        );
    }
    let after = file
        .metadata()
        .with_context(|| format!("failed to revalidate opened file {}", path.display()))?;
    ensure_regular_single_link_open_file(path, file, &after)?;
    validate(&after)
        .with_context(|| format!("opened file metadata policy changed for {}", path.display()))?;
    #[cfg(windows)]
    let same_generation = before_identity
        == crate::file_identity::windows_file_identity(file).with_context(|| {
            format!(
                "failed to revalidate opened file identity {}",
                path.display()
            )
        })?
        && same_file_generation(&before, &after);
    #[cfg(not(windows))]
    let same_generation = same_file_generation(&before, &after);
    if !same_generation {
        bail!(
            "file identity changed during bounded read: {}",
            path.display()
        );
    }
    Ok(contents)
}

#[cfg(unix)]
fn same_file_generation(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.uid() == after.uid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(windows)]
fn same_file_generation(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.file_attributes() == after.file_attributes()
        && before.file_size() == after.file_size()
        && before.creation_time() == after.creation_time()
        && before.last_write_time() == after.last_write_time()
}

#[cfg(not(any(unix, windows)))]
fn same_file_generation(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    identity_from_metadata(before) == identity_from_metadata(after) && before.len() == after.len()
}

#[cfg(unix)]
fn open_relative_regular_unix_allow_mounts(root: &Path, relative: &Path) -> Result<File> {
    let mut directory = open_unix_directory(root)?;
    let components = relative.components().collect::<Vec<_>>();
    let mut walked = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(segment) = component else {
            bail!("invalid relative component in {}", relative.display());
        };
        walked.push(segment);
        let name = c_string(segment)?;
        let is_final = index + 1 == components.len();
        if !is_final {
            let intent = DirectoryOpenIntent::Traverse;
            let opened =
                open_directory_component_at(&directory, &name, intent).with_context(|| {
                    format!(
                        "failed to open repository-relative component {} without following links",
                        walked.display()
                    )
                })?;
            let metadata = opened.metadata().with_context(|| {
                format!("failed to inspect directory component {}", walked.display())
            })?;
            if !metadata.file_type().is_dir() {
                bail!(
                    "relative path component is not a directory: {}",
                    walked.display()
                );
            }
            directory = opened;
            continue;
        }
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to open repository-relative component {} without following links",
                    walked.display()
                )
            });
        }
        let opened = unsafe { File::from_raw_fd(fd) };
        identity_from_file(&opened, &root.join(relative))?;
        return Ok(opened);
    }
    bail!(
        "relative path has no final component: {}",
        relative.display()
    )
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
const RESOLVE_NO_XDEV: u64 = 0x01;
#[cfg(target_os = "linux")]
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
#[cfg(target_os = "linux")]
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
#[cfg(target_os = "linux")]
const RESOLVE_BENEATH: u64 = 0x08;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxMountIdentity {
    mount_id: u64,
}

#[cfg(target_os = "linux")]
fn linux_mount_identity_for_fd(fd: RawFd) -> Result<LinuxMountIdentity> {
    let expected = fstat(fd)?;
    linux_mount_identity(
        fd,
        c"",
        libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        &expected,
    )
}

#[cfg(target_os = "linux")]
fn linux_mount_identity_at(
    directory_fd: RawFd,
    name: &std::ffi::CStr,
    expected: &libc::stat,
) -> Result<LinuxMountIdentity> {
    linux_mount_identity(
        directory_fd,
        name,
        libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT,
        expected,
    )
}

#[cfg(target_os = "linux")]
fn linux_mount_identity(
    directory_fd: RawFd,
    name: &std::ffi::CStr,
    flags: libc::c_int,
    expected: &libc::stat,
) -> Result<LinuxMountIdentity> {
    let mut observed = std::mem::MaybeUninit::<libc::statx>::zeroed();
    let result = unsafe {
        libc::statx(
            directory_fd,
            name.as_ptr(),
            flags,
            libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
            observed.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect filesystem mount identity with statx");
    }
    let observed = unsafe { observed.assume_init() };
    if observed.stx_mask & libc::STATX_MNT_ID == 0 {
        bail!("statx did not report a filesystem mount identity");
    }
    if observed.stx_mnt_id == 0 {
        bail!("statx reported an invalid zero filesystem mount identity");
    }
    if observed.stx_ino != unsigned_to_u64(expected.st_ino)
        || observed.stx_dev_major != libc::major(expected.st_dev)
        || observed.stx_dev_minor != libc::minor(expected.st_dev)
    {
        bail!("filesystem entry changed while its mount identity was inspected");
    }
    Ok(LinuxMountIdentity {
        mount_id: observed.stx_mnt_id,
    })
}

#[cfg(target_os = "linux")]
fn require_linux_mount_id(expected: u64, observed: u64, subject: &str) -> Result<()> {
    if observed != expected {
        bail!(
            "refusing filesystem mount crossing for {subject}: expected mount {expected}, observed {observed}"
        );
    }
    Ok(())
}

#[cfg(all(target_os = "linux", test))]
thread_local! {
    static NEXT_LINUX_MOUNT_MISMATCH_SUBJECT: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(target_os = "linux", test))]
fn inject_next_linux_mount_mismatch(subject: &'static str) {
    NEXT_LINUX_MOUNT_MISMATCH_SUBJECT.with(|slot| slot.set(Some(subject)));
}

#[cfg(all(target_os = "linux", test))]
fn apply_linux_mount_test_observation(subject: &str, observed: u64) -> u64 {
    NEXT_LINUX_MOUNT_MISMATCH_SUBJECT.with(|slot| {
        if slot.get().is_some_and(|requested| requested == subject) {
            slot.set(None);
            observed
                .checked_add(1)
                .unwrap_or(observed.saturating_sub(1))
        } else {
            observed
        }
    })
}

#[cfg(all(target_os = "linux", not(test)))]
fn apply_linux_mount_test_observation(_subject: &str, observed: u64) -> u64 {
    observed
}

#[cfg(target_os = "linux")]
fn verify_linux_mount_at(
    directory_fd: RawFd,
    name: &std::ffi::CStr,
    stat: &libc::stat,
    expected_mount_id: u64,
    subject: &str,
) -> Result<()> {
    let observed = linux_mount_identity_at(directory_fd, name, stat)?.mount_id;
    let observed = apply_linux_mount_test_observation(subject, observed);
    require_linux_mount_id(expected_mount_id, observed, subject)
}

#[cfg(target_os = "linux")]
fn verify_linux_mount_for_fd(fd: RawFd, expected_mount_id: u64, subject: &str) -> Result<()> {
    let observed = linux_mount_identity_for_fd(fd)?.mount_id;
    require_linux_mount_id(expected_mount_id, observed, subject)
}

#[cfg(target_os = "linux")]
fn open_repository_relative_linux(root: &Path, relative: &Path) -> Result<File> {
    let root = open_unix_directory(root)?;
    open_repository_relative_linux_fd(root.as_raw_fd(), relative)
}

#[cfg(target_os = "linux")]
fn open_repository_relative_linux_fd(root_fd: RawFd, relative: &Path) -> Result<File> {
    let relative = c_string(relative.as_os_str())?;
    let how = LinuxOpenHow {
        flags: u64::try_from(libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .context("openat2 flags did not fit u64")?,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd,
            relative.as_ptr(),
            &how as *const LinuxOpenHow,
            std::mem::size_of::<LinuxOpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to open mount-confined repository-relative path {}",
                Path::new(relative.to_string_lossy().as_ref()).display()
            )
        });
    }
    let fd = i32::try_from(fd).context("openat2 returned an invalid file descriptor")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
fn open_repository_relative_regular_linux(root: &Path, relative: &Path) -> Result<File> {
    let file = open_repository_relative_linux(root, relative)?;
    identity_from_file(&file, &root.join(relative))?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_repository_relative_optional_regular_linux(
    root: &Path,
    relative: &Path,
) -> Result<Option<File>> {
    let file = match open_repository_relative_linux(root, relative) {
        Ok(file) => file,
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect mount-confined repository-relative path {}",
            relative.display()
        )
    })?;
    if metadata.file_type().is_dir() {
        return Ok(None);
    }
    ensure_regular_single_link_metadata(&root.join(relative), &metadata)?;
    Ok(Some(file))
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
fn open_stable_private_file_at(
    root: &SafeRoot,
    file_name: &OsStr,
    policy: LockFilePolicy,
) -> Result<File> {
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
    let path = root.path().join(file_name);
    let metadata = file.metadata()?;
    ensure_regular_single_link_metadata(&path, &metadata)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "stable lock file is not owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if created {
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            let chmod_error = std::io::Error::last_os_error();
            if policy != LockFilePolicy::EmptyCoordination {
                return Err(chmod_error).with_context(|| {
                    format!("failed to set private lock mode on {}", path.display())
                });
            }
        }
    } else if policy == LockFilePolicy::OwnerPrivate && mode != 0o600 {
        bail!(
            "existing stable lock file has unsafe mode {:04o}; refusing to change it: {}",
            mode,
            path.display()
        );
    }
    if policy == LockFilePolicy::EmptyCoordination {
        validate_empty_coordination_lock_metadata(&path, &file.metadata()?)?;
    }
    Ok(file)
}

#[cfg(unix)]
fn validate_empty_coordination_lock_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    ensure_regular_single_link_metadata(path, metadata)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "empty coordination lock is not owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o022 != 0 || mode & 0o6000 != 0 {
        bail!(
            "empty coordination lock has group/world write or special bits {:04o}: {}",
            mode,
            path.display()
        );
    }
    if metadata.len() != 0 {
        bail!(
            "empty coordination lock must remain empty: {}",
            path.display()
        );
    }
    Ok(())
}

include!("safe_state/part2.rs");

#[cfg(test)]
mod tests;
