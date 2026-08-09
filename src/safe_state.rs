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
/// against a concurrent rename/replacement of the directory.
#[derive(Debug)]
pub struct DirectoryBindingGuard {
    path: PathBuf,
    directory: File,
    identity: FileIdentity,
    #[cfg(unix)]
    generation: fs::Metadata,
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
                generation: directory.metadata()?,
                directory,
            })
        }
        #[cfg(not(unix))]
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
        bail!("descriptor-relative mount-confined reads require Linux openat2")
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
        bail!("descriptor-relative mount-confined reads require Linux openat2")
    }

    pub fn verify(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let held = fstat(self.directory.as_raw_fd())?;
            let held_generation = self.directory.metadata()?;
            if held.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&held) != self.identity
                || !same_file_generation(&self.generation, &held_generation)
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
            let rebound_generation = rebound_directory.metadata()?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != self.identity
                || !same_file_generation(&self.generation, &rebound_generation)
            {
                bail!(
                    "directory pathname binding changed: {}",
                    self.path.display()
                );
            }
            Ok(())
        }
        #[cfg(not(unix))]
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
        mut action: F,
    ) -> Result<Vec<BoundedTreeEntry>>
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
            #[cfg(not(target_os = "linux"))]
            if limits.same_device {
                bail!("mount-confined bounded tree walks require Linux statx mount identities");
            }
            let deadline = Instant::now()
                .checked_add(limits.max_duration)
                .context("bounded tree walk deadline overflowed")?;
            let mut budget = InventoryBudget {
                remaining_entries: limits.max_entries,
                total_path_bytes: 0,
                deadline,
            };
            let mut entries = Vec::new();
            let mut walker = InventoryWalkState {
                root_device: root_stat.st_dev,
                #[cfg(target_os = "linux")]
                root_mount_id,
                limits,
                budget: &mut budget,
                action: &mut action,
                entries: &mut entries,
            };
            walker.walk(root_binding.directory.as_raw_fd(), Path::new(""), 0)?;
            budget.ensure_before_deadline("after repository traversal")?;
            root_binding.verify()?;
            Ok(entries)
        }

        #[cfg(not(unix))]
        {
            let _ = (root_binding, limits, &mut action);
            bail!("descriptor-relative bounded tree walks are unsupported on this platform")
        }
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

        #[cfg(not(target_os = "linux"))]
        bail!("mount-confined repository-relative reads require Linux openat2")
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
        bail!("mount-confined repository-relative reads require Linux openat2")
    }

    pub fn identity(path: impl AsRef<Path>) -> Result<FileIdentity> {
        let path = path.as_ref();
        let file = open_regular_no_follow(path, false)?;
        identity_from_file(&file, path)
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

    pub(crate) fn acquire_direct_with_timeout(
        root: &SafeRoot,
        file_name: impl AsRef<OsStr>,
        timeout: Duration,
    ) -> Result<Self> {
        let file_name = file_name.as_ref();
        validate_single_component(file_name)?;
        root.verify()?;
        let path = root.direct_child(file_name)?;
        let file = open_stable_private_file_at(root, file_name)?;
        let identity = verify_open_lock_binding(root, file_name, &file, None, &path)?;
        lock_file(&file, &path, timeout)?;
        run_kernel_lock_after_flock_hook(&path);
        let lock = Self {
            file,
            path,
            file_name: file_name.to_os_string(),
            identity,
            root_identity: root.identity().clone(),
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
        let identity = verify_open_lock_binding(root, file_name, &file, None, &path)?;
        lock_file(&file, &path, LOCK_ACQUIRE_TIMEOUT)?;
        run_kernel_lock_after_flock_hook(&path);
        let lock = Self {
            file,
            path,
            file_name: file_name.to_os_string(),
            identity,
            root_identity: root.identity().clone(),
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
        let identity = verify_open_lock_binding(root, file_name, &file, None, &path)?;
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
        let file = open_stable_private_file_at(root, file_name)?;
        let identity = verify_open_lock_binding(root, file_name, &file, None, &path)?;
        try_lock_file(&file, &path, operation)?;
        run_kernel_lock_after_flock_hook(&path);
        let lock = Self {
            file,
            path,
            file_name: file_name.to_os_string(),
            identity,
            root_identity: root.identity().clone(),
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
) -> Result<FileIdentity> {
    root.verify()?;
    let descriptor = fstat(file.as_raw_fd())?;
    validate_private_lock_stat(&descriptor, path)?;
    let name = c_string(file_name)?;
    let pathname = fstatat_no_follow(root.directory.as_raw_fd(), &name)?;
    validate_private_lock_stat(&pathname, path)?;
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
) -> Result<FileIdentity> {
    bail!(
        "descriptor/path lock binding verification is unsupported on this platform: {}",
        path.display()
    )
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
    ensure_regular_single_link_metadata(path, &before)?;
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
    ensure_regular_single_link_metadata(path, &after)?;
    validate(&after)
        .with_context(|| format!("opened file metadata policy changed for {}", path.display()))?;
    if !same_file_generation(&before, &after) {
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
    before.volume_serial_number() == after.volume_serial_number()
        && before.file_index() == after.file_index()
        && before.file_attributes() == after.file_attributes()
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

#[cfg(unix)]
fn open_existing_stable_private_file_at(
    root: &SafeRoot,
    file_name: &OsStr,
) -> Result<Option<File>> {
    let name = c_string(file_name)?;
    let fd = unsafe {
        libc::openat(
            root.directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).with_context(|| {
            format!(
                "failed to open existing stable lock file {}",
                root.path().join(file_name).display()
            )
        });
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    ensure_regular_single_link_metadata(&root.path().join(file_name), &metadata)?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        bail!(
            "existing stable lock file is not owner-private mode 0600: {}",
            root.path().join(file_name).display()
        );
    }
    Ok(Some(file))
}

#[cfg(not(unix))]
fn open_stable_private_file_at(root: &SafeRoot, file_name: &OsStr) -> Result<File> {
    bail!(
        "handle-relative stable lock files are unsupported on this platform: {}",
        root.path().join(file_name).display()
    )
}

#[cfg(not(unix))]
fn open_existing_stable_private_file_at(
    root: &SafeRoot,
    file_name: &OsStr,
) -> Result<Option<File>> {
    bail!(
        "handle-relative existing lock files are unsupported on this platform: {}",
        root.path().join(file_name).display()
    )
}

#[cfg(unix)]
fn lock_file(file: &File, path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("kernel state lock timeout overflowed")?;
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
                timeout.as_secs(),
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

#[cfg(unix)]
fn try_lock_file_if_idle(file: &File, path: &Path) -> Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(false);
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

#[cfg(not(unix))]
fn try_lock_file_if_idle(_file: &File, path: &Path) -> Result<bool> {
    bail!(
        "exclusive cooperative kernel lock probing is unsupported on this platform: {}",
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
fn lock_file(file: &File, path: &Path, timeout: Duration) -> Result<()> {
    use windows_sys::Win32::{
        Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
        System::IO::OVERLAPPED,
    };
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("kernel state lock timeout overflowed")?;
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
                timeout.as_secs(),
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
fn lock_file(_file: &File, path: &Path, _timeout: Duration) -> Result<()> {
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

#[cfg(unix)]
fn component_checksum(name: &OsStr) -> String {
    stable_checksum(name.as_bytes())
}

#[cfg(unix)]
fn deletion_quarantine_name(name: &OsStr, identity: &FileIdentity) -> OsString {
    let source = base64url_encode(name.as_bytes());
    let tag = deletion_quarantine_tag(name, identity);
    OsString::from(format!(
        "{DELETION_QUARANTINE_V2_PREFIX}{source}-{tag}-{:016x}-{:016x}",
        identity.device, identity.file
    ))
}

#[cfg(unix)]
fn deletion_quarantine_tag(name: &OsStr, identity: &FileIdentity) -> String {
    let mut payload = Vec::with_capacity(
        DELETION_QUARANTINE_V2_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(name.as_bytes().len())
            .saturating_add(16),
    );
    payload.extend_from_slice(DELETION_QUARANTINE_V2_DOMAIN);
    payload.extend_from_slice(
        &u64::try_from(name.as_bytes().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&identity.device.to_be_bytes());
    payload.extend_from_slice(&identity.file.to_be_bytes());
    let checksum = stable_checksum(&payload);
    // stable_checksum has a fixed `maco-v1-` prefix followed by two u64s.
    checksum[8..40].to_string()
}

#[cfg(unix)]
fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().saturating_add(2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        let second_index = (first & 0x03) << 4 | chunk.get(1).copied().unwrap_or(0) >> 4;
        encoded.push(char::from(ALPHABET[usize::from(second_index)]));
        if let Some(second) = chunk.get(1).copied() {
            let third_index = (second & 0x0f) << 2 | chunk.get(2).copied().unwrap_or(0) >> 6;
            encoded.push(char::from(ALPHABET[usize::from(third_index)]));
        }
        if let Some(third) = chunk.get(2).copied() {
            encoded.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        }
    }
    encoded
}

#[cfg(unix)]
fn base64url_decode(encoded: &[u8]) -> Result<Vec<u8>> {
    if encoded.is_empty() || encoded.len() % 4 == 1 {
        bail!("private residue quarantine source encoding is malformed");
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3 + 2);
    for chunk in encoded.chunks(4) {
        let mut values = [0u8; 4];
        for (index, byte) in chunk.iter().copied().enumerate() {
            values[index] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => bail!("private residue quarantine source is not canonical base64url"),
            };
        }
        decoded.push(values[0] << 2 | values[1] >> 4);
        if chunk.len() >= 3 {
            decoded.push(values[1] << 4 | values[2] >> 2);
        }
        if chunk.len() == 4 {
            decoded.push(values[2] << 6 | values[3]);
        }
    }
    if base64url_encode(&decoded).as_bytes() != encoded {
        bail!("private residue quarantine source encoding is not canonical");
    }
    Ok(decoded)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct DeletionQuarantineBinding {
    source: OsString,
    identity: FileIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PrivateRandomDirectoryResidue {
    name: OsString,
    identity: FileIdentity,
    already_quarantined: bool,
}

#[cfg(target_os = "linux")]
fn scavenge_private_random_directories_linux(
    root: &SafeRoot,
    stable_lock_file: &OsStr,
    random_name_seed: &OsStr,
    limits: PrivateDirectoryScavengeLimits,
    deadline: Instant,
) -> Result<usize> {
    if limits.max_root_entries == 0
        || limits.max_directories == 0
        || limits.max_tree_entries == 0
        || limits.max_duration.is_zero()
    {
        bail!("private directory scavenging limits must be non-zero");
    }
    ensure_before_deadline(Some(deadline), "before private residue root verification")?;
    root.verify()?;
    let root_stat = fstat(root.directory.as_raw_fd())?;
    let mut root_budget = TreeBudget {
        remaining_entries: limits.max_root_entries,
    };
    let names =
        directory_entries_until(root.directory.as_raw_fd(), &mut root_budget, Some(deadline))
            .with_context(|| {
                format!(
                    "private residue root exceeded its {} entry budget",
                    limits.max_root_entries
                )
            })?;
    let mut saw_lock = false;
    let mut residues = Vec::new();
    let mut identities = BTreeMap::new();

    for name in names {
        ensure_before_deadline(Some(deadline), "during private residue root scan")?;
        let name_c = c_string(&name)?;
        let stat = fstatat_no_follow(root.directory.as_raw_fd(), &name_c)?;
        if name == stable_lock_file {
            validate_private_scavenge_lock(root, &name, &stat, root_stat.st_dev)?;
            saw_lock = true;
            continue;
        }

        let live = is_canonical_random_temp_name(random_name_seed, &name);
        let quarantined = deletion_quarantine_binding(&name)?;
        if !live && quarantined.is_none() {
            bail!(
                "unexpected entry in private residue root requires manual inspection: {}",
                root.path().join(&name).display()
            );
        }
        validate_private_scavenge_directory(root, &name, &stat, root_stat.st_dev)?;
        let identity = identity_from_stat(&stat);
        if let Some(encoded) = quarantined {
            if !is_canonical_random_temp_name(random_name_seed, &encoded.source) {
                bail!(
                    "private residue quarantine does not encode a canonical source name: {}",
                    root.path().join(&name).display()
                );
            }
            if encoded.identity != identity {
                bail!(
                    "private residue quarantine identity is malformed or changed: {}",
                    root.path().join(&name).display()
                );
            }
        }
        let binding = root.bind_existing_direct_child_directory(&name)?;
        if binding.identity() != &identity {
            bail!(
                "private residue directory identity changed while binding: {}",
                root.path().join(&name).display()
            );
        }
        if identities
            .insert((identity.device, identity.file), name.clone())
            .is_some()
        {
            bail!("private residue root contains duplicate directory identities");
        }
        residues.push(PrivateRandomDirectoryResidue {
            name,
            identity,
            already_quarantined: !live,
        });
    }

    if !saw_lock {
        bail!("private residue root is missing its held stable lock file");
    }
    if residues.len() > limits.max_directories {
        bail!(
            "private residue root contains {} directories, exceeding its cleanup limit of {}",
            residues.len(),
            limits.max_directories
        );
    }

    let mut tree_budget = TreeBudget {
        remaining_entries: limits.max_tree_entries,
    };
    let mut remaining_bytes = limits.max_total_bytes;
    for residue in &residues {
        ensure_before_deadline(Some(deadline), "before private residue tree audit")?;
        let name_c = c_string(&residue.name)?;
        let directory = openat_directory(root.directory.as_raw_fd(), &name_c)?;
        let opened = fstat(directory.as_raw_fd())?;
        if identity_from_stat(&opened) != residue.identity {
            bail!(
                "private residue directory changed before bounded audit: {}",
                root.path().join(&residue.name).display()
            );
        }
        audit_private_residue_tree(
            directory.as_raw_fd(),
            root_stat.st_dev,
            0,
            &mut tree_budget,
            &mut remaining_bytes,
            Some(deadline),
        )
        .with_context(|| {
            format!(
                "private residue tree exceeded its bounded safety contract: {}",
                root.path().join(&residue.name).display()
            )
        })?;
    }

    let mut removed = 0usize;
    for residue in residues {
        ensure_before_deadline(Some(deadline), "before top-level residue quarantine")?;
        let cleanup_name = if residue.already_quarantined {
            residue.name
        } else {
            let cleanup_name = deletion_quarantine_name(&residue.name, &residue.identity);
            quarantine_direct_child_directory_linux(
                root,
                &residue.name,
                &cleanup_name,
                &residue.identity,
            )?;
            cleanup_name
        };
        remove_tree_at_name_linux_with_deadline(
            root,
            &cleanup_name,
            &residue.identity,
            TreeLinkPolicy::UnlinkLinks,
            Some(deadline),
        )?;
        removed = removed.saturating_add(1);
    }
    ensure_before_deadline(Some(deadline), "after private residue cleanup")?;
    root.verify()?;
    Ok(removed)
}

#[cfg(target_os = "linux")]
fn validate_private_scavenge_lock(
    root: &SafeRoot,
    name: &OsStr,
    stat: &libc::stat,
    root_device: libc::dev_t,
) -> Result<()> {
    if stat.st_dev != root_device
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o600
    {
        bail!(
            "private residue lock is unsafe or changed: {}",
            root.path().join(name).display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private_scavenge_directory(
    root: &SafeRoot,
    name: &OsStr,
    stat: &libc::stat,
    root_device: libc::dev_t,
) -> Result<()> {
    if stat.st_dev != root_device
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o700
    {
        bail!(
            "private residue entry is not an owner-private directory: {}",
            root.path().join(name).display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_canonical_random_temp_name(seed: &OsStr, name: &OsStr) -> bool {
    let seed = seed.as_bytes();
    let name = name.as_bytes();
    let prefix_len = seed.len().saturating_add(2);
    if name.len() <= prefix_len.saturating_add(4)
        || name.first() != Some(&b'.')
        || name.get(1..1 + seed.len()) != Some(seed)
        || name.get(1 + seed.len()) != Some(&b'.')
        || !name.ends_with(b".tmp")
    {
        return false;
    }
    let middle = &name[prefix_len..name.len() - 4];
    let Some(separator) = middle.iter().position(|byte| *byte == b'-') else {
        return false;
    };
    if middle[separator + 1..].contains(&b'-') {
        return false;
    }
    canonical_decimal_u64(&middle[..separator]) && canonical_decimal_u64(&middle[separator + 1..])
}

#[cfg(target_os = "linux")]
fn canonical_decimal_u64(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes.first() == Some(&b'0'))
    {
        return false;
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some()
}

#[cfg(target_os = "linux")]
fn deletion_quarantine_binding(name: &OsStr) -> Result<Option<DeletionQuarantineBinding>> {
    let bytes = name.as_bytes();
    let prefix = DELETION_QUARANTINE_PREFIX.as_bytes();
    if !bytes.starts_with(prefix) {
        return Ok(None);
    }
    let v2_prefix = DELETION_QUARANTINE_V2_PREFIX.as_bytes();
    if !bytes.starts_with(v2_prefix) {
        bail!("private residue deletion quarantine version is unsupported");
    }
    let body = &bytes[v2_prefix.len()..];
    if body.len() < 2 + 32 + 1 + 16 + 1 + 16 {
        bail!("private residue deletion quarantine name is malformed");
    }
    let inode_separator = body
        .len()
        .checked_sub(17)
        .context("private residue quarantine name underflow")?;
    let device_separator = inode_separator
        .checked_sub(17)
        .context("private residue quarantine name underflow")?;
    if body.get(inode_separator) != Some(&b'-') || body.get(device_separator) != Some(&b'-') {
        bail!("private residue deletion quarantine identity is malformed");
    }
    let source_and_tag = &body[..device_separator];
    let tag_separator = source_and_tag
        .len()
        .checked_sub(33)
        .context("private residue quarantine tag underflow")?;
    if source_and_tag.get(tag_separator) != Some(&b'-') {
        bail!("private residue deletion quarantine tag is malformed");
    }
    let encoded_source = &source_and_tag[..tag_separator];
    let tag = &source_and_tag[tag_separator + 1..];
    if tag.len() != 32
        || !tag
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("private residue deletion quarantine tag is not canonical lowercase hex");
    }
    let source = OsString::from_vec(base64url_decode(encoded_source)?);
    validate_single_component(&source)?;
    let device = parse_fixed_lower_hex_u64(&body[device_separator + 1..inode_separator])?;
    let file = parse_fixed_lower_hex_u64(&body[inode_separator + 1..])?;
    let identity = FileIdentity { device, file };
    let expected = deletion_quarantine_name(&source, &identity);
    if expected.as_bytes() != bytes {
        bail!("private residue deletion quarantine authentication tag does not match");
    }
    Ok(Some(DeletionQuarantineBinding { source, identity }))
}

#[cfg(unix)]
fn parse_fixed_lower_hex_u64(bytes: &[u8]) -> Result<u64> {
    if bytes.len() != 16
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("private residue quarantine identity is not canonical lowercase hex");
    }
    u64::from_str_radix(std::str::from_utf8(bytes)?, 16)
        .context("private residue quarantine identity overflow")
}

#[cfg(target_os = "linux")]
fn audit_private_residue_tree(
    fd: RawFd,
    device: libc::dev_t,
    depth: usize,
    entry_budget: &mut TreeBudget,
    remaining_bytes: &mut u64,
    deadline: Option<Instant>,
) -> Result<()> {
    ensure_before_deadline(deadline, "during private residue tree audit")?;
    if depth > MAX_TREE_DEPTH {
        bail!("private residue tree exceeded its maximum depth of {MAX_TREE_DEPTH}");
    }
    for name in directory_entries_until(fd, entry_budget, deadline)? {
        ensure_before_deadline(deadline, "during private residue tree audit")?;
        let name_c = c_string(&name)?;
        let stat = fstatat_no_follow(fd, &name_c)?;
        if stat.st_dev != device || stat.st_uid != unsafe { libc::geteuid() } {
            bail!(
                "private residue entry changed owner or filesystem: {}",
                name.to_string_lossy()
            );
        }
        let kind = stat.st_mode & libc::S_IFMT;
        match kind {
            libc::S_IFDIR => {
                if stat.st_mode & 0o777 != 0o700 {
                    bail!(
                        "private residue directory has unsafe mode: {}",
                        name.to_string_lossy()
                    );
                }
                let child = openat_directory(fd, &name_c)?;
                let opened = fstat(child.as_raw_fd())?;
                if identity_from_stat(&opened) != identity_from_stat(&stat) {
                    bail!(
                        "private residue directory identity changed: {}",
                        name.to_string_lossy()
                    );
                }
                audit_private_residue_tree(
                    child.as_raw_fd(),
                    device,
                    depth.saturating_add(1),
                    entry_budget,
                    remaining_bytes,
                    deadline,
                )?;
            }
            libc::S_IFREG => {
                if stat.st_nlink != 1 || stat.st_mode & 0o777 != 0o600 {
                    bail!(
                        "private residue file is not owner-private and single-link: {}",
                        name.to_string_lossy()
                    );
                }
                consume_private_residue_bytes(stat.st_size, remaining_bytes)?;
            }
            libc::S_IFLNK => {
                if stat.st_nlink != 1 {
                    bail!(
                        "private residue symlink has an unsafe link count: {}",
                        name.to_string_lossy()
                    );
                }
                consume_private_residue_bytes(stat.st_size, remaining_bytes)?;
            }
            _ => bail!(
                "private residue contains a special file: {}",
                name.to_string_lossy()
            ),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn consume_private_residue_bytes(size: libc::off_t, remaining: &mut u64) -> Result<()> {
    let size = u64::try_from(size).context("private residue entry has a negative size")?;
    *remaining = remaining.checked_sub(size).with_context(|| {
        format!(
            "private residue trees exceed their {} byte cleanup budget",
            remaining.saturating_add(size)
        )
    })?;
    Ok(())
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
fn temp_quarantine_name(file_name: &OsStr, source: &OsStr, identity: &FileIdentity) -> OsString {
    let encoded_target = base64url_encode(file_name.as_bytes());
    let source_checksum = component_checksum_tag(source);
    let binding = temp_quarantine_binding_tag(file_name, &source_checksum, identity);
    OsString::from(format!(
        "{TEMP_QUARANTINE_V2_PREFIX}{encoded_target}-{source_checksum}-{binding}-{:016x}-{:016x}",
        identity.device, identity.file
    ))
}

#[cfg(unix)]
fn component_checksum_tag(name: &OsStr) -> String {
    component_checksum(name)[8..40].to_string()
}

#[cfg(unix)]
fn temp_quarantine_binding_tag(
    file_name: &OsStr,
    source_checksum: &str,
    identity: &FileIdentity,
) -> String {
    let mut payload = Vec::with_capacity(
        TEMP_QUARANTINE_V2_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(file_name.as_bytes().len())
            .saturating_add(source_checksum.len())
            .saturating_add(16),
    );
    payload.extend_from_slice(TEMP_QUARANTINE_V2_DOMAIN);
    payload.extend_from_slice(
        &u64::try_from(file_name.as_bytes().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    payload.extend_from_slice(file_name.as_bytes());
    payload.extend_from_slice(source_checksum.as_bytes());
    payload.extend_from_slice(&identity.device.to_be_bytes());
    payload.extend_from_slice(&identity.file.to_be_bytes());
    stable_checksum(&payload)[8..40].to_string()
}

#[cfg(unix)]
fn canonical_random_temp_target(name: &OsStr) -> Option<OsString> {
    let bytes = name.as_bytes();
    let body = bytes.strip_prefix(b".")?.strip_suffix(b".tmp")?;
    let separator = body.iter().rposition(|byte| *byte == b'.')?;
    let target = body.get(..separator)?;
    let random = body.get(separator + 1..)?;
    if target.is_empty() || random.is_empty() {
        return None;
    }
    let dash = random.iter().position(|byte| *byte == b'-')?;
    if random.get(dash + 1..)?.contains(&b'-') {
        return None;
    }
    let first = std::str::from_utf8(random.get(..dash)?).ok()?;
    let second = std::str::from_utf8(random.get(dash + 1..)?).ok()?;
    if !is_canonical_decimal_u64(first) || !is_canonical_decimal_u64(second) {
        return None;
    }
    Some(OsString::from_vec(target.to_vec()))
}

#[cfg(unix)]
fn is_canonical_decimal_u64(value: &str) -> bool {
    value
        .parse::<u64>()
        .ok()
        .is_some_and(|parsed| parsed.to_string() == value)
}

#[cfg(unix)]
struct TempQuarantineBinding {
    target: OsString,
    identity: FileIdentity,
}

#[cfg(unix)]
fn canonical_temp_quarantine_binding(name: &OsStr) -> Result<Option<TempQuarantineBinding>> {
    let bytes = name.as_bytes();
    if !bytes.starts_with(TEMP_QUARANTINE_PREFIX.as_bytes()) {
        return Ok(None);
    }
    let body = bytes
        .strip_prefix(TEMP_QUARANTINE_V2_PREFIX.as_bytes())
        .context("state temp quarantine version is unsupported")?;
    let inode_separator = body
        .len()
        .checked_sub(17)
        .context("state temp quarantine name is malformed")?;
    let device_separator = inode_separator
        .checked_sub(17)
        .context("state temp quarantine identity is malformed")?;
    let binding_separator = device_separator
        .checked_sub(33)
        .context("state temp quarantine binding is malformed")?;
    let source_separator = binding_separator
        .checked_sub(33)
        .context("state temp quarantine source checksum is malformed")?;
    for separator in [
        source_separator,
        binding_separator,
        device_separator,
        inode_separator,
    ] {
        if body.get(separator) != Some(&b'-') {
            bail!("state temp quarantine framing is malformed");
        }
    }
    let encoded_target = &body[..source_separator];
    let source_checksum = &body[source_separator + 1..binding_separator];
    let binding = &body[binding_separator + 1..device_separator];
    if !is_lower_hex_bytes_width(source_checksum, 32) || !is_lower_hex_bytes_width(binding, 32) {
        bail!("state temp quarantine checksums are not canonical lowercase hex");
    }
    let target = OsString::from_vec(base64url_decode(encoded_target)?);
    validate_single_component(&target)?;
    let device = parse_fixed_lower_hex_u64(&body[device_separator + 1..inode_separator])?;
    let file = parse_fixed_lower_hex_u64(&body[inode_separator + 1..])?;
    let identity = FileIdentity { device, file };
    let source_checksum = std::str::from_utf8(source_checksum)?;
    let expected_binding = temp_quarantine_binding_tag(&target, source_checksum, &identity);
    if expected_binding.as_bytes() != binding {
        bail!("state temp quarantine target/source/identity binding does not match");
    }
    Ok(Some(TempQuarantineBinding { target, identity }))
}

#[cfg(unix)]
fn is_lower_hex_bytes_width(value: &[u8], width: usize) -> bool {
    value.len() == width
        && value
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
fn restore_quarantined_direct_child_directory_linux(
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
            "source and quarantine both exist; refusing ambiguous restore for {}",
            root.path().join(child_name).display()
        ),
        (None, None) => bail!(
            "source and quarantine are both absent; refusing ambiguous restore for {}",
            root.path().join(child_name).display()
        ),
        (Some(stat), None) => {
            validate_private_quarantine_directory(root, child_name, &stat, expected)?;
            Ok(expected.clone())
        }
        (None, Some(stat)) => {
            validate_private_quarantine_directory(root, quarantine_name, &stat, expected)?;
            rename_noreplace_at(root, quarantine_name, child_name)?;
            let rebound = fstatat_no_follow(parent_fd, &source)?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != *expected
            {
                bail!(
                    "restored directory identity mismatch after atomic rename for {}",
                    root.path().join(child_name).display()
                );
            }
            if fstatat_optional_no_follow(parent_fd, &quarantine)?.is_some() {
                bail!("quarantine name reappeared during directory restore");
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
    let root_mount_id = linux_mount_identity_for_fd(root.directory.as_raw_fd())?.mount_id;
    verify_linux_mount_at(
        root.directory.as_raw_fd(),
        &cname,
        stat,
        root_mount_id,
        "quarantine directory entry",
    )?;
    let directory = openat_directory(root.directory.as_raw_fd(), &cname)?;
    let opened = fstat(directory.as_raw_fd())?;
    if identity_from_stat(&opened) != *expected {
        bail!("quarantine directory changed while opening its handle");
    }
    verify_linux_mount_for_fd(
        directory.as_raw_fd(),
        root_mount_id,
        "opened quarantine directory",
    )?;
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
    let cleanup_name = quarantined_direct_child_cleanup_name(quarantine_name, expected)?;
    let quarantine = c_string(quarantine_name)?;
    let cleanup = c_string(&cleanup_name)?;
    let source_exists =
        fstatat_optional_no_follow(root.directory.as_raw_fd(), &quarantine)?.is_some();
    let cleanup_exists =
        fstatat_optional_no_follow(root.directory.as_raw_fd(), &cleanup)?.is_some();
    if !source_exists && !cleanup_exists {
        return Ok(false);
    }
    if source_exists && cleanup_exists {
        bail!(
            "quarantine and cleanup residue both exist; refusing ambiguous removal for {}",
            root.path().join(quarantine_name).display()
        );
    }
    let expected_mount_id = linux_mount_identity_for_fd(root.directory.as_raw_fd())?.mount_id;
    let preaudit_name = if source_exists {
        quarantine_name
    } else {
        cleanup_name.as_os_str()
    };
    audit_tree_at_name_linux_on_mount(
        root,
        preaudit_name,
        expected,
        policy,
        None,
        expected_mount_id,
    )?;
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
    remove_tree_at_name_linux_with_deadline(root, name, expected, policy, None)
}

#[cfg(target_os = "linux")]
fn remove_tree_at_name_linux_with_deadline(
    root: &SafeRoot,
    name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
    deadline: Option<Instant>,
) -> Result<()> {
    let expected_mount_id = linux_mount_identity_for_fd(root.directory.as_raw_fd())?.mount_id;
    remove_tree_at_name_linux_with_deadline_on_mount(
        root,
        name,
        expected,
        policy,
        deadline,
        expected_mount_id,
    )
}

#[cfg(target_os = "linux")]
fn audit_tree_at_name_linux_on_mount(
    root: &SafeRoot,
    name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
    deadline: Option<Instant>,
    expected_mount_id: u64,
) -> Result<()> {
    ensure_before_deadline(deadline, "before opening quarantine tree for audit")?;
    let directory = root.directory.as_ref();
    verify_linux_mount_for_fd(
        directory.as_raw_fd(),
        expected_mount_id,
        "quarantine audit root",
    )?;
    let root_stat = fstat(directory.as_raw_fd())?;
    let cname = c_string(name)?;
    let child_path_stat = fstatat_no_follow(directory.as_raw_fd(), &cname)?;
    verify_linux_mount_at(
        directory.as_raw_fd(),
        &cname,
        &child_path_stat,
        expected_mount_id,
        "top-level quarantine tree during pre-audit",
    )?;
    let child = openat_directory(directory.as_raw_fd(), &cname)?;
    let child_stat = fstat(child.as_raw_fd())?;
    if child_stat.st_dev != root_stat.st_dev {
        bail!(
            "refusing to cross a filesystem boundary while auditing {}",
            root.path().join(name).display()
        );
    }
    verify_linux_mount_for_fd(
        child.as_raw_fd(),
        expected_mount_id,
        "opened top-level quarantine tree during pre-audit",
    )?;
    if identity_from_stat(&child_stat) != *expected {
        bail!(
            "directory identity changed before deletion audit at {}",
            root.path().join(name).display()
        );
    }
    let mut audit_budget = TreeBudget::new();
    audit_directory_unix(
        child.as_raw_fd(),
        child_stat.st_dev,
        expected_mount_id,
        policy,
        0,
        &mut audit_budget,
        deadline,
    )
}

#[cfg(target_os = "linux")]
fn remove_tree_at_name_linux_with_deadline_on_mount(
    root: &SafeRoot,
    name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
    deadline: Option<Instant>,
    expected_mount_id: u64,
) -> Result<()> {
    ensure_before_deadline(deadline, "before opening quarantined tree")?;
    let directory = root.directory.as_ref();
    verify_linux_mount_for_fd(
        directory.as_raw_fd(),
        expected_mount_id,
        "quarantine cleanup root",
    )?;
    let root_stat = fstat(directory.as_raw_fd())?;
    let cname = c_string(name)?;
    let child_path_stat = fstatat_no_follow(directory.as_raw_fd(), &cname)?;
    verify_linux_mount_at(
        directory.as_raw_fd(),
        &cname,
        &child_path_stat,
        expected_mount_id,
        "top-level quarantine tree",
    )?;
    let child = openat_directory(directory.as_raw_fd(), &cname)?;
    let child_stat = fstat(child.as_raw_fd())?;
    if child_stat.st_dev != root_stat.st_dev {
        bail!(
            "refusing to cross a filesystem boundary while deleting {}",
            root.path().join(name).display()
        );
    }
    verify_linux_mount_for_fd(
        child.as_raw_fd(),
        expected_mount_id,
        "opened top-level quarantine tree",
    )?;
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
        expected_mount_id,
        policy,
        0,
        &mut audit_budget,
        deadline,
    )?;
    let mut removal_budget = TreeBudget::new();
    remove_directory_contents_unix(
        child.as_raw_fd(),
        child_stat.st_dev,
        expected_mount_id,
        policy,
        0,
        &mut removal_budget,
        deadline,
    )?;
    drop(child);
    ensure_before_deadline(deadline, "before top-level quarantine removal")?;
    let rebound = fstatat_no_follow(directory.as_raw_fd(), &cname)?;
    if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR || identity_from_stat(&rebound) != observed {
        bail!(
            "top-level directory binding changed immediately before removal: {}",
            root.path().join(name).display()
        );
    }
    verify_linux_mount_at(
        directory.as_raw_fd(),
        &cname,
        &rebound,
        expected_mount_id,
        "top-level quarantine tree before removal",
    )?;
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
struct InventoryBudget {
    remaining_entries: usize,
    total_path_bytes: usize,
    deadline: Instant,
}

#[cfg(unix)]
impl InventoryBudget {
    fn consume_entry(&mut self) -> Result<()> {
        self.remaining_entries = self
            .remaining_entries
            .checked_sub(1)
            .context("repository inventory exceeded its global entry limit")?;
        Ok(())
    }

    fn consume_path(&mut self, path: &Path, limits: BoundedTreeWalkLimits) -> Result<()> {
        let bytes = path.as_os_str().as_bytes().len();
        if bytes == 0 || bytes > limits.max_path_bytes {
            bail!(
                "repository inventory path exceeds its {}-byte limit: {}",
                limits.max_path_bytes,
                path.display()
            );
        }
        self.total_path_bytes = self
            .total_path_bytes
            .checked_add(bytes)
            .context("repository inventory path byte count overflowed")?;
        if self.total_path_bytes > limits.max_total_path_bytes {
            bail!(
                "repository inventory paths exceed their {}-byte aggregate limit",
                limits.max_total_path_bytes
            );
        }
        Ok(())
    }

    fn ensure_before_deadline(&self, phase: &str) -> Result<()> {
        if Instant::now() >= self.deadline {
            bail!("repository inventory exceeded its time limit {phase}");
        }
        Ok(())
    }
}

#[cfg(unix)]
struct InventoryWalkState<'a, F> {
    root_device: libc::dev_t,
    #[cfg(target_os = "linux")]
    root_mount_id: Option<u64>,
    limits: BoundedTreeWalkLimits,
    budget: &'a mut InventoryBudget,
    action: &'a mut F,
    entries: &'a mut Vec<BoundedTreeEntry>,
}

pub(crate) fn unsigned_to_u64<T>(value: T) -> u64
where
    T: TryInto<u64>,
{
    value.try_into().unwrap_or(u64::MAX)
}

pub(crate) fn unsigned_to_u32<T>(value: T) -> u32
where
    T: TryInto<u32>,
{
    value.try_into().unwrap_or(u32::MAX)
}

#[cfg(target_os = "linux")]
fn stat_mtime_seconds(stat: &libc::stat) -> i64 {
    stat.st_mtime
}

#[cfg(target_os = "linux")]
fn stat_mtime_nanoseconds(stat: &libc::stat) -> i64 {
    stat.st_mtime_nsec
}

#[cfg(target_os = "linux")]
fn stat_ctime_seconds(stat: &libc::stat) -> i64 {
    stat.st_ctime
}

#[cfg(target_os = "linux")]
fn stat_ctime_nanoseconds(stat: &libc::stat) -> i64 {
    stat.st_ctime_nsec
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_mtime_seconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_mtime_nanoseconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_ctime_seconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_ctime_nanoseconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(unix)]
impl<F> InventoryWalkState<'_, F>
where
    F: FnMut(&BoundedTreeEntry) -> Result<BoundedTreeWalkAction>,
{
    fn walk(&mut self, directory_fd: RawFd, relative_directory: &Path, depth: usize) -> Result<()> {
        self.budget
            .ensure_before_deadline("before directory enumeration")?;
        for name in inventory_directory_entries(directory_fd, self.budget)? {
            self.budget
                .ensure_before_deadline("during entry inspection")?;
            let relative = relative_directory.join(&name);
            let entry_depth = depth.saturating_add(1);
            if entry_depth > self.limits.max_depth {
                bail!(
                    "repository inventory exceeded its maximum depth of {} at {}",
                    self.limits.max_depth,
                    relative.display()
                );
            }
            self.budget.consume_path(&relative, self.limits)?;
            let name_c = c_string(&name)?;
            let stat = fstatat_no_follow(directory_fd, &name_c).with_context(|| {
                format!("failed to inspect repository entry {}", relative.display())
            })?;
            if self.limits.same_device && stat.st_dev != self.root_device {
                bail!(
                    "repository inventory refused a cross-device entry: {}",
                    relative.display()
                );
            }
            #[cfg(target_os = "linux")]
            if let Some(root_mount_id) = self.root_mount_id {
                let entry_mount = linux_mount_identity_at(directory_fd, &name_c, &stat)?;
                if entry_mount.mount_id != root_mount_id {
                    bail!(
                        "repository inventory refused a mounted entry: {}",
                        relative.display()
                    );
                }
            }
            let file_kind = stat.st_mode & libc::S_IFMT;
            let kind = if file_kind == libc::S_IFDIR {
                BoundedTreeEntryKind::Directory
            } else if file_kind == libc::S_IFREG {
                BoundedTreeEntryKind::RegularFile
            } else if file_kind == libc::S_IFLNK {
                BoundedTreeEntryKind::Symlink
            } else {
                BoundedTreeEntryKind::Special
            };
            let entry = BoundedTreeEntry {
                relative_path: relative.clone(),
                kind,
                size_bytes: u64::try_from(stat.st_size).unwrap_or(0),
                hard_link_count: unsigned_to_u64(stat.st_nlink),
                unix_mode: unsigned_to_u32(stat.st_mode & 0o7777),
                identity: identity_from_stat(&stat),
                modified_seconds: stat_mtime_seconds(&stat),
                modified_nanoseconds: stat_mtime_nanoseconds(&stat),
                changed_seconds: stat_ctime_seconds(&stat),
                changed_nanoseconds: stat_ctime_nanoseconds(&stat),
            };
            let decision = (self.action)(&entry)?;
            self.budget
                .ensure_before_deadline("after repository inventory callback")?;
            if matches!(
                decision,
                BoundedTreeWalkAction::Record | BoundedTreeWalkAction::RecordAndDescend
            ) {
                self.entries.push(entry.clone());
            }
            if decision == BoundedTreeWalkAction::RecordAndDescend {
                if kind != BoundedTreeEntryKind::Directory {
                    bail!(
                        "bounded tree walk requested descent through a non-directory: {}",
                        relative.display()
                    );
                }
                if entry_depth >= self.limits.max_depth {
                    bail!(
                        "repository inventory refused to descend beyond depth {} at {}",
                        self.limits.max_depth,
                        relative.display()
                    );
                }
                let child = openat_directory(directory_fd, &name_c).with_context(|| {
                    format!(
                        "failed to open repository directory without following links: {}",
                        relative.display()
                    )
                })?;
                let opened = fstat(child.as_raw_fd())?;
                if opened.st_mode & libc::S_IFMT != libc::S_IFDIR
                    || identity_from_stat(&opened) != entry.identity
                    || (self.limits.same_device && opened.st_dev != self.root_device)
                {
                    bail!(
                        "repository directory changed during bounded traversal: {}",
                        relative.display()
                    );
                }
                #[cfg(target_os = "linux")]
                if let Some(root_mount_id) = self.root_mount_id {
                    if linux_mount_identity_for_fd(child.as_raw_fd())?.mount_id != root_mount_id {
                        bail!(
                            "repository directory crossed a mount boundary while opening: {}",
                            relative.display()
                        );
                    }
                }
                self.walk(child.as_raw_fd(), &relative, entry_depth)?;
            }
            let rebound = fstatat_no_follow(directory_fd, &name_c).with_context(|| {
                format!(
                    "failed to revalidate repository entry after traversal: {}",
                    relative.display()
                )
            })?;
            if rebound.st_mode & libc::S_IFMT != file_kind
                || identity_from_stat(&rebound) != entry.identity
            {
                bail!(
                    "repository entry changed during bounded traversal: {}",
                    relative.display()
                );
            }
            #[cfg(target_os = "linux")]
            if let Some(root_mount_id) = self.root_mount_id {
                if linux_mount_identity_at(directory_fd, &name_c, &rebound)?.mount_id
                    != root_mount_id
                {
                    bail!(
                        "repository entry crossed a mount boundary during traversal: {}",
                        relative.display()
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn inventory_directory_entries(fd: RawFd, budget: &mut InventoryBudget) -> Result<Vec<OsString>> {
    budget.ensure_before_deadline("before directory stream open")?;
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
            .context("failed to open an independent repository directory stream");
    }
    let directory = unsafe { libc::fdopendir(stream_fd) };
    if directory.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(stream_fd) };
        return Err(error).context("failed to open repository directory stream");
    }
    let mut entries = Vec::new();
    loop {
        if let Err(error) = budget.ensure_before_deadline("during directory enumeration") {
            unsafe { libc::closedir(directory) };
            return Err(error);
        }
        clear_thread_errno()?;
        let raw = unsafe { libc::readdir(directory) };
        if raw.is_null() {
            let errno = std::io::Error::last_os_error();
            unsafe { libc::closedir(directory) };
            if errno.raw_os_error().unwrap_or(0) != 0 {
                return Err(errno).context("failed while reading repository directory stream");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*raw).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if let Err(error) = budget.consume_entry() {
            unsafe { libc::closedir(directory) };
            return Err(error);
        }
        entries.push(OsString::from_vec(name.to_bytes().to_vec()));
    }
    entries.sort();
    budget.ensure_before_deadline("after directory entry sorting")?;
    Ok(entries)
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
    expected_mount_id: u64,
    policy: TreeLinkPolicy,
    depth: usize,
    budget: &mut TreeBudget,
    deadline: Option<Instant>,
) -> Result<()> {
    ensure_before_deadline(deadline, "during recursive deletion audit")?;
    verify_linux_mount_for_fd(fd, expected_mount_id, "audited quarantine directory")?;
    if depth > MAX_TREE_DEPTH {
        bail!("recursive deletion exceeded its maximum depth of {MAX_TREE_DEPTH}");
    }
    for name in directory_entries_until(fd, budget, deadline)? {
        ensure_before_deadline(deadline, "during recursive deletion audit")?;
        let cname = c_string(&name)?;
        let stat = fstatat_no_follow(fd, &cname)?;
        if stat.st_dev != device {
            bail!(
                "refusing to traverse a mounted filesystem entry: {}",
                name.to_string_lossy()
            );
        }
        verify_linux_mount_at(
            fd,
            &cname,
            &stat,
            expected_mount_id,
            "quarantine tree entry during deletion audit",
        )?;
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
            verify_linux_mount_for_fd(
                child.as_raw_fd(),
                expected_mount_id,
                "opened quarantine child during deletion audit",
            )?;
            audit_directory_unix(
                child.as_raw_fd(),
                device,
                expected_mount_id,
                policy,
                depth.saturating_add(1),
                budget,
                deadline,
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
    expected_mount_id: u64,
    policy: TreeLinkPolicy,
    depth: usize,
    budget: &mut TreeBudget,
    deadline: Option<Instant>,
) -> Result<()> {
    ensure_before_deadline(deadline, "during recursive deletion")?;
    verify_linux_mount_for_fd(fd, expected_mount_id, "quarantine removal directory")?;
    if depth > MAX_TREE_DEPTH {
        bail!("recursive deletion exceeded its maximum depth of {MAX_TREE_DEPTH}");
    }
    for name in directory_entries_until(fd, budget, deadline)? {
        ensure_before_deadline(deadline, "before child quarantine")?;
        let source_name = c_string(&name)?;
        let stat = fstatat_no_follow(fd, &source_name)?;
        if stat.st_dev != device {
            bail!(
                "filesystem entry changed across devices during deletion: {}",
                name.to_string_lossy()
            );
        }
        verify_linux_mount_at(
            fd,
            &source_name,
            &stat,
            expected_mount_id,
            "quarantine tree entry before child rename",
        )?;
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
        verify_linux_mount_at(
            fd,
            &quarantine_c,
            &rebound,
            expected_mount_id,
            "quarantined child after rename",
        )?;
        if fstatat_optional_no_follow(fd, &source_name)?.is_some() {
            bail!("child source name reappeared during quarantine");
        }
        let cname = c_string(&quarantine_name)?;
        let quarantined = fstatat_no_follow(fd, &cname)?;
        if identity_from_stat(&quarantined) != expected {
            bail!("quarantined child identity changed before deletion");
        }
        verify_linux_mount_at(
            fd,
            &cname,
            &quarantined,
            expected_mount_id,
            "quarantined child before deletion",
        )?;
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
            verify_linux_mount_for_fd(
                child.as_raw_fd(),
                expected_mount_id,
                "opened quarantine child during deletion",
            )?;
            remove_directory_contents_unix(
                child.as_raw_fd(),
                device,
                expected_mount_id,
                policy,
                depth.saturating_add(1),
                budget,
                deadline,
            )?;
            drop(child);
            ensure_before_deadline(deadline, "before child directory unlink")?;
            let rebound = fstatat_no_follow(fd, &cname)?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != expected
            {
                bail!(
                    "child directory binding changed immediately before removal: {}",
                    name.to_string_lossy()
                );
            }
            verify_linux_mount_at(
                fd,
                &cname,
                &rebound,
                expected_mount_id,
                "quarantine child directory before removal",
            )?;
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
            verify_linux_mount_at(
                fd,
                &cname,
                &rebound,
                expected_mount_id,
                "quarantine child entry before unlink",
            )?;
            ensure_before_deadline(deadline, "before child unlink")?;
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
    directory_entries_until(fd, budget, None)
}

#[cfg(unix)]
fn directory_entries_until(
    fd: RawFd,
    budget: &mut TreeBudget,
    deadline: Option<Instant>,
) -> Result<Vec<OsString>> {
    ensure_before_deadline(deadline, "before directory enumeration")?;
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
        if let Err(error) = ensure_before_deadline(deadline, "during directory enumeration") {
            unsafe { libc::closedir(directory) };
            return Err(error);
        }
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

fn ensure_before_deadline(deadline: Option<Instant>, phase: &str) -> Result<()> {
    #[cfg(test)]
    {
        let forced = SCAVENGE_DEADLINE_HOOK.with(|slot| {
            let mut slot = slot.borrow_mut();
            let triggered = slot.as_mut().is_some_and(|hook| hook(phase));
            if triggered {
                slot.take();
            }
            triggered
        });
        if forced {
            bail!("private directory scavenging exceeded its total time budget at {phase}");
        }
    }
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        bail!("private directory scavenging exceeded its total time budget at {phase}");
    }
    Ok(())
}

#[cfg(test)]
type ScavengeDeadlineHook = Box<dyn FnMut(&str) -> bool>;

#[cfg(test)]
thread_local! {
    static SCAVENGE_DEADLINE_HOOK: std::cell::RefCell<Option<ScavengeDeadlineHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_scavenge_deadline_hook(hook: impl FnMut(&str) -> bool + 'static) {
    SCAVENGE_DEADLINE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
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
fn validate_owned_direct_child_stat(
    stat: &libc::stat,
    expected_identity: &FileIdentity,
    kind: DirectChildType,
) -> Result<()> {
    let observed_kind = stat.st_mode & libc::S_IFMT;
    let kind_is_safe = match kind {
        DirectChildType::SingleLinkRegularFile => {
            observed_kind == libc::S_IFREG && stat.st_nlink == 1
        }
        DirectChildType::Directory => observed_kind == libc::S_IFDIR && stat.st_nlink != 0,
    };
    if !kind_is_safe
        || stat.st_uid != unsafe { libc::geteuid() }
        || identity_from_stat(stat) != *expected_identity
    {
        bail!("bound direct child type, ownership, linkage, or identity changed");
    }
    Ok(())
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
        device: unsigned_to_u64(stat.st_dev),
        file: unsigned_to_u64(stat.st_ino),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    #[test]
    fn quarantined_direct_child_unlink_refuses_reappeared_source_without_deleting_replacement() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("state")).expect("safe root");
        let source = root.path().join("created.lock");
        fs::write(&source, b"original").expect("original source");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o600))
            .expect("owner-private source");
        let identity = identity_for_path(&source).expect("source identity");
        let binding = root
            .bind_owned_direct_child(
                "created.lock",
                &identity,
                DirectChildType::SingleLinkRegularFile,
            )
            .expect("direct child binding");
        set_direct_child_before_quarantine_unlink_hook({
            let source = source.clone();
            move || {
                fs::write(&source, b"replacement").expect("replacement source");
                fs::set_permissions(&source, fs::Permissions::from_mode(0o600))
                    .expect("replacement mode");
            }
        });

        let error = binding
            .unlink_fenced(&root)
            .expect_err("reappeared source must refuse unlink");

        assert!(error.to_string().contains("reappeared"));
        assert_eq!(
            fs::read(&source).expect("replacement remains"),
            b"replacement"
        );
        let quarantine = root
            .path()
            .join(entry_quarantine_name(OsStr::new("created.lock"), &identity));
        assert_eq!(
            fs::read(quarantine).expect("original quarantine"),
            b"original"
        );
    }

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
        let fifo_started = Instant::now();
        assert!(BoundedRegularReader::read(&fifo, 32).is_err());
        assert!(
            fifo_started.elapsed() < Duration::from_secs(1),
            "no-writer FIFO open must fail without blocking"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_relative_reader_refuses_mount_boundary() {
        let error = BoundedRegularReader::read_relative("/", "proc/self/status", 64 * 1024)
            .expect_err("repository-relative reader must not cross into procfs");

        assert!(format!("{error:#}").contains("mount-confined"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn statx_mount_identity_distinguishes_procfs_boundary() {
        let root = open_unix_directory(Path::new("/")).expect("open filesystem root");
        let root_mount =
            linux_mount_identity_for_fd(root.as_raw_fd()).expect("root mount identity");
        let proc_name = c"proc";
        let proc_stat =
            fstatat_no_follow(root.as_raw_fd(), proc_name).expect("inspect proc mountpoint");
        let proc_mount = linux_mount_identity_at(root.as_raw_fd(), proc_name, &proc_stat)
            .expect("proc mount identity");

        assert_ne!(root_mount, proc_mount);
        assert!(
            require_linux_mount_id(root_mount.mount_id, proc_mount.mount_id, "procfs fixture",)
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn safe_root_mount_identity_rechecks_path_and_direct_child() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("root")).expect("safe root");
        fs::write(root.path().join("child"), b"bound").expect("child");
        let mount_id = root.linux_mount_id().expect("root mount id");

        root.verify_linux_mount_id(mount_id)
            .expect("stable root mount");
        assert_eq!(
            root.direct_child_linux_mount_id("child")
                .expect("child mount id"),
            Some(mount_id)
        );
        assert!(root
            .verify_linux_mount_id(mount_id.saturating_add(1))
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn directory_binding_guard_rejects_pathname_replacement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bound = temp.path().join("bound");
        let displaced = temp.path().join("displaced");
        fs::create_dir(&bound).expect("create bound directory");
        let guard = DirectoryBindingGuard::bind(&bound).expect("bind directory");
        fs::rename(&bound, &displaced).expect("displace bound directory");
        fs::create_dir(&bound).expect("create replacement directory");

        let error = guard
            .verify()
            .expect_err("replacement directory must fail binding verification");

        assert!(error.to_string().contains("binding changed"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_same_inode_generation_change_and_truncation() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("changing-input");
        fs::write(&path, b"original").expect("write input");

        let mut changing = open_regular_no_follow(&path, false).expect("open changing input");
        let changed = read_bounded_file_with_hook(&mut changing, &path, 32, || {
            fs::write(&path, b"replaced").expect("replace same-length contents");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
                .expect("change input generation");
        })
        .expect_err("same-inode generation change must fail");
        assert!(changed.to_string().contains("changed"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore permissions");
        fs::write(&path, b"original").expect("restore input");
        let mut truncating = open_regular_no_follow(&path, false).expect("open truncating input");
        let truncated = read_bounded_file_with_hook(&mut truncating, &path, 32, || {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open for truncate")
                .set_len(3)
                .expect("truncate input");
        })
        .expect_err("truncation during read must fail");
        assert!(truncated.to_string().contains("truncated"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_metadata_validator_is_bound_to_the_open_descriptor_generation() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("validated-input");
        fs::write(&path, b"reviewed").expect("write input");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private input mode");
        let validator = |metadata: &fs::Metadata| -> Result<()> {
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
                bail!("unsafe descriptor metadata");
            }
            Ok(())
        };
        assert_eq!(
            BoundedRegularReader::read_tree_no_follow_validated(&path, 32, validator)
                .expect("validated read"),
            b"reviewed"
        );

        let mut opened = open_regular_no_follow(&path, false).expect("open validated input");
        let mut validator = |metadata: &fs::Metadata| -> Result<()> {
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
                bail!("unsafe descriptor metadata");
            }
            Ok(())
        };
        let changed = read_bounded_file_with_validator_and_hook(
            &mut opened,
            &path,
            32,
            &mut validator,
            || {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o622))
                    .expect("make descriptor unsafe");
            },
        )
        .expect_err("permission change on the opened descriptor must fail");
        assert!(changed.to_string().contains("metadata policy"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_path_replacement_during_read() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("replaceable-input");
        let displaced = temp.path().join("displaced-input");
        fs::write(&path, b"original").expect("write original input");

        let mut opened = open_regular_no_follow(&path, false).expect("open original input");
        let replaced = read_bounded_file_with_hook(&mut opened, &path, 32, || {
            fs::rename(&path, &displaced).expect("displace original path");
            fs::write(&path, b"attacker").expect("replace input path");
        })
        .expect_err("path replacement must fail closed");

        assert!(replaced.to_string().contains("identity changed"));
        assert_eq!(fs::read(&path).expect("read replacement"), b"attacker");
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
    fn directory_quarantine_restore_is_identity_bound_and_no_replace() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
        let source = root.path().join("source");
        let quarantine = root.path().join("quarantine");
        fs::create_dir(&source).expect("source");
        fs::write(source.join("valuable"), "keep").expect("valuable file");
        let expected = identity_for_path(&source).expect("identity");

        quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect("quarantine");
        restore_quarantined_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect("restore");
        assert_eq!(
            identity_for_path(&source).expect("restored identity"),
            expected
        );
        assert_eq!(
            fs::read_to_string(source.join("valuable")).expect("restored content"),
            "keep"
        );
        assert!(!quarantine.exists());
        restore_quarantined_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect("idempotent restore");

        quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect("quarantine again");
        fs::create_dir(&source).expect("replacement source");
        let error =
            restore_quarantined_direct_child_directory(&root, "source", "quarantine", &expected)
                .expect_err("replacement must block restore");
        assert!(error.to_string().contains("both exist"));
        assert!(source.exists());
        assert!(quarantine.join("valuable").exists());
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
        let cleanup_name =
            quarantined_direct_child_cleanup_name("quarantine", &expected).expect("cleanup name");
        fs::rename(&quarantine, root.path().join(&cleanup_name))
            .expect("simulate crash after top-level cleanup rename");

        assert!(remove_quarantined_direct_child_tree(
            &root,
            "quarantine",
            &expected,
            TreeLinkPolicy::UnlinkLinks,
        )
        .expect("resume cleanup"));
        assert!(!quarantine.exists());
        assert!(!root.path().join(cleanup_name).exists());
        assert!(!remove_quarantined_direct_child_tree(
            &root,
            "quarantine",
            &expected,
            TreeLinkPolicy::UnlinkLinks,
        )
        .expect("idempotent completed cleanup"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quarantined_tree_cleanup_refuses_nested_mount_mismatch_without_removal() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
        let source = root.path().join("source");
        fs::create_dir(&source).expect("source");
        fs::write(source.join("valuable"), "keep").expect("valuable file");
        let expected = identity_for_path(&source).expect("source identity");
        quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect("durable quarantine");
        let cleanup_name =
            quarantined_direct_child_cleanup_name("quarantine", &expected).expect("cleanup name");

        // Unprivileged test environments cannot create a same-device bind mount. Inject the
        // otherwise statx-backed mismatch at the first nested audit entry instead.
        inject_next_linux_mount_mismatch("quarantine tree entry during deletion audit");
        let error = remove_quarantined_direct_child_tree(
            &root,
            "quarantine",
            &expected,
            TreeLinkPolicy::UnlinkLinks,
        )
        .expect_err("nested mount mismatch must fail closed");

        assert!(error.to_string().contains("mount crossing"));
        assert!(!root.path().join(cleanup_name).exists());
        assert_eq!(
            fs::read_to_string(root.path().join("quarantine").join("valuable"))
                .expect("quarantined content survives"),
            "keep"
        );
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

    #[cfg(unix)]
    #[test]
    fn stable_lock_rejects_path_replacement_after_flock() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
        let lock_path = root.path().join("state.lock");
        let moved_path = root.path().join("state.lock.original");
        set_kernel_lock_after_flock_hook({
            let moved_path = moved_path.clone();
            move |path| {
                fs::rename(path, &moved_path).expect("move acquired lock inode");
                fs::write(path, b"").expect("create replacement lock inode");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .expect("private replacement mode");
                true
            }
        });

        let error = KernelStateLock::acquire(&lock_path)
            .expect_err("post-flock pathname replacement must fail closed");
        assert!(
            error
                .to_string()
                .contains("does not name its opened descriptor")
                || error.to_string().contains("was rebound"),
            "unexpected error: {error:#}"
        );
        assert!(lock_path.exists());
        assert!(moved_path.exists());
        assert_ne!(
            identity_for_path(&lock_path).expect("replacement identity"),
            identity_for_path(&moved_path).expect("original identity")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn locked_writer_scavenges_only_safe_matching_crash_temps() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
        let _lock = KernelStateLock::acquire_direct(&root, "claims.lock").expect("lock");
        let residue_name = random_temp_name(OsStr::new("claims.json"));
        let residue = root.path().join(&residue_name);
        fs::write(&residue, "partial").expect("residue");
        fs::set_permissions(&residue, fs::Permissions::from_mode(0o600)).expect("private mode");
        let expected = BoundedRegularReader::identity(&residue).expect("residue identity");
        let quarantine = temp_quarantine_name(OsStr::new("claims.json"), &residue_name, &expected);
        quarantine_regular_file(&root, &residue_name, &quarantine, &expected)
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

    #[cfg(target_os = "linux")]
    #[test]
    fn root_wide_temp_scavenge_recovers_interrupted_quarantine_and_live_temp() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
        let _lock = KernelStateLock::acquire_direct(&root, "root.lock").expect("lock");
        let quarantined_target = OsString::from("locator-a.json");
        let quarantined_source = random_temp_name(&quarantined_target);
        let quarantined_path = root.path().join(&quarantined_source);
        fs::write(&quarantined_path, b"partial-a").expect("quarantined source");
        fs::set_permissions(&quarantined_path, fs::Permissions::from_mode(0o600))
            .expect("private quarantine source");
        let identity = BoundedRegularReader::identity(&quarantined_path).expect("source identity");
        let quarantine = temp_quarantine_name(&quarantined_target, &quarantined_source, &identity);
        quarantine_regular_file(&root, &quarantined_source, &quarantine, &identity)
            .expect("simulate interrupted quarantine cleanup");

        let live_target = OsString::from("locator-b.json");
        let live_source = random_temp_name(&live_target);
        let live_path = root.path().join(&live_source);
        fs::write(&live_path, b"partial-b").expect("live source");
        fs::set_permissions(&live_path, fs::Permissions::from_mode(0o600))
            .expect("private live source");

        let foreign_target = OsString::from("foreign.json");
        let foreign_source = random_temp_name(&foreign_target);
        let foreign_path = root.path().join(&foreign_source);
        fs::write(&foreign_path, b"foreign").expect("foreign source");
        fs::set_permissions(&foreign_path, fs::Permissions::from_mode(0o600))
            .expect("private foreign source");

        let removed = AtomicStateWriter::scavenge_direct_temp_namespaces_bounded(&root, 8, |_| {
            Ok(BTreeSet::from([
                quarantined_target.clone(),
                live_target.clone(),
            ]))
        })
        .expect("root-wide recovery");

        assert_eq!(removed, 2);
        assert!(!root.path().join(quarantine).exists());
        assert!(!live_path.exists());
        assert!(foreign_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_wide_temp_scavenge_rejects_rebound_quarantine_identity() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
        let _lock = KernelStateLock::acquire_direct(&root, "root.lock").expect("lock");
        let target = OsString::from("locator.json");
        let source = random_temp_name(&target);
        let source_path = root.path().join(&source);
        fs::write(&source_path, b"partial").expect("source");
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600))
            .expect("private source");
        let identity = BoundedRegularReader::identity(&source_path).expect("source identity");
        let forged_identity = FileIdentity {
            device: identity.device,
            file: identity.file.wrapping_add(1),
        };
        let forged = temp_quarantine_name(&target, &source, &forged_identity);
        fs::rename(&source_path, root.path().join(&forged)).expect("forge rebound quarantine");

        let error = AtomicStateWriter::scavenge_direct_temp_namespaces_bounded(&root, 4, |_| {
            Ok(BTreeSet::from([target.clone()]))
        })
        .expect_err("encoded quarantine identity must bind its inode");

        assert!(error
            .to_string()
            .contains("identity is malformed or changed"));
        assert!(root.path().join(forged).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_wide_temp_scavenge_rejects_legacy_quarantine_format() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
        let _lock = KernelStateLock::acquire_direct(&root, "root.lock").expect("lock");
        let target = OsString::from("locator.json");
        let source = random_temp_name(&target);
        let legacy = OsString::from(format!(
            "{TEMP_QUARANTINE_PREFIX}{}-{}-0000000000000001-0000000000000001",
            component_checksum(&target),
            component_checksum(&source)
        ));
        let legacy_path = root.path().join(&legacy);
        fs::write(&legacy_path, b"legacy").expect("legacy quarantine");
        fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o600))
            .expect("private legacy quarantine");

        let error = AtomicStateWriter::scavenge_direct_temp_namespaces_bounded(&root, 4, |_| {
            Ok(BTreeSet::from([target.clone()]))
        })
        .expect_err("unreleased legacy quarantine format must fail closed");

        assert!(error.to_string().contains("version is unsupported"));
        assert!(legacy_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn caller_bounded_temp_scavenge_can_cover_a_large_finite_namespace() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("large-state")).expect("state root");
        for index in 0..=4096_u32 {
            fs::write(root.path().join(format!("filler-{index:04}")), b"").expect("filler entry");
        }
        let residue = root
            .path()
            .join(random_temp_name(OsStr::new("locator.json")));
        fs::write(&residue, b"partial").expect("temp residue");
        fs::set_permissions(&residue, fs::Permissions::from_mode(0o600)).expect("private temp");

        let legacy_error = AtomicStateWriter::scavenge_direct_temps(&root, "locator.json")
            .expect_err("legacy scan budget is intentionally too small");
        assert!(legacy_error.to_string().contains("entry budget"));
        assert_eq!(
            AtomicStateWriter::scavenge_direct_temps_bounded(&root, "locator.json", 4_100)
                .expect("caller capacity covers complete root"),
            1
        );
        assert!(!residue.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forged_or_legacy_deletion_quarantine_is_never_removed() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("residues")).expect("root");
        let _lock = KernelStateLock::acquire_direct(&root, "bounded-status.lock").expect("lock");
        let residue = root
            .reserve_random_direct_child_directory("git-status")
            .expect("residue");
        let source = residue
            .path()
            .file_name()
            .expect("source name")
            .to_os_string();
        fs::write(residue.path().join("sentinel"), b"keep").expect("sentinel");
        fs::set_permissions(
            residue.path().join("sentinel"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("sentinel mode");
        let mut forged = deletion_quarantine_name(&source, residue.identity())
            .as_bytes()
            .to_vec();
        let tag_start = forged.len().checked_sub(66).expect("tag position");
        forged[tag_start] = if forged[tag_start] == b'a' {
            b'b'
        } else {
            b'a'
        };
        let forged = OsString::from_vec(forged);
        fs::rename(residue.path(), root.path().join(&forged)).expect("forge quarantine name");

        let error = scavenge_private_random_directories(
            &root,
            "bounded-status.lock",
            "git-status",
            PrivateDirectoryScavengeLimits {
                max_root_entries: 8,
                max_directories: 4,
                max_tree_entries: 16,
                max_total_bytes: 1024,
                max_duration: Duration::from_secs(5),
            },
        )
        .expect_err("forged quarantine must fail closed");
        assert!(format!("{error:#}").contains("authentication tag"));
        assert!(root.path().join(&forged).join("sentinel").exists());

        let legacy = OsStr::new(".maco-delete-maco-v1-deadbeef-0000000000000001-0000000000000002");
        assert!(deletion_quarantine_binding(legacy)
            .expect_err("legacy quarantine must be rejected")
            .to_string()
            .contains("version is unsupported"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deadline_interrupted_scavenge_resumes_from_authenticated_quarantine() {
        let temp = TempDir::new().expect("tempdir");
        let root = SafeRoot::open_or_create(temp.path().join("residues")).expect("root");
        let _lock = KernelStateLock::acquire_direct(&root, "bounded-status.lock").expect("lock");
        let residue = root
            .reserve_random_direct_child_directory("git-status")
            .expect("residue");
        for name in ["first", "second"] {
            fs::write(residue.path().join(name), name).expect("residue file");
            fs::set_permissions(residue.path().join(name), fs::Permissions::from_mode(0o600))
                .expect("private residue file");
        }
        let limits = PrivateDirectoryScavengeLimits {
            max_root_entries: 8,
            max_directories: 4,
            max_tree_entries: 16,
            max_total_bytes: 1024,
            max_duration: Duration::from_secs(5),
        };
        let mut child_quarantines = 0usize;
        set_scavenge_deadline_hook(move |phase| {
            if phase == "before child quarantine" {
                child_quarantines = child_quarantines.saturating_add(1);
            }
            child_quarantines == 2
        });

        let error =
            scavenge_private_random_directories(&root, "bounded-status.lock", "git-status", limits)
                .expect_err("forced deadline must interrupt cleanup");
        assert!(format!("{error:#}").contains("time budget"));
        assert!(!residue.path().exists());

        assert_eq!(
            scavenge_private_random_directories(
                &root,
                "bounded-status.lock",
                "git-status",
                limits,
            )
            .expect("resume authenticated cleanup"),
            1
        );
        let entries = fs::read_dir(root.path())
            .expect("root entries")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![OsString::from("bounded-status.lock")]);
    }

    #[cfg(unix)]
    fn inventory_limits(max_entries: usize) -> BoundedTreeWalkLimits {
        BoundedTreeWalkLimits {
            max_depth: 16,
            max_entries,
            max_path_bytes: 4096,
            max_total_path_bytes: 64 * 1024,
            max_duration: Duration::from_secs(5),
            same_device: true,
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_tree_walk_records_but_never_follows_unsafe_entries() {
        use std::os::unix::{fs::symlink, net::UnixListener};

        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("repo");
        let outside = temp.path().join("outside");
        fs::create_dir_all(root.join("src")).expect("repo tree");
        fs::create_dir_all(&outside).expect("outside tree");
        fs::write(root.join("src/lib.rs"), "pub fn ok() {}\n").expect("source");
        fs::write(outside.join("secret"), "outside\n").expect("outside secret");
        fs::hard_link(root.join("src/lib.rs"), root.join("hardlink.rs")).expect("hardlink");
        symlink(&outside, root.join("outside-link")).expect("outside symlink");
        let _socket = UnixListener::bind(root.join("socket")).expect("unix socket");

        let entries = BoundedTreeWalker::walk(&root, inventory_limits(32)).expect("inventory");
        assert!(entries.iter().any(|entry| {
            entry.relative_path == Path::new("outside-link")
                && entry.kind == BoundedTreeEntryKind::Symlink
        }));
        assert!(entries.iter().any(|entry| {
            entry.relative_path == Path::new("socket")
                && entry.kind == BoundedTreeEntryKind::Special
        }));
        assert!(!entries
            .iter()
            .any(|entry| entry.relative_path == Path::new("outside-link/secret")));
        assert!(entries
            .iter()
            .filter(|entry| entry.kind == BoundedTreeEntryKind::RegularFile)
            .all(|entry| entry.hard_link_count == 2 && !entry.is_safe_regular_file()));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_tree_walk_enforces_entry_depth_and_path_budgets() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("repo");
        fs::create_dir_all(root.join("a/b")).expect("repo tree");
        fs::write(root.join("a/b/file"), "data").expect("file");

        let error = BoundedTreeWalker::walk(&root, inventory_limits(1))
            .expect_err("entry limit must fail closed");
        assert!(format!("{error:#}").contains("entry limit"));

        let mut limits = inventory_limits(16);
        limits.max_depth = 2;
        let error =
            BoundedTreeWalker::walk(&root, limits).expect_err("depth limit must fail closed");
        assert!(format!("{error:#}").contains("depth"));

        limits = inventory_limits(16);
        limits.max_total_path_bytes = 2;
        let error =
            BoundedTreeWalker::walk(&root, limits).expect_err("path aggregate must fail closed");
        assert!(format!("{error:#}").contains("aggregate"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_tree_walk_checks_deadline_after_callback() {
        let root = tempfile::tempdir().expect("tempdir");
        fs::write(root.path().join("entry"), "data").expect("write entry");
        let limits = BoundedTreeWalkLimits {
            max_depth: 8,
            max_entries: 8,
            max_path_bytes: 128,
            max_total_path_bytes: 1024,
            max_duration: Duration::from_millis(1),
            same_device: true,
        };

        let error = BoundedTreeWalker::walk_with(root.path(), limits, |_entry| {
            std::thread::sleep(Duration::from_millis(5));
            Ok(BoundedTreeWalkAction::Record)
        })
        .expect_err("callback overrun must fail the hard deadline check");

        assert!(error.to_string().contains("time limit"));
    }

    #[cfg(unix)]
    #[test]
    fn optional_relative_reader_preserves_scopes_and_rejects_unsafe_files() {
        use std::os::unix::{fs::symlink, net::UnixListener};

        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("repo tree");
        fs::write(root.join("src/lib.rs"), "source\n").expect("source");
        fs::hard_link(root.join("src/lib.rs"), root.join("hardlink.rs")).expect("hardlink");
        symlink("src/lib.rs", root.join("link.rs")).expect("symlink");
        let _socket = UnixListener::bind(root.join("socket")).expect("unix socket");

        assert_eq!(
            BoundedRegularReader::read_relative_optional_utf8(&root, "missing.rs", 64)
                .expect("missing scope"),
            None
        );
        assert_eq!(
            BoundedRegularReader::read_relative_optional_utf8(&root, "src", 64)
                .expect("directory scope"),
            None
        );
        for path in ["src/lib.rs", "hardlink.rs", "link.rs", "socket"] {
            assert!(BoundedRegularReader::read_relative_optional_utf8(&root, path, 64).is_err());
        }
    }
}
