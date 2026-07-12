//! Parent-owned output capabilities for paths exposed near less-trusted child workspaces.
//!
//! The security boundary includes a hostile same-UID process outside the child sandbox. Callers
//! therefore retain directory and file descriptors captured before child execution and never
//! reopen child-writable output paths after execution. On Unix, every path component is opened
//! with `O_NOFOLLOW`, private roots must be owned by the effective user with mode `0700`, output
//! leaves are `0600` single-link regular files, and replacement uses descriptor-relative
//! `renameat` plus `fsync`. Unsupported hosts fail closed instead of silently weakening this
//! contract.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{
    ffi::OsStr,
    fs::File,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::{
    ffi::CString,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::ffi::OsStrExt,
    },
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::path::Component;

#[cfg(unix)]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildSetupFault {
    None,
    #[cfg(test)]
    BeforeOpen,
    #[cfg(test)]
    AfterOpen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AtomicWriteFault {
    None,
    #[cfg(test)]
    RebindTempBeforeRename {
        sentinel: PathBuf,
    },
    #[cfg(test)]
    RebindDestinationAfterRename {
        sentinel: PathBuf,
    },
}

/// A private directory held open independently of its potentially tainted pathname.
#[derive(Debug)]
pub(crate) struct SecureOutputRoot {
    path: PathBuf,
    directory: File,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

/// A newly reserved output leaf. The descriptor is the capability; `path` is display-only.
#[derive(Debug)]
pub(crate) struct ReservedOutputFile {
    path: PathBuf,
    directory: File,
    file: File,
    name: std::ffi::OsString,
    #[cfg(unix)]
    root_device: u64,
    #[cfg(unix)]
    root_inode: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl SecureOutputRoot {
    /// Opens an existing private directory without creating any path component.
    pub(crate) fn open_private(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let absolute = absolute_normalized(path)?;
            let directory = open_existing_directory_tree(&absolute)?;
            let metadata = directory.metadata().with_context(|| {
                format!(
                    "failed to inspect secure output root {}",
                    absolute.display()
                )
            })?;
            validate_private_directory(&metadata, &absolute)?;
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                path: absolute,
                directory,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    /// Creates a new private final directory. Existing final paths are refused even when safe.
    pub(crate) fn create_new(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let absolute = absolute_normalized(path)?;
            let directory = create_new_directory_tree(&absolute)?;
            let metadata = directory.metadata().with_context(|| {
                format!(
                    "failed to inspect secure output root {}",
                    absolute.display()
                )
            })?;
            validate_private_directory(&metadata, &absolute)?;
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                path: absolute,
                directory,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    /// Creates the final directory or opens an existing private directory without following any
    /// symlink component. Existing final directories are never chmodded; unsafe permissions fail.
    pub(crate) fn open_or_create(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let absolute = absolute_normalized(path)?;
            let directory = open_or_create_directory_tree(&absolute)?;
            let metadata = directory.metadata().with_context(|| {
                format!(
                    "failed to inspect secure output root {}",
                    absolute.display()
                )
            })?;
            validate_private_directory(&metadata, &absolute)?;
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                path: absolute,
                directory,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    /// Creates a private direct child and returns it as another descriptor-held root.
    pub(crate) fn create_child(&self, name: &OsStr) -> Result<Self> {
        self.create_child_impl(name, ChildSetupFault::None)
    }

    #[cfg(test)]
    fn create_child_failing_before_open(&self, name: &OsStr) -> Result<Self> {
        self.create_child_impl(name, ChildSetupFault::BeforeOpen)
    }

    #[cfg(test)]
    fn create_child_failing_after_open(&self, name: &OsStr) -> Result<Self> {
        self.create_child_impl(name, ChildSetupFault::AfterOpen)
    }

    fn create_child_impl(&self, name: &OsStr, _fault: ChildSetupFault) -> Result<Self> {
        #[cfg(unix)]
        {
            self.verify_path_identity()?;
            let name_c = leaf_cstring(name)?;
            // SAFETY: the directory fd and NUL-terminated name remain valid for the call.
            let result =
                unsafe { libc::mkdirat(self.directory.as_raw_fd(), name_c.as_ptr(), 0o700) };
            if result != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to create secure output child {}",
                        self.path.join(name).display()
                    )
                });
            }
            let created_identity = created_directory_identity(&self.directory, &name_c)
                .with_context(|| {
                    format!(
                        "failed to bind newly created secure child {}",
                        self.path.join(name).display()
                    )
                })?;
            if let Err(error) = self.directory.sync_all() {
                cleanup_created_directory(
                    &self.directory,
                    &name_c,
                    created_identity,
                    &self.path.join(name),
                )?;
                return Err(error).with_context(|| {
                    format!(
                        "failed to flush secure output parent {}",
                        self.path.display()
                    )
                });
            }
            #[cfg(test)]
            if _fault == ChildSetupFault::BeforeOpen {
                cleanup_created_directory(
                    &self.directory,
                    &name_c,
                    created_identity,
                    &self.path.join(name),
                )?;
                bail!("synthetic secure child setup failure before open");
            }
            let directory = match openat_directory(self.directory.as_raw_fd(), &name_c) {
                Ok(directory) => directory,
                Err(error) => {
                    cleanup_created_directory(
                        &self.directory,
                        &name_c,
                        created_identity,
                        &self.path.join(name),
                    )?;
                    return Err(error).with_context(|| {
                        format!(
                            "failed to open secure output child {}",
                            self.path.join(name).display()
                        )
                    });
                }
            };
            let prepared = (|| -> Result<(u64, u64)> {
                #[cfg(test)]
                if _fault == ChildSetupFault::AfterOpen {
                    bail!("synthetic secure child setup failure after open");
                }
                let metadata = directory.metadata()?;
                let path = self.path.join(name);
                validate_private_directory(&metadata, &path)?;
                use std::os::unix::fs::MetadataExt;
                Ok((metadata.dev(), metadata.ino()))
            })();
            let (device, inode) = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    cleanup_created_directory(
                        &self.directory,
                        &name_c,
                        created_identity,
                        &self.path.join(name),
                    )?;
                    return Err(error).with_context(|| {
                        format!(
                            "failed to finish secure output child {}",
                            self.path.join(name).display()
                        )
                    });
                }
            };
            let path = self.path.join(name);
            Ok(Self {
                path,
                directory,
                device,
                inode,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = name;
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Refuses a parent output root located inside a child-writable workspace.
    pub(crate) fn reject_inside(&self, writable_workspace: &Path) -> Result<()> {
        let workspace = std::fs::canonicalize(writable_workspace).with_context(|| {
            format!(
                "failed to canonicalize child-writable workspace {}",
                writable_workspace.display()
            )
        })?;
        self.verify_path_identity()?;
        let root = std::fs::canonicalize(&self.path).with_context(|| {
            format!(
                "failed to canonicalize secure output root {}",
                self.path.display()
            )
        })?;
        if root == workspace || root.starts_with(&workspace) || workspace.starts_with(&root) {
            bail!(
                "secure output root {} may not overlap child-writable workspace {}",
                root.display(),
                workspace.display()
            );
        }
        Ok(())
    }

    /// Refuses identical or ancestor/descendant output roots, both by path and held inode.
    pub(crate) fn reject_overlap(&self, other: &Self) -> Result<()> {
        self.verify_path_identity()?;
        other.verify_path_identity()?;
        #[cfg(unix)]
        if self.device == other.device && self.inode == other.inode {
            bail!("secure output roots resolve to the same inode");
        }
        let left = std::fs::canonicalize(&self.path)?;
        let right = std::fs::canonicalize(&other.path)?;
        if left.starts_with(&right) || right.starts_with(&left) {
            bail!(
                "secure output roots overlap: {} and {}",
                left.display(),
                right.display()
            );
        }
        Ok(())
    }

    /// Reserves a new `0600` regular file before releasing less-trusted execution.
    pub(crate) fn reserve(&self, name: &OsStr) -> Result<ReservedOutputFile> {
        self.reserve_impl(name, false, true, false)
    }

    /// Opens a previously secured leaf or creates it. Intended for resumable state only.
    pub(crate) fn open_or_reserve(&self, name: &OsStr) -> Result<ReservedOutputFile> {
        self.reserve_impl(name, true, true, false)
    }

    /// Opens an existing private regular leaf without creating a missing target.
    pub(crate) fn open_existing_leaf(&self, name: &OsStr) -> Result<ReservedOutputFile> {
        self.reserve_impl(name, true, false, false)
    }

    #[cfg(test)]
    fn reserve_failing_after_open(&self, name: &OsStr) -> Result<ReservedOutputFile> {
        self.reserve_impl(name, false, true, true)
    }

    fn reserve_impl(
        &self,
        name: &OsStr,
        allow_existing: bool,
        create_if_missing: bool,
        fail_after_open: bool,
    ) -> Result<ReservedOutputFile> {
        #[cfg(unix)]
        {
            self.verify_path_identity()?;
            let name_c = leaf_cstring(name)?;
            // O_NONBLOCK is inert for regular files and prevents a pre-existing FIFO/device from
            // blocking or triggering device-specific open behavior before fstat rejects it.
            let base_flags = libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
            let (fd, created) = if allow_existing {
                // SAFETY: the held directory fd and NUL-terminated leaf name remain valid.
                let existing = unsafe {
                    libc::openat(self.directory.as_raw_fd(), name_c.as_ptr(), base_flags)
                };
                if existing >= 0 {
                    (existing, false)
                } else if create_if_missing
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
                {
                    // SAFETY: the descriptor and name are valid; O_EXCL prevents raced reuse.
                    let created = unsafe {
                        libc::openat(
                            self.directory.as_raw_fd(),
                            name_c.as_ptr(),
                            base_flags | libc::O_CREAT | libc::O_EXCL,
                            0o600,
                        )
                    };
                    (created, true)
                } else {
                    (-1, false)
                }
            } else {
                // SAFETY: the descriptor and name are valid; O_EXCL prevents existing reuse.
                (
                    unsafe {
                        libc::openat(
                            self.directory.as_raw_fd(),
                            name_c.as_ptr(),
                            base_flags | libc::O_CREAT | libc::O_EXCL,
                            0o600,
                        )
                    },
                    true,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to reserve secure output {}",
                        self.path.join(name).display()
                    )
                });
            }
            // SAFETY: `openat` returned an owned descriptor.
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            use std::os::unix::fs::MetadataExt;
            let identity = (metadata.dev(), metadata.ino());
            let prepared = (|| -> Result<()> {
                if fail_after_open {
                    bail!("synthetic secure output setup failure after open");
                }
                validate_private_file(&metadata, &self.path.join(name))?;
                file.sync_all().with_context(|| {
                    format!(
                        "failed to flush reserved secure output {}",
                        self.path.join(name).display()
                    )
                })?;
                self.directory.sync_all().with_context(|| {
                    format!(
                        "failed to flush secure output directory {}",
                        self.path.display()
                    )
                })?;
                Ok(())
            })();
            if let Err(error) = prepared {
                if created {
                    cleanup_created_file(
                        &self.directory,
                        &name_c,
                        identity,
                        &self.path.join(name),
                    )?;
                }
                return Err(error);
            }
            let slot = ReservedOutputFile {
                path: self.path.join(name),
                directory: self.directory.try_clone()?,
                file,
                name: name.to_os_string(),
                root_device: self.device,
                root_inode: self.inode,
                device: identity.0,
                inode: identity.1,
            };
            slot.verify_path_identity()?;
            Ok(slot)
        }
        #[cfg(not(unix))]
        {
            let _ = (name, allow_existing, create_if_missing, fail_after_open);
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    #[cfg(unix)]
    fn verify_path_identity(&self) -> Result<()> {
        let reopened = open_existing_directory_tree(&self.path)
            .with_context(|| format!("secure output root path changed: {}", self.path.display()))?;
        let metadata = reopened.metadata()?;
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            bail!("secure output root inode changed: {}", self.path.display());
        }
        validate_private_directory(&metadata, &self.path)
    }

    #[cfg(not(unix))]
    fn verify_path_identity(&self) -> Result<()> {
        bail!("secure output capabilities are not implemented on this host")
    }
}

impl ReservedOutputFile {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Removes an unused reserved leaf only while its held and path identities still match.
    pub(crate) fn remove(self) -> Result<()> {
        self.verify_path_identity()?;
        #[cfg(unix)]
        {
            cleanup_created_file(
                &self.directory,
                &leaf_cstring(&self.name)?,
                (self.device, self.inode),
                &self.path,
            )?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    /// Reads from the descriptor captured before child execution. No pathname is reopened.
    pub(crate) fn read_bounded(&self, max_bytes: usize) -> Result<Vec<u8>> {
        #[cfg(unix)]
        {
            self.verify_path_identity()?;
            let metadata = self.file.metadata()?;
            if metadata.len() > max_bytes as u64 {
                bail!(
                    "secure output {} exceeds the configured {max_bytes} byte limit",
                    self.path.display()
                );
            }
            let mut file = self.file.try_clone()?;
            file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            Read::by_ref(&mut file)
                .take(max_bytes.saturating_add(1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > max_bytes {
                bail!(
                    "secure output {} grew beyond the configured {max_bytes} byte limit",
                    self.path.display()
                );
            }
            self.verify_path_identity()?;
            Ok(bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = max_bytes;
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    pub(crate) fn write_json_atomic<T: Serialize>(
        &mut self,
        value: &T,
        max_bytes: usize,
    ) -> Result<()> {
        let mut bytes =
            serde_json::to_vec_pretty(value).context("failed to serialize secure JSON output")?;
        bytes.push(b'\n');
        self.write_bytes_atomic(&bytes, max_bytes)
    }

    /// Atomically replaces the reserved leaf using only the held directory descriptor.
    pub(crate) fn write_bytes_atomic(&mut self, bytes: &[u8], max_bytes: usize) -> Result<()> {
        self.write_bytes_atomic_impl(bytes, max_bytes, AtomicWriteFault::None)
    }

    #[cfg(all(test, unix))]
    fn write_bytes_atomic_with_temp_rebind(
        &mut self,
        bytes: &[u8],
        max_bytes: usize,
        sentinel: &Path,
    ) -> Result<()> {
        self.write_bytes_atomic_impl(
            bytes,
            max_bytes,
            AtomicWriteFault::RebindTempBeforeRename {
                sentinel: sentinel.to_path_buf(),
            },
        )
    }

    #[cfg(all(test, unix))]
    fn write_bytes_atomic_with_destination_rebind(
        &mut self,
        bytes: &[u8],
        max_bytes: usize,
        sentinel: &Path,
    ) -> Result<()> {
        self.write_bytes_atomic_impl(
            bytes,
            max_bytes,
            AtomicWriteFault::RebindDestinationAfterRename {
                sentinel: sentinel.to_path_buf(),
            },
        )
    }

    fn write_bytes_atomic_impl(
        &mut self,
        bytes: &[u8],
        max_bytes: usize,
        fault: AtomicWriteFault,
    ) -> Result<()> {
        if bytes.len() > max_bytes {
            bail!(
                "secure output {} exceeds the configured {max_bytes} byte limit",
                self.path.display()
            );
        }
        #[cfg(unix)]
        {
            #[cfg(not(test))]
            let _ = fault;
            self.verify_path_identity()?;
            let temp_name = std::ffi::OsString::from(format!(
                ".maco-secure-{}-{}-{}.tmp",
                std::process::id(),
                self.inode,
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let temp_c = leaf_cstring(&temp_name)?;
            // SAFETY: descriptor and name are valid. O_EXCL prevents attacker-controlled reuse.
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    temp_c.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to create secure temporary output for {}",
                        self.path.display()
                    )
                });
            }
            // SAFETY: `openat` returned an owned descriptor.
            let mut temp = unsafe { File::from_raw_fd(fd) };
            let temp_metadata = temp.metadata().with_context(|| {
                format!(
                    "failed to inspect secure temporary output for {}",
                    self.path.display()
                )
            })?;
            use std::os::unix::fs::MetadataExt;
            let temp_identity = (temp_metadata.dev(), temp_metadata.ino());
            let mut renamed = false;
            let name_c = leaf_cstring(&self.name)?;
            let result = (|| -> Result<()> {
                temp.write_all(bytes)?;
                temp.sync_all()?;
                let metadata = temp.metadata()?;
                validate_private_file(&metadata, &self.path)?;
                if (metadata.dev(), metadata.ino()) != temp_identity {
                    bail!(
                        "secure temporary output descriptor identity changed for {}",
                        self.path.display()
                    );
                }
                #[cfg(test)]
                if let AtomicWriteFault::RebindTempBeforeRename { sentinel } = &fault {
                    rebind_name_to_sentinel_for_test(&self.directory, &temp_c, sentinel)?;
                }
                self.verify_path_identity()?;
                verify_named_private_file(&self.directory, &temp_c, temp_identity, &self.path)?;
                // SAFETY: source and destination names are relative to the same held directory.
                if unsafe {
                    libc::renameat(
                        self.directory.as_raw_fd(),
                        temp_c.as_ptr(),
                        self.directory.as_raw_fd(),
                        name_c.as_ptr(),
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to atomically replace secure output");
                }
                renamed = true;
                #[cfg(test)]
                if let AtomicWriteFault::RebindDestinationAfterRename { sentinel } = &fault {
                    rebind_name_to_sentinel_for_test(&self.directory, &name_c, sentinel)?;
                }
                if let Err(error) =
                    verify_named_private_file(&self.directory, &name_c, temp_identity, &self.path)
                {
                    let destination_error =
                        error.context("secure output destination changed immediately after rename");
                    if let Err(recovery_error) = restore_reserved_leaf(self, &name_c, max_bytes) {
                        return Err(destination_error.context(format!(
                            "failed to restore reserved output after destination rebind for {}: {recovery_error:#}",
                            self.path.display()
                        )));
                    }
                    return Err(destination_error);
                }
                self.device = temp_identity.0;
                self.inode = temp_identity.1;
                self.file = temp.try_clone()?;
                self.verify_path_identity()?;
                self.directory.sync_all()?;
                Ok(())
            })();
            match result {
                Ok(()) => Ok(()),
                Err(mut operation_error) => {
                    if let Err(cleanup_error) = cleanup_failed_temp_leaf(
                        &self.directory,
                        &temp_c,
                        temp_identity,
                        &self.path,
                    ) {
                        operation_error = operation_error.context(format!(
                            "secure temporary output cleanup also failed: {cleanup_error:#}"
                        ));
                    }
                    if renamed {
                        if let Err(sync_error) = self.directory.sync_all() {
                            operation_error = operation_error.context(format!(
                                "secure output directory recovery flush also failed: {sync_error:#}"
                            ));
                        }
                    }
                    Err(operation_error)
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (bytes, fault);
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    fn verify_held_file(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let metadata = self.file.metadata()?;
            validate_private_file(&metadata, &self.path)?;
            use std::os::unix::fs::MetadataExt;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                bail!("secure output held inode changed: {}", self.path.display());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            bail!("secure output capabilities are not implemented on this host")
        }
    }

    #[cfg(unix)]
    fn verify_path_identity(&self) -> Result<()> {
        let root_metadata = self.directory.metadata()?;
        use std::os::unix::fs::MetadataExt;
        if root_metadata.dev() != self.root_device || root_metadata.ino() != self.root_inode {
            bail!("secure output directory descriptor changed");
        }
        validate_private_directory(&root_metadata, self.path.parent().unwrap_or(Path::new("/")))?;
        self.verify_held_file()?;
        let name_c = leaf_cstring(&self.name)?;
        // SAFETY: storage is initialized and the descriptor/name are valid.
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                name_c.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("secure output path changed: {}", self.path.display()));
        }
        let (path_device, path_inode) = stat_identity(&stat);
        if path_device != self.device
            || path_inode != self.inode
            || (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
            || stat.st_nlink != 1
        {
            bail!(
                "secure output path identity changed: {}",
                self.path.display()
            );
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn verify_path_identity(&self) -> Result<()> {
        bail!("secure output capabilities are not implemented on this host")
    }
}

#[cfg(unix)]
fn absolute_normalized(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                bail!("secure output path may not contain parent or prefix components")
            }
        }
    }
    Ok(normalized)
}

#[cfg(unix)]
fn open_or_create_directory_tree(path: &Path) -> Result<File> {
    walk_directory_tree(path, DirectoryCreateMode::Missing)
}

#[cfg(unix)]
fn create_new_directory_tree(path: &Path) -> Result<File> {
    walk_directory_tree(path, DirectoryCreateMode::NewFinal)
}

#[cfg(unix)]
fn open_existing_directory_tree(path: &Path) -> Result<File> {
    walk_directory_tree(path, DirectoryCreateMode::Never)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryCreateMode {
    Never,
    Missing,
    NewFinal,
}

#[cfg(unix)]
fn walk_directory_tree(path: &Path, create_mode: DirectoryCreateMode) -> Result<File> {
    let absolute = absolute_normalized(path)?;
    // SAFETY: constant is NUL-terminated; the returned descriptor is owned on success.
    let root_fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to open filesystem root");
    }
    // SAFETY: `open` returned an owned descriptor.
    let mut current = unsafe { File::from_raw_fd(root_fd) };
    let components = absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let name = leaf_cstring(component)?;
        let final_component = index + 1 == components.len();
        match openat_directory(current.as_raw_fd(), &name) {
            Ok(_) if create_mode == DirectoryCreateMode::NewFinal && final_component => {
                bail!("secure output root must be new: {}", absolute.display())
            }
            Ok(next) => current = next,
            Err(error)
                if create_mode != DirectoryCreateMode::Never
                    && error.raw_os_error() == Some(libc::ENOENT) =>
            {
                // SAFETY: descriptor and name are valid for this call.
                if unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    return Err(std::io::Error::last_os_error()).with_context(|| {
                        format!("failed to create secure output root {}", absolute.display())
                    });
                }
                current.sync_all().with_context(|| {
                    format!(
                        "failed to flush parent after creating secure output root {}",
                        absolute.display()
                    )
                })?;
                current = openat_directory(current.as_raw_fd(), &name)?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to walk secure output path {}", absolute.display())
                })
            }
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn openat_directory(parent: RawFd, name: &CString) -> std::io::Result<File> {
    // SAFETY: descriptor and NUL-terminated name remain valid for the call.
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned an owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn created_directory_identity(parent: &File, name: &CString) -> Result<(u64, u64)> {
    // SAFETY: storage is initialized and the descriptor/name are valid.
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("failed to stat created directory");
    }
    if (metadata.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        bail!("created secure output child was rebound to a non-directory");
    }
    Ok(stat_identity(&metadata))
}

#[cfg(unix)]
fn named_leaf_stat(parent: &File, name: &CString) -> std::io::Result<libc::stat> {
    // SAFETY: storage is initialized and the descriptor/name are valid.
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(stat)
    }
}

#[cfg(unix)]
fn verify_named_private_file(
    parent: &File,
    name: &CString,
    expected: (u64, u64),
    display_path: &Path,
) -> Result<()> {
    let stat = named_leaf_stat(parent, name).with_context(|| {
        format!(
            "failed to inspect secure output leaf {}",
            display_path.display()
        )
    })?;
    // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if stat_identity(&stat) != expected
        || (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != effective_uid
        || (stat.st_mode & 0o777) != 0o600
    {
        bail!(
            "secure output leaf no longer names its held private file: {}",
            display_path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_failed_temp_leaf(
    parent: &File,
    name: &CString,
    expected: (u64, u64),
    display_path: &Path,
) -> Result<()> {
    let actual = match named_leaf_stat(parent, name) {
        Ok(actual) => actual,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect secure temporary output for {}",
                    display_path.display()
                )
            })
        }
    };
    if stat_identity(&actual) == expected
        && (actual.st_mode & libc::S_IFMT) == libc::S_IFREG
        && actual.st_nlink == 1
    {
        return cleanup_created_file(parent, name, expected, display_path);
    }
    quarantine_and_remove_rebound_leaf(parent, name, &actual, display_path)
}

#[cfg(target_os = "linux")]
fn quarantine_and_remove_rebound_leaf(
    parent: &File,
    name: &CString,
    observed: &libc::stat,
    display_path: &Path,
) -> Result<()> {
    let mut renamed = None;
    for _ in 0..16 {
        let quarantine = std::ffi::OsString::from(format!(
            ".maco-secure-quarantine-{}-{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let quarantine_c = leaf_cstring(&quarantine)?;
        // SAFETY: both names are descriptor-relative and NUL-terminated. RENAME_NOREPLACE keeps
        // an attacker-controlled pre-existing quarantine name from being overwritten.
        let result = unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                name.as_ptr(),
                parent.as_raw_fd(),
                quarantine_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            renamed = Some(quarantine_c);
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error).with_context(|| {
                format!(
                    "failed to quarantine rebound secure output {}",
                    display_path.display()
                )
            });
        }
    }
    let quarantine = renamed.context("secure output quarantine name budget was exhausted")?;
    parent.sync_all()?;
    let moved = named_leaf_stat(parent, &quarantine)
        .context("failed to inspect quarantined secure output replacement")?;
    if stat_identity(&moved) != stat_identity(observed)
        || (moved.st_mode & libc::S_IFMT) != (observed.st_mode & libc::S_IFMT)
    {
        bail!("secure output replacement changed while it was quarantined");
    }
    let flags = if (moved.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        libc::AT_REMOVEDIR
    } else {
        0
    };
    // SAFETY: unlinkat removes the quarantined directory entry without following it.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), quarantine.as_ptr(), flags) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to remove quarantined secure output replacement");
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn quarantine_and_remove_rebound_leaf(
    parent: &File,
    name: &CString,
    observed: &libc::stat,
    display_path: &Path,
) -> Result<()> {
    let mut quarantine = None;
    for _ in 0..16 {
        let quarantine_name = std::ffi::OsString::from(format!(
            ".maco-secure-quarantine-{}-{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let quarantine_c = leaf_cstring(&quarantine_name)?;
        // Reserve the quarantine name before using portable renameat, which otherwise replaces an
        // existing destination. The placeholder is never opened from an attacker-controlled path.
        // SAFETY: descriptor and NUL-terminated name remain valid for the call.
        let placeholder_fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                quarantine_c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if placeholder_fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(error).context("failed to reserve secure output quarantine");
        }
        // SAFETY: openat returned an owned descriptor.
        let placeholder = unsafe { File::from_raw_fd(placeholder_fd) };
        let placeholder_metadata = placeholder.metadata()?;
        use std::os::unix::fs::MetadataExt;
        let placeholder_identity = (placeholder_metadata.dev(), placeholder_metadata.ino());
        // SAFETY: both names are descriptor-relative and NUL-terminated. Replacing the exact
        // O_EXCL-created placeholder moves the rebound leaf away from its sensitive final name.
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                name.as_ptr(),
                parent.as_raw_fd(),
                quarantine_c.as_ptr(),
            )
        } != 0
        {
            let error = std::io::Error::last_os_error();
            cleanup_created_file(parent, &quarantine_c, placeholder_identity, display_path)?;
            return Err(error).with_context(|| {
                format!(
                    "failed to quarantine rebound secure output {}",
                    display_path.display()
                )
            });
        }
        quarantine = Some(quarantine_c);
        break;
    }
    let quarantine = quarantine.context("secure output quarantine name budget was exhausted")?;
    parent.sync_all()?;
    let moved = named_leaf_stat(parent, &quarantine)
        .context("failed to inspect quarantined secure output replacement")?;
    if stat_identity(&moved) != stat_identity(observed)
        || (moved.st_mode & libc::S_IFMT) != (observed.st_mode & libc::S_IFMT)
    {
        bail!("secure output replacement changed while it was quarantined");
    }
    let flags = if (moved.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        libc::AT_REMOVEDIR
    } else {
        0
    };
    // SAFETY: unlinkat removes the quarantined entry without following it.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), quarantine.as_ptr(), flags) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to remove quarantined secure output replacement");
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn quarantine_named_leaf_if_present(
    parent: &File,
    name: &CString,
    display_path: &Path,
) -> Result<()> {
    match named_leaf_stat(parent, name) {
        Ok(observed) => quarantine_and_remove_rebound_leaf(parent, name, &observed, display_path),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect rebound secure output {}",
                display_path.display()
            )
        }),
    }
}

#[cfg(unix)]
fn create_recovery_leaf(parent: &File, name: &CString, display_path: &Path) -> Result<File> {
    for _ in 0..16 {
        quarantine_named_leaf_if_present(parent, name, display_path)?;
        // SAFETY: O_EXCL reserves the final name only when it is still absent.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd >= 0 {
            // SAFETY: openat returned an owned descriptor.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error).context("failed to restore reserved secure output leaf");
        }
    }
    // Leave no observed attacker entry at the sensitive final name when the retry budget is
    // exhausted. A continuously racing same-UID peer can still recreate it after this syscall.
    quarantine_named_leaf_if_present(parent, name, display_path)?;
    bail!("secure output recovery retry budget was exhausted")
}

#[cfg(unix)]
fn restore_reserved_leaf(
    slot: &mut ReservedOutputFile,
    name: &CString,
    max_bytes: usize,
) -> Result<()> {
    // Remove the observed post-rename replacement before inspecting recovery material. Even if
    // the prior held reservation can no longer be restored, the sensitive final name must not
    // retain the attacker-controlled entry that triggered this path.
    quarantine_named_leaf_if_present(&slot.directory, name, &slot.path)?;
    let old_metadata = slot.file.metadata()?;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // The prior rename may have unlinked the reserved destination, so nlink=0 is expected here.
    // All other held-file properties and the original identity must still match.
    // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !old_metadata.is_file()
        || old_metadata.uid() != effective_uid
        || old_metadata.permissions().mode() & 0o777 != 0o600
        || old_metadata.nlink() != 0
        || old_metadata.dev() != slot.device
        || old_metadata.ino() != slot.inode
    {
        bail!("held reservation changed before secure output recovery");
    }
    if old_metadata.len() > max_bytes as u64 {
        bail!("held reservation exceeds its recovery byte limit");
    }
    let mut old = slot.file.try_clone()?;
    old.seek(SeekFrom::Start(0))?;
    let mut old_bytes = Vec::with_capacity(old_metadata.len() as usize);
    Read::by_ref(&mut old)
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut old_bytes)?;
    if old_bytes.len() > max_bytes {
        bail!("held reservation grew beyond its recovery byte limit");
    }

    let mut restored = create_recovery_leaf(&slot.directory, name, &slot.path)?;
    let restored_metadata = match restored.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            quarantine_named_leaf_if_present(&slot.directory, name, &slot.path)?;
            return Err(error).context("failed to inspect restored secure output leaf");
        }
    };
    let restored_identity = (restored_metadata.dev(), restored_metadata.ino());
    let restored_result = (|| -> Result<()> {
        validate_private_file(&restored_metadata, &slot.path)?;
        restored.write_all(&old_bytes)?;
        restored.sync_all()?;
        verify_named_private_file(&slot.directory, name, restored_identity, &slot.path)?;
        slot.directory.sync_all()?;
        Ok(())
    })();
    if let Err(error) = restored_result {
        cleanup_failed_temp_leaf(&slot.directory, name, restored_identity, &slot.path)?;
        return Err(error);
    }
    slot.device = restored_identity.0;
    slot.inode = restored_identity.1;
    slot.file = restored;
    slot.verify_path_identity()
}

#[cfg(all(test, unix))]
fn rebind_name_to_sentinel_for_test(parent: &File, name: &CString, sentinel: &Path) -> Result<()> {
    // SAFETY: unlinkat unlinks only the descriptor-relative name. Its original held descriptor
    // remains open, deterministically emulating a same-UID name rebind.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to remove test secure output name");
    }
    let target = CString::new(sentinel.as_os_str().as_bytes())
        .context("test sentinel path contains a NUL byte")?;
    // SAFETY: both target and link name are NUL-terminated; symlinkat creates only the
    // descriptor-relative attacker replacement and never opens the sentinel target.
    if unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to create test secure output replacement");
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn cleanup_created_directory(
    parent: &File,
    name: &CString,
    expected: (u64, u64),
    display_path: &Path,
) -> Result<()> {
    // SAFETY: storage is initialized and the descriptor/name are valid.
    let mut actual = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut actual,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to inspect failed secure child {}",
                display_path.display()
            )
        });
    }
    let actual_identity = stat_identity(&actual);
    if actual_identity.0 != expected.0
        || actual_identity.1 != expected.1
        || (actual.st_mode & libc::S_IFMT) != libc::S_IFDIR
    {
        bail!(
            "refusing to clean up rebound secure child {}",
            display_path.display()
        );
    }
    // SAFETY: `AT_REMOVEDIR` removes only an empty directory and never follows a symlink.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to clean up incomplete secure child {}",
                display_path.display()
            )
        });
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn cleanup_created_file(
    parent: &File,
    name: &CString,
    expected: (u64, u64),
    display_path: &Path,
) -> Result<()> {
    // SAFETY: storage is initialized and the descriptor/name are valid.
    let mut actual = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut actual,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to inspect failed secure output {}",
                display_path.display()
            )
        });
    }
    let actual_identity = stat_identity(&actual);
    if actual_identity.0 != expected.0
        || actual_identity.1 != expected.1
        || (actual.st_mode & libc::S_IFMT) != libc::S_IFREG
    {
        bail!(
            "refusing to clean up rebound secure output {}",
            display_path.display()
        );
    }
    // SAFETY: unlinkat never follows the final component.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to clean up incomplete secure output {}",
                display_path.display()
            )
        });
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)]
fn stat_identity(metadata: &libc::stat) -> (u64, u64) {
    // `dev_t`/`ino_t` widths differ across Unix targets; normalize them for stored evidence.
    (metadata.st_dev as u64, metadata.st_ino as u64)
}

#[cfg(unix)]
fn leaf_cstring(name: &OsStr) -> Result<CString> {
    if name.is_empty()
        || name.as_bytes().contains(&b'/')
        || name == OsStr::new(".")
        || name == OsStr::new("..")
    {
        bail!("secure output name must be one non-special path component");
    }
    CString::new(name.as_bytes()).context("secure output name contains a NUL byte")
}

#[cfg(unix)]
fn validate_private_directory(metadata: &std::fs::Metadata, path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        bail!(
            "secure output root must be an owner-private 0700 directory: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(metadata: &std::fs::Metadata, path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        bail!(
            "secure output leaf must be an owner-private 0600 single-link regular file: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    #[cfg(unix)]
    fn rejects_existing_nonprivate_root_without_chmodding_it() -> Result<()> {
        let temp = tempdir()?;
        let root = temp.path().join("artifacts");
        std::fs::create_dir(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
        let error = SecureOutputRoot::open_or_create(&root).unwrap_err();
        assert!(error.to_string().contains("0700"));
        assert_eq!(
            std::fs::metadata(&root)?.permissions().mode() & 0o777,
            0o755
        );
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn create_new_refuses_existing_private_root() -> Result<()> {
        let temp = tempdir()?;
        let path = temp.path().join("root");
        let root = SecureOutputRoot::create_new(&path)?;
        assert!(SecureOutputRoot::create_new(root.path()).is_err());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn refuses_symlink_root_and_existing_leaf() -> Result<()> {
        let temp = tempdir()?;
        let real = temp.path().join("real");
        std::fs::create_dir(&real)?;
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700))?;
        let alias = temp.path().join("alias");
        symlink(&real, &alias)?;
        assert!(SecureOutputRoot::open_or_create(&alias).is_err());

        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        std::fs::write(root.path().join("report.json"), "sentinel")?;
        assert!(root.reserve(OsStr::new("report.json")).is_err());
        assert_eq!(std::fs::read(root.path().join("report.json"))?, b"sentinel");
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn held_fd_read_rejects_replaced_symlink_without_touching_sentinel() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        let slot = root.reserve(OsStr::new("child.json"))?;
        let sentinel = temp.path().join("sentinel");
        std::fs::write(&sentinel, "untouched")?;
        std::fs::remove_file(slot.path())?;
        symlink(&sentinel, slot.path())?;
        assert!(slot.read_bounded(1024).is_err());
        assert_eq!(std::fs::read(&sentinel)?, b"untouched");
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn held_fd_read_rejects_added_hardlink() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        let slot = root.reserve(OsStr::new("child.json"))?;
        std::fs::hard_link(slot.path(), root.path().join("extra-link"))?;
        assert!(slot.read_bounded(1024).is_err());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn held_fd_read_rejects_renamed_leaf_and_same_name_rebind() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        let slot = root.reserve(OsStr::new("child.json"))?;
        std::fs::rename(slot.path(), root.path().join("moved.json"))?;
        std::fs::write(slot.path(), "attacker replacement")?;
        std::fs::set_permissions(slot.path(), std::fs::Permissions::from_mode(0o600))?;
        assert!(slot.read_bounded(1024).is_err());
        assert_eq!(std::fs::read(slot.path())?, b"attacker replacement");
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn rejects_workspace_contained_by_output_root() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        let workspace = root.path().join("child-workspace");
        std::fs::create_dir(&workspace)?;
        assert!(root.reject_inside(&workspace).is_err());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn failed_child_setup_cleans_identity_bound_directory_for_retry() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        assert!(root
            .create_child_failing_before_open(OsStr::new("incoming"))
            .is_err());
        assert!(!root.path().join("incoming").exists());
        assert!(root
            .create_child_failing_after_open(OsStr::new("incoming"))
            .is_err());
        assert!(!root.path().join("incoming").exists());
        let child = root.create_child(OsStr::new("incoming"))?;
        assert!(child.path().is_dir());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn failed_new_leaf_setup_cleans_identity_bound_file_for_retry() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        assert!(root
            .reserve_failing_after_open(OsStr::new("report.json"))
            .is_err());
        assert!(!root.path().join("report.json").exists());
        let slot = root.reserve(OsStr::new("report.json"))?;
        assert!(slot.path().is_file());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn existing_fifo_leaf_fails_immediately_without_replacement() -> Result<()> {
        use std::os::unix::fs::FileTypeExt;
        use std::time::{Duration, Instant};

        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        // SAFETY: the path is NUL-terminated and points into a test-owned private directory.
        if unsafe {
            libc::mkfifo(
                CString::new(root.path().join("state.json").as_os_str().as_bytes())?.as_ptr(),
                0o600,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error()).context("failed to create test FIFO");
        }
        let started = Instant::now();
        assert!(root.open_or_reserve(OsStr::new("state.json")).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        let metadata = std::fs::symlink_metadata(root.path().join("state.json"))?;
        assert!(metadata.file_type().is_fifo());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn atomic_replace_does_not_follow_raced_symlink_and_leaves_no_temp() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        let mut slot = root.reserve(OsStr::new("report.json"))?;
        let sentinel = temp.path().join("sentinel");
        std::fs::write(&sentinel, "untouched")?;
        std::fs::remove_file(slot.path())?;
        symlink(&sentinel, slot.path())?;
        assert!(slot.write_bytes_atomic(b"new", 1024).is_err());
        assert_eq!(std::fs::read(&sentinel)?, b"untouched");
        assert!(!std::fs::read_dir(root.path())?.any(|entry| {
            entry
                .ok()
                .is_some_and(|entry| entry.file_name().to_string_lossy().contains("maco-secure"))
        }));
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn atomic_replace_rejects_temp_name_rebind_without_accepting_attacker_output() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        let mut slot = root.reserve(OsStr::new("report.json"))?;
        slot.write_bytes_atomic(b"trusted-old", 1024)?;
        let sentinel = temp.path().join("sentinel");
        std::fs::write(&sentinel, "sentinel-untouched")?;

        let error = slot
            .write_bytes_atomic_with_temp_rebind(b"untrusted-new", 1024, &sentinel)
            .unwrap_err();

        assert!(format!("{error:#}").contains("no longer names its held private file"));
        assert_eq!(slot.read_bounded(1024)?, b"trusted-old");
        assert_eq!(std::fs::read(slot.path())?, b"trusted-old");
        assert_eq!(std::fs::read(&sentinel)?, b"sentinel-untouched");
        assert_no_secure_transient_entries(root.path())?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn atomic_replace_recovers_reservation_after_destination_rebind() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("root"))?;
        let mut slot = root.reserve(OsStr::new("report.json"))?;
        slot.write_bytes_atomic(b"trusted-old", 1024)?;
        let sentinel = temp.path().join("sentinel");
        std::fs::write(&sentinel, "sentinel-untouched")?;

        let error = slot
            .write_bytes_atomic_with_destination_rebind(b"untrusted-new", 1024, &sentinel)
            .unwrap_err();

        assert!(format!("{error:#}").contains("destination changed immediately after rename"));
        assert_eq!(slot.read_bounded(1024)?, b"trusted-old");
        assert_eq!(std::fs::read(slot.path())?, b"trusted-old");
        assert_eq!(std::fs::read(&sentinel)?, b"sentinel-untouched");
        assert_no_secure_transient_entries(root.path())?;
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn atomic_json_write_is_private_and_bounded() -> Result<()> {
        let temp = tempdir()?;
        let root = SecureOutputRoot::open_or_create(&temp.path().join("nested/run/root"))?;
        let mut slot = root.reserve(OsStr::new("report.json"))?;
        slot.write_json_atomic(&serde_json::json!({"ok": true}), 1024)?;
        assert_eq!(
            std::fs::metadata(slot.path())?.permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(slot.read_bounded(1024)?, b"{\n  \"ok\": true\n}\n");
        assert!(slot.write_bytes_atomic(&[0; 9], 8).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn assert_no_secure_transient_entries(root: &Path) -> Result<()> {
        let names = std::fs::read_dir(root)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        assert!(names
            .iter()
            .all(|name| !name.to_string_lossy().starts_with(".maco-secure-")));
        Ok(())
    }
}
