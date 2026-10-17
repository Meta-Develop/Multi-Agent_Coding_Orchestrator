//! Linux-only executable identity capture and sealed execution preparation.
//!
//! The process runner owns the eventual hidden-helper and containment wiring.
//! This module deliberately separates all validation and materialization from
//! the irreversible `exec` operation so the trust boundary can be tested in
//! ordinary unit tests.

use std::{
    env,
    ffi::{CString, OsStr, OsString},
    fmt,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::{
    fs,
    fs::OpenOptions,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
};

#[cfg(not(target_os = "linux"))]
type RawFd = i32;

pub(crate) const PINNED_EXEC_REQUEST_VERSION: u8 = 1;
pub(crate) const HIDDEN_PINNED_EXEC_ARGUMENT: &str = "--maco-internal-pinned-exec-v1";
pub(crate) const PINNED_EXEC_DESCRIPTOR_NAME: &str = "pinned-exec-request-v1";
// v1 remains byte-identical for implicit-current-helper callers. v2 adds the
// source-bound main helper to the same digest-protected request.
const SOURCE_BOUND_REQUEST_VERSION: u8 = 2;
const SOURCE_BOUND_HELPER_ARGUMENT: &str = "--maco-internal-source-bound-pinned-exec-v1";
// Unprivileged FD execution only. This mode cannot attest host-root provenance.
pub(crate) const SEALED_NATIVE_HELPER_ARGUMENT: &str = "--maco-internal-sealed-native-exec-v1";
const REQUEST_MAGIC: &[u8] = b"MACO-PINNED-EXEC\0";
const SHA256_BYTES: usize = 32;
const SHA256_HEX_BYTES: usize = SHA256_BYTES * 2;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EXECUTABLE_PATH_BYTES: usize = 4096;
const MAX_SHEBANG_BYTES: usize = 256;
const MAX_PINNED_ARGUMENTS: usize = 256;
const MAX_PINNED_ARGUMENT_BYTES: usize = 32 * 1024;
const MAX_PINNED_ARGUMENT_TOTAL_BYTES: usize = 256 * 1024;
const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PinnedDirectExecutable {
    source: ExecutableBinding,
    script: Option<ScriptBinding>,
    main_helper: Option<SourceBoundMainHelper>,
}

/// A reviewed main binary from the same frozen source as its controller. The
/// binary digest is supplied by the independent package receipt; it is never
/// inferred from a name, version label, PATH, or the test controller.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SourceBoundMainHelper {
    executable: ExecutableBinding,
    source_sha256: [u8; SHA256_BYTES],
    package: MainHelperPackageIdentity,
}

#[derive(Clone, PartialEq, Eq)]
struct MainHelperPackageIdentity {
    declaration_identity: [u64; 4],
    declaration_sha256: [u8; SHA256_BYTES],
    manifest_identity: [u64; 4],
}

// Decoded data is image continuity, never a parent capability. In particular,
// canonical wire + a self-computed digest cannot construct SourceBoundMainHelper.
#[derive(Clone, PartialEq, Eq)]
struct MainHelperImageBinding {
    executable: ExecutableBinding,
    source_sha256: [u8; SHA256_BYTES],
    package: MainHelperPackageIdentity,
}

impl MainHelperImageBinding {
    #[cfg(target_os = "linux")]
    fn revalidate(&self) -> io::Result<PathBuf> {
        let path = PathBuf::from(OsString::from_vec(self.executable.path.clone()));
        let actual = SourceBoundMainHelper::capture_packaged(&path)?;
        if actual.executable != self.executable
            || actual.source_sha256 != self.source_sha256
            || actual.package != self.package
        {
            return Err(invalid_data("main helper image continuity changed"));
        }
        Ok(path)
    }

    #[cfg(target_os = "linux")]
    fn validate_current(&self) -> io::Result<()> {
        // Legacy v2 still performs the original strict root/package/loaded-image
        // validation. It does not promote this decoded snapshot into authority.
        let path = self.revalidate()?;
        let actual = SourceBoundMainHelper::capture_packaged(&path)?;
        actual.validate_current()?;
        if actual.executable != self.executable
            || actual.source_sha256 != self.source_sha256
            || actual.package != self.package
        {
            return Err(invalid_data("main helper image continuity changed"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct HeldProtectedObject {
    path: PathBuf,
    file: File,
    identity: [u64; 5],
    directory: bool,
}

#[cfg(target_os = "linux")]
struct HostRootCustody {
    namespace: File,
    namespace_identity: (u64, u64),
    objects: Vec<HeldProtectedObject>,
}

#[cfg(target_os = "linux")]
impl HostRootCustody {
    fn capture(helper: &SourceBoundMainHelper) -> io::Result<Self> {
        validate_controller_root_namespace()?;
        // This kernel magic link is intentional; it is not a caller path.
        let namespace = File::open("/proc/self/ns/user")?;
        let namespace_identity = metadata_identity(&namespace.metadata()?);
        let executable = PathBuf::from(OsString::from_vec(helper.executable.path.clone()));
        let prefix = executable
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| invalid_input("main helper package omitted its prefix"))?;
        let paths = [
            executable.clone(),
            prefix.join("share/maco/main-helper.json"),
            prefix.join("share/maco/source-manifest.json"),
        ];
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        let mut objects = vec![held_protected_object(PathBuf::from("/"), root, true)?];
        for path in paths {
            let components = path.components().skip(1).collect::<Vec<_>>();
            let mut parent = 0;
            let mut current = PathBuf::from("/");
            for (index, component) in components.iter().enumerate() {
                let std::path::Component::Normal(name) = component else {
                    return Err(invalid_input("protected package path was not normalized"));
                };
                current.push(name);
                if let Some(existing) = objects.iter().position(|entry| entry.path == current) {
                    parent = existing;
                    continue;
                }
                let directory = index + 1 != components.len();
                let name = CString::new(name.as_bytes())
                    .map_err(|_| invalid_input("protected component contained NUL"))?;
                let flags = libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | if directory {
                        libc::O_PATH | libc::O_DIRECTORY
                    } else {
                        libc::O_RDONLY | libc::O_NONBLOCK
                    };
                // SAFETY: parent is a live held directory, name is one normal
                // NUL-terminated component; openat returns a new owned FD.
                let fd =
                    unsafe { libc::openat(objects[parent].file.as_raw_fd(), name.as_ptr(), flags) };
                if fd < 0 {
                    return Err(opaque_last_os_error(
                        "could not hold protected package component",
                    ));
                }
                // SAFETY: successful openat returned a new descriptor owned here.
                let file = unsafe { File::from_raw_fd(fd) };
                objects.push(held_protected_object(current.clone(), file, directory)?);
                parent = objects.len() - 1;
            }
        }
        let custody = Self {
            namespace,
            namespace_identity,
            objects,
        };
        custody.revalidate()?;
        helper.revalidate()?;
        Ok(custody)
    }

    fn revalidate(&self) -> io::Result<()> {
        validate_controller_root_namespace()?;
        if metadata_identity(&self.namespace.metadata()?) != self.namespace_identity
            || metadata_identity(&fs::metadata("/proc/self/ns/user")?) != self.namespace_identity
        {
            return Err(invalid_data("controller user namespace changed"));
        }
        for entry in &self.objects {
            let held = entry.file.metadata()?;
            let named = fs::symlink_metadata(&entry.path)?;
            if protected_object_identity(&held, entry.directory) != entry.identity
                || protected_object_identity(&named, entry.directory) != entry.identity
                || !protected_object_allowed(&entry.path, &held, entry.directory)
                || !protected_object_allowed(&entry.path, &named, entry.directory)
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "held protected package identity changed",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn protected_object_identity(metadata: &fs::Metadata, directory: bool) -> [u64; 5] {
    [
        metadata.dev(),
        metadata.ino(),
        u64::from(permission_mode(metadata)),
        u64::from(metadata.uid()),
        if directory { 0 } else { metadata.len() },
    ]
}

#[cfg(target_os = "linux")]
fn protected_object_allowed(path: &Path, metadata: &fs::Metadata, directory: bool) -> bool {
    if path == Path::new("/nix/store") {
        return source_bound_store_anchor_allowed(
            metadata.uid(),
            permission_mode(metadata),
            metadata.is_dir(),
            metadata.file_type().is_symlink(),
        );
    }
    metadata.uid() == 0
        && !metadata.file_type().is_symlink()
        && permission_mode(metadata) & 0o022 == 0
        && if directory {
            metadata.is_dir()
        } else {
            metadata.is_file() && permission_mode(metadata) & 0o6000 == 0
        }
}

#[cfg(target_os = "linux")]
fn held_protected_object(
    path: PathBuf,
    file: File,
    directory: bool,
) -> io::Result<HeldProtectedObject> {
    let metadata = file.metadata()?;
    if !protected_object_allowed(&path, &metadata, directory) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "protected package object was not host-root owned and immutable",
        ));
    }
    Ok(HeldProtectedObject {
        identity: protected_object_identity(&metadata, directory),
        path,
        file,
        directory,
    })
}

#[cfg(target_os = "linux")]
fn controller_has_full_identity_map(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut lines = text.lines();
    let Some(line) = lines.next() else {
        return false;
    };
    if lines.next().is_some() {
        return false;
    }
    let fields = line.split_whitespace().collect::<Vec<_>>();
    fields.len() == 3 && fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295"
}

#[cfg(target_os = "linux")]
fn open_controller_proc_entry(
    root: &File,
    path: &std::ffi::CStr,
    flags: libc::c_int,
) -> io::Result<File> {
    // Linux openat2 UAPI: three u64 fields, with no extension or creation mode.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        // NO_XDEV includes same-filesystem bind mounts. Keep the magic-link
        // restriction explicit; BENEATH alone is not its lasting contract.
        resolve: 0x01 | 0x02 | 0x04 | 0x08,
    };
    // SAFETY: root owns the directory FD; path and the initialized C-layout
    // structure remain live for this synchronous kernel lookup.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            std::ptr::from_ref(&how),
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        // Unsupported, blocked, raced or substituted lookups all refuse. There
        // is deliberately no open/openat fallback or weakened resolve retry.
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat2 returned a new descriptor owned here.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

#[cfg(target_os = "linux")]
fn validate_controller_proc_root(root: &File) -> io::Result<()> {
    let metadata = root.metadata()?;
    // SAFETY: statfs is plain C storage; fstatfs initializes it through a valid
    // writable pointer while root owns the borrowed descriptor.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(root.as_raw_fd(), &mut filesystem) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // PROC_ROOT_INO is 1; procfs creates this immutable root directory itself.
    // A proc PID directory, comm inode or ordinary directory is not an anchor.
    if !metadata.is_dir()
        || metadata.ino() != 1
        || metadata.uid() != 0
        || permission_mode(&metadata) & 0o022 != 0
        || filesystem.f_type != libc::PROC_SUPER_MAGIC
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "controller proc root was not a protected kernel procfs root",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_controller_uid_map(root: &File, expected_pid: u32) -> io::Result<File> {
    validate_controller_proc_root(root)?;
    // O_PATH|O_NOFOLLOW returns the final self link itself. No link or mount
    // is traversed; readlinkat on that held inode asks the kernel for its TGID
    // in this proc instance's PID namespace, not a caller-supplied wire PID.
    let subject = open_controller_proc_entry(root, c"self", libc::O_PATH)?;
    if !subject.metadata()?.file_type().is_symlink() {
        return Err(invalid_data("controller proc self was not the kernel link"));
    }
    let mut target = [0_u8; 32];
    // SAFETY: subject is the held final symlink; empty-path readlinkat reads
    // that descriptor and target is a live, bounded writable buffer.
    let count = unsafe {
        libc::syscall(
            libc::SYS_readlinkat,
            subject.as_raw_fd(),
            c"".as_ptr(),
            target.as_mut_ptr().cast::<libc::c_char>(),
            target.len(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let expected = expected_pid.to_string();
    if count as usize != expected.len() || &target[..count as usize] != expected.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "controller proc subject did not match the current syscall PID",
        ));
    }
    let path = CString::new(format!("{expected}/uid_map"))
        .map_err(|_| invalid_input("controller proc subject was not a decimal PID"))?;
    let file = open_controller_proc_entry(root, &path, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.dev() != root.metadata()?.dev() {
        return Err(invalid_data("controller UID map was not its procfs file"));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn validate_controller_root_namespace() -> io::Result<()> {
    // The trusted root anchor and protected self lookup bind the fixed map
    // inode to this actual task even with an inherited ancestor proc mount.
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/proc")?;
    // SAFETY: getpid is a read-only syscall with no pointer arguments. Use the
    // direct syscall, as with readlinkat above, without a libc path fallback.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    let pid = u32::try_from(pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| invalid_data("controller syscall PID was invalid"))?;
    let mut file = open_controller_uid_map(&root, pid)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(257).read_to_end(&mut bytes)?;
    if bytes.len() > 256 || !controller_has_full_identity_map(&bytes) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sealed native authority requires the outside host-root UID context",
        ));
    }
    Ok(())
}

/// Parent-only custody. No decoder/raw-FD constructor or wire representation.
#[cfg(target_os = "linux")]
pub(crate) struct PreparedNativeEntry {
    helper: SourceBoundMainHelper,
    custody: HostRootCustody,
    image: SealedExecutable,
}

#[cfg(target_os = "linux")]
impl PartialEq for PreparedNativeEntry {
    fn eq(&self, other: &Self) -> bool {
        // Equality of cloned custody is identity of the issued capability,
        // never equality of a reconstructible wire snapshot or FD number.
        std::ptr::eq(self, other)
    }
}
#[cfg(target_os = "linux")]
impl Eq for PreparedNativeEntry {}

#[cfg(target_os = "linux")]
impl PreparedNativeEntry {
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        self.custody.revalidate()?;
        self.helper.revalidate()?;
        validate_native_seals(&self.image.file, self.image.length)?;
        Ok(())
    }

    pub(crate) fn relay_file(&self) -> io::Result<File> {
        self.revalidate()?;
        self.image.file.try_clone()
    }
}

#[cfg(target_os = "linux")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MainHelperDeclaration {
    schema: String,
    binary_sha256: String,
    source_manifest_sha256: String,
    main_entry_sha256: String,
}

impl fmt::Debug for SourceBoundMainHelper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceBoundMainHelper(<redacted binding>)")
    }
}

impl SourceBoundMainHelper {
    /// Explicit qualification input: the supplied digests must also match the
    /// protected package declaration and actual manifest bytes.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn capture(
        path: &Path,
        binary_sha256: &str,
        source_sha256: &str,
    ) -> io::Result<Self> {
        let expected_binary = decode_sha256_hex(binary_sha256.as_bytes())?;
        let expected_source = decode_sha256_hex(source_sha256.as_bytes())?;
        let helper = Self::capture_packaged(path)?;
        if !constant_time_eq(&helper.executable.sha256, &expected_binary)
            || !constant_time_eq(&helper.source_sha256, &expected_source)
        {
            return Err(invalid_data(
                "source-bound main helper did not match its qualification receipt",
            ));
        }
        Ok(helper)
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn capture_qualification_environment() -> io::Result<Self> {
        let path = env::var_os("MACO_CURSOR_MAIN_HELPER_FOR_TEST")
            .ok_or_else(|| invalid_input("qualification omitted its packaged main helper"))?;
        let binary = env::var("MACO_CURSOR_MAIN_HELPER_SHA256_FOR_TEST")
            .map_err(|_| invalid_input("qualification omitted its reviewed main binary digest"))?;
        let source = env::var("MACO_CURSOR_MAIN_HELPER_SOURCE_SHA256_FOR_TEST")
            .map_err(|_| invalid_input("qualification omitted its frozen main source digest"))?;
        Self::capture(Path::new(&path), &binary, &source)
    }

    /// Normal production invocation derives the exact package from the loaded
    /// main. No PATH search, ambient configuration or libtest fallback occurs.
    #[cfg(target_os = "linux")]
    pub(crate) fn capture_current_packaged() -> io::Result<Self> {
        let current = env::current_exe()
            .map_err(|error| opaque_io(error, "could not resolve the source-bound main helper"))?;
        let helper = Self::capture_packaged(&current)?;
        helper.validate_loaded_image()?;
        Ok(helper)
    }

    #[cfg(target_os = "linux")]
    fn capture_packaged(path: &Path) -> io::Result<Self> {
        validate_source_bound_helper_path(path)?;
        let prefix = path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| invalid_input("source-bound main helper omitted its package"))?;
        let declaration_path = prefix.join("share/maco/main-helper.json");
        let manifest_path = prefix.join("share/maco/source-manifest.json");
        let (declaration_bytes, declaration_identity) =
            read_helper_package_file(&declaration_path)?;
        let declaration = validate_main_helper_declaration(&declaration_bytes)?;
        let source_sha256 = decode_sha256_hex(declaration.source_manifest_sha256.as_bytes())?;
        validate_compiled_source_binding(&source_sha256)?;
        let (manifest_bytes, manifest_identity) = read_helper_package_file(&manifest_path)?;
        if !constant_time_eq(&sha256(&manifest_bytes)?, &source_sha256) {
            return Err(invalid_data(
                "main helper manifest bytes did not match its declaration",
            ));
        }
        let expected_binary = decode_sha256_hex(declaration.binary_sha256.as_bytes())?;
        let (executable, prefix_bytes) = capture_executable_binding(path)?;
        if executable.path != executable.argv0
            || !prefix_bytes.starts_with(b"\x7fELF")
            || !constant_time_eq(&executable.sha256, &expected_binary)
        {
            return Err(invalid_data(
                "source-bound main helper binary did not match its package",
            ));
        }
        validate_source_bound_helper_path(path)?;
        Ok(Self {
            executable,
            source_sha256,
            package: MainHelperPackageIdentity {
                declaration_identity,
                declaration_sha256: sha256(&declaration_bytes)?,
                manifest_identity,
            },
        })
    }

    #[cfg(target_os = "linux")]
    fn revalidate(&self) -> io::Result<PathBuf> {
        let path = PathBuf::from(OsString::from_vec(self.executable.path.clone()));
        let current = Self::capture_packaged(&path)?;
        if current != *self {
            return Err(invalid_data(
                "source-bound main helper or package identity changed",
            ));
        }
        Ok(path)
    }

    #[cfg(target_os = "linux")]
    fn validate_current(&self) -> io::Result<()> {
        self.validate_loaded_image()?;
        self.revalidate().map(|_| ())
    }

    #[cfg(target_os = "linux")]
    fn validate_loaded_image(&self) -> io::Result<()> {
        let current = env::current_exe()
            .map_err(|error| opaque_io(error, "could not resolve the source-bound main helper"))?;
        if current.as_os_str().as_bytes() != self.executable.path {
            return Err(invalid_data("source-bound main helper invocation changed"));
        }
        // /proc/self/exe is the kernel's loaded-image identity, not a filesystem
        // helper alias. A renamed/replaced main must not bind its replacement.
        let loaded = fs::metadata("/proc/self/exe")
            .map_err(|error| opaque_io(error, "could not inspect the loaded main helper"))?;
        if loaded.uid() != 0
            || metadata_identity(&loaded) != (self.executable.device, self.executable.inode)
            || permission_mode(&loaded) != self.executable.mode
            || loaded.len() != self.executable.length
        {
            return Err(invalid_data(
                "loaded main helper identity did not match its package",
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn validate_main_helper_declaration(bytes: &[u8]) -> io::Result<MainHelperDeclaration> {
    let declaration: MainHelperDeclaration = serde_json::from_slice(bytes)
        .map_err(|_| invalid_data("main helper package declaration was malformed"))?;
    if declaration.schema != "maco-source-bound-main-helper-v1" {
        return Err(invalid_data(
            "main helper package declaration schema was unsupported",
        ));
    }
    decode_sha256_hex(declaration.binary_sha256.as_bytes())?;
    decode_sha256_hex(declaration.source_manifest_sha256.as_bytes())?;
    let entry_digest = decode_sha256_hex(declaration.main_entry_sha256.as_bytes())?;
    if !constant_time_eq(&entry_digest, &sha256(include_bytes!("bin/maco.rs"))?) {
        return Err(invalid_data(
            "main helper entry source did not match its controller",
        ));
    }
    Ok(declaration)
}

#[cfg(target_os = "linux")]
fn helper_package_file_identity(metadata: &fs::Metadata) -> [u64; 4] {
    [
        metadata.dev(),
        metadata.ino(),
        u64::from(permission_mode(metadata)),
        metadata.len(),
    ]
}

#[cfg(target_os = "linux")]
fn read_helper_package_file(path: &Path) -> io::Result<(Vec<u8>, [u64; 4])> {
    validate_source_bound_package_path(path, false)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| opaque_io(error, "could not open main helper package metadata"))?;
    let before = file
        .metadata()
        .map_err(|error| opaque_io(error, "could not inspect main helper package metadata"))?;
    if !before.is_file()
        || before.uid() != 0
        || permission_mode(&before) & 0o6022 != 0
        || before.len() == 0
        || before.len() > MAX_DESCRIPTOR_BYTES as u64
    {
        return Err(invalid_data(
            "main helper package metadata was not immutable and bounded",
        ));
    }
    let identity = helper_package_file_identity(&before);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_DESCRIPTOR_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| opaque_io(error, "could not read main helper package metadata"))?;
    let after = file
        .metadata()
        .map_err(|error| opaque_io(error, "could not re-inspect main helper package metadata"))?;
    let named = fs::symlink_metadata(path)
        .map_err(|error| opaque_io(error, "could not re-inspect main helper package path"))?;
    if after.uid() != 0
        || named.uid() != 0
        || named.file_type().is_symlink()
        || helper_package_file_identity(&after) != identity
        || helper_package_file_identity(&named) != identity
        || bytes.len() as u64 != before.len()
        || bytes.len() > MAX_DESCRIPTOR_BYTES
    {
        return Err(invalid_data(
            "main helper package metadata changed during capture",
        ));
    }
    validate_source_bound_package_path(path, false)?;
    Ok((bytes, identity))
}

#[cfg(target_os = "linux")]
fn validate_compiled_source_binding(expected: &[u8; SHA256_BYTES]) -> io::Result<()> {
    validate_source_binding(expected, option_env!("MACO_SOURCE_MANIFEST_SHA256"))
}

#[cfg(target_os = "linux")]
fn validate_source_binding(
    expected: &[u8; SHA256_BYTES],
    compiled: Option<&str>,
) -> io::Result<()> {
    let compiled =
        compiled.ok_or_else(|| invalid_data("main helper source binding is unavailable"))?;
    let actual = decode_sha256_hex(compiled.as_bytes())?;
    if !constant_time_eq(expected, &actual) {
        return Err(invalid_data(
            "main helper source binding did not match its controller",
        ));
    }
    Ok(())
}

impl fmt::Debug for PinnedDirectExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedDirectExecutable")
            .field(
                "kind",
                &if self.script.is_some() {
                    "script"
                } else {
                    "native"
                },
            )
            .field("source", &"<redacted binding>")
            .field(
                "interpreter",
                &self.script.as_ref().map(|_| "<redacted binding>"),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ScriptBinding {
    interpreter: ExecutableBinding,
    interpreter_argument: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExecutableBinding {
    path: Vec<u8>,
    argv0: Vec<u8>,
    device: u64,
    inode: u64,
    mode: u32,
    length: u64,
    sha256: [u8; SHA256_BYTES],
}

impl fmt::Debug for ExecutableBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableBinding")
            .field("path", &"<redacted>")
            .field("identity", &"<redacted>")
            .field("length", &self.length)
            .field("sha256", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EncodedPinnedExecDescriptor {
    bytes: Vec<u8>,
    digest: [u8; SHA256_BYTES],
}

impl fmt::Debug for EncodedPinnedExecDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedPinnedExecDescriptor")
            .field(
                "bytes",
                &format_args!("<redacted:{} bytes>", self.bytes.len()),
            )
            .field("digest", &"<redacted>")
            .finish()
    }
}

impl EncodedPinnedExecDescriptor {
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[cfg(test)]
    pub(crate) fn digest_hex(&self) -> String {
        hex_encode(&self.digest)
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, String) {
        let digest = hex_encode(&self.digest);
        (self.bytes, digest)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPinnedExecRequest {
    source: ExecutableBinding,
    script: Option<ScriptBinding>,
    arguments: Vec<Vec<u8>>,
    environment: Vec<(Vec<u8>, Vec<u8>)>,
    main_helper: Option<MainHelperImageBinding>,
}

impl fmt::Debug for VerifiedPinnedExecRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedPinnedExecRequest")
            .field(
                "kind",
                &if self.script.is_some() {
                    "script"
                } else {
                    "native"
                },
            )
            .field(
                "arguments",
                &format_args!("<redacted:{} entries>", self.arguments.len()),
            )
            .field(
                "environment",
                &format_args!("<redacted:{} entries>", self.environment.len()),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecDescriptorPolicy {
    CloseOnExec,
    RetainForScriptPath,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PreparedPinnedExecPlan {
    executable: ExecutableBinding,
    argv: Vec<Vec<u8>>,
    script: Option<ExecutableBinding>,
    script_descriptor_policy: ExecDescriptorPolicy,
}

impl fmt::Debug for PreparedPinnedExecPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPinnedExecPlan")
            .field("executable", &"<redacted binding>")
            .field(
                "argv",
                &format_args!("<redacted:{} entries>", self.argv.len()),
            )
            .field(
                "script",
                &self.script.as_ref().map(|_| "<redacted binding>"),
            )
            .field("script_descriptor_policy", &self.script_descriptor_policy)
            .finish()
    }
}

impl PreparedPinnedExecPlan {
    pub(crate) fn executable(&self) -> &ExecutableBinding {
        &self.executable
    }

    pub(crate) fn argv(&self) -> &[Vec<u8>] {
        &self.argv
    }

    #[cfg(test)]
    pub(crate) fn script(&self) -> Option<&ExecutableBinding> {
        self.script.as_ref()
    }

    pub(crate) const fn script_descriptor_policy(&self) -> ExecDescriptorPolicy {
        self.script_descriptor_policy
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct SealedExecutable {
    file: File,
    length: u64,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for SealedExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedExecutable")
            .field("fd", &self.file.as_raw_fd())
            .field("length", &self.length)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl SealedExecutable {
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub(crate) fn set_close_on_exec(&self, close_on_exec: bool) -> io::Result<()> {
        let fd = self.file.as_raw_fd();
        // SAFETY: F_GETFD only reads descriptor flags from the live descriptor owned by `self`.
        let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if current < 0 {
            return Err(opaque_last_os_error(
                "could not inspect sealed descriptor flags",
            ));
        }
        let next = if close_on_exec {
            current | libc::FD_CLOEXEC
        } else {
            current & !libc::FD_CLOEXEC
        };
        // SAFETY: F_SETFD changes only descriptor flags for the live descriptor owned by `self`.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
            return Err(opaque_last_os_error(
                "could not update sealed descriptor flags",
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl PinnedDirectExecutable {
    // Kept crate-internal until a safety-sensitive caller opts into this capability.
    #[allow(dead_code)]
    pub(crate) fn capture(path: &Path) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            validated_current_helper_path()?;
            Self::capture_source(path)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(unsupported())
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn capture_source(path: &Path) -> io::Result<Self> {
        let (source, prefix) = capture_executable_binding(path)?;
        let script = match parse_shebang(&prefix)? {
            None => None,
            Some(shebang) => {
                let interpreter_path = PathBuf::from(OsString::from_vec(shebang.path));
                let (interpreter, interpreter_prefix) =
                    capture_executable_binding(&interpreter_path)?;
                reject_dispatching_interpreter(&interpreter)?;
                if interpreter_prefix.starts_with(b"#!") {
                    return Err(invalid_data(
                        "script interpreters must be native executables",
                    ));
                }
                Some(ScriptBinding {
                    interpreter,
                    interpreter_argument: shebang.argument,
                })
            }
        };
        Ok(Self {
            source,
            script,
            main_helper: None,
        })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn capture_for_test(path: &Path) -> io::Result<Self> {
        Self::capture_source(path)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn capture_with_main_helper(
        path: &Path,
        helper: SourceBoundMainHelper,
    ) -> io::Result<Self> {
        helper.revalidate()?;
        let mut pinned = Self::capture_source(path)?;
        pinned.main_helper = Some(helper);
        Ok(pinned)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare_native_entry(
        &self,
        checkpoint: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Option<PreparedNativeEntry>> {
        let Some(helper) = &self.main_helper else {
            return Ok(None);
        };
        if self.script.is_some() {
            return Ok(None);
        }
        checkpoint()?;
        helper.revalidate()?;
        let custody = HostRootCustody::capture(helper)?;
        checkpoint()?;
        let image = materialize_sealed_checked(&self.source, checkpoint)?;
        validate_native_seals(&image.file, self.source.length)?;
        let prepared = PreparedNativeEntry {
            helper: helper.clone(),
            custody,
            image,
        };
        prepared.revalidate()?;
        checkpoint()?;
        Ok(Some(prepared))
    }

    pub(crate) fn validated_launch_helper_path(&self) -> io::Result<PathBuf> {
        #[cfg(target_os = "linux")]
        if let Some(helper) = &self.main_helper {
            return helper.revalidate();
        }
        validated_current_helper_path()
    }

    pub(crate) fn hidden_helper_argument(&self) -> &'static str {
        if self.main_helper.is_some() {
            SOURCE_BOUND_HELPER_ARGUMENT
        } else {
            HIDDEN_PINNED_EXEC_ARGUMENT
        }
    }

    pub(crate) fn matches_program(&self, program: &Path) -> io::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            Ok(program.as_os_str().as_bytes() == self.source.argv0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = program;
            Err(unsupported())
        }
    }

    pub(crate) fn encode_descriptor(
        &self,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
    ) -> io::Result<EncodedPinnedExecDescriptor> {
        #[cfg(target_os = "linux")]
        {
            let arguments = validate_and_copy_arguments(arguments)?;
            let mut bytes = Vec::with_capacity(512);
            bytes.extend_from_slice(REQUEST_MAGIC);
            bytes.push(if self.main_helper.is_some() {
                SOURCE_BOUND_REQUEST_VERSION
            } else {
                PINNED_EXEC_REQUEST_VERSION
            });
            encode_binding(&mut bytes, &self.source)?;
            match &self.script {
                Some(script) => {
                    bytes.push(1);
                    encode_binding(&mut bytes, &script.interpreter)?;
                    encode_optional_bytes(&mut bytes, script.interpreter_argument.as_deref())?;
                }
                None => bytes.push(0),
            }
            write_u32(&mut bytes, arguments.len(), "argument count")?;
            for argument in &arguments {
                write_bounded_bytes(&mut bytes, argument, "argument")?;
            }
            let environment = validate_and_copy_environment(environment)?;
            write_u32(&mut bytes, environment.len(), "environment count")?;
            for (name, value) in &environment {
                write_bounded_bytes(&mut bytes, name, "environment name")?;
                write_bytes_allow_empty(&mut bytes, value)?;
            }
            if let Some(helper) = &self.main_helper {
                helper.revalidate()?;
                encode_binding(&mut bytes, &helper.executable)?;
                bytes.extend_from_slice(&helper.source_sha256);
                for value in helper.package.declaration_identity {
                    bytes.extend_from_slice(&value.to_be_bytes());
                }
                bytes.extend_from_slice(&helper.package.declaration_sha256);
                for value in helper.package.manifest_identity {
                    bytes.extend_from_slice(&value.to_be_bytes());
                }
            }
            if bytes.len() > MAX_DESCRIPTOR_BYTES {
                return Err(file_too_large(
                    "pinned executable descriptor exceeded its bound",
                ));
            }
            let digest = sha256(&bytes)?;
            Ok(EncodedPinnedExecDescriptor { bytes, digest })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (arguments, environment);
            Err(unsupported())
        }
    }
}

pub(crate) fn validate_helper_path(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        validate_helper_path_from_anchor(path, Path::new("/"), 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(unsupported())
    }
}

pub(crate) fn validated_current_helper_path() -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let current = env::current_exe()
            .map_err(|error| opaque_io(error, "could not resolve the current pinned helper"))?;
        validate_helper_path(&current)?;
        Ok(current)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(unsupported())
    }
}

pub(crate) fn validate_descriptor_digest(descriptor: &[u8], digest: &OsStr) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if descriptor.len() > MAX_DESCRIPTOR_BYTES {
            return Err(file_too_large(
                "pinned executable descriptor exceeded its bound",
            ));
        }
        let expected = decode_sha256_hex(digest.as_bytes())?;
        let actual = sha256(descriptor)?;
        if !constant_time_eq(&actual, &expected) {
            return Err(invalid_data(
                "pinned executable descriptor digest did not match",
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (descriptor, digest);
        Err(unsupported())
    }
}

pub(crate) fn decode_verified_descriptor(
    descriptor: &[u8],
    digest: &OsStr,
) -> io::Result<VerifiedPinnedExecRequest> {
    validate_descriptor_digest(descriptor, digest)?;
    #[cfg(target_os = "linux")]
    {
        let mut cursor = DescriptorCursor::new(descriptor);
        cursor.require_exact(REQUEST_MAGIC)?;
        let version = cursor.read_u8()?;
        if !matches!(
            version,
            PINNED_EXEC_REQUEST_VERSION | SOURCE_BOUND_REQUEST_VERSION
        ) {
            return Err(invalid_data(
                "unsupported pinned executable descriptor version",
            ));
        }
        let source = decode_binding(&mut cursor)?;
        let script = match cursor.read_u8()? {
            0 => None,
            1 => Some(ScriptBinding {
                interpreter: decode_binding(&mut cursor)?,
                interpreter_argument: decode_optional_bytes(&mut cursor)?,
            }),
            _ => return Err(invalid_data("invalid pinned executable descriptor kind")),
        };
        let count = usize::try_from(cursor.read_u32()?)
            .map_err(|_| invalid_data("pinned executable argument count overflow"))?;
        if count > MAX_PINNED_ARGUMENTS {
            return Err(invalid_data(
                "pinned executable argument count exceeded its bound",
            ));
        }
        let mut arguments = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            let argument = cursor.read_bounded_bytes(MAX_PINNED_ARGUMENT_BYTES)?;
            validate_argument_bytes(&argument)?;
            total = total
                .checked_add(argument.len())
                .ok_or_else(|| invalid_data("pinned executable argument size overflow"))?;
            arguments.push(argument);
        }
        if total > MAX_PINNED_ARGUMENT_TOTAL_BYTES {
            return Err(invalid_data(
                "pinned executable arguments exceeded their aggregate bound",
            ));
        }
        let environment_count = usize::try_from(cursor.read_u32()?)
            .map_err(|_| invalid_data("pinned executable environment count overflow"))?;
        if environment_count > 256 {
            return Err(invalid_data(
                "pinned executable environment count exceeded its bound",
            ));
        }
        let mut environment = Vec::with_capacity(environment_count);
        let mut environment_total = 0usize;
        let mut previous_name: Option<Vec<u8>> = None;
        for _ in 0..environment_count {
            let name = cursor.read_bounded_bytes(256)?;
            let value = cursor.read_bytes_allow_empty(1024 * 1024)?;
            validate_environment_entry(&name, &value)?;
            if previous_name
                .as_ref()
                .is_some_and(|previous| previous >= &name)
            {
                return Err(invalid_data(
                    "pinned executable environment was not canonically ordered",
                ));
            }
            environment_total = environment_total
                .checked_add(name.len())
                .and_then(|total| total.checked_add(value.len()))
                .ok_or_else(|| invalid_data("pinned executable environment size overflow"))?;
            previous_name = Some(name.clone());
            environment.push((name, value));
        }
        if environment_total > 4 * 1024 * 1024 {
            return Err(invalid_data(
                "pinned executable environment exceeded its aggregate bound",
            ));
        }
        let main_helper = if version == SOURCE_BOUND_REQUEST_VERSION {
            let executable = decode_binding(&mut cursor)?;
            validate_binding(&executable)?;
            let source_sha256 = cursor.read_array()?;
            let mut declaration_identity = [0u64; 4];
            for value in &mut declaration_identity {
                *value = cursor.read_u64()?;
            }
            let declaration_sha256 = cursor.read_array()?;
            let mut manifest_identity = [0u64; 4];
            for value in &mut manifest_identity {
                *value = cursor.read_u64()?;
            }
            Some(MainHelperImageBinding {
                executable,
                source_sha256,
                package: MainHelperPackageIdentity {
                    declaration_identity,
                    declaration_sha256,
                    manifest_identity,
                },
            })
        } else {
            None
        };
        cursor.require_end()?;
        validate_binding(&source)?;
        if let Some(script) = &script {
            validate_binding(&script.interpreter)?;
            if let Some(argument) = &script.interpreter_argument {
                validate_argument_bytes(argument)?;
            }
        }
        Ok(VerifiedPinnedExecRequest {
            source,
            script,
            arguments,
            environment,
            main_helper,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = descriptor;
        Err(unsupported())
    }
}

/// Dispatches the reserved helper mode before CLI parsing or runtime initialization.
///
/// A successful helper execution replaces the current process and never returns. `false` means
/// the reserved marker was not present and normal CLI startup should continue.
pub(crate) fn maybe_run_helper_from_args() -> io::Result<bool> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(marker) = arguments.next() else {
        return Ok(false);
    };
    let source_bound = marker == OsStr::new(SOURCE_BOUND_HELPER_ARGUMENT);
    let mechanical_native = marker == OsStr::new(SEALED_NATIVE_HELPER_ARGUMENT);
    if marker != OsStr::new(HIDDEN_PINNED_EXEC_ARGUMENT) && !source_bound && !mechanical_native {
        return Ok(false);
    }
    #[cfg(target_os = "linux")]
    {
        let descriptor_path = arguments
            .next()
            .ok_or_else(|| invalid_input("pinned helper omitted its descriptor path"))?;
        let digest = arguments
            .next()
            .ok_or_else(|| invalid_input("pinned helper omitted its descriptor digest"))?;
        if arguments.next().is_some() {
            return Err(invalid_input("pinned helper received unexpected arguments"));
        }
        if mechanical_native {
            validate_current_environment()?;
            let request =
                load_verified_descriptor_and_remove(Path::new(&descriptor_path), &digest)?;
            execute_mechanical_native(request)?;
            return Err(io::Error::other(
                "sealed native execution returned unexpectedly",
            ));
        }
        if source_bound {
            let current = env::current_exe().map_err(|error| {
                opaque_io(error, "could not resolve the source-bound main helper")
            })?;
            validate_source_bound_helper_path(&current)?;
        } else {
            validated_current_helper_path()?;
        }
        validate_current_environment()?;
        let request = load_verified_descriptor_and_remove(Path::new(&descriptor_path), &digest)?;
        request.validate_helper_mode(source_bound)?;
        execute_verified_request(request)?;
        Err(io::Error::other(
            "pinned helper execution returned unexpectedly",
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = arguments;
        Err(unsupported())
    }
}

impl VerifiedPinnedExecRequest {
    #[cfg(target_os = "linux")]
    fn validate_helper_mode(&self, source_bound: bool) -> io::Result<()> {
        if self.main_helper.is_some() != source_bound {
            return Err(invalid_data(
                "pinned helper mode did not match its descriptor",
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_exec_plan(&self, script_fd: RawFd) -> io::Result<PreparedPinnedExecPlan> {
        #[cfg(target_os = "linux")]
        {
            match &self.script {
                None => {
                    let mut argv = Vec::with_capacity(self.arguments.len().saturating_add(1));
                    argv.push(self.source.argv0.clone());
                    argv.extend(self.arguments.iter().cloned());
                    validate_exec_argv(&argv)?;
                    Ok(PreparedPinnedExecPlan {
                        executable: self.source.clone(),
                        argv,
                        script: None,
                        script_descriptor_policy: ExecDescriptorPolicy::CloseOnExec,
                    })
                }
                Some(script) => {
                    if script_fd < 0 {
                        return Err(invalid_input("script descriptor was invalid"));
                    }
                    let script_path = format!("/proc/self/fd/{script_fd}").into_bytes();
                    let mut argv = Vec::with_capacity(self.arguments.len().saturating_add(
                        if script.interpreter_argument.is_some() {
                            3
                        } else {
                            2
                        },
                    ));
                    argv.push(script.interpreter.argv0.clone());
                    if let Some(argument) = &script.interpreter_argument {
                        argv.push(argument.clone());
                    }
                    argv.push(script_path);
                    argv.extend(self.arguments.iter().cloned());
                    validate_exec_argv(&argv)?;
                    Ok(PreparedPinnedExecPlan {
                        executable: script.interpreter.clone(),
                        argv,
                        script: Some(self.source.clone()),
                        script_descriptor_policy: ExecDescriptorPolicy::RetainForScriptPath,
                    })
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = script_fd;
            Err(unsupported())
        }
    }
}

#[cfg(target_os = "linux")]
fn load_verified_descriptor_and_remove(
    path: &Path,
    digest: &OsStr,
) -> io::Result<VerifiedPinnedExecRequest> {
    let path_bytes = path.as_os_str().as_bytes();
    validate_path_bytes(path_bytes)?;
    if path.file_name() != Some(OsStr::new(PINNED_EXEC_DESCRIPTOR_NAME)) {
        return Err(invalid_input("pinned helper descriptor name was invalid"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| opaque_io(error, "could not open pinned helper descriptor"))?;
    let metadata = file
        .metadata()
        .map_err(|error| opaque_io(error, "could not inspect pinned helper descriptor"))?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != effective_uid
        || permission_mode(&metadata) != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_DESCRIPTOR_BYTES as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pinned helper descriptor identity or permissions were invalid",
        ));
    }
    let identity = (
        metadata.dev(),
        metadata.ino(),
        permission_mode(&metadata),
        metadata.len(),
    );
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| file_too_large("pinned helper descriptor exceeded its bound"))?,
    );
    Read::by_ref(&mut file)
        .take((MAX_DESCRIPTOR_BYTES as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| opaque_io(error, "could not read pinned helper descriptor"))?;
    let after = file
        .metadata()
        .map_err(|error| opaque_io(error, "could not re-inspect pinned helper descriptor"))?;
    let after_identity = (
        after.dev(),
        after.ino(),
        permission_mode(&after),
        after.len(),
    );
    let loaded = if bytes.len() > MAX_DESCRIPTOR_BYTES
        || u64::try_from(bytes.len()).ok() != Some(metadata.len())
        || after_identity != identity
    {
        Err(invalid_data(
            "pinned helper descriptor changed while being read",
        ))
    } else {
        decode_verified_descriptor(&bytes, digest)
    };
    let cleanup = remove_descriptor_if_identity_matches(path, identity);
    match (loaded, cleanup) {
        (Ok(request), Ok(())) => Ok(request),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn remove_descriptor_if_identity_matches(
    path: &Path,
    expected: (u64, u64, u32, u64),
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| opaque_io(error, "could not re-inspect pinned helper descriptor path"))?;
    let actual = (
        metadata.dev(),
        metadata.ino(),
        permission_mode(&metadata),
        metadata.len(),
    );
    if metadata.file_type().is_symlink() || actual != expected {
        return Err(invalid_data(
            "pinned helper descriptor path identity changed",
        ));
    }
    fs::remove_file(path)
        .map_err(|error| opaque_io(error, "could not remove consumed pinned helper descriptor"))
}

#[cfg(target_os = "linux")]
fn validate_current_environment() -> io::Result<()> {
    const MAX_ENTRIES: usize = 256;
    const MAX_KEY_BYTES: usize = 256;
    const MAX_VALUE_BYTES: usize = 1024 * 1024;
    const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;

    let mut count = 0usize;
    let mut total = 0usize;
    for (key, value) in env::vars_os() {
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid_input("pinned helper environment count overflow"))?;
        if count > MAX_ENTRIES {
            return Err(invalid_input(
                "pinned helper environment exceeded its entry bound",
            ));
        }
        let key = key.as_os_str().as_bytes();
        let value = value.as_os_str().as_bytes();
        if key.is_empty()
            || key.len() > MAX_KEY_BYTES
            || value.len() > MAX_VALUE_BYTES
            || key.contains(&0)
            || value.contains(&0)
            || key.iter().any(|byte| byte.is_ascii_control())
            || value.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(invalid_input(
                "pinned helper environment entry was malformed or oversized",
            ));
        }
        total = total
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| invalid_input("pinned helper environment size overflow"))?;
        if total > MAX_TOTAL_BYTES {
            return Err(invalid_input(
                "pinned helper environment exceeded its aggregate bound",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_native_seals(file: &File, length: u64) -> io::Result<()> {
    let metadata = file.metadata()?;
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: the live file is owned/borrowed for this read-only query.
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if !metadata.is_file()
        || metadata.len() != length
        || !(4..=MAX_EXECUTABLE_BYTES).contains(&length)
        || permission_mode(&metadata) != 0o500
        || seals < 0
        || seals & required != required
    {
        return Err(invalid_data(
            "native entry descriptor was not sealed and bounded",
        ));
    }
    use std::os::unix::fs::FileExt;
    let mut prefix = [0; 4];
    file.read_exact_at(&mut prefix, 0)?;
    if &prefix != b"\x7fELF" {
        return Err(invalid_data("native entry was not ELF"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn receive_native_image(
    request: &VerifiedPinnedExecRequest,
    fd: RawFd,
) -> io::Result<SealedExecutable> {
    if request.script.is_some() {
        return Err(invalid_input("mechanical native mode refuses scripts"));
    }
    // Duplicate before replacing fd0; the original guardian copies must close
    // on final exec too. A raw/sealed FD is execution data, not host authority.
    // SAFETY: fcntl duplicates the supplied FD or fails; no memory is accessed.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 5) };
    if duplicate < 0 {
        return Err(opaque_last_os_error(
            "could not retain native entry descriptor",
        ));
    }
    // SAFETY: the successful fcntl returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(duplicate) };
    validate_native_seals(&file, request.source.length)?;
    file.seek(SeekFrom::Start(0))?;
    let digest = hash_reader(&mut file, request.source.length)?;
    if !constant_time_eq(&digest, &request.source.sha256) {
        return Err(invalid_data(
            "native entry bytes did not match the exact request",
        ));
    }
    Ok(SealedExecutable {
        file,
        length: request.source.length,
    })
}

#[cfg(target_os = "linux")]
fn execute_mechanical_native(request: VerifiedPinnedExecRequest) -> io::Result<()> {
    let image = receive_native_image(&request, libc::STDIN_FILENO)?;
    let plan = request.prepare_exec_plan(-1)?;
    use std::os::unix::fs::FileTypeExt;
    let null = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/null")?;
    let metadata = null.metadata()?;
    if !metadata.file_type().is_char_device() || metadata.rdev() != libc::makedev(1, 3) {
        return Err(invalid_data("native target stdin was not the null device"));
    }
    // SAFETY: null is a live read handle; dup2 restores true Null stdin.
    if unsafe { libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO) } < 0 {
        return Err(opaque_last_os_error(
            "could not restore native target null stdin",
        ));
    }
    // Kernel close-on-exec covers the relayed stdin/fd4 image copies, owner FIFO,
    // descriptor-read handles and our retained image. No fallback leaks FDs.
    // SAFETY: close_range with CLOEXEC changes FD flags, not the open images.
    if unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) } != 0 {
        return Err(opaque_last_os_error(
            "could not seal native exec descriptor lifetime",
        ));
    }
    fexecve_sealed(&image, plan.argv(), &request.environment)
}

#[cfg(target_os = "linux")]
fn execute_verified_request(request: VerifiedPinnedExecRequest) -> io::Result<()> {
    if let Some(helper) = &request.main_helper {
        helper.validate_current()?;
    }
    match request.script.as_ref() {
        None => {
            let executable = materialize_sealed(&request.source)?;
            let plan = request.prepare_exec_plan(-1)?;
            debug_assert_eq!(
                plan.script_descriptor_policy(),
                ExecDescriptorPolicy::CloseOnExec
            );
            fexecve_sealed(&executable, plan.argv(), &request.environment)
        }
        Some(_) => {
            let script = materialize_sealed(&request.source)?;
            let plan = request.prepare_exec_plan(script.as_raw_fd())?;
            let interpreter = materialize_sealed(plan.executable())?;
            script.set_close_on_exec(false)?;
            debug_assert_eq!(
                plan.script_descriptor_policy(),
                ExecDescriptorPolicy::RetainForScriptPath
            );
            fexecve_sealed(&interpreter, plan.argv(), &request.environment)
        }
    }
}

#[cfg(target_os = "linux")]
fn fexecve_sealed(
    executable: &SealedExecutable,
    argv: &[Vec<u8>],
    environment: &[(Vec<u8>, Vec<u8>)],
) -> io::Result<()> {
    validate_exec_argv(argv)?;
    let cstrings = argv
        .iter()
        .map(|argument| {
            CString::new(argument.as_slice())
                .map_err(|_| invalid_input("prepared executable argv contained a NUL byte"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut pointers = cstrings
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    pointers.push(std::ptr::null());
    let environment_strings = environment
        .iter()
        .map(|(name, value)| {
            validate_environment_entry(name, value)?;
            let mut entry =
                Vec::with_capacity(name.len().saturating_add(value.len()).saturating_add(1));
            entry.extend_from_slice(name);
            entry.push(b'=');
            entry.extend_from_slice(value);
            CString::new(entry)
                .map_err(|_| invalid_input("prepared target environment contained a NUL byte"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut environment_pointers = environment_strings
        .iter()
        .map(|entry| entry.as_ptr())
        .collect::<Vec<_>>();
    environment_pointers.push(std::ptr::null());
    if environment_pointers.len() > 257 {
        return Err(invalid_input(
            "prepared target environment exceeded its entry bound",
        ));
    }
    // SAFETY: the sealed descriptor remains live for the call; `pointers` is a NUL-terminated
    // argv array backed by live CStrings; `environment_pointers` is a non-null, NUL-terminated
    // envp array backed by live CStrings, including when the authenticated environment is empty.
    let result = unsafe {
        libc::fexecve(
            executable.as_raw_fd(),
            pointers.as_ptr(),
            environment_pointers.as_ptr(),
        )
    };
    debug_assert_eq!(result, -1);
    Err(opaque_last_os_error(
        "could not execute the sealed executable",
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn materialize_sealed(binding: &ExecutableBinding) -> io::Result<SealedExecutable> {
    materialize_sealed_checked(binding, &mut || Ok(()))
}

#[cfg(target_os = "linux")]
fn materialize_sealed_checked(
    binding: &ExecutableBinding,
    checkpoint: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<SealedExecutable> {
    checkpoint()?;
    validate_binding(binding)?;
    let source_path = PathBuf::from(OsString::from_vec(binding.path.clone()));
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&source_path)
        .map_err(|error| opaque_io(error, "could not open pinned executable source"))?;
    verify_open_binding(&source, binding)?;

    let name = b"maco-pinned-exec\0";
    // SAFETY: `name` is NUL-terminated and points to immutable storage for the duration of the
    // syscall; the flags are the documented memfd_create bit set.
    let fd = unsafe {
        libc::memfd_create(
            name.as_ptr().cast(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(opaque_last_os_error(
            "could not create sealed executable descriptor",
        ));
    }
    // SAFETY: successful memfd_create returned a new owned descriptor that is transferred to File.
    let mut destination = unsafe { File::from_raw_fd(fd) };
    // SAFETY: fchmod changes only the mode of the anonymous file owned by `destination`.
    if unsafe { libc::fchmod(destination.as_raw_fd(), 0o500) } < 0 {
        return Err(opaque_last_os_error(
            "could not mark sealed executable as executable",
        ));
    }

    let copied_hash =
        copy_and_hash_checked(&mut source, &mut destination, binding.length, checkpoint)?;
    if !constant_time_eq(&copied_hash, &binding.sha256) {
        return Err(invalid_data(
            "pinned executable content changed before sealing",
        ));
    }
    verify_open_binding(&source, binding)?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: F_ADD_SEALS applies the requested immutable seals to the owned memfd.
    if unsafe { libc::fcntl(destination.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(opaque_last_os_error("could not seal executable descriptor"));
    }
    // SAFETY: F_GET_SEALS only reads seal flags from the owned memfd.
    let observed_seals = unsafe { libc::fcntl(destination.as_raw_fd(), libc::F_GET_SEALS) };
    if observed_seals < 0 || observed_seals & seals != seals {
        return Err(io::Error::other(
            "sealed executable did not retain all required seals",
        ));
    }
    let metadata = destination
        .metadata()
        .map_err(|error| opaque_io(error, "could not inspect sealed executable"))?;
    if metadata.len() != binding.length {
        return Err(invalid_data(
            "sealed executable length did not match its binding",
        ));
    }
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|error| opaque_io(error, "could not rewind sealed executable"))?;
    let (verified_hash, _, verified_length) =
        hash_reader_with_prefix_checked(&mut destination, binding.length, checkpoint)?;
    if verified_length != binding.length {
        return Err(invalid_data(
            "hashed executable length did not match its binding",
        ));
    }
    if !constant_time_eq(&verified_hash, &binding.sha256) {
        return Err(invalid_data(
            "sealed executable digest did not match its binding",
        ));
    }
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|error| opaque_io(error, "could not rewind verified sealed executable"))?;
    let sealed = SealedExecutable {
        file: destination,
        length: binding.length,
    };
    sealed.set_close_on_exec(true)?;
    Ok(sealed)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn materialize_sealed(_binding: &ExecutableBinding) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn capture_executable_binding(path: &Path) -> io::Result<(ExecutableBinding, Vec<u8>)> {
    let invocation_path = path.as_os_str().as_bytes();
    validate_path_bytes(invocation_path)?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| opaque_io(error, "could not resolve pinned executable source"))?;
    let path_bytes = canonical.as_os_str().as_bytes();
    validate_path_bytes(path_bytes)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&canonical)
        .map_err(|error| opaque_io(error, "could not open pinned executable source"))?;
    let metadata = file
        .metadata()
        .map_err(|error| opaque_io(error, "could not inspect pinned executable source"))?;
    validate_executable_metadata(&metadata)?;
    let identity = metadata_identity(&metadata);
    let (sha256, prefix, length) = hash_reader_with_prefix(&mut file, MAX_EXECUTABLE_BYTES)?;
    if length != metadata.len() {
        return Err(invalid_data(
            "pinned executable length changed during capture",
        ));
    }
    let after = file
        .metadata()
        .map_err(|error| opaque_io(error, "could not re-inspect pinned executable source"))?;
    if metadata_identity(&after) != identity
        || after.len() != metadata.len()
        || permission_mode(&after) != permission_mode(&metadata)
    {
        return Err(invalid_data(
            "pinned executable identity changed during capture",
        ));
    }
    Ok((
        ExecutableBinding {
            path: path_bytes.to_vec(),
            argv0: invocation_path.to_vec(),
            device: identity.0,
            inode: identity.1,
            mode: permission_mode(&metadata),
            length,
            sha256,
        },
        prefix,
    ))
}

#[cfg(target_os = "linux")]
fn verify_open_binding(file: &File, binding: &ExecutableBinding) -> io::Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| opaque_io(error, "could not inspect pinned executable source"))?;
    validate_executable_metadata(&metadata)?;
    let (device, inode) = metadata_identity(&metadata);
    if device != binding.device
        || inode != binding.inode
        || permission_mode(&metadata) != binding.mode
        || metadata.len() != binding.length
    {
        return Err(invalid_data(
            "pinned executable metadata did not match its binding",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_executable_metadata(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(invalid_input(
            "pinned executable source was not a regular file",
        ));
    }
    let mode = permission_mode(metadata);
    if mode & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pinned executable source was not executable",
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(file_too_large(
            "pinned executable source exceeded its bound",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn metadata_identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

#[cfg(target_os = "linux")]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    metadata.permissions().mode() & 0o7777
}

#[cfg(target_os = "linux")]
fn validate_source_bound_helper_path(path: &Path) -> io::Result<()> {
    validate_source_bound_helper_layout(path)?;
    validate_source_bound_package_path(path, true)
}

#[cfg(target_os = "linux")]
fn validate_source_bound_package_path(path: &Path, executable: bool) -> io::Result<()> {
    let mut current = PathBuf::from("/");
    validate_helper_component_with_role(
        &current,
        0,
        false,
        Some(ProtectedHelperComponentRole::FilesystemRoot),
    )?;
    let components = path.components().skip(1).collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            return Err(invalid_input(
                "source-bound main helper path was not normalized",
            ));
        };
        current.push(component);
        if current == Path::new("/nix/store") {
            let metadata = fs::symlink_metadata(&current).map_err(|error| {
                opaque_io(error, "could not inspect source-bound helper store anchor")
            })?;
            if !source_bound_store_anchor_allowed(
                metadata.uid(),
                permission_mode(&metadata),
                metadata.is_dir(),
                metadata.file_type().is_symlink(),
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "source-bound helper store anchor was not protected",
                ));
            }
        } else {
            let final_component = index + 1 == components.len();
            if final_component && !executable {
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    opaque_io(error, "could not inspect main helper package path")
                })?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.uid() != 0
                    || permission_mode(&metadata) & 0o6022 != 0
                {
                    return Err(invalid_data(
                        "main helper package file was not root-owned and immutable",
                    ));
                }
            } else {
                validate_helper_component_with_role(
                    &current,
                    0,
                    final_component,
                    source_bound_helper_component_role(&current),
                )?;
            }
        }
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| opaque_io(error, "could not inspect source-bound main helper"))?;
    if permission_mode(&metadata) & 0o6000 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "source-bound main helper had privilege bits",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_source_bound_helper_layout(path: &Path) -> io::Result<()> {
    validate_path_bytes(path.as_os_str().as_bytes())?;
    let relative = path
        .strip_prefix("/nix/store")
        .map_err(|_| invalid_input("source-bound main helper was outside its package anchor"))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.len() != 3
        || !matches!(components[0], std::path::Component::Normal(_))
        || components[1] != std::path::Component::Normal(OsStr::new("bin"))
        || components[2] != std::path::Component::Normal(OsStr::new("maco"))
        || Path::new("/nix/store").join(relative).as_os_str() != path.as_os_str()
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return Err(invalid_input(
            "source-bound main helper did not have the exact package layout",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn source_bound_store_anchor_allowed(
    owner: u32,
    mode: u32,
    directory: bool,
    symlink: bool,
) -> bool {
    owner == 0
        && directory
        && !symlink
        && mode & 0o002 == 0
        && (mode & 0o020 == 0 || mode & 0o1000 != 0)
        && mode & 0o6000 == 0
}

#[cfg(target_os = "linux")]
fn validate_helper_path_from_anchor(path: &Path, anchor: &Path, owner: u32) -> io::Result<()> {
    if !path.is_absolute() || !anchor.is_absolute() || !path.starts_with(anchor) || path == anchor {
        return Err(invalid_input(
            "fixed helper path was not an absolute descendant",
        ));
    }
    let mut current = anchor.to_path_buf();
    validate_helper_component(&current, owner, false)?;
    let relative = path
        .strip_prefix(anchor)
        .map_err(|_| invalid_input("fixed helper path escaped its trust anchor"))?;
    let components = relative.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(invalid_input("fixed helper path omitted its executable"));
    }
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            return Err(invalid_input(
                "fixed helper path contained a non-normal component",
            ));
        };
        current.push(component);
        validate_helper_component(&current, owner, index + 1 == components.len())?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectedHelperComponentRole {
    FilesystemRoot,
    NixRoot,
    PackageRoot,
    PackageBin,
    PackageExecutable,
    PackageShare,
    PackageMetadataDirectory,
}

#[cfg(target_os = "linux")]
impl ProtectedHelperComponentRole {
    fn label(self) -> &'static str {
        match self {
            Self::FilesystemRoot => "FilesystemRoot",
            Self::NixRoot => "NixRoot",
            Self::PackageRoot => "PackageRoot",
            Self::PackageBin => "PackageBin",
            Self::PackageExecutable => "PackageExecutable",
            Self::PackageShare => "PackageShare",
            Self::PackageMetadataDirectory => "PackageMetadataDirectory",
        }
    }
}

#[cfg(target_os = "linux")]
fn source_bound_helper_component_role(path: &Path) -> Option<ProtectedHelperComponentRole> {
    use std::path::Component;
    use ProtectedHelperComponentRole::*;

    if !path.is_absolute() || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    {
        return None;
    }
    if path == Path::new("/") {
        return Some(FilesystemRoot);
    }
    if path == Path::new("/nix") {
        return Some(NixRoot);
    }
    let components = path
        .strip_prefix("/nix/store")
        .ok()?
        .components()
        .collect::<Vec<_>>();
    match components.as_slice() {
        [Component::Normal(_)] => Some(PackageRoot),
        [Component::Normal(_), kind] if *kind == Component::Normal(OsStr::new("bin")) => {
            Some(PackageBin)
        }
        [Component::Normal(_), kind] if *kind == Component::Normal(OsStr::new("share")) => {
            Some(PackageShare)
        }
        [Component::Normal(_), kind, leaf]
            if *kind == Component::Normal(OsStr::new("bin"))
                && *leaf == Component::Normal(OsStr::new("maco")) =>
        {
            Some(PackageExecutable)
        }
        [Component::Normal(_), kind, leaf]
            if *kind == Component::Normal(OsStr::new("share"))
                && *leaf == Component::Normal(OsStr::new("maco")) =>
        {
            Some(PackageMetadataDirectory)
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn protected_helper_component_refusal_message(
    component: Option<ProtectedHelperComponentRole>,
    symlink: bool,
    owner_mismatch: bool,
    writable: bool,
) -> String {
    let Some(component) = component else {
        return "fixed helper path was not owner-controlled and immutable".to_owned();
    };
    // Only closed labels and predicate bits leave the helper. No pathname, metadata value,
    // or underlying error is rendered. The shared validator has no invocation-stage context.
    format!(
        "fixed helper path was not owner-controlled and immutable; component={}; symlink={}; owner_mismatch={}; writable={}",
        component.label(),
        u8::from(symlink),
        u8::from(owner_mismatch),
        u8::from(writable),
    )
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn protected_helper_component_refusal_message_for_test(
    path: &Path,
    symlink: bool,
    owner_mismatch: bool,
    writable: bool,
) -> String {
    protected_helper_component_refusal_message(
        source_bound_helper_component_role(path),
        symlink,
        owner_mismatch,
        writable,
    )
}

#[cfg(target_os = "linux")]
fn validate_helper_component(path: &Path, owner: u32, final_component: bool) -> io::Result<()> {
    validate_helper_component_with_role(path, owner, final_component, None)
}

#[cfg(target_os = "linux")]
fn validate_helper_component_with_role(
    path: &Path,
    owner: u32,
    final_component: bool,
    component: Option<ProtectedHelperComponentRole>,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| opaque_io(error, "could not inspect fixed helper path"))?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || permission_mode(&metadata) & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            protected_helper_component_refusal_message(
                component,
                metadata.file_type().is_symlink(),
                metadata.uid() != owner,
                permission_mode(&metadata) & 0o022 != 0,
            ),
        ));
    }
    if final_component {
        if !metadata.is_file() || permission_mode(&metadata) & 0o111 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "fixed helper target was not an executable regular file",
            ));
        }
    } else if !metadata.is_dir() {
        return Err(invalid_input(
            "fixed helper path ancestor was not a directory",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_binding(binding: &ExecutableBinding) -> io::Result<()> {
    validate_path_bytes(&binding.path)?;
    validate_path_bytes(&binding.argv0)?;
    if binding.device == 0
        || binding.inode == 0
        || binding.mode & 0o111 == 0
        || binding.length == 0
        || binding.length > MAX_EXECUTABLE_BYTES
    {
        return Err(invalid_data("pinned executable binding was malformed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_dispatching_interpreter(binding: &ExecutableBinding) -> io::Result<()> {
    let path = Path::new(OsStr::from_bytes(&binding.path));
    let basename = path.file_name().and_then(|name| name.to_str());
    if basename == Some("env") {
        return Err(invalid_input(
            "dispatcher shebang interpreters are not supported by pinned execution",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_path_bytes(path: &[u8]) -> io::Result<()> {
    if path.is_empty()
        || path.len() > MAX_EXECUTABLE_PATH_BYTES
        || path[0] != b'/'
        || path.contains(&0)
        || path.iter().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid_input(
            "pinned executable path was malformed or oversized",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
struct ParsedShebang {
    path: Vec<u8>,
    argument: Option<Vec<u8>>,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn parse_shebang(prefix: &[u8]) -> io::Result<Option<ParsedShebang>> {
    if !prefix.starts_with(b"#!") {
        return Ok(None);
    }
    let search = &prefix[..prefix.len().min(MAX_SHEBANG_BYTES.saturating_add(1))];
    let newline = search
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| invalid_data("script shebang exceeded its bound"))?;
    if newline > MAX_SHEBANG_BYTES {
        return Err(invalid_data("script shebang exceeded its bound"));
    }
    let mut line = &search[2..newline];
    if line.last() == Some(&b'\r') {
        line = &line[..line.len().saturating_sub(1)];
    }
    line = trim_ascii_space_tab(line);
    let split = line
        .iter()
        .position(|byte| matches!(*byte, b' ' | b'\t'))
        .unwrap_or(line.len());
    let path = &line[..split];
    let remainder = trim_ascii_space_tab(&line[split..]);
    validate_path_bytes(path)?;
    let argument = if remainder.is_empty() {
        None
    } else {
        validate_argument_bytes(remainder)?;
        Some(remainder.to_vec())
    };
    Ok(Some(ParsedShebang {
        path: path.to_vec(),
        argument,
    }))
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn trim_ascii_space_tab(mut bytes: &[u8]) -> &[u8] {
    while bytes
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        bytes = &bytes[1..];
    }
    while bytes
        .last()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        bytes = &bytes[..bytes.len().saturating_sub(1)];
    }
    bytes
}

#[cfg(target_os = "linux")]
fn validate_and_copy_arguments(arguments: &[OsString]) -> io::Result<Vec<Vec<u8>>> {
    if arguments.len() > MAX_PINNED_ARGUMENTS {
        return Err(invalid_input(
            "pinned executable argument count exceeded its bound",
        ));
    }
    let mut copied = Vec::with_capacity(arguments.len());
    let mut total = 0usize;
    for argument in arguments {
        let bytes = argument.as_os_str().as_bytes();
        validate_argument_bytes(bytes)?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| invalid_input("pinned executable argument size overflow"))?;
        copied.push(bytes.to_vec());
    }
    if total > MAX_PINNED_ARGUMENT_TOTAL_BYTES {
        return Err(invalid_input(
            "pinned executable arguments exceeded their aggregate bound",
        ));
    }
    Ok(copied)
}

#[cfg(target_os = "linux")]
fn validate_and_copy_environment(
    environment: &[(OsString, OsString)],
) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if environment.len() > 256 {
        return Err(invalid_input(
            "pinned executable environment count exceeded its bound",
        ));
    }
    let mut copied = environment
        .iter()
        .map(|(name, value)| {
            let name = name.as_os_str().as_bytes().to_vec();
            let value = value.as_os_str().as_bytes().to_vec();
            validate_environment_entry(&name, &value)?;
            Ok((name, value))
        })
        .collect::<io::Result<Vec<_>>>()?;
    copied.sort_by(|left, right| left.0.cmp(&right.0));
    let mut total = 0usize;
    let mut previous: Option<&[u8]> = None;
    for (name, value) in &copied {
        if previous == Some(name.as_slice()) {
            return Err(invalid_input(
                "pinned executable environment contained duplicates",
            ));
        }
        total = total
            .checked_add(name.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or_else(|| invalid_input("pinned executable environment size overflow"))?;
        previous = Some(name);
    }
    if total > 4 * 1024 * 1024 {
        return Err(invalid_input(
            "pinned executable environment exceeded its aggregate bound",
        ));
    }
    Ok(copied)
}

#[cfg(target_os = "linux")]
fn validate_environment_entry(name: &[u8], value: &[u8]) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 256
        || value.len() > 1024 * 1024
        || name.contains(&0)
        || name.contains(&b'=')
        || value.contains(&0)
        || name.iter().any(|byte| byte.is_ascii_control())
        || value.iter().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid_input(
            "pinned executable environment entry was malformed or oversized",
        ));
    }
    reject_code_hook_environment(name)
}

#[cfg(target_os = "linux")]
fn reject_code_hook_environment(name: &[u8]) -> io::Result<()> {
    let exact = [
        b"BASH_ENV".as_slice(),
        b"ENV".as_slice(),
        b"SHELLOPTS".as_slice(),
        b"BASHOPTS".as_slice(),
        b"KSH_ENV".as_slice(),
        b"ZDOTDIR".as_slice(),
        b"PYTHONPATH".as_slice(),
        b"PYTHONHOME".as_slice(),
        b"PYTHONSTARTUP".as_slice(),
        b"PYTHONINSPECT".as_slice(),
        b"PYTHONUSERBASE".as_slice(),
        b"PERL5OPT".as_slice(),
        b"PERL5LIB".as_slice(),
        b"PERLLIB".as_slice(),
        b"PERL5DB".as_slice(),
        b"RUBYOPT".as_slice(),
        b"RUBYLIB".as_slice(),
        b"NODE_OPTIONS".as_slice(),
        b"NODE_PATH".as_slice(),
        b"GCONV_PATH".as_slice(),
        b"LOCPATH".as_slice(),
        b"JAVA_TOOL_OPTIONS".as_slice(),
        b"_JAVA_OPTIONS".as_slice(),
        b"JDK_JAVA_OPTIONS".as_slice(),
        b"CLASSPATH".as_slice(),
        b"LUA_PATH".as_slice(),
        b"LUA_CPATH".as_slice(),
        b"LUA_INIT".as_slice(),
        b"PHPRC".as_slice(),
        b"PHP_INI_SCAN_DIR".as_slice(),
        b"RUSTC_WRAPPER".as_slice(),
        b"RUSTC_WORKSPACE_WRAPPER".as_slice(),
        b"GIT_EXEC_PATH".as_slice(),
        b"GIT_TEMPLATE_DIR".as_slice(),
    ];
    let forbidden = name.starts_with(b"LD_")
        || name.starts_with(b"DYLD_")
        || name.starts_with(b"MALLOC_")
        || name.starts_with(b"LUA_INIT_")
        || exact.contains(&name);
    if forbidden {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pinned executable environment contained a code-loading hook",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_argument_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty()
        || bytes.len() > MAX_PINNED_ARGUMENT_BYTES
        || bytes.contains(&0)
        || bytes.iter().any(|byte| byte.is_ascii_control())
    {
        return Err(invalid_input(
            "pinned executable argument was malformed or oversized",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_exec_argv(argv: &[Vec<u8>]) -> io::Result<()> {
    if argv.is_empty() || argv.len() > MAX_PINNED_ARGUMENTS.saturating_add(3) {
        return Err(invalid_data("prepared executable argv count was invalid"));
    }
    for argument in argv {
        validate_argument_bytes(argument)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn encode_binding(output: &mut Vec<u8>, binding: &ExecutableBinding) -> io::Result<()> {
    validate_binding(binding)?;
    write_bounded_bytes(output, &binding.path, "executable path")?;
    write_bounded_bytes(output, &binding.argv0, "executable argv0")?;
    output.extend_from_slice(&binding.device.to_be_bytes());
    output.extend_from_slice(&binding.inode.to_be_bytes());
    output.extend_from_slice(&binding.mode.to_be_bytes());
    output.extend_from_slice(&binding.length.to_be_bytes());
    output.extend_from_slice(&binding.sha256);
    Ok(())
}

#[cfg(target_os = "linux")]
fn decode_binding(cursor: &mut DescriptorCursor<'_>) -> io::Result<ExecutableBinding> {
    let binding = ExecutableBinding {
        path: cursor.read_bounded_bytes(MAX_EXECUTABLE_PATH_BYTES)?,
        argv0: cursor.read_bounded_bytes(MAX_EXECUTABLE_PATH_BYTES)?,
        device: cursor.read_u64()?,
        inode: cursor.read_u64()?,
        mode: cursor.read_u32()?,
        length: cursor.read_u64()?,
        sha256: cursor.read_array()?,
    };
    validate_binding(&binding)?;
    Ok(binding)
}

#[cfg(target_os = "linux")]
fn encode_optional_bytes(output: &mut Vec<u8>, bytes: Option<&[u8]>) -> io::Result<()> {
    match bytes {
        Some(bytes) => {
            output.push(1);
            write_bounded_bytes(output, bytes, "optional argument")?;
        }
        None => output.push(0),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn decode_optional_bytes(cursor: &mut DescriptorCursor<'_>) -> io::Result<Option<Vec<u8>>> {
    match cursor.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(cursor.read_bounded_bytes(MAX_PINNED_ARGUMENT_BYTES)?)),
        _ => Err(invalid_data("invalid optional argument tag")),
    }
}

#[cfg(target_os = "linux")]
fn write_bounded_bytes(output: &mut Vec<u8>, bytes: &[u8], label: &str) -> io::Result<()> {
    write_u32(output, bytes.len(), label)?;
    output.extend_from_slice(bytes);
    if output.len() > MAX_DESCRIPTOR_BYTES {
        return Err(file_too_large(
            "pinned executable descriptor exceeded its bound",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_bytes_allow_empty(output: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
    write_u32(output, bytes.len(), "environment value")?;
    output.extend_from_slice(bytes);
    if output.len() > MAX_DESCRIPTOR_BYTES {
        return Err(file_too_large(
            "pinned executable descriptor exceeded its bound",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_u32(output: &mut Vec<u8>, value: usize, _label: &str) -> io::Result<()> {
    let value = u32::try_from(value)
        .map_err(|_| invalid_input("pinned executable descriptor field overflow"))?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

#[cfg(target_os = "linux")]
struct DescriptorCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[cfg(target_os = "linux")]
impl<'a> DescriptorCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn require_exact(&mut self, expected: &[u8]) -> io::Result<()> {
        if self.take(expected.len())? != expected {
            return Err(invalid_data(
                "pinned executable descriptor magic did not match",
            ));
        }
        Ok(())
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut output = [0u8; N];
        output.copy_from_slice(self.take(N)?);
        Ok(output)
    }

    fn read_bounded_bytes(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_| invalid_data("pinned executable descriptor length overflow"))?;
        if length == 0 || length > max {
            return Err(invalid_data(
                "pinned executable descriptor field exceeded its bound",
            ));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn read_bytes_allow_empty(&mut self, max: usize) -> io::Result<Vec<u8>> {
        let length = usize::try_from(self.read_u32()?)
            .map_err(|_| invalid_data("pinned executable descriptor length overflow"))?;
        if length > max {
            return Err(invalid_data(
                "pinned executable descriptor field exceeded its bound",
            ));
        }
        Ok(self.take(length)?.to_vec())
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid_data("pinned executable descriptor offset overflow"))?;
        if end > self.bytes.len() {
            return Err(invalid_data("pinned executable descriptor was truncated"));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn require_end(&self) -> io::Result<()> {
        if self.offset != self.bytes.len() {
            return Err(invalid_data(
                "pinned executable descriptor had trailing data",
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn copy_and_hash_checked(
    source: &mut File,
    destination: &mut File,
    expected: u64,
    checkpoint: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<[u8; 32]> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| opaque_io(error, "could not rewind pinned executable source"))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint()?;
        let read = source
            .read(&mut buffer)
            .map_err(|error| opaque_io(error, "could not read pinned executable source"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| invalid_data("copy length overflow"))?)
            .ok_or_else(|| invalid_data("copy length overflow"))?;
        if total > expected || total > MAX_EXECUTABLE_BYTES {
            return Err(file_too_large(
                "pinned executable source exceeded its bound",
            ));
        }
        hasher.update(&buffer[..read])?;
        destination.write_all(&buffer[..read]).map_err(|error| {
            opaque_io(error, "could not copy pinned executable into sealed memory")
        })?;
    }
    if total != expected {
        return Err(invalid_data(
            "pinned executable copy length did not match its binding",
        ));
    }
    Ok(hasher.finalize())
}

#[cfg(target_os = "linux")]
fn hash_reader(reader: &mut File, expected: u64) -> io::Result<[u8; 32]> {
    let (hash, _, length) = hash_reader_with_prefix(reader, expected)?;
    if length != expected {
        return Err(invalid_data(
            "hashed executable length did not match its binding",
        ));
    }
    Ok(hash)
}

#[cfg(target_os = "linux")]
fn hash_reader_with_prefix(reader: &mut File, max: u64) -> io::Result<([u8; 32], Vec<u8>, u64)> {
    hash_reader_with_prefix_checked(reader, max, &mut || Ok(()))
}

#[cfg(target_os = "linux")]
fn hash_reader_with_prefix_checked(
    reader: &mut File,
    max: u64,
    checkpoint: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<([u8; 32], Vec<u8>, u64)> {
    let mut hasher = Sha256::new();
    let mut prefix = Vec::with_capacity(MAX_SHEBANG_BYTES.saturating_add(1));
    let mut total = 0u64;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|error| opaque_io(error, "could not hash executable content"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| invalid_data("hash length overflow"))?)
            .ok_or_else(|| invalid_data("hash length overflow"))?;
        if total > max || total > MAX_EXECUTABLE_BYTES {
            return Err(file_too_large("executable content exceeded its hash bound"));
        }
        if prefix.len() < MAX_SHEBANG_BYTES.saturating_add(1) {
            let remaining = MAX_SHEBANG_BYTES
                .saturating_add(1)
                .saturating_sub(prefix.len());
            prefix.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        hasher.update(&buffer[..read])?;
    }
    Ok((hasher.finalize(), prefix, total))
}

#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Sha256 {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    const fn new() -> Self {
        Self {
            state: Self::INITIAL,
            buffer: [0; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        self.total_bytes = self
            .total_bytes
            .checked_add(
                u64::try_from(bytes.len()).map_err(|_| invalid_data("hash length overflow"))?,
            )
            .ok_or_else(|| invalid_data("hash length overflow"))?;
        if self.buffer_len > 0 {
            let available = 64usize.saturating_sub(self.buffer_len);
            let copied = available.min(bytes.len());
            self.buffer[self.buffer_len..self.buffer_len + copied]
                .copy_from_slice(&bytes[..copied]);
            self.buffer_len += copied;
            bytes = &bytes[copied..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        while bytes.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&bytes[..64]);
            self.compress(&block);
            bytes = &bytes[64..];
        }
        if !bytes.is_empty() {
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.buffer_len = bytes.len();
        }
        Ok(())
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_length = self.total_bytes.wrapping_mul(8);
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut output = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            let offset = index * 4;
            output[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn sha256(bytes: &[u8]) -> io::Result<[u8; SHA256_BYTES]> {
    let mut state = Sha256::new();
    state.update(bytes)?;
    Ok(state.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_sha256_hex(bytes: &[u8]) -> io::Result<[u8; SHA256_BYTES]> {
    if bytes.len() != SHA256_HEX_BYTES {
        return Err(invalid_input("pinned executable digest was malformed"));
    }
    let mut output = [0u8; SHA256_BYTES];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        output[index] = (decode_lower_hex(pair[0])? << 4) | decode_lower_hex(pair[1])?;
    }
    Ok(output)
}

fn decode_lower_hex(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid_input("pinned executable digest was malformed")),
    }
}

fn constant_time_eq(left: &[u8; SHA256_BYTES], right: &[u8; SHA256_BYTES]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn file_too_large(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::FileTooLarge, message)
}

#[cfg(not(target_os = "linux"))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "pinned executable sealing is available only on Linux",
    )
}

#[cfg(target_os = "linux")]
fn opaque_io(error: io::Error, message: &'static str) -> io::Error {
    io::Error::new(error.kind(), message)
}

#[cfg(target_os = "linux")]
fn opaque_last_os_error(message: &'static str) -> io::Error {
    let error = io::Error::last_os_error();
    io::Error::new(error.kind(), message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    use std::{
        fs::OpenOptions,
        os::{
            fd::{AsRawFd, FromRawFd, RawFd},
            unix::{ffi::OsStringExt, fs::PermissionsExt},
        },
    };

    #[cfg(target_os = "linux")]
    fn executable(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .expect("create executable fixture");
        file.write_all(bytes).expect("write executable fixture");
        file.set_permissions(fs::Permissions::from_mode(0o755))
            .expect("chmod executable fixture");
    }

    #[cfg(target_os = "linux")]
    const PROC_FIXTURE_STAGE_UNSHARE: u8 = b'u';
    #[cfg(target_os = "linux")]
    const PROC_FIXTURE_STAGE_SETGROUPS: u8 = b's';
    #[cfg(target_os = "linux")]
    const PROC_FIXTURE_STAGE_UID_MAP: u8 = b'i';
    #[cfg(target_os = "linux")]
    const PROC_FIXTURE_STAGE_GID_MAP: u8 = b'g';
    #[cfg(target_os = "linux")]
    const PROC_FIXTURE_STAGE_MOUNT: u8 = b'm';
    #[cfg(target_os = "linux")]
    const PROC_FIXTURE_STAGE_PREPARED: u8 = b'p';

    #[cfg(target_os = "linux")]
    fn write_proc_fixture_stage(stage_fd: RawFd, stage: u8) -> io::Result<()> {
        let bytes = [stage];
        // SAFETY: stage_fd is the inherited CLOEXEC diagnostic write end; bytes
        // remains readable for one byte. No allocator, lock, env, or path I/O.
        let count = unsafe { libc::write(stage_fd, bytes.as_ptr().cast(), 1) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count != 1 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn write_proc_fixture_mapping(
        path: &std::ffi::CStr,
        bytes: &[u8],
        stage_fd: RawFd,
        stage: u8,
    ) -> io::Result<()> {
        // Used only between fork and exec: raw syscalls, prebuilt bytes, and a
        // one-byte diagnostic write. No allocator, locks, environment access or
        // Rust file buffering. Stage is written before the mapping open.
        write_proc_fixture_stage(stage_fd, stage)?;
        // SAFETY: path is a live C string; open returns a new owned descriptor.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is owned here and bytes remains readable for its length.
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        let error = if count < 0 {
            Some(io::Error::last_os_error())
        } else if count as usize != bytes.len() {
            Some(io::Error::from_raw_os_error(libc::EIO))
        } else {
            None
        };
        // SAFETY: close consumes only the descriptor opened above.
        let closed = unsafe { libc::close(fd) };
        if let Some(error) = error {
            return Err(error);
        }
        if closed != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn prepare_proc_substitution_fixture(
        uid_map: &[u8],
        gid_map: &[u8],
        stage_fd: RawFd,
    ) -> io::Result<()> {
        // SAFETY: invoked only in this test's owned, single-threaded pre-exec
        // child. The parent's user/mount namespace and proc view are untouched.
        write_proc_fixture_stage(stage_fd, PROC_FIXTURE_STAGE_UNSHARE)?;
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
            return Err(io::Error::last_os_error());
        }
        write_proc_fixture_mapping(
            c"/proc/self/setgroups",
            b"deny",
            stage_fd,
            PROC_FIXTURE_STAGE_SETGROUPS,
        )?;
        write_proc_fixture_mapping(
            c"/proc/self/uid_map",
            uid_map,
            stage_fd,
            PROC_FIXTURE_STAGE_UID_MAP,
        )?;
        write_proc_fixture_mapping(
            c"/proc/self/gid_map",
            gid_map,
            stage_fd,
            PROC_FIXTURE_STAGE_GID_MAP,
        )?;
        write_proc_fixture_stage(stage_fd, PROC_FIXTURE_STAGE_MOUNT)?;
        // SAFETY: fixed mount propagation operation applies only in the new
        // owned mount namespace; no filesystem or source is supplied.
        if unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        write_proc_fixture_stage(stage_fd, PROC_FIXTURE_STAGE_PREPARED)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn open_proc_fixture_stage_pipe() -> io::Result<(File, File)> {
        let mut fds = [-1; 2];
        // SAFETY: pipe2 writes two new owned descriptors into fds on success.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe2 succeeded; each descriptor is uniquely owned here.
        Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
    }

    #[cfg(target_os = "linux")]
    fn read_proc_fixture_last_stage(fd: RawFd) -> Option<u8> {
        // SAFETY: fd is the parent-owned diagnostic read end.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return None;
        }
        // SAFETY: O_NONBLOCK applies only to this owned read end.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
            return None;
        }
        let mut buf = [0u8; 8];
        let mut filled = 0usize;
        for _ in 0..buf.len() {
            if filled >= buf.len() {
                break;
            }
            // SAFETY: fd is the owned read end; buf[filled..] is writable.
            let count =
                unsafe { libc::read(fd, buf[filled..].as_mut_ptr().cast(), buf.len() - filled) };
            if count < 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    _ => break,
                }
            }
            if count == 0 {
                break;
            }
            filled += count as usize;
        }
        if filled == 0 {
            None
        } else {
            Some(buf[filled - 1])
        }
    }

    #[cfg(target_os = "linux")]
    fn proc_fixture_stage_label(stage: Option<u8>) -> &'static str {
        match stage {
            Some(PROC_FIXTURE_STAGE_UNSHARE) => "unshare",
            Some(PROC_FIXTURE_STAGE_SETGROUPS) => "setgroups mapping",
            Some(PROC_FIXTURE_STAGE_UID_MAP) => "uid mapping",
            Some(PROC_FIXTURE_STAGE_GID_MAP) => "gid mapping",
            Some(PROC_FIXTURE_STAGE_MOUNT) => "private mount",
            Some(PROC_FIXTURE_STAGE_PREPARED) => "prepared",
            Some(_) => "unknown",
            None => "none",
        }
    }

    #[cfg(target_os = "linux")]
    fn exercise_proc_substitution_fixture() {
        // This isolated child does not exec again. Its own comm therefore
        // supplies the same writable procfs object as the retained sibling in
        // the counterexample, without another process or a keeper protocol.
        fs::write("/proc/self/comm", b"0 0 4294967295").expect("owned child comm");
        let pid = std::process::id();
        let source = CString::new(format!("/proc/{pid}/comm")).expect("fixed source");
        let target = CString::new(format!("/proc/{pid}/uid_map")).expect("fixed target");
        // SAFETY: both fixed paths name only this owned child's proc entries.
        // Propagation is private and the mount dies with the child namespace.
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0,
            "isolated proc substitution setup failed"
        );
        let mut substituted = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(OsStr::from_bytes(target.as_bytes()))
            .expect("substituted proc inode");
        // Demonstrate the exact old accepting premises on real descriptors,
        // not a fabricated statfs value or only a map-string parser fixture.
        // SAFETY: statfs is plain C storage initialized by fstatfs below.
        let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: substituted owns the FD and filesystem is writable storage.
        assert_eq!(
            unsafe { libc::fstatfs(substituted.as_raw_fd(), &mut filesystem) },
            0
        );
        assert_eq!(filesystem.f_type, libc::PROC_SUPER_MAGIC);
        let mut bytes = Vec::new();
        Read::by_ref(&mut substituted)
            .take(257)
            .read_to_end(&mut bytes)
            .expect("bounded map bytes");
        assert!(controller_has_full_identity_map(&bytes));
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/proc")
            .expect("child proc anchor");
        let relative = CString::new(format!("{pid}/uid_map")).expect("fixed relative path");
        let error = match open_controller_proc_entry(&root, &relative, libc::O_RDONLY) {
            Err(error) => error,
            Ok(_) => panic!("bind mount must refuse"),
        };
        assert_eq!(error.raw_os_error(), Some(libc::EXDEV));
        assert!(validate_controller_root_namespace().is_err());
        println!("proc-substitution-refused");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mechanical_native_data_refuses_unsealed_drift_scripts_and_false_host_maps() {
        const TEST: &str = "pinned_exec::tests::mechanical_native_data_refuses_unsealed_drift_scripts_and_false_host_maps";
        const CHILD_ARGV0: &str = "/maco-proc-substitution-fixture";
        let child_argv0 = env::args_os().next() == Some(OsString::from(CHILD_ARGV0));
        if child_argv0 || env::var_os("MACO_PROC_SUBSTITUTION_CHILD").is_some() {
            assert!(child_argv0);
            assert_eq!(
                env::var_os("MACO_PROC_SUBSTITUTION_CHILD"),
                Some(OsString::from("1"))
            );
            exercise_proc_substitution_fixture();
            return;
        }
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/proc")
            .expect("genuine proc root");
        let pid = std::process::id();
        open_controller_uid_map(&root, pid).expect("actual syscall PID and kernel self agree");
        assert!(open_controller_uid_map(&root, pid.checked_add(1).expect("bounded PID")).is_err());
        let wrong_root = open_controller_proc_entry(
            &root,
            &CString::new(pid.to_string()).expect("decimal PID"),
            libc::O_PATH | libc::O_DIRECTORY,
        )
        .expect("real proc PID directory");
        assert!(validate_controller_proc_root(&wrong_root).is_err());
        use std::os::unix::process::CommandExt;
        // SAFETY: these identity syscalls read only this owned test process.
        let uid_map = format!("0 {} 1\n", unsafe { libc::getuid() });
        // SAFETY: getgid reads the current process's real group identity.
        let gid_map = format!("0 {} 1\n", unsafe { libc::getgid() });
        let mut child = std::process::Command::new(env::current_exe().expect("libtest executable"));
        child
            .arg0(CHILD_ARGV0)
            .args(["--exact", TEST, "--nocapture"])
            .env_clear()
            .env("MACO_PROC_SUBSTITUTION_CHILD", "1")
            .stdin(std::process::Stdio::null());
        let (stage_read, stage_write) =
            open_proc_fixture_stage_pipe().expect("owned diagnostic pipe");
        let stage_fd = stage_write.as_raw_fd();
        // SAFETY: the closure calls only raw namespace/mapping syscalls, one-byte
        // writes to the inherited CLOEXEC diagnostic fd, and bytes built before
        // fork. No allocator or inherited lock is used.
        unsafe {
            child.pre_exec(move || {
                prepare_proc_substitution_fixture(uid_map.as_bytes(), gid_map.as_bytes(), stage_fd)
            });
        }
        let spawn = child.output();
        drop(stage_write);
        let last_stage = read_proc_fixture_last_stage(stage_read.as_raw_fd());
        let result = match spawn {
            Ok(result) => result,
            Err(error) => panic!(
                "owned isolated proc refusal child: last stage {}: {error}",
                proc_fixture_stage_label(last_stage),
            ),
        };
        assert!(
            result.status.success(),
            "isolated proc refusal child failed"
        );
        let stdout = std::str::from_utf8(&result.stdout).expect("fixed child output");
        assert_eq!(
            stdout
                .lines()
                .filter(|line| *line == "proc-substitution-refused")
                .count(),
            1
        );
        assert_eq!(
            stdout
                .matches("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;")
                .count(),
            1
        );
        assert!(controller_has_full_identity_map(
            b"         0          0 4294967295\n"
        ));
        for bytes in [
            b"".as_slice(),
            b"0 1000 1\n",
            b"0 0 1\n",
            b"0 0 4294967296\n",
            b"0\n0\n4294967295\n",
            b"0 0 4294967295\n1 1 1\n",
            b"secret 0 0 4294967295",
            b"0 0 4294967295\nextra",
            b"0 0 4294967295\xff",
        ] {
            assert!(!controller_has_full_identity_map(bytes));
        }
        let temp = tempfile::tempdir().expect("owned fixture");
        let path = temp.path().join("native");
        executable(&path, b"\x7fELFbounded fixture");
        let pinned = PinnedDirectExecutable::capture_for_test(&path).expect("image binding");
        // A real image and canonical self-authored descriptor still cannot
        // issue parent custody: this pin has no genuine SourceBoundMainHelper.
        assert!(pinned
            .prepare_native_entry(&mut || Ok(()))
            .expect("no authority")
            .is_none());
        let encoded = pinned
            .encode_descriptor(&[OsString::from("original argument")], &[])
            .expect("data");
        let request =
            decode_verified_descriptor(encoded.bytes(), OsStr::new(&encoded.digest_hex()))
                .expect("wire data");
        let ordinary = File::open(&path).expect("unsealed file");
        assert!(receive_native_image(&request, ordinary.as_raw_fd()).is_err());
        let sealed = materialize_sealed(&pinned.source).expect("sealed data");
        let received =
            receive_native_image(&request, sealed.as_raw_fd()).expect("image continuity");
        // SAFETY: received owns a live descriptor; F_GETFD only reads flags.
        let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        let mut drift = request.clone();
        drift.source.sha256[0] ^= 1;
        assert!(receive_native_image(&drift, sealed.as_raw_fd()).is_err());
        let mut script = request.clone();
        script.script = Some(ScriptBinding {
            interpreter: request.source.clone(),
            interpreter_argument: None,
        });
        assert!(receive_native_image(&script, sealed.as_raw_fd()).is_err());
        let mut cancelled = || {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "synthetic cancellation",
            ))
        };
        let error = match materialize_sealed_checked(&pinned.source, &mut cancelled) {
            Err(error) => error,
            Ok(_) => panic!("refusal"),
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        let mut checkpoints = 0;
        let mut during_copy = || {
            checkpoints += 1;
            if checkpoints >= 3 {
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "synthetic mid-copy cancellation",
                ))
            } else {
                Ok(())
            }
        };
        let error = match materialize_sealed_checked(&pinned.source, &mut during_copy) {
            Err(error) => error,
            Ok(_) => panic!("copy refused"),
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        let mut drifted = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open existing native fixture for in-place drift");
        drifted
            .write_all(b"\x7fELFdifferent bytes")
            .expect("write drifted fixture bytes");
        drop(drifted);
        assert!(materialize_sealed(&pinned.source).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mechanical_native_exec_preserves_argv_env_null_stdin_and_closes_relay_fds() {
        const TEST: &str = "pinned_exec::tests::mechanical_native_exec_preserves_argv_env_null_stdin_and_closes_relay_fds";
        let target_argv0 = env::args_os().next() == Some(OsString::from("/native-contract-argv0"));
        if target_argv0 || env::var_os("MACO_NATIVE_CONTRACT_TARGET").is_some() {
            // Either target discriminator enters mandatory assertions, not a
            // success fallback. Lost environment must fail rather than recurse.
            assert!(env::var_os("MACO_NATIVE_CONTRACT_TARGET").is_some());
            assert_eq!(
                env::args_os().collect::<Vec<_>>(),
                [
                    OsString::from("/native-contract-argv0"),
                    OsString::from("--exact"),
                    OsString::from(TEST),
                    OsString::from("--nocapture")
                ]
            );
            assert_eq!(
                env::var("MACO_NATIVE_CONTRACT_VALUE").expect("explicit value"),
                "bounded value"
            );
            assert!(env::var_os("MACO_NATIVE_CONTRACT_CHILD").is_none());
            assert!(env::var_os("HOME").is_none());
            let mut byte = [0];
            assert_eq!(io::stdin().read(&mut byte).expect("null stdin"), 0);
            let relay = env::var("MACO_NATIVE_CONTRACT_RELAY").expect("test image identity");
            for fd in [4, 51] {
                // SAFETY: plain stat storage is initialized by fstat for the
                // numeric FD; failure must be EBADF, never an ignored error.
                let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(fd, &mut metadata) } == 0 {
                    assert_ne!(
                        format!("{}:{}", metadata.st_dev, metadata.st_ino),
                        relay,
                        "an inherited native image copy survived exec"
                    );
                } else {
                    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
                }
            }
            println!("mechanical-native-contract-ok");
            return;
        }
        if let Some(path) = env::var_os("MACO_NATIVE_CONTRACT_CHILD") {
            // Reproduce the guardian's non-CLOEXEC stdin copy and an extra
            // relayed copy. Both must disappear in the final native image.
            // SAFETY: only this owned isolated test child is affected; stdin is
            // the relayed image and the named FD slots are synthetic copies.
            assert_eq!(unsafe { libc::dup2(0, 4) }, 4);
            assert_eq!(unsafe { libc::dup2(0, 51) }, 51);
            let digest = env::var_os("MACO_NATIVE_CONTRACT_DIGEST").expect("exact digest");
            let request = load_verified_descriptor_and_remove(Path::new(&path), &digest)
                .expect("private descriptor");
            execute_mechanical_native(request)
                .expect("native exec must replace this isolated test child");
            panic!("mechanical native exec returned");
        }
        let temp = tempfile::tempdir().expect("held request owner");
        let executable = env::current_exe().expect("libtest executable");
        let pinned = PinnedDirectExecutable::capture_for_test(&executable).expect("native image");
        let args = [
            OsString::from("--exact"),
            OsString::from(TEST),
            OsString::from("--nocapture"),
        ];
        let image = materialize_sealed(&pinned.source).expect("sealed libtest image");
        let relay_metadata = image.file.metadata().expect("test image metadata");
        let environment = [
            (
                OsString::from("MACO_NATIVE_CONTRACT_RELAY"),
                OsString::from(format!("{}:{}", relay_metadata.dev(), relay_metadata.ino())),
            ),
            (
                OsString::from("MACO_NATIVE_CONTRACT_TARGET"),
                OsString::from("1"),
            ),
            (
                OsString::from("MACO_NATIVE_CONTRACT_VALUE"),
                OsString::from("bounded value"),
            ),
        ];
        let encoded = pinned
            .encode_descriptor(&args, &environment)
            .expect("exact request");
        let mut request =
            decode_verified_descriptor(encoded.bytes(), OsStr::new(&encoded.digest_hex()))
                .expect("data");
        request.source.argv0 = b"/native-contract-argv0".to_vec();
        // Encode the original argv0 into the request using the same encoder.
        let mut test_pin = pinned.clone();
        test_pin.source.argv0 = request.source.argv0;
        let encoded = test_pin
            .encode_descriptor(&args, &environment)
            .expect("explicit argv0");
        let path = temp.path().join(PINNED_EXEC_DESCRIPTOR_NAME);
        fs::write(&path, encoded.bytes()).expect("owned descriptor");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private mode");
        let result = std::process::Command::new(&executable)
            .args(["--exact", TEST, "--nocapture"])
            .env_clear()
            .env("MACO_NATIVE_CONTRACT_CHILD", &path)
            .env("MACO_NATIVE_CONTRACT_DIGEST", encoded.digest_hex())
            .stdin(std::process::Stdio::from(
                image.file.try_clone().expect("relay image"),
            ))
            .output()
            .expect("owned provider-free child");
        assert!(
            result.status.success(),
            "provider-free mechanical native contract failed"
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("mechanical-native-contract-ok"));
        assert!(!path.exists(), "request was consumed by identity");
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            hex_encode(&sha256(b"abc").expect("sha256")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_bound_main_helper_requires_exact_compiled_source() {
        let source = sha256(b"frozen source manifest").expect("source digest");
        assert!(validate_source_binding(&source, None).is_err());
        assert!(validate_source_binding(&source, Some("unbound")).is_err());
        assert!(
            validate_source_binding(&source, Some(&hex_encode(&source).to_uppercase())).is_err()
        );
        let other = sha256(b"different source manifest").expect("other source digest");
        assert!(validate_source_binding(&source, Some(&hex_encode(&other))).is_err());
        validate_source_binding(&source, Some(&hex_encode(&source))).expect("same source");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_bound_main_helper_declaration_requires_exact_schema_and_main_entry() {
        let source = hex_encode(&sha256(b"frozen manifest").expect("source digest"));
        let binary = hex_encode(&sha256(b"binary digest parser fixture").expect("binary digest"));
        let entry = hex_encode(&sha256(include_bytes!("bin/maco.rs")).expect("entry digest"));
        let declaration = serde_json::json!({
            "schema": "maco-source-bound-main-helper-v1", "binary_sha256": binary,
            "source_manifest_sha256": source, "main_entry_sha256": entry,
        });
        validate_main_helper_declaration(&serde_json::to_vec(&declaration).expect("json"))
            .expect("exact declaration shape");
        for field in [
            "binary_sha256",
            "source_manifest_sha256",
            "main_entry_sha256",
        ] {
            let mut missing = declaration.clone();
            missing.as_object_mut().expect("object").remove(field);
            assert!(
                validate_main_helper_declaration(&serde_json::to_vec(&missing).expect("json"))
                    .is_err()
            );
            let mut malformed = declaration.clone();
            malformed[field] = serde_json::json!("malformed");
            assert!(validate_main_helper_declaration(
                &serde_json::to_vec(&malformed).expect("json")
            )
            .is_err());
        }
        let mut unknown = declaration.clone();
        unknown["fallback"] = serde_json::json!(true);
        assert!(
            validate_main_helper_declaration(&serde_json::to_vec(&unknown).expect("json")).is_err()
        );
        let mut wrong_schema = declaration.clone();
        wrong_schema["schema"] = serde_json::json!("unsupported");
        assert!(validate_main_helper_declaration(
            &serde_json::to_vec(&wrong_schema).expect("json")
        )
        .is_err());
        let mut wrong_entry = declaration;
        wrong_entry["main_entry_sha256"] = serde_json::json!(source);
        assert!(
            validate_main_helper_declaration(&serde_json::to_vec(&wrong_entry).expect("json"))
                .is_err()
        );
        assert!(validate_main_helper_declaration(b"not json").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_bound_main_helper_store_rule_is_exact_and_root_owned() {
        let correct = Path::new("/nix/store/package/bin/maco");
        validate_source_bound_helper_layout(correct).expect("exact layout");
        for wrong in [
            "/home/example/bin/maco",
            "/nix/store-other/package/bin/maco",
            "/nix/store/package/bin/libtest",
            "/nix/store/package/nested/bin/maco",
            "/nix/store/package/../other/bin/maco",
            "/nix/store/package/./bin/maco",
            "/nix//store/package/bin/maco",
            "/nix/store/package/bin/maco/",
        ] {
            assert!(
                validate_source_bound_helper_layout(Path::new(wrong)).is_err(),
                "{wrong}"
            );
        }
        assert!(source_bound_store_anchor_allowed(0, 0o1775, true, false));
        assert!(source_bound_store_anchor_allowed(0, 0o0755, true, false));
        for (owner, mode, directory, symlink) in [
            (1000, 0o1775, true, false),
            (0, 0o0775, true, false),
            (0, 0o1777, true, false),
            (0, 0o1775, false, false),
            (0, 0o1775, true, true),
            (0, 0o3775, true, false),
        ] {
            assert!(!source_bound_store_anchor_allowed(
                owner, mode, directory, symlink
            ));
        }
        // The default helper policy still rejects a writable ancestor. A
        // user-owned libtest executable cannot qualify through the new policy.
        let temp = tempfile::tempdir().expect("tempdir");
        let anchor = temp.path().join("anchor");
        fs::create_dir(&anchor).expect("anchor");
        let helper = anchor.join("maco");
        executable(&helper, b"test-only path metadata");
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o1775)).expect("sticky anchor");
        let owner = fs::symlink_metadata(&anchor).expect("metadata").uid();
        assert!(validate_helper_path_from_anchor(&helper, &anchor, owner).is_err());
        assert!(
            validate_source_bound_helper_path(&env::current_exe().expect("libtest path")).is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_bound_main_helper_descriptor_preserves_git_binding_and_rejects_mode_substitution() {
        // This is parser coverage, not a qualified or executed main helper.
        let temp = tempfile::tempdir().expect("tempdir");
        let program = temp.path().join("git");
        executable(&program, b"descriptor fixture");
        let pinned = PinnedDirectExecutable::capture_for_test(&program).expect("capture fixture");
        let arguments = [
            OsString::from("diff"),
            OsString::from("--check"),
            OsString::from("--"),
            OsString::from("assigned.txt"),
        ];
        let encoded = pinned
            .encode_descriptor(&arguments, &[])
            .expect("v1 encode");
        assert_eq!(
            encoded.bytes()[REQUEST_MAGIC.len()],
            PINNED_EXEC_REQUEST_VERSION
        );
        let original =
            decode_verified_descriptor(encoded.bytes(), OsStr::new(&encoded.digest_hex()))
                .expect("v1 decode");
        original.validate_helper_mode(false).expect("implicit mode");
        assert!(original.validate_helper_mode(true).is_err());
        let mut bytes = encoded.bytes().to_vec();
        bytes[REQUEST_MAGIC.len()] = SOURCE_BOUND_REQUEST_VERSION;
        // Append exactly the new v2 fields to the otherwise unchanged v1
        // Git request. No fixture capability is released to the launcher.
        encode_binding(&mut bytes, &pinned.source).expect("helper metadata field");
        let source = sha256(b"frozen source manifest").expect("source digest");
        bytes.extend_from_slice(&source);
        for value in [1u64, 2, 0o444, 3] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&sha256(b"declaration").expect("declaration digest"));
        for value in [1u64, 4, 0o444, 5] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        let digest = hex_encode(&sha256(&bytes).expect("descriptor digest"));
        let request = decode_verified_descriptor(&bytes, OsStr::new(&digest)).expect("v2 decode");
        assert_eq!(request.source, original.source);
        assert!(request.script == original.script);
        assert_eq!(request.arguments, original.arguments);
        assert_eq!(request.environment, original.environment);
        assert_eq!(
            request
                .main_helper
                .as_ref()
                .expect("explicit helper")
                .source_sha256,
            source
        );
        request.validate_helper_mode(true).expect("explicit mode");
        assert!(request.validate_helper_mode(false).is_err());
        assert!(request
            .main_helper
            .as_ref()
            .expect("helper")
            .revalidate()
            .is_err());
        *bytes.last_mut().expect("source digest byte") ^= 1;
        assert!(decode_verified_descriptor(&bytes, OsStr::new(&digest)).is_err());
        bytes.pop();
        let truncated_digest = hex_encode(&sha256(&bytes).expect("truncated digest"));
        assert!(decode_verified_descriptor(&bytes, OsStr::new(&truncated_digest)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_bound_helper_open_binding_rejects_replacement_symlink_and_content_drift() {
        // Exercise the same no-follow/hash/metadata primitive used during
        // helper revalidation, without granting root trust to a fixture.
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("maco");
        executable(&path, b"original executable");
        let (binding, _) = capture_executable_binding(&path).expect("capture identity");
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .expect("open binding");
        verify_open_binding(&file, &binding).expect("unchanged metadata");
        let (hash, _, _) =
            hash_reader_with_prefix(&mut file, MAX_EXECUTABLE_BYTES).expect("hash unchanged");
        assert_eq!(hash, binding.sha256);
        let old = temp.path().join("old");
        fs::rename(&path, &old).expect("move old");
        executable(&path, b"original executable");
        let replacement = File::open(&path).expect("replacement");
        assert!(verify_open_binding(&replacement, &binding).is_err());
        fs::remove_file(&path).expect("remove replacement");
        std::os::unix::fs::symlink(&old, &path).expect("symlink");
        assert!(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .is_err());
        assert!(validate_helper_path_from_anchor(
            &path,
            temp.path(),
            fs::metadata(temp.path()).expect("owner").uid()
        )
        .is_err());
        fs::remove_file(&path).expect("remove symlink");
        fs::rename(&old, &path).expect("restore inode");
        fs::write(&path, b"modified executable").expect("same-length content drift");
        let mut changed = File::open(&path).expect("changed inode");
        verify_open_binding(&changed, &binding).expect("same metadata");
        let (hash, _, _) =
            hash_reader_with_prefix(&mut changed, MAX_EXECUTABLE_BYTES).expect("hash drift");
        assert_ne!(hash, binding.sha256);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_digest_and_canonical_decode_reject_mutation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("program");
        executable(&path, b"native fixture bytes");
        let pinned = PinnedDirectExecutable::capture_for_test(&path).expect("capture");
        let encoded = pinned
            .encode_descriptor(&[OsString::from("--flag"), OsString::from("value")], &[])
            .expect("encode");
        let request =
            decode_verified_descriptor(encoded.bytes(), OsStr::new(&encoded.digest_hex()))
                .expect("decode verified request");
        let plan = request.prepare_exec_plan(99).expect("native plan");
        assert_eq!(plan.argv().len(), 3);
        assert_eq!(
            plan.script_descriptor_policy(),
            ExecDescriptorPolicy::CloseOnExec
        );

        let mut mutated = encoded.bytes().to_vec();
        let last = mutated.last_mut().expect("descriptor byte");
        *last ^= 1;
        let error = decode_verified_descriptor(&mutated, OsStr::new(&encoded.digest_hex()))
            .expect_err("mutated descriptor must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_descriptor_is_identity_checked_and_removed_on_success_and_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let program = temp.path().join("program");
        executable(&program, b"native fixture bytes");
        let pinned = PinnedDirectExecutable::capture_for_test(&program).expect("capture");
        let encoded = pinned.encode_descriptor(&[], &[]).expect("encode");
        let descriptor_path = temp.path().join(PINNED_EXEC_DESCRIPTOR_NAME);
        fs::write(&descriptor_path, encoded.bytes()).expect("write descriptor");
        fs::set_permissions(&descriptor_path, fs::Permissions::from_mode(0o600))
            .expect("chmod descriptor");
        load_verified_descriptor_and_remove(&descriptor_path, OsStr::new(&encoded.digest_hex()))
            .expect("load descriptor");
        assert!(!descriptor_path.exists());

        fs::write(&descriptor_path, encoded.bytes()).expect("rewrite descriptor");
        fs::set_permissions(&descriptor_path, fs::Permissions::from_mode(0o600))
            .expect("chmod descriptor");
        let error = load_verified_descriptor_and_remove(
            &descriptor_path,
            OsStr::new("0000000000000000000000000000000000000000000000000000000000000000"),
        )
        .expect_err("wrong digest must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!descriptor_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_replacement_and_same_inode_content_drift_fail_materialization() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("program");
        executable(&path, b"original executable");
        let pinned = PinnedDirectExecutable::capture_for_test(&path).expect("capture");
        let request = decode_verified_descriptor(
            pinned.encode_descriptor(&[], &[]).expect("encode").bytes(),
            OsStr::new(
                &pinned
                    .encode_descriptor(&[], &[])
                    .expect("encode")
                    .digest_hex(),
            ),
        );
        assert!(request.is_ok());

        let old = temp.path().join("old");
        fs::rename(&path, &old).expect("rename original");
        executable(&path, b"original executable");
        let error = materialize_sealed(&pinned.source).expect_err("replacement must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        fs::remove_file(&path).expect("remove replacement");
        fs::rename(&old, &path).expect("restore original inode");
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open original inode");
        file.write_all(b"drifted executable!")
            .expect("rewrite same inode");
        let error = materialize_sealed(&pinned.source).expect_err("hash drift must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_memfd_refuses_writes_and_starts_cloexec() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("program");
        executable(&path, b"sealed executable fixture");
        let pinned = PinnedDirectExecutable::capture_for_test(&path).expect("capture");
        let mut sealed = materialize_sealed(&pinned.source).expect("materialize");
        let write_error = sealed
            .file_mut()
            .write_all(b"x")
            .expect_err("sealed write must fail");
        assert_eq!(write_error.raw_os_error(), Some(libc::EPERM));
        // SAFETY: F_GETFD reads flags from the live descriptor owned by `sealed`.
        let flags = unsafe { libc::fcntl(sealed.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn script_plan_pins_interpreter_and_builds_proc_fd_argv() {
        let temp = tempfile::tempdir().expect("tempdir");
        let interpreter = temp.path().join("interpreter");
        executable(&interpreter, b"native interpreter fixture");
        let script = temp.path().join("script");
        let script_bytes = format!("#!{} -safe\necho test\n", interpreter.display());
        executable(&script, script_bytes.as_bytes());
        let pinned = PinnedDirectExecutable::capture_for_test(&script).expect("capture script");
        let encoded = pinned
            .encode_descriptor(&[OsString::from("payload")], &[])
            .expect("encode script descriptor");
        let request =
            decode_verified_descriptor(encoded.bytes(), OsStr::new(&encoded.digest_hex()))
                .expect("decode script request");
        let plan = request.prepare_exec_plan(41).expect("script plan");
        assert!(plan.script().is_some());
        assert_eq!(
            plan.executable(),
            request.script.as_ref().map(|s| &s.interpreter).unwrap()
        );
        assert_eq!(plan.argv()[1], b"-safe");
        assert_eq!(plan.argv()[2], b"/proc/self/fd/41");
        assert_eq!(plan.argv()[3], b"payload");
        assert_eq!(
            plan.script_descriptor_policy(),
            ExecDescriptorPolicy::RetainForScriptPath
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_script_fexecve_runs_with_retained_proc_fd() {
        const CHILD: &str = "MACO_TEST_PINNED_SCRIPT_FEXECVE_CHILD";
        const SCRIPT: &str = "MACO_TEST_PINNED_SCRIPT_PATH";
        const MARKER: &str = "MACO_TEST_PINNED_SCRIPT_MARKER";
        if let (Some(script), Some(marker)) = (env::var_os(SCRIPT), env::var_os(MARKER)) {
            if env::var_os(CHILD).is_some() {
                let pinned = PinnedDirectExecutable::capture_for_test(Path::new(&script))
                    .expect("capture script in isolated child");
                let encoded = pinned
                    .encode_descriptor(&[marker], &[])
                    .expect("encode script in isolated child");
                let request =
                    decode_verified_descriptor(encoded.bytes(), OsStr::new(&encoded.digest_hex()))
                        .expect("decode script in isolated child");
                execute_verified_request(request)
                    .expect("sealed script fexecve must replace the isolated child");
                panic!("sealed script fexecve returned unexpectedly");
            }
        }

        let temp = tempfile::tempdir().expect("tempdir");
        let script = temp.path().join("script");
        let marker = temp.path().join("marker");
        executable(&script, b"#!/bin/sh\nprintf sealed-exec > \"$1\"\n");
        let current = env::current_exe().expect("current test executable");
        let status = std::process::Command::new(current)
            .arg("--exact")
            .arg("pinned_exec::tests::sealed_script_fexecve_runs_with_retained_proc_fd")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env(SCRIPT, &script)
            .env(MARKER, &marker)
            .status()
            .expect("spawn isolated sealed-script test");
        assert!(status.success(), "isolated sealed-script status: {status}");
        assert_eq!(
            fs::read_to_string(marker).expect("read sealed script marker"),
            "sealed-exec"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_native_fexecve_runs_from_memfd() {
        const CHILD: &str = "MACO_TEST_PINNED_NATIVE_FEXECVE_CHILD";
        if env::var_os(CHILD).is_some() {
            let true_path = [
                Path::new("/usr/bin/true"),
                Path::new("/bin/true"),
                Path::new("/run/current-system/sw/bin/true"),
            ]
            .into_iter()
            .find(|path| path.exists())
            .expect("true executable");
            let pinned = PinnedDirectExecutable::capture_for_test(true_path)
                .expect("capture true in isolated child");
            let encoded = pinned
                .encode_descriptor(&[], &[])
                .expect("encode true in isolated child");
            let request =
                decode_verified_descriptor(encoded.bytes(), OsStr::new(&encoded.digest_hex()))
                    .expect("decode true in isolated child");
            execute_verified_request(request)
                .expect("sealed native fexecve must replace the isolated child");
            panic!("sealed native fexecve returned unexpectedly");
        }

        let current = env::current_exe().expect("current test executable");
        let status = std::process::Command::new(current)
            .arg("--exact")
            .arg("pinned_exec::tests::sealed_native_fexecve_runs_from_memfd")
            .arg("--nocapture")
            .env(CHILD, "1")
            .status()
            .expect("spawn isolated sealed-native test");
        assert!(status.success(), "isolated sealed-native status: {status}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn env_dispatcher_shebang_is_rejected_including_dash_s() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dispatcher = temp.path().join("env");
        executable(&dispatcher, b"native dispatcher fixture");
        for suffix in ["python", "-S python -I"] {
            let script = temp.path().join(suffix.replace(' ', "-"));
            let script_bytes = format!("#!{} {suffix}\nprint('test')\n", dispatcher.display());
            executable(&script, script_bytes.as_bytes());
            let error = PinnedDirectExecutable::capture_for_test(&script)
                .expect_err("env dispatcher shebang must fail closed");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn argument_and_descriptor_bounds_fail_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("program");
        executable(&path, b"native fixture bytes");
        let pinned = PinnedDirectExecutable::capture_for_test(&path).expect("capture");
        let oversized = OsString::from_vec(vec![b'a'; MAX_PINNED_ARGUMENT_BYTES + 1]);
        let error = pinned
            .encode_descriptor(&[oversized], &[])
            .expect_err("oversized argument must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        let oversized_descriptor = vec![0u8; MAX_DESCRIPTOR_BYTES + 1];
        let error = validate_descriptor_digest(
            &oversized_descriptor,
            OsStr::new("0000000000000000000000000000000000000000000000000000000000000000"),
        )
        .expect_err("oversized descriptor must fail");
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn loader_and_interpreter_hook_environment_is_rejected_before_encoding() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("program");
        executable(&path, b"native fixture bytes");
        let pinned = PinnedDirectExecutable::capture_for_test(&path).expect("capture");
        for key in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "BASH_ENV",
            "PYTHONPATH",
            "PERL5OPT",
            "RUBYOPT",
            "NODE_OPTIONS",
            "GCONV_PATH",
        ] {
            let error = pinned
                .encode_descriptor(
                    &[],
                    &[(OsString::from(key), OsString::from("/untrusted/hook"))],
                )
                .expect_err("code-loading hook must fail closed");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{key}");
        }

        let encoded = pinned
            .encode_descriptor(
                &[],
                &[
                    (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
                    (OsString::from("HOME"), OsString::from("/private/home")),
                ],
            )
            .expect("safe environment");
        let request =
            decode_verified_descriptor(encoded.bytes(), OsStr::new(&encoded.digest_hex()))
                .expect("decode environment");
        assert_eq!(request.environment.len(), 2);
        assert_eq!(request.environment[0].0, b"HOME");
        assert_eq!(request.environment[1].0, b"PATH");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_path_requires_immutable_owned_ancestors_and_target() {
        // The injected owner/anchor variant exercises the same traversal as the root-only public
        // validator without requiring tests to manufacture root-owned fixtures.
        let temp = tempfile::tempdir().expect("tempdir");
        let anchor = temp.path().join("trusted");
        fs::create_dir(&anchor).expect("create trust anchor");
        fs::set_permissions(&anchor, fs::Permissions::from_mode(0o700)).expect("chmod anchor");
        let bin = anchor.join("bin");
        fs::create_dir(&bin).expect("create bin");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod bin");
        let helper = bin.join("maco");
        executable(&helper, b"helper fixture");
        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let owner = unsafe { libc::geteuid() };
        validate_helper_path_from_anchor(&helper, &anchor, owner).expect("trusted helper");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o777)).expect("loosen bin");
        let error = validate_helper_path_from_anchor(&helper, &anchor, owner)
            .expect_err("writable ancestor must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_fails_closed() {
        let error = PinnedDirectExecutable::capture(Path::new("program"))
            .expect_err("non-Linux capture must fail");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
