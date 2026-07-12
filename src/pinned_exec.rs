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
        Ok(Self { source, script })
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn capture_for_test(path: &Path) -> io::Result<Self> {
        Self::capture_source(path)
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
            bytes.push(PINNED_EXEC_REQUEST_VERSION);
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
        if cursor.read_u8()? != PINNED_EXEC_REQUEST_VERSION {
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
    if marker != OsStr::new(HIDDEN_PINNED_EXEC_ARGUMENT) {
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
        validated_current_helper_path()?;
        validate_current_environment()?;
        let request = load_verified_descriptor_and_remove(Path::new(&descriptor_path), &digest)?;
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
fn execute_verified_request(request: VerifiedPinnedExecRequest) -> io::Result<()> {
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

    let copied_hash = copy_and_hash(&mut source, &mut destination, binding.length)?;
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
    let verified_hash = hash_reader(&mut destination, binding.length)?;
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
fn validate_helper_component(path: &Path, owner: u32, final_component: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| opaque_io(error, "could not inspect fixed helper path"))?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != owner
        || permission_mode(&metadata) & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixed helper path was not owner-controlled and immutable",
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
fn copy_and_hash(source: &mut File, destination: &mut File, expected: u64) -> io::Result<[u8; 32]> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| opaque_io(error, "could not rewind pinned executable source"))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
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
    let mut hasher = Sha256::new();
    let mut prefix = Vec::with_capacity(MAX_SHEBANG_BYTES.saturating_add(1));
    let mut total = 0u64;
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    loop {
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
        os::unix::{ffi::OsStringExt, fs::PermissionsExt},
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

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            hex_encode(&sha256(b"abc").expect("sha256")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
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
