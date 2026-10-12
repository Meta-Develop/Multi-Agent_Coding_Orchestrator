//! Headless account-authority service: Unix socket listen + accept loop.

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use coding_agent_manager_lib::account_authority::{
    listen, resolve_socket_path, AuthorityContext, AuthorityServerConfig, ListenError,
    StoredAccountRegistry,
};
use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::login::LoginService;
use coding_agent_manager_lib::paths;
use coding_agent_manager_lib::providers::gemini_cli::GeminiCliAdapter;

const SOCKET_ENV: &str = "CAM_ACCOUNT_AUTHORITY_SOCKET";

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "--relay") {
        // The client path cannot instantiate a registry, runtime, login service,
        // listener or provider. It forwards exactly one existing protocol RPC.
        return relay::run(&args[1..]);
    }
    let configured = configured_socket_path()?;
    let safe = resolve_socket_path(&configured).map_err(|error| error.to_string())?;

    let registry = stored_account_registry().map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let service = LoginService::new(
        StoredAccountRegistry::new(registry.metadata_path().to_path_buf()),
        runtime.handle().clone(),
    );
    let ctx = AuthorityContext::new(registry);
    let config = AuthorityServerConfig::new(ctx)
        .map_err(|error| error.to_string())?
        .with_gemini_login(service, GeminiCliAdapter::default());

    let listener = listen(safe, config).map_err(listen_failure)?;

    #[cfg(unix)]
    {
        let bound = listener.path().display();
        let _ = writeln!(io::stderr(), "account-authority listening on {bound}");
        loop {
            if let Err(error) = listener.accept_once() {
                let _ = writeln!(io::stderr(), "accept failed: {error}");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = listener;
        Err("unix socket transport is unsupported on this platform".to_string())
    }
}

fn listen_failure(error: ListenError) -> String {
    error.to_string()
}

fn stored_account_registry() -> Result<StoredAccountRegistry, Error> {
    let dirs = paths::project_dirs().ok_or_else(|| Error::ConfigRead {
        provider: "account-metadata".to_string(),
        reason: "the application data directory could not be resolved".to_string(),
    })?;
    Ok(StoredAccountRegistry::new(paths::stored_accounts_path(
        dirs.data_dir(),
    )))
}

/// Operator-supplied socket path from `--socket-path` or [`SOCKET_ENV`].
pub fn configured_socket_path() -> Result<PathBuf, String> {
    configured_socket_path_from(
        env::args().skip(1).collect::<Vec<_>>().as_slice(),
        env::var(SOCKET_ENV).ok(),
    )
}

fn configured_socket_path_from(
    args: &[String],
    env_value: Option<String>,
) -> Result<PathBuf, String> {
    let mut from_flag: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            "--socket-path" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--socket-path requires a value".to_string())?;
                from_flag = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                return Err(format!("unknown argument: {unknown} (try --help)"));
            }
        }
    }

    if let Some(path) = from_flag {
        if path.as_os_str().is_empty() {
            return Err(format!(
                "socket path is required: pass --socket-path PATH or set {SOCKET_ENV}"
            ));
        }
        return Ok(path);
    }
    if let Some(path) = env_value {
        if path.is_empty() {
            return Err(format!(
                "socket path is required: pass --socket-path PATH or set {SOCKET_ENV}"
            ));
        }
        return Ok(PathBuf::from(path));
    }
    Err(format!(
        "socket path is required: pass --socket-path PATH or set {SOCKET_ENV}"
    ))
}

fn print_usage() {
    let _ = writeln!(
        io::stderr(),
        "Usage: account-authority --socket-path PATH\n\
         Environment: {SOCKET_ENV} (used when --socket-path is omitted)\n\
         Installed client: --relay --socket-path PATH --expected-uid UID \
         --expected-helper PATH --helper-elf-sha256 HEX \
         --source-manifest-sha256 HEX --authority-id HEX"
    );
}

mod relay {
    use super::*;

    #[cfg(target_os = "linux")]
    const APPROVED_LAUNCHER: &str = "/usr/local/libexec/maco-account-authority";

    struct Binding {
        socket: PathBuf,
        uid: u32,
        helper: PathBuf,
        elf_sha: String,
        manifest_sha: String,
        authority_id: String,
    }

    fn absolute_path(value: &str) -> bool {
        value.starts_with('/')
            && !value.ends_with('/')
            && value.len() <= 4096
            && value.split('/').skip(1).all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
    }

    fn digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    fn parse(args: &[String]) -> Result<Binding, String> {
        let mut flags = std::collections::BTreeMap::new();
        if args.len() != 12 {
            return Err("invalid relay binding arguments".into());
        }
        for pair in args.chunks_exact(2) {
            if !matches!(
                pair[0].as_str(),
                "--socket-path"
                    | "--expected-uid"
                    | "--expected-helper"
                    | "--helper-elf-sha256"
                    | "--source-manifest-sha256"
                    | "--authority-id"
            ) || flags.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err("invalid relay binding arguments".into());
            }
        }
        // Six flag/value pairs; no environment defaults are used in relay mode.
        let get = |key| {
            flags
                .get(key)
                .copied()
                .ok_or_else(|| "missing relay binding".to_string())
        };
        let socket = get("--socket-path")?;
        let helper = get("--expected-helper")?;
        let uid_text = get("--expected-uid")?;
        let uid = uid_text
            .parse::<u32>()
            .map_err(|_| "invalid relay principal")?;
        let elf_sha = get("--helper-elf-sha256")?;
        let manifest_sha = get("--source-manifest-sha256")?;
        let authority_id = get("--authority-id")?;
        if uid == 0
            || uid.to_string() != uid_text
            || !absolute_path(socket)
            || socket.len() > 107
            || !absolute_path(helper)
            || !helper.ends_with("/bin/account-authority")
            || !digest(elf_sha)
            || !digest(manifest_sha)
            || !digest(authority_id)
        {
            return Err("invalid relay binding".into());
        }
        Ok(Binding {
            socket: socket.into(),
            uid,
            helper: helper.into(),
            elf_sha: elf_sha.into(),
            manifest_sha: manifest_sha.into(),
            authority_id: authority_id.into(),
        })
    }

    pub fn run(args: &[String]) -> Result<(), String> {
        let binding = parse(args)?;
        #[cfg(target_os = "linux")]
        {
            linux::run(binding)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                binding.socket,
                binding.uid,
                binding.helper,
                binding.elf_sha,
                binding.manifest_sha,
                binding.authority_id,
            );
            Err("installed authority relay requires Linux".into())
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use coding_agent_manager_lib::account_authority::{
            decode_request, AuthorityResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
            PROTOCOL_VERSION, REQUEST_IO_DEADLINE,
        };
        use sha2::{Digest, Sha256};
        use std::fs::{self, File, OpenOptions};
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, FromRawFd, RawFd};
        use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
        use std::os::unix::net::UnixStream;
        use std::path::{Component, Path};
        use std::time::Instant;

        fn root_protected(uid: u32, mode: u32) -> bool {
            uid == 0 && mode & 0o022 == 0
        }

        fn source_bound_store_anchor_allowed(
            path: &Path,
            uid: u32,
            mode: u32,
            directory: bool,
            symlink: bool,
        ) -> bool {
            let mode = mode & 0o7777;
            path.as_os_str() == Path::new("/nix/store").as_os_str()
                && uid == 0
                && directory
                && !symlink
                && mode & 0o002 == 0
                && (mode & 0o020 == 0 || mode & 0o1000 != 0)
                && mode & 0o6000 == 0
        }

        fn protected_file(path: &Path) -> Result<File, String> {
            let mut current = PathBuf::new();
            for part in path.components() {
                if !matches!(part, Component::RootDir | Component::Normal(_)) {
                    return Err("invalid immutable package path".into());
                }
                current.push(part.as_os_str());
                let metadata =
                    fs::symlink_metadata(&current).map_err(|_| "immutable package unavailable")?;
                let protected_component = if current != path
                    && current.as_os_str() == Path::new("/nix/store").as_os_str()
                {
                    source_bound_store_anchor_allowed(
                        &current,
                        metadata.uid(),
                        metadata.mode(),
                        metadata.is_dir(),
                        metadata.file_type().is_symlink(),
                    )
                } else {
                    root_protected(metadata.uid(), metadata.mode())
                };
                if metadata.file_type().is_symlink()
                    || !protected_component
                    || (current != path && !metadata.is_dir())
                {
                    return Err("immutable package ancestry is not root-protected".into());
                }
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|_| "immutable package unavailable")?;
            let metadata = file
                .metadata()
                .map_err(|_| "immutable package unavailable")?;
            if !metadata.is_file() || !root_protected(metadata.uid(), metadata.mode()) {
                return Err("immutable package file is not root-protected".into());
            }
            Ok(file)
        }

        fn sha(mut file: File, deadline: Instant) -> Result<String, String> {
            let mut hasher = Sha256::new();
            let mut bytes = [0; 65536];
            loop {
                if Instant::now() >= deadline {
                    return Err("relay deadline elapsed".into());
                }
                let size = file
                    .read(&mut bytes)
                    .map_err(|_| "cannot verify immutable package")?;
                if size == 0 {
                    break;
                }
                hasher.update(&bytes[..size]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }

        fn package(binding: &Binding, deadline: Instant) -> Result<fs::Metadata, String> {
            let helper = protected_file(&binding.helper)?;
            let helper_metadata = helper
                .metadata()
                .map_err(|_| "package identity unavailable")?;
            let loaded =
                File::open("/proc/self/exe").map_err(|_| "loaded executable unavailable")?;
            let loaded_metadata = loaded
                .metadata()
                .map_err(|_| "loaded executable unavailable")?;
            if helper_metadata.dev() != loaded_metadata.dev()
                || helper_metadata.ino() != loaded_metadata.ino()
                || fs::read_link("/proc/self/exe").map_err(|_| "loaded executable unavailable")?
                    != binding.helper
            {
                return Err("loaded executable does not match installed package".into());
            }
            let launcher = Path::new(APPROVED_LAUNCHER);
            // Only the fixed root-owned launcher may be a symlink. Its complete
            // parent ancestry and resolved target must be protected by root.
            let mut current = PathBuf::new();
            for part in launcher.components() {
                current.push(part.as_os_str());
                let metadata =
                    fs::symlink_metadata(&current).map_err(|_| "approved launcher unavailable")?;
                if current == launcher && metadata.file_type().is_symlink() {
                    if metadata.uid() != 0 {
                        return Err("approved launcher has wrong owner".into());
                    }
                } else if !root_protected(metadata.uid(), metadata.mode())
                    || metadata.file_type().is_symlink()
                {
                    return Err("approved launcher is not root-protected".into());
                }
            }
            if fs::canonicalize(launcher).map_err(|_| "approved launcher unavailable")?
                != binding.helper
                || sha(loaded, deadline)? != binding.elf_sha
            {
                return Err("approved launcher package identity mismatch".into());
            }
            let package_root = binding
                .helper
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| "invalid package root".to_string())?;
            if sha(
                protected_file(&package_root.join("source-manifest.json"))?,
                deadline,
            )? != binding.manifest_sha
            {
                return Err("installed source manifest mismatch".into());
            }
            Ok(helper_metadata)
        }

        fn wait(fd: RawFd, events: i16, deadline: Instant) -> Result<(), String> {
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("relay deadline elapsed".into());
                }
                let mut poll = libc::pollfd {
                    fd,
                    events,
                    revents: 0,
                };
                // SAFETY: poll points at a live single-element array.
                let result = unsafe {
                    libc::poll(
                        &mut poll,
                        1,
                        remaining.as_millis().clamp(1, i32::MAX as u128) as i32,
                    )
                };
                if result > 0 {
                    if poll.revents & libc::POLLNVAL != 0 {
                        return Err("relay descriptor unavailable".into());
                    }
                    return Ok(());
                }
                if result == 0 {
                    return Err("relay deadline elapsed".into());
                }
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return Err("relay I/O unavailable".into());
                }
            }
        }

        fn read_exact<T: Read + AsRawFd>(
            input: &mut T,
            mut bytes: &mut [u8],
            deadline: Instant,
        ) -> Result<(), String> {
            while !bytes.is_empty() {
                wait(input.as_raw_fd(), libc::POLLIN, deadline)?;
                match input.read(bytes) {
                    Ok(0) => return Err("truncated relay frame".into()),
                    Ok(count) => bytes = &mut bytes[count..],
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                        ) => {}
                    Err(_) => return Err("relay read failed".into()),
                }
            }
            Ok(())
        }

        fn write_all<T: Write + AsRawFd>(
            output: &mut T,
            mut bytes: &[u8],
            deadline: Instant,
        ) -> Result<(), String> {
            while !bytes.is_empty() {
                wait(output.as_raw_fd(), libc::POLLOUT, deadline)?;
                match output.write(bytes) {
                    Ok(0) => return Err("relay write failed".into()),
                    Ok(count) => bytes = &bytes[count..],
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                        ) => {}
                    Err(_) => return Err("relay write failed".into()),
                }
            }
            Ok(())
        }

        fn read_frame<T: Read + AsRawFd>(
            input: &mut T,
            limit: usize,
            deadline: Instant,
        ) -> Result<Vec<u8>, String> {
            let mut length = [0; 4];
            read_exact(input, &mut length, deadline)?;
            let size = u32::from_be_bytes(length) as usize;
            if size == 0 || size > limit {
                return Err("invalid relay frame length".into());
            }
            let mut bytes = vec![0; size];
            read_exact(input, &mut bytes, deadline)?;
            Ok(bytes)
        }

        fn write_frame<T: Write + AsRawFd>(
            output: &mut T,
            bytes: &[u8],
            deadline: Instant,
        ) -> Result<(), String> {
            write_all(output, &(bytes.len() as u32).to_be_bytes(), deadline)?;
            write_all(output, bytes, deadline)
        }

        fn nonblocking(fd: RawFd) -> Result<(), String> {
            // SAFETY: fd belongs to a live File/UnixStream.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                    return Err("relay descriptor unavailable".into());
                }
            }
            Ok(())
        }

        fn stdio(fd: RawFd) -> Result<File, String> {
            // SAFETY: duplicate the standard descriptor; File takes sole ownership.
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                return Err("relay standard I/O unavailable".into());
            }
            let file = unsafe { File::from_raw_fd(duplicate) };
            nonblocking(file.as_raw_fd())?;
            Ok(file)
        }

        fn connect(
            binding: &Binding,
            package: &fs::Metadata,
            deadline: Instant,
        ) -> Result<(UnixStream, i32), String> {
            resolve_socket_path(&binding.socket).map_err(|_| "unsafe authority socket ancestry")?;
            let parent = binding
                .socket
                .parent()
                .ok_or("missing private socket directory")?;
            for path in [parent, binding.socket.as_path()] {
                let metadata =
                    fs::symlink_metadata(path).map_err(|_| "authority socket unavailable")?;
                if metadata.uid() != binding.uid
                    || metadata.mode() & 0o077 != 0
                    || (path == parent && !metadata.is_dir())
                    || (path != parent && !metadata.file_type().is_socket())
                {
                    return Err("authority socket is not owner-private".into());
                }
            }
            // Nonblocking connect bounds even a full Unix socket listen backlog.
            let fd = unsafe {
                libc::socket(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                )
            };
            if fd < 0 {
                return Err("authority connection unavailable".into());
            }
            let stream = unsafe { UnixStream::from_raw_fd(fd) };
            let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            address.sun_family = libc::AF_UNIX as libc::sa_family_t;
            use std::os::unix::ffi::OsStrExt;
            let path = binding.socket.as_os_str().as_bytes();
            if path.len() >= address.sun_path.len() {
                return Err("invalid authority socket length".into());
            }
            for (to, from) in address.sun_path.iter_mut().zip(path) {
                *to = *from as libc::c_char;
            }
            let result = unsafe {
                libc::connect(
                    fd,
                    (&address as *const libc::sockaddr_un).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            if result != 0 {
                if io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
                    return Err("authority connection unavailable".into());
                }
                wait(fd, libc::POLLOUT, deadline)?;
                if stream
                    .take_error()
                    .map_err(|_| "authority connection unavailable")?
                    .is_some()
                {
                    return Err("authority connection unavailable".into());
                }
            }
            let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
            let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut peer as *mut libc::ucred).cast(),
                    &mut size,
                )
            };
            if result != 0
                || size as usize != std::mem::size_of_val(&peer)
                || peer.uid != binding.uid
                || peer.pid <= 0
            {
                return Err("authority server principal mismatch".into());
            }
            let server = fs::metadata(format!("/proc/{}/exe", peer.pid))
                .map_err(|_| "authority server identity unavailable")?;
            if server.dev() != package.dev() || server.ino() != package.ino() {
                return Err("authority server package mismatch".into());
            }
            Ok((stream, peer.pid))
        }

        fn response(bytes: &[u8], id: &str) -> Result<AuthorityResponse, String> {
            let response: AuthorityResponse =
                serde_json::from_slice(bytes).map_err(|_| "invalid authority response")?;
            if response.protocol_version != PROTOCOL_VERSION
                || response.request_id != id
                || response.error.is_some() == response.result.is_some()
            {
                return Err("authority response identity mismatch".into());
            }
            Ok(response)
        }

        pub(super) fn run(binding: Binding) -> Result<(), String> {
            let deadline = Instant::now() + REQUEST_IO_DEADLINE;
            if unsafe { libc::geteuid() } != binding.uid || unsafe { libc::getuid() } != binding.uid
            {
                return Err("relay requires the configured non-root principal".into());
            }
            let package = package(&binding, deadline)?;
            let mut input = stdio(0)?;
            let request = read_frame(&mut input, MAX_REQUEST_BYTES, deadline)?;
            let decoded = decode_request(&request).map_err(|_| "invalid authority request")?;
            // A second frame, garbage, or a producer that never closes stdin is
            // refused before any RPC can take effect.
            let mut extra = [0];
            wait(input.as_raw_fd(), libc::POLLIN, deadline)?;
            if input
                .read(&mut extra)
                .map_err(|_| "relay input did not finish")?
                != 0
            {
                return Err("relay accepts exactly one request".into());
            }
            let describe_id = "cam-installed-relay-describe";
            let describe =
                serde_json::to_vec(&serde_json::json!({"protocolVersion": PROTOCOL_VERSION,
                "requestId": describe_id, "operation": "authority.describe"}))
                .map_err(|_| "relay encoding failed")?;
            let (mut handshake, server_pid) = connect(&binding, &package, deadline)?;
            write_frame(&mut handshake, &describe, deadline)?;
            let identity = response(
                &read_frame(&mut handshake, MAX_RESPONSE_BYTES, deadline)?,
                describe_id,
            )?;
            if identity
                .result
                .as_ref()
                .and_then(|v| v.get("authorityId"))
                .and_then(serde_json::Value::as_str)
                != Some(binding.authority_id.as_str())
            {
                return Err("authority identity mismatch".into());
            }
            drop(handshake);
            let (mut server, actual_pid) = connect(&binding, &package, deadline)?;
            if actual_pid != server_pid {
                return Err("authority server changed during relay".into());
            }
            write_frame(&mut server, &request, deadline)?;
            let reply = read_frame(&mut server, MAX_RESPONSE_BYTES, deadline)?;
            response(&reply, &decoded.request_id)?;
            let mut output = stdio(1)?;
            write_frame(&mut output, &reply, deadline)
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            #[test]
            fn root_package_policy_rejects_owner_and_writable_content() {
                assert!(root_protected(0, 0o755));
                assert!(!root_protected(1000, 0o755));
                assert!(!root_protected(0, 0o775));
                assert!(!root_protected(0, 0o777));
            }

            #[test]
            fn store_anchor_accepts_exact_root_owned_protected_directory() {
                for mode in [0o1775, 0o755, libc::S_IFDIR | 0o1775] {
                    assert!(source_bound_store_anchor_allowed(
                        Path::new("/nix/store"),
                        0,
                        mode,
                        true,
                        false,
                    ));
                }
            }

            #[test]
            fn store_anchor_rejects_unsafe_owner_mode_and_type() {
                for (uid, mode, directory, symlink) in [
                    (0, 0o775, true, false),
                    (0, 0o1777, true, false),
                    (1000, 0o1775, true, false),
                    (0, 0o1775, false, false),
                    (0, 0o1775, true, true),
                    (0, 0o3775, true, false),
                    (0, 0o5775, true, false),
                    (0, 0o2755, true, false),
                    (0, 0o4755, true, false),
                ] {
                    assert!(!source_bound_store_anchor_allowed(
                        Path::new("/nix/store"),
                        uid,
                        mode,
                        directory,
                        symlink,
                    ));
                }
            }

            #[test]
            fn sticky_store_exception_never_admits_other_ancestors_or_package_files() {
                for path in [
                    "/nix",
                    "/tmp",
                    "/nix/store-other",
                    "/nix/store/pkg",
                    "/nix/store/pkg/bin",
                ] {
                    assert!(!root_protected(0, 0o1775));
                    assert!(!source_bound_store_anchor_allowed(
                        Path::new(path),
                        0,
                        0o1775,
                        true,
                        false,
                    ));
                }
                for path in [
                    "/nix/store/pkg/bin/account-authority",
                    "/nix/store/pkg/source-manifest.json",
                ] {
                    for (uid, mode) in [(0, 0o775), (0, 0o1775), (0, 0o777), (1000, 0o555)] {
                        assert!(!root_protected(uid, mode));
                        assert!(!source_bound_store_anchor_allowed(
                            Path::new(path),
                            uid,
                            mode,
                            false,
                            false,
                        ));
                    }
                }
            }

            #[test]
            fn framing_rejects_zero_oversize_truncation_and_deadline() {
                for bytes in [
                    0u32.to_be_bytes().to_vec(),
                    ((MAX_REQUEST_BYTES + 1) as u32).to_be_bytes().to_vec(),
                    vec![0, 0, 0, 2, b'x'],
                ] {
                    let (mut writer, mut reader) = UnixStream::pair().unwrap();
                    writer.write_all(&bytes).unwrap();
                    drop(writer);
                    assert!(read_frame(
                        &mut reader,
                        MAX_REQUEST_BYTES,
                        Instant::now() + REQUEST_IO_DEADLINE
                    )
                    .is_err());
                }
                let (_writer, mut reader) = UnixStream::pair().unwrap();
                assert!(read_frame(&mut reader, MAX_REQUEST_BYTES, Instant::now()).is_err());
            }
            #[test]
            fn frame_roundtrip_keeps_bytes_and_envelope_requires_correlation() {
                let (mut writer, mut reader) = UnixStream::pair().unwrap();
                let reply = serde_json::to_vec(&AuthorityResponse::result(
                    "rpc",
                    serde_json::json!({"ok":true}),
                ))
                .unwrap();
                let deadline = Instant::now() + REQUEST_IO_DEADLINE;
                write_frame(&mut writer, &reply, deadline).unwrap();
                assert_eq!(
                    read_frame(&mut reader, MAX_RESPONSE_BYTES, deadline).unwrap(),
                    reply
                );
                assert!(response(&reply, "other").is_err());
                assert!(response(br#"{"protocolVersion":1,"requestId":"rpc","result":{},"error":{"code":"busy","message":"busy"}}"#, "rpc").is_err());
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn args() -> Vec<String> {
            [
                "--socket-path",
                "/run/user/1000/maco/account-authority.sock",
                "--expected-uid",
                "1000",
                "--expected-helper",
                "/opt/maco/package/bin/account-authority",
                "--helper-elf-sha256",
                &"a".repeat(64),
                "--source-manifest-sha256",
                &"b".repeat(64),
                "--authority-id",
                &"c".repeat(64),
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        }
        #[test]
        fn strict_relay_binding_rejects_missing_duplicate_unknown_and_root() {
            assert!(parse(&args()).is_ok());
            for (index, value) in [
                (0, "--command"),
                (3, "0"),
                (3, "01000"),
                (1, "/run/../tmp/x"),
                (5, "/tmp/shell"),
                (7, "not-a-hash"),
                (8, "--authority-id"),
            ] {
                let mut values = args();
                values[index] = value.into();
                assert!(parse(&values).is_err());
            }
            assert!(parse(&[]).is_err());
            let mut values = args();
            values.extend(["--socket-path".into(), "/tmp/x".into()]);
            assert!(parse(&values).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_socket_path_fails_closed() {
        let error = configured_socket_path_from(&[], None).expect_err("missing");
        assert!(error.contains(SOCKET_ENV));
    }

    #[test]
    fn flag_overrides_empty_env() {
        let path = configured_socket_path_from(
            &["--socket-path".to_string(), "/tmp/account.sock".to_string()],
            Some(String::new()),
        )
        .expect("flag");
        assert_eq!(path.as_os_str(), "/tmp/account.sock");
    }

    #[test]
    fn env_used_when_flag_absent() {
        let path =
            configured_socket_path_from(&[], Some("/run/account.sock".to_string())).expect("env");
        assert_eq!(path.as_os_str(), "/run/account.sock");
    }

    #[test]
    fn unknown_argument_is_rejected() {
        let error =
            configured_socket_path_from(&["--verbose".to_string()], None).expect_err("unknown");
        assert!(error.contains("--verbose"));
    }
}
