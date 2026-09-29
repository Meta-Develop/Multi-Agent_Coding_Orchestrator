use std::{
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        io::{AsRawFd, FromRawFd, OwnedFd},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::pinned_exec::{self, HIDDEN_PINNED_EXEC_ARGUMENT};

pub(crate) const HIDDEN_CLAUDE_RELAY_ARGUMENT: &str = "--maco-internal-claude-relay-v1";
pub(crate) const CLAUDE_CHILD_LOOPBACK_PORT: u16 = 38_473;
pub(crate) const CLAUDE_CHILD_LOOPBACK_BASE_URL: &str = "http://127.0.0.1:38473";

const MAX_RELAY_CONNECTIONS: usize = 16;
const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 18 * 1024 * 1024;
const IO_POLL: Duration = Duration::from_millis(100);

struct HelperRequest {
    parent_socket: PathBuf,
    deadline_unix_millis: u64,
    expected_uid: u32,
    expected_unit: String,
    registration_nonce: String,
    pinned_descriptor: OsString,
    pinned_digest: OsString,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParentEndpointIdentity {
    pid: u32,
    uid: u32,
    start_ticks: u64,
    program: PathBuf,
    socket_device: u64,
    socket_inode: u64,
}

#[derive(Clone, Copy)]
struct ParentSocketIdentity {
    device: u64,
    inode: u64,
}

pub(super) fn maybe_run_helper_from_args() -> io::Result<bool> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(marker) = arguments.next() else {
        return Ok(false);
    };
    if marker != OsStr::new(HIDDEN_CLAUDE_RELAY_ARGUMENT) {
        return Ok(false);
    }
    let request = parse_request(arguments)?;
    let code = run_helper(request)?;
    std::process::exit(code);
}

fn parse_request(mut arguments: impl Iterator<Item = OsString>) -> io::Result<HelperRequest> {
    let parent_socket = PathBuf::from(required(&mut arguments, "parent socket")?);
    let deadline_unix_millis = parse_u64(
        required(&mut arguments, "deadline")?,
        "Claude relay deadline",
    )?;
    let expected_uid = u32::try_from(parse_u64(
        required(&mut arguments, "effective uid")?,
        "Claude relay effective uid",
    )?)
    .map_err(|_| invalid("Claude relay effective uid is out of range"))?;
    let expected_unit = required(&mut arguments, "systemd unit")?
        .into_string()
        .map_err(|_| invalid("Claude relay systemd unit is not UTF-8"))?;
    if expected_unit.is_empty()
        || expected_unit.len() > 255
        || expected_unit.contains('/')
        || expected_unit.chars().any(char::is_control)
    {
        return Err(invalid("Claude relay systemd unit is malformed"));
    }
    let registration_nonce = required(&mut arguments, "helper registration nonce")?
        .into_string()
        .map_err(|_| invalid("Claude helper registration nonce is not UTF-8"))?;
    if registration_nonce.len() != 64
        || !registration_nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("Claude helper registration nonce is malformed"));
    }
    let pinned_marker = required(&mut arguments, "pinned helper marker")?;
    if pinned_marker != OsStr::new(HIDDEN_PINNED_EXEC_ARGUMENT) {
        return Err(invalid("Claude relay omitted the pinned executable helper"));
    }
    let pinned_descriptor = required(&mut arguments, "pinned descriptor")?;
    let pinned_digest = required(&mut arguments, "pinned descriptor digest")?;
    if arguments.next().is_some() {
        return Err(invalid("Claude relay helper received unexpected arguments"));
    }
    Ok(HelperRequest {
        parent_socket,
        deadline_unix_millis,
        expected_uid,
        expected_unit,
        registration_nonce,
        pinned_descriptor,
        pinned_digest,
    })
}

fn required(arguments: &mut impl Iterator<Item = OsString>, name: &str) -> io::Result<OsString> {
    arguments
        .next()
        .ok_or_else(|| invalid(format!("Claude relay helper omitted its {name}")))
}

fn parse_u64(value: OsString, name: &str) -> io::Result<u64> {
    value
        .into_string()
        .map_err(|_| invalid(format!("{name} is not UTF-8")))?
        .parse::<u64>()
        .map_err(|_| invalid(format!("{name} is invalid")))
}

fn run_helper(request: HelperRequest) -> io::Result<i32> {
    let helper = pinned_exec::validated_current_helper_path()?;
    let (cgroup, start_ticks) = validate_owner_and_cgroup(&request)?;
    let socket_identity = validate_parent_socket(&request.parent_socket, request.expected_uid)?;
    require_before_deadline(request.deadline_unix_millis)?;
    let parent_identity =
        register_with_parent(&request, &cgroup, start_ticks, socket_identity, &helper)?;

    let listener = TcpListener::bind(("127.0.0.1", CLAUDE_CHILD_LOOPBACK_PORT))?;
    listener.set_nonblocking(true)?;
    let mut child = Command::new(&helper)
        .env_clear()
        .arg(HIDDEN_PINNED_EXEC_ARGUMENT)
        .arg(&request.pinned_descriptor)
        .arg(&request.pinned_digest)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let result = supervise_child_relay(
        &mut child,
        listener,
        &request.parent_socket,
        &parent_identity,
        request.deadline_unix_millis,
    );
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait();
    result?;
    let status = status?;
    Ok(status.code().unwrap_or(1))
}

fn supervise_child_relay(
    child: &mut std::process::Child,
    listener: TcpListener,
    parent_socket: &Path,
    parent_identity: &ParentEndpointIdentity,
    deadline_unix_millis: u64,
) -> io::Result<()> {
    let expected_cgroup = read_single_cgroup(Path::new("/proc/self/cgroup"))?;
    let child_cgroup_path = PathBuf::from(format!("/proc/{}/cgroup", child.id()));
    let mut child_bound = false;
    let (result_tx, result_rx) = mpsc::channel::<io::Result<()>>();
    let mut handlers = Vec::new();
    let mut accepted = 0usize;

    loop {
        require_before_deadline(deadline_unix_millis)?;
        if !child_bound {
            match read_single_cgroup(&child_cgroup_path) {
                Ok(observed) if observed == expected_cgroup => child_bound = true,
                Ok(_) => {
                    return Err(io::Error::other(
                        "Claude native child escaped its relay cgroup",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        while let Ok(result) = result_rx.try_recv() {
            result?;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                accepted = accepted.saturating_add(1);
                if accepted > MAX_RELAY_CONNECTIONS {
                    return Err(io::Error::other(
                        "Claude native child exceeded its relay connection bound",
                    ));
                }
                let socket = parent_socket.to_path_buf();
                let parent_identity = parent_identity.clone();
                let sender = result_tx.clone();
                handlers.push(thread::spawn(move || {
                    let result = relay_one(stream, &socket, &parent_identity, deadline_unix_millis);
                    let mirrored = result
                        .as_ref()
                        .map(|_| ())
                        .map_err(|error| io::Error::new(error.kind(), error.to_string()));
                    let _ = sender.send(mirrored);
                    result
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if child.try_wait()?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    drop(result_tx);
    for handler in handlers {
        handler
            .join()
            .map_err(|_| io::Error::other("Claude relay connection thread panicked"))??;
    }
    while let Ok(result) = result_rx.try_recv() {
        result?;
    }
    if !child_bound {
        return Err(io::Error::other(
            "Claude native child exited before cgroup custody was verified",
        ));
    }
    Ok(())
}

fn relay_one(
    mut child_stream: TcpStream,
    parent_socket: &Path,
    expected_parent: &ParentEndpointIdentity,
    deadline_unix_millis: u64,
) -> io::Result<()> {
    child_stream.set_read_timeout(Some(IO_POLL))?;
    child_stream.set_write_timeout(Some(IO_POLL))?;
    let mut parent_stream = connect_unix_bounded(parent_socket, deadline_unix_millis)?;
    let socket_identity = validate_parent_socket(parent_socket, expected_parent.uid)?;
    let observed_parent = authenticate_parent_endpoint(
        &parent_stream,
        parent_socket,
        socket_identity,
        expected_parent.uid,
        &expected_parent.program,
    )?;
    if &observed_parent != expected_parent {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Claude parent relay endpoint identity changed",
        ));
    }
    parent_stream.set_read_timeout(Some(IO_POLL))?;
    parent_stream.set_write_timeout(Some(IO_POLL))?;

    let request = read_child_request(&mut child_stream, deadline_unix_millis)?;
    write_bounded(
        &mut parent_stream,
        &request,
        deadline_unix_millis,
        "Claude parent request",
    )?;
    parent_stream.shutdown(Shutdown::Write)?;
    let response = read_to_close_bounded(
        &mut parent_stream,
        MAX_RESPONSE_BYTES,
        deadline_unix_millis,
        "Claude parent response",
    )?;
    write_bounded(
        &mut child_stream,
        &response,
        deadline_unix_millis,
        "Claude child response",
    )?;
    child_stream.shutdown(Shutdown::Write)?;
    Ok(())
}

fn read_child_request(stream: &mut TcpStream, deadline_unix_millis: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut target = None;
    loop {
        require_before_deadline(deadline_unix_millis)?;
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                if bytes.len().saturating_add(read) > MAX_REQUEST_BYTES {
                    return Err(io::Error::other(
                        "Claude child request exceeded its byte bound",
                    ));
                }
                bytes.extend_from_slice(&chunk[..read]);
                if target.is_none() {
                    target = request_target_length(&bytes);
                }
                if target.is_some_and(|length| bytes.len() >= length) {
                    return Ok(bytes);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
}

fn request_target_length(bytes: &[u8]) -> Option<usize> {
    let split = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let Ok(head) = std::str::from_utf8(&bytes[..split]) else {
        return Some(bytes.len());
    };
    let mut content_length = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Some(bytes.len());
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Some(bytes.len());
            }
            let Ok(value) = value.trim().parse::<usize>() else {
                return Some(bytes.len());
            };
            content_length = Some(value);
        }
    }
    split
        .checked_add(4)
        .and_then(|head_length| head_length.checked_add(content_length.unwrap_or(0)))
        .filter(|length| *length <= MAX_REQUEST_BYTES)
        .or(Some(bytes.len()))
}

fn read_to_close_bounded(
    stream: &mut UnixStream,
    max_bytes: usize,
    deadline_unix_millis: u64,
    label: &str,
) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        require_before_deadline(deadline_unix_millis)?;
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                if bytes.len().saturating_add(read) > max_bytes {
                    return Err(io::Error::other(format!("{label} exceeded its byte bound")));
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
}

fn write_bounded(
    stream: &mut impl Write,
    bytes: &[u8],
    deadline_unix_millis: u64,
    label: &str,
) -> io::Result<()> {
    let mut written = 0usize;
    while written < bytes.len() {
        require_before_deadline(deadline_unix_millis)?;
        match stream.write(&bytes[written..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, label)),
            Ok(count) => written += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    stream.flush()
}

fn connect_unix_bounded(path: &Path, deadline_unix_millis: u64) -> io::Result<UnixStream> {
    let path_bytes = path.as_os_str().as_bytes();
    // SAFETY: zero is a valid initial representation before family/path initialization.
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    if path_bytes.is_empty()
        || path_bytes.contains(&0)
        || path_bytes.len() >= address.sun_path.len()
    {
        return Err(invalid("Claude parent relay socket path is invalid"));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(path_bytes) {
        *target = *source as libc::c_char;
    }
    // SAFETY: socket has no Rust memory preconditions. Ownership is transferred immediately.
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly-created owned descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let address_length =
        (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
    // SAFETY: address points to a fully initialized pathname sockaddr_un.
    let connected = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            address_length,
        )
    };
    if connected != 0 {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == libc::EINPROGRESS || code == libc::EAGAIN => {}
            _ => return Err(error),
        }
        loop {
            require_before_deadline(deadline_unix_millis)?;
            let mut descriptor = libc::pollfd {
                fd: owned.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: descriptor points to one initialized pollfd for the owned descriptor.
            let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            let mut socket_error = 0;
            let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: outputs are valid for SO_ERROR on this descriptor.
            if unsafe {
                libc::getsockopt(
                    owned.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut socket_error as *mut libc::c_int).cast(),
                    &mut length,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if socket_error != 0 {
                return Err(io::Error::from_raw_os_error(socket_error));
            }
            break;
        }
    }
    Ok(UnixStream::from(owned))
}

fn validate_owner_and_cgroup(request: &HelperRequest) -> io::Result<(String, u64)> {
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let actual_uid = unsafe { libc::geteuid() };
    if actual_uid != request.expected_uid {
        return Err(io::Error::other("Claude relay effective uid changed"));
    }
    let cgroup = read_single_cgroup(Path::new("/proc/self/cgroup"))?;
    let expected_suffix = format!("/app.slice/{}", request.expected_unit);
    if !cgroup.ends_with(&expected_suffix) {
        return Err(io::Error::other(
            "Claude relay cgroup does not match its launch unit",
        ));
    }
    let stat = fs::read_to_string("/proc/self/stat")?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("Claude relay process stat is malformed"))?;
    let start_ticks = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| io::Error::other("Claude relay process start time is unavailable"))?;
    Ok((cgroup, start_ticks))
}

fn register_with_parent(
    request: &HelperRequest,
    cgroup: &str,
    start_ticks: u64,
    socket_identity: ParentSocketIdentity,
    expected_program: &Path,
) -> io::Result<ParentEndpointIdentity> {
    let mut stream = connect_unix_bounded(&request.parent_socket, request.deadline_unix_millis)?;
    let parent_identity = authenticate_parent_endpoint(
        &stream,
        &request.parent_socket,
        socket_identity,
        request.expected_uid,
        expected_program,
    )?;
    stream.set_read_timeout(Some(IO_POLL))?;
    stream.set_write_timeout(Some(IO_POLL))?;
    let registration = format!(
        "MACO-CLAUDE-HELPER-V1\t{}\t{}\t{}\t{}\t{}\n",
        request.registration_nonce,
        std::process::id(),
        start_ticks,
        request.expected_unit,
        cgroup
    );
    write_bounded(
        &mut stream,
        registration.as_bytes(),
        request.deadline_unix_millis,
        "Claude helper registration",
    )?;
    stream.shutdown(Shutdown::Write)?;
    let acknowledgement = read_to_close_bounded(
        &mut stream,
        128,
        request.deadline_unix_millis,
        "Claude helper registration acknowledgement",
    )?;
    if acknowledgement != b"MACO-CLAUDE-HELPER-ACK-V1\n" {
        return Err(io::Error::other(
            "Claude parent refused the helper registration binding",
        ));
    }
    Ok(parent_identity)
}

fn read_single_cgroup(path: &Path) -> io::Result<String> {
    let value = fs::read_to_string(path)?;
    let mut lines = value.lines();
    let line = lines
        .next()
        .filter(|line| line.starts_with("0::/"))
        .ok_or_else(|| io::Error::other("Claude relay requires one cgroup v2 membership"))?;
    if lines.next().is_some() || line.len() > 4096 || line.chars().any(char::is_control) {
        return Err(io::Error::other(
            "Claude relay cgroup membership is malformed",
        ));
    }
    Ok(line[3..].to_string())
}

fn validate_parent_socket(path: &Path, expected_uid: u32) -> io::Result<ParentSocketIdentity> {
    if !path.is_absolute() || path.as_os_str().len() > 100 {
        return Err(invalid("Claude parent relay socket path is invalid"));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Claude parent relay socket is not an owner-private Unix socket",
        ));
    }
    Ok(ParentSocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn authenticate_parent_endpoint(
    stream: &UnixStream,
    path: &Path,
    socket_identity: ParentSocketIdentity,
    expected_uid: u32,
    expected_program: &Path,
) -> io::Result<ParentEndpointIdentity> {
    let rebound = fs::symlink_metadata(path)?;
    if !rebound.file_type().is_socket()
        || rebound.uid() != expected_uid
        || rebound.permissions().mode() & 0o777 != 0o600
        || rebound.dev() != socket_identity.device
        || rebound.ino() != socket_identity.inode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Claude parent relay socket identity changed",
        ));
    }
    // SAFETY: the output buffer and length are valid for SO_PEERCRED on this live stream.
    let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err(io::Error::last_os_error());
    }
    let pid = u32::try_from(credentials.pid)
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| io::Error::other("Claude parent relay peer PID is invalid"))?;
    if credentials.uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Claude parent relay peer UID is not the launch owner",
        ));
    }
    let start_ticks = process_start_ticks(pid)?;
    let program = fs::read_link(format!("/proc/{pid}/exe"))?;
    if program != expected_program {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Claude parent relay peer executable is not the pinned owner program",
        ));
    }
    Ok(ParentEndpointIdentity {
        pid,
        uid: credentials.uid,
        start_ticks,
        program,
        socket_device: socket_identity.device,
        socket_inode: socket_identity.inode,
    })
}

fn process_start_ticks(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("Claude parent relay process stat is malformed"))?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| io::Error::other("Claude parent relay process start time is unavailable"))
}

fn require_before_deadline(deadline_unix_millis: u64) -> io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system clock precedes the Unix epoch"))?
        .as_millis();
    if now >= u128::from(deadline_unix_millis) {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Claude relay deadline expired",
        ))
    } else {
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_request_binds_parent_deadline_uid_unit_and_pinned_descriptor() {
        let request = parse_request(
            [
                "/run/user/1000/private/relay.sock",
                "123456789",
                "1000",
                "maco-process-7-9.service",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                HIDDEN_PINNED_EXEC_ARGUMENT,
                "/run/user/1000/private/pinned-exec-v1.bin",
                "0123456789abcdef",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .expect("bound helper request");
        assert_eq!(
            request.parent_socket,
            Path::new("/run/user/1000/private/relay.sock")
        );
        assert_eq!(request.deadline_unix_millis, 123456789);
        assert_eq!(request.expected_uid, 1000);
        assert_eq!(request.expected_unit, "maco-process-7-9.service");
        assert_eq!(
            request.registration_nonce,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            request.pinned_descriptor,
            OsStr::new("/run/user/1000/private/pinned-exec-v1.bin")
        );
    }

    #[test]
    fn helper_request_refuses_missing_pinned_guardian_or_extra_arguments() {
        let wrong_marker = [
            "/run/user/1000/private/relay.sock",
            "123456789",
            "1000",
            "maco-process-7-9.service",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "--not-the-pinned-helper",
            "/run/user/1000/private/pinned-exec-v1.bin",
            "digest",
        ]
        .into_iter()
        .map(OsString::from);
        assert!(parse_request(wrong_marker).is_err());

        let extra = [
            "/run/user/1000/private/relay.sock",
            "123456789",
            "1000",
            "maco-process-7-9.service",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            HIDDEN_PINNED_EXEC_ARGUMENT,
            "/run/user/1000/private/pinned-exec-v1.bin",
            "digest",
            "extra",
        ]
        .into_iter()
        .map(OsString::from);
        assert!(parse_request(extra).is_err());
    }

    #[test]
    fn child_http_framing_is_bounded_by_complete_content_length() {
        let head = b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        assert_eq!(request_target_length(head), Some(head.len()));
        let message = b"POST /v1/messages HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(request_target_length(message), Some(message.len()));
        let duplicate = b"POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(request_target_length(duplicate), Some(duplicate.len()));
    }

    #[test]
    fn parent_endpoint_is_kernel_bound_before_registration_or_request() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("parent.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let uid = unsafe { libc::geteuid() };
        let socket_identity = validate_parent_socket(&socket, uid).unwrap();
        let client = UnixStream::connect(&socket).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let program = fs::read_link("/proc/self/exe").unwrap();
        let identity =
            authenticate_parent_endpoint(&client, &socket, socket_identity, uid, &program).unwrap();
        assert_eq!(identity.pid, std::process::id());
        assert_eq!(identity.uid, uid);
        assert_eq!(
            identity.start_ticks,
            process_start_ticks(identity.pid).unwrap()
        );
        assert_eq!(identity.program, program);

        assert!(authenticate_parent_endpoint(
            &client,
            &socket,
            socket_identity,
            uid,
            Path::new("/foreign-parent-program"),
        )
        .is_err());

        fs::remove_file(&socket).unwrap();
        let replacement = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            authenticate_parent_endpoint(&client, &socket, socket_identity, uid, &program,)
                .is_err()
        );
        drop(replacement);
    }
}
