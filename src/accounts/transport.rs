use super::{protocol::*, AccountError};
use serde::Serialize;
use std::{path::PathBuf, time::Duration};

/// An operator-selected endpoint and expected service identity. No discovery fallback.
#[derive(Clone)]
pub struct AccountClientConfig {
    pub socket: PathBuf,
    pub expected_uid: u32,
    pub timeout: Duration,
}

#[derive(Clone)]
pub struct AccountClient {
    config: AccountClientConfig,
}

impl AccountClient {
    pub fn new(config: AccountClientConfig) -> Result<Self, AccountError> {
        if config.timeout.is_zero() || config.timeout > Duration::from_secs(MAX_REQUEST_SECONDS) {
            return Err(AccountError::InvalidInput);
        }
        Ok(Self { config })
    }

    pub fn list(&self) -> Result<AccountList, AccountError> {
        #[derive(Serialize)]
        struct Empty {}
        let result: AccountList = self.request("accounts.list", Empty {})?;
        result.validate()?;
        Ok(result)
    }

    pub fn discover(&self, alias: &str) -> Result<AccountDiscovery, AccountError> {
        if !valid_alias(alias) {
            return Err(AccountError::InvalidInput);
        }
        #[derive(Serialize)]
        struct Arguments<'a> {
            alias: &'a str,
        }
        let result: AccountDiscovery = self.request("accounts.discover", Arguments { alias })?;
        result.validate()?;
        if result.account.alias != alias {
            return Err(AccountError::Protocol);
        }
        Ok(result)
    }

    pub(super) fn endpoint_binding(&self) -> Result<String, AccountError> {
        if !self.config.socket.is_absolute()
            || self.config.socket.components().any(|component| {
                !matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err(AccountError::UnsafeEndpoint);
        }
        let mut bytes = b"MACO-account-management-endpoint-v1\0".to_vec();
        bytes.extend_from_slice(&self.config.expected_uid.to_be_bytes());
        bytes.extend_from_slice(self.config.socket.as_os_str().as_encoded_bytes());
        Ok(crate::artifacts::state_auth::sha256_hex(&bytes))
    }

    pub(super) fn request<A: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        capability: &'static str,
        arguments: A,
    ) -> Result<T, AccountError> {
        // Each connection carries exactly one request, so identity 1 is unambiguous.
        let mut bytes = serde_json::to_vec(&Request {
            id: 1,
            capability,
            arguments,
        })
        .map_err(|_| AccountError::InvalidInput)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(AccountError::InvalidInput);
        }
        decode(&exchange(&self.config, &bytes)?, 1)
    }
}

#[cfg(not(target_os = "linux"))]
fn exchange(_config: &AccountClientConfig, _request: &[u8]) -> Result<Vec<u8>, AccountError> {
    Err(AccountError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
use linux::exchange;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::CString,
        fs::{File, OpenOptions},
        io::{Read, Write},
        mem::{size_of, zeroed},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
                net::UnixStream,
            },
        },
        path::Component,
        time::Instant,
    };

    fn io_error(error: std::io::Error) -> AccountError {
        match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => AccountError::Timeout,
            _ => AccountError::Unavailable,
        }
    }

    fn pinned_parent(config: &AccountClientConfig) -> Result<(File, CString), AccountError> {
        let mut parts = config.socket.components();
        if parts.next() != Some(Component::RootDir) {
            return Err(AccountError::UnsafeEndpoint);
        }
        let mut names = Vec::new();
        for part in parts {
            let Component::Normal(name) = part else {
                return Err(AccountError::UnsafeEndpoint);
            };
            names.push(CString::new(name.as_bytes()).map_err(|_| AccountError::UnsafeEndpoint)?);
        }
        let leaf = names.pop().ok_or(AccountError::UnsafeEndpoint)?;
        if names.is_empty() {
            return Err(AccountError::UnsafeEndpoint);
        }
        let mut parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|_| AccountError::UnsafeEndpoint)?;
        for name in names {
            // SAFETY: live directory descriptor and NUL-terminated component; ownership is transferred once.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(AccountError::UnsafeEndpoint);
            }
            parent = unsafe { File::from_raw_fd(fd) };
            let metadata = parent
                .metadata()
                .map_err(|_| AccountError::UnsafeEndpoint)?;
            if (metadata.uid() != 0 && metadata.uid() != config.expected_uid)
                || metadata.mode() & 0o022 != 0
            {
                return Err(AccountError::UnsafeEndpoint);
            }
        }
        let metadata = parent
            .metadata()
            .map_err(|_| AccountError::UnsafeEndpoint)?;
        // Group traversal may be granted deliberately; no world access or non-owner writes.
        if metadata.uid() != config.expected_uid || metadata.mode() & 0o027 != 0 {
            return Err(AccountError::UnsafeEndpoint);
        }
        Ok((parent, leaf))
    }

    fn pin_socket(parent: &File, leaf: &CString, uid: u32) -> Result<File, AccountError> {
        // O_PATH does not connect or follow a symbolic link. fstat checks the pinned inode.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(AccountError::UnsafeEndpoint);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| AccountError::UnsafeEndpoint)?;
        if metadata.uid() != uid
            || metadata.mode() & libc::S_IFMT != libc::S_IFSOCK
            || metadata.mode() & 0o7777 != 0o660
        {
            return Err(AccountError::UnsafeEndpoint);
        }
        Ok(file)
    }

    fn wait(fd: i32, events: i16, deadline: Instant) -> Result<(), AccountError> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(AccountError::Timeout)?;
            let millis = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut poll = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut poll, 1, millis) };
            if result == 0 {
                return Err(AccountError::Timeout);
            }
            if result > 0 {
                if poll.revents & libc::POLLNVAL != 0 {
                    return Err(AccountError::Unavailable);
                }
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(io_error(error));
            }
        }
    }

    fn verify_peer(stream: &UnixStream, expected_uid: u32) -> Result<(), AccountError> {
        let mut credentials: libc::ucred = unsafe { zeroed() };
        let mut len = size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if result != 0
            || len as usize != size_of::<libc::ucred>()
            || credentials.uid != expected_uid
        {
            return Err(AccountError::UnsafeEndpoint);
        }
        Ok(())
    }

    pub(super) fn exchange(
        config: &AccountClientConfig,
        request: &[u8],
    ) -> Result<Vec<u8>, AccountError> {
        let deadline = Instant::now() + config.timeout;
        let (parent, leaf) = pinned_parent(config)?;
        let pinned = pin_socket(&parent, &leaf, config.expected_uid)?;
        let address = format!(
            "/proc/self/fd/{}/{}",
            parent.as_raw_fd(),
            leaf.to_str().map_err(|_| AccountError::UnsafeEndpoint)?
        );
        let mut sockaddr: libc::sockaddr_un = unsafe { zeroed() };
        if address.len() >= sockaddr.sun_path.len() {
            return Err(AccountError::UnsafeEndpoint);
        }
        sockaddr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (dest, source) in sockaddr.sun_path.iter_mut().zip(address.bytes()) {
            *dest = source as libc::c_char;
        }
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(AccountError::Unavailable);
        }
        let socket = unsafe { OwnedFd::from_raw_fd(fd) };
        let result = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&sockaddr as *const libc::sockaddr_un).cast(),
                size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(io_error(error));
            }
            wait(socket.as_raw_fd(), libc::POLLOUT, deadline)?;
        }
        let mut stream = UnixStream::from(socket);
        if let Some(error) = stream.take_error().map_err(io_error)? {
            return Err(io_error(error));
        }
        verify_peer(&stream, config.expected_uid)?;
        let current = pin_socket(&parent, &leaf, config.expected_uid)?;
        let before = pinned
            .metadata()
            .map_err(|_| AccountError::UnsafeEndpoint)?;
        let after = current
            .metadata()
            .map_err(|_| AccountError::UnsafeEndpoint)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(AccountError::UnsafeEndpoint);
        }
        let mut remaining = request;
        while !remaining.is_empty() {
            wait(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
            match stream.write(remaining) {
                Ok(0) => return Err(AccountError::Unavailable),
                Ok(n) => remaining = &remaining[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(io_error(e)),
            }
        }
        let mut frame = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            wait(stream.as_raw_fd(), libc::POLLIN, deadline)?;
            let n = match stream.read(&mut buffer) {
                Ok(0) => return Err(AccountError::Protocol),
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(io_error(e)),
            };
            if frame.len() + n > MAX_FRAME_BYTES {
                return Err(AccountError::Protocol);
            }
            frame.extend_from_slice(&buffer[..n]);
            if let Some(end) = frame.iter().position(|b| *b == b'\n') {
                if end + 1 != frame.len() {
                    return Err(AccountError::Protocol);
                }
                return Ok(frame);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn peer_uid_is_checked_from_kernel_credentials() {
            let (stream, _peer) = UnixStream::pair().unwrap();
            let uid = unsafe { libc::geteuid() };
            assert_eq!(verify_peer(&stream, uid), Ok(()));
            assert_eq!(
                verify_peer(&stream, uid ^ 1),
                Err(AccountError::UnsafeEndpoint)
            );
        }
    }
}
