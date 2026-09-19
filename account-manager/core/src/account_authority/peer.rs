//! Unix peer credentials for the headless authority socket.
//!
//! Authorization is `uid == euid` only. A failed peer is closed with no bytes
//! before any request is read or decoded.

use std::io;
use std::os::unix::io::RawFd;

/// Credentials retrieved from a connected Unix-domain socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
}

/// Accept only a peer whose effective user id matches this process.
pub fn authorize_peer(peer: PeerCredentials, euid: u32) -> bool {
    peer.uid == euid
}

/// Current process effective user id.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid is always successful and has no preconditions.
    unsafe { libc::geteuid() }
}

/// Read peer credentials from an already-connected socket.
pub fn peer_credentials(fd: RawFd) -> io::Result<PeerCredentials> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux_peer_credentials(fd)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        bsd_peer_credentials(fd)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_peer_credentials(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a connected socket; `cred` and `len` are valid for getsockopt.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        uid: cred.uid,
        gid: cred.gid,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bsd_peer_credentials(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a connected socket; uid/gid pointers are valid for getpeereid.
    let result = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials { uid, gid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_peer_requires_uid_to_equal_euid() {
        assert!(authorize_peer(PeerCredentials { uid: 7, gid: 1 }, 7));
        assert!(!authorize_peer(PeerCredentials { uid: 8, gid: 1 }, 7));
    }
}
