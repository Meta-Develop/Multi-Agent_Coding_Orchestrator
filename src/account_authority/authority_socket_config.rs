//! Operator configuration for the headless CAM authority Unix socket.

use std::path::PathBuf;

/// Operator override for the headless CAM authority socket endpoint.
pub(crate) const CAM_AUTHORITY_SOCKET_ENV: &str = "MACO_CAM_AUTHORITY_SOCKET";

/// Returns an explicit operator-configured authority socket path, if any.
pub(crate) fn configured_cam_authority_socket() -> Option<PathBuf> {
    let value = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV)?;
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard};

    static ENV_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(value: Option<&str>) -> Self {
            let lock = ENV_TEST_LOCK.lock().expect("env test lock");
            let previous = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV);
            match value {
                Some(text) => std::env::set_var(CAM_AUTHORITY_SOCKET_ENV, text),
                None => std::env::remove_var(CAM_AUTHORITY_SOCKET_ENV),
            }
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(CAM_AUTHORITY_SOCKET_ENV, value),
                None => std::env::remove_var(CAM_AUTHORITY_SOCKET_ENV),
            }
        }
    }

    #[test]
    fn configured_socket_is_absent_by_default() {
        let _guard = EnvGuard::set(None);
        assert!(configured_cam_authority_socket().is_none());
    }

    #[test]
    fn configured_socket_ignores_empty_env() {
        let _guard = EnvGuard::set(Some(""));
        assert!(configured_cam_authority_socket().is_none());
    }

    #[test]
    fn configured_socket_reads_explicit_env() {
        let _guard = EnvGuard::set(Some("/tmp/maco-authority.sock"));
        assert_eq!(
            configured_cam_authority_socket().expect("path"),
            PathBuf::from("/tmp/maco-authority.sock")
        );
    }
}
