//! Operator configuration for the headless CAM authority Unix socket.

use std::path::PathBuf;

/// Operator override for the headless CAM authority socket endpoint.
pub(crate) const CAM_AUTHORITY_SOCKET_ENV: &str = "MACO_CAM_AUTHORITY_SOCKET";

#[cfg(test)]
thread_local! {
    /// `None`: no override, read the process environment.
    /// `Some(None)`: explicit unset. `Some(Some(value))`: explicit raw value.
    static CAM_AUTHORITY_SOCKET_OVERRIDE: std::cell::RefCell<Option<Option<std::ffi::OsString>>> =
        const { std::cell::RefCell::new(None) };
}

/// Raw `MACO_CAM_AUTHORITY_SOCKET` value.
///
/// Non-test builds read `std::env::var_os`. Test builds use a thread-local override
/// when one is installed. An explicit unset does not fall through to the process environment.
pub(crate) fn cam_authority_socket_value() -> Option<std::ffi::OsString> {
    #[cfg(test)]
    {
        if let Some(overridden) = CAM_AUTHORITY_SOCKET_OVERRIDE.with(|slot| slot.borrow().clone()) {
            return overridden;
        }
    }
    std::env::var_os(CAM_AUTHORITY_SOCKET_ENV)
}

/// Publish `value` as the raw socket value. Callers trim; this function does not.
///
/// Non-test builds use `std::env::set_var`. Test builds update the thread-local override only.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn set_cam_authority_socket_value(value: &str) {
    #[cfg(test)]
    {
        CAM_AUTHORITY_SOCKET_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = Some(Some(std::ffi::OsString::from(value)));
        });
    }
    #[cfg(not(test))]
    {
        // SAFETY: supervise CLI entry pins process environment before supervised worker threads start.
        unsafe { std::env::set_var(CAM_AUTHORITY_SOCKET_ENV, value) };
    }
}

/// Thread-local socket override. `Drop` restores the override captured at `install`.
#[cfg(test)]
pub(crate) struct CamAuthoritySocketTestGuard {
    previous: Option<Option<std::ffi::OsString>>,
    _thread_affinity: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl CamAuthoritySocketTestGuard {
    pub(crate) fn install(value: Option<&std::ffi::OsStr>) -> Self {
        let installed = Some(value.map(std::ffi::OsString::from));
        let previous = CAM_AUTHORITY_SOCKET_OVERRIDE.with(|slot| slot.replace(installed));
        Self {
            previous,
            _thread_affinity: std::marker::PhantomData,
        }
    }

    pub(crate) fn set(&self, value: Option<&std::ffi::OsStr>) {
        let _ = self;
        let installed = Some(value.map(std::ffi::OsString::from));
        CAM_AUTHORITY_SOCKET_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = installed;
        });
    }
}

#[cfg(test)]
impl Drop for CamAuthoritySocketTestGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CAM_AUTHORITY_SOCKET_OVERRIDE.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

/// Returns an explicit operator-configured authority socket path, if any.
pub(crate) fn configured_cam_authority_socket() -> Option<PathBuf> {
    let value = cam_authority_socket_value()?;
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn configured_socket_is_absent_by_default() {
        let process_before = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV);
        let guard = CamAuthoritySocketTestGuard::install(None);
        assert!(cam_authority_socket_value().is_none());
        assert!(configured_cam_authority_socket().is_none());
        assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
        drop(guard);
        assert_eq!(cam_authority_socket_value(), process_before);
        assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
    }

    #[test]
    fn configured_socket_ignores_empty_env() {
        let process_before = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV);
        let guard = CamAuthoritySocketTestGuard::install(Some(OsStr::new("")));
        assert_eq!(
            cam_authority_socket_value().as_deref(),
            Some(OsStr::new(""))
        );
        assert!(configured_cam_authority_socket().is_none());
        assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
        drop(guard);
        assert_eq!(cam_authority_socket_value(), process_before);
        assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
    }

    #[test]
    fn configured_socket_reads_explicit_env() {
        let process_before = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV);
        let guard =
            CamAuthoritySocketTestGuard::install(Some(OsStr::new("/tmp/maco-authority.sock")));
        assert_eq!(
            configured_cam_authority_socket().expect("path"),
            PathBuf::from("/tmp/maco-authority.sock")
        );
        assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
        drop(guard);
        assert_eq!(cam_authority_socket_value(), process_before);
    }

    #[test]
    fn nested_socket_override_restores_and_explicit_unset_is_distinct() {
        let process_before = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV);
        let outer = CamAuthoritySocketTestGuard::install(Some(OsStr::new("/tmp/maco-outer.sock")));
        assert_eq!(
            cam_authority_socket_value().as_deref(),
            Some(OsStr::new("/tmp/maco-outer.sock"))
        );
        assert_eq!(
            configured_cam_authority_socket(),
            Some(PathBuf::from("/tmp/maco-outer.sock"))
        );
        {
            let inner = CamAuthoritySocketTestGuard::install(None);
            assert!(cam_authority_socket_value().is_none());
            assert!(configured_cam_authority_socket().is_none());
            inner.set(Some(OsStr::new("/tmp/maco-inner.sock")));
            assert_eq!(
                cam_authority_socket_value().as_deref(),
                Some(OsStr::new("/tmp/maco-inner.sock"))
            );
            set_cam_authority_socket_value("  /tmp/maco-untrimmed.sock  ");
            assert_eq!(
                cam_authority_socket_value().as_deref(),
                Some(OsStr::new("  /tmp/maco-untrimmed.sock  "))
            );
            assert_eq!(
                configured_cam_authority_socket(),
                Some(PathBuf::from("  /tmp/maco-untrimmed.sock  "))
            );
            assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
        }
        assert_eq!(
            cam_authority_socket_value().as_deref(),
            Some(OsStr::new("/tmp/maco-outer.sock"))
        );
        outer.set(None);
        assert!(cam_authority_socket_value().is_none());
        assert!(configured_cam_authority_socket().is_none());
        drop(outer);
        assert_eq!(cam_authority_socket_value(), process_before);
        assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
    }

    #[test]
    fn socket_override_does_not_leak_into_sibling_without_override() {
        let process_before = std::env::var_os(CAM_AUTHORITY_SOCKET_ENV);
        let default_before = cam_authority_socket_value();
        assert_eq!(default_before, process_before);

        let phase = Arc::new(Barrier::new(2));
        let sibling_phase = Arc::clone(&phase);
        let sibling_default = default_before.clone();
        let sibling_process = process_before.clone();
        let sibling = std::thread::spawn(move || {
            sibling_phase.wait();
            let during_override = cam_authority_socket_value();
            sibling_phase.wait();
            sibling_phase.wait();
            let during_unset = cam_authority_socket_value();
            sibling_phase.wait();
            sibling_phase.wait();
            let after_restore = cam_authority_socket_value();
            sibling_phase.wait();
            assert_eq!(during_override, sibling_default);
            assert_eq!(during_unset, sibling_default);
            assert_eq!(after_restore, sibling_default);
            assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), sibling_process);
        });

        let guard =
            CamAuthoritySocketTestGuard::install(Some(OsStr::new("/tmp/maco-thread-a.sock")));
        phase.wait();
        assert_eq!(
            cam_authority_socket_value().as_deref(),
            Some(OsStr::new("/tmp/maco-thread-a.sock"))
        );
        assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
        phase.wait();
        guard.set(None);
        phase.wait();
        assert!(cam_authority_socket_value().is_none());
        phase.wait();
        drop(guard);
        phase.wait();
        assert_eq!(cam_authority_socket_value(), default_before);
        assert_eq!(std::env::var_os(CAM_AUTHORITY_SOCKET_ENV), process_before);
        phase.wait();
        sibling.join().expect("sibling thread");
    }
}
