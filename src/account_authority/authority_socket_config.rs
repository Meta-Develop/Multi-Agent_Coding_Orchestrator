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

/// Returns the operator override, or the Linux user's persistent service endpoint.
/// Connection-time ancestry and socket authorization checks remain authoritative.
pub(crate) fn configured_cam_authority_socket() -> Option<PathBuf> {
    // Existing isolated authority tests explicitly disable service discovery.
    // This override is thread-local and does not alter production defaults.
    #[cfg(test)]
    if let Some(overridden) = CAM_AUTHORITY_SOCKET_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return overridden
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
    }
    resolve_cam_authority_socket(cam_authority_socket_value())
}

fn resolve_cam_authority_socket(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    if let Some(value) = value {
        return (!value.is_empty()).then(|| PathBuf::from(value));
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: geteuid has no preconditions and reads no Rust memory.
        let uid = unsafe { libc::geteuid() };
        Some(default_cam_authority_socket(
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
            uid,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    None
}

#[cfg(target_os = "linux")]
fn default_cam_authority_socket(runtime_dir: Option<&std::ffi::OsStr>, uid: u32) -> PathBuf {
    use std::os::unix::fs::MetadataExt;

    let runtime = runtime_dir
        .map(PathBuf::from)
        .filter(|path| {
            path.is_absolute()
                && std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0
                })
        })
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
    runtime.join("maco/account-authority.sock")
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};

    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_uses_effective_uid_runtime_path_without_xdg() {
        assert_eq!(
            default_cam_authority_socket(None, 1000),
            PathBuf::from("/run/user/1000/maco/account-authority.sock")
        );
        assert_eq!(
            default_cam_authority_socket(Some(OsStr::new("relative-runtime")), 1000),
            default_cam_authority_socket(None, 1000)
        );
        assert_eq!(
            resolve_cam_authority_socket(None),
            Some(default_cam_authority_socket(
                std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
                // SAFETY: geteuid has no preconditions.
                unsafe { libc::geteuid() },
            ))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_accepts_private_owned_xdg_and_rejects_unsafe_directory() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let runtime = tempfile::tempdir().expect("private runtime fixture");
        let path = runtime.path();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("private runtime mode");
        let uid = std::fs::symlink_metadata(path)
            .expect("runtime metadata")
            .uid();
        assert_eq!(
            default_cam_authority_socket(Some(path.as_os_str()), uid),
            path.join("maco/account-authority.sock")
        );
        assert_eq!(
            default_cam_authority_socket(Some(path.as_os_str()), uid.wrapping_add(1)),
            default_cam_authority_socket(None, uid.wrapping_add(1))
        );
        let link = path.join("runtime-link");
        symlink(path, &link).expect("symlink runtime fixture");
        assert_eq!(
            default_cam_authority_socket(Some(link.as_os_str()), uid),
            default_cam_authority_socket(None, uid)
        );
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o770))
            .expect("unsafe runtime mode");
        assert_eq!(
            default_cam_authority_socket(Some(path.as_os_str()), uid),
            default_cam_authority_socket(None, uid)
        );
    }

    #[test]
    fn production_resolver_preserves_explicit_override_and_empty_value() {
        assert_eq!(
            resolve_cam_authority_socket(Some("/explicit/authority.sock".into())),
            Some(PathBuf::from("/explicit/authority.sock"))
        );
        assert!(resolve_cam_authority_socket(Some("".into())).is_none());
        #[cfg(not(target_os = "linux"))]
        assert!(resolve_cam_authority_socket(None).is_none());
    }

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
