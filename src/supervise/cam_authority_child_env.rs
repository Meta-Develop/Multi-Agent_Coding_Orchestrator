//! Propagate the operator-pinned headless CAM authority socket into nested MACO child launches.

use crate::external_agent::ExternalAgentCommand;
use std::collections::BTreeMap;

/// Operator override shared with supervise CLI pinning and the CAM authority client.
pub(crate) const CAM_AUTHORITY_SOCKET_ENV: &str = "MACO_CAM_AUTHORITY_SOCKET";

/// Returns the supervise process pinned socket path when present and non-empty.
pub(crate) fn parent_cam_authority_socket_value() -> Option<String> {
    let raw = crate::account_authority::authority_socket_config::cam_authority_socket_value()?;
    let value = raw.to_string_lossy();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

pub(crate) fn insert_cam_authority_socket_into_launch_environment(
    environment: &mut BTreeMap<String, String>,
    pin: Option<&str>,
) {
    let Some(value) = pin.filter(|value| !value.is_empty()) else {
        return;
    };
    environment.insert(CAM_AUTHORITY_SOCKET_ENV.to_string(), value.to_string());
}

pub(crate) fn apply_parent_socket_pin_to_command(
    command: ExternalAgentCommand,
) -> ExternalAgentCommand {
    match parent_cam_authority_socket_value() {
        Some(value) => command.with_cam_authority_socket_pin(Some(value)),
        None => command,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard {
        _inner: crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard,
    }

    impl EnvGuard {
        fn set(value: Option<&str>) -> Self {
            Self {
                _inner: crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard::install(
                    value.map(std::ffi::OsStr::new),
                ),
            }
        }
    }

    #[test]
    fn parent_socket_is_absent_when_env_unset() {
        let _guard = EnvGuard::set(None);
        assert!(parent_cam_authority_socket_value().is_none());
    }

    #[test]
    fn parent_socket_ignores_empty_env() {
        let _guard = EnvGuard::set(Some(""));
        assert!(parent_cam_authority_socket_value().is_none());
    }

    #[test]
    fn parent_socket_reads_non_empty_env() {
        let _guard = EnvGuard::set(Some("/tmp/maco-authority.sock"));
        assert_eq!(
            parent_cam_authority_socket_value().as_deref(),
            Some("/tmp/maco-authority.sock")
        );
    }

    #[test]
    fn launch_environment_omits_socket_without_pin() {
        let _guard = EnvGuard::set(None);
        let mut environment = BTreeMap::from([("LANG".to_string(), "C.UTF-8".to_string())]);
        insert_cam_authority_socket_into_launch_environment(&mut environment, None);
        assert!(!environment.contains_key(CAM_AUTHORITY_SOCKET_ENV));
    }

    #[test]
    fn launch_environment_includes_pinned_socket() {
        let mut environment = BTreeMap::new();
        insert_cam_authority_socket_into_launch_environment(
            &mut environment,
            Some("/run/maco/cam.sock"),
        );
        assert_eq!(
            environment
                .get(CAM_AUTHORITY_SOCKET_ENV)
                .map(String::as_str),
            Some("/run/maco/cam.sock")
        );
    }
}
