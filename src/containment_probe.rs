//! Shared containment and host-ownership probes used by tests and benchmarks.
//!
//! Strict containment requires a Linux cgroup v2 path inside a `user@*.service`
//! unit. Hosted CI runners typically lack that manager; callers print one
//! `SKIP <test>: <reason>` line and return instead of failing.
//! Nested user namespaces must also map uid 0 and recognize the host root's owner.

use std::io;

/// Returns whether a `/proc/self/uid_map` snapshot maps uid 0 inside the namespace.
pub fn root_uid_mapped(uid_map: &str) -> bool {
    uid_map.lines().any(|line| {
        let mut fields = line.split_whitespace().map(str::parse::<u64>);
        matches!(
            (fields.next(), fields.next(), fields.next(), fields.next()),
            (Some(Ok(0)), Some(Ok(_)), Some(Ok(1..)), None)
        )
    })
}

/// Returns the shared skip line when namespace uid 0 is not mapped.
pub fn host_ownership_skip_reason(test_name: &str, uid_map: &str) -> Option<String> {
    host_ownership_skip_reason_for_root(test_name, uid_map, 0)
}

fn host_ownership_skip_reason_for_root(
    test_name: &str,
    uid_map: &str,
    root_uid: u32,
) -> Option<String> {
    if root_uid_mapped(uid_map) && root_uid == 0 {
        return None;
    }
    Some(format!(
        "SKIP {test_name}: user namespace does not map uid 0, so root-owned host paths appear unowned (nested sandbox)"
    ))
}

/// Checks the namespace uid map and the actual owner of `/` on Linux.
#[cfg(target_os = "linux")]
pub fn skip_if_host_ownership_unavailable(test_name: &str) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let uid_map = std::fs::read_to_string("/proc/self/uid_map")?;
    // Mapping namespace uid 0 to an offset does not make host uid 0 visible.
    let root_uid = std::fs::metadata("/")?.uid();
    match host_ownership_skip_reason_for_root(test_name, &uid_map, root_uid) {
        Some(message) => {
            eprintln!("{message}");
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Non-Linux hosts do not use this host-ownership gate; callers run the test body.
#[cfg(not(target_os = "linux"))]
pub fn skip_if_host_ownership_unavailable(_test_name: &str) -> io::Result<bool> {
    Ok(false)
}

/// Returns whether `cgroups` places the process inside a delegated systemd user manager.
pub fn delegated_user_manager_available(cgroups: &str) -> bool {
    unified_cgroup(cgroups).is_some_and(|current| {
        current
            .split('/')
            .any(|component| component.starts_with("user@") && component.ends_with(".service"))
    })
}

/// Returns the unified cgroup v2 path from a `/proc/self/cgroup` snapshot.
pub fn unified_cgroup(cgroups: &str) -> Option<&str> {
    cgroups.lines().find_map(|line| line.strip_prefix("0::"))
}

/// Returns the shared skip line when the snapshot is outside a delegated user manager.
pub fn skip_reason(test_name: &str, cgroups: &str) -> Option<String> {
    if delegated_user_manager_available(cgroups) {
        return None;
    }
    let current = unified_cgroup(cgroups).unwrap_or("<unified cgroup v2 entry absent>");
    Some(format!(
        "SKIP {test_name}: current cgroup {current} is not inside a delegated systemd user manager"
    ))
}

/// Prints the shared skip line and returns `true` when the snapshot cannot run containment tests.
pub fn skip_if_unavailable_for_cgroups(test_name: &str, cgroups: &str) -> bool {
    match skip_reason(test_name, cgroups) {
        Some(message) => {
            eprintln!("{message}");
            true
        }
        None => false,
    }
}

/// Checks delegated containment first, then host ownership, on Linux.
#[cfg(target_os = "linux")]
pub fn skip_if_unavailable(test_name: &str) -> io::Result<bool> {
    let cgroups = std::fs::read_to_string("/proc/self/cgroup")?;
    if skip_if_unavailable_for_cgroups(test_name, &cgroups) {
        return Ok(true);
    }
    skip_if_host_ownership_unavailable(test_name)
}

/// Non-Linux hosts do not use this cgroup gate; callers run the test body.
#[cfg(not(target_os = "linux"))]
pub fn skip_if_unavailable(_test_name: &str) -> io::Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_uid_mapping_requires_inside_root() {
        assert!(root_uid_mapped("0 100000 65536\n"));
        assert!(root_uid_mapped("         0          0 4294967295\n"));
        assert!(!root_uid_mapped("30033 30033 1\n"));
        assert!(!root_uid_mapped("1000 0 1\n"));
        assert!(!root_uid_mapped(""));
        assert!(!root_uid_mapped("x y z\n"));
    }

    #[test]
    fn host_ownership_skip_reason_uses_the_shared_skip_message() {
        assert_eq!(
            host_ownership_skip_reason("example::tests::needs_host", "30033 30033 1\n"),
            Some("SKIP example::tests::needs_host: user namespace does not map uid 0, so root-owned host paths appear unowned (nested sandbox)".to_owned())
        );
        assert!(
            host_ownership_skip_reason("example::tests::needs_host", "0 100000 65536\n").is_none()
        );
    }

    #[test]
    fn offset_mapping_still_requires_the_host_root_owner() {
        let uid_map = "0 100000 65536\n";
        assert!(root_uid_mapped(uid_map));
        assert!(host_ownership_skip_reason("example::tests::needs_host", uid_map).is_none());
        assert_eq!(
            host_ownership_skip_reason_for_root("example::tests::needs_host", uid_map, 65534),
            Some("SKIP example::tests::needs_host: user namespace does not map uid 0, so root-owned host paths appear unowned (nested sandbox)".to_owned())
        );
        assert!(host_ownership_skip_reason_for_root(
            "example::tests::needs_host",
            "0 0 4294967295\n",
            0,
        )
        .is_none());
    }

    #[test]
    fn delegated_user_manager_detection_matches_integration_helper() {
        assert!(delegated_user_manager_available(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/maco.scope\n",
        ));
        assert!(!delegated_user_manager_available(
            "0::/system.slice/hosted-compute-agent.service\n",
        ));
        assert!(!delegated_user_manager_available("1:name=systemd:/\n"));
        assert!(!delegated_user_manager_available(""));
    }

    #[test]
    fn skip_reason_uses_the_shared_skip_message() {
        let message = skip_reason(
            "example::tests::needs_containment",
            "0::/system.slice/hosted-compute-agent.service\n",
        )
        .expect("hosted runner snapshot must skip");
        assert_eq!(
            message,
            "SKIP example::tests::needs_containment: current cgroup /system.slice/hosted-compute-agent.service is not inside a delegated systemd user manager"
        );
        assert!(skip_reason(
            "example::tests::needs_containment",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/maco.scope\n",
        )
        .is_none());
        assert_eq!(
            skip_reason("example::tests::needs_containment", "1:name=systemd:/\n")
                .expect("missing unified entry must skip"),
            "SKIP example::tests::needs_containment: current cgroup <unified cgroup v2 entry absent> is not inside a delegated systemd user manager"
        );
    }
}
