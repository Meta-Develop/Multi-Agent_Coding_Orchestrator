//! Shared delegated-user-manager probe used by tests and benchmarks.
//!
//! Strict containment requires a Linux cgroup v2 path inside a `user@*.service`
//! unit. Hosted CI runners typically lack that manager; callers print one
//! `SKIP <test>: <reason>` line and return instead of failing.

use std::io;

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

/// Reads `/proc/self/cgroup` on Linux and applies [`skip_if_unavailable_for_cgroups`].
#[cfg(target_os = "linux")]
pub fn skip_if_unavailable(test_name: &str) -> io::Result<bool> {
    let cgroups = std::fs::read_to_string("/proc/self/cgroup")?;
    Ok(skip_if_unavailable_for_cgroups(test_name, &cgroups))
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
