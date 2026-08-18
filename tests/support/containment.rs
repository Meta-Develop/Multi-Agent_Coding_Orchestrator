use std::io;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn delegated_user_manager_available(cgroups: &str) -> bool {
    cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .is_some_and(|current| {
            current
                .split('/')
                .any(|component| component.starts_with("user@") && component.ends_with(".service"))
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn skip_if_unavailable(test_name: &str) -> io::Result<bool> {
    let cgroups = std::fs::read_to_string("/proc/self/cgroup")?;
    Ok(skip_if_unavailable_for_cgroups(test_name, &cgroups))
}

#[cfg(target_os = "linux")]
pub(crate) fn skip_if_unavailable_for_cgroups(test_name: &str, cgroups: &str) -> bool {
    if delegated_user_manager_available(cgroups) {
        return false;
    }

    let current = cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or("<unified cgroup v2 entry absent>");
    eprintln!(
        "SKIP {test_name}: current cgroup {current} is not inside a delegated systemd user manager"
    );
    true
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn skip_if_unavailable(_test_name: &str) -> io::Result<bool> {
    Ok(false)
}
