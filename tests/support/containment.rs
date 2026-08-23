use multi_agent_coding_orchestrator::containment_probe;

#[allow(dead_code)]
pub(crate) fn delegated_user_manager_available(cgroups: &str) -> bool {
    containment_probe::delegated_user_manager_available(cgroups)
}

pub(crate) fn skip_if_unavailable(test_name: &str) -> std::io::Result<bool> {
    containment_probe::skip_if_unavailable(test_name)
}

#[allow(dead_code)]
pub(crate) fn skip_if_unavailable_for_cgroups(test_name: &str, cgroups: &str) -> bool {
    containment_probe::skip_if_unavailable_for_cgroups(test_name, cgroups)
}
