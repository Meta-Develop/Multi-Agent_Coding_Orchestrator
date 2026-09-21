//! Thin MACO consumer for Coding Agent Manager selected-account authority.

use serde::{Deserialize, Serialize};

pub(crate) mod authority_socket_config;
#[cfg(target_os = "linux")]
pub(crate) mod grok;
#[cfg(target_os = "linux")]
pub(crate) mod socket_client;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const GROK_CLI_PROVIDER_ID: &str = "grok-cli";

/// Non-secret selected binding recorded on MACO execution evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ManagedGrokAccountSelectionEvidence {
    pub provider_id: String,
    pub account_id: String,
    pub account_incarnation: String,
    pub selection_revision: u64,
    /// Opaque CAM authority identity. Present whenever the frozen selection captured it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_id: Option<String>,
}

/// Frozen selected Grok binding admitted for selector observation and launch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct FrozenGrokSelectedBinding {
    pub authority_id: Option<String>,
    pub provider_id: String,
    pub account_id: String,
    pub account_incarnation: String,
    pub selection_revision: u64,
}

impl FrozenGrokSelectedBinding {
    #[cfg(target_os = "linux")]
    pub(crate) fn from_selected_binding(
        authority_id: Option<String>,
        binding: &coding_agent_manager_lib::account_authority::SelectedAccountBinding,
    ) -> Self {
        Self {
            authority_id,
            provider_id: binding.provider_id.clone(),
            account_id: binding.account_id.clone(),
            account_incarnation: binding.account_incarnation.clone(),
            selection_revision: binding.selection_revision,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn to_selected_binding(
        &self,
    ) -> coding_agent_manager_lib::account_authority::SelectedAccountBinding {
        coding_agent_manager_lib::account_authority::SelectedAccountBinding {
            provider_id: self.provider_id.clone(),
            account_id: self.account_id.clone(),
            account_incarnation: self.account_incarnation.clone(),
            selection_revision: self.selection_revision,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn matches_selected_binding(
        &self,
        binding: &coding_agent_manager_lib::account_authority::SelectedAccountBinding,
    ) -> bool {
        self.provider_id == binding.provider_id
            && self.account_id == binding.account_id
            && self.account_incarnation == binding.account_incarnation
            && self.selection_revision == binding.selection_revision
    }
}

#[cfg(test)]
thread_local! {
    static FROZEN_GROK_SELECTION: std::cell::RefCell<Option<FrozenGrokSelectedBinding>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(not(test))]
static FROZEN_GROK_SELECTION: std::sync::Mutex<Option<FrozenGrokSelectedBinding>> =
    std::sync::Mutex::new(None);

/// Record or clear the Grok binding admitted from selector observation.
#[cfg(target_os = "linux")]
pub(crate) fn record_observed_grok_selection(
    provider_id: &str,
    authority_id: Option<String>,
    binding: Option<&coding_agent_manager_lib::account_authority::SelectedAccountBinding>,
) {
    if provider_id != GROK_CLI_PROVIDER_ID {
        return;
    }
    freeze_observed_grok_selection(
        binding
            .map(|binding| FrozenGrokSelectedBinding::from_selected_binding(authority_id, binding)),
    );
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn freeze_observed_grok_selection(frozen: Option<FrozenGrokSelectedBinding>) {
    #[cfg(test)]
    {
        FROZEN_GROK_SELECTION.with(|cell| *cell.borrow_mut() = frozen);
    }
    #[cfg(not(test))]
    {
        *FROZEN_GROK_SELECTION
            .lock()
            .expect("frozen Grok selection lock") = frozen;
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn frozen_observed_grok_selection() -> Option<FrozenGrokSelectedBinding> {
    #[cfg(test)]
    {
        FROZEN_GROK_SELECTION.with(|cell| cell.borrow().clone())
    }
    #[cfg(not(test))]
    {
        FROZEN_GROK_SELECTION
            .lock()
            .expect("frozen Grok selection lock")
            .clone()
    }
}

#[cfg(test)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct FrozenGrokSelectionGuard {
    previous: Option<FrozenGrokSelectedBinding>,
}

#[cfg(test)]
impl FrozenGrokSelectionGuard {
    pub(crate) fn pin(frozen: Option<FrozenGrokSelectedBinding>) -> Self {
        let previous = frozen_observed_grok_selection();
        freeze_observed_grok_selection(frozen);
        Self { previous }
    }
}

#[cfg(test)]
impl Drop for FrozenGrokSelectionGuard {
    fn drop(&mut self) {
        freeze_observed_grok_selection(self.previous.take());
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) static CAM_AUTHORITY_SOCKET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) use authority_socket_config::configured_cam_authority_socket;
#[cfg(target_os = "linux")]
pub(crate) use grok::GrokLaunchAuthority;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use grok::{
    activate_cam_grok_test_harness, build_cam_grok_test_harness, CamGrokTestHarness,
};
#[cfg(target_os = "linux")]
pub(crate) use socket_client::{
    observe_selected_authority_via_socket, observe_selected_via_authority_socket,
    selected_binding_via_authority_socket,
};
