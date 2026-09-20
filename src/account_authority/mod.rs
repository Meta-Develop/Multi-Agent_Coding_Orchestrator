//! Thin MACO consumer for Coding Agent Manager selected-account authority.

use serde::{Deserialize, Serialize};

pub(crate) mod authority_socket_config;
#[cfg(target_os = "linux")]
pub(crate) mod grok;
#[cfg(target_os = "linux")]
pub(crate) mod socket_client;

/// Non-secret selected binding recorded on MACO execution evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ManagedGrokAccountSelectionEvidence {
    pub provider_id: String,
    pub account_id: String,
    pub account_incarnation: String,
    pub selection_revision: u64,
}

pub(crate) use authority_socket_config::configured_cam_authority_socket;
#[cfg(target_os = "linux")]
pub(crate) use grok::GrokLaunchAuthority;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use grok::{
    activate_cam_grok_test_harness, build_cam_grok_test_harness, CamGrokTestHarness,
    GROK_CLI_PROVIDER_ID,
};
#[cfg(target_os = "linux")]
pub(crate) use socket_client::observe_selected_via_authority_socket;
