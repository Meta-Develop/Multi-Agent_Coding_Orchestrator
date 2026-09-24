//! Thin MACO consumer for Coding Agent Manager selected-account authority.

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{anyhow, Result};
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

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn matches_selection_evidence(
        &self,
        evidence: &ManagedGrokAccountSelectionEvidence,
    ) -> bool {
        evidence.provider_id == self.provider_id
            && evidence.account_id == self.account_id
            && evidence.account_incarnation == self.account_incarnation
            && evidence.selection_revision == self.selection_revision
            && (self.authority_id.is_none() || evidence.authority_id == self.authority_id)
    }
}

#[cfg(test)]
thread_local! {
    static FROZEN_GROK_SELECTION: std::cell::RefCell<Option<FrozenGrokSelectedBinding>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(not(test))]
static FROZEN_GROK_SELECTION: Mutex<Option<FrozenGrokSelectedBinding>> = Mutex::new(None);

/// Production-contract store of admitted Grok bindings keyed by supervisor run id.
/// Launch must copy this onto the run/launch contract; it is never the launch source of truth.
static GROK_RUN_ACCOUNT_BINDINGS: Mutex<BTreeMap<String, FrozenGrokSelectedBinding>> =
    Mutex::new(BTreeMap::new());

/// Record or clear the Grok binding admitted from selector observation for one run.
#[cfg(target_os = "linux")]
pub(crate) fn record_observed_grok_selection(
    run_id: Option<&str>,
    provider_id: &str,
    authority_id: Option<String>,
    binding: Option<&coding_agent_manager_lib::account_authority::SelectedAccountBinding>,
) -> Option<FrozenGrokSelectedBinding> {
    if provider_id != GROK_CLI_PROVIDER_ID {
        return None;
    }
    let frozen = binding
        .map(|binding| FrozenGrokSelectedBinding::from_selected_binding(authority_id, binding));
    freeze_observed_grok_selection(frozen.clone());
    if let Some(run_id) = run_id {
        admit_grok_run_account_binding(run_id, frozen.clone());
    }
    frozen
}

/// Admit or clear the immutable Grok binding for one supervisor run id.
///
/// Clearing another run id cannot drop this run's evidence. Multiple reads clone the
/// same admitted binding. Launch still copies the value onto the run/launch contract.
pub(crate) fn admit_grok_run_account_binding(
    run_id: &str,
    frozen: Option<FrozenGrokSelectedBinding>,
) -> Option<FrozenGrokSelectedBinding> {
    let mut slots = GROK_RUN_ACCOUNT_BINDINGS
        .lock()
        .expect("Grok run account binding lock");
    match frozen {
        Some(frozen) => {
            slots.insert(run_id.to_string(), frozen.clone());
            Some(frozen)
        }
        None => {
            slots.remove(run_id);
            None
        }
    }
}

/// Clone the admitted binding for one run. Does not consume or weaken the stored evidence.
pub(crate) fn grok_run_account_binding(run_id: &str) -> Option<FrozenGrokSelectedBinding> {
    GROK_RUN_ACCOUNT_BINDINGS
        .lock()
        .expect("Grok run account binding lock")
        .get(run_id)
        .cloned()
}

/// Resolve the frozen binding carried on a specific launch contract.
///
/// A configured CAM socket with no binding for this run refuses, even if another run
/// left evidence in ambient process state.
pub(crate) fn require_carried_grok_launch_binding(
    carried: Option<&FrozenGrokSelectedBinding>,
    cam_socket_configured: bool,
) -> Result<Option<&FrozenGrokSelectedBinding>> {
    if cam_socket_configured {
        let frozen = carried.ok_or_else(|| {
            anyhow!(
                "no frozen Grok selection binding from Coding Agent Manager authority socket observation"
            )
        })?;
        Ok(Some(frozen))
    } else {
        Ok(carried)
    }
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

#[cfg(test)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn frozen_observed_grok_selection() -> Option<FrozenGrokSelectedBinding> {
    FROZEN_GROK_SELECTION.with(|cell| cell.borrow().clone())
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

pub(crate) use authority_socket_config::configured_cam_authority_socket;
#[cfg(target_os = "linux")]
pub(crate) use grok::GrokLaunchAuthority;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use grok::{
    activate_cam_grok_test_harness, build_cam_grok_test_harness, CamGrokTestHarness,
};
#[cfg(target_os = "linux")]
pub(crate) use socket_client::{
    observe_selected_authority_via_socket, selected_binding_via_authority_socket,
};

#[cfg(test)]
mod run_binding_tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn synthetic_binding(account_id: &str, revision: u64) -> FrozenGrokSelectedBinding {
        FrozenGrokSelectedBinding {
            authority_id: Some(format!("auth-{account_id}")),
            provider_id: GROK_CLI_PROVIDER_ID.to_string(),
            account_id: account_id.to_string(),
            account_incarnation: format!("inc-{account_id}"),
            selection_revision: revision,
        }
    }

    #[test]
    fn two_run_interleaving_cannot_launch_with_sibling_evidence() {
        const RUN_A: &str = "issue-601-run-a";
        const RUN_B: &str = "issue-601-run-b";
        let binding_a = synthetic_binding("account-a", 1);
        let binding_b = synthetic_binding("account-b", 2);
        admit_grok_run_account_binding(RUN_A, Some(binding_a.clone()));
        freeze_observed_grok_selection(Some(binding_a.clone()));
        let carried_a =
            grok_run_account_binding(RUN_A).expect("run A must admit a carried binding");
        let first_read = grok_run_account_binding(RUN_A);
        let second_read = grok_run_account_binding(RUN_A);
        assert_eq!(first_read.as_ref(), Some(&binding_a));
        assert_eq!(second_read, first_read);
        assert_eq!(carried_a, binding_a);

        let ready = Arc::new(Barrier::new(2));
        let overwritten = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let ready_a = ready.clone();
            let overwritten_a = overwritten.clone();
            let carried_a = carried_a.clone();
            let binding_a = binding_a.clone();
            let binding_b_for_a = binding_b.clone();
            scope.spawn(move || {
                ready_a.wait();
                overwritten_a.wait();
                let map_again = grok_run_account_binding(RUN_A).expect("run A map must survive");
                assert_eq!(map_again, binding_a);
                assert_eq!(carried_a, binding_a);
                let _ambient_b = FrozenGrokSelectionGuard::pin(Some(binding_b_for_a.clone()));
                let launched = require_carried_grok_launch_binding(Some(&carried_a), true)
                    .expect("run A launch uses the carried contract");
                assert_eq!(launched, Some(&carried_a));
                assert_ne!(launched, Some(&binding_b_for_a));
                let missing = require_carried_grok_launch_binding(None, true)
                    .expect_err("socket with no binding for THIS run must refuse");
                assert!(
                    missing
                        .to_string()
                        .contains("no frozen Grok selection binding"),
                    "unexpected refusal: {missing:#}"
                );
            });

            ready.wait();
            admit_grok_run_account_binding(RUN_B, Some(binding_b.clone()));
            freeze_observed_grok_selection(Some(binding_b.clone()));
            admit_grok_run_account_binding(RUN_B, Some(binding_b.clone()));
            overwritten.wait();
        });

        freeze_observed_grok_selection(None);
        admit_grok_run_account_binding(RUN_B, None);
        let after_clear = grok_run_account_binding(RUN_A).expect("clearing B cannot drop A");
        assert_eq!(after_clear, binding_a);
        assert_eq!(frozen_observed_grok_selection(), None);
        let still_carried = require_carried_grok_launch_binding(Some(&carried_a), true)
            .expect("carried A survives observation clearing");
        assert_eq!(still_carried, Some(&carried_a));
        admit_grok_run_account_binding(RUN_A, None);
    }

    #[test]
    fn socket_without_this_run_binding_refuses_even_when_sibling_evidence_exists() {
        const RUN_B: &str = "issue-601-sibling-b";
        let binding_b = synthetic_binding("account-b", 9);
        admit_grok_run_account_binding(RUN_B, Some(binding_b.clone()));
        freeze_observed_grok_selection(Some(binding_b));
        let error = require_carried_grok_launch_binding(None, true)
            .expect_err("configured socket with no frozen binding for this run must refuse");
        assert!(
            error
                .to_string()
                .contains("no frozen Grok selection binding"),
            "unexpected refusal: {error:#}"
        );
        admit_grok_run_account_binding(RUN_B, None);
        freeze_observed_grok_selection(None);
    }
}
