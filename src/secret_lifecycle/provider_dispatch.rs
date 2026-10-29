//! Reference-only evidence from the closed stored-account launch operation.

use coding_agent_manager_lib::account_authority::SelectedAccountBinding;
use coding_agent_manager_lib::providers::launch_lifecycle::{
    CredentialEnvironmentInput, LaunchLifecycleView, LaunchPhase,
};
use serde::{Deserialize, Serialize};

/// Descriptive evidence only. Restoring it cannot recreate a lease, credential
/// capability, pending admission, or authority to finalize a live child.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLaunchMetadata {
    pub run_id: String,
    pub operation_id: String,
    pub binding: SelectedAccountBinding,
    pub environment: Vec<CredentialEnvironmentInput>,
    pub phase: LaunchPhase,
    pub revoked: bool,
}

impl From<LaunchLifecycleView> for ProviderLaunchMetadata {
    fn from(view: LaunchLifecycleView) -> Self {
        Self {
            run_id: view.run_id,
            operation_id: view.operation_id,
            binding: view.binding,
            environment: view.environment,
            phase: view.phase,
            revoked: view.revoked,
        }
    }
}
