//! Shared admission for selected-account credential construction.

use std::cell::{RefCell, RefMut};
use std::time::Instant;

use anyhow::Result;
use coding_agent_manager_lib::account_authority::{SelectedAccountBinding, StoredAccountRegistry};
use coding_agent_manager_lib::model::StoredAccountMetadata;
use coding_agent_manager_lib::providers::launch_lifecycle::{
    CredentialEnvironmentInput, ExternalLaunchCustody, LaunchLifecycle, LaunchLifecycleHandle,
};
use coding_agent_manager_lib::providers::{LaunchSpec, ProviderAdapter};

pub(crate) struct LaunchAdmission<'a> {
    pub run_id: &'a str,
    pub operation_id: &'a str,
    pub deadline: Instant,
    pub handle: &'a mut Option<LaunchLifecycleHandle>,
}

#[cfg(test)]
pub(crate) mod tests;

pub(crate) struct SelectedLaunch(RefCell<ExternalLaunchCustody>);

impl SelectedLaunch {
    fn operation(
        binding: &SelectedAccountBinding,
        admission: Option<LaunchAdmission<'_>>,
    ) -> Result<LaunchLifecycle> {
        let operation = if let Some(admission) = admission {
            let operation = LaunchLifecycle::new(
                admission.run_id,
                admission.operation_id,
                binding.clone(),
                Some(admission.deadline),
            )?;
            *admission.handle = Some(operation.handle());
            operation
        } else {
            // Isolated acquisition tests still use the same guarded construction.
            LaunchLifecycle::new(
                "selected-account",
                "selected-account",
                binding.clone(),
                None,
            )?
        };
        Ok(operation)
    }

    pub(crate) fn prepare<T>(
        registry: &StoredAccountRegistry,
        adapter: &dyn ProviderAdapter,
        binding: &SelectedAccountBinding,
        admission: Option<LaunchAdmission<'_>>,
        construct: impl FnOnce(&LaunchSpec) -> Result<T>,
    ) -> Result<(Self, T)> {
        let (custody, material) =
            Self::operation(binding, admission)?.prepare_external(registry, adapter, construct)?;
        Ok((Self(RefCell::new(custody)), material))
    }

    pub(crate) fn prepare_material<T>(
        registry: &StoredAccountRegistry,
        binding: &SelectedAccountBinding,
        admission: Option<LaunchAdmission<'_>>,
        construct: impl FnOnce(&StoredAccountMetadata) -> Result<(T, Vec<CredentialEnvironmentInput>)>,
    ) -> Result<(Self, T)> {
        let (custody, material) =
            Self::operation(binding, admission)?.prepare_external_material(registry, construct)?;
        Ok((Self(RefCell::new(custody)), material))
    }

    pub(crate) fn custody(&self) -> RefMut<'_, ExternalLaunchCustody> {
        self.0.borrow_mut()
    }

    pub(crate) fn construct<T>(&self, construct: impl FnOnce() -> Result<T>) -> Result<T> {
        self.0.borrow().construct(construct)
    }
}
