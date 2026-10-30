//! Selected-use custody for synchronous external process runners.

use crate::account_authority::SelectedUseLease;

use super::*;
use crate::providers::LaunchSpec;

/// A declared launch whose process is owned by an external runner. That runner
/// must confirm the entire owned process tree is empty before finalization.
/// Dropping unknown custody retains the selected-use barrier until process exit.
#[must_use = "external launch custody must be settled from live process evidence"]
pub struct ExternalLaunchCustody {
    lifecycle: LaunchLifecycle,
    lease: Option<SelectedUseLease>,
}

impl LaunchLifecycle {
    /// Guard a provider-specific credential handoff without a CLI declaration.
    /// Only the exact selected incarnation can supply material; the callback
    /// returns reference-only environment provenance alongside its private value.
    pub fn prepare_external_material<T, E: From<Error>>(
        self,
        registry: &StoredAccountRegistry,
        construct: impl FnOnce(
            &crate::model::StoredAccountMetadata,
        ) -> std::result::Result<(T, Vec<CredentialEnvironmentInput>), E>,
    ) -> std::result::Result<(ExternalLaunchCustody, T), E> {
        let binding = {
            let mut view = self.handle.0.lock().expect("launch lifecycle lock");
            self.check_admission(&view)?;
            view.phase = LaunchPhase::Constructing;
            view.binding.clone()
        };
        let (lease, account) = registry.acquire_selected_use_snapshot(&binding)?;
        let (material, environment) = construct(&account)?;
        {
            let mut view = self.handle.0.lock().expect("launch lifecycle lock");
            self.check_admission(&view)?;
            view.environment = environment;
        }
        Ok((
            ExternalLaunchCustody {
                lifecycle: self,
                lease: Some(lease),
            },
            material,
        ))
    }

    /// Adopt an adapter declaration under a fresh exact-selection lease. Resolve
    /// vendor-home capabilities only in `construct`, while admission is pending.
    /// Credential-store launches use [`Self::spawn`] instead.
    pub fn prepare_external<T, E: From<Error>>(
        self,
        registry: &StoredAccountRegistry,
        adapter: &dyn ProviderAdapter,
        construct: impl FnOnce(&LaunchSpec) -> std::result::Result<T, E>,
    ) -> std::result::Result<(ExternalLaunchCustody, T), E> {
        let binding = {
            let mut view = self.handle.0.lock().expect("launch lifecycle lock");
            self.check_admission(&view)?;
            view.phase = LaunchPhase::Constructing;
            view.binding.clone()
        };
        if binding.provider_id != adapter.id() {
            return Err(Error::UnknownProvider(binding.provider_id).into());
        }
        let (lease, account) = registry.acquire_selected_use_snapshot(&binding)?;
        let spec = launch_spec_for(adapter, &account)?;
        if spec.requires_credential() {
            return Err(refused("external runner requires a vendor-home declaration").into());
        }
        {
            let mut view = self.handle.0.lock().expect("launch lifecycle lock");
            self.check_admission(&view)?;
            view.environment = spec
                .environment
                .iter()
                .filter_map(|entry| match entry {
                    LaunchEnvironment::Remove { name } => {
                        Some(CredentialEnvironmentInput::Removed(name.clone()))
                    }
                    LaunchEnvironment::SetPlain { name, .. } => {
                        Some(CredentialEnvironmentInput::SelectedCredential(name.clone()))
                    }
                    LaunchEnvironment::SetSecret { .. } => None,
                })
                .collect();
        }
        let material = construct(&spec)?;
        self.check_admission(&self.handle.0.lock().expect("launch lifecycle lock"))?;
        Ok((
            ExternalLaunchCustody {
                lifecycle: self,
                lease: Some(lease),
            },
            material,
        ))
    }
}

impl ExternalLaunchCustody {
    pub fn lifecycle(&self) -> LaunchLifecycleHandle {
        self.lifecycle.handle()
    }

    /// Record the names explicitly passed by a clear-and-set process map.
    /// Values remain private to process construction.
    pub fn declare_inherited_environment<'a>(&self, names: impl IntoIterator<Item = &'a String>) {
        let mut view = self
            .lifecycle
            .handle
            .0
            .lock()
            .expect("launch lifecycle lock");
        if view.phase != LaunchPhase::Constructing {
            return;
        }
        for name in names {
            if !view.environment.iter().any(|input| match input {
                CredentialEnvironmentInput::Inherited(existing)
                | CredentialEnvironmentInput::SelectedCredential(existing)
                | CredentialEnvironmentInput::Removed(existing) => existing == name,
            }) {
                view.environment
                    .push(CredentialEnvironmentInput::Inherited(name.clone()));
            }
        }
    }

    /// Open an external credential capability while construction is pending.
    /// Revocation or expiry during construction refuses the resulting material.
    pub fn construct<T, E: From<Error>>(
        &self,
        construct: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        {
            let view = self
                .lifecycle
                .handle
                .0
                .lock()
                .expect("launch lifecycle lock");
            if view.phase != LaunchPhase::Constructing {
                return Err(refused("external launch construction is no longer pending").into());
            }
            self.lifecycle.check_admission(&view)?;
        }
        let material = construct()?;
        self.lifecycle.check_admission(
            &self
                .lifecycle
                .handle
                .0
                .lock()
                .expect("launch lifecycle lock"),
        )?;
        Ok(material)
    }

    /// Admission and revocation serialize before the runner can release a child.
    pub fn begin_spawn(&mut self) -> Result<()> {
        let mut view = self
            .lifecycle
            .handle
            .0
            .lock()
            .expect("launch lifecycle lock");
        if view.phase != LaunchPhase::Constructing {
            return Err(refused("external launch is not pending construction"));
        }
        self.lifecycle.check_admission(&view)?;
        view.phase = LaunchPhase::Running;
        Ok(())
    }

    /// The caller has live evidence that no child was released, or that the
    /// complete owned tree has exited. Unknown exit must use `exit_unknown`.
    pub fn finalize(&mut self, reason: LaunchFinalization) {
        let mut view = self
            .lifecycle
            .handle
            .0
            .lock()
            .expect("launch lifecycle lock");
        let allowed = match reason {
            LaunchFinalization::Refused => {
                matches!(view.phase, LaunchPhase::Constructing | LaunchPhase::Running)
            }
            LaunchFinalization::SpawnFailed => view.phase == LaunchPhase::Running,
            _ => matches!(view.phase, LaunchPhase::Running | LaunchPhase::ExitUnknown),
        };
        if allowed {
            view.phase = LaunchPhase::Finalized(reason);
            self.lease.take();
        }
    }

    /// Also applies to an unconfirmed preflight child during construction.
    pub fn exit_unknown(&mut self) {
        let mut view = self
            .lifecycle
            .handle
            .0
            .lock()
            .expect("launch lifecycle lock");
        if !matches!(view.phase, LaunchPhase::Finalized(_)) {
            view.phase = LaunchPhase::ExitUnknown;
        }
    }
}

impl Drop for ExternalLaunchCustody {
    fn drop(&mut self) {
        let mut view = self
            .lifecycle
            .handle
            .0
            .lock()
            .expect("launch lifecycle lock");
        if matches!(view.phase, LaunchPhase::Running | LaunchPhase::ExitUnknown) {
            view.phase = LaunchPhase::ExitUnknown;
            if let Some(lease) = self.lease.take() {
                // An external runner failed to prove exit. Releasing this lease
                // would permit replacing credentials still reachable by a child.
                std::mem::forget(lease);
            }
        }
    }
}
