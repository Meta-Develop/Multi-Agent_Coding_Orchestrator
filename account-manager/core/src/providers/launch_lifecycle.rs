//! One-shot launch admission and reference-only finalization evidence.
//!
//! This is an in-process operation, not a remote authority operation or a
//! credential rotation service. Account incarnations are its material generation
//! tokens. The selected-use lease protects that generation through child exit.

use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::account_authority::{SelectedAccountBinding, StoredAccountRegistry};
use crate::error::{Error, Result};
use crate::storage::{CredentialStore, SecretRef};

use super::leased_launch::LeasedChild;
use super::{
    launch_spec_for, spawn_command, spawn_launch_with, LaunchEnvironment, ProviderAdapter,
};

mod external;
pub use external::ExternalLaunchCustody;

/// Closed finalization reasons. An unconfirmed exit is never a finalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LaunchFinalization {
    Refused,
    SpawnFailed,
    Exited,
    AbnormalExit,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LaunchPhase {
    Prepared,
    Constructing,
    Running,
    ExitUnknown,
    Finalized(LaunchFinalization),
}

/// Names and sources only; no inherited or resolved environment values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CredentialEnvironmentInput {
    Inherited(String),
    SelectedCredential(String),
    Removed(String),
}

/// Public evidence for one run/operation and exact selected incarnation.
/// Contains no command arguments, home contents, store handles, or material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchLifecycleView {
    pub run_id: String,
    pub operation_id: String,
    pub binding: SelectedAccountBinding,
    pub credential: Option<SecretRef>,
    pub environment: Vec<CredentialEnvironmentInput>,
    /// Monotonic admission deadline within this process, not a persisted expiry.
    pub deadline: Option<Instant>,
    pub phase: LaunchPhase,
    pub revoked: bool,
}

/// Observation and pre-spawn revocation capability, without child custody.
#[derive(Clone)]
pub struct LaunchLifecycleHandle(Arc<Mutex<LaunchLifecycleView>>);

impl PartialEq for LaunchLifecycleHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for LaunchLifecycleHandle {}

impl LaunchLifecycleHandle {
    pub fn snapshot(&self) -> LaunchLifecycleView {
        self.0.lock().expect("launch lifecycle lock").clone()
    }

    /// Revoke pending admission. Once spawned, use child cancellation and wait
    /// for confirmed exit; revocation alone cannot release material custody.
    pub fn revoke_before_spawn(&self) -> Result<()> {
        let mut view = self.0.lock().expect("launch lifecycle lock");
        match view.phase {
            LaunchPhase::Prepared | LaunchPhase::Constructing => {
                view.revoked = true;
                Ok(())
            }
            _ => Err(refused("launch admission has already completed")),
        }
    }
}

/// A non-cloneable, single-use launch operation. Dropping it before spawn
/// finalizes refusal; only its leased child can finalize after spawn.
#[must_use = "launch admission must be spawned or dropped"]
pub struct LaunchLifecycle {
    handle: LaunchLifecycleHandle,
}

impl LaunchLifecycle {
    pub fn new(
        run_id: impl Into<String>,
        operation_id: impl Into<String>,
        binding: SelectedAccountBinding,
        deadline: Option<Instant>,
    ) -> Result<Self> {
        let run_id = run_id.into();
        let operation_id = operation_id.into();
        if [&run_id, &operation_id]
            .iter()
            .any(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        {
            return Err(refused(
                "launch requires bounded run and operation identifiers",
            ));
        }
        Ok(Self {
            handle: LaunchLifecycleHandle(Arc::new(Mutex::new(LaunchLifecycleView {
                run_id,
                operation_id,
                binding,
                credential: None,
                environment: Vec::new(),
                deadline,
                phase: LaunchPhase::Prepared,
                revoked: false,
            }))),
        })
    }

    pub fn handle(&self) -> LaunchLifecycleHandle {
        self.handle.clone()
    }

    /// Resolve the adapter and selected store only inside this operation.
    /// Admission is checked both before resolution and at the actual spawn edge.
    /// Revocation and spawn serialize on the same lock. Expiry gates admission;
    /// it does not assert that an already-running child has stopped.
    pub fn spawn(
        self,
        registry: &StoredAccountRegistry,
        adapter: &dyn ProviderAdapter,
        credential_store: impl FnOnce() -> Result<Box<dyn CredentialStore>>,
    ) -> Result<LeasedChild> {
        let binding = {
            let mut view = self.handle.0.lock().expect("launch lifecycle lock");
            self.check_admission(&view)?;
            view.phase = LaunchPhase::Constructing;
            view.binding.clone()
        };
        if binding.provider_id != adapter.id() {
            return Err(Error::UnknownProvider(binding.provider_id.clone()));
        }
        let lease = registry.acquire_selected_use(&binding)?;
        let account = registry.complete(adapter.id(), &binding.account_id)?;
        let spec = launch_spec_for(adapter, &account)?;
        {
            let mut view = self.handle.0.lock().expect("launch lifecycle lock");
            view.credential = spec
                .requires_credential()
                .then(|| SecretRef::for_account(&binding.provider_id, &binding.account_id));
            view.environment = spec
                .environment
                .iter()
                .filter_map(|entry| match entry {
                    LaunchEnvironment::SetSecret { name } => {
                        Some(CredentialEnvironmentInput::SelectedCredential(name.clone()))
                    }
                    LaunchEnvironment::Remove { name } => {
                        Some(CredentialEnvironmentInput::Removed(name.clone()))
                    }
                    LaunchEnvironment::SetPlain { .. } => None,
                })
                .collect();
        }
        let store = spec
            .requires_credential()
            .then(credential_store)
            .transpose()?;
        let child = spawn_launch_with(spec, &account, store.as_deref(), |command| {
            let mut view = self.handle.0.lock().expect("launch lifecycle lock");
            self.check_admission(&view)?;
            match spawn_command(command, &binding.provider_id) {
                Ok(child) => {
                    view.phase = LaunchPhase::Running;
                    Ok(child)
                }
                Err(error) => {
                    view.phase = LaunchPhase::Finalized(LaunchFinalization::SpawnFailed);
                    Err(error)
                }
            }
        })?;
        Ok(LeasedChild::new(child, binding, lease, self))
    }

    fn check_admission(&self, view: &LaunchLifecycleView) -> Result<()> {
        if view.revoked {
            return Err(refused("launch admission was revoked"));
        }
        if view
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(refused("launch admission expired"));
        }
        Ok(())
    }

    pub(super) fn confirmed_exit(&self, status: ExitStatus, cancelled: bool) {
        let mut view = self.handle.0.lock().expect("launch lifecycle lock");
        if matches!(view.phase, LaunchPhase::Running | LaunchPhase::ExitUnknown) {
            view.phase = LaunchPhase::Finalized(if cancelled {
                LaunchFinalization::Cancelled
            } else if status.success() {
                LaunchFinalization::Exited
            } else {
                LaunchFinalization::AbnormalExit
            });
        }
    }

    pub(super) fn exit_unknown(&self) {
        let mut view = self.handle.0.lock().expect("launch lifecycle lock");
        if view.phase == LaunchPhase::Running {
            view.phase = LaunchPhase::ExitUnknown;
        }
    }
}

impl Drop for LaunchLifecycle {
    fn drop(&mut self) {
        let mut view = self.handle.0.lock().expect("launch lifecycle lock");
        if matches!(
            view.phase,
            LaunchPhase::Prepared | LaunchPhase::Constructing
        ) {
            view.phase = LaunchPhase::Finalized(LaunchFinalization::Refused);
        }
    }
}

fn refused(reason: &'static str) -> Error {
    Error::ConfigWrite {
        provider: "launch-lifecycle".into(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests;
