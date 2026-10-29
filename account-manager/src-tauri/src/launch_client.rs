//! Desktop-owned launch references; the authority retains remote child custody.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;

use crate::account_authority::{
    new_account_incarnation, ErrorCode, LaunchOperationStatus, OperationHandle,
    SelectedAccountBinding,
};
use crate::authority_client::{AccountAuthority, AuthorityClient, LaunchRpcError};
use crate::error::{Error, Result};
use crate::model::LaunchedProcess;
use crate::providers::{self, ActivationMechanism, ProviderAdapter};
use crate::storage;

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum DesktopLaunch {
    Local(LaunchedProcess),
    Remote(LaunchOperationStatus),
}

struct RemoteLaunch {
    client: AuthorityClient,
    authority_id: String,
    service_id: String,
    binding: SelectedAccountBinding,
    key: String,
}

#[derive(Default)]
struct References {
    pending: HashMap<String, RemoteLaunch>,
    started: HashMap<OperationHandle, RemoteLaunch>,
}

/// One desktop-process lifetime. Pending starts retain their exact retry key
/// and binding after a lost reply; known handles retain their original service.
pub struct ManagedLaunchService {
    authority: AccountAuthority,
    references: Mutex<References>,
}

impl ManagedLaunchService {
    pub fn new(authority: AccountAuthority) -> Self {
        Self {
            authority,
            references: Mutex::new(References::default()),
        }
    }

    pub fn start(&self, adapter: &dyn ProviderAdapter) -> Result<DesktopLaunch> {
        if adapter.activation_mechanism() != ActivationMechanism::LaunchEnvironment {
            return Err(Error::NotImplemented("launch_provider"));
        }
        let client = match &self.authority {
            AccountAuthority::InProcess(registry) => {
                let binding = registry
                    .selected_binding(adapter.id())?
                    .ok_or_else(|| Error::NoSelectedAccount(adapter.id().to_string()))?;
                let mut child = providers::spawn_selected_launch(
                    registry,
                    adapter,
                    &binding,
                    storage::default_store,
                )?;
                let process = LaunchedProcess {
                    provider_id: binding.provider_id,
                    account_id: binding.account_id,
                    process_id: child.id(),
                };
                // Both the child and its selected-use lease move to the reaper.
                std::thread::spawn(move || child.wait());
                return Ok(DesktopLaunch::Local(process));
            }
            AccountAuthority::Remote(client) => client,
        };
        let mut references = self.references.lock().map_err(|_| reference_error())?;
        if !references.pending.contains_key(adapter.id()) {
            if references.pending.len() + references.started.len() >= 1024 {
                return Err(Error::AccountAuthorityBusy {
                    reason: "desktop launch reference limit reached".into(),
                });
            }
            let (authority_id, service_id) = client.launch_identity()?;
            let binding = client
                .selected_binding(adapter.id())?
                .ok_or_else(|| Error::NoSelectedAccount(adapter.id().to_string()))?;
            references.pending.insert(
                adapter.id().to_string(),
                RemoteLaunch {
                    client: client.clone(),
                    authority_id,
                    service_id,
                    binding,
                    key: new_account_incarnation(),
                },
            );
        }
        let pending = &references.pending[adapter.id()];
        let status = match pending.client.launch_start(
            &pending.authority_id,
            &pending.service_id,
            &pending.binding,
            &pending.key,
        ) {
            Ok(status) => status,
            Err(error) => {
                // These confirmed refusals precede recording the retry key.
                // Other errors can follow dispatch and must retain the snapshot.
                if matches!(
                    error,
                    LaunchRpcError::Wire(
                        ErrorCode::AccessDenied | ErrorCode::Busy | ErrorCode::Unavailable
                    )
                ) {
                    references.pending.remove(adapter.id());
                }
                return Err(error.into_error());
            }
        };
        let reference = references
            .pending
            .remove(adapter.id())
            .expect("pending start");
        references.started.insert(status.handle.clone(), reference);
        Ok(DesktopLaunch::Remote(status))
    }

    pub fn status(&self, handle: &OperationHandle, cancel: bool) -> Result<LaunchOperationStatus> {
        let references = self.references.lock().map_err(|_| reference_error())?;
        let reference = references.started.get(handle).ok_or_else(reference_error)?;
        // A disconnect changes no local state and never claims cancellation.
        // Retrying uses the original authority/service and exact opaque handle.
        reference.client.launch_status(
            &reference.authority_id,
            &reference.service_id,
            handle,
            cancel,
        )
    }
}

fn reference_error() -> Error {
    Error::ConfigRead {
        provider: "account-authority".into(),
        reason: "desktop launch reference unavailable".into(),
    }
}

#[cfg(test)]
#[path = "commands_launch_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "launch_client_remote_tests.rs"]
mod remote_tests;
