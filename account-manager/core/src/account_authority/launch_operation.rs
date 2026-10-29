//! Closed, service-owned provider launches. Records survive client disconnects,
//! including a lost start response. Retries never launch a second child.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::operation::new_operation_handle;
use super::{ErrorCode, OperationHandle, SelectedAccountBinding};
use crate::providers::launch_lifecycle::{
    LaunchFinalization, LaunchLifecycle, LaunchLifecycleHandle, LaunchPhase,
};
use crate::providers::LeasedChild;

// Keep terminal rows for the listener's lifetime: evicting a key could turn an
// old retry into another launch. Refuse new work once the bounded store is full.
const MAX_OPERATIONS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchOperationState {
    Starting,
    Running,
    Cancelling,
    Exited,
    Cancelled,
    Failed,
    OutcomeUnknown,
}

/// The only launch data returned over the socket. No output, command, paths,
/// environment, credential references, or credential material cross this seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaunchOperationStatus {
    pub handle: OperationHandle,
    pub state: LaunchOperationState,
    pub process_id: Option<u32>,
    pub exit_code: Option<i32>,
    pub failure_code: Option<ErrorCode>,
}

pub(super) struct LaunchOperationStore {
    pub service_id: String,
    inner: Mutex<Store>,
}

#[derive(Default)]
struct Store {
    by_key: HashMap<(String, String, String), OperationHandle>,
    by_handle: HashMap<OperationHandle, Arc<Mutex<Row>>>,
}

struct Row {
    authority_id: String,
    caller: String,
    binding: SelectedAccountBinding,
    status: LaunchOperationStatus,
    child: Option<LeasedChild>,
    lifecycle: LaunchLifecycleHandle,
}

impl LaunchOperationStore {
    pub fn new() -> Self {
        Self {
            service_id: super::new_account_incarnation(),
            inner: Mutex::new(Store::default()),
        }
    }

    pub fn start(
        &self,
        authority_id: &str,
        caller: &str,
        binding: &SelectedAccountBinding,
        idempotency_key: &str,
        spawn: impl FnOnce(LaunchLifecycle) -> Result<LeasedChild, ErrorCode>,
    ) -> Result<LaunchOperationStatus, ErrorCode> {
        let key = (
            authority_id.to_string(),
            caller.to_string(),
            idempotency_key.to_string(),
        );
        let mut store = self.inner.lock().map_err(|_| ErrorCode::StateUnavailable)?;
        if let Some(handle) = store.by_key.get(&key) {
            let row = Arc::clone(&store.by_handle[handle]);
            drop(store);
            let row = row.lock().map_err(|_| ErrorCode::StateUnavailable)?;
            if row.binding != *binding {
                return Err(ErrorCode::InvalidRequest);
            }
            return Ok(row.status.clone());
        }
        if store.by_handle.len() >= MAX_OPERATIONS {
            return Err(ErrorCode::Busy);
        }
        let handle = new_operation_handle().map_err(|_| ErrorCode::Unavailable)?;
        let lifecycle = LaunchLifecycle::new(
            self.service_id.clone(),
            handle.as_str(),
            binding.clone(),
            None,
        )
        .map_err(|_| ErrorCode::Unavailable)?;
        let row = Arc::new(Mutex::new(Row {
            authority_id: authority_id.to_string(),
            caller: caller.to_string(),
            binding: binding.clone(),
            status: LaunchOperationStatus {
                handle: handle.clone(),
                state: LaunchOperationState::Starting,
                process_id: None,
                exit_code: None,
                failure_code: None,
            },
            child: None,
            lifecycle: lifecycle.handle(),
        }));
        let mut custody = row.lock().map_err(|_| ErrorCode::StateUnavailable)?;
        store.by_key.insert(key, handle.clone());
        store.by_handle.insert(handle, Arc::clone(&row));
        drop(store);

        // Establish a reaper before acquiring material or spawning. Holding the
        // row lock keeps it idle until the child or a terminal failure is stored.
        let reaper_row = Arc::clone(&row);
        if std::thread::Builder::new()
            .name("authority-launch".into())
            .spawn(move || reap(reaper_row))
            .is_err()
        {
            custody.status.state = LaunchOperationState::Failed;
            custody.status.failure_code = Some(ErrorCode::Unavailable);
        } else {
            match spawn(lifecycle) {
                Ok(child) => {
                    custody.status.process_id = Some(child.id());
                    custody.status.state = LaunchOperationState::Running;
                    custody.child = Some(child);
                }
                Err(code) => {
                    custody.status.state = LaunchOperationState::Failed;
                    custody.status.failure_code = Some(code);
                }
            }
        }
        Ok(custody.status.clone())
    }

    pub fn status(
        &self,
        authority_id: &str,
        caller: &str,
        handle: &OperationHandle,
        cancel: bool,
    ) -> Result<LaunchOperationStatus, ErrorCode> {
        let row = {
            let store = self.inner.lock().map_err(|_| ErrorCode::StateUnavailable)?;
            store
                .by_handle
                .get(handle)
                .cloned()
                .ok_or(ErrorCode::AccessDenied)?
        };
        let mut row = row.lock().map_err(|_| ErrorCode::StateUnavailable)?;
        if row.authority_id != authority_id || row.caller != caller {
            return Err(ErrorCode::AccessDenied);
        }
        let running = poll(&mut row);
        if cancel && running {
            // Child::kill targets only the child still owned by this custody.
            // Neither a successful signal nor a failed signal releases a lease.
            match row.child.as_mut().expect("owned child").request_cancel() {
                Ok(true) => {
                    row.status.state = LaunchOperationState::Cancelling;
                    row.status.failure_code = None;
                }
                Ok(false) => {}
                Err(_) => {
                    row.status.state = LaunchOperationState::OutcomeUnknown;
                    row.status.failure_code = Some(ErrorCode::OutcomeUnknown);
                }
            }
            poll(&mut row);
        }
        Ok(row.status.clone())
    }
}

// A failed wait cannot establish that a PID still belongs to this child. Only
// a successful live poll permits cancellation to issue a signal.
fn poll(row: &mut Row) -> bool {
    let Some(child) = row.child.as_mut() else {
        return false;
    };
    match child.try_wait() {
        Ok(Some(exit)) => {
            row.status.state = if row.lifecycle.snapshot().phase
                == LaunchPhase::Finalized(LaunchFinalization::Cancelled)
            {
                LaunchOperationState::Cancelled
            } else {
                LaunchOperationState::Exited
            };
            row.status.exit_code = exit.code();
            row.status.failure_code = None;
            row.child.take();
            false
        }
        Ok(None) => true,
        Err(_) => {
            row.status.state = LaunchOperationState::OutcomeUnknown;
            row.status.failure_code = Some(ErrorCode::OutcomeUnknown);
            false
        }
    }
}

fn reap(row: Arc<Mutex<Row>>) {
    loop {
        {
            let Ok(mut row) = row.lock() else {
                // Poisoned custody remains in the store. LeasedChild also
                // retains the barrier if unconfirmed custody is ever dropped.
                return;
            };
            poll(&mut row);
            if row.child.is_none() || row.status.state == LaunchOperationState::OutcomeUnknown {
                // Unknown custody remains in the row; later status calls can
                // retry the wait without a permanently polling worker.
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
#[path = "launch_operation_tests.rs"]
mod tests;
