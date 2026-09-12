//! A durable manual preference, explicitly separate from execution authority.

use super::{
    protocol::{required_option, valid_alias, MAX_FRAME_BYTES},
    AccountError,
};
use crate::safe_state::{AtomicStateWriter, BoundedRegularReader, KernelStateLock, SafeRoot};
use serde::{Deserialize, Serialize};
use std::path::Path;

const SETTINGS: &str = "selection.json";
const LOCK: &str = "selection.lock";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualSelection {
    pub revision: u64,
    #[serde(deserialize_with = "required_option")]
    pub selected_alias: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSelection {
    schema_version: u32,
    endpoint_binding: String,
    selection: ManualSelection,
}

pub(super) struct SelectionStore {
    root: SafeRoot,
    endpoint_binding: String,
}

impl SelectionStore {
    pub(super) fn open_existing(
        path: &Path,
        endpoint_binding: String,
    ) -> Result<Self, AccountError> {
        let root = SafeRoot::open_existing_private(path).map_err(|_| AccountError::UnsafeState)?;
        let store = Self {
            root,
            endpoint_binding,
        };
        store.read()?;
        Ok(store)
    }

    /// Commit an intent while selection is locked. Later UI changes affect future intents.
    pub(super) fn freeze<T>(
        &self,
        alias: &str,
        commit: impl FnOnce(&ManualSelection) -> Result<T, AccountError>,
    ) -> Result<T, AccountError> {
        let lock = self.lock()?;
        let selection = self.read_locked(&lock)?;
        if selection.revision == 0 || selection.selected_alias.as_deref() != Some(alias) {
            return Err(AccountError::SelectionConflict);
        }
        let result = commit(&selection)?;
        lock.verify_direct_binding(&self.root)
            .map_err(|_| AccountError::UnsafeState)?;
        Ok(result)
    }

    pub(super) fn open(path: &Path, endpoint_binding: String) -> Result<Self, AccountError> {
        let root = SafeRoot::open_or_create(path).map_err(|_| AccountError::UnsafeState)?;
        let store = Self {
            root,
            endpoint_binding,
        };
        let lock = store.lock()?;
        let existing = store
            .root
            .direct_child_exists(SETTINGS)
            .map_err(|_| AccountError::UnsafeState)?;
        if !existing {
            store.write(
                &ManualSelection {
                    revision: 0,
                    selected_alias: None,
                },
                &lock,
            )?;
        }
        store.read_locked(&lock)?;
        Ok(store)
    }

    pub(super) fn read(&self) -> Result<ManualSelection, AccountError> {
        self.read_locked(&self.lock()?)
    }

    pub(super) fn select(
        &self,
        alias: &str,
        expected_revision: u64,
    ) -> Result<ManualSelection, AccountError> {
        if !valid_alias(alias) {
            return Err(AccountError::InvalidInput);
        }
        let lock = self.lock()?;
        let current = self.read_locked(&lock)?;
        if current.revision != expected_revision {
            return Err(AccountError::SelectionConflict);
        }
        if current.selected_alias.as_deref() == Some(alias) {
            return Ok(current);
        }
        let selected = ManualSelection {
            revision: current
                .revision
                .checked_add(1)
                .ok_or(AccountError::UnsafeState)?,
            selected_alias: Some(alias.into()),
        };
        self.write(&selected, &lock)?;
        Ok(selected)
    }

    fn lock(&self) -> Result<KernelStateLock, AccountError> {
        KernelStateLock::acquire_direct(&self.root, LOCK).map_err(|_| AccountError::UnsafeState)
    }

    fn read_locked(&self, lock: &KernelStateLock) -> Result<ManualSelection, AccountError> {
        lock.verify_direct_binding(&self.root)
            .map_err(|_| AccountError::UnsafeState)?;
        let bytes = BoundedRegularReader::read_direct(&self.root, SETTINGS, MAX_FRAME_BYTES as u64)
            .map_err(|_| AccountError::UnsafeState)?;
        let value: StoredSelection =
            serde_json::from_slice(&bytes).map_err(|_| AccountError::UnsafeState)?;
        if value.schema_version != 1
            || value.endpoint_binding != self.endpoint_binding
            || value
                .selection
                .selected_alias
                .as_ref()
                .is_some_and(|alias| !valid_alias(alias))
        {
            return Err(AccountError::UnsafeState);
        }
        lock.verify_direct_binding(&self.root)
            .map_err(|_| AccountError::UnsafeState)?;
        Ok(value.selection)
    }

    fn write(
        &self,
        selection: &ManualSelection,
        lock: &KernelStateLock,
    ) -> Result<(), AccountError> {
        let value = StoredSelection {
            schema_version: 1,
            endpoint_binding: self.endpoint_binding.clone(),
            selection: selection.clone(),
        };
        let bytes = serde_json::to_vec(&value).map_err(|_| AccountError::UnsafeState)?;
        AtomicStateWriter::write_direct_fenced(&self.root, SETTINGS, &bytes, || {
            lock.verify_direct_binding(&self.root)
        })
        .map_err(|_| AccountError::UnsafeState)
    }
}
