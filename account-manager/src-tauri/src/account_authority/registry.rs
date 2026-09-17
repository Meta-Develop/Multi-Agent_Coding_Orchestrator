//! Durable stored-account registry with cross-process coordination.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::error::{Error, Result};
use crate::model::{AuthKind, StoredAccountMaterial, StoredAccountMetadata, StoredAccountState};
use crate::storage::{CredentialStore, Secret, SecretRef};

use super::binding::SelectedAccountBinding;
use super::document::{
    bump_selection_revision, metadata_write_error, parse_document_bytes, selection_revision_for,
    validate_document, validate_metadata_fields, StoredAccountsDocument, STORED_ACCOUNTS_VERSION,
};
use super::incarnation::new_account_incarnation;
use super::lock::RegistryFileLock;
use super::use_lease::{refuse_provider_authority_mutations, SelectedUseLease};

static STORED_ACCOUNTS_IN_PROCESS_LOCK: Mutex<()> = Mutex::new(());

pub struct StoredAccountRegistry {
    path: PathBuf,
}

impl StoredAccountRegistry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn metadata_path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Vec<StoredAccountMetadata>> {
        self.with_locked(|document| Ok(document.accounts.clone()))
    }

    pub fn begin_add(
        &self,
        provider_id: &str,
        account_id: &str,
        label: &str,
        auth_kind: AuthKind,
        material: StoredAccountMaterial,
    ) -> Result<StoredAccountMetadata> {
        validate_metadata_fields(provider_id, account_id, label)?;
        self.with_locked_mut(|document| {
            if document
                .accounts
                .iter()
                .any(|account| account.provider_id == provider_id && account.id == account_id)
            {
                return Err(metadata_write_error(
                    provider_id,
                    format!("account `{account_id}` already exists"),
                ));
            }
            let account = StoredAccountMetadata {
                id: account_id.to_string(),
                provider_id: provider_id.to_string(),
                label: label.to_string(),
                auth_kind,
                state: StoredAccountState::Pending,
                material,
                is_selected: false,
                account_incarnation: new_account_incarnation(),
            };
            document.accounts.push(account.clone());
            Ok(account)
        })
    }

    pub fn complete_add(&self, provider_id: &str, account_id: &str) -> Result<()> {
        self.update_account(provider_id, account_id, |account| {
            if account.state != StoredAccountState::Pending {
                return Err(metadata_write_error(
                    provider_id,
                    format!("account `{account_id}` is not pending"),
                ));
            }
            account.state = StoredAccountState::Complete;
            Ok(())
        })
    }

    pub fn add_with_secret(
        &self,
        provider_id: &str,
        account_id: &str,
        label: &str,
        auth_kind: AuthKind,
        secret: &Secret,
        credential_store: &dyn CredentialStore,
    ) -> Result<()> {
        self.begin_add(
            provider_id,
            account_id,
            label,
            auth_kind,
            StoredAccountMaterial::CredentialStore,
        )?;
        credential_store.put(&SecretRef::for_account(provider_id, account_id), secret)?;
        self.complete_add(provider_id, account_id)
    }

    pub fn select_complete(&self, provider_id: &str, account_id: &str) -> Result<()> {
        self.select_complete_revision(provider_id, account_id, None)?;
        Ok(())
    }

    pub fn select_complete_revision(
        &self,
        provider_id: &str,
        account_id: &str,
        expected_revision: Option<u64>,
    ) -> Result<SelectedAccountBinding> {
        self.with_locked_mut(|document| {
            refuse_provider_authority_mutations(&self.path, provider_id)?;
            if let Some(expected) = expected_revision {
                if selection_revision_for(document, provider_id) != expected {
                    return Err(Error::StaleSelection {
                        provider: provider_id.to_string(),
                    });
                }
            }
            let selected = document.accounts.iter().any(|account| {
                account.provider_id == provider_id
                    && account.id == account_id
                    && account.state == StoredAccountState::Complete
            });
            if !selected {
                return Err(Error::UnknownAccount(account_id.to_string()));
            }
            for account in document
                .accounts
                .iter_mut()
                .filter(|account| account.provider_id == provider_id)
            {
                account.is_selected = account.id == account_id;
            }
            let revision = bump_selection_revision(document, provider_id)?;
            binding_for_selection(document, provider_id, revision)
        })
    }

    pub fn selected(&self, provider_id: &str) -> Result<Option<StoredAccountMetadata>> {
        Ok(self.load()?.into_iter().find(|account| {
            account.provider_id == provider_id
                && account.state == StoredAccountState::Complete
                && account.is_selected
        }))
    }

    pub fn selected_binding(&self, provider_id: &str) -> Result<Option<SelectedAccountBinding>> {
        self.with_locked(|document| Ok(selected_binding_from_document(document, provider_id)))
    }

    pub fn complete(&self, provider_id: &str, account_id: &str) -> Result<StoredAccountMetadata> {
        self.load()?
            .into_iter()
            .find(|account| {
                account.provider_id == provider_id
                    && account.id == account_id
                    && account.state == StoredAccountState::Complete
            })
            .ok_or_else(|| Error::UnknownAccount(account_id.to_string()))
    }

    pub fn account(&self, provider_id: &str, account_id: &str) -> Result<StoredAccountMetadata> {
        self.load()?
            .into_iter()
            .find(|account| account.provider_id == provider_id && account.id == account_id)
            .ok_or_else(|| Error::UnknownAccount(account_id.to_string()))
    }

    pub fn begin_delete(&self, provider_id: &str, account_id: &str) -> Result<()> {
        self.with_locked_mut(|document| {
            refuse_provider_authority_mutations(&self.path, provider_id)?;
            let account = document
                .accounts
                .iter_mut()
                .find(|account| account.provider_id == provider_id && account.id == account_id)
                .ok_or_else(|| Error::UnknownAccount(account_id.to_string()))?;
            let was_selected = account.is_selected;
            account.state = StoredAccountState::Deleting;
            account.is_selected = false;
            if was_selected {
                bump_selection_revision(document, provider_id)?;
            }
            Ok(())
        })
    }

    pub fn finish_delete(&self, provider_id: &str, account_id: &str) -> Result<()> {
        self.with_locked_mut(|document| {
            refuse_provider_authority_mutations(&self.path, provider_id)?;
            let before = document.accounts.len();
            document.accounts.retain(|account| {
                !(account.provider_id == provider_id
                    && account.id == account_id
                    && account.state == StoredAccountState::Deleting)
            });
            if document.accounts.len() == before {
                return Err(Error::UnknownAccount(account_id.to_string()));
            }
            Ok(())
        })
    }

    pub fn delete(
        &self,
        provider_id: &str,
        account_id: &str,
        credential_store: Option<&dyn CredentialStore>,
    ) -> Result<()> {
        self.begin_delete(provider_id, account_id)?;
        let account = self
            .load()?
            .into_iter()
            .find(|account| account.provider_id == provider_id && account.id == account_id)
            .ok_or_else(|| Error::UnknownAccount(account_id.to_string()))?;
        if account.material == StoredAccountMaterial::CredentialStore {
            let store = credential_store.ok_or_else(|| {
                Error::CredentialStoreUnavailable(
                    "deleting this account requires its credential store".to_string(),
                )
            })?;
            store.delete(&SecretRef::for_account(provider_id, account_id))?;
        }
        self.finish_delete(provider_id, account_id)
    }

    pub fn recover(&self, credential_store: Option<&dyn CredentialStore>) -> Result<()> {
        self.with_locked_mut(|document| {
            let mut affected_providers = HashSet::new();
            for account in document
                .accounts
                .iter()
                .filter(|account| account.state != StoredAccountState::Complete)
            {
                if account.state == StoredAccountState::Pending
                    && account.material == StoredAccountMaterial::VendorHome
                {
                    continue;
                }
                affected_providers.insert(account.provider_id.clone());
            }
            for provider_id in affected_providers {
                refuse_provider_authority_mutations(&self.path, &provider_id)?;
            }

            let mut changed = false;
            for account in document
                .accounts
                .iter()
                .filter(|account| account.state != StoredAccountState::Complete)
            {
                if account.state == StoredAccountState::Pending
                    && account.material == StoredAccountMaterial::VendorHome
                {
                    continue;
                }
                if account.material == StoredAccountMaterial::CredentialStore {
                    let store = credential_store.ok_or_else(|| {
                        Error::CredentialStoreUnavailable(
                            "recovering account metadata requires its credential store".to_string(),
                        )
                    })?;
                    store.delete(&SecretRef::for_account(&account.provider_id, &account.id))?;
                }
                changed = true;
            }
            if changed {
                document.accounts.retain(|account| {
                    account.state == StoredAccountState::Complete
                        || (account.state == StoredAccountState::Pending
                            && account.material == StoredAccountMaterial::VendorHome)
                });
            }
            Ok(())
        })
    }

    pub fn acquire_selected_use(
        &self,
        expected: &SelectedAccountBinding,
    ) -> Result<SelectedUseLease> {
        let _process = in_process_guard()?;
        let _registry = RegistryFileLock::acquire(&self.path)?;
        let document = self.read_document_under_lock()?;
        let binding = selected_binding_from_document(&document, &expected.provider_id)
            .ok_or_else(|| Error::NoSelectedAccount(expected.provider_id.clone()))?;
        if binding != *expected {
            if binding.selection_revision != expected.selection_revision {
                return Err(Error::StaleSelection {
                    provider: expected.provider_id.clone(),
                });
            }
            if binding.account_incarnation != expected.account_incarnation {
                return Err(Error::StaleAccount {
                    account_id: expected.account_id.clone(),
                });
            }
            if binding.account_id != expected.account_id {
                return Err(Error::UnknownAccount(expected.account_id.clone()));
            }
            return Err(Error::StaleSelection {
                provider: expected.provider_id.clone(),
            });
        }
        let account = document
            .accounts
            .iter()
            .find(|account| {
                account.provider_id == expected.provider_id && account.id == expected.account_id
            })
            .ok_or_else(|| Error::UnknownAccount(expected.account_id.clone()))?;
        if account.state != StoredAccountState::Complete {
            return Err(Error::UnknownAccount(expected.account_id.clone()));
        }
        if account.account_incarnation != expected.account_incarnation {
            return Err(Error::StaleAccount {
                account_id: expected.account_id.clone(),
            });
        }
        SelectedUseLease::acquire_while_registry_held(&self.path, expected)
    }

    fn update_account(
        &self,
        provider_id: &str,
        account_id: &str,
        update: impl FnOnce(&mut StoredAccountMetadata) -> Result<()>,
    ) -> Result<()> {
        self.with_locked_mut(|document| {
            let account = document
                .accounts
                .iter_mut()
                .find(|account| account.provider_id == provider_id && account.id == account_id)
                .ok_or_else(|| Error::UnknownAccount(account_id.to_string()))?;
            update(account)
        })
    }

    fn with_locked<R>(
        &self,
        reader: impl FnOnce(&StoredAccountsDocument) -> Result<R>,
    ) -> Result<R> {
        let _process = in_process_guard()?;
        let _file = RegistryFileLock::acquire(&self.path)?;
        let document = self.read_document_under_lock()?;
        reader(&document)
    }

    fn with_locked_mut<R>(
        &self,
        mutator: impl FnOnce(&mut StoredAccountsDocument) -> Result<R>,
    ) -> Result<R> {
        let _process = in_process_guard()?;
        let _file = RegistryFileLock::acquire(&self.path)?;
        let mut document = self.read_document_under_lock()?;
        let result = mutator(&mut document)?;
        self.write_document(&document)?;
        Ok(result)
    }

    fn read_document_under_lock(&self) -> Result<StoredAccountsDocument> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StoredAccountsDocument::default());
            }
            Err(error) => return Err(crate::fsx::io_at(&self.path, error)),
        };
        let migrated_from_v1 =
            document_schema_version(&bytes)? == super::document::STORED_ACCOUNTS_VERSION_V1;
        let document = parse_document_bytes(&bytes).map_err(|error| match error {
            Error::ConfigRead { provider, reason } => Error::ConfigRead {
                provider,
                reason: format!("{}: {reason}", self.path.display()),
            },
            other => other,
        })?;
        validate_document(&document).map_err(|error| Error::ConfigRead {
            provider: "account-metadata".to_string(),
            reason: format!("{} is inconsistent: {error}", self.path.display()),
        })?;
        if migrated_from_v1 {
            self.write_document(&document)?;
        }
        Ok(document)
    }

    fn write_document(&self, document: &StoredAccountsDocument) -> Result<()> {
        validate_document(document)?;
        if document.schema_version != STORED_ACCOUNTS_VERSION {
            return Err(Error::ConfigWrite {
                provider: "account-metadata".to_string(),
                reason: format!(
                    "refusing to write unsupported schema version {}",
                    document.schema_version
                ),
            });
        }
        if let Some(parent) = self.path.parent() {
            crate::fsx::create_dir_all_private(parent)?;
        }
        let mut bytes = serde_json::to_vec_pretty(document)?;
        bytes.push(b'\n');
        crate::fsx::write_atomic(&self.path, &bytes)
    }
}

fn document_schema_version(bytes: &[u8]) -> Result<u32> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| Error::ConfigRead {
            provider: "account-metadata".to_string(),
            reason: format!("metadata is not valid JSON: {error}"),
        })?;
    value
        .get("schemaVersion")
        .and_then(|field| field.as_u64())
        .ok_or_else(|| Error::ConfigRead {
            provider: "account-metadata".to_string(),
            reason: "metadata is missing schemaVersion".to_string(),
        })
        .map(|version| version as u32)
}

fn selected_binding_from_document(
    document: &StoredAccountsDocument,
    provider_id: &str,
) -> Option<SelectedAccountBinding> {
    let account = document.accounts.iter().find(|account| {
        account.provider_id == provider_id
            && account.state == StoredAccountState::Complete
            && account.is_selected
    })?;
    Some(SelectedAccountBinding {
        provider_id: provider_id.to_string(),
        account_id: account.id.clone(),
        account_incarnation: account.account_incarnation.clone(),
        selection_revision: selection_revision_for(document, provider_id),
    })
}

fn binding_for_selection(
    document: &StoredAccountsDocument,
    provider_id: &str,
    revision: u64,
) -> Result<SelectedAccountBinding> {
    let account = document
        .accounts
        .iter()
        .find(|account| {
            account.provider_id == provider_id
                && account.state == StoredAccountState::Complete
                && account.is_selected
        })
        .ok_or_else(|| Error::UnknownAccount(provider_id.to_string()))?;
    Ok(SelectedAccountBinding {
        provider_id: provider_id.to_string(),
        account_id: account.id.clone(),
        account_incarnation: account.account_incarnation.clone(),
        selection_revision: revision,
    })
}

fn in_process_guard() -> Result<MutexGuard<'static, ()>> {
    STORED_ACCOUNTS_IN_PROCESS_LOCK.lock().map_err(|_| {
        Error::Io(std::io::Error::other(
            "stored-account metadata lock is poisoned",
        ))
    })
}
