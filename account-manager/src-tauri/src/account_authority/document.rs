//! Versioned on-disk registry document and v1→v2 migration.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::{StoredAccountMetadata, StoredAccountState};

use super::incarnation::{new_account_incarnation, validate_account_incarnation};

pub(crate) const STORED_ACCOUNTS_VERSION_V1: u32 = 1;
pub(crate) const STORED_ACCOUNTS_VERSION: u32 = 2;
const STORED_ACCOUNTS_VERSION_V1_U64: u64 = STORED_ACCOUNTS_VERSION_V1 as u64;
const STORED_ACCOUNTS_VERSION_U64: u64 = STORED_ACCOUNTS_VERSION as u64;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoredAccountsDocumentV1 {
    schema_version: u32,
    accounts: Vec<StoredAccountMetadataV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredAccountMetadataV1 {
    id: String,
    provider_id: String,
    label: String,
    auth_kind: crate::model::AuthKind,
    state: StoredAccountState,
    material: crate::model::StoredAccountMaterial,
    is_selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoredAccountsDocument {
    pub schema_version: u32,
    #[serde(default)]
    pub selection_revisions: BTreeMap<String, u64>,
    pub accounts: Vec<StoredAccountMetadata>,
}

impl Default for StoredAccountsDocument {
    fn default() -> Self {
        Self {
            schema_version: STORED_ACCOUNTS_VERSION,
            selection_revisions: BTreeMap::new(),
            accounts: Vec::new(),
        }
    }
}

pub(crate) fn parse_document_bytes(bytes: &[u8]) -> Result<StoredAccountsDocument> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| Error::ConfigRead {
            provider: "account-metadata".to_string(),
            reason: format!("metadata is not valid JSON: {error}"),
        })?;
    let version = value
        .get("schemaVersion")
        .and_then(|field| field.as_u64())
        .ok_or_else(|| Error::ConfigRead {
            provider: "account-metadata".to_string(),
            reason: "metadata is missing schemaVersion".to_string(),
        })?;
    match version {
        STORED_ACCOUNTS_VERSION_V1_U64 => {
            let v1: StoredAccountsDocumentV1 =
                serde_json::from_value(value).map_err(|error| Error::ConfigRead {
                    provider: "account-metadata".to_string(),
                    reason: format!("v1 metadata is malformed: {error}"),
                })?;
            if v1.schema_version != STORED_ACCOUNTS_VERSION_V1 {
                return Err(unsupported_schema(v1.schema_version));
            }
            Ok(migrate_v1_document(v1))
        }
        STORED_ACCOUNTS_VERSION_U64 => {
            let document: StoredAccountsDocument =
                serde_json::from_value(value).map_err(|error| Error::ConfigRead {
                    provider: "account-metadata".to_string(),
                    reason: format!("v2 metadata is malformed: {error}"),
                })?;
            if document.schema_version != STORED_ACCOUNTS_VERSION {
                return Err(unsupported_schema(document.schema_version));
            }
            Ok(document)
        }
        other => Err(unsupported_schema(other as u32)),
    }
}

fn migrate_v1_document(v1: StoredAccountsDocumentV1) -> StoredAccountsDocument {
    let mut selection_revisions = BTreeMap::new();
    let mut selected_providers = HashSet::new();
    for account in &v1.accounts {
        if account.is_selected {
            selected_providers.insert(account.provider_id.clone());
        }
    }
    for account in &v1.accounts {
        selection_revisions
            .entry(account.provider_id.clone())
            .or_insert(if selected_providers.contains(&account.provider_id) {
                1
            } else {
                0
            });
    }
    let accounts = v1
        .accounts
        .into_iter()
        .map(|account| StoredAccountMetadata {
            id: account.id,
            provider_id: account.provider_id,
            label: account.label,
            auth_kind: account.auth_kind,
            state: account.state,
            material: account.material,
            is_selected: account.is_selected,
            account_incarnation: new_account_incarnation(),
        })
        .collect();
    StoredAccountsDocument {
        schema_version: STORED_ACCOUNTS_VERSION,
        selection_revisions,
        accounts,
    }
}

pub(crate) fn validate_document(document: &StoredAccountsDocument) -> Result<()> {
    if document.schema_version != STORED_ACCOUNTS_VERSION {
        return Err(unsupported_schema(document.schema_version));
    }
    let mut identities = HashSet::new();
    let mut selected_providers = HashSet::new();
    for account in &document.accounts {
        validate_metadata_fields(&account.provider_id, &account.id, &account.label)?;
        validate_account_incarnation(&account.account_incarnation)?;
        if !identities.insert((account.provider_id.as_str(), account.id.as_str())) {
            return Err(metadata_write_error(
                &account.provider_id,
                format!("account `{}` appears more than once", account.id),
            ));
        }
        if account.is_selected
            && (account.state != StoredAccountState::Complete
                || !selected_providers.insert(account.provider_id.as_str()))
        {
            return Err(metadata_write_error(
                &account.provider_id,
                "selection metadata is inconsistent",
            ));
        }
    }
    Ok(())
}

pub(crate) fn selection_revision_for(document: &StoredAccountsDocument, provider_id: &str) -> u64 {
    document
        .selection_revisions
        .get(provider_id)
        .copied()
        .unwrap_or(0)
}

pub(crate) fn bump_selection_revision(
    document: &mut StoredAccountsDocument,
    provider_id: &str,
) -> Result<u64> {
    let current = selection_revision_for(document, provider_id);
    let next = current
        .checked_add(1)
        .ok_or_else(|| metadata_write_error(provider_id, "selection revision overflow"))?;
    document
        .selection_revisions
        .insert(provider_id.to_string(), next);
    Ok(next)
}

pub(crate) fn validate_metadata_fields(
    provider_id: &str,
    account_id: &str,
    label: &str,
) -> Result<()> {
    if !account_id_is_safe(provider_id) {
        return Err(metadata_write_error(
            provider_id,
            "provider id is not path-safe",
        ));
    }
    if !account_id_is_safe(account_id) {
        return Err(metadata_write_error(
            provider_id,
            "account id is not path-safe",
        ));
    }
    if label.trim().is_empty() || label.len() > 256 || label.contains(['\0', '\r', '\n']) {
        return Err(metadata_write_error(
            provider_id,
            "account label is empty or invalid",
        ));
    }
    Ok(())
}

pub(crate) fn metadata_write_error(provider_id: &str, reason: impl Into<String>) -> Error {
    Error::ConfigWrite {
        provider: provider_id.to_string(),
        reason: reason.into(),
    }
}

fn account_id_is_safe(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() <= 128
        && !account_id.contains("..")
        && account_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn unsupported_schema(version: u32) -> Error {
    Error::ConfigRead {
        provider: "account-metadata".to_string(),
        reason: format!(
            "uses unsupported schema version {version} (expected {})",
            STORED_ACCOUNTS_VERSION
        ),
    }
}
