//! Account-scoped observation for one frozen selection binding.

use std::collections::BTreeSet;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::account_authority::{
    AccountObserveRequest, AccountObserveResult, AuthObservation, CategoryObservation,
    ModelsObservation, ObserveCategory, ObservationError, ObservationErrorKind,
    QuotaObservation, StoredAccountRegistry,
};
use crate::error::{Error, Result};
use crate::storage::CredentialStore;

use super::ProviderAdapter;

/// Observe only the account named by `request.binding`. Never selects another account.
pub fn observe_selected_account(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    request: AccountObserveRequest,
    credential_store: Option<&dyn CredentialStore>,
) -> Result<AccountObserveResult> {
    if request.categories.is_empty() {
        return Err(Error::ConfigRead {
            provider: request.binding.provider_id.clone(),
            reason: "account.observe requires at least one category".to_string(),
        });
    }
    let categories: BTreeSet<ObserveCategory> = request.categories.iter().copied().collect();
    if categories.len() != request.categories.len() {
        return Err(Error::ConfigRead {
            provider: request.binding.provider_id.clone(),
            reason: "account.observe categories must not contain duplicates".to_string(),
        });
    }
    if request.binding.provider_id != adapter.id() {
        return Err(Error::UnknownProvider(request.binding.provider_id.clone()));
    }

    let _lease = registry.acquire_selected_use(&request.binding)?;
    let account = registry.complete(adapter.id(), &request.binding.account_id)?;

    let payload = adapter.observe_account(&account, &categories, credential_store)?;
    let observed_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| Error::ConfigRead {
            provider: adapter.id().to_string(),
            reason: format!("could not format observation time: {error}"),
        })?;

    Ok(AccountObserveResult {
        binding: request.binding,
        observed_at,
        auth: payload.auth,
        models: payload.models,
        quota: payload.quota,
    })
}

/// Per-category observations returned by an adapter for one stored account.
#[derive(Debug, Clone, PartialEq)]
pub struct AdapterObservePayload {
    pub auth: Option<CategoryObservation<AuthObservation>>,
    pub models: Option<CategoryObservation<ModelsObservation>>,
    pub quota: Option<CategoryObservation<QuotaObservation>>,
}

impl AdapterObservePayload {
    pub fn empty() -> Self {
        Self {
            auth: None,
            models: None,
            quota: None,
        }
    }
}

pub(crate) fn models_category_default() -> CategoryObservation<ModelsObservation> {
    CategoryObservation::unknown()
}

pub(crate) fn auth_category_unavailable() -> CategoryObservation<AuthObservation> {
    CategoryObservation::unavailable()
}

pub(crate) fn observation_error_from_core(error: &Error) -> ObservationError {
    let kind = match error {
        Error::ConfigRead { .. } => ObservationErrorKind::ConfigRead,
        Error::CredentialStoreUnavailable(_) => ObservationErrorKind::CredentialStoreUnavailable,
        _ => ObservationErrorKind::Other,
    };
    ObservationError {
        kind,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthKind, StoredAccountMaterial, StoredAccountMetadata, StoredAccountState,
    };

    struct StubAdapter;

    impl ProviderAdapter for StubAdapter {
        fn id(&self) -> &'static str {
            "stub"
        }

        fn descriptor(&self) -> crate::model::ProviderDescriptor {
            unimplemented!("not used in observe unit tests")
        }

        fn config_paths(&self) -> Vec<std::path::PathBuf> {
            Vec::new()
        }

        fn detect(&self) -> crate::model::InstallState {
            crate::model::InstallState::Unknown
        }

        fn list_accounts(&self) -> Result<Vec<crate::model::Account>> {
            Ok(Vec::new())
        }

        fn activate_account(&self, _account_id: &str) -> Result<()> {
            Err(Error::NotImplemented("activate"))
        }

        fn quota_for_account(
            &self,
            _account: &StoredAccountMetadata,
        ) -> Result<Vec<crate::model::QuotaSnapshot>> {
            Ok(Vec::new())
        }
    }

    fn fixture_account() -> StoredAccountMetadata {
        StoredAccountMetadata {
            id: "work".to_string(),
            provider_id: "stub".to_string(),
            label: "Work".to_string(),
            auth_kind: AuthKind::ApiKey,
            state: StoredAccountState::Complete,
            material: StoredAccountMaterial::CredentialStore,
            is_selected: true,
            account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
        }
    }

    #[test]
    fn empty_quota_maps_to_unknown_not_observed_zero() {
        let adapter = StubAdapter;
        let snapshots = adapter
            .quota_for_account(&fixture_account())
            .expect("quota read");
        assert!(snapshots.is_empty());
    }
}
