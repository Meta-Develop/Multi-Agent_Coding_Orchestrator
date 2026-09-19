//! Account-scoped observation for one frozen selection binding.

use std::collections::BTreeSet;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::account_authority::{
    AccountObserveRequest, AccountObserveResult, AuthObservation, CategoryObservation,
    ModelsObservation, ObservationError, ObservationErrorKind, ObserveCategory, QuotaObservation,
    StoredAccountRegistry,
};
use crate::error::{Error, Result};
use crate::model::QuotaSnapshot;
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

/// Fail closed before quota snapshots become `Observed` content (FR-5, NFR-8).
pub(crate) fn invalid_quota_snapshot_message(snapshots: &[QuotaSnapshot]) -> Option<&'static str> {
    for snapshot in snapshots {
        if !snapshot.utilization.is_finite() || !(0.0..=1.0).contains(&snapshot.utilization) {
            return Some("adapter returned quota utilization outside 0..=1");
        }
        if !is_rfc3339_timestamp(&snapshot.captured_at) {
            return Some("adapter returned quota with invalid capturedAt");
        }
        if snapshot
            .resets_at
            .as_deref()
            .is_some_and(|resets_at| !is_rfc3339_timestamp(resets_at))
        {
            return Some("adapter returned quota with invalid resetsAt");
        }
    }
    None
}

pub(crate) fn is_rfc3339_timestamp(timestamp: &str) -> bool {
    OffsetDateTime::parse(timestamp, &Rfc3339).is_ok()
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
    use crate::account_authority::ObservationOutcome;
    use crate::model::{
        AuthKind, QuotaSnapshot, QuotaSource, StoredAccountMaterial, StoredAccountMetadata,
        StoredAccountState,
    };

    struct StubAdapter;

    struct InvalidQuotaResetsAdapter;

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
        ) -> Result<Vec<QuotaSnapshot>> {
            Ok(Vec::new())
        }
    }

    impl ProviderAdapter for InvalidQuotaResetsAdapter {
        fn id(&self) -> &'static str {
            "invalid-quota"
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
        ) -> Result<Vec<QuotaSnapshot>> {
            Ok(vec![QuotaSnapshot {
                account_id: "work".to_string(),
                model: None,
                utilization: 0.42,
                window_label: None,
                resets_at: Some("not-rfc3339".to_string()),
                captured_at: "2030-01-01T00:00:00Z".to_string(),
                source: QuotaSource::LocalFile,
            }])
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

    #[test]
    fn invalid_quota_resets_at_fails_closed_without_invented_utilization() {
        use std::collections::BTreeSet;

        let adapter = InvalidQuotaResetsAdapter;
        let categories = BTreeSet::from([ObserveCategory::Quota]);
        let payload = adapter
            .observe_account(&fixture_account(), &categories, None)
            .expect("observe payload");
        let quota = payload.quota.expect("quota category");
        assert_ne!(quota.outcome, ObservationOutcome::Observed);
        assert!(quota.content.is_none());
        let json = serde_json::to_string(&quota).expect("json");
        assert!(!json.contains("utilization"));
        assert!(!json.contains("0.42"));
    }
}
