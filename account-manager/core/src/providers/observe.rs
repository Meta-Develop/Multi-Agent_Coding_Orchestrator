//! Account-scoped observation for one frozen selection binding.

use std::collections::BTreeSet;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::account_authority::{
    validate_observed_models_for_binding, AccountObserveRequest, AccountObserveResult,
    AuthObservation, CategoryObservation, ModelsObservation, ObservationError,
    ObservationErrorKind, ObservationOutcome, ObserveCategory, QuotaObservation,
    SelectedAccountBinding, StoredAccountRegistry,
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

    let payload = observe_bound_account(
        adapter,
        &account,
        &request.binding,
        &categories,
        credential_store,
    )?;
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

/// Observe and validate model source evidence for the exact selected binding.
fn observe_bound_account(
    adapter: &dyn ProviderAdapter,
    account: &crate::model::StoredAccountMetadata,
    binding: &SelectedAccountBinding,
    categories: &BTreeSet<ObserveCategory>,
    credential_store: Option<&dyn CredentialStore>,
) -> Result<AdapterObservePayload> {
    let payload =
        adapter.observe_account_for_binding(account, binding, categories, credential_store)?;
    if let Some(models) = &payload.models {
        if models.outcome == ObservationOutcome::Observed {
            let content = models.content.as_ref().ok_or_else(|| Error::ConfigRead {
                provider: binding.provider_id.clone(),
                reason: "Observed model category requires content".to_string(),
            })?;
            validate_observed_models_for_binding(content, binding).map_err(|_| {
                Error::ConfigRead {
                    provider: binding.provider_id.clone(),
                    reason: "Observed model category has invalid source evidence".to_string(),
                }
            })?;
        }
    }
    Ok(payload)
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

    struct ObservationAdapter {
        expected_binding: Option<SelectedAccountBinding>,
        models: Option<CategoryObservation<ModelsObservation>>,
    }

    impl ProviderAdapter for ObservationAdapter {
        fn id(&self) -> &'static str {
            "stub"
        }
        fn descriptor(&self) -> crate::model::ProviderDescriptor {
            StubAdapter.descriptor()
        }
        fn config_paths(&self) -> Vec<std::path::PathBuf> {
            Vec::new()
        }
        fn detect(&self) -> crate::model::InstallState {
            StubAdapter.detect()
        }
        fn list_accounts(&self) -> Result<Vec<crate::model::Account>> {
            Ok(Vec::new())
        }
        fn activate_account(&self, account_id: &str) -> Result<()> {
            StubAdapter.activate_account(account_id)
        }
        fn observe_account(
            &self,
            account: &StoredAccountMetadata,
            categories: &BTreeSet<ObserveCategory>,
            credential_store: Option<&dyn CredentialStore>,
        ) -> Result<AdapterObservePayload> {
            assert!(
                self.expected_binding.is_none(),
                "bound override must be used"
            );
            assert_eq!(account, &fixture_account());
            assert_eq!(categories, &BTreeSet::from([ObserveCategory::Models]));
            assert!(credential_store.is_none());
            Ok(AdapterObservePayload {
                auth: None,
                models: self.models.clone(),
                quota: None,
            })
        }
        fn observe_account_for_binding(
            &self,
            account: &StoredAccountMetadata,
            binding: &SelectedAccountBinding,
            categories: &BTreeSet<ObserveCategory>,
            credential_store: Option<&dyn CredentialStore>,
        ) -> Result<AdapterObservePayload> {
            if let Some(expected) = &self.expected_binding {
                assert!(
                    binding == expected,
                    "exact selected binding must reach adapter"
                );
                assert_eq!(account, &fixture_account());
                assert_eq!(categories, &BTreeSet::from([ObserveCategory::Models]));
                assert!(credential_store.is_none());
                Ok(AdapterObservePayload {
                    auth: None,
                    models: self.models.clone(),
                    quota: None,
                })
            } else {
                self.observe_account(account, categories, credential_store)
            }
        }
    }

    struct LegacyObservationAdapter(ObservationAdapter);

    impl ProviderAdapter for LegacyObservationAdapter {
        fn id(&self) -> &'static str {
            self.0.id()
        }

        fn descriptor(&self) -> crate::model::ProviderDescriptor {
            self.0.descriptor()
        }

        fn config_paths(&self) -> Vec<std::path::PathBuf> {
            self.0.config_paths()
        }

        fn detect(&self) -> crate::model::InstallState {
            self.0.detect()
        }

        fn list_accounts(&self) -> Result<Vec<crate::model::Account>> {
            self.0.list_accounts()
        }

        fn activate_account(&self, account_id: &str) -> Result<()> {
            self.0.activate_account(account_id)
        }

        fn observe_account(
            &self,
            account: &StoredAccountMetadata,
            categories: &BTreeSet<ObserveCategory>,
            credential_store: Option<&dyn CredentialStore>,
        ) -> Result<AdapterObservePayload> {
            self.0
                .observe_account(account, categories, credential_store)
        }
    }

    fn fixture_binding() -> SelectedAccountBinding {
        SelectedAccountBinding {
            provider_id: "stub".into(),
            account_id: "work".into(),
            account_incarnation: "0123456789abcdef0123456789abcdef".into(),
            selection_revision: 7,
        }
    }

    fn cache_models() -> ModelsObservation {
        ModelsObservation {
            models: vec![crate::account_authority::ObservedModel {
                model_id: "cached-model".into(),
                supported_efforts: None,
                default_effort: None,
                access: crate::account_authority::ModelAccessOutcome::UnknownAccess,
            }],
            provenance: Some(crate::account_authority::ModelCatalogProvenance {
                source_kind: crate::account_authority::ModelCatalogSourceKind::ManagedHomeCache,
                fetched_at: None,
                stale: true,
                principal_binding: None,
                access_basis: None,
            }),
        }
    }

    fn observe_fixture(adapter: &dyn ProviderAdapter) -> Result<AdapterObservePayload> {
        observe_bound_account(
            adapter,
            &fixture_account(),
            &fixture_binding(),
            &BTreeSet::from([ObserveCategory::Models]),
            None,
        )
    }

    #[test]
    fn bound_hook_receives_exact_selected_tuple() {
        let adapter = ObservationAdapter {
            expected_binding: Some(fixture_binding()),
            models: Some(CategoryObservation::observed(cache_models())),
        };
        assert_eq!(observe_fixture(&adapter).unwrap().models, adapter.models);
    }

    #[test]
    fn observed_models_refuse_foreign_principal_and_missing_content() {
        let mut models = cache_models();
        let mut foreign = fixture_binding();
        foreign.selection_revision += 1;
        models.provenance.as_mut().unwrap().principal_binding = Some(foreign);
        let mut adapter = ObservationAdapter {
            expected_binding: Some(fixture_binding()),
            models: Some(CategoryObservation::observed(models)),
        };
        assert!(matches!(
            observe_fixture(&adapter),
            Err(Error::ConfigRead { .. })
        ));
        let category = adapter.models.as_mut().unwrap();
        category.content = None;
        assert!(matches!(
            observe_fixture(&adapter),
            Err(Error::ConfigRead { .. })
        ));
    }

    #[test]
    fn unknown_cache_models_without_source_principal_remain_unknown() {
        let adapter = ObservationAdapter {
            expected_binding: Some(fixture_binding()),
            models: Some(CategoryObservation::observed(cache_models())),
        };
        let payload = observe_fixture(&adapter).unwrap();
        assert_eq!(payload.models, adapter.models);
        let mut absent = adapter;
        absent.models = None;
        assert!(observe_fixture(&absent).unwrap().models.is_none());
        absent.models = Some(CategoryObservation::unavailable());
        assert_eq!(observe_fixture(&absent).unwrap().models, absent.models);
    }

    #[test]
    fn default_bound_hook_forwards_legacy_observation() {
        let legacy = LegacyObservationAdapter(ObservationAdapter {
            expected_binding: None,
            models: Some(CategoryObservation::observed(cache_models())),
        });
        let payload = observe_fixture(&legacy).expect("legacy observation");
        assert_eq!(payload.models, legacy.0.models);
        assert!(payload.auth.is_none());
        assert!(payload.quota.is_none());
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
