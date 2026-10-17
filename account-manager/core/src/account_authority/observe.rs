//! Account-scoped observation types for `account.observe`.
//!
//! Categories report unknown, stale, unavailable, failed, or observed content
//! separately. Absence of a numeric quota signal is never encoded as zero.

use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::model::{AuthKind, QuotaSnapshot};

use super::binding::SelectedAccountBinding;

/// One observation category named in an `account.observe` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObserveCategory {
    Auth,
    Models,
    Quota,
}

/// Closed request: exact selection binding and explicit categories only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountObserveRequest {
    pub binding: SelectedAccountBinding,
    pub categories: Vec<ObserveCategory>,
}

/// Account-scoped observation echoing the binding and per-category outcomes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountObserveResult {
    pub binding: SelectedAccountBinding,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<CategoryObservation<AuthObservation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub models: Option<CategoryObservation<ModelsObservation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota: Option<CategoryObservation<QuotaObservation>>,
}

/// One category's outcome plus optional typed content when [`ObservationOutcome::Observed`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryObservation<T> {
    pub outcome: ObservationOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<T>,
}

/// Per-category state machine shared by auth, models, and quota.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ObservationOutcome {
    Unknown,
    Stale,
    Unavailable,
    Failed { error: ObservationError },
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservationError {
    pub kind: ObservationErrorKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservationErrorKind {
    ConfigRead,
    CredentialStoreUnavailable,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthObservation {
    pub auth_kind: AuthKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masked_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// One account-observed model. Effort fields are omitted when unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservedModel {
    pub model_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_efforts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_effort: Option<String>,
    #[serde(default)]
    pub access: ModelAccessOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelsObservation {
    pub models: Vec<ObservedModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ModelCatalogProvenance>,
}

/// Access is distinct from advertisement, authentication, and phase capabilities.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelAccessOutcome {
    #[default]
    UnknownAccess,
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelCatalogSourceKind {
    ManagedHomeCache,
    AuthenticatedCatalog,
    ProductiveExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelAccessBasis {
    ConfirmedModelEntitlement,
    AcceptedProductiveExecution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelCatalogProvenance {
    pub source_kind: ModelCatalogSourceKind,
    pub fetched_at: Option<String>,
    pub stale: bool,
    pub principal_binding: Option<SelectedAccountBinding>,
    pub access_basis: Option<ModelAccessBasis>,
}

/// Closed effort spellings that may appear on Observed model content.
fn is_known_observed_effort(value: &str) -> bool {
    matches!(
        value,
        "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | "ultra"
    )
}

/// Validate content that would be admitted as [`ObservationOutcome::Observed`].
///
/// Empty `models`, empty `supportedEfforts`, unknown effort spellings, and a
/// `defaultEffort` absent from `supportedEfforts` are not Observed.
pub fn validate_observed_models(observation: &ModelsObservation) -> Result<(), String> {
    if observation.models.is_empty() {
        return Err("Observed models must contain at least one modelId".to_string());
    }
    for model in &observation.models {
        if model.access != ModelAccessOutcome::UnknownAccess {
            let provenance = observation
                .provenance
                .as_ref()
                .ok_or("Known model access requires source provenance")?;
            if provenance.stale
                || provenance.principal_binding.is_none()
                || provenance.source_kind == ModelCatalogSourceKind::ManagedHomeCache
                || !matches!(
                    (provenance.source_kind, provenance.access_basis),
                    (
                        ModelCatalogSourceKind::AuthenticatedCatalog,
                        Some(ModelAccessBasis::ConfirmedModelEntitlement)
                    ) | (
                        ModelCatalogSourceKind::ProductiveExecution,
                        Some(ModelAccessBasis::AcceptedProductiveExecution)
                    )
                )
            {
                return Err(
                    "Known model access requires fresh principal-bound access evidence".to_string(),
                );
            }
            let fetched_at = provenance
                .fetched_at
                .as_deref()
                .ok_or("Known model access requires an RFC3339 source timestamp")?;
            if OffsetDateTime::parse(fetched_at, &Rfc3339).is_err() {
                return Err(
                    "Known model access requires a valid RFC3339 source timestamp".to_string(),
                );
            }
        }
        if model.model_id.trim().is_empty() {
            return Err("Observed modelId must be a non-empty identifier".to_string());
        }
        if let Some(efforts) = &model.supported_efforts {
            if efforts.is_empty() {
                return Err(
                    "Observed supportedEfforts must be omitted when unknown, not empty".to_string(),
                );
            }
            for effort in efforts {
                if !is_known_observed_effort(effort) {
                    return Err(format!(
                        "Observed supportedEfforts contains unknown effort '{effort}'"
                    ));
                }
            }
            if let Some(default_effort) = &model.default_effort {
                if !efforts.iter().any(|effort| effort == default_effort) {
                    return Err(
                        "Observed defaultEffort must be present in supportedEfforts".to_string()
                    );
                }
            }
        } else if let Some(default_effort) = &model.default_effort {
            if !is_known_observed_effort(default_effort) {
                return Err(format!(
                    "Observed defaultEffort '{default_effort}' is not a known effort"
                ));
            }
        }
    }
    Ok(())
}

/// The outer selected-account tuple cannot substitute for source identity evidence.
pub fn validate_observed_models_for_binding(
    observation: &ModelsObservation,
    binding: &SelectedAccountBinding,
) -> Result<(), String> {
    validate_observed_models(observation)?;
    if let Some(principal) = observation
        .provenance
        .as_ref()
        .and_then(|provenance| provenance.principal_binding.as_ref())
    {
        if principal != binding {
            return Err("Model catalog source principal differs from selected account".to_string());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuotaObservation {
    pub snapshots: Vec<QuotaSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_label: Option<String>,
}

impl<T> CategoryObservation<T> {
    pub fn unknown() -> Self {
        Self {
            outcome: ObservationOutcome::Unknown,
            content: None,
        }
    }

    pub fn stale() -> Self {
        Self {
            outcome: ObservationOutcome::Stale,
            content: None,
        }
    }

    pub fn unavailable() -> Self {
        Self {
            outcome: ObservationOutcome::Unavailable,
            content: None,
        }
    }

    pub fn failed(error: ObservationError) -> Self {
        Self {
            outcome: ObservationOutcome::Failed { error },
            content: None,
        }
    }

    pub fn observed(content: T) -> Self {
        Self {
            outcome: ObservationOutcome::Observed,
            content: Some(content),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_wire_and_cache_advertisement_never_assert_access() {
        let mut models: ModelsObservation = serde_json::from_str(
            r#"{"models":[{"modelId":"native-model","supportedEfforts":["none"],"defaultEffort":"none"}]}"#,
        ).unwrap();
        assert_eq!(models.models[0].access, ModelAccessOutcome::UnknownAccess);
        assert!(models.provenance.is_none());
        assert!(validate_observed_models(&models).is_ok());
        models.provenance = Some(ModelCatalogProvenance {
            source_kind: ModelCatalogSourceKind::ManagedHomeCache,
            fetched_at: None,
            stale: true,
            principal_binding: None,
            access_basis: None,
        });
        for access in [
            ModelAccessOutcome::Available,
            ModelAccessOutcome::Unavailable,
        ] {
            models.models[0].access = access;
            assert!(validate_observed_models(&models).is_err());
        }
        models.models[0].access = ModelAccessOutcome::UnknownAccess;
        models.models[0].supported_efforts = Some(vec!["deep".into()]);
        assert!(validate_observed_models(&models).is_err());
    }

    #[test]
    fn known_access_requires_fresh_exact_principal_and_evidence_basis() {
        let binding = SelectedAccountBinding {
            provider_id: "runtime-cli".into(),
            account_id: "account".into(),
            account_incarnation: "0123456789abcdef0123456789abcdef".into(),
            selection_revision: 2,
        };
        let mut models = ModelsObservation {
            models: vec![ObservedModel {
                model_id: "native-model".into(),
                supported_efforts: Some(vec!["none".into()]),
                default_effort: None,
                access: ModelAccessOutcome::Unavailable,
            }],
            provenance: Some(ModelCatalogProvenance {
                source_kind: ModelCatalogSourceKind::AuthenticatedCatalog,
                fetched_at: Some("2026-10-03T00:00:00Z".into()),
                stale: false,
                principal_binding: Some(binding.clone()),
                access_basis: None,
            }),
        };
        // Authentication of a generic catalog GET is insufficient.
        assert!(validate_observed_models_for_binding(&models, &binding).is_err());
        models.provenance.as_mut().unwrap().access_basis =
            Some(ModelAccessBasis::ConfirmedModelEntitlement);
        assert!(validate_observed_models_for_binding(&models, &binding).is_ok());
        let mut different = binding.clone();
        different.selection_revision += 1;
        assert!(validate_observed_models_for_binding(&models, &different).is_err());
        models.provenance.as_mut().unwrap().stale = true;
        assert!(validate_observed_models_for_binding(&models, &binding).is_err());
        assert!(serde_json::from_str::<ModelsObservation>(
            r#"{"models":[],"provenance":{"sourceKind":"managed-home-cache","fetchedAt":null,"stale":true,"principalBinding":null,"accessBasis":null,"inventedAuthority":true}}"#
        ).is_err());
    }

    fn qualified_models_for_access(access: ModelAccessOutcome) -> ModelsObservation {
        ModelsObservation {
            models: vec![ObservedModel {
                model_id: "native-model".into(),
                supported_efforts: None,
                default_effort: None,
                access,
            }],
            provenance: Some(ModelCatalogProvenance {
                source_kind: ModelCatalogSourceKind::AuthenticatedCatalog,
                fetched_at: Some("2026-10-03T00:00:00Z".into()),
                stale: false,
                principal_binding: Some(SelectedAccountBinding {
                    provider_id: "runtime-cli".into(),
                    account_id: "account".into(),
                    account_incarnation: "0123456789abcdef0123456789abcdef".into(),
                    selection_revision: 2,
                }),
                access_basis: Some(ModelAccessBasis::ConfirmedModelEntitlement),
            }),
        }
    }

    #[test]
    fn known_access_requires_valid_rfc3339_source_timestamp() {
        for access in [
            ModelAccessOutcome::Available,
            ModelAccessOutcome::Unavailable,
        ] {
            let mut models = qualified_models_for_access(access);
            for fetched_at in [
                None,
                Some(""),
                Some("   "),
                Some("not-a-timestamp"),
                Some("2026-10-03"),
                Some("2026-02-30T00:00:00Z"),
            ] {
                models.provenance.as_mut().unwrap().fetched_at = fetched_at.map(str::to_string);
                let error = validate_observed_models(&models).unwrap_err();
                assert!(error.contains("source timestamp"));
            }
        }
    }

    #[test]
    fn known_access_accepts_valid_rfc3339_source_timezone_offsets() {
        for access in [
            ModelAccessOutcome::Available,
            ModelAccessOutcome::Unavailable,
        ] {
            let mut models = qualified_models_for_access(access);
            for fetched_at in ["2026-10-03T12:34:56+09:00", "2026-10-03T03:34:56-05:30"] {
                models.provenance.as_mut().unwrap().fetched_at = Some(fetched_at.into());
                assert!(validate_observed_models(&models).is_ok());
            }
        }
    }

    #[test]
    fn unknown_access_allows_absent_or_invalid_source_timestamp() {
        let mut models = qualified_models_for_access(ModelAccessOutcome::UnknownAccess);
        let provenance = models.provenance.as_mut().unwrap();
        provenance.source_kind = ModelCatalogSourceKind::ManagedHomeCache;
        provenance.principal_binding = None;
        provenance.access_basis = None;
        provenance.stale = true;
        for fetched_at in [
            None,
            Some(""),
            Some("not-a-timestamp"),
            Some("2026-02-30T00:00:00Z"),
        ] {
            models.provenance.as_mut().unwrap().fetched_at = fetched_at.map(str::to_string);
            assert!(validate_observed_models(&models).is_ok());
        }
        models.provenance = None;
        assert!(validate_observed_models(&models).is_ok());
    }

    #[test]
    fn unknown_quota_serializes_without_numeric_utilization() {
        let result = AccountObserveResult {
            binding: SelectedAccountBinding {
                provider_id: "gemini-cli".to_string(),
                account_id: "work".to_string(),
                account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
                selection_revision: 1,
            },
            observed_at: "2026-09-18T00:00:00Z".to_string(),
            auth: None,
            models: None,
            quota: Some(CategoryObservation::unknown()),
        };
        let json = serde_json::to_string(&result).expect("json");
        assert!(!json.contains("utilization"));
        assert!(json.contains(r#""kind":"unknown""#));
    }

    #[test]
    fn observed_models_require_ids_and_known_efforts() {
        assert!(validate_observed_models(&ModelsObservation {
            provenance: None,
            models: vec![ObservedModel {
                access: crate::account_authority::ModelAccessOutcome::UnknownAccess,
                model_id: String::new(),
                supported_efforts: Some(vec!["high".to_string()]),
                default_effort: None,
            }],
        })
        .is_err());
        assert!(validate_observed_models(&ModelsObservation {
            provenance: None,
            models: vec![ObservedModel {
                access: crate::account_authority::ModelAccessOutcome::UnknownAccess,
                model_id: "gpt-5.6-sol".to_string(),
                supported_efforts: Some(vec!["ludicrous".to_string()]),
                default_effort: None,
            }],
        })
        .is_err());
        assert!(validate_observed_models(&ModelsObservation {
            provenance: None,
            models: vec![ObservedModel {
                access: crate::account_authority::ModelAccessOutcome::UnknownAccess,
                model_id: "gpt-5.6-sol".to_string(),
                supported_efforts: Some(vec!["high".to_string(), "xhigh".to_string()]),
                default_effort: Some("high".to_string()),
            }],
        })
        .is_ok());
    }

    #[test]
    fn observed_models_reject_empty_list_and_empty_efforts() {
        assert!(validate_observed_models(&ModelsObservation {
            provenance: None,
            models: Vec::new()
        })
        .is_err());
        assert!(validate_observed_models(&ModelsObservation {
            provenance: None,
            models: vec![ObservedModel {
                access: crate::account_authority::ModelAccessOutcome::UnknownAccess,
                model_id: "gpt-5.6-sol".to_string(),
                supported_efforts: Some(Vec::new()),
                default_effort: None,
            }],
        })
        .is_err());
    }

    #[test]
    fn observed_default_effort_must_be_supported() {
        assert!(validate_observed_models(&ModelsObservation {
            provenance: None,
            models: vec![ObservedModel {
                access: crate::account_authority::ModelAccessOutcome::UnknownAccess,
                model_id: "gpt-5.6-sol".to_string(),
                supported_efforts: Some(vec!["high".to_string()]),
                default_effort: Some("xhigh".to_string()),
            }],
        })
        .is_err());
        assert!(validate_observed_models(&ModelsObservation {
            provenance: None,
            models: vec![ObservedModel {
                access: crate::account_authority::ModelAccessOutcome::UnknownAccess,
                model_id: "gpt-5.6-sol".to_string(),
                supported_efforts: Some(vec!["high".to_string(), "xhigh".to_string()]),
                default_effort: Some("xhigh".to_string()),
            }],
        })
        .is_ok());
    }

    #[test]
    fn unknown_models_still_omit_effort_fields() {
        let unknown = CategoryObservation::<ModelsObservation>::unknown();
        let json = serde_json::to_string(&unknown).expect("json");
        assert!(!json.contains("supportedEfforts"));
        assert!(!json.contains("defaultEffort"));
        assert!(!json.contains("modelId"));
        assert!(!json.contains("models"));
        assert!(json.contains(r#""kind":"unknown""#));
    }
}
