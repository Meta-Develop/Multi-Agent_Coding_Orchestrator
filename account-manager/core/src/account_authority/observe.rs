//! Account-scoped observation types for `account.observe`.
//!
//! Categories report unknown, stale, unavailable, failed, or observed content
//! separately. Absence of a numeric quota signal is never encoded as zero.

use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelsObservation {
    pub models: Vec<ObservedModel>,
}

/// Closed effort spellings that may appear on Observed model content.
fn is_known_observed_effort(value: &str) -> bool {
    matches!(
        value,
        "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | "ultra"
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
            models: vec![ObservedModel {
                model_id: String::new(),
                supported_efforts: Some(vec!["high".to_string()]),
                default_effort: None,
            }],
        })
        .is_err());
        assert!(validate_observed_models(&ModelsObservation {
            models: vec![ObservedModel {
                model_id: "gpt-5.6-sol".to_string(),
                supported_efforts: Some(vec!["ludicrous".to_string()]),
                default_effort: None,
            }],
        })
        .is_err());
        assert!(validate_observed_models(&ModelsObservation {
            models: vec![ObservedModel {
                model_id: "gpt-5.6-sol".to_string(),
                supported_efforts: Some(vec!["high".to_string(), "xhigh".to_string()]),
                default_effort: Some("high".to_string()),
            }],
        })
        .is_ok());
    }

    #[test]
    fn observed_models_reject_empty_list_and_empty_efforts() {
        assert!(validate_observed_models(&ModelsObservation { models: Vec::new() }).is_err());
        assert!(validate_observed_models(&ModelsObservation {
            models: vec![ObservedModel {
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
            models: vec![ObservedModel {
                model_id: "gpt-5.6-sol".to_string(),
                supported_efforts: Some(vec!["high".to_string()]),
                default_effort: Some("xhigh".to_string()),
            }],
        })
        .is_err());
        assert!(validate_observed_models(&ModelsObservation {
            models: vec![ObservedModel {
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
