//! Identity provenance is descriptive, never execution or publication authority.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityBasis {
    /// Exact selection applied by the launch contract; no claim about served effort.
    Requested,
    ProviderReported,
}

/// Parent-owned launch identity. `model` and `effort` contain provider reports
/// only. A requested basis refers to the corresponding requested field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeIdentityObservation {
    pub requested_model: Option<String>,
    pub requested_effort: Option<String>,
    pub model: Option<String>,
    pub effort: Option<String>,
    #[serde(default)]
    pub model_basis: Option<IdentityBasis>,
    #[serde(default)]
    pub effort_basis: Option<IdentityBasis>,
}

/// Missing provider effort is allowed only with an explicit canonical request.
/// A reported contradiction (including an alias) never falls back to requested.
pub(crate) fn effort_matches_request(requested: Option<&str>, reported: Option<&str>) -> bool {
    requested.is_some_and(|requested| {
        matches!(
            requested,
            "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | "ultra"
        ) && reported.is_none_or(|reported| reported == requested)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_effort_accepts_absence_but_never_upgrades_or_aliases() {
        for requested in ["low", "medium", "xhigh"] {
            assert!(effort_matches_request(Some(requested), None));
            assert!(effort_matches_request(Some(requested), Some(requested)));
        }
        for reported in ["xhigh", "LOW", "deep", ""] {
            assert!(!effort_matches_request(Some("low"), Some(reported)));
        }
        assert!(!effort_matches_request(None, None));
        assert!(!effort_matches_request(Some("deep"), None));
    }
}
