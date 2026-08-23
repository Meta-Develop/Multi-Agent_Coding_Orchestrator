//! Open identifier newtypes.
//!
//! These are strings, not closed enums, so later phases can introduce new
//! backends, providers, feature keys, and resource dimensions without
//! editing optimizer core types.

use serde::{Deserialize, Serialize};
use std::fmt;

use super::error::OptimizerError;

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, OptimizerError> {
                let value = value.into();
                if value.trim().is_empty() || value != value.trim() {
                    return Err(OptimizerError::EmptyIdentifier);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

typed_id!(
    /// Provider capability owner (for example `openai`, `xai`, `cursor`, `local`).
    ProviderId
);
typed_id!(
    /// Runtime adapter identity (for example `codex_cli`, `grok_build_cli`).
    BackendId
);
typed_id!(/// Family label that groups runtime slugs (for example `gpt-5.6`, `grok-4`).
    ModelFamilyId);
typed_id!(/// Catalog-advertised runtime slug. Never silently substituted.
    RuntimeSlug);
typed_id!(/// Version of the catalog snapshot that advertised a model.
    CatalogVersion);
typed_id!(PolicyId);
typed_id!(PolicyNodeId);
typed_id!(VerifierProfileId);
typed_id!(ContractId);
typed_id!(RequirementId);
typed_id!(ValidatorId);
typed_id!(CandidateId);
typed_id!(TaskId);
typed_id!(EvidenceId);
typed_id!(FeatureId);
typed_id!(ResourceDimensionId);
typed_id!(RoleId);
typed_id!(FindingId);
typed_id!(ReviewId);

/// Milliseconds since the Unix epoch. Serialisable and deterministic in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TimestampMillis(u64);

impl TimestampMillis {
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

impl BackendId {
    pub const CODEX_CLI: &'static str = "codex_cli";
    pub const CODEX_APP_SERVER: &'static str = "codex_app_server";
    pub const GROK_BUILD_CLI: &'static str = "grok_build_cli";
    pub const XAI_API: &'static str = "xai_api";
    pub const CURSOR_AGENT: &'static str = "cursor_agent";
    pub const LOCAL_MODEL: &'static str = "local_model";
    pub const FAKE_PROVIDER: &'static str = "fake_provider";

    pub fn well_known(name: &'static str) -> Self {
        Self(name.to_string())
    }
}

impl ResourceDimensionId {
    pub const CODEX_CREDITS: &'static str = "codex_credits";
    pub const GROK_BASIS_POINTS: &'static str = "grok_basis_points";
    pub const CURSOR_USAGE_UNITS: &'static str = "cursor_usage_units";
    pub const API_COST_USD: &'static str = "api_cost_usd";
    pub const LOCAL_COMPUTE_SECONDS: &'static str = "local_compute_seconds";
    pub const HUMAN_MINUTES: &'static str = "human_minutes";
    pub const HUMAN_REWORK_COST: &'static str = "human_rework_cost";

    pub fn well_known(name: &'static str) -> Self {
        Self(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_or_untrimmed_identifiers() {
        assert_eq!(
            BackendId::new("").unwrap_err(),
            OptimizerError::EmptyIdentifier
        );
        assert_eq!(
            ProviderId::new("  openai").unwrap_err(),
            OptimizerError::EmptyIdentifier
        );
    }
}
