//! Runtime model catalog trait.
//!
//! Adapters from #146 implement [`RuntimeModelCatalog`]. The optimizer core
//! depends only on this snapshot, never on a provider CLI.
//!
//! Capability metadata used by policy instantiation (#165) is configurable
//! evidence — never a hardcoded vendor or model name.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::action::{CanonicalEffort, RuntimeModelId};
use super::error::OptimizerError;
use super::ids::{CatalogVersion, TimestampMillis};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub identity: RuntimeModelId,
    pub supported_efforts: Vec<CanonicalEffort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCatalogSnapshot {
    pub catalog_version: CatalogVersion,
    pub observed_at: TimestampMillis,
    pub models: Vec<CatalogEntry>,
}

impl ModelCatalogSnapshot {
    pub fn identities(&self) -> impl Iterator<Item = &RuntimeModelId> {
        self.models.iter().map(|entry| &entry.identity)
    }
}

/// Object-safe catalog. Implementations live at the #146 adapter boundary.
pub trait RuntimeModelCatalog {
    fn snapshot(&self) -> Result<ModelCatalogSnapshot, OptimizerError>;
}

/// Capability class used by the starter policy library. These are role
/// tiers, not vendors: assignment arrives as catalog evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityClass {
    Frontier,
    Worker,
    Precision,
}

impl CapabilityClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Frontier => "frontier",
            Self::Worker => "worker",
            Self::Precision => "precision",
        }
    }
}

impl std::fmt::Display for CapabilityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-model capability record. Filters (#165) consult this, not CLI names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCapability {
    pub identity: RuntimeModelId,
    pub supported_efforts: Vec<CanonicalEffort>,
    pub tool_capabilities: BTreeSet<String>,
    pub network_dependent: bool,
    pub trusted: bool,
    pub capability_class: CapabilityClass,
}

impl ModelCapability {
    pub fn from_entry(entry: &CatalogEntry) -> Self {
        Self {
            identity: entry.identity.clone(),
            supported_efforts: entry.supported_efforts.clone(),
            tool_capabilities: BTreeSet::new(),
            network_dependent: false,
            trusted: true,
            capability_class: CapabilityClass::Worker,
        }
    }

    pub fn supports_effort(&self, effort: &CanonicalEffort) -> bool {
        self.supported_efforts.contains(effort)
    }

    pub fn has_tools(&self, required: &BTreeSet<String>) -> bool {
        required
            .iter()
            .all(|tool| self.tool_capabilities.contains(tool))
    }
}

/// Evidence-backed capability view of a catalog snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCatalog {
    pub catalog_version: CatalogVersion,
    pub observed_at: TimestampMillis,
    pub models: Vec<ModelCapability>,
}

impl CapabilityCatalog {
    pub fn from_snapshot(snapshot: &ModelCatalogSnapshot) -> Self {
        Self {
            catalog_version: snapshot.catalog_version.clone(),
            observed_at: snapshot.observed_at,
            models: snapshot
                .models
                .iter()
                .map(ModelCapability::from_entry)
                .collect(),
        }
    }

    pub fn from_capabilities(
        catalog_version: CatalogVersion,
        observed_at: TimestampMillis,
        models: Vec<ModelCapability>,
    ) -> Self {
        Self {
            catalog_version,
            observed_at,
            models,
        }
    }

    pub fn snapshot(&self) -> ModelCatalogSnapshot {
        ModelCatalogSnapshot {
            catalog_version: self.catalog_version.clone(),
            observed_at: self.observed_at,
            models: self
                .models
                .iter()
                .map(|model| CatalogEntry {
                    identity: model.identity.clone(),
                    supported_efforts: model.supported_efforts.clone(),
                })
                .collect(),
        }
    }

    pub fn get(&self, identity: &RuntimeModelId) -> Option<&ModelCapability> {
        self.models.iter().find(|model| &model.identity == identity)
    }

    pub fn class_members(&self, class: CapabilityClass) -> impl Iterator<Item = &ModelCapability> {
        self.models
            .iter()
            .filter(move |model| model.capability_class == class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::{BackendId, ModelFamilyId, ProviderId, RuntimeSlug};

    fn identity(slug: &str) -> RuntimeModelId {
        RuntimeModelId {
            provider: ProviderId::new("local").expect("provider"),
            backend: BackendId::well_known(BackendId::FAKE_PROVIDER),
            model_family: ModelFamilyId::new("family").expect("family"),
            runtime_slug: RuntimeSlug::new(slug).expect("slug"),
            catalog_version: CatalogVersion::new("cat-1").expect("catalog"),
            observation_timestamp: TimestampMillis::from_millis(1),
        }
    }

    #[test]
    fn capability_catalog_preserves_snapshot_identities() {
        let snapshot = ModelCatalogSnapshot {
            catalog_version: CatalogVersion::new("cat-1").expect("catalog"),
            observed_at: TimestampMillis::from_millis(1),
            models: vec![CatalogEntry {
                identity: identity("alpha"),
                supported_efforts: vec![CanonicalEffort::Medium],
            }],
        };
        let catalog = CapabilityCatalog::from_snapshot(&snapshot);
        assert_eq!(catalog.models.len(), 1);
        assert_eq!(catalog.models[0].capability_class, CapabilityClass::Worker);
        assert_eq!(
            catalog
                .snapshot()
                .identities()
                .map(|id| id.runtime_slug.as_str().to_string())
                .collect::<Vec<_>>(),
            vec!["alpha"]
        );
    }

    #[test]
    fn tool_and_effort_queries_are_evidence_backed() {
        let mut capability = ModelCapability::from_entry(&CatalogEntry {
            identity: identity("alpha"),
            supported_efforts: vec![CanonicalEffort::Low, CanonicalEffort::Medium],
        });
        capability.tool_capabilities.insert("edit".to_string());
        assert!(capability.supports_effort(&CanonicalEffort::Medium));
        assert!(!capability.supports_effort(&CanonicalEffort::High));
        let mut required = BTreeSet::new();
        required.insert("edit".to_string());
        assert!(capability.has_tools(&required));
        required.insert("web".to_string());
        assert!(!capability.has_tools(&required));
    }
}
