//! Runtime model catalog trait.
//!
//! Adapters from #146 implement [`RuntimeModelCatalog`]. The optimizer core
//! depends only on this snapshot, never on a provider CLI.

use serde::{Deserialize, Serialize};

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
