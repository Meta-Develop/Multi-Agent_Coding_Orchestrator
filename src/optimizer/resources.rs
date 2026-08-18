//! Multi-dimensional resource vector (scaffold).
//!
//! Budget, reserve, and shadow-price behaviour is issue #162. Dimensions are
//! keyed so later provider adapters add pools without editing this type.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::error::OptimizerError;
use super::ids::{ResourceDimensionId, TimestampMillis};

/// Integer quantity in the dimension's native units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Quantity(i64);

impl Quantity {
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    pub const fn as_i64(self) -> i64 {
        self.0
    }

    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationKind {
    Measured,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceObservation {
    pub kind: ObservationKind,
    /// Confidence in basis points (10000 = 100%).
    pub confidence_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDimension {
    pub id: ResourceDimensionId,
    pub remaining: Quantity,
    pub reset_at: Option<TimestampMillis>,
    pub frontier_reserve: Quantity,
    pub emergency_margin: Quantity,
    pub uncertainty: Quantity,
    /// Shadow price in milliprice units. Soft objective only.
    pub shadow_price: i64,
    pub observation: ResourceObservation,
}

impl ResourceDimension {
    pub fn optional_budget(&self) -> Quantity {
        self.remaining
            .saturating_sub(self.frontier_reserve)
            .saturating_sub(self.emergency_margin)
    }
}

/// One field (key) per constrained pool. Never collapsed into a scalar dollar.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceVector {
    dimensions: BTreeMap<ResourceDimensionId, ResourceDimension>,
}

impl ResourceVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, dimension: ResourceDimension) {
        self.dimensions.insert(dimension.id.clone(), dimension);
    }

    pub fn get(&self, id: &ResourceDimensionId) -> Option<&ResourceDimension> {
        self.dimensions.get(id)
    }

    pub fn get_mut(&mut self, id: &ResourceDimensionId) -> Option<&mut ResourceDimension> {
        self.dimensions.get_mut(id)
    }

    pub fn dimensions(&self) -> impl Iterator<Item = &ResourceDimension> {
        self.dimensions.values()
    }

    pub fn is_empty(&self) -> bool {
        self.dimensions.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub observed_at: TimestampMillis,
    pub vector: ResourceVector,
}

/// Object-safe observer. #151 adapters implement this without editing core.
pub trait ResourceObserver {
    fn observe(&self) -> Result<ResourceSnapshot, OptimizerError>;
}
