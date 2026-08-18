//! Feature bags consumed by [`crate::optimizer::state::OptimizerState`].
//!
//! Issue #163 implements extractors that fill these bags. Keys are open
//! [`FeatureId`]s so new features do not require edits to optimizer core.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::ids::FeatureId;

/// Deterministic feature value. Fractional quantities use millionths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FeatureValue {
    Boolean(bool),
    Integer(i64),
    Text(String),
    Micro(i64),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureBag {
    values: BTreeMap<FeatureId, FeatureValue>,
}

impl FeatureBag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: FeatureId, value: FeatureValue) {
        self.values.insert(id, value);
    }

    pub fn get(&self, id: &FeatureId) -> Option<&FeatureValue> {
        self.values.get(id)
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FeatureId, &FeatureValue)> {
        self.values.iter()
    }
}

pub type TaskFeatures = FeatureBag;
pub type RepoFeatures = FeatureBag;
pub type TrajectoryFeatures = FeatureBag;

/// Extractor seam for issue #163. Implementors live outside this file.
pub trait FeatureExtractor {
    fn extract_task(&self) -> TaskFeatures;
    fn extract_repo(&self) -> RepoFeatures;
    fn extract_trajectory(&self) -> TrajectoryFeatures;
}
