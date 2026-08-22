//! Drift detection and time-decayed learning types (issue #170).
//!
//! Learned statistics key on the full runtime identity, including
//! [`CatalogVersion`]. A bare slug is not a legal key. This first slice lands
//! the type-level objects: exponential decay, catalog-version drift, and a
//! configured change-point window. Policy retirement cadence and reserve
//! recalibration remain later slices; [`super::drift`] keeps the existing
//! store.

use serde::{Deserialize, Serialize};

use super::action::{CanonicalEffort, RuntimeModelId};
use super::ids::{CatalogVersion, RuntimeSlug, TimestampMillis};

/// Statistics key: runtime identity including catalog version, never a slug.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VersionedModelKey {
    pub identity: RuntimeModelId,
    pub effort: CanonicalEffort,
}

impl VersionedModelKey {
    pub fn new(identity: RuntimeModelId, effort: CanonicalEffort) -> Self {
        Self { identity, effort }
    }

    pub fn runtime_slug(&self) -> &RuntimeSlug {
        &self.identity.runtime_slug
    }

    pub fn catalog_version(&self) -> &CatalogVersion {
        &self.identity.catalog_version
    }

    /// Same advertised slug, different catalog snapshot.
    pub fn same_slug_different_catalog(&self, other: &Self) -> bool {
        self.runtime_slug() == other.runtime_slug()
            && self.catalog_version() != other.catalog_version()
    }
}

/// Exponential half-life used to age observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExponentialDecay {
    pub half_life_ms: u64,
}

impl ExponentialDecay {
    pub fn new(half_life_ms: u64) -> Self {
        Self {
            half_life_ms: half_life_ms.max(1),
        }
    }

    /// Weight in milli-counts: `1000 * 1/2^(age / half_life)`.
    pub fn weight_milli(self, age_ms: u64) -> u32 {
        let mut weight = 1_000u32;
        let mut remaining = age_ms;
        while remaining >= self.half_life_ms {
            weight /= 2;
            remaining -= self.half_life_ms;
            if weight == 0 {
                return 0;
            }
        }
        weight
    }
}

/// Decayed Bernoulli sufficient statistics in milli-counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DecayedConfidence {
    pub weighted_successes_milli: u32,
    pub weighted_trials_milli: u32,
}

impl DecayedConfidence {
    pub fn absorb(&mut self, certified: bool, weight_milli: u32) {
        self.weighted_trials_milli = self.weighted_trials_milli.saturating_add(weight_milli);
        if certified {
            self.weighted_successes_milli =
                self.weighted_successes_milli.saturating_add(weight_milli);
        }
    }

    pub fn effective_sample_size_milli(&self) -> u32 {
        self.weighted_trials_milli
    }

    pub fn mean_bp(&self) -> u16 {
        if self.weighted_trials_milli == 0 {
            return 0;
        }
        ((u64::from(self.weighted_successes_milli) * 10_000)
            / u64::from(self.weighted_trials_milli)) as u16
    }

    /// Catalog-version change: old data must not permanently dominate.
    pub fn widen(&mut self) {
        self.weighted_successes_milli /= 4;
        self.weighted_trials_milli /= 4;
    }
}

/// Same slug, new catalog version. Reduces confidence from the previous key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogVersionChange {
    pub slug: RuntimeSlug,
    pub previous: CatalogVersion,
    pub next: CatalogVersion,
    pub at: TimestampMillis,
}

impl CatalogVersionChange {
    pub fn applies_to(&self, key: &VersionedModelKey) -> bool {
        key.runtime_slug() == &self.slug && key.catalog_version() == &self.previous
    }

    pub fn reduce_previous(&self, prior: DecayedConfidence) -> DecayedConfidence {
        let mut reduced = prior;
        reduced.widen();
        reduced
    }
}

/// Configured window for a mean-shift change-point on a binary stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangePointWindow {
    pub window: usize,
    pub drop_bp: u16,
}

impl ChangePointWindow {
    pub fn new(window: usize, drop_bp: u16) -> Self {
        Self {
            window: window.max(1),
            drop_bp,
        }
    }

    /// Returns the index of the last sample in the first window that drops.
    pub fn detect(&self, outcomes: &[bool]) -> Option<usize> {
        let span = self.window.saturating_mul(2);
        if outcomes.len() < span {
            return None;
        }
        for end in span..=outcomes.len() {
            let recent = &outcomes[end - self.window..end];
            let prior = &outcomes[end - span..end - self.window];
            let recent_bp = mean_bp(recent);
            let prior_bp = mean_bp(prior);
            if prior_bp.saturating_sub(recent_bp) >= self.drop_bp {
                return Some(end - 1);
            }
        }
        None
    }
}

fn mean_bp(outcomes: &[bool]) -> u16 {
    if outcomes.is_empty() {
        return 0;
    }
    let successes = outcomes.iter().filter(|outcome| **outcome).count();
    ((successes as u64 * 10_000) / outcomes.len() as u64) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::{BackendId, ModelFamilyId, ProviderId};

    fn identity(slug: &str, version: &str) -> RuntimeModelId {
        RuntimeModelId {
            provider: ProviderId::new("catalog").expect("provider"),
            backend: BackendId::well_known(BackendId::FAKE_PROVIDER),
            model_family: ModelFamilyId::new(slug).expect("family"),
            runtime_slug: RuntimeSlug::new(slug).expect("slug"),
            catalog_version: CatalogVersion::new(version).expect("cat"),
            observation_timestamp: TimestampMillis::from_millis(1),
        }
    }

    fn key(slug: &str, version: &str) -> VersionedModelKey {
        VersionedModelKey::new(identity(slug, version), CanonicalEffort::Medium)
    }

    #[test]
    fn statistics_keys_include_catalog_version_not_bare_slug() {
        let v1 = key("catalog-small", "v1");
        let v2 = key("catalog-small", "v2");
        assert_ne!(v1, v2);
        assert!(v1.same_slug_different_catalog(&v2));
        assert_eq!(v1.runtime_slug(), v2.runtime_slug());
        assert_ne!(v1.catalog_version(), v2.catalog_version());
    }

    #[test]
    fn catalog_version_change_widens_previous_confidence() {
        let mut prior = DecayedConfidence::default();
        for _ in 0..16 {
            prior.absorb(true, 1_000);
        }
        let before = prior.effective_sample_size_milli();
        let change = CatalogVersionChange {
            slug: RuntimeSlug::new("catalog-small").expect("slug"),
            previous: CatalogVersion::new("v1").expect("prev"),
            next: CatalogVersion::new("v2").expect("next"),
            at: TimestampMillis::from_millis(100),
        };
        assert!(change.applies_to(&key("catalog-small", "v1")));
        assert!(!change.applies_to(&key("catalog-small", "v2")));
        let after = change.reduce_previous(prior);
        assert!(after.effective_sample_size_milli() < before);
        assert_eq!(after.effective_sample_size_milli(), before / 4);
        assert!(after.mean_bp() <= prior.mean_bp());
    }

    #[test]
    fn exponential_decay_ages_older_observations() {
        let decay = ExponentialDecay::new(1_000);
        assert_eq!(decay.weight_milli(0), 1_000);
        assert_eq!(decay.weight_milli(1_000), 500);
        assert_eq!(decay.weight_milli(2_000), 250);
        let mut confidence = DecayedConfidence::default();
        confidence.absorb(true, decay.weight_milli(0));
        confidence.absorb(false, decay.weight_milli(3_000));
        assert!(
            confidence.mean_bp() > 5_000,
            "fresh success must outweigh a three-half-life failure: {}",
            confidence.mean_bp()
        );
    }

    #[test]
    fn changepoint_in_synthetic_outcomes_is_detected_inside_the_window() {
        let detector = ChangePointWindow::new(8, 4_000);
        let mut outcomes = vec![true; 12];
        outcomes.extend(std::iter::repeat_n(false, 12));
        let index = detector.detect(&outcomes).expect("change-point");
        assert!(
            index < outcomes.len(),
            "detector returned an out-of-range index"
        );
        assert!(
            index + 1 >= detector.window,
            "detection must fall inside the configured window length"
        );
        assert!(detector.detect(&[true; 10]).is_none());
    }
}
