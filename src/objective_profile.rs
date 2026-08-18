//! Versioned operator-tunable objective profiles for evaluation and selection.
//!
//! Pareto dominance stays preference-free. A profile names the weights that turn
//! a frontier into an auditable choice.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DEFAULT_OBJECTIVE_PROFILE_ID: &str = "maco-default-objective-v1";
pub const DEFAULT_OBJECTIVE_PROFILE_VERSION: u32 = 1;
pub const HELD_OUT_WEIGHT_PERCENT: u32 = 50;
pub const BREADTH_WEIGHT_PERCENT: u32 = 25;
pub const ANTI_SHORTCUT_WEIGHT_PERCENT: u32 = 25;

/// Named, versioned weights over quality components and non-quality axes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveProfile {
    pub id: String,
    pub version: u32,
    pub quality: QualityWeights,
    #[serde(default)]
    pub tradeoffs: TradeoffWeights,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualityWeights {
    pub held_out_percent: u32,
    pub breadth_percent: u32,
    pub anti_shortcut_percent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffWeights {
    #[serde(default = "default_cost_weight")]
    pub monetary_cost_percent: u32,
    #[serde(default)]
    pub quota_consumption_percent: u32,
    #[serde(default)]
    pub latency_percent: u32,
    #[serde(default)]
    pub retry_rework_percent: u32,
    #[serde(default)]
    pub human_review_percent: u32,
}

const fn default_cost_weight() -> u32 {
    100
}

impl Default for TradeoffWeights {
    fn default() -> Self {
        Self {
            monetary_cost_percent: 100,
            quota_consumption_percent: 0,
            latency_percent: 0,
            retry_rework_percent: 0,
            human_review_percent: 0,
        }
    }
}

/// Binding recorded beside an experiment so re-weighting cannot silently
/// invalidate past conclusions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveProfileBinding {
    pub id: String,
    pub version: u32,
    pub content_hash: String,
    pub quality: QualityWeights,
    pub tradeoffs: TradeoffWeights,
}

impl Default for ObjectiveProfile {
    fn default() -> Self {
        default_objective_profile()
    }
}

pub fn default_objective_profile() -> ObjectiveProfile {
    ObjectiveProfile {
        id: DEFAULT_OBJECTIVE_PROFILE_ID.to_string(),
        version: DEFAULT_OBJECTIVE_PROFILE_VERSION,
        quality: QualityWeights {
            held_out_percent: HELD_OUT_WEIGHT_PERCENT,
            breadth_percent: BREADTH_WEIGHT_PERCENT,
            anti_shortcut_percent: ANTI_SHORTCUT_WEIGHT_PERCENT,
        },
        tradeoffs: TradeoffWeights::default(),
    }
}

impl ObjectiveProfile {
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            bail!("objective profile id cannot be empty");
        }
        if self.version == 0 {
            bail!("objective profile version must be greater than zero");
        }
        let quality_total = self
            .quality
            .held_out_percent
            .checked_add(self.quality.breadth_percent)
            .and_then(|total| total.checked_add(self.quality.anti_shortcut_percent))
            .context("objective quality weights overflowed")?;
        if quality_total != 100 {
            bail!("objective quality weights must sum to 100, got {quality_total}");
        }
        let tradeoff_total = self
            .tradeoffs
            .monetary_cost_percent
            .checked_add(self.tradeoffs.quota_consumption_percent)
            .and_then(|total| total.checked_add(self.tradeoffs.latency_percent))
            .and_then(|total| total.checked_add(self.tradeoffs.retry_rework_percent))
            .and_then(|total| total.checked_add(self.tradeoffs.human_review_percent))
            .context("objective tradeoff weights overflowed")?;
        if tradeoff_total != 100 {
            bail!("objective tradeoff weights must sum to 100, got {tradeoff_total}");
        }
        Ok(())
    }

    pub fn content_hash(&self) -> Result<String> {
        let payload = serde_json::to_vec(self).context("failed to serialize objective profile")?;
        Ok(crate::artifacts::state_auth::sha256_hex(&payload))
    }

    pub fn binding(&self) -> Result<ObjectiveProfileBinding> {
        self.validate()?;
        Ok(ObjectiveProfileBinding {
            id: self.id.clone(),
            version: self.version,
            content_hash: self.content_hash()?,
            quality: self.quality.clone(),
            tradeoffs: self.tradeoffs.clone(),
        })
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let profile: Self =
            serde_json::from_slice(bytes).context("objective profile is not valid JSON")?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn overall_quality_basis_points(
        &self,
        held_out_basis_points: u32,
        breadth_basis_points: u32,
        anti_shortcut_basis_points: u32,
    ) -> u32 {
        let weighted = u64::from(held_out_basis_points)
            * u64::from(self.quality.held_out_percent)
            + u64::from(breadth_basis_points) * u64::from(self.quality.breadth_percent)
            + u64::from(anti_shortcut_basis_points) * u64::from(self.quality.anti_shortcut_percent);
        (weighted / 100) as u32
    }
}

/// Preference-bearing score used only after Pareto evidence is computed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ObjectiveSelection {
    pub profile_id: String,
    pub profile_hash: String,
    pub selected_profile_id: String,
    pub selected_score: f64,
    pub runner_up_profile_id: Option<String>,
    pub runner_up_score: Option<f64>,
    pub scores: BTreeMap<String, f64>,
}

/// Choose one frontier point using the profile. Empty frontiers yield `None`.
pub fn select_from_frontier(
    profile: &ObjectiveProfile,
    points: &[(String, FrontierAxes)],
) -> Result<Option<ObjectiveSelection>> {
    profile.validate()?;
    if points.is_empty() {
        return Ok(None);
    }
    let mut scores = BTreeMap::new();
    let mut ranked = Vec::new();
    for (id, axes) in points {
        let score = profile.score_axes(axes);
        scores.insert(id.clone(), score);
        ranked.push((id.clone(), score));
    }
    ranked.sort_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    let selected = ranked.first().cloned().expect("non-empty frontier");
    let runner_up = ranked.get(1).cloned();
    Ok(Some(ObjectiveSelection {
        profile_id: profile.id.clone(),
        profile_hash: profile.content_hash()?,
        selected_profile_id: selected.0,
        selected_score: selected.1,
        runner_up_profile_id: runner_up.as_ref().map(|(id, _)| id.clone()),
        runner_up_score: runner_up.map(|(_, score)| score),
        scores,
    }))
}

/// Normalized axes used by the selection policy. Lower is better.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FrontierAxes {
    pub monetary_cost: f64,
    pub quota_consumption: f64,
    pub latency: f64,
    pub retry_rework: f64,
    pub human_review: f64,
}

impl ObjectiveProfile {
    fn score_axes(&self, axes: &FrontierAxes) -> f64 {
        (axes.monetary_cost * f64::from(self.tradeoffs.monetary_cost_percent)
            + axes.quota_consumption * f64::from(self.tradeoffs.quota_consumption_percent)
            + axes.latency * f64::from(self.tradeoffs.latency_percent)
            + axes.retry_rework * f64::from(self.tradeoffs.retry_rework_percent)
            + axes.human_review * f64::from(self.tradeoffs.human_review_percent))
            / 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_reproduces_50_25_25_and_hashes_stably() {
        let profile = default_objective_profile();
        profile.validate().expect("default");
        assert_eq!(
            profile.overall_quality_basis_points(10_000, 0, 0),
            5_000
        );
        assert_eq!(
            profile.overall_quality_basis_points(0, 10_000, 0),
            2_500
        );
        assert_eq!(
            profile.overall_quality_basis_points(0, 0, 10_000),
            2_500
        );
        let first = profile.content_hash().expect("hash");
        let second = profile.content_hash().expect("hash");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn selection_records_profile_hash_and_runner_up() {
        let profile = default_objective_profile();
        let selection = select_from_frontier(
            &profile,
            &[
                (
                    "cheap".to_string(),
                    FrontierAxes {
                        monetary_cost: 1.0,
                        quota_consumption: 0.0,
                        latency: 0.0,
                        retry_rework: 0.0,
                        human_review: 0.0,
                    },
                ),
                (
                    "expensive".to_string(),
                    FrontierAxes {
                        monetary_cost: 9.0,
                        quota_consumption: 0.0,
                        latency: 0.0,
                        retry_rework: 0.0,
                        human_review: 0.0,
                    },
                ),
            ],
        )
        .expect("select")
        .expect("non-empty");
        assert_eq!(selection.selected_profile_id, "cheap");
        assert_eq!(selection.runner_up_profile_id.as_deref(), Some("expensive"));
        assert_eq!(selection.profile_id, DEFAULT_OBJECTIVE_PROFILE_ID);
        assert_eq!(
            selection.profile_hash,
            profile.content_hash().expect("hash")
        );
    }

    #[test]
    fn invalid_weights_fail_closed() {
        let mut profile = default_objective_profile();
        profile.quality.held_out_percent = 40;
        assert!(profile.validate().unwrap_err().to_string().contains("100"));
    }
}
