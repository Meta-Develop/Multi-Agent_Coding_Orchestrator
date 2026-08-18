//! Predictive outcome distributions. Implemented by issue #167.
//!
//! Initial models are interpretable and calibrated, not point estimates.
//! Hierarchical partial pooling lets a new runtime inherit broad priors with
//! wide uncertainty. Public benchmark rankings are weak priors only.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::action::{AgentRole, ModelAction};
use super::error::OptimizerError;
use super::explanation::role_label;
use super::features::{FeatureBag, FeatureValue};
use super::ids::{FeatureId, PolicyId, ResourceDimensionId};
use super::policy::{PolicyGraph, PolicyNode};
use super::resources::{ConsumptionForecast, Quantity};
use super::state::OptimizerState;

/// Documented feature keys the router reads. Extractors (#163) fill them.
pub mod feature_keys {
    pub const TASK_CLASS: &str = "optimizer.task.class";
    pub const LANGUAGE: &str = "optimizer.task.language";
    pub const REPO_ID: &str = "optimizer.repo.id";
    pub const QUALITY_DELTA_Q_BP: &str = "optimizer.quality.delta_q_bp";
    pub const DETERMINISTIC_GUARANTEE: &str = "optimizer.quality.deterministic_guarantee";
    pub const FORMAL_PROOF_REQUIRED: &str = "optimizer.quality.formal_proof_required";
    pub const FORMAL_TOOL_AVAILABLE: &str = "optimizer.capability.formal_tool_available";
    pub const VERIFIER_AVAILABLE: &str = "optimizer.capability.verifier_available";
    pub const MODEL_AVAILABLE: &str = "optimizer.capability.model_available";
    pub const BACKEND_OK: &str = "optimizer.capability.backend_ok";
    pub const CONTAINMENT_OK: &str = "optimizer.security.containment_ok";
    pub const CURRENT_POLICY: &str = "optimizer.trajectory.current_policy";
    pub const TEST_FAILURES_DECREASING: &str = "optimizer.trajectory.test_failures_decreasing";
    pub const COMPILER_FAILURES_DECREASING: &str =
        "optimizer.trajectory.compiler_failures_decreasing";
    pub const COVERAGE_INCREASING: &str = "optimizer.trajectory.requirement_coverage_increasing";
    pub const DIFF_CHURN_BOUNDED: &str = "optimizer.trajectory.diff_churn_bounded";
    pub const REPEATED_FAILURE: &str = "optimizer.trajectory.repeated_failure_signature";
    pub const PROGRESS_BELOW_THRESHOLD: &str = "optimizer.trajectory.progress_below_threshold";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OutcomeDistributionDetails {
    pub certified_by_deadline_lcb_bp: u16,
    pub deadline_miss_probability_bp: u16,
    pub tail_latency_p95_micros: i64,
    pub cvar95_latency_micros: i64,
    pub expected_human_micros: i64,
    pub uncertainty_micros: i64,
    pub human_intervention_bp: u16,
    pub first_pass_success_bp: u16,
    pub failure_mode_bp: BTreeMap<String, u16>,
    pub consumption: BTreeMap<ResourceDimensionId, ConsumptionForecast>,
    pub time_to_cert_samples_micros: Vec<i64>,
    pub monetary_cost_samples_micros: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutcomeDistribution {
    pub policy_id: PolicyId,
    /// Millionths of a unit; deterministic stand-in for a real density.
    pub expected_cost_micros: i64,
    pub expected_latency_micros: i64,
    pub quality_lower_confidence_bp: u16,
    pub certified_probability_bp: u16,
    #[serde(default)]
    pub details: OutcomeDistributionDetails,
}

impl PolicyOutcomeDistribution {
    pub fn new(
        policy_id: PolicyId,
        expected_cost_micros: i64,
        expected_latency_micros: i64,
        quality_lower_confidence_bp: u16,
        certified_probability_bp: u16,
    ) -> Self {
        Self {
            policy_id,
            expected_cost_micros,
            expected_latency_micros,
            quality_lower_confidence_bp,
            certified_probability_bp,
            details: OutcomeDistributionDetails::default(),
        }
    }

    pub fn with_details(mut self, details: OutcomeDistributionDetails) -> Self {
        self.details = details;
        if self.details.certified_by_deadline_lcb_bp == 0 {
            self.details.certified_by_deadline_lcb_bp = self.quality_lower_confidence_bp;
        }
        if self.details.cvar95_latency_micros == 0 {
            self.details.cvar95_latency_micros = self.expected_latency_micros;
        }
        if self.details.tail_latency_p95_micros == 0 {
            self.details.tail_latency_p95_micros = self.expected_latency_micros;
        }
        self
    }

    pub fn mean_consumption(&self, id: &ResourceDimensionId) -> i64 {
        self.details
            .consumption
            .get(id)
            .map(mean_quantity)
            .unwrap_or(0)
    }
}

pub trait PolicyPredictor {
    fn predict(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
    ) -> Result<PolicyOutcomeDistribution, OptimizerError>;
}

/// Scripted distributions for deterministic router tests and replay fixtures.
#[derive(Debug, Clone, Default)]
pub struct ScriptedPredictor {
    outcomes: BTreeMap<PolicyId, PolicyOutcomeDistribution>,
}

impl ScriptedPredictor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, distribution: PolicyOutcomeDistribution) {
        self.outcomes
            .insert(distribution.policy_id.clone(), distribution);
    }
}

impl PolicyPredictor for ScriptedPredictor {
    fn predict(
        &self,
        _state: &OptimizerState,
        policy: &PolicyGraph,
    ) -> Result<PolicyOutcomeDistribution, OptimizerError> {
        self.outcomes
            .get(&policy.policy_id)
            .cloned()
            .ok_or_else(|| {
                OptimizerError::invalid(format!(
                    "no scripted prediction for policy {}",
                    policy.policy_id
                ))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HierarchyKey(Vec<(String, String)>);

impl HierarchyKey {
    pub fn global() -> Self {
        Self(vec![("global".to_string(), "all".to_string())])
    }

    pub fn push(&mut self, dimension: impl Into<String>, value: impl Into<String>) {
        self.0.push((dimension.into(), value.into()));
    }

    pub fn prefixes(&self) -> Vec<HierarchyKey> {
        (1..=self.0.len())
            .map(|end| HierarchyKey(self.0[..end].to_vec()))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetaBinomialCell {
    pub alpha_milli: u64,
    pub beta_milli: u64,
    pub observations: u32,
}

impl BetaBinomialCell {
    pub fn jeffreys() -> Self {
        Self {
            alpha_milli: 500,
            beta_milli: 500,
            observations: 0,
        }
    }

    pub fn weak_prior(success_bp: u16, strength_milli: u64) -> Self {
        let success_bp = u64::from(success_bp.min(10_000));
        Self {
            alpha_milli: strength_milli.saturating_mul(success_bp) / 10_000,
            beta_milli: strength_milli.saturating_mul(10_000 - success_bp) / 10_000,
            observations: 0,
        }
    }

    pub fn observe(&mut self, success: bool) {
        if success {
            self.alpha_milli = self.alpha_milli.saturating_add(1_000);
        } else {
            self.beta_milli = self.beta_milli.saturating_add(1_000);
        }
        self.observations = self.observations.saturating_add(1);
    }

    pub fn mean_bp(&self) -> u16 {
        let total = self.alpha_milli.saturating_add(self.beta_milli);
        if total == 0 {
            return 0;
        }
        ((self.alpha_milli.saturating_mul(10_000)) / total).min(10_000) as u16
    }

    pub fn observation_weight(&self, prior_strength: u32) -> u32 {
        let n = self.observations;
        if n + prior_strength == 0 {
            return 0;
        }
        (n.saturating_mul(1_000)) / (n.saturating_add(prior_strength))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleCell {
    pub samples: Vec<i64>,
    pub observations: u32,
}

impl SampleCell {
    pub fn observe(&mut self, sample: i64) {
        self.samples.push(sample);
        self.observations = self.observations.saturating_add(1);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultinomialCell {
    pub counts: BTreeMap<String, u32>,
    pub observations: u32,
}

impl MultinomialCell {
    pub fn observe(&mut self, mode: impl Into<String>) {
        *self.counts.entry(mode.into()).or_insert(0) += 1;
        self.observations = self.observations.saturating_add(1);
    }

    pub fn probabilities_bp(&self) -> BTreeMap<String, u16> {
        let total = self
            .counts
            .values()
            .try_fold(0u64, |acc, count| acc.checked_add(u64::from(*count)))
            .unwrap_or(0)
            .max(1);
        self.counts
            .iter()
            .map(|(mode, count)| {
                let bp = (u64::from(*count).saturating_mul(10_000) / total).min(10_000) as u16;
                (mode.clone(), bp)
            })
            .collect()
    }
}

/// Hierarchical, integer-arithmetic predictor.
///
/// Certification: pooled Beta-Binomial (logistic stand-in).
/// First-pass success: Beta-Binomial per (task class, model-effort).
/// Time and tokens: empirical / Gamma-like sample cells.
/// Failure mode: multinomial.
/// Human intervention: Bernoulli (Beta-Binomial).
/// Quota: empirical quantiles per resource dimension.
#[derive(Debug, Clone)]
pub struct HierarchicalPolicyPredictor {
    certification: BTreeMap<HierarchyKey, BetaBinomialCell>,
    first_pass: BTreeMap<HierarchyKey, BetaBinomialCell>,
    human: BTreeMap<HierarchyKey, BetaBinomialCell>,
    latency: BTreeMap<HierarchyKey, SampleCell>,
    cost: BTreeMap<HierarchyKey, SampleCell>,
    failure: BTreeMap<HierarchyKey, MultinomialCell>,
    consumption: BTreeMap<(HierarchyKey, ResourceDimensionId), SampleCell>,
    /// Wilson z in hundredths (196 = 1.96 ≈ 95%).
    lcb_z_hundredths: u32,
    pooling_strength: u32,
}

impl Default for HierarchicalPolicyPredictor {
    fn default() -> Self {
        let mut predictor = Self {
            certification: BTreeMap::new(),
            first_pass: BTreeMap::new(),
            human: BTreeMap::new(),
            latency: BTreeMap::new(),
            cost: BTreeMap::new(),
            failure: BTreeMap::new(),
            consumption: BTreeMap::new(),
            lcb_z_hundredths: 196,
            pooling_strength: 4,
        };
        predictor
            .certification
            .insert(HierarchyKey::global(), BetaBinomialCell::jeffreys());
        predictor
            .first_pass
            .insert(HierarchyKey::global(), BetaBinomialCell::jeffreys());
        predictor.human.insert(
            HierarchyKey::global(),
            BetaBinomialCell::weak_prior(500, 1_000),
        );
        predictor.latency.insert(
            HierarchyKey::global(),
            SampleCell {
                samples: wide_latency_prior(),
                observations: 0,
            },
        );
        predictor.cost.insert(
            HierarchyKey::global(),
            SampleCell {
                samples: wide_cost_prior(),
                observations: 0,
            },
        );
        predictor
    }
}

impl HierarchicalPolicyPredictor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Public benchmark rankings are weak priors, never production evidence.
    pub fn insert_weak_benchmark_prior(&mut self, key: HierarchyKey, success_bp: u16) {
        self.certification
            .insert(key, BetaBinomialCell::weak_prior(success_bp, 400));
    }

    pub fn observe_certification(&mut self, key: HierarchyKey, certified: bool) {
        self.certification
            .entry(key)
            .or_insert_with(BetaBinomialCell::jeffreys)
            .observe(certified);
    }

    pub fn observe_latency(&mut self, key: HierarchyKey, micros: i64) {
        self.latency.entry(key).or_default().observe(micros);
    }

    pub fn observe_cost(&mut self, key: HierarchyKey, micros: i64) {
        self.cost.entry(key).or_default().observe(micros);
    }

    pub fn observe_failure_mode(&mut self, key: HierarchyKey, mode: impl Into<String>) {
        self.failure.entry(key).or_default().observe(mode);
    }

    pub fn observe_human(&mut self, key: HierarchyKey, needed: bool) {
        self.human
            .entry(key)
            .or_insert_with(|| BetaBinomialCell::weak_prior(500, 1_000))
            .observe(needed);
    }

    pub fn observe_consumption(
        &mut self,
        key: HierarchyKey,
        dimension: ResourceDimensionId,
        amount: i64,
    ) {
        self.consumption
            .entry((key, dimension))
            .or_default()
            .observe(amount);
    }

    pub fn hierarchy_for(state: &OptimizerState, policy: &PolicyGraph) -> HierarchyKey {
        let mut key = HierarchyKey::global();
        if let Some(action) = primary_action(policy) {
            key.push("provider", action.provider_id.to_string());
            key.push("backend", action.backend_id.to_string());
            key.push(
                "model_family",
                action.runtime_model.model_family.to_string(),
            );
            key.push(
                "runtime",
                format!(
                    "{}@{}",
                    action.runtime_model.runtime_slug, action.runtime_model.catalog_version
                ),
            );
            key.push("effort", action.effort.as_label());
            key.push("role", role_label(&action.role));
        }
        if let Some(class) = feature_text(&state.task_features, feature_keys::TASK_CLASS) {
            key.push("task_class", class);
        }
        if let Some(language) = feature_text(&state.task_features, feature_keys::LANGUAGE) {
            key.push("language", language);
        }
        if let Some(repo) = feature_text(&state.repo_features, feature_keys::REPO_ID) {
            key.push("repository", repo);
        }
        key.push("policy_template", policy.policy_id.to_string());
        key
    }

    fn pooled_beta(
        &self,
        cells: &BTreeMap<HierarchyKey, BetaBinomialCell>,
        key: &HierarchyKey,
    ) -> BetaBinomialCell {
        let mut pooled = BetaBinomialCell::jeffreys();
        let mut remaining = 1_000u32;
        for prefix in key.prefixes().into_iter().rev() {
            let Some(cell) = cells.get(&prefix) else {
                continue;
            };
            let weight = cell
                .observation_weight(self.pooling_strength)
                .min(remaining);
            if weight == 0 && prefix.0.len() > 1 {
                continue;
            }
            let used = if prefix.0.len() == 1 {
                remaining
            } else {
                weight.max(1).min(remaining)
            };
            pooled.alpha_milli = pooled
                .alpha_milli
                .saturating_add(cell.alpha_milli.saturating_mul(u64::from(used)) / 1_000);
            pooled.beta_milli = pooled
                .beta_milli
                .saturating_add(cell.beta_milli.saturating_mul(u64::from(used)) / 1_000);
            pooled.observations = pooled.observations.saturating_add(cell.observations);
            remaining = remaining.saturating_sub(used);
            if remaining == 0 {
                break;
            }
        }
        pooled
    }

    fn pooled_samples(
        &self,
        cells: &BTreeMap<HierarchyKey, SampleCell>,
        key: &HierarchyKey,
    ) -> Vec<i64> {
        let mut samples = Vec::new();
        for prefix in key.prefixes().into_iter().rev() {
            if let Some(cell) = cells.get(&prefix) {
                if !cell.samples.is_empty() {
                    samples.extend(cell.samples.iter().copied());
                    if cell.observations > 0 {
                        break;
                    }
                }
            }
        }
        if samples.is_empty() {
            samples = wide_latency_prior();
        }
        samples
    }
}

impl PolicyPredictor for HierarchicalPolicyPredictor {
    fn predict(
        &self,
        state: &OptimizerState,
        policy: &PolicyGraph,
    ) -> Result<PolicyOutcomeDistribution, OptimizerError> {
        policy.validate()?;
        let key = Self::hierarchy_for(state, policy);
        let cert = self.pooled_beta(&self.certification, &key);
        let first_pass = self.pooled_beta(&self.first_pass, &key);
        let human = self.pooled_beta(&self.human, &key);
        let time_samples = self.pooled_samples(&self.latency, &key);
        let cost_samples = self.pooled_samples(&self.cost, &key);

        let remaining_deadline_micros = remaining_deadline_micros(state);
        let miss_bp = deadline_miss_bp(&time_samples, remaining_deadline_micros);
        let cert_mean = cert.mean_bp();
        let cert_and_on_time_successes = cert
            .alpha_milli
            .saturating_mul(u64::from(10_000u16.saturating_sub(miss_bp)))
            / 10_000;
        let lcb = wilson_lcb_bp(
            cert_and_on_time_successes / 1_000,
            cert.alpha_milli.saturating_add(cert.beta_milli) / 1_000,
            self.lcb_z_hundredths,
        );

        let mut consumption = BTreeMap::new();
        if let Some(action) = primary_action(policy) {
            let dimension = dimension_for_backend(&action.backend_id.to_string());
            let mut samples = Vec::new();
            for prefix in key.prefixes().into_iter().rev() {
                if let Some(cell) = self.consumption.get(&(prefix, dimension.clone())) {
                    samples.extend(cell.samples.iter().copied());
                    if cell.observations > 0 {
                        break;
                    }
                }
            }
            if samples.is_empty() {
                samples = vec![1, 2, 3, 4, 6, 8, 12];
            }
            consumption.insert(
                dimension,
                ConsumptionForecast {
                    samples: samples.into_iter().map(Quantity::new).collect(),
                },
            );
        }

        let mut failure_modes = self
            .failure
            .get(&key)
            .cloned()
            .or_else(|| {
                key.prefixes()
                    .into_iter()
                    .rev()
                    .find_map(|prefix| self.failure.get(&prefix).cloned())
            })
            .unwrap_or_default()
            .probabilities_bp();
        if failure_modes.is_empty() {
            failure_modes.insert("unknown".to_string(), 10_000u16.saturating_sub(cert_mean));
            failure_modes.insert("certified".to_string(), cert_mean);
        }

        let expected_latency = mean_i64(&time_samples);
        let expected_cost = mean_i64(&cost_samples);
        let details = OutcomeDistributionDetails {
            certified_by_deadline_lcb_bp: lcb,
            deadline_miss_probability_bp: miss_bp,
            tail_latency_p95_micros: quantile_i64(&time_samples, 9_500),
            cvar95_latency_micros: cvar_i64(&time_samples, 9_500),
            expected_human_micros: i64::from(human.mean_bp()).saturating_mul(60_000_000) / 10_000,
            uncertainty_micros: stddev_i64(&time_samples).saturating_add(1),
            human_intervention_bp: human.mean_bp(),
            first_pass_success_bp: first_pass.mean_bp(),
            failure_mode_bp: failure_modes,
            consumption,
            time_to_cert_samples_micros: time_samples,
            monetary_cost_samples_micros: cost_samples,
        };

        Ok(PolicyOutcomeDistribution {
            policy_id: policy.policy_id.clone(),
            expected_cost_micros: expected_cost,
            expected_latency_micros: expected_latency,
            quality_lower_confidence_bp: lcb,
            certified_probability_bp: cert_mean,
            details,
        })
    }
}

pub(crate) fn primary_action(policy: &PolicyGraph) -> Option<&ModelAction> {
    match policy.nodes.get(&policy.start_node) {
        Some(
            PolicyNode::Probe(action)
            | PolicyNode::Plan(action)
            | PolicyNode::Execute(action)
            | PolicyNode::Repair(action)
            | PolicyNode::Audit(action),
        ) => Some(action),
        _ => policy.nodes.values().find_map(|node| match node {
            PolicyNode::Probe(action)
            | PolicyNode::Plan(action)
            | PolicyNode::Execute(action)
            | PolicyNode::Repair(action)
            | PolicyNode::Audit(action) => Some(action),
            PolicyNode::Certify(_) | PolicyNode::Stop => None,
        }),
    }
}

pub(crate) fn feature_bool(bag: &FeatureBag, key: &str) -> Option<bool> {
    let id = FeatureId::new(key).ok()?;
    match bag.get(&id) {
        Some(FeatureValue::Boolean(value)) => Some(*value),
        _ => None,
    }
}

pub(crate) fn feature_int(bag: &FeatureBag, key: &str) -> Option<i64> {
    let id = FeatureId::new(key).ok()?;
    match bag.get(&id) {
        Some(FeatureValue::Integer(value)) => Some(*value),
        Some(FeatureValue::Micro(value)) => Some(*value),
        _ => None,
    }
}

pub(crate) fn feature_text(bag: &FeatureBag, key: &str) -> Option<String> {
    let id = FeatureId::new(key).ok()?;
    match bag.get(&id) {
        Some(FeatureValue::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn insert_bool(bag: &mut FeatureBag, key: &str, value: bool) {
    if let Ok(id) = FeatureId::new(key) {
        bag.insert(id, FeatureValue::Boolean(value));
    }
}

#[cfg(test)]
pub(crate) fn insert_int(bag: &mut FeatureBag, key: &str, value: i64) {
    if let Ok(id) = FeatureId::new(key) {
        bag.insert(id, FeatureValue::Integer(value));
    }
}

pub(crate) fn insert_text(bag: &mut FeatureBag, key: &str, value: impl Into<String>) {
    if let Ok(id) = FeatureId::new(key) {
        bag.insert(id, FeatureValue::Text(value.into()));
    }
}

fn remaining_deadline_micros(state: &OptimizerState) -> Option<i64> {
    let deadline = state.horizon.deadline?;
    let remaining_ms = deadline
        .as_millis()
        .saturating_sub(state.horizon.now.as_millis());
    Some(i64::try_from(remaining_ms.saturating_mul(1_000)).unwrap_or(i64::MAX))
}

fn deadline_miss_bp(samples: &[i64], remaining: Option<i64>) -> u16 {
    let Some(limit) = remaining else {
        return 0;
    };
    if samples.is_empty() {
        return 10_000;
    }
    let misses = samples.iter().filter(|sample| **sample > limit).count();
    ((misses as u64).saturating_mul(10_000) / samples.len() as u64).min(10_000) as u16
}

fn wide_latency_prior() -> Vec<i64> {
    vec![
        1_000_000,
        5_000_000,
        15_000_000,
        30_000_000,
        60_000_000,
        180_000_000,
        600_000_000,
        1_800_000_000,
        7_200_000_000,
        14_400_000_000,
    ]
}

fn wide_cost_prior() -> Vec<i64> {
    vec![
        50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000,
    ]
}

pub(crate) fn mean_i64(samples: &[i64]) -> i64 {
    if samples.is_empty() {
        return 0;
    }
    let sum = samples
        .iter()
        .fold(0i128, |acc, sample| acc + i128::from(*sample));
    i64::try_from(sum / i128::from(samples.len() as i64)).unwrap_or(i64::MAX)
}

fn mean_quantity(forecast: &ConsumptionForecast) -> i64 {
    if forecast.samples.is_empty() {
        return 0;
    }
    let sum = forecast
        .samples
        .iter()
        .fold(0i128, |acc, sample| acc + i128::from(sample.as_i64()));
    i64::try_from(sum / i128::from(forecast.samples.len() as i64)).unwrap_or(i64::MAX)
}

pub(crate) fn quantile_i64(samples: &[i64], quantile_bp: u16) -> i64 {
    if samples.is_empty() {
        return 0;
    }
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let rank = u64::from(quantile_bp)
        .saturating_mul(ordered.len() as u64)
        .div_ceil(10_000);
    let index = rank.saturating_sub(1).min(ordered.len() as u64 - 1) as usize;
    ordered[index]
}

pub(crate) fn cvar_i64(samples: &[i64], alpha_bp: u16) -> i64 {
    if samples.is_empty() {
        return 0;
    }
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let start = (u64::from(alpha_bp).saturating_mul(ordered.len() as u64) / 10_000) as usize;
    let tail = &ordered[start.min(ordered.len() - 1)..];
    mean_i64(tail)
}

fn stddev_i64(samples: &[i64]) -> i64 {
    if samples.len() < 2 {
        return 0;
    }
    let mean = mean_i64(samples);
    let var = samples.iter().fold(0i128, |acc, sample| {
        let delta = i128::from(*sample) - i128::from(mean);
        acc.saturating_add(delta.saturating_mul(delta))
    }) / i128::from((samples.len() - 1) as i64);
    isqrt(var)
}

fn isqrt(value: i128) -> i64 {
    if value <= 0 {
        return 0;
    }
    let mut x = value;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + value / x) / 2;
    }
    i64::try_from(x).unwrap_or(i64::MAX)
}

/// Wilson score lower confidence bound in basis points.
pub(crate) fn wilson_lcb_bp(successes: u64, n: u64, z_hundredths: u32) -> u16 {
    if n == 0 {
        return 0;
    }
    let z2 = i128::from(z_hundredths).saturating_mul(i128::from(z_hundredths));
    let n = i128::from(n);
    let successes = i128::from(successes.min(n as u64));
    let unit = 100_000_000i128;
    let p = successes * unit / n;
    let z2u = z2 * unit / 10_000;
    let center = p + z2u / (2 * n);
    let pq = p * (unit - p) / unit;
    let inner = pq * unit / n + z2u * unit / (4 * n * n);
    let margin = isqrt_i128(inner) * i128::from(z_hundredths) / 100;
    let denom = unit + z2u / n;
    let lcb = (center.saturating_sub(margin)) * unit / denom;
    let bp = (lcb * 10_000 / unit).clamp(0, 10_000);
    bp as u16
}

fn isqrt_i128(value: i128) -> i128 {
    if value <= 0 {
        return 0;
    }
    let mut x = value;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + value / x) / 2;
    }
    x
}

fn dimension_for_backend(backend: &str) -> ResourceDimensionId {
    match backend {
        id if id == super::ids::BackendId::CODEX_CLI
            || id == super::ids::BackendId::CODEX_APP_SERVER =>
        {
            ResourceDimensionId::well_known(ResourceDimensionId::CODEX_CREDITS)
        }
        id if id == super::ids::BackendId::GROK_BUILD_CLI
            || id == super::ids::BackendId::XAI_API =>
        {
            ResourceDimensionId::well_known(ResourceDimensionId::GROK_BASIS_POINTS)
        }
        id if id == super::ids::BackendId::CURSOR_AGENT => {
            ResourceDimensionId::well_known(ResourceDimensionId::CURSOR_USAGE_UNITS)
        }
        id if id == super::ids::BackendId::LOCAL_MODEL => {
            ResourceDimensionId::well_known(ResourceDimensionId::LOCAL_COMPUTE_SECONDS)
        }
        _ => ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
    }
}

/// Roles whose consumption is mandatory frontier work, not optional worker spend.
pub(crate) fn is_frontier_role(role: &AgentRole) -> bool {
    matches!(
        role,
        AgentRole::Planner
            | AgentRole::Supervisor
            | AgentRole::ChildOrchestrator
            | AgentRole::Auditor
            | AgentRole::Certifier
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        CanonicalEffort, ExecutionBudget, HedgeTopology, PlannerTopology, RestartMode,
        ReviewTopology, TopologySpec, WorkerTopology,
    };
    use crate::optimizer::ids::{
        BackendId, CatalogVersion, ModelFamilyId, PolicyNodeId, ProviderId, RuntimeSlug,
        TimestampMillis, VerifierProfileId,
    };
    use crate::optimizer::state::DecisionHorizon;

    fn topology() -> TopologySpec {
        TopologySpec {
            planner: PlannerTopology::Single,
            workers: WorkerTopology::One,
            hedge: HedgeTopology::None,
            review: ReviewTopology::Independent,
            restart: RestartMode::Continuation,
        }
    }

    fn action(family: &str, slug: &str, effort: CanonicalEffort) -> ModelAction {
        ModelAction {
            backend_id: BackendId::well_known(BackendId::FAKE_PROVIDER),
            provider_id: ProviderId::new("local").expect("provider"),
            runtime_model: crate::optimizer::action::RuntimeModelId {
                provider: ProviderId::new("local").expect("provider"),
                backend: BackendId::well_known(BackendId::FAKE_PROVIDER),
                model_family: ModelFamilyId::new(family).expect("family"),
                runtime_slug: RuntimeSlug::new(slug).expect("slug"),
                catalog_version: CatalogVersion::new("v1").expect("cat"),
                observation_timestamp: TimestampMillis::from_millis(1),
            },
            requested_slug: RuntimeSlug::new(slug).expect("slug"),
            effort,
            role: AgentRole::Worker,
            max_turns: ExecutionBudget::default().max_turns,
            timeout_seconds: 60,
            tool_budget: None,
            output_token_budget: None,
            concurrency: 1,
            verifier_profile: VerifierProfileId::new("default").expect("profile"),
        }
    }

    fn graph(id: &str, family: &str, slug: &str, effort: CanonicalEffort) -> PolicyGraph {
        let start = PolicyNodeId::new("start").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new(id).expect("policy"),
            1,
            start.clone(),
            topology(),
        );
        graph
            .insert_node(start, PolicyNode::Execute(action(family, slug, effort)))
            .expect("node");
        graph
    }

    fn state() -> OptimizerState {
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1_000),
            deadline: Some(TimestampMillis::from_millis(1_000 + 3_600_000)),
            next_reset: None,
        });
        insert_text(&mut state.task_features, feature_keys::TASK_CLASS, "repair");
        insert_text(&mut state.task_features, feature_keys::LANGUAGE, "rust");
        insert_text(&mut state.repo_features, feature_keys::REPO_ID, "demo");
        state
    }

    #[test]
    fn predictor_emits_full_distribution_not_point_values() {
        let predictor = HierarchicalPolicyPredictor::new();
        let predicted = predictor
            .predict(
                &state(),
                &graph("p1", "family-a", "model-a", CanonicalEffort::Low),
            )
            .expect("predict");
        assert!(!predicted.details.time_to_cert_samples_micros.is_empty());
        assert!(!predicted.details.monetary_cost_samples_micros.is_empty());
        assert!(!predicted.details.failure_mode_bp.is_empty());
        assert!(predicted.details.uncertainty_micros > 0);
        assert!(
            predicted.details.cvar95_latency_micros >= predicted.details.tail_latency_p95_micros
                || predicted.details.time_to_cert_samples_micros.len() == 1
        );
    }

    #[test]
    fn hierarchical_new_model_inherits_wide_prior() {
        let mut predictor = HierarchicalPolicyPredictor::new();
        let known = graph("known", "family-a", "model-a", CanonicalEffort::Medium);
        let key = HierarchicalPolicyPredictor::hierarchy_for(&state(), &known);
        for _ in 0..40 {
            predictor.observe_certification(key.clone(), true);
            predictor.observe_latency(key.clone(), 2_000_000);
        }
        let known_pred = predictor.predict(&state(), &known).expect("known");
        let new = graph("new", "family-a", "model-new", CanonicalEffort::Medium);
        let new_pred = predictor.predict(&state(), &new).expect("new");
        assert!(
            new_pred.quality_lower_confidence_bp < known_pred.quality_lower_confidence_bp,
            "new LCB {} should be wider/lower than known {}",
            new_pred.quality_lower_confidence_bp,
            known_pred.quality_lower_confidence_bp
        );
        assert!(new_pred.details.uncertainty_micros >= known_pred.details.uncertainty_micros);
    }

    #[test]
    fn public_benchmark_is_weak_prior_only() {
        let mut predictor = HierarchicalPolicyPredictor::new();
        let policy = graph("bench", "family-b", "model-b", CanonicalEffort::High);
        let key = HierarchicalPolicyPredictor::hierarchy_for(&state(), &policy);
        predictor.insert_weak_benchmark_prior(key.clone(), 9_900);
        let before = predictor.predict(&state(), &policy).expect("before");
        for _ in 0..20 {
            predictor.observe_certification(key.clone(), false);
        }
        let after = predictor.predict(&state(), &policy).expect("after");
        assert!(
            after.certified_probability_bp < before.certified_probability_bp,
            "measured failures must wash out the weak benchmark prior"
        );
    }

    #[test]
    fn wilson_lcb_is_below_mean_and_zero_without_data() {
        assert_eq!(wilson_lcb_bp(0, 0, 196), 0);
        let lcb = wilson_lcb_bp(90, 100, 196);
        assert!(lcb < 9_000);
        assert!(lcb > 7_000);
    }

    #[test]
    fn cvar_penalises_long_tail() {
        let tight = [100, 110, 120, 130, 140];
        let tailed = [100, 110, 120, 130, 10_000];
        assert!(cvar_i64(&tailed, 9_500) > cvar_i64(&tight, 9_500));
        assert!(cvar_i64(&tailed, 9_500) > mean_i64(&tailed));
    }
}
