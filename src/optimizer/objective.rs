//! Cost-to-certification objective and operator preference profiles.
//!
//! Quality is not a term in this objective. It is a hard constraint evaluated
//! by [`crate::optimizer::certification`]. Preference weights (#171) scale the
//! soft objective only; they cannot lower a quality floor or drop a validator.
//!
//! The [`ObjectiveEvaluator`] trait signature is unchanged so the router
//! (#167) can plug in without a core edit.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use super::error::OptimizerError;
use super::explanation::DecisionExplanation;
use super::ids::{PolicyId, ProviderId};
use super::predictor::PolicyOutcomeDistribution;

pub const PREFERENCE_SCHEMA_VERSION: u32 = 1;

const FORBIDDEN_PREFERENCE_KEYS: &[&str] = &[
    "quality_lcb_threshold",
    "quality_floor",
    "quality_threshold",
    "quality_threshold_bp",
    "mandatory_validators",
    "drop_validator",
    "remove_validator",
    "certification_authority",
    "grant_certification",
    "bypass_fail_closed",
    "fail_closed",
    "llm_only_review_permitted",
    "shadow_isolation",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectiveValue {
    pub policy_id: PolicyId,
    pub risk_adjusted_cost_micros: i64,
    pub tail_latency_micros: i64,
}

pub trait ObjectiveEvaluator {
    fn evaluate(
        &self,
        distribution: &PolicyOutcomeDistribution,
    ) -> Result<ObjectiveValue, OptimizerError>;
}

/// Named, versioned preference identity. Open string so operators can add
/// profiles without editing optimizer core types.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PreferenceProfileId(String);

impl PreferenceProfileId {
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

impl fmt::Display for PreferenceProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Per-provider / per-pool soft weights. These feed shadow-price priors
/// (`target_usage_bp`) and interactive-headroom aversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderPreference {
    pub prior_weight_bp: i64,
    pub target_usage_bp: i64,
    pub interactive_reserve_bp: i64,
    pub external_consumption_margin_bp: i64,
}

impl Default for ProviderPreference {
    fn default() -> Self {
        Self {
            prior_weight_bp: 10_000,
            target_usage_bp: 5_000,
            interactive_reserve_bp: 0,
            external_consumption_margin_bp: 0,
        }
    }
}

impl ProviderPreference {
    pub fn avoidance_penalty_bp(&self) -> i64 {
        self.interactive_reserve_bp
            .saturating_add(self.external_consumption_margin_bp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorationBudget {
    pub probes_per_period: u32,
    pub period_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgeAggressiveness {
    pub max_concurrent_hedges: u32,
    pub min_delay_seconds: u64,
    pub max_delay_seconds: u64,
}

impl Default for HedgeAggressiveness {
    fn default() -> Self {
        Self {
            max_concurrent_hedges: 1,
            min_delay_seconds: 0,
            max_delay_seconds: 60,
        }
    }
}

/// Optional per-task-class override of the soft weights.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferenceOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_weight_bp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_weight_bp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserve_margin_native: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_intervention_aversion_bp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncertainty_aversion_bp: Option<i64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_weights: BTreeMap<ProviderId, ProviderPreference>,
}

/// Operator-tunable preference profile. Soft objective only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferenceProfile {
    pub schema_version: u32,
    pub id: PreferenceProfileId,
    pub version: u32,
    #[serde(default)]
    pub provider_weights: BTreeMap<ProviderId, ProviderPreference>,
    #[serde(default)]
    pub reserve_margin_native: i64,
    pub latency_weight_bp: i64,
    pub cost_weight_bp: i64,
    #[serde(default)]
    pub human_intervention_aversion_bp: i64,
    #[serde(default)]
    pub uncertainty_aversion_bp: i64,
    #[serde(default)]
    pub exploration: BTreeMap<ProviderId, ExplorationBudget>,
    #[serde(default)]
    pub hedge: HedgeAggressiveness,
    #[serde(default)]
    pub task_class_overrides: BTreeMap<String, PreferenceOverride>,
}

impl PreferenceProfile {
    pub fn shipped_default() -> Self {
        parse_preference_profile(super::weight_profile::DEFAULT_PREFERENCE_PROFILE_JSON.as_bytes())
            .unwrap_or_else(|error| {
                panic!("tracked default preference profile failed validation: {error}")
            })
    }

    pub fn attribution(&self) -> PreferenceAttribution {
        PreferenceAttribution {
            profile_id: self.id.clone(),
            profile_version: self.version,
            schema_version: self.schema_version,
        }
    }

    pub fn provider_preference(&self, provider: &ProviderId) -> ProviderPreference {
        self.provider_weights
            .get(provider)
            .cloned()
            .unwrap_or_default()
    }

    pub fn resolved_for_task_class(&self, task_class: Option<&str>) -> PreferenceProfile {
        let Some(task_class) = task_class else {
            return self.clone();
        };
        let Some(override_set) = self.task_class_overrides.get(task_class) else {
            return self.clone();
        };
        let mut resolved = self.clone();
        if let Some(value) = override_set.latency_weight_bp {
            resolved.latency_weight_bp = value;
        }
        if let Some(value) = override_set.cost_weight_bp {
            resolved.cost_weight_bp = value;
        }
        if let Some(value) = override_set.reserve_margin_native {
            resolved.reserve_margin_native = value;
        }
        if let Some(value) = override_set.human_intervention_aversion_bp {
            resolved.human_intervention_aversion_bp = value;
        }
        if let Some(value) = override_set.uncertainty_aversion_bp {
            resolved.uncertainty_aversion_bp = value;
        }
        for (provider, preference) in &override_set.provider_weights {
            resolved
                .provider_weights
                .insert(provider.clone(), preference.clone());
        }
        resolved
    }

    pub fn validate(&self) -> Result<(), OptimizerError> {
        if self.schema_version != PREFERENCE_SCHEMA_VERSION {
            return Err(OptimizerError::invalid(format!(
                "unsupported preference schema version {}",
                self.schema_version
            )));
        }
        if self.version == 0 {
            return Err(OptimizerError::invalid(
                "preference profile version must be at least 1",
            ));
        }
        if self.cost_weight_bp < 0 || self.latency_weight_bp < 0 {
            return Err(OptimizerError::invalid(
                "preference cost and latency weights must be non-negative",
            ));
        }
        if self.hedge.min_delay_seconds > self.hedge.max_delay_seconds {
            return Err(OptimizerError::invalid(
                "hedge min delay cannot exceed max delay",
            ));
        }
        Ok(())
    }

    /// Content binding for the exact effective profile used by a decision.
    /// `BTreeMap` fields make the serialized representation deterministic.
    pub fn content_hash(&self) -> Result<String, OptimizerError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| {
            OptimizerError::invalid(format!("serialize preference profile for hashing: {error}"))
        })?;
        Ok(super::digest::sha256_hex(&bytes))
    }
}

/// Provenance recorded on every replay snapshot and decision explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferenceAttribution {
    pub profile_id: PreferenceProfileId,
    pub profile_version: u32,
    pub schema_version: u32,
}

impl PreferenceAttribution {
    pub fn label(&self) -> String {
        format!(
            "preference_profile:{}@{}",
            self.profile_id, self.profile_version
        )
    }
}

/// Record the profile that scaled the soft objective. `DecisionExplanation`
/// has no dedicated field (owned by #167); the label is appended so replay
/// can recover it without editing that type.
pub fn annotate_explanation_with_profile(
    explanation: &mut DecisionExplanation,
    profile: &PreferenceProfile,
) {
    let label = profile.attribution().label();
    if !explanation
        .rejection_reasons
        .iter()
        .any(|reason| reason == &label)
    {
        explanation.rejection_reasons.push(label);
    }
}

/// Parse a preference profile from JSON. Forbidden hard-constraint keys are
/// rejected with a targeted error before the profile is accepted.
pub fn parse_preference_profile(bytes: &[u8]) -> Result<PreferenceProfile, OptimizerError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| OptimizerError::invalid(format!("preference profile JSON: {error}")))?;
    reject_forbidden_preference_keys(&value, "")?;
    super::weight_profile::validate_preference_profile_document(&value)?;
    let profile: PreferenceProfile = serde_json::from_value(value)
        .map_err(|error| OptimizerError::invalid(format!("preference profile schema: {error}")))?;
    profile.validate()?;
    Ok(profile)
}

fn reject_forbidden_preference_keys(
    value: &serde_json::Value,
    path: &str,
) -> Result<(), OptimizerError> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if FORBIDDEN_PREFERENCE_KEYS.contains(&key.as_str()) {
                    return Err(forbidden_preference_error(key));
                }
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                reject_forbidden_preference_keys(child, &child_path)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                reject_forbidden_preference_keys(child, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn forbidden_preference_error(key: &str) -> OptimizerError {
    let detail = match key {
        "quality_lcb_threshold"
        | "quality_floor"
        | "quality_threshold"
        | "quality_threshold_bp" => {
            format!("preference profile cannot lower a quality floor ({key})")
        }
        "mandatory_validators" | "drop_validator" | "remove_validator" => {
            format!("preference profile cannot remove or weaken a mandatory validator ({key})")
        }
        "certification_authority" | "grant_certification" => {
            format!("preference profile cannot grant certification authority ({key})")
        }
        "bypass_fail_closed" | "fail_closed" | "shadow_isolation" | "llm_only_review_permitted" => {
            format!("preference profile cannot bypass fail-closed or shadow isolation ({key})")
        }
        other => format!("preference profile cannot express hard-constraint field {other}"),
    };
    OptimizerError::invalid(detail)
}

/// Soft-objective candidate. Quality remains a hard filter, not a weight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferenceCandidate {
    pub policy_id: PolicyId,
    pub provider: ProviderId,
    /// Concrete terminal execution identity. Legacy policy-only candidates may
    /// omit all three fields, but partial identities fail closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(
        default,
        alias = "reasoning_effort",
        skip_serializing_if = "Option::is_none"
    )]
    pub effort: Option<String>,
    /// Recorded admission evidence. Omission remains observable: it is
    /// compatible only for legacy policy-only candidates and fails closed for
    /// a concrete runtime/model/effort identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted: Option<bool>,
    /// Authority denials are evidence, never a soft score term.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_refusals: Vec<String>,
    pub certified: bool,
    pub quality_lower_confidence_bp: u16,
    pub expected_cost_micros: i64,
    pub expected_latency_micros: i64,
    #[serde(default)]
    pub human_minutes_micros: i64,
    #[serde(default)]
    pub uncertainty_bp: u16,
}

pub const DEFAULT_TERMINAL_RUNTIME: &str = "grok";
pub const DEFAULT_TERMINAL_MODEL: &str = "grok-4.6";
pub const DEFAULT_TERMINAL_EFFORT: &str = "xhigh";
pub const DEFAULT_TERMINAL_PROVIDER: &str = "xai";
pub const DEFAULT_TERMINAL_EVIDENCE_OBSERVED_ON: &str = "2026-08-22";
pub const DEFAULT_TERMINAL_EVIDENCE_SOURCE_ID: &str =
    "optimizer-seed-grok-4-6-cost-quality-2026-08";

// Selector class-fit costs use the same 100,000-microunit-per-USD scale as
// the shipped dated priors. Keeping the scale explicit prevents a measured
// dollar value from silently becoming a model preference table.
const SELECTOR_COST_MICROUNITS_PER_USD: f64 = 100_000.0;

/// Objective evidence used to admit, score, and explain the default terminal
/// worker candidate. Runtime membership remains a separate live hard gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalWorkerRoutingEconomics {
    pub runtime: String,
    pub model: String,
    pub effort: String,
    pub observed_on: String,
    pub source_id: String,
    pub prior_scope: String,
    pub limitations: Vec<String>,
    pub quality_basis_points: u16,
    pub sample_size: u32,
    pub execution_cost_microunits: u64,
}

/// Evaluate the tracked Grok observations into selector-compatible economics.
///
/// This function does not select a role or bypass catalog membership. It
/// converts the exact shipped cost and software-engineering quality axes into
/// a bounded class-fit prior; the selector still applies availability,
/// authority, operator, quality, and pool gates before ranking it.
pub fn terminal_worker_routing_economics() -> Result<TerminalWorkerRoutingEconomics, OptimizerError>
{
    let document = super::seed_evidence::load_shipped_seed_evidence()?;
    let measured_cost = exact_seed_observation(
        &document,
        DEFAULT_TERMINAL_MODEL,
        "measured_cost_per_task_usd",
    )?;
    let software_quality = exact_seed_observation(&document, DEFAULT_TERMINAL_MODEL, "swe_bench")?;
    let execution_cost_microunits = scaled_observation_value(
        measured_cost,
        SELECTOR_COST_MICROUNITS_PER_USD,
        "measured_cost_per_task_usd",
    )?;
    let quality_basis_points = u16::try_from(scaled_observation_value(
        software_quality,
        10_000.0,
        "swe_bench",
    )?)
    .map_err(|_| {
        OptimizerError::invalid("grok-4.6 SWE-bench seed observation exceeds basis-point range")
    })?;
    if quality_basis_points > 10_000 {
        return Err(OptimizerError::invalid(
            "grok-4.6 SWE-bench seed observation exceeds 10000 basis points",
        ));
    }
    Ok(TerminalWorkerRoutingEconomics {
        runtime: DEFAULT_TERMINAL_RUNTIME.to_string(),
        model: DEFAULT_TERMINAL_MODEL.to_string(),
        effort: DEFAULT_TERMINAL_EFFORT.to_string(),
        observed_on: DEFAULT_TERMINAL_EVIDENCE_OBSERVED_ON.to_string(),
        source_id: DEFAULT_TERMINAL_EVIDENCE_SOURCE_ID.to_string(),
        prior_scope: "tracked cost and software-engineering quality observations evaluated for bounded terminal implementation work"
            .to_string(),
        limitations: vec![
            format!(
                "quality is the shipped aggregate SWE-bench observation from {}; local accepted-task outcomes remain authoritative",
                software_quality.source
            ),
            format!(
                "execution cost is the shipped measured cost-per-task observation from {} on the explicit selector scale",
                measured_cost.source
            ),
            "bounded terminal implementation work only; no delegation, review, audit, gate, or publication authority"
                .to_string(),
        ],
        quality_basis_points,
        sample_size: 1,
        execution_cost_microunits,
    })
}

fn exact_seed_observation<'a>(
    document: &'a super::seed_evidence::SeedEvidenceDocument,
    model: &str,
    axis: &str,
) -> Result<&'a super::seed_evidence::SeedObservation, OptimizerError> {
    let mut matches = document
        .observations
        .iter()
        .filter(|observation| observation.model == model && observation.axis == axis);
    let observation = matches.next().ok_or_else(|| {
        OptimizerError::invalid(format!(
            "shipped seed evidence has no exact '{model}' observation for axis '{axis}'"
        ))
    })?;
    if matches.next().is_some() {
        return Err(OptimizerError::invalid(format!(
            "shipped seed evidence has duplicate '{model}' observations for axis '{axis}'"
        )));
    }
    Ok(observation)
}

fn scaled_observation_value(
    observation: &super::seed_evidence::SeedObservation,
    scale: f64,
    axis: &str,
) -> Result<u64, OptimizerError> {
    let value = observation
        .value
        .as_ref()
        .and_then(serde_json::Value::as_f64)
        .ok_or_else(|| {
            OptimizerError::invalid(format!(
                "'{axis}' seed observation must contain a numeric value"
            ))
        })?;
    let scaled = value * scale;
    let rounded = scaled.round();
    if !scaled.is_finite()
        || scaled < 0.0
        || (scaled - rounded).abs() > f64::EPSILON * scale
        || rounded > u64::MAX as f64
    {
        return Err(OptimizerError::invalid(format!(
            "'{axis}' seed observation cannot be represented on its objective scale"
        )));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(rounded as u64)
}

/// Stable identity used in decision evidence and deterministic tie-breaking.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceCandidateIdentity {
    pub policy_id: PolicyId,
    pub provider: ProviderId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
}

impl PreferenceCandidate {
    pub fn identity(&self) -> PreferenceCandidateIdentity {
        PreferenceCandidateIdentity {
            policy_id: self.policy_id.clone(),
            provider: self.provider.clone(),
            runtime: self.runtime.clone(),
            model: self.model.clone(),
            effort: self.effort.clone(),
        }
    }

    fn validate_execution_identity(&self) -> Result<(), OptimizerError> {
        let fields = [
            self.runtime.as_deref(),
            self.model.as_deref(),
            self.effort.as_deref(),
        ];
        let populated = fields.iter().filter(|field| field.is_some()).count();
        if populated != 0 && populated != fields.len() {
            return Err(OptimizerError::invalid(format!(
                "candidate '{}' must provide runtime, model, and effort together",
                self.policy_id
            )));
        }
        if fields
            .iter()
            .flatten()
            .any(|value| value.is_empty() || *value != value.trim())
        {
            return Err(OptimizerError::invalid(format!(
                "candidate '{}' runtime, model, and effort must be non-empty trimmed strings",
                self.policy_id
            )));
        }
        if self
            .authority_refusals
            .iter()
            .any(|reason| reason.is_empty() || reason != reason.trim())
        {
            return Err(OptimizerError::invalid(format!(
                "candidate '{}' authority refusals must be non-empty trimmed strings",
                self.policy_id
            )));
        }
        Ok(())
    }

    fn is_default_terminal_preference(&self) -> bool {
        self.effective_admission()
            && self.authority_refusals.is_empty()
            && self.provider.as_str() == DEFAULT_TERMINAL_PROVIDER
            && self.runtime.as_deref() == Some(DEFAULT_TERMINAL_RUNTIME)
            && self.model.as_deref() == Some(DEFAULT_TERMINAL_MODEL)
            && self.effort.as_deref() == Some(DEFAULT_TERMINAL_EFFORT)
    }

    fn effective_admission(&self) -> bool {
        match self.admitted {
            Some(admitted) => admitted,
            None => self.runtime.is_none() && self.model.is_none() && self.effort.is_none(),
        }
    }
}

/// Score and hard-gate evidence for every candidate, including refusals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceCandidateScore {
    pub identity: PreferenceCandidateIdentity,
    pub score_micros: i64,
    /// Exact input evidence; `None` distinguishes omission from denial.
    pub admitted: Option<bool>,
    pub effective_admission: bool,
    pub eligible: bool,
    pub default_terminal_preference: bool,
    pub rejection_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceAuthorityRefusal {
    pub identity: PreferenceCandidateIdentity,
    pub reasons: Vec<String>,
}

/// Self-contained, replayable selection decision. It records the exact
/// effective objective, every score, and both leading identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceDecision {
    pub objective_profile: PreferenceProfile,
    pub objective_profile_hash: String,
    pub quality_threshold_bp: u16,
    pub candidate_scores: Vec<PreferenceCandidateScore>,
    pub selected: Option<PreferenceCandidateIdentity>,
    pub runner_up: Option<PreferenceCandidateIdentity>,
    pub authority_refusals: Vec<PreferenceAuthorityRefusal>,
    pub selection: PreferenceSelection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreferenceSelection {
    Selected {
        policy_id: PolicyId,
        score_micros: i64,
        attribution: PreferenceAttribution,
    },
    Infeasible {
        reason: String,
        attribution: PreferenceAttribution,
    },
}

impl PreferenceSelection {
    pub fn selected_policy(&self) -> Option<&PolicyId> {
        match self {
            Self::Selected { policy_id, .. } => Some(policy_id),
            Self::Infeasible { .. } => None,
        }
    }

    pub fn attribution(&self) -> &PreferenceAttribution {
        match self {
            Self::Selected { attribution, .. } | Self::Infeasible { attribution, .. } => {
                attribution
            }
        }
    }
}

/// Integer soft score. Lower is better. Quality is never a term.
pub fn score_candidate(candidate: &PreferenceCandidate, profile: &PreferenceProfile) -> i64 {
    let provider = profile.provider_preference(&candidate.provider);
    let cost_term = scale_bp(candidate.expected_cost_micros, profile.cost_weight_bp);
    let latency_term = scale_bp(candidate.expected_latency_micros, profile.latency_weight_bp);
    let human_term = scale_bp(
        candidate.human_minutes_micros,
        profile.human_intervention_aversion_bp,
    );
    let uncertainty_term = scale_bp(
        i64::from(candidate.uncertainty_bp),
        profile.uncertainty_aversion_bp,
    );
    let avoidance_term = scale_bp(1_000_000, provider.avoidance_penalty_bp());
    cost_term
        .saturating_add(latency_term)
        .saturating_add(human_term)
        .saturating_add(uncertainty_term)
        .saturating_add(avoidance_term)
}

fn scale_bp(value: i64, weight_bp: i64) -> i64 {
    value.saturating_mul(weight_bp) / 10_000
}

pub fn select_with_profile(
    candidates: &[PreferenceCandidate],
    profile: &PreferenceProfile,
    quality_threshold_bp: u16,
) -> Result<PreferenceSelection, OptimizerError> {
    Ok(decide_with_profile(candidates, profile, quality_threshold_bp)?.selection)
}

pub fn decide_with_profile(
    candidates: &[PreferenceCandidate],
    profile: &PreferenceProfile,
    quality_threshold_bp: u16,
) -> Result<PreferenceDecision, OptimizerError> {
    profile.validate()?;
    let objective_profile_hash = profile.content_hash()?;
    let attribution = profile.attribution();
    let mut identities = BTreeSet::new();
    let mut candidate_scores = Vec::with_capacity(candidates.len());
    let mut authority_refusals = Vec::new();
    for candidate in candidates {
        candidate.validate_execution_identity()?;
        let identity = candidate.identity();
        if !identities.insert(identity.clone()) {
            return Err(OptimizerError::invalid(format!(
                "duplicate preference candidate identity for policy '{}'",
                candidate.policy_id
            )));
        }
        let mut rejection_reasons = Vec::new();
        let effective_admission = candidate.effective_admission();
        if !effective_admission {
            rejection_reasons.push("candidate_not_admitted".to_string());
        }
        let mut refusal_reasons = candidate.authority_refusals.clone();
        refusal_reasons.sort();
        refusal_reasons.dedup();
        if !refusal_reasons.is_empty() {
            rejection_reasons.push("authority_refused".to_string());
            authority_refusals.push(PreferenceAuthorityRefusal {
                identity: identity.clone(),
                reasons: refusal_reasons,
            });
        }
        if !candidate.certified {
            rejection_reasons.push("candidate_not_certified".to_string());
        }
        if candidate.quality_lower_confidence_bp < quality_threshold_bp {
            rejection_reasons.push("quality_contract_not_satisfied".to_string());
        }
        candidate_scores.push(PreferenceCandidateScore {
            identity,
            score_micros: score_candidate(candidate, profile),
            admitted: candidate.admitted,
            effective_admission,
            eligible: rejection_reasons.is_empty(),
            default_terminal_preference: candidate.is_default_terminal_preference(),
            rejection_reasons,
        });
    }
    candidate_scores.sort_by(|left, right| left.identity.cmp(&right.identity));
    authority_refusals.sort_by(|left, right| left.identity.cmp(&right.identity));

    let mut ranked = candidate_scores
        .iter()
        .filter(|candidate| candidate.eligible)
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        left.score_micros
            .cmp(&right.score_micros)
            // The explicit terminal default is only a tie-break after the
            // resolved profile score and only exists for an admitted candidate.
            .then_with(|| {
                right
                    .default_terminal_preference
                    .cmp(&left.default_terminal_preference)
            })
            .then_with(|| left.identity.cmp(&right.identity))
    });
    let selected = ranked.first().map(|candidate| candidate.identity.clone());
    let runner_up = ranked.get(1).map(|candidate| candidate.identity.clone());
    let selection = if let Some(winner) = ranked.first() {
        PreferenceSelection::Selected {
            policy_id: winner.identity.policy_id.clone(),
            score_micros: winner.score_micros,
            attribution,
        }
    } else {
        PreferenceSelection::Infeasible {
            reason: "no candidate satisfies admission, authority, certification, and quality gates"
                .to_string(),
            attribution,
        }
    };
    Ok(PreferenceDecision {
        objective_profile: profile.clone(),
        objective_profile_hash,
        quality_threshold_bp,
        candidate_scores,
        selected,
        runner_up,
        authority_refusals,
        selection,
    })
}

/// Side-by-side preview used by the CLI and GUI preference surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferencePreview {
    pub quality_threshold_bp: u16,
    pub profile_a: PreferenceAttribution,
    pub profile_b: PreferenceAttribution,
    pub selected_a: Option<PolicyId>,
    pub selected_b: Option<PolicyId>,
    pub selections_differ: bool,
    pub hard_constraint_bound: bool,
    pub selection_a: PreferenceSelection,
    pub selection_b: PreferenceSelection,
    pub decision_a: PreferenceDecision,
    pub decision_b: PreferenceDecision,
}

pub fn preview_profile_effect(
    candidates: &[PreferenceCandidate],
    profile_a: &PreferenceProfile,
    profile_b: &PreferenceProfile,
    quality_threshold_bp: u16,
) -> Result<PreferencePreview, OptimizerError> {
    let decision_a = decide_with_profile(candidates, profile_a, quality_threshold_bp)?;
    let decision_b = decide_with_profile(candidates, profile_b, quality_threshold_bp)?;
    let selection_a = decision_a.selection.clone();
    let selection_b = decision_b.selection.clone();
    let selected_a = selection_a.selected_policy().cloned();
    let selected_b = selection_b.selected_policy().cloned();
    let eligible_count = decision_a
        .candidate_scores
        .iter()
        .filter(|candidate| candidate.eligible)
        .count();
    Ok(PreferencePreview {
        quality_threshold_bp,
        profile_a: profile_a.attribution(),
        profile_b: profile_b.attribution(),
        selections_differ: selected_a != selected_b,
        hard_constraint_bound: eligible_count <= 1,
        selected_a,
        selected_b,
        selection_a,
        selection_b,
        decision_a,
        decision_b,
    })
}

/// Objective evaluator that applies a preference profile's latency/cost mix.
pub struct PreferenceObjectiveEvaluator {
    pub profile: PreferenceProfile,
}

impl ObjectiveEvaluator for PreferenceObjectiveEvaluator {
    fn evaluate(
        &self,
        distribution: &PolicyOutcomeDistribution,
    ) -> Result<ObjectiveValue, OptimizerError> {
        self.profile.validate()?;
        let cost = scale_bp(
            distribution.expected_cost_micros,
            self.profile.cost_weight_bp,
        );
        let latency = scale_bp(
            distribution.expected_latency_micros,
            self.profile.latency_weight_bp,
        );
        Ok(ObjectiveValue {
            policy_id: distribution.policy_id.clone(),
            risk_adjusted_cost_micros: cost.saturating_add(latency),
            tail_latency_micros: distribution.expected_latency_micros,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferenceFieldDiff {
    pub field: String,
    pub left: String,
    pub right: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferenceDiff {
    pub left: PreferenceAttribution,
    pub right: PreferenceAttribution,
    pub fields: Vec<PreferenceFieldDiff>,
}

pub fn diff_profiles(left: &PreferenceProfile, right: &PreferenceProfile) -> PreferenceDiff {
    let mut fields = Vec::new();
    push_diff(
        &mut fields,
        "latency_weight_bp",
        left.latency_weight_bp,
        right.latency_weight_bp,
    );
    push_diff(
        &mut fields,
        "cost_weight_bp",
        left.cost_weight_bp,
        right.cost_weight_bp,
    );
    push_diff(
        &mut fields,
        "reserve_margin_native",
        left.reserve_margin_native,
        right.reserve_margin_native,
    );
    push_diff(
        &mut fields,
        "human_intervention_aversion_bp",
        left.human_intervention_aversion_bp,
        right.human_intervention_aversion_bp,
    );
    push_diff(
        &mut fields,
        "uncertainty_aversion_bp",
        left.uncertainty_aversion_bp,
        right.uncertainty_aversion_bp,
    );
    let providers: BTreeSet<&ProviderId> = left
        .provider_weights
        .keys()
        .chain(right.provider_weights.keys())
        .collect();
    for provider in providers {
        let left_pref = left.provider_preference(provider);
        let right_pref = right.provider_preference(provider);
        if left_pref != right_pref {
            fields.push(PreferenceFieldDiff {
                field: format!("provider_weights.{provider}"),
                left: format!("{left_pref:?}"),
                right: format!("{right_pref:?}"),
            });
        }
    }
    PreferenceDiff {
        left: left.attribution(),
        right: right.attribution(),
        fields,
    }
}

fn push_diff<T: PartialEq + fmt::Display>(
    fields: &mut Vec<PreferenceFieldDiff>,
    name: &str,
    left: T,
    right: T,
) {
    if left != right {
        fields.push(PreferenceFieldDiff {
            field: name.to_string(),
            left: left.to_string(),
            right: right.to_string(),
        });
    }
}

/// One on-disk format shared by the CLI and the GUI preference surface.
pub struct PreferenceStore {
    root: PathBuf,
}

impl PreferenceStore {
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn ensure(&self) -> Result<(), OptimizerError> {
        fs::create_dir_all(&self.root).map_err(|error| {
            OptimizerError::invalid(format!(
                "failed to create preference store {}: {error}",
                self.root.display()
            ))
        })
    }

    pub fn save(&self, profile: &PreferenceProfile) -> Result<PathBuf, OptimizerError> {
        profile.validate()?;
        self.ensure()?;
        let path = self.profile_path(&profile.id, profile.version);
        let body = serde_json::to_vec_pretty(profile).map_err(|error| {
            OptimizerError::invalid(format!("serialize preference profile: {error}"))
        })?;
        fs::write(&path, body).map_err(|error| {
            OptimizerError::invalid(format!("write {}: {error}", path.display()))
        })?;
        Ok(path)
    }

    pub fn load(&self, id: &str) -> Result<PreferenceProfile, OptimizerError> {
        let mut matches: Vec<PreferenceProfile> = self
            .list()?
            .into_iter()
            .filter(|profile| profile.id.as_str() == id)
            .collect();
        matches.sort_by_key(|profile| profile.version);
        matches.pop().ok_or_else(|| {
            OptimizerError::invalid(format!("preference profile '{id}' is not in the store"))
        })
    }

    pub fn list(&self) -> Result<Vec<PreferenceProfile>, OptimizerError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut profiles = Vec::new();
        let entries = fs::read_dir(&self.root).map_err(|error| {
            OptimizerError::invalid(format!("read {}: {error}", self.root.display()))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                OptimizerError::invalid(format!("read {}: {error}", self.root.display()))
            })?;
            let path = entry.path();
            if path.file_name().and_then(|name| name.to_str()) == Some("default.json") {
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let bytes = fs::read(&path).map_err(|error| {
                OptimizerError::invalid(format!("read {}: {error}", path.display()))
            })?;
            profiles.push(parse_preference_profile(&bytes)?);
        }
        profiles.sort_by(|left, right| {
            left.id
                .as_str()
                .cmp(right.id.as_str())
                .then(left.version.cmp(&right.version))
        });
        Ok(profiles)
    }

    pub fn set_project_default(&self, id: &str) -> Result<(), OptimizerError> {
        let profile = self.load(id)?;
        self.ensure()?;
        let path = self.root.join("default.json");
        let body = serde_json::json!({
            "id": profile.id.as_str(),
            "version": profile.version,
        });
        fs::write(
            &path,
            serde_json::to_vec_pretty(&body).expect("default json"),
        )
        .map_err(|error| OptimizerError::invalid(format!("write {}: {error}", path.display())))
    }

    pub fn project_default(&self) -> Result<Option<PreferenceProfile>, OptimizerError> {
        let path = self.root.join("default.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|error| {
            OptimizerError::invalid(format!("read {}: {error}", path.display()))
        })?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            OptimizerError::invalid(format!("parse default preference pointer: {error}"))
        })?;
        let id = value
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| OptimizerError::invalid("default.json is missing id"))?;
        Ok(Some(self.load(id)?))
    }

    fn profile_path(&self, id: &PreferenceProfileId, version: u32) -> PathBuf {
        self.root.join(format!("{}.v{version}.json", id.as_str()))
    }
}

/// Self-contained GUI preference surface. Same JSON schema as the CLI.
pub fn render_preference_surface_html(
    profile_a: &PreferenceProfile,
    profile_b: &PreferenceProfile,
    preview: Option<&PreferencePreview>,
) -> Result<String, OptimizerError> {
    profile_a.validate()?;
    profile_b.validate()?;
    let json_a = serde_json::to_string_pretty(profile_a)
        .map_err(|error| OptimizerError::invalid(format!("profile A JSON: {error}")))?;
    let json_b = serde_json::to_string_pretty(profile_b)
        .map_err(|error| OptimizerError::invalid(format!("profile B JSON: {error}")))?;
    let preview_json = match preview {
        Some(preview) => serde_json::to_string_pretty(preview)
            .map_err(|error| OptimizerError::invalid(format!("preview JSON: {error}")))?,
        None => "null".to_string(),
    };
    let selected_a = preview
        .and_then(|preview| preview.selected_a.as_ref())
        .map(PolicyId::as_str)
        .unwrap_or("(none)");
    let selected_b = preview
        .and_then(|preview| preview.selected_b.as_ref())
        .map(PolicyId::as_str)
        .unwrap_or("(none)");
    let differ = preview
        .map(|preview| preview.selections_differ)
        .unwrap_or(false);
    Ok(format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MACO optimizer preference surface</title>
<style>
body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 1.5rem; color: #111; }}
h1 {{ font-size: 1.25rem; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
textarea {{ width: 100%; min-height: 22rem; font-family: ui-monospace, monospace; font-size: 0.8rem; }}
.preview {{ margin-top: 1rem; padding: 1rem; border: 1px solid #ccc; }}
.differ {{ background: #fff6d8; }}
.same {{ background: #eef8ee; }}
code {{ background: #f4f4f4; padding: 0.1rem 0.3rem; }}
</style>
</head>
<body>
<h1>Optimizer preference profiles</h1>
<p>One storage format. Edit JSON here, export, and the CLI reads the same file.</p>
<div class="grid">
<section>
<h2>Profile A — {id_a}@{ver_a}</h2>
<textarea id="profile-a" readonly>{json_a}</textarea>
</section>
<section>
<h2>Profile B — {id_b}@{ver_b}</h2>
<textarea id="profile-b" readonly>{json_b}</textarea>
</section>
</div>
<div class="preview {preview_class}">
<h2>Preview</h2>
<p>With profile A the router would have picked <code>{selected_a}</code>.</p>
<p>With profile B it picks <code>{selected_b}</code>.</p>
<p>Selections differ: <strong>{differ}</strong></p>
<pre id="preview">{preview_json}</pre>
</div>
</body>
</html>
"##,
        id_a = html_escape(profile_a.id.as_str()),
        ver_a = profile_a.version,
        id_b = html_escape(profile_b.id.as_str()),
        ver_b = profile_b.version,
        json_a = html_escape(&json_a),
        json_b = html_escape(&json_b),
        selected_a = html_escape(selected_a),
        selected_b = html_escape(selected_b),
        differ = differ,
        preview_class = if differ { "differ" } else { "same" },
        preview_json = html_escape(&preview_json),
    ))
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn provider(name: &str) -> ProviderId {
        ProviderId::new(name).expect("provider")
    }

    fn policy(name: &str) -> PolicyId {
        PolicyId::new(name).expect("policy")
    }

    fn certified(id: &str, provider_name: &str, cost: i64, latency: i64) -> PreferenceCandidate {
        PreferenceCandidate {
            policy_id: policy(id),
            provider: provider(provider_name),
            runtime: None,
            model: None,
            effort: None,
            admitted: None,
            authority_refusals: Vec::new(),
            certified: true,
            quality_lower_confidence_bp: 9_000,
            expected_cost_micros: cost,
            expected_latency_micros: latency,
            human_minutes_micros: 0,
            uncertainty_bp: 0,
        }
    }

    #[test]
    fn shipped_default_loads_tracked_profile_with_current_constants() {
        let profile = PreferenceProfile::shipped_default();
        assert_eq!(profile.schema_version, PREFERENCE_SCHEMA_VERSION);
        assert_eq!(profile.id.as_str(), "default");
        assert_eq!(profile.version, 1);
        assert_eq!(profile.latency_weight_bp, 5_000);
        assert_eq!(profile.cost_weight_bp, 5_000);
        assert_eq!(profile.reserve_margin_native, 0);
        assert_eq!(profile.human_intervention_aversion_bp, 0);
        assert_eq!(profile.uncertainty_aversion_bp, 0);
        assert!(profile.provider_weights.is_empty());
        assert!(profile.exploration.is_empty());
        assert!(profile.task_class_overrides.is_empty());
        assert_eq!(profile.hedge, HedgeAggressiveness::default());
    }

    #[test]
    fn terminal_worker_economics_are_derived_from_exact_shipped_observations() {
        let evidence = terminal_worker_routing_economics().expect("terminal worker economics");
        assert_eq!(evidence.runtime, DEFAULT_TERMINAL_RUNTIME);
        assert_eq!(evidence.model, DEFAULT_TERMINAL_MODEL);
        assert_eq!(evidence.effort, DEFAULT_TERMINAL_EFFORT);
        assert_eq!(evidence.quality_basis_points, 9_560);
        assert_eq!(evidence.execution_cost_microunits, 83_700);
        assert_eq!(evidence.sample_size, 1);
        assert!(evidence
            .limitations
            .iter()
            .any(|limitation| limitation.contains("no delegation")));
    }

    #[test]
    fn operator_profile_missing_required_weight_fails_closed() {
        let error = parse_preference_profile(
            br#"{"schema_version":1,"id":"bad","version":1,"latency_weight_bp":1}"#,
        )
        .expect_err("missing cost weight");
        assert!(error.to_string().contains("cost_weight_bp"), "{error}");
    }

    #[test]
    fn two_profiles_over_the_same_evidence_select_differently_when_the_frontier_allows() {
        let mut cost_first = PreferenceProfile::shipped_default();
        cost_first.id = PreferenceProfileId::new("cost-first").expect("id");
        cost_first.cost_weight_bp = 9_000;
        cost_first.latency_weight_bp = 1_000;

        let mut latency_first = PreferenceProfile::shipped_default();
        latency_first.id = PreferenceProfileId::new("latency-first").expect("id");
        latency_first.cost_weight_bp = 1_000;
        latency_first.latency_weight_bp = 9_000;

        let candidates = vec![
            certified("cheap-slow", "pool-a", 1_000, 50_000),
            certified("dear-fast", "pool-a", 20_000, 1_000),
        ];
        let preview = preview_profile_effect(&candidates, &cost_first, &latency_first, 8_000)
            .expect("preview");
        assert_eq!(
            preview.selected_a.as_ref().map(PolicyId::as_str),
            Some("cheap-slow")
        );
        assert_eq!(
            preview.selected_b.as_ref().map(PolicyId::as_str),
            Some("dear-fast")
        );
        assert!(preview.selections_differ);
        assert!(!preview.hard_constraint_bound);
    }

    #[test]
    fn provider_avoidance_flips_selection_on_an_open_frontier() {
        let mut avoid = PreferenceProfile::shipped_default();
        avoid.id = PreferenceProfileId::new("avoid-interactive").expect("id");
        avoid.provider_weights.insert(
            provider("shared"),
            ProviderPreference {
                prior_weight_bp: 10_000,
                target_usage_bp: 1_000,
                interactive_reserve_bp: 8_000,
                external_consumption_margin_bp: 2_000,
            },
        );

        let keep = PreferenceProfile::shipped_default();
        let candidates = vec![
            certified("use-shared", "shared", 1_000, 1_000),
            certified("use-other", "other", 3_000, 3_000),
        ];
        let preview = preview_profile_effect(&candidates, &keep, &avoid, 8_000).expect("preview");
        assert_eq!(
            preview.selected_a.as_ref().map(PolicyId::as_str),
            Some("use-shared")
        );
        assert_eq!(
            preview.selected_b.as_ref().map(PolicyId::as_str),
            Some("use-other")
        );
    }

    #[test]
    fn hard_constraints_bind_to_the_same_selection_under_any_profile() {
        let mut cost_first = PreferenceProfile::shipped_default();
        cost_first.id = PreferenceProfileId::new("cost-first").expect("id");
        cost_first.cost_weight_bp = 9_000;
        let mut latency_first = PreferenceProfile::shipped_default();
        latency_first.id = PreferenceProfileId::new("latency-first").expect("id");
        latency_first.latency_weight_bp = 9_000;

        let candidates = vec![
            PreferenceCandidate {
                policy_id: policy("uncertified-cheap"),
                provider: provider("pool-a"),
                runtime: None,
                model: None,
                effort: None,
                admitted: None,
                authority_refusals: Vec::new(),
                certified: false,
                quality_lower_confidence_bp: 4_000,
                expected_cost_micros: 1,
                expected_latency_micros: 1,
                human_minutes_micros: 0,
                uncertainty_bp: 0,
            },
            certified("only-certified", "pool-a", 99_000, 99_000),
        ];
        let preview = preview_profile_effect(&candidates, &cost_first, &latency_first, 8_000)
            .expect("preview");
        assert_eq!(
            preview.selected_a.as_ref().map(PolicyId::as_str),
            Some("only-certified")
        );
        assert_eq!(preview.selected_a, preview.selected_b);
        assert!(!preview.selections_differ);
        assert!(preview.hard_constraint_bound);
    }

    #[test]
    fn profile_cannot_relax_quality_floor_or_drop_a_validator() {
        let floor = parse_preference_profile(
            br#"{"schema_version":1,"id":"bad","version":1,"latency_weight_bp":1,"cost_weight_bp":1,"quality_lcb_threshold":1}"#,
        )
        .expect_err("floor");
        assert!(floor.to_string().contains("quality floor"), "{floor}");

        let validator = parse_preference_profile(
            br#"{"schema_version":1,"id":"bad","version":1,"latency_weight_bp":1,"cost_weight_bp":1,"mandatory_validators":[]}"#,
        )
        .expect_err("validator");
        assert!(
            validator.to_string().contains("mandatory validator"),
            "{validator}"
        );

        let authority = parse_preference_profile(
            br#"{"schema_version":1,"id":"bad","version":1,"latency_weight_bp":1,"cost_weight_bp":1,"certification_authority":true}"#,
        )
        .expect_err("authority");
        assert!(
            authority.to_string().contains("certification authority"),
            "{authority}"
        );

        let bypass = parse_preference_profile(
            br#"{"schema_version":1,"id":"bad","version":1,"latency_weight_bp":1,"cost_weight_bp":1,"bypass_fail_closed":true}"#,
        )
        .expect_err("bypass");
        assert!(bypass.to_string().contains("fail-closed"), "{bypass}");
    }

    #[test]
    fn gui_edited_profile_round_trips_through_the_cli_store() {
        let temp = TempDir::new().expect("tempdir");
        let store = PreferenceStore::open(temp.path());
        let mut profile = PreferenceProfile::shipped_default();
        profile.id = PreferenceProfileId::new("interactive-reserve").expect("id");
        profile.reserve_margin_native = 12;
        profile.provider_weights.insert(
            provider("shared"),
            ProviderPreference {
                prior_weight_bp: 8_000,
                target_usage_bp: 2_000,
                interactive_reserve_bp: 7_000,
                external_consumption_margin_bp: 1_000,
            },
        );
        let gui_bytes = serde_json::to_vec_pretty(&profile).expect("gui export");
        let parsed = parse_preference_profile(&gui_bytes).expect("cli import");
        store.save(&parsed).expect("save");
        store
            .set_project_default("interactive-reserve")
            .expect("default");
        let loaded = store
            .project_default()
            .expect("load default")
            .expect("present");
        assert_eq!(loaded, profile);
        let html =
            render_preference_surface_html(&profile, &PreferenceProfile::shipped_default(), None)
                .expect("html");
        assert!(html.contains("interactive-reserve"));
        assert!(html.contains("Optimizer preference profiles"));
    }

    #[test]
    fn preference_evaluator_does_not_include_quality() {
        let evaluator = PreferenceObjectiveEvaluator {
            profile: PreferenceProfile::shipped_default(),
        };
        let value = evaluator
            .evaluate(&PolicyOutcomeDistribution::new(
                policy("p1"),
                10_000,
                2_000,
                1,
                1,
            ))
            .expect("evaluate");
        assert_eq!(value.risk_adjusted_cost_micros, 6_000);
        assert_eq!(value.tail_latency_micros, 2_000);
    }
}
