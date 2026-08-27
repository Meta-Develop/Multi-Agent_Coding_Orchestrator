//! Context-switch cost as a first-class objective term (issue #201).
//!
//! Switching runtime, model, or session invalidates prompt cache and forces
//! re-priming. Those two effects are priced as explicit, independently fitted
//! terms — not a lumped residual later split for display. Offline replay
//! cannot reconstruct cache state, so replay estimates are labelled
//! `switch-cost-uncorrected` and cannot promote a policy into the safe set
//! on their own.

use serde::{de, Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

use super::action::{ModelAction, RestartMode};
use super::error::OptimizerError;
use super::ids::ResourceDimensionId;
use super::objective::{ObjectiveEvaluator, ObjectiveValue};
use super::policy::PolicyGraph;
use super::predictor::{feature_keys, feature_text, primary_action, SampleCell};
use super::resources::ObservationKind;
use super::state::OptimizerState;
use super::telemetry::InvocationRecord;

pub const REPLAY_UNCORRECTED_LABEL: &str = "switch-cost-uncorrected";
pub const DEFAULT_HYSTERESIS_BP: u16 = 1_000;
pub const DEFAULT_OSCILLATION_ALARM: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionClass {
    Continue,
    ModelChangeSameRuntime,
    RuntimeAdapterChange,
    FreshSessionOrWorktree,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchEvidenceStatus {
    Measured,
    Mixed,
    #[default]
    Inferred,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchEvidenceSource {
    ContinueZero,
    ExplicitObservation,
    ExactTransitionTelemetry,
    ClassTelemetry,
    GlobalTelemetry,
    ColdStartPrior,
    #[default]
    LegacyUnknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchCostInterval {
    pub lower: i64,
    pub upper: i64,
}

impl SwitchCostInterval {
    fn point(value: i64) -> Self {
        Self {
            lower: value,
            upper: value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchComponentProvenance {
    pub source: SwitchEvidenceSource,
    pub sample_count: u32,
    pub observation: ObservationKind,
    pub uncertainty: SwitchCostInterval,
}

impl Default for SwitchComponentProvenance {
    fn default() -> Self {
        Self {
            source: SwitchEvidenceSource::LegacyUnknown,
            sample_count: 0,
            observation: ObservationKind::Inferred,
            uncertainty: SwitchCostInterval::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchCostProvenance {
    pub cached_prefix_invalidation: SwitchComponentProvenance,
    pub context_reprime: SwitchComponentProvenance,
    pub runtime_startup: SwitchComponentProvenance,
    pub lost_checkpoint: SwitchComponentProvenance,
}

impl TransitionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "continue",
            Self::ModelChangeSameRuntime => "model_change_same_runtime",
            Self::RuntimeAdapterChange => "runtime_adapter_change",
            Self::FreshSessionOrWorktree => "fresh_session_or_worktree",
        }
    }

    pub fn is_switch(self) -> bool {
        !matches!(self, Self::Continue)
    }
}

/// Classify a candidate relative to the currently active action.
///
/// An unknown current action is not a switch: treating every action-bearing
/// candidate as [`TransitionClass::FreshSessionOrWorktree`] would apply the
/// large fresh-session prior and skew a mixed action/non-action set toward
/// non-action policies. Explicit [`RestartMode::CleanRestart`] still prices
/// as a fresh session.
pub fn classify_transition(
    previous: Option<&ModelAction>,
    next: Option<&ModelAction>,
    restart: RestartMode,
) -> TransitionClass {
    if restart == RestartMode::CleanRestart {
        return TransitionClass::FreshSessionOrWorktree;
    }
    match (previous, next) {
        (None, Some(_)) | (Some(_), None) | (None, None) => TransitionClass::Continue,
        (Some(prev), Some(next)) => {
            if prev.backend_id != next.backend_id {
                TransitionClass::RuntimeAdapterChange
            } else if prev.runtime_model.runtime_slug != next.runtime_model.runtime_slug {
                TransitionClass::ModelChangeSameRuntime
            } else {
                TransitionClass::Continue
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwitchCostEstimate {
    pub class: TransitionClass,
    pub cached_prefix_invalidation_tokens: i64,
    pub context_reprime_tokens: i64,
    pub runtime_startup_micros: i64,
    pub lost_checkpoint_cost_micros: i64,
    pub total_cost_micros: i64,
    pub observation: ObservationKind,
    pub status: SwitchEvidenceStatus,
    pub sample_count: u32,
    pub uncertainty_micros: SwitchCostInterval,
    pub provenance: SwitchCostProvenance,
}

#[derive(Deserialize)]
struct SwitchCostEstimateWire {
    class: TransitionClass,
    cached_prefix_invalidation_tokens: i64,
    context_reprime_tokens: i64,
    runtime_startup_micros: i64,
    lost_checkpoint_cost_micros: i64,
    total_cost_micros: i64,
    observation: ObservationKind,
    status: Option<SwitchEvidenceStatus>,
    sample_count: Option<u32>,
    uncertainty_micros: Option<SwitchCostInterval>,
    provenance: Option<SwitchCostProvenance>,
}

impl<'de> Deserialize<'de> for SwitchCostEstimate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SwitchCostEstimateWire::deserialize(deserializer)?;
        let metadata_fields = [
            wire.status.is_some(),
            wire.sample_count.is_some(),
            wire.uncertainty_micros.is_some(),
            wire.provenance.is_some(),
        ];
        let estimate = if metadata_fields.iter().all(|present| !present) {
            let migrated = if wire.class == TransitionClass::Continue {
                SwitchCostEstimate::zero(wire.class)
            } else {
                SwitchCostEstimate::from_explicit_terms(
                    wire.class,
                    wire.cached_prefix_invalidation_tokens,
                    wire.context_reprime_tokens,
                    wire.runtime_startup_micros,
                    wire.lost_checkpoint_cost_micros,
                    wire.observation,
                )
            };
            if migrated.observation != wire.observation {
                return Err(de::Error::custom(
                    "legacy continue estimate must be measured zero evidence",
                ));
            }
            migrated
        } else if metadata_fields.iter().all(|present| *present) {
            Self {
                class: wire.class,
                cached_prefix_invalidation_tokens: wire.cached_prefix_invalidation_tokens,
                context_reprime_tokens: wire.context_reprime_tokens,
                runtime_startup_micros: wire.runtime_startup_micros,
                lost_checkpoint_cost_micros: wire.lost_checkpoint_cost_micros,
                total_cost_micros: wire.total_cost_micros,
                observation: wire.observation,
                status: wire.status.ok_or_else(|| {
                    de::Error::custom("switch-cost status metadata is incomplete")
                })?,
                sample_count: wire.sample_count.ok_or_else(|| {
                    de::Error::custom("switch-cost sample metadata is incomplete")
                })?,
                uncertainty_micros: wire.uncertainty_micros.ok_or_else(|| {
                    de::Error::custom("switch-cost uncertainty metadata is incomplete")
                })?,
                provenance: wire.provenance.ok_or_else(|| {
                    de::Error::custom("switch-cost provenance metadata is incomplete")
                })?,
            }
        } else {
            return Err(de::Error::custom(
                "switch-cost evidence metadata must be entirely present or entirely legacy",
            ));
        };
        if estimate.total_cost_micros != wire.total_cost_micros {
            return Err(de::Error::custom(
                "switch-cost total conflicts with its explicit components",
            ));
        }
        estimate.validate().map_err(de::Error::custom)?;
        Ok(estimate)
    }
}

impl SwitchCostEstimate {
    pub fn zero(class: TransitionClass) -> Self {
        let zero = SwitchComponentProvenance {
            source: SwitchEvidenceSource::ContinueZero,
            sample_count: 0,
            observation: ObservationKind::Measured,
            uncertainty: SwitchCostInterval::point(0),
        };
        Self::from_evidence(
            class,
            0,
            0,
            0,
            0,
            SwitchCostProvenance {
                cached_prefix_invalidation: zero.clone(),
                context_reprime: zero.clone(),
                runtime_startup: zero.clone(),
                lost_checkpoint: zero,
            },
        )
    }

    /// Price `S(a_prev → a)` from the four explicit terms. The scalar total is
    /// derived; callers must not invent a total that disagrees with the terms.
    pub fn from_explicit_terms(
        class: TransitionClass,
        cached_prefix_invalidation_tokens: i64,
        context_reprime_tokens: i64,
        runtime_startup_micros: i64,
        lost_checkpoint_cost_micros: i64,
        observation: ObservationKind,
    ) -> Self {
        let component = |value| SwitchComponentProvenance {
            source: match observation {
                ObservationKind::Measured => SwitchEvidenceSource::ExplicitObservation,
                ObservationKind::Inferred => SwitchEvidenceSource::ColdStartPrior,
            },
            sample_count: u32::from(observation == ObservationKind::Measured),
            observation,
            uncertainty: SwitchCostInterval::point(value),
        };
        Self::from_evidence(
            class,
            cached_prefix_invalidation_tokens,
            context_reprime_tokens,
            runtime_startup_micros,
            lost_checkpoint_cost_micros,
            SwitchCostProvenance {
                cached_prefix_invalidation: component(cached_prefix_invalidation_tokens),
                context_reprime: component(context_reprime_tokens),
                runtime_startup: component(runtime_startup_micros),
                lost_checkpoint: component(lost_checkpoint_cost_micros),
            },
        )
    }

    fn from_evidence(
        class: TransitionClass,
        cached_prefix_invalidation_tokens: i64,
        context_reprime_tokens: i64,
        runtime_startup_micros: i64,
        lost_checkpoint_cost_micros: i64,
        provenance: SwitchCostProvenance,
    ) -> Self {
        let components = [
            &provenance.cached_prefix_invalidation,
            &provenance.context_reprime,
            &provenance.runtime_startup,
            &provenance.lost_checkpoint,
        ];
        let measured = components
            .iter()
            .filter(|component| component.observation == ObservationKind::Measured)
            .count();
        let status = match measured {
            0 => SwitchEvidenceStatus::Inferred,
            4 => SwitchEvidenceStatus::Measured,
            _ => SwitchEvidenceStatus::Mixed,
        };
        let sample_count = components
            .iter()
            .map(|component| component.sample_count)
            .max()
            .unwrap_or(0);
        let uncertainty_micros = SwitchCostInterval {
            lower: token_cost_micros(provenance.cached_prefix_invalidation.uncertainty.lower)
                .saturating_add(token_cost_micros(
                    provenance.context_reprime.uncertainty.lower,
                ))
                .saturating_add(provenance.runtime_startup.uncertainty.lower)
                .saturating_add(provenance.lost_checkpoint.uncertainty.lower),
            upper: token_cost_micros(provenance.cached_prefix_invalidation.uncertainty.upper)
                .saturating_add(token_cost_micros(
                    provenance.context_reprime.uncertainty.upper,
                ))
                .saturating_add(provenance.runtime_startup.uncertainty.upper)
                .saturating_add(provenance.lost_checkpoint.uncertainty.upper),
        };
        let mut estimate = Self {
            class,
            cached_prefix_invalidation_tokens,
            context_reprime_tokens,
            runtime_startup_micros,
            lost_checkpoint_cost_micros,
            total_cost_micros: 0,
            observation: if status == SwitchEvidenceStatus::Measured {
                ObservationKind::Measured
            } else {
                ObservationKind::Inferred
            },
            status,
            sample_count,
            uncertainty_micros,
            provenance,
        };
        estimate.total_cost_micros = estimate.explicit_objective_term_micros();
        estimate
    }

    /// Validate component values, provenance, intervals, and every aggregate
    /// field duplicated for durable explanation/replay output.
    pub fn validate(&self) -> Result<(), OptimizerError> {
        let components = [
            (
                "cached_prefix_invalidation",
                self.cached_prefix_invalidation_tokens,
                &self.provenance.cached_prefix_invalidation,
            ),
            (
                "context_reprime",
                self.context_reprime_tokens,
                &self.provenance.context_reprime,
            ),
            (
                "runtime_startup",
                self.runtime_startup_micros,
                &self.provenance.runtime_startup,
            ),
            (
                "lost_checkpoint",
                self.lost_checkpoint_cost_micros,
                &self.provenance.lost_checkpoint,
            ),
        ];
        for (name, value, provenance) in components {
            if value < 0 {
                return Err(OptimizerError::invalid(format!(
                    "switch-cost component {name} is negative"
                )));
            }
            if provenance.uncertainty.lower < 0
                || provenance.uncertainty.upper < provenance.uncertainty.lower
                || value < provenance.uncertainty.lower
                || value > provenance.uncertainty.upper
            {
                return Err(OptimizerError::invalid(format!(
                    "switch-cost component {name} has an invalid uncertainty interval"
                )));
            }
            let provenance_valid = match provenance.source {
                SwitchEvidenceSource::ContinueZero => {
                    self.class == TransitionClass::Continue
                        && value == 0
                        && provenance.sample_count == 0
                        && provenance.observation == ObservationKind::Measured
                }
                SwitchEvidenceSource::ExplicitObservation
                | SwitchEvidenceSource::ExactTransitionTelemetry
                | SwitchEvidenceSource::ClassTelemetry => {
                    provenance.sample_count > 0
                        && provenance.observation == ObservationKind::Measured
                }
                SwitchEvidenceSource::GlobalTelemetry => {
                    provenance.sample_count > 0
                        && provenance.observation == ObservationKind::Inferred
                }
                SwitchEvidenceSource::ColdStartPrior => {
                    provenance.sample_count == 0
                        && provenance.observation == ObservationKind::Inferred
                }
                SwitchEvidenceSource::LegacyUnknown => false,
            };
            if !provenance_valid {
                return Err(OptimizerError::invalid(format!(
                    "switch-cost component {name} has conflicting provenance"
                )));
            }
        }
        if self.class == TransitionClass::Continue && self.explicit_objective_term_micros() != 0 {
            return Err(OptimizerError::invalid(
                "continue transition must have zero switch cost",
            ));
        }
        let derived = Self::from_evidence(
            self.class,
            self.cached_prefix_invalidation_tokens,
            self.context_reprime_tokens,
            self.runtime_startup_micros,
            self.lost_checkpoint_cost_micros,
            self.provenance.clone(),
        );
        if self.total_cost_micros != derived.total_cost_micros
            || self.observation != derived.observation
            || self.status != derived.status
            || self.sample_count != derived.sample_count
            || self.uncertainty_micros != derived.uncertainty_micros
        {
            return Err(OptimizerError::invalid(
                "switch-cost aggregate fields conflict with component evidence",
            ));
        }
        Ok(())
    }

    /// Cache invalidation + re-priming + startup + lost checkpoint.
    /// This is the routing-objective term; [`Self::total_cost_micros`] mirrors it.
    pub fn explicit_objective_term_micros(&self) -> i64 {
        token_cost_micros(self.cached_prefix_invalidation_tokens)
            .saturating_add(token_cost_micros(self.context_reprime_tokens))
            .saturating_add(self.runtime_startup_micros)
            .saturating_add(self.lost_checkpoint_cost_micros)
    }

    /// Cost actually licensed for a decision. Inferred components remain
    /// visible as raw evidence but are excluded unless the caller explicitly
    /// enables cold-start priors.
    pub fn applied_objective_term_micros(&self, include_inferred: bool) -> i64 {
        let include = |provenance: &SwitchComponentProvenance| {
            include_inferred || provenance.observation == ObservationKind::Measured
        };
        let cache = if include(&self.provenance.cached_prefix_invalidation) {
            token_cost_micros(self.cached_prefix_invalidation_tokens)
        } else {
            0
        };
        let reprime = if include(&self.provenance.context_reprime) {
            token_cost_micros(self.context_reprime_tokens)
        } else {
            0
        };
        let startup = if include(&self.provenance.runtime_startup) {
            self.runtime_startup_micros
        } else {
            0
        };
        let checkpoint = if include(&self.provenance.lost_checkpoint) {
            self.lost_checkpoint_cost_micros
        } else {
            0
        };
        cache
            .saturating_add(reprime)
            .saturating_add(startup)
            .saturating_add(checkpoint)
    }

    /// Per-resource-dimension view (#162). Token terms stay on `api_cost_usd`;
    /// process warmup and lost checkpoint stay on `local_compute_seconds`.
    pub fn cost_by_dimension(&self) -> BTreeMap<ResourceDimensionId, i64> {
        let mut costs = BTreeMap::new();
        let token = token_cost_micros(self.cached_prefix_invalidation_tokens)
            .saturating_add(token_cost_micros(self.context_reprime_tokens));
        if token != 0 {
            costs.insert(
                ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
                token,
            );
        }
        let runtime = self
            .runtime_startup_micros
            .saturating_add(self.lost_checkpoint_cost_micros);
        if runtime != 0 {
            costs.insert(
                ResourceDimensionId::well_known(ResourceDimensionId::LOCAL_COMPUTE_SECONDS),
                runtime,
            );
        }
        costs
    }

    pub fn observation_label(&self) -> &'static str {
        match self.status {
            SwitchEvidenceStatus::Measured => "measured",
            SwitchEvidenceStatus::Mixed => "mixed",
            SwitchEvidenceStatus::Inferred => "inferred",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchHysteresis {
    pub margin_bp: u16,
}

impl Default for SwitchHysteresis {
    fn default() -> Self {
        Self {
            margin_bp: DEFAULT_HYSTERESIS_BP,
        }
    }
}

impl SwitchHysteresis {
    pub fn priced_switch_cost(self, switch_cost_micros: i64) -> i64 {
        switch_cost_micros.saturating_mul(i64::from(10_000u16.saturating_add(self.margin_bp)))
            / 10_000
    }

    pub fn should_switch(self, predicted_improvement_micros: i64, switch_cost_micros: i64) -> bool {
        predicted_improvement_micros > self.priced_switch_cost(switch_cost_micros)
    }
}

/// Hierarchical per-class switch costs fitted from #159 cache-token fields.
///
/// Cache-prefix invalidation, context re-priming, startup, and checkpoint loss
/// retain separate exact-transition, class, and global cells. Cold-start
/// samples are used only when no telemetry exists at any level.
#[derive(Debug, Clone, Default)]
pub struct SwitchCostModel {
    cache_invalidation: BTreeMap<TransitionClass, SampleCell>,
    reprime: BTreeMap<TransitionClass, SampleCell>,
    startup: BTreeMap<TransitionClass, SampleCell>,
    checkpoint: BTreeMap<TransitionClass, SampleCell>,
    exact_cache_invalidation: BTreeMap<TransitionIdentity, SampleCell>,
    exact_reprime: BTreeMap<TransitionIdentity, SampleCell>,
    exact_startup: BTreeMap<TransitionIdentity, SampleCell>,
    exact_checkpoint: BTreeMap<TransitionIdentity, SampleCell>,
    global_cache_invalidation: SampleCell,
    global_reprime: SampleCell,
    global_startup: SampleCell,
    global_checkpoint: SampleCell,
    hit_ratio_bp: BTreeMap<TransitionClass, SampleCell>,
    hysteresis: SwitchHysteresis,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TransitionIdentity {
    class: TransitionClass,
    from_backend: String,
    from_model: String,
    to_backend: String,
    to_model: String,
}

impl SwitchCostModel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_hysteresis(mut self, hysteresis: SwitchHysteresis) -> Self {
        self.hysteresis = hysteresis;
        self
    }

    pub fn hysteresis(&self) -> SwitchHysteresis {
        self.hysteresis
    }

    pub fn observe(
        &mut self,
        class: TransitionClass,
        cached_miss_tokens: i64,
        reprime_tokens: i64,
        startup_micros: i64,
        lost_checkpoint_micros: i64,
    ) {
        self.observe_components(
            class,
            None,
            Some(cached_miss_tokens),
            Some(reprime_tokens),
            Some(startup_micros),
            Some(lost_checkpoint_micros),
        );
    }

    fn observe_components(
        &mut self,
        class: TransitionClass,
        identity: Option<TransitionIdentity>,
        cache_invalidation: Option<i64>,
        reprime: Option<i64>,
        startup: Option<i64>,
        checkpoint: Option<i64>,
    ) {
        if [cache_invalidation, reprime, startup, checkpoint]
            .into_iter()
            .flatten()
            .any(|value| value < 0)
        {
            return;
        }
        observe_component(
            &mut self.cache_invalidation,
            &mut self.exact_cache_invalidation,
            &mut self.global_cache_invalidation,
            class,
            identity.as_ref(),
            cache_invalidation,
        );
        observe_component(
            &mut self.reprime,
            &mut self.exact_reprime,
            &mut self.global_reprime,
            class,
            identity.as_ref(),
            reprime,
        );
        observe_component(
            &mut self.startup,
            &mut self.exact_startup,
            &mut self.global_startup,
            class,
            identity.as_ref(),
            startup,
        );
        observe_component(
            &mut self.checkpoint,
            &mut self.exact_checkpoint,
            &mut self.global_checkpoint,
            class,
            identity.as_ref(),
            checkpoint,
        );
    }

    /// Fit cache-invalidation / re-priming terms from #159 invocation records.
    /// Records missing `input_tokens` or `cached_input_tokens` are skipped
    /// rather than zero-filled.
    pub fn observe_invocations(&mut self, records: &[InvocationRecord]) {
        let mut groups: BTreeMap<String, Vec<&InvocationRecord>> = BTreeMap::new();
        for record in records {
            groups
                .entry(trajectory_key(record))
                .or_default()
                .push(record);
        }
        for group in groups.values_mut() {
            group.sort_by_key(|record| record.started_at.as_millis());
            let mut previous = None;
            for next in group.iter().copied() {
                self.observe_invocation_transition(previous, next);
                previous = Some(next);
            }
        }
    }

    pub fn observe_invocation_transition(
        &mut self,
        previous: Option<&InvocationRecord>,
        next: &InvocationRecord,
    ) {
        let Some(class) = classify_invocation_transition(previous, next) else {
            return;
        };
        if let (Some(input), Some(cached)) = (next.input_tokens, next.cached_input_tokens) {
            if input > 0 {
                let cached = cached.min(input);
                let hit_bp =
                    i64::try_from(u128::from(cached).saturating_mul(10_000) / u128::from(input))
                        .unwrap_or(10_000);
                self.hit_ratio_bp.entry(class).or_default().observe(hit_bp);
            }
        }
        if !class.is_switch() {
            return;
        }
        let token_terms = next
            .input_tokens
            .zip(next.cached_input_tokens)
            .map(|(input, cached)| {
                let reprime = tokens_i64(input.saturating_sub(cached.min(input)));
                let invalidation = previous
                    .and_then(|record| record.cached_input_tokens)
                    .map(tokens_i64);
                (invalidation, Some(reprime))
            });
        let (invalidation, reprime) = token_terms.unwrap_or((None, None));
        self.observe_components(
            class,
            invocation_transition_identity(previous, next, class),
            invalidation,
            reprime,
            next.runtime_startup_micros,
            next.lost_checkpoint_cost_micros,
        );
    }

    pub fn cache_hit_ratio_bp(&self, class: TransitionClass) -> Option<(u16, ObservationKind)> {
        let cell = self.hit_ratio_bp.get(&class)?;
        if cell.samples.is_empty() {
            return None;
        }
        let mean = super::predictor::mean_i64(&cell.samples).clamp(0, 10_000) as u16;
        let kind = if cell.observations == 0 {
            ObservationKind::Inferred
        } else {
            ObservationKind::Measured
        };
        Some((mean, kind))
    }

    pub fn estimate(&self, class: TransitionClass) -> SwitchCostEstimate {
        if class == TransitionClass::Continue {
            return SwitchCostEstimate::zero(class);
        }
        self.estimate_with_identity(class, None)
    }

    pub fn estimate_invocation_transition(
        &self,
        previous: Option<&InvocationRecord>,
        next: &InvocationRecord,
    ) -> Option<SwitchCostEstimate> {
        let class = classify_invocation_transition(previous, next)?;
        if class == TransitionClass::Continue {
            return Some(SwitchCostEstimate::zero(class));
        }
        Some(self.estimate_with_identity(
            class,
            invocation_transition_identity(previous, next, class).as_ref(),
        ))
    }

    fn estimate_with_identity(
        &self,
        class: TransitionClass,
        identity: Option<&TransitionIdentity>,
    ) -> SwitchCostEstimate {
        let cache = component_estimate(
            class,
            identity,
            &self.cache_invalidation,
            &self.exact_cache_invalidation,
            &self.global_cache_invalidation,
            PriorComponent::CacheInvalidation,
        );
        let reprime = component_estimate(
            class,
            identity,
            &self.reprime,
            &self.exact_reprime,
            &self.global_reprime,
            PriorComponent::Reprime,
        );
        let startup = component_estimate(
            class,
            identity,
            &self.startup,
            &self.exact_startup,
            &self.global_startup,
            PriorComponent::Startup,
        );
        let checkpoint = component_estimate(
            class,
            identity,
            &self.checkpoint,
            &self.exact_checkpoint,
            &self.global_checkpoint,
            PriorComponent::Checkpoint,
        );
        SwitchCostEstimate::from_evidence(
            class,
            cache.0,
            reprime.0,
            startup.0,
            checkpoint.0,
            SwitchCostProvenance {
                cached_prefix_invalidation: cache.1,
                context_reprime: reprime.1,
                runtime_startup: startup.1,
                lost_checkpoint: checkpoint.1,
            },
        )
    }
}

/// Classify consecutive #159 records. Incomplete identity is not guessed.
pub fn classify_invocation_transition(
    previous: Option<&InvocationRecord>,
    next: &InvocationRecord,
) -> Option<TransitionClass> {
    let Some(prev) = previous else {
        if next.backend.is_some() || next.resolved_model.is_some() {
            return Some(TransitionClass::FreshSessionOrWorktree);
        }
        return None;
    };
    let session_changed = prev
        .session_id
        .as_ref()
        .zip(next.session_id.as_ref())
        .is_some_and(|(previous, current)| previous != current);
    let worktree_changed = prev
        .worktree_id
        .as_ref()
        .zip(next.worktree_id.as_ref())
        .is_some_and(|(previous, current)| previous != current);
    if session_changed || worktree_changed {
        return Some(TransitionClass::FreshSessionOrWorktree);
    }
    match (
        prev.backend.as_ref(),
        next.backend.as_ref(),
        prev.resolved_model.as_ref(),
        next.resolved_model.as_ref(),
    ) {
        (Some(prev_backend), Some(next_backend), Some(prev_model), Some(next_model)) => {
            Some(if prev_backend != next_backend {
                TransitionClass::RuntimeAdapterChange
            } else if prev_model != next_model {
                TransitionClass::ModelChangeSameRuntime
            } else {
                TransitionClass::Continue
            })
        }
        _ => None,
    }
}

/// Resolve the currently active action from the candidate set when the
/// caller supplies the live policy id as a feature.
pub fn current_action_from_candidates<'a>(
    state: &OptimizerState,
    candidates: &'a [PolicyGraph],
) -> Option<&'a ModelAction> {
    let current_id = feature_text(&state.task_features, feature_keys::CURRENT_POLICY);
    current_id
        .as_deref()
        .and_then(|id| {
            candidates
                .iter()
                .find(|policy| policy.policy_id.as_str() == id)
        })
        .and_then(primary_action)
        .or_else(|| {
            state
                .trajectory
                .events()
                .last()
                .and_then(|event| {
                    candidates
                        .iter()
                        .find(|policy| policy.policy_id == event.policy_id)
                })
                .and_then(primary_action)
        })
}

pub fn estimate_switch(
    model: &SwitchCostModel,
    previous: Option<&ModelAction>,
    policy: &PolicyGraph,
) -> SwitchCostEstimate {
    let class = classify_transition(previous, primary_action(policy), policy.topology.restart);
    if class == TransitionClass::Continue {
        return SwitchCostEstimate::zero(class);
    }
    let identity = action_transition_identity(previous, primary_action(policy), class);
    model.estimate_with_identity(class, identity.as_ref())
}

/// Objective wrapper that adds `S(a_prev -> a)` after the inner evaluator.
pub struct SwitchAwareObjective {
    inner: Box<dyn ObjectiveEvaluator + Send + Sync>,
    switch: SwitchCostEstimate,
}

impl SwitchAwareObjective {
    pub fn new(
        inner: Box<dyn ObjectiveEvaluator + Send + Sync>,
        switch: SwitchCostEstimate,
    ) -> Self {
        Self { inner, switch }
    }
}

impl ObjectiveEvaluator for SwitchAwareObjective {
    fn evaluate(
        &self,
        distribution: &super::predictor::PolicyOutcomeDistribution,
    ) -> Result<ObjectiveValue, OptimizerError> {
        let mut value = self.inner.evaluate(distribution)?;
        value.risk_adjusted_cost_micros = value
            .risk_adjusted_cost_micros
            .saturating_add(self.switch.explicit_objective_term_micros());
        Ok(value)
    }
}

pub fn apply_switch_cost(
    value: &mut ObjectiveValue,
    estimate: &SwitchCostEstimate,
    hysteresis: SwitchHysteresis,
    include_inferred: bool,
) -> i64 {
    let applied =
        hysteresis.priced_switch_cost(estimate.applied_objective_term_micros(include_inferred));
    value.risk_adjusted_cost_micros = value.risk_adjusted_cost_micros.saturating_add(applied);
    applied
}

/// Replay cannot reconstruct cache state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySwitchEstimate {
    pub label: String,
    pub uncorrected: bool,
    pub replay_cost_micros: i64,
    pub correction_milli: Option<i64>,
    pub corrected_cost_micros: Option<i64>,
    #[serde(default)]
    pub correction_provenance: Option<String>,
    #[serde(default)]
    pub correction_sample_count: u32,
    #[serde(default)]
    pub correction_uncertainty_milli: Option<SwitchCostInterval>,
    #[serde(default)]
    pub correction_observation: Option<ObservationKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayCorrectionEvidence {
    pub correction_milli: i64,
    pub sample_count: u32,
    pub uncertainty_milli: SwitchCostInterval,
    pub provenance: String,
    pub observation: ObservationKind,
}

impl ReplayCorrectionEvidence {
    pub fn measured(
        correction_milli: i64,
        sample_count: u32,
        lower_milli: i64,
        upper_milli: i64,
        provenance: impl Into<String>,
    ) -> Self {
        let correction_milli = correction_milli.max(1);
        Self {
            correction_milli,
            sample_count,
            uncertainty_milli: SwitchCostInterval {
                lower: lower_milli.min(correction_milli).max(1),
                upper: upper_milli.max(correction_milli),
            },
            provenance: provenance.into(),
            observation: ObservationKind::Measured,
        }
    }
}

impl ReplaySwitchEstimate {
    pub fn from_replay(replay_cost_micros: i64) -> Self {
        Self {
            label: REPLAY_UNCORRECTED_LABEL.to_string(),
            uncorrected: true,
            replay_cost_micros,
            correction_milli: None,
            corrected_cost_micros: None,
            correction_provenance: None,
            correction_sample_count: 0,
            correction_uncertainty_milli: None,
            correction_observation: None,
        }
    }

    pub fn with_measured_correction(
        replay_cost_micros: i64,
        evidence: ReplayCorrectionEvidence,
    ) -> Self {
        let corrected_cost_micros =
            replay_cost_micros.saturating_mul(evidence.correction_milli) / 1_000;
        Self {
            label: "switch-cost-corrected".to_string(),
            uncorrected: false,
            replay_cost_micros,
            correction_milli: Some(evidence.correction_milli),
            corrected_cost_micros: Some(corrected_cost_micros),
            correction_provenance: Some(evidence.provenance),
            correction_sample_count: evidence.sample_count,
            correction_uncertainty_milli: Some(evidence.uncertainty_milli),
            correction_observation: Some(evidence.observation),
        }
    }

    pub fn has_measured_correction(&self) -> bool {
        let Some(correction_milli) = self.correction_milli else {
            return false;
        };
        let Some(corrected_cost_micros) = self.corrected_cost_micros else {
            return false;
        };
        let Some(uncertainty) = self.correction_uncertainty_milli else {
            return false;
        };
        !self.uncorrected
            && self.label == "switch-cost-corrected"
            && self.replay_cost_micros >= 0
            && correction_milli > 0
            && uncertainty.lower > 0
            && uncertainty.upper >= uncertainty.lower
            && correction_milli >= uncertainty.lower
            && correction_milli <= uncertainty.upper
            && corrected_cost_micros
                == self.replay_cost_micros.saturating_mul(correction_milli) / 1_000
            && self.correction_sample_count > 0
            && self.correction_observation == Some(ObservationKind::Measured)
            && self
                .correction_provenance
                .as_deref()
                .is_some_and(|provenance| !provenance.trim().is_empty())
    }

    /// Safe-set promotion must not rest on an uncorrected offline estimate or
    /// on a gain that the measured correction (including its upper interval)
    /// overturns.
    pub fn may_promote(&self, predicted_gain_micros: i64) -> bool {
        if !self.has_measured_correction() {
            return false;
        }
        let upper_correction = self
            .correction_uncertainty_milli
            .map(|interval| interval.upper)
            .or(self.correction_milli)
            .unwrap_or(i64::MAX);
        let corrected_upper = self.replay_cost_micros.saturating_mul(upper_correction) / 1_000;
        predicted_gain_micros > corrected_upper
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscillationTracker {
    pub sequence: Vec<String>,
    pub alarm_threshold: u32,
}

impl OscillationTracker {
    pub fn new(alarm_threshold: u32) -> Self {
        Self {
            sequence: Vec::new(),
            alarm_threshold,
        }
    }

    pub fn push(&mut self, identity: impl Into<String>) {
        self.sequence.push(identity.into());
    }

    pub fn count(&self) -> u32 {
        oscillation_count(&self.sequence)
    }

    pub fn alarmed(&self) -> bool {
        self.count() >= self.alarm_threshold.max(1)
    }
}

pub fn oscillation_count(sequence: &[String]) -> u32 {
    sequence
        .windows(3)
        .filter(|window| window[0] == window[2] && window[0] != window[1])
        .count() as u32
}

pub fn identity_of(action: &ModelAction) -> String {
    format!(
        "{}:{}",
        action.backend_id, action.runtime_model.runtime_slug
    )
}

const TOKEN_MICROS: i64 = 50;

fn token_cost_micros(tokens: i64) -> i64 {
    tokens.saturating_mul(TOKEN_MICROS)
}

fn tokens_i64(tokens: u64) -> i64 {
    i64::try_from(tokens).unwrap_or(i64::MAX)
}

#[derive(Debug, Clone, Copy)]
enum PriorComponent {
    CacheInvalidation,
    Reprime,
    Startup,
    Checkpoint,
}

fn observe_component(
    class_cells: &mut BTreeMap<TransitionClass, SampleCell>,
    exact_cells: &mut BTreeMap<TransitionIdentity, SampleCell>,
    global_cell: &mut SampleCell,
    class: TransitionClass,
    identity: Option<&TransitionIdentity>,
    value: Option<i64>,
) {
    let Some(value) = value else {
        return;
    };
    class_cells.entry(class).or_default().observe(value);
    if let Some(identity) = identity {
        exact_cells
            .entry(identity.clone())
            .or_default()
            .observe(value);
    }
    global_cell.observe(value);
}

fn component_estimate(
    class: TransitionClass,
    identity: Option<&TransitionIdentity>,
    class_cells: &BTreeMap<TransitionClass, SampleCell>,
    exact_cells: &BTreeMap<TransitionIdentity, SampleCell>,
    global_cell: &SampleCell,
    prior_component: PriorComponent,
) -> (i64, SwitchComponentProvenance) {
    if let Some(cell) = identity
        .and_then(|identity| exact_cells.get(identity))
        .filter(|cell| cell.observations > 0 && !cell.samples.is_empty())
    {
        return component_from_cell(
            cell,
            SwitchEvidenceSource::ExactTransitionTelemetry,
            ObservationKind::Measured,
        );
    }
    if let Some(cell) = class_cells
        .get(&class)
        .filter(|cell| cell.observations > 0 && !cell.samples.is_empty())
    {
        return component_from_cell(
            cell,
            SwitchEvidenceSource::ClassTelemetry,
            ObservationKind::Measured,
        );
    }
    if global_cell.observations > 0 && !global_cell.samples.is_empty() {
        let mut pooled = prior_component_samples(class, prior_component);
        pooled.extend(global_cell.samples.iter().copied());
        let value = super::predictor::mean_i64(&pooled);
        return (
            value,
            SwitchComponentProvenance {
                source: SwitchEvidenceSource::GlobalTelemetry,
                sample_count: global_cell.observations,
                observation: ObservationKind::Inferred,
                uncertainty: SwitchCostInterval {
                    lower: pooled.iter().copied().min().unwrap_or(value),
                    upper: pooled.iter().copied().max().unwrap_or(value),
                },
            },
        );
    }
    let samples = prior_component_samples(class, prior_component);
    let value = super::predictor::mean_i64(&samples);
    let lower = samples.iter().copied().min().unwrap_or(value);
    let upper = samples.iter().copied().max().unwrap_or(value);
    (
        value,
        SwitchComponentProvenance {
            source: SwitchEvidenceSource::ColdStartPrior,
            sample_count: 0,
            observation: ObservationKind::Inferred,
            uncertainty: SwitchCostInterval { lower, upper },
        },
    )
}

fn component_from_cell(
    cell: &SampleCell,
    source: SwitchEvidenceSource,
    observation: ObservationKind,
) -> (i64, SwitchComponentProvenance) {
    let value = super::predictor::mean_i64(&cell.samples);
    (
        value,
        SwitchComponentProvenance {
            source,
            sample_count: cell.observations,
            observation,
            uncertainty: SwitchCostInterval {
                lower: cell.samples.iter().copied().min().unwrap_or(value),
                upper: cell.samples.iter().copied().max().unwrap_or(value),
            },
        },
    )
}

fn prior_component_samples(class: TransitionClass, component: PriorComponent) -> Vec<i64> {
    let totals = match class {
        TransitionClass::Continue => vec![0],
        TransitionClass::ModelChangeSameRuntime => wide_model_switch_prior(),
        TransitionClass::RuntimeAdapterChange => wide_runtime_switch_prior(),
        TransitionClass::FreshSessionOrWorktree => wide_fresh_session_prior(),
    };
    totals
        .into_iter()
        .map(|total| {
            let (cache, reprime, startup, checkpoint) = split_components(class, total);
            match component {
                PriorComponent::CacheInvalidation => cache / TOKEN_MICROS,
                PriorComponent::Reprime => reprime / TOKEN_MICROS,
                PriorComponent::Startup => startup,
                PriorComponent::Checkpoint => checkpoint,
            }
        })
        .collect()
}

fn invocation_transition_identity(
    previous: Option<&InvocationRecord>,
    next: &InvocationRecord,
    class: TransitionClass,
) -> Option<TransitionIdentity> {
    let previous = previous?;
    Some(TransitionIdentity {
        class,
        from_backend: previous.backend.as_ref()?.to_string(),
        from_model: previous.resolved_model.as_ref()?.to_string(),
        to_backend: next.backend.as_ref()?.to_string(),
        to_model: next.resolved_model.as_ref()?.to_string(),
    })
}

fn action_transition_identity(
    previous: Option<&ModelAction>,
    next: Option<&ModelAction>,
    class: TransitionClass,
) -> Option<TransitionIdentity> {
    let previous = previous?;
    let next = next?;
    Some(TransitionIdentity {
        class,
        from_backend: previous.backend_id.to_string(),
        from_model: previous.runtime_model.runtime_slug.to_string(),
        to_backend: next.backend_id.to_string(),
        to_model: next.runtime_model.runtime_slug.to_string(),
    })
}

fn trajectory_key(record: &InvocationRecord) -> String {
    if let Some(execution) = &record.policy_execution_id {
        return format!("exec:{}", execution.as_str());
    }
    if let Some(run) = &record.optimization_run_id {
        return format!("run:{}", run.as_str());
    }
    format!("row:{}", record.started_at.as_millis())
}

fn split_components(class: TransitionClass, total: i64) -> (i64, i64, i64, i64) {
    match class {
        TransitionClass::Continue => (0, 0, 0, 0),
        TransitionClass::ModelChangeSameRuntime => {
            (total * 4 / 10, total * 4 / 10, total / 10, total / 10)
        }
        TransitionClass::RuntimeAdapterChange => {
            (total * 3 / 10, total * 3 / 10, total * 3 / 10, total / 10)
        }
        TransitionClass::FreshSessionOrWorktree => (total / 5, total * 2 / 5, total / 5, total / 5),
    }
}

fn wide_model_switch_prior() -> Vec<i64> {
    vec![80_000, 120_000, 200_000, 350_000, 500_000]
}

fn wide_runtime_switch_prior() -> Vec<i64> {
    vec![400_000, 800_000, 1_500_000, 3_000_000, 6_000_000]
}

fn wide_fresh_session_prior() -> Vec<i64> {
    vec![2_000_000, 5_000_000, 10_000_000, 20_000_000, 40_000_000]
}

/// Durable policy identities from the trajectory itself. Candidate graphs are
/// intentionally not consulted: a historical A/B/A oscillation must survive
/// eviction of A or B from the current candidate set.
pub fn trajectory_policy_identities(state: &OptimizerState) -> Vec<String> {
    state
        .trajectory
        .events()
        .iter()
        .map(|event| event.policy_id.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::{
        AgentRole, CanonicalEffort, ExecutionBudget, HedgeTopology, PlannerTopology,
        ReviewTopology, RuntimeModelId, TopologySpec, WorkerTopology,
    };
    use crate::optimizer::features::TrajectoryFeatures;
    use crate::optimizer::ids::{
        BackendId, CandidateId, CatalogVersion, ModelFamilyId, PolicyId, PolicyNodeId, ProviderId,
        RuntimeSlug, TimestampMillis, VerifierProfileId,
    };
    use crate::optimizer::policy::PolicyNode;
    use crate::optimizer::predictor::{insert_text, PolicyOutcomeDistribution};
    use crate::optimizer::resources::ResourceVector;
    use crate::optimizer::state::DecisionHorizon;
    use crate::optimizer::telemetry::{InvocationId, PolicyExecutionId};
    use crate::optimizer::trajectory::{TrajectoryEvent, TrajectoryObservation};

    fn action(backend: &str, slug: &str) -> ModelAction {
        ModelAction {
            backend_id: BackendId::new(backend).expect("backend"),
            provider_id: ProviderId::new("local").expect("provider"),
            runtime_model: RuntimeModelId {
                provider: ProviderId::new("local").expect("provider"),
                backend: BackendId::new(backend).expect("backend"),
                model_family: ModelFamilyId::new("family").expect("family"),
                runtime_slug: RuntimeSlug::new(slug).expect("slug"),
                catalog_version: CatalogVersion::new("v1").expect("cat"),
                observation_timestamp: TimestampMillis::from_millis(1),
            },
            requested_slug: RuntimeSlug::new(slug).expect("slug"),
            effort: CanonicalEffort::Low,
            role: AgentRole::Worker,
            max_turns: ExecutionBudget::default().max_turns,
            timeout_seconds: 60,
            tool_budget: None,
            output_token_budget: None,
            concurrency: 1,
            verifier_profile: VerifierProfileId::new("default").expect("profile"),
        }
    }

    fn graph(id: &str, backend: &str, slug: &str, restart: RestartMode) -> PolicyGraph {
        let start = PolicyNodeId::new("start").expect("node");
        let mut graph = PolicyGraph::new(
            PolicyId::new(id).expect("policy"),
            1,
            start.clone(),
            TopologySpec {
                planner: PlannerTopology::Single,
                workers: WorkerTopology::One,
                hedge: HedgeTopology::None,
                review: ReviewTopology::Independent,
                restart,
            },
        );
        graph
            .insert_node(start, PolicyNode::Execute(action(backend, slug)))
            .expect("node");
        graph
    }

    #[test]
    fn unobserved_transition_uses_wide_prior_and_is_inferred() {
        let model = SwitchCostModel::new();
        let estimate = model.estimate(TransitionClass::ModelChangeSameRuntime);
        assert_eq!(estimate.observation, ObservationKind::Inferred);
        assert!(estimate.total_cost_micros > 0);
        let fresh = model.estimate(TransitionClass::FreshSessionOrWorktree);
        let runtime = model.estimate(TransitionClass::RuntimeAdapterChange);
        assert!(fresh.total_cost_micros > runtime.total_cost_micros);
        assert!(runtime.total_cost_micros > estimate.total_cost_micros);
        assert_eq!(
            model.estimate(TransitionClass::Continue).total_cost_micros,
            0
        );
        assert_eq!(
            estimate.total_cost_micros,
            estimate.explicit_objective_term_micros()
        );
        assert!(estimate.cached_prefix_invalidation_tokens > 0);
        assert!(estimate.context_reprime_tokens > 0);
    }

    #[test]
    fn canonical_evidence_exposes_component_provenance_samples_and_wide_interval() {
        let model = SwitchCostModel::new();
        let estimate = model.estimate(TransitionClass::RuntimeAdapterChange);

        assert_eq!(estimate.status, SwitchEvidenceStatus::Inferred);
        assert_eq!(estimate.sample_count, 0);
        assert_eq!(
            estimate.provenance.cached_prefix_invalidation.source,
            SwitchEvidenceSource::ColdStartPrior
        );
        assert_eq!(
            estimate.provenance.context_reprime.source,
            SwitchEvidenceSource::ColdStartPrior
        );
        assert_eq!(
            estimate.provenance.runtime_startup.source,
            SwitchEvidenceSource::ColdStartPrior
        );
        assert_eq!(
            estimate.provenance.lost_checkpoint.source,
            SwitchEvidenceSource::ColdStartPrior
        );
        assert!(estimate.uncertainty_micros.lower < estimate.total_cost_micros);
        assert!(estimate.uncertainty_micros.upper > estimate.total_cost_micros);
    }

    #[test]
    fn measured_observations_narrow_the_prior() {
        let mut model = SwitchCostModel::new();
        let before = model
            .estimate(TransitionClass::ModelChangeSameRuntime)
            .total_cost_micros;
        for _ in 0..20 {
            model.observe(TransitionClass::ModelChangeSameRuntime, 10, 10, 1, 1);
        }
        let after = model.estimate(TransitionClass::ModelChangeSameRuntime);
        assert_eq!(after.observation, ObservationKind::Measured);
        assert!(after.total_cost_micros < before);
        assert_eq!(after.cached_prefix_invalidation_tokens, 10);
        assert_eq!(after.context_reprime_tokens, 10);
        assert_eq!(
            after.total_cost_micros,
            after.explicit_objective_term_micros()
        );
    }

    #[test]
    fn legacy_measured_estimate_deserializes_without_losing_applied_cost() {
        let legacy = serde_json::json!({
            "class": "model_change_same_runtime",
            "cached_prefix_invalidation_tokens": 10,
            "context_reprime_tokens": 20,
            "runtime_startup_micros": 30,
            "lost_checkpoint_cost_micros": 40,
            "total_cost_micros": 1_570,
            "observation": "Measured"
        });
        let estimate: SwitchCostEstimate =
            serde_json::from_value(legacy).expect("safe legacy migration");
        assert_eq!(estimate.status, SwitchEvidenceStatus::Measured);
        assert_eq!(estimate.applied_objective_term_micros(false), 1_570);
        assert_eq!(
            estimate.provenance.cached_prefix_invalidation.source,
            SwitchEvidenceSource::ExplicitObservation
        );
    }

    #[test]
    fn deserialization_rejects_conflicting_derived_switch_cost_fields() {
        let estimate = SwitchCostEstimate::from_explicit_terms(
            TransitionClass::RuntimeAdapterChange,
            10,
            20,
            30,
            40,
            ObservationKind::Measured,
        );
        let canonical = serde_json::to_value(estimate).expect("serialize");

        let mut wrong_total = canonical.clone();
        wrong_total["total_cost_micros"] = serde_json::json!(999_999);
        let mut wrong_status = canonical.clone();
        wrong_status["status"] = serde_json::json!("inferred");
        let mut wrong_provenance = canonical.clone();
        wrong_provenance["provenance"]["cached_prefix_invalidation"]["source"] =
            serde_json::json!("cold_start_prior");
        let mut wrong_component_interval = canonical.clone();
        wrong_component_interval["provenance"]["context_reprime"]["uncertainty"]["lower"] =
            serde_json::json!(-1);
        let mut wrong_aggregate_interval = canonical;
        wrong_aggregate_interval["uncertainty_micros"]["upper"] = serde_json::json!(1);

        for conflicting in [
            wrong_total,
            wrong_status,
            wrong_provenance,
            wrong_component_interval,
            wrong_aggregate_interval,
        ] {
            assert!(serde_json::from_value::<SwitchCostEstimate>(conflicting).is_err());
        }
    }

    #[test]
    fn negative_observation_components_do_not_poison_the_model() {
        let mut model = SwitchCostModel::new();
        let before = model.estimate(TransitionClass::ModelChangeSameRuntime);
        model.observe(TransitionClass::ModelChangeSameRuntime, -1, 10, 10, 10);
        assert_eq!(
            model.estimate(TransitionClass::ModelChangeSameRuntime),
            before
        );
    }

    #[test]
    fn replay_only_estimate_is_uncorrected_and_cannot_promote() {
        let estimate = ReplaySwitchEstimate::from_replay(1_000);
        assert!(estimate.uncorrected);
        assert_eq!(estimate.label, REPLAY_UNCORRECTED_LABEL);
        assert!(!estimate.may_promote(10_000));
        let corrected = ReplaySwitchEstimate::with_measured_correction(
            1_000,
            ReplayCorrectionEvidence::measured(2_500, 10, 2_000, 3_000, "shadow"),
        );
        assert!(!corrected.uncorrected);
        assert!(corrected.may_promote(3_001));
        assert!(!corrected.may_promote(3_000));
        assert_eq!(corrected.corrected_cost_micros, Some(2_500));
    }

    #[test]
    fn oscillation_a_b_a_is_observable() {
        let mut tracker = OscillationTracker::new(DEFAULT_OSCILLATION_ALARM);
        tracker.push("runtime-a:model-a");
        tracker.push("runtime-a:model-b");
        tracker.push("runtime-a:model-a");
        assert_eq!(tracker.count(), 1);
        assert!(tracker.alarmed());
    }

    #[test]
    fn trajectory_oscillation_survives_historical_policy_eviction() {
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(4),
            deadline: None,
            next_reset: None,
        });
        for (at, policy_id) in [(1, "policy-a"), (2, "policy-b"), (3, "policy-a")] {
            state.trajectory.push(TrajectoryEvent {
                at: TimestampMillis::from_millis(at),
                policy_id: PolicyId::new(policy_id).expect("policy"),
                node_id: PolicyNodeId::new("execute").expect("node"),
                observation: TrajectoryObservation::Progress,
                features: TrajectoryFeatures::new(),
            });
        }
        assert_eq!(oscillation_count(&trajectory_policy_identities(&state)), 1);
    }

    #[test]
    fn hysteresis_blocks_a_switch_whose_gain_is_below_margin() {
        let hysteresis = SwitchHysteresis { margin_bp: 1_000 };
        assert!(!hysteresis.should_switch(100, 100));
        assert!(hysteresis.should_switch(200, 100));
        assert_eq!(hysteresis.priced_switch_cost(100), 110);
    }

    #[test]
    fn transition_classes_are_distinct() {
        let current = action("adapter-a", "model-a");
        let same = action("adapter-a", "model-a");
        let other_model = action("adapter-a", "model-b");
        let other_runtime = action("adapter-b", "model-a");
        assert_eq!(
            classify_transition(Some(&current), Some(&same), RestartMode::Continuation),
            TransitionClass::Continue
        );
        assert_eq!(
            classify_transition(
                Some(&current),
                Some(&other_model),
                RestartMode::Continuation
            ),
            TransitionClass::ModelChangeSameRuntime
        );
        assert_eq!(
            classify_transition(
                Some(&current),
                Some(&other_runtime),
                RestartMode::Continuation
            ),
            TransitionClass::RuntimeAdapterChange
        );
        assert_eq!(
            classify_transition(Some(&current), Some(&same), RestartMode::CleanRestart),
            TransitionClass::FreshSessionOrWorktree
        );
    }

    #[test]
    fn unknown_previous_does_not_price_action_as_fresh_session() {
        let next = action("adapter-a", "model-a");
        assert_eq!(
            classify_transition(None, Some(&next), RestartMode::Continuation),
            TransitionClass::Continue
        );
        assert_eq!(
            classify_transition(None, None, RestartMode::Continuation),
            TransitionClass::Continue
        );
        assert_eq!(
            classify_transition(None, Some(&next), RestartMode::CleanRestart),
            TransitionClass::FreshSessionOrWorktree
        );
    }

    struct ConstantObjective;

    impl ObjectiveEvaluator for ConstantObjective {
        fn evaluate(
            &self,
            distribution: &PolicyOutcomeDistribution,
        ) -> Result<ObjectiveValue, OptimizerError> {
            Ok(ObjectiveValue {
                policy_id: distribution.policy_id.clone(),
                risk_adjusted_cost_micros: distribution.expected_cost_micros,
                tail_latency_micros: distribution.expected_latency_micros,
            })
        }
    }

    #[test]
    fn switch_aware_objective_adds_the_term() {
        let switch = SwitchCostEstimate::from_explicit_terms(
            TransitionClass::ModelChangeSameRuntime,
            10,
            10,
            0,
            0,
            ObservationKind::Measured,
        );
        assert_eq!(switch.total_cost_micros, 1_000);
        let objective = SwitchAwareObjective::new(Box::new(ConstantObjective), switch);
        let value = objective
            .evaluate(&PolicyOutcomeDistribution::new(
                PolicyId::new("p").expect("id"),
                100,
                100,
                9_000,
                9_000,
            ))
            .expect("eval");
        assert_eq!(value.risk_adjusted_cost_micros, 1_100);
    }

    #[test]
    fn current_action_reads_live_policy_feature() {
        let continue_policy = graph("keep", "adapter-a", "model-a", RestartMode::Continuation);
        let switch_policy = graph("swap", "adapter-a", "model-b", RestartMode::Continuation);
        let mut state = OptimizerState::new(DecisionHorizon {
            now: TimestampMillis::from_millis(1),
            deadline: None,
            next_reset: None,
        });
        insert_text(
            &mut state.task_features,
            feature_keys::CURRENT_POLICY,
            "keep",
        );
        let candidates = [continue_policy.clone(), switch_policy.clone()];
        let previous = current_action_from_candidates(&state, &candidates);
        let estimate = estimate_switch(&SwitchCostModel::new(), previous, &switch_policy);
        assert_eq!(estimate.class, TransitionClass::ModelChangeSameRuntime);
        let stay = estimate_switch(&SwitchCostModel::new(), previous, &continue_policy);
        assert_eq!(stay.class, TransitionClass::Continue);
        assert_eq!(stay.total_cost_micros, 0);
    }

    fn invocation(
        id: &str,
        backend: &str,
        model: &str,
        started: u64,
        input: Option<u64>,
        cached: Option<u64>,
    ) -> InvocationRecord {
        let mut record = InvocationRecord::new(
            PolicyId::new("p").expect("policy"),
            CandidateId::new("c").expect("cand"),
            TimestampMillis::from_millis(started),
            ResourceVector::new().snapshot(TimestampMillis::from_millis(started)),
        );
        record.policy_execution_id = Some(PolicyExecutionId::new("exec-1").expect("exec"));
        record.invocation_id = Some(InvocationId::new(id).expect("id"));
        record.backend = Some(BackendId::new(backend).expect("backend"));
        record.resolved_model = Some(RuntimeSlug::new(model).expect("model"));
        record.input_tokens = input;
        record.cached_input_tokens = cached;
        record
    }

    #[test]
    fn telemetry_fits_explicit_cache_invalidation_and_reprime() {
        let mut warm = invocation("warm", "adapter-a", "model-a", 1, Some(1_000), Some(800));
        warm.session_id = Some("session-a".to_string());
        warm.worktree_id = Some("worktree-a".to_string());
        let mut switched = invocation("swap", "adapter-a", "model-b", 2, Some(900), Some(0));
        switched.session_id = Some("session-a".to_string());
        switched.worktree_id = Some("worktree-a".to_string());
        switched.runtime_startup_micros = Some(1_200);
        let mut model = SwitchCostModel::new();
        model.observe_invocations(&[warm.clone(), switched.clone()]);

        let estimate = model
            .estimate_invocation_transition(Some(&warm), &switched)
            .expect("classified transition");
        assert_eq!(estimate.status, SwitchEvidenceStatus::Mixed);
        assert_eq!(estimate.cached_prefix_invalidation_tokens, 800);
        assert_eq!(estimate.context_reprime_tokens, 900);
        assert_eq!(estimate.runtime_startup_micros, 1_200);
        assert_eq!(
            estimate.provenance.cached_prefix_invalidation.source,
            SwitchEvidenceSource::ExactTransitionTelemetry
        );
        assert_eq!(
            estimate.provenance.runtime_startup.source,
            SwitchEvidenceSource::ExactTransitionTelemetry
        );
        assert_eq!(
            estimate.provenance.lost_checkpoint.source,
            SwitchEvidenceSource::ColdStartPrior
        );
        assert_eq!(
            estimate.provenance.cached_prefix_invalidation.sample_count,
            1
        );
        assert_eq!(
            estimate.total_cost_micros,
            estimate.explicit_objective_term_micros()
        );
        assert_eq!(
            estimate
                .cost_by_dimension()
                .get(&ResourceDimensionId::well_known(
                    ResourceDimensionId::API_COST_USD
                )),
            Some(&token_cost_micros(1_700))
        );

        let stay = model.estimate(TransitionClass::Continue);
        assert_eq!(stay.total_cost_micros, 0);
        let (hit_bp, hit_kind) = model
            .cache_hit_ratio_bp(TransitionClass::ModelChangeSameRuntime)
            .expect("hit ratio");
        assert_eq!(hit_kind, ObservationKind::Measured);
        assert_eq!(hit_bp, 0);

        let hysteresis = SwitchHysteresis { margin_bp: 1_000 };
        assert!(!hysteresis.should_switch(1_000, estimate.explicit_objective_term_micros()));
    }

    #[test]
    fn session_or_worktree_change_is_a_distinct_fresh_transition() {
        let mut previous = invocation("a", "adapter-a", "model-a", 1, Some(100), Some(90));
        previous.session_id = Some("session-a".to_string());
        previous.worktree_id = Some("worktree-a".to_string());
        let mut next = invocation("b", "adapter-a", "model-a", 2, Some(100), Some(0));
        next.session_id = Some("session-b".to_string());
        next.worktree_id = Some("worktree-a".to_string());
        assert_eq!(
            classify_invocation_transition(Some(&previous), &next),
            Some(TransitionClass::FreshSessionOrWorktree)
        );
    }

    #[test]
    fn continue_records_high_cache_hit_and_zero_switch_term() {
        let first = invocation("a", "adapter-a", "model-a", 1, Some(1_000), Some(200));
        let again = invocation("b", "adapter-a", "model-a", 2, Some(1_000), Some(900));
        let mut model = SwitchCostModel::new();
        model.observe_invocations(&[first, again]);
        assert_eq!(
            model
                .estimate(TransitionClass::Continue)
                .explicit_objective_term_micros(),
            0
        );
        let (hit_bp, kind) = model
            .cache_hit_ratio_bp(TransitionClass::Continue)
            .expect("continue hit");
        assert_eq!(kind, ObservationKind::Measured);
        assert_eq!(hit_bp, 9_000);
        assert_eq!(
            model
                .estimate(TransitionClass::ModelChangeSameRuntime)
                .observation,
            ObservationKind::Inferred
        );
    }

    #[test]
    fn missing_token_fields_are_not_fabricated_as_measured_zeros() {
        let previous = invocation("a", "adapter-a", "model-a", 1, None, None);
        let next = invocation("b", "adapter-a", "model-b", 2, None, None);
        let mut model = SwitchCostModel::new();
        model.observe_invocations(&[previous, next]);
        let estimate = model.estimate(TransitionClass::ModelChangeSameRuntime);
        assert_eq!(estimate.observation, ObservationKind::Inferred);
        assert!(estimate.explicit_objective_term_micros() > 0);
        assert!(model
            .cache_hit_ratio_bp(TransitionClass::ModelChangeSameRuntime)
            .is_none());
    }

    #[test]
    fn inferred_prior_exposes_nonzero_cache_and_reprime_terms() {
        let estimate = SwitchCostModel::new().estimate(TransitionClass::RuntimeAdapterChange);
        assert_eq!(estimate.observation, ObservationKind::Inferred);
        assert!(estimate.cached_prefix_invalidation_tokens > 0);
        assert!(estimate.context_reprime_tokens > 0);
        assert_eq!(
            estimate.total_cost_micros,
            estimate.explicit_objective_term_micros()
        );
    }
}
