//! Drift detection and reserve recalibration cadence. Implemented by issue #170.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

use super::action::{CanonicalEffort, RuntimeModelId};
use super::error::OptimizerError;
use super::ids::{CatalogVersion, PolicyId, ResourceDimensionId, RuntimeSlug, TimestampMillis};
use super::resources::ResourceVector;
use super::safe_set::{EvaluationFidelity, InMemorySafeSetStore, PromotionEvent, TaskClass};
use super::telemetry::InvocationRecord;

pub trait DriftDetector {
    fn detect(&self, records: &[InvocationRecord]) -> Result<bool, OptimizerError>;
}

/// Recalibration hook. #170 owns the cadence; #162 owns the reserve math.
pub trait ReserveRecalibrator {
    fn recalibrate(
        &self,
        current: &ResourceVector,
        as_of: TimestampMillis,
        records: &[InvocationRecord],
    ) -> Result<ResourceVector, OptimizerError>;
}

/// Statistics key: runtime identity including catalog version, never a bare slug.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ModelStatisticsKey {
    pub identity: RuntimeModelId,
    pub effort: CanonicalEffort,
    pub task_class: TaskClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeSample {
    pub at: TimestampMillis,
    pub certified: bool,
    pub cost_micros: i64,
}

/// Exponentially decayed Bernoulli sufficient statistics in millionths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DecayedBernoulli {
    pub weighted_successes_micro: u64,
    pub weighted_trials_micro: u64,
}

impl DecayedBernoulli {
    pub fn absorb(&mut self, certified: bool, age_ms: u64, half_life_ms: u64) {
        let weight = decay_weight_micro(age_ms, half_life_ms);
        self.weighted_trials_micro = self.weighted_trials_micro.saturating_add(weight);
        if certified {
            self.weighted_successes_micro = self.weighted_successes_micro.saturating_add(weight);
        }
    }

    pub fn effective_sample_size(&self) -> u32 {
        (self.weighted_trials_micro / 1_000_000).min(u64::from(u32::MAX)) as u32
    }

    pub fn mean_bp(&self) -> u16 {
        if self.weighted_trials_micro == 0 {
            return 0;
        }
        ((self.weighted_successes_micro * 10_000) / self.weighted_trials_micro) as u16
    }

    pub fn wilson_lcb_bp(&self) -> u16 {
        let trials = self.effective_sample_size();
        if trials == 0 {
            return 0;
        }
        let successes = ((self.weighted_successes_micro / 1_000_000).min(u64::from(trials))) as u32;
        wilson_lcb_bp(successes, trials)
    }

    /// Catalog-version change: old data must not permanently dominate.
    pub fn widen(&mut self) {
        self.weighted_successes_micro /= 4;
        self.weighted_trials_micro /= 4;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdaptationEventKind {
    CatalogVersionDrift,
    ChangePointDetected,
    PolicyRetired,
    PolicyRepromoted,
    ReserveRecalibrated,
    DecayApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptationEvent {
    pub kind: AdaptationEventKind,
    pub at: TimestampMillis,
    pub subject: String,
    pub reason: String,
    pub prior_confidence_bp: u16,
    pub posterior_confidence_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptationAdvice {
    pub selected: PolicyId,
    pub reason: String,
    pub confidence_bp: u16,
}

/// Page-Hinkley change-point detector on a binary outcome stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageHinkleyDetector {
    pub delta_micro: i64,
    pub lambda_micro: i64,
}

impl Default for PageHinkleyDetector {
    fn default() -> Self {
        Self {
            delta_micro: 50_000,
            lambda_micro: 400_000,
        }
    }
}

impl PageHinkleyDetector {
    pub fn detect(&self, outcomes: &[bool]) -> Option<usize> {
        if outcomes.len() < 4 {
            return None;
        }
        let mut mean_micro = 0_i64;
        let mut up = 0_i64;
        let mut down = 0_i64;
        let mut up_min = 0_i64;
        let mut down_min = 0_i64;
        for (index, outcome) in outcomes.iter().enumerate() {
            let x = if *outcome { 1_000_000 } else { 0 };
            let n = (index as i64) + 1;
            mean_micro += (x - mean_micro) / n;
            up += x - mean_micro - self.delta_micro;
            down += mean_micro - x - self.delta_micro;
            if up < up_min {
                up_min = up;
            }
            if down < down_min {
                down_min = down;
            }
            if (up - up_min >= self.lambda_micro || down - down_min >= self.lambda_micro)
                && index + 1 >= 4
            {
                return Some(index);
            }
        }
        None
    }
}

/// Continuous adaptation store: versioned statistics, drift events, retirement.
#[derive(Debug)]
pub struct AdaptationStore {
    half_life_ms: u64,
    stats: Mutex<BTreeMap<ModelStatisticsKey, DecayedBernoulli>>,
    samples: Mutex<BTreeMap<ModelStatisticsKey, Vec<OutcomeSample>>>,
    events: Mutex<Vec<AdaptationEvent>>,
    changepoint: PageHinkleyDetector,
}

impl AdaptationStore {
    pub fn new(half_life_ms: u64) -> Self {
        Self {
            half_life_ms: half_life_ms.max(1),
            stats: Mutex::new(BTreeMap::new()),
            samples: Mutex::new(BTreeMap::new()),
            events: Mutex::new(Vec::new()),
            changepoint: PageHinkleyDetector::default(),
        }
    }

    pub fn record_outcome(
        &self,
        key: &ModelStatisticsKey,
        sample: OutcomeSample,
        now: TimestampMillis,
    ) -> Result<DecayedBernoulli, OptimizerError> {
        let age = now.as_millis().saturating_sub(sample.at.as_millis());
        let mut stats = self
            .stats
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation stats lock poisoned"))?;
        let entry = stats.entry(key.clone()).or_default();
        entry.absorb(sample.certified, age, self.half_life_ms);
        self.samples
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation samples lock poisoned"))?
            .entry(key.clone())
            .or_default()
            .push(sample);
        self.push_event(AdaptationEvent {
            kind: AdaptationEventKind::DecayApplied,
            at: now,
            subject: key.identity.runtime_slug.to_string(),
            reason: format!(
                "catalog_version={} effort={}",
                key.identity.catalog_version, key.effort
            ),
            prior_confidence_bp: 10_000,
            posterior_confidence_bp: confidence_from_ess(entry.effective_sample_size()),
        })?;
        Ok(*entry)
    }

    pub fn posterior(&self, key: &ModelStatisticsKey) -> Result<DecayedBernoulli, OptimizerError> {
        Ok(self
            .stats
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation stats lock poisoned"))?
            .get(key)
            .copied()
            .unwrap_or_default())
    }

    pub fn events_snapshot(&self) -> Result<Vec<AdaptationEvent>, OptimizerError> {
        Ok(self
            .events
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation events lock poisoned"))?
            .clone())
    }

    /// Same slug, new catalog version: widen the previous version and start empty on the new one.
    pub fn note_catalog_version_change(
        &self,
        slug: &RuntimeSlug,
        previous: &CatalogVersion,
        next: &CatalogVersion,
        at: TimestampMillis,
    ) -> Result<AdaptationEvent, OptimizerError> {
        let mut stats = self
            .stats
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation stats lock poisoned"))?;
        let mut prior = 10_000_u16;
        let mut posterior = 10_000_u16;
        for (key, value) in stats.iter_mut() {
            if &key.identity.runtime_slug == slug && &key.identity.catalog_version == previous {
                prior = confidence_from_ess(value.effective_sample_size());
                value.widen();
                posterior = confidence_from_ess(value.effective_sample_size());
            }
            if &key.identity.runtime_slug == slug && &key.identity.catalog_version == next {
                *value = DecayedBernoulli::default();
            }
        }
        let event = AdaptationEvent {
            kind: AdaptationEventKind::CatalogVersionDrift,
            at,
            subject: slug.to_string(),
            reason: format!("catalog version {previous} -> {next}"),
            prior_confidence_bp: prior,
            posterior_confidence_bp: posterior,
        };
        self.events
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation events lock poisoned"))?
            .push(event.clone());
        Ok(event)
    }

    pub fn detect_changepoint(
        &self,
        key: &ModelStatisticsKey,
        at: TimestampMillis,
    ) -> Result<Option<AdaptationEvent>, OptimizerError> {
        let samples = self
            .samples
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation samples lock poisoned"))?;
        let Some(series) = samples.get(key) else {
            return Ok(None);
        };
        let outcomes: Vec<bool> = series.iter().map(|sample| sample.certified).collect();
        let Some(index) = self.changepoint.detect(&outcomes) else {
            return Ok(None);
        };
        drop(samples);
        let event = AdaptationEvent {
            kind: AdaptationEventKind::ChangePointDetected,
            at,
            subject: key.identity.runtime_slug.to_string(),
            reason: format!("change-point at sample {index}"),
            prior_confidence_bp: 10_000,
            posterior_confidence_bp: 2_500,
        };
        if let Some(stats) = self
            .stats
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation stats lock poisoned"))?
            .get_mut(key)
        {
            stats.widen();
        }
        self.events
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation events lock poisoned"))?
            .push(event.clone());
        Ok(Some(event))
    }

    /// Demote any non-baseline policy whose decayed LCB is below the safe-set threshold.
    pub fn retire_stale_policies(
        &self,
        store: &InMemorySafeSetStore,
        task_class: &TaskClass,
        at: TimestampMillis,
        keys: &[(PolicyId, ModelStatisticsKey)],
    ) -> Result<Vec<PromotionEvent>, OptimizerError> {
        let threshold = store.threshold_for(task_class)?;
        let mut retired = Vec::new();
        for (policy_id, key) in keys {
            if policy_id == store.baseline_policy() {
                continue;
            }
            if !store.contains_for_class(policy_id, task_class)? {
                continue;
            }
            let posterior = self.posterior(key)?;
            if posterior.wilson_lcb_bp() < threshold.lcb_bp {
                let event = store.demote(policy_id, task_class, at)?;
                self.push_event(AdaptationEvent {
                    kind: AdaptationEventKind::PolicyRetired,
                    at,
                    subject: policy_id.to_string(),
                    reason: format!(
                        "decayed LCB {} < threshold {}",
                        posterior.wilson_lcb_bp(),
                        threshold.lcb_bp
                    ),
                    prior_confidence_bp: posterior.mean_bp(),
                    posterior_confidence_bp: posterior.wilson_lcb_bp(),
                })?;
                retired.push(event);
            }
        }
        Ok(retired)
    }

    /// Re-promotion is the normal F4/F5 shadow → safe-set path; this only records the event.
    pub fn note_repromotion(
        &self,
        policy_id: &PolicyId,
        at: TimestampMillis,
        fidelity: EvaluationFidelity,
    ) -> Result<AdaptationEvent, OptimizerError> {
        if !fidelity.can_promote_to_safe_set() {
            return Err(OptimizerError::invalid(
                "re-promotion requires F4/F5 evidence",
            ));
        }
        let event = AdaptationEvent {
            kind: AdaptationEventKind::PolicyRepromoted,
            at,
            subject: policy_id.to_string(),
            reason: format!("re-promoted via {fidelity:?}"),
            prior_confidence_bp: 0,
            posterior_confidence_bp: 10_000,
        };
        self.push_event(event.clone())?;
        Ok(event)
    }

    /// Router-facing advice: same slug with a newer catalog version is preferred
    /// once the old version's confidence has been widened.
    pub fn advise(
        &self,
        previous: &ModelStatisticsKey,
        current: &ModelStatisticsKey,
        previous_policy: &PolicyId,
        current_policy: &PolicyId,
    ) -> Result<AdaptationAdvice, OptimizerError> {
        let old = self.posterior(previous)?;
        let new = self.posterior(current)?;
        let old_conf = confidence_from_ess(old.effective_sample_size());
        let new_conf = if new.effective_sample_size() == 0 {
            1_000
        } else {
            confidence_from_ess(new.effective_sample_size())
        };
        if old_conf > new_conf
            && previous.identity.runtime_slug == current.identity.runtime_slug
            && previous.identity.catalog_version != current.identity.catalog_version
        {
            return Ok(AdaptationAdvice {
                selected: current_policy.clone(),
                reason: format!(
                    "catalog version drift: {} confidence {}bp no longer dominates {}",
                    previous.identity.catalog_version, old_conf, current.identity.catalog_version
                ),
                confidence_bp: new_conf,
            });
        }
        if new.wilson_lcb_bp() >= old.wilson_lcb_bp() {
            Ok(AdaptationAdvice {
                selected: current_policy.clone(),
                reason: "current version LCB is at least as strong".to_string(),
                confidence_bp: new_conf.max(old_conf),
            })
        } else {
            Ok(AdaptationAdvice {
                selected: previous_policy.clone(),
                reason: "previous version still has a stronger decayed LCB".to_string(),
                confidence_bp: old_conf,
            })
        }
    }

    fn push_event(&self, event: AdaptationEvent) -> Result<(), OptimizerError> {
        self.events
            .lock()
            .map_err(|_| OptimizerError::invalid("adaptation events lock poisoned"))?
            .push(event);
        Ok(())
    }
}

impl DriftDetector for AdaptationStore {
    fn detect(&self, records: &[InvocationRecord]) -> Result<bool, OptimizerError> {
        if records.len() < 4 {
            return Ok(false);
        }
        let outcomes: Vec<bool> = records
            .windows(2)
            .map(|pair| pair[1].started_at.as_millis() >= pair[0].started_at.as_millis())
            .collect();
        Ok(self.changepoint.detect(&outcomes).is_some())
    }
}

/// Pure function of the telemetry ledger snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerReserveRecalibrator {
    pub quantile_bp: u16,
}

impl Default for LedgerReserveRecalibrator {
    fn default() -> Self {
        Self { quantile_bp: 9_900 }
    }
}

impl LedgerReserveRecalibrator {
    pub fn new(quantile_bp: u16) -> Self {
        Self { quantile_bp }
    }
}

impl ReserveRecalibrator for LedgerReserveRecalibrator {
    fn recalibrate(
        &self,
        current: &ResourceVector,
        _as_of: TimestampMillis,
        records: &[InvocationRecord],
    ) -> Result<ResourceVector, OptimizerError> {
        let mut updated = current.clone();
        let ids: Vec<ResourceDimensionId> = current
            .dimensions()
            .map(|dimension| dimension.id.clone())
            .collect();
        for id in ids {
            let mut samples = Vec::new();
            for record in records {
                if let Some(dimension) = record.quota_snapshot.vector.get(&id) {
                    samples.push(dimension.frontier_reserve);
                }
            }
            if !samples.is_empty() {
                updated.recalibrate_frontier_reserve(&id, &samples, self.quantile_bp)?;
            }
        }
        Ok(updated)
    }
}

fn decay_weight_micro(age_ms: u64, half_life_ms: u64) -> u64 {
    if age_ms == 0 {
        return 1_000_000;
    }
    let half_lives = age_ms / half_life_ms.max(1);
    1_000_000_u64 >> half_lives.min(20)
}

fn wilson_lcb_bp(successes: u32, trials: u32) -> u16 {
    if trials == 0 {
        return 0;
    }
    let n = f64::from(trials);
    let p = f64::from(successes) / n;
    let z = 1.96_f64;
    let z2 = z * z;
    let center = p + z2 / (2.0 * n);
    let spread = z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    let denom = 1.0 + z2 / n;
    let lcb = ((center - spread) / denom).clamp(0.0, 1.0);
    (lcb * 10_000.0).floor() as u16
}

fn confidence_from_ess(ess: u32) -> u16 {
    (ess.saturating_mul(400)).min(10_000) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::{
        BackendId, CandidateId, ModelFamilyId, PolicyId, ProviderId, ResourceDimensionId,
    };
    use crate::optimizer::resources::{
        ObservationKind, Quantity, ResourceDimension, ResourceObservation, ResourceSnapshot,
    };
    use crate::optimizer::safe_set::{
        PromotionDecisionKind, PromotionEvidence, PromotionRequest, PromotionThreshold,
    };
    use crate::optimizer::telemetry::InvocationRecord;

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

    fn key(slug: &str, version: &str) -> ModelStatisticsKey {
        ModelStatisticsKey {
            identity: identity(slug, version),
            effort: CanonicalEffort::Medium,
            task_class: TaskClass::new("coding").expect("class"),
        }
    }

    fn pool(reserve: i64) -> ResourceVector {
        let mut vector = ResourceVector::new();
        vector.insert(ResourceDimension {
            id: ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
            remaining: Quantity::new(1_000),
            reset_at: None,
            frontier_reserve: Quantity::new(reserve),
            emergency_margin: Quantity::new(10),
            uncertainty: Quantity::ZERO,
            shadow_price: 0,
            observation: ResourceObservation {
                kind: ObservationKind::Measured,
                confidence_bp: 10_000,
            },
            chance_epsilon_bp: 100,
            target_usage_bp: 5_000,
            learning_rate: 100,
        });
        vector
    }

    fn record_with_reserve(reserve: i64, at: u64) -> InvocationRecord {
        let mut record = InvocationRecord::new(
            PolicyId::new("p").expect("policy"),
            CandidateId::new("c").expect("cand"),
            TimestampMillis::from_millis(at),
            ResourceSnapshot {
                observed_at: TimestampMillis::from_millis(at),
                vector: pool(reserve),
            },
        );
        record.finished_at = Some(TimestampMillis::from_millis(at + 1));
        record
    }

    #[test]
    fn catalog_version_change_widens_previous_uncertainty_and_changes_advice() {
        let store = AdaptationStore::new(1_000);
        let old_key = key("catalog-small", "v1");
        let new_key = key("catalog-small", "v2");
        for i in 0..20 {
            store
                .record_outcome(
                    &old_key,
                    OutcomeSample {
                        at: TimestampMillis::from_millis(i),
                        certified: true,
                        cost_micros: 10,
                    },
                    TimestampMillis::from_millis(i),
                )
                .expect("record");
        }
        let before = store.posterior(&old_key).expect("before");
        assert!(before.effective_sample_size() >= 10);
        let event = store
            .note_catalog_version_change(
                &old_key.identity.runtime_slug,
                &old_key.identity.catalog_version,
                &new_key.identity.catalog_version,
                TimestampMillis::from_millis(100),
            )
            .expect("drift");
        assert_eq!(event.kind, AdaptationEventKind::CatalogVersionDrift);
        let after = store.posterior(&old_key).expect("after");
        assert!(after.effective_sample_size() < before.effective_sample_size());
        let advice = store
            .advise(
                &old_key,
                &new_key,
                &PolicyId::new("old").expect("id"),
                &PolicyId::new("new").expect("id"),
            )
            .expect("advise");
        assert_eq!(advice.selected.as_str(), "new");
        assert!(advice.reason.contains("catalog version drift"));
        assert!(advice.confidence_bp < 10_000);
    }

    #[test]
    fn changepoint_in_synthetic_outcomes_is_detected() {
        let detector = PageHinkleyDetector {
            delta_micro: 20_000,
            lambda_micro: 200_000,
        };
        let mut outcomes = vec![true; 12];
        outcomes.extend(std::iter::repeat_n(false, 12));
        assert!(detector.detect(&outcomes).is_some());

        let store = AdaptationStore::new(10_000);
        let key = key("catalog-small", "v1");
        for (i, certified) in outcomes.iter().enumerate() {
            store
                .record_outcome(
                    &key,
                    OutcomeSample {
                        at: TimestampMillis::from_millis(i as u64),
                        certified: *certified,
                        cost_micros: 1,
                    },
                    TimestampMillis::from_millis(i as u64),
                )
                .expect("record");
        }
        let event = store
            .detect_changepoint(&key, TimestampMillis::from_millis(50))
            .expect("detect");
        assert!(event.is_some());
        assert_eq!(
            event.expect("event").kind,
            AdaptationEventKind::ChangePointDetected
        );
    }

    #[test]
    fn retirement_demotes_without_human_action_and_is_reversible() {
        let adaptation = AdaptationStore::new(1);
        let safe = InMemorySafeSetStore::cold_start(PolicyId::new("baseline").expect("id"));
        let class = TaskClass::new("coding").expect("class");
        safe.set_threshold(&class, PromotionThreshold { lcb_bp: 7_000 })
            .expect("threshold");
        let candidate = PolicyId::new("stale").expect("id");
        for _ in 0..30 {
            safe.record_outcome(&candidate, &class, true).expect("ok");
        }
        let promoted = safe
            .promote(PromotionRequest {
                policy_id: &candidate,
                task_class: &class,
                decided_at: TimestampMillis::from_millis(1),
                evidence: PromotionEvidence::DirectEvaluation {
                    fidelity: EvaluationFidelity::F4HiddenValidation,
                },
            })
            .expect("promote");
        assert_eq!(promoted.kind, PromotionDecisionKind::Promoted);

        let stale_key = key("catalog-small", "v1");
        for i in 0..8 {
            adaptation
                .record_outcome(
                    &stale_key,
                    OutcomeSample {
                        at: TimestampMillis::from_millis(i),
                        certified: false,
                        cost_micros: 50,
                    },
                    TimestampMillis::from_millis(10_000),
                )
                .expect("fail");
        }
        let retired = adaptation
            .retire_stale_policies(
                &safe,
                &class,
                TimestampMillis::from_millis(11),
                &[(candidate.clone(), stale_key)],
            )
            .expect("retire");
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].kind, PromotionDecisionKind::Demoted);
        assert!(!safe.contains_for_class(&candidate, &class).expect("gone"));

        for _ in 0..30 {
            safe.record_outcome(&candidate, &class, true).expect("ok");
        }
        let again = safe
            .promote(PromotionRequest {
                policy_id: &candidate,
                task_class: &class,
                decided_at: TimestampMillis::from_millis(20),
                evidence: PromotionEvidence::DirectEvaluation {
                    fidelity: EvaluationFidelity::F5ProductionShadow,
                },
            })
            .expect("repromote");
        assert_eq!(again.kind, PromotionDecisionKind::Promoted);
        adaptation
            .note_repromotion(
                &candidate,
                TimestampMillis::from_millis(21),
                EvaluationFidelity::F5ProductionShadow,
            )
            .expect("note");
        assert!(safe.contains_for_class(&candidate, &class).expect("back"));
    }

    #[test]
    fn recalibration_is_a_pure_function_of_the_ledger_snapshot() {
        let recalibrator = LedgerReserveRecalibrator::new(9_900);
        let current = pool(10);
        let records = vec![
            record_with_reserve(20, 1),
            record_with_reserve(40, 2),
            record_with_reserve(80, 3),
            record_with_reserve(100, 4),
        ];
        let first = recalibrator
            .recalibrate(&current, TimestampMillis::from_millis(5), &records)
            .expect("first");
        let second = recalibrator
            .recalibrate(&current, TimestampMillis::from_millis(5), &records)
            .expect("second");
        assert_eq!(first, second);
        let id = ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD);
        assert_ne!(
            first.get(&id).expect("dim").frontier_reserve,
            current.get(&id).expect("dim").frontier_reserve
        );
    }

    #[test]
    fn statistics_are_keyed_by_catalog_version_not_bare_slug() {
        let store = AdaptationStore::new(1_000);
        let v1 = key("catalog-small", "v1");
        let v2 = key("catalog-small", "v2");
        store
            .record_outcome(
                &v1,
                OutcomeSample {
                    at: TimestampMillis::from_millis(1),
                    certified: true,
                    cost_micros: 1,
                },
                TimestampMillis::from_millis(1),
            )
            .expect("v1");
        assert!(store.posterior(&v1).expect("v1").effective_sample_size() > 0);
        assert_eq!(store.posterior(&v2).expect("v2").effective_sample_size(), 0);
    }
}
