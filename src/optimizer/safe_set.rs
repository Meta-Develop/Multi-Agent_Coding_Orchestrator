//! Safe-set promotion. Implemented by issue #169.
//!
//! Production routing selects only from the safe set. Candidates enter after
//! their lower confidence bound on certification probability exceeds the
//! configured threshold for the relevant task class, and only on F4/F5
//! evidence. Cold-start always keeps a known-safe baseline policy available
//! as the fallback.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use super::error::OptimizerError;
use super::ids::{PolicyId, ResourceDimensionId, TimestampMillis};
use super::replay::DecisionSnapshot;
use super::resources::{Quantity, ResourceVector};
use super::switch_cost::ReplaySwitchEstimate;

/// Multi-fidelity evaluation ladder from issue #169.
///
/// Low-fidelity observations may steer search, but only F4/F5 evidence can
/// promote a policy into the production safe set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvaluationFidelity {
    F0StaticPrediction,
    F1CheapRepoProbe,
    F2PartialTrajectory,
    F3HistoricalReplay,
    F4HiddenValidation,
    F5ProductionShadow,
}

impl EvaluationFidelity {
    pub fn can_promote_to_safe_set(self) -> bool {
        matches!(self, Self::F4HiddenValidation | Self::F5ProductionShadow)
    }
}

/// Open task-class key. Not a closed enum so later phases can add classes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TaskClass(String);

impl TaskClass {
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeSet {
    pub policy_ids: Vec<PolicyId>,
}

pub trait SafeSetStore {
    fn contains(&self, policy_id: &PolicyId) -> Result<bool, OptimizerError>;
    fn snapshot(&self) -> Result<SafeSet, OptimizerError>;
}

/// Per-task-class promotion threshold (basis points, 10000 = 100%).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionThreshold {
    pub lcb_bp: u16,
}

impl Default for PromotionThreshold {
    fn default() -> Self {
        Self { lcb_bp: 8_000 }
    }
}

/// Binomial certification evidence for one (policy, task class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CertificationEvidence {
    pub certified_successes: u32,
    pub trials: u32,
    pub weak_prior_trials: u32,
}

impl CertificationEvidence {
    pub const MAX_WEAK_PRIOR_TRIALS: u32 = 3;

    pub fn record_trial(&mut self, certified: bool) {
        self.trials = self.trials.saturating_add(1);
        if certified {
            self.certified_successes = self.certified_successes.saturating_add(1);
        }
    }

    /// Benchmark / provider-tier information enters only as a weak prior.
    pub fn record_weak_prior(&mut self, certified: bool) {
        if self.weak_prior_trials >= Self::MAX_WEAK_PRIOR_TRIALS {
            return;
        }
        self.weak_prior_trials = self.weak_prior_trials.saturating_add(1);
        self.record_trial(certified);
    }

    /// Wilson score lower confidence bound in basis points (≈95%, z=1.96).
    pub fn wilson_lcb_bp(&self) -> u16 {
        if self.trials == 0 {
            return 0;
        }
        let n = f64::from(self.trials);
        let p = f64::from(self.certified_successes) / n;
        let z = 1.96_f64;
        let z2 = z * z;
        let center = p + z2 / (2.0 * n);
        let spread = z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
        let denom = 1.0 + z2 / n;
        let lcb = ((center - spread) / denom).clamp(0.0, 1.0);
        (lcb * 10_000.0).floor() as u16
    }

    pub fn empirical_mean_bp(&self) -> u16 {
        if self.trials == 0 {
            return 0;
        }
        ((u64::from(self.certified_successes) * 10_000) / u64::from(self.trials)) as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionDecisionKind {
    Promoted,
    RejectedBelowLcb,
    RejectedInsufficientFidelity,
    RejectedSwitchCostUncorrected,
    RejectedSwitchCostOverturnsGain,
    Demoted,
    BaselineRetained,
}

/// Provenance class for a persisted safe-set decision.
///
/// `DirectEvaluation` means historical replay did not influence the candidate
/// or its claimed gain. Replay-influenced promotion must use the distinct
/// request variant so an absent or unsafe production correction fails closed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionBasis {
    #[default]
    DirectEvaluation,
    ReplayInfluenced,
    Administrative,
}

/// Evidence required by the single safe-set promotion entrypoint.
#[derive(Debug, Clone, Copy)]
pub enum PromotionEvidence<'a> {
    DirectEvaluation {
        fidelity: EvaluationFidelity,
    },
    ReplayInfluenced {
        validation_fidelity: EvaluationFidelity,
        predicted_gain_micros: i64,
        snapshot: &'a DecisionSnapshot,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct PromotionRequest<'a> {
    pub policy_id: &'a PolicyId,
    pub task_class: &'a TaskClass,
    pub decided_at: TimestampMillis,
    pub evidence: PromotionEvidence<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvent {
    pub policy_id: PolicyId,
    pub task_class: TaskClass,
    pub decided_at: TimestampMillis,
    pub kind: PromotionDecisionKind,
    pub lcb_bp: u16,
    pub threshold_bp: u16,
    pub evidence: CertificationEvidence,
    pub fidelity: EvaluationFidelity,
    #[serde(default)]
    pub basis: PromotionBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_switch_estimate: Option<ReplaySwitchEstimate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplorationBudgetRequest {
    pub pool: ResourceDimensionId,
    pub demand: Quantity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExplorationAdmission {
    Admit,
    Reject { reason: String },
}

/// Calibrated exploration inside the current safe set only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExplorationMethod {
    ThompsonSampling,
    Ucb { exploration_bp: u16 },
}

/// In-memory safe-set with cold-start baseline and per-class LCB promotion.
#[derive(Debug)]
pub struct InMemorySafeSetStore {
    baseline: PolicyId,
    /// policy_id -> task classes for which it is safe.
    membership: Mutex<BTreeMap<String, BTreeSet<String>>>,
    evidence: Mutex<BTreeMap<(String, String), CertificationEvidence>>,
    thresholds: Mutex<BTreeMap<String, PromotionThreshold>>,
    events: Mutex<Vec<PromotionEvent>>,
    default_threshold: PromotionThreshold,
}

impl InMemorySafeSetStore {
    pub fn cold_start(baseline: PolicyId) -> Self {
        let mut membership = BTreeMap::new();
        membership.insert(baseline.to_string(), BTreeSet::new());
        Self {
            baseline,
            membership: Mutex::new(membership),
            evidence: Mutex::new(BTreeMap::new()),
            thresholds: Mutex::new(BTreeMap::new()),
            events: Mutex::new(Vec::new()),
            default_threshold: PromotionThreshold::default(),
        }
    }

    pub fn baseline_policy(&self) -> &PolicyId {
        &self.baseline
    }

    pub fn set_threshold(
        &self,
        task_class: &TaskClass,
        threshold: PromotionThreshold,
    ) -> Result<(), OptimizerError> {
        self.thresholds
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set thresholds lock poisoned"))?
            .insert(task_class.as_str().to_string(), threshold);
        Ok(())
    }

    pub fn threshold_for(
        &self,
        task_class: &TaskClass,
    ) -> Result<PromotionThreshold, OptimizerError> {
        Ok(self
            .thresholds
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set thresholds lock poisoned"))?
            .get(task_class.as_str())
            .copied()
            .unwrap_or(self.default_threshold))
    }

    pub fn record_outcome(
        &self,
        policy_id: &PolicyId,
        task_class: &TaskClass,
        certified: bool,
    ) -> Result<CertificationEvidence, OptimizerError> {
        let mut evidence = self
            .evidence
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set evidence lock poisoned"))?;
        let entry = evidence
            .entry((policy_id.to_string(), task_class.as_str().to_string()))
            .or_default();
        entry.record_trial(certified);
        Ok(*entry)
    }

    pub fn record_weak_prior(
        &self,
        policy_id: &PolicyId,
        task_class: &TaskClass,
        certified: bool,
    ) -> Result<CertificationEvidence, OptimizerError> {
        let mut evidence = self
            .evidence
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set evidence lock poisoned"))?;
        let entry = evidence
            .entry((policy_id.to_string(), task_class.as_str().to_string()))
            .or_default();
        entry.record_weak_prior(certified);
        Ok(*entry)
    }

    pub fn evidence_for(
        &self,
        policy_id: &PolicyId,
        task_class: &TaskClass,
    ) -> Result<CertificationEvidence, OptimizerError> {
        Ok(self
            .evidence
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set evidence lock poisoned"))?
            .get(&(policy_id.to_string(), task_class.as_str().to_string()))
            .copied()
            .unwrap_or_default())
    }

    /// Canonical safe-set promotion boundary. Replay-influenced candidates
    /// cannot bypass correction checks through a second, weaker method.
    pub fn promote(&self, request: PromotionRequest<'_>) -> Result<PromotionEvent, OptimizerError> {
        let PromotionRequest {
            policy_id,
            task_class,
            decided_at,
            evidence: promotion_evidence,
        } = request;
        let (fidelity, basis, replay) = match promotion_evidence {
            PromotionEvidence::DirectEvaluation { fidelity } => {
                (fidelity, PromotionBasis::DirectEvaluation, None)
            }
            PromotionEvidence::ReplayInfluenced {
                validation_fidelity,
                predicted_gain_micros,
                snapshot,
            } => {
                if snapshot.selected.as_ref() != Some(policy_id) {
                    return Err(OptimizerError::invalid(
                        "replay promotion policy does not match the recorded selection",
                    ));
                }
                (
                    validation_fidelity,
                    PromotionBasis::ReplayInfluenced,
                    Some((
                        predicted_gain_micros,
                        snapshot.replay_switch_estimate.as_ref(),
                    )),
                )
            }
        };
        let threshold = self.threshold_for(task_class)?;
        let evidence = self.evidence_for(policy_id, task_class)?;
        let lcb_bp = evidence.wilson_lcb_bp();
        let kind = if replay.is_some_and(|(_, estimate)| {
            !estimate.is_some_and(ReplaySwitchEstimate::has_measured_correction)
        }) {
            PromotionDecisionKind::RejectedSwitchCostUncorrected
        } else if replay.is_some_and(|(gain, estimate)| {
            !estimate.is_some_and(|estimate| estimate.may_promote(gain))
        }) {
            PromotionDecisionKind::RejectedSwitchCostOverturnsGain
        } else if !fidelity.can_promote_to_safe_set() {
            PromotionDecisionKind::RejectedInsufficientFidelity
        } else if lcb_bp >= threshold.lcb_bp {
            let mut membership = self
                .membership
                .lock()
                .map_err(|_| OptimizerError::invalid("safe-set membership lock poisoned"))?;
            membership
                .entry(policy_id.to_string())
                .or_default()
                .insert(task_class.as_str().to_string());
            PromotionDecisionKind::Promoted
        } else {
            PromotionDecisionKind::RejectedBelowLcb
        };
        let event = PromotionEvent {
            policy_id: policy_id.clone(),
            task_class: task_class.clone(),
            decided_at,
            kind,
            lcb_bp,
            threshold_bp: threshold.lcb_bp,
            evidence,
            fidelity,
            basis,
            replay_switch_estimate: replay.and_then(|(_, estimate)| estimate.cloned()),
        };
        self.events
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set events lock poisoned"))?
            .push(event.clone());
        Ok(event)
    }

    pub fn demote(
        &self,
        policy_id: &PolicyId,
        task_class: &TaskClass,
        at: TimestampMillis,
    ) -> Result<PromotionEvent, OptimizerError> {
        if policy_id == &self.baseline {
            let event = PromotionEvent {
                policy_id: policy_id.clone(),
                task_class: task_class.clone(),
                decided_at: at,
                kind: PromotionDecisionKind::BaselineRetained,
                lcb_bp: 10_000,
                threshold_bp: self.threshold_for(task_class)?.lcb_bp,
                evidence: CertificationEvidence::default(),
                fidelity: EvaluationFidelity::F4HiddenValidation,
                basis: PromotionBasis::Administrative,
                replay_switch_estimate: None,
            };
            self.events
                .lock()
                .map_err(|_| OptimizerError::invalid("safe-set events lock poisoned"))?
                .push(event.clone());
            return Ok(event);
        }
        let evidence = self.evidence_for(policy_id, task_class)?;
        let lcb_bp = evidence.wilson_lcb_bp();
        if let Some(classes) = self
            .membership
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set membership lock poisoned"))?
            .get_mut(&policy_id.to_string())
        {
            classes.remove(task_class.as_str());
        }
        let event = PromotionEvent {
            policy_id: policy_id.clone(),
            task_class: task_class.clone(),
            decided_at: at,
            kind: PromotionDecisionKind::Demoted,
            lcb_bp,
            threshold_bp: self.threshold_for(task_class)?.lcb_bp,
            evidence,
            fidelity: EvaluationFidelity::F4HiddenValidation,
            basis: PromotionBasis::Administrative,
            replay_switch_estimate: None,
        };
        self.events
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set events lock poisoned"))?
            .push(event.clone());
        Ok(event)
    }

    /// Production selection: baseline is always eligible; others require class membership.
    pub fn production_candidates(
        &self,
        task_class: &TaskClass,
    ) -> Result<Vec<PolicyId>, OptimizerError> {
        let membership = self
            .membership
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set membership lock poisoned"))?;
        let mut ids = vec![self.baseline.clone()];
        for (policy, classes) in membership.iter() {
            if policy == self.baseline.as_str() {
                continue;
            }
            if classes.contains(task_class.as_str()) {
                ids.push(PolicyId::new(policy.clone())?);
            }
        }
        ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        ids.dedup();
        Ok(ids)
    }

    pub fn contains_for_class(
        &self,
        policy_id: &PolicyId,
        task_class: &TaskClass,
    ) -> Result<bool, OptimizerError> {
        if policy_id == &self.baseline {
            return Ok(true);
        }
        Ok(self
            .membership
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set membership lock poisoned"))?
            .get(policy_id.as_str())
            .is_some_and(|classes| classes.contains(task_class.as_str())))
    }

    pub fn events_snapshot(&self) -> Result<Vec<PromotionEvent>, OptimizerError> {
        Ok(self
            .events
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set events lock poisoned"))?
            .clone())
    }

    /// Exploration must never consume the mandatory frontier reserve, even
    /// when no other pool can host the work.
    pub fn admit_exploration(
        &self,
        resources: &ResourceVector,
        request: &ExplorationBudgetRequest,
    ) -> Result<ExplorationAdmission, OptimizerError> {
        let dimension = resources.require(&request.pool)?;
        if dimension.optional_budget().as_i64() < request.demand.as_i64() {
            return Err(OptimizerError::FrontierReserveViolation(
                request.pool.to_string(),
            ));
        }
        Ok(ExplorationAdmission::Admit)
    }

    /// Select one production policy from the current safe set only.
    pub fn select_from_safe_set(
        &self,
        task_class: &TaskClass,
        method: ExplorationMethod,
        seed: u64,
    ) -> Result<PolicyId, OptimizerError> {
        let candidates = self.production_candidates(task_class)?;
        if candidates.is_empty() {
            return Err(OptimizerError::invalid(
                "safe set is empty; cold-start baseline is missing",
            ));
        }
        let mut scored = Vec::new();
        let total_trials: u64 = {
            let mut sum = 0_u64;
            for policy in &candidates {
                sum = sum.saturating_add(u64::from(
                    self.evidence_for(policy, task_class)?.trials.max(1),
                ));
            }
            sum
        };
        let mut rng = SplitMix64::new(seed);
        for policy in &candidates {
            let evidence = self.evidence_for(policy, task_class)?;
            let score = match method {
                ExplorationMethod::ThompsonSampling => {
                    sample_beta_bp(&mut rng, evidence.certified_successes + 1, {
                        let failures = evidence.trials.saturating_sub(evidence.certified_successes);
                        failures.saturating_add(1)
                    })
                }
                ExplorationMethod::Ucb { exploration_bp } => {
                    let mean = u32::from(evidence.empirical_mean_bp());
                    let n_i = f64::from(evidence.trials.max(1));
                    let bonus = f64::from(exploration_bp)
                        * (f64::from(total_trials.max(1) as u32).ln() / n_i).sqrt();
                    mean.saturating_add(bonus.floor() as u32)
                }
            };
            scored.push((score, policy.clone()));
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.as_str().cmp(b.1.as_str())));
        scored
            .into_iter()
            .next()
            .map(|(_, policy)| policy)
            .ok_or_else(|| OptimizerError::invalid("safe-set selection produced no candidate"))
    }
}

impl SafeSetStore for InMemorySafeSetStore {
    fn contains(&self, policy_id: &PolicyId) -> Result<bool, OptimizerError> {
        if policy_id == &self.baseline {
            return Ok(true);
        }
        Ok(self
            .membership
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set membership lock poisoned"))?
            .get(policy_id.as_str())
            .is_some_and(|classes| !classes.is_empty()))
    }

    fn snapshot(&self) -> Result<SafeSet, OptimizerError> {
        let membership = self
            .membership
            .lock()
            .map_err(|_| OptimizerError::invalid("safe-set membership lock poisoned"))?;
        let mut policy_ids = vec![self.baseline.clone()];
        for (policy, classes) in membership.iter() {
            if policy != self.baseline.as_str() && !classes.is_empty() {
                policy_ids.push(PolicyId::new(policy.clone())?);
            }
        }
        policy_ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        policy_ids.dedup();
        Ok(SafeSet { policy_ids })
    }
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn unit_open(&mut self) -> f64 {
        let value = (self.next_u64() >> 11) as f64 / ((1_u64 << 53) as f64);
        value.clamp(f64::EPSILON, 1.0 - f64::EPSILON)
    }
}

fn sample_beta_bp(rng: &mut SplitMix64, alpha: u32, beta: u32) -> u32 {
    let mut gamma_a = 0.0_f64;
    for _ in 0..alpha.max(1) {
        gamma_a -= rng.unit_open().ln();
    }
    let mut gamma_b = 0.0_f64;
    for _ in 0..beta.max(1) {
        gamma_b -= rng.unit_open().ln();
    }
    let denom = gamma_a + gamma_b;
    if denom <= 0.0 {
        return 5_000;
    }
    ((gamma_a / denom) * 10_000.0).floor() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::ResourceDimensionId;
    use crate::optimizer::resources::{ObservationKind, ResourceDimension, ResourceObservation};

    fn policy(id: &str) -> PolicyId {
        PolicyId::new(id).expect("policy")
    }

    fn class(id: &str) -> TaskClass {
        TaskClass::new(id).expect("class")
    }

    fn pool(remaining: i64, reserve: i64, emergency: i64) -> ResourceVector {
        let id = ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD);
        let mut vector = ResourceVector::new();
        vector.insert(ResourceDimension {
            id,
            remaining: Quantity::new(remaining),
            reset_at: None,
            frontier_reserve: Quantity::new(reserve),
            emergency_margin: Quantity::new(emergency),
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

    fn direct_promotion<'a>(
        policy_id: &'a PolicyId,
        task_class: &'a TaskClass,
        decided_at: TimestampMillis,
        fidelity: EvaluationFidelity,
    ) -> PromotionRequest<'a> {
        PromotionRequest {
            policy_id,
            task_class,
            decided_at,
            evidence: PromotionEvidence::DirectEvaluation { fidelity },
        }
    }

    fn promote_with_successes(
        store: &InMemorySafeSetStore,
        candidate: &PolicyId,
        coding: &TaskClass,
        n: u32,
    ) {
        for _ in 0..n {
            store
                .record_outcome(candidate, coding, true)
                .expect("record");
        }
        store
            .promote(direct_promotion(
                candidate,
                coding,
                TimestampMillis::from_millis(1),
                EvaluationFidelity::F4HiddenValidation,
            ))
            .expect("promote");
    }

    #[test]
    fn cold_start_baseline_is_always_available() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        assert!(store.contains(&policy("baseline-safe")).expect("contains"));
        let snap = store.snapshot().expect("snap");
        assert_eq!(snap.policy_ids, vec![policy("baseline-safe")]);
        assert!(store
            .contains_for_class(&policy("baseline-safe"), &class("coding"))
            .expect("class"));
    }

    #[test]
    fn promotion_requires_lcb_threshold_per_task_class() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let candidate = policy("candidate");
        let coding = class("coding");
        store
            .set_threshold(&coding, PromotionThreshold { lcb_bp: 7_000 })
            .expect("threshold");

        for _ in 0..20 {
            store
                .record_outcome(&candidate, &coding, true)
                .expect("record");
        }
        let promoted = store
            .promote(direct_promotion(
                &candidate,
                &coding,
                TimestampMillis::from_millis(1),
                EvaluationFidelity::F5ProductionShadow,
            ))
            .expect("promote");
        assert_eq!(promoted.kind, PromotionDecisionKind::Promoted);
        assert!(store.contains(&candidate).expect("contains"));

        let docs = class("docs");
        store
            .set_threshold(&docs, PromotionThreshold { lcb_bp: 9_500 })
            .expect("threshold");
        store
            .record_outcome(&candidate, &docs, true)
            .expect("record");
        let rejected = store
            .promote(direct_promotion(
                &candidate,
                &docs,
                TimestampMillis::from_millis(2),
                EvaluationFidelity::F4HiddenValidation,
            ))
            .expect("promote");
        assert_eq!(rejected.kind, PromotionDecisionKind::RejectedBelowLcb);
        assert!(!store.contains_for_class(&candidate, &docs).expect("class"));
    }

    #[test]
    fn low_fidelity_evidence_cannot_promote_even_with_perfect_lcb() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let candidate = policy("candidate");
        let coding = class("coding");
        store
            .set_threshold(&coding, PromotionThreshold { lcb_bp: 1_000 })
            .expect("threshold");
        for _ in 0..30 {
            store
                .record_outcome(&candidate, &coding, true)
                .expect("record");
        }
        for fidelity in [
            EvaluationFidelity::F0StaticPrediction,
            EvaluationFidelity::F1CheapRepoProbe,
            EvaluationFidelity::F2PartialTrajectory,
            EvaluationFidelity::F3HistoricalReplay,
        ] {
            let rejected = store
                .promote(direct_promotion(
                    &candidate,
                    &coding,
                    TimestampMillis::from_millis(3),
                    fidelity,
                ))
                .expect("promote");
            assert_eq!(
                rejected.kind,
                PromotionDecisionKind::RejectedInsufficientFidelity
            );
        }
        assert!(!store.contains(&candidate).expect("contains"));
    }

    #[test]
    fn demotion_removes_from_production_selection_but_baseline_is_retained() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let candidate = policy("candidate");
        let coding = class("coding");
        store
            .set_threshold(&coding, PromotionThreshold { lcb_bp: 1_000 })
            .expect("threshold");
        promote_with_successes(&store, &candidate, &coding, 30);
        let demoted = store
            .demote(&candidate, &coding, TimestampMillis::from_millis(4))
            .expect("demote");
        assert_eq!(demoted.kind, PromotionDecisionKind::Demoted);
        assert!(!store
            .contains_for_class(&candidate, &coding)
            .expect("class"));

        let retained = store
            .demote(
                &policy("baseline-safe"),
                &coding,
                TimestampMillis::from_millis(5),
            )
            .expect("demote baseline");
        assert_eq!(retained.kind, PromotionDecisionKind::BaselineRetained);
        assert!(store
            .contains_for_class(&policy("baseline-safe"), &coding)
            .expect("baseline"));
    }

    #[test]
    fn exploration_is_rejected_when_it_would_dip_into_frontier_reserve() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        // remaining 100, reserve 60, emergency 20 => optional budget 20
        let resources = pool(100, 60, 20);
        let err = store
            .admit_exploration(
                &resources,
                &ExplorationBudgetRequest {
                    pool: ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
                    demand: Quantity::new(25),
                },
            )
            .expect_err("must reject");
        assert!(matches!(err, OptimizerError::FrontierReserveViolation(_)));

        store
            .admit_exploration(
                &resources,
                &ExplorationBudgetRequest {
                    pool: ResourceDimensionId::well_known(ResourceDimensionId::API_COST_USD),
                    demand: Quantity::new(20),
                },
            )
            .expect("optional budget is admissible");
    }

    #[test]
    fn production_selection_never_leaves_the_safe_set() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let coding = class("coding");
        store
            .set_threshold(&coding, PromotionThreshold { lcb_bp: 1_000 })
            .expect("threshold");
        let outsider = policy("not-promoted");
        for _ in 0..20 {
            store
                .record_outcome(&outsider, &coding, true)
                .expect("record");
        }
        let selected = store
            .select_from_safe_set(&coding, ExplorationMethod::ThompsonSampling, 7)
            .expect("select");
        assert_eq!(selected, policy("baseline-safe"));
        assert!(!store.contains(&outsider).expect("outsider"));
    }

    #[test]
    fn thompson_sampling_and_ucb_choose_among_safe_policies() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let coding = class("coding");
        store
            .set_threshold(&coding, PromotionThreshold { lcb_bp: 500 })
            .expect("threshold");
        let strong = policy("strong");
        promote_with_successes(&store, &strong, &coding, 40);
        let thompson = store
            .select_from_safe_set(&coding, ExplorationMethod::ThompsonSampling, 11)
            .expect("thompson");
        let ucb = store
            .select_from_safe_set(
                &coding,
                ExplorationMethod::Ucb {
                    exploration_bp: 1_000,
                },
                11,
            )
            .expect("ucb");
        let allowed = store.production_candidates(&coding).expect("safe");
        assert!(allowed.contains(&thompson));
        assert!(allowed.contains(&ucb));
    }

    #[test]
    fn weak_priors_cannot_alone_clear_a_strict_threshold() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let candidate = policy("tier-prior");
        let coding = class("coding");
        store
            .set_threshold(&coding, PromotionThreshold { lcb_bp: 8_000 })
            .expect("threshold");
        for _ in 0..8 {
            store
                .record_weak_prior(&candidate, &coding, true)
                .expect("prior");
        }
        let evidence = store.evidence_for(&candidate, &coding).expect("evidence");
        assert_eq!(
            evidence.weak_prior_trials,
            CertificationEvidence::MAX_WEAK_PRIOR_TRIALS
        );
        let rejected = store
            .promote(direct_promotion(
                &candidate,
                &coding,
                TimestampMillis::from_millis(9),
                EvaluationFidelity::F4HiddenValidation,
            ))
            .expect("promote");
        assert_eq!(rejected.kind, PromotionDecisionKind::RejectedBelowLcb);
    }

    #[test]
    fn promotion_events_are_persisted_and_replayable() {
        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let candidate = policy("candidate");
        let coding = class("coding");
        store
            .set_threshold(&coding, PromotionThreshold { lcb_bp: 500 })
            .expect("threshold");
        for _ in 0..10 {
            store
                .record_outcome(&candidate, &coding, true)
                .expect("record");
        }
        store
            .promote(direct_promotion(
                &candidate,
                &coding,
                TimestampMillis::from_millis(9),
                EvaluationFidelity::F5ProductionShadow,
            ))
            .expect("promote");
        let events = store.events_snapshot().expect("events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, PromotionDecisionKind::Promoted);
        assert_eq!(events[0].policy_id, candidate);
        assert_eq!(events[0].fidelity, EvaluationFidelity::F5ProductionShadow);
    }

    #[test]
    fn replay_switch_correction_is_consumed_by_safe_set_promotion() {
        use crate::optimizer::switch_cost::{
            ReplayCorrectionEvidence, ReplaySwitchEstimate, REPLAY_UNCORRECTED_LABEL,
        };

        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let candidate = policy("candidate");
        let coding = class("coding");
        store
            .set_threshold(&coding, PromotionThreshold { lcb_bp: 500 })
            .expect("threshold");
        for _ in 0..30 {
            store
                .record_outcome(&candidate, &coding, true)
                .expect("record");
        }

        let mut replay_snapshot = DecisionSnapshot::new(
            super::super::ids::CatalogVersion::new("test-catalog").expect("catalog"),
            1,
            super::super::objective::PreferenceProfile::shipped_default().attribution(),
        );
        replay_snapshot.selected = Some(candidate.clone());
        replay_snapshot.replay_switch_estimate = Some(ReplaySwitchEstimate::from_replay(1_000));
        let uncorrected = replay_snapshot
            .replay_switch_estimate
            .as_ref()
            .expect("estimate");
        assert_eq!(uncorrected.label, REPLAY_UNCORRECTED_LABEL);
        let rejected = store
            .promote(PromotionRequest {
                policy_id: &candidate,
                task_class: &coding,
                decided_at: TimestampMillis::from_millis(10),
                evidence: PromotionEvidence::ReplayInfluenced {
                    validation_fidelity: EvaluationFidelity::F4HiddenValidation,
                    predicted_gain_micros: 2_000,
                    snapshot: &replay_snapshot,
                },
            })
            .expect("promotion decision");
        assert_eq!(
            rejected.kind,
            PromotionDecisionKind::RejectedSwitchCostUncorrected
        );

        replay_snapshot.replay_switch_estimate =
            Some(ReplaySwitchEstimate::with_measured_correction(
                1_000,
                ReplayCorrectionEvidence::measured(2_500, 8, 2_000, 3_000, "shadow"),
            ));
        let rejected = store
            .promote(PromotionRequest {
                policy_id: &candidate,
                task_class: &coding,
                decided_at: TimestampMillis::from_millis(11),
                evidence: PromotionEvidence::ReplayInfluenced {
                    validation_fidelity: EvaluationFidelity::F4HiddenValidation,
                    predicted_gain_micros: 2_000,
                    snapshot: &replay_snapshot,
                },
            })
            .expect("promotion decision");
        assert_eq!(
            rejected.kind,
            PromotionDecisionKind::RejectedSwitchCostOverturnsGain
        );
        assert!(!store.contains(&candidate).expect("contains"));
    }
}
