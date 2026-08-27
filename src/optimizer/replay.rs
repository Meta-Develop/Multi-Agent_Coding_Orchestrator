//! Offline replay, provenance, and certified-equal comparison.
//!
//! The [`ReplayStore`] trait signature is unchanged (`load` only) so later
//! phases can keep implementing it. Durable snapshot types, comparison
//! modes, and certified-equal Pareto live beside that seam.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::certification::CertificationResult;
use super::error::OptimizerError;
use super::explanation::DecisionExplanation;
use super::feasibility::FeasibilityResult;
use super::features::FeatureBag;
use super::ids::{CatalogVersion, ContractId, PolicyId, TimestampMillis, ValidatorId};
use super::objective::{
    annotate_explanation_with_profile, ObjectiveValue, PreferenceAttribution, PreferenceProfile,
};
use super::resources::ResourceVector;
use super::switch_cost::ReplaySwitchEstimate;
use super::telemetry::InvocationRecord;

pub const REPLAY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRecord {
    pub policy_id: PolicyId,
    pub explanation: DecisionExplanation,
    #[serde(default)]
    pub snapshot: Option<DecisionSnapshot>,
}

pub trait ReplayStore {
    fn load(&self, policy_id: &PolicyId) -> Result<Option<ReplayRecord>, OptimizerError>;
}

/// Inputs required to reproduce a router decision bit-identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSnapshot {
    pub schema_version: u32,
    pub optimizer_version: String,
    pub policy_library_version: u32,
    pub catalog_version: CatalogVersion,
    pub prediction_model_version: String,
    pub features: FeatureBag,
    pub budget: ResourceVector,
    pub random_seed: u64,
    pub candidate_set: Vec<PolicyId>,
    pub feasibility_results: Vec<FeasibilityResult>,
    pub objective_values: Vec<ObjectiveValue>,
    pub selected: Option<PolicyId>,
    pub preference: PreferenceAttribution,
    pub decided_at: TimestampMillis,
    /// Offline replay cannot reproduce live cache/session state. This field is
    /// absent on legacy snapshots and carries the measured production
    /// correction required before replay evidence can influence promotion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_switch_estimate: Option<ReplaySwitchEstimate>,
}

impl DecisionSnapshot {
    pub fn new(
        catalog_version: CatalogVersion,
        policy_library_version: u32,
        preference: PreferenceAttribution,
    ) -> Self {
        Self {
            schema_version: REPLAY_SCHEMA_VERSION,
            optimizer_version: env!("CARGO_PKG_VERSION").to_string(),
            policy_library_version,
            catalog_version,
            prediction_model_version: "none".to_string(),
            features: FeatureBag::new(),
            budget: ResourceVector::new(),
            random_seed: 0,
            candidate_set: Vec::new(),
            feasibility_results: Vec::new(),
            objective_values: Vec::new(),
            selected: None,
            preference,
            decided_at: TimestampMillis::from_millis(0),
            replay_switch_estimate: None,
        }
    }
}

/// Reproduce the selected policy from recorded feasibility and objectives.
/// Tie-break is (score, policy_id); the seed is part of the snapshot identity.
pub fn reproduce_decision(snapshot: &DecisionSnapshot) -> Result<Option<PolicyId>, OptimizerError> {
    if snapshot.schema_version != REPLAY_SCHEMA_VERSION {
        return Err(OptimizerError::invalid(format!(
            "unsupported replay schema version {}",
            snapshot.schema_version
        )));
    }
    let feasible: BTreeMap<&str, &FeasibilityResult> = snapshot
        .feasibility_results
        .iter()
        .map(|result| (result.policy_id.as_str(), result))
        .collect();
    let mut ranked: Vec<(&ObjectiveValue, &str)> = snapshot
        .objective_values
        .iter()
        .filter(|value| {
            snapshot
                .candidate_set
                .iter()
                .any(|id| id.as_str() == value.policy_id.as_str())
                && feasible
                    .get(value.policy_id.as_str())
                    .is_some_and(|result| result.feasible)
        })
        .map(|value| (value, value.policy_id.as_str()))
        .collect();
    ranked.sort_by_key(|(value, id)| (value.risk_adjusted_cost_micros, (*id).to_string()));
    Ok(ranked
        .first()
        .map(|(_, id)| PolicyId::new(*id).expect("recorded policy id is non-empty")))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergentField {
    pub name: String,
    pub recorded: String,
    pub replayed: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotComparison {
    pub bit_identical: bool,
    pub same_decision: bool,
    pub divergent_fields: Vec<DivergentField>,
}

pub fn compare_snapshots(
    recorded: &DecisionSnapshot,
    replayed: &DecisionSnapshot,
) -> SnapshotComparison {
    let mut divergent_fields = Vec::new();
    push_field(
        &mut divergent_fields,
        "optimizer_version",
        &recorded.optimizer_version,
        &replayed.optimizer_version,
    );
    push_field(
        &mut divergent_fields,
        "policy_library_version",
        recorded.policy_library_version,
        replayed.policy_library_version,
    );
    push_field(
        &mut divergent_fields,
        "catalog_version",
        recorded.catalog_version.as_str(),
        replayed.catalog_version.as_str(),
    );
    push_field(
        &mut divergent_fields,
        "prediction_model_version",
        &recorded.prediction_model_version,
        &replayed.prediction_model_version,
    );
    push_field(
        &mut divergent_fields,
        "random_seed",
        recorded.random_seed,
        replayed.random_seed,
    );
    push_field(
        &mut divergent_fields,
        "preference_profile",
        recorded.preference.label(),
        replayed.preference.label(),
    );
    if recorded.features != replayed.features {
        divergent_fields.push(DivergentField {
            name: "features".to_string(),
            recorded: format!("{:?}", recorded.features),
            replayed: format!("{:?}", replayed.features),
        });
    }
    if recorded.budget != replayed.budget {
        divergent_fields.push(DivergentField {
            name: "budget".to_string(),
            recorded: "recorded".to_string(),
            replayed: "replayed".to_string(),
        });
    }
    if recorded.candidate_set != replayed.candidate_set {
        divergent_fields.push(DivergentField {
            name: "candidate_set".to_string(),
            recorded: format!("{:?}", recorded.candidate_set),
            replayed: format!("{:?}", replayed.candidate_set),
        });
    }
    let recorded_decision = recorded.selected.clone();
    let replayed_decision = replayed.selected.clone();
    SnapshotComparison {
        bit_identical: recorded == replayed,
        same_decision: recorded_decision == replayed_decision,
        divergent_fields,
    }
}

fn push_field<T: PartialEq + std::fmt::Display>(
    fields: &mut Vec<DivergentField>,
    name: &str,
    recorded: T,
    replayed: T,
) {
    if recorded != replayed {
        fields.push(DivergentField {
            name: name.to_string(),
            recorded: recorded.to_string(),
            replayed: replayed.to_string(),
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayComparisonMode {
    SameBase { repository_digest: String },
    SameSpec { task_spec_digest: String },
    SameValidator { bar: CertificationBar },
}

/// Certification bar that must match before Pareto ranking is licensed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificationBar {
    pub contract_id: ContractId,
    pub validator_ids: Vec<ValidatorId>,
    pub quality_threshold_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributedCost {
    pub invocation: InvocationRecord,
    pub cost_micros: i64,
}

/// Full attributed chain, not first-call cost.
pub fn aggregate_cost_to_certification(chain: &[AttributedCost]) -> i64 {
    chain
        .iter()
        .fold(0_i64, |total, item| total.saturating_add(item.cost_micros))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComparisonArm {
    pub policy_id: PolicyId,
    pub certified: bool,
    pub certification_bar: CertificationBar,
    pub certification: CertificationResult,
    pub cost_to_certification_micros: i64,
    pub latency_micros: i64,
    pub attributed_chain: Vec<AttributedCost>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParetoPoint {
    pub policy_id: PolicyId,
    pub cost_to_certification_micros: i64,
    pub latency_micros: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedEqualReport {
    pub schema_version: u32,
    pub bar: CertificationBar,
    pub frontier: Vec<ParetoPoint>,
    pub dominated: Vec<PolicyId>,
}

/// Pareto over equally certified arms. Differing bars are an explicit error;
/// uncertified arms never share a frontier with certified ones.
pub fn certified_equal_pareto(
    arms: &[ComparisonArm],
) -> Result<CertifiedEqualReport, OptimizerError> {
    if arms.is_empty() {
        return Err(OptimizerError::invalid(
            "certified-equal Pareto requires at least one arm",
        ));
    }
    let bar = arms[0].certification_bar.clone();
    for arm in arms {
        if arm.certification_bar != bar {
            return Err(OptimizerError::invalid(
                "certified-equal Pareto refuses to rank arms whose certification bars differ",
            ));
        }
    }
    let certified: Vec<&ComparisonArm> = arms.iter().filter(|arm| arm.certified).collect();
    let mut frontier = Vec::new();
    let mut dominated = Vec::new();
    for arm in &certified {
        let is_dominated = certified.iter().any(|other| {
            other.policy_id != arm.policy_id
                && other.cost_to_certification_micros <= arm.cost_to_certification_micros
                && other.latency_micros <= arm.latency_micros
                && (other.cost_to_certification_micros < arm.cost_to_certification_micros
                    || other.latency_micros < arm.latency_micros)
        });
        if is_dominated {
            dominated.push(arm.policy_id.clone());
        } else {
            frontier.push(ParetoPoint {
                policy_id: arm.policy_id.clone(),
                cost_to_certification_micros: arm.cost_to_certification_micros,
                latency_micros: arm.latency_micros,
            });
        }
    }
    frontier.sort_by_key(|point| {
        (
            point.cost_to_certification_micros,
            point.latency_micros,
            point.policy_id.as_str().to_string(),
        )
    });
    Ok(CertifiedEqualReport {
        schema_version: REPLAY_SCHEMA_VERSION,
        bar,
        frontier,
        dominated,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutcomeAggregate {
    pub policy_id: PolicyId,
    pub sample_count: u32,
    pub total_cost_micros: i64,
    pub mean_cost_micros: i64,
    pub mean_latency_micros: i64,
}

pub fn aggregate_policy_outcomes(arms: &[ComparisonArm]) -> Vec<PolicyOutcomeAggregate> {
    let mut grouped: BTreeMap<String, (i64, i64, u32, PolicyId)> = BTreeMap::new();
    for arm in arms {
        let entry = grouped
            .entry(arm.policy_id.as_str().to_string())
            .or_insert((0, 0, 0, arm.policy_id.clone()));
        entry.0 = entry.0.saturating_add(arm.cost_to_certification_micros);
        entry.1 = entry.1.saturating_add(arm.latency_micros);
        entry.2 = entry.2.saturating_add(1);
    }
    grouped
        .into_values()
        .map(
            |(total_cost, total_latency, count, policy_id)| PolicyOutcomeAggregate {
                policy_id,
                sample_count: count,
                total_cost_micros: total_cost,
                mean_cost_micros: total_cost / i64::from(count.max(1)),
                mean_latency_micros: total_latency / i64::from(count.max(1)),
            },
        )
        .collect()
}

#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    records: BTreeMap<String, ReplayRecord>,
}

impl MemoryReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store(&mut self, record: ReplayRecord) {
        self.records
            .insert(record.policy_id.as_str().to_string(), record);
    }
}

impl ReplayStore for MemoryReplayStore {
    fn load(&self, policy_id: &PolicyId) -> Result<Option<ReplayRecord>, OptimizerError> {
        Ok(self.records.get(policy_id.as_str()).cloned())
    }
}

pub struct FileReplayStore {
    root: PathBuf,
}

impl FileReplayStore {
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn store(&self, record: &ReplayRecord) -> Result<PathBuf, OptimizerError> {
        fs::create_dir_all(&self.root).map_err(|error| {
            OptimizerError::invalid(format!(
                "create replay store {}: {error}",
                self.root.display()
            ))
        })?;
        let path = self.root.join(format!(
            "replay-v{REPLAY_SCHEMA_VERSION}-{}.json",
            record.policy_id
        ));
        let body = serde_json::to_vec_pretty(record)
            .map_err(|error| OptimizerError::invalid(format!("serialize replay: {error}")))?;
        fs::write(&path, body).map_err(|error| {
            OptimizerError::invalid(format!("write {}: {error}", path.display()))
        })?;
        Ok(path)
    }
}

impl ReplayStore for FileReplayStore {
    fn load(&self, policy_id: &PolicyId) -> Result<Option<ReplayRecord>, OptimizerError> {
        let path = self
            .root
            .join(format!("replay-v{REPLAY_SCHEMA_VERSION}-{policy_id}.json"));
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path).map_err(|error| {
            OptimizerError::invalid(format!("read {}: {error}", path.display()))
        })?;
        let record: ReplayRecord = serde_json::from_slice(&bytes)
            .map_err(|error| OptimizerError::invalid(format!("parse replay: {error}")))?;
        Ok(Some(record))
    }
}

pub fn record_decision(
    snapshot: DecisionSnapshot,
    mut explanation: DecisionExplanation,
    profile: &PreferenceProfile,
) -> Result<ReplayRecord, OptimizerError> {
    annotate_explanation_with_profile(&mut explanation, profile);
    explanation.selected = snapshot.selected.clone();
    explanation.candidate_ids = snapshot.candidate_set.clone();
    let policy_id = snapshot
        .selected
        .clone()
        .unwrap_or_else(|| PolicyId::new("infeasible").expect("id"));
    Ok(ReplayRecord {
        policy_id,
        explanation,
        snapshot: Some(snapshot),
    })
}

/// Replay a stored production decision and compare it to a possibly mutated input.
pub fn replay_recorded_decision(
    record: &ReplayRecord,
    replayed_snapshot: &DecisionSnapshot,
) -> Result<SnapshotComparison, OptimizerError> {
    let recorded = record.snapshot.as_ref().ok_or_else(|| {
        OptimizerError::invalid("replay record is missing a versioned decision snapshot")
    })?;
    let recorded_choice = reproduce_decision(recorded)?;
    if recorded_choice != recorded.selected {
        return Err(OptimizerError::invalid(
            "recorded snapshot does not reproduce its own selected policy",
        ));
    }
    Ok(compare_snapshots(recorded, replayed_snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::CandidateId;
    use crate::optimizer::objective::PreferenceProfileId;
    use crate::optimizer::resources::ResourceSnapshot;
    use tempfile::TempDir;

    fn policy(name: &str) -> PolicyId {
        PolicyId::new(name).expect("policy")
    }

    fn profile() -> PreferenceProfile {
        let mut profile = PreferenceProfile::shipped_default();
        profile.id = PreferenceProfileId::new("default").expect("id");
        profile
    }

    fn snapshot(catalog: &str, selected: &str) -> DecisionSnapshot {
        let preference = profile().attribution();
        let mut snapshot = DecisionSnapshot::new(
            CatalogVersion::new(catalog).expect("catalog"),
            1,
            preference,
        );
        snapshot.candidate_set = vec![policy("cheap"), policy("dear")];
        snapshot.feasibility_results = vec![
            FeasibilityResult {
                policy_id: policy("cheap"),
                feasible: true,
                rejection_reasons: Vec::new(),
            },
            FeasibilityResult {
                policy_id: policy("dear"),
                feasible: true,
                rejection_reasons: Vec::new(),
            },
        ];
        snapshot.objective_values = vec![
            ObjectiveValue {
                policy_id: policy("cheap"),
                risk_adjusted_cost_micros: 10,
                tail_latency_micros: 20,
            },
            ObjectiveValue {
                policy_id: policy("dear"),
                risk_adjusted_cost_micros: 50,
                tail_latency_micros: 5,
            },
        ];
        snapshot.selected = Some(policy(selected));
        snapshot
    }

    fn explanation() -> DecisionExplanation {
        DecisionExplanation {
            decided_at: TimestampMillis::from_millis(1),
            selected: None,
            candidate_ids: Vec::new(),
            rejection_reasons: Vec::new(),
            resources: ResourceSnapshot {
                observed_at: TimestampMillis::from_millis(1),
                vector: ResourceVector::new(),
            },
        }
    }

    fn bar(name: &str) -> CertificationBar {
        CertificationBar {
            contract_id: ContractId::new(name).expect("contract"),
            validator_ids: vec![ValidatorId::new("hidden-tests").expect("validator")],
            quality_threshold_bp: 8_000,
        }
    }

    fn arm(
        id: &str,
        bar: CertificationBar,
        certified: bool,
        cost: i64,
        latency: i64,
    ) -> ComparisonArm {
        ComparisonArm {
            policy_id: policy(id),
            certified,
            certification_bar: bar,
            certification: if certified {
                let mut result = CertificationResult::rejected();
                result.certified = true;
                result
            } else {
                CertificationResult::rejected()
            },
            cost_to_certification_micros: cost,
            latency_micros: latency,
            attributed_chain: vec![
                AttributedCost {
                    invocation: {
                        let mut record = InvocationRecord::new(
                            policy(id),
                            CandidateId::new(id).expect("candidate"),
                            TimestampMillis::from_millis(1),
                            ResourceSnapshot {
                                observed_at: TimestampMillis::from_millis(1),
                                vector: ResourceVector::new(),
                            },
                        );
                        record.finished_at = Some(TimestampMillis::from_millis(2));
                        record
                    },
                    cost_micros: cost / 2,
                },
                AttributedCost {
                    invocation: {
                        let mut record = InvocationRecord::new(
                            policy(id),
                            CandidateId::new(format!("{id}-repair")).expect("candidate"),
                            TimestampMillis::from_millis(3),
                            ResourceSnapshot {
                                observed_at: TimestampMillis::from_millis(3),
                                vector: ResourceVector::new(),
                            },
                        );
                        record.finished_at = Some(TimestampMillis::from_millis(4));
                        record
                    },
                    cost_micros: cost - cost / 2,
                },
            ],
        }
    }

    #[test]
    fn recorded_decision_replays_bit_identically_and_catalog_mutation_diverges() {
        let recorded = snapshot("cat-1", "cheap");
        assert_eq!(
            reproduce_decision(&recorded).expect("reproduce"),
            Some(policy("cheap"))
        );
        let mut store = MemoryReplayStore::new();
        let record = record_decision(recorded.clone(), explanation(), &profile()).expect("record");
        assert!(record
            .explanation
            .rejection_reasons
            .iter()
            .any(|reason| reason == "preference_profile:default@1"));
        store.store(record.clone());
        let loaded = store
            .load(&policy("cheap"))
            .expect("load")
            .expect("present");
        let identical = replay_recorded_decision(&loaded, &recorded).expect("replay");
        assert!(identical.bit_identical);
        assert!(identical.same_decision);
        assert!(identical.divergent_fields.is_empty());

        let mut mutated = recorded;
        mutated.catalog_version = CatalogVersion::new("cat-2").expect("catalog");
        let comparison = replay_recorded_decision(&loaded, &mutated).expect("mutated");
        assert!(!comparison.bit_identical);
        assert!(
            comparison
                .divergent_fields
                .iter()
                .any(|field| field.name == "catalog_version"),
            "{comparison:?}"
        );
    }

    #[test]
    fn cost_to_certification_aggregates_the_full_attributed_chain() {
        let arm = arm("chain", bar("c1"), true, 40, 10);
        assert_eq!(arm.attributed_chain.len(), 2);
        assert_eq!(aggregate_cost_to_certification(&arm.attributed_chain), 40);
        assert_ne!(arm.attributed_chain[0].cost_micros, 40);
    }

    #[test]
    fn certified_equal_pareto_refuses_differing_bars_and_excludes_uncertified_arms() {
        let shared = bar("same");
        let mixed = vec![
            arm("cheap-uncertified", shared.clone(), false, 1, 1),
            arm("certified-a", shared.clone(), true, 20, 30),
            arm("certified-b", shared, true, 25, 10),
        ];
        let report = certified_equal_pareto(&mixed).expect("pareto");
        assert_eq!(report.frontier.len(), 2);
        assert!(report
            .frontier
            .iter()
            .all(|point| point.policy_id.as_str() != "cheap-uncertified"));

        let differing = vec![
            arm("a", bar("left"), true, 10, 10),
            arm("b", bar("right"), true, 11, 9),
        ];
        let error = certified_equal_pareto(&differing).expect_err("bars");
        assert!(
            error.to_string().contains("certification bars differ"),
            "{error}"
        );
    }

    #[test]
    fn file_replay_store_round_trips_a_versioned_schema() {
        let temp = TempDir::new().expect("tempdir");
        let store = FileReplayStore::open(temp.path());
        let record =
            record_decision(snapshot("cat-1", "cheap"), explanation(), &profile()).expect("record");
        store.store(&record).expect("store");
        let loaded = ReplayStore::load(&store, &policy("cheap"))
            .expect("load")
            .expect("present");
        assert_eq!(
            loaded.snapshot.unwrap().schema_version,
            REPLAY_SCHEMA_VERSION
        );
    }

    #[test]
    fn replay_snapshot_carries_measured_switch_correction_provenance() {
        let correction = super::super::switch_cost::ReplayCorrectionEvidence::measured(
            2_500,
            12,
            2_000,
            3_000,
            "production-shadow/session-pairs",
        );
        let mut recorded = snapshot("cat-1", "cheap");
        recorded.replay_switch_estimate = Some(
            super::super::switch_cost::ReplaySwitchEstimate::with_measured_correction(
                1_000, correction,
            ),
        );
        let record = record_decision(recorded, explanation(), &profile()).expect("record");
        let body = serde_json::to_vec(&record).expect("serialize");
        let restored: ReplayRecord = serde_json::from_slice(&body).expect("restore");
        let evidence = restored
            .snapshot
            .expect("snapshot")
            .replay_switch_estimate
            .expect("switch correction");
        assert_eq!(evidence.correction_sample_count, 12);
        assert_eq!(
            evidence.correction_provenance.as_deref(),
            Some("production-shadow/session-pairs")
        );
        assert_eq!(evidence.corrected_cost_micros, Some(2_500));
    }

    #[test]
    fn recorded_replay_uses_canonical_safe_set_promotion_entrypoint() {
        use crate::optimizer::safe_set::{
            EvaluationFidelity, InMemorySafeSetStore, PromotionDecisionKind, PromotionEvidence,
            PromotionRequest, PromotionThreshold, SafeSetStore, TaskClass,
        };
        use crate::optimizer::switch_cost::{ReplayCorrectionEvidence, ReplaySwitchEstimate};

        let store = InMemorySafeSetStore::cold_start(policy("baseline-safe"));
        let candidate = policy("cheap");
        let task_class = TaskClass::new("coding").expect("task class");
        store
            .set_threshold(&task_class, PromotionThreshold { lcb_bp: 500 })
            .expect("threshold");
        for _ in 0..30 {
            store
                .record_outcome(&candidate, &task_class, true)
                .expect("record outcome");
        }

        let uncorrected = record_decision(snapshot("cat-1", "cheap"), explanation(), &profile())
            .expect("record replay");
        let rejected = store
            .promote(PromotionRequest {
                policy_id: &candidate,
                task_class: &task_class,
                decided_at: TimestampMillis::from_millis(10),
                evidence: PromotionEvidence::ReplayInfluenced {
                    validation_fidelity: EvaluationFidelity::F4HiddenValidation,
                    predicted_gain_micros: 2_000,
                    snapshot: uncorrected.snapshot.as_ref().expect("snapshot"),
                },
            })
            .expect("promotion decision");
        assert_eq!(
            rejected.kind,
            PromotionDecisionKind::RejectedSwitchCostUncorrected
        );

        let mut corrected_snapshot = snapshot("cat-1", "cheap");
        corrected_snapshot.replay_switch_estimate =
            Some(ReplaySwitchEstimate::with_measured_correction(
                1_000,
                ReplayCorrectionEvidence::measured(
                    1_500,
                    8,
                    1_200,
                    1_800,
                    "production-shadow/session-pairs",
                ),
            ));
        let corrected = record_decision(corrected_snapshot, explanation(), &profile())
            .expect("corrected replay");
        let promoted = store
            .promote(PromotionRequest {
                policy_id: &candidate,
                task_class: &task_class,
                decided_at: TimestampMillis::from_millis(11),
                evidence: PromotionEvidence::ReplayInfluenced {
                    validation_fidelity: EvaluationFidelity::F4HiddenValidation,
                    predicted_gain_micros: 2_000,
                    snapshot: corrected.snapshot.as_ref().expect("snapshot"),
                },
            })
            .expect("promotion decision");
        assert_eq!(promoted.kind, PromotionDecisionKind::Promoted);
        assert!(store.contains(&candidate).expect("contains"));
    }
}
