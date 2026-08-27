//! Historical rescoring of validated, stored evaluation documents.
//!
//! Rescoring leaves the stored document and its original scoring provenance
//! untouched. The envelope records the newly applied profile and only the
//! preference-bearing selection recomputed from the stored preference-free
//! Pareto evidence.

use super::{
    invalid_results, select_evaluation_frontier, select_experiment_frontier, EvaluationError,
    EvaluationManifest, EvaluationObjectiveEvidence, EvaluationResults, ExperimentManifest,
    ExperimentResults, ObjectiveScoringKind,
};
use crate::objective_profile::{
    ObjectiveProfileBinding, ObjectiveProfileSource, ObjectiveSelection, ResolvedObjectiveProfile,
};
use serde::{Deserialize, Serialize};

pub const HISTORICAL_RESCORE_SCHEMA_VERSION: u32 = 1;

/// Identifies a scoring operation that was applied after the stored run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalRescoreKind {
    HistoricalRescore,
}

/// Strict output envelope shared by the two stored evaluation-result families.
///
/// `stored_results` retains the complete original document, including its
/// original objective binding and selection. `objective_selection` is the only
/// result recomputed under `applied_profile`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalRescore<T> {
    pub version: u32,
    pub kind: HistoricalRescoreKind,
    pub original_profile: ObjectiveProfileBinding,
    pub applied_profile: ObjectiveProfileBinding,
    pub stored_results: T,
    pub objective_selection: Option<ObjectiveSelection>,
}

pub type EvaluationHistoricalRescore = HistoricalRescore<EvaluationResults>;
pub type ExperimentHistoricalRescore = HistoricalRescore<ExperimentResults>;

/// Re-score one validated evaluation result without changing its stored
/// observations, aggregates, frontier, or original scoring provenance.
pub fn rescore_evaluation_results(
    manifest: &EvaluationManifest,
    stored_results: &EvaluationResults,
    applied_profile: ResolvedObjectiveProfile,
) -> Result<EvaluationHistoricalRescore, EvaluationError> {
    stored_results.validate_against(manifest)?;
    let original_profile = original_evaluation_profile(stored_results)?.profile.clone();
    let applied_profile = applied_profile.profile;
    validate_profile_binding("applied_profile", &applied_profile)?;
    let selection_profile = selection_profile(&applied_profile);
    let objective_selection = select_evaluation_frontier(
        &selection_profile,
        &stored_results.profile_summaries,
        &stored_results.pareto_frontier,
    )?;
    let rescore = HistoricalRescore {
        version: HISTORICAL_RESCORE_SCHEMA_VERSION,
        kind: HistoricalRescoreKind::HistoricalRescore,
        original_profile,
        applied_profile,
        stored_results: stored_results.clone(),
        objective_selection,
    };
    rescore.validate_against(manifest)?;
    Ok(rescore)
}

/// Re-score one validated isolated-experiment result without changing its
/// stored observations, aggregates, frontier, or original scoring provenance.
pub fn rescore_experiment_results(
    manifest: &ExperimentManifest,
    stored_results: &ExperimentResults,
    applied_profile: ResolvedObjectiveProfile,
) -> Result<ExperimentHistoricalRescore, EvaluationError> {
    stored_results.validate_against(manifest)?;
    let original_profile = original_experiment_profile(stored_results)?.profile.clone();
    let applied_profile = applied_profile.profile;
    validate_profile_binding("applied_profile", &applied_profile)?;
    let selection_profile = selection_profile(&applied_profile);
    let objective_selection = select_experiment_frontier(
        &selection_profile,
        &stored_results.profile_summaries,
        &stored_results.pareto_frontier,
    )?;
    let rescore = HistoricalRescore {
        version: HISTORICAL_RESCORE_SCHEMA_VERSION,
        kind: HistoricalRescoreKind::HistoricalRescore,
        original_profile,
        applied_profile,
        stored_results: stored_results.clone(),
        objective_selection,
    };
    rescore.validate_against(manifest)?;
    Ok(rescore)
}

impl HistoricalRescore<EvaluationResults> {
    /// Validate the source document and every rescore-specific invariant.
    pub fn validate_against(&self, manifest: &EvaluationManifest) -> Result<(), EvaluationError> {
        validate_envelope_header(self.version, self.kind)?;
        self.stored_results.validate_against(manifest)?;
        let stored_original = original_evaluation_profile(&self.stored_results)?;
        validate_envelope_profiles(
            stored_original,
            &self.original_profile,
            &self.applied_profile,
        )?;
        let selection_profile = selection_profile(&self.applied_profile);
        let expected = select_evaluation_frontier(
            &selection_profile,
            &self.stored_results.profile_summaries,
            &self.stored_results.pareto_frontier,
        )?;
        validate_selection(&self.objective_selection, &expected)
    }
}

impl HistoricalRescore<ExperimentResults> {
    /// Validate the source document and every rescore-specific invariant.
    pub fn validate_against(&self, manifest: &ExperimentManifest) -> Result<(), EvaluationError> {
        validate_envelope_header(self.version, self.kind)?;
        self.stored_results.validate_against(manifest)?;
        let stored_original = original_experiment_profile(&self.stored_results)?;
        validate_envelope_profiles(
            stored_original,
            &self.original_profile,
            &self.applied_profile,
        )?;
        let selection_profile = selection_profile(&self.applied_profile);
        let expected = select_experiment_frontier(
            &selection_profile,
            &self.stored_results.profile_summaries,
            &self.stored_results.pareto_frontier,
        )?;
        validate_selection(&self.objective_selection, &expected)
    }
}

fn original_evaluation_profile(
    results: &EvaluationResults,
) -> Result<&ResolvedObjectiveProfile, EvaluationError> {
    match &results.objective_scoring {
        EvaluationObjectiveEvidence::Scored(scoring)
            if scoring.kind == ObjectiveScoringKind::Original =>
        {
            Ok(&scoring.applied_profile)
        }
        EvaluationObjectiveEvidence::Scored(_) => Err(invalid_results(
            "stored_results.objective_scoring.kind",
            "historical rescoring requires a stored result with original scoring provenance",
        )),
        EvaluationObjectiveEvidence::Legacy(_) => Err(invalid_results(
            "stored_results.objective_scoring",
            "historical rescoring requires a canonical stored objective binding",
        )),
    }
}

fn original_experiment_profile(
    results: &ExperimentResults,
) -> Result<&ResolvedObjectiveProfile, EvaluationError> {
    match results.objective_scoring.as_ref() {
        Some(scoring) if scoring.kind == ObjectiveScoringKind::Original => {
            Ok(&scoring.applied_profile)
        }
        Some(_) => Err(invalid_results(
            "stored_results.objective_scoring.kind",
            "historical rescoring requires a stored result with original scoring provenance",
        )),
        None => Err(invalid_results(
            "stored_results.objective_scoring",
            "historical rescoring requires a canonical stored objective binding",
        )),
    }
}

fn validate_profile_binding(
    field: &str,
    profile: &ObjectiveProfileBinding,
) -> Result<(), EvaluationError> {
    profile
        .validate()
        .map_err(|error| invalid_results(field, error.to_string()))?;
    Ok(())
}

/// The existing selectors accept a resolved profile but read only its immutable
/// binding. This compatibility wrapper is never serialized; its source value
/// is therefore not claimed as historical provenance.
fn selection_profile(profile: &ObjectiveProfileBinding) -> ResolvedObjectiveProfile {
    ResolvedObjectiveProfile {
        profile: profile.clone(),
        source: ObjectiveProfileSource::BuiltIn,
    }
}

fn validate_envelope_header(
    version: u32,
    kind: HistoricalRescoreKind,
) -> Result<(), EvaluationError> {
    if version != HISTORICAL_RESCORE_SCHEMA_VERSION {
        return Err(invalid_results(
            "version",
            format!(
                "unsupported historical rescore schema version {version}; expected {HISTORICAL_RESCORE_SCHEMA_VERSION}"
            ),
        ));
    }
    if kind != HistoricalRescoreKind::HistoricalRescore {
        return Err(invalid_results(
            "kind",
            "historical rescore output must carry the historical_rescore label",
        ));
    }
    Ok(())
}

fn validate_envelope_profiles(
    stored_original: &ResolvedObjectiveProfile,
    recorded_original: &ObjectiveProfileBinding,
    applied_profile: &ObjectiveProfileBinding,
) -> Result<(), EvaluationError> {
    validate_profile_binding("original_profile", recorded_original)?;
    if recorded_original != &stored_original.profile {
        return Err(invalid_results(
            "original_profile",
            "does not exactly match the stored result's original scoring binding",
        ));
    }
    validate_profile_binding("applied_profile", applied_profile)
}

fn validate_selection(
    recorded: &Option<ObjectiveSelection>,
    expected: &Option<ObjectiveSelection>,
) -> Result<(), EvaluationError> {
    if recorded != expected {
        return Err(invalid_results(
            "objective_selection",
            "does not match the applied profile scored over the stored preference-free frontier",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evaluation::{run_fake_supervise_experiment, EvaluationRunRequest, ExperimentRunRequest},
        llm::provider::Usage,
        objective_profile::{
            ContextSwitchCosts, ObjectiveProfile, ObjectiveProfileSource, QualityWeights,
            TradeoffWeights,
        },
    };

    const EVALUATION_MANIFEST: &str =
        include_str!("../../tests/fixtures/model_mix_evaluation/manifest-v1.json");
    const EVALUATION_PLAN: &[u8] =
        include_bytes!("../../tests/fixtures/model_mix_evaluation/hand-authored-plan-v1.json");
    const EXPERIMENT_MANIFEST: &str =
        include_str!("../../tests/fixtures/model_mix_evaluation/experiment-manifest-v1.json");

    fn applied_profile() -> ResolvedObjectiveProfile {
        let profile = ObjectiveProfile {
            id: "historical-latency-v1".to_string(),
            version: 1,
            quality: QualityWeights {
                held_out_percent: 0,
                breadth_percent: 100,
                anti_shortcut_percent: 0,
            },
            tradeoffs: TradeoffWeights {
                monetary_cost_percent: 0,
                quota_consumption_percent: 0,
                latency_percent: 100,
                retry_rework_percent: 0,
                human_review_percent: 0,
            },
            switch_costs: ContextSwitchCosts::zero(),
            quality_operations_balance: crate::objective_profile::QualityOperationsBalance::default(
            ),
        };
        ResolvedObjectiveProfile {
            profile: profile.binding().expect("bind test objective profile"),
            source: ObjectiveProfileSource::RepositoryOverride,
        }
    }

    fn retain_deterministic_experiment_frontier(stored: &mut ExperimentResults) {
        assert_eq!(stored.profile_summaries.len(), 2);
        for (index, summary) in stored.profile_summaries.iter_mut().enumerate() {
            let (held_out, breadth, overall) = if index == 0 {
                (10_000, 0, 7_500)
            } else {
                (0, 10_000, 5_000)
            };
            summary.aggregate_usage = Some(Usage {
                input_tokens: 80,
                output_tokens: 20,
                total_tokens: 100,
            });
            summary.aggregate_cost_usd = Some(1.0);
            summary.mean_cost_usd = 1.0;
            summary.mean_wall_time_ms = super::super::PreciseMean {
                total: 10,
                count: 1,
            };
            summary.mean_quality = super::super::PreciseQualityScore {
                held_out_basis_points: super::super::PreciseMean {
                    total: held_out,
                    count: 1,
                },
                breadth_basis_points: super::super::PreciseMean {
                    total: breadth,
                    count: 1,
                },
                anti_shortcut_basis_points: super::super::PreciseMean {
                    total: 10_000,
                    count: 1,
                },
                overall_basis_points: super::super::PreciseMean {
                    total: overall,
                    count: 1,
                },
            };
            summary.pareto_optimal = true;
        }
        stored.pareto_conclusion.status = super::super::ParetoConclusionStatus::Available;
        stored.pareto_frontier = stored
            .profile_summaries
            .iter()
            .map(|summary| super::super::ParetoPoint {
                profile_id: summary.profile_id.clone(),
                mean_cost_usd: summary.mean_cost_usd,
                mean_quota_consumption_tokens: Some(super::super::PreciseMean {
                    total: 100,
                    count: 1,
                }),
                mean_wall_time_ms: Some(summary.mean_wall_time_ms),
                quality_basis_points: summary.mean_quality.overall_basis_points,
                held_out_basis_points: summary.mean_quality.held_out_basis_points,
                breadth_basis_points: summary.mean_quality.breadth_basis_points,
                anti_shortcut_basis_points: summary.mean_quality.anti_shortcut_basis_points,
            })
            .collect();
        let original = original_experiment_profile(stored)
            .expect("stored original profile")
            .clone();
        stored.objective_selection = select_experiment_frontier(
            &original,
            &stored.profile_summaries,
            &stored.pareto_frontier,
        )
        .expect("score deterministic stored frontier");
    }

    #[test]
    fn evaluation_rescore_round_trip_preserves_original_document_and_bindings() {
        let mut manifest = serde_json::from_str::<EvaluationManifest>(EVALUATION_MANIFEST)
            .expect("read evaluation manifest");
        manifest.objective_profile = Some(
            crate::objective_profile::default_resolved_objective_profile()
                .expect("resolve original profile"),
        );
        let stored = super::super::run_evaluation(
            &manifest,
            EVALUATION_PLAN,
            EvaluationRunRequest {
                fake_seed: 26,
                ..EvaluationRunRequest::default()
            },
        )
        .expect("create validated stored evaluation");
        let original = original_evaluation_profile(&stored)
            .expect("stored original profile")
            .clone();
        let applied = applied_profile();

        let rescored = rescore_evaluation_results(&manifest, &stored, applied.clone())
            .expect("rescore stored evaluation");

        assert_eq!(rescored.kind, HistoricalRescoreKind::HistoricalRescore);
        assert_eq!(rescored.stored_results, stored);
        assert_eq!(rescored.original_profile, original.profile);
        assert_eq!(rescored.applied_profile, applied.profile);
        assert_eq!(rescored.objective_selection, None);

        let json = serde_json::to_value(&rescored).expect("serialize rescore envelope");
        assert_eq!(json["kind"], "historical_rescore");
        assert_eq!(
            json["stored_results"]["objective_scoring"]["kind"],
            "original"
        );
        assert_eq!(
            json["original_profile"]["content_hash"],
            json["stored_results"]["objective_scoring"]["applied_profile"]["profile"]
                ["content_hash"]
        );
        assert_eq!(json["applied_profile"]["id"], "historical-latency-v1");

        let decoded = serde_json::from_value::<EvaluationHistoricalRescore>(json)
            .expect("deserialize strict rescore envelope");
        decoded
            .validate_against(&manifest)
            .expect("round-tripped rescore remains valid");
        assert_eq!(decoded, rescored);

        let parity = rescore_evaluation_results(&manifest, &stored, original.clone())
            .expect("same-profile historical parity rescore");
        assert_eq!(parity.original_profile, original.profile);
        assert_eq!(parity.applied_profile, parity.original_profile);
        assert_eq!(parity.objective_selection, stored.objective_selection);

        let mut legacy_source = stored.clone();
        legacy_source.objective_scoring =
            EvaluationObjectiveEvidence::Legacy(Some(parity.original_profile.clone()));
        let error = original_evaluation_profile(&legacy_source)
            .expect_err("legacy stored evidence lacks canonical original provenance");
        assert!(error
            .to_string()
            .contains("canonical stored objective binding"));
    }

    #[test]
    fn experiment_rescore_uses_new_profile_scores_and_rejects_forgery() {
        let mut manifest = serde_json::from_str::<ExperimentManifest>(EXPERIMENT_MANIFEST)
            .expect("read experiment manifest");
        manifest.objective_profile = Some(
            crate::objective_profile::default_resolved_objective_profile()
                .expect("resolve original profile"),
        );
        let mut stored = run_fake_supervise_experiment(&manifest, ExperimentRunRequest::default())
            .expect("create validated stored experiment");
        retain_deterministic_experiment_frontier(&mut stored);
        stored
            .validate_against(&manifest)
            .expect("deterministic stored frontier validates");
        let original = original_experiment_profile(&stored)
            .expect("stored original profile")
            .clone();
        let applied = applied_profile();
        let expected = select_experiment_frontier(
            &applied,
            &stored.profile_summaries,
            &stored.pareto_frontier,
        )
        .expect("score stored preference-free frontier");

        let rescored = rescore_experiment_results(&manifest, &stored, applied.clone())
            .expect("rescore stored experiment");

        assert_eq!(rescored.stored_results, stored);
        assert_eq!(rescored.original_profile, original.profile);
        assert_eq!(rescored.applied_profile, applied.profile);
        assert_eq!(rescored.objective_selection, expected);
        let selection = rescored
            .objective_selection
            .as_ref()
            .expect("experiment fixture has a preference-free frontier");
        assert_eq!(selection.profile_id, rescored.applied_profile.id);
        assert_eq!(
            selection.profile_hash,
            rescored.applied_profile.content_hash
        );
        assert_ne!(rescored.objective_selection, stored.objective_selection);
        assert_ne!(
            selection.selected_score,
            stored
                .objective_selection
                .as_ref()
                .expect("original stored selection")
                .selected_score
        );

        let mut forged_original = rescored.clone();
        forged_original.original_profile = forged_original.applied_profile.clone();
        let error = forged_original
            .validate_against(&manifest)
            .expect_err("forged original binding must fail closed");
        assert!(error.to_string().contains("original_profile"));

        let mut forged_selection = rescored.clone();
        forged_selection
            .objective_selection
            .as_mut()
            .expect("selection")
            .selected_score += 0.25;
        let error = forged_selection
            .validate_against(&manifest)
            .expect_err("forged rescore values must fail closed");
        assert!(error.to_string().contains("objective_selection"));

        let mut forged_applied = rescored.clone();
        forged_applied.applied_profile.content_hash = "0".repeat(64);
        let error = forged_applied
            .validate_against(&manifest)
            .expect_err("tampered applied binding must fail closed");
        assert!(error.to_string().contains("applied_profile"));

        let round_trip = serde_json::from_value::<ExperimentHistoricalRescore>(
            serde_json::to_value(&rescored).expect("serialize valid experiment rescore"),
        )
        .expect("deserialize valid experiment rescore");
        round_trip
            .validate_against(&manifest)
            .expect("round-tripped experiment rescore remains valid");
        assert_eq!(round_trip, rescored);

        let mut unsupported = rescored.clone();
        unsupported.version = HISTORICAL_RESCORE_SCHEMA_VERSION + 1;
        let error = unsupported
            .validate_against(&manifest)
            .expect_err("unsupported rescore version must fail closed");
        assert!(error
            .to_string()
            .contains("unsupported historical rescore schema version"));

        let mut malformed = serde_json::to_value(&rescored).expect("serialize rescore envelope");
        malformed
            .as_object_mut()
            .expect("rescore object")
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<ExperimentHistoricalRescore>(malformed).is_err());

        let parity = rescore_experiment_results(&manifest, &stored, original.clone())
            .expect("same-profile historical parity rescore");
        assert_eq!(parity.original_profile, original.profile);
        assert_eq!(parity.applied_profile, parity.original_profile);
        assert_eq!(parity.objective_selection, stored.objective_selection);
    }
}
