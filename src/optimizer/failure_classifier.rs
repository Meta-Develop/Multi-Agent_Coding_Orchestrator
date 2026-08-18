//! Evidence-based progress and failure-mode classification (issue #164).
//!
//! Labels come from recorded trajectory features, never from a model's
//! self-assessment. Model-reported uncertainty is ignored as a decision
//! input. Non-model failures are kept off the localized/structural flags so
//! they cannot poison learned model statistics.

use serde::{Deserialize, Serialize};

use super::error::OptimizerError;
use super::features::{
    keys, FeatureBag, FeatureExtractor, SnapshotFeatureExtractor, TrajectoryFeatures,
};
use super::ids::TimestampMillis;
use super::policy::TransitionEvidence;
use super::trajectory::{TrajectoryHistory, TrajectoryObservation};

/// Classifier output at a checkpoint. Routing implications:
/// `LocalizedFailure` → precision-repair eligible;
/// `StructuralFailure` → clean-restart eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryLabel {
    MakingProgress,
    CompletedPendingCertification,
    LocalizedFailure,
    StructuralFailure,
    OracleFailure,
    EnvironmentFailure,
    ProviderFailure,
    QuotaFailure,
    NoProgress,
    UnsafeScopeExpansion,
}

impl TrajectoryLabel {
    pub fn precision_repair_eligible(self) -> bool {
        matches!(self, Self::LocalizedFailure)
    }

    pub fn clean_restart_eligible(self) -> bool {
        matches!(self, Self::StructuralFailure)
    }

    /// Map onto the core transition vocabulary without adding variants there.
    pub fn to_transition_evidence(self) -> TransitionEvidence {
        match self {
            Self::MakingProgress => TransitionEvidence {
                progress_above_threshold: true,
                ..TransitionEvidence::default()
            },
            Self::CompletedPendingCertification => TransitionEvidence {
                progress_above_threshold: true,
                certification_passed: None,
                ..TransitionEvidence::default()
            },
            Self::LocalizedFailure => TransitionEvidence {
                localized_failure: true,
                ..TransitionEvidence::default()
            },
            Self::StructuralFailure => TransitionEvidence {
                structural_failure: true,
                ..TransitionEvidence::default()
            },
            Self::OracleFailure => TransitionEvidence {
                human_escalation_required: true,
                ..TransitionEvidence::default()
            },
            Self::EnvironmentFailure | Self::ProviderFailure => TransitionEvidence::default(),
            Self::QuotaFailure => TransitionEvidence {
                quota_pressure: true,
                ..TransitionEvidence::default()
            },
            Self::NoProgress => TransitionEvidence {
                no_progress: true,
                ..TransitionEvidence::default()
            },
            Self::UnsafeScopeExpansion => TransitionEvidence {
                human_escalation_required: true,
                ..TransitionEvidence::default()
            },
        }
    }
}

/// Stored label plus eventual ground truth so misclassification is auditable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassificationRecord {
    pub schema_version: u32,
    pub label: TrajectoryLabel,
    pub evidence: TransitionEvidence,
    pub classified_at: TimestampMillis,
    pub ground_truth_certification: Option<bool>,
    pub ground_truth_label: Option<TrajectoryLabel>,
}

impl ClassificationRecord {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn misclassified(&self) -> Option<bool> {
        self.ground_truth_label.map(|truth| truth != self.label)
    }

    pub fn with_ground_truth(mut self, label: TrajectoryLabel, certified: Option<bool>) -> Self {
        self.ground_truth_label = Some(label);
        self.ground_truth_certification = certified;
        self
    }
}

/// Evidence-only restart context. There is no field for free-form model
/// reasoning — the type itself makes an unverified chain unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RestartHandoff {
    pub specification: String,
    pub repository_snapshot: String,
    pub observed_diff: String,
    pub command_outputs: Vec<String>,
    pub test_evidence: Vec<String>,
    pub stack_traces: Vec<String>,
    pub changed_paths: Vec<String>,
    pub failure_signatures: Vec<String>,
}

impl RestartHandoff {
    pub fn from_evidence(evidence: RestartHandoff) -> Self {
        evidence
    }
}

/// Deterministic thresholds. Defaults are conservative and fixture-stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifierThresholds {
    pub no_progress_after_ms: u64,
    pub structural_repetition: u32,
    pub structural_reverts: u32,
    pub localized_changed_file_bound: u32,
    pub unsafe_scope_growth_micro: i64,
}

impl Default for ClassifierThresholds {
    fn default() -> Self {
        Self {
            no_progress_after_ms: 30_000,
            structural_repetition: 3,
            structural_reverts: 2,
            localized_changed_file_bound: 3,
            unsafe_scope_growth_micro: 750_000,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceBasedClassifier {
    thresholds: ClassifierThresholds,
}

impl EvidenceBasedClassifier {
    pub fn new(thresholds: ClassifierThresholds) -> Self {
        Self { thresholds }
    }

    pub fn classify_label(
        &self,
        history: &TrajectoryHistory,
    ) -> Result<TrajectoryLabel, OptimizerError> {
        let features = history
            .latest_features()
            .cloned()
            .unwrap_or_else(TrajectoryFeatures::new);
        Ok(self.label_from_features(&features, history.last_observation()))
    }

    pub fn classify_record(
        &self,
        history: &TrajectoryHistory,
        classified_at: TimestampMillis,
    ) -> Result<ClassificationRecord, OptimizerError> {
        let label = self.classify_label(history)?;
        let mut evidence = label.to_transition_evidence();
        if matches!(
            history.last_observation(),
            Some(TrajectoryObservation::Certified)
        ) {
            evidence.certification_passed = Some(true);
        }
        if matches!(
            history.last_observation(),
            Some(TrajectoryObservation::FailedCertification)
        ) {
            evidence.certification_passed = Some(false);
        }
        Ok(ClassificationRecord {
            schema_version: ClassificationRecord::SCHEMA_VERSION,
            label,
            evidence,
            classified_at,
            ground_truth_certification: None,
            ground_truth_label: None,
        })
    }

    pub fn label_from_features(
        &self,
        features: &FeatureBag,
        last_observation: Option<&TrajectoryObservation>,
    ) -> TrajectoryLabel {
        let failing = int(features, keys::TRAJ_FAILING_TEST_COUNT);
        let compiler = int(features, keys::TRAJ_COMPILER_ERROR_COUNT);
        let repetition = int(features, keys::TRAJ_ERROR_SIGNATURE_REPETITION);
        let changed = int(features, keys::TRAJ_CHANGED_FILE_COUNT);
        let scope = int(features, keys::TRAJ_SCOPE_GROWTH_RATE_MICRO);
        let churn = int(features, keys::TRAJ_DIFF_CHURN);
        let reverted = int(features, keys::TRAJ_REVERTED_CHANGES);
        let idle = int(features, keys::TRAJ_TIME_SINCE_LAST_PROGRESS_MS);
        let test_delta = int(features, keys::TRAJ_TEST_DELTA_PER_TURN);
        let coverage_delta = int(features, keys::TRAJ_REQUIREMENT_COVERAGE_DELTA_MICRO);
        let env_errors = int(features, keys::TRAJ_ENVIRONMENT_ERROR_COUNT);
        let provider_errors = int(features, keys::TRAJ_PROVIDER_ERROR_COUNT);
        let new_dep = flag(features, keys::TRAJ_NEW_DEPENDENCY_INTRODUCTION);
        let public_api_break = flag(features, keys::TRAJ_PUBLIC_API_BREAK);
        let oracle = flag(features, keys::TRAJ_ORACLE_INCONSISTENT);
        let quota = flag(features, keys::TRAJ_QUOTA_EXHAUSTED);
        let certified = flag(features, keys::TRAJ_CERTIFIED);
        let reproduction = flag(features, keys::TRAJ_REPRODUCTION_ACHIEVED);

        // Non-model failures first so they cannot be attributed to the policy.
        if oracle {
            return TrajectoryLabel::OracleFailure;
        }
        if env_errors > 0 {
            return TrajectoryLabel::EnvironmentFailure;
        }
        if provider_errors > 0 {
            return TrajectoryLabel::ProviderFailure;
        }
        if quota || matches!(last_observation, Some(TrajectoryObservation::QuotaPressure)) {
            return TrajectoryLabel::QuotaFailure;
        }

        let unsafe_scope = scope >= self.thresholds.unsafe_scope_growth_micro
            && (new_dep || changed > i64::from(self.thresholds.localized_changed_file_bound));
        if unsafe_scope {
            return TrajectoryLabel::UnsafeScopeExpansion;
        }

        let structural = public_api_break
            || (repetition >= i64::from(self.thresholds.structural_repetition)
                && reverted >= i64::from(self.thresholds.structural_reverts))
            || (new_dep && scope >= 500_000)
            || (coverage_delta < 0
                && changed > i64::from(self.thresholds.localized_changed_file_bound));
        if structural {
            return TrajectoryLabel::StructuralFailure;
        }

        let localized = (compiler > 0
            && changed > 0
            && changed <= i64::from(self.thresholds.localized_changed_file_bound)
            && repetition < i64::from(self.thresholds.structural_repetition))
            || (failing > 0
                && failing <= 3
                && changed <= i64::from(self.thresholds.localized_changed_file_bound)
                && repetition < i64::from(self.thresholds.structural_repetition));
        if localized {
            return TrajectoryLabel::LocalizedFailure;
        }

        if certified || matches!(last_observation, Some(TrajectoryObservation::Certified)) {
            return TrajectoryLabel::CompletedPendingCertification;
        }

        let pending_cert =
            reproduction && failing == 0 && compiler == 0 && changed > 0 && !certified;
        if pending_cert {
            return TrajectoryLabel::CompletedPendingCertification;
        }

        let making_progress = test_delta > 0
            || coverage_delta > 0
            || (idle < i64::try_from(self.thresholds.no_progress_after_ms).unwrap_or(i64::MAX)
                && (churn > 0 || changed > 0)
                && failing == 0);
        if making_progress {
            return TrajectoryLabel::MakingProgress;
        }

        TrajectoryLabel::NoProgress
    }
}

impl FailureClassifier for EvidenceBasedClassifier {
    fn classify(&self, history: &TrajectoryHistory) -> Result<TransitionEvidence, OptimizerError> {
        Ok(self.classify_label(history)?.to_transition_evidence())
    }
}

pub trait FailureClassifier {
    fn classify(&self, history: &TrajectoryHistory) -> Result<TransitionEvidence, OptimizerError>;
}

fn int(features: &FeatureBag, key: &str) -> i64 {
    features.integer(key).unwrap_or(0)
}

fn flag(features: &FeatureBag, key: &str) -> bool {
    features.boolean(key).unwrap_or(false)
}

/// Build a history event's feature bag from a recorded checkpoint so tests
/// and live extractors share one schema.
pub fn features_from_extractor(extractor: &SnapshotFeatureExtractor) -> TrajectoryFeatures {
    extractor.extract_trajectory()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::features::{
        RecordedFeatureInputs, RecordedRepoInput, RecordedTaskInput, RecordedTrajectoryInput,
        FEATURE_SCHEMA_VERSION,
    };
    use crate::optimizer::ids::{PolicyId, PolicyNodeId};
    use crate::optimizer::policy::TransitionCondition;

    fn history_from(input: RecordedTrajectoryInput) -> TrajectoryHistory {
        let extractor = SnapshotFeatureExtractor::new(RecordedFeatureInputs {
            schema_version: FEATURE_SCHEMA_VERSION,
            task: RecordedTaskInput::default(),
            repo: RecordedRepoInput::default(),
            trajectory: input,
        });
        let mut history = TrajectoryHistory::new();
        history.push(crate::optimizer::trajectory::TrajectoryEvent {
            at: TimestampMillis::from_millis(10),
            policy_id: PolicyId::new("policy").expect("policy"),
            node_id: PolicyNodeId::new("execute").expect("node"),
            observation: TrajectoryObservation::Started,
            features: features_from_extractor(&extractor),
        });
        history
    }

    fn classify(input: RecordedTrajectoryInput) -> (TrajectoryLabel, TransitionEvidence) {
        let history = history_from(input);
        let classifier = EvidenceBasedClassifier::default();
        let label = classifier.classify_label(&history).expect("label");
        let evidence = classifier.classify(&history).expect("evidence");
        (label, evidence)
    }

    fn base() -> RecordedTrajectoryInput {
        RecordedTrajectoryInput {
            schema_version: FEATURE_SCHEMA_VERSION,
            ..RecordedTrajectoryInput::default()
        }
    }

    #[test]
    fn fixtures_cover_every_label() {
        let cases = [
            (
                RecordedTrajectoryInput {
                    test_delta_per_turn: 2,
                    requirement_coverage_delta_micro: 100_000,
                    time_since_last_progress_ms: 500,
                    ..base()
                },
                TrajectoryLabel::MakingProgress,
            ),
            (
                RecordedTrajectoryInput {
                    reproduction_achieved: true,
                    failing_test_count: 0,
                    compiler_error_count: 0,
                    changed_file_count: 2,
                    certified: false,
                    ..base()
                },
                TrajectoryLabel::CompletedPendingCertification,
            ),
            (
                RecordedTrajectoryInput {
                    compiler_error_count: 1,
                    changed_file_count: 1,
                    failing_test_count: 1,
                    error_signature_repetition: 1,
                    ..base()
                },
                TrajectoryLabel::LocalizedFailure,
            ),
            (
                RecordedTrajectoryInput {
                    error_signature_repetition: 4,
                    reverted_changes: 3,
                    changed_file_count: 6,
                    public_api_break: true,
                    ..base()
                },
                TrajectoryLabel::StructuralFailure,
            ),
            (
                RecordedTrajectoryInput {
                    oracle_inconsistent: true,
                    failing_test_count: 2,
                    ..base()
                },
                TrajectoryLabel::OracleFailure,
            ),
            (
                RecordedTrajectoryInput {
                    environment_error_count: 1,
                    ..base()
                },
                TrajectoryLabel::EnvironmentFailure,
            ),
            (
                RecordedTrajectoryInput {
                    provider_error_count: 2,
                    ..base()
                },
                TrajectoryLabel::ProviderFailure,
            ),
            (
                RecordedTrajectoryInput {
                    quota_exhausted: true,
                    ..base()
                },
                TrajectoryLabel::QuotaFailure,
            ),
            (
                RecordedTrajectoryInput {
                    time_since_last_progress_ms: 90_000,
                    test_delta_per_turn: 0,
                    ..base()
                },
                TrajectoryLabel::NoProgress,
            ),
            (
                RecordedTrajectoryInput {
                    scope_growth_rate_micro: 900_000,
                    new_dependency_introduction: true,
                    changed_file_count: 8,
                    ..base()
                },
                TrajectoryLabel::UnsafeScopeExpansion,
            ),
        ];

        let mut seen = Vec::new();
        for (input, expected) in cases {
            let (label, evidence) = classify(input);
            assert_eq!(label, expected);
            assert_eq!(evidence, expected.to_transition_evidence());
            seen.push(label);
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn localized_failure_is_precision_repair_eligible() {
        let (label, evidence) = classify(RecordedTrajectoryInput {
            compiler_error_count: 2,
            changed_file_count: 1,
            error_signature_repetition: 1,
            ..base()
        });
        assert_eq!(label, TrajectoryLabel::LocalizedFailure);
        assert!(label.precision_repair_eligible());
        assert!(!label.clean_restart_eligible());
        assert!(TransitionCondition::LocalizedFailure.matches(&evidence));
        assert!(!TransitionCondition::StructuralFailure.matches(&evidence));
    }

    #[test]
    fn structural_failure_is_clean_restart_eligible() {
        let (label, evidence) = classify(RecordedTrajectoryInput {
            error_signature_repetition: 5,
            reverted_changes: 2,
            changed_file_count: 7,
            ..base()
        });
        assert_eq!(label, TrajectoryLabel::StructuralFailure);
        assert!(label.clean_restart_eligible());
        assert!(!label.precision_repair_eligible());
        assert!(TransitionCondition::StructuralFailure.matches(&evidence));
        assert!(!TransitionCondition::LocalizedFailure.matches(&evidence));
    }

    #[test]
    fn non_model_failures_do_not_set_localized_or_structural_flags() {
        for (input, expected) in [
            (
                RecordedTrajectoryInput {
                    oracle_inconsistent: true,
                    compiler_error_count: 4,
                    ..base()
                },
                TrajectoryLabel::OracleFailure,
            ),
            (
                RecordedTrajectoryInput {
                    environment_error_count: 1,
                    failing_test_count: 4,
                    ..base()
                },
                TrajectoryLabel::EnvironmentFailure,
            ),
            (
                RecordedTrajectoryInput {
                    provider_error_count: 1,
                    public_api_break: true,
                    ..base()
                },
                TrajectoryLabel::ProviderFailure,
            ),
            (
                RecordedTrajectoryInput {
                    quota_exhausted: true,
                    error_signature_repetition: 9,
                    ..base()
                },
                TrajectoryLabel::QuotaFailure,
            ),
        ] {
            let (label, evidence) = classify(input);
            assert_eq!(label, expected);
            assert!(!evidence.localized_failure);
            assert!(!evidence.structural_failure);
        }
    }

    #[test]
    fn restart_handoff_has_no_model_reasoning_field() {
        let handoff = RestartHandoff::from_evidence(RestartHandoff {
            specification: "fix the parser".to_string(),
            repository_snapshot: "sha-abc".to_string(),
            observed_diff: "-a\n+b\n".to_string(),
            command_outputs: vec!["cargo test".to_string()],
            test_evidence: vec!["parse::nested failed".to_string()],
            stack_traces: vec!["thread 'parse' panicked".to_string()],
            changed_paths: vec!["src/parser.rs".to_string()],
            failure_signatures: vec!["E0308".to_string()],
        });
        let value = serde_json::to_value(&handoff).expect("json");
        let object = value.as_object().expect("object");
        assert_eq!(object.len(), 8);
        for key in object.keys() {
            let lowered = key.to_ascii_lowercase();
            assert!(!lowered.contains("reason"));
            assert!(!lowered.contains("rationale"));
            assert!(!lowered.contains("chain"));
            assert!(!lowered.contains("thinking"));
            assert!(!lowered.contains("model"));
        }
    }

    #[test]
    fn classification_is_reproducible_from_recorded_features() {
        let input = RecordedTrajectoryInput {
            compiler_error_count: 1,
            changed_file_count: 1,
            error_signature_repetition: 1,
            ..base()
        };
        let first = classify(input.clone());
        let second = classify(input);
        assert_eq!(first, second);
    }

    #[test]
    fn misclassification_is_measurable_against_ground_truth() {
        let history = history_from(RecordedTrajectoryInput {
            compiler_error_count: 1,
            changed_file_count: 1,
            ..base()
        });
        let classifier = EvidenceBasedClassifier::default();
        let record = classifier
            .classify_record(&history, TimestampMillis::from_millis(99))
            .expect("record")
            .with_ground_truth(TrajectoryLabel::StructuralFailure, Some(false));
        assert_eq!(record.misclassified(), Some(true));
        assert_eq!(record.ground_truth_certification, Some(false));
        let correct = record
            .clone()
            .with_ground_truth(TrajectoryLabel::LocalizedFailure, Some(false));
        assert_eq!(correct.misclassified(), Some(false));
    }

    #[test]
    fn model_reported_uncertainty_does_not_override_evidence() {
        let (label, _) = classify(RecordedTrajectoryInput {
            compiler_error_count: 1,
            changed_file_count: 1,
            model_reported_uncertainty_micro: Some(0),
            ..base()
        });
        assert_eq!(label, TrajectoryLabel::LocalizedFailure);
    }
}
