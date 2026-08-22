//! Feature bags consumed by [`crate::optimizer::state::OptimizerState`].
//!
//! Issue #163 implements extractors that fill these bags. Keys are open
//! [`FeatureId`]s so new features do not require edits to optimizer core.
//! Extractors are pure with respect to their recorded inputs: the same
//! snapshot always reproduces the same vector.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::ids::FeatureId;
use crate::repo_map::{RepoEntryKind, RepoMap};
use crate::repo_semantic::{SemanticRepoMap, SemanticRiskReport};

/// Current feature-schema version. Old records without this key are treated
/// as version 1 and remain readable.
pub const FEATURE_SCHEMA_VERSION: u32 = 1;

/// Stable feature keys. Schema additions increment [`FEATURE_SCHEMA_VERSION`].
pub mod keys {
    pub const SCHEMA_VERSION: &str = "schema.version";
    pub const EXTRACTION_DURATION_MICROS: &str = "extraction.duration_micros";

    pub const TASK_REQUIREMENT_COUNT: &str = "task.requirement_count";
    pub const TASK_REQUIREMENT_AMBIGUITY_MICRO: &str = "task.requirement_ambiguity_micro";
    pub const TASK_EXPLICIT_INVARIANT_COUNT: &str = "task.explicit_invariant_count";
    pub const TASK_NON_GOAL_COUNT: &str = "task.non_goal_count";
    pub const TASK_ESTIMATED_FILES_AFFECTED: &str = "task.estimated_files_affected";
    pub const TASK_ESTIMATED_MODULES_AFFECTED: &str = "task.estimated_modules_affected";
    pub const TASK_DEPENDENCY_FAN_OUT: &str = "task.dependency_fan_out";
    pub const TASK_PUBLIC_API_IMPACT: &str = "task.public_api_impact";
    pub const TASK_SCHEMA_OR_MIGRATION_IMPACT: &str = "task.schema_or_migration_impact";
    pub const TASK_CONCURRENCY_INVOLVEMENT: &str = "task.concurrency_involvement";
    pub const TASK_SECURITY_SENSITIVITY: &str = "task.security_sensitivity";
    pub const TASK_PERFORMANCE_SENSITIVITY: &str = "task.performance_sensitivity";
    pub const TASK_HARDWARE_OR_ENVIRONMENT_COUPLING: &str = "task.hardware_or_environment_coupling";
    pub const TASK_ROLLBACK_DIFFICULTY_MICRO: &str = "task.rollback_difficulty_micro";
    pub const TASK_TEST_ORACLE_STRENGTH_MICRO: &str = "task.test_oracle_strength_micro";
    pub const TASK_FORMAL_VERIFICATION_AVAILABLE: &str = "task.formal_verification_available";
    pub const TASK_ESTIMATED_CONTEXT_SIZE: &str = "task.estimated_context_size";
    pub const TASK_ESTIMATED_TOOL_STEP_COUNT: &str = "task.estimated_tool_step_count";
    pub const TASK_LANGUAGE: &str = "task.language";
    pub const TASK_FRAMEWORK: &str = "task.framework";
    pub const TASK_HISTORICAL_CLASS_COUNT: &str = "task.historical_class_count";

    pub const REPO_SIZE_BYTES: &str = "repo.size_bytes";
    pub const REPO_FILE_COUNT: &str = "repo.file_count";
    pub const REPO_MODULE_COUNT: &str = "repo.module_count";
    pub const REPO_SYMBOL_COUNT: &str = "repo.symbol_count";
    pub const REPO_DEPENDENCY_EDGE_COUNT: &str = "repo.dependency_edge_count";
    pub const REPO_DEPENDENCY_CENTRALITY_MICRO: &str = "repo.dependency_centrality_micro";
    pub const REPO_TEST_DENSITY_MICRO: &str = "repo.test_density_micro";
    pub const REPO_BUILD_DURATION_MS: &str = "repo.build_duration_ms";
    pub const REPO_HISTORICAL_FLAKY_TESTS: &str = "repo.historical_flaky_tests";
    pub const REPO_FILE_CHURN: &str = "repo.file_churn";
    pub const REPO_OWNERSHIP_BOUNDARY_COUNT: &str = "repo.ownership_boundary_count";
    pub const REPO_MEGAFILE_RISK: &str = "repo.megafile_risk";
    pub const REPO_GENERATED_CODE_FILE_COUNT: &str = "repo.generated_code_file_count";
    pub const REPO_EXTERNAL_SERVICE_DEPENDENCY_COUNT: &str =
        "repo.external_service_dependency_count";
    pub const REPO_UNPARSED_NON_RUST_FILES: &str = "repo.unparsed_non_rust_files";
    pub const REPO_RUST_PARSE_OK: &str = "repo.rust_parse_ok";
    pub const REPO_LANGUAGE_COUNT: &str = "repo.language_count";
    pub const REPO_RISK_IMPACTED_FILES: &str = "repo.risk_impacted_files";

    pub const TRAJ_RELEVANT_FILES_DISCOVERED: &str = "traj.relevant_files_discovered";
    pub const TRAJ_REPRODUCTION_ACHIEVED: &str = "traj.reproduction_achieved";
    pub const TRAJ_FAILING_TEST_COUNT: &str = "traj.failing_test_count";
    pub const TRAJ_PASSING_TEST_COUNT: &str = "traj.passing_test_count";
    pub const TRAJ_COMPILER_ERROR_COUNT: &str = "traj.compiler_error_count";
    pub const TRAJ_ERROR_SIGNATURE_REPETITION: &str = "traj.error_signature_repetition";
    pub const TRAJ_CHANGED_FILE_COUNT: &str = "traj.changed_file_count";
    pub const TRAJ_SCOPE_GROWTH_RATE_MICRO: &str = "traj.scope_growth_rate_micro";
    pub const TRAJ_DIFF_CHURN: &str = "traj.diff_churn";
    pub const TRAJ_REVERTED_CHANGES: &str = "traj.reverted_changes";
    pub const TRAJ_TOOL_CALL_PRODUCTIVITY_MICRO: &str = "traj.tool_call_productivity_micro";
    pub const TRAJ_TIME_SINCE_LAST_PROGRESS_MS: &str = "traj.time_since_last_progress_ms";
    pub const TRAJ_TEST_DELTA_PER_TURN: &str = "traj.test_delta_per_turn";
    pub const TRAJ_NEW_DEPENDENCY_INTRODUCTION: &str = "traj.new_dependency_introduction";
    pub const TRAJ_REQUIREMENT_COVERAGE_DELTA_MICRO: &str = "traj.requirement_coverage_delta_micro";
    pub const TRAJ_PERFORMANCE_DELTA_MICRO: &str = "traj.performance_delta_micro";
    pub const TRAJ_MODEL_REPORTED_UNCERTAINTY_MICRO: &str = "traj.model_reported_uncertainty_micro";
    pub const TRAJ_MODEL_REPORTED_UNCERTAINTY_IS_WEAK: &str =
        "traj.model_reported_uncertainty_is_weak";
    pub const TRAJ_ORACLE_INCONSISTENT: &str = "traj.oracle_inconsistent";
    pub const TRAJ_ENVIRONMENT_ERROR_COUNT: &str = "traj.environment_error_count";
    pub const TRAJ_PROVIDER_ERROR_COUNT: &str = "traj.provider_error_count";
    pub const TRAJ_QUOTA_EXHAUSTED: &str = "traj.quota_exhausted";
    pub const TRAJ_PUBLIC_API_BREAK: &str = "traj.public_api_break";
    pub const TRAJ_CERTIFIED: &str = "traj.certified";

    pub const TASK_TAXONOMY_VERSION: &str = "task.taxonomy.version";
    pub const TASK_TAXONOMY_DOMAIN: &str = "task.taxonomy.domain";
    pub const TASK_TAXONOMY_KIND: &str = "task.taxonomy.kind";
    pub const TASK_TAXONOMY_MODIFIERS: &str = "task.taxonomy.modifiers";
    pub const TASK_TAXONOMY_CONFIDENCE_BP: &str = "task.taxonomy.confidence_bp";
}

/// Deterministic feature value. Fractional quantities use millionths.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FeatureValue {
    Boolean(bool),
    Integer(i64),
    Text(String),
    Micro(i64),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureBag {
    values: BTreeMap<FeatureId, FeatureValue>,
}

impl FeatureBag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: FeatureId, value: FeatureValue) {
        self.values.insert(id, value);
    }

    pub fn get(&self, id: &FeatureId) -> Option<&FeatureValue> {
        self.values.get(id)
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FeatureId, &FeatureValue)> {
        self.values.iter()
    }

    pub fn integer(&self, key: &str) -> Option<i64> {
        match self.get(&feature_id(key)?) {
            Some(FeatureValue::Integer(value)) => Some(*value),
            Some(FeatureValue::Micro(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn boolean(&self, key: &str) -> Option<bool> {
        match self.get(&feature_id(key)?) {
            Some(FeatureValue::Boolean(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn text(&self, key: &str) -> Option<&str> {
        match self.get(&feature_id(key)?) {
            Some(FeatureValue::Text(value)) => Some(value.as_str()),
            _ => None,
        }
    }
}

pub type TaskFeatures = FeatureBag;
pub type RepoFeatures = FeatureBag;
pub type TrajectoryFeatures = FeatureBag;

/// Extractor seam for issue #163. Implementors hold recorded inputs so the
/// trait stays object-safe and extraction stays pure.
pub trait FeatureExtractor {
    fn extract_task(&self) -> TaskFeatures;
    fn extract_repo(&self) -> RepoFeatures;
    fn extract_trajectory(&self) -> TrajectoryFeatures;
}

/// Static task snapshot captured at intake.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedTaskInput {
    #[serde(default = "schema_v1")]
    pub schema_version: u32,
    #[serde(default)]
    pub requirement_count: u32,
    #[serde(default)]
    pub requirement_ambiguity_micro: i64,
    #[serde(default)]
    pub explicit_invariant_count: u32,
    #[serde(default)]
    pub non_goal_count: u32,
    #[serde(default)]
    pub estimated_files_affected: u32,
    #[serde(default)]
    pub estimated_modules_affected: u32,
    #[serde(default)]
    pub dependency_fan_out: u32,
    #[serde(default)]
    pub public_api_impact: bool,
    #[serde(default)]
    pub schema_or_migration_impact: bool,
    #[serde(default)]
    pub concurrency_involvement: bool,
    #[serde(default)]
    pub security_sensitivity: bool,
    #[serde(default)]
    pub performance_sensitivity: bool,
    #[serde(default)]
    pub hardware_or_environment_coupling: bool,
    #[serde(default)]
    pub rollback_difficulty_micro: i64,
    #[serde(default)]
    pub test_oracle_strength_micro: i64,
    #[serde(default)]
    pub formal_verification_available: bool,
    #[serde(default)]
    pub estimated_context_size: u32,
    #[serde(default)]
    pub estimated_tool_step_count: u32,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub framework: Option<String>,
    #[serde(default)]
    pub historical_task_class_success_bp: BTreeMap<String, u16>,
}

/// Optional repo signals that the live maps do not already carry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoFeatureExtras {
    #[serde(default)]
    pub build_duration_ms: Option<u64>,
    #[serde(default)]
    pub historical_flaky_tests: u32,
    #[serde(default)]
    pub file_churn: u32,
    #[serde(default)]
    pub ownership_boundary_count: Option<u32>,
    #[serde(default)]
    pub megafile_risk: Option<bool>,
    #[serde(default)]
    pub generated_code_file_count: Option<u32>,
    #[serde(default)]
    pub external_service_dependency_count: u32,
}

/// Repository snapshot reused from the existing repo-map / risk-report types.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedRepoInput {
    #[serde(default = "schema_v1")]
    pub schema_version: u32,
    #[serde(default)]
    pub repository_size_bytes: u64,
    #[serde(default)]
    pub file_count: u32,
    #[serde(default)]
    pub language_bytes: BTreeMap<String, u64>,
    #[serde(default)]
    pub module_count: u32,
    #[serde(default)]
    pub symbol_count: u32,
    #[serde(default)]
    pub dependency_edge_count: u32,
    #[serde(default)]
    pub dependency_centrality_micro: i64,
    #[serde(default)]
    pub test_file_count: u32,
    #[serde(default)]
    pub source_file_count: u32,
    #[serde(default)]
    pub build_duration_ms: Option<u64>,
    #[serde(default)]
    pub historical_flaky_tests: u32,
    #[serde(default)]
    pub file_churn: u32,
    #[serde(default)]
    pub ownership_boundary_count: u32,
    #[serde(default)]
    pub megafile_risk: bool,
    #[serde(default)]
    pub generated_code_file_count: u32,
    #[serde(default)]
    pub external_service_dependency_count: u32,
    #[serde(default)]
    pub rust_parse_ok: bool,
    #[serde(default)]
    pub unparsed_non_rust_files: u32,
    #[serde(default)]
    pub risk_impacted_files: u32,
}

/// Dynamic trajectory snapshot captured at a checkpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedTrajectoryInput {
    #[serde(default = "schema_v1")]
    pub schema_version: u32,
    #[serde(default)]
    pub relevant_files_discovered: u32,
    #[serde(default)]
    pub reproduction_achieved: bool,
    #[serde(default)]
    pub failing_test_count: u32,
    #[serde(default)]
    pub passing_test_count: u32,
    #[serde(default)]
    pub compiler_error_count: u32,
    #[serde(default)]
    pub error_signature_repetition: u32,
    #[serde(default)]
    pub changed_file_count: u32,
    #[serde(default)]
    pub scope_growth_rate_micro: i64,
    #[serde(default)]
    pub diff_churn: u32,
    #[serde(default)]
    pub reverted_changes: u32,
    #[serde(default)]
    pub tool_call_productivity_micro: i64,
    #[serde(default)]
    pub time_since_last_progress_ms: u64,
    #[serde(default)]
    pub test_delta_per_turn: i32,
    #[serde(default)]
    pub new_dependency_introduction: bool,
    #[serde(default)]
    pub requirement_coverage_delta_micro: i64,
    #[serde(default)]
    pub performance_delta_micro: i64,
    /// Weak signal only — no certification authority and no veto power.
    #[serde(default)]
    pub model_reported_uncertainty_micro: Option<i64>,
    #[serde(default)]
    pub oracle_inconsistent: bool,
    #[serde(default)]
    pub environment_error_count: u32,
    #[serde(default)]
    pub provider_error_count: u32,
    #[serde(default)]
    pub quota_exhausted: bool,
    #[serde(default)]
    pub public_api_break: bool,
    #[serde(default)]
    pub certified: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedFeatureInputs {
    #[serde(default = "schema_v1")]
    pub schema_version: u32,
    #[serde(default)]
    pub task: RecordedTaskInput,
    #[serde(default)]
    pub repo: RecordedRepoInput,
    #[serde(default)]
    pub trajectory: RecordedTrajectoryInput,
}

/// Versioned feature snapshot used for replay and telemetry hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasuredFeatureSnapshot {
    pub schema_version: u32,
    pub task: TaskFeatures,
    pub repo: RepoFeatures,
    pub trajectory: TrajectoryFeatures,
    pub duration_micros: u64,
}

/// Pure extractor: all I/O happens before construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFeatureExtractor {
    inputs: RecordedFeatureInputs,
}

impl SnapshotFeatureExtractor {
    pub fn new(inputs: RecordedFeatureInputs) -> Self {
        Self { inputs }
    }

    pub fn inputs(&self) -> &RecordedFeatureInputs {
        &self.inputs
    }

    pub fn extract_measured(&self) -> MeasuredFeatureSnapshot {
        let started = Instant::now();
        let task = self.extract_task();
        let repo = self.extract_repo();
        let trajectory = self.extract_trajectory();
        let duration_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        MeasuredFeatureSnapshot {
            schema_version: FEATURE_SCHEMA_VERSION,
            task,
            repo,
            trajectory,
            duration_micros,
        }
    }
}

impl FeatureExtractor for SnapshotFeatureExtractor {
    fn extract_task(&self) -> TaskFeatures {
        extract_task_features(&self.inputs.task)
    }

    fn extract_repo(&self) -> RepoFeatures {
        extract_repo_features(&self.inputs.repo)
    }

    fn extract_trajectory(&self) -> TrajectoryFeatures {
        extract_trajectory_features(&self.inputs.trajectory)
    }
}

const MEGAFILE_BYTE_THRESHOLD: u64 = 256 * 1024;

impl RecordedRepoInput {
    /// Collapse live repo-map / semantic / risk-report machinery into a
    /// recorded snapshot. Non-Rust files contribute to size and language
    /// distribution and are otherwise skipped (no fabricated symbols).
    pub fn from_repository_maps(
        repo_map: &RepoMap,
        semantic: Option<&SemanticRepoMap>,
        risk: Option<&SemanticRiskReport>,
        extras: RepoFeatureExtras,
    ) -> Self {
        let mut language_bytes = BTreeMap::new();
        let mut repository_size_bytes = 0_u64;
        let mut file_count = 0_u32;
        let mut test_file_count = 0_u32;
        let mut source_file_count = 0_u32;
        let mut unparsed_non_rust_files = 0_u32;
        let mut generated_code_file_count = 0_u32;
        let mut megafile_risk = false;
        let mut ownership = BTreeMap::new();

        for entry in &repo_map.entries {
            if entry.kind != RepoEntryKind::File {
                continue;
            }
            file_count = file_count.saturating_add(1);
            let size = entry.size_bytes.unwrap_or(0);
            repository_size_bytes = repository_size_bytes.saturating_add(size);
            *language_bytes.entry(entry.category.clone()).or_insert(0) += size;
            if size >= MEGAFILE_BYTE_THRESHOLD {
                megafile_risk = true;
            }
            if is_test_path(&entry.path) {
                test_file_count = test_file_count.saturating_add(1);
            } else if is_source_path(&entry.path) {
                source_file_count = source_file_count.saturating_add(1);
            }
            if is_generated_path(&entry.path) {
                generated_code_file_count = generated_code_file_count.saturating_add(1);
            }
            if entry.category != "rust" {
                unparsed_non_rust_files = unparsed_non_rust_files.saturating_add(1);
            }
            if let Some(root) = entry.path.components().next() {
                *ownership
                    .entry(root.as_os_str().to_os_string())
                    .or_insert(0) += 1;
            }
        }

        let (module_count, symbol_count, dependency_edge_count, centrality, rust_parse_ok) =
            match semantic {
                Some(map) => (
                    u32::try_from(map.files.len()).unwrap_or(u32::MAX),
                    u32::try_from(map.symbols.len()).unwrap_or(u32::MAX),
                    u32::try_from(map.dependencies.len()).unwrap_or(u32::MAX),
                    dependency_centrality_micro(map),
                    map.errors.is_empty(),
                ),
                None => (0, 0, 0, 0, file_count == unparsed_non_rust_files),
            };

        Self {
            schema_version: FEATURE_SCHEMA_VERSION,
            repository_size_bytes,
            file_count,
            language_bytes,
            module_count,
            symbol_count,
            dependency_edge_count,
            dependency_centrality_micro: centrality,
            test_file_count,
            source_file_count,
            build_duration_ms: extras.build_duration_ms,
            historical_flaky_tests: extras.historical_flaky_tests,
            file_churn: extras.file_churn,
            ownership_boundary_count: extras
                .ownership_boundary_count
                .unwrap_or_else(|| u32::try_from(ownership.len()).unwrap_or(u32::MAX)),
            megafile_risk: extras.megafile_risk.unwrap_or(megafile_risk),
            generated_code_file_count: extras
                .generated_code_file_count
                .unwrap_or(generated_code_file_count),
            external_service_dependency_count: extras.external_service_dependency_count,
            rust_parse_ok,
            unparsed_non_rust_files,
            risk_impacted_files: risk
                .map(|report| u32::try_from(report.impacted_files.len()).unwrap_or(u32::MAX))
                .unwrap_or(0),
        }
    }
}

fn extract_task_features(input: &RecordedTaskInput) -> TaskFeatures {
    let mut bag = FeatureBag::new();
    insert_int(
        &mut bag,
        keys::SCHEMA_VERSION,
        i64::from(input.schema_version),
    );
    insert_int(
        &mut bag,
        keys::TASK_REQUIREMENT_COUNT,
        i64::from(input.requirement_count),
    );
    insert_micro(
        &mut bag,
        keys::TASK_REQUIREMENT_AMBIGUITY_MICRO,
        input.requirement_ambiguity_micro,
    );
    insert_int(
        &mut bag,
        keys::TASK_EXPLICIT_INVARIANT_COUNT,
        i64::from(input.explicit_invariant_count),
    );
    insert_int(
        &mut bag,
        keys::TASK_NON_GOAL_COUNT,
        i64::from(input.non_goal_count),
    );
    insert_int(
        &mut bag,
        keys::TASK_ESTIMATED_FILES_AFFECTED,
        i64::from(input.estimated_files_affected),
    );
    insert_int(
        &mut bag,
        keys::TASK_ESTIMATED_MODULES_AFFECTED,
        i64::from(input.estimated_modules_affected),
    );
    insert_int(
        &mut bag,
        keys::TASK_DEPENDENCY_FAN_OUT,
        i64::from(input.dependency_fan_out),
    );
    insert_bool(
        &mut bag,
        keys::TASK_PUBLIC_API_IMPACT,
        input.public_api_impact,
    );
    insert_bool(
        &mut bag,
        keys::TASK_SCHEMA_OR_MIGRATION_IMPACT,
        input.schema_or_migration_impact,
    );
    insert_bool(
        &mut bag,
        keys::TASK_CONCURRENCY_INVOLVEMENT,
        input.concurrency_involvement,
    );
    insert_bool(
        &mut bag,
        keys::TASK_SECURITY_SENSITIVITY,
        input.security_sensitivity,
    );
    insert_bool(
        &mut bag,
        keys::TASK_PERFORMANCE_SENSITIVITY,
        input.performance_sensitivity,
    );
    insert_bool(
        &mut bag,
        keys::TASK_HARDWARE_OR_ENVIRONMENT_COUPLING,
        input.hardware_or_environment_coupling,
    );
    insert_micro(
        &mut bag,
        keys::TASK_ROLLBACK_DIFFICULTY_MICRO,
        input.rollback_difficulty_micro,
    );
    insert_micro(
        &mut bag,
        keys::TASK_TEST_ORACLE_STRENGTH_MICRO,
        input.test_oracle_strength_micro,
    );
    insert_bool(
        &mut bag,
        keys::TASK_FORMAL_VERIFICATION_AVAILABLE,
        input.formal_verification_available,
    );
    insert_int(
        &mut bag,
        keys::TASK_ESTIMATED_CONTEXT_SIZE,
        i64::from(input.estimated_context_size),
    );
    insert_int(
        &mut bag,
        keys::TASK_ESTIMATED_TOOL_STEP_COUNT,
        i64::from(input.estimated_tool_step_count),
    );
    if let Some(language) = &input.language {
        insert_text(&mut bag, keys::TASK_LANGUAGE, language.clone());
    }
    if let Some(framework) = &input.framework {
        insert_text(&mut bag, keys::TASK_FRAMEWORK, framework.clone());
    }
    insert_int(
        &mut bag,
        keys::TASK_HISTORICAL_CLASS_COUNT,
        i64::try_from(input.historical_task_class_success_bp.len()).unwrap_or(i64::MAX),
    );
    for (class, rate) in &input.historical_task_class_success_bp {
        insert_int(
            &mut bag,
            &format!("task.historical_success_bp.{class}"),
            i64::from(*rate),
        );
    }
    bag
}

fn extract_repo_features(input: &RecordedRepoInput) -> RepoFeatures {
    let mut bag = FeatureBag::new();
    insert_int(
        &mut bag,
        keys::SCHEMA_VERSION,
        i64::from(input.schema_version),
    );
    insert_int(
        &mut bag,
        keys::REPO_SIZE_BYTES,
        i64::try_from(input.repository_size_bytes).unwrap_or(i64::MAX),
    );
    insert_int(&mut bag, keys::REPO_FILE_COUNT, i64::from(input.file_count));
    insert_int(
        &mut bag,
        keys::REPO_MODULE_COUNT,
        i64::from(input.module_count),
    );
    insert_int(
        &mut bag,
        keys::REPO_SYMBOL_COUNT,
        i64::from(input.symbol_count),
    );
    insert_int(
        &mut bag,
        keys::REPO_DEPENDENCY_EDGE_COUNT,
        i64::from(input.dependency_edge_count),
    );
    insert_micro(
        &mut bag,
        keys::REPO_DEPENDENCY_CENTRALITY_MICRO,
        input.dependency_centrality_micro,
    );
    let density = if input.source_file_count == 0 {
        0
    } else {
        i64::from(input.test_file_count) * 1_000_000 / i64::from(input.source_file_count)
    };
    insert_micro(&mut bag, keys::REPO_TEST_DENSITY_MICRO, density);
    if let Some(duration) = input.build_duration_ms {
        insert_int(
            &mut bag,
            keys::REPO_BUILD_DURATION_MS,
            i64::try_from(duration).unwrap_or(i64::MAX),
        );
    }
    insert_int(
        &mut bag,
        keys::REPO_HISTORICAL_FLAKY_TESTS,
        i64::from(input.historical_flaky_tests),
    );
    insert_int(&mut bag, keys::REPO_FILE_CHURN, i64::from(input.file_churn));
    insert_int(
        &mut bag,
        keys::REPO_OWNERSHIP_BOUNDARY_COUNT,
        i64::from(input.ownership_boundary_count),
    );
    insert_bool(&mut bag, keys::REPO_MEGAFILE_RISK, input.megafile_risk);
    insert_int(
        &mut bag,
        keys::REPO_GENERATED_CODE_FILE_COUNT,
        i64::from(input.generated_code_file_count),
    );
    insert_int(
        &mut bag,
        keys::REPO_EXTERNAL_SERVICE_DEPENDENCY_COUNT,
        i64::from(input.external_service_dependency_count),
    );
    insert_int(
        &mut bag,
        keys::REPO_UNPARSED_NON_RUST_FILES,
        i64::from(input.unparsed_non_rust_files),
    );
    insert_bool(&mut bag, keys::REPO_RUST_PARSE_OK, input.rust_parse_ok);
    insert_int(
        &mut bag,
        keys::REPO_LANGUAGE_COUNT,
        i64::try_from(input.language_bytes.len()).unwrap_or(i64::MAX),
    );
    insert_int(
        &mut bag,
        keys::REPO_RISK_IMPACTED_FILES,
        i64::from(input.risk_impacted_files),
    );
    for (language, bytes) in &input.language_bytes {
        insert_int(
            &mut bag,
            &format!("repo.language_bytes.{language}"),
            i64::try_from(*bytes).unwrap_or(i64::MAX),
        );
    }
    bag
}

fn extract_trajectory_features(input: &RecordedTrajectoryInput) -> TrajectoryFeatures {
    let mut bag = FeatureBag::new();
    insert_int(
        &mut bag,
        keys::SCHEMA_VERSION,
        i64::from(input.schema_version),
    );
    insert_int(
        &mut bag,
        keys::TRAJ_RELEVANT_FILES_DISCOVERED,
        i64::from(input.relevant_files_discovered),
    );
    insert_bool(
        &mut bag,
        keys::TRAJ_REPRODUCTION_ACHIEVED,
        input.reproduction_achieved,
    );
    insert_int(
        &mut bag,
        keys::TRAJ_FAILING_TEST_COUNT,
        i64::from(input.failing_test_count),
    );
    insert_int(
        &mut bag,
        keys::TRAJ_PASSING_TEST_COUNT,
        i64::from(input.passing_test_count),
    );
    insert_int(
        &mut bag,
        keys::TRAJ_COMPILER_ERROR_COUNT,
        i64::from(input.compiler_error_count),
    );
    insert_int(
        &mut bag,
        keys::TRAJ_ERROR_SIGNATURE_REPETITION,
        i64::from(input.error_signature_repetition),
    );
    insert_int(
        &mut bag,
        keys::TRAJ_CHANGED_FILE_COUNT,
        i64::from(input.changed_file_count),
    );
    insert_micro(
        &mut bag,
        keys::TRAJ_SCOPE_GROWTH_RATE_MICRO,
        input.scope_growth_rate_micro,
    );
    insert_int(&mut bag, keys::TRAJ_DIFF_CHURN, i64::from(input.diff_churn));
    insert_int(
        &mut bag,
        keys::TRAJ_REVERTED_CHANGES,
        i64::from(input.reverted_changes),
    );
    insert_micro(
        &mut bag,
        keys::TRAJ_TOOL_CALL_PRODUCTIVITY_MICRO,
        input.tool_call_productivity_micro,
    );
    insert_int(
        &mut bag,
        keys::TRAJ_TIME_SINCE_LAST_PROGRESS_MS,
        i64::try_from(input.time_since_last_progress_ms).unwrap_or(i64::MAX),
    );
    insert_int(
        &mut bag,
        keys::TRAJ_TEST_DELTA_PER_TURN,
        i64::from(input.test_delta_per_turn),
    );
    insert_bool(
        &mut bag,
        keys::TRAJ_NEW_DEPENDENCY_INTRODUCTION,
        input.new_dependency_introduction,
    );
    insert_micro(
        &mut bag,
        keys::TRAJ_REQUIREMENT_COVERAGE_DELTA_MICRO,
        input.requirement_coverage_delta_micro,
    );
    insert_micro(
        &mut bag,
        keys::TRAJ_PERFORMANCE_DELTA_MICRO,
        input.performance_delta_micro,
    );
    insert_bool(
        &mut bag,
        keys::TRAJ_MODEL_REPORTED_UNCERTAINTY_IS_WEAK,
        true,
    );
    if let Some(uncertainty) = input.model_reported_uncertainty_micro {
        insert_micro(
            &mut bag,
            keys::TRAJ_MODEL_REPORTED_UNCERTAINTY_MICRO,
            uncertainty,
        );
    }
    insert_bool(
        &mut bag,
        keys::TRAJ_ORACLE_INCONSISTENT,
        input.oracle_inconsistent,
    );
    insert_int(
        &mut bag,
        keys::TRAJ_ENVIRONMENT_ERROR_COUNT,
        i64::from(input.environment_error_count),
    );
    insert_int(
        &mut bag,
        keys::TRAJ_PROVIDER_ERROR_COUNT,
        i64::from(input.provider_error_count),
    );
    insert_bool(&mut bag, keys::TRAJ_QUOTA_EXHAUSTED, input.quota_exhausted);
    insert_bool(
        &mut bag,
        keys::TRAJ_PUBLIC_API_BREAK,
        input.public_api_break,
    );
    insert_bool(&mut bag, keys::TRAJ_CERTIFIED, input.certified);
    bag
}

fn schema_v1() -> u32 {
    1
}

pub(crate) fn feature_id(key: &str) -> Option<FeatureId> {
    FeatureId::new(key).ok()
}

fn insert_int(bag: &mut FeatureBag, key: &str, value: i64) {
    if let Some(id) = feature_id(key) {
        bag.insert(id, FeatureValue::Integer(value));
    }
}

fn insert_bool(bag: &mut FeatureBag, key: &str, value: bool) {
    if let Some(id) = feature_id(key) {
        bag.insert(id, FeatureValue::Boolean(value));
    }
}

fn insert_micro(bag: &mut FeatureBag, key: &str, value: i64) {
    if let Some(id) = feature_id(key) {
        bag.insert(id, FeatureValue::Micro(value));
    }
}

fn insert_text(bag: &mut FeatureBag, key: &str, value: String) {
    if let Some(id) = feature_id(key) {
        bag.insert(id, FeatureValue::Text(value));
    }
}

fn dependency_centrality_micro(map: &SemanticRepoMap) -> i64 {
    let mut incoming: BTreeMap<PathBuf, u32> = BTreeMap::new();
    for dependency in &map.dependencies {
        if let Some(to) = &dependency.to_file {
            *incoming.entry(to.clone()).or_default() += 1;
        }
    }
    let max = incoming.values().copied().max().unwrap_or(0);
    let n = i64::try_from(map.files.len().max(1)).unwrap_or(1);
    i64::from(max).saturating_mul(1_000_000) / n
}

fn is_test_path(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| name == "tests" || name == "test")
    }) || path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .is_some_and(|stem| stem.ends_with("_test") || stem.starts_with("test_"))
}

fn is_source_path(path: &Path) -> bool {
    !is_test_path(path)
        && path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                matches!(
                    ext,
                    "rs" | "py" | "js" | "ts" | "go" | "c" | "cc" | "cpp" | "h" | "java"
                )
            })
}

fn is_generated_path(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| name.contains("generated") || name == "target")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo_map::{RepoGitStatus, RepoMapEntry};
    use crate::repo_semantic::{
        SemanticDependency, SemanticDependencyKind, SemanticFile, SemanticScanError,
        SemanticScanErrorKind, SemanticSymbol, SemanticSymbolKind, SourceSpan,
    };

    fn task_fixture() -> RecordedTaskInput {
        let mut historical = BTreeMap::new();
        historical.insert("localized_bugfix".to_string(), 8_200);
        RecordedTaskInput {
            schema_version: FEATURE_SCHEMA_VERSION,
            requirement_count: 4,
            requirement_ambiguity_micro: 250_000,
            explicit_invariant_count: 2,
            non_goal_count: 1,
            estimated_files_affected: 3,
            estimated_modules_affected: 2,
            dependency_fan_out: 5,
            public_api_impact: true,
            schema_or_migration_impact: false,
            concurrency_involvement: true,
            security_sensitivity: false,
            performance_sensitivity: true,
            hardware_or_environment_coupling: false,
            rollback_difficulty_micro: 400_000,
            test_oracle_strength_micro: 800_000,
            formal_verification_available: false,
            estimated_context_size: 12_000,
            estimated_tool_step_count: 18,
            language: Some("rust".to_string()),
            framework: Some("tokio".to_string()),
            historical_task_class_success_bp: historical,
        }
    }

    fn trajectory_fixture() -> RecordedTrajectoryInput {
        RecordedTrajectoryInput {
            schema_version: FEATURE_SCHEMA_VERSION,
            relevant_files_discovered: 4,
            reproduction_achieved: true,
            failing_test_count: 1,
            passing_test_count: 20,
            compiler_error_count: 1,
            error_signature_repetition: 1,
            changed_file_count: 2,
            scope_growth_rate_micro: 100_000,
            diff_churn: 30,
            reverted_changes: 0,
            tool_call_productivity_micro: 500_000,
            time_since_last_progress_ms: 1_000,
            test_delta_per_turn: 1,
            new_dependency_introduction: false,
            requirement_coverage_delta_micro: 200_000,
            performance_delta_micro: 0,
            model_reported_uncertainty_micro: Some(700_000),
            oracle_inconsistent: false,
            environment_error_count: 0,
            provider_error_count: 0,
            quota_exhausted: false,
            public_api_break: false,
            certified: false,
        }
    }

    fn file_entry(path: &str, category: &str, size: u64) -> RepoMapEntry {
        RepoMapEntry {
            path: PathBuf::from(path),
            kind: RepoEntryKind::File,
            size_bytes: Some(size),
            category: category.to_string(),
            git_status: RepoGitStatus::Clean,
        }
    }

    fn span() -> SourceSpan {
        SourceSpan {
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
            signature_end_line: 1,
        }
    }

    #[test]
    fn static_task_features_are_deterministic() {
        let extractor = SnapshotFeatureExtractor::new(RecordedFeatureInputs {
            schema_version: FEATURE_SCHEMA_VERSION,
            task: task_fixture(),
            repo: RecordedRepoInput::default(),
            trajectory: RecordedTrajectoryInput::default(),
        });
        let first = extractor.extract_task();
        let second = extractor.extract_task();
        assert_eq!(first, second);
        assert_eq!(first.integer(keys::TASK_REQUIREMENT_COUNT), Some(4));
        assert_eq!(first.boolean(keys::TASK_PUBLIC_API_IMPACT), Some(true));
        assert_eq!(
            first.integer("task.historical_success_bp.localized_bugfix"),
            Some(8_200)
        );
        assert_eq!(first.integer(keys::SCHEMA_VERSION), Some(1));
    }

    #[test]
    fn non_rust_files_degrade_without_fabricated_symbols() {
        let repo_map = RepoMap {
            root: PathBuf::from("/tmp/fixture"),
            entries: vec![
                file_entry("src/lib.rs", "rust", 120),
                file_entry("scripts/ok.py", "unknown", 80),
                file_entry("tests/lib.rs", "rust", 40),
                file_entry("generated/out.rs", "rust", 300_000),
            ],
        };
        let semantic = SemanticRepoMap {
            root: PathBuf::from("/tmp/fixture"),
            files: vec![SemanticFile {
                path: PathBuf::from("src/lib.rs"),
                module_path: vec!["lib".to_string()],
                byte_len: 120,
                line_count: 8,
            }],
            symbols: vec![SemanticSymbol {
                id: "lib::ok".to_string(),
                file: PathBuf::from("src/lib.rs"),
                name: "ok".to_string(),
                qualified_path: vec!["lib".to_string(), "ok".to_string()],
                kind: SemanticSymbolKind::Function,
                visibility: "pub".to_string(),
                parent_symbol: None,
                impl_target: None,
                impl_trait: None,
                span: span(),
            }],
            imports: Vec::new(),
            re_exports: Vec::new(),
            dependencies: vec![SemanticDependency {
                from_file: PathBuf::from("src/lib.rs"),
                from_module: vec!["lib".to_string()],
                to: "std".to_string(),
                to_file: None,
                kind: SemanticDependencyKind::Import,
                span: span(),
            }],
            errors: vec![SemanticScanError {
                file: PathBuf::from("src/broken.rs"),
                kind: SemanticScanErrorKind::Parse,
                message: "syntax".to_string(),
                span: None,
            }],
        };
        let recorded = RecordedRepoInput::from_repository_maps(
            &repo_map,
            Some(&semantic),
            None,
            RepoFeatureExtras {
                build_duration_ms: Some(1_200),
                historical_flaky_tests: 2,
                file_churn: 7,
                ownership_boundary_count: None,
                megafile_risk: None,
                generated_code_file_count: None,
                external_service_dependency_count: 1,
            },
        );
        assert_eq!(recorded.unparsed_non_rust_files, 1);
        assert!(!recorded.rust_parse_ok);
        assert!(recorded.megafile_risk);
        assert_eq!(recorded.generated_code_file_count, 1);
        assert_eq!(recorded.symbol_count, 1);

        let extractor = SnapshotFeatureExtractor::new(RecordedFeatureInputs {
            schema_version: FEATURE_SCHEMA_VERSION,
            task: RecordedTaskInput::default(),
            repo: recorded,
            trajectory: RecordedTrajectoryInput::default(),
        });
        let repo = extractor.extract_repo();
        assert_eq!(repo.integer(keys::REPO_UNPARSED_NON_RUST_FILES), Some(1));
        assert_eq!(repo.boolean(keys::REPO_MEGAFILE_RISK), Some(true));
        assert_eq!(repo.integer(keys::REPO_SYMBOL_COUNT), Some(1));
        assert_eq!(repo.integer("repo.language_bytes.unknown"), Some(80));
    }

    #[test]
    fn trajectory_features_keep_model_uncertainty_weak() {
        let extractor = SnapshotFeatureExtractor::new(RecordedFeatureInputs {
            schema_version: FEATURE_SCHEMA_VERSION,
            task: RecordedTaskInput::default(),
            repo: RecordedRepoInput::default(),
            trajectory: trajectory_fixture(),
        });
        let features = extractor.extract_trajectory();
        assert_eq!(
            features.boolean(keys::TRAJ_MODEL_REPORTED_UNCERTAINTY_IS_WEAK),
            Some(true)
        );
        assert_eq!(
            features.integer(keys::TRAJ_MODEL_REPORTED_UNCERTAINTY_MICRO),
            Some(700_000)
        );
        assert_eq!(
            features.boolean(keys::TRAJ_REPRODUCTION_ACHIEVED),
            Some(true)
        );
    }

    #[test]
    fn same_snapshot_reproduces_the_same_vector() {
        let inputs = RecordedFeatureInputs {
            schema_version: FEATURE_SCHEMA_VERSION,
            task: task_fixture(),
            repo: RecordedRepoInput {
                schema_version: FEATURE_SCHEMA_VERSION,
                repository_size_bytes: 1_024,
                file_count: 3,
                ..RecordedRepoInput::default()
            },
            trajectory: trajectory_fixture(),
        };
        let encoded = serde_json::to_string(&inputs).expect("encode");
        let decoded: RecordedFeatureInputs = serde_json::from_str(&encoded).expect("decode");
        let left = SnapshotFeatureExtractor::new(inputs).extract_measured();
        let right = SnapshotFeatureExtractor::new(decoded).extract_measured();
        assert_eq!(left.schema_version, right.schema_version);
        assert_eq!(left.task, right.task);
        assert_eq!(left.repo, right.repo);
        assert_eq!(left.trajectory, right.trajectory);
    }

    #[test]
    fn old_records_without_new_fields_remain_readable() {
        let json =
            r#"{"schema_version":1,"task":{"requirement_count":2},"repo":{},"trajectory":{}}"#;
        let inputs: RecordedFeatureInputs = serde_json::from_str(json).expect("legacy");
        assert_eq!(inputs.task.requirement_count, 2);
        assert_eq!(inputs.task.non_goal_count, 0);
        assert!(inputs.repo.language_bytes.is_empty());
        let bag = SnapshotFeatureExtractor::new(inputs).extract_task();
        assert_eq!(bag.integer(keys::TASK_REQUIREMENT_COUNT), Some(2));
    }

    #[test]
    fn extraction_cost_is_bounded_for_small_snapshots() {
        let extractor = SnapshotFeatureExtractor::new(RecordedFeatureInputs {
            schema_version: FEATURE_SCHEMA_VERSION,
            task: task_fixture(),
            repo: RecordedRepoInput::default(),
            trajectory: trajectory_fixture(),
        });
        let snapshot = extractor.extract_measured();
        assert!(
            snapshot.duration_micros < 50_000,
            "small-task extraction took {}µs",
            snapshot.duration_micros
        );
    }
}
