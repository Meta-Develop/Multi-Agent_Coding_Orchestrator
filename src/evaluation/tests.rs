use super::*;
use crate::autopilot::{
    AutopilotProfile, AutopilotProfileExecutionBindingReport, AutopilotReviewLensExecutionBinding,
    AutopilotRoleModelExecutionBinding,
};
use serde_json::json;

const FIXTURE_PLAN: &[u8] =
    include_bytes!("../../tests/fixtures/model_mix_evaluation/hand-authored-plan-v1.json");
const FIXTURE_MANIFEST: &str =
    include_str!("../../tests/fixtures/model_mix_evaluation/manifest-v1.json");
const FIXTURE_RESULTS: &str =
    include_str!("../../tests/fixtures/model_mix_evaluation/runs-v1.json");
const FIXTURE_SUMMARY: &str =
    include_str!("../../tests/fixtures/model_mix_evaluation/summary-v1.json");
const SUPERVISOR_EXECUTION_V2: &[u8] =
    include_bytes!("../../tests/fixtures/model_mix_evaluation/supervisor-final-execution-v2.json");
const SUPERVISOR_EXECUTION_V1_LEGACY: &[u8] = include_bytes!(
    "../../tests/fixtures/model_mix_evaluation/supervisor-final-execution-v1-legacy.json"
);

fn model(model: &str, reasoning_effort: &str) -> RoleModelSelection {
    RoleModelSelection {
        model: Some(model.to_string()),
        reasoning_effort: Some(reasoning_effort.to_string()),
        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
    }
}

fn profile(id: &str, orchestrator_model: &str, worker_model: &str) -> EvaluationProfile {
    EvaluationProfile {
        id: id.to_string(),
        role_models: BTreeMap::from([
            (
                AgentRole::ChildOrchestrator,
                model(orchestrator_model, "high"),
            ),
            (AgentRole::Worker, model(worker_model, "medium")),
        ]),
    }
}

fn labelled_test_plan() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version": 1,
        "evidence": EvaluationEvidence::provisional_fake_only(),
        "task": "deterministic fake evaluation test plan",
        "assignments": []
    }))
    .expect("serialize labelled test plan")
}

fn manifest() -> EvaluationManifest {
    let plan = labelled_test_plan();
    EvaluationManifest {
        version: EVALUATION_MANIFEST_SCHEMA_VERSION,
        experiment_id: "issue-26-phase-a".to_string(),
        evidence: EvaluationEvidence::provisional_fake_only(),
        target: EvaluationTarget {
            spec_or_goal_id: "issue-26".to_string(),
            spec_or_goal_digest:
                "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e1bca75d84e1400c421b321"
                    .to_string(),
            hand_authored_plan_digest: format!("sha256:{}", sha256_hex(&plan)),
        },
        repository_base_snapshot: "a".repeat(40),
        limits: EvaluationLimits {
            wall_time_seconds: 600,
            max_dispatches: 8,
        },
        held_out_validation: vec![
            HeldOutValidation {
                id: "unit".to_string(),
                command: vec![
                    "cargo".to_string(),
                    "test".to_string(),
                    "held_out_unit".to_string(),
                ],
            },
            HeldOutValidation {
                id: "integration".to_string(),
                command: vec![
                    "cargo".to_string(),
                    "test".to_string(),
                    "held_out_integration".to_string(),
                ],
            },
        ],
        repetitions: 3,
        profiles: vec![
            profile("frontier-workers", "frontier-v1", "fast-v1"),
            profile("all-frontier", "frontier-v1", "frontier-v1"),
        ],
        objective_profile: Some(
            crate::objective_profile::default_resolved_objective_profile()
                .expect("resolved default objective"),
        ),
    }
}

fn run_fake(
    manifest: &EvaluationManifest,
    seed: u64,
) -> Result<EvaluationResults, EvaluationError> {
    run_evaluation(
        manifest,
        &labelled_test_plan(),
        EvaluationRunRequest {
            fake_seed: seed,
            ..EvaluationRunRequest::default()
        },
    )
}

fn committed_manifest() -> EvaluationManifest {
    serde_json::from_str(FIXTURE_MANIFEST).expect("deserialize committed evaluation manifest")
}

fn committed_results() -> EvaluationResults {
    serde_json::from_str(FIXTURE_RESULTS).expect("deserialize committed evaluation results")
}

fn committed_summary() -> EvaluationSummary {
    serde_json::from_str(FIXTURE_SUMMARY).expect("deserialize committed evaluation summary")
}

fn precise_quality(score: QualityScore) -> PreciseQualityScore {
    PreciseQualityScore {
        held_out_basis_points: PreciseMean {
            total: u64::from(score.held_out_basis_points),
            count: 1,
        },
        breadth_basis_points: PreciseMean {
            total: u64::from(score.breadth_basis_points),
            count: 1,
        },
        anti_shortcut_basis_points: PreciseMean {
            total: u64::from(score.anti_shortcut_basis_points),
            count: 1,
        },
        overall_basis_points: PreciseMean {
            total: u64::from(score.overall_basis_points),
            count: 1,
        },
    }
}

fn complete_observed_binding(role_model: &str, lens_model: &str) -> AutopilotProfileBindingReport {
    AutopilotProfileBindingReport {
        version: 3,
        status: AutopilotProfileBindingStatus::Matched,
        configuration_status: AutopilotProfileBindingStatus::Matched,
        requested: AutopilotProfile::default(),
        effective: None,
        execution: Some(AutopilotProfileExecutionBindingReport {
            role_models: vec![AutopilotRoleModelExecutionBinding {
                role: AgentRole::Worker,
                requested: model("requested-plan-value-must-not-be-observed", ""),
                observed_models: vec![role_model.to_string()],
                observation: RoleUsageObservation::ProcessObserved,
                status: AutopilotProfileBindingStatus::Matched,
                unavailable_reason: None,
            }],
            review_lenses: vec![AutopilotReviewLensExecutionBinding {
                lens_id: "quality-lens".to_string(),
                requested_backend_id: "requested-provider-must-not-be-observed".to_string(),
                requested_model: "requested-model-must-not-be-observed".to_string(),
                requested_reasoning_effort: Some("requested-effort".to_string()),
                observed_backend_id: Some("observed-provider".to_string()),
                observed_model: Some(lens_model.to_string()),
                observed_reasoning_effort: Some("xhigh".to_string()),
                dispatch_count: 1,
                observation: RoleUsageObservation::ProcessObserved,
                status: AutopilotProfileBindingStatus::Matched,
                unavailable_reason: None,
            }],
            unavailable_reason: None,
        }),
        failure: None,
    }
}

fn complete_supervisor_execution_record() -> ObservedDispatchRecord {
    observed_dispatch_record_from_supervisor_final_json(SUPERVISOR_EXECUTION_V2)
        .expect("consume supervisor execution telemetry fixture")
}

fn supervisor_execution_record_with_model(model: &str) -> ObservedDispatchRecord {
    let mut record = complete_supervisor_execution_record();
    for role in &mut record.roles {
        role.models = vec![model.to_string()];
    }
    for binding in &mut record
        .supervisor_execution
        .as_mut()
        .expect("fixture execution")
        .role_bindings
    {
        binding.resolved_model = Some(model.to_string());
    }
    record
}

#[test]
fn legacy_a4_observations_are_incomparable_without_execution_v2() {
    let left = observed_dispatch_record_from_profile_binding(&complete_observed_binding(
        "observed-worker-a",
        "observed-review-a",
    ))
    .expect("complete left dispatch evidence");
    let right = observed_dispatch_record_from_profile_binding(&complete_observed_binding(
        "observed-worker-b",
        "observed-review-b",
    ))
    .expect("complete right dispatch evidence");

    assert_eq!(
        compare_observed_dispatch_records(Some(&left), Some(&right)),
        RequirementFourComparability::Incomparable
    );
    let claim = DispatchComparabilityClaim::dispatch_only();
    assert_eq!(claim.scope, EvaluationComparabilityScope::Dispatch);
    assert!(!claim.provider_execution_difference_established);
    assert!(claim.notice.contains("does not establish"));
}

#[test]
fn supervisor_final_v2_is_consumed_without_configured_value_substitution() {
    let record = complete_supervisor_execution_record();
    let execution = record
        .supervisor_execution
        .as_ref()
        .expect("normalized supervisor execution");

    assert_eq!(execution.schema_version, 2);
    assert_eq!(execution.assignment_count, 2);
    assert_eq!(execution.started_assignment_count, 2);
    assert_eq!(execution.completed_assignment_count, 2);
    assert_eq!(execution.concurrency.configured_max_concurrent_children, 2);
    assert_eq!(execution.concurrency.achieved_max_concurrent_children, 2);
    assert_eq!(
        execution.concurrency.achieved_mean_concurrent_children,
        Some(1.75)
    );
    assert_eq!(execution.role_bindings.len(), 5);
    let worker = execution
        .role_bindings
        .iter()
        .find(|binding| binding.role == AgentRole::Worker)
        .expect("worker binding");
    assert_eq!(worker.resolved_model.as_deref(), Some("gpt-fixture"));
    assert_eq!(worker.resolved_reasoning_effort.as_deref(), Some("medium"));
    assert_eq!(
        execution.usage.total_usage,
        Some(Usage {
            input_tokens: 1_200,
            output_tokens: 300,
            total_tokens: 1_500,
        })
    );
    assert_eq!(execution.usage.total_cost_usd, Some(0.0125));
    assert!(execution.usage.usage_complete);
}

#[test]
fn execution_and_resolved_selection_axes_compare_separately() {
    let left = complete_supervisor_execution_record();
    let mut usage_difference = left.clone();
    usage_difference
        .supervisor_execution
        .as_mut()
        .expect("execution")
        .usage
        .total_cost_usd = Some(0.02);
    assert_eq!(
        compare_observed_dispatch_records(Some(&left), Some(&usage_difference)),
        RequirementFourComparability::DispatchGroundedSelectionsEquivalent
    );
    assert_eq!(
        compare_observed_supervisor_execution(
            left.supervisor_execution.as_ref(),
            usage_difference.supervisor_execution.as_ref(),
        ),
        ExecutionTelemetryComparability::Different
    );

    let different_selection = supervisor_execution_record_with_model("other-resolved-model");
    assert_eq!(
        compare_observed_dispatch_records(Some(&left), Some(&different_selection)),
        RequirementFourComparability::DispatchGroundedSelectionsDiffer
    );
    assert_eq!(
        compare_observed_supervisor_execution(
            left.supervisor_execution.as_ref(),
            different_selection.supervisor_execution.as_ref(),
        ),
        ExecutionTelemetryComparability::Different
    );
}

#[test]
fn legacy_or_incomplete_execution_metadata_is_incomparable() {
    let valid = complete_supervisor_execution_record();
    let identical_artifacts =
        compare_supervisor_final_artifacts(SUPERVISOR_EXECUTION_V2, SUPERVISOR_EXECUTION_V2);
    assert_eq!(
        identical_artifacts.comparability,
        RequirementFourComparability::DispatchGroundedSelectionsEquivalent
    );
    assert_eq!(
        identical_artifacts.execution_telemetry_comparability,
        ExecutionTelemetryComparability::Equivalent
    );
    let legacy_error =
        observed_dispatch_record_from_supervisor_final_json(SUPERVISOR_EXECUTION_V1_LEGACY)
            .expect_err("legacy profile must not acquire configured-value observations");
    assert!(legacy_error.contains("unsupported supervisor execution telemetry schema 1"));
    let legacy_comparison =
        compare_supervisor_final_artifacts(SUPERVISOR_EXECUTION_V1_LEGACY, SUPERVISOR_EXECUTION_V2);
    assert_eq!(
        legacy_comparison.comparability,
        RequirementFourComparability::Incomparable
    );
    assert_eq!(
        legacy_comparison.execution_telemetry_comparability,
        ExecutionTelemetryComparability::Incomparable
    );
    assert!(legacy_comparison
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("schema 1")));
    assert_eq!(
        compare_observed_dispatch_records(None, Some(&valid)),
        RequirementFourComparability::Incomparable
    );

    let mut incomplete_usage = valid.clone();
    let usage = &mut incomplete_usage
        .supervisor_execution
        .as_mut()
        .expect("execution")
        .usage;
    usage.usage_complete = false;
    usage.total_cost_usd = None;
    usage.unavailable_reason = Some("pricing was not process-observable".to_string());
    assert_eq!(
        compare_observed_dispatch_records(Some(&valid), Some(&incomplete_usage)),
        RequirementFourComparability::DispatchGroundedSelectionsEquivalent
    );
    assert_eq!(
        compare_observed_supervisor_execution(
            valid.supervisor_execution.as_ref(),
            incomplete_usage.supervisor_execution.as_ref(),
        ),
        ExecutionTelemetryComparability::Incomparable
    );
}

#[test]
fn unresolved_runtime_binding_remains_explicit_and_incomparable() {
    let valid = complete_supervisor_execution_record();
    let mut document: Value =
        serde_json::from_slice(SUPERVISOR_EXECUTION_V2).expect("parse v2 fixture");
    let worker = &mut document["role_economics_profile"]["execution"]["role_bindings"]["worker"];
    worker["resolved_model"] = Value::Null;
    worker["observation"] = json!("runtime_default_resolved");
    worker["unavailable_reason"] = json!("concrete model slug was not process-observable");
    let bytes = serde_json::to_vec(&document).expect("serialize unresolved fixture");
    let unresolved = observed_dispatch_record_from_supervisor_final_json(&bytes)
        .expect("explicit unresolved markers remain consumable");

    assert!(!unresolved
        .roles
        .iter()
        .any(|role| role.role == AgentRole::Worker));
    let worker_binding = unresolved
        .supervisor_execution
        .as_ref()
        .expect("execution")
        .role_bindings
        .iter()
        .find(|binding| binding.role == AgentRole::Worker)
        .expect("worker marker");
    assert_eq!(worker_binding.resolved_model, None);
    assert_eq!(
        worker_binding.observation,
        RoleBindingObservation::RuntimeDefaultResolved
    );
    assert_eq!(
        compare_observed_dispatch_records(Some(&valid), Some(&unresolved)),
        RequirementFourComparability::Incomparable
    );

    let mut missing_effort_document: Value =
        serde_json::from_slice(SUPERVISOR_EXECUTION_V2).expect("parse v2 fixture");
    missing_effort_document["role_economics_profile"]["execution"]["role_bindings"]["worker"]
        ["resolved_reasoning_effort"] = Value::Null;
    let missing_effort_bytes =
        serde_json::to_vec(&missing_effort_document).expect("serialize missing effort fixture");
    let missing_effort = observed_dispatch_record_from_supervisor_final_json(&missing_effort_bytes)
        .expect("explicit null effort remains retained");
    assert_eq!(
        missing_effort
            .supervisor_execution
            .as_ref()
            .expect("execution")
            .role_bindings
            .iter()
            .find(|binding| binding.role == AgentRole::Worker)
            .expect("worker binding")
            .resolved_reasoning_effort,
        None
    );
    assert_eq!(
        compare_observed_dispatch_records(Some(&valid), Some(&missing_effort)),
        RequirementFourComparability::Incomparable
    );
    assert_eq!(
        compare_observed_supervisor_execution(
            valid.supervisor_execution.as_ref(),
            missing_effort.supervisor_execution.as_ref(),
        ),
        ExecutionTelemetryComparability::Incomparable
    );
}

#[test]
fn public_comparators_reject_malformed_normalized_records() {
    let valid = complete_supervisor_execution_record();
    let mut malformed = valid.clone();
    let execution = malformed
        .supervisor_execution
        .as_mut()
        .expect("fixture execution");
    execution.schema_version = 1;
    assert_eq!(
        compare_observed_dispatch_records(Some(&malformed), Some(&malformed)),
        RequirementFourComparability::Incomparable
    );
    assert_eq!(
        compare_observed_supervisor_execution(
            malformed.supervisor_execution.as_ref(),
            malformed.supervisor_execution.as_ref(),
        ),
        ExecutionTelemetryComparability::Incomparable
    );

    let mut duplicate_roles = valid.clone();
    let bindings = &mut duplicate_roles
        .supervisor_execution
        .as_mut()
        .expect("fixture execution")
        .role_bindings;
    bindings[0].role = AgentRole::Worker;
    assert_eq!(
        compare_observed_dispatch_records(Some(&duplicate_roles), Some(&duplicate_roles)),
        RequirementFourComparability::Incomparable
    );

    let mut invalid_cost = valid;
    invalid_cost
        .supervisor_execution
        .as_mut()
        .expect("fixture execution")
        .usage
        .total_cost_usd = Some(f64::NAN);
    assert_eq!(
        compare_observed_supervisor_execution(
            invalid_cost.supervisor_execution.as_ref(),
            invalid_cost.supervisor_execution.as_ref(),
        ),
        ExecutionTelemetryComparability::Incomparable
    );
}

#[test]
fn equivalent_dispatches_refuse_a_pareto_conclusion() {
    let comparisons = vec![DispatchComparison {
        left_profile_id: "left".to_string(),
        right_profile_id: "right".to_string(),
        repetition: 0,
        comparability: RequirementFourComparability::DispatchGroundedSelectionsEquivalent,
        execution_telemetry_comparability: ExecutionTelemetryComparability::Equivalent,
        unavailable_reason: None,
    }];

    assert_eq!(
        pareto_conclusion(&comparisons).status,
        ParetoConclusionStatus::RefusedNoDispatchDifference
    );
}

#[test]
fn observed_dispatch_validation_requires_canonical_ordering() {
    let record = observed_dispatch_record_from_profile_binding(&complete_observed_binding(
        "observed-worker",
        "observed-review",
    ))
    .expect("complete dispatch record");

    let mut unsorted_models = record.clone();
    unsorted_models.roles[0].models = vec!["z-model".to_string(), "a-model".to_string()];
    let error = validate_observed_dispatch_record(&unsorted_models, 0)
        .expect_err("model reordering must not fabricate a dispatch difference");
    assert!(error.to_string().contains("canonical sorted order"));

    let mut unsorted_roles = record.clone();
    unsorted_roles.roles.push(ObservedRoleDispatch {
        role: AgentRole::ChildOrchestrator,
        models: vec!["observed-orchestrator".to_string()],
        reasoning_effort: None,
    });
    unsorted_roles.roles.sort();
    unsorted_roles.roles.reverse();
    let error = validate_observed_dispatch_record(&unsorted_roles, 0)
        .expect_err("role reordering must not fabricate a dispatch difference");
    assert!(error.to_string().contains("canonical sorted order"));

    let mut unsorted_lenses = record;
    let mut second_lens = unsorted_lenses.review_lenses[0].clone();
    second_lens.lens_id = "another-lens".to_string();
    unsorted_lenses.review_lenses.push(second_lens);
    unsorted_lenses.review_lenses.sort();
    unsorted_lenses.review_lenses.reverse();
    let error = validate_observed_dispatch_record(&unsorted_lenses, 0)
        .expect_err("review-lens reordering must not fabricate a dispatch difference");
    assert!(error.to_string().contains("canonical sorted order"));
}

#[test]
fn configured_difference_without_observed_selection_is_incomparable() {
    let mut absent = complete_observed_binding("observed-worker", "observed-review");
    absent.status = AutopilotProfileBindingStatus::Incomparable;
    absent.execution = None;
    absent.requested.role_models.insert(
        AgentRole::Worker,
        model("configured-only-difference", "high"),
    );

    assert!(observed_dispatch_record_from_profile_binding(&absent).is_err());
    assert_eq!(
        compare_observed_dispatch_records(None, None),
        RequirementFourComparability::Incomparable
    );
}

#[test]
fn one_incomparable_run_refuses_pareto_among_otherwise_grounded_comparisons() {
    let manifest = manifest();
    let mut results = run_fake(&manifest, 71).expect("fake result shell");
    for run in &mut results.runs {
        let model = if run.profile_id == manifest.profiles[0].id {
            "observed-a"
        } else {
            "observed-b"
        };
        run.observed_dispatch = Some(supervisor_execution_record_with_model(model));
    }
    results.runs[0].observed_dispatch = None;

    let comparisons =
        compare_same_repetition_dispatches(&manifest, &results.runs).expect("comparisons");
    assert!(comparisons.iter().any(|comparison| {
        comparison.comparability == RequirementFourComparability::DispatchGroundedSelectionsDiffer
    }));
    assert!(comparisons.iter().any(|comparison| {
        comparison.comparability == RequirementFourComparability::Incomparable
    }));
    let conclusion = pareto_conclusion(&comparisons);
    assert_eq!(
        conclusion.status,
        ParetoConclusionStatus::RefusedIncomparableDispatchEvidence
    );
    let (summaries, frontier) = summarize_profiles_with_pareto(&manifest, &results.runs, false)
        .expect("descriptive summaries without Pareto");
    assert!(frontier.is_empty());
    assert!(summaries.iter().all(|summary| !summary.pareto_optimal));
}

#[test]
fn provisional_fake_results_refuse_forged_observed_dispatch_records() {
    let manifest = manifest();
    let mut results = run_fake(&manifest, 73).expect("fake result shell");
    for run in &mut results.runs {
        let observed_model = if run.profile_id == manifest.profiles[0].id {
            "observed-a"
        } else {
            "observed-b"
        };
        run.observed_dispatch = Some(supervisor_execution_record_with_model(observed_model));
    }

    results.dispatch_comparisons =
        compare_same_repetition_dispatches(&manifest, &results.runs).expect("comparisons");
    results.pareto_conclusion = pareto_conclusion(&results.dispatch_comparisons);
    let pareto_allowed = results.pareto_conclusion.status == ParetoConclusionStatus::Available;
    (results.profile_summaries, results.pareto_frontier) =
        summarize_profiles_with_pareto(&manifest, &results.runs, pareto_allowed)
            .expect("internally coherent forged aggregates");
    assert_eq!(
        results.pareto_conclusion.status,
        ParetoConclusionStatus::Available
    );

    let serialized = serde_json::to_vec(&results).expect("serialize forged results");
    let forged = serde_json::from_slice::<EvaluationResults>(&serialized)
        .expect("deserialize forged results");
    let error = forged
        .validate_against(&manifest)
        .expect_err("Fake-labelled observations must not license grounded comparisons");
    assert!(error.to_string().contains("runs.observed_dispatch"));
    assert!(error
        .to_string()
        .contains("require separately retained A4 runtime provenance"));
}

#[test]
fn manifest_profile_count_accepts_boundary_and_refuses_excess() {
    let mut manifest = manifest();
    manifest.profiles = (0..MAX_EVALUATION_PROFILES)
        .map(|index| {
            profile(
                &format!("profile-{index}"),
                "orchestrator-model",
                &format!("worker-model-{index}"),
            )
        })
        .collect();
    manifest
        .validate()
        .expect("maximum profile count remains accepted");

    manifest.profiles.push(profile(
        "profile-over-limit",
        "orchestrator-model",
        "worker-model-over-limit",
    ));
    let error = manifest
        .validate()
        .expect_err("profile count above the conservative bound must fail closed");
    assert!(matches!(
        error,
        EvaluationError::InvalidManifest { ref field, .. } if field == "profiles"
    ));
    assert!(error
        .to_string()
        .contains(&format!("at most {MAX_EVALUATION_PROFILES}")));
}

#[test]
fn manifest_held_out_count_accepts_boundary_and_refuses_excess() {
    let mut manifest = manifest();
    manifest.held_out_validation = (0..MAX_EVALUATION_HELD_OUT_VALIDATIONS)
        .map(|index| HeldOutValidation {
            id: format!("held-out-{index}"),
            command: vec!["true".to_string()],
        })
        .collect();
    manifest
        .validate()
        .expect("maximum held-out validation count remains accepted");

    manifest.held_out_validation.push(HeldOutValidation {
        id: "held-out-over-limit".to_string(),
        command: vec!["true".to_string()],
    });
    let error = manifest
        .validate()
        .expect_err("held-out count above the conservative bound must fail closed");
    assert!(matches!(
        error,
        EvaluationError::InvalidManifest { ref field, .. } if field == "held_out_validation"
    ));
    assert!(error
        .to_string()
        .contains(&format!("at most {MAX_EVALUATION_HELD_OUT_VALIDATIONS}")));
}

#[test]
fn committed_fixtures_match_the_deterministic_harness() {
    let manifest = committed_manifest();
    manifest.validate().expect("validate committed manifest");
    manifest
        .validate_hand_authored_plan(FIXTURE_PLAN)
        .expect("manifest binds the exact committed plan bytes");

    let results = committed_results();
    assert_eq!(results.fake_seed, COMMITTED_FIXTURE_FAKE_SEED);
    results
        .validate_against(&manifest)
        .expect("committed results validate against their manifest");
    let reproduced = run_evaluation(
        &manifest,
        FIXTURE_PLAN,
        EvaluationRunRequest {
            fake_seed: COMMITTED_FIXTURE_FAKE_SEED,
            ..EvaluationRunRequest::default()
        },
    )
    .expect("reproduce committed deterministic results");
    assert_eq!(
        FIXTURE_RESULTS,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&reproduced)
                .expect("serialize reproduced deterministic results")
        )
    );

    let summary = committed_summary();
    summary
        .validate_against(&manifest, &results)
        .expect("committed summary is an exact validated projection");
    assert_eq!(
        FIXTURE_SUMMARY,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&reproduced.summary())
                .expect("serialize reproduced deterministic summary")
        )
    );
}

#[test]
fn committed_fixtures_use_unique_synthetic_ids_without_comparability_claims() {
    let manifest = committed_manifest();
    let results = committed_results();
    results
        .validate_against(&manifest)
        .expect("fixture declared-input consistency validation");

    let expected_runs = manifest.profiles.len() * manifest.repetitions as usize;
    assert_eq!(results.runs.len(), expected_runs);
    for profile in &manifest.profiles {
        let repetitions = results
            .runs
            .iter()
            .filter(|run| run.profile_id == profile.id)
            .map(|run| run.repetition)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            repetitions,
            (0..manifest.repetitions).collect::<BTreeSet<_>>()
        );
    }

    let fake_run_ids = results
        .runs
        .iter()
        .map(|run| run.synthetic_run_identity.fake_run_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(fake_run_ids.len(), expected_runs);
    assert!(!results.evidence.observed_isolated_repository_state);
    assert_eq!(
        results.evidence.requirement_four_comparability,
        RequirementFourComparability::NotEstablishedDeferredToPhaseB
    );
    assert!(results
        .runs
        .iter()
        .all(|run| run.declared_inputs_digest == results.declared_inputs_digest));
}

#[test]
fn committed_fixtures_have_complete_metrics_and_anti_shortcut_aware_pareto_results() {
    let manifest = committed_manifest();
    let results = committed_results();
    results
        .validate_against(&manifest)
        .expect("fixture metric and Pareto validation");

    for run in &results.runs {
        let profile = manifest
            .profiles
            .iter()
            .find(|profile| profile.id == run.profile_id)
            .expect("run profile is manifest-bound");
        assert_eq!(run.metrics.role_usage.len(), profile.role_models.len());
        assert!(run.metrics.role_usage.values().all(|report| {
            report.usage.is_some()
                && report.cost_usd.is_some()
                && report.observation == RoleUsageObservation::SyntheticFake
        }));
        assert_eq!(
            run.metrics.held_out_validation.len(),
            manifest.held_out_validation.len()
        );
        assert!(run.metrics.review.breadth.checks_run > 0);
        assert!(run.metrics.review.anti_shortcut.checks_run > 0);
        assert!(run.metrics.quality.held_out_basis_points <= BASIS_POINTS);
        assert!(run.metrics.quality.breadth_basis_points <= BASIS_POINTS);
        assert!(run.metrics.quality.anti_shortcut_basis_points <= BASIS_POINTS);
    }

    assert!(results.pareto_frontier.is_empty());
    assert_eq!(
        results.pareto_conclusion.status,
        ParetoConclusionStatus::RefusedIncomparableDispatchEvidence
    );
    assert!(results.profile_summaries.iter().all(|summary| {
        summary
            .aggregate_role_usage
            .values()
            .all(|report| report.observation == RoleUsageObservation::SyntheticFake)
    }));
    assert!(results
        .profile_summaries
        .iter()
        .all(|summary| !summary.pareto_optimal));
    let frontier_profiles = results
        .pareto_frontier
        .iter()
        .map(|point| point.profile_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        frontier_profiles,
        results
            .profile_summaries
            .iter()
            .filter(|summary| summary.pareto_optimal)
            .map(|summary| summary.profile_id.as_str())
            .collect()
    );
}

#[test]
fn committed_fixtures_are_schema_labeled_provisional_fake_only() {
    let manifest = committed_manifest();
    let results = committed_results();
    let summary = committed_summary();
    let plan: Value = serde_json::from_slice(FIXTURE_PLAN).expect("parse committed plan");
    let plan_evidence: EvaluationEvidence =
        serde_json::from_value(plan["evidence"].clone()).expect("parse plan evidence");
    for evidence in [
        &manifest.evidence,
        &plan_evidence,
        &results.evidence,
        &summary.evidence,
    ] {
        assert_eq!(
            evidence.kind,
            EvaluationEvidenceKind::ProvisionalDeterministicFakeOnly
        );
        assert_eq!(evidence.plan_basis, EvaluationPlanBasis::HandAuthored);
        assert!(!evidence.real_provider_executed);
        assert!(!evidence.observed_isolated_repository_state);
        assert_eq!(
            evidence.requirement_four_comparability,
            RequirementFourComparability::NotEstablishedDeferredToPhaseB
        );
        assert!(!evidence.eligible_for_production_economics);
        assert!(!evidence.eligible_to_justify_named_default);
        assert!(!evidence.eligible_for_production_or_default_decisions);
        assert_eq!(evidence.notice, PROVISIONAL_FAKE_EVIDENCE_NOTICE);
    }
}

#[test]
#[ignore = "explicit snapshot regeneration only"]
fn regenerate_committed_evaluation_fixtures() {
    let manifest = committed_manifest();
    manifest.validate().expect("validate committed manifest");
    manifest
        .validate_hand_authored_plan(FIXTURE_PLAN)
        .expect("manifest binds committed plan");
    let results = run_evaluation(
        &manifest,
        FIXTURE_PLAN,
        EvaluationRunRequest {
            fake_seed: COMMITTED_FIXTURE_FAKE_SEED,
            ..EvaluationRunRequest::default()
        },
    )
    .expect("generate deterministic fixture results");
    let summary = results.summary();
    let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/model_mix_evaluation");

    std::fs::write(
        fixture_root.join("runs-v1.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&results).expect("serialize fixture results")
        ),
    )
    .expect("write fixture results");
    std::fs::write(
        fixture_root.join("summary-v1.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&summary).expect("serialize fixture summary")
        ),
    )
    .expect("write fixture summary");
}

#[test]
fn deterministic_fake_results_are_reproducible_complete_and_provisional() {
    let manifest = manifest();
    let request = EvaluationRunRequest {
        fake_seed: 42,
        ..EvaluationRunRequest::default()
    };
    let plan = labelled_test_plan();
    let first = run_evaluation(&manifest, &plan, request).expect("first deterministic fake run");
    let second = run_evaluation(&manifest, &plan, request).expect("second deterministic fake run");

    assert_eq!(first, second);
    assert_eq!(
        first.evidence.kind,
        EvaluationEvidenceKind::ProvisionalDeterministicFakeOnly
    );
    assert!(!first.evidence.real_provider_executed);
    assert!(!first.evidence.observed_isolated_repository_state);
    assert!(!first.evidence.eligible_for_production_economics);
    assert!(!first.evidence.eligible_to_justify_named_default);
    assert_eq!(first.runs.len(), 6);
    assert_eq!(first.profile_summaries.len(), 2);
    assert!(first.pareto_frontier.is_empty());
    assert_eq!(
        first.pareto_conclusion.status,
        ParetoConclusionStatus::RefusedIncomparableDispatchEvidence
    );

    let fake_run_ids = first
        .runs
        .iter()
        .map(|run| run.synthetic_run_identity.fake_run_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(fake_run_ids.len(), first.runs.len());
    for run in &first.runs {
        assert_eq!(run.metrics.role_usage.len(), 2);
        assert!(run
            .metrics
            .role_usage
            .values()
            .all(|usage| usage.usage.is_some() && usage.cost_usd.is_some()));
        assert_eq!(run.metrics.held_out_validation.len(), 2);
        assert!(run.metrics.review.breadth.checks_run > 0);
        assert!(run.metrics.review.anti_shortcut.checks_run > 0);
    }
    first
        .validate_against(&manifest)
        .expect("generated results remain consistent with declared inputs");
}

#[test]
fn deterministic_fake_retains_all_outcomes_and_obeys_execution_limits() {
    let mut manifest = manifest();
    manifest.limits = EvaluationLimits {
        wall_time_seconds: 1,
        max_dispatches: 1,
    };
    let results = run_fake(&manifest, 31).expect("bounded fake results");

    assert_eq!(
        results.runs.len(),
        manifest.profiles.len() * manifest.repetitions as usize
    );
    let outcomes = results
        .runs
        .iter()
        .map(|run| run.execution.outcome)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        outcomes,
        BTreeSet::from([
            EvaluationExecutionOutcome::Success,
            EvaluationExecutionOutcome::Failure,
            EvaluationExecutionOutcome::Timeout,
        ])
    );
    assert_eq!(
        results
            .runs
            .iter()
            .filter(|run| run.execution.outcome != EvaluationExecutionOutcome::Success)
            .count(),
        manifest.profiles.len() * 2
    );

    for run in &results.runs {
        assert!(run.execution.observed_dispatch_count <= manifest.limits.max_dispatches);
        assert!(run.metrics.wall_time_ms <= manifest.limits.wall_time_seconds * 1_000);
        match run.execution.outcome {
            EvaluationExecutionOutcome::Success => {
                assert!(run.execution.error_evidence.is_none());
            }
            EvaluationExecutionOutcome::Failure | EvaluationExecutionOutcome::Timeout => {
                let error = run
                    .execution
                    .error_evidence
                    .as_ref()
                    .expect("unsuccessful fake run retains bounded error evidence");
                assert!(!error.message.trim().is_empty());
                assert!(error.message.len() <= MAX_EXECUTION_ERROR_EVIDENCE_BYTES);
            }
        }
    }
    assert!(results
        .profile_summaries
        .iter()
        .all(|summary| summary.repetitions == manifest.repetitions));
    results
        .validate_against(&manifest)
        .expect("successes and retained unsuccessful runs validate together");
}

#[test]
fn execution_validation_enforces_limits_and_bounded_outcome_evidence() {
    let manifest = manifest();

    let mut results = run_fake(&manifest, 37).expect("fake results");
    results.runs[0].execution.observed_dispatch_count = manifest.limits.max_dispatches + 1;
    let error = results
        .validate_against(&manifest)
        .expect_err("dispatch limit must be enforced");
    assert!(error.to_string().contains("exceeds manifest limit"));
    assert!(error.to_string().contains("observed_dispatch_count"));

    let mut results = run_fake(&manifest, 37).expect("fake results");
    results.runs[0].metrics.wall_time_ms = manifest.limits.wall_time_seconds * 1_000 + 1;
    let error = results
        .validate_against(&manifest)
        .expect_err("wall-time limit must be enforced");
    assert!(error.to_string().contains("exceeds manifest limit"));
    assert!(error.to_string().contains("wall_time_ms"));

    let mut results = run_fake(&manifest, 37).expect("fake results");
    let failed = results
        .runs
        .iter_mut()
        .find(|run| run.execution.outcome == EvaluationExecutionOutcome::Failure)
        .expect("fake failure");
    failed.execution.error_evidence = None;
    let error = results
        .validate_against(&manifest)
        .expect_err("failure evidence is required");
    assert!(error
        .to_string()
        .contains("required when outcome is failure"));

    let mut results = run_fake(&manifest, 37).expect("fake results");
    let successful = results
        .runs
        .iter_mut()
        .find(|run| run.execution.outcome == EvaluationExecutionOutcome::Success)
        .expect("fake success");
    successful.execution.error_evidence = Some(ExecutionErrorEvidence {
        message: "unexpected evidence".to_string(),
        truncated: false,
    });
    let error = results
        .validate_against(&manifest)
        .expect_err("success cannot carry error evidence");
    assert!(error.to_string().contains("must be absent"));

    let mut results = run_fake(&manifest, 37).expect("fake results");
    let timed_out = results
        .runs
        .iter_mut()
        .find(|run| run.execution.outcome == EvaluationExecutionOutcome::Timeout)
        .expect("fake timeout");
    timed_out
        .execution
        .error_evidence
        .as_mut()
        .expect("timeout evidence")
        .message = "x".repeat(MAX_EXECUTION_ERROR_EVIDENCE_BYTES + 1);
    let error = results
        .validate_against(&manifest)
        .expect_err("oversized error evidence must fail closed");
    assert!(error
        .to_string()
        .contains("must be at most 256 UTF-8 bytes"));
}

#[test]
fn precise_profile_means_retain_non_divisible_totals() {
    let manifest = manifest();
    let mut results = run_fake(&manifest, 41).expect("fake results");
    let profile_id = manifest.profiles[0].id.as_str();
    for (index, run) in results
        .runs
        .iter_mut()
        .filter(|run| run.profile_id == profile_id)
        .enumerate()
    {
        let value = if index == 0 { 1 } else { 2 };
        run.metrics.wall_time_ms = value;
        run.metrics.churn_count = value;
        run.metrics.conflict_count = value;
        run.metrics.loc_added = value;
        run.metrics.loc_deleted = value;
        run.metrics.diff_bytes = value;
        run.metrics.quality = QualityScore {
            held_out_basis_points: value as u32,
            breadth_basis_points: value as u32,
            anti_shortcut_basis_points: value as u32,
            overall_basis_points: value as u32,
        };
    }

    let (summaries, _) =
        summarize_profiles(&manifest, &results.runs).expect("summarize exact totals");
    let summary = summaries
        .iter()
        .find(|summary| summary.profile_id == profile_id)
        .expect("profile summary");
    let five_thirds = PreciseMean { total: 5, count: 3 };
    assert_eq!(summary.mean_wall_time_ms, five_thirds);
    assert_eq!(summary.mean_churn_count, five_thirds);
    assert_eq!(summary.mean_conflict_count, five_thirds);
    assert_eq!(summary.mean_loc_added, five_thirds);
    assert_eq!(summary.mean_loc_deleted, five_thirds);
    assert_eq!(summary.mean_diff_bytes, five_thirds);
    assert_eq!(summary.mean_quality.held_out_basis_points, five_thirds);
    assert_eq!(summary.mean_quality.breadth_basis_points, five_thirds);
    assert_eq!(summary.mean_quality.anti_shortcut_basis_points, five_thirds);
    assert_eq!(summary.mean_quality.overall_basis_points, five_thirds);
}

#[test]
fn versioned_schemas_round_trip_and_reject_unknown_fields() {
    let manifest = manifest();
    let manifest_json = serde_json::to_value(&manifest).expect("serialize manifest");
    assert_eq!(
        manifest_json["version"],
        json!(EVALUATION_MANIFEST_SCHEMA_VERSION)
    );
    assert_eq!(
        serde_json::from_value::<EvaluationManifest>(manifest_json).expect("read manifest"),
        manifest
    );

    let results = run_fake(&manifest, 7).expect("fake results");
    let results_json = serde_json::to_value(&results).expect("serialize results");
    assert_eq!(
        results_json["version"],
        json!(EVALUATION_RESULTS_SCHEMA_VERSION)
    );
    assert_eq!(
        results_json["evidence"]["kind"],
        json!("provisional_deterministic_fake_only")
    );
    let decoded = serde_json::from_value::<EvaluationResults>(results_json).expect("read results");
    decoded
        .validate_against(&manifest)
        .expect("valid round trip");

    let mut invalid_manifest = serde_json::to_value(&manifest).expect("serialize manifest");
    invalid_manifest["unversioned_extension"] = json!(true);
    let error = serde_json::from_value::<EvaluationManifest>(invalid_manifest)
        .expect_err("unknown manifest fields fail closed");
    assert!(error.to_string().contains("unknown field"));

    let mut invalid_manifest_evidence =
        serde_json::to_value(&manifest).expect("serialize manifest");
    invalid_manifest_evidence["evidence"]["unversioned_extension"] = json!(true);
    let error = serde_json::from_value::<EvaluationManifest>(invalid_manifest_evidence)
        .expect_err("unknown manifest evidence fields fail closed");
    assert!(error.to_string().contains("unknown field"));

    let mut invalid_selection = serde_json::to_value(&manifest).expect("serialize manifest");
    invalid_selection["profiles"][0]["role_models"]["worker"]["unexpected_selection_field"] =
        json!(true);
    let error = serde_json::from_value::<EvaluationManifest>(invalid_selection)
        .expect_err("unknown RoleModelSelection fields fail closed");
    assert!(error.to_string().contains("unknown field"));

    let results = run_fake(&manifest, 7).expect("fake results");
    let mut invalid_total_usage = serde_json::to_value(&results).expect("serialize results");
    invalid_total_usage["runs"][0]["metrics"]["total_usage"]["unexpected_usage_field"] =
        json!(true);
    let error = serde_json::from_value::<EvaluationResults>(invalid_total_usage)
        .expect_err("unknown Usage fields fail closed");
    assert!(error.to_string().contains("unknown field"));

    let mut invalid_role_report = serde_json::to_value(&results).expect("serialize results");
    invalid_role_report["runs"][0]["metrics"]["role_usage"]["worker"]
        ["unexpected_role_usage_field"] = json!(true);
    let error = serde_json::from_value::<EvaluationResults>(invalid_role_report)
        .expect_err("unknown RoleUsageReport fields fail closed");
    assert!(error.to_string().contains("unknown field"));

    let mut invalid_nested_usage = serde_json::to_value(&results).expect("serialize results");
    invalid_nested_usage["profile_summaries"][0]["aggregate_role_usage"]["worker"]["usage"]
        ["unexpected_nested_usage_field"] = json!(true);
    let error = serde_json::from_value::<EvaluationResults>(invalid_nested_usage)
        .expect_err("nested unknown Usage fields in summaries fail closed");
    assert!(error.to_string().contains("unknown field"));

    let mut invalid_finding = serde_json::to_value(&results).expect("serialize results");
    invalid_finding["runs"][0]["metrics"]["review"]["findings"] = json!([{
        "severity": "warning",
        "message": "representative review finding",
        "paths": [],
        "unexpected_finding_field": true
    }]);
    let error = serde_json::from_value::<EvaluationResults>(invalid_finding)
        .expect_err("unknown Finding fields fail closed");
    assert!(error.to_string().contains("unknown field"));

    let mut supervisor_record = serde_json::to_value(complete_supervisor_execution_record())
        .expect("serialize supervisor execution record");
    supervisor_record["supervisor_execution"]["usage"]["total_usage"]["unexpected_usage_field"] =
        json!(true);
    let error = serde_json::from_value::<ObservedDispatchRecord>(supervisor_record)
        .expect_err("unknown supervisor execution usage fields fail closed");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
// Exercises the full v2 document path, not only permissive field decoding.
fn legacy_results_without_execution_telemetry_or_typed_pareto_coordinates_remain_readable() {
    let manifest = manifest();
    let results = run_fake(&manifest, 7).expect("current fake results");
    let mut legacy_json = serde_json::to_value(&results).expect("serialize results");
    legacy_json["version"] = json!(LEGACY_EVALUATION_RESULTS_SCHEMA_VERSION);
    let legacy_binding = legacy_json["objective_scoring"]["applied_profile"]["profile"].clone();
    let legacy_object = legacy_json.as_object_mut().expect("legacy result object");
    legacy_object.remove("objective_scoring");
    legacy_object.remove("objective_selection");
    legacy_object.insert("objective_profile".to_string(), legacy_binding);
    legacy_json["declared_inputs"]
        .as_object_mut()
        .expect("declared input object")
        .remove("objective_profile");
    let legacy_declared_inputs: DeclaredInputsBinding =
        serde_json::from_value(legacy_json["declared_inputs"].clone())
            .expect("legacy declared inputs");
    let legacy_digest = digest_serializable(&legacy_declared_inputs).expect("legacy input digest");
    legacy_json["declared_inputs_digest"] = json!(legacy_digest.clone());
    for run in legacy_json["runs"].as_array_mut().expect("legacy runs") {
        run["declared_inputs_digest"] = json!(legacy_digest.clone());
    }
    for comparison in legacy_json["dispatch_comparisons"]
        .as_array_mut()
        .expect("comparison array")
    {
        comparison
            .as_object_mut()
            .expect("comparison object")
            .remove("execution_telemetry_comparability");
        comparison["unavailable_reason"] = json!(
            "not_process_observable: one or both runs lack a complete observed dispatch record"
        );
    }
    for point in legacy_json["pareto_frontier"]
        .as_array_mut()
        .expect("Pareto frontier array")
    {
        let point = point.as_object_mut().expect("Pareto frontier point object");
        point.remove("mean_quota_consumption_tokens");
        point.remove("mean_wall_time_ms");
    }
    let legacy =
        serde_json::from_value::<EvaluationResults>(legacy_json).expect("read legacy v2 results");
    assert!(legacy.dispatch_comparisons.iter().all(|comparison| {
        comparison.execution_telemetry_comparability
            == ExecutionTelemetryComparability::Incomparable
    }));
    legacy.validate_against(&manifest).expect(
        "legacy v2 results remain readable despite absent execution telemetry and later typed \
             Pareto coordinates",
    );

    // Historical result documents with a populated frontier used this exact
    // point shape even though the provisional fixture above cannot itself
    // license a nonempty production frontier.
    let summary = &results.profile_summaries[0];
    let current_point = ParetoPoint {
        profile_id: summary.profile_id.clone(),
        mean_cost_usd: summary.mean_cost_usd,
        mean_quota_consumption_tokens: Some(
            PreciseMean::new(
                u64::try_from(summary.aggregate_usage.total_tokens)
                    .expect("test token total fits u64"),
                summary.repetitions,
            )
            .expect("valid test quota mean"),
        ),
        mean_wall_time_ms: Some(summary.mean_wall_time_ms),
        quality_basis_points: summary.mean_quality.overall_basis_points,
        held_out_basis_points: summary.mean_quality.held_out_basis_points,
        breadth_basis_points: summary.mean_quality.breadth_basis_points,
        anti_shortcut_basis_points: summary.mean_quality.anti_shortcut_basis_points,
    };
    let mut old_point_json = serde_json::to_value(&current_point).expect("serialize Pareto point");
    let old_point = old_point_json.as_object_mut().expect("Pareto point object");
    old_point.remove("mean_quota_consumption_tokens");
    old_point.remove("mean_wall_time_ms");
    let legacy_point =
        serde_json::from_value::<ParetoPoint>(old_point_json).expect("read v2 Pareto point");
    assert!(pareto_frontiers_equivalent(
        &[legacy_point],
        &[current_point],
        true,
    ));
}

#[test]
fn public_runner_binds_and_validates_supplied_plan_bytes_before_dispatch() {
    let manifest = manifest();
    for request in [
        EvaluationRunRequest::default(),
        EvaluationRunRequest {
            execution: EvaluationExecution::RealProvider,
            allow_real_provider: true,
            fake_seed: 0,
        },
    ] {
        let mismatch = run_evaluation(&manifest, br#"{"evidence":{}}"#, request)
            .expect_err("mismatched bytes must fail before execution selection");
        assert!(matches!(
            mismatch,
            EvaluationError::HandAuthoredPlanBindingMismatch { .. }
        ));
    }

    let invalid_json = b"not-json";
    let mut invalid_manifest = manifest.clone();
    invalid_manifest.target.hand_authored_plan_digest =
        format!("sha256:{}", sha256_hex(invalid_json));
    let invalid = run_evaluation(
        &invalid_manifest,
        invalid_json,
        EvaluationRunRequest::default(),
    )
    .expect_err("digest-matched invalid JSON must fail before fake execution");
    assert!(matches!(
        invalid,
        EvaluationError::InvalidHandAuthoredPlan { .. }
    ));

    let unlabelled = br#"{"version":1,"task":"unlabelled"}"#;
    let mut unlabelled_manifest = manifest;
    unlabelled_manifest.target.hand_authored_plan_digest =
        format!("sha256:{}", sha256_hex(unlabelled));
    let unlabelled_error = run_evaluation(
        &unlabelled_manifest,
        unlabelled,
        EvaluationRunRequest::default(),
    )
    .expect_err("digest-matched unlabelled JSON must fail before fake execution");
    assert!(matches!(
        unlabelled_error,
        EvaluationError::InvalidHandAuthoredPlan { .. }
    ));
}

#[test]
fn real_provider_execution_has_opt_in_and_phase_a_refusal_gates() {
    let manifest = manifest();
    let plan = labelled_test_plan();
    let without_opt_in = run_evaluation(
        &manifest,
        &plan,
        EvaluationRunRequest {
            execution: EvaluationExecution::RealProvider,
            allow_real_provider: false,
            fake_seed: 0,
        },
    );
    assert_eq!(
        without_opt_in,
        Err(EvaluationError::RealProviderOptInRequired)
    );

    let explicitly_opted_in = run_evaluation(
        &manifest,
        &plan,
        EvaluationRunRequest {
            execution: EvaluationExecution::RealProvider,
            allow_real_provider: true,
            fake_seed: 0,
        },
    );
    assert_eq!(
        explicitly_opted_in,
        Err(EvaluationError::RealProviderUnavailableInPhaseA)
    );
}

#[test]
fn manifest_rejects_hidden_or_inconsistent_profile_inputs() {
    let mut candidate = manifest();
    candidate.repository_base_snapshot = "main".to_string();
    let error = candidate
        .validate()
        .expect_err("symbolic Git refs are not immutable");
    assert!(matches!(
        error,
        EvaluationError::InvalidManifest { ref field, .. }
            if field == "repository_base_snapshot"
    ));

    let mut candidate = manifest();
    candidate.profiles[1].role_models = candidate.profiles[0].role_models.clone();
    let error = candidate
        .validate()
        .expect_err("duplicate mixes are rejected");
    assert!(error.to_string().contains("duplicates another"));

    let mut candidate = manifest();
    candidate.profiles[1]
        .role_models
        .insert(AgentRole::Auditor, model("review-v1", "high"));
    let error = candidate
        .validate()
        .expect_err("profile role sets must match");
    assert!(error.to_string().contains("role set differs"));

    let mut candidate = manifest();
    candidate.profiles[0]
        .role_models
        .get_mut(&AgentRole::Worker)
        .expect("worker selection")
        .model = None;
    let error = candidate
        .validate()
        .expect_err("ambient model defaults are not reproducible");
    assert!(error.to_string().contains("explicitly name a model"));
}

#[test]
fn phase_a_profiles_account_for_gate_classifier_independently() {
    let mut candidate = manifest();
    candidate.profiles[0].role_models.insert(
        AgentRole::GateClassifier,
        model("classifier-balanced-v1", "high"),
    );
    candidate.profiles[1].role_models.insert(
        AgentRole::GateClassifier,
        model("classifier-economy-v1", "medium"),
    );
    candidate.validate().expect("classifier profiles validate");
    let results = run_fake(&candidate, 34).expect("classifier fake results");
    for run in &results.runs {
        let classifier = &run.metrics.role_usage[&AgentRole::GateClassifier];
        assert_eq!(classifier.observation, RoleUsageObservation::SyntheticFake);
        assert!(classifier.usage.is_some());
        assert!(classifier.cost_usd.is_some());
        assert_eq!(
            run.metrics.role_usage[&AgentRole::Worker].observation,
            RoleUsageObservation::SyntheticFake
        );
    }
}

#[test]
fn declared_input_validation_rejects_reused_ids_or_changed_bindings() {
    let manifest = manifest();
    let mut results = run_fake(&manifest, 11).expect("fake results");
    results.runs[1].synthetic_run_identity.fake_run_id =
        results.runs[0].synthetic_run_identity.fake_run_id.clone();
    let error = results
        .validate_against(&manifest)
        .expect_err("a synthetic run identity cannot be reused");
    assert!(error.to_string().contains("was reused"));

    let mut results = run_fake(&manifest, 11).expect("fake results");
    results.declared_inputs.limits.max_dispatches += 1;
    let error = results
        .validate_against(&manifest)
        .expect_err("changed dispatch limits break declared-input consistency");
    assert!(error
        .to_string()
        .contains("full role/model profile set differ"));

    let results = run_fake(&manifest, 11).expect("fake results");
    let mut changed_manifest = manifest.clone();
    changed_manifest.profiles[0]
        .role_models
        .get_mut(&AgentRole::Worker)
        .expect("worker selection")
        .reasoning_effort = Some("low".to_string());
    changed_manifest
        .validate()
        .expect("reasoning-effort variant remains a valid manifest");
    let error = results
        .validate_against(&changed_manifest)
        .expect_err("reasoning-effort drift changes the full profile binding");
    assert!(error
        .to_string()
        .contains("full role/model profile set differ"));
}

#[test]
fn metric_validation_requires_complete_accounting_and_quality_evidence() {
    let manifest = manifest();
    let mut results = run_fake(&manifest, 19).expect("fake results");
    results.runs[0]
        .metrics
        .role_usage
        .get_mut(&AgentRole::Worker)
        .expect("worker usage")
        .cost_usd = None;
    let error = results
        .validate_against(&manifest)
        .expect_err("per-role cost is required");
    assert!(error.to_string().contains("per-role cost is required"));

    let mut results = run_fake(&manifest, 19).expect("fake results");
    results.runs[0]
        .metrics
        .role_usage
        .get_mut(&AgentRole::Worker)
        .expect("worker usage")
        .observation = RoleUsageObservation::ProcessObserved;
    let error = results
        .validate_against(&manifest)
        .expect_err("synthetic usage cannot be labelled process-observed");
    assert!(error.to_string().contains("synthetic_fake"));

    let mut results = run_fake(&manifest, 19).expect("fake results");
    results.runs[0].metrics.review.anti_shortcut.checks_run = 0;
    let error = results
        .validate_against(&manifest)
        .expect_err("anti-shortcut evidence cannot be omitted");
    assert!(error.to_string().contains("must be greater than zero"));

    let mut results = run_fake(&manifest, 19).expect("fake results");
    results.runs[0].metrics.total_usage.total_tokens += 1;
    let error = results
        .validate_against(&manifest)
        .expect_err("incoherent token accounting is rejected");
    assert!(error.to_string().contains("input_tokens + output_tokens"));
}

#[test]
fn quality_and_pareto_retain_breadth_and_anti_shortcut_signals() {
    let held_out = vec![HeldOutValidationResult {
        id: "held-out".to_string(),
        assertions_run: 10,
        assertions_passed: 10,
        passed: true,
    }];
    let full_review = ReviewQuality {
        breadth: ReviewDimension {
            checks_run: 10,
            checks_passed: 10,
        },
        anti_shortcut: ReviewDimension {
            checks_run: 10,
            checks_passed: 10,
        },
        findings: Vec::new(),
    };
    let shortcut_review = ReviewQuality {
        breadth: ReviewDimension {
            checks_run: 10,
            checks_passed: 10,
        },
        anti_shortcut: ReviewDimension {
            checks_run: 10,
            checks_passed: 0,
        },
        findings: Vec::new(),
    };
    let objective = crate::objective_profile::default_resolved_objective_profile()
        .expect("resolved default objective");
    let full_quality =
        calculate_quality(&objective, &held_out, &full_review).expect("full quality");
    let shortcut_quality =
        calculate_quality(&objective, &held_out, &shortcut_review).expect("shortcut quality");
    assert_eq!(full_quality.overall_basis_points, BASIS_POINTS);
    assert_eq!(shortcut_quality.overall_basis_points, 7_500);

    let results = run_fake(&manifest(), 23).expect("fake results");
    let mut high_quality = results.profile_summaries[0].clone();
    high_quality.mean_cost_usd = 1.0;
    high_quality.mean_loc_added = PreciseMean {
        total: 1_000,
        count: 1,
    };
    high_quality.mean_quality = precise_quality(full_quality);
    let mut shortcut = results.profile_summaries[1].clone();
    shortcut.mean_cost_usd = 1.0;
    shortcut.aggregate_usage = high_quality.aggregate_usage;
    shortcut.mean_wall_time_ms = high_quality.mean_wall_time_ms;
    shortcut.mean_loc_added = PreciseMean { total: 1, count: 1 };
    shortcut.mean_quality = precise_quality(shortcut_quality);

    assert!(dominates(&high_quality, &shortcut));
    assert!(!dominates(&shortcut, &high_quality));

    shortcut.mean_cost_usd = 0.5;
    assert!(!dominates(&high_quality, &shortcut));
    assert!(!dominates(&shortcut, &high_quality));
}

#[test]
fn pareto_dominance_is_preference_free_across_raw_quality_axes() {
    let results = run_fake(&manifest(), 127).expect("fake summary shells");
    let mut held_out_specialist = results.profile_summaries[0].clone();
    held_out_specialist.mean_cost_usd = 1.0;
    held_out_specialist.mean_quality = precise_quality(QualityScore {
        held_out_basis_points: 10_000,
        breadth_basis_points: 0,
        anti_shortcut_basis_points: 0,
        overall_basis_points: 5_000,
    });
    let mut review_specialist = results.profile_summaries[1].clone();
    review_specialist.mean_cost_usd = 1.0;
    review_specialist.aggregate_usage = held_out_specialist.aggregate_usage;
    review_specialist.mean_wall_time_ms = held_out_specialist.mean_wall_time_ms;
    review_specialist.mean_quality = precise_quality(QualityScore {
        held_out_basis_points: 0,
        breadth_basis_points: 10_000,
        anti_shortcut_basis_points: 10_000,
        overall_basis_points: 5_000,
    });

    assert!(!dominates(&held_out_specialist, &review_specialist));
    assert!(!dominates(&review_specialist, &held_out_specialist));

    review_specialist.mean_quality.overall_basis_points = PreciseMean {
        total: 7_500,
        count: 1,
    };
    assert!(
        !dominates(&review_specialist, &held_out_specialist),
        "a profile-weighted overall score must not change Pareto membership"
    );
}

#[test]
fn loc_or_held_out_pass_inflation_alone_cannot_win_quality() {
    let perfect_held_out = vec![HeldOutValidationResult {
        id: "held-out".to_string(),
        assertions_run: 100,
        assertions_passed: 100,
        passed: true,
    }];
    let shortcut_only = ReviewQuality {
        breadth: ReviewDimension {
            checks_run: 10,
            checks_passed: 0,
        },
        anti_shortcut: ReviewDimension {
            checks_run: 10,
            checks_passed: 0,
        },
        findings: Vec::new(),
    };
    let broad_review = ReviewQuality {
        breadth: ReviewDimension {
            checks_run: 10,
            checks_passed: 10,
        },
        anti_shortcut: ReviewDimension {
            checks_run: 10,
            checks_passed: 10,
        },
        findings: Vec::new(),
    };
    let objective = crate::objective_profile::default_resolved_objective_profile()
        .expect("resolved default objective");
    let shortcut_quality =
        calculate_quality(&objective, &perfect_held_out, &shortcut_only).expect("shortcut quality");
    let broad_quality =
        calculate_quality(&objective, &perfect_held_out, &broad_review).expect("broad quality");
    assert_eq!(shortcut_quality.held_out_basis_points, BASIS_POINTS);
    assert!(shortcut_quality.overall_basis_points < broad_quality.overall_basis_points);

    let results = run_fake(&manifest(), 73).expect("fake summary shells");
    let mut inflated = results.profile_summaries[0].clone();
    inflated.mean_cost_usd = 1.0;
    inflated.mean_loc_added = PreciseMean {
        total: u64::MAX,
        count: 1,
    };
    inflated.mean_quality = precise_quality(shortcut_quality);
    let mut broad = results.profile_summaries[1].clone();
    broad.mean_cost_usd = 1.0;
    broad.aggregate_usage = inflated.aggregate_usage;
    broad.mean_wall_time_ms = inflated.mean_wall_time_ms;
    broad.mean_loc_added = PreciseMean { total: 1, count: 1 };
    broad.mean_quality = precise_quality(broad_quality);

    assert!(dominates(&broad, &inflated));
    assert!(!dominates(&inflated, &broad));
}

fn experiment_manifest() -> ExperimentManifest {
    ExperimentManifest {
        version: EXPERIMENT_MANIFEST_SCHEMA_VERSION,
        experiment_id: "issue-26-fake-supervise".to_string(),
        goal: "Record the same isolated Fake supervise goal under two profiles.".to_string(),
        spec: "Keep production_eligible false and compare machine-readable summaries.".to_string(),
        limits: EvaluationLimits {
            wall_time_seconds: 120,
            max_dispatches: 4,
        },
        held_out_validation: vec![HeldOutValidation {
            id: "held-out-unit".to_string(),
            command: vec!["true".to_string()],
        }],
        repetitions: 1,
        profiles: vec![
            profile("hybrid-mix", "planner-fast", "worker-fast"),
            profile("all-frontier", "planner-frontier", "worker-frontier"),
        ],
        objective_profile: Some(
            crate::objective_profile::default_resolved_objective_profile()
                .expect("resolved default objective"),
        ),
    }
}

#[test]
fn two_profiles_produce_comparable_machine_readable_summary() {
    let manifest = experiment_manifest();
    let results = run_fake_supervise_experiment(&manifest, ExperimentRunRequest::default())
        .expect("isolated Fake supervise experiment");

    results
        .validate_against(&manifest)
        .expect("experiment results validate");
    assert_eq!(results.schema, EXPERIMENT_RESULT_SCHEMA);
    assert_eq!(results.runs.len(), 2);
    assert_eq!(results.profile_summaries.len(), 2);
    assert!(!results.evidence.production_eligible);
    assert!(!results.evidence.real_provider_executed);
    assert!(results.evidence.isolated_fake_supervise_state);
    assert!(
        !results
            .dispatch_comparability_claim
            .provider_execution_difference_established
    );

    let left = &results.profile_summaries[0];
    let right = &results.profile_summaries[1];
    assert_ne!(left.profile_id, right.profile_id);
    assert_eq!(left.repetitions, right.repetitions);
    assert_eq!(left.mean_assignment_count, right.mean_assignment_count);
    assert_eq!(
        left.mean_quality.held_out_basis_points.count,
        right.mean_quality.held_out_basis_points.count
    );
    assert!(results.runs.iter().all(|run| {
        !run.production_eligible
            && run.assignment_count > 0
            && run.held_out_validation.len() == manifest.held_out_validation.len()
            && run.quality.overall_basis_points <= BASIS_POINTS
    }));
    assert_ne!(
        results.runs[0].isolated_run_id,
        results.runs[1].isolated_run_id
    );
    assert!(
        results.pareto_conclusion.status == ParetoConclusionStatus::Available
            || results.pareto_conclusion.status
                == ParetoConclusionStatus::RefusedNoDispatchDifference
    );

    let output = serde_json::to_value(&results).expect("serialize experiment results");
    assert_eq!(output["objective_scoring"]["kind"], "original");
    assert_eq!(
        output["objective_scoring"]["applied_profile"]["profile"]["id"],
        crate::objective_profile::DEFAULT_OBJECTIVE_PROFILE_ID
    );
    assert!(
        output.get("objective_selection").is_some(),
        "experiment output must explicitly record the post-frontier profile policy result"
    );
}

#[test]
fn legacy_experiment_v1_without_objective_fields_remains_valid_for_default_manifest() {
    let mut manifest = experiment_manifest();
    manifest.objective_profile = None;
    let current = run_fake_supervise_experiment(&manifest, ExperimentRunRequest::default())
        .expect("current isolated Fake experiment");
    let mut old_wire = serde_json::to_value(current).expect("serialize current experiment");
    old_wire["version"] = json!(LEGACY_EXPERIMENT_RESULTS_SCHEMA_VERSION);
    old_wire["schema"] = json!(LEGACY_EXPERIMENT_RESULT_SCHEMA);
    let old_wire = old_wire.as_object_mut().expect("experiment result object");
    old_wire.remove("objective_scoring");
    old_wire.remove("objective_selection");
    for point in old_wire["pareto_frontier"]
        .as_array_mut()
        .expect("experiment Pareto frontier array")
    {
        let point = point
            .as_object_mut()
            .expect("experiment Pareto frontier point object");
        point.remove("mean_quota_consumption_tokens");
        point.remove("mean_wall_time_ms");
    }
    let legacy =
        serde_json::from_value::<ExperimentResults>(serde_json::Value::Object(old_wire.clone()))
            .expect("deserialize genuine v1 experiment shape");

    assert_eq!(legacy.objective_scoring, None);
    assert_eq!(legacy.objective_selection, None);
    legacy
        .validate_against(&manifest)
        .expect("legacy v1 result remains valid only at the historical default-objective boundary");
}

#[test]
fn fake_supervise_experiment_refuses_real_provider() {
    let manifest = experiment_manifest();
    assert_eq!(
        run_fake_supervise_experiment(
            &manifest,
            ExperimentRunRequest {
                execution: EvaluationExecution::RealProvider,
                allow_real_provider: false,
            },
        ),
        Err(EvaluationError::RealProviderOptInRequired)
    );
    assert_eq!(
        run_fake_supervise_experiment(
            &manifest,
            ExperimentRunRequest {
                execution: EvaluationExecution::RealProvider,
                allow_real_provider: true,
            },
        ),
        Err(EvaluationError::RealProviderUnavailableInPhaseA)
    );
}
