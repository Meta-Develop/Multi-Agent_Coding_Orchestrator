use super::*;
use crate::{
    llm::FakeProvider,
    planning::{ProviderPlanningConfig, ProviderRecursiveTaskPlan, ProviderTaskAssignmentTree},
    supervise::plan_api::normalize_task_execution_feedback_from_supervisor_final_report_for_test as normalize_task_execution_feedback_from_supervisor_final_report,
};

#[test]
fn authored_serial_plan_reports_independent_scope_width_warning() {
    let mut assignment = injected_assignment(false);
    assignment.assigned_paths = vec![PathBuf::from("README.md"), PathBuf::from("src/planning.rs")];
    let plan = injected_plan(assignment, 0);

    let warning =
        supervisor_plan_fan_out_width_warning(&plan).expect("serial fan-out width warning");

    assert_eq!(warning.code, "planning_width_pinned_to_one");
    assert_eq!(warning.independent_scope_count, 2);
    assert!(warning.message.contains("serializes work that can fan out"));
    println!(
        "width_warning_demo {}",
        serde_json::to_string(&warning).expect("serialize warning")
    );
    validate_legacy_supervisor_plan(plan).expect("warning does not invalidate authored plan");
}

#[test]
fn old_and_new_supervisor_model_economics_schema_round_trip() {
    let old_json = serde_json::from_slice::<Value>(&bounded_loader_plan_json())
        .expect("parse old plan fixture");
    let old = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&old_json).expect("serialize old plan"),
    )
    .expect("old plan remains valid");
    assert!(old.plan.role_models.is_empty());
    assert!(old.plan.model_pricing.is_empty());
    let old_round_trip = supervisor_plan_value(
        &old.plan,
        &old.consultant,
        &old.assignment_metadata,
        &old.plan_metadata,
    )
    .expect("serialize old plan");
    assert!(old_round_trip.get("role_models").is_none());
    assert!(old_round_trip.get("model_pricing").is_none());

    let mut new_json = old_json;
    let object = new_json.as_object_mut().expect("plan object");
    object.insert(
        "role_models".to_string(),
        json!({
            "supervisor": {
                "model": "supervisor-model",
                "reasoning_effort": "xhigh"
            },
            "child_orchestrator": {
                "model": " planner-model ",
                "reasoning_effort": " high "
            },
            "worker": {
                "model": "worker-model",
                "reasoning_effort": "low"
            },
            "auditor": {
                "model": "auditor-model",
                "reasoning_effort": "xhigh"
            }
        }),
    );
    object.insert(
        "model_pricing".to_string(),
        json!({
            "planner-model": {
                "input_usd_per_million_tokens": 2.5,
                "output_usd_per_million_tokens": 10.0
            },
            "worker-model": {
                "input_usd_per_million_tokens": 0.25,
                "output_usd_per_million_tokens": 1.0
            }
        }),
    );
    let new = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&new_json).expect("serialize new plan"),
    )
    .expect("new model economics plan");
    assert_eq!(
        new.plan.role_models[&AgentRole::Supervisor]
            .model
            .as_deref(),
        Some("supervisor-model")
    );
    assert_eq!(
        new.plan.role_models[&AgentRole::Supervisor]
            .reasoning_effort
            .as_deref(),
        Some("xhigh")
    );
    assert_eq!(new.plan.role_models.len(), 4);
    assert_eq!(
        new.plan.role_models[&AgentRole::ChildOrchestrator]
            .model
            .as_deref(),
        Some("planner-model")
    );
    assert_eq!(
        new.plan.role_models[&AgentRole::ChildOrchestrator]
            .reasoning_effort
            .as_deref(),
        Some("high")
    );
    let normalized = supervisor_plan_value(
        &new.plan,
        &new.consultant,
        &new.assignment_metadata,
        &new.plan_metadata,
    )
    .expect("serialize new plan");
    let reparsed = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized).expect("serialize normalized new plan"),
    )
    .expect("reparse normalized new plan");
    assert_eq!(reparsed, new);

    let mut empty_model = new.plan.clone();
    empty_model
        .role_models
        .get_mut(&AgentRole::Worker)
        .expect("worker selection")
        .model = Some("  ".to_string());
    assert!(validate_legacy_supervisor_plan(empty_model)
        .expect_err("empty present model must fail")
        .to_string()
        .contains("role_models.worker.model cannot be empty"));

    let mut invalid_pricing = new.plan;
    invalid_pricing.model_pricing.insert(
        "bad-model".to_string(),
        ModelPricing {
            input_usd_per_million_tokens: f64::INFINITY,
            output_usd_per_million_tokens: 1.0,
        },
    );
    assert!(validate_legacy_supervisor_plan(invalid_pricing)
        .expect_err("non-finite pricing must fail")
        .to_string()
        .contains("finite, non-negative"));
}

#[test]
fn assignment_reasoning_effort_round_trips_and_rejects_unknown_values() {
    let mut document = serde_json::from_slice::<Value>(&bounded_loader_plan_json())
        .expect("parse supervisor plan fixture");
    document["assignments"][0]["reasoning_effort"] = json!("low");
    let loaded = parse_supervisor_plan_with_consultant(&document.to_string())
        .expect("typed assignment effort");
    let assignment_id = loaded.plan.assignments[0].id.clone();
    assert_eq!(
        loaded.assignment_metadata.reasoning_effort(&assignment_id),
        Some(ReasoningEffort::Low)
    );
    let normalized = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
    .expect("serialize assignment effort");
    assert_eq!(normalized["assignments"][0]["reasoning_effort"], "low");
    let reparsed = parse_supervisor_plan_with_consultant(&normalized.to_string())
        .expect("reparse assignment effort");
    assert_eq!(reparsed, loaded);

    document["assignments"][0]["reasoning_effort"] = json!("turbo");
    let error = parse_supervisor_plan_with_consultant(&document.to_string())
        .expect_err("unknown assignment effort must be typed-rejected");
    assert!(
        format!("{error:#}").contains("reasoning_effort is invalid"),
        "unexpected rejection: {error:#}"
    );
}

#[test]
fn supervisor_plan_loads_executable_stacked_review_lens_configuration() {
    let mut value =
        serde_json::from_slice::<Value>(&bounded_loader_plan_json()).expect("parse base plan");
    let object = value.as_object_mut().expect("plan object");
    object.insert(
        "review_lenses".to_string(),
        json!([
            {
                "id": "diff-security",
                "backend": {
                    "kind": "model",
                    "backend_id": "provider-alpha",
                    "model": "model-alpha",
                    "reasoning_effort": "high"
                },
                "information_scope": "diff_only"
            },
            {
                "id": "report-consistency",
                "backend": {
                    "kind": "model",
                    "backend_id": "provider-beta",
                    "model": "model-beta",
                    "reasoning_effort": "xhigh"
                },
                "information_scope": "output_report_only"
            }
        ]),
    );
    object.insert(
        "review_aggregation_policy".to_string(),
        json!({"kind": "validated_quorum", "minimum_accepts": 2}),
    );
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&value).expect("serialize stacked plan"),
    )
    .expect("load stacked review lens plan");
    assert_eq!(loaded.plan.review_lenses.len(), 2);
    assert_eq!(
        loaded.plan.review_lenses[0].backend.backend_id(),
        "provider-alpha"
    );
    assert_eq!(loaded.plan.review_lenses[0].backend.model(), "model-alpha");
    assert_eq!(
        loaded.plan.review_lenses[0].backend.reasoning_effort(),
        Some("high")
    );
    assert_eq!(
        loaded.plan.review_lenses[1].information_scope,
        ReviewInformationScope::OutputReportOnly
    );
    assert_eq!(
        loaded.plan.review_aggregation_policy,
        ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts: 2 }
    );
}

#[test]
fn recursive_supervisor_plan_flattens_and_preserves_schedule_on_round_trip() {
    let source = json!({
        "version": 1,
        "task": "recursive plan",
        "max_depth": 3,
        "max_child_assignments": 2,
        "spec_fragment_ids": ["SPEC-root", "SPEC-child", "SPEC-gap"],
        "assignments": [{
            "id": "root-child",
            "assigned_paths": ["src/root.rs"],
            "spec_fragment_ids": ["SPEC-root"],
            "worker_assignments": [],
            "child_assignments": [{
                "id": "nested-child",
                "assigned_paths": ["src/nested.rs"],
                "spec_fragment_ids": ["SPEC-child"],
                "worker_assignments": []
            }]
        }]
    });
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&source).expect("serialize recursive source"),
    )
    .expect("parse recursive plan");
    assert_eq!(
        loaded
            .plan
            .assignments
            .iter()
            .map(|assignment| assignment.id.as_str())
            .collect::<Vec<_>>(),
        vec!["root-child", "nested-child"]
    );
    assert_eq!(
        loaded.plan_metadata.assignment_schedule,
        vec![
            AssignmentScheduleEntry {
                assignment_id: "root-child".to_string(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: "nested-child".to_string(),
                parent_assignment_id: Some("root-child".to_string()),
                depth: 3,
                flattened_index: 1,
            },
        ]
    );
    assert_eq!(
        loaded.plan_metadata.coverage_gaps,
        vec![SupervisorCoverageGap {
            kind: CoverageGapKind::UnassignedSpecFragment,
            spec_fragment_id: Some("SPEC-gap".to_string()),
            assignment_id: None,
            message: "spec fragment 'SPEC-gap' is not mapped to an assignment".to_string(),
        }]
    );

    let normalized = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
    .expect("normalize recursive plan");
    assert_eq!(
        normalized["assignments"]
            .as_array()
            .expect("normalized assignments")
            .len(),
        2
    );
    assert!(normalized["assignments"][0]
        .get("child_assignments")
        .is_none());
    let reparsed = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized).expect("serialize normalized plan"),
    )
    .expect("reparse normalized recursive plan");
    assert_eq!(reparsed, loaded);
}

#[test]
fn goal_spec_planning_emits_nested_workstream_hierarchies_with_workers_and_gaps() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    Repository::init(repo).expect("initialize repository");
    fs::create_dir_all(repo.join("src")).expect("create src");
    fs::write(repo.join("src/alpha.rs"), "pub struct AlphaHandler;\n").expect("write alpha");
    fs::write(repo.join("src/beta.rs"), "pub struct BetaHandler;\n").expect("write beta");

    let document = supervisor_plan_document_from_goal_spec(
        repo,
        "Implement the requested changes.",
        "- Update AlphaHandler.\n- Update BetaHandler.\n- Explain the unmatched frobnicator.",
    )
    .expect("plan goal/spec");
    let assignments = document["assignments"]
        .as_array()
        .expect("assignments array");
    assert_eq!(document["max_depth"], 3);
    assert_eq!(document["max_child_assignments"], 4);
    assert_eq!(assignments.len(), 4);
    assert_eq!(assignments[0]["id"], "assignment-001-planning");
    assert_eq!(assignments[0]["assigned_paths"], json!(["src/alpha.rs"]));
    assert_eq!(
        assignments[0]["semantic_symbols"],
        json!(["crate::alpha::AlphaHandler"])
    );
    assert!(assignments[0]["worker_assignments"]
        .as_array()
        .expect("planning workers")
        .is_empty());
    assert!(assignments[0].get("spec_fragment_ids").is_none());
    assert!(assignments[0]["task"]
        .as_str()
        .expect("planning task")
        .contains("Read-only planning gate"));
    assert_eq!(assignments[1]["id"], "assignment-001");
    assert_eq!(assignments[1]["assigned_paths"], json!(["src/alpha.rs"]));
    assert_eq!(assignments[1]["spec_fragment_ids"], json!(["fragment-002"]));
    assert_eq!(
        assignments[1]["worker_assignments"][0]["id"],
        "assignment-001-worker"
    );
    assert_eq!(
        assignments[1]["worker_assignments"][0]["task"],
        "Update AlphaHandler."
    );
    assert_eq!(assignments[2]["id"], "assignment-002-planning");
    assert_eq!(assignments[2]["assigned_paths"], json!(["src/beta.rs"]));
    assert!(assignments[2]["worker_assignments"]
        .as_array()
        .expect("planning workers")
        .is_empty());
    assert_eq!(assignments[3]["id"], "assignment-002");
    assert_eq!(assignments[3]["assigned_paths"], json!(["src/beta.rs"]));
    assert_eq!(assignments[3]["spec_fragment_ids"], json!(["fragment-003"]));
    assert_eq!(
        document["assignment_schedule"],
        json!([
            {
                "assignment_id": "assignment-001-planning",
                "depth": 2,
                "flattened_index": 0
            },
            {
                "assignment_id": "assignment-001",
                "parent_assignment_id": "assignment-001-planning",
                "depth": 3,
                "flattened_index": 1
            },
            {
                "assignment_id": "assignment-002-planning",
                "depth": 2,
                "flattened_index": 2
            },
            {
                "assignment_id": "assignment-002",
                "parent_assignment_id": "assignment-002-planning",
                "depth": 3,
                "flattened_index": 3
            }
        ])
    );
    assert_eq!(
        document["coverage_gaps"]
            .as_array()
            .expect("coverage gaps")
            .iter()
            .map(|gap| gap["spec_fragment_id"].as_str().expect("fragment id"))
            .collect::<Vec<_>>(),
        vec!["fragment-001", "fragment-004"]
    );

    let repeated = supervisor_plan_document_from_goal_spec(
        repo,
        "Implement the requested changes.",
        "- Update AlphaHandler.\n- Update BetaHandler.\n- Explain the unmatched frobnicator.",
    )
    .expect("repeat goal/spec planning");
    assert_eq!(repeated, document);

    let reparsed = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&document).expect("serialize generated plan"),
    )
    .expect("reparse generated plan");
    let renormalized = supervisor_plan_value(
        &reparsed.plan,
        &reparsed.consultant,
        &reparsed.assignment_metadata,
        &reparsed.plan_metadata,
    )
    .expect("renormalize generated plan");
    assert_eq!(renormalized, document);
}

fn provider_planning_node(
    id: &str,
    task: &str,
    fragment_ids: &[&str],
    path: &str,
    child_assignments: Vec<ProviderTaskAssignmentTree>,
) -> ProviderTaskAssignmentTree {
    let module = Path::new(path)
        .file_stem()
        .and_then(OsStr::to_str)
        .expect("provider test path has a UTF-8 file stem");
    let is_leaf = child_assignments.is_empty();
    let assigned_paths = if is_leaf {
        vec![PathBuf::from(path)]
    } else {
        child_assignments
            .iter()
            .flat_map(|child| child.assigned_paths.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let semantic_symbols = if is_leaf {
        vec![format!("crate::{module}::{module}")]
    } else {
        child_assignments
            .iter()
            .flat_map(|child| child.semantic_symbols.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let semantic_modules = if is_leaf {
        vec![format!("crate::{module}")]
    } else {
        child_assignments
            .iter()
            .flat_map(|child| child.semantic_modules.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    ProviderTaskAssignmentTree {
        id: id.to_string(),
        task: task.to_string(),
        fragment_ids: fragment_ids
            .iter()
            .map(|fragment_id| (*fragment_id).to_string())
            .collect(),
        assigned_paths,
        semantic_symbols,
        semantic_modules,
        child_assignments,
    }
}

fn provider_traceability(
    assignment_id: &str,
    parent_assignment_id: Option<&str>,
    depth: u8,
    flattened_index: usize,
    fragment_ids: &[&str],
    path: &str,
    report_status: Option<ReviewStatus>,
) -> AssignmentTraceability {
    AssignmentTraceability {
        assignment_id: assignment_id.to_string(),
        parent_assignment_id: parent_assignment_id.map(str::to_string),
        depth,
        flattened_index,
        spec_fragment_ids: fragment_ids
            .iter()
            .map(|fragment_id| (*fragment_id).to_string())
            .collect(),
        assigned_paths: vec![PathBuf::from(path)],
        produced_changed_paths: Vec::new(),
        produced_diff_binding: None,
        report_status,
    }
}

fn persist_provider_supervisor_artifact(
    repo: &Path,
    artifact_run_id: &RunId,
    document: &Value,
    report: &SupervisorFinalReport,
    finalize: bool,
) {
    persist_provider_supervisor_artifact_with_pre_dispatch_document(
        repo,
        artifact_run_id,
        document,
        document,
        report,
        finalize,
    );
}

fn persist_provider_supervisor_artifact_with_pre_dispatch_document(
    repo: &Path,
    artifact_run_id: &RunId,
    document: &Value,
    pre_dispatch_document: &Value,
    report: &SupervisorFinalReport,
    finalize: bool,
) {
    persist_provider_supervisor_artifact_with_faults(
        repo,
        artifact_run_id,
        document,
        pre_dispatch_document,
        report,
        finalize,
        ProviderSupervisorArtifactFaults::default(),
    );
}

#[derive(Default)]
struct ProviderSupervisorArtifactFaults<'a> {
    finalized_report_replacement: Option<&'a SupervisorFinalReport>,
    auditor_dispatch_before_plan: bool,
}

#[allow(clippy::too_many_arguments)]
fn persist_provider_supervisor_artifact_with_faults(
    repo: &Path,
    artifact_run_id: &RunId,
    document: &Value,
    pre_dispatch_document: &Value,
    report: &SupervisorFinalReport,
    finalize: bool,
    faults: ProviderSupervisorArtifactFaults<'_>,
) {
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(document).expect("serialize provider supervisor plan"),
    )
    .expect("parse provider supervisor plan for authenticated timeline");
    let normalized_plan_sha256 = normalized_supervisor_plan_sha256(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
    .expect("digest provider supervisor plan");
    let ledger = RunBudgetLedger::new(RunBudgetLimits::default())
        .expect("provider supervisor timeline budget ledger");
    let mut authenticated_report = report.clone();
    if authenticated_report.run_budget.is_none() {
        authenticated_report.run_budget = Some(
            ledger
                .report()
                .expect("provider supervisor authenticated report budget"),
        );
    }
    let report = &authenticated_report;
    let mut writer = ArtifactRunWriter::reserve(
        repo,
        RunArtifactFamily::Supervise,
        artifact_run_id.clone(),
        "provider-planning-feedback-test",
    )
    .expect("reserve provider supervisor artifact");
    let mut checkpoint = SupervisorCheckpointWriter::create(
        repo,
        SupervisorCheckpointPreparation::new(
            artifact_run_id,
            &Oid::ZERO_SHA1,
            normalized_plan_sha256,
            1,
            &loaded.plan,
            writer
                .resume_binding()
                .expect("bind empty provider supervisor artifact"),
            ledger.report().expect("initial provider supervisor budget"),
        ),
    )
    .expect("create authenticated provider supervisor checkpoint");
    if faults.auditor_dispatch_before_plan {
        checkpoint
            .dispatch_started(true, "provider-pre-plan-auditor", 1)
            .expect("record pre-plan auditor dispatch start");
        checkpoint
            .dispatch_completed(true, "provider-pre-plan-auditor", 1)
            .expect("record pre-plan auditor dispatch completion");
    }
    writer
        .write_json(
            "assignments/supervisor-plan.json",
            pre_dispatch_document,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write bound provider supervisor plan");
    for (index, assignment) in loaded.plan.assignments.iter().enumerate() {
        checkpoint
            .assignment_started(
                assignment,
                index,
                Some(
                    writer
                        .resume_binding()
                        .expect("bind pre-dispatch provider supervisor evidence"),
                ),
                ledger.report().expect("provider supervisor start budget"),
            )
            .expect("record provider supervisor assignment start");
        checkpoint
            .dispatch_started(false, &assignment.id, 1)
            .expect("record provider supervisor child dispatch start");
        checkpoint
            .dispatch_completed(false, &assignment.id, 1)
            .expect("record provider supervisor child dispatch completion");
        checkpoint
            .assignment_completed(
                assignment,
                index,
                Some(
                    writer
                        .resume_binding()
                        .expect("bind completed provider supervisor evidence"),
                ),
                ledger
                    .report()
                    .expect("provider supervisor completion budget"),
                None,
                Vec::new(),
            )
            .expect("record provider supervisor assignment completion");
    }
    if pre_dispatch_document != document {
        writer
            .write_json(
                "assignments/supervisor-plan.json",
                document,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("replace late provider supervisor plan");
    }
    checkpoint
        .scheduler_closed(
            writer
                .resume_binding()
                .expect("bind closed provider supervisor scheduler"),
            ledger.report().expect("provider supervisor closed budget"),
        )
        .expect("close provider supervisor scheduler checkpoint");
    let report_bytes = encode_final_report(report).expect("encode provider supervisor report");
    checkpoint
        .final_report_planned(
            report,
            &report_bytes,
            writer
                .resume_binding()
                .expect("bind planned provider supervisor report"),
        )
        .expect("plan provider supervisor final report");
    writer
        .write_bytes(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &report_bytes,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write provider supervisor final report");
    checkpoint
        .final_report_committed(
            report,
            &report_bytes,
            writer
                .resume_binding()
                .expect("bind committed provider supervisor report"),
        )
        .expect("commit provider supervisor final report checkpoint");
    if let Some(replacement) = faults.finalized_report_replacement {
        let mut replacement = replacement.clone();
        if replacement.run_budget.is_none() {
            replacement.run_budget = report.run_budget.clone();
        }
        writer
            .write_bytes(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                &encode_final_report(&replacement)
                    .expect("encode replaced provider supervisor report"),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("replace provider supervisor report after checkpoint commit");
    }
    checkpoint
        .finalization_started(report, &report_bytes)
        .expect("start provider supervisor artifact finalization");
    if finalize {
        writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize provider supervisor artifact");
        checkpoint
            .finalized(report, &report_bytes)
            .expect("finalize provider supervisor checkpoint");
    }
}

#[test]
fn provider_feedback_requires_exact_authenticated_pre_dispatch_planning_binding() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    Repository::init(repo).expect("initialize repository");
    let config = ProviderPlanningConfig::new("binding", "fake-model")
        .with_max_child_assignments(1)
        .with_max_depth(1);
    let session = planning::validated_provider_session_for_test(
        planning::ValidatedProviderSessionTestInput {
            fragments: vec![planning::TaskSpecFragment {
                id: "fragment-001".to_string(),
                text: "Implement alpha.".to_string(),
            }],
            provider_plan: ProviderRecursiveTaskPlan {
                assignments: vec![provider_planning_node(
                    "provider-alpha",
                    "Implement alpha.",
                    &["fragment-001"],
                    "src/alpha.rs",
                    Vec::new(),
                )],
            },
            repository_paths: vec![PathBuf::from("src/alpha.rs")],
            semantic_modules: ["crate::alpha".to_string()].into_iter().collect(),
            semantic_symbols: ["crate::alpha::alpha".to_string()].into_iter().collect(),
            provider_id: "fake-planner",
            model: "fake-model",
            config: &config,
        },
    )
    .expect("deterministically validated provider session");
    let run_id = RunId::new("provider-binding-timeline").expect("valid run id");
    let bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        "Implement alpha in src/alpha.rs.",
        &session,
        run_id.clone(),
    )
    .expect("bind provider supervisor plan");
    let mut report = artifact_test_final_report(&run_id);
    report.assigned_paths = vec![PathBuf::from("src/alpha.rs")];
    report.semantic_symbols = vec!["crate::alpha::alpha".to_string()];
    report.semantic_modules = vec!["crate::alpha".to_string()];
    report.assignment_traceability = vec![provider_traceability(
        "provider-alpha",
        None,
        2,
        0,
        &["fragment-001"],
        "src/alpha.rs",
        Some(ReviewStatus::Succeeded),
    )];
    persist_provider_supervisor_artifact(repo, &run_id, &bound.document, &report, true);
    let feedback = task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        "Implement alpha in src/alpha.rs.",
        &session,
        &bound.execution_binding,
    )
    .expect("read exact authenticated pre-dispatch planning binding");
    assert_eq!(feedback.completed_assignment_ids, vec!["provider-alpha"]);

    let collision_session = session
        .reissue_provider_authority_for_test("fake-planner", "fake-model")
        .expect("reissue otherwise identical planning session");
    let collision = bind_provider_task_planning_session_to_supervisor_run(
        "",
        "Implement alpha in src/alpha.rs.",
        &collision_session,
        run_id.clone(),
    )
    .expect("bind colliding session");
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        "Implement alpha in src/alpha.rs.",
        &collision_session,
        &collision.execution_binding,
    )
    .expect_err("same-run session collision must fail")
    .to_string()
    .contains("wrong provider/session/model/plan"));

    let late_run_id = RunId::new("provider-binding-late").expect("valid late run id");
    let late = bind_provider_task_planning_session_to_supervisor_run(
        "",
        "Implement alpha in src/alpha.rs.",
        &session,
        late_run_id.clone(),
    )
    .expect("bind late provider plan");
    let mut unbound = late.document.clone();
    unbound["assignments"][0]
        .as_object_mut()
        .expect("first assignment object")
        .remove("notes");
    let mut late_report = report.clone();
    late_report.run_id = late_run_id.clone();
    persist_provider_supervisor_artifact_with_pre_dispatch_document(
        repo,
        &late_run_id,
        &late.document,
        &unbound,
        &late_report,
        true,
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        "Implement alpha in src/alpha.rs.",
        &session,
        &late.execution_binding,
    )
    .expect_err("late binding replacement must fail")
    .to_string()
    .contains("missing or replaced after the pre-dispatch artifact boundary"));

    let replaced_report_run_id =
        RunId::new("provider-binding-report-replaced").expect("valid replaced-report run id");
    let replaced_report_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        "Implement alpha in src/alpha.rs.",
        &session,
        replaced_report_run_id.clone(),
    )
    .expect("bind replaced-report provider plan");
    let mut committed_report = report.clone();
    committed_report.run_id = replaced_report_run_id.clone();
    let mut replaced_report = committed_report.clone();
    replaced_report.status = ReviewStatus::Failed;
    replaced_report.success = false;
    persist_provider_supervisor_artifact_with_faults(
        repo,
        &replaced_report_run_id,
        &replaced_report_bound.document,
        &replaced_report_bound.document,
        &committed_report,
        true,
        ProviderSupervisorArtifactFaults {
            finalized_report_replacement: Some(&replaced_report),
            auditor_dispatch_before_plan: false,
        },
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        "Implement alpha in src/alpha.rs.",
        &session,
        &replaced_report_bound.execution_binding,
    )
    .expect_err("report replaced after checkpoint commit must fail")
    .to_string()
    .contains("differs from its checkpoint-committed bytes"));

    let auditor_first_run_id =
        RunId::new("provider-binding-auditor-before-plan").expect("valid auditor-first run id");
    let auditor_first_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        "Implement alpha in src/alpha.rs.",
        &session,
        auditor_first_run_id.clone(),
    )
    .expect("bind auditor-first provider plan");
    let mut auditor_first_report = report.clone();
    auditor_first_report.run_id = auditor_first_run_id.clone();
    persist_provider_supervisor_artifact_with_faults(
        repo,
        &auditor_first_run_id,
        &auditor_first_bound.document,
        &auditor_first_bound.document,
        &auditor_first_report,
        true,
        ProviderSupervisorArtifactFaults {
            finalized_report_replacement: None,
            auditor_dispatch_before_plan: true,
        },
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        "Implement alpha in src/alpha.rs.",
        &session,
        &auditor_first_bound.execution_binding,
    )
    .expect_err("auditor dispatch before plan boundary must fail")
    .to_string()
    .contains("auditor dispatch preceded every assignment plan artifact boundary"));

    for (suffix, source_phase, appended_phase, expected) in [
        (
            "duplicate-finalized",
            "artifact_finalized",
            "artifact_finalized",
            "finalization completion is out of order",
        ),
        (
            "late-assignment",
            "assignment_started",
            "assignment_started",
            "duplicate or late assignment start",
        ),
        (
            "conflicting-dispatch",
            "child_dispatch_started",
            "child_dispatch_started",
            "child dispatch started after assignment completion",
        ),
    ] {
        let journal_run_id =
            RunId::new(format!("provider-binding-{suffix}")).expect("valid journal run id");
        let journal_bound = bind_provider_task_planning_session_to_supervisor_run(
            "",
            "Implement alpha in src/alpha.rs.",
            &session,
            journal_run_id.clone(),
        )
        .expect("bind journal-fault provider plan");
        let mut journal_report = report.clone();
        journal_report.run_id = journal_run_id.clone();
        persist_provider_supervisor_artifact(
            repo,
            &journal_run_id,
            &journal_bound.document,
            &journal_report,
            true,
        );
        let authenticator = repository_authenticator_key_only(repo)
            .expect("open journal-fault repository authenticator");
        let mut journal = crate::state_journal::StateJournal::open_instance(
            authenticator,
            journal_run_id.as_str(),
        )
        .expect("open authenticated provider checkpoint journal");
        let source = journal
            .records()
            .iter()
            .find(|record| record.phase == source_phase)
            .expect("source checkpoint phase")
            .clone();
        journal
            .append(appended_phase, source.subject.as_deref(), &source.payload)
            .expect("append valid-MAC invalid-lifecycle checkpoint record");
        drop(journal);
        let error = task_execution_feedback_from_authenticated_supervisor_run(
            repo,
            "",
            "Implement alpha in src/alpha.rs.",
            &session,
            &journal_bound.execution_binding,
        )
        .expect_err("valid-MAC invalid-lifecycle journal tail must fail");
        let error = format!("{error:#}");
        assert!(
            error.contains(expected),
            "unexpected journal rejection: {error}"
        );
    }
}

#[test]
fn provider_recursive_plan_lowers_and_finalized_feedback_drives_remaining_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    Repository::init(repo).expect("initialize repository");
    fs::create_dir_all(repo.join("src")).expect("create src");
    fs::write(repo.join("src/root.rs"), "pub fn root() {}\n").expect("write root");
    fs::write(repo.join("src/alpha.rs"), "pub fn alpha() {}\n").expect("write alpha");
    fs::write(repo.join("src/beta.rs"), "pub fn beta() {}\n").expect("write beta");

    let initial = ProviderRecursiveTaskPlan {
        assignments: vec![provider_planning_node(
            "provider-root",
            "Coordinate the two disjoint implementation leaves.",
            &["fragment-001", "fragment-002"],
            "src/root.rs",
            vec![
                provider_planning_node(
                    "provider-alpha",
                    "Implement alpha.",
                    &["fragment-001"],
                    "src/alpha.rs",
                    Vec::new(),
                ),
                provider_planning_node(
                    "provider-beta",
                    "Implement beta.",
                    &["fragment-002"],
                    "src/beta.rs",
                    Vec::new(),
                ),
            ],
        )],
    };
    let revised = ProviderRecursiveTaskPlan {
        assignments: vec![provider_planning_node(
            "remaining-root",
            "Coordinate the revised remaining beta work.",
            &["fragment-002"],
            "src/root.rs",
            vec![provider_planning_node(
                "provider-beta-revised",
                "Revise beta using execution feedback.",
                &["fragment-002"],
                "src/beta.rs",
                Vec::new(),
            )],
        )],
    };
    let mut provider = FakeProvider::new("fake-planner", "fake-model");
    provider
        .push_json_response("plan-runtime-proposal", &initial)
        .expect("serialize initial provider plan");
    provider
        .push_response(
            "plan-runtime-replan-01",
            crate::llm::WorkProposal::summary("malformed recursive replan"),
        )
        .push_json_response("plan-runtime-replan-02", &revised)
        .expect("serialize revised provider plan");
    let config = ProviderPlanningConfig::new("plan-runtime", "fake-model")
        .with_max_child_assignments(3)
        .with_max_depth(2);
    let spec = "- Implement alpha in src/alpha.rs.\n- Implement beta in src/beta.rs.";
    let mut session =
        planning::propose_task_decomposition_with_provider(repo, "", spec, &mut provider, &config)
            .expect("validated recursive provider plan");
    let heuristic_session =
        planning::propose_task_decomposition_with_optional_provider(repo, "", spec, None, &config)
            .expect("heuristic planning session");
    assert!(bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &heuristic_session,
        RunId::new("heuristic-binding-refusal").expect("valid refusal run id"),
    )
    .expect_err("heuristic session must not receive provider execution binding")
    .to_string()
    .contains("requires a provider planning session"));

    let run_id = RunId::new("provider-planning-feedback").expect("valid run id");
    let bound =
        bind_provider_task_planning_session_to_supervisor_run("", spec, &session, run_id.clone())
            .expect("lower and bind initial provider tree");
    assert_eq!(bound.execution_binding.run_id(), &run_id);
    assert_eq!(bound.plan.max_depth, 3);
    assert_eq!(bound.plan.max_child_assignments, 3);
    assert_eq!(bound.plan.assignments.len(), 3);
    let initial_document = bound.document.clone();
    assert_eq!(initial_document["max_depth"], 3);
    assert_eq!(initial_document["max_child_assignments"], 3);
    assert_eq!(
        initial_document["spec_fragment_ids"],
        json!(["fragment-001", "fragment-002"])
    );
    assert_eq!(
        initial_document["assignments"]
            .as_array()
            .expect("initial assignments")
            .iter()
            .map(|assignment| assignment["id"].as_str().expect("assignment id"))
            .collect::<Vec<_>>(),
        vec!["provider-root", "provider-alpha", "provider-beta"]
    );
    assert!(initial_document["assignments"][0]["worker_assignments"]
        .as_array()
        .expect("internal workers")
        .is_empty());
    assert!(initial_document["assignments"][0]
        .get("spec_fragment_ids")
        .is_none());
    assert_eq!(
        initial_document["assignments"][0]["semantic_symbols"],
        json!(["crate::alpha::alpha", "crate::beta::beta"])
    );
    assert_eq!(
        initial_document["assignments"][0]["semantic_modules"],
        json!(["crate::alpha", "crate::beta"])
    );
    for leaf_index in [1usize, 2] {
        let leaf = &initial_document["assignments"][leaf_index];
        assert_eq!(
            leaf["worker_assignments"]
                .as_array()
                .expect("leaf workers")
                .len(),
            1
        );
        assert_eq!(
            leaf["worker_assignments"][0]["assigned_paths"],
            leaf["assigned_paths"]
        );
        assert_eq!(leaf["worker_assignments"][0]["task"], leaf["task"]);
    }
    assert_eq!(
        initial_document["assignment_schedule"],
        json!([
            {
                "assignment_id": "provider-root",
                "depth": 2,
                "flattened_index": 0
            },
            {
                "assignment_id": "provider-alpha",
                "parent_assignment_id": "provider-root",
                "depth": 3,
                "flattened_index": 1
            },
            {
                "assignment_id": "provider-beta",
                "parent_assignment_id": "provider-root",
                "depth": 3,
                "flattened_index": 2
            }
        ])
    );
    let parsed_initial = parse_supervisor_plan_with_consultant(&initial_document.to_string())
        .expect("round-trip initial provider plan");
    let renormalized_initial = supervisor_plan_value(
        &parsed_initial.plan,
        &parsed_initial.consultant,
        &parsed_initial.assignment_metadata,
        &parsed_initial.plan_metadata,
    )
    .expect("renormalize initial provider plan");
    assert_eq!(renormalized_initial, initial_document);

    let mut report = artifact_test_final_report(&run_id);
    report.assigned_paths = vec![PathBuf::from("src/alpha.rs"), PathBuf::from("src/beta.rs")];
    report.semantic_symbols = vec![
        "crate::alpha::alpha".to_string(),
        "crate::beta::beta".to_string(),
    ];
    report.semantic_modules = vec!["crate::alpha".to_string(), "crate::beta".to_string()];
    report.assignment_traceability = vec![
        provider_traceability(
            "provider-root",
            None,
            2,
            0,
            &[],
            "src/root.rs",
            Some(ReviewStatus::Succeeded),
        ),
        provider_traceability(
            "provider-alpha",
            Some("provider-root"),
            3,
            1,
            &["fragment-001"],
            "src/alpha.rs",
            Some(ReviewStatus::Succeeded),
        ),
        provider_traceability(
            "provider-beta",
            Some("provider-root"),
            3,
            2,
            &["fragment-002"],
            "src/beta.rs",
            Some(ReviewStatus::Failed),
        ),
    ];
    report.assignment_traceability[0].assigned_paths =
        vec![PathBuf::from("src/alpha.rs"), PathBuf::from("src/beta.rs")];
    let beta_gap = SupervisorCoverageGap {
        kind: CoverageGapKind::NoProducedChanges,
        spec_fragment_id: Some("fragment-002".to_string()),
        assignment_id: Some("provider-beta".to_string()),
        message: "beta produced no accepted changes".to_string(),
    };
    report.coverage_gaps = vec![beta_gap.clone(), beta_gap.clone()];

    persist_provider_supervisor_artifact(repo, &run_id, &initial_document, &report, true);
    let feedback = task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &bound.execution_binding,
    )
    .expect("adapt authenticated finalized report feedback");
    assert_eq!(feedback.completed_assignment_ids, vec!["provider-alpha"]);
    assert_eq!(feedback.failed_assignment_ids, vec!["provider-beta"]);
    assert_eq!(feedback.coverage_gap_fragment_ids, vec!["fragment-002"]);
    assert!(feedback.notes.is_empty());

    let reissued_session = session
        .reissue_provider_authority_for_test("fake-planner", "fake-model")
        .expect("reissue otherwise identical provider session");
    let same_run_collision = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &reissued_session,
        run_id.clone(),
    )
    .expect("bind reissued session to colliding run id");
    assert_ne!(
        same_run_collision.execution_binding,
        bound.execution_binding
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &reissued_session,
        &same_run_collision.execution_binding,
    )
    .expect_err("same-run otherwise identical session collision must fail")
    .to_string()
    .contains("wrong provider/session/model/plan"));

    for (provider_id, model) in [
        ("different-provider", "fake-model"),
        ("fake-planner", "different-model"),
    ] {
        let replaced_authority = session
            .reissue_provider_authority_for_test(provider_id, model)
            .expect("reissue provider/model authority");
        let replaced = bind_provider_task_planning_session_to_supervisor_run(
            "",
            spec,
            &replaced_authority,
            run_id.clone(),
        )
        .expect("bind replaced provider/model authority");
        assert!(task_execution_feedback_from_authenticated_supervisor_run(
            repo,
            "",
            spec,
            &replaced_authority,
            &replaced.execution_binding,
        )
        .expect_err("wrong provider or model binding must fail")
        .to_string()
        .contains("wrong provider/session/model/plan"));
    }

    let missing_binding_run_id =
        RunId::new("provider-feedback-missing-binding").expect("valid missing-binding run id");
    let missing_binding_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        missing_binding_run_id.clone(),
    )
    .expect("bind missing-binding run");
    let mut missing_binding_document = missing_binding_bound.document.clone();
    missing_binding_document["assignments"][0]
        .as_object_mut()
        .expect("first assignment object")
        .remove("notes");
    let mut missing_binding_report = report.clone();
    missing_binding_report.run_id = missing_binding_run_id.clone();
    persist_provider_supervisor_artifact(
        repo,
        &missing_binding_run_id,
        &missing_binding_document,
        &missing_binding_report,
        true,
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &missing_binding_bound.execution_binding,
    )
    .expect_err("missing durable provider binding must fail")
    .to_string()
    .contains("exactly one provider execution binding"));

    let duplicate_binding_run_id =
        RunId::new("provider-feedback-duplicate-binding").expect("valid duplicate-binding run id");
    let duplicate_binding_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        duplicate_binding_run_id.clone(),
    )
    .expect("bind duplicate-binding run");
    let mut duplicate_binding_document = duplicate_binding_bound.document.clone();
    duplicate_binding_document["assignments"][1]["notes"] =
        duplicate_binding_document["assignments"][0]["notes"].clone();
    let mut duplicate_binding_report = report.clone();
    duplicate_binding_report.run_id = duplicate_binding_run_id.clone();
    persist_provider_supervisor_artifact(
        repo,
        &duplicate_binding_run_id,
        &duplicate_binding_document,
        &duplicate_binding_report,
        true,
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &duplicate_binding_bound.execution_binding,
    )
    .expect_err("duplicate durable provider binding must fail")
    .to_string()
    .contains("exactly one provider execution binding"));

    let late_binding_run_id =
        RunId::new("provider-feedback-late-binding").expect("valid late-binding run id");
    let late_binding_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        late_binding_run_id.clone(),
    )
    .expect("bind late-binding run");
    let mut pre_dispatch_unbound_document = late_binding_bound.document.clone();
    pre_dispatch_unbound_document["assignments"][0]
        .as_object_mut()
        .expect("first assignment object")
        .remove("notes");
    let mut late_binding_report = report.clone();
    late_binding_report.run_id = late_binding_run_id.clone();
    persist_provider_supervisor_artifact_with_pre_dispatch_document(
        repo,
        &late_binding_run_id,
        &late_binding_bound.document,
        &pre_dispatch_unbound_document,
        &late_binding_report,
        true,
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &late_binding_bound.execution_binding,
    )
    .expect_err("late provider binding replacement must fail")
    .to_string()
    .contains("missing or replaced after the pre-dispatch artifact boundary"));

    let provider_calls_before_bounded_feedback = provider.calls().len();
    let repeated_gap_run_id =
        RunId::new("provider-feedback-repeated-gaps").expect("valid repeated-gap run id");
    let repeated_gap_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        repeated_gap_run_id.clone(),
    )
    .expect("bind repeated-gap provider run");
    let mut repeated_gap_report = report.clone();
    repeated_gap_report.run_id = repeated_gap_run_id.clone();
    repeated_gap_report.coverage_gaps = vec![beta_gap.clone(); 129];
    persist_provider_supervisor_artifact(
        repo,
        &repeated_gap_run_id,
        &repeated_gap_bound.document,
        &repeated_gap_report,
        true,
    );
    assert!(
        replan_provider_task_planning_session_from_authenticated_supervisor_run(
            repo,
            "",
            spec,
            &mut session,
            &repeated_gap_bound.execution_binding,
            &mut provider,
            &config,
        )
        .expect_err("raw repeated coverage gaps must exceed the feedback item bound")
        .to_string()
        .contains("items but at most 128")
    );
    assert_eq!(session.replans_used(), 0);
    assert_eq!(
        provider.calls().len(),
        provider_calls_before_bounded_feedback
    );

    let padded_gap_run_id =
        RunId::new("provider-feedback-padded-gap").expect("valid padded-gap run id");
    let padded_gap_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        padded_gap_run_id.clone(),
    )
    .expect("bind padded-gap provider run");
    let mut padded_gap_report = report.clone();
    padded_gap_report.run_id = padded_gap_run_id.clone();
    padded_gap_report.coverage_gaps = vec![SupervisorCoverageGap {
        spec_fragment_id: Some(format!("{}fragment-002", " ".repeat(16 * 1024 + 1))),
        ..beta_gap.clone()
    }];
    persist_provider_supervisor_artifact(
        repo,
        &padded_gap_run_id,
        &padded_gap_bound.document,
        &padded_gap_report,
        true,
    );
    assert!(
        replan_provider_task_planning_session_from_authenticated_supervisor_run(
            repo,
            "",
            spec,
            &mut session,
            &padded_gap_bound.execution_binding,
            &mut provider,
            &config,
        )
        .expect_err("raw whitespace-padded coverage gap must exceed the byte bound")
        .to_string()
        .contains("item contains")
    );
    assert_eq!(session.replans_used(), 0);
    assert_eq!(
        provider.calls().len(),
        provider_calls_before_bounded_feedback
    );

    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "different goal",
        spec,
        &session,
        &bound.execution_binding,
    )
    .expect_err("changed goal must invalidate execution binding")
    .to_string()
    .contains("does not match the current session and normalized plan"));

    let missing_run_id = RunId::new("provider-feedback-missing").expect("valid missing run id");
    let missing_bound =
        bind_provider_task_planning_session_to_supervisor_run("", spec, &session, missing_run_id)
            .expect("bind missing provider run");
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &missing_bound.execution_binding,
    )
    .expect_err("missing artifact must fail")
    .to_string()
    .contains("not an authenticated finalized artifact"));

    let unfinalized_run_id =
        RunId::new("provider-feedback-unfinalized").expect("valid unfinalized run id");
    let unfinalized_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        unfinalized_run_id.clone(),
    )
    .expect("bind unfinalized provider run");
    let mut unfinalized_report = report.clone();
    unfinalized_report.run_id = unfinalized_run_id.clone();
    persist_provider_supervisor_artifact(
        repo,
        &unfinalized_run_id,
        &unfinalized_bound.document,
        &unfinalized_report,
        false,
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &unfinalized_bound.execution_binding,
    )
    .expect_err("unfinalized artifact must fail")
    .to_string()
    .contains("not an authenticated finalized artifact"));

    let nonterminal_report_run_id =
        RunId::new("provider-feedback-nonterminal-report").expect("valid nonterminal run id");
    let nonterminal_report_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        nonterminal_report_run_id.clone(),
    )
    .expect("bind nonterminal-report provider run");
    let mut nonterminal_report = report.clone();
    nonterminal_report.run_id = nonterminal_report_run_id.clone();
    nonterminal_report.run_lifecycle = SupervisorRunLifecycle::Active;
    persist_provider_supervisor_artifact(
        repo,
        &nonterminal_report_run_id,
        &nonterminal_report_bound.document,
        &nonterminal_report,
        true,
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &nonterminal_report_bound.execution_binding,
    )
    .expect_err("authenticated nonterminal report must fail")
    .to_string()
    .contains("requires a finalized report"));

    let mismatched_report_run_id =
        RunId::new("provider-feedback-report-id").expect("valid report-id run id");
    let mismatched_report_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        mismatched_report_run_id.clone(),
    )
    .expect("bind report-id provider run");
    let mut mismatched_report = report.clone();
    mismatched_report.run_id =
        RunId::new("different-provider-report-id").expect("valid different report id");
    persist_provider_supervisor_artifact(
        repo,
        &mismatched_report_run_id,
        &mismatched_report_bound.document,
        &mismatched_report,
        true,
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &mismatched_report_bound.execution_binding,
    )
    .expect_err("mismatched authenticated report run id must fail")
    .to_string()
    .contains("does not match bound run"));

    let mismatched_plan_run_id =
        RunId::new("provider-feedback-plan-id").expect("valid plan-id run id");
    let mismatched_plan_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        mismatched_plan_run_id.clone(),
    )
    .expect("bind plan-id provider run");
    let mut mismatched_document = mismatched_plan_bound.document.clone();
    mismatched_document["task"] = json!("stale normalized provider task");
    let mut mismatched_plan_report = report.clone();
    mismatched_plan_report.run_id = mismatched_plan_run_id.clone();
    persist_provider_supervisor_artifact(
        repo,
        &mismatched_plan_run_id,
        &mismatched_document,
        &mismatched_plan_report,
        true,
    );
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &mismatched_plan_bound.execution_binding,
    )
    .expect_err("mismatched authenticated normalized plan must fail")
    .to_string()
    .contains("normalized plan does not match"));

    let mut invalid = report.clone();
    invalid.assigned_paths.pop();
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("stale aggregate paths must fail")
            .to_string()
            .contains("aggregate path or semantic scope")
    );

    let mut invalid = report.clone();
    invalid.semantic_symbols[0] = "crate::invented::symbol".to_string();
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("stale aggregate symbols must fail")
            .to_string()
            .contains("aggregate path or semantic scope")
    );

    let mut invalid = report.clone();
    invalid.semantic_modules[0] = "crate::invented".to_string();
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("stale aggregate modules must fail")
            .to_string()
            .contains("aggregate path or semantic scope")
    );

    let mut invalid = report.clone();
    invalid.run_lifecycle = SupervisorRunLifecycle::Active;
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("nonfinalized report must fail")
            .to_string()
            .contains("finalized")
    );

    let mut invalid = report.clone();
    invalid.assignment_traceability.remove(0);
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("missing internal node trace must fail")
            .to_string()
            .contains("provider tree node 'provider-root'")
    );

    for internal_status in [
        Some(ReviewStatus::Pending),
        Some(ReviewStatus::Failed),
        Some(ReviewStatus::Rejected),
        Some(ReviewStatus::Missing),
        None,
    ] {
        let mut invalid = report.clone();
        invalid.assignment_traceability[0].report_status = internal_status;
        assert!(
            normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
                .expect_err("nonsuccess internal node must fail")
                .to_string()
                .contains("internal provider node 'provider-root' is not terminal succeeded")
        );
    }

    let mut invalid = report.clone();
    invalid.assignment_traceability[2].report_status = Some(ReviewStatus::Pending);
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("pending leaf must fail")
            .to_string()
            .contains("pending")
    );

    for failed_status in [
        Some(ReviewStatus::Failed),
        Some(ReviewStatus::Rejected),
        Some(ReviewStatus::Missing),
        None,
    ] {
        let mut terminal_failure = report.clone();
        terminal_failure.assignment_traceability[2].report_status = failed_status;
        let normalized = normalize_task_execution_feedback_from_supervisor_final_report(
            &session,
            &terminal_failure,
        )
        .expect("terminal nonsuccess maps to failed feedback");
        assert_eq!(normalized.failed_assignment_ids, vec!["provider-beta"]);
    }

    let mut invalid = report.clone();
    invalid
        .assignment_traceability
        .push(invalid.assignment_traceability[2].clone());
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("duplicate report id must fail")
            .to_string()
            .contains("repeats provider assignment")
    );

    let mut invalid = report.clone();
    invalid.assignment_traceability[2].assignment_id = "invented-provider-id".to_string();
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("unknown report id must fail")
            .to_string()
            .contains("unknown provider assignment")
    );

    let mut invalid = report.clone();
    invalid.assignment_traceability.pop();
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("missing leaf report must fail")
            .to_string()
            .contains("no traceability row")
    );

    let mut invalid = report.clone();
    invalid.assignment_traceability[2].depth = 2;
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("mismatched provider schedule must fail")
            .to_string()
            .contains("schedule and scope")
    );

    let mut invalid = report.clone();
    invalid.assignment_traceability[2].spec_fragment_ids = vec!["invented-fragment".to_string()];
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("unknown trace fragment must fail")
            .to_string()
            .contains("unknown current fragment")
    );

    let mut invalid = report.clone();
    invalid.coverage_gaps[0].spec_fragment_id = Some("invented-fragment".to_string());
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("unknown gap fragment must fail")
            .to_string()
            .contains("unknown current fragment")
    );

    let mut invalid = report.clone();
    invalid.coverage_gaps = vec![SupervisorCoverageGap {
        kind: CoverageGapKind::NoProducedChanges,
        spec_fragment_id: None,
        assignment_id: None,
        message: "fragmentless global gap".to_string(),
    }];
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("fragmentless global gap must fail")
            .to_string()
            .contains("fragmentless coverage gap")
    );

    let mut invalid = report.clone();
    invalid.coverage_gaps.push(SupervisorCoverageGap {
        kind: CoverageGapKind::MissingAssignmentReport,
        spec_fragment_id: None,
        assignment_id: Some("provider-root".to_string()),
        message: "internal report missing".to_string(),
    });
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("fragmentless internal missing-report gap must fail")
            .to_string()
            .contains("fragmentless coverage gap")
    );

    let mut invalid = report.clone();
    invalid.assignment_traceability[2].report_status = Some(ReviewStatus::Succeeded);
    assert!(
        normalize_task_execution_feedback_from_supervisor_final_report(&session, &invalid)
            .expect_err("succeeded fragment gap contradiction must fail")
            .to_string()
            .contains("succeeded fragment")
    );

    let proposal_before_invalid_attempt = session.proposal().clone();
    replan_provider_task_planning_session_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &mut session,
        &bound.execution_binding,
        &mut provider,
        &config,
    )
    .expect_err("invalid authenticated re-plan proposal must fail closed");
    assert_eq!(session.replans_used(), 1);
    assert_eq!(session.proposal(), &proposal_before_invalid_attempt);
    task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &bound.execution_binding,
    )
    .expect("failed proposal attempt must retain the original validated-plan binding");
    replan_provider_task_planning_session_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &mut session,
        &bound.execution_binding,
        &mut provider,
        &config,
    )
    .expect("authenticated finalized feedback re-plans remaining provider work");
    assert_eq!(session.replans_used(), planning::MAX_PROVIDER_REPLANS);
    assert!(task_execution_feedback_from_authenticated_supervisor_run(
        repo,
        "",
        spec,
        &session,
        &bound.execution_binding,
    )
    .expect_err("successful re-plan must stale the executed-plan binding")
    .to_string()
    .contains("does not match the current session and normalized plan"));
    let revised_document = supervisor_plan_document_from_task_planning_session("", spec, &session)
        .expect("lower revised remaining tree");
    assert_eq!(revised_document["max_depth"], 3);
    assert_eq!(revised_document["max_child_assignments"], 2);
    assert_eq!(
        revised_document["spec_fragment_ids"],
        json!(["fragment-002"])
    );
    assert!(revised_document.get("coverage_gaps").is_none());
    assert_eq!(
        revised_document["assignments"]
            .as_array()
            .expect("revised assignments")
            .iter()
            .map(|assignment| assignment["id"].as_str().expect("assignment id"))
            .collect::<Vec<_>>(),
        vec!["remaining-root", "provider-beta-revised"]
    );
    assert_eq!(
        revised_document["assignment_schedule"],
        json!([
            {
                "assignment_id": "remaining-root",
                "depth": 2,
                "flattened_index": 0
            },
            {
                "assignment_id": "provider-beta-revised",
                "parent_assignment_id": "remaining-root",
                "depth": 3,
                "flattened_index": 1
            }
        ])
    );
    assert!(revised_document["assignments"]
        .as_array()
        .expect("revised assignments")
        .iter()
        .all(|assignment| assignment["id"] != "provider-alpha"));

    let exhausted_run_id =
        RunId::new("provider-feedback-exact-exhaustion").expect("valid exhaustion run id");
    let exhausted_bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        spec,
        &session,
        exhausted_run_id.clone(),
    )
    .expect("bind final validated plan at exact re-plan exhaustion");
    let mut exhausted_report = artifact_test_final_report(&exhausted_run_id);
    exhausted_report.assigned_paths = vec![PathBuf::from("src/beta.rs")];
    exhausted_report.semantic_symbols = vec!["crate::beta::beta".to_string()];
    exhausted_report.semantic_modules = vec!["crate::beta".to_string()];
    exhausted_report.assignment_traceability = vec![
        provider_traceability(
            "remaining-root",
            None,
            2,
            0,
            &[],
            "src/beta.rs",
            Some(ReviewStatus::Succeeded),
        ),
        provider_traceability(
            "provider-beta-revised",
            Some("remaining-root"),
            3,
            1,
            &["fragment-002"],
            "src/beta.rs",
            Some(ReviewStatus::Failed),
        ),
    ];
    exhausted_report.coverage_gaps = vec![SupervisorCoverageGap {
        kind: CoverageGapKind::NoProducedChanges,
        spec_fragment_id: Some("fragment-002".to_string()),
        assignment_id: Some("provider-beta-revised".to_string()),
        message: "revised beta remains incomplete".to_string(),
    }];
    persist_provider_supervisor_artifact(
        repo,
        &exhausted_run_id,
        &exhausted_bound.document,
        &exhausted_report,
        true,
    );
    let session_at_exhaustion = session.clone();
    let calls_at_exhaustion = provider.calls().len();
    assert!(
        replan_provider_task_planning_session_from_authenticated_supervisor_run(
            repo,
            "",
            spec,
            &mut session,
            &exhausted_bound.execution_binding,
            &mut provider,
            &config,
        )
        .expect_err("third re-plan attempt must fail at the exact bound")
        .to_string()
        .contains("limit of 2 attempt(s) has been exhausted")
    );
    assert_eq!(session, session_at_exhaustion);
    assert_eq!(provider.calls().len(), calls_at_exhaustion);
}

#[test]
fn plain_text_task_without_actionable_scope_returns_guidance() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    Repository::init(&repo).expect("initialize repository");
    fs::write(repo.join("README.md"), "# fixture\n").expect("write readme");
    let task_file = temp.path().join("task.txt");
    fs::write(&task_file, "Explain the unmatched frobnicator.\n").expect("write task");

    let error = supervisor_plan_document_from_task_file(&repo, &task_file)
        .expect_err("scope-free task must fail")
        .to_string();
    assert!(error.contains("produced no actionable workstreams"));
    assert!(error.contains("repository path, Rust module, or Rust symbol"));
}

#[test]
fn supervisor_depth_bounds_are_configurable_and_enforced() {
    let recursive = |max_depth| {
        json!({
            "version": 1,
            "task": "depth bounds",
            "max_depth": max_depth,
            "max_child_assignments": 2,
            "assignments": [{
                "id": "root-child",
                "assigned_paths": ["src/root.rs"],
                "child_assignments": [{
                    "id": "nested-child",
                    "assigned_paths": ["src/nested.rs"]
                }]
            }]
        })
    };
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&recursive(3)).expect("serialize depth-three plan")
    )
    .is_ok());
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&recursive(2)).expect("serialize shallow plan")
    )
    .expect_err("nested assignment must exceed max depth two")
    .to_string()
    .contains("depth 3"));

    for invalid_depth in [1, MAX_SUPERVISOR_DEPTH.saturating_add(1)] {
        let source = json!({
            "version": 1,
            "task": "invalid depth",
            "max_depth": invalid_depth,
            "max_child_assignments": 1,
            "assignments": [{
                "id": "child-a",
                "assigned_paths": ["README.md"]
            }]
        });
        assert!(parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize invalid depth")
        )
        .is_err());
    }
}

#[test]
fn supervisor_represents_and_validates_assignment_trees_to_arbitrary_configured_depth() {
    let source = json!({
        "version": 1,
        "task": "deep recursive plan",
        "max_depth": 5,
        "max_child_assignments": 4,
        "assignments": [{
            "id": "depth-2",
            "assigned_paths": ["src/depth_2.rs"],
            "child_assignments": [{
                "id": "depth-3",
                "assigned_paths": ["src/depth_3.rs"],
                "child_assignments": [{
                    "id": "depth-4",
                    "assigned_paths": ["src/depth_4.rs"],
                    "child_assignments": [{
                        "id": "depth-5",
                        "assigned_paths": ["src/depth_5.rs"]
                    }]
                }]
            }]
        }]
    });
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&source).expect("serialize deep plan"),
    )
    .expect("parse deep plan");
    assert_eq!(
        loaded
            .plan_metadata
            .assignment_schedule
            .iter()
            .map(|entry| {
                (
                    entry.assignment_id.as_str(),
                    entry.parent_assignment_id.as_deref(),
                    entry.depth,
                    entry.flattened_index,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("depth-2", None, 2, 0),
            ("depth-3", Some("depth-2"), 3, 1),
            ("depth-4", Some("depth-3"), 4, 2),
            ("depth-5", Some("depth-4"), 5, 3),
        ]
    );

    let mut too_shallow = source;
    too_shallow["max_depth"] = json!(4);
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&too_shallow).expect("serialize shallow bound")
    )
    .expect_err("deepest assignment must exceed configured bound")
    .to_string()
    .contains("depth 5"));
}

#[test]
fn supervisor_allows_overlapping_scopes_only_across_strict_lineage() {
    let ancestor_overlap = json!({
        "version": 1,
        "task": "lineage overlap",
        "max_depth": 3,
        "max_child_assignments": 2,
        "assignments": [{
            "id": "planning-root",
            "assigned_paths": ["src/shared.rs"],
            "semantic_symbols": ["crate::shared::Shared"],
            "child_assignments": [{
                "id": "execution-child",
                "assigned_paths": ["src/shared.rs"],
                "semantic_symbols": ["crate::shared::Shared"]
            }]
        }]
    });
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&ancestor_overlap).expect("serialize lineage overlap"),
    )
    .expect("strict ancestor overlap is dependency-gated");
    assert!(schedule_entries_share_strict_lineage(
        &loaded.plan_metadata.assignment_schedule,
        0,
        1
    ));

    let sibling_overlap = json!({
        "version": 1,
        "task": "sibling overlap",
        "max_depth": 3,
        "max_child_assignments": 3,
        "assignments": [{
            "id": "planning-root",
            "assigned_paths": ["src"],
            "child_assignments": [
                {
                    "id": "execution-a",
                    "assigned_paths": ["src/shared.rs"]
                },
                {
                    "id": "execution-b",
                    "assigned_paths": ["src/shared.rs"]
                }
            ]
        }]
    });
    let error = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&sibling_overlap).expect("serialize sibling overlap"),
    )
    .expect_err("sibling overlap remains concurrent and must be rejected")
    .to_string();
    assert!(error.contains("assignments 'execution-a'"));
    assert!(error.contains("'execution-b'"));
    assert!(error.contains("overlap after normalization"));
}

#[test]
fn hierarchy_admission_waits_for_accepted_successful_parent() {
    let assignments = [
        injected_named_assignment("planning-root", "src/shared.rs"),
        injected_named_assignment("execution-child", "src/shared.rs"),
    ];
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: "planning-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: "execution-child".to_string(),
            parent_assignment_id: Some("planning-root".to_string()),
            depth: 3,
            flattened_index: 1,
        },
    ];
    let mut outcomes = vec![None, None];
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes)
            .expect("classify waiting execution child"),
        AssignmentAdmissionState::Waiting
    );

    outcomes[0] = Some(AssignmentExecutionOutcome {
        report: Some(injected_child_report(&assignments[0])),
        ..AssignmentExecutionOutcome::default()
    });
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes)
            .expect("classify ready execution child"),
        AssignmentAdmissionState::Ready
    );
    assert!(assignment_outcome_succeeded(
        outcomes[0].as_ref().expect("successful parent outcome")
    ));
}

#[test]
fn failed_parent_suppresses_descendants_but_not_independent_roots() {
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: "failed-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: "suppressed-child".to_string(),
            parent_assignment_id: Some("failed-root".to_string()),
            depth: 3,
            flattened_index: 1,
        },
        AssignmentScheduleEntry {
            assignment_id: "suppressed-grandchild".to_string(),
            parent_assignment_id: Some("suppressed-child".to_string()),
            depth: 4,
            flattened_index: 2,
        },
        AssignmentScheduleEntry {
            assignment_id: "independent-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 3,
        },
    ];
    let mut outcomes = vec![
        Some(AssignmentExecutionOutcome {
            assignment_failed: true,
            ..AssignmentExecutionOutcome::default()
        }),
        None,
        None,
        None,
    ];
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes).expect("classify failed-parent child"),
        AssignmentAdmissionState::Suppressed {
            parent_assignment_id: "failed-root".to_string()
        }
    );
    assert_eq!(
        assignment_admission_state(2, &schedule, &outcomes).expect("classify waiting grandchild"),
        AssignmentAdmissionState::Waiting
    );
    assert_eq!(
        assignment_admission_state(3, &schedule, &outcomes).expect("classify independent root"),
        AssignmentAdmissionState::Ready
    );

    let suppressed = injected_named_assignment("suppressed-child", "src/suppressed.rs");
    outcomes[1] = Some(suppressed_descendant_outcome(&suppressed, "failed-root"));
    assert_eq!(
        assignment_admission_state(2, &schedule, &outcomes)
            .expect("classify transitively suppressed grandchild"),
        AssignmentAdmissionState::Suppressed {
            parent_assignment_id: "suppressed-child".to_string()
        }
    );
}

#[test]
fn same_lineage_semantic_preview_excludes_ancestor_but_retains_independent_root() {
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: "planning-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: "execution-child".to_string(),
            parent_assignment_id: Some("planning-root".to_string()),
            depth: 3,
            flattened_index: 1,
        },
        AssignmentScheduleEntry {
            assignment_id: "independent-root".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 2,
        },
    ];
    let intent = |token, agent_id: &str| SemanticIntent {
        token: crate::semantic_coord::SemanticIntentToken::from_u64(token),
        agent_id: agent_id.to_string(),
        paths: vec![PathBuf::from("src/shared.rs")],
        symbols: Vec::new(),
        modules: vec!["crate::shared".to_string()],
        impacted_files: Vec::new(),
        task_digest: None,
        task_excerpt: None,
        notes: Vec::new(),
        warnings: Vec::new(),
    };
    let planned = vec![
        (0, intent(1, "planning-root")),
        (2, intent(2, "independent-root")),
    ];

    let relevant = semantic_preview_intents_for_assignment(1, &schedule, &planned);
    assert_eq!(
        relevant
            .iter()
            .map(|intent| intent.agent_id.as_str())
            .collect::<Vec<_>>(),
        vec!["independent-root"]
    );
}

#[test]
fn supervisor_rejects_normalized_path_symbol_and_module_collisions() {
    let collision_error = |left: Value, right: Value| {
        let source = json!({
            "version": 1,
            "task": "collision",
            "max_depth": 2,
            "max_child_assignments": 2,
            "assignments": [left, right]
        });
        parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize collision plan"),
        )
        .expect_err("collision must fail before launch")
        .to_string()
    };
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/generated/../lib.rs"]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/lib.rs"]
        }),
    )
    .contains("path 'src/lib.rs'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src"]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/nested/lib.rs"]
        }),
    )
    .contains("overlap after normalization"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_symbols": [" crate :: SharedSymbol "]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_symbols": ["crate::SharedSymbol"]
        }),
    )
    .contains("semantic symbol 'crate::SharedSymbol'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_modules": [" shared "]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_modules": ["crate :: shared"]
        }),
    )
    .contains("semantic module 'crate::shared'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_modules": ["crate::shared"]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_modules": ["crate::shared::nested"]
        }),
    )
    .contains("semantic module hierarchy 'crate::shared' and 'crate::shared::nested'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_modules": ["crate::shared"]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_symbols": ["crate::shared::SharedSymbol"]
        }),
    )
    .contains("semantic module 'crate::shared' and symbol 'crate::shared::SharedSymbol'"));
}

#[test]
fn supervisor_rejects_normalized_worker_semantic_collisions() {
    let worker_collision_error = |first: Value, second: Value| {
        let source = json!({
            "version": 1,
            "task": "worker collision",
            "max_depth": 2,
            "max_child_assignments": 1,
            "assignments": [{
                "id": "child-a",
                "assigned_paths": ["src"],
                "worker_assignments": [first, second]
            }]
        });
        parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize worker collision"),
        )
        .expect_err("worker collision must fail")
        .to_string()
    };
    assert!(worker_collision_error(
        json!({
            "id": "worker-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_modules": [" shared "]
        }),
        json!({
            "id": "worker-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_modules": ["crate :: shared"]
        }),
    )
    .contains("workers 'worker-a' and 'worker-b'"));
    assert!(worker_collision_error(
        json!({
            "id": "worker-a",
            "assigned_paths": ["src/a.rs"],
            "semantic_symbols": [" crate :: SharedSymbol "]
        }),
        json!({
            "id": "worker-b",
            "assigned_paths": ["src/b.rs"],
            "semantic_symbols": ["crate::SharedSymbol"]
        }),
    )
    .contains("semantic symbol 'crate::SharedSymbol'"));
    assert!(worker_collision_error(
        json!({
            "id": "worker-a",
            "assigned_paths": ["src/generated/../lib.rs"]
        }),
        json!({
            "id": "worker-b",
            "assigned_paths": ["src/lib.rs"]
        }),
    )
    .contains("overlaps worker"));
}

#[test]
fn supervisor_rejects_cross_assignment_worker_semantic_collisions() {
    let collision_error = |left: Value, right: Value| {
        let source = json!({
            "version": 1,
            "task": "cross assignment worker collision",
            "max_depth": 2,
            "max_child_assignments": 2,
            "assignments": [left, right]
        });
        parse_supervisor_plan_with_consultant(
            &serde_json::to_string(&source).expect("serialize cross assignment collision"),
        )
        .expect_err("cross assignment worker semantics must fail")
        .to_string()
    };
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a"],
            "worker_assignments": [{
                "id": "worker-a",
                "assigned_paths": ["src/a/worker.rs"],
                "semantic_symbols": [" crate :: SharedSymbol "]
            }]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b"],
            "worker_assignments": [{
                "id": "worker-b",
                "assigned_paths": ["src/b/worker.rs"],
                "semantic_symbols": ["crate::SharedSymbol"]
            }]
        }),
    )
    .contains("worker 'worker-a' under assignment 'child-a' and worker 'worker-b'"));
    assert!(collision_error(
        json!({
            "id": "child-a",
            "assigned_paths": ["src/a"],
            "semantic_modules": [" shared "]
        }),
        json!({
            "id": "child-b",
            "assigned_paths": ["src/b"],
            "worker_assignments": [{
                "id": "worker-b",
                "assigned_paths": ["src/b/worker.rs"],
                "semantic_modules": ["crate :: shared"]
            }]
        }),
    )
    .contains("assignment 'child-a' and worker 'worker-b'"));
}

#[test]
fn supervisor_traceability_reports_missing_changes_and_diff_binding() {
    let plan = injected_multi_plan(
        vec![
            injected_named_assignment("child-a", "src/a.rs"),
            injected_named_assignment("child-b", "src/b.rs"),
        ],
        0,
    );
    let metadata = SupervisorPlanMetadata {
        execution_target: None,
        spec_fragment_ids: vec!["SPEC-a".to_string(), "SPEC-b".to_string()],
        spec_fragment_ids_by_assignment: BTreeMap::from([
            ("child-a".to_string(), vec!["SPEC-a".to_string()]),
            ("child-b".to_string(), vec!["SPEC-b".to_string()]),
        ]),
        assignment_schedule: vec![
            AssignmentScheduleEntry {
                assignment_id: "child-a".to_string(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: "child-b".to_string(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 1,
            },
        ],
        coverage_gaps: Vec::new(),
        run_budget: SupervisorBudgetConfig::default(),
        run_budget_max_duration_seconds: None,
        admission: SupervisorAdmissionConfig::default(),
        evidence_only_reaudit: None,
        generated_follow_up: None,
        review_loop_guard: None,
    };
    let mut report_a = injected_child_report(&plan.assignments[0]);
    report_a.files_changed = vec![PathBuf::from("src/a.rs")];
    let mut report_b = injected_child_report(&plan.assignments[1]);
    report_b.files_changed.clear();
    let (traceability, gaps) = supervisor_assignment_traceability(
        &plan,
        &metadata,
        &[report_a, report_b],
        &BTreeMap::new(),
    );
    assert_eq!(traceability.len(), 2);
    assert_eq!(
        traceability[0].produced_changed_paths,
        vec![PathBuf::from("src/a.rs")]
    );
    assert!(traceability[0].produced_diff_binding.is_none());
    assert!(gaps.iter().any(|gap| {
        gap.kind == CoverageGapKind::MissingDiffBinding
            && gap.assignment_id.as_deref() == Some("child-a")
            && gap.spec_fragment_id.as_deref() == Some("SPEC-a")
    }));
    assert!(gaps.iter().any(|gap| {
        gap.kind == CoverageGapKind::NoProducedChanges
            && gap.assignment_id.as_deref() == Some("child-b")
            && gap.spec_fragment_id.as_deref() == Some("SPEC-b")
    }));
}

#[test]
fn supervisor_traceability_binds_ordinary_success_to_observed_paths_and_diff() {
    let plan = injected_multi_plan(vec![injected_named_assignment("child-a", "src/a.rs")], 0);
    let metadata = SupervisorPlanMetadata {
        execution_target: None,
        spec_fragment_ids: vec!["SPEC-a".to_string()],
        spec_fragment_ids_by_assignment: BTreeMap::from([(
            "child-a".to_string(),
            vec!["SPEC-a".to_string()],
        )]),
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id: "child-a".to_string(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        }],
        coverage_gaps: Vec::new(),
        run_budget: SupervisorBudgetConfig::default(),
        run_budget_max_duration_seconds: None,
        admission: SupervisorAdmissionConfig::default(),
        evidence_only_reaudit: None,
        generated_follow_up: None,
        review_loop_guard: None,
    };
    let mut report = injected_child_report(&plan.assignments[0]);
    report.files_changed = vec![PathBuf::from("src/a.rs")];
    let binding = CandidateValidationBinding {
        version: 1,
        agent_id: "child-a".to_string(),
        primary_head: Some("1111111111111111111111111111111111111111".to_string()),
        agent_head: Some("2222222222222222222222222222222222222222".to_string()),
        merge_base: Some("1111111111111111111111111111111111111111".to_string()),
        diff_oid: "3333333333333333333333333333333333333333".to_string(),
    };
    let inspections = BTreeMap::from([(
        "child-a".to_string(),
        SupervisorCandidateInspection {
            binding: binding.clone(),
            changed_paths: vec![PathBuf::from("src/a.rs")],
        },
    )]);

    let (traceability, gaps) =
        supervisor_assignment_traceability(&plan, &metadata, &[report], &inspections);

    assert!(gaps.is_empty());
    assert_eq!(traceability.len(), 1);
    assert_eq!(traceability[0].spec_fragment_ids, vec!["SPEC-a"]);
    assert_eq!(
        traceability[0].produced_changed_paths,
        vec![PathBuf::from("src/a.rs")]
    );
    assert_eq!(traceability[0].produced_diff_binding, Some(binding));
    assert_eq!(traceability[0].report_status, Some(ReviewStatus::Succeeded));
}

#[test]
fn admitted_nested_assignment_retains_ordinary_pipeline_and_acceptance_evidence() {
    let planning = injected_named_assignment("planning-root", "src/shared.rs");
    let mut execution = injected_named_assignment("execution-child", "src/shared.rs");
    execution.worker_assignments.push(WorkerAssignment {
        id: "execution-child-worker".to_string(),
        role: AgentRole::Worker,
        assigned_paths: execution.assigned_paths.clone(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: Some("implement the nested execution task".to_string()),
        environment_requirements: Vec::new(),
        report_path: None,
    });
    let mut plan = injected_multi_plan(vec![planning.clone(), execution.clone()], 0);
    plan.max_depth = 3;
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: planning.id.clone(),
            parent_assignment_id: None,
            depth: 2,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: execution.id.clone(),
            parent_assignment_id: Some(planning.id.clone()),
            depth: 3,
            flattened_index: 1,
        },
    ];
    let outcomes = vec![
        Some(AssignmentExecutionOutcome {
            report: Some(injected_child_report(&planning)),
            ..AssignmentExecutionOutcome::default()
        }),
        None,
    ];
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes).expect("admit execution child"),
        AssignmentAdmissionState::Ready
    );
    assert!(release_assignment_resources_after_completion(
        &plan, &schedule, 1
    ));

    let worktree = WorktreeRecord {
        name: execution.id.clone(),
        path: PathBuf::from("/tmp/maco-nested-execution"),
        branch: "maco/execution-child".to_string(),
    };
    let claim = PathClaim {
        token: ClaimToken::from_u64(41),
        agent_id: execution.id.clone(),
        paths: execution.assigned_paths.clone(),
    };
    let prompt = child_orchestrator_prompt(ChildOrchestratorPromptContext {
        plan: &plan,
        execution_target: None,
        assignment: &execution,
        run_dir: Path::new("/tmp/maco-run"),
        worktree: &worktree,
        report_path: Path::new("/tmp/maco-run/incoming/execution-child.json"),
        schema_path: Path::new("/tmp/maco-run/schemas/orchestrator-review-report.schema.json"),
        worker_schema_path: Path::new("/tmp/maco-run/schemas/worker-report.schema.json"),
        auditor_schema_path: Path::new("/tmp/maco-run/schemas/auditor-report.schema.json"),
        consultant: &SupervisorConsultantPlan::default(),
        claim_context: ChildPromptClaimContext {
            claim: &claim,
            semantic_intent_token: Some(43),
        },
    })
    .expect("render ordinary nested execution prompt");
    assert!(prompt.contains("Path claim token: 41"));
    assert!(prompt.contains("Semantic intent token: 43"));
    assert!(prompt.contains("/tmp/maco-run/incoming/worker-journals/execution-child-worker.jsonl"));
    assert!(prompt.contains("Return your OrchestratorReviewReport JSON"));
    assert!(prompt.contains("Review auditor prompt template:"));

    let mut accepted_report = injected_child_report(&execution);
    accepted_report.files_changed = vec![PathBuf::from("src/shared.rs")];
    let accepted_audit = injected_auditor_report(&execution, &accepted_report);
    accepted_report.audit_reports.push(accepted_audit);
    let binding = CandidateValidationBinding {
        version: 1,
        agent_id: execution.id.clone(),
        primary_head: Some("1111111111111111111111111111111111111111".to_string()),
        agent_head: Some("2222222222222222222222222222222222222222".to_string()),
        merge_base: Some("1111111111111111111111111111111111111111".to_string()),
        diff_oid: "3333333333333333333333333333333333333333".to_string(),
    };
    let metadata = SupervisorPlanMetadata {
        execution_target: None,
        spec_fragment_ids: vec!["SPEC-execution".to_string()],
        spec_fragment_ids_by_assignment: BTreeMap::from([(
            execution.id.clone(),
            vec!["SPEC-execution".to_string()],
        )]),
        assignment_schedule: schedule,
        coverage_gaps: Vec::new(),
        run_budget: SupervisorBudgetConfig::default(),
        run_budget_max_duration_seconds: None,
        admission: SupervisorAdmissionConfig::default(),
        evidence_only_reaudit: None,
        generated_follow_up: None,
        review_loop_guard: None,
    };
    let inspections = BTreeMap::from([(
        execution.id.clone(),
        SupervisorCandidateInspection {
            binding: binding.clone(),
            changed_paths: vec![PathBuf::from("src/shared.rs")],
        },
    )]);
    let (traceability, gaps) =
        supervisor_assignment_traceability(&plan, &metadata, &[accepted_report], &inspections);
    assert!(gaps.iter().any(|gap| {
        gap.assignment_id.as_deref() == Some("planning-root")
            && gap.kind == CoverageGapKind::MissingAssignmentReport
    }));
    let execution_trace = traceability
        .iter()
        .find(|entry| entry.assignment_id == execution.id)
        .expect("execution traceability entry");
    assert_eq!(
        execution_trace.parent_assignment_id.as_deref(),
        Some("planning-root")
    );
    assert_eq!(execution_trace.produced_diff_binding, Some(binding));
    assert_eq!(execution_trace.report_status, Some(ReviewStatus::Succeeded));
}

#[test]
fn role_selection_produces_distinct_launched_role_argv() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models = BTreeMap::from([
        (
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: Some(BALANCED_PROFILE_MODEL.to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        ),
        (
            AgentRole::Worker,
            RoleModelSelection {
                model: Some(FRONTIER_PROFILE_MODEL.to_string()),
                reasoning_effort: Some("low".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        ),
        (
            AgentRole::Auditor,
            RoleModelSelection {
                model: Some(FRONTIER_PROFILE_MODEL.to_string()),
                reasoning_effort: Some("xhigh".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        ),
    ]);
    let base_command = || {
        ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        )
    };
    let catalog = injected_codex_runtime_catalog(&[BALANCED_PROFILE_MODEL, FRONTIER_PROFILE_MODEL]);
    let child = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("runtime catalog contains the configured child selection");
    let auditor = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::Auditor,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("runtime catalog contains the configured auditor selection");
    let child_argv = crate::external_agent::command_argv(&child)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let auditor_argv = crate::external_agent::command_argv(&auditor)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(child_argv
        .windows(2)
        .any(|arguments| arguments == ["-m", BALANCED_PROFILE_MODEL]));
    assert!(child_argv
        .windows(2)
        .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"high\""] }));
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| arguments == ["-m", FRONTIER_PROFILE_MODEL]));
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"xhigh\""] }));
    assert!(!child_argv
        .iter()
        .any(|argument| argument.contains(FRONTIER_PROFILE_MODEL)));
    assert_ne!(child_argv, auditor_argv);

    plan.role_models
        .get_mut(&AgentRole::ChildOrchestrator)
        .expect("child selection")
        .model = Some(ECONOMY_PROFILE_MODEL.to_string());
    let weak_error = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &injected_codex_runtime_catalog(&[ECONOMY_PROFILE_MODEL]),
    )
    .expect_err("weak model must not launch child implementation judgment");
    assert!(format!("{weak_error:#}").contains("does not satisfy role 'child_orchestrator'"));
}

#[test]
fn no_override_selects_single_slug_effort_profile_for_every_role() {
    let plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    let profile = plan.effective_role_economics_profile();
    assert_eq!(profile.name, PROVISIONAL_DEFAULT_HYBRID_PROFILE_NAME);
    assert_eq!(
        profile.evidence,
        PROVISIONAL_DEFAULT_HYBRID_PROFILE_EVIDENCE
    );
    assert!(profile.evidence_notice.contains("production-ineligible"));
    assert!(!profile.production_eligible);
    assert_eq!(profile.model_availability, RoleModelAvailability::Unknown);
    assert!(profile.overridden_roles.is_empty());
    assert_eq!(profile.role_models.len(), 5);
    let catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL]);
    for role in [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ] {
        assert_eq!(
            profile.role_models[&role].model.as_deref(),
            Some(FRONTIER_PROFILE_MODEL),
            "default {role:?} binding diverged from the standard slug"
        );
        let UnavailableModelFallback::OrderedCatalogChain(chain) =
            &profile.role_models[&role].unavailable_model_fallback
        else {
            panic!("default {role:?} binding lost catalog-chain data");
        };
        assert!(
            chain.models.is_empty(),
            "default {role:?} availability chain names a nonstandard slug"
        );
        let resolved = catalog
            .resolve_role_model_selection(&profile.role_models[&role], SupervisorRuntime::Codex)
            .unwrap_or_else(|error| panic!("default {role:?} binding did not resolve: {error:#}"));
        assert_eq!(
            resolved.selection.model.as_deref(),
            Some(FRONTIER_PROFILE_MODEL),
            "default {role:?} binding resolved away from the standard slug"
        );
    }
    assert_eq!(
        profile.role_models[&AgentRole::ChildOrchestrator]
            .reasoning_effort
            .as_deref(),
        Some("xhigh")
    );
    assert_eq!(
        profile.role_models[&AgentRole::Worker]
            .reasoning_effort
            .as_deref(),
        Some("medium")
    );
    assert!(matches!(
        &profile.role_models[&AgentRole::GateClassifier].unavailable_model_fallback,
        UnavailableModelFallback::OrderedCatalogChain(OrderedCatalogFallback {
            on_exhausted: TerminalUnavailableModelFallback::LocalDeterministicFake,
            ..
        })
    ));
    assert!(matches!(
        &profile.role_models[&AgentRole::Auditor].unavailable_model_fallback,
        UnavailableModelFallback::OrderedCatalogChain(OrderedCatalogFallback {
            on_exhausted: TerminalUnavailableModelFallback::RuntimeDefault,
            ..
        })
    ));

    let base_command = || {
        ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        )
    };
    let catalog = injected_codex_runtime_catalog(&[
        FRONTIER_PROFILE_MODEL,
        BALANCED_PROFILE_MODEL,
        ECONOMY_PROFILE_MODEL,
    ]);
    let runtime_profile = plan.effective_role_economics_profile_for_runtime(&catalog);
    assert_eq!(
        runtime_profile.model_availability,
        RoleModelAvailability::Available
    );
    let child = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("apply no-override child selection");
    let child_argv = crate::external_agent::app_server_command_argv(&child)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        child_argv
            .windows(2)
            .any(|arguments| arguments == ["-c", "model=\"gpt-5.6-sol\""]),
        "writable child app-server argv did not select the provisional model: {child_argv:?}"
    );
    assert!(child_argv
        .windows(2)
        .any(|arguments| arguments == ["-c", "model_reasoning_effort=\"xhigh\""]));

    let auditor = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::Auditor,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("apply no-override auditor selection");
    let auditor_argv = crate::external_agent::command_argv(&auditor)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| arguments == ["-m", FRONTIER_PROFILE_MODEL]));
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| arguments == ["-c", "model_reasoning_effort=\"xhigh\""]));
}

#[test]
fn single_slug_profile_with_budget_chains_round_trips_through_plan_json() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models = provisional_default_role_models();
    let document = serde_json::to_string(&plan).expect("serialize tiered plan");
    assert!(document.contains("ordered_catalog_chain"));
    let loaded = parse_supervisor_plan_with_consultant(&document).expect("reload tiered plan");
    assert_eq!(loaded.plan.role_models, plan.role_models);

    plan.role_models = all_frontier_role_models();
    let document = serde_json::to_string(&plan).expect("serialize all-frontier plan");
    let loaded =
        parse_supervisor_plan_with_consultant(&document).expect("reload all-frontier plan");
    assert_eq!(loaded.plan.role_models, plan.role_models);
    assert_eq!(
        loaded.plan.effective_role_economics_profile().name,
        ALL_FRONTIER_PROFILE_NAME
    );
    assert!(loaded
        .plan
        .role_models
        .values()
        .all(|selection| selection.model.as_deref() == Some(FRONTIER_PROFILE_MODEL)));
    assert!(loaded.plan.role_models.values().all(|selection| matches!(
        &selection.unavailable_model_fallback,
        UnavailableModelFallback::OrderedCatalogChain(OrderedCatalogFallback {
            models,
            ..
        }) if models.is_empty()
    )));
    assert_eq!(
        loaded.plan.role_models[&AgentRole::ChildOrchestrator].unavailable_model_fallback,
        UnavailableModelFallback::OrderedCatalogChain(OrderedCatalogFallback {
            models: Vec::new(),
            budget_degrade_models: vec![
                BALANCED_PROFILE_MODEL.to_string(),
                ECONOMY_PROFILE_MODEL.to_string(),
            ],
            on_exhausted: TerminalUnavailableModelFallback::RuntimeDefault,
        })
    );
}

#[test]
fn admission_policy_inputs_round_trip_through_plan_json_and_reject_zero() {
    let mut document =
        serde_json::from_slice::<Value>(&bounded_loader_plan_json()).expect("parse plan fixture");
    document.as_object_mut().expect("plan object").insert(
        "concurrency".to_string(),
        json!({
            "max_concurrent_children": 12,
            "provider_inflight_limit": 9,
            "host_memory_available_mib": 8192,
            "host_memory_per_child_mib": 1024,
            "host_fd_available": 640,
            "host_fds_per_child": 128,
            "host_disk_available_mib": 9000,
            "host_disk_per_child_mib": 1000,
            "host_fallback_children": 2
        }),
    );
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&document).expect("serialize configured plan"),
    )
    .expect("parse configured admission policy");
    let normalized = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
    .expect("normalize configured admission policy");
    assert_eq!(normalized["concurrency"], document["concurrency"]);
    let reparsed = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&normalized).expect("serialize normalized policy"),
    )
    .expect("reparse normalized policy");
    assert_eq!(
        reparsed.plan_metadata.admission,
        loaded.plan_metadata.admission
    );

    document["concurrency"]["provider_inflight_limit"] = json!(0);
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&document).expect("serialize invalid policy")
    )
    .expect_err("zero provider quota must fail")
    .to_string()
    .contains("concurrency.provider_inflight_limit must be greater than zero"));
}

#[test]
fn ordered_catalog_chain_selects_first_available_model_with_typed_observation() {
    let configured = RoleModelSelection {
        model: Some(BALANCED_PROFILE_MODEL.to_string()),
        reasoning_effort: Some("xhigh".to_string()),
        unavailable_model_fallback: UnavailableModelFallback::OrderedCatalogChain(
            OrderedCatalogFallback {
                models: vec![
                    FRONTIER_PROFILE_MODEL.to_string(),
                    ECONOMY_PROFILE_MODEL.to_string(),
                ],
                budget_degrade_models: vec![ECONOMY_PROFILE_MODEL.to_string()],
                on_exhausted: TerminalUnavailableModelFallback::RuntimeDefault,
            },
        ),
    };
    let catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL]);
    let resolved = catalog
        .resolve_role_model_selection(&configured, SupervisorRuntime::Codex)
        .expect("resolve fallback chain");
    assert_eq!(
        resolved.selection.model.as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(
        resolved.observation,
        ModelResolutionObservation::CatalogFallback
    );
    assert_eq!(resolved.resolved_candidate_index, Some(1));
    assert_eq!(
        resolved.configured_model_chain,
        vec![
            BALANCED_PROFILE_MODEL.to_string(),
            FRONTIER_PROFILE_MODEL.to_string(),
            ECONOMY_PROFILE_MODEL.to_string()
        ]
    );

    let plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    let resolved_prompt_plan =
        runtime_resolved_prompt_plan(&plan, SupervisorRuntime::Codex, &catalog)
            .expect("resolve prompt selections");
    assert_eq!(
        effective_role_model_selection(&resolved_prompt_plan, AgentRole::ChildOrchestrator)
            .model
            .as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(
        effective_role_model_selection(&resolved_prompt_plan, AgentRole::Worker)
            .model
            .as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
}

#[test]
fn ordered_catalog_chain_rejects_invalid_profile_data_during_plan_load() {
    for (label, chain, expected) in [
        (
            "whitespace",
            json!({"models": [" gpt-5.6-sol"], "on_exhausted": "runtime_default"}),
            "must be non-empty and trimmed",
        ),
        (
            "duplicate fallback",
            json!({"models": ["gpt-5.6-terra", "gpt-5.6-terra"], "on_exhausted": "runtime_default"}),
            "contains duplicate model",
        ),
        (
            "repeated primary",
            json!({"models": ["gpt-5.6-luna"], "on_exhausted": "runtime_default"}),
            "repeats configured model",
        ),
    ] {
        let mut document: serde_json::Value =
            serde_json::from_slice(&bounded_loader_plan_json()).expect("base plan JSON");
        document["role_models"] = json!({
            "worker": {
                "model": "gpt-5.6-luna",
                "unavailable_model_fallback": {"ordered_catalog_chain": chain}
            }
        });
        let error = format!(
            "{:#}",
            parse_supervisor_plan_with_consultant(&document.to_string()).expect_err(label)
        );
        assert!(error.contains(expected), "{label}: {error}");
    }
}

#[test]
fn gate_classifier_override_and_unavailable_fallback_are_independent() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models.insert(
        AgentRole::GateClassifier,
        RoleModelSelection {
            model: Some("classifier-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let profile = plan.effective_role_economics_profile();
    assert_eq!(
        profile.role_models[&AgentRole::GateClassifier]
            .model
            .as_deref(),
        Some("classifier-model")
    );
    assert_eq!(
        profile.role_models[&AgentRole::Auditor].model.as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(profile.overridden_roles, vec![AgentRole::GateClassifier]);

    let fallback = profile.role_models[&AgentRole::GateClassifier]
        .resolve_for_availability(RoleModelAvailability::Unavailable, SupervisorRuntime::Codex)
        .expect("runtime-default fallback");
    assert!(fallback.model.is_none());
    assert_eq!(fallback.reasoning_effort.as_deref(), Some("high"));
    let local_fake = RuntimeModelCatalog::LocalDeterministicFake
        .resolve_role_model_selection(
            &provisional_default_role_model_selection(AgentRole::GateClassifier),
            SupervisorRuntime::Fake,
        )
        .expect("local fake fallback");
    assert_eq!(local_fake.selection, RoleModelSelection::default());
    assert_eq!(
        local_fake.observation,
        ModelResolutionObservation::LocalDeterministicFake
    );
    assert!(injected_codex_runtime_catalog(&["unrelated-model"])
        .resolve_role_model_selection(
            &provisional_default_role_model_selection(AgentRole::GateClassifier),
            SupervisorRuntime::Codex,
        )
        .expect_err("local fake cannot replace a Codex model")
        .to_string()
        .contains("valid only for the fake runtime"));
}

#[test]
fn unavailable_model_fallback_is_a_runtime_aware_command_contract() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some(BALANCED_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let base_command = || {
        ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        )
    };
    let missing_catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL]);

    let runtime_default_error = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &missing_catalog,
    )
    .expect_err("runtime-default identity is not trusted capability evidence");
    assert!(format!("{runtime_default_error:#}")
        .contains("runtime-default model selection is not capability evidence"));

    plan.role_models
        .get_mut(&AgentRole::ChildOrchestrator)
        .expect("child selection")
        .unavailable_model_fallback = UnavailableModelFallback::FailClosed;
    let fail_closed_error = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &missing_catalog,
    )
    .expect_err("fail_closed rejects runtime-advertised unavailability");
    assert!(format!("{fail_closed_error:#}").contains("fallback is fail_closed"));

    plan.role_models
        .get_mut(&AgentRole::ChildOrchestrator)
        .expect("child selection")
        .unavailable_model_fallback = UnavailableModelFallback::LocalDeterministicFake;
    let local_fake = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Fake,
        &RuntimeModelCatalog::LocalDeterministicFake,
    )
    .expect("the fake runtime may use its deterministic local fallback");
    assert_eq!(local_fake.model, None);
    assert_eq!(local_fake.reasoning_effort, None);
    let invalid_runtime_error = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &missing_catalog,
    )
    .expect_err("known-unavailable Codex cannot use the deterministic local fallback");
    assert!(format!("{invalid_runtime_error:#}").contains("valid only for the fake runtime"));
}

#[test]
fn known_unavailable_child_runtime_default_rejects_before_dispatch_or_artifacts() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment, 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some(BALANCED_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let run_id = "known-unavailable-child-runtime-default";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL]);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("runtime-default capability rejection must prevent dispatch")
    };

    let error = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect_err("runtime-default model must fail before artifact reservation");

    assert_eq!(invocations, 0);
    assert!(
        format!("{error:#}").contains("runtime-default model selection is not capability evidence")
    );
    assert!(!repo_path
        .join(RunArtifactFamily::Supervise.run_root())
        .exists());
    assert!(!repo_path.join(".maco").exists());
}

#[test]
fn configured_lens_selection_uses_trusted_builtin_and_clamps_to_auditor_floor() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some(BALANCED_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    plan.role_models.insert(
        AgentRole::Auditor,
        RoleModelSelection {
            model: Some(FRONTIER_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let ReviewLensBackendConfig::Model {
        model,
        reasoning_effort,
        ..
    } = &mut plan.review_lenses[0].backend
    else {
        panic!("default supervisor lens must be model-backed");
    };
    *model = FRONTIER_PROFILE_MODEL.to_string();
    *reasoning_effort = Some("low".to_string());
    let options = injected_options(&repo_path, temp.path(), "trusted-auditor-lens-floor");
    let catalog = injected_codex_runtime_catalog(&[BALANCED_PROFILE_MODEL, FRONTIER_PROFILE_MODEL]);
    let mut child_seen = false;
    let mut auditor_seen = false;
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            auditor_seen = true;
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
            assert_eq!(command.model.as_deref(), Some(FRONTIER_PROFILE_MODEL));
            assert_eq!(command.model_provider.as_deref(), Some("openai"));
            assert!(fs::read_to_string(&command.prompt)
                .expect("read resolved auditor prompt")
                .contains("Reasoning effort: xhigh"));
            let argv = crate::external_agent::command_argv(command)
                .into_iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(argv
                .windows(2)
                .any(|arguments| arguments == ["-m", FRONTIER_PROFILE_MODEL]));
            assert!(argv
                .windows(2)
                .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"xhigh\""] }));
            let mut child = injected_child_report(&assignment);
            child.files_changed = vec![PathBuf::from("README.md")];
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
        } else {
            child_seen = true;
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadWrite);
            let argv = crate::external_agent::app_server_command_argv(command)
                .into_iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(argv.windows(2).any(|arguments| {
                arguments[0] == "-c"
                    && arguments[1] == format!("model=\"{BALANCED_PROFILE_MODEL}\"")
            }));
            fs::write(command.cwd.join("README.md"), "trusted lens candidate\n")
                .expect("write trusted lens candidate");
            let mut child = injected_child_report(&assignment);
            child.files_changed = vec![PathBuf::from("README.md")];
            write_injected_json(&command.output_last_message, &child);
        }
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect("run production command path with trusted built-in lens model");

    assert!(child_seen);
    assert!(auditor_seen);
    assert_eq!(
        report
            .role_economics_profile
            .as_ref()
            .map(|profile| profile.model_availability),
        Some(RoleModelAvailability::Available)
    );
}

#[test]
fn known_unavailable_child_fail_closed_reaches_production_core_without_dispatch_or_scratch() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment, 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some(BALANCED_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let run_id = "known-unavailable-child-fail-closed";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL]);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("known-unavailable fail_closed selection must prevent dispatch")
    };

    let error = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect_err("fail_closed selection must reject before artifact reservation");

    assert_eq!(invocations, 0);
    assert!(format!("{error:#}").contains("fallback is fail_closed"));
    let run_root = repo_path
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id);
    assert!(!run_root.exists());
    assert!(!repo_path
        .join(RunArtifactFamily::Supervise.run_root())
        .exists());
    assert!(!repo_path.join(".maco").exists());
}

#[test]
fn local_deterministic_fake_fallback_reaches_shared_supervisor_core_without_external_dispatch() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment, 0);
    for role in [AgentRole::ChildOrchestrator, AgentRole::Auditor] {
        plan.role_models.insert(
            role,
            RoleModelSelection {
                model: Some("codex-only-model".to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::LocalDeterministicFake,
            },
        );
    }
    let mut options = injected_options(&repo_path, temp.path(), "local-fake-fallback-shared-core");
    options.runtime = SupervisorRuntime::Fake;
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("deterministic fake fallback must not invoke the external runner")
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(RuntimeModelCatalog::LocalDeterministicFake),
        &mut runner,
    )
    .expect("run deterministic fake fallback through the shared supervisor core");

    assert_eq!(invocations, 0);
    assert!(!report.success);
    assert!(!report.publishable);
    assert!(!report.accepted);
    assert!(report.rejected);
    assert_eq!(report.status, ReviewStatus::Failed);
    assert_eq!(report.commands_run.len(), 2);
    assert!(report.commands_run.iter().all(|command| {
        command.command.len() == 1
            && command.command[0] == "maco-internal-deterministic-fake"
            && command.status == ReviewStatus::Succeeded
    }));
    assert_eq!(
        report
            .role_economics_profile
            .as_ref()
            .map(|profile| profile.model_availability),
        Some(RoleModelAvailability::Unavailable)
    );
    let child = report
        .orchestrator_reports
        .first()
        .expect("shared core must retain the deterministic child report");
    assert!(!child.accepted);
    assert!(child.rejected);
    assert_eq!(child.status, ReviewStatus::Failed);
    assert!(child.findings.iter().any(|finding| finding
        .message
        .contains("no pre-auditor supervisor candidate binding")));
}

#[test]
fn runtime_model_catalog_preflight_is_typed_persisted_and_short_circuits_assignment_preflight() {
    let (temp, repo_path) = injected_repository();
    let plan = injected_plan(injected_assignment(true), 0);
    let options = injected_options(
        &repo_path,
        temp.path(),
        "model-catalog-failure-before-dispatch",
    );
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("catalog preflight failure must prevent assignment environment preflight")
    };
    let run_id = options.run_id.clone();

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Err(Box::new(EnvironmentFailure::runtime_model_catalog(
            "injected catalog acquisition failure".to_string(),
        ))),
        &mut runner,
    )
    .expect("typed catalog failure must materialize as a terminal supervisor report");

    assert_eq!(invocations, 0);
    assert!(!report.success);
    assert!(!report.publishable);
    assert!(!report.accepted);
    assert!(report.rejected);
    assert_eq!(report.status, ReviewStatus::Failed);
    assert!(report.commands_run.is_empty());
    assert!(report.orchestrator_reports.is_empty());
    let profile = report
        .role_economics_profile
        .as_ref()
        .expect("catalog failure must still emit economics metadata");
    assert_eq!(
        profile.schema_version,
        SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION
    );
    assert_eq!(
        profile.model_catalog_observation,
        RuntimeModelCatalogObservation::ConsultationFailed
    );
    let execution = profile
        .execution
        .as_ref()
        .expect("catalog failure must still emit execution metadata");
    assert_eq!(execution.assignment_count, 1);
    assert_eq!(execution.started_assignment_count, 0);
    assert_eq!(execution.completed_assignment_count, 0);
    assert_eq!(execution.concurrency.achieved_max_concurrent_children, 0);
    assert!(execution.role_bindings.values().all(|binding| {
        binding.observation == RoleBindingObservation::CatalogUnavailable
            && binding.resolved_model.is_none()
            && binding.resolved_reasoning_effort.is_none()
    }));
    assert_eq!(
        execution.usage.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert_eq!(report.role_usage.len(), 5);
    assert_eq!(report.environment_failures.len(), 1);
    assert_eq!(
        report.environment_failures[0].category,
        EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
    );
    assert!(report.environment_failures[0].requirement.is_none());
    assert_eq!(
        report.environment_failures[0].summary,
        "environment preflight reported runtime_model_catalog_unavailable"
    );
    assert!(!report.environment_failures[0].remediation.is_empty());

    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("typed catalog failure must finalize authenticated supervisor artifacts");
    let persisted = read_supervisor_final_report(&reader)
        .expect("read persisted runtime catalog environment failure report");
    assert_eq!(persisted, report);
}

#[test]
fn process_role_usage_aggregation_prices_children_and_auditors() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.model_pricing = BTreeMap::from([
        (
            "planner-model".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 2.0,
                output_usd_per_million_tokens: 8.0,
            },
        ),
        (
            "auditor-model".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 1.0,
                output_usd_per_million_tokens: 4.0,
            },
        ),
    ]);
    let ReviewLensBackendConfig::Model { model, .. } = &mut plan.review_lenses[0].backend else {
        panic!("default supervisor lens must be model-backed");
    };
    *model = "auditor-model".to_string();
    let samples = vec![
        RoleUsageSample {
            role: AgentRole::ChildOrchestrator,
            lens_id: None,
            model: Some("planner-model".to_string()),
            usage: Usage {
                input_tokens: 1_000,
                output_tokens: 200,
                total_tokens: 1_200,
            },
        },
        RoleUsageSample {
            role: AgentRole::ChildOrchestrator,
            lens_id: None,
            model: Some("planner-model".to_string()),
            usage: Usage {
                input_tokens: 500,
                output_tokens: 100,
                total_tokens: 600,
            },
        },
        RoleUsageSample {
            role: AgentRole::Auditor,
            lens_id: Some("parent-acceptance".to_string()),
            model: Some("auditor-model".to_string()),
            usage: Usage {
                input_tokens: 500,
                output_tokens: 100,
                total_tokens: 600,
            },
        },
        RoleUsageSample {
            role: AgentRole::Auditor,
            lens_id: Some("parent-acceptance".to_string()),
            model: Some("auditor-model".to_string()),
            usage: Usage {
                input_tokens: 250,
                output_tokens: 50,
                total_tokens: 300,
            },
        },
    ];
    let RoleUsageAggregation {
        reports: by_role,
        lens_reports,
        total_usage: total,
        total_cost_usd: cost,
        lens_total_usage,
        lens_total_cost_usd,
    } = role_usage_report(&plan, samples.clone()).expect("aggregate process usage");
    assert_eq!(
        by_role[&AgentRole::ChildOrchestrator].usage,
        Some(Usage {
            input_tokens: 1_500,
            output_tokens: 300,
            total_tokens: 1_800,
        })
    );
    assert_eq!(
        total,
        Some(Usage {
            input_tokens: 2_250,
            output_tokens: 450,
            total_tokens: 2_700,
        })
    );
    let expected_cost = 0.0054 + 0.00135;
    assert!((cost.expect("fully priced total") - expected_cost).abs() < 1e-12);
    assert_eq!(
        by_role[&AgentRole::Worker].observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(by_role[&AgentRole::Worker].usage.is_none());
    assert!(by_role[&AgentRole::Worker]
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("runtime-side role-tagged usage reporting")));
    assert_eq!(
        by_role[&AgentRole::GateClassifier].observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(by_role[&AgentRole::GateClassifier].usage.is_none());
    assert!(by_role[&AgentRole::GateClassifier]
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("deterministic local broker")));
    let serialized_worker =
        serde_json::to_value(&by_role[&AgentRole::Worker]).expect("serialize worker marker");
    assert_eq!(serialized_worker["observation"], "not_process_observable");
    assert!(serialized_worker.get("usage").is_none());
    assert!(serialized_worker["unavailable_reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("runtime-side role-tagged usage reporting")));
    assert_eq!(
        by_role[&AgentRole::Supervisor].observation,
        RoleUsageObservation::SupervisorAggregate
    );
    assert_eq!(by_role[&AgentRole::Supervisor].usage, total);
    assert_eq!(lens_reports.len(), 1);
    assert_eq!(lens_reports[0].lens_id, "parent-acceptance");
    assert_eq!(
        lens_reports[0].observation,
        RoleUsageObservation::ProcessObserved
    );
    assert_eq!(
        lens_reports[0].usage,
        Some(Usage {
            input_tokens: 750,
            output_tokens: 150,
            total_tokens: 900,
        })
    );
    assert_eq!(lens_total_usage, lens_reports[0].usage);
    assert_eq!(lens_total_cost_usd, lens_reports[0].cost_usd);

    plan.model_pricing.clear();
    let RoleUsageAggregation {
        reports: unpriced,
        lens_reports: unpriced_lenses,
        total_usage: unpriced_total,
        total_cost_usd: unpriced_cost,
        lens_total_usage: unpriced_lens_total,
        lens_total_cost_usd: unpriced_lens_cost,
    } = role_usage_report(&plan, samples).expect("aggregate unpriced process usage");
    assert_eq!(unpriced_total, total);
    assert!(unpriced.values().all(|report| report.cost_usd.is_none()));
    assert!(unpriced_cost.is_none());
    assert_eq!(unpriced_lens_total, lens_total_usage);
    assert!(unpriced_lens_cost.is_none());
    assert!(unpriced_lenses
        .iter()
        .all(|report| report.cost_usd.is_none()));

    let mut incomplete = by_role;
    assert!(finalize_supervisor_cost(false, &mut incomplete, cost).is_none());
    assert!(incomplete[&AgentRole::Supervisor].cost_usd.is_none());
    assert!(incomplete[&AgentRole::Supervisor]
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("at least one MACO-launched process")));
}

#[test]
fn empty_process_usage_has_no_synthetic_supervisor_or_worker_totals() {
    let plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    let RoleUsageAggregation {
        reports: by_role,
        lens_reports,
        total_usage: total,
        total_cost_usd: cost,
        lens_total_usage,
        lens_total_cost_usd,
    } = role_usage_report(&plan, Vec::new()).expect("empty process aggregation");
    assert!(total.is_none());
    assert!(cost.is_none());
    assert!(by_role[&AgentRole::Supervisor].usage.is_none());
    assert!(by_role[&AgentRole::Supervisor].cost_usd.is_none());
    assert!(by_role[&AgentRole::Worker].usage.is_none());
    assert_eq!(
        by_role[&AgentRole::Worker].observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(lens_total_usage.is_none());
    assert!(lens_total_cost_usd.is_none());
    assert_eq!(lens_reports.len(), 1);
    assert_eq!(
        lens_reports[0].observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(lens_reports[0]
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("not heuristically allocated")));
}

#[test]
fn supervisor_derives_review_coverage_from_assignment_and_run_report() {
    let assignment = injected_assignment(true);
    let mut child = injected_child_report(&assignment);
    child.files_changed = vec![PathBuf::from("docs/runtime-evidence.md")];
    let required = supervisor_review_coverage_requirement(&assignment, &child);
    assert_eq!(required.worker_ids, vec!["worker-a"]);
    assert_eq!(
        required.paths,
        vec![
            PathBuf::from("README.md"),
            PathBuf::from("docs/runtime-evidence.md")
        ]
    );
}

#[test]
fn stacked_review_lenses_execute_every_configured_boundary_and_aggregate() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.review_lenses = vec![
        ReviewLensConfig {
            id: "diff-security".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "provider-alpha".to_string(),
                model: FRONTIER_PROFILE_MODEL.to_string(),
                reasoning_effort: Some("high".to_string()),
            },
            information_scope: ReviewInformationScope::DiffOnly,
        },
        ReviewLensConfig {
            id: "report-consistency".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "provider-beta".to_string(),
                model: FRONTIER_PROFILE_MODEL.to_string(),
                reasoning_effort: Some("xhigh".to_string()),
            },
            information_scope: ReviewInformationScope::OutputReportOnly,
        },
    ];
    plan.review_aggregation_policy = ReviewAggregationPolicy::AllMustAccept;
    plan.model_pricing = BTreeMap::from([(
        FRONTIER_PROFILE_MODEL.to_string(),
        ModelPricing {
            input_usd_per_million_tokens: 2.0,
            output_usd_per_million_tokens: 4.0,
        },
    )]);
    let options = injected_options(&repo_path, temp.path(), "stacked-review-lenses-execute");
    let run_id = options.run_id.clone();
    let catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL]);
    let mut lens_commands = Vec::new();
    let mut lens_prompts = Vec::new();
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .expect("UTF-8 output name");
        if name.contains("review-auditor") {
            let mut child = injected_child_report(&assignment);
            child.files_changed = vec![PathBuf::from("README.md")];
            let mut audit = injected_auditor_report(&assignment, &child);
            audit.id = name
                .strip_suffix(".json")
                .expect("auditor JSON suffix")
                .to_string();
            write_injected_json(&command.output_last_message, &audit);
            lens_commands.push(command.clone());
            lens_prompts.push(fs::read_to_string(&command.prompt).expect("read lens prompt"));
            if name.contains("lens-0") {
                write_injected_usage(command, 100, 20);
            } else {
                write_injected_usage(command, 200, 40);
            }
        } else {
            fs::write(command.cwd.join("README.md"), "stacked lens candidate\n")
                .expect("write stacked lens candidate");
            let mut child = injected_child_report(&assignment);
            child.files_changed = vec![PathBuf::from("README.md")];
            write_injected_json(&command.output_last_message, &child);
            write_injected_usage(command, 50, 10);
        }
        injected_verified_run(command)
    };
    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect("run stacked review lenses");

    assert_eq!(lens_commands.len(), 2);
    assert_ne!(lens_commands[0].cwd, lens_commands[1].cwd);
    assert_eq!(
        lens_commands[0].model_provider.as_deref(),
        Some("provider-alpha")
    );
    assert_eq!(
        lens_commands[0].model.as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(lens_commands[0].reasoning_effort.as_deref(), Some("xhigh"));
    assert_eq!(
        lens_commands[1].model_provider.as_deref(),
        Some("provider-beta")
    );
    assert_eq!(
        lens_commands[1].model.as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(lens_commands[1].reasoning_effort.as_deref(), Some("xhigh"));
    assert!(lens_prompts[0].contains("\"scope\":\"diff_only\""));
    assert!(!lens_prompts[0].contains("\"scope\":\"output_report_only\""));
    assert!(lens_prompts[1].contains("\"scope\":\"output_report_only\""));
    assert!(!lens_prompts[1].contains("\"scope\":\"diff_only\""));
    let child = &report.orchestrator_reports[0];
    let aggregate = child
        .review_lens_aggregate
        .as_ref()
        .expect("parent-computed lens aggregate");
    assert_eq!(
        aggregate.authority(),
        ReviewLensAggregateAuthority::ParentComputed
    );
    assert_eq!(aggregate.decision, ReviewAggregationDecision::Accept);
    assert_eq!(aggregate.lens_verdicts.len(), 2);
    assert_eq!(child.audit_reports.len(), 2);
    assert!(report.usage_complete);
    assert_eq!(report.review_lens_usage.len(), 2);
    assert!(report.review_lens_usage.iter().all(|usage| {
        usage.observation == RoleUsageObservation::ProcessObserved && usage.usage.is_some()
    }));
    assert_eq!(
        report.review_lens_total_usage,
        Some(Usage {
            input_tokens: 300,
            output_tokens: 60,
            total_tokens: 360,
        })
    );
    assert!(report
        .review_lens_total_cost_usd
        .is_some_and(|cost| (cost - 0.00084).abs() < 1e-12));
    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("open stacked-lens artifacts");
    let events = read_finalized_orchestration_events(&reader);
    let aggregate_event = events
        .iter()
        .find(|event| {
            event.kind == OrchestrationEventKind::Gate
                && event.payload.get("review_lens_aggregate").is_some()
        })
        .expect("strict aggregate gate event");
    assert_eq!(
        aggregate_event.payload["review_lens_aggregate"]["lens_verdicts"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    for audit in &child.audit_reports {
        assert!(events.iter().any(|event| {
            event.node == audit.id
                && event.kind == OrchestrationEventKind::Accept
                && event.payload["status"] == "succeeded"
        }));
    }
    let reloaded: SupervisorFinalReport = serde_json::from_value(
        serde_json::to_value(&report).expect("serialize stacked final report"),
    )
    .expect("deserialize stacked final report");
    assert_eq!(
        reloaded.orchestrator_reports[0]
            .review_lens_aggregate
            .as_ref()
            .map(ReviewLensAggregate::authority),
        Some(ReviewLensAggregateAuthority::DeserializedNonAuthoritative)
    );
}

#[test]
fn unknown_advertised_lens_model_rejects_before_dispatch_or_artifacts() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment, 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some(BALANCED_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let ReviewLensBackendConfig::Model { model, .. } = &mut plan.review_lenses[0].backend else {
        panic!("default supervisor lens must be model-backed");
    };
    *model = "unknown-advertised-lens-model".to_string();
    let run_id = "unknown-advertised-lens-model";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let catalog = injected_codex_runtime_catalog(&[
        FRONTIER_PROFILE_MODEL,
        BALANCED_PROFILE_MODEL,
        "unknown-advertised-lens-model",
    ]);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("unknown advertised lens model must prevent dispatch")
    };
    let error = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect_err("unknown advertised lens model must fail static policy");

    assert_eq!(invocations, 0);
    assert!(format!("{error:#}").contains("no trusted built-in capability policy"));
    assert!(!repo_path
        .join(RunArtifactFamily::Supervise.run_root())
        .exists());
    assert!(!repo_path.join(".maco").exists());
}

#[cfg(unix)]
#[test]
fn supervisor_input_loader_accepts_direct_regular_files_and_refuses_unsafe_inputs() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    Repository::init(&repo).expect("initialize repository");
    fs::write(repo.join("README.md"), "# test\n").expect("write readme");

    let plain = temp.path().join("task.txt");
    fs::write(&plain, "Update README.md.\n").expect("write plain task");
    let loaded =
        supervisor_plan_and_consultant_from_task_file(&repo, &plain).expect("load plain task");
    assert_eq!(loaded.plan.task, "Update README.md.\n");
    assert_eq!(
        loaded
            .plan
            .assignments
            .iter()
            .map(|assignment| assignment.id.as_str())
            .collect::<Vec<_>>(),
        vec!["assignment-001-planning", "assignment-001"]
    );
    assert_eq!(
        loaded.plan.assignments[0].assigned_paths,
        vec![PathBuf::from("README.md")]
    );
    assert!(loaded.plan.assignments[0].worker_assignments.is_empty());
    assert_eq!(
        loaded.plan.assignments[1].assigned_paths,
        vec![PathBuf::from("README.md")]
    );
    assert_eq!(loaded.plan.assignments[1].worker_assignments.len(), 1);
    assert_eq!(
        loaded.plan_metadata.assignment_schedule,
        vec![
            AssignmentScheduleEntry {
                assignment_id: "assignment-001-planning".to_string(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: "assignment-001".to_string(),
                parent_assignment_id: Some("assignment-001-planning".to_string()),
                depth: 3,
                flattened_index: 1,
            },
        ]
    );

    let plan = temp.path().join("plan.json");
    fs::write(&plan, bounded_loader_plan_json()).expect("write plan");
    assert_eq!(
        load_supervisor_plan_file(&plan)
            .expect("load direct regular plan")
            .task,
        "bounded loader"
    );

    let invalid_utf8 = temp.path().join("invalid.json");
    fs::write(&invalid_utf8, [0xff, 0xfe]).expect("write invalid utf8");
    assert!(load_supervisor_plan_file(&invalid_utf8)
        .expect_err("invalid UTF-8 must fail")
        .to_string()
        .contains("not valid UTF-8"));

    let oversized = temp.path().join("oversized.json");
    fs::write(
        &oversized,
        vec![b' '; usize::try_from(MAX_SUPERVISOR_INPUT_BYTES).unwrap_or(usize::MAX) + 1],
    )
    .expect("write oversized input");
    assert!(load_supervisor_plan_file(&oversized).is_err());

    let symlinked = temp.path().join("symlinked.json");
    symlink(&plan, &symlinked).expect("create plan symlink");
    assert!(load_supervisor_plan_file(&symlinked).is_err());

    let hardlinked = temp.path().join("hardlinked.json");
    fs::hard_link(&plan, &hardlinked).expect("create plan hardlink");
    assert!(load_supervisor_plan_file(&hardlinked).is_err());

    let fifo = temp.path().join("plan.fifo");
    let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    assert!(load_supervisor_plan_file(&fifo).is_err());
}
