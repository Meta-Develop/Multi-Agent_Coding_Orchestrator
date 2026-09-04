use super::*;

const LICENSED_INTERFACE: &str = "crate::api::new_name";
const LICENSED_SIGNATURE: &str =
    "error[E0425]: cannot find function crate::api::new_name in dependent client";

struct LicensedScenario {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    run_id: RunId,
    report: SupervisorFinalReport,
}

fn licensed_assignment() -> OrchestratorAssignment {
    let mut assignment = injected_assignment(false);
    assignment.licensed_breakage = Some(LicensedBreakageDeclaration {
        migration_rationale:
            "Rename callers to crate::api::new_name before dispatching the dependent update"
                .to_string(),
        dependents: vec![LicensedBreakageDependentScope {
            dependent_id: "client-a".to_string(),
            paths: vec![PathBuf::from("src/client.rs")],
            interfaces: vec![LICENSED_INTERFACE.to_string()],
        }],
    });
    assignment
}

fn dependent_failure_child(
    assignment: &OrchestratorAssignment,
    failure_path: &str,
) -> OrchestratorReviewReport {
    let mut child = injected_child_report(assignment);
    child.files_changed = vec![PathBuf::from("README.md")];
    child.validation_results = vec![ValidationResult {
        name: "client-a".to_string(),
        status: ReviewStatus::Failed,
        command: vec![
            "cargo".to_string(),
            "check".to_string(),
            "-p".to_string(),
            "client-a".to_string(),
        ],
        message: Some(LICENSED_SIGNATURE.to_string()),
    }];
    child.findings = vec![Finding {
        severity: FindingSeverity::Error,
        message: LICENSED_SIGNATURE.to_string(),
        paths: vec![PathBuf::from(failure_path)],
    }];
    child.accepted = false;
    child.rejected = true;
    child.status = ReviewStatus::Failed;
    child.remaining_risk = "client-a requires the declared migration".to_string();
    child.next_safe_action = "generate the scoped dependent update".to_string();
    child
}

fn worker_dependent_failure_child(assignment: &OrchestratorAssignment) -> OrchestratorReviewReport {
    let mut child = injected_child_report(assignment);
    child.files_changed = vec![PathBuf::from("README.md")];
    let worker = child.worker_reports.first_mut().expect("worker fixture");
    worker.files_changed = vec![PathBuf::from("README.md")];
    worker.validation_results = vec![ValidationResult {
        name: "client-a".to_string(),
        status: ReviewStatus::Failed,
        command: vec![
            "cargo".to_string(),
            "check".to_string(),
            "-p".to_string(),
            "client-a".to_string(),
        ],
        message: Some(LICENSED_SIGNATURE.to_string()),
    }];
    worker.findings = vec![Finding {
        severity: FindingSeverity::Error,
        message: LICENSED_SIGNATURE.to_string(),
        paths: vec![PathBuf::from("src/client.rs")],
    }];
    worker.accepted = false;
    worker.rejected = true;
    worker.status = ReviewStatus::Failed;
    child.accepted = false;
    child.rejected = true;
    child.status = ReviewStatus::Failed;

    let declaration_sha256 = licensed_breakage_declaration_sha256(
        assignment
            .licensed_breakage
            .as_ref()
            .expect("licensed worker fixture declaration"),
    )
    .expect("hash licensed worker fixture declaration");
    let mut child_auditor = licensed_auditor_report(assignment, Some(&declaration_sha256));
    child_auditor.id = "child-side-auditor".to_string();
    child_auditor.reviewed_worker_ids = vec![worker.id.clone()];
    child.audit_reports = vec![child_auditor];
    child
}

fn licensed_auditor_report(
    assignment: &OrchestratorAssignment,
    declaration_sha256: Option<&str>,
) -> AuditorReport {
    let mut validations = vec![ValidationResult {
        name: "injected auditor validation".to_string(),
        status: ReviewStatus::Succeeded,
        command: Vec::new(),
        message: None,
    }];
    if let Some(declaration_sha256) = declaration_sha256 {
        validations.push(ValidationResult {
            name: LICENSED_BREAKAGE_AUDIT_VALIDATION_NAME.to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: Some(declaration_sha256.to_string()),
        });
    }
    AuditorReport {
        id: review_lens_auditor_id(assignment, 0),
        role: AgentRole::Auditor,
        reviewed_worker_ids: if assignment.worker_assignments.is_empty() {
            vec![assignment.id.clone()]
        } else {
            assignment
                .worker_assignments
                .iter()
                .map(|worker| worker.id.clone())
                .collect()
        },
        reviewed_paths: assignment.assigned_paths.clone(),
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        validation_results: validations,
        findings: Vec::new(),
        rejection_kind: None,
        no_further_delegation: Some(true),
        read_only: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "the declared dependent update remains to be dispatched".to_string(),
        next_safe_action: "dispatch the journaled follow-up through a new plan".to_string(),
    }
}

fn licensed_follow_up_assignment() -> OrchestratorAssignment {
    OrchestratorAssignment {
        id: "child-a-licensed-update-01".to_string(),
        phase: AssignmentPhase::Execution,
        runtime: None,
        role: AgentRole::ChildOrchestrator,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from("src/client.rs")],
        semantic_symbols: vec![LICENSED_INTERFACE.to_string()],
        semantic_modules: Vec::new(),
        task: Some("apply the generated licensed dependent update".to_string()),
        worker_assignments: Vec::new(),
        environment_requirements: Vec::new(),
        licensed_breakage: None,
        notes: None,
    }
}

#[cfg(target_os = "linux")]
fn secure_machine_global_retention(
    root: &Path,
    correlation_id: &str,
) -> crate::machine_global::MachineGlobalRetentionBinding {
    use std::os::unix::fs::PermissionsExt;

    let runtime_root = crate::process_runner::trusted_linux_runtime_root()
        .expect("resolve trusted runtime root for generated follow-up cleanup");
    let state_root = root.join(format!("{correlation_id}-machine-global-state"));
    fs::create_dir(&state_root).expect("create generated follow-up machine-global state");
    fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
        .expect("secure generated follow-up machine-global state");
    let config = root.join(format!("{correlation_id}-machine-global.json"));
    fs::write(
        &config,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "state_root": state_root,
            "roots": [{
                "id": "runtime",
                "path": runtime_root,
                "protected_paths": [],
                "quarantine_grace_seconds": 60
            }]
        }))
        .expect("serialize generated follow-up machine-global config"),
    )
    .expect("write generated follow-up machine-global config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
        .expect("secure generated follow-up machine-global config");
    crate::machine_global::MachineGlobalRetentionBinding {
        config,
        root_id: "runtime".to_string(),
        owner: "maco-supervise-test".to_string(),
        correction_correlation_id: correlation_id.to_string(),
    }
}

fn run_licensed_scenario(
    assignment: OrchestratorAssignment,
    mut child: OrchestratorReviewReport,
    auditor_accepts_license: bool,
    run_name: &str,
) -> LicensedScenario {
    let (temp, repo) = injected_repository();
    let plan = injected_plan(assignment.clone(), 0);
    let run_id = RunId::new(run_name).expect("valid licensed scenario run id");
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: temp.path().join(format!("{run_name}.json")),
        run_id: run_id.clone(),
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: true,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(injected_machine_global_retention(temp.path())),
    };
    let declaration_sha256 = assignment
        .licensed_breakage
        .as_ref()
        .map(licensed_breakage_declaration_sha256)
        .transpose()
        .expect("hash licensed declaration");
    let mut child_dispatched = false;
    let mut runner = |command: &ExternalAgentCommand| {
        let output_name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if output_name.contains("review-auditor") {
            let marker = auditor_accepts_license
                .then_some(declaration_sha256.as_deref())
                .flatten();
            write_injected_json(
                &command.output_last_message,
                &licensed_auditor_report(&assignment, marker),
            );
        } else {
            assert!(
                !child_dispatched,
                "licensed scenario unexpectedly retried child"
            );
            child_dispatched = true;
            fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                .expect("write breaking candidate");
            child.id = assignment.id.clone();
            write_injected_json(&command.output_last_message, &child);
        }
        injected_verified_run(command)
    };
    let report = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("run licensed breakage scenario");
    LicensedScenario {
        _temp: temp,
        repo,
        run_id,
        report,
    }
}

#[test]
fn declared_scoped_breakage_passes_and_journals_dispatchable_follow_up_plan() {
    skip_without_containment!();
    let assignment = licensed_assignment();
    let child = dependent_failure_child(&assignment, "src/client.rs");
    let scenario = run_licensed_scenario(assignment, child, true, "licensed-breakage-e2e");

    assert!(scenario.report.success, "{:#?}", scenario.report.findings);
    assert_eq!(scenario.report.generated_follow_up_tasks.len(), 1);
    let task = &scenario.report.generated_follow_up_tasks[0];
    assert_eq!(task.breaking_assignment_id, "child-a");
    assert_eq!(task.breaking_change.agent_id, "child-a");
    assert!(!task.breaking_change.diff_oid.is_empty());
    let follow_up_assignment = task
        .supervisor_plan
        .assignments
        .first()
        .expect("generated plan assignment");
    assert_eq!(
        follow_up_assignment.assigned_paths,
        vec![PathBuf::from("src/client.rs")]
    );
    assert_eq!(
        follow_up_assignment.semantic_symbols,
        vec![LICENSED_INTERFACE]
    );
    assert!(follow_up_assignment.licensed_breakage.is_none());
    assert_eq!(task.cascade_depth, LICENSED_BREAKAGE_CASCADE_DEPTH);
    assert_eq!(
        task.dispatch_status,
        GeneratedFollowUpDispatchStatus::DeferredForPlannedRun
    );
    assert_eq!(
        scenario.report.autonomy_kpis.licensed_dependent_failures,
        Some(1)
    );
    assert_eq!(
        scenario.report.autonomy_kpis.generated_follow_up_tasks,
        Some(1)
    );
    assert_eq!(scenario.report.autonomy_kpis.denials, Some(0));
    assert_eq!(scenario.report.autonomy_kpis.self_corrections, Some(0));
    assert_eq!(scenario.report.autonomy_kpis.actions_reviewed, Some(0));
    assert_eq!(
        scenario.report.autonomy_kpis.population,
        AutonomyKpiPopulation::ReviewedGateActions
    );
    assert!(scenario.report.gate_denials.is_empty());
    assert_eq!(
        scenario.report.orchestrator_reports[0].validation_results[0].status,
        ReviewStatus::Failed
    );
    assert_eq!(
        scenario.report.orchestrator_reports[0].status,
        ReviewStatus::Succeeded
    );
    let review = scenario.report.orchestrator_reports[0]
        .licensed_breakage_review
        .as_ref()
        .expect("supervisor-owned licensed review");
    assert_eq!(review.failures.len(), 1);
    let parent_auditors = scenario.report.orchestrator_reports[0]
        .audit_reports
        .iter()
        .filter(|auditor| is_parent_auditor_id(&licensed_assignment(), &auditor.id))
        .collect::<Vec<_>>();
    assert!(!parent_auditors.is_empty());
    assert!(parent_auditors.iter().all(|auditor| {
        auditor.validation_results.iter().any(|validation| {
            validation.name == LICENSED_BREAKAGE_AUDIT_VALIDATION_NAME
                && validation.status == ReviewStatus::Succeeded
                && validation.message.as_deref() == Some(review.declaration_sha256.as_str())
        })
    }));

    assert_eq!(task.supervisor_plan.assignments.len(), 1);
    assert_eq!(task.supervisor_plan.max_child_assignments, 1);
    assert_eq!(
        task.supervisor_plan.review_lenses,
        default_supervisor_review_lenses()
    );
    assert_eq!(
        task.supervisor_plan.review_aggregation_policy,
        ReviewAggregationPolicy::AllMustAccept
    );
    assert_eq!(task.supervisor_plan.run_budget.limits.hard_tokens, Some(2));
    assert_eq!(
        task.supervisor_plan.generated_follow_up.operator_defaults,
        generated_follow_up_operator_defaults()
    );
    let follow_up_plan_path = scenario._temp.path().join("generated-follow-up-plan.json");
    fs::write(
        &follow_up_plan_path,
        serde_json::to_vec_pretty(&task.supervisor_plan).expect("serialize generated plan"),
    )
    .expect("write generated plan directly");
    let loaded = load_supervisor_plan_file_with_consultant(&follow_up_plan_path)
        .expect("real supervise plan loader accepts generated plan without injected metadata");
    assert_eq!(loaded.plan, task.supervisor_plan.ordinary_plan());
    assert_eq!(loaded.consultant, task.supervisor_plan.consultant);
    assert_eq!(
        loaded.plan_metadata.assignment_schedule,
        task.supervisor_plan.assignment_schedule
    );
    assert_eq!(
        loaded.plan_metadata.run_budget,
        task.supervisor_plan.run_budget
    );
    assert_eq!(
        loaded.plan_metadata.generated_follow_up.as_ref(),
        Some(&task.supervisor_plan.generated_follow_up)
    );

    let reader = ArtifactRunReader::open(
        &scenario.repo,
        RunArtifactFamily::Supervise,
        &scenario.run_id,
    )
    .expect("open licensed run artifacts");
    let follow_up_events = read_finalized_orchestration_events(&reader)
        .into_iter()
        .filter(|event| event.payload.get("licensed_breakage_follow_up").is_some())
        .collect::<Vec<_>>();
    assert_eq!(follow_up_events.len(), 1);
    assert_eq!(follow_up_events[0].node, follow_up_assignment.id);
    assert_eq!(follow_up_events[0].parent.as_deref(), Some("child-a"));
    let journaled_task = serde_json::from_value::<GeneratedFollowUpTaskRecord>(
        follow_up_events[0].payload["licensed_breakage_follow_up"].clone(),
    )
    .expect("typed journaled follow-up task");
    assert_eq!(&journaled_task, task);

    let collected = collect_supervisor_run(&scenario.repo, scenario.run_id.clone())
        .expect("collect finalized licensed run");
    assert_eq!(
        collected.generated_follow_up_tasks,
        scenario.report.generated_follow_up_tasks
    );
    assert!(collected
        .remaining_risk
        .contains("separate cascade outcome determines whether dispatch occurred"));
    assert!(supervisor_final_report_schema_value()["properties"]
        .get("generated_follow_up_tasks")
        .is_some());
    assert!(orchestrator_report_schema_value()["properties"]
        .get("licensed_breakage_review")
        .is_some());
}

#[test]
fn generated_follow_up_plan_inherits_gate_context_and_closes_budget() {
    let assignment = licensed_assignment();
    let declaration = assignment.licensed_breakage.as_ref().expect("declaration");
    let review = LicensedBreakageReview {
        declaration_sha256: licensed_breakage_declaration_sha256(declaration)
            .expect("hash declaration"),
        migration_rationale: declaration.migration_rationale.clone(),
        failures: vec![LicensedDependentFailure {
            dependent_id: "client-a".to_string(),
            validation_name: "client-a".to_string(),
            failure_signature: LICENSED_SIGNATURE.to_string(),
            paths: vec![PathBuf::from("src/client.rs")],
            interfaces: vec![LICENSED_INTERFACE.to_string()],
        }],
    };
    let mut report = injected_child_report(&assignment);
    report.licensed_breakage_review = Some(review);
    let mut source_plan = injected_plan(assignment.clone(), 1);
    source_plan.max_depth = 4;
    source_plan.max_child_assignments = 5;
    source_plan.max_gate_corrections = 2;
    source_plan.child_timeout_seconds = 47;
    source_plan.semantic_coordination = SemanticCoordinationMode::Block;
    let mut second_lens = source_plan.review_lenses[0].clone();
    second_lens.id = "second-acceptance".to_string();
    source_plan.review_lenses.push(second_lens);
    source_plan.review_aggregation_policy =
        ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts: 2 };
    inject_priced_process_roles(&mut source_plan, "licensed-follow-up-model", 3.25);
    let source_consultant = SupervisorConsultantPlan {
        enabled: true,
        runtime: "codex".to_string(),
        max_consultations: 2,
    };
    let mut source_budget =
        injected_run_budget(Some(500), Some(1_000), Some(25.0), Some(30.0), 7, 11);
    source_budget
        .role_token_reservations
        .insert(AgentRole::Worker, 13);
    source_budget
        .role_token_reservations
        .insert(AgentRole::GateClassifier, 17);

    let tasks = generated_licensed_follow_up_tasks(
        &source_plan,
        &source_consultant,
        &source_budget,
        &assignment,
        &report,
        &CandidateValidationBinding {
            version: 1,
            agent_id: assignment.id.clone(),
            primary_head: None,
            agent_head: None,
            merge_base: None,
            diff_oid: "2222222222222222222222222222222222222222".to_string(),
        },
    )
    .expect("generate context-derived follow-up plan");
    let generated = &tasks[0].supervisor_plan;

    assert_eq!(generated.max_depth, source_plan.max_depth);
    // The generated schedule contains one assignment, so its capacity is
    // deliberately narrowed instead of copying unused source capacity.
    assert_eq!(generated.max_child_assignments, 1);
    assert_eq!(generated.max_child_retries, 1);
    assert_eq!(generated.max_gate_corrections, 2);
    assert_eq!(
        generated.child_timeout_seconds,
        source_plan.child_timeout_seconds
    );
    assert_eq!(
        generated.semantic_coordination,
        source_plan.semantic_coordination
    );
    assert_eq!(generated.role_models, source_plan.role_models);
    assert_eq!(generated.model_pricing, source_plan.model_pricing);
    assert_eq!(generated.review_lenses, source_plan.review_lenses);
    assert_eq!(
        generated.review_aggregation_policy,
        source_plan.review_aggregation_policy
    );
    assert_eq!(generated.consultant, source_consultant);
    assert_eq!(
        generated.run_budget.role_token_reservations,
        BTreeMap::from([(AgentRole::ChildOrchestrator, 7), (AgentRole::Auditor, 11),])
    );
    assert!(!generated
        .run_budget
        .role_token_reservations
        .contains_key(&AgentRole::Worker));
    assert!(!generated
        .run_budget
        .role_token_reservations
        .contains_key(&AgentRole::GateClassifier));
    // Four maximum child attempts plus two lenses per attempt:
    // 4 * 7 child tokens + 8 * 11 auditor tokens = 116.
    assert_eq!(generated.run_budget.limits.soft_tokens, Some(116));
    assert_eq!(generated.run_budget.limits.hard_tokens, Some(116));
    assert_eq!(generated.run_budget.limits.soft_cost_usd, Some(25.0));
    assert_eq!(generated.run_budget.limits.hard_cost_usd, Some(30.0));

    let generated_document =
        serde_json::to_string(generated).expect("serialize generated follow-up plan");
    assert!(generated_document.contains("\"soft_cost_usd\":25.0"));
    assert!(generated_document.contains("\"hard_cost_usd\":30.0"));
    let loaded = parse_supervisor_plan_with_consultant(&generated_document)
        .expect("real plan loader accepts generated cost ceilings");
    assert_eq!(loaded.plan.max_depth, source_plan.max_depth);
    assert_eq!(
        loaded.plan.child_timeout_seconds,
        source_plan.child_timeout_seconds
    );
    assert_eq!(
        loaded.plan.semantic_coordination,
        source_plan.semantic_coordination
    );
    assert_eq!(loaded.plan.role_models, source_plan.role_models);
    assert_eq!(loaded.plan.model_pricing, source_plan.model_pricing);
    assert_eq!(
        loaded.plan_metadata.run_budget.limits.soft_cost_usd,
        Some(25.0)
    );
    assert_eq!(
        loaded.plan_metadata.run_budget.limits.hard_cost_usd,
        Some(30.0)
    );
}

#[test]
fn generated_follow_up_real_loader_rejects_stripped_required_section() {
    skip_without_containment!();
    let assignment = licensed_assignment();
    let child = dependent_failure_child(&assignment, "src/client.rs");
    let scenario = run_licensed_scenario(
        assignment,
        child,
        true,
        "licensed-breakage-plan-section-neuter",
    );
    let task = scenario
        .report
        .generated_follow_up_tasks
        .first()
        .expect("generated follow-up task");
    let mut document =
        serde_json::to_value(&task.supervisor_plan).expect("serialize generated plan value");
    document
        .as_object_mut()
        .expect("generated plan object")
        .remove("run_budget")
        .expect("generated run_budget section");
    let neutered_path = scenario._temp.path().join("neutered-follow-up-plan.json");
    fs::write(
        &neutered_path,
        serde_json::to_vec_pretty(&document).expect("serialize neutered plan"),
    )
    .expect("write neutered plan");

    let error = load_supervisor_plan_file_with_consultant(&neutered_path)
        .expect_err("real supervise plan loader must reject a stripped required section");
    assert!(
        format!("{error:#}")
            .contains("generated follow-up supervisor plan requires explicit 'run_budget' section"),
        "unexpected loader refusal: {error:#}"
    );
}

#[test]
fn licensed_worker_failure_remains_subject_to_child_and_parent_auditor_gates() {
    skip_without_containment!();
    let mut assignment = licensed_assignment();
    assignment.worker_assignments = vec![WorkerAssignment {
        id: "worker-a".to_string(),
        role: AgentRole::Worker,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from("README.md")],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: Some("implement the breaking change".to_string()),
        environment_requirements: Vec::new(),
        report_path: None,
    }];
    let child = worker_dependent_failure_child(&assignment);
    let scenario = run_licensed_scenario(assignment, child, true, "licensed-worker-breakage-gates");

    assert!(scenario.report.success, "{:#?}", scenario.report.findings);
    assert_eq!(scenario.report.generated_follow_up_tasks.len(), 1);
    let report = &scenario.report.orchestrator_reports[0];
    assert_eq!(report.worker_reports[0].status, ReviewStatus::Succeeded);
    assert_eq!(
        report.worker_reports[0].validation_results[0].status,
        ReviewStatus::Failed
    );
    assert!(report
        .review_lens_aggregate
        .as_ref()
        .is_some_and(|aggregate| { aggregate.decision == ReviewAggregationDecision::Accept }));
}

#[test]
fn undeclared_breakage_keeps_validation_gate_failure_and_generates_nothing() {
    let assignment = injected_assignment(false);
    let child = dependent_failure_child(&assignment, "src/client.rs");
    let scenario = run_licensed_scenario(assignment, child, false, "unlicensed-breakage-e2e");

    assert!(!scenario.report.success);
    assert!(scenario.report.generated_follow_up_tasks.is_empty());
    assert!(scenario
        .report
        .gate_denials
        .iter()
        .any(|denial| matches!(denial.reason, GateDenialReason::ValidationRepair { .. })));
}

#[test]
fn undeclared_attribution_guard_is_directly_fail_capable() {
    let assignment = injected_assignment(false);
    let mut report = dependent_failure_child(&assignment, "src/client.rs");

    prepare_licensed_breakage_review(&assignment, &mut report);

    assert_eq!(report.status, ReviewStatus::Failed);
    assert!(report.rejected);
    assert!(!report.accepted);
    assert!(report.licensed_breakage_review.is_none());
}

#[test]
fn failure_outside_declared_path_scope_is_not_licensed() {
    let assignment = licensed_assignment();
    let child = dependent_failure_child(&assignment, "src/outside.rs");
    let scenario = run_licensed_scenario(assignment, child, true, "licensed-scope-enforcement");

    assert!(!scenario.report.success);
    assert!(scenario.report.generated_follow_up_tasks.is_empty());
    assert!(scenario
        .report
        .gate_denials
        .iter()
        .any(|denial| matches!(denial.reason, GateDenialReason::ValidationRepair { .. })));
    assert!(scenario.report.orchestrator_reports[0]
        .licensed_breakage_review
        .as_ref()
        .is_some_and(|review| review.failures.is_empty()));
}

#[test]
fn auditor_must_accept_exact_declaration_digest_before_tasks_exist() {
    skip_without_containment!();
    let assignment = licensed_assignment();
    let child = dependent_failure_child(&assignment, "src/client.rs");
    let scenario = run_licensed_scenario(assignment, child, false, "licensed-auditor-refusal");

    assert!(!scenario.report.success);
    assert!(scenario.report.generated_follow_up_tasks.is_empty());
    assert!(scenario
        .report
        .gate_denials
        .iter()
        .any(|denial| matches!(denial.reason, GateDenialReason::AuditorRepair { .. })));
}

#[test]
fn child_cannot_self_grant_license_or_generate_follow_up_authority() {
    let assignment = injected_assignment(false);
    let mut child = injected_child_report(&assignment);
    child.files_changed = vec![PathBuf::from("README.md")];
    child.licensed_breakage_review = Some(LicensedBreakageReview {
        declaration_sha256: "0".repeat(64),
        migration_rationale: "self granted".to_string(),
        failures: Vec::new(),
    });
    let scenario = run_licensed_scenario(assignment, child, false, "licensed-self-grant");

    assert!(!scenario.report.success);
    assert!(scenario.report.generated_follow_up_tasks.is_empty());
    assert!(scenario.report.orchestrator_reports[0]
        .findings
        .iter()
        .any(|finding| finding
            .message
            .contains("attempted to self-assert supervisor-owned licensed breakage")));
}

#[test]
fn over_broad_license_and_diff_only_auditor_are_rejected_during_plan_validation() {
    let mut assignment = licensed_assignment();
    assignment
        .licensed_breakage
        .as_mut()
        .expect("licensed assignment")
        .dependents[0]
        .paths = vec![PathBuf::from(".")];
    let metadata = SupervisorPlanMetadata {
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        ..SupervisorPlanMetadata::default()
    };
    let error = validate_supervisor_plan(injected_plan(assignment, 0), metadata)
        .expect_err("root-wide license must fail plan validation");
    assert!(format!("{error:#}").contains("over-broad"));

    let assignment = licensed_assignment();
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.review_lenses[0].information_scope = ReviewInformationScope::DiffOnly;
    let metadata = SupervisorPlanMetadata {
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id: assignment.id,
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        ..SupervisorPlanMetadata::default()
    };
    let error = validate_supervisor_plan(plan, metadata)
        .expect_err("auditor that cannot see the declaration must fail plan validation");
    assert!(format!("{error:#}").contains("receive the output report"));
}

#[test]
fn strict_journal_failure_cannot_silently_swallow_generated_tasks() {
    let (temp, repo) = injected_repository();
    let run_id = RunId::new("licensed-journal-failure").expect("valid journal failure run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "licensed-journal-failure-test",
    )
    .expect("reserve licensed journal artifacts");
    let mut journal = Some(OrchestrationEventJournal::new(
        "licensed-test-repo",
        run_id.as_str(),
    ));
    let mut collector = AutonomyKpiCollector::default();
    let assignment = licensed_assignment();
    let declaration = assignment.licensed_breakage.as_ref().expect("declaration");
    let review = LicensedBreakageReview {
        declaration_sha256: licensed_breakage_declaration_sha256(declaration)
            .expect("hash declaration"),
        migration_rationale: declaration.migration_rationale.clone(),
        failures: vec![LicensedDependentFailure {
            dependent_id: "client-a".to_string(),
            validation_name: "client-a".to_string(),
            failure_signature: LICENSED_SIGNATURE.to_string(),
            paths: vec![PathBuf::from("src/client.rs")],
            interfaces: vec![LICENSED_INTERFACE.to_string()],
        }],
    };
    let mut report = injected_child_report(&assignment);
    report.licensed_breakage_review = Some(review.clone());
    let tasks = generated_licensed_follow_up_tasks(
        &injected_plan(assignment.clone(), 0),
        &SupervisorConsultantPlan::default(),
        &SupervisorBudgetConfig::default(),
        &assignment,
        &report,
        &CandidateValidationBinding {
            version: 1,
            agent_id: assignment.id.clone(),
            primary_head: None,
            agent_head: None,
            merge_base: None,
            diff_oid: "1111111111111111111111111111111111111111".to_string(),
        },
    )
    .expect("generate follow-up task fixture");
    let mutation_session = SupervisorRunMutationSession::local_for_test(run_id.as_str());
    {
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut collector,
            checkpoint: None,
            mutation_session: &mutation_session,
        });
        let error =
            record_licensed_breakage_follow_up_tasks(&artifacts, &assignment.id, &review, &[])
                .expect_err("a licensed failure with no follow-up task must fail closed");
        assert!(format!("{error:#}").contains("exactly one durable follow-up task each"));
        set_orchestration_event_append_fault();
        let error =
            record_licensed_breakage_follow_up_tasks(&artifacts, &assignment.id, &review, &tasks)
                .expect_err("journal append failure must refuse the licensed outcome");
        assert!(format!("{error:#}").contains("failed to journal licensed breakage follow-up task"));
    }
    assert!(!journal.as_ref().expect("journal").is_enabled());
    assert_eq!(collector.report(false), AutonomyKpiReport::default());
    drop(temp);
}

#[test]
fn license_is_content_bound_into_checkpoint_plan_and_evidence_only_prompt() {
    let assignment = licensed_assignment();
    let plan = injected_plan(assignment.clone(), 0);
    let metadata = SupervisorPlanMetadata {
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        ..SupervisorPlanMetadata::default()
    };
    let licensed_hash = normalized_supervisor_plan_sha256(
        &plan,
        &SupervisorConsultantPlan::default(),
        &AssignmentMetadata::new(),
        &metadata,
    )
    .expect("hash licensed checkpoint plan");
    let mut unlicensed_plan = plan.clone();
    unlicensed_plan.assignments[0].licensed_breakage = None;
    let unlicensed_hash = normalized_supervisor_plan_sha256(
        &unlicensed_plan,
        &SupervisorConsultantPlan::default(),
        &AssignmentMetadata::new(),
        &metadata,
    )
    .expect("hash unlicensed checkpoint plan");
    assert_ne!(licensed_hash, unlicensed_hash);

    let mut authenticated_source = dependent_failure_child(&assignment, "src/client.rs");
    prepare_licensed_breakage_review(&assignment, &mut authenticated_source);
    assert_eq!(
        authenticated_source
            .licensed_breakage_review
            .as_ref()
            .expect("source licensed review")
            .failures
            .len(),
        1
    );
    let mut evidence_only_report = authenticated_source.clone();
    evidence_only_report.licensed_breakage_review = None;
    evidence_only_report.generated_follow_up_tasks.clear();
    evidence_only_report.audit_reports.clear();
    prepare_licensed_breakage_review(&assignment, &mut evidence_only_report);
    assert_eq!(
        evidence_only_report
            .licensed_breakage_review
            .as_ref()
            .expect("reconstructed evidence-only licensed review")
            .failures
            .len(),
        1
    );

    let source_report = injected_child_report(&assignment);
    let source = EvidenceOnlyReauditSource {
        operation: EvidenceOnlyReauditPlan {
            source_run_id: RunId::new("licensed-source-run").expect("source run id"),
            assignment_id: assignment.id.clone(),
            attempt: 1,
            preserved_candidate_binding: CandidateValidationBinding {
                version: 1,
                agent_id: assignment.id.clone(),
                primary_head: None,
                agent_head: None,
                merge_base: None,
                diff_oid: "licensed-source-diff".to_string(),
            },
        },
        report: source_report,
    };
    let prompt = render_evidence_only_reaudit_prompt(
        &assignment,
        &WorktreeRecord {
            name: assignment.id.clone(),
            path: PathBuf::from("/tmp/licensed-re-audit"),
            branch: "maco/licensed-re-audit".to_string(),
        },
        Path::new("/tmp/licensed-report.json"),
        Path::new("/tmp/licensed-schema.json"),
        &source,
        "diff --git a/README.md b/README.md",
    )
    .expect("render licensed evidence-only prompt")
    .prompt;
    assert!(prompt.contains("licensed_breakage"));
    assert!(prompt.contains(LICENSED_INTERFACE));
    assert!(prompt.contains("Immutable assignment JSON"));
}

#[test]
fn licensed_follow_up_survives_authenticated_final_report_resume_without_redispatch() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let assignment = licensed_assignment();
    let plan = injected_plan(assignment.clone(), 0);
    let run_id = RunId::new("licensed-final-report-resume").expect("licensed resume run id");
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: temp.path().join("licensed-final-report-resume.json"),
        run_id: run_id.clone(),
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: true,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(injected_machine_global_retention(temp.path())),
    };
    let declaration_sha256 = licensed_breakage_declaration_sha256(
        assignment
            .licensed_breakage
            .as_ref()
            .expect("licensed resume declaration"),
    )
    .expect("hash licensed resume declaration");
    let mut child = dependent_failure_child(&assignment, "src/client.rs");
    let mut child_dispatched = false;
    let mut runner = |command: &ExternalAgentCommand| {
        let output_name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if output_name.contains("review-auditor") {
            write_injected_json(
                &command.output_last_message,
                &licensed_auditor_report(&assignment, Some(&declaration_sha256)),
            );
        } else {
            assert!(!child_dispatched, "resume fixture redispatched child");
            child_dispatched = true;
            fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                .expect("write licensed resume candidate");
            child.id = assignment.id.clone();
            write_injected_json(&command.output_last_message, &child);
        }
        injected_verified_run(command)
    };
    install_checkpoint_failure(run_id.as_str(), "after:final_report_planned");
    let error = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect_err("licensed final-report checkpoint interruption");
    assert!(format!("{error:#}").contains("after phase 'final_report_planned'"));

    let resumed = resume_supervisor_run(&repo, run_id).expect("resume licensed final report");
    assert!(resumed.resumed);
    assert_eq!(resumed.completed_assignments, vec!["child-a"]);
    let final_report = resumed.final_report.expect("resumed licensed final report");
    assert!(final_report.success);
    assert_eq!(final_report.generated_follow_up_tasks.len(), 1);
    assert_eq!(
        final_report.generated_follow_up_tasks,
        final_report.orchestrator_reports[0].generated_follow_up_tasks
    );
}

#[cfg(target_os = "linux")]
#[test]
fn licensed_follow_up_cascade_dispatches_one_authenticated_round_and_keeps_primary_untouched() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_assignment = licensed_assignment();
    let follow_up_assignment = licensed_follow_up_assignment();
    let plan = injected_plan(source_assignment.clone(), 0);
    let run_id = RunId::new("licensed-cascade-depth-two").expect("cascade source run id");
    let plan_file = temp.path().join("licensed-cascade-depth-two.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&plan).expect("serialize licensed cascade source plan"),
    )
    .expect("write licensed cascade source plan");
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file,
        run_id,
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(secure_machine_global_retention(
            temp.path(),
            "licensed-cascade-depth-two",
        )),
    };
    let declaration_sha256 = licensed_breakage_declaration_sha256(
        source_assignment
            .licensed_breakage
            .as_ref()
            .expect("licensed cascade declaration"),
    )
    .expect("hash licensed cascade declaration");
    let queue_root = repo
        .join(".git/maco/state")
        .join(crate::follow_up_queue::GENERATED_FOLLOW_UP_QUEUE_ROOT_NAME);
    assert!(
        !queue_root.exists(),
        "queue must not predate the source run"
    );
    let observations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = std::rc::Rc::clone(&observations);
    set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });
    let primary_before =
        verified_whole_primary_snapshot_sha256(&repo).expect("capture whole-primary baseline");
    let mut source_child_dispatches = 0_usize;
    let mut follow_up_child_dispatches = 0_usize;
    let mut runner = |command: &ExternalAgentCommand| {
        let output_path = command.output_last_message.to_string_lossy();
        let is_follow_up = output_path.contains("child-a-licensed-update-01");
        let is_auditor = output_path.contains("review-auditor");
        if is_auditor && is_follow_up {
            let mut child = injected_child_report(&follow_up_assignment);
            child.files_changed = vec![PathBuf::from("src/client.rs")];
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&follow_up_assignment, &child),
            );
        } else if is_auditor {
            write_injected_json(
                &command.output_last_message,
                &licensed_auditor_report(&source_assignment, Some(&declaration_sha256)),
            );
        } else if is_follow_up {
            follow_up_child_dispatches += 1;
            assert_eq!(follow_up_child_dispatches, 1, "follow-up child reran");
            fs::create_dir_all(command.cwd.join("src")).expect("create dependent source dir");
            fs::write(
                command.cwd.join("src/client.rs"),
                "pub fn migrated_client() {}\n",
            )
            .expect("write generated dependent update");
            let mut child = injected_child_report(&follow_up_assignment);
            child.files_changed = vec![PathBuf::from("src/client.rs")];
            write_injected_json(&command.output_last_message, &child);
        } else {
            source_child_dispatches += 1;
            assert_eq!(source_child_dispatches, 1, "source child reran");
            fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                .expect("write licensed source candidate");
            write_injected_json(
                &command.output_last_message,
                &dependent_failure_child(&source_assignment, "src/client.rs"),
            );
        }
        write_injected_usage(command, 0, 1);
        injected_verified_run(command)
    };

    let outcome = run_supervisor_plan_file_cascade_with_runner(options, &mut runner)
        .expect("dispatch authenticated bounded licensed cascade");
    clear_generated_follow_up_queue_observer();
    let primary_after = verified_whole_primary_snapshot_sha256(&repo)
        .expect("capture whole-primary final observation");

    assert!(outcome.source_report.success, "{outcome:#?}");
    assert!(outcome.source_report.publishable, "{outcome:#?}");
    assert!(outcome.follow_up_cascade_success, "{outcome:#?}");
    assert_eq!(outcome.follow_up_primary_worktree_untouched, Some(true));
    assert!(outcome.generated_follow_up_dispatch_performed());
    let queue = outcome
        .follow_up_queue
        .expect("authenticated queue summary");
    assert!(queue.enqueue_committed);
    assert_eq!(queue.item_count, 1);
    assert_eq!(queue.pending_count, 0);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 1);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 1);
    assert_eq!(outcome.follow_up_reports.len(), 1);
    assert!(outcome.follow_up_reports[0].success);
    assert!(outcome.follow_up_reports[0]
        .generated_follow_up_tasks
        .is_empty());
    assert_eq!(source_child_dispatches, 1);
    assert_eq!(follow_up_child_dispatches, 1);
    assert_eq!(primary_after, primary_before);
    assert!(!repo.join("src/client.rs").exists());
    let observations = observations.borrow();
    let created = observations
        .iter()
        .find(|observation| observation.label == "created_or_opened")
        .expect("queue Created observation");
    assert_eq!(created.pending_count, 0);
    assert_eq!(created.dispatch_started_count, 0);
    let enqueued = observations
        .iter()
        .find(|observation| observation.label == "enqueued")
        .expect("durable Enqueued observation");
    assert_eq!(enqueued.pending_count, 1);
    assert_eq!(enqueued.dispatch_started_count, 0);
    let started = observations
        .iter()
        .find(|observation| observation.label == "dispatch_started")
        .expect("durable DispatchStarted observation");
    assert_eq!(started.pending_count, 0);
    assert_eq!(started.dispatch_started_count, 1);
    assert_eq!(started.authenticated_child_dispatch_started_count, 0);
    let acknowledged = observations
        .iter()
        .find(|observation| observation.label == "acknowledged_terminal")
        .expect("durable Acknowledged observation");
    assert_eq!(acknowledged.acknowledged_terminal_count, 1);
    assert_eq!(acknowledged.authenticated_child_dispatch_started_count, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn generated_follow_up_exact_loaded_plan_drift_refuses_before_child_dispatch() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_assignment = licensed_assignment();
    let plan = injected_plan(source_assignment.clone(), 0);
    let run_id = RunId::new("licensed-cascade-exact-plan-refusal")
        .expect("exact-plan refusal source run id");
    let plan_file = temp.path().join("licensed-cascade-exact-plan-refusal.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&plan).expect("serialize exact-plan refusal source"),
    )
    .expect("write exact-plan refusal source");
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file,
        run_id,
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(secure_machine_global_retention(
            temp.path(),
            "licensed-cascade-exact-plan-refusal",
        )),
    };
    let declaration_sha256 = licensed_breakage_declaration_sha256(
        source_assignment
            .licensed_breakage
            .as_ref()
            .expect("exact-plan refusal declaration"),
    )
    .expect("hash exact-plan refusal declaration");
    let primary_before = verified_whole_primary_snapshot_sha256(&repo)
        .expect("capture exact-plan refusal primary baseline");
    let observations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = std::rc::Rc::clone(&observations);
    set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });
    set_before_generated_follow_up_plan_load_hook(|path| {
        let bytes = fs::read(path).expect("read persisted generated follow-up plan");
        let mut value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("decode generated follow-up plan");
        value["assignments"][0]["assigned_paths"] =
            serde_json::json!(["src/client.rs", "src/expanded.rs"]);
        fs::write(
            path,
            serde_json::to_vec_pretty(&value).expect("encode drifted generated follow-up plan"),
        )
        .expect("mutate persisted generated follow-up scope");
    });
    let mut source_child_dispatches = 0_usize;
    let mut generated_child_dispatches = 0_usize;
    let mut runner = |command: &ExternalAgentCommand| {
        let output_path = command.output_last_message.to_string_lossy();
        let is_follow_up = output_path.contains("child-a-licensed-update-01");
        let is_auditor = output_path.contains("review-auditor");
        if is_follow_up {
            generated_child_dispatches += 1;
            panic!("drifted generated plan reached a child or auditor dispatch");
        } else if is_auditor {
            write_injected_json(
                &command.output_last_message,
                &licensed_auditor_report(&source_assignment, Some(&declaration_sha256)),
            );
        } else {
            source_child_dispatches += 1;
            assert_eq!(source_child_dispatches, 1, "source child reran");
            fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                .expect("write exact-plan refusal source candidate");
            write_injected_json(
                &command.output_last_message,
                &dependent_failure_child(&source_assignment, "src/client.rs"),
            );
        }
        write_injected_usage(command, 0, 1);
        injected_verified_run(command)
    };

    let outcome = run_supervisor_plan_file_cascade_with_runner(options, &mut runner)
        .expect("return typed exact generated-plan refusal");
    clear_generated_follow_up_queue_observer();
    let primary_after = verified_whole_primary_snapshot_sha256(&repo)
        .expect("capture exact-plan refusal primary final");

    assert!(outcome.source_report.success, "{outcome:#?}");
    assert!(!outcome.follow_up_cascade_success);
    assert!(!outcome.generated_follow_up_dispatch_performed());
    assert_eq!(outcome.follow_up_primary_worktree_untouched, Some(true));
    assert!(outcome.follow_up_reports.is_empty());
    assert!(outcome.follow_up_gate_denials.iter().any(|denial| {
        matches!(
            denial.reason,
            GateDenialReason::ApprovalReview {
                denial: crate::gate_denial::ApprovalReviewDenial::PermissionExpansion
            }
        )
    }));
    let queue = outcome.follow_up_queue.expect("refused queue summary");
    assert_eq!(queue.pending_count, 1);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 0);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 0);
    assert_eq!(source_child_dispatches, 1);
    assert_eq!(generated_child_dispatches, 0);
    assert_eq!(primary_after, primary_before);
    assert!(!repo.join("src/client.rs").exists());
    assert!(observations
        .borrow()
        .iter()
        .all(|observation| observation.label != "dispatch_started"));
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum GeneratedRoundLastMomentMutation {
    Primary,
    MachineGlobalConfig,
    MachineGlobalConfigDeleted,
}

#[cfg(target_os = "linux")]
struct GeneratedRoundLastMomentScenario {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    outcome: SupervisorCascadeOutcome,
    primary_before: String,
    primary_after: String,
    machine_global_config_before: Vec<u8>,
    machine_global_config_after: Option<Vec<u8>>,
    queue_observations: Vec<GeneratedFollowUpQueueTestObservation>,
    profile_callback_invocations: usize,
    source_child_dispatches: usize,
    generated_runner_dispatches: usize,
}

#[cfg(target_os = "linux")]
fn run_generated_round_last_moment_mutation(
    run_name: &str,
    mutation: GeneratedRoundLastMomentMutation,
) -> GeneratedRoundLastMomentScenario {
    let (temp, repo) = injected_repository();
    let source_assignment = licensed_assignment();
    let plan = injected_plan(source_assignment.clone(), 0);
    let run_id = RunId::new(run_name).expect("last-moment gate source run id");
    let plan_file = temp.path().join(format!("{run_name}.json"));
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&plan).expect("serialize last-moment gate source plan"),
    )
    .expect("write last-moment gate source plan");
    let retention = secure_machine_global_retention(temp.path(), run_name);
    let machine_global_config = retention.config.clone();
    let machine_global_config_before =
        fs::read(&machine_global_config).expect("read original machine-global config");
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file,
        run_id,
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(retention),
    };
    let declaration_sha256 = licensed_breakage_declaration_sha256(
        source_assignment
            .licensed_breakage
            .as_ref()
            .expect("last-moment gate licensed declaration"),
    )
    .expect("hash last-moment gate declaration");
    let primary_before =
        verified_whole_primary_snapshot_sha256(&repo).expect("capture last-moment primary before");
    let queue_observations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = std::rc::Rc::clone(&queue_observations);
    set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });
    let mut profile_callback_invocations = 0_usize;
    let repo_for_gate = repo.clone();
    let config_for_gate = machine_global_config.clone();
    let mut source_child_dispatches = 0_usize;
    let mut generated_runner_dispatches = 0_usize;
    let outer_run_id =
        RunId::new(format!("{run_name}-outer")).expect("last-moment outer command run id");
    let outcome = {
        let mut before_dispatch = |_effective: &SupervisorPlan| {
            profile_callback_invocations = profile_callback_invocations.saturating_add(1);
            if profile_callback_invocations == 2 {
                match mutation {
                    GeneratedRoundLastMomentMutation::Primary => {
                        fs::write(
                            repo_for_gate.join("README.md"),
                            "primary changed after generated profile approval\n",
                        )
                        .expect("mutate primary after generated profile approval");
                    }
                    GeneratedRoundLastMomentMutation::MachineGlobalConfig => {
                        let mut changed = fs::read(&config_for_gate)
                            .expect("reread machine-global config before drift");
                        changed.extend_from_slice(b"\n ");
                        fs::write(&config_for_gate, changed)
                            .expect("mutate machine-global config after profile approval");
                    }
                    GeneratedRoundLastMomentMutation::MachineGlobalConfigDeleted => {
                        fs::remove_file(&config_for_gate)
                            .expect("delete machine-global config after profile approval");
                    }
                }
            }
            Ok(true)
        };
        let mut runner = |command: &ExternalAgentCommand| {
            let output_path = command.output_last_message.to_string_lossy();
            let is_follow_up = output_path.contains("child-a-licensed-update-01");
            let is_auditor = output_path.contains("review-auditor");
            if is_follow_up {
                generated_runner_dispatches = generated_runner_dispatches.saturating_add(1);
                panic!("last-moment generated-round refusal reached an external runner");
            } else if is_auditor {
                write_injected_json(
                    &command.output_last_message,
                    &licensed_auditor_report(&source_assignment, Some(&declaration_sha256)),
                );
            } else {
                source_child_dispatches = source_child_dispatches.saturating_add(1);
                assert_eq!(source_child_dispatches, 1, "source child reran");
                fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                    .expect("write last-moment source candidate");
                write_injected_json(
                    &command.output_last_message,
                    &dependent_failure_child(&source_assignment, "src/client.rs"),
                );
            }
            write_injected_usage(command, 0, 1);
            injected_verified_run(command)
        };
        run_supervisor_plan_file_cascade_with_runner_and_gate(
            options,
            GeneratedFollowUpQueueEntrypoint::SuperviseRun,
            &outer_run_id,
            &mut before_dispatch,
            &mut runner,
        )
        .expect("return typed last-moment generated-round refusal")
    };
    clear_generated_follow_up_queue_observer();
    let primary_after =
        verified_whole_primary_snapshot_sha256(&repo).expect("capture last-moment primary after");
    let machine_global_config_after = fs::read(&machine_global_config).ok();
    let queue_observations = queue_observations.borrow().clone();

    GeneratedRoundLastMomentScenario {
        _temp: temp,
        repo,
        outcome,
        primary_before,
        primary_after,
        machine_global_config_before,
        machine_global_config_after,
        queue_observations,
        profile_callback_invocations,
        source_child_dispatches,
        generated_runner_dispatches,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn generated_follow_up_rechecks_primary_after_profile_before_dispatch() {
    skip_without_containment!();
    let scenario = run_generated_round_last_moment_mutation(
        "licensed-cascade-last-moment-primary",
        GeneratedRoundLastMomentMutation::Primary,
    );

    assert!(
        scenario.outcome.source_report.success,
        "{:#?}",
        scenario.outcome
    );
    assert!(!scenario.outcome.follow_up_cascade_success);
    assert!(!scenario.outcome.generated_follow_up_dispatch_performed());
    assert_eq!(
        scenario.outcome.follow_up_primary_worktree_untouched,
        Some(false)
    );
    assert!(scenario
        .outcome
        .follow_up_gate_denials
        .iter()
        .any(|denial| { matches!(denial.reason, GateDenialReason::PrimaryIntegrityFailure) }));
    let queue = scenario
        .outcome
        .follow_up_queue
        .expect("last-moment primary queue summary");
    assert_eq!(queue.pending_count, 1);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 0);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 0);
    assert_eq!(scenario.profile_callback_invocations, 2);
    assert_eq!(scenario.source_child_dispatches, 1);
    assert_eq!(scenario.generated_runner_dispatches, 0);
    assert_ne!(scenario.primary_after, scenario.primary_before);
    assert_eq!(
        scenario.machine_global_config_after.as_deref(),
        Some(scenario.machine_global_config_before.as_slice())
    );
    assert!(!scenario.repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn generated_follow_up_rechecks_machine_global_after_profile_before_dispatch() {
    skip_without_containment!();
    let scenario = run_generated_round_last_moment_mutation(
        "licensed-cascade-last-moment-retention",
        GeneratedRoundLastMomentMutation::MachineGlobalConfig,
    );

    assert!(
        scenario.outcome.source_report.success,
        "{:#?}",
        scenario.outcome
    );
    assert!(!scenario.outcome.follow_up_cascade_success);
    assert!(!scenario.outcome.generated_follow_up_dispatch_performed());
    assert_eq!(
        scenario.outcome.follow_up_primary_worktree_untouched,
        Some(true)
    );
    assert!(scenario
        .outcome
        .follow_up_gate_denials
        .iter()
        .any(|denial| {
            matches!(
                denial.reason,
                GateDenialReason::ApprovalReview {
                    denial: crate::gate_denial::ApprovalReviewDenial::PermissionExpansion
                }
            )
        }));
    let queue = scenario
        .outcome
        .follow_up_queue
        .expect("last-moment retention queue summary");
    assert_eq!(queue.pending_count, 1);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 0);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 0);
    assert_eq!(scenario.profile_callback_invocations, 2);
    assert_eq!(scenario.source_child_dispatches, 1);
    assert_eq!(scenario.generated_runner_dispatches, 0);
    assert_eq!(scenario.primary_after, scenario.primary_before);
    assert_ne!(
        scenario
            .machine_global_config_after
            .as_deref()
            .expect("drifted machine-global config remains readable"),
        scenario.machine_global_config_before.as_slice()
    );
    assert!(!scenario.repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn generated_follow_up_deleted_retention_is_journaled_probe_failed_and_retryable() {
    skip_without_containment!();
    let scenario = run_generated_round_last_moment_mutation(
        "licensed-cascade-last-moment-retention-deleted",
        GeneratedRoundLastMomentMutation::MachineGlobalConfigDeleted,
    );

    assert!(
        scenario.outcome.source_report.success,
        "{:#?}",
        scenario.outcome
    );
    assert!(!scenario.outcome.follow_up_cascade_success);
    assert!(!scenario.outcome.generated_follow_up_dispatch_performed());
    assert_eq!(
        scenario.outcome.follow_up_primary_worktree_untouched,
        Some(true)
    );
    assert!(scenario.outcome.follow_up_gate_denials.is_empty());
    assert_eq!(scenario.outcome.follow_up_environment_failures.len(), 1);
    let failure = &scenario.outcome.follow_up_environment_failures[0];
    assert_eq!(failure.category, EnvironmentFailureCategory::ProbeFailed);
    assert!(failure.summary.contains("I/O error kind NotFound"));
    let queue = scenario
        .outcome
        .follow_up_queue
        .expect("deleted-retention queue summary");
    assert_eq!(queue.pending_count, 1);
    assert_eq!(queue.claimed_count, 0);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 0);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 0);
    let journaled = scenario
        .queue_observations
        .iter()
        .find(|observation| observation.label == "environment_failed")
        .expect("observe journaled environment failure after claim release");
    assert_eq!(journaled.pending_count, 1);
    assert_eq!(journaled.claimed_count, 0);
    assert_eq!(journaled.dispatch_started_count, 0);
    assert_eq!(journaled.environment_failures.len(), 1);
    assert_eq!(
        journaled.environment_failures[0].category,
        EnvironmentFailureCategory::ProbeFailed
    );
    assert_eq!(scenario.profile_callback_invocations, 2);
    assert_eq!(scenario.source_child_dispatches, 1);
    assert_eq!(scenario.generated_runner_dispatches, 0);
    assert_eq!(scenario.primary_after, scenario.primary_before);
    assert!(scenario.machine_global_config_after.is_none());
    assert!(!scenario.repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn generated_follow_up_initial_deleted_retention_is_typed_without_queue() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_assignment = licensed_assignment();
    let plan = injected_plan(source_assignment.clone(), 0);
    let run_id = RunId::new("licensed-cascade-initial-retention-deleted")
        .expect("initial deleted-retention source run id");
    let plan_file = temp.path().join("initial-retention-deleted.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&plan).expect("serialize initial deleted-retention source plan"),
    )
    .expect("write initial deleted-retention source plan");
    let retention =
        secure_machine_global_retention(temp.path(), "licensed-cascade-initial-retention-deleted");
    let config = retention.config.clone();
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file,
        run_id,
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(retention),
    };
    let declaration_sha256 = licensed_breakage_declaration_sha256(
        source_assignment
            .licensed_breakage
            .as_ref()
            .expect("initial deleted-retention declaration"),
    )
    .expect("hash initial deleted-retention declaration");
    let primary_before = verified_whole_primary_snapshot_sha256(&repo)
        .expect("capture initial deleted-retention primary before");
    let mut source_child_dispatches = 0_usize;
    let source = {
        let mut source_runner = |command: &ExternalAgentCommand| {
            let is_auditor = command
                .output_last_message
                .to_string_lossy()
                .contains("review-auditor");
            if is_auditor {
                write_injected_json(
                    &command.output_last_message,
                    &licensed_auditor_report(&source_assignment, Some(&declaration_sha256)),
                );
            } else {
                source_child_dispatches = source_child_dispatches.saturating_add(1);
                assert_eq!(source_child_dispatches, 1, "initial source child reran");
                fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                    .expect("write initial deleted-retention source candidate");
                write_injected_json(
                    &command.output_last_message,
                    &dependent_failure_child(&source_assignment, "src/client.rs"),
                );
            }
            write_injected_usage(command, 0, 1);
            injected_verified_run(command)
        };
        run_supervisor_plan_file_with_runner(options.clone(), &mut source_runner)
            .expect("finalize source before deleting initial retention config")
    };
    assert!(source.success, "{source:#?}");
    assert_eq!(source.generated_follow_up_tasks.len(), 1);
    fs::remove_file(&config).expect("delete retention config before cascade initialization");
    let mut unexpected_generated_dispatches = 0_usize;
    let outcome = {
        let mut no_generated_runner = |_command: &ExternalAgentCommand| {
            unexpected_generated_dispatches = unexpected_generated_dispatches.saturating_add(1);
            panic!("initial deleted retention reached generated runner");
        };
        resume_supervisor_plan_file_cascade_with_runner(options, &mut no_generated_runner)
            .expect("return typed initial retention probe failure")
    };

    assert!(!outcome.follow_up_cascade_success);
    assert!(!outcome.generated_follow_up_dispatch_performed());
    assert_eq!(outcome.follow_up_primary_worktree_untouched, None);
    assert!(outcome.follow_up_queue.is_none());
    assert!(outcome.follow_up_gate_denials.is_empty());
    assert_eq!(outcome.follow_up_environment_failures.len(), 1);
    assert_eq!(
        outcome.follow_up_environment_failures[0].category,
        EnvironmentFailureCategory::ProbeFailed
    );
    assert!(outcome.follow_up_environment_failures[0]
        .summary
        .contains("I/O error kind NotFound"));
    assert_eq!(source_child_dispatches, 1);
    assert_eq!(unexpected_generated_dispatches, 0);
    assert_eq!(
        verified_whole_primary_snapshot_sha256(&repo)
            .expect("capture initial deleted-retention primary after"),
        primary_before
    );
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn licensed_follow_up_enqueue_interruption_resumes_without_rerunning_source() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_assignment = licensed_assignment();
    let follow_up_assignment = licensed_follow_up_assignment();
    let plan = injected_plan(source_assignment.clone(), 0);
    let run_id = RunId::new("licensed-cascade-enqueue-resume").expect("cascade resume run id");
    let plan_file = temp.path().join("licensed-cascade-enqueue-resume.json");
    fs::write(
        &plan_file,
        serde_json::to_vec_pretty(&plan).expect("serialize resumable licensed source plan"),
    )
    .expect("write resumable licensed source plan");
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file,
        run_id,
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(secure_machine_global_retention(
            temp.path(),
            "licensed-cascade-enqueue-resume",
        )),
    };
    let declaration_sha256 = licensed_breakage_declaration_sha256(
        source_assignment
            .licensed_breakage
            .as_ref()
            .expect("resumable licensed declaration"),
    )
    .expect("hash resumable licensed declaration");
    let observations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = std::rc::Rc::clone(&observations);
    set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });
    let source_child_dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let follow_up_child_dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut runner = |command: &ExternalAgentCommand| {
        let output_path = command.output_last_message.to_string_lossy();
        let is_follow_up = output_path.contains("child-a-licensed-update-01");
        let is_auditor = output_path.contains("review-auditor");
        if is_auditor && is_follow_up {
            let mut child = injected_child_report(&follow_up_assignment);
            child.files_changed = vec![PathBuf::from("src/client.rs")];
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&follow_up_assignment, &child),
            );
        } else if is_auditor {
            write_injected_json(
                &command.output_last_message,
                &licensed_auditor_report(&source_assignment, Some(&declaration_sha256)),
            );
        } else if is_follow_up {
            let count = follow_up_child_dispatches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .saturating_add(1);
            assert_eq!(count, 1, "resumed follow-up reran");
            fs::create_dir_all(command.cwd.join("src")).expect("create resumed dependent dir");
            fs::write(command.cwd.join("src/client.rs"), "pub fn migrated() {}\n")
                .expect("write resumed dependent update");
            let mut child = injected_child_report(&follow_up_assignment);
            child.files_changed = vec![PathBuf::from("src/client.rs")];
            write_injected_json(&command.output_last_message, &child);
        } else {
            let count = source_child_dispatches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .saturating_add(1);
            assert_eq!(count, 1, "source reran across resume");
            fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                .expect("write resumable licensed source candidate");
            write_injected_json(
                &command.output_last_message,
                &dependent_failure_child(&source_assignment, "src/client.rs"),
            );
        }
        write_injected_usage(command, 0, 1);
        injected_verified_run(command)
    };

    set_interrupt_after_follow_up_enqueue();
    let error = run_supervisor_plan_file_cascade_with_runner(options.clone(), &mut runner)
        .expect_err("interrupt after durable follow-up enqueue");
    assert!(format!("{error:#}")
        .contains("injected interruption after durable generated follow-up enqueue"));
    assert_eq!(
        source_child_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        follow_up_child_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    {
        let observations = observations.borrow();
        let interrupted = observations.last().expect("interrupted queue observation");
        assert_eq!(interrupted.label, "enqueued");
        assert_eq!(interrupted.pending_count, 1);
        assert_eq!(interrupted.dispatch_started_count, 0);
        assert_eq!(interrupted.acknowledged_terminal_count, 0);
    }

    let outcome = resume_supervisor_plan_file_cascade_with_runner(options, &mut runner)
        .expect("resume exact finalized source and drain durable queue");
    clear_generated_follow_up_queue_observer();
    assert!(outcome.follow_up_cascade_success, "{outcome:#?}");
    assert!(outcome.generated_follow_up_dispatch_performed());
    assert_eq!(
        source_child_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        follow_up_child_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let queue = outcome.follow_up_queue.expect("resumed queue summary");
    assert_eq!(queue.pending_count, 0);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 1);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 1);
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn immediate_error_refuses_preexisting_finalized_subordinate_with_different_plan() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_assignment = licensed_assignment();
    let follow_up_assignment = licensed_follow_up_assignment();
    let plan = injected_plan(source_assignment.clone(), 0);
    let source_run_id = RunId::new("licensed-immediate-error-plan-mismatch")
        .expect("immediate mismatch source run id");
    let source_plan_file = temp.path().join("immediate-error-plan-mismatch.json");
    fs::write(
        &source_plan_file,
        serde_json::to_vec_pretty(&plan).expect("serialize immediate mismatch source plan"),
    )
    .expect("write immediate mismatch source plan");
    let retention =
        secure_machine_global_retention(temp.path(), "licensed-immediate-error-plan-mismatch");
    let source_options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: source_plan_file,
        run_id: source_run_id.clone(),
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(retention.clone()),
    };
    let declaration_sha256 = licensed_breakage_declaration_sha256(
        source_assignment
            .licensed_breakage
            .as_ref()
            .expect("immediate mismatch source declaration"),
    )
    .expect("hash immediate mismatch source declaration");
    let observations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = std::rc::Rc::clone(&observations);
    set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });
    let primary_before = verified_whole_primary_snapshot_sha256(&repo)
        .expect("capture immediate mismatch primary before");
    let source_child_dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let source_dispatches = std::sync::Arc::clone(&source_child_dispatches);
    let mut source_runner = move |command: &ExternalAgentCommand| {
        let output_path = command.output_last_message.to_string_lossy();
        let is_follow_up = output_path.contains("child-a-licensed-update-01");
        let is_auditor = output_path.contains("review-auditor");
        assert!(!is_follow_up, "enqueue interruption dispatched a follow-up");
        if is_auditor {
            write_injected_json(
                &command.output_last_message,
                &licensed_auditor_report(&source_assignment, Some(&declaration_sha256)),
            );
        } else {
            let count = source_dispatches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .saturating_add(1);
            assert_eq!(count, 1, "immediate mismatch source child reran");
            fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                .expect("write immediate mismatch source candidate");
            write_injected_json(
                &command.output_last_message,
                &dependent_failure_child(&source_assignment, "src/client.rs"),
            );
        }
        write_injected_usage(command, 0, 1);
        injected_verified_run(command)
    };

    set_interrupt_after_follow_up_enqueue();
    let error =
        run_supervisor_plan_file_cascade_with_runner(source_options.clone(), &mut source_runner)
            .expect_err("interrupt after immediate mismatch enqueue");
    assert!(format!("{error:#}")
        .contains("injected interruption after durable generated follow-up enqueue"));
    let enqueued = observations
        .borrow()
        .iter()
        .find(|observation| observation.label == "enqueued")
        .cloned()
        .expect("observe immediate mismatch enqueued state");
    assert_eq!(enqueued.pending_count, 1);
    assert_eq!(enqueued.dispatch_started_count, 0);
    assert_eq!(enqueued.acknowledged_terminal_count, 0);
    assert_eq!(enqueued.item_ids.len(), 1);

    let source_report = supervisor_status(&repo, source_run_id)
        .expect("read immediate mismatch finalized source")
        .final_report
        .expect("immediate mismatch source final report");
    let queued_task = source_report
        .generated_follow_up_tasks
        .first()
        .cloned()
        .expect("immediate mismatch queued task");
    let mut different_plan = queued_task.supervisor_plan;
    different_plan
        .task
        .push_str(" with pre-existing unauthorized plan drift");
    let subordinate_run_id = RunId::new(format!("follow-up-{}", enqueued.item_ids[0]))
        .expect("deterministic immediate mismatch subordinate run id");
    let subordinate_plan_file = temp.path().join("immediate-mismatch-subordinate.json");
    fs::write(
        &subordinate_plan_file,
        serde_json::to_vec_pretty(&different_plan)
            .expect("serialize immediate mismatch subordinate plan"),
    )
    .expect("write immediate mismatch subordinate plan");
    let preexisting_child_dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let preexisting_dispatches = std::sync::Arc::clone(&preexisting_child_dispatches);
    let mut preexisting_runner = move |command: &ExternalAgentCommand| {
        let is_auditor = command
            .output_last_message
            .to_string_lossy()
            .contains("review-auditor");
        if is_auditor {
            let mut child = injected_child_report(&follow_up_assignment);
            child.files_changed = vec![PathBuf::from("src/client.rs")];
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&follow_up_assignment, &child),
            );
        } else {
            let count = preexisting_dispatches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .saturating_add(1);
            assert_eq!(count, 1, "pre-existing mismatched subordinate retried");
            fs::create_dir_all(command.cwd.join("src"))
                .expect("create pre-existing mismatch source dir");
            fs::write(
                command.cwd.join("src/client.rs"),
                "pub fn mismatched() {}\n",
            )
            .expect("write pre-existing mismatch candidate");
            let mut child = injected_child_report(&follow_up_assignment);
            child.files_changed = vec![PathBuf::from("src/client.rs")];
            write_injected_json(&command.output_last_message, &child);
        }
        write_injected_usage(command, 0, 1);
        injected_verified_run(command)
    };
    let preexisting = run_supervisor_plan_file_with_runner(
        SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: subordinate_plan_file,
            run_id: subordinate_run_id,
            parent_node: None,
            codex_bin: PathBuf::from("unused-injected-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: Some(retention),
        },
        &mut preexisting_runner,
    )
    .expect("finalize pre-existing mismatched subordinate");
    assert!(preexisting.success, "{preexisting:#?}");

    let unexpected_resume_dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let unexpected = std::sync::Arc::clone(&unexpected_resume_dispatches);
    let mut resume_runner = move |_command: &ExternalAgentCommand| {
        unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("immediate mismatch reconciliation started a new external dispatch");
    };
    let outcome =
        resume_supervisor_plan_file_cascade_with_runner(source_options, &mut resume_runner)
            .expect("return typed immediate mismatch refusal");
    clear_generated_follow_up_queue_observer();
    let primary_after = verified_whole_primary_snapshot_sha256(&repo)
        .expect("capture immediate mismatch primary after");

    assert!(!outcome.follow_up_cascade_success);
    assert!(!outcome.generated_follow_up_dispatch_performed());
    assert!(outcome.follow_up_reports.is_empty());
    assert!(outcome.follow_up_gate_denials.iter().any(|denial| {
        matches!(
            denial.reason,
            GateDenialReason::ApprovalReview {
                denial: crate::gate_denial::ApprovalReviewDenial::PermissionExpansion
            }
        )
    }));
    let queue = outcome
        .follow_up_queue
        .expect("immediate mismatch queue summary");
    assert_eq!(queue.pending_count, 0);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.held_ambiguous_count, 1);
    assert_eq!(queue.acknowledged_terminal_count, 0);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 0);
    assert_eq!(
        source_child_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        preexisting_child_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        unexpected_resume_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(primary_after, primary_before);
    assert!(!repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum HeldFinalizedSubordinateVariant {
    Exact,
    PlanDrift,
    GeneratesThirdRound,
}

#[cfg(target_os = "linux")]
struct HeldFinalizedSubordinateScenario {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    held_observation: GeneratedFollowUpQueueTestObservation,
    finalized_subordinate: SupervisorFinalReport,
    outcome: SupervisorCascadeOutcome,
    source_child_dispatches: usize,
    subordinate_child_dispatches: usize,
    unexpected_reconciliation_dispatches: usize,
    primary_before: String,
    primary_after: String,
}

#[cfg(target_os = "linux")]
fn run_held_finalized_subordinate_scenario(
    run_name: &str,
    variant: HeldFinalizedSubordinateVariant,
) -> HeldFinalizedSubordinateScenario {
    let (temp, repo) = injected_repository();
    let source_assignment = licensed_assignment();
    let follow_up_assignment = licensed_follow_up_assignment();
    let plan = injected_plan(source_assignment.clone(), 0);
    let source_run_id = RunId::new(run_name).expect("held source run id");
    let source_plan_file = temp.path().join(format!("{run_name}.json"));
    fs::write(
        &source_plan_file,
        serde_json::to_vec_pretty(&plan).expect("serialize held source plan"),
    )
    .expect("write held source plan");
    let retention = secure_machine_global_retention(temp.path(), run_name);
    let source_options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: source_plan_file,
        run_id: source_run_id.clone(),
        parent_node: None,
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(retention.clone()),
    };
    let declaration_sha256 = licensed_breakage_declaration_sha256(
        source_assignment
            .licensed_breakage
            .as_ref()
            .expect("held source declaration"),
    )
    .expect("hash held source declaration");
    let observations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = std::rc::Rc::clone(&observations);
    set_generated_follow_up_queue_observer(move |observation| {
        observed.borrow_mut().push(observation);
    });
    let primary_before =
        verified_whole_primary_snapshot_sha256(&repo).expect("capture held primary before");
    let source_child_dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let source_follow_up_dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut source_runner = |command: &ExternalAgentCommand| {
        let output_path = command.output_last_message.to_string_lossy();
        let is_follow_up = output_path.contains("child-a-licensed-update-01");
        let is_auditor = output_path.contains("review-auditor");
        if is_follow_up {
            source_follow_up_dispatches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            panic!("ambiguous-hold seam reached a subordinate external runner");
        } else if is_auditor {
            write_injected_json(
                &command.output_last_message,
                &licensed_auditor_report(&source_assignment, Some(&declaration_sha256)),
            );
        } else {
            let count = source_child_dispatches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .saturating_add(1);
            assert_eq!(count, 1, "held source child reran");
            fs::write(command.cwd.join("README.md"), "licensed breaking change\n")
                .expect("write held source candidate");
            write_injected_json(
                &command.output_last_message,
                &dependent_failure_child(&source_assignment, "src/client.rs"),
            );
        }
        write_injected_usage(command, 0, 1);
        injected_verified_run(command)
    };

    set_interrupt_after_follow_up_dispatch_started();
    let error =
        run_supervisor_plan_file_cascade_with_runner(source_options.clone(), &mut source_runner)
            .expect_err("interrupt after authenticated ambiguous hold");
    assert!(format!("{error:#}")
        .contains("injected interruption after durable generated follow-up ambiguous hold"));
    assert_eq!(
        source_follow_up_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let held_observation = observations
        .borrow()
        .iter()
        .find(|observation| observation.label == "held_ambiguous")
        .cloned()
        .expect("observe authenticated HeldAmbiguous state");
    assert_eq!(held_observation.held_ambiguous_count, 1);
    assert_eq!(
        held_observation.authenticated_child_dispatch_started_count,
        0
    );
    assert_eq!(held_observation.subordinate_run_ids.len(), 1);
    let subordinate_run_id =
        RunId::new(&held_observation.subordinate_run_ids[0]).expect("held subordinate run id");
    let source_report = supervisor_status(&repo, source_run_id)
        .expect("read finalized held source")
        .final_report
        .expect("held source final report");
    let queued_task = source_report
        .generated_follow_up_tasks
        .first()
        .cloned()
        .expect("held source queued task");
    let mut finalized_plan = queued_task.supervisor_plan.clone();
    if matches!(variant, HeldFinalizedSubordinateVariant::PlanDrift) {
        finalized_plan
            .task
            .push_str(" with unauthorized plan drift");
    }
    let subordinate_plan_file = temp.path().join(format!("{run_name}-subordinate.json"));
    fs::write(
        &subordinate_plan_file,
        serde_json::to_vec_pretty(&finalized_plan).expect("serialize held subordinate plan"),
    )
    .expect("write held subordinate plan");
    if matches!(
        variant,
        HeldFinalizedSubordinateVariant::GeneratesThirdRound
    ) {
        set_before_supervisor_final_report_persist_hook(move |report| {
            report.generated_follow_up_tasks = vec![queued_task.clone()];
        });
    }
    let subordinate_child_dispatches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut subordinate_runner = |command: &ExternalAgentCommand| {
        let output_path = command.output_last_message.to_string_lossy();
        let is_auditor = output_path.contains("review-auditor");
        if is_auditor {
            let mut child = injected_child_report(&follow_up_assignment);
            child.files_changed = vec![PathBuf::from("src/client.rs")];
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&follow_up_assignment, &child),
            );
        } else {
            let count = subordinate_child_dispatches
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .saturating_add(1);
            assert_eq!(count, 1, "held subordinate child reran");
            fs::create_dir_all(command.cwd.join("src"))
                .expect("create held subordinate source dir");
            fs::write(command.cwd.join("src/client.rs"), "pub fn migrated() {}\n")
                .expect("write held subordinate candidate");
            let mut child = injected_child_report(&follow_up_assignment);
            child.files_changed = vec![PathBuf::from("src/client.rs")];
            write_injected_json(&command.output_last_message, &child);
        }
        write_injected_usage(command, 0, 1);
        injected_verified_run(command)
    };
    let finalized_subordinate = run_supervisor_plan_file_with_runner(
        SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: subordinate_plan_file,
            run_id: subordinate_run_id,
            parent_node: None,
            codex_bin: PathBuf::from("unused-injected-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: Some(retention),
        },
        &mut subordinate_runner,
    )
    .expect("finalize deterministic held subordinate through ordinary supervisor");
    assert!(finalized_subordinate.success, "{finalized_subordinate:#?}");

    let unexpected_reconciliation_dispatches =
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let unexpected = std::sync::Arc::clone(&unexpected_reconciliation_dispatches);
    let mut reconciliation_runner = move |_command: &ExternalAgentCommand| {
        unexpected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("HeldAmbiguous reconciliation attempted a new external dispatch");
    };
    let outcome =
        resume_supervisor_plan_file_cascade_with_runner(source_options, &mut reconciliation_runner)
            .expect("reconcile newly finalized HeldAmbiguous subordinate");
    clear_generated_follow_up_queue_observer();
    let primary_after =
        verified_whole_primary_snapshot_sha256(&repo).expect("capture held primary after");

    HeldFinalizedSubordinateScenario {
        _temp: temp,
        repo,
        held_observation,
        finalized_subordinate,
        outcome,
        source_child_dispatches: source_child_dispatches.load(std::sync::atomic::Ordering::SeqCst),
        subordinate_child_dispatches: subordinate_child_dispatches
            .load(std::sync::atomic::Ordering::SeqCst),
        unexpected_reconciliation_dispatches: unexpected_reconciliation_dispatches
            .load(std::sync::atomic::Ordering::SeqCst),
        primary_before,
        primary_after,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn held_ambiguous_reconciles_newly_finalized_exact_subordinate() {
    skip_without_containment!();
    let scenario = run_held_finalized_subordinate_scenario(
        "licensed-held-finalized-exact",
        HeldFinalizedSubordinateVariant::Exact,
    );

    assert!(
        scenario.outcome.follow_up_cascade_success,
        "{:#?}",
        scenario.outcome
    );
    assert!(scenario.outcome.generated_follow_up_dispatch_performed());
    assert!(scenario.outcome.follow_up_gate_denials.is_empty());
    assert_eq!(scenario.outcome.follow_up_reports.len(), 1);
    let queue = scenario
        .outcome
        .follow_up_queue
        .expect("reconciled HeldAmbiguous queue");
    assert_eq!(
        queue.queue_instance_id,
        scenario.held_observation.queue_instance_id
    );
    assert_eq!(queue.pending_count, 0);
    assert_eq!(queue.dispatch_started_count, 0);
    assert_eq!(queue.held_ambiguous_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 1);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 1);
    assert_eq!(scenario.source_child_dispatches, 1);
    assert_eq!(scenario.subordinate_child_dispatches, 1);
    assert_eq!(scenario.unexpected_reconciliation_dispatches, 0);
    assert_eq!(scenario.primary_after, scenario.primary_before);
    assert!(!scenario.repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn held_ambiguous_refuses_finalized_subordinate_plan_drift_without_counting() {
    skip_without_containment!();
    let scenario = run_held_finalized_subordinate_scenario(
        "licensed-held-finalized-plan-drift",
        HeldFinalizedSubordinateVariant::PlanDrift,
    );

    assert!(scenario.finalized_subordinate.success);
    assert!(!scenario.outcome.follow_up_cascade_success);
    assert!(!scenario.outcome.generated_follow_up_dispatch_performed());
    assert!(scenario.outcome.follow_up_reports.is_empty());
    assert!(scenario
        .outcome
        .follow_up_gate_denials
        .iter()
        .any(|denial| {
            matches!(
                denial.reason,
                GateDenialReason::ApprovalReview {
                    denial: crate::gate_denial::ApprovalReviewDenial::PermissionExpansion
                }
            )
        }));
    let queue = scenario
        .outcome
        .follow_up_queue
        .expect("plan-drift HeldAmbiguous queue");
    assert_eq!(queue.held_ambiguous_count, 1);
    assert_eq!(queue.acknowledged_terminal_count, 0);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 0);
    assert_eq!(scenario.source_child_dispatches, 1);
    assert_eq!(scenario.subordinate_child_dispatches, 1);
    assert_eq!(scenario.unexpected_reconciliation_dispatches, 0);
    assert_eq!(scenario.primary_after, scenario.primary_before);
    assert!(!scenario.repo.join("src/client.rs").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn held_ambiguous_finalized_round_two_tasks_refuse_maximum_round() {
    skip_without_containment!();
    let scenario = run_held_finalized_subordinate_scenario(
        "licensed-held-finalized-maximum-round",
        HeldFinalizedSubordinateVariant::GeneratesThirdRound,
    );

    assert_eq!(
        scenario
            .finalized_subordinate
            .generated_follow_up_tasks
            .len(),
        1
    );
    assert!(!scenario.outcome.follow_up_cascade_success);
    assert!(scenario.outcome.generated_follow_up_dispatch_performed());
    assert_eq!(scenario.outcome.follow_up_reports.len(), 1);
    assert!(scenario
        .outcome
        .follow_up_gate_denials
        .iter()
        .any(|denial| {
            matches!(
                denial.reason,
                GateDenialReason::ApprovalReview {
                    denial: crate::gate_denial::ApprovalReviewDenial::PermissionExpansion
                }
            )
        }));
    let queue = scenario
        .outcome
        .follow_up_queue
        .expect("maximum-round HeldAmbiguous queue");
    assert_eq!(queue.held_ambiguous_count, 0);
    assert_eq!(queue.acknowledged_terminal_count, 1);
    assert_eq!(queue.authenticated_child_dispatch_started_count, 1);
    assert_eq!(scenario.source_child_dispatches, 1);
    assert_eq!(scenario.subordinate_child_dispatches, 1);
    assert_eq!(scenario.unexpected_reconciliation_dispatches, 0);
    assert_eq!(scenario.primary_after, scenario.primary_before);
    assert!(!scenario.repo.join("src/client.rs").exists());
}
