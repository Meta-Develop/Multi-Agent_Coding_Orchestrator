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
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: true,
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
fn declared_scoped_breakage_passes_and_journals_dispatch_shaped_follow_up() {
    let assignment = licensed_assignment();
    let child = dependent_failure_child(&assignment, "src/client.rs");
    let scenario = run_licensed_scenario(assignment, child, true, "licensed-breakage-e2e");

    assert!(scenario.report.success, "{:#?}", scenario.report.findings);
    assert_eq!(scenario.report.generated_follow_up_tasks.len(), 1);
    let task = &scenario.report.generated_follow_up_tasks[0];
    assert_eq!(task.breaking_assignment_id, "child-a");
    assert_eq!(task.breaking_change.agent_id, "child-a");
    assert!(!task.breaking_change.diff_oid.is_empty());
    assert_eq!(
        task.assignment.assigned_paths,
        vec![PathBuf::from("src/client.rs")]
    );
    assert_eq!(task.assignment.semantic_symbols, vec![LICENSED_INTERFACE]);
    assert!(task.assignment.licensed_breakage.is_none());
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

    let follow_up_metadata = SupervisorPlanMetadata {
        assignment_schedule: vec![AssignmentScheduleEntry {
            assignment_id: task.assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        }],
        ..SupervisorPlanMetadata::default()
    };
    validate_supervisor_plan(
        injected_plan(task.assignment.clone(), 0),
        follow_up_metadata,
    )
    .expect("generated task remains admissible only through an ordinary validated plan");

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
    assert_eq!(follow_up_events[0].node, task.assignment.id);
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
    assert!(collected.remaining_risk.contains("remain deferred"));
    assert!(supervisor_final_report_schema_value()["properties"]
        .get("generated_follow_up_tasks")
        .is_some());
    assert!(orchestrator_report_schema_value()["properties"]
        .get("licensed_breakage_review")
        .is_some());
}

#[test]
fn licensed_worker_failure_remains_subject_to_child_and_parent_auditor_gates() {
    let mut assignment = licensed_assignment();
    assignment.worker_assignments = vec![WorkerAssignment {
        id: "worker-a".to_string(),
        role: AgentRole::Worker,
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
        &assignment,
        &report,
        &CandidateValidationBinding {
            version: 1,
            agent_id: assignment.id.clone(),
            primary_head: None,
            agent_head: None,
            merge_base: None,
            diff_oid: "licensed-test-diff".to_string(),
        },
    )
    .expect("generate follow-up task fixture");
    {
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut collector,
            checkpoint: None,
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
    let (temp, repo) = injected_repository();
    let assignment = licensed_assignment();
    let plan = injected_plan(assignment.clone(), 0);
    let run_id = RunId::new("licensed-final-report-resume").expect("licensed resume run id");
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: temp.path().join("licensed-final-report-resume.json"),
        run_id: run_id.clone(),
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: true,
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
