use super::*;

fn install_budget_fixture_models() -> InstalledModelCapabilityPolicy {
    install_test_fixture_models(&[
        ("priced-model", ModelCapabilityClass::CriticalJudgment),
        ("unpriced-model", ModelCapabilityClass::CriticalJudgment),
    ])
    .expect("budget fixture capability policy")
}

#[test]
fn budget_integration_plan_sidecar_is_backward_compatible_and_schema_visible() {
    let legacy_source = json!({
        "version": SUPERVISOR_SCHEMA_VERSION,
        "task": "legacy plan",
        "max_child_assignments": 1,
        "assignments": [{
            "id": "child-a",
            "phase": "execution",
            "assigned_paths": ["README.md"]
        }]
    });
    let legacy = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&legacy_source).expect("serialize legacy plan"),
    )
    .expect("parse legacy plan");
    assert!(legacy.plan_metadata.run_budget.is_unconfigured());
    let legacy_normalized = supervisor_plan_value(
        &legacy.plan,
        &legacy.consultant,
        &legacy.assignment_metadata,
        &legacy.plan_metadata,
    )
    .expect("normalize legacy plan");
    assert!(legacy_normalized.get("run_budget").is_none());

    let mut mechanical_source = legacy_source.clone();
    mechanical_source["assignments"][0]["worker_assignments"] = json!([{
        "id": "worker-a",
        "role": "worker",
        "assigned_paths": ["README.md"],
        "mechanical_duty": "run_preselected_command"
    }]);
    let mechanical = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&mechanical_source).expect("serialize mechanical plan"),
    )
    .expect("parse typed mechanical Worker metadata");
    assert_eq!(
        mechanical
            .assignment_metadata
            .get(&("child-a".to_string(), "worker-a".to_string()))
            .and_then(|metadata| metadata.mechanical_duty),
        Some(MechanicalTerminalDuty::RunPreselectedCommand)
    );
    let mechanical_normalized = supervisor_plan_value(
        &mechanical.plan,
        &mechanical.consultant,
        &mechanical.assignment_metadata,
        &mechanical.plan_metadata,
    )
    .expect("normalize typed mechanical Worker metadata");
    assert_eq!(
        mechanical_normalized["assignments"][0]["worker_assignments"][0]["mechanical_duty"],
        "run_preselected_command"
    );

    let mut budget_source = legacy_source;
    budget_source["run_budget"] = json!({
        "soft_tokens": 10,
        "hard_tokens": 20,
        "soft_cost_usd": 0.01,
        "hard_cost_usd": 0.02,
        "max_duration_seconds": 600,
        "role_token_reservations": {
            "child_orchestrator": 10,
            "auditor": 10
        }
    });
    let loaded = parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&budget_source).expect("serialize budget plan"),
    )
    .expect("parse budget plan");
    assert_eq!(
        loaded.plan_metadata.run_budget.limits,
        RunBudgetLimits {
            soft_tokens: Some(10),
            hard_tokens: Some(20),
            soft_cost_usd: Some(0.01),
            hard_cost_usd: Some(0.02),
        }
    );
    assert_eq!(
        loaded.plan_metadata.run_budget_max_duration_seconds,
        Some(600)
    );
    let normalized = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
    .expect("normalize budget plan");
    assert_eq!(normalized["run_budget"], budget_source["run_budget"]);

    budget_source["run_budget"]["max_duration_seconds"] = json!(0);
    assert!(parse_supervisor_plan_with_consultant(
        &serde_json::to_string(&budget_source).expect("serialize invalid duration budget")
    )
    .expect_err("zero duration budget must fail")
    .to_string()
    .contains("run_budget.max_duration_seconds must be greater than zero"));

    let schema = supervisor_final_report_schema_value();
    let required = schema["properties"]["run_budget"]["required"]
        .as_array()
        .expect("run budget required fields");
    for field in [
        "consumed",
        "reserved",
        "committed",
        "remaining",
        "elapsed_seconds",
        "usage_complete",
        "action",
        "new_dispatch_allowed",
    ] {
        assert!(
            required.iter().any(|value| value == field),
            "run budget schema omitted {field}"
        );
    }
    assert!(
        schema["properties"]["run_budget"]["properties"]["reasons"]["items"]["enum"]
            .as_array()
            .is_some_and(|reasons| reasons
                .iter()
                .any(|reason| reason == "missing_provider_usage"))
    );
    assert!(
        schema["properties"]["run_budget"]["properties"]["reasons"]["items"]["enum"]
            .as_array()
            .is_some_and(|reasons| reasons
                .iter()
                .any(|reason| reason == "max_duration_reached"))
    );
    assert_eq!(
        schema["properties"]["run_budget"]["properties"]["sources"]["required"],
        serde_json::json!(["plan", "cli"])
    );
    let autonomy = &schema["properties"]["autonomy_kpis"];
    let required = autonomy["required"]
        .as_array()
        .expect("autonomy KPI required fields");
    for field in [
        "population",
        "coverage",
        "actions_reviewed",
        "denials",
        "self_corrections",
        "human_escalations",
        "interrupted",
    ] {
        assert!(
            required.iter().any(|value| value == field),
            "autonomy KPI schema omitted {field}"
        );
    }
    assert!(autonomy["properties"]["observation"]["enum"]
        .as_array()
        .is_some_and(|observations| observations
            .iter()
            .any(|observation| observation == "not_process_observable")));
    assert_eq!(
        autonomy["properties"]["population"]["const"],
        "reviewed_gate_actions"
    );
    let coverage = &autonomy["properties"]["coverage"];
    let coverage_required = coverage["required"]
        .as_array()
        .expect("autonomy KPI coverage required fields");
    for field in [
        "review_decisions",
        "reviewed_denial_terminal_lifecycles",
        "human_follow_up_responses",
        "scheduler_budget_denial_lifecycles",
        "rate_denominators",
    ] {
        assert!(
            coverage_required.iter().any(|value| value == field),
            "autonomy KPI coverage schema omitted {field}"
        );
        assert!(
            coverage["properties"][field]["properties"]["observation"]["enum"]
                .as_array()
                .is_some_and(|observations| observations
                    .iter()
                    .any(|observation| observation == "not_process_observable"))
        );
    }
    let degradations = &schema["properties"]["role_economics_profile"]["properties"]["execution"]
        ["properties"]["budget_degradations"]["items"];
    assert!(degradations["required"]
        .as_array()
        .is_some_and(|required| required.iter().any(|field| field == "trigger")));
    assert!(degradations["properties"]["trigger"]["enum"]
        .as_array()
        .is_some_and(|triggers| triggers
            .iter()
            .any(|trigger| trigger == "low_difficulty_mechanical")));
    assert_eq!(
        degradations["properties"]["role_binding_transition"]["properties"]["before"]["required"],
        json!(["model", "reasoning_effort"])
    );
}

#[test]
fn budget_integration_serial_scheduler_accounts_exact_hard_boundary_by_process_role() {
    skip_without_containment!();
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(20), None, None, 10, 10);
    let options = injected_options(&repo_path, temp.path(), "budget-serial-exact-hard");
    let mut invocations = 0usize;
    let mut runner = |command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            let child = injected_child_report(&assignment);
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
        } else {
            write_injected_assignment_report(command, &assignment);
        }
        write_injected_usage(command, 7, 3);
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("run serial budget boundary");

    assert!(report.success, "unexpected failed report: {report:#?}");
    assert_eq!(invocations, 2);
    assert_eq!(report.total_usage.map(|usage| usage.total_tokens), Some(20));
    let budget = report.run_budget.expect("final run budget");
    assert_eq!(budget.consumed.tokens, 20);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.committed.tokens, 20);
    assert_eq!(budget.active_reservations, 0);
    assert!(budget.usage_complete);
    assert!(!budget.new_dispatch_allowed);
    assert_eq!(budget.action, BudgetAction::OwnerEscalation);
    assert!(budget
        .reasons
        .contains(&BudgetReason::HardTokenCeilingReached));
    assert_eq!(
        budget
            .roles
            .iter()
            .find(|role| role.role == AgentRole::ChildOrchestrator)
            .map(|role| role.consumed.tokens),
        Some(10)
    );
    assert_eq!(
        budget
            .roles
            .iter()
            .find(|role| role.role == AgentRole::Auditor)
            .map(|role| role.consumed.tokens),
        Some(10)
    );
}

#[test]
fn budget_integration_auditor_admission_refusal_reaches_typed_child_and_final_reports() {
    skip_without_containment!();
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(15), None, None, 10, 10);
    let options = injected_options(&repo_path, temp.path(), "budget-auditor-typed-denial");
    let mut invocations = 0usize;
    let mut runner = |command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        assert!(
            !command
                .output_last_message
                .to_string_lossy()
                .contains("review-auditor"),
            "auditor must be refused before launch"
        );
        write_injected_assignment_report(command, &assignment);
        write_injected_usage(command, 7, 3);
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("finalize typed auditor budget refusal");

    assert!(!report.success);
    assert_eq!(invocations, 1);
    let budget = report.run_budget.as_ref().expect("auditor budget report");
    assert_eq!(budget.consumed.tokens, 10);
    assert!(!budget.new_dispatch_allowed);
    assert!(budget
        .reasons
        .contains(&BudgetReason::HardTokenCeilingReached));
    assert_eq!(report.gate_denials.len(), 1);
    let denial = &report.gate_denials[0];
    assert_eq!(
        denial.reason,
        GateDenialReason::BudgetAdmission {
            denial: BudgetAdmissionDenial::HardTokenCeiling,
        }
    );
    assert_eq!(denial.context.source, GateCheckSource::BudgetAdmission);
    assert_eq!(denial.route, GateDenialRoute::ChildController);
    assert_eq!(denial.retryability, GateRetryability::NotRetryable);
    let child = report
        .orchestrator_reports
        .first()
        .expect("failed child report retained");
    assert_eq!(child.gate_denials, report.gate_denials);
    assert_eq!(
        child.gate_correction_outcomes,
        report.gate_correction_outcomes
    );
    assert!(child
        .findings
        .iter()
        .all(|finding| !finding.message.contains("BudgetAdmissionRefusal")));
    assert!(report
        .findings
        .iter()
        .all(|finding| !finding.message.contains("BudgetAdmissionRefusal")));
    assert_eq!(
        report.autonomy_kpis.observation,
        RoleUsageObservation::SupervisorAggregate
    );
    assert_eq!(
        report.autonomy_kpis.population,
        AutonomyKpiPopulation::ReviewedGateActions
    );
    assert_eq!(
        report
            .autonomy_kpis
            .coverage
            .scheduler_budget_denial_lifecycles
            .observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(report
        .autonomy_kpis
        .coverage
        .scheduler_budget_denial_lifecycles
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("do not produce gate correction lifecycle")));
}

#[test]
fn budget_integration_cost_enforcement_refuses_missing_model_pricing_before_launch() {
    assert_unpriced_dispatch_refused("unpriced-model");
}

#[test]
fn pricing_guard_placeholder_refuses_before_runner_invocation() {
    assert_unpriced_dispatch_refused("gpt-5.6-sol");
}

fn assert_unpriced_dispatch_refused(model: &str) {
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment, 0);
    let selection = RoleModelSelection {
        model: Some(model.to_string()),
        reasoning_effort: None,
        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
    };
    plan.role_models
        .insert(AgentRole::ChildOrchestrator, selection.clone());
    plan.role_models.insert(AgentRole::Auditor, selection);
    let budget = injected_run_budget(None, Some(100), None, Some(1.0), 50, 50);
    let options = injected_options(&repo_path, temp.path(), "budget-missing-pricing");
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("missing pricing must refuse before invoking the external runner")
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("finalize missing pricing refusal");

    assert!(!report.success);
    assert_eq!(invocations, 0);
    let budget = report.run_budget.expect("missing pricing budget report");
    assert_eq!(budget.consumed.tokens, 0);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    assert!(budget.usage_complete);
    assert!(!budget.new_dispatch_allowed);
    assert!(budget.reasons.contains(&BudgetReason::MissingPricing));
    assert_eq!(budget.action, BudgetAction::OwnerEscalation);
    assert_eq!(report.released_claims.len(), 1);
    assert!(report.release_errors.is_empty());
    assert_eq!(report.gate_denials.len(), 1);
    let denial = &report.gate_denials[0];
    assert_eq!(
        denial.reason,
        GateDenialReason::BudgetAdmission {
            denial: BudgetAdmissionDenial::MissingCostEstimate,
        }
    );
    assert_eq!(denial.context.source, GateCheckSource::BudgetAdmission);
    assert_eq!(denial.route, GateDenialRoute::ChildController);
    assert_eq!(denial.retryability, GateRetryability::NotRetryable);
    assert_eq!(
        denial.next_safe_operation,
        crate::gate_denial::NextSafeOperation::ReviewRunBudgetAndStartNewRun
    );
    assert!(report
        .findings
        .iter()
        .all(|finding| !finding.message.contains("BudgetAdmissionRefusal")));
}

#[test]
fn budget_integration_concurrent_scheduler_cannot_oversubscribe_and_drains_admitted_work() {
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "a.txt"),
        injected_named_assignment("child-b", "b.txt"),
    ];
    let mut plan = injected_multi_plan(assignments.clone(), 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(100), None, None, 60, 40);
    let options = injected_options(
        &repo_path,
        temp.path(),
        "budget-concurrent-oversubscription",
    );
    let child_invocations = Arc::new(AtomicUsize::new(0));
    let runner = {
        let child_invocations = Arc::clone(&child_invocations);
        let assignments = assignments.clone();
        move |command: &ExternalAgentCommand| {
            let name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            let assignment = assignments
                .iter()
                .find(|assignment| name.starts_with(&assignment.id))
                .unwrap_or_else(|| panic!("missing assignment for {name}"));
            if name.contains("review-auditor") {
                let child = injected_child_report(assignment);
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(assignment, &child),
                );
                write_injected_usage(command, 30, 10);
            } else {
                child_invocations.fetch_add(1, Ordering::SeqCst);
                write_injected_assignment_report(command, assignment);
                write_injected_usage(command, 45, 15);
            }
            injected_verified_run(command)
        }
    };

    let report = run_supervisor_plan_with_budget_and_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        2,
        &runner,
    )
    .expect("finalize concurrent budget refusal");

    assert!(!report.success);
    assert_eq!(child_invocations.load(Ordering::SeqCst), 1);
    let budget = report.run_budget.expect("concurrent budget report");
    assert!(matches!(budget.consumed.tokens, 60 | 100));
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    assert!(!budget.new_dispatch_allowed);
    assert!(budget
        .reasons
        .contains(&BudgetReason::HardTokenCeilingReached));
    assert_eq!(report.released_claims.len(), 2);
    assert!(report.release_errors.is_empty());
    assert_eq!(report.orchestrator_reports.len(), 1);
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("run budget stopped one or more new dispatches")));
}

#[cfg(target_os = "linux")]
#[test]
fn budget_integration_concurrent_scheduler_waits_for_full_live_grant_and_resumes() {
    exercise_live_grant_scheduler(false);
}

#[cfg(target_os = "linux")]
#[test]
fn budget_integration_parent_reviews_wait_for_another_live_grant() {
    exercise_live_grant_scheduler(true);
}

#[cfg(target_os = "linux")]
fn exercise_live_grant_scheduler(interleave_review: bool) {
    use crate::external_agent::codex_app_server::{
        CommandExecutionEvidence, CommandExecutionObservation, CommandExecutionSnapshot,
        CommandExecutionStatus, TurnTerminalStatus,
    };
    use crate::external_agent::{
        CodexParentEvidence, CodexParentResolvedField, CodexParentTurnUsage,
    };

    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let assignments = ["a.txt", "b.txt"]
        .into_iter()
        .enumerate()
        .map(|(index, path)| {
            let mut assignment = injected_named_assignment(&format!("research-{index}"), path);
            assignment.role = AgentRole::Researcher;
            assignment.role_category = Some(RoleCategory::ReadOnlyResearcher);
            assignment
        })
        .collect::<Vec<_>>();
    let mut plan = injected_multi_plan(assignments.clone(), 0);
    if interleave_review {
        plan.review_lenses = default_supervisor_review_lenses();
    }
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    plan.role_models.insert(
        AgentRole::Researcher,
        plan.role_models[&AgentRole::ChildOrchestrator].clone(),
    );
    let mut budget = injected_run_budget(None, Some(220_000), None, None, 16_384, 1_000);
    budget
        .role_token_reservations
        .insert(AgentRole::Researcher, 16_384);
    let run_id = if interleave_review {
        "budget-live-review-interleave"
    } else {
        "budget-live-grant-admission"
    };
    let options = injected_options(&repo_path, temp.path(), run_id);
    let (sender, receiver) = std::sync::mpsc::channel();
    if !interleave_review {
        crate::supervise::scheduler::set_live_grant_admission_observer(sender);
    }
    let receiver = std::sync::Mutex::new(receiver);
    // Setup includes real containment/worktree preparation. Synchronize on its
    // completion (or an explicit participant exit), not a wall-clock guess.
    // Only the actual live-grant contention below has a ten-second deadline.
    let (review_ready_tx, review_ready_rx) = std::sync::mpsc::channel::<Result<(), &'static str>>();
    let review_ready_rx = std::sync::Mutex::new(review_ready_rx);
    let (b_started_tx, b_started_rx) = std::sync::mpsc::channel::<Result<(), &'static str>>();
    let b_started_rx = std::sync::Mutex::new(b_started_rx);
    let (a_waiting_tx, a_waiting_rx) = std::sync::mpsc::channel();
    let a_waiting_rx = std::sync::Mutex::new(a_waiting_rx);
    let first_review = AtomicUsize::new(0);
    let b_admitted = std::sync::atomic::AtomicBool::new(false);
    let waiting_observations = Arc::new(AtomicUsize::new(0));
    let _hook = interleave_review.then(|| {
        let waiting_observations = Arc::clone(&waiting_observations);
        let b_preparation_tx = b_started_tx.clone();
        install_budget_admission_test_hook(
            run_id,
            Arc::new(move |stage, owner| match stage {
                "admission_committed" if owner == "research-0" => {
                    review_ready_rx
                        .lock()
                        .unwrap()
                        .recv()
                        .expect("A preparation lifecycle remains connected")
                        .expect("A reached mandatory review after settlement");
                }
                "admission_committed" if owner == "research-1" => {
                    b_admitted.store(true, Ordering::SeqCst);
                }
                "before_review_admission"
                    if owner == "research-0"
                        && first_review.fetch_add(1, Ordering::SeqCst) == 0 =>
                {
                    review_ready_tx.send(Ok(())).unwrap();
                    b_started_rx
                        .lock()
                        .unwrap()
                        .recv()
                        .expect("B preparation lifecycle remains connected")
                        .expect("B holds remaining grant");
                }
                "waiting_for_grant" if owner.starts_with("research-0") => {
                    waiting_observations.fetch_add(1, Ordering::SeqCst);
                    a_waiting_tx.send(()).unwrap();
                }
                "assignment_finished" if owner == "research-0" => {
                    let _ = review_ready_tx.send(Err("A exited before mandatory review"));
                }
                "assignment_finished" if owner == "research-1" => {
                    let _ = b_preparation_tx.send(Err("B exited before holding its live grant"));
                }
                "scheduler_draining" if !b_admitted.load(Ordering::SeqCst) => {
                    let _ = b_preparation_tx.send(Err("scheduler drained without admitting B"));
                }
                "scheduler_finished" => {
                    let _ = review_ready_tx.send(Err("scheduler exited during A preparation"));
                    let _ = b_preparation_tx.send(Err("scheduler exited during B preparation"));
                }
                _ => {}
            }),
        )
    });
    let child_invocations = AtomicUsize::new(0);
    let audit_invocations = AtomicUsize::new(0);
    let runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap();
        let assignment = assignments
            .iter()
            .find(|assignment| name.starts_with(&assignment.id))
            .unwrap();
        let mut child = injected_child_report(assignment);
        child.role = AgentRole::Researcher;
        child.validation_results.clear();
        let mut inspection = injected_command_record();
        inspection.command = vec!["git status".to_string()];
        inspection.cwd = command.cwd.clone();
        inspection.timeout_seconds = 0;
        inspection.duration_ms = 0;
        child.commands_run.push(inspection);
        child.validation_results.push(ValidationResult {
            name: "read-only inspection".to_string(),
            status: ReviewStatus::Succeeded,
            command: vec!["git status".to_string()],
            message: None,
        });
        if name.contains("review-auditor") {
            if interleave_review && assignment.id == "research-0" {
                assert!(
                    waiting_observations.load(Ordering::SeqCst) > 0,
                    "A must resume from live-grant admission waiting before any audit runs"
                );
            }
            audit_invocations.fetch_add(1, Ordering::SeqCst);
            let mut audit = injected_auditor_report(assignment, &child);
            audit.id = name.strip_suffix(".json").unwrap().to_string();
            write_injected_json(&command.output_last_message, &audit);
            write_injected_usage(command, 900, 100);
            return injected_verified_run(command);
        }
        let ordinal = child_invocations.fetch_add(1, Ordering::SeqCst);
        let grant = command
            .live_token_grant_for_test()
            .expect("trusted active grant");
        if ordinal == 0 {
            assert_eq!(grant.tokens(), 220_000);
            // Hold the first turn until the real scheduler has inspected its full
            // reservation. Without the wait fix, it permanently denies the second child.
            if !interleave_review {
                assert_eq!(
                    receiver
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap(),
                    220_000
                );
            }
        } else {
            assert!(grant.tokens() > 37_000);
            assert!(grant.tokens() <= 183_000);
            if interleave_review {
                assert_eq!(grant.tokens(), 183_000);
                b_started_tx.send(Ok(())).unwrap();
                a_waiting_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .expect("A actually waits in mandatory review admission");
            }
        }
        assert!(!grant.stopped(), "held capacity must not cancel its owner");
        let mut wire = serde_json::to_value(&child).unwrap();
        wire["read_only"] = json!(true);
        wire["no_further_delegation"] = json!(true);
        write_injected_json(&command.output_last_message, &wire);
        let mut run = injected_verified_run(command);
        let started = CommandExecutionSnapshot {
            command: "git status".to_string(),
            cwd: command.cwd.to_string_lossy().into_owned(),
            status: CommandExecutionStatus::InProgress,
            exit_code: None,
        };
        run.set_codex_command_execution_evidence_for_test(CommandExecutionEvidence {
            thread_id: assignment.id.clone(),
            turn_id: "turn".to_string(),
            turn_status: TurnTerminalStatus::Completed,
            observations: vec![CommandExecutionObservation::Complete {
                item_id: "inspection".to_string(),
                completed: CommandExecutionSnapshot {
                    status: CommandExecutionStatus::Completed,
                    exit_code: Some(0),
                    ..started.clone()
                },
                started,
            }],
        });
        run.codex_parent_evidence = Some(CodexParentEvidence {
            codex_version: Some("0.144.4".to_string()),
            thread_id: Some(assignment.id.clone()),
            requested_model: command.model.clone(),
            requested_effort: command.reasoning_effort.clone(),
            rollout_model: CodexParentResolvedField::Unknown,
            rollout_effort: CodexParentResolvedField::Unknown,
            observed_model: CodexParentResolvedField::Known("priced-model".to_string()),
            observed_effort: CodexParentResolvedField::Known("xhigh".to_string()),
            server_rerouted_model: None,
            model_mismatch: false,
            turn_usage: CodexParentTurnUsage::Known {
                input_tokens: 35_000,
                output_tokens: 2_000,
                cached_input_tokens: 0,
                reasoning_output_tokens: 0,
            },
            resolution_status: "complete".to_string(),
        });
        run.retain_app_server_parent_evidence_for_test();
        run
    };
    let report = run_supervisor_plan_with_budget_and_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        2,
        &runner,
    )
    .expect("complete pending researcher after live grant settlement");
    assert_eq!(
        child_invocations.load(Ordering::SeqCst),
        2,
        "{:?}",
        report.findings
    );
    if interleave_review {
        assert!(waiting_observations.load(Ordering::SeqCst) > 0);
        assert_eq!(audit_invocations.load(Ordering::SeqCst), 6, "{report:#?}");
        for child in &report.orchestrator_reports {
            assert_eq!(child.audit_reports.len(), 3, "{child:#?}");
            assert!(child.accepted, "{child:#?}");
        }
        assert!(report.success, "{report:#?}");
    }
    let budget = report.run_budget.unwrap();
    if interleave_review {
        assert_eq!(budget.consumed.tokens, 80_000);
    }
    assert!(budget.consumed.tokens >= 74_000);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    assert!(budget.usage_complete);
    assert!(budget.new_dispatch_allowed);
    assert!(!budget
        .reasons
        .contains(&BudgetReason::HardTokenCeilingReached));
    assert!(!report.findings.iter().any(|finding| finding
        .message
        .contains("run budget stopped one or more new dispatches")));
}

#[test]
fn budget_integration_scheduler_preserves_judgment_bindings_before_halt() {
    let (temp, repo_path) = injected_repository();
    let assignments = (0..7)
        .map(|index| {
            injected_named_assignment(
                &format!("degrade-child-{index}"),
                &format!("degrade-{index}.txt"),
            )
        })
        .collect::<Vec<_>>();
    let plan = injected_multi_plan(assignments.clone(), 0);
    let budget = injected_run_budget(Some(10), Some(60), None, None, 10, 1);
    let run_id = "budget-degrade-production-scheduler";
    let mut options = injected_options(&repo_path, temp.path(), run_id);
    options.admission_overrides = SupervisorAdmissionConfig {
        provider_inflight_limit: Some(8),
        host_memory_available_mib: Some(8_192),
        host_memory_per_child_mib: Some(1_024),
        host_fd_available: Some(1_024),
        host_fds_per_child: Some(128),
        host_disk_available_mib: Some(4_096),
        host_disk_per_child_mib: Some(512),
        ..SupervisorAdmissionConfig::default()
    };
    let child_bindings = Arc::new(Mutex::new(BTreeMap::<String, (String, String)>::new()));
    let runner = {
        let child_bindings = Arc::clone(&child_bindings);
        let assignments = assignments.clone();
        move |command: &ExternalAgentCommand| {
            let name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            let assignment = assignments
                .iter()
                .find(|assignment| name.starts_with(&assignment.id))
                .unwrap_or_else(|| panic!("missing assignment for {name}"));
            if name.contains("review-auditor") {
                let child = injected_child_report(assignment);
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(assignment, &child),
                );
            } else {
                child_bindings
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(
                        assignment.id.clone(),
                        (
                            command.model.clone().expect("resolved child model"),
                            command
                                .reasoning_effort
                                .clone()
                                .expect("resolved child effort"),
                        ),
                    );
                write_injected_assignment_report(command, assignment);
            }
            write_injected_usage(command, 7, 3);
            injected_verified_run(command)
        }
    };

    let report = run_supervisor_plan_with_budget_and_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        8,
        &runner,
    )
    .expect("finalize production scheduler degradation run");

    assert!(
        !report.success,
        "hard halt must leave the final assignment pending"
    );
    let child_bindings = child_bindings
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(child_bindings.len(), 6);
    assert_eq!(
        child_bindings["degrade-child-0"],
        (FRONTIER_PROFILE_MODEL.to_string(), "xhigh".to_string())
    );
    assert_eq!(
        child_bindings["degrade-child-1"],
        (FRONTIER_PROFILE_MODEL.to_string(), "xhigh".to_string())
    );
    assert_eq!(
        child_bindings["degrade-child-2"],
        (FRONTIER_PROFILE_MODEL.to_string(), "xhigh".to_string())
    );
    assert!(!child_bindings.contains_key("degrade-child-6"));

    let execution = report
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.execution.as_ref())
        .expect("execution telemetry");
    assert_eq!(execution.budget_degradations.len(), 1);
    assert!(matches!(
        execution.budget_degradations[0].change,
        BudgetDegradationChange::Halt { .. }
    ));
    assert_ne!(
        execution.role_bindings[&AgentRole::ChildOrchestrator].observation,
        RoleBindingObservation::AssignmentSpecific,
        "budget pressure must not degrade a judgment binding"
    );
    assert_eq!(
        execution
            .assignment_effort_bindings
            .iter()
            .filter(|binding| binding.role == AgentRole::ChildOrchestrator)
            .map(|binding| {
                (
                    binding.assignment_id.as_str(),
                    binding.resolved_reasoning_effort.as_str(),
                )
            })
            .take(3)
            .collect::<Vec<_>>(),
        vec![
            ("degrade-child-0", "xhigh"),
            ("degrade-child-1", "xhigh"),
            ("degrade-child-2", "xhigh"),
        ]
    );
    let degraded_child_binding = execution
        .assignment_effort_bindings
        .iter()
        .find(|binding| {
            binding.role == AgentRole::ChildOrchestrator
                && binding.assignment_id == "degrade-child-1"
        })
        .expect("first budget-degraded child admission binding");
    // Judgment-role (child orchestrator) effort bindings are preserved under
    // budget pressure: the merged degradation ladder degrades worker model
    // tier/effort only, so the child stays on its role fallback.
    assert_eq!(
        degraded_child_binding.resolution_observation,
        EffortResolutionObservation::RoleFallback
    );
    assert!(degraded_child_binding
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| {
            reason.contains("admission-only") && reason.contains("selection_decisions")
        }));

    let persisted: serde_json::Value = serde_json::from_slice(
        &fs::read(
            repo_path
                .join(RunArtifactFamily::Supervise.run_root())
                .join(run_id)
                .join(RunArtifactFamily::Supervise.final_report_relative_path()),
        )
        .expect("persisted supervisor-final.json"),
    )
    .expect("parse persisted supervisor-final.json");
    assert_eq!(
        persisted["role_economics_profile"]["execution"]["budget_degradations"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn budget_integration_parseable_partial_usage_from_failed_run_is_estimated_and_latched() {
    assert_parseable_partial_usage_is_conservative(
        "budget-partial-usage-failed",
        ParseablePartialRunOutcome::Failed,
    );
}

#[test]
fn budget_integration_parseable_partial_usage_from_timeout_is_estimated_and_latched() {
    assert_parseable_partial_usage_is_conservative(
        "budget-partial-usage-timeout",
        ParseablePartialRunOutcome::TimedOut,
    );
}

fn assert_budget_pre_runner_dispatch_cleanup(
    report: &SupervisorFinalReport,
    repo: &Path,
    run_id: &str,
    started_worktree: &str,
    unstarted_worktrees: &[&str],
    expected_paths: &[PathBuf],
) {
    assert_eq!(report.released_claims.len(), 1);
    assert!(report.release_errors.is_empty());
    assert_eq!(report.released_semantic_intents.len(), 1);
    assert_eq!(report.released_semantic_intents[0].agent_id, "child-a");
    assert_eq!(
        report.released_semantic_intents[0].paths,
        expected_paths.to_vec()
    );
    assert!(report.semantic_release_errors.is_empty());
    assert!(report.breaker_trip.is_none());
    assert!(report.gate_denials.is_empty());
    assert!(report.gate_correction_outcomes.is_empty());
    assert!(SyncStore::open(repo)
        .expect("reopen lifecycle sync store")
        .snapshot()
        .expect("snapshot lifecycle claims")
        .is_empty());
    assert!(SemanticIntentStore::open(repo)
        .expect("reopen lifecycle semantic store")
        .snapshot()
        .expect("snapshot lifecycle semantic intents")
        .is_empty());

    let run_root = repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id);
    let scratch_entries = fs::read_dir(&run_root)
        .expect("read finalized lifecycle artifact root")
        .map(|entry| {
            entry
                .expect("read lifecycle artifact entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("incoming") || name.starts_with("capture"))
        .collect::<Vec<_>>();
    assert!(
        scratch_entries.is_empty(),
        "invocation scratch artifacts leaked: {scratch_entries:?}"
    );
    assert!(run_root.join(ARTIFACT_FINALIZATION_MARKER).exists());

    let manager = WorktreeManager::new(repo);
    let records = manager.list().expect("list lifecycle worktrees");
    assert!(records.iter().any(|record| record.name == started_worktree));
    for unstarted in unstarted_worktrees {
        assert!(
            records.iter().all(|record| record.name != *unstarted),
            "pending assignment worktree {unstarted} was unexpectedly created"
        );
    }
    let lease = manager
        .acquire_write_execution_lease(started_worktree)
        .expect("started worktree execution lease must be released");
    drop(lease);
}

#[test]
fn budget_lifecycle_child_pre_runner_failure_releases_reservation_and_stops_pending() {
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    // Sync coordination accepts this claim set, but ReviewContext rejects more than 256 rules.
    let malformed_claims = (0..257)
        .map(|index| PathBuf::from(format!("claims/claim-{index:03}.txt")))
        .collect::<Vec<_>>();
    let mut child_a = injected_named_assignment("child-a", "README.md");
    child_a.assigned_paths = malformed_claims.clone();
    let child_b = injected_named_assignment("child-b", "src/lib.rs");
    let mut plan = injected_multi_plan(vec![child_a, child_b], 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(200), None, None, 50, 50);
    let run_id = "budget-child-pre-runner-release";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| -> ExternalAgentRun {
        invocations = invocations.saturating_add(1);
        panic!("pre-runner child failure must not invoke an external runner")
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("finalize child pre-runner failure");

    assert!(!report.success);
    assert_eq!(invocations, 0);
    assert!(report.usage_complete);
    assert!(report.findings.iter().any(|finding| {
        finding
            .message
            .contains("failed to construct pre-action review context")
            && finding.message.contains("claim rule count exceeds")
    }));
    let budget = report.run_budget.as_ref().expect("child lifecycle budget");
    assert_eq!(budget.consumed.tokens, 0);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    assert!(budget.usage_complete);
    assert!(budget.new_dispatch_allowed);
    assert_eq!(budget.action, BudgetAction::Continue);
    assert!(budget.reasons.is_empty());
    assert_eq!(
        budget
            .roles
            .iter()
            .find(|role| role.role == AgentRole::ChildOrchestrator)
            .map(|role| (role.consumed.tokens, role.usage_complete)),
        Some((0, true))
    );
    assert_budget_pre_runner_dispatch_cleanup(
        &report,
        &repo_path,
        run_id,
        "child-a",
        &["child-b"],
        &malformed_claims,
    );
}

#[test]
fn budget_lifecycle_oversized_child_intent_reaches_runner_once() {
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let mut child = injected_named_assignment("child-a", "README.md");
    child.task = Some("x".repeat(8 * 1024 + 1));
    let mut plan = injected_plan(child.clone(), 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(200), None, None, 50, 50);
    let options = injected_options(&repo_path, temp.path(), "budget-oversized-child-intent");
    let mut invocations = 0usize;
    let mut runner = |command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        assert_eq!(injected_command_assignment_id(command), "child-a");
        write_injected_assignment_report(command, &child);
        write_injected_usage(command, 7, 3);
        injected_verified_nonzero_run(command, 17)
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("finalize oversized child intent after runner execution");

    assert!(!report.success);
    assert_eq!(invocations, 1);
    assert!(report
        .orchestrator_reports
        .iter()
        .any(|orchestrator| orchestrator.id == "child-a"));
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("child orchestrator 'child-a' failed")));
    assert!(report.findings.iter().all(|finding| !finding
        .message
        .contains("failed to construct pre-action review context")));
}

#[test]
fn budget_lifecycle_auditor_pre_runner_failure_releases_reservation_and_stops_pending() {
    skip_without_containment!();
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let child_a = injected_assignment(true);
    let child_b = injected_named_assignment("child-b", "src/lib.rs");
    let mut plan = injected_multi_plan(vec![child_a.clone(), child_b], 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(200), None, None, 50, 50);
    let run_id = "budget-auditor-pre-runner-release";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let mut invocations = 0usize;
    let mut runner = |command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        assert!(!name.contains("review-auditor"));
        assert!(name.starts_with("child-a"));
        write_injected_assignment_report(command, &child_a);
        write_injected_usage(command, 7, 3);
        set_dispatch_pre_runner_fault(AgentRole::Auditor);
        let mut run = injected_verified_run(command);
        retain_priced_single_turn_fixture(
            &mut run,
            command,
            "priced-model",
            &fs::read(&command.json_log).expect("complete child capture"),
        );
        run
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("finalize auditor pre-runner failure");

    assert!(!report.success);
    assert_eq!(invocations, 1);
    assert!(report.usage_complete);
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("injected 'auditor' pre-runner preparation failure")));
    let budget = report
        .run_budget
        .as_ref()
        .expect("auditor lifecycle budget");
    assert_eq!(budget.consumed.tokens, 10);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    assert!(budget.usage_complete);
    assert!(budget.new_dispatch_allowed);
    assert_eq!(budget.action, BudgetAction::Continue);
    assert!(budget.reasons.is_empty());
    assert_eq!(
        budget
            .roles
            .iter()
            .find(|role| role.role == AgentRole::Auditor)
            .map(|role| (role.consumed.tokens, role.usage_complete)),
        Some((0, true))
    );
    assert_injected_dispatch_cleanup(&report, &repo_path, run_id, "child-a", &["child-b"], false);
}

#[test]
fn budget_lifecycle_child_runner_panic_reconciles_missing_and_stops_pending() {
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let child_a = injected_named_assignment("child-a", "README.md");
    let child_b = injected_named_assignment("child-b", "src/lib.rs");
    let mut plan = injected_multi_plan(vec![child_a, child_b], 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(200), None, None, 50, 50);
    let run_id = "budget-child-runner-panic";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| -> ExternalAgentRun {
        invocations = invocations.saturating_add(1);
        panic!("injected child runner panic")
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("finalize child runner panic");

    assert!(!report.success);
    assert_eq!(invocations, 1);
    assert!(!report.usage_complete);
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("supervisor assignment 'child-a' panicked")));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("conservatively reconciled")));
    let budget = report.run_budget.as_ref().expect("child panic budget");
    assert_eq!(budget.consumed.tokens, 50);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    assert!(!budget.usage_complete);
    assert!(!budget.new_dispatch_allowed);
    assert_eq!(budget.action, BudgetAction::OwnerEscalation);
    assert!(budget.reasons.contains(&BudgetReason::MissingProviderUsage));
    assert_eq!(
        budget
            .roles
            .iter()
            .find(|role| role.role == AgentRole::ChildOrchestrator)
            .map(|role| (role.consumed.tokens, role.usage_complete)),
        Some((50, false))
    );
    assert_injected_dispatch_cleanup(&report, &repo_path, run_id, "child-a", &["child-b"], true);
}

#[test]
fn budget_lifecycle_auditor_runner_panic_reconciles_missing_and_stops_pending() {
    skip_without_containment!();
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let child_a = injected_assignment(true);
    let child_b = injected_named_assignment("child-b", "src/lib.rs");
    let mut plan = injected_multi_plan(vec![child_a.clone(), child_b], 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(200), None, None, 50, 50);
    let run_id = "budget-auditor-runner-panic";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let mut invocations = 0usize;
    let mut runner = |command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            panic!("injected auditor runner panic");
        }
        assert!(name.starts_with("child-a"));
        write_injected_assignment_report(command, &child_a);
        write_injected_usage(command, 7, 3);
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("finalize auditor runner panic");

    assert!(!report.success);
    assert_eq!(invocations, 2);
    assert!(!report.usage_complete);
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("supervisor assignment 'child-a' panicked")));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("conservatively reconciled")));
    let budget = report.run_budget.as_ref().expect("auditor panic budget");
    assert_eq!(budget.consumed.tokens, 60);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    assert!(!budget.usage_complete);
    assert!(!budget.new_dispatch_allowed);
    assert_eq!(budget.action, BudgetAction::OwnerEscalation);
    assert!(budget.reasons.contains(&BudgetReason::MissingProviderUsage));
    assert_eq!(
        budget
            .roles
            .iter()
            .find(|role| role.role == AgentRole::Auditor)
            .map(|role| (role.consumed.tokens, role.usage_complete)),
        Some((50, false))
    );
    assert_injected_dispatch_cleanup(&report, &repo_path, run_id, "child-a", &["child-b"], true);
}

#[test]
fn budget_integration_reservation_is_released_when_codex_process_never_starts() {
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment.clone(), 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(100), None, None, 50, 50);
    let options = injected_options(&repo_path, temp.path(), "budget-never-started-release");
    let mut invocations = 0usize;
    let mut runner = |command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        write_injected_assignment_report(command, &assignment);
        let mut run = injected_verified_run(command);
        run.process_tree = None;
        run
    };

    let report = run_supervisor_plan_with_budget_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        budget,
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("finalize never-started dispatch");

    assert!(!report.success);
    assert_eq!(invocations, 1);
    assert!(report.usage_complete);
    let budget = report.run_budget.expect("never-started budget report");
    assert_eq!(budget.consumed.tokens, 0);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(budget.committed.tokens, 0);
    assert_eq!(budget.active_reservations, 0);
    assert!(budget.usage_complete);
    assert!(budget.new_dispatch_allowed);
    assert!(report.release_errors.is_empty());
}

#[test]
fn budget_integration_uncertain_start_is_conservatively_reconciled_not_released() {
    let _capability = install_budget_fixture_models();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment, 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(100), None, None, 50, 50);
    let ledger = RunBudgetLedger::new(budget.limits).expect("budget ledger");
    let temp = tempfile::tempdir().expect("uncertain-start command root");
    let mut command = ExternalAgentCommand::codex(
        "codex",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    command.model = Some("priced-model".to_string());
    let mut reservation = match reserve_dispatch_budget(
        &plan,
        &budget,
        &ledger,
        (AgentRole::ChildOrchestrator, SupervisorRuntime::Codex),
        &command,
    )
    .expect("reserve uncertain-start dispatch")
    {
        DispatchBudgetAdmission::Admitted(reservation) => reservation,
        DispatchBudgetAdmission::Refused(refusal) => {
            panic!("unexpected budget refusal: {refusal:?}")
        }
    };
    reservation
        .mark_invoked()
        .expect("mark uncertain-start dispatch invoked");
    let mut run = injected_target_attempted(injected_verified_run_without_journals(&command));
    run.process_tree = None;
    assert!(!run.scratch_quiescence_verified());
    assert_eq!(
        reservation
            .settle(&run, SupervisorRuntime::Codex, &command)
            .expect("reconcile uncertain-start dispatch")
            .reliability,
        DispatchUsageReliability::Missing
    );

    let report = ledger.report().expect("uncertain-start budget report");
    assert_eq!(report.consumed.tokens, 50);
    assert_eq!(report.reserved.tokens, 0);
    assert_eq!(report.committed.tokens, 50);
    assert_eq!(report.active_reservations, 0);
    assert!(!report.usage_complete);
    assert!(!report.new_dispatch_allowed);
    assert!(report.reasons.contains(&BudgetReason::MissingProviderUsage));
    assert_eq!(report.action, BudgetAction::OwnerEscalation);
}

#[test]
fn budget_integration_parseable_usage_without_verified_containment_is_estimated() {
    let _capability = install_budget_fixture_models();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment, 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(100), None, Some(1.0), 50, 50);
    let ledger = RunBudgetLedger::new(budget.limits).expect("budget ledger");
    let temp = tempfile::tempdir().expect("unverified containment command root");
    let mut command = ExternalAgentCommand::codex(
        "codex",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    command.model = Some("priced-model".to_string());
    let mut reservation = match reserve_dispatch_budget(
        &plan,
        &budget,
        &ledger,
        (AgentRole::ChildOrchestrator, SupervisorRuntime::Codex),
        &command,
    )
    .expect("reserve unverified containment dispatch")
    {
        DispatchBudgetAdmission::Admitted(reservation) => reservation,
        DispatchBudgetAdmission::Refused(refusal) => {
            panic!("unexpected budget refusal: {refusal:?}")
        }
    };
    reservation
        .mark_invoked()
        .expect("mark unverified containment dispatch invoked");
    write_injected_usage(&command, 7, 3);
    let mut run = injected_verified_run_without_journals(&command);
    run.side_effects = None;
    let settlement = reservation
        .settle(&run, SupervisorRuntime::Codex, &command)
        .expect("reconcile unverified containment dispatch");
    assert_eq!(
        settlement.observed_usage.map(|usage| usage.total_tokens),
        Some(10)
    );
    assert_eq!(settlement.reliability, DispatchUsageReliability::Estimated);

    let report = ledger
        .report()
        .expect("unverified containment budget report");
    assert_eq!(report.consumed.tokens, 50);
    assert_eq!(report.consumed.cost_usd, None);
    assert!(!report.usage_complete);
    assert!(!report.new_dispatch_allowed);
    assert!(report
        .reasons
        .contains(&BudgetReason::EstimatedProviderUsage));
    assert!(matches!(
        reserve_dispatch_budget(
            &plan,
            &budget,
            &ledger,
            (AgentRole::ChildOrchestrator, SupervisorRuntime::Codex),
            &command,
        )
        .expect("later admission result"),
        DispatchBudgetAdmission::Refused(BudgetAdmissionRefusal::NewDispatchStopped)
    ));
}

#[test]
fn budget_integration_parseable_usage_from_truncated_capture_is_estimated() {
    let _capability = install_budget_fixture_models();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment, 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(100), None, Some(1.0), 50, 50);
    let ledger = RunBudgetLedger::new(budget.limits).expect("budget ledger");
    let temp = tempfile::tempdir().expect("truncated capture command root");
    let mut command = ExternalAgentCommand::codex(
        "codex",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    command.model = Some("priced-model".to_string());
    let mut reservation = match reserve_dispatch_budget(
        &plan,
        &budget,
        &ledger,
        (AgentRole::ChildOrchestrator, SupervisorRuntime::Codex),
        &command,
    )
    .expect("reserve truncated-capture dispatch")
    {
        DispatchBudgetAdmission::Admitted(reservation) => reservation,
        DispatchBudgetAdmission::Refused(refusal) => {
            panic!("unexpected budget refusal: {refusal:?}")
        }
    };
    reservation
        .mark_invoked()
        .expect("mark truncated-capture dispatch invoked");
    write_injected_usage(&command, 7, 3);
    let mut run = injected_verified_run_without_journals(&command);
    run.stdout.truncated = true;
    assert!(external_process_completed(&run, SupervisorRuntime::Codex));
    assert!(external_safety_verified(&run, SupervisorRuntime::Codex));
    assert_eq!(
        complete_external_codex_usage(&run, &command).map(|usage| usage.total_tokens),
        Some(10)
    );

    let settlement = reservation
        .settle(&run, SupervisorRuntime::Codex, &command)
        .expect("reconcile truncated-capture dispatch");
    assert_eq!(
        settlement.observed_usage.map(|usage| usage.total_tokens),
        Some(10)
    );
    assert_eq!(settlement.reliability, DispatchUsageReliability::Estimated);

    let report = ledger.report().expect("truncated-capture budget report");
    assert_eq!(report.consumed.tokens, 50);
    assert_eq!(report.committed.tokens, 50);
    assert_eq!(report.consumed.cost_usd, None);
    assert!(!report.usage_complete);
    assert!(!report.new_dispatch_allowed);
    assert_eq!(report.action, BudgetAction::OwnerEscalation);
    assert!(report
        .reasons
        .contains(&BudgetReason::EstimatedProviderUsage));
    assert!(matches!(
        reserve_dispatch_budget(
            &plan,
            &budget,
            &ledger,
            (AgentRole::ChildOrchestrator, SupervisorRuntime::Codex),
            &command,
        )
        .expect("later admission result"),
        DispatchBudgetAdmission::Refused(BudgetAdmissionRefusal::NewDispatchStopped)
    ));
}

#[test]
fn completed_app_server_parent_usage_is_available_without_cli_jsonl() {
    use crate::external_agent::codex_app_server::{CommandExecutionEvidence, TurnTerminalStatus};
    use crate::external_agent::{
        CodexParentEvidence, CodexParentResolvedField, CodexParentTurnUsage,
    };

    let temp = tempfile::tempdir().expect("app-server usage fixture");
    let command = ExternalAgentCommand::codex(
        "codex",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("missing-cli-capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    let mut run = injected_verified_run_without_journals(&command);
    run.set_codex_command_execution_evidence_for_test(CommandExecutionEvidence {
        thread_id: "correlated-thread".to_string(),
        turn_id: "correlated-turn".to_string(),
        turn_status: TurnTerminalStatus::Completed,
        observations: Vec::new(),
    });
    run.codex_parent_evidence = Some(CodexParentEvidence {
        codex_version: Some("0.144.4".to_string()),
        thread_id: Some("correlated-thread".to_string()),
        requested_model: Some("gpt-5.6-sol".to_string()),
        requested_effort: Some("xhigh".to_string()),
        rollout_model: CodexParentResolvedField::Unknown,
        rollout_effort: CodexParentResolvedField::Unknown,
        observed_model: CodexParentResolvedField::Known("gpt-5.6-sol".to_string()),
        observed_effort: CodexParentResolvedField::Known("xhigh".to_string()),
        server_rerouted_model: None,
        model_mismatch: false,
        turn_usage: CodexParentTurnUsage::Known {
            input_tokens: 25,
            output_tokens: 7,
            cached_input_tokens: 3,
            reasoning_output_tokens: 2,
        },
        resolution_status: "complete".to_string(),
    });
    run.retain_app_server_parent_evidence_for_test();
    assert!(external_process_completed(&run, SupervisorRuntime::Codex));
    for raw_loss in [false, true] {
        let mut incomplete = run.clone();
        let evidence = incomplete.codex_parent_evidence.as_mut().unwrap();
        evidence.turn_usage = CodexParentTurnUsage::Known {
            input_tokens: 35_000,
            output_tokens: 2_000,
            cached_input_tokens: 30_000,
            reasoning_output_tokens: 1_000,
        };
        if raw_loss {
            // Legacy/unknown raw provenance is conservatively interpreted as loss.
            // The contained transport regression separately exercises actual raw loss.
            incomplete.stdout.truncated = true;
        } else {
            evidence.observed_effort = CodexParentResolvedField::Unknown;
            evidence.resolution_status = "ambiguous".to_string();
        }
        incomplete.retain_app_server_parent_evidence_for_test();
        assert!(!external_process_completed(
            &incomplete,
            SupervisorRuntime::Codex
        ));
        // No configured ceiling: accounting incompleteness alone must not be the
        // mechanism that rejects this otherwise-successful process receipt.
        let ledger = RunBudgetLedger::new(RunBudgetLimits::default()).unwrap();
        let BudgetAdmission::Admitted { reservation, .. } = ledger
            .reserve(BudgetReservationRequest {
                role: AgentRole::Researcher,
                tokens: 16_384,
                cost_usd: Some(1.0),
            })
            .unwrap()
        else {
            panic!("admit incomplete receipt fixture")
        };
        let mut held = DispatchBudgetReservation {
            ledger: &ledger,
            reservation,
            pricing: None,
            model_pricing: BTreeMap::new(),
            state: DispatchBudgetReservationState::Invoked(SupervisorRuntime::Codex),
        };
        let settled = held.settle_bound_runtime(&incomplete, &command).unwrap();
        assert_eq!(
            settled.reliability,
            if raw_loss {
                DispatchUsageReliability::Estimated
            } else {
                DispatchUsageReliability::Reliable
            }
        );
        let charged = ledger.report().unwrap();
        assert_eq!(charged.consumed.tokens, 37_000);
        assert_eq!(charged.usage_complete, !raw_loss);
        assert!(charged.consumed.cost_usd.is_none());
    }

    assert_eq!(
        complete_external_codex_usage(&run, &command).map(|usage| usage.total_tokens),
        Some(32)
    );
    run.codex_parent_evidence
        .as_mut()
        .expect("parent evidence")
        .resolution_status = "jsonl_invalid".to_string();
    assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
    assert_eq!(
        complete_external_codex_usage(&run, &command)
            .unwrap()
            .total_tokens,
        32
    );
    let evidence = run.codex_parent_evidence.as_mut().unwrap();
    evidence.resolution_status = "turn_failed".to_string();
    evidence.observed_model = CodexParentResolvedField::Unknown;
    evidence.turn_usage = CodexParentTurnUsage::Known {
        input_tokens: 1_287_714,
        output_tokens: 8_761,
        cached_input_tokens: 1_219_968,
        reasoning_output_tokens: 4_288,
    };
    run.timed_out = true;
    run.error = Some("protocol timeout".to_string());
    run.retain_app_server_parent_evidence_for_test();
    let ledger = RunBudgetLedger::new(RunBudgetLimits {
        hard_tokens: Some(220_000),
        ..Default::default()
    })
    .unwrap();
    let BudgetAdmission::Admitted { reservation, .. } = ledger
        .reserve(BudgetReservationRequest {
            role: AgentRole::Researcher,
            tokens: 16_384,
            cost_usd: Some(1.0),
        })
        .unwrap()
    else {
        panic!("admission")
    };
    let mut held = DispatchBudgetReservation {
        ledger: &ledger,
        reservation,
        pricing: None,
        model_pricing: BTreeMap::new(),
        state: DispatchBudgetReservationState::Invoked(SupervisorRuntime::Codex),
    };
    assert_eq!(
        complete_external_codex_usage(&run, &command)
            .unwrap()
            .total_tokens,
        1_296_475
    );
    run.codex_parent_evidence.as_mut().unwrap().turn_usage = CodexParentTurnUsage::Known {
        input_tokens: 1,
        output_tokens: 1,
        cached_input_tokens: 0,
        reasoning_output_tokens: 0,
    };
    let settlement = held.settle_bound_runtime(&run, &command).unwrap();
    assert_eq!(settlement.reliability, DispatchUsageReliability::Estimated);
    let report = ledger.report().unwrap();
    assert_eq!(report.consumed.tokens, 1_296_475);
    assert!(!report.usage_complete);
    assert!(report.consumed.cost_usd.is_none());
    assert!(!report.new_dispatch_allowed);
    assert_eq!(
        complete_external_codex_usage(&run, &command)
            .unwrap()
            .total_tokens,
        1_296_475,
        "public tampering must never erase the authenticated billing lower bound"
    );
}

#[test]
fn cli_usage_keeps_aggregating_each_turn_even_with_parent_provenance() {
    let temp = tempfile::tempdir().expect("CLI usage fixture");
    let command = ExternalAgentCommand::codex(
        "codex",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    fs::write(
        &command.json_log,
        "{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":10,\"output_tokens\":4}}\n{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":25,\"output_tokens\":7}}\n",
    )
    .expect("two-turn CLI capture");
    let mut run = injected_verified_run_without_journals(&command);
    run.codex_parent_evidence = Some(crate::external_agent::CodexParentEvidence {
        codex_version: Some("0.144.4".to_string()),
        thread_id: Some("cli-thread".to_string()),
        requested_model: Some("gpt-5.6-sol".to_string()),
        requested_effort: Some("xhigh".to_string()),
        rollout_model: crate::external_agent::CodexParentResolvedField::Known(
            "gpt-5.6-sol".to_string(),
        ),
        rollout_effort: crate::external_agent::CodexParentResolvedField::Known("xhigh".to_string()),
        observed_model: crate::external_agent::CodexParentResolvedField::Known(
            "gpt-5.6-sol".to_string(),
        ),
        observed_effort: crate::external_agent::CodexParentResolvedField::Known(
            "xhigh".to_string(),
        ),
        server_rerouted_model: None,
        model_mismatch: false,
        turn_usage: crate::external_agent::CodexParentTurnUsage::Known {
            input_tokens: 25,
            output_tokens: 7,
            cached_input_tokens: 0,
            reasoning_output_tokens: 0,
        },
        resolution_status: "complete".to_string(),
    });
    assert!(run.codex_command_execution_evidence().is_none());
    assert_eq!(
        complete_external_codex_usage(&run, &command).map(|usage| usage.total_tokens),
        Some(46)
    );
}

#[cfg(unix)]
#[test]
fn budget_integration_large_capture_distinguishes_display_shortening_from_raw_loss() {
    use crate::process_runner::{run_process, ContainmentPolicy, ProcessSpec};

    let _capability = install_budget_fixture_models();
    for (capture_limit, retain_log, expected) in [
        (8 * 1024 * 1024, true, DispatchUsageReliability::Reliable),
        (8 * 1024 * 1024, false, DispatchUsageReliability::Reliable),
        (256, true, DispatchUsageReliability::Estimated),
        (256, false, DispatchUsageReliability::Missing),
    ] {
        let mut plan = injected_plan(injected_assignment(false), 0);
        inject_priced_process_roles(&mut plan, "priced-model", 1.0);
        let budget = injected_run_budget(None, Some(100), None, Some(1.0), 50, 50);
        let ledger = RunBudgetLedger::new(budget.limits).expect("budget ledger");
        let temp = tempfile::tempdir().expect("large capture command root");
        let mut command = ExternalAgentCommand::codex(
            "codex",
            temp.path(),
            temp.path().join("prompt.md"),
            temp.path().join("capture.jsonl"),
            temp.path().join("report.json"),
            Duration::from_secs(1),
        );
        command.model = Some("priced-model".to_string());
        let transcript = format!(
            "{}\n{}\n",
            json!({"type": "item.completed", "item": {"text": "x".repeat(40 * 1024)}}),
            json!({"type": "turn.completed", "usage": {"input_tokens": 7, "output_tokens": 3}}),
        );
        fs::write(&command.json_log, &transcript).expect("write full large transcript");
        let capture = run_process(
            ProcessSpec::direct(
                "capture large usage fixture",
                "/bin/cat",
                [command.json_log.as_os_str()],
                temp.path(),
                capture_limit,
            )
            .with_containment(ContainmentPolicy::TrustedBestEffort)
            .with_timeout(Some(Duration::from_secs(5))),
        )
        .expect("capture fixture through real bounded pipe");
        assert!(capture.status.is_some_and(|status| status.success()));
        let mut run = injected_verified_run_without_journals(&command);
        run.stdout = CapturedOutput::from_captured_bytes_for_test(&capture.stdout);
        assert!(run.stdout.truncated, "public display must remain shortened");
        assert_eq!(run.stdout.raw_capture_truncated(), capture_limit == 256);
        if capture_limit > transcript.len() {
            assert_eq!(run.stdout.text.chars().count(), 32 * 1024);
            assert_eq!(run.stdout_bytes(), transcript.as_bytes());
        }
        if !run.stdout.raw_capture_truncated() {
            retain_priced_single_turn_fixture(
                &mut run,
                &command,
                "priced-model",
                capture.stdout.as_bytes(),
            );
        }
        if !retain_log {
            fs::remove_file(&command.json_log).expect("exercise held stdout fallback");
        }
        let mut reservation = match reserve_dispatch_budget(
            &plan,
            &budget,
            &ledger,
            (AgentRole::ChildOrchestrator, SupervisorRuntime::Codex),
            &command,
        )
        .expect("reserve large-capture dispatch")
        {
            DispatchBudgetAdmission::Admitted(reservation) => reservation,
            DispatchBudgetAdmission::Refused(refusal) => {
                panic!("unexpected budget refusal: {refusal:?}")
            }
        };
        reservation
            .mark_invoked()
            .expect("mark capture dispatch invoked");
        let settlement = reservation
            .settle(&run, SupervisorRuntime::Codex, &command)
            .expect("settle large capture");
        assert_eq!(settlement.reliability, expected);
        let report = ledger.report().expect("large capture budget report");
        let reliable = expected == DispatchUsageReliability::Reliable;
        assert_eq!(report.consumed.tokens, if reliable { 10 } else { 50 });
        assert_eq!(report.usage_complete, reliable);
        assert_eq!(report.new_dispatch_allowed, reliable);
        assert_eq!(report.reserved.tokens, 0);
        assert_eq!(report.active_reservations, 0);
        assert_eq!(
            settlement.observed_usage.map(|usage| usage.total_tokens),
            if expected == DispatchUsageReliability::Missing {
                None
            } else {
                Some(10)
            },
        );
    }
}

#[test]
fn runtime_aware_external_completion_accepts_only_verified_publishable_adapter_runs() {
    let temp = tempfile::tempdir().expect("runtime completion command root");
    let command = ExternalAgentCommand::codex(
        "injected-codex",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    let mut grok_run = injected_verified_run_without_journals(&command);
    grok_run.program_trust = ExternalProgramTrust::ExplicitCustom;
    grok_run.codex_permissions = None;

    assert!(external_process_completed(
        &grok_run,
        SupervisorRuntime::Grok
    ));
    assert!(external_safety_verified(&grok_run, SupervisorRuntime::Grok));
    assert_eq!(
        command_record_from_external_for_runtime(&grok_run, &command, SupervisorRuntime::Grok)
            .status,
        ReviewStatus::Succeeded
    );
    assert!(!grok_run.succeeded());
    let mut codex_without_permissions = grok_run.clone();
    codex_without_permissions.program_trust = ExternalProgramTrust::TrustedSystemCodex;
    assert!(!codex_without_permissions.safely_executed());
    assert!(!external_process_completed(
        &codex_without_permissions,
        SupervisorRuntime::Codex
    ));

    let mut missing_containment = grok_run.clone();
    missing_containment.process_tree = None;
    assert!(!external_process_completed(
        &missing_containment,
        SupervisorRuntime::Grok
    ));

    let mut nonzero = grok_run.clone();
    nonzero.exit_code = Some(23);
    assert!(!external_process_completed(
        &nonzero,
        SupervisorRuntime::Grok
    ));

    let mut errored = grok_run.clone();
    errored.error = Some("adapter process error".to_string());
    assert!(!external_process_completed(
        &errored,
        SupervisorRuntime::Grok
    ));

    let mut timed_out = grok_run.clone();
    timed_out.timed_out = true;
    assert!(!external_process_completed(
        &timed_out,
        SupervisorRuntime::Grok
    ));

    let mut unpublishable = grok_run;
    unpublishable.publishable = false;
    assert!(!external_process_completed(
        &unpublishable,
        SupervisorRuntime::Grok
    ));
}

#[test]
fn runtime_aware_external_completion_preserves_fake_simulation_contract() {
    let temp = tempfile::tempdir().expect("fake completion command root");
    let command = ExternalAgentCommand::codex(
        "unused-codex",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    let fake_run = deterministic_fake_run(&command, Vec::new());
    assert!(external_process_completed(
        &fake_run,
        SupervisorRuntime::Fake
    ));

    let mut wrong_trust = fake_run.clone();
    wrong_trust.program_trust = ExternalProgramTrust::TrustedSystemCodex;
    assert!(!external_process_completed(
        &wrong_trust,
        SupervisorRuntime::Fake
    ));

    let mut publishable = fake_run;
    publishable.publishable = true;
    assert!(!external_process_completed(
        &publishable,
        SupervisorRuntime::Fake
    ));
}

#[test]
fn budget_reliability_uses_bound_adapter_runtime_completion() {
    let _capability = install_budget_fixture_models();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment, 0);
    inject_priced_process_roles(&mut plan, "priced-model", 1.0);
    let budget = injected_run_budget(None, Some(100), None, Some(1.0), 50, 50);
    let ledger = RunBudgetLedger::new(budget.limits).expect("budget ledger");
    let temp = tempfile::tempdir().expect("adapter budget command root");
    let mut command = ExternalAgentCommand::codex(
        "grok",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    )
    .with_runtime_adapter(
        SupervisorRuntime::Grok,
        crate::runtime_adapter::RuntimeAdapterConfig::defaults(SupervisorRuntime::Grok),
    );
    command.model = Some("priced-model".to_string());
    let mut reservation = match reserve_dispatch_budget(
        &plan,
        &budget,
        &ledger,
        (AgentRole::ChildOrchestrator, SupervisorRuntime::Grok),
        &command,
    )
    .expect("reserve adapter dispatch")
    {
        DispatchBudgetAdmission::Admitted(reservation) => reservation,
        DispatchBudgetAdmission::Refused(refusal) => {
            panic!("unexpected budget refusal: {refusal:?}")
        }
    };
    reservation
        .mark_invoked_for_runtime(SupervisorRuntime::Grok)
        .expect("retain adapter launch runtime");
    write_injected_usage(&command, 7, 3);
    let mut run = injected_verified_run_without_journals(&command);
    run.program_trust = ExternalProgramTrust::ExplicitCustom;
    run.codex_permissions = None;

    let settlement = reservation
        .settle(&run, SupervisorRuntime::Grok, &command)
        .expect("settle verified adapter usage");
    assert_eq!(
        settlement.observed_usage.map(|usage| usage.total_tokens),
        Some(10)
    );
    assert_eq!(settlement.reliability, DispatchUsageReliability::Reliable);
}

#[test]
fn dispatch_composes_plan_and_cli_token_ceilings_in_all_four_directions() {
    skip_without_containment!();
    let _capability = install_budget_fixture_models();
    for (name, plan_hard, cli_hard, expected) in [
        ("cli_tighter", Some(100usize), Some(20usize), Some(20usize)),
        ("plan_tighter", Some(20), Some(100), Some(20)),
        ("plan_silent", None, Some(20), Some(20)),
        ("cli_silent", Some(20), None, Some(20)),
    ] {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(true);
        let mut plan = injected_plan(assignment.clone(), 0);
        inject_priced_process_roles(&mut plan, "priced-model", 1.0);
        let budget = match plan_hard {
            Some(hard) => injected_run_budget(None, Some(hard), None, None, 10, 10),
            None => SupervisorBudgetConfig {
                limits: RunBudgetLimits::default(),
                role_token_reservations: BTreeMap::from([
                    (AgentRole::ChildOrchestrator, 10),
                    (AgentRole::Auditor, 10),
                ]),
            },
        };
        let mut options = injected_options(&repo_path, temp.path(), &format!("compose-{name}"));
        options.budget_overrides = RunBudgetLimits {
            hard_tokens: cli_hard,
            ..RunBudgetLimits::default()
        };
        let mut runner = |command: &ExternalAgentCommand| {
            let file_name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            if file_name.contains("review-auditor") {
                let child = injected_child_report(&assignment);
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(&assignment, &child),
                );
            } else {
                write_injected_assignment_report(command, &assignment);
            }
            write_injected_usage(command, 1, 0);
            injected_verified_run(command)
        };
        let report = run_supervisor_plan_with_budget_and_runner(
            plan,
            SupervisorConsultantPlan::default(),
            budget,
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .unwrap_or_else(|error| panic!("{name} dispatch composition failed: {error:#}"));
        assert!(report.success, "{name} unexpectedly failed: {report:#?}");
        let run_budget = report.run_budget.expect("composed run budget");
        assert_eq!(
            run_budget.limits.hard_tokens, expected,
            "{name} effective hard token ceiling"
        );
    }
}

#[test]
fn pricing_guard_unknown_and_placeholder_costs_are_not_reservable_for_real_runtimes() {
    let plan = injected_plan(injected_assignment(false), 0);
    for runtime in [
        SupervisorRuntime::Codex,
        SupervisorRuntime::Grok,
        SupervisorRuntime::Cursor,
        SupervisorRuntime::ClaudeCode,
        SupervisorRuntime::GeminiCli,
    ] {
        for model in ["gpt-5.6-sol", "gpt-5.6-luna", "fake", "unknown-model"] {
            // A model label never confers Fake launch authority.
            assert!(pricing_for_runtime(&plan, model, runtime).is_none());
        }
    }
    assert!(pricing_for_runtime(&plan, "unknown-model", SupervisorRuntime::Fake).is_none());
}

#[test]
fn pricing_guard_reservation_runtime_cannot_drift_from_fake_to_real() {
    let plan = injected_plan(injected_assignment(false), 0);
    let budget = injected_run_budget(None, Some(100), None, Some(1.0), 50, 50);
    let ledger = RunBudgetLedger::new(budget.limits).expect("ledger");
    let temp = tempfile::tempdir().expect("command root");
    let mut command = ExternalAgentCommand::codex(
        "unused",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    command.model = Some("gpt-5.6-sol".to_string());
    let mut reservation = match reserve_dispatch_budget(
        &plan,
        &budget,
        &ledger,
        (AgentRole::ChildOrchestrator, SupervisorRuntime::Fake),
        &command,
    )
    .expect("Fake admission")
    {
        DispatchBudgetAdmission::Admitted(reservation) => reservation,
        DispatchBudgetAdmission::Refused(refusal) => panic!("unexpected refusal: {refusal:?}"),
    };
    assert_eq!(ledger.report().unwrap().reserved.cost_usd, Some(0.0));
    assert!(reservation
        .mark_invoked_for_runtime(SupervisorRuntime::Codex)
        .is_err());
    assert!(matches!(
        reservation.state,
        DispatchBudgetReservationState::Reserved(SupervisorRuntime::Fake)
    ));
    drop(reservation);
    let report = ledger.report().unwrap();
    assert_eq!(report.active_reservations, 0);
    assert_eq!(report.consumed.tokens, 0);
    assert_eq!(report.reserved.tokens, 0);
    assert!(report.usage_complete);
}

#[test]
fn pricing_guard_token_only_settlement_keeps_unknown_cost_and_complete_tokens() {
    assert_pricing_guard_settlement(SupervisorRuntime::Codex, None, None);
}

#[test]
fn pricing_guard_explicit_zero_and_nonzero_overrides_remain_priced() {
    for rate in [0.0, 2.0] {
        assert_pricing_guard_settlement(
            SupervisorRuntime::Codex,
            Some(rate),
            Some(10.0 * rate / 1_000_000.0),
        );
    }
}

#[test]
fn pricing_guard_fake_placeholder_simulation_remains_usable() {
    assert_pricing_guard_settlement(SupervisorRuntime::Fake, None, Some(0.0));
}

fn assert_pricing_guard_settlement(
    runtime: SupervisorRuntime,
    rate: Option<f64>,
    expected_cost: Option<f64>,
) {
    let mut plan = injected_plan(injected_assignment(false), 0);
    if let Some(rate) = rate {
        plan.model_pricing.insert(
            "gpt-5.6-sol".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: rate,
                output_usd_per_million_tokens: rate,
            },
        );
        let resolved =
            crate::llm::provider::resolve_model_pricing(&plan.model_pricing, "gpt-5.6-sol")
                .unwrap();
        assert_eq!(
            resolved.provenance,
            crate::llm::provider::ModelPricingProvenance::PlanOverride
        );
        // The persisted plan retains even an explicit zero override.
        let persisted: SupervisorPlan =
            serde_json::from_value(serde_json::to_value(&plan).unwrap()).unwrap();
        assert_eq!(persisted.model_pricing, plan.model_pricing);
    }
    let budget = injected_run_budget(None, Some(100), None, expected_cost.map(|_| 1.0), 50, 50);
    let ledger = RunBudgetLedger::new(budget.limits).expect("ledger");
    let temp = tempfile::tempdir().expect("command root");
    let mut command = ExternalAgentCommand::codex(
        "unused",
        temp.path(),
        temp.path().join("prompt.md"),
        temp.path().join("capture.jsonl"),
        temp.path().join("report.json"),
        Duration::from_secs(1),
    );
    command.model = Some("gpt-5.6-sol".to_string());
    let mut reservation = match reserve_dispatch_budget(
        &plan,
        &budget,
        &ledger,
        (AgentRole::ChildOrchestrator, runtime),
        &command,
    )
    .expect("admission")
    {
        DispatchBudgetAdmission::Admitted(reservation) => reservation,
        DispatchBudgetAdmission::Refused(refusal) => panic!("unexpected refusal: {refusal:?}"),
    };
    assert_eq!(
        ledger.report().unwrap().reserved.cost_usd.is_some(),
        expected_cost.is_some()
    );
    reservation
        .mark_invoked_for_runtime(runtime)
        .expect("bound invocation");
    write_injected_usage(&command, 7, 3);
    let mut run = if runtime == SupervisorRuntime::Fake {
        deterministic_fake_run(&command, Vec::new())
    } else {
        injected_verified_run_without_journals(&command)
    };
    if runtime == SupervisorRuntime::Codex {
        retain_attribution_fixture(&mut run, &command, Some("gpt-5.6-sol"), false, false);
    }
    let settlement = reservation
        .settle_bound_runtime(&run, &command)
        .expect("settlement");
    assert_eq!(settlement.reliability, DispatchUsageReliability::Reliable);
    let usage = settlement.reliable_usage().expect("complete tokens");
    assert_eq!(usage.total_tokens, 10);
    let report = ledger.report().unwrap();
    assert_eq!(report.consumed.tokens, 10);
    assert_eq!(report.consumed.cost_usd, expected_cost);
    assert_eq!(report.roles[0].consumed.cost_usd, expected_cost);
    assert_eq!(report.active_reservations, 0);
    assert_eq!(report.reserved.tokens, 0);
    assert!(report.usage_complete);
    assert!(report.new_dispatch_allowed);
    if expected_cost.is_none() {
        assert!(report.reasons.contains(&BudgetReason::MissingActualCost));
    }
    // Settlement is single-use even when the observed cost is unknown or zero.
    assert!(reservation.settle_bound_runtime(&run, &command).is_err());
    assert_eq!(ledger.report().unwrap().consumed.tokens, 10);
    let aggregation = role_usage_report(
        &plan,
        vec![settlement
            .role_sample(AgentRole::ChildOrchestrator, None)
            .unwrap()],
    )
    .expect("role cost report");
    assert_eq!(aggregation.total_usage, Some(usage));
    assert_eq!(aggregation.total_cost_usd, expected_cost);
    assert_eq!(
        aggregation.reports[&AgentRole::ChildOrchestrator].cost_usd,
        expected_cost
    );
    assert_eq!(
        aggregation.reports[&AgentRole::Supervisor].cost_usd,
        expected_cost
    );
}

#[test]
fn pricing_guard_real_usage_prevents_fake_zero_from_masking_unknown_role_and_lens_cost() {
    let plan = injected_plan(injected_assignment(false), 0);
    let usage = Usage {
        input_tokens: 7,
        output_tokens: 3,
        total_tokens: 10,
    };
    let mut samples = vec![RoleUsageSample {
        cost_usd: Some(0.0),
        role: AgentRole::Auditor,
        lens_id: Some(plan.review_lenses[0].id.clone()),
        model: Some("fake".to_string()),
        usage,
    }];
    for role in [
        AgentRole::Researcher,
        AgentRole::Worker,
        AgentRole::ChildOrchestrator,
        AgentRole::Auditor,
    ] {
        samples.push(RoleUsageSample {
            cost_usd: None,
            role,
            lens_id: (role == AgentRole::Auditor).then(|| plan.review_lenses[0].id.clone()),
            model: Some("fake".to_string()),
            usage,
        });
    }
    let report = role_usage_report(&plan, samples).expect("aggregate mixed runtime samples");
    assert_eq!(report.total_usage.unwrap().total_tokens, 50);
    assert!(report.total_cost_usd.is_none());
    assert!(report.lens_total_cost_usd.is_none());
    assert!(report
        .lens_reports
        .iter()
        .all(|lens| lens.cost_usd.is_none()));
    for role in [
        AgentRole::Researcher,
        AgentRole::Worker,
        AgentRole::ChildOrchestrator,
        AgentRole::Auditor,
        AgentRole::Supervisor,
    ] {
        assert!(report.reports[&role].cost_usd.is_none());
        assert!(report.reports[&role].usage.is_some());
    }
}

// Parent-capture seam: no agent-authored output supplies this private identity.
fn retain_attribution_fixture(
    run: &mut ExternalAgentRun,
    command: &ExternalAgentCommand,
    observed: Option<&str>,
    app_server: bool,
    rerouted: bool,
) {
    use crate::external_agent::{
        CodexParentEvidence, CodexParentResolvedField as Field, CodexParentTurnUsage,
        CodexServerRerouteEvidence,
    };
    run.codex_parent_evidence = Some(CodexParentEvidence {
        codex_version: Some("0.144.4".to_string()),
        thread_id: Some("attribution-thread".to_string()),
        requested_model: command.model.clone(),
        requested_effort: command.reasoning_effort.clone(),
        rollout_model: if app_server {
            Field::Unknown
        } else {
            observed
                .map(|model| Field::Known(model.to_string()))
                .unwrap_or(Field::Unknown)
        },
        rollout_effort: Field::Known("xhigh".to_string()),
        observed_model: observed
            .map(|model| Field::Known(model.to_string()))
            .unwrap_or(Field::Unknown),
        observed_effort: Field::Known("xhigh".to_string()),
        server_rerouted_model: rerouted.then(|| CodexServerRerouteEvidence {
            from: command.model.clone().unwrap(),
            to: observed.unwrap().to_string(),
        }),
        model_mismatch: observed.is_some_and(|model| Some(model) != command.model.as_deref()),
        turn_usage: CodexParentTurnUsage::Known {
            input_tokens: 7,
            output_tokens: 3,
            cached_input_tokens: 0,
            reasoning_output_tokens: 0,
        },
        resolution_status: if observed.is_some() {
            "complete"
        } else {
            "ambiguous"
        }
        .to_string(),
    });
    if app_server {
        use crate::external_agent::codex_app_server::{
            CommandExecutionEvidence, TurnTerminalStatus,
        };
        run.set_codex_command_execution_evidence_for_test(CommandExecutionEvidence {
            thread_id: "attribution-thread".to_string(),
            turn_id: "turn".to_string(),
            turn_status: TurnTerminalStatus::Completed,
            observations: Vec::new(),
        });
        run.retain_app_server_parent_evidence_for_test();
    } else {
        run.retain_cli_parent_evidence_for_test(&fs::read(&command.json_log).unwrap());
    }
}

#[test]
fn model_attribution_settlement_and_all_role_reports_share_verified_allocation() {
    for app_server in [false, true] {
        for (observed, rerouted, expected_model, expected_cost) in [
            (Some("model-a"), false, Some("model-a"), Some(0.00002)),
            (Some("model-b"), false, Some("model-b"), Some(0.00007)),
            (Some("unpriced"), false, Some("unpriced"), None),
            (None, false, None, None),
            (Some("model-b"), true, None, None),
        ] {
            for money_ceiling in [false, true] {
                let mut plan = injected_plan(injected_assignment(false), 0);
                for (model, rate) in [("model-a", 2.0), ("model-b", 7.0)] {
                    plan.model_pricing.insert(
                        model.to_string(),
                        ModelPricing {
                            input_usd_per_million_tokens: rate,
                            output_usd_per_million_tokens: rate,
                        },
                    );
                }
                let budget = injected_run_budget(
                    None,
                    Some(1000),
                    None,
                    money_ceiling.then_some(1.0),
                    50,
                    50,
                );
                let temp = tempfile::tempdir().unwrap();
                let mut command = ExternalAgentCommand::codex(
                    "unused",
                    temp.path(),
                    temp.path().join("prompt"),
                    temp.path().join("usage"),
                    temp.path().join("report"),
                    Duration::from_secs(1),
                );
                command.model = Some("model-a".to_string());
                write_injected_usage(&command, 7, 3);
                let mut run = injected_verified_run_without_journals(&command);
                retain_attribution_fixture(&mut run, &command, observed, app_server, rerouted);
                let original_evidence = run.codex_parent_evidence.clone();
                for role in [
                    AgentRole::ChildOrchestrator,
                    AgentRole::Researcher,
                    AgentRole::Worker,
                    AgentRole::Auditor,
                ] {
                    let ledger = RunBudgetLedger::new(budget.limits).unwrap();
                    let mut role_budget = budget.clone();
                    role_budget.role_token_reservations.insert(role, 50);
                    let DispatchBudgetAdmission::Admitted(mut reservation) =
                        reserve_dispatch_budget(
                            &plan,
                            &role_budget,
                            &ledger,
                            (role, SupervisorRuntime::Codex),
                            &command,
                        )
                        .unwrap()
                    else {
                        panic!("admission")
                    };
                    reservation
                        .mark_invoked_for_runtime(SupervisorRuntime::Codex)
                        .unwrap();
                    let settled = reservation.settle_bound_runtime(&run, &command).unwrap();
                    assert_eq!(settled.reliable_usage().unwrap().total_tokens, 10);
                    assert_eq!(settled.model.as_deref(), expected_model);
                    assert_eq!(settled.cost_usd, expected_cost);
                    let charged = ledger.report().unwrap();
                    assert_eq!(charged.consumed.tokens, 10);
                    assert_eq!(charged.consumed.cost_usd, expected_cost);
                    assert!(charged.usage_complete);
                    assert_eq!(
                        charged.new_dispatch_allowed,
                        !money_ceiling || expected_cost.is_some()
                    );
                    assert_eq!(charged.active_reservations, 0);
                    let lens_id =
                        (role == AgentRole::Auditor).then(|| plan.review_lenses[0].id.clone());
                    let sample = settled.role_sample(role, lens_id).unwrap();
                    // Reporting must use the settled price snapshot, even if plan rates change.
                    let mut later_plan = plan.clone();
                    later_plan
                        .model_pricing
                        .values_mut()
                        .for_each(|price| price.input_usd_per_million_tokens = 999.0);
                    let report = role_usage_report(&later_plan, vec![sample]).unwrap();
                    assert_eq!(report.total_cost_usd, charged.consumed.cost_usd);
                    assert_eq!(report.total_usage.unwrap().total_tokens, 10);
                    assert_eq!(
                        report.reports[&role].models,
                        expected_model
                            .into_iter()
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    );
                    assert_eq!(
                        report.reports[&AgentRole::Supervisor].cost_usd,
                        expected_cost
                    );
                    if role == AgentRole::Auditor {
                        let lens = report
                            .lens_reports
                            .iter()
                            .find(|lens| lens.usage.is_some())
                            .unwrap();
                        assert_eq!(lens.cost_usd, expected_cost);
                        assert_eq!(lens.model, expected_model.unwrap_or("unknown"));
                        assert_eq!(lens.usage.unwrap().total_tokens, 10);
                    }
                }
                assert_eq!(run.codex_parent_evidence, original_evidence);
                if observed.is_none() && app_server
                    || run.codex_parent_evidence.as_ref().unwrap().model_mismatch
                {
                    assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
                }
            }
        }
    }
}

#[test]
fn model_attribution_public_identity_and_conflicting_allocation_cannot_restore_cost() {
    let mut plan = injected_plan(injected_assignment(false), 0);
    inject_priced_process_roles(&mut plan, "model-a", 2.0);
    let temp = tempfile::tempdir().unwrap();
    let mut command = ExternalAgentCommand::codex(
        "unused",
        temp.path(),
        temp.path().join("prompt"),
        temp.path().join("usage"),
        temp.path().join("report"),
        Duration::from_secs(1),
    );
    command.model = Some("model-a".to_string());
    write_injected_usage(&command, 7, 3);
    for conflicting in [false, true] {
        let mut run = injected_verified_run_without_journals(&command);
        retain_attribution_fixture(&mut run, &command, Some("model-a"), false, false);
        if conflicting {
            run.codex_parent_evidence.as_mut().unwrap().rollout_model =
                crate::external_agent::CodexParentResolvedField::Known("model-b".to_string());
            run.retain_cli_parent_evidence_for_test(&fs::read(&command.json_log).unwrap());
        } else {
            let public = run.codex_parent_evidence.clone();
            run = injected_verified_run_without_journals(&command);
            run.codex_parent_evidence = public;
        }
        let budget = injected_run_budget(None, Some(1000), None, Some(1.0), 50, 50);
        let ledger = RunBudgetLedger::new(budget.limits).unwrap();
        let DispatchBudgetAdmission::Admitted(mut reservation) = reserve_dispatch_budget(
            &plan,
            &budget,
            &ledger,
            (AgentRole::ChildOrchestrator, SupervisorRuntime::Codex),
            &command,
        )
        .unwrap() else {
            panic!("admission")
        };
        reservation
            .mark_invoked_for_runtime(SupervisorRuntime::Codex)
            .unwrap();
        let settlement = reservation.settle_bound_runtime(&run, &command).unwrap();
        assert_eq!(settlement.reliable_usage().unwrap().total_tokens, 10);
        assert!(settlement.model.is_none());
        assert!(settlement.cost_usd.is_none());
        assert!(!ledger.report().unwrap().new_dispatch_allowed);
    }
}

#[test]
fn model_attribution_cli_invalid_aggregate_retains_unpriced_partial_lower_bound() {
    let mut plan = injected_plan(injected_assignment(false), 0);
    inject_priced_process_roles(&mut plan, "model-a", 7.0);
    let budget = injected_run_budget(None, Some(100_000), None, Some(1.0), 50, 50);
    let temp = tempfile::tempdir().unwrap();
    let mut command = ExternalAgentCommand::codex(
        "unused",
        temp.path(),
        temp.path().join("prompt"),
        temp.path().join("usage"),
        temp.path().join("report"),
        Duration::from_secs(1),
    );
    command.model = Some("model-a".to_string());
    for (overflow, log_tokens) in [(false, 37_000), (false, 2), (false, 40_000), (true, 0)] {
        write_injected_usage(&command, 37_000, 0);
        let mut run = injected_verified_run_without_journals(&command);
        retain_attribution_fixture(&mut run, &command, Some("model-a"), false, false);
        let lower_bound = if overflow {
            usize::MAX
        } else {
            37_000.max(log_tokens)
        };
        let (input, output) = if overflow {
            (usize::MAX - 1, 1)
        } else {
            (37_000, 0)
        };
        run.codex_parent_evidence.as_mut().unwrap().turn_usage =
            crate::external_agent::CodexParentTurnUsage::Known {
                input_tokens: u64::try_from(input).unwrap(),
                output_tokens: u64::try_from(output).unwrap(),
                cached_input_tokens: 0,
                reasoning_output_tokens: 0,
            };
        let invalid_stream = if overflow {
            let turn = format!(
                r#"{{"type":"turn.completed","usage":{{"input_tokens":{input},"output_tokens":{output}}}}}"#
            );
            format!("{turn}\n{turn}\n")
        } else {
            "{truncated".to_string()
        };
        run.retain_cli_parent_evidence_for_test(invalid_stream.as_bytes());
        if overflow {
            fs::write(&command.json_log, &invalid_stream).unwrap();
        } else {
            run.stdout.truncated = true;
            write_injected_usage(&command, log_tokens, 0);
        }
        assert!(run.authenticated_codex_usage().is_none());
        assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
        let ledger = RunBudgetLedger::new(budget.limits).unwrap();
        let DispatchBudgetAdmission::Admitted(mut reservation) = reserve_dispatch_budget(
            &plan,
            &budget,
            &ledger,
            (AgentRole::ChildOrchestrator, SupervisorRuntime::Codex),
            &command,
        )
        .unwrap() else {
            panic!("admission")
        };
        reservation
            .mark_invoked_for_runtime(SupervisorRuntime::Codex)
            .unwrap();
        let settled = reservation.settle_bound_runtime(&run, &command).unwrap();
        assert_eq!(settled.observed_usage.unwrap().total_tokens, lower_bound);
        assert_eq!(settled.reliability, DispatchUsageReliability::Estimated);
        assert!(settled.cost_usd.is_none());
        assert!(settled.model.is_none());
        let charged = ledger.report().unwrap();
        assert_eq!(charged.consumed.tokens, lower_bound);
        assert!(!charged.usage_complete);
        assert!(charged.consumed.cost_usd.is_none());
        assert!(!charged.new_dispatch_allowed);
        assert_eq!(charged.active_reservations, 0);
    }
}

#[test]
fn model_attribution_cli_multiple_turns_use_private_aggregate_for_ledger_and_roles() {
    let mut plan = injected_plan(injected_assignment(false), 0);
    inject_priced_process_roles(&mut plan, "model-a", 7.0);
    let budget = injected_run_budget(None, Some(1000), None, Some(1.0), 50, 50);
    let temp = tempfile::tempdir().unwrap();
    let mut command = ExternalAgentCommand::codex(
        "unused",
        temp.path(),
        temp.path().join("prompt"),
        temp.path().join("usage"),
        temp.path().join("report"),
        Duration::from_secs(1),
    );
    command.model = Some("model-a".to_string());
    let stdout = b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":10,\"output_tokens\":4}}\n{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":25,\"output_tokens\":7}}\n";
    fs::write(&command.json_log, stdout).unwrap();
    let mut run = injected_verified_run_without_journals(&command);
    retain_attribution_fixture(&mut run, &command, Some("model-a"), false, false);
    // The public identity schema retains only the last turn. Neither economics
    // nor settlement may confuse it with the private invocation-wide usage.
    run.codex_parent_evidence.as_mut().unwrap().turn_usage =
        crate::external_agent::CodexParentTurnUsage::Known {
            input_tokens: 25,
            output_tokens: 7,
            cached_input_tokens: 0,
            reasoning_output_tokens: 0,
        };
    run.retain_cli_parent_evidence_for_test(stdout);
    // A later writable log cannot replace the parent-held aggregate.
    write_injected_usage(&command, 1, 1);
    for role in [AgentRole::ChildOrchestrator, AgentRole::Auditor] {
        let ledger = RunBudgetLedger::new(budget.limits).unwrap();
        let DispatchBudgetAdmission::Admitted(mut reservation) = reserve_dispatch_budget(
            &plan,
            &budget,
            &ledger,
            (role, SupervisorRuntime::Codex),
            &command,
        )
        .unwrap() else {
            panic!("admission")
        };
        reservation
            .mark_invoked_for_runtime(SupervisorRuntime::Codex)
            .unwrap();
        let settled = reservation.settle_bound_runtime(&run, &command).unwrap();
        assert_eq!(
            settled.reliable_usage().unwrap(),
            Usage {
                input_tokens: 35,
                output_tokens: 11,
                total_tokens: 46
            }
        );
        assert_eq!(settled.cost_usd, Some(0.000322));
        let charged = ledger.report().unwrap();
        assert_eq!(charged.consumed.tokens, 46);
        assert_eq!(charged.consumed.cost_usd, settled.cost_usd);
        assert!(charged.usage_complete);
        assert_eq!(charged.active_reservations, 0);
        let sample = settled
            .role_sample(
                role,
                (role == AgentRole::Auditor).then(|| plan.review_lenses[0].id.clone()),
            )
            .unwrap();
        let reports = role_usage_report(&plan, vec![sample]).unwrap();
        assert_eq!(reports.total_usage.unwrap().total_tokens, 46);
        assert_eq!(reports.total_cost_usd, settled.cost_usd);
        if role == AgentRole::Auditor {
            assert_eq!(reports.lens_total_cost_usd, settled.cost_usd);
        }
    }
}

#[test]
fn model_attribution_child_and_auditor_paths_retain_tokens_without_accepting_unknown_identity() {
    skip_without_containment!();
    assert_attribution_pipeline_refuses_identity(None);
}

#[test]
fn model_attribution_child_and_auditor_reject_priced_start_model_mismatch() {
    skip_without_containment!();
    assert_attribution_pipeline_refuses_identity(Some("fallback-model"));
}

fn assert_attribution_pipeline_refuses_identity(observed: Option<&str>) {
    let _capability = install_budget_fixture_models();
    for unknown_auditor in [false, true] {
        // Known-cost identity refusals still require independent review of
        // reported changes. Unknown cost stops budget admission first.
        let expected_invocations = if observed.is_some() || unknown_auditor {
            2
        } else {
            1
        };
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(true);
        let mut plan = injected_plan(assignment.clone(), 0);
        inject_priced_process_roles(&mut plan, "priced-model", 2.0);
        plan.model_pricing.insert(
            "fallback-model".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 7.0,
                output_usd_per_million_tokens: 7.0,
            },
        );
        let budget = injected_run_budget(None, Some(1000), None, Some(1.0), 50, 50);
        let options = injected_options(&repo_path, temp.path(), "model-attribution-pipeline");
        let mut invocations = 0;
        let mut runner = |command: &ExternalAgentCommand| {
            invocations += 1;
            assert!(
                invocations <= expected_invocations,
                "no dispatch beyond the single required parent review"
            );
            let auditor = command
                .output_last_message
                .to_string_lossy()
                .contains("review-auditor");
            if auditor {
                write_injected_json(
                    &command.output_last_message,
                    &injected_auditor_report(&assignment, &injected_child_report(&assignment)),
                );
            } else {
                write_injected_assignment_report(command, &assignment);
            }
            write_injected_usage(command, 7, 3);
            let mut run = injected_verified_run(command);
            if auditor == unknown_auditor {
                retain_attribution_fixture(&mut run, command, observed, true, false);
                // The transport held a complete usage notice, then identity resolution
                // refused publication. Accounting must not erase the authentic tokens.
                if observed.is_none() {
                    run.publishable = false;
                    run.error =
                        Some("Codex app-server identity resolution is incomplete".to_string());
                }
                // A successfully completed transport with priced fallback identity must
                // still fail the actual child/Auditor acceptance gate.
                assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
            } else {
                retain_attribution_fixture(&mut run, command, Some("priced-model"), false, false);
            }
            run
        };
        let report = run_supervisor_plan_with_budget_and_runner(
            plan,
            SupervisorConsultantPlan::default(),
            budget,
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .unwrap();
        assert!(
            !report.success,
            "unknown or mismatched identity must not become acceptance"
        );
        assert!(!report.accepted);
        assert!(!report.publishable);
        assert_eq!(invocations, expected_invocations);
        let charged = report.run_budget.as_ref().unwrap();
        assert_eq!(charged.consumed.tokens, invocations * 10);
        assert_eq!(charged.active_reservations, 0);
        assert_eq!(charged.reserved.tokens, 0);
        assert!(charged.usage_complete);
        let rejected_cost = observed.map(|_| 0.00007);
        let total_cost = rejected_cost.map(|cost| {
            cost + if expected_invocations == 2 {
                0.00002
            } else {
                0.0
            }
        });
        assert_eq!(charged.consumed.cost_usd, total_cost);
        assert_eq!(report.total_cost_usd, total_cost);
        if observed.is_none() {
            assert!(!charged.new_dispatch_allowed);
        }
        assert_eq!(report.total_usage.unwrap().total_tokens, invocations * 10);
        let role = if unknown_auditor {
            AgentRole::Auditor
        } else {
            AgentRole::ChildOrchestrator
        };
        assert_eq!(report.role_usage[&role].usage.unwrap().total_tokens, 10);
        assert_eq!(
            report.role_usage[&role].models,
            observed.into_iter().map(str::to_string).collect::<Vec<_>>()
        );
        assert_eq!(report.role_usage[&role].cost_usd, rejected_cost);
        if unknown_auditor {
            let lens = report
                .review_lens_usage
                .iter()
                .find(|lens| lens.usage.is_some())
                .unwrap();
            assert_eq!(lens.model, observed.unwrap_or("unknown"));
            assert_eq!(lens.usage.unwrap().total_tokens, 10);
            assert_eq!(lens.cost_usd, rejected_cost);
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn researcher_source_inputs_local_refusal_settles_not_started_but_unknown_helper_is_conservative(
) -> Result<()> {
    use crate::external_agent::researcher_inputs::tests::{failed_local_probe, fixture};
    for unknown_helper in [false, true] {
        let (_root, mut command) = fixture()?;
        command.model = Some("gpt-5.6-sol".into());
        let plan = injected_plan(injected_assignment(false), 0);
        let mut budget = injected_run_budget(None, Some(100), None, None, 50, 50);
        budget
            .role_token_reservations
            .insert(AgentRole::Researcher, 50);
        let ledger = RunBudgetLedger::new(budget.limits)?;
        let DispatchBudgetAdmission::Admitted(mut reservation) = reserve_dispatch_budget(
            &plan,
            &budget,
            &ledger,
            (AgentRole::Researcher, SupervisorRuntime::Codex),
            &command,
        )?
        else {
            panic!("admission");
        };
        reservation.mark_invoked_for_runtime(SupervisorRuntime::Codex)?;
        let run = failed_local_probe(&command, unknown_helper)?;
        assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
        let settlement = reservation.settle_bound_runtime(&run, &command)?;
        assert!(settlement.observed_usage.is_none());
        assert!(settlement.cost_usd.is_none());
        let report = ledger.report()?;
        assert_eq!(report.active_reservations, 0);
        assert_eq!(report.reserved.tokens, 0);
        if unknown_helper {
            assert_eq!(settlement.reliability, DispatchUsageReliability::Missing);
            assert_eq!(report.consumed.tokens, 50);
            assert!(!report.new_dispatch_allowed);
        } else {
            assert_eq!(settlement.reliability, DispatchUsageReliability::NotStarted);
            assert_eq!(report.consumed.tokens, 0);
            assert!(report.new_dispatch_allowed);
            assert!(settlement
                .role_sample(AgentRole::Researcher, None)
                .is_none());
            // A public wire receipt never restores the private no-release proof.
            let restored: ExternalAgentRun = serde_json::from_value(serde_json::to_value(&run)?)?;
            assert!(external_dispatch_may_have_started(
                &restored,
                SupervisorRuntime::Codex
            ));
        }
        assert!(reservation.settle_bound_runtime(&run, &command).is_err());
        assert_eq!(
            ledger.report()?.consumed.tokens,
            if unknown_helper { 50 } else { 0 }
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn researcher_source_inputs_late_refusal_after_successful_probe_refunds_only_quiescent_prelaunch(
) -> Result<()> {
    use crate::external_agent::researcher_inputs::tests::{fixture, late_source_refusal};
    for (mutation, unknown_helper) in [
        ("changed", false),
        ("missing", false),
        ("rebound", false),
        ("changed", true),
    ] {
        let (_root, mut command) = fixture()?;
        command.model = Some("gpt-5.6-sol".into());
        let plan = injected_plan(injected_assignment(false), 0);
        let mut budget = injected_run_budget(None, Some(100), None, None, 50, 50);
        budget
            .role_token_reservations
            .insert(AgentRole::Researcher, 50);
        let ledger = RunBudgetLedger::new(budget.limits)?;
        let DispatchBudgetAdmission::Admitted(mut reservation) = reserve_dispatch_budget(
            &plan,
            &budget,
            &ledger,
            (AgentRole::Researcher, SupervisorRuntime::Codex),
            &command,
        )?
        else {
            panic!("admission");
        };
        reservation.mark_invoked_for_runtime(SupervisorRuntime::Codex)?;
        let run = late_source_refusal(&command, mutation, unknown_helper)?;
        assert!(run
            .error
            .as_deref()
            .is_some_and(|error| error.contains("source input changed before target release")));
        assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
        assert!(!run.publishable);
        let settlement = reservation.settle_bound_runtime(&run, &command)?;
        assert!(settlement.observed_usage.is_none());
        assert!(settlement.cost_usd.is_none());
        assert!(settlement
            .role_sample(AgentRole::Researcher, None)
            .is_none());
        assert_eq!(
            settlement.reliability,
            if unknown_helper {
                DispatchUsageReliability::Missing
            } else {
                DispatchUsageReliability::NotStarted
            }
        );
        let report = ledger.report()?;
        assert_eq!(report.active_reservations, 0);
        assert_eq!(report.reserved.tokens, 0);
        assert_eq!(report.consumed.tokens, if unknown_helper { 50 } else { 0 });
        assert_eq!(report.new_dispatch_allowed, !unknown_helper);
        assert!(reservation.settle_bound_runtime(&run, &command).is_err());
        assert_eq!(ledger.report()?.consumed.tokens, report.consumed.tokens);
        // Public serialization, including a forged witness key, cannot restore
        // the private proof that only local quiescent probes have run.
        let mut wire = serde_json::to_value(&run)?;
        wire["local_source_probe_refusal_quiescent"] = serde_json::json!(true);
        let restored: ExternalAgentRun = serde_json::from_value(wire)?;
        assert!(!restored.source_probe_confirmed_no_provider_release());
        assert!(external_dispatch_may_have_started(
            &restored,
            SupervisorRuntime::Codex
        ));
    }
    Ok(())
}
