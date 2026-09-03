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
    let _capability = install_budget_fixture_models();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(false);
    let mut plan = injected_plan(assignment, 0);
    let selection = RoleModelSelection {
        model: Some("unpriced-model".to_string()),
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
        AgentRole::ChildOrchestrator,
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
        AgentRole::ChildOrchestrator,
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
            AgentRole::ChildOrchestrator,
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
        AgentRole::ChildOrchestrator,
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
            AgentRole::ChildOrchestrator,
            &command,
        )
        .expect("later admission result"),
        DispatchBudgetAdmission::Refused(BudgetAdmissionRefusal::NewDispatchStopped)
    ));
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
        AgentRole::ChildOrchestrator,
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
