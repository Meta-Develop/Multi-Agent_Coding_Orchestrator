use super::*;
use crate::orchestration_event::{OrchestrationEvent, ORCHESTRATION_EVENT_PATH};
use git2::Signature;

static TEST_RUNTIME_MODEL_CATALOG: RuntimeModelCatalog =
    RuntimeModelCatalog::LocalDeterministicFake;

fn test_assignment(id: &str, path: &str) -> OrchestratorAssignment {
    OrchestratorAssignment {
        id: id.to_string(),
        phase: AssignmentPhase::Execution,
        runtime: None,
        role: AgentRole::ChildOrchestrator,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from(path)],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: None,
        worker_assignments: Vec::new(),
        environment_requirements: Vec::new(),
        licensed_breakage: None,
        notes: None,
    }
}

fn test_plan(assignments: Vec<OrchestratorAssignment>) -> SupervisorPlan {
    SupervisorPlan {
        version: SUPERVISOR_SCHEMA_VERSION,
        task: "scheduler decomposition fixture".to_string(),
        task_file: None,
        max_depth: MIN_SUPERVISOR_DEPTH,
        max_child_assignments: assignments.len(),
        max_child_retries: 0,
        max_gate_corrections: 0,
        child_timeout_seconds: 10,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: default_supervisor_review_lenses(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments,
    }
}

fn mechanical_assignment(id: &str) -> OrchestratorAssignment {
    let mut assignment = test_assignment(id, "mechanical.txt");
    assignment.worker_assignments.push(WorkerAssignment {
        id: "mechanical-worker".to_string(),
        role: AgentRole::Worker,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from("mechanical.txt")],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: None,
        environment_requirements: Vec::new(),
        report_path: None,
    });
    assignment
}

fn insert_mechanical_metadata(metadata: &mut AssignmentMetadata, assignment_id: &str) {
    metadata.insert(
        (assignment_id.to_string(), "mechanical-worker".to_string()),
        WorkerAssignmentMetadata {
            kind: AssignmentKind::Ordinary,
            mechanical_duty: Some(MechanicalTerminalDuty::RunPreselectedCommand),
            target_path: None,
        },
    );
}

fn worker_degrade_plan(assignments: Vec<OrchestratorAssignment>) -> SupervisorPlan {
    let mut plan = test_plan(assignments);
    plan.role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some(FRONTIER_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::OrderedCatalogChain(
                OrderedCatalogFallback {
                    models: Vec::new(),
                    budget_degrade_models: vec![ECONOMY_PROFILE_MODEL.to_string()],
                    on_exhausted: TerminalUnavailableModelFallback::FailClosed,
                },
            ),
        },
    );
    plan
}

fn degrade_report() -> RunBudgetReport {
    let ledger = RunBudgetLedger::new(RunBudgetLimits {
        soft_tokens: Some(1),
        hard_tokens: Some(4),
        soft_cost_usd: None,
        hard_cost_usd: None,
    })
    .expect("degradation ledger");
    ledger
        .reserve(BudgetReservationRequest {
            role: AgentRole::ChildOrchestrator,
            tokens: 1,
            cost_usd: None,
        })
        .expect("soft reservation")
        .report()
        .clone()
}

fn budget_policy_request<'a>(
    assignment: &'a OrchestratorAssignment,
    requested_reasoning_effort: Option<ReasoningEffort>,
    report: &'a RunBudgetReport,
    plan: &'a SupervisorPlan,
    requested_plan: &'a SupervisorPlan,
    assignment_metadata: &'a AssignmentMetadata,
    catalog: &'a RuntimeModelCatalog,
) -> AssignmentBudgetPolicyRequest<'a> {
    AssignmentBudgetPolicyRequest {
        assignment,
        requested_reasoning_effort,
        report,
        plan,
        requested_plan,
        assignment_metadata,
        catalog,
        runtime: SupervisorRuntime::Codex,
    }
}

#[test]
fn role_binding_telemetry_retains_catalog_fallback_resolution() {
    let mut plan = test_plan(Vec::new());
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
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
        },
    );
    let catalog = RuntimeModelCatalog::Codex(
        CodexRuntimeModelCatalog::from_slugs([FRONTIER_PROFILE_MODEL]).expect("fallback catalog"),
    );
    let bindings =
        resolved_role_execution_bindings(&plan, SupervisorRuntime::Codex, Some(&catalog));
    let binding = &bindings[&AgentRole::ChildOrchestrator];
    assert_eq!(
        binding.configured_model.as_deref(),
        Some(BALANCED_PROFILE_MODEL)
    );
    assert_eq!(
        binding.resolved_model.as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(
        binding.observation,
        RoleBindingObservation::RuntimeCatalogResolved
    );
    assert_eq!(
        binding.resolution_observation,
        ModelResolutionObservation::CatalogFallback
    );
    assert_eq!(binding.resolved_candidate_index, Some(1));
    assert_eq!(
        binding.configured_model_chain,
        vec![
            BALANCED_PROFILE_MODEL.to_string(),
            FRONTIER_PROFILE_MODEL.to_string(),
            ECONOMY_PROFILE_MODEL.to_string()
        ]
    );
}

#[test]
fn budget_degrade_ladder_applies_worker_model_effort_fanout_then_halts() {
    let mut model_assignment = test_assignment("model-assignment", "model.txt");
    model_assignment.worker_assignments.push(WorkerAssignment {
        id: "mechanical-worker".to_string(),
        role: AgentRole::Worker,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from("model.txt")],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: None,
        environment_requirements: Vec::new(),
        report_path: None,
    });
    let mut effort_assignment = model_assignment.clone();
    effort_assignment.id = "effort-assignment".to_string();
    let mut fanout_assignment = model_assignment.clone();
    fanout_assignment.id = "fanout-assignment".to_string();
    let halted_assignment = test_assignment("halted-assignment", "halted.txt");
    let mut plan = test_plan(Vec::new());
    plan.role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some(FRONTIER_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::OrderedCatalogChain(
                OrderedCatalogFallback {
                    models: Vec::new(),
                    budget_degrade_models: vec![ECONOMY_PROFILE_MODEL.to_string()],
                    on_exhausted: TerminalUnavailableModelFallback::FailClosed,
                },
            ),
        },
    );
    let requested_plan = plan.clone();
    let mut assignment_metadata = AssignmentMetadata::new();
    assignment_metadata.insert(
        (model_assignment.id.clone(), "mechanical-worker".to_string()),
        WorkerAssignmentMetadata {
            kind: AssignmentKind::Ordinary,
            mechanical_duty: Some(MechanicalTerminalDuty::RunPreselectedCommand),
            target_path: None,
        },
    );
    for assignment_id in [&effort_assignment.id, &fanout_assignment.id] {
        assignment_metadata.insert(
            (assignment_id.clone(), "mechanical-worker".to_string()),
            WorkerAssignmentMetadata {
                kind: AssignmentKind::Ordinary,
                mechanical_duty: Some(MechanicalTerminalDuty::RunPreselectedCommand),
                target_path: None,
            },
        );
    }
    let catalog = RuntimeModelCatalog::Codex(
        CodexRuntimeModelCatalog::from_slugs([
            FRONTIER_PROFILE_MODEL,
            BALANCED_PROFILE_MODEL,
            ECONOMY_PROFILE_MODEL,
        ])
        .expect("degradation catalog"),
    );
    let ledger = RunBudgetLedger::new(RunBudgetLimits {
        soft_tokens: Some(1),
        hard_tokens: Some(4),
        soft_cost_usd: None,
        hard_cost_usd: None,
    })
    .expect("degradation ledger");
    let soft = ledger
        .reserve(BudgetReservationRequest {
            role: AgentRole::ChildOrchestrator,
            tokens: 1,
            cost_usd: None,
        })
        .expect("soft reservation")
        .report()
        .clone();
    assert_eq!(soft.action, BudgetAction::Degrade);

    let mut controller = BudgetDegradationController::new(8);
    let model_policy = controller
        .assignment_policy(budget_policy_request(
            &model_assignment,
            None,
            &soft,
            &plan,
            &requested_plan,
            &assignment_metadata,
            &catalog,
        ))
        .expect("model degradation")
        .expect("model admission");
    assert_eq!(
        model_policy.apply(&plan).role_models[&AgentRole::Worker]
            .model
            .as_deref(),
        Some(ECONOMY_PROFILE_MODEL)
    );
    let effort_policy = controller
        .assignment_policy(budget_policy_request(
            &effort_assignment,
            None,
            &soft,
            &plan,
            &requested_plan,
            &assignment_metadata,
            &catalog,
        ))
        .expect("effort degradation")
        .expect("effort admission");
    assert_eq!(
        effort_policy.apply(&plan).role_models[&AgentRole::Worker]
            .reasoning_effort
            .as_deref(),
        Some("high")
    );
    controller
        .assignment_policy(budget_policy_request(
            &fanout_assignment,
            None,
            &soft,
            &plan,
            &requested_plan,
            &assignment_metadata,
            &catalog,
        ))
        .expect("fan-out degradation")
        .expect("fan-out admission");
    assert_eq!(controller.effective_fan_out, 4);

    let hard = ledger
        .reserve(BudgetReservationRequest {
            role: AgentRole::ChildOrchestrator,
            tokens: 3,
            cost_usd: None,
        })
        .expect("hard reservation")
        .report()
        .clone();
    assert_eq!(hard.action, BudgetAction::OwnerEscalation);
    assert!(controller
        .assignment_policy(budget_policy_request(
            &halted_assignment,
            None,
            &hard,
            &plan,
            &requested_plan,
            &assignment_metadata,
            &catalog,
        ))
        .expect("halt decision")
        .is_none());

    assert_eq!(controller.records.len(), 4);
    assert_eq!(
        controller.records[0].change,
        BudgetDegradationChange::ModelTier {
            role: AgentRole::Worker,
            before: FRONTIER_PROFILE_MODEL.to_string(),
            after: ECONOMY_PROFILE_MODEL.to_string(),
            resolved_candidate_index: 0,
        }
    );
    assert!(matches!(
        &controller.records[1].change,
        BudgetDegradationChange::ReasoningEffort { role: AgentRole::Worker, before, after }
            if before == "xhigh" && after == "high"
    ));
    assert_eq!(
        controller.records[2].change,
        BudgetDegradationChange::FanOut {
            before: 8,
            after: 4
        }
    );
    assert_eq!(
        controller.records[3].change,
        BudgetDegradationChange::Halt {
            before_new_dispatch_allowed: true,
            after_new_dispatch_allowed: false
        }
    );
    assert_eq!(
        controller.records[0].trigger,
        BudgetDegradationTrigger::BudgetPressure
    );
    let transition = controller.records[0]
        .role_binding_transition
        .as_ref()
        .expect("Worker model transition evidence");
    assert_eq!(transition.role, AgentRole::Worker);
    assert_eq!(
        transition.before.model.as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(
        transition.after.model.as_deref(),
        Some(ECONOMY_PROFILE_MODEL)
    );
    assert!(controller
        .records
        .iter()
        .take(3)
        .all(|record| { record.effective_child_model.as_deref() == Some(FRONTIER_PROFILE_MODEL) }));
    let mut construction = test_report_construction(
        &plan,
        RunId::new("budget-degradation-artifact").expect("run id"),
    );
    construction.budget_degradations = controller.records.clone();
    let final_report = build_supervisor_final_report(construction);
    assert_eq!(
        final_report
            .role_economics_profile
            .as_ref()
            .and_then(|profile| profile.execution.as_ref())
            .expect("execution telemetry")
            .budget_degradations,
        controller.records
    );
    let schema = supervisor_final_report_schema_value();
    let execution = &schema["properties"]["role_economics_profile"]["properties"]["execution"];
    assert!(execution["required"]
        .as_array()
        .is_some_and(|required| required.iter().any(|field| field == "budget_degradations")));
    assert_eq!(
        execution["properties"]["budget_degradations"]["items"]["properties"]["change"]["oneOf"][2]
            ["properties"]["kind"]["const"],
        "fan_out"
    );
}

#[test]
fn low_difficulty_mechanical_trigger_consumes_only_worker_requested_ladder() {
    let assignment = mechanical_assignment("low-difficulty-mechanical");
    let inherited_assignment = mechanical_assignment("inherited-mechanical");
    let plan = worker_degrade_plan(vec![assignment.clone(), inherited_assignment.clone()]);
    let requested_plan = plan.clone();
    let mut metadata = AssignmentMetadata::new();
    insert_mechanical_metadata(&mut metadata, &assignment.id);
    insert_mechanical_metadata(&mut metadata, &inherited_assignment.id);
    let catalog = RuntimeModelCatalog::Codex(
        CodexRuntimeModelCatalog::from_slugs([FRONTIER_PROFILE_MODEL, ECONOMY_PROFILE_MODEL])
            .expect("mechanical catalog"),
    );
    let report = RunBudgetLedger::new(RunBudgetLimits::default())
        .expect("unbounded budget")
        .report()
        .expect("unbounded report");
    let mut controller = BudgetDegradationController::new(4);

    let policy = controller
        .assignment_policy(budget_policy_request(
            &assignment,
            None,
            &report,
            &plan,
            &requested_plan,
            &metadata,
            &catalog,
        ))
        .expect("low-difficulty model degradation")
        .expect("assignment admitted");

    assert_eq!(report.action, BudgetAction::Continue);
    assert_eq!(
        policy.apply(&plan).role_models[&AgentRole::Worker]
            .model
            .as_deref(),
        Some(ECONOMY_PROFILE_MODEL)
    );
    assert_eq!(controller.records.len(), 1);
    assert_eq!(
        controller.records[0].trigger,
        BudgetDegradationTrigger::LowDifficultyMechanical
    );
    assert!(controller.records[0].budget_reasons.is_empty());
    assert_eq!(controller.effective_fan_out, 4);

    let inherited_policy = controller
        .assignment_policy(budget_policy_request(
            &inherited_assignment,
            None,
            &report,
            &plan,
            &requested_plan,
            &metadata,
            &catalog,
        ))
        .expect("inherited mechanical binding evidence")
        .expect("inherited assignment admitted");
    assert_eq!(controller.rung, BudgetDegradationRung::Effort);
    assert_eq!(controller.effective_fan_out, 4);
    assert_eq!(controller.records.len(), 2);
    assert_eq!(
        controller.records[1].change,
        BudgetDegradationChange::RoleBindingApplied {
            role: AgentRole::Worker
        }
    );
    assert_eq!(
        inherited_policy.apply(&plan).role_models[&AgentRole::Worker]
            .model
            .as_deref(),
        Some(ECONOMY_PROFILE_MODEL)
    );
    let mut ledger = build_assignment_selection_ledger(&plan, &[], SupervisorRuntime::Codex);
    apply_budget_degradations_to_selection_ledger(&mut ledger, &controller.records);
    let inherited = ledger
        .iter()
        .find(|entry| {
            entry.assignment_id == inherited_assignment.id && entry.role == AgentRole::Worker
        })
        .expect("inherited Worker ledger row");
    assert_eq!(
        inherited.selection_source,
        AssignmentSelectionSource::LowDifficultyMechanical
    );
    assert_eq!(
        inherited.selected_model.as_deref(),
        Some(ECONOMY_PROFILE_MODEL)
    );
}

#[test]
fn judgment_assignment_is_not_degraded_by_shared_worker_binding() {
    let seed_assignment = mechanical_assignment("mechanical-seed");
    let mut assignment = mechanical_assignment("judgment-assignment");
    assignment.worker_assignments.push(WorkerAssignment {
        id: "unmarked-worker".to_string(),
        role: AgentRole::Worker,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from("mechanical.txt")],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: None,
        environment_requirements: Vec::new(),
        report_path: None,
    });
    let plan = worker_degrade_plan(vec![seed_assignment.clone(), assignment.clone()]);
    let requested_plan = plan.clone();
    let mut metadata = AssignmentMetadata::new();
    insert_mechanical_metadata(&mut metadata, &seed_assignment.id);
    insert_mechanical_metadata(&mut metadata, &assignment.id);
    let catalog = RuntimeModelCatalog::Codex(
        CodexRuntimeModelCatalog::from_slugs([FRONTIER_PROFILE_MODEL, ECONOMY_PROFILE_MODEL])
            .expect("judgment exclusion catalog"),
    );
    let report = degrade_report();
    let mut controller = BudgetDegradationController::new(4);
    controller
        .assignment_policy(budget_policy_request(
            &seed_assignment,
            None,
            &report,
            &plan,
            &requested_plan,
            &metadata,
            &catalog,
        ))
        .expect("seed mechanical degradation")
        .expect("seed assignment admitted");

    let policy = controller
        .assignment_policy(budget_policy_request(
            &assignment,
            None,
            &report,
            &plan,
            &requested_plan,
            &metadata,
            &catalog,
        ))
        .expect("judgment assignment policy")
        .expect("judgment assignment admitted");

    let effective = policy.apply(&plan);
    assert_eq!(
        effective.role_models[&AgentRole::Worker].model.as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(
        effective.role_models[&AgentRole::ChildOrchestrator]
            .model
            .as_deref(),
        Some(FRONTIER_PROFILE_MODEL)
    );
    assert_eq!(controller.records.len(), 1);
    assert_eq!(controller.rung, BudgetDegradationRung::Effort);
    assert_eq!(controller.effective_fan_out, 4);
}

#[test]
fn worker_model_rung_refuses_no_distinct_eligible_target_without_advancing() {
    let assignment = mechanical_assignment("no-target");
    let mut plan = worker_degrade_plan(vec![assignment.clone()]);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some(FRONTIER_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::OrderedCatalogChain(
                OrderedCatalogFallback {
                    models: Vec::new(),
                    budget_degrade_models: vec![ECONOMY_PROFILE_MODEL.to_string()],
                    on_exhausted: TerminalUnavailableModelFallback::FailClosed,
                },
            ),
        },
    );
    let mut requested_plan = plan.clone();
    requested_plan
        .role_models
        .get_mut(&AgentRole::Worker)
        .expect("Worker selection")
        .unavailable_model_fallback =
        UnavailableModelFallback::OrderedCatalogChain(OrderedCatalogFallback {
            models: Vec::new(),
            budget_degrade_models: vec![
                FRONTIER_PROFILE_MODEL.to_string(),
                BALANCED_PROFILE_MODEL.to_string(),
            ],
            on_exhausted: TerminalUnavailableModelFallback::FailClosed,
        });
    let mut metadata = AssignmentMetadata::new();
    insert_mechanical_metadata(&mut metadata, &assignment.id);
    let catalog = RuntimeModelCatalog::Codex(
        CodexRuntimeModelCatalog::from_slugs([
            FRONTIER_PROFILE_MODEL,
            BALANCED_PROFILE_MODEL,
            ECONOMY_PROFILE_MODEL,
        ])
        .expect("no-target catalog"),
    );
    let report = degrade_report();
    let mut controller = BudgetDegradationController::new(8);

    let error = controller
        .assignment_policy(budget_policy_request(
            &assignment,
            None,
            &report,
            &plan,
            &requested_plan,
            &metadata,
            &catalog,
        ))
        .expect_err("no eligible Worker target must refuse degradation");

    assert!(error.to_string().contains(
        "requested-plan budget_degrade_models ladder has no distinct runtime-advertised authority-eligible target"
    ));
    assert_eq!(controller.rung, BudgetDegradationRung::ModelTier);
    assert_eq!(controller.effective_fan_out, 8);
    assert!(controller.records.is_empty());
}

#[test]
fn assignment_effort_resolves_per_duty_and_records_hard_floor_clamps() {
    let assignment = test_assignment("bounded-task", "bounded.txt");
    let mut plan = test_plan(vec![assignment.clone()]);
    let ReviewLensBackendConfig::Model {
        reasoning_effort, ..
    } = &mut plan.review_lenses[0].backend
    else {
        panic!("default review lens is model-backed");
    };
    *reasoning_effort = Some("low".to_string());
    let catalog = RuntimeModelCatalog::Codex(
        CodexRuntimeModelCatalog::from_slugs([FRONTIER_PROFILE_MODEL])
            .expect("assignment effort catalog"),
    );
    let report = RunBudgetLedger::new(RunBudgetLimits::default())
        .expect("unbounded ledger")
        .report()
        .expect("unbounded report");
    let mut controller = BudgetDegradationController::new(1);
    let assignment_metadata = AssignmentMetadata::new();
    let policy = controller
        .assignment_policy(budget_policy_request(
            &assignment,
            Some(ReasoningEffort::Low),
            &report,
            &plan,
            &plan,
            &assignment_metadata,
            &catalog,
        ))
        .expect("assignment effort resolution")
        .expect("assignment admission");
    let effective = policy.apply(&plan);
    assert_eq!(
        effective.role_models[&AgentRole::ChildOrchestrator]
            .reasoning_effort
            .as_deref(),
        Some("low")
    );
    assert_eq!(
        effective.role_models[&AgentRole::GateClassifier]
            .reasoning_effort
            .as_deref(),
        Some("high")
    );
    assert_eq!(
        effective.role_models[&AgentRole::Auditor]
            .reasoning_effort
            .as_deref(),
        Some("xhigh")
    );
    let child = controller
        .assignment_effort_bindings
        .iter()
        .find(|binding| binding.role == AgentRole::ChildOrchestrator)
        .expect("child binding");
    assert_eq!(child.requested_reasoning_effort, Some(ReasoningEffort::Low));
    assert_eq!(child.resolved_reasoning_effort, "low");
    assert_eq!(
        child.resolution_observation,
        EffortResolutionObservation::AssignmentOverride
    );
    let gate = controller
        .assignment_effort_bindings
        .iter()
        .find(|binding| binding.role == AgentRole::GateClassifier)
        .expect("gate binding");
    assert_eq!(gate.resolved_reasoning_effort, "high");
    assert_eq!(
        gate.resolution_observation,
        EffortResolutionObservation::HardFloorClamped
    );
    let auditor = controller
        .assignment_effort_bindings
        .iter()
        .find(|binding| binding.role == AgentRole::Auditor)
        .expect("auditor binding");
    assert_eq!(
        auditor.requested_reasoning_effort,
        Some(ReasoningEffort::Low)
    );
    assert_eq!(auditor.resolved_reasoning_effort, "xhigh");
    assert_eq!(
        auditor.resolution_observation,
        EffortResolutionObservation::HardFloorClamped
    );
    let mut construction = test_report_construction(
        &plan,
        RunId::new("assignment-effort-telemetry").expect("run id"),
    );
    construction.assignment_effort_bindings = controller.assignment_effort_bindings.clone();
    let final_report = build_supervisor_final_report(construction);
    assert_eq!(
        final_report
            .role_economics_profile
            .as_ref()
            .and_then(|profile| profile.execution.as_ref())
            .expect("execution telemetry")
            .assignment_effort_bindings,
        controller.assignment_effort_bindings
    );
    println!(
        "assignment_effort_telemetry {}",
        serde_json::to_string(&controller.assignment_effort_bindings)
            .expect("serialize effort telemetry")
    );
}

#[test]
fn protected_duty_floors_bound_budget_effort_degradation() {
    let gate = resolve_reasoning_effort(
        AgentRole::GateClassifier,
        Some(ReasoningEffort::Xhigh),
        Some("high"),
        4,
    );
    assert_eq!(gate.resolved, "high");
    assert_eq!(
        gate.observation,
        EffortResolutionObservation::HardFloorClamped
    );
    let auditor = resolve_reasoning_effort(
        AgentRole::Auditor,
        Some(ReasoningEffort::Ultra),
        Some("xhigh"),
        4,
    );
    assert_eq!(auditor.resolved, "xhigh");
    assert_eq!(
        auditor.observation,
        EffortResolutionObservation::HardFloorClamped
    );
}

fn root_schedule(plan: &SupervisorPlan) -> Vec<AssignmentScheduleEntry> {
    plan.assignments
        .iter()
        .enumerate()
        .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index,
        })
        .collect()
}

fn test_options(repo: &Path, run_id: &str) -> SupervisorRunOptions {
    SupervisorRunOptions {
        repo: repo.to_path_buf(),
        plan_file: repo.join("plan.json"),
        run_id: RunId::new(run_id).expect("valid scheduler test run id"),
        parent_node: None,
        codex_bin: PathBuf::from("unused-test-codex"),
        runtime: SupervisorRuntime::Fake,
        allow_dirty_primary: true,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: crate::supervise::RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(crate::machine_global::MachineGlobalRetentionBinding {
            config: repo.join("unused-machine-global.json"),
            root_id: "runtime".to_string(),
            owner: "maco-supervise-test".to_string(),
            correction_correlation_id: run_id.to_string(),
        }),
    }
}

fn test_repository() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("temporary scheduler repository");
    let repo = temp.path().join("repo");
    let repository = Repository::init(&repo).expect("initialize scheduler repository");
    fs::write(repo.join("README.md"), "scheduler fixture\n")
        .expect("write scheduler repository fixture");
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .expect("write second scheduler repository fixture");
    fs::create_dir(repo.join("tests")).expect("create scheduler test-target directory");
    fs::write(
        repo.join("tests/scheduler_preclaim.rs"),
        "#[test]\nfn scheduler_preclaim_fixture() {}\n",
    )
    .expect("write scheduler test-target fixture");
    fs::write(
        repo.join("tests/scheduler_preclaim_b.rs"),
        "#[test]\nfn scheduler_preclaim_b_fixture() {}\n",
    )
    .expect("write second scheduler test-target fixture");
    let mut index = repository.index().expect("open scheduler fixture index");
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .expect("stage scheduler fixture");
    index.write().expect("write scheduler fixture index");
    let tree_id = index.write_tree().expect("write scheduler fixture tree");
    let tree = repository
        .find_tree(tree_id)
        .expect("find scheduler fixture tree");
    let signature =
        Signature::now("maco test", "maco-test@example.invalid").expect("fixture signature");
    repository
        .commit(Some("HEAD"), &signature, &signature, "baseline", &tree, &[])
        .expect("commit scheduler fixture");
    (temp, repo)
}

macro_rules! with_invalid_schedule_context {
    ($context:ident, $body:block) => {{
        let (_temp, repo) = test_repository();
        let options = test_options(&repo, "direct-scheduler");
        let plan = test_plan(vec![test_assignment("child-a", "README.md")]);
        let schedule = Vec::new();
        let consultant = SupervisorConsultantPlan::default();
        let assignment_metadata = AssignmentMetadata::new();
        let budget_config = SupervisorBudgetConfig::default();
        let budget_ledger = RunBudgetLedger::new(budget_config.limits).expect("test budget ledger");
        let mut artifact_writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            options.run_id.clone(),
            "scheduler-decomposition-test",
        )
        .expect("reserve scheduler artifacts");
        let run_dir = artifact_writer.run_dir().to_path_buf();
        let dirs = RunDirs::for_writer(&artifact_writer);
        let manager = WorktreeManager::new(&repo);
        let existing_ids = BTreeSet::new();
        let sync_store = SyncStore::open(&repo).expect("open scheduler sync store");
        let semantic_store =
            SemanticIntentStore::open(&repo).expect("open scheduler semantic store");
        let prepared = vec![PreparedSemanticAssignment::default()];
        let field_guide = SupervisorFieldGuidePrompt::empty().expect("empty scheduler field guide");
        let mut journal = initialize_orchestration_event_journal(
            &repo,
            &options.run_id,
            options.parent_node.as_deref(),
        );
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut artifact_writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let runtime_model_catalog = RuntimeModelCatalog::LocalDeterministicFake;
        let runner = |_: &ExternalAgentCommand,
                      _: &ProcessCancellation,
                      _: Option<ExternalPreActionReviewRuntime<'_>>|
         -> ExternalAgentRun {
            panic!("invalid schedule must fail before external dispatch")
        };
        let $context = AssignmentSchedulerContext {
            plan: &plan,
            requested_plan: &plan,
            execution_target: None,
            budget_config: &budget_config,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            evidence_only_reaudit: None,
            options: &options,
            repo: &repo,
            run_dir: &run_dir,
            dirs: &dirs,
            execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
            worktree_creation: SupervisorWorktreeCreation::TestOnly,
            manager: &manager,
            existing_ids: &existing_ids,
            sync_store: &sync_store,
            semantic_store: &semantic_store,
            prepared_semantic_assignments: &prepared,
            assignment_schedule: &schedule,
            field_guide: &field_guide,
            artifacts: &shared_artifacts,
            budget_ledger: &budget_ledger,
            runtime_model_catalog: &runtime_model_catalog,
            external_runner: &runner,
            release_per_assignment: false,
        };
        $body
    }};
}

macro_rules! with_valid_schedule_context {
    ($context:ident, $assignments:expr, $max_children:expr, $body:block) => {{
        let assignments = $assignments;
        let requested_assignments = assignments.clone();
        with_valid_schedule_context!(
            @plans,
            $context,
            assignments,
            requested_assignments,
            $max_children,
            $body
        )
    }};
    (
        $context:ident,
        current = $assignments:expr,
        requested = $requested_assignments:expr,
        $max_children:expr,
        $body:block
    ) => {{
        with_valid_schedule_context!(
            @plans,
            $context,
            $assignments,
            $requested_assignments,
            $max_children,
            $body
        )
    }};
    (
        @plans,
        $context:ident,
        $assignments:expr,
        $requested_assignments:expr,
        $max_children:expr,
        $body:block
    ) => {{
        let (_temp, repo) = test_repository();
        let options = test_options(&repo, "direct-valid-scheduler");
        let plan = test_plan($assignments);
        let requested_plan = test_plan($requested_assignments);
        let schedule = root_schedule(&plan);
        let consultant = SupervisorConsultantPlan::default();
        let assignment_metadata = AssignmentMetadata::new();
        let budget_config = SupervisorBudgetConfig::default();
        let budget_ledger = RunBudgetLedger::new(budget_config.limits).expect("test budget ledger");
        let mut artifact_writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            options.run_id.clone(),
            "scheduler-success-test",
        )
        .expect("reserve scheduler artifacts");
        let run_dir = artifact_writer.run_dir().to_path_buf();
        let dirs = RunDirs::for_writer(&artifact_writer);
        let manager = WorktreeManager::new(&repo);
        let existing_ids = BTreeSet::new();
        let sync_store = SyncStore::open(&repo).expect("open scheduler sync store");
        let semantic_store =
            SemanticIntentStore::open(&repo).expect("open scheduler semantic store");
        let prepared = plan
            .assignments
            .iter()
            .map(|_| PreparedSemanticAssignment::default())
            .collect::<Vec<_>>();
        let field_guide = SupervisorFieldGuidePrompt::empty().expect("empty scheduler field guide");
        let mut journal = initialize_orchestration_event_journal(
            &repo,
            &options.run_id,
            options.parent_node.as_deref(),
        );
        let mut autonomy_kpis = AutonomyKpiCollector::default();
        let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut artifact_writer,
            journal: &mut journal,
            autonomy_kpis: &mut autonomy_kpis,
            checkpoint: None,
        });
        let runtime_model_catalog = RuntimeModelCatalog::LocalDeterministicFake;
        let runner = |_: &ExternalAgentCommand,
                      _: &ProcessCancellation,
                      _: Option<ExternalPreActionReviewRuntime<'_>>|
         -> ExternalAgentRun {
            panic!("fake scheduler success fixture must not invoke the external runner")
        };
        let $context = AssignmentSchedulerContext {
            plan: &plan,
            requested_plan: &requested_plan,
            execution_target: None,
            budget_config: &budget_config,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            evidence_only_reaudit: None,
            options: &options,
            repo: &repo,
            run_dir: &run_dir,
            dirs: &dirs,
            execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
            worktree_creation: SupervisorWorktreeCreation::TestOnly,
            manager: &manager,
            existing_ids: &existing_ids,
            sync_store: &sync_store,
            semantic_store: &semantic_store,
            prepared_semantic_assignments: &prepared,
            assignment_schedule: &schedule,
            field_guide: &field_guide,
            artifacts: &shared_artifacts,
            budget_ledger: &budget_ledger,
            runtime_model_catalog: &runtime_model_catalog,
            external_runner: &runner,
            release_per_assignment: true,
        };
        $body
    }};
}

fn test_report_construction(
    plan: &SupervisorPlan,
    run_id: RunId,
) -> SupervisorFinalReportConstruction<'_> {
    SupervisorFinalReportConstruction {
        plan,
        runtime_model_catalog: Some(&TEST_RUNTIME_MODEL_CATALOG),
        max_concurrent_children: 1,
        admission_policy_input: SupervisorAdmissionPolicyInput::resolve(
            Path::new("."),
            1,
            SupervisorAdmissionConfig::default(),
            SupervisorAdmissionConfig::default(),
        )
        .expect("test admission policy"),
        achieved_concurrency: AchievedConcurrency::default(),
        has_multiple_independent_assignment_scopes: false,
        run_id,
        report_plan_file: PathBuf::from("plan.json"),
        report_run_dir: PathBuf::from(".maco/o2/runs/test"),
        runtime: SupervisorRuntime::Fake,
        publishable: false,
        success: true,
        run_budget_report: None,
        budget_degradations: Vec::new(),
        assignment_effort_bindings: Vec::new(),
        evidence_only_reaudit: None,
        role_usage: BTreeMap::new(),
        review_lens_usage: Vec::new(),
        review_lens_total_usage: None,
        review_lens_total_cost_usd: None,
        total_usage: None,
        total_cost_usd: None,
        usage_complete: true,
        environment_failures: Vec::new(),
        sandbox_denials: Vec::new(),
        collected: CollectedAssignmentOutcomes::default(),
        bloated_file_flags: Vec::new(),
        decomposition_candidates: Vec::new(),
        assignment_traceability: Vec::new(),
        coverage_gaps: Vec::new(),
        supervisor_breaker_trip: None,
        autonomy_kpis: AutonomyKpiReport::default(),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        external_containment_failed: false,
        final_primary_integrity_failed: false,
        budget_prevented_dispatch: false,
        budget_accounting_failed: false,
        breaker_tripped: false,
        field_guide_mutation_failed: false,
    }
}

#[test]
fn ready_nonoverlap_selector_skips_active_path_conflict() {
    let plan = test_plan(vec![
        test_assignment("active", "src"),
        test_assignment("overlap", "src/lib.rs"),
        test_assignment("ready", "README.md"),
    ]);
    let schedule = root_schedule(&plan);
    let pending = BTreeSet::from([1, 2]);
    let outcomes = (0..plan.assignments.len())
        .map(|_| None)
        .collect::<Vec<_>>();

    let selected = select_ready_nonoverlapping_assignment(
        &pending,
        &schedule,
        &outcomes,
        &plan,
        std::iter::once(0),
    )
    .expect("select a ready non-overlapping assignment");

    assert_eq!(selected, Some(2));
}

#[test]
fn strict_parent_child_schedule_is_not_independent_fan_out() {
    let schedule = vec![
        AssignmentScheduleEntry {
            assignment_id: "parent".to_string(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index: 0,
        },
        AssignmentScheduleEntry {
            assignment_id: "child".to_string(),
            parent_assignment_id: Some("parent".to_string()),
            depth: MIN_SUPERVISOR_DEPTH + 1,
            flattened_index: 1,
        },
    ];

    assert!(!has_multiple_independent_assignment_scopes(
        &schedule,
        &SupervisorPlanMetadata::default()
    ));

    let metadata = SupervisorPlanMetadata {
        spec_fragment_ids: vec!["scope-a".to_string(), "scope-b".to_string()],
        ..SupervisorPlanMetadata::default()
    };
    assert!(has_multiple_independent_assignment_scopes(
        &schedule, &metadata
    ));
}

#[test]
fn serial_scheduler_preserves_schedule_error_context() {
    with_invalid_schedule_context!(context, {
        let mut progress = SchedulerProgress::new(1, 1);
        let cancellation = ProcessCancellation::new();
        let serial_intents = Mutex::new(Vec::new());
        let error =
            run_serial_assignment_schedule(&context, &mut progress, &cancellation, &serial_intents)
                .expect_err("invalid serial schedule must fail");
        assert_eq!(
            error.to_string(),
            "assignment admission referenced an index outside the validated schedule"
        );
        assert!(progress.indexed_outcomes[0].is_none());
    });
}

#[test]
fn concurrent_scheduler_preserves_schedule_error_context_before_spawning() {
    with_invalid_schedule_context!(context, {
        let mut progress = SchedulerProgress::new(1, 1);
        let cancellation = ProcessCancellation::new();
        let semantic_block_gate = SemanticBlockGate::default();
        let error = run_concurrent_assignment_schedule(
            &context,
            &mut progress,
            &cancellation,
            &semantic_block_gate,
        )
        .expect_err("invalid concurrent schedule must fail");
        assert_eq!(
            error.to_string(),
            "assignment admission referenced an index outside the validated schedule"
        );
        assert!(progress.indexed_outcomes[0].is_none());
    });
}

#[test]
fn preclaim_viable_assignment_passes_unchanged_and_completes_normally() {
    // Fake dispatch keeps the provisional default model's configured
    // capability evidence; it does not treat an empty resolved slug as
    // authority by itself.
    let mut viable_assignment = test_assignment("serial-child", "tests/scheduler_preclaim.rs");
    viable_assignment.task = Some(
        "update tests/scheduler_preclaim.rs and run cargo test --test scheduler_preclaim"
            .to_string(),
    );
    let unchanged_assignment = viable_assignment.clone();
    with_valid_schedule_context!(context, vec![viable_assignment], 1, {
        let mut progress = SchedulerProgress::new(1, 2);
        let cancellation = ProcessCancellation::new();
        let serial_intents = Mutex::new(Vec::new());

        run_serial_assignment_schedule(&context, &mut progress, &cancellation, &serial_intents)
            .expect("serial scheduler dispatch succeeds");

        let outcome = progress.indexed_outcomes[0]
            .as_ref()
            .expect("serial scheduler stores completed outcome");
        assert_eq!(
            outcome.report.as_ref().map(|report| report.id.as_str()),
            Some("serial-child")
        );
        assert!(outcome.fatal_error.is_none());
        assert!(!outcome.assignment_failed);
        assert_eq!(outcome.released_claims.len(), 1);
        assert!(outcome.release_errors.is_empty());
        assert!(outcome.semantic_release_errors.is_empty());
        let concurrency = progress.concurrency.finish();
        assert_eq!(concurrency.started_assignment_count, 1);
        assert_eq!(concurrency.completed_assignment_count, 1);
        assert_eq!(concurrency.peak, 1);
        assert!(concurrency
            .mean
            .is_some_and(|mean| mean > 0.0 && mean <= 1.0));
        assert_eq!(
            outcome.claimed_paths,
            vec![PathBuf::from("tests/scheduler_preclaim.rs")]
        );
        assert_eq!(context.plan.assignments[0], unchanged_assignment);
        let decisions =
            fs::read_to_string(context.run_dir.join(preclaim::PRECLAIM_DECISIONS_RELATIVE))
                .expect("read recorded pre-claim decisions");
        assert!(
            decisions.contains("\"disposition\":\"claim\"")
                || decisions.contains("\"disposition\": \"claim\"")
        );
        assert!(
            decisions.contains("\"evidence_source\":\"synthetic_simulation\"")
                || decisions.contains("\"evidence_source\": \"synthetic_simulation\"")
        );
        assert!(decisions.contains("serial-child"));
    });
}

fn requested_preclaim_directive(json: &str) -> String {
    format!("maco-preclaim-v1:{json}")
}

fn read_recorded_preclaim_decisions(run_dir: &Path) -> Vec<preclaim::PreclaimDecision> {
    fs::read_to_string(run_dir.join(preclaim::PRECLAIM_DECISIONS_RELATIVE))
        .expect("read recorded pre-claim decisions")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("parse recorded pre-claim decision"))
        .collect()
}

#[test]
fn trusted_requested_plan_claim_override_is_recorded_before_scheduler_claim_state() {
    let mut current = test_assignment("trusted-claim", "README.md");
    current.task = Some("update the bounded documentation assignment".to_string());
    let mut requested = current.clone();
    requested.notes = Some(requested_preclaim_directive(
        r#"{"operator_override":{"disposition":"claim","rationale":"operator reviewed the bounded documentation change"}}"#,
    ));

    with_valid_schedule_context!(
        context,
        current = vec![current],
        requested = vec![requested],
        1,
        {
            let evidence = PreclaimRunEvidence::acquire(
                context.repo,
                SupervisorRuntime::Fake,
                SupervisorExecutionRuntime::Verified,
            );
            let decision = preclaim_assignment(
                context.artifacts,
                &context.plan.assignments[0],
                &context.requested_plan.assignments,
                &evidence,
            )
            .expect("trusted claim override produces a persisted decision");

            assert_eq!(decision.disposition, preclaim::PreclaimDisposition::Claim);
            assert_eq!(
                decision.triage_outcome,
                preclaim::PreclaimTriageOutcome::OperatorOverride
            );
            assert_eq!(
                decision.authority,
                preclaim::PreclaimDecisionAuthority::Operator
            );
            assert!(decision.map_present && decision.risk_present && decision.runtime_present);
            assert_eq!(
                decision.dimensions.clear_verification_path,
                preclaim::ViabilityFinding::Unknown
            );
            let recorded_override = decision
                .operator_override
                .as_ref()
                .expect("claim override remains typed on the decision");
            assert_eq!(
                recorded_override.rationale,
                "operator reviewed the bounded documentation change"
            );
            assert!(!recorded_override.rationale.trim().is_empty());
            assert!(!decision.reason.contains("README.md"));

            let recorded_decisions = read_recorded_preclaim_decisions(context.run_dir);
            let [recorded_before_claim] = recorded_decisions.as_slice() else {
                panic!("trusted claim override must persist exactly one pre-claim decision");
            };
            assert_eq!(recorded_before_claim, &decision);
            assert!(context
                .sync_store
                .snapshot()
                .expect("snapshot claims before scheduler admission")
                .is_empty());
            assert!(context
                .manager
                .list()
                .expect("list worktrees before scheduler admission")
                .is_empty());
            assert!(!context
                .run_dir
                .join("assignments/trusted-claim.prompt.md")
                .exists());

            let mut progress = SchedulerProgress::new(1, 1);
            progress
                .install_preclaim_decisions(vec![decision])
                .expect("install trusted prepared pre-claim decision");
            let cancellation = ProcessCancellation::new();
            let serial_intents = Mutex::new(Vec::new());
            run_serial_assignment_schedule(&context, &mut progress, &cancellation, &serial_intents)
                .expect("trusted claim override admits the otherwise ambiguous assignment");

            let outcome = progress.indexed_outcomes[0]
                .as_ref()
                .expect("claim override stores an execution outcome");
            assert!(!outcome.assignment_failed);
            assert!(outcome.report.is_some());
            assert_eq!(outcome.claimed_paths, vec![PathBuf::from("README.md")]);
            assert_eq!(outcome.released_claims.len(), 1);
            assert_eq!(progress.concurrency.finish().started_assignment_count, 1);
        }
    );
}

#[test]
fn verified_preparation_uses_requested_plan_override_before_assignment_selection_or_claim() {
    let (_temp, repo) = test_repository();
    let mut assignment = test_assignment("verified-operator-claim", "README.md");
    assignment.task = Some("update the bounded documentation assignment".to_string());
    assignment.notes = Some(requested_preclaim_directive(
        r#"{"operator_override":{"disposition":"claim","rationale":"authenticated caller approved the ambiguous verification path"}}"#,
    ));
    let plan = test_plan(vec![assignment]);
    let catalog = test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)
        .expect("construct deterministic Codex selector catalog");
    let mut options = test_options(&repo, "verified-operator-claim");
    options.runtime = SupervisorRuntime::Codex;

    let prepared = prepare_supervisor_run(
        LoadedSupervisorPlan {
            plan,
            consultant: SupervisorConsultantPlan::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        },
        &options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::VerifiedTestOnly,
        Ok(catalog),
    )
    .expect("trusted requested-plan override passes verified scheduler preparation");

    let [decision] = prepared.preclaim_decisions.as_slice() else {
        panic!("verified preparation must retain exactly one pre-claim decision");
    };
    assert_eq!(decision.disposition, preclaim::PreclaimDisposition::Claim);
    assert_eq!(
        decision.triage_outcome,
        preclaim::PreclaimTriageOutcome::OperatorOverride
    );
    assert_eq!(
        decision.authority,
        preclaim::PreclaimDecisionAuthority::Operator
    );
    assert!(decision.map_present && decision.risk_present && decision.runtime_present);
    assert_eq!(
        decision.dimensions.clear_verification_path,
        preclaim::ViabilityFinding::Unknown
    );
    assert_eq!(
        decision
            .operator_override
            .as_ref()
            .map(|operator_override| operator_override.rationale.as_str()),
        Some("authenticated caller approved the ambiguous verification path")
    );
    assert!(!prepared.selection_decisions.is_empty());
    assert!(!prepared.plan.role_models.is_empty());
    assert!(prepared.requested_plan.role_models.is_empty());

    let recorded = read_recorded_preclaim_decisions(&prepared.run_dir);
    assert_eq!(recorded, prepared.preclaim_decisions);
    assert!(SyncStore::open(&repo)
        .expect("open verified pre-claim sync store")
        .snapshot()
        .expect("snapshot verified pre-claim sync store")
        .is_empty());
    assert!(prepared
        .manager
        .list()
        .expect("list verified pre-claim worktrees")
        .is_empty());
    assert!(!prepared
        .run_dir
        .join("assignments/verified-operator-claim.prompt.md")
        .exists());
}

fn preselection_failure_assignment(assignment_id: &str) -> OrchestratorAssignment {
    let mut assignment = mechanical_assignment(assignment_id);
    assignment.assigned_paths = vec![PathBuf::from("tests/scheduler_preclaim.rs")];
    assignment.task = Some(
        "update tests/scheduler_preclaim.rs and run cargo test --test scheduler_preclaim"
            .to_string(),
    );
    assignment.worker_assignments[0].assigned_paths = assignment.assigned_paths.clone();
    assignment
}

fn assert_preselection_failure_has_no_assignment_side_effects(
    repo: &Path,
    run_id: &RunId,
    assignment_id: &str,
) {
    assert!(SyncStore::open(repo)
        .expect("open failed-preselection claim store")
        .snapshot()
        .expect("snapshot failed-preselection claim store")
        .is_empty());
    assert!(WorktreeManager::new(repo)
        .list()
        .expect("list failed-preselection worktrees")
        .is_empty());

    let run_dir = repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id.as_str());
    assert!(run_dir.is_dir());
    for forbidden in [
        PathBuf::from(SELECTION_LEDGER_RELATIVE),
        RunArtifactFamily::Supervise.final_report_relative_path(),
        PathBuf::from(format!("assignments/{assignment_id}.prompt.md")),
        PathBuf::from(format!(
            "assignments/{assignment_id}.attempt-1.worktree-writable-admission.json"
        )),
        PathBuf::from(format!("reports/{assignment_id}.json")),
        PathBuf::from(format!("evidence/incoming/{assignment_id}.json")),
        PathBuf::from(format!("logs/{assignment_id}.jsonl")),
        PathBuf::from(format!("logs/{assignment_id}.summary.json")),
        PathBuf::from(format!(
            "logs/workers/{assignment_id}/mechanical-worker.jsonl"
        )),
    ] {
        assert!(
            !run_dir.join(&forbidden).exists(),
            "failed preselection unexpectedly created {}",
            forbidden.display()
        );
    }
    for forbidden_directory in ["assignments", "selection", "reports", "logs", "incoming"] {
        assert!(
            !run_dir.join(forbidden_directory).exists(),
            "failed preselection unexpectedly created {forbidden_directory}"
        );
    }

    let rolling_budget_root = repo
        .join(".git/maco/state")
        .join(crate::budget_ledger::BUDGET_LEDGER_ROOT_NAME)
        .join("workspace");
    assert!(
        !rolling_budget_root.exists(),
        "failed preselection must not reserve or consume workspace budget"
    );
    assert!(
        open_supervisor_checkpoint(repo, run_id).is_err(),
        "failed preselection must not create a checkpoint or assignment_started record"
    );
}

#[test]
fn preclaim_early_durability_survives_objective_preselection_failure() {
    let (_temp, repo) = test_repository();
    let assignment_id = "durable-before-preselection-failure";
    let assignment = preselection_failure_assignment(assignment_id);
    assert!(assignment.runtime.is_none());
    let plan = test_plan(vec![assignment]);
    assert!(plan.role_models.is_empty());
    let catalog = test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)
        .expect("construct deterministic Codex selector catalog");
    let plan_metadata = SupervisorPlanMetadata {
        objective_profile: Some("missing-preclaim-durability-v1".to_string()),
        ..SupervisorPlanMetadata::default()
    };
    let run_id = RunId::new("durable-before-preselection-failure")
        .expect("valid failed-preselection run id");
    let mut options = test_options(&repo, run_id.as_str());
    options.runtime = SupervisorRuntime::Codex;

    let error = match prepare_supervisor_run(
        LoadedSupervisorPlan {
            plan,
            consultant: SupervisorConsultantPlan::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata,
        },
        &options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::VerifiedTestOnly,
        Ok(catalog),
    ) {
        Ok(_) => panic!("unknown objective profile must fail scheduler preselection"),
        Err(error) => error,
    };
    let error = format!("{error:#}");
    assert!(error.contains("failed to resolve the supervisor objective profile"));
    assert!(error.contains("unknown objective profile id 'missing-preclaim-durability-v1'"));

    let run_dir = repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id.as_str());
    let decisions = read_recorded_preclaim_decisions(&run_dir);
    let [decision] = decisions.as_slice() else {
        panic!("preselection failure must retain exactly one private pre-claim decision");
    };
    assert_eq!(decision.assignment_id, assignment_id);
    assert_eq!(decision.disposition, preclaim::PreclaimDisposition::Claim);

    let events = fs::read_to_string(run_dir.join(ORCHESTRATION_EVENT_PATH))
        .expect("read failed-preselection orchestration events")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str::<OrchestrationEvent>(line)
                .expect("parse failed-preselection orchestration event")
        })
        .filter(|event| event.node == assignment_id && event.kind == OrchestrationEventKind::Gate)
        .collect::<Vec<_>>();
    let [gate] = events.as_slice() else {
        panic!("preselection failure must retain exactly one assignment Gate event");
    };
    assert_eq!(gate.payload["assignment_id"].as_str(), Some(assignment_id));
    assert_eq!(gate.payload["disposition"].as_str(), Some("claim"));

    assert_preselection_failure_has_no_assignment_side_effects(&repo, &run_id, assignment_id);
}

#[test]
fn preclaim_early_durability_gate_failure_stops_before_assignment_side_effects() {
    let (_temp, repo) = test_repository();
    let assignment_id = "preclaim-gate-persistence-failure";
    let assignment = preselection_failure_assignment(assignment_id);
    assert!(assignment.runtime.is_none());
    let plan = test_plan(vec![assignment]);
    assert!(plan.role_models.is_empty());
    let catalog = test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)
        .expect("construct deterministic Codex selector catalog");
    let run_id = RunId::new("preclaim-gate-persistence-failure")
        .expect("valid Gate-persistence-failure run id");
    let mut options = test_options(&repo, run_id.as_str());
    options.runtime = SupervisorRuntime::Codex;
    crate::orchestration_event::set_orchestration_event_append_fault();

    let error = match prepare_supervisor_run(
        LoadedSupervisorPlan {
            plan,
            consultant: SupervisorConsultantPlan::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        },
        &options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::VerifiedTestOnly,
        Ok(catalog),
    ) {
        Ok(_) => panic!("failed pre-claim Gate persistence must stop scheduler preparation"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("failed to persist pre-claim orchestration Gate event"));

    let run_dir = repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id.as_str());
    let decisions = read_recorded_preclaim_decisions(&run_dir);
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].assignment_id, assignment_id);
    let assignment_gate_count = fs::read_to_string(run_dir.join(ORCHESTRATION_EVENT_PATH))
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str::<OrchestrationEvent>(line)
                .expect("parse Gate-persistence-failure orchestration event")
        })
        .filter(|event| event.node == assignment_id && event.kind == OrchestrationEventKind::Gate)
        .count();
    assert_eq!(assignment_gate_count, 0);

    assert_preselection_failure_has_no_assignment_side_effects(&repo, &run_id, assignment_id);
}

#[test]
fn trusted_requested_plan_park_override_is_reversible_and_has_no_scheduler_side_effects() {
    let mut current = mechanical_assignment("trusted-park");
    current.assigned_paths = vec![PathBuf::from("tests/scheduler_preclaim.rs")];
    current.worker_assignments[0].assigned_paths = current.assigned_paths.clone();
    let mut requested = current.clone();
    requested.notes = Some(requested_preclaim_directive(
        r#"{"operator_override":{"disposition":"park","rationale":"operator requested a reversible hold"}}"#,
    ));

    with_valid_schedule_context!(
        context,
        current = vec![current],
        requested = vec![requested],
        1,
        {
            let evidence = PreclaimRunEvidence::acquire(
                context.repo,
                SupervisorRuntime::Fake,
                SupervisorExecutionRuntime::Verified,
            );
            let decision = preclaim_assignment(
                context.artifacts,
                &context.plan.assignments[0],
                &context.requested_plan.assignments,
                &evidence,
            )
            .expect("trusted park override produces a persisted decision");
            assert_eq!(decision.disposition, preclaim::PreclaimDisposition::Park);
            assert_eq!(
                decision.triage_outcome,
                preclaim::PreclaimTriageOutcome::OperatorOverride
            );
            assert_eq!(
                decision.authority,
                preclaim::PreclaimDecisionAuthority::Operator
            );
            assert!(decision.parking_reversible);
            assert!(decision.map_present && decision.risk_present && decision.runtime_present);
            assert_eq!(
                decision
                    .operator_override
                    .as_ref()
                    .map(|operator_override| operator_override.rationale.as_str()),
                Some("operator requested a reversible hold")
            );

            let mut progress = SchedulerProgress::new(1, 1);
            progress
                .install_preclaim_decisions(vec![decision.clone()])
                .expect("install trusted prepared park decision");
            let cancellation = ProcessCancellation::new();
            let serial_intents = Mutex::new(Vec::new());
            run_serial_assignment_schedule(&context, &mut progress, &cancellation, &serial_intents)
                .expect("trusted park override remains a normal reversible scheduler outcome");

            let outcome = progress.indexed_outcomes[0]
                .as_ref()
                .expect("park override stores a scheduler outcome");
            assert!(outcome.assignment_failed);
            assert!(outcome.claim_tokens.is_empty());
            assert!(outcome.claimed_paths.is_empty());
            assert!(outcome.report.is_none());
            assert_eq!(progress.concurrency.finish().started_assignment_count, 0);
            assert!(context
                .sync_store
                .snapshot()
                .expect("snapshot parked claims")
                .is_empty());
            assert!(context
                .manager
                .list()
                .expect("list parked worktrees")
                .is_empty());
            assert!(!context
                .run_dir
                .join("assignments/trusted-park.prompt.md")
                .exists());
            assert_eq!(
                read_recorded_preclaim_decisions(context.run_dir),
                vec![decision]
            );
        }
    );
}

#[test]
fn current_assignment_only_directive_is_untrusted_and_parked_by_scheduler() {
    let mut current = test_assignment("current-only-directive", "tests/scheduler_preclaim.rs");
    current.notes = Some(requested_preclaim_directive(
        r#"{"operator_override":{"disposition":"claim","rationale":"untrusted resolved text"}}"#,
    ));
    let mut requested = current.clone();
    requested.notes = None;

    with_valid_schedule_context!(
        context,
        current = vec![current],
        requested = vec![requested],
        1,
        {
            let evidence = PreclaimRunEvidence::acquire(
                context.repo,
                SupervisorRuntime::Fake,
                SupervisorExecutionRuntime::Verified,
            );
            let decision = preclaim_assignment(
                context.artifacts,
                &context.plan.assignments[0],
                &context.requested_plan.assignments,
                &evidence,
            )
            .expect("current-only directive produces a recorded fail-closed decision");
            assert_eq!(decision.disposition, preclaim::PreclaimDisposition::Park);
            assert_eq!(
                decision.authority,
                preclaim::PreclaimDecisionAuthority::UntrustedAssignmentInput
            );
            assert!(decision.operator_override.is_none());

            let mut progress = SchedulerProgress::new(1, 1);
            progress
                .install_preclaim_decisions(vec![decision])
                .expect("install untrusted current-only decision");
            let cancellation = ProcessCancellation::new();
            let serial_intents = Mutex::new(Vec::new());
            run_serial_assignment_schedule(&context, &mut progress, &cancellation, &serial_intents)
                .expect("untrusted current-only directive parks without aborting scheduler");
            assert!(progress.indexed_outcomes[0]
                .as_ref()
                .is_some_and(|outcome| outcome.assignment_failed && outcome.report.is_none()));
            assert_eq!(progress.concurrency.finish().started_assignment_count, 0);
            assert!(context
                .sync_store
                .snapshot()
                .expect("snapshot untrusted current-only claims")
                .is_empty());
        }
    );
}

#[test]
fn default_park_and_trusted_reject_ambiguity_bias_are_deterministic_and_recorded() {
    let default = test_assignment("default-park-bias", "README.md");
    with_valid_schedule_context!(context, vec![default], 1, {
        let evidence = PreclaimRunEvidence::acquire(
            context.repo,
            SupervisorRuntime::Fake,
            SupervisorExecutionRuntime::Verified,
        );
        let first = preclaim_assignment(
            context.artifacts,
            &context.plan.assignments[0],
            &context.requested_plan.assignments,
            &evidence,
        )
        .expect("record default ambiguity-bias decision");
        let second = preclaim_assignment(
            context.artifacts,
            &context.plan.assignments[0],
            &context.requested_plan.assignments,
            &evidence,
        )
        .expect("record repeated default ambiguity-bias decision");
        assert_eq!(first, second);
        assert_eq!(first.ambiguity_bias, preclaim::PreclaimAmbiguityBias::Park);
        assert_eq!(
            first.triage_outcome,
            preclaim::PreclaimTriageOutcome::Ambiguous
        );
        assert_eq!(first.disposition, preclaim::PreclaimDisposition::Park);
        assert_eq!(
            read_recorded_preclaim_decisions(context.run_dir),
            vec![first; 2]
        );
    });

    let current = test_assignment("trusted-reject-bias", "README.md");
    let mut requested = current.clone();
    requested.notes = Some(requested_preclaim_directive(
        r#"{"ambiguity_bias":"reject"}"#,
    ));
    with_valid_schedule_context!(
        context,
        current = vec![current],
        requested = vec![requested],
        1,
        {
            let evidence = PreclaimRunEvidence::acquire(
                context.repo,
                SupervisorRuntime::Fake,
                SupervisorExecutionRuntime::Verified,
            );
            let first = preclaim_assignment(
                context.artifacts,
                &context.plan.assignments[0],
                &context.requested_plan.assignments,
                &evidence,
            )
            .expect("record trusted reject-bias decision");
            let second = preclaim_assignment(
                context.artifacts,
                &context.plan.assignments[0],
                &context.requested_plan.assignments,
                &evidence,
            )
            .expect("record repeated trusted reject-bias decision");
            assert_eq!(first, second);
            assert_eq!(
                first.ambiguity_bias,
                preclaim::PreclaimAmbiguityBias::Reject
            );
            assert_eq!(
                first.triage_outcome,
                preclaim::PreclaimTriageOutcome::Rejected
            );
            assert_eq!(first.disposition, preclaim::PreclaimDisposition::Park);
            assert_eq!(
                read_recorded_preclaim_decisions(context.run_dir),
                vec![first; 2]
            );
        }
    );
}

fn assert_authenticated_park_has_no_assignment_side_effects(
    max_concurrent_children: usize,
    run_id: &str,
    assignment_id: &str,
) {
    let (_temp, repo) = test_repository();
    let mut assignment = mechanical_assignment(assignment_id);
    assignment.assigned_paths = vec![PathBuf::from("tests/scheduler_preclaim.rs")];
    assignment.task = Some(
        "update tests/scheduler_preclaim.rs and run cargo test --test scheduler_preclaim"
            .to_string(),
    );
    assignment.environment_requirements = vec![EnvironmentRequirement::network(
        crate::external_agent::EnvironmentNetworkAccess::Enabled,
    )];
    assignment.worker_assignments[0].assigned_paths = assignment.assigned_paths.clone();
    assignment.worker_assignments[0].environment_requirements =
        vec![EnvironmentRequirement::network(
            crate::external_agent::EnvironmentNetworkAccess::Enabled,
        )];
    assert!(assignment.notes.is_none());

    let run_id = RunId::new(run_id).expect("valid authenticated parked run id");
    let mut options = test_options(&repo, run_id.as_str());
    options.runtime = SupervisorRuntime::Codex;
    options.admission_overrides = SupervisorAdmissionConfig {
        max_concurrent_children: Some(max_concurrent_children),
        provider_inflight_limit: Some(max_concurrent_children),
        host_memory_available_mib: Some(max_concurrent_children),
        host_memory_per_child_mib: Some(1),
        host_fd_available: Some(max_concurrent_children),
        host_fds_per_child: Some(1),
        host_disk_available_mib: Some(max_concurrent_children),
        host_disk_per_child_mib: Some(1),
        host_fallback_children: Some(max_concurrent_children),
    };
    let plan = test_plan(vec![assignment.clone()]);
    let runtime_model_catalog = test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)
        .expect("construct deterministic Codex selector catalog");
    let loaded = LoadedSupervisorPlan {
        plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata: AssignmentMetadata::new(),
        plan_metadata: SupervisorPlanMetadata::default(),
    };
    let runner_calls = std::sync::atomic::AtomicUsize::new(0);
    let runner = |_: &ExternalAgentCommand,
                  _: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>|
     -> ExternalAgentRun {
        runner_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        panic!("parked assignment must not invoke the child runner")
    };

    let report = run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::VerifiedTestOnly,
        Ok(runtime_model_catalog),
        &runner,
    )
    .expect("parked assignment finalizes an authenticated supervisor report");

    assert!(!report.success);
    assert!(report.rejected);
    assert_eq!(report.runtime, SupervisorRuntime::Codex);
    assert!(!report.publishable);
    assert_eq!(report.run_lifecycle, SupervisorRunLifecycle::Finalized);
    assert_eq!(runner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(report.claim_tokens.is_empty());
    assert!(report.released_claims.is_empty());
    assert!(report.release_errors.is_empty());
    assert!(report.orchestrator_reports.is_empty());
    assert!(report.commands_run.is_empty());
    assert!(report.environment_failures.is_empty());
    assert!(report.gate_denials.is_empty());
    assert!(report.findings.iter().any(|finding| {
        finding.message.contains("pre-claim viability parked")
            && finding.message.contains("autonomously_completable=no")
    }));

    let execution = report
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.execution.as_ref())
        .expect("parked run records scheduler-observed execution telemetry");
    assert_eq!(execution.started_assignment_count, 0);
    assert_eq!(execution.completed_assignment_count, 0);
    assert_eq!(
        execution.concurrency.configured_max_concurrent_children,
        max_concurrent_children
    );
    let admission = execution
        .concurrency
        .policy_input_details
        .as_ref()
        .expect("parked run records resolved admission inputs");
    assert_eq!(admission.entrypoint_bound, max_concurrent_children);
    assert_eq!(admission.resolved_bound, max_concurrent_children);
    assert_eq!(admission.host.resolved_bound, max_concurrent_children);
    assert_eq!(
        admission.provider_inflight_source,
        AdmissionInputSource::Configured
    );
    assert_eq!(
        admission.host.memory_available_source,
        AdmissionInputSource::Configured
    );
    assert_eq!(
        admission.host.fd_available_source,
        AdmissionInputSource::Configured
    );
    assert_eq!(
        admission.host.disk_available_source,
        AdmissionInputSource::Configured
    );
    assert_eq!(admission.host.memory_bound, Some(max_concurrent_children));
    assert_eq!(admission.host.fd_bound, Some(max_concurrent_children));
    assert_eq!(admission.host.disk_bound, Some(max_concurrent_children));
    assert_eq!(
        admission.effective.max_concurrent_children,
        Some(max_concurrent_children)
    );
    assert_eq!(admission.provider_inflight_bound, max_concurrent_children);
    assert_eq!(execution.concurrency.achieved_max_concurrent_children, 0);
    assert!(execution
        .concurrency
        .achieved_mean_concurrent_children
        .is_none());
    assert!(execution.budget_degradations.is_empty());
    assert!(execution.assignment_effort_bindings.is_empty());
    assert!(execution.selection_decisions.is_empty());
    let [selection_ledger_entry] = execution.assignment_selection_ledger.as_slice() else {
        panic!("parked assignment must have exactly one unbound selection ledger entry");
    };
    assert_eq!(selection_ledger_entry.assignment_id, assignment_id);
    assert_eq!(selection_ledger_entry.attempt, 0);
    assert!(selection_ledger_entry.selected_runtime.is_none());
    assert!(selection_ledger_entry.selected_model.is_none());
    assert!(selection_ledger_entry.selected_reasoning_effort.is_none());
    assert_eq!(
        selection_ledger_entry.catalog_source,
        AssignmentCatalogSource::None
    );
    assert!(selection_ledger_entry.catalog_snapshot_digest.is_none());
    assert!(selection_ledger_entry.catalog_revisions.is_empty());
    assert!(selection_ledger_entry.rejected_candidates.is_empty());
    assert!(selection_ledger_entry.quota_evidence.is_none());
    assert!(selection_ledger_entry
        .evidence_gap
        .as_deref()
        .is_some_and(|gap| gap.contains("parked by the pre-claim viability gate")));

    let budget = report
        .run_budget
        .as_ref()
        .expect("parked run records unchanged budget state");
    for amount in [budget.consumed, budget.reserved, budget.committed] {
        assert_eq!(amount.tokens, 0);
        assert!(amount.cost_usd.is_none_or(|cost| cost == 0.0));
    }
    assert_eq!(budget.active_reservations, 0);
    assert!(budget.roles.is_empty());

    assert!(SyncStore::open(&repo)
        .expect("reopen parked claim store")
        .snapshot()
        .expect("snapshot parked claim store")
        .is_empty());
    assert!(WorktreeManager::new(&repo)
        .list()
        .expect("list parked managed worktrees")
        .is_empty());

    let run_dir = repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id.as_str());
    let forbidden_assignment_artifacts = [
        PathBuf::from(format!("assignments/{assignment_id}.prompt.md")),
        PathBuf::from(format!(
            "assignments/{assignment_id}.attempt-1.worktree-writable-admission.json"
        )),
        PathBuf::from(format!(
            "assignments/{assignment_id}.attempt-1.worktree-writable-admission.schema.json"
        )),
        PathBuf::from(format!("reports/{assignment_id}.json")),
        PathBuf::from(format!("evidence/incoming/{assignment_id}.json")),
        PathBuf::from(format!("logs/{assignment_id}.jsonl")),
        PathBuf::from(format!("logs/{assignment_id}.summary.json")),
        PathBuf::from(format!(
            "logs/workers/{assignment_id}/mechanical-worker.jsonl"
        )),
    ];
    for relative in &forbidden_assignment_artifacts {
        assert!(
            !run_dir.join(relative).exists(),
            "parked assignment unexpectedly created {}",
            relative.display()
        );
    }
    assert!(!run_dir.join("incoming").exists());

    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized parked supervisor artifacts");
    assert!(reader
        .read(RunArtifactFamily::Supervise.final_report_relative_path())
        .is_ok());
    let preclaim_decision_bytes = reader
        .read(preclaim::PRECLAIM_DECISIONS_RELATIVE)
        .expect("read finalized parked pre-claim decisions");
    let preclaim_decisions = preclaim_decision_bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice::<preclaim::PreclaimDecision>(line)
                .expect("parse finalized parked pre-claim decision")
        })
        .collect::<Vec<_>>();
    let [preclaim_decision] = preclaim_decisions.as_slice() else {
        panic!("parked assignment must persist exactly one pre-claim decision");
    };
    assert_eq!(preclaim_decision.assignment_id, assignment_id);
    assert_eq!(
        preclaim_decision.disposition,
        preclaim::PreclaimDisposition::Park
    );

    let orchestration_event_bytes = reader
        .read(ORCHESTRATION_EVENT_PATH)
        .expect("read finalized parked orchestration journal");
    let assignment_gate_events = orchestration_event_bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice::<OrchestrationEvent>(line)
                .expect("parse finalized parked orchestration event")
        })
        .filter(|event| event.node == assignment_id && event.kind == OrchestrationEventKind::Gate)
        .collect::<Vec<_>>();
    let [assignment_gate_event] = assignment_gate_events.as_slice() else {
        panic!("parked assignment must record exactly one orchestration Gate event");
    };
    assert_eq!(
        assignment_gate_event.payload["assignment_id"].as_str(),
        Some(assignment_id)
    );
    assert_eq!(
        assignment_gate_event.payload["disposition"].as_str(),
        Some("park")
    );
    assert!(forbidden_assignment_artifacts.iter().all(|forbidden| {
        reader
            .finalization()
            .files
            .iter()
            .all(|record| record.path.as_path() != forbidden.as_path())
    }));

    let (checkpoint_writer, checkpoint) =
        open_supervisor_checkpoint(&repo, &run_id).expect("open authenticated parked checkpoint");
    assert_eq!(
        checkpoint.pending_assignments,
        vec![assignment_id.to_string()]
    );
    assert!(checkpoint.uncertain_assignments.is_empty());
    assert!(checkpoint.completed_assignments.is_empty());
    assert!(checkpoint.final_report.is_some());
    assert!(checkpoint.finalization_started);
    assert!(checkpoint.finalized);
    drop(checkpoint_writer);

    let authenticator =
        repository_authenticator_key_only(&repo).expect("open checkpoint authenticator");
    let checkpoint_journal =
        crate::state_journal::StateJournal::open_instance(authenticator, run_id.as_str())
            .expect("open authenticated parked checkpoint journal");
    let checkpoint_records = checkpoint_journal.records();
    assert_eq!(
        checkpoint_records
            .first()
            .map(|record| record.phase.as_str()),
        Some("supervise_prepared")
    );
    assert_eq!(
        checkpoint_records
            .first()
            .and_then(|record| record.payload["max_concurrent_children"].as_u64()),
        u64::try_from(max_concurrent_children).ok()
    );
    assert!(checkpoint_records
        .iter()
        .any(|record| record.phase == "artifact_finalized"));
    assert!(checkpoint_records
        .iter()
        .all(|record| record.phase != "assignment_started"));
    assert!(checkpoint_records
        .iter()
        .all(|record| record.phase != "assignment_completed"));
}

#[test]
fn preclaim_serial_park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects() {
    assert_authenticated_park_has_no_assignment_side_effects(
        1,
        "serial-authenticated-park",
        "serial-parked-child",
    );
}

#[test]
fn preclaim_concurrent_park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects() {
    assert_authenticated_park_has_no_assignment_side_effects(
        2,
        "concurrent-authenticated-park",
        "concurrent-parked-child",
    );
}

#[test]
fn missing_map_risk_runtime_parks_before_claiming_paths() {
    with_valid_schedule_context!(
        context,
        vec![test_assignment("parked-child", "README.md")],
        1,
        {
            let evidence = PreclaimRunEvidence::missing();
            let decision = preclaim_assignment(
                context.artifacts,
                &context.plan.assignments[0],
                &context.requested_plan.assignments,
                &evidence,
            )
            .expect("record missing-evidence pre-claim decision");
            assert!(!decision.allows_path_claim());
            assert!(decision.reason.contains("missing map, risk, runtime"));

            let parked = parked_preclaim_outcome(&context.plan.assignments[0], &decision);
            assert!(parked.assignment_failed);
            assert!(parked.claim_tokens.is_empty());
            assert!(parked.claimed_paths.is_empty());
            assert!(parked.released_claims.is_empty());
            assert!(parked.findings.iter().any(|finding| {
                finding.message.contains("pre-claim viability parked")
                    && finding.message.contains("missing map, risk, runtime")
            }));

            let decisions =
                fs::read_to_string(context.run_dir.join(preclaim::PRECLAIM_DECISIONS_RELATIVE))
                    .expect("read recorded pre-claim decisions");
            let recorded: preclaim::PreclaimDecision = serde_json::from_str(
                decisions
                    .lines()
                    .find(|line| !line.is_empty())
                    .expect("persisted one decision"),
            )
            .expect("parse recorded pre-claim decision");
            assert_eq!(recorded, decision);
            assert!(context
                .sync_store
                .snapshot()
                .expect("snapshot claims")
                .is_empty());
        }
    );
}

#[test]
fn simulation_acquire_records_synthetic_claim_without_map_risk_scan() {
    let (_temp, repo) = test_repository();
    let evidence = PreclaimRunEvidence::acquire(
        &repo,
        SupervisorRuntime::Fake,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    );
    let assignment = test_assignment("acquired-child", "tests/scheduler_preclaim.rs");
    assert!(
        evidence.repo_map.is_none(),
        "simulation must not require a scanned repository map"
    );
    assert!(
        evidence.risk_for(&assignment.assigned_paths).is_none(),
        "simulation must not require a scanned risk report"
    );
    let decision = preclaim::evaluate_preclaim_viability(
        &assignment,
        std::slice::from_ref(&assignment),
        evidence.repo_map.as_ref(),
        None,
        evidence.runtime,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    );
    assert!(
        decision.allows_path_claim(),
        "simulation should record synthetic viability: {}",
        decision.reason
    );
    assert_eq!(
        decision.evidence_source,
        preclaim::PreclaimEvidenceSource::SyntheticSimulation
    );
}

#[test]
fn verified_acquire_without_evidence_still_fails_closed() {
    let assignment = test_assignment("verified-child", "README.md");
    let decision = preclaim::evaluate_preclaim_viability(
        &assignment,
        std::slice::from_ref(&assignment),
        None,
        None,
        None,
        SupervisorExecutionRuntime::Verified,
    );
    assert!(!decision.allows_path_claim());
    assert_eq!(
        decision.evidence_source,
        preclaim::PreclaimEvidenceSource::Acquired
    );
    assert!(decision.reason.contains("missing map, risk, runtime"));
}

#[test]
fn concurrency_tracker_measures_live_guards_and_closes_on_unwind() {
    let tracker = SchedulerConcurrencyTracker::new();
    {
        let first = tracker.assignment_started();
        drop(first);
        let second = tracker.assignment_started();
        drop(second);
    }
    let sequential = tracker.finish();
    assert_eq!(sequential.started_assignment_count, 2);
    assert_eq!(sequential.completed_assignment_count, 2);
    assert_eq!(sequential.peak, 1);

    let tracker = SchedulerConcurrencyTracker::new();
    let first = tracker.assignment_started();
    let second = tracker.assignment_started();
    drop(second);
    drop(first);
    let overlapping = tracker.finish();
    assert_eq!(overlapping.started_assignment_count, 2);
    assert_eq!(overlapping.completed_assignment_count, 2);
    assert_eq!(overlapping.peak, 2);

    let tracker = SchedulerConcurrencyTracker::new();
    let unwind_tracker = tracker.clone();
    let _ = std::panic::catch_unwind(move || {
        let _guard = unwind_tracker.assignment_started();
        panic!("test unwind");
    });
    let unwound = tracker.finish();
    assert_eq!(unwound.started_assignment_count, 1);
    assert_eq!(unwound.completed_assignment_count, 1);
    assert_eq!(unwound.peak, 1);
}

#[test]
fn concurrent_scheduler_directly_dispatches_completes_and_orders_fake_assignments() {
    with_valid_schedule_context!(
        context,
        vec![
            test_assignment("concurrent-a", "tests/scheduler_preclaim.rs"),
            test_assignment("concurrent-b", "tests/scheduler_preclaim_b.rs"),
        ],
        2,
        {
            let mut progress = SchedulerProgress::new(2, 2);
            let cancellation = ProcessCancellation::new();
            let semantic_block_gate = SemanticBlockGate::default();

            run_concurrent_assignment_schedule(
                &context,
                &mut progress,
                &cancellation,
                &semantic_block_gate,
            )
            .expect("concurrent scheduler dispatch succeeds");

            assert_eq!(
                progress
                    .indexed_outcomes
                    .iter()
                    .map(|outcome| {
                        outcome
                            .as_ref()
                            .and_then(|outcome| outcome.report.as_ref())
                            .map(|report| report.id.as_str())
                    })
                    .collect::<Vec<_>>(),
                vec![Some("concurrent-a"), Some("concurrent-b")]
            );
            assert!(progress.indexed_outcomes.iter().all(|outcome| {
                outcome.as_ref().is_some_and(|outcome| {
                    outcome.fatal_error.is_none()
                        && !outcome.assignment_failed
                        && outcome.released_claims.len() == 1
                        && outcome.release_errors.is_empty()
                        && outcome.semantic_release_errors.is_empty()
                })
            }));
            let concurrency = progress.concurrency.finish();
            assert_eq!(concurrency.started_assignment_count, 2);
            assert_eq!(concurrency.completed_assignment_count, 2);
            assert!((1..=2).contains(&concurrency.peak));
            assert!(concurrency
                .mean
                .is_some_and(|mean| (1.0..=2.0).contains(&mean)));
        }
    );
}

#[test]
fn indexed_outcome_collection_keeps_plan_order_and_first_fatal() {
    let first = AssignmentExecutionOutcome {
        findings: vec![Finding {
            severity: FindingSeverity::Warning,
            message: "first".to_string(),
            paths: Vec::new(),
        }],
        assignment_failed: true,
        fatal_error: Some("first fatal".to_string()),
        ..AssignmentExecutionOutcome::default()
    };
    let second = AssignmentExecutionOutcome {
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: "second".to_string(),
            paths: Vec::new(),
        }],
        external_containment_failed: true,
        fatal_error: Some("second fatal".to_string()),
        ..AssignmentExecutionOutcome::default()
    };
    let mut collected = CollectedAssignmentOutcomes::default();

    let fatal_errors = collect_indexed_assignment_outcomes(
        vec![Some(first), None, Some(second)],
        false,
        &mut collected,
    );

    assert_eq!(fatal_errors, vec!["first fatal", "second fatal"]);
    assert_eq!(
        collected
            .findings
            .iter()
            .map(|finding| finding.message.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
    assert!(collected.assignment_execution_failed);
    assert!(collected.external_containment_failed);
}

#[test]
fn resource_release_collection_preserves_concurrent_release_evidence_without_stores() {
    let released_claim = PathClaim {
        token: ClaimToken::from_u64(7),
        agent_id: "child-a".to_string(),
        paths: vec![PathBuf::from("README.md")],
    };
    let mut collected = CollectedSchedulerResources {
        concurrently_released_claims: vec![released_claim.clone()],
        concurrent_release_errors: vec!["claim release failed".to_string()],
        concurrent_semantic_release_errors: vec!["semantic release failed".to_string()],
        ..CollectedSchedulerResources::default()
    };

    let released = release_collected_scheduler_resources(None, None, &mut collected);

    assert_eq!(released.released_claims, vec![released_claim]);
    assert_eq!(released.release_errors, vec!["claim release failed"]);
    assert!(released.released_semantic_intents.is_empty());
    assert_eq!(
        released.semantic_release_errors,
        vec!["semantic release failed"]
    );
    assert!(collected.concurrently_released_claims.is_empty());
    assert!(collected.concurrent_release_errors.is_empty());
    assert!(collected.concurrent_semantic_release_errors.is_empty());
}

#[test]
fn report_paths_keep_repo_relative_plan_and_fallback_for_external_run_dir() {
    let repo = Path::new("/repo");
    let run_id = RunId::new("direct-report-paths").expect("valid report path run id");

    let (plan_file, run_dir) = supervisor_report_paths(
        repo,
        Path::new("/repo/plans/supervise.json"),
        Path::new("/external/run"),
        &run_id,
    );

    assert_eq!(plan_file, PathBuf::from("plans/supervise.json"));
    assert_eq!(
        run_dir,
        RunArtifactFamily::Supervise
            .run_root()
            .join("direct-report-paths")
    );
}

#[test]
fn report_builder_keeps_fake_success_nonpublishable() {
    let plan = test_plan(vec![
        test_assignment("child-a", "README.md"),
        test_assignment("child-b", "README.md"),
    ]);
    let report = build_supervisor_final_report(test_report_construction(
        &plan,
        RunId::new("direct-report-builder").expect("valid report run id"),
    ));

    assert!(report.success);
    assert!(!report.publishable);
    assert!(!report.accepted);
    assert_eq!(report.assigned_paths, vec![PathBuf::from("README.md")]);
    assert_eq!(
            report.remaining_risk,
            "fake supervisor simulation succeeded but is not publishable or acceptable as real model evidence"
        );
    let profile = report
        .role_economics_profile
        .as_ref()
        .expect("new reports always carry economics metadata");
    assert_eq!(
        profile.schema_version,
        SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION
    );
    assert_eq!(
        profile.model_catalog_observation,
        RuntimeModelCatalogObservation::NotConsulted
    );
    let execution = profile
        .execution
        .as_ref()
        .expect("new reports always carry execution metadata");
    assert_eq!(execution.assignment_count, 2);
    assert_eq!(execution.concurrency.configured_max_concurrent_children, 1);
    assert_eq!(
        execution
            .concurrency
            .policy_input_details
            .as_ref()
            .expect("retained policy input")
            .resolved_bound,
        1
    );
    assert_eq!(
        execution.concurrency.policy_input_observation,
        ProcessObservation::SchedulerObserved
    );
    assert_eq!(execution.concurrency.achieved_max_concurrent_children, 0);
    assert!(execution.role_bindings.values().all(|binding| {
        binding.observation == RoleBindingObservation::SyntheticFake
            && binding.resolved_model.is_none()
            && binding.resolved_reasoning_effort.is_none()
    }));
    assert_eq!(report.role_usage.len(), 5);
}

#[test]
fn admission_resolution_uses_strictest_entrypoint_plan_quota_and_host_bound() {
    let temp = tempfile::tempdir().expect("temporary admission repository");
    let plan = SupervisorAdmissionConfig {
        max_concurrent_children: Some(12),
        provider_inflight_limit: Some(9),
        host_memory_available_mib: Some(8_192),
        host_memory_per_child_mib: Some(1_024),
        host_fd_available: Some(640),
        host_fds_per_child: Some(128),
        host_disk_available_mib: Some(9_000),
        host_disk_per_child_mib: Some(1_000),
        host_fallback_children: Some(2),
    };
    let cli = SupervisorAdmissionConfig {
        max_concurrent_children: Some(10),
        provider_inflight_limit: Some(7),
        host_fd_available: Some(384),
        ..SupervisorAdmissionConfig::default()
    };

    let resolved = SupervisorAdmissionPolicyInput::resolve(temp.path(), 20, plan, cli)
        .expect("resolve admission policy");

    assert_eq!(resolved.effective.max_concurrent_children, Some(10));
    assert_eq!(resolved.provider_inflight_bound, 7);
    assert_eq!(resolved.host.memory_bound, Some(8));
    assert_eq!(resolved.host.fd_bound, Some(3));
    assert_eq!(resolved.host.disk_bound, Some(9));
    assert_eq!(resolved.host.resolved_bound, 3);
    assert_eq!(resolved.resolved_bound, 3);
    assert_eq!(
        resolved.provider_inflight_source,
        AdmissionInputSource::Configured
    );
}

#[test]
fn report_builder_warns_when_independent_scopes_collapse_to_width_one() {
    let plan = test_plan(vec![
        test_assignment("child-a", "README.md"),
        test_assignment("child-b", "Cargo.toml"),
    ]);
    let mut construction = test_report_construction(
        &plan,
        RunId::new("collapsed-fan-out").expect("valid run id"),
    );
    construction.max_concurrent_children = 2;
    construction.achieved_concurrency = AchievedConcurrency {
        started_assignment_count: 2,
        completed_assignment_count: 2,
        peak: 1,
        mean: Some(1.0),
    };
    construction.has_multiple_independent_assignment_scopes = true;

    let report = build_supervisor_final_report(construction);

    assert!(report.findings.iter().any(|finding| {
        finding.severity == FindingSeverity::Warning
            && finding.message.contains("fan-out collapsed")
            && finding.message.contains("achieved width 1")
    }));
    let execution = report
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.execution.as_ref())
        .expect("execution metadata");
    assert_eq!(execution.concurrency.configured_max_concurrent_children, 2);
    assert_eq!(execution.concurrency.achieved_max_concurrent_children, 1);
    assert_eq!(
        execution.concurrency.achieved_mean_concurrent_children,
        Some(1.0)
    );
}

#[test]
fn legacy_economics_profile_defaults_to_version_one_without_execution() {
    let plan = test_plan(Vec::new());
    let report = build_supervisor_final_report(test_report_construction(
        &plan,
        RunId::new("legacy-economics-read").expect("valid run id"),
    ));
    let mut value = serde_json::to_value(report).expect("serialize current report");
    let profile = value["role_economics_profile"]
        .as_object_mut()
        .expect("economics profile object");
    profile.remove("schema_version");
    profile.remove("model_catalog_observation");
    profile.remove("execution");

    let legacy: SupervisorFinalReport =
        serde_json::from_value(value).expect("legacy report remains readable");
    let profile = legacy
        .role_economics_profile
        .as_ref()
        .expect("legacy economics block remains readable");
    assert_eq!(profile.schema_version, 1);
    assert_eq!(
        profile.model_catalog_observation,
        RuntimeModelCatalogObservation::NotConsulted
    );
    assert!(profile.execution.is_none());
}

#[test]
fn legacy_v4_model_tier_profile_remains_readable_under_v5_schema() {
    let profile: RoleEconomicsProfile = serde_json::from_str(include_str!(
        "../../../tests/fixtures/supervise/supervisor-final-economics-v4.json"
    ))
    .expect("parse supervisor-final economics fixture");

    assert_eq!(profile.schema_version, 4);
    assert_eq!(
        profile.name,
        LEGACY_PROVISIONAL_DEFAULT_MODEL_TIER_PROFILE_NAME
    );
    assert_eq!(
        profile.model_catalog_observation,
        RuntimeModelCatalogObservation::Consulted
    );
    let execution = profile.execution.expect("fixture execution metadata");
    assert_eq!(execution.assignment_count, 2);
    assert_eq!(execution.concurrency.configured_max_concurrent_children, 2);
    assert_eq!(execution.concurrency.achieved_max_concurrent_children, 2);
    assert_eq!(
        execution
            .concurrency
            .policy_input_details
            .expect("typed admission policy input")
            .resolved_bound,
        2
    );
    assert_eq!(execution.role_bindings.len(), 5);
    assert!(execution.assignment_effort_bindings.is_empty());
    assert_eq!(
        execution.usage.total_usage,
        Some(Usage {
            input_tokens: 1_200,
            output_tokens: 300,
            total_tokens: 1_500,
        })
    );

    let schema = supervisor_final_report_schema_value();
    assert_eq!(
        schema["properties"]["role_economics_profile"]["properties"]["schema_version"]["const"],
        SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION
    );
    assert!(
        schema["properties"]["role_economics_profile"]["properties"]["execution"]["required"]
            .as_array()
            .is_some_and(|required| required.iter().any(|field| field == "role_bindings"))
    );
    assert!(
        schema["properties"]["role_economics_profile"]["properties"]["execution"]["required"]
            .as_array()
            .is_some_and(|required| {
                required
                    .iter()
                    .any(|field| field == "assignment_effort_bindings")
            })
    );
}

#[test]
fn preflight_preserves_typed_runtime_catalog_failure_for_materialization() {
    let (_temp, repo) = test_repository();
    let loaded = LoadedSupervisorPlan {
        plan: test_plan(Vec::new()),
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata: AssignmentMetadata::new(),
        plan_metadata: SupervisorPlanMetadata::default(),
    };
    let options = test_options(&repo, "direct-preflight");
    let failure = Box::new(EnvironmentFailure::runtime_model_catalog(
        "catalog probe failed".to_string(),
    ));

    let prepared = prepare_supervisor_run(
        loaded,
        &options,
        1,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        Err(failure.clone()),
    )
    .expect("typed catalog failure must survive preparation for final-report materialization");
    let retained = prepared
        .runtime_model_catalog
        .expect_err("catalog failure must remain typed until supervisor finalization");

    assert_eq!(retained, failure);
    assert_eq!(
        retained.category,
        EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
    );
}

#[test]
fn preflight_directly_validates_schedule_and_reserves_artifacts() {
    let (_temp, repo) = test_repository();
    let plan = test_plan(vec![test_assignment("prepared-child", "README.md")]);
    let loaded = LoadedSupervisorPlan {
        plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata: AssignmentMetadata::new(),
        plan_metadata: SupervisorPlanMetadata::default(),
    };
    let options = test_options(&repo, "direct-preflight-success");

    let prepared = prepare_supervisor_run(
        loaded,
        &options,
        1,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        Ok(RuntimeModelCatalog::LocalDeterministicFake),
    )
    .expect("prepare scheduler run directly");

    assert_eq!(prepared.repo, repo);
    assert_eq!(prepared.runtime, SupervisorRuntime::Fake);
    assert_eq!(prepared.assignment_schedule.len(), 1);
    assert_eq!(
        prepared.assignment_schedule[0].assignment_id,
        "prepared-child"
    );
    assert!(prepared.run_dir.is_dir());
    assert_eq!(prepared.dirs.run_dir, prepared.run_dir);
    assert!(
        prepared
            .budget_ledger
            .report()
            .expect("prepared budget report")
            .new_dispatch_allowed
    );
}

#[test]
fn preflight_composes_cli_budget_overrides_with_plan_by_strictest_limit() {
    let (_temp, repo) = test_repository();
    let mut metadata = SupervisorPlanMetadata::default();
    metadata.run_budget.limits = RunBudgetLimits {
        soft_tokens: Some(100),
        hard_tokens: Some(200),
        soft_cost_usd: Some(0.5),
        hard_cost_usd: Some(1.0),
    };
    metadata.run_budget_max_duration_seconds = Some(600);
    let loaded = LoadedSupervisorPlan {
        plan: test_plan(vec![test_assignment("budgeted-child", "README.md")]),
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata: AssignmentMetadata::new(),
        plan_metadata: metadata,
    };
    let mut options = test_options(&repo, "strictest-cli-plan-budget");
    options.budget_overrides = RunBudgetLimits {
        hard_tokens: Some(50),
        hard_cost_usd: Some(0.4),
        ..RunBudgetLimits::default()
    };
    options.budget_max_duration_seconds = Some(300);

    let prepared = prepare_supervisor_run(
        loaded,
        &options,
        1,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        Ok(RuntimeModelCatalog::LocalDeterministicFake),
    )
    .expect("prepare run with CLI budget overrides");
    let report = prepared
        .budget_ledger
        .report()
        .expect("composed run budget report");

    assert_eq!(
        report.limits,
        RunBudgetLimits {
            soft_tokens: Some(50),
            hard_tokens: Some(50),
            soft_cost_usd: Some(0.4),
            hard_cost_usd: Some(0.4),
        }
    );
    assert_eq!(report.max_duration_seconds, Some(300));
    assert_eq!(
        report.sources,
        Some(crate::supervise::RunBudgetSources {
            plan: crate::supervise::RunBudgetSource {
                limits: RunBudgetLimits {
                    soft_tokens: Some(100),
                    hard_tokens: Some(200),
                    soft_cost_usd: Some(0.5),
                    hard_cost_usd: Some(1.0),
                },
                max_duration_seconds: Some(600),
            },
            cli: crate::supervise::RunBudgetSource {
                limits: RunBudgetLimits {
                    hard_tokens: Some(50),
                    hard_cost_usd: Some(0.4),
                    ..RunBudgetLimits::default()
                },
                max_duration_seconds: Some(300),
            },
        })
    );
}

#[test]
fn evidence_initialization_populates_stores_journal_and_baseline() {
    let (_temp, repo) = test_repository();
    let mut options = test_options(&repo, "direct-evidence-initialization");
    options.parent_node = Some("external-root".to_string());
    let plan = test_plan(Vec::new());
    let consultant = SupervisorConsultantPlan::default();
    let assignment_metadata = AssignmentMetadata::new();
    let plan_metadata = SupervisorPlanMetadata::default();
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        options.run_id.clone(),
        "scheduler-initialization-test",
    )
    .expect("reserve initialization artifacts");
    let mut field_guide_store = None;
    let mut field_guide_prompt = None;
    let mut sync_store = None;
    let mut semantic_store = None;
    let mut journal = None;
    let mut baseline = None;

    initialize_scheduler_evidence(&mut SchedulerEvidenceInitialization {
        plan: &plan,
        execution_target: None,
        consultant: &consultant,
        assignment_metadata: &assignment_metadata,
        plan_metadata: &plan_metadata,
        options: &options,
        repo: &repo,
        execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
        artifact_writer: &mut writer,
        field_guide_store_slot: &mut field_guide_store,
        field_guide_prompt_slot: &mut field_guide_prompt,
        sync_store_slot: &mut sync_store,
        semantic_store_slot: &mut semantic_store,
        orchestration_journal: &mut journal,
        primary_run_baseline: &mut baseline,
    })
    .expect("initialize scheduler evidence directly");

    assert!(field_guide_store.is_some());
    assert!(field_guide_prompt.is_some());
    assert!(sync_store.is_some());
    assert!(semantic_store.is_some());
    assert!(journal.is_some());
    assert!(baseline.is_some());
    let root_event = journal
        .as_ref()
        .expect("initialized orchestration journal")
        .create_event(
            options.run_id.as_str(),
            None,
            OrchestrationRole::Supervisor,
            OrchestrationEventKind::Status,
            json!({"status": "running"}),
        )
        .expect("create root supervisor event");
    assert_eq!(root_event.parent.as_deref(), Some("external-root"));
}

#[test]
fn persistence_records_gate_before_status_and_finalizes_report() {
    let (_temp, repo) = test_repository();
    let run_id = RunId::new("direct-report-persistence").expect("valid persistence run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "scheduler-persistence-test",
    )
    .expect("reserve persistence artifacts");
    write_supervisor_final_schema(
        &mut writer,
        Path::new("schemas/supervisor-final-report.schema.json"),
    )
    .expect("write persistence schema fixture");
    let _field_guide_store = FieldGuideStore::open(&repo, FieldGuideLimits::default())
        .expect("initialize authenticated persistence fixture");
    let mut journal = initialize_orchestration_event_journal(&repo, &run_id, None);
    assert!(journal.is_some());
    let plan = test_plan(Vec::new());
    let mut report = build_supervisor_final_report(test_report_construction(&plan, run_id.clone()));
    let consultant = SupervisorConsultantPlan::default();
    let assignment_metadata = AssignmentMetadata::new();
    let plan_metadata = SupervisorPlanMetadata::default();
    let budget_ledger =
        RunBudgetLedger::new(RunBudgetLimits::default()).expect("checkpoint budget ledger");
    report.run_budget = Some(
        budget_ledger
            .report()
            .expect("checkpoint final report budget"),
    );
    let mut checkpoint = SupervisorCheckpointWriter::create(
        &repo,
        SupervisorCheckpointPreparation::new(
            &run_id,
            &current_head_oid(&repo).expect("checkpoint primary base"),
            normalized_supervisor_plan_sha256(
                &plan,
                &consultant,
                &assignment_metadata,
                &plan_metadata,
            )
            .expect("checkpoint normalized plan binding"),
            1,
            &plan,
            writer
                .resume_binding()
                .expect("checkpoint artifact binding"),
            budget_ledger.report().expect("checkpoint initial budget"),
        ),
    )
    .expect("create supervise checkpoint");
    checkpoint
        .scheduler_closed(
            writer.resume_binding().expect("scheduler close binding"),
            budget_ledger.report().expect("scheduler close budget"),
        )
        .expect("close checkpoint scheduler");

    let persisted = persist_supervisor_final_report(
        report,
        &mut journal,
        writer,
        Some(&mut checkpoint),
        || Ok(()),
    )
    .expect("persist scheduler final report directly");

    assert_eq!(persisted.run_id, run_id);
    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized scheduler artifacts");
    let journal_bytes = reader
        .read(ORCHESTRATION_EVENT_PATH)
        .expect("read scheduler orchestration journal");
    let kinds = journal_bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice::<OrchestrationEvent>(line)
                .expect("parse scheduler orchestration event")
                .kind
        })
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![OrchestrationEventKind::Gate, OrchestrationEventKind::Status]
    );
}

#[test]
fn persist_releases_terminal_claims_without_checkpoint_writer() {
    let (_temp, repo) = test_repository();
    let run_id = RunId::new("degraded-terminal-release").expect("valid degraded persist run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "scheduler-degraded-persist-test",
    )
    .expect("reserve degraded persist artifacts");
    write_supervisor_final_schema(
        &mut writer,
        Path::new("schemas/supervisor-final-report.schema.json"),
    )
    .expect("write degraded persist schema fixture");
    let _field_guide_store = FieldGuideStore::open(&repo, FieldGuideLimits::default())
        .expect("initialize authenticated degraded persist fixture");
    let mut journal = initialize_orchestration_event_journal(&repo, &run_id, None);
    let plan = test_plan(Vec::new());
    let report = build_supervisor_final_report(test_report_construction(&plan, run_id.clone()));
    let released = std::sync::atomic::AtomicBool::new(false);

    persist_supervisor_final_report(report, &mut journal, writer, None, || {
        released.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    })
    .expect("persist without a checkpoint writer");

    assert!(
        released.load(std::sync::atomic::Ordering::SeqCst),
        "terminal release must run even when checkpoint finalization is unavailable"
    );
}
