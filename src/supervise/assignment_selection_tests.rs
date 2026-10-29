fn declared_selection_fixture() -> Result<(SupervisorPlan, AssignmentSelectionShapes)> {
    let frozen =
        crate::selection::routing_policy::current_routing_policy().context("fixture policy")?;
    let mut plan = test_plan();
    plan.task = "Fix documentation".into();
    plan.assignments = ["tight", "broad", "high", "context", "horizon"]
        .into_iter()
        .map(|id| {
            serde_json::from_value(json!({
                "id": id, "role": "worker", "phase": "execution",
                "task": "Fix one documentation typo", "assigned_paths": ["README.md"]
            }))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let schedule = plan
        .assignments
        .iter()
        .enumerate()
        .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index,
        })
        .collect::<Vec<_>>();
    for (index, raised) in [
        None,
        Some(("boundedness", "cross_cutting")),
        Some(("risk", "high")),
        Some(("context", "long")),
        Some(("horizon", "long")),
    ]
    .into_iter()
    .enumerate()
    {
        let declaration = AssignmentShapeDeclaration::assess(
            &plan,
            index,
            &schedule,
            &frozen,
            AssignmentEffects::RepositoryWrite,
        )?;
        let mut wire = serde_json::to_value(declaration)?;
        if let Some((dimension, value)) = raised {
            wire["profile"][dimension] = json!(value);
        }
        plan.assignments[index].assignment_shape = Some(serde_json::from_value(wire)?);
    }
    let shapes = AssignmentSelectionShapes::validate(&plan, &schedule, Some(&frozen))?;
    Ok((plan, shapes))
}

#[test]
fn same_role_assignment_shapes_enforce_cheap_lane_ceilings() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (mut plan, shapes) = declared_selection_fixture()?;
    let catalog = codex_catalog()?;
    let advertised = advertised_with_grok(discover_grok_observation(CAPTURED_GROK_CATALOG)?);
    let resolution = initialize_supervisor_selection_with_shapes(
        &mut plan,
        SupervisorRuntime::Codex,
        &catalog,
        &test_admission(),
        &advertised,
        Some(&default_resolved_profile()),
        SupervisorQuotaSelectionInput::default(),
        None,
        &[],
        None,
        &shapes,
    )?;
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let initial = resolution
        .automatic_state
        .context("assignment replay state")?;
    for assignment in &plan.assignments {
        let dispatch =
            super::super::scheduler::assignment_policy_after_completed_settlement_for_test(
                initial.clone(),
                assignment,
                &RunBudgetLedger::new(RunBudgetLimits::default())?.report()?,
                &plan,
                &catalog,
                SupervisorRuntime::Codex,
            )?;
        let initial_dispatch = &dispatch.selector_decisions[0];
        assert_eq!(
            initial_dispatch.assignment_id.as_deref(),
            Some(assignment.id.as_str())
        );
        assert!(initial_dispatch
            .provenance
            .normalized_input
            .assignment_shape_identity
            .is_some());
        for budget_signal in [BudgetSignal::Continue, BudgetSignal::Degrade] {
            if budget_signal == BudgetSignal::Degrade {
                let mut budget_report =
                    RunBudgetLedger::new(RunBudgetLimits::default())?.report()?;
                budget_report.action = BudgetAction::Degrade;
                budget_report.reasons = vec![BudgetReason::SoftTokenCeilingReached];
                let dispatch =
                    super::super::scheduler::assignment_policy_after_completed_settlement_for_test(
                        initial.clone(),
                        assignment,
                        &budget_report,
                        &plan,
                        &catalog,
                        SupervisorRuntime::Codex,
                    )?;
                assert!(dispatch.selector_decisions.iter().all(|event| {
                    event.role == AgentRole::Worker || event.role == AgentRole::Auditor
                }));
                assert!(dispatch.selector_decisions.iter().any(|event| {
                    event.role == AgentRole::Worker
                        && event.provenance.normalized_input.assignment_shape_identity
                            == initial_dispatch
                                .provenance
                                .normalized_input
                                .assignment_shape_identity
                }));
            }
            let mut state = initial.clone();
            if budget_signal == BudgetSignal::Degrade {
                for decision in state.decisions.values_mut() {
                    for pool in &mut decision.normalized_input.pools {
                        pool.pool_pressure_basis_points = 10_000;
                        pool.marginal_cost_microunits = 3_000_000;
                    }
                }
            }
            for retry in [0, 1] {
                let selected = reselect_assignment_from_supplied_catalog_snapshot(
                    &mut state,
                    SupervisorRuntime::Codex,
                    &catalog,
                    &[AgentRole::Worker],
                    retry,
                    budget_signal,
                    &[],
                    Some(&assignment.id),
                )?;
                let decision = &selected.decisions[0].1;
                assert_eq!(
                    decision.normalized_input.assignment_shape_identity,
                    initial_dispatch
                        .provenance
                        .normalized_input
                        .assignment_shape_identity
                );
                assert_eq!(
                    decision.normalized_task,
                    assignment
                        .assignment_shape
                        .as_ref()
                        .unwrap()
                        .validate(
                            &plan,
                            plan.assignments
                                .iter()
                                .position(|entry| entry.id == assignment.id)
                                .unwrap(),
                            &plan
                                .assignments
                                .iter()
                                .enumerate()
                                .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
                                    assignment_id: assignment.id.clone(),
                                    parent_assignment_id: None,
                                    depth: MIN_SUPERVISOR_DEPTH,
                                    flattened_index,
                                })
                                .collect::<Vec<_>>(),
                            &crate::selection::routing_policy::current_routing_policy().unwrap()
                        )?
                        .profile()
                        .clone()
                );
                let cheap = decision
                    .candidate_set
                    .iter()
                    .filter(|candidate| {
                        candidate.candidate.runtime
                            == crate::optimizer::objective::DEFAULT_TERMINAL_RUNTIME
                            && candidate.candidate.model
                                == crate::optimizer::objective::DEFAULT_TERMINAL_MODEL
                    })
                    .collect::<Vec<_>>();
                assert!(!cheap.is_empty());
                assert_eq!(
                    cheap.iter().any(|candidate| candidate.eligible),
                    assignment.id == "tight",
                    "{} {retry} {budget_signal:?}",
                    assignment.id
                );
                assert_eq!(
                    decision
                        .normalized_input
                        .signals
                        .accepted_task_cost_context
                        .as_ref()
                        .unwrap()
                        .assignment_shape_identity,
                    *decision
                        .normalized_input
                        .assignment_shape_identity
                        .as_ref()
                        .unwrap()
                );
                let decoded: SelectionInput =
                    serde_json::from_slice(&serde_json::to_vec(&decision.normalized_input)?)?;
                assert_eq!(
                    decoded.assignment_shape_identity,
                    decision.normalized_input.assignment_shape_identity
                );
                assert_eq!(
                    selection::select(&decoded)?.input_digests,
                    selection::select(&decision.normalized_input)?.input_digests
                );
                let event = SupervisorSelectionEvent {
                    assignment_id: Some(assignment.id.clone()),
                    attempt: retry as usize,
                    role: AgentRole::Worker,
                    primary_cause: SupervisorSelectionEventCause::Initial,
                    provenance: decision.clone(),
                };
                let mut manager = initial.clone();
                manager.commit_completed_selection_events(
                    SupervisorRuntime::Codex,
                    std::slice::from_ref(&event),
                )?;
                let mut substituted = event.clone();
                substituted.assignment_id = Some(
                    if assignment.id == "tight" {
                        "high"
                    } else {
                        "tight"
                    }
                    .into(),
                );
                assert!(manager
                    .commit_completed_selection_events(SupervisorRuntime::Codex, &[substituted])
                    .is_err());
            }
        }
    }
    Ok(())
}

fn delegating_shape_fixture(
    mixed: bool,
    raised: bool,
) -> Result<(
    SupervisorPlan,
    AssignmentSelectionShapes,
    ValidatedAssignmentShape,
)> {
    let frozen = crate::selection::routing_policy::current_routing_policy().unwrap();
    let mut plan = test_plan();
    plan.task = "Update two interfaces".into();
    plan.assignments = vec![serde_json::from_value(json!({
        "id": "declared-parent", "role": "child_orchestrator", "phase": "execution",
        "task": "Update two interfaces", "assigned_paths": ["src"],
        "worker_assignments": [
            {"id": "first-worker", "role": "worker", "assigned_paths": ["src/a.rs"]},
            {"id": "second-worker", "role": "worker", "assigned_paths": ["src/b.rs"]}
        ]
    }))?];
    if mixed {
        let mut undeclared = plan.assignments[0].clone();
        undeclared.id = "undeclared-parent".into();
        for worker in &mut undeclared.worker_assignments {
            worker.id = format!("undeclared-{}", worker.id);
        }
        plan.assignments.push(undeclared);
    }
    let schedule = plan
        .assignments
        .iter()
        .enumerate()
        .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index,
        })
        .collect::<Vec<_>>();
    let declaration = AssignmentShapeDeclaration::assess(
        &plan,
        0,
        &schedule,
        &frozen,
        AssignmentEffects::RepositoryWrite,
    )?;
    let mut wire = serde_json::to_value(declaration)?;
    if raised {
        wire["profile"]["risk"] = json!("high");
        wire["profile"]["boundedness"] = json!("cross_cutting");
        wire["profile"]["context"] = json!("long");
        wire["profile"]["horizon"] = json!("long");
    }
    let declaration: AssignmentShapeDeclaration = serde_json::from_value(wire)?;
    let validated = declaration.validate(&plan, 0, &schedule, &frozen)?;
    plan.assignments[0].assignment_shape = Some(declaration);
    let shapes = AssignmentSelectionShapes::validate(&plan, &schedule, Some(&frozen))?;
    Ok((plan, shapes, validated))
}

#[test]
fn delegating_assignment_shapes_bind_nested_workers_on_initial_dispatch_and_degrade() -> Result<()>
{
    let _policy = bind_fixture_routing_policy()?;
    let (mut plan, shapes, validated) = delegating_shape_fixture(false, true)?;
    let catalog = codex_catalog()?;
    let advertised = advertised_with_grok(discover_grok_observation(CAPTURED_GROK_CATALOG)?);
    let resolution = initialize_supervisor_selection_with_shapes(
        &mut plan,
        SupervisorRuntime::Codex,
        &catalog,
        &test_admission(),
        &advertised,
        Some(&default_resolved_profile()),
        SupervisorQuotaSelectionInput::default(),
        None,
        &[],
        None,
        &shapes,
    )?;
    assert!(resolution.selection_preflight_failure.is_none());
    let initial = resolution
        .automatic_state
        .context("delegating replay state")?;
    let assignment = &plan.assignments[0];
    let expected_worker = TaskProfile {
        risk: RiskLevel::High,
        boundedness: Boundedness::CrossCutting,
        context: ContextSize::Long,
        horizon: TaskHorizon::Long,
        ..task_profile_for_role(AgentRole::Worker)
    };
    for degrade in [false, true] {
        let mut report = RunBudgetLedger::new(RunBudgetLimits::default())?.report()?;
        if degrade {
            report.action = BudgetAction::Degrade;
            report.reasons = vec![BudgetReason::SoftTokenCeilingReached];
        }
        let dispatch =
            super::super::scheduler::assignment_policy_after_completed_settlement_for_test(
                initial.clone(),
                assignment,
                &report,
                &plan,
                &catalog,
                SupervisorRuntime::Codex,
            )?;
        let worker = dispatch
            .selector_decisions
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("nested worker must be reselected before dispatch")?;
        assert_eq!(worker.provenance.normalized_task, expected_worker);
        assert_eq!(
            worker.provenance.normalized_task.authority_role,
            AuthorityRole::TerminalLeaf
        );
        assert_eq!(
            worker
                .provenance
                .normalized_input
                .assignment_shape_identity
                .as_ref(),
            Some(validated.identity())
        );
        assert_eq!(
            worker
                .provenance
                .normalized_input
                .signals
                .accepted_task_cost_context
                .as_ref()
                .unwrap()
                .role,
            AgentRole::Worker
        );
        assert_eq!(
            worker.primary_cause,
            if degrade {
                SupervisorSelectionEventCause::BudgetDegrade
            } else {
                SupervisorSelectionEventCause::Initial
            }
        );
        let cheap = worker
            .provenance
            .candidate_set
            .iter()
            .filter(|candidate| {
                candidate.candidate.runtime == crate::optimizer::objective::DEFAULT_TERMINAL_RUNTIME
                    && candidate.candidate.model
                        == crate::optimizer::objective::DEFAULT_TERMINAL_MODEL
            })
            .collect::<Vec<_>>();
        assert!(!cheap.is_empty());
        assert!(cheap.iter().all(|candidate| !candidate.eligible));
        let parent = dispatch
            .selector_decisions
            .iter()
            .find(|event| event.role == AgentRole::ChildOrchestrator)
            .unwrap();
        assert_eq!(&parent.provenance.normalized_task, validated.profile());
        assert_eq!(
            parent.provenance.normalized_task.authority_role,
            AuthorityRole::Delegating
        );
        let prompt_plan = super::super::prompts::runtime_resolved_prompt_plan(
            &dispatch.apply(&plan),
            assignment,
            dispatch
                .selected_runtime_for(AgentRole::ChildOrchestrator)
                .unwrap(),
            dispatch.selected_runtime_for(AgentRole::Worker).unwrap(),
            &catalog,
        )?;
        assert_eq!(
            prompt_plan.role_models[&AgentRole::Worker],
            role_selection_from_choice(worker.provenance.choice.as_ref().unwrap())
        );
        let mut manager = initial.clone();
        manager.commit_completed_selection_events(
            SupervisorRuntime::Codex,
            &dispatch.selector_decisions,
        )?;
        let mut malformed = worker.clone();
        malformed
            .provenance
            .normalized_input
            .assignment_shape_identity = None;
        assert!(manager
            .commit_completed_selection_events(SupervisorRuntime::Codex, &[malformed])
            .is_err());
        let mut malformed = worker.clone();
        malformed.provenance.normalized_input.task.risk = RiskLevel::Medium;
        malformed.provenance.normalized_task.risk = RiskLevel::Medium;
        assert!(manager
            .commit_completed_selection_events(SupervisorRuntime::Codex, &[malformed])
            .is_err());
    }
    Ok(())
}

#[test]
fn nested_worker_shape_preserves_intrinsic_profile_minimums() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_, shapes, parent) = delegating_shape_fixture(false, false)?;
    let intrinsic = task_profile_for_role(AgentRole::Worker);
    assert!(parent.profile().risk <= intrinsic.risk);
    assert!(parent.profile().boundedness <= intrinsic.boundedness);
    assert!(parent.profile().context <= intrinsic.context);
    assert!(parent.profile().horizon <= intrinsic.horizon);
    let mut input = selection::selection_test_base_input();
    shapes.bind_input("declared-parent", AgentRole::Worker, &mut input)?;
    assert_eq!(input.task, intrinsic);
    assert_eq!(
        input.assignment_shape_identity.as_ref(),
        Some(parent.identity())
    );
    Ok(())
}

#[test]
fn mixed_delegating_declarations_do_not_poison_declared_sibling_preflight() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (mut plan, shapes, validated) = delegating_shape_fixture(true, true)?;
    let catalog = codex_catalog()?;
    let resolution = initialize_supervisor_selection_with_shapes(
        &mut plan,
        SupervisorRuntime::Codex,
        &catalog,
        &test_admission(),
        &AdvertisedCatalogSet::empty(),
        Some(&default_resolved_profile()),
        SupervisorQuotaSelectionInput::default(),
        None,
        &[],
        None,
        &shapes,
    )?;
    assert!(resolution.selection_preflight_failure.is_none());
    let state = resolution
        .automatic_state
        .context("mixed-plan replay state")?;
    let report = RunBudgetLedger::new(RunBudgetLimits::default())?.report()?;
    let declared = super::super::scheduler::assignment_policy_after_completed_settlement_for_test(
        state.clone(),
        &plan.assignments[0],
        &report,
        &plan,
        &catalog,
        SupervisorRuntime::Codex,
    )?;
    for role in [AgentRole::ChildOrchestrator, AgentRole::Worker] {
        let event = declared
            .selector_decisions
            .iter()
            .find(|event| event.role == role)
            .unwrap();
        assert_eq!(
            event
                .provenance
                .normalized_input
                .assignment_shape_identity
                .as_ref(),
            Some(validated.identity())
        );
        let mut input = event.provenance.normalized_input.clone();
        shapes.bind_input("undeclared-parent", role, &mut input)?;
        assert_eq!(input.task.risk, RiskLevel::Unknown);
        assert!(input.assignment_shape_identity.is_none());
        assert!(selection::select(&input).is_err());
    }
    let unknown = super::super::scheduler::assignment_policy_after_completed_settlement_for_test(
        state,
        &plan.assignments[1],
        &report,
        &plan,
        &catalog,
        SupervisorRuntime::Codex,
    )
    .unwrap_err();
    assert!(unknown.to_string().contains("task.risk must be known"));
    Ok(())
}

#[test]
fn dispatch_revalidates_assignment_shape_after_plan_changes() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (plan, shapes) = declared_selection_fixture()?;
    let frozen = crate::selection::routing_policy::current_routing_policy().unwrap();
    for mutation in 0..4 {
        let mut changed = plan.clone();
        match mutation {
            0 => changed.assignments[0].task = Some("Fix another task".into()),
            1 => changed.assignments[0]
                .assigned_paths
                .push("other.md".into()),
            2 => changed.assignments[0].assignment_shape = None,
            3 => {
                let mut declaration =
                    serde_json::to_value(changed.assignments[0].assignment_shape.as_ref())?;
                declaration["profile"]["risk"] = json!("high");
                changed.assignments[0].assignment_shape =
                    Some(serde_json::from_value(declaration)?);
            }
            _ => unreachable!(),
        }
        assert!(shapes
            .validate_current_assignment(&changed, &changed.assignments[0], Some(&frozen))
            .is_err());
    }
    let mut rerouted = plan.clone();
    rerouted.assignments[0].runtime = Some(SupervisorRuntime::Grok);
    shapes.validate_current_assignment(&rerouted, &rerouted.assignments[0], Some(&frozen))?;
    Ok(())
}

#[test]
fn undeclared_assignment_shape_remains_unknown() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (mut plan, _) = declared_selection_fixture()?;
    for assignment in &mut plan.assignments {
        assignment.assignment_shape = None;
    }
    let shapes = AssignmentSelectionShapes::validate(&plan, &[], None)?;
    let mut input = selection::selection_test_base_input();
    input.task = task_profile_with_assessment(AgentRole::Worker, None, None, None)?;
    shapes.bind_input("tight", AgentRole::Worker, &mut input)?;
    assert_eq!(input.task.risk, RiskLevel::Unknown);
    assert!(input.assignment_shape_identity.is_none());
    assert!(selection::select(&input).is_err());
    assert!(shapes.role_profile(&plan, AgentRole::Worker)?.is_none());
    Ok(())
}
