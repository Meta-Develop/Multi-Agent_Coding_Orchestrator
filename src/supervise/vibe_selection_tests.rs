// Automatic Vibe Worker selection from operator-declared prior rows.
use std::os::unix::fs::PermissionsExt;

const VIBE_MODEL: &str = "zai-glm-5-3";

fn vibe_selection_prior(
    repo: &Path,
    task_shape_ceiling: Option<selection::TaskShapeCeiling>,
) -> Result<super::super::prior_input::OperatorPriorDataGuard> {
    let mut prior = codex_prior_for(|_| true)?;
    prior.runtime = "vibe".into();
    prior.model = VIBE_MODEL.into();
    prior.source_id = "synthetic-vibe-automatic-selection-regression".into();
    prior.prohibited_authority_roles = [
        AuthorityRole::Delegating,
        AuthorityRole::AcceptanceGate,
        AuthorityRole::ReviewAuditor,
        AuthorityRole::Audit,
        AuthorityRole::ConflictResolution,
        AuthorityRole::FailureClassification,
        AuthorityRole::GitPublication,
        AuthorityRole::UnknownJudgment,
    ]
    .into_iter()
    .collect();
    prior
        .class_fit
        .retain(|fit| fit.task_class == AUTOMATIC_SELECTION_TASK_CLASS);
    prior.class_fit.truncate(1);
    assert_eq!(prior.class_fit.len(), 1);
    for fit in &mut prior.class_fit {
        fit.effort = SelectorEffort::High;
        fit.quality_basis_points = 9900;
        fit.sample_size = 100;
        fit.execution_cost_microunits = 1;
        fit.review_cost_microunits = 1;
        fit.rework_cost_microunits = 1;
        fit.rereview_cost_microunits = 1;
    }
    prior.task_shape_ceiling = task_shape_ceiling;
    prior.strong_gate_fallback_efforts = [SelectorEffort::High].into_iter().collect();
    std::fs::write(
        repo.join("prior.json"),
        serde_json::to_vec(&json!({
            "schema_version": 1, "dataset_id": "vibe-automatic-selection-fixture",
            "revision": "synthetic-v1", "published_on": "2026-11-04",
            "models": [prior], "capability_policy": default_model_capability_policy(),
        }))?,
    )?;
    super::super::prior_input::bind_operator_prior_data(repo, "prior.json")
}

fn bind_vibe_fixture_programs(
    repo: &Path,
    vibe: bool,
) -> Result<super::super::runtime_executables::RuntimeExecutableGuard> {
    let primary = repo.join("codex-bin");
    let program = repo.join("vibe-bin");
    for path in [&primary, &program] {
        std::fs::write(path, "#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    super::super::runtime_executables::bind_new(
        repo,
        &RunId::new("vibe-automatic-selection")?,
        SupervisorRuntime::Codex,
        &primary,
        &if vibe {
            vec![(SupervisorRuntime::Vibe, program)]
        } else {
            vec![]
        },
    )
}

fn automatic_worker_plan() -> Result<SupervisorPlan> {
    let mut plan = test_plan();
    plan.task = "Fix one documentation typo".into();
    plan.assignments = vec![serde_json::from_value(json!({
        "id": "vibe-automatic-worker", "phase": "execution", "role": "worker",
        "assigned_paths": ["README.md"], "role_category": "non_delegating_terminal_worker",
        "worker_assignments": []
    }))?];
    Ok(plan)
}

fn resolve_automatic(plan: &mut SupervisorPlan) -> Result<SupervisorSelectionResolution> {
    initialize_supervisor_selection(
        plan,
        SupervisorRuntime::Codex,
        &codex_catalog()?,
        &test_admission(),
        &AdvertisedCatalogSet::empty(),
    )
}

fn worker_provenance(resolution: &SupervisorSelectionResolution) -> Result<&SelectionProvenance> {
    Ok(&resolution
        .decisions
        .iter()
        .find(|event| event.role == AgentRole::Worker)
        .context("Worker decision")?
        .provenance)
}

#[test]
fn vibe_prior_backed_worker_is_selected_automatically_when_cheaper() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior = vibe_selection_prior(&repo, None)?;
    let mut plan = automatic_worker_plan()?;
    let resolution = resolve_automatic(&mut plan)?;
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let decision = worker_provenance(&resolution)?;
    let choice = decision
        .choice
        .as_ref()
        .context("automatic Worker choice")?;
    assert_eq!(
        (&*choice.candidate.runtime, &*choice.candidate.model),
        ("vibe", VIBE_MODEL)
    );
    assert!(decision
        .candidate_set
        .iter()
        .any(|candidate| candidate.candidate.runtime == "vibe"));
    assert!(resolution
        .decisions
        .iter()
        .filter(|event| event.role != AgentRole::Worker)
        .all(|event| event
            .provenance
            .choice
            .as_ref()
            .is_some_and(|choice| choice.candidate.runtime != "vibe")));
    bind_selected_assignment_runtimes(&mut plan, &resolution.decisions)?;
    assert_eq!(plan.assignments[0].runtime, Some(SupervisorRuntime::Vibe));
    Ok(())
}

#[test]
fn vibe_reselection_keeps_bound_vibe_lane_for_worker() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior = vibe_selection_prior(&repo, None)?;
    let mut plan = automatic_worker_plan()?;
    assert_bound_vibe_reselection(resolve_automatic(&mut plan)?)
}

#[cfg(target_os = "linux")]
#[test]
fn vibe_reselection_keeps_bound_vibe_lane_with_account_observed_primary() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior = vibe_selection_prior(&repo, None)?;
    let mut plan = automatic_worker_plan()?;
    let accounts = vec![(
        SupervisorRuntime::Codex,
        qualified_account_fixture("codex-cli", FRONTIER_PROFILE_MODEL, "xhigh"),
    )];
    let (assessment, _, _) = fixture_task_assessment(&plan)?;
    let resolution = initialize_supervisor_selection_with_shapes(
        &mut plan,
        SupervisorRuntime::Codex,
        &codex_catalog()?,
        &test_admission(),
        &AdvertisedCatalogSet::empty(),
        Some(&default_resolved_profile()),
        SupervisorQuotaSelectionInput::default(),
        None,
        &accounts,
        Some(&assessment),
        &AssignmentSelectionShapes::default(),
    )?;
    assert_eq!(
        resolution
            .automatic_state
            .as_ref()
            .context("automatic account selection state")?
            .account_observations,
        accounts
    );
    assert_bound_vibe_reselection(resolution)
}

fn assert_bound_vibe_reselection(resolution: SupervisorSelectionResolution) -> Result<()> {
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let initial = worker_provenance(&resolution)?;
    let choice = initial.choice.as_ref().context("initial Worker choice")?;
    assert_eq!(
        (&*choice.candidate.runtime, &*choice.candidate.model),
        ("vibe", VIBE_MODEL)
    );
    let initial_pools = initial.normalized_input.pools.clone();
    let state = resolution
        .automatic_state
        .context("automatic selection state")?;
    let catalog = codex_catalog()?;
    for keep_vibe_pool in [true, false] {
        let mut state = state.clone();
        if !keep_vibe_pool {
            state
                .decisions
                .get_mut(&AgentRole::Worker)
                .context("Worker replay state")?
                .normalized_input
                .pools
                .retain(|pool| pool.runtime != "vibe");
        }
        for retry_count in [0, 1] {
            let replay = reselect_assignment_from_supplied_catalog_snapshot(
                &mut state,
                SupervisorRuntime::Codex,
                &catalog,
                &[AgentRole::Worker],
                retry_count,
                BudgetSignal::Continue,
                &[],
                None,
            )?;
            let decision = &replay.decisions[0].1;
            let input = &decision.normalized_input;
            assert_eq!(
                input
                    .catalogs
                    .iter()
                    .filter(|catalog| catalog.runtime == "vibe")
                    .count(),
                1
            );
            assert!(input.constraints.allowed_runtimes.contains("vibe"));
            assert_eq!(
                input
                    .pools
                    .iter()
                    .filter(|pool| pool.runtime == "vibe")
                    .count(),
                1
            );
            if keep_vibe_pool {
                assert_eq!(input.pools, initial_pools);
            }
            let choice = decision
                .choice
                .as_ref()
                .context("reselected Worker choice")?;
            assert_eq!(
                (&*choice.candidate.runtime, &*choice.candidate.model),
                ("vibe", VIBE_MODEL)
            );
        }
    }
    let non_worker_roles = state
        .decisions
        .keys()
        .copied()
        .filter(|role| *role != AgentRole::Worker)
        .collect::<Vec<_>>();
    let replay = reselect_assignment_from_supplied_catalog_snapshot(
        &mut state.clone(),
        SupervisorRuntime::Codex,
        &catalog,
        &non_worker_roles,
        0,
        BudgetSignal::Continue,
        &[],
        None,
    )?;
    for (_, decision) in replay.decisions {
        assert!(decision
            .normalized_input
            .catalogs
            .iter()
            .all(|catalog| catalog.runtime != "vibe"));
    }
    Ok(())
}

#[test]
fn vibe_reselection_without_bound_executable_adds_no_lane() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, false)?;
    let _prior = vibe_selection_prior(&repo, None)?;
    let mut plan = automatic_worker_plan()?;
    let resolution = resolve_automatic(&mut plan)?;
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let mut state = resolution
        .automatic_state
        .context("automatic selection state")?;
    for retry_count in [0, 1] {
        let replay = reselect_assignment_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &codex_catalog()?,
            &[AgentRole::Worker],
            retry_count,
            BudgetSignal::Continue,
            &[],
            None,
        )?;
        let decision = &replay.decisions[0].1;
        assert!(decision
            .normalized_input
            .catalogs
            .iter()
            .all(|catalog| catalog.runtime != "vibe"));
        assert!(decision
            .normalized_input
            .pools
            .iter()
            .all(|pool| pool.runtime != "vibe"));
        assert!(!decision
            .normalized_input
            .constraints
            .allowed_runtimes
            .contains("vibe"));
        assert_eq!(
            decision
                .choice
                .as_ref()
                .context("reselected Worker choice")?
                .candidate
                .runtime,
            "codex"
        );
    }
    Ok(())
}

#[test]
fn vibe_prior_task_shape_ceiling_excludes_high_risk_worker_task() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior =
        vibe_selection_prior(&repo, Some(selection::TaskShapeCeiling::bounded_terminal()))?;
    let resolved_profile = default_resolved_profile();
    let mut input = super::selection_input_for_role_with_assessment(
        SelectionInputForRoleArgs {
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Codex,
            catalog: &codex_catalog()?,
            advertised: &AdvertisedCatalogSet::empty(),
            admission: &test_admission(),
            resolved_objective_profile: &resolved_profile,
            quota_context: None,
            quota_ledger: None,
            account_observation: None,
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
                accepted_task_cost_context: None,
                accepted_task_cost_observations: Vec::new(),
            },
            debug_override: None,
            history: None,
        },
        None,
        None,
        None,
    )?;
    input.task.risk = RiskLevel::High;
    input.task.boundedness = Boundedness::Bounded;
    input.task.context = ContextSize::Medium;
    input.task.horizon = TaskHorizon::Medium;
    assert!(input
        .catalogs
        .iter()
        .any(|catalog| catalog.runtime == "vibe"));
    let decision = selection::select(&input)?;
    let choice = decision.choice.context("high-risk Worker choice")?;
    assert_eq!(choice.candidate.runtime, "codex");
    assert!(decision
        .candidate_set
        .iter()
        .filter(|candidate| candidate.candidate.runtime == "vibe")
        .all(|candidate| !candidate.eligible));
    Ok(())
}

#[test]
fn vibe_lane_requires_both_bound_executable_and_prior_rows() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let baseline_choice = {
        let _binding = bind_vibe_fixture_programs(&repo, false)?;
        let mut plan = automatic_worker_plan()?;
        let resolution = resolve_automatic(&mut plan)?;
        assert!(
            resolution.selection_preflight_failure.is_none(),
            "{:?}",
            resolution.selection_preflight_failure
        );
        worker_provenance(&resolution)?
            .choice
            .as_ref()
            .context("baseline Worker choice")?
            .candidate
            .clone()
    };
    for (program, prior) in [(false, true), (true, false)] {
        let _binding = bind_vibe_fixture_programs(&repo, program)?;
        let _prior = if prior {
            Some(vibe_selection_prior(&repo, None)?)
        } else {
            None
        };
        let mut plan = automatic_worker_plan()?;
        let resolution = resolve_automatic(&mut plan)?;
        assert!(
            resolution.selection_preflight_failure.is_none(),
            "program={program}, prior={prior}: {:?}",
            resolution.selection_preflight_failure
        );
        let decision = worker_provenance(&resolution)?;
        assert!(
            decision
                .candidate_set
                .iter()
                .all(|candidate| candidate.candidate.runtime != "vibe"),
            "program={program}, prior={prior}"
        );
        let choice = decision
            .choice
            .as_ref()
            .context("partial-binding Worker choice")?;
        assert_eq!(choice.candidate, baseline_choice);
    }
    Ok(())
}

#[test]
fn explicit_worker_override_for_codex_keeps_vibe_out() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior = vibe_selection_prior(&repo, None)?;
    let mut plan = automatic_worker_plan()?;
    plan.role_models.insert(
        AgentRole::Worker,
        role_selection(FRONTIER_PROFILE_MODEL.into(), Some("high")),
    );
    let resolution = resolve_automatic(&mut plan)?;
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let decision = worker_provenance(&resolution)?;
    let choice = decision
        .choice
        .as_ref()
        .context("overridden Worker choice")?;
    assert_eq!(choice.candidate.runtime, "codex");
    assert_eq!(choice.candidate.model, FRONTIER_PROFILE_MODEL);
    assert_eq!(choice.reason, selection::ChoiceReason::DebugOverride);
    assert!(decision
        .candidate_set
        .iter()
        .all(|candidate| candidate.candidate.runtime != "vibe"));
    Ok(())
}

#[test]
fn vibe_lane_absence_is_empty_when_the_lane_is_offered() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior = vibe_selection_prior(&repo, None)?;
    let mut plan = automatic_worker_plan()?;
    let resolution = resolve_automatic(&mut plan)?;
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let decision = worker_provenance(&resolution)?;
    assert!(super::vibe_lane_absence_for_ledger(AgentRole::Worker, decision).is_none());
    for event in resolution
        .decisions
        .iter()
        .filter(|event| event.role != AgentRole::Worker)
    {
        assert!(super::vibe_lane_absence_for_ledger(event.role, &event.provenance).is_none());
    }
    Ok(())
}

#[test]
fn vibe_lane_absence_records_unbound_executable() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, false)?;
    let _prior = vibe_selection_prior(&repo, None)?;
    let mut plan = automatic_worker_plan()?;
    let resolution = resolve_automatic(&mut plan)?;
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let decision = worker_provenance(&resolution)?;
    let absence =
        super::vibe_lane_absence_for_ledger(AgentRole::Worker, decision).context("absence")?;
    assert_eq!(absence.runtime, "vibe");
    assert_eq!(absence.code, "executable_not_bound");
    Ok(())
}

#[test]
fn vibe_lane_absence_records_missing_prior_rows() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let mut plan = automatic_worker_plan()?;
    let resolution = resolve_automatic(&mut plan)?;
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let decision = worker_provenance(&resolution)?;
    let absence =
        super::vibe_lane_absence_for_ledger(AgentRole::Worker, decision).context("absence")?;
    assert_eq!(absence.runtime, "vibe");
    assert_eq!(absence.code, "no_prior_rows");
    Ok(())
}

#[test]
fn vibe_lane_absence_records_debug_override() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior = vibe_selection_prior(&repo, None)?;
    let mut plan = automatic_worker_plan()?;
    plan.role_models.insert(
        AgentRole::Worker,
        role_selection(FRONTIER_PROFILE_MODEL.into(), Some("high")),
    );
    let resolution = resolve_automatic(&mut plan)?;
    assert!(
        resolution.selection_preflight_failure.is_none(),
        "{:?}",
        resolution.selection_preflight_failure
    );
    let decision = worker_provenance(&resolution)?;
    let absence =
        super::vibe_lane_absence_for_ledger(AgentRole::Worker, decision).context("absence")?;
    assert_eq!(absence.runtime, "vibe");
    assert_eq!(absence.code, "debug_override_pins_other_runtime");
    Ok(())
}

#[test]
fn vibe_lane_absence_is_empty_when_the_ceiling_rejects_vibe() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior =
        vibe_selection_prior(&repo, Some(selection::TaskShapeCeiling::bounded_terminal()))?;
    let resolved_profile = default_resolved_profile();
    let mut input = super::selection_input_for_role_with_assessment(
        SelectionInputForRoleArgs {
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Codex,
            catalog: &codex_catalog()?,
            advertised: &AdvertisedCatalogSet::empty(),
            admission: &test_admission(),
            resolved_objective_profile: &resolved_profile,
            quota_context: None,
            quota_ledger: None,
            account_observation: None,
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
                accepted_task_cost_context: None,
                accepted_task_cost_observations: Vec::new(),
            },
            debug_override: None,
            history: None,
        },
        None,
        None,
        None,
    )?;
    input.task.risk = RiskLevel::High;
    input.task.boundedness = Boundedness::Bounded;
    input.task.context = ContextSize::Medium;
    input.task.horizon = TaskHorizon::Medium;
    let decision = selection::select(&input)?;
    assert!(super::vibe_lane_absence_for_ledger(AgentRole::Worker, &decision).is_none());
    Ok(())
}

#[test]
fn vibe_lane_absence_round_trips_in_ledger_entry() -> Result<()> {
    let absence = AssignmentLaneAbsence {
        runtime: "vibe".to_string(),
        code: "executable_not_bound".to_string(),
        detail: "no Vibe executable is bound for this run".to_string(),
    };
    let entry = |absent_lanes| AssignmentSelectionLedgerEntry {
        assignment_id: "assignment".to_string(),
        attempt: 1,
        role: AgentRole::Worker,
        role_assignment: None,
        selection_source: AssignmentSelectionSource::Automatic,
        selected_runtime: Some("codex".to_string()),
        selected_model: Some("model".to_string()),
        selected_reasoning_effort: Some("high".to_string()),
        catalog_source: AssignmentCatalogSource::None,
        catalog_snapshot_digest: None,
        catalog_revisions: Vec::new(),
        rejected_candidates: Vec::new(),
        absent_lanes,
        quota_evidence: None,
        evidence_gap: None,
    };
    let with_absence = entry(vec![absence.clone()]);
    let serialized = serde_json::to_value(&with_absence)?;
    assert!(serialized
        .get("absent_lanes")
        .context("absent_lanes key")?
        .is_array());
    assert_eq!(
        serde_json::from_value::<AssignmentSelectionLedgerEntry>(serialized.clone())?,
        with_absence
    );
    let without_absence = entry(Vec::new());
    let serialized = serde_json::to_value(&without_absence)?;
    assert!(serialized.get("absent_lanes").is_none());
    assert_eq!(
        serde_json::from_value::<AssignmentSelectionLedgerEntry>(serialized)?,
        without_absence
    );
    Ok(())
}
