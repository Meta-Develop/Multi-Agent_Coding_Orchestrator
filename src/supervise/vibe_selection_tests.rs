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

fn resolve_automatic(
    plan: &mut SupervisorPlan,
) -> Result<SupervisorSelectionResolution> {
    initialize_supervisor_selection(
        plan,
        SupervisorRuntime::Codex,
        &codex_catalog()?,
        &test_admission(),
        &AdvertisedCatalogSet::empty(),
    )
}

fn worker_provenance(
    resolution: &SupervisorSelectionResolution,
) -> Result<&SelectionProvenance> {
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
fn vibe_prior_task_shape_ceiling_excludes_high_risk_worker_task() -> Result<()> {
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let _binding = bind_vibe_fixture_programs(&repo, true)?;
    let _prior = vibe_selection_prior(
        &repo,
        Some(selection::TaskShapeCeiling::bounded_terminal()),
    )?;
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
