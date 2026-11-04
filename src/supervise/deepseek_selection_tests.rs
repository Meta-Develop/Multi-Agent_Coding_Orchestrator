// Providerless selection-to-launch receipts with operator-authored evidence.
fn deepseek_selection_prior(
    repo: &Path,
) -> Result<super::super::prior_input::OperatorPriorDataGuard> {
    let mut prior = codex_prior_for(|_| true)?;
    prior.runtime = "deepseek".into();
    prior.model = "deepseek-synthetic".into();
    prior.source_id = "synthetic-selection-regression".into();
    prior.prohibited_authority_roles.clear();
    // Deliberately assert strong authority evidence: it must never grant this
    // runtime a control role, regardless of the operator's capability claim.
    for fit in &mut prior.class_fit {
        fit.effort = SelectorEffort::High;
        fit.quality_basis_points = 9900;
        fit.sample_size = 100;
    }
    prior
        .class_fit
        .dedup_by(|left, right| left.task_class == right.task_class);
    prior.authority_evidence = [
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
    .map(|role| selection::AuthorityEvidencePrior {
        task_class: JUDGMENT_SELECTION_TASK_CLASS.into(),
        role,
        effort: SelectorEffort::High,
        quality_basis_points: 9900,
        sample_size: 100,
    })
    .collect();
    prior.strong_gate_fallback_efforts = [SelectorEffort::High].into_iter().collect();
    let mut capabilities = default_model_capability_policy();
    capabilities.models.push(ModelCapabilityEvidence {
        model: prior.model.clone(),
        capability: ModelCapabilityClass::CriticalJudgment,
        eligible: true,
        evidence: "synthetic regression only".into(),
        as_of: "2026-11-04".into(),
    });
    std::fs::write(
        repo.join("prior.json"),
        serde_json::to_vec(&json!({
            "schema_version": 1, "dataset_id": "deepseek-selection-fixture",
            "revision": "synthetic-v1", "published_on": "2026-11-04",
            "models": [prior], "capability_policy": capabilities,
        }))?,
    )?;
    super::super::prior_input::bind_operator_prior_data(repo, "prior.json")
}

#[test]
fn codex_parent_selects_prior_backed_deepseek_researcher_and_binds_canonical_launch() -> Result<()>
{
    use std::os::unix::fs::PermissionsExt;
    let _policy = bind_fixture_routing_policy()?;
    let (_temporary, repo) = super::super::tests::injected_repository();
    let primary = repo.join("codex-bin");
    let deepseek = repo.join("dsh-bin");
    for program in [&primary, &deepseek] {
        std::fs::write(program, "#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700))?;
    }
    let run_id = RunId::new("deepseek-selection-launch")?;
    let catalog = codex_catalog()?;
    for (binding, prior, admitted) in [
        (2, true, true),
        (1, true, false),
        (0, true, false),
        (2, false, false),
    ] {
        let _binding = if binding == 0 {
            super::super::runtime_executables::install_captured(None)
        } else {
            super::super::runtime_executables::bind_new(
                &repo,
                &run_id,
                SupervisorRuntime::Codex,
                &primary,
                &if binding == 2 {
                    vec![(SupervisorRuntime::DeepSeek, deepseek.clone())]
                } else {
                    vec![]
                },
            )?
        };
        let _prior = if prior {
            Some(deepseek_selection_prior(&repo)?)
        } else {
            None
        };
        let mut plan = test_plan();
        plan.assignments = vec![serde_json::from_value(json!({
            "id":"research", "phase":"execution", "role":"researcher",
            "runtime":"deepseek", "role_category":"read_only_researcher",
            "assigned_paths":["README.md"], "worker_assignments":[]
        }))?];
        plan.role_models.insert(
            AgentRole::Researcher,
            role_selection("deepseek-synthetic".into(), Some("high")),
        );
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;
        if !admitted {
            assert!(
                resolution.selection_preflight_failure.is_some(),
                "binding={binding}, prior={prior}"
            );
            assert!(qualification_refusals(&resolution)?
                .iter()
                .any(|(role, rejection, _)| *role == AgentRole::Researcher
                    && *rejection
                        == selection_preflight::SelectionPreflightRejection::ModelUnavailable));
            assert!(!resolution.decisions.iter().any(|event| event
                .provenance
                .choice
                .as_ref()
                .is_some_and(|choice| choice.candidate.runtime == "deepseek")));
            continue;
        }
        assert!(
            resolution.selection_preflight_failure.is_none(),
            "{:?}",
            resolution.selection_preflight_failure
        );
        let decision = resolution
            .decisions
            .iter()
            .find(|event| event.role == AgentRole::Researcher)
            .context("Researcher decision")?;
        let choice = &decision
            .provenance
            .choice
            .as_ref()
            .context("Researcher choice")?
            .candidate;
        assert_eq!(
            (&*choice.runtime, &*choice.model, choice.effort),
            ("deepseek", "deepseek-synthetic", SelectorEffort::High)
        );
        assert!(resolution
            .decisions
            .iter()
            .filter(|event| event.role != AgentRole::Researcher)
            .all(|event| event
                .provenance
                .choice
                .as_ref()
                .is_some_and(|choice| choice.candidate.runtime == "codex")));
        // An observed Codex primary must retain this authored non-CAM lane.
        let mut account_plan = plan.clone();
        let account_resolution = initialize_supervisor_selection_with_accounts(
            &mut account_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &[(
                SupervisorRuntime::Codex,
                qualified_account_fixture("codex-cli", FRONTIER_PROFILE_MODEL, "xhigh"),
            )],
        )?;
        assert!(
            account_resolution.selection_preflight_failure.is_none(),
            "{:?}",
            account_resolution.selection_preflight_failure
        );
        let input = &account_resolution
            .decisions
            .iter()
            .find(|event| event.role == AgentRole::Researcher)
            .context("account-backed Researcher")?
            .provenance
            .normalized_input;
        assert_eq!(
            input
                .catalogs
                .iter()
                .filter(|catalog| catalog.runtime == "deepseek")
                .count(),
            1
        );
        assert_eq!(
            input
                .pools
                .iter()
                .filter(|pool| pool.runtime == "deepseek")
                .count(),
            1
        );
        bind_selected_assignment_runtimes(&mut plan, &resolution.decisions)?;
        let command = crate::external_agent::deepseek_tests::command(&repo.join("capture"))?;
        let prompt = command.prompt.clone();
        let options = SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: repo.join("plan.json"),
            run_id: run_id.clone(),
            parent_node: None,
            codex_bin: primary.clone(),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: SupervisorAdmissionConfig::default(),
            budget_overrides: RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: None,
        };
        let (runtime, command) =
            super::super::assignment_execution::bind_selected_assignment_launch_for_test(
                command,
                &plan.assignments[0],
                &AssignmentBudgetPolicy::default(),
                &plan,
                &options,
                &catalog,
            )?;
        assert_eq!(runtime, SupervisorRuntime::DeepSeek);
        assert_eq!(command.program, deepseek);
        assert_eq!(command.model.as_deref(), Some("deepseek-synthetic"));
        assert_eq!(command.reasoning_effort.as_deref(), Some("high"));
        assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
        super::super::runtime_executables::validate_launch(&command)?;
        let mut events = crate::external_agent::deepseek_tests::fixture_events();
        events[0]["cwd"] = json!(command.cwd);
        let run = crate::external_agent::deepseek_tests::capture(
            &command,
            crate::external_agent::deepseek_tests::stream(&events),
            false,
            0,
            None,
            &BTreeMap::new(),
        )?;
        assert!(run.publishable, "{:?}", run.error);
        assert_eq!(
            run.output_last_message(),
            Some(b"inspection complete".as_slice())
        );
        let patch =
            std::fs::read_to_string(crate::runtime_adapter::deepseek::launch_patch_path(&prompt))?;
        assert!(
            patch.contains("model: \"deepseek-synthetic\"")
                && patch.contains("reasoningEffort: high")
        );
        // Even a prior that asserts control-role evidence cannot expose a
        // DeepSeek candidate to any authority or writable Worker selection.
        let priors = selector_priors_with_terminal_worker_economics()?;
        for role in [
            AgentRole::Supervisor,
            AgentRole::ChildOrchestrator,
            AgentRole::GateClassifier,
            AgentRole::Auditor,
            AgentRole::Worker,
        ] {
            let catalogs = constructed_selection_catalogs(
                SupervisorRuntime::Codex,
                &catalog,
                &AdvertisedCatalogSet::empty(),
                &task_profile_for_role(role),
                &priors,
                None,
            )?;
            assert!(
                catalogs.iter().all(|catalog| catalog.runtime != "deepseek"),
                "{role:?}"
            );
            let mut requested = plan.clone();
            requested.assignments[0].role = role;
            requested.assignments[0].role_category = None;
            requested.role_models.insert(
                role,
                role_selection("deepseek-synthetic".into(), Some("high")),
            );
            let refused = initialize_supervisor_selection(
                &mut requested,
                SupervisorRuntime::Codex,
                &catalog,
                &test_admission(),
                &AdvertisedCatalogSet::empty(),
            );
            assert!(
                refused.is_err()
                    || refused
                        .as_ref()
                        .is_ok_and(|resolution| resolution.selection_preflight_failure.is_some()),
                "authority request {role:?} must refuse"
            );
            assert!(
                super::super::assignment_execution::bind_selected_assignment_launch_for_test(
                    command.clone(),
                    &requested.assignments[0],
                    &AssignmentBudgetPolicy::default(),
                    &requested,
                    &options,
                    &catalog,
                )
                .is_err(),
                "launch must also refuse {role:?}"
            );
        }
    }
    Ok(())
}
