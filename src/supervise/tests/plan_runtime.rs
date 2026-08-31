use super::*;
use crate::supervise::selection_bridge::{
    bind_test_selector_triple_catalog, selector_effort_as_str,
};

fn default_resolved_objective_profile() -> ResolvedObjectiveProfile {
    ResolvedObjectiveProfile {
        profile: crate::objective_profile::default_objective_profile()
            .binding()
            .expect("default objective profile binding"),
        source: crate::objective_profile::ObjectiveProfileSource::BuiltIn,
    }
}

fn quota_config_fixture(extra: &str) -> String {
    format!(
        r#"{{
          "version": 1,
          "pools": [{{
            "runtime": "codex",
            "account": "operator",
            "pool_kind": "subscription_included",
            "window": "calendar_month",
            "nominal_capacity": {{"units": 1000}},
            "rate_limits": {{"max_concurrent_sessions": 2}},
            "exhaustion_behavior": "fail_closed"{extra}
          }}]
        }}"#
    )
}

#[test]
fn operator_quota_config_binding_is_repository_local_strict_and_scoped() {
    let temp = tempfile::tempdir().expect("temp repo");
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).expect("create repo");
    Repository::init(&repo).expect("initialize repo");
    fs::create_dir(repo.join("config")).expect("create config directory");
    fs::write(repo.join("config/quota.json"), quota_config_fixture(""))
        .expect("write quota config");

    assert!(current_operator_quota_config_binding().is_none());
    {
        let _guard = bind_operator_quota_config(&repo, "config/quota.json")
            .expect("bind strict repository-local quota config");
        let context = live_quota_context_for_run(&repo)
            .expect("load live quota context")
            .expect("configured quota context");
        assert_eq!(context.relative_path, PathBuf::from("config/quota.json"));
        assert_eq!(context.config.pools.len(), 1);
        assert_eq!(
            live_quota_concurrency_bound(&context).expect("cap"),
            Some(2)
        );
    }
    assert!(current_operator_quota_config_binding().is_none());

    for unsafe_path in [
        PathBuf::from("../outside.json"),
        repo.join("config/quota.json"),
    ] {
        let error = bind_operator_quota_config(&repo, &unsafe_path)
            .expect_err("quota config path must be repository-relative");
        assert!(
            error.to_string().contains("repository-relative"),
            "unexpected unsafe-path error: {error:#}"
        );
    }

    fs::write(
        repo.join("config/unknown.json"),
        quota_config_fixture(", \"unknown\": true"),
    )
    .expect("write invalid strict config");
    let error = bind_operator_quota_config(&repo, "config/unknown.json")
        .expect_err("unknown quota config field must fail closed");
    assert!(error.to_string().contains("strict schema"), "{error:#}");
}

#[cfg(unix)]
#[test]
fn operator_quota_config_binding_refuses_symlinked_input() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temp repo");
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).expect("create repo");
    Repository::init(&repo).expect("initialize repo");
    fs::write(repo.join("quota-target.json"), quota_config_fixture(""))
        .expect("write quota target");
    symlink("quota-target.json", repo.join("quota-link.json")).expect("create quota symlink");

    let error = bind_operator_quota_config(&repo, "quota-link.json")
        .expect_err("quota config symlink must fail closed");
    assert!(
        format!("{error:#}")
            .to_ascii_lowercase()
            .contains("symbolic"),
        "unexpected symlink refusal: {error:#}"
    );
}

#[test]
fn completed_quota_refresh_switches_the_next_actual_assignment_launch_to_cursor() {
    use crate::{
        budget_ledger::WorkspaceBudgetLedger,
        optimizer::{
            ids::RuntimeSlug,
            quota_pools::{
                AccountId, EntitlementDescriptor, ExhaustionBehavior, NominalCapacity, PoolKind,
                PoolReference, QuotaConfig, RateLimits, ResetWindow, QUOTA_CONFIG_VERSION,
            },
        },
    };

    let (temp, repo_path) = injected_repository();
    fs::write(repo_path.join("SECOND.md"), "second baseline\n").expect("write second fixture");
    commit_injected_repository(&repo_path, "second fixture path");
    fs::create_dir(repo_path.join("config")).expect("create quota config directory");
    let cursor_reference = PoolReference {
        runtime: RuntimeSlug::new("cursor").expect("cursor runtime"),
        account: AccountId::new("cursor-metered").expect("cursor account"),
        window: ResetWindow::None,
    };
    let quota_config = QuotaConfig {
        version: QUOTA_CONFIG_VERSION,
        pools: vec![
            EntitlementDescriptor {
                runtime: RuntimeSlug::new("codex").expect("codex runtime"),
                account: AccountId::new("codex-included").expect("codex account"),
                pool_kind: PoolKind::SubscriptionIncluded,
                window: ResetWindow::None,
                nominal_capacity: NominalCapacity::Units(10),
                rate_limits: RateLimits::default(),
                priority_tier: None,
                exhaustion_behavior: ExhaustionBehavior::Degrade,
                authorized_alternatives: vec![cursor_reference.clone()],
                declared_list_price_microunits: None,
            },
            EntitlementDescriptor {
                runtime: cursor_reference.runtime.clone(),
                account: cursor_reference.account.clone(),
                pool_kind: PoolKind::Metered,
                window: cursor_reference.window,
                nominal_capacity: NominalCapacity::Unknown,
                rate_limits: RateLimits::default(),
                priority_tier: None,
                exhaustion_behavior: ExhaustionBehavior::FailClosed,
                authorized_alternatives: Vec::new(),
                declared_list_price_microunits: Some(500),
            },
        ],
    };
    quota_config.validate().expect("valid degrade quota config");
    fs::write(
        repo_path.join("config/quota.json"),
        serde_json::to_vec_pretty(&quota_config).expect("serialize quota config"),
    )
    .expect("write quota config");
    let cursor_fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runtime_adapter/cursor/captured-minimal-20260820.txt");
    let _catalog_guard = bind_test_cursor_catalog_fixture(&cursor_fixture)
        .expect("bind hermetic advertised Cursor catalog");
    let _quota_guard = bind_operator_quota_config(&repo_path, "config/quota.json")
        .expect("bind operator quota config");

    let mut first = injected_named_assignment("quota-first", "README.md");
    first.role = AgentRole::Worker;
    let mut second = injected_named_assignment("quota-second", "SECOND.md");
    second.role = AgentRole::Worker;
    let mut plan = injected_multi_plan(vec![first.clone(), second.clone()], 0);
    let options = injected_options(&repo_path, temp.path(), "quota-live-sequential");
    let catalog = test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)
        .expect("construct Codex test catalog");
    let advertised = advertised_catalogs_for_launch(&repo_path)
        .expect("load hermetic advertised runtime catalogs");
    let quota_context = LiveQuotaSelectionContext {
        repo: repo_path.clone(),
        relative_path: PathBuf::from("config/quota.json"),
        config: quota_config.clone(),
    };
    let admission = SupervisorAdmissionPolicyInput::resolve_with_quota(
        &repo_path,
        1,
        SupervisorAdmissionConfig::default(),
        SupervisorAdmissionConfig::default(),
        Some(&quota_context),
    )
    .expect("resolve quota-aware admission input");
    let mut budget_ledger =
        RunBudgetLedger::new(RunBudgetLimits::default()).expect("create run budget ledger");
    budget_ledger
        .attach_quota_config(&repo_path, options.run_id.as_str(), &quota_config)
        .expect("attach quota config to shared run budget ledger");
    let resolved_profile = default_resolved_objective_profile();
    let selection = initialize_supervisor_selection_with_quota(
        &mut plan,
        SupervisorRuntime::Codex,
        &catalog,
        &admission,
        &advertised,
        Some(&resolved_profile),
        SupervisorQuotaSelectionInput {
            context: Some(&quota_context),
            ledger: Some(&budget_ledger),
        },
    )
    .expect("initialize automatic live quota selection");
    assert!(selection.selection_preflight_failure.is_none());
    let initial_worker = selection
        .decisions
        .iter()
        .find(|event| event.role == AgentRole::Worker)
        .expect("initial Worker selection");
    assert_eq!(
        initial_worker
            .provenance
            .choice
            .as_ref()
            .expect("initial Worker choice")
            .candidate
            .runtime,
        "codex"
    );
    let automatic_state = selection
        .automatic_state
        .expect("automatic live quota replay state");
    let selected_models = plan
        .role_models
        .values()
        .filter_map(|selection| selection.model.clone())
        .collect::<Vec<_>>();
    for model in selected_models {
        plan.model_pricing.insert(
            model,
            ModelPricing {
                input_usd_per_million_tokens: 1.0,
                output_usd_per_million_tokens: 1.0,
            },
        );
    }
    let budget_config = SupervisorBudgetConfig {
        limits: RunBudgetLimits::default(),
        role_token_reservations: BTreeMap::from([(AgentRole::Worker, 10)]),
    };
    let launches = Mutex::new(Vec::<(String, SupervisorRuntime, Option<String>)>::new());
    let runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .expect("UTF-8 output name");
        let assignment = if name.contains(&first.id) {
            &first
        } else if name.contains(&second.id) {
            &second
        } else {
            panic!("unexpected assignment output {name}")
        };
        let auditor = name.contains("review-auditor");
        if auditor {
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(assignment, &injected_child_report(assignment)),
            );
            write_injected_usage(command, 0, 0);
            return injected_verified_run(command);
        }

        let launch_runtime = if command.runtime_adapter.is_some() {
            SupervisorRuntime::Cursor
        } else {
            SupervisorRuntime::Codex
        };
        launches.lock().expect("launch observations").push((
            assignment.id.clone(),
            launch_runtime,
            command.model.clone(),
        ));
        write_injected_assignment_report(command, assignment);
        if assignment.id == first.id {
            write_injected_usage(command, 7, 3);
            injected_verified_run(command)
        } else {
            write_injected_usage(command, 2, 1);
            let mut run = injected_verified_run(command);
            if launch_runtime == SupervisorRuntime::Cursor {
                assert_eq!(command.program, PathBuf::from("cursor-agent"));
                run.publishable = false;
                run.program_trust = ExternalProgramTrust::ExplicitCustom;
                run.codex_permissions = None;
            }
            run
        }
    };

    let first_command = ExternalAgentCommand::codex(
        &options.codex_bin,
        &repo_path,
        temp.path().join("quota-first-prompt.md"),
        temp.path().join("quota-first-log.jsonl"),
        temp.path().join("quota-first-output.json"),
        Duration::from_secs(10),
    );
    let first_policy = AssignmentBudgetPolicy::default();
    let (first_launch_runtime, first_command) = bind_selected_assignment_launch_for_test(
        first_command,
        &first,
        &first_policy,
        &plan,
        &options,
        &catalog,
    )
    .expect("bind initial Codex launch");
    assert_eq!(first_launch_runtime, SupervisorRuntime::Codex);
    let mut first_budget = match reserve_dispatch_budget(
        &plan,
        &budget_config,
        &budget_ledger,
        AgentRole::Worker,
        &first_command,
    )
    .expect("reserve first assignment budget")
    {
        DispatchBudgetAdmission::Admitted(reservation) => reservation,
        DispatchBudgetAdmission::Refused(refusal) => {
            panic!("first assignment budget was refused: {refusal:?}")
        }
    };
    first_budget
        .mark_invoked_for_runtime(first_launch_runtime)
        .expect("mark first Codex dispatch invoked");
    let first_run = runner(&first_command);
    let first_settlement = first_budget
        .settle(&first_run, first_launch_runtime, &first_command)
        .expect("settle completed first Codex assignment");
    assert_eq!(
        first_settlement.reliability,
        DispatchUsageReliability::Reliable
    );
    assert_eq!(
        first_settlement
            .observed_usage
            .expect("first completed usage")
            .total_tokens,
        10
    );

    let completed_report = budget_ledger
        .report()
        .expect("completed first-assignment budget report");
    let second_policy = assignment_policy_after_completed_settlement_for_test(
        automatic_state,
        &second,
        &completed_report,
        &plan,
        &catalog,
        SupervisorRuntime::Codex,
    )
    .expect("refresh live quota selection through scheduler admission policy");
    assert_eq!(
        second_policy.selected_runtime_for(AgentRole::Worker),
        Some(SupervisorRuntime::Cursor)
    );
    let second_decision = second_policy
        .selector_decisions
        .iter()
        .find(|event| {
            event.assignment_id.as_deref() == Some("quota-second")
                && event.role == AgentRole::Worker
        })
        .expect("second assignment live selection");
    let second_choice = second_decision
        .provenance
        .choice
        .as_ref()
        .expect("second assignment choice");
    assert_eq!(second_choice.candidate.runtime, "cursor");
    assert_eq!(
        second_decision
            .provenance
            .quota
            .as_ref()
            .expect("second assignment quota provenance")
            .disposition,
        crate::selection::QuotaDecisionDisposition::Degraded
    );
    let cursor_model = second_choice.candidate.model.clone();
    let mut second_plan = second_policy.apply(&plan);
    assert_eq!(
        second_plan
            .role_models
            .get(&AgentRole::Worker)
            .and_then(|selection| selection.model.clone())
            .as_deref(),
        Some(cursor_model.as_str())
    );
    second_plan.model_pricing.insert(
        cursor_model.clone(),
        ModelPricing {
            input_usd_per_million_tokens: 1.0,
            output_usd_per_million_tokens: 1.0,
        },
    );
    let second_command = ExternalAgentCommand::codex(
        &options.codex_bin,
        &repo_path,
        temp.path().join("quota-second-prompt.md"),
        temp.path().join("quota-second-log.jsonl"),
        temp.path().join("quota-second-output.json"),
        Duration::from_secs(10),
    );
    let (second_launch_runtime, second_command) = bind_selected_assignment_launch_for_test(
        second_command,
        &second,
        &second_policy,
        &second_plan,
        &options,
        &catalog,
    )
    .expect("bind degraded Cursor launch");
    assert_eq!(second_launch_runtime, SupervisorRuntime::Cursor);
    let mut second_budget = match reserve_dispatch_budget(
        &second_plan,
        &budget_config,
        &budget_ledger,
        AgentRole::Worker,
        &second_command,
    )
    .expect("reserve second assignment budget")
    {
        DispatchBudgetAdmission::Admitted(reservation) => reservation,
        DispatchBudgetAdmission::Refused(refusal) => {
            panic!("second assignment budget was refused: {refusal:?}")
        }
    };
    second_budget
        .mark_invoked_for_runtime(second_launch_runtime)
        .expect("mark second Cursor dispatch invoked");
    let second_run = runner(&second_command);
    let second_settlement = second_budget
        .settle(&second_run, second_launch_runtime, &second_command)
        .expect("settle completed second Cursor assignment");
    assert_eq!(
        second_settlement.reliability,
        DispatchUsageReliability::Estimated
    );
    assert_eq!(
        second_settlement
            .observed_usage
            .expect("second completed usage")
            .total_tokens,
        3
    );

    let observed_launches = launches.lock().expect("launch observations").clone();
    assert_eq!(observed_launches.len(), 2);
    assert_eq!(observed_launches[0].1, SupervisorRuntime::Codex);
    assert_eq!(observed_launches[1].1, SupervisorRuntime::Cursor);
    assert_eq!(
        observed_launches[1].2.as_deref(),
        Some(cursor_model.as_str())
    );
    drop(second_budget);
    drop(first_budget);
    drop(second_policy);
    drop(budget_ledger);
    let workspace =
        WorkspaceBudgetLedger::open_or_create(&repo_path).expect("reopen completed quota ledger");
    let now = crate::budget_ledger::unix_now().expect("ledger observation time");
    let codex = workspace
        .pool_usage(&quota_config.pools[0].key(), now)
        .expect("Codex pool usage");
    let cursor = workspace
        .pool_usage(&quota_config.pools[1].key(), now)
        .expect("Cursor pool usage");
    assert_eq!(codex.tokens, 10);
    assert_eq!(cursor.tokens, 10);
    assert_eq!(cursor.requests, 1);
}

#[test]
fn fake_runtime_refuses_operator_quota_before_dispatch_and_no_config_stays_legacy() {
    let (temp, repo_path) = injected_repository();
    fs::create_dir(repo_path.join("config")).expect("create quota config directory");
    fs::write(
        repo_path.join("config/quota.json"),
        quota_config_fixture(""),
    )
    .expect("write quota config");
    let plan = injected_plan(injected_assignment(false), 0);
    let mut options = injected_options(&repo_path, temp.path(), "fake-quota-refusal");
    options.runtime = SupervisorRuntime::Fake;
    let invocations = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&invocations);
    let mut runner = move |_command: &ExternalAgentCommand| {
        observed.fetch_add(1, Ordering::SeqCst);
        panic!("Fake quota refusal must happen before dispatch")
    };
    let error = {
        let _quota_guard = bind_operator_quota_config(&repo_path, "config/quota.json")
            .expect("bind operator quota config");
        run_supervisor_plan_with_runtime_model_catalog_and_runner(
            plan.clone(),
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            Ok(RuntimeModelCatalog::LocalDeterministicFake),
            &mut runner,
        )
        .expect_err("Fake runtime with quota config must refuse")
    };
    assert!(
        error
            .to_string()
            .contains("operator quota config is not valid for the nonpublishable Fake"),
        "unexpected Fake quota refusal: {error:#}"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    let mut legacy_options = injected_options(&repo_path, temp.path(), "fake-no-quota-legacy");
    legacy_options.runtime = SupervisorRuntime::Fake;
    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        legacy_options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(RuntimeModelCatalog::LocalDeterministicFake),
        &mut runner,
    )
    .expect("unconfigured Fake runtime retains legacy behavior");
    assert!(
        report.success,
        "unexpected legacy Fake failure: {report:#?}"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn default_child_timeout_covers_nested_worker_and_auditor_turns() {
    assert_eq!(default_child_timeout_seconds(), 1_200);
}

#[test]
fn objective_profile_request_round_trips_outside_the_public_plan_struct() {
    let default_document = serde_json::from_slice::<Value>(&bounded_loader_plan_json())
        .expect("parse default plan fixture");
    let default_loaded = parse_supervisor_plan_with_consultant(&default_document.to_string())
        .expect("load omitted objective profile");
    assert!(default_loaded.plan_metadata.objective_profile.is_none());
    let default_normalized = supervisor_plan_value(
        &default_loaded.plan,
        &default_loaded.consultant,
        &default_loaded.assignment_metadata,
        &default_loaded.plan_metadata,
    )
    .expect("normalize omitted objective profile");
    assert!(default_normalized.get("objective_profile").is_none());

    let mut named_document = default_document;
    named_document["objective_profile"] = json!("review-balanced-v2");
    let named_loaded = parse_supervisor_plan_with_consultant(&named_document.to_string())
        .expect("load named objective profile");
    assert_eq!(
        named_loaded.plan_metadata.objective_profile.as_deref(),
        Some("review-balanced-v2")
    );
    assert!(named_loaded
        .plan_metadata
        .resolved_objective_profile
        .is_none());
    let named_normalized = supervisor_plan_value(
        &named_loaded.plan,
        &named_loaded.consultant,
        &named_loaded.assignment_metadata,
        &named_loaded.plan_metadata,
    )
    .expect("normalize named objective profile");
    assert_eq!(named_normalized["objective_profile"], "review-balanced-v2");
    let reparsed = parse_supervisor_plan_with_consultant(&named_normalized.to_string())
        .expect("reparse named objective profile");
    assert_eq!(reparsed, named_loaded);

    named_document["objective_profile"] = json!({"id": "not-a-string"});
    let error = parse_supervisor_plan_with_consultant(&named_document.to_string())
        .expect_err("non-string objective profile request must fail");
    assert!(format!("{error:#}").contains("objective_profile must be a string"));
}

#[test]
fn authored_profile_reaches_verified_scheduler_selection_and_exact_score_evidence() {
    let (temp, repo_path) = injected_repository();
    let profile_id = "review-sensitive-routing-v1";
    fs::write(
        repo_path.join(crate::objective_profile::OBJECTIVE_PROFILE_OVERRIDE_FILE),
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "profiles": [{
                "id": profile_id,
                "version": 1,
                "quality": {
                    "held_out_percent": 50,
                    "breadth_percent": 25,
                    "anti_shortcut_percent": 25
                },
                "tradeoffs": {
                    "monetary_cost_percent": 25,
                    "quota_consumption_percent": 0,
                    "latency_percent": 0,
                    "retry_rework_percent": 0,
                    "human_review_percent": 75
                }
            }]
        }))
        .expect("serialize objective profile override"),
    )
    .expect("write objective profile override");

    let plan_document = serde_json::to_value(injected_plan(injected_assignment(false), 0))
        .expect("serialize injected plan");
    let mut authored_document = plan_document.clone();
    authored_document["objective_profile"] = json!(profile_id);
    let mut default_loaded =
        parse_supervisor_plan_with_consultant(&plan_document.to_string()).expect("default plan");
    let mut authored_loaded = parse_supervisor_plan_with_consultant(&authored_document.to_string())
        .expect("authored objective-profile plan");
    assert_eq!(
        authored_loaded.plan_metadata.objective_profile.as_deref(),
        Some(profile_id)
    );

    let catalog = RuntimeModelCatalog::Codex(
        CodexRuntimeModelCatalog::from_slugs(
            crate::selection::built_in_prior_dataset()
                .expect("built-in selector priors")
                .models
                .into_iter()
                .filter(|prior| prior.runtime == "codex")
                .map(|prior| prior.model),
        )
        .expect("Codex selector catalog"),
    );
    let catalog = Ok(catalog);
    let admission = SupervisorAdmissionPolicyInput::resolve(
        &repo_path,
        1,
        SupervisorAdmissionConfig::default(),
        SupervisorAdmissionConfig::default(),
    )
    .expect("resolve selector admission");

    let default = initialize_supervisor_selection_from_prepared_metadata(
        &mut default_loaded.plan,
        &mut default_loaded.plan_metadata,
        PreparedSupervisorSelectionRequest {
            repo: &repo_path,
            runtime: SupervisorRuntime::Codex,
            execution_runtime: SupervisorExecutionRuntime::Verified,
            runtime_model_catalog: &catalog,
            admission_policy_input: &admission,
            quota: SupervisorQuotaSelectionInput::default(),
        },
    )
    .expect("default verified scheduler selection");
    let adjusted = initialize_supervisor_selection_from_prepared_metadata(
        &mut authored_loaded.plan,
        &mut authored_loaded.plan_metadata,
        PreparedSupervisorSelectionRequest {
            repo: &repo_path,
            runtime: SupervisorRuntime::Codex,
            execution_runtime: SupervisorExecutionRuntime::Verified,
            runtime_model_catalog: &catalog,
            admission_policy_input: &admission,
            quota: SupervisorQuotaSelectionInput::default(),
        },
    )
    .expect("authored verified scheduler selection");

    fn worker_decision(resolution: &SupervisorSelectionResolution) -> &SupervisorSelectionEvent {
        resolution
            .decisions
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .expect("worker selector decision")
    }
    let default_worker = worker_decision(&default);
    let adjusted_worker = worker_decision(&adjusted);
    let default_choice = default_worker
        .provenance
        .choice
        .as_ref()
        .expect("default worker choice");
    let adjusted_choice = adjusted_worker
        .provenance
        .choice
        .as_ref()
        .expect("adjusted worker choice");
    assert_ne!(default_choice.candidate, adjusted_choice.candidate);
    assert_eq!(
        adjusted_choice.reason,
        crate::selection::ChoiceReason::LowestLegacyBaselinePlusCostProxyAdjustments
    );

    let resolved = &adjusted_worker.provenance.resolved_objective_profile;
    assert_eq!(resolved.profile.id, profile_id);
    assert_eq!(
        resolved.source,
        crate::objective_profile::ObjectiveProfileSource::RepositoryOverride
    );
    assert_eq!(resolved.profile.tradeoffs.monetary_cost_percent, 25);
    assert_eq!(resolved.profile.tradeoffs.human_review_percent, 75);
    assert_eq!(resolved.profile.tradeoffs.quota_consumption_percent, 0);
    assert_eq!(resolved.profile.tradeoffs.latency_percent, 0);
    assert_eq!(resolved.profile.tradeoffs.retry_rework_percent, 0);
    let selected_score = adjusted_worker
        .provenance
        .candidate_set
        .iter()
        .find(|candidate| candidate.candidate == adjusted_choice.candidate)
        .and_then(|candidate| candidate.score.as_ref())
        .expect("selected candidate score evidence");
    assert_eq!(
        selected_score.routing_score_semantics,
        crate::selection::RoutingScoreSemantics::LegacyBaselinePlusCostProxyAdjustmentsV1
    );
    assert_eq!(
        selected_score.routing_tradeoff_weights,
        resolved.profile.tradeoffs
    );
    assert_eq!(selected_score.retry_rework_adjustment_microunits, 0);
    assert_eq!(
        selected_score.human_review_adjustment_microunits,
        selected_score.human_review_cost_proxy_microunits * 75 / 25
    );
    assert_eq!(
        selected_score.total_adjustment_microunits,
        selected_score.human_review_adjustment_microunits
    );
    assert_eq!(
        selected_score.total_score_microunits,
        selected_score.legacy_baseline_score_microunits
            + selected_score.total_adjustment_microunits
    );
    assert_eq!(
        authored_loaded.plan_metadata.resolved_objective_profile,
        Some(resolved.clone())
    );
    drop(temp);
}

#[test]
fn cost_weighted_and_quality_weighted_profiles_select_distinct_acceptable_outcomes() {
    use crate::objective_profile::{
        select_from_frontier, FrontierAxes, ObjectiveProfileSource, QualityOperationsBalance,
    };

    let outcome = |quality_basis_points: u32, monetary_cost: f64| FrontierAxes {
        held_out_quality_basis_points: quality_basis_points,
        breadth_quality_basis_points: quality_basis_points,
        anti_shortcut_quality_basis_points: quality_basis_points,
        monetary_cost,
        quota_consumption: 0.0,
        latency: 0.0,
        retry_rework: 0.0,
        human_review: 0.0,
    };
    let frontier = [
        ("quality-first".to_string(), outcome(9_700, 0.8)),
        ("cost-first".to_string(), outcome(9_000, 0.2)),
    ];
    assert!(frontier.iter().all(|(_, outcome)| {
        outcome.held_out_quality_basis_points >= 9_000
            && outcome.breadth_quality_basis_points >= 9_000
            && outcome.anti_shortcut_quality_basis_points >= 9_000
    }));

    let profile = |id: &str, quality_percent: u32| {
        let mut profile = crate::objective_profile::default_objective_profile();
        profile.id = id.to_string();
        profile.quality_operations_balance = QualityOperationsBalance {
            quality_percent,
            operations_percent: 100 - quality_percent,
        };
        ResolvedObjectiveProfile {
            profile: profile.binding().expect("acceptance profile binding"),
            source: ObjectiveProfileSource::RepositoryOverride,
        }
    };
    let cost_profile = profile("acceptance-cost-weighted-v1", 0);
    let quality_profile = profile("acceptance-quality-weighted-v1", 100);

    let cost_selection = select_from_frontier(&cost_profile, &frontier)
        .expect("cost-weighted selection")
        .expect("non-empty cost frontier");
    let quality_selection = select_from_frontier(&quality_profile, &frontier)
        .expect("quality-weighted selection")
        .expect("non-empty quality frontier");

    assert_eq!(cost_selection.selected_profile_id, "cost-first");
    assert_eq!(quality_selection.selected_profile_id, "quality-first");
    assert_eq!(
        cost_selection.runner_up_profile_id.as_deref(),
        Some("quality-first")
    );
    assert_eq!(
        quality_selection.runner_up_profile_id.as_deref(),
        Some("cost-first")
    );
    assert_eq!(
        cost_selection.profile_hash,
        cost_profile.profile.content_hash
    );
    assert_eq!(
        quality_selection.profile_hash,
        quality_profile.profile.content_hash
    );
    assert_ne!(cost_selection.profile_hash, quality_selection.profile_hash);
    assert!(cost_selection.selected_score < cost_selection.runner_up_score.unwrap());
    assert!(quality_selection.selected_score < quality_selection.runner_up_score.unwrap());
    let selected_cost = |selection: &crate::objective_profile::ObjectiveSelection| {
        frontier
            .iter()
            .find(|(id, _)| id == &selection.selected_profile_id)
            .map(|(_, outcome)| outcome.monetary_cost)
            .expect("selected frontier cost")
    };
    assert_eq!(selected_cost(&cost_selection), 0.2);
    assert_eq!(selected_cost(&quality_selection), 0.8);
    let measurable_cost_difference =
        selected_cost(&quality_selection) - selected_cost(&cost_selection);
    assert!((measurable_cost_difference - 0.6).abs() < 1e-12);
}

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
fn assignment_phase_is_required_and_fail_closed() {
    let explicit = serde_json::from_slice::<Value>(&bounded_loader_plan_json())
        .expect("parse explicit plan fixture");
    let loaded = parse_supervisor_plan_with_consultant(&explicit.to_string())
        .expect("explicit execution phase");
    assert_eq!(loaded.plan.assignments[0].phase, AssignmentPhase::Execution);
    let normalized = supervisor_plan_value(
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
    .expect("normalize explicit plan");
    assert_eq!(normalized["assignments"][0]["phase"], "execution");

    let mut omitted = explicit.clone();
    omitted["assignments"][0]
        .as_object_mut()
        .expect("assignment object")
        .remove("phase");
    let omitted_error = parse_supervisor_plan_with_consultant(&omitted.to_string())
        .expect_err("omitted phase must not grant execution authority");
    assert!(format!("{omitted_error:#}").contains("missing field `phase`"));

    let mut mixed = explicit.clone();
    mixed["max_depth"] = json!(3);
    mixed["max_child_assignments"] = json!(2);
    mixed["assignments"][0]["child_assignments"] = json!([{
        "id": "nested-without-phase",
        "assigned_paths": ["src/nested.rs"],
        "worker_assignments": []
    }]);
    let mixed_error = parse_supervisor_plan_with_consultant(&mixed.to_string())
        .expect_err("mixed explicit and omitted phase authority must fail closed");
    assert!(format!("{mixed_error:#}").contains("missing field `phase`"));

    let mut unknown = explicit.clone();
    unknown["assignments"][0]["phase"] = json!("untrusted");
    let unknown_error = parse_supervisor_plan_with_consultant(&unknown.to_string())
        .expect_err("unknown phase must be rejected by typed deserialization");
    assert!(format!("{unknown_error:#}").contains("unknown variant `untrusted`"));

    let mut null_phase = explicit.clone();
    null_phase["assignments"][0]["phase"] = Value::Null;
    let null_error = parse_supervisor_plan_with_consultant(&null_phase.to_string())
        .expect_err("null phase must not grant execution authority");
    assert!(format!("{null_error:#}").contains("supervisor plan fields are invalid"));

    let direct_assignment = json!({
        "id": "direct-without-phase",
        "assigned_paths": ["README.md"]
    });
    assert!(serde_json::from_value::<OrchestratorAssignment>(direct_assignment).is_err());
}

#[test]
fn planning_phase_rejects_execution_authority() {
    let mut document =
        serde_json::from_slice::<Value>(&bounded_loader_plan_json()).expect("parse plan fixture");
    document["assignments"][0]["phase"] = json!("planning");
    document["assignments"][0]["worker_assignments"] = json!([{
        "id": "forbidden-worker",
        "assigned_paths": ["README.md"]
    }]);
    let error = parse_supervisor_plan_with_consultant(&document.to_string())
        .expect_err("planning assignment must not delegate execution");
    assert!(error
        .to_string()
        .contains("may not declare terminal worker assignments"));
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
            "phase": "execution",
            "assigned_paths": ["src/root.rs"],
            "spec_fragment_ids": ["SPEC-root"],
            "worker_assignments": [],
            "child_assignments": [{
                "id": "nested-child",
                "phase": "execution",
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
    assert!(loaded
        .plan
        .assignments
        .iter()
        .all(|assignment| assignment.phase == AssignmentPhase::Execution));
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
    skip_without_containment!();
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
    assert_eq!(assignments[0]["phase"], "planning");
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
    assert_eq!(assignments[1]["phase"], "execution");
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
    assert_eq!(assignments[2]["phase"], "planning");
    assert_eq!(assignments[2]["assigned_paths"], json!(["src/beta.rs"]));
    assert!(assignments[2]["worker_assignments"]
        .as_array()
        .expect("planning workers")
        .is_empty());
    assert_eq!(assignments[3]["id"], "assignment-002");
    assert_eq!(assignments[3]["phase"], "execution");
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

    let mut stripped = document;
    for assignment in stripped["assignments"]
        .as_array_mut()
        .expect("generated assignments")
    {
        assignment
            .as_object_mut()
            .expect("generated assignment object")
            .remove("phase");
    }
    let error = parse_supervisor_plan_with_consultant(&stripped.to_string())
        .expect_err("stripping every generated phase must fail closed");
    assert!(format!("{error:#}").contains("missing field `phase`"));
}

#[test]
fn authoritative_single_file_goal_lowers_to_one_planning_execution_pair() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    Repository::init(repo).expect("initialize repository");
    fs::write(repo.join("RELEASE_NOTES.md"), "# Releases\n").expect("write release notes");
    fs::write(
        repo.join("src.rs"),
        "pub fn write() {}\npub fn commit() {}\n",
    )
    .expect("write semantic decoys");

    let document = supervisor_plan_document_from_goal_spec(
        repo,
        "Smoke goal — prove a managed-worktree child write",
        r#"## Goal

Add a single new line at the end of `RELEASE_NOTES.md`. Do not change any other file.

## Spec

- Edit only `RELEASE_NOTES.md`.
- Commit the change with message `docs: child write`.

## Acceptance

- `RELEASE_NOTES.md` ends with the new line and is committed."#,
    )
    .expect("plan authoritative single-file goal");

    let assignments = document["assignments"]
        .as_array()
        .expect("assignments array");
    assert_eq!(assignments.len(), 2);
    assert_eq!(assignments[0]["id"], "assignment-001-planning");
    assert_eq!(assignments[1]["id"], "assignment-001");
    for assignment in assignments {
        assert_eq!(assignment["assigned_paths"], json!(["RELEASE_NOTES.md"]));
        assert_eq!(assignment["semantic_symbols"], json!([]));
        assert_eq!(assignment["semantic_modules"], json!([]));
    }
    assert_eq!(
        document["assignment_schedule"]
            .as_array()
            .expect("assignment schedule")
            .len(),
        2
    );
    assert!(document.get("coverage_gaps").is_none());
}

#[test]
fn literal_existing_file_edit_lowers_to_direct_grok_eligible_worker() {
    skip_without_containment!();
    let (_temp, repo) = injected_repository();
    let task = "In README.md, replace baseline with exactly: MACO literal routing reached the terminal worker. Verify the result with git diff --check and confirm README.md contains exactly that line.";
    let mut plan =
        supervisor_plan_from_goal_spec(&repo, "", task).expect("plan literal existing-file edit");
    let [planning, execution] = plan.assignments.as_slice() else {
        panic!("literal existing-file plan must contain one planning/execution pair");
    };
    assert_eq!(planning.phase, AssignmentPhase::Planning);
    assert_eq!(planning.role, AgentRole::ChildOrchestrator);
    assert_eq!(execution.phase, AssignmentPhase::Execution);
    assert_eq!(execution.role, AgentRole::Worker);
    assert_eq!(
        execution.role_category,
        Some(RoleCategory::NonDelegatingTerminalWorker)
    );
    assert!(execution.worker_assignments.is_empty());
    assert!(execution
        .notes
        .as_deref()
        .is_some_and(|notes| notes.contains("existing_git_visible_regular_file_edit")));

    plan.role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some("grok-4.6".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let execution = plan.assignments[1].clone();
    let resolved = runtime_resolved_prompt_plan(
        &plan,
        &execution,
        SupervisorRuntime::Grok,
        SupervisorRuntime::Grok,
        &RuntimeModelCatalog::OperatorDeclared,
    )
    .expect("resolve direct Grok terminal worker");
    let worker = effective_role_model_selection(&resolved, AgentRole::Worker);
    assert_eq!(worker.model.as_deref(), Some("grok-4.6"));
    assert_eq!(worker.reasoning_effort.as_deref(), Some("xhigh"));
    assert_eq!(
        worker.unavailable_model_fallback,
        UnavailableModelFallback::FailClosed
    );

    let ordinary = supervisor_plan_from_goal_spec(&repo, "", "Update README.md.")
        .expect("plan ordinary README task");
    assert_eq!(ordinary.assignments[1].role, AgentRole::ChildOrchestrator);
    assert_eq!(ordinary.assignments[1].worker_assignments.len(), 1);
    assert!(!ordinary.assignments[1]
        .notes
        .as_deref()
        .is_some_and(|notes| notes.contains("existing_git_visible_regular_file_edit")));
}

#[test]
fn plain_text_task_without_actionable_scope_returns_guidance() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    Repository::init(&repo).expect("initialize repository");
    fs::write(repo.join("README.md"), "# fixture\n").expect("write readme");
    let task_file = temp.path().join("task.txt");
    fs::write(&task_file, "Explain the unmatched frobnicator.\n").expect("write task");

    let error = supervisor_plan_document_from_task_file(&repo, &task_file)
        .expect_err("scope-free task must fail");
    let error = format!("{error:#}");
    assert!(error.contains("produced no actionable workstreams"));
    assert!(error.contains("repository path, Rust module, or Rust symbol"));
    assert!(error.contains("documentation, policy, and script files are valid scopes"));
}

#[test]
fn plain_text_policy_and_script_task_emits_workstreams() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    Repository::init(&repo).expect("initialize repository");
    fs::create_dir_all(repo.join(".agents/skills/agent-orchestration")).expect("create skills");
    fs::create_dir_all(repo.join(".agents/scripts")).expect("create scripts");
    fs::write(
        repo.join(".agents/skills/agent-orchestration/SKILL.md"),
        "# Orchestration\n",
    )
    .expect("write skill");
    fs::write(repo.join(".agents/scripts/o2-autopilot"), "#!/bin/sh\n").expect("write script");
    let task_file = temp.path().join("task.md");
    fs::write(
        &task_file,
        "- Update `.agents/skills/agent-orchestration/SKILL.md`.\n\
         - Update `.agents/scripts/o2-autopilot`.\n",
    )
    .expect("write task");

    let document = supervisor_plan_document_from_task_file(&repo, &task_file)
        .expect("plan policy/script task");
    let assignments = document["assignments"]
        .as_array()
        .expect("assignments array");
    assert_eq!(assignments.len(), 4);
    let scopes = assignments
        .iter()
        .map(|assignment| {
            assignment["assigned_paths"]
                .as_array()
                .expect("paths")
                .iter()
                .map(|path| path.as_str().expect("path").to_string())
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        scopes,
        BTreeSet::from([
            vec![".agents/scripts/o2-autopilot".to_string()],
            vec![".agents/skills/agent-orchestration/SKILL.md".to_string()],
        ])
    );
}

#[test]
fn plain_text_gitignored_policy_path_emits_workstream() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    Repository::init(&repo).expect("initialize repository");
    fs::write(repo.join(".gitignore"), ".agents/\n").expect("write gitignore");
    fs::create_dir_all(repo.join(".agents/skills/agent-orchestration")).expect("create skills");
    fs::write(
        repo.join(".agents/skills/agent-orchestration/SKILL.md"),
        "# Orchestration\n",
    )
    .expect("write skill");
    fs::write(repo.join("README.md"), "# fixture\n").expect("write readme");
    let task_file = temp.path().join("task.md");
    fs::write(
        &task_file,
        "- Update `.agents/skills/agent-orchestration/SKILL.md`.\n",
    )
    .expect("write task");

    let document = supervisor_plan_document_from_task_file(&repo, &task_file)
        .expect("plan gitignored policy path");
    let assignments = document["assignments"]
        .as_array()
        .expect("assignments array");
    assert_eq!(assignments.len(), 2);
    let scopes = assignments
        .iter()
        .map(|assignment| {
            assignment["assigned_paths"]
                .as_array()
                .expect("paths")
                .iter()
                .map(|path| path.as_str().expect("path").to_string())
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        scopes,
        BTreeSet::from([vec![
            ".agents/skills/agent-orchestration/SKILL.md".to_string()
        ]])
    );
}

#[test]
fn plain_text_task_with_missing_named_path_surfaces_cause() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    Repository::init(&repo).expect("initialize repository");
    fs::write(repo.join("README.md"), "# fixture\n").expect("write readme");
    let task_file = temp.path().join("task.md");
    fs::write(&task_file, "- Update `.agents/skills/missing/SKILL.md`.\n").expect("write task");

    let error = supervisor_plan_document_from_task_file(&repo, &task_file)
        .expect_err("missing named path must fail");
    let error = format!("{error:#}");
    assert!(error.contains("failed to plan plain-text task specification"));
    assert!(error.contains("failed to decompose goal/spec into repository workstreams"));
    assert!(error.contains(".agents/skills/missing/SKILL.md"));
    assert!(error.contains("not a readable regular file"));
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
                "phase": "execution",
                "assigned_paths": ["src/root.rs"],
                "child_assignments": [{
                    "id": "nested-child",
                    "phase": "execution",
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
                "phase": "execution",
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
            "phase": "execution",
            "assigned_paths": ["src/depth_2.rs"],
            "child_assignments": [{
                "id": "depth-3",
                "phase": "execution",
                "assigned_paths": ["src/depth_3.rs"],
                "child_assignments": [{
                    "id": "depth-4",
                    "phase": "execution",
                    "assigned_paths": ["src/depth_4.rs"],
                    "child_assignments": [{
                        "id": "depth-5",
                        "phase": "execution",
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
            "phase": "planning",
            "assigned_paths": ["src/shared.rs"],
            "semantic_symbols": ["crate::shared::Shared"],
            "child_assignments": [{
                "id": "execution-child",
                "phase": "execution",
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
            "phase": "planning",
            "assigned_paths": ["src"],
            "child_assignments": [
                {
                    "id": "execution-a",
                    "phase": "execution",
                    "assigned_paths": ["src/shared.rs"]
                },
                {
                    "id": "execution-b",
                    "phase": "execution",
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
    let collision_error = |mut left: Value, mut right: Value| {
        left["phase"] = json!("execution");
        right["phase"] = json!("execution");
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
                "phase": "execution",
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
    let collision_error = |mut left: Value, mut right: Value| {
        left["phase"] = json!("execution");
        right["phase"] = json!("execution");
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
        objective_profile: None,
        resolved_objective_profile: None,
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
        path_proposal: Default::default(),
        router: SupervisorRouterConfig::default(),
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
        objective_profile: None,
        resolved_objective_profile: None,
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
        path_proposal: Default::default(),
        router: SupervisorRouterConfig::default(),
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
        role_category: None,
        selection_source: None,
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
    let exact_report_contract = concat!(
        "Collection:\n",
        "- Artifact-only incoming root: /tmp/maco-run/incoming\n",
        "- Exact report path for Codex CLI --output-last-message only (never tools): /tmp/maco-run/incoming/execution-child.json\n",
        "- Source writes only in assigned worktree paths; each worker journal is a separate exact precreated append-only file and the sole non-source write under a nonwritable parent (never create, replace, rename, link, or swap).\n",
        "- Schemas: OrchestratorReviewReport=/tmp/maco-run/schemas/orchestrator-review-report.schema.json; WorkerReport=/tmp/maco-run/schemas/worker-report.schema.json; AuditorReport=/tmp/maco-run/schemas/auditor-report.schema.json\n",
    );
    assert!(
        prompt.contains(exact_report_contract),
        "nested assignment must retain the exact report-root, output, schema, worker, auditor, and journal capability contract"
    );
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
        objective_profile: None,
        resolved_objective_profile: None,
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
        path_proposal: Default::default(),
        router: SupervisorRouterConfig::default(),
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
    let _capability =
        install_named_test_models(&["planner-model", "worker-model", "auditor-model"]);
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models = BTreeMap::from([
        (
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: Some("planner-model".to_string()),
                reasoning_effort: Some("high".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        ),
        (
            AgentRole::Worker,
            RoleModelSelection {
                model: Some("worker-model".to_string()),
                reasoning_effort: Some("low".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
            },
        ),
        (
            AgentRole::Auditor,
            RoleModelSelection {
                model: Some("auditor-model".to_string()),
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
    let catalog =
        injected_codex_runtime_catalog(&["planner-model", "worker-model", "auditor-model"]);
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
        .any(|arguments| arguments == ["-m", "planner-model"]));
    assert!(child_argv
        .windows(2)
        .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"high\""] }));
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| arguments == ["-m", "auditor-model"]));
    assert!(auditor_argv
        .windows(2)
        .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"xhigh\""] }));
    assert!(!child_argv
        .iter()
        .any(|argument| argument.contains("worker-model")));
    assert_ne!(child_argv, auditor_argv);
}

#[test]
fn verified_supervise_dispatch_consumes_and_persists_the_selector_triple() {
    skip_without_containment!();
    let (temp, repo_path) = injected_repository();
    let verification_target = PathBuf::from("tests/selector_triple.rs");
    fs::create_dir(repo_path.join("tests")).expect("create injected tests directory");
    fs::write(
        repo_path.join(&verification_target),
        "#[test]\nfn selector_triple_fixture() {}\n",
    )
    .expect("write injected selector test target");
    commit_injected_repository(&repo_path, "selector test target");

    let mut assignment = injected_assignment(true);
    assignment.assigned_paths = vec![verification_target.clone()];
    assignment.worker_assignments[0].assigned_paths = vec![verification_target];
    let plan = injected_plan(assignment.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "verified-selector-triple-dispatch");
    let run_id = options.run_id.clone();
    let (_selector_fixture, catalog) = bind_test_selector_triple_catalog()
        .expect("construct selector-backed Codex catalog with a deterministic runner-up");
    let mut child_commands = Vec::new();
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .expect("UTF-8 output name");
        if name.contains("review-auditor") {
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &injected_child_report(&assignment)),
            );
        } else {
            child_commands.push(command.clone());
            write_injected_assignment_report(command, &assignment);
        }
        write_injected_usage(command, 8, 3);
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::Verified,
        Ok(catalog),
        &mut runner,
    )
    .expect("run verified selector-backed supervise dispatch");

    assert!(report.success, "unexpected failed report: {report:#?}");
    assert_eq!(child_commands.len(), 1);
    let economics = report
        .role_economics_profile
        .as_ref()
        .expect("selector role economics evidence");
    let resolved_profile = economics
        .resolved_objective_profile
        .as_ref()
        .expect("omitted profile resolves to a frozen built-in default");
    assert_eq!(
        resolved_profile.source,
        crate::objective_profile::ObjectiveProfileSource::BuiltIn
    );
    assert_eq!(
        resolved_profile.profile.id,
        crate::objective_profile::DEFAULT_OBJECTIVE_PROFILE_ID
    );
    resolved_profile
        .profile
        .validate()
        .expect("built-in objective profile hash binding");
    let execution = economics
        .execution
        .as_ref()
        .expect("selector execution evidence");
    let decision = execution
        .selection_decisions
        .iter()
        .find(|decision| decision.role == AgentRole::ChildOrchestrator)
        .expect("ChildOrchestrator selector decision");
    let choice = decision
        .provenance
        .choice
        .as_ref()
        .expect("selected ChildOrchestrator choice");
    assert_eq!(
        decision.primary_cause,
        SupervisorSelectionEventCause::Initial
    );
    assert_eq!(
        decision.provenance.resolved_objective_profile,
        *resolved_profile
    );
    assert_eq!(
        decision
            .provenance
            .input_digests
            .resolved_objective_profile
            .algorithm,
        "sha256"
    );
    assert_eq!(
        decision
            .provenance
            .input_digests
            .resolved_objective_profile
            .value,
        crate::artifacts::state_auth::sha256_hex(
            &serde_json::to_vec(resolved_profile).expect("serialize frozen objective profile")
        )
    );
    let selected_score = decision
        .provenance
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == choice.candidate)
        .and_then(|evaluation| evaluation.score.as_ref())
        .expect("selected score evidence");
    assert_eq!(
        selected_score.total_score_microunits,
        choice.total_score_microunits
    );
    let runner_up = decision
        .provenance
        .runner_up_scores
        .first()
        .expect("runner-up decision evidence");
    assert_eq!(runner_up.rank, 2);
    assert_ne!(runner_up.candidate, choice.candidate);
    assert!(runner_up.total_score_microunits >= choice.total_score_microunits);
    let runner_up_evaluation = decision
        .provenance
        .candidate_set
        .iter()
        .find(|evaluation| evaluation.candidate == runner_up.candidate)
        .expect("runner-up candidate evaluation");
    assert!(runner_up_evaluation.eligible);
    assert_eq!(
        runner_up_evaluation
            .score
            .as_ref()
            .expect("eligible runner-up score")
            .total_score_microunits,
        runner_up.total_score_microunits
    );
    let command = &child_commands[0];
    assert_eq!(choice.candidate.runtime, "codex");
    assert!(command.runtime_adapter.is_none());
    assert_eq!(
        command.model.as_deref(),
        Some(choice.candidate.model.as_str())
    );
    assert_eq!(
        command.reasoning_effort.as_deref(),
        Some(selector_effort_as_str(choice.candidate.effort))
    );

    assert_eq!(execution.selection_decisions.len(), 6);
    let ledger = execution
        .assignment_selection_ledger
        .iter()
        .find(|entry| {
            entry.assignment_id == assignment.id && entry.role == AgentRole::ChildOrchestrator
        })
        .expect("ChildOrchestrator selection ledger entry");
    assert_eq!(
        ledger.selection_source,
        AssignmentSelectionSource::Automatic
    );
    assert_eq!(ledger.selected_runtime.as_deref(), Some("codex"));
    assert_eq!(
        ledger.selected_model.as_deref(),
        Some(choice.candidate.model.as_str())
    );
    assert_eq!(
        ledger.selected_reasoning_effort.as_deref(),
        Some(selector_effort_as_str(choice.candidate.effort))
    );
    assert!(ledger.catalog_snapshot_digest.is_some());
    assert!(!ledger.catalog_revisions.is_empty());
    assert!(!ledger.rejected_candidates.is_empty());

    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("open persisted selector-backed supervise artifacts");
    let persisted = read_supervisor_final_report(&reader)
        .expect("read persisted selector-backed supervisor report");
    let persisted_execution = persisted
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.execution.as_ref())
        .expect("persisted selector execution evidence");
    assert_eq!(
        persisted_execution.selection_decisions,
        execution.selection_decisions
    );
    assert_eq!(
        persisted_execution.assignment_selection_ledger,
        execution.assignment_selection_ledger
    );
    let persisted_ledger: AssignmentSelectionLedger = serde_json::from_slice(
        &reader
            .read(Path::new(SELECTION_LEDGER_RELATIVE))
            .expect("read persisted assignment selection ledger"),
    )
    .expect("decode persisted assignment selection ledger");
    assert_eq!(
        persisted_ledger.schema_version,
        ASSIGNMENT_SELECTION_LEDGER_SCHEMA_VERSION
    );
    assert_eq!(
        persisted_ledger.entries,
        execution.assignment_selection_ledger
    );
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
            // gpt-5.6-terra is recorded as ineligible in the shipped capability
            // policy, so the default degrade ladder may only name luna.
            budget_degrade_models: vec![ECONOMY_PROFILE_MODEL.to_string()],
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
}

#[test]
fn assignment_scoped_prompt_resolution_skips_irrelevant_cross_runtime_worker() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.assignments[0].phase = AssignmentPhase::Planning;
    plan.role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some("grok-4.6".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let assignment = plan.assignments[0].clone();
    let catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL]);

    let resolved_prompt_plan = runtime_resolved_prompt_plan(
        &plan,
        &assignment,
        SupervisorRuntime::Codex,
        SupervisorRuntime::Grok,
        &catalog,
    )
    .expect("resolve only the directly launched planning role");
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
        Some("grok-4.6")
    );
}

#[test]
fn assignment_scoped_prompt_resolution_uses_direct_grok_worker_catalog() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    let mut child_selection = configured_role_model_selection(&plan, AgentRole::ChildOrchestrator);
    child_selection.unavailable_model_fallback = UnavailableModelFallback::RuntimeDefault;
    plan.role_models
        .insert(AgentRole::ChildOrchestrator, child_selection);
    plan.role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some("grok-4.6".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let mut assignment = plan.assignments[0].clone();
    assignment.runtime = Some(SupervisorRuntime::Grok);
    assignment.role = AgentRole::Worker;
    assignment.role_category = Some(RoleCategory::NonDelegatingTerminalWorker);

    let resolved_prompt_plan = runtime_resolved_prompt_plan(
        &plan,
        &assignment,
        SupervisorRuntime::Grok,
        SupervisorRuntime::Grok,
        &RuntimeModelCatalog::OperatorDeclared,
    )
    .expect("resolve the directly launched Grok Worker");

    assert_eq!(
        effective_role_model_selection(&resolved_prompt_plan, AgentRole::Worker)
            .model
            .as_deref(),
        Some("grok-4.6")
    );
    assert_eq!(
        effective_role_model_selection(&resolved_prompt_plan, AgentRole::Worker)
            .unavailable_model_fallback,
        UnavailableModelFallback::FailClosed
    );
    assert_eq!(
        effective_role_model_selection(&resolved_prompt_plan, AgentRole::ChildOrchestrator)
            .unavailable_model_fallback,
        UnavailableModelFallback::RuntimeDefault
    );
}

#[test]
fn assignment_scoped_prompt_resolution_resolves_same_runtime_nested_worker() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some(ECONOMY_PROFILE_MODEL.to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    let mut assignment = plan.assignments[0].clone();
    assignment.worker_assignments.push(WorkerAssignment {
        id: "nested-worker".to_string(),
        role: AgentRole::Worker,
        role_category: Some(RoleCategory::NonDelegatingTerminalWorker),
        selection_source: Some(AssignmentSelectionSource::Automatic),
        assigned_paths: assignment.assigned_paths.clone(),
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: Some("complete the nested worker task".to_string()),
        environment_requirements: Vec::new(),
        report_path: None,
    });
    let catalog = injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL, ECONOMY_PROFILE_MODEL]);

    let resolved_prompt_plan = runtime_resolved_prompt_plan(
        &plan,
        &assignment,
        SupervisorRuntime::Codex,
        SupervisorRuntime::Codex,
        &catalog,
    )
    .expect("resolve the child and its same-runtime nested Worker");

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
        Some(ECONOMY_PROFILE_MODEL)
    );
    assert_eq!(
        effective_role_model_selection(&resolved_prompt_plan, AgentRole::Worker)
            .unavailable_model_fallback,
        UnavailableModelFallback::FailClosed
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
            model: Some("preferred-model".to_string()),
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
    let missing_catalog = injected_codex_runtime_catalog(&["different-model"]);
    let _capability = install_named_test_models(&["preferred-model"]);

    let runtime_default = apply_role_model_selection(
        base_command(),
        &plan,
        AgentRole::ChildOrchestrator,
        SupervisorRuntime::Codex,
        &missing_catalog,
    )
    .expect_err("runtime-default selection is not capability evidence");
    assert!(
        format!("{runtime_default:#}")
            .contains("runtime-default model selection is not capability evidence"),
        "{runtime_default:#}"
    );

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
fn known_unavailable_child_runtime_default_is_refused_as_capability_evidence() {
    let _capability =
        install_named_test_models(&["unavailable-child-model", "available-auditor-model"]);
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("unavailable-child-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    plan.role_models.insert(
        AgentRole::Auditor,
        RoleModelSelection {
            model: Some("available-auditor-model".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
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
    *model = "available-auditor-model".to_string();
    *reasoning_effort = Some("xhigh".to_string());
    let options = injected_options(
        &repo_path,
        temp.path(),
        "known-unavailable-child-runtime-default",
    );
    let catalog = injected_codex_runtime_catalog(&["available-auditor-model"]);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("runtime-default model selection must not reach dispatch")
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect("runtime-default capability refusal should produce a finalized report");

    assert_eq!(invocations, 0);
    assert!(!report.success);
    assert!(
        report.findings.iter().any(|finding| {
            finding
                .message
                .contains("runtime-default model selection is not capability evidence")
        }),
        "expected capability refusal, got {report:#?}"
    );
    let resolved = report
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.resolved_objective_profile.as_ref())
        .expect("new final report freezes the effective objective profile");
    assert_eq!(
        resolved.source,
        crate::objective_profile::ObjectiveProfileSource::BuiltIn
    );
    assert_eq!(
        resolved.profile,
        crate::objective_profile::default_objective_profile()
            .binding()
            .expect("default objective binding")
    );
    assert_eq!(resolved.profile.quality.held_out_percent, 50);
    assert_eq!(resolved.profile.quality.breadth_percent, 25);
    assert_eq!(resolved.profile.quality.anti_shortcut_percent, 25);
    assert_eq!(resolved.profile.tradeoffs.monetary_cost_percent, 100);
    let round_trip: SupervisorFinalReport = serde_json::from_value(
        serde_json::to_value(&report).expect("serialize objective profile evidence"),
    )
    .expect("round-trip objective profile evidence");
    assert_eq!(
        round_trip
            .role_economics_profile
            .and_then(|profile| profile.resolved_objective_profile),
        Some(resolved.clone())
    );
}

#[test]
fn invalid_objective_profile_file_fails_before_external_dispatch() {
    let (temp, repo_path) = injected_repository();
    fs::write(
        repo_path.join(crate::objective_profile::OBJECTIVE_PROFILE_OVERRIDE_FILE),
        br#"{
          "schema_version": 1,
          "profiles": [],
          "unexpected": true
        }"#,
    )
    .expect("write invalid objective profile override");
    let plan = injected_plan(injected_assignment(false), 0);
    let options = injected_options(&repo_path, temp.path(), "invalid-objective-profile-file");
    let catalog = injected_codex_runtime_catalog(&[DEFAULT_PROFILE_MODEL]);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("invalid objective profile configuration must prevent dispatch")
    };

    let error = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect_err("invalid objective profile file must fail closed");

    assert_eq!(invocations, 0);
    assert!(
        format!("{error:#}").contains("unknown field"),
        "unexpected objective-profile error: {error:#}"
    );
}

#[test]
fn configured_lens_selection_supersedes_role_model_and_clamps_to_auditor_floor() {
    skip_without_containment!();
    let _capability =
        install_named_test_models(&["available-child-model", "unavailable-auditor-model"]);
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("available-child-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
        },
    );
    plan.role_models.insert(
        AgentRole::Auditor,
        RoleModelSelection {
            model: Some("unavailable-auditor-model".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::RuntimeDefault,
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
    *model = "available-child-model".to_string();
    *reasoning_effort = Some("low".to_string());
    let options = injected_options(
        &repo_path,
        temp.path(),
        "known-unavailable-auditor-runtime-default",
    );
    let catalog = injected_codex_runtime_catalog(&["available-child-model"]);
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
            assert_eq!(command.model.as_deref(), Some("available-child-model"));
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
                .any(|arguments| arguments == ["-m", "available-child-model"]));
            assert!(argv
                .windows(2)
                .any(|arguments| { arguments == ["-c", "model_reasoning_effort=\"xhigh\""] }));
            let child = injected_child_report(&assignment);
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
            assert!(argv
                .windows(2)
                .any(|arguments| { arguments == ["-c", "model=\"available-child-model\""] }));
            write_injected_assignment_report(command, &assignment);
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
    .expect("run production command path with unavailable auditor model");

    assert!(report.success, "unexpected failed report: {report:#?}");
    assert!(child_seen);
    assert!(auditor_seen);
    assert_eq!(
        report
            .role_economics_profile
            .as_ref()
            .map(|profile| profile.model_availability),
        Some(RoleModelAvailability::Unavailable)
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
            model: Some("unavailable-child-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let run_id = "known-unavailable-child-fail-closed";
    let options = injected_options(&repo_path, temp.path(), run_id);
    let catalog = injected_codex_runtime_catalog(&["different-model"]);
    let mut invocations = 0usize;
    let mut runner = |_command: &ExternalAgentCommand| {
        invocations = invocations.saturating_add(1);
        panic!("known-unavailable fail_closed selection must prevent dispatch")
    };

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Ok(catalog),
        &mut runner,
    )
    .expect("fail_closed selection should produce a finalized rejection report");

    assert_eq!(invocations, 0);
    assert!(!report.success);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("fallback is fail_closed")));
    let run_root = repo_path
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id);
    let scratch_entries = fs::read_dir(&run_root)
        .expect("read finalized fail_closed artifact root")
        .map(|entry| {
            entry
                .expect("read fail_closed artifact entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("incoming") || name.starts_with("capture"))
        .collect::<Vec<_>>();
    assert!(
        scratch_entries.is_empty(),
        "fail_closed command construction leaked invocation scratch: {scratch_entries:?}"
    );
    assert!(run_root.join(ARTIFACT_FINALIZATION_MARKER).exists());
}

#[test]
fn local_deterministic_fake_fallback_reaches_shared_supervisor_core_without_external_dispatch() {
    skip_without_containment!();
    // Fake harness fallback is configured execution, not a provider-model claim.
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
    assert!(report.success, "unexpected fake-core failure: {report:#?}");
    assert!(!report.publishable);
    assert_eq!(report.commands_run.len(), 2);
    assert_eq!(
        report
            .role_economics_profile
            .as_ref()
            .map(|profile| profile.model_availability),
        Some(RoleModelAvailability::Unavailable)
    );
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
    let secret = "CATALOG_SECRET_MARKER_83";
    let catalog_diagnostic = format!(
        "injected catalog acquisition failure\r\nAPI_TOKEN={secret}\n{}",
        "long diagnostic tail ".repeat(MAX_ENVIRONMENT_FAILURE_DIAGNOSTIC_CHARS)
    );

    let report = run_supervisor_plan_with_runtime_model_catalog_and_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        Err(Box::new(EnvironmentFailure::runtime_model_catalog(
            catalog_diagnostic,
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
    let canonical_prefix = "environment preflight reported runtime_model_catalog_unavailable";
    let summary = &report.environment_failures[0].summary;
    assert!(summary.starts_with(&format!(
        "{canonical_prefix}: injected catalog acquisition failure "
    )));
    assert!(summary.contains("API_TOKEN <redacted:secret>"));
    assert!(!summary.contains(secret));
    assert!(!summary
        .chars()
        .any(|character| matches!(character, '\r' | '\n')));
    let diagnostic = summary
        .strip_prefix(&format!("{canonical_prefix}: "))
        .expect("catalog failure summary retains a canonical bounded diagnostic");
    assert!(
        diagnostic.chars().count() <= MAX_ENVIRONMENT_FAILURE_DIAGNOSTIC_CHARS,
        "catalog diagnostic exceeded its Unicode-scalar limit"
    );
    assert!(diagnostic.ends_with(ENVIRONMENT_FAILURE_DIAGNOSTIC_TRUNCATION_MARKER));
    assert!(!report.environment_failures[0].remediation.is_empty());
    let operator_summary = render_supervisor_operator_summary(&report);
    assert!(operator_summary.contains(&format!("- environment: {summary}")));
    assert!(!operator_summary.contains(secret));

    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("typed catalog failure must finalize authenticated supervisor artifacts");
    let persisted_summary = String::from_utf8(
        reader
            .read(Path::new("SUMMARY.md"))
            .expect("read authenticated operator summary"),
    )
    .expect("authenticated operator summary is UTF-8");
    let persisted_environment_line = persisted_summary
        .lines()
        .find(|line| line.starts_with("- environment: "))
        .expect("operator summary contains the typed environment failure");
    assert_eq!(
        persisted_environment_line,
        format!("- environment: {summary}")
    );
    assert!(persisted_environment_line.contains("injected catalog acquisition failure"));
    assert!(persisted_environment_line.contains("API_TOKEN <redacted:secret>"));
    assert!(!persisted_summary.contains(secret));
    let persisted = read_supervisor_final_report(&reader)
        .expect("read persisted runtime catalog environment failure report");
    assert_eq!(persisted, report);
    assert_eq!(persisted.environment_failures[0].summary, *summary);
}

#[test]
fn runtime_model_catalog_empty_diagnostic_normalization_is_idempotent() {
    let run_id = RunId::new("model-catalog-empty-diagnostic").expect("valid run id");
    let mut report = artifact_test_final_report(&run_id);
    report.environment_failures = vec![EnvironmentFailure::runtime_model_catalog(
        "\r\n\t".to_string(),
    )];

    enforce_supervisor_final_environment_failure_outcome(&mut report);
    let normalized = report.environment_failures.clone();
    enforce_supervisor_final_environment_failure_outcome(&mut report);

    assert_eq!(report.environment_failures, normalized);
    assert_eq!(
        report.environment_failures[0].summary,
        "environment preflight reported runtime_model_catalog_unavailable"
    );
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
    let worker_unavailable_reason = by_role[&AgentRole::Worker]
        .unavailable_reason
        .as_deref()
        .expect("worker usage unavailability reason");
    assert!(worker_unavailable_reason.contains("runtime-side role-tagged usage reporting"));
    assert!(worker_unavailable_reason.contains("separately observe a worker process"));
    assert!(worker_unavailable_reason.contains("runtime identity"));
    assert!(!worker_unavailable_reason.contains("child Codex sessions"));
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
fn process_role_usage_aggregation_prices_direct_workers() {
    let mut plan = parse_supervisor_plan_with_consultant(
        std::str::from_utf8(&bounded_loader_plan_json()).expect("UTF-8 plan"),
    )
    .expect("base plan")
    .plan;
    plan.model_pricing = BTreeMap::from([
        (
            "worker-primary".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 2.0,
                output_usd_per_million_tokens: 8.0,
            },
        ),
        (
            "worker-fallback".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 1.0,
                output_usd_per_million_tokens: 4.0,
            },
        ),
    ]);
    let first_usage = Usage {
        input_tokens: 1_000,
        output_tokens: 200,
        total_tokens: 1_200,
    };
    let second_usage = Usage {
        input_tokens: 500,
        output_tokens: 100,
        total_tokens: 600,
    };

    let aggregation = role_usage_report(
        &plan,
        vec![
            RoleUsageSample {
                role: AgentRole::Worker,
                lens_id: None,
                model: Some("worker-primary".to_string()),
                usage: first_usage,
            },
            RoleUsageSample {
                role: AgentRole::Worker,
                lens_id: None,
                model: Some("worker-fallback".to_string()),
                usage: second_usage,
            },
        ],
    )
    .expect("aggregate direct Worker process usage");

    let worker = &aggregation.reports[&AgentRole::Worker];
    let expected_usage = first_usage.saturating_add(second_usage);
    let expected_cost = 0.0036 + 0.0009;
    assert_eq!(
        worker.models,
        vec!["worker-fallback".to_string(), "worker-primary".to_string()]
    );
    assert_eq!(worker.usage, Some(expected_usage));
    assert!(worker
        .cost_usd
        .is_some_and(|cost| (cost - expected_cost).abs() < 1e-12));
    assert_eq!(worker.observation, RoleUsageObservation::ProcessObserved);
    assert!(worker.unavailable_reason.is_none());
    assert_eq!(aggregation.total_usage, Some(expected_usage));
    assert!(aggregation
        .total_cost_usd
        .is_some_and(|cost| (cost - expected_cost).abs() < 1e-12));
    assert_eq!(
        aggregation.reports[&AgentRole::Supervisor].usage,
        Some(expected_usage)
    );
}

#[test]
fn final_usage_evidence_preserves_rejected_and_active_auditor_models() {
    let assignment = injected_assignment(true);
    assert_eq!(assignment.role, AgentRole::ChildOrchestrator);
    assert_eq!(assignment.worker_assignments.len(), 1);
    assert_eq!(assignment.worker_assignments[0].role, AgentRole::Worker);
    let mut plan = injected_plan(assignment, 1);
    let lens_id = plan.review_lenses[0].id.clone();
    let backend_id = plan.review_lenses[0].backend.backend_id().to_string();
    let ReviewLensBackendConfig::Model { model, .. } = &mut plan.review_lenses[0].backend else {
        panic!("default supervisor lens must be model-backed");
    };
    *model = "auditor-initial".to_string();
    plan.model_pricing = BTreeMap::from([
        (
            "auditor-initial".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 1.0,
                output_usd_per_million_tokens: 2.0,
            },
        ),
        (
            "auditor-active".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 3.0,
                output_usd_per_million_tokens: 4.0,
            },
        ),
    ]);
    let rejected_usage = Usage {
        input_tokens: 100,
        output_tokens: 20,
        total_tokens: 120,
    };
    let accepted_usage = Usage {
        input_tokens: 200,
        output_tokens: 40,
        total_tokens: 240,
    };
    let aggregation = role_usage_report(
        &plan,
        vec![
            RoleUsageSample {
                role: AgentRole::Auditor,
                lens_id: Some(lens_id.clone()),
                model: Some("auditor-initial".to_string()),
                usage: rejected_usage,
            },
            RoleUsageSample {
                role: AgentRole::Auditor,
                lens_id: Some(lens_id.clone()),
                model: Some("auditor-active".to_string()),
                usage: accepted_usage,
            },
        ],
    )
    .expect("aggregate final scheduler usage across an auditor retry switch");

    assert_eq!(aggregation.lens_reports.len(), 2);
    assert_eq!(aggregation.lens_reports[0].lens_id, lens_id);
    assert_eq!(aggregation.lens_reports[0].backend_id, backend_id);
    assert_eq!(aggregation.lens_reports[0].model, "auditor-active");
    assert_eq!(aggregation.lens_reports[0].usage, Some(accepted_usage));
    assert_eq!(aggregation.lens_reports[1].model, "auditor-initial");
    assert_eq!(aggregation.lens_reports[1].usage, Some(rejected_usage));
    let expected_total = rejected_usage.saturating_add(accepted_usage);
    assert_eq!(aggregation.lens_total_usage, Some(expected_total));
    assert_eq!(aggregation.total_usage, Some(expected_total));
    let rejected_cost = 0.00014;
    let accepted_cost = 0.00076;
    assert!(aggregation
        .lens_reports
        .iter()
        .find(|usage| usage.model == "auditor-initial")
        .and_then(|usage| usage.cost_usd)
        .is_some_and(|cost| (cost - rejected_cost).abs() < 1e-12));
    assert!(aggregation
        .lens_reports
        .iter()
        .find(|usage| usage.model == "auditor-active")
        .and_then(|usage| usage.cost_usd)
        .is_some_and(|cost| (cost - accepted_cost).abs() < 1e-12));
    assert!(aggregation.lens_total_cost_usd.is_some_and(|cost| (cost
        - rejected_cost
        - accepted_cost)
        .abs()
        < 1e-12));

    let run_id = RunId::new("active-auditor-final-usage").expect("valid run id");
    let mut final_report = artifact_test_final_report(&run_id);
    final_report.role_usage = aggregation.reports;
    final_report.review_lens_usage = aggregation.lens_reports;
    final_report.review_lens_total_usage = aggregation.lens_total_usage;
    final_report.review_lens_total_cost_usd = aggregation.lens_total_cost_usd;
    final_report.total_usage = aggregation.total_usage;
    final_report.total_cost_usd = aggregation.total_cost_usd;
    let persisted: SupervisorFinalReport = serde_json::from_value(
        serde_json::to_value(&final_report).expect("serialize active auditor final evidence"),
    )
    .expect("deserialize active auditor final evidence");
    assert_eq!(persisted.review_lens_usage[0].model, "auditor-active");
    assert_eq!(persisted.review_lens_usage[1].model, "auditor-initial");
    assert_eq!(persisted.review_lens_total_usage, Some(expected_total));

    let missing_model_error = match role_usage_report(
        &plan,
        vec![RoleUsageSample {
            role: AgentRole::Auditor,
            lens_id: Some(plan.review_lenses[0].id.clone()),
            model: None,
            usage: Usage::default(),
        }],
    ) {
        Ok(_) => panic!("lens usage without model attribution must fail closed"),
        Err(error) => error,
    };
    assert!(missing_model_error
        .to_string()
        .contains("omitted the dispatched model attribution"));
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
fn nested_process_usage_has_no_synthetic_worker_totals() {
    let assignment = injected_assignment(true);
    assert_eq!(assignment.role, AgentRole::ChildOrchestrator);
    assert_eq!(assignment.worker_assignments.len(), 1);
    let nested_plan = injected_plan(assignment, 1);
    let child_usage = Usage {
        input_tokens: 400,
        output_tokens: 100,
        total_tokens: 500,
    };
    let nested = role_usage_report(
        &nested_plan,
        vec![RoleUsageSample {
            role: AgentRole::ChildOrchestrator,
            lens_id: None,
            model: Some("planner-model".to_string()),
            usage: child_usage,
        }],
    )
    .expect("aggregate child-orchestrator usage without synthesizing nested Worker usage");
    let nested_worker = &nested.reports[&AgentRole::Worker];
    assert!(nested_worker.models.is_empty());
    assert!(nested_worker.usage.is_none());
    assert!(nested_worker.cost_usd.is_none());
    assert_eq!(
        nested_worker.observation,
        RoleUsageObservation::NotProcessObservable
    );
    assert!(nested_worker
        .unavailable_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("nested-worker delegation")));
    assert_eq!(nested.total_usage, Some(child_usage));
    assert_eq!(
        nested.reports[&AgentRole::Supervisor].usage,
        Some(child_usage)
    );
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
    skip_without_containment!();
    let _capability = install_named_test_models(&["model-alpha", "model-beta"]);
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.review_lenses = vec![
        ReviewLensConfig {
            id: "diff-security".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "provider-alpha".to_string(),
                model: "model-alpha".to_string(),
                reasoning_effort: Some("high".to_string()),
            },
            information_scope: ReviewInformationScope::DiffOnly,
        },
        ReviewLensConfig {
            id: "report-consistency".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "provider-beta".to_string(),
                model: "model-beta".to_string(),
                reasoning_effort: Some("xhigh".to_string()),
            },
            information_scope: ReviewInformationScope::OutputReportOnly,
        },
    ];
    plan.review_aggregation_policy = ReviewAggregationPolicy::AllMustAccept;
    plan.model_pricing = BTreeMap::from([
        (
            "model-alpha".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 1.0,
                output_usd_per_million_tokens: 2.0,
            },
        ),
        (
            "model-beta".to_string(),
            ModelPricing {
                input_usd_per_million_tokens: 3.0,
                output_usd_per_million_tokens: 4.0,
            },
        ),
    ]);
    let options = injected_options(&repo_path, temp.path(), "stacked-review-lenses-execute");
    let run_id = options.run_id.clone();
    let catalog =
        injected_codex_runtime_catalog(&[FRONTIER_PROFILE_MODEL, "model-alpha", "model-beta"]);
    let mut lens_commands = Vec::new();
    let mut lens_prompts = Vec::new();
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .expect("UTF-8 output name");
        if name.contains("review-auditor") {
            let mut audit =
                injected_auditor_report(&assignment, &injected_child_report(&assignment));
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
            write_injected_assignment_report(command, &assignment);
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

    assert!(
        report.success,
        "unexpected stacked-lens failure: {report:#?}"
    );
    assert_eq!(lens_commands.len(), 2);
    assert_ne!(lens_commands[0].cwd, lens_commands[1].cwd);
    assert_eq!(
        lens_commands[0].model_provider.as_deref(),
        Some("provider-alpha")
    );
    assert_eq!(lens_commands[0].model.as_deref(), Some("model-alpha"));
    assert_eq!(lens_commands[0].reasoning_effort.as_deref(), Some("xhigh"));
    assert_eq!(
        lens_commands[1].model_provider.as_deref(),
        Some("provider-beta")
    );
    assert_eq!(lens_commands[1].model.as_deref(), Some("model-beta"));
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
        .is_some_and(|cost| (cost - 0.0009).abs() < 1e-12));
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
fn unavailable_lens_runtime_selection_is_reported_and_journaled_procedurally() {
    skip_without_containment!();
    let _capability = install_named_test_models(&["child-model"]);
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.role_models.insert(
        AgentRole::ChildOrchestrator,
        RoleModelSelection {
            model: Some("child-model".to_string()),
            reasoning_effort: Some("high".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let ReviewLensBackendConfig::Model { model, .. } = &mut plan.review_lenses[0].backend else {
        panic!("default supervisor lens must be model-backed");
    };
    *model = "missing-lens-model".to_string();
    let options = injected_options(
        &repo_path,
        temp.path(),
        "unavailable-lens-selection-procedural",
    );
    let run_id = options.run_id.clone();
    let catalog = injected_codex_runtime_catalog(&["child-model"]);
    let mut invocations = Vec::new();
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .expect("UTF-8 output name");
        invocations.push(name.to_string());
        assert!(!name.contains("review-auditor"));
        write_injected_assignment_report(command, &assignment);
        write_injected_usage(command, 50, 10);
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
    .expect("finalize unavailable-lens procedural report");
    assert_eq!(invocations.len(), 1);
    assert!(!report.success);
    let aggregate = report.orchestrator_reports[0]
        .review_lens_aggregate
        .as_ref()
        .expect("procedural aggregate");
    assert_eq!(
        aggregate.decision,
        ReviewAggregationDecision::ProceduralFailure
    );
    assert_eq!(aggregate.procedural_failures, 1);
    assert_eq!(
        aggregate.lens_verdicts[0].effective_verdict,
        ReviewLensVerdictStatus::ProceduralFailure
    );
    assert_eq!(
        report.review_lens_usage[0].observation,
        RoleUsageObservation::NotProcessObservable
    );
    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("open procedural lens artifacts");
    assert!(read_finalized_orchestration_events(&reader)
        .iter()
        .any(|event| {
            event.kind == OrchestrationEventKind::Gate
                && event.payload["review_lens_aggregate"]["decision"] == "procedural_failure"
        }));
}

#[cfg(unix)]
#[test]
fn supervisor_input_loader_accepts_direct_regular_files_and_refuses_unsafe_inputs() {
    skip_without_containment!();
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

#[test]
fn provider_planning_session_lowers_recursive_tree_and_binds_run_identity() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    git2::Repository::init(repo).expect("init repo");
    std::fs::create_dir_all(repo.join("src")).expect("src dir");
    std::fs::write(repo.join("src/alpha.rs"), "pub fn alpha_task() {}\n").expect("alpha");
    std::fs::write(repo.join("src/beta.rs"), "pub fn beta_task() {}\n").expect("beta");
    let config = crate::planning::ProviderPlanningConfig::new("lower", "planner-model");
    let provider_plan = crate::planning::ProviderRecursiveTaskPlan {
        assignments: vec![crate::planning::ProviderTaskAssignmentTree {
            id: "parent".to_string(),
            task: "Coordinate alpha and beta".to_string(),
            fragment_ids: vec!["fragment-001".to_string(), "fragment-002".to_string()],
            assigned_paths: vec![PathBuf::from("src/alpha.rs"), PathBuf::from("src/beta.rs")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            child_assignments: vec![
                crate::planning::ProviderTaskAssignmentTree {
                    id: "alpha".to_string(),
                    task: "Update alpha".to_string(),
                    fragment_ids: vec!["fragment-001".to_string()],
                    assigned_paths: vec![PathBuf::from("src/alpha.rs")],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    child_assignments: Vec::new(),
                },
                crate::planning::ProviderTaskAssignmentTree {
                    id: "beta".to_string(),
                    task: "Update beta".to_string(),
                    fragment_ids: vec!["fragment-002".to_string()],
                    assigned_paths: vec![PathBuf::from("src/beta.rs")],
                    semantic_symbols: Vec::new(),
                    semantic_modules: Vec::new(),
                    child_assignments: Vec::new(),
                },
            ],
        }],
    };
    let mut provider = crate::llm::fake::FakeProvider::new("fake-planner", "planner-model");
    provider
        .push_json_response("lower-proposal", &provider_plan)
        .expect("script recursive plan");
    let session = crate::planning::propose_task_decomposition_with_provider(
        repo,
        "",
        "- Update alpha behavior.\n- Update beta behavior.",
        &mut provider,
        &config,
    )
    .expect("provider session");

    let plan = supervisor_plan_from_task_planning_session(
        "",
        "- Update alpha behavior.\n- Update beta behavior.",
        &session,
    )
    .expect("lower provider session");
    assert_eq!(plan.assignments.len(), 3);
    assert_eq!(plan.assignments[0].id, "parent");
    assert_eq!(plan.assignments[0].phase, AssignmentPhase::Planning);
    assert!(plan.assignments[0].worker_assignments.is_empty());
    assert_eq!(plan.assignments[1].id, "alpha");
    assert_eq!(plan.assignments[1].phase, AssignmentPhase::Execution);
    assert_eq!(plan.assignments[1].worker_assignments.len(), 1);
    assert_eq!(plan.assignments[2].id, "beta");
    assert_eq!(plan.assignments[2].phase, AssignmentPhase::Execution);

    let run_id = crate::orchestrator::RunId::new("provider-bind-run").expect("valid run id");
    let bound = bind_provider_task_planning_session_to_supervisor_run(
        "",
        "- Update alpha behavior.\n- Update beta behavior.",
        &session,
        run_id.clone(),
    )
    .expect("bind provider session");
    assert_eq!(bound.execution_binding.run_id(), &run_id);
    assert_eq!(bound.plan.assignments.len(), 3);
    assert!(bound.document.get("assignments").is_some());
}

#[test]
fn heuristic_feedback_replan_lowers_remaining_work_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    git2::Repository::init(repo).expect("init repo");
    std::fs::create_dir_all(repo.join("src")).expect("src dir");
    std::fs::write(repo.join("src/alpha.rs"), "pub fn alpha_task() {}\n").expect("alpha");
    std::fs::write(repo.join("src/beta.rs"), "pub fn beta_task() {}\n").expect("beta");
    std::fs::write(repo.join("src/gamma.rs"), "pub fn gamma_task() {}\n").expect("gamma");
    let config = crate::planning::ProviderPlanningConfig::new("replan", "planner-model");
    let spec = "- Update alpha_task in src/alpha.rs.\n- Update beta_task in src/beta.rs.";
    let mut session = crate::planning::propose_task_decomposition_with_optional_provider(
        repo, "", spec, None, &config,
    )
    .expect("heuristic session");
    let feedback = crate::planning::TaskExecutionFeedback {
        completed_assignment_ids: vec!["assignment-001".to_string()],
        failed_assignment_ids: vec!["assignment-002".to_string()],
        coverage_gap_fragment_ids: vec!["fragment-002".to_string()],
        notes: vec!["execution found the implementation in src/gamma.rs".to_string()],
    };

    let plan = supervisor_plan_from_feedback_replan(repo, "", spec, &mut session, &feedback)
        .expect("lower heuristic feedback re-plan");

    assert_eq!(session.replans_used(), 1);
    assert_eq!(plan.assignments.len(), 2);
    assert_eq!(plan.assignments[0].id, "assignment-replan-01-001-planning");
    assert_eq!(plan.assignments[0].phase, AssignmentPhase::Planning);
    assert_eq!(plan.assignments[1].id, "assignment-replan-01-001");
    assert_eq!(plan.assignments[1].phase, AssignmentPhase::Execution);
    assert!(
        plan.assignments[1]
            .assigned_paths
            .contains(&PathBuf::from("src/gamma.rs")),
        "remaining work should pick up the feedback path: {:?}",
        plan.assignments[1].assigned_paths
    );
    assert!(plan
        .assignments
        .iter()
        .all(|assignment| assignment.id != "assignment-001"));
}
