use super::*;
use crate::selection::{
    routing_policy::{
        bind_routing_policy, captured_selected_authorizations, current_routing_policy,
        load_routing_policy, seal_selected_candidate, RoutingPolicyReceipt, TaskRoutingFeatures,
    },
    select_with_loaded_routing_policy, selection_test_base_input, CandidateKey, DecisionStatus,
    ReasoningEffort, SelectionProvenance,
};
use git2::Repository;
use tempfile::TempDir;

fn selected_candidate(role: AgentRole) -> Result<SelectionProvenance> {
    selected_candidate_for_model(role, "gpt-6.1-sol")
}

fn selected_candidate_for_model(role: AgentRole, model: &str) -> Result<SelectionProvenance> {
    let receipt = RoutingPolicyReceipt {
        frozen: current_routing_policy().context("active test policy")?,
        role: role.as_str().into(),
        features: TaskRoutingFeatures {
            scope_paths: 1,
            scope_modules: 1,
            complexity: 0,
            risk: 0,
            horizon: 0,
            context_tokens: 0,
            dependency_edges: 0,
            independent_groups: 1,
            evidence: vec!["bounded test scope".into()],
        },
    };
    let mut input = selection_test_base_input();
    input.catalogs.truncate(1);
    input.catalogs[0].models.truncate(1);
    input.catalogs[0].models[0].model = model.into();
    input.catalogs[0].models[0].supported_efforts = vec![ReasoningEffort::Xhigh];
    input.pools.truncate(1);
    let decision = select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    assert_eq!(decision.status, DecisionStatus::Selected);
    assert_eq!(
        decision
            .choice
            .as_ref()
            .context("selected candidate")?
            .candidate,
        CandidateKey {
            runtime: "codex".into(),
            model: model.into(),
            effort: ReasoningEffort::Xhigh,
        }
    );
    Ok(decision)
}

fn metadata(repo: &Path, role: AgentRole) -> Result<AgentLaunchMetadata> {
    AgentLaunchMetadata::new(repo, role.as_str(), "selector-authority", "assignment")
}

fn argv() -> Vec<String> {
    [
        "codex",
        "exec",
        "--model",
        "gpt-6.1-sol",
        "-c",
        "model_reasoning_effort=\"xhigh\"",
    ]
    .map(str::to_string)
    .into()
}

fn assert_selector_refusal(result: Result<()>) {
    let error = result.expect_err("missing exact role/model selection must refuse launch");
    assert!(
        error
            .to_string()
            .contains("selector-authorized loaded-policy binding"),
        "{error:#}"
    );
}

#[test]
fn researcher_launch_accepts_own_selector_authorization_without_worker_binding() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let _policy = bind_routing_policy(Some(load_routing_policy(temp.path())?))?;
    let decision = selected_candidate(AgentRole::Researcher)?;
    seal_selected_candidate("researcher", &decision)?;
    let authorizations = captured_selected_authorizations();
    assert_eq!(authorizations.len(), 1);
    assert!(authorizations.contains_key("researcher"));
    assert!(!authorizations.contains_key("worker"));

    authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Researcher)?,
        &argv(),
        temp.path(),
        None,
    )?;
    let authority = derive_launch_authority("researcher", &argv(), None)?;
    assert_eq!(authority.category, RoleCategory::ReadOnlyResearcher);
    assert_eq!(authority.requested_model.as_deref(), Some("gpt-6.1-sol"));
    assert_eq!(authority.source, "role_and_exact_requested_argv");
    assert!(!authority.may_delegate);
    assert!(!authority.may_write);
    assert!(!authority.may_judge_acceptance);
    assert!(!authority.may_mutate_git_history);
    assert!(!authority.probe_only);
    Ok(())
}

#[test]
fn researcher_launch_requires_own_selector_authorization() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let _policy = bind_routing_policy(Some(load_routing_policy(temp.path())?))?;
    let _unsealed = selected_candidate(AgentRole::Researcher)?;
    assert!(captured_selected_authorizations().is_empty());
    assert_selector_refusal(authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Researcher)?,
        &argv(),
        temp.path(),
        None,
    ));
    let missing_model = ["codex".into(), "exec".into()];
    assert!(authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Researcher)?,
        &missing_model,
        temp.path(),
        None,
    )
    .is_err());
    Ok(())
}

#[test]
fn worker_and_researcher_selector_authorizations_do_not_cross_authorize() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    for (selected, refused) in [
        (AgentRole::Worker, AgentRole::Researcher),
        (AgentRole::Researcher, AgentRole::Worker),
    ] {
        let _policy = bind_routing_policy(Some(load_routing_policy(temp.path())?))?;
        seal_selected_candidate(selected.as_str(), &selected_candidate(selected)?)?;
        assert_eq!(captured_selected_authorizations().len(), 1);
        assert_selector_refusal(authorize_process_launch_before_spawn(
            &metadata(temp.path(), refused)?,
            &argv(),
            temp.path(),
            None,
        ));
    }
    Ok(())
}

#[test]
fn researcher_launch_rejects_model_outside_own_selector_authorization() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let _policy = bind_routing_policy(Some(load_routing_policy(temp.path())?))?;
    seal_selected_candidate("researcher", &selected_candidate(AgentRole::Researcher)?)?;
    seal_selected_candidate(
        "worker",
        &selected_candidate_for_model(AgentRole::Worker, "unselected-model")?,
    )?;
    assert_eq!(captured_selected_authorizations().len(), 2);
    let mut changed = argv();
    changed[3] = "unselected-model".into();
    authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Worker)?,
        &changed,
        temp.path(),
        None,
    )?;
    assert_selector_refusal(authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Researcher)?,
        &changed,
        temp.path(),
        None,
    ));
    Ok(())
}

fn bind_distinct_policy(
    repo: &Path,
    id: &str,
) -> Result<crate::selection::routing_policy::RoutingPolicyGuard> {
    let mut frozen = load_routing_policy(repo)?;
    frozen.policy.policy_id = id.into();
    frozen.sha256 = crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
    bind_routing_policy(Some(frozen))
}

#[cfg(target_os = "linux")]
#[test]
fn historical_registry_survives_new_policy_without_reauthorizing_old_roles() -> Result<()> {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let registry = AgentRegistry::open(temp.path())?;
    let children = [
        Child(std::process::Command::new("sleep").arg("60").spawn()?),
        Child(std::process::Command::new("sleep").arg("60").spawn()?),
    ];
    let old_records;
    let old_json;
    {
        let _policy_a = bind_distinct_policy(temp.path(), "historical-policy-a")?;
        let mut records = Vec::new();
        for (role, child) in [AgentRole::ChildOrchestrator, AgentRole::Worker]
            .into_iter()
            .zip(&children)
        {
            seal_selected_candidate(role.as_str(), &selected_candidate(role)?)?;
            let record = registry.register(&metadata(temp.path(), role)?, child.0.id(), argv())?;
            record.launch_authority()?;
            records.push(record);
        }
        old_json = serde_json::to_vec(&records)?;
        old_records = records;
    }
    let _policy_b = bind_distinct_policy(temp.path(), "historical-policy-b")?;
    seal_selected_candidate("researcher", &selected_candidate(AgentRole::Researcher)?)?;
    let selected_before = captured_selected_authorizations();
    assert_eq!(selected_before.len(), 1);
    assert!(selected_before.contains_key("researcher"));
    let decoded: Vec<AgentProcessRecord> = serde_json::from_slice(&old_json)?;
    assert_eq!(decoded, old_records);
    assert_eq!(serde_json::to_vec(&decoded)?, old_json);
    let inspections = registry.inspect()?;
    assert_eq!(inspections.len(), 2);
    assert!(inspections
        .iter()
        .all(|entry| entry.identity == AgentIdentityLiveness::Live));
    for record in &decoded {
        assert!(record.launch_authority().is_err());
        assert_selector_refusal(authorize_process_launch_before_spawn(
            &metadata(
                temp.path(),
                lifecycle_policy_role(&record.role).context("old role")?,
            )?,
            &record.argv,
            temp.path(),
            None,
        ));
        assert!(registry
            .register(
                &metadata(
                    temp.path(),
                    lifecycle_policy_role(&record.role).context("old role")?
                )?,
                std::process::id(),
                record.argv.clone(),
            )
            .is_err());
    }
    let path = registry.registry_path();
    let before_refusal = std::fs::read(&path)?;
    let mut unknown_model = argv();
    unknown_model[3] = "unselected-unknown-model".into();
    assert!(registry
        .register(
            &metadata(temp.path(), AgentRole::Researcher)?,
            std::process::id(),
            unknown_model,
        )
        .is_err());
    assert!(registry
        .register(
            &metadata(temp.path(), AgentRole::Worker)?,
            std::process::id(),
            vec!["codex".into(), "exec".into()],
        )
        .is_err());
    assert_eq!(std::fs::read(&path)?, before_refusal);

    // Real registration rewrites the registry under B, preserving A's records.
    let fresh = registry.register(
        &metadata(temp.path(), AgentRole::Researcher)?,
        std::process::id(),
        argv(),
    )?;
    fresh.launch_authority()?;
    let all = registry.snapshot_all()?;
    assert_eq!(all.len(), 3);
    assert!(old_records.iter().all(|record| all.contains(record)));
    let probe = registry.register(
        &metadata(temp.path(), AgentRole::Worker)?,
        std::process::id(),
        vec!["codex".into(), "--version".into()],
    )?;
    assert!(probe.launch_authority()?.probe_only);
    registry.unregister(probe.pid, &probe.process_start_time)?;
    assert_eq!(registry.snapshot_all()?, old_records);
    assert_eq!(captured_selected_authorizations(), selected_before);

    // Existing exact dispatch-triple enforcement is unchanged by historical reads.
    use crate::selection::routing_policy::validate_selected_launch;
    validate_selected_launch("researcher", "codex", "gpt-6.1-sol", "xhigh")?;
    for (role, runtime, model, effort) in [
        ("worker", "codex", "gpt-6.1-sol", "xhigh"),
        ("researcher", "claude", "gpt-6.1-sol", "xhigh"),
        ("researcher", "codex", "unselected-model", "xhigh"),
        ("researcher", "codex", "gpt-6.1-sol", "high"),
    ] {
        assert!(validate_selected_launch(role, runtime, model, effort).is_err());
    }
    Ok(())
}

fn historical_record(repo: &Path) -> AgentProcessRecord {
    AgentProcessRecord {
        pid: 4242,
        process_start_time: "linux-v2:4242:11111111-2222-3333-4444-555555555555:1".into(),
        role: "child_orchestrator".into(),
        run_id: "historical-run".into(),
        task_id: "historical-task".into(),
        parent: None,
        repo: repo.into(),
        argv: argv(),
        launch_timestamp_ms: 1,
        mechanical_executor: None,
    }
}

#[test]
fn historical_serde_rejects_forged_authority_argv_unknown_models_and_schema() -> Result<()> {
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let encoded;
    {
        let _policy_a = bind_distinct_policy(temp.path(), "forgery-policy-a")?;
        seal_selected_candidate(
            "child_orchestrator",
            &selected_candidate(AgentRole::ChildOrchestrator)?,
        )?;
        let record = historical_record(temp.path());
        record.launch_authority()?;
        encoded = serde_json::to_value(record)?;
    }
    let _policy_b = bind_distinct_policy(temp.path(), "forgery-policy-b")?;
    seal_selected_candidate("worker", &selected_candidate(AgentRole::Worker)?)?;
    let mut mutations = Vec::new();
    let mut forged = encoded.clone();
    forged["launch_authority"]["may_mutate_git_history"] = true.into();
    mutations.push(forged);
    let mut forged = encoded.clone();
    forged["role"] = "worker".into();
    mutations.push(forged);
    let mut forged = encoded.clone();
    forged["argv"].as_array_mut().context("argv")?.extend([
        serde_json::json!("--model"),
        serde_json::json!("conflicting-model"),
    ]);
    mutations.push(forged);
    let mut forged = encoded.clone();
    forged["argv"][3] = "unclassified-historical-model".into();
    forged
        .as_object_mut()
        .context("record")?
        .remove("launch_authority");
    mutations.push(forged);
    let mut forged = encoded.clone();
    forged["argv"] = serde_json::json!([]);
    mutations.push(forged);
    let mut forged = encoded.clone();
    forged["unexpected_field"] = true.into();
    mutations.push(forged);
    for forged in mutations {
        assert!(serde_json::from_value::<AgentProcessRecord>(forged).is_err());
    }
    let record: AgentProcessRecord = serde_json::from_value(encoded)?;
    record.validate(temp.path())?;
    assert!(record.validate(&temp.path().join("foreign-repo")).is_err());
    let mut invalid = record.clone();
    invalid.pid = 0;
    assert!(invalid.validate(temp.path()).is_err());
    invalid = record;
    invalid.argv.push("nul\0argument".into());
    assert!(invalid.validate(temp.path()).is_err());
    Ok(())
}

#[test]
fn historical_mechanical_serde_preserves_evidence_without_minting_live_proof() -> Result<()> {
    let _overlay = crate::supervise::install_test_fixture_models(&[(
        "historical-mechanical-fixture",
        ModelCapabilityClass::WeakMechanical,
    )])?;
    let temp = TempDir::new()?;
    Repository::init(temp.path())?;
    let mut record = historical_record(temp.path());
    record.role = "worker".into();
    record.argv[0] = "/usr/bin/codex".into();
    record.argv[3] = "historical-mechanical-fixture".into();
    record.mechanical_executor = Some(MechanicalExecutorLaunchEvidence {
        grant_nonce: 7,
        kind: MechanicalExecutorGrantKind::AssignmentChild,
        role: "worker".into(),
        phase: OrchestrationPhase::MechanicalTerminal,
        duty: MechanicalTerminalDuty::RunPreselectedCommand,
        model: record.argv[3].clone(),
        canonical_program: PathBuf::from(&record.argv[0]),
        cwd: temp.path().into(),
        argv: record.argv.clone(),
        run_id: record.run_id.clone(),
        subject: record.task_id.clone(),
        attempt: 1,
    });
    let encoded;
    {
        let _policy_a = bind_distinct_policy(temp.path(), "mechanical-policy-a")?;
        seal_selected_candidate(
            "worker",
            &selected_candidate_for_model(AgentRole::Worker, "historical-mechanical-fixture")?,
        )?;
        record.launch_authority()?;
        encoded = serde_json::to_value(&record)?;
    }
    {
        let _policy_b = bind_distinct_policy(temp.path(), "mechanical-policy-b")?;
        seal_selected_candidate("researcher", &selected_candidate(AgentRole::Researcher)?)?;
        let decoded: AgentProcessRecord = serde_json::from_value(encoded.clone())?;
        assert_eq!(decoded, record);
        decoded.validate(temp.path())?;
        assert!(decoded.launch_authority().is_err());
        assert!(authorize_process_launch_before_spawn(
            &metadata(temp.path(), AgentRole::Worker)?,
            &decoded.argv,
            temp.path(),
            None,
        )
        .is_err());
        assert_eq!(captured_selected_authorizations().len(), 1);
    }
    // With no loaded selector policy, deserialized mechanical evidence still
    // cannot replace a consumed ReservedMechanicalExecutorExecution.
    let _legacy = bind_routing_policy(None)?;
    let decoded: AgentProcessRecord = serde_json::from_value(encoded.clone())?;
    let error = authorize_process_launch_before_spawn(
        &metadata(temp.path(), AgentRole::Worker)?,
        &decoded.argv,
        temp.path(),
        None,
    )
    .expect_err("historical mechanical evidence is not a live reserved proof");
    assert!(error
        .to_string()
        .contains("consumed assignment-child mechanical executor proof"));
    for (key, value) in [
        ("role", serde_json::json!("researcher")),
        ("phase", serde_json::json!("implementation")),
        ("model", serde_json::json!("gpt-6.1-sol")),
        ("canonical_program", serde_json::json!("/foreign/codex")),
        ("cwd", serde_json::json!("relative")),
        ("run_id", serde_json::json!("foreign-run")),
        ("subject", serde_json::json!("foreign-task")),
        ("grant_nonce", serde_json::json!(0)),
        ("attempt", serde_json::json!(0)),
        ("argv", serde_json::json!(["/foreign/codex", "exec"])),
    ] {
        let mut forged = encoded.clone();
        forged["mechanical_executor"][key] = value;
        assert!(
            serde_json::from_value::<AgentProcessRecord>(forged).is_err(),
            "{key}"
        );
    }
    Ok(())
}
