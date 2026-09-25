use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

// Real managed resources and the existing prepare/collect boundary, with an
// injected deterministic runner. No provider process or native subagent runs.
fn driver_fixture(case: &str) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main")?;
    fs::create_dir(repo.join("src"))?;
    fs::write(repo.join("src/lib.rs"), "pub fn selected() {}\n")?;
    let git = crate::git_repository::open(&repo)?;
    let mut index = git.index()?;
    index.add_path(Path::new("src/lib.rs"))?;
    index.write()?;
    let tree = git.find_tree(index.write_tree()?)?;
    let signature = git2::Signature::now("test", "test@example.invalid")?;
    git.commit(Some("HEAD"), &signature, &signature, "base", &tree, &[])?;
    let parent: OrchestratorAssignment = serde_json::from_value(json!({
        "id":"parent", "phase":"execution", "role":"child_orchestrator",
        "assigned_paths":["src"], "task":"parent task",
        "worker_assignments":[{"id":"worker", "role":"worker",
            "assigned_paths":["src/lib.rs"], "task":"worker task", "report_path":"worker.json"}]
    }))?;
    let worker: OrchestratorAssignment = serde_json::from_value(json!({
        "id":"worker", "phase":"execution", "role":"worker",
        "assigned_paths":["src/lib.rs"], "task":"worker task", "worker_assignments":[]
    }))?;
    let plan: SupervisorPlan = serde_json::from_value(json!({
        "version":SUPERVISOR_SCHEMA_VERSION, "task":"nested driver fixture",
        "max_depth":2, "max_child_assignments":1, "max_child_retries":0,
        "max_gate_corrections":0, "child_timeout_seconds":10,
        "semantic_coordination":"off", "assignments":[parent],
        "role_models":{
            "child_orchestrator":{"model":"gpt-5.6-sol", "reasoning_effort":"high"},
            "worker":{"model":"gpt-5.6-sol", "reasoning_effort":"high"},
            "auditor":{"model":"gpt-5.6-sol", "reasoning_effort":"high"}
        }
    }))?;
    let run_id = RunId::new("nested-driver-test")?;
    let manager = WorktreeManager::new(&repo);
    let worktree = manager.create(crate::worktree::WorktreeCreateOptions {
        agent_id: parent.id.clone(),
        branch: None,
        base: None,
        worktree_root: Some(temp.path().join("worktrees")),
    })?;
    let lease = manager.acquire_write_execution_lease(&parent.id)?;
    let sync_store = SyncStore::open(&repo)?;
    let semantic_store = SemanticIntentStore::open(&repo)?;
    let claim = sync_store.claim_paths_for_run(&run_id, &parent.id, &parent.assigned_paths)?;
    let cancellation = ProcessCancellation::new();
    let mut preflight = AssignmentExecutionPreflight {
        journal_parent_id: run_id.as_str(),
        environment_requirements: Vec::new(),
        semantic_token: None,
        child_base_head: current_head_oid(&worktree.path)?,
        mandatory_worktree_controls: provision_mandatory_worktree_controls(&worktree.path)?,
        worktree: worktree.clone(),
        worktree_write_lease: Some(lease),
        primary_scope_baseline: None,
        claim: claim.clone(),
        managed_process_cancellation: sync_store
            .managed_process_cancellation_for_claim(claim.token, &cancellation)?,
        assignment: parent.clone(),
        _semantic_block_turn: None,
    };
    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: temp.path().join("plan.json"),
        run_id: run_id.clone(),
        parent_node: None,
        codex_bin: "never-invoke-provider".into(),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: Default::default(),
        budget_overrides: Default::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(crate::machine_global::MachineGlobalRetentionBinding {
            config: temp.path().join("unused-retention.json"),
            root_id: "runtime".into(),
            owner: "maco-supervise".into(),
            correction_correlation_id: run_id.as_str().into(),
        }),
    };
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "nested-driver-test",
    )?;
    let run_dir = writer.run_dir().to_path_buf();
    let dirs = RunDirs::for_writer(&writer);
    write_worker_schema(&mut writer, Path::new("schemas/worker-report.schema.json"))?;
    write_codex_worker_schema(
        &mut writer,
        Path::new("schemas/worker-report.codex-output.schema.json"),
    )?;
    write_orchestrator_schema(
        &mut writer,
        Path::new("schemas/orchestrator-review-report.schema.json"),
    )?;
    write_codex_orchestrator_schema(
        &mut writer,
        Path::new("schemas/orchestrator-review-report.codex-output.schema.json"),
    )?;
    write_auditor_schema(&mut writer, Path::new("schemas/auditor-report.schema.json"))?;
    let schedule = vec![AssignmentScheduleEntry {
        assignment_id: parent.id.clone(),
        parent_assignment_id: None,
        depth: 1,
        flattened_index: 0,
    }];
    super::super::messaging_bridge::initialize_supervisor_messaging_session(
        &mut writer,
        &plan,
        &SupervisorPlanMetadata {
            assignment_schedule: schedule.clone(),
            ..Default::default()
        },
    )?;
    let mut journal = initialize_orchestration_event_journal(&repo, &run_id, None);
    let mut kpis = AutonomyKpiCollector::default();
    let artifacts = Mutex::new(SharedSupervisorArtifacts {
        writer: &mut writer,
        journal: &mut journal,
        autonomy_kpis: &mut kpis,
        checkpoint: None,
    });
    let budget_config = SupervisorBudgetConfig {
        role_token_reservations: BTreeMap::from([
            (AgentRole::ChildOrchestrator, 2),
            (AgentRole::Worker, 2),
        ]),
        ..Default::default()
    };
    let ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
    let metadata = AssignmentMetadata::new();
    let consultant = SupervisorConsultantPlan::default();
    let guide = SupervisorFieldGuidePrompt::empty()?;
    let catalog =
        RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(["gpt-5.6-sol"])?);
    let parent_running = AtomicBool::new(false);
    let calls = Mutex::new(Vec::new());
    let runner = |command: &ExternalAgentCommand,
                  _: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>| {
        let subject = if command.agent_lifecycle.as_ref().unwrap().task_id == "parent" {
            assert!(!parent_running.swap(true, Ordering::SeqCst));
            &parent
        } else {
            assert!(
                !parent_running.load(Ordering::SeqCst),
                "overlapping parent and worker"
            );
            assert_eq!(command.reasoning_effort.as_deref(), Some("xhigh"));
            assert!(command.assignment_messaging_launch().is_none());
            &worker
        };
        calls.lock().unwrap().push(subject.id.clone());
        assert_eq!(command.cwd, worktree.path);
        assert_eq!(sync_store.snapshot().unwrap(), vec![claim.clone()]);
        let mut simulated = command.clone();
        simulated.model = None;
        let mut run =
            deterministic_fake_child_run(&simulated, subject, &metadata, claim.token.get(), None)
                .unwrap();
        run.stdout.target_launch_attempted = true;
        run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            crate::process_runner::ContainmentBackend::SystemdUserService,
        ));
        run.side_effects = Some(SideEffectConfinementEvidence::Verified(
            crate::process_runner::SideEffectConfinementProfileKind::ExternalCodex,
        ));
        run.publishable = true;
        run.program_trust = ExternalProgramTrust::TrustedSystemCodex;
        run.codex_permissions = Some(crate::external_agent::CodexPermissionEvidence {
            codex_version: "0.142.3".into(),
            minimum_version: "0.138.0".into(),
            permission_profile: "maco_external_codex".into(),
            workspace_access: command.workspace_access,
            network_enabled: false,
            argv_digest: "fixture".into(),
            executable_identity: "fixture".into(),
        });
        if subject.id == "parent" {
            if case.starts_with("yield-") {
                let report = json!({
                    "version":1, "outcome":"yield_workers", "run_id":run_id.as_str(),
                    "parent_id":"parent", "parent_attempt":1,
                    "requests":[{"request_id":"request-1", "worker_id":"worker"}]
                });
                let mut captured = report.clone();
                if case == "yield-forged-capture" {
                    captured["requests"][0]["request_id"] = json!("forged");
                }
                // Path bytes disagree with the held descriptor result. Yield
                // validation must use the latter, including when it is invalid.
                fs::write(
                    &command.output_last_message,
                    serde_json::to_vec(&report).unwrap(),
                )
                .unwrap();
                run.output_last_message = Some(serde_json::to_vec(&captured).unwrap());
            }
            parent_running.store(false, Ordering::SeqCst);
        } else if case == "worker-uncertain" {
            run.process_tree = None;
        }
        run
    };
    let context = AssignmentExecutionContext {
        index: 0,
        concurrent_mode: false,
        plan: &plan,
        requested_plan: &plan,
        budget_config: &budget_config,
        consultant: &consultant,
        assignment_metadata: &metadata,
        assignment: &parent,
        evidence_only_reaudit: None,
        options: &options,
        repo: &repo,
        run_dir: &run_dir,
        dirs: &dirs,
        execution_runtime: SupervisorExecutionRuntime::Verified,
        execution_target: None,
        worktree_creation: SupervisorWorktreeCreation::ExistingOnly,
        manager: &manager,
        reused: true,
        sync_store: &sync_store,
        semantic_store: &semantic_store,
        prepared_semantic_token: None,
        prepared_semantic_findings: &[],
        prepared_semantic_signals: &[],
        prepared_semantic_failed: false,
        assignment_schedule: &schedule,
        field_guide: &guide,
        serial_semantic_warn_intents: None,
        semantic_block_order: None,
        semantic_block_gate: None,
        artifacts: &artifacts,
        budget_ledger: &ledger,
        budget_policy: AssignmentBudgetPolicy::default(),
        admission_commit: None,
        runtime_model_catalog: &catalog,
        cancellation: cancellation.clone(),
        external_runner: &runner,
    };
    let mut outcome = AssignmentExecutionOutcome::default();
    let prepared = match prepare_child_attempt(
        &context,
        &mut outcome,
        &context.budget_policy,
        &preflight,
        run_id.as_str(),
        1,
        1,
        &None,
        &dirs.schemas.join("orchestrator-review-report.schema.json"),
        &dirs.schemas.join("worker-report.schema.json"),
        &dirs.schemas.join("auditor-report.schema.json"),
    )? {
        AssignmentExecutionDisposition::Continue(prepared) => prepared,
        AssignmentExecutionDisposition::Complete => {
            bail!("parent preparation unexpectedly completed")
        }
    };
    let mut collected = dispatch_and_collect_child_attempt(
        &context,
        &mut outcome,
        &preflight,
        run_id.as_str(),
        1,
        prepared,
    )?;
    assert_eq!(*calls.lock().unwrap(), ["parent"]);
    match case {
        "yield-blocked" => collected.environment_blocked = true,
        "yield-side-effects" => {
            collected.external_side_effect_state = Some(ExternalSideEffectState::Ambiguous)
        }
        "yield-side-effects-completed" => {
            collected.external_side_effect_state = Some(ExternalSideEffectState::Completed)
        }
        "parent-uncertain" | "yield-nonquiescent" => collected.external_run.process_tree = None,
        "parent-unconfined" => collected.external_run.side_effects = None,
        "parent-never-started" => collected.external_run.stdout.target_launch_attempted = false,
        "parent-failed" => collected.external_run.exit_code = Some(1),
        "parent-external-side-effect-ambiguous" => {
            collected.external_side_effect_state = Some(ExternalSideEffectState::Ambiguous);
        }
        "parent-external-side-effect-completed" => {
            collected.external_side_effect_state = Some(ExternalSideEffectState::Completed);
        }
        "parent-wrong-worktree" => collected.external_run.cwd = repo.clone(),
        "parent-restored" | "yield-restored" => {
            collected.external_run =
                serde_json::from_value(serde_json::to_value(&collected.external_run)?)?;
        }
        "parent-wrong-id" => {
            collected._command.agent_lifecycle.as_mut().unwrap().task_id = "other".into()
        }
        "cancelled-before" => cancellation.cancel(),
        _ => {}
    }
    let attempt = if case == "parent-wrong-attempt" { 2 } else { 1 };
    let binding = NestedWorkerSerialDriver::from_collected_parent(
        &context,
        &mut preflight,
        &mut outcome,
        attempt,
        &collected,
    );
    if matches!(case, "yield-side-effects" | "yield-side-effects-completed") {
        // Side effects invalidate the handoff itself, before a driver may
        // inspect the yield report or expose any requested Worker IDs.
        let error = binding
            .err()
            .context("accepted parent external side effects")?;
        assert_eq!(
            error.to_string(),
            "nested serial handoff requires verified parent-process quiescence and integrity",
            "unexpected handoff refusal for {case}"
        );
    } else if case.starts_with("parent-")
        || matches!(
            case,
            "cancelled-before" | "yield-nonquiescent" | "yield-restored"
        )
    {
        assert!(binding.is_err(), "accepted {case}");
    } else if case.starts_with("yield-") {
        let driver = binding?;
        if case == "yield-revoked" {
            sync_store.release(claim.token)?;
        }
        if case == "yield-cancelled" {
            cancellation.cancel();
        }
        let expected = [parent_turn_yield::ExpectedWorkerRequest::new(
            "request-1",
            "worker",
        )?];
        let result = driver.validate_parent_turn_yield(&expected);
        if case == "yield-happy" {
            let validated = result?;
            assert_eq!(validated.parent_binding(), (run_id.as_str(), "parent", 1));
            assert_eq!(
                validated.requests().collect::<Vec<_>>(),
                [("request-1", "worker")]
            );
        } else {
            assert!(result.is_err(), "accepted {case}");
        }
    } else {
        let mut driver = binding?;
        let mut active_policy = context.budget_policy.clone();
        active_policy.set_selector_binding_for_test(
            AgentRole::Worker,
            if case == "current-runtime-refused" {
                SupervisorRuntime::Grok
            } else {
                SupervisorRuntime::Codex
            },
            RoleModelSelection {
                model: Some("gpt-5.6-sol".into()),
                reasoning_effort: Some("xhigh".into()),
                ..Default::default()
            },
        );
        match case {
            "cancelled-after" => cancellation.cancel(),
            "claim-revoked" => {
                sync_store.release(claim.token)?;
            }
            _ => {}
        }
        let result = driver.execute_worker(
            if case == "unknown-worker" {
                "other"
            } else {
                "worker"
            },
            &active_policy,
        );
        if case == "happy" {
            let evidence = result?;
            assert_eq!(evidence.report.id, "worker");
            assert_eq!(evidence.journals.len(), 1);
            assert!(
                driver.execute_worker("worker", &active_policy).is_err(),
                "replayed worker"
            );
            assert!(!cancellation.is_cancelled());
        } else {
            assert!(result.is_err(), "accepted {case}");
            if case == "worker-uncertain" {
                assert!(cancellation.is_cancelled());
                assert!(driver.outcome.assignment_failed);
                assert!(driver.outcome.external_containment_failed);
            }
        }
    }
    let expected = if matches!(case, "happy" | "worker-uncertain") {
        vec!["parent", "worker"]
    } else {
        vec!["parent"]
    };
    assert_eq!(
        *calls.lock().unwrap(),
        expected,
        "unexpected dispatch for {case}"
    );
    assert_eq!(manager.list_managed_verified()?.len(), 1);
    manager.verify_write_execution_lease(
        &parent.id,
        preflight.worktree_write_lease.as_ref().unwrap(),
    )?;
    if !matches!(case, "claim-revoked" | "yield-revoked") {
        assert_eq!(sync_store.snapshot()?, vec![claim.clone()]);
    }
    assert_eq!(ledger.report()?.active_reservations, 0);
    assert_eq!(
        context
            .budget_policy
            .selected_runtime_for(AgentRole::Worker),
        None
    );
    Ok(())
}

#[test]
fn nested_driver_serial_handoff_uses_current_policy_and_retains_parent_resources() -> Result<()> {
    driver_fixture("happy")
}

#[test]
fn nested_driver_refuses_unverified_or_substituted_parent_completion() -> Result<()> {
    for case in [
        "parent-uncertain",
        "parent-unconfined",
        "parent-never-started",
        "parent-failed",
        "parent-wrong-worktree",
        "parent-restored",
        "parent-wrong-id",
        "parent-wrong-attempt",
        "cancelled-before",
    ] {
        driver_fixture(case)?;
    }
    Ok(())
}

#[test]
fn nested_driver_refuses_ambiguous_parent_external_side_effect() -> Result<()> {
    driver_fixture("parent-external-side-effect-ambiguous")
}

#[test]
fn nested_driver_refuses_completed_parent_external_side_effect() -> Result<()> {
    driver_fixture("parent-external-side-effect-completed")
}

#[test]
fn nested_driver_revalidates_authority_cancellation_and_current_policy_before_worker() -> Result<()>
{
    for case in [
        "cancelled-after",
        "claim-revoked",
        "current-runtime-refused",
        "unknown-worker",
    ] {
        driver_fixture(case)?;
    }
    Ok(())
}

#[test]
fn nested_driver_uncertain_worker_cancels_parent_continuation() -> Result<()> {
    driver_fixture("worker-uncertain")
}

#[test]
fn parent_turn_yield_validates_held_capture_without_executing_workers() -> Result<()> {
    driver_fixture("yield-happy")?;
    driver_fixture("yield-forged-capture")
}

#[test]
fn parent_turn_yield_refuses_nonquiescent_restored_or_revoked_parent() -> Result<()> {
    for case in [
        "yield-nonquiescent",
        "yield-restored",
        "yield-revoked",
        "yield-cancelled",
        "yield-blocked",
        "yield-side-effects",
        "yield-side-effects-completed",
    ] {
        driver_fixture(case).with_context(|| format!("parent-turn yield fixture case: {case}"))?;
    }
    Ok(())
}
