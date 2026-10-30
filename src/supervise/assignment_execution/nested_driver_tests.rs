use super::*;
use crate::supervise::messaging_bridge::{
    with_supervisor_messaging_session,
    worker_requests::{
        frozen::{WorkerInboxEndpoint, WorkerInboxResources, WorkerInboxTurn},
        WorkerRequestInbox,
    },
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

// The Grok fixture's binary override is scoped to the fixture and restored even
// on assertion failure. Its exact native tests run serially in this module.
static GROK_BINARY_ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

const INVALID_CONTINUATION_CASES: [&str; 8] = [
    "continuation-missing",
    "continuation-duplicate",
    "continuation-forged-id",
    "continuation-forged-summary",
    "continuation-wrong-attempt-artifact",
    "continuation-missing-journal",
    "continuation-restored",
    "continuation-oversize",
];

struct GrokBinaryEnvironmentGuard {
    previous: Option<std::ffi::OsString>,
}

impl GrokBinaryEnvironmentGuard {
    fn install(program: &Path) -> (std::sync::MutexGuard<'static, ()>, Self) {
        let lock = GROK_BINARY_ENVIRONMENT_LOCK
            .lock()
            .expect("lock Grok binary environment");
        let previous = std::env::var_os("MACO_GROK_BIN");
        std::env::set_var("MACO_GROK_BIN", program);
        (lock, Self { previous })
    }
}

impl Drop for GrokBinaryEnvironmentGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(previous) => std::env::set_var("MACO_GROK_BIN", previous),
            None => std::env::remove_var("MACO_GROK_BIN"),
        }
    }
}

// Real managed resources and the existing prepare/collect boundary, with an
// injected deterministic runner. No provider process or native subagent runs.
pub(super) fn driver_fixture(case: &str) -> Result<()> {
    let attached_capture = matches!(
        case,
        "attached-capture-success"
            | "attached-capture-panic"
            | "attached-capture-unquiescent"
            | "attached-capture-errors"
    );
    let bound_parent = case.starts_with("bound-");
    let unbound_parent = !case.starts_with("managed-cycle-") && !attached_capture && !bound_parent;
    let _cam_authority = (attached_capture || bound_parent || unbound_parent).then(|| {
        crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard::install(
            None,
        )
    });
    let isolated = case.starts_with("managed-cycle-isolated-");
    let grok_continuation = case == "continuation-grok-happy";
    let temp = tempfile::tempdir()?;
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main")?;
    fs::create_dir(repo.join("src"))?;
    fs::write(repo.join("src/lib.rs"), "pub fn selected() {}\n")?;
    if isolated {
        fs::write(repo.join("src/other.rs"), "pub fn other() {}\n")?;
    }
    let git = crate::git_repository::open(&repo)?;
    if case.starts_with("managed-cycle-") {
        let mut config = git.config()?;
        config.set_str("user.name", "Fixture Owner")?;
        config.set_str("user.email", "fixture@example.invalid")?;
    }
    let mut index = git.index()?;
    index.add_path(Path::new("src/lib.rs"))?;
    if isolated {
        index.add_path(Path::new("src/other.rs"))?;
    }
    index.write()?;
    let tree = git.find_tree(index.write_tree()?)?;
    let signature = git2::Signature::now("test", "test@example.invalid")?;
    git.commit(Some("HEAD"), &signature, &signature, "base", &tree, &[])?;
    let protected_index = fs::read(git.path().join("index"))?;
    let mut parent: OrchestratorAssignment = serde_json::from_value(json!({
        "id":"parent", "phase":"execution", "role":"child_orchestrator",
        "assigned_paths":["src"], "task":"parent task",
        "worker_assignments":[{"id":"worker", "role":"worker",
            "assigned_paths":["src/lib.rs"], "task":"worker task", "report_path":"worker.json"}]
    }))?;
    if case.starts_with("continuation-")
        || case.starts_with("bound-")
        || case.starts_with("managed-cycle-")
    {
        let mut second = parent.worker_assignments[0].clone();
        second.id = "worker-two".into();
        second.report_path = Some("worker-two.json".into());
        if isolated {
            second.assigned_paths = vec!["src/other.rs".into()];
        }
        parent.worker_assignments.push(second);
    }
    let worker: OrchestratorAssignment = serde_json::from_value(json!({
        "id":"worker", "phase":"execution", "role":"worker",
        "assigned_paths":["src/lib.rs"], "task":"worker task", "worker_assignments":[]
    }))?;
    let mut worker_two = worker.clone();
    worker_two.id = "worker-two".into();
    if isolated {
        worker_two.assigned_paths = vec!["src/other.rs".into()];
    }
    let mut plan: SupervisorPlan = serde_json::from_value(json!({
        "version":SUPERVISOR_SCHEMA_VERSION, "task":"nested driver fixture",
        "max_depth":2, "max_child_assignments": if case.starts_with("managed-cycle-") { 2 } else { 1 }, "max_child_retries":0,
        "max_gate_corrections":0, "child_timeout_seconds":10,
        "semantic_coordination":"off", "assignments":[parent],
        "role_models":{
            "child_orchestrator":{"model":"gpt-6.1-sol", "reasoning_effort":"high"},
            "worker":{"model":"gpt-6.1-sol", "reasoning_effort": if case.starts_with("managed-cycle-") { "xhigh" } else { "high" }},
            "auditor":{"model":"gpt-6.1-sol", "reasoning_effort":"high"}
        }
    }))?;
    let run_id =
        if case.starts_with("managed-cycle-") || attached_capture || bound_parent || unbound_parent
        {
            RunId::new(format!(
                "nested-driver-test-{}",
                crate::artifacts::state_auth::random_identifier()?
            ))?
        } else {
            RunId::new("nested-driver-test")?
        };
    #[cfg(target_os = "linux")]
    if case.starts_with("managed-cycle-") || attached_capture || bound_parent || unbound_parent {
        crate::account_authority::record_observed_codex_selection(
            Some(run_id.as_str()),
            crate::account_authority::CODEX_CLI_PROVIDER_ID,
            Some("nested-driver-fixture-authority".into()),
            Some(
                &coding_agent_manager_lib::account_authority::SelectedAccountBinding {
                    provider_id: crate::account_authority::CODEX_CLI_PROVIDER_ID.into(),
                    account_id: "nested-driver-fixture-account".into(),
                    account_incarnation: "nested-driver-fixture-incarnation".into(),
                    selection_revision: 1,
                },
            ),
        );
    }
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
    let preflight = AssignmentExecutionPreflight {
        nested_turn_issued: AtomicBool::new(false),
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
    let grok_program = temp.path().join("pinned-grok");
    let (_grok_environment_lock, _grok_environment_guard) = if grok_continuation {
        fs::write(&grok_program, "#!/bin/sh\nexit 99\n")?;
        #[cfg(unix)]
        fs::set_permissions(&grok_program, fs::Permissions::from_mode(0o755))?;
        let (lock, guard) = GrokBinaryEnvironmentGuard::install(&grok_program);
        (Some(lock), Some(guard))
    } else {
        (None, None)
    };
    if grok_continuation {
        crate::account_authority::admit_grok_run_account_binding(
            run_id.as_str(),
            Some(crate::account_authority::FrozenGrokSelectedBinding {
                authority_socket: None,
                authority_id: Some("nested-grok-authority".into()),
                provider_id: crate::account_authority::GROK_CLI_PROVIDER_ID.into(),
                account_id: "nested-grok-account".into(),
                account_incarnation: "nested-grok-incarnation".into(),
                selection_revision: 1,
            }),
        );
    }
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
    let ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
    let metadata = AssignmentMetadata::new();
    let consultant = SupervisorConsultantPlan::default();
    // Only this case exercises completion-checkpoint failure. Bind the existing
    // authenticated writer before preparation creates non-resumable scratches.
    let mut checkpoint = if case == "managed-cycle-retained-checkpoint-error" {
        Some(SupervisorCheckpointWriter::create(
            &repo,
            SupervisorCheckpointPreparation::new(
                &run_id,
                &current_head_oid(&repo)?,
                normalized_supervisor_plan_sha256(
                    &plan,
                    &consultant,
                    &metadata,
                    &SupervisorPlanMetadata {
                        assignment_schedule: schedule.clone(),
                        ..Default::default()
                    },
                )?,
                1,
                &plan,
                writer.resume_binding()?,
                ledger.report()?,
            ),
        )?)
    } else {
        None
    };
    let mut journal = initialize_orchestration_event_journal(&repo, &run_id, None);
    let mut kpis = AutonomyKpiCollector::default();
    let artifacts = Mutex::new(SharedSupervisorArtifacts {
        writer: &mut writer,
        journal: &mut journal,
        autonomy_kpis: &mut kpis,
        checkpoint: checkpoint.as_mut(),
    });
    if case == "managed-cycle-retained-checkpoint-error" {
        record_assignment_started_checkpoint(&artifacts, &parent, 0, &ledger)?;
    }
    let budget_config = SupervisorBudgetConfig {
        role_token_reservations: BTreeMap::from([
            (AgentRole::ChildOrchestrator, 2),
            (AgentRole::Worker, 2),
        ]),
        ..Default::default()
    };
    let guide = SupervisorFieldGuidePrompt::empty()?;
    let catalog =
        RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(["gpt-6.1-sol"])?);
    // This fixture exercises the actual loaded selector and controller path.
    // Its policy preferences are test inputs, not product effort defaults.
    let _routing_policy = if isolated {
        use crate::selection::routing_policy::{bind_routing_policy, load_routing_policy};
        let mut frozen = load_routing_policy(&repo)?;
        frozen.policy.objective.effort_distance_weight = 1_000_000_000_000;
        let mut worker_preference = frozen.policy.default_role.clone();
        worker_preference.preferred_effort = Some(crate::selection::ReasoningEffort::Xhigh);
        frozen
            .policy
            .role_preferences
            .insert("worker".into(), worker_preference);
        let mut parent_preference = frozen.policy.default_role.clone();
        parent_preference.preferred_effort = Some(crate::selection::ReasoningEffort::High);
        frozen
            .policy
            .role_preferences
            .insert("child_orchestrator".into(), parent_preference);
        frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        // The parent coordinates these authored terminal Workers; it is not a
        // third independent task, and their disjoint scopes remain separate.
        let assignments = plan
            .assignments
            .iter()
            .flat_map(|parent| {
                parent.worker_assignments.iter().map(move |worker| {
                    Ok(crate::planning::TaskAssignmentProposal {
                        id: worker.id.clone(),
                        task: worker
                            .task
                            .clone()
                            .context("isolated fixture requires its authored Worker task")?,
                        fragment_ids: vec![worker.id.clone()],
                        assigned_paths: worker.assigned_paths.clone(),
                        semantic_symbols: worker.semantic_symbols.clone(),
                        semantic_modules: worker.semantic_modules.clone(),
                        decision_dependencies: parent
                            .decision_refs
                            .iter()
                            .map(|reference| reference.question_key().to_owned())
                            .collect(),
                    })
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let disjointness = crate::planning::task_assignment_disjointness(&assignments)?;
        let proposal = crate::planning::TaskDecompositionProposal {
            fragments: assignments
                .iter()
                .map(|assignment| crate::planning::TaskSpecFragment {
                    id: assignment.id.clone(),
                    text: assignment.task.clone(),
                })
                .collect(),
            assignments,
            coverage_gaps: Vec::new(),
            diagnostics: Default::default(),
            disjointness,
        };
        let assessment =
            super::super::task_routing::assess_task_routing(&plan.task, &proposal, &frozen)?;
        let guard = bind_routing_policy(Some(frozen))?;
        plan.role_models.clear();
        let admission = SupervisorAdmissionPolicyInput::resolve_with_quota(
            &repo,
            2,
            SupervisorAdmissionConfig::default(),
            options.admission_overrides,
            None,
        )?;
        let selected =
            super::super::selection_bridge::initialize_supervisor_selection_with_assessment(
                &mut plan,
                SupervisorRuntime::Codex,
                &catalog,
                &admission,
                &super::super::selection_bridge::AdvertisedCatalogSet::empty(),
                Some(&crate::objective_profile::default_resolved_objective_profile()?),
                super::super::selection_bridge::SupervisorQuotaSelectionInput::default(),
                None,
                &[],
                Some(&assessment),
            )?;
        assert!(
            selected.selection_preflight_failure.is_none(),
            "fixture selector refused: {:?}",
            selected.selection_preflight_failure
        );
        Some(guard)
    } else {
        None
    };
    let parent_running = AtomicBool::new(false);
    let calls = Mutex::new(Vec::new());
    let managed_parent_turns = AtomicUsize::new(0);
    let captured_worker_reports = Mutex::new(Vec::<WorkerReport>::new());
    let captured_worker_claims = Mutex::new(Vec::new());
    let overlapping_workers = (
        Mutex::new(Vec::<(
            String,
            PathBuf,
            std::time::Instant,
            Option<std::time::Instant>,
        )>::new()),
        std::sync::Condvar::new(),
    );
    let runner = |command: &ExternalAgentCommand,
                  runner_cancellation: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>| {
        let subject = if command.agent_lifecycle.as_ref().unwrap().task_id == "parent" {
            assert!(!parent_running.swap(true, Ordering::SeqCst));
            &parent
        } else {
            let identity = command.agent_lifecycle.as_ref().unwrap();
            let subject = if identity.task_id == "worker-two" {
                &worker_two
            } else {
                &worker
            };
            assert!(
                !parent_running.load(Ordering::SeqCst),
                "overlapping parent and worker"
            );
            assert_eq!(command.reasoning_effort.as_deref(), Some("xhigh"));
            if isolated {
                let launch = command
                    .assignment_messaging_launch()
                    .expect("worker assignment messaging launch");
                assert_eq!(identity.run_id, run_id.as_str());
                assert_eq!(identity.task_id, subject.id);
                assert!(launch.environment_for(run_id.as_str(), &subject.id).is_ok());
                assert!(launch.environment_for("foreign-run", &subject.id).is_err());
                assert!(launch.environment_for(run_id.as_str(), &parent.id).is_err());
                assert!(command
                    .verify_assignment_messaging_protocol_instructions()
                    .is_ok());
                assert!(!command.codex_managed_worker_requests_enabled());
                assert!(!command.codex_managed_readonly_continuation_enabled());
            } else {
                assert!(command.assignment_messaging_launch().is_none());
            }
            subject
        };
        calls.lock().unwrap().push(subject.id.clone());
        if attached_capture || ((bound_parent || unbound_parent) && subject.id == "parent") {
            let identity = command.agent_lifecycle.as_ref().unwrap();
            assert_eq!(identity.run_id, run_id.as_str());
            assert_eq!(identity.task_id, parent.id);
            assert_eq!(identity.role, "child_orchestrator");
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
            assert!(command.codex_native_delegation_is_disabled());
            assert!(command.codex_managed_worker_requests_enabled());
            assert!(!command.codex_managed_readonly_continuation_enabled());
            assert!(command.worker_journal_artifacts.is_empty());
            let launch = command
                .assignment_messaging_launch()
                .expect("attached managed parent inbox launch");
            assert!(launch.environment_for(run_id.as_str(), &parent.id).is_ok());
            assert!(launch.environment_for("foreign-run", &parent.id).is_err());
            assert!(launch.environment_for(run_id.as_str(), &worker.id).is_err());
            command
                .verify_assignment_messaging_protocol_instructions()
                .expect("attached managed parent inbox protocol instructions");
        }
        if case == "attached-capture-panic" && subject.id == "parent" {
            panic!("attached parent runner panicked");
        }
        let launch_claim = if isolated && subject.id != "parent" {
            assert_ne!(
                command.cwd, worktree.path,
                "isolated worker borrowed parent worktree"
            );
            let claims = sync_store.snapshot().unwrap();
            assert!(
                claims.contains(&claim),
                "parent union authority was released"
            );
            let child = claims
                .into_iter()
                .find(|entry| entry.agent_id == subject.id)
                .unwrap();
            assert_eq!(child.paths, subject.assigned_paths);
            captured_worker_claims.lock().unwrap().push(child.clone());
            let (lock, ready) = &overlapping_workers;
            let mut live = lock.lock().unwrap();
            live.push((
                subject.id.clone(),
                command.cwd.clone(),
                std::time::Instant::now(),
                None,
            ));
            ready.notify_all();
            let (live, deadline) = ready
                .wait_timeout_while(live, Duration::from_secs(5), |live| live.len() < 2)
                .unwrap();
            assert!(
                !deadline.timed_out(),
                "workers did not overlap within the bounded fixture wait"
            );
            assert_ne!(live[0].1, live[1].1, "workers share one worktree lease");
            drop(live);
            // Recheck the held read-only source while both workers are alive.
            assert_eq!(
                fs::read_to_string(worktree.path.join("src/lib.rs")).unwrap(),
                "pub fn selected() {}\n"
            );
            if case == "managed-cycle-isolated-cancel-both" {
                runner_cancellation.cancel();
            }
            child
        } else {
            assert_eq!(command.cwd, worktree.path);
            if isolated
                && subject.id == "parent"
                && command.codex_managed_readonly_continuation_enabled()
            {
                let children = captured_worker_claims.lock().unwrap().clone();
                assert!(
                    children.len() == parent.worker_assignments.len(),
                    "isolated final parent requires every captured worker claim"
                );
                let mut expected = vec![claim.clone()];
                expected.extend(children);
                expected.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
                let mut observed = sync_store.snapshot().unwrap();
                observed.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
                assert!(
                    observed == expected,
                    "isolated final parent lost the exact held claim set"
                );
            } else {
                assert!(
                    sync_store.snapshot().unwrap() == vec![claim.clone()],
                    "initial parent or serial runner lost the exact parent claim"
                );
            }
            claim.clone()
        };
        let mut simulated = command.clone();
        simulated.model = None;
        let mut fake_subject = subject.clone();
        if (case.starts_with("managed-cycle-")
            || attached_capture
            || bound_parent
            || unbound_parent)
            && subject.id == "parent"
        {
            fake_subject.worker_assignments.clear();
        }
        if case.starts_with("managed-cycle-") && subject.id != "parent" {
            assert_eq!(
                command.workspace_access,
                WorkspaceAccess::ReadWrite,
                "managed-cycle worker launch must be read-write"
            );
            assert_eq!(
                command.writable_launch_target,
                crate::runtime_adapter::WritableLaunchTarget::ManagedChildWorktree,
                "managed-cycle worker launch must target the managed child worktree"
            );
            crate::external_agent::prepare_managed_child_git_boundary_for_test(&command.cwd)
                .expect(
                    "managed-cycle worker fixture failed to prepare the private child Git boundary",
                );
        }
        let mut run = deterministic_fake_child_run(
            &simulated,
            &fake_subject,
            &metadata,
            launch_claim.token.get(),
            None,
        )
        .unwrap();
        let preserved_journals = run.worker_journal_artifacts().to_vec();
        if case == "attached-capture-success"
            || case == "attached-capture-errors"
            || case.starts_with("managed-cycle-")
            || (bound_parent && subject.id == "parent")
        {
            run.stdout = crate::external_agent::CapturedOutput::from_captured_bytes_for_test(
                &crate::process_runner::CapturedBytes::from_bytes_for_test(
                    b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":10,\"output_tokens\":4}}\n"
                        .to_vec(),
                ),
            );
        }
        run.stdout.target_launch_attempted = true;
        if case.starts_with("managed-cycle-") {
            run.replace_worker_journal_artifacts(preserved_journals);
        }
        run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            crate::process_runner::ContainmentBackend::SystemdUserService,
        ));
        let grok_worker = subject.id != "parent" && grok_continuation;
        run.side_effects = Some(SideEffectConfinementEvidence::Verified(if grok_worker {
            crate::process_runner::SideEffectConfinementProfileKind::ExternalGrok
        } else {
            crate::process_runner::SideEffectConfinementProfileKind::ExternalCodex
        }));
        run.publishable = true;
        run.program_trust = if grok_worker {
            ExternalProgramTrust::ExplicitCustom
        } else {
            ExternalProgramTrust::TrustedSystemCodex
        };
        run.codex_permissions =
            (!grok_worker).then(|| crate::external_agent::CodexPermissionEvidence {
                codex_version: "0.142.3".into(),
                minimum_version: "0.138.0".into(),
                permission_profile: "maco_external_codex".into(),
                workspace_access: command.workspace_access,
                network_enabled: false,
                argv_digest: "fixture".into(),
                executable_identity: "fixture".into(),
            });
        if subject.id == "parent" {
            if bound_parent {
                run.output_last_message = Some(
                    serde_json::to_vec(&super::bound_parent_turn_tests::yield_report(
                        run_id.as_str(),
                    ))
                    .unwrap(),
                );
            }
            if case.starts_with("yield-") || case.starts_with("continuation-") {
                let mut report = json!({
                    "version":1, "outcome":"yield_workers", "run_id":run_id.as_str(),
                    "parent_id":"parent", "parent_attempt":1,
                    "requests":[{"request_id":"request-1", "worker_id":"worker"}]
                });
                if case.starts_with("continuation-") {
                    report["requests"] = json!([
                        {"request_id":"request-2", "worker_id":"worker-two"},
                        {"request_id":"request-1", "worker_id":"worker"}
                    ]);
                }
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
            if case.starts_with("managed-cycle-") {
                assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
                assert!(command.codex_native_delegation_is_disabled());
                assert_eq!(
                    command
                        .agent_lifecycle
                        .as_ref()
                        .map(|identity| identity.role.as_str()),
                    Some("child_orchestrator")
                );
                let turn = managed_parent_turns.fetch_add(1, Ordering::SeqCst) + 1;
                if turn == 1 {
                    assert!(command.codex_managed_worker_requests_enabled());
                    let launch = command
                        .assignment_messaging_launch()
                        .expect("managed parent inbox launch");
                    if case == "managed-cycle-lost-reply" {
                        super::managed_parent_controller_tests::submit_worker_request(
                            launch,
                            run_id.as_str(),
                            "r1",
                            "worker",
                            false,
                        )
                        .unwrap();
                    }
                    if case != "managed-cycle-foreign-yield" {
                        super::managed_parent_controller_tests::submit_worker_request(
                            launch,
                            run_id.as_str(),
                            "r1",
                            "worker",
                            true,
                        )
                        .unwrap();
                        super::managed_parent_controller_tests::submit_worker_request(
                            launch,
                            run_id.as_str(),
                            "r2",
                            "worker-two",
                            true,
                        )
                        .unwrap();
                    }
                    let requests = if case == "managed-cycle-foreign-yield" {
                        json!([{"request_id":"unacked-foreign","worker_id":"worker"}])
                    } else {
                        json!([
                            {"request_id":"r1","worker_id":"worker"},
                            {"request_id":"r2","worker_id":"worker-two"}
                        ])
                    };
                    run.output_last_message = Some(
                        serde_json::to_vec(&json!({
                            "version":1, "outcome":"yield_workers",
                            "run_id":run_id.as_str(), "parent_id":"parent", "parent_attempt":1,
                            "requests": requests
                        }))
                        .unwrap(),
                    );
                } else {
                    if case == "managed-cycle-isolated-final-panic" {
                        panic!("injected unknown final runner result");
                    }
                    assert!(command.assignment_messaging_launch().is_none());
                    assert!(command.codex_managed_readonly_continuation_enabled());
                    assert!(!command.codex_managed_worker_requests_enabled());
                    let mut reports = captured_worker_reports.lock().unwrap().clone();
                    if isolated {
                        reports.sort_by_key(|report| {
                            parent
                                .worker_assignments
                                .iter()
                                .position(|worker| worker.id == report.id)
                                .unwrap()
                        });
                    }
                    let completed_worker_ids: Vec<_> =
                        reports.iter().map(|report| report.id.clone()).collect();
                    let mut report: OrchestratorReviewReport =
                        serde_json::from_slice(run.output_last_message().unwrap()).unwrap();
                    report.worker_reports = reports;
                    report.files_changed = if isolated {
                        vec!["src/lib.rs".into(), "src/other.rs".into()]
                    } else {
                        vec!["src/lib.rs".into()]
                    };
                    report.audit_reports.clear();
                    report.review_lens_aggregate = None;
                    if case == "managed-cycle-final-forgery"
                        || case == "managed-cycle-isolated-final-forgery"
                    {
                        report.worker_reports[0].id = "forged".into();
                    }
                    run.output_last_message = Some(
                        serde_json::to_vec(&json!({
                            "version":1,
                            "run_id":run_id.as_str(),
                            "parent_id":"parent",
                            "source_parent_attempt":1,
                            "parent_attempt":2,
                            "completed_worker_ids": completed_worker_ids,
                            "turn": {"outcome":"final_report", "report": report}
                        }))
                        .unwrap(),
                    );
                    if case == "managed-cycle-isolated-final-malformed" {
                        run.output_last_message = Some(b"{invalid final".to_vec());
                    }
                    if case == "managed-cycle-isolated-final-unknown-containment" {
                        run.process_tree = None;
                    }
                }
            }
            parent_running.store(false, Ordering::SeqCst);
        } else if case == "worker-uncertain" {
            run.process_tree = None;
        } else if case.starts_with("bound-evidence-") {
            match case {
                "bound-evidence-edits" | "bound-evidence-second-failure"
                    if case == "bound-evidence-edits" || subject.id == "worker-two" =>
                {
                    fs::write(
                        command.cwd.join("src/lib.rs"),
                        format!("// written by {}\n", subject.id),
                    )
                    .unwrap();
                    let mut report: WorkerReport =
                        serde_json::from_slice(run.output_last_message().unwrap()).unwrap();
                    report.files_changed = vec!["src/lib.rs".into()];
                    report.commands_run = vec![serde_json::from_value(json!({
                        "command":["fixture-edit"], "cwd":command.cwd, "exit_code":0,
                        "status":"succeeded", "timeout_seconds":1, "duration_ms":1, "timed_out":false
                    })).unwrap()];
                    run.output_last_message = Some(serde_json::to_vec(&report).unwrap());
                    let mut captures = run.worker_journal_artifacts().to_vec();
                    captures[0].status = crate::external_agent::WorkerJournalArtifactCaptureStatus::Loaded(
                        serde_json::to_vec(&json!({"command":["fixture-edit"], "cwd":command.cwd,
                            "start_timestamp":"fixture-start", "end_timestamp":"fixture-end", "changed_paths":["src/lib.rs"]})).unwrap());
                    run.replace_worker_journal_artifacts(captures);
                }
                "bound-evidence-forged" | "bound-evidence-widened" => {
                    let mut report: WorkerReport =
                        serde_json::from_slice(run.output_last_message().unwrap()).unwrap();
                    if case == "bound-evidence-forged" {
                        report.id = "forged".into();
                    } else {
                        report.assigned_paths.push("outside".into());
                    }
                    run.output_last_message = Some(serde_json::to_vec(&report).unwrap());
                }
                "bound-evidence-failure" | "bound-evidence-second-failure" => {
                    run.exit_code = Some(1)
                }
                "bound-evidence-cancel-during" => cancellation.cancel(),
                _ => {}
            }
        } else if case.starts_with("managed-cycle-") {
            let edited_path = if isolated {
                subject.assigned_paths[0].as_path()
            } else {
                Path::new("src/lib.rs")
            };
            fs::write(
                command.cwd.join(edited_path),
                format!("// written by {}\n", subject.id),
            )
            .unwrap();
            let mut report: WorkerReport =
                serde_json::from_slice(run.output_last_message().unwrap()).unwrap();
            report.files_changed = vec![edited_path.into()];
            report.commands_run = vec![serde_json::from_value(json!({
                "command":["fixture-edit"], "cwd":command.cwd, "exit_code":0,
                "status":"succeeded", "timeout_seconds":1, "duration_ms":1, "timed_out":false
            }))
            .unwrap()];
            run.output_last_message = Some(serde_json::to_vec(&report).unwrap());
            let mut captures = run.worker_journal_artifacts().to_vec();
            captures[0].status = crate::external_agent::WorkerJournalArtifactCaptureStatus::Loaded(
                serde_json::to_vec(&json!({
                    "command":["fixture-edit"], "cwd":command.cwd,
                    "start_timestamp":"fixture-start", "end_timestamp":"fixture-end",
                    "changed_paths":[edited_path]
                }))
                .unwrap(),
            );
            run.replace_worker_journal_artifacts(captures);
            if case == "managed-cycle-isolated-seal-rejection" && subject.id == "worker" {
                report.assigned_paths.push("outside-authority".into());
                run.output_last_message = Some(serde_json::to_vec(&report).unwrap());
            }
            if case == "managed-cycle-isolated-unknown-containment" && subject.id == "worker" {
                run.process_tree = None;
            }
            captured_worker_reports.lock().unwrap().push(report);
            if case == "managed-cycle-cancel-after-first" && subject.id == "worker" {
                cancellation.cancel();
            }
            if isolated {
                let mut live = overlapping_workers.0.lock().unwrap();
                live.iter_mut()
                    .find(|entry| entry.0 == subject.id)
                    .unwrap()
                    .3 = Some(std::time::Instant::now());
            }
        }
        if subject.id == "parent" && case == "attached-capture-errors" {
            sync_store.release(claim.token).unwrap();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = artifacts.lock().unwrap();
                panic!("poison supervisor artifacts");
            }));
        }
        if subject.id == "parent" && case == "attached-capture-unquiescent" {
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
        worktree_creation: if isolated {
            SupervisorWorktreeCreation::VerifiedTestOnly
        } else {
            SupervisorWorktreeCreation::ExistingOnly
        },
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
        budget_policy: {
            let mut policy = AssignmentBudgetPolicy::default();
            policy.worker_dispatch_limit = if isolated { 2 } else { 1 };
            policy
        },
        admission_commit: None,
        runtime_model_catalog: &catalog,
        cancellation: cancellation.clone(),
        external_runner: &runner,
    };
    // Keep the real initial-parent endpoint owner alive through collected-turn
    // handoff; a matching launch value alone does not own its journal or service.
    let unbound_binding = if unbound_parent {
        Some(with_supervisor_messaging_session(&run_dir, |factory| {
            factory.worker_request_binding(&run_id, &parent, 1, "generation")
        })?)
    } else {
        None
    };
    let unbound_turn = unbound_binding
        .as_ref()
        .map(|binding| {
            WorkerInboxTurn::new(
                binding.clone(),
                1,
                WorkerInboxResources {
                    repo: &repo,
                    parent: &preflight.assignment,
                    lease: preflight.worktree_write_lease.as_ref().unwrap(),
                    claim: &preflight.claim,
                    claims: &sync_store,
                },
            )
        })
        .transpose()?;
    let unbound_endpoint = unbound_turn
        .as_ref()
        .map(|turn| {
            WorkerInboxEndpoint::start(
                &run_dir,
                turn,
                WorkerRequestInbox::create(
                    crate::artifacts::repository_authenticator_key_only(&repo)?,
                    unbound_binding
                        .as_ref()
                        .context("unbound parent lost its fresh inbox binding")?
                        .clone(),
                )?,
                cancellation.clone(),
            )
        })
        .transpose()?;
    let unbound_launch = unbound_endpoint.as_ref().map(WorkerInboxEndpoint::launch);
    let mut outcome = AssignmentExecutionOutcome::default();
    ISOLATED_TEST_REFUSE_SPAWN.with(|flag| flag.set(case == "managed-cycle-isolated-unstarted"));
    let Some(mut collected) = prepare_and_collect_fixture_parent(
        case,
        &context,
        &preflight,
        &mut outcome,
        &calls,
        unbound_launch.as_ref(),
    )?
    else {
        if isolated {
            assert_eq!(
                fs::read(git.path().join("index"))?,
                protected_index,
                "protected primary index bytes changed"
            );
        }
        if isolated && case != "managed-cycle-isolated-unstarted" {
            let live = overlapping_workers.0.lock().unwrap();
            assert_eq!(live.len(), 2);
            let latest_start = live.iter().map(|entry| entry.2).max().unwrap();
            let first_finish = live
                .iter()
                .map(|entry| entry.3.expect("worker returned"))
                .min()
                .unwrap();
            assert!(
                latest_start < first_finish,
                "independent leased workers had no overlapping live interval"
            );
            assert_ne!(live[0].1, live[1].1);
            assert!(live.iter().all(|entry| entry.1 != worktree.path));
        }
        return Ok(());
    };
    assert_eq!(*calls.lock().unwrap(), ["parent"]);
    if case.starts_with("permit-") {
        match case {
            "permit-failed-issue" => {
                assert!(preflight.issue_nested_turn(0).is_err());
            }
            "permit-failed-construction" => {
                let evidence = collected.external_run.process_tree.take();
                assert!(NestedWorkerSerialDriver::from_collected_parent(
                    &context,
                    &preflight,
                    &mut outcome,
                    1,
                    &collected,
                )
                .is_err());
                collected.external_run.process_tree = evidence;
            }
            "permit-drop" => {
                drop(NestedWorkerSerialDriver::from_collected_parent(
                    &context,
                    &preflight,
                    &mut outcome,
                    1,
                    &collected,
                )?);
            }
            "permit-race" => {
                let barrier = std::sync::Barrier::new(2);
                std::thread::scope(|scope| {
                    let construct = || {
                        let mut independent_outcome = AssignmentExecutionOutcome::default();
                        barrier.wait();
                        let result = NestedWorkerSerialDriver::from_collected_parent(
                            &context,
                            &preflight,
                            &mut independent_outcome,
                            1,
                            &collected,
                        );
                        // Hold the successful driver until both constructors return.
                        barrier.wait();
                        result.is_ok()
                    };
                    let first = scope.spawn(construct);
                    let second = scope.spawn(construct);
                    assert_eq!(
                        usize::from(first.join().unwrap()) + usize::from(second.join().unwrap()),
                        1
                    );
                });
            }
            _ => bail!("unknown permit case {case}"),
        }
        for attempt in [1, 2] {
            let mut different_outcome = AssignmentExecutionOutcome::default();
            let error = NestedWorkerSerialDriver::from_collected_parent(
                &context,
                &preflight,
                &mut different_outcome,
                attempt,
                &collected,
            )
            .err()
            .context("nested permit was reissued")?;
            assert!(error.to_string().contains("already been issued"));
        }
        assert_eq!(*calls.lock().unwrap(), ["parent"]);
        assert_eq!(sync_store.snapshot()?, vec![claim.clone()]);
        assert_eq!(ledger.report()?.active_reservations, 0);
        return Ok(());
    }
    if case.starts_with("continuation-") {
        return exercise_fixture_continuation(
            case,
            &context,
            &preflight,
            &mut outcome,
            &collected,
            &calls,
        );
    }
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
        &preflight,
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
            "cancelled-before" | "yield-nonquiescent" | "yield-restored" | "yield-side-effects"
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
                model: Some("gpt-6.1-sol".into()),
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
            assert_eq!(evidence.report().id, "worker");
            assert_eq!(evidence.journals().len(), 1);
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

// Keep preparation and dispatch values out of the shared setup/case frame.
#[inline(never)]
fn prepare_and_collect_fixture_parent<'a>(
    case: &str,
    context: &AssignmentExecutionContext<'a, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    calls: &Mutex<Vec<String>>,
    unbound_launch: Option<&crate::messaging::transport::AssignmentMessagingLaunch>,
) -> Result<Option<Box<CollectedChildAttempt<'a>>>> {
    let run_id = &context.options.run_id;
    let dirs = context.dirs;
    if case.starts_with("managed-cycle-")
        || case.starts_with("attached-capture-")
        || case.starts_with("bound-")
    {
        let prepared = match prepare_managed_parent_initial_attempt(
            context,
            outcome,
            &context.budget_policy,
            preflight,
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
                bail!("managed parent preparation unexpectedly completed")
            }
        };
        if case.starts_with("bound-") {
            super::bound_parent_turn_tests::exercise(case, context, preflight, outcome, prepared)?;
            let expected = match case {
                "bound-shared-driver"
                | "bound-evidence-happy"
                | "bound-evidence-edits"
                | "bound-evidence-candidate-after"
                | "bound-evidence-cancel-after"
                | "bound-evidence-second-failure"
                | "bound-evidence-claim-revoked" => vec!["parent", "worker-two", "worker"],
                "bound-evidence-forged"
                | "bound-evidence-widened"
                | "bound-evidence-failure"
                | "bound-evidence-cancel-during" => vec!["parent", "worker-two"],
                case if case.starts_with("bound-evidence-handoff-") => vec!["parent", "worker-two"],
                _ => vec!["parent"],
            };
            assert_eq!(*calls.lock().unwrap(), expected);
            context.manager.verify_write_execution_lease(
                &preflight.assignment.id,
                preflight.worktree_write_lease.as_ref().unwrap(),
            )?;
            assert_eq!(context.manager.list_managed_verified()?.len(), 1);
            assert_eq!(context.budget_ledger.report()?.active_reservations, 0);
            return Ok(None);
        }
        if case.starts_with("attached-capture-") {
            let result = super::attached_parent_capture_tests::exercise(
                case, context, preflight, outcome, prepared,
            );
            assert_eq!(*calls.lock().unwrap(), ["parent"]);
            result?;
            return Ok(None);
        }
        super::managed_parent_controller_tests::exercise(
            case, context, preflight, outcome, prepared, calls,
        )?;
        return Ok(None);
    }
    let mut prepared = match prepare_managed_parent_initial_attempt(
        context,
        outcome,
        &context.budget_policy,
        preflight,
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
    let launch = unbound_launch.context("unbound parent requires its held fresh inbox endpoint")?;
    prepared.command = prepared
        .command
        .clone()
        .with_assignment_messaging(launch.clone());
    prepared
        .command
        .verify_assignment_messaging_protocol_instructions()?;
    assert_eq!(prepared.command.assignment_messaging_launch(), Some(launch));
    prepared.command_admission = Some(
        super::managed_parent_controller::admit_attached_parent_initial_for_test(
            context, preflight, &prepared,
        )?,
    );
    let collected = dispatch_and_collect_child_attempt(
        context,
        outcome,
        preflight,
        run_id.as_str(),
        1,
        prepared,
    )?;
    Ok(Some(Box::new(collected)))
}

// Continuation-only temporaries must not overlap initial parent preparation.
#[inline(never)]
fn exercise_fixture_continuation(
    case: &str,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    collected: &CollectedChildAttempt<'_>,
    calls: &Mutex<Vec<String>>,
) -> Result<()> {
    let run_id = &context.options.run_id;
    let dirs = context.dirs;
    let worktree = &preflight.worktree;
    let sync_store = context.sync_store;
    let claim = &preflight.claim;
    let ledger = context.budget_ledger;
    let cancellation = &context.cancellation;
    let grok_continuation = case == "continuation-grok-happy";
    let mut policy = context.budget_policy.clone();
    policy.set_selector_binding_for_test(
        AgentRole::Worker,
        if grok_continuation {
            SupervisorRuntime::Grok
        } else {
            SupervisorRuntime::Codex
        },
        RoleModelSelection {
            model: Some(if grok_continuation {
                "grok-4.6".into()
            } else {
                "gpt-6.1-sol".into()
            }),
            reasoning_effort: Some("xhigh".into()),
            ..Default::default()
        },
    );
    let mut driver =
        NestedWorkerSerialDriver::from_collected_parent(context, preflight, outcome, 1, collected)?;
    let expected = [
        parent_turn_yield::ExpectedWorkerRequest::new("request-2", "worker-two")?,
        parent_turn_yield::ExpectedWorkerRequest::new("request-1", "worker")?,
    ];
    let yielded = driver.validate_parent_turn_yield(&expected)?;
    // Input completion order is deliberately different from the frozen yield order.
    let mut completed = vec![
        driver.execute_worker("worker", &policy)?,
        driver.execute_worker("worker-two", &policy)?,
    ];
    drop(driver);
    if case == "continuation-invalid-results" {
        // Provision the authenticated parent and execute its two deterministic
        // Workers once. Each refusal still receives independent held evidence;
        // rebuilding the complete durable fixture eight times can spend the
        // entire test deadline in filesystem syncs on a busy host.
        let valid = ParentContinuationLaunch::from_unbound_completed_workers_for_test(
            context, preflight, &yielded, &completed,
        )?;
        assert_eq!(valid.worker_ids(), ["worker-two", "worker"]);
        drop(valid);
        for invalid_case in INVALID_CONTINUATION_CASES {
            let mut invalid = completed.clone();
            if invalid_case == "continuation-missing" {
                invalid.pop();
            } else {
                nested_worker_executor::corrupt_continuation_evidence_for_test(
                    &mut invalid,
                    invalid_case,
                    MAX_PARENT_CONTINUATION_BYTES,
                )?;
            }
            assert!(
                ParentContinuationLaunch::from_unbound_completed_workers_for_test(
                    context, preflight, &yielded, &invalid,
                )
                .is_err(),
                "accepted {invalid_case}"
            );
        }
        assert_eq!(*calls.lock().unwrap(), ["parent", "worker", "worker-two"]);
        assert_eq!(sync_store.snapshot()?, vec![claim.clone()]);
        assert_eq!(ledger.report()?.active_reservations, 0);
        return Ok(());
    }
    if case == "continuation-missing" {
        completed.pop();
    } else {
        nested_worker_executor::corrupt_continuation_evidence_for_test(
            &mut completed,
            case,
            MAX_PARENT_CONTINUATION_BYTES,
        )?;
    }
    let contract = ParentContinuationLaunch::from_unbound_completed_workers_for_test(
        context, preflight, &yielded, &completed,
    );
    if case == "continuation-missing-live-inbox-binding" {
        // The same held results pass all staged preparation checks, but
        // matching run/attempt paths do not prove state-instance/generation.
        let fixture = contract?;
        fixture.revalidate(context, preflight, 2)?;
        let error = ParentContinuationLaunch::from_completed_workers(
            context, preflight, &yielded, &completed,
        )
        .err()
        .context("constructed continuation without a live inbox binding")?;
        assert!(error.to_string().contains("construction unavailable"));
        assert!(error
            .to_string()
            .contains("state-instance and inbox-generation"));
    } else if let Some(drift) = case.strip_prefix("continuation-candidate-") {
        let mut contract = contract?;
        let candidate_git = crate::git_repository::open(&worktree.path)?;
        match drift {
            "content" => fs::write(worktree.path.join("src/lib.rs"), "changed after binding\n")?,
            "untracked" => fs::write(worktree.path.join("src/new.rs"), "new after binding\n")?,
            "index" => {
                let mut index = candidate_git.index()?;
                index.remove_path(Path::new("src/lib.rs"))?;
                index.write()?;
            }
            "head" => {
                // Keep the held metadata inode intact: test the snapshot
                // check, not the separate replaced-metadata identity gate.
                fs::write(
                    candidate_git.path().join("HEAD"),
                    format!("{}\n", candidate_git.head()?.target().unwrap()),
                )?
            }
            "uninspectable" => fs::write(candidate_git.path().join("index"), b"invalid index")?,
            "incomplete-held" => {
                contract.candidate_snapshot.inspection_error = Some("incomplete fixture".into());
            }
            _ => bail!("unknown candidate drift case {drift}"),
        }
        let error = prepare_child_attempt(
            context,
            outcome,
            &policy,
            preflight,
            run_id.as_str(),
            2,
            1,
            &None,
            &dirs.schemas.join("orchestrator-review-report.schema.json"),
            &dirs.schemas.join("worker-report.schema.json"),
            &dirs.schemas.join("auditor-report.schema.json"),
            Some(&contract),
        )
        .err()
        .with_context(|| format!("accepted candidate drift: {drift}"))?;
        assert!(
            error.to_string().contains("candidate snapshot"),
            "{error:#}"
        );
        assert!(!dirs
            .schemas
            .join("parent-continuation-2.schema.json")
            .exists());
    } else if !matches!(case, "continuation-happy" | "continuation-grok-happy") {
        assert!(contract.is_err(), "accepted {case}");
    } else {
        let contract = contract?;
        assert_eq!(contract.worker_ids(), ["worker-two", "worker"]);
        let summaries: serde_json::Value = serde_json::from_str(contract.summaries())?;
        assert_eq!(summaries[0]["worker_id"], "worker-two");
        assert_eq!(summaries[0]["request_id"], "request-2");
        assert_eq!(
            summaries[0]["worker_report"],
            serde_json::to_value(completed[1].report())?
        );
        assert!(contract.revalidate(context, preflight, 1).is_err());
        let prepared = match prepare_child_attempt(
            context,
            outcome,
            &policy,
            preflight,
            run_id.as_str(),
            2,
            1,
            &None,
            &dirs.schemas.join("orchestrator-review-report.schema.json"),
            &dirs.schemas.join("worker-report.schema.json"),
            &dirs.schemas.join("auditor-report.schema.json"),
            Some(&contract),
        )? {
            AssignmentExecutionDisposition::Continue(prepared) => prepared,
            AssignmentExecutionDisposition::Complete => {
                bail!("continuation preparation refused")
            }
        };
        assert!(!prepared.corrective_retry_used);
        assert_eq!(prepared.command.workspace_access, WorkspaceAccess::ReadOnly);
        assert!(prepared.command.worktree_control_exceptions.is_empty());
        assert!(prepared.command.cam_authority_socket_pin().is_none());
        assert!(prepared.command_admission.is_none());
        assert!(prepared.command.worker_journal_artifacts.is_empty());
        assert!(!prepared
            .incoming_scratch
            .path()
            .join("worker-journals")
            .exists());
        let prompt = fs::read_to_string(&prepared.attempt_artifacts.prompt_path)?;
        let initial = fs::read_to_string(&collected.attempt_artifacts.prompt_path)?;
        assert!(initial.contains("Source and Git are read-only"));
        assert!(initial.contains(
            "Do not use Native SubAgent, spawn_agent, a raw provider CLI, or nested MACO worker launches."
        ));
        assert!(initial.contains("maco_worker_request"));
        assert!(initial.contains("outcome=yield_workers"));
        assert!(initial.contains("request_id=r1 worker_id=worker"));
        assert!(initial.contains("request_id=r2 worker_id=worker-two"));
        assert!(!prompt.contains("Launch every supplied terminal worker"));
        assert!(prompt.contains("Native SubAgent, spawn_agent, raw CLI/provider processes and nested MACO launches are forbidden"));
        assert!(prompt.contains(contract.summaries()));
        assert!(prompt.contains("Fresh parent turn: 2"));
        assert!(prompt.contains("No Worker-journal write capability"));
        assert!(prompt.contains("Source is read-only"));
        assert!(prompt.contains("do not edit, stage, commit, reset"));
        contract.revalidate(context, preflight, 2)?;
        let schema_path = prepared.command.output_schema.as_ref().unwrap();
        assert!(schema_path.ends_with("parent-continuation-2.codex-output.schema.json"));
        let codex_schema: serde_json::Value = serde_json::from_slice(&fs::read(schema_path)?)?;
        let schema = super::super::schema_artifacts::parent_continuation_schema_value(&contract);
        assert_eq!(codex_schema["title"], "ParentContinuationTurn");
        let instance = json!({"version":1, "run_id":run_id.as_str(), "parent_id":"parent",
            "source_parent_attempt":1, "parent_attempt":2,
            "completed_worker_ids":["worker-two", "worker"],
            "turn":{"outcome":"yield_workers", "requests":[{"request_id":"next", "worker_id":"unresolved"}]}});
        for schema in [schema, codex_schema] {
            let authoritative = schema["properties"]["turn"].get("oneOf").is_some();
            let mut compiler = boon::Compiler::new();
            compiler.set_default_draft(boon::Draft::V2020_12);
            compiler
                .add_resource("urn:maco:continuation-test", schema)
                .expect("register continuation schema");
            let mut schemas = boon::Schemas::new();
            let index = compiler
                .compile("urn:maco:continuation-test", &mut schemas)
                .expect("compile continuation schema");
            schemas
                .validate(&instance, index)
                .expect("valid yield envelope");
            if authoritative {
                let mut final_turn = instance.clone();
                final_turn["turn"] =
                    json!({"outcome":"final_report", "report":collected.attempt_report});
                schemas
                    .validate(&final_turn, index)
                    .expect("valid final report envelope");
                final_turn["turn"]["requests"] = instance["turn"]["requests"].clone();
                assert!(schemas.validate(&final_turn, index).is_err());
            }
            let mut mixed = instance.clone();
            mixed["turn"]["report"] = json!({});
            assert!(schemas.validate(&mixed, index).is_err());
            mixed["turn"]["outcome"] = json!("final_report");
            assert!(schemas.validate(&mixed, index).is_err());
            for ids in [
                json!(["worker", "worker-two"]),
                json!(["worker", "worker"]),
                json!(["forged", "worker"]),
                json!(["worker"]),
            ] {
                let mut wrong = instance.clone();
                wrong["completed_worker_ids"] = ids;
                assert!(schemas.validate(&wrong, index).is_err());
            }
            assert!(schemas.validate(&instance["turn"], index).is_err());
        }
        // Preparation only: no fresh parent, IPC, collector or acceptance is invoked.
        drop(prepared);
        cancellation.cancel();
        assert!(contract.revalidate(context, preflight, 2).is_err());
    }
    assert_eq!(*calls.lock().unwrap(), ["parent", "worker", "worker-two"]);
    assert_eq!(sync_store.snapshot()?, vec![claim.clone()]);
    assert_eq!(ledger.report()?.active_reservations, 0);
    if grok_continuation {
        crate::account_authority::admit_grok_run_account_binding(run_id.as_str(), None);
    }
    Ok(())
}

#[test]
fn nested_driver_permit_is_one_shot_across_failure_drop_and_concurrent_issuance() -> Result<()> {
    for case in [
        "permit-failed-issue",
        "permit-failed-construction",
        "permit-drop",
        "permit-race",
    ] {
        driver_fixture(case)?;
    }
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

#[test]
fn parent_continuation_preparation_binds_held_results_without_worker_journal_capability(
) -> Result<()> {
    driver_fixture("continuation-happy")
}

#[cfg(target_os = "linux")]
#[test]
fn parent_continuation_preparation_accepts_qualified_native_grok_workers() -> Result<()> {
    driver_fixture("continuation-grok-happy")
}

#[test]
fn parent_continuation_rejects_missing_forged_duplicate_or_oversized_held_results() -> Result<()> {
    driver_fixture("continuation-invalid-results")
}

#[test]
fn parent_continuation_construction_requires_unavailable_live_inbox_binding() -> Result<()> {
    driver_fixture("continuation-missing-live-inbox-binding")
}

#[test]
fn parent_continuation_refuses_candidate_drift_or_incomplete_snapshot() -> Result<()> {
    for drift in [
        "content",
        "untracked",
        "index",
        "head",
        "uninspectable",
        "incomplete-held",
    ] {
        driver_fixture(&format!("continuation-candidate-{drift}"))?;
    }
    Ok(())
}

#[test]
fn parent_continuation_accepts_only_contained_qualified_native_grok_completion() -> Result<()> {
    let mut run = ExternalAgentRun {
        command: vec!["/pinned/grok".into()],
        cwd: "/managed/parent".into(),
        timeout_seconds: 30,
        exit_code: Some(0),
        duration_ms: 1,
        timed_out: false,
        process_tree: Some(ProcessTreeEvidence::VerifiedEmpty(
            crate::process_runner::ContainmentBackend::SystemdUserService,
        )),
        side_effects: Some(SideEffectConfinementEvidence::Verified(
            crate::process_runner::SideEffectConfinementProfileKind::ExternalGrok,
        )),
        publishable: true,
        program_trust: ExternalProgramTrust::ExplicitCustom,
        codex_permissions: None,
        stdout: crate::external_agent::CapturedOutput::default(),
        stderr: crate::external_agent::CapturedOutput::default(),
        error: None,
        output_last_message: Some(b"{}".to_vec()),
        grok_stream_usage_evidence: None,
        grok_acp_parent_evidence: None,
        cursor_managed_parent_evidence: None,
        codex_parent_evidence: None,
    };
    run.stdout.target_launch_attempted = true;
    let mut provenance = CompletedLaunchModelProvenance {
        launch_runtime: SupervisorRuntime::Grok,
        configured_model: Some("grok-4.6".into()),
        launched_model: Some("grok-4.6".into()),
        resolution_observation: ModelResolutionObservation::PreferredModel,
    };
    assert_eq!(
        super::parent_continuation_binding::verified_worker_completion_runtime(&provenance, &run,)?,
        SupervisorRuntime::Grok
    );
    provenance.launched_model = Some("account-selected-model".into());
    assert_eq!(
        super::parent_continuation_binding::verified_worker_completion_runtime(&provenance, &run,)?,
        SupervisorRuntime::Grok
    );
    provenance.launched_model = Some("grok-4.7".into());
    assert_eq!(
        super::parent_continuation_binding::verified_worker_completion_runtime(&provenance, &run,)?,
        SupervisorRuntime::Grok
    );
    run.process_tree = None;
    assert!(
        super::parent_continuation_binding::verified_worker_completion_runtime(&provenance, &run,)
            .is_err()
    );
    provenance.launch_runtime = SupervisorRuntime::Cursor;
    assert!(
        super::parent_continuation_binding::verified_worker_completion_runtime(&provenance, &run,)
            .is_err()
    );
    Ok(())
}
