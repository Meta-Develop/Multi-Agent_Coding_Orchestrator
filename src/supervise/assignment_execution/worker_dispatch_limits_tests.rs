use super::*;
use crate::external_agent::codex_app_server::{self, JsonLineTransport, TransportRead};
use crate::external_agent::{CodexParentEvidence, CodexParentResolvedField, CodexParentTurnUsage};
use crate::messaging::transport::{ENV_MESSAGE_ENDPOINT, ENV_MESSAGE_TOKEN};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Transport {
    incoming: VecDeque<serde_json::Value>,
    sent: Vec<serde_json::Value>,
}

impl JsonLineTransport for Transport {
    fn receive(
        &mut self,
        _: Duration,
        _: usize,
        bytes: &mut Vec<u8>,
    ) -> Result<TransportRead, String> {
        bytes.clear();
        match self.incoming.pop_front() {
            Some(value) => {
                bytes.extend(value.to_string().bytes());
                Ok(TransportRead::Line)
            }
            None => Ok(TransportRead::Eof),
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.sent
            .push(serde_json::from_slice(bytes).map_err(|e| e.to_string())?);
        Ok(())
    }
}

fn usage(tokens: u64) -> serde_json::Value {
    let counters = json!({"inputTokens":tokens - 1,"outputTokens":1,
        "cachedInputTokens":0,"reasoningOutputTokens":0,"totalTokens":tokens});
    json!({"method":"thread/tokenUsage/updated", "params":{"threadId":"thread",
        "turnId":"turn", "tokenUsage":{"last":counters,"total":counters}}})
}

fn retain_usage(
    run: &mut ExternalAgentRun,
    command: &ExternalAgentCommand,
    tokens: u64,
    complete: bool,
) {
    run.codex_parent_evidence = Some(CodexParentEvidence {
        codex_version: Some("0.162.0".into()),
        thread_id: Some("thread".into()),
        requested_model: command.model.clone(),
        requested_effort: command.reasoning_effort.clone(),
        rollout_model: CodexParentResolvedField::Unknown,
        rollout_effort: CodexParentResolvedField::Unknown,
        observed_model: CodexParentResolvedField::Known(command.model.clone().unwrap()),
        observed_effort: CodexParentResolvedField::Known(command.reasoning_effort.clone().unwrap()),
        server_rerouted_model: None,
        model_mismatch: false,
        turn_usage: CodexParentTurnUsage::Known {
            input_tokens: tokens - 1,
            output_tokens: 1,
            cached_input_tokens: 0,
            reasoning_output_tokens: 0,
        },
        resolution_status: "complete".into(),
    });
    run.set_codex_command_execution_evidence_for_test(codex_app_server::CommandExecutionEvidence {
        thread_id: "thread".into(),
        turn_id: "turn".into(),
        observations: Vec::new(),
        turn_status: if complete {
            codex_app_server::TurnTerminalStatus::Completed
        } else {
            codex_app_server::TurnTerminalStatus::Failed
        },
    });
    run.retain_app_server_parent_evidence_for_test();
    run.retain_live_budget_invocation_for_test(command);
}

fn rendezvous(state: &(Mutex<usize>, std::sync::Condvar)) {
    let mut count = state.0.lock().unwrap();
    *count += 1;
    state.1.notify_all();
    let (count, deadline) = state
        .1
        .wait_timeout_while(count, Duration::from_secs(10), |n| *n < 2)
        .unwrap();
    assert_eq!(*count, 2);
    assert!(!deadline.timed_out(), "bounded Worker rendezvous timed out");
}

type AdmissionSignals = (Mutex<(bool, bool)>, std::sync::Condvar);

fn signal(state: &AdmissionSignals, launched: bool) {
    let mut flags = state.0.lock().unwrap();
    if launched {
        flags.0 = true;
    } else {
        flags.1 = true;
    }
    state.1.notify_all();
}

fn wait_for_signal(state: &AdmissionSignals, launched: bool) {
    let flags = state.0.lock().unwrap();
    let (_flags, deadline) = state
        .1
        .wait_timeout_while(flags, Duration::from_secs(10), |flags| {
            if launched {
                !flags.0
            } else {
                !flags.1
            }
        })
        .unwrap();
    assert!(
        !deadline.timed_out(),
        "bounded budget-admission handoff timed out"
    );
}

fn qualification(parent_tokens: usize, width: usize, inflight: usize) -> Result<()> {
    qualification_mode(parent_tokens, width, inflight, false, None)
}

fn qualification_mode(
    parent_tokens: usize,
    width: usize,
    inflight: usize,
    waiting: bool,
    live_limit: Option<usize>,
) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main")?;
    let mut loaded = super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
        include_str!("../../../examples/supervise/nested-codex-budget-qualification.json"),
        Some(&repo),
    )?;
    let second = loaded.plan.assignments.remove(1);
    loaded.plan.assignments[0]
        .worker_assignments
        .push(second.worker_assignments[0].clone());
    loaded.plan.assignments[0]
        .assigned_paths
        .extend(second.worker_assignments[0].assigned_paths.clone());
    loaded.plan_metadata.assignment_schedule.truncate(1);
    loaded.plan_metadata.run_budget.limits.hard_tokens = Some(65_000);
    loaded
        .plan_metadata
        .run_budget
        .worker_live_token_limits
        .clear();
    if let Some(limit) = live_limit {
        loaded
            .plan_metadata
            .run_budget
            .worker_live_token_limits
            .insert("admission-worker".into(), limit);
    }
    let git = crate::git_repository::open(&repo)?;
    git.config()?.set_str("user.name", "Fixture Owner")?;
    git.config()?
        .set_str("user.email", "fixture@example.invalid")?;
    let mut index = git.index()?;
    for path in &loaded.plan.assignments[0].assigned_paths {
        fs::create_dir_all(repo.join(path).parent().unwrap())?;
        fs::write(repo.join(path), "# frozen fixture candidate\n")?;
        index.add_path(path)?;
    }
    index.write()?;
    let tree = git.find_tree(index.write_tree()?)?;
    let signature = git2::Signature::now("test", "test@example.invalid")?;
    git.commit(Some("HEAD"), &signature, &signature, "base", &tree, &[])?;
    let run_id = RunId::new(format!(
        "worker-width-{}",
        crate::artifacts::state_auth::random_identifier()?
    ))?;
    let admission = SupervisorAdmissionPolicyInput::resolve(
        &repo,
        width,
        loaded.plan_metadata.admission,
        SupervisorAdmissionConfig {
            provider_inflight_limit: Some(inflight),
            host_memory_available_mib: Some(65536),
            host_fd_available: Some(65536),
            host_disk_available_mib: Some(65536),
            ..Default::default()
        },
    )?;
    assert_eq!(admission.resolved_bound, width.min(inflight));
    let catalog =
        RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(["gpt-6.1-sol"])?);
    let _routing = crate::selection::routing_policy::bind_routing_policy(
        loaded.plan_metadata.resolved_routing_policy.clone(),
    )?;
    let selected = super::super::selection_bridge::initialize_supervisor_selection_with_assessment(
        &mut loaded.plan,
        SupervisorRuntime::Codex,
        &catalog,
        &admission,
        &super::super::selection_bridge::AdvertisedCatalogSet::empty(),
        Some(&crate::objective_profile::default_resolved_objective_profile()?),
        super::super::selection_bridge::SupervisorQuotaSelectionInput::default(),
        None,
        &[],
        loaded.plan_metadata.task_routing_assessment.as_ref(),
    )?;
    assert!(
        selected.selection_preflight_failure.is_none(),
        "{selected:?}"
    );
    crate::account_authority::record_observed_codex_selection(
        Some(run_id.as_str()),
        crate::account_authority::CODEX_CLI_PROVIDER_ID,
        Some("fixture-authority".into()),
        Some(
            &coding_agent_manager_lib::account_authority::SelectedAccountBinding {
                provider_id: crate::account_authority::CODEX_CLI_PROVIDER_ID.into(),
                account_id: "fixture-account".into(),
                account_incarnation: "fixture-incarnation".into(),
                selection_revision: 1,
            },
        ),
    );
    let plan = &loaded.plan;
    let parent = &plan.assignments[0];
    let budget_config = &loaded.plan_metadata.run_budget;
    let ledger = RunBudgetLedger::new(budget_config.limits)?;
    let manager = WorktreeManager::new(&repo);
    let worktree = manager.create(crate::worktree::WorktreeCreateOptions {
        agent_id: parent.id.clone(),
        branch: None,
        base: None,
        worktree_root: Some(temp.path().join("worktrees")),
    })?;
    let sync_store = SyncStore::open(&repo)?;
    let semantic_store = SemanticIntentStore::open(&repo)?;
    let cancellation = ProcessCancellation::new();
    let claim = sync_store.claim_paths_for_run(&run_id, &parent.id, &parent.assigned_paths)?;
    let preflight = AssignmentExecutionPreflight {
        nested_turn_issued: AtomicBool::new(false),
        journal_parent_id: run_id.as_str(),
        environment_requirements: Vec::new(),
        semantic_token: None,
        child_base_head: current_head_oid(&worktree.path)?,
        mandatory_worktree_controls: provision_mandatory_worktree_controls(&worktree.path)?,
        worktree: worktree.clone(),
        worktree_write_lease: Some(manager.acquire_write_execution_lease(&parent.id)?),
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
        admission_overrides: admission.cli,
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
        "worker-width-test",
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
    super::super::messaging_bridge::initialize_supervisor_messaging_session(
        &mut writer,
        plan,
        &loaded.plan_metadata,
    )?;
    let mut journal = initialize_orchestration_event_journal(&repo, &run_id, None);
    let mut kpis = AutonomyKpiCollector::default();
    let artifacts = Mutex::new(SharedSupervisorArtifacts {
        writer: &mut writer,
        journal: &mut journal,
        autonomy_kpis: &mut kpis,
        checkpoint: None,
    });
    let field_guide = SupervisorFieldGuidePrompt::empty()?;
    let (policy, _) = super::super::scheduler::assignment_budget_policy_for_test(
        super::super::scheduler::AssignmentBudgetPolicyRequest {
            assignment: parent,
            requested_reasoning_effort: None,
            report: &ledger.report()?,
            plan,
            requested_plan: plan,
            assignment_metadata: &loaded.assignment_metadata,
            catalog: &catalog,
            runtime: SupervisorRuntime::Codex,
        },
        admission.resolved_bound,
    )?
    .context("initial policy refused")?;
    let concurrent = width.min(inflight) == 2 && !waiting;
    let reserved = Arc::new((Mutex::new(0usize), std::sync::Condvar::new()));
    let admission_signals = Arc::new((Mutex::new((false, false)), std::sync::Condvar::new()));
    let _hook = (concurrent || waiting).then(|| {
        let reserved = reserved.clone();
        let signals = admission_signals.clone();
        install_budget_admission_test_hook(
            run_id.as_str(),
            Arc::new(move |stage, owner| {
                if concurrent && stage == "reserved" && owner.ends_with("-worker") {
                    rendezvous(&reserved);
                }
                if waiting && owner == "settlement-worker" {
                    if stage == "preparing" {
                        wait_for_signal(&signals, true);
                    }
                    if stage == "waiting_for_grant" {
                        signal(&signals, false);
                    }
                }
            }),
        )
    });
    let live = (Mutex::new(0usize), std::sync::Condvar::new());
    let returned = (Mutex::new(0usize), std::sync::Condvar::new());
    let calls = Mutex::new(Vec::<String>::new());
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let reservations = Mutex::new(Vec::new());
    let runner = |command: &ExternalAgentCommand,
                  runner_cancel: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>| {
        let id = &command.agent_lifecycle.as_ref().unwrap().task_id;
        calls.lock().unwrap().push(id.clone());
        let is_parent = id == &parent.id;
        let subject = if is_parent {
            parent.clone()
        } else {
            let worker = parent
                .worker_assignments
                .iter()
                .find(|w| &w.id == id)
                .unwrap();
            let mut subject = parent.clone();
            subject.id = worker.id.clone();
            subject.role = AgentRole::Worker;
            subject.role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
            subject.assigned_paths = worker.assigned_paths.clone();
            subject.worker_assignments.clear();
            subject
        };
        let launch_claim = if is_parent {
            claim.clone()
        } else {
            assert_ne!(command.cwd, worktree.path);
            sync_store
                .snapshot()
                .unwrap()
                .into_iter()
                .find(|c| c.agent_id == *id)
                .unwrap()
        };
        let mut simulated = command.clone();
        simulated.model = None;
        let mut fake_subject = subject.clone();
        if is_parent {
            fake_subject.worker_assignments.clear();
        } else {
            crate::external_agent::prepare_managed_child_git_boundary_for_test(&command.cwd)
                .expect("prepare isolated Worker Git boundary");
        }
        let mut run = deterministic_fake_child_run(
            &simulated,
            &fake_subject,
            &loaded.assignment_metadata,
            launch_claim.token.get(),
            None,
        )
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
            codex_version: "0.162.0".into(),
            minimum_version: "0.138.0".into(),
            permission_profile: "maco_external_codex".into(),
            workspace_access: command.workspace_access,
            network_enabled: false,
            argv_digest: "fixture".into(),
            executable_identity: "fixture".into(),
        });
        if is_parent {
            assert_eq!(
                calls.lock().unwrap().len(),
                1,
                "parent continuation after exhausted Worker"
            );
            let launch = command.assignment_messaging_launch().unwrap();
            let requests = parent
                .worker_assignments
                .iter()
                .enumerate()
                .map(|(i, worker)| {
                    let request_id = format!("request-{i}");
                    let env: BTreeMap<_, _> = launch
                        .environment_for(run_id.as_str(), &parent.id)
                        .unwrap()
                        .into_iter()
                        .collect();
                    let mut stream = TcpStream::connect(&env[ENV_MESSAGE_ENDPOINT]).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
                    writeln!(stream, "{}", json!({"bearer":env[ENV_MESSAGE_TOKEN], "request":{
                        "operation":"submit_worker_request", "request_id":request_id, "worker_id":worker.id
                    }})).unwrap();
                    stream.flush().unwrap();
                    let mut response = String::new();
                    BufReader::new(stream).read_line(&mut response).unwrap();
                    assert_eq!(serde_json::from_str::<serde_json::Value>(&response).unwrap()["ok"], true);
                    json!({"request_id":request_id,"worker_id":worker.id})
                })
                .collect::<Vec<_>>();
            run.output_last_message = Some(serde_json::to_vec(&json!({"version":1,"outcome":"yield_workers",
                "run_id":run_id.as_str(),"parent_id":parent.id,"parent_attempt":1,"requests":requests})).unwrap());
            retain_usage(&mut run, command, parent_tokens as u64, true);
        } else {
            assert_eq!(
                command.managed_worker_app_server_selected_for_test(),
                Ok(true)
            );
            assert!(command.codex_native_delegation_is_disabled());
            assert_eq!(command.worker_journal_artifacts.len(), 1);
            assert_eq!(launch_claim.paths, subject.assigned_paths);
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            if concurrent {
                rendezvous(&live);
            }
            let grant = command.live_token_grant_for_test().unwrap();
            let binding = ledger
                .report()
                .unwrap()
                .dispatch_bindings
                .into_iter()
                .find(|binding| binding.invocation.assignment_id == *id)
                .unwrap();
            assert_eq!(binding.grant_id, grant.id());
            assert_eq!(
                binding.invocation.account,
                crate::supervise_budget::BudgetAccountIdentity::Selected {
                    authority_id: "fixture-authority".into(),
                    provider_id: "codex-cli".into(),
                    account_id: "fixture-account".into(),
                    account_incarnation: "fixture-incarnation".into(),
                    selection_revision: 1,
                }
            );
            assert!(run_dir
                .join(format!(
                    "budget/dispatch-{}.admitted.json",
                    binding.reservation_id
                ))
                .is_file());
            if waiting {
                assert_eq!(id, "admission-worker");
                signal(&admission_signals, true);
                wait_for_signal(&admission_signals, false);
            }
            reservations.lock().unwrap().push(grant.tokens());
            if !concurrent {
                assert_eq!(
                    grant.tokens(),
                    live_limit.unwrap_or(65000 - parent_tokens) as u64
                );
            }
            let limit = if concurrent { 100 } else { grant.tokens() };
            let mut transport = Transport {
                incoming: VecDeque::from([
                    json!({"id":1,"result":{}}),
                    json!({"id":2,"result":{"thread":{"id":"thread"},"model":"gpt-6.1-sol","reasoningEffort":"high",
                    "approvalPolicy":"on-request","approvalsReviewer":"user","activePermissionProfile":{"id":"maco_external_codex"},"cwd":command.cwd}}),
                    json!({"id":3,"result":{"turn":{"id":"turn","status":"inProgress"}}}),
                    json!({"method":"turn/started","params":{"threadId":"thread","turn":{"id":"turn","status":"inProgress"}}}),
                    usage(limit / 2),
                    usage(limit / 2),
                    usage(limit),
                    usage(limit + 7),
                    json!({"method":"turn/completed","params":{"threadId":"thread","turn":{"id":"turn","status":if concurrent { "completed" } else { "interrupted" }}}}),
                ]),
                sent: Vec::new(),
            };
            let turn = codex_app_server::AppServerTurn {
                cwd: command.cwd.to_string_lossy().into_owned(),
                permission_profile: "maco_external_codex".into(),
                prompt: fs::read_to_string(&command.prompt).unwrap(),
                model: command.model.clone(),
                minimum_effort: None,
                output_schema: None,
            };
            let observed = crate::external_agent::run_managed_worker_app_server_turn(
                &mut transport,
                &turn,
                command,
                runner_cancel,
            )
            .unwrap();
            assert_eq!(
                transport
                    .sent
                    .iter()
                    .filter(|v| v["method"] == "turn/interrupt")
                    .count(),
                usize::from(!concurrent)
            );
            assert!(
                transport.incoming.is_empty(),
                "terminal drain did not complete"
            );
            assert_eq!(
                observed.token_usage.as_ref().unwrap().input_tokens
                    + observed.token_usage.as_ref().unwrap().output_tokens,
                limit + 7
            );
            assert_eq!(grant.stopped(), !concurrent);
            run.error = observed.protocol_error.clone();
            run.exit_code = Some(if concurrent { 0 } else { 1 });
            run.publishable = concurrent;
            retain_usage(&mut run, command, limit + 7, concurrent);
            // Failure after real usage cannot refund or duplicate that settlement.
            run.output_last_message = Some(b"{invalid Worker report".to_vec());
            fs::write(
                command.cwd.join(&subject.assigned_paths[0]),
                "# interrupted partial candidate\n",
            )
            .unwrap();
            if concurrent {
                rendezvous(&returned);
            }
            active.fetch_sub(1, Ordering::SeqCst);
        }
        run
    };
    let context = AssignmentExecutionContext {
        index: 0,
        concurrent_mode: false,
        plan,
        requested_plan: plan,
        budget_config,
        consultant: &loaded.consultant,
        assignment_metadata: &loaded.assignment_metadata,
        assignment: parent,
        evidence_only_reaudit: None,
        options: &options,
        repo: &repo,
        run_dir: &run_dir,
        dirs: &dirs,
        execution_runtime: SupervisorExecutionRuntime::Verified,
        execution_target: None,
        worktree_creation: SupervisorWorktreeCreation::VerifiedTestOnly,
        manager: &manager,
        reused: true,
        sync_store: &sync_store,
        semantic_store: &semantic_store,
        prepared_semantic_token: None,
        prepared_semantic_findings: &[],
        prepared_semantic_signals: &[],
        prepared_semantic_failed: false,
        assignment_schedule: &loaded.plan_metadata.assignment_schedule,
        field_guide: &field_guide,
        serial_semantic_warn_intents: None,
        semantic_block_order: None,
        semantic_block_gate: None,
        artifacts: &artifacts,
        budget_ledger: &ledger,
        budget_policy: policy,
        admission_commit: None,
        runtime_model_catalog: &catalog,
        cancellation,
        external_runner: &runner,
    };
    let mut outcome = AssignmentExecutionOutcome {
        gate_tracker: Some(GateCorrectionTracker::new(0)),
        ..Default::default()
    };
    let prepared = match prepare_managed_parent_initial_attempt(
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
        AssignmentExecutionDisposition::Complete => bail!("initial parent unexpectedly refused"),
    };
    let result = super::managed_parent_controller::dispatch_and_collect_managed_parent_attempt(
        &context,
        &mut outcome,
        &preflight,
        run_id.as_str(),
        1,
        prepared,
        &context.budget_policy,
        1,
        &dirs.schemas.join("orchestrator-review-report.schema.json"),
        &dirs.schemas.join("worker-report.schema.json"),
        &dirs.schemas.join("auditor-report.schema.json"),
    );
    assert!(result.is_err());
    let calls = calls.lock().unwrap();
    assert_eq!(calls[0], parent.id);
    if concurrent {
        assert_eq!(
            calls.len(),
            3,
            "{:#?}; {:?}",
            result.err(),
            outcome.findings
        );
        assert_eq!(peak.load(Ordering::SeqCst), 2);
    } else {
        let expected = if parent_tokens > 64000 {
            vec![parent.id.clone()]
        } else {
            vec![parent.id.clone(), "admission-worker".into()]
        };
        assert_eq!(
            *calls,
            expected,
            "{:#?}; {:?}",
            result.err(),
            outcome.findings
        );
        assert_eq!(
            peak.load(Ordering::SeqCst),
            usize::from(parent_tokens <= 64000)
        );
        assert!(outcome.budget_dispatch_stopped);
        assert!(outcome.findings.iter().any(
            |f| f.message.contains("budget denied") && f.message.contains("settlement-worker")
        ));
        let denial = outcome
            .gate_denials
            .iter()
            .find(|denial| {
                denial.context.owner == "settlement-worker"
                    && matches!(
                        denial.reason,
                        GateDenialReason::BudgetAdmission {
                            denial: BudgetAdmissionDenial::NewDispatchStopped
                        }
                    )
            })
            .context("missing typed queued-Worker budget refusal")?;
        let events =
            fs::read_to_string(run_dir.join(crate::orchestration_event::ORCHESTRATION_EVENT_PATH))?;
        let events = events
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let refusals = events
            .iter()
            .filter(|event| {
                event["node"] == "settlement-worker"
                    && event["payload"]["denial_id"] == denial.denial_id.as_str()
            })
            .collect::<Vec<_>>();
        assert_eq!(refusals.len(), 2, "one blocked/terminal refusal pair");
        assert_eq!(refusals[0]["payload"]["state"], "blocked");
        if parent_tokens <= 64000 {
            assert_eq!(
                fs::read(run_dir.join("evidence/incoming/admission-worker.json"))
                    .context("read retained interrupted Worker report")?,
                b"{invalid Worker report"
            );
            let workers = manager.list_managed_verified()?;
            let worker = workers
                .iter()
                .find(|record| record.name == "admission-worker")
                .context("lost partial candidate")?;
            assert_eq!(
                fs::read_to_string(
                    worker
                        .path
                        .join(&parent.worker_assignments[0].assigned_paths[0])
                )?,
                "# interrupted partial candidate\n"
            );
        }
    }
    let budget = ledger.report()?;
    assert_eq!(
        budget.charges.len(),
        calls.len(),
        "one charge per invocation"
    );
    assert_eq!(
        budget
            .charges
            .iter()
            .map(|charge| charge.reservation_id)
            .collect::<BTreeSet<_>>()
            .len(),
        budget.charges.len(),
        "reservation settled more than once"
    );
    for binding in &budget.dispatch_bindings {
        let charge = budget
            .charges
            .iter()
            .find(|charge| charge.reservation_id == binding.reservation_id)
            .unwrap();
        assert_eq!(binding.charged_tokens, Some(charge.tokens));
        assert_eq!(binding.usage_complete, Some(charge.usage_complete));
        assert!(binding.invocation_verified);
        assert_eq!(binding.thread_id.as_deref(), Some("thread"));
        assert_eq!(binding.turn_id.as_deref(), Some("turn"));
        let receipt: Value = serde_json::from_slice(&fs::read(run_dir.join(format!(
            "budget/dispatch-{}.settled.json",
            binding.reservation_id
        )))?)?;
        assert_eq!(receipt["binding"], serde_json::to_value(binding)?);
    }
    assert_eq!(budget.charges[0].role, AgentRole::ChildOrchestrator);
    assert_eq!(budget.charges[0].tokens, parent_tokens);
    assert_eq!(budget.active_reservations, 0);
    assert_eq!(budget.reserved.tokens, 0);
    assert_eq!(
        budget.consumed.tokens as u64,
        parent_tokens as u64
            + if concurrent {
                214
            } else if parent_tokens > 64000 {
                0
            } else {
                reservations.lock().unwrap().iter().sum::<u64>() + 7
            }
    );
    if live_limit.is_some() {
        assert!(budget.remaining.hard_tokens.unwrap() > 20_000);
        assert!(budget
            .reasons
            .contains(&BudgetReason::LiveTokenGrantExhausted));
    }
    assert_eq!(budget.new_dispatch_allowed, concurrent);
    assert_eq!(sync_store.snapshot()?, vec![claim.clone()]);
    assert!(
        preflight.issue_nested_turn(1).is_err(),
        "replayed spent turn"
    );
    Ok(())
}

#[test]
fn frozen_nested_workers_width_one_exhaustion_drains_settles_and_refuses_next() -> Result<()> {
    for parent in [41684, 62526] {
        qualification(parent, 1, 1)?;
    }
    Ok(())
}

#[test]
fn frozen_nested_workers_provider_inflight_one_serializes_wider_run() -> Result<()> {
    qualification(41684, 2, 1)
}

#[test]
fn frozen_nested_workers_exact_estimate_boundary_admits_64000_refuses_64001() -> Result<()> {
    qualification(64000, 1, 1)?;
    qualification(64001, 1, 1)
}

#[test]
fn frozen_nested_workers_width_two_allows_bounded_concurrency() -> Result<()> {
    qualification(41684, 2, 2)
}

#[test]
fn frozen_nested_workers_stopped_live_grant_wait_records_budget_refusal() -> Result<()> {
    qualification_mode(41684, 2, 2, true, None)
}

#[test]
fn frozen_nested_worker_explicit_grant_exhausts_with_unused_run_balance() -> Result<()> {
    qualification_mode(43_233, 1, 1, false, Some(1_000))
}
