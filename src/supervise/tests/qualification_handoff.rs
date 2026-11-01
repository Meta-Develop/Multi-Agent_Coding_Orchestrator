use super::*;

// Real supervisor/controller, artifact custody, broker and review boundaries;
// only the provider transport is replaced with deterministic returned captures.
fn handoff(case: &str) -> Result<()> {
    let (temp, repo) = injected_repository();
    fs::create_dir(repo.join("tests"))?;
    fs::write(repo.join("tests/first.rs"), "#[test]\nfn first() {}\n")?;
    fs::write(repo.join("tests/second.rs"), "#[test]\nfn second() {}\n")?;
    commit_injected_repository(&repo, "qualification seeds");
    let mut first = injected_assignment(true);
    first.assigned_paths = vec!["tests/first.rs".into()];
    first.worker_assignments[0].assigned_paths = first.assigned_paths.clone();
    let mut second = first.clone();
    second.id = "second-parent".into();
    second.assigned_paths = vec!["tests/second.rs".into()];
    second.worker_assignments[0].id = "second-worker".into();
    second.worker_assignments[0].assigned_paths = second.assigned_paths.clone();
    let mut plan = injected_plan(first.clone(), 0);
    plan.assignments.push(second.clone());
    plan.max_child_assignments = 2;
    plan.max_depth = 3;
    let options = injected_options(&repo, temp.path(), &format!("q714-{case}"));
    let run_id = options.run_id.clone();
    let (_selector, catalog) = bind_test_selector_triple_catalog()?;
    #[cfg(target_os = "linux")]
    let _cam = crate::supervise::scheduler::install_positive_injected_cam_fixture(&temp, &catalog)?;
    let mut metadata = SupervisorPlanMetadata {
        assignment_schedule: vec![
            AssignmentScheduleEntry {
                assignment_id: first.id.clone(),
                parent_assignment_id: None,
                depth: 2,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: second.id.clone(),
                parent_assignment_id: Some(first.id.clone()),
                depth: 3,
                flattened_index: 1,
            },
        ],
        ..Default::default()
    };
    if case == "seal" {
        metadata.run_budget.limits.hard_tokens = Some(100_000);
        metadata.run_budget.role_token_reservations = BTreeMap::from([
            (AgentRole::ChildOrchestrator, 1_000),
            (AgentRole::Worker, 1_000),
            (AgentRole::Auditor, 1_000),
        ]);
        metadata.run_budget.worker_live_token_limits = BTreeMap::from([
            ("worker-a".into(), 10_000),
            ("second-worker".into(), 10_000),
        ]);
    }
    let _routing = bind_assessed_injected_plan(&plan, &repo, &mut metadata)?;
    let calls = Mutex::new(Vec::new());
    let reports = Mutex::new(BTreeMap::<String, OrchestratorReviewReport>::new());
    let digests = Mutex::new(BTreeMap::<String, String>::new());
    let runner = |command: &ExternalAgentCommand,
                  _: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>| {
        use crate::messaging::transport::{ENV_MESSAGE_ENDPOINT, ENV_MESSAGE_TOKEN};
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpStream;
        let identity = command.agent_lifecycle.as_ref().unwrap();
        let parent = if identity.task_id.starts_with("second") {
            &second
        } else {
            &first
        };
        let is_auditor = identity.role == "auditor";
        let is_worker = identity.role == "worker";
        let phase = if is_auditor {
            "auditor"
        } else if is_worker {
            "worker"
        } else if command.codex_managed_worker_requests_enabled() {
            "parent"
        } else {
            "continuation"
        };
        calls.lock().unwrap().push(format!("{}:{phase}", parent.id));
        if is_auditor {
            if parent.id == first.id {
                if case == "packet" {
                    let prompt = fs::read_to_string(&command.prompt).unwrap();
                    assert!(
                        prompt.contains("worker_execution_evidence"),
                        "review omitted original Worker evidence"
                    );
                    assert!(
                        prompt.contains("native-worker-observation"),
                        "review omitted native Worker transcript"
                    );
                    assert!(
                        prompt.contains("fixture-worker-check"),
                        "review omitted Worker journal"
                    );
                    assert!(
                        prompt.contains("validation_candidate"),
                        "validations lack a held candidate binding"
                    );
                }
                if case == "failed-candidate" {
                    let run = command
                        .prompt
                        .ancestors()
                        .find(|p| p.file_name().is_some_and(|n| n == run_id.as_str()))
                        .unwrap();
                    let bytes = fs::read(run.join("reports/child-a.candidate.json"))
                        .expect("failed report must retain candidate before Auditor launch");
                    let value: Value = serde_json::from_slice(&bytes).unwrap();
                    assert!(value["candidate_tree"].as_str().is_some());
                    assert_eq!(value["acceptance_authority"], false);
                    let patch = fs::read(run.join("reports/child-a.candidate.patch")).unwrap();
                    assert!(!patch.is_empty());
                    assert_eq!(
                        value["patch"]["sha256"],
                        crate::artifacts::state_auth::sha256_hex(&patch)
                    );
                    let git = crate::git_repository::open(&repo).unwrap();
                    let base = git
                        .find_commit(value["base_commit"].as_str().unwrap().parse().unwrap())
                        .unwrap();
                    let diff = git2::Diff::from_buffer(&patch).unwrap();
                    let mut index = git
                        .apply_to_tree(&base.tree().unwrap(), &diff, None)
                        .unwrap();
                    assert_eq!(
                        index.write_tree_to(&git).unwrap().to_string(),
                        value["candidate_tree"].as_str().unwrap()
                    );
                }
                if case == "seal" {
                    let run = command
                        .prompt
                        .ancestors()
                        .find(|p| p.file_name().is_some_and(|n| n == run_id.as_str()))
                        .unwrap();
                    let summary: Value = serde_json::from_slice(
                        &fs::read(run.join("nested/child-a/attempt-1/worker-a/command.json"))
                            .unwrap(),
                    )
                    .unwrap();
                    let seal = &summary["command_seal_snapshot"];
                    assert_eq!(seal["version"], 2, "missing reproducible command seal");
                    assert_eq!(
                        crate::artifacts::state_auth::sha256_hex(
                            &serde_json::to_vec(seal).unwrap()
                        ),
                        digests.lock().unwrap()["worker-a"]
                    );
                }
            }
            let child = reports.lock().unwrap()[&parent.id].clone();
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(parent, &child),
            );
        } else if is_worker {
            if case == "seal" {
                digests.lock().unwrap().insert(
                    identity.task_id.clone(),
                    command
                        .live_budget_invocation()
                        .unwrap()
                        .unwrap()
                        .command_sha256,
                );
            }
            let mut child = injected_child_report(parent);
            let claims = SyncStore::open(&repo).unwrap().snapshot().unwrap();
            let claim = claims
                .iter()
                .find(|claim| claim.agent_id == parent.id)
                .unwrap();
            child.claim_token = Some(claim.token.get());
            let worker = &mut child.worker_reports[0];
            worker.claim_token = child.claim_token;
            worker.commands_run = vec![serde_json::from_value(json!({
                "command":["fixture-worker-check"], "cwd":command.cwd,
                "exit_code":0, "status":"succeeded", "timeout_seconds":1,
                "duration_ms":1, "timed_out":false
            }))
            .unwrap()];
            if case == "failed-candidate" {
                worker.files_changed = parent.assigned_paths.clone();
                child.files_changed = parent.assigned_paths.clone();
            }
            write_injected_json(&command.output_last_message, worker);
            reports.lock().unwrap().insert(parent.id.clone(), child);
        } else if phase == "parent" {
            let launch = command.assignment_messaging_launch().unwrap();
            let env: BTreeMap<_, _> = launch
                .environment_for(run_id.as_str(), &parent.id)
                .unwrap()
                .into_iter()
                .collect();
            let mut stream = TcpStream::connect(&env[ENV_MESSAGE_ENDPOINT]).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            writeln!(stream, "{}", json!({"bearer":env[ENV_MESSAGE_TOKEN], "request":{
                "operation":"submit_worker_request", "request_id":"r1", "worker_id":parent.worker_assignments[0].id
            }})).unwrap();
            stream.flush().unwrap();
            let mut response = String::new();
            BufReader::new(stream).read_line(&mut response).unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&response).unwrap()["ok"],
                true
            );
            write_injected_json(
                &command.output_last_message,
                &json!({
                    "version":1, "outcome":"yield_workers", "run_id":run_id.as_str(),
                    "parent_id":parent.id, "parent_attempt":1,
                    "requests":[{"request_id":"r1", "worker_id":parent.worker_assignments[0].id}]
                }),
            );
        } else {
            let mut child = reports.lock().unwrap()[&parent.id].clone();
            if case == "failed-candidate" {
                child.status = ReviewStatus::Failed;
                child.accepted = false;
                child.rejected = true;
            }
            reports
                .lock()
                .unwrap()
                .insert(parent.id.clone(), child.clone());
            write_injected_json(
                &command.output_last_message,
                &json!({
                    "version":1, "run_id":run_id.as_str(), "parent_id":parent.id,
                    "source_parent_attempt":1, "parent_attempt":2,
                    "completed_worker_ids":[parent.worker_assignments[0].id],
                    "turn":{"outcome":"final_report", "report":child}
                }),
            );
        }
        write_injected_usage(command, 8, 3);
        let mut run = injected_verified_run(command);
        if is_worker && case == "failed-candidate" {
            // Native edits remain uncommitted until the supervisor captures them.
            // Perform this after the generic fixture's optional Git import.
            fs::write(
                command.cwd.join(&parent.assigned_paths[0]),
                "#[test]\nfn repaired() {}\n",
            )
            .unwrap();
        }
        run.stdout.target_launch_attempted = true;
        if is_worker {
            let journals = run.worker_journal_artifacts().to_vec();
            run.stdout = CapturedOutput::from_captured_bytes_for_test(&crate::process_runner::CapturedBytes::from_bytes_for_test(
                b"{\"type\":\"native-worker-observation\"}\n{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":8,\"output_tokens\":3}}\n".to_vec()));
            run.stdout.target_launch_attempted = true;
            run.replace_worker_journal_artifacts(journals);
            run.retain_live_budget_invocation_for_test(command);
        }
        if is_auditor && parent.id == first.id {
            let run_dir = command
                .prompt
                .ancestors()
                .find(|p| p.file_name().is_some_and(|n| n == run_id.as_str()))
                .unwrap();
            super::super::messaging_bridge::recover_supervisor_messaging_session(run_dir).unwrap();
        }
        run
    };
    let report = super::super::scheduler::run_supervisor_plan_with_runner_and_creation(
        LoadedSupervisorPlan {
            plan,
            consultant: Default::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: metadata,
        },
        options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::VerifiedTestOnly,
        Ok(catalog),
        &runner,
    )?;
    let calls = calls.into_inner().unwrap();
    if case == "failed-candidate" {
        assert!(!report.success, "failed parent report became accepted");
        let root = crate::artifacts::run_dir(&repo, RunArtifactFamily::Supervise, &run_id);
        assert!(
            root.join("reports/child-a.candidate.json").is_file(),
            "failed report lost candidate: calls={calls:?}, findings={:?}",
            report.findings
        );
        assert!(
            calls.iter().any(|call| call == "child-a:auditor"),
            "failed candidate never reached Auditor: calls={calls:?}, findings={:?}",
            report.findings
        );
        assert!(!calls.iter().any(|call| call.starts_with("second-parent")));
    } else {
        assert!(
            report.success,
            "handoff failed: calls={calls:?}, findings={:?}",
            report.findings
        );
        assert_eq!(
            calls,
            [
                "child-a:parent",
                "child-a:worker",
                "child-a:continuation",
                "child-a:auditor",
                "second-parent:parent",
                "second-parent:worker",
                "second-parent:continuation",
                "second-parent:auditor"
            ]
        );
    }
    Ok(())
}

#[test]
fn q714_cycle_then_second_parent_after_broker_recovery() -> Result<()> {
    handoff("cycle")
}

#[test]
fn q714_review_packet_contains_original_worker_journal_and_transcript() -> Result<()> {
    handoff("packet")
}

#[test]
fn q714_failed_report_retains_candidate_before_auditor() -> Result<()> {
    handoff("failed-candidate")
}

#[test]
fn q714_retained_command_seal_recomputes_digest() -> Result<()> {
    handoff("seal")
}

#[test]
fn q714_fixture_requires_stage_one_acceptance() -> Result<()> {
    let (temp, repo) = injected_repository();
    let loaded = plan_api::parse_supervisor_plan_with_consultant_in_repo(
        include_str!("../../../examples/supervise/nested-codex-budget-qualification.json"),
        Some(&repo),
    )?;
    let schedule = loaded.plan_metadata.assignment_schedule;
    let mut outcomes = vec![None, None];
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes)?,
        AssignmentAdmissionState::Waiting
    );
    outcomes[0] = Some(AssignmentExecutionOutcome {
        report: Some(injected_child_report(&loaded.plan.assignments[0])),
        ..Default::default()
    });
    assert_eq!(
        assignment_admission_state(1, &schedule, &outcomes)?,
        AssignmentAdmissionState::Ready
    );
    outcomes[0]
        .as_mut()
        .unwrap()
        .report
        .as_mut()
        .unwrap()
        .status = ReviewStatus::Failed;
    assert!(matches!(
        assignment_admission_state(1, &schedule, &outcomes)?,
        AssignmentAdmissionState::Suppressed { .. }
    ));
    drop(temp);
    Ok(())
}
