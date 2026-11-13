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
                if matches!(
                    case,
                    "packet" | "initial-only" | "initial-missing-output" | "large-output"
                ) {
                    let prompt = fs::read_to_string(&command.prompt).unwrap();
                    let request: crate::review::ReviewLensRequest = serde_json::from_str(
                        prompt
                            .split_once("REVIEW_LENS_REQUEST_JSON:\n")
                            .unwrap()
                            .1
                            .trim(),
                    )
                    .unwrap();
                    assert!(
                        serde_json::to_vec(&request).unwrap().len()
                            <= REVIEW_LENS_REQUEST_LIMIT_BYTES
                    );
                    let crate::review::ReviewLensScopedInformation::BoundedFullChildTranscript {
                        bindings,
                        ..
                    } = request.information
                    else {
                        panic!("expected full review");
                    };
                    let native = &bindings.validation_bindings["native_execution_evidence"];
                    if case == "large-output" {
                        assert!(
                            serde_json::to_vec(&bindings).unwrap().len()
                                < REVIEW_LENS_REQUEST_LIMIT_BYTES
                        );
                        assert!(
                            !bindings.validation_bindings["worker_execution_evidence"].is_null()
                        );
                        let worker = native["targets"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|target| target["binding"]["role"] == "worker")
                            .unwrap();
                        let commands = worker["commands"]["commands"].as_array().unwrap();
                        let sizes = [26895, 16849, 43076, 20676, 44002, 27527, 36772, 19012];
                        assert_eq!(commands.len(), sizes.len());
                        assert!(sizes.iter().sum::<usize>() > 64 * 1024);
                        for (index, observed) in commands.iter().enumerate() {
                            assert_eq!(
                                observed["native_command"]["text"],
                                format!("/bin/bash -lc 'fixture-worker-check-{index}'")
                            );
                            assert_eq!(observed["status"], "completed");
                            assert_eq!(observed["exit_code"], 0);
                            assert_eq!(
                                observed["aggregated_output"]["original_bytes"],
                                sizes[index]
                            );
                            assert_eq!(
                                observed["aggregated_output"]["sha256"],
                                crate::artifacts::state_auth::sha256_hex(
                                    "x".repeat(sizes[index]).as_bytes()
                                )
                            );
                            assert_eq!(observed["aggregated_output"]["view_truncated"], true);
                        }
                    }
                    assert_eq!(native["required_for_acceptance"], true);
                    assert_eq!(native["review_complete"], case != "initial-missing-output");
                    let targets = native["targets"].as_array().unwrap();
                    assert_eq!(
                        targets.len(),
                        3,
                        "initial, final and Worker source are required"
                    );
                    let parents = targets
                        .iter()
                        .filter(|target| target["binding"]["task_id"] == parent.id)
                        .collect::<Vec<_>>();
                    assert_eq!(parents.len(), 2);
                    assert_eq!(parents[0]["binding"]["attempt"], 1);
                    assert_eq!(parents[1]["binding"]["attempt"], 2);
                    assert_eq!(parents[0]["source_attempt"], 1);
                    assert_eq!(parents[1]["source_attempt"], 1);
                    assert_eq!(parents[1]["commands"]["observation_count"], 0);
                    if case.starts_with("initial-") {
                        let observed = &parents[0]["commands"]["commands"][0];
                        assert_eq!(observed["status"], "failed");
                        assert_eq!(observed["exit_code"], 7);
                        assert_eq!(
                            parents[0]["candidate_at_execution"],
                            "unknown; not observed by command capture"
                        );
                        if case == "initial-only" {
                            assert_eq!(
                                observed["aggregated_output"]["text"],
                                "initial-parent-only-result\n"
                            );
                        }
                        assert!(targets
                            .iter()
                            .filter(|target| target["binding"]["role"] == "worker")
                            .all(|target| target["commands"]["observation_count"] == 0));
                    }
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
            if case.starts_with("initial-") {
                worker.commands_run.clear();
            }
            if case == "large-output" {
                worker.commands_run = (0..8)
                    .map(|index| {
                        serde_json::from_value(json!({
                            "command":[format!("fixture-worker-check-{index}")], "cwd":command.cwd,
                            "exit_code":0, "status":"succeeded", "timeout_seconds":1,
                            "duration_ms":1, "timed_out":false
                        }))
                        .unwrap()
                    })
                    .collect();
            }
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
                    "version":2, "run_id":run_id.as_str(), "parent_id":parent.id,
                    "source_parent_attempt":1, "parent_attempt":2,
                    "completed_worker_ids":[parent.worker_assignments[0].id],
                    "turn":assignment_execution::parent_continuation_response::final_turn_for_test(command, &child)
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
        let items = if phase == "parent" && case.starts_with("initial-") {
            review_command_items(
                command,
                "initial-parent-command",
                "/bin/bash -lc 'inspect-before-workers'",
                7,
                (case != "initial-missing-output").then_some("initial-parent-only-result\n"),
            )
        } else if is_worker && case == "large-output" {
            let sizes = [26895, 16849, 43076, 20676, 44002, 27527, 36772, 19012];
            sizes
                .iter()
                .enumerate()
                .flat_map(|(index, size)| {
                    review_command_items(
                        command,
                        &format!("native-worker-command-{index}"),
                        &format!("/bin/bash -lc 'fixture-worker-check-{index}'"),
                        0,
                        Some(&"x".repeat(*size)),
                    )
                })
                .collect()
        } else if is_worker && !case.starts_with("initial-") {
            review_command_items(
                command,
                "native-worker-observation",
                "/bin/bash -lc 'fixture-worker-check'",
                0,
                Some("controlled Worker fixture result\n"),
            )
        } else {
            Vec::new()
        };
        retained_review_turn_fixture(command, &mut run, items, 8, 3);
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
    if case == "initial-missing-output" {
        assert!(!report.success, "missing initial output was accepted");
        assert!(calls.iter().any(|call| call == "child-a:auditor"));
        assert!(!calls.iter().any(|call| call.starts_with("second-parent")));
    } else if case == "failed-candidate" {
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

#[path = "qualification_operation_evidence.rs"]
mod operation_evidence;

#[test]
fn managed_review_retains_only_command_result_from_initial_parent() -> Result<()> {
    handoff("initial-only")
}

#[test]
fn managed_review_missing_initial_output_cannot_be_hidden_by_empty_final_turn() -> Result<()> {
    handoff("initial-missing-output")
}

#[test]
fn managed_large_native_fields_fit_with_worker_operation_evidence_and_all_command_identities(
) -> Result<()> {
    handoff("large-output")
}
