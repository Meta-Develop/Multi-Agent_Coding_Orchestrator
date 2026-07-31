use super::*;

#[test]
fn concurrent_disjoint_assignments_make_progress_and_finalize_in_plan_order() {
    #[derive(Default)]
    struct GateState {
        started: BTreeSet<String>,
        child_b_finished: bool,
        scratch_roots: BTreeSet<PathBuf>,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "Cargo.toml"),
        injected_named_assignment("child-d", "RELEASE_NOTES.md"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "concurrent-plan-order");
    let gate = Arc::new((Mutex::new(GateState::default()), Condvar::new()));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let runner = {
        let gate = Arc::clone(&gate);
        let in_flight = Arc::clone(&in_flight);
        let peak = Arc::clone(&peak);
        let assignments = assignments.clone();
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let active = in_flight.fetch_add(1, Ordering::SeqCst).saturating_add(1);
            peak.fetch_max(active, Ordering::SeqCst);
            let (lock, condvar) = &*gate;
            let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            state.started.insert(id.clone());
            if let Some(root) = command.output_last_message.parent() {
                state.scratch_roots.insert(root.to_path_buf());
            }
            condvar.notify_all();
            if id == "child-a" {
                while !state.child_b_finished {
                    state = condvar
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else {
                while !state.started.contains("child-a") {
                    state = condvar
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            drop(state);

            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            let run = injected_verified_run(command);
            in_flight.fetch_sub(1, Ordering::SeqCst);
            if id == "child-b" {
                let mut state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                state.child_b_finished = true;
                condvar.notify_all();
            }
            run
        }
    };

    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("run two disjoint assignments");

    assert!(report.success, "unexpected failed report: {report:#?}");
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    assert_eq!(
        report
            .orchestrator_reports
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["child-a", "child-b", "child-c", "child-d"]
    );
    assert_eq!(
        report
            .released_claims
            .iter()
            .map(|claim| claim.agent_id.as_str())
            .collect::<Vec<_>>(),
        vec!["child-a", "child-b", "child-c", "child-d"]
    );
    assert_eq!(report.commands_run.len(), 4);

    let state = gate
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert_eq!(state.scratch_roots.len(), 4);
    assert!(state.scratch_roots.iter().all(|path| {
        !path.ends_with("incoming")
            && path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with("incoming-assignment-"))
    }));
    drop(state);

    let run_id = RunId::new("concurrent-plan-order").expect("valid run id");
    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized concurrent artifacts");
    let journal = reader
        .read(ORCHESTRATION_EVENT_PATH)
        .expect("read synchronized event journal");
    assert!(journal.ends_with(b"\n"));
    for line in journal
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        serde_json::from_slice::<OrchestrationEvent>(line)
            .expect("event journal line must remain well formed");
    }
    let run_root = repo_path.join(".maco/o2/runs/concurrent-plan-order");
    for relative in [
        "evidence/incoming/child-a.json",
        "evidence/incoming/child-b.json",
        "evidence/incoming/child-c.json",
        "evidence/incoming/child-d.json",
        "reports/child-a.json",
        "reports/child-b.json",
        "reports/child-c.json",
        "reports/child-d.json",
    ] {
        assert!(run_root.join(relative).exists(), "missing {relative}");
    }
    assert!(fs::read_dir(&run_root)
        .expect("read finalized run root")
        .filter_map(std::result::Result::ok)
        .all(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            !name.starts_with("incoming-") && !name.starts_with("capture-")
        }));
}

#[test]
fn auto_policy_serializes_overlap_without_head_of_line_blocking() {
    #[derive(Default)]
    struct ScheduleState {
        events: Vec<String>,
        child_c_started: bool,
        child_a_finished: bool,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "src"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "README.md"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "concurrent-overlap-scan");
    let state = Arc::new((Mutex::new(ScheduleState::default()), Condvar::new()));
    let runner = {
        let state = Arc::clone(&state);
        let assignments = assignments.clone();
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut schedule = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            schedule.events.push(format!("{id}-start"));
            if id == "child-c" {
                schedule.child_c_started = true;
                condvar.notify_all();
            }
            if id == "child-a" {
                while !schedule.child_c_started {
                    schedule = condvar
                        .wait(schedule)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            if id == "child-b" {
                assert!(schedule.child_a_finished);
            }
            drop(schedule);
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            let run = injected_verified_run(command);
            let mut schedule = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            schedule.events.push(format!("{id}-finish"));
            if id == "child-a" {
                schedule.child_a_finished = true;
                condvar.notify_all();
            }
            run
        }
    };

    let auto_bound =
        SupervisorConcurrencyPolicy::Auto.resolve(HostProcessCapacity::from_parallelism(
            NonZeroUsize::new(2).expect("test capacity is non-zero"),
        ));
    assert_eq!(auto_bound, 2);
    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        auto_bound,
        &runner,
    )
    .expect("run overlap-aware scheduler");
    assert!(report.success, "unexpected failed report: {report:#?}");
    let schedule = state
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let c_start = schedule
        .events
        .iter()
        .position(|event| event == "child-c-start")
        .expect("child C start");
    let a_finish = schedule
        .events
        .iter()
        .position(|event| event == "child-a-finish")
        .expect("child A finish");
    let b_start = schedule
        .events
        .iter()
        .position(|event| event == "child-b-start")
        .expect("child B start");
    assert!(c_start < a_finish, "{:?}", schedule.events);
    assert!(b_start > a_finish, "{:?}", schedule.events);
}

#[test]
fn scoped_spawn_failure_records_fatal_index_and_stops_new_scheduling() {
    let mut indexed_outcomes = (0..3)
        .map(|_| None)
        .collect::<Vec<Option<AssignmentExecutionOutcome>>>();
    let mut stop_scheduling = false;
    record_assignment_spawn_failure(
        &mut indexed_outcomes,
        &mut stop_scheduling,
        1,
        "child-b",
        &std::io::Error::other("injected scoped spawn failure"),
    )
    .expect("record injected spawn failure");

    assert!(stop_scheduling);
    assert!(indexed_outcomes[0].is_none());
    assert!(indexed_outcomes[2].is_none());
    let outcome = indexed_outcomes[1]
        .as_ref()
        .expect("spawn failure outcome at plan index");
    assert!(outcome.requires_scheduler_abort());
    assert!(outcome
        .fatal_error
        .as_deref()
        .is_some_and(|message| message.contains("child-b")
            && message.contains("injected scoped spawn failure")));
}

#[test]
fn serial_overlapping_assignments_release_between_slots_with_legacy_scratch_names() {
    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "src"),
        injected_named_assignment("child-b", "src/lib.rs"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "serial-overlap-release");
    let invocations = Arc::new(Mutex::new(Vec::new()));
    let runner = {
        let assignments = assignments.clone();
        let invocations = Arc::clone(&invocations);
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            invocations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((
                    id.clone(),
                    command
                        .output_last_message
                        .parent()
                        .and_then(Path::file_name)
                        .and_then(OsStr::to_str)
                        .unwrap_or_default()
                        .to_string(),
                    command
                        .json_log
                        .parent()
                        .and_then(Path::file_name)
                        .and_then(OsStr::to_str)
                        .unwrap_or_default()
                        .to_string(),
                ));
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        }
    };

    let serial_bound =
        SupervisorConcurrencyPolicy::Fixed(NonZeroUsize::new(1).expect("serial limit is non-zero"))
            .resolve(HostProcessCapacity::from_parallelism(
                NonZeroUsize::new(8).expect("test capacity is non-zero"),
            ));
    assert_eq!(serial_bound, 1);
    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        serial_bound,
        &runner,
    )
    .expect("run serial overlapping assignments");
    assert!(report.success, "unexpected failed report: {report:#?}");
    assert_eq!(
        report
            .orchestrator_reports
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["child-a", "child-b"]
    );
    assert_eq!(
        report
            .released_claims
            .iter()
            .map(|claim| claim.agent_id.as_str())
            .collect::<Vec<_>>(),
        vec!["child-a", "child-b"]
    );
    assert_eq!(
        *invocations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec![
            (
                "child-a".to_string(),
                "incoming".to_string(),
                "capture".to_string()
            ),
            (
                "child-b".to_string(),
                "incoming".to_string(),
                "capture".to_string()
            ),
        ]
    );
}

#[test]
fn semantic_warn_previews_are_plan_ordered_once_at_serial_and_concurrent_bounds() {
    for max_concurrent_children in [1usize, 2] {
        let (temp, repo_path) = injected_repository();
        fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")
            .expect("write injected Rust source");
        commit_injected_repository(&repo_path, "add semantic fixture");
        let mut assignments = vec![
            injected_named_assignment("child-a", "README.md"),
            injected_named_assignment("child-b", "src/lib.rs"),
        ];
        for assignment in &mut assignments {
            assignment.semantic_symbols = vec!["Shared".to_string()];
        }
        let mut plan = injected_multi_plan(assignments.clone(), 0);
        plan.semantic_coordination = SemanticCoordinationMode::Warn;
        let run_id = format!("semantic-warn-plan-order-{max_concurrent_children}");
        let options = injected_options(&repo_path, temp.path(), &run_id);
        let runner = move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        };

        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            max_concurrent_children,
            &runner,
        )
        .expect("run deterministic semantic warn preview");
        assert!(report.success, "unexpected failed report: {report:#?}");
        let warnings = report
            .findings
            .iter()
            .filter(|finding| {
                finding
                    .message
                    .contains("semantic coordination warn-mode preview")
            })
            .collect::<Vec<_>>();
        assert_eq!(warnings.len(), 1, "unexpected warnings: {warnings:#?}");
        assert!(warnings[0].message.contains("assignment 'child-b'"));
    }

    let (temp, repo_path) = injected_repository();
    fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
    fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")
        .expect("write injected Rust source");
    commit_injected_repository(&repo_path, "add serial warn failure fixture");
    let sync_store = SyncStore::open(&repo_path).expect("open injected sync store");
    let external_claim = sync_store
        .claim_paths("external-owner", [PathBuf::from("README.md")])
        .expect("reserve first serial assignment path");
    let mut assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
    ];
    for assignment in &mut assignments {
        assignment.semantic_symbols = vec!["Shared".to_string()];
    }
    let mut plan = injected_multi_plan(assignments.clone(), 0);
    plan.semantic_coordination = SemanticCoordinationMode::Warn;
    let options = injected_options(&repo_path, temp.path(), "serial-warn-early-failure");
    let runner = move |command: &ExternalAgentCommand| {
        let id = injected_command_assignment_id(command);
        let assignment = assignments
            .iter()
            .find(|assignment| assignment.id == id)
            .unwrap_or_else(|| panic!("missing assignment {id}"));
        write_injected_assignment_report(command, assignment);
        injected_verified_run(command)
    };
    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        1,
        &runner,
    )
    .expect("serial warn early failure remains reportable");
    sync_store
        .release(external_claim.token)
        .expect("release serial warn external claim");
    assert!(!report.success);
    assert!(report.findings.iter().all(|finding| !finding
        .message
        .contains("semantic coordination warn-mode preview")));
}

#[test]
fn semantic_resolution_failure_does_not_stop_healthy_assignment_at_any_bound() {
    for (case, semantic_coordination, max_concurrent_children) in [
        ("warn-serial", SemanticCoordinationMode::Warn, 1usize),
        ("warn-concurrent", SemanticCoordinationMode::Warn, 2usize),
        ("block-concurrent", SemanticCoordinationMode::Block, 2usize),
    ] {
        let (temp, repo_path) = injected_repository();
        fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
        fs::write(repo_path.join("src/lib.rs"), "pub struct Shared;\n")
            .expect("write injected Rust source");
        commit_injected_repository(&repo_path, "add semantic resolution fixture");
        let mut assignments = vec![
            injected_named_assignment("bad-semantic", "README.md"),
            injected_named_assignment("healthy-semantic", "src/lib.rs"),
        ];
        assignments[0].semantic_symbols = vec!["MissingSymbol".to_string()];
        assignments[1].semantic_symbols = vec!["Shared".to_string()];
        let mut plan = injected_multi_plan(assignments.clone(), 0);
        plan.semantic_coordination = semantic_coordination;
        let options = injected_options(
            &repo_path,
            temp.path(),
            &format!("semantic-resolution-isolation-{case}"),
        );
        let started = Arc::new(Mutex::new(Vec::new()));
        let runner = {
            let assignments = assignments.clone();
            let started = Arc::clone(&started);
            move |command: &ExternalAgentCommand| {
                let id = injected_command_assignment_id(command);
                started
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(id.clone());
                let assignment = assignments
                    .iter()
                    .find(|assignment| assignment.id == id)
                    .unwrap_or_else(|| panic!("missing assignment {id}"));
                write_injected_assignment_report(command, assignment);
                injected_verified_run(command)
            }
        };

        let report = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            max_concurrent_children,
            &runner,
        )
        .expect("semantic resolution failure remains assignment-local");
        assert!(!report.success);
        assert_eq!(
            *started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
            vec!["healthy-semantic".to_string()],
            "case {case}"
        );
        assert_eq!(
            report
                .orchestrator_reports
                .iter()
                .map(|item| item.id.as_str())
                .collect::<Vec<_>>(),
            vec!["healthy-semantic"],
            "case {case}"
        );
        assert!(report.findings.iter().any(|finding| finding
                .message
                .contains("bad-semantic' failed during semantic resolution: unresolved semantic symbol: MissingSymbol")),
                "case {case}: {:?}", report.findings);
    }
}

#[test]
fn semantic_block_claims_follow_actual_dispatch_order_with_overlap_scan_ahead() {
    #[derive(Default)]
    struct BlockState {
        child_c_started: bool,
    }

    let (temp, repo_path) = injected_repository();
    fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Alpha;\npub struct Beta;\npub struct Gamma;\n",
    )
    .expect("write injected Rust source");
    commit_injected_repository(&repo_path, "add Block semantic fixture");
    let mut assignments = vec![
        injected_named_assignment("child-a", "src"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "README.md"),
    ];
    assignments[0].semantic_symbols = vec!["Alpha".to_string()];
    assignments[1].semantic_symbols = vec!["Beta".to_string()];
    assignments[2].semantic_symbols = vec!["Gamma".to_string()];
    let mut plan = injected_multi_plan(assignments.clone(), 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    let options = injected_options(&repo_path, temp.path(), "semantic-block-dispatch-order");
    let state = Arc::new((Mutex::new(BlockState::default()), Condvar::new()));
    let runner = {
        let assignments = assignments.clone();
        let state = Arc::clone(&state);
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut block = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if id == "child-c" {
                block.child_c_started = true;
                condvar.notify_all();
            } else if id == "child-a" {
                while !block.child_c_started {
                    block = condvar
                        .wait(block)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            drop(block);
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        }
    };

    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("run deterministic semantic Block scheduling");
    assert!(report.success, "unexpected failed report: {report:#?}");
    assert_eq!(
        report
            .released_semantic_intents
            .iter()
            .map(|intent| (intent.agent_id.as_str(), intent.token.get()))
            .collect::<Vec<_>>(),
        vec![("child-a", 1), ("child-b", 3), ("child-c", 2)]
    );
}

#[test]
fn claim_and_semantic_block_conflicts_fail_only_the_affected_assignment() {
    let (temp, repo_path) = injected_repository();
    let sync_store = SyncStore::open(&repo_path).expect("open injected sync store");
    let external_claim = sync_store
        .claim_paths("external-owner", [PathBuf::from("README.md")])
        .expect("reserve injected conflicting claim");
    let assignments = vec![
        injected_named_assignment("claim-blocked", "README.md"),
        injected_named_assignment("claim-healthy", "src/lib.rs"),
    ];
    let mut plan = injected_multi_plan(assignments.clone(), 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    let options = injected_options(&repo_path, temp.path(), "claim-conflict-isolation");
    let started = Arc::new(Mutex::new(Vec::new()));
    let runner = {
        let assignments = assignments.clone();
        let started = Arc::clone(&started);
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(id.clone());
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        }
    };
    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("claim conflict remains assignment-local");
    sync_store
        .release(external_claim.token)
        .expect("release injected external claim");
    assert!(!report.success);
    assert_eq!(
        *started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        vec!["claim-healthy".to_string()]
    );
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("claim")));

    #[derive(Default)]
    struct SemanticConflictState {
        child_c_started: bool,
        blocked_runner_started: bool,
    }

    let (temp, repo_path) = injected_repository();
    fs::create_dir_all(repo_path.join("src")).expect("create injected source root");
    fs::write(
        repo_path.join("src/lib.rs"),
        "pub struct Shared;\npub struct Gamma;\n",
    )
    .expect("write injected Rust source");
    commit_injected_repository(&repo_path, "add semantic conflict fixture");
    let mut assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "Cargo.toml"),
    ];
    assignments[0].semantic_symbols = vec!["Shared".to_string()];
    assignments[1].semantic_symbols = vec!["Shared".to_string()];
    assignments[2].semantic_symbols = vec!["Gamma".to_string()];
    let mut plan = injected_multi_plan(assignments.clone(), 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    let options = injected_options(&repo_path, temp.path(), "semantic-block-isolation");
    let state = Arc::new((Mutex::new(SemanticConflictState::default()), Condvar::new()));
    let runner = {
        let assignments = assignments.clone();
        let state = Arc::clone(&state);
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut conflict = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if id == "child-b" {
                conflict.blocked_runner_started = true;
            } else if id == "child-c" {
                conflict.child_c_started = true;
                condvar.notify_all();
            } else if id == "child-a" {
                while !conflict.child_c_started {
                    conflict = condvar
                        .wait(conflict)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            drop(conflict);
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        }
    };
    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("semantic Block conflict remains assignment-local");
    assert!(!report.success);
    assert_eq!(
        report
            .orchestrator_reports
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["child-a", "child-c"]
    );
    let conflict = state
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(conflict.child_c_started);
    assert!(!conflict.blocked_runner_started);
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("semantic coordination blocked assignment 'child-b'")));
}

#[test]
fn concurrent_failure_isolated_and_retry_retains_assignment_slot() {
    #[derive(Default)]
    struct RetryState {
        events: Vec<String>,
        child_b_started: bool,
        child_a_retry_started: bool,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "Cargo.toml"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 1);
    let options = injected_options(&repo_path, temp.path(), "concurrent-retry-slot");
    let state = Arc::new((Mutex::new(RetryState::default()), Condvar::new()));
    let runner = {
        let state = Arc::clone(&state);
        let assignments = assignments.clone();
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let file_name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            let attempt = if file_name.contains("attempt-2") {
                2
            } else {
                1
            };
            let (lock, condvar) = &*state;
            let mut retry = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            retry.events.push(format!("{id}-attempt-{attempt}"));
            if id == "child-b" {
                retry.child_b_started = true;
                condvar.notify_all();
                while !retry.child_a_retry_started {
                    retry = condvar
                        .wait(retry)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            if id == "child-a" && attempt == 1 {
                while !retry.child_b_started {
                    retry = condvar
                        .wait(retry)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            if id == "child-a" && attempt == 2 {
                retry.child_a_retry_started = true;
                condvar.notify_all();
            }
            if id == "child-c" {
                assert!(retry.child_a_retry_started);
            }
            drop(retry);

            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            let mut report = injected_child_report(assignment);
            if id == "child-a" && attempt == 1 {
                report.id = "wrong-id".to_string();
            }
            write_injected_json(&command.output_last_message, &report);
            injected_verified_run(command)
        }
    };

    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("run retry slot scheduler");
    assert!(report.success, "unexpected failed report: {report:#?}");
    assert_eq!(
        report
            .orchestrator_reports
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["child-a", "child-b", "child-c"]
    );
    let retry = state
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let retry_start = retry
        .events
        .iter()
        .position(|event| event == "child-a-attempt-2")
        .expect("child A retry start");
    let child_c_start = retry
        .events
        .iter()
        .position(|event| event == "child-c-attempt-1")
        .expect("child C start");
    assert!(retry_start < child_c_start, "{:?}", retry.events);

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("failed-child", "README.md"),
        injected_named_assignment("healthy-child", "src/lib.rs"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "concurrent-failure-isolation");
    let started = Arc::new(Mutex::new(BTreeSet::new()));
    let runner = {
        let started = Arc::clone(&started);
        let assignments = assignments.clone();
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            started
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(id.clone());
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            let mut report = injected_child_report(assignment);
            if id == "failed-child" {
                report.accepted = false;
                report.rejected = true;
                report.status = ReviewStatus::Failed;
            }
            write_injected_json(&command.output_last_message, &report);
            injected_verified_run(command)
        }
    };
    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("normal child failure remains a finalized report");
    assert!(!report.success);
    assert!(report.breaker_trip.is_none());
    assert_eq!(report.orchestrator_reports.len(), 2);
    assert_eq!(
        started
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len(),
        2
    );
}

#[test]
fn cascade_breaker_stops_admission_drains_active_and_releases_claims() {
    #[derive(Default)]
    struct BreakerState {
        started: BTreeSet<String>,
        release_child_d: bool,
        child_d_finished: bool,
        child_d_observed_cancellation: bool,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "Cargo.toml"),
        injected_named_assignment("child-d", "RELEASE_NOTES.md"),
        injected_named_assignment("child-e", "SECURITY.md"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "circuit-breaker-cascade");
    let state = Arc::new((Mutex::new(BreakerState::default()), Condvar::new()));
    let runner = {
        let assignments = assignments.clone();
        let state = Arc::clone(&state);
        move |command: &ExternalAgentCommand,
              cancellation: &ProcessCancellation,
              _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            breaker.started.insert(id.clone());
            condvar.notify_all();
            if id == "child-b" {
                while !breaker.started.contains("child-c") {
                    breaker = condvar
                        .wait(breaker)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-c" {
                while !breaker.started.contains("child-d") {
                    breaker = condvar
                        .wait(breaker)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-d" {
                while !breaker.release_child_d {
                    breaker.child_d_observed_cancellation |= cancellation.is_cancelled();
                    breaker = condvar
                        .wait(breaker)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            drop(breaker);

            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            let mut report = injected_child_report(assignment);
            if matches!(id.as_str(), "child-a" | "child-b" | "child-c") {
                report.accepted = false;
                report.rejected = true;
                report.status = ReviewStatus::Rejected;
            }
            write_injected_json(&command.output_last_message, &report);
            let run = injected_verified_run(command);
            if id == "child-d" {
                let mut breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                breaker.child_d_finished = true;
                condvar.notify_all();
            }
            run
        }
    };

    let (done_sender, done_receiver) = mpsc::channel();
    let supervisor_thread = thread::spawn(move || {
        let result = run_supervisor_plan_with_concurrent_cancellable_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        );
        let _ = done_sender.send(result);
    });

    let event_path = repo_path
        .join(".maco/o2/runs/circuit-breaker-cascade")
        .join(ORCHESTRATION_EVENT_PATH);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let breaker_recorded = fs::read_to_string(&event_path)
            .is_ok_and(|events| events.contains("swarm_health_circuit_breaker"));
        if breaker_recorded {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "breaker transition was not journaled before the deadline"
        );
        thread::sleep(Duration::from_millis(5));
    }

    let (lock, condvar) = &*state;
    let mut breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(breaker.started.contains("child-d"));
    assert!(!breaker.started.contains("child-e"));
    assert!(!breaker.child_d_finished);
    assert!(!breaker.child_d_observed_cancellation);
    assert!(matches!(
        done_receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    breaker.release_child_d = true;
    condvar.notify_all();
    drop(breaker);

    let report = done_receiver
        .recv()
        .expect("supervisor breaker result after active child drain")
        .expect("breaker trip remains reportable");
    supervisor_thread
        .join()
        .unwrap_or_else(|_| panic!("supervisor test thread panicked"));

    assert!(!report.success);
    assert_eq!(report.orchestrator_reports.len(), 4);
    assert_eq!(report.commands_run.len(), 4);
    assert_eq!(report.released_claims.len(), 4);
    assert!(report.release_errors.is_empty());
    assert!(matches!(
        report.breaker_trip.as_ref().map(|trip| &trip.reason),
        Some(CircuitBreakerTripReason::RepeatedRejectionLoop {
            rejections: 3,
            retries: 0,
            threshold: 3,
        })
    ));
    assert!(report
        .breaker_trip
        .as_ref()
        .is_some_and(|trip| trip.window.repeated_rejections == 3
            && trip
                .recovery_guidance
                .contains("pending assignments were not launched")));
    assert!(report
        .run_budget
        .as_ref()
        .is_some_and(|budget| { budget.active_reservations == 0 && budget.new_dispatch_allowed }));
    let breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(breaker.child_d_finished);
    assert!(!breaker.child_d_observed_cancellation);
    assert!(!breaker.started.contains("child-e"));
    drop(breaker);
    assert!(SyncStore::open(&repo_path)
        .expect("open claims after breaker drain")
        .snapshot()
        .expect("snapshot claims after breaker drain")
        .is_empty());

    let run_id = RunId::new("circuit-breaker-cascade").expect("valid breaker run id");
    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized breaker artifacts");
    let events = read_finalized_orchestration_events(&reader);
    assert!(events.iter().any(|event| {
        event.kind == OrchestrationEventKind::Gate
            && event.payload["gate"] == "swarm_health_circuit_breaker"
            && event.payload["transition"] == "closed_to_open"
            && event.payload["trip"]["reason"]["kind"] == "repeated_rejection_loop"
    }));
}

#[test]
fn contained_nonzero_child_failure_does_not_stop_pending_unrelated_assignment() {
    #[derive(Default)]
    struct FailureState {
        child_b_started: bool,
        child_c_started: bool,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "Cargo.toml"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "contained-nonzero-isolation");
    let state = Arc::new((Mutex::new(FailureState::default()), Condvar::new()));
    let runner = {
        let assignments = assignments.clone();
        let state = Arc::clone(&state);
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut failure = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if id == "child-b" {
                failure.child_b_started = true;
                condvar.notify_all();
                while !failure.child_c_started {
                    failure = condvar
                        .wait(failure)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-a" {
                while !failure.child_b_started {
                    failure = condvar
                        .wait(failure)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-c" {
                failure.child_c_started = true;
                condvar.notify_all();
            }
            drop(failure);

            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            if id == "child-a" {
                let run = injected_verified_nonzero_run(command, 7);
                assert!(external_safety_verified(&run, SupervisorRuntime::Codex));
                assert!(run.codex_permissions.is_some());
                assert!(!run.publishable);
                assert!(!run.succeeded());
                run
            } else {
                injected_verified_run(command)
            }
        }
    };

    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("contained child failure remains reportable");
    assert!(!report.success);
    assert_eq!(
        report
            .orchestrator_reports
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec!["child-a", "child-b", "child-c"]
    );
    assert!(
        state
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .child_c_started
    );
    assert!(report
        .findings
        .iter()
        .all(|finding| !finding.message.contains("containment was not verified")));
}

#[test]
fn fatal_scheduler_abort_stops_new_starts_and_joins_active_assignment() {
    #[derive(Default)]
    struct AbortState {
        child_a_returned: bool,
        child_b_started: bool,
        release_child_b: bool,
        child_c_started: bool,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "README.md/blocked-after-fatal"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "concurrent-fatal-join");
    let state = Arc::new((Mutex::new(AbortState::default()), Condvar::new()));
    let runner = {
        let state = Arc::clone(&state);
        let assignments = assignments.clone();
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if id == "child-b" {
                abort.child_b_started = true;
                condvar.notify_all();
                while !abort.release_child_b {
                    abort = condvar
                        .wait(abort)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-a" {
                while !abort.child_b_started {
                    abort = condvar
                        .wait(abort)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-c" {
                abort.child_c_started = true;
            }
            drop(abort);

            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            let mut run = injected_verified_run(command);
            if id == "child-a" {
                run.process_tree = Some(ProcessTreeEvidence::Unverified(
                    ContainmentBackend::SystemdUserService,
                ));
                let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                abort.child_a_returned = true;
                condvar.notify_all();
            }
            run
        }
    };
    let (done_sender, done_receiver) = mpsc::channel();
    let supervisor_thread = thread::spawn(move || {
        let result = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        );
        let _ = done_sender.send(result);
    });

    let (lock, condvar) = &*state;
    let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    while !abort.child_a_returned {
        abort = condvar
            .wait(abort)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    assert!(!abort.child_c_started);
    assert!(matches!(
        done_receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    abort.release_child_b = true;
    condvar.notify_all();
    drop(abort);

    let report = done_receiver
        .recv()
        .expect("supervisor result after active child release")
        .expect("fatal containment result remains reportable");
    supervisor_thread
        .join()
        .unwrap_or_else(|_| panic!("supervisor test thread panicked"));
    assert!(!report.success);
    let abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(!abort.child_c_started);
    assert_eq!(report.orchestrator_reports.len(), 2);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("containment")));
}

#[test]
fn fatal_scheduler_abort_cancels_active_sibling_without_manual_release() {
    #[derive(Default)]
    struct AbortState {
        child_b_started: bool,
        child_b_observed_cancellation: bool,
        child_c_started: bool,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "README.md/blocked-after-fatal"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "concurrent-fatal-cancels-active");
    let state = Arc::new((Mutex::new(AbortState::default()), Condvar::new()));
    let runner = {
        let state = Arc::clone(&state);
        let assignments = assignments.clone();
        move |command: &ExternalAgentCommand,
              cancellation: &ProcessCancellation,
              _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            if id == "child-b" {
                {
                    let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    abort.child_b_started = true;
                    condvar.notify_all();
                }
                while !cancellation.is_cancelled() {
                    thread::sleep(Duration::from_millis(1));
                }
                lock.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .child_b_observed_cancellation = true;
            } else if id == "child-a" {
                let mut abort = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                while !abort.child_b_started {
                    abort = condvar
                        .wait(abort)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-c" {
                lock.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .child_c_started = true;
            }

            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            let mut run = injected_verified_run(command);
            if id == "child-a" {
                run.process_tree = Some(ProcessTreeEvidence::Unverified(
                    ContainmentBackend::SystemdUserService,
                ));
            } else if id == "child-b" {
                run.exit_code = None;
                run.error = Some("cancelled by scheduler".to_string());
            }
            run
        }
    };

    let report = run_supervisor_plan_with_concurrent_cancellable_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("fatal containment result remains reportable");

    assert!(!report.success);
    let abort = state
        .0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(abort.child_b_observed_cancellation);
    assert!(!abort.child_c_started);
    assert_eq!(report.orchestrator_reports.len(), 2);
}

#[test]
fn concurrent_release_error_stops_new_starts_and_joins_active_assignment() {
    #[derive(Default)]
    struct ReleaseState {
        child_a_returned: bool,
        child_b_started: bool,
        release_child_b: bool,
        child_c_started: bool,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "README.md/blocked-after-release-error"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "concurrent-release-error-abort");
    let state = Arc::new((Mutex::new(ReleaseState::default()), Condvar::new()));
    let runner_repo = repo_path.clone();
    let runner = {
        let assignments = assignments.clone();
        let state = Arc::clone(&state);
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut release = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if id == "child-b" {
                release.child_b_started = true;
                condvar.notify_all();
                while !release.release_child_b {
                    release = condvar
                        .wait(release)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-a" {
                while !release.child_b_started {
                    release = condvar
                        .wait(release)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-c" {
                release.child_c_started = true;
            }
            drop(release);

            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            let run = injected_verified_run(command);
            if id == "child-a" {
                let store = SyncStore::open(&runner_repo).expect("open injected sync store");
                let claim = store
                    .snapshot()
                    .expect("snapshot injected claims")
                    .into_iter()
                    .find(|claim| claim.agent_id == id)
                    .expect("find child A claim");
                store
                    .release(claim.token)
                    .expect("inject scheduler release failure");
                let mut release = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                release.child_a_returned = true;
                condvar.notify_all();
            }
            run
        }
    };
    let (done_sender, done_receiver) = mpsc::channel();
    let supervisor_thread = thread::spawn(move || {
        let result = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        );
        let _ = done_sender.send(result);
    });

    let (lock, condvar) = &*state;
    let mut release = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    while !release.child_a_returned {
        release = condvar
            .wait(release)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    assert!(!release.child_c_started);
    assert!(matches!(
        done_receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    release.release_child_b = true;
    condvar.notify_all();
    drop(release);

    let report = done_receiver
        .recv()
        .expect("supervisor result after release-error join")
        .expect("release error remains reportable");
    supervisor_thread
        .join()
        .unwrap_or_else(|_| panic!("supervisor test thread panicked"));
    assert!(!report.success);
    assert!(
        !lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .child_c_started
    );
    assert_eq!(report.orchestrator_reports.len(), 2);
    assert_eq!(report.release_errors.len(), 1);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("cleanup failed")));
    assert!(SyncStore::open(&repo_path)
        .expect("reopen sync store")
        .snapshot()
        .expect("snapshot released claims")
        .is_empty());
}

#[test]
fn panic_after_claim_releases_tokens_stops_pending_and_joins_active_assignment() {
    #[derive(Default)]
    struct PanicState {
        child_a_panicking: bool,
        child_b_started: bool,
        release_child_b: bool,
        child_c_started: bool,
    }

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("child-a", "README.md"),
        injected_named_assignment("child-b", "src/lib.rs"),
        injected_named_assignment("child-c", "README.md/blocked-after-panic"),
    ];
    let mut plan = injected_multi_plan(assignments.clone(), 0);
    plan.semantic_coordination = SemanticCoordinationMode::Block;
    let options = injected_options(&repo_path, temp.path(), "concurrent-panic-token-release");
    let state = Arc::new((Mutex::new(PanicState::default()), Condvar::new()));
    let runner = {
        let assignments = assignments.clone();
        let state = Arc::clone(&state);
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut panic_state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if id == "child-b" {
                panic_state.child_b_started = true;
                condvar.notify_all();
                while !panic_state.release_child_b {
                    panic_state = condvar
                        .wait(panic_state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            } else if id == "child-a" {
                while !panic_state.child_b_started {
                    panic_state = condvar
                        .wait(panic_state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                panic_state.child_a_panicking = true;
                condvar.notify_all();
                drop(panic_state);
                panic!("injected panic after assignment claim");
            } else if id == "child-c" {
                panic_state.child_c_started = true;
            }
            drop(panic_state);

            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .unwrap_or_else(|| panic!("missing assignment {id}"));
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        }
    };
    let (done_sender, done_receiver) = mpsc::channel();
    let supervisor_thread = thread::spawn(move || {
        let result = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        );
        let _ = done_sender.send(result);
    });

    let (lock, condvar) = &*state;
    let mut panic_state = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    while !panic_state.child_a_panicking {
        panic_state = condvar
            .wait(panic_state)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
    assert!(!panic_state.child_c_started);
    assert!(matches!(
        done_receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    panic_state.release_child_b = true;
    condvar.notify_all();
    drop(panic_state);

    let report = done_receiver
        .recv()
        .expect("supervisor result after panic join")
        .expect("panic remains reportable");
    supervisor_thread
        .join()
        .unwrap_or_else(|_| panic!("supervisor test thread panicked"));
    assert!(!report.success);
    assert!(
        !lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .child_c_started
    );
    assert_eq!(report.orchestrator_reports.len(), 1);
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("supervisor assignment 'child-a' panicked")));
    assert!(SyncStore::open(&repo_path)
        .expect("reopen sync store")
        .snapshot()
        .expect("snapshot released panic claims")
        .is_empty());
    assert!(SemanticIntentStore::open(&repo_path)
        .expect("reopen semantic store")
        .snapshot()
        .expect("snapshot released panic semantic intents")
        .is_empty());
}

#[test]
fn supervise_holds_exclusive_worktree_lease_through_child_and_parent_auditor() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let plan = injected_plan(assignment.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "injected-write-lease");
    let competing_manager = WorktreeManager::new(&repo_path);
    let mut invocation_count = 0usize;
    let mut runner = |command: &ExternalAgentCommand| {
        invocation_count = invocation_count.saturating_add(1);
        let read_error = competing_manager
            .acquire_read_execution_lease(&assignment.id)
            .expect_err("supervise write lease must exclude a concurrent reader");
        assert!(read_error.to_string().contains("shared read lease"));
        let write_error = competing_manager
            .acquire_write_execution_lease(&assignment.id)
            .expect_err("supervise write lease must exclude a concurrent writer");
        assert!(write_error.to_string().contains("exclusive write lease"));
        let remove_error = competing_manager
            .remove(&assignment.id, true, false)
            .expect_err("supervise write lease must exclude managed removal");
        assert!(remove_error
            .to_string()
            .contains("active cooperative execution lease"));

        let output_name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        let lifecycle = command
            .agent_lifecycle
            .as_ref()
            .expect("supervise provider command must carry lifecycle identity");
        assert_eq!(lifecycle.registry_repo, repo_path);
        assert_eq!(lifecycle.run_id, "injected-write-lease");
        if output_name.contains("review-auditor") {
            assert_eq!(lifecycle.role, "auditor");
            assert_eq!(lifecycle.task_id, parent_auditor_id(&assignment));
            let child = injected_child_report(&assignment);
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
        } else {
            assert_eq!(lifecycle.role, "child_orchestrator");
            assert_eq!(lifecycle.task_id, assignment.id);
            write_injected_json(
                &command.output_last_message,
                &injected_child_report(&assignment),
            );
        }
        injected_verified_run(command)
    };

    let report = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("run write-lease regression");
    assert!(report.success, "unexpected failed report: {report:#?}");
    assert_eq!(invocation_count, 2, "child and parent auditor must run");
    let read_after = competing_manager
        .acquire_read_execution_lease(&assignment.id)
        .expect("read lease must be available after supervise lifecycle");
    assert_eq!(read_after.record().name, assignment.id);
}

#[test]
fn injected_runner_path_violation_blocks_retry_and_primary_mutations_fail_integrity_gate() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(false);
    let plan = injected_plan(assignment.clone(), 1);
    let options = injected_options(&repo_path, temp.path(), "injected-path-violation");
    let mut invocations = Vec::new();
    let mut runner = |command: &ExternalAgentCommand| {
        invocations.push(
            command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string(),
        );
        fs::write(command.cwd.join("outside.txt"), "unauthorized\n")
            .expect("write unauthorized child path");
        let mut child = injected_child_report(&assignment);
        child.id = "wrong-id".to_string();
        child.files_changed = vec![PathBuf::from("outside.txt")];
        write_injected_json(&command.output_last_message, &child);
        injected_verified_run(command)
    };
    let report = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("run injected path violation");
    assert!(!report.success);
    assert!(!invocations
        .iter()
        .any(|name| name.ends_with("attempt-2.json")));
    assert!(
        finding_messages(&report.orchestrator_reports[0]).contains("outside its assigned paths")
    );

    for scenario in ["tracked", "untracked", "index", "commit"] {
        let (temp, repo_path) = injected_repository();
        let assignment = injected_assignment(false);
        let plan = injected_plan(assignment.clone(), 0);
        let options = injected_options(
            &repo_path,
            temp.path(),
            &format!("injected-primary-{scenario}"),
        );
        let primary = repo_path.clone();
        let mut runner = |command: &ExternalAgentCommand| {
            write_injected_json(
                &command.output_last_message,
                &injected_child_report(&assignment),
            );
            match scenario {
                "tracked" => fs::write(primary.join("README.md"), "mutated\n")
                    .expect("mutate tracked primary"),
                "untracked" => fs::write(primary.join("rogue.txt"), "mutated\n")
                    .expect("mutate untracked primary"),
                "index" => fs::write(primary.join(".git/index"), b"invalid-index")
                    .expect("mutate primary index"),
                "commit" => {
                    fs::write(primary.join("README.md"), "committed mutation\n")
                        .expect("write commit mutation");
                    commit_injected_repository(&primary, "primary mutation");
                }
                _ => unreachable!(),
            }
            injected_verified_run(command)
        };
        let report = run_supervisor_plan_with_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &mut runner,
        )
        .expect("run injected primary mutation");
        assert!(
            !report.success,
            "scenario {scenario} escaped integrity gate"
        );
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.message.contains("primary")));
        assert!(report.release_errors.is_empty());
    }
}
