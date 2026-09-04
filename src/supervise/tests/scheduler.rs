use super::*;
use std::io::Write;
use std::sync::atomic::AtomicBool;

#[derive(Debug)]
enum ConcurrencyFixtureWaitError {
    TimedOut {
        test: &'static str,
        run_id: &'static str,
        stage: &'static str,
        bound: Duration,
    },
    ChannelDisconnected {
        test: &'static str,
        run_id: &'static str,
        stage: &'static str,
        bound: Duration,
    },
}

impl std::fmt::Display for ConcurrencyFixtureWaitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut {
                test,
                run_id,
                stage,
                bound,
            } => write!(
                formatter,
                "concurrency fixture wait timed out: test={test} run_id={run_id} stage={stage} bound={bound:?}"
            ),
            Self::ChannelDisconnected {
                test,
                run_id,
                stage,
                bound,
            } => write!(
                formatter,
                "concurrency fixture channel disconnected: test={test} run_id={run_id} stage={stage} bound={bound:?}"
            ),
        }
    }
}

fn fixture_wait_timed_out(
    test: &'static str,
    run_id: &'static str,
    stage: &'static str,
    bound: Duration,
) -> ! {
    panic!(
        "{}",
        ConcurrencyFixtureWaitError::TimedOut {
            test,
            run_id,
            stage,
            bound,
        }
    )
}

fn recv_fixture_stage<T>(
    receiver: &mpsc::Receiver<T>,
    test: &'static str,
    run_id: &'static str,
    stage: &'static str,
    bound: Duration,
) -> T {
    match receiver.recv_timeout(bound) {
        Ok(value) => value,
        Err(mpsc::RecvTimeoutError::Timeout) => fixture_wait_timed_out(test, run_id, stage, bound),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
            "{}",
            ConcurrencyFixtureWaitError::ChannelDisconnected {
                test,
                run_id,
                stage,
                bound,
            }
        ),
    }
}

fn wait_for_fixture_state<'a, T>(
    condvar: &Condvar,
    state: std::sync::MutexGuard<'a, T>,
    ready: impl Fn(&T) -> bool,
    test: &'static str,
    run_id: &'static str,
    stage: &'static str,
    bound: Duration,
) -> std::sync::MutexGuard<'a, T> {
    let (state, _) = condvar
        .wait_timeout_while(state, bound, |state| !ready(state))
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !ready(&state) {
        fixture_wait_timed_out(test, run_id, stage, bound);
    }
    state
}

fn fixture_condition_reached(ready: impl Fn() -> bool, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    loop {
        if ready() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_fixture_condition(
    ready: impl Fn() -> bool,
    test: &'static str,
    run_id: &'static str,
    stage: &'static str,
    bound: Duration,
) {
    if !fixture_condition_reached(ready, bound) {
        fixture_wait_timed_out(test, run_id, stage, bound);
    }
}

fn wait_for_fixture_file_marker(
    path: &Path,
    marker: &str,
    test: &'static str,
    run_id: &'static str,
    stage: &'static str,
    bound: Duration,
) {
    let deadline = Instant::now() + bound;
    loop {
        if fs::read_to_string(path).is_ok_and(|contents| contents.contains(marker)) {
            return;
        }
        if Instant::now() >= deadline {
            fixture_wait_timed_out(test, run_id, stage, bound);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_fixture_thread_finish<T>(
    handle: &thread::JoinHandle<T>,
    test: &'static str,
    run_id: &'static str,
    stage: &'static str,
    bound: Duration,
) {
    wait_for_fixture_condition(|| handle.is_finished(), test, run_id, stage, bound);
}

struct UnwindCleanup<F: FnOnce()> {
    action: Option<F>,
}

impl<F: FnOnce()> UnwindCleanup<F> {
    fn new(action: F) -> Self {
        Self {
            action: Some(action),
        }
    }

    fn run(&mut self) {
        if let Some(action) = self.action.take() {
            action();
        }
    }
}

impl<F: FnOnce()> Drop for UnwindCleanup<F> {
    fn drop(&mut self) {
        self.run();
    }
}

struct SupervisorThreadGuard<T, F: FnOnce()> {
    handle: Option<thread::JoinHandle<T>>,
    release_fixture: Option<F>,
    test: &'static str,
    run_id: &'static str,
    cleanup_stage: &'static str,
    cleanup_bound: Duration,
}

impl<T, F: FnOnce()> SupervisorThreadGuard<T, F> {
    fn new(
        handle: thread::JoinHandle<T>,
        release_fixture: F,
        test: &'static str,
        run_id: &'static str,
        cleanup_stage: &'static str,
        cleanup_bound: Duration,
    ) -> Self {
        Self {
            handle: Some(handle),
            release_fixture: Some(release_fixture),
            test,
            run_id,
            cleanup_stage,
            cleanup_bound,
        }
    }

    fn release_fixture(&mut self) {
        if let Some(release_fixture) = self.release_fixture.take() {
            release_fixture();
        }
    }

    fn is_finished(&self) -> bool {
        self.handle
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
    }

    fn join(mut self, stage: &'static str, bound: Duration) -> thread::Result<T> {
        wait_for_fixture_thread_finish(
            self.handle
                .as_ref()
                .expect("supervisor thread handle must be owned until join"),
            self.test,
            self.run_id,
            stage,
            bound,
        );
        let handle = self
            .handle
            .take()
            .expect("finished supervisor thread handle must still be owned");
        debug_assert!(handle.is_finished());
        handle.join()
    }
}

impl<T, F: FnOnce()> Drop for SupervisorThreadGuard<T, F> {
    fn drop(&mut self) {
        self.release_fixture();
        if let Some(handle) = self.handle.as_ref() {
            if !fixture_condition_reached(|| handle.is_finished(), self.cleanup_bound) {
                let _ = writeln!(
                    std::io::stderr(),
                    "{}",
                    ConcurrencyFixtureWaitError::TimedOut {
                        test: self.test,
                        run_id: self.run_id,
                        stage: self.cleanup_stage,
                        bound: self.cleanup_bound,
                    }
                );
                return;
            }
        }
        if self
            .handle
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
        {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

#[test]
fn concurrent_disjoint_assignments_make_progress_and_finalize_in_plan_order() {
    skip_without_containment!();
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
fn network_auto_policy_serializes_overlap_without_head_of_line_blocking() {
    let plan = injected_multi_plan(
        vec![
            injected_named_assignment("child-a", "src"),
            injected_named_assignment("child-b", "src/lib.rs"),
            injected_named_assignment("child-c", "README.md"),
        ],
        0,
    );
    let schedule = plan
        .assignments
        .iter()
        .enumerate()
        .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index,
        })
        .collect::<Vec<_>>();
    let outcomes = (0..plan.assignments.len())
        .map(|_| None)
        .collect::<Vec<Option<AssignmentExecutionOutcome>>>();
    let mut pending = BTreeSet::from([0, 1, 2]);
    let mut active = BTreeSet::new();

    let auto_bound =
        SupervisorConcurrencyPolicy::Auto.resolve(HostProcessCapacity::from_parallelism(
            NonZeroUsize::new(2).expect("test capacity is non-zero"),
        ));
    assert_eq!(auto_bound, 4);

    // Exercise the exact selector used by concurrent admission without coupling this scheduler
    // invariant to the environment-bound candidate capture and report-binding pipeline.
    let select = |pending: &BTreeSet<usize>, active: &BTreeSet<usize>| {
        super::super::scheduler::select_ready_nonoverlapping_assignment(
            pending,
            &schedule,
            &outcomes,
            &plan,
            active.iter().copied(),
        )
        .expect("select overlap-aware assignment")
    };

    assert_eq!(select(&pending, &active), Some(0));
    pending.remove(&0);
    active.insert(0);

    // B overlaps active A, so admission must scan ahead and start disjoint C.
    assert_eq!(select(&pending, &active), Some(2));
    pending.remove(&2);
    active.insert(2);
    assert!(active.len() < auto_bound);

    // B remains serialized behind A even after C finishes, then becomes ready with A complete.
    assert_eq!(select(&pending, &active), None);
    active.remove(&2);
    assert_eq!(select(&pending, &active), None);

    active.remove(&0);
    assert_eq!(select(&pending, &active), Some(1));
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
    skip_without_containment!();
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
    skip_without_containment!();
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
    skip_without_containment!();
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
    let retained_run = RunId::new("retained-claim-run").expect("valid retained run id");
    let external_claim = sync_store
        .claim_paths_for_run(
            &retained_run,
            "external-owner",
            [PathBuf::from("README.md")],
        )
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
    let blocking_finding = report
        .findings
        .iter()
        .find(|finding| finding.message.contains("failed to claim paths"))
        .expect("claim conflict must produce a named blocking finding");
    assert!(blocking_finding.message.contains("external-owner"));
    assert!(blocking_finding
        .message
        .contains(&format!("token {}", external_claim.token.get())));
    assert!(blocking_finding.message.contains("run retained-claim-run"));
    assert!(blocking_finding.message.contains("owner_run_state=active"));
    assert!(report
        .gate_denials
        .iter()
        .any(|denial| denial.reason == GateDenialReason::ClaimConflict));

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

#[cfg(target_os = "linux")]
#[test]
fn external_termination_named_conflict_release_and_reacquisition_form_one_recovery_sequence() {
    skip_without_containment!();
    const HOLDER_PROCESS_ENV: &str = "MACO_ISSUE51_SUPERVISE_HOLDER_PROCESS";
    const HOLDER_REPO_ENV: &str = "MACO_ISSUE51_SUPERVISE_HOLDER_REPO";
    const HOLDER_ROOT_ENV: &str = "MACO_ISSUE51_SUPERVISE_HOLDER_ROOT";
    const HOLDER_READY_ENV: &str = "MACO_ISSUE51_SUPERVISE_HOLDER_READY";

    if std::env::var_os(HOLDER_PROCESS_ENV).is_some() {
        let repo_path = PathBuf::from(
            std::env::var_os(HOLDER_REPO_ENV).expect("holder subprocess repository path"),
        );
        let root = PathBuf::from(
            std::env::var_os(HOLDER_ROOT_ENV).expect("holder subprocess fixture root"),
        );
        let ready = PathBuf::from(
            std::env::var_os(HOLDER_READY_ENV).expect("holder subprocess ready marker"),
        );
        let assignment = injected_named_assignment("interrupted-scope", "README.md");
        let plan = injected_multi_plan(vec![assignment], 0);
        let options = injected_options(&repo_path, &root, "externally-terminated-run");
        let runner = move |_command: &ExternalAgentCommand| -> ExternalAgentRun {
            fs::write(&ready, b"claim acquired\n").expect("publish holder readiness");
            loop {
                std::thread::park_timeout(Duration::from_secs(60));
            }
        };
        let result = run_supervisor_plan_with_concurrent_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            1,
            &runner,
        );
        panic!("holder supervise run returned before external termination: {result:#?}");
    }

    struct KillOnDrop(Option<std::process::Child>);

    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    let (temp, repo_path) = injected_repository();
    let ready = temp.path().join("issue-51-supervise-holder-ready");
    let holder = std::process::Command::new(
        std::env::current_exe().expect("resolve current supervise test executable"),
    )
        .args([
            "--exact",
            "supervise::tests::scheduler::external_termination_named_conflict_release_and_reacquisition_form_one_recovery_sequence",
            "--nocapture",
        ])
        .env(HOLDER_PROCESS_ENV, "1")
        .env(HOLDER_REPO_ENV, &repo_path)
        .env(HOLDER_ROOT_ENV, temp.path())
        .env(HOLDER_READY_ENV, &ready)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn real supervise holder process");
    let mut holder = KillOnDrop(Some(holder));
    let holder_pid = holder.0.as_ref().expect("live holder process").id();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "real supervise holder did not reach its production dispatch path"
        );
        let status = holder
            .0
            .as_mut()
            .expect("live holder process")
            .try_wait()
            .expect("inspect supervise holder process");
        assert!(
            status.is_none(),
            "real supervise holder exited before external termination: {status:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let store = SyncStore::open(&repo_path).expect("open recovery-sequence sync store");
    let live = store
        .status_snapshot()
        .expect("inspect production claim before external termination");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].claim.agent_id, "interrupted-scope");
    assert_eq!(
        live[0].owner_run_id.as_deref(),
        Some("externally-terminated-run")
    );
    assert_eq!(live[0].owner_process_id, Some(holder_pid));
    assert_eq!(
        live[0].owner_run_state,
        crate::sync_store::ClaimOwnerRunState::Active
    );
    let retained = live[0].claim.clone();

    let mut holder_process = holder.0.take().expect("take supervise holder process");
    holder_process
        .kill()
        .expect("externally terminate supervise holder process");
    holder_process
        .wait()
        .expect("reap supervise holder process");

    let leftover = store
        .status_snapshot()
        .expect("inspect claim after external termination");
    assert_eq!(leftover.len(), 1);
    assert_eq!(leftover[0].claim, retained);
    assert_eq!(
        leftover[0].owner_run_state,
        crate::sync_store::ClaimOwnerRunState::Interrupted
    );

    let blocked_assignment = injected_named_assignment("blocked-retry", "README.md");
    let blocked_plan = injected_multi_plan(vec![blocked_assignment.clone()], 0);
    let blocked_options = injected_options(
        &repo_path,
        temp.path(),
        "external-termination-blocked-retry",
    );
    let blocked_runner = move |command: &ExternalAgentCommand| {
        write_injected_assignment_report(command, &blocked_assignment);
        injected_verified_run(command)
    };
    let blocked = run_supervisor_plan_with_concurrent_runner(
        blocked_plan,
        SupervisorConsultantPlan::default(),
        blocked_options,
        1,
        &blocked_runner,
    )
    .expect("retained claim produces a reportable typed refusal");
    let conflict = blocked
        .findings
        .iter()
        .find(|finding| finding.message.contains("failed to claim paths"))
        .expect("reacquisition must name the blocking claim");
    assert!(conflict.message.contains("interrupted-scope"));
    assert!(conflict
        .message
        .contains(&format!("token {}", retained.token.get())));
    assert!(conflict.message.contains("run externally-terminated-run"));
    assert!(conflict.message.contains("owner_run_state=interrupted"));
    assert!(blocked
        .gate_denials
        .iter()
        .any(|denial| denial.reason == GateDenialReason::ClaimConflict));

    assert_eq!(
        store
            .release(retained.token)
            .expect("explicitly release interrupted claim"),
        retained
    );

    let recovered_assignment = injected_named_assignment("recovered-retry", "README.md");
    let recovered_plan = injected_multi_plan(vec![recovered_assignment.clone()], 0);
    let recovered_options = injected_options(
        &repo_path,
        temp.path(),
        "external-termination-recovered-retry",
    );
    let recovered_runner = move |command: &ExternalAgentCommand| {
        write_injected_assignment_report(command, &recovered_assignment);
        injected_verified_run(command)
    };
    let recovered = run_supervisor_plan_with_concurrent_runner(
        recovered_plan,
        SupervisorConsultantPlan::default(),
        recovered_options,
        1,
        &recovered_runner,
    )
    .expect("reacquisition after explicit disposition succeeds");
    assert!(recovered.success, "recovered run failed: {recovered:#?}");
    assert_eq!(recovered.released_claims.len(), 1);
    assert_eq!(recovered.released_claims[0].agent_id, "recovered-retry");
}

#[test]
fn concurrent_failure_isolated_and_retry_retains_assignment_slot() {
    skip_without_containment!();
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
fn nonaccepted_run_releases_claim_and_followup_reacquires_same_path() {
    skip_without_containment!();
    let (temp, repo_path) = injected_repository();
    let failed_assignment = injected_named_assignment("failed-scope", "README.md");
    let failed_plan = injected_multi_plan(vec![failed_assignment.clone()], 0);
    let failed_options = injected_options(&repo_path, temp.path(), "claim-disposition-nonaccepted");
    let failed_runner = move |command: &ExternalAgentCommand| {
        let mut report = injected_child_report(&failed_assignment);
        report.accepted = false;
        report.rejected = true;
        report.status = ReviewStatus::Failed;
        write_injected_json(&command.output_last_message, &report);
        injected_verified_run(command)
    };

    let failed_report = run_supervisor_plan_with_concurrent_runner(
        failed_plan,
        SupervisorConsultantPlan::default(),
        failed_options,
        1,
        &failed_runner,
    )
    .expect("nonaccepted run remains reportable");

    assert!(!failed_report.success);
    assert_eq!(failed_report.released_claims.len(), 1);
    assert_eq!(failed_report.released_claims[0].agent_id, "failed-scope");
    assert!(failed_report.release_errors.is_empty());
    let store = SyncStore::open(&repo_path).expect("reopen claims after nonaccepted run");
    assert!(store
        .status_snapshot()
        .expect("status after nonaccepted run")
        .is_empty());

    let followup_assignment = injected_named_assignment("followup-scope", "README.md");
    let followup_plan = injected_multi_plan(vec![followup_assignment.clone()], 0);
    let followup_options = injected_options(&repo_path, temp.path(), "claim-disposition-followup");
    let followup_runner = move |command: &ExternalAgentCommand| {
        write_injected_assignment_report(command, &followup_assignment);
        injected_verified_run(command)
    };
    let followup_report = run_supervisor_plan_with_concurrent_runner(
        followup_plan,
        SupervisorConsultantPlan::default(),
        followup_options,
        1,
        &followup_runner,
    )
    .expect("followup run reacquires released path");

    assert!(
        followup_report.success,
        "followup run failed to reacquire path: {followup_report:#?}"
    );
    assert_eq!(followup_report.released_claims.len(), 1);
    assert_eq!(
        followup_report.released_claims[0].agent_id,
        "followup-scope"
    );
}

#[test]
fn serial_assignment_terminal_checkpoint_precedes_claim_release() {
    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("serial-terminal-a", "README.md"),
        injected_named_assignment("serial-terminal-b", "README.md"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let run_id = RunId::new("serial-terminal-before-release").expect("valid serial run id");
    let options = injected_options(&repo_path, temp.path(), run_id.as_str());
    let runner = move |command: &ExternalAgentCommand| {
        let id = injected_command_assignment_id(command);
        let assignment = assignments
            .iter()
            .find(|assignment| assignment.id == id)
            .expect("serial checkpoint assignment");
        write_injected_assignment_report(command, assignment);
        injected_verified_run(command)
    };
    install_checkpoint_failure(run_id.as_str(), "after:assignment_completed");

    let _report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        1,
        &runner,
    )
    .expect("checkpoint failure remains reportable after terminal finalization");

    let (_checkpoint, snapshot) =
        open_supervisor_checkpoint(&repo_path, &run_id).expect("open serial terminal checkpoint");
    assert_eq!(snapshot.completed_assignments.len(), 1);
    let completed = &snapshot.completed_assignments[0];
    let store = SyncStore::open(&repo_path).expect("open serial terminal claims");
    let active = store.snapshot().expect("snapshot serial terminal claims");
    let retained = active
        .iter()
        .find(|claim| &claim.agent_id == completed)
        .expect("journaled serial assignment claim must remain active before release");
    store
        .release(retained.token)
        .expect("release retained serial terminal claim");
}

#[test]
fn degraded_manifest_boundary_finalization_still_releases_serial_claims() {
    skip_without_containment!();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_named_assignment("degraded-serial", "README.md");
    let plan = injected_multi_plan(vec![assignment.clone()], 0);
    let options = injected_options(&repo_path, temp.path(), "degraded-serial-release");
    let runner = move |command: &ExternalAgentCommand| {
        write_injected_assignment_report(command, &assignment);
        injected_verified_run(command)
    };
    set_force_degraded_checkpoint_finalization();

    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        1,
        &runner,
    )
    .expect("degraded finalization remains reportable");

    assert!(report.success, "degraded finalization report: {report:#?}");
    assert_eq!(report.released_claims.len(), 1);
    assert_eq!(report.released_claims[0].agent_id, "degraded-serial");
    assert!(report.release_errors.is_empty());
    assert!(SyncStore::open(&repo_path)
        .expect("open claims after degraded finalization")
        .snapshot()
        .expect("snapshot claims after degraded finalization")
        .is_empty());
}

#[test]
fn admission_commit_recv_failure_cancels_and_drains_active_assignments() {
    const TEST: &str = "admission_commit_recv_failure_cancels_and_drains_active_assignments";
    const RUN_ID: &str = "admission-recv-drain";
    const WAIT_BOUND: Duration = Duration::from_secs(30);
    const SUPERVISOR_REAP_BOUND: Duration = Duration::from_secs(60);

    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("admit-a", "README.md"),
        injected_named_assignment("admit-b", "src/lib.rs"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), RUN_ID);
    let cancelled_active = Arc::new(AtomicUsize::new(0));
    let runner_unwind_release = Arc::new(AtomicBool::new(false));
    let (runner_started_sender, runner_started_receiver) = mpsc::channel();
    let runner = {
        let assignments = assignments.clone();
        let cancelled_active = Arc::clone(&cancelled_active);
        let runner_unwind_release = Arc::clone(&runner_unwind_release);
        move |command: &ExternalAgentCommand,
              cancellation: &ProcessCancellation,
              _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
              _authorization: SupervisorProcessLaunchAuthorization| {
            let id = injected_command_assignment_id(command);
            if id == "admit-a" {
                let _ = runner_started_sender.send(());
                wait_for_fixture_condition(
                    || cancellation.is_cancelled() || runner_unwind_release.load(Ordering::SeqCst),
                    TEST,
                    RUN_ID,
                    "admit-a observes cancellation or unwind release",
                    WAIT_BOUND,
                );
                if cancellation.is_cancelled() {
                    cancelled_active.fetch_add(1, Ordering::SeqCst);
                }
            }
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .expect("admission drain assignment");
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        }
    };
    set_abort_admission_commit_on_spawn(&options.run_id, 2);
    let injection_run_id = options.run_id.clone();
    let injection_cleanup = UnwindCleanup::new(move || {
        set_abort_admission_commit_on_spawn(&injection_run_id, 0);
    });

    let supervisor_handle = thread::spawn(move || {
        let _injection_cleanup = injection_cleanup;
        let result = run_supervisor_plan_with_concurrent_cancellable_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        );
        (temp, result)
    });
    let supervisor_thread = SupervisorThreadGuard::new(
        supervisor_handle,
        {
            let runner_unwind_release = Arc::clone(&runner_unwind_release);
            move || runner_unwind_release.store(true, Ordering::SeqCst)
        },
        TEST,
        RUN_ID,
        "reap supervisor after admission test unwind",
        SUPERVISOR_REAP_BOUND,
    );

    recv_fixture_stage(
        &runner_started_receiver,
        TEST,
        RUN_ID,
        "admit-a runner-entry milestone",
        WAIT_BOUND,
    );
    let (_temp, result) = supervisor_thread
        .join(
            "supervisor completion after admission failure drain",
            SUPERVISOR_REAP_BOUND,
        )
        .unwrap_or_else(|_| panic!("admission-drain supervisor test thread panicked"));
    let report = result.expect("admission-commit recv failure remains reportable after drain");

    assert!(!report.success);
    assert!(
        report.findings.iter().any(|finding| finding
            .message
            .contains("ended before committing or declining budget admission")),
        "admission-commit failure must remain visible: {:#?}",
        report.findings
    );
    assert_eq!(cancelled_active.load(Ordering::SeqCst), 1);
    assert!(
        report
            .released_claims
            .iter()
            .any(|claim| claim.agent_id == "admit-a"),
        "drained active assignment claim must be released: {:#?}",
        report.released_claims
    );
    assert!(report.release_errors.is_empty());
    assert!(SyncStore::open(&repo_path)
        .expect("open claims after admission drain")
        .snapshot()
        .expect("snapshot claims after admission drain")
        .is_empty());
}

#[test]
fn serial_scheduler_error_after_completion_collects_outcomes_and_releases_claims() {
    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("serial-collect-a", "README.md"),
        injected_named_assignment("serial-collect-b", "src/lib.rs"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let run_id = RunId::new("serial-collect-after-error").expect("valid serial collect run id");
    let options = injected_options(&repo_path, temp.path(), run_id.as_str());
    let runner = {
        let assignments = assignments.clone();
        let run_id = run_id.clone();
        move |command: &ExternalAgentCommand| {
            let id = injected_command_assignment_id(command);
            if id == "serial-collect-a" {
                install_checkpoint_failure(run_id.as_str(), "assignment_started");
            }
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.id == id)
                .expect("serial collect assignment");
            write_injected_assignment_report(command, assignment);
            injected_verified_run(command)
        }
    };

    let report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        1,
        &runner,
    )
    .expect("serial scheduling error remains reportable after collecting completed work");

    assert!(!report.success);
    assert_eq!(
        report
            .orchestrator_reports
            .iter()
            .map(|child| child.id.as_str())
            .collect::<Vec<_>>(),
        vec!["serial-collect-a"]
    );
    assert_eq!(report.released_claims.len(), 1);
    assert_eq!(report.released_claims[0].agent_id, "serial-collect-a");
    assert!(report.release_errors.is_empty());
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.message.contains("assignment_started")),
        "scheduler error must remain visible in the final report: {:#?}",
        report.findings
    );
    assert!(SyncStore::open(&repo_path)
        .expect("open claims after serial collect")
        .snapshot()
        .expect("snapshot claims after serial collect")
        .is_empty());
}

#[test]
fn concurrent_assignment_terminal_checkpoint_precedes_claim_release() {
    let (temp, repo_path) = injected_repository();
    let assignments = vec![
        injected_named_assignment("concurrent-terminal-a", "README.md"),
        injected_named_assignment("concurrent-terminal-b", "src/lib.rs"),
    ];
    let plan = injected_multi_plan(assignments.clone(), 0);
    let run_id = RunId::new("concurrent-terminal-before-release").expect("valid concurrent run id");
    let options = injected_options(&repo_path, temp.path(), run_id.as_str());
    let runner = move |command: &ExternalAgentCommand| {
        let id = injected_command_assignment_id(command);
        if id == "concurrent-terminal-b" {
            std::thread::sleep(Duration::from_millis(200));
        }
        let assignment = assignments
            .iter()
            .find(|assignment| assignment.id == id)
            .expect("concurrent checkpoint assignment");
        write_injected_assignment_report(command, assignment);
        injected_verified_run(command)
    };
    install_checkpoint_failure(run_id.as_str(), "after:assignment_completed");

    let _report = run_supervisor_plan_with_concurrent_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        2,
        &runner,
    )
    .expect("concurrent checkpoint failure remains reportable after terminal finalization");

    let (_checkpoint, snapshot) = open_supervisor_checkpoint(&repo_path, &run_id)
        .expect("open concurrent terminal checkpoint");
    assert_eq!(snapshot.completed_assignments.len(), 1);
    let completed = &snapshot.completed_assignments[0];
    let store = SyncStore::open(&repo_path).expect("open concurrent terminal claims");
    let active = store
        .snapshot()
        .expect("snapshot concurrent terminal claims");
    assert!(active.iter().any(|claim| &claim.agent_id == completed));
    for claim in active {
        store
            .release(claim.token)
            .expect("release retained concurrent terminal claim");
    }
}

#[test]
fn cascade_breaker_stops_admission_drains_active_and_releases_claims() {
    const TEST: &str = "cascade_breaker_stops_admission_drains_active_and_releases_claims";
    const RUN_ID: &str = "circuit-breaker-cascade";
    const WAIT_BOUND: Duration = Duration::from_secs(30);
    const BREAKER_MARKER_BOUND: Duration = Duration::from_secs(60);
    const CHILD_D_RELEASE_BOUND: Duration = Duration::from_secs(120);
    const SUPERVISOR_REAP_BOUND: Duration = Duration::from_secs(60);

    #[derive(Default)]
    struct BreakerState {
        started: BTreeSet<String>,
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
    let options = injected_options(&repo_path, temp.path(), RUN_ID);
    let state = Arc::new((Mutex::new(BreakerState::default()), Condvar::new()));
    let release_child_d = Arc::new(AtomicBool::new(false));
    let runner = {
        let assignments = assignments.clone();
        let state = Arc::clone(&state);
        let release_child_d = Arc::clone(&release_child_d);
        move |command: &ExternalAgentCommand,
              cancellation: &ProcessCancellation,
              _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
              _authorization: SupervisorProcessLaunchAuthorization| {
            let id = injected_command_assignment_id(command);
            let (lock, condvar) = &*state;
            let mut breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            breaker.started.insert(id.clone());
            condvar.notify_all();
            if id == "child-b" {
                breaker = wait_for_fixture_state(
                    condvar,
                    breaker,
                    |breaker| breaker.started.contains("child-c"),
                    TEST,
                    RUN_ID,
                    "child-b waits for child-c runner entry",
                    WAIT_BOUND,
                );
            } else if id == "child-c" {
                breaker = wait_for_fixture_state(
                    condvar,
                    breaker,
                    |breaker| breaker.started.contains("child-d"),
                    TEST,
                    RUN_ID,
                    "child-c waits for child-d runner entry",
                    WAIT_BOUND,
                );
            }
            drop(breaker);
            if id == "child-d" {
                wait_for_fixture_condition(
                    || release_child_d.load(Ordering::SeqCst),
                    TEST,
                    RUN_ID,
                    "child-d waits for unconditional main-test release",
                    CHILD_D_RELEASE_BOUND,
                );
                let mut breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                breaker.child_d_observed_cancellation |= cancellation.is_cancelled();
            }

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

    let supervisor_handle = thread::spawn(move || {
        let result = run_supervisor_plan_with_concurrent_cancellable_runner(
            plan,
            SupervisorConsultantPlan::default(),
            options,
            2,
            &runner,
        );
        (temp, result)
    });
    let mut supervisor_thread = SupervisorThreadGuard::new(
        supervisor_handle,
        {
            let release_child_d = Arc::clone(&release_child_d);
            move || release_child_d.store(true, Ordering::SeqCst)
        },
        TEST,
        RUN_ID,
        "reap supervisor after cascade test unwind",
        SUPERVISOR_REAP_BOUND,
    );

    let event_path = repo_path
        .join(format!(".maco/o2/runs/{RUN_ID}"))
        .join(ORCHESTRATION_EVENT_PATH);
    let (lock, condvar) = &*state;
    let breaker = wait_for_fixture_state(
        condvar,
        lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()),
        |breaker| breaker.started.contains("child-d"),
        TEST,
        RUN_ID,
        "main test observes child-d runner entry",
        WAIT_BOUND,
    );
    drop(breaker);
    wait_for_fixture_file_marker(
        &event_path,
        "swarm_health_circuit_breaker",
        TEST,
        RUN_ID,
        "breaker transition journal visibility",
        BREAKER_MARKER_BOUND,
    );

    let breaker = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(breaker.started.contains("child-d"));
    assert!(!breaker.started.contains("child-e"));
    assert!(!breaker.child_d_finished);
    assert!(!breaker.child_d_observed_cancellation);
    assert!(
        !supervisor_thread.is_finished(),
        "supervisor completed before child-d release"
    );
    drop(breaker);
    supervisor_thread.release_fixture();

    let (_temp, result) = supervisor_thread
        .join(
            "supervisor completion after active child-d drain",
            SUPERVISOR_REAP_BOUND,
        )
        .unwrap_or_else(|_| panic!("supervisor test thread panicked"));
    let report = result.expect("breaker trip remains reportable");

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

    let run_id = RunId::new(RUN_ID).expect("valid breaker run id");
    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized breaker artifacts");
    let events = read_finalized_orchestration_events(&reader);
    let breaker_event = events
        .iter()
        .find(|event| {
            event.kind == OrchestrationEventKind::Gate
                && event.payload["gate"] == "swarm_health_circuit_breaker"
                && event.payload["transition"] == "closed_to_open"
                && event.payload["trip"]["reason"]["kind"] == "repeated_rejection_loop"
        })
        .expect("typed breaker transition event");
    assert_eq!(
        breaker_event.payload["autonomy_kpis"]["coverage"]["rate_denominators"]["observation"],
        "not_process_observable"
    );
    assert!(breaker_event.payload["autonomy_kpis"]
        .get("denial_rate")
        .is_none());
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
              _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
              _authorization: SupervisorProcessLaunchAuthorization| {
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
    skip_without_containment!();
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
            assert_eq!(lifecycle.task_id, review_lens_auditor_id(&assignment, 0));
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
