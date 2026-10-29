use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn commit_snapshot(root: &Path) -> Result<()> {
    let repo = Repository::open(root)?;
    let mut index = repo.index()?;
    index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
    index.write()?;
    let tree = repo.find_tree(index.write_tree()?)?;
    let parent = repo.head()?.peel_to_commit()?;
    let signature = Signature::now("Check tests", "checks@example.invalid")?;
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "Checks",
        &tree,
        &[&parent],
    )?;
    Ok(())
}

fn fixture(root: &Path) -> Result<LoadedSupervisorPlan> {
    fs::write(root.join(".gitignore"), ".maco/\n")?;
    fs::create_dir(root.join("src"))?;
    fs::create_dir(root.join("checks"))?;
    let python = ["/usr/bin/python3", "/bin/python3"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .context("Python 3 is missing")?;
    let mut workers = Vec::new();
    let mut checks = Vec::new();
    for subject in ["identifier", "duration"] {
        let source = format!("src/{subject}.py");
        let check = format!("checks/check_{subject}.py");
        fs::write(root.join(&source), "value = 1\n")?;
        fs::write(root.join(&check), format!(
            "import importlib.util\nspec = importlib.util.spec_from_file_location('subject', '{source}')\nsubject = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(subject)\nassert subject.value == 1\n"
        ))?;
        workers.push(
            json!({"id":subject, "assigned_paths":[source], "task":"Repair the declared source"}),
        );
        checks.push(
            json!({"worker_id":subject, "assigned_paths":[source], "check_path":check,
            "argv":[python, "-I", "-B", check]}),
        );
    }
    commit_snapshot(root)?;
    super::super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
        &json!({"task":"Repair identifier and duration", "assignments":[{
            "id":"parent", "phase":"execution", "assigned_paths":["src/identifier.py", "src/duration.py"],
            "task":"Repair identifier and duration within the declared source files",
            "worker_assignments":workers, "authored_independent_checks":checks
        }]}).to_string(), Some(root),
    )
}

fn acquire_evidence(root: &Path, loaded: &LoadedSupervisorPlan) -> Result<PreclaimRunEvidence> {
    acquire_supervisor_preclaim_evidence(
        root,
        SupervisorRuntime::Codex,
        SupervisorExecutionRuntime::Verified,
        &loaded.plan,
        &loaded.consultant,
        &loaded.assignment_metadata,
        &loaded.plan_metadata,
    )
}

#[test]
fn dynamic_import_checks_bind_two_workers_before_claim() -> Result<()> {
    with_valid_schedule_context!(context, vec![test_assignment("parent", "README.md")], 1, {
        let mut loaded = fixture(context.repo)?;
        let (assessment, frozen) = assessed_requested_preclaim_routing(&loaded.plan)?;
        let _routing_policy =
            crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
        loaded.plan_metadata.task_routing_assessment = Some(assessment);
        loaded.plan_metadata.resolved_routing_policy = Some(frozen);
        let catalog = test_runtime_model_catalog(&loaded.plan, SupervisorRuntime::Codex)?;
        #[cfg(target_os = "linux")]
        let cam_temp = tempfile::tempdir()?;
        #[cfg(target_os = "linux")]
        let _cam = install_positive_injected_cam_fixture(&cam_temp, &catalog)?;
        let mut options = test_options(context.repo, "authored-preparation");
        options.runtime = SupervisorRuntime::Codex;
        let prepared = prepare_supervisor_run(
            loaded.clone(),
            &options,
            1,
            SupervisorExecutionRuntime::Verified,
            SupervisorWorktreeCreation::VerifiedTestOnly,
            Ok(catalog),
        )?;
        assert!(
            prepared.preclaim_decisions[0].allows_path_claim(),
            "{}",
            prepared.preclaim_decisions[0].reason
        );
        assert!(!prepared.selection_decisions.is_empty());
        let evidence = prepared.preclaim_evidence;
        let assignment = &loaded.plan.assignments[0];
        let risk = evidence
            .risk_for(&assignment.assigned_paths)
            .context("risk missing")?;
        assert!(risk.dependency_impacts.is_empty());
        let without_receipt = preclaim::evaluate_preclaim_viability(
            assignment,
            &loaded.plan.assignments,
            evidence.repo_map.as_ref(),
            Some(&risk),
            Some(SupervisorRuntime::Codex),
            SupervisorExecutionRuntime::Verified,
        );
        assert_eq!(
            without_receipt.dimensions.clear_verification_path,
            preclaim::ViabilityFinding::Unknown
        );
        let decisions = evaluate_supervisor_preclaims(&loaded.plan, &loaded.plan, &evidence);
        assert!(decisions[0].allows_path_claim(), "{}", decisions[0].reason);
        assert_eq!(
            decisions[0].evidence_source,
            preclaim::PreclaimEvidenceSource::Acquired
        );
        assert_eq!(
            decisions[0].dimensions.clear_verification_path,
            preclaim::ViabilityFinding::Yes
        );
        let context = AssignmentSchedulerContext {
            plan: &loaded.plan,
            requested_plan: &loaded.plan,
            assignment_metadata: &loaded.assignment_metadata,
            execution_runtime: SupervisorExecutionRuntime::Verified,
            worktree_creation: SupervisorWorktreeCreation::VerifiedTestOnly,
            ..context
        };
        let mut progress = SchedulerProgress::new(1, 1);
        progress.install_preclaim_decisions(decisions)?;
        progress.prepared_preclaim_evidence = Some(evidence);
        assert!(schedule_preclaim_decision(&context, &progress, None, 0)?.allows_path_claim());
        for check in &loaded.assignment_metadata.authored_independent_checks["parent"] {
            let status = std::process::Command::new(&check.argv[0])
                .args(&check.argv[1..])
                .current_dir(context.repo)
                .status()?;
            assert!(status.success());
        }
        assert!(context.sync_store.snapshot()?.is_empty());
        assert!(context.manager.list()?.is_empty());
        assert_eq!(context.budget_ledger.report()?.reserved.tokens, 0);
        assert_eq!(context.budget_ledger.report()?.consumed.tokens, 0);
    });
    Ok(())
}

#[test]
fn tampered_check_or_plan_refuses_before_claim() -> Result<()> {
    for max_children in [1, 2] {
        for case in 0..21 {
            with_valid_schedule_context!(
                context,
                vec![test_assignment("parent", "README.md")],
                max_children,
                {
                    let mut loaded = fixture(context.repo)?;
                    let runtime = tempfile::tempdir()?;
                    let interpreter = runtime.path().join("python3");
                    if matches!(case, 7 | 8) {
                        let source = fs::canonicalize(
                            &loaded.assignment_metadata.authored_independent_checks["parent"][0]
                                .argv[0],
                        )?;
                        fs::copy(source, &interpreter)?;
                        fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o755))?;
                        for check in loaded
                            .assignment_metadata
                            .authored_independent_checks
                            .get_mut("parent")
                            .unwrap()
                        {
                            check.argv[0] = interpreter.to_str().unwrap().to_string();
                        }
                    }
                    let evidence = acquire_evidence(context.repo, &loaded)?;
                    let decisions =
                        evaluate_supervisor_preclaims(&loaded.plan, &loaded.plan, &evidence);
                    assert!(
                        decisions[0].allows_path_claim(),
                        "case {case}: {}",
                        decisions[0].reason
                    );
                    let mut current = loaded.plan.clone();
                    let mut requested = loaded.plan.clone();
                    let mut metadata = loaded.assignment_metadata.clone();
                    let check = context.repo.join("checks/check_identifier.py");
                    match case {
                        0 => fs::write(&check, "assert False\n")?,
                        1 => {
                            fs::remove_file(&check)?;
                            symlink("../src/identifier.py", &check)?;
                        }
                        2 => {
                            fs::remove_file(&check)?;
                            fs::hard_link(context.repo.join("src/identifier.py"), &check)?;
                        }
                        3 => fs::remove_file(&check)?,
                        4 => fs::write(&check, "")?,
                        5 => fs::write(context.repo.join("unrelated.txt"), "snapshot drift\n")?,
                        6 => {
                            fs::write(context.repo.join("README.md"), "new snapshot\n")?;
                            commit_snapshot(context.repo)?;
                        }
                        7 => fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o600))?,
                        8 => {
                            let bytes = fs::read(&interpreter)?;
                            fs::remove_file(&interpreter)?;
                            fs::write(&interpreter, bytes)?;
                            fs::set_permissions(&interpreter, fs::Permissions::from_mode(0o755))?;
                        }
                        9 => {
                            metadata
                                .authored_independent_checks
                                .get_mut("parent")
                                .unwrap()[0]
                                .argv[3] = "checks/check_duration.py".to_string()
                        }
                        10 => {
                            metadata
                                .authored_independent_checks
                                .get_mut("parent")
                                .unwrap()[0]
                                .check_path = "checks/check_duration.py".to_string()
                        }
                        11 => {
                            metadata
                                .authored_independent_checks
                                .get_mut("parent")
                                .unwrap()[0]
                                .worker_id = "unrelated".to_string()
                        }
                        12 => {
                            metadata
                                .authored_independent_checks
                                .get_mut("parent")
                                .unwrap()[0]
                                .assigned_paths = vec!["README.md".to_string()]
                        }
                        13 => metadata.authored_independent_checks.clear(),
                        14 => {
                            current.assignments[0].worker_assignments[0].assigned_paths =
                                vec!["README.md".into()]
                        }
                        15 => current.assignments[0]
                            .assigned_paths
                            .push("README.md".into()),
                        16 => current.assignments[0].task = Some("unrelated task".to_string()),
                        17 => {
                            requested.assignments[0].task = Some("changed frozen plan".to_string())
                        }
                        18 => current.assignments[0].id = "unrelated".to_string(),
                        19 => {
                            fs::write(context.repo.join("src/identifier.py"), "value = 2\n")?;
                            commit_snapshot(context.repo)?;
                        }
                        20 => fs::set_permissions(&check, fs::Permissions::from_mode(0o000))?,
                        _ => unreachable!(),
                    }
                    let context = AssignmentSchedulerContext {
                        plan: &current,
                        requested_plan: &requested,
                        assignment_metadata: &metadata,
                        execution_runtime: SupervisorExecutionRuntime::Verified,
                        worktree_creation: SupervisorWorktreeCreation::VerifiedTestOnly,
                        ..context
                    };
                    let mut progress = SchedulerProgress::new(1, max_children);
                    progress.install_preclaim_decisions(decisions)?;
                    progress.prepared_preclaim_evidence = Some(evidence);
                    let cancellation = ProcessCancellation::new();
                    let result = if max_children == 1 {
                        run_serial_assignment_schedule(
                            &context,
                            &mut progress,
                            &cancellation,
                            &Mutex::new(Vec::new()),
                        )
                    } else {
                        run_concurrent_assignment_schedule(
                            &context,
                            &mut progress,
                            &cancellation,
                            &SemanticBlockGate::default(),
                        )
                    };
                    assert!(
                        result.is_err(),
                        "case {case}, concurrency {max_children} admitted drift"
                    );
                    assert_eq!(progress.concurrency.finish().started_assignment_count, 0);
                    assert!(context.sync_store.snapshot()?.is_empty());
                    assert!(context.manager.list()?.is_empty());
                    assert_eq!(context.budget_ledger.report()?.reserved.tokens, 0);
                    assert_eq!(context.budget_ledger.report()?.consumed.tokens, 0);
                    assert!(!context
                        .run_dir
                        .join("assignments/parent.prompt.md")
                        .exists());
                }
            );
        }
    }
    Ok(())
}

#[test]
fn authored_checks_require_fresh_risk_and_acquired_metadata() -> Result<()> {
    with_valid_schedule_context!(context, vec![test_assignment("parent", "README.md")], 1, {
        let loaded = fixture(context.repo)?;
        let mut stale_map = crate::repo_semantic::scan_repository(context.repo)?;
        stale_map.files.clear();
        let stale = PreclaimRunEvidence::verified_for_test(
            crate::repo_map::scan_repository(context.repo)?,
            stale_map,
            SupervisorRuntime::Codex,
        );
        let document = super::super::super::plan_api::supervisor_plan_value(
            &loaded.plan,
            &loaded.consultant,
            &loaded.assignment_metadata,
            &loaded.plan_metadata,
        )?
        .to_string();
        let stale = stale.with_authored_checks(
            context.repo,
            document.clone(),
            &loaded.plan.assignments,
            &loaded.assignment_metadata,
        );
        let decision = stale.evaluate(&loaded.plan.assignments[0], &loaded.plan.assignments);
        assert!(!decision.allows_path_claim());
        assert!(decision.reason.contains("semantic risk changed"));

        let restored =
            super::super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
                &document,
                Some(context.repo),
            )?;
        let declarations_only = PreclaimRunEvidence::acquire(
            context.repo,
            SupervisorRuntime::Codex,
            SupervisorExecutionRuntime::Verified,
        )
        .with_assignment_metadata(&restored.assignment_metadata);
        assert!(!declarations_only
            .evaluate(&restored.plan.assignments[0], &restored.plan.assignments)
            .allows_path_claim());
        for case in 0..5 {
            let mut changed = restored.assignment_metadata.clone();
            let check = &mut changed
                .authored_independent_checks
                .get_mut("parent")
                .unwrap()[0];
            match case {
                0 => check.argv = vec!["/bin/sh".to_string(), "-c".to_string(), "true".to_string()],
                1 => check.assigned_paths = vec!["src/duration.py".to_string()],
                2 => check.worker_id = "unrelated".to_string(),
                3 => check.check_path = "src/identifier.py".to_string(),
                4 => check.argv[0] = "/missing/python3".to_string(),
                _ => unreachable!(),
            }
            let evidence = PreclaimRunEvidence::acquire(
                context.repo,
                SupervisorRuntime::Codex,
                SupervisorExecutionRuntime::Verified,
            )
            .with_authored_checks(
                context.repo,
                document.clone(),
                &restored.plan.assignments,
                &changed,
            );
            assert!(
                !evidence
                    .evaluate(&restored.plan.assignments[0], &restored.plan.assignments)
                    .allows_path_claim(),
                "metadata case {case}"
            );
        }
        assert!(context.sync_store.snapshot()?.is_empty());
        assert_eq!(context.budget_ledger.report()?.reserved.tokens, 0);
    });
    Ok(())
}
