use super::*;

const PRIMARY_SCOPE: &str = "local/deploy.txt";

fn primary_assignment(with_worker: bool) -> OrchestratorAssignment {
    let mut assignment = injected_assignment(with_worker);
    assignment.assigned_paths = vec![PathBuf::from(PRIMARY_SCOPE)];
    for worker in &mut assignment.worker_assignments {
        worker.assigned_paths = assignment.assigned_paths.clone();
    }
    assignment
}

fn primary_target() -> SupervisorExecutionTarget {
    SupervisorExecutionTarget::PrimaryWorktree {
        claim_paths: vec![PathBuf::from(PRIMARY_SCOPE)],
    }
}

fn validated_primary_loaded(assignment: OrchestratorAssignment) -> LoadedSupervisorPlan {
    let assignment_id = assignment.id.clone();
    let plan = injected_plan(assignment, 0);
    let (plan, plan_metadata) = validate_supervisor_plan(
        plan,
        SupervisorPlanMetadata {
            execution_target: Some(primary_target()),
            assignment_schedule: vec![AssignmentScheduleEntry {
                assignment_id,
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index: 0,
            }],
            ..SupervisorPlanMetadata::default()
        },
    )
    .expect("validate primary-worktree fixture");
    LoadedSupervisorPlan {
        plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata: AssignmentMetadata::new(),
        plan_metadata,
    }
}

fn injected_primary_repository() -> (tempfile::TempDir, PathBuf) {
    let (temp, repo) = injected_repository();
    fs::write(repo.join(".gitignore"), "local/\n").expect("write local deployment ignore");
    fs::create_dir(repo.join("outside")).expect("create outside-scope fixture directory");
    fs::write(repo.join("outside/sentinel.txt"), "preserve\n")
        .expect("write outside-scope fixture");
    commit_injected_repository(&repo, "ignore local deployment state");
    fs::create_dir(repo.join("local")).expect("create local deployment directory");
    fs::write(repo.join(PRIMARY_SCOPE), "baseline\n").expect("write local deployment baseline");
    (temp, repo)
}

#[test]
fn primary_worktree_outside_scope_mutation_fails_integrity_and_releases_claim() {
    skip_without_containment!();
    let (temp, repo) = injected_primary_repository();
    let assignment = primary_assignment(false);
    let loaded = validated_primary_loaded(assignment.clone());
    let options = injected_options(&repo, temp.path(), "primary-outside-scope");
    let runner_repo = repo.clone();
    let dispatches = AtomicUsize::new(0);
    let runner = |command: &ExternalAgentCommand,
                  _: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>| {
        dispatches.fetch_add(1, Ordering::SeqCst);
        fs::write(runner_repo.join(PRIMARY_SCOPE), "deployed\n")
            .expect("mutate declared scope in outside-scope test");
        fs::write(runner_repo.join("outside/sentinel.txt"), "escaped\n")
            .expect("inject outside-scope mutation");
        let mut child = injected_child_report(&assignment);
        child.files_changed = vec![PathBuf::from(PRIMARY_SCOPE)];
        write_injected_json(&command.output_last_message, &child);
        injected_verified_run(command)
    };

    let report = run_primary_with_runner(loaded, options, &runner)
        .expect("outside-scope mutation must finalize an inspectable refusal");
    assert!(!report.success);
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    assert!(report.findings.iter().any(|finding| {
        finding
            .message
            .contains("outside declared execution_target claim_paths")
            && finding.paths == vec![PathBuf::from("outside/sentinel.txt")]
    }));
    assert_eq!(report.released_claims.len(), 1);
    assert!(SyncStore::open(&repo)
        .expect("reopen outside-scope claim store")
        .snapshot()
        .expect("snapshot released outside-scope claim")
        .is_empty());
}

fn run_primary_with_runner(
    loaded: LoadedSupervisorPlan,
    options: SupervisorRunOptions,
    runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    let runtime_model_catalog = test_runtime_model_catalog(&loaded.plan, options.runtime)?;
    authorize_and_run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        1,
        SupervisorExecutionRuntime::Verified,
        SupervisorWorktreeCreation::PrimaryWorktree,
        Ok(runtime_model_catalog),
        runner,
    )
}

#[test]
fn primary_missing_double_opt_in_gate_is_refused_before_artifact_or_dispatch() {
    let (temp, repo) = injected_primary_repository();
    let loaded = validated_primary_loaded(primary_assignment(false));
    let options = injected_options(&repo, temp.path(), "primary-missing-mutation-gate");
    let run_id = options.run_id.clone();
    let dispatches = AtomicUsize::new(0);
    let _manifest_mutation = set_effective_supervisor_manifest_test_mutations([
        EffectiveSupervisorManifestTestMutation::RemoveRequiredGate(
            ExplicitMutationGate::PrimaryPlanCliDoubleOptIn,
        ),
    ]);
    let runner = |_command: &ExternalAgentCommand,
                  _cancellation: &ProcessCancellation,
                  _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>| {
        dispatches.fetch_add(1, Ordering::SeqCst);
        panic!("missing primary mutation gate must precede dispatch")
    };

    let error = run_primary_with_runner(loaded, options, &runner)
        .expect_err("primary mutation without double opt-in gate must fail closed");

    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(
        supervisor_mutation_admission_gate_id(&error),
        Some(ExplicitMutationGate::PrimaryPlanCliDoubleOptIn.id())
    );
    assert!(!repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(run_id.as_str())
        .exists());
}

#[test]
fn primary_execution_target_requires_both_opt_ins() {
    let target = primary_target();
    let missing_cli = validate_execution_target_opt_in(Some(&target), false)
        .expect_err("plan declaration alone must be refused");
    assert_eq!(
        missing_cli.downcast_ref::<SupervisorExecutionTargetOptInError>(),
        Some(&SupervisorExecutionTargetOptInError::MissingCliAcknowledgement)
    );

    let missing_plan = validate_execution_target_opt_in(None, true)
        .expect_err("CLI acknowledgement alone must be refused");
    assert_eq!(
        missing_plan.downcast_ref::<SupervisorExecutionTargetOptInError>(),
        Some(&SupervisorExecutionTargetOptInError::MissingPlanDeclaration)
    );
    validate_execution_target_opt_in(Some(&target), true)
        .expect("double opt-in must pass pre-dispatch validation");
}

#[test]
fn primary_execution_target_rejects_missing_broad_and_git_scopes() {
    for (paths, expected) in [
        (Vec::new(), "requires between 1 and"),
        (vec![PathBuf::from(".")], "is over-broad"),
        (
            vec![PathBuf::from(".git/config")],
            "overlaps protected .git metadata",
        ),
    ] {
        let mut assignment = primary_assignment(false);
        assignment.assigned_paths = paths.clone();
        let error = validate_supervisor_plan(
            injected_plan(assignment, 0),
            SupervisorPlanMetadata {
                execution_target: Some(SupervisorExecutionTarget::PrimaryWorktree {
                    claim_paths: paths,
                }),
                ..SupervisorPlanMetadata::default()
            },
        )
        .expect_err("unsafe primary scope must fail closed");
        assert!(
            format!("{error:#}").contains(expected),
            "unexpected primary-scope refusal: {error:#}"
        );
    }
}

#[test]
fn dirty_primary_scope_refuses_before_dispatch_and_releases_claim() {
    skip_without_containment!();
    let (temp, repo) = injected_primary_repository();
    run_injected_git(&repo, &["add", "-f", PRIMARY_SCOPE]);
    commit_injected_repository(&repo, "track deployment state for dirty-scope test");
    fs::write(repo.join(PRIMARY_SCOPE), "operator edits\n").expect("dirty claimed file");

    let assignment = primary_assignment(false);
    let loaded = validated_primary_loaded(assignment.clone());
    let options = injected_options(&repo, temp.path(), "primary-dirty-scope");
    let dispatches = AtomicUsize::new(0);
    let runner = |_: &ExternalAgentCommand,
                  _: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>| {
        dispatches.fetch_add(1, Ordering::SeqCst);
        panic!("dirty primary scope must be refused before dispatch")
    };

    let report = run_primary_with_runner(loaded, options, &runner)
        .expect("dirty-scope refusal must finalize an inspectable report");
    assert!(!report.success);
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("Git-visible dirty state inside declared claim_paths")));
    assert_eq!(report.released_claims.len(), 1);
    assert_eq!(report.released_claims[0].agent_id, assignment.id);
    assert_eq!(
        report.released_claims[0].paths,
        vec![PathBuf::from(PRIMARY_SCOPE)]
    );
    assert!(SyncStore::open(&repo)
        .expect("reopen primary dirty-scope claim store")
        .snapshot()
        .expect("snapshot released primary dirty-scope claims")
        .is_empty());
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("explicitly targeted the existing primary checkout")));
}

#[test]
fn bounded_primary_command_run_mutates_scope_holds_and_releases_claim_and_marks_reports() {
    skip_without_containment!();
    let (temp, repo) = injected_primary_repository();
    let assignment = primary_assignment(false);
    let loaded = validated_primary_loaded(assignment.clone());
    let options = injected_options(&repo, temp.path(), "primary-bounded-command");
    let dispatches = AtomicUsize::new(0);
    let runner_repo = repo.clone();
    let runner_assignment = assignment.clone();
    let runner = |command: &ExternalAgentCommand,
                  _: &ProcessCancellation,
                  _: Option<ExternalPreActionReviewRuntime<'_>>| {
        dispatches.fetch_add(1, Ordering::SeqCst);
        let active_claims = SyncStore::open(&runner_repo)
            .expect("open active primary claims")
            .snapshot()
            .expect("snapshot active primary claims");
        assert_eq!(active_claims.len(), 1);
        assert_eq!(active_claims[0].agent_id, runner_assignment.id);
        assert_eq!(active_claims[0].paths, vec![PathBuf::from(PRIMARY_SCOPE)]);

        let output_name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if output_name.contains("review-auditor") {
            let mut child = injected_child_report(&runner_assignment);
            child.files_changed = vec![PathBuf::from(PRIMARY_SCOPE)];
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&runner_assignment, &child),
            );
        } else {
            assert_eq!(command.cwd, runner_repo);
            let prompt = fs::read_to_string(&command.prompt).expect("read primary child prompt");
            assert!(prompt
                .contains("Execution target: primary_worktree (declared scope: local/deploy.txt)"));
            assert!(prompt.contains("existing primary checkout"));
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadWrite);
            assert!(command.worktree_control_exceptions.is_empty());
            fs::write(runner_repo.join(PRIMARY_SCOPE), "deployed\n")
                .expect("mutate exact primary scope");
            let mut child = injected_child_report(&runner_assignment);
            child.files_changed = vec![PathBuf::from(PRIMARY_SCOPE)];
            write_injected_json(&command.output_last_message, &child);
        }
        injected_verified_run(command)
    };

    let report = run_primary_with_runner(loaded, options, &runner)
        .expect("run bounded primary command fixture");
    assert!(
        report.success,
        "unexpected failed primary report: {report:#?}"
    );
    assert!(report.publishable);
    assert_eq!(dispatches.load(Ordering::SeqCst), 2);
    assert_eq!(
        fs::read_to_string(repo.join(PRIMARY_SCOPE)).expect("read deployed primary file"),
        "deployed\n"
    );
    assert_eq!(report.files_changed, vec![PathBuf::from(PRIMARY_SCOPE)]);
    assert_eq!(report.released_claims.len(), 1);
    assert_eq!(
        report.released_claims[0].paths,
        vec![PathBuf::from(PRIMARY_SCOPE)]
    );
    assert!(report.release_errors.is_empty());
    assert!(SyncStore::open(&repo)
        .expect("reopen successful primary claim store")
        .snapshot()
        .expect("snapshot released successful primary claims")
        .is_empty());
    assert!(report.findings.iter().any(|finding| finding
        .message
        .contains("explicitly targeted the existing primary checkout")));
    assert!(report.orchestrator_reports[0]
        .findings
        .iter()
        .any(|finding| finding
            .message
            .contains("targeted the existing primary checkout with declared scope")));
    assert!(report
        .remaining_risk
        .contains("accepted changes already reside in the existing primary checkout"));
    assert!(WorktreeManager::new(&repo)
        .list()
        .expect("list managed worktrees after primary run")
        .is_empty());
}

#[test]
fn primary_worker_contract_names_checkout_and_exact_scope() {
    let assignment = primary_assignment(true);
    let plan = injected_plan(assignment.clone(), 0);
    let target = primary_target();
    let worktree = WorktreeRecord {
        name: assignment.id.clone(),
        path: PathBuf::from("/tmp/maco-primary-contract"),
        branch: "primary_worktree".to_string(),
    };
    let claim = PathClaim {
        token: ClaimToken::from_u64(82),
        agent_id: assignment.id.clone(),
        paths: assignment.assigned_paths.clone(),
    };
    let prompt = child_orchestrator_prompt(ChildOrchestratorPromptContext {
        plan: &plan,
        execution_target: Some(&target),
        assignment: &assignment,
        run_dir: Path::new("/tmp/maco-primary-contract-run"),
        worktree: &worktree,
        report_path: Path::new("/tmp/maco-primary-contract-run/incoming/child-a.json"),
        schema_path: Path::new(
            "/tmp/maco-primary-contract-run/schemas/orchestrator-review-report.schema.json",
        ),
        worker_schema_path: Path::new(
            "/tmp/maco-primary-contract-run/schemas/worker-report.schema.json",
        ),
        auditor_schema_path: Path::new(
            "/tmp/maco-primary-contract-run/schemas/auditor-report.schema.json",
        ),
        consultant: &SupervisorConsultantPlan::default(),
        claim_context: ChildPromptClaimContext {
            claim: &claim,
            semantic_intent_token: None,
        },
    })
    .expect("render primary-worktree child and embedded worker contracts");

    assert!(
        prompt.contains("Execution target: primary_worktree (declared scope: local/deploy.txt)")
    );
    assert!(prompt.contains("This assignment explicitly targets the existing primary checkout"));
    assert!(prompt.contains("The assigned worktree is the existing primary checkout"));
    assert!(prompt.contains("exact declared primary-worktree claim paths"));
    assert!(prompt.contains("do not stage, commit, or change Git metadata"));
}
