use super::*;

const TECHNICAL_FAILURES: &[&str] = &[
    "rejected",
    "failed-status",
    "missing-status",
    "validation",
    "command-status",
    "command-exit",
    "command-timeout",
    "command-error",
    "command-environment",
    "command-denial",
    "environment",
    "error-finding",
];

fn fail_decomposition_worker(worker: &mut WorkerReport, failure: &str) {
    let mut command = injected_command_record();
    match failure {
        "rejected" => worker.rejected = true,
        "failed-status" => worker.status = ReviewStatus::Failed,
        "missing-status" => worker.status = ReviewStatus::Missing,
        "validation" => worker.validation_results[0].status = ReviewStatus::Failed,
        "command-status" => command.status = ReviewStatus::Failed,
        "command-exit" => command.exit_code = Some(1),
        "command-timeout" => command.timed_out = true,
        "command-error" => command.error = Some("command failed".to_string()),
        "command-environment" => {
            command
                .environment_failures
                .push(EnvironmentFailure::sandbox_unavailable(
                    "test environment failure".to_string(),
                ))
        }
        "command-denial" => command.sandbox_denials.push(denial_fixture(
            SandboxDenialBoundary::InnerCodex,
            "test-denial",
            Some("README.md"),
            SandboxDenialRetryability::NotRetryable,
        )),
        "environment" => worker
            .environment_failures
            .push(EnvironmentFailure::sandbox_unavailable(
                "test environment failure".to_string(),
            )),
        "error-finding" => worker.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: "unresolved decomposition failure".to_string(),
            paths: Vec::new(),
        }),
        _ => panic!("unknown technical failure: {failure}"),
    }
    worker.commands_run.push(command);
}

fn decomposition_fixture(
    accepted: bool,
) -> (
    OrchestratorAssignment,
    AssignmentMetadata,
    OrchestratorReviewReport,
) {
    let mut assignment = injected_assignment(true);
    assignment
        .assigned_paths
        .push(PathBuf::from("src/readme_part.md"));
    assignment.worker_assignments[0]
        .assigned_paths
        .push(PathBuf::from("src/readme_part.md"));
    let metadata = BTreeMap::from([(
        (
            assignment.id.clone(),
            assignment.worker_assignments[0].id.clone(),
        ),
        WorkerAssignmentMetadata {
            kind: AssignmentKind::MegafileDecomposition,
            target_path: Some(PathBuf::from("README.md")),
            mechanical_duty: None,
        },
    )])
    .into();
    let mut report = injected_child_report(&assignment);
    report.files_changed = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/readme_part.md"),
    ];
    let worker = &mut report.worker_reports[0];
    worker.accepted = accepted;
    worker.assignment_kind = AssignmentKind::MegafileDecomposition;
    worker.target_path = Some(PathBuf::from("./README.md"));
    worker.files_changed = report.files_changed.clone();
    let completion = DecompositionCompletion {
        target_path: PathBuf::from("./README.md"),
        replacement_paths: vec![PathBuf::from("./src/readme_part.md")],
        supervisor_candidate_binding: None,
    };
    worker.decomposition_completion = Some(completion.clone());
    report.decomposition_completions = vec![completion];
    (assignment, metadata, report)
}

fn validate_decomposition(
    assignment: &OrchestratorAssignment,
    metadata: &AssignmentMetadata,
    report: &mut OrchestratorReviewReport,
) {
    let path = Path::new("decomposition.json");
    validate_worker_report_evidence(assignment, metadata, path, report);
    validate_assignment_report_plumbing(assignment, metadata, path, report);
}

// A Worker can reserve acceptance for parent review while supplying completion evidence.
#[test]
fn decomposition_raw_false_reaches_review() {
    let (assignment, metadata, mut report) = decomposition_fixture(false);
    validate_decomposition(&assignment, &metadata, &mut report);
    assert_eq!(report.status, ReviewStatus::Succeeded);
    assert!(!report.worker_reports[0].accepted);
    let completion = DecompositionCompletion {
        target_path: PathBuf::from("README.md"),
        replacement_paths: vec![PathBuf::from("src/readme_part.md")],
        supervisor_candidate_binding: None,
    };
    assert_eq!(report.decomposition_completions, vec![completion.clone()]);
    assert_eq!(
        report.worker_reports[0].decomposition_completion,
        Some(completion.clone())
    );

    let mut unreviewed = report.clone();
    validate_auditor_reports(&assignment, Path::new("unreviewed.json"), &mut unreviewed);
    assert!(report_failed(&unreviewed));
    assert!(accepted_decomposition_candidates(&[unreviewed]).is_empty());

    let mut auditor = injected_auditor_report(&assignment, &report);
    auditor.commands_run.push(injected_command_record());
    report.audit_reports.push(auditor);
    validate_auditor_reports(&assignment, Path::new("reviewed.json"), &mut report);
    attach_parent_computed_review_lens_aggregate(
        &injected_plan(assignment.clone(), 0),
        &assignment,
        &mut report,
    );
    assert!(!report_failed(&report));
    assert!(!report.worker_reports[0].accepted);
    let mut final_report =
        artifact_test_final_report(&RunId::new("raw-false-decomposition").expect("run id"));
    final_report.decomposition_candidates =
        accepted_decomposition_candidates(&[report.clone(), report]);
    assert_eq!(final_report.decomposition_candidates, vec![completion]);
}

// Reserving acceptance must not lose the binding to the exact candidate bytes.
#[test]
fn decomposition_raw_false_gets_candidate_binding() {
    skip_without_containment!();
    let (_temp, repo_path) = injected_repository();
    let (assignment, metadata, mut report) = decomposition_fixture(true);
    validate_decomposition(&assignment, &metadata, &mut report);
    assert_eq!(report.status, ReviewStatus::Succeeded);

    let manager = WorktreeManager::new(&repo_path);
    let agent = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: assignment.id.clone(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create supervisor-inspection worktree");
    fs::write(agent.path.join("README.md"), "x\n").expect("shrink inspected target");
    fs::create_dir_all(agent.path.join("src")).expect("create replacement parent");
    fs::write(agent.path.join("src/readme_part.md"), "reviewed\n")
        .expect("write inspected replacement");

    report.worker_reports[0].accepted = false;
    let unbound_report = report.clone();
    let lease = manager
        .acquire_write_execution_lease(&assignment.id)
        .expect("acquire supervisor candidate lease");
    let before =
        bind_supervisor_decomposition_candidate(&repo_path, &assignment, &mut report, &lease, None)
            .expect("bind supervisor candidate")
            .expect("typed decomposition inspection");
    assert_eq!(
        report.decomposition_completions[0].supervisor_candidate_binding,
        Some(before.binding.clone())
    );
    assert_eq!(
        report.worker_reports[0]
            .decomposition_completion
            .as_ref()
            .and_then(|completion| completion.supervisor_candidate_binding.clone()),
        Some(before.binding.clone())
    );
    assert!(!report.worker_reports[0].accepted);
    assert!(report.audit_reports.is_empty());
    assert!(report.review_lens_aggregate.is_none());

    for accepted in [false, true] {
        for failure in TECHNICAL_FAILURES {
            let mut failed = unbound_report.clone();
            failed.worker_reports[0].accepted = accepted;
            fail_decomposition_worker(&mut failed.worker_reports[0], failure);
            bind_supervisor_decomposition_candidate(
                &repo_path,
                &assignment,
                &mut failed,
                &lease,
                None,
            )
            .expect("inspect candidate with failed worker evidence");
            assert!(
                failed.worker_reports[0]
                    .decomposition_completion
                    .as_ref()
                    .unwrap()
                    .supervisor_candidate_binding
                    .is_none(),
                "accepted={accepted}, failure={failure} acquired a worker binding"
            );
        }
    }

    fs::write(agent.path.join("src/readme_part.md"), "substituted\n")
        .expect("substitute inspected replacement bytes");
    let after = inspect_supervisor_candidate(&repo_path, &assignment, &lease, None)
        .expect("recapture substituted candidate");
    assert_eq!(after.changed_paths, before.changed_paths);
    assert_ne!(after.binding, before.binding);
}

#[test]
fn decomposition_technical_failures_cannot_supply_completion_evidence() {
    for accepted in [false, true] {
        for failure in TECHNICAL_FAILURES {
            // Exercise both Worker normalization and the independent aggregate
            // comparison, which must reject evidence from a failed Worker.
            for normalize_worker in [false, true] {
                let (assignment, metadata, mut report) = decomposition_fixture(accepted);
                if !normalize_worker {
                    validate_decomposition(&assignment, &metadata, &mut report);
                    assert_eq!(report.status, ReviewStatus::Succeeded);
                }
                fail_decomposition_worker(&mut report.worker_reports[0], failure);
                if normalize_worker {
                    validate_decomposition(&assignment, &metadata, &mut report);
                } else {
                    validate_assignment_report_plumbing(
                        &assignment,
                        &metadata,
                        Path::new("failed-completion.json"),
                        &mut report,
                    );
                }
                assert!(
                    report_failed(&report),
                    "accepted={accepted}, failure={failure}, normalize_worker={normalize_worker}"
                );
                assert!(report.decomposition_completions.is_empty());
            }
        }
    }
}

#[test]
fn decomposition_success_requires_completion_for_either_raw_bit() {
    for accepted in [false, true] {
        let (assignment, metadata, mut report) = decomposition_fixture(accepted);
        report.worker_reports[0].decomposition_completion = None;
        report.decomposition_completions.clear();
        validate_decomposition(&assignment, &metadata, &mut report);
        assert!(report_failed(&report), "accepted={accepted}");
        assert!(finding_messages(&report).contains("omitted decomposition_completion"));
    }
}

#[test]
fn decomposition_missing_or_rejected_parent_review_cannot_accept_either_raw_bit() {
    for accepted in [false, true] {
        for review in ["missing", "rejected", "uncovered"] {
            let (assignment, metadata, mut report) = decomposition_fixture(accepted);
            report.worker_reports[0].findings.push(Finding {
                severity: FindingSeverity::Warning,
                message: "nonblocking decomposition note".to_string(),
                paths: Vec::new(),
            });
            validate_decomposition(&assignment, &metadata, &mut report);
            assert_eq!(report.status, ReviewStatus::Succeeded);
            assert_eq!(report.worker_reports[0].accepted, accepted);
            if review != "missing" {
                let mut auditor = injected_auditor_report(&assignment, &report);
                auditor.commands_run.push(injected_command_record());
                if review == "rejected" {
                    auditor.accepted = false;
                    auditor.rejected = true;
                } else {
                    auditor.reviewed_worker_ids.clear();
                }
                report.audit_reports.push(auditor);
            }
            validate_auditor_reports(&assignment, Path::new("failed-review.json"), &mut report);
            assert!(
                report_failed(&report),
                "accepted={accepted}, review={review}"
            );
            assert!(accepted_decomposition_candidates(&[report]).is_empty());
        }
    }
}

fn finalized_decomposition_fixture() -> (tempfile::TempDir, PathBuf, SupervisorFinalReport) {
    let (temp, repo_path) = injected_repository();
    let manager = WorktreeManager::new(&repo_path);
    let agent = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create finalized evidence worktree");
    fs::write(agent.path.join("README.md"), "x\n").expect("shrink target");
    fs::create_dir_all(agent.path.join("src")).expect("replacement parent");
    fs::write(agent.path.join("src/readme_part.md"), "part\n").expect("replacement");
    let source_id = RunId::new("source-evidence").expect("source id");
    write_test_finalized_megafile_decomposition_evidence(
        &repo_path,
        source_id.clone(),
        "agent-a",
        "worker-a",
        PathBuf::from("README.md"),
        vec![PathBuf::from("src/readme_part.md")],
    )
    .expect("write source evidence");
    let paths = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/readme_part.md"),
    ];
    verified_megafile_decomposition_evidence(
        &repo_path,
        source_id.clone(),
        "agent-a",
        Path::new("README.md"),
        &paths,
    )
    .expect("unchanged source fixture must verify");
    let report =
        read_finalized_supervisor_report(&repo_path, &source_id, &run_dir(&repo_path, &source_id))
            .expect("read authenticated source")
            .expect("source finalized");
    (temp, repo_path, report)
}

fn verify_finalized_reviewed_decomposition(
    repo: &Path,
    mut report: SupervisorFinalReport,
    accepted: bool,
    suffix: &str,
    change: impl FnOnce(&mut SupervisorFinalReport),
) -> Result<VerifiedMegafileDecompositionEvidence> {
    let reviewed_id = RunId::new(format!("reviewed-evidence-{suffix}"))?;
    report.run_id = reviewed_id.clone();
    report.run_dir = RunArtifactFamily::Supervise
        .run_root()
        .join(reviewed_id.as_str());
    let paths = report.files_changed.clone();
    let child = &mut report.orchestrator_reports[0];
    child.worker_reports[0].accepted = accepted;
    let mut assignment = injected_assignment(true);
    assignment.id = "agent-a".to_string();
    assignment.worker_assignments[0].id = "worker-a".to_string();
    assignment.assigned_paths = paths.clone();
    assignment.worker_assignments[0].assigned_paths = paths.clone();
    validate_auditor_reports(&assignment, Path::new("reviewed.json"), child);
    assert!(
        !report_failed(child),
        "parent/Auditor acceptance must remain successful"
    );
    attach_parent_computed_review_lens_aggregate(
        &injected_plan(assignment.clone(), 0),
        &assignment,
        child,
    );
    assert_eq!(
        child.review_lens_aggregate.as_ref().unwrap().decision,
        ReviewAggregationDecision::Accept
    );
    assert!(child.worker_reports[0]
        .decomposition_completion
        .as_ref()
        .unwrap()
        .supervisor_candidate_binding
        .is_some());
    assert_eq!(child.worker_reports[0].accepted, accepted);
    change(&mut report);
    let mut writer = ArtifactRunWriter::reserve(
        repo,
        RunArtifactFamily::Supervise,
        reviewed_id.clone(),
        "reviewed-decomposition",
    )?;
    write_final_report(&mut writer, &report)?;
    writer.finalize(
        RunArtifactFamily::Supervise.final_report_relative_path(),
        true,
    )?;
    verified_megafile_decomposition_evidence(
        repo,
        reviewed_id,
        "agent-a",
        Path::new("README.md"),
        &paths,
    )
}

// The reviewer reproduced the downstream merge gate using these two raw values.
#[test]
fn reviewed_decomposition_true_finalized_evidence_is_accepted() {
    skip_without_containment!();
    let (_temp, repo, report) = finalized_decomposition_fixture();
    verify_finalized_reviewed_decomposition(&repo, report, true, "raw-true", |_| {})
        .expect("reviewed raw-true evidence must verify");
}

#[test]
fn reviewed_decomposition_raw_false_finalized_evidence_is_accepted() {
    skip_without_containment!();
    let (_temp, repo, report) = finalized_decomposition_fixture();
    verify_finalized_reviewed_decomposition(&repo, report, false, "raw-false", |_| {})
        .expect("reviewed raw-false evidence must verify");
}

#[test]
fn finalized_decomposition_rejects_technical_failures_for_either_raw_bit() {
    skip_without_containment!();
    let (_temp, repo, report) = finalized_decomposition_fixture();
    for accepted in [false, true] {
        for (index, failure) in TECHNICAL_FAILURES.iter().enumerate() {
            let result = verify_finalized_reviewed_decomposition(
                &repo,
                report.clone(),
                accepted,
                &format!("technical-{accepted}-{index}"),
                |report| {
                    fail_decomposition_worker(
                        &mut report.orchestrator_reports[0].worker_reports[0],
                        failure,
                    )
                },
            );
            assert!(
                result.is_err(),
                "review erased a Worker technical failure: accepted={accepted}, failure={failure}"
            );
        }
    }
}

#[test]
fn finalized_decomposition_requires_review_and_binding_for_either_raw_bit() {
    skip_without_containment!();
    let (_temp, repo, report) = finalized_decomposition_fixture();
    for accepted in [false, true] {
        for (index, missing) in [
            "publishability",
            "parent-acceptance",
            "parent-success",
            "auditor",
            "auditor-acceptance",
            "auditor-validation",
            "worker-coverage",
            "path-coverage",
            "terminal-worker",
            "completion",
            "binding",
            "child-completion",
            "final-completion",
        ]
        .into_iter()
        .enumerate()
        {
            let result = verify_finalized_reviewed_decomposition(
                &repo,
                report.clone(),
                accepted,
                &format!("review-{accepted}-{index}"),
                |report| {
                    let child = &mut report.orchestrator_reports[0];
                    match missing {
                        "publishability" => report.publishable = false,
                        "parent-acceptance" => child.accepted = false,
                        "parent-success" => child.status = ReviewStatus::Failed,
                        "auditor" => child.audit_reports.clear(),
                        "auditor-acceptance" => child.audit_reports[0].accepted = false,
                        "auditor-validation" => {
                            child.audit_reports[0].validation_results[0].status =
                                ReviewStatus::Failed
                        }
                        "worker-coverage" => child.audit_reports[0].reviewed_worker_ids.clear(),
                        "path-coverage" => child.audit_reports[0].reviewed_paths.clear(),
                        "terminal-worker" => {
                            child.worker_reports[0].no_further_delegation = Some(false)
                        }
                        "completion" => child.worker_reports[0].decomposition_completion = None,
                        "binding" => {
                            child.worker_reports[0]
                                .decomposition_completion
                                .as_mut()
                                .unwrap()
                                .supervisor_candidate_binding = None
                        }
                        "child-completion" => child.decomposition_completions.clear(),
                        "final-completion" => report.decomposition_candidates.clear(),
                        _ => unreachable!(),
                    }
                },
            );
            assert!(result.is_err(), "accepted={accepted}, missing={missing}");
        }
    }
}
