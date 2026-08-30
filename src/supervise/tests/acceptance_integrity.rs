use super::*;

#[test]
#[cfg(unix)]
fn parent_report_slots_reject_child_time_symlink_rebinding_without_clobbering_sentinels() {
    use std::os::unix::fs::symlink;

    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(false);
    let plan = injected_plan(assignment.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "parent-report-rebind");
    let child_sentinel = temp.path().join("child-sentinel");
    let final_sentinel = temp.path().join("final-sentinel");
    fs::write(&child_sentinel, "child untouched").expect("write child sentinel");
    fs::write(&final_sentinel, "final untouched").expect("write final sentinel");

    let mut runner = |command: &ExternalAgentCommand| {
        let run_root = command
            .output_last_message
            .parent()
            .and_then(Path::parent)
            .expect("incoming path under run root");
        let normalized = run_root.join("reports/child-a.json");
        let supervisor_final = run_root.join("reports/supervisor-final.json");
        fs::create_dir_all(
            normalized
                .parent()
                .expect("normalized report has parent directory"),
        )
        .expect("create reports directory");
        fs::set_permissions(
            normalized
                .parent()
                .expect("normalized report has parent directory"),
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .expect("private reports directory");
        remove_report_slot_if_present(&normalized).expect("remove reserved normalized report");
        symlink(&child_sentinel, &normalized).expect("rebind normalized report");
        remove_report_slot_if_present(&supervisor_final).expect("remove reserved final report");
        symlink(&final_sentinel, &supervisor_final).expect("rebind final report");
        write_injected_json(
            &command.output_last_message,
            &injected_child_report(&assignment),
        );
        injected_verified_run(command)
    };

    let error = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect_err("rebound supervisor final slot must fail closed");

    assert!(error
        .to_string()
        .contains("failed to write normalized supervisor final report"));
    assert_eq!(
        fs::read_to_string(&child_sentinel).expect("read child sentinel"),
        "child untouched"
    );
    assert_eq!(
        fs::read_to_string(&final_sentinel).expect("read final sentinel"),
        "final untouched"
    );
}

#[test]
fn injected_parent_auditor_primary_mutation_is_rejected() {
    skip_without_containment!();
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let plan = injected_plan(assignment.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "injected-auditor-mutation");
    let primary = repo_path.clone();
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        let child = injected_child_report(&assignment);
        if name.contains("review-auditor") {
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
            fs::write(primary.join("README.md"), "auditor mutation\n")
                .expect("mutate primary during auditor");
        } else {
            write_injected_json(&command.output_last_message, &child);
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
    .expect("run injected auditor mutation");
    assert!(!report.success);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.message.contains("primary")));
}

#[test]
fn injected_missing_child_or_auditor_and_failed_child_propagate_final_failure() {
    skip_without_containment!();
    for scenario in [
        "missing-child",
        "failed-child",
        "failed-worker",
        "missing-auditor",
    ] {
        let (temp, repo_path) = injected_repository();
        let with_worker = matches!(
            scenario,
            "missing-child" | "failed-worker" | "missing-auditor"
        );
        let assignment = injected_assignment(with_worker);
        let plan = injected_plan(assignment.clone(), 0);
        let options = injected_options(&repo_path, temp.path(), &format!("injected-{scenario}"));
        let mut invocations = Vec::new();
        let mut runner = |command: &ExternalAgentCommand| {
            let name = command
                .output_last_message
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string();
            invocations.push(name.clone());
            if with_worker && !name.contains("review-auditor") {
                assert_eq!(command.worker_journal_artifacts.len(), 1);
                let artifact = &command.worker_journal_artifacts[0];
                let journal = &artifact.path;
                assert_eq!(artifact.worker_id, "worker-a");
                assert_eq!(
                    artifact.incoming_root,
                    command.output_last_message.parent().unwrap()
                );
                assert!(journal.is_file());
                assert_eq!(
                    journal.parent().and_then(Path::file_name),
                    Some(OsStr::new("worker-journals"))
                );
                assert_eq!(journal.file_name(), Some(OsStr::new("worker-a.jsonl")));
            } else {
                assert!(command.worker_journal_artifacts.is_empty());
            }
            match scenario {
                "missing-child" => {}
                "failed-child" => {
                    let mut child = injected_child_report(&assignment);
                    child.status = ReviewStatus::Failed;
                    child.accepted = false;
                    child.rejected = true;
                    child.remaining_risk = "injected child failure".to_string();
                    write_injected_json(&command.output_last_message, &child);
                }
                "failed-worker" if name.contains("review-auditor") => {
                    let child = injected_child_report(&assignment);
                    write_injected_json(
                        &command.output_last_message,
                        &injected_auditor_report(&assignment, &child),
                    );
                }
                "failed-worker" => {
                    let mut child = injected_child_report(&assignment);
                    child.status = ReviewStatus::Failed;
                    child.accepted = false;
                    child.rejected = true;
                    child.worker_reports[0].status = ReviewStatus::Failed;
                    child.worker_reports[0].accepted = false;
                    child.worker_reports[0].rejected = true;
                    child.remaining_risk = "injected worker failure".to_string();
                    write_injected_json(&command.output_last_message, &child);
                }
                "missing-auditor" if !name.contains("review-auditor") => {
                    write_injected_json(
                        &command.output_last_message,
                        &injected_child_report(&assignment),
                    );
                }
                "missing-auditor" => {}
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
        .expect("collect injected missing or failed report");

        assert!(
            !report.success,
            "scenario {scenario} unexpectedly succeeded"
        );
        assert!(!report.accepted);
        assert!(report.rejected);
        assert_eq!(report.status, ReviewStatus::Failed);
        assert_eq!(
            invocations
                .iter()
                .filter(|name| name.contains("review-auditor"))
                .count(),
            usize::from(matches!(scenario, "failed-worker" | "missing-auditor")),
            "scenario {scenario} launched the wrong follow-ups"
        );
        if scenario == "missing-child" {
            assert!(finding_messages(&report.orchestrator_reports[0])
                .contains("required child report is missing or invalid"));
        }
        if scenario == "missing-auditor" {
            assert!(report.orchestrator_reports[0]
                .audit_reports
                .iter()
                .any(report_failed));
        }
    }
}

#[test]
fn injected_diff_reconciliation_rejects_unattributed_worker_diff() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let plan = injected_plan(assignment.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "injected-diff-reconciliation");
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        let child = injected_child_report(&assignment);
        if name.contains("review-auditor") {
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
        } else {
            fs::write(command.cwd.join("README.md"), "child worktree edit\n")
                .expect("write assigned child diff");
            write_injected_json(&command.output_last_message, &child);
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
    .expect("run injected diff reconciliation");

    assert!(!report.success);
    assert_eq!(report.files_changed, vec![PathBuf::from("README.md")]);
    let child = &report.orchestrator_reports[0];
    assert_eq!(child.files_changed, vec![PathBuf::from("README.md")]);
    assert_eq!(child.status, ReviewStatus::Failed);
    let messages = finding_messages(child);
    assert!(messages.contains("child-reported files_changed does not match actual"));
    assert!(messages.contains("worker files_changed union differs from actual"));
    assert!(messages.contains("observed-but-not-reported: README.md"));
}

#[test]
fn injected_runner_rejects_missing_worker_execution_journal() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let plan = injected_plan(assignment.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "injected-missing-journal");
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            let child = injected_child_report(&assignment);
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
            return injected_verified_run(command);
        }
        write_injected_json(
            &command.output_last_message,
            &injected_child_report(&assignment),
        );
        injected_verified_run_without_journals(command)
    };

    let report = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("run injected missing journal");

    assert!(!report.success);
    let child = &report.orchestrator_reports[0];
    assert_eq!(child.status, ReviewStatus::Failed);
    assert!(finding_messages(child).contains("execution journal is missing"));
}

#[test]
fn injected_runner_rejects_unexpected_worker_journal_capture() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(true);
    let plan = injected_plan(assignment.clone(), 0);
    let options = injected_options(&repo_path, temp.path(), "injected-extra-journal-capture");
    let mut runner = |command: &ExternalAgentCommand| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        let child = injected_child_report(&assignment);
        if name.contains("review-auditor") {
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &child),
            );
            return injected_verified_run(command);
        }
        write_injected_json(&command.output_last_message, &child);
        let mut run = injected_verified_run(command);
        let mut captures = run.worker_journal_artifacts().to_vec();
        captures.push(WorkerJournalArtifactCapture {
            worker_id: "worker-extra".to_string(),
            path: command
                .output_last_message
                .parent()
                .expect("incoming report root")
                .join("worker-journals/worker-extra.jsonl"),
            status: WorkerJournalArtifactCaptureStatus::Loaded(Vec::new()),
        });
        run.replace_worker_journal_artifacts(captures);
        run
    };

    let report = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("unexpected journal capture should produce a finalized rejection report");

    assert!(!report.success);
    assert!(report.rejected);
    assert!(report.findings.iter().any(|finding| {
        finding
            .message
            .contains("trusted worker journal capture set violates the assignment contract")
            && finding
                .message
                .contains("unexpected worker journal capture 'worker-extra'")
    }));
}

#[test]
fn injected_zero_worker_assignment_rejects_nonempty_worker_journal_capture_set() {
    let (temp, repo_path) = injected_repository();
    let assignment = injected_assignment(false);
    let plan = injected_plan(assignment.clone(), 0);
    let options = injected_options(
        &repo_path,
        temp.path(),
        "injected-zero-worker-extra-journal",
    );
    let mut runner = |command: &ExternalAgentCommand| {
        write_injected_json(
            &command.output_last_message,
            &injected_child_report(&assignment),
        );
        let mut run = injected_verified_run(command);
        assert!(run.worker_journal_artifacts().is_empty());
        run.replace_worker_journal_artifacts(vec![WorkerJournalArtifactCapture {
            worker_id: "worker-extra".to_string(),
            path: command
                .output_last_message
                .parent()
                .expect("incoming report root")
                .join("worker-journals/worker-extra.jsonl"),
            status: WorkerJournalArtifactCaptureStatus::Loaded(Vec::new()),
        }]);
        run
    };

    let report = run_supervisor_plan_with_runner(
        plan,
        SupervisorConsultantPlan::default(),
        options,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        &mut runner,
    )
    .expect("zero-worker unexpected capture should produce a finalized rejection report");

    assert!(!report.success);
    assert!(report.rejected);
    assert!(report.orchestrator_reports.is_empty());
    assert!(report.findings.iter().any(|finding| {
        finding
            .message
            .contains("trusted worker journal capture set violates the assignment contract")
            && finding
                .message
                .contains("unexpected worker journal capture 'worker-extra'")
    }));
}

#[test]
fn injected_schema_and_evidence_matrix_rejects_missing_fields_and_extra_workers() {
    let assignment = injected_assignment(true);
    let mut missing_evidence = injected_child_report(&assignment);
    missing_evidence.worker_reports.clear();
    missing_evidence.audit_reports.clear();
    validate_worker_report_delegation_attestations(
        &assignment,
        Path::new("missing-evidence.json"),
        &mut missing_evidence,
    );
    validate_auditor_reports(
        &assignment,
        Path::new("missing-evidence.json"),
        &mut missing_evidence,
    );
    assert_eq!(missing_evidence.status, ReviewStatus::Failed);
    let missing_messages = finding_messages(&missing_evidence);
    assert!(missing_messages.contains("omitted required worker reports"));
    assert!(missing_messages.contains("omitted required review auditor report"));

    let mut extra_worker = injected_child_report(&assignment);
    let mut undeclared = extra_worker.worker_reports[0].clone();
    undeclared.id = "worker-extra".to_string();
    undeclared.files_changed = vec![PathBuf::from("README.md")];
    extra_worker.worker_reports.push(undeclared);
    validate_worker_report_evidence(
        &assignment,
        &AssignmentMetadata::new(),
        Path::new("extra-worker.json"),
        &mut extra_worker,
    );
    assert_eq!(extra_worker.status, ReviewStatus::Failed);
    assert!(finding_messages(&extra_worker).contains("is not declared in assignment"));

    for scenario in [
        "reviewed-worker-ids",
        "reviewed-paths",
        "commands",
        "validation",
        "terminal-attestation",
        "read-only",
        "remaining-risk",
        "next-action",
    ] {
        let mut child = injected_child_report(&assignment);
        let mut auditor = injected_auditor_report(&assignment, &child);
        auditor.commands_run.push(injected_command_record());
        match scenario {
            "reviewed-worker-ids" => auditor.reviewed_worker_ids.clear(),
            "reviewed-paths" => auditor.reviewed_paths.clear(),
            "commands" => auditor.commands_run.clear(),
            "validation" => auditor.validation_results.clear(),
            "terminal-attestation" => auditor.no_further_delegation = None,
            "read-only" => auditor.read_only = false,
            "remaining-risk" => auditor.remaining_risk.clear(),
            "next-action" => auditor.next_safe_action.clear(),
            _ => unreachable!(),
        }
        child.audit_reports.push(auditor);
        validate_auditor_reports(&assignment, Path::new("auditor-evidence.json"), &mut child);
        assert_eq!(
            child.status,
            ReviewStatus::Failed,
            "missing {scenario} evidence was accepted"
        );
        assert!(child.audit_reports[0].findings.iter().any(|finding| {
            finding.severity == FindingSeverity::Error && finding.message.contains("omitted")
        }));
    }

    for (label, schema, required) in [
        (
            "orchestrator",
            orchestrator_report_schema_value(),
            &[
                "decomposition_completions",
                "worker_reports",
                "audit_reports",
                "remaining_risk",
                "next_safe_action",
            ][..],
        ),
        (
            "worker",
            worker_report_schema_value(),
            &[
                "assignment_kind",
                "target_path",
                "bloated_file_flags",
                "decomposition_completion",
                "no_further_delegation",
                "validation_results",
                "remaining_risk",
            ][..],
        ),
        (
            "auditor",
            auditor_report_schema_value(),
            &[
                "reviewed_worker_ids",
                "reviewed_paths",
                "commands_run",
                "validation_results",
                "no_further_delegation",
                "read_only",
                "remaining_risk",
                "next_safe_action",
            ][..],
        ),
    ] {
        assert_eq!(schema["additionalProperties"], false, "{label} schema open");
        let required_fields = schema["required"]
            .as_array()
            .expect("schema required array");
        for field in required {
            assert!(
                required_fields.iter().any(|value| value == field),
                "{label} schema omitted required field {field}"
            );
        }
    }
}

#[test]
fn worker_report_identity_rejects_declared_assignment_scope_mismatches() {
    let mut assignment = injected_assignment(true);
    assignment.worker_assignments[0].semantic_symbols = vec!["crate::expected_symbol".to_string()];
    assignment.worker_assignments[0].semantic_modules = vec!["crate::expected_module".to_string()];

    for field in ["assigned_paths", "semantic_symbols", "semantic_modules"] {
        let mut report = injected_child_report(&assignment);
        match field {
            "assigned_paths" => {
                report.worker_reports[0].assigned_paths = vec![PathBuf::from("src/other.rs")];
            }
            "semantic_symbols" => {
                report.worker_reports[0].semantic_symbols = vec!["crate::other_symbol".to_string()];
            }
            "semantic_modules" => {
                report.worker_reports[0].semantic_modules = vec!["crate::other_module".to_string()];
            }
            _ => unreachable!(),
        }

        validate_worker_report_evidence(
            &assignment,
            &AssignmentMetadata::new(),
            Path::new("worker-assignment-identity.json"),
            &mut report,
        );

        assert_eq!(
            report.status,
            ReviewStatus::Failed,
            "mismatched {field} was accepted"
        );
        assert!(!report.accepted, "mismatched {field} retained acceptance");
        assert!(report.rejected, "mismatched {field} was not rejected");
        assert_eq!(report.worker_reports[0].status, ReviewStatus::Failed);
        assert!(!report.worker_reports[0].accepted);
        assert!(report.worker_reports[0].rejected);
        assert!(
            finding_messages(&report).contains(&format!(
                "{field} do not exactly match the declared worker assignment"
            )),
            "missing assignment-identity finding for {field}: {}",
            finding_messages(&report)
        );
    }
}

#[test]
fn typed_decomposition_prompt_report_and_final_evidence_remain_gated() {
    let mut assignment = injected_assignment(true);
    assignment
        .assigned_paths
        .push(PathBuf::from("src/readme_part.md"));
    assignment.worker_assignments[0]
        .assigned_paths
        .push(PathBuf::from("src/readme_part.md"));
    let worker = &assignment.worker_assignments[0];
    let metadata = WorkerAssignmentMetadata {
        kind: AssignmentKind::MegafileDecomposition,
        target_path: Some(PathBuf::from("README.md")),
        mechanical_duty: None,
    };
    let assignment_metadata: AssignmentMetadata =
        BTreeMap::from([((assignment.id.clone(), worker.id.clone()), metadata.clone())]).into();

    let worker_value =
        worker_assignment_value(worker, &metadata).expect("serialize typed worker assignment");
    assert_eq!(worker_value["kind"], "megafile_decomposition");
    assert_eq!(worker_value["target_path"], "README.md");
    let assignment_value = orchestrator_assignment_value(&assignment, &assignment_metadata)
        .expect("serialize typed orchestrator assignment");
    assert_eq!(
        assignment_value["worker_assignments"][0]["kind"],
        "megafile_decomposition"
    );
    assert_eq!(
        assignment_value["worker_assignments"][0]["target_path"],
        "README.md"
    );

    let plan = injected_plan(assignment.clone(), 0);
    let prompt = worker_prompt_with_incoming_root(
        &plan,
        &assignment,
        worker,
        &metadata,
        Path::new("/tmp/maco-run"),
        Path::new("/tmp/maco-run/incoming"),
        Path::new("/tmp/maco-run/schemas/worker-report.schema.json"),
    )
    .expect("render typed worker prompt");
    assert!(prompt.contains("Assignment kind: megafile_decomposition"));
    assert!(prompt.contains("Decomposition target path: README.md"));
    assert!(prompt.contains("\"kind\": \"megafile_decomposition\""));
    assert!(prompt.contains("\"target_path\": \"README.md\""));
    assert!(prompt.contains("does not bypass the isolated worktree, hard claim"));

    let mut child = injected_child_report(&assignment);
    child.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
    child.worker_reports[0].target_path = Some(PathBuf::from("./README.md"));
    child.worker_reports[0].files_changed = vec![
        PathBuf::from("./README.md"),
        PathBuf::from("./src/readme_part.md"),
    ];
    child.files_changed = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/readme_part.md"),
    ];
    child.worker_reports[0].bloated_file_flags = vec![
        BloatedFileFlag {
            path: PathBuf::from("./README.md"),
        },
        BloatedFileFlag {
            path: PathBuf::from("README.md"),
        },
    ];
    child.worker_reports[0].decomposition_completion = Some(DecompositionCompletion {
        target_path: PathBuf::from("./README.md"),
        replacement_paths: vec![PathBuf::from("./src/readme_part.md")],
        supervisor_candidate_binding: None,
    });
    child.decomposition_completions = vec![DecompositionCompletion {
        target_path: PathBuf::from("./README.md"),
        replacement_paths: vec![PathBuf::from("./src/readme_part.md")],
        supervisor_candidate_binding: None,
    }];
    validate_worker_report_evidence(
        &assignment,
        &assignment_metadata,
        Path::new("typed-worker.json"),
        &mut child,
    );
    validate_assignment_report_plumbing(
        &assignment,
        &assignment_metadata,
        Path::new("typed-child.json"),
        &mut child,
    );
    assert_eq!(child.status, ReviewStatus::Succeeded);
    assert_eq!(
        child.worker_reports[0].bloated_file_flags,
        vec![BloatedFileFlag {
            path: PathBuf::from("README.md")
        }]
    );
    assert_eq!(
        child.decomposition_completions,
        vec![DecompositionCompletion {
            target_path: PathBuf::from("README.md"),
            replacement_paths: vec![PathBuf::from("src/readme_part.md")],
            supervisor_candidate_binding: None,
        }]
    );

    let reports = vec![child.clone(), child];
    assert_eq!(
        accepted_bloated_file_flags(&reports),
        vec![BloatedFileFlag {
            path: PathBuf::from("README.md")
        }]
    );
    assert_eq!(
        accepted_decomposition_candidates(&reports),
        vec![DecompositionCompletion {
            target_path: PathBuf::from("README.md"),
            replacement_paths: vec![PathBuf::from("src/readme_part.md")],
            supervisor_candidate_binding: None,
        }]
    );
    let mut final_report =
        artifact_test_final_report(&RunId::new("typed-megafile-final").expect("run id"));
    final_report.bloated_file_flags = accepted_bloated_file_flags(&reports);
    final_report.decomposition_candidates = accepted_decomposition_candidates(&reports);
    let final_value = serde_json::to_value(final_report).expect("serialize final report");
    assert_eq!(final_value["bloated_file_flags"][0]["path"], "README.md");
    assert_eq!(
        final_value["decomposition_candidates"][0]["target_path"],
        "README.md"
    );
    assert!(final_value.get("successful_decompositions").is_none());
}

#[test]
fn typed_decomposition_rejects_missing_target_replacements_and_ordinary_pseudo_evidence() {
    let mut assignment = injected_assignment(true);
    assignment
        .assigned_paths
        .push(PathBuf::from("src/readme_part.md"));
    assignment.worker_assignments[0]
        .assigned_paths
        .push(PathBuf::from("src/readme_part.md"));
    let worker = &assignment.worker_assignments[0];
    let metadata = WorkerAssignmentMetadata {
        kind: AssignmentKind::MegafileDecomposition,
        target_path: Some(PathBuf::from("README.md")),
        mechanical_duty: None,
    };
    let assignment_metadata: AssignmentMetadata =
        BTreeMap::from([((assignment.id.clone(), worker.id.clone()), metadata)]).into();

    let mut no_replacements = injected_child_report(&assignment);
    no_replacements.files_changed = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/readme_part.md"),
    ];
    no_replacements.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
    no_replacements.worker_reports[0].target_path = Some(PathBuf::from("README.md"));
    no_replacements.worker_reports[0].files_changed = no_replacements.files_changed.clone();
    no_replacements.worker_reports[0].decomposition_completion = Some(DecompositionCompletion {
        target_path: PathBuf::from("README.md"),
        replacement_paths: Vec::new(),
        supervisor_candidate_binding: None,
    });
    validate_worker_report_evidence(
        &assignment,
        &assignment_metadata,
        Path::new("no-replacements.json"),
        &mut no_replacements,
    );
    assert_eq!(no_replacements.status, ReviewStatus::Failed);
    assert!(finding_messages(&no_replacements).contains("at least one replacement path"));

    let mut no_target_change = injected_child_report(&assignment);
    no_target_change.files_changed = vec![PathBuf::from("src/readme_part.md")];
    no_target_change.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
    no_target_change.worker_reports[0].target_path = Some(PathBuf::from("README.md"));
    no_target_change.worker_reports[0].files_changed = no_target_change.files_changed.clone();
    no_target_change.worker_reports[0].decomposition_completion = Some(DecompositionCompletion {
        target_path: PathBuf::from("README.md"),
        replacement_paths: vec![PathBuf::from("src/readme_part.md")],
        supervisor_candidate_binding: None,
    });
    validate_worker_report_evidence(
        &assignment,
        &assignment_metadata,
        Path::new("no-target-change.json"),
        &mut no_target_change,
    );
    assert_eq!(no_target_change.status, ReviewStatus::Failed);
    assert!(finding_messages(&no_target_change).contains("files_changed omits the exact target"));

    let ordinary_metadata = AssignmentMetadata::new();
    let mut ordinary = injected_child_report(&assignment);
    ordinary.worker_reports[0].decomposition_completion = Some(DecompositionCompletion {
        target_path: PathBuf::from("README.md"),
        replacement_paths: vec![PathBuf::from("src/readme_part.md")],
        supervisor_candidate_binding: None,
    });
    validate_worker_report_evidence(
        &assignment,
        &ordinary_metadata,
        Path::new("ordinary-pseudo-decomposition.json"),
        &mut ordinary,
    );
    assert_eq!(ordinary.status, ReviewStatus::Failed);
    assert!(finding_messages(&ordinary)
        .contains("ordinary assignment must not report decomposition_completion"));

    let mut self_asserted = injected_child_report(&assignment);
    self_asserted.files_changed = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/readme_part.md"),
    ];
    self_asserted.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
    self_asserted.worker_reports[0].target_path = Some(PathBuf::from("README.md"));
    self_asserted.worker_reports[0].files_changed = self_asserted.files_changed.clone();
    self_asserted.worker_reports[0].decomposition_completion = Some(DecompositionCompletion {
        target_path: PathBuf::from("README.md"),
        replacement_paths: vec![PathBuf::from("src/readme_part.md")],
        supervisor_candidate_binding: Some(CandidateValidationBinding {
            version: 1,
            agent_id: assignment.id.clone(),
            primary_head: None,
            agent_head: None,
            merge_base: None,
            diff_oid: "0000000000000000000000000000000000000000".to_string(),
        }),
    });
    validate_worker_report_evidence(
        &assignment,
        &assignment_metadata,
        Path::new("worker-self-asserted-binding.json"),
        &mut self_asserted,
    );
    assert_eq!(self_asserted.status, ReviewStatus::Failed);
    assert!(finding_messages(&self_asserted)
        .contains("must not self-assert supervisor_candidate_binding"));
    assert!(decomposition_completion_schema_value()["properties"]
        .get("supervisor_candidate_binding")
        .is_none());
}

#[test]
fn finalized_decomposition_evidence_binds_exact_candidate_and_exposes_chain_ids() {
    skip_without_containment!();
    let (_temp, repo_path) = injected_repository();
    let manager = WorktreeManager::new(&repo_path);
    let agent = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create finalized-evidence agent worktree");
    fs::write(agent.path.join("README.md"), "x\n").expect("shrink test target");
    fs::create_dir_all(agent.path.join("src")).expect("create test replacement parent");
    fs::write(agent.path.join("src/readme_part.md"), "part\n").expect("write test replacement");
    let run_id = RunId::new("verified-decomposition-chain").expect("run id");
    write_test_finalized_megafile_decomposition_evidence(
        &repo_path,
        run_id.clone(),
        "agent-a",
        "worker-a",
        PathBuf::from("README.md"),
        vec![PathBuf::from("src/readme_part.md")],
    )
    .expect("write finalized decomposition evidence");
    let exact_paths = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/readme_part.md"),
    ];
    let evidence = verified_megafile_decomposition_evidence(
        &repo_path,
        run_id.clone(),
        "agent-a",
        Path::new("README.md"),
        &exact_paths,
    )
    .expect("verify exact finalized evidence");
    assert_eq!(evidence.run_id, run_id);
    assert_eq!(evidence.orchestrator_id, "agent-a");
    assert_eq!(evidence.worker_id, "worker-a");
    assert_eq!(evidence.target_path, PathBuf::from("README.md"));
    assert_eq!(
        evidence.replacement_paths,
        vec![PathBuf::from("src/readme_part.md")]
    );
    assert_eq!(evidence.supervisor_candidate_binding.agent_id, "agent-a");

    let missing_binding_run =
        RunId::new("missing-decomposition-content-binding").expect("missing binding run id");
    write_test_finalized_megafile_decomposition_evidence_with_binding(
        &repo_path,
        missing_binding_run.clone(),
        "agent-a",
        "worker-a",
        PathBuf::from("README.md"),
        vec![PathBuf::from("src/readme_part.md")],
        false,
    )
    .expect("write finalized evidence without supervisor binding");
    let missing_error = verified_megafile_decomposition_evidence(
        &repo_path,
        missing_binding_run,
        "agent-a",
        Path::new("README.md"),
        &exact_paths,
    )
    .expect_err("missing finalized content binding must fail closed");
    assert!(missing_error
        .to_string()
        .contains("missing the supervisor-inspected candidate binding"));

    let mut extra_paths = exact_paths;
    extra_paths.push(PathBuf::from("unrelated.txt"));
    let error = verified_megafile_decomposition_evidence(
        &repo_path,
        run_id,
        "agent-a",
        Path::new("README.md"),
        &extra_paths,
    )
    .expect_err("unrelated candidate path must break exact run binding");
    assert!(error
        .to_string()
        .contains("files_changed does not exactly match the merge candidate"));
}

#[test]
fn supervisor_injects_binding_from_stable_candidate_and_detects_later_bytes() {
    skip_without_containment!();
    let (_temp, repo_path) = injected_repository();
    let mut assignment = injected_assignment(true);
    assignment
        .assigned_paths
        .push(PathBuf::from("src/readme_part.md"));
    assignment.worker_assignments[0]
        .assigned_paths
        .push(PathBuf::from("src/readme_part.md"));
    let metadata = WorkerAssignmentMetadata {
        kind: AssignmentKind::MegafileDecomposition,
        target_path: Some(PathBuf::from("README.md")),
        mechanical_duty: None,
    };
    let assignment_metadata: AssignmentMetadata = BTreeMap::from([(
        (
            assignment.id.clone(),
            assignment.worker_assignments[0].id.clone(),
        ),
        metadata,
    )])
    .into();

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
    fs::create_dir_all(agent.path.join("src")).expect("create inspected replacement parent");
    fs::write(agent.path.join("src/readme_part.md"), "reviewed\n")
        .expect("write inspected replacement");

    let mut child = injected_child_report(&assignment);
    child.files_changed = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/readme_part.md"),
    ];
    child.worker_reports[0].assignment_kind = AssignmentKind::MegafileDecomposition;
    child.worker_reports[0].target_path = Some(PathBuf::from("README.md"));
    child.worker_reports[0].files_changed = child.files_changed.clone();
    let completion = DecompositionCompletion {
        target_path: PathBuf::from("README.md"),
        replacement_paths: vec![PathBuf::from("src/readme_part.md")],
        supervisor_candidate_binding: None,
    };
    child.worker_reports[0].decomposition_completion = Some(completion.clone());
    child.decomposition_completions = vec![completion];
    validate_worker_report_evidence(
        &assignment,
        &assignment_metadata,
        Path::new("stable-candidate-worker.json"),
        &mut child,
    );
    validate_assignment_report_plumbing(
        &assignment,
        &assignment_metadata,
        Path::new("stable-candidate-child.json"),
        &mut child,
    );
    assert_eq!(child.status, ReviewStatus::Succeeded);

    let lease = manager
        .acquire_write_execution_lease(&assignment.id)
        .expect("acquire supervisor candidate lease");
    let before =
        bind_supervisor_decomposition_candidate(&repo_path, &assignment, &mut child, &lease)
            .expect("bind supervisor candidate")
            .expect("typed decomposition inspection");
    assert_eq!(
        child.decomposition_completions[0].supervisor_candidate_binding,
        Some(before.binding.clone())
    );
    assert_eq!(
        child.worker_reports[0]
            .decomposition_completion
            .as_ref()
            .and_then(|completion| completion.supervisor_candidate_binding.clone()),
        Some(before.binding.clone())
    );

    fs::write(agent.path.join("src/readme_part.md"), "substituted\n")
        .expect("substitute inspected replacement bytes");
    let after = inspect_supervisor_candidate(&repo_path, &assignment, &lease)
        .expect("recapture substituted candidate");
    assert_eq!(after.changed_paths, before.changed_paths);
    assert_ne!(after.binding, before.binding);
}

#[test]
fn worker_bloated_file_flags_are_bounded_and_fail_closed() {
    let assignment = injected_assignment(true);
    let mut child = injected_child_report(&assignment);
    child.worker_reports[0].bloated_file_flags = (0..=MAX_BLOATED_FILE_FLAGS_PER_WORKER)
        .map(|_| BloatedFileFlag {
            path: PathBuf::from("README.md"),
        })
        .collect();
    validate_worker_report_evidence(
        &assignment,
        &AssignmentMetadata::new(),
        Path::new("too-many-flags.json"),
        &mut child,
    );
    assert_eq!(child.status, ReviewStatus::Failed);
    assert!(child.worker_reports[0].bloated_file_flags.is_empty());
    assert!(finding_messages(&child).contains("at most 64 are allowed"));

    let schema = worker_report_schema_value();
    assert_eq!(
        schema["properties"]["bloated_file_flags"]["maxItems"],
        MAX_BLOATED_FILE_FLAGS_PER_WORKER
    );
    assert_eq!(
        schema["properties"]["bloated_file_flags"]["items"]["additionalProperties"],
        false
    );
}

#[test]
fn injected_worker_execution_journals_reject_material_mismatches() {
    let assignment = injected_assignment(true);
    let report_path = Path::new("worker-journal-evidence.json");

    let mut missing = injected_child_report(&assignment);
    missing.files_changed = vec![PathBuf::from("README.md")];
    missing.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
    validate_worker_execution_journal_evidence(
        &assignment,
        report_path,
        &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Missing),
        &mut missing,
    );
    assert_eq!(missing.status, ReviewStatus::Failed);
    assert!(finding_messages(&missing).contains("execution journal is missing"));

    let mut invalid = injected_child_report(&assignment);
    validate_worker_execution_journal_evidence(
        &assignment,
        report_path,
        &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Invalid(
            "not JSONL".to_string(),
        )),
        &mut invalid,
    );
    assert_eq!(invalid.status, ReviewStatus::Failed);
    assert!(finding_messages(&invalid).contains("execution journal"));
    assert!(finding_messages(&invalid).contains("invalid"));

    let mut unsupported_by_journal = injected_child_report(&assignment);
    unsupported_by_journal.files_changed = vec![PathBuf::from("README.md")];
    unsupported_by_journal.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
    validate_worker_execution_journal_evidence(
        &assignment,
        report_path,
        &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(Vec::new())),
        &mut unsupported_by_journal,
    );
    assert_eq!(unsupported_by_journal.status, ReviewStatus::Failed);
    assert!(
        finding_messages(&unsupported_by_journal).contains("not supported by execution journal")
    );

    let mut unsupported_by_git = injected_child_report(&assignment);
    unsupported_by_git.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
    validate_worker_execution_journal_evidence(
        &assignment,
        report_path,
        &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(vec![
            injected_journal_entry(vec![PathBuf::from("README.md")]),
        ])),
        &mut unsupported_by_git,
    );
    assert_eq!(unsupported_by_git.status, ReviewStatus::Failed);
    assert!(finding_messages(&unsupported_by_git)
        .contains("not supported by supervisor-inspected Git diff"));

    let mut outside_assigned = injected_child_report(&assignment);
    validate_worker_execution_journal_evidence(
        &assignment,
        report_path,
        &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(vec![
            injected_journal_entry(vec![PathBuf::from("Cargo.toml")]),
        ])),
        &mut outside_assigned,
    );
    assert_eq!(outside_assigned.status, ReviewStatus::Failed);
    assert!(finding_messages(&outside_assigned).contains("outside assigned_paths"));

    let mut journal_claim_without_git = injected_child_report(&assignment);
    validate_worker_execution_journal_evidence(
        &assignment,
        report_path,
        &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(vec![
            injected_journal_entry(vec![PathBuf::from("README.md")]),
        ])),
        &mut journal_claim_without_git,
    );
    assert_eq!(journal_claim_without_git.status, ReviewStatus::Failed);
    assert!(finding_messages(&journal_claim_without_git)
        .contains("changed paths are not supported by supervisor-inspected Git diff"));

    let mut command_claim_without_journal = injected_child_report(&assignment);
    command_claim_without_journal.worker_reports[0]
        .commands_run
        .push(injected_command_record());
    validate_worker_execution_journal_evidence(
        &assignment,
        report_path,
        &injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(Vec::new())),
        &mut command_claim_without_journal,
    );
    assert_eq!(command_claim_without_journal.status, ReviewStatus::Failed);
    assert!(finding_messages(&command_claim_without_journal)
        .contains("commands_run entries are not supported by execution journal"));
}

#[test]
fn worker_journal_reconciliation_accepts_exact_multiline_and_failed_command_identities() {
    let assignment = injected_assignment(true);
    let report_path = Path::new("worker-journal-exact-command-identities.json");
    let cwd = PathBuf::from("/native/local/tmp/c6/a1/.maco/worktrees/r/assignment-001");
    let multiline_command = vec![
        "bash".to_string(),
        "-lc".to_string(),
        "set -euo pipefail\nprivate_git=/native/local/tmp/c6/a1/r/.git/worktrees/assignment-001/maco-private-git-v1\ncommon_objects=/native/local/tmp/c6/a1/r/.git/objects\nGIT_ALTERNATE_OBJECT_DIRECTORIES=\"$common_objects\" git --git-dir=\"$private_git\" --work-tree=/native/local/tmp/c6/a1/.maco/worktrees/r/assignment-001 status --short".to_string(),
    ];
    let failed_command = vec![
        "bash".to_string(),
        "-lc".to_string(),
        "git add -- RELEASE_NOTES.md".to_string(),
    ];

    let mut multiline_record = injected_command_record();
    multiline_record.command = multiline_command.clone();
    multiline_record.cwd = cwd.clone();
    let mut failed_record = injected_command_record();
    failed_record.command = failed_command.clone();
    failed_record.cwd = cwd.clone();
    failed_record.exit_code = Some(128);
    failed_record.status = ReviewStatus::Failed;
    failed_record.error = Some("managed worktree index is read-only".to_string());

    let journals = injected_worker_journal_evidence(WorkerExecutionJournalStatus::Loaded(vec![
        WorkerExecutionJournalEntry {
            command: multiline_command,
            cwd: cwd.clone(),
            start_timestamp: "2026-08-25T02:16:22Z".to_string(),
            end_timestamp: "2026-08-25T02:16:22Z".to_string(),
            changed_paths: Vec::new(),
        },
        WorkerExecutionJournalEntry {
            command: failed_command,
            cwd,
            start_timestamp: "2026-08-25T02:15:49Z".to_string(),
            end_timestamp: "2026-08-25T02:15:49Z".to_string(),
            changed_paths: Vec::new(),
        },
    ]));

    let mut exact = injected_child_report(&assignment);
    exact.worker_reports[0].commands_run = vec![multiline_record, failed_record];
    validate_worker_execution_journal_evidence(&assignment, report_path, &journals, &mut exact);

    assert_eq!(exact.status, ReviewStatus::Succeeded);
    assert!(exact.accepted);
    assert!(!exact.rejected);
    assert_eq!(
        exact.worker_reports[0].commands_run[1].status,
        ReviewStatus::Failed,
        "a failed command remains reportable when its command and cwd identity are exact"
    );
    assert!(!finding_messages(&exact).contains("not supported by execution journal"));

    let mut paraphrased = injected_child_report(&assignment);
    paraphrased.worker_reports[0].commands_run = exact.worker_reports[0].commands_run.clone();
    paraphrased.worker_reports[0].commands_run[0].command[2] =
        "validate private Git status".to_string();
    validate_worker_execution_journal_evidence(
        &assignment,
        report_path,
        &journals,
        &mut paraphrased,
    );

    assert_eq!(paraphrased.status, ReviewStatus::Failed);
    assert!(!paraphrased.accepted);
    assert!(paraphrased.rejected);
    assert!(finding_messages(&paraphrased)
        .contains("commands_run entries are not supported by execution journal"));
}

#[test]
fn primary_integrity_matrix_covers_index_flags_split_sparse_submodule_non_utf8_and_runtime_roots() {
    let base = injected_primary_snapshot();
    let replacement = injected_oid("replacement");
    let mut cases = Vec::new();

    for (name, tag) in [("assume-unchanged", b'h'), ("skip-worktree", b'S')] {
        let mut before = base.clone();
        before
            .index
            .get_mut(&injected_index_key("README.md"))
            .unwrap()
            .tag = tag;
        let mut after = before.clone();
        after.worktree.insert(
            b"README.md".to_vec(),
            PrimaryPathState::File {
                id: replacement,
                mode: 0o100644,
            },
        );
        cases.push((
            name,
            before,
            after,
            "worktree content/type changed",
            PathBuf::from("README.md"),
        ));
    }

    let before = base.clone();
    let mut after = before.clone();
    after.index_storage.worktree_index = IndexFileSnapshot::Present {
        bytes: 9,
        digest: replacement,
    };
    cases.push((
        "raw-index",
        before,
        after,
        "raw worktree index",
        PathBuf::from(".git/index"),
    ));

    let mut before = base.clone();
    before.index_storage.shared_index = Some(SharedIndexFileSnapshot {
        path: PathBuf::from(".git/sharedindex.test"),
        storage: IndexFileSnapshot::Present {
            bytes: 7,
            digest: injected_oid("shared"),
        },
    });
    let mut after = before.clone();
    after.index_storage.shared_index = None;
    cases.push((
        "split-index",
        before,
        after,
        "split-index storage changed",
        PathBuf::from(".git/index"),
    ));

    let mut before = base.clone();
    before.index.insert(
        injected_index_key("other"),
        PrimaryIndexEntryState {
            id: injected_oid("sparse-tree"),
            mode: SPARSE_DIRECTORY_MODE,
            tag: b'S',
        },
    );
    before.worktree.insert(
        b"other".to_vec(),
        PrimaryPathState::Directory {
            nested_repository: None,
            contents_digest: Some(injected_oid("sparse-before")),
            mode: 0o040755,
        },
    );
    let mut after = before.clone();
    after.worktree.insert(
        b"other".to_vec(),
        PrimaryPathState::Directory {
            nested_repository: None,
            contents_digest: Some(injected_oid("sparse-after")),
            mode: 0o040755,
        },
    );
    cases.push((
        "sparse-directory",
        before,
        after,
        "worktree content/type changed",
        PathBuf::from("other"),
    ));

    let nested_before = base.clone();
    let mut nested_after = nested_before.clone();
    nested_after.worktree.insert(
        b"README.md".to_vec(),
        PrimaryPathState::File {
            id: replacement,
            mode: 0o100644,
        },
    );
    let mut before = base.clone();
    before.index.insert(
        injected_index_key("deps/nested"),
        PrimaryIndexEntryState {
            id: injected_oid("gitlink"),
            mode: GITLINK_MODE,
            tag: b'H',
        },
    );
    before.worktree.insert(
        b"deps/nested".to_vec(),
        PrimaryPathState::Directory {
            nested_repository: Some(Box::new(nested_before)),
            contents_digest: None,
            mode: 0o040755,
        },
    );
    let mut after = before.clone();
    after.worktree.insert(
        b"deps/nested".to_vec(),
        PrimaryPathState::Directory {
            nested_repository: Some(Box::new(nested_after)),
            contents_digest: None,
            mode: 0o040755,
        },
    );
    cases.push((
        "submodule",
        before,
        after,
        "worktree content/type changed",
        PathBuf::from("deps/nested"),
    ));

    let non_utf8 = vec![b'o', b'p', b'-', 0x80];
    let before = base.clone();
    let mut after = before.clone();
    after.worktree.insert(
        non_utf8.clone(),
        PrimaryPathState::File {
            id: replacement,
            mode: 0o100644,
        },
    );
    cases.push((
        "non-utf8",
        before,
        after,
        "worktree content/type changed",
        finding_path_from_git_bytes(&non_utf8),
    ));

    let mut before = base.clone();
    before.status.insert(
        b".maco-cache/tracked.txt".to_vec(),
        PrimaryStatusState {
            code: *b" M",
            original_path: None,
        },
    );
    let mut after = before.clone();
    after
        .status
        .get_mut(b".maco-cache/tracked.txt".as_slice())
        .unwrap()
        .code = *b"MM";
    cases.push((
        "tracked-runtime-root",
        before,
        after,
        "Git status changed",
        PathBuf::from(".maco-cache/tracked.txt"),
    ));

    for (name, before, after, detail, path) in cases {
        let changes = primary_integrity_changes(&before, &after);
        assert!(!changes.is_empty(), "scenario {name} was not detected");
        assert!(
            changes.details.iter().any(|value| value.contains(detail)),
            "scenario {name} lacked detail {detail}: {:?}",
            changes.details
        );
        assert!(
            changes.paths.contains(&path),
            "scenario {name} lacked path {path:?}"
        );
    }

    let mut stable_flagged = base.clone();
    stable_flagged
        .index
        .get_mut(&injected_index_key("README.md"))
        .unwrap()
        .tag = b'h';
    assert!(primary_integrity_changes(&stable_flagged, &stable_flagged).is_empty());
    for path in [
        b".maco/run.json".as_slice(),
        b".maco-cache/state.json".as_slice(),
        b".agents/live/claims/test.md".as_slice(),
    ] {
        assert!(is_untracked_runtime_artifact_bytes(path));
    }
    assert!(!is_untracked_runtime_artifact_bytes(b".maco-visible"));
    assert!(!is_untracked_runtime_artifact_bytes(b".agents/config.json"));
}

#[test]
fn primary_snapshot_captures_real_index_flags_split_storage_and_ignores_untracked_runtime() {
    let (_temp, repo_path) = injected_repository();
    run_injected_git(
        &repo_path,
        &["update-index", "--assume-unchanged", "README.md"],
    );
    let assumed = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("snapshot assume-unchanged index");
    assert!(assumed.index[&injected_index_key("README.md")]
        .tag
        .is_ascii_lowercase());

    run_injected_git(
        &repo_path,
        &["update-index", "--no-assume-unchanged", "README.md"],
    );
    run_injected_git(
        &repo_path,
        &["update-index", "--skip-worktree", "README.md"],
    );
    let skipped = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("snapshot skip-worktree index");
    assert_eq!(skipped.index[&injected_index_key("README.md")].tag, b'S');

    run_injected_git(
        &repo_path,
        &["update-index", "--no-skip-worktree", "README.md"],
    );
    let ordinary = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("snapshot ordinary index");
    run_injected_git(&repo_path, &["update-index", "--split-index"]);
    let split = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("snapshot split index");
    assert!(split.index_storage.shared_index.is_some());
    let split_changes = primary_integrity_changes(&ordinary, &split);
    assert!(split_changes
        .details
        .iter()
        .any(|detail| detail.contains("split-index storage changed")));
    let split_stable = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("repeat stable split-index snapshot");
    assert!(primary_integrity_changes(&split, &split_stable).is_empty());

    fs::create_dir_all(repo_path.join(".maco-cache")).expect("create runtime root");
    fs::write(repo_path.join(".maco-cache/runtime.json"), "{}\n").expect("write runtime artifact");
    let runtime = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("snapshot runtime artifact");
    assert!(!runtime
        .status
        .contains_key(b".maco-cache/runtime.json".as_slice()));
}

#[test]
fn primary_snapshot_detects_changes_to_preexisting_dirty_untracked_and_tracked_runtime_paths() {
    let (_temp, repo_path) = injected_repository();
    fs::create_dir_all(repo_path.join(".maco-cache")).expect("create tracked runtime root");
    fs::write(
        repo_path.join(".maco-cache/tracked.txt"),
        "tracked runtime\n",
    )
    .expect("write tracked runtime file");
    commit_injected_repository(&repo_path, "track runtime file");
    fs::write(repo_path.join("README.md"), "preexisting dirty\n")
        .expect("write dirty tracked path");
    fs::write(
        repo_path.join("operator-notes.txt"),
        "preexisting untracked\n",
    )
    .expect("write preexisting untracked path");

    let before = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("snapshot preexisting state");
    let unchanged = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("repeat unchanged preexisting snapshot");
    assert!(primary_integrity_changes(&before, &unchanged).is_empty());

    fs::write(repo_path.join("README.md"), "changed dirty path\n")
        .expect("mutate dirty tracked path");
    fs::write(
        repo_path.join("operator-notes.txt"),
        "changed untracked path\n",
    )
    .expect("mutate untracked path");
    fs::write(
        repo_path.join(".maco-cache/tracked.txt"),
        "changed tracked runtime\n",
    )
    .expect("mutate tracked runtime path");
    let after = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("snapshot changed preexisting state");
    let changes = primary_integrity_changes(&before, &after);
    for path in [
        PathBuf::from("README.md"),
        PathBuf::from("operator-notes.txt"),
        PathBuf::from(".maco-cache/tracked.txt"),
    ] {
        assert!(
            changes.paths.contains(&path),
            "missing changed path {path:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn primary_snapshot_supports_non_utf8_repository_root_without_lossy_git_arguments() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let temp = tempfile::tempdir().expect("temporary non-UTF-8 root");
    let repo_path = temp.path().join(OsString::from_vec(b"repo-\x80".to_vec()));
    Repository::init(&repo_path).expect("initialize non-UTF-8 repository");
    fs::write(repo_path.join("README.md"), "baseline\n").expect("write baseline");
    commit_injected_repository(&repo_path, "baseline");

    let snapshot = primary_worktree_snapshot(
        &repo_path,
        SupervisorExecutionRuntime::NonpublishableSimulation,
    )
    .expect("capture non-UTF-8 primary snapshot");
    assert!(snapshot.inspection_problem().is_none());
    let serialized = serializable_path(&repo_path);
    assert!(serialized.starts_with("<non-utf8-git-path>/"));
    assert!(serialized.is_ascii());
    assert!(!serialized.contains('\u{fffd}'));
}

#[test]
fn parses_clean_child_report_json_without_recovery() {
    let parsed: ParsedReport<OrchestratorReviewReport> =
        parse_report_json(&sample_child_report_json("child-a"))
            .expect("clean child report should parse");
    assert_eq!(parsed.report.id, "child-a");
    assert!(!parsed.recovered);
}

#[test]
fn parses_fenced_auditor_report_json_with_recovery() {
    let contents = format!("```json\n{}\n```", sample_auditor_report_json("auditor-a"));
    let parsed: ParsedReport<AuditorReport> =
        parse_report_json(&contents).expect("fenced auditor report should parse");
    assert_eq!(parsed.report.id, "auditor-a");
    assert!(parsed.recovered);
}

#[test]
fn extracts_last_top_level_child_report_json_with_recovery() {
    let contents = format!(
        "summary before\n{{\"ignored\": true}}\n{}\ntrailing notes",
        sample_child_report_json("child-prose")
    );
    let parsed: ParsedReport<OrchestratorReviewReport> =
        parse_report_json(&contents).expect("prose-wrapped child report should parse");
    assert_eq!(parsed.report.id, "child-prose");
    assert!(parsed.recovered);
}

#[test]
fn rejects_report_garbage_beyond_recovery() {
    let error =
        parse_report_json::<OrchestratorReviewReport>("{\n  \"role\": \"child_orchestrator\"\n}")
            .expect_err("malformed contract should not parse");
    let message = error.to_string();
    assert!(message.contains("report JSON/contract parse failed"));
    assert!(message.contains("missing field `id` at line 3 column 1"));
    assert!(message.contains("lenient JSON extraction did not produce"));
}

#[test]
fn missing_child_report_preserves_original_and_adds_actionable_contract_finding() {
    let temp = tempfile::tempdir().expect("temporary report fixture");
    let workspace = temp.path().join("workspace");
    let artifacts = temp.path().join("artifacts");
    fs::create_dir(&workspace).expect("create report fixture workspace");
    fs::create_dir(&artifacts).expect("create report fixture artifacts");
    let command = control_test_command(&workspace, &artifacts);
    let external_run = injected_verified_run_without_journals(&command);
    let assignment = injected_assignment(false);
    let report_path = Path::new("assignments/child-a.raw.json");
    let parse_error = "failed to parse child report assignments/child-a.raw.json: report JSON/contract parse failed: missing field `id` at line 3 column 1";
    let report = missing_child_report(
        &assignment,
        report_path,
        &external_run,
        &command,
        parse_error.to_string(),
    );
    assert_eq!(report.findings.len(), 2);
    assert_eq!(
        report.findings[0].message,
        format!("required child report is missing or invalid: {parse_error}")
    );
    assert_eq!(report.findings[0].severity, FindingSeverity::Error);
    assert_eq!(report.findings[1].severity, FindingSeverity::Error);
    assert!(report.findings[1]
        .message
        .contains("assignments/child-a.raw.json"));
    assert!(report.findings[1]
        .message
        .contains("missing field `id` at line 3 column 1"));
    assert!(report.findings[1].message.contains("Corrective action"));
    assert_eq!(report.findings[1].paths, vec![report_path.to_path_buf()]);
}

#[test]
fn thread_id_parser_uses_first_valid_id_in_bounded_stdout_jsonl() {
    let stdout = b"diagnostic prelude\n{\"type\":\"thread.started\",\"thread_id\":\"thread-first\"}\n{\"thread_id\":\"thread-later\"}\n";
    assert_eq!(
        codex_thread_id_from_stdout(stdout).as_deref(),
        Some("thread-first")
    );
    assert_eq!(
        codex_thread_id_from_stdout(
            b"{\"type\":\"turn.started\"}\n{\"thread_id\":\"thread-later\"}\n"
        )
        .as_deref(),
        Some("thread-later")
    );
    assert_eq!(
            codex_thread_id_from_stdout(
                b"{\"thread_id\":\"\"}\n{\"thread_id\":\"bad\\nthread\"}\n{\"thread_id\":\"thread-valid\"}\n"
            )
            .as_deref(),
            Some("thread-valid")
        );
}

#[cfg(unix)]
#[test]
fn finding_serialization_escapes_non_utf8_paths_reversibly() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let finding = Finding {
        severity: FindingSeverity::Error,
        message: "non-UTF8 evidence".to_string(),
        paths: vec![PathBuf::from(OsString::from_vec(vec![
            b'b', b'a', b'd', b'-', 0x80,
        ]))],
    };

    let value = serde_json::to_value(finding).expect("serialize finding");
    assert_eq!(value["paths"][0], "<non-utf8-git-path>/6261642d80");
}

#[cfg(unix)]
#[test]
fn supervisor_required_optional_and_vector_paths_share_reversible_serialization() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let path = PathBuf::from(OsString::from_vec(vec![b'r', b'o', b'o', b't', 0x80]));
    let encoded = "<non-utf8-git-path>/726f6f7480";
    let plan = SupervisorPlan {
        version: SUPERVISOR_SCHEMA_VERSION,
        task: "path serialization".to_string(),
        task_file: Some(path.clone()),
        max_depth: 2,
        max_child_assignments: 1,
        max_child_retries: 0,
        max_gate_corrections: 0,
        child_timeout_seconds: 1,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: default_supervisor_review_lenses(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments: vec![OrchestratorAssignment {
            id: "child-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![path.clone()],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: vec![WorkerAssignment {
                id: "worker-a".to_string(),
                role: AgentRole::Worker,
                role_category: None,
                selection_source: None,
                assigned_paths: vec![path.clone()],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: None,
                environment_requirements: Vec::new(),
                report_path: Some(path.clone()),
            }],
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        }],
    };
    let value = serde_json::to_value(plan).expect("serialize plan paths");
    assert_eq!(value["task_file"], encoded);
    assert_eq!(value["assignments"][0]["assigned_paths"][0], encoded);
    assert_eq!(
        value["assignments"][0]["worker_assignments"][0]["report_path"],
        encoded
    );

    let record = CommandRunRecord {
        command: Vec::new(),
        cwd: path,
        exit_code: Some(0),
        status: ReviewStatus::Succeeded,
        timeout_seconds: 1,
        duration_ms: 0,
        timed_out: false,
        stdout: String::new(),
        stderr: String::new(),
        sandbox_denials: Vec::new(),
        environment_preflight_results: Vec::new(),
        environment_failures: Vec::new(),
        error: None,
    };
    let value = serde_json::to_value(record).expect("serialize command cwd");
    assert_eq!(value["cwd"], encoded);
}
