use super::*;
#[cfg(target_os = "linux")]
use crate::process_runner::{ExternalCodexProfile, Shell};

fn run_evidence_rejected_source(
    temp: &tempfile::TempDir,
    repo: &Path,
    run_id: &str,
    rejection_kind: AuditorRejectionKind,
) -> (SupervisorFinalReport, OrchestratorAssignment, PathBuf) {
    run_evidence_rejected_source_with_assignment(
        temp,
        repo,
        run_id,
        rejection_kind,
        injected_assignment(true),
    )
}

fn reaudit_source_child_report(assignment: &OrchestratorAssignment) -> OrchestratorReviewReport {
    if assignment.role != AgentRole::Worker {
        return injected_child_report(assignment);
    }
    let mut worker = injected_child_report(&injected_assignment(true))
        .worker_reports
        .remove(0);
    worker.id = assignment.id.clone();
    worker.assigned_paths = assignment.assigned_paths.clone();
    worker.semantic_symbols = assignment.semantic_symbols.clone();
    worker.semantic_modules = assignment.semantic_modules.clone();
    direct_worker_report_envelope(worker)
}

fn run_evidence_rejected_source_with_assignment(
    temp: &tempfile::TempDir,
    repo: &Path,
    run_id: &str,
    rejection_kind: AuditorRejectionKind,
    assignment: OrchestratorAssignment,
) -> (SupervisorFinalReport, OrchestratorAssignment, PathBuf) {
    let mut plan = injected_plan(assignment.clone(), 0);
    plan.max_gate_corrections = 1;
    let budget = injected_run_budget(None, None, None, None, 100, 100);
    let options = injected_options(repo, temp.path(), run_id);
    let mut preserved_worktree = None;
    let mut runner = |command: &ExternalAgentCommand, _pre_action_review: bool| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            let mut child = reaudit_source_child_report(&assignment);
            child.files_changed = vec![PathBuf::from("README.md")];
            child.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
            let mut auditor = injected_auditor_report(&assignment, &child);
            auditor.accepted = false;
            auditor.rejected = true;
            auditor.status = ReviewStatus::Rejected;
            auditor.rejection_kind = Some(rejection_kind);
            auditor.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: match rejection_kind {
                    AuditorRejectionKind::ImplementationDefect => {
                        "implementation must change before acceptance"
                    }
                    AuditorRejectionKind::EvidenceQuality => {
                        "implementation is sound but validation evidence is insufficient"
                    }
                }
                .to_string(),
                paths: vec![PathBuf::from("README.md")],
            });
            write_injected_json(&command.output_last_message, &auditor);
            write_injected_usage(command, 11, 9);
        } else {
            preserved_worktree = Some(command.cwd.clone());
            fs::write(command.cwd.join("README.md"), "preserved implementation\n")
                .expect("write preserved implementation diff");
            let mut child = reaudit_source_child_report(&assignment);
            child.files_changed = vec![PathBuf::from("README.md")];
            child.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
            if assignment.role == AgentRole::Worker {
                let worker = &child.worker_reports[0];
                let journal = command
                    .worker_journal_artifacts
                    .iter()
                    .find(|artifact| artifact.worker_id == assignment.id)
                    .expect("direct journal capture");
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(&journal.path)
                    .expect("precreated journal");
                for entry in injected_worker_journal_entries(worker) {
                    append_worker_execution_journal_record(&mut file, &entry)
                        .expect("append worker journal");
                }
                write_injected_json(&command.output_last_message, worker);
            } else {
                write_injected_json(&command.output_last_message, &child);
            }
            write_injected_usage(command, 13, 7);
        }
        injected_verified_run(command)
    };
    let loaded = LoadedSupervisorPlan {
        plan,
        consultant: SupervisorConsultantPlan::default(),
        assignment_metadata: AssignmentMetadata::new(),
        plan_metadata: SupervisorPlanMetadata {
            assignment_schedule: vec![AssignmentScheduleEntry {
                assignment_id: assignment.id.clone(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index: 0,
            }],
            run_budget: budget,
            ..SupervisorPlanMetadata::default()
        },
    };
    let report = run_loaded_supervisor_plan_with_runner(loaded, options, &mut runner)
        .expect("run typed parent-auditor rejection source");
    (
        report,
        assignment,
        preserved_worktree.expect("source child worktree"),
    )
}

#[test]
fn evidence_rejection_reaudits_preserved_diff_without_worker_rerun_and_can_accept() {
    skip_without_containment!();
    assert_evidence_reaudit_preserves_candidate(false);
}

#[test]
fn generated_direct_worker_evidence_rejection_reaudits_unchanged_candidate_and_accepts() {
    skip_without_containment!();
    assert_evidence_reaudit_preserves_candidate(true);
}

fn assert_evidence_reaudit_preserves_candidate(generated_direct: bool) {
    let (temp, repo) = injected_repository();
    let assignment = if generated_direct {
        let plan =
            supervisor_plan_from_goal_spec(&repo, "", "Update README.md.").expect("generated plan");
        let worker = plan.assignments.last().unwrap().clone();
        assert_eq!(worker.role, AgentRole::Worker);
        assert!(worker.worker_assignments.is_empty());
        worker
    } else {
        injected_assignment(true)
    };
    let source_id = RunId::new("reaudit-source-evidence").expect("valid source run id");
    let (source, assignment, preserved_worktree) = run_evidence_rejected_source_with_assignment(
        &temp,
        &repo,
        source_id.as_str(),
        AuditorRejectionKind::EvidenceQuality,
        assignment,
    );
    assert!(!source.success);
    assert_eq!(
        source
            .run_budget
            .as_ref()
            .map(|budget| budget.consumed.tokens),
        Some(40)
    );
    let source_child = source
        .orchestrator_reports
        .first()
        .expect("source child report")
        .clone();
    assert!(matches!(
        source_child.gate_denials.as_slice(),
        [GateDenial {
            reason: GateDenialReason::AuditorRepair {
                rejection: AuditorRejectionKind::EvidenceQuality,
            },
            ..
        }]
    ));
    assert_eq!(
        source_child.gate_denials[0].next_safe_operation,
        crate::gate_denial::NextSafeOperation::EvidenceOnlyReaudit
    );
    assert_eq!(
        source_child.gate_correction_outcomes[0].terminal_class,
        GateCorrectionTerminalClass::Escalated
    );
    assert_eq!(
        source_child.gate_correction_outcomes[0].correction_attempts,
        0
    );
    let source_binding = source
        .assignment_traceability
        .first()
        .and_then(|trace| trace.produced_diff_binding.clone())
        .expect("source diff binding");

    let loaded = evidence_only_reaudit_plan_from_source(&repo, &source_id, &assignment.id)
        .expect("load authenticated evidence-only re-audit plan");
    let operation = loaded
        .plan_metadata
        .evidence_only_reaudit
        .clone()
        .expect("evidence-only operation");
    assert_eq!(operation.preserved_candidate_binding, source_binding);
    assert_eq!(loaded.plan.assignments[0].role, assignment.role);
    let options = injected_options(&repo, temp.path(), "reaudit-accepts-preserved");
    let mut evidence_dispatches = 0usize;
    let mut auditor_dispatches = 0usize;
    let mut evidence_pre_action_review = false;
    let mut live_claim_observed = false;
    let mut evidence_prompt = String::new();
    let mut runner = |command: &ExternalAgentCommand, pre_action_review: bool| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            auditor_dispatches = auditor_dispatches.saturating_add(1);
            let mut evidence = source_child.clone();
            evidence.audit_reports.clear();
            evidence.review_lens_aggregate = None;
            evidence.gate_denials.clear();
            evidence.gate_correction_outcomes.clear();
            evidence.accepted = true;
            evidence.rejected = false;
            evidence.status = ReviewStatus::Succeeded;
            let auditor = injected_auditor_report(&assignment, &evidence);
            write_injected_json(&command.output_last_message, &auditor);
            write_injected_usage(command, 5, 4);
        } else {
            evidence_dispatches = evidence_dispatches.saturating_add(1);
            evidence_pre_action_review = pre_action_review;
            live_claim_observed = SyncStore::open(&repo)
                .expect("open claim store during re-audit")
                .snapshot()
                .expect("snapshot live re-audit claim")
                .iter()
                .any(|claim| claim.agent_id == assignment.id);
            assert_eq!(command.cwd, preserved_worktree);
            evidence_prompt =
                fs::read_to_string(&command.prompt).expect("read evidence-only child prompt");
            let mut evidence = source_child.clone();
            evidence.audit_reports.clear();
            evidence.review_lens_aggregate = None;
            evidence.gate_denials.clear();
            evidence.gate_correction_outcomes.clear();
            evidence.findings.clear();
            evidence.role = AgentRole::ChildOrchestrator;
            evidence.validation_results.push(ValidationResult {
                name: "refreshed unchanged-candidate validation".to_string(),
                status: ReviewStatus::Succeeded,
                command: vec!["validation".to_string()],
                message: None,
            });
            assert!(command.output_schema.as_ref().is_some_and(|path| path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("orchestrator-review-report")));
            evidence.accepted = true;
            evidence.rejected = false;
            evidence.status = ReviewStatus::Succeeded;
            evidence.remaining_risk = "none after refreshed validation evidence".to_string();
            evidence.next_safe_action = "run the read-only parent audit".to_string();
            write_injected_json(&command.output_last_message, &evidence);
            write_injected_usage(command, 4, 3);
        }
        injected_verified_run(command)
    };
    let report = run_loaded_supervisor_plan_with_runner(loaded, options, &mut runner)
        .expect("run evidence-only re-audit");

    assert!(report.success, "unexpected re-audit failure: {report:#?}");
    assert_eq!(report.orchestrator_reports[0].role, assignment.role);
    assert!(report.orchestrator_reports[0]
        .validation_results
        .iter()
        .any(|result| result.name == "refreshed unchanged-candidate validation"));
    assert_eq!(evidence_dispatches, 1);
    assert_eq!(auditor_dispatches, 1);
    assert!(
        evidence_pre_action_review,
        "evidence report dispatch must re-enter the pre-action review boundary"
    );
    assert!(
        live_claim_observed,
        "the assignment claim must remain live throughout the re-audit dispatch"
    );
    assert!(evidence_prompt.contains("Evidence-only operation"));
    assert!(evidence_prompt.contains(source_binding.diff_oid.as_str()));
    assert!(evidence_prompt.contains("launch workers"));
    assert_eq!(
        report
            .run_budget
            .as_ref()
            .map(|budget| budget.consumed.tokens),
        Some(16),
        "the new ledger must charge only the evidence and auditor dispatches"
    );
    let role_budgets = &report
        .run_budget
        .as_ref()
        .expect("evidence-only role budget report")
        .roles;
    assert_eq!(role_budgets.len(), 2);
    assert_eq!(
        role_budgets
            .iter()
            .find(|budget| budget.role == assignment.role)
            .map(|budget| budget.consumed.tokens),
        Some(7),
        "only the refreshed evidence report belongs to the child-orchestrator role"
    );
    assert_eq!(
        role_budgets
            .iter()
            .find(|budget| budget.role == AgentRole::Auditor)
            .map(|budget| budget.consumed.tokens),
        Some(9),
        "the new read-only audit has its own exact auditor charge"
    );
    assert_eq!(
        report
            .evidence_only_reaudit
            .as_ref()
            .map(|record| (record.attempt, record.accepted)),
        Some((1, true))
    );
    assert_eq!(report.released_claims.len(), 1);
    assert_eq!(
        report
            .assignment_traceability
            .first()
            .and_then(|trace| trace.produced_diff_binding.as_ref()),
        Some(&source_binding)
    );
    assert_eq!(
        report.orchestrator_reports[0].worker_reports, source_child.worker_reports,
        "terminal-worker evidence must be preserved rather than regenerated"
    );
    let destination_id =
        RunId::new("reaudit-accepts-preserved").expect("valid evidence-only destination run id");
    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &destination_id)
        .expect("open authenticated re-audit artifacts");
    let plan_snapshot: Value = serde_json::from_slice(
        &reader
            .read("assignments/supervisor-plan.json")
            .expect("read authenticated re-audit plan"),
    )
    .expect("parse authenticated re-audit plan");
    assert_eq!(
        plan_snapshot["evidence_only_reaudit"]["source_run_id"],
        source_id.as_str()
    );
    assert_eq!(plan_snapshot["evidence_only_reaudit"]["attempt"], 1);
}

#[test]
fn evidence_only_reaudit_refuses_typed_implementation_defect_without_new_run() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_id = RunId::new("reaudit-source-defect").expect("valid source run id");
    let (source, assignment, _worktree) = run_evidence_rejected_source(
        &temp,
        &repo,
        source_id.as_str(),
        AuditorRejectionKind::ImplementationDefect,
    );
    assert!(!source.success);
    assert_eq!(
        source.orchestrator_reports[0].gate_correction_outcomes[0].terminal_class,
        GateCorrectionTerminalClass::Exhausted
    );
    assert_eq!(
        source.orchestrator_reports[0].gate_correction_outcomes[0].correction_attempts, 1,
        "the ordinary full assignment repair path remains available for defects"
    );
    let destination_id = RunId::new("reaudit-defect-refused").expect("valid destination run id");
    let response = reaudit_supervisor_assignment(SupervisorEvidenceOnlyReauditOptions {
        repo: repo.clone(),
        source_run_id: source_id,
        assignment_id: assignment.id,
        run_id: destination_id.clone(),
        codex_bin: PathBuf::from("unused-injected-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: true,
        machine_global_retention: None,
    })
    .expect("return typed defect refusal");

    assert!(!response.success);
    assert!(response.final_report.is_none());
    assert!(matches!(
        response.gate_denial,
        Some(GateDenial {
            reason: GateDenialReason::AuditorRepair {
                rejection: AuditorRejectionKind::ImplementationDefect,
            },
            ..
        })
    ));
    assert!(!repo
        .join(RunArtifactFamily::Supervise.run_root())
        .join(destination_id.as_str())
        .exists());
}

#[test]
fn evidence_only_reaudit_refuses_modified_preserved_tree_before_dispatch() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_id = RunId::new("reaudit-source-binding").expect("valid source run id");
    let (_source, assignment, preserved_worktree) = run_evidence_rejected_source(
        &temp,
        &repo,
        source_id.as_str(),
        AuditorRejectionKind::EvidenceQuality,
    );
    let loaded = evidence_only_reaudit_plan_from_source(&repo, &source_id, &assignment.id)
        .expect("load authenticated evidence-only plan before tamper");
    fs::write(
        preserved_worktree.join("README.md"),
        "different implementation after source finalization\n",
    )
    .expect("modify preserved worktree after authenticated binding");
    let options = injected_options(&repo, temp.path(), "reaudit-binding-refused");
    let mut dispatches = 0usize;
    let mut runner = |command: &ExternalAgentCommand, _pre_action_review: bool| {
        dispatches = dispatches.saturating_add(1);
        write_injected_assignment_report(command, &assignment);
        injected_verified_run(command)
    };
    let report = run_loaded_supervisor_plan_with_runner(loaded, options, &mut runner)
        .expect("complete typed content-binding refusal");

    assert!(!report.success);
    assert_eq!(dispatches, 0, "binding refusal must precede every dispatch");
    assert!(matches!(
        report.gate_denials.as_slice(),
        [GateDenial {
            reason: GateDenialReason::MergeRemediation {
                blocker: GateApplyBlocker::StaleBase,
            },
            context: VerifiedGateContext {
                source: GateCheckSource::ValidationBinding,
                ..
            },
            ..
        }]
    ));
    assert_eq!(
        report
            .evidence_only_reaudit
            .as_ref()
            .map(|record| record.accepted),
        Some(false)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn evidence_only_dispatch_physically_denies_mutate_validate_restore() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_id = RunId::new("reaudit-source-transient-mutation").expect("valid source run id");
    let (source, assignment, preserved_worktree) = run_evidence_rejected_source(
        &temp,
        &repo,
        source_id.as_str(),
        AuditorRejectionKind::EvidenceQuality,
    );
    let source_report = source
        .orchestrator_reports
        .first()
        .expect("authenticated source assignment report")
        .clone();
    let loaded = evidence_only_reaudit_plan_from_source(&repo, &source_id, &assignment.id)
        .expect("reload authenticated evidence-only plan");
    let options = injected_options(&repo, temp.path(), "reaudit-transient-mutation-denied");
    let mut mutation_probe_ran = false;
    let mut runner = |command: &ExternalAgentCommand, pre_action_review: bool| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            let mut evidence = source_report.clone();
            evidence.audit_reports.clear();
            evidence.review_lens_aggregate = None;
            evidence.gate_denials.clear();
            evidence.gate_correction_outcomes.clear();
            evidence.accepted = true;
            evidence.rejected = false;
            evidence.status = ReviewStatus::Succeeded;
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &evidence),
            );
            write_injected_usage(command, 1, 1);
        } else {
            mutation_probe_ran = true;
            assert!(pre_action_review, "evidence dispatch must remain reviewed");
            assert_eq!(command.cwd, preserved_worktree);
            let profile = match command.workspace_access {
                WorkspaceAccess::ReadOnly => ExternalCodexProfile::read_only(&command.cwd),
                WorkspaceAccess::ReadWrite => ExternalCodexProfile::read_write(&command.cwd),
            };
            let source_path = command.cwd.join("README.md");
            let probe = run_process(
                ProcessSpec::shell(
                    "evidence-only mutate-validate-restore probe",
                    Shell::UnixSh,
                    r#"if printf 'transient validation bytes\n' > README.md; then
  if [ "$(cat README.md)" = "transient validation bytes" ]; then
    printf 'preserved implementation\n' > README.md
    printf 'transient-validation-observed\n'
    exit 23
  fi
  exit 24
else
  printf 'mutation-denied-before-validation\n'
fi"#,
                    &command.cwd,
                    8 * 1024,
                )
                .with_stdin(StdinMode::Null)
                .with_timeout(Some(Duration::from_secs(45)))
                .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(profile)),
            )
            .expect("launch strict evidence-only mutation probe");
            let stdout = probe.stdout.summarize_chars(8 * 1024).text;
            assert!(
                probe.safety_sensitive_succeeded(),
                "read-only mutation denial must retain verified containment: {probe:#?}"
            );
            assert!(stdout.contains("mutation-denied-before-validation"));
            assert!(!stdout.contains("transient-validation-observed"));
            assert_eq!(
                fs::read_to_string(&source_path).expect("read preserved source after probe"),
                "preserved implementation\n",
                "restoring after transient validation must not conceal a writable evidence view"
            );

            let mut evidence = source_report.clone();
            evidence.audit_reports.clear();
            evidence.review_lens_aggregate = None;
            evidence.gate_denials.clear();
            evidence.gate_correction_outcomes.clear();
            evidence.findings.clear();
            evidence.accepted = true;
            evidence.rejected = false;
            evidence.status = ReviewStatus::Succeeded;
            write_injected_json(&command.output_last_message, &evidence);
            write_injected_usage(command, 1, 1);
        }
        injected_verified_run(command)
    };
    let report = run_loaded_supervisor_plan_with_runner(loaded, options, &mut runner)
        .expect("run read-only evidence dispatch");

    assert!(mutation_probe_ran);
    assert!(report.success, "unexpected re-audit refusal: {report:#?}");
}

#[test]
fn ordinary_report_refuses_candidate_mismatch_across_parent_audit() {
    skip_without_containment!();
    let (temp, repo) = injected_repository();
    let source_id = RunId::new("reaudit-source-ordinary-mismatch").expect("valid source run id");
    let (source, assignment, preserved_worktree) = run_evidence_rejected_source(
        &temp,
        &repo,
        source_id.as_str(),
        AuditorRejectionKind::EvidenceQuality,
    );
    let loaded = evidence_only_reaudit_plan_from_source(&repo, &source_id, &assignment.id)
        .expect("load authenticated evidence-only plan");
    let source_report = source
        .orchestrator_reports
        .first()
        .expect("authenticated source assignment report")
        .clone();
    assert!(source_report.decomposition_completions.is_empty());
    let options = injected_options(&repo, temp.path(), "reaudit-ordinary-across-audit-mismatch");
    let mut auditor_changed_candidate = false;
    let mut runner = |command: &ExternalAgentCommand, _pre_action_review: bool| {
        let name = command
            .output_last_message
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if name.contains("review-auditor") {
            fs::write(
                preserved_worktree.join("README.md"),
                "candidate changed during parent audit\n",
            )
            .expect("change candidate across injected parent audit");
            auditor_changed_candidate = true;
            let mut evidence = source_report.clone();
            evidence.audit_reports.clear();
            evidence.review_lens_aggregate = None;
            evidence.gate_denials.clear();
            evidence.gate_correction_outcomes.clear();
            evidence.accepted = true;
            evidence.rejected = false;
            evidence.status = ReviewStatus::Succeeded;
            write_injected_json(
                &command.output_last_message,
                &injected_auditor_report(&assignment, &evidence),
            );
            write_injected_usage(command, 1, 1);
        } else {
            let mut evidence = source_report.clone();
            evidence.audit_reports.clear();
            evidence.review_lens_aggregate = None;
            evidence.gate_denials.clear();
            evidence.gate_correction_outcomes.clear();
            evidence.findings.clear();
            evidence.accepted = true;
            evidence.rejected = false;
            evidence.status = ReviewStatus::Succeeded;
            write_injected_json(&command.output_last_message, &evidence);
            write_injected_usage(command, 1, 1);
        }
        injected_verified_run(command)
    };
    let report = run_loaded_supervisor_plan_with_runner(loaded, options, &mut runner)
        .expect("complete ordinary across-audit mismatch refusal");

    assert!(auditor_changed_candidate);
    assert!(!report.success);
    let child = report
        .orchestrator_reports
        .first()
        .expect("ordinary mismatch report");
    assert!(child.decomposition_completions.is_empty());
    assert!(report_failed(child));
    assert!(child.findings.iter().any(|finding| finding
        .message
        .contains("candidate content, paths, or base changed across parent auditor review")));
    assert!(report
        .assignment_traceability
        .iter()
        .all(|trace| trace.produced_diff_binding.is_none()));
}

#[test]
fn generated_direct_worker_reaudit_collects_refreshed_envelope_and_preserves_worker_evidence() {
    for plan in
        crate::supervise::plan_api::generated_terminal_worker_tests::generated_plans_for_gate_tests(
        )
    {
        let assignment = plan.assignments.last().unwrap();
        let temp = tempfile::tempdir().expect("tempdir");
        let command = ExternalAgentCommand::codex(
            "codex",
            temp.path(),
            temp.path().join("prompt"),
            temp.path().join("log"),
            temp.path().join("report.json"),
            Duration::from_secs(1),
        );
        let mut source = reaudit_source_child_report(assignment);
        source.files_changed = assignment.assigned_paths.clone();
        source.worker_reports[0].files_changed = source.files_changed.clone();
        let mut rejection = injected_auditor_report(assignment, &source);
        rejection.commands_run.push(injected_command_record());
        rejection.accepted = false;
        rejection.rejected = true;
        rejection.status = ReviewStatus::Rejected;
        rejection.rejection_kind = Some(AuditorRejectionKind::EvidenceQuality);
        source.audit_reports.push(rejection);
        validate_auditor_reports(assignment, Path::new("source.json"), &mut source);
        assert!(report_failed(&source));
        let mut refreshed = source.clone();
        refreshed.role = AgentRole::ChildOrchestrator;
        refreshed.audit_reports.clear();
        refreshed.findings.clear();
        refreshed.accepted = true;
        refreshed.rejected = false;
        refreshed.status = ReviewStatus::Succeeded;
        refreshed.validation_results.push(ValidationResult {
            name: "refreshed validation".to_string(),
            status: ReviewStatus::Succeeded,
            command: vec!["validate".to_string()],
            message: None,
        });
        for tampered in [false, true] {
            let mut response = refreshed.clone();
            if tampered {
                response.worker_reports[0].validation_results =
                    refreshed.validation_results.clone();
            }
            write_injected_json(&command.output_last_message, &response);
            let run = injected_verified_run_without_journals(&command);
            let (mut collected, shape_problems) =
                collect_child_report(ChildReportCollectionContext {
                    assignment,
                    assignment_metadata: &AssignmentMetadata::new(),
                    report_path: &command.output_last_message,
                    external_run: &run,
                    external_command: &command,
                    worktree_path: temp.path(),
                    child_base_head: &injected_oid("preserved-base"),
                    observed_changed_paths: None,
                    worker_journals: &WorkerExecutionJournalEvidenceSet::new(),
                    evidence_only_source: Some(&source),
                });
            assert!(shape_problems.is_empty(), "{shape_problems:?}");
            assert_eq!(collected.role, AgentRole::Worker);
            if tampered {
                assert!(report_failed(&collected));
                assert!(finding_messages(&collected)
                    .contains("changed preserved implementation evidence"));
            } else {
                assert!(!report_failed(&collected), "{collected:#?}");
                assert_eq!(collected.worker_reports, source.worker_reports);
                assert_eq!(collected.files_changed, source.files_changed);
                assert_eq!(collected.validation_results, refreshed.validation_results);
                let mut audit = injected_auditor_report(assignment, &collected);
                audit.commands_run.push(injected_command_record());
                collected.audit_reports.push(audit);
                validate_auditor_reports(assignment, &command.output_last_message, &mut collected);
                assert!(!report_failed(&collected), "{collected:#?}");
            }
        }
    }
}
