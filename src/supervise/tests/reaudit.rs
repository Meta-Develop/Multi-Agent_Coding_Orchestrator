use super::*;

fn run_evidence_rejected_source(
    temp: &tempfile::TempDir,
    repo: &Path,
    run_id: &str,
    rejection_kind: AuditorRejectionKind,
) -> (SupervisorFinalReport, OrchestratorAssignment, PathBuf) {
    let assignment = injected_assignment(true);
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
            let mut child = injected_child_report(&assignment);
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
            let mut child = injected_child_report(&assignment);
            child.files_changed = vec![PathBuf::from("README.md")];
            child.worker_reports[0].files_changed = vec![PathBuf::from("README.md")];
            write_injected_json(&command.output_last_message, &child);
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
    let (temp, repo) = injected_repository();
    let source_id = RunId::new("reaudit-source-evidence").expect("valid source run id");
    let (source, assignment, preserved_worktree) = run_evidence_rejected_source(
        &temp,
        &repo,
        source_id.as_str(),
        AuditorRejectionKind::EvidenceQuality,
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
