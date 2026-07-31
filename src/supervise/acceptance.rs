use super::*;

pub(super) fn collect_child_report(
    context: ChildReportCollectionContext<'_>,
) -> (OrchestratorReviewReport, Vec<String>) {
    let ChildReportCollectionContext {
        assignment,
        assignment_metadata,
        report_path,
        external_run,
        external_command,
        worktree_path,
        child_base_head,
        worker_journals,
    } = context;
    if external_run.environment_blocked() {
        return (
            environment_blocked_child_report(
                assignment,
                assignment_metadata,
                report_path,
                external_run,
                external_command,
            ),
            Vec::new(),
        );
    }
    let mut report_shape_problems = Vec::new();
    let mut report = match read_child_report(external_run.output_last_message(), report_path) {
        Ok(parsed) => {
            let mut report = parsed.report;
            if parsed.recovered {
                report.findings.push(Finding {
                    severity: FindingSeverity::Warning,
                    message: LENIENT_JSON_EXTRACTION_WARNING.to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if report.id != assignment.id {
                let message = format!(
                    "report id '{}' does not match assignment '{}'",
                    report.id, assignment.id
                );
                report_shape_problems.push(message.clone());
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message,
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if report.role != AgentRole::ChildOrchestrator {
                let message = "orchestrator report role must be child_orchestrator".to_string();
                report_shape_problems.push(message.clone());
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message,
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if !external_process_completed(external_run) && report.status == ReviewStatus::Succeeded
            {
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: "external child process failed despite report success".to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            report
        }
        Err(error) => {
            let message = format!("required child report is missing or invalid: {error}");
            report_shape_problems.push(message);
            missing_child_report(
                assignment,
                report_path,
                external_run,
                external_command,
                error.to_string(),
            )
        }
    };
    if !report.gate_denials.is_empty() || !report.gate_correction_outcomes.is_empty() {
        report.gate_denials.clear();
        report.gate_correction_outcomes.clear();
        report.status = ReviewStatus::Failed;
        report.accepted = false;
        report.rejected = true;
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message:
                "child report attempted to self-assert supervisor-owned gate correction evidence"
                    .to_string(),
            paths: vec![report_path.to_path_buf()],
        });
    }
    validate_worker_report_delegation_attestations(assignment, report_path, &mut report);
    verify_child_report_paths(assignment, worktree_path, child_base_head, &mut report);
    validate_worker_report_evidence(assignment, assignment_metadata, report_path, &mut report);
    validate_assignment_report_plumbing(assignment, assignment_metadata, report_path, &mut report);
    validate_worker_execution_journal_evidence(
        assignment,
        report_path,
        worker_journals,
        &mut report,
    );
    enforce_orchestrator_environment_failure_outcome(&mut report);
    (report, report_shape_problems)
}

pub(super) fn collect_parent_auditor_report(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    external_run: &ExternalAgentRun,
    external_command: &ExternalAgentCommand,
) -> AuditorReport {
    let expected_id = parent_auditor_id(assignment);
    if external_run.environment_blocked() {
        let mut report = missing_parent_auditor_report(
            &expected_id,
            report_path,
            external_run,
            anyhow!("parent-observed environment preflight blocked the auditor before launch"),
        );
        report
            .commands_run
            .push(command_record_from_external(external_run, external_command));
        return report;
    }
    let mut report = match read_auditor_report(external_run.output_last_message(), report_path) {
        Ok(parsed) => {
            let mut report = parsed.report;
            if parsed.recovered {
                report.findings.push(Finding {
                    severity: FindingSeverity::Warning,
                    message: LENIENT_JSON_EXTRACTION_WARNING.to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if report.id != expected_id {
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "parent auditor report id '{}' does not match expected '{}'",
                        report.id, expected_id
                    ),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            if !external_process_completed(external_run) && report.status == ReviewStatus::Succeeded
            {
                report.status = ReviewStatus::Failed;
                report.accepted = false;
                report.rejected = true;
                report.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: "external parent review auditor process failed despite report success"
                        .to_string(),
                    paths: vec![report_path.to_path_buf()],
                });
            }
            report
        }
        Err(error) => missing_parent_auditor_report(&expected_id, report_path, external_run, error),
    };
    report
        .commands_run
        .push(command_record_from_external(external_run, external_command));
    enforce_auditor_environment_failure_outcome(&mut report);
    report
}

pub(super) fn validate_auditor_reports(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    let required_review_subject_ids = required_auditor_review_subject_ids(assignment, report);
    if required_review_subject_ids.is_empty() {
        return;
    }

    let required_parent_auditor_id = parent_auditor_id(assignment);
    let required_reviewed_paths = required_auditor_review_paths(assignment, report);
    let mut covered_review_subject_ids = BTreeSet::<String>::new();
    let mut parent_auditor_accepted = false;
    let mut invalid_auditors = Vec::new();

    for audit_report in &mut report.audit_reports {
        let mut valid = true;
        let mut messages = Vec::new();
        if audit_report.role != AgentRole::Auditor {
            valid = false;
            messages.push("auditor report role must be auditor".to_string());
        }
        if audit_report.no_further_delegation != Some(true) {
            valid = false;
            messages.push(match audit_report.no_further_delegation {
                Some(false) => "auditor report indicates further delegation".to_string(),
                None => "auditor report omitted no_further_delegation terminal-auditor attestation"
                    .to_string(),
                Some(true) => String::new(),
            });
        }
        if !audit_report.read_only {
            valid = false;
            messages.push("auditor report omitted read_only review-only attestation".to_string());
        }
        if audit_report.reviewed_worker_ids.is_empty() {
            valid = false;
            messages.push("auditor report omitted reviewed_worker_ids evidence".to_string());
        }
        if audit_report.reviewed_paths.is_empty() {
            valid = false;
            messages.push("auditor report omitted reviewed_paths evidence".to_string());
        }
        if audit_report.commands_run.is_empty() {
            valid = false;
            messages.push("auditor report omitted commands_run evidence".to_string());
        }
        if audit_report.validation_results.is_empty() {
            valid = false;
            messages.push("auditor report omitted validation_results evidence".to_string());
        }
        if audit_report.remaining_risk.trim().is_empty() {
            valid = false;
            messages.push("auditor report omitted remaining_risk evidence".to_string());
        }
        if audit_report.next_safe_action.trim().is_empty() {
            valid = false;
            messages.push("auditor report omitted next_safe_action evidence".to_string());
        }
        if !audit_report.accepted
            || audit_report.rejected
            || audit_report.status != ReviewStatus::Succeeded
        {
            valid = false;
            messages.push("auditor report was not accepted as succeeded".to_string());
        }
        if audit_report.id == required_parent_auditor_id {
            let coverage = auditor_review_path_coverage(audit_report, &required_reviewed_paths);
            if !coverage.excluded_paths.is_empty() {
                audit_report.findings.push(Finding {
                    severity: FindingSeverity::Warning,
                    message: format!(
                        "auditor reviewed_paths entries were retained as evidence but excluded from repository-relative coverage computation: {}",
                        display_paths(&coverage.excluded_paths)
                    ),
                    paths: coverage.excluded_paths,
                });
            }
            if !coverage.missing_paths.is_empty() {
                valid = false;
                messages.push(format!(
                    "parent auditor reviewed_paths omitted required assignment/change path coverage for: {}",
                    display_paths(&coverage.missing_paths)
                ));
            }
        }

        if valid {
            if audit_report.id == required_parent_auditor_id {
                parent_auditor_accepted = true;
            }
            covered_review_subject_ids.extend(
                audit_report
                    .reviewed_worker_ids
                    .iter()
                    .filter(|id| required_review_subject_ids.contains(id.as_str()))
                    .cloned(),
            );
            continue;
        }

        audit_report.status = ReviewStatus::Failed;
        audit_report.accepted = false;
        audit_report.rejected = true;
        for message in messages.into_iter().filter(|message| !message.is_empty()) {
            audit_report.findings.push(Finding {
                severity: FindingSeverity::Error,
                message,
                paths: vec![report_path.to_path_buf()],
            });
        }
        invalid_auditors.push(audit_report.id.clone());
    }

    let missing_review_subject_ids = required_review_subject_ids
        .difference(&covered_review_subject_ids)
        .map(|id| (*id).to_string())
        .collect::<Vec<_>>();

    if invalid_auditors.is_empty()
        && missing_review_subject_ids.is_empty()
        && parent_auditor_accepted
    {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;

    if !assignment.worker_assignments.is_empty() && report.worker_reports.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' contained zero worker_reports despite assigned worker IDs: {}",
                report.id,
                display_strings(
                    &assignment
                        .worker_assignments
                        .iter()
                        .map(|worker| worker.id.clone())
                        .collect::<Vec<_>>()
                )
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    if report.audit_reports.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' omitted required review auditor report for worker assignments",
                report.id
            ),
            paths: vec![report_path.to_path_buf()],
        });
    } else if !missing_review_subject_ids.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' omitted accepted review auditor coverage for review subject IDs: {}",
                report.id,
                missing_review_subject_ids.join(", ")
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    if !parent_auditor_accepted {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' lacks accepted parent-launched review auditor report '{}'",
                report.id, required_parent_auditor_id
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    if !invalid_auditors.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' included invalid review auditor reports: {}",
                report.id,
                invalid_auditors.join(", ")
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    report.remaining_risk =
        "required terminal review-auditor evidence is missing or invalid".to_string();
    report.next_safe_action =
        "rerun the child scope with a read-only review auditor before finalizing".to_string();
}

pub(super) fn parent_auditor_required(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> bool {
    (!assignment.worker_assignments.is_empty() && !report.worker_reports.is_empty())
        || (assignment.worker_assignments.is_empty() && !report.files_changed.is_empty())
        || report_has_field_guide_suggestions(report)
}

pub(super) fn report_has_field_guide_suggestions(report: &OrchestratorReviewReport) -> bool {
    !report.field_guide_entries.is_empty()
        || report
            .worker_reports
            .iter()
            .any(|worker| !worker.field_guide_entries.is_empty())
}

pub(super) fn inspect_supervisor_candidate(
    repo: &Path,
    assignment: &OrchestratorAssignment,
    worktree_write_lease: &ManagedWorktreeWriteLease,
) -> Result<SupervisorCandidateInspection> {
    let candidate = collect_agent_result_with_evidence_and_write_lease(
        MergeCollectOptions {
            repo: repo.to_path_buf(),
            agent_id: assignment.id.clone(),
            claimed_paths: assignment.assigned_paths.clone(),
            include_full_diff: false,
            diff_summary_char_limit: 1,
            validations: Vec::new(),
        },
        ValidationEvidenceBundle::default(),
        worktree_write_lease,
    )
    .context("failed to capture supervisor-inspected decomposition candidate")?;
    Ok(SupervisorCandidateInspection {
        binding: candidate.validation_binding,
        changed_paths: normalize_paths(candidate.changed_paths)
            .context("supervisor-inspected decomposition candidate paths are invalid")?,
    })
}

pub(super) fn bind_supervisor_decomposition_candidate(
    repo: &Path,
    assignment: &OrchestratorAssignment,
    report: &mut OrchestratorReviewReport,
    worktree_write_lease: &ManagedWorktreeWriteLease,
) -> Result<Option<SupervisorCandidateInspection>> {
    if report_failed(report) || report.decomposition_completions.is_empty() {
        return Ok(None);
    }
    if report
        .decomposition_completions
        .iter()
        .any(|completion| completion.supervisor_candidate_binding.is_some())
        || report.worker_reports.iter().any(|worker| {
            worker
                .decomposition_completion
                .as_ref()
                .is_some_and(|completion| completion.supervisor_candidate_binding.is_some())
        })
    {
        bail!(
            "incoming worker or child decomposition evidence self-asserted supervisor_candidate_binding"
        );
    }

    let inspection = inspect_supervisor_candidate(repo, assignment, worktree_write_lease)?;
    let report_paths =
        normalize_paths(report.files_changed.clone()).context("child files_changed invalid")?;
    if inspection.changed_paths != report_paths {
        bail!(
            "supervisor-inspected decomposition candidate paths changed after child report validation"
        );
    }

    for worker in &mut report.worker_reports {
        if report_failed(worker) {
            continue;
        }
        if let Some(completion) = &mut worker.decomposition_completion {
            completion.supervisor_candidate_binding = Some(inspection.binding.clone());
        }
    }
    for completion in &mut report.decomposition_completions {
        completion.supervisor_candidate_binding = Some(inspection.binding.clone());
    }
    Ok(Some(inspection))
}

pub(super) fn reject_supervisor_decomposition_binding(
    report: &mut OrchestratorReviewReport,
    report_path: &Path,
    error: &anyhow::Error,
) {
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "supervisor could not bind the exact decomposition candidate reviewed by the parent auditor: {error:#}"
        ),
        paths: vec![report_path.to_path_buf()],
    });
    report.remaining_risk =
        "the finalized evidence does not bind the exact reviewed candidate content".to_string();
    report.next_safe_action =
        "rerun the child scope and parent auditor against one stable candidate snapshot"
            .to_string();
}

fn required_auditor_review_subject_ids(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> BTreeSet<String> {
    if assignment.worker_assignments.is_empty() {
        if report.files_changed.is_empty() && !report_has_field_guide_suggestions(report) {
            BTreeSet::new()
        } else {
            BTreeSet::from([report.id.clone()])
        }
    } else {
        assignment
            .worker_assignments
            .iter()
            .map(|worker| worker.id.clone())
            .collect()
    }
}

pub(super) fn required_auditor_prompt_subject_ids(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> Vec<String> {
    required_auditor_review_subject_ids(assignment, report)
        .into_iter()
        .collect()
}

pub(super) fn required_auditor_review_paths(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> Vec<PathBuf> {
    collapse_covered_paths(
        assignment
            .assigned_paths
            .iter()
            .chain(report.files_changed.iter())
            .cloned()
            .collect(),
    )
}

fn auditor_review_path_coverage(
    audit_report: &AuditorReport,
    required_paths: &[PathBuf],
) -> AuditorReviewPathCoverage {
    let mut normalized_paths = BTreeSet::new();
    let mut excluded_paths = Vec::new();
    for path in &audit_report.reviewed_paths {
        match normalize_repo_relative_path(path) {
            Ok(path) => {
                normalized_paths.insert(path);
            }
            Err(_) => excluded_paths.push(path.clone()),
        }
    }
    let reviewed_paths = collapse_covered_paths(normalized_paths);
    let missing_paths = required_paths
        .iter()
        .filter(|required| {
            !reviewed_paths
                .iter()
                .any(|reviewed| path_is_covered_by_claim(required, reviewed))
        })
        .cloned()
        .collect();
    AuditorReviewPathCoverage {
        missing_paths,
        excluded_paths,
    }
}

pub(super) fn validate_worker_report_delegation_attestations(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    let mut invalid_workers = Vec::new();
    let actual_worker_ids = report
        .worker_reports
        .iter()
        .map(|worker_report| worker_report.id.as_str())
        .collect::<BTreeSet<_>>();
    let missing_workers = assignment
        .worker_assignments
        .iter()
        .filter(|worker| !actual_worker_ids.contains(worker.id.as_str()))
        .map(|worker| worker.id.clone())
        .collect::<Vec<_>>();

    for worker_report in &mut report.worker_reports {
        if worker_report.no_further_delegation == Some(true) {
            continue;
        }
        let message = match worker_report.no_further_delegation {
            Some(false) => "worker report indicates further delegation".to_string(),
            None => "worker report omitted no_further_delegation terminal-worker attestation"
                .to_string(),
            Some(true) => continue,
        };
        worker_report.status = ReviewStatus::Failed;
        worker_report.accepted = false;
        worker_report.rejected = true;
        worker_report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message,
            paths: vec![report_path.to_path_buf()],
        });
        invalid_workers.push(worker_report.id.clone());
    }

    if invalid_workers.is_empty() && missing_workers.is_empty() {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;

    if !invalid_workers.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' included worker reports without terminal no-delegation attestation: {}",
                report.id,
                invalid_workers.join(", ")
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    if !missing_workers.is_empty() {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' omitted required worker reports for assignment worker IDs: {}",
                report.id,
                missing_workers.join(", ")
            ),
            paths: vec![report_path.to_path_buf()],
        });
    }

    report.remaining_risk = if missing_workers.is_empty() {
        "one or more worker reports indicate delegation beyond the terminal worker contract"
            .to_string()
    } else {
        "one or more required worker reports are missing terminal no-delegation attestations"
            .to_string()
    };
    report.next_safe_action =
        "inspect worker output and rerun the child scope with terminal workers only".to_string();
}

fn verify_child_report_paths(
    assignment: &OrchestratorAssignment,
    worktree_path: &Path,
    child_base_head: &Oid,
    report: &mut OrchestratorReviewReport,
) {
    let reported_paths = normalize_paths(report.files_changed.clone());
    let actual_paths = match collect_paths_changed_since_base(worktree_path, child_base_head) {
        Ok(paths) => paths,
        Err(error) => {
            report.status = ReviewStatus::Failed;
            report.accepted = false;
            report.rejected = true;
            report.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!("failed to inspect actual child worktree changes: {error}"),
                paths: Vec::new(),
            });
            return;
        }
    };

    let mismatch = match &reported_paths {
        Ok(paths) => paths != &actual_paths,
        Err(_) => true,
    };
    if mismatch {
        let mismatch_paths = match reported_paths {
            Ok(paths) => union_paths(&paths, &actual_paths),
            Err(_) => actual_paths.clone(),
        };
        report.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "child-reported files_changed does not match actual child worktree Git changes; using supervisor-inspected paths".to_string(),
            paths: mismatch_paths,
        });
    }

    report.files_changed = actual_paths.clone();

    let unauthorized_paths = actual_paths
        .iter()
        .filter(|path| {
            !assignment
                .assigned_paths
                .iter()
                .any(|assigned| path_is_covered_by_claim(path, assigned))
        })
        .cloned()
        .collect::<Vec<_>>();

    if unauthorized_paths.is_empty() {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "child orchestrator '{}' changed paths outside its assigned paths: {}",
            assignment.id,
            display_paths(&unauthorized_paths)
        ),
        paths: unauthorized_paths,
    });
    report.remaining_risk =
        "child worktree contains Git-visible changes outside the assigned paths".to_string();
    report.next_safe_action =
        "inspect the unauthorized child worktree changes before rerunning or collecting"
            .to_string();
}

pub(super) fn validate_assignment_report_plumbing(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    let result = (|| -> Result<()> {
        validate_field_guide_suggestions("child orchestrator", &report.field_guide_entries)?;
        let mut aggregate_entry_count = report.field_guide_entries.len();
        let mut aggregate_bytes = field_guide_suggestion_bytes(&report.field_guide_entries)?;
        for worker in &report.worker_reports {
            aggregate_entry_count = aggregate_entry_count
                .checked_add(worker.field_guide_entries.len())
                .context("field-guide suggestion count overflowed")?;
            aggregate_bytes = aggregate_bytes
                .checked_add(field_guide_suggestion_bytes(&worker.field_guide_entries)?)
                .context("field-guide suggestion byte count overflowed")?;
        }
        if aggregate_entry_count > MAX_FIELD_GUIDE_ENTRIES_PER_RUN
            || aggregate_bytes > MAX_FIELD_GUIDE_RUN_BYTES
        {
            bail!(
                "field_guide_entries aggregate exceeds the {} item or {} byte child-report bound",
                MAX_FIELD_GUIDE_ENTRIES_PER_RUN,
                MAX_FIELD_GUIDE_RUN_BYTES
            );
        }
        if report.decomposition_completions.len() > assignment.worker_assignments.len() {
            bail!("decomposition_completions exceeds the worker assignment count");
        }
        let mut normalized = BTreeSet::new();
        for completion in std::mem::take(&mut report.decomposition_completions) {
            normalized.insert(normalize_unbound_decomposition_completion(completion)?);
        }
        let expected = report
            .worker_reports
            .iter()
            .filter(|worker_report| !report_failed(*worker_report))
            .filter_map(|worker_report| worker_report.decomposition_completion.clone())
            .collect::<BTreeSet<_>>();
        let successful =
            report.accepted && !report.rejected && report.status == ReviewStatus::Succeeded;
        if !successful && !normalized.is_empty() {
            bail!(
                "decomposition_completions cannot claim success on an unaccepted or unsuccessful child report"
            );
        }
        if successful && normalized != expected {
            bail!("decomposition_completions does not match accepted successful worker evidence");
        }
        for completion in &normalized {
            if !assignment.worker_assignments.iter().any(|worker| {
                let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
                metadata.kind == AssignmentKind::MegafileDecomposition
                    && metadata.target_path.as_ref() == Some(&completion.target_path)
            }) {
                bail!(
                    "decomposition completion target_path '{}' is not declared by a worker assignment",
                    completion.target_path.display()
                );
            }
        }
        report.decomposition_completions = normalized.into_iter().collect();
        Ok(())
    })();

    if let Err(error) = result {
        report.field_guide_entries.clear();
        for worker in &mut report.worker_reports {
            worker.field_guide_entries.clear();
        }
        report.decomposition_completions.clear();
        report.status = ReviewStatus::Failed;
        report.accepted = false;
        report.rejected = true;
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "child orchestrator '{}' has invalid assignment/decomposition report plumbing: {error}",
                report.id
            ),
            paths: vec![report_path.to_path_buf()],
        });
        report.remaining_risk =
            "typed assignment or decomposition completion evidence is invalid".to_string();
        report.next_safe_action =
            "rerun the child scope with report fields matching the normalized assignment"
                .to_string();
    }
}

fn validate_field_guide_suggestions(
    owner: &str,
    entries: &[FieldGuideEntrySuggestion],
) -> Result<()> {
    if entries.len() > MAX_FIELD_GUIDE_ENTRIES_PER_REPORT {
        bail!(
            "{owner} field_guide_entries contains {} items but at most {} are allowed",
            entries.len(),
            MAX_FIELD_GUIDE_ENTRIES_PER_REPORT
        );
    }
    for entry in entries {
        if entry.finding.trim().is_empty() {
            bail!("{owner} field-guide finding must not be empty");
        }
        if entry.finding.len() > MAX_FIELD_GUIDE_FINDING_BYTES {
            bail!(
                "{owner} field-guide finding exceeds its {} byte bound",
                MAX_FIELD_GUIDE_FINDING_BYTES
            );
        }
        if entry.context.trim().is_empty() {
            bail!("{owner} field-guide context must not be empty");
        }
        if entry.context.len() > MAX_FIELD_GUIDE_CONTEXT_BYTES {
            bail!(
                "{owner} field-guide context exceeds its {} byte bound",
                MAX_FIELD_GUIDE_CONTEXT_BYTES
            );
        }
    }
    let bytes = field_guide_suggestion_bytes(entries)?;
    if bytes > MAX_FIELD_GUIDE_REPORT_BYTES {
        bail!(
            "{owner} field_guide_entries exceeds its {} byte aggregate bound",
            MAX_FIELD_GUIDE_REPORT_BYTES
        );
    }
    Ok(())
}

fn field_guide_suggestion_bytes(entries: &[FieldGuideEntrySuggestion]) -> Result<usize> {
    entries.iter().try_fold(0_usize, |total, entry| {
        total
            .checked_add(entry.finding.len())
            .and_then(|value| value.checked_add(entry.context.len()))
            .context("field-guide suggestion byte count overflowed")
    })
}

fn normalize_worker_report_plumbing(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    workers_by_id: &BTreeMap<&str, &WorkerAssignment>,
    report: &mut WorkerReport,
) -> Result<()> {
    let worker = workers_by_id
        .get(report.id.as_str())
        .context("worker is not declared in the assignment")?;
    let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
    if report.assignment_kind != metadata.kind {
        bail!(
            "assignment_kind '{}' does not match planned kind '{}'",
            report.assignment_kind.as_str(),
            metadata.kind.as_str()
        );
    }
    report.target_path = normalize_report_target_path(report.target_path.take(), "target_path")?;
    if report.target_path != metadata.target_path {
        bail!(
            "target_path '{}' does not match planned target_path '{}'",
            display_optional_path(report.target_path.as_deref()),
            display_optional_path(metadata.target_path.as_deref())
        );
    }

    match metadata.kind {
        AssignmentKind::Ordinary => {
            if report.decomposition_completion.is_some() {
                bail!("ordinary assignment must not report decomposition_completion");
            }
        }
        AssignmentKind::MegafileDecomposition => {
            let target_path = metadata
                .target_path
                .as_deref()
                .context("validated megafile decomposition assignment has no target_path")?;
            let completion = report
                .decomposition_completion
                .take()
                .map(normalize_unbound_decomposition_completion)
                .transpose()?;
            let successful =
                report.accepted && !report.rejected && report.status == ReviewStatus::Succeeded;
            if successful && completion.is_none() {
                bail!(
                    "accepted successful megafile_decomposition worker omitted decomposition_completion"
                );
            }
            if completion.is_some() && !successful {
                bail!("decomposition_completion requires an accepted successful worker");
            }
            if completion.as_ref().map(|value| value.target_path.as_path()) != Some(target_path)
                && completion.is_some()
            {
                bail!("decomposition_completion target_path does not match the assignment");
            }
            if let Some(completion) = &completion {
                let files_changed = normalize_paths(report.files_changed.clone())
                    .context("megafile_decomposition worker files_changed is invalid")?;
                if !files_changed.iter().any(|path| path == target_path) {
                    bail!(
                        "accepted megafile_decomposition worker files_changed omits the exact target"
                    );
                }
                for replacement in &completion.replacement_paths {
                    if !files_changed.contains(replacement) {
                        bail!(
                            "decomposition replacement path '{}' is not reported in files_changed",
                            replacement.display()
                        );
                    }
                    if !worker
                        .assigned_paths
                        .iter()
                        .any(|assigned| path_is_covered_by_claim(replacement, assigned))
                    {
                        bail!(
                            "decomposition replacement path '{}' is outside assigned_paths",
                            replacement.display()
                        );
                    }
                }
            }
            report.decomposition_completion = completion;
        }
    }
    Ok(())
}

fn normalize_bloated_file_flags(
    report: &mut WorkerReport,
    workers_by_id: &BTreeMap<&str, &WorkerAssignment>,
) -> Result<()> {
    if report.bloated_file_flags.len() > MAX_BLOATED_FILE_FLAGS_PER_WORKER {
        bail!(
            "contains {} flags but at most {} are allowed",
            report.bloated_file_flags.len(),
            MAX_BLOATED_FILE_FLAGS_PER_WORKER
        );
    }
    let worker = workers_by_id
        .get(report.id.as_str())
        .context("worker is not declared in the assignment")?;
    let mut normalized = BTreeSet::new();
    for flag in std::mem::take(&mut report.bloated_file_flags) {
        let path = normalize_repo_relative_path(&flag.path)
            .with_context(|| format!("invalid path '{}'", flag.path.display()))?;
        if path.as_os_str().is_empty() {
            bail!("flag path must name a repository file");
        }
        if !worker
            .assigned_paths
            .iter()
            .any(|assigned| path_is_covered_by_claim(&path, assigned))
        {
            bail!("flag path '{}' is outside assigned_paths", path.display());
        }
        normalized.insert(BloatedFileFlag { path });
    }
    report.bloated_file_flags = normalized.into_iter().collect();
    Ok(())
}

pub(super) fn normalize_report_target_path(value: Option<PathBuf>, field: &str) -> Result<Option<PathBuf>> {
    value
        .map(|path| {
            let normalized = normalize_repo_relative_path(&path)
                .with_context(|| format!("{field} '{}' is invalid", path.display()))?;
            if normalized.as_os_str().is_empty() {
                bail!("{field} must name a repository file");
            }
            Ok(normalized)
        })
        .transpose()
}

pub(super) fn normalize_decomposition_completion(
    mut completion: DecompositionCompletion,
) -> Result<DecompositionCompletion> {
    completion.target_path = normalize_report_target_path(
        Some(completion.target_path),
        "decomposition_completion.target_path",
    )?
    .context("decomposition_completion.target_path is required")?;
    if completion.replacement_paths.len() > MAX_DECOMPOSITION_REPLACEMENT_PATHS {
        bail!(
            "decomposition_completion contains {} replacement paths but at most {} are allowed",
            completion.replacement_paths.len(),
            MAX_DECOMPOSITION_REPLACEMENT_PATHS
        );
    }
    completion.replacement_paths = normalize_paths(completion.replacement_paths)
        .context("decomposition_completion.replacement_paths is invalid")?;
    if completion.replacement_paths.is_empty() {
        bail!("decomposition_completion requires at least one replacement path");
    }
    if completion
        .replacement_paths
        .contains(&completion.target_path)
    {
        bail!("decomposition_completion replacement_paths must not include target_path");
    }
    completion.supervisor_candidate_binding = completion
        .supervisor_candidate_binding
        .map(CandidateValidationBinding::canonicalized)
        .transpose()
        .context("decomposition_completion supervisor candidate binding is invalid")?;
    Ok(completion)
}

fn normalize_unbound_decomposition_completion(
    completion: DecompositionCompletion,
) -> Result<DecompositionCompletion> {
    if completion.supervisor_candidate_binding.is_some() {
        bail!(
            "incoming worker or child decomposition evidence must not self-assert supervisor_candidate_binding"
        );
    }
    normalize_decomposition_completion(completion)
}

fn display_optional_path(path: Option<&Path>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "<none>".to_string())
}

pub(super) fn worker_assignment_metadata(
    assignment_metadata: &AssignmentMetadata,
    assignment: &OrchestratorAssignment,
    worker: &WorkerAssignment,
) -> WorkerAssignmentMetadata {
    assignment_metadata
        .get(&(assignment.id.clone(), worker.id.clone()))
        .cloned()
        .unwrap_or_default()
}

pub(super) fn worker_assignment_value(
    worker: &WorkerAssignment,
    metadata: &WorkerAssignmentMetadata,
) -> Result<Value> {
    let mut value =
        serde_json::to_value(worker).context("failed to serialize worker assignment fields")?;
    let object = value
        .as_object_mut()
        .context("worker assignment did not serialize to an object")?;
    let metadata_value = serde_json::to_value(metadata)
        .context("failed to serialize worker assignment kind/target_path")?;
    let metadata_object = metadata_value
        .as_object()
        .context("worker assignment metadata did not serialize to an object")?;
    object.extend(metadata_object.clone());
    Ok(value)
}

pub(super) fn orchestrator_assignment_value(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
) -> Result<Value> {
    let mut value = serde_json::to_value(assignment)
        .context("failed to serialize orchestrator assignment fields")?;
    let workers = value
        .get_mut("worker_assignments")
        .and_then(Value::as_array_mut)
        .context("worker_assignments did not serialize to an array")?;
    for (worker_value, worker) in workers.iter_mut().zip(&assignment.worker_assignments) {
        let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
        *worker_value = worker_assignment_value(worker, &metadata)?;
    }
    Ok(value)
}

pub(super) fn display_decomposition_targets(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
) -> String {
    let targets = assignment
        .worker_assignments
        .iter()
        .filter_map(|worker| {
            worker_assignment_metadata(assignment_metadata, assignment, worker)
                .target_path
                .map(|path| format!("{}={}", worker.id, path.display()))
        })
        .collect::<Vec<_>>();
    if targets.is_empty() {
        "<none>".to_string()
    } else {
        targets.join(", ")
    }
}

pub(super) fn validate_worker_report_evidence(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    if report.worker_reports.is_empty() {
        return;
    }

    let workers_by_id = assignment
        .worker_assignments
        .iter()
        .map(|worker| (worker.id.as_str(), worker))
        .collect::<BTreeMap<_, _>>();
    let actual_paths = report.files_changed.clone();
    let actual_set = actual_paths.iter().cloned().collect::<BTreeSet<_>>();
    let mut reported_union = BTreeSet::<PathBuf>::new();
    let mut blocking_messages = Vec::new();

    for worker_report in &mut report.worker_reports {
        if let Err(error) =
            validate_field_guide_suggestions("worker", &worker_report.field_guide_entries)
        {
            let message = format!(
                "worker '{}' has invalid field_guide_entries: {error}",
                worker_report.id
            );
            worker_report.field_guide_entries.clear();
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                vec![report_path.to_path_buf()],
            );
            blocking_messages.push((message, vec![report_path.to_path_buf()]));
        }
        if let Err(error) = normalize_worker_report_plumbing(
            assignment,
            assignment_metadata,
            &workers_by_id,
            worker_report,
        ) {
            let message = format!(
                "worker '{}' has invalid assignment/decomposition report plumbing: {error}",
                worker_report.id
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                vec![report_path.to_path_buf()],
            );
            blocking_messages.push((message, vec![report_path.to_path_buf()]));
        }
        if let Err(error) = normalize_bloated_file_flags(worker_report, &workers_by_id) {
            let message = format!(
                "worker '{}' has invalid bloated_file_flags: {error}",
                worker_report.id
            );
            worker_report.bloated_file_flags.clear();
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                vec![report_path.to_path_buf()],
            );
            blocking_messages.push((message, vec![report_path.to_path_buf()]));
        }
        let normalized_files_changed = match normalize_paths(worker_report.files_changed.clone()) {
            Ok(paths) => {
                worker_report.files_changed = paths.clone();
                paths
            }
            Err(error) => {
                let message = format!(
                    "worker '{}' reported invalid files_changed paths: {error}",
                    worker_report.id
                );
                mark_worker_report_structural_inconsistency(
                    worker_report,
                    message.clone(),
                    vec![report_path.to_path_buf()],
                );
                blocking_messages.push((message, vec![report_path.to_path_buf()]));
                Vec::new()
            }
        };
        reported_union.extend(normalized_files_changed.iter().cloned());

        let allowed_paths = if let Some(worker) = workers_by_id.get(worker_report.id.as_str()) {
            worker.assigned_paths.clone()
        } else {
            let message = format!(
                "worker '{}' is not declared in assignment '{}' worker_assignments",
                worker_report.id, assignment.id
            );
            let paths = if normalized_files_changed.is_empty() {
                vec![report_path.to_path_buf()]
            } else {
                normalized_files_changed.clone()
            };
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                paths.clone(),
            );
            blocking_messages.push((message, paths));
            Vec::new()
        };
        let unauthorized_paths = normalized_files_changed
            .iter()
            .filter(|path| {
                !allowed_paths
                    .iter()
                    .any(|assigned| path_is_covered_by_claim(path, assigned))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !unauthorized_paths.is_empty() {
            let message = format!(
                "worker '{}' reported files_changed outside its assigned_paths: {}",
                worker_report.id,
                display_paths(&unauthorized_paths)
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                unauthorized_paths.clone(),
            );
            blocking_messages.push((message, unauthorized_paths));
        }

        if worker_report.accepted
            && worker_report.status == ReviewStatus::Succeeded
            && worker_report
                .validation_results
                .iter()
                .any(validation_failed)
        {
            let failed_validation_paths = if normalized_files_changed.is_empty() {
                vec![report_path.to_path_buf()]
            } else {
                normalized_files_changed.clone()
            };
            let message = format!(
                "worker '{}' reports failed validation while accepted=true and status=succeeded",
                worker_report.id
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                failed_validation_paths.clone(),
            );
            blocking_messages.push((message, failed_validation_paths));
        }
    }

    let reported_but_not_observed = reported_union
        .difference(&actual_set)
        .cloned()
        .collect::<Vec<_>>();
    let observed_but_not_reported = actual_set
        .difference(&reported_union)
        .cloned()
        .collect::<Vec<_>>();
    if !reported_but_not_observed.is_empty() || !observed_but_not_reported.is_empty() {
        let paths = union_paths(&reported_but_not_observed, &observed_but_not_reported);
        let message = format!(
            "worker files_changed union differs from actual child worktree Git changes; reported-but-not-observed: {}; observed-but-not-reported: {}",
            display_paths(&reported_but_not_observed),
            display_paths(&observed_but_not_reported)
        );
        blocking_messages.push((message, paths));
    }

    if blocking_messages.is_empty() {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    for (message, paths) in blocking_messages {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message,
            paths,
        });
    }
    report.remaining_risk =
        "one or more worker reports have structural evidence inconsistencies".to_string();
    report.next_safe_action =
        "inspect worker reports and rerun the child scope with corrected evidence".to_string();
}

pub(super) fn validate_worker_execution_journal_evidence(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    journals: &WorkerExecutionJournalEvidenceSet,
    report: &mut OrchestratorReviewReport,
) {
    if assignment.worker_assignments.is_empty() || report.worker_reports.is_empty() {
        return;
    }

    let workers_by_id = assignment
        .worker_assignments
        .iter()
        .map(|worker| (worker.id.as_str(), worker))
        .collect::<BTreeMap<_, _>>();
    let actual_set = report
        .files_changed
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut blocking_messages = Vec::new();

    for worker_report in &mut report.worker_reports {
        let Some(worker_assignment) = workers_by_id.get(worker_report.id.as_str()) else {
            continue;
        };
        let Some(journal) = journals.get(&worker_report.id) else {
            let message = format!(
                "worker '{}' execution journal evidence was not imported by the supervisor gate",
                worker_report.id
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                vec![report_path.to_path_buf()],
            );
            blocking_messages.push((message, vec![report_path.to_path_buf()]));
            continue;
        };

        let entries = match &journal.status {
            WorkerExecutionJournalStatus::Loaded(entries) => entries,
            WorkerExecutionJournalStatus::Missing => {
                let message = format!(
                    "worker '{}' execution journal is missing; expected {} imported as {}",
                    worker_report.id,
                    journal.incoming_relative_path.display(),
                    journal.evidence_relative_path.display()
                );
                mark_worker_report_structural_inconsistency(
                    worker_report,
                    message.clone(),
                    vec![journal.evidence_relative_path.clone()],
                );
                blocking_messages.push((message, vec![journal.evidence_relative_path.clone()]));
                continue;
            }
            WorkerExecutionJournalStatus::Invalid(error) => {
                let message = format!(
                    "worker '{}' execution journal {} is invalid: {}",
                    worker_report.id,
                    journal.evidence_relative_path.display(),
                    error
                );
                mark_worker_report_structural_inconsistency(
                    worker_report,
                    message.clone(),
                    vec![journal.evidence_relative_path.clone()],
                );
                blocking_messages.push((message, vec![journal.evidence_relative_path.clone()]));
                continue;
            }
        };

        let mut journal_paths = BTreeSet::<PathBuf>::new();
        let mut journal_unauthorized_paths = BTreeSet::<PathBuf>::new();
        for entry in entries {
            for path in &entry.changed_paths {
                journal_paths.insert(path.clone());
                if !worker_assignment
                    .assigned_paths
                    .iter()
                    .any(|assigned| path_is_covered_by_claim(path, assigned))
                {
                    journal_unauthorized_paths.insert(path.clone());
                }
            }
        }

        if !journal_unauthorized_paths.is_empty() {
            let paths = journal_unauthorized_paths.into_iter().collect::<Vec<_>>();
            let message = format!(
                "worker '{}' execution journal {} changed paths outside assigned_paths: {}",
                worker_report.id,
                journal.evidence_relative_path.display(),
                display_paths(&paths)
            );
            let finding_paths = union_paths(
                &paths,
                std::slice::from_ref(&journal.evidence_relative_path),
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                finding_paths.clone(),
            );
            blocking_messages.push((message, finding_paths));
        }

        let journal_without_git = journal_paths
            .difference(&actual_set)
            .cloned()
            .collect::<Vec<_>>();
        if !journal_without_git.is_empty() {
            let message = format!(
                "worker '{}' execution journal {} changed paths are not supported by supervisor-inspected Git diff: {}",
                worker_report.id,
                journal.evidence_relative_path.display(),
                display_paths(&journal_without_git)
            );
            let finding_paths = union_paths(
                &journal_without_git,
                std::slice::from_ref(&journal.evidence_relative_path),
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                finding_paths.clone(),
            );
            blocking_messages.push((message, finding_paths));
        }

        let journal_commands = entries
            .iter()
            .map(|entry| (entry.command.clone(), entry.cwd.clone()))
            .collect::<BTreeSet<_>>();
        let reported_commands_without_journal = worker_report
            .commands_run
            .iter()
            .filter(|record| {
                !journal_commands.contains(&(record.command.clone(), record.cwd.clone()))
            })
            .map(|record| (record.command.clone(), record.cwd.clone()))
            .collect::<Vec<_>>();
        if !reported_commands_without_journal.is_empty() {
            let message = format!(
                "worker '{}' commands_run entries are not supported by execution journal {}: {}",
                worker_report.id,
                journal.evidence_relative_path.display(),
                display_command_identities(&reported_commands_without_journal)
            );
            let paths = vec![
                report_path.to_path_buf(),
                journal.evidence_relative_path.clone(),
            ];
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                paths.clone(),
            );
            blocking_messages.push((message, paths));
        }

        let reported_paths = worker_report
            .files_changed
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let report_without_journal = reported_paths
            .difference(&journal_paths)
            .cloned()
            .collect::<Vec<_>>();
        if !report_without_journal.is_empty() {
            let message = format!(
                "worker '{}' files_changed paths are not supported by execution journal {}: {}",
                worker_report.id,
                journal.evidence_relative_path.display(),
                display_paths(&report_without_journal)
            );
            let finding_paths = union_paths(
                &report_without_journal,
                std::slice::from_ref(&journal.evidence_relative_path),
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                finding_paths.clone(),
            );
            blocking_messages.push((message, finding_paths));
        }

        let report_without_git = reported_paths
            .difference(&actual_set)
            .cloned()
            .collect::<Vec<_>>();
        if !report_without_git.is_empty() {
            let message = format!(
                "worker '{}' files_changed paths are not supported by supervisor-inspected Git diff: {}",
                worker_report.id,
                display_paths(&report_without_git)
            );
            mark_worker_report_structural_inconsistency(
                worker_report,
                message.clone(),
                report_without_git.clone(),
            );
            blocking_messages.push((message, report_without_git));
        }
    }

    if blocking_messages.is_empty() {
        return;
    }

    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    for (message, paths) in blocking_messages {
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message,
            paths,
        });
    }
    report.remaining_risk =
        "one or more worker execution journals are missing, invalid, or inconsistent with reported evidence".to_string();
    report.next_safe_action =
        "inspect worker execution journals and rerun the child scope with corrected process evidence"
            .to_string();
}

fn mark_worker_report_structural_inconsistency(
    worker_report: &mut WorkerReport,
    message: String,
    paths: Vec<PathBuf>,
) {
    worker_report.status = ReviewStatus::Failed;
    worker_report.accepted = false;
    worker_report.rejected = true;
    worker_report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message,
        paths,
    });
}

pub(super) fn should_retry_child_report(
    report: &OrchestratorReviewReport,
    report_shape_problems: &[String],
    attempt: usize,
    max_child_retries: u8,
) -> bool {
    if report_shape_problems.is_empty() || attempt > usize::from(max_child_retries) {
        return false;
    }
    if report.worker_reports.iter().any(report_failed)
        || report.validation_results.iter().any(validation_failed)
    {
        return false;
    }
    !report.findings.iter().any(|finding| {
        finding.severity == FindingSeverity::Error
            && !report_shape_problems
                .iter()
                .any(|problem| finding.message.contains(problem))
            && !retryable_cascaded_shape_message(&finding.message)
    })
}

fn retryable_cascaded_shape_message(message: &str) -> bool {
    message.contains("omitted required worker reports for assignment worker IDs")
        || message.contains("contained zero worker_reports despite assigned worker IDs")
}

pub(super) fn validation_failed(result: &ValidationResult) -> bool {
    result.status != ReviewStatus::Succeeded
}

pub(super) fn mark_child_containment_violation(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    process_tree: Option<ProcessTreeEvidence>,
    side_effects: Option<SideEffectConfinementEvidence>,
    report: &mut OrchestratorReviewReport,
) {
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "child orchestrator '{}' process safety was not verified; process_tree={process_tree:?}; side_effects={side_effects:?}",
            assignment.id,
        ),
        paths: vec![report_path.to_path_buf()],
    });
    report.remaining_risk =
        "the child process tree may still be live, so no retry or parent auditor was launched"
            .to_string();
    report.next_safe_action =
        "restore the primary worktree if needed, fix host containment support, and rerun this child scope"
            .to_string();
}

pub(super) fn mark_primary_integrity_violation(
    assignment: &OrchestratorAssignment,
    changes: &PrimaryIntegrityChanges,
    report: &mut OrchestratorReviewReport,
) {
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "primary worktree integrity changed during child orchestrator '{}' run: {}",
            assignment.id,
            changes.details.join("; ")
        ),
        paths: changes.paths.clone(),
    });
    report.remaining_risk =
        "child run mutated primary HEAD/ref, index, tracked content, or non-runtime untracked content"
            .to_string();
    report.next_safe_action =
        "inspect and restore the primary worktree before rerunning supervise".to_string();
}

pub(super) fn mark_auditor_primary_integrity_violation(
    assignment: &OrchestratorAssignment,
    changes: &PrimaryIntegrityChanges,
    report: &mut AuditorReport,
) {
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.read_only = false;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: format!(
            "primary worktree integrity changed during parent review auditor '{}' run: {}",
            parent_auditor_id(assignment),
            changes.details.join("; ")
        ),
        paths: changes.paths.clone(),
    });
    report.remaining_risk =
        "parent auditor invocation mutated primary HEAD/ref, index, tracked content, or non-runtime untracked content"
            .to_string();
    report.next_safe_action =
        "inspect and restore the primary worktree before rerunning supervise".to_string();
}
