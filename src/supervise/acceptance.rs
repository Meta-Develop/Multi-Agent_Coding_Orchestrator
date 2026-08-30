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
        evidence_only_source,
        observed_changed_paths,
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
    let direct_worker = assignment.role == AgentRole::Worker
        && assignment.role_category == Some(RoleCategory::NonDelegatingTerminalWorker);
    let mut report_shape_problems = Vec::new();
    let parsed_report = if direct_worker {
        read_direct_worker_report(external_run.output_last_message(), report_path).map(|parsed| {
            ParsedReport {
                report: direct_worker_report_envelope(parsed.report),
                recovered: parsed.recovered,
            }
        })
    } else {
        read_child_report(external_run.output_last_message(), report_path)
    };
    let mut report = match parsed_report {
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
            if report.role != assignment.role {
                let message = format!(
                    "assignment report role must be '{}'",
                    assignment.role.as_str()
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
            let error = format!("{error:#}");
            let message = format!("required assignment report is missing or invalid: {error}");
            report_shape_problems.push(message);
            let mut report = missing_child_report(
                assignment,
                report_path,
                external_run,
                external_command,
                error,
            );
            report.role = assignment.role;
            report
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
    if report.review_lens_aggregate.take().is_some() {
        report.status = ReviewStatus::Failed;
        report.accepted = false;
        report.rejected = true;
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message:
                "child report attempted to self-assert a supervisor-owned review-lens aggregate"
                    .to_string(),
            paths: vec![report_path.to_path_buf()],
        });
    }
    if report.licensed_breakage_review.take().is_some()
        || !report.generated_follow_up_tasks.is_empty()
    {
        report.generated_follow_up_tasks.clear();
        report.status = ReviewStatus::Failed;
        report.accepted = false;
        report.rejected = true;
        report.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: "child report attempted to self-assert supervisor-owned licensed breakage authority or generated follow-up tasks"
                .to_string(),
            paths: vec![report_path.to_path_buf()],
        });
    }
    validate_worker_report_delegation_attestations(assignment, report_path, &mut report);
    if evidence_only_source.is_none() {
        verify_child_report_paths(
            assignment,
            worktree_path,
            child_base_head,
            observed_changed_paths,
            &mut report,
        );
    }
    prepare_licensed_breakage_review(assignment, &mut report);
    validate_worker_report_evidence(assignment, assignment_metadata, report_path, &mut report);
    validate_assignment_report_plumbing(assignment, assignment_metadata, report_path, &mut report);
    if let Some(source) = evidence_only_source {
        validate_evidence_only_report_preservation(source, report_path, &mut report);
    } else {
        validate_worker_execution_journal_evidence(
            assignment,
            report_path,
            worker_journals,
            &mut report,
        );
    }
    enforce_orchestrator_environment_failure_outcome(&mut report);
    (report, report_shape_problems)
}

fn read_direct_worker_report(
    contents: Option<&[u8]>,
    display_path: &Path,
) -> Result<ParsedReport<WorkerReport>> {
    let contents =
        contents.context("external run did not capture a descriptor-held direct worker report")?;
    let contents = std::str::from_utf8(contents).with_context(|| {
        format!(
            "descriptor-held direct worker report is not UTF-8: {}",
            display_path.display()
        )
    })?;
    parse_report_json(contents).with_context(|| {
        format!(
            "failed to parse direct worker report {}",
            display_path.display()
        )
    })
}

fn direct_worker_report_envelope(worker: WorkerReport) -> OrchestratorReviewReport {
    OrchestratorReviewReport {
        id: worker.id.clone(),
        role: worker.role,
        assigned_paths: worker.assigned_paths.clone(),
        semantic_symbols: worker.semantic_symbols.clone(),
        semantic_modules: worker.semantic_modules.clone(),
        claim_token: worker.claim_token,
        semantic_intent_token: worker.semantic_intent_token,
        commands_run: worker.commands_run.clone(),
        environment_failures: worker.environment_failures.clone(),
        files_changed: worker.files_changed.clone(),
        validation_results: worker.validation_results.clone(),
        findings: worker.findings.clone(),
        field_guide_entries: Vec::new(),
        worker_reports: vec![worker.clone()],
        audit_reports: Vec::new(),
        review_lens_aggregate: None,
        decomposition_completions: worker
            .decomposition_completion
            .clone()
            .into_iter()
            .collect(),
        licensed_breakage_review: None,
        generated_follow_up_tasks: Vec::new(),
        gate_denials: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        accepted: worker.accepted,
        rejected: worker.rejected,
        status: worker.status,
        remaining_risk: worker.remaining_risk.clone(),
        next_safe_action: worker.next_safe_action.clone(),
    }
}

#[derive(Clone, Copy)]
struct FailedValidationSource<'a> {
    validation: &'a ValidationResult,
    findings: &'a [Finding],
}

pub(super) fn prepare_licensed_breakage_review(
    assignment: &OrchestratorAssignment,
    report: &mut OrchestratorReviewReport,
) {
    let Some(declaration) = assignment.licensed_breakage.as_ref() else {
        return;
    };
    let Ok(declaration_sha256) = licensed_breakage_declaration_sha256(declaration) else {
        return;
    };
    report.licensed_breakage_review = Some(LicensedBreakageReview {
        declaration_sha256,
        migration_rationale: declaration.migration_rationale.clone(),
        failures: Vec::new(),
    });
    if !report.environment_failures.is_empty()
        || report.audit_reports.iter().any(|audit| {
            report_failed(audit)
                || !audit.environment_failures.is_empty()
                || audit
                    .findings
                    .iter()
                    .any(|finding| finding.severity == FindingSeverity::Error)
        })
    {
        return;
    }

    let mut sources = report
        .validation_results
        .iter()
        .filter(|validation| validation_failed(validation))
        .map(|validation| FailedValidationSource {
            validation,
            findings: &report.findings,
        })
        .collect::<Vec<_>>();
    sources.extend(report.worker_reports.iter().flat_map(|worker| {
        worker
            .validation_results
            .iter()
            .filter(|validation| validation_failed(validation))
            .map(|validation| FailedValidationSource {
                validation,
                findings: &worker.findings,
            })
    }));
    if sources.is_empty() {
        return;
    }
    let Some(failures) = sources
        .iter()
        .map(|source| classify_licensed_dependent_failure(declaration, *source))
        .collect::<Option<Vec<_>>>()
    else {
        return;
    };
    if failures.len() != sources.len()
        || !all_error_findings_are_licensed(report, &failures)
        || !all_failed_commands_are_licensed(report, &failures)
    {
        return;
    }
    let licensed_signatures = failures
        .iter()
        .map(|failure| failure.failure_signature.as_str())
        .collect::<BTreeSet<_>>();
    for worker in &mut report.worker_reports {
        let has_licensed_failure = worker.validation_results.iter().any(|validation| {
            validation_failed(validation)
                && validation
                    .message
                    .as_deref()
                    .is_some_and(|message| licensed_signatures.contains(message))
        });
        if has_licensed_failure {
            worker.accepted = true;
            worker.rejected = false;
            worker.status = ReviewStatus::Succeeded;
        }
    }
    report.accepted = true;
    report.rejected = false;
    report.status = ReviewStatus::Succeeded;
    if let Some(review) = report.licensed_breakage_review.as_mut() {
        review.failures = failures;
    }
}

fn classify_licensed_dependent_failure(
    declaration: &LicensedBreakageDeclaration,
    source: FailedValidationSource<'_>,
) -> Option<LicensedDependentFailure> {
    let signature = source.validation.message.as_deref()?.trim();
    if signature.is_empty()
        || signature != source.validation.message.as_deref()?
        || signature.len() > MAX_LICENSED_BREAKAGE_FAILURE_SIGNATURE_BYTES
        || signature.chars().any(char::is_control)
    {
        return None;
    }
    let dependent = declaration
        .dependents
        .iter()
        .find(|dependent| dependent.dependent_id == source.validation.name)?;
    let matching_findings = source
        .findings
        .iter()
        .filter(|finding| {
            finding.severity == FindingSeverity::Error && finding.message == signature
        })
        .collect::<Vec<_>>();
    if matching_findings.is_empty() {
        return None;
    }
    let paths = normalize_paths(
        matching_findings
            .iter()
            .flat_map(|finding| finding.paths.iter().cloned())
            .collect(),
    )
    .ok()?;
    if paths.is_empty()
        || paths.iter().any(|path| {
            !dependent
                .paths
                .iter()
                .any(|licensed| path_is_covered_by_claim(path, licensed))
        })
    {
        return None;
    }
    let interfaces = dependent
        .interfaces
        .iter()
        .filter(|interface| failure_signature_references_interface(signature, interface))
        .cloned()
        .collect::<Vec<_>>();
    if interfaces.is_empty() {
        return None;
    }
    Some(LicensedDependentFailure {
        dependent_id: dependent.dependent_id.clone(),
        validation_name: source.validation.name.clone(),
        failure_signature: signature.to_string(),
        paths,
        interfaces,
    })
}

fn failure_signature_references_interface(signature: &str, interface: &str) -> bool {
    signature.match_indices(interface).any(|(start, _)| {
        let end = start.saturating_add(interface.len());
        let boundary = |character: Option<char>| {
            character.is_none_or(|character| {
                !character.is_ascii_alphanumeric() && !matches!(character, '_' | ':')
            })
        };
        boundary(signature[..start].chars().next_back())
            && boundary(signature[end..].chars().next())
    })
}

fn all_error_findings_are_licensed(
    report: &OrchestratorReviewReport,
    failures: &[LicensedDependentFailure],
) -> bool {
    let signatures = failures
        .iter()
        .map(|failure| failure.failure_signature.as_str())
        .collect::<BTreeSet<_>>();
    report
        .findings
        .iter()
        .chain(
            report
                .worker_reports
                .iter()
                .flat_map(|worker| worker.findings.iter()),
        )
        .filter(|finding| finding.severity == FindingSeverity::Error)
        .all(|finding| signatures.contains(finding.message.as_str()))
}

fn all_failed_commands_are_licensed(
    report: &OrchestratorReviewReport,
    failures: &[LicensedDependentFailure],
) -> bool {
    let signatures = failures
        .iter()
        .map(|failure| failure.failure_signature.as_str())
        .collect::<Vec<_>>();
    report
        .commands_run
        .iter()
        .chain(
            report
                .worker_reports
                .iter()
                .flat_map(|worker| worker.commands_run.iter()),
        )
        .filter(|command| command.status != ReviewStatus::Succeeded)
        .all(|command| {
            !command.timed_out
                && command.error.is_none()
                && command.environment_failures.is_empty()
                && signatures.iter().any(|signature| {
                    command.stdout.contains(*signature) || command.stderr.contains(*signature)
                })
        })
}

pub(super) fn generated_licensed_follow_up_tasks(
    plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
    source_budget: &SupervisorBudgetConfig,
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
    breaking_change: &CandidateValidationBinding,
) -> Result<Vec<GeneratedFollowUpTaskRecord>> {
    let Some(review) = report.licensed_breakage_review.as_ref() else {
        return Ok(Vec::new());
    };
    if report_failed(report) {
        bail!(
            "cannot generate licensed follow-up tasks before assignment '{}' passes its auditor gate",
            assignment.id
        );
    }
    if !report.generated_follow_up_tasks.is_empty() {
        bail!(
            "assignment '{}' already contains supervisor-owned generated follow-up tasks",
            assignment.id
        );
    }
    if review.failures.is_empty() {
        bail!(
            "assignment '{}' licensed dependent failures generated no follow-up task inputs",
            assignment.id
        );
    }
    let existing_ids = plan
        .assignments
        .iter()
        .flat_map(|assignment| {
            std::iter::once(assignment.id.as_str()).chain(
                assignment
                    .worker_assignments
                    .iter()
                    .map(|worker| worker.id.as_str()),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut generated_ids = BTreeSet::new();
    review
        .failures
        .iter()
        .enumerate()
        .map(|(index, failure)| {
            let ordinal = index.saturating_add(1);
            let id = normalize_agent_id(&format!(
                "{}-licensed-update-{ordinal:02}",
                assignment.id
            ))?;
            if existing_ids.contains(id.as_str()) || !generated_ids.insert(id.clone()) {
                bail!(
                    "generated licensed follow-up assignment id '{}' collides with the task tree",
                    id
                );
            }
            let follow_up_assignment = OrchestratorAssignment {
                id,
                phase: AssignmentPhase::Execution,
                runtime: None,
                role: AgentRole::ChildOrchestrator,
                role_category: None,
                selection_source: None,
                assigned_paths: failure.paths.clone(),
                semantic_symbols: failure.interfaces.clone(),
                semantic_modules: Vec::new(),
                task: Some(format!(
                    "Update dependent '{}' for the licensed breaking change from assignment '{}'. Migration rationale: {} Failure signature: {}",
                    failure.dependent_id,
                    assignment.id,
                    review.migration_rationale,
                    failure.failure_signature
                )),
                worker_assignments: Vec::new(),
                environment_requirements: Vec::new(),
                licensed_breakage: None,
                notes: Some(
                    "Generated licensed-breakage follow-up in a complete ordinary supervisor plan; authenticated queue admission requires an accepted publishable source run"
                        .to_string(),
                ),
            };
            let schedule = vec![AssignmentScheduleEntry {
                assignment_id: follow_up_assignment.id.clone(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index: 0,
            }];
            let ordinary_plan = SupervisorPlan {
                version: SUPERVISOR_SCHEMA_VERSION,
                task: format!(
                    "Dispatch generated dependent update '{}' for licensed breaking assignment '{}'. The generated_follow_up section documents candidate provenance, authenticated queue eligibility, and every operator-owned default.",
                    failure.dependent_id, assignment.id
                ),
                task_file: None,
                max_depth: plan.max_depth,
                max_child_assignments: 1,
                max_child_retries: plan.max_child_retries,
                max_gate_corrections: plan.max_gate_corrections,
                child_timeout_seconds: plan.child_timeout_seconds,
                semantic_coordination: plan.semantic_coordination,
                role_models: plan.role_models.clone(),
                model_pricing: plan.model_pricing.clone(),
                review_lenses: plan.review_lenses.clone(),
                review_aggregation_policy: plan.review_aggregation_policy,
                assignments: vec![follow_up_assignment],
            };
            let run_budget = derived_generated_follow_up_budget(&ordinary_plan, source_budget)?;
            let handoff = "an accepted publishable source command may admit this exact supervisor_plan to the authenticated durable bounded follow-up queue; fake and non-publishable sources remain deferred"
                .to_string();
            let generated_context = GeneratedFollowUpPlanContext {
                breaking_assignment_id: assignment.id.clone(),
                breaking_change: breaking_change.clone(),
                declaration_sha256: review.declaration_sha256.clone(),
                failure_signature: failure.failure_signature.clone(),
                migration_rationale: review.migration_rationale.clone(),
                cascade_depth: LICENSED_BREAKAGE_CASCADE_DEPTH,
                dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
                handoff: handoff.clone(),
                operator_defaults: generated_follow_up_operator_defaults(),
            };
            let mut supervisor_plan = GeneratedFollowUpSupervisorPlan {
                version: ordinary_plan.version,
                task: ordinary_plan.task.clone(),
                task_file: ordinary_plan.task_file.clone(),
                max_depth: ordinary_plan.max_depth,
                max_child_assignments: ordinary_plan.max_child_assignments,
                max_child_retries: ordinary_plan.max_child_retries,
                max_gate_corrections: ordinary_plan.max_gate_corrections,
                child_timeout_seconds: ordinary_plan.child_timeout_seconds,
                semantic_coordination: ordinary_plan.semantic_coordination,
                role_models: ordinary_plan.role_models.clone(),
                model_pricing: ordinary_plan.model_pricing.clone(),
                review_lenses: ordinary_plan.review_lenses.clone(),
                review_aggregation_policy: ordinary_plan.review_aggregation_policy,
                assignments: ordinary_plan.assignments.clone(),
                spec_fragment_ids: Vec::new(),
                assignment_schedule: schedule,
                run_budget,
                consultant: consultant.clone(),
                generated_follow_up: generated_context,
            };
            supervisor_plan.bind_assignment_role_categories();
            let serialized_plan = serde_json::to_string(&supervisor_plan)
                .context("failed to serialize generated follow-up supervisor plan")?;
            let loaded = parse_supervisor_plan_with_consultant(&serialized_plan)
                .context("generated follow-up supervisor plan is not dispatchable")?;
            if loaded.plan != supervisor_plan.ordinary_plan()
                || loaded.consultant != supervisor_plan.consultant
                || loaded.plan_metadata.assignment_schedule != supervisor_plan.assignment_schedule
                || loaded.plan_metadata.run_budget != supervisor_plan.run_budget
                || loaded.plan_metadata.generated_follow_up
                    != Some(supervisor_plan.generated_follow_up.clone())
            {
                bail!("generated follow-up supervisor plan changed across the ordinary plan loader");
            }
            Ok(GeneratedFollowUpTaskRecord {
                supervisor_plan,
                breaking_assignment_id: assignment.id.clone(),
                breaking_change: breaking_change.clone(),
                declaration_sha256: review.declaration_sha256.clone(),
                failure_signature: failure.failure_signature.clone(),
                migration_rationale: review.migration_rationale.clone(),
                cascade_depth: LICENSED_BREAKAGE_CASCADE_DEPTH,
                dispatch_status: GeneratedFollowUpDispatchStatus::DeferredForPlannedRun,
                handoff,
            })
        })
        .collect()
}

fn validate_evidence_only_report_preservation(
    source: &OrchestratorReviewReport,
    report_path: &Path,
    report: &mut OrchestratorReviewReport,
) {
    let preserved = report.assigned_paths == source.assigned_paths
        && report.semantic_symbols == source.semantic_symbols
        && report.semantic_modules == source.semantic_modules
        && report.files_changed == source.files_changed
        && report.field_guide_entries == source.field_guide_entries
        && report.worker_reports == source.worker_reports
        && report.decomposition_completions == source.decomposition_completions
        && report.audit_reports.is_empty();
    if preserved {
        return;
    }
    report.status = ReviewStatus::Failed;
    report.accepted = false;
    report.rejected = true;
    report.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: "evidence-only report changed preserved implementation evidence or self-asserted auditor evidence"
            .to_string(),
        paths: vec![report_path.to_path_buf()],
    });
    report.remaining_risk =
        "the evidence-only report is not bound to the authenticated source report".to_string();
    report.next_safe_action =
        "discard this report and retain the authenticated source assignment".to_string();
}

pub(super) fn collect_parent_auditor_report(
    expected_id: &str,
    report_path: &Path,
    external_run: &ExternalAgentRun,
    external_command: &ExternalAgentCommand,
) -> AuditorReport {
    if external_run.environment_blocked() {
        let mut report = missing_parent_auditor_report(
            expected_id,
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
        Err(error) => missing_parent_auditor_report(expected_id, report_path, external_run, error),
    };
    report
        .commands_run
        .push(command_record_from_external(external_run, external_command));
    enforce_auditor_environment_failure_outcome(&mut report);
    report
}

pub(super) fn review_lens_verdict_from_auditor(
    lens: &ReviewLensConfig,
    expected_request: &ReviewLensRequest,
    expected_auditor_id: &str,
    report: &AuditorReport,
    licensed_breakage_review: Option<&LicensedBreakageReview>,
    process_procedural_failure: bool,
) -> Result<ReviewLensVerdict> {
    let normalized_paths = normalize_paths(report.reviewed_paths.clone()).ok();
    let normalized_workers = report
        .reviewed_worker_ids
        .iter()
        .map(|worker_id| normalize_agent_id(worker_id))
        .collect::<Result<BTreeSet<_>>>()
        .ok();
    let structurally_valid = normalized_paths.is_some()
        && normalized_workers.is_some()
        && report.id == expected_auditor_id
        && report.role == AgentRole::Auditor
        && report.no_further_delegation == Some(true)
        && report.read_only
        && !report.commands_run.is_empty()
        && !report.validation_results.is_empty()
        && auditor_accepted_licensed_breakage(report, licensed_breakage_review)
        && !report.remaining_risk.trim().is_empty()
        && !report.next_safe_action.trim().is_empty()
        && if report.accepted && !report.rejected && report.status == ReviewStatus::Succeeded {
            report.rejection_kind.is_none()
        } else if report.rejected || report.status == ReviewStatus::Rejected {
            report.rejection_kind.is_some()
        } else {
            true
        };
    let verdict = if process_procedural_failure || !structurally_valid {
        ReviewLensVerdictStatus::ProceduralFailure
    } else if report.accepted && !report.rejected && report.status == ReviewStatus::Succeeded {
        ReviewLensVerdictStatus::Accept
    } else if report.rejected || report.status == ReviewStatus::Rejected {
        ReviewLensVerdictStatus::Reject
    } else {
        ReviewLensVerdictStatus::ProceduralFailure
    };
    let coverage = ReviewLensCoverage {
        worker_ids: normalized_workers.unwrap_or_default().into_iter().collect(),
        paths: normalized_paths.unwrap_or_default(),
    };
    let evidence = if verdict == ReviewLensVerdictStatus::ProceduralFailure {
        Vec::new()
    } else {
        vec![(
            ReviewLensEvidenceKind::ModelReview,
            serde_json::to_string(report)
                .context("failed to recompute parent-owned review-lens evidence")?,
        )]
    };
    ReviewLensVerdict::for_lens(
        lens,
        expected_request.request_binding.clone(),
        verdict,
        coverage,
        evidence,
    )
}

fn auditor_accepted_licensed_breakage(
    report: &AuditorReport,
    review: Option<&LicensedBreakageReview>,
) -> bool {
    let markers = report
        .validation_results
        .iter()
        .filter(|validation| validation.name == LICENSED_BREAKAGE_AUDIT_VALIDATION_NAME)
        .collect::<Vec<_>>();
    match review {
        None => markers.is_empty(),
        Some(review) => {
            markers.len() == 1
                && markers[0].status == ReviewStatus::Succeeded
                && markers[0].message.as_deref() == Some(review.declaration_sha256.as_str())
        }
    }
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
        if !auditor_accepted_licensed_breakage(
            audit_report,
            report.licensed_breakage_review.as_ref(),
        ) {
            valid = false;
            messages.push(
                "auditor report did not accept the exact supervisor-bound licensed breakage declaration"
                    .to_string(),
            );
        }
        if !audit_report.accepted
            || audit_report.rejected
            || audit_report.status != ReviewStatus::Succeeded
        {
            valid = false;
            messages.push("auditor report was not accepted as succeeded".to_string());
        }
        if is_parent_auditor_id(assignment, &audit_report.id) {
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
            if is_parent_auditor_id(assignment, &audit_report.id) {
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
        || report.licensed_breakage_review.is_some()
        || report_has_field_guide_suggestions(report)
}

pub(super) fn report_has_field_guide_suggestions(report: &OrchestratorReviewReport) -> bool {
    !report.field_guide_entries.is_empty()
        || report
            .worker_reports
            .iter()
            .any(|worker| !worker.field_guide_entries.is_empty())
}

pub(super) fn inspect_fake_simulation_candidate(
    repo: &Path,
    assignment: &OrchestratorAssignment,
    worktree_write_lease: &ManagedWorktreeWriteLease,
) -> Result<SupervisorCandidateInspection> {
    let repo_root = discover_repo_root(repo)?;
    WorktreeManager::new(&repo_root)
        .verify_write_execution_lease(&assignment.id, worktree_write_lease)
        .context("fake simulation candidate has no exclusive write lease")?;
    let record = worktree_write_lease.record();
    let primary_head = current_head_oid(&repo_root)?;
    let agent_head = current_head_oid(&record.path)?;
    let changed_paths = normalize_paths(collect_paths_changed_since_base(
        &record.path,
        &primary_head,
    )?)
    .context("fake simulation candidate paths are invalid")?;
    let raw_diff =
        collect_diff_since_base(&record.path, &primary_head, REVIEW_LENS_REQUEST_LIMIT_BYTES)
            .context("failed to capture fake simulation candidate diff")?;
    let binding = candidate_validation_binding(
        &WorktreeMergeMetadata {
            agent_id: assignment.id.clone(),
            worktree_path: record.path.clone(),
            branch: record.branch.clone(),
            primary_repo_root: repo_root,
            primary_head: Some(primary_head.to_string()),
            agent_head: Some(agent_head.to_string()),
            merge_base: Some(primary_head.to_string()),
            base_matches_primary: Some(true),
        },
        raw_diff.as_bytes(),
    )
    .context("fake simulation candidate binding is invalid")?;
    Ok(SupervisorCandidateInspection {
        binding,
        changed_paths,
    })
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

pub(super) fn inspect_primary_scope_candidate(
    repo: &Path,
    assignment: &OrchestratorAssignment,
    baseline: &PrimaryScopeSnapshot,
    runtime: SupervisorExecutionRuntime,
) -> Result<SupervisorCandidateInspection> {
    let current = capture_primary_scope_snapshot(repo, &assignment.assigned_paths, false, runtime)?;
    let changed_paths = primary_scope_changed_paths(baseline, &current);
    let framed = format!(
        "maco-primary-worktree-candidate-v1\nassignment={}\nbaseline={baseline:?}\ncurrent={current:?}",
        assignment.id
    );
    let diff_oid = Oid::hash_object(ObjectType::Blob, framed.as_bytes())
        .context("failed to hash primary-worktree candidate binding")?;
    let head = current_head_oid(repo)?.to_string();
    let binding = CandidateValidationBinding {
        version: VALIDATION_BINDING_VERSION,
        agent_id: assignment.id.clone(),
        primary_head: Some(head.clone()),
        agent_head: Some(head.clone()),
        merge_base: Some(head),
        diff_oid: diff_oid.to_string(),
    }
    .canonicalized()
    .context("primary-worktree candidate binding is invalid")?;
    Ok(SupervisorCandidateInspection {
        binding,
        changed_paths,
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

pub(super) fn reject_supervisor_candidate_binding(
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
            "supervisor could not bind the exact candidate reviewed by the parent auditor: {error:#}"
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
        if report.files_changed.is_empty()
            && !report_has_field_guide_suggestions(report)
            && report.licensed_breakage_review.is_none()
        {
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

pub(super) fn supervisor_review_coverage_requirement(
    assignment: &OrchestratorAssignment,
    report: &OrchestratorReviewReport,
) -> ReviewCoverageRequirement {
    ReviewCoverageRequirement {
        worker_ids: required_auditor_prompt_subject_ids(assignment, report),
        paths: required_auditor_review_paths(assignment, report),
    }
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
    observed_changed_paths: Option<&[PathBuf]>,
    report: &mut OrchestratorReviewReport,
) {
    let reported_paths = normalize_paths(report.files_changed.clone());
    let actual_paths = match observed_changed_paths
        .map(|paths| Ok(paths.to_vec()))
        .unwrap_or_else(|| collect_paths_changed_since_base(worktree_path, child_base_head))
    {
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
    if report.role != AgentRole::Worker {
        bail!("worker report role must be worker");
    }
    if assignment.role == AgentRole::Worker
        && assignment.role_category == Some(RoleCategory::NonDelegatingTerminalWorker)
        && report.id == assignment.id
    {
        if report.assigned_paths != assignment.assigned_paths {
            bail!("assigned_paths do not exactly match the declared direct worker assignment");
        }
        if report.semantic_symbols != assignment.semantic_symbols {
            bail!("semantic_symbols do not exactly match the declared direct worker assignment");
        }
        if report.semantic_modules != assignment.semantic_modules {
            bail!("semantic_modules do not exactly match the declared direct worker assignment");
        }
        if report.assignment_kind != AssignmentKind::Ordinary {
            bail!("direct worker assignment_kind must be ordinary");
        }
        report.target_path =
            normalize_report_target_path(report.target_path.take(), "target_path")?;
        if report.target_path.is_some() {
            bail!("direct worker target_path must be null");
        }
        if report.decomposition_completion.is_some() {
            bail!("direct worker must not report decomposition_completion");
        }
        return Ok(());
    }
    let worker = workers_by_id
        .get(report.id.as_str())
        .context("worker is not declared in the assignment")?;
    if report.assigned_paths != worker.assigned_paths {
        bail!("assigned_paths do not exactly match the declared worker assignment");
    }
    if report.semantic_symbols != worker.semantic_symbols {
        bail!("semantic_symbols do not exactly match the declared worker assignment");
    }
    if report.semantic_modules != worker.semantic_modules {
        bail!("semantic_modules do not exactly match the declared worker assignment");
    }
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
    assignment: &OrchestratorAssignment,
    workers_by_id: &BTreeMap<&str, &WorkerAssignment>,
) -> Result<()> {
    if report.bloated_file_flags.len() > MAX_BLOATED_FILE_FLAGS_PER_WORKER {
        bail!(
            "contains {} flags but at most {} are allowed",
            report.bloated_file_flags.len(),
            MAX_BLOATED_FILE_FLAGS_PER_WORKER
        );
    }
    let allowed_paths = if let Some(worker) = workers_by_id.get(report.id.as_str()) {
        worker.assigned_paths.as_slice()
    } else if assignment.role == AgentRole::Worker
        && assignment.role_category == Some(RoleCategory::NonDelegatingTerminalWorker)
        && report.id == assignment.id
    {
        assignment.assigned_paths.as_slice()
    } else {
        bail!("worker is not declared in the assignment");
    };
    let mut normalized = BTreeSet::new();
    for flag in std::mem::take(&mut report.bloated_file_flags) {
        let path = normalize_repo_relative_path(&flag.path)
            .with_context(|| format!("invalid path '{}'", flag.path.display()))?;
        if path.as_os_str().is_empty() {
            bail!("flag path must name a repository file");
        }
        if !allowed_paths
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

pub(super) fn normalize_report_target_path(
    value: Option<PathBuf>,
    field: &str,
) -> Result<Option<PathBuf>> {
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
    let licensed_worker_failures = report
        .licensed_breakage_review
        .as_ref()
        .map(|review| {
            review
                .failures
                .iter()
                .map(|failure| {
                    (
                        failure.validation_name.clone(),
                        failure.failure_signature.clone(),
                    )
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

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
        if let Err(error) = normalize_bloated_file_flags(worker_report, assignment, &workers_by_id)
        {
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
        } else if assignment.role == AgentRole::Worker
            && assignment.role_category == Some(RoleCategory::NonDelegatingTerminalWorker)
            && worker_report.id == assignment.id
        {
            assignment.assigned_paths.clone()
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

        let all_failed_validations_are_licensed = worker_report
            .validation_results
            .iter()
            .filter(|validation| validation_failed(validation))
            .all(|validation| {
                validation.message.as_ref().is_some_and(|signature| {
                    licensed_worker_failures.contains(&(validation.name.clone(), signature.clone()))
                })
            });
        if worker_report.accepted
            && worker_report.status == ReviewStatus::Succeeded
            && worker_report
                .validation_results
                .iter()
                .any(validation_failed)
            && !all_failed_validations_are_licensed
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
