use super::*;

pub(super) fn read_child_report(
    contents: Option<&[u8]>,
    display_path: &Path,
) -> Result<ParsedReport<OrchestratorReviewReport>> {
    let contents =
        contents.context("external run did not capture a descriptor-held child report")?;
    let contents = std::str::from_utf8(contents).with_context(|| {
        format!(
            "descriptor-held child report is not UTF-8: {}",
            display_path.display()
        )
    })?;
    parse_report_json(contents)
        .with_context(|| format!("failed to parse child report {}", display_path.display()))
}

pub(super) fn write_child_report(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    report: &OrchestratorReviewReport,
) -> Result<()> {
    let mut normalized_report = report.clone();
    enforce_orchestrator_environment_failure_outcome(&mut normalized_report);
    write_artifact_json(
        writer,
        relative,
        &normalized_report,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .with_context(|| {
        format!(
            "failed to update normalized child report {}",
            relative.display()
        )
    })
}

pub(super) fn read_auditor_report(
    contents: Option<&[u8]>,
    display_path: &Path,
) -> Result<ParsedReport<AuditorReport>> {
    let contents =
        contents.context("external run did not capture a descriptor-held auditor report")?;
    let contents = std::str::from_utf8(contents).with_context(|| {
        format!(
            "descriptor-held auditor report is not UTF-8: {}",
            display_path.display()
        )
    })?;
    parse_report_json(contents)
        .with_context(|| format!("failed to parse auditor report {}", display_path.display()))
}

pub(super) fn import_worker_execution_journals(
    writer: &mut ArtifactRunWriter,
    assignment: &OrchestratorAssignment,
    incoming_scratch: &ArtifactScratchDirectory,
) -> Result<WorkerExecutionJournalEvidenceSet> {
    let mut journals = WorkerExecutionJournalEvidenceSet::new();
    for worker in &assignment.worker_assignments {
        let incoming_relative_path = worker_execution_journal_incoming_relative(worker);
        let scratch_path = incoming_scratch.path().join(&incoming_relative_path);
        let evidence_relative_path =
            worker_execution_journal_evidence_relative(&assignment.id, &worker.id);
        let status = match read_bounded_regular_file_nofollow(
            &scratch_path,
            MAX_WORKER_EXECUTION_JOURNAL_BYTES,
        ) {
            Ok(bytes) => {
                writer.write_bytes(
                    &evidence_relative_path,
                    &bytes,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
                match parse_worker_execution_journal(&bytes, &evidence_relative_path) {
                    Ok(entries) => WorkerExecutionJournalStatus::Loaded(entries),
                    Err(error) => WorkerExecutionJournalStatus::Invalid(error.to_string()),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                WorkerExecutionJournalStatus::Missing
            }
            Err(error) => WorkerExecutionJournalStatus::Invalid(format!(
                "failed to read incoming worker execution journal {}: {error}",
                incoming_relative_path.display()
            )),
        };
        journals.insert(
            worker.id.clone(),
            WorkerExecutionJournalEvidence {
                incoming_relative_path,
                evidence_relative_path,
                status,
            },
        );
    }
    Ok(journals)
}

fn parse_worker_execution_journal(
    bytes: &[u8],
    display_path: &Path,
) -> Result<Vec<WorkerExecutionJournalEntry>> {
    if bytes.len() > MAX_WORKER_EXECUTION_JOURNAL_BYTES {
        bail!(
            "worker execution journal {} exceeds its configured {} byte limit",
            display_path.display(),
            MAX_WORKER_EXECUTION_JOURNAL_BYTES
        );
    }
    let contents = std::str::from_utf8(bytes).with_context(|| {
        format!(
            "worker execution journal {} is not UTF-8",
            display_path.display()
        )
    })?;
    let mut entries = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line_number = index.saturating_add(1);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut entry: WorkerExecutionJournalEntry =
            serde_json::from_str(trimmed).with_context(|| {
                format!(
                    "failed to parse worker execution journal {} line {}",
                    display_path.display(),
                    line_number
                )
            })?;
        if entry.command.is_empty() {
            bail!(
                "worker execution journal {} line {} omitted command",
                display_path.display(),
                line_number
            );
        }
        if entry.cwd.as_os_str().is_empty() {
            bail!(
                "worker execution journal {} line {} omitted cwd",
                display_path.display(),
                line_number
            );
        }
        if entry.start_timestamp.trim().is_empty() {
            bail!(
                "worker execution journal {} line {} omitted start_timestamp",
                display_path.display(),
                line_number
            );
        }
        if entry.end_timestamp.trim().is_empty() {
            bail!(
                "worker execution journal {} line {} omitted end_timestamp",
                display_path.display(),
                line_number
            );
        }
        entry.changed_paths = normalize_paths(std::mem::take(&mut entry.changed_paths))
            .with_context(|| {
                format!(
                    "worker execution journal {} line {} has invalid changed_paths",
                    display_path.display(),
                    line_number
                )
            })?;
        entries.push(entry);
    }
    Ok(entries)
}

pub(super) fn import_external_attempt_evidence(
    writer: &mut ArtifactRunWriter,
    context: ExternalAttemptEvidenceContext<'_>,
) -> Result<()> {
    let ExternalAttemptEvidenceContext {
        incoming_scratch,
        capture_scratch,
        artifacts,
        external_run,
        external_command,
        raw_report_validated,
        runtime,
    } = context;
    let import_result = (|| -> Result<()> {
        if raw_report_validated {
            if let Some(contents) = external_run.output_last_message() {
                if contents.len() > MAX_SUPERVISOR_REPORT_BYTES {
                    bail!(
                        "descriptor-held external report exceeds its configured {} byte limit",
                        MAX_SUPERVISOR_REPORT_BYTES
                    );
                }
                writer.write_bytes(
                    &artifacts.raw_report_relative,
                    contents,
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
            }
        }
        let stdout_bytes = external_run.stdout_bytes();
        if stdout_bytes.len() > MAX_SUPERVISOR_REPORT_BYTES {
            bail!(
                "descriptor-held external stdout exceeds its configured {} byte limit",
                MAX_SUPERVISOR_REPORT_BYTES
            );
        }
        writer.write_bytes(
            &artifacts.raw_stdout_relative,
            stdout_bytes,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        let command_record = command_record_from_external(external_run, external_command);
        write_artifact_json(
            writer,
            &artifacts.command_record_relative,
            &command_record,
            MAX_SUPERVISOR_REPORT_BYTES,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        Ok(())
    })();

    let discard_result = if external_process_quiescent_for_scratch(external_run, runtime) {
        discard_invocation_scratches(writer, incoming_scratch, capture_scratch)
    } else {
        bail!(
            "refusing to discard invocation artifact scratches without verified process quiescence: {}, {}",
            incoming_scratch.path().display(),
            capture_scratch.path().display()
        )
    };

    match (import_result, discard_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(discard_error)) => Err(error.context(format!(
            "artifact scratch cleanup also failed: {discard_error:#}"
        ))),
    }
}

pub(super) fn create_named_invocation_scratches(
    writer: &mut ArtifactRunWriter,
    incoming_name: &Path,
    capture_name: &Path,
) -> Result<(ArtifactScratchDirectory, ArtifactScratchDirectory)> {
    let incoming = writer.create_scratch_dir(incoming_name)?;
    match writer.create_scratch_dir(capture_name) {
        Ok(capture) => Ok((incoming, capture)),
        Err(error) => {
            writer.discard_scratch(&incoming)?;
            Err(error).context("failed to reserve parent capture scratch")
        }
    }
}

pub(super) fn invocation_scratch_names(
    assignment_index: usize,
    attempt: usize,
    auditor: bool,
    concurrent_mode: bool,
) -> (PathBuf, PathBuf) {
    if !concurrent_mode {
        return (PathBuf::from("incoming"), PathBuf::from("capture"));
    }
    let suffix = if auditor {
        format!("assignment-{assignment_index:04}-auditor")
    } else {
        format!("assignment-{assignment_index:04}-attempt-{attempt:02}")
    };
    (
        PathBuf::from(format!("incoming-{suffix}")),
        PathBuf::from(format!("capture-{suffix}")),
    )
}

pub(super) fn discard_invocation_scratches(
    writer: &mut ArtifactRunWriter,
    incoming: &ArtifactScratchDirectory,
    capture: &ArtifactScratchDirectory,
) -> Result<()> {
    let incoming_result = writer.discard_scratch(incoming);
    let capture_result = writer.discard_scratch(capture);
    match (incoming_result, capture_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(capture_error)) => Err(error.context(format!(
            "capture scratch cleanup also failed: {capture_error:#}"
        ))),
    }
}

fn external_process_quiescent_for_scratch(
    run: &ExternalAgentRun,
    runtime: SupervisorRuntime,
) -> bool {
    match runtime {
        SupervisorRuntime::Codex => run.scratch_quiescence_verified(),
        // Fake mode is an in-process serializer and never launches a child.
        SupervisorRuntime::Fake => true,
    }
}

fn parse_report_json<T>(contents: &str) -> Result<ParsedReport<T>>
where
    T: DeserializeOwned,
{
    if let Ok(report) = serde_json::from_str(contents) {
        return Ok(ParsedReport {
            report,
            recovered: false,
        });
    }

    if let Some(stripped) = strip_surrounding_markdown_fence(contents) {
        if let Ok(report) = serde_json::from_str(stripped) {
            return Ok(ParsedReport {
                report,
                recovered: true,
            });
        }
    }

    if let Some(object) = last_top_level_json_object(contents) {
        if let Ok(report) = serde_json::from_str(object) {
            return Ok(ParsedReport {
                report,
                recovered: true,
            });
        }
    }

    if let Some(stripped) = strip_surrounding_markdown_fence(contents) {
        if let Some(object) = last_top_level_json_object(stripped) {
            if let Ok(report) = serde_json::from_str(object) {
                return Ok(ParsedReport {
                    report,
                    recovered: true,
                });
            }
        }
    }

    Err(anyhow!(
        "report is not valid JSON and lenient JSON extraction failed"
    ))
}

fn strip_surrounding_markdown_fence(contents: &str) -> Option<&str> {
    let trimmed = contents.trim();
    if !trimmed.starts_with("```") || !trimmed.ends_with("```") {
        return None;
    }

    let first_newline = trimmed.find('\n')?;
    let (opening, body_with_closing) = trimmed.split_at(first_newline);
    let info = opening.trim_start_matches("```").trim();
    if !info.is_empty() && info != "json" {
        return None;
    }
    let body_with_closing = body_with_closing.trim_start_matches('\n');
    let closing_start = body_with_closing.rfind("```")?;
    Some(body_with_closing[..closing_start].trim())
}

fn last_top_level_json_object(contents: &str) -> Option<&str> {
    let mut depth = 0usize;
    let mut start = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut last_object = None;

    for (index, character) in contents.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match character {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match character {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(index);
                }
                depth = depth.saturating_add(1);
            }
            '}' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    if let Some(object_start) = start.take() {
                        let object_end = index + character.len_utf8();
                        last_object = contents.get(object_start..object_end);
                    }
                }
            }
            _ => {}
        }
    }

    last_object
}

fn environment_failure_category_name(category: EnvironmentFailureCategory) -> &'static str {
    match category {
        EnvironmentFailureCategory::MissingExecutable => "missing_executable",
        EnvironmentFailureCategory::VersionMismatch => "version_mismatch",
        EnvironmentFailureCategory::MissingCredential => "missing_credential",
        EnvironmentFailureCategory::NetworkForbidden => "network_forbidden",
        EnvironmentFailureCategory::SandboxUnavailable => "sandbox_unavailable",
        EnvironmentFailureCategory::ProbeFailed => "probe_failed",
    }
}

fn environment_failure_categories(failures: &[EnvironmentFailure]) -> String {
    failures
        .iter()
        .map(|failure| environment_failure_category_name(failure.category))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ")
}

fn sanitize_environment_failure(mut failure: EnvironmentFailure) -> EnvironmentFailure {
    failure.summary = format!(
        "environment preflight reported {}",
        environment_failure_category_name(failure.category)
    );
    failure.remediation = match failure.category {
        EnvironmentFailureCategory::MissingExecutable
        | EnvironmentFailureCategory::VersionMismatch => vec![
            EnvironmentRemediation {
                scope: EnvironmentRemediationScope::ProjectLocal,
                guidance:
                    "declare the required toolchain in the project environment and rerun preflight"
                        .to_string(),
            },
            EnvironmentRemediation {
                scope: EnvironmentRemediationScope::PersistentNixosHostSoftware,
                guidance:
                    "request persistent host software through the declarative NixOS workflow"
                        .to_string(),
            },
        ],
        EnvironmentFailureCategory::MissingCredential => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::CredentialConfiguration,
            guidance:
                "configure the named credential or configuration through an approved secret source; do not put secret values in the plan"
                    .to_string(),
        }],
        EnvironmentFailureCategory::NetworkForbidden => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::CapabilityPolicy,
            guidance:
                "revise the assignment for offline execution or request an explicit policy change; do not enable networking automatically"
                    .to_string(),
        }],
        EnvironmentFailureCategory::SandboxUnavailable => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::CapabilityPolicy,
            guidance:
                "restore the verified confinement capability before rerunning; do not broaden the sandbox automatically"
                    .to_string(),
        }],
        EnvironmentFailureCategory::ProbeFailed => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::ProjectLocal,
            guidance:
                "inspect the fixed preflight probe evidence and correct the project or host environment before rerunning"
                    .to_string(),
        }],
    };
    failure
}

fn sanitized_environment_failures(
    failures: impl IntoIterator<Item = EnvironmentFailure>,
) -> Vec<EnvironmentFailure> {
    let mut sanitized = Vec::new();
    append_unique_environment_failures(
        &mut sanitized,
        failures.into_iter().map(sanitize_environment_failure),
    );
    sanitized
}

fn append_unique_environment_failures(
    destination: &mut Vec<EnvironmentFailure>,
    failures: impl IntoIterator<Item = EnvironmentFailure>,
) {
    for failure in failures {
        if !destination.contains(&failure) {
            destination.push(failure);
        }
    }
}

fn normalize_command_environment_failures(record: &mut CommandRunRecord) {
    record.environment_failures =
        sanitized_environment_failures(std::mem::take(&mut record.environment_failures));
    if !record.environment_failures.is_empty() {
        record.status = ReviewStatus::Failed;
    }
}

fn normalize_command_records_environment_failures(
    records: &mut [CommandRunRecord],
) -> Vec<EnvironmentFailure> {
    let mut failures = Vec::new();
    for record in records {
        normalize_command_environment_failures(record);
        append_unique_environment_failures(&mut failures, record.environment_failures.clone());
    }
    failures
}

fn enforce_worker_environment_failure_outcome(report: &mut WorkerReport) {
    let command_failures = normalize_command_records_environment_failures(&mut report.commands_run);
    report.environment_failures =
        sanitized_environment_failures(std::mem::take(&mut report.environment_failures));
    append_unique_environment_failures(&mut report.environment_failures, command_failures);
    if !report.environment_failures.is_empty() {
        report.accepted = false;
        report.rejected = true;
        report.status = ReviewStatus::Failed;
    }
}

pub(super) fn enforce_auditor_environment_failure_outcome(report: &mut AuditorReport) {
    let command_failures = normalize_command_records_environment_failures(&mut report.commands_run);
    report.environment_failures =
        sanitized_environment_failures(std::mem::take(&mut report.environment_failures));
    append_unique_environment_failures(&mut report.environment_failures, command_failures);
    if !report.environment_failures.is_empty() {
        report.accepted = false;
        report.rejected = true;
        report.status = ReviewStatus::Failed;
    }
}

pub(super) fn enforce_orchestrator_environment_failure_outcome(report: &mut OrchestratorReviewReport) {
    let command_failures = normalize_command_records_environment_failures(&mut report.commands_run);
    report.environment_failures =
        sanitized_environment_failures(std::mem::take(&mut report.environment_failures));
    append_unique_environment_failures(&mut report.environment_failures, command_failures);
    for worker in &mut report.worker_reports {
        enforce_worker_environment_failure_outcome(worker);
    }
    for auditor in &mut report.audit_reports {
        enforce_auditor_environment_failure_outcome(auditor);
    }
    let nested_failures = report
        .worker_reports
        .iter()
        .flat_map(|worker| worker.environment_failures.iter())
        .chain(
            report
                .audit_reports
                .iter()
                .flat_map(|auditor| auditor.environment_failures.iter()),
        )
        .cloned()
        .collect::<Vec<_>>();
    append_unique_environment_failures(&mut report.environment_failures, nested_failures);
    if !report.environment_failures.is_empty() {
        report.accepted = false;
        report.rejected = true;
        report.status = ReviewStatus::Failed;
    }
}

pub(super) fn enforce_supervisor_final_environment_failure_outcome(report: &mut SupervisorFinalReport) {
    let command_failures = normalize_command_records_environment_failures(&mut report.commands_run);
    for child in &mut report.orchestrator_reports {
        enforce_orchestrator_environment_failure_outcome(child);
    }
    let mut failures =
        sanitized_environment_failures(std::mem::take(&mut report.environment_failures));
    append_unique_environment_failures(&mut failures, command_failures);
    append_unique_environment_failures(
        &mut failures,
        aggregate_environment_failures(&report.commands_run, &report.orchestrator_reports),
    );
    report.environment_failures = failures;
    if !report.environment_failures.is_empty() {
        report.publishable = false;
        report.success = false;
        report.accepted = false;
        report.rejected = true;
        report.status = ReviewStatus::Failed;
    }
}

pub(super) fn environment_blocked_child_report(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    report_path: &Path,
    external_run: &ExternalAgentRun,
    external_command: &ExternalAgentCommand,
) -> OrchestratorReviewReport {
    let failures = sanitized_environment_failures(external_run.environment_failures().to_vec());
    let categories = environment_failure_categories(&failures);
    let worker_reports = assignment
        .worker_assignments
        .iter()
        .map(|worker| {
            let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
            WorkerReport {
                id: worker.id.clone(),
                role: AgentRole::Worker,
                assignment_kind: metadata.kind,
                target_path: metadata.target_path,
                assigned_paths: worker.assigned_paths.clone(),
                semantic_symbols: worker.semantic_symbols.clone(),
                semantic_modules: worker.semantic_modules.clone(),
                claim_token: None,
                semantic_intent_token: None,
                commands_run: Vec::new(),
                environment_failures: failures.clone(),
                files_changed: Vec::new(),
                validation_results: Vec::new(),
                findings: vec![Finding {
                    severity: FindingSeverity::Error,
                    message: format!(
                        "worker was not launched because parent-observed environment preflight blocked the assignment: {categories}"
                    ),
                    paths: vec![report_path.to_path_buf()],
                }],
                field_guide_entries: Vec::new(),
                bloated_file_flags: Vec::new(),
                decomposition_completion: None,
                no_further_delegation: Some(true),
                accepted: false,
                rejected: true,
                status: ReviewStatus::Failed,
                remaining_risk: "declared environment requirements were not satisfied".to_string(),
                next_safe_action:
                    "apply the structured environment remediation without broadening confinement, then rerun the assignment"
                        .to_string(),
            }
        })
        .collect();
    OrchestratorReviewReport {
        id: assignment.id.clone(),
        role: AgentRole::ChildOrchestrator,
        assigned_paths: assignment.assigned_paths.clone(),
        semantic_symbols: assignment.semantic_symbols.clone(),
        semantic_modules: assignment.semantic_modules.clone(),
        claim_token: None,
        semantic_intent_token: None,
        commands_run: vec![command_record_from_external(external_run, external_command)],
        environment_failures: failures,
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "parent-observed environment preflight blocked the child assignment before launch: {categories}"
            ),
            paths: vec![report_path.to_path_buf()],
        }],
        field_guide_entries: Vec::new(),
        worker_reports,
        audit_reports: Vec::new(),
        decomposition_completions: Vec::new(),
        gate_denials: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        accepted: false,
        rejected: true,
        status: ReviewStatus::Failed,
        remaining_risk: "declared environment requirements were not satisfied".to_string(),
        next_safe_action:
            "apply the structured environment remediation without broadening confinement, then rerun the assignment"
                .to_string(),
    }
}

pub(super) fn missing_child_report(
    assignment: &OrchestratorAssignment,
    report_path: &Path,
    external_run: &ExternalAgentRun,
    external_command: &ExternalAgentCommand,
    error: String,
) -> OrchestratorReviewReport {
    OrchestratorReviewReport {
        id: assignment.id.clone(),
        role: AgentRole::ChildOrchestrator,
        assigned_paths: assignment.assigned_paths.clone(),
        semantic_symbols: assignment.semantic_symbols.clone(),
        semantic_modules: assignment.semantic_modules.clone(),
        claim_token: None,
        semantic_intent_token: None,
        commands_run: vec![command_record_from_external(external_run, external_command)],
        environment_failures: sanitized_environment_failures(
            external_run.environment_failures().to_vec(),
        ),
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!("required child report is missing or invalid: {error}"),
            paths: vec![report_path.to_path_buf()],
        }],
        field_guide_entries: Vec::new(),
        worker_reports: Vec::new(),
        audit_reports: Vec::new(),
        decomposition_completions: Vec::new(),
        gate_denials: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        accepted: false,
        rejected: true,
        status: ReviewStatus::Missing,
        remaining_risk: "child orchestrator did not produce a usable report".to_string(),
        next_safe_action: "inspect child logs and rerun the failed assignment".to_string(),
    }
}

pub(super) fn missing_parent_auditor_report(
    expected_id: &str,
    report_path: &Path,
    external_run: &ExternalAgentRun,
    error: anyhow::Error,
) -> AuditorReport {
    AuditorReport {
        id: expected_id.to_string(),
        role: AgentRole::Auditor,
        reviewed_worker_ids: Vec::new(),
        reviewed_paths: Vec::new(),
        commands_run: Vec::new(),
        environment_failures: sanitized_environment_failures(
            external_run.environment_failures().to_vec(),
        ),
        validation_results: Vec::new(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "required parent-launched auditor report is missing or invalid: {error}"
            ),
            paths: vec![report_path.to_path_buf()],
        }],
        no_further_delegation: Some(true),
        read_only: true,
        accepted: false,
        rejected: true,
        status: ReviewStatus::Missing,
        remaining_risk: "parent-launched review auditor did not produce a usable report"
            .to_string(),
        next_safe_action: "inspect auditor logs and rerun the child scope".to_string(),
    }
}

pub(super) fn report_failed<T: ReportStatus>(report: &T) -> bool {
    !report.accepted() || report.rejected() || report.status() != ReviewStatus::Succeeded
}

pub(super) fn accepted_bloated_file_flags(reports: &[OrchestratorReviewReport]) -> Vec<BloatedFileFlag> {
    reports
        .iter()
        .filter(|report| !report_failed(*report))
        .flat_map(|report| report.worker_reports.iter())
        .filter(|report| !report_failed(*report))
        .flat_map(|report| report.bloated_file_flags.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn accepted_decomposition_candidates(
    reports: &[OrchestratorReviewReport],
) -> Vec<DecompositionCompletion> {
    reports
        .iter()
        .filter(|report| !report_failed(*report))
        .flat_map(|report| report.decomposition_completions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn accepted_field_guide_drafts(
    plan: &SupervisorPlan,
    reports: &[OrchestratorReviewReport],
) -> Result<Vec<AcceptedFieldGuideDraft>> {
    let mut drafts = Vec::new();
    let mut aggregate_bytes = 0_usize;
    for assignment in &plan.assignments {
        let Some(report) = reports.iter().find(|report| report.id == assignment.id) else {
            continue;
        };
        if report_failed(report) {
            continue;
        }
        let parent_auditor_id = parent_auditor_id(assignment);
        let parent_audited = report.audit_reports.iter().any(|auditor| {
            auditor.id == parent_auditor_id
                && !report_failed(auditor)
                && auditor.role == AgentRole::Auditor
                && auditor.read_only
                && auditor.no_further_delegation == Some(true)
        });
        if report_has_field_guide_suggestions(report) && !parent_audited {
            bail!(
                "accepted child '{}' has field-guide suggestions without an accepted parent audit",
                report.id
            );
        }
        for suggestion in &report.field_guide_entries {
            push_accepted_field_guide_draft(
                &mut drafts,
                &mut aggregate_bytes,
                &report.id,
                "child_orchestrator",
                suggestion,
            )?;
        }
        for worker_assignment in &assignment.worker_assignments {
            let Some(worker_report) = report
                .worker_reports
                .iter()
                .find(|worker| worker.id == worker_assignment.id)
            else {
                continue;
            };
            if report_failed(worker_report) {
                continue;
            }
            for suggestion in &worker_report.field_guide_entries {
                push_accepted_field_guide_draft(
                    &mut drafts,
                    &mut aggregate_bytes,
                    &worker_report.id,
                    "worker",
                    suggestion,
                )?;
            }
        }
    }
    Ok(drafts)
}

fn push_accepted_field_guide_draft(
    drafts: &mut Vec<AcceptedFieldGuideDraft>,
    aggregate_bytes: &mut usize,
    source_node: &str,
    source_role: &'static str,
    suggestion: &FieldGuideEntrySuggestion,
) -> Result<()> {
    if drafts.len() >= MAX_FIELD_GUIDE_ENTRIES_PER_RUN {
        bail!(
            "accepted field-guide suggestions exceed the {} item run bound",
            MAX_FIELD_GUIDE_ENTRIES_PER_RUN
        );
    }
    let suggestion_bytes = suggestion
        .finding
        .len()
        .checked_add(suggestion.context.len())
        .context("accepted field-guide suggestion byte count overflowed")?;
    let next_aggregate = aggregate_bytes
        .checked_add(suggestion_bytes)
        .context("accepted field-guide aggregate byte count overflowed")?;
    if next_aggregate > MAX_FIELD_GUIDE_RUN_BYTES {
        bail!(
            "accepted field-guide suggestions exceed the {} byte run bound",
            MAX_FIELD_GUIDE_RUN_BYTES
        );
    }
    let draft = FieldGuideDraft::new(suggestion.finding.clone(), suggestion.context.clone())
        .context("accepted field-guide suggestion failed store validation")?;
    drafts.push(AcceptedFieldGuideDraft {
        source_node: source_node.to_string(),
        source_role,
        finding_bytes: suggestion.finding.len(),
        context_bytes: suggestion.context.len(),
        draft,
    });
    *aggregate_bytes = next_aggregate;
    Ok(())
}

pub(super) fn append_accepted_field_guide_drafts(
    plan: &SupervisorPlan,
    reports: &[OrchestratorReviewReport],
    run_id: &RunId,
    store: Option<&FieldGuideStore>,
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
) -> Result<usize> {
    let drafts = accepted_field_guide_drafts(plan, reports)?;
    if drafts.is_empty() {
        return Ok(0);
    }
    let store = store.context("authenticated field-guide store was not initialized")?;
    let date = trusted_parent_utc_date(SystemTime::now())?;
    let provenance = ParentFieldGuideProvenance::new(date, run_id.as_str())
        .context("failed to construct trusted field-guide provenance")?;
    let total_count = drafts.len();
    let mut appended = 0_usize;
    for (ordinal, accepted) in drafts.into_iter().enumerate() {
        record_field_guide_event_strict(
            journal,
            writer,
            run_id.as_str(),
            None,
            OrchestrationRole::Supervisor,
            json!({
                "field_guide_event_kind": FieldGuideEventKind::AppendMutation,
                "phase": "planned",
                "ordinal": ordinal,
                "batch_entry_count": total_count,
                "source_role": accepted.source_role,
                "source_node": accepted.source_node,
                "provenance_date": provenance.date(),
                "provenance_source_run": provenance.source_run(),
                "finding_bytes": accepted.finding_bytes,
                "context_bytes": accepted.context_bytes,
            }),
        )?;
        let result = store
            .append(accepted.draft, provenance.clone())
            .context("authenticated field-guide append failed after planned evidence")?;
        record_field_guide_event_strict(
            journal,
            writer,
            run_id.as_str(),
            None,
            OrchestrationRole::Supervisor,
            json!({
                "field_guide_event_kind": FieldGuideEventKind::AppendMutation,
                "phase": "committed",
                "ordinal": ordinal,
                "sequence": result.sequence(),
                "retained": result.retained(),
                "retained_entry_count": result.snapshot().entries().len(),
                "evicted_entry_count": result.evicted_entries(),
            }),
        )?;
        record_field_guide_event_strict(
            journal,
            writer,
            run_id.as_str(),
            None,
            OrchestrationRole::Supervisor,
            json!({
                "field_guide_event_kind": FieldGuideEventKind::DeterministicCuration,
                "phase": "committed",
                "ordinal": ordinal,
                "evicted_entry_count": result.evicted_entries(),
                "retained_entry_count": result.snapshot().entries().len(),
                "line_budget": result.snapshot().line_budget(),
            }),
        )?;
        appended = appended.saturating_add(1);
    }
    Ok(appended)
}

fn trusted_parent_utc_date(timestamp: SystemTime) -> Result<String> {
    let elapsed = timestamp
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    let days = i64::try_from(elapsed.as_secs() / 86_400)
        .context("system clock is outside the supported field-guide date range")?;
    let shifted_days = days
        .checked_add(719_468)
        .context("field-guide date calculation overflowed")?;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days
            .checked_sub(146_096)
            .context("field-guide date calculation overflowed")?
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = month_position + if month_position < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(0..=9_999).contains(&year) {
        bail!("system clock is outside the supported field-guide date range");
    }
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

pub(super) fn deterministic_fake_child_run(
    command: &ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
    claim_token: u64,
    semantic_intent_token: Option<u64>,
) -> Result<ExternalAgentRun> {
    if command.model.is_some() {
        bail!("deterministic fake child command retained a provider model slug");
    }
    write_deterministic_fake_worker_journals(command, assignment)?;
    let worker_reports = assignment
        .worker_assignments
        .iter()
        .map(|worker| {
            let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
            WorkerReport {
                id: worker.id.clone(),
                role: AgentRole::Worker,
                assignment_kind: metadata.kind,
                target_path: metadata.target_path.clone(),
                assigned_paths: worker.assigned_paths.clone(),
                semantic_symbols: worker.semantic_symbols.clone(),
                semantic_modules: worker.semantic_modules.clone(),
                claim_token: None,
                semantic_intent_token: None,
                commands_run: Vec::new(),
                environment_failures: Vec::new(),
                files_changed: Vec::new(),
                validation_results: vec![ValidationResult {
                    name: "deterministic fake worker validation".to_string(),
                    status: ReviewStatus::Succeeded,
                    command: Vec::new(),
                    message: None,
                }],
                findings: Vec::new(),
                field_guide_entries: Vec::new(),
                bloated_file_flags: Vec::new(),
                decomposition_completion: metadata.target_path.map(|target_path| {
                    DecompositionCompletion {
                        target_path,
                        replacement_paths: Vec::new(),
                        supervisor_candidate_binding: None,
                    }
                }),
                no_further_delegation: Some(true),
                accepted: true,
                rejected: false,
                status: ReviewStatus::Succeeded,
                remaining_risk: "simulation-only evidence".to_string(),
                next_safe_action: "rerun with the verified Codex runtime".to_string(),
            }
        })
        .collect::<Vec<_>>();
    let decomposition_completions = worker_reports
        .iter()
        .filter_map(|report| report.decomposition_completion.clone())
        .collect();
    let report = OrchestratorReviewReport {
        id: assignment.id.clone(),
        role: AgentRole::ChildOrchestrator,
        assigned_paths: assignment.assigned_paths.clone(),
        semantic_symbols: assignment.semantic_symbols.clone(),
        semantic_modules: assignment.semantic_modules.clone(),
        claim_token: Some(claim_token),
        semantic_intent_token,
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        files_changed: Vec::new(),
        validation_results: vec![ValidationResult {
            name: "deterministic fake child validation".to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: None,
        }],
        findings: Vec::new(),
        field_guide_entries: Vec::new(),
        worker_reports,
        audit_reports: Vec::new(),
        decomposition_completions,
        gate_denials: Vec::new(),
        gate_correction_outcomes: Vec::new(),
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "simulation-only evidence".to_string(),
        next_safe_action: "rerun with the verified Codex runtime".to_string(),
    };
    let mut output = serde_json::to_vec_pretty(&report)?;
    output.push(b'\n');
    Ok(deterministic_fake_run(command, output))
}

fn write_deterministic_fake_worker_journals(
    command: &ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
) -> Result<()> {
    let incoming_path = command
        .output_last_message
        .parent()
        .context("deterministic fake child report path has no parent directory")?;
    let journal_root = incoming_path.join("worker-journals");
    fs::create_dir_all(&journal_root).with_context(|| {
        format!(
            "failed to create deterministic fake worker journal directory {}",
            journal_root.display()
        )
    })?;
    for worker in &assignment.worker_assignments {
        let journal_path = journal_root.join(worker_execution_journal_file_name(&worker.id));
        fs::write(&journal_path, b"").with_context(|| {
            format!(
                "failed to write deterministic fake worker execution journal {}",
                journal_path.display()
            )
        })?;
    }
    Ok(())
}

pub(super) fn deterministic_fake_auditor_run(
    command: &ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
    child_report: &OrchestratorReviewReport,
) -> Result<ExternalAgentRun> {
    if command.model.is_some() {
        bail!("deterministic fake auditor command retained a provider model slug");
    }
    let report = AuditorReport {
        id: parent_auditor_id(assignment),
        role: AgentRole::Auditor,
        reviewed_worker_ids: required_auditor_prompt_subject_ids(assignment, child_report),
        reviewed_paths: required_auditor_review_paths(assignment, child_report),
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        validation_results: vec![ValidationResult {
            name: "deterministic fake auditor validation".to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: None,
        }],
        findings: Vec::new(),
        no_further_delegation: Some(true),
        read_only: true,
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "simulation-only evidence".to_string(),
        next_safe_action: "rerun with the verified Codex runtime".to_string(),
    };
    let mut output = serde_json::to_vec_pretty(&report)?;
    output.push(b'\n');
    Ok(deterministic_fake_run(command, output))
}

fn deterministic_fake_run(command: &ExternalAgentCommand, output: Vec<u8>) -> ExternalAgentRun {
    ExternalAgentRun {
        command: vec!["maco-internal-deterministic-fake".to_string()],
        cwd: command.cwd.clone(),
        timeout_seconds: command.timeout.as_secs(),
        exit_code: Some(0),
        duration_ms: 0,
        timed_out: false,
        process_tree: None,
        side_effects: None,
        publishable: false,
        program_trust: ExternalProgramTrust::ExplicitCustom,
        codex_permissions: None,
        stdout: crate::external_agent::CapturedOutput::default(),
        stderr: crate::external_agent::CapturedOutput::default(),
        error: None,
        output_last_message: Some(output),
    }
}

pub(super) fn external_safety_verified(run: &ExternalAgentRun, runtime: SupervisorRuntime) -> bool {
    match runtime {
        SupervisorRuntime::Codex => {
            run.process_tree
                .is_some_and(ProcessTreeEvidence::is_verified_empty)
                && run
                    .side_effects
                    .is_some_and(SideEffectConfinementEvidence::is_verified)
                && run.program_trust == ExternalProgramTrust::TrustedSystemCodex
                && run.codex_permissions.is_some()
        }
        SupervisorRuntime::Fake => {
            run.simulation_succeeded() && run.program_trust == ExternalProgramTrust::ExplicitCustom
        }
    }
}

pub(super) fn external_containment_verified(run: &ExternalAgentRun, runtime: SupervisorRuntime) -> bool {
    if run.environment_blocked() {
        run.environment_preflight_quiescence_verified()
    } else {
        external_safety_verified(run, runtime)
    }
}

pub(super) fn external_process_completed(run: &ExternalAgentRun) -> bool {
    run.succeeded()
        || (run.simulation_succeeded() && run.program_trust == ExternalProgramTrust::ExplicitCustom)
}

pub(super) fn complete_external_codex_usage(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
) -> Option<Usage> {
    const MAX_USAGE_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
    match read_bounded_regular_file_nofollow(&command.json_log, MAX_USAGE_CAPTURE_BYTES) {
        Ok(bytes) if bytes.len() < MAX_USAGE_CAPTURE_BYTES => {
            codex_usage_from_jsonl(&bytes).ok().flatten()
        }
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !run.stdout.truncated => {
            codex_usage_from_jsonl(run.stdout_bytes()).ok().flatten()
        }
        Err(_) => None,
    }
}

pub(super) fn role_usage_report(
    plan: &SupervisorPlan,
    samples: Vec<RoleUsageSample>,
) -> Result<RoleUsageAggregation> {
    let mut aggregates = BTreeMap::<AgentRole, (Usage, BTreeSet<String>, Option<f64>)>::new();
    let mut total_usage = Usage::default();
    let mut total_cost_usd = Some(0.0);
    for sample in samples {
        if !matches!(
            sample.role,
            AgentRole::ChildOrchestrator | AgentRole::GateClassifier | AgentRole::Auditor
        ) {
            bail!(
                "{} usage is not directly process-observable",
                sample.role.as_str()
            );
        }
        total_usage = total_usage.saturating_add(sample.usage);
        let sample_cost_usd = sample
            .model
            .as_ref()
            .and_then(|model| plan.model_pricing.get(model))
            .map(|pricing| pricing.cost_usd(sample.usage))
            .filter(|cost| cost.is_finite());
        total_cost_usd = match (total_cost_usd, sample_cost_usd) {
            (Some(total), Some(cost)) => {
                let total = total + cost;
                total.is_finite().then_some(total)
            }
            _ => None,
        };
        let aggregate = aggregates
            .entry(sample.role)
            .or_insert_with(|| (Usage::default(), BTreeSet::new(), Some(0.0)));
        aggregate.0 = aggregate.0.saturating_add(sample.usage);
        if let Some(model) = sample.model {
            aggregate.1.insert(model);
        }
        aggregate.2 = match (aggregate.2, sample_cost_usd) {
            (Some(total), Some(cost)) => {
                let total = total + cost;
                total.is_finite().then_some(total)
            }
            _ => None,
        };
    }
    let has_observed_samples = !aggregates.is_empty();
    let reports = aggregates
        .into_iter()
        .map(|(role, (usage, models, cost_usd))| {
            (
                role,
                RoleUsageReport {
                    models: models.into_iter().collect(),
                    usage: Some(usage),
                    cost_usd,
                    observation: RoleUsageObservation::ProcessObserved,
                    unavailable_reason: None,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut reports = reports;
    reports.insert(
        AgentRole::Worker,
        RoleUsageReport {
            models: Vec::new(),
            usage: None,
            cost_usd: None,
            observation: RoleUsageObservation::NotProcessObservable,
            unavailable_reason: Some(
                "nested workers execute inside child Codex sessions and are not separate MACO-launched processes; runtime-side role-tagged usage reporting is required before worker usage or cost can be reported"
                    .to_string(),
            ),
        },
    );
    reports
        .entry(AgentRole::GateClassifier)
        .or_insert_with(|| RoleUsageReport {
            models: Vec::new(),
            usage: None,
            cost_usd: None,
            observation: RoleUsageObservation::NotProcessObservable,
            unavailable_reason: Some(
                "the current pre-action gate classifier is a deterministic local broker with no \
                 role-tagged provider invocation; usage and cost remain unavailable until a \
                 genuine runtime-side gate_classifier sample exists"
                    .to_string(),
            ),
        });
    if !has_observed_samples {
        total_cost_usd = None;
    }
    let total_usage = has_observed_samples.then_some(total_usage);
    reports.insert(
        AgentRole::Supervisor,
        RoleUsageReport {
            models: reports
                .values()
                .flat_map(|report| report.models.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            usage: total_usage,
            cost_usd: total_cost_usd,
            observation: RoleUsageObservation::SupervisorAggregate,
            unavailable_reason: total_usage.is_none().then(|| {
                "no MACO-launched child-orchestrator or auditor process usage was observed"
                    .to_string()
            }),
        },
    );
    Ok(RoleUsageAggregation {
        reports,
        total_usage,
        total_cost_usd,
    })
}

pub(super) fn finalize_supervisor_cost(
    usage_complete: bool,
    role_usage: &mut BTreeMap<AgentRole, RoleUsageReport>,
    observed_total_cost_usd: Option<f64>,
) -> Option<f64> {
    if usage_complete {
        return observed_total_cost_usd;
    }
    if let Some(supervisor_usage) = role_usage.get_mut(&AgentRole::Supervisor) {
        supervisor_usage.cost_usd = None;
        supervisor_usage.unavailable_reason = Some(
            "supervisor aggregate cost is unavailable because at least one MACO-launched process usage sample is missing, incomplete, or unreliable"
                .to_string(),
        );
    }
    None
}

pub(super) fn command_record_from_external(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
) -> CommandRunRecord {
    CommandRunRecord {
        command: serializable_external_command(&run.command, command),
        cwd: PathBuf::from("<child-worktree>"),
        exit_code: run.exit_code,
        status: if external_process_completed(run) {
            ReviewStatus::Succeeded
        } else {
            ReviewStatus::Failed
        },
        timeout_seconds: run.timeout_seconds,
        duration_ms: run.duration_ms,
        timed_out: run.timed_out,
        stdout: run.stdout.text.clone(),
        stderr: run.stderr.text.clone(),
        sandbox_denials: sandbox_denials_for_report(run.sandbox_denials()),
        environment_preflight_results: run.environment_preflight_results().to_vec(),
        environment_failures: sanitized_environment_failures(run.environment_failures().to_vec()),
        error: run.error.clone(),
    }
}

fn sandbox_denials_for_report(denials: &[SandboxDenialEvidence]) -> Vec<SandboxDenialEvidence> {
    denials
        .iter()
        .cloned()
        .map(|mut denial| {
            if let Some(path) = denial.path.take() {
                denial.path = normalize_repo_relative_path(&path)
                    .ok()
                    .filter(|normalized| normalized == &path);
            }
            denial
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn aggregate_sandbox_denials(command_records: &[CommandRunRecord]) -> Vec<SandboxDenialEvidence> {
    command_records
        .iter()
        .flat_map(|record| record.sandbox_denials.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn aggregate_environment_failures(
    command_records: &[CommandRunRecord],
    reports: &[OrchestratorReviewReport],
) -> Vec<EnvironmentFailure> {
    let failures = command_records
        .iter()
        .flat_map(|record| record.environment_failures.iter())
        .chain(
            reports
                .iter()
                .flat_map(|report| report.environment_failures.iter()),
        )
        .chain(
            reports
                .iter()
                .flat_map(|report| report.commands_run.iter())
                .flat_map(|record| record.environment_failures.iter()),
        )
        .chain(
            reports
                .iter()
                .flat_map(|report| report.worker_reports.iter())
                .flat_map(|report| report.environment_failures.iter()),
        )
        .chain(
            reports
                .iter()
                .flat_map(|report| report.worker_reports.iter())
                .flat_map(|report| report.commands_run.iter())
                .flat_map(|record| record.environment_failures.iter()),
        )
        .chain(
            reports
                .iter()
                .flat_map(|report| report.audit_reports.iter())
                .flat_map(|report| report.environment_failures.iter()),
        )
        .chain(
            reports
                .iter()
                .flat_map(|report| report.audit_reports.iter())
                .flat_map(|report| report.commands_run.iter())
                .flat_map(|record| record.environment_failures.iter()),
        )
        .cloned()
        .collect::<Vec<_>>();
    sanitized_environment_failures(failures)
}

fn serializable_external_command(
    rendered: &[String],
    command: &ExternalAgentCommand,
) -> Vec<String> {
    let path_replacements = [
        (&command.program, "<codex-executable>"),
        (&command.cwd, "<child-worktree>"),
        (&command.output_last_message, "<incoming-report>"),
        (&command.json_log, "<parent-capture>"),
        (&command.prompt, "<supervisor-prompt>"),
    ]
    .into_iter()
    .chain(
        command
            .output_schema
            .iter()
            .map(|path| (path, "<report-schema>")),
    )
    .map(|(path, replacement)| (path.display().to_string(), replacement.to_string()))
    .collect::<BTreeMap<_, _>>();
    rendered
        .iter()
        .map(|argument| {
            path_replacements
                .get(argument)
                .cloned()
                .unwrap_or_else(|| argument.clone())
        })
        .collect()
}
