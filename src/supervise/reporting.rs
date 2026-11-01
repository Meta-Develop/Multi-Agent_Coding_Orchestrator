use super::*;

#[cfg(all(test, unix))]
#[path = "claude_identity_tests.rs"]
mod claude_identity_tests;

#[path = "journal_observation.rs"]
mod journal_observation;
#[cfg(test)]
pub(crate) use journal_observation::run_worker_execution_journal_command;
pub(crate) use journal_observation::run_worker_execution_journal_command_with_clock;
pub(super) use journal_observation::validate_worker_journal_observations;

pub(super) const MAX_ENVIRONMENT_FAILURE_DIAGNOSTIC_CHARS: usize = 1024;
pub(super) const ENVIRONMENT_FAILURE_DIAGNOSTIC_TRUNCATION_MARKER: &str = "…<truncated>";

pub(super) fn render_supervisor_operator_summary(report: &SupervisorFinalReport) -> String {
    let mut lines = vec![
        format!("# Supervise run {}", report.run_id.as_str()),
        String::new(),
        format!("- Status: {}", review_status_label(report.status)),
        format!("- Success: {}", report.success),
        format!("- Accepted: {}", report.accepted),
        format!("- Rejected: {}", report.rejected),
        format!("- Lifecycle: {}", lifecycle_label(report.run_lifecycle)),
        String::new(),
        "## Assignments".to_string(),
        String::new(),
    ];
    if let Some(budget) = &report.run_budget {
        let pricing = budget.pricing_contract.as_ref().map_or_else(
            || "No operator pricing contract is bound".to_string(),
            |provenance| {
                format!(
                    "Retained operator contract for estimates: {} revision {} ({} through {}; binding {})",
                    provenance.contract.contract_id,
                    provenance.contract.revision,
                    provenance.contract.effective_date,
                    provenance.contract.valid_through,
                    provenance.normalized_sha256
                )
            },
        );
        lines.insert(7, format!("- Pricing: {pricing}"));
        lines.insert(
            8,
            format!("- Priced-cost complete: {}", budget.cost_complete),
        );
    }
    if report.orchestrator_reports.is_empty() {
        lines.push("No assignment reports were persisted.".to_string());
    } else {
        for child in &report.orchestrator_reports {
            lines.push(format!(
                "- `{}`: {} (accepted={}, rejected={})",
                child.id,
                review_status_label(child.status),
                child.accepted,
                child.rejected
            ));
            if !child.next_safe_action.is_empty() {
                lines.push(format!("  next: {}", child.next_safe_action));
            }
        }
    }
    if !report.environment_failures.is_empty() || !report.gate_denials.is_empty() {
        lines.push(String::new());
        lines.push("## Failures".to_string());
        lines.push(String::new());
        for failure in &report.environment_failures {
            let failure = sanitize_environment_failure(failure.clone());
            lines.push(format!("- environment: {}", failure.summary));
        }
        for denial in &report.gate_denials {
            lines.push(format!("- gate: {}", denial.denial_id.as_str()));
        }
    }
    lines.push(String::new());
    lines.push("## Remaining risk".to_string());
    lines.push(String::new());
    lines.push(report.remaining_risk.clone());
    lines.push(String::new());
    lines.push("## Next safe action".to_string());
    lines.push(String::new());
    lines.push(report.next_safe_action.clone());
    lines.push(String::new());
    lines.join("\n")
}

fn review_status_label(status: ReviewStatus) -> &'static str {
    match status {
        ReviewStatus::Pending => "pending",
        ReviewStatus::Succeeded => "succeeded",
        ReviewStatus::Failed => "failed",
        ReviewStatus::Rejected => "rejected",
        ReviewStatus::Missing => "missing",
    }
}

fn lifecycle_label(lifecycle: SupervisorRunLifecycle) -> &'static str {
    match lifecycle {
        SupervisorRunLifecycle::Active => "active",
        SupervisorRunLifecycle::Interrupted => "interrupted",
        SupervisorRunLifecycle::Uncertain => "uncertain",
        SupervisorRunLifecycle::Resumable => "resumable",
        SupervisorRunLifecycle::Finalized => "finalized",
    }
}

pub(super) fn apply_execution_target_reporting(
    report: &mut SupervisorFinalReport,
    execution_target: Option<&SupervisorExecutionTarget>,
) {
    let Some(target) = execution_target else {
        return;
    };
    report.findings.push(Finding {
        severity: FindingSeverity::Info,
        message: format!(
            "supervise run explicitly targeted the existing primary checkout with declared scope: {}",
            display_paths(target.claim_paths())
        ),
        paths: target.claim_paths().to_vec(),
    });
    if report.success && report.publishable {
        report.remaining_risk = format!(
            "accepted changes already reside in the existing primary checkout and were bounded to declared scope: {}",
            display_paths(target.claim_paths())
        );
        report.next_safe_action =
            "review the in-place primary-checkout changes; no separate child-worktree merge or apply step exists for this run"
                .to_string();
    } else if report.success {
        report.remaining_risk = format!(
            "the simulation targeted primary-worktree semantics for declared scope {} but is not publishable evidence",
            display_paths(target.claim_paths())
        );
        report.next_safe_action =
            "rerun the same double-opted-in primary-worktree plan with the verified Codex runtime before acceptance"
                .to_string();
    } else {
        report.remaining_risk = format!(
            "the failed run targeted the existing primary checkout within declared scope {}; inspect that scope before retrying",
            display_paths(target.claim_paths())
        );
        report.next_safe_action =
            "inspect the declared primary-worktree scope and authenticated run evidence before deciding whether a new in-place run is safe"
                .to_string();
    }
}

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
    let parsed: ParsedReport<OrchestratorReviewReport> = parse_report_json(contents)
        .with_context(|| format!("failed to parse child report {}", display_path.display()))?;
    if parsed.report.role != AgentRole::ChildOrchestrator {
        bail!(
            "child report {} declared non-child role {:?}",
            display_path.display(),
            parsed.report.role
        );
    }
    Ok(parsed)
}

pub(super) fn read_worker_report(
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

pub(super) fn write_child_report(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    report: &OrchestratorReviewReport,
) -> Result<()> {
    let mut normalized_report = report.clone();
    enforce_orchestrator_environment_failure_outcome(&mut normalized_report);
    // This artifact also serves as the child process output contract. Keep supervisor-owned lens
    // authority out of that child-writable file; the aggregate is published in the supervisor
    // final report and strict event journal instead.
    normalized_report.review_lens_aggregate = None;
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

pub(super) fn write_worker_report(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    report: &WorkerReport,
) -> Result<()> {
    let mut normalized_report = report.clone();
    enforce_worker_environment_failure_outcome(&mut normalized_report);
    write_artifact_json(
        writer,
        relative,
        &normalized_report,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .with_context(|| {
        format!(
            "failed to update normalized direct worker report {}",
            relative.display()
        )
    })
}

pub(super) fn finalized_direct_worker_report(
    assignment: &OrchestratorAssignment,
    envelope: &OrchestratorReviewReport,
    report_path: &Path,
) -> WorkerReport {
    let matching_worker = match envelope.worker_reports.as_slice() {
        [worker] if worker.id == assignment.id => Some(worker.clone()),
        _ => None,
    };
    let matched = matching_worker.is_some();
    let mut report = matching_worker.unwrap_or_else(|| WorkerReport {
        id: assignment.id.clone(),
        role: AgentRole::Worker,
        assignment_kind: AssignmentKind::Ordinary,
        target_path: None,
        assigned_paths: assignment.assigned_paths.clone(),
        semantic_symbols: assignment.semantic_symbols.clone(),
        semantic_modules: assignment.semantic_modules.clone(),
        claim_token: envelope.claim_token,
        semantic_intent_token: envelope.semantic_intent_token,
        commands_run: envelope.commands_run.clone(),
        environment_failures: envelope.environment_failures.clone(),
        files_changed: envelope.files_changed.clone(),
        validation_results: envelope.validation_results.clone(),
        findings: vec![Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "direct worker finalization envelope contained {} WorkerReport entries instead of exactly one report bound to assignment '{}'",
                envelope.worker_reports.len(),
                assignment.id
            ),
            paths: vec![report_path.to_path_buf()],
        }],
        field_guide_entries: Vec::new(),
        bloated_file_flags: Vec::new(),
        decomposition_completion: None,
        no_further_delegation: None,
        accepted: false,
        rejected: true,
        status: if envelope.status == ReviewStatus::Succeeded {
            ReviewStatus::Failed
        } else {
            envelope.status
        },
        remaining_risk: envelope.remaining_risk.clone(),
        next_safe_action: envelope.next_safe_action.clone(),
    });
    for finding in &envelope.findings {
        if !report.findings.contains(finding) {
            report.findings.push(finding.clone());
        }
    }
    if matched {
        report.accepted = envelope.accepted;
        report.rejected = envelope.rejected;
        report.status = envelope.status;
    }
    report
        .environment_failures
        .clone_from(&envelope.environment_failures);
    report.remaining_risk.clone_from(&envelope.remaining_risk);
    report
        .next_safe_action
        .clone_from(&envelope.next_safe_action);
    enforce_worker_environment_failure_outcome(&mut report);
    report
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

pub(super) fn assignment_worker_journal_subject_ids(
    assignment: &OrchestratorAssignment,
) -> Result<Vec<&str>> {
    if assignment.role == AgentRole::Worker {
        if !assignment.worker_assignments.is_empty() {
            bail!(
                "direct terminal-worker assignment '{}' attempted nested worker delegation",
                assignment.id
            );
        }
        return Ok(vec![assignment.id.as_str()]);
    }
    Ok(assignment
        .worker_assignments
        .iter()
        .map(|worker| worker.id.as_str())
        .collect())
}

pub(super) fn import_worker_execution_journals(
    writer: &mut ArtifactRunWriter,
    assignment: &OrchestratorAssignment,
    incoming_scratch: &ArtifactScratchDirectory,
    external_run: &ExternalAgentRun,
) -> Result<WorkerExecutionJournalEvidenceSet> {
    import_worker_execution_journals_at(writer, assignment, incoming_scratch, external_run, None)
}

pub(crate) fn import_worker_execution_journals_at(
    writer: &mut ArtifactRunWriter,
    assignment: &OrchestratorAssignment,
    incoming_scratch: &ArtifactScratchDirectory,
    external_run: &ExternalAgentRun,
    evidence_root: Option<&Path>,
) -> Result<WorkerExecutionJournalEvidenceSet> {
    let mut journals = WorkerExecutionJournalEvidenceSet::new();
    let worker_ids = assignment_worker_journal_subject_ids(assignment)?;
    let process_quiescent = external_run.scratch_quiescence_verified();
    let mut capture_contract_error = None;
    let mut seen_capture_ids = BTreeSet::new();
    for capture in external_run.worker_journal_artifacts() {
        let expected_path = worker_ids
            .iter()
            .copied()
            .find(|worker_id| capture.worker_id.as_str() == *worker_id)
            .map(|worker_id| {
                incoming_scratch
                    .path()
                    .join(worker_execution_journal_incoming_relative_for_id(worker_id))
            });
        if !seen_capture_ids.insert(capture.worker_id.clone()) {
            capture_contract_error = Some(format!(
                "trusted runner returned duplicate worker journal capture '{}'",
                capture.worker_id
            ));
            break;
        }
        match expected_path {
            Some(expected_path) if expected_path == capture.path => {}
            Some(expected_path) => {
                capture_contract_error = Some(format!(
                    "trusted runner returned out-of-contract worker journal path {} for '{}'; expected {}",
                    capture.path.display(),
                    capture.worker_id,
                    expected_path.display()
                ));
                break;
            }
            None => {
                capture_contract_error = Some(format!(
                    "trusted runner returned unexpected worker journal capture '{}' at {}",
                    capture.worker_id,
                    capture.path.display()
                ));
                break;
            }
        }
    }
    if let Some(error) = capture_contract_error {
        bail!("trusted worker journal capture set violates the assignment contract: {error}");
    }
    for worker_id in worker_ids {
        let incoming_relative_path = worker_execution_journal_incoming_relative_for_id(worker_id);
        let scratch_path = incoming_scratch.path().join(&incoming_relative_path);
        let evidence_relative_path = evidence_root.map_or_else(
            || worker_execution_journal_evidence_relative(&assignment.id, worker_id),
            |root| root.join(worker_execution_journal_file_name(worker_id)),
        );
        let matching_capture = external_run
            .worker_journal_artifacts()
            .iter()
            .find(|capture| capture.worker_id.as_str() == worker_id);
        let status = if !process_quiescent {
            WorkerExecutionJournalStatus::Invalid(
                "worker journal evidence was not imported because external process quiescence was not verified"
                    .to_string(),
            )
        } else if let Some(capture) = matching_capture {
            if capture.path != scratch_path {
                WorkerExecutionJournalStatus::Invalid(format!(
                    "trusted worker journal capture for '{}' had unexpected contract path {}; expected {}",
                    worker_id,
                    capture.path.display(),
                    scratch_path.display()
                ))
            } else {
                match &capture.status {
                    WorkerJournalArtifactCaptureStatus::Loaded(bytes) => {
                        writer.write_bytes(
                            &evidence_relative_path,
                            bytes,
                            ArtifactFileDisposition::PrivateEvidence,
                        )?;
                        match parse_worker_execution_journal(bytes, &evidence_relative_path) {
                            Ok(entries) => WorkerExecutionJournalStatus::Loaded(entries),
                            Err(error) => {
                                WorkerExecutionJournalStatus::Invalid(format!("{error:#}"))
                            }
                        }
                    }
                    WorkerJournalArtifactCaptureStatus::Invalid(error) => {
                        WorkerExecutionJournalStatus::Invalid(error.clone())
                    }
                }
            }
        } else {
            WorkerExecutionJournalStatus::Missing
        };
        journals.insert(
            worker_id.to_string(),
            WorkerExecutionJournalEvidence {
                incoming_relative_path,
                evidence_relative_path,
                command_binding: matching_capture
                    .and_then(|capture| capture.command_binding.clone()),
                status,
            },
        );
    }
    Ok(journals)
}

pub(crate) fn parse_worker_execution_journal(
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
        entry.changed_paths = normalize_paths(std::mem::take(&mut entry.changed_paths))
            .with_context(|| {
                format!(
                    "worker execution journal {} line {} has invalid changed_paths",
                    display_path.display(),
                    line_number
                )
            })?;
        validate_worker_execution_journal_record(&entry).with_context(|| {
            format!(
                "worker execution journal {} line {} failed semantic validation",
                display_path.display(),
                line_number
            )
        })?;
        entries.push(entry);
    }
    validate_worker_journal_observations(&entries)?;
    Ok(entries)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WorkerExecutionJournalRecordError {
    #[error(
        "worker execution journal record omitted command; corrective action: provide a nonempty command array before retrying the append"
    )]
    MissingCommand,
    #[error(
        "worker execution journal apply_patch record omitted the patch payload; corrective action: preserve the complete nonempty patch as command[1] before retrying the append"
    )]
    MissingApplyPatchPayload,
    #[error(
        "worker execution journal record omitted cwd; corrective action: provide the absolute assigned-worktree cwd before retrying the append"
    )]
    MissingCwd,
    #[error(
        "worker execution journal record omitted start_timestamp; corrective action: provide the command's nonempty RFC3339 start timestamp before retrying the append"
    )]
    MissingStartTimestamp,
    #[error(
        "worker execution journal record omitted end_timestamp; corrective action: provide the command's nonempty RFC3339 end timestamp before retrying the append"
    )]
    MissingEndTimestamp,
    #[error(
        "worker execution journal record has invalid changed_paths: {detail}; corrective action: provide canonical repository-relative changed paths before retrying the append"
    )]
    InvalidChangedPaths { detail: String },
    #[error(
        "worker execution journal record could not be serialized before append: {detail}; corrective action: provide UTF-8 JSON field values before retrying the append"
    )]
    Serialization { detail: String },
    #[error(
        "validated worker execution journal record could not be appended: {source}; corrective action: stop and report the exact journal write failure without replacing the precreated file"
    )]
    Append {
        #[source]
        source: std::io::Error,
    },
}

fn validate_worker_execution_journal_record(
    entry: &WorkerExecutionJournalEntry,
) -> std::result::Result<(), WorkerExecutionJournalRecordError> {
    if entry.command.is_empty() {
        return Err(WorkerExecutionJournalRecordError::MissingCommand);
    }
    if entry.command.first().map(String::as_str) == Some("apply_patch") {
        match entry.command.get(1) {
            Some(payload) if !payload.trim().is_empty() => {}
            _ => return Err(WorkerExecutionJournalRecordError::MissingApplyPatchPayload),
        }
    }
    let cwd_is_blank = match entry.cwd.to_str() {
        Some(cwd) => cwd.trim().is_empty(),
        None => entry.cwd.as_os_str().is_empty(),
    };
    if cwd_is_blank {
        return Err(WorkerExecutionJournalRecordError::MissingCwd);
    }
    if entry.start_timestamp.trim().is_empty() {
        return Err(WorkerExecutionJournalRecordError::MissingStartTimestamp);
    }
    if entry.end_timestamp.trim().is_empty() {
        return Err(WorkerExecutionJournalRecordError::MissingEndTimestamp);
    }
    Ok(())
}

pub(crate) fn append_worker_execution_journal_record(
    journal: &mut impl std::io::Write,
    entry: &WorkerExecutionJournalEntry,
) -> std::result::Result<(), WorkerExecutionJournalRecordError> {
    validate_worker_execution_journal_record(entry)?;
    let mut normalized = entry.clone();
    normalized.changed_paths = normalize_paths(normalized.changed_paths).map_err(|error| {
        WorkerExecutionJournalRecordError::InvalidChangedPaths {
            detail: error.to_string(),
        }
    })?;
    let mut record = serde_json::to_vec(&normalized).map_err(|error| {
        WorkerExecutionJournalRecordError::Serialization {
            detail: error.to_string(),
        }
    })?;
    record.push(b'\n');
    journal
        .write_all(&record)
        .map_err(|source| WorkerExecutionJournalRecordError::Append { source })
}

/// Append through the existing serializer to an already delegated journal file.
/// The expected identity checks continuity; it does not grant filesystem authority
/// or replace the parent's private held-descriptor capture and acceptance checks.
#[cfg(test)]
pub(crate) fn append_precreated_worker_execution_journal(
    path: &Path,
    expected: &crate::safe_state::FileIdentity,
    entry: &WorkerExecutionJournalEntry,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Validate and encode before opening the append descriptor. Never expose a
        // partial hand-escaped JSON record to the journal.
        let mut record = Vec::new();
        append_worker_execution_journal_record(&mut record, entry)?;
        let file = open_worker_journal_no_follow(path, true)?;
        verify_worker_journal_identity(&file.metadata()?, expected)?;
        let mut locked = WorkerJournalAppendLock::acquire(file)?;
        append_locked_worker_journal(path, expected, &mut locked.file, &record)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected, entry);
        bail!("precreated worker journal append requires the qualified Linux file contract")
    }
}

/// Release the lock explicitly before closing the descriptor. Another thread's
/// concurrent fork can temporarily retain this open file description, including
/// CLOEXEC descriptors until exec, so close alone can leave a completed append
/// locked. Contending append operations wait for a bounded time and never steal
/// or replace a lock, including a stale or foreign holder's lock.
#[cfg(target_os = "linux")]
struct WorkerJournalAppendLock {
    file: fs::File,
}

#[cfg(target_os = "linux")]
impl WorkerJournalAppendLock {
    fn acquire(file: fs::File) -> Result<Self> {
        Self::acquire_with_timeout(file, std::time::Duration::from_secs(30))
    }

    fn acquire_with_timeout(file: fs::File, timeout: std::time::Duration) -> Result<Self> {
        use std::os::fd::AsRawFd;
        use std::time::{Duration, Instant};

        let started = Instant::now();
        loop {
            // SAFETY: flock acts on a live owned descriptor without pointers.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self { file });
            }
            let error = std::io::Error::last_os_error();
            if !matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                return Err(error).context("cannot acquire exclusive worker journal append lock");
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "timed out after {} ms waiting for exclusive worker journal append lock; stop without replacing or repairing the journal",
                        timeout.as_millis()
                    ),
                )
                .into());
            }
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for WorkerJournalAppendLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: self owns the live descriptor throughout this explicit unlock.
        // flock LOCK_UN has no contention failure; closing follows on all paths.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(target_os = "linux")]
fn append_locked_worker_journal(
    path: &Path,
    expected: &crate::safe_state::FileIdentity,
    file: &mut fs::File,
    record: &[u8],
) -> Result<()> {
    use std::io::Write;
    let before = file.metadata()?;
    verify_worker_journal_identity(&before, expected)?;
    let final_len = before
        .len()
        .checked_add(u64::try_from(record.len())?)
        .filter(|len| *len <= MAX_WORKER_EXECUTION_JOURNAL_BYTES as u64)
        .context("worker journal append exceeds the existing capture byte limit")?;
    let rebound = open_worker_journal_no_follow(path, false)?;
    verify_worker_journal_identity(&rebound.metadata()?, expected)?;
    if rebound.metadata()?.len() != before.len() {
        bail!("worker journal length changed before append");
    }
    file.write_all(record)
        .context("worker journal append failed; stop without repairing the file")?;
    file.sync_data()
        .context("worker journal append flush failed")?;
    let after = file.metadata()?;
    verify_worker_journal_identity(&after, expected)?;
    let rebound = open_worker_journal_no_follow(path, false)?;
    let rebound_metadata = rebound.metadata()?;
    verify_worker_journal_identity(&rebound_metadata, expected)?;
    if after.len() != final_len || rebound_metadata.len() != final_len {
        bail!("worker journal changed during append; stop without repairing the file");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_worker_journal_identity(
    metadata: &fs::Metadata,
    expected: &crate::safe_state::FileIdentity,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.file
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        bail!(
            "worker journal is not the expected current-user-owned single-link 0600 regular file"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_worker_journal_no_follow(path: &Path, append: bool) -> Result<fs::File> {
    use std::os::fd::AsRawFd;
    use std::path::Component;

    if !path.is_absolute()
        || !path
            .components()
            .skip(1)
            .all(|part| matches!(part, Component::Normal(_)))
        || path.file_name().is_none()
    {
        bail!("worker journal path must be an exact absolute path without traversal");
    }
    let relative = path.strip_prefix("/")?;
    let root = fs::File::open("/")?;
    let flags = if append {
        libc::O_WRONLY | libc::O_APPEND
    } else {
        libc::O_RDONLY
    };
    // Exact-file containment admits mounts. The shared ENOSYS-only fallback
    // never follows, creates or truncates; callers verify identity and policy.
    let file =
        crate::safe_state::open_relative_no_follow_linux(root.as_raw_fd(), relative, flags, false)
            .context("cannot open the existing worker journal without following links")?;
    if !file.metadata()?.is_file() {
        bail!("worker journal is not a regular file");
    }
    Ok(file)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "reporting_tests.rs"]
mod tests;

pub(super) fn worker_execution_journal_apply_patch_example() -> Result<String> {
    let entry = WorkerExecutionJournalEntry {
        command: vec![
            "apply_patch".to_string(),
            "*** Begin Patch\n*** Add File: p\n+x\n*** End Patch".to_string(),
        ],
        cwd: PathBuf::from("/worktree"),
        start_timestamp: "2026-08-25T00:00:00Z".to_string(),
        end_timestamp: "2026-08-25T00:00:01Z".to_string(),
        changed_paths: vec![PathBuf::from("p")],
        observation: None,
    };
    let mut encoded = Vec::new();
    append_worker_execution_journal_record(&mut encoded, &entry)
        .context("failed to render the validated apply_patch journal example")?;
    let rendered = String::from_utf8(encoded)
        .context("validated apply_patch journal example was not UTF-8")?;
    Ok(rendered.trim_end().to_string())
}

pub(super) fn import_external_attempt_evidence(
    writer: &mut ArtifactRunWriter,
    context: ExternalAttemptEvidenceContext<'_>,
) -> Result<()> {
    let import_result = retain_external_attempt_evidence(writer, &context);
    let ExternalAttemptEvidenceContext {
        incoming_scratch,
        capture_scratch,
        external_run,
        runtime,
        ..
    } = context;
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

/// Copy descriptor-held evidence without consuming its source scratches. Callers
/// retaining independent evidence decide when it is safe to discard the sources.
pub(super) fn retain_external_attempt_evidence(
    writer: &mut ArtifactRunWriter,
    context: &ExternalAttemptEvidenceContext<'_>,
) -> Result<()> {
    let ExternalAttemptEvidenceContext {
        artifacts,
        external_run,
        external_command,
        raw_report_validated,
        runtime,
        ..
    } = *context;
    super::target_containment::persist(writer, artifacts, external_command, runtime, external_run)?;
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
    Ok(())
}

pub(super) fn create_named_invocation_scratches(
    writer: &mut ArtifactRunWriter,
    incoming_name: &Path,
    capture_name: &Path,
) -> Result<(ArtifactScratchDirectory, ArtifactScratchDirectory)> {
    let incoming = writer.create_supervisor_invocation_scratch_dir(incoming_name)?;
    match writer.create_supervisor_invocation_scratch_dir(capture_name) {
        Ok(capture) => Ok((incoming, capture)),
        Err(error) => {
            writer.discard_scratch(&incoming)?;
            Err(error).context("failed to reserve parent capture scratch")
        }
    }
}

pub(super) fn precreate_worker_execution_journals(
    assignment: &OrchestratorAssignment,
    incoming_scratch: &ArtifactScratchDirectory,
) -> Result<Vec<PathBuf>> {
    let worker_ids = assignment_worker_journal_subject_ids(assignment)?;
    if worker_ids.is_empty() {
        return Ok(Vec::new());
    }
    let journal_root = incoming_scratch.path().join("worker-journals");
    fs::create_dir(&journal_root).with_context(|| {
        format!(
            "failed to create private worker journal directory {}",
            journal_root.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to restrict worker journal directory {}",
                    journal_root.display()
                )
            },
        )?;
    }
    let journal_root = fs::canonicalize(&journal_root)
        .context("failed to resolve private worker journal directory")?;
    if journal_root.parent() != Some(incoming_scratch.path()) {
        bail!("worker journal directory escaped the incoming scratch root");
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::DirBuilderExt;

        for name in CODEX_WRITABLE_ROOT_PROTECTED_MOUNT_TARGETS {
            let path = journal_root.join(name);
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(&path).with_context(|| {
                format!(
                    "failed to precreate private Codex protected mount target {}",
                    path.display()
                )
            })?;
        }
    }
    let mut paths = Vec::with_capacity(worker_ids.len());
    for worker_id in worker_ids {
        let file_name = worker_execution_journal_file_name(worker_id);
        let path = journal_root.join(&file_name);
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(&path).with_context(|| {
            format!(
                "failed to precreate worker journal artifact {}",
                path.display()
            )
        })?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("precreated worker journal artifact is not a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            if metadata.uid() != effective_uid
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                bail!(
                    "precreated worker journal artifact must be current-user-owned, mode 0600, and single-link"
                );
            }
        }
        file.sync_all().with_context(|| {
            format!("failed to flush worker journal artifact {}", path.display())
        })?;
        let canonical = fs::canonicalize(&path)
            .context("failed to resolve precreated worker journal artifact")?;
        if canonical != path {
            bail!("precreated worker journal artifact changed identity before launch");
        }
        paths.push(canonical);
    }
    Ok(paths)
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
        SupervisorRuntime::Grok
        | SupervisorRuntime::Cursor
        | SupervisorRuntime::ClaudeCode
        | SupervisorRuntime::GeminiCli => run.scratch_quiescence_verified(),
    }
}

pub(super) fn parse_report_json<T>(contents: &str) -> Result<ParsedReport<T>>
where
    T: DeserializeOwned,
{
    let direct_error = match serde_json::from_str(contents) {
        Ok(report) => {
            return Ok(ParsedReport {
                report,
                recovered: false,
            });
        }
        Err(error) => error,
    };

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
        "report JSON/contract parse failed: {direct_error}; lenient JSON extraction did not produce a contract-valid report"
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
        EnvironmentFailureCategory::NetworkUnavailable => "network_unavailable",
        EnvironmentFailureCategory::ProviderAuthRequired => "provider_auth_required",
        EnvironmentFailureCategory::SandboxUnavailable => "sandbox_unavailable",
        EnvironmentFailureCategory::MissingGitAttribution => "missing_git_attribution",
        EnvironmentFailureCategory::ProbeFailed => "probe_failed",
        EnvironmentFailureCategory::RuntimeModelCatalogUnavailable => {
            "runtime_model_catalog_unavailable"
        }
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

fn sanitize_environment_failure_diagnostic(
    summary: &str,
    canonical_summary: &str,
) -> Option<String> {
    let diagnostic = summary
        .strip_prefix(canonical_summary)
        .map(|suffix| suffix.strip_prefix(": ").unwrap_or(suffix))
        .unwrap_or(summary);
    let diagnostic = diagnostic
        .chars()
        .map(|character| match character {
            '\r' => '\n',
            character if character.is_control() && character != '\n' => ' ',
            character => character,
        })
        .collect::<String>();
    let redacted = crate::llm::Redactor::new().redact(&diagnostic).text;
    // The generic redactor intentionally preserves a secret assignment's key and delimiter.
    // Remove that delimiter from the already-redacted representation so a subsequent report
    // normalization remains idempotent instead of treating the rest of the single-line summary
    // as the assignment value.
    let redacted = redacted
        .replace("= <redacted:secret>", " <redacted:secret>")
        .replace("=<redacted:secret>", " <redacted:secret>")
        .replace(": <redacted:secret>", " <redacted:secret>")
        .replace(":<redacted:secret>", " <redacted:secret>");
    let single_line = redacted.split_whitespace().collect::<Vec<_>>().join(" ");
    if single_line.is_empty() {
        return None;
    }

    let mut characters = single_line.chars();
    let bounded = characters
        .by_ref()
        .take(MAX_ENVIRONMENT_FAILURE_DIAGNOSTIC_CHARS)
        .collect::<String>();
    if characters.next().is_none() {
        return Some(bounded);
    }

    let marker_chars = ENVIRONMENT_FAILURE_DIAGNOSTIC_TRUNCATION_MARKER
        .chars()
        .count();
    let retained_chars = MAX_ENVIRONMENT_FAILURE_DIAGNOSTIC_CHARS.saturating_sub(marker_chars);
    let mut truncated = bounded.chars().take(retained_chars).collect::<String>();
    truncated.push_str(ENVIRONMENT_FAILURE_DIAGNOSTIC_TRUNCATION_MARKER);
    Some(truncated)
}

fn sanitize_environment_failure(mut failure: EnvironmentFailure) -> EnvironmentFailure {
    let canonical_summary = format!(
        "environment preflight reported {}",
        environment_failure_category_name(failure.category)
    );
    failure.summary =
        if failure.category == EnvironmentFailureCategory::RuntimeModelCatalogUnavailable {
            sanitize_environment_failure_diagnostic(&failure.summary, &canonical_summary)
                .map(|diagnostic| format!("{canonical_summary}: {diagnostic}"))
                .unwrap_or(canonical_summary)
        } else {
            canonical_summary
        };
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
        EnvironmentFailureCategory::MissingCredential | EnvironmentFailureCategory::ProviderAuthRequired => vec![EnvironmentRemediation {
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
        EnvironmentFailureCategory::NetworkUnavailable => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::CapabilityPolicy,
            guidance: "repair resolver/transport access for the existing contained runtime and retry; retain the native inference failure evidence".to_string(),
        }],
        EnvironmentFailureCategory::SandboxUnavailable => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::CapabilityPolicy,
            guidance:
                "restore the verified confinement capability before rerunning; do not broaden the sandbox automatically"
                    .to_string(),
        }],
        EnvironmentFailureCategory::MissingGitAttribution => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::ProjectLocal,
            guidance: "configure repository-local user.name and user.email with the approved author identity in the source repository, then start a fresh managed run; global identity is not projected and attribution/hook policy is unchanged".to_string(),
        }],
        EnvironmentFailureCategory::ProbeFailed => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::ProjectLocal,
            guidance:
                "inspect the fixed preflight probe evidence and correct the project or host environment before rerunning"
                    .to_string(),
        }],
        EnvironmentFailureCategory::RuntimeModelCatalogUnavailable => vec![
            EnvironmentRemediation {
                scope: EnvironmentRemediationScope::CapabilityPolicy,
                guidance: "restore the trusted system Codex runtime-catalog path and verified confinement; do not substitute a custom executable or broaden the sandbox"
                    .to_string(),
            },
            EnvironmentRemediation {
                scope: EnvironmentRemediationScope::CredentialConfiguration,
                guidance: "validate the existing Codex auth source without copying secret material into the repository or plan"
                    .to_string(),
            },
        ],
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

pub(super) fn enforce_orchestrator_environment_failure_outcome(
    report: &mut OrchestratorReviewReport,
) {
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

pub(super) fn enforce_supervisor_final_environment_failure_outcome(
    report: &mut SupervisorFinalReport,
) {
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
    runtime: SupervisorRuntime,
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
        commands_run: vec![command_record_from_external_for_runtime(
            external_run,
            external_command,
            runtime,
        )],
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
        review_lens_aggregate: None,
        decomposition_completions: Vec::new(),
        licensed_breakage_review: None,
        generated_follow_up_tasks: Vec::new(),
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
    runtime: SupervisorRuntime,
    error: String,
) -> OrchestratorReviewReport {
    let corrective_action = if assignment.role == AgentRole::Worker {
        "return exactly one non-delegating WorkerReport JSON object bound to this assignment id and matching the supplied output schema; the supervisor runs the independent auditor"
    } else {
        "return exactly one OrchestratorReviewReport JSON object matching the supplied output schema, with every accepted terminal WorkerReport embedded and at least one read-only AuditorReport covering every worker id"
    };
    OrchestratorReviewReport {
        id: assignment.id.clone(),
        role: AgentRole::ChildOrchestrator,
        assigned_paths: assignment.assigned_paths.clone(),
        semantic_symbols: assignment.semantic_symbols.clone(),
        semantic_modules: assignment.semantic_modules.clone(),
        claim_token: None,
        semantic_intent_token: None,
        commands_run: vec![command_record_from_external_for_runtime(
            external_run,
            external_command,
            runtime,
        )],
        environment_failures: sanitized_environment_failures(
            external_run.environment_failures().to_vec(),
        ),
        files_changed: Vec::new(),
        validation_results: Vec::new(),
        findings: vec![
            Finding {
                severity: FindingSeverity::Error,
                message: format!("required child report is missing or invalid: {error}"),
                paths: vec![report_path.to_path_buf()],
            },
            Finding {
                severity: FindingSeverity::Error,
                message: format!(
                    "child report contract failure at '{}': {error}. Corrective action: {corrective_action}; do not add a prose or Markdown wrapper",
                    report_path.display()
                ),
                paths: vec![report_path.to_path_buf()],
            },
        ],
        field_guide_entries: Vec::new(),
        worker_reports: Vec::new(),
        audit_reports: Vec::new(),
        review_lens_aggregate: None,
        decomposition_completions: Vec::new(),
        licensed_breakage_review: None,
        generated_follow_up_tasks: Vec::new(),
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
        rejection_kind: None,
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

pub(super) fn accepted_bloated_file_flags(
    reports: &[OrchestratorReviewReport],
) -> Vec<BloatedFileFlag> {
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

pub(super) fn accepted_field_guide_drafts(
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
        let parent_audited = report
            .review_lens_aggregate
            .as_ref()
            .is_some_and(|aggregate| {
                aggregate.authority() == ReviewLensAggregateAuthority::ParentComputed
                    && aggregate.decision == ReviewAggregationDecision::Accept
            })
            && report.audit_reports.iter().any(|auditor| {
                is_parent_auditor_id(assignment, &auditor.id)
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
    let worker_journal_artifacts = write_deterministic_fake_worker_journals(command, assignment)?;
    if assignment.role == AgentRole::Worker {
        let report = deterministic_fake_worker_report(
            &assignment.id,
            &assignment.assigned_paths,
            &assignment.semantic_symbols,
            &assignment.semantic_modules,
            AssignmentKind::Ordinary,
            None,
            Some(claim_token),
            semantic_intent_token,
        );
        let mut output = serde_json::to_vec_pretty(&report)?;
        output.push(b'\n');
        let mut run = deterministic_fake_run(command, output);
        run.replace_worker_journal_artifacts(worker_journal_artifacts);
        return Ok(run);
    }
    let worker_reports = assignment
        .worker_assignments
        .iter()
        .map(|worker| {
            let metadata = worker_assignment_metadata(assignment_metadata, assignment, worker);
            deterministic_fake_worker_report(
                &worker.id,
                &worker.assigned_paths,
                &worker.semantic_symbols,
                &worker.semantic_modules,
                metadata.kind,
                metadata.target_path,
                None,
                None,
            )
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
        review_lens_aggregate: None,
        decomposition_completions,
        licensed_breakage_review: None,
        generated_follow_up_tasks: Vec::new(),
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
    let mut run = deterministic_fake_run(command, output);
    run.replace_worker_journal_artifacts(worker_journal_artifacts);
    Ok(run)
}

#[allow(clippy::too_many_arguments)]
fn deterministic_fake_worker_report(
    id: &str,
    assigned_paths: &[PathBuf],
    semantic_symbols: &[String],
    semantic_modules: &[String],
    assignment_kind: AssignmentKind,
    target_path: Option<PathBuf>,
    claim_token: Option<u64>,
    semantic_intent_token: Option<u64>,
) -> WorkerReport {
    WorkerReport {
        id: id.to_string(),
        role: AgentRole::Worker,
        assignment_kind,
        target_path: target_path.clone(),
        assigned_paths: assigned_paths.to_vec(),
        semantic_symbols: semantic_symbols.to_vec(),
        semantic_modules: semantic_modules.to_vec(),
        claim_token,
        semantic_intent_token,
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
        decomposition_completion: target_path.map(|target_path| DecompositionCompletion {
            target_path,
            replacement_paths: Vec::new(),
            supervisor_candidate_binding: None,
        }),
        no_further_delegation: Some(true),
        accepted: true,
        rejected: false,
        status: ReviewStatus::Succeeded,
        remaining_risk: "simulation-only evidence".to_string(),
        next_safe_action: "rerun with the verified Codex runtime".to_string(),
    }
}

fn write_deterministic_fake_worker_journals(
    command: &ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
) -> Result<Vec<WorkerJournalArtifactCapture>> {
    let worker_ids = assignment_worker_journal_subject_ids(assignment)?;
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
    let mut captures = Vec::with_capacity(worker_ids.len());
    for worker_id in worker_ids {
        let journal_path = journal_root.join(worker_execution_journal_file_name(worker_id));
        let matching_specs = command
            .worker_journal_artifacts
            .iter()
            .filter(|artifact| artifact.worker_id.as_str() == worker_id)
            .collect::<Vec<_>>();
        if matching_specs.len() != 1
            || matching_specs[0].incoming_root != incoming_path
            || matching_specs[0].path != journal_path
        {
            bail!(
                "deterministic fake worker journal capability does not exactly match worker '{}'",
                worker_id
            );
        }
        fs::write(&journal_path, b"").with_context(|| {
            format!(
                "failed to write deterministic fake worker execution journal {}",
                journal_path.display()
            )
        })?;
        captures.push(WorkerJournalArtifactCapture {
            worker_id: worker_id.to_string(),
            path: journal_path,
            command_binding: None,
            status: WorkerJournalArtifactCaptureStatus::Loaded(Vec::new()),
        });
    }
    if command.worker_journal_artifacts.len() != captures.len() {
        bail!("deterministic fake worker journal capability set contains unexpected entries");
    }
    Ok(captures)
}

pub(super) fn deterministic_fake_auditor_run(
    command: &ExternalAgentCommand,
    expected_id: &str,
    assignment: &OrchestratorAssignment,
    child_report: &OrchestratorReviewReport,
) -> Result<ExternalAgentRun> {
    if command.model.is_some() {
        bail!("deterministic fake auditor command retained a provider model slug");
    }
    let mut validation_results = vec![ValidationResult {
        name: "deterministic fake auditor validation".to_string(),
        status: ReviewStatus::Succeeded,
        command: Vec::new(),
        message: None,
    }];
    if let Some(review) = child_report.licensed_breakage_review.as_ref() {
        validation_results.push(ValidationResult {
            name: LICENSED_BREAKAGE_AUDIT_VALIDATION_NAME.to_string(),
            status: ReviewStatus::Succeeded,
            command: Vec::new(),
            message: Some(review.declaration_sha256.clone()),
        });
    }
    let report = AuditorReport {
        id: expected_id.to_string(),
        role: AgentRole::Auditor,
        reviewed_worker_ids: required_auditor_prompt_subject_ids(assignment, child_report),
        reviewed_paths: required_auditor_review_paths(assignment, child_report),
        commands_run: Vec::new(),
        environment_failures: Vec::new(),
        validation_results,
        findings: Vec::new(),
        rejection_kind: None,
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

pub(super) fn deterministic_fake_run(
    command: &ExternalAgentCommand,
    output: Vec<u8>,
) -> ExternalAgentRun {
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
        grok_stream_usage_evidence: None,
        grok_acp_parent_evidence: None,
        cursor_managed_parent_evidence: None,
        codex_parent_evidence: None,
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
        SupervisorRuntime::Grok
        | SupervisorRuntime::Cursor
        | SupervisorRuntime::ClaudeCode
        | SupervisorRuntime::GeminiCli => {
            run.process_tree
                .is_some_and(ProcessTreeEvidence::is_verified_empty)
                && run
                    .side_effects
                    .is_some_and(SideEffectConfinementEvidence::is_verified)
                && run.exit_code == Some(0)
                && run.error.is_none()
        }
    }
}

pub(super) fn external_containment_verified(
    run: &ExternalAgentRun,
    runtime: SupervisorRuntime,
) -> bool {
    if run.environment_blocked() {
        run.environment_preflight_quiescence_verified()
    } else if runtime.is_adapter_subprocess() {
        // A failed or timed-out target can still have a verified-empty process
        // tree. Completion and publication are checked separately; conflating
        // them here falsely quarantines contained failures and prevents recovery.
        run.process_tree
            .is_some_and(ProcessTreeEvidence::is_verified_empty)
            && run
                .side_effects
                .is_some_and(SideEffectConfinementEvidence::is_verified)
    } else {
        external_safety_verified(run, runtime)
    }
}

pub(super) fn external_process_completed(
    run: &ExternalAgentRun,
    runtime: SupervisorRuntime,
) -> bool {
    if runtime == SupervisorRuntime::GeminiCli {
        let Some(evidence) = run.gemini_bridge_evidence() else {
            return false;
        };
        return run.publishable
            && run.exit_code == Some(0)
            && !run.timed_out
            && run.error.is_none()
            && run.managed_gemini_selection_evidence().is_some()
            && evidence.provider_released
            && evidence.identity_matches_launch()
            && ((evidence.managed_worker_completed
                && evidence.tool_mutation_observed
                && !evidence.managed_read_only_completed)
                || evidence.read_only_completion_valid(run))
            && external_safety_verified(run, runtime);
    }
    if runtime == SupervisorRuntime::Fake {
        return run.simulation_succeeded()
            && run.program_trust == ExternalProgramTrust::ExplicitCustom;
    }
    run.publishable
        && run.exit_code == Some(0)
        && !run.timed_out
        && run.error.is_none()
        && (runtime != SupervisorRuntime::Codex
            || run.authenticated_codex_evidence().is_none_or(|evidence| {
                !evidence.model_mismatch && run.authenticated_codex_usage().is_some()
            }))
        && (runtime != SupervisorRuntime::ClaudeCode
            || (run.authenticated_claude_usage_complete()
                && run.authenticated_claude_model().is_some()
                && run.claude_managed_effort_qualified()
                && !run.stdout.raw_capture_truncated()))
        && (runtime != SupervisorRuntime::Cursor
            || cursor_managed_usage(run).is_some_and(|(_, complete)| complete))
        && run
            .authenticated_app_server_evidence()
            .is_none_or(|evidence| {
                evidence.resolution_status == "complete"
                    && !run.stdout.raw_capture_truncated()
                    && run.codex_parent_evidence.as_ref() == Some(evidence)
            })
        && run.codex_auditor_effort_qualified()
        && external_safety_verified(run, runtime)
}

fn cursor_managed_usage(run: &ExternalAgentRun) -> Option<(Usage, bool)> {
    let evidence = run.cursor_managed_parent_evidence.as_ref()?;
    let counters = [
        evidence.input_tokens,
        evidence.output_tokens,
        evidence.cache_read_tokens,
        evidence.cache_write_tokens,
    ];
    if counters.iter().all(Option::is_none) {
        return None;
    }
    // Preserve each observed bucket once. Missing counters contribute only a
    // zero lower bound; they cannot establish complete invocation accounting.
    let values = counters.map(|value| usize::try_from(value.unwrap_or(0)).unwrap_or(usize::MAX));
    let input_tokens = values[0]
        .saturating_add(values[2])
        .saturating_add(values[3]);
    let output_tokens = values[1];
    let usage = Usage {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens.saturating_add(output_tokens),
    };
    let exact_total = counters.into_iter().try_fold(0_usize, |total, value| {
        total.checked_add(usize::try_from(value?).ok()?)
    });
    let complete = evidence.peer_verified
        && evidence.admitted_attempts != 0
        && evidence.completed_attempts == evidence.admitted_attempts
        && evidence.usage_attempts_covered == evidence.admitted_attempts
        && evidence.usage_attempts_incomplete == 0
        && evidence.usage_is_incomplete == Some(false)
        && exact_total.is_some();
    Some((usage, complete))
}

pub(super) fn external_usage_for_runtime(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
    runtime: SupervisorRuntime,
) -> Option<Usage> {
    if runtime == SupervisorRuntime::Grok {
        // Never parse mutable logs/public reports as Grok spend, including
        // Codex-shaped counters or ACP cost ticks masquerading as tokens.
        run.authenticated_grok_usage(command)
            .map(|(usage, _)| usage)
    } else if runtime == SupervisorRuntime::ClaudeCode {
        run.authenticated_claude_usage()
            .or_else(|| run.authenticated_claude_usage_lower_bound())
    } else if runtime == SupervisorRuntime::Cursor {
        // ACP raw events are not Codex JSONL. The managed parent retains the
        // per-attempt floors and completeness independently of writable logs.
        cursor_managed_usage(run).map(|(usage, _)| usage)
    } else if runtime == SupervisorRuntime::GeminiCli {
        run.gemini_bridge_evidence()?.usage_for_command(command)
    } else {
        complete_external_codex_usage(run, command)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn gemini_read_only_reporting_completion_requires_live_native_custody() -> Result<()> {
    crate::external_agent::gemini_bridge::test_read_only_completion_consumer(|run| {
        external_process_completed(run, SupervisorRuntime::GeminiCli)
    })
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn gemini_worker_reporting_requires_complete_private_usage_and_served_identity() -> Result<()> {
    crate::external_agent::gemini_bridge::test_worker_usage_consumer(|run, command, case| {
        assert_eq!(
            external_process_completed(run, SupervisorRuntime::GeminiCli),
            case == "complete",
            "{case}"
        );
        let usage = external_usage_for_runtime(run, command, SupervisorRuntime::GeminiCli);
        assert_eq!(
            usage.is_some(),
            matches!(case, "complete" | "mismatch" | "effort"),
            "{case}"
        );
        if let Some(usage) = usage {
            assert_eq!(
                usage,
                Usage {
                    input_tokens: 10,
                    output_tokens: 10,
                    total_tokens: 20
                }
            );
        }
        Ok(())
    })
}

pub(super) fn complete_external_codex_usage(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
) -> Option<Usage> {
    // Only the live app-server driver retains this private, correlated turn
    // transcript. CLI exec can emit more than one turn.completed event; its
    // JSONL accounting below must continue to sum those per-turn samples.
    if run.authenticated_app_server_evidence().is_some() {
        return run.authenticated_codex_usage();
    }
    if let Some(usage) = run.authenticated_codex_usage() {
        return Some(usage);
    }
    if run.codex_command_execution_evidence().is_some() {
        return None;
    }
    const MAX_USAGE_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
    match read_bounded_regular_file_nofollow(&command.json_log, MAX_USAGE_CAPTURE_BYTES) {
        Ok(bytes) if bytes.len() < MAX_USAGE_CAPTURE_BYTES => {
            codex_usage_from_jsonl(&bytes).ok().flatten()
        }
        Ok(_) => None,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && !run.stdout.raw_capture_truncated() =>
        {
            codex_usage_from_jsonl(run.stdout_bytes()).ok().flatten()
        }
        Err(_) => None,
    }
    .into_iter()
    .chain(run.authenticated_codex_partial_usage())
    // These observations overlap. Keep the larger lower bound, never sum them
    // or let a smaller mutable log erase privately retained tokens.
    .max_by_key(|usage| usage.total_tokens)
}

pub(super) fn role_usage_report(
    plan: &SupervisorPlan,
    samples: Vec<RoleUsageSample>,
) -> Result<RoleUsageAggregation> {
    #[derive(Debug)]
    struct LensModelUsage {
        usage: Usage,
        cost_usd: Option<f64>,
        last_observed_sequence: usize,
    }

    #[derive(Debug)]
    struct LensUsage {
        backend_id: String,
        configured_model: String,
        models: BTreeMap<Option<String>, LensModelUsage>,
    }

    let mut aggregates = BTreeMap::<AgentRole, (Usage, BTreeSet<String>, Option<f64>)>::new();
    let mut lens_aggregates = BTreeMap::new();
    for lens in &plan.review_lenses {
        let prior = lens_aggregates.insert(
            lens.id.clone(),
            LensUsage {
                backend_id: lens.backend.backend_id().to_string(),
                configured_model: lens.backend.model().to_string(),
                models: BTreeMap::new(),
            },
        );
        if prior.is_some() {
            bail!(
                "cannot attribute review usage because configured lens id '{}' is duplicated",
                lens.id
            );
        }
    }
    let mut total_usage = Usage::default();
    let mut total_cost_usd = Some(0.0);
    for (sample_sequence, sample) in samples.into_iter().enumerate() {
        if !matches!(
            sample.role,
            AgentRole::ChildOrchestrator
                | AgentRole::Worker
                | AgentRole::Researcher
                | AgentRole::GateClassifier
                | AgentRole::Auditor
        ) {
            bail!(
                "{} usage is not directly process-observable",
                sample.role.as_str()
            );
        }
        total_usage = total_usage.saturating_add(sample.usage);
        // Never reconstruct a requested-model price after settlement withheld it.
        let sample_cost_usd = sample.cost_usd;
        if let Some(lens_id) = sample.lens_id.as_deref() {
            if sample.role != AgentRole::Auditor {
                bail!(
                    "review lens '{}' usage was attributed to non-auditor role {}",
                    lens_id,
                    sample.role.as_str()
                );
            }
            let lens_aggregate = lens_aggregates.get_mut(lens_id).with_context(|| {
                format!("usage referenced unknown configured review lens '{lens_id}'")
            })?;
            let model_aggregate =
                lens_aggregate
                    .models
                    .entry(sample.model.clone())
                    .or_insert(LensModelUsage {
                        usage: Usage::default(),
                        cost_usd: Some(0.0),
                        last_observed_sequence: sample_sequence,
                    });
            model_aggregate.usage = model_aggregate.usage.saturating_add(sample.usage);
            model_aggregate.cost_usd = match (model_aggregate.cost_usd, sample_cost_usd) {
                (Some(total), Some(cost)) => {
                    let total = total + cost;
                    total.is_finite().then_some(total)
                }
                _ => None,
            };
            model_aggregate.last_observed_sequence = sample_sequence;
        }
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
    reports
        .entry(AgentRole::Worker)
        .or_insert_with(|| RoleUsageReport {
            models: Vec::new(),
            usage: None,
            cost_usd: None,
            observation: RoleUsageObservation::NotProcessObservable,
            unavailable_reason: Some(
                "nested-worker delegation is requested through the child-orchestrator contract, but MACO does not separately observe a worker process or runtime identity; runtime-side role-tagged usage reporting is required before worker usage or cost can be reported"
                    .to_string(),
            ),
        });
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
    let all_lenses_observed = !lens_aggregates.is_empty()
        && lens_aggregates
            .values()
            .all(|aggregate| !aggregate.models.is_empty());
    let lens_total_usage = all_lenses_observed.then(|| {
        lens_aggregates
            .values()
            .flat_map(|aggregate| aggregate.models.values())
            .fold(Usage::default(), |total, model| {
                total.saturating_add(model.usage)
            })
    });
    let lens_total_cost_usd = all_lenses_observed
        .then(|| {
            lens_aggregates
                .values()
                .flat_map(|aggregate| aggregate.models.values())
                .try_fold(0.0, |total, model| {
                    model.cost_usd.and_then(|cost| {
                        let total = total + cost;
                        total.is_finite().then_some(total)
                    })
                })
        })
        .flatten();
    let lens_reports = lens_aggregates
        .into_iter()
        .flat_map(|(lens_id, aggregate)| {
            if aggregate.models.is_empty() {
                return vec![ReviewLensUsageReport {
                    lens_id,
                    backend_id: aggregate.backend_id,
                    model: aggregate.configured_model,
                    usage: None,
                    cost_usd: None,
                    observation: RoleUsageObservation::NotProcessObservable,
                    unavailable_reason: Some(
                        "no reliable process-observable usage sample was attributed to this configured review lens; usage and cost are not heuristically allocated"
                            .to_string(),
                    ),
                }];
            }
            let mut models = aggregate.models.into_iter().collect::<Vec<_>>();
            // Keep the most recently observed (therefore currently active) model first so
            // consumers that bind one entry per lens do not mistake an earlier rejected attempt
            // for the final active selection. Every attempted model remains a distinct entry.
            models.sort_by(|left, right| {
                right
                    .1
                    .last_observed_sequence
                    .cmp(&left.1.last_observed_sequence)
                    .then_with(|| left.0.cmp(&right.0))
            });
            models
                .into_iter()
                .map(|(model, model_usage)| ReviewLensUsageReport {
                    lens_id: lens_id.clone(),
                    backend_id: aggregate.backend_id.clone(),
                    model: model.clone().unwrap_or_else(|| "unknown".to_string()),
                    usage: Some(model_usage.usage),
                    cost_usd: model_usage.cost_usd,
                    observation: RoleUsageObservation::ProcessObserved,
                    unavailable_reason: model.is_none().then(|| "token usage is known, but a single parent-verified model allocation is unavailable".to_string()),
                })
                .collect::<Vec<_>>()
        })
        .collect();
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
                "no MACO-launched worker, child-orchestrator, or auditor process usage was observed"
                    .to_string()
            }),
        },
    );
    Ok(RoleUsageAggregation {
        reports,
        lens_reports,
        total_usage,
        total_cost_usd,
        lens_total_usage,
        lens_total_cost_usd,
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

pub(super) fn command_record_from_external_for_runtime(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
    runtime: SupervisorRuntime,
) -> CommandRunRecord {
    CommandRunRecord {
        command: serializable_external_command(&run.command, command),
        cwd: PathBuf::from("<child-worktree>"),
        exit_code: run.exit_code,
        status: if external_process_completed(run, runtime) {
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
        grok_stream_usage_evidence: run.grok_stream_usage_evidence.clone(),
        grok_acp_parent_evidence: run.grok_acp_parent_evidence.clone(),
        codex_parent_evidence: run.codex_parent_evidence.clone(),
        fixed_version_probe_evidence: run.fixed_version_probe_evidence().cloned(),
    }
}

#[cfg(test)]
pub(crate) fn command_record_from_external(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
) -> CommandRunRecord {
    let runtime = if run.simulation_succeeded()
        && run.program_trust == ExternalProgramTrust::ExplicitCustom
    {
        SupervisorRuntime::Fake
    } else {
        command
            .invocation
            .adapter_id()
            .and_then(crate::runtime_adapter::AdapterId::to_runtime_id)
            .unwrap_or(SupervisorRuntime::Codex)
    };
    command_record_from_external_for_runtime(run, command, runtime)
}

pub(super) fn sandbox_denials_for_report(
    denials: &[SandboxDenialEvidence],
) -> Vec<SandboxDenialEvidence> {
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

pub(super) fn aggregate_sandbox_denials(
    command_records: &[CommandRunRecord],
) -> Vec<SandboxDenialEvidence> {
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

#[cfg(test)]
mod grok_stream_usage_evidence {
    use super::*;
    use crate::external_agent::{
        CapturedOutput, ExternalAgentCommand, ExternalAgentRun, ExternalProgramTrust,
    };
    use crate::process_runner::{
        ContainmentBackend, ProcessTreeEvidence, SideEffectConfinementEvidence,
        SideEffectConfinementProfileKind,
    };
    use crate::runtime_adapter::grok::{GrokStreamUsageEvidence, GrokStreamUsageNativeEvidence};
    use crate::runtime_adapter::{RuntimeAdapterConfig, RuntimeId};
    use std::time::Duration;

    #[test]
    fn authenticated_command_record_retains_grok_stream_usage_evidence() {
        let command = ExternalAgentCommand::codex(
            "grok",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        )
        .with_runtime_adapter(
            RuntimeId::Grok,
            RuntimeAdapterConfig::defaults(RuntimeId::Grok),
        );
        let external_run = ExternalAgentRun {
            command: vec!["grok".to_string()],
            cwd: command.cwd.clone(),
            timeout_seconds: 1,
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            process_tree: Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            )),
            side_effects: Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalGrok,
            )),
            publishable: true,
            program_trust: ExternalProgramTrust::ExplicitCustom,
            codex_permissions: None,
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: None,
            output_last_message: None,
            grok_stream_usage_evidence: Some(GrokStreamUsageEvidence::Native(
                GrokStreamUsageNativeEvidence {
                    served_identity: Some(
                        crate::runtime_adapter::grok::identity::GrokServedIdentityEvidence::from_terminal(
                            br#"{"modelUsage":{"grok-4.6-build":{}}}"#,
                            true,
                        ),
                    ),
                    input_tokens: 3,
                    output_tokens: 1,
                    cache_read_input_tokens: None,
                    cache_creation_input_tokens: None,
                    reasoning_tokens: None,
                    total_tokens: Some(4),
                },
            )),
            grok_acp_parent_evidence: None,
            cursor_managed_parent_evidence: None,
            codex_parent_evidence: None,
        };
        let record = command_record_from_external_for_runtime(
            &external_run,
            &command,
            SupervisorRuntime::Grok,
        );
        assert_eq!(
            record.grok_stream_usage_evidence,
            external_run.grok_stream_usage_evidence
        );
        let value = serde_json::to_value(&record).expect("serialize command record");
        assert_eq!(
            value["grok_stream_usage_evidence"]["status"],
            serde_json::json!("native")
        );
    }

    #[test]
    fn claude_completion_refuses_private_evidence_without_whole_call_witness() {
        let command = ExternalAgentCommand::codex(
            "claude",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        )
        .with_runtime_adapter(
            RuntimeId::ClaudeCode,
            RuntimeAdapterConfig::defaults(RuntimeId::ClaudeCode),
        );
        let mut external_run = ExternalAgentRun {
            command: vec!["claude".to_string()],
            cwd: command.cwd.clone(),
            timeout_seconds: 1,
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            process_tree: Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            )),
            side_effects: Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            )),
            publishable: true,
            program_trust: ExternalProgramTrust::ExplicitCustom,
            codex_permissions: None,
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: None,
            output_last_message: Some(b"done".to_vec()),
            grok_stream_usage_evidence: None,
            grok_acp_parent_evidence: None,
            cursor_managed_parent_evidence: None,
            codex_parent_evidence: None,
        };
        let stream = [
            serde_json::json!({"type":"system","subtype":"init","session_id":"session-1","tools":["Read","Glob","Grep","Edit","Write"],"mcp_servers":[]}),
            serde_json::json!({"type":"stream_event","session_id":"session-1","event":{"type":"message_start","message":{"id":"message-1","model":"observed-claude-model","usage":{"input_tokens":10,"cache_creation_input_tokens":5,"cache_read_input_tokens":3,"output_tokens":0,"cache_creation":{"ephemeral_5m_input_tokens":2,"ephemeral_1h_input_tokens":3}}}}}),
            serde_json::json!({"type":"stream_event","session_id":"session-1","event":{"type":"message_delta","usage":{"output_tokens":7}}}),
            serde_json::json!({"type":"stream_event","session_id":"session-1","event":{"type":"message_stop"}}),
            serde_json::json!({"type":"assistant","session_id":"session-1","message":{"id":"message-1","model":"observed-claude-model"}}),
            serde_json::json!({"type":"result","subtype":"success","is_error":false,"session_id":"session-1","num_turns":1,"result":"done","modelUsage":{"observed-claude-model":{"inputTokens":10,"cacheCreationInputTokens":5,"cacheReadInputTokens":3,"outputTokens":7}}}),
        ]
        .into_iter()
        .map(|value| serde_json::to_string(&value).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
        external_run.set_claude_native_stream_for_test(&stream, false, false);
        assert!(!external_process_completed(
            &external_run,
            SupervisorRuntime::ClaudeCode
        ));
        assert!(external_run
            .authenticated_claude_usage_lower_bound()
            .is_some());

        let restored: ExternalAgentRun = serde_json::from_value(
            serde_json::to_value(&external_run).expect("serialize live Claude run"),
        )
        .expect("deserialize public Claude run");
        assert!(!external_process_completed(
            &restored,
            SupervisorRuntime::ClaudeCode
        ));

        external_run.set_claude_native_stream_for_test(&stream, false, true);
        assert!(!external_process_completed(
            &external_run,
            SupervisorRuntime::ClaudeCode
        ));
    }
}

#[cfg(test)]
mod cursor_managed_usage_evidence {
    use super::*;
    use crate::external_agent::CapturedOutput;
    use crate::process_runner::{ContainmentBackend, SideEffectConfinementProfileKind};
    use crate::runtime_adapter::{CursorManagedParentEvidence, RuntimeAdapterConfig};

    fn fixture(command: &ExternalAgentCommand) -> ExternalAgentRun {
        // Synthetic parent counters exercise settlement, not productive provider acceptance.
        ExternalAgentRun {
            command: vec!["cursor-agent".to_string()],
            cwd: command.cwd.clone(),
            timeout_seconds: 1,
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            process_tree: Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            )),
            side_effects: Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCursor,
            )),
            publishable: true,
            program_trust: ExternalProgramTrust::ExplicitCustom,
            codex_permissions: None,
            stdout: CapturedOutput::default(),
            stderr: CapturedOutput::default(),
            error: None,
            output_last_message: None,
            grok_stream_usage_evidence: None,
            grok_acp_parent_evidence: None,
            cursor_managed_parent_evidence: Some(CursorManagedParentEvidence {
                peer_verified: true,
                admitted_attempts: 2,
                completed_attempts: 2,
                captured_events: 3,
                input_tokens: Some(7),
                output_tokens: Some(3),
                cache_read_tokens: Some(2),
                cache_write_tokens: Some(1),
                usage_attempts_covered: 2,
                usage_is_incomplete: Some(false),
                ..Default::default()
            }),
            codex_parent_evidence: None,
        }
    }

    fn settle(
        ledger: &RunBudgetLedger,
        run: &ExternalAgentRun,
        command: &ExternalAgentCommand,
    ) -> DispatchUsageSettlement {
        let BudgetAdmission::Admitted { reservation, .. } = ledger
            .reserve(BudgetReservationRequest {
                role: AgentRole::Worker,
                tokens: 64,
                cost_usd: None,
            })
            .expect("Cursor token reservation")
        else {
            panic!("Cursor reservation was refused")
        };
        let mut held = DispatchBudgetReservation {
            ledger,
            reservation,
            pricing: None,
            pricing_model: None,
            state: DispatchBudgetReservationState::Reserved(SupervisorRuntime::Cursor),
        };
        held.mark_invoked_for_runtime(SupervisorRuntime::Cursor)
            .expect("bound Cursor invocation");
        held.settle_bound_runtime(run, command)
            .expect("Cursor settlement")
    }

    fn command(root: &Path) -> ExternalAgentCommand {
        let command = ExternalAgentCommand::codex(
            "cursor-agent",
            root,
            root.join("prompt.md"),
            root.join("capture.jsonl"),
            root.join("report.json"),
            Duration::from_secs(1),
        )
        .with_runtime_adapter(
            RuntimeId::Cursor,
            RuntimeAdapterConfig::defaults(RuntimeId::Cursor),
        );
        fs::write(
            &command.json_log,
            br#"{"type":"turn.completed","usage":{"input_tokens":90000,"output_tokens":90000}}"#,
        )
        .expect("conflicting mutable Codex-shaped log");
        command
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cursor_contract_settlement_preserves_rolling_usd_cost_completeness() {
        use crate::budget_ledger::{
            bind_rolling_budget, RollingBudgetQuota, WorkspaceBudgetLedger,
        };
        use coding_agent_manager_lib::account_authority::SelectedAccountBinding;

        for expired_at_settlement in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            git2::Repository::init(temp.path()).unwrap();
            let run_id = format!("synthetic-cursor-pricing-{expired_at_settlement}");
            let selected = SelectedAccountBinding {
                provider_id: "cursor".into(),
                account_id: "synthetic-cursor-account".into(),
                account_incarnation: "synthetic-cursor-incarnation".into(),
                selection_revision: 1,
            };
            crate::account_authority::record_observed_cursor_selection(
                Some(&run_id),
                "cursor",
                Some("synthetic-authority".into()),
                Some(&selected),
            );
            let _rolling = bind_rolling_budget(
                temp.path(),
                RollingBudgetQuota {
                    max_tokens: None,
                    max_cost_usd: Some(1.0),
                    window_seconds: 3600,
                },
                &run_id,
            )
            .unwrap();
            let mut plan: SupervisorPlan = serde_json::from_value(json!({
                "model_pricing": {"synthetic-cursor-model": {
                    "input_usd_per_million_tokens": 2.0,
                    "output_usd_per_million_tokens": 3.0
                }}
            }))
            .unwrap();
            let input = operator_pricing::synthetic_input(&plan, &selected.account_id).unwrap();
            let input = serde_json::to_value(input).unwrap();
            let mut contract: Value =
                serde_json::from_str(input["contract_json"].as_str().unwrap()).unwrap();
            contract["scopes"][0]["runtime"] = json!("cursor");
            if expired_at_settlement {
                contract["valid_through"] = json!("2001-01-01");
            }
            let source = json!({
                "pricing_contract": contract,
                "pricing_plan_id": "synthetic-plan",
                "model_pricing": plan.model_pricing,
            });
            let view = operator_pricing::load(&source.to_string(), &mut plan)
                .unwrap()
                .unwrap()
                .bind(&run_id)
                .unwrap();
            let budget = SupervisorBudgetConfig {
                worker_live_token_limits: BTreeMap::new(),
                limits: RunBudgetLimits {
                    hard_cost_usd: Some(1.0),
                    ..Default::default()
                },
                role_token_reservations: BTreeMap::from([(AgentRole::Worker, 64)]),
            };
            let mut ledger = RunBudgetLedger::new(budget.limits).unwrap();
            ledger.operator_pricing = Some(view.clone());
            let mut command = command(temp.path());
            command.model = Some("synthetic-cursor-model".into());
            let mut held = if expired_at_settlement {
                // An already-invoked reservation can outlive the contract's date.
                // Its old estimate must not substitute for a fresh applicability check.
                let BudgetAdmission::Admitted { reservation, .. } = ledger
                    .reserve(BudgetReservationRequest {
                        role: AgentRole::Worker,
                        tokens: 64,
                        cost_usd: Some(0.000192),
                    })
                    .unwrap()
                else {
                    panic!("held pre-expiry reservation")
                };
                DispatchBudgetReservation {
                    ledger: &ledger,
                    reservation,
                    pricing: Some(plan.model_pricing["synthetic-cursor-model"]),
                    pricing_model: command.model.clone(),
                    state: DispatchBudgetReservationState::Invoked(SupervisorRuntime::Cursor),
                }
            } else {
                let DispatchBudgetAdmission::Admitted(mut held) = reserve_dispatch_budget(
                    &plan,
                    &budget,
                    &ledger,
                    (AgentRole::Worker, SupervisorRuntime::Cursor),
                    &command,
                )
                .unwrap() else {
                    panic!("matching Cursor contract admission")
                };
                held.mark_invoked_for_runtime(SupervisorRuntime::Cursor)
                    .unwrap();
                held
            };
            let settled = held
                .settle_bound_runtime(&fixture(&command), &command)
                .unwrap();
            let expected_cost = (!expired_at_settlement).then_some(0.000029);
            assert_eq!(settled.reliability, DispatchUsageReliability::Reliable);
            assert_eq!(settled.reliable_usage().unwrap().total_tokens, 13);
            assert_eq!(settled.cost_usd, expected_cost);
            let report = ledger.report().unwrap();
            assert_eq!(report.consumed.cost_usd, expected_cost);
            assert_eq!(report.cost_complete, !expired_at_settlement);
            assert_eq!(report.pricing_contract, Some(view.provenance()));
            let pricing = report.charges[0].pricing.clone();
            assert_eq!(pricing.contract, report.pricing_contract);
            assert_eq!(pricing.runtime.as_deref(), Some("cursor"));
            assert_eq!(pricing.model.as_deref(), Some("synthetic-cursor-model"));
            assert_eq!(
                pricing.basis,
                if expired_at_settlement {
                    ChargePricingBasis::Unpriced
                } else {
                    ChargePricingBasis::OperatorContractEstimate
                }
            );
            assert_eq!(report.new_dispatch_allowed, !expired_at_settlement);
            assert_eq!(
                report.reasons.contains(&BudgetReason::MissingActualCost),
                expired_at_settlement
            );
            drop(held);
            drop(ledger);
            let history = WorkspaceBudgetLedger::open_or_create(temp.path()).unwrap();
            assert_eq!(history.settled_pricing(), vec![&pricing]);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            assert_eq!(
                history.usage_in_window(3600, now).unwrap().cost_usd,
                expected_cost
            );
            drop(history);
            let mut next = RunBudgetLedger::new(budget.limits).unwrap();
            next.operator_pricing = Some(view);
            assert_eq!(
                next.report().unwrap().new_dispatch_allowed,
                !expired_at_settlement
            );
            if !expired_at_settlement {
                let DispatchBudgetAdmission::Admitted(mut held) = reserve_dispatch_budget(
                    &plan,
                    &budget,
                    &next,
                    (AgentRole::Worker, SupervisorRuntime::Cursor),
                    &command,
                )
                .unwrap() else {
                    panic!("priced rolling history must permit the next dispatch")
                };
                held.settle_not_started().unwrap();
            }
            crate::account_authority::record_observed_cursor_selection(
                Some(&run_id),
                "cursor",
                None,
                None,
            );
        }
    }

    #[test]
    fn cursor_settlement_uses_parent_buckets_and_keeps_token_only_dispatch_open() {
        let temp = tempfile::tempdir().expect("Cursor usage fixture");
        let command = command(temp.path());
        let run = fixture(&command);
        let expected = Usage {
            input_tokens: 10,
            output_tokens: 3,
            total_tokens: 13,
        };
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            hard_tokens: Some(200),
            ..Default::default()
        })
        .unwrap();
        let settled = settle(&ledger, &run, &command);
        assert_eq!(settled.reliability, DispatchUsageReliability::Reliable);
        assert_eq!(settled.reliable_usage(), Some(expected));
        assert!(settled.cost_usd.is_none());
        assert!(settled.model.is_none());
        let report = ledger.report().unwrap();
        assert_eq!(report.consumed.tokens, 13);
        assert_eq!(report.reserved.tokens, 0);
        assert_eq!(report.active_reservations, 0);
        assert!(report.usage_complete);
        assert!(report.reasons.contains(&BudgetReason::MissingActualCost));
        assert!(!report.reasons.contains(&BudgetReason::MissingProviderUsage));
        assert!(report.new_dispatch_allowed);
        assert!(matches!(
            ledger.reserve(BudgetReservationRequest {
                role: AgentRole::Auditor,
                tokens: 64,
                cost_usd: None,
            }),
            Ok(BudgetAdmission::Admitted { .. })
        ));
    }

    #[test]
    fn cursor_settlement_keeps_partial_failed_floors_without_log_fallback() {
        let temp = tempfile::tempdir().expect("Cursor usage fixture");
        let command = command(temp.path());
        for case in [
            "missing_bucket",
            "incomplete",
            "uncovered_attempt",
            "timeout",
            "missing_parent",
        ] {
            let mut run = fixture(&command);
            run.cursor_managed_parent_evidence
                .as_mut()
                .unwrap()
                .input_tokens = Some(101);
            let mut expected = Some(107);
            match case {
                "missing_bucket" => {
                    run.cursor_managed_parent_evidence
                        .as_mut()
                        .unwrap()
                        .cache_write_tokens = None;
                    expected = Some(106);
                }
                "incomplete" => {
                    run.cursor_managed_parent_evidence
                        .as_mut()
                        .unwrap()
                        .usage_is_incomplete = Some(true);
                }
                "uncovered_attempt" => {
                    run.cursor_managed_parent_evidence
                        .as_mut()
                        .unwrap()
                        .usage_attempts_covered = 1;
                }
                "timeout" => run.timed_out = true,
                "missing_parent" => {
                    run.cursor_managed_parent_evidence = None;
                    expected = None;
                }
                _ => unreachable!(),
            }
            let ledger = RunBudgetLedger::new(RunBudgetLimits {
                hard_tokens: Some(200),
                ..Default::default()
            })
            .unwrap();
            let settled = settle(&ledger, &run, &command);
            assert_eq!(
                settled.observed_usage.map(|usage| usage.total_tokens),
                expected,
                "{case}"
            );
            assert_eq!(
                settled.reliability,
                if expected.is_some() {
                    DispatchUsageReliability::Estimated
                } else {
                    DispatchUsageReliability::Missing
                },
                "{case}"
            );
            assert!(settled.reliable_usage().is_none(), "{case}");
            assert!(settled.cost_usd.is_none(), "{case}");
            let report = ledger.report().unwrap();
            assert_eq!(report.consumed.tokens, expected.unwrap_or(64), "{case}");
            assert!(!report.usage_complete, "{case}");
            assert!(!report.new_dispatch_allowed, "{case}");
        }
    }
}
