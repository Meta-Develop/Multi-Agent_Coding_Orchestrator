use super::*;

pub(super) fn child_attempt_artifacts(
    dirs: &RunDirs,
    incoming_path: &Path,
    capture_path: &Path,
    assignment_id: &str,
    attempt: usize,
    attempt_numbered: bool,
) -> ChildAttemptArtifacts {
    let stem = if attempt_numbered {
        format!("{assignment_id}.attempt-{attempt}")
    } else {
        assignment_id.to_string()
    };
    ChildAttemptArtifacts {
        prompt_path: dirs.assignments.join(format!("{stem}.prompt.md")),
        report_path: incoming_path.join(format!("{stem}.json")),
        log_path: capture_path.join(format!("{stem}.jsonl")),
        raw_report_relative: PathBuf::from("evidence")
            .join("incoming")
            .join(format!("{stem}.json")),
        raw_stdout_relative: PathBuf::from("logs").join(format!("{stem}.jsonl")),
        command_record_relative: PathBuf::from("logs").join(format!("{stem}.summary.json")),
    }
}

pub(super) fn worker_execution_journal_file_name(worker_id: &str) -> String {
    format!("{worker_id}.jsonl")
}

pub(super) fn worker_execution_journal_incoming_relative_for_id(worker_id: &str) -> PathBuf {
    PathBuf::from("worker-journals").join(worker_execution_journal_file_name(worker_id))
}

pub(super) fn worker_execution_journal_incoming_relative(worker: &WorkerAssignment) -> PathBuf {
    worker_execution_journal_incoming_relative_for_id(&worker.id)
}

pub(super) fn worker_execution_journal_evidence_relative(
    assignment_id: &str,
    worker_id: &str,
) -> PathBuf {
    PathBuf::from("logs")
        .join("workers")
        .join(assignment_id)
        .join(worker_execution_journal_file_name(worker_id))
}

pub(super) fn prompt_with_structural_retry(prompt: &str) -> String {
    format!(
        r#"{prompt}

STRUCTURAL REPORT RETRY:
The previous response did not satisfy the trusted report schema.

Return only a compliant OrchestratorReviewReport JSON final response matching the schema. Do not include Markdown fences, prose, or any non-JSON wrapper.
"#
    )
}

pub(super) fn prompt_with_gate_correction(prompt: &str, denial: &GateDenial) -> Result<String> {
    let correction = denial
        .corrective_prompt()
        .context("failed to render validated gate correction prompt")?;
    Ok(format!("{prompt}\n\n{correction}"))
}

pub(super) fn append_child_attempt_history(
    report: &mut OrchestratorReviewReport,
    histories: &[ChildAttemptHistory],
) {
    if histories.is_empty() {
        return;
    }
    for history in histories {
        let structural_problems = if history.structural_problems.is_empty() {
            "<none>".to_string()
        } else {
            history.structural_problems.join("; ")
        };
        report.findings.push(Finding {
            severity: FindingSeverity::Info,
            message: format!(
                "child attempt {} history: structural_problems={}; corrective_retry_used={}",
                history.attempt, structural_problems, history.corrective_retry_used
            ),
            paths: vec![history.report_path.clone()],
        });
    }
}

pub(super) fn initialize_orchestration_event_journal(
    repo: &Path,
    run_id: &RunId,
    parent_node: Option<&str>,
) -> Option<OrchestrationEventJournal> {
    match repository_authenticator_key_only(repo) {
        Ok(authenticator) => Some(OrchestrationEventJournal::with_root_parent(
            authenticator.binding().repository_id.clone(),
            run_id.as_str(),
            parent_node.map(str::to_owned),
        )),
        Err(error) => {
            tracing::warn!(
                error = %error,
                "supervise orchestration event journal is unavailable"
            );
            None
        }
    }
}

pub(super) fn write_boundary_refs(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|path| serializable_path(path)).collect()
}

pub(super) fn assignment_scope_ref(assignment_id: &str) -> String {
    format!("assignment:{assignment_id}")
}

pub(super) fn run_scope_ref(run_id: &str) -> String {
    format!("run:{run_id}")
}

pub(super) fn worker_scope_ref(worker_id: &str) -> String {
    format!("worker:{worker_id}")
}

pub(super) fn record_supervision_spawn_payload(
    child_agent_id: &str,
    parent_agent_id: &str,
    role: OrchestrationRole,
    plan_role: AgentRole,
    write_boundary: Vec<String>,
    scope_ref: &str,
    payload: Value,
) -> Result<Value> {
    record_supervision_spawn_payload_with_category(
        child_agent_id,
        parent_agent_id,
        role,
        plan_role,
        None,
        write_boundary,
        scope_ref,
        payload,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn record_supervision_spawn_payload_with_category(
    child_agent_id: &str,
    parent_agent_id: &str,
    role: OrchestrationRole,
    plan_role: AgentRole,
    category_override: Option<RoleCategory>,
    write_boundary: Vec<String>,
    scope_ref: &str,
    mut payload: Value,
) -> Result<Value> {
    let edge = SupervisionEdgeRecord::new(
        child_agent_id,
        parent_agent_id,
        role,
        plan_role.as_str(),
        write_boundary,
        scope_ref,
    )?;
    insert_supervision_edge(&mut payload, &edge)?;
    let assignment = assign_role_category_with_provenance(
        child_agent_id,
        plan_role,
        category_override,
        RoleAssignmentProvenance::granted_by(parent_agent_id),
    )?;
    insert_role_assignment(&mut payload, &assignment)?;
    Ok(payload)
}

pub(super) fn record_gate_ownership(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    record: &GateOwnershipRecord,
) {
    match gate_ownership_payload(record) {
        Ok(payload) => record_orchestration_event(
            journal,
            writer,
            node,
            parent,
            role,
            OrchestrationEventKind::Gate,
            payload,
        ),
        Err(error) => tracing::warn!(
            error = %error,
            node,
            "refused to append malformed gate-ownership ledger record"
        ),
    }
}

pub(super) fn record_shared_gate_ownership(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    record: GateOwnershipRecord,
) -> Result<()> {
    with_supervisor_artifacts(artifacts, |writer, journal| {
        record_gate_ownership(journal, writer, node, parent, role, &record);
        Ok(())
    })
}

pub(super) fn record_orchestration_event(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    kind: OrchestrationEventKind,
    payload: Value,
) {
    append_phase_heartbeat(writer, node, kind, &payload);
    let Some(active_journal) = journal.as_mut() else {
        return;
    };
    let append_error = active_journal
        .append(writer, node, parent, role, kind, payload)
        .err();
    if let Some(error) = append_error {
        tracing::warn!(
            error = %error,
            node,
            ?kind,
            "disabled supervise orchestration event journal after append failure"
        );
        *journal = None;
    }
}

fn append_phase_heartbeat(
    writer: &mut ArtifactRunWriter,
    node: &str,
    kind: OrchestrationEventKind,
    payload: &Value,
) {
    match kind {
        OrchestrationEventKind::Spawn
        | OrchestrationEventKind::Status
        | OrchestrationEventKind::Gate
        | OrchestrationEventKind::Accept
        | OrchestrationEventKind::Reject
        | OrchestrationEventKind::Escalate => {}
        OrchestrationEventKind::Journal | OrchestrationEventKind::Claim => return,
    }
    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            payload
                .get("success")
                .and_then(Value::as_bool)
                .map(|success| {
                    if success {
                        "ok".to_string()
                    } else {
                        "failed".to_string()
                    }
                })
        })
        .unwrap_or_else(|| heartbeat_kind_status(kind).to_string());
    crate::run_ops::append_run_heartbeat_best_effort(
        writer,
        heartbeat_kind_name(kind),
        Some(node.to_string()),
        status,
        None,
    );
}

fn heartbeat_kind_name(kind: OrchestrationEventKind) -> &'static str {
    match kind {
        OrchestrationEventKind::Spawn => "spawn",
        OrchestrationEventKind::Status => "status",
        OrchestrationEventKind::Gate => "gate",
        OrchestrationEventKind::Accept => "accept",
        OrchestrationEventKind::Reject => "reject",
        OrchestrationEventKind::Escalate => "escalate",
        OrchestrationEventKind::Journal => "journal",
        OrchestrationEventKind::Claim => "claim",
    }
}

fn heartbeat_kind_status(kind: OrchestrationEventKind) -> &'static str {
    match kind {
        OrchestrationEventKind::Spawn => "started",
        OrchestrationEventKind::Accept => "accepted",
        OrchestrationEventKind::Reject => "rejected",
        OrchestrationEventKind::Escalate => "escalated",
        OrchestrationEventKind::Gate => "gate",
        OrchestrationEventKind::Status => "ok",
        OrchestrationEventKind::Journal | OrchestrationEventKind::Claim => "ok",
    }
}

pub(super) fn record_field_guide_event_strict(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    payload: Value,
) -> Result<()> {
    let active_journal = journal
        .as_mut()
        .context("strict field-guide provenance requires an orchestration event journal")?;
    if !active_journal.is_enabled() {
        bail!("strict field-guide provenance journal is disabled");
    }
    active_journal
        .append(
            writer,
            node,
            parent,
            role,
            OrchestrationEventKind::Journal,
            payload,
        )
        .context("failed to append strict field-guide provenance event")?;
    if !active_journal.is_enabled() {
        bail!("strict field-guide provenance journal became disabled");
    }
    Ok(())
}

pub(super) fn record_gate_correction_event_strict(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    payload: Value,
) -> Result<()> {
    let active_journal = journal
        .as_mut()
        .context("strict gate correction lifecycle requires an orchestration event journal")?;
    if !active_journal.is_enabled() {
        bail!("strict gate correction lifecycle journal is disabled");
    }
    active_journal
        .append(
            writer,
            node,
            parent,
            role,
            OrchestrationEventKind::Gate,
            payload,
        )
        .context("failed to append strict gate correction lifecycle event")?;
    if !active_journal.is_enabled() {
        bail!("strict gate correction lifecycle journal became disabled");
    }
    Ok(())
}

pub(super) fn record_pre_action_event_strict(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    node: &str,
    parent: Option<&str>,
    record: &PreActionJournalRecord,
) -> Result<()> {
    let active_journal = journal
        .as_mut()
        .context("strict pre-action review requires an orchestration event journal")?;
    if !active_journal.is_enabled() {
        bail!("strict pre-action review journal is disabled");
    }
    active_journal
        .append(
            writer,
            node,
            parent,
            OrchestrationRole::Orchestrator,
            OrchestrationEventKind::Gate,
            json!({"pre_action_review": record}),
        )
        .context("failed to append strict pre-action review event")?;
    if !active_journal.is_enabled() {
        bail!("strict pre-action review journal became disabled");
    }
    Ok(())
}

pub(super) fn field_guide_injection_payload(
    prompt_role: SupervisePromptRole,
    prompt: &SupervisorFieldGuidePrompt,
    attempt: usize,
) -> Value {
    json!({
        "field_guide_event_kind": FieldGuideEventKind::PromptInjectionEvidence,
        "prompt_role": prompt_role.canonical_role(),
        "attempt": attempt,
        "entry_count": prompt.entry_count,
        "line_count": prompt.line_count,
        "rendered_bytes": prompt.rendered_bytes,
        "line_cap": MAX_SUPERVISE_FIELD_GUIDE_LINES,
        "byte_cap": MAX_SUPERVISE_FIELD_GUIDE_BYTES,
        "cap_applied": prompt.cap_applied,
        "omitted_entry_count": prompt.omitted_entry_count,
    })
}

pub(super) fn record_field_guide_prompt_injection_strict(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    prompt_role: SupervisePromptRole,
    prompt: &SupervisorFieldGuidePrompt,
    attempt: usize,
) -> Result<()> {
    with_supervisor_artifacts(artifacts, |writer, journal| {
        record_field_guide_event_strict(
            journal,
            writer,
            node,
            parent,
            role,
            field_guide_injection_payload(prompt_role, prompt, attempt),
        )
    })
}

pub(super) fn lifecycle_event_payload(
    status: &str,
    attempt: Option<usize>,
    thread_id: Option<&str>,
) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("status".to_string(), Value::String(status.to_string()));
    if let Some(attempt) = attempt {
        payload.insert("attempt".to_string(), json!(attempt));
    }
    if let Some(thread_id) = thread_id {
        payload.insert(
            "thread_id".to_string(),
            Value::String(thread_id.to_string()),
        );
    }
    Value::Object(payload)
}

pub(super) fn codex_thread_id_from_stdout(stdout: &[u8]) -> Option<String> {
    stdout
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter_map(|value| {
            value
                .get("thread_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .find(|thread_id| {
            !thread_id.is_empty()
                && thread_id.len() <= 256
                && !thread_id.chars().any(char::is_control)
        })
}

pub(super) fn record_worker_journal_events(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    assignment: &OrchestratorAssignment,
    journals: &WorkerExecutionJournalEvidenceSet,
) {
    for (worker_id, evidence) in journals {
        let (status, entries, error) = match &evidence.status {
            WorkerExecutionJournalStatus::Loaded(entries) => ("loaded", Some(entries.len()), None),
            WorkerExecutionJournalStatus::Missing => ("missing", None, None),
            WorkerExecutionJournalStatus::Invalid(error) => ("invalid", None, Some(error.as_str())),
        };
        let worker = assignment
            .worker_assignments
            .iter()
            .find(|worker| worker.id == *worker_id);
        let write_boundary = worker
            .map(|worker| write_boundary_refs(&worker.assigned_paths))
            .unwrap_or_default();
        let plan_role = worker
            .map(|worker| worker.role)
            .unwrap_or(AgentRole::Worker);
        let category_override = worker.and_then(WorkerAssignment::category_override);
        match record_supervision_spawn_payload_with_category(
            worker_id,
            &assignment.id,
            OrchestrationRole::Worker,
            plan_role,
            category_override,
            write_boundary,
            &worker_scope_ref(worker_id),
            json!({}),
        ) {
            Ok(payload) => record_orchestration_event(
                journal,
                writer,
                worker_id,
                Some(&assignment.id),
                OrchestrationRole::Worker,
                OrchestrationEventKind::Spawn,
                payload,
            ),
            Err(error) => tracing::warn!(
                error = %error,
                worker_id,
                "refused to append malformed worker supervision-edge record"
            ),
        }
        match GateOwnershipRecord::assign(
            worker_id,
            &assignment.id,
            OrchestrationRole::Orchestrator,
            "child_orchestrator",
            "initial_parent_gate",
        ) {
            Ok(record) => record_gate_ownership(
                journal,
                writer,
                &assignment.id,
                None,
                OrchestrationRole::Orchestrator,
                &record,
            ),
            Err(error) => tracing::warn!(
                error = %error,
                worker_id,
                "refused to append malformed worker gate-ownership record"
            ),
        }
        record_orchestration_event(
            journal,
            writer,
            worker_id,
            Some(&assignment.id),
            OrchestrationRole::Worker,
            OrchestrationEventKind::Journal,
            json!({
                "status": status,
                "entries": entries,
                "error": error,
                "evidence_path": serializable_path(&evidence.evidence_relative_path),
            }),
        );
    }
}

pub(super) fn record_final_report_decisions(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    orchestrator_parent_id: &str,
    report: &OrchestratorReviewReport,
) {
    for worker in &report.worker_reports {
        record_orchestration_event(
            journal,
            writer,
            &worker.id,
            Some(&report.id),
            OrchestrationRole::Worker,
            if report_failed(worker) {
                OrchestrationEventKind::Reject
            } else {
                OrchestrationEventKind::Accept
            },
            json!({
                "status": worker.status,
                "accepted": worker.accepted,
                "rejected": worker.rejected,
            }),
        );
    }
    for auditor in &report.audit_reports {
        record_orchestration_event(
            journal,
            writer,
            &auditor.id,
            Some(&report.id),
            OrchestrationRole::Auditor,
            if report_failed(auditor) {
                OrchestrationEventKind::Reject
            } else {
                OrchestrationEventKind::Accept
            },
            json!({
                "status": auditor.status,
                "accepted": auditor.accepted,
                "rejected": auditor.rejected,
            }),
        );
    }
    record_orchestration_event(
        journal,
        writer,
        &report.id,
        Some(orchestrator_parent_id),
        OrchestrationRole::Orchestrator,
        if report_failed(report) {
            OrchestrationEventKind::Reject
        } else {
            OrchestrationEventKind::Accept
        },
        json!({
            "status": report.status,
            "accepted": report.accepted,
            "rejected": report.rejected,
        }),
    );
}

pub(super) fn record_final_worker_report_decision(
    journal: &mut Option<OrchestrationEventJournal>,
    writer: &mut ArtifactRunWriter,
    parent_id: &str,
    report: &WorkerReport,
) {
    record_orchestration_event(
        journal,
        writer,
        &report.id,
        Some(parent_id),
        OrchestrationRole::Worker,
        if report_failed(report) {
            OrchestrationEventKind::Reject
        } else {
            OrchestrationEventKind::Accept
        },
        json!({
            "status": report.status,
            "accepted": report.accepted,
            "rejected": report.rejected,
        }),
    );
}
