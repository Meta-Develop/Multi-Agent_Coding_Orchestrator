use super::*;

/// Capture evidence independently of the report's success flags. A failed or
/// partial report may still describe a useful candidate, but grants no authority.
pub(super) fn capture_candidate(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    report: &mut OrchestratorReviewReport,
    attempt: usize,
) -> Result<SupervisorCandidateInspection> {
    if preflight.primary_scope_baseline.is_some() && !report.decomposition_completions.is_empty() {
        bail!("primary-worktree execution does not support megafile decomposition evidence");
    }
    let inspection = if preflight.primary_scope_baseline.is_none() {
        bind_supervisor_decomposition_candidate(
            context.repo,
            &preflight.assignment,
            report,
            preflight
                .worktree_write_lease
                .as_ref()
                .context("review candidate has no write lease")?,
            context.worktree_creation.expected_source_head(),
        )?
        .map(Ok)
        .unwrap_or_else(|| inspect_assignment_candidate(context, preflight))?
    } else {
        inspect_assignment_candidate(context, preflight)?
    };
    // Fake simulations retain their existing non-executing inspection boundary.
    if context.options.runtime == SupervisorRuntime::Fake
        && context.execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation
    {
        return Ok(inspection);
    }
    let (base, tree, patch) = if let Some(baseline) = &preflight.primary_scope_baseline {
        let current = capture_primary_scope_snapshot(
            context.repo,
            &preflight.assignment.assigned_paths,
            false,
            context.execution_runtime,
        )?;
        (
            inspection.binding.primary_head.clone(),
            None,
            render_primary_scope_diff(baseline, &current)?.into_bytes(),
        )
    } else if let Some(base) = context.worktree_creation.expected_source_head() {
        let candidate = crate::merge::capture_exact_base_worktree_with_write_lease(
            context.repo,
            &preflight.assignment.id,
            &preflight.assignment.assigned_paths,
            preflight
                .worktree_write_lease
                .as_ref()
                .context("review candidate lost its lease")?,
            base,
        )?;
        (
            Some(base.to_string()),
            Some(candidate.snapshot_tree.to_string()),
            candidate.raw_diff,
        )
    } else {
        let candidate = collect_agent_result_with_evidence_and_write_lease(
            MergeCollectOptions {
                repo: context.repo.to_path_buf(),
                agent_id: preflight.assignment.id.clone(),
                claimed_paths: preflight.assignment.assigned_paths.clone(),
                include_full_diff: false,
                diff_summary_char_limit: 1,
                validations: Vec::new(),
            },
            ValidationEvidenceBundle::default(),
            preflight
                .worktree_write_lease
                .as_ref()
                .context("review candidate lost its lease")?,
        )?;
        if candidate.validation_binding != inspection.binding {
            bail!("candidate changed while retaining the review patch");
        }
        (
            candidate
                .metadata
                .merge_base
                .or(candidate.metadata.primary_head),
            Some(candidate.snapshot_tree.to_string()),
            candidate.raw_diff,
        )
    };
    if inspect_assignment_candidate(context, preflight)? != inspection {
        bail!("candidate changed while retaining review evidence");
    }
    let manifest =
        PathBuf::from("reports").join(format!("{}.candidate.json", preflight.assignment.id));
    with_supervisor_artifacts(context.artifacts, |writer, _| {
        let patch = writer.write_bytes(
            manifest.with_extension("patch"),
            &patch,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        writer.write_json(
            &manifest,
            &json!({
                "version":1, "run_id":context.options.run_id.as_str(),
                "assignment_id":preflight.assignment.id, "attempt":attempt, "base_commit":base,
                "candidate_tree":tree, "candidate_binding":inspection.binding,
                "assigned_paths":preflight.assignment.assigned_paths,
                "changed_paths":inspection.changed_paths, "patch":patch,
                "report_status":report.status, "acceptance_authority":false
            }),
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        Ok(())
    })?;
    Ok(inspection)
}

/// Read only supervisor-imported artifacts, never paths supplied in a report.
/// Bound each original separately so a long native stream cannot hide journals.
pub(super) fn worker_evidence(
    writer: &ArtifactRunWriter,
    journals: &WorkerExecutionJournalEvidenceSet,
) -> Result<Value> {
    let mut sources = BTreeMap::new();
    for (worker_id, journal) in journals {
        let path = &journal.evidence_relative_path;
        if writer
            .read_optional_authenticated(path, MAX_SUPERVISOR_REPORT_BYTES)?
            .is_some()
        {
            sources.insert(path.clone(), (worker_id, "worker_journal"));
        }
        if path.starts_with("nested") {
            let root = path
                .parent()
                .and_then(Path::parent)
                .context("nested journal has no Worker root")?;
            sources.insert(
                root.join("stdout.jsonl"),
                (worker_id, "worker_native_transcript"),
            );
        }
    }
    // Reserve the array brackets and separators as part of the packet bound.
    let budget = (WORKER_REVIEW_EVIDENCE_BYTES - 2) / sources.len().max(1);
    let budget = budget.saturating_sub(1);
    let mut evidence = Vec::new();
    for (path, (worker_id, kind)) in sources {
        let bytes = writer.read_authenticated(&path, MAX_SUPERVISOR_REPORT_BYTES)?;
        evidence.push(select_worker_operations(
            worker_id, kind, &path, &bytes, budget,
        )?);
    }
    let evidence = Value::Array(evidence);
    if serde_json::to_vec(&evidence)?.len() > WORKER_REVIEW_EVIDENCE_BYTES {
        bail!("Worker evidence exceeds the finite review packet budget");
    }
    Ok(evidence)
}

// The bound covers the serialized array, including redacted content, record
// coordinates/hashes and omission manifests. In qualification -04 the journal
// was 10,049 B and the stream 573,420 B, but its 21 operation events were only
// 35,492 B. 128 KiB allows those whole records plus JSON escaping/metadata while
// excluding the much larger reasoning/usage traffic. Sources receive equal
// shares so a noisy stream cannot consume a journal's allowance.
const WORKER_REVIEW_EVIDENCE_BYTES: usize = 128 * 1024;
const WHOLE_WORKER_SOURCE_BYTES: usize = 16 * 1024;

struct ReviewOperationRecord<'a> {
    line: usize,
    start: usize,
    text: &'a str,
    kind: &'static str,
    required: bool,
    selected: Option<Value>,
    omission: &'static str,
}

impl ReviewOperationRecord<'_> {
    fn end(&self) -> usize {
        self.start + self.text.len()
    }

    fn select(&mut self, redactor: &crate::llm::Redactor) {
        self.selected = Some(json!({
            "line":self.line, "byte_start":self.start, "byte_end":self.end(),
            "sha256":crate::artifacts::state_auth::sha256_hex(self.text.as_bytes()),
            "kind":self.kind, "content":redactor.redact(self.text).text,
        }));
    }
}

// Retain every command/file-change boundary, including final diff observations.
// This includes the journal's matching native events without guessing from a
// shell command string or trusting provider output as execution authority.
fn native_operation_kind(value: &Value) -> Option<&'static str> {
    let method = value
        .get("method")
        .or_else(|| value.get("type"))?
        .as_str()?;
    if matches!(method, "turn/diff/updated" | "turn.diff.updated") {
        return Some("native_diff");
    }
    if !matches!(
        method,
        "item/started" | "item/completed" | "item.started" | "item.completed"
    ) {
        return None;
    }
    let item = value
        .pointer("/params/item")
        .or_else(|| value.get("item"))?;
    match item.get("type")?.as_str()? {
        "commandExecution" | "command_execution" => Some("native_command"),
        "fileChange" | "file_change" => Some("native_file_change"),
        _ => None,
    }
}

fn operation_evidence_value(
    worker_id: &str,
    kind: &str,
    path: &Path,
    bytes: &[u8],
    records: &[ReviewOperationRecord<'_>],
    budget: usize,
) -> Value {
    let mut ranges = Vec::new();
    let mut omitted_records = 0;
    let mut omitted_bytes = 0;
    let mut required_records_omitted = 0;
    let mut index = 0;
    while index < records.len() {
        if records[index].selected.is_some() {
            index += 1;
            continue;
        }
        let first = index;
        let mut reasons = BTreeMap::<&str, usize>::new();
        let mut kinds = BTreeMap::<&str, usize>::new();
        while index < records.len() && records[index].selected.is_none() {
            let record = &records[index];
            *reasons.entry(record.omission).or_default() += 1;
            *kinds.entry(record.kind).or_default() += 1;
            required_records_omitted += usize::from(record.required);
            omitted_bytes += record.text.len();
            omitted_records += 1;
            index += 1;
        }
        let start = records[first].start;
        let end = records[index - 1].end();
        ranges.push(json!({
            "first_line":records[first].line, "last_line":records[index - 1].line,
            "byte_start":start, "byte_end":end, "records":index - first,
            "sha256":crate::artifacts::state_auth::sha256_hex(&bytes[start..end]),
            "kinds":kinds, "reasons":reasons,
        }));
    }
    json!({"worker_id":worker_id, "kind":kind, "evidence":{
        "version":2, "source":path, "sha256":crate::artifacts::state_auth::sha256_hex(bytes),
        "original_bytes":bytes.len(), "record_count":records.len(),
        "source_budget_bytes":budget, "packet_budget_bytes":WORKER_REVIEW_EVIDENCE_BYTES,
        "selection":"whole_short_sources_when_share_allows_else_journal_operations_and_native_command_file_change_diff_events",
        "hashes":"original_bytes_before_redaction; offsets_zero_based_end_exclusive; lines_one_based",
        "records":records.iter().filter_map(|record| record.selected.as_ref()).collect::<Vec<_>>(),
        "omission_manifest":{
            "omitted_records":omitted_records, "omitted_bytes":omitted_bytes,
            "required_records_omitted":required_records_omitted, "ranges":ranges,
        },
    }})
}

fn select_worker_operations(
    worker_id: &str,
    kind: &str,
    path: &Path,
    bytes: &[u8],
    budget: usize,
) -> Result<Value> {
    let text = std::str::from_utf8(bytes).context("Worker review evidence is not UTF-8")?;
    let whole = bytes.len() <= WHOLE_WORKER_SOURCE_BYTES;
    let journal = kind == "worker_journal";
    let mut offset = 0;
    let mut records = text
        .split_inclusive('\n')
        .enumerate()
        .map(|(index, text)| {
            let native = if journal {
                None
            } else {
                serde_json::from_str::<Value>(text)
                    .ok()
                    .as_ref()
                    .and_then(native_operation_kind)
            };
            let record = ReviewOperationRecord {
                line: index + 1,
                start: offset,
                text,
                kind: if journal {
                    "journal_operation"
                } else {
                    native.unwrap_or("other_native_event")
                },
                required: journal || native.is_some(),
                selected: None,
                omission: if journal || native.is_some() || whole {
                    "source_budget"
                } else {
                    "non_operation_event"
                },
            };
            offset += text.len();
            record
        })
        .collect::<Vec<_>>();
    let redactor = crate::llm::Redactor::new();
    if whole {
        for record in &mut records {
            record.select(&redactor);
        }
        let full = operation_evidence_value(worker_id, kind, path, bytes, &records, budget);
        if serde_json::to_vec(&full)?.len() <= budget {
            return Ok(full);
        }
        for record in &mut records {
            record.selected = None;
        }
    }
    let baseline = operation_evidence_value(worker_id, kind, path, bytes, &records, budget);
    let baseline_len = serde_json::to_vec(&baseline)?.len();
    if baseline_len > budget {
        bail!("Worker review source metadata exceeds its finite {budget}-byte share");
    }
    let mut remaining = budget - baseline_len;
    // Selecting one record can split one omission range in two. Reserve 512 B
    // for the additional range (coordinates, counts, kinds, reasons and hash),
    // independently of the exact serialized, redacted record size.
    for record in records.iter_mut().rev() {
        if !record.required && !whole {
            continue;
        }
        record.select(&redactor);
        let cost = serde_json::to_vec(record.selected.as_ref().unwrap())?.len() + 512;
        if cost <= remaining {
            remaining -= cost;
        } else {
            record.selected = None;
            record.omission = if cost > budget - baseline_len {
                "record_exceeds_source_budget"
            } else {
                "source_budget"
            };
        }
    }
    let selected = operation_evidence_value(worker_id, kind, path, bytes, &records, budget);
    if serde_json::to_vec(&selected)?.len() > budget {
        bail!("Worker operation evidence exceeded its finite serialized budget");
    }
    Ok(selected)
}

pub(super) struct NativeReviewSources<'a> {
    pub assignment: &'a OrchestratorAssignment,
    pub sources: &'a [super::super::target_containment::ReviewAttemptSource],
    pub source_attempt: usize,
    pub journals: &'a WorkerExecutionJournalEvidenceSet,
    pub candidate: &'a SupervisorCandidateInspection,
    pub required_for_acceptance: bool,
    pub repo: &'a Path,
    pub evidence_only_source: Option<&'a EvidenceOnlyReauditSource>,
}

/// Bind existing native receipts to the exact candidate under review. This
/// adds no probes, execution permission, completion grant, or model-authored
/// input. Narrow lenses never serialize validation_bindings.
pub(super) fn execution_evidence(
    writer: &ArtifactRunWriter,
    sources: NativeReviewSources<'_>,
) -> Result<(Value, Value)> {
    let NativeReviewSources {
        assignment,
        sources,
        source_attempt,
        journals,
        candidate,
        required_for_acceptance,
        repo,
        evidence_only_source,
    } = sources;
    if source_attempt == 0
        || sources.is_empty()
        || sources
            .iter()
            .any(|source| !source.matches_assignment(assignment))
        || candidate.binding.agent_id != assignment.id
        || candidate.binding.clone().canonicalized()? != candidate.binding
    {
        bail!("native review source assignment, attempt, or candidate binding mismatch");
    }
    let mut targets = Vec::new();
    let mut physical_turns = BTreeSet::new();
    for source in sources {
        let mut target = super::super::target_containment::bound_review_evidence(writer, source)?;
        if !physical_turns.insert(target["binding"]["attempt"].as_u64()) {
            bail!("native review repeats a parent physical turn");
        }
        target["source_attempt"] = json!(source_attempt);
        target["execution_epoch"] = json!("current_assignment_execution");
        // Current candidate binding identifies the review subject. Commands in
        // an earlier parent turn do not attest to the later Worker candidate.
        target["candidate_at_execution"] = json!("unknown; not observed by command capture");
        targets.push(target);
    }
    let historical = evidence_only_source
        .filter(|_| required_for_acceptance && !assignment.worker_assignments.is_empty())
        .map(|source| historical_worker_evidence(repo, assignment, source, candidate))
        .transpose()?;
    let worker_operations = if let Some((operations, historical_targets)) = historical {
        targets.extend(historical_targets);
        operations
    } else {
        for (worker, journal) in journals {
            if !journal.evidence_relative_path.starts_with("nested") {
                continue;
            }
            let expected = PathBuf::from("nested")
                .join(&assignment.id)
                .join(format!("attempt-{source_attempt}"))
                .join(worker)
                .join("journals")
                .join(format!("{worker}.jsonl"));
            if journal.evidence_relative_path != expected
                || !assignment
                    .worker_assignments
                    .iter()
                    .any(|assigned| assigned.id == *worker && assigned.role == AgentRole::Worker)
            {
                bail!("native review journal belongs to a foreign Worker or parent attempt");
            }
            // Keep the journal's separate authentication and occurrence controls.
            writer.read_authenticated(&expected, MAX_SUPERVISOR_REPORT_BYTES)?;
            let mut target = super::super::target_containment::nested_review_evidence(
                writer,
                &assignment.id,
                worker,
                source_attempt,
            )?;
            target["source_attempt"] = json!(source_attempt);
            target["candidate_at_execution"] = json!("unknown; not observed by command capture");
            targets.push(target);
        }
        for worker in &assignment.worker_assignments {
            if !journals
                .get(&worker.id)
                .is_some_and(|journal| journal.evidence_relative_path.starts_with("nested"))
            {
                targets.push(json!({
                    "worker_id": worker.id,
                    "commands_status": "unavailable_independent_native_capture",
                    "review_complete": false,
                    "acceptance_authority": false,
                }));
            }
        }
        worker_evidence(writer, journals)?
    };
    Ok((
        worker_operations,
        json!({
            "version": 1,
            "assignment_id": assignment.id,
            "source_attempt": source_attempt,
            "candidate_binding": candidate.binding,
            "required_for_acceptance": required_for_acceptance,
            "review_complete": targets.iter().all(|target|
                target["review_complete"].as_bool() == Some(true)),
            "targets": targets,
            "acceptance_authority": false,
        }),
    ))
}

/// Re-audit reuses the finalized owning run's descriptive evidence. Each link
/// uses the existing authenticated source verifier and the unchanged candidate;
/// no historical command or grant is reconstructed.
fn historical_worker_evidence(
    repo: &Path,
    assignment: &OrchestratorAssignment,
    source: &EvidenceOnlyReauditSource,
    candidate: &SupervisorCandidateInspection,
) -> Result<(Value, Vec<Value>)> {
    if candidate.binding != source.operation.preserved_candidate_binding {
        bail!("historical Worker evidence belongs to a changed candidate");
    }
    let mut operation = source.operation.clone();
    for _ in 0..MAX_EVIDENCE_ONLY_REAUDITS {
        let reader =
            ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, &operation.source_run_id)?;
        let plan_bytes = reader.read("assignments/supervisor-plan.json")?;
        let loaded = parse_supervisor_plan_with_consultant_in_repo(
            std::str::from_utf8(&plan_bytes)?,
            Some(repo),
        )?;
        let verified = verify_evidence_only_reaudit_source(
            repo,
            &operation,
            assignment,
            loaded.plan_metadata.task_routing_assessment.as_ref(),
        )?;
        if verified.report.worker_reports != source.report.worker_reports
            || operation.preserved_candidate_binding != candidate.binding
        {
            bail!("historical Worker report lineage or candidate binding changed");
        }
        let manifest_path =
            PathBuf::from("reports").join(format!("{}.candidate.json", assignment.id));
        let manifest: Value = serde_json::from_slice(&reader.read(&manifest_path)?)?;
        if manifest["run_id"] != operation.source_run_id.as_str()
            || manifest["assignment_id"] != assignment.id
            || manifest["candidate_binding"] != serde_json::to_value(&candidate.binding)?
        {
            bail!("historical Worker candidate manifest does not match its source");
        }
        if let Some(predecessor) = loaded.plan_metadata.evidence_only_reaudit {
            if predecessor.assignment_id != assignment.id
                || predecessor.preserved_candidate_binding != candidate.binding
                || predecessor.attempt.checked_add(1) != Some(operation.attempt)
            {
                bail!("historical Worker re-audit lineage is inconsistent");
            }
            operation = predecessor;
            continue;
        }
        let attempt = manifest["attempt"]
            .as_u64()
            .and_then(|attempt| usize::try_from(attempt).ok())
            .filter(|attempt| *attempt > 0)
            .context("historical Worker candidate has no source attempt")?;
        let source_count = assignment
            .worker_assignments
            .len()
            .checked_mul(2)
            .context("historical Worker source count overflow")?;
        let budget = ((WORKER_REVIEW_EVIDENCE_BYTES - 2) / source_count.max(1)).saturating_sub(1);
        let mut operations = Vec::new();
        let mut targets = Vec::new();
        for worker in &assignment.worker_assignments {
            let root = PathBuf::from("nested")
                .join(&assignment.id)
                .join(format!("attempt-{attempt}"))
                .join(&worker.id);
            let report_path = root.join("report.json");
            let report_bytes = reader.read(&report_path)?;
            let report = read_worker_report(Some(&report_bytes), &report_path)?.report;
            if worker.role != AgentRole::Worker
                || report.id != worker.id
                || !verified
                    .report
                    .worker_reports
                    .iter()
                    .any(|held| held == &report)
            {
                bail!("historical Worker report differs from its owning source capture");
            }
            let journal = root.join("journals").join(format!("{}.jsonl", worker.id));
            let journal_bytes = reader.read(&journal)?;
            parse_worker_execution_journal(&journal_bytes, &journal)?;
            let transcript = root.join("stdout.jsonl");
            let transcript_bytes = reader.read(&transcript)?;
            for (path, bytes, kind) in [
                (&journal, &journal_bytes, "worker_journal"),
                (&transcript, &transcript_bytes, "worker_native_transcript"),
            ] {
                let mut evidence = select_worker_operations(&worker.id, kind, path, bytes, budget)?;
                evidence["execution_epoch"] = json!("historical_worker_execution");
                evidence["source_run_id"] = json!(operation.source_run_id);
                evidence["source_candidate_binding"] = json!(candidate.binding);
                operations.push(evidence);
            }
            let mut target = super::super::target_containment::historical_nested_review_evidence(
                &reader,
                &assignment.id,
                &worker.id,
                attempt,
            )?;
            target["execution_epoch"] = json!("historical_worker_execution");
            target["source_attempt"] = json!(attempt);
            target["source_candidate_binding"] = json!(candidate.binding);
            target["worker_report_sha256"] =
                json!(crate::artifacts::state_auth::sha256_hex(&report_bytes));
            target["candidate_at_execution"] = json!("unknown; not observed by command capture");
            targets.push(target);
        }
        if verified.report.worker_reports.len() != assignment.worker_assignments.len() {
            bail!("historical Worker source does not cover the authored Worker inventory");
        }
        let operations = Value::Array(operations);
        if serde_json::to_vec(&operations)?.len() > WORKER_REVIEW_EVIDENCE_BYTES {
            bail!("historical Worker evidence exceeds the finite review packet budget");
        }
        return Ok((operations, targets));
    }
    bail!("historical Worker evidence exceeds the authenticated re-audit lineage bound")
}
