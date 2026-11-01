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
    for record in &mut records {
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
