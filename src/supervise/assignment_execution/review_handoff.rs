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
    let budget = 8 * 1024 / sources.len().max(1);
    let mut evidence = Vec::new();
    for (path, (worker_id, kind)) in sources {
        let bytes = writer.read_authenticated(&path, MAX_SUPERVISOR_REPORT_BYTES)?;
        let text = std::str::from_utf8(&bytes).context("Worker review evidence is not UTF-8")?;
        let mut excerpt = crate::review::bounded_review_transcript(
            text,
            &path,
            &crate::artifacts::state_auth::sha256_hex(&bytes),
            budget,
            text.len() > budget,
        )?;
        // Keep the original byte identity while applying the existing redactor
        // to the only content that is allowed to cross the review boundary.
        let redactor = crate::llm::Redactor::new();
        excerpt.head_excerpt = redactor.redact(&excerpt.head_excerpt).text;
        excerpt.tail_excerpt = redactor.redact(&excerpt.tail_excerpt).text;
        evidence.push(json!({"worker_id":worker_id, "kind":kind, "evidence":excerpt}));
    }
    Ok(Value::Array(evidence))
}
