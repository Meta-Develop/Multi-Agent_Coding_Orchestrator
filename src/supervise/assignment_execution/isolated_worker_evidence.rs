use super::*;

/// Private evidence only. All writers have drained, but the report may be empty
/// and the dispatch grant may already be exhausted. No materialization follows
/// from retaining this snapshot or importing the descriptor-held observations.
pub(super) fn retain(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    parent_id: &str,
    parent_attempt: usize,
    captured: &CapturedChildAttempt<'_>,
) -> Result<(WorkerExecutionJournalEvidenceSet, PrimaryWorktreeSnapshot)> {
    if !captured.external_run.scratch_quiescence_verified() {
        bail!("isolated evidence retention requires verified scratch quiescence");
    }
    // Attempt each independent import before propagating failures. In particular,
    // an invalid report or an uncapturable candidate must not hide its journals.
    let journals = with_supervisor_artifacts(context.artifacts, |writer, journal| {
        let evidence = import_worker_execution_journals(
            writer,
            &preflight.assignment,
            &captured.incoming_scratch,
            &captured.external_run,
        )?;
        record_worker_journal_events(journal, writer, &preflight.assignment, &evidence);
        Ok(evidence)
    });
    let candidate = retain_candidate(context, preflight, parent_id, parent_attempt, captured);
    let report = with_supervisor_artifacts(context.artifacts, |writer, _| {
        if let Some(bytes) = captured.external_run.output_last_message() {
            if bytes.len() > MAX_SUPERVISOR_REPORT_BYTES {
                bail!("isolated Worker report exceeds its configured byte limit");
            }
            writer.write_bytes(
                &captured.attempt_artifacts.raw_report_relative,
                bytes,
                ArtifactFileDisposition::PrivateEvidence,
            )?;
        }
        Ok(())
    });
    let attempt = with_supervisor_artifacts(context.artifacts, |writer, _| {
        retain_external_attempt_evidence(
            writer,
            &ExternalAttemptEvidenceContext {
                incoming_scratch: &captured.incoming_scratch,
                capture_scratch: &captured.capture_scratch,
                artifacts: &captured.attempt_artifacts,
                external_run: &captured.external_run,
                external_command: &captured.command,
                raw_report_validated: false,
                runtime: captured.launch_runtime,
            },
        )
    });
    let mut errors = Vec::new();
    for (label, result) in [
        ("journals", journals.as_ref().map(|_| ())),
        ("candidate", candidate.as_ref().map(|_| ())),
        ("report", report.as_ref().map(|_| ())),
        ("attempt", attempt.as_ref().map(|_| ())),
    ] {
        if let Err(error) = result {
            errors.push(format!("{label}: {error:#}"));
        }
    }
    if !errors.is_empty() {
        bail!(
            "isolated Worker evidence retention failed: {}",
            errors.join("; ")
        );
    }
    // Post-return diagnostics still reject the attempt. Keep the original sources
    // on that path too, even when every durable copy succeeded.
    if captured.post_return_error.is_none() {
        with_supervisor_artifacts(context.artifacts, |writer, _| {
            discard_invocation_scratches(
                writer,
                &captured.incoming_scratch,
                &captured.capture_scratch,
            )
        })?;
    }
    Ok((journals?, candidate?))
}

fn retain_candidate(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    parent_id: &str,
    parent_attempt: usize,
    captured: &CapturedChildAttempt<'_>,
) -> Result<PrimaryWorktreeSnapshot> {
    let before = primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?;
    if before.inspection_problem().is_some() {
        bail!("isolated candidate snapshot is incomplete");
    }
    let candidate = crate::merge::capture_exact_base_worktree_with_write_lease(
        context.repo,
        &preflight.assignment.id,
        &preflight.assignment.assigned_paths,
        preflight
            .worktree_write_lease
            .as_ref()
            .context("isolated candidate lost its lease")?,
        preflight.child_base_head,
    )?;
    let after = primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?;
    if before != after {
        bail!("isolated candidate changed during evidence capture");
    }
    let manifest = captured
        .attempt_artifacts
        .raw_report_relative
        .with_extension("candidate.json");
    let patch = manifest.with_extension("patch");
    with_supervisor_artifacts(context.artifacts, |writer, _| {
        let patch = writer.write_bytes(
            &patch,
            &candidate.raw_diff,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        writer.write_json(&manifest, &json!({
            "version":1, "run_id":context.options.run_id.as_str(),
            "parent_id":parent_id, "parent_attempt":parent_attempt,
            "assignment_id":preflight.assignment.id, "attempt":1,
            "reservation_id":captured.budget_reservation.reservation.id,
            "base_commit":preflight.child_base_head.to_string(),
            "candidate_tree":candidate.snapshot_tree.to_string(),
            "assigned_paths":preflight.assignment.assigned_paths,
            "changed_paths":candidate.changed_paths, "patch":patch,
            "worker_journal":worker_execution_journal_evidence_relative(&preflight.assignment.id, &preflight.assignment.id),
            "raw_report":captured.attempt_artifacts.raw_report_relative,
            "review_status":"pending", "acceptance_authority":false
        }), ArtifactFileDisposition::PrivateEvidence)?;
        Ok(())
    })?;
    Ok(after)
}
