//! Production parent-continuation launch bound to completed nested Worker evidence.
//! The frozen inbox, its turn owner, and the captured Worker evidence stay borrowed
//! for the launch lifetime. This module does not mint inbox bindings or deserialize
//! authority from reports.

use super::bound_parent_turn::BoundNestedWorkerEvidence;
use super::*;
use crate::supervise::messaging_bridge::worker_requests::frozen::WorkerInboxTurn;

const MAX_PARENT_CONTINUATION_BYTES: usize = 64 * 1024;

pub(super) fn verified_worker_completion_runtime(
    provenance: &CompletedLaunchModelProvenance,
    run: &ExternalAgentRun,
) -> Result<SupervisorRuntime> {
    let runtime = provenance.launch_runtime;
    if runtime == SupervisorRuntime::Fake {
        bail!("continuation Worker requires a real admitted runtime");
    }
    if !run.stdout.target_launch_attempted
        || !run.scratch_quiescence_verified()
        || !external_process_completed(run, runtime)
        || !external_containment_verified(run, runtime)
    {
        bail!("continuation Worker did not retain its runtime-specific completion and containment");
    }
    Ok(runtime)
}

impl<'evidence> ParentContinuationLaunch<'evidence> {
    /// Isolated siblings keep independent candidate snapshots and claims. The
    /// parent's candidate is unchanged; no serial predecessor chain is inferred.
    pub(super) fn from_bound_isolated_workers(
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        source_attempt: usize,
        current: &WorkerInboxTurn<'_>,
        completed: &'evidence bound_parent_turn::BoundIsolatedWorkers<'_, '_>,
    ) -> Result<Self> {
        let (view, workers) = completed.revalidate(context, preflight, source_attempt, current)?;
        let attempt = source_attempt
            .checked_add(1)
            .context("isolated parent turn overflow")?;
        let mut summaries = Vec::new();
        let mut held_workers = Vec::new();
        let mut ordered_worker_ids = Vec::new();
        for (request, worker) in view.requests.iter().zip(workers) {
            let evidence = worker.evidence();
            let bytes = evidence
                .run()
                .output_last_message()
                .context("isolated continuation lost the held Worker capture")?;
            if bytes.len() > MAX_PARENT_CONTINUATION_BYTES {
                bail!("isolated continuation Worker capture exceeds its bounded payload");
            }
            let runtime =
                verified_worker_completion_runtime(evidence.model_provenance(), evidence.run())?;
            summaries.push(json!({
                "request_id":request.request_id, "worker_id":request.worker_id,
                "worker_attempt":worker.worker_attempt(), "worker_report":evidence.report(),
                "observed_changed_paths":evidence.observed_changed_paths(),
                "launch_runtime":runtime, "launched_model":evidence.model_provenance().launched_model,
                "report_artifact":evidence.artifacts().raw_report_relative,
                "execution_workspace":"isolated_sibling", "worktree":worker.lease().record().name,
                "claim_token":worker.claim().token.get()
            }));
            if serde_json::to_vec(&summaries)?.len() > MAX_PARENT_CONTINUATION_BYTES {
                bail!("isolated continuation summaries exceed the bounded payload");
            }
            held_workers.push(evidence);
            ordered_worker_ids.push(request.worker_id.clone());
        }
        let contract = Self {
            run_id: context.options.run_id.as_str().to_string(),
            assignment: preflight.assignment.clone(),
            source_attempt,
            attempt,
            worktree: preflight.worktree.path.clone(),
            candidate_snapshot: completed.parent_candidate().clone(),
            claim_token: preflight.claim.token.get(),
            semantic_token: preflight.semantic_token,
            ordered_worker_ids,
            summaries: serde_json::to_string(&summaries)?,
            _held_workers: held_workers,
        };
        contract.revalidate(context, preflight, attempt)?;
        completed.revalidate(context, preflight, source_attempt, current)?;
        Ok(contract)
    }

    /// Builds a continuation from Worker results already bound to the frozen inbox.
    /// `completed.revalidate` is the only source of request order and held evidence.
    pub(super) fn from_bound_completed_workers(
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        source_attempt: usize,
        current: &WorkerInboxTurn<'_>,
        completed: &'evidence BoundNestedWorkerEvidence<'_, '_>,
    ) -> Result<Self> {
        let (view, workers) = completed.revalidate(context, preflight, source_attempt, current)?;
        let attempt = source_attempt
            .checked_add(1)
            .context("parent turn overflow")?;
        if source_attempt == 0 || workers.is_empty() || workers.len() != view.requests.len() {
            bail!("continuation differs from the held parent yield and completed Worker set");
        }
        let run_id = context.options.run_id.as_str();
        let parent_id = preflight.assignment.id.as_str();
        let mut seen_worker_ids = BTreeSet::new();
        let mut seen_request_ids = BTreeSet::new();
        let mut summaries = Vec::new();
        let mut held_workers = Vec::new();
        let mut ordered_worker_ids = Vec::new();
        for (index, (request, bound)) in view.requests.iter().zip(workers.iter()).enumerate() {
            let request_id = request.request_id.as_str();
            let worker_id = request.worker_id.as_str();
            let (sequence, bound_request_id, bound_worker_id) = bound.identity();
            if sequence != index + 1
                || bound_request_id != request_id
                || bound_worker_id != worker_id
                || !seen_request_ids.insert(request_id.to_string())
                || !seen_worker_ids.insert(worker_id.to_string())
            {
                bail!("continuation contains duplicate completed Worker identities");
            }
            let mut authored = preflight
                .assignment
                .worker_assignments
                .iter()
                .filter(|worker| worker.id == worker_id);
            let worker = authored
                .next()
                .context("continuation Worker is not authored")?;
            if authored.next().is_some()
                || worker.role != AgentRole::Worker
                || worker.effective_role_category() != RoleCategory::NonDelegatingTerminalWorker
            {
                bail!("continuation requires one exact authored terminal Worker");
            }
            let evidence = bound.evidence();
            let worker_runtime =
                verified_worker_completion_runtime(evidence.model_provenance(), evidence.run())?;
            let report_bytes = evidence
                .run()
                .output_last_message()
                .context("continuation requires a descriptor-held Worker result")?;
            let expected_artifact = PathBuf::from("nested")
                .join(parent_id)
                .join(format!("attempt-{source_attempt}"))
                .join(worker_id)
                .join("report.json");
            if report_bytes.len() > MAX_PARENT_CONTINUATION_BYTES
                || evidence.artifacts().raw_report_relative != expected_artifact
                || evidence.artifacts().prompt_path
                    != context
                        .run_dir
                        .join("nested")
                        .join(parent_id)
                        .join(format!("attempt-{source_attempt}"))
                        .join(worker_id)
                        .join("prompt.md")
                || evidence.run().cwd != preflight.worktree.path
                || !evidence.run().sandbox_denials().is_empty()
                || !evidence.run().gate_denials().is_empty()
                || evidence.run().external_side_effect_state().is_some()
                || evidence.run().environment_blocked()
                || evidence.report().role != AgentRole::Worker
                || evidence.report().id != worker_id
                || evidence.report().assigned_paths != worker.assigned_paths
                || evidence.report().semantic_symbols != worker.semantic_symbols
                || evidence.report().semantic_modules != worker.semantic_modules
                || evidence.report().claim_token != Some(preflight.claim.token.get())
                || evidence.report().semantic_intent_token != preflight.semantic_token
                || evidence.report().no_further_delegation != Some(true)
                || evidence.report().files_changed != *evidence.observed_changed_paths()
                || evidence.journals().len() != 1
                || !evidence.journals().get(worker_id).is_some_and(|journal| {
                    matches!(journal.status, WorkerExecutionJournalStatus::Loaded(_))
                })
            {
                bail!(
                    "continuation Worker evidence is incomplete, oversized or has a different binding"
                );
            }
            if read_worker_report(Some(report_bytes), &expected_artifact)?.report
                != *evidence.report()
            {
                bail!("continuation Worker report differs from its held capture");
            }
            summaries.push(json!({
                "request_id": request_id,
                "worker_id": worker_id,
                "worker_report": evidence.report(),
                "observed_changed_paths": evidence.observed_changed_paths(),
                "launch_runtime": worker_runtime,
                "launched_model": evidence.model_provenance().launched_model,
                "report_artifact": expected_artifact,
            }));
            if serde_json::to_vec(&summaries)?.len() > MAX_PARENT_CONTINUATION_BYTES {
                bail!("continuation Worker summaries exceed the payload limit");
            }
            held_workers.push(evidence);
            ordered_worker_ids.push(worker_id.to_string());
        }
        if ordered_worker_ids.len() != view.requests.len() || held_workers.len() != workers.len() {
            bail!("continuation includes an unrequested Worker result");
        }
        let contract = Self {
            run_id: run_id.to_string(),
            assignment: preflight.assignment.clone(),
            source_attempt,
            attempt,
            worktree: preflight.worktree.path.clone(),
            candidate_snapshot: primary_worktree_snapshot(
                &preflight.worktree.path,
                context.execution_runtime,
            )?,
            claim_token: preflight.claim.token.get(),
            semantic_token: preflight.semantic_token,
            ordered_worker_ids,
            summaries: serde_json::to_string(&summaries)?,
            _held_workers: held_workers,
        };
        contract.revalidate(context, preflight, attempt)?;
        completed.revalidate(context, preflight, source_attempt, current)?;
        Ok(contract)
    }
}
