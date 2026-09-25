//! Serial, supervisor-owned execution of one authored terminal Worker. The parent
//! retains its write lease, claim, cancellation and recovery boundary throughout.
//! There is deliberately no wire request, scheduler or report-driven entry point.

use super::*;

/// Evidence for the enclosing parent's gate, never an accepted/materialized change.
pub(super) struct NestedWorkerAttemptEvidence {
    report: WorkerReport,
    journals: WorkerExecutionJournalEvidenceSet,
    artifacts: ChildAttemptArtifacts,
    run: ExternalAgentRun,
    observed_changed_paths: Vec<PathBuf>,
    model_provenance: CompletedLaunchModelProvenance,
    // Exact snapshots used below for scope and report validation; never recaptured.
    candidate_before: PrimaryWorktreeSnapshot,
    candidate_after: PrimaryWorktreeSnapshot,
}

impl NestedWorkerAttemptEvidence {
    pub(super) fn report(&self) -> &WorkerReport {
        &self.report
    }
    pub(super) fn journals(&self) -> &WorkerExecutionJournalEvidenceSet {
        &self.journals
    }
    pub(super) fn artifacts(&self) -> &ChildAttemptArtifacts {
        &self.artifacts
    }
    pub(super) fn run(&self) -> &ExternalAgentRun {
        &self.run
    }
    pub(super) fn observed_changed_paths(&self) -> &Vec<PathBuf> {
        &self.observed_changed_paths
    }
    pub(super) fn model_provenance(&self) -> &CompletedLaunchModelProvenance {
        &self.model_provenance
    }
    pub(super) fn candidate_snapshots(
        &self,
    ) -> (&PrimaryWorktreeSnapshot, &PrimaryWorktreeSnapshot) {
        (&self.candidate_before, &self.candidate_after)
    }
}

// Deliberate corruptions for the existing negative continuation tests only.
// Production consumers receive shared references and cannot rewrite evidence.
#[cfg(test)]
pub(super) fn corrupt_continuation_evidence_for_test(
    completed: &mut [NestedWorkerAttemptEvidence],
    case: &str,
    max_bytes: usize,
) -> Result<()> {
    match case {
        "continuation-duplicate" => completed[1].report.id = "worker".into(),
        "continuation-forged-id" => completed[1].report.id = "outside".into(),
        "continuation-forged-summary" => completed[0].report.remaining_risk = "substituted".into(),
        "continuation-wrong-attempt-artifact" => {
            completed[0].artifacts.raw_report_relative =
                "nested/parent/attempt-99/worker/report.json".into()
        }
        "continuation-missing-journal" => completed[0].journals.clear(),
        "continuation-restored" => {
            completed[0].run = serde_json::from_value(serde_json::to_value(&completed[0].run)?)?
        }
        "continuation-oversize" => {
            completed[0].report.remaining_risk = "x".repeat(max_bytes);
            completed[0].run.output_last_message = Some(serde_json::to_vec(&completed[0].report)?);
        }
        _ => {}
    }
    Ok(())
}

fn terminal_subject(
    parent: &OrchestratorAssignment,
    worker_id: &str,
) -> Result<OrchestratorAssignment> {
    if parent.role != AgentRole::ChildOrchestrator || parent.phase != AssignmentPhase::Execution {
        bail!("nested execution requires an execution-phase ChildOrchestrator");
    }
    let mut workers = parent
        .worker_assignments
        .iter()
        .filter(|w| w.id == worker_id);
    let worker = workers
        .next()
        .context("nested worker is not authored under this parent")?;
    if workers.next().is_some()
        || worker.id == parent.id
        || worker.role != AgentRole::Worker
        || worker.effective_role_category() != RoleCategory::NonDelegatingTerminalWorker
    {
        bail!("nested execution requires one exact authored terminal Worker");
    }
    // This projection is for existing terminal prompt/model/journal helpers only.
    // It must never be used to acquire or identify a worktree or a path claim.
    Ok(OrchestratorAssignment {
        id: worker.id.clone(),
        phase: AssignmentPhase::Execution,
        runtime: None,
        role: AgentRole::Worker,
        role_category: Some(RoleCategory::NonDelegatingTerminalWorker),
        selection_source: worker.selection_source,
        assigned_paths: worker.assigned_paths.clone(),
        semantic_symbols: worker.semantic_symbols.clone(),
        semantic_modules: worker.semantic_modules.clone(),
        task: worker.task.clone().or_else(|| parent.task.clone()),
        worker_assignments: Vec::new(),
        environment_requirements: parent
            .environment_requirements
            .iter()
            .chain(&worker.environment_requirements)
            .cloned()
            .collect(),
        licensed_breakage: parent.licensed_breakage.clone(),
        notes: parent.notes.clone(),
        decision_refs: parent.decision_refs.clone(),
    })
}

struct NestedArtifactLayout {
    root: PathBuf,
    incoming: PathBuf,
    capture: PathBuf,
}

impl NestedArtifactLayout {
    fn new(parent: &str, worker: &str, attempt: usize, scratch_index: usize) -> Result<Self> {
        if attempt == 0
            || normalize_agent_id(parent)? != parent
            || normalize_agent_id(worker)? != worker
        {
            bail!("nested artifact identity must be canonical and attempt nonzero");
        }
        // Persistent evidence uses distinct components. Scratch ordinals are allocated
        // beyond all top-level assignments, using the existing authenticated grammar.
        let identity = PathBuf::from(parent)
            .join(format!("attempt-{attempt}"))
            .join(worker);
        let (incoming, capture) = invocation_scratch_names(scratch_index, attempt, false, true);
        Ok(Self {
            root: PathBuf::from("nested").join(&identity),
            incoming,
            capture,
        })
    }

    fn artifacts(&self, run_dir: &Path) -> ChildAttemptArtifacts {
        ChildAttemptArtifacts {
            prompt_path: run_dir.join(&self.root).join("prompt.md"),
            report_path: run_dir.join(&self.incoming).join("report.json"),
            log_path: run_dir.join(&self.capture).join("events.jsonl"),
            raw_report_relative: self.root.join("report.json"),
            raw_stdout_relative: self.root.join("stdout.jsonl"),
            command_record_relative: self.root.join("command.json"),
        }
    }
}

fn nested_scratch_index(
    plan: &SupervisorPlan,
    parent_index: usize,
    parent: &str,
    worker: &str,
) -> Result<usize> {
    let assignment = plan
        .assignments
        .get(parent_index)
        .filter(|a| a.id == parent)
        .context("nested worker parent index does not match the current plan")?;
    let ordinal = assignment
        .worker_assignments
        .iter()
        .position(|w| w.id == worker)
        .context("nested worker is not present in the current plan")?;
    plan.assignments[..parent_index]
        .iter()
        .try_fold(plan.assignments.len(), |offset, a| {
            offset
                .checked_add(a.worker_assignments.len())
                .context("nested scratch ordinal overflow")
        })?
        .checked_add(ordinal)
        .context("nested scratch ordinal overflow")
}

fn validate_report_binding(
    report: &WorkerReport,
    subject: &OrchestratorAssignment,
    claim: &PathClaim,
    semantic_token: Option<u64>,
) -> Result<()> {
    if report.id != subject.id
        || report.role != AgentRole::Worker
        || report.assigned_paths != subject.assigned_paths
        || report.semantic_symbols != subject.semantic_symbols
        || report.semantic_modules != subject.semantic_modules
        || report.claim_token != Some(claim.token.get())
        || report.semantic_intent_token != semantic_token
        || report.no_further_delegation != Some(true)
        || report.assignment_kind != AssignmentKind::Ordinary
        || report.target_path.is_some()
        || normalize_paths(report.files_changed.clone())? != report.files_changed
        || report.files_changed.iter().any(|path| {
            !subject
                .assigned_paths
                .iter()
                .any(|scope| path_is_covered_by_claim(path, scope))
        })
    {
        bail!("nested worker report does not match the admitted terminal subject and parent resources");
    }
    Ok(())
}

/// One execution per worker per enclosing attempt. The exclusive permit borrow
/// serializes nested execution while frozen evidence shares the preflight lease.
/// A distinct outcome cannot bypass that one-shot permit. Its caller must
/// already own the enclosing assignment's started checkpoint; nested attempts do
/// not create a second top-level dispatch or an independently resumable assignment.
pub(super) fn execute_nested_worker_attempt(
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    permit: &mut NestedTurnExecutionPermit<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
    parent_attempt: usize,
    worker_id: &str,
) -> Result<NestedWorkerAttemptEvidence> {
    permit.revalidate(preflight, parent_attempt)?;
    if context.execution_runtime != SupervisorExecutionRuntime::Verified
        || context.execution_target.is_some()
        || context.evidence_only_reaudit.is_some()
    {
        bail!("nested execution requires verified managed parent execution");
    }
    let mut subject = terminal_subject(&preflight.assignment, worker_id)?;
    let worker = preflight
        .assignment
        .worker_assignments
        .iter()
        .find(|w| w.id == worker_id)
        .unwrap();
    let metadata =
        worker_assignment_metadata(context.assignment_metadata, &preflight.assignment, worker);
    if metadata.kind != AssignmentKind::Ordinary || metadata.target_path.is_some() {
        bail!("nested executor does not yet support decomposition workers");
    }
    let runtime = nested_worker_launch_runtime(
        assignment_launch_runtime(
            &preflight.assignment,
            context.options,
            &context.budget_policy,
        ),
        &context.budget_policy,
    );
    if runtime != SupervisorRuntime::Codex {
        bail!("nested executor currently requires the verified Codex launch path");
    }
    subject.runtime = Some(runtime);
    let scratch_index = nested_scratch_index(
        context.plan,
        context.index,
        &preflight.assignment.id,
        worker_id,
    )?;
    let layout = NestedArtifactLayout::new(
        &preflight.assignment.id,
        worker_id,
        parent_attempt,
        scratch_index,
    )?;
    let artifacts = layout.artifacts(context.run_dir);
    let budget_plan = context.budget_policy.apply(context.plan);
    let catalog = runtime_model_catalog_for_launch(
        context.runtime_model_catalog,
        context.options.runtime,
        runtime,
    )?;
    let prompt_plan =
        runtime_resolved_prompt_plan(&budget_plan, &subject, runtime, runtime, &catalog)?;
    let schema = context.dirs.schemas.join("worker-report.schema.json");
    let child_schema = context
        .dirs
        .schemas
        .join("orchestrator-review-report.schema.json");
    let auditor_schema = context.dirs.schemas.join("auditor-report.schema.json");
    let requirements = canonical_environment_requirements(&subject)?;
    let mut projected_metadata = AssignmentMetadata::new();
    if let Some(duty) = metadata.mechanical_duty {
        projected_metadata.insert_direct_mechanical_duty(subject.id.clone(), duty);
    }
    let rendered = render_child_orchestrator_prompt_with_incoming_root_and_field_guide(
        ChildOrchestratorPromptContext {
            plan: &prompt_plan,
            execution_target: None,
            assignment: &subject,
            run_dir: context.run_dir,
            worktree: &preflight.worktree,
            report_path: &artifacts.report_path,
            schema_path: &child_schema,
            worker_schema_path: &schema,
            auditor_schema_path: &auditor_schema,
            consultant: context.consultant,
            claim_context: ChildPromptClaimContext {
                claim: &preflight.claim,
                semantic_intent_token: preflight.semantic_token,
            },
        },
        &context.run_dir.join(&layout.incoming),
        &projected_metadata,
        context.field_guide,
        runtime,
        runtime,
    )?;
    let command = ExternalAgentCommand::codex(
        &context.options.codex_bin,
        &preflight.worktree.path,
        &artifacts.prompt_path,
        &artifacts.log_path,
        &artifacts.report_path,
        Duration::from_secs(budget_plan.child_timeout_seconds),
    );
    let bound = bind_selected_runtime_launch(
        command,
        &subject,
        &budget_plan,
        context.options,
        runtime,
        &catalog,
        metadata.mechanical_duty,
    )?;
    let mut command = bind_runtime_output_schema(bound.command, runtime, &schema)?;
    command = bind_runtime_read_only_schema_files(command, runtime, &[&schema]);
    command = command
        .with_agent_lifecycle(
            context.repo,
            "worker",
            context.options.run_id.as_str(),
            worker_id,
        )
        .with_agent_parent(&preflight.assignment.id);
    command = bind_supervisor_machine_global_staging_cleanup(command, context.options)?;
    command = apply_canonical_environment_requirements(command, &requirements);
    command = configure_assignment_phase_command(
        command,
        AssignmentPhase::Execution,
        &subject.assigned_paths,
    )?;
    let mut grant = admit_assignment_child_process_intent(
        context.options.run_id.as_str(),
        worker_id,
        parent_attempt,
        Path::new("codex"),
        command.model.as_deref(),
        ASSIGNMENT_CHILD_PROCESS_DUTY,
    )?;
    if let Some(duty) = metadata.mechanical_duty {
        if command
            .model
            .as_deref()
            .is_some_and(recorded_model_is_weak_mechanical)
        {
            grant = grant.seal_mechanical_executor(
                SealedMechanicalExecutorRole::Worker,
                SealedMechanicalExecutorPhase::MechanicalTerminal,
                sealed_mechanical_executor_duty(duty),
            )?;
        }
    }
    command =
        command.with_assignment_process_launch(AssignmentProcessLaunchKind::AssignmentChild, grant);
    // No messaging capability or child JSON participates in this launch authority.
    let authority = AssignmentAttemptAuthority::from_preflight(context, preflight, parent_attempt)?;
    authority.admit(worker_id, &command, runtime)?;
    preflight.mandatory_worktree_controls.revalidate()?;
    let primary_before = primary_worktree_snapshot(context.repo, context.execution_runtime)?;
    if let Some(error) = primary_before.inspection_problem() {
        bail!("nested launch requires a complete primary integrity snapshot: {error}");
    }
    let review = pre_action_review_context(context.options, &subject, &preflight.worktree.path)?;
    let (incoming, capture) = with_supervisor_artifacts(context.artifacts, |writer, _| {
        if writer.run_dir() != context.run_dir {
            bail!("nested artifact run directory mismatch");
        }
        let marker = layout.root.join("reserved.json");
        match fs::symlink_metadata(writer.run_dir().join(&marker)) {
            Ok(_) => bail!("nested worker attempt has already been reserved"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        write_artifact_json(
            writer,
            &marker,
            &json!({"parent": preflight.assignment.id, "worker": worker_id, "attempt": parent_attempt}),
            MAX_SUPERVISOR_REPORT_BYTES,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        write_private_prompt(writer, &layout.root.join("prompt.md"), &rendered.prompt)?;
        create_named_invocation_scratches(writer, &layout.incoming, &layout.capture)
    })?;
    let mut invoked = false;
    let mut spawned = false;
    let mut safety_verified = false;
    let mut result = (|| -> Result<NestedWorkerAttemptEvidence> {
        let incoming_root = SecureOutputRoot::open_private(incoming.path())?;
        let capture_root = SecureOutputRoot::open_private(capture.path())?;
        command = bind_worker_journal_artifacts(
            command.clone(),
            &subject,
            incoming.path(),
            precreate_worker_execution_journals(&subject, &incoming)?,
        )?;
        let cancellation = preflight.managed_process_cancellation.cancellation();
        if let Some(validation) = &context.assignment_metadata.parent_validation {
            command.timeout = command
                .timeout
                .min(validation.admit(&preflight.assignment.id, cancellation)?);
        }
        let admission = authority.admit(worker_id, &command, runtime)?;
        let mut reservation = match reserve_dispatch_budget(
            &budget_plan,
            context.budget_config,
            context.budget_ledger,
            AgentRole::Worker,
            &command,
        )? {
            DispatchBudgetAdmission::Admitted(reservation) => reservation,
            DispatchBudgetAdmission::Refused(refusal) => {
                bail!("nested worker budget refused: {refusal:?}")
            }
        };
        record_shared_orchestration_event(
            context.artifacts,
            worker_id,
            Some(&preflight.assignment.id),
            OrchestrationRole::Worker,
            OrchestrationEventKind::Spawn,
            record_supervision_spawn_payload_with_category(
                worker_id,
                &preflight.assignment.id,
                OrchestrationRole::Worker,
                AgentRole::Worker,
                subject.category_override(),
                write_boundary_refs(&subject.assigned_paths),
                &assignment_scope_ref(worker_id),
                json!({"attempt": parent_attempt, "runtime": runtime, "model": command.model, "resource_owner": preflight.assignment.id}),
            )?,
        )?;
        spawned = true;
        preflight.mandatory_worktree_controls.revalidate()?;
        if let Some(expected) = context.worktree_creation.expected_source_head() {
            if current_head_oid(&preflight.worktree.path)? != expected {
                bail!("nested parent worktree no longer has the admitted source HEAD");
            }
        }
        let worker_before =
            primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?;
        if let Some(error) = worker_before.inspection_problem() {
            bail!("nested launch requires a complete worker worktree snapshot: {error}");
        }
        admission.revalidate(&authority, worker_id, &command)?;
        permit.revalidate(preflight, parent_attempt)?;
        reservation.mark_invoked_for_runtime(runtime)?;
        invoked = true;
        let mut review_journal = SupervisorPreActionJournalSink {
            artifacts: context.artifacts,
            node: worker_id,
            parent: Some(&preflight.assignment.id),
        };
        let run = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (context.external_runner)(
                &command,
                cancellation,
                requires_hosted_pre_action_review(&command).then_some(
                    ExternalPreActionReviewRuntime {
                        context: &review,
                        journal: &mut review_journal,
                    },
                ),
            )
        })) {
            Ok(run) => run,
            Err(_) => bail!(
                "nested worker runner panicked; scratches retained because quiescence is unknown"
            ),
        };
        // No early return after invocation until accounting and evidence cleanup have
        // both been attempted. Unknown quiescence retains both private scratch roots.
        let settlement = reservation.settle_bound_runtime(&run, &command);
        let report = read_worker_report(run.output_last_message(), &artifacts.raw_report_relative)
            .and_then(|parsed| {
                validate_report_binding(
                    &parsed.report,
                    &subject,
                    &preflight.claim,
                    preflight.semantic_token,
                )?;
                Ok(parsed.report)
            });
        drop(incoming_root);
        drop(capture_root);
        let journals = with_supervisor_artifacts(context.artifacts, |writer, _| {
            import_worker_execution_journals_at(
                writer,
                &subject,
                &incoming,
                &run,
                Some(&layout.root.join("journals")),
            )
        });
        let cleanup = with_supervisor_artifacts(context.artifacts, |writer, _| {
            import_external_attempt_evidence(
                writer,
                ExternalAttemptEvidenceContext {
                    incoming_scratch: &incoming,
                    capture_scratch: &capture,
                    artifacts: &artifacts,
                    external_run: &run,
                    external_command: &command,
                    raw_report_validated: report.is_ok(),
                    runtime,
                },
            )
        });
        outcome
            .command_records
            .push(command_record_from_external_for_runtime(
                &run, &command, runtime,
            ));
        let settlement = settlement?;
        if let Some(usage) = settlement.reliable_usage() {
            outcome.usage_samples.push(RoleUsageSample {
                role: AgentRole::Worker,
                lens_id: None,
                model: command.model.clone(),
                usage,
            });
        } else if settlement.is_degraded() {
            outcome.usage_incomplete = true;
        }
        cleanup?;
        let primary_after = primary_worktree_snapshot(context.repo, context.execution_runtime)?;
        if primary_after.inspection_problem().is_some()
            || !primary_integrity_changes(&primary_before, &primary_after).is_empty()
            || !external_containment_verified(&run, runtime)
        {
            bail!("nested worker failed containment or primary integrity verification");
        }
        if !external_process_completed(&run, runtime) {
            bail!("nested worker process did not complete successfully");
        }
        admission.revalidate(&authority, worker_id, &command)?;
        let worker_after =
            primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?;
        let worker_changes = primary_integrity_changes(&worker_before, &worker_after);
        if worker_after.inspection_problem().is_some()
            || !primary_integrity_changes_outside_scope(&worker_changes, &subject.assigned_paths)
                .is_empty()
        {
            bail!("nested worker changed paths outside its authored scope");
        }
        safety_verified = true;
        let report = report?;
        if report.files_changed != worker_changes.paths {
            bail!("nested worker report differs from observed per-attempt changes");
        }
        let journals = journals?;
        if !journals
            .values()
            .all(|j| matches!(j.status, WorkerExecutionJournalStatus::Loaded(_)))
        {
            bail!("nested worker journal evidence is incomplete");
        }
        Ok(NestedWorkerAttemptEvidence {
            report,
            journals,
            artifacts,
            run,
            candidate_before: worker_before,
            candidate_after: worker_after,
            observed_changed_paths: worker_changes.paths,
            model_provenance: bound.model_provenance,
        })
    })();
    if result.is_err() {
        if invoked {
            // The parent must not continue accepting changes after uncertain execution.
            // Cancellation is shared with its already-registered managed process tree.
            context.cancellation.cancel();
            outcome.assignment_failed = true;
            outcome.external_containment_failed |= !safety_verified;
        } else if let Err(cleanup_error) =
            with_supervisor_artifacts(context.artifacts, |writer, _| {
                discard_invocation_scratches(writer, &incoming, &capture)
            })
        {
            result = match result {
                Ok(_) => Err(cleanup_error).context("nested invocation scratch cleanup failed"),
                Err(attempt_error) => Err(attempt_error.context(format!(
                    "nested invocation scratch cleanup also failed: {cleanup_error:#}"
                ))),
            };
        }
    }
    // Finalize every recorded Spawn, including failures before the runner call
    // and errors during cleanup. Uncertain process quiescence still retains scratch.
    if spawned {
        let terminal = record_shared_orchestration_event(
            context.artifacts,
            worker_id,
            Some(&preflight.assignment.id),
            OrchestrationRole::Worker,
            OrchestrationEventKind::Status,
            lifecycle_event_payload(
                if result.is_ok() {
                    "completed"
                } else {
                    "failed"
                },
                Some(parent_attempt),
                None,
            ),
        );
        if let Err(error) = terminal {
            result = match result {
                Ok(_) => Err(error).context("failed to record nested terminal status"),
                Err(attempt_error) => Err(attempt_error.context(format!(
                    "recording nested terminal status also failed: {error:#}"
                ))),
            };
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn parent() -> OrchestratorAssignment {
        serde_json::from_value(json!({
            "id":"parent", "phase":"execution", "role":"child_orchestrator",
            "assigned_paths":["src"], "task":"parent task",
            "semantic_symbols":["crate::selected"], "semantic_modules":["crate"],
            "worker_assignments":[
                {"id":"worker", "role":"worker", "assigned_paths":["src/lib.rs"],
                 "semantic_symbols":["crate::selected"], "semantic_modules":["crate"],
                 "task":"worker task", "report_path":"untrusted-location.json"},
                {"id":"sibling", "role":"worker", "assigned_paths":["src/other.rs"]}
            ]
        }))
        .unwrap()
    }

    fn plan(parent: OrchestratorAssignment) -> SupervisorPlan {
        serde_json::from_value(json!({
            "version": SUPERVISOR_SCHEMA_VERSION, "task":"nested executor fixture",
            "max_depth":2, "max_child_assignments":1, "max_child_retries":0,
            "max_gate_corrections":0, "child_timeout_seconds":10,
            "semantic_coordination":"off", "assignments":[parent]
        }))
        .unwrap()
    }

    #[test]
    fn nested_executor_projects_only_the_authored_terminal_subject() -> Result<()> {
        let parent = parent();
        let subject = terminal_subject(&parent, "worker")?;
        assert_eq!(subject.role, AgentRole::Worker);
        assert_eq!(subject.task.as_deref(), Some("worker task"));
        assert_eq!(subject.assigned_paths, vec![PathBuf::from("src/lib.rs")]);
        assert!(subject.worker_assignments.is_empty());
        assert_eq!(
            subject.semantic_symbols,
            parent.worker_assignments[0].semantic_symbols
        );
        assert!(terminal_subject(&parent, "missing").is_err());
        for mutation in [
            "duplicate",
            "role",
            "category",
            "parent",
            "phase",
            "same-id",
        ] {
            let mut changed = parent.clone();
            match mutation {
                "duplicate" => changed
                    .worker_assignments
                    .push(changed.worker_assignments[0].clone()),
                "role" => changed.worker_assignments[0].role = AgentRole::ChildOrchestrator,
                "category" => {
                    changed.worker_assignments[0].role_category =
                        Some(AgentRole::ChildOrchestrator.authority_category())
                }
                "parent" => changed.role = AgentRole::Worker,
                "phase" => changed.phase = AssignmentPhase::Planning,
                "same-id" => changed.id = "worker".into(),
                _ => unreachable!(),
            }
            assert!(
                terminal_subject(&changed, "worker").is_err(),
                "accepted {mutation}"
            );
        }
        Ok(())
    }

    #[test]
    fn nested_executor_artifacts_are_disjoint_and_do_not_use_authored_report_paths() -> Result<()> {
        let plan = plan(parent());
        let first = nested_scratch_index(&plan, 0, "parent", "worker")?;
        let sibling = nested_scratch_index(&plan, 0, "parent", "sibling")?;
        assert!(first >= plan.assignments.len());
        assert_ne!(first, sibling);
        let layout = NestedArtifactLayout::new("parent", "worker", 1, first)?;
        let next = NestedArtifactLayout::new("parent", "worker", 2, first)?;
        let other = NestedArtifactLayout::new("parent", "sibling", 1, sibling)?;
        assert_ne!(layout.incoming, next.incoming);
        assert_ne!(layout.incoming, other.incoming);
        assert_ne!(layout.root, next.root);
        assert_ne!(layout.root, other.root);
        let artifacts = layout.artifacts(Path::new("run"));
        assert_eq!(
            artifacts.report_path,
            Path::new("run").join(&layout.incoming).join("report.json")
        );
        assert_eq!(
            artifacts.raw_report_relative,
            Path::new("nested/parent/attempt-1/worker/report.json")
        );
        for id in ["../parent", "parent/worker", " parent", "..", ""] {
            assert!(NestedArtifactLayout::new(id, "worker", 1, first).is_err());
            assert!(NestedArtifactLayout::new("parent", id, 1, first).is_err());
        }
        assert!(NestedArtifactLayout::new("parent", "worker", 0, first).is_err());
        assert!(nested_scratch_index(&plan, 0, "substitute", "worker").is_err());
        assert!(nested_scratch_index(&plan, 1, "parent", "worker").is_err());
        assert!(nested_scratch_index(&plan, 0, "parent", "missing").is_err());
        Ok(())
    }

    #[test]
    fn nested_executor_report_binding_rejects_substitution_and_widening() -> Result<()> {
        let subject = terminal_subject(&parent(), "worker")?;
        let claim: PathClaim =
            serde_json::from_value(json!({"token":1,"agent_id":"parent","paths":["src"]}))?;
        let report: WorkerReport = serde_json::from_value(json!({
            "id":"worker", "role":"worker", "assigned_paths":["src/lib.rs"],
            "semantic_symbols":["crate::selected"], "semantic_modules":["crate"],
            "claim_token":1,"semantic_intent_token":3,"no_further_delegation":true,
            "accepted":true,"rejected":false,"status":"succeeded",
            "remaining_risk":"fixture", "next_safe_action":"parent review"
        }))?;
        validate_report_binding(&report, &subject, &claim, Some(3))?;
        for field in [
            "id",
            "role",
            "paths",
            "symbol",
            "claim",
            "semantic",
            "delegation",
            "changed",
            "escape",
            "kind",
        ] {
            let mut report = report.clone();
            match field {
                "id" => report.id = "sibling".into(),
                "role" => report.role = AgentRole::ChildOrchestrator,
                "paths" => report.assigned_paths = vec!["src".into()],
                "symbol" => report.semantic_symbols.clear(),
                "claim" => report.claim_token = Some(2),
                "semantic" => report.semantic_intent_token = None,
                "delegation" => report.no_further_delegation = Some(false),
                "changed" => report.files_changed = vec!["src/other.rs".into()],
                "escape" => report.files_changed = vec!["src/../lib.rs".into()],
                "kind" => report.assignment_kind = AssignmentKind::MegafileDecomposition,
                _ => unreachable!(),
            }
            assert!(
                validate_report_binding(&report, &subject, &claim, Some(3)).is_err(),
                "accepted {field}"
            );
        }
        Ok(())
    }

    // Real authenticated parent resources, deterministic injected runner. These
    // exercise lifecycle plumbing, not provider availability or Linux confinement.
    fn execution_fixture(case: &str) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main")?;
        fs::create_dir(repo.join("src"))?;
        fs::write(repo.join("src/lib.rs"), "pub fn selected() {}\n")?;
        let git = crate::git_repository::open(&repo)?;
        let mut index = git.index()?;
        index.add_path(Path::new("src/lib.rs"))?;
        index.write()?;
        let tree = git.find_tree(index.write_tree()?)?;
        let signature = git2::Signature::now("test", "test@example.com")?;
        git.commit(Some("HEAD"), &signature, &signature, "base", &tree, &[])?;
        let parent = parent();
        let plan = plan(parent.clone());
        let subject = terminal_subject(&parent, "worker")?;
        let run_id = RunId::new("nested-executor-test")?;
        let manager = WorktreeManager::new(&repo);
        let worktree = manager.create(crate::worktree::WorktreeCreateOptions {
            agent_id: parent.id.clone(),
            branch: None,
            base: None,
            worktree_root: Some(temp.path().join("worktrees")),
        })?;
        let lease = manager.acquire_write_execution_lease(&parent.id)?;
        let sync_store = SyncStore::open(&repo)?;
        let semantic_store = SemanticIntentStore::open(&repo)?;
        let claim = sync_store.claim_paths_for_run(&run_id, &parent.id, &parent.assigned_paths)?;
        let cancellation = ProcessCancellation::new();
        let preflight = AssignmentExecutionPreflight {
            nested_turn_issued: AtomicBool::new(false),
            journal_parent_id: run_id.as_str(),
            environment_requirements: Vec::new(),
            semantic_token: None,
            child_base_head: current_head_oid(&worktree.path)?,
            mandatory_worktree_controls: provision_mandatory_worktree_controls(&worktree.path)?,
            worktree: worktree.clone(),
            worktree_write_lease: Some(lease),
            primary_scope_baseline: None,
            claim: claim.clone(),
            managed_process_cancellation: sync_store
                .managed_process_cancellation_for_claim(claim.token, &cancellation)?,
            assignment: parent.clone(),
            _semantic_block_turn: None,
        };
        let foreign_preflight = if case == "foreign-permit" {
            let mut assignment = parent.clone();
            assignment.id = "foreign-parent".into();
            assignment.assigned_paths = vec!["foreign".into()];
            assignment.worker_assignments.clear();
            let worktree = manager.create(crate::worktree::WorktreeCreateOptions {
                agent_id: assignment.id.clone(),
                branch: None,
                base: None,
                worktree_root: Some(temp.path().join("worktrees")),
            })?;
            let claim = sync_store.claim_paths_for_run(
                &run_id,
                &assignment.id,
                &assignment.assigned_paths,
            )?;
            Some(AssignmentExecutionPreflight {
                nested_turn_issued: AtomicBool::new(false),
                journal_parent_id: run_id.as_str(),
                environment_requirements: Vec::new(),
                semantic_token: None,
                child_base_head: current_head_oid(&worktree.path)?,
                mandatory_worktree_controls: provision_mandatory_worktree_controls(&worktree.path)?,
                worktree_write_lease: Some(manager.acquire_write_execution_lease(&assignment.id)?),
                worktree,
                primary_scope_baseline: None,
                managed_process_cancellation: sync_store
                    .managed_process_cancellation_for_claim(claim.token, &cancellation)?,
                claim,
                assignment,
                _semantic_block_turn: None,
            })
        } else {
            None
        };
        let options = SupervisorRunOptions {
            repo: repo.clone(),
            plan_file: temp.path().join("plan.json"),
            run_id: run_id.clone(),
            parent_node: None,
            codex_bin: "never-invoke-provider".into(),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: Default::default(),
            budget_overrides: Default::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: Some(crate::machine_global::MachineGlobalRetentionBinding {
                config: temp.path().join("unused-retention.json"),
                root_id: "runtime".into(),
                owner: "maco-supervise".into(),
                correction_correlation_id: run_id.as_str().into(),
            }),
        };
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "nested-executor-test",
        )?;
        let run_dir = writer.run_dir().to_path_buf();
        let dirs = RunDirs::for_writer(&writer);
        write_worker_schema(&mut writer, Path::new("schemas/worker-report.schema.json"))?;
        write_codex_worker_schema(
            &mut writer,
            Path::new("schemas/worker-report.codex-output.schema.json"),
        )?;
        let mut journal = initialize_orchestration_event_journal(&repo, &run_id, None);
        let mut kpis = AutonomyKpiCollector::default();
        let artifacts = Mutex::new(SharedSupervisorArtifacts {
            writer: &mut writer,
            journal: &mut journal,
            autonomy_kpis: &mut kpis,
            checkpoint: None,
        });
        let budget_config = SupervisorBudgetConfig {
            role_token_reservations: BTreeMap::from([(AgentRole::Worker, 2)]),
            ..Default::default()
        };
        let limits = if case == "budget" {
            RunBudgetLimits {
                hard_tokens: Some(1),
                ..Default::default()
            }
        } else {
            RunBudgetLimits::default()
        };
        let ledger = RunBudgetLedger::new(limits)?;
        let metadata = AssignmentMetadata::new();
        let consultant = SupervisorConsultantPlan::default();
        let guide = SupervisorFieldGuidePrompt::empty()?;
        let catalog =
            RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(["gpt-5.6-sol"])?);
        let calls = AtomicUsize::new(0);
        let runner = |command: &ExternalAgentCommand,
                      _: &ProcessCancellation,
                      _: Option<ExternalPreActionReviewRuntime<'_>>| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(command.cwd, worktree.path);
            assert_eq!(command.agent_lifecycle.as_ref().unwrap().task_id, "worker");
            assert_eq!(
                command.agent_lifecycle.as_ref().unwrap().parent.as_deref(),
                Some("parent")
            );
            assert!(command.assignment_messaging_launch().is_none());
            assert_eq!(command.worker_journal_artifacts.len(), 1);
            assert!(fs::read_to_string(&command.prompt)
                .unwrap()
                .contains("worker task"));
            if case == "panic" {
                panic!("injected runner failure");
            }
            let mut simulated = command.clone();
            simulated.model = None;
            let mut run = deterministic_fake_child_run(
                &simulated,
                &subject,
                &metadata,
                claim.token.get(),
                None,
            )
            .unwrap();
            run.stdout.target_launch_attempted = true;
            run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
                crate::process_runner::ContainmentBackend::SystemdUserService,
            ));
            run.side_effects = Some(SideEffectConfinementEvidence::Verified(
                crate::process_runner::SideEffectConfinementProfileKind::ExternalCodex,
            ));
            run.publishable = true;
            run.program_trust = ExternalProgramTrust::TrustedSystemCodex;
            run.codex_permissions = Some(crate::external_agent::CodexPermissionEvidence {
                codex_version: "0.142.3".into(),
                minimum_version: "0.138.0".into(),
                permission_profile: "maco_external_codex".into(),
                workspace_access: command.workspace_access,
                network_enabled: false,
                argv_digest: "fixture".into(),
                executable_identity: "fixture".into(),
            });
            if case == "quiescence" {
                run.process_tree = None;
            }
            if case == "report" {
                run.output_last_message = Some(b"{}".to_vec());
            }
            if case == "scope" {
                fs::write(
                    worktree.path.join("src/other.rs"),
                    "unauthorized sibling change\n",
                )
                .unwrap();
            }
            if case == "revoked-after" {
                sync_store.release(claim.token).unwrap();
            }
            run
        };
        let context = AssignmentExecutionContext {
            index: 0,
            concurrent_mode: false,
            plan: &plan,
            requested_plan: &plan,
            execution_target: None,
            budget_config: &budget_config,
            consultant: &consultant,
            assignment_metadata: &metadata,
            assignment: &parent,
            evidence_only_reaudit: None,
            options: &options,
            repo: &repo,
            run_dir: &run_dir,
            dirs: &dirs,
            execution_runtime: SupervisorExecutionRuntime::Verified,
            worktree_creation: SupervisorWorktreeCreation::ExistingOnly,
            manager: &manager,
            reused: true,
            sync_store: &sync_store,
            semantic_store: &semantic_store,
            prepared_semantic_token: None,
            prepared_semantic_findings: &[],
            prepared_semantic_signals: &[],
            prepared_semantic_failed: false,
            assignment_schedule: &[],
            field_guide: &guide,
            serial_semantic_warn_intents: None,
            semantic_block_order: None,
            semantic_block_gate: None,
            artifacts: &artifacts,
            budget_ledger: &ledger,
            budget_policy: AssignmentBudgetPolicy::default(),
            admission_commit: None,
            runtime_model_catalog: &catalog,
            cancellation: cancellation.clone(),
            external_runner: &runner,
        };
        let claims_before = sync_store.snapshot()?;
        if case == "revoked" {
            sync_store.release(claim.token)?;
        }
        if case == "cancelled" {
            cancellation.cancel();
        }
        if case == "snapshot" {
            let child_git = crate::git_repository::open(&worktree.path)?;
            fs::write(child_git.path().join("index"), b"invalid index fixture")?;
        }
        let mut outcome = AssignmentExecutionOutcome::default();
        // Both owners have issued permits: rejecting the foreign one must depend
        // on exact preflight identity, not merely the destination's issued bit.
        let _target_permit = if foreign_preflight.is_some() {
            Some(preflight.issue_nested_turn(1)?)
        } else {
            None
        };
        let mut permit = foreign_preflight
            .as_ref()
            .unwrap_or(&preflight)
            .issue_nested_turn(if case == "wrong-permit-attempt" { 2 } else { 1 })?;
        let result = execute_nested_worker_attempt(
            &context,
            &preflight,
            &mut permit,
            &mut outcome,
            1,
            if case == "unknown" {
                "unknown"
            } else {
                "worker"
            },
        );
        if case == "happy" {
            let evidence = result?;
            assert_eq!(evidence.report.id, "worker");
            assert_eq!(evidence.journals.len(), 1);
            assert!(run_dir
                .join(evidence.artifacts.raw_report_relative)
                .is_file());
            assert!(run_dir
                .join("nested/parent/attempt-1/worker/journals/worker.jsonl")
                .is_file());
            assert_eq!(outcome.command_records.len(), 1);
            assert!(execute_nested_worker_attempt(
                &context,
                &preflight,
                &mut permit,
                &mut outcome,
                1,
                "worker"
            )
            .err()
            .unwrap()
            .to_string()
            .contains("already been reserved"));
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        } else {
            assert!(result.is_err(), "unexpected success for {case}");
            if matches!(case, "foreign-permit" | "wrong-permit-attempt") {
                assert!(result
                    .as_ref()
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("permit differs"));
                assert!(
                    !run_dir.join("nested").exists(),
                    "foreign permit created reservation artifacts"
                );
                assert!(outcome.command_records.is_empty());
            }
            if case == "budget" {
                assert!(result
                    .as_ref()
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("nested worker budget refused: HardTokenCeiling"));
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                usize::from(matches!(
                    case,
                    "quiescence" | "panic" | "report" | "scope" | "revoked-after"
                ))
            );
        }
        let event_path = run_dir.join(crate::orchestration_event::ORCHESTRATION_EVENT_PATH);
        let event_text = if event_path.exists() {
            fs::read_to_string(event_path)?
        } else {
            String::new()
        };
        let events = event_text
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let worker_events = events
            .iter()
            .filter(|event| event["node"] == "worker")
            .collect::<Vec<_>>();
        let spawned = !matches!(
            case,
            "unknown"
                | "revoked"
                | "cancelled"
                | "budget"
                | "foreign-permit"
                | "wrong-permit-attempt"
        );
        assert_eq!(
            worker_events
                .iter()
                .filter(|event| event["kind"] == "spawn")
                .count(),
            usize::from(spawned),
            "spawn events for {case}"
        );
        let terminal = worker_events
            .iter()
            .filter(|event| event["kind"] == "status")
            .collect::<Vec<_>>();
        assert_eq!(
            terminal.len(),
            usize::from(spawned),
            "one terminal status per spawn for {case}"
        );
        if spawned {
            assert_eq!(terminal[0]["parent"], "parent");
            assert_eq!(terminal[0]["payload"]["attempt"], 1);
            assert_eq!(
                terminal[0]["payload"]["status"],
                if case == "happy" {
                    "completed"
                } else {
                    "failed"
                }
            );
        }
        let layout = NestedArtifactLayout::new("parent", "worker", 1, 1)?;
        assert_eq!(
            run_dir.join(layout.incoming).exists(),
            matches!(case, "quiescence" | "panic")
        );
        assert_eq!(
            run_dir.join(layout.capture).exists(),
            matches!(case, "quiescence" | "panic")
        );
        if !matches!(case, "revoked" | "revoked-after") {
            assert_eq!(sync_store.snapshot()?, claims_before);
        }
        assert_eq!(
            ledger.report()?.active_reservations,
            0,
            "budget reservation leaked for {case}"
        );
        assert_eq!(
            manager.list_managed_verified()?.len(),
            if case == "foreign-permit" { 2 } else { 1 }
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_executor_rejects_foreign_preflight_and_attempt_permits_before_dispatch() -> Result<()>
    {
        execution_fixture("foreign-permit")?;
        execution_fixture("wrong-permit-attempt")
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_executor_happy_path_reuses_parent_and_rejects_replay() -> Result<()> {
        execution_fixture("happy")
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_executor_refuses_before_dispatch_and_cleans_reserved_scratch() -> Result<()> {
        for case in ["unknown", "revoked", "cancelled", "budget", "snapshot"] {
            execution_fixture(case)?;
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "requires Linux authenticated managed resources"
    )]
    fn nested_executor_retains_uncertain_scratch_and_cleans_rejected_report() -> Result<()> {
        for case in ["quiescence", "panic", "report", "scope", "revoked-after"] {
            execution_fixture(case)?;
        }
        Ok(())
    }
}
