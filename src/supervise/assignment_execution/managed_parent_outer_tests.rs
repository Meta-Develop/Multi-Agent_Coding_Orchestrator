//! Production outer-loop regressions. Only the provider peer and account/prior
//! observations are synthetic; admission, confinement, capture, journals,
//! settlement, correction gates and the independent review stack run normally.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Debug)]
struct Call {
    id: String,
    turn: usize,
    cwd: PathBuf,
    claim: u64,
}

pub(super) struct Fixture {
    case: String,
    run_dir: PathBuf,
    repo: PathBuf,
    parent: PathBuf,
    turn: AtomicUsize,
    calls: Mutex<Vec<Call>>,
    workers: Mutex<Vec<WorkerReport>>,
    requests: Mutex<Vec<crate::review::ReviewLensRequest>>,
    audits: Mutex<Vec<AuditorReport>>,
    archived: Mutex<BTreeMap<PathBuf, Vec<u8>>>,
    predecessor_runs: Mutex<BTreeMap<String, ExternalAgentRun>>,
}

impl Fixture {
    pub(super) fn new(case: &str, run_dir: &Path, repo: &Path, parent: &Path) -> Self {
        Self {
            case: case.into(),
            run_dir: run_dir.into(),
            repo: repo.into(),
            parent: parent.into(),
            turn: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            workers: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
            audits: Mutex::new(Vec::new()),
            archived: Mutex::new(BTreeMap::new()),
            predecessor_runs: Mutex::new(BTreeMap::new()),
        }
    }

    fn archive_predecessor(&self) -> Result<()> {
        let mut paths = vec![
            PathBuf::from("evidence/incoming/parent.attempt-1.json"),
            PathBuf::from("evidence/incoming/parent.attempt-2.json"),
            PathBuf::from("logs/parent.attempt-1.jsonl"),
            PathBuf::from("logs/parent.attempt-2.jsonl"),
        ];
        for worker in ["worker", "worker-two"] {
            if self.case.contains("isolated") {
                paths.extend([
                    PathBuf::from(format!("evidence/incoming/{worker}.json")),
                    PathBuf::from(format!("logs/{worker}.jsonl")),
                    worker_execution_journal_evidence_relative(worker, worker),
                ]);
            } else {
                let root = PathBuf::from(format!("nested/parent/attempt-1/{worker}"));
                paths.extend([
                    root.join("report.json"),
                    root.join("stdout.jsonl"),
                    root.join(format!("journals/{worker}.jsonl")),
                ]);
            }
        }
        let mut archived = self.archived.lock().unwrap();
        assert!(archived.is_empty(), "predecessor archive was replaced");
        for path in paths {
            archived.insert(path.clone(), fs::read(self.run_dir.join(path))?);
        }
        Ok(())
    }

    pub(super) fn run(
        &self,
        command: &ExternalAgentCommand,
        cancellation: &ProcessCancellation,
        parent: &OrchestratorAssignment,
        metadata: &AssignmentMetadata,
        sync: &SyncStore,
    ) -> Result<ExternalAgentRun> {
        let identity = command
            .agent_lifecycle
            .as_ref()
            .context("native lifecycle")?;
        let claims = sync.snapshot()?;
        let parent_claim = claims
            .iter()
            .find(|claim| claim.agent_id == parent.id)
            .context("original parent union claim")?;
        assert_eq!(parent_claim.paths, parent.assigned_paths);
        let mut simulated = command.clone();
        simulated.model = None;
        if identity.role == AgentRole::Auditor.as_str() {
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
            assert!(command.worker_journal_artifacts.is_empty());
            assert!(command.assignment_messaging_launch().is_none());
            assert_ne!(command.cwd, self.parent);
            assert_ne!(command.cwd, self.repo);
            assert!(!command.cwd.join("src/lib.rs").exists());
            if self.case.contains("isolated") && self.turn.load(Ordering::Acquire) == 1 {
                self.assert_no_isolated_commit_or_import()?;
            }
            let prompt = fs::read_to_string(&command.prompt)?;
            let request = decode_prompt_json::<crate::review::ReviewLensRequest>(
                &prompt,
                "REVIEW_LENS_REQUEST_JSON:\n",
            )?;
            let coverage: crate::review::ReviewCoverageRequirement =
                decode_prompt_json(&prompt, "REQUIRED_COVERAGE_JSON:\n")?;
            let report = AuditorReport {
                id: identity.task_id.clone(),
                role: AgentRole::Auditor,
                reviewed_worker_ids: coverage.worker_ids,
                reviewed_paths: coverage.paths,
                commands_run: Vec::new(),
                environment_failures: Vec::new(),
                validation_results: Vec::new(),
                findings: Vec::new(),
                rejection_kind: None,
                no_further_delegation: Some(true),
                read_only: true,
                accepted: true,
                rejected: false,
                status: ReviewStatus::Succeeded,
                remaining_risk: "offline scoped packet review only".into(),
                next_safe_action: "return the scoped verdict to the parent".into(),
            };
            let run = crate::external_agent::managed_parent_fixture::run(
                command,
                cancellation,
                json!({"mode":"review", "case":self.case, "report":report, "request":request}),
            )?;
            require_native(&run)?;
            let observed: AuditorReport =
                serde_json::from_slice(run.output_last_message().context("review capture")?)?;
            if self.case.contains("isolated") && self.turn.load(Ordering::Acquire) == 1 {
                self.assert_no_isolated_commit_or_import()?;
            }
            assert_eq!(observed.id, identity.task_id);
            self.requests.lock().unwrap().push(request);
            self.audits.lock().unwrap().push(observed);
            self.calls.lock().unwrap().push(Call {
                id: identity.task_id.clone(),
                turn: self.turn.load(Ordering::Acquire),
                cwd: command.cwd.clone(),
                claim: parent_claim.token.get(),
            });
            return Ok(run);
        }
        assert!(command.codex_native_delegation_is_disabled());
        let source_turn = if identity.task_id == parent.id {
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadOnly);
            let schema: Value =
                serde_json::from_slice(&fs::read(command.output_schema.as_ref().unwrap())?)?;
            let field = if command.codex_managed_worker_requests_enabled() {
                "parent_attempt"
            } else {
                "source_parent_attempt"
            };
            let turn = schema
                .pointer(&format!("/properties/{field}/const"))
                .or_else(|| schema.pointer(&format!("/properties/{field}/enum/0")))
                .and_then(Value::as_u64)
                .context("physical native parent turn")? as usize;
            if command.codex_managed_worker_requests_enabled() {
                if turn == 3 {
                    self.archive_predecessor()?;
                }
                self.turn.store(turn, Ordering::Release);
            } else {
                assert!(command.codex_managed_readonly_continuation_enabled());
            }
            turn
        } else {
            assert_eq!(command.workspace_access, WorkspaceAccess::ReadWrite);
            self.turn.load(Ordering::Acquire)
        };
        let claim = claims
            .iter()
            .find(|claim| claim.agent_id == identity.task_id)
            .unwrap_or(parent_claim);
        let mut subject = if identity.task_id == parent.id {
            let mut subject = parent.clone();
            subject.worker_assignments.clear();
            subject
        } else {
            let worker = parent
                .worker_assignments
                .iter()
                .find(|worker| worker.id == identity.task_id)
                .context("exact authored Worker")?;
            serde_json::from_value(json!({"id":worker.id, "phase":"execution", "role":"worker",
                "assigned_paths":worker.assigned_paths, "task":worker.task}))?
        };
        subject.runtime = Some(SupervisorRuntime::Codex);
        let template =
            deterministic_fake_child_run(&simulated, &subject, metadata, claim.token.get(), None)?;
        let run = super::managed_parent_process_tests::run(
            &self.case,
            command,
            cancellation,
            &template,
            &self.workers,
            None,
        )?;
        require_native(&run)?;
        if identity.role == AgentRole::Worker.as_str() && source_turn == 1 {
            self.predecessor_runs
                .lock()
                .unwrap()
                .insert(identity.task_id.clone(), run.clone());
        }
        self.calls.lock().unwrap().push(Call {
            id: identity.task_id.clone(),
            turn: source_turn,
            cwd: command.cwd.clone(),
            claim: parent_claim.token.get(),
        });
        Ok(run)
    }

    fn assert_no_isolated_commit_or_import(&self) -> Result<()> {
        let base = current_head_oid(&self.repo)?;
        let calls = self.calls.lock().unwrap();
        let mut paths = vec![self.repo.clone(), self.parent.clone()];
        paths.extend(
            calls
                .iter()
                .filter(|call| call.id == "worker" || call.id == "worker-two")
                .map(|call| call.cwd.clone()),
        );
        assert!(
            paths.len() >= 4,
            "both isolated Workers must have completed before review"
        );
        for path in paths {
            assert_eq!(
                current_head_oid(&path)?,
                base,
                "pre-review private ref advanced"
            );
            let repository = crate::git_repository::open(&path)?;
            let mut commits = BTreeSet::new();
            repository.odb()?.foreach(|oid| {
                if repository.find_commit(*oid).is_ok() {
                    commits.insert(*oid);
                }
                true
            })?;
            assert_eq!(
                commits,
                BTreeSet::from([base]),
                "pre-review commit/import created an object"
            );
        }
        Ok(())
    }

    pub(super) fn exercise(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        base: Oid,
        isolated: bool,
    ) -> Result<()> {
        let primary = primary_worktree_snapshot(context.repo, context.execution_runtime)?;
        let assignment = context.assignment.clone();
        let mut outcome = AssignmentExecutionOutcome {
            gate_tracker: Some(GateCorrectionTracker::new(
                context.plan.max_gate_corrections,
            )),
            ..Default::default()
        };
        let result = execute_supervisor_assignment_inner(context, &mut outcome);
        if [
            "outer-unknown",
            "outer-launch",
            "outer-signal",
            "outer-omitted-failure",
            "outer-omitted-repeat-failure",
            "outer-reordered",
            "outer-wrong-occurrence",
            "outer-wrong-validation-occurrence",
            "outer-ambiguous-validation-reference",
        ]
        .iter()
        .any(|case| self.case.ends_with(case))
        {
            assert!(
                result.is_err() || outcome.assignment_failed,
                "untrusted outcome minted a writable correction"
            );
            assert_eq!(self.turn.load(Ordering::Acquire), 1);
            assert!(self.calls.lock().unwrap().iter().all(|call| call.turn == 1));
            assert_eq!(outcome.gate_tracker.as_ref().unwrap().used, 0);
            assert!(self.requests.lock().unwrap().is_empty());
            assert_eq!(
                primary_worktree_snapshot(context.repo, context.execution_runtime)?,
                primary
            );
            let runs = self.predecessor_runs.lock().unwrap();
            let raw = read_worker_report(
                runs["worker"].output_last_message(),
                Path::new("held-negative.json"),
            )?
            .report;
            if self.case.ends_with("outer-omitted-failure")
                || self.case.ends_with("outer-omitted-repeat-failure")
                || self.case.ends_with("outer-reordered")
                || self.case.ends_with("outer-wrong-occurrence")
                || self.case.ends_with("outer-wrong-validation-occurrence")
                || self.case.ends_with("outer-ambiguous-validation-reference")
            {
                let native = &runs["worker"];
                let capture = &native.worker_journal_artifacts()[0];
                let WorkerJournalArtifactCaptureStatus::Loaded(bytes) = &capture.status else {
                    bail!("negative subset fixture lost its actual journal capture");
                };
                let evidence = WorkerExecutionJournalEvidence {
                    incoming_relative_path: capture.path.clone(),
                    evidence_relative_path: capture.path.clone(),
                    command_binding: capture.command_binding.clone(),
                    status: WorkerExecutionJournalStatus::Loaded(parse_worker_execution_journal(
                        bytes,
                        &capture.path,
                    )?),
                };
                let error = super::managed_parent_correction::require_worker_custody(
                    &raw, &evidence, native,
                )
                .expect_err("invalid report subset acquired live custody");
                if self.case.ends_with("outer-reordered") {
                    assert!(error
                        .to_string()
                        .contains("no exact unconsumed host outcome"));
                    assert_eq!(raw.commands_run.len(), 2);
                    assert_eq!(raw.commands_run[0].exit_code, Some(1));
                    assert_eq!(raw.commands_run[1].exit_code, Some(0));
                } else if self.case.ends_with("outer-wrong-validation-occurrence")
                    || self.case.ends_with("outer-ambiguous-validation-reference")
                {
                    let WorkerExecutionJournalStatus::Loaded(entries) = &evidence.status else {
                        bail!("validation reference fixture lost its parsed journal");
                    };
                    let command = &raw.commands_run[0];
                    assert_eq!(raw.commands_run.len(), 1);
                    assert_eq!(command.exit_code, Some(1));
                    let failed = super::super::journal_command::resolve_wrapper(
                        &command.command,
                        &command.cwd,
                        &evidence,
                        entries,
                    )
                    .context("correct reported failing occurrence")?;
                    assert!(std::ptr::eq(
                        failed,
                        entries.last().context("terminal failure")?
                    ));
                    let validation = &raw.validation_results[0];
                    assert!(validation_failed(validation));
                    assert!(!validation.command.is_empty());
                    if self.case.ends_with("outer-wrong-validation-occurrence") {
                        assert!(error
                            .to_string()
                            .contains("no exact native failing command"));
                        let successful = super::super::journal_command::resolve_wrapper(
                            &validation.command,
                            &command.cwd,
                            &evidence,
                            entries,
                        )
                        .context("earlier successful validation reference")?;
                        assert_eq!(successful.command, failed.command);
                        assert!(!std::ptr::eq(successful, failed));
                        assert_eq!(successful.changed_paths, raw.files_changed);
                        assert!(failed.changed_paths.is_empty());
                    } else {
                        assert!(error.to_string().contains("no unique journal occurrence"));
                        assert!(validation
                            .command
                            .iter()
                            .any(|arg| arg == "--auto-timestamps"));
                        assert!(super::super::journal_command::resolve_wrapper(
                            &validation.command,
                            &command.cwd,
                            &evidence,
                            entries,
                        )
                        .is_none());
                        assert_eq!(
                            entries
                                .iter()
                                .filter(|entry| super::super::journal_command::resolve_wrapper(
                                    &validation.command,
                                    &command.cwd,
                                    &evidence,
                                    std::slice::from_ref(*entry),
                                )
                                .is_some())
                                .count(),
                            2,
                            "ambiguous reference must match two real occurrences"
                        );
                    }
                } else if self.case.ends_with("outer-wrong-occurrence") {
                    assert!(error
                        .to_string()
                        .contains("omitted or contradicted an actual host failure"));
                    assert_eq!(raw.commands_run.len(), 1);
                    assert_eq!(raw.commands_run[0].exit_code, Some(1));
                    assert!(raw.commands_run[0]
                        .command
                        .iter()
                        .any(|arg| arg == "--start-timestamp"));
                } else {
                    assert!(error.to_string().contains("omitted an actual host failure"));
                    assert_eq!(raw.commands_run.len(), 1);
                    assert_eq!(
                        raw.commands_run[0].exit_code,
                        Some(if self.case.ends_with("outer-omitted-failure") {
                            0
                        } else {
                            1
                        })
                    );
                }
                if self.case.ends_with("outer-omitted-repeat-failure")
                    || self.case.ends_with("outer-wrong-occurrence")
                    || self.case.ends_with("outer-wrong-validation-occurrence")
                    || self.case.ends_with("outer-ambiguous-validation-reference")
                {
                    use crate::external_agent::codex_app_server::CommandExecutionObservation;
                    let host = native
                        .codex_command_execution_evidence()
                        .context("live host")?;
                    let repeated = &host.observations[host.observations.len() - 2..];
                    let mut identities = Vec::new();
                    for (index, item) in repeated.iter().enumerate() {
                        let CommandExecutionObservation::Complete { completed, .. } = item else {
                            bail!("repeated command has no completed host outcome");
                        };
                        let code =
                            if index == 0 && !self.case.ends_with("outer-omitted-repeat-failure") {
                                0
                            } else {
                                1
                            };
                        assert_eq!(completed.exit_code, Some(code));
                        identities.push(&completed.command);
                    }
                    assert_eq!(
                        identities[0], identities[1],
                        "not a repeated command identity"
                    );
                }
            } else {
                assert_eq!(raw.commands_run[0].exit_code, Some(1));
                assert!(raw.commands_run[0].error.is_none());
            }
            return Ok(());
        }
        result?;
        assert!(!outcome.assignment_failed, "{:?}", outcome.findings);
        assert!(!outcome.authority_requires_quarantine());
        assert!(outcome.release_errors.is_empty());
        let report = outcome.report.as_ref().context("outer-loop final report")?;
        assert!(!report_failed(report), "{report:?}");
        assert_eq!(report.id, assignment.id);
        assert_eq!(report.assigned_paths, assignment.assigned_paths);
        assert_eq!(context.assignment, &assignment);
        assert_eq!(
            primary_worktree_snapshot(context.repo, context.execution_runtime)?,
            primary
        );
        assert_eq!(current_head_oid(context.repo)?, base);
        let lease = context
            .manager
            .acquire_write_execution_lease(&assignment.id)?;
        let current = inspect_supervisor_candidate(
            context.repo,
            &assignment,
            &lease,
            context.worktree_creation.expected_source_head(),
        )?;
        assert_eq!(outcome.candidate_inspection.as_ref(), Some(&current));
        assert_ne!(current.binding.agent_head, Some(base.to_string()));
        drop(lease);
        if self.case.ends_with("accepted") {
            assert!(isolated);
            let calls = self.calls.lock().unwrap();
            assert_eq!(calls.iter().filter(|call| call.id == "parent").count(), 2);
            assert!(calls.iter().all(|call| call.turn == 1));
            assert_eq!(
                self.requests.lock().unwrap().len(),
                context.plan.review_lenses.len()
            );
            assert!(self
                .audits
                .lock()
                .unwrap()
                .iter()
                .all(|audit| audit.accepted && !audit.rejected));
            assert_eq!(
                report
                    .review_lens_aggregate
                    .as_ref()
                    .context("accepted isolated review aggregate")?
                    .decision,
                ReviewAggregationDecision::Accept
            );
            for worker in &assignment.worker_assignments {
                let invocation = calls
                    .iter()
                    .find(|call| call.id == worker.id)
                    .context("isolated invocation")?;
                assert_ne!(invocation.cwd, self.parent);
                assert_ne!(
                    current_head_oid(&invocation.cwd)?,
                    base,
                    "accepted isolated handoff never materialized Worker"
                );
                assert!(!worker_technical_failure(
                    report
                        .worker_reports
                        .iter()
                        .find(|row| row.id == worker.id)
                        .unwrap(),
                    &[]
                ));
                drop(context.manager.acquire_write_execution_lease(&worker.id)?);
            }
            assert_eq!(outcome.gate_tracker.as_ref().unwrap().used, 0);
            let budget = context.budget_ledger.report()?;
            assert_eq!(budget.active_reservations, 0);
            assert_eq!(budget.charges.len(), 4 + context.plan.review_lenses.len());
            assert!(budget.usage_complete);
            assert_eq!(context.sync_store.snapshot()?.len(), 1);
            return Ok(());
        }
        let calls = self.calls.lock().unwrap();
        let parent_calls = calls
            .iter()
            .filter(|call| call.id == "parent")
            .collect::<Vec<_>>();
        assert_eq!(
            parent_calls
                .iter()
                .map(|call| call.turn)
                .collect::<Vec<_>>(),
            [1, 1, 3, 3]
        );
        let claim = parent_calls[0].claim;
        assert!(calls.iter().all(|call| call.claim == claim));
        assert_eq!(report.claim_token, Some(claim));
        for worker in &assignment.worker_assignments {
            let invocations = calls
                .iter()
                .filter(|call| call.id == worker.id)
                .collect::<Vec<_>>();
            assert_eq!(invocations.len(), 2);
            assert_eq!(
                invocations.iter().map(|call| call.turn).collect::<Vec<_>>(),
                [1, 3]
            );
            assert_eq!(invocations[0].cwd == self.parent, !isolated);
            assert_eq!(
                invocations[1].cwd, self.parent,
                "correction must repair the exact union serially"
            );
            let fresh = report
                .worker_reports
                .iter()
                .find(|fresh| fresh.id == worker.id)
                .unwrap();
            assert!(!worker_technical_failure(fresh, &[]));
            assert_eq!(fresh.assigned_paths, worker.assigned_paths);
            assert_eq!(fresh.claim_token, Some(claim));
            assert!(fresh
                .commands_run
                .iter()
                .all(|command| command.status == ReviewStatus::Succeeded
                    && command.exit_code == Some(0)));
            assert!(fresh.commands_run.iter().any(|command| command
                .command
                .iter()
                .any(|arg| arg.contains("physical Worker turn 3"))));
        }
        let journal_path = PathBuf::from("nested/parent/attempt-3/worker/journals/worker.jsonl");
        let fresh_entries = parse_worker_execution_journal(
            &fs::read(self.run_dir.join(&journal_path))?,
            &journal_path,
        )?;
        let completed = fresh_entries
            .iter()
            .filter(|entry| {
                entry.observation.as_ref().is_some_and(|observation| {
                    observation.phase == WorkerJournalObservationPhase::Completed
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            completed.len(),
            3,
            "two real inspections plus actual edit/validation"
        );
        assert_eq!(completed[0].command, completed[1].command);
        assert!(completed[..2]
            .iter()
            .all(|entry| entry.changed_paths.is_empty()));
        let fresh = report
            .worker_reports
            .iter()
            .find(|worker| worker.id == "worker")
            .unwrap();
        assert_eq!(fresh.commands_run.len(), 1);
        assert!(
            !fresh.commands_run[0]
                .command
                .ends_with(&completed[0].command),
            "successful wrapped inspection was not omitted"
        );
        let baseline = fresh_entries[0]
            .observation
            .as_ref()
            .context("supervisor candidate baseline")?;
        assert_eq!(baseline.phase, WorkerJournalObservationPhase::Baseline);
        assert_eq!(baseline.head_oid, Some(base.to_string()));
        let sibling = Path::new("src/other.rs");
        assert!(
            baseline.after.contains_key(sibling)
                && baseline.after.contains_key(Path::new("src/lib.rs"))
        );
        assert!(fresh_entries[0].changed_paths.is_empty());
        assert_eq!(
            fresh_entries[1].observation.as_ref().unwrap().phase,
            WorkerJournalObservationPhase::NativeEdit
        );
        assert!(
            fresh_entries[1].changed_paths.is_empty(),
            "opening observation attributed inherited source"
        );
        for entry in &fresh_entries {
            let observation = entry.observation.as_ref().unwrap();
            assert_eq!(observation.after.get(sibling), baseline.after.get(sibling));
            assert!(
                !entry.changed_paths.iter().any(|path| path == sibling),
                "unchanged sibling was newly attributed"
            );
        }
        let archived = self.archived.lock().unwrap();
        assert!(!archived.is_empty());
        for (path, bytes) in archived.iter() {
            assert_eq!(
                &fs::read(self.run_dir.join(path))?,
                bytes,
                "spent evidence changed: {path:?}"
            );
            assert_eq!(
                crate::artifacts::state_auth::sha256_hex(bytes),
                crate::artifacts::state_auth::sha256_hex(&fs::read(self.run_dir.join(path))?)
            );
        }
        if !self.case.ends_with("auditor") {
            let old_path = if isolated {
                PathBuf::from("evidence/incoming/worker.json")
            } else {
                PathBuf::from("nested/parent/attempt-1/worker/report.json")
            };
            let old: WorkerReport = serde_json::from_slice(&archived[&old_path])?;
            assert!(report_failed(&old));
            assert!(
                worker_technical_failure(&old, &[]),
                "old failure was waived"
            );
            assert!(old
                .commands_run
                .iter()
                .any(|command| command.exit_code == Some(1)));
            let journal_path = if isolated {
                worker_execution_journal_evidence_relative("worker", "worker")
            } else {
                PathBuf::from("nested/parent/attempt-1/worker/journals/worker.jsonl")
            };
            let entries = parse_worker_execution_journal(&archived[&journal_path], &journal_path)?;
            let predecessor_runs = self.predecessor_runs.lock().unwrap();
            let native = &predecessor_runs["worker"];
            use crate::external_agent::codex_app_server::CommandExecutionObservation;
            let host = native
                .codex_command_execution_evidence()
                .context("live host outcomes")?;
            let exits = host
                .observations
                .iter()
                .map(|item| match item {
                    CommandExecutionObservation::Complete { completed, .. } => completed.exit_code,
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                exits,
                [Some(0), Some(0), Some(0), Some(1)],
                "omitted inspections must really succeed before the failed validation"
            );
            assert_eq!(old.commands_run.len(), 1);
            let evidence = WorkerExecutionJournalEvidence {
                incoming_relative_path: journal_path.clone(),
                evidence_relative_path: journal_path,
                command_binding: native.worker_journal_artifacts()[0].command_binding.clone(),
                status: WorkerExecutionJournalStatus::Loaded(entries.clone()),
            };
            super::managed_parent_correction::require_worker_custody(&old, &evidence, native)?;
            assert_eq!(old.validation_results[0].command, Vec::<String>::new());
            assert_eq!(
                old.commands_run[0].error.as_deref(),
                Some("Wrapped command exited with status 1; journal retained.")
            );
            let restored: ExternalAgentRun = serde_json::from_value(serde_json::to_value(native)?)?;
            assert!(super::managed_parent_correction::require_worker_custody(
                &old, &evidence, &restored
            )
            .is_err());
            let mut invalid = evidence.clone();
            let mut failed_append = entries.clone();
            let observation = failed_append
                .last_mut()
                .unwrap()
                .observation
                .as_mut()
                .unwrap();
            observation.phase = WorkerJournalObservationPhase::Failed;
            observation.failure = Some("test append observation failed".into());
            invalid.status = WorkerExecutionJournalStatus::Loaded(failed_append);
            assert!(super::managed_parent_correction::require_worker_custody(
                &old, &invalid, native
            )
            .is_err());
            invalid.status = WorkerExecutionJournalStatus::Missing;
            assert!(super::managed_parent_correction::require_worker_custody(
                &old, &invalid, native
            )
            .is_err());
            let mut unknown = old.clone();
            unknown.commands_run[0].exit_code = None;
            assert!(super::managed_parent_correction::require_worker_custody(
                &unknown, &evidence, native
            )
            .is_err());
            let mut legacy = entries;
            for entry in &mut legacy {
                entry.observation = None;
            }
            invalid.status = WorkerExecutionJournalStatus::Loaded(legacy);
            assert!(super::managed_parent_correction::require_worker_custody(
                &old, &invalid, native
            )
            .is_err());
            let final_turn: Value = serde_json::from_slice(
                &archived[Path::new("evidence/incoming/parent.attempt-2.json")],
            )?;
            assert_eq!(final_turn["turn"]["report"]["status"], "failed");
            assert_eq!(final_turn["turn"]["report"]["accepted"], false);
        }
        for turn in [1, 2, 3, 4] {
            let envelope: Value = serde_json::from_slice(&fs::read(
                self.run_dir
                    .join(format!("evidence/incoming/parent.attempt-{turn}.json")),
            )?)?;
            assert_eq!(envelope["parent_attempt"], json!(turn));
            if turn % 2 == 0 {
                assert_eq!(envelope["source_parent_attempt"], json!(turn - 1));
            }
        }
        let requests = self.requests.lock().unwrap();
        let review_cycles = if self.case.ends_with("auditor") { 2 } else { 1 };
        let lenses = &context.plan.review_lenses;
        assert_eq!(lenses.len(), 3, "required review stack was changed");
        assert_eq!(requests.len(), lenses.len() * review_cycles);
        assert_eq!(report.audit_reports.len(), lenses.len());
        let audits = self.audits.lock().unwrap();
        assert_eq!(audits.len(), requests.len());
        if review_cycles == 2 {
            assert!(audits[..lenses.len()]
                .iter()
                .any(|audit| audit.rejection_kind
                    == Some(AuditorRejectionKind::ImplementationDefect)
                    && audit.status == ReviewStatus::Rejected
                    && audit.rejected));
            assert_ne!(
                requests[0].request_binding,
                requests[requests.len() - lenses.len()].request_binding
            );
        }
        assert!(audits[audits.len() - lenses.len()..]
            .iter()
            .all(|audit| audit.accepted
                && !audit.rejected
                && audit.status == ReviewStatus::Succeeded));
        let final_requests = &requests[requests.len() - lenses.len()..];
        let aggregate = report
            .review_lens_aggregate
            .as_ref()
            .context("actual independent review aggregate")?;
        assert_eq!(aggregate.decision, ReviewAggregationDecision::Accept);
        assert_eq!(aggregate.validated_accepts, lenses.len());
        let manifest: Value = serde_json::from_slice(&fs::read(
            self.run_dir.join("reports/parent.candidate.json"),
        )?)?;
        let patch = fs::read_to_string(self.run_dir.join("reports/parent.candidate.patch"))?;
        for (lens, request) in lenses.iter().zip(final_requests) {
            assert_eq!(request.lens_id, lens.id);
            assert_eq!(request.information.scope(), lens.information_scope);
            assert!(aggregate
                .lens_verdicts
                .iter()
                .any(|verdict| verdict.lens.id == lens.id
                    && verdict.request_binding.as_deref()
                        == Some(request.request_binding.as_str())));
            use crate::review::ReviewLensScopedInformation;
            match &request.information {
                ReviewLensScopedInformation::BoundedFullChildTranscript {
                    bindings,
                    diff,
                    output_report,
                    ..
                } => {
                    assert_eq!(
                        bindings.candidate_binding["supervisor_inspected"],
                        manifest["candidate_binding"]
                    );
                    assert_eq!(diff, &patch);
                    let reviewed: OrchestratorReviewReport = serde_json::from_str(output_report)?;
                    assert_eq!(reviewed.worker_reports, report.worker_reports);
                    let evidence = bindings.validation_bindings["worker_execution_evidence"]
                        .as_array()
                        .context("current-cycle Worker evidence packet")?;
                    assert_eq!(evidence.len(), assignment.worker_assignments.len() * 2);
                    assert!(
                        evidence.iter().all(|entry| entry["evidence"]["source"]
                            .as_str()
                            .is_some_and(|path| path.starts_with("nested/parent/attempt-3/"))),
                        "old failed journal leaked into current proof"
                    );
                }
                ReviewLensScopedInformation::DiffOnly { diff } => assert_eq!(diff, &patch),
                ReviewLensScopedInformation::OutputReportOnly { output_report } => {
                    let reviewed: OrchestratorReviewReport = serde_json::from_str(output_report)?;
                    assert_eq!(reviewed.worker_reports, report.worker_reports);
                }
                other => bail!("unexpected review scope: {other:?}"),
            }
        }
        let events = fs::read_to_string(
            self.run_dir
                .join(crate::orchestration_event::ORCHESTRATION_EVENT_PATH),
        )?;
        let corrections = events
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|event| {
                event
                    .get("payload")
                    .and_then(|payload| payload.get("managed_correction_cycle"))
                    .cloned()
            })
            .collect::<Vec<_>>();
        assert_eq!(corrections.len(), 1);
        let correction = &corrections[0];
        assert_eq!(correction["parent_attempt"], 3);
        assert_eq!(correction["continuation_attempt"], 4);
        let old = &correction["predecessor_inbox_binding"];
        let fresh = &correction["inbox_binding"];
        assert_eq!(old["state_instance"], fresh["state_instance"]);
        assert_eq!(old["run"], fresh["run"]);
        assert_eq!(old["parent"], fresh["parent"]);
        assert_eq!(old["workers"], fresh["workers"]);
        assert_eq!(old["attempt"], 1);
        assert_eq!(fresh["attempt"], 3);
        assert_ne!(old["generation"], fresh["generation"]);
        let tracker = outcome.gate_tracker.as_ref().unwrap();
        assert_eq!(tracker.used, 1);
        assert!(tracker.denials.iter().any(|denial| matches!(
            denial.reason,
            GateDenialReason::ValidationRepair { .. }
                | GateDenialReason::AuditorRepair {
                    rejection: AuditorRejectionKind::ImplementationDefect
                }
        )));
        let budget = context.budget_ledger.report()?;
        let review_charges = lenses.len() * review_cycles;
        assert_eq!(budget.active_reservations, 0);
        assert_eq!(budget.charges.len(), 8 + review_charges);
        assert_eq!(budget.consumed.tokens, 14 * (8 + review_charges));
        assert_eq!(
            budget
                .charges
                .iter()
                .map(|charge| charge.reservation_id)
                .collect::<BTreeSet<_>>()
                .len(),
            8 + review_charges
        );
        assert_eq!(
            budget
                .charges
                .iter()
                .filter(|charge| charge.role != AgentRole::Auditor)
                .count(),
            8
        );
        assert!(budget.usage_complete && !outcome.usage_incomplete);
        assert_eq!(context.sync_store.snapshot()?.len(), 1);
        assert_eq!(context.sync_store.snapshot()?[0].token.get(), claim);
        Ok(())
    }
}

fn decode_prompt_json<T: serde::de::DeserializeOwned>(prompt: &str, marker: &str) -> Result<T> {
    let source = prompt
        .split_once(marker)
        .context("scoped review prompt marker")?
        .1;
    let mut values = serde_json::Deserializer::from_str(source).into_iter::<T>();
    values
        .next()
        .context("scoped review JSON missing")?
        .map_err(Into::into)
}

fn require_native(run: &ExternalAgentRun) -> Result<()> {
    if !run.scratch_quiescence_verified()
        || !external_process_completed(run, SupervisorRuntime::Codex)
        || !external_containment_verified(run, SupervisorRuntime::Codex)
        || run.authenticated_app_server_evidence().is_none()
        || !run.stdout.target_launch_attempted
    {
        bail!("fixture lost actual native confinement/capture/completion");
    }
    Ok(())
}

#[test]
fn managed_correction_outer_loop_observed_failed_worker_then_fresh_worker_and_required_reviews(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-outer-validation")
}

#[test]
fn managed_correction_outer_loop_omitted_failure_repeated_failure_and_reordered_subset_refuse(
) -> Result<()> {
    for case in [
        "omitted-failure",
        "omitted-repeat-failure",
        "reordered",
        "wrong-occurrence",
    ] {
        super::nested_driver_tests::driver_fixture(&format!("managed-cycle-process-outer-{case}"))?;
    }
    Ok(())
}

#[test]
fn managed_correction_outer_loop_explicit_validation_reference_refuses_wrong_or_ambiguous_occurrence(
) -> Result<()> {
    for case in [
        "wrong-validation-occurrence",
        "ambiguous-validation-reference",
    ] {
        super::nested_driver_tests::driver_fixture(&format!("managed-cycle-process-outer-{case}"))?;
    }
    Ok(())
}

#[test]
fn managed_correction_outer_loop_isolated_failure_then_serial_union_repair_and_required_reviews(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-outer-isolated")
}

#[test]
fn managed_correction_outer_loop_actual_implementation_auditor_repair_repeats_required_reviews(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-outer-auditor")
}

/// Same explicit synthetic prior pattern as the existing selected-review
/// fixtures. No real account entitlement or model quality is inferred from it.
pub(super) fn bind_fixture_prior(
    repo: &Path,
    plan: &SupervisorPlan,
) -> Result<super::super::prior_input::OperatorPriorDataGuard> {
    use super::super::model_policy::{ModelCapabilityEvidence, ModelCapabilityPolicy};
    use super::super::prior_input::{bind_operator_prior_data, OperatorPriorSnapshot};
    let base =
        super::super::selection_bridge::base_selector_priors_with_terminal_worker_economics()?;
    let mut prior = base
        .models
        .iter()
        .find(|row| row.runtime == "codex" && row.model == "gpt-6.1-sol")
        .cloned()
        .context("existing fixture baseline prior")?;
    let baseline = prior.clone();
    prior.source_id = "synthetic-managed-outer-loop".into();
    prior.prior_scope = "offline native loop fixture only".into();
    prior
        .limitations
        .push("synthetic fixture; not measured model or account evidence".into());
    for lens in &plan.review_lenses {
        let effort = crate::selection::ReasoningEffort::parse(
            &resolve_review_lens_reasoning_effort(lens, None).resolved,
        )
        .context("fixture lens effort")?;
        if !prior
            .class_fit
            .iter()
            .any(|row| row.task_class == "review_gate" && row.effort == effort)
        {
            let mut row = baseline
                .class_fit
                .iter()
                .find(|row| row.task_class == "review_gate")
                .cloned()
                .context("fixture review baseline")?;
            row.effort = effort;
            prior
                .authority_evidence
                .push(crate::selection::AuthorityEvidencePrior {
                    task_class: row.task_class.clone(),
                    role: crate::selection::AuthorityRole::ReviewAuditor,
                    effort,
                    quality_basis_points: row.quality_basis_points,
                    sample_size: row.sample_size,
                });
            prior.class_fit.push(row);
        }
    }
    let snapshot = OperatorPriorSnapshot {
        schema_version: 1,
        dataset_id: "synthetic-managed-outer-loop".into(),
        revision: format!("{}+managed-outer-fixture", base.revision),
        published_on: base.published_on.clone(),
        models: vec![prior],
        public_benchmarks: Vec::new(),
        capability_policy: ModelCapabilityPolicy {
            id: "synthetic-managed-outer-loop".into(),
            version: 1,
            source: "offline native fixture only".into(),
            models: vec![ModelCapabilityEvidence {
                model: "gpt-6.1-sol".into(),
                capability: ModelCapabilityClass::CriticalJudgment,
                eligible: true,
                evidence: "synthetic fixture only; no account qualification".into(),
                as_of: base.published_on,
            }],
        },
    };
    let relative = Path::new("managed-outer-fixture-prior.json");
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(repo.join(relative))?;
    file.write_all(&serde_json::to_vec(&snapshot)?)?;
    drop(file);
    bind_operator_prior_data(repo, relative)
}

pub(super) fn bind_fixture_policy(
    repo: &Path,
    plan: &SupervisorPlan,
    metadata: &mut SupervisorPlanMetadata,
    isolated: bool,
) -> Result<crate::selection::routing_policy::RoutingPolicyGuard> {
    use crate::selection::routing_policy::{bind_routing_policy, load_routing_policy};
    let mut frozen = load_routing_policy(repo)?;
    frozen.policy.objective.effort_distance_weight = 1_000_000_000_000;
    for (role, effort) in [
        ("worker", crate::selection::ReasoningEffort::Xhigh),
        (
            "child_orchestrator",
            crate::selection::ReasoningEffort::High,
        ),
    ] {
        let mut preference = frozen.policy.default_role.clone();
        preference.preferred_effort = Some(effort);
        frozen
            .policy
            .role_preferences
            .insert(role.into(), preference);
    }
    frozen.sha256 = crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
    let parent = &plan.assignments[0];
    let assignments = if isolated {
        parent
            .worker_assignments
            .iter()
            .map(|worker| crate::planning::TaskAssignmentProposal {
                id: worker.id.clone(),
                task: worker.task.clone().unwrap(),
                fragment_ids: vec![worker.id.clone()],
                assigned_paths: worker.assigned_paths.clone(),
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                decision_dependencies: Vec::new(),
            })
            .collect::<Vec<_>>()
    } else {
        vec![crate::planning::TaskAssignmentProposal {
            id: parent.id.clone(),
            task: parent.task.clone().unwrap(),
            fragment_ids: vec![parent.id.clone()],
            assigned_paths: parent.assigned_paths.clone(),
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            decision_dependencies: Vec::new(),
        }]
    };
    let proposal = crate::planning::TaskDecompositionProposal {
        fragments: assignments
            .iter()
            .map(|assignment| crate::planning::TaskSpecFragment {
                id: assignment.id.clone(),
                text: assignment.task.clone(),
            })
            .collect(),
        disjointness: crate::planning::task_assignment_disjointness(&assignments)?,
        assignments,
        coverage_gaps: Vec::new(),
        diagnostics: Default::default(),
    };
    metadata.task_routing_assessment = Some(super::super::task_routing::assess_task_routing(
        &plan.task, &proposal, &frozen,
    )?);
    metadata.resolved_routing_policy = Some(frozen.clone());
    bind_routing_policy(Some(frozen))
}

/// Only selected explicitly by the contained offline peer. This subprocess uses
/// the real CLI parser, native journal producer and numeric process exit contract.
#[test]
#[ignore = "subprocess endpoint; invoked by the native production-journal fixture"]
fn production_journal_cli_helper() {
    use clap::Parser;
    let args = std::env::args().collect::<Vec<_>>();
    let index = args
        .iter()
        .position(|arg| arg == "--skip")
        .expect("native helper argv");
    let argv: Vec<String> = serde_json::from_str(&args[index + 1]).expect("exact CLI argv");
    let code = match crate::cli::Cli::try_parse_from(argv)
        .map_err(anyhow::Error::from)
        .and_then(|cli| cli.run())
    {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error:#}");
            error
                .downcast_ref::<WorkerJournalCommandExit>()
                .map_or(125, |exit| exit.code())
        }
    };
    std::process::exit(code);
}

#[test]
fn managed_correction_outer_loop_isolated_success_then_actual_auditor_rejection_never_imports_pre_review(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-outer-isolated-auditor")
}
#[test]
fn managed_correction_outer_loop_unknown_host_outcome_cannot_be_repaired_by_worker_json(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-outer-unknown")
}
#[test]
fn managed_correction_outer_loop_real_launch_failure_cannot_be_repaired_by_worker_json(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-outer-launch")
}
#[test]
fn managed_correction_outer_loop_real_signal_failure_cannot_be_repaired_by_worker_json(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-outer-signal")
}

#[test]
fn managed_correction_outer_loop_isolated_success_integrates_once_only_after_all_reviews_accept(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-outer-isolated-accepted")
}
