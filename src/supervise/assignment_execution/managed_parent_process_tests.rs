use super::*;

pub(super) fn run(
    case: &str,
    command: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    template: &ExternalAgentRun,
    workers: &Mutex<Vec<WorkerReport>>,
) -> Result<ExternalAgentRun> {
    let case = case.strip_prefix("managed-cycle-process-").unwrap();
    let identity = command.agent_lifecycle.as_ref().unwrap();
    assert!(command.codex_native_delegation_is_disabled());
    let mode;
    let report;
    let mut payload = json!({"case":case});
    if identity.task_id != "parent" {
        mode = "worker";
        report = serde_json::from_slice(template.output_last_message().unwrap())?;
        assert_eq!(command.worker_journal_artifacts.len(), 1);
        payload["journal"] = json!(command.worker_journal_artifacts[0].path);
        payload["edit"] = json!(if identity.task_id == "worker" {
            "pub mod other;\npub fn first() -> u32 { 40 }\n"
        } else {
            "pub fn second() -> u32 { crate::first() + 2 }\n"
        });
    } else if command.codex_managed_worker_requests_enabled() {
        mode = "initial";
        assert!(command.worker_journal_artifacts.is_empty());
        report = json!({"version":1,"outcome":"yield_workers","run_id":identity.run_id,
            "parent_id":"parent","parent_attempt":1,"requests":[
                {"request_id":"r1","worker_id":"worker"},
                {"request_id":"r2","worker_id":"worker-two"}]});
    } else {
        mode = "final";
        assert!(command.codex_managed_readonly_continuation_enabled());
        assert!(command.worker_journal_artifacts.is_empty());
        let mut parent: OrchestratorReviewReport =
            serde_json::from_slice(template.output_last_message().unwrap())?;
        parent.worker_reports = workers.lock().unwrap().clone();
        parent.worker_reports.sort_by(|a, b| a.id.cmp(&b.id));
        parent.files_changed = vec!["src/lib.rs".into(), "src/other.rs".into()];
        parent.remaining_risk = "offline managed process fixture".into();
        parent.audit_reports.clear();
        parent.review_lens_aggregate = None;
        if case.ends_with("rejected-review") {
            parent.accepted = false;
            parent.rejected = true;
            parent.status = ReviewStatus::Failed;
        }
        if case == "forged-report" {
            parent.worker_reports[0].id = "foreign".into();
        }
        report = json!({"version":1,"run_id":identity.run_id,"parent_id":"parent",
            "source_parent_attempt":1,"parent_attempt":2,"completed_worker_ids":["worker","worker-two"],
            "turn":{"outcome":"final_report","report":parent}});
    }
    payload["mode"] = json!(mode);
    payload["report"] = report;
    let run = crate::external_agent::managed_parent_fixture::run(command, cancellation, payload)?;
    assert!(run.scratch_quiescence_verified());
    assert!(run.stdout.target_launch_attempted);
    assert!(run.authenticated_app_server_evidence().is_some(), "{run:?}");
    if mode == "initial" && !matches!(case, "forged-identity" | "widened-request") {
        assert!(run.publishable, "{run:?}");
    }
    if mode == "final" && case == "isolated-tampered" {
        let worker = workers
            .lock()
            .unwrap()
            .iter()
            .find(|worker| worker.id == "worker")
            .context("fixture Worker report")?
            .commands_run
            .first()
            .context("fixture Worker command")?
            .cwd
            .clone();
        fs::write(worker.join("src/lib.rs"), "tampered after capture\n")?;
    }
    if mode == "worker" {
        if case == "cancel-active-worker" && identity.task_id == "worker" {
            assert!(cancellation.is_cancelled());
            assert!(!run.publishable);
            assert!(!external_process_completed(&run, SupervisorRuntime::Codex));
            return Ok(run);
        }
        assert!(run.publishable, "{run:?}");
        workers.lock().unwrap().push(serde_json::from_slice(
            run.output_last_message().context("fixture Worker report")?,
        )?);
        if case == "cancel-after-first" && identity.task_id == "worker" {
            cancellation.cancel();
        }
    }
    Ok(run)
}

pub(super) fn exercise(
    case: &str,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    prepared: Box<PreparedChildAttempt<'_>>,
    calls: &Mutex<Vec<String>>,
) -> Result<()> {
    let case = case.strip_prefix("managed-cycle-process-").unwrap();
    // The fixture hand-builds the parent preflight. Mirror the production
    // preflight's pending token so terminal cleanup can detect double releases.
    outcome.claim_tokens.push(preflight.claim.token);
    let schemas = &context.dirs.schemas;
    let result = super::managed_parent_controller::dispatch_and_collect_managed_parent_attempt(
        context,
        outcome,
        preflight,
        context.options.run_id.as_str(),
        1,
        prepared,
        &context.budget_policy,
        1,
        &schemas.join("orchestrator-review-report.schema.json"),
        &schemas.join("worker-report.schema.json"),
        &schemas.join("auditor-report.schema.json"),
    );
    let observed = calls.lock().unwrap().clone();
    let budget = context.budget_ledger.report()?;
    assert_eq!(budget.active_reservations, 0);
    assert_eq!(budget.reserved.tokens, 0);
    if case != "isolated-tampered" {
        assert_eq!(
            context.sync_store.snapshot()?,
            vec![preflight.claim.clone()]
        );
        assert!(
            outcome.release_errors.is_empty(),
            "{:?}",
            outcome.release_errors
        );
        assert_eq!(outcome.claim_tokens, vec![preflight.claim.token]);
        assert_eq!(
            planned_claim_releases(context.sync_store, &outcome.claim_tokens)?,
            vec![preflight.claim.clone()]
        );
    }
    context.manager.verify_write_execution_lease(
        &preflight.assignment.id,
        preflight.worktree_write_lease.as_ref().unwrap(),
    )?;
    assert_eq!(
        fs::read_to_string(context.repo.join("src/lib.rs"))?,
        "pub fn selected() {}\n"
    );
    match case {
        "forged-identity" | "widened-request" => {
            assert!(result.is_err(), "invalid request accepted");
            assert_eq!(observed, ["parent"]);
        }
        "cancel-after-first" | "cancel-active-worker" => {
            assert!(result.is_err(), "cancelled cycle accepted");
            assert_eq!(observed, ["parent", "worker"]);
        }
        "widened-worker" => {
            let error = result.err().context("widened Worker edit accepted")?;
            assert!(
                format!("{error:#}").contains("outside its authored scope"),
                "{error:#}"
            );
            assert_eq!(observed, ["parent", "worker"]);
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
        }
        "forged-report" => {
            assert!(result.is_err(), "forged report accepted");
            assert_eq!(observed, ["parent", "worker", "worker-two", "parent"]);
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
        }
        "isolated-rejected-review" => {
            assert!(
                format!("{:#}", result.err().context("rejected parent integrated")?)
                    .contains("integration is not authorized")
            );
            assert_eq!(
                fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?,
                "pub fn selected() {}\n"
            );
            assert_eq!(
                fs::read_to_string(preflight.worktree.path.join("src/other.rs"))?,
                "pub fn other() {}\n"
            );
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
            assert_eq!(outcome.released_claims.len(), 2);
            for worker in ["worker", "worker-two"] {
                let path = context
                    .manager
                    .list_managed_verified()?
                    .into_iter()
                    .find(|record| record.name == worker)
                    .context("fixture Worker worktree")?
                    .path;
                assert_eq!(
                    current_head_oid(&path)?,
                    preflight.child_base_head,
                    "rejected Worker commit materialized"
                );
            }
            assert!(
                !super::super::scheduler::nested_workers_lack_observed_usage(
                    context.plan,
                    Some(&budget)
                )
            );
        }
        "isolated-tampered" => {
            assert!(result.is_err(), "tampered candidate accepted");
            assert!(outcome.external_containment_failed);
            assert!(
                !outcome.usage_incomplete,
                "tamper regression must reach the settled final capture"
            );
            assert!(outcome
                .release_errors
                .iter()
                .all(|error| !error.contains("not active")));
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
            assert_eq!(
                context.sync_store.snapshot()?.len(),
                3,
                "drift must retain authority"
            );
        }
        "isolated-overlap" => {
            assert!(result.is_err(), "overlapping candidate accepted");
            assert!(!observed.iter().skip(1).any(|id| id == "parent"));
            assert_eq!(
                current_head_oid(&preflight.worktree.path)?,
                preflight.child_base_head
            );
            assert_eq!(
                fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?,
                "pub fn selected() {}\n"
            );
        }
        "happy" | "lost-response" | "rejected-review" | "isolated-happy" => {
            let collected = result?;
            assert!(
                collected.report_shape_problems.is_empty(),
                "{:?}",
                collected.report_shape_problems
            );
            assert!(collected.attempt_containment_verified);
            assert_eq!(observed.len(), 4);
            assert_eq!(observed.first().unwrap(), "parent");
            assert_eq!(observed.last().unwrap(), "parent");
            assert_eq!(
                report_failed(&collected.attempt_report),
                case == "rejected-review"
            );
            assert_eq!(collected._worker_journal_evidence.len(), 2);
            let candidate = fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?;
            assert!(candidate.contains("pub fn first() -> u32 { 40 }"));
            let second = fs::read_to_string(preflight.worktree.path.join("src/other.rs"))?;
            assert!(second.contains("pub fn second() -> u32 { crate::first() + 2 }"));
            assert_eq!(budget.consumed.tokens, 56);
            let worker_charges = budget
                .charges
                .iter()
                .filter(|charge| charge.role == AgentRole::Worker)
                .collect::<Vec<_>>();
            assert_eq!(worker_charges.len(), 2);
            assert_ne!(
                worker_charges[0].reservation_id,
                worker_charges[1].reservation_id
            );
            assert!(worker_charges.iter().all(|charge| charge.tokens == 14));
            assert!(!outcome.usage_incomplete);
            if case == "isolated-happy" {
                assert_eq!(outcome.released_claims.len(), 2);
                assert!(
                    !super::super::scheduler::nested_workers_lack_observed_usage(
                        context.plan,
                        Some(&budget)
                    )
                );
                let mut unverified = budget.clone();
                unverified
                    .dispatch_bindings
                    .iter_mut()
                    .filter(|b| b.invocation.assignment_id == "worker-two")
                    .for_each(|b| b.invocation_verified = false);
                assert!(super::super::scheduler::nested_workers_lack_observed_usage(
                    context.plan,
                    Some(&unverified)
                ));
                let mut missing = budget.clone();
                missing
                    .dispatch_bindings
                    .retain(|b| b.invocation.assignment_id != "worker-two");
                assert!(super::super::scheduler::nested_workers_lack_observed_usage(
                    context.plan,
                    Some(&missing)
                ));
                let combined = collected
                    .attempt_report
                    .validation_results
                    .iter()
                    .find(|v| v.name == "combined check")
                    .context("final parent did not run combined check")?;
                assert_eq!(combined.status, ReviewStatus::Succeeded);
            }
            assert!(
                preflight.issue_nested_turn(1).is_err(),
                "spent turn replayed"
            );
            if case == "rejected-review" {
                assert_eq!(
                    current_head_oid(&preflight.worktree.path)?,
                    preflight.child_base_head
                );
            }
        }
        _ => bail!("unknown contained parent fixture case"),
    }
    Ok(())
}

#[test]
fn managed_parent_process_two_workers_edit_and_bind_observed_journals() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-happy")
}

#[test]
fn managed_parent_process_duplicate_receipt_executes_each_worker_once() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-lost-response")
}

#[test]
fn managed_parent_process_refuses_forged_identity_and_widened_request() -> Result<()> {
    for case in ["forged-identity", "widened-request"] {
        super::nested_driver_tests::driver_fixture(&format!("managed-cycle-process-{case}"))?;
    }
    Ok(())
}

#[test]
fn managed_parent_process_cancellation_prevents_second_worker() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-cancel-after-first")
}

#[test]
fn managed_parent_process_cancellation_drains_active_worker_and_descendant() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-cancel-active-worker")
}

#[test]
fn managed_parent_process_refuses_substituted_worker_report() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-forged-report")
}

#[test]
fn managed_parent_process_refuses_worker_edits_outside_authored_scope() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-widened-worker")
}

#[test]
fn managed_parent_process_rejected_parent_review_cannot_accept_workers() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-rejected-review")
}

#[test]
fn managed_parent_process_isolated_final_sees_combined_candidate_and_complete_diagnostics(
) -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-happy")
}

#[test]
fn managed_parent_process_isolated_rejection_discards_tentative_candidate() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-rejected-review")
}

#[test]
fn managed_parent_process_isolated_refuses_post_capture_tampering() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-tampered")
}

#[test]
fn managed_parent_process_isolated_refuses_overlapping_candidate_paths() -> Result<()> {
    super::nested_driver_tests::driver_fixture("managed-cycle-process-isolated-overlap")
}
