use super::*;

fn artifact_hashes(
    context: &AssignmentExecutionContext<'_, '_>,
) -> Result<BTreeMap<PathBuf, String>> {
    [
        "evidence/incoming/parent.attempt-1.json",
        "evidence/incoming/parent.attempt-2.json",
        "nested/parent/attempt-1/worker/report.json",
        "nested/parent/attempt-1/worker/journals/worker.jsonl",
        "nested/parent/attempt-1/worker-two/report.json",
        "nested/parent/attempt-1/worker-two/journals/worker-two.jsonl",
    ]
    .into_iter()
    .map(|name| {
        Ok((
            PathBuf::from(name),
            crate::artifacts::state_auth::sha256_hex(&fs::read(context.run_dir.join(name))?),
        ))
    })
    .collect()
}

/// Exercises the production managed controller and decision/authorization path
/// with native contained app-server peers. The peer really edits and compiles
/// the candidate. Its deliberately rejected first report is a gate input, not
/// evidence that the compiler failed. Independent reviewer execution still
/// needs the separate read-only review-packet peer (not supplied by this fixture).
pub(in super::super) fn exercise(
    case: &str,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    prepared: Box<PreparedChildAttempt<'_>>,
    calls: &Mutex<Vec<String>>,
) -> Result<()> {
    outcome.gate_tracker = Some(GateCorrectionTracker::new(if case == "correction-budget" {
        0
    } else {
        context.plan.max_gate_corrections
    }));
    // Model disjoint assignment B with an actually admitted reservation in A's
    // shared ledger. It stays active throughout A's native correction cycle.
    let unrelated = if case == "correction-concurrent-reservation" {
        let admission =
            context
                .budget_ledger
                .reserve(crate::supervise_budget::BudgetReservationRequest {
                    role: AgentRole::Auditor,
                    tokens: 17,
                    cost_usd: Some(0.0),
                })?;
        Some(
            admission
                .reservation()
                .context("unrelated B admission")?
                .clone(),
        )
    } else {
        None
    };
    let primary = primary_worktree_snapshot(context.repo, context.execution_runtime)?;
    let parent = preflight.assignment.clone();
    let original_claim = preflight.claim.clone();
    let base = preflight.child_base_head;
    let schemas = &context.dirs.schemas;
    let mut collected = managed_parent_controller::dispatch_and_collect_managed_parent_attempt(
        context,
        outcome,
        preflight,
        preflight.journal_parent_id,
        1,
        prepared,
        &context.budget_policy,
        3,
        &schemas.join("orchestrator-review-report.schema.json"),
        &schemas.join("worker-report.schema.json"),
        &schemas.join("auditor-report.schema.json"),
        None,
    )?;
    assert!(collected.external_run.scratch_quiescence_verified());
    assert!(external_process_completed(
        &collected.external_run,
        SupervisorRuntime::Codex
    ));
    assert!(collected
        .external_run
        .authenticated_app_server_evidence()
        .is_some());
    assert_eq!(
        *calls.lock().unwrap(),
        ["parent", "worker", "worker-two", "parent"]
    );
    let old_artifacts = artifact_hashes(context)?;
    let mut completion = collected
        .managed_completion
        .take()
        .context("native completion")?;
    let old_binding = completion.binding.clone();
    let mut structural = 1;
    let mut feedback = None;
    let mut history = Vec::new();
    let mut warning = None;
    let disposition = decide_child_attempt(
        context,
        outcome,
        preflight,
        preflight.journal_parent_id,
        1,
        &mut structural,
        &mut feedback,
        &mut history,
        &mut warning,
        collected,
    )?;
    if case == "correction-budget" {
        assert!(matches!(
            disposition,
            ChildAttemptDisposition::Finish { .. }
        ));
        assert!(feedback.is_none());
        assert_eq!(calls.lock().unwrap().len(), 4);
        return Ok(());
    }
    if matches!(case, "correction-auditor" | "correction-evidence-only") {
        assert!(matches!(
            disposition,
            ChildAttemptDisposition::Finish { .. }
        ));
        let denial = GateDenial::new(
            "native-correction-auditor",
            GateDenialReason::AuditorRepair {
                rejection: if case == "correction-auditor" {
                    AuditorRejectionKind::ImplementationDefect
                } else {
                    AuditorRejectionKind::EvidenceQuality
                },
            },
            VerifiedGateContext::new(&parent.id, GateCheckSource::Auditor, &parent.assigned_paths)?,
        )?;
        feedback = outcome
            .gate_tracker
            .as_mut()
            .unwrap()
            .authorize(
                denial,
                context.artifacts,
                &parent.id,
                preflight.journal_parent_id,
                &mut outcome.health_signals,
            )?
            .map(ChildAttemptCorrection::Gate);
    } else {
        assert!(matches!(disposition, ChildAttemptDisposition::Retry));
    }
    assert_eq!(history.len(), 1);
    match case {
        "correction-stale" => {
            fs::write(
                preflight.worktree.path.join("src/lib.rs"),
                "// stale candidate\n",
            )?;
        }
        "correction-foreign" => completion.assignment.id = "foreign-parent".into(),
        "correction-unknown-quiescence" => completion.live_run.process_tree = None,
        "correction-serialized" => {
            completion.live_run =
                serde_json::from_value(serde_json::to_value(&completion.live_run)?)?;
        }
        "correction-fake" => completion.runtime = SupervisorRuntime::Fake,
        "correction-cancelled" => context.cancellation.cancel(),
        _ => {}
    }
    if unrelated.is_some() {
        let budget = context.budget_ledger.report()?;
        assert_eq!(budget.active_reservations, 1);
        assert_eq!(budget.reserved.tokens, 17);
        assert_eq!(budget.charges.len(), 4, "A's predecessor was not settled");
        assert!(budget.usage_complete && budget.new_dispatch_allowed);
    }
    let authorized = completion.authorize(
        context,
        preflight,
        outcome,
        feedback
            .as_ref()
            .context("authorized correction feedback")?,
        structural,
        2,
        if case == "correction-cycle-budget" {
            1
        } else {
            3
        },
    );
    if matches!(
        case,
        "correction-stale"
            | "correction-foreign"
            | "correction-unknown-quiescence"
            | "correction-serialized"
            | "correction-fake"
            | "correction-cancelled"
            | "correction-cycle-budget"
            | "correction-evidence-only"
    ) {
        assert!(authorized.is_err(), "unsafe correction authorized: {case}");
        assert_eq!(
            calls.lock().unwrap().len(),
            4,
            "correction Worker was launched"
        );
        assert_eq!(artifact_hashes(context)?, old_artifacts);
        return Ok(());
    }
    let authority = authorized?;
    if case == "correction-replay" {
        let (binding, _permit) = authority.admit(
            context,
            preflight,
            outcome,
            3,
            SupervisorRuntime::Codex,
            &context.budget_policy,
        )?;
        assert!(binding != old_binding);
        assert!(authority
            .admit(
                context,
                preflight,
                outcome,
                3,
                SupervisorRuntime::Codex,
                &context.budget_policy
            )
            .is_err());
        assert!(preflight.issue_nested_turn(3).is_err());
        assert_eq!(calls.lock().unwrap().len(), 4);
        return Ok(());
    }
    if case == "correction-native-lane" {
        // Native execution is Verified Codex, not a separate RuntimeId. A
        // deterministic Fake lane must not replace this live native predecessor.
        assert_eq!(
            context.execution_runtime,
            SupervisorExecutionRuntime::Verified
        );
        assert_eq!(authority.predecessor.runtime, SupervisorRuntime::Codex);
        let denial = authority
            .admit(
                context,
                preflight,
                outcome,
                3,
                SupervisorRuntime::Fake,
                &context.budget_policy,
            )
            .err()
            .context("native correction accepted a Fake runtime substitution")?;
        assert_eq!(
            denial.to_string(),
            "managed correction cannot replay admission or change its parent runtime"
        );
        assert_eq!(calls.lock().unwrap().len(), 4);
        return Ok(());
    }
    if case == "correction-late-stale" {
        fs::write(
            preflight.worktree.path.join("src/lib.rs"),
            "// late candidate drift\n",
        )?;
    }
    if case == "correction-foreign-owner" {
        context.sync_store.release(preflight.claim.token)?;
    }
    if matches!(case, "correction-late-stale" | "correction-foreign-owner") {
        assert!(authority
            .revalidate(context, preflight, outcome, 3)
            .is_err());
        assert_eq!(calls.lock().unwrap().len(), 4);
        return Ok(());
    }
    assert!(
        preflight.issue_nested_turn(3).is_err(),
        "initial permit was replenished"
    );
    let prepared = match prepare_child_attempt_with_purpose(
        context,
        outcome,
        &context.budget_policy,
        preflight,
        preflight.journal_parent_id,
        3,
        3,
        &feedback,
        &schemas.join("orchestrator-review-report.schema.json"),
        &schemas.join("worker-report.schema.json"),
        &schemas.join("auditor-report.schema.json"),
        ChildAttemptPurpose::ManagedParentCorrection(&authority),
    )? {
        AssignmentExecutionDisposition::Continue(prepared) => prepared,
        AssignmentExecutionDisposition::Complete => {
            bail!("fresh native correction stopped before dispatch")
        }
    };
    assert_eq!(prepared.command.workspace_access, WorkspaceAccess::ReadOnly);
    assert!(prepared.command.codex_managed_worker_requests_enabled());
    let mut corrected = managed_parent_controller::dispatch_and_collect_managed_parent_attempt(
        context,
        outcome,
        preflight,
        preflight.journal_parent_id,
        3,
        prepared,
        &context.budget_policy,
        3,
        &schemas.join("orchestrator-review-report.schema.json"),
        &schemas.join("worker-report.schema.json"),
        &schemas.join("auditor-report.schema.json"),
        Some(&authority),
    )?;
    let fresh = corrected
        .managed_completion
        .take()
        .context("fresh native completion")?;
    assert_eq!(fresh.source_attempt, 3);
    assert!(fresh.binding != old_binding);
    assert_eq!(fresh.base, base);
    assert_eq!(fresh.assignment, parent);
    assert_eq!(preflight.claim, original_claim);
    assert!(authority
        .revalidate(context, preflight, outcome, 3)
        .is_err());
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "parent",
            "worker",
            "worker-two",
            "parent",
            "parent",
            "worker",
            "worker-two",
            "parent"
        ]
    );
    assert_eq!(
        artifact_hashes(context)?,
        old_artifacts,
        "spent evidence changed"
    );
    for turn in [1, 2, 3, 4] {
        let value: Value = serde_json::from_slice(&fs::read(
            context
                .run_dir
                .join(format!("evidence/incoming/parent.attempt-{turn}.json")),
        )?)?;
        assert_eq!(value["parent_attempt"], json!(turn));
        if turn % 2 == 0 {
            assert_eq!(value["source_parent_attempt"], json!(turn - 1));
        }
    }
    let disposition = decide_child_attempt(
        context,
        outcome,
        preflight,
        preflight.journal_parent_id,
        3,
        &mut structural,
        &mut feedback,
        &mut history,
        &mut warning,
        corrected,
    )?;
    let ChildAttemptDisposition::Finish {
        report,
        containment_verified,
        gate_terminal,
    } = disposition
    else {
        bail!("corrected native candidate did not finish its continuation");
    };
    assert!(!report_failed(&report), "{report:?}");
    assert!(containment_verified && !gate_terminal);
    assert!(
        parent_auditor_required(&parent, &report),
        "correction bypassed independent review"
    );
    assert_eq!(
        history
            .iter()
            .map(|entry| entry.attempt)
            .collect::<Vec<_>>(),
        [1, 3]
    );
    assert_eq!(
        primary_worktree_snapshot(context.repo, context.execution_runtime)?,
        primary
    );
    assert_eq!(current_head_oid(&preflight.worktree.path)?, base);
    assert_eq!(
        crate::external_agent::bind_existing_managed_child_git_boundary(&preflight.worktree.path)?
            .revalidate()?,
        base,
        "parent materialized before independent review"
    );
    let budget = context.budget_ledger.report()?;
    assert_eq!(budget.active_reservations, usize::from(unrelated.is_some()));
    assert_eq!(
        budget.reserved.tokens,
        if unrelated.is_some() { 17 } else { 0 }
    );
    assert_eq!(budget.consumed.tokens, 112);
    assert_eq!(budget.charges.len(), 8);
    assert!(budget.usage_complete && !outcome.usage_incomplete);
    assert!(
        budget
            .charges
            .iter()
            .map(|charge| charge.reservation_id)
            .collect::<BTreeSet<_>>()
            .len()
            == 8
    );
    assert_eq!(context.sync_store.snapshot()?, [original_claim]);
    if let Some(unrelated) = unrelated {
        // Only B's uninvoked fixture reservation is released at teardown, after
        // A has completed its correction without waiting for B.
        context.budget_ledger.release(unrelated.id)?;
        let after = context.budget_ledger.report()?;
        assert_eq!(after.active_reservations, 0);
        assert_eq!(after.reserved.tokens, 0);
        assert_eq!(after.consumed, budget.consumed);
        assert_eq!(after.charges, budget.charges);
    }
    Ok(())
}

#[test]
fn managed_correction_native_validation_cycles_preserve_evidence_scope_base_and_usage() -> Result<()>
{
    super::super::nested_driver_tests::driver_fixture("managed-cycle-process-correction-validation")
}

#[test]
fn managed_correction_native_settled_assignment_corrects_while_disjoint_reservation_stays_active(
) -> Result<()> {
    super::super::nested_driver_tests::driver_fixture(
        "managed-cycle-process-correction-concurrent-reservation",
    )
}

#[test]
fn managed_correction_native_structural_and_auditor_repairs_use_fresh_cycles() -> Result<()> {
    for case in ["structural", "auditor"] {
        super::super::nested_driver_tests::driver_fixture(&format!(
            "managed-cycle-process-correction-{case}"
        ))?;
    }
    Ok(())
}

#[test]
fn managed_correction_native_replay_stale_foreign_cancel_unknown_and_budgets_refuse() -> Result<()>
{
    for case in [
        "replay",
        "stale",
        "foreign",
        "cancelled",
        "unknown-quiescence",
        "serialized",
        "fake",
        "budget",
        "cycle-budget",
        "evidence-only",
        "late-stale",
        "foreign-owner",
        "native-lane",
    ] {
        super::super::nested_driver_tests::driver_fixture(&format!(
            "managed-cycle-process-correction-{case}"
        ))?;
    }
    Ok(())
}

#[test]
fn managed_correction_physical_turns_do_not_share_continuation_identity() -> Result<()> {
    assert_eq!(
        (1..=4).map(physical_turn).collect::<Result<Vec<_>>>()?,
        [1, 3, 5, 7]
    );
    assert!(physical_turn(0).is_err());
    assert!(physical_turn(usize::MAX).is_err());
    Ok(())
}
