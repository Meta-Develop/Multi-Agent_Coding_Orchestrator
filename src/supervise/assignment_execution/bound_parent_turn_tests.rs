use super::*;
use crate::supervise::messaging_bridge::{
    with_supervisor_messaging_session,
    worker_requests::{
        frozen::{WorkerInboxEndpoint, WorkerInboxResources, WorkerInboxTurn},
        WorkerRequestBinding, WorkerRequestInbox,
    },
};
use crate::{
    artifacts::repository_authenticator_key_only,
    messaging::transport::{AssignmentMessagingLaunch, ENV_MESSAGE_ENDPOINT, ENV_MESSAGE_TOKEN},
};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
};

fn submit(
    launch: &AssignmentMessagingLaunch,
    run: &str,
    request: &str,
    worker: &str,
) -> Result<()> {
    let env: BTreeMap<_, _> = launch.environment_for(run, "parent")?.into_iter().collect();
    let mut stream = TcpStream::connect(&env[ENV_MESSAGE_ENDPOINT])?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    writeln!(
        stream,
        "{}",
        json!({"bearer":env[ENV_MESSAGE_TOKEN], "request":{
            "operation":"submit_worker_request", "request_id":request, "worker_id":worker
        }})
    )?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&response)?["ok"],
        true
    );
    Ok(())
}

// Production collection does not attach a Worker inbox yet. Inject that future
// collected-command/capture boundary explicitly, using a real authenticated IPC
// endpoint and journal. This is not an E2E collector/dispatch activation test.
pub(super) fn exercise(
    case: &str,
    context: &AssignmentExecutionContext<'_, '_>,
    preflight: &AssignmentExecutionPreflight<'_>,
    outcome: &mut AssignmentExecutionOutcome,
    parent: &mut CollectedChildAttempt<'_>,
) -> Result<()> {
    let resources = || WorkerInboxResources {
        repo: context.repo,
        parent: &preflight.assignment,
        lease: preflight.worktree_write_lease.as_ref().unwrap(),
        claim: &preflight.claim,
        claims: context.sync_store,
    };
    let binding = with_supervisor_messaging_session(context.run_dir, |factory| {
        factory.worker_request_binding(
            &context.options.run_id,
            &preflight.assignment,
            1,
            "generation",
        )
    })?;
    let turn = WorkerInboxTurn::new(binding.clone(), 7, resources())?;
    let inbox = WorkerRequestInbox::create(
        repository_authenticator_key_only(context.repo)?,
        binding.clone(),
    )?;
    if case == "bound-recovered" {
        drop(inbox);
        let recovered =
            WorkerRequestInbox::recover(repository_authenticator_key_only(context.repo)?, binding)?;
        assert!(WorkerInboxEndpoint::start(
            context.run_dir,
            &turn,
            recovered,
            ProcessCancellation::new()
        )
        .is_err());
        return Ok(());
    }
    let endpoint =
        WorkerInboxEndpoint::start(context.run_dir, &turn, inbox, ProcessCancellation::new())?;
    let launch = endpoint.launch();
    // Durable order deliberately differs from lexical order and authored order.
    submit(
        &launch,
        context.options.run_id.as_str(),
        "z-first",
        "worker-two",
    )?;
    submit(
        &launch,
        context.options.run_id.as_str(),
        "a-second",
        "worker",
    )?;
    let frozen = endpoint.shutdown()?;
    let mut report = json!({"version":1, "outcome":"yield_workers",
        "run_id":context.options.run_id.as_str(), "parent_id":"parent", "parent_attempt":1,
        "requests":[{"request_id":"z-first", "worker_id":"worker-two"},
                    {"request_id":"a-second", "worker_id":"worker"}]});
    match case {
        "bound-forged" => report["requests"][0]["request_id"] = json!("forged"),
        "bound-wrong-worker" => report["requests"][0]["worker_id"] = json!("foreign"),
        "bound-duplicate" => report["requests"][1] = report["requests"][0].clone(),
        "bound-missing" => {
            report["requests"].as_array_mut().unwrap().pop();
        }
        "bound-wrong-order" => report["requests"].as_array_mut().unwrap().reverse(),
        "bound-stale-yield" => report["parent_attempt"] = json!(2),
        "bound-mixed-envelope" => report["report"] = json!({}),
        _ => {}
    }
    parent.external_run.output_last_message = Some(serde_json::to_vec(&report)?);
    // Neither good nor bad filesystem report bytes may replace the held capture.
    fs::write(
        context
            .run_dir
            .join(&parent.attempt_artifacts.raw_report_relative),
        b"{\"outcome\":\"final_report\"}",
    )
    .context("substitute retained report artifact after scratch cleanup")?;
    if case != "bound-ordinary-endpoint" {
        parent._command = parent._command.clone().with_assignment_messaging(launch);
    }
    match case {
        "bound-restored" => {
            parent.external_run =
                serde_json::from_value(serde_json::to_value(&parent.external_run)?)?
        }
        "bound-nonquiescent" => parent.external_run.process_tree = None,
        "bound-blocked" => parent.environment_blocked = true,
        "bound-side-effects" => {
            parent.external_side_effect_state = Some(ExternalSideEffectState::Ambiguous)
        }
        "bound-cancelled-before" => context.cancellation.cancel(),
        _ => {}
    }
    let mut foreign_binding = binding.clone();
    if case == "bound-foreign-generation" {
        foreign_binding = with_supervisor_messaging_session(context.run_dir, |factory| {
            factory.worker_request_binding(
                &context.options.run_id,
                &preflight.assignment,
                1,
                "other-generation",
            )
        })?;
    }
    if case == "bound-foreign-state" {
        foreign_binding = WorkerRequestBinding::new(
            "foreign-state-instance",
            &context.options.run_id,
            &preflight.assignment,
            1,
            "generation",
        )?;
    }
    let foreign_turn = WorkerInboxTurn::new(
        foreign_binding,
        if case == "bound-foreign-turn" { 8 } else { 7 },
        resources(),
    )?;
    let current = if matches!(
        case,
        "bound-foreign-state"
            | "bound-foreign-generation"
            | "bound-foreign-turn"
            | "bound-same-label-owner"
    ) {
        &foreign_turn
    } else {
        &turn
    };
    let attempt = if case == "bound-wrong-attempt" { 2 } else { 1 };
    let result = bound_parent_turn::BoundParentTurnYield::bind(
        context, preflight, attempt, parent, current, frozen,
    );
    let expected_error = match case {
        "bound-forged"
        | "bound-wrong-worker"
        | "bound-duplicate"
        | "bound-missing"
        | "bound-wrong-order"
        | "bound-stale-yield"
        | "bound-mixed-envelope" => Some("yield"),
        "bound-ordinary-endpoint" => Some("endpoint"),
        "bound-foreign-state"
        | "bound-foreign-generation"
        | "bound-foreign-turn"
        | "bound-same-label-owner" => Some("foreign"),
        "bound-wrong-attempt" => Some("attempt"),
        "bound-restored" | "bound-nonquiescent" => Some("quiescence"),
        "bound-blocked" | "bound-side-effects" => Some("unblocked"),
        "bound-cancelled-before" => Some("revoked"),
        _ => None,
    };
    if let Some(expected) = expected_error {
        let error = result.err().with_context(|| format!("accepted {case}"))?;
        assert!(format!("{error:#}").contains(expected), "{case}: {error:#}");
        return Ok(());
    }
    let bound = result?;
    assert_eq!(
        bound.requests().collect::<Vec<_>>(),
        [("z-first", "worker-two"), ("a-second", "worker")]
    );
    let view = bound.revalidate(context, preflight, 1, &turn)?;
    assert_eq!(view.turn, 7);
    assert_eq!(view.watermark.last_sequence, 2);
    let before = context.sync_store.status_snapshot()?;
    if case.starts_with("bound-evidence-") {
        let mut policy = context.budget_policy.clone();
        policy.set_selector_binding_for_test(
            AgentRole::Worker,
            SupervisorRuntime::Codex,
            RoleModelSelection {
                model: Some("gpt-5.6-sol".into()),
                reasoning_effort: Some("xhigh".into()),
                ..Default::default()
            },
        );
        let consumer = if case == "bound-evidence-stale" {
            &foreign_turn
        } else {
            &turn
        };
        if case == "bound-evidence-cancel-before" {
            context.cancellation.cancel();
        }
        if case == "bound-evidence-candidate-before" {
            fs::write(
                preflight.worktree.path.join("src/lib.rs"),
                "changed before dispatch\n",
            )?;
        }
        if let Some(boundary) = case.strip_prefix("bound-evidence-handoff-") {
            bound_parent_turn::set_candidate_handoff_mutation(
                boundary.starts_with("before"),
                if boundary.ends_with("outside") {
                    "outside.txt"
                } else {
                    "src/lib.rs"
                }
                .into(),
            );
        }
        let usage_start = outcome.usage_samples.len();
        let commands_start = outcome.command_records.len();
        let completed = bound.execute_serial(context, preflight, 1, consumer, outcome, &policy);
        if matches!(
            case,
            "bound-evidence-stale"
                | "bound-evidence-cancel-before"
                | "bound-evidence-candidate-before"
        ) {
            assert!(completed.is_err());
            return Ok(());
        }
        // Even failure cannot produce another driver with a fresh outcome/attempt.
        for attempt in [1, 2] {
            let mut other = AssignmentExecutionOutcome::default();
            assert!(NestedWorkerSerialDriver::from_collected_parent(
                context, preflight, &mut other, attempt, parent
            )
            .is_err());
        }
        if matches!(
            case,
            "bound-evidence-forged"
                | "bound-evidence-widened"
                | "bound-evidence-failure"
                | "bound-evidence-cancel-during"
                | "bound-evidence-second-failure"
        ) || case.starts_with("bound-evidence-handoff-")
        {
            let error = completed
                .err()
                .with_context(|| format!("accepted {case}"))?;
            if case.starts_with("bound-evidence-handoff-before") {
                assert!(
                    format!("{error:#}").contains("bound predecessor"),
                    "{error:#}"
                );
            } else if case.starts_with("bound-evidence-handoff-after") {
                assert!(
                    format!("{error:#}").contains("candidate snapshot changed"),
                    "{error:#}"
                );
            } else if case == "bound-evidence-second-failure" {
                assert!(
                    format!("{error:#}").contains("did not complete successfully"),
                    "{error:#}"
                );
                assert_eq!(
                    fs::read_to_string(preflight.worktree.path.join("src/lib.rs"))?,
                    "// written by worker-two\n"
                );
                assert_eq!(outcome.command_records.len() - commands_start, 2);
            }
            assert!(context.cancellation.is_cancelled());
            assert!(outcome.assignment_failed);
            let mut recovered = WorkerRequestInbox::recover(
                repository_authenticator_key_only(context.repo)?,
                binding.clone(),
            )?;
            assert!(recovered.requires_reconciliation());
            assert!(recovered.submit("z-first", "worker-two").is_err());
            assert!(recovered.transition("z-first", crate::supervise::messaging_bridge::worker_requests::WorkerRequestStatus::Reserved).is_err());
            return Ok(());
        }
        let completed = completed?;
        let (view, workers) = completed.revalidate(context, preflight, 1, &turn)?;
        assert_eq!(view.binding, &binding);
        assert_eq!(view.turn, 7);
        assert_eq!(view.watermark.last_sequence, 2);
        assert_eq!(
            workers.iter().map(|w| w.identity()).collect::<Vec<_>>(),
            [(1, "z-first", "worker-two"), (2, "a-second", "worker")]
        );
        assert_eq!(
            workers.iter().flat_map(|w| w.usage()).collect::<Vec<_>>(),
            outcome.usage_samples[usage_start..]
                .iter()
                .collect::<Vec<_>>()
        );
        for worker in workers {
            assert_eq!(worker.evidence().report().id, worker.identity().2);
            assert_eq!(worker.evidence().journals().len(), 1);
            assert!(worker.evidence().run().output_last_message().is_some());
            if case == "bound-evidence-edits" {
                assert_eq!(
                    worker.evidence().observed_changed_paths(),
                    &[PathBuf::from("src/lib.rs")]
                );
                assert_ne!(
                    worker.candidate_snapshots().0,
                    worker.candidate_snapshots().1
                );
            }
        }
        assert_eq!(
            workers[0].candidate_snapshots().1,
            workers[1].candidate_snapshots().0
        );
        assert!(completed.revalidate(context, preflight, 2, &turn).is_err());
        assert!(completed
            .revalidate(context, preflight, 1, &foreign_turn)
            .is_err());
        // Process liveness is a fresh observation, not part of claim identity.
        let after = context.sync_store.status_snapshot()?;
        assert_eq!(after.len(), before.len());
        for (after, before) in after.iter().zip(&before) {
            assert_eq!(after.claim, before.claim);
            assert_eq!(after.owner_run_id, before.owner_run_id);
            assert_eq!(after.owner_process_id, before.owner_process_id);
        }
        if case == "bound-evidence-candidate-after" {
            fs::write(
                preflight.worktree.path.join("src/lib.rs"),
                "changed after completion\n",
            )?;
            assert!(completed.revalidate(context, preflight, 1, &turn).is_err());
        }
        if case == "bound-evidence-cancel-after" {
            context.cancellation.cancel();
            assert!(completed.revalidate(context, preflight, 1, &turn).is_err());
        }
        if case == "bound-evidence-claim-revoked" {
            context.sync_store.release(preflight.claim.token)?;
            assert!(completed.revalidate(context, preflight, 1, &turn).is_err());
        }
        // A bound result is still evidence, not permission to activate continuation.
        assert!(ParentContinuationLaunch::from_completed_workers(
            context,
            preflight,
            &parent_turn_yield::validate_frozen_yield_bytes(
                parent.external_run.output_last_message().unwrap(),
                context.options.run_id.as_str(),
                &preflight.assignment,
                1,
                &[
                    parent_turn_yield::ExpectedWorkerRequest::new("z-first", "worker-two")?,
                    parent_turn_yield::ExpectedWorkerRequest::new("a-second", "worker")?
                ]
            )?,
            &[]
        )
        .is_err());
        return Ok(());
    }
    if matches!(case, "bound-shared-driver" | "bound-shared-cancelled") {
        let mut policy = context.budget_policy.clone();
        policy.set_selector_binding_for_test(
            AgentRole::Worker,
            SupervisorRuntime::Codex,
            RoleModelSelection {
                model: Some("gpt-5.6-sol".into()),
                reasoning_effort: Some("xhigh".into()),
                ..Default::default()
            },
        );
        // Compile regression: the frozen turn still borrows this exact lease.
        // No move/drop/reconstruction of preflight or bound evidence is needed.
        let mut driver = NestedWorkerSerialDriver::from_collected_parent(
            context, preflight, outcome, 1, parent,
        )?;
        let mut other_outcome = AssignmentExecutionOutcome::default();
        let error = NestedWorkerSerialDriver::from_collected_parent(
            context,
            preflight,
            &mut other_outcome,
            1,
            parent,
        )
        .err()
        .context("second driver accepted a distinct outcome")?;
        assert!(error.to_string().contains("already been issued"));
        if case == "bound-shared-cancelled" {
            context.cancellation.cancel();
            assert!(driver.execute_worker("worker-two", &policy).is_err());
            assert!(bound.revalidate(context, preflight, 1, &turn).is_err());
            return Ok(());
        }
        let mut completed = Vec::new();
        for (_, worker) in bound.requests() {
            bound.revalidate(context, preflight, 1, &turn)?;
            completed.push(driver.execute_worker(worker, &policy)?);
            let error = driver
                .execute_worker(worker, &policy)
                .err()
                .context("replayed worker")?;
            assert!(error.to_string().contains("already been reserved"));
        }
        drop(driver);
        assert!(NestedWorkerSerialDriver::from_collected_parent(
            context, preflight, outcome, 1, parent,
        )
        .is_err());
        // These injected Workers make no edits. The pre-Worker candidate remains
        // evidence only; even held completions do not open production continuation.
        bound.revalidate(context, preflight, 1, &turn)?;
        assert_eq!(
            completed
                .iter()
                .map(|e| e.report().id.as_str())
                .collect::<Vec<_>>(),
            ["worker-two", "worker"]
        );
        let expected = bound
            .requests()
            .map(|(r, w)| parent_turn_yield::ExpectedWorkerRequest::new(r, w))
            .collect::<Result<Vec<_>>>()?;
        let yielded = parent_turn_yield::validate_frozen_yield_bytes(
            parent.external_run.output_last_message().unwrap(),
            context.options.run_id.as_str(),
            &preflight.assignment,
            1,
            &expected,
        )?;
        let error = ParentContinuationLaunch::from_completed_workers(
            context, preflight, &yielded, &completed,
        )
        .err()
        .context("continuation opened")?;
        assert!(error.to_string().contains("construction unavailable"));
        assert_eq!(context.sync_store.status_snapshot()?, before);
        return Ok(());
    }
    match case {
        "bound-candidate-content" => fs::write(
            preflight.worktree.path.join("src/lib.rs"),
            "same path, different bytes\n",
        )?,
        "bound-candidate-index" => {
            let git = crate::git_repository::open(&preflight.worktree.path)?;
            let mut index = git.index()?;
            index.remove_path(Path::new("src/lib.rs"))?;
            index.write()?;
        }
        "bound-candidate-uninspectable" => {
            let git = crate::git_repository::open(&preflight.worktree.path)?;
            fs::write(git.path().join("index"), b"invalid index")?;
        }
        "bound-cancelled-after" => context.cancellation.cancel(),
        "bound-claim-revoked" => {
            context.sync_store.release(preflight.claim.token)?;
        }
        "bound-stale-consumer" => {
            assert!(bound.revalidate(context, preflight, 2, &turn).is_err());
            return Ok(());
        }
        "bound-happy" => {
            assert_eq!(context.sync_store.status_snapshot()?, before);
            // The current continuation constructor must remain closed even
            // though this live binding exists. It has no completed request token.
            let expected = bound
                .requests()
                .map(|(r, w)| parent_turn_yield::ExpectedWorkerRequest::new(r, w))
                .collect::<Result<Vec<_>>>()?;
            let yielded = parent_turn_yield::validate_frozen_yield_bytes(
                parent.external_run.output_last_message().unwrap(),
                context.options.run_id.as_str(),
                &preflight.assignment,
                1,
                &expected,
            )?;
            let error =
                ParentContinuationLaunch::from_completed_workers(context, preflight, &yielded, &[])
                    .err()
                    .context("continuation opened")?;
            assert!(error.to_string().contains("construction unavailable"));
            return Ok(());
        }
        _ => bail!("unknown bound fixture {case}"),
    }
    let error = bound
        .revalidate(context, preflight, 1, &turn)
        .err()
        .with_context(|| format!("accepted {case}"))?;
    if case.starts_with("bound-candidate-") {
        assert!(
            format!("{error:#}").contains("candidate snapshot"),
            "{error:#}"
        );
    }
    Ok(())
}

#[test]
fn bound_nested_evidence_two_workers_preserve_frozen_identity_and_block_replay() -> Result<()> {
    nested_driver_tests::driver_fixture("bound-evidence-happy")?;
    nested_driver_tests::driver_fixture("bound-evidence-edits")
}

#[test]
fn bound_nested_evidence_rejects_forged_widened_failed_and_cancelled_results() -> Result<()> {
    for case in ["forged", "widened", "failure", "cancel-during"] {
        nested_driver_tests::driver_fixture(&format!("bound-evidence-{case}"))?;
    }
    Ok(())
}

#[test]
fn bound_nested_evidence_revalidates_source_candidate_and_held_resources() -> Result<()> {
    for case in [
        "stale",
        "cancel-before",
        "candidate-before",
        "candidate-after",
        "cancel-after",
        "claim-revoked",
    ] {
        nested_driver_tests::driver_fixture(&format!("bound-evidence-{case}"))?;
    }
    Ok(())
}

#[test]
fn bound_parent_turn_shares_preflight_with_one_driver_and_serial_workers() -> Result<()> {
    nested_driver_tests::driver_fixture("bound-shared-driver")
}

#[test]
fn bound_parent_turn_shared_driver_still_refuses_cancellation() -> Result<()> {
    nested_driver_tests::driver_fixture("bound-shared-cancelled")
}

#[test]
fn bound_parent_turn_retains_exact_live_order_and_candidate_without_activation() -> Result<()> {
    nested_driver_tests::driver_fixture("bound-happy")
}

#[test]
fn bound_parent_turn_rejects_forged_duplicate_missing_mixed_or_reordered_yield() -> Result<()> {
    for case in [
        "forged",
        "wrong-worker",
        "duplicate",
        "missing",
        "wrong-order",
        "stale-yield",
        "mixed-envelope",
    ] {
        nested_driver_tests::driver_fixture(&format!("bound-{case}"))?;
    }
    Ok(())
}

#[test]
fn bound_parent_turn_rejects_foreign_stale_recovered_or_unbound_endpoint() -> Result<()> {
    for case in [
        "foreign-generation",
        "foreign-state",
        "foreign-turn",
        "same-label-owner",
        "wrong-attempt",
        "recovered",
        "ordinary-endpoint",
        "stale-consumer",
    ] {
        nested_driver_tests::driver_fixture(&format!("bound-{case}"))?;
    }
    Ok(())
}

#[test]
fn bound_parent_turn_rejects_lost_quiescence_capture_authority_or_cancellation() -> Result<()> {
    for case in [
        "restored",
        "nonquiescent",
        "blocked",
        "side-effects",
        "cancelled-before",
        "cancelled-after",
        "claim-revoked",
    ] {
        nested_driver_tests::driver_fixture(&format!("bound-{case}"))?;
    }
    Ok(())
}

#[test]
fn bound_parent_turn_rejects_same_path_candidate_drift_and_incomplete_inspection() -> Result<()> {
    for case in ["content", "index", "uninspectable"] {
        nested_driver_tests::driver_fixture(&format!("bound-candidate-{case}"))?;
    }
    Ok(())
}

#[test]
fn bound_nested_evidence_rejects_mutation_at_executor_handoffs() -> Result<()> {
    for boundary in ["before", "before-outside", "after", "after-outside"] {
        nested_driver_tests::driver_fixture(&format!("bound-evidence-handoff-{boundary}"))?;
    }
    Ok(())
}

#[test]
fn bound_nested_evidence_second_failure_retains_first_edit_without_replay() -> Result<()> {
    nested_driver_tests::driver_fixture("bound-evidence-second-failure")
}
