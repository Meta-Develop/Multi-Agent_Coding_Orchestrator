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
    let mut foreign_binding = binding;
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
