//! Lease-fenced follow-up execution helpers: ambiguous holds, authenticated
//! terminals, and scoped lease heartbeats while the subordinate runs on the
//! caller thread.

use super::super::{
    encode_final_report,
    follow_up_lease::{
        bound_branch_completion, current_lease_proof, observed_lease_time, FollowUpLeaseDriver,
    },
    EnvironmentFailure, GateDenial, ProcessCancellation, SupervisorFinalReport,
};
use super::*;
use crate::{
    artifacts::state_auth::sha256_hex,
    follow_up_queue::{
        graph::{BranchOutcome, BranchSuccess, DurableText},
        GeneratedFollowUpQueue,
    },
};
use anyhow::{anyhow, Context, Result};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::mpsc,
};

pub(super) fn hold_ambiguous(
    queue: &mut GeneratedFollowUpQueue,
    item_id: &str,
    gate_denial: Option<GateDenial>,
    environment_failures: Vec<EnvironmentFailure>,
) -> Result<()> {
    if queue.snapshot().item_branch_id(item_id).is_some() {
        let proof = current_lease_proof(queue, item_id)?;
        queue.mark_leased_held_ambiguous(item_id, proof, gate_denial, environment_failures)?;
    } else {
        queue.mark_held_ambiguous(item_id, gate_denial, environment_failures)?;
    }
    Ok(())
}

pub(super) fn apply_terminal(
    queue: &mut GeneratedFollowUpQueue,
    authenticated: AuthenticatedGeneratedFollowUpTerminal,
    report: &SupervisorFinalReport,
) -> Result<()> {
    let (queue_instance_id, item_id, observation) = authenticated.into_parts();
    if queue.snapshot().item_branch_id(&item_id).is_some() {
        let observed_at = observed_lease_time()?;
        let proof = current_lease_proof(queue, &item_id)?;
        let outcome = branch_outcome_from_authenticated_report(report)?;
        let graph_completion = bound_branch_completion(queue, &item_id, outcome)?;
        let authenticated = AuthenticatedGeneratedFollowUpTerminal {
            queue_instance_id,
            item_id,
            observation,
        };
        queue.apply_leased_authenticated_terminal(
            authenticated,
            proof,
            observed_at,
            graph_completion,
        )?;
    } else {
        let authenticated = AuthenticatedGeneratedFollowUpTerminal {
            queue_instance_id,
            item_id,
            observation,
        };
        queue.apply_authenticated_terminal(authenticated)?;
    }
    Ok(())
}

pub(super) fn with_heartbeat<T>(
    queue: &mut GeneratedFollowUpQueue,
    driver: &FollowUpLeaseDriver,
    item_id: &str,
    run: impl FnOnce(&ProcessCancellation) -> Result<T>,
) -> Result<T> {
    driver
        .heartbeat(queue, item_id)
        .context("initial follow-up lease heartbeat before subordinate execution")?;

    let heartbeat_cancellation = ProcessCancellation::new();

    std::thread::scope(|scope| {
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let thread_cancellation = heartbeat_cancellation.clone();
        let heartbeat_handle = scope.spawn(move || loop {
            match stop_rx.recv_timeout(driver.heartbeat_interval()) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Err(error) = driver.heartbeat(queue, item_id) {
                        thread_cancellation.cancel();
                        return Err(error);
                    }
                }
            }
        });

        let run_result = match catch_unwind(AssertUnwindSafe(|| run(&heartbeat_cancellation))) {
            Ok(inner) => inner.context("follow-up leased subordinate execution failed"),
            Err(_) => Err(anyhow!("follow-up leased subordinate execution panicked")),
        };

        drop(stop_tx);
        let heartbeat_result = match heartbeat_handle.join() {
            Ok(result) => result,
            Err(_) => Err(anyhow!("follow-up lease heartbeat thread panicked")),
        };
        heartbeat_result
            .context("follow-up lease heartbeat failed during subordinate execution")?;
        run_result
    })
}

fn branch_outcome_from_authenticated_report(
    report: &SupervisorFinalReport,
) -> Result<BranchOutcome> {
    if follow_up_terminal_succeeded(report) {
        let result_ref = DurableText::new(authenticated_final_report_ref(report)?)?;
        Ok(BranchOutcome::Success {
            success: BranchSuccess::new(result_ref, Vec::new())?,
        })
    } else {
        let error = DurableText::new(format!(
            "permanent-subordinate-terminal-outcome:{}",
            authenticated_final_report_ref(report)?
        ))?;
        Ok(BranchOutcome::Failure { error })
    }
}

fn follow_up_terminal_succeeded(report: &SupervisorFinalReport) -> bool {
    report.success
        && report.accepted
        && report.publishable
        && !report.rejected
        && report.generated_follow_up_tasks.is_empty()
}

fn authenticated_final_report_ref(report: &SupervisorFinalReport) -> Result<String> {
    let digest = sha256_hex(&encode_final_report(report)?);
    Ok(format!(
        "supervisor-run:{}:final-report-sha256:{}",
        report.run_id.as_str(),
        digest
    ))
}
