//! Supervisor parsing of descriptor-held control output and authenticated enqueueing.
//! Proposed IDs never become launch, scope, account, budget, or recovery authority.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;

use super::{AgentRole, AssignmentPhase, OrchestratorAssignment};
use crate::messaging::transport::AssignmentMessagingLaunch;

const MAX_CONTROL_ENVELOPE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlEnvelope {
    version: u32,
    outcome: String,
    run_id: String,
    parent_id: String,
    parent_attempt: usize,
    requests: Vec<ControlRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlRequest {
    request_id: String,
    worker_id: String,
}

fn validate_envelope(
    bytes: &[u8],
    run_id: &str,
    parent: &OrchestratorAssignment,
    attempt: usize,
) -> Result<Vec<ControlRequest>> {
    if bytes.len() > MAX_CONTROL_ENVELOPE_BYTES {
        bail!("parent control envelope exceeds its descriptor-capture bound");
    }
    let envelope: ControlEnvelope = serde_json::from_slice(bytes)
        .context("parent control requires one strict JSON envelope")?;
    if envelope.version != 1
        || envelope.outcome != "yield_workers"
        || envelope.run_id != run_id
        || envelope.parent_id != parent.id
        || envelope.parent_attempt != attempt
        || attempt == 0
        || parent.phase != AssignmentPhase::Execution
        || parent.role != AgentRole::ChildOrchestrator
        || parent.effective_role_category() != parent.role.authority_category()
        || parent.worker_assignments.is_empty()
        || envelope.requests.len() != parent.worker_assignments.len()
    {
        bail!("parent control differs from the supervisor-owned turn and Worker set");
    }
    let mut request_ids = BTreeSet::new();
    let mut worker_ids = BTreeSet::new();
    for (request, worker) in envelope.requests.iter().zip(&parent.worker_assignments) {
        if request.worker_id != worker.id
            || worker.id == parent.id
            || worker.role != AgentRole::Worker
            || worker.effective_role_category() != worker.role.authority_category()
            || !worker_ids.insert(worker.id.as_str())
            || !request_ids.insert(request.request_id.as_str())
            || request.request_id.is_empty()
            || request.request_id.len() > 128
            || matches!(request.request_id.as_str(), "." | "..")
            || !request
                .request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            bail!(
                "parent control requires canonical unique requests in exact authored Worker order"
            );
        }
    }
    // Still a proposal only. The authenticated inbox independently binds scope
    // and the later frozen-yield validator checks these bytes against its journal.
    Ok(envelope.requests)
}

/// Call only after the current managed parent has returned quiescent, while its
/// authenticated fresh endpoint is still owned and before shutdown/freeze. The
/// caller checks the descriptor-selected SupervisorCapturedEnvelope transport.
/// A failure may leave queued requests; it yields no launch token and the existing
/// owner retains the journal for refusal/reconciliation. Never retry by minting a
/// fresh turn or reconstruct this authority from a persisted report pathname.
pub(super) fn submit_captured_envelope(
    bytes: &[u8],
    run_id: &str,
    parent: &OrchestratorAssignment,
    attempt: usize,
    launch: &AssignmentMessagingLaunch,
    cancelled: &dyn Fn() -> bool,
) -> Result<()> {
    if cancelled() {
        bail!("parent control submission is cancelled");
    }
    let validated = validate_envelope(bytes, run_id, parent, attempt)?;
    for request in &validated {
        let request_id = request.request_id.as_str();
        let worker_id = request.worker_id.as_str();
        let receipt = launch.forward_worker_request(
            run_id,
            &parent.id,
            &json!({
                "operation":"submit_worker_request", "request_id":request_id, "worker_id":worker_id
            }),
            cancelled,
        )?;
        if receipt.get("request_id").and_then(|value| value.as_str()) != Some(request_id)
            || receipt.get("worker_id").and_then(|value| value.as_str()) != Some(worker_id)
            || receipt.get("status").and_then(|value| value.as_str()) != Some("queued")
        {
            bail!("parent control receipt differs from the authenticated queued order");
        }
    }
    if cancelled() {
        bail!("parent control submission was revoked before freeze");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> OrchestratorAssignment {
        serde_json::from_value(json!({
            "id":"parent", "phase":"execution", "role":"child_orchestrator",
            "worker_assignments":[{"id":"one","role":"worker"},{"id":"two","role":"worker"}]
        }))
        .unwrap()
    }

    fn envelope() -> serde_json::Value {
        json!({"version":1,"outcome":"yield_workers","run_id":"run","parent_id":"parent",
            "parent_attempt":1,"requests":[{"request_id":"r1","worker_id":"one"},{"request_id":"r2","worker_id":"two"}]})
    }

    #[test]
    fn envelope_is_an_exact_turn_bound_proposal() {
        let bytes = serde_json::to_vec(&envelope()).unwrap();
        assert!(validate_envelope(&bytes, "run", &parent(), 1).is_ok());
        assert!(validate_envelope(&bytes, "another-run", &parent(), 1).is_err());
        assert!(validate_envelope(&bytes, "run", &parent(), 2).is_err());
    }

    #[test]
    fn child_cannot_supply_scope_or_duplicate_substitute_reorder_workers() {
        for variant in ["scope", "duplicate", "substitute", "reorder"] {
            let mut body = envelope();
            match variant {
                "scope" => body["requests"][0]["assigned_paths"] = json!(["outside.rs"]),
                "duplicate" => body["requests"][1]["request_id"] = json!("r1"),
                "substitute" => body["requests"][1]["worker_id"] = json!("foreign"),
                "reorder" => body["requests"].as_array_mut().unwrap().reverse(),
                _ => unreachable!(),
            }
            assert!(
                validate_envelope(&serde_json::to_vec(&body).unwrap(), "run", &parent(), 1)
                    .is_err(),
                "{variant}"
            );
        }
    }
}
