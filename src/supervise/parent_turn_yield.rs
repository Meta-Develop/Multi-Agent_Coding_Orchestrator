//! Validate a descriptor-captured parent yield against supervisor-owned requests.
//! This is neither final-report acceptance nor authority to launch a Worker.
//! The caller must freeze the expected request snapshot after endpoint shutdown;
//! never reconstruct it from the yield JSON. Scheduling and recovery are separate.

use super::*;
use serde::Deserialize;

const MAX_YIELD_BYTES: usize = 64 * 1024;

/// A request already bound by the supervisor to this parent turn. Deliberately
/// not deserializable: future inbox integration must construct these from its
/// authenticated, current request records, not a caller-supplied message body.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ExpectedWorkerRequest {
    request_id: String,
    worker_id: String,
}

impl ExpectedWorkerRequest {
    pub(super) fn new(request_id: &str, worker_id: &str) -> Result<Self> {
        validate_request_id(request_id)?;
        Ok(Self {
            request_id: request_id.into(),
            worker_id: worker_id.into(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct YieldWire {
    version: u32,
    outcome: YieldOutcome,
    run_id: String,
    parent_id: String,
    parent_attempt: usize,
    requests: Vec<RequestWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum YieldOutcome {
    YieldWorkers,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    request_id: String,
    worker_id: String,
}

/// IDs validated at collection time only. Not serializable, not a resumed
/// quiescence proof, and not consumable as AssignmentCommandAdmission.
#[derive(Debug)]
pub(super) struct ValidatedParentTurnYield {
    run_id: String,
    parent_id: String,
    parent_attempt: usize,
    requests: Vec<ExpectedWorkerRequest>,
}

impl ValidatedParentTurnYield {
    pub(super) fn parent_binding(&self) -> (&str, &str, usize) {
        (&self.run_id, &self.parent_id, self.parent_attempt)
    }

    pub(super) fn requests(&self) -> impl Iterator<Item = (&str, &str)> {
        self.requests
            .iter()
            .map(|request| (request.request_id.as_str(), request.worker_id.as_str()))
    }
}

impl NestedWorkerSerialDriver<'_, '_, '_, '_> {
    /// The driver can only be constructed from a live collected parent result.
    /// Recheck authority here because cancellation/claim revocation may occur
    /// after construction. Read only held output bytes, never a report pathname.
    pub(super) fn validate_parent_turn_yield(
        &self,
        expected: &[ExpectedWorkerRequest],
    ) -> Result<ValidatedParentTurnYield> {
        Self::verify_parent_quiescence(self.parent, self.preflight)?;
        self.parent_admission.revalidate(
            &AssignmentAttemptAuthority::from_preflight(
                self.context,
                self.preflight,
                self.parent_attempt,
            )?,
            &self.preflight.assignment.id,
            &self.parent._command,
        )?;
        // These conditions prevent a yielded turn from bypassing existing
        // collection failures which are handled by final-report decision today.
        if self.parent.environment_blocked || self.parent.external_side_effect_state.is_some() {
            bail!("parent yield requires an unblocked parent without external side effects");
        }
        let bytes = self
            .parent
            .external_run
            .output_last_message()
            .context("parent yield requires descriptor-captured output")?;
        validate_yield_bytes(
            bytes,
            self.context.options.run_id.as_str(),
            &self.preflight.assignment,
            self.parent_attempt,
            expected,
        )
    }
}

fn validate_yield_bytes(
    bytes: &[u8],
    run_id: &str,
    parent: &OrchestratorAssignment,
    attempt: usize,
    expected: &[ExpectedWorkerRequest],
) -> Result<ValidatedParentTurnYield> {
    if bytes.len() > MAX_YIELD_BYTES || expected.is_empty() {
        bail!("parent yield must contain a bounded nonempty request set");
    }
    if attempt == 0
        || parent.phase != AssignmentPhase::Execution
        || parent.role != AgentRole::ChildOrchestrator
        || parent.effective_role_category()
            != super::super::role_authority::RoleCategory::DelegatingCoordinator
    {
        bail!("parent yield requires a current authored execution coordinator");
    }
    let wire: YieldWire = serde_json::from_slice(bytes).context("invalid parent yield report")?;
    let YieldOutcome::YieldWorkers = wire.outcome;
    if wire.version != 1
        || wire.run_id != run_id
        || wire.parent_id != parent.id
        || wire.parent_attempt != attempt
        || wire.requests.len() != expected.len()
        || expected.len() > parent.worker_assignments.len()
    {
        bail!("parent yield differs from the current run, parent, attempt or request snapshot");
    }
    let mut expected_ids = BTreeMap::new();
    let mut expected_workers = BTreeSet::new();
    for request in expected {
        validate_request_id(&request.request_id)?;
        let mut authored = parent
            .worker_assignments
            .iter()
            .filter(|worker| worker.id == request.worker_id);
        let worker = authored.next().context("yield Worker is not authored")?;
        if authored.next().is_some()
            || worker.id == parent.id
            || worker.role != AgentRole::Worker
            || worker.effective_role_category()
                != super::super::role_authority::RoleCategory::NonDelegatingTerminalWorker
            || expected_ids
                .insert(request.request_id.as_str(), request.worker_id.as_str())
                .is_some()
            || !expected_workers.insert(request.worker_id.as_str())
        {
            bail!("parent yield requires unique requests for exact authored terminal Workers");
        }
    }
    let mut seen = BTreeSet::new();
    for request in wire.requests {
        validate_request_id(&request.request_id)?;
        if !seen.insert(request.request_id.clone())
            || expected_ids.get(request.request_id.as_str()).copied()
                != Some(request.worker_id.as_str())
        {
            bail!("parent yield contains duplicate, forged or substituted request/Worker IDs");
        }
    }
    Ok(ValidatedParentTurnYield {
        run_id: run_id.into(),
        parent_id: parent.id.clone(),
        parent_attempt: attempt,
        // The child may name the exact set, but cannot reorder the supervisor's
        // frozen request snapshot and thereby choose future execution order.
        requests: expected
            .iter()
            .map(|request| ExpectedWorkerRequest {
                request_id: request.request_id.clone(),
                worker_id: request.worker_id.clone(),
            })
            .collect(),
    })
}

fn validate_request_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || matches!(id, "." | "..")
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        bail!("parent yield request ID must be canonical ASCII of 1..=128 bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> OrchestratorAssignment {
        serde_json::from_value(json!({
            "id":"parent", "phase":"execution", "role":"child_orchestrator",
            "worker_assignments":[{"id":"one", "role":"worker"},
                                  {"id":"two", "role":"worker"}]
        }))
        .unwrap()
    }

    fn report() -> serde_json::Value {
        json!({"version":1, "outcome":"yield_workers", "run_id":"run",
            "parent_id":"parent", "parent_attempt":1,
            "requests":[{"request_id":"r1", "worker_id":"one"},
                        {"request_id":"r2", "worker_id":"two"}]})
    }

    fn expected() -> Vec<ExpectedWorkerRequest> {
        vec![
            ExpectedWorkerRequest::new("r1", "one").unwrap(),
            ExpectedWorkerRequest::new("r2", "two").unwrap(),
        ]
    }

    fn validate(report: serde_json::Value) -> Result<ValidatedParentTurnYield> {
        validate_yield_bytes(
            &serde_json::to_vec(&report)?,
            "run",
            &parent(),
            1,
            &expected(),
        )
    }

    #[test]
    fn parent_turn_yield_exact_requests_only() -> Result<()> {
        let mut wire = report();
        wire["requests"].as_array_mut().unwrap().reverse();
        let validated = validate(wire)?;
        assert_eq!(validated.parent_binding(), ("run", "parent", 1));
        assert_eq!(
            validated.requests().collect::<Vec<_>>(),
            [("r1", "one"), ("r2", "two")]
        );
        Ok(())
    }

    #[test]
    fn parent_turn_yield_rejects_forged_duplicate_unknown_and_substituted_ids() {
        for mutation in 0..11 {
            let mut report = report();
            match mutation {
                0 => report["requests"][0]["request_id"] = json!("forged"),
                1 => report["requests"][0]["worker_id"] = json!("unknown"),
                2 => report["requests"][0]["worker_id"] = json!("two"),
                3 => report["requests"][1] = report["requests"][0].clone(),
                4 => report["run_id"] = json!("foreign-run"),
                5 => report["parent_id"] = json!("foreign-parent"),
                6 => report["parent_attempt"] = json!(2),
                7 => report["requests"] = json!([]),
                8 => report["requests"].as_array_mut().unwrap().truncate(1),
                9 => report["requests"][0]["request_id"] = json!("../r1"),
                _ => report["requests"][0]["worker_id"] = json!("parent"),
            }
            assert!(validate(report).is_err(), "accepted mutation {mutation}");
        }
    }

    #[test]
    fn parent_turn_yield_rejects_acceptance_extra_fields_and_ambiguous_json() {
        for mutation in 0..5 {
            let mut report = report();
            match mutation {
                0 => report["accepted"] = json!(true),
                1 => report["requests"][0]["accepted"] = json!(true),
                2 => report["outcome"] = json!("completed"),
                3 => report["version"] = json!(2),
                _ => report["command"] = json!("launch anything"),
            }
            assert!(validate(report).is_err());
        }
        let canonical = serde_json::to_string(&report()).unwrap();
        let duplicate_key = canonical.replacen('{', "{\"parent_attempt\":1,", 1);
        for bytes in [
            duplicate_key.as_bytes(),
            b"{} trailing",
            &[b' '; MAX_YIELD_BYTES + 1],
        ] {
            assert!(validate_yield_bytes(bytes, "run", &parent(), 1, &expected()).is_err());
        }
    }

    #[test]
    fn parent_turn_yield_rejects_invalid_supervisor_snapshot_and_nonterminal_worker() {
        let bytes = serde_json::to_vec(&report()).unwrap();
        for mutation in 0..8 {
            let mut parent = parent();
            let mut expected = expected();
            match mutation {
                0 => expected[1].request_id = "r1".into(),
                1 => expected[1].worker_id = "one".into(),
                2 => expected[0].worker_id = "unknown".into(),
                3 => parent.worker_assignments[0].role = AgentRole::Auditor,
                4 => parent.worker_assignments[1].id = "one".into(),
                5 => parent.phase = AssignmentPhase::Planning,
                6 => parent.role = AgentRole::Worker,
                _ => {
                    parent.role_category = Some(
                        super::super::super::role_authority::RoleCategory::NonDelegatingTerminalWorker,
                    );
                }
            }
            assert!(validate_yield_bytes(&bytes, "run", &parent, 1, &expected).is_err());
        }
        assert!(ExpectedWorkerRequest::new("", "one").is_err());
        assert!(ExpectedWorkerRequest::new(&"x".repeat(129), "one").is_err());
    }
}
