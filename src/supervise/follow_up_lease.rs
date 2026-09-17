//! Lease-bound adapter for the graph consumer follow-up queue writer.
//!
//! Owns logical worker identity, derived lease identities, and in-memory proof
//! tracking while the cascade holds the queue lifetime lock.

use crate::{
    artifacts::state_auth::sha256_hex,
    follow_up_queue::{
        graph::{
            BranchAttemptRecord, BranchOutcome, DurableGraphEvent, DurableGraphNodeKind,
            GraphBranchId,
        },
        lease::{LeaseIdentity, LeasePhase, LeaseProof, LeaseState, WorkerIdentity},
        GeneratedFollowUpQueue, GeneratedFollowUpQueueEventData, GeneratedFollowUpQueuePhase,
        GeneratedFollowUpQueueSnapshot,
    },
    orchestrator::RunId,
    sync_store::ClaimTiming,
};
use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const WORKER_ID_PREFIX: &str = "follow-up-worker-";
const LEASE_ID_PREFIX: &str = "follow-up-lease-";

pub(super) struct FollowUpLeaseDriver {
    queue_instance_id: String,
    worker: WorkerIdentity,
    timing: ClaimTiming,
    proofs: BTreeMap<String, LeaseProof>,
}

impl FollowUpLeaseDriver {
    pub(super) fn new(queue: &GeneratedFollowUpQueue, worker_run_id: &RunId) -> Result<Self> {
        let queue_instance_id = queue.snapshot().queue_instance_id().to_string();
        let worker = logical_follow_up_worker_identity(&queue_instance_id, worker_run_id)?;
        Ok(Self {
            queue_instance_id,
            worker,
            timing: ClaimTiming::default(),
            proofs: BTreeMap::new(),
        })
    }

    pub(super) fn prepare_existing_claims(
        &mut self,
        queue: &mut GeneratedFollowUpQueue,
    ) -> Result<()> {
        self.ensure_queue_instance(queue)?;
        let observed_at = observed_lease_time()?;
        let candidate_item_ids: Vec<String> = queue
            .snapshot()
            .items()
            .iter()
            .filter(|(item_id, item)| prepare_candidate_item(queue.snapshot(), item_id, item))
            .map(|(item_id, _)| item_id.clone())
            .collect();
        for item_id in candidate_item_ids {
            let snapshot = queue.snapshot();
            let item = snapshot
                .item(&item_id)
                .with_context(|| format!("generated follow-up queue item {item_id} is unknown"))?;
            if !prepare_candidate_item(snapshot, &item_id, item) {
                continue;
            }
            let lease = snapshot
                .lease(&item_id)
                .context("graph-bound claimed item has no lease state")?;
            match lease.phase() {
                LeasePhase::EffectFenced | LeasePhase::Acknowledged => continue,
                LeasePhase::Available => continue,
                LeasePhase::Active => {
                    require_strict_observation_advance(lease, observed_at)?;
                    let proof = lease
                        .active_proof()
                        .context("active lease has no proof")?
                        .clone();
                    let expires_at = lease.expires_at().context("active lease has no expiry")?;
                    if observed_at < expires_at {
                        if proof.worker() == &self.worker {
                            self.proofs.insert(item_id, proof);
                        }
                        continue;
                    }
                    let successor_generation = successor_lease_generation(lease)?;
                    let successor_lease_id = follow_up_lease_identity(
                        &self.queue_instance_id,
                        &item_id,
                        self.worker.as_str(),
                        successor_generation,
                    )?;
                    let successor_expires_at =
                        lease_expires_at(observed_at, self.timing.stale_after_seconds)?;
                    let (_, successor) = queue.reclaim_expired_lease(
                        &item_id,
                        observed_at,
                        self.worker.clone(),
                        successor_lease_id,
                        successor_expires_at,
                    )?;
                    self.proofs.insert(item_id, successor);
                }
            }
        }
        Ok(())
    }

    pub(super) fn owns_claim(&self, queue: &GeneratedFollowUpQueue, item_id: &str) -> bool {
        self.matches_owned_active_claim(queue, item_id).is_ok()
    }

    pub(super) fn claim_prepared(
        &mut self,
        queue: &mut GeneratedFollowUpQueue,
        item_id: &str,
    ) -> Result<LeaseProof> {
        self.ensure_queue_instance(queue)?;
        let snapshot = queue.snapshot();
        let item = snapshot
            .item(item_id)
            .with_context(|| format!("generated follow-up queue item {item_id} is unknown"))?;
        match item.phase() {
            GeneratedFollowUpQueuePhase::Claimed => {
                let proof = self
                    .proofs
                    .get(item_id)
                    .context("follow-up lease driver does not own prepared claim")?
                    .clone();
                let lease = snapshot
                    .lease(item_id)
                    .context("claimed item has no lease state")?;
                self.validate_owned_live_proof(
                    snapshot,
                    item_id,
                    &proof,
                    OwnedLiveProofMode::Execution,
                )?;
                let observed_at = observed_lease_time()?;
                require_strict_observation_advance(lease, observed_at)?;
                let expires_at = lease.expires_at().context("active lease has no expiry")?;
                if observed_at >= expires_at {
                    bail!("prepared claim lease has expired");
                }
                Ok(proof)
            }
            GeneratedFollowUpQueuePhase::Enqueued => {
                if snapshot.item_branch_id(item_id).is_none() {
                    bail!("follow-up lease claim requires a graph-bound queue item");
                }
                let observed_at = observed_lease_time()?;
                let expires_at = lease_expires_at(observed_at, self.timing.stale_after_seconds)?;
                let lease = snapshot
                    .lease(item_id)
                    .context("graph-bound queue item has no lease state")?;
                let generation = successor_lease_generation(lease)?;
                let lease_id = follow_up_lease_identity(
                    &self.queue_instance_id,
                    item_id,
                    self.worker.as_str(),
                    generation,
                )?;
                let graph_attempt = derive_branch_attempt_started(snapshot, item_id)?;
                let (_, proof) = queue.claim_with_lease(
                    item_id,
                    self.worker.clone(),
                    lease_id,
                    observed_at,
                    expires_at,
                    graph_attempt,
                )?;
                self.proofs.insert(item_id.to_string(), proof.clone());
                Ok(proof)
            }
            _ => bail!("follow-up lease claim requires enqueued or prepared claimed state"),
        }
    }

    pub(super) fn mark_effect_started(
        &self,
        queue: &mut GeneratedFollowUpQueue,
        item_id: &str,
    ) -> Result<GeneratedFollowUpQueueEventData> {
        self.ensure_queue_instance(queue)?;
        let proof = self.require_owned_proof(queue, item_id)?;
        let observed_at = observed_lease_time()?;
        queue.mark_leased_effect_started(item_id, proof, observed_at)
    }

    pub(super) fn heartbeat(
        &self,
        queue: &mut GeneratedFollowUpQueue,
        item_id: &str,
    ) -> Result<()> {
        self.ensure_queue_instance(queue)?;
        let proof = self.require_owned_heartbeat_proof(queue, item_id)?;
        let observed_at = observed_lease_time()?;
        let expires_at = lease_expires_at(observed_at, self.timing.stale_after_seconds)?;
        queue
            .heartbeat_lease(item_id, proof, observed_at, expires_at)
            .map(|_| ())
    }

    pub(super) fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.timing.heartbeat_interval_seconds)
    }

    fn ensure_queue_instance(&self, queue: &GeneratedFollowUpQueue) -> Result<()> {
        if queue.snapshot().queue_instance_id() != self.queue_instance_id {
            bail!("follow-up lease driver is bound to a different queue instance");
        }
        Ok(())
    }

    fn require_owned_proof(
        &self,
        queue: &GeneratedFollowUpQueue,
        item_id: &str,
    ) -> Result<LeaseProof> {
        let proof = self
            .proofs
            .get(item_id)
            .context("follow-up lease driver does not own item claim")?
            .clone();
        self.validate_owned_live_proof(
            queue.snapshot(),
            item_id,
            &proof,
            OwnedLiveProofMode::Execution,
        )?;
        Ok(proof)
    }

    fn require_owned_heartbeat_proof(
        &self,
        queue: &GeneratedFollowUpQueue,
        item_id: &str,
    ) -> Result<LeaseProof> {
        let proof = self
            .proofs
            .get(item_id)
            .context("follow-up lease driver does not own item claim")?
            .clone();
        self.validate_owned_live_proof(
            queue.snapshot(),
            item_id,
            &proof,
            OwnedLiveProofMode::Heartbeat,
        )?;
        Ok(proof)
    }

    fn matches_owned_active_claim(
        &self,
        queue: &GeneratedFollowUpQueue,
        item_id: &str,
    ) -> Result<()> {
        let proof = self
            .proofs
            .get(item_id)
            .context("follow-up lease driver does not own item claim")?;
        self.validate_owned_live_proof(
            queue.snapshot(),
            item_id,
            proof,
            OwnedLiveProofMode::Execution,
        )
    }

    fn validate_owned_live_proof(
        &self,
        snapshot: &GeneratedFollowUpQueueSnapshot,
        item_id: &str,
        owned: &LeaseProof,
        mode: OwnedLiveProofMode,
    ) -> Result<()> {
        if snapshot.queue_instance_id() != self.queue_instance_id {
            bail!("follow-up lease driver is bound to a different queue instance");
        }
        let item = snapshot
            .item(item_id)
            .context("generated follow-up queue item is unknown")?;
        let lease = snapshot
            .lease(item_id)
            .context("owned follow-up claim has no lease state")?;
        validate_owned_live_proof_state(item.phase(), lease, owned, &self.worker, mode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnedLiveProofMode {
    Execution,
    Heartbeat,
}

fn validate_owned_live_proof_state(
    item_phase: GeneratedFollowUpQueuePhase,
    lease: &LeaseState,
    owned: &LeaseProof,
    driver_worker: &WorkerIdentity,
    mode: OwnedLiveProofMode,
) -> Result<()> {
    let lease_phase = lease.phase();
    let allowed = match mode {
        OwnedLiveProofMode::Execution => owned_execution_live_state(item_phase, lease_phase),
        OwnedLiveProofMode::Heartbeat => owned_heartbeat_live_state(item_phase, lease_phase),
    };
    if !allowed {
        bail!("owned follow-up lease proof does not match an allowed queue and lease phase");
    }
    let stored = lease.active_proof().context("lease has no active proof")?;
    if stored != owned {
        bail!("owned follow-up claim proof does not match queue lease state");
    }
    if owned.worker() != driver_worker {
        bail!("owned follow-up claim proof does not match logical worker identity");
    }
    Ok(())
}

fn owned_execution_live_state(
    item_phase: GeneratedFollowUpQueuePhase,
    lease_phase: LeasePhase,
) -> bool {
    item_phase == GeneratedFollowUpQueuePhase::Claimed && lease_phase == LeasePhase::Active
}

fn owned_heartbeat_live_state(
    item_phase: GeneratedFollowUpQueuePhase,
    lease_phase: LeasePhase,
) -> bool {
    matches!(
        (item_phase, lease_phase),
        (GeneratedFollowUpQueuePhase::Claimed, LeasePhase::Active)
            | (
                GeneratedFollowUpQueuePhase::DispatchStarted,
                LeasePhase::EffectFenced
            )
    )
}

pub(super) fn observed_lease_time() -> Result<u64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the UNIX epoch")?;
    u64::try_from(duration.as_nanos()).context("lease observation exceeds u64 nanosecond bound")
}

pub(super) fn current_lease_proof(
    queue: &GeneratedFollowUpQueue,
    item_id: &str,
) -> Result<LeaseProof> {
    let lease = queue
        .snapshot()
        .lease(item_id)
        .context("generated follow-up queue item has no lease state")?;
    lease
        .active_proof()
        .cloned()
        .context("generated follow-up queue item has no active lease proof")
}

pub(super) fn bound_branch_completion(
    queue: &GeneratedFollowUpQueue,
    item_id: &str,
    outcome: BranchOutcome,
) -> Result<DurableGraphEvent> {
    let snapshot = queue.snapshot();
    let branch_id = snapshot
        .item_branch_id(item_id)
        .context("follow-up branch completion requires a graph-bound item")?
        .clone();
    let visit = bound_graph_task_visit(snapshot, item_id)?;
    let graph = snapshot
        .graph()
        .context("graph-bound item has no replay-derived graph state")?;
    let branch = graph
        .branch(&branch_id)
        .context("graph-bound item names an unknown branch")?;
    let attempt = branch
        .attempt_in_progress()
        .context("follow-up branch completion requires an in-progress attempt")?;
    Ok(branch_attempt_completed_event(
        branch_id, visit, attempt, outcome,
    ))
}

fn prepare_candidate_item(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    item_id: &str,
    item: &crate::follow_up_queue::GeneratedFollowUpQueueItemSnapshot,
) -> bool {
    snapshot.item_branch_id(item_id).is_some()
        && item.phase() == GeneratedFollowUpQueuePhase::Claimed
        && item.subordinate_run_id().is_none()
        && item.observation().is_none()
        && item.external_side_effect_state().is_none()
}

pub(super) fn derive_branch_attempt_started(
    snapshot: &GeneratedFollowUpQueueSnapshot,
    item_id: &str,
) -> Result<DurableGraphEvent> {
    let branch_id = snapshot
        .item_branch_id(item_id)
        .context("graph-bound queue item has no branch binding")?
        .clone();
    let graph = snapshot
        .graph()
        .context("graph-bound queue item has no replay-derived graph state")?;
    let branch = graph
        .branch(&branch_id)
        .context("graph-bound queue item names an unknown branch")?;
    let cursor = next_branch_attempt_cursor(branch.attempts())?;
    Ok(DurableGraphEvent::BranchAttemptStarted {
        branch_id,
        visit: cursor.visit,
        attempt: cursor.attempt,
    })
}

fn bound_graph_task_visit(snapshot: &GeneratedFollowUpQueueSnapshot, item_id: &str) -> Result<u16> {
    let branch_id = snapshot
        .item_branch_id(item_id)
        .context("queue item has no immutable graph branch binding")?;
    let graph = snapshot
        .graph()
        .context("queue item binding has no replay-derived graph state")?;
    let task_node = graph
        .definition()
        .nodes()
        .iter()
        .find(|node| {
            matches!(
                node.kind(),
                DurableGraphNodeKind::Task {
                    branch_id: candidate,
                    ..
                } if candidate == branch_id
            )
        })
        .context("queue item binding has no graph task node")?;
    graph
        .node_visit(task_node.id())
        .filter(|visit| *visit > 0)
        .context("queue item binding has no active graph task visit")
}

fn logical_follow_up_worker_identity(
    queue_instance_id: &str,
    worker_run_id: &RunId,
) -> Result<WorkerIdentity> {
    let digest = canonical_tuple_sha256(&[
        queue_instance_id.as_bytes(),
        worker_run_id.as_str().as_bytes(),
    ])?;
    WorkerIdentity::new(format!("{WORKER_ID_PREFIX}{digest}"))
}

fn follow_up_lease_identity(
    queue_instance_id: &str,
    item_id: &str,
    worker_identity: &str,
    generation: u64,
) -> Result<LeaseIdentity> {
    let generation_bytes = generation.to_be_bytes();
    let digest = canonical_tuple_sha256(&[
        queue_instance_id.as_bytes(),
        item_id.as_bytes(),
        worker_identity.as_bytes(),
        &generation_bytes,
    ])?;
    LeaseIdentity::new(format!("{LEASE_ID_PREFIX}{digest}"))
}

fn canonical_tuple_sha256(parts: &[&[u8]]) -> Result<String> {
    let mut capacity = 0usize;
    for part in parts {
        capacity = capacity
            .checked_add(std::mem::size_of::<u64>())
            .and_then(|value| value.checked_add(part.len()))
            .context("follow-up lease identity input length overflowed")?;
    }
    let mut framed = Vec::with_capacity(capacity);
    for part in parts {
        let length = u64::try_from(part.len())
            .context("follow-up lease identity field length overflowed")?;
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(part);
    }
    Ok(sha256_hex(&framed))
}

fn successor_lease_generation(lease: &LeaseState) -> Result<u64> {
    lease
        .generation()
        .checked_add(1)
        .context("follow-up lease generation overflowed")
}

fn lease_expires_at(observed_at: u64, stale_after_seconds: u64) -> Result<u64> {
    let ttl = seconds_to_nanos(stale_after_seconds)?;
    observed_at
        .checked_add(ttl)
        .context("follow-up lease expiry overflowed")
}

fn seconds_to_nanos(seconds: u64) -> Result<u64> {
    seconds
        .checked_mul(1_000_000_000)
        .context("follow-up lease timing seconds overflowed nanosecond conversion")
}

fn require_strict_observation_advance(lease: &LeaseState, observed_at: u64) -> Result<()> {
    if let Some(last_observed_at) = lease.last_observed_at() {
        if observed_at <= last_observed_at {
            bail!("follow-up lease observation time did not strictly advance");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BranchAttemptCursor {
    visit: u16,
    attempt: u16,
}

fn next_branch_attempt_cursor(attempts: &[BranchAttemptRecord]) -> Result<BranchAttemptCursor> {
    let Some(previous) = attempts.last() else {
        return Ok(BranchAttemptCursor {
            visit: 1,
            attempt: 1,
        });
    };
    if matches!(previous.outcome(), BranchOutcome::RetryableFailure { .. }) {
        Ok(BranchAttemptCursor {
            visit: previous.visit(),
            attempt: previous
                .attempt()
                .checked_add(1)
                .context("follow-up branch retry attempt overflowed")?,
        })
    } else {
        Ok(BranchAttemptCursor {
            visit: previous
                .visit()
                .checked_add(1)
                .context("follow-up branch visit overflowed")?,
            attempt: 1,
        })
    }
}

fn branch_attempt_completed_event(
    branch_id: GraphBranchId,
    visit: u16,
    attempt: u16,
    outcome: BranchOutcome,
) -> DurableGraphEvent {
    DurableGraphEvent::BranchAttemptCompleted {
        branch_id,
        visit,
        attempt,
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::follow_up_queue::graph::{BranchOutcome, GraphBranchId};

    #[test]
    fn logical_worker_identity_is_stable_and_parent_bound() {
        let queue_id = "a".repeat(64);
        let run_a = RunId::new("worker-run-a").expect("run id");
        let run_b = RunId::new("worker-run-b").expect("run id");
        let left = logical_follow_up_worker_identity(&queue_id, &run_a).expect("worker a");
        let right = logical_follow_up_worker_identity(&queue_id, &run_a).expect("worker a again");
        let other = logical_follow_up_worker_identity(&queue_id, &run_b).expect("worker b");
        assert_eq!(left, right);
        assert_ne!(left, other);
        assert!(left.as_str().starts_with(WORKER_ID_PREFIX));
    }

    #[test]
    fn lease_identity_changes_with_generation() {
        let queue_id = "b".repeat(64);
        let item_id = "c".repeat(64);
        let worker = "follow-up-worker-deadbeef";
        let first = follow_up_lease_identity(&queue_id, &item_id, worker, 1).expect("gen 1");
        let second = follow_up_lease_identity(&queue_id, &item_id, worker, 2).expect("gen 2");
        assert_ne!(first, second);
        assert!(first.as_str().starts_with(LEASE_ID_PREFIX));
    }

    #[test]
    fn seconds_to_nanos_rejects_overflow() {
        assert!(seconds_to_nanos(u64::MAX).is_err());
        assert_eq!(seconds_to_nanos(2).expect("two seconds"), 2_000_000_000);
    }

    #[test]
    fn observation_rollback_is_rejected() {
        let lease = LeaseState::replay(&[crate::follow_up_queue::lease::LeaseEvent::claimed(
            LeaseProof::new(
                WorkerIdentity::new("follow-up-worker-test").expect("worker"),
                LeaseIdentity::new("follow-up-lease-test").expect("lease"),
                1,
            )
            .expect("proof"),
            10,
            20,
        )
        .expect("claim")])
        .expect("lease");
        assert!(require_strict_observation_advance(&lease, 10).is_err());
        assert!(require_strict_observation_advance(&lease, 9).is_err());
        require_strict_observation_advance(&lease, 11).expect("strict advance");
    }

    #[test]
    fn branch_completion_uses_current_visit_and_in_progress_attempt() {
        let branch_id = GraphBranchId::new("licensed-follow-up-branch:test").expect("branch");
        let event = branch_attempt_completed_event(
            branch_id.clone(),
            3,
            2,
            BranchOutcome::Failure {
                error: crate::follow_up_queue::graph::DurableText::new("err").expect("text"),
            },
        );
        assert_eq!(
            event,
            DurableGraphEvent::BranchAttemptCompleted {
                branch_id,
                visit: 3,
                attempt: 2,
                outcome: BranchOutcome::Failure {
                    error: crate::follow_up_queue::graph::DurableText::new("err").expect("text"),
                },
            }
        );
    }

    #[test]
    fn next_branch_attempt_cursor_matches_graph_rules() {
        assert_eq!(
            next_branch_attempt_cursor(&[]).expect("initial"),
            BranchAttemptCursor {
                visit: 1,
                attempt: 1,
            }
        );
    }

    fn sample_proof(worker: &str, lease: &str, generation: u64) -> LeaseProof {
        LeaseProof::new(
            WorkerIdentity::new(worker).expect("worker"),
            LeaseIdentity::new(lease).expect("lease"),
            generation,
        )
        .expect("proof")
    }

    fn active_claimed_lease(proof: &LeaseProof) -> LeaseState {
        LeaseState::replay(&[crate::follow_up_queue::lease::LeaseEvent::claimed(
            proof.clone(),
            10,
            20,
        )
        .expect("claim")])
        .expect("active lease")
    }

    fn fenced_dispatch_lease(proof: &LeaseProof) -> LeaseState {
        LeaseState::replay(&[
            crate::follow_up_queue::lease::LeaseEvent::claimed(proof.clone(), 10, 20)
                .expect("claim"),
            crate::follow_up_queue::lease::LeaseEvent::effect_started(proof.clone(), 15)
                .expect("effect start"),
        ])
        .expect("fenced lease")
    }

    #[test]
    fn owned_live_proof_predicates_distinguish_execution_and_heartbeat() {
        let worker = WorkerIdentity::new("follow-up-worker-owned").expect("worker");
        let proof = sample_proof("follow-up-worker-owned", "follow-up-lease-owned", 1);
        let active = active_claimed_lease(&proof);
        let fenced = fenced_dispatch_lease(&proof);
        assert!(owned_execution_live_state(
            GeneratedFollowUpQueuePhase::Claimed,
            LeasePhase::Active,
        ));
        assert!(owned_heartbeat_live_state(
            GeneratedFollowUpQueuePhase::DispatchStarted,
            LeasePhase::EffectFenced,
        ));
        validate_owned_live_proof_state(
            GeneratedFollowUpQueuePhase::Claimed,
            &active,
            &proof,
            &worker,
            OwnedLiveProofMode::Execution,
        )
        .expect("execution on claimed active");
        validate_owned_live_proof_state(
            GeneratedFollowUpQueuePhase::DispatchStarted,
            &fenced,
            &proof,
            &worker,
            OwnedLiveProofMode::Heartbeat,
        )
        .expect("heartbeat on fenced dispatch");
        assert!(validate_owned_live_proof_state(
            GeneratedFollowUpQueuePhase::DispatchStarted,
            &fenced,
            &proof,
            &worker,
            OwnedLiveProofMode::Execution,
        )
        .is_err());
        assert!(validate_owned_live_proof_state(
            GeneratedFollowUpQueuePhase::Claimed,
            &active,
            &proof,
            &worker,
            OwnedLiveProofMode::Heartbeat,
        )
        .is_ok());
    }

    #[test]
    fn owned_live_proof_rejects_foreign_and_invalid_phases() {
        let worker = WorkerIdentity::new("follow-up-worker-owned").expect("worker");
        let foreign = WorkerIdentity::new("follow-up-worker-foreign").expect("foreign");
        let proof = sample_proof("follow-up-worker-owned", "follow-up-lease-owned", 1);
        let active = active_claimed_lease(&proof);
        assert!(validate_owned_live_proof_state(
            GeneratedFollowUpQueuePhase::Claimed,
            &active,
            &proof,
            &foreign,
            OwnedLiveProofMode::Execution,
        )
        .is_err());
        assert!(!owned_heartbeat_live_state(
            GeneratedFollowUpQueuePhase::HeldAmbiguous,
            LeasePhase::EffectFenced,
        ));
        assert!(validate_owned_live_proof_state(
            GeneratedFollowUpQueuePhase::HeldAmbiguous,
            &fenced_dispatch_lease(&proof),
            &proof,
            &worker,
            OwnedLiveProofMode::Heartbeat,
        )
        .is_err());
    }
}
