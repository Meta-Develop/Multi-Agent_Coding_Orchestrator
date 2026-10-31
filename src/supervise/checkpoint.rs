use super::*;
use crate::{
    artifacts::{
        repository_auth_writer, validate_repository_authenticated_state, ArtifactRunResumeBinding,
    },
    state_journal::{JournalRecord, StateJournal},
};

const SUPERVISE_CHECKPOINT_VERSION: u32 = 1;
const PHASE_LIVE_BUDGET_ADMITTED: &str = "live_budget_admitted";
const PHASE_LIVE_BUDGET_SETTLED: &str = "live_budget_settled";
const PHASE_LIVE_BUDGET_RECOVERED: &str = "live_budget_recovered";
const PHASE_PREPARED: &str = "supervise_prepared";
const PHASE_ASSIGNMENT_STARTED: &str = "assignment_started";
const PHASE_ASSIGNMENT_COMPLETED: &str = "assignment_completed";
const PHASE_CHILD_DISPATCH_STARTED: &str = "child_dispatch_started";
const PHASE_CHILD_DISPATCH_COMPLETED: &str = "child_dispatch_completed";
const PHASE_AUDITOR_DISPATCH_STARTED: &str = "auditor_dispatch_started";
const PHASE_AUDITOR_DISPATCH_COMPLETED: &str = "auditor_dispatch_completed";
const PHASE_SCHEDULER_CLOSED: &str = "scheduler_closed";
const PHASE_FINAL_REPORT_PLANNED: &str = "final_report_planned";
const PHASE_FINAL_REPORT_COMMITTED: &str = "final_report_committed";
const PHASE_FINALIZATION_STARTED: &str = "artifact_finalization_started";
const PHASE_FINALIZED: &str = "artifact_finalized";

#[cfg(test)]
#[derive(Debug)]
struct CheckpointFailureHook {
    run_id: String,
    phase: String,
}

#[cfg(test)]
static CHECKPOINT_FAILURE_HOOKS: std::sync::OnceLock<Mutex<Vec<CheckpointFailureHook>>> =
    std::sync::OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointWorktreeBinding {
    name: String,
    path: PathBuf,
    branch: String,
}

impl From<&WorktreeRecord> for CheckpointWorktreeBinding {
    fn from(record: &WorktreeRecord) -> Self {
        Self {
            name: record.name.clone(),
            path: record.path.clone(),
            branch: record.branch.clone(),
        }
    }
}

impl CheckpointWorktreeBinding {
    fn matches(&self, record: &WorktreeRecord) -> bool {
        self.name == record.name && self.path == record.path && self.branch == record.branch
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedCheckpoint {
    version: u32,
    run_id: String,
    primary_base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inbox_pr_source_head_oid: Option<String>,
    normalized_plan_sha256: String,
    max_concurrent_children: usize,
    assignment_ids: Vec<String>,
    assignment_claim_paths: BTreeMap<String, Vec<PathBuf>>,
    artifact: ArtifactRunResumeBinding,
    budget: RunBudgetReport,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignmentCheckpoint {
    version: u32,
    index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact: Option<ArtifactRunResumeBinding>,
    budget: RunBudgetReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worktree: Option<CheckpointWorktreeBinding>,
    #[serde(default)]
    claim_tokens: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claim_paths: Option<Vec<PathBuf>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DispatchCheckpoint {
    version: u32,
    attempt: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveBudgetCheckpoint {
    binding: BudgetDispatchBinding,
    budget: RunBudgetReport,
    reservation: BudgetReservation,
}

// Accept the first implementation's binding-only records without granting
// them authority to execute an interrupted invocation again.
#[derive(Deserialize)]
#[serde(untagged)]
enum LiveBudgetCheckpointPayload {
    Snapshot(Box<LiveBudgetCheckpoint>),
    Legacy(Box<BudgetDispatchBinding>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchedulerClosedCheckpoint {
    version: u32,
    artifact: ArtifactRunResumeBinding,
    budget: RunBudgetReport,
    pending_assignments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalReportPlannedCheckpoint {
    version: u32,
    artifact: ArtifactRunResumeBinding,
    budget: Option<RunBudgetReport>,
    report_json: String,
    publish_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalReportCommittedCheckpoint {
    version: u32,
    artifact: ArtifactRunResumeBinding,
    budget: Option<RunBudgetReport>,
    report_sha256: String,
    publish_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizationCheckpoint {
    version: u32,
    report_sha256: String,
    budget: Option<RunBudgetReport>,
    publish_requested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssignmentResumeState {
    Pending,
    Started,
    Completed,
}

#[derive(Debug)]
struct ChildDispatchWithoutAssignmentStart;

impl std::fmt::Display for ChildDispatchWithoutAssignmentStart {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("checkpoint child dispatch has no preceding assignment start")
    }
}

impl std::error::Error for ChildDispatchWithoutAssignmentStart {}

#[derive(Debug, Clone)]
pub(super) struct FinalReportResumePlan {
    pub(super) report: SupervisorFinalReport,
    pub(super) report_bytes: Vec<u8>,
    pub(super) artifact: ArtifactRunResumeBinding,
    pub(super) artifact_committed: bool,
    pub(super) publish_requested: bool,
}

#[derive(Debug)]
pub(super) struct SupervisorCheckpointSnapshot {
    pub(super) completed_assignments: Vec<String>,
    pub(super) pending_assignments: Vec<String>,
    pub(super) uncertain_assignments: Vec<String>,
    pub(super) final_report: Option<FinalReportResumePlan>,
    pub(super) finalization_started: bool,
    pub(super) finalized: bool,
    pub(super) run_budget: RunBudgetReport,
    live_reservations: BTreeMap<u64, BudgetReservation>,
    primary_base: Oid,
    pub(super) inbox_pr_source_head_oid: Option<Oid>,
    worktrees: BTreeMap<String, CheckpointWorktreeBinding>,
    claims: BTreeMap<u64, (String, Vec<PathBuf>)>,
}

impl SupervisorCheckpointSnapshot {
    pub(super) fn reconcile_live_budget(
        &mut self,
        checkpoint: &mut SupervisorCheckpointWriter,
    ) -> Result<bool> {
        if !self
            .run_budget
            .dispatch_bindings
            .iter()
            .any(|binding| binding.state == crate::supervise_budget::BudgetDispatchState::Admitted)
        {
            return Ok(false);
        }
        let recovered = self
            .run_budget
            .reconcile_interrupted_dispatches(&self.live_reservations)?;
        checkpoint.append(PHASE_LIVE_BUDGET_RECOVERED, None, &recovered)?;
        self.run_budget = recovered;
        Ok(true)
    }

    pub(super) fn verify_primary_binding(
        &self,
        repo: &Path,
        manager: &WorktreeManager,
    ) -> Result<RepositoryCleanlinessCapability> {
        if current_head_oid(repo)? != self.primary_base {
            bail!("primary HEAD changed after the authenticated supervise checkpoint");
        }
        manager
            .acquire_repository_cleanliness()
            .context("primary worktree is not clean at resume reconciliation")
    }

    pub(super) fn verify_completed_worktrees(&self, manager: &WorktreeManager) -> Result<()> {
        let observed = manager
            .list()?
            .into_iter()
            .map(|record| (record.name.clone(), record))
            .collect::<BTreeMap<_, _>>();
        for (assignment, binding) in &self.worktrees {
            let record = observed.get(&binding.name).with_context(|| {
                format!("completed assignment '{assignment}' checkpoint worktree is missing")
            })?;
            if !binding.matches(record) {
                bail!("completed assignment '{assignment}' checkpoint worktree identity changed");
            }
        }
        Ok(())
    }

    pub(super) fn verify_claim_disposition(
        &self,
        store: &SyncStore,
        report: &SupervisorFinalReport,
        allow_active_terminal_release_plan: bool,
    ) -> Result<()> {
        let released = report
            .released_claims
            .iter()
            .map(|claim| (claim.token.get(), claim))
            .collect::<BTreeMap<_, _>>();
        if released.len() != report.released_claims.len()
            || report.claim_tokens.iter().copied().collect::<BTreeSet<_>>()
                != released.keys().copied().collect()
        {
            bail!("final report released-claim identity is internally inconsistent");
        }
        let active = store
            .snapshot()?
            .into_iter()
            .map(|claim| (claim.token.get(), claim))
            .collect::<BTreeMap<_, _>>();
        for (token, (assignment, paths)) in &self.claims {
            if let Some(released_claim) = released.get(token) {
                if &released_claim.agent_id != assignment || &released_claim.paths != paths {
                    bail!("released checkpoint claim token {token} changed identity or scope");
                }
                if let Some(active_claim) = active.get(token) {
                    if &active_claim.agent_id != assignment || &active_claim.paths != paths {
                        bail!(
                            "active terminal-release claim token {token} changed identity or scope"
                        );
                    }
                    if !allow_active_terminal_release_plan {
                        bail!("released checkpoint claim token {token} remains active");
                    }
                }
                continue;
            }
            let claim = active.get(token).with_context(|| {
                format!("checkpoint claim token {token} is neither durably released nor retained")
            })?;
            if &claim.agent_id != assignment || &claim.paths != paths {
                bail!("retained checkpoint claim token {token} changed identity or scope");
            }
        }
        Ok(())
    }
}

pub(super) struct SupervisorCheckpointWriter {
    journal: StateJournal,
    append_recovery_failed: bool,
    assignment_states: BTreeMap<String, AssignmentResumeState>,
}

pub(super) struct SupervisorCheckpointPreparation<'a> {
    run_id: &'a RunId,
    primary_base: &'a Oid,
    inbox_pr_source_head_oid: Option<Oid>,
    normalized_plan_sha256: String,
    max_concurrent_children: usize,
    plan: &'a SupervisorPlan,
    artifact: ArtifactRunResumeBinding,
    budget: RunBudgetReport,
}

impl<'a> SupervisorCheckpointPreparation<'a> {
    pub(super) fn new(
        run_id: &'a RunId,
        primary_base: &'a Oid,
        normalized_plan_sha256: String,
        max_concurrent_children: usize,
        plan: &'a SupervisorPlan,
        artifact: ArtifactRunResumeBinding,
        budget: RunBudgetReport,
    ) -> Self {
        Self {
            run_id,
            primary_base,
            inbox_pr_source_head_oid: None,
            normalized_plan_sha256,
            max_concurrent_children,
            plan,
            artifact,
            budget,
        }
    }

    pub(super) fn with_inbox_pr_source_head(mut self, head: Option<Oid>) -> Self {
        self.inbox_pr_source_head_oid = head;
        self
    }
}

impl SupervisorCheckpointWriter {
    pub(super) fn create(
        repo: &Path,
        preparation: SupervisorCheckpointPreparation<'_>,
    ) -> Result<Self> {
        let SupervisorCheckpointPreparation {
            run_id,
            primary_base,
            inbox_pr_source_head_oid,
            normalized_plan_sha256,
            max_concurrent_children,
            plan,
            artifact,
            budget,
        } = preparation;
        let authenticator = repository_auth_writer(repo)?.into_authenticator()?;
        let assignment_ids = plan
            .assignments
            .iter()
            .map(|assignment| assignment.id.clone())
            .collect::<Vec<_>>();
        let assignment_states = assignment_ids
            .iter()
            .map(|id| (id.clone(), AssignmentResumeState::Pending))
            .collect::<BTreeMap<_, _>>();
        let mut writer = Self {
            journal: StateJournal::create(authenticator, run_id.as_str())?,
            assignment_states,
            append_recovery_failed: false,
        };
        let assignment_claim_paths = plan
            .assignments
            .iter()
            .map(|assignment| (assignment.id.clone(), assignment.assigned_paths.clone()))
            .collect::<BTreeMap<_, _>>();
        writer.append(
            PHASE_PREPARED,
            None,
            &PreparedCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                run_id: run_id.as_str().to_string(),
                primary_base: primary_base.to_string(),
                inbox_pr_source_head_oid: inbox_pr_source_head_oid.map(|head| head.to_string()),
                normalized_plan_sha256,
                max_concurrent_children,
                assignment_ids,
                assignment_claim_paths,
                artifact,
                budget,
            },
        )?;
        Ok(writer)
    }

    pub(super) fn assignment_started(
        &mut self,
        assignment: &OrchestratorAssignment,
        index: usize,
        artifact: Option<ArtifactRunResumeBinding>,
        budget: RunBudgetReport,
    ) -> Result<()> {
        if self.assignment_states.get(&assignment.id) != Some(&AssignmentResumeState::Pending) {
            bail!("supervise checkpoint assignment start is not uniquely pending");
        }
        self.append(
            PHASE_ASSIGNMENT_STARTED,
            Some(&assignment.id),
            &AssignmentCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                index,
                artifact,
                budget,
                worktree: None,
                claim_tokens: Vec::new(),
                claim_paths: None,
            },
        )?;
        self.assignment_states
            .insert(assignment.id.clone(), AssignmentResumeState::Started);
        Ok(())
    }

    pub(super) fn assignment_completed(
        &mut self,
        assignment: &OrchestratorAssignment,
        index: usize,
        artifact: Option<ArtifactRunResumeBinding>,
        budget: RunBudgetReport,
        worktree: Option<&WorktreeRecord>,
        claim_tokens: Vec<u64>,
    ) -> Result<()> {
        if self.assignment_states.get(&assignment.id) != Some(&AssignmentResumeState::Started) {
            bail!("supervise checkpoint assignment completion has no unique start");
        }
        let claim_paths = (!claim_tokens.is_empty()).then(|| assignment.assigned_paths.clone());
        self.append(
            PHASE_ASSIGNMENT_COMPLETED,
            Some(&assignment.id),
            &AssignmentCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                index,
                artifact,
                budget,
                worktree: worktree.map(CheckpointWorktreeBinding::from),
                claim_tokens,
                claim_paths,
            },
        )?;
        self.assignment_states
            .insert(assignment.id.clone(), AssignmentResumeState::Completed);
        Ok(())
    }

    pub(super) fn dispatch_started(
        &mut self,
        auditor: bool,
        subject: &str,
        attempt: usize,
    ) -> Result<()> {
        self.append(
            if auditor {
                PHASE_AUDITOR_DISPATCH_STARTED
            } else {
                PHASE_CHILD_DISPATCH_STARTED
            },
            Some(subject),
            &DispatchCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                attempt,
            },
        )
    }

    pub(super) fn dispatch_completed(
        &mut self,
        auditor: bool,
        subject: &str,
        attempt: usize,
    ) -> Result<()> {
        self.append(
            if auditor {
                PHASE_AUDITOR_DISPATCH_COMPLETED
            } else {
                PHASE_CHILD_DISPATCH_COMPLETED
            },
            Some(subject),
            &DispatchCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                attempt,
            },
        )
    }

    pub(super) fn scheduler_closed(
        &mut self,
        artifact: ArtifactRunResumeBinding,
        budget: RunBudgetReport,
    ) -> Result<()> {
        let pending_assignments = self
            .assignment_states
            .iter()
            .filter_map(|(id, state)| {
                (*state == AssignmentResumeState::Pending).then_some(id.clone())
            })
            .collect();
        self.append(
            PHASE_SCHEDULER_CLOSED,
            None,
            &SchedulerClosedCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                artifact,
                budget,
                pending_assignments,
            },
        )
    }

    pub(super) fn final_report_planned(
        &mut self,
        report: &SupervisorFinalReport,
        report_bytes: &[u8],
        artifact: ArtifactRunResumeBinding,
    ) -> Result<()> {
        let report_json = String::from_utf8(report_bytes.to_vec())
            .context("normalized supervisor final report is not UTF-8")?;
        self.append(
            PHASE_FINAL_REPORT_PLANNED,
            None,
            &FinalReportPlannedCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                artifact,
                budget: report.run_budget.clone(),
                report_json,
                publish_requested: report.publishable,
            },
        )
    }

    pub(super) fn final_report_committed(
        &mut self,
        report: &SupervisorFinalReport,
        report_bytes: &[u8],
        artifact: ArtifactRunResumeBinding,
    ) -> Result<()> {
        self.append(
            PHASE_FINAL_REPORT_COMMITTED,
            None,
            &FinalReportCommittedCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                artifact,
                budget: report.run_budget.clone(),
                report_sha256: crate::artifacts::state_auth::sha256_hex(report_bytes),
                publish_requested: report.publishable,
            },
        )
    }

    pub(super) fn finalization_started(
        &mut self,
        report: &SupervisorFinalReport,
        report_bytes: &[u8],
    ) -> Result<()> {
        self.append(
            PHASE_FINALIZATION_STARTED,
            None,
            &FinalizationCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                report_sha256: crate::artifacts::state_auth::sha256_hex(report_bytes),
                budget: report.run_budget.clone(),
                publish_requested: report.publishable,
            },
        )
    }

    pub(super) fn finalized(
        &mut self,
        report: &SupervisorFinalReport,
        report_bytes: &[u8],
    ) -> Result<()> {
        self.append(
            PHASE_FINALIZED,
            None,
            &FinalizationCheckpoint {
                version: SUPERVISE_CHECKPOINT_VERSION,
                report_sha256: crate::artifacts::state_auth::sha256_hex(report_bytes),
                budget: report.run_budget.clone(),
                publish_requested: report.publishable,
            },
        )
    }

    fn append<T: Serialize>(
        &mut self,
        phase: &str,
        subject: Option<&str>,
        payload: &T,
    ) -> Result<()> {
        if self.append_recovery_failed {
            bail!("supervise checkpoint requires authenticated recovery after an uncertain append");
        }
        #[cfg(test)]
        if take_checkpoint_failure(self.journal.instance_id(), phase) {
            bail!("injected supervise checkpoint failure before phase '{phase}'");
        }
        self.journal.append(phase, subject, payload)?;
        #[cfg(test)]
        if take_checkpoint_failure(self.journal.instance_id(), &format!("after:{phase}")) {
            bail!("injected supervise checkpoint failure after phase '{phase}'");
        }
        Ok(())
    }
}

pub(super) fn record_assignment_started_checkpoint(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    assignment: &OrchestratorAssignment,
    index: usize,
    budget_ledger: &RunBudgetLedger,
) -> Result<()> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    if guard.checkpoint.is_none() {
        return Ok(());
    }
    let artifact = match guard.writer.resume_binding() {
        Ok(binding) => Some(binding),
        Err(error)
            if error
                .to_string()
                .contains("not at a resumable manifest boundary") =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let budget = budget_ledger.report()?;
    guard
        .checkpoint
        .as_deref_mut()
        .context("supervise checkpoint writer disappeared")?
        .assignment_started(assignment, index, artifact, budget)
}

pub(super) fn record_assignment_completed_checkpoint(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    assignment: &OrchestratorAssignment,
    index: usize,
    budget_ledger: &RunBudgetLedger,
    worktree: Option<&WorktreeRecord>,
    claim_tokens: Vec<u64>,
) -> Result<()> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    if guard.checkpoint.is_none() {
        return Ok(());
    }
    let artifact = match guard.writer.resume_binding() {
        Ok(binding) => Some(binding),
        Err(error)
            if error
                .to_string()
                .contains("not at a resumable manifest boundary") =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let budget = budget_ledger.report()?;
    guard
        .checkpoint
        .as_deref_mut()
        .context("supervise checkpoint writer disappeared")?
        .assignment_completed(assignment, index, artifact, budget, worktree, claim_tokens)
}

pub(super) fn record_dispatch_checkpoint(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    auditor: bool,
    completed: bool,
    subject: &str,
    attempt: usize,
) -> Result<()> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifact writer mutex was poisoned"))?;
    let Some(checkpoint) = guard.checkpoint.as_deref_mut() else {
        return Ok(());
    };
    if completed {
        checkpoint.dispatch_completed(auditor, subject, attempt)
    } else {
        checkpoint.dispatch_started(auditor, subject, attempt)
    }
}

pub(super) fn record_live_budget_admission(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    reservation: &DispatchBudgetReservation<'_>,
    command: &ExternalAgentCommand,
) -> Result<()> {
    // This evidence contract covers terminal Worker dispatches (both shared
    // parent-worktree and isolated sibling routes).
    if reservation.reservation.role != AgentRole::Worker {
        return Ok(());
    }
    let Some(invocation) = command
        .live_budget_invocation()
        .map_err(anyhow::Error::msg)?
    else {
        return Ok(());
    };
    let grant = command
        .bound_live_token_grant()
        .map_err(anyhow::Error::msg)?
        .context("live dispatch has no retained grant")?;
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifacts poisoned"))?;
    reservation
        .ledger
        .bind_dispatch(reservation.reservation.id, invocation, grant)?;
    let result = persist_live_budget_binding_locked(&mut guard, reservation, false);
    if result.is_err() {
        reservation
            .ledger
            .discard_unconfirmed_dispatch(reservation.reservation.id)?;
    }
    result
}

pub(super) fn persist_live_budget_binding(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    reservation: &DispatchBudgetReservation<'_>,
    settled: bool,
) -> Result<()> {
    let mut guard = artifacts
        .lock()
        .map_err(|_| anyhow!("supervisor artifacts poisoned"))?;
    let result = persist_live_budget_binding_locked(&mut guard, reservation, settled);
    if !settled && result.is_err() {
        reservation
            .ledger
            .discard_unconfirmed_dispatch(reservation.reservation.id)?;
    }
    result
}

fn persist_live_budget_binding_locked(
    guard: &mut SharedSupervisorArtifacts<'_>,
    reservation: &DispatchBudgetReservation<'_>,
    settled: bool,
) -> Result<()> {
    let budget = reservation.ledger.report()?;
    let Some(binding) = budget
        .dispatch_bindings
        .iter()
        .find(|binding| binding.reservation_id == reservation.reservation.id.get())
    else {
        return Ok(());
    };
    if settled && binding.state == crate::supervise_budget::BudgetDispatchState::Admitted {
        // No successful accounting transaction exists yet (for example a
        // runner error before release). The final checkpoint records the
        // release/drop disposition; never label this an observed settlement.
        return Ok(());
    }
    let suffix = if settled { "settled" } else { "admitted" };
    write_artifact_json(
        guard.writer,
        &PathBuf::from(format!(
            "budget/dispatch-{}.{}.json",
            binding.reservation_id, suffix
        )),
        &json!({"binding": binding, "budget": budget}),
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    if let Some(checkpoint) = guard.checkpoint.as_deref_mut() {
        let phase = if settled {
            PHASE_LIVE_BUDGET_SETTLED
        } else {
            PHASE_LIVE_BUDGET_ADMITTED
        };
        let previous_records = checkpoint.journal.records().len();
        let result = checkpoint.append(
            phase,
            Some(&binding.invocation.assignment_id),
            &LiveBudgetCheckpoint {
                binding: binding.clone(),
                budget: budget.clone(),
                reservation: reservation.reservation.clone(),
            },
        );
        if !settled && result.is_err() {
            checkpoint
                .journal
                .recover_failed_append()
                .map_err(|error| {
                    checkpoint.append_recovery_failed = true;
                    error.context("could not authenticate failed live admission append")
                })?;
        }
        // An error can occur after the immutable record is published (for
        // example updating its head). Retain that admission on abort; otherwise
        // releasing the reservation removes the unjournaled tentative binding.
        if !settled && checkpoint.journal.records().len() > previous_records {
            reservation
                .ledger
                .confirm_dispatch_admission(reservation.reservation.id)?;
        }
        result?;
    } else if !settled {
        reservation
            .ledger
            .confirm_dispatch_admission(reservation.reservation.id)?;
    }
    Ok(())
}

fn same_budget_admission(
    before: &crate::supervise_budget::BudgetDispatchBinding,
    after: &crate::supervise_budget::BudgetDispatchBinding,
) -> bool {
    let mut copy = after.clone();
    copy.state = before.state;
    copy.thread_id.clone_from(&before.thread_id);
    copy.turn_id.clone_from(&before.turn_id);
    copy.invocation_verified = before.invocation_verified;
    copy.charged_tokens = before.charged_tokens;
    copy.usage_complete = before.usage_complete;
    copy == *before
}

fn validate_live_budget_report(
    budget: &RunBudgetReport,
    admitted: &BTreeMap<u64, BudgetDispatchBinding>,
) -> Result<()> {
    use crate::supervise_budget::BudgetDispatchState;
    if budget.dispatch_bindings.len() != admitted.len() {
        bail!("budget lost authenticated live dispatch bindings");
    }
    let mut seen = BTreeSet::new();
    for binding in &budget.dispatch_bindings {
        let before = admitted
            .get(&binding.reservation_id)
            .context("unauthenticated live dispatch binding")?;
        if !seen.insert(binding.reservation_id)
            || !same_budget_admission(before, binding)
            || (before.state != BudgetDispatchState::Admitted && before != binding)
        {
            bail!("budget changed its authenticated live dispatch binding");
        }
        let charges = budget
            .charges
            .iter()
            .filter(|charge| charge.reservation_id == binding.reservation_id)
            .collect::<Vec<_>>();
        match binding.state {
            BudgetDispatchState::Settled
                if charges.len() == 1
                    && Some(charges[0].tokens) == binding.charged_tokens
                    && Some(charges[0].usage_complete) == binding.usage_complete => {}
            BudgetDispatchState::Admitted | BudgetDispatchState::NotStarted
                if charges.is_empty()
                    && binding.charged_tokens.is_none()
                    && binding.usage_complete.is_none() => {}
            _ => bail!("live dispatch disposition differs from its unique charge"),
        }
    }
    Ok(())
}

fn merge_legacy_budget_binding(
    budget: &mut RunBudgetReport,
    binding: BudgetDispatchBinding,
) -> Result<()> {
    use crate::supervise_budget::BudgetDispatchState;
    if binding.state == BudgetDispatchState::Admitted {
        let grant = usize::try_from(binding.grant_tokens)?;
        budget.consumed.tokens = budget.consumed.tokens.max(binding.consumed_before);
        budget.reserved.tokens = binding.reserved_at_admission;
        budget.reserved.cost_usd = None;
        budget.active_reservations = binding.active_at_admission;
        if !budget
            .roles
            .iter()
            .any(|role| role.role == AgentRole::Worker)
        {
            budget
                .roles
                .push(crate::supervise_budget::RoleBudgetReport {
                    role: AgentRole::Worker,
                    consumed: BudgetAmount {
                        tokens: 0,
                        cost_usd: Some(0.0),
                    },
                    reserved: BudgetAmount {
                        tokens: 0,
                        cost_usd: None,
                    },
                    active_reservations: 0,
                    usage_complete: true,
                });
        }
        let role = budget
            .roles
            .iter_mut()
            .find(|role| role.role == AgentRole::Worker)
            .unwrap();
        role.reserved.tokens = role
            .reserved
            .tokens
            .checked_add(grant)
            .context("legacy grant overflow")?;
        role.reserved.cost_usd = None;
        role.active_reservations += 1;
        budget.dispatch_bindings.push(binding);
    } else {
        // Old settlement records lack a full accounting snapshot. Start with
        // the same conservative transaction, then retain the authenticated
        // observed token count and its explicit completeness, never a guess.
        let mut recovered = budget.reconcile_interrupted_dispatches_matching(
            &BTreeMap::new(),
            Some(binding.reservation_id),
        )?;
        let target = recovered
            .dispatch_bindings
            .iter_mut()
            .find(|item| item.reservation_id == binding.reservation_id)
            .context("legacy settlement has no admission")?;
        let floor = target
            .charged_tokens
            .context("legacy settlement has no floor")?;
        let charge = recovered
            .charges
            .iter_mut()
            .find(|item| item.reservation_id == binding.reservation_id)
            .unwrap();
        let tokens = binding.charged_tokens.unwrap_or(0);
        recovered.consumed.tokens = recovered.consumed.tokens - floor + tokens;
        let role = recovered
            .roles
            .iter_mut()
            .find(|role| role.role == AgentRole::Worker)
            .unwrap();
        role.consumed.tokens = role.consumed.tokens - floor + tokens;
        if binding.state == BudgetDispatchState::NotStarted {
            recovered
                .charges
                .retain(|charge| charge.reservation_id != binding.reservation_id);
        } else {
            charge.tokens = tokens;
            charge.usage_complete = binding.usage_complete.unwrap_or(false);
        }
        *target = binding;
        *budget = recovered;
    }
    budget.committed.tokens = budget
        .consumed
        .tokens
        .checked_add(budget.reserved.tokens)
        .context("legacy committed tokens overflow")?;
    budget.remaining.soft_tokens = budget
        .limits
        .soft_tokens
        .map(|limit| limit.saturating_sub(budget.committed.tokens));
    budget.remaining.hard_tokens = budget
        .limits
        .hard_tokens
        .map(|limit| limit.saturating_sub(budget.committed.tokens));
    Ok(())
}

pub(super) fn normalized_supervisor_plan_sha256(
    plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
    assignment_metadata: &AssignmentMetadata,
    plan_metadata: &SupervisorPlanMetadata,
) -> Result<String> {
    let value = supervisor_plan_value(plan, consultant, assignment_metadata, plan_metadata)?;
    let bytes = serde_json::to_vec(&value).context("failed to encode normalized plan binding")?;
    Ok(crate::artifacts::state_auth::sha256_hex(&bytes))
}

pub(super) fn open_supervisor_checkpoint(
    repo: &Path,
    run_id: &RunId,
) -> Result<(SupervisorCheckpointWriter, SupervisorCheckpointSnapshot)> {
    let authenticator = repository_authenticator_key_only(repo)?;
    validate_repository_authenticated_state(repo, &authenticator)?;
    let journal = StateJournal::open_instance(authenticator, run_id.as_str())?;
    let snapshot = analyze_checkpoint_records(journal.records(), run_id)?;
    let assignment_states = snapshot
        .completed_assignments
        .iter()
        .map(|id| (id.clone(), AssignmentResumeState::Completed))
        .chain(
            snapshot
                .pending_assignments
                .iter()
                .map(|id| (id.clone(), AssignmentResumeState::Pending)),
        )
        .chain(
            snapshot
                .uncertain_assignments
                .iter()
                .map(|id| (id.clone(), AssignmentResumeState::Started)),
        )
        .collect();
    Ok((
        SupervisorCheckpointWriter {
            journal,
            assignment_states,
            append_recovery_failed: false,
        },
        snapshot,
    ))
}

pub(super) fn authenticated_child_dispatch_started(repo: &Path, run_id: &RunId) -> Result<bool> {
    let authenticator = repository_authenticator_key_only(repo)?;
    validate_repository_authenticated_state(repo, &authenticator)?;
    let journal = StateJournal::open_instance(authenticator, run_id.as_str())?;
    let records = journal.records();
    // Opening authenticates the complete chain and repository/key epoch. The
    // supervise analyzer additionally proves that the authenticated records
    // form a structurally valid checkpoint before a raw phase can become
    // execution evidence.
    if let Err(error) = analyze_checkpoint_records(records, run_id) {
        if error.is::<ChildDispatchWithoutAssignmentStart>() {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(records
        .iter()
        .any(|record| record.phase == PHASE_CHILD_DISPATCH_STARTED))
}

fn analyze_checkpoint_records(
    records: &[JournalRecord],
    run_id: &RunId,
) -> Result<SupervisorCheckpointSnapshot> {
    let first = records
        .first()
        .context("authenticated supervise checkpoint has no durable prepared record")?;
    if first.phase != PHASE_PREPARED || first.subject.is_some() {
        bail!("authenticated journal is not a supervise checkpoint");
    }
    let prepared: PreparedCheckpoint = decode_payload(first)?;
    validate_version(prepared.version)?;
    let primary_base = Oid::from_str(&prepared.primary_base)
        .context("authenticated supervise primary base is malformed")?;
    let inbox_pr_source_head_oid = prepared
        .inbox_pr_source_head_oid
        .as_deref()
        .map(|value| {
            let head = Oid::from_str(value)
                .context("authenticated Inbox PR source checkpoint head is malformed")?;
            if value != head.to_string() {
                bail!("authenticated Inbox PR source checkpoint head is not canonical");
            }
            Ok(head)
        })
        .transpose()?;
    if prepared.run_id != run_id.as_str()
        || prepared.assignment_ids.len() != prepared.assignment_claim_paths.len()
        || !is_canonical_lower_hex_64(&prepared.normalized_plan_sha256)
    {
        bail!("authenticated supervise prepared checkpoint binding is invalid");
    }
    let mut assignments = prepared
        .assignment_ids
        .iter()
        .map(|id| (id.clone(), AssignmentResumeState::Pending))
        .collect::<BTreeMap<_, _>>();
    if assignments.len() != prepared.assignment_ids.len()
        || assignments
            .keys()
            .any(|id| !prepared.assignment_claim_paths.contains_key(id))
    {
        bail!("authenticated supervise checkpoint assignment binding is invalid");
    }
    let mut worktrees = BTreeMap::new();
    let mut claims = BTreeMap::new();
    let mut scheduler_closed = false;
    let mut scheduler_budget = None;
    let mut run_budget = prepared.budget.clone();
    let mut live_reservations = BTreeMap::new();
    let mut dispatches = BTreeSet::new();
    let mut live_bindings = BTreeMap::new();
    let mut final_report = None;
    let mut final_report_committed = false;
    let mut finalization_started = false;
    let mut finalized = false;
    for record in records.iter().skip(1) {
        match record.phase.as_str() {
            PHASE_ASSIGNMENT_STARTED => {
                let subject = required_subject(record)?;
                let payload: AssignmentCheckpoint = decode_payload(record)?;
                validate_assignment_payload(&prepared, subject, &payload)?;
                run_budget = payload.budget.clone();
                let state = assignments
                    .get_mut(subject)
                    .context("checkpoint start references an unknown assignment")?;
                if *state != AssignmentResumeState::Pending || scheduler_closed {
                    bail!("checkpoint contains a duplicate or late assignment start");
                }
                *state = AssignmentResumeState::Started;
            }
            PHASE_ASSIGNMENT_COMPLETED => {
                let subject = required_subject(record)?;
                let payload: AssignmentCheckpoint = decode_payload(record)?;
                validate_assignment_payload(&prepared, subject, &payload)?;
                run_budget = payload.budget.clone();
                let state = assignments
                    .get_mut(subject)
                    .context("checkpoint completion references an unknown assignment")?;
                if *state != AssignmentResumeState::Started || scheduler_closed {
                    bail!("checkpoint completion has no unique preceding assignment start");
                }
                *state = AssignmentResumeState::Completed;
                let prepared_claim_paths = prepared
                    .assignment_claim_paths
                    .get(subject)
                    .context("checkpoint assignment claim scope disappeared")?;
                let claim_paths = match payload.claim_paths {
                    Some(paths) => {
                        if payload.claim_tokens.is_empty()
                            || paths.is_empty()
                            || paths.iter().collect::<BTreeSet<_>>().len() != paths.len()
                            || paths
                                .iter()
                                .any(|path| !prepared_claim_paths.contains(path))
                        {
                            bail!(
                                "checkpoint assignment claim scope is not a non-empty subset of its prepared scope"
                            );
                        }
                        paths
                    }
                    None => prepared_claim_paths.clone(),
                };
                for token in payload.claim_tokens {
                    if claims
                        .insert(token, (subject.to_string(), claim_paths.clone()))
                        .is_some()
                    {
                        bail!("checkpoint claim token is bound to multiple assignments");
                    }
                }
                if let Some(worktree) = payload.worktree {
                    worktrees.insert(subject.to_string(), worktree);
                }
            }
            PHASE_CHILD_DISPATCH_STARTED | PHASE_AUDITOR_DISPATCH_STARTED => {
                let subject = required_subject(record)?;
                let payload: DispatchCheckpoint = decode_payload(record)?;
                validate_version(payload.version)?;
                let auditor = record.phase == PHASE_AUDITOR_DISPATCH_STARTED;
                if !auditor {
                    match assignments.get(subject) {
                        Some(AssignmentResumeState::Started) => {}
                        Some(AssignmentResumeState::Completed) => {
                            bail!("checkpoint child dispatch started after assignment completion")
                        }
                        Some(AssignmentResumeState::Pending) | None => {
                            return Err(ChildDispatchWithoutAssignmentStart.into());
                        }
                    }
                }
                if !dispatches.insert((auditor, subject.to_string(), payload.attempt)) {
                    bail!("checkpoint contains a duplicate dispatch start");
                }
            }
            PHASE_CHILD_DISPATCH_COMPLETED | PHASE_AUDITOR_DISPATCH_COMPLETED => {
                let subject = required_subject(record)?;
                let payload: DispatchCheckpoint = decode_payload(record)?;
                validate_version(payload.version)?;
                let auditor = record.phase == PHASE_AUDITOR_DISPATCH_COMPLETED;
                if !dispatches.remove(&(auditor, subject.to_string(), payload.attempt)) {
                    bail!("checkpoint dispatch completion has no unique preceding start");
                }
            }
            PHASE_LIVE_BUDGET_ADMITTED | PHASE_LIVE_BUDGET_SETTLED => {
                use crate::supervise_budget::{BudgetDispatchBinding, BudgetDispatchState};
                let payload: LiveBudgetCheckpointPayload = decode_payload(record)?;
                let (binding, budget) = match payload {
                    LiveBudgetCheckpointPayload::Snapshot(payload) => {
                        if payload.reservation.id.get() != payload.binding.reservation_id
                            || payload.reservation.tokens != payload.binding.estimate_tokens
                            || payload.reservation.role != AgentRole::Worker
                        {
                            bail!("live budget checkpoint changed its reservation");
                        }
                        live_reservations
                            .insert(payload.binding.reservation_id, payload.reservation);
                        (payload.binding, Some(payload.budget))
                    }
                    LiveBudgetCheckpointPayload::Legacy(binding) => (*binding, None),
                };
                if scheduler_closed {
                    bail!("live budget checkpoint followed scheduler closure");
                }
                if binding.version != 1
                    || binding.invocation.run_id != run_id.as_str()
                    || record.subject.as_deref() != Some(&binding.invocation.assignment_id)
                    || binding.reservation_id == 0
                    || binding.invocation.attempt == 0
                    || binding.grant_tokens < binding.estimate_tokens as u64
                {
                    bail!("invalid authenticated live budget binding");
                }
                if record.phase == PHASE_LIVE_BUDGET_ADMITTED {
                    if binding.state != BudgetDispatchState::Admitted
                        || live_bindings
                            .values()
                            .any(|prior: &BudgetDispatchBinding| prior.grant_id == binding.grant_id)
                        || !is_canonical_lower_hex_64(&binding.invocation.command_sha256)
                        || binding.reserved_at_admission < binding.grant_tokens as usize
                        || live_bindings
                            .insert(binding.reservation_id, binding.clone())
                            .is_some()
                    {
                        bail!("duplicate or invalid live budget admission");
                    }
                } else {
                    let before = live_bindings
                        .get_mut(&binding.reservation_id)
                        .context("live budget settlement has no admission")?;
                    if before.state != BudgetDispatchState::Admitted
                        || binding.state == BudgetDispatchState::Admitted
                        || !same_budget_admission(before, &binding)
                    {
                        bail!("live budget settlement changed its admitted invocation");
                    }
                    *before = binding.clone();
                }
                if let Some(budget) = budget {
                    validate_live_budget_report(&budget, &live_bindings)?;
                    run_budget = budget;
                } else {
                    merge_legacy_budget_binding(&mut run_budget, binding)?;
                }
            }
            PHASE_LIVE_BUDGET_RECOVERED => {
                if scheduler_closed || record.subject.is_some() {
                    bail!("live budget recovery is outside the interrupted lifecycle");
                }
                validate_live_budget_report(&run_budget, &live_bindings)?;
                let recovered: RunBudgetReport = decode_payload(record)?;
                if recovered == run_budget
                    || recovered
                        != run_budget.reconcile_interrupted_dispatches(&live_reservations)?
                {
                    bail!("live budget recovery changed or repeated its conservative disposition");
                }
                for binding in &recovered.dispatch_bindings {
                    live_bindings.insert(binding.reservation_id, binding.clone());
                }
                run_budget = recovered;
            }
            PHASE_SCHEDULER_CLOSED => {
                if record.subject.is_some() || scheduler_closed {
                    bail!("checkpoint contains a duplicate scheduler closure");
                }
                let payload: SchedulerClosedCheckpoint = decode_payload(record)?;
                validate_version(payload.version)?;
                let pending = assignments
                    .iter()
                    .filter_map(|(id, state)| {
                        (*state == AssignmentResumeState::Pending).then_some(id.clone())
                    })
                    .collect::<Vec<_>>();
                if payload.pending_assignments != pending {
                    bail!("checkpoint scheduler closure has inconsistent pending assignments");
                }
                if payload.budget.dispatch_bindings.len() != live_bindings.len() {
                    bail!("final budget lost authenticated live dispatch bindings");
                }
                for binding in &payload.budget.dispatch_bindings {
                    let admitted = live_bindings
                        .get(&binding.reservation_id)
                        .context("final budget has an unauthenticated dispatch binding")?;
                    if !same_budget_admission(admitted, binding)
                        || (admitted.state
                            != crate::supervise_budget::BudgetDispatchState::Admitted
                            && admitted != binding)
                    {
                        bail!("final budget changed its admitted invocation or settlement");
                    }
                    if binding.state == crate::supervise_budget::BudgetDispatchState::Admitted
                        || (binding.state == crate::supervise_budget::BudgetDispatchState::Settled
                            && binding.charged_tokens.is_none())
                    {
                        bail!("final budget has an unsettled live dispatch binding");
                    }
                    if let Some(tokens) = binding.charged_tokens {
                        if !payload.budget.charges.iter().any(|charge| {
                            charge.reservation_id == binding.reservation_id
                                && charge.tokens == tokens
                                && Some(charge.usage_complete) == binding.usage_complete
                        }) {
                            bail!("final live budget settlement differs from its charge");
                        }
                    }
                }
                run_budget = payload.budget.clone();
                scheduler_budget = Some(payload.budget);
                scheduler_closed = true;
            }
            PHASE_FINAL_REPORT_PLANNED => {
                if record.subject.is_some() || !scheduler_closed || final_report.is_some() {
                    bail!("checkpoint final report plan is out of lifecycle order");
                }
                let payload: FinalReportPlannedCheckpoint = decode_payload(record)?;
                validate_version(payload.version)?;
                let report_bytes = payload.report_json.into_bytes();
                let report: SupervisorFinalReport = serde_json::from_slice(&report_bytes)
                    .context("authenticated planned supervisor final report is malformed")?;
                if report.run_id != *run_id
                    || report.run_budget != payload.budget
                    || report.run_budget.as_ref() != scheduler_budget.as_ref()
                    || report.publishable != payload.publish_requested
                {
                    bail!("authenticated planned supervisor report binding is inconsistent");
                }
                final_report = Some(FinalReportResumePlan {
                    report,
                    report_bytes,
                    artifact: payload.artifact,
                    artifact_committed: false,
                    publish_requested: payload.publish_requested,
                });
            }
            PHASE_FINAL_REPORT_COMMITTED => {
                if record.subject.is_some() || final_report_committed {
                    bail!("checkpoint contains a duplicate final report commit");
                }
                let payload: FinalReportCommittedCheckpoint = decode_payload(record)?;
                validate_version(payload.version)?;
                let plan = final_report
                    .as_mut()
                    .context("checkpoint final report commit has no planned report")?;
                validate_final_report_transition(
                    plan,
                    &payload.report_sha256,
                    payload.budget.as_ref(),
                    payload.publish_requested,
                )?;
                plan.artifact = payload.artifact;
                plan.artifact_committed = true;
                final_report_committed = true;
            }
            PHASE_FINALIZATION_STARTED | PHASE_FINALIZED => {
                if record.subject.is_some() {
                    bail!("checkpoint finalization transition cannot have a subject");
                }
                let payload: FinalizationCheckpoint = decode_payload(record)?;
                validate_version(payload.version)?;
                let plan = final_report
                    .as_ref()
                    .context("checkpoint finalization has no planned report")?;
                if !final_report_committed {
                    bail!("checkpoint finalization began before report commit");
                }
                validate_final_report_transition(
                    plan,
                    &payload.report_sha256,
                    payload.budget.as_ref(),
                    payload.publish_requested,
                )?;
                if record.phase == PHASE_FINALIZATION_STARTED {
                    if finalization_started || finalized {
                        bail!("checkpoint contains a duplicate finalization start");
                    }
                    finalization_started = true;
                } else {
                    if !finalization_started || finalized {
                        bail!("checkpoint finalization completion is out of order");
                    }
                    finalized = true;
                }
            }
            _ => bail!("authenticated supervise checkpoint contains an unknown transition"),
        }
    }
    let completed_assignments = assignments
        .iter()
        .filter_map(|(id, state)| {
            (*state == AssignmentResumeState::Completed).then_some(id.clone())
        })
        .collect();
    let pending_assignments = assignments
        .iter()
        .filter_map(|(id, state)| (*state == AssignmentResumeState::Pending).then_some(id.clone()))
        .collect();
    let mut uncertain_assignments = assignments
        .iter()
        .filter_map(|(id, state)| (*state == AssignmentResumeState::Started).then_some(id.clone()))
        .collect::<BTreeSet<_>>();
    uncertain_assignments.extend(dispatches.into_iter().map(|(_, subject, _)| {
        owning_assignment_id_for_dispatch_subject(&subject, &prepared.assignment_ids).to_string()
    }));
    validate_live_budget_report(&run_budget, &live_bindings)?;
    Ok(SupervisorCheckpointSnapshot {
        completed_assignments,
        pending_assignments,
        uncertain_assignments: uncertain_assignments.into_iter().collect(),
        final_report,
        finalization_started,
        finalized,
        run_budget,
        live_reservations,
        primary_base,
        inbox_pr_source_head_oid,
        worktrees,
        claims,
    })
}

fn validate_assignment_payload(
    prepared: &PreparedCheckpoint,
    subject: &str,
    payload: &AssignmentCheckpoint,
) -> Result<()> {
    validate_version(payload.version)?;
    if prepared
        .assignment_ids
        .get(payload.index)
        .map(String::as_str)
        != Some(subject)
    {
        bail!("checkpoint assignment index does not match its subject");
    }
    Ok(())
}

fn validate_final_report_transition(
    plan: &FinalReportResumePlan,
    report_sha256: &str,
    budget: Option<&RunBudgetReport>,
    publish_requested: bool,
) -> Result<()> {
    if report_sha256 != crate::artifacts::state_auth::sha256_hex(&plan.report_bytes)
        || budget != plan.report.run_budget.as_ref()
        || publish_requested != plan.publish_requested
    {
        bail!("checkpoint final report transition binding is inconsistent");
    }
    Ok(())
}

fn required_subject(record: &JournalRecord) -> Result<&str> {
    record
        .subject
        .as_deref()
        .context("checkpoint assignment transition has no subject")
}

fn decode_payload<T: DeserializeOwned>(record: &JournalRecord) -> Result<T> {
    serde_json::from_value(record.payload.clone())
        .with_context(|| format!("checkpoint phase '{}' payload is malformed", record.phase))
}

fn validate_version(version: u32) -> Result<()> {
    if version != SUPERVISE_CHECKPOINT_VERSION {
        bail!("unsupported supervise checkpoint version {version}");
    }
    Ok(())
}

fn is_canonical_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
pub(super) fn install_checkpoint_failure(run_id: &str, phase: &str) {
    let hooks = CHECKPOINT_FAILURE_HOOKS.get_or_init(|| Mutex::new(Vec::new()));
    let mut hooks = hooks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(!hooks
        .iter()
        .any(|hook| hook.run_id == run_id && hook.phase == phase));
    hooks.push(CheckpointFailureHook {
        run_id: run_id.to_string(),
        phase: phase.to_string(),
    });
}

#[cfg(test)]
fn take_checkpoint_failure(run_id: &str, phase: &str) -> bool {
    let hooks = CHECKPOINT_FAILURE_HOOKS.get_or_init(|| Mutex::new(Vec::new()));
    let mut hooks = hooks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match hooks
        .iter()
        .position(|hook| hook.run_id == run_id && hook.phase == phase)
    {
        Some(index) => {
            hooks.remove(index);
            true
        }
        None => false,
    }
}

#[cfg(test)]
pub(super) fn verify_live_budget_checkpoint_tampering(repo: &Path, run_id: &RunId) -> Result<()> {
    let (writer, _) = open_supervisor_checkpoint(repo, run_id)?;
    for pointer in [
        "/grant_id",
        "/grant_tokens",
        "/reservation_id",
        "/invocation/attempt",
        "/invocation/command_sha256",
        "/invocation/account",
    ] {
        let mut records = writer.journal.records().to_vec();
        let record = records
            .iter_mut()
            .find(|record| record.phase == PHASE_LIVE_BUDGET_SETTLED)
            .unwrap();
        let pointer = format!("/binding{pointer}");
        let field = record.payload.pointer_mut(&pointer).unwrap();
        *field = if field.is_number() {
            json!(field.as_u64().unwrap() + 1)
        } else if field.is_object() {
            json!({"kind":"local_auth"})
        } else {
            json!("substituted")
        };
        assert!(
            analyze_checkpoint_records(&records, run_id).is_err(),
            "accepted tampered {pointer}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod auditor_failure_probes {
    use super::*;
    use crate::supervise_budget::BudgetReservationId;

    struct Fixture {
        _temp: tempfile::TempDir,
        repo: PathBuf,
        run_id: RunId,
        plan: SupervisorPlan,
        writer: ArtifactRunWriter,
        checkpoint: SupervisorCheckpointWriter,
        ledger: RunBudgetLedger,
        id: BudgetReservationId,
        binding: BudgetDispatchBinding,
    }

    fn prepare(case: &str) -> Result<Fixture> {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new(format!("auditor-{case}"))?;
        let plan: SupervisorPlan = serde_json::from_value(
            json!({"assignments":[{"id":"parent", "phase":"execution", "assigned_paths":["README.md"], "worker_assignments":[{"id":"worker", "role":"worker", "assigned_paths":["README.md"]}]}]}),
        )?;
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            hard_tokens: Some(1000),
            ..Default::default()
        })?;
        let writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "auditor-probe",
        )?;
        let mut checkpoint = SupervisorCheckpointWriter::create(
            &repo,
            SupervisorCheckpointPreparation::new(
                &run_id,
                &current_head_oid(&repo)?,
                "a".repeat(64),
                1,
                &plan,
                writer.resume_binding()?,
                ledger.report()?,
            ),
        )?;
        checkpoint.assignment_started(
            &plan.assignments[0],
            0,
            Some(writer.resume_binding()?),
            ledger.report()?,
        )?;
        let BudgetAdmission::Admitted { reservation, .. } =
            ledger.reserve(BudgetReservationRequest {
                role: AgentRole::Worker,
                tokens: 10,
                cost_usd: None,
            })?
        else {
            unreachable!()
        };
        let grant = ledger.live_token_grant(reservation.id)?.unwrap();
        let binding = ledger.bind_dispatch(
            reservation.id,
            BudgetDispatchInvocation {
                run_id: run_id.as_str().into(),
                assignment_id: "worker".into(),
                parent_id: Some("parent".into()),
                attempt: 1,
                runtime: "codex".into(),
                account: BudgetAccountIdentity::Unspecified,
                command_sha256: "b".repeat(64),
            },
            &grant,
        )?;
        Ok(Fixture {
            _temp: temp,
            repo,
            run_id,
            plan,
            writer,
            checkpoint,
            ledger,
            id: reservation.id,
            binding,
        })
    }

    #[test]
    fn review714_crash_before_observation_preserves_budget_for_reconciliation() -> Result<()> {
        let Fixture {
            _temp,
            repo,
            run_id,
            writer,
            mut checkpoint,
            ledger,
            binding,
            ..
        } = prepare("crash")?;
        checkpoint.append(PHASE_LIVE_BUDGET_ADMITTED, Some("worker"), &binding)?;
        drop(checkpoint);
        drop(writer);
        drop(ledger);
        let resumed = resume_supervisor_run(&repo, run_id.clone())?;
        let collected = collect_supervisor_run(&repo, run_id.clone())?;
        assert!(
            resumed.run_budget.is_some() && collected.run_budget.is_some(),
            "durably admitted grant disappeared: resume budget={:?}, collect budget={:?}",
            resumed.run_budget,
            collected.run_budget
        );
        assert!(resumed.budget_reconciled_from_checkpoint);
        assert!(!resumed.resumed);
        let budget = resumed.run_budget.unwrap();
        assert_eq!(budget.consumed.tokens, 10);
        assert_eq!(budget.reserved.tokens, 0);
        assert_eq!(budget.active_reservations, 0);
        assert!(!budget.usage_complete);
        assert!(!budget.new_dispatch_allowed);
        assert_eq!(budget.charges.len(), 1);
        assert!(!budget.charges[0].usage_complete);
        assert_eq!(
            budget.dispatch_bindings[0].state,
            crate::supervise_budget::BudgetDispatchState::Settled
        );
        assert_eq!(budget.dispatch_bindings[0].thread_id, None);
        assert_eq!(Some(budget.clone()), collected.run_budget);
        let again = resume_supervisor_run(&repo, run_id.clone())?;
        assert_eq!(again.run_budget, Some(budget));
        let (checkpoint, _) = open_supervisor_checkpoint(&repo, &run_id)?;
        assert_eq!(
            checkpoint
                .journal
                .records()
                .iter()
                .filter(|record| record.phase == PHASE_LIVE_BUDGET_RECOVERED)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn nested_worker_durable_budget_binding_recovers_full_snapshot_after_append_failure(
    ) -> Result<()> {
        let Fixture {
            _temp,
            repo,
            run_id,
            writer,
            mut checkpoint,
            ledger,
            id,
            binding,
            ..
        } = prepare("snapshot-crash")?;
        let reservation = BudgetReservation {
            id,
            role: AgentRole::Worker,
            tokens: 10,
            cost_usd: None,
        };
        checkpoint.append(
            PHASE_LIVE_BUDGET_ADMITTED,
            Some("worker"),
            &LiveBudgetCheckpoint {
                binding,
                budget: ledger.report()?,
                reservation,
            },
        )?;
        drop(checkpoint);
        drop(writer);
        drop(ledger);
        install_checkpoint_failure(run_id.as_str(), "after:live_budget_recovered");
        assert!(resume_supervisor_run(&repo, run_id.clone()).is_err());
        let resumed = resume_supervisor_run(&repo, run_id.clone())?;
        let budget = resumed.run_budget.context("missing recovered snapshot")?;
        assert!(!resumed.resumed);
        assert_eq!(budget.charges.len(), 1);
        assert_eq!(budget.charges[0].tokens, 10);
        assert_eq!(budget.reserved.tokens, 0);
        assert_eq!(budget.active_reservations, 0);
        assert!(!budget.usage_complete);
        assert_eq!(
            collect_supervisor_run(&repo, run_id.clone())?.run_budget,
            Some(budget)
        );
        let (checkpoint, _) = open_supervisor_checkpoint(&repo, &run_id)?;
        assert_eq!(
            checkpoint
                .journal
                .records()
                .iter()
                .filter(|record| record.phase == PHASE_LIVE_BUDGET_RECOVERED)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn review714_admission_write_failure_leaves_readable_checkpoint() -> Result<()> {
        let Fixture {
            _temp,
            repo,
            run_id,
            plan,
            writer,
            mut checkpoint,
            ledger,
            id,
            binding,
        } = prepare("admission-write")?;
        install_checkpoint_failure(run_id.as_str(), PHASE_LIVE_BUDGET_ADMITTED);
        assert!(checkpoint
            .append(PHASE_LIVE_BUDGET_ADMITTED, Some("worker"), &binding)
            .is_err());
        ledger.release(id)?;
        checkpoint.assignment_completed(
            &plan.assignments[0],
            0,
            Some(writer.resume_binding()?),
            ledger.report()?,
            None,
            vec![],
        )?;
        checkpoint.scheduler_closed(writer.resume_binding()?, ledger.report()?)?;
        drop(checkpoint);
        drop(writer);
        let opened = open_supervisor_checkpoint(&repo, &run_id);
        if let Err(error) = opened {
            panic!("refused-before-release dispatch corrupted checkpoint: {error:#}");
        }
        Ok(())
    }

    #[test]
    fn nested_worker_durable_budget_binding_admission_abort_before_and_after_append() -> Result<()>
    {
        for after in [false, true] {
            let mut fixture = prepare(if after { "abort-after" } else { "abort-before" })?;
            let reservation = DispatchBudgetReservation {
                ledger: &fixture.ledger,
                reservation: BudgetReservation {
                    id: fixture.id,
                    role: AgentRole::Worker,
                    tokens: 10,
                    cost_usd: None,
                },
                pricing: None,
                pricing_model: None,
                state: DispatchBudgetReservationState::Reserved(SupervisorRuntime::Codex),
            };
            install_checkpoint_failure(
                fixture.run_id.as_str(),
                if after {
                    "after:live_budget_admitted"
                } else {
                    PHASE_LIVE_BUDGET_ADMITTED
                },
            );
            let mut journal = None;
            let mut autonomy_kpis = AutonomyKpiCollector::default();
            let artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut fixture.writer,
                journal: &mut journal,
                autonomy_kpis: &mut autonomy_kpis,
                checkpoint: Some(&mut fixture.checkpoint),
            });
            assert!(persist_live_budget_binding(&artifacts, &reservation, false).is_err());
            artifacts
                .into_inner()
                .map_err(|_| anyhow!("test artifacts poisoned"))?;
            drop(reservation);
            let budget = fixture.ledger.report()?;
            assert_eq!(budget.charges.len(), 0);
            assert_eq!(budget.dispatch_bindings.len(), usize::from(after));
            fixture.checkpoint.assignment_completed(
                &fixture.plan.assignments[0],
                0,
                Some(fixture.writer.resume_binding()?),
                budget.clone(),
                None,
                vec![],
            )?;
            fixture
                .checkpoint
                .scheduler_closed(fixture.writer.resume_binding()?, budget)?;
            drop(fixture.checkpoint);
            drop(fixture.writer);
            let (_, snapshot) = open_supervisor_checkpoint(&fixture.repo, &fixture.run_id)?;
            assert_eq!(
                snapshot.run_budget.dispatch_bindings.len(),
                usize::from(after)
            );
            if after {
                assert_eq!(
                    snapshot.run_budget.dispatch_bindings[0].state,
                    crate::supervise_budget::BudgetDispatchState::NotStarted
                );
            }
        }
        Ok(())
    }
}
