use super::*;
use crate::{
    artifacts::{
        repository_auth_writer, validate_repository_authenticated_state, ArtifactRunResumeBinding,
    },
    state_journal::{JournalRecord, StateJournal},
};

const SUPERVISE_CHECKPOINT_VERSION: u32 = 2;
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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "unsupported supervise checkpoint version {observed} (supported version: {supported}); start a new run or reconcile the retained checkpoint with a supported migration tool"
)]
pub(super) struct UnsupportedCheckpointVersion {
    pub(super) observed: u32,
    pub(super) supported: u32,
}

pub(super) fn unsupported_checkpoint_version_denial(
    error: &anyhow::Error,
) -> Option<ResumeCheckpointDenial> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<UnsupportedCheckpointVersion>())
        .map(
            |unsupported| ResumeCheckpointDenial::UnsupportedCheckpointVersion {
                observed: unsupported.observed,
                supported: unsupported.supported,
            },
        )
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_node: Option<String>,
    dispatch_identity: EffectiveSupervisorDispatchIdentity,
    primary_base: String,
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
    primary_base: Oid,
    normalized_plan_sha256: String,
    parent_node: Option<String>,
    dispatch_identity: EffectiveSupervisorDispatchIdentity,
    worktrees: BTreeMap<String, CheckpointWorktreeBinding>,
    claims: BTreeMap<u64, (String, Vec<PathBuf>)>,
}

impl SupervisorCheckpointSnapshot {
    pub(super) fn primary_base(&self) -> &Oid {
        &self.primary_base
    }

    pub(super) fn normalized_plan_sha256(&self) -> &str {
        &self.normalized_plan_sha256
    }

    pub(super) fn parent_node(&self) -> Option<&str> {
        self.parent_node.as_deref()
    }

    pub(super) fn dispatch_identity(&self) -> &EffectiveSupervisorDispatchIdentity {
        &self.dispatch_identity
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
    assignment_states: BTreeMap<String, AssignmentResumeState>,
}

pub(super) struct SupervisorCheckpointPreparation<'a> {
    run_id: &'a RunId,
    primary_base: &'a Oid,
    normalized_plan_sha256: String,
    max_concurrent_children: usize,
    plan: &'a SupervisorPlan,
    artifact: ArtifactRunResumeBinding,
    budget: RunBudgetReport,
    parent_node: Option<String>,
    dispatch_identity: EffectiveSupervisorDispatchIdentity,
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
            normalized_plan_sha256,
            max_concurrent_children,
            plan,
            artifact,
            budget,
            parent_node: None,
            dispatch_identity: EffectiveSupervisorDispatchIdentity::Root,
        }
    }

    pub(super) fn with_parent_node(mut self, parent_node: Option<String>) -> Self {
        self.parent_node = parent_node;
        self
    }

    pub(super) fn with_dispatch_identity(
        mut self,
        dispatch_identity: EffectiveSupervisorDispatchIdentity,
    ) -> Self {
        self.dispatch_identity = dispatch_identity;
        self
    }
}

impl SupervisorCheckpointWriter {
    pub(super) fn create_authorized(
        repo: &Path,
        preparation: SupervisorCheckpointPreparation<'_>,
        permit: &crate::mutation_taxonomy::SupervisorOperationPermit<'_>,
    ) -> Result<Self> {
        permit.verify(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
        Self::create_with_version(repo, preparation, SUPERVISE_CHECKPOINT_VERSION)
    }

    #[cfg(test)]
    pub(super) fn create(
        repo: &Path,
        preparation: SupervisorCheckpointPreparation<'_>,
    ) -> Result<Self> {
        Self::create_with_version(repo, preparation, SUPERVISE_CHECKPOINT_VERSION)
    }

    fn create_with_version(
        repo: &Path,
        preparation: SupervisorCheckpointPreparation<'_>,
        version: u32,
    ) -> Result<Self> {
        let SupervisorCheckpointPreparation {
            run_id,
            primary_base,
            normalized_plan_sha256,
            max_concurrent_children,
            plan,
            artifact,
            budget,
            parent_node,
            dispatch_identity,
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
                version,
                run_id: run_id.as_str().to_string(),
                parent_node,
                dispatch_identity,
                primary_base: primary_base.to_string(),
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

    #[cfg(test)]
    pub(super) fn create_unsupported_v1_for_test(
        repo: &Path,
        preparation: SupervisorCheckpointPreparation<'_>,
    ) -> Result<Self> {
        Self::create_with_version(repo, preparation, 1)
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
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorCheckpointJournalLifecycle)?
        .verify(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
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
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorCheckpointJournalLifecycle)?
        .verify(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
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
    guard
        .mutation_session
        .permit(MutationOperation::SupervisorCheckpointJournalLifecycle)?
        .verify(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
    let Some(checkpoint) = guard.checkpoint.as_deref_mut() else {
        return Ok(());
    };
    if completed {
        checkpoint.dispatch_completed(auditor, subject, attempt)
    } else {
        checkpoint.dispatch_started(auditor, subject, attempt)
    }
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

fn open_supervisor_checkpoint_mutating(
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
        },
        snapshot,
    ))
}

#[cfg(test)]
pub(super) fn open_supervisor_checkpoint(
    repo: &Path,
    run_id: &RunId,
) -> Result<(SupervisorCheckpointWriter, SupervisorCheckpointSnapshot)> {
    open_supervisor_checkpoint_mutating(repo, run_id)
}

pub(super) fn open_supervisor_checkpoint_authorized(
    repo: &Path,
    run_id: &RunId,
    session: &crate::mutation_taxonomy::ResumeRecoveryMutationSession,
) -> Result<(SupervisorCheckpointWriter, SupervisorCheckpointSnapshot)> {
    session
        .permit(MutationOperation::SupervisorCheckpointJournalLifecycle)?
        .verify(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
    open_supervisor_checkpoint_mutating(repo, run_id)
}

/// Authenticates a stable checkpoint without invoking recovery or acquiring a
/// mutation-capable journal. Status and evidence callers must use this path.
pub(super) fn read_supervisor_checkpoint(
    repo: &Path,
    run_id: &RunId,
) -> Result<SupervisorCheckpointSnapshot> {
    let authenticator = repository_authenticator_key_only(repo)?;
    validate_repository_authenticated_state(repo, &authenticator)?;
    let journal = StateJournal::open_instance_read_only(authenticator, run_id.as_str())?;
    analyze_checkpoint_records(journal.records(), run_id)
}

pub(super) fn authenticated_child_dispatch_started(repo: &Path, run_id: &RunId) -> Result<bool> {
    let authenticator = repository_authenticator_key_only(repo)?;
    validate_repository_authenticated_state(repo, &authenticator)?;
    let journal = StateJournal::open_instance_read_only(authenticator, run_id.as_str())?;
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
    let mut dispatches = BTreeSet::new();
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
    Ok(SupervisorCheckpointSnapshot {
        completed_assignments,
        pending_assignments,
        uncertain_assignments: uncertain_assignments.into_iter().collect(),
        final_report,
        finalization_started,
        finalized,
        primary_base,
        normalized_plan_sha256: prepared.normalized_plan_sha256,
        parent_node: prepared.parent_node,
        dispatch_identity: prepared.dispatch_identity,
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
        return Err(UnsupportedCheckpointVersion {
            observed: version,
            supported: SUPERVISE_CHECKPOINT_VERSION,
        }
        .into());
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
