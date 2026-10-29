use std::path::Path;

#[cfg(test)]
use super::accepted_task_cost::observed_cost_per_accepted_task_microunits;
use super::accepted_task_cost::{
    attempt_cost_record, rollup_cost_per_accepted_task, rollup_selection_cost_cohorts,
    AttemptCostRecord,
};
use super::environment_observation::AccountObserveOutcomeKind;
use super::*;
use crate::selection::OutcomeResult;

#[cfg(target_os = "linux")]
use coding_agent_manager_lib::account_authority::{
    authority_id_for, AccountObserveRequest, ObserveCategory, StoredAccountRegistry,
};
#[cfg(target_os = "linux")]
use coding_agent_manager_lib::paths::{project_dirs, stored_accounts_path};
#[cfg(target_os = "linux")]
use coding_agent_manager_lib::providers::observe_selected_account;

mod authored_check_admission;
mod preclaim;
pub(super) use preclaim::assignment_requires_file_change;
#[cfg(test)]
use preclaim::evaluate_preclaim_viability;
use preclaim::{
    parked_preclaim_outcome, persist_preclaim_decision, preclaim_assignment, PreclaimDecision,
    PreclaimRunEvidence,
};

/// Admission policy for concurrently runnable supervisor children.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SupervisorConcurrencyPolicy {
    /// Use the conservative network-bound child default before quota and host-resource inputs
    /// are composed by admission preflight.
    ///
    /// The issue #24 swarm-health circuit breaker remains the admission safety backstop: higher
    /// default fan-out never bypasses its pre-dispatch check or active-child drain behavior.
    #[default]
    Auto,
    /// Run at most this explicit positive number of children.
    Fixed(NonZeroUsize),
}

impl SupervisorConcurrencyPolicy {
    pub(crate) const fn resolve(self, capacity: HostProcessCapacity) -> usize {
        match self {
            Self::Auto => capacity.supervisor_children(),
            Self::Fixed(limit) => limit.get(),
        }
    }

    pub(crate) const fn configured_limit(self) -> Option<usize> {
        match self {
            Self::Auto => None,
            Self::Fixed(limit) => Some(limit.get()),
        }
    }
}

impl fmt::Display for SupervisorConcurrencyPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => formatter.write_str("auto"),
            Self::Fixed(limit) => write!(formatter, "{limit}"),
        }
    }
}

impl FromStr for SupervisorConcurrencyPolicy {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if value == "auto" {
            return Ok(Self::Auto);
        }
        let parsed = value
            .parse::<usize>()
            .map_err(|_| "--max-concurrent-children must be at least 1 or 'auto'".to_string())?;
        NonZeroUsize::new(parsed)
            .map(Self::Fixed)
            .ok_or_else(|| "--max-concurrent-children must be at least 1 or 'auto'".to_string())
    }
}

#[cfg(test)]
type BeforeSupervisorFinalReportPersistHook = Box<dyn FnMut(&mut SupervisorFinalReport)>;

#[cfg(test)]
thread_local! {
    static BEFORE_SUPERVISOR_FINAL_REPORT_PERSIST_HOOK: std::cell::RefCell<Option<BeforeSupervisorFinalReportPersistHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
thread_local! {
    static SUPERVISOR_EVIDENCE_PROVIDER: std::cell::RefCell<Option<SupervisorEvidenceProvider>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct SupervisorEvidenceProvider {
    preclaim_run_evidence: Option<PreclaimRunEvidence>,
    primary_worktree_snapshots: std::collections::VecDeque<PrimaryWorktreeSnapshot>,
}

#[cfg(test)]
static SUPERVISOR_EVIDENCE_PROVIDER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
struct SupervisorEvidenceProviderGuard {
    _serialized: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for SupervisorEvidenceProviderGuard {
    fn drop(&mut self) {
        let remaining = SUPERVISOR_EVIDENCE_PROVIDER.with(|slot| slot.borrow_mut().take());
        if !std::thread::panicking() {
            let remaining = remaining.expect("supervisor evidence provider disappeared");
            assert!(
                remaining.preclaim_run_evidence.is_none()
                    && remaining.primary_worktree_snapshots.is_empty(),
                "injected supervisor evidence was not consumed: preclaim={}, primary_snapshots={}",
                usize::from(remaining.preclaim_run_evidence.is_some()),
                remaining.primary_worktree_snapshots.len(),
            );
        }
    }
}

#[cfg(test)]
fn set_supervisor_evidence_provider_for_test(
    preclaim_run_evidence: PreclaimRunEvidence,
    primary_worktree_snapshots: [PrimaryWorktreeSnapshot; 2],
) -> SupervisorEvidenceProviderGuard {
    assert!(
        SUPERVISOR_EVIDENCE_PROVIDER.with(|slot| slot.borrow().is_none()),
        "supervisor evidence provider is already active on this test thread"
    );
    let serialized = SUPERVISOR_EVIDENCE_PROVIDER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    SUPERVISOR_EVIDENCE_PROVIDER.with(|slot| {
        let mut slot = slot.borrow_mut();
        debug_assert!(slot.is_none());
        *slot = Some(SupervisorEvidenceProvider {
            preclaim_run_evidence: Some(preclaim_run_evidence),
            primary_worktree_snapshots: primary_worktree_snapshots.into_iter().collect(),
        });
    });
    SupervisorEvidenceProviderGuard {
        _serialized: serialized,
    }
}

#[cfg(test)]
fn take_supervisor_preclaim_run_evidence() -> Option<PreclaimRunEvidence> {
    SUPERVISOR_EVIDENCE_PROVIDER.with(|slot| {
        slot.borrow_mut().as_mut().map(|provider| {
            provider
                .preclaim_run_evidence
                .take()
                .expect("injected supervisor pre-claim evidence was already consumed")
        })
    })
}

#[cfg(test)]
fn take_supervisor_primary_worktree_snapshot() -> Option<PrimaryWorktreeSnapshot> {
    SUPERVISOR_EVIDENCE_PROVIDER.with(|slot| {
        slot.borrow_mut().as_mut().map(|provider| {
            provider
                .primary_worktree_snapshots
                .pop_front()
                .expect("injected supervisor primary-worktree snapshots were exhausted")
        })
    })
}

#[cfg(test)]
pub(crate) fn set_before_supervisor_final_report_persist_hook(
    hook: impl FnMut(&mut SupervisorFinalReport) + 'static,
) {
    BEFORE_SUPERVISOR_FINAL_REPORT_PERSIST_HOOK
        .with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_supervisor_final_report_persist_hook(report: &mut SupervisorFinalReport) {
    BEFORE_SUPERVISOR_FINAL_REPORT_PERSIST_HOOK.with(|slot| {
        if let Some(mut hook) = slot.borrow_mut().take() {
            hook(report);
        }
    });
}

#[cfg(test)]
thread_local! {
    static FORCE_DEGRADED_CHECKPOINT_FINALIZATION: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_force_degraded_checkpoint_finalization() {
    FORCE_DEGRADED_CHECKPOINT_FINALIZATION.with(|flag| flag.set(true));
}

#[cfg(test)]
fn take_force_degraded_checkpoint_finalization() -> bool {
    FORCE_DEGRADED_CHECKPOINT_FINALIZATION.with(|flag| flag.replace(false))
}

#[cfg(test)]
thread_local! {
    static LIVE_GRANT_ADMISSION_OBSERVER: std::cell::RefCell<Option<std::sync::mpsc::Sender<usize>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_live_grant_admission_observer(sender: std::sync::mpsc::Sender<usize>) {
    LIVE_GRANT_ADMISSION_OBSERVER.with(|observer| *observer.borrow_mut() = Some(sender));
}

#[cfg(test)]
thread_local! {
    static CONCURRENT_RELEASE_ERROR_OBSERVER: std::cell::RefCell<Option<std::sync::mpsc::Sender<()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_concurrent_release_error_observer(sender: std::sync::mpsc::Sender<()>) {
    CONCURRENT_RELEASE_ERROR_OBSERVER.with(|observer| *observer.borrow_mut() = Some(sender));
}

#[cfg(test)]
fn admission_commit_abort_injections(
) -> &'static std::sync::Mutex<std::collections::BTreeMap<String, usize>> {
    static INJECTIONS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, usize>>,
    > = std::sync::OnceLock::new();
    INJECTIONS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

#[cfg(test)]
pub(crate) fn set_abort_admission_commit_on_spawn(run_id: &RunId, remaining: usize) {
    let mut injections = admission_commit_abort_injections()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if remaining == 0 {
        injections.remove(run_id.as_str());
    } else {
        injections.insert(run_id.as_str().to_string(), remaining);
    }
}

#[cfg(test)]
fn take_abort_admission_commit_on_spawn(run_id: &RunId) -> bool {
    let mut injections = admission_commit_abort_injections()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let should_abort = match injections.get_mut(run_id.as_str()) {
        Some(remaining) => {
            *remaining = remaining.saturating_sub(1);
            *remaining == 0
        }
        None => false,
    };
    if should_abort {
        injections.remove(run_id.as_str());
    }
    should_abort
}

fn assignments_overlap(left: &OrchestratorAssignment, right: &OrchestratorAssignment) -> bool {
    left.assigned_paths.iter().any(|left_path| {
        right
            .assigned_paths
            .iter()
            .any(|right_path| paths_overlap(left_path, right_path))
    })
}

fn plan_has_overlapping_assignments(plan: &SupervisorPlan) -> bool {
    plan.assignments
        .iter()
        .enumerate()
        .any(|(left_index, left)| {
            plan.assignments
                .iter()
                .skip(left_index.saturating_add(1))
                .any(|right| assignments_overlap(left, right))
        })
}

fn validated_scheduler_assignment_schedule(
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
) -> Result<Vec<AssignmentScheduleEntry>> {
    let flattened_assignments = plan
        .assignments
        .iter()
        .enumerate()
        .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
            assignment_id: assignment.id.clone(),
            parent_assignment_id: None,
            depth: MIN_SUPERVISOR_DEPTH,
            flattened_index,
        })
        .collect::<Vec<_>>();
    let supplied = if metadata.assignment_schedule.is_empty() {
        flattened_assignments.clone()
    } else {
        metadata.assignment_schedule.clone()
    };
    validate_assignment_schedule(supplied, &flattened_assignments, plan.max_depth)
        .context("supervisor scheduler rejected the validated assignment schedule")
}

fn has_multiple_independent_assignment_scopes(
    schedule: &[AssignmentScheduleEntry],
    plan_metadata: &SupervisorPlanMetadata,
) -> bool {
    let schedule_has_independent_scopes = (0..schedule.len()).any(|left_index| {
        (left_index.saturating_add(1)..schedule.len()).any(|right_index| {
            !schedule_entries_share_strict_lineage(schedule, left_index, right_index)
        })
    });
    schedule_has_independent_scopes || plan_metadata.spec_fragment_ids.len() > 1
}

pub(super) fn release_assignment_resources_after_completion(
    plan: &SupervisorPlan,
    schedule: &[AssignmentScheduleEntry],
    max_concurrent_children: usize,
) -> bool {
    max_concurrent_children > 1
        || plan_has_overlapping_assignments(plan)
        || schedule
            .iter()
            .any(|entry| entry.parent_assignment_id.is_some())
}

pub(super) fn semantic_preview_intents_for_assignment(
    assignment_index: usize,
    schedule: &[AssignmentScheduleEntry],
    planned: &[(usize, SemanticIntent)],
) -> Vec<SemanticIntent> {
    planned
        .iter()
        .filter(|(planned_index, _)| {
            !schedule_entries_share_strict_lineage(schedule, *planned_index, assignment_index)
        })
        .map(|(_, intent)| intent.clone())
        .collect()
}

fn prepare_semantic_warn_assignments(
    store: &SemanticIntentStore,
    plan: &SupervisorPlan,
    schedule: &[AssignmentScheduleEntry],
) -> Result<Vec<PreparedSemanticAssignment>> {
    let mut prepared = plan
        .assignments
        .iter()
        .map(|_| PreparedSemanticAssignment::default())
        .collect::<Vec<_>>();
    if plan.semantic_coordination != SemanticCoordinationMode::Warn {
        return Ok(prepared);
    }

    let mut planned_preview_intents = Vec::<(usize, SemanticIntent)>::new();
    for (index, assignment) in plan.assignments.iter().enumerate() {
        let additional_active =
            semantic_preview_intents_for_assignment(index, schedule, &planned_preview_intents);
        let report = match store.preview_with_additional_active(
            semantic_assignment_request(assignment),
            &additional_active,
        ) {
            Ok(report) => report,
            Err(error) if semantic_resolution_error(&error) => {
                prepared[index]
                    .findings
                    .push(semantic_resolution_finding(assignment, &error));
                prepared[index].assignment_failed = true;
                continue;
            }
            Err(error) => return Err(error),
        };
        if report.has_blocking_conflicts || report.has_advisory_conflicts {
            let conflict_count = report
                .blocking_conflict_count
                .saturating_add(report.advisory_conflict_count);
            prepared[index].findings.push(Finding {
                severity: FindingSeverity::Warning,
                message: format!(
                    "semantic coordination warn-mode preview for assignment '{}' found {} conflict(s)",
                    assignment.id,
                    conflict_count
                ),
                paths: assignment.assigned_paths.clone(),
            });
            prepared[index]
                .health_signals
                .push(SwarmHealthSignal::SemanticConflictWarned {
                    conflicts: conflict_count,
                });
        }
        prepared[index].token = Some(report.intent.token.get());
        planned_preview_intents.push((index, report.intent));
    }
    Ok(prepared)
}

struct AssignmentSchedulerContext<'context, 'writer> {
    /// Selector-resolved execution plan used for every dispatched duty.
    plan: &'context SupervisorPlan,
    /// Caller-authenticated plan retained for generated follow-up intent.
    requested_plan: &'context SupervisorPlan,
    budget_config: &'context SupervisorBudgetConfig,
    consultant: &'context SupervisorConsultantPlan,
    assignment_metadata: &'context AssignmentMetadata,
    evidence_only_reaudit: Option<&'context EvidenceOnlyReauditSource>,
    options: &'context SupervisorRunOptions,
    repo: &'context Path,
    run_dir: &'context Path,
    dirs: &'context RunDirs,
    execution_runtime: SupervisorExecutionRuntime,
    execution_target: Option<&'context SupervisorExecutionTarget>,
    worktree_creation: SupervisorWorktreeCreation<'context>,
    manager: &'context WorktreeManager,
    existing_ids: &'context BTreeSet<String>,
    sync_store: &'context SyncStore,
    semantic_store: &'context SemanticIntentStore,
    prepared_semantic_assignments: &'context [PreparedSemanticAssignment],
    assignment_schedule: &'context [AssignmentScheduleEntry],
    field_guide: &'context SupervisorFieldGuidePrompt,
    artifacts: &'context Mutex<SharedSupervisorArtifacts<'writer>>,
    budget_ledger: &'context RunBudgetLedger,
    runtime_model_catalog: &'context RuntimeModelCatalog,
    external_runner: &'context CancellableExternalRunner<'context>,
    release_per_assignment: bool,
}

struct SchedulerProgress {
    indexed_outcomes: Vec<Option<AssignmentExecutionOutcome>>,
    prepared_preclaim_decisions: Option<Vec<PreclaimDecision>>,
    prepared_preclaim_evidence: Option<PreclaimRunEvidence>,
    health_breaker: SwarmHealthCircuitBreaker,
    budget_prevented_dispatch: bool,
    budget_denied_assignment_indices: BTreeSet<usize>,
    circuit_breaker_trip: Option<CircuitBreakerTrip>,
    concurrency: SchedulerConcurrencyTracker,
    budget_degradation: BudgetDegradationController,
}

impl SchedulerProgress {
    #[cfg(test)]
    fn new(assignment_count: usize, max_concurrent_children: usize) -> Self {
        Self::new_with_selection_state(
            assignment_count,
            max_concurrent_children,
            None,
            SupervisorRuntime::Fake,
        )
        .expect("scheduler progress without automatic selection is valid")
    }

    fn new_with_selection_state(
        assignment_count: usize,
        max_concurrent_children: usize,
        automatic_selection_state: Option<SupervisorAutomaticSelectionState>,
        runtime: SupervisorRuntime,
    ) -> Result<Self> {
        Ok(Self {
            indexed_outcomes: (0..assignment_count).map(|_| None).collect(),
            prepared_preclaim_decisions: None,
            prepared_preclaim_evidence: None,
            health_breaker: SwarmHealthCircuitBreaker::default(),
            budget_prevented_dispatch: false,
            budget_denied_assignment_indices: BTreeSet::new(),
            circuit_breaker_trip: None,
            concurrency: SchedulerConcurrencyTracker::new(),
            budget_degradation: BudgetDegradationController::new_with_selection_state(
                max_concurrent_children,
                automatic_selection_state,
                runtime,
            )?,
        })
    }

    fn install_preclaim_decisions(&mut self, decisions: Vec<PreclaimDecision>) -> Result<()> {
        if decisions.len() != self.indexed_outcomes.len() {
            bail!(
                "prepared pre-claim decision count {} does not match assignment count {}",
                decisions.len(),
                self.indexed_outcomes.len()
            );
        }
        self.prepared_preclaim_decisions = Some(decisions);
        Ok(())
    }

    fn prepared_preclaim_decision(&self, index: usize) -> Result<Option<PreclaimDecision>> {
        let Some(decisions) = self.prepared_preclaim_decisions.as_ref() else {
            return Ok(None);
        };
        decisions
            .get(index)
            .cloned()
            .map(Some)
            .with_context(|| format!("missing prepared pre-claim decision at index {index}"))
    }

    fn commit_completed_selection_prefix(
        &mut self,
        runtime: SupervisorRuntime,
        run_dir: &Path,
    ) -> Result<()> {
        self.budget_degradation.commit_completed_selection_prefix(
            &self.indexed_outcomes,
            runtime,
            run_dir,
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct AssignmentBudgetPolicy {
    model_overrides: BTreeMap<AgentRole, RoleModelSelection>,
    worker_effort_degradation_steps: usize,
    assignment_reasoning_effort: Option<ReasoningEffort>,
    selector_state: Option<SupervisorAutomaticSelectionState>,
    selector_overrides: BTreeMap<AgentRole, RoleModelSelection>,
    selector_runtime_overrides: BTreeMap<AgentRole, SupervisorRuntime>,
    pub(super) selector_decisions: Vec<SupervisorSelectionEvent>,
    pub(super) initial_selector_decisions: Vec<SupervisorSelectionEvent>,
    this_run_run_dir: Option<PathBuf>,
}

impl AssignmentBudgetPolicy {
    pub(super) fn apply(&self, plan: &SupervisorPlan) -> SupervisorPlan {
        let mut effective = plan.clone();
        for (role, selection) in &self.model_overrides {
            effective.role_models.insert(*role, selection.clone());
        }
        let mut roles = vec![
            AgentRole::ChildOrchestrator,
            AgentRole::Worker,
            AgentRole::GateClassifier,
            AgentRole::Auditor,
        ];
        if plan
            .assignments
            .iter()
            .any(|assignment| assignment.role == AgentRole::Researcher)
        {
            roles.push(AgentRole::Researcher);
        }
        for role in roles {
            let mut selection = effective_role_model_selection(&effective, role);
            let resolved = resolve_reasoning_effort(
                role,
                self.assignment_reasoning_effort,
                configured_role_model_selection(plan, role)
                    .reasoning_effort
                    .as_deref(),
                if role == AgentRole::Worker {
                    self.worker_effort_degradation_steps
                } else {
                    0
                },
            );
            selection.reasoning_effort = Some(resolved.resolved);
            effective.role_models.insert(role, selection);
        }
        let mechanical_worker_binding_active =
            self.model_overrides.contains_key(&AgentRole::Worker)
                || self.worker_effort_degradation_steps > 0;
        let initial_auditor = effective_role_model_selection(plan, AgentRole::Auditor);
        for (role, selection) in &self.selector_overrides {
            if *role != AgentRole::Worker || !mechanical_worker_binding_active {
                effective.role_models.insert(*role, selection.clone());
            }
        }
        if let Some(auditor) = self.selector_overrides.get(&AgentRole::Auditor) {
            for lens in &mut effective.review_lenses {
                if let ReviewLensBackendConfig::Model {
                    model,
                    reasoning_effort,
                    ..
                } = &mut lens.backend
                {
                    if initial_auditor.model.as_deref() == Some(model.as_str())
                        && initial_auditor.reasoning_effort.as_deref()
                            == reasoning_effort.as_deref()
                    {
                        if let (Some(selected_model), Some(selected_effort)) =
                            (&auditor.model, &auditor.reasoning_effort)
                        {
                            *model = selected_model.clone();
                            *reasoning_effort = Some(selected_effort.clone());
                        }
                    }
                }
            }
        }
        // Review triples have already been selector-authorized. Assignment effort
        // overrides and role floors cannot rewrite a lens after that decision.
        effective
    }

    pub(super) fn reselect(
        &mut self,
        runtime: SupervisorRuntime,
        catalog: &RuntimeModelCatalog,
        request: SelectorReselectionRequest<'_>,
    ) -> Result<Vec<SupervisorSelectionEvent>> {
        let SelectorReselectionRequest {
            roles,
            assignment_id,
            attempt,
            primary_cause,
            retry_count,
            budget_signal,
            environment_rejections,
        } = request;
        let Some(state) = self.selector_state.as_mut() else {
            return Ok(Vec::new());
        };
        if let Some(run_dir) = self.this_run_run_dir.as_deref() {
            let load = load_this_run_outcome_records(run_dir)?;
            state.set_this_run_outcomes(load.records, load.exclusions);
        }
        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            state,
            runtime,
            catalog,
            roles,
            retry_count,
            budget_signal,
            environment_rejections,
        )?;
        self.selector_overrides.extend(reselection.overrides);
        self.selector_runtime_overrides
            .extend(reselection.runtime_overrides);
        Ok(reselection
            .decisions
            .into_iter()
            .map(|(role, provenance)| SupervisorSelectionEvent {
                assignment_id: assignment_id.map(str::to_string),
                attempt,
                role,
                primary_cause,
                provenance,
            })
            .collect())
    }

    fn commit_completed_selection_events(
        &mut self,
        runtime: SupervisorRuntime,
        events: &[SupervisorSelectionEvent],
    ) -> Result<()> {
        let Some(state) = self.selector_state.as_mut() else {
            if events.is_empty() {
                return Ok(());
            }
            bail!("completed automatic-selection events have no manager replay state");
        };
        let bindings = state.commit_completed_selection_events(runtime, events)?;
        self.selector_overrides.extend(bindings.model_overrides);
        self.selector_runtime_overrides
            .extend(bindings.runtime_overrides);
        Ok(())
    }

    pub(super) fn selected_runtime_for(&self, role: AgentRole) -> Option<SupervisorRuntime> {
        self.selector_runtime_overrides.get(&role).copied()
    }

    pub(super) fn account_observe_environment_decision(
        &self,
    ) -> Option<(AccountObserveOutcomeKind, Option<u64>)> {
        self.selector_state
            .as_ref()
            .and_then(SupervisorAutomaticSelectionState::account_observe_environment_decision)
    }

    pub(super) fn refresh_observed_accepted_task_cost(
        &mut self,
        run_dir: &Path,
        reports: &[OrchestratorReviewReport],
    ) {
        self.this_run_run_dir = Some(run_dir.to_path_buf());
        let cohorts =
            this_run_accepted_task_cost_cohorts(&load_this_run_attempt_cost_rows(run_dir), reports);
        if let Some(state) = self.selector_state.as_mut() {
            state.set_observed_accepted_task_cost(
                cohorts
                    .map(|cohorts| cohorts.observations())
                    .unwrap_or_default(),
            );
        }
    }

    #[cfg(test)]
    pub(super) fn set_selector_binding_for_test(
        &mut self,
        role: AgentRole,
        runtime: SupervisorRuntime,
        selection: RoleModelSelection,
    ) {
        self.selector_overrides.insert(role, selection);
        self.selector_runtime_overrides.insert(role, runtime);
    }

    #[cfg(test)]
    pub(super) fn set_assignment_reasoning_effort_for_test(
        &mut self,
        reasoning_effort: Option<ReasoningEffort>,
    ) {
        self.assignment_reasoning_effort = reasoning_effort;
    }

    #[cfg(test)]
    pub(super) fn set_selected_runtime_for_test(
        &mut self,
        role: AgentRole,
        runtime: SupervisorRuntime,
    ) {
        self.selector_runtime_overrides.insert(role, runtime);
    }
}

pub(super) struct SelectorReselectionRequest<'a> {
    pub(super) roles: &'a [AgentRole],
    pub(super) assignment_id: Option<&'a str>,
    pub(super) attempt: usize,
    pub(super) primary_cause: SupervisorSelectionEventCause,
    pub(super) retry_count: u32,
    pub(super) budget_signal: crate::selection::BudgetSignal,
    pub(super) environment_rejections: &'a [TypedSelectorEnvironmentRejection],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum BudgetDegradationRung {
    #[default]
    ModelTier,
    Effort,
    FanOut,
    Exhausted,
}

#[derive(Debug, Clone)]
struct BudgetDegradationController {
    rung: BudgetDegradationRung,
    policy: AssignmentBudgetPolicy,
    worker_binding_trigger: Option<BudgetDegradationTrigger>,
    effective_fan_out: usize,
    records: Vec<BudgetDegradationRecord>,
    assignment_effort_bindings: Vec<AssignmentEffortBinding>,
    last_new_dispatch_allowed: bool,
    next_selection_commit_index: usize,
}

pub(super) struct AssignmentBudgetPolicyRequest<'a> {
    pub(super) assignment: &'a OrchestratorAssignment,
    pub(super) requested_reasoning_effort: Option<ReasoningEffort>,
    pub(super) report: &'a RunBudgetReport,
    pub(super) plan: &'a SupervisorPlan,
    pub(super) requested_plan: &'a SupervisorPlan,
    pub(super) assignment_metadata: &'a AssignmentMetadata,
    pub(super) catalog: &'a RuntimeModelCatalog,
    pub(super) runtime: SupervisorRuntime,
}

impl BudgetDegradationController {
    #[cfg(test)]
    fn new(max_concurrent_children: usize) -> Self {
        Self::new_with_selection_state(max_concurrent_children, None, SupervisorRuntime::Fake)
            .expect("budget controller without automatic selection is valid")
    }

    fn new_with_selection_state(
        max_concurrent_children: usize,
        automatic_selection_state: Option<SupervisorAutomaticSelectionState>,
        runtime: SupervisorRuntime,
    ) -> Result<Self> {
        let selector_bindings = automatic_selection_state
            .as_ref()
            .map(|state| state.executable_bindings(runtime))
            .transpose()?
            .unwrap_or_default();
        Ok(Self {
            rung: BudgetDegradationRung::ModelTier,
            policy: AssignmentBudgetPolicy {
                selector_state: automatic_selection_state,
                selector_overrides: selector_bindings.model_overrides,
                selector_runtime_overrides: selector_bindings.runtime_overrides,
                ..AssignmentBudgetPolicy::default()
            },
            worker_binding_trigger: None,
            effective_fan_out: max_concurrent_children.max(1),
            records: Vec::new(),
            assignment_effort_bindings: Vec::new(),
            last_new_dispatch_allowed: true,
            next_selection_commit_index: 0,
        })
    }

    fn commit_completed_selection_prefix(
        &mut self,
        indexed_outcomes: &[Option<AssignmentExecutionOutcome>],
        runtime: SupervisorRuntime,
        run_dir: &Path,
    ) -> Result<()> {
        while let Some(Some(outcome)) = indexed_outcomes.get(self.next_selection_commit_index) {
            self.policy
                .commit_completed_selection_events(runtime, &outcome.selection_decisions)
                .with_context(|| {
                    format!(
                        "failed to commit automatic-selection events for schedule index {}",
                        self.next_selection_commit_index
                    )
                })?;
            self.next_selection_commit_index = self
                .next_selection_commit_index
                .checked_add(1)
                .context("automatic-selection schedule commit index overflowed")?;
        }
        let reports = indexed_outcomes
            .iter()
            .take(self.next_selection_commit_index)
            .filter_map(|slot| slot.as_ref().and_then(|outcome| outcome.report.clone()))
            .collect::<Vec<_>>();
        self.policy
            .refresh_observed_accepted_task_cost(run_dir, &reports);
        Ok(())
    }

    fn assignment_policy(
        &mut self,
        request: AssignmentBudgetPolicyRequest<'_>,
    ) -> Result<Option<AssignmentBudgetPolicy>> {
        let assignment = request.assignment;
        let requested_reasoning_effort = request.requested_reasoning_effort;
        let report = request.report;
        let plan = request.plan;
        let assignment_metadata = request.assignment_metadata;
        if !report.new_dispatch_allowed || report.action == BudgetAction::OwnerEscalation {
            self.record_halt(&assignment.id, report);
            return Ok(None);
        }
        let budget_trigger = report.action == BudgetAction::Degrade
            && report.reasons.iter().any(|reason| {
                matches!(
                    reason,
                    BudgetReason::SoftTokenCeilingReached | BudgetReason::SoftCostCeilingReached
                )
            });
        let mechanical_duties = assignment_mechanical_duties(assignment, assignment_metadata);
        let records_before = self.records.len();
        let low_difficulty_trigger = !budget_trigger
            && self.rung == BudgetDegradationRung::ModelTier
            && mechanical_duties.is_some();
        if low_difficulty_trigger || (budget_trigger && mechanical_duties.is_some()) {
            self.advance(
                &request,
                mechanical_duties.as_deref(),
                if budget_trigger {
                    BudgetDegradationTrigger::BudgetPressure
                } else {
                    BudgetDegradationTrigger::LowDifficultyMechanical
                },
            )?;
        }
        let (mut selection_roles, selection_cause, budget_signal) = if budget_trigger {
            (
                vec![
                    AgentRole::ChildOrchestrator,
                    AgentRole::Worker,
                    AgentRole::Auditor,
                ],
                SupervisorSelectionEventCause::BudgetDegrade,
                crate::selection::BudgetSignal::Degrade,
            )
        } else {
            (
                vec![assignment.role],
                SupervisorSelectionEventCause::Initial,
                crate::selection::BudgetSignal::Continue,
            )
        };
        if assignment.role == AgentRole::Researcher
            && !selection_roles.contains(&AgentRole::Researcher)
        {
            selection_roles.push(AgentRole::Researcher);
        }
        let selector_decisions = self.policy.reselect(
            request.runtime,
            request.catalog,
            SelectorReselectionRequest {
                roles: &selection_roles,
                assignment_id: Some(&assignment.id),
                attempt: 0,
                primary_cause: selection_cause,
                retry_count: 0,
                budget_signal,
                environment_rejections: &[],
            },
        )?;
        self.last_new_dispatch_allowed = report.new_dispatch_allowed;
        let mut policy = self.policy.clone();
        if mechanical_duties.is_none() {
            policy.model_overrides.remove(&AgentRole::Worker);
            policy.worker_effort_degradation_steps = 0;
        }
        policy.assignment_reasoning_effort = requested_reasoning_effort;
        policy.selector_decisions = selector_decisions;
        if mechanical_duties.is_some()
            && self.records.len() == records_before
            && (policy.model_overrides.contains_key(&AgentRole::Worker)
                || policy.worker_effort_degradation_steps > 0)
        {
            self.record_inherited_worker_binding(&request, &policy)?;
        }
        self.record_assignment_effort_bindings(
            assignment,
            requested_reasoning_effort,
            plan,
            &policy,
        );
        Ok(Some(policy))
    }

    fn advance(
        &mut self,
        request: &AssignmentBudgetPolicyRequest<'_>,
        mechanical_duties: Option<&[MechanicalTerminalDuty]>,
        trigger: BudgetDegradationTrigger,
    ) -> Result<()> {
        let assignment = request.assignment;
        let requested_reasoning_effort = request.requested_reasoning_effort;
        let report = request.report;
        let plan = request.plan;
        let requested_plan = request.requested_plan;
        let catalog = request.catalog;
        let runtime = request.runtime;
        let mut before_policy = self.policy.clone();
        before_policy.assignment_reasoning_effort = requested_reasoning_effort;
        let before_effective = resolved_budget_role_binding(
            &before_policy,
            plan,
            AgentRole::Worker,
            catalog,
            runtime,
        )?;
        let change = match self.rung {
            BudgetDegradationRung::ModelTier => {
                let duties = mechanical_duties.with_context(|| {
                    format!(
                        "Worker model degradation for assignment '{}' requires every Worker to declare a typed mechanical_duty",
                        assignment.id
                    )
                })?;
                let configured = self
                    .policy
                    .model_overrides
                    .get(&AgentRole::Worker)
                    .cloned()
                    .unwrap_or_else(|| effective_role_model_selection(plan, AgentRole::Worker));
                let resolved = catalog.resolve_role_model_selection(&configured, runtime)?;
                let before = resolved.selection.model.clone().with_context(|| {
                    format!(
                        "Worker model degradation for assignment '{}' requires a distinct resolved model before applying the requested ladder",
                        assignment.id
                    )
                })?;
                let requested_worker =
                    configured_role_model_selection(requested_plan, AgentRole::Worker);
                let candidates = match &requested_worker.unavailable_model_fallback {
                    UnavailableModelFallback::OrderedCatalogChain(chain) => {
                        &chain.budget_degrade_models
                    }
                    _ => {
                        bail!(
                            "Worker model degradation refused for assignment '{}': the requested-plan Worker role has no budget_degrade_models ladder",
                            assignment.id
                        )
                    }
                };
                let Some(before_capability) = trusted_model_capability(&before) else {
                    bail!(
                        "Worker model degradation refused for assignment '{}': the resolved Worker model has no trusted capability class, so ModelTier cannot select a strictly-lower candidate",
                        assignment.id
                    )
                };
                let Some((resolved_candidate_index, after)) = candidates
                    .iter()
                    .enumerate()
                    .find(|(_, model)| {
                        model.as_str() != before
                            && mechanical_worker_model_is_eligible(model, duties)
                            && matches!(
                                (catalog, runtime),
                                (RuntimeModelCatalog::Codex(_), SupervisorRuntime::Codex)
                            )
                            && catalog
                                .availability(Some(model.as_str()), runtime)
                                .is_ok_and(|availability| {
                                    availability == RoleModelAvailability::Available
                                })
                            && trusted_model_capability(model).is_some_and(|target_capability| {
                                target_capability < before_capability
                            })
                    })
                    .map(|(index, model)| (index, model.clone()))
                else {
                    bail!(
                        "Worker model degradation refused for assignment '{}': the requested-plan budget_degrade_models ladder has no distinct runtime-advertised authority-eligible strictly-lower target",
                        assignment.id
                    )
                };
                self.policy.model_overrides.insert(
                    AgentRole::Worker,
                    RoleModelSelection {
                        model: Some(after.clone()),
                        reasoning_effort: resolved.selection.reasoning_effort,
                        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
                    },
                );
                self.rung = BudgetDegradationRung::Effort;
                BudgetDegradationChange::ModelTier {
                    role: AgentRole::Worker,
                    before,
                    after,
                    resolved_candidate_index,
                }
            }
            BudgetDegradationRung::Effort => {
                mechanical_duties.with_context(|| {
                    format!(
                        "Worker effort degradation for assignment '{}' requires every Worker to declare a typed mechanical_duty",
                        assignment.id
                    )
                })?;
                let before = resolve_reasoning_effort(
                    AgentRole::Worker,
                    requested_reasoning_effort,
                    effective_role_model_selection(plan, AgentRole::Worker)
                        .reasoning_effort
                        .as_deref(),
                    self.policy.worker_effort_degradation_steps,
                )
                .resolved;
                self.policy.worker_effort_degradation_steps = self
                    .policy
                    .worker_effort_degradation_steps
                    .saturating_add(1);
                let after = resolve_reasoning_effort(
                    AgentRole::Worker,
                    requested_reasoning_effort,
                    effective_role_model_selection(plan, AgentRole::Worker)
                        .reasoning_effort
                        .as_deref(),
                    self.policy.worker_effort_degradation_steps,
                )
                .resolved;
                self.rung = BudgetDegradationRung::FanOut;
                BudgetDegradationChange::ReasoningEffort {
                    role: AgentRole::Worker,
                    before,
                    after,
                }
            }
            BudgetDegradationRung::FanOut => {
                let before = self.effective_fan_out;
                self.effective_fan_out = (before / 2).max(1);
                self.rung = BudgetDegradationRung::Exhausted;
                if self.effective_fan_out == before {
                    return Ok(());
                }
                BudgetDegradationChange::FanOut {
                    before,
                    after: self.effective_fan_out,
                }
            }
            BudgetDegradationRung::Exhausted => return Ok(()),
        };
        let mut assignment_policy = self.policy.clone();
        assignment_policy.assignment_reasoning_effort = requested_reasoning_effort;
        let effective = assignment_policy.apply(plan);
        let worker_effective = effective_role_model_selection(&effective, AgentRole::Worker);
        let worker_resolved = catalog.resolve_role_model_selection(&worker_effective, runtime)?;
        let after_effective = BudgetDegradationRoleBinding {
            model: worker_resolved.selection.model,
            reasoning_effort: worker_resolved.selection.reasoning_effort,
        };
        let child_effective =
            effective_role_model_selection(&effective, AgentRole::ChildOrchestrator);
        let child_resolved = catalog.resolve_role_model_selection(&child_effective, runtime)?;
        if matches!(
            &change,
            BudgetDegradationChange::ReasoningEffort {
                role: AgentRole::Worker,
                ..
            } | BudgetDegradationChange::ModelTier {
                role: AgentRole::Worker,
                ..
            }
        ) {
            self.worker_binding_trigger = Some(trigger);
        }
        self.records.push(BudgetDegradationRecord {
            sequence: self.records.len().saturating_add(1),
            assignment_id: assignment.id.clone(),
            trigger,
            budget_action: report.action,
            budget_reasons: report.reasons.clone(),
            change,
            role_binding_transition: Some(BudgetDegradationRoleBindingTransition {
                role: AgentRole::Worker,
                before: before_effective,
                after: after_effective,
            }),
            effective_child_model: child_resolved.selection.model,
            effective_child_reasoning_effort: child_resolved.selection.reasoning_effort,
            effective_fan_out: self.effective_fan_out,
            observation: BudgetDegradationObservation::AdmissionPolicyResolved,
        });
        Ok(())
    }

    fn record_inherited_worker_binding(
        &mut self,
        request: &AssignmentBudgetPolicyRequest<'_>,
        policy: &AssignmentBudgetPolicy,
    ) -> Result<()> {
        if self.records.iter().any(|record| {
            record.assignment_id == request.assignment.id
                && matches!(
                    record.change,
                    BudgetDegradationChange::RoleBindingApplied {
                        role: AgentRole::Worker
                    }
                )
        }) {
            return Ok(());
        }
        let trigger = self.worker_binding_trigger.with_context(|| {
            format!(
                "inherited Worker binding for assignment '{}' has no originating degradation trigger",
                request.assignment.id
            )
        })?;
        let mut base_policy = AssignmentBudgetPolicy {
            assignment_reasoning_effort: request.requested_reasoning_effort,
            ..AssignmentBudgetPolicy::default()
        };
        base_policy.selector_decisions.clear();
        let before = resolved_budget_role_binding(
            &base_policy,
            request.plan,
            AgentRole::Worker,
            request.catalog,
            request.runtime,
        )?;
        let after = resolved_budget_role_binding(
            policy,
            request.plan,
            AgentRole::Worker,
            request.catalog,
            request.runtime,
        )?;
        let effective = policy.apply(request.plan);
        let child = effective_role_model_selection(&effective, AgentRole::ChildOrchestrator);
        let child = request
            .catalog
            .resolve_role_model_selection(&child, request.runtime)?;
        self.records.push(BudgetDegradationRecord {
            sequence: self.records.len().saturating_add(1),
            assignment_id: request.assignment.id.clone(),
            trigger,
            budget_action: request.report.action,
            budget_reasons: request.report.reasons.clone(),
            change: BudgetDegradationChange::RoleBindingApplied {
                role: AgentRole::Worker,
            },
            role_binding_transition: Some(BudgetDegradationRoleBindingTransition {
                role: AgentRole::Worker,
                before,
                after,
            }),
            effective_child_model: child.selection.model,
            effective_child_reasoning_effort: child.selection.reasoning_effort,
            effective_fan_out: self.effective_fan_out,
            observation: BudgetDegradationObservation::AdmissionPolicyResolved,
        });
        Ok(())
    }

    fn record_halt(&mut self, assignment_id: &str, report: &RunBudgetReport) {
        if self.records.iter().any(|record| {
            record.assignment_id == assignment_id
                && matches!(record.change, BudgetDegradationChange::Halt { .. })
        }) {
            return;
        }
        self.records.push(BudgetDegradationRecord {
            sequence: self.records.len().saturating_add(1),
            assignment_id: assignment_id.to_string(),
            trigger: BudgetDegradationTrigger::BudgetPressure,
            budget_action: report.action,
            budget_reasons: report.reasons.clone(),
            change: BudgetDegradationChange::Halt {
                before_new_dispatch_allowed: self.last_new_dispatch_allowed,
                after_new_dispatch_allowed: report.new_dispatch_allowed,
            },
            role_binding_transition: None,
            effective_child_model: self
                .policy
                .model_overrides
                .get(&AgentRole::ChildOrchestrator)
                .and_then(|selection| selection.model.clone()),
            effective_child_reasoning_effort: self
                .assignment_effort_bindings
                .iter()
                .rev()
                .find(|binding| binding.role == AgentRole::ChildOrchestrator)
                .map(|binding| binding.resolved_reasoning_effort.clone()),
            effective_fan_out: self.effective_fan_out,
            observation: BudgetDegradationObservation::AdmissionPolicyResolved,
        });
    }

    fn record_assignment_effort_bindings(
        &mut self,
        assignment: &OrchestratorAssignment,
        requested_reasoning_effort: Option<ReasoningEffort>,
        plan: &SupervisorPlan,
        policy: &AssignmentBudgetPolicy,
    ) {
        // These bindings describe the assignment admission policy only. Retry-time selector
        // decisions remain attempt-aware in `selection_decisions` and command evidence; do not
        // overwrite this admission record and misrepresent a later retry as the initial binding.
        let effective_plan = policy.apply(plan);
        let mut push = |duty_id: String,
                        role: AgentRole,
                        requested: Option<ReasoningEffort>,
                        fallback: Option<&str>,
                        active_effort: Option<&str>,
                        budget_steps: usize,
                        process_observation: ProcessObservation,
                        unavailable_reason: Option<String>| {
            let mut resolved = resolve_reasoning_effort(role, requested, fallback, budget_steps);
            if let Some(active_effort) = active_effort {
                if resolved.resolved != active_effort {
                    resolved.fallback = active_effort.to_string();
                    resolved.resolved = active_effort.to_string();
                    resolved.observation = EffortResolutionObservation::BudgetDegraded;
                }
            }
            self.assignment_effort_bindings
                .push(AssignmentEffortBinding {
                    assignment_id: assignment.id.clone(),
                    duty_id,
                    role,
                    requested_reasoning_effort: resolved.requested,
                    fallback_reasoning_effort: resolved.fallback,
                    resolved_reasoning_effort: resolved.resolved,
                    resolution_observation: resolved.observation,
                    process_observation,
                    unavailable_reason,
                });
        };
        let child_fallback =
            configured_role_model_selection(plan, AgentRole::ChildOrchestrator).reasoning_effort;
        let active_child_effort =
            configured_role_model_selection(&effective_plan, AgentRole::ChildOrchestrator)
                .reasoning_effort;
        push(
            assignment.id.clone(),
            AgentRole::ChildOrchestrator,
            requested_reasoning_effort,
            child_fallback.as_deref(),
            active_child_effort.as_deref(),
            0,
            ProcessObservation::SchedulerObserved,
            Some(
                "admission-only effort binding; retry-time active effort is recorded in selection_decisions and process command evidence"
                    .to_string(),
            ),
        );
        let worker_fallback =
            configured_role_model_selection(plan, AgentRole::Worker).reasoning_effort;
        let active_worker_effort =
            configured_role_model_selection(&effective_plan, AgentRole::Worker).reasoning_effort;
        for worker in &assignment.worker_assignments {
            push(
                worker.id.clone(),
                AgentRole::Worker,
                requested_reasoning_effort,
                worker_fallback.as_deref(),
                active_worker_effort.as_deref(),
                policy.worker_effort_degradation_steps,
                ProcessObservation::NotProcessObservable,
                Some(
                    "admission-only nested-worker effort binding; retry-time active effort is recorded in selection_decisions and prompt evidence, and MACO does not separately observe a worker process or runtime identity"
                        .to_string(),
                ),
            );
        }
        let gate_fallback =
            configured_role_model_selection(plan, AgentRole::GateClassifier).reasoning_effort;
        let active_gate_effort =
            configured_role_model_selection(&effective_plan, AgentRole::GateClassifier)
                .reasoning_effort;
        push(
            format!("{}-acceptance-gate", assignment.id),
            AgentRole::GateClassifier,
            requested_reasoning_effort,
            gate_fallback.as_deref(),
            active_gate_effort.as_deref(),
            0,
            ProcessObservation::NotProcessObservable,
            Some(
                "admission-only effort binding; the current acceptance-gate classifier is a deterministic local broker without provider reasoning-effort telemetry"
                    .to_string(),
            ),
        );
        for (lens_index, lens) in effective_plan.review_lenses.iter().enumerate() {
            let requested = {
                lens.backend
                    .reasoning_effort()
                    .and_then(ReasoningEffort::parse)
            };
            push(
                review_lens_auditor_id(assignment, lens_index),
                AgentRole::Auditor,
                requested,
                lens.backend.reasoning_effort(),
                lens.backend.reasoning_effort(),
                0,
                ProcessObservation::NotRetained,
                Some(
                    "admission-only review-auditor effort binding; retry-time active effort is recorded in selection_decisions, and commands_run contains launch evidence"
                        .to_string(),
                ),
            );
        }
    }
}

#[cfg(test)]
pub(super) fn assignment_policy_after_completed_settlement_for_test(
    automatic_selection_state: SupervisorAutomaticSelectionState,
    assignment: &OrchestratorAssignment,
    report: &RunBudgetReport,
    plan: &SupervisorPlan,
    catalog: &RuntimeModelCatalog,
    runtime: SupervisorRuntime,
) -> Result<AssignmentBudgetPolicy> {
    let assignment_metadata = AssignmentMetadata::new();
    BudgetDegradationController::new_with_selection_state(
        1,
        Some(automatic_selection_state),
        runtime,
    )?
    .assignment_policy(AssignmentBudgetPolicyRequest {
        assignment,
        requested_reasoning_effort: None,
        report,
        plan,
        requested_plan: plan,
        assignment_metadata: &assignment_metadata,
        catalog,
        runtime,
    })?
    .context("completed settlement unexpectedly stopped the next assignment admission")
}

#[cfg(test)]
pub(super) fn assignment_budget_policy_for_test(
    request: AssignmentBudgetPolicyRequest<'_>,
    max_concurrent_children: usize,
) -> Result<Option<(AssignmentBudgetPolicy, Vec<BudgetDegradationRecord>)>> {
    let mut controller = BudgetDegradationController::new_with_selection_state(
        max_concurrent_children,
        None,
        request.runtime,
    )?;
    let policy = controller.assignment_policy(request)?;
    Ok(policy.map(|policy| (policy, controller.records.clone())))
}

fn typed_direct_mechanical_worker_duty(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
) -> Option<MechanicalTerminalDuty> {
    // Direct Worker ModelTier is opt-in on the assignment itself. Nested
    // `worker_assignments` keep the existing all-or-nothing collect below.
    // `direct_worker_mechanical_duty` is role-only; do not copy that helper
    // here and grant planning, judgment, or delegating roles.
    if assignment.role != AgentRole::Worker
        || assignment.phase != AssignmentPhase::Execution
        || assignment.role_category != Some(RoleCategory::NonDelegatingTerminalWorker)
        || !assignment.worker_assignments.is_empty()
    {
        return None;
    }
    assignment_metadata.direct_mechanical_duty(&assignment.id)
}

fn assignment_mechanical_duties(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
) -> Option<Vec<MechanicalTerminalDuty>> {
    if assignment.worker_assignments.is_empty() {
        return typed_direct_mechanical_worker_duty(assignment, assignment_metadata)
            .map(|duty| vec![duty]);
    }
    assignment
        .worker_assignments
        .iter()
        .map(|worker| {
            (worker.role == AgentRole::Worker)
                .then_some(())
                .and_then(|()| assignment_metadata.get(&(assignment.id.clone(), worker.id.clone())))
                .and_then(|metadata| metadata.mechanical_duty)
        })
        .collect()
}

fn mechanical_worker_model_is_eligible(model: &str, duties: &[MechanicalTerminalDuty]) -> bool {
    let Some(capability) = trusted_model_capability(model) else {
        return false;
    };
    let measured_eligible = super::prior_input::current_measured_authority_eligibility(
        model,
        crate::selection::AuthorityRole::TerminalLeaf,
    )
    .is_ok_and(|eligibility| {
        !matches!(
            eligibility,
            crate::selection::MeasuredAuthorityEligibility::Ineligible { .. }
        )
    });
    measured_eligible
        && duties.iter().all(|duty| {
            validate_budget_model_degradation(
                AgentRole::Worker,
                OrchestrationPhase::MechanicalTerminal,
                Some(*duty),
                capability,
            )
            .is_ok()
        })
}

fn resolved_budget_role_binding(
    policy: &AssignmentBudgetPolicy,
    plan: &SupervisorPlan,
    role: AgentRole,
    catalog: &RuntimeModelCatalog,
    runtime: SupervisorRuntime,
) -> Result<BudgetDegradationRoleBinding> {
    let effective_plan = policy.apply(plan);
    let selection = effective_role_model_selection(&effective_plan, role);
    let resolved = catalog.resolve_role_model_selection(&selection, runtime)?;
    Ok(BudgetDegradationRoleBinding {
        model: resolved.selection.model,
        reasoning_effort: resolved.selection.reasoning_effort,
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct AchievedConcurrency {
    started_assignment_count: usize,
    completed_assignment_count: usize,
    peak: usize,
    mean: Option<f64>,
}

#[derive(Clone)]
struct SchedulerConcurrencyTracker {
    state: Arc<Mutex<SchedulerConcurrencyState>>,
}

struct SchedulerConcurrencyState {
    last_transition: std::time::Instant,
    active_children: usize,
    peak: usize,
    started_assignment_count: usize,
    completed_assignment_count: usize,
    busy_seconds: f64,
    child_seconds: f64,
}

impl SchedulerConcurrencyTracker {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(SchedulerConcurrencyState {
                last_transition: std::time::Instant::now(),
                active_children: 0,
                peak: 0,
                started_assignment_count: 0,
                completed_assignment_count: 0,
                busy_seconds: 0.0,
                child_seconds: 0.0,
            })),
        }
    }

    fn record_elapsed(state: &mut SchedulerConcurrencyState) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(state.last_transition).as_secs_f64();
        if state.active_children > 0 {
            state.busy_seconds += elapsed;
            state.child_seconds += elapsed * state.active_children as f64;
        }
        state.last_transition = now;
    }

    fn assignment_started(&self) -> ActiveAssignmentConcurrencyGuard {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::record_elapsed(&mut state);
        state.active_children = state.active_children.saturating_add(1);
        state.started_assignment_count = state.started_assignment_count.saturating_add(1);
        state.peak = state.peak.max(state.active_children);
        ActiveAssignmentConcurrencyGuard {
            tracker: self.clone(),
        }
    }

    fn assignment_completed(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::record_elapsed(&mut state);
        state.active_children = state.active_children.saturating_sub(1);
        state.completed_assignment_count = state.completed_assignment_count.saturating_add(1);
    }

    fn finish(&self) -> AchievedConcurrency {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::record_elapsed(&mut state);
        AchievedConcurrency {
            started_assignment_count: state.started_assignment_count,
            completed_assignment_count: state.completed_assignment_count,
            peak: state.peak,
            mean: (state.busy_seconds > 0.0).then(|| state.child_seconds / state.busy_seconds),
        }
    }
}

struct ActiveAssignmentConcurrencyGuard {
    tracker: SchedulerConcurrencyTracker,
}

impl Drop for ActiveAssignmentConcurrencyGuard {
    fn drop(&mut self) {
        self.tracker.assignment_completed();
    }
}

#[derive(Default)]
struct CollectedAssignmentOutcomes {
    acquired_claim_tokens: Vec<ClaimToken>,
    acquired_semantic_tokens: Vec<crate::semantic_coord::SemanticIntentToken>,
    concurrently_released_claims: Vec<PathClaim>,
    concurrent_release_errors: Vec<String>,
    concurrently_released_semantic_intents: Vec<SemanticIntent>,
    concurrent_semantic_release_errors: Vec<String>,
    command_records: Vec<CommandRunRecord>,
    usage_samples: Vec<RoleUsageSample>,
    usage_incomplete: bool,
    orchestrator_reports: Vec<OrchestratorReviewReport>,
    gate_denials: Vec<GateDenial>,
    pre_action_review_metrics: Vec<ReviewMetricSnapshot>,
    gate_correction_outcomes: Vec<GateCorrectionOutcomeRecord>,
    selection_decisions: Vec<SupervisorSelectionEvent>,
    preclaim_parked_assignment_ids: BTreeSet<String>,
    candidate_inspections: BTreeMap<String, SupervisorCandidateInspection>,
    findings: Vec<Finding>,
    assignment_execution_failed: bool,
    external_containment_failed: bool,
}

fn collect_indexed_assignment_outcomes(
    indexed_outcomes: Vec<Option<AssignmentExecutionOutcome>>,
    release_per_assignment: bool,
    collected: &mut CollectedAssignmentOutcomes,
) -> Vec<String> {
    let mut fatal_errors = Vec::new();
    for outcome in indexed_outcomes.into_iter().flatten() {
        collected.command_records.extend(outcome.command_records);
        collected.usage_samples.extend(outcome.usage_samples);
        collected.usage_incomplete |= outcome.usage_incomplete;
        collected.findings.extend(outcome.findings);
        collected.gate_denials.extend(outcome.gate_denials);
        collected
            .pre_action_review_metrics
            .extend(outcome.pre_action_review_metrics);
        collected
            .gate_correction_outcomes
            .extend(outcome.gate_correction_outcomes);
        let mut selection_decisions = outcome.selection_decisions;
        selection_decisions
            .sort_by(|left, right| (left.attempt, left.role).cmp(&(right.attempt, right.role)));
        collected.selection_decisions.extend(selection_decisions);
        collected.assignment_execution_failed |= outcome.assignment_failed;
        collected.external_containment_failed |= outcome.external_containment_failed;
        if !release_per_assignment {
            collected.acquired_claim_tokens.extend(outcome.claim_tokens);
            collected
                .acquired_semantic_tokens
                .extend(outcome.semantic_tokens);
        } else {
            collected
                .concurrently_released_claims
                .extend(outcome.released_claims);
            collected
                .concurrent_release_errors
                .extend(outcome.release_errors);
            collected
                .concurrently_released_semantic_intents
                .extend(outcome.released_semantic_intents);
            collected
                .concurrent_semantic_release_errors
                .extend(outcome.semantic_release_errors);
        }
        if let (Some(report), Some(inspection)) =
            (outcome.report.as_ref(), outcome.candidate_inspection)
        {
            collected
                .candidate_inspections
                .insert(report.id.clone(), inspection);
        }
        if let Some(report) = outcome.report {
            collected.orchestrator_reports.push(report);
        }
        if let Some(error) = outcome.fatal_error {
            fatal_errors.push(error);
        }
    }
    fatal_errors
}

pub(super) fn select_ready_nonoverlapping_assignment<I>(
    pending: &BTreeSet<usize>,
    assignment_schedule: &[AssignmentScheduleEntry],
    indexed_outcomes: &[Option<AssignmentExecutionOutcome>],
    plan: &SupervisorPlan,
    active_indices: I,
) -> Result<Option<usize>>
where
    I: Iterator<Item = usize> + Clone,
{
    for candidate in pending.iter().copied() {
        if assignment_admission_state(candidate, assignment_schedule, indexed_outcomes)?
            != AssignmentAdmissionState::Ready
        {
            continue;
        }
        if active_indices.clone().all(|active_index| {
            !assignments_overlap(
                &plan.assignments[candidate],
                &plan.assignments[active_index],
            )
        }) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn schedule_preclaim_decision(
    context: &AssignmentSchedulerContext<'_, '_>,
    progress: &SchedulerProgress,
    fallback_evidence: Option<&PreclaimRunEvidence>,
    index: usize,
) -> Result<PreclaimDecision> {
    if let Some(decision) = progress.prepared_preclaim_decision(index)? {
        if decision.assignment_id != context.plan.assignments[index].id {
            bail!("prepared pre-claim decision assignment binding changed");
        }
        if decision.allows_path_claim() {
            if let Some(evidence) = progress.prepared_preclaim_evidence.as_ref() {
                evidence.revalidate_authored(
                    context.repo,
                    &context.plan.assignments[index],
                    &context.requested_plan.assignments,
                    context.assignment_metadata,
                )?;
            } else if context
                .assignment_metadata
                .authored_independent_checks
                .contains_key(&context.plan.assignments[index].id)
            {
                bail!("authored check receipts were not retained for scheduler admission");
            }
        }
        return Ok(decision);
    }
    let evidence = fallback_evidence.context(
        "scheduler has neither a prepared pre-claim decision nor fallback pre-claim evidence",
    )?;
    preclaim_assignment(
        context.artifacts,
        &context.plan.assignments[index],
        &context.requested_plan.assignments,
        evidence,
    )
}

fn scheduler_preclaim_evidence(
    context: &AssignmentSchedulerContext<'_, '_>,
) -> PreclaimRunEvidence {
    PreclaimRunEvidence::acquire(
        context.repo,
        context.options.runtime,
        preclaim_assessment_runtime(
            context.options.runtime,
            context.execution_runtime,
            context.worktree_creation,
        ),
    )
    .with_assignment_metadata(context.assignment_metadata)
}

pub(super) fn recheck_narrowed_assignment_preclaim(
    artifacts: &Mutex<SharedSupervisorArtifacts<'_>>,
    assignment: &OrchestratorAssignment,
    requested_assignments: &[OrchestratorAssignment],
    repo_and_metadata: (&Path, &AssignmentMetadata),
    runtime: SupervisorRuntime,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
) -> Result<Option<AssignmentExecutionOutcome>> {
    let (repo, assignment_metadata) = repo_and_metadata;
    let evidence = PreclaimRunEvidence::acquire(
        repo,
        runtime,
        preclaim_assessment_runtime(runtime, execution_runtime, worktree_creation),
    )
    .with_assignment_metadata(assignment_metadata);
    let decision = preclaim_assignment(artifacts, assignment, requested_assignments, &evidence)?;
    if decision.allows_path_claim() {
        Ok(None)
    } else {
        Ok(Some(parked_preclaim_outcome(assignment, &decision)))
    }
}

fn run_serial_assignment_schedule(
    context: &AssignmentSchedulerContext<'_, '_>,
    progress: &mut SchedulerProgress,
    cancellation: &ProcessCancellation,
    serial_semantic_warn_intents: &Mutex<Vec<(usize, SemanticIntent)>>,
) -> Result<()> {
    let fallback_preclaim_evidence = progress
        .prepared_preclaim_decisions
        .is_none()
        .then(|| scheduler_preclaim_evidence(context));
    let mut pending = (0..context.plan.assignments.len()).collect::<BTreeSet<_>>();
    while !pending.is_empty() {
        suppress_failed_descendants(
            &mut pending,
            &mut progress.indexed_outcomes,
            context.plan,
            context.assignment_schedule,
            context.artifacts,
        )?;
        progress.commit_completed_selection_prefix(context.options.runtime, context.run_dir)?;
        if pending.is_empty() {
            break;
        }
        if !progress.health_breaker.permits_admission() {
            break;
        }
        let budget_report = context
            .budget_ledger
            .report()
            .context("failed to inspect run budget before serial admission")?;
        if !budget_report.new_dispatch_allowed {
            progress.budget_prevented_dispatch = true;
            progress
                .budget_denied_assignment_indices
                .extend(pending.iter().copied());
            for index in &pending {
                progress
                    .budget_degradation
                    .record_halt(&context.plan.assignments[*index].id, &budget_report);
            }
            break;
        }
        let mut next = None;
        for candidate in pending.iter().copied() {
            if assignment_admission_state(
                candidate,
                context.assignment_schedule,
                &progress.indexed_outcomes,
            )? == AssignmentAdmissionState::Ready
            {
                next = Some(candidate);
                break;
            }
        }
        let Some(index) = next else {
            bail!("supervisor scheduler could not select a hierarchy-ready pending assignment");
        };
        let assignment = &context.plan.assignments[index];
        let preclaim = schedule_preclaim_decision(
            context,
            progress,
            fallback_preclaim_evidence.as_ref(),
            index,
        )?;
        if !preclaim.allows_path_claim() {
            pending.remove(&index);
            progress.indexed_outcomes[index] = Some(parked_preclaim_outcome(assignment, &preclaim));
            progress.commit_completed_selection_prefix(context.options.runtime, context.run_dir)?;
            continue;
        }
        let Some(budget_policy) =
            progress
                .budget_degradation
                .assignment_policy(AssignmentBudgetPolicyRequest {
                    assignment,
                    requested_reasoning_effort: context
                        .assignment_metadata
                        .reasoning_effort(&assignment.id),
                    report: &budget_report,
                    plan: context.plan,
                    requested_plan: context.requested_plan,
                    assignment_metadata: context.assignment_metadata,
                    catalog: context.runtime_model_catalog,
                    runtime: context.options.runtime,
                })?
        else {
            progress.budget_prevented_dispatch = true;
            progress
                .budget_denied_assignment_indices
                .extend(pending.iter().copied());
            break;
        };
        pending.remove(&index);
        record_assignment_started_checkpoint(
            context.artifacts,
            assignment,
            index,
            context.budget_ledger,
        )?;
        let concurrency_guard = progress.concurrency.assignment_started();
        let outcome = execute_supervisor_assignment(AssignmentExecutionContext {
            index,
            concurrent_mode: false,
            plan: context.plan,
            requested_plan: context.requested_plan,
            budget_config: context.budget_config,
            consultant: context.consultant,
            assignment_metadata: context.assignment_metadata,
            assignment,
            evidence_only_reaudit: context.evidence_only_reaudit,
            options: context.options,
            repo: context.repo,
            run_dir: context.run_dir,
            dirs: context.dirs,
            execution_runtime: context.execution_runtime,
            execution_target: context.execution_target,
            worktree_creation: context.worktree_creation,
            manager: context.manager,
            reused: context.existing_ids.contains(&assignment.id),
            sync_store: context.sync_store,
            semantic_store: context.semantic_store,
            prepared_semantic_token: context.prepared_semantic_assignments[index].token,
            prepared_semantic_findings: &context.prepared_semantic_assignments[index].findings,
            prepared_semantic_signals: &context.prepared_semantic_assignments[index].health_signals,
            prepared_semantic_failed: context.prepared_semantic_assignments[index]
                .assignment_failed,
            assignment_schedule: context.assignment_schedule,
            field_guide: context.field_guide,
            serial_semantic_warn_intents: Some(serial_semantic_warn_intents),
            semantic_block_order: None,
            semantic_block_gate: None,
            artifacts: context.artifacts,
            budget_ledger: context.budget_ledger,
            budget_policy,
            admission_commit: None,
            runtime_model_catalog: context.runtime_model_catalog,
            cancellation: cancellation.child_scope(),
            external_runner: context.external_runner,
        });
        drop(concurrency_guard);
        let mut outcome = outcome;
        record_completed_assignment_checkpoint(context, index, &outcome)?;
        if context.release_per_assignment {
            release_concurrent_assignment(&mut outcome, context.sync_store, context.semantic_store);
        }
        if progress.circuit_breaker_trip.is_none() {
            if let Some(trip) = observe_assignment_health(&mut progress.health_breaker, &outcome) {
                record_breaker_trip(context.artifacts, &context.options.run_id, &trip)?;
                progress.circuit_breaker_trip = Some(trip);
            }
        }
        let abort = outcome.requires_scheduler_abort();
        let budget_stopped = outcome.budget_dispatch_stopped;
        progress.indexed_outcomes[index] = Some(outcome);
        progress.commit_completed_selection_prefix(context.options.runtime, context.run_dir)?;
        if abort || budget_stopped {
            progress.budget_prevented_dispatch |= budget_stopped;
            if !pending.is_empty()
                && !context
                    .budget_ledger
                    .report()
                    .context("failed to inspect run budget after aborted serial dispatch")?
                    .new_dispatch_allowed
            {
                progress.budget_prevented_dispatch = true;
                progress
                    .budget_denied_assignment_indices
                    .extend(pending.iter().copied());
            }
            if budget_stopped {
                progress
                    .budget_denied_assignment_indices
                    .extend(pending.iter().copied());
            }
            break;
        }
        if !pending.is_empty()
            && !context
                .budget_ledger
                .report()
                .context("failed to inspect run budget after serial dispatch")?
                .new_dispatch_allowed
        {
            progress.budget_prevented_dispatch = true;
            progress
                .budget_denied_assignment_indices
                .extend(pending.iter().copied());
            break;
        }
    }
    Ok(())
}

// Preparation rendezvous in budget tests must also wake when a participant
// returns early or unwinds, before the scoped scheduler joins its workers.
#[cfg(test)]
struct BudgetAdmissionTestCompletion<'a> {
    run_id: &'a str,
    owner: &'a str,
    stage: &'static str,
}

#[cfg(test)]
impl Drop for BudgetAdmissionTestCompletion<'_> {
    fn drop(&mut self) {
        observe_budget_admission_for_test(self.run_id, self.stage, self.owner);
    }
}

fn run_concurrent_assignment_schedule(
    context: &AssignmentSchedulerContext<'_, '_>,
    progress: &mut SchedulerProgress,
    cancellation: &ProcessCancellation,
    semantic_block_gate: &SemanticBlockGate,
) -> Result<()> {
    let fallback_preclaim_evidence = progress
        .prepared_preclaim_decisions
        .is_none()
        .then(|| scheduler_preclaim_evidence(context));
    thread::scope(|scope| -> Result<()> {
        #[cfg(test)]
        let _test_completion = BudgetAdmissionTestCompletion {
            run_id: context.options.run_id.as_str(),
            owner: "scheduler",
            stage: "scheduler_finished",
        };
        let (completion_sender, completion_receiver) = mpsc::channel::<usize>();
        let mut pending = (0..context.plan.assignments.len()).collect::<BTreeSet<_>>();
        let mut active = BTreeMap::new();
        let mut stop_scheduling = false;
        let mut next_semantic_block_order = 0usize;

        while !pending.is_empty() || !active.is_empty() {
            if !stop_scheduling {
                suppress_failed_descendants(
                    &mut pending,
                    &mut progress.indexed_outcomes,
                    context.plan,
                    context.assignment_schedule,
                    context.artifacts,
                )?;
                progress
                    .commit_completed_selection_prefix(context.options.runtime, context.run_dir)?;
                while active.len() < progress.budget_degradation.effective_fan_out {
                    if !progress.health_breaker.permits_admission() {
                        stop_scheduling = true;
                        break;
                    }
                    let (budget_report, waiting_for_live_grant) = context
                        .budget_ledger
                        .concurrent_admission_report()
                        .context("failed to inspect run budget before concurrent admission")?;
                    if !budget_report.new_dispatch_allowed {
                        #[cfg(test)]
                        LIVE_GRANT_ADMISSION_OBSERVER.with(|observer| {
                            if let Some(sender) = observer.borrow_mut().take() {
                                let _ = sender.send(budget_report.reserved.tokens);
                            }
                        });
                        if waiting_for_live_grant && !active.is_empty() {
                            // The admission handshake already bound the active child's grant.
                            // Wait for its settlement to release unused capacity; do not deny
                            // pending work or cancel the ordinary running turn.
                            break;
                        }
                        progress.budget_prevented_dispatch |= !pending.is_empty();
                        progress
                            .budget_denied_assignment_indices
                            .extend(pending.iter().copied());
                        for index in &pending {
                            progress
                                .budget_degradation
                                .record_halt(&context.plan.assignments[*index].id, &budget_report);
                        }
                        stop_scheduling = true;
                        break;
                    }
                    let next = select_ready_nonoverlapping_assignment(
                        &pending,
                        context.assignment_schedule,
                        &progress.indexed_outcomes,
                        context.plan,
                        active.keys().copied(),
                    )?;
                    let Some(index) = next else {
                        break;
                    };
                    let assignment = &context.plan.assignments[index];
                    if active.len() >= progress.budget_degradation.effective_fan_out {
                        break;
                    }
                    let preclaim = schedule_preclaim_decision(
                        context,
                        progress,
                        fallback_preclaim_evidence.as_ref(),
                        index,
                    )?;
                    if !preclaim.allows_path_claim() {
                        pending.remove(&index);
                        progress.indexed_outcomes[index] =
                            Some(parked_preclaim_outcome(assignment, &preclaim));
                        progress.commit_completed_selection_prefix(
                            context.options.runtime,
                            context.run_dir,
                        )?;
                        continue;
                    }
                    let Some(budget_policy) = progress.budget_degradation.assignment_policy(
                        AssignmentBudgetPolicyRequest {
                            assignment,
                            requested_reasoning_effort: context
                                .assignment_metadata
                                .reasoning_effort(&assignment.id),
                            report: &budget_report,
                            plan: context.plan,
                            requested_plan: context.requested_plan,
                            assignment_metadata: context.assignment_metadata,
                            catalog: context.runtime_model_catalog,
                            runtime: context.options.runtime,
                        },
                    )?
                    else {
                        progress.budget_prevented_dispatch |= !pending.is_empty();
                        progress
                            .budget_denied_assignment_indices
                            .extend(pending.iter().copied());
                        stop_scheduling = true;
                        break;
                    };
                    pending.remove(&index);
                    record_assignment_started_checkpoint(
                        context.artifacts,
                        assignment,
                        index,
                        context.budget_ledger,
                    )?;
                    let semantic_block_order = (context.plan.semantic_coordination
                        == SemanticCoordinationMode::Block)
                        .then(|| {
                            let order = next_semantic_block_order;
                            next_semantic_block_order = next_semantic_block_order.saturating_add(1);
                            order
                        });
                    let completion_sender = completion_sender.clone();
                    let assignment_cancellation = cancellation.child_scope();
                    let concurrency = progress.concurrency.clone();
                    let (admission_commit, admission_receiver) = AdmissionCommitSignal::new();
                    let prior_binding = super::prior_input::captured_binding();
                    let routing_policy = crate::selection::routing_policy::current_routing_policy();
                    let selected_authorizations =
                        crate::selection::routing_policy::captured_selected_authorizations();
                    let runtime_binding = super::runtime_executables::captured_binding();
                    #[cfg(all(test, target_os = "linux"))]
                    let cam_observe_fixture = captured_cam_observe_test_harness();
                    let spawn_result = thread::Builder::new().spawn_scoped(scope, move || {
                        #[cfg(all(test, target_os = "linux"))]
                        let _cam_observe_guard =
                            install_captured_cam_observe_test_harness(cam_observe_fixture);
                        #[cfg(test)]
                        let _test_completion = BudgetAdmissionTestCompletion {
                            run_id: context.options.run_id.as_str(),
                            owner: &assignment.id,
                            stage: "assignment_finished",
                        };
                        let _prior_binding_guard =
                            super::prior_input::install_captured(prior_binding);
                        let _routing_policy_guard =
                            crate::selection::routing_policy::bind_routing_policy(routing_policy)
                                .expect("already validated frozen routing policy");
                        crate::selection::routing_policy::install_selected_authorizations(
                            selected_authorizations,
                        );
                        let _runtime_binding_guard =
                            super::runtime_executables::install_captured(runtime_binding);
                        let _completion = CompletionSignal {
                            index,
                            sender: completion_sender,
                        };
                        let _concurrency_guard = concurrency.assignment_started();
                        #[cfg(test)]
                        if take_abort_admission_commit_on_spawn(&context.options.run_id) {
                            panic!("injected admission-commit abort before notify");
                        }
                        execute_supervisor_assignment(AssignmentExecutionContext {
                            index,
                            concurrent_mode: true,
                            plan: context.plan,
                            requested_plan: context.requested_plan,
                            budget_config: context.budget_config,
                            consultant: context.consultant,
                            assignment_metadata: context.assignment_metadata,
                            assignment,
                            evidence_only_reaudit: context.evidence_only_reaudit,
                            options: context.options,
                            repo: context.repo,
                            run_dir: context.run_dir,
                            dirs: context.dirs,
                            execution_runtime: context.execution_runtime,
                            execution_target: context.execution_target,
                            worktree_creation: context.worktree_creation,
                            manager: context.manager,
                            reused: context.existing_ids.contains(&assignment.id),
                            sync_store: context.sync_store,
                            semantic_store: context.semantic_store,
                            prepared_semantic_token: context.prepared_semantic_assignments[index]
                                .token,
                            prepared_semantic_findings: &context.prepared_semantic_assignments
                                [index]
                                .findings,
                            prepared_semantic_signals: &context.prepared_semantic_assignments
                                [index]
                                .health_signals,
                            prepared_semantic_failed: context.prepared_semantic_assignments[index]
                                .assignment_failed,
                            assignment_schedule: context.assignment_schedule,
                            field_guide: context.field_guide,
                            serial_semantic_warn_intents: None,
                            semantic_block_order,
                            semantic_block_gate: semantic_block_order.map(|_| semantic_block_gate),
                            artifacts: context.artifacts,
                            budget_ledger: context.budget_ledger,
                            budget_policy,
                            admission_commit: Some(admission_commit),
                            runtime_model_catalog: context.runtime_model_catalog,
                            cancellation: assignment_cancellation,
                            external_runner: context.external_runner,
                        })
                    });
                    match spawn_result {
                        Ok(handle) => {
                            active.insert(index, handle);
                            if let Err(error) = admission_receiver.recv() {
                                cancellation.cancel();
                                for (active_index, active_handle) in std::mem::take(&mut active) {
                                    let mut outcome = match active_handle.join() {
                                        Ok(outcome) => outcome,
                                        Err(_) => AssignmentExecutionOutcome::fatal(format!(
                                            "supervisor assignment '{}' thread panicked",
                                            context.plan.assignments[active_index].id
                                        )),
                                    };
                                    record_completed_assignment_checkpoint(
                                        context,
                                        active_index,
                                        &outcome,
                                    )?;
                                    release_concurrent_assignment(
                                        &mut outcome,
                                        context.sync_store,
                                        context.semantic_store,
                                    );
                                    progress.indexed_outcomes[active_index] = Some(outcome);
                                }
                                progress.commit_completed_selection_prefix(
                                    context.options.runtime,
                                    context.run_dir,
                                )?;
                                return Err(error).context(format!(
                                    "supervisor assignment '{}' ended before committing or declining budget admission",
                                    assignment.id
                                ));
                            }
                            #[cfg(test)]
                            observe_budget_admission_for_test(
                                context.options.run_id.as_str(),
                                "admission_committed",
                                &assignment.id,
                            );
                        }
                        Err(error) => {
                            #[cfg(test)]
                            observe_budget_admission_for_test(
                                context.options.run_id.as_str(),
                                "assignment_finished",
                                &assignment.id,
                            );
                            cancellation.cancel();
                            record_assignment_spawn_failure(
                                &mut progress.indexed_outcomes,
                                &mut stop_scheduling,
                                index,
                                &assignment.id,
                                &error,
                            )?;
                            let outcome = progress.indexed_outcomes[index]
                                .as_ref()
                                .context("spawn failure outcome disappeared")?;
                            record_completed_assignment_checkpoint(context, index, outcome)?;
                            progress.commit_completed_selection_prefix(
                                context.options.runtime,
                                context.run_dir,
                            )?;
                            break;
                        }
                    }
                }
            }

            if active.is_empty() {
                if pending.is_empty() || stop_scheduling {
                    break;
                }
                cancellation.cancel();
                bail!("supervisor scheduler could not select a hierarchy-ready pending assignment");
            }

            #[cfg(test)]
            observe_budget_admission_for_test(
                context.options.run_id.as_str(),
                "scheduler_draining",
                "scheduler",
            );
            let completed_index = match completion_receiver.recv() {
                Ok(index) => index,
                Err(error) => {
                    cancellation.cancel();
                    return Err(error).context("supervisor assignment completion channel closed");
                }
            };
            let handle = match active.remove(&completed_index) {
                Some(handle) => handle,
                None => {
                    cancellation.cancel();
                    bail!("supervisor completion referenced an inactive assignment");
                }
            };
            let mut outcome = match handle.join() {
                Ok(outcome) => outcome,
                Err(_) => AssignmentExecutionOutcome::fatal(format!(
                    "supervisor assignment '{}' thread panicked",
                    context.plan.assignments[completed_index].id
                )),
            };
            record_completed_assignment_checkpoint(context, completed_index, &outcome)?;
            release_concurrent_assignment(&mut outcome, context.sync_store, context.semantic_store);
            if outcome.requires_scheduler_abort() {
                cancellation.cancel();
                stop_scheduling = true;
                #[cfg(test)]
                if !outcome.release_errors.is_empty() || !outcome.semantic_release_errors.is_empty()
                {
                    CONCURRENT_RELEASE_ERROR_OBSERVER.with(|observer| {
                        if let Some(sender) = observer.borrow_mut().take() {
                            let _ = sender.send(());
                        }
                    });
                }
            } else {
                if progress.circuit_breaker_trip.is_none() {
                    if let Some(trip) =
                        observe_assignment_health(&mut progress.health_breaker, &outcome)
                    {
                        record_breaker_trip(context.artifacts, &context.options.run_id, &trip)?;
                        progress.circuit_breaker_trip = Some(trip);
                        // A breaker trip is a graceful scheduler stop: pending assignments are not
                        // admitted, while already-active children retain their cancellation tokens
                        // and are drained.
                        stop_scheduling = true;
                    }
                }
                let (budget_report, waiting_for_live_grant) = context
                    .budget_ledger
                    .concurrent_admission_report()
                    .context("failed to inspect run budget after concurrent dispatch")?;
                if outcome.budget_dispatch_stopped
                    || (!pending.is_empty()
                        && !budget_report.new_dispatch_allowed
                        && (active.is_empty() || !waiting_for_live_grant))
                {
                    progress.budget_prevented_dispatch = true;
                    progress
                        .budget_denied_assignment_indices
                        .extend(pending.iter().copied());
                    stop_scheduling = true;
                }
            }
            progress.indexed_outcomes[completed_index] = Some(outcome);
            progress.commit_completed_selection_prefix(context.options.runtime, context.run_dir)?;
        }

        for (index, handle) in active {
            let mut outcome = match handle.join() {
                Ok(outcome) => outcome,
                Err(_) => AssignmentExecutionOutcome::fatal(format!(
                    "supervisor assignment '{}' thread panicked",
                    context.plan.assignments[index].id
                )),
            };
            record_completed_assignment_checkpoint(context, index, &outcome)?;
            release_concurrent_assignment(&mut outcome, context.sync_store, context.semantic_store);
            progress.indexed_outcomes[index] = Some(outcome);
            progress.commit_completed_selection_prefix(context.options.runtime, context.run_dir)?;
        }
        Ok(())
    })
}

fn record_completed_assignment_checkpoint(
    context: &AssignmentSchedulerContext<'_, '_>,
    index: usize,
    outcome: &AssignmentExecutionOutcome,
) -> Result<()> {
    let assignment = context
        .plan
        .assignments
        .get(index)
        .context("checkpoint completion index is outside the supervisor plan")?;
    let mut checkpoint_assignment = assignment.clone();
    if !outcome.claimed_paths.is_empty() {
        checkpoint_assignment.assigned_paths = outcome.claimed_paths.clone();
    }
    let worktrees = context.manager.list()?;
    let worktree = worktrees.iter().find(|record| record.name == assignment.id);
    let claim_tokens = outcome
        .claim_tokens
        .iter()
        .map(|token| token.get())
        .chain(
            outcome
                .released_claims
                .iter()
                .map(|claim| claim.token.get()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    record_assignment_completed_checkpoint(
        context.artifacts,
        &checkpoint_assignment,
        index,
        context.budget_ledger,
        worktree,
        claim_tokens,
    )
}

struct SupervisorFinalReportConstruction<'context> {
    plan: &'context SupervisorPlan,
    runtime_model_catalog: Option<&'context RuntimeModelCatalog>,
    max_concurrent_children: usize,
    admission_policy_input: SupervisorAdmissionPolicyInput,
    achieved_concurrency: AchievedConcurrency,
    has_multiple_independent_assignment_scopes: bool,
    run_id: RunId,
    report_plan_file: PathBuf,
    report_run_dir: PathBuf,
    runtime: SupervisorRuntime,
    publishable: bool,
    success: bool,
    run_budget_report: Option<RunBudgetReport>,
    budget_degradations: Vec<BudgetDegradationRecord>,
    assignment_effort_bindings: Vec<AssignmentEffortBinding>,
    evidence_only_reaudit: Option<EvidenceOnlyReauditPlan>,
    role_usage: BTreeMap<AgentRole, RoleUsageReport>,
    review_lens_usage: Vec<ReviewLensUsageReport>,
    review_lens_total_usage: Option<Usage>,
    review_lens_total_cost_usd: Option<f64>,
    total_usage: Option<Usage>,
    total_cost_usd: Option<f64>,
    usage_complete: bool,
    environment_failures: Vec<EnvironmentFailure>,
    sandbox_denials: Vec<SandboxDenialEvidence>,
    collected: CollectedAssignmentOutcomes,
    this_run_attempt_rows: Vec<ThisRunAttemptCostRow>,
    bloated_file_flags: Vec<BloatedFileFlag>,
    decomposition_candidates: Vec<DecompositionCompletion>,
    assignment_traceability: Vec<AssignmentTraceability>,
    coverage_gaps: Vec<SupervisorCoverageGap>,
    supervisor_breaker_trip: Option<SupervisorBreakerTrip>,
    autonomy_kpis: AutonomyKpiReport,
    released_claims: Vec<PathClaim>,
    release_errors: Vec<String>,
    released_semantic_intents: Vec<SemanticIntent>,
    semantic_release_errors: Vec<String>,
    external_containment_failed: bool,
    final_primary_integrity_failed: bool,
    budget_prevented_dispatch: bool,
    budget_accounting_failed: bool,
    breaker_tripped: bool,
    field_guide_mutation_failed: bool,
}

fn complete_role_usage_reports(
    mut reports: BTreeMap<AgentRole, RoleUsageReport>,
) -> BTreeMap<AgentRole, RoleUsageReport> {
    for role in [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ] {
        reports.entry(role).or_insert_with(|| RoleUsageReport {
            models: Vec::new(),
            usage: None,
            cost_usd: None,
            observation: RoleUsageObservation::NotProcessObservable,
            unavailable_reason: Some(format!(
                "no reliable process-observable usage sample was attributed to the {} role",
                role.as_str()
            )),
        });
    }
    reports
}

fn resolved_role_execution_bindings(
    plan: &SupervisorPlan,
    runtime: SupervisorRuntime,
    runtime_model_catalog: Option<&RuntimeModelCatalog>,
    assignment_selection_ledger: &[AssignmentSelectionLedgerEntry],
    selection_decisions: &[SupervisorSelectionEvent],
) -> BTreeMap<AgentRole, ResolvedRoleExecutionBinding> {
    let assignment_specific_worker_binding = assignment_specific_worker_role_binding(
        plan,
        assignment_selection_ledger,
        selection_decisions,
    );
    [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ]
    .into_iter()
    .map(|role| {
        if role == AgentRole::Worker {
            if let Some(binding) = assignment_specific_worker_binding.as_ref() {
                return (role, binding.clone());
            }
        }
        let configured = configured_role_model_selection(plan, role);
        let mut effective = configured.clone();
        effective.reasoning_effort =
            enforce_role_reasoning_effort_floor(role, effective.reasoning_effort);
        let (
            resolved_model,
            resolved_reasoning_effort,
            observation,
            resolution_observation,
            configured_model_chain,
            resolved_candidate_index,
            unavailable_reason,
        ) =
            match runtime_model_catalog {
                None => (
                    None,
                    None,
                    RoleBindingObservation::CatalogUnavailable,
                    ModelResolutionObservation::NotResolved,
                    configured.configured_model_chain(),
                    None,
                    Some(
                        "runtime model catalog acquisition failed before role selection could be resolved"
                            .to_string(),
                    ),
                ),
                Some(catalog) if runtime == SupervisorRuntime::Fake => {
                    let resolution = catalog.resolve_role_model_selection(&effective, runtime);
                    let resolution_observation = resolution
                        .as_ref()
                        .map(|resolution| resolution.observation)
                        .unwrap_or(ModelResolutionObservation::NotResolved);
                    (
                        None,
                        None,
                        RoleBindingObservation::SyntheticFake,
                        resolution_observation,
                        effective.configured_model_chain(),
                        None,
                        Some(
                            "the deterministic fake runtime does not execute a provider model or reasoning effort"
                                .to_string(),
                        ),
                    )
                }
                Some(catalog) => {
                    let resolved = catalog.resolve_role_model_selection(&effective, runtime);
                    match resolved {
                        Ok(resolved) if resolved.selection.model.is_some() => (
                            resolved.selection.model,
                            resolved.selection.reasoning_effort,
                            RoleBindingObservation::RuntimeCatalogResolved,
                            resolved.observation,
                            resolved.configured_model_chain,
                            resolved.resolved_candidate_index,
                            None,
                        ),
                        Ok(resolved) => (
                            None,
                            resolved.selection.reasoning_effort,
                            RoleBindingObservation::RuntimeDefaultResolved,
                            resolved.observation,
                            resolved.configured_model_chain,
                            resolved.resolved_candidate_index,
                            Some(
                                "the runtime-default fallback was selected, so the concrete provider model slug is not process-observable"
                                    .to_string(),
                            ),
                        ),
                        Err(error) => (
                            None,
                            None,
                            RoleBindingObservation::ResolutionFailed,
                            ModelResolutionObservation::NotResolved,
                            configured.configured_model_chain(),
                            None,
                            Some(format!("role model resolution failed: {error:#}")),
                        ),
                    }
                }
            };
        (
            role,
            ResolvedRoleExecutionBinding {
                configured_model: configured.model,
                configured_reasoning_effort: configured.reasoning_effort,
                resolved_model,
                resolved_reasoning_effort,
                observation,
                resolution_observation,
                configured_model_chain,
                resolved_candidate_index,
                unavailable_reason,
            },
        )
    })
    .collect()
}

fn assignment_specific_worker_role_binding(
    plan: &SupervisorPlan,
    assignment_selection_ledger: &[AssignmentSelectionLedgerEntry],
    selection_decisions: &[SupervisorSelectionEvent],
) -> Option<ResolvedRoleExecutionBinding> {
    // This is a final-report projection only. Launch authorization and runtime binding have
    // already completed before the scheduler constructs this evidence aggregate.
    let observed = assignment_selection_ledger
        .iter()
        .filter(|entry| entry.role == AgentRole::Worker)
        .filter(|entry| {
            selection_decisions.iter().rev().any(|event| {
                event.role == AgentRole::Worker
                    && event
                        .assignment_id
                        .as_deref()
                        .is_none_or(|assignment_id| assignment_id == entry.assignment_id)
                    && event.attempt == entry.attempt
                    && event.provenance.status == crate::selection::DecisionStatus::Selected
                    && event.provenance.choice.is_some()
            })
        })
        .filter_map(|entry| {
            Some((
                entry.selected_runtime.clone()?,
                entry.selected_model.clone()?,
                entry.selected_reasoning_effort.clone()?,
            ))
        })
        .collect::<BTreeSet<_>>();
    let observed_count = observed.len();
    if observed_count == 0 {
        return None;
    }

    let configured = configured_role_model_selection(plan, AgentRole::Worker);
    let (resolved_model, resolved_reasoning_effort, unavailable_reason) = if observed_count == 1 {
        let (_, model, effort) = observed.into_iter().next()?;
        (Some(model), Some(effort), None)
    } else {
        (
            None,
            None,
            Some(format!(
                "retained Worker selections contain {observed_count} distinct runtime/model/reasoning-effort bindings, so no single aggregate Worker model or reasoning effort is truthful; inspect role_economics_profile.execution.assignment_selection_ledger for each assignment's selected_runtime, selected_model, and selected_reasoning_effort"
            )),
        )
    };
    let configured_model_chain = configured.configured_model_chain();
    Some(ResolvedRoleExecutionBinding {
        configured_model: configured.model,
        configured_reasoning_effort: configured.reasoning_effort,
        resolved_model,
        resolved_reasoning_effort,
        observation: RoleBindingObservation::AssignmentSpecific,
        resolution_observation: ModelResolutionObservation::NotResolved,
        configured_model_chain,
        resolved_candidate_index: None,
        unavailable_reason,
    })
}

fn execution_role_economics_profile(
    plan: &SupervisorPlan,
    runtime: SupervisorRuntime,
    runtime_model_catalog: Option<&RuntimeModelCatalog>,
) -> RoleEconomicsProfile {
    match runtime_model_catalog {
        Some(catalog) => plan.effective_role_economics_profile_for_runtime(catalog),
        None => {
            let mut profile = plan.effective_role_economics_profile();
            profile.model_catalog_observation = RuntimeModelCatalogObservation::ConsultationFailed;
            if runtime == SupervisorRuntime::Fake {
                profile.model_catalog_observation = RuntimeModelCatalogObservation::NotConsulted;
            }
            profile
        }
    }
}

fn supervisor_execution_usage_report(
    total_usage: Option<Usage>,
    total_cost_usd: Option<f64>,
    usage_complete: bool,
) -> SupervisorExecutionUsageReport {
    SupervisorExecutionUsageReport {
        total_usage,
        total_cost_usd,
        usage_complete,
        observation: if total_usage.is_some() {
            RoleUsageObservation::SupervisorAggregate
        } else {
            RoleUsageObservation::NotProcessObservable
        },
        unavailable_reason: if total_usage.is_none() {
            Some(
                "no reliable process-observable child-orchestrator or auditor usage sample was available"
                    .to_string(),
            )
        } else if !usage_complete {
            Some(
                "the aggregate contains observable usage, but one or more launched process samples were missing or unreliable"
                    .to_string(),
            )
        } else if total_cost_usd.is_none() {
            Some(
                "usage was process-observed, but total cost is unavailable because pricing was incomplete"
                    .to_string(),
            )
        } else {
            None
        },
    }
}

const THIS_RUN_ATTEMPT_EVIDENCE_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ThisRunAttemptCostRow {
    assignment_id: String,
    attempt: usize,
    selection: Option<AttemptSelectionBinding>,
    parent_result: Option<OutcomeResult>,
    costs: AttemptAttributableCosts,
}

fn load_this_run_attempt_cost_rows(run_dir: &Path) -> Vec<ThisRunAttemptCostRow> {
    let attempts_dir = run_dir.join("selection-attempts");
    let entries = match std::fs::read_dir(&attempts_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let mut rows = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some((assignment, ordinal)) = name
            .strip_suffix(".json")
            .and_then(|name| name.rsplit_once(".attempt-"))
        else {
            continue;
        };
        let Ok(ordinal) = ordinal.parse::<usize>() else {
            continue;
        };
        let Ok(bytes) =
            read_bounded_regular_file_nofollow(&path, THIS_RUN_ATTEMPT_EVIDENCE_MAX_BYTES)
        else {
            continue;
        };
        let Ok(evidence) = serde_json::from_slice::<AttemptOutcomeEvidence>(&bytes) else {
            continue;
        };
        if evidence.attempt == 0
            || evidence.attempt != ordinal
            || evidence.assignment_id != assignment
        {
            continue;
        }
        rows.push(ThisRunAttemptCostRow {
            assignment_id: evidence.assignment_id,
            attempt: evidence.attempt,
            selection: evidence.selection,
            parent_result: evidence.parent_result,
            costs: evidence.costs,
        });
    }
    rows.sort_by(|left, right| {
        (&left.assignment_id, left.attempt).cmp(&(&right.assignment_id, right.attempt))
    });
    rows
}

fn resolve_this_run_terminal_result(
    row: &ThisRunAttemptCostRow,
    last_attempt: Option<usize>,
    reports: &[OrchestratorReviewReport],
) -> Option<OutcomeResult> {
    if let Some(result) = row.parent_result {
        return Some(result);
    }
    if last_attempt != Some(row.attempt) {
        return None;
    }
    let matches = reports
        .iter()
        .filter(|item| item.id == row.assignment_id)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return None;
    }
    matches.first().and_then(|item| {
        if item.accepted && !item.rejected {
            Some(OutcomeResult::Accepted)
        } else if item.rejected && !item.accepted {
            Some(OutcomeResult::Rejected)
        } else {
            None
        }
    })
}

fn this_run_attempt_cost_records(
    rows: &[ThisRunAttemptCostRow],
    reports: &[OrchestratorReviewReport],
) -> Vec<AttemptCostRecord> {
    let mut last_attempt = BTreeMap::<&str, usize>::new();
    for row in rows {
        last_attempt
            .entry(row.assignment_id.as_str())
            .and_modify(|last| *last = (*last).max(row.attempt))
            .or_insert(row.attempt);
    }
    rows.iter()
        .map(|row| {
            attempt_cost_record(
                row.selection.clone(),
                row.costs.clone(),
                resolve_this_run_terminal_result(
                    row,
                    last_attempt.get(row.assignment_id.as_str()).copied(),
                    reports,
                ),
            )
        })
        .collect()
}

fn this_run_accepted_task_cost(
    rows: &[ThisRunAttemptCostRow],
    reports: &[OrchestratorReviewReport],
) -> Option<AcceptedTaskCostRollup> {
    rollup_cost_per_accepted_task(&this_run_attempt_cost_records(rows, reports)).ok()
}

fn this_run_accepted_task_cost_cohorts(
    rows: &[ThisRunAttemptCostRow],
    reports: &[OrchestratorReviewReport],
) -> Option<AcceptedTaskCostCohorts> {
    rollup_selection_cost_cohorts(&this_run_attempt_cost_records(rows, reports)).ok()
}

fn build_supervisor_final_report(
    construction: SupervisorFinalReportConstruction<'_>,
) -> SupervisorFinalReport {
    let SupervisorFinalReportConstruction {
        plan,
        runtime_model_catalog,
        max_concurrent_children,
        admission_policy_input,
        achieved_concurrency,
        has_multiple_independent_assignment_scopes,
        run_id,
        report_plan_file,
        report_run_dir,
        runtime,
        publishable,
        success,
        run_budget_report,
        budget_degradations,
        assignment_effort_bindings,
        evidence_only_reaudit,
        role_usage,
        review_lens_usage,
        review_lens_total_usage,
        review_lens_total_cost_usd,
        total_usage,
        total_cost_usd,
        usage_complete,
        environment_failures,
        sandbox_denials,
        mut collected,
        this_run_attempt_rows,
        bloated_file_flags,
        decomposition_candidates,
        assignment_traceability,
        coverage_gaps,
        supervisor_breaker_trip,
        autonomy_kpis,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
        external_containment_failed,
        final_primary_integrity_failed,
        budget_prevented_dispatch,
        budget_accounting_failed,
        breaker_tripped,
        field_guide_mutation_failed,
    } = construction;
    let selection_decisions = collected.selection_decisions.clone();
    let generated_follow_up_tasks = collected
        .orchestrator_reports
        .iter()
        .flat_map(|report| report.generated_follow_up_tasks.iter().cloned())
        .collect::<Vec<_>>();
    let generated_follow_up_task_count = generated_follow_up_tasks.len();
    let role_usage = complete_role_usage_reports(role_usage);
    let mut role_economics_profile =
        execution_role_economics_profile(plan, runtime, runtime_model_catalog);
    if has_multiple_independent_assignment_scopes && achieved_concurrency.peak == 1 {
        collected.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: format!(
                "supervisor fan-out collapsed to achieved width 1 across {} planned assignments with multiple independent scopes (resolved configured bound: {max_concurrent_children})",
                plan.assignments.len()
            ),
            paths: Vec::new(),
        });
    }
    let mut assignment_selection_ledger =
        build_assignment_selection_ledger(plan, &selection_decisions, runtime);
    apply_budget_degradations_to_selection_ledger(
        &mut assignment_selection_ledger,
        &budget_degradations,
    );
    let mut recorded_parked_assignments = BTreeSet::new();
    assignment_selection_ledger.retain(|entry| {
        !collected
            .preclaim_parked_assignment_ids
            .contains(&entry.assignment_id)
            || recorded_parked_assignments.insert(entry.assignment_id.clone())
    });
    for entry in &mut assignment_selection_ledger {
        if !collected
            .preclaim_parked_assignment_ids
            .contains(&entry.assignment_id)
        {
            continue;
        }
        entry.attempt = 0;
        entry.selected_runtime = None;
        entry.selected_model = None;
        entry.selected_reasoning_effort = None;
        entry.catalog_source = AssignmentCatalogSource::None;
        entry.catalog_snapshot_digest = None;
        entry.catalog_revisions.clear();
        entry.rejected_candidates.clear();
        entry.quota_evidence = None;
        entry.evidence_gap = Some(
            "assignment parked by the pre-claim viability gate before model or effort selection"
                .to_string(),
        );
    }
    let mut role_bindings = resolved_role_execution_bindings(
        plan,
        runtime,
        runtime_model_catalog,
        &assignment_selection_ledger,
        &selection_decisions,
    );
    if budget_degradations.iter().any(|record| {
        matches!(
            record.change,
            BudgetDegradationChange::ReasoningEffort {
                role: AgentRole::Worker,
                ..
            } | BudgetDegradationChange::ModelTier {
                role: AgentRole::Worker,
                ..
            }
        )
    }) {
        if let Some(binding) = role_bindings
            .get_mut(&AgentRole::Worker)
            .filter(|binding| binding.observation != RoleBindingObservation::AssignmentSpecific)
        {
            binding.resolved_model = None;
            binding.resolved_reasoning_effort = None;
            binding.observation = RoleBindingObservation::AssignmentSpecific;
            binding.resolution_observation = ModelResolutionObservation::NotResolved;
            binding.resolved_candidate_index = None;
            binding.unavailable_reason = Some(
                "mechanical Worker degradation produced assignment-specific model or effort bindings; inspect budget_degradations for the typed trigger and resolved per-assignment policy"
                    .to_string(),
            );
        }
    }
    let (serialized_admission_policy_input, policy_input_unavailable_reason) =
        match serde_json::to_string(&admission_policy_input) {
            Ok(serialized) => (Some(serialized), None),
            Err(error) => (
                None,
                Some(format!(
                    "scheduler could not serialize the observed admission policy input: {error}"
                )),
            ),
        };
    role_economics_profile.execution = Some(SupervisorExecutionMetadata {
        assignment_count: plan.assignments.len(),
        started_assignment_count: achieved_concurrency.started_assignment_count,
        completed_assignment_count: achieved_concurrency.completed_assignment_count,
        concurrency: SupervisorConcurrencyReport {
            configured_max_concurrent_children: max_concurrent_children,
            policy_input_observation: ProcessObservation::SchedulerObserved,
            policy_input: serialized_admission_policy_input,
            policy_input_details: Some(admission_policy_input),
            policy_input_unavailable_reason,
            achieved_max_concurrent_children: achieved_concurrency.peak,
            achieved_mean_concurrent_children: achieved_concurrency.mean,
            achieved_mean_observation: if achieved_concurrency.mean.is_some() {
                ProcessObservation::SchedulerObserved
            } else {
                ProcessObservation::NotProcessObservable
            },
            achieved_mean_unavailable_reason: achieved_concurrency.mean.is_none().then(|| {
                "no assignment execution interval was observed by the scheduler".to_string()
            }),
        },
        role_bindings,
        assignment_effort_bindings,
        budget_degradations,
        selection_decisions: selection_decisions.clone(),
        assignment_selection_ledger,
        accepted_task_cost: this_run_accepted_task_cost(
            &this_run_attempt_rows,
            &collected.orchestrator_reports,
        ),
        accepted_task_cost_cohorts: this_run_accepted_task_cost_cohorts(
            &this_run_attempt_rows,
            &collected.orchestrator_reports,
        ),
        usage: supervisor_execution_usage_report(total_usage, total_cost_usd, usage_complete),
    });
    SupervisorFinalReport {
        version: SUPERVISOR_SCHEMA_VERSION,
        run_id,
        role: AgentRole::Supervisor,
        repo: PathBuf::from("."),
        plan_file: report_plan_file,
        run_dir: report_run_dir,
        runtime,
        publishable,
        success,
        accepted: publishable,
        rejected: !success,
        status: if success {
            ReviewStatus::Succeeded
        } else {
            ReviewStatus::Failed
        },
        run_lifecycle: SupervisorRunLifecycle::Finalized,
        evidence_only_reaudit: evidence_only_reaudit.map(|operation| EvidenceOnlyReauditRecord {
            source_run_id: operation.source_run_id,
            assignment_id: operation.assignment_id,
            attempt: operation.attempt,
            preserved_candidate_binding: operation.preserved_candidate_binding,
            accepted: success,
        }),
        assigned_paths: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.assigned_paths.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        semantic_symbols: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.semantic_symbols.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        semantic_modules: plan
            .assignments
            .iter()
            .flat_map(|assignment| assignment.semantic_modules.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        claim_tokens: released_claims
            .iter()
            .map(|claim| claim.token.get())
            .collect(),
        semantic_intent_tokens: released_semantic_intents
            .iter()
            .map(|intent| intent.token.get())
            .collect(),
        role_economics_profile: Some(role_economics_profile),
        run_budget: run_budget_report,
        role_usage,
        review_lens_usage,
        review_lens_total_usage,
        review_lens_total_cost_usd,
        total_usage,
        total_cost_usd,
        usage_complete,
        commands_run: collected.command_records,
        environment_failures: environment_failures.clone(),
        sandbox_denials,
        gate_denials: collected.gate_denials,
        pre_action_review_metrics: collected.pre_action_review_metrics,
        gate_correction_outcomes: collected.gate_correction_outcomes,
        autonomy_kpis,
        files_changed: collected
            .orchestrator_reports
            .iter()
            .flat_map(|report| report.files_changed.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        validation_results: collected
            .orchestrator_reports
            .iter()
            .flat_map(|report| report.validation_results.iter().cloned())
            .collect(),
        findings: collected.findings,
        bloated_file_flags,
        decomposition_candidates,
        generated_follow_up_tasks,
        assignment_traceability,
        coverage_gaps: coverage_gaps.clone(),
        breaker_trip: supervisor_breaker_trip,
        orchestrator_reports: collected.orchestrator_reports,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
        remaining_risk: if success && generated_follow_up_task_count > 0 && !publishable {
            format!(
                "{}; {generated_follow_up_task_count} generated dependent update task(s) remain deferred and must be regenerated by an accepted publishable run",
                nonpublishable_success_guidance(runtime).0
            )
        } else if success && generated_follow_up_task_count > 0 {
            format!(
                "the breaking assignments completed under accepted narrow licenses; {generated_follow_up_task_count} complete generated dependent update plan(s) are eligible for the authenticated command-level queue, whose separate cascade outcome determines whether dispatch occurred"
            )
        } else if success && !publishable {
            nonpublishable_success_guidance(runtime).0.to_string()
        } else if success && !coverage_gaps.is_empty() {
            format!(
                "all child reports passed, but {} spec-to-diff traceability coverage gap(s) remain; worker changes remain isolated in child worktrees",
                coverage_gaps.len()
            )
        } else if success {
            "no failed child orchestrator reports; worker changes remain isolated in child worktrees"
                .to_string()
        } else if !environment_failures.is_empty() {
            "the supervisor or one or more assignments were blocked by a structured environment failure"
                .to_string()
        } else if external_containment_failed {
            "one or more external agent process trees lacked verified-empty containment; delayed child activity cannot be ruled out"
                .to_string()
        } else if final_primary_integrity_failed {
            "primary worktree final integrity could not be established".to_string()
        } else if budget_prevented_dispatch || budget_accounting_failed {
            "run budget enforcement stopped new dispatch or could not prove reliable accounting; already-started work was drained and assignment resources were released"
                .to_string()
        } else if breaker_tripped {
            "the swarm-health circuit breaker stopped pending assignment admission after a repeated coordination failure"
                .to_string()
        } else if field_guide_mutation_failed {
            "field-guide mutation or strict journal provenance did not complete; planned evidence may require manual reconciliation"
                .to_string()
        } else {
            "one or more child or worker reports failed, were rejected, or were missing".to_string()
        },
        next_safe_action: if success && generated_follow_up_task_count > 0 && !publishable {
            nonpublishable_success_guidance(runtime).1.to_string()
        } else if success && generated_follow_up_task_count > 0 {
            "inspect the authenticated follow-up queue and cascade outcome; any admitted generated plan still passes ordinary claims, budget admission, checkpoints, child gates, and review lenses"
                .to_string()
        } else if success && !publishable {
            nonpublishable_success_guidance(runtime).1.to_string()
        } else if success && !coverage_gaps.is_empty() {
            "inspect traceability coverage_gaps and child worktree diffs before any separate merge preview or apply step"
                .to_string()
        } else if success {
            "review child worktree diffs before any separate merge preview or apply step"
                .to_string()
        } else if !environment_failures.is_empty() {
            "apply the structured environment remediation without auto-installing software, injecting secrets, enabling networking, or broadening confinement, then rerun the blocked preflight"
                .to_string()
        } else if external_containment_failed {
            "do not trust or merge child outputs; restore the primary worktree if needed, fix host containment support, and rerun supervise"
                .to_string()
        } else if final_primary_integrity_failed {
            "inspect and restore the primary worktree before rerunning supervise".to_string()
        } else if budget_prevented_dispatch || budget_accounting_failed {
            "inspect run_budget reasons and per-role attribution, then raise the configured ceiling, repair pricing/usage accounting, or explicitly narrow the next run"
                .to_string()
        } else if breaker_tripped {
            BREAKER_RECOVERY_GUIDANCE.to_string()
        } else if field_guide_mutation_failed {
            "inspect strict field-guide planned/committed journal evidence and authenticated state before any manual retry"
                .to_string()
        } else {
            "inspect run reports and rerun failed child scopes after correcting the issue"
                .to_string()
        },
        executable: Some(crate::build_identity::ExecutableBuildIdentity::compiled()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleasedSchedulerResources {
    released_claims: Vec<PathClaim>,
    release_errors: Vec<String>,
    released_semantic_intents: Vec<SemanticIntent>,
    semantic_release_errors: Vec<String>,
}

#[derive(Default)]
struct CollectedSchedulerResources {
    acquired_claim_tokens: Vec<ClaimToken>,
    acquired_semantic_tokens: Vec<crate::semantic_coord::SemanticIntentToken>,
    concurrently_released_claims: Vec<PathClaim>,
    concurrent_release_errors: Vec<String>,
    concurrently_released_semantic_intents: Vec<SemanticIntent>,
    concurrent_semantic_release_errors: Vec<String>,
}

impl CollectedSchedulerResources {
    fn take_from(collected: &mut CollectedAssignmentOutcomes) -> Self {
        Self {
            acquired_claim_tokens: std::mem::take(&mut collected.acquired_claim_tokens),
            acquired_semantic_tokens: std::mem::take(&mut collected.acquired_semantic_tokens),
            concurrently_released_claims: std::mem::take(
                &mut collected.concurrently_released_claims,
            ),
            concurrent_release_errors: std::mem::take(&mut collected.concurrent_release_errors),
            concurrently_released_semantic_intents: std::mem::take(
                &mut collected.concurrently_released_semantic_intents,
            ),
            concurrent_semantic_release_errors: std::mem::take(
                &mut collected.concurrent_semantic_release_errors,
            ),
        }
    }
}

fn planned_collected_scheduler_resources(
    sync_store: Option<&SyncStore>,
    semantic_store: Option<&SemanticIntentStore>,
    collected: &CollectedSchedulerResources,
) -> Result<ReleasedSchedulerResources> {
    let mut released_claims = match sync_store {
        Some(store) => planned_claim_releases(store, &collected.acquired_claim_tokens)?,
        None if collected.acquired_claim_tokens.is_empty() => Vec::new(),
        None => bail!("supervisor sync store is unavailable for terminal claim cleanup"),
    };
    released_claims.extend(collected.concurrently_released_claims.iter().cloned());
    let mut released_semantic_intents = match semantic_store {
        Some(store) => {
            planned_semantic_intent_releases(store, &collected.acquired_semantic_tokens)?
        }
        None if collected.acquired_semantic_tokens.is_empty() => Vec::new(),
        None => bail!("supervisor semantic store is unavailable for terminal intent cleanup"),
    };
    released_semantic_intents.extend(
        collected
            .concurrently_released_semantic_intents
            .iter()
            .cloned(),
    );
    Ok(ReleasedSchedulerResources {
        released_claims,
        release_errors: collected.concurrent_release_errors.clone(),
        released_semantic_intents,
        semantic_release_errors: collected.concurrent_semantic_release_errors.clone(),
    })
}

fn release_collected_scheduler_resources(
    sync_store: Option<&SyncStore>,
    semantic_store: Option<&SemanticIntentStore>,
    collected: &mut CollectedSchedulerResources,
) -> ReleasedSchedulerResources {
    let (mut released_claims, mut release_errors) = match sync_store {
        Some(store) => release_claims(store, std::mem::take(&mut collected.acquired_claim_tokens)),
        None => (Vec::new(), Vec::new()),
    };
    released_claims.extend(std::mem::take(&mut collected.concurrently_released_claims));
    release_errors.extend(std::mem::take(&mut collected.concurrent_release_errors));
    let (mut released_semantic_intents, mut semantic_release_errors) = match semantic_store {
        Some(store) => release_semantic_intents(
            store,
            std::mem::take(&mut collected.acquired_semantic_tokens),
        ),
        None => (Vec::new(), Vec::new()),
    };
    released_semantic_intents.extend(std::mem::take(
        &mut collected.concurrently_released_semantic_intents,
    ));
    semantic_release_errors.extend(std::mem::take(
        &mut collected.concurrent_semantic_release_errors,
    ));
    ReleasedSchedulerResources {
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    }
}

fn supervisor_report_paths(
    repo: &Path,
    plan_file: &Path,
    run_dir: &Path,
    run_id: &RunId,
) -> (PathBuf, PathBuf) {
    let report_plan_file = plan_file
        .strip_prefix(repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| PathBuf::from("<external-plan>"));
    let report_run_dir = run_dir
        .strip_prefix(repo)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| {
            RunArtifactFamily::Supervise
                .run_root()
                .join(run_id.as_str())
        });
    (report_plan_file, report_run_dir)
}

fn require_live_supervisor_final_profile_and_scores(report: &SupervisorFinalReport) -> Result<()> {
    let profile = report
        .role_economics_profile
        .as_ref()
        .context("newly finalized supervisor reports require role_economics_profile")?;
    let resolved = profile
        .resolved_objective_profile
        .as_ref()
        .context("newly finalized supervisor reports require resolved_objective_profile")?;
    resolved
        .profile
        .validate()
        .context("newly finalized supervisor reports require a valid resolved_objective_profile")?;
    if let Some(execution) = profile.execution.as_ref() {
        for event in &execution.selection_decisions {
            event
                .provenance
                .resolved_objective_profile
                .profile
                .validate()
                .context(
                    "newly finalized supervisor reports require scored selector profile evidence",
                )?;
        }
    }
    Ok(())
}

fn persist_supervisor_final_report(
    mut final_report: SupervisorFinalReport,
    orchestration_journal: &mut Option<OrchestrationEventJournal>,
    mut artifact_writer: ArtifactRunWriter,
    checkpoint_writer: Option<&mut SupervisorCheckpointWriter>,
    invocation_scratch_quiescence: Option<crate::artifacts::ArtifactScratchQuiescence>,
    release_after_terminal_record: impl FnOnce() -> Result<()>,
) -> Result<SupervisorFinalReport> {
    if let Some(quiescence) = invocation_scratch_quiescence {
        // Incoming/capture trees are identity-bound reservations counted by the
        // artifact writer, even when a post-reservation admission check returns
        // before the normal import/discard path. This terminal boundary receives
        // proof only after every invocation has joined (or no child launched), so
        // it can discard those run-owned trees without weakening the gate for
        // unverified or foreign scratch.
        artifact_writer
            .discard_supervisor_invocation_scratches_after_quiescence(quiescence)
            .context("failed to discard quiescent supervisor invocation scratches")?;
    }
    enforce_supervisor_final_environment_failure_outcome(&mut final_report);
    record_orchestration_event(
        orchestration_journal,
        &mut artifact_writer,
        final_report.run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Gate,
        json!({
            "success": final_report.success,
            "publishable": final_report.publishable,
            "accepted": final_report.accepted,
            "rejected": final_report.rejected,
            "breaker_trip": final_report.breaker_trip,
            "run_budget": final_report.run_budget,
            "autonomy_kpis": final_report.autonomy_kpis,
        }),
    );
    record_orchestration_event(
        orchestration_journal,
        &mut artifact_writer,
        final_report.run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Status,
        json!({
            "status": "final",
            "result": final_report.status,
            "success": final_report.success,
            "run_budget": final_report.run_budget,
            "autonomy_kpis": final_report.autonomy_kpis,
        }),
    );
    if !orchestration_journal_observable(orchestration_journal) {
        final_report.autonomy_kpis = AutonomyKpiReport::not_process_observable();
        if let Some(trip) = &mut final_report.breaker_trip {
            trip.autonomy_kpis = final_report.autonomy_kpis.clone();
        }
    }
    #[cfg(test)]
    run_before_supervisor_final_report_persist_hook(&mut final_report);
    require_live_supervisor_final_profile_and_scores(&final_report)?;
    crate::run_ops::append_run_heartbeat_best_effort(
        &mut artifact_writer,
        "finalizing",
        None,
        if final_report.success { "ok" } else { "failed" },
        None,
    );
    crate::run_ops::write_operator_summary(
        &mut artifact_writer,
        &render_supervisor_operator_summary(&final_report),
    )?;
    let report_bytes = encode_final_report(&final_report)?;
    let mut checkpoint_writer = checkpoint_writer;
    if let Some(checkpoint) = checkpoint_writer.as_deref_mut() {
        let artifact_binding = artifact_writer
            .resume_binding()
            .context("failed to establish a durable terminal supervisor report boundary")?;
        checkpoint
            .final_report_planned(&final_report, &report_bytes, artifact_binding)
            .context("failed to persist the terminal supervisor report plan")?;
    }
    release_after_terminal_record()
        .context("failed to release scheduler resources after the durable terminal record")?;
    artifact_writer
        .write_bytes(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &report_bytes,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .context("failed to write normalized supervisor final report")?;
    write_selection_ledger_from_report(&mut artifact_writer, &final_report)?;
    if let Some(checkpoint) = checkpoint_writer.as_deref_mut() {
        checkpoint.final_report_committed(
            &final_report,
            &report_bytes,
            artifact_writer.resume_binding()?,
        )?;
        checkpoint.finalization_started(&final_report, &report_bytes)?;
    }
    artifact_writer.finalize(
        RunArtifactFamily::Supervise.final_report_relative_path(),
        final_report.publishable,
    )?;
    if let Some(checkpoint) = checkpoint_writer {
        checkpoint.finalized(&final_report, &report_bytes)?;
    }
    Ok(final_report)
}

struct SchedulerEvidenceInitialization<'context> {
    plan: &'context SupervisorPlan,
    consultant: &'context SupervisorConsultantPlan,
    assignment_metadata: &'context AssignmentMetadata,
    plan_metadata: &'context SupervisorPlanMetadata,
    options: &'context SupervisorRunOptions,
    repo: &'context Path,
    execution_runtime: SupervisorExecutionRuntime,
    execution_target: Option<&'context SupervisorExecutionTarget>,
    artifact_writer: &'context mut ArtifactRunWriter,
    field_guide_store_slot: &'context mut Option<FieldGuideStore>,
    field_guide_prompt_slot: &'context mut Option<SupervisorFieldGuidePrompt>,
    sync_store_slot: &'context mut Option<SyncStore>,
    semantic_store_slot: &'context mut Option<SemanticIntentStore>,
    orchestration_journal: &'context mut Option<OrchestrationEventJournal>,
    primary_run_baseline: &'context mut Option<PrimaryWorktreeSnapshot>,
}

fn initialize_scheduler_evidence(
    initialization: &mut SchedulerEvidenceInitialization<'_>,
) -> Result<()> {
    if initialization.execution_target.is_none() && !initialization.options.allow_dirty_primary {
        ensure_clean_primary(initialization.repo, initialization.execution_runtime)?;
    }
    write_plan_snapshot(
        initialization.artifact_writer,
        Path::new("assignments/supervisor-plan.json"),
        initialization.plan,
        initialization.consultant,
        initialization.assignment_metadata,
        initialization.plan_metadata,
    )?;
    write_orchestrator_schema(
        initialization.artifact_writer,
        Path::new("schemas/orchestrator-review-report.schema.json"),
    )?;
    write_codex_orchestrator_schema(
        initialization.artifact_writer,
        Path::new("schemas/orchestrator-review-report.codex-output.schema.json"),
    )?;
    write_worker_schema(
        initialization.artifact_writer,
        Path::new("schemas/worker-report.schema.json"),
    )?;
    if initialization
        .plan
        .assignments
        .iter()
        .any(|assignment| assignment.role == AgentRole::Researcher)
    {
        write_researcher_schemas(initialization.artifact_writer)?;
    }
    write_codex_worker_schema(
        initialization.artifact_writer,
        Path::new("schemas/worker-report.codex-output.schema.json"),
    )?;
    write_auditor_schema(
        initialization.artifact_writer,
        Path::new("schemas/auditor-report.schema.json"),
    )?;
    write_codex_auditor_schema(
        initialization.artifact_writer,
        Path::new("schemas/auditor-report.codex-output.schema.json"),
    )?;
    write_supervisor_final_schema(
        initialization.artifact_writer,
        Path::new("schemas/supervisor-final-report.schema.json"),
    )?;
    let field_guide_store = FieldGuideStore::open(initialization.repo, FieldGuideLimits::default())
        .context("failed to open authenticated field guide for supervise run")?;
    let field_guide_prompt = SupervisorFieldGuidePrompt::from_store(&field_guide_store)?;
    *initialization.field_guide_store_slot = Some(field_guide_store);
    *initialization.field_guide_prompt_slot = Some(field_guide_prompt);
    *initialization.sync_store_slot = Some(SyncStore::open(initialization.repo)?);
    *initialization.semantic_store_slot = Some(SemanticIntentStore::open(initialization.repo)?);
    *initialization.orchestration_journal = initialize_orchestration_event_journal(
        initialization.repo,
        &initialization.options.run_id,
        initialization.options.parent_node.as_deref(),
    );
    let run_id = initialization.options.run_id.as_str();
    let parent_node = initialization.options.parent_node.as_deref();
    let supervisor_spawn_payload = if let Some(parent) = parent_node {
        record_supervision_spawn_payload(
            run_id,
            parent,
            OrchestrationRole::Supervisor,
            AgentRole::Supervisor,
            Vec::new(),
            &run_scope_ref(run_id),
            json!({}),
        )?
    } else {
        json!({})
    };
    record_orchestration_event(
        initialization.orchestration_journal,
        initialization.artifact_writer,
        run_id,
        parent_node,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Spawn,
        supervisor_spawn_payload,
    );
    record_gate_ownership(
        initialization.orchestration_journal,
        initialization.artifact_writer,
        run_id,
        parent_node,
        OrchestrationRole::Supervisor,
        &GateOwnershipRecord::assign(
            run_id,
            run_id,
            OrchestrationRole::Supervisor,
            "supervisor",
            "run_acceptance_gate",
        )?,
    );
    record_orchestration_event(
        initialization.orchestration_journal,
        initialization.artifact_writer,
        run_id,
        parent_node,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Status,
        lifecycle_event_payload("running", None, None),
    );

    let baseline = supervisor_primary_worktree_snapshot(
        initialization.repo,
        initialization.execution_runtime,
    )?;
    if let Some(error) = baseline.inspection_problem() {
        bail!(
            "refusing to launch supervised work without a complete primary integrity snapshot: {error}"
        );
    }
    *initialization.primary_run_baseline = Some(baseline);
    Ok(())
}

fn evaluate_supervisor_preclaims(
    plan: &SupervisorPlan,
    requested_plan: &SupervisorPlan,
    evidence: &PreclaimRunEvidence,
) -> Vec<PreclaimDecision> {
    plan.assignments
        .iter()
        .map(|assignment| evidence.evaluate(assignment, &requested_plan.assignments))
        .collect()
}

fn acquire_supervisor_preclaim_evidence(
    repo: &Path,
    runtime: SupervisorRuntime,
    execution_runtime: SupervisorExecutionRuntime,
    requested_plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
    assignment_metadata: &AssignmentMetadata,
    plan_metadata: &SupervisorPlanMetadata,
) -> Result<PreclaimRunEvidence> {
    let mut evidence = supervisor_preclaim_run_evidence(repo, runtime, execution_runtime)
        .with_assignment_metadata(assignment_metadata);
    if !assignment_metadata.authored_independent_checks.is_empty() {
        let document = super::plan_api::supervisor_plan_value(
            requested_plan,
            consultant,
            assignment_metadata,
            plan_metadata,
        )?
        .to_string();
        evidence = evidence.with_authored_checks(
            repo,
            document,
            &requested_plan.assignments,
            assignment_metadata,
        );
    }
    Ok(evidence)
}

fn supervisor_preclaim_run_evidence(
    repo: &Path,
    runtime: SupervisorRuntime,
    execution_runtime: SupervisorExecutionRuntime,
) -> PreclaimRunEvidence {
    #[cfg(test)]
    if let Some(evidence) = take_supervisor_preclaim_run_evidence() {
        return evidence;
    }
    PreclaimRunEvidence::acquire(repo, runtime, execution_runtime)
}

fn supervisor_primary_worktree_snapshot(
    repo: &Path,
    execution_runtime: SupervisorExecutionRuntime,
) -> Result<PrimaryWorktreeSnapshot> {
    #[cfg(test)]
    if let Some(snapshot) = take_supervisor_primary_worktree_snapshot() {
        return Ok(snapshot);
    }
    primary_worktree_snapshot(repo, execution_runtime)
}

/// Derive viability-assessment runtime independently of effect containment.
///
/// Production plan-file and follow-up entry points always execute through
/// `Verified` + `Bound`, including `--runtime fake`. Fake never supplies
/// production map/risk verification evidence, so assessment uses the same
/// synthetic simulation path the scheduler family already uses. Codex +
/// `Verified` stays strict outside tests. Test `Bound`/`PrimaryWorktree`
/// fixtures inject runners to exercise containment, not production viability
/// evidence; `VerifiedTestOnly` remains the real pre-claim acceptance boundary.
fn preclaim_assessment_runtime(
    runtime: SupervisorRuntime,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
) -> SupervisorExecutionRuntime {
    if runtime == SupervisorRuntime::Fake {
        return SupervisorExecutionRuntime::NonpublishableSimulation;
    }

    #[cfg(test)]
    if matches!(
        worktree_creation,
        SupervisorWorktreeCreation::Bound(_)
            | SupervisorWorktreeCreation::BoundSourceHead(_, _)
            | SupervisorWorktreeCreation::PrimaryWorktree
    ) {
        return SupervisorExecutionRuntime::NonpublishableSimulation;
    }

    #[cfg(not(test))]
    let _ = worktree_creation;

    execution_runtime
}

fn persist_prepared_preclaim_decisions(
    repo: &Path,
    run_id: &RunId,
    parent_node: Option<&str>,
    artifact_writer: &mut ArtifactRunWriter,
    assignments: &[OrchestratorAssignment],
    decisions: &[PreclaimDecision],
) -> Result<()> {
    if assignments.len() != decisions.len() {
        bail!(
            "cannot persist {} pre-claim decisions for {} assignments",
            decisions.len(),
            assignments.len()
        );
    }
    let mut journal = initialize_orchestration_event_journal(repo, run_id, parent_node);
    let mut autonomy_kpis = AutonomyKpiCollector::default();
    let artifacts = Mutex::new(SharedSupervisorArtifacts {
        writer: artifact_writer,
        journal: &mut journal,
        autonomy_kpis: &mut autonomy_kpis,
        checkpoint: None,
    });
    for (assignment, decision) in assignments.iter().zip(decisions) {
        persist_preclaim_decision(&artifacts, assignment, decision)?;
    }
    Ok(())
}

fn resolve_preselection_objective_profile(
    repo: &Path,
    plan_metadata: &mut SupervisorPlanMetadata,
) -> Result<()> {
    if plan_metadata.resolved_objective_profile.is_none() {
        let requested_objective_profile = plan_metadata.objective_profile.clone();
        plan_metadata.resolved_objective_profile = Some(
            resolve_objective_profile(repo, requested_objective_profile.as_deref())
                .context("failed to resolve the supervisor objective profile")?,
        );
    }
    Ok(())
}

fn no_dispatch_selection_resolution(
    plan: &SupervisorPlan,
    runtime: SupervisorRuntime,
    execution_runtime: SupervisorExecutionRuntime,
) -> SupervisorSelectionResolution {
    let mode = if execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation {
        SupervisorSelectionMode::LegacyNonpublishableSimulation
    } else if runtime == SupervisorRuntime::Fake {
        SupervisorSelectionMode::LegacyFake
    } else if plan.role_models.is_empty() {
        SupervisorSelectionMode::Automatic
    } else {
        SupervisorSelectionMode::DebugOverride
    };
    SupervisorSelectionResolution {
        mode,
        decisions: Vec::new(),
        automatic_state: None,
        selection_preflight_failure: None,
    }
}

struct PreparedSupervisorRun {
    /// Selector-resolved execution plan. Only pre-claim-viable assignments may
    /// receive selector-bound assignment runtime state.
    plan: SupervisorPlan,
    /// Original caller plan used for artifact identity and follow-up inheritance.
    requested_plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    assignment_metadata: AssignmentMetadata,
    plan_metadata: SupervisorPlanMetadata,
    max_concurrent_children: usize,
    admission_policy_input: SupervisorAdmissionPolicyInput,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
    selection_mode: SupervisorSelectionMode,
    selection_decisions: Vec<SupervisorSelectionEvent>,
    selection_preflight_failure: Option<SupervisorSelectionPreflightFailure>,
    automatic_selection_state: Option<SupervisorAutomaticSelectionState>,
    preclaim_decisions: Vec<PreclaimDecision>,
    preclaim_evidence: PreclaimRunEvidence,
    budget_ledger: RunBudgetLedger,
    runtime: SupervisorRuntime,
    repo: PathBuf,
    assignment_schedule: Vec<AssignmentScheduleEntry>,
    evidence_only_reaudit: Option<EvidenceOnlyReauditSource>,
    artifact_writer: ArtifactRunWriter,
    checkpoint_writer: SupervisorCheckpointWriter,
    run_dir: PathBuf,
    dirs: RunDirs,
    manager: WorktreeManager,
    _process_registration: Option<crate::run_ops::SupervisorProcessGuard>,
}

fn prepare_supervisor_run(
    loaded: LoadedSupervisorPlan,
    options: &SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
) -> Result<PreparedSupervisorRun> {
    assignment_executor::validate_assignment_executors_pre_dispatch(&loaded.assignment_metadata)?;
    let LoadedSupervisorPlan {
        mut plan,
        consultant,
        assignment_metadata,
        mut plan_metadata,
    } = loaded;
    validate_max_concurrent_children(max_concurrent_children)?;
    match worktree_creation {
        SupervisorWorktreeCreation::Bound(_)
        | SupervisorWorktreeCreation::BoundSourceHead(_, _)
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("verified worktree creation capability requires the verified supervisor runtime")
        }
        SupervisorWorktreeCreation::ExistingOnly
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("existing-only worktree execution requires the verified supervisor runtime")
        }
        SupervisorWorktreeCreation::PrimaryWorktree
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("primary-worktree execution requires the verified supervisor runtime")
        }
        SupervisorWorktreeCreation::NonpublishableSimulation
            if execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation =>
        {
            bail!(
                "nonpublishable-simulation worktree creation requires the simulation supervisor runtime"
            )
        }
        #[cfg(test)]
        SupervisorWorktreeCreation::TestOnly
            if execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation =>
        {
            bail!("test-only worktree creation requires the simulation supervisor runtime")
        }
        #[cfg(test)]
        SupervisorWorktreeCreation::VerifiedTestOnly
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("verified test-only worktree creation requires the verified supervisor runtime")
        }
        _ => {}
    }
    if execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation
        && !worktree_creation.is_nonpublishable_simulation()
    {
        bail!("simulation supervisor runtime requires nonpublishable-simulation worktree creation");
    }
    match (worktree_creation, plan_metadata.execution_target.as_ref()) {
        (
            SupervisorWorktreeCreation::PrimaryWorktree,
            Some(SupervisorExecutionTarget::PrimaryWorktree { .. }),
        ) => {}
        (SupervisorWorktreeCreation::PrimaryWorktree, None) => {
            bail!("primary-worktree execution requires its validated plan declaration")
        }
        (_, Some(SupervisorExecutionTarget::PrimaryWorktree { .. })) => {
            bail!("primary-worktree plan declaration cannot use managed-child execution")
        }
        (_, None) => {}
    }
    let runtime = options.runtime;
    if matches!(
        worktree_creation,
        SupervisorWorktreeCreation::NonpublishableSimulation
    ) && runtime != SupervisorRuntime::Fake
    {
        bail!("nonpublishable-simulation worktree creation requires the Fake supervisor runtime");
    }
    let repo = discover_repo_root(&options.repo)?;
    super::prior_input::require_binding_repo(&repo)?;
    super::runtime_executables::require_binding_repo_run(&repo, &options.run_id)?;
    let requested_plan = plan.clone();
    let collision = crate::run_ops::refuse_live_run_collision(
        &repo,
        RunArtifactFamily::Supervise,
        &options.run_id,
        options.allow_live_run_collision,
    )?;
    let process_registration =
        crate::run_ops::register_current_supervisor_process(&repo, "supervise", &options.run_id)
            .ok()
            .flatten();
    let mut artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        options.run_id.clone(),
        "maco-supervise",
    )?;
    let preflight_spec = crate::run_ops::LaunchPreflightSpec {
        family: RunArtifactFamily::Supervise,
        run_id: options.run_id.clone(),
        runtime: crate::runtime_adapter::AdapterId::from_runtime(options.runtime)
            .as_str()
            .to_string(),
        runtime_bin: Some(options.codex_bin.clone()),
        allow_dirty_primary: options.allow_dirty_primary,
        allow_live_run_collision: options.allow_live_run_collision,
    };
    crate::run_ops::persist_launch_preflight(
        &mut artifact_writer,
        &repo,
        &preflight_spec,
        &collision,
    )?;
    if let Some(head) = worktree_creation.expected_source_head() {
        artifact_writer.write_json(
            INBOX_PR_SOURCE_HEAD_MARKER,
            &InboxPrSourceHeadMarker::new(&options.run_id, head),
            ArtifactFileDisposition::PrivateEvidence,
        )?;
    }
    crate::run_ops::append_run_heartbeat_best_effort(
        &mut artifact_writer,
        "initialized",
        None,
        "ok",
        None,
    );
    // The acceptance gate is evaluated from immutable assignment evidence before
    // selector, quota-ledger attachment, or assignment admission policy state can
    // affect the run. Persist every decision immediately after evaluation so any
    // later preparation failure still leaves durable gate evidence.
    let preclaim_runtime =
        preclaim_assessment_runtime(runtime, execution_runtime, worktree_creation);
    let preclaim_evidence = acquire_supervisor_preclaim_evidence(
        &repo,
        runtime,
        preclaim_runtime,
        &requested_plan,
        &consultant,
        &assignment_metadata,
        &plan_metadata,
    )?;
    let preclaim_decisions =
        evaluate_supervisor_preclaims(&plan, &requested_plan, &preclaim_evidence);
    persist_prepared_preclaim_decisions(
        &repo,
        &options.run_id,
        options.parent_node.as_deref(),
        &mut artifact_writer,
        &requested_plan.assignments,
        &preclaim_decisions,
    )?;
    super::prior_input::archive_current(&mut artifact_writer, &repo)?;
    super::runtime_executables::archive_current(&mut artifact_writer, &repo, &options.run_id)?;
    let mut budget_ledger = RunBudgetLedger::new_composed(
        plan_metadata.run_budget.limits,
        options.budget_overrides,
        plan_metadata.run_budget_max_duration_seconds,
        options.budget_max_duration_seconds,
    )
    .context("failed to initialize the supervise run budget ledger")?;
    plan_metadata.run_budget.limits = budget_ledger.effective_limits();
    let quota_context = live_quota_context_for_run(&repo)?;
    if quota_context.is_some() && runtime == SupervisorRuntime::Fake {
        bail!("operator quota config is not valid for the nonpublishable Fake supervisor runtime");
    }
    if let Some(quota_context) = &quota_context {
        budget_ledger
            .attach_quota_config(&repo, options.run_id.as_str(), &quota_context.config)
            .context("failed to attach operator quota config to the run budget ledger")?;
    }
    let admission_policy_input = SupervisorAdmissionPolicyInput::resolve_with_quota(
        &repo,
        max_concurrent_children,
        plan_metadata.admission,
        options.admission_overrides,
        quota_context.as_ref(),
    )?;
    let max_concurrent_children = admission_policy_input.resolved_bound;
    resolve_preselection_objective_profile(&repo, &mut plan_metadata)?;
    let mut selector_plan = plan.clone();
    selector_plan.assignments = selector_plan
        .assignments
        .into_iter()
        .zip(&preclaim_decisions)
        .filter_map(|(assignment, decision)| decision.allows_path_claim().then_some(assignment))
        .collect();
    let selection = if selector_plan.assignments.is_empty() {
        no_dispatch_selection_resolution(&plan, runtime, execution_runtime)
    } else {
        initialize_supervisor_selection_from_prepared_metadata(
            &mut selector_plan,
            &mut plan_metadata,
            PreparedSupervisorSelectionRequest {
                repo: &repo,
                current_run: Some(&options.run_id),
                runtime,
                execution_runtime,
                runtime_model_catalog: &runtime_model_catalog,
                admission_policy_input: &admission_policy_input,
                quota: SupervisorQuotaSelectionInput {
                    context: quota_context.as_ref(),
                    ledger: quota_context.as_ref().map(|_| &budget_ledger),
                },
            },
        )?
    };
    if selection.selection_preflight_failure.is_none() && !selector_plan.assignments.is_empty() {
        plan.role_models = selector_plan.role_models;
        plan.review_lenses = selector_plan.review_lenses;
        let mut selected_viable_assignments = selector_plan.assignments.iter();
        for (assignment, decision) in plan.assignments.iter_mut().zip(&preclaim_decisions) {
            if !decision.allows_path_claim() {
                continue;
            }
            let selected = selected_viable_assignments.next().with_context(|| {
                format!(
                    "selector-resolved viable assignment list ended before assignment '{}'",
                    assignment.id
                )
            })?;
            if selected.id != assignment.id {
                bail!(
                    "selector-resolved viable assignment '{}' does not match original assignment '{}'",
                    selected.id,
                    assignment.id
                );
            }
            assignment.runtime = selected.runtime;
        }
        if selected_viable_assignments.next().is_some() {
            bail!("selector-resolved viable assignment list contains an unmatched assignment");
        }
    }
    let evidence_only_reaudit = plan_metadata
        .evidence_only_reaudit
        .as_ref()
        .map(|operation| {
            let assignment = plan
                .assignments
                .first()
                .context("evidence-only re-audit plan has no assignment")?;
            verify_evidence_only_reaudit_source(
                &repo,
                operation,
                assignment,
                plan_metadata.task_routing_assessment.as_ref(),
            )
        })
        .transpose()?;
    let assignment_schedule = validated_scheduler_assignment_schedule(&plan, &plan_metadata)?;
    let primary_base = current_head_oid(&repo)?;
    let normalized_plan_sha256 = normalized_supervisor_plan_sha256(
        &requested_plan,
        &consultant,
        &assignment_metadata,
        &plan_metadata,
    )?;
    let checkpoint_writer = SupervisorCheckpointWriter::create(
        &repo,
        SupervisorCheckpointPreparation::new(
            &options.run_id,
            &primary_base,
            normalized_plan_sha256,
            max_concurrent_children,
            &requested_plan,
            artifact_writer.resume_binding()?,
            budget_ledger.report()?,
        )
        .with_inbox_pr_source_head(worktree_creation.expected_source_head()),
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    let dirs = RunDirs::for_writer(&artifact_writer);
    let manager = WorktreeManager::new(&repo);
    Ok(PreparedSupervisorRun {
        plan,
        requested_plan,
        consultant,
        assignment_metadata,
        plan_metadata,
        max_concurrent_children,
        admission_policy_input,
        runtime_model_catalog,
        selection_mode: selection.mode,
        selection_decisions: selection.decisions,
        selection_preflight_failure: selection.selection_preflight_failure,
        automatic_selection_state: selection.automatic_state,
        preclaim_decisions,
        preclaim_evidence,
        budget_ledger,
        runtime,
        repo,
        assignment_schedule,
        evidence_only_reaudit,
        artifact_writer,
        checkpoint_writer,
        run_dir,
        dirs,
        manager,
        _process_registration: process_registration,
    })
}

pub(super) struct PreparedSupervisorSelectionRequest<'a> {
    pub(super) repo: &'a Path,
    pub(super) current_run: Option<&'a RunId>,
    pub(super) runtime: SupervisorRuntime,
    pub(super) execution_runtime: SupervisorExecutionRuntime,
    pub(super) runtime_model_catalog: &'a RuntimeModelCatalogAcquisition,
    pub(super) admission_policy_input: &'a SupervisorAdmissionPolicyInput,
    pub(super) quota: SupervisorQuotaSelectionInput<'a>,
}

#[cfg(target_os = "linux")]
fn cam_provider_id_for_supervisor_runtime(runtime: SupervisorRuntime) -> Option<&'static str> {
    match runtime {
        SupervisorRuntime::Grok => Some("grok-cli"),
        SupervisorRuntime::Codex => Some("codex-cli"),
        SupervisorRuntime::GeminiCli => Some("gemini-cli"),
        SupervisorRuntime::ClaudeCode => Some("claude-code"),
        SupervisorRuntime::Cursor => Some("cursor"),
        SupervisorRuntime::Fake => None,
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) struct CamObserveTestHarness {
    registry: StoredAccountRegistry,
    adapter: Box<dyn coding_agent_manager_lib::providers::ProviderAdapter>,
    secondary_adapter: Option<Box<dyn coding_agent_manager_lib::providers::ProviderAdapter>>,
    advertised: Option<AdvertisedCatalogSet>,
    resolved_auditor: Option<SupervisorSelectionEvent>,
    _root: tempfile::TempDir,
}

#[cfg(all(test, target_os = "linux"))]
pub(super) struct CamObserveTestGuard {
    previous: Option<Arc<CamObserveTestHarness>>,
    _thread_affinity: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static CAM_OBSERVE_TEST_OVERRIDE: RefCell<Option<Arc<CamObserveTestHarness>>> =
        const { RefCell::new(None) };
}

#[cfg(all(test, target_os = "linux"))]
fn activate_cam_observe_test_harness(harness: CamObserveTestHarness) -> CamObserveTestGuard {
    install_captured_cam_observe_test_harness(Some(Arc::new(harness)))
}

// Share fixture custody, not an observation snapshot: Core re-reads the same
// selected registry and invokes the same provider adapter on every observation.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn captured_cam_observe_test_harness() -> Option<Arc<CamObserveTestHarness>> {
    CAM_OBSERVE_TEST_OVERRIDE.with(|cell| cell.borrow().clone())
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_captured_cam_observe_test_harness(
    harness: Option<Arc<CamObserveTestHarness>>,
) -> CamObserveTestGuard {
    let previous = CAM_OBSERVE_TEST_OVERRIDE.with(|cell| cell.replace(harness));
    CamObserveTestGuard {
        previous,
        _thread_affinity: std::marker::PhantomData,
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for CamObserveTestGuard {
    fn drop(&mut self) {
        CAM_OBSERVE_TEST_OVERRIDE.with(|cell| {
            *cell.borrow_mut() = self.previous.take();
        });
    }
}

// Explicit nonlive account input for the positive injected Verified fixtures.
// Unknown access stays unknown; the ordinary policy and selector remain authoritative.
#[cfg(all(test, target_os = "linux"))]
pub(super) struct PositiveInjectedCamFixtureGuard<'a> {
    _cam: CamObserveTestGuard,
    _owner: &'a tempfile::TempDir,
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_positive_injected_cam_fixture<'a>(
    owner: &'a tempfile::TempDir,
    supplied: &RuntimeModelCatalog,
) -> Result<PositiveInjectedCamFixtureGuard<'a>> {
    use coding_agent_manager_lib::account_authority::{
        validate_observed_models, ModelAccessOutcome, ModelsObservation, ObservedModel,
    };
    use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};

    if CAM_OBSERVE_TEST_OVERRIDE.with(|slot| slot.borrow().is_some()) {
        bail!("positive injected CAM fixture must not replace an existing observation control");
    }
    let RuntimeModelCatalog::Codex(catalog) = supplied else {
        bail!("positive injected CAM fixture requires its supplied Codex catalog");
    };
    let priors = super::selection_bridge::selector_priors_with_terminal_worker_economics()?;
    let mut models = Vec::new();
    for prior in priors
        .models
        .iter()
        .filter(|prior| prior.runtime == "codex" && catalog.contains(&prior.model))
    {
        // The caller explicitly opts into this synthetic menu. Reuse its existing
        // fixture priors (including held overlays), never invent a vendor default.
        let supported = match catalog.effort_metadata(&prior.model) {
            Some(metadata) => metadata
                .supported
                .clone()
                .context("fixture catalog has unknown supported efforts")?,
            None => prior
                .class_fit
                .iter()
                .map(|fit| fit.effort.as_str().to_string())
                .chain(
                    prior
                        .authority_evidence
                        .iter()
                        .map(|evidence| evidence.effort.as_str().to_string()),
                )
                .chain(
                    prior
                        .strong_gate_fallback_efforts
                        .iter()
                        .map(|effort| effort.as_str().to_string()),
                )
                .collect::<BTreeSet<_>>(),
        };
        if supported.is_empty() {
            continue;
        }
        models.push(ObservedModel {
            model_id: prior.model.clone(),
            supported_efforts: Some(supported.into_iter().collect()),
            default_effort: catalog
                .effort_metadata(&prior.model)
                .and_then(|metadata| metadata.default.clone()),
            access: ModelAccessOutcome::UnknownAccess,
        });
    }
    let models = ModelsObservation {
        models,
        provenance: None,
    };
    validate_observed_models(&models).map_err(anyhow::Error::msg)?;

    let root = tempfile::tempdir_in(owner.path())?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&root.path().join("data")));
    registry.begin_add(
        "codex-cli",
        "synthetic-positive-injected",
        "Synthetic fixture only",
        AuthKind::OAuth,
        StoredAccountMaterial::VendorHome,
    )?;
    registry.complete_add("codex-cli", "synthetic-positive-injected")?;
    registry.select_complete_revision("codex-cli", "synthetic-positive-injected", None)?;
    let cam = activate_cam_observe_test_harness(CamObserveTestHarness {
        registry,
        secondary_adapter: None,
        adapter: Box::new(ConcurrentFixtureCodexObservation { models }),
        advertised: None,
        resolved_auditor: None,
        _root: root,
    });
    Ok(PositiveInjectedCamFixtureGuard {
        _cam: cam,
        _owner: owner,
        _same_thread: std::marker::PhantomData,
    })
}

// A repository-root loan for this one real libtest child. This is fixture custody,
// never an account, process-launch, selection or publication grant.
#[cfg(all(test, target_os = "linux"))]
const CONCURRENT_HOLDER_TEST: &str = "supervise::tests::scheduler::external_termination_named_conflict_release_and_reacquisition_form_one_recovery_sequence";
#[cfg(all(test, target_os = "linux"))]
const CONCURRENT_CUSTODY_WITNESS: &str = "concurrent-holder-custody.json";
#[cfg(all(test, target_os = "linux"))]
const CONCURRENT_CUSTODY_LOCK: &str = "concurrent-holder-custody.lock";
#[cfg(all(test, target_os = "linux"))]
const MAX_CONCURRENT_CUSTODY_BYTES: u64 = 64 * 1024;

#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConcurrentCustodyWitness {
    version: u8,
    test: String,
    parent_pid: u32,
    parent_incarnation: String,
    root: PathBuf,
    root_identity: crate::safe_state::FileIdentity,
    repo: PathBuf,
    repo_identity: crate::safe_state::FileIdentity,
    // Readiness does not exist yet: bind its existing parent and future path only.
    ready: PathBuf,
    run: String,
    inputs: [String; 3],
    witness_identity: crate::safe_state::FileIdentity,
    lock_identity: crate::safe_state::FileIdentity,
}

#[cfg(all(test, target_os = "linux"))]
fn concurrent_custody_inputs(
    plan: &SupervisorPlan,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    assessment: &TaskRoutingAssessment,
) -> Result<[String; 3]> {
    assessment.validate_for_task(frozen, &plan.task)?;
    Ok([
        crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(plan)?),
        crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(frozen)?),
        crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(assessment)?),
    ])
}

#[cfg(all(test, target_os = "linux"))]
fn verify_concurrent_custody_root(root: &crate::safe_state::SafeRoot) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    root.verify()?;
    let metadata = std::fs::symlink_metadata(root.path())?;
    // SAFETY: geteuid reads only the calling process's effective UID.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || *root.identity()
            != (crate::safe_state::FileIdentity {
                device: metadata.dev(),
                file: metadata.ino(),
            })
    {
        bail!("inherited concurrent fixture root is not the pinned private directory");
    }
    root.verify()
}

#[cfg(all(test, target_os = "linux"))]
fn concurrent_custody_ready(root: &crate::safe_state::SafeRoot, ready: &Path) -> Result<PathBuf> {
    if ready.parent() != Some(root.path())
        || ready.file_name() != Some(std::ffi::OsStr::new("issue-51-supervise-holder-ready"))
    {
        bail!("inherited concurrent fixture readiness path differs");
    }
    root.direct_child("issue-51-supervise-holder-ready")
}

#[cfg(all(test, target_os = "linux"))]
pub(super) struct ParentConcurrentFixtureCustody<'a> {
    witness: PathBuf,
    _root: crate::safe_state::SafeRoot,
    _repo: crate::safe_state::SafeRoot,
    _lock: crate::safe_state::KernelStateLock,
    _policy: crate::selection::routing_policy::RoutingPolicyGuard,
    _owner: &'a tempfile::TempDir,
}

#[cfg(all(test, target_os = "linux"))]
impl<'a> ParentConcurrentFixtureCustody<'a> {
    pub(super) fn create(
        plan: &SupervisorPlan,
        options: &SupervisorRunOptions,
        metadata: &SupervisorPlanMetadata,
        owner: &'a tempfile::TempDir,
        ready: &Path,
        policy: crate::selection::routing_policy::RoutingPolicyGuard,
    ) -> Result<Self> {
        use std::io::Write;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let root = crate::safe_state::SafeRoot::open_existing(owner.path())?;
        verify_concurrent_custody_root(&root)?;
        let repo = crate::safe_state::SafeRoot::open_existing(&options.repo)?;
        if !repo.path().starts_with(root.path()) || options.runtime != SupervisorRuntime::Codex {
            bail!("parent concurrent fixture requires its original owned Codex repository");
        }
        let ready = concurrent_custody_ready(&root, ready)?;
        match std::fs::symlink_metadata(&ready) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => bail!("parent concurrent fixture readiness must still be absent"),
        }
        let frozen = metadata
            .resolved_routing_policy
            .as_ref()
            .context("fixture frozen policy")?;
        let assessment = metadata
            .task_routing_assessment
            .as_ref()
            .context("fixture assessment")?;
        if crate::selection::routing_policy::current_routing_policy().as_ref() != Some(frozen) {
            bail!("parent concurrent fixture requires its held frozen policy");
        }
        let parent_pid = std::process::id();
        let parent_incarnation = crate::agent_lifecycle::process_start_time(parent_pid)?;
        let lock =
            crate::safe_state::KernelStateLock::acquire_direct(&root, CONCURRENT_CUSTODY_LOCK)?;
        let witness = root.direct_child(CONCURRENT_CUSTODY_WITNESS)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&witness)?;
        let file_metadata = file.metadata()?;
        let data = ConcurrentCustodyWitness {
            version: 1,
            test: CONCURRENT_HOLDER_TEST.to_string(),
            parent_pid,
            parent_incarnation,
            root: root.path().to_path_buf(),
            root_identity: root.identity().clone(),
            repo: repo.path().to_path_buf(),
            repo_identity: repo.identity().clone(),
            ready,
            run: options.run_id.as_str().to_owned(),
            inputs: concurrent_custody_inputs(plan, frozen, assessment)?,
            witness_identity: crate::safe_state::FileIdentity {
                device: file_metadata.dev(),
                file: file_metadata.ino(),
            },
            lock_identity: lock.identity().clone(),
        };
        let bytes = serde_json::to_vec(&data)?;
        if bytes.len() as u64 > MAX_CONCURRENT_CUSTODY_BYTES {
            bail!("parent concurrent fixture custody witness exceeds its bound");
        }
        file.write_all(&bytes)?;
        file.sync_all()?;
        lock.verify_direct_binding(&root)?;
        repo.verify()?;
        verify_concurrent_custody_root(&root)?;
        Ok(Self {
            witness,
            _root: root,
            _repo: repo,
            _lock: lock,
            _policy: policy,
            _owner: owner,
        })
    }

    pub(super) fn witness_path(&self) -> &Path {
        &self.witness
    }
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Clone)]
pub(super) struct InheritedConcurrentFixtureRoot {
    root: crate::safe_state::SafeRoot,
    repo: crate::safe_state::SafeRoot,
    witness_path: PathBuf,
    witness: ConcurrentCustodyWitness,
}

#[cfg(all(test, target_os = "linux"))]
impl InheritedConcurrentFixtureRoot {
    fn read_witness(path: &Path) -> Result<ConcurrentCustodyWitness> {
        use std::os::unix::fs::MetadataExt;
        let mut identity = None;
        let bytes = crate::safe_state::BoundedRegularReader::read_tree_no_follow_validated(
            path,
            MAX_CONCURRENT_CUSTODY_BYTES,
            |metadata| {
                // SAFETY: geteuid reads only the calling process's effective UID.
                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o077 != 0
                    || metadata.nlink() != 1
                {
                    bail!("inherited concurrent fixture witness is not private single-link data");
                }
                let observed = crate::safe_state::FileIdentity {
                    device: metadata.dev(),
                    file: metadata.ino(),
                };
                if identity.as_ref().is_some_and(|prior| prior != &observed) {
                    bail!("inherited concurrent fixture witness identity changed");
                }
                identity = Some(observed);
                Ok(())
            },
        )?;
        let witness: ConcurrentCustodyWitness = serde_json::from_slice(&bytes)?;
        if identity.as_ref() != Some(&witness.witness_identity) {
            bail!("inherited concurrent fixture witness identity differs");
        }
        Ok(witness)
    }

    pub(super) fn open(
        plan: &SupervisorPlan,
        options: &SupervisorRunOptions,
        metadata: &SupervisorPlanMetadata,
        root: &Path,
        ready: &Path,
        witness_path: &Path,
    ) -> Result<Self> {
        let root = crate::safe_state::SafeRoot::open_existing(root)?;
        let repo = crate::safe_state::SafeRoot::open_existing(&options.repo)?;
        if witness_path != root.direct_child(CONCURRENT_CUSTODY_WITNESS)?
            || !repo.path().starts_with(root.path())
        {
            bail!("inherited concurrent fixture paths are outside parent custody");
        }
        let witness = Self::read_witness(witness_path)?;
        if witness.ready != concurrent_custody_ready(&root, ready)? {
            bail!("inherited concurrent fixture readiness binding differs");
        }
        let inherited = Self {
            root,
            repo,
            witness_path: witness_path.to_path_buf(),
            witness,
        };
        inherited.verify(
            plan,
            &options.run_id,
            &options.repo,
            metadata
                .resolved_routing_policy
                .as_ref()
                .context("fixture frozen policy")?,
            metadata
                .task_routing_assessment
                .as_ref()
                .context("fixture assessment")?,
        )?;
        Ok(inherited)
    }

    fn verify(
        &self,
        plan: &SupervisorPlan,
        run: &RunId,
        repo: &Path,
        frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
        assessment: &TaskRoutingAssessment,
    ) -> Result<()> {
        use crate::safe_state::{BoundedRegularReader, ExistingExclusiveLock, KernelStateLock};
        verify_concurrent_custody_root(&self.root)?;
        self.repo.verify()?;
        let witness = Self::read_witness(&self.witness_path)?;
        if witness != self.witness
            || witness.version != 1
            || witness.test != CONCURRENT_HOLDER_TEST
            || witness.root != self.root.path()
            || witness.root_identity != *self.root.identity()
            || witness.repo != self.repo.path()
            || witness.repo_identity != *self.repo.identity()
            || witness.repo != repo
            || witness.run != run.as_str()
            || witness.inputs != concurrent_custody_inputs(plan, frozen, assessment)?
        {
            bail!("inherited concurrent fixture input binding differs");
        }
        let lock_path = self.root.direct_child(CONCURRENT_CUSTODY_LOCK)?;
        if BoundedRegularReader::identity(&lock_path)? != witness.lock_identity {
            bail!("inherited concurrent fixture custody lock identity differs");
        }
        match KernelStateLock::try_acquire_existing_exclusive_direct(
            &self.root,
            CONCURRENT_CUSTODY_LOCK,
        )? {
            ExistingExclusiveLock::Busy => {}
            ExistingExclusiveLock::Missing | ExistingExclusiveLock::Acquired(_) => {
                bail!("inherited concurrent fixture custody is not held");
            }
        }
        if BoundedRegularReader::identity(&lock_path)? != witness.lock_identity {
            bail!("inherited concurrent fixture custody lock identity changed");
        }
        // Busy is contention, not a PID proof. Check actual parentage/incarnation too.
        // The parent-side borrowed owner and KillOnDrop/reap order hold the fixture loan.
        // SAFETY: getppid reads only the calling process's actual parent PID.
        let parent_pid = unsafe { libc::getppid() };
        if parent_pid <= 0
            || parent_pid as u32 != witness.parent_pid
            || !crate::agent_lifecycle::supported_process_start_time(
                witness.parent_pid,
                &witness.parent_incarnation,
            )
            || crate::agent_lifecycle::process_start_time(witness.parent_pid)?
                != witness.parent_incarnation
        {
            bail!("inherited concurrent fixture parent incarnation differs");
        }
        Ok(())
    }
}

// Explicit, nonlive selection evidence for an opted-in injected concurrency fixture.
// This does not grant process, account-login, worktree or publication authority.
#[cfg(all(test, target_os = "linux"))]
struct SelectedConcurrentFixture {
    run: RunId,
    repo: PathBuf,
    plan: SupervisorPlan,
    catalog: CodexRuntimeModelCatalog,
    assessment: TaskRoutingAssessment,
    frozen: crate::selection::routing_policy::FrozenRoutingPolicy,
    inherited: Option<InheritedConcurrentFixtureRoot>,
    budget_bootstrap: Option<ConcurrentBudgetBootstrap>,
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Clone)]
struct ConcurrentBudgetBootstrap {
    model: String,
    effort: ReasoningEffort,
    concurrency: usize,
    prior: crate::selection::OperatorPriorDataProvenance,
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static SELECTED_CONCURRENT_FIXTURE: RefCell<Option<SelectedConcurrentFixture>> =
        const { RefCell::new(None) };
}

#[cfg(all(test, target_os = "linux"))]
pub(super) struct SelectedConcurrentFixtureGuard<'a> {
    #[cfg(target_os = "linux")]
    previous: Option<SelectedConcurrentFixture>,
    #[cfg(target_os = "linux")]
    _cam: CamObserveTestGuard,
    _policy: crate::selection::routing_policy::RoutingPolicyGuard,
    _owner: &'a tempfile::TempDir,
    _inherited: Option<&'a InheritedConcurrentFixtureRoot>,
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for SelectedConcurrentFixtureGuard<'_> {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        SELECTED_CONCURRENT_FIXTURE.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
struct ConcurrentFixtureCodexObservation {
    models: coding_agent_manager_lib::account_authority::ModelsObservation,
}

#[cfg(all(test, target_os = "linux"))]
impl coding_agent_manager_lib::providers::ProviderAdapter for ConcurrentFixtureCodexObservation {
    fn id(&self) -> &'static str {
        "codex-cli"
    }

    fn descriptor(&self) -> coding_agent_manager_lib::model::ProviderDescriptor {
        use coding_agent_manager_lib::model::{
            AuthKind, InstallState, Maturity, ProviderDescriptor,
        };
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "Synthetic concurrent fixture (not a live provider)".to_string(),
            vendor: "test".to_string(),
            auth_kinds: vec![AuthKind::OAuth],
            maturity: Maturity::Experimental,
            install_state: InstallState::Unknown,
            capabilities: Vec::new(),
        }
    }

    fn config_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    fn detect(&self) -> coding_agent_manager_lib::model::InstallState {
        coding_agent_manager_lib::model::InstallState::Unknown
    }

    fn list_accounts(
        &self,
    ) -> coding_agent_manager_lib::error::Result<Vec<coding_agent_manager_lib::model::Account>>
    {
        Ok(Vec::new())
    }

    fn activate_account(&self, _account: &str) -> coding_agent_manager_lib::error::Result<()> {
        Err(coding_agent_manager_lib::error::Error::NotImplemented(
            "synthetic concurrent fixture activation",
        ))
    }

    fn quota_for_account(
        &self,
        _account: &coding_agent_manager_lib::model::StoredAccountMetadata,
    ) -> coding_agent_manager_lib::error::Result<Vec<coding_agent_manager_lib::model::QuotaSnapshot>>
    {
        Ok(Vec::new())
    }

    fn observe_models_for_account(
        &self,
        _account: &coding_agent_manager_lib::model::StoredAccountMetadata,
    ) -> coding_agent_manager_lib::error::Result<
        coding_agent_manager_lib::account_authority::CategoryObservation<
            coding_agent_manager_lib::account_authority::ModelsObservation,
        >,
    > {
        Ok(
            coding_agent_manager_lib::account_authority::CategoryObservation::observed(
                self.models.clone(),
            ),
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
struct GrokReviewFixtureObservation {
    models: coding_agent_manager_lib::account_authority::ModelsObservation,
}

#[cfg(all(test, target_os = "linux"))]
impl coding_agent_manager_lib::providers::ProviderAdapter for GrokReviewFixtureObservation {
    fn id(&self) -> &'static str {
        "grok-cli"
    }

    fn descriptor(&self) -> coding_agent_manager_lib::model::ProviderDescriptor {
        use coding_agent_manager_lib::model::{
            AuthKind, InstallState, Maturity, ProviderDescriptor,
        };
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "Synthetic Grok review-cost fixture (not a live provider)".to_string(),
            vendor: "test".to_string(),
            auth_kinds: vec![AuthKind::OAuth],
            maturity: Maturity::Experimental,
            install_state: InstallState::Unknown,
            capabilities: Vec::new(),
        }
    }

    fn config_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    fn detect(&self) -> coding_agent_manager_lib::model::InstallState {
        coding_agent_manager_lib::model::InstallState::Unknown
    }

    fn list_accounts(
        &self,
    ) -> coding_agent_manager_lib::error::Result<Vec<coding_agent_manager_lib::model::Account>>
    {
        Ok(Vec::new())
    }

    fn activate_account(&self, _account: &str) -> coding_agent_manager_lib::error::Result<()> {
        Err(coding_agent_manager_lib::error::Error::NotImplemented(
            "synthetic Grok review-cost fixture activation",
        ))
    }

    fn quota_for_account(
        &self,
        _account: &coding_agent_manager_lib::model::StoredAccountMetadata,
    ) -> coding_agent_manager_lib::error::Result<Vec<coding_agent_manager_lib::model::QuotaSnapshot>>
    {
        Ok(Vec::new())
    }

    fn observe_models_for_account(
        &self,
        _account: &coding_agent_manager_lib::model::StoredAccountMetadata,
    ) -> coding_agent_manager_lib::error::Result<
        coding_agent_manager_lib::account_authority::CategoryObservation<
            coding_agent_manager_lib::account_authority::ModelsObservation,
        >,
    > {
        Ok(
            coding_agent_manager_lib::account_authority::CategoryObservation::observed(
                self.models.clone(),
            ),
        )
    }
}

// A known-access observation for a synthetic selected account, never a live
// Grok entitlement or billing claim. Normal observe/freeze and selector gates apply.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_selected_grok_review_fixture<'a>(
    owner: &'a tempfile::TempDir,
    fixture_model: &str,
    supported_efforts: &[ReasoningEffort],
) -> Result<PositiveInjectedCamFixtureGuard<'a>> {
    use coding_agent_manager_lib::account_authority::{
        ModelAccessBasis, ModelAccessOutcome, ModelCatalogProvenance, ModelCatalogSourceKind,
        ModelsObservation, ObservedModel,
    };
    use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};

    if CAM_OBSERVE_TEST_OVERRIDE.with(|slot| slot.borrow().is_some()) {
        bail!("Grok review fixture must not replace an existing CAM observation control");
    }
    let menu: BTreeSet<String> = supported_efforts
        .iter()
        .map(|effort| effort.as_str().to_string())
        .collect();
    if menu.is_empty() {
        bail!("synthetic Grok review fixture requires a nonempty supported-effort menu");
    }
    let default_effort = if menu.len() == 1 {
        menu.iter().next().cloned()
    } else {
        None
    };
    let root = tempfile::tempdir_in(owner.path())?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&root.path().join("data")));
    registry.begin_add(
        "grok-cli",
        "synthetic-review-cost",
        "Synthetic review-cost account only",
        AuthKind::OAuth,
        StoredAccountMaterial::VendorHome,
    )?;
    registry.complete_add("grok-cli", "synthetic-review-cost")?;
    registry.select_complete_revision("grok-cli", "synthetic-review-cost", None)?;
    let binding = registry
        .selected_binding("grok-cli")?
        .context("synthetic Grok review fixture selected account")?;
    let models = ModelsObservation {
        models: vec![ObservedModel {
            model_id: fixture_model.to_string(),
            default_effort,
            supported_efforts: Some(menu.into_iter().collect()),
            access: ModelAccessOutcome::Available,
        }],
        provenance: Some(ModelCatalogProvenance {
            source_kind: ModelCatalogSourceKind::AuthenticatedCatalog,
            fetched_at: Some("2026-09-19T00:00:00Z".to_string()),
            stale: false,
            principal_binding: Some(binding),
            access_basis: Some(ModelAccessBasis::ConfirmedModelEntitlement),
        }),
    };
    coding_agent_manager_lib::account_authority::validate_observed_models(&models)
        .map_err(anyhow::Error::msg)?;
    let cam = activate_cam_observe_test_harness(CamObserveTestHarness {
        registry,
        secondary_adapter: None,
        adapter: Box::new(GrokReviewFixtureObservation { models }),
        advertised: None,
        resolved_auditor: None,
        _root: root,
    });
    Ok(PositiveInjectedCamFixtureGuard {
        _cam: cam,
        _owner: owner,
        _same_thread: std::marker::PhantomData,
    })
}

// Associate the licensed scenario's already-held genuine account with the exact
// NonpublishableSimulation source run. No second CAM observer is installed.
#[cfg(all(test, target_os = "linux"))]
pub(super) struct SelectedLicensedSourceFixtureGuard<'scope, 'owner> {
    previous: Option<SelectedConcurrentFixture>,
    _parent_acceptance: &'scope super::InjectedSupervisorParentAcceptanceGuard<'owner>,
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for SelectedLicensedSourceFixtureGuard<'_, '_> {
    fn drop(&mut self) {
        SELECTED_CONCURRENT_FIXTURE.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn bind_selected_licensed_source_fixture<'scope, 'owner>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    catalog: &RuntimeModelCatalog,
    metadata: SupervisorPlanMetadata,
    parent_acceptance: &'scope super::InjectedSupervisorParentAcceptanceGuard<'owner>,
) -> Result<SelectedLicensedSourceFixtureGuard<'scope, 'owner>> {
    let repo = options.repo.canonicalize()?;
    let [assignment] = plan.assignments.as_slice() else {
        bail!("licensed source fixture requires exactly one original child");
    };
    let [lens] = plan.review_lenses.as_slice() else {
        bail!("licensed source fixture requires its single parent-acceptance contract");
    };
    let RuntimeModelCatalog::Codex(catalog) = catalog else {
        bail!("licensed source fixture requires its actual Codex catalog");
    };
    if options.runtime != SupervisorRuntime::Codex
        || !repo.starts_with(parent_acceptance._account._owner.path().canonicalize()?)
        || !plan.role_models.is_empty()
        || assignment.role != AgentRole::ChildOrchestrator
        || assignment.phase != AssignmentPhase::Execution
        || assignment.effective_role_category() != RoleCategory::DelegatingCoordinator
        || assignment.assigned_paths.is_empty()
        || assignment
            .runtime
            .is_some_and(|runtime| runtime != SupervisorRuntime::Codex)
        || assignment.worker_assignments.iter().any(|worker| {
            worker.role != AgentRole::Worker
                || worker.effective_role_category() != RoleCategory::NonDelegatingTerminalWorker
                || worker.assigned_paths.is_empty()
                || worker
                    .assigned_paths
                    .iter()
                    .any(|path| !assignment.assigned_paths.contains(path))
        })
        || lens.id != "parent-acceptance"
        || lens.information_scope != ReviewInformationScope::FullChildTranscript
    {
        bail!(
            "licensed source fixture requires owned default-role Codex subjects and bounded workers"
        );
    }
    let ReviewLensBackendConfig::Model {
        model,
        reasoning_effort: Some(effort),
        ..
    } = &lens.backend
    else {
        bail!("licensed source fixture requires its normally selected executable lens");
    };
    if !catalog.contains(model)
        || ReasoningEffort::parse(effort).is_none()
        || super::test_runtime_model_catalog(plan, options.runtime)?
            != RuntimeModelCatalog::Codex(catalog.clone())
    {
        bail!("licensed source fixture must retain its complete actual catalog and lens effort");
    }
    let frozen = metadata
        .resolved_routing_policy
        .context("licensed source frozen policy")?;
    let assessment = metadata
        .task_routing_assessment
        .context("licensed source parsed assessment")?;
    assessment.validate_for_task(&frozen, &plan.task)?;
    if crate::selection::routing_policy::current_routing_policy().as_ref() != Some(&frozen)
        || !CAM_OBSERVE_TEST_OVERRIDE.with(|slot| slot.borrow().is_some())
    {
        bail!("licensed source fixture requires its held policy and selected-account observer");
    }
    let fixture = SelectedConcurrentFixture {
        run: options.run_id.clone(),
        repo,
        plan: plan.clone(),
        catalog: catalog.clone(),
        assessment,
        frozen,
        inherited: None,
        budget_bootstrap: None,
    };
    let previous = SELECTED_CONCURRENT_FIXTURE.with(|slot| slot.borrow_mut().replace(fixture));
    Ok(SelectedLicensedSourceFixtureGuard {
        previous,
        _parent_acceptance: parent_acceptance,
    })
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_selected_nested_review_fixture<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    catalog: &CodexRuntimeModelCatalog,
    metadata: SupervisorPlanMetadata,
    owner: &'a tempfile::TempDir,
    policy: crate::selection::routing_policy::RoutingPolicyGuard,
    effort: ReasoningEffort,
) -> Result<SelectedConcurrentFixtureGuard<'a>> {
    let repo = options.repo.canonicalize()?;
    let [assignment, pending @ ..] = plan.assignments.as_slice() else {
        bail!("nested review fixture requires an authored nested child");
    };
    // Single-lens budget lifecycle cases also retain one pending ordinary child.
    // The existing two/three-lens fixtures still require exactly one nested child.
    if !pending.is_empty()
        && (plan.review_lenses.len() != 1
            || pending.len() != 1
            || pending.iter().any(|child| {
                child.role != AgentRole::ChildOrchestrator
                    || child.phase != AssignmentPhase::Execution
                    || child.effective_role_category() != RoleCategory::DelegatingCoordinator
                    || child.assigned_paths.is_empty()
                    || !child.worker_assignments.is_empty()
                    || child
                        .runtime
                        .is_some_and(|runtime| runtime != SupervisorRuntime::Codex)
            }))
    {
        bail!("single-lens nested review fixture permits only one pending ordinary Codex child");
    }
    if !repo.starts_with(owner.path().canonicalize()?)
        || options.runtime != SupervisorRuntime::Codex
        || assignment.role != AgentRole::ChildOrchestrator
        || assignment.phase != AssignmentPhase::Execution
        || assignment.effective_role_category() != RoleCategory::DelegatingCoordinator
        || (assignment.worker_assignments.is_empty() && plan.review_lenses.len() != 1)
        || assignment
            .runtime
            .is_some_and(|runtime| runtime != SupervisorRuntime::Codex)
        || assignment.worker_assignments.iter().any(|worker| {
            worker.role != AgentRole::Worker
                || worker.effective_role_category() != RoleCategory::NonDelegatingTerminalWorker
                || worker.assigned_paths.is_empty()
                || worker
                    .assigned_paths
                    .iter()
                    .any(|path| !assignment.assigned_paths.contains(path))
        })
    {
        bail!("nested review fixture requires an owned Codex child with bounded terminal workers");
    }
    let frozen = metadata
        .resolved_routing_policy
        .context("nested review fixture frozen policy")?;
    let assessment = metadata
        .task_routing_assessment
        .context("nested review fixture parsed assessment")?;
    assessment.validate_for_task(&frozen, &plan.task)?;
    if crate::selection::routing_policy::current_routing_policy().as_ref() != Some(&frozen) {
        bail!("nested review fixture requires its held matching policy guard");
    }
    let model = plan
        .role_models
        .get(&AgentRole::ChildOrchestrator)
        .and_then(|selection| selection.model.as_ref())
        .context("nested review fixture authored child model")?;
    let mut models = BTreeSet::from([(model.clone(), effort.as_str().to_string())]);
    if !catalog.contains(model) || !matches!(plan.review_lenses.len(), 1..=3) {
        bail!("nested review fixture requires its actual child catalog and one to three lenses");
    }
    for lens in &plan.review_lenses {
        let ReviewLensBackendConfig::Model {
            model,
            reasoning_effort: Some(effort),
            ..
        } = &lens.backend
        else {
            bail!("nested review fixture requires unchanged executable review contracts");
        };
        if ReasoningEffort::parse(effort).is_none() {
            bail!("nested review fixture lens has an invalid authored effort");
        }
        // A missing authored lens is a negative selection control, never observed access.
        if catalog.contains(model) {
            models.insert((
                model.clone(),
                resolve_review_lens_reasoning_effort(lens, None).resolved,
            ));
        }
    }
    // Retain a separately selected generic Auditor profile as well as the child
    // and authored lenses. Equal-profile callers add the same existing set entry.
    if let Some(auditor) = plan.role_models.get(&AgentRole::Auditor) {
        if let Some(effort) = auditor.reasoning_effort.as_deref() {
            let model = auditor
                .model
                .as_ref()
                .context("nested review fixture resolved Auditor model")?;
            if !catalog.contains(model) || ReasoningEffort::parse(effort).is_none() {
                bail!(
                    "nested review fixture Auditor is absent from its supplied model/effort catalog"
                );
            }
            models.insert((
                model.clone(),
                enforce_role_reasoning_effort_floor(AgentRole::Auditor, Some(effort.to_string()))
                    .context("fixture Auditor effort floor")?,
            ));
        }
    }
    let uniform = models.len() == 1 && plan.review_lenses.len() == 3;
    super::prior_input::require_binding_repo(&repo)?;
    let prior = super::prior_input::current_provenance()
        .context("nested review fixture requires its bound synthetic prior")?;
    let cam = install_concurrent_fixture_observations(owner, models)?;
    Ok(bind_selected_concurrent_fixture_inputs(
        SelectedConcurrentFixture {
            run: options.run_id.clone(),
            repo,
            plan: plan.clone(),
            catalog: catalog.clone(),
            assessment,
            frozen,
            inherited: None,
            budget_bootstrap: uniform.then(|| ConcurrentBudgetBootstrap {
                model: model.clone(),
                effort,
                concurrency: 1,
                prior,
            }),
        },
        cam,
        policy,
        owner,
        None,
    ))
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_selected_concurrent_fixture<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    catalog: &CodexRuntimeModelCatalog,
    metadata: SupervisorPlanMetadata,
    owner: &'a tempfile::TempDir,
    policy: crate::selection::routing_policy::RoutingPolicyGuard,
) -> Result<SelectedConcurrentFixtureGuard<'a>> {
    install_selected_concurrent_fixture_with_custody(
        plan, options, catalog, metadata, owner, policy, None,
    )
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_selected_inherited_concurrent_fixture<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    catalog: &CodexRuntimeModelCatalog,
    metadata: SupervisorPlanMetadata,
    registry_owner: &'a tempfile::TempDir,
    policy: crate::selection::routing_policy::RoutingPolicyGuard,
    inherited: &'a InheritedConcurrentFixtureRoot,
) -> Result<SelectedConcurrentFixtureGuard<'a>> {
    install_selected_concurrent_fixture_with_custody(
        plan,
        options,
        catalog,
        metadata,
        registry_owner,
        policy,
        Some(inherited),
    )
}

#[cfg(all(test, target_os = "linux"))]
fn install_selected_concurrent_fixture_with_custody<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    catalog: &CodexRuntimeModelCatalog,
    metadata: SupervisorPlanMetadata,
    owner: &'a tempfile::TempDir,
    policy: crate::selection::routing_policy::RoutingPolicyGuard,
    inherited: Option<&'a InheritedConcurrentFixtureRoot>,
) -> Result<SelectedConcurrentFixtureGuard<'a>> {
    {
        let repo = options.repo.canonicalize()?;
        let repo_owned = match inherited {
            Some(custody) => {
                custody.verify(
                    plan,
                    &options.run_id,
                    &options.repo,
                    metadata
                        .resolved_routing_policy
                        .as_ref()
                        .context("fixture frozen policy")?,
                    metadata
                        .task_routing_assessment
                        .as_ref()
                        .context("fixture assessment")?,
                )?;
                repo == custody.repo.path()
            }
            None => repo.starts_with(owner.path().canonicalize()?),
        };
        if !repo_owned
            || options.runtime != SupervisorRuntime::Codex
            || plan.assignments.is_empty()
            || plan.assignments.iter().any(|assignment| {
                let nested_workers = !assignment.worker_assignments.is_empty();
                let runtime_ok = !assignment
                    .runtime
                    .is_some_and(|runtime| runtime != SupervisorRuntime::Codex);
                let ordinary_child = assignment.role == AgentRole::ChildOrchestrator
                    && assignment.phase == AssignmentPhase::Execution
                    && assignment.effective_role_category() == RoleCategory::DelegatingCoordinator
                    && !nested_workers
                    && runtime_ok;
                let terminal_worker = assignment.role == AgentRole::Worker
                    && assignment.phase == AssignmentPhase::Execution
                    && assignment.role_category == Some(RoleCategory::NonDelegatingTerminalWorker)
                    && !nested_workers
                    && runtime_ok;
                let researcher = assignment.role == AgentRole::Researcher
                    && assignment.phase == AssignmentPhase::Execution
                    && assignment.role_category == Some(RoleCategory::ReadOnlyResearcher)
                    && !nested_workers
                    && runtime_ok;
                !(ordinary_child || terminal_worker || researcher)
            })
        {
            bail!(
                "selected concurrent fixture requires owned workerless Codex ChildOrchestrators, explicit terminal Workers, or explicit read-only Researchers"
            );
        }
        let frozen = metadata
            .resolved_routing_policy
            .context("fixture frozen policy")?;
        let assessment = metadata
            .task_routing_assessment
            .context("fixture parsed assessment")?;
        assessment.validate_for_task(&frozen, &plan.task)?;
        if crate::selection::routing_policy::current_routing_policy().as_ref() != Some(&frozen) {
            bail!("selected concurrent fixture requires its held matching policy guard");
        }
        if CAM_OBSERVE_TEST_OVERRIDE.with(|slot| slot.borrow().is_some()) {
            bail!("selected concurrent fixture must not replace an existing CAM control fixture");
        }
        // Use the caller's unchanged authored review contract, not a new model/effort default.
        let mut lens_models = BTreeSet::new();
        for lens in &plan.review_lenses {
            let ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } = &lens.backend
            else {
                bail!("selected concurrent fixture requires an executable authored review lens");
            };
            let effort = reasoning_effort.as_ref().context("fixture review effort")?;
            if !catalog.contains(model) {
                bail!("fixture review model is absent from the actual supplied Codex catalog");
            }
            lens_models.insert((model.clone(), effort.clone()));
        }
        if lens_models.len() != 1 {
            bail!(
                "selected concurrent fixture requires one unchanged review model/effort contract"
            );
        }
        let cam = install_concurrent_fixture_observations(owner, lens_models)?;
        Ok(bind_selected_concurrent_fixture_inputs(
            SelectedConcurrentFixture {
                run: options.run_id.clone(),
                repo,
                plan: plan.clone(),
                catalog: catalog.clone(),
                assessment,
                frozen,
                inherited: inherited.cloned(),
                budget_bootstrap: None,
            },
            cam,
            policy,
            owner,
            inherited,
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
fn install_concurrent_fixture_observations(
    owner: &tempfile::TempDir,
    lens_models: BTreeSet<(String, String)>,
) -> Result<CamObserveTestGuard> {
    use coding_agent_manager_lib::account_authority::{
        ModelAccessBasis, ModelAccessOutcome, ModelCatalogProvenance, ModelCatalogSourceKind,
        ModelsObservation, ObservedModel,
    };
    use coding_agent_manager_lib::model::{AuthKind, StoredAccountMaterial};

    if CAM_OBSERVE_TEST_OVERRIDE.with(|slot| slot.borrow().is_some()) {
        bail!("selected concurrent fixture must not replace an existing CAM control fixture");
    }
    let root = tempfile::tempdir_in(owner.path())?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&root.path().join("data")));
    registry.begin_add(
        "codex-cli",
        "synthetic-concurrent",
        "Synthetic only",
        AuthKind::OAuth,
        StoredAccountMaterial::VendorHome,
    )?;
    registry.complete_add("codex-cli", "synthetic-concurrent")?;
    registry.select_complete_revision("codex-cli", "synthetic-concurrent", None)?;
    let binding = registry
        .selected_binding("codex-cli")?
        .context("fixture selected account")?;
    // These are deliberately synthetic, principal-bound fixture observations.
    // The unchanged selector still validates access, priors, prohibitions and authority roles.
    let models = ModelsObservation {
        models: lens_models
            .into_iter()
            .fold(
                BTreeMap::<String, BTreeSet<String>>::new(),
                |mut models, (model, effort)| {
                    models.entry(model).or_default().insert(effort);
                    models
                },
            )
            .into_iter()
            .map(|(model_id, efforts)| ObservedModel {
                model_id,
                default_effort: (efforts.len() == 1).then(|| efforts.first().unwrap().clone()),
                supported_efforts: Some(efforts.into_iter().collect()),
                access: ModelAccessOutcome::Available,
            })
            .collect(),
        provenance: Some(ModelCatalogProvenance {
            source_kind: ModelCatalogSourceKind::AuthenticatedCatalog,
            fetched_at: Some("2026-09-19T00:00:00Z".to_string()),
            stale: false,
            principal_binding: Some(binding),
            access_basis: Some(ModelAccessBasis::ConfirmedModelEntitlement),
        }),
    };
    coding_agent_manager_lib::account_authority::validate_observed_models(&models)
        .map_err(anyhow::Error::msg)?;
    let cam = activate_cam_observe_test_harness(CamObserveTestHarness {
        registry,
        secondary_adapter: None,
        adapter: Box::new(ConcurrentFixtureCodexObservation { models }),
        advertised: None,
        resolved_auditor: None,
        _root: root,
    });
    Ok(cam)
}

// A nonlive selected account held across the licensed source and generated runs.
// This supplies observations only; each real RunId must pass normal selection/freeze.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_licensed_autopilot_account_fixture<'a>(
    owner: &'a tempfile::TempDir,
    supplied: &RuntimeModelCatalog,
) -> Result<PositiveInjectedCamFixtureGuard<'a>> {
    let RuntimeModelCatalog::Codex(catalog) = supplied else {
        bail!("licensed Autopilot fixture requires its actual Codex catalog");
    };
    let priors = super::selection_bridge::selector_priors_with_terminal_worker_economics()?;
    let mut models = BTreeSet::new();
    for prior in priors
        .models
        .iter()
        .filter(|prior| prior.runtime == "codex" && catalog.contains(&prior.model))
    {
        let supported = match catalog.effort_metadata(&prior.model) {
            Some(metadata) => metadata
                .supported
                .clone()
                .context("licensed fixture catalog has unknown supported efforts")?,
            None => prior
                .class_fit
                .iter()
                .map(|fit| fit.effort.as_str().to_string())
                .chain(
                    prior
                        .authority_evidence
                        .iter()
                        .map(|evidence| evidence.effort.as_str().to_string()),
                )
                .chain(
                    prior
                        .strong_gate_fallback_efforts
                        .iter()
                        .map(|effort| effort.as_str().to_string()),
                )
                .collect(),
        };
        models.extend(
            supported
                .into_iter()
                .map(|effort| (prior.model.clone(), effort)),
        );
    }
    let cam = install_concurrent_fixture_observations(owner, models)?;
    Ok(PositiveInjectedCamFixtureGuard {
        _cam: cam,
        _owner: owner,
        _same_thread: std::marker::PhantomData,
    })
}

#[cfg(all(test, target_os = "linux"))]
fn bind_selected_concurrent_fixture_inputs<'a>(
    fixture: SelectedConcurrentFixture,
    cam: CamObserveTestGuard,
    policy: crate::selection::routing_policy::RoutingPolicyGuard,
    owner: &'a tempfile::TempDir,
    inherited: Option<&'a InheritedConcurrentFixtureRoot>,
) -> SelectedConcurrentFixtureGuard<'a> {
    let previous = SELECTED_CONCURRENT_FIXTURE.with(|slot| slot.borrow_mut().replace(fixture));
    SelectedConcurrentFixtureGuard {
        previous,
        _cam: cam,
        _policy: policy,
        _owner: owner,
        _inherited: inherited,
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_selected_child_budget_fixture<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    owner: &'a tempfile::TempDir,
    profile: (&str, ReasoningEffort),
    concurrency: usize,
) -> Result<SelectedConcurrentFixtureGuard<'a>> {
    if plan.assignments.iter().any(|assignment| {
        assignment.role != AgentRole::ChildOrchestrator
            || assignment.effective_role_category() != RoleCategory::DelegatingCoordinator
    }) {
        bail!(
            "budget Child fixture requires only ChildOrchestrator/DelegatingCoordinator subjects"
        );
    }
    install_selected_budget_fixture(plan, options, owner, profile, concurrency)
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn install_selected_researcher_budget_fixture<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    owner: &'a tempfile::TempDir,
    profile: (&str, ReasoningEffort),
    concurrency: usize,
) -> Result<SelectedConcurrentFixtureGuard<'a>> {
    if plan.assignments.iter().any(|assignment| {
        assignment.role != AgentRole::Researcher
            || assignment.effective_role_category() != RoleCategory::ReadOnlyResearcher
    }) {
        bail!("budget Researcher fixture requires only Researcher/ReadOnlyResearcher subjects");
    }
    install_selected_budget_fixture(plan, options, owner, profile, concurrency)
}

#[cfg(all(test, target_os = "linux"))]
fn install_selected_budget_fixture<'a>(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    owner: &'a tempfile::TempDir,
    profile: (&str, ReasoningEffort),
    concurrency: usize,
) -> Result<SelectedConcurrentFixtureGuard<'a>> {
    let repo = options.repo.canonicalize()?;
    if !repo.starts_with(owner.path().canonicalize()?)
        || options.runtime != SupervisorRuntime::Codex
        || plan.assignments.is_empty()
        || plan.assignments.iter().any(|assignment| {
            assignment.phase != AssignmentPhase::Execution
                || !assignment.worker_assignments.is_empty()
                || assignment
                    .runtime
                    .is_some_and(|runtime| runtime != SupervisorRuntime::Codex)
        })
    {
        bail!("budget fixture requires owned workerless Execution Codex subjects");
    }
    let RuntimeModelCatalog::Codex(catalog) =
        super::test_runtime_model_catalog(plan, options.runtime)?
    else {
        bail!("budget fixture requires its actual supplied Codex catalog");
    };
    if !catalog.contains(profile.0) {
        bail!("budget profile is absent from the actual supplied Codex catalog");
    }
    let mut metadata = SupervisorPlanMetadata::default();
    let policy = super::bind_assessed_injected_plan(plan, &repo, &mut metadata)?;
    let frozen = metadata
        .resolved_routing_policy
        .context("budget fixture frozen policy")?;
    let assessment = metadata
        .task_routing_assessment
        .context("budget fixture assessment")?;
    assessment.validate_for_task(&frozen, &plan.task)?;
    super::prior_input::require_binding_repo(&repo)?;
    let prior = super::prior_input::current_provenance()
        .context("budget fixture requires its bound synthetic prior")?;
    let cam = install_concurrent_fixture_observations(
        owner,
        [(profile.0.to_string(), profile.1.as_str().to_string())]
            .into_iter()
            .collect(),
    )?;
    Ok(bind_selected_concurrent_fixture_inputs(
        SelectedConcurrentFixture {
            run: options.run_id.clone(),
            repo,
            plan: plan.clone(),
            catalog,
            assessment,
            frozen,
            inherited: None,
            budget_bootstrap: Some(ConcurrentBudgetBootstrap {
                model: profile.0.to_string(),
                effort: profile.1,
                concurrency,
                prior,
            }),
        },
        cam,
        policy,
        owner,
        None,
    ))
}

// Complete only the opted-in budget fixture at the normal preparation boundary.
// Both bootstrap and final evaluation borrow the same resolved run inputs.
#[cfg(all(test, target_os = "linux"))]
fn complete_selected_budget_fixture(
    plan: &mut SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
    request: &PreparedSupervisorSelectionRequest<'_>,
    history: Option<&super::outcome_history::FrozenOutcomeHistory>,
    observations: &[(SupervisorRuntime, AccountObserveResult)],
) -> Result<()> {
    let pending = SELECTED_CONCURRENT_FIXTURE.with(|slot| {
        slot.borrow().as_ref().and_then(|fixture| {
            fixture.budget_bootstrap.as_ref().map(|bootstrap| {
                (
                    fixture.run.clone(),
                    fixture.plan.clone(),
                    fixture.assessment.clone(),
                    fixture.frozen.clone(),
                    bootstrap.clone(),
                )
            })
        })
    });
    let Some((run, mut completed, assessment, frozen, bootstrap)) = pending else {
        return Ok(());
    };
    if request.current_run != Some(&run)
        || serde_json::to_vec(plan)? != serde_json::to_vec(&completed)?
        || request.admission_policy_input.entrypoint_bound != bootstrap.concurrency
        || request.quota.context.is_some()
        || request.quota.ledger.is_some()
        || history.is_some_and(|history| {
            history.provenance.projected_attempt_count != 0
                || !history.provenance.source_digests.is_empty()
                || !history.provenance.exclusions.is_empty()
        })
        || super::prior_input::current_provenance().as_ref() != Some(&bootstrap.prior)
        || observations.len() != 1
        || observations[0].0 != SupervisorRuntime::Codex
    {
        bail!("budget bootstrap requires its unchanged no-history/no-quota run inputs");
    }
    super::prior_input::require_binding_repo(request.repo)?;
    let objective = metadata
        .resolved_objective_profile
        .as_ref()
        .context("budget fixture resolved run objective")?;
    let features = super::selection_bridge::routing_features_with_assessment(
        &completed,
        Some(&assessment),
        Some(&frozen),
    )?;
    let priors = super::selection_bridge::selector_priors_with_terminal_worker_economics()?;
    let observation = &observations[0].1;
    let observation_digest =
        crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(observation)?);
    let subject_role = completed.assignments[0].role;
    let (subject_effort, auditor_effort) = {
        // Temporary review authorization is restored before the completed fixture
        // is stored; normal initialization must independently seal every role.
        let _bootstrap_policy =
            crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
        let (subject, subject_decision) =
            super::selection_bridge::select_normal_account_intake_with_assessment(
                &completed,
                &frozen,
                observations,
                request.admission_policy_input,
                objective,
                history,
                Some(&assessment),
            )?;
        let subject = subject.context("budget fixture subject selection refused")?;
        let (auditor, auditor_decision) =
            super::selection_bridge::select_account_review_auditor_with_assessment(
                &completed,
                &frozen,
                observations,
                request.admission_policy_input,
                objective,
                Some(&assessment),
            )?;
        let auditor = auditor.context("budget fixture auditor selection refused")?;
        for (role, selected, decision) in [
            (subject_role, &subject, &subject_decision),
            (AgentRole::Auditor, &auditor, &auditor_decision),
        ] {
            let receipt = decision
                .routing_policy
                .as_ref()
                .context("budget bootstrap policy receipt")?;
            let choice = decision
                .choice
                .as_ref()
                .context("budget bootstrap choice")?;
            let task = super::selection_bridge::task_profile_with_assessment(
                role,
                Some(&assessment),
                Some(&features),
                Some(&frozen),
            )?;
            selected.validate_binding(&crate::selection::routing_policy::AccountBinding::from(
                &observation.binding,
            ))?;
            if decision.status != crate::selection::DecisionStatus::Selected
                || selected.candidate() != &choice.candidate
                || selected.candidate().runtime != SupervisorRuntime::Codex.as_str()
                || selected.candidate().model != bootstrap.model
                || selected.candidate().effort.as_str() != bootstrap.effort.as_str()
                || receipt.frozen != frozen
                || receipt.role != role.as_str()
                || receipt.features != features
                || selected.policy_digest != frozen.sha256
                || selected.task_features != features
                || selected.catalog_digest != observation_digest
                || selected.catalog_revision
                    != format!("account-observe-sha256:{observation_digest}")
                || decision.normalized_input.task != task
                || decision.normalized_task != task
                || decision.normalized_input.resolved_objective_profile != *objective
                || decision.resolved_objective_profile != *objective
                || decision.normalized_input.priors.dataset_id != priors.dataset_id
                || decision.normalized_input.priors.revision != priors.revision
                || decision.normalized_input.priors.published_on != priors.published_on
                || decision.operator_prior_data.as_ref() != Some(&bootstrap.prior)
                || decision.normalized_input.debug_override.is_some()
                || decision.debug_override.is_some()
                || !decision.normalized_input.outcomes.is_empty()
                || !decision.candidate_set.iter().any(|evaluation| {
                    evaluation.candidate == choice.candidate
                        && evaluation.eligible
                        && evaluation.ineligibility_reasons.is_empty()
                })
            {
                bail!("budget bootstrap differs from its genuine role/account/policy decision");
            }
        }
        (subject.candidate().effort, auditor.candidate().effort)
    };
    for (role, effort) in [
        (subject_role, subject_effort),
        (AgentRole::Auditor, auditor_effort),
    ] {
        let configured = completed
            .role_models
            .get_mut(&role)
            .context("budget fixture requires its authored role preference")?;
        if configured.model.as_deref() != Some(bootstrap.model.as_str())
            || configured
                .reasoning_effort
                .as_deref()
                .is_some_and(|existing| existing != effort.as_str())
        {
            bail!("budget fixture selection conflicts with its authored role preference");
        }
        if configured.reasoning_effort.is_none() {
            configured.reasoning_effort = Some(effort.as_str().to_string());
        }
    }
    for lens in &mut completed.review_lenses {
        let ReviewLensBackendConfig::Model {
            model,
            reasoning_effort,
            ..
        } = &mut lens.backend
        else {
            bail!("budget fixture requires its authored executable review lenses");
        };
        if model.as_str() != bootstrap.model.as_str()
            || reasoning_effort
                .as_deref()
                .is_some_and(|existing| existing != auditor_effort.as_str())
        {
            bail!("budget fixture selection conflicts with its authored review lens");
        }
        if reasoning_effort.is_none() {
            *reasoning_effort = Some(auditor_effort.as_str().to_string());
        }
    }
    SELECTED_CONCURRENT_FIXTURE.with(|slot| -> Result<()> {
        let mut slot = slot.borrow_mut();
        let fixture = slot
            .as_mut()
            .context("budget fixture binding disappeared")?;
        if fixture.run != run || fixture.budget_bootstrap.is_none() {
            bail!("budget fixture binding changed during completion");
        }
        fixture.plan = completed.clone();
        fixture.budget_bootstrap = None;
        Ok(())
    })?;
    *plan = completed;
    if !selected_concurrent_fixture_matches(plan, metadata, request)? {
        bail!("completed budget fixture lost its exact binding");
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn carry_selected_concurrent_fixture_metadata(
    plan: &SupervisorPlan,
    options: &SupervisorRunOptions,
    catalog: &RuntimeModelCatalog,
    metadata: &mut SupervisorPlanMetadata,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    let _ = (plan, options, catalog, metadata);
    #[cfg(target_os = "linux")]
    SELECTED_CONCURRENT_FIXTURE.with(|slot| -> Result<()> {
        let slot = slot.borrow();
        let Some(fixture) = slot
            .as_ref()
            .filter(|fixture| fixture.run == options.run_id)
        else {
            return Ok(());
        };
        if let Some(custody) = &fixture.inherited {
            custody.verify(
                &fixture.plan,
                &fixture.run,
                &fixture.repo,
                &fixture.frozen,
                &fixture.assessment,
            )?;
        }
        if options.repo.canonicalize()? != fixture.repo
            || options.runtime != SupervisorRuntime::Codex
            || serde_json::to_vec(plan)? != serde_json::to_vec(&fixture.plan)?
            || !matches!(catalog, RuntimeModelCatalog::Codex(actual) if actual == &fixture.catalog)
            || metadata.task_routing_assessment.is_some()
            || metadata.resolved_routing_policy.is_some()
        {
            bail!("selected concurrent fixture input differs from its explicit binding");
        }
        metadata.task_routing_assessment = Some(fixture.assessment.clone());
        metadata.resolved_routing_policy = Some(fixture.frozen.clone());
        Ok(())
    })?;
    Ok(())
}

// Evidence-only fixtures retain authenticated historical metadata separately
// from the assessment of the current task. No candidate-tree check belongs here.
#[cfg(all(test, target_os = "linux"))]
struct SelectedEvidenceOnlyReauditFixture {
    run: RunId,
    repo: PathBuf,
    plan: SupervisorPlan,
    catalog: CodexRuntimeModelCatalog,
    historical_metadata: SupervisorPlanMetadata,
    current_assessment: TaskRoutingAssessment,
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static SELECTED_EVIDENCE_ONLY_REAUDIT_FIXTURE: RefCell<Option<SelectedEvidenceOnlyReauditFixture>> =
        const { RefCell::new(None) };
}

#[cfg(all(test, target_os = "linux"))]
pub(super) struct SelectedEvidenceOnlyReauditFixtureGuard<'scope, 'owner> {
    previous: Option<SelectedEvidenceOnlyReauditFixture>,
    _parent_acceptance: &'scope super::InjectedSupervisorParentAcceptanceGuard<'owner>,
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for SelectedEvidenceOnlyReauditFixtureGuard<'_, '_> {
    fn drop(&mut self) {
        SELECTED_EVIDENCE_ONLY_REAUDIT_FIXTURE.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(super) fn bind_selected_evidence_only_reaudit_fixture<'scope, 'owner>(
    loaded: &LoadedSupervisorPlan,
    options: &SupervisorRunOptions,
    catalog: &RuntimeModelCatalog,
    current_assessment: TaskRoutingAssessment,
    parent_acceptance: &'scope super::InjectedSupervisorParentAcceptanceGuard<'owner>,
) -> Result<SelectedEvidenceOnlyReauditFixtureGuard<'scope, 'owner>> {
    let repo = options.repo.canonicalize()?;
    let [assignment] = loaded.plan.assignments.as_slice() else {
        bail!("selected evidence-only fixture requires exactly its historical subject");
    };
    let operation = loaded
        .plan_metadata
        .evidence_only_reaudit
        .as_ref()
        .context("selected evidence-only fixture operation")?;
    let frozen = loaded
        .plan_metadata
        .resolved_routing_policy
        .as_ref()
        .context("selected evidence-only fixture historical policy")?;
    let historical = loaded
        .plan_metadata
        .task_routing_assessment
        .as_ref()
        .context("selected evidence-only fixture historical assessment")?;
    let RuntimeModelCatalog::Codex(catalog) = catalog else {
        bail!("selected evidence-only fixture requires its actual Codex catalog");
    };
    if options.runtime != SupervisorRuntime::Codex
        || !repo.starts_with(parent_acceptance._account._owner.path().canonicalize()?)
        || options.run_id == operation.source_run_id
        || assignment.id != operation.assignment_id
        || loaded.plan_metadata.execution_target.is_some()
        || loaded.plan_metadata.normal_intake_selection.is_some()
        || loaded.plan_metadata.generated_follow_up.is_some()
        || crate::selection::routing_policy::current_routing_policy().as_ref() != Some(frozen)
        || !CAM_OBSERVE_TEST_OVERRIDE.with(|slot| slot.borrow().is_some())
        || SELECTED_CONCURRENT_FIXTURE.with(|slot| slot.borrow().is_some())
        || SELECTED_EVIDENCE_ONLY_REAUDIT_FIXTURE.with(|slot| slot.borrow().is_some())
        || super::test_runtime_model_catalog(&loaded.plan, options.runtime)?
            != RuntimeModelCatalog::Codex(catalog.clone())
    {
        bail!(
            "selected evidence-only fixture lost its owned run, catalog or held policy/account custody"
        );
    }
    historical.validate(frozen)?;
    current_assessment.validate_for_task(frozen, &loaded.plan.task)?;
    // This checks authenticated history and lineage only. It never reads or
    // validates the mutable preserved candidate tree, whose denial stays typed.
    verify_evidence_only_reaudit_source(&repo, operation, assignment, Some(historical))?;
    let fixture = SelectedEvidenceOnlyReauditFixture {
        run: options.run_id.clone(),
        repo,
        plan: loaded.plan.clone(),
        catalog: catalog.clone(),
        historical_metadata: loaded.plan_metadata.clone(),
        current_assessment,
    };
    let previous =
        SELECTED_EVIDENCE_ONLY_REAUDIT_FIXTURE.with(|slot| slot.borrow_mut().replace(fixture));
    Ok(SelectedEvidenceOnlyReauditFixtureGuard {
        previous,
        _parent_acceptance: parent_acceptance,
    })
}

#[cfg(all(test, target_os = "linux"))]
fn selected_evidence_only_reaudit_fixture_matches(
    fixture: &SelectedEvidenceOnlyReauditFixture,
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
    request: &PreparedSupervisorSelectionRequest<'_>,
) -> Result<bool> {
    // Preparation resolves a missing objective normally. Compare that resolved
    // copy without modifying the historical metadata retained by the caller.
    let mut expected_metadata = fixture.historical_metadata.clone();
    resolve_preselection_objective_profile(&fixture.repo, &mut expected_metadata)?;
    if request.current_run != Some(&fixture.run)
        || request.execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation
        || request.runtime != SupervisorRuntime::Codex
        || request.repo.canonicalize()? != fixture.repo
        || !matches!(request.runtime_model_catalog, Ok(RuntimeModelCatalog::Codex(actual)) if actual == &fixture.catalog)
        || plan != &fixture.plan
        || metadata != &expected_metadata
        || crate::selection::routing_policy::current_routing_policy().as_ref()
            != expected_metadata.resolved_routing_policy.as_ref()
    {
        bail!("selected evidence-only scheduler request differs from its exact fixture binding");
    }
    fixture.current_assessment.validate_for_task(
        expected_metadata
            .resolved_routing_policy
            .as_ref()
            .context("selected evidence-only fixture policy disappeared")?,
        &plan.task,
    )?;
    Ok(true)
}

#[cfg(all(test, target_os = "linux"))]
fn selected_concurrent_fixture_matches(
    plan: &SupervisorPlan,
    metadata: &SupervisorPlanMetadata,
    request: &PreparedSupervisorSelectionRequest<'_>,
) -> Result<bool> {
    if let Some(matches) = SELECTED_EVIDENCE_ONLY_REAUDIT_FIXTURE.with(|slot| {
        slot.borrow().as_ref().map(|fixture| {
            selected_evidence_only_reaudit_fixture_matches(fixture, plan, metadata, request)
        })
    }) {
        return matches;
    }
    SELECTED_CONCURRENT_FIXTURE.with(|slot| {
        let slot = slot.borrow();
        let Some(fixture) = slot.as_ref().filter(|fixture| request.current_run == Some(&fixture.run)) else {
            return Ok(false);
        };
        if let Some(custody) = &fixture.inherited {
            custody.verify(&fixture.plan, &fixture.run, &fixture.repo, &fixture.frozen, &fixture.assessment)?;
        }
        let mut expected_plan = fixture.plan.clone();
        expected_plan.assignments = plan.assignments.clone();
        if request.execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation
            || request.runtime != SupervisorRuntime::Codex
            || request.repo.canonicalize()? != fixture.repo
            || !matches!(request.runtime_model_catalog, Ok(RuntimeModelCatalog::Codex(actual)) if actual == &fixture.catalog)
            || metadata.resolved_routing_policy.as_ref() != Some(&fixture.frozen)
            || serde_json::to_vec(&metadata.task_routing_assessment)? != serde_json::to_vec(&Some(&fixture.assessment))?
            || metadata.evidence_only_reaudit.is_some()
            || metadata.execution_target.is_some()
            || metadata.normal_intake_selection.is_some()
            || serde_json::to_vec(plan)? != serde_json::to_vec(&expected_plan)?
        {
            bail!("selected concurrent scheduler request differs from its fixture binding");
        }
        // Preclaim may remove blocked assignments. It must not add or alter any subject.
        for assignment in &plan.assignments {
            let expected = fixture.plan.assignments.iter().find(|item| item.id == assignment.id)
                .context("selected concurrent preclaim subject is outside its fixture")?;
            if serde_json::to_vec(assignment)? != serde_json::to_vec(expected)? {
                bail!("selected concurrent preclaim subject differs from its fixture");
            }
        }
        fixture.assessment.validate_for_task(&fixture.frozen, &plan.task)?;
        Ok(true)
    })
}

#[cfg(target_os = "linux")]
fn observe_selected_cam_binding(
    registry: &StoredAccountRegistry,
    adapter: &dyn coding_agent_manager_lib::providers::ProviderAdapter,
    provider_id: &str,
) -> Result<Option<AccountObserveResult>> {
    let binding = match registry.selected_binding(provider_id) {
        Ok(None) => return Ok(None),
        Ok(Some(binding)) => binding,
        Err(error) => {
            return Err(anyhow!(
                "failed to read Coding Agent Manager selection for `{provider_id}`: {error}"
            ));
        }
    };
    observe_selected_account(
        registry,
        adapter,
        AccountObserveRequest {
            binding,
            categories: vec![ObserveCategory::Models, ObserveCategory::Quota],
        },
        None,
    )
    .map(Some)
    .map_err(|error| {
        anyhow!(
            "failed to observe selected Coding Agent Manager account for `{provider_id}`: {error}"
        )
    })
}

pub(super) fn acquire_normal_intake_catalog(
    options: &SupervisorRunOptions,
    selected: &crate::selection::routing_policy::SelectedLaunchRequest,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
) -> RuntimeModelCatalogAcquisition {
    let acquired = (|| -> Result<RuntimeModelCatalog> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (options, selected, frozen);
            bail!("normal account catalog requires managed Linux");
        }
        #[cfg(target_os = "linux")]
        {
            use coding_agent_manager_lib::account_authority::ObservationOutcome;
            if options.runtime.as_str() != selected.candidate().runtime {
                bail!("normal intake runtime differs from the frozen selected account route");
            }
            let observation = account_observation_for_launch_runtime(
                options.runtime,
                Some(options.run_id.as_str()),
            )?
            .context("normal intake selected account is no longer available")?;
            selected.validate_binding(&(&observation.binding).into())?;
            crate::selection::routing_policy::SelectedLaunchRequest::from_observation(
                selected.candidate().clone(),
                &observation,
                frozen,
                selected.task_features.clone(),
                selected.control_transport,
            )?;
            let models = observation
                .models
                .as_ref()
                .filter(|category| category.outcome == ObservationOutcome::Observed)
                .and_then(|category| category.content.as_ref())
                .context("normal intake account model metadata is unknown")?;
            if options.runtime == SupervisorRuntime::Codex {
                Ok(RuntimeModelCatalog::Codex(
                    CodexRuntimeModelCatalog::from_observed_models(models)?,
                ))
            } else {
                Ok(RuntimeModelCatalog::OperatorDeclared)
            }
        }
    })();
    acquired.map_err(|error| {
        Box::new(EnvironmentFailure::runtime_model_catalog(format!(
            "account-bound normal catalog refused: {error:#}"
        )))
    })
}

pub(crate) struct NormalIntakeConfig<'a> {
    pub(crate) admission_overrides: SupervisorAdmissionConfig,
    pub(crate) max_concurrent_children: usize,
    pub(crate) objective_profile: Option<&'a str>,
}

pub(crate) fn select_normal_intake(
    repo: &Path,
    run_id: &RunId,
    plan: &SupervisorPlan,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    assessment: Option<&TaskRoutingAssessment>,
    config: NormalIntakeConfig<'_>,
) -> Result<(
    SupervisorRuntime,
    crate::selection::routing_policy::SelectedLaunchRequest,
    crate::selection::SelectionProvenance,
)> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (repo, run_id, plan, frozen, assessment, config);
        bail!("automatic account-bound normal intake requires the managed Linux runtime");
    }
    #[cfg(target_os = "linux")]
    {
        let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
        let assessment = assessment.context(
            "automatic task assessment is unassessed: adopt task_estimation in the loaded routing policy before normal intake",
        )?;
        assessment.validate_for_task(frozen, &plan.task)?;
        let admission = SupervisorAdmissionPolicyInput::resolve_with_quota(
            repo,
            config.max_concurrent_children,
            SupervisorAdmissionConfig::default(),
            config.admission_overrides,
            None,
        )?;
        let objective = resolve_objective_profile(repo, config.objective_profile)?;
        let mut observations = Vec::new();
        for adapter in coding_agent_manager_lib::providers::registry() {
            let runtime = match adapter.id() {
                "codex-cli" => SupervisorRuntime::Codex,
                "grok-cli" => SupervisorRuntime::Grok,
                "cursor" => SupervisorRuntime::Cursor,
                "claude-code" => SupervisorRuntime::ClaudeCode,
                "gemini-cli" => SupervisorRuntime::GeminiCli,
                _ => continue,
            };
            if let Some(observation) =
                account_observation_for_launch_runtime(runtime, Some(run_id.as_str()))?
            {
                observations.push((runtime, observation));
            }
        }
        let history = load_frozen_outcome_history(repo, run_id)?;
        let (selected, decision) =
            super::selection_bridge::select_normal_account_intake_with_assessment(
                plan,
                frozen,
                &observations,
                &admission,
                &objective,
                Some(&history),
                Some(assessment),
            )?;
        let selected = selected.with_context(|| {
            format!(
                "normal account-bound intake refused before dispatch: {}{}",
                decision.decision_reason,
                crate::selection::runtime_model_policy::missing_model_guidance(
                    &decision.normalized_input
                )
            )
        })?;
        let runtime = super::selection_bridge::runtime_from_name(&selected.candidate().runtime)?;
        // Check the complete live tuple again before handing this binding to the
        // ordinary supervisor. Execution still performs its own account checks.
        let provider = &selected.account_binding().provider_id;
        let live = if let Some(socket) =
            crate::account_authority::cam_socket_for_run_selection(run_id.as_str(), provider)?
        {
            crate::account_authority::selected_binding_via_authority_socket(&socket, provider)?
                .map(|(_, binding)| binding)
        } else {
            let data_dir = project_dirs().context("account metadata directory is unavailable")?;
            StoredAccountRegistry::new(stored_accounts_path(data_dir.data_dir()))
                .selected_binding(provider)
                .map_err(|error| anyhow!("failed to revalidate normal intake selection: {error}"))?
        }
        .context("normal intake selected account disappeared")?;
        selected.validate_binding(&(&live).into())?;
        Ok((runtime, selected, decision))
    }
}

fn nonpublishable_success_guidance(runtime: SupervisorRuntime) -> (&'static str, &'static str) {
    if runtime == SupervisorRuntime::Fake {
        (
            "fake supervisor simulation succeeded but is not publishable or acceptable as real model evidence",
            "rerun with a verified runtime and complete candidate and configured review proof before acceptance, merge, publication, or follow-up dispatch",
        )
    } else {
        (
            "supervisor completed without a reported failure, but verified execution, exact assignment candidate evidence, or complete configured parent review proof is missing; the run is not publishable",
            "inspect the missing execution, assignment candidate, and configured parent review proof, then rerun the affected scopes before acceptance, merge, publication, or follow-up dispatch",
        )
    }
}

fn terminal_publishable(
    success: bool,
    runtime: SupervisorRuntime,
    execution_runtime: SupervisorExecutionRuntime,
    plan: &SupervisorPlan,
    reports: &[OrchestratorReviewReport],
    inspections: &BTreeMap<String, SupervisorCandidateInspection>,
) -> bool {
    if !success
        || runtime == SupervisorRuntime::Fake
        || execution_runtime != SupervisorExecutionRuntime::Verified
        || plan.assignments.is_empty()
        || validate_review_lens_set(&plan.review_lenses, plan.review_lens_correlation).is_err()
        || reports.len() != plan.assignments.len()
        || inspections.len() != plan.assignments.len()
    {
        return false;
    }
    let assignment_ids = plan
        .assignments
        .iter()
        .map(|assignment| assignment.id.as_str())
        .collect::<BTreeSet<_>>();
    let report_ids = reports
        .iter()
        .map(|report| report.id.as_str())
        .collect::<BTreeSet<_>>();
    if assignment_ids.len() != plan.assignments.len()
        || report_ids != assignment_ids
        || inspections
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != assignment_ids
    {
        return false;
    }
    plan.assignments.iter().all(|assignment| {
        let report = reports
            .iter()
            .find(|report| report.id == assignment.id)
            .expect("exact report ids checked above");
        let inspection = &inspections[&assignment.id];
        let Some(aggregate) = report.review_lens_aggregate.as_ref() else {
            return false;
        };
        if report_failed(report)
            || report.role != assignment.role
            || report.assigned_paths != assignment.assigned_paths
            || inspection.binding.agent_id != assignment.id
            || inspection.binding.clone().canonicalized().is_err()
            || normalize_paths(report.files_changed.clone()).ok().as_ref()
                != Some(&inspection.changed_paths)
            || aggregate.authority() != ReviewLensAggregateAuthority::ParentComputed
            || aggregate.decision != ReviewAggregationDecision::Accept
            || aggregate.policy != plan.review_aggregation_policy
            || aggregate.required_coverage
                != supervisor_review_coverage_requirement(assignment, report)
            || aggregate.lens_verdicts.len() != plan.review_lenses.len()
        {
            return false;
        }
        plan.review_lenses.iter().all(|lens| {
            let matching = aggregate
                .lens_verdicts
                .iter()
                .filter(|verdict| verdict.lens.id == lens.id)
                .collect::<Vec<_>>();
            matching.len() == 1
                && matching[0].reported
                && matching[0].validation_errors.is_empty()
                && matching[0].lens.information_scope == lens.information_scope
                && aggregate
                    .required_coverage
                    .worker_ids
                    .iter()
                    .all(|id| matching[0].coverage.worker_ids.contains(id))
                && aggregate
                    .required_coverage
                    .paths
                    .iter()
                    .all(|path| matching[0].coverage.paths.contains(path))
        })
    })
}

pub(crate) fn account_observations_for_selection(
    primary_runtime: SupervisorRuntime,
    run_id: Option<&str>,
) -> Result<Vec<(SupervisorRuntime, AccountObserveResult)>> {
    if primary_runtime == SupervisorRuntime::Fake {
        return Ok(Vec::new());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (primary_runtime, run_id);
        Ok(Vec::new())
    }
    #[cfg(target_os = "linux")]
    {
        let mut observations = Vec::new();
        for adapter in coding_agent_manager_lib::providers::registry() {
            let Some(runtime) = super::selection_bridge::runtime_for_account_provider(adapter.id())
            else {
                continue;
            };
            if !super::runtime_executables::runtime_allowed(runtime) {
                continue;
            }
            if let Some(observation) = account_observation_for_launch_runtime(runtime, run_id)? {
                observations.push((runtime, observation));
            }
        }
        Ok(observations)
    }
}

pub(super) fn account_observation_for_launch_runtime(
    runtime: SupervisorRuntime,
    run_id: Option<&str>,
) -> Result<Option<AccountObserveResult>> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (runtime, run_id);
        return Ok(None);
    }
    #[cfg(target_os = "linux")]
    {
        let Some(provider_id) = cam_provider_id_for_supervisor_runtime(runtime) else {
            return Ok(None);
        };
        let socket_path = match run_id {
            Some(run_id) => {
                crate::account_authority::cam_socket_for_run_selection(run_id, provider_id)?
            }
            None => crate::account_authority::configured_cam_authority_socket(),
        };
        #[cfg(test)]
        {
            if let Some(result) = CAM_OBSERVE_TEST_OVERRIDE.with(|cell| {
                cell.borrow().as_ref().map(|harness| {
                    let adapter = harness
                        .secondary_adapter
                        .as_deref()
                        .filter(|adapter| adapter.id() == provider_id)
                        .unwrap_or(harness.adapter.as_ref());
                    observe_selected_cam_binding(&harness.registry, adapter, provider_id).inspect(
                        |observation| {
                            freeze_observed_managed_selection_from_registry(
                                run_id,
                                provider_id,
                                &harness.registry,
                                observation.as_ref(),
                            );
                        },
                    )
                })
            }) {
                return result;
            }
        }
        if let Some(socket_path) = socket_path {
            let observed = crate::account_authority::observe_selected_authority_via_socket(
                &socket_path,
                provider_id,
            )?;
            return Ok(match observed {
                Some(observed) => {
                    record_observed_managed_selection(
                        run_id,
                        provider_id,
                        Some(observed.authority_id.clone()),
                        Some(&observed.observation.binding),
                        Some(&socket_path),
                    );
                    Some(observed.observation)
                }
                None => {
                    record_observed_managed_selection(
                        run_id,
                        provider_id,
                        None,
                        None,
                        Some(&socket_path),
                    );
                    None
                }
            });
        }
        let Some(data_dir) = project_dirs().map(|dirs| dirs.data_dir().to_path_buf()) else {
            if provider_id == crate::account_authority::CODEX_CLI_PROVIDER_ID {
                record_observed_managed_selection(run_id, provider_id, None, None, None);
            }
            return Ok(None);
        };
        let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
        let adapter = coding_agent_manager_lib::providers::find(provider_id).ok_or_else(|| {
            anyhow!("Coding Agent Manager provider `{provider_id}` is not registered")
        })?;
        let observation = observe_selected_cam_binding(&registry, adapter.as_ref(), provider_id)?;
        freeze_observed_managed_selection_from_registry(
            run_id,
            provider_id,
            &registry,
            observation.as_ref(),
        );
        Ok(observation)
    }
}

#[cfg(target_os = "linux")]
fn freeze_observed_managed_selection_from_registry(
    run_id: Option<&str>,
    provider_id: &str,
    registry: &StoredAccountRegistry,
    observation: Option<&AccountObserveResult>,
) {
    record_observed_managed_selection(
        run_id,
        provider_id,
        observation.map(|_| authority_id_for(registry.metadata_path())),
        observation.map(|observation| &observation.binding),
        None,
    );
}

#[cfg(target_os = "linux")]
fn freeze_selected_codex_launch_binding(run_id: Option<&str>) -> Result<()> {
    let Some(run_id) = run_id else { return Ok(()) };
    if crate::account_authority::codex_run_account_binding(run_id).is_some() {
        return Ok(());
    }
    // Parent, terminal roles and a nested Codex Worker share this initialized run.
    // Read selection metadata only; never acquire a model catalog or auth here.
    const PROVIDER: &str = crate::account_authority::CODEX_CLI_PROVIDER_ID;
    #[cfg(test)]
    if CAM_OBSERVE_TEST_OVERRIDE
        .with(|cell| {
            cell.borrow().as_ref().map(|harness| {
                let binding = harness.registry.selected_binding(PROVIDER)?;
                crate::account_authority::record_observed_codex_selection_from_source(
                    Some(run_id),
                    PROVIDER,
                    binding
                        .as_ref()
                        .map(|_| authority_id_for(harness.registry.metadata_path())),
                    binding.as_ref(),
                    None,
                );
                Ok::<(), coding_agent_manager_lib::error::Error>(())
            })
        })
        .transpose()?
        .is_some()
    {
        return Ok(());
    }
    if let Some(socket_path) = crate::account_authority::configured_cam_authority_socket() {
        let live = crate::account_authority::selected_binding_via_authority_socket(
            &socket_path,
            PROVIDER,
        )?;
        match live {
            Some((authority, binding)) => {
                crate::account_authority::record_observed_codex_selection_from_source(
                    Some(run_id),
                    PROVIDER,
                    Some(authority),
                    Some(&binding),
                    Some(&socket_path),
                )
            }
            None => crate::account_authority::record_observed_codex_selection_from_source(
                Some(run_id),
                PROVIDER,
                None,
                None,
                Some(&socket_path),
            ),
        }
        return Ok(());
    }
    let Some(data_dir) = project_dirs() else {
        crate::account_authority::record_observed_codex_selection_from_source(
            Some(run_id),
            PROVIDER,
            None,
            None,
            None,
        );
        return Ok(());
    };
    let registry = StoredAccountRegistry::new(stored_accounts_path(data_dir.data_dir()));
    let binding = registry
        .selected_binding(PROVIDER)
        .context("failed to read selected Coding Agent Manager Codex account")?;
    crate::account_authority::record_observed_codex_selection_from_source(
        Some(run_id),
        PROVIDER,
        binding
            .as_ref()
            .map(|_| authority_id_for(registry.metadata_path())),
        binding.as_ref(),
        None,
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn freeze_selected_claude_launch_binding(run_id: Option<&str>) -> Result<()> {
    const PROVIDER: &str = crate::account_authority::CLAUDE_CODE_PROVIDER_ID;
    let socket_path = match run_id {
        Some(run_id) => crate::account_authority::cam_socket_for_run_selection(run_id, PROVIDER)?,
        None => crate::account_authority::configured_cam_authority_socket(),
    };
    if let Some(socket_path) = socket_path {
        let selected = crate::account_authority::selected_binding_via_authority_socket(
            &socket_path,
            PROVIDER,
        )?;
        match selected {
            Some((authority_id, binding)) => {
                record_observed_managed_selection(
                    run_id,
                    PROVIDER,
                    Some(authority_id),
                    Some(&binding),
                    Some(&socket_path),
                );
            }
            None => {
                record_observed_managed_selection(run_id, PROVIDER, None, None, Some(&socket_path));
            }
        }
        return Ok(());
    }
    let data_dir = project_dirs()
        .map(|dirs| dirs.data_dir().to_path_buf())
        .context("Coding Agent Manager data directory is unavailable")?;
    let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
    let binding = registry
        .selected_binding(PROVIDER)
        .context("failed to read selected Coding Agent Manager Claude account")?;
    record_observed_managed_selection(
        run_id,
        PROVIDER,
        binding
            .as_ref()
            .map(|_| authority_id_for(registry.metadata_path())),
        binding.as_ref(),
        None,
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn record_observed_managed_selection(
    run_id: Option<&str>,
    provider_id: &str,
    authority_id: Option<String>,
    binding: Option<&coding_agent_manager_lib::account_authority::SelectedAccountBinding>,
    authority_socket: Option<&Path>,
) {
    if provider_id == crate::account_authority::CODEX_CLI_PROVIDER_ID {
        crate::account_authority::record_observed_codex_selection_from_source(
            run_id,
            provider_id,
            authority_id,
            binding,
            authority_socket,
        );
    } else if provider_id == crate::account_authority::GROK_CLI_PROVIDER_ID {
        crate::account_authority::record_observed_grok_selection(
            run_id,
            provider_id,
            authority_id,
            binding,
            authority_socket,
        );
    } else if provider_id == crate::account_authority::CLAUDE_CODE_PROVIDER_ID {
        crate::account_authority::record_observed_claude_selection(
            run_id,
            provider_id,
            authority_id,
            binding,
            authority_socket,
        );
    } else if provider_id == crate::account_authority::GEMINI_CLI_PROVIDER_ID {
        crate::account_authority::record_observed_gemini_selection(
            run_id,
            provider_id,
            authority_id,
            binding,
            authority_socket,
        );
    } else if provider_id == crate::account_authority::CURSOR_PROVIDER_ID {
        crate::account_authority::record_observed_cursor_selection_from_source(
            run_id,
            provider_id,
            authority_id,
            binding,
            authority_socket,
        );
    }
}

#[cfg(target_os = "linux")]
fn freeze_selected_secondary_managed_launch_bindings(
    plan: &SupervisorPlan,
    decisions: &[SupervisorSelectionEvent],
    primary_runtime: SupervisorRuntime,
    run_id: Option<&str>,
) -> Result<()> {
    let Some(run_id) = run_id else { return Ok(()) };
    let has_nested_workers = plan.assignments.iter().any(|assignment| {
        assignment.role == AgentRole::ChildOrchestrator && !assignment.worker_assignments.is_empty()
    });
    let resolved_runtime = |role| {
        decisions
            .iter()
            .rev()
            .find(|decision| decision.role == role)
            .and_then(|decision| decision.provenance.choice.as_ref())
            .map(|choice| runtime_from_name(&choice.candidate.runtime))
            .transpose()
    };
    let nested_runtime = if has_nested_workers {
        resolved_runtime(AgentRole::Worker)?
            .filter(|runtime| matches!(runtime, SupervisorRuntime::Codex | SupervisorRuntime::Grok))
    } else {
        None
    };
    // Parent review is not a top-level assignment: its model-backed lenses use
    // the resolved Auditor runtime. Any launched assignment can produce a
    // report requiring parent review; no empty plan or unused selector role
    // authorizes an additional account lookup.
    let auditor_runtime = if !plan.assignments.is_empty()
        && plan
            .review_lenses
            .iter()
            .any(|lens| matches!(&lens.backend, ReviewLensBackendConfig::Model { .. }))
    {
        resolved_runtime(AgentRole::Auditor)?
    } else {
        None
    };
    for runtime in [
        SupervisorRuntime::Grok,
        SupervisorRuntime::GeminiCli,
        SupervisorRuntime::Cursor,
    ] {
        if runtime == primary_runtime
            || (!plan
                .assignments
                .iter()
                .any(|assignment| assignment.runtime == Some(runtime))
                && nested_runtime != Some(runtime)
                && auditor_runtime != Some(runtime))
        {
            continue;
        }
        let already_frozen = match runtime {
            SupervisorRuntime::Grok => {
                crate::account_authority::grok_run_account_binding(run_id).is_some()
            }
            SupervisorRuntime::GeminiCli => {
                crate::account_authority::gemini_run_account_binding(run_id).is_some()
            }
            SupervisorRuntime::Cursor => {
                crate::account_authority::cursor_run_account_binding(run_id).is_some()
            }
            _ => unreachable!(),
        };
        if already_frozen {
            continue;
        }
        let provider = cam_provider_id_for_supervisor_runtime(runtime)
            .context("selected secondary runtime has no Coding Agent Manager provider")?;
        // Selection metadata only: no secondary adapter/catalog/auth/provider observation.
        #[cfg(test)]
        let test_binding = CAM_OBSERVE_TEST_OVERRIDE
            .with(|cell| {
                cell.borrow().as_ref().map(|harness| {
                    harness.registry.selected_binding(provider).map(|binding| {
                        binding.map(|binding| {
                            (authority_id_for(harness.registry.metadata_path()), binding)
                        })
                    })
                })
            })
            .transpose()?;
        #[cfg(not(test))]
        let test_binding: Option<
            Option<(
                String,
                coding_agent_manager_lib::account_authority::SelectedAccountBinding,
            )>,
        > = None;
        let authority_socket = if test_binding.is_some() {
            None
        } else {
            crate::account_authority::cam_socket_for_run_selection(run_id, provider)?
        };
        let selected = if let Some(selected) = test_binding {
            selected
        } else if let Some(socket) = authority_socket.as_ref() {
            crate::account_authority::selected_binding_via_authority_socket(socket, provider)?
        } else {
            let dirs =
                project_dirs().context("Coding Agent Manager data directory is unavailable")?;
            let registry = StoredAccountRegistry::new(stored_accounts_path(dirs.data_dir()));
            registry
                .selected_binding(provider)
                .context("failed to read selected secondary Coding Agent Manager account")?
                .map(|binding| (authority_id_for(registry.metadata_path()), binding))
        };
        let Some((authority, binding)) = selected else {
            record_observed_managed_selection(
                Some(run_id),
                provider,
                None,
                None,
                authority_socket.as_deref(),
            );
            bail!(
                "no complete selected Coding Agent Manager account for secondary runtime '{provider}'"
            );
        };
        if binding.provider_id != provider {
            bail!("selected secondary Coding Agent Manager binding has a different provider");
        }
        record_observed_managed_selection(
            Some(run_id),
            provider,
            Some(authority),
            Some(&binding),
            authority_socket.as_deref(),
        );
    }
    Ok(())
}

pub(super) fn initialize_supervisor_selection_from_prepared_metadata(
    plan: &mut SupervisorPlan,
    plan_metadata: &mut SupervisorPlanMetadata,
    request: PreparedSupervisorSelectionRequest<'_>,
) -> Result<SupervisorSelectionResolution> {
    initialize_supervisor_selection_with_catalog_discovery(
        plan,
        plan_metadata,
        request,
        advertised_catalogs_for_launch,
    )
}

fn initialize_supervisor_selection_with_catalog_discovery(
    plan: &mut SupervisorPlan,
    plan_metadata: &mut SupervisorPlanMetadata,
    request: PreparedSupervisorSelectionRequest<'_>,
    discover_catalogs: impl FnOnce(&Path) -> Result<AdvertisedCatalogSet>,
) -> Result<SupervisorSelectionResolution> {
    #[cfg(all(test, target_os = "linux"))]
    let selected_concurrent_fixture =
        selected_concurrent_fixture_matches(plan, plan_metadata, &request)?;
    let PreparedSupervisorSelectionRequest {
        repo,
        current_run,
        runtime,
        execution_runtime,
        runtime_model_catalog,
        admission_policy_input,
        quota,
    } = request;
    if plan_metadata.resolved_routing_policy.is_none() {
        plan_metadata.resolved_routing_policy =
            Some(crate::selection::routing_policy::load_routing_policy(repo)?);
    }
    let _routing_policy_guard = crate::selection::routing_policy::bind_routing_policy(
        plan_metadata.resolved_routing_policy.clone(),
    )?;
    if plan_metadata.resolved_objective_profile.is_none() {
        let requested_objective_profile = plan_metadata.objective_profile.clone();
        plan_metadata.resolved_objective_profile = Some(
            resolve_objective_profile(repo, requested_objective_profile.as_deref())
                .context("failed to resolve the supervisor objective profile")?,
        );
    }

    #[cfg(all(test, target_os = "linux"))]
    if selected_concurrent_fixture {
        // Explicit fixture evidence only; no ambient provider discovery or live-proof claim.
        let account_observations =
            account_observations_for_selection(runtime, current_run.map(RunId::as_str))?;
        let history = current_run
            .map(|run| load_frozen_outcome_history(repo, run))
            .transpose()?;
        let catalog = runtime_model_catalog
            .as_ref()
            .map_err(|_| anyhow!("selected fixture catalog failed"))?;
        complete_selected_budget_fixture(
            plan,
            plan_metadata,
            &PreparedSupervisorSelectionRequest {
                repo,
                current_run,
                runtime,
                execution_runtime,
                runtime_model_catalog,
                admission_policy_input,
                quota,
            },
            history.as_ref(),
            &account_observations,
        )?;
        let current_reaudit_assessment = SELECTED_EVIDENCE_ONLY_REAUDIT_FIXTURE.with(|slot| {
            slot.borrow()
                .as_ref()
                .map(|fixture| fixture.current_assessment.clone())
        });
        let resolution = super::selection_bridge::initialize_supervisor_selection_with_assessment(
            plan,
            runtime,
            catalog,
            admission_policy_input,
            &AdvertisedCatalogSet::empty(),
            plan_metadata.resolved_objective_profile.as_ref(),
            quota,
            history.as_ref(),
            &account_observations,
            current_reaudit_assessment
                .as_ref()
                .or(plan_metadata.task_routing_assessment.as_ref()),
        )?;
        if resolution.selection_preflight_failure.is_none() {
            bind_selected_assignment_runtimes(plan, &resolution.decisions)?;
            freeze_selected_codex_launch_binding(current_run.map(RunId::as_str))?;
            freeze_selected_secondary_managed_launch_bindings(
                plan,
                &resolution.decisions,
                runtime,
                current_run.map(RunId::as_str),
            )?;
        }
        return Ok(resolution);
    }
    let legacy_nonpublishable_explicit_selection =
        uses_legacy_nonpublishable_explicit_selection(execution_runtime, plan);
    match runtime_model_catalog.as_ref() {
        Ok(_) if legacy_nonpublishable_explicit_selection => Ok(SupervisorSelectionResolution {
            mode: SupervisorSelectionMode::LegacyNonpublishableSimulation,
            decisions: Vec::new(),
            automatic_state: None,
            selection_preflight_failure: None,
        }),
        Ok(catalog) => {
            // Model labels do not select an executor. Only an acquired local
            // Fake catalog with no authored real executor can avoid discovery.
            let local_deterministic_fake = runtime == SupervisorRuntime::Fake
                && matches!(catalog, RuntimeModelCatalog::LocalDeterministicFake)
                && plan.assignments.iter().all(|assignment| {
                    assignment.runtime.is_none()
                        || assignment.runtime == Some(SupervisorRuntime::Fake)
                });
            let advertised = if local_deterministic_fake {
                AdvertisedCatalogSet::empty()
            } else {
                discover_catalogs(repo)?
            };
            #[cfg(all(test, target_os = "linux"))]
            let advertised = CAM_OBSERVE_TEST_OVERRIDE
                .with(|cell| {
                    cell.borrow()
                        .as_ref()
                        .and_then(|harness| harness.advertised.clone())
                })
                .unwrap_or(advertised);
            let frozen_history = current_run
                .map(|run| load_frozen_outcome_history(repo, run))
                .transpose()?;
            let account_observations =
                account_observations_for_selection(runtime, current_run.map(RunId::as_str))?;
            #[cfg(target_os = "linux")]
            let account_observation = account_observations
                .iter()
                .find(|(observed_runtime, _)| *observed_runtime == runtime)
                .map(|(_, observation)| observation);
            #[cfg(target_os = "linux")]
            if let Some(selected) = &plan_metadata.normal_intake_selection {
                let observed = account_observation
                    .context("normal intake account observation disappeared before selection")?;
                selected.validate_binding(&(&observed.binding).into())?;
                let revalidated =
                    crate::selection::routing_policy::SelectedLaunchRequest::from_observation(
                        selected.candidate().clone(),
                        observed,
                        plan_metadata
                            .resolved_routing_policy
                            .as_ref()
                            .context("normal intake policy disappeared")?,
                        selected.task_features.clone(),
                        selected.control_transport,
                    )?;
                // Persist current catalog qualification and uncertainty rather
                // than carrying an earlier advertisement as live access proof.
                plan_metadata.normal_intake_selection = Some(revalidated);
            }
            let resolution =
                super::selection_bridge::initialize_supervisor_selection_with_assessment(
                    plan,
                    runtime,
                    catalog,
                    admission_policy_input,
                    &advertised,
                    plan_metadata.resolved_objective_profile.as_ref(),
                    quota,
                    frozen_history.as_ref(),
                    &account_observations,
                    if plan_metadata.evidence_only_reaudit.is_some() {
                        None
                    } else {
                        plan_metadata.task_routing_assessment.as_ref()
                    },
                )?;
            #[cfg(all(test, target_os = "linux"))]
            let resolution = {
                let mut resolution = resolution;
                // A synthetic resolved role exercises the real initialization
                // and launch-binding boundary without account-slot seeding or
                // claiming a provider/model catalog observation.
                if resolution.selection_preflight_failure.is_none() {
                    let auditor = CAM_OBSERVE_TEST_OVERRIDE.with(|cell| {
                        cell.borrow()
                            .as_ref()
                            .and_then(|harness| harness.resolved_auditor.clone())
                    });
                    if let Some(mut auditor) = auditor {
                        let choice = auditor
                            .provenance
                            .choice
                            .as_ref()
                            .context("synthetic resolved Auditor choice")?;
                        let old_model = plan
                            .role_models
                            .get(&AgentRole::Auditor)
                            .and_then(|selection| selection.model.clone());
                        for lens in &mut plan.review_lenses {
                            if let ReviewLensBackendConfig::Model {
                                model,
                                reasoning_effort,
                                ..
                            } = &mut lens.backend
                            {
                                if Some(model.as_str()) == old_model.as_deref() {
                                    *model = choice.candidate.model.clone();
                                    *reasoning_effort = Some(
                                        selector_effort_as_str(choice.candidate.effort).to_string(),
                                    );
                                }
                            }
                        }
                        plan.role_models.insert(
                            AgentRole::Auditor,
                            RoleModelSelection {
                                model: Some(choice.candidate.model.clone()),
                                reasoning_effort: Some(
                                    selector_effort_as_str(choice.candidate.effort).to_string(),
                                ),
                                unavailable_model_fallback: UnavailableModelFallback::FailClosed,
                            },
                        );
                        auditor.assignment_id = Some("synthetic-resolved-auditor".to_string());
                        auditor.provenance.normalized_input.signals.previous_choice = resolution
                            .decisions
                            .iter()
                            .find(|decision| decision.role == AgentRole::Auditor)
                            .and_then(|decision| decision.provenance.choice.as_ref())
                            .map(|choice| choice.candidate.clone());
                        if let Some(state) = resolution.automatic_state.as_mut() {
                            state.commit_completed_selection_events(
                                runtime,
                                std::slice::from_ref(&auditor),
                            )?;
                        }
                        resolution
                            .decisions
                            .retain(|decision| decision.role != AgentRole::Auditor);
                        resolution.decisions.push(auditor);
                    }
                }
                resolution
            };
            if resolution.selection_preflight_failure.is_none() {
                bind_selected_assignment_runtimes(plan, &resolution.decisions)?;
                #[cfg(target_os = "linux")]
                // Automatic state supplies budget-selected Worker/Auditor
                // runtimes. Any such state or decision retains account binding.
                if !local_deterministic_fake
                    || resolution.automatic_state.is_some()
                    || !resolution.decisions.is_empty()
                {
                    freeze_selected_codex_launch_binding(current_run.map(RunId::as_str))?;
                    if plan
                        .assignments
                        .iter()
                        .any(|assignment| assignment.runtime == Some(SupervisorRuntime::ClaudeCode))
                    {
                        freeze_selected_claude_launch_binding(current_run.map(RunId::as_str))?;
                    }
                    freeze_selected_secondary_managed_launch_bindings(
                        plan,
                        &resolution.decisions,
                        runtime,
                        current_run.map(RunId::as_str),
                    )?;
                }
            }
            Ok(resolution)
        }
        Err(_) => Ok(SupervisorSelectionResolution {
            mode: SupervisorSelectionMode::LegacyFake,
            decisions: Vec::new(),
            automatic_state: None,
            selection_preflight_failure: None,
        }),
    }
}

struct PredispatchFailureFinalization<'context, 'checkpoint> {
    plan: &'context SupervisorPlan,
    plan_metadata: &'context SupervisorPlanMetadata,
    options: &'context SupervisorRunOptions,
    repo: &'context Path,
    budget_ledger: &'context RunBudgetLedger,
    artifact_writer: ArtifactRunWriter,
    checkpoint_writer: &'checkpoint mut SupervisorCheckpointWriter,
    run_dir: &'context Path,
    max_concurrent_children: usize,
    admission_policy_input: SupervisorAdmissionPolicyInput,
    has_multiple_independent_assignment_scopes: bool,
    runtime_model_catalog: Option<&'context RuntimeModelCatalog>,
    selection_decisions: Vec<SupervisorSelectionEvent>,
    preclaim_parked_assignment_ids: BTreeSet<String>,
}

enum SupervisorPredispatchFailure {
    RuntimeModelCatalog(EnvironmentFailure),
    Selection(SupervisorSelectionPreflightFailure),
}

fn persist_supervisor_predispatch_failure(
    finalization: PredispatchFailureFinalization<'_, '_>,
    failure: SupervisorPredispatchFailure,
) -> Result<SupervisorFinalReport> {
    let PredispatchFailureFinalization {
        plan,
        plan_metadata,
        options,
        repo,
        budget_ledger,
        artifact_writer,
        checkpoint_writer,
        run_dir,
        max_concurrent_children,
        admission_policy_input,
        has_multiple_independent_assignment_scopes,
        runtime_model_catalog,
        selection_decisions,
        preclaim_parked_assignment_ids,
    } = finalization;
    let run_budget_report = budget_ledger.report()?;
    let (report_plan_file, report_run_dir) =
        supervisor_report_paths(repo, &options.plan_file, run_dir, &options.run_id);
    let mut collected = CollectedAssignmentOutcomes {
        selection_decisions,
        preclaim_parked_assignment_ids,
        ..CollectedAssignmentOutcomes::default()
    };
    let (finding_message, environment_failures) = match failure {
        SupervisorPredispatchFailure::RuntimeModelCatalog(failure) => (
            "runtime model catalog preflight blocked supervisor dispatch; inspect the typed environment_failures entry"
                .to_string(),
            vec![failure],
        ),
        SupervisorPredispatchFailure::Selection(failure) => (
            format!(
                "selection preflight failed for role '{}' with typed state '{:?}': {}",
                failure.role.as_str(), failure.kind, failure.message
            ),
            Vec::new(),
        ),
    };
    collected.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: finding_message,
        paths: Vec::new(),
    });
    let mut final_report = build_supervisor_final_report(SupervisorFinalReportConstruction {
        plan,
        runtime_model_catalog,
        max_concurrent_children,
        admission_policy_input,
        achieved_concurrency: AchievedConcurrency::default(),
        has_multiple_independent_assignment_scopes,
        run_id: options.run_id.clone(),
        report_plan_file,
        report_run_dir,
        runtime: options.runtime,
        publishable: false,
        success: false,
        run_budget_report: Some(run_budget_report.clone()),
        budget_degradations: Vec::new(),
        assignment_effort_bindings: Vec::new(),
        evidence_only_reaudit: plan_metadata.evidence_only_reaudit.clone(),
        role_usage: BTreeMap::new(),
        review_lens_usage: Vec::new(),
        review_lens_total_usage: None,
        review_lens_total_cost_usd: None,
        total_usage: None,
        total_cost_usd: None,
        usage_complete: true,
        environment_failures,
        sandbox_denials: Vec::new(),
        collected,
        this_run_attempt_rows: load_this_run_attempt_cost_rows(artifact_writer.run_dir()),
        bloated_file_flags: Vec::new(),
        decomposition_candidates: Vec::new(),
        assignment_traceability: Vec::new(),
        coverage_gaps: plan_metadata.coverage_gaps.clone(),
        supervisor_breaker_trip: None,
        autonomy_kpis: AutonomyKpiReport::default(),
        released_claims: Vec::new(),
        release_errors: Vec::new(),
        released_semantic_intents: Vec::new(),
        semantic_release_errors: Vec::new(),
        external_containment_failed: false,
        final_primary_integrity_failed: false,
        budget_prevented_dispatch: false,
        budget_accounting_failed: false,
        breaker_tripped: false,
        field_guide_mutation_failed: false,
    });
    if let Some(profile) = final_report.role_economics_profile.as_mut() {
        profile.resolved_objective_profile = plan_metadata.resolved_objective_profile.clone();
    }
    apply_execution_target_reporting(&mut final_report, plan_metadata.execution_target.as_ref());
    let binding = artifact_writer
        .resume_binding()
        .context("failed to establish predispatch failure report boundary")?;
    checkpoint_writer.scheduler_closed(binding, run_budget_report)?;
    let mut orchestration_journal = None;
    persist_supervisor_final_report(
        final_report,
        &mut orchestration_journal,
        artifact_writer,
        Some(checkpoint_writer),
        Some(crate::artifacts::ArtifactScratchQuiescence::Verified),
        || Ok(()),
    )
}

pub(super) fn seal_successful_preflight_decisions(
    decisions: &[SupervisorSelectionEvent],
    failure: Option<&SupervisorSelectionPreflightFailure>,
) -> Result<()> {
    if failure.is_none() {
        for decision in decisions {
            if decision.provenance.status == crate::selection::DecisionStatus::Selected {
                crate::selection::routing_policy::seal_selected_candidate(
                    decision.role.as_str(),
                    &decision.provenance,
                )?;
            }
        }
    }
    Ok(())
}

pub(super) fn run_supervisor_plan_with_runner_and_creation(
    loaded: LoadedSupervisorPlan,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    let PreparedSupervisorRun {
        plan,
        requested_plan,
        consultant,
        assignment_metadata,
        plan_metadata,
        max_concurrent_children,
        admission_policy_input,
        runtime_model_catalog,
        selection_mode: _selection_mode,
        mut selection_decisions,
        selection_preflight_failure,
        automatic_selection_state,
        preclaim_decisions,
        preclaim_evidence,
        budget_ledger,
        runtime,
        repo,
        assignment_schedule,
        evidence_only_reaudit,
        mut artifact_writer,
        mut checkpoint_writer,
        run_dir,
        dirs,
        manager,
        _process_registration,
    } = prepare_supervisor_run(
        loaded,
        &options,
        max_concurrent_children,
        execution_runtime,
        worktree_creation,
        runtime_model_catalog,
    )?;
    let _routing_policy_guard = crate::selection::routing_policy::bind_routing_policy(
        plan_metadata.resolved_routing_policy.clone(),
    )?;
    seal_successful_preflight_decisions(
        &selection_decisions,
        selection_preflight_failure.as_ref(),
    )?;
    let preclaim_parked_assignment_ids = preclaim_decisions
        .iter()
        .filter(|decision| !decision.allows_path_claim())
        .map(|decision| decision.assignment_id.clone())
        .collect::<BTreeSet<_>>();
    // Runtime catalog acquisition is the first dispatch-capable environment preflight. A typed
    // failure is finalized here and deliberately short-circuits every assignment environment
    // preflight, which can begin only inside `external_runner` below.
    let runtime_model_catalog = match runtime_model_catalog {
        Ok(catalog) => catalog,
        Err(failure) => {
            return persist_supervisor_predispatch_failure(
                PredispatchFailureFinalization {
                    plan: &plan,
                    plan_metadata: &plan_metadata,
                    options: &options,
                    repo: &repo,
                    budget_ledger: &budget_ledger,
                    artifact_writer,
                    checkpoint_writer: &mut checkpoint_writer,
                    run_dir: &run_dir,
                    max_concurrent_children,
                    admission_policy_input,
                    has_multiple_independent_assignment_scopes:
                        has_multiple_independent_assignment_scopes(
                            &assignment_schedule,
                            &plan_metadata,
                        ),
                    runtime_model_catalog: None,
                    selection_decisions,
                    preclaim_parked_assignment_ids,
                },
                SupervisorPredispatchFailure::RuntimeModelCatalog(*failure),
            );
        }
    };
    if let Some(failure) = selection_preflight_failure {
        return persist_supervisor_predispatch_failure(
            PredispatchFailureFinalization {
                plan: &plan,
                plan_metadata: &plan_metadata,
                options: &options,
                repo: &repo,
                budget_ledger: &budget_ledger,
                artifact_writer,
                checkpoint_writer: &mut checkpoint_writer,
                run_dir: &run_dir,
                max_concurrent_children,
                admission_policy_input,
                has_multiple_independent_assignment_scopes:
                    has_multiple_independent_assignment_scopes(&assignment_schedule, &plan_metadata),
                runtime_model_catalog: Some(&runtime_model_catalog),
                selection_decisions,
                preclaim_parked_assignment_ids,
            },
            SupervisorPredispatchFailure::Selection(failure),
        );
    }
    let budget_config = &plan_metadata.run_budget;
    let mut sync_store_slot = None;
    let mut semantic_store_slot = None;
    let mut field_guide_store_slot = None;
    let mut field_guide_prompt_slot = None;
    let mut orchestration_journal = None;
    let mut autonomy_kpi_collector = AutonomyKpiCollector::default();
    let mut collected = CollectedAssignmentOutcomes {
        preclaim_parked_assignment_ids,
        ..CollectedAssignmentOutcomes::default()
    };
    collected
        .selection_decisions
        .append(&mut selection_decisions);
    if runtime == SupervisorRuntime::Fake {
        collected.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message:
                "explicit fake supervisor runtime is simulation-only and cannot publish acceptance"
                    .to_string(),
            paths: Vec::new(),
        });
    }
    let mut primary_run_baseline = None;
    let mut budget_prevented_dispatch = false;
    let mut budget_denied_assignment_indices = BTreeSet::new();
    let mut budget_degradations = Vec::new();
    let mut assignment_effort_bindings = Vec::new();
    let mut circuit_breaker_trip = None;
    let mut achieved_concurrency = AchievedConcurrency::default();
    let run_result = (|| -> Result<()> {
        initialize_scheduler_evidence(&mut SchedulerEvidenceInitialization {
            plan: &requested_plan,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            plan_metadata: &plan_metadata,
            options: &options,
            repo: &repo,
            execution_runtime,
            execution_target: plan_metadata.execution_target.as_ref(),
            artifact_writer: &mut artifact_writer,
            field_guide_store_slot: &mut field_guide_store_slot,
            field_guide_prompt_slot: &mut field_guide_prompt_slot,
            sync_store_slot: &mut sync_store_slot,
            semantic_store_slot: &mut semantic_store_slot,
            orchestration_journal: &mut orchestration_journal,
            primary_run_baseline: &mut primary_run_baseline,
        })?;
        let sync_store = sync_store_slot
            .as_ref()
            .context("supervisor sync store was not initialized")?;
        let semantic_store = semantic_store_slot
            .as_ref()
            .context("supervisor semantic store was not initialized")?;
        let field_guide = field_guide_prompt_slot
            .as_ref()
            .context("supervisor field-guide prompt was not initialized")?;

        let existing_ids = manager
            .list()?
            .into_iter()
            .map(|record| record.name)
            .collect::<BTreeSet<_>>();
        let release_per_assignment = release_assignment_resources_after_completion(
            &plan,
            &assignment_schedule,
            max_concurrent_children,
        );
        let prepared_semantic_assignments = if max_concurrent_children > 1 {
            prepare_semantic_warn_assignments(semantic_store, &plan, &assignment_schedule)?
        } else {
            plan.assignments
                .iter()
                .map(|_| PreparedSemanticAssignment::default())
                .collect()
        };
        let (scheduler_result, mut progress) = {
            let cancellation = ProcessCancellation::new();
            let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut artifact_writer,
                journal: &mut orchestration_journal,
                autonomy_kpis: &mut autonomy_kpi_collector,
                checkpoint: Some(&mut checkpoint_writer),
            });
            let semantic_block_gate = SemanticBlockGate::default();
            let serial_semantic_warn_intents = Mutex::new(Vec::<(usize, SemanticIntent)>::new());
            let mut progress = SchedulerProgress::new_with_selection_state(
                plan.assignments.len(),
                max_concurrent_children,
                automatic_selection_state,
                options.runtime,
            )?;
            progress
                .budget_degradation
                .policy
                .initial_selector_decisions = collected.selection_decisions.clone();
            progress.budget_degradation.policy.this_run_run_dir = Some(run_dir.clone());
            progress.install_preclaim_decisions(preclaim_decisions)?;
            progress.prepared_preclaim_evidence = Some(preclaim_evidence);
            let scheduler_context = AssignmentSchedulerContext {
                plan: &plan,
                requested_plan: &requested_plan,
                budget_config,
                consultant: &consultant,
                assignment_metadata: &assignment_metadata,
                evidence_only_reaudit: evidence_only_reaudit.as_ref(),
                options: &options,
                repo: &repo,
                run_dir: &run_dir,
                dirs: &dirs,
                execution_runtime,
                execution_target: plan_metadata.execution_target.as_ref(),
                worktree_creation,
                manager: &manager,
                existing_ids: &existing_ids,
                sync_store,
                semantic_store,
                prepared_semantic_assignments: &prepared_semantic_assignments,
                assignment_schedule: &assignment_schedule,
                field_guide,
                artifacts: &shared_artifacts,
                budget_ledger: &budget_ledger,
                runtime_model_catalog: &runtime_model_catalog,
                external_runner,
                release_per_assignment,
            };
            let scheduler_result = if max_concurrent_children == 1 {
                run_serial_assignment_schedule(
                    &scheduler_context,
                    &mut progress,
                    &cancellation,
                    &serial_semantic_warn_intents,
                )
            } else {
                run_concurrent_assignment_schedule(
                    &scheduler_context,
                    &mut progress,
                    &cancellation,
                    &semantic_block_gate,
                )
            };
            (scheduler_result, progress)
        };
        achieved_concurrency = progress.concurrency.finish();
        budget_prevented_dispatch |= progress.budget_prevented_dispatch;
        if let Ok(report) = budget_ledger.report() {
            if !report.new_dispatch_allowed {
                for index in &progress.budget_denied_assignment_indices {
                    progress
                        .budget_degradation
                        .record_halt(&plan.assignments[*index].id, &report);
                }
            }
        }
        budget_denied_assignment_indices.extend(progress.budget_denied_assignment_indices);
        budget_degradations.append(&mut progress.budget_degradation.records);
        assignment_effort_bindings
            .append(&mut progress.budget_degradation.assignment_effort_bindings);
        circuit_breaker_trip = progress.circuit_breaker_trip;

        let fatal_errors = collect_indexed_assignment_outcomes(
            progress.indexed_outcomes,
            release_per_assignment,
            &mut collected,
        );
        scheduler_result?;
        if let Some(error) = fatal_errors.into_iter().next() {
            bail!("{error}");
        }
        Ok(())
    })();

    if let Err(error) = &run_result {
        collected.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!("{error:#}"),
            paths: Vec::new(),
        });
    }
    let breaker_tripped = circuit_breaker_trip.is_some();
    let mut supervisor_breaker_trip = circuit_breaker_trip.map(|trip| SupervisorBreakerTrip {
        reason: trip.reason,
        window: trip.window,
        autonomy_kpis: AutonomyKpiReport::default(),
        recovery_guidance: BREAKER_RECOVERY_GUIDANCE.to_string(),
    });
    if let Some(trip) = &supervisor_breaker_trip {
        collected.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: format!(
                "swarm-health circuit breaker opened and drained active assignments: {:?}",
                trip.reason
            ),
            paths: Vec::new(),
        });
    }

    let mut scheduler_resources = CollectedSchedulerResources::take_from(&mut collected);
    let planned_scheduler_resources = planned_collected_scheduler_resources(
        sync_store_slot.as_ref(),
        semantic_store_slot.as_ref(),
        &scheduler_resources,
    )?;
    let ReleasedSchedulerResources {
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
    } = planned_scheduler_resources.clone();
    let final_primary_integrity_failed = match primary_run_baseline.as_ref() {
        Some(baseline) => match supervisor_primary_worktree_snapshot(&repo, execution_runtime) {
            Ok(final_snapshot) => {
                if let Some(error) = final_snapshot.inspection_problem() {
                    collected.findings.push(Finding {
                        severity: FindingSeverity::Error,
                        message: format!(
                            "primary worktree final integrity snapshot was incomplete: {error}"
                        ),
                        paths: Vec::new(),
                    });
                    true
                } else {
                    let changes = primary_integrity_changes(baseline, &final_snapshot);
                    let changes = match plan_metadata.execution_target.as_ref() {
                        Some(target) => {
                            primary_integrity_changes_outside_scope(&changes, target.claim_paths())
                        }
                        None => changes,
                    };
                    let integrity_failed = !changes.is_empty();
                    if integrity_failed {
                        collected.findings.push(Finding {
                            severity: FindingSeverity::Error,
                            message: format!(
                                "primary worktree integrity differed from the supervise-run baseline during final acceptance: {}",
                                changes.details.join("; ")
                            ),
                            paths: changes.paths,
                        });
                    }
                    integrity_failed
                }
            }
            Err(error) => {
                collected.findings.push(Finding {
                    severity: FindingSeverity::Error,
                    message: format!("primary worktree final integrity check failed: {error}"),
                    paths: Vec::new(),
                });
                true
            }
        },
        None => true,
    };
    let nested_workers_present = plan
        .assignments
        .iter()
        .any(|assignment| !assignment.worker_assignments.is_empty());
    if nested_workers_present {
        collected.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "worker usage is not process-observable because nested-worker delegation is requested through the child-orchestrator contract without a separately MACO-observed worker process or runtime identity; child-orchestrator and auditor process usage remains reportable, while runtime-side role-tagged usage reporting is required before worker usage or cost can be reported"
                .to_string(),
            paths: Vec::new(),
        });
    }
    let (run_budget_report, budget_accounting_failed) = match budget_ledger.report() {
        Ok(report) => (Some(report), false),
        Err(error) => {
            collected.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!("run budget accounting could not be finalized: {error}"),
                paths: Vec::new(),
            });
            (None, true)
        }
    };
    collected.usage_incomplete |= budget_accounting_failed
        || run_budget_report
            .as_ref()
            .is_some_and(|report| !report.usage_complete);
    if collected.usage_incomplete {
        collected.findings.push(Finding {
            severity: FindingSeverity::Warning,
            message: "process usage is incomplete because at least one runtime's native usage evidence was missing, truncated, or malformed, or conservatively reconciled because usage was observed but unreliable after its run failed, timed out, or lacked verified completion or containment"
                .to_string(),
            paths: Vec::new(),
        });
    }
    if budget_prevented_dispatch {
        for index in &budget_denied_assignment_indices {
            let assignment = plan
                .assignments
                .get(*index)
                .context("budget denial referenced an assignment outside the plan")?;
            collected.gate_denials.push(
                GateDenial::new(
                    gate_correlation_id(&assignment.id, 1),
                    GateDenialReason::BudgetAdmission {
                        denial: BudgetAdmissionDenial::NewDispatchStopped,
                    },
                    VerifiedGateContext::new(
                        &assignment.id,
                        GateCheckSource::BudgetAdmission,
                        &assignment.assigned_paths,
                    )?,
                )
                .context("failed to construct scheduler budget-admission gate denial")?,
            );
        }
        collected.findings.push(Finding {
            severity: FindingSeverity::Error,
            message: "run budget stopped one or more new dispatches and drained already-started work; inspect typed gate_denials and the structured run_budget report"
                .to_string(),
            paths: Vec::new(),
        });
    }
    let field_guide_mutation_failed = match append_accepted_field_guide_drafts(
        &plan,
        &collected.orchestrator_reports,
        &options.run_id,
        field_guide_store_slot.as_ref(),
        &mut orchestration_journal,
        &mut artifact_writer,
    ) {
        Ok(_) => false,
        Err(error) => {
            collected.findings.push(Finding {
                severity: FindingSeverity::Error,
                message: format!(
                    "accepted field-guide suggestions were not fully persisted: {error:#}; do not retry blindly when planned mutation evidence exists"
                ),
                paths: Vec::new(),
            });
            true
        }
    };
    let autonomy_kpis =
        autonomy_kpi_collector.report(orchestration_journal_observable(&orchestration_journal));
    if let Some(trip) = &mut supervisor_breaker_trip {
        trip.autonomy_kpis = autonomy_kpis.clone();
    }
    let environment_failures =
        aggregate_environment_failures(&collected.command_records, &collected.orchestrator_reports);
    let failed = run_result.is_err()
        || !release_errors.is_empty()
        || !semantic_release_errors.is_empty()
        || collected.assignment_execution_failed
        || budget_prevented_dispatch
        || budget_accounting_failed
        || collected.external_containment_failed
        || final_primary_integrity_failed
        || breaker_tripped
        || field_guide_mutation_failed
        || !environment_failures.is_empty()
        || collected.orchestrator_reports.iter().any(report_failed);
    let success = !failed;
    let publishable = terminal_publishable(
        success,
        runtime,
        execution_runtime,
        &plan,
        &collected.orchestrator_reports,
        &collected.candidate_inspections,
    );
    let (report_plan_file, report_run_dir) =
        supervisor_report_paths(&repo, &options.plan_file, &run_dir, &options.run_id);
    let usage_complete = !collected.usage_incomplete;
    let RoleUsageAggregation {
        reports: mut role_usage,
        lens_reports: review_lens_usage,
        total_usage,
        total_cost_usd: observed_total_cost_usd,
        lens_total_usage: review_lens_total_usage,
        lens_total_cost_usd: observed_review_lens_total_cost_usd,
        // The validated plan remains the immutable authority for lens/backend identity and
        // pricing. Each usage sample carries its actual active-attempt model; aggregation must
        // retain that model rather than re-impose the original configured selection.
    } = role_usage_report(&plan, std::mem::take(&mut collected.usage_samples))?;
    let total_cost_usd =
        finalize_supervisor_cost(usage_complete, &mut role_usage, observed_total_cost_usd);
    let review_lens_total_cost_usd = usage_complete
        .then_some(observed_review_lens_total_cost_usd)
        .flatten();
    let bloated_file_flags = accepted_bloated_file_flags(&collected.orchestrator_reports);
    let decomposition_candidates =
        accepted_decomposition_candidates(&collected.orchestrator_reports);
    let (assignment_traceability, runtime_coverage_gaps) = supervisor_assignment_traceability(
        &plan,
        &plan_metadata,
        &collected.orchestrator_reports,
        &collected.candidate_inspections,
    );
    let mut coverage_gaps = plan_metadata.coverage_gaps.clone();
    coverage_gaps.extend(runtime_coverage_gaps);
    let sandbox_denials = aggregate_sandbox_denials(&collected.command_records);
    let external_containment_failed = collected.external_containment_failed;
    let mut final_report = build_supervisor_final_report(SupervisorFinalReportConstruction {
        plan: &plan,
        runtime_model_catalog: Some(&runtime_model_catalog),
        max_concurrent_children,
        admission_policy_input,
        achieved_concurrency,
        has_multiple_independent_assignment_scopes: has_multiple_independent_assignment_scopes(
            &assignment_schedule,
            &plan_metadata,
        ),
        run_id: options.run_id,
        report_plan_file,
        report_run_dir,
        runtime,
        publishable,
        success,
        run_budget_report,
        budget_degradations,
        assignment_effort_bindings,
        evidence_only_reaudit: plan_metadata.evidence_only_reaudit.clone(),
        role_usage,
        review_lens_usage,
        review_lens_total_usage,
        review_lens_total_cost_usd,
        total_usage,
        total_cost_usd,
        usage_complete,
        environment_failures,
        sandbox_denials,
        collected,
        this_run_attempt_rows: load_this_run_attempt_cost_rows(artifact_writer.run_dir()),
        bloated_file_flags,
        decomposition_candidates,
        assignment_traceability,
        coverage_gaps,
        supervisor_breaker_trip,
        autonomy_kpis,
        released_claims,
        release_errors,
        released_semantic_intents,
        semantic_release_errors,
        external_containment_failed,
        final_primary_integrity_failed,
        budget_prevented_dispatch,
        budget_accounting_failed,
        breaker_tripped,
        field_guide_mutation_failed,
    });
    if let Some(profile) = final_report.role_economics_profile.as_mut() {
        profile.resolved_objective_profile = plan_metadata.resolved_objective_profile.clone();
    }
    apply_execution_target_reporting(&mut final_report, plan_metadata.execution_target.as_ref());
    let resume_binding = artifact_writer.resume_binding();
    #[cfg(test)]
    let resume_binding = if take_force_degraded_checkpoint_finalization() {
        Err(anyhow!(
            "artifact run is not at a resumable manifest boundary"
        ))
    } else {
        resume_binding
    };
    let checkpoint_finalization = match resume_binding {
        Ok(binding) => {
            // Bind the same snapshot already sealed into the final report.
            // A second budget_ledger.report() can cross a 1-second boundary and
            // diverge on elapsed_seconds / remaining.max_duration_seconds,
            // making resume refuse a still-valid interrupted finalization.
            checkpoint_writer.scheduler_closed(
                binding,
                final_report.run_budget.clone().context(
                    "run budget accounting could not be finalized for the scheduler-closed checkpoint",
                )?,
            )?;
            true
        }
        Err(error)
            if error
                .to_string()
                .contains("not at a resumable manifest boundary") =>
        {
            // Keep the planned terminal release in the report. Persist still
            // runs release_after_terminal_record even without a checkpoint.
            false
        }
        Err(error) => {
            return Err(error).context("failed to write normalized supervisor final report");
        }
    };
    persist_supervisor_final_report(
        final_report,
        &mut orchestration_journal,
        artifact_writer,
        checkpoint_finalization.then_some(&mut checkpoint_writer),
        (!external_containment_failed)
            .then_some(crate::artifacts::ArtifactScratchQuiescence::Verified),
        || {
            let released = release_collected_scheduler_resources(
                sync_store_slot.as_ref(),
                semantic_store_slot.as_ref(),
                &mut scheduler_resources,
            );
            if released != planned_scheduler_resources {
                bail!(
                    "terminal scheduler cleanup differed from its durable final-report plan: planned={planned_scheduler_resources:?}, observed={released:?}"
                );
            }
            Ok(())
        },
    )
}

#[cfg(test)]
mod selection_policy_tests {
    use super::super::tests::single_parent_acceptance_review_lenses;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SELECTOR_TEST_TARGET: &str = "tests/selector.rs";

    fn accepted_review_report(assignment_id: &str) -> OrchestratorReviewReport {
        OrchestratorReviewReport {
            id: assignment_id.to_string(),
            role: AgentRole::Worker,
            assigned_paths: Vec::new(),
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            claim_token: None,
            semantic_intent_token: None,
            commands_run: Vec::new(),
            environment_failures: Vec::new(),
            files_changed: Vec::new(),
            validation_results: Vec::new(),
            findings: Vec::new(),
            field_guide_entries: Vec::new(),
            worker_reports: Vec::new(),
            audit_reports: Vec::new(),
            review_lens_aggregate: None,
            decomposition_completions: Vec::new(),
            licensed_breakage_review: None,
            generated_follow_up_tasks: Vec::new(),
            gate_denials: Vec::new(),
            gate_correction_outcomes: Vec::new(),
            accepted: true,
            rejected: false,
            status: ReviewStatus::Succeeded,
            remaining_risk: String::new(),
            next_safe_action: String::new(),
        }
    }

    fn publication_proof_fixture() -> Result<(
        SupervisorPlan,
        Vec<OrchestratorReviewReport>,
        BTreeMap<String, SupervisorCandidateInspection>,
    )> {
        let mut plan = test_plan();
        plan.assignments = vec![
            terminal_worker_assignment("worker-a"),
            terminal_worker_assignment("worker-b"),
        ];
        plan.assignments[1].assigned_paths = vec![PathBuf::from("tests/selector-two.rs")];
        let mut reports = Vec::new();
        let mut inspections = BTreeMap::new();
        for assignment in &plan.assignments {
            let mut report = accepted_review_report(&assignment.id);
            report.assigned_paths = assignment.assigned_paths.clone();
            report.files_changed = assignment.assigned_paths.clone();
            let required = supervisor_review_coverage_requirement(assignment, &report);
            let coverage = ReviewLensCoverage {
                worker_ids: required.worker_ids.clone(),
                paths: required.paths.clone(),
            };
            let child_transcript = format!(
                "Synthetic publication fixture transcript for {}.",
                assignment.id
            );
            let diff = format!("Synthetic candidate paths: {:?}", report.files_changed);
            let output_report = serde_json::to_string(&report)?;
            let verdicts = plan
                .review_lenses
                .iter()
                .map(|lens| {
                    let request = crate::review::build_review_lens_request(
                        lens,
                        crate::review::ReviewLensRequestSources {
                            child_transcript: &child_transcript,
                            diff: &diff,
                            output_report: &output_report,
                        },
                    )?;
                    let evidence_content = serde_json::to_string(&serde_json::json!({
                        "fixture": "publication-proof",
                        "request": &request,
                        "coverage": &coverage,
                        "verdict": "accept",
                    }))?;
                    ReviewLensVerdict::for_lens(
                        lens,
                        request.request_binding,
                        ReviewLensVerdictStatus::Accept,
                        coverage.clone(),
                        vec![(
                            crate::review::ReviewLensDescriptor::from(lens).expected_evidence_kind,
                            evidence_content,
                        )],
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            report.review_lens_aggregate = Some(crate::review::aggregate_review_lenses(
                &plan.review_lenses,
                plan.review_aggregation_policy,
                required,
                verdicts,
            )?);
            inspections.insert(
                assignment.id.clone(),
                SupervisorCandidateInspection {
                    binding: CandidateValidationBinding {
                        version: VALIDATION_BINDING_VERSION,
                        agent_id: assignment.id.clone(),
                        primary_head: Some("1".repeat(40)),
                        agent_head: Some("2".repeat(40)),
                        merge_base: Some("1".repeat(40)),
                        diff_oid: "3".repeat(40),
                    },
                    changed_paths: report.files_changed.clone(),
                },
            );
            reports.push(report);
        }
        Ok((plan, reports, inspections))
    }

    #[test]
    fn publication_proof_fixture_uses_content_bound_review_requests() -> Result<()> {
        let (plan, reports, _) = publication_proof_fixture()?;
        for report in &reports {
            let aggregate = report
                .review_lens_aggregate
                .as_ref()
                .context("fixture review aggregate")?;
            let mut source_report = report.clone();
            source_report.review_lens_aggregate = None;
            let child_transcript = format!(
                "Synthetic publication fixture transcript for {}.",
                report.id
            );
            let diff = format!("Synthetic candidate paths: {:?}", report.files_changed);
            let output_report = serde_json::to_string(&source_report)?;
            let changed_transcript = format!("{child_transcript}\nChanged fixture transcript.");
            let changed_diff = format!("{diff}\nChanged fixture diff.");
            let changed_output = format!("{output_report}\nChanged fixture output.");
            assert_eq!(aggregate.lens_verdicts.len(), plan.review_lenses.len());
            for (lens, verdict) in plan.review_lenses.iter().zip(&aggregate.lens_verdicts) {
                let request = crate::review::build_review_lens_request(
                    lens,
                    crate::review::ReviewLensRequestSources {
                        child_transcript: &child_transcript,
                        diff: &diff,
                        output_report: &output_report,
                    },
                )?;
                assert_eq!(
                    verdict.request_binding.as_deref(),
                    Some(request.request_binding.as_str())
                );
                assert_eq!(request.request_binding.len(), 64);
                assert!(request
                    .request_binding
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
                let changed = crate::review::build_review_lens_request(
                    lens,
                    crate::review::ReviewLensRequestSources {
                        child_transcript: &changed_transcript,
                        diff: &changed_diff,
                        output_report: &changed_output,
                    },
                )?;
                assert_ne!(request.request_binding, changed.request_binding);
            }
        }
        Ok(())
    }

    #[test]
    fn terminal_publication_is_provider_neutral_and_keeps_unknown_economics_separate() -> Result<()>
    {
        let (plan, reports, inspections) = publication_proof_fixture()?;
        assert!(plan.model_pricing.is_empty());
        for runtime in [
            SupervisorRuntime::Codex,
            SupervisorRuntime::Grok,
            SupervisorRuntime::Cursor,
            SupervisorRuntime::ClaudeCode,
            SupervisorRuntime::GeminiCli,
        ] {
            assert!(terminal_publishable(
                true,
                runtime,
                SupervisorExecutionRuntime::Verified,
                &plan,
                &reports,
                &inspections,
            ));
            assert!(!terminal_publishable(
                false,
                runtime,
                SupervisorExecutionRuntime::Verified,
                &plan,
                &reports,
                &inspections,
            ));
            assert!(!terminal_publishable(
                true,
                runtime,
                SupervisorExecutionRuntime::NonpublishableSimulation,
                &plan,
                &reports,
                &inspections,
            ));
        }
        assert!(!terminal_publishable(
            true,
            SupervisorRuntime::Fake,
            SupervisorExecutionRuntime::Verified,
            &plan,
            &reports,
            &inspections,
        ));
        Ok(())
    }

    #[test]
    fn terminal_publication_requires_exact_accepted_assignment_candidates() -> Result<()> {
        for defect in [
            "missing-report",
            "duplicate-report",
            "foreign-report",
            "missing-inspection",
            "foreign-inspection",
            "foreign-candidate",
            "invalid-candidate",
            "changed-paths",
            "role",
            "scope",
            "failed-report",
            "empty-plan",
        ] {
            let (mut plan, mut reports, mut inspections) = publication_proof_fixture()?;
            match defect {
                "missing-report" => {
                    reports.pop();
                }
                "duplicate-report" => reports[1] = reports[0].clone(),
                "foreign-report" => reports[0].id = "foreign".to_string(),
                "missing-inspection" => {
                    inspections.remove("worker-a");
                }
                "foreign-inspection" => {
                    let inspection = inspections.remove("worker-a").unwrap();
                    inspections.insert("foreign".to_string(), inspection);
                }
                "foreign-candidate" => {
                    inspections.get_mut("worker-a").unwrap().binding.agent_id =
                        "foreign".to_string();
                }
                "invalid-candidate" => {
                    inspections.get_mut("worker-a").unwrap().binding.diff_oid = String::new();
                }
                "changed-paths" => inspections
                    .get_mut("worker-a")
                    .unwrap()
                    .changed_paths
                    .clear(),
                "role" => reports[0].role = AgentRole::ChildOrchestrator,
                "scope" => reports[0].assigned_paths.clear(),
                "failed-report" => reports[0].accepted = false,
                "empty-plan" => {
                    plan.assignments.clear();
                    reports.clear();
                    inspections.clear();
                }
                _ => unreachable!(),
            }
            assert!(
                !terminal_publishable(
                    true,
                    SupervisorRuntime::Grok,
                    SupervisorExecutionRuntime::Verified,
                    &plan,
                    &reports,
                    &inspections,
                ),
                "publication accepted {defect}"
            );
        }
        Ok(())
    }

    #[test]
    fn terminal_publication_requires_parent_review_authority_and_configured_lens_coverage(
    ) -> Result<()> {
        for defect in [
            "missing-aggregate",
            "deserialized-authority",
            "policy",
            "missing-lens",
            "foreign-lens",
            "duplicate-lens",
            "scope",
            "required-coverage",
            "worker-coverage",
            "path-coverage",
            "unreported-lens",
            "validation-error",
            "rejected-review",
            "unconfigured-reviews",
            "duplicate-configured-lens",
        ] {
            let (mut plan, mut reports, inspections) = publication_proof_fixture()?;
            if defect == "missing-aggregate" {
                reports[0].review_lens_aggregate = None;
            } else if defect == "deserialized-authority" {
                let bytes = serde_json::to_vec(reports[0].review_lens_aggregate.as_ref().unwrap())?;
                reports[0].review_lens_aggregate = Some(serde_json::from_slice(&bytes)?);
            } else {
                let aggregate = reports[0].review_lens_aggregate.as_mut().unwrap();
                match defect {
                    "policy" => {
                        aggregate.policy =
                            ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts: 1 };
                    }
                    "missing-lens" => {
                        aggregate.lens_verdicts.pop();
                    }
                    "foreign-lens" => aggregate.lens_verdicts[0].lens.id = "foreign".to_string(),
                    "duplicate-lens" => {
                        aggregate.lens_verdicts[1] = aggregate.lens_verdicts[0].clone();
                    }
                    "scope" => {
                        aggregate.lens_verdicts[0].lens.information_scope =
                            ReviewInformationScope::OutputReportOnly;
                    }
                    "required-coverage" => aggregate.required_coverage.worker_ids.clear(),
                    "worker-coverage" => aggregate.lens_verdicts[0].coverage.worker_ids.clear(),
                    "path-coverage" => aggregate.lens_verdicts[0].coverage.paths.clear(),
                    "unreported-lens" => aggregate.lens_verdicts[0].reported = false,
                    "validation-error" => {
                        aggregate.lens_verdicts[0]
                            .validation_errors
                            .push("invalid".to_string());
                    }
                    "rejected-review" => aggregate.decision = ReviewAggregationDecision::Reject,
                    "unconfigured-reviews" => plan.review_lenses.clear(),
                    "duplicate-configured-lens" => {
                        plan.review_lenses[1] = plan.review_lenses[0].clone();
                    }
                    _ => unreachable!(),
                }
            }
            assert!(
                !terminal_publishable(
                    true,
                    SupervisorRuntime::Grok,
                    SupervisorExecutionRuntime::Verified,
                    &plan,
                    &reports,
                    &inspections,
                ),
                "publication accepted {defect}"
            );
        }
        Ok(())
    }

    #[test]
    fn nonpublishable_real_success_reports_missing_proof_without_codex_only_guidance() {
        let (simulation_risk, _) = nonpublishable_success_guidance(SupervisorRuntime::Fake);
        assert!(simulation_risk.contains("fake supervisor simulation"));
        for runtime in [SupervisorRuntime::Codex, SupervisorRuntime::Grok] {
            let (risk, action) = nonpublishable_success_guidance(runtime);
            assert!(risk.contains("proof is missing"));
            assert!(!risk.contains("fake"));
            assert!(!action.contains("Codex"));
        }
    }

    fn complete_attempt_costs() -> AttemptAttributableCosts {
        AttemptAttributableCosts {
            execution_cost_microunits: Some(10),
            review_cost_microunits: Some(2),
            rework_cost_microunits: Some(0),
            rereview_cost_microunits: Some(0),
            environment_cost_microunits: Some(0),
        }
    }

    fn test_plan() -> SupervisorPlan {
        SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "selector scheduler policy fixture".to_string(),
            task_file: None,
            max_depth: MIN_SUPERVISOR_DEPTH,
            max_child_assignments: 1,
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: DEFAULT_CHILD_TIMEOUT_SECONDS,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: default_supervisor_review_lenses(),
            review_lens_correlation: Default::default(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: Vec::new(),
        }
    }

    fn role_selection(model: &str, effort: &str) -> RoleModelSelection {
        RoleModelSelection {
            model: Some(model.to_string()),
            reasoning_effort: Some(effort.to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        }
    }

    fn default_resolved_objective_profile() -> Result<ResolvedObjectiveProfile> {
        Ok(ResolvedObjectiveProfile {
            profile: crate::objective_profile::default_objective_profile().binding()?,
            source: crate::objective_profile::ObjectiveProfileSource::BuiltIn,
        })
    }

    fn assessed_selection_fixture() -> Result<(
        SupervisorPlan,
        TaskRoutingAssessment,
        crate::selection::routing_policy::FrozenRoutingPolicy,
    )> {
        use crate::selection::routing_policy::{FrozenRoutingPolicy, LoadedRoutingPolicy};

        let policy: LoadedRoutingPolicy =
            serde_json::from_str(include_str!("../selection/data/routing-policy.json"))?;
        policy.validate()?;
        let frozen = FrozenRoutingPolicy {
            sha256: crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&policy)?),
            policy,
            source: "public-scheduler-selection-fixture".to_string(),
        };
        let mut plan = test_plan();
        plan.task = format!("Create {SELECTOR_TEST_TARGET} with one line: ready");
        plan.assignments = vec![serde_json::from_value(serde_json::json!({
            "id":"selector-parent", "phase":"execution", "role":"child_orchestrator",
            "task": &plan.task, "assigned_paths":["tests"], "worker_assignments":[
                {"id":"selector-worker", "role":"worker", "task": &plan.task,
                    "assigned_paths":[SELECTOR_TEST_TARGET]}
            ]
        }))?];
        let proposal: crate::planning::TaskDecompositionProposal =
            serde_json::from_value(serde_json::json!({
                "fragments":[{"id":"selector", "text": &plan.task}],
                "assignments":[{"id":"selector-worker", "task": &plan.task,
                    "fragment_ids":["selector"], "assigned_paths":[SELECTOR_TEST_TARGET],
                    "semantic_symbols":[], "semantic_modules":[]}],
                "diagnostics":{"degraded":false, "notes":[]},
                "disjointness":{"disjoint":true, "conflicts":[]}
            }))?;
        let assessment =
            super::super::task_routing::assess_task_routing(&plan.task, &proposal, &frozen)?;
        Ok((plan, assessment, frozen))
    }

    fn automatic_selection_fixture() -> Result<(
        RuntimeModelCatalog,
        SupervisorAutomaticSelectionState,
        Vec<SupervisorSelectionEvent>,
        SupervisorPlan,
        crate::selection::routing_policy::FrozenRoutingPolicy,
    )> {
        let priors = crate::selection::built_in_prior_dataset()?;
        let catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(
            priors
                .models
                .iter()
                .filter(|prior| prior.runtime == "codex")
                .map(|prior| prior.model.clone()),
        )?);
        let admission = SupervisorAdmissionPolicyInput {
            entrypoint_bound: 1,
            plan: SupervisorAdmissionConfig::default(),
            cli: SupervisorAdmissionConfig::default(),
            effective: SupervisorAdmissionConfig::default(),
            provider_inflight_bound: 1,
            provider_inflight_source: AdmissionInputSource::ConservativeDefault,
            quota_inflight_bound: None,
            quota_inflight_source: None,
            quota_config_path: None,
            host: SupervisorHostResourcePolicyInput {
                memory_available_mib: None,
                memory_available_source: AdmissionInputSource::ConservativeDefault,
                memory_per_child_mib: DEFAULT_HOST_MEMORY_PER_CHILD_MIB,
                memory_bound: None,
                fd_available: None,
                fd_available_source: AdmissionInputSource::ConservativeDefault,
                fds_per_child: DEFAULT_HOST_FDS_PER_CHILD,
                fd_bound: None,
                disk_available_mib: None,
                disk_available_source: AdmissionInputSource::ConservativeDefault,
                disk_per_child_mib: DEFAULT_HOST_DISK_PER_CHILD_MIB,
                disk_bound: None,
                fallback_children: DEFAULT_HOST_FALLBACK_CHILDREN,
                resolved_bound: 1,
            },
            resolved_bound: 1,
        };
        let (mut plan, assessment, frozen) = assessed_selection_fixture()?;
        let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
        let resolved_objective_profile = default_resolved_objective_profile()?;
        let resolution =
            super::super::selection_bridge::initialize_supervisor_selection_with_assessment(
                &mut plan,
                SupervisorRuntime::Codex,
                &catalog,
                &admission,
                &AdvertisedCatalogSet::empty(),
                Some(&resolved_objective_profile),
                SupervisorQuotaSelectionInput::default(),
                None,
                &[],
                Some(&assessment),
            )?;
        Ok((
            catalog,
            resolution
                .automatic_state
                .context("automatic selector same-run state")?,
            resolution.decisions,
            plan,
            frozen,
        ))
    }

    fn automatic_provenance() -> Result<crate::selection::SelectionProvenance> {
        automatic_selection_fixture()?
            .2
            .into_iter()
            .next()
            .map(|event| event.provenance)
            .context("initial selector provenance")
    }

    fn terminal_worker_assignment(id: &str) -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: id.to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::Worker,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from(SELECTOR_TEST_TARGET)],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
            decision_refs: Vec::new(),
        }
    }

    fn selected_worker_event(
        mut provenance: crate::selection::SelectionProvenance,
        assignment_id: &str,
        runtime: &str,
        model: &str,
        effort: crate::selection::ReasoningEffort,
    ) -> SupervisorSelectionEvent {
        let choice = provenance
            .choice
            .as_mut()
            .expect("automatic selection provenance has a selected choice");
        choice.candidate.runtime = runtime.to_string();
        choice.candidate.model = model.to_string();
        choice.candidate.effort = effort;
        SupervisorSelectionEvent {
            assignment_id: Some(assignment_id.to_string()),
            attempt: 1,
            role: AgentRole::Worker,
            primary_cause: SupervisorSelectionEventCause::Initial,
            provenance,
        }
    }

    #[test]
    fn worker_role_binding_uses_unanimous_cross_runtime_assignment_evidence() -> Result<()> {
        let (catalog, _, initial_events, mut plan, _) = automatic_selection_fixture()?;
        plan.assignments = vec![
            terminal_worker_assignment("worker-a"),
            terminal_worker_assignment("worker-b"),
        ];
        plan.role_models
            .insert(AgentRole::Worker, role_selection("grok-4.6", "xhigh"));

        let legacy = resolved_role_execution_bindings(
            &plan,
            SupervisorRuntime::Codex,
            Some(&catalog),
            &[],
            &[],
        );
        let legacy_worker = legacy
            .get(&AgentRole::Worker)
            .context("legacy Worker role binding")?;
        assert_eq!(
            legacy_worker.observation,
            RoleBindingObservation::ResolutionFailed
        );
        assert!(legacy_worker
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("grok-4.6")));

        let provenance = initial_events
            .into_iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("initial Worker selection provenance")?
            .provenance;
        let decisions = vec![
            selected_worker_event(
                provenance.clone(),
                "worker-a",
                "grok",
                "grok-4.6",
                crate::selection::ReasoningEffort::Xhigh,
            ),
            selected_worker_event(
                provenance,
                "worker-b",
                "grok",
                "grok-4.6",
                crate::selection::ReasoningEffort::Xhigh,
            ),
        ];
        let ledger = build_assignment_selection_ledger(&plan, &decisions, SupervisorRuntime::Codex);
        let worker_rows = ledger
            .iter()
            .filter(|entry| entry.role == AgentRole::Worker)
            .collect::<Vec<_>>();
        assert_eq!(worker_rows.len(), 2);
        assert!(worker_rows.iter().all(|entry| {
            entry.selected_runtime.as_deref() == Some("grok")
                && entry.selected_model.as_deref() == Some("grok-4.6")
                && entry.selected_reasoning_effort.as_deref() == Some("xhigh")
                && entry.catalog_source == AssignmentCatalogSource::RuntimeAdvertised
        }));

        let bindings = resolved_role_execution_bindings(
            &plan,
            SupervisorRuntime::Codex,
            Some(&catalog),
            &ledger,
            &decisions,
        );
        let worker = bindings
            .get(&AgentRole::Worker)
            .context("assignment-specific Worker role binding")?;
        assert_eq!(
            worker.observation,
            RoleBindingObservation::AssignmentSpecific
        );
        assert_eq!(worker.resolved_model.as_deref(), Some("grok-4.6"));
        assert_eq!(worker.resolved_reasoning_effort.as_deref(), Some("xhigh"));
        assert_eq!(
            worker.resolution_observation,
            ModelResolutionObservation::NotResolved
        );
        assert!(worker.unavailable_reason.is_none());
        Ok(())
    }

    #[test]
    fn worker_role_binding_keeps_heterogeneous_assignments_explicit() -> Result<()> {
        let (catalog, _, initial_events, mut plan, _) = automatic_selection_fixture()?;
        plan.assignments = vec![
            terminal_worker_assignment("worker-a"),
            terminal_worker_assignment("worker-b"),
        ];
        let provenance = initial_events
            .into_iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("initial Worker selection provenance")?
            .provenance;
        let decisions = vec![
            selected_worker_event(
                provenance.clone(),
                "worker-a",
                "grok",
                "grok-4.6",
                crate::selection::ReasoningEffort::Xhigh,
            ),
            selected_worker_event(
                provenance,
                "worker-b",
                "codex",
                "gpt-6.1-sol",
                crate::selection::ReasoningEffort::High,
            ),
        ];
        let ledger = build_assignment_selection_ledger(&plan, &decisions, SupervisorRuntime::Codex);

        let bindings = resolved_role_execution_bindings(
            &plan,
            SupervisorRuntime::Codex,
            Some(&catalog),
            &ledger,
            &decisions,
        );
        let worker = bindings
            .get(&AgentRole::Worker)
            .context("heterogeneous Worker role binding")?;
        assert_eq!(
            worker.observation,
            RoleBindingObservation::AssignmentSpecific
        );
        assert!(worker.resolved_model.is_none());
        assert!(worker.resolved_reasoning_effort.is_none());
        let reason = worker
            .unavailable_reason
            .as_deref()
            .context("heterogeneous Worker explanation")?;
        assert!(reason.contains("2 distinct runtime/model/reasoning-effort bindings"));
        assert!(reason.contains("assignment_selection_ledger"));
        assert!(reason.contains("selected_runtime"));
        assert!(reason.contains("selected_model"));
        assert!(reason.contains("selected_reasoning_effort"));
        Ok(())
    }

    fn initialized_repository() -> (tempfile::TempDir, PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary selector repository");
        let repo_path = temporary.path().join("repo");
        let repository = git2::Repository::init(&repo_path).expect("initialize repository");
        fs::write(repo_path.join("README.md"), "baseline\n").expect("write baseline");
        fs::create_dir(repo_path.join("tests")).expect("create selector test directory");
        fs::write(
            repo_path.join(SELECTOR_TEST_TARGET),
            "#[test]\nfn selector_fixture() {}\n",
        )
        .expect("write selector test target");
        let mut index = repository.index().expect("repository index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage baseline");
        index
            .add_path(Path::new(SELECTOR_TEST_TARGET))
            .expect("stage selector test target");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repository.find_tree(tree_id).expect("find tree");
        let signature =
            git2::Signature::now("maco test", "maco-test@example.invalid").expect("test signature");
        repository
            .commit(Some("HEAD"), &signature, &signature, "baseline", &tree, &[])
            .expect("commit baseline");
        drop(tree);
        drop(repository);
        (temporary, repo_path)
    }

    fn predispatch_options(repo: &Path, root: &Path, run_id: &str) -> SupervisorRunOptions {
        SupervisorRunOptions {
            repo: repo.to_path_buf(),
            plan_file: root.join(format!("{run_id}.json")),
            run_id: RunId::new(run_id).expect("valid run id"),
            parent_node: None,
            codex_bin: PathBuf::from("unused-selector-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: true,
            allow_live_run_collision: false,
            admission_overrides: SupervisorAdmissionConfig::default(),
            budget_overrides: RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: None,
        }
    }

    #[test]
    fn preclaim_runtime_is_derived_separately_from_effect_containment() -> Result<()> {
        skip_without_containment!(ok);
        let (_temporary, repo) = initialized_repository();
        let manager = WorktreeManager::new(&repo);
        let cleanliness = manager.acquire_repository_cleanliness()?;

        assert_eq!(
            preclaim_assessment_runtime(
                SupervisorRuntime::Fake,
                SupervisorExecutionRuntime::Verified,
                SupervisorWorktreeCreation::ExistingOnly,
            ),
            SupervisorExecutionRuntime::NonpublishableSimulation
        );
        assert_eq!(
            preclaim_assessment_runtime(
                SupervisorRuntime::Codex,
                SupervisorExecutionRuntime::NonpublishableSimulation,
                SupervisorWorktreeCreation::ExistingOnly,
            ),
            SupervisorExecutionRuntime::NonpublishableSimulation
        );
        assert_eq!(
            preclaim_assessment_runtime(
                SupervisorRuntime::Codex,
                SupervisorExecutionRuntime::Verified,
                SupervisorWorktreeCreation::Bound(&cleanliness),
            ),
            SupervisorExecutionRuntime::NonpublishableSimulation
        );
        assert_eq!(
            preclaim_assessment_runtime(
                SupervisorRuntime::Codex,
                SupervisorExecutionRuntime::Verified,
                SupervisorWorktreeCreation::PrimaryWorktree,
            ),
            SupervisorExecutionRuntime::NonpublishableSimulation
        );
        assert_eq!(
            preclaim_assessment_runtime(
                SupervisorRuntime::Codex,
                SupervisorExecutionRuntime::Verified,
                SupervisorWorktreeCreation::VerifiedTestOnly,
            ),
            SupervisorExecutionRuntime::Verified
        );
        assert_eq!(
            preclaim_assessment_runtime(
                SupervisorRuntime::Codex,
                SupervisorExecutionRuntime::Verified,
                SupervisorWorktreeCreation::ExistingOnly,
            ),
            SupervisorExecutionRuntime::Verified
        );
        Ok(())
    }

    #[test]
    fn selector_override_is_applied_after_legacy_budget_mutations() {
        let mut plan = test_plan();
        plan.review_lenses = single_parent_acceptance_review_lenses();
        plan.role_models.insert(
            AgentRole::ChildOrchestrator,
            role_selection("plan-child", "xhigh"),
        );
        let (initial_auditor_model, initial_auditor_effort) = match &plan.review_lenses[0].backend {
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } => (
                model.clone(),
                reasoning_effort.clone().expect("default effort"),
            ),
            ReviewLensBackendConfig::Precomputed { .. } => panic!("default lens must be a model"),
        };
        plan.role_models.insert(
            AgentRole::Auditor,
            role_selection(&initial_auditor_model, &initial_auditor_effort),
        );
        let mut policy = AssignmentBudgetPolicy {
            worker_effort_degradation_steps: 1,
            assignment_reasoning_effort: Some(ReasoningEffort::Low),
            ..AssignmentBudgetPolicy::default()
        };
        policy.model_overrides.insert(
            AgentRole::ChildOrchestrator,
            role_selection("legacy-degraded-child", "low"),
        );
        policy.model_overrides.insert(
            AgentRole::Worker,
            role_selection("mechanical-degraded-worker", "low"),
        );
        policy.selector_overrides.insert(
            AgentRole::ChildOrchestrator,
            role_selection("selector-child", "high"),
        );
        policy.selector_overrides.insert(
            AgentRole::Auditor,
            role_selection("selector-auditor", "xhigh"),
        );
        policy
            .selector_overrides
            .insert(AgentRole::Worker, role_selection("selector-worker", "high"));

        let effective = policy.apply(&plan);

        assert_eq!(
            effective.role_models[&AgentRole::ChildOrchestrator],
            role_selection("selector-child", "high")
        );
        assert_eq!(
            effective.role_models[&AgentRole::Auditor],
            role_selection("selector-auditor", "xhigh")
        );
        assert_eq!(
            effective.role_models[&AgentRole::Worker].model.as_deref(),
            Some("mechanical-degraded-worker")
        );
        match &effective.review_lenses[0].backend {
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } => {
                assert_eq!(model, "selector-auditor");
                assert_eq!(reasoning_effort.as_deref(), Some("xhigh"));
            }
            ReviewLensBackendConfig::Precomputed { .. } => {
                panic!("selector-bound lens changed backend")
            }
        }
    }

    #[test]
    fn admission_effort_bindings_use_the_active_budget_selection() {
        let mut plan = test_plan();
        plan.review_lenses = single_parent_acceptance_review_lenses();
        let assignment = OrchestratorAssignment {
            id: "active-effort-assignment".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: vec![WorkerAssignment {
                id: "active-effort-worker".to_string(),
                role: AgentRole::Worker,
                role_category: None,
                selection_source: None,
                assigned_paths: vec![PathBuf::from("README.md")],
                semantic_symbols: Vec::new(),
                semantic_modules: Vec::new(),
                task: None,
                environment_requirements: Vec::new(),
                report_path: None,
            }],
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
            decision_refs: Vec::new(),
        };
        plan.assignments = vec![assignment.clone()];
        plan.role_models
            .insert(AgentRole::Worker, role_selection("initial-worker", "low"));
        let (initial_auditor_model, initial_auditor_effort) = match &plan.review_lenses[0].backend {
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } => (
                model.clone(),
                reasoning_effort.clone().expect("default auditor effort"),
            ),
            ReviewLensBackendConfig::Precomputed { .. } => {
                panic!("default lens must be model-backed")
            }
        };
        plan.role_models.insert(
            AgentRole::Auditor,
            role_selection(&initial_auditor_model, &initial_auditor_effort),
        );
        plan.review_lenses.push(ReviewLensConfig {
            id: "active-effort-custom-lens".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "custom-provider".to_string(),
                model: "custom-auditor".to_string(),
                reasoning_effort: Some("ultra".to_string()),
            },
            information_scope: ReviewInformationScope::OutputReportOnly,
        });
        let mut policy = AssignmentBudgetPolicy::default();
        policy.set_assignment_reasoning_effort_for_test(Some(ReasoningEffort::Low));
        policy.set_selector_binding_for_test(
            AgentRole::Worker,
            SupervisorRuntime::Codex,
            role_selection("active-worker", "high"),
        );
        policy.set_selector_binding_for_test(
            AgentRole::Auditor,
            SupervisorRuntime::Codex,
            role_selection("active-auditor", "ultra"),
        );
        let active_plan = policy.apply(&plan);
        assert_eq!(
            active_plan.role_models[&AgentRole::Worker]
                .reasoning_effort
                .as_deref(),
            Some("high")
        );
        assert_eq!(
            active_plan.role_models[&AgentRole::Auditor]
                .reasoning_effort
                .as_deref(),
            Some("ultra")
        );
        assert_eq!(active_plan.review_lenses.len(), 2);
        assert_eq!(active_plan.review_lenses[0].id, "parent-acceptance");
        assert_eq!(
            active_plan.review_lenses[0].information_scope,
            ReviewInformationScope::FullChildTranscript
        );
        match &active_plan.review_lenses[0].backend {
            ReviewLensBackendConfig::Model {
                backend_id,
                model,
                reasoning_effort,
                ..
            } => {
                assert_eq!(backend_id, "openai");
                assert_eq!(model, "active-auditor");
                assert_eq!(reasoning_effort.as_deref(), Some("ultra"));
            }
            ReviewLensBackendConfig::Precomputed { .. } => {
                panic!("selector-bound lens changed backend")
            }
        }
        assert_eq!(active_plan.review_lenses[1].id, "active-effort-custom-lens");
        assert_eq!(
            active_plan.review_lenses[1].information_scope,
            ReviewInformationScope::OutputReportOnly
        );
        match &active_plan.review_lenses[1].backend {
            ReviewLensBackendConfig::Model {
                backend_id,
                model,
                reasoning_effort,
                ..
            } => {
                assert_eq!(backend_id, "custom-provider");
                assert_eq!(model, "custom-auditor");
                assert_eq!(reasoning_effort.as_deref(), Some("ultra"));
            }
            ReviewLensBackendConfig::Precomputed { .. } => {
                panic!("independent custom lens changed backend")
            }
        }

        let mut controller = BudgetDegradationController::new(1);
        controller.record_assignment_effort_bindings(
            &assignment,
            Some(ReasoningEffort::Low),
            &plan,
            &policy,
        );
        let worker = controller
            .assignment_effort_bindings
            .iter()
            .find(|binding| binding.role == AgentRole::Worker)
            .expect("nested-worker admission binding");
        assert_eq!(worker.resolved_reasoning_effort, "high");
        assert_eq!(
            worker.resolution_observation,
            EffortResolutionObservation::BudgetDegraded
        );
        assert!(worker
            .unavailable_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("admission-only")));
        let auditors = controller
            .assignment_effort_bindings
            .iter()
            .filter(|binding| binding.role == AgentRole::Auditor)
            .collect::<Vec<_>>();
        assert_eq!(auditors.len(), 2);
        for (lens_index, auditor) in auditors.into_iter().enumerate() {
            assert_eq!(
                auditor.duty_id,
                review_lens_auditor_id(&assignment, lens_index)
            );
            assert_eq!(
                auditor.requested_reasoning_effort,
                Some(ReasoningEffort::Ultra)
            );
            assert_eq!(auditor.fallback_reasoning_effort, "ultra");
            assert_eq!(auditor.resolved_reasoning_effort, "ultra");
            assert_eq!(
                auditor.resolution_observation,
                EffortResolutionObservation::AssignmentOverride
            );
            assert!(auditor
                .unavailable_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("retry-time active effort")));
        }
    }

    #[test]
    fn completed_retry_promotes_matching_execution_override_and_reroute_state() -> Result<()> {
        let (catalog, state, _, plan, frozen) = automatic_selection_fixture()?;
        let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
        let mut controller = BudgetDegradationController::new_with_selection_state(
            2,
            Some(state),
            SupervisorRuntime::Codex,
        )?;
        let mut retry_policy = controller.policy.clone();

        let retry_events = retry_policy.reselect(
            SupervisorRuntime::Codex,
            &catalog,
            SelectorReselectionRequest {
                roles: &[AgentRole::Worker],
                assignment_id: Some("retry-assignment"),
                attempt: 2,
                primary_cause: SupervisorSelectionEventCause::Retry,
                retry_count: 1,
                budget_signal: crate::selection::BudgetSignal::Continue,
                environment_rejections: &[],
            },
        )?;
        let retry_choice = retry_events[0]
            .provenance
            .choice
            .as_ref()
            .context("retry selected worker choice")?
            .candidate
            .clone();
        let retry_selection = retry_policy
            .selector_overrides
            .get(&AgentRole::Worker)
            .context("retry selected executable worker override")?
            .clone();
        assert_eq!(
            retry_policy
                .selected_runtime_for(AgentRole::Worker)
                .map(SupervisorRuntime::as_str),
            Some(retry_choice.runtime.as_str())
        );

        let indexed_outcomes = vec![Some(AssignmentExecutionOutcome {
            selection_decisions: retry_events.clone(),
            ..AssignmentExecutionOutcome::default()
        })];
        controller.commit_completed_selection_prefix(
            &indexed_outcomes,
            SupervisorRuntime::Codex,
            Path::new("/nonexistent-maco-cpo-refresh"),
        )?;

        let continue_plan = controller.policy.apply(&plan);
        assert_eq!(
            continue_plan.role_models.get(&AgentRole::Worker),
            Some(&retry_selection)
        );
        assert_eq!(
            controller
                .policy
                .selected_runtime_for(AgentRole::Worker)
                .map(SupervisorRuntime::as_str),
            Some(retry_choice.runtime.as_str())
        );

        let mut later_policy = controller.policy.clone();
        let later_events = later_policy.reselect(
            SupervisorRuntime::Codex,
            &catalog,
            SelectorReselectionRequest {
                roles: &[AgentRole::Worker],
                assignment_id: Some("later-budget-assignment"),
                attempt: 0,
                primary_cause: SupervisorSelectionEventCause::BudgetDegrade,
                retry_count: 0,
                budget_signal: crate::selection::BudgetSignal::Degrade,
                environment_rejections: &[],
            },
        )?;

        assert_eq!(
            retry_events[0].assignment_id.as_deref(),
            Some("retry-assignment")
        );
        assert_eq!(retry_events[0].attempt, 2);
        assert_eq!(
            later_events[0]
                .provenance
                .normalized_input
                .signals
                .previous_choice
                .as_ref(),
            Some(&retry_choice)
        );
        assert_eq!(
            later_events[0].primary_cause,
            SupervisorSelectionEventCause::BudgetDegrade
        );
        Ok(())
    }

    #[test]
    fn same_run_cost_rows_preserve_selection_lane_identity() -> Result<()> {
        let (catalog, mut state, events, _, frozen) = automatic_selection_fixture()?;
        let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
        let provenance = &events
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("worker selection")?
            .provenance;
        let candidate = provenance
            .choice
            .as_ref()
            .context("worker choice")?
            .candidate
            .clone();
        let binding = AttemptSelectionBinding {
            role: AgentRole::Worker,
            event_assignment_id: None,
            event_attempt: 0,
            normalized_input_sha256: provenance.input_digests.normalized_input.value.clone(),
            task: provenance.normalized_task.clone(),
            assignment_shape_identity: Some(
                crate::selection::AssignmentShapeIdentity::v1("a".repeat(64))
                    .expect("validated shape fixture"),
            ),
            requested_candidate: candidate.clone(),
        };
        let run_dir = tempfile::TempDir::new()?;
        let attempts = run_dir.path().join("selection-attempts");
        std::fs::create_dir_all(&attempts)?;
        for (id, selection) in [
            ("bound", Some(binding.clone())),
            (
                "unbound",
                Some(AttemptSelectionBinding {
                    assignment_shape_identity: None,
                    ..binding.clone()
                }),
            ),
            ("legacy", None),
        ] {
            let evidence = AttemptOutcomeEvidence {
                version: 1,
                run_id: "cost-cohorts".to_string(),
                assignment_id: id.to_string(),
                attempt: 1,
                verified_execution: false,
                selection,
                requested_runtime: candidate.runtime.clone(),
                requested_model: Some(candidate.model.clone()),
                requested_effort: Some(candidate.effort.as_str().to_string()),
                observed_candidate: None,
                parent_result: Some(OutcomeResult::Accepted),
                parent_cause: None,
                failure_class: None,
                costs: complete_attempt_costs(),
                parent_phase_continuation: None,
            };
            std::fs::write(
                attempts.join(format!("{id}.attempt-1.json")),
                serde_json::to_vec(&evidence)?,
            )?;
        }
        let rows = load_this_run_attempt_cost_rows(run_dir.path());
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].selection.as_ref(), Some(&binding));
        let records = this_run_attempt_cost_records(&rows, &[]);
        assert_eq!(records[0].selection.as_ref(), Some(&binding));
        let cohorts = this_run_accepted_task_cost_cohorts(&rows, &[]).context("cohorts")?;
        assert_eq!(cohorts.lanes.len(), 1);
        assert_eq!(cohorts.lanes[0].lane.candidate, candidate);
        assert_eq!(cohorts.unattributed.complete_attempt_count, 2);
        let observations = cohorts.observations();
        state.set_observed_accepted_task_cost(observations.clone());
        let replay = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            0,
            crate::selection::BudgetSignal::Continue,
            &[],
        )?;
        let signals = &replay.decisions[0].1.normalized_input.signals;
        assert_eq!(signals.accepted_task_cost_observations, observations);
        assert!(signals.accepted_task_cost_context.is_none());
        Ok(())
    }

    #[test]
    fn this_run_cpo_infers_accepted_from_report_when_parent_result_is_absent() {
        let rows = [ThisRunAttemptCostRow {
            assignment_id: "assignment-1".to_string(),
            attempt: 1,
            selection: None,
            parent_result: None,
            costs: complete_attempt_costs(),
        }];
        let unresolved = this_run_accepted_task_cost(&rows, &[]).expect("unresolved row retained");
        assert_eq!(unresolved.complete_attempt_count, 1);
        assert_eq!(unresolved.unknown_terminal_result_count, 1);
        assert_eq!(unresolved.complete_total_cycle_cost_microunits, 12);
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&unresolved)),
            None
        );
        let rollup = this_run_accepted_task_cost(&rows, &[accepted_review_report("assignment-1")])
            .expect("complete accepted rollup");
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&rollup)),
            Some(12)
        );
    }

    #[test]
    fn this_run_cpo_retains_unresolved_earlier_attempts_after_latest_acceptance() {
        let rows = [
            ThisRunAttemptCostRow {
                assignment_id: "assignment-1".to_string(),
                attempt: 1,
                selection: None,
                parent_result: None,
                costs: complete_attempt_costs(),
            },
            ThisRunAttemptCostRow {
                assignment_id: "assignment-1".to_string(),
                attempt: 2,
                selection: None,
                parent_result: None,
                costs: complete_attempt_costs(),
            },
        ];
        let reports = [accepted_review_report("assignment-1")];
        let records = this_run_attempt_cost_records(&rows, &reports);
        assert_eq!(records.len(), rows.len());
        assert_eq!(records[0].result, None);
        assert_eq!(records[1].result, Some(OutcomeResult::Accepted));
        assert_eq!(records[0].costs, rows[0].costs);
        let rollup = this_run_accepted_task_cost(&rows, &reports).expect("retained cost rollup");
        assert_eq!(rollup.complete_attempt_count, 2);
        assert_eq!(rollup.unknown_terminal_result_count, 1);
        assert_eq!(rollup.complete_total_cycle_cost_microunits, 24);
        assert_eq!(rollup.cost_per_accepted_task_microunits, None);
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&rollup)),
            None
        );
    }

    #[test]
    fn this_run_cpo_refuses_mixed_missing_cost_but_retains_known_subtotal() {
        let mut incomplete_costs = complete_attempt_costs();
        incomplete_costs.environment_cost_microunits = None;
        let rows = [
            ThisRunAttemptCostRow {
                assignment_id: "accepted".to_string(),
                attempt: 1,
                selection: None,
                parent_result: Some(OutcomeResult::Accepted),
                costs: complete_attempt_costs(),
            },
            ThisRunAttemptCostRow {
                assignment_id: "blocked".to_string(),
                attempt: 1,
                selection: None,
                parent_result: Some(OutcomeResult::Blocked),
                costs: incomplete_costs,
            },
        ];
        let records = this_run_attempt_cost_records(&rows, &[]);
        assert_eq!(records.len(), rows.len());
        assert_eq!(records[1].costs.environment_cost_microunits, None);
        let rollup = this_run_accepted_task_cost(&rows, &[]).expect("partial cost rollup");
        assert_eq!(rollup.incomplete_attempt_count, 1);
        assert_eq!(rollup.unknown_terminal_result_count, 0);
        assert_eq!(rollup.complete_total_cycle_cost_microunits, 12);
        assert_eq!(rollup.cost_per_accepted_task_microunits, None);
        assert_eq!(
            observed_cost_per_accepted_task_microunits(Some(&rollup)),
            None
        );
    }

    #[test]
    fn commit_prefix_keeps_unbound_cpo_out_of_shared_policy_reselect() -> Result<()> {
        let (catalog, state, _, _, frozen) = automatic_selection_fixture()?;
        let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
        let mut controller = BudgetDegradationController::new_with_selection_state(
            2,
            Some(state),
            SupervisorRuntime::Codex,
        )?;
        let run_dir = tempfile::TempDir::new()?;
        let attempts = run_dir.path().join("selection-attempts");
        std::fs::create_dir_all(&attempts)?;
        let evidence = AttemptOutcomeEvidence {
            version: 1,
            run_id: "cpo-refresh".to_string(),
            assignment_id: "assignment-1".to_string(),
            attempt: 1,
            verified_execution: false,
            selection: None,
            requested_runtime: "codex".to_string(),
            requested_model: None,
            requested_effort: None,
            observed_candidate: None,
            parent_result: None,
            parent_cause: None,
            failure_class: None,
            costs: complete_attempt_costs(),
            parent_phase_continuation: None,
        };
        std::fs::write(
            attempts.join("assignment-1.attempt-1.json"),
            serde_json::to_vec(&evidence)?,
        )?;
        let indexed_outcomes = vec![Some(AssignmentExecutionOutcome {
            report: Some(accepted_review_report("assignment-1")),
            ..AssignmentExecutionOutcome::default()
        })];
        controller.commit_completed_selection_prefix(
            &indexed_outcomes,
            SupervisorRuntime::Codex,
            run_dir.path(),
        )?;

        let mut later_policy = controller.policy.clone();
        let later_events = later_policy.reselect(
            SupervisorRuntime::Codex,
            &catalog,
            SelectorReselectionRequest {
                roles: &[AgentRole::Worker],
                assignment_id: Some("later-assignment"),
                attempt: 0,
                primary_cause: SupervisorSelectionEventCause::BudgetDegrade,
                retry_count: 0,
                budget_signal: crate::selection::BudgetSignal::Degrade,
                environment_rejections: &[],
            },
        )?;
        let signals = &later_events[0].provenance.normalized_input.signals;
        assert!(signals.accepted_task_cost_context.is_none());
        assert!(signals.accepted_task_cost_observations.is_empty());
        Ok(())
    }

    #[test]
    fn concurrent_retries_share_predispatch_state_and_commit_in_schedule_order() -> Result<()> {
        let (catalog, state, initial_events, plan, frozen) = automatic_selection_fixture()?;
        let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
        let initial_worker = initial_events
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .and_then(|event| event.provenance.choice.as_ref())
            .context("initial worker selection")?
            .candidate
            .clone();
        let mut controller = BudgetDegradationController::new_with_selection_state(
            2,
            Some(state),
            SupervisorRuntime::Codex,
        )?;
        let policies = [controller.policy.clone(), controller.policy.clone()];
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut completed = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for (index, mut policy) in policies.into_iter().enumerate() {
                let barrier = barrier.clone();
                let catalog = &catalog;
                let frozen = frozen.clone();
                handles.push(scope.spawn(
                    move || -> Result<(usize, SupervisorSelectionEvent, RoleModelSelection)> {
                        barrier.wait();
                        let _policy =
                            crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
                        let events = policy.reselect(
                            SupervisorRuntime::Codex,
                            catalog,
                            SelectorReselectionRequest {
                                roles: &[AgentRole::Worker],
                                assignment_id: Some(if index == 0 {
                                    "schedule-0"
                                } else {
                                    "schedule-1"
                                }),
                                attempt: index + 1,
                                primary_cause: SupervisorSelectionEventCause::Retry,
                                retry_count: u32::try_from(index + 1)
                                    .context("test retry count fits u32")?,
                                budget_signal: crate::selection::BudgetSignal::Continue,
                                environment_rejections: &[],
                            },
                        )?;
                        let selection = policy
                            .selector_overrides
                            .get(&AgentRole::Worker)
                            .context("retry worker override")?
                            .clone();
                        Ok((
                            index,
                            events.into_iter().next().context("retry event")?,
                            selection,
                        ))
                    },
                ));
            }
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .expect("concurrent retry thread did not panic")
                })
                .collect::<Result<Vec<_>>>()
        })?;
        completed.sort_by_key(|(index, _, _)| *index);
        assert!(completed.iter().all(|(_, event, _)| {
            event
                .provenance
                .normalized_input
                .signals
                .previous_choice
                .as_ref()
                == Some(&initial_worker)
        }));

        let schedule_one_choice = completed[1]
            .1
            .provenance
            .choice
            .as_ref()
            .context("schedule-one retry choice")?
            .clone();
        let mut indexed_outcomes = vec![None, None];
        indexed_outcomes[1] = Some(AssignmentExecutionOutcome {
            selection_decisions: vec![completed[1].1.clone()],
            ..AssignmentExecutionOutcome::default()
        });
        controller.commit_completed_selection_prefix(
            &indexed_outcomes,
            SupervisorRuntime::Codex,
            Path::new("/nonexistent-maco-cpo-refresh"),
        )?;
        assert_eq!(controller.next_selection_commit_index, 0);

        indexed_outcomes[0] = Some(AssignmentExecutionOutcome {
            selection_decisions: vec![completed[0].1.clone()],
            ..AssignmentExecutionOutcome::default()
        });
        controller.commit_completed_selection_prefix(
            &indexed_outcomes,
            SupervisorRuntime::Codex,
            Path::new("/nonexistent-maco-cpo-refresh"),
        )?;
        assert_eq!(controller.next_selection_commit_index, 2);
        assert_eq!(
            controller
                .policy
                .selected_runtime_for(AgentRole::Worker)
                .map(SupervisorRuntime::as_str),
            Some(schedule_one_choice.candidate.runtime.as_str())
        );
        assert_eq!(
            controller
                .policy
                .apply(&plan)
                .role_models
                .get(&AgentRole::Worker),
            Some(&completed[1].2)
        );

        let mut later_policy = controller.policy.clone();
        let later_events = later_policy.reselect(
            SupervisorRuntime::Codex,
            &catalog,
            SelectorReselectionRequest {
                roles: &[AgentRole::Worker],
                assignment_id: Some("schedule-2"),
                attempt: 1,
                primary_cause: SupervisorSelectionEventCause::Retry,
                retry_count: 1,
                budget_signal: crate::selection::BudgetSignal::Continue,
                environment_rejections: &[],
            },
        )?;
        assert_eq!(
            later_events[0]
                .provenance
                .normalized_input
                .signals
                .previous_choice
                .as_ref(),
            Some(&schedule_one_choice.candidate)
        );
        Ok(())
    }

    #[test]
    fn selection_decision_collection_is_schedule_attempt_role_deterministic() -> Result<()> {
        fn tagged(
            mut provenance: crate::selection::SelectionProvenance,
            tag: &str,
        ) -> crate::selection::SelectionProvenance {
            provenance.decision_reason = tag.to_string();
            provenance
        }

        let provenance = automatic_provenance()?;
        let schedule_zero = AssignmentExecutionOutcome {
            selection_decisions: vec![
                SupervisorSelectionEvent {
                    assignment_id: Some("schedule-0".to_string()),
                    attempt: 2,
                    role: AgentRole::Worker,
                    primary_cause: SupervisorSelectionEventCause::Retry,
                    provenance: tagged(provenance.clone(), "schedule-0-attempt-2-worker"),
                },
                SupervisorSelectionEvent {
                    assignment_id: Some("schedule-0".to_string()),
                    attempt: 1,
                    role: AgentRole::Worker,
                    primary_cause: SupervisorSelectionEventCause::Retry,
                    provenance: tagged(provenance.clone(), "schedule-0-attempt-1-worker"),
                },
                SupervisorSelectionEvent {
                    assignment_id: Some("schedule-0".to_string()),
                    attempt: 1,
                    role: AgentRole::ChildOrchestrator,
                    primary_cause: SupervisorSelectionEventCause::Retry,
                    provenance: tagged(provenance.clone(), "schedule-0-attempt-1-child"),
                },
            ],
            ..AssignmentExecutionOutcome::default()
        };
        let schedule_one = AssignmentExecutionOutcome {
            selection_decisions: vec![SupervisorSelectionEvent {
                assignment_id: Some("schedule-1".to_string()),
                attempt: 1,
                role: AgentRole::Auditor,
                primary_cause: SupervisorSelectionEventCause::Retry,
                provenance: tagged(provenance, "schedule-1-attempt-1-auditor"),
            }],
            ..AssignmentExecutionOutcome::default()
        };
        let mut collected = CollectedAssignmentOutcomes::default();

        let fatal_errors = collect_indexed_assignment_outcomes(
            vec![Some(schedule_zero), Some(schedule_one)],
            false,
            &mut collected,
        );

        assert!(fatal_errors.is_empty());
        assert_eq!(
            collected
                .selection_decisions
                .iter()
                .map(|event| event.provenance.decision_reason.as_str())
                .collect::<Vec<_>>(),
            vec![
                "schedule-0-attempt-1-child",
                "schedule-0-attempt-1-worker",
                "schedule-0-attempt-2-worker",
                "schedule-1-attempt-1-auditor",
            ]
        );
        Ok(())
    }

    #[test]
    fn selection_event_serialization_is_strict_and_retains_execution_context() -> Result<()> {
        let event = SupervisorSelectionEvent {
            assignment_id: Some("assignment-a".to_string()),
            attempt: 2,
            role: AgentRole::Worker,
            primary_cause: SupervisorSelectionEventCause::Retry,
            provenance: automatic_provenance()?,
        };

        let value = serde_json::to_value(&event)?;
        assert_eq!(value["assignment_id"], "assignment-a");
        assert_eq!(value["attempt"], 2);
        assert_eq!(value["role"], "worker");
        assert_eq!(value["primary_cause"], "retry");
        assert_eq!(
            serde_json::from_value::<SupervisorSelectionEvent>(value.clone())?,
            event
        );

        let mut unexpected = value;
        unexpected
            .as_object_mut()
            .context("serialized event object")?
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SupervisorSelectionEvent>(unexpected).is_err());
        Ok(())
    }

    #[test]
    fn empty_role_model_test_catalog_supports_verified_automatic_selection() -> Result<()> {
        let (temporary, repo) = initialized_repository();
        let (mut plan, assessment, frozen) = assessed_selection_fixture()?;
        let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
        let catalog = test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)?;
        let priors = crate::selection::built_in_prior_dataset()?;
        let RuntimeModelCatalog::Codex(codex_catalog) = &catalog else {
            bail!("Codex test runtime did not produce a Codex catalog")
        };
        for prior in priors
            .models
            .iter()
            .filter(|prior| prior.runtime == "codex")
        {
            assert!(codex_catalog.contains(&prior.model));
        }
        let admission = SupervisorAdmissionPolicyInput::resolve(
            &repo,
            1,
            SupervisorAdmissionConfig::default(),
            SupervisorAdmissionConfig::default(),
        )?;

        let resolved_objective_profile = default_resolved_objective_profile()?;
        let resolution =
            super::super::selection_bridge::initialize_supervisor_selection_with_assessment(
                &mut plan,
                SupervisorRuntime::Codex,
                &catalog,
                &admission,
                &AdvertisedCatalogSet::empty(),
                Some(&resolved_objective_profile),
                SupervisorQuotaSelectionInput::default(),
                None,
                &[],
                Some(&assessment),
            )?;

        assert_eq!(resolution.mode, SupervisorSelectionMode::Automatic);
        assert_eq!(resolution.decisions.len(), 5);
        assert!(resolution.selection_preflight_failure.is_none());
        assert_eq!(plan.role_models.len(), 5);
        drop(temporary);
        Ok(())
    }

    #[test]
    fn verified_automatic_preparation_separates_requested_and_effective_plans() -> Result<()> {
        let (temporary, repo) = initialized_repository();
        let mut plan = test_plan();
        plan.assignments = vec![OrchestratorAssignment {
            id: "assignment-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from(SELECTOR_TEST_TARGET)],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
            decision_refs: Vec::new(),
        }];
        let requested_plan = plan.clone();
        let catalog = test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)?;
        #[cfg(target_os = "linux")]
        let _cam = install_positive_injected_cam_fixture(&temporary, &catalog)?;
        let mut plan_metadata = SupervisorPlanMetadata::default();
        let _routing_policy =
            crate::supervise::bind_assessed_injected_plan(&plan, &repo, &mut plan_metadata)?;
        let options =
            predispatch_options(&repo, temporary.path(), "automatic-requested-plan-identity");

        let prepared = prepare_supervisor_run(
            LoadedSupervisorPlan {
                plan,
                consultant: SupervisorConsultantPlan::default(),
                assignment_metadata: AssignmentMetadata::new(),
                plan_metadata,
            },
            &options,
            1,
            SupervisorExecutionRuntime::Verified,
            SupervisorWorktreeCreation::ExistingOnly,
            Ok(catalog),
        )?;

        assert_eq!(prepared.requested_plan, requested_plan);
        assert!(prepared.requested_plan.role_models.is_empty());
        assert_eq!(
            prepared.requested_plan.review_lenses,
            requested_plan.review_lenses
        );
        let expected_roles = BTreeSet::from([
            AgentRole::Supervisor,
            AgentRole::GateClassifier,
            AgentRole::Auditor,
            AgentRole::ChildOrchestrator,
        ]);
        let actual_roles: BTreeSet<_> = prepared.plan.role_models.keys().copied().collect();
        assert_eq!(actual_roles, expected_roles);
        assert!(actual_roles.contains(&AgentRole::Supervisor));
        assert!(actual_roles.contains(&AgentRole::GateClassifier));
        assert!(actual_roles.contains(&AgentRole::Auditor));
        assert!(actual_roles.contains(&AgentRole::ChildOrchestrator));
        assert!(!actual_roles.contains(&AgentRole::Researcher));
        assert_ne!(prepared.plan, prepared.requested_plan);
        Ok(())
    }

    #[test]
    fn fail_closed_debug_selection_is_persisted_before_any_external_dispatch() -> Result<()> {
        let (temporary, repo) = initialized_repository();
        let mut plan = test_plan();
        plan.assignments = vec![OrchestratorAssignment {
            id: "assignment-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from(SELECTOR_TEST_TARGET)],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
            decision_refs: Vec::new(),
        }];
        let priors = crate::selection::built_in_prior_dataset()?;
        let ineligible = priors
            .models
            .iter()
            .find(|prior| {
                prior.runtime == "codex"
                    && prior
                        .prohibited_authority_roles
                        .contains(&crate::selection::AuthorityRole::ReviewAuditor)
            })
            .context("ineligible auditor prior")?;
        plan.role_models.insert(
            AgentRole::Auditor,
            role_selection(&ineligible.model, "high"),
        );
        let original_role_models = plan.role_models.clone();
        let catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(
            priors
                .models
                .iter()
                .filter(|prior| prior.runtime == "codex")
                .map(|prior| prior.model.clone()),
        )?);
        #[cfg(target_os = "linux")]
        let _cam = install_positive_injected_cam_fixture(&temporary, &catalog)?;
        let admission = SupervisorAdmissionPolicyInput::resolve(
            &repo,
            1,
            SupervisorAdmissionConfig::default(),
            SupervisorAdmissionConfig::default(),
        )?;
        let mut plan_metadata = SupervisorPlanMetadata::default();
        let _routing_policy =
            crate::supervise::bind_assessed_injected_plan(&plan, &repo, &mut plan_metadata)?;
        let mut bridge_plan = plan.clone();
        let resolved_objective_profile = default_resolved_objective_profile()?;
        let bridge_resolution = initialize_supervisor_selection_with_assessment(
            &mut bridge_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &AdvertisedCatalogSet::empty(),
            Some(&resolved_objective_profile),
            SupervisorQuotaSelectionInput::default(),
            None,
            &[],
            plan_metadata.task_routing_assessment.as_ref(),
        )?;
        assert_eq!(bridge_plan.role_models, original_role_models);
        assert!(bridge_resolution.selection_preflight_failure.is_some());
        let options = predispatch_options(
            &repo,
            temporary.path(),
            "selection-fail-closed-before-dispatch",
        );
        let run_id = options.run_id.clone();
        let calls = AtomicUsize::new(0);
        let runner =
            |_command: &ExternalAgentCommand,
             _cancellation: &ProcessCancellation,
             _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>| {
                calls.fetch_add(1, Ordering::SeqCst);
                panic!("selection preflight failure must prevent external dispatch")
            };

        let report = run_supervisor_plan_with_runner_and_creation(
            LoadedSupervisorPlan {
                plan,
                consultant: SupervisorConsultantPlan::default(),
                assignment_metadata: AssignmentMetadata::new(),
                plan_metadata,
            },
            options,
            1,
            SupervisorExecutionRuntime::Verified,
            SupervisorWorktreeCreation::ExistingOnly,
            Ok(catalog),
            &runner,
        )?;

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!report.success);
        assert!(!report.publishable);
        assert!(report.environment_failures.is_empty());
        assert!(report.findings.iter().any(|finding| {
            finding.severity == FindingSeverity::Error
                && finding.message.contains("selection preflight failed")
        }));
        let profile = report
            .role_economics_profile
            .as_ref()
            .context("selection failure economics profile")?;
        assert_eq!(profile.overridden_roles, vec![AgentRole::Auditor]);
        assert_eq!(
            profile.role_models.len(),
            provisional_default_role_models().len()
        );
        let normalized_auditor = &profile.role_models[&AgentRole::Auditor];
        assert_eq!(
            normalized_auditor.model,
            original_role_models[&AgentRole::Auditor].model
        );
        assert_eq!(
            normalized_auditor.reasoning_effort,
            original_role_models[&AgentRole::Auditor].reasoning_effort
        );
        let events = &profile
            .execution
            .as_ref()
            .context("selection failure execution metadata")?
            .selection_decisions;
        let required_roles = BTreeSet::from([
            AgentRole::Supervisor,
            AgentRole::GateClassifier,
            AgentRole::Auditor,
            AgentRole::ChildOrchestrator,
        ]);
        assert_eq!(events.len(), required_roles.len());
        let event_roles: BTreeSet<_> = events.iter().map(|event| event.role).collect();
        assert_eq!(event_roles, required_roles);
        assert!(!event_roles.contains(&AgentRole::Researcher));
        let auditor_event = events
            .iter()
            .find(|event| event.role == AgentRole::Auditor)
            .context("persisted fail-closed auditor selection event")?;
        assert_eq!(
            auditor_event.primary_cause,
            SupervisorSelectionEventCause::DebugOverride
        );
        assert_eq!(
            auditor_event.provenance.status,
            crate::selection::DecisionStatus::FailClosed
        );
        assert!(auditor_event.provenance.choice.is_none());
        assert!(!auditor_event.provenance.candidate_set.is_empty());
        let ledger = &profile
            .execution
            .as_ref()
            .context("selection failure execution metadata")?
            .assignment_selection_ledger;
        assert!(ledger.iter().any(|entry| {
            entry.assignment_id == "assignment-a"
                && entry.role == AgentRole::Auditor
                && entry.selection_source == AssignmentSelectionSource::PlanRoleModels
                && entry.selected_model.is_none()
                && entry.evidence_gap.is_some()
                && !entry.rejected_candidates.is_empty()
        }));

        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)?;
        let persisted = read_supervisor_final_report(&reader)?;
        assert_eq!(persisted, report);
        let persisted_ledger: AssignmentSelectionLedger = serde_json::from_slice(
            &reader
                .read(Path::new(SELECTION_LEDGER_RELATIVE))
                .context("read persisted selection ledger")?,
        )?;
        assert_eq!(
            persisted_ledger.schema_version,
            ASSIGNMENT_SELECTION_LEDGER_SCHEMA_VERSION
        );
        assert_eq!(persisted_ledger.entries, *ledger);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    mod account_observe_wire {
        use super::*;
        use coding_agent_manager_lib::account_authority::{
            CategoryObservation, ModelsObservation, ObservationOutcome, ObservedModel,
        };
        use coding_agent_manager_lib::error::Error as CamError;
        use coding_agent_manager_lib::model::{
            Account, AuthKind, InstallState, Maturity, ProviderDescriptor, QuotaSnapshot,
            StoredAccountMaterial, StoredAccountMetadata,
        };
        use coding_agent_manager_lib::paths::stored_accounts_path;
        use coding_agent_manager_lib::providers::ProviderAdapter;

        enum SchedulerObserveStubMode {
            ObservedModels,
            ObservedSynthetic(ObservedModel),
            ObserveError,
        }

        struct SchedulerObserveStub {
            id: &'static str,
            mode: SchedulerObserveStubMode,
        }

        impl ProviderAdapter for SchedulerObserveStub {
            fn id(&self) -> &'static str {
                self.id
            }

            fn descriptor(&self) -> ProviderDescriptor {
                ProviderDescriptor {
                    id: self.id.to_string(),
                    display_name: self.id.to_string(),
                    vendor: "test".to_string(),
                    auth_kinds: vec![AuthKind::OAuth],
                    maturity: Maturity::Experimental,
                    install_state: InstallState::Unknown,
                    capabilities: Vec::new(),
                }
            }

            fn config_paths(&self) -> Vec<PathBuf> {
                Vec::new()
            }

            fn detect(&self) -> InstallState {
                InstallState::Unknown
            }

            fn list_accounts(&self) -> coding_agent_manager_lib::error::Result<Vec<Account>> {
                Ok(Vec::new())
            }

            fn activate_account(
                &self,
                _account_id: &str,
            ) -> coding_agent_manager_lib::error::Result<()> {
                Err(CamError::NotImplemented("activate"))
            }

            fn quota_for_account(
                &self,
                _account: &StoredAccountMetadata,
            ) -> coding_agent_manager_lib::error::Result<Vec<QuotaSnapshot>> {
                Ok(Vec::new())
            }

            fn observe_models_for_account(
                &self,
                _account: &StoredAccountMetadata,
            ) -> coding_agent_manager_lib::error::Result<CategoryObservation<ModelsObservation>>
            {
                match &self.mode {
                    SchedulerObserveStubMode::ObservedModels => {
                        Ok(CategoryObservation::observed(ModelsObservation {
                            provenance: None,
                            models: vec![ObservedModel {
    access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                                model_id: FRONTIER_PROFILE_MODEL.to_string(),
                                supported_efforts: Some(vec![
                                    "high".to_string(),
                                    "xhigh".to_string(),
                                ]),
                                default_effort: Some("high".to_string()),
                            }],
                        }))
                    }
                    SchedulerObserveStubMode::ObservedSynthetic(model) => {
                        Ok(CategoryObservation::observed(ModelsObservation {
                            provenance: None,
                            models: vec![model.clone()],
                        }))
                    }
                    SchedulerObserveStubMode::ObserveError => Err(CamError::ConfigRead {
                        provider: self.id.to_string(),
                        reason: "scheduler observe stub refused models".to_string(),
                    }),
                }
            }
        }

        fn synthetic_prior_observed_model(prior: &crate::selection::ModelPrior) -> ObservedModel {
            let mut efforts = std::collections::BTreeSet::new();
            for fit in &prior.class_fit {
                efforts.insert(fit.effort.as_str().to_string());
            }
            for evidence in &prior.authority_evidence {
                efforts.insert(evidence.effort.as_str().to_string());
            }
            for effort in &prior.strong_gate_fallback_efforts {
                efforts.insert(effort.as_str().to_string());
            }
            ObservedModel {
                access:
                    coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                model_id: prior.model.clone(),
                supported_efforts: if efforts.is_empty() {
                    None
                } else {
                    Some(efforts.into_iter().collect())
                },
                default_effort: None,
            }
        }

        fn isolated_registry() -> (tempfile::TempDir, StoredAccountRegistry) {
            let root = tempfile::tempdir().expect("isolated CAM data dir");
            let data_dir = root.path().join("data");
            let registry = StoredAccountRegistry::new(stored_accounts_path(&data_dir));
            (root, registry)
        }

        fn seed_complete_account(registry: &StoredAccountRegistry, selected: bool) {
            registry
                .begin_add(
                    "codex-cli",
                    "work",
                    "Work",
                    AuthKind::OAuth,
                    StoredAccountMaterial::VendorHome,
                )
                .expect("begin add");
            registry
                .complete_add("codex-cli", "work")
                .expect("complete add");
            if selected {
                registry
                    .select_complete_revision("codex-cli", "work", None)
                    .expect("select complete account");
            }
        }

        fn activate_stub(selected: bool, mode: SchedulerObserveStubMode) -> CamObserveTestGuard {
            let (root, registry) = isolated_registry();
            if selected {
                seed_complete_account(&registry, true);
            }
            activate_cam_observe_test_harness(CamObserveTestHarness {
                registry,
                secondary_adapter: None,
                adapter: Box::new(SchedulerObserveStub {
                    id: "codex-cli",
                    mode,
                }),
                advertised: None,
                resolved_auditor: None,
                _root: root,
            })
        }

        fn prepared_codex_request<'a>(
            repo: &'a Path,
            catalog: &'a RuntimeModelCatalogAcquisition,
            admission: &'a SupervisorAdmissionPolicyInput,
        ) -> PreparedSupervisorSelectionRequest<'a> {
            PreparedSupervisorSelectionRequest {
                repo,
                current_run: None,
                runtime: SupervisorRuntime::Codex,
                execution_runtime: SupervisorExecutionRuntime::Verified,
                runtime_model_catalog: catalog,
                admission_policy_input: admission,
                quota: SupervisorQuotaSelectionInput::default(),
            }
        }

        fn prepared_selection_fixture() -> Result<(
            tempfile::TempDir,
            PathBuf,
            RuntimeModelCatalogAcquisition,
            SupervisorAdmissionPolicyInput,
            SupervisorPlan,
            SupervisorPlanMetadata,
        )> {
            let (temporary, repo) = super::initialized_repository();
            let plan = super::test_plan();
            let catalog: RuntimeModelCatalogAcquisition = Ok(
                super::super::super::test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)?,
            );
            let admission = SupervisorAdmissionPolicyInput::resolve(
                &repo,
                1,
                SupervisorAdmissionConfig::default(),
                SupervisorAdmissionConfig::default(),
            )?;
            let plan_metadata = SupervisorPlanMetadata {
                resolved_objective_profile: Some(super::default_resolved_objective_profile()?),
                ..SupervisorPlanMetadata::default()
            };
            Ok((temporary, repo, catalog, admission, plan, plan_metadata))
        }

        #[test]
        fn captured_cam_fixture_keeps_child_custody_and_restores_destination() -> Result<()> {
            use crate::account_authority::{codex_run_account_binding, CodexRunAccountBinding};

            let parent_guard = activate_stub(true, SchedulerObserveStubMode::ObservedModels);
            let captured = captured_cam_observe_test_harness().context("parent CAM fixture")?;
            let root = captured._root.path().to_path_buf();
            let registry_path = captured.registry.metadata_path().to_path_buf();
            let expected = captured
                .registry
                .selected_binding("codex-cli")?
                .context("parent selected Codex account")?;
            let authority = authority_id_for(&registry_path);
            let child_root = root.clone();
            thread::scope(|scope| -> Result<()> {
                scope
                    .spawn(|| assert!(captured_cam_observe_test_harness().is_none()))
                    .join()
                    .map_err(|_| anyhow!("unrelated sibling panicked"))?;
                // The capture, then the destination guard, must own the real
                // registry and TempDir after the coordinator's guard is gone.
                drop(parent_guard);
                assert!(root.exists());
                scope
                    .spawn(move || -> Result<()> {
                        assert!(captured_cam_observe_test_harness().is_none());
                        let destination_guard =
                            activate_stub(true, SchedulerObserveStubMode::ObservedModels);
                        let destination =
                            account_observation_for_launch_runtime(SupervisorRuntime::Codex, None)?
                                .context("destination selected account")?;
                        let result = (|| -> Result<()> {
                            let _inherited =
                                install_captured_cam_observe_test_harness(Some(captured));
                            let run = "captured-cam-child-owned-registry";
                            let observed = account_observation_for_launch_runtime(
                                SupervisorRuntime::Codex,
                                Some(run),
                            )?
                            .context("inherited selected account")?;
                            assert_eq!(observed.binding, expected);
                            let Some(CodexRunAccountBinding::Selected(frozen)) =
                                codex_run_account_binding(run)
                            else {
                                bail!("child observation did not freeze its genuine selection");
                            };
                            assert_eq!(frozen.to_selected_binding(), expected);
                            assert_eq!(frozen.authority_id, authority);
                            assert!(child_root.exists());
                            assert!(registry_path.exists());
                            bail!("injected child scope exit after genuine observation")
                        })();
                        assert_eq!(
                            result.unwrap_err().to_string(),
                            "injected child scope exit after genuine observation"
                        );
                        assert!(!child_root.exists());
                        let restored =
                            account_observation_for_launch_runtime(SupervisorRuntime::Codex, None)?
                                .context("restored destination account")?;
                        assert_eq!(restored.binding, destination.binding);
                        drop(destination_guard);
                        assert!(captured_cam_observe_test_harness().is_none());
                        Ok(())
                    })
                    .join()
                    .map_err(|_| anyhow!("inherited child panicked"))??;
                Ok(())
            })?;
            assert!(!root.exists());
            Ok(())
        }

        #[test]
        fn captured_cam_fixture_reobserves_drift_before_frozen_review() -> Result<()> {
            let _cam = activate_stub(true, SchedulerObserveStubMode::ObservedModels);
            let (_temporary, repo, catalog, admission, mut plan, mut metadata) =
                prepared_selection_fixture()?;
            let mut worker = super::terminal_worker_assignment("captured-review-worker");
            worker.role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
            plan.assignments = vec![worker];
            let _routing_policy =
                crate::supervise::bind_assessed_injected_plan(&plan, &repo, &mut metadata)?;
            let run = RunId::new("captured-cam-live-review-drift")?;
            let mut request = prepared_codex_request(&repo, &catalog, &admission);
            request.current_run = Some(&run);
            let initial = initialize_supervisor_selection_from_prepared_metadata(
                &mut plan,
                &mut metadata,
                request,
            )?;
            assert!(initial.selection_preflight_failure.is_none());
            let baseline = initial
                .decisions
                .iter()
                .find(|decision| decision.role == AgentRole::Auditor)
                .context("genuine assessed Auditor decision")?
                .clone();
            let lens = plan
                .review_lenses
                .first()
                .context("resolved review lens")?
                .clone();
            let effort = lens
                .backend
                .reasoning_effort()
                .context("resolved fixture lens effort")?
                .to_string();
            let supplied_catalog = catalog
                .as_ref()
                .map_err(|_| anyhow!("fixture catalog is unavailable"))?;
            let expected = super::super::super::selection_bridge::frozen_review_account_binding(
                SupervisorRuntime::Codex,
                run.as_str(),
            )?
            .context("frozen selected review account")?;
            let expected_account = (&expected).into();
            let observed = account_observation_for_launch_runtime(SupervisorRuntime::Codex, None)?
                .context("original selected account observation")?;
            // Establish the ordinary review contract before introducing drift.
            super::super::super::selection_bridge::select_authored_review_lens(
                &lens,
                &effort,
                SupervisorRuntime::Codex,
                supplied_catalog,
                &baseline.provenance,
                super::super::super::selection_bridge::ReviewLensAccount::Selected {
                    observation: &observed,
                    expected_binding: &expected_account,
                },
                SupervisorQuotaSelectionInput::default(),
            )?;
            let captured =
                captured_cam_observe_test_harness().context("captured review fixture")?;
            captured.registry.begin_add(
                "codex-cli",
                "changed",
                "Synthetic changed account",
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )?;
            captured.registry.complete_add("codex-cli", "changed")?;
            captured
                .registry
                .select_complete_revision("codex-cli", "changed", None)?;
            let frozen = metadata
                .resolved_routing_policy
                .context("held frozen policy")?;
            let prior = crate::supervise::prior_input::captured_binding();
            thread::scope(|scope| -> Result<()> {
                scope
                    .spawn(move || -> Result<()> {
                        let _cam = install_captured_cam_observe_test_harness(Some(captured));
                        let _prior = crate::supervise::prior_input::install_captured(prior);
                        let _policy =
                            crate::selection::routing_policy::bind_routing_policy(Some(frozen))?;
                        let observed =
                            account_observation_for_launch_runtime(SupervisorRuntime::Codex, None)?
                                .context("current selected account after capture")?;
                        assert_eq!(observed.binding.provider_id, expected.provider_id);
                        assert_eq!(observed.binding.account_id, "changed");
                        assert_ne!(
                            observed.binding.account_incarnation,
                            expected.account_incarnation
                        );
                        assert_ne!(
                            observed.binding.selection_revision,
                            expected.selection_revision
                        );
                        assert_eq!(
                            super::super::super::selection_bridge::frozen_review_account_binding(
                                SupervisorRuntime::Codex,
                                run.as_str(),
                            )?,
                            Some(expected)
                        );
                        let error =
                            super::super::super::selection_bridge::select_authored_review_lens(
                                &lens,
                                &effort,
                                SupervisorRuntime::Codex,
                                supplied_catalog,
                                &baseline.provenance,
                                super::super::super::selection_bridge::ReviewLensAccount::Selected {
                                    observation: &observed, expected_binding: &expected_account,
                                },
                                SupervisorQuotaSelectionInput::default(),
                            )
                            .err()
                            .context("registry drift must refuse the frozen review contract")?;
                        assert_eq!(
                            error.to_string(),
                            "review lens selected account changed from the frozen run binding"
                        );
                        Ok(())
                    })
                    .join()
                    .map_err(|_| anyhow!("drift observation child panicked"))??;
                Ok(())
            })
        }

        #[test]
        fn prepared_local_fake_selection_avoids_discovery_and_account_freezing() -> Result<()> {
            use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;

            let (_temporary, repo, _, admission, mut plan, mut metadata) =
                prepared_selection_fixture()?;
            let absent_socket = repo.join("absent-authority.sock");
            assert!(!absent_socket.exists());
            let _socket = CamAuthoritySocketTestGuard::install(Some(absent_socket.as_os_str()));
            let run = RunId::new("prepared-local-fake-no-authority")?;
            let catalog = Ok(RuntimeModelCatalog::LocalDeterministicFake);
            plan.assignments = vec![super::terminal_worker_assignment("fake-worker")];
            let original_lenses = plan.review_lenses.clone();
            for authored_runtime in [None, Some(SupervisorRuntime::Fake)] {
                plan.assignments[0].runtime = authored_runtime;
                let mut request = prepared_codex_request(&repo, &catalog, &admission);
                request.runtime = SupervisorRuntime::Fake;
                request.current_run = Some(&run);
                // Verified is the production experiment entrypoint, not the
                // legacy nonpublishable-simulation shortcut used by unit helpers.
                let resolution = initialize_supervisor_selection_with_catalog_discovery(
                    &mut plan,
                    &mut metadata,
                    request,
                    |_| bail!("local Fake must not discover real catalogs"),
                )?;
                assert_eq!(resolution.mode, SupervisorSelectionMode::LegacyFake);
                assert!(resolution.selection_preflight_failure.is_none());
                assert!(resolution.decisions.is_empty());
                assert!(resolution.automatic_state.is_none());
                assert_eq!(plan.assignments[0].runtime, authored_runtime);
                assert_eq!(plan.review_lenses, original_lenses);
                assert!(metadata.resolved_routing_policy.is_some());
                assert!(metadata.resolved_objective_profile.is_some());
                let controller = BudgetDegradationController::new_with_selection_state(
                    1,
                    resolution.automatic_state,
                    SupervisorRuntime::Fake,
                )?;
                for role in [AgentRole::Worker, AgentRole::Auditor] {
                    assert!(controller.policy.selected_runtime_for(role).is_none());
                }
                assert!(
                    crate::account_authority::codex_run_account_binding(run.as_str()).is_none()
                );
                assert!(
                    crate::account_authority::claude_run_account_binding(run.as_str()).is_none()
                );
                assert!(crate::account_authority::grok_run_account_binding(run.as_str()).is_none());
                assert!(
                    crate::account_authority::gemini_run_account_binding(run.as_str()).is_none()
                );
                assert!(
                    crate::account_authority::cursor_run_account_binding(run.as_str()).is_none()
                );
            }
            Ok(())
        }

        #[test]
        fn prepared_fake_real_runtime_overrides_retain_catalog_discovery_errors() -> Result<()> {
            let (_temporary, repo, _, admission, mut plan, mut metadata) =
                prepared_selection_fixture()?;
            plan.assignments = vec![super::terminal_worker_assignment("mixed-worker")];
            let catalog = Ok(RuntimeModelCatalog::LocalDeterministicFake);
            for authored_runtime in [
                SupervisorRuntime::Codex,
                SupervisorRuntime::Grok,
                SupervisorRuntime::Cursor,
                SupervisorRuntime::ClaudeCode,
                SupervisorRuntime::GeminiCli,
            ] {
                plan.assignments[0].runtime = Some(authored_runtime);
                let mut request = prepared_codex_request(&repo, &catalog, &admission);
                request.runtime = SupervisorRuntime::Fake;
                let error = initialize_supervisor_selection_with_catalog_discovery(
                    &mut plan,
                    &mut metadata,
                    request,
                    |_| bail!("real catalog discovery refused"),
                )
                .expect_err("an authored real executor must retain discovery failure");
                assert_eq!(error.to_string(), "real catalog discovery refused");
                assert_eq!(plan.assignments[0].runtime, Some(authored_runtime));
            }
            // Neither a real primary executor nor a non-local acquired catalog
            // qualifies, even when assignment runtimes are unspecified.
            plan.assignments[0].runtime = None;
            for (runtime, catalog) in [
                (
                    SupervisorRuntime::Codex,
                    RuntimeModelCatalog::LocalDeterministicFake,
                ),
                (
                    SupervisorRuntime::Fake,
                    RuntimeModelCatalog::OperatorDeclared,
                ),
            ] {
                let catalog = Ok(catalog);
                let mut request = prepared_codex_request(&repo, &catalog, &admission);
                request.runtime = runtime;
                let error = initialize_supervisor_selection_with_catalog_discovery(
                    &mut plan,
                    &mut metadata,
                    request,
                    |_| bail!("real catalog discovery refused"),
                )
                .expect_err("Fake runtime and acquired local catalog are both required");
                assert_eq!(error.to_string(), "real catalog discovery refused");
            }
            Ok(())
        }

        #[test]
        fn codex_scheduler_observation_and_secondary_selection_are_frozen_per_run() -> Result<()> {
            use crate::account_authority::{codex_run_account_binding, CodexRunAccountBinding};
            let _guard = activate_stub(true, SchedulerObserveStubMode::ObservedModels);
            let run = "synthetic-codex-primary-observed";
            let observation =
                account_observation_for_launch_runtime(SupervisorRuntime::Codex, Some(run))?
                    .context("selected synthetic account")?;
            let Some(CodexRunAccountBinding::Selected(frozen)) = codex_run_account_binding(run)
            else {
                panic!("Codex primary observation did not freeze its selected account");
            };
            assert_eq!(frozen.to_selected_binding(), observation.binding);
            freeze_selected_codex_launch_binding(Some(run))?;
            assert_eq!(
                codex_run_account_binding(run),
                Some(CodexRunAccountBinding::Selected(frozen.clone()))
            );
            let nested_run = "synthetic-codex-secondary-selected";
            freeze_selected_codex_launch_binding(Some(nested_run))?;
            assert_eq!(
                codex_run_account_binding(nested_run),
                Some(CodexRunAccountBinding::Selected(frozen))
            );
            Ok(())
        }

        #[test]
        fn local_auth_codex_scheduler_keeps_primary_with_only_grok_observed() -> Result<()> {
            use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;
            use crate::account_authority::{codex_run_account_binding, CodexRunAccountBinding};

            let _socket = CamAuthoritySocketTestGuard::install(None);
            let (root, registry) = isolated_registry();
            registry.begin_add(
                "grok-cli",
                "work",
                "Synthetic Grok account",
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )?;
            registry.complete_add("grok-cli", "work")?;
            registry.select_complete_revision("grok-cli", "work", None)?;
            let grok_prior = crate::selection::built_in_prior_dataset()?
                .models
                .into_iter()
                .find(|prior| prior.runtime == "grok" && !prior.prohibited)
                .context("synthetic Grok prior")?;
            let _guard = activate_cam_observe_test_harness(CamObserveTestHarness {
                registry,
                adapter: Box::new(SchedulerObserveStub {
                    id: "codex-cli",
                    mode: SchedulerObserveStubMode::ObservedModels,
                }),
                secondary_adapter: Some(Box::new(SchedulerObserveStub {
                    id: "grok-cli",
                    mode: SchedulerObserveStubMode::ObservedSynthetic(
                        synthetic_prior_observed_model(&grok_prior),
                    ),
                })),
                advertised: None,
                resolved_auditor: None,
                _root: root,
            });
            let run = RunId::new("r10-local-auth-codex-with-grok")?;
            let observations =
                account_observations_for_selection(SupervisorRuntime::Codex, Some(run.as_str()))?;
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].0, SupervisorRuntime::Grok);
            assert_eq!(
                codex_run_account_binding(run.as_str()),
                Some(CodexRunAccountBinding::LocalAuth)
            );

            let (_temporary, repo, catalog, admission, mut plan, mut metadata) =
                prepared_selection_fixture()?;
            plan.assignments = vec![super::terminal_worker_assignment("local-auth-worker")];
            plan.assignments[0].role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
            let _policy =
                crate::supervise::bind_assessed_injected_plan(&plan, &repo, &mut metadata)?;
            let mut request = prepared_codex_request(&repo, &catalog, &admission);
            request.current_run = Some(&run);
            let resolution = initialize_supervisor_selection_with_catalog_discovery(
                &mut plan,
                &mut metadata,
                request,
                |_| Ok(AdvertisedCatalogSet::empty()),
            )?;
            assert!(resolution.selection_preflight_failure.is_none());
            assert_eq!(plan.assignments[0].runtime, Some(SupervisorRuntime::Codex));
            assert!(resolution.decisions.iter().all(|event| {
                event.provenance.normalized_input.catalogs.len() == 1
                    && event.provenance.normalized_input.catalogs[0].runtime == "codex"
                    && event.provenance.choice.as_ref().unwrap().candidate.runtime == "codex"
            }));
            assert_eq!(
                codex_run_account_binding(run.as_str()),
                Some(CodexRunAccountBinding::LocalAuth)
            );
            Ok(())
        }

        #[test]
        fn codex_scheduler_missing_local_selection_freezes_local_auth() -> Result<()> {
            use crate::account_authority::{codex_run_account_binding, CodexRunAccountBinding};
            let _guard = activate_stub(false, SchedulerObserveStubMode::ObservedModels);
            let run = "synthetic-codex-secondary-missing";
            freeze_selected_codex_launch_binding(Some(run))?;
            assert_eq!(
                codex_run_account_binding(run),
                Some(CodexRunAccountBinding::LocalAuth)
            );
            assert!(codex_run_account_binding("synthetic-never-initialized-codex").is_none());
            Ok(())
        }

        #[test]
        fn absent_implicit_cam_scheduler_observation_uses_local_registry() -> Result<()> {
            use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;
            use crate::account_authority::{codex_run_account_binding, CodexRunAccountBinding};

            let runtime = tempfile::tempdir()?;
            let _socket = CamAuthoritySocketTestGuard::install_default(
                runtime.path().join("maco/account-authority.sock"),
            );
            assert!(crate::account_authority::configured_cam_authority_socket().is_none());
            let _selected = activate_stub(true, SchedulerObserveStubMode::ObservedModels);
            let run = "r9-scheduler-local-selected";
            let observation =
                account_observation_for_launch_runtime(SupervisorRuntime::Codex, Some(run))?
                    .context("local registry selection")?;
            let Some(CodexRunAccountBinding::Selected(frozen)) = codex_run_account_binding(run)
            else {
                panic!("local selection was not frozen");
            };
            assert_eq!(frozen.to_selected_binding(), observation.binding);
            assert!(frozen.authority_socket.is_none());
            let _empty = activate_stub(false, SchedulerObserveStubMode::ObservedModels);
            let run = "r9-scheduler-local-empty";
            assert!(
                account_observation_for_launch_runtime(SupervisorRuntime::Codex, Some(run))?
                    .is_none()
            );
            freeze_selected_codex_launch_binding(Some(run))?;
            assert_eq!(
                codex_run_account_binding(run),
                Some(CodexRunAccountBinding::LocalAuth)
            );
            Ok(())
        }

        #[test]
        fn configured_cam_scheduler_observation_refuses_missing_or_unsafe_endpoint() -> Result<()> {
            use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;

            let runtime = tempfile::tempdir()?;
            let socket = runtime.path().join("maco/account-authority.sock");
            {
                let _explicit = CamAuthoritySocketTestGuard::install(Some(socket.as_os_str()));
                assert!(
                    account_observation_for_launch_runtime(SupervisorRuntime::Codex, None).is_err()
                );
                assert!(
                    freeze_selected_codex_launch_binding(Some("r9-explicit-missing-freeze"))
                        .is_err()
                );
            }
            fs::create_dir(socket.parent().unwrap())?;
            std::os::unix::fs::symlink("missing.sock", &socket)?;
            let _default = CamAuthoritySocketTestGuard::install_default(socket);
            assert!(
                account_observation_for_launch_runtime(SupervisorRuntime::Codex, None).is_err()
            );
            assert!(
                freeze_selected_codex_launch_binding(Some("r9-implicit-unsafe-freeze")).is_err()
            );
            Ok(())
        }

        #[test]
        fn socket_source_cannot_be_overwritten_by_local_reobservation() -> Result<()> {
            use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;

            let root = tempfile::tempdir()?;
            let socket = root.path().join("maco/account-authority.sock");
            let _socket = CamAuthoritySocketTestGuard::install_default(socket.clone());
            for runtime in [
                SupervisorRuntime::Codex,
                SupervisorRuntime::Grok,
                SupervisorRuntime::GeminiCli,
                SupervisorRuntime::ClaudeCode,
                SupervisorRuntime::Cursor,
            ] {
                let provider = cam_provider_id_for_supervisor_runtime(runtime).unwrap();
                let run = format!("r9-socket-reobserve-{provider}");
                let binding = coding_agent_manager_lib::account_authority::SelectedAccountBinding {
                    provider_id: provider.into(),
                    account_id: "synthetic".into(),
                    account_incarnation: "synthetic-incarnation".into(),
                    selection_revision: 1,
                };
                record_observed_managed_selection(
                    Some(&run),
                    provider,
                    Some("synthetic-authority".into()),
                    Some(&binding),
                    Some(&socket),
                );
                let error =
                    account_observation_for_launch_runtime(runtime, Some(&run)).unwrap_err();
                assert!(format!("{error:#}").contains("refusing local fallback"));
                assert!(
                    crate::account_authority::cam_socket_for_run_selection(&run, provider).is_err()
                );
            }
            Ok(())
        }

        fn secondary_command(
            runtime: SupervisorRuntime,
            run: &str,
            task: &str,
        ) -> ExternalAgentCommand {
            secondary_role_command(runtime, AgentRole::Worker, run, task)
        }

        fn secondary_role_command(
            runtime: SupervisorRuntime,
            role: AgentRole,
            run: &str,
            task: &str,
        ) -> ExternalAgentCommand {
            let adapter = match runtime {
                SupervisorRuntime::Grok => crate::runtime_adapter::RuntimeId::Grok,
                SupervisorRuntime::GeminiCli => crate::runtime_adapter::RuntimeId::GeminiCli,
                SupervisorRuntime::Cursor => crate::runtime_adapter::RuntimeId::Cursor,
                _ => panic!("secondary fixture requires a managed adapter"),
            };
            // This is the same adapter/lifecycle construction used by ordinary and
            // nested assignment callers; no account is supplied to the command.
            ExternalAgentCommand::codex(
                "unused-provider",
                "/workspace",
                "prompt",
                "log",
                "report",
                Duration::from_secs(1),
            )
            .with_runtime_adapter(
                adapter,
                crate::runtime_adapter::RuntimeAdapterConfig::defaults(adapter),
            )
            .with_agent_lifecycle("/workspace", role.as_str(), run, task)
        }

        #[test]
        fn scheduler_initialization_carries_secondary_grok_to_ordinary_and_nested_commands(
        ) -> Result<()> {
            use crate::runtime_adapter::grok::{
                inject_grok_advertised_catalog, GrokModelCatalog, GrokModelCatalogEntry,
            };
            let (root, registry) = isolated_registry();
            seed_complete_account(&registry, true);
            registry.begin_add(
                "grok-cli",
                "work",
                "Work",
                AuthKind::OAuth,
                StoredAccountMaterial::VendorHome,
            )?;
            registry.complete_add("grok-cli", "work")?;
            registry.select_complete_revision("grok-cli", "work", None)?;
            let expected = registry
                .selected_binding("grok-cli")?
                .context("selected Grok fixture")?;
            let authority = authority_id_for(registry.metadata_path());
            let grok_prior = crate::selection::built_in_prior_dataset()?
                .models
                .into_iter()
                .find(|prior| prior.runtime == "grok" && !prior.prohibited)
                .context("synthetic advertised Grok prior")?;
            let advertised = inject_grok_advertised_catalog(
                GrokModelCatalog::from_injected_entries([GrokModelCatalogEntry::new(
                    grok_prior.model.clone(),
                    "Synthetic Worker",
                )?])?,
                Some(1_787_240_463_000),
                b"synthetic-secondary-grok-catalog",
            )?;
            let _guard = activate_cam_observe_test_harness(CamObserveTestHarness {
                registry,
                // Both isolated selected accounts use their exact provider's
                // nonlive menu through normal Core observation and validation.
                adapter: Box::new(SchedulerObserveStub {
                    id: "codex-cli",
                    mode: SchedulerObserveStubMode::ObservedModels,
                }),
                secondary_adapter: Some(Box::new(SchedulerObserveStub {
                    id: "grok-cli",
                    mode: SchedulerObserveStubMode::ObservedSynthetic(
                        synthetic_prior_observed_model(&grok_prior),
                    ),
                })),
                advertised: Some(AdvertisedCatalogSet::with_grok(advertised)),
                resolved_auditor: None,
                _root: root,
            });
            let (_temporary, repo, catalog, admission, mut plan, mut metadata) =
                prepared_selection_fixture()?;
            let mut worker = super::terminal_worker_assignment("ordinary-secondary");
            worker.role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
            worker.assigned_paths = vec![PathBuf::from("tests/ordinary-secondary.txt")];
            let mut parent = super::terminal_worker_assignment("parent-secondary");
            parent.role = AgentRole::ChildOrchestrator;
            parent.worker_assignments = vec![serde_json::from_value(serde_json::json!({
                "id": "nested-secondary", "assigned_paths": [SELECTOR_TEST_TARGET]
            }))?];
            plan.assignments = vec![worker, parent];
            plan.max_child_assignments = plan.assignments.len();
            let _routing_policy =
                crate::supervise::bind_assessed_injected_plan(&plan, &repo, &mut metadata)?;
            let available = initialize_supervisor_selection_from_prepared_metadata(
                &mut plan,
                &mut metadata,
                prepared_codex_request(&repo, &catalog, &admission),
            )?;
            assert!(available.selection_preflight_failure.is_none());
            let candidate = available
                .decisions
                .iter()
                .find(|event| event.role == AgentRole::Worker)
                .and_then(|event| {
                    event.provenance.candidate_set.iter().find(|candidate| {
                        candidate.eligible && candidate.candidate.runtime == "grok"
                    })
                })
                .context("eligible synthetic Grok Worker candidate")?
                .candidate
                .clone();
            plan.assignments[0].runtime = Some(SupervisorRuntime::Grok);
            plan.role_models.clear();
            plan.role_models.insert(
                AgentRole::Worker,
                super::role_selection(&candidate.model, selector_effort_as_str(candidate.effort)),
            );
            let run = RunId::new("synthetic-secondary-grok-initialized")?;
            let before =
                secondary_command(SupervisorRuntime::Grok, run.as_str(), "ordinary-secondary");
            assert!(before
                .verify_grok_run_account_binding(run.as_str())
                .is_err());
            let mut request = prepared_codex_request(&repo, &catalog, &admission);
            request.current_run = Some(&run);
            let resolution = initialize_supervisor_selection_from_prepared_metadata(
                &mut plan,
                &mut metadata,
                request,
            )?;
            assert!(
                resolution.selection_preflight_failure.is_none(),
                "{:?}",
                resolution.selection_preflight_failure
            );
            assert_eq!(plan.assignments[0].runtime, Some(SupervisorRuntime::Grok));
            let frozen = crate::account_authority::grok_run_account_binding(run.as_str())
                .context("initialized secondary Grok")?;
            assert_eq!(frozen.to_selected_binding(), expected);
            assert_eq!(frozen.authority_id.as_deref(), Some(authority.as_str()));
            for task in ["ordinary-secondary", "nested-secondary"] {
                let command = secondary_command(SupervisorRuntime::Grok, run.as_str(), task);
                command.verify_grok_run_account_binding(run.as_str())?;
                assert_eq!(
                    command
                        .clone()
                        .with_grok_run_account_binding(Some(frozen.clone())),
                    command
                );
                assert!(command
                    .verify_grok_run_account_binding("synthetic-other-run")
                    .is_err());
            }
            // The same resolved Worker choice must also initialize a nested-only
            // run: there is no top-level Grok assignment in this projection.
            plan.assignments.remove(0);
            let nested_run = "synthetic-secondary-grok-nested-only";
            freeze_selected_secondary_managed_launch_bindings(
                &plan,
                &resolution.decisions,
                SupervisorRuntime::Codex,
                Some(nested_run),
            )?;
            secondary_command(SupervisorRuntime::Grok, nested_run, "nested-secondary")
                .verify_grok_run_account_binding(nested_run)?;
            assert_eq!(
                crate::account_authority::grok_run_account_binding(nested_run),
                Some(frozen)
            );
            assert!(crate::account_authority::gemini_run_account_binding(run.as_str()).is_none());
            assert!(crate::account_authority::cursor_run_account_binding(run.as_str()).is_none());
            Ok(())
        }

        #[test]
        fn scheduler_secondary_metadata_preserves_identity_and_refuses_missing_selection(
        ) -> Result<()> {
            {
                let _guard = activate_stub(true, SchedulerObserveStubMode::ObservedModels);
                let (_temporary, repo, catalog, admission, mut plan, mut metadata) =
                    prepared_selection_fixture()?;
                let mut worker = super::terminal_worker_assignment("codex-reviewed-worker");
                worker.runtime = Some(SupervisorRuntime::Codex);
                worker.role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
                plan.assignments = vec![worker];
                let _routing_policy =
                    crate::supervise::bind_assessed_injected_plan(&plan, &repo, &mut metadata)?;
                let initial = initialize_supervisor_selection_from_prepared_metadata(
                    &mut plan,
                    &mut metadata,
                    prepared_codex_request(&repo, &catalog, &admission),
                )?;
                assert!(initial.selection_preflight_failure.is_none());
                let mut auditor = initial
                    .decisions
                    .iter()
                    .find(|decision| decision.role == AgentRole::Auditor)
                    .context("resolved Auditor fixture")?
                    .clone();
                // Only the resolved routing result is synthetic. This exercises
                // initialization and the parent's real automatic budget-policy
                // consumer, not Gemini catalog/provider acceptance.
                auditor
                    .provenance
                    .choice
                    .as_mut()
                    .context("Auditor choice")?
                    .candidate
                    .runtime = "gemini-cli".to_string();
                // Nonlive transport menu only: retain the assessed choice's model
                // and effort without asserting Gemini capability or entitlement.
                let candidate = &auditor
                    .provenance
                    .choice
                    .as_ref()
                    .context("Auditor choice for synthetic transport menu")?
                    .candidate;
                let synthetic_transport_menu = ObservedModel {
                    model_id: candidate.model.clone(),
                    supported_efforts: Some(vec![candidate.effort.as_str().to_string()]),
                    default_effort: Some(candidate.effort.as_str().to_string()),
                    access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                };
                let expected = CAM_OBSERVE_TEST_OVERRIDE.with(|cell| -> Result<_> {
                    let mut cell = cell.borrow_mut();
                    let harness = Arc::get_mut(cell.as_mut().unwrap())
                        .context("CAM fixture setup requires exclusive observer custody")?;
                    harness.registry.begin_add(
                        "gemini-cli",
                        "review",
                        "Review",
                        AuthKind::OAuth,
                        StoredAccountMaterial::VendorHome,
                    )?;
                    harness.registry.complete_add("gemini-cli", "review")?;
                    harness
                        .registry
                        .select_complete_revision("gemini-cli", "review", None)?;
                    harness.secondary_adapter = Some(Box::new(SchedulerObserveStub {
                        id: "gemini-cli",
                        mode: SchedulerObserveStubMode::ObservedSynthetic(
                            synthetic_transport_menu.clone(),
                        ),
                    }));
                    harness.resolved_auditor = Some(auditor);
                    Ok((
                        authority_id_for(harness.registry.metadata_path()),
                        harness
                            .registry
                            .selected_binding("gemini-cli")?
                            .context("selected Gemini Auditor")?,
                    ))
                })?;
                let run = RunId::new("synthetic-codex-worker-gemini-parent-auditor")?;
                assert!(
                    crate::account_authority::gemini_run_account_binding(run.as_str()).is_none()
                );
                assert!(
                    crate::account_authority::require_carried_gemini_launch_binding(None, true)
                        .is_err()
                );
                plan.role_models.clear();
                plan.review_lenses = default_supervisor_review_lenses();
                let mut request = prepared_codex_request(&repo, &catalog, &admission);
                request.current_run = Some(&run);
                let resolution = initialize_supervisor_selection_from_prepared_metadata(
                    &mut plan,
                    &mut metadata,
                    request,
                )?;
                assert!(resolution.selection_preflight_failure.is_none());
                assert_eq!(plan.assignments[0].runtime, Some(SupervisorRuntime::Codex));
                let controller = BudgetDegradationController::new_with_selection_state(
                    1,
                    resolution.automatic_state,
                    SupervisorRuntime::Codex,
                )?;
                let launch_runtime = controller
                    .policy
                    .selected_runtime_for(AgentRole::Auditor)
                    .unwrap_or(SupervisorRuntime::Codex);
                assert_eq!(launch_runtime, SupervisorRuntime::GeminiCli);
                let frozen = crate::account_authority::gemini_run_account_binding(run.as_str())
                    .context("initialized parent Auditor binding")?;
                assert_eq!(frozen.to_selected_binding(), expected.1);
                assert_eq!(frozen.authority_id.as_deref(), Some(expected.0.as_str()));
                let active_plan = controller.policy.apply(&plan);
                assert_eq!(
                    active_plan.review_lenses.len(),
                    default_supervisor_review_lenses().len()
                );
                for (index, lens) in active_plan.review_lenses.iter().enumerate() {
                    let command = secondary_role_command(
                        launch_runtime,
                        AgentRole::Auditor,
                        run.as_str(),
                        &format!("parent-lens-{index}"),
                    )
                    .with_model_selection(
                        Some(lens.backend.model().to_string()),
                        lens.backend.reasoning_effort().map(str::to_string),
                    )
                    .with_agent_parent("codex-reviewed-worker");
                    assert_eq!(
                        command
                            .clone()
                            .with_gemini_run_account_binding(Some(frozen.clone())),
                        command
                    );
                    assert_eq!(
                        crate::account_authority::require_carried_gemini_launch_binding(
                            Some(&frozen),
                            true
                        )?,
                        Some(&frozen)
                    );
                }
                assert!(crate::account_authority::grok_run_account_binding(run.as_str()).is_none());
                assert!(
                    crate::account_authority::cursor_run_account_binding(run.as_str()).is_none()
                );
                let empty_run = "synthetic-gemini-auditor-without-assignment";
                freeze_selected_secondary_managed_launch_bindings(
                    &super::test_plan(),
                    &resolution.decisions,
                    SupervisorRuntime::Codex,
                    Some(empty_run),
                )?;
                assert!(crate::account_authority::gemini_run_account_binding(empty_run).is_none());
                let mut no_lenses = plan.clone();
                no_lenses.review_lenses.clear();
                let unused_run = "synthetic-gemini-auditor-without-lenses";
                freeze_selected_secondary_managed_launch_bindings(
                    &no_lenses,
                    &resolution.decisions,
                    SupervisorRuntime::Codex,
                    Some(unused_run),
                )?;
                assert!(crate::account_authority::gemini_run_account_binding(unused_run).is_none());
                let mut unlaunched_roles = resolution.decisions.clone();
                unlaunched_roles.retain(|decision| decision.role != AgentRole::Auditor);
                for decision in &mut unlaunched_roles {
                    if matches!(
                        decision.role,
                        AgentRole::Supervisor | AgentRole::GateClassifier
                    ) {
                        decision
                            .provenance
                            .choice
                            .as_mut()
                            .context("unused role choice")?
                            .candidate
                            .runtime = "gemini-cli".to_string();
                    }
                }
                let unchosen_run = "synthetic-secondary-unused-selector-roles";
                freeze_selected_secondary_managed_launch_bindings(
                    &plan,
                    &unlaunched_roles,
                    SupervisorRuntime::Codex,
                    Some(unchosen_run),
                )?;
                assert!(
                    crate::account_authority::gemini_run_account_binding(unchosen_run).is_none()
                );
                let _missing = activate_stub(false, SchedulerObserveStubMode::ObserveError);
                CAM_OBSERVE_TEST_OVERRIDE.with(|cell| -> Result<()> {
                    let mut cell = cell.borrow_mut();
                    let harness = Arc::get_mut(cell.as_mut().unwrap())
                        .context("CAM fixture setup requires exclusive observer custody")?;
                    harness.resolved_auditor = resolution
                        .decisions
                        .iter()
                        .find(|decision| decision.role == AgentRole::Auditor)
                        .cloned();
                    Ok(())
                })?;
                let missing_run = RunId::new("synthetic-gemini-parent-auditor-missing-account")?;
                plan.role_models.clear();
                plan.review_lenses = default_supervisor_review_lenses();
                let mut request = prepared_codex_request(&repo, &catalog, &admission);
                request.current_run = Some(&missing_run);
                let error = initialize_supervisor_selection_from_prepared_metadata(
                    &mut plan,
                    &mut metadata,
                    request,
                )
                .expect_err("missing parent Auditor account must refuse at initialization");
                assert!(error
                    .to_string()
                    .contains("no complete selected Coding Agent Manager account"));
                assert!(
                    crate::account_authority::gemini_run_account_binding(missing_run.as_str())
                        .is_none()
                );
            }
            for runtime in [
                SupervisorRuntime::Grok,
                SupervisorRuntime::GeminiCli,
                SupervisorRuntime::Cursor,
            ] {
                let provider = cam_provider_id_for_supervisor_runtime(runtime).unwrap();
                let (root, registry) = isolated_registry();
                registry.begin_add(
                    provider,
                    "work",
                    "Work",
                    AuthKind::OAuth,
                    StoredAccountMaterial::VendorHome,
                )?;
                registry.complete_add(provider, "work")?;
                registry.select_complete_revision(provider, "work", None)?;
                let expected = registry
                    .selected_binding(provider)?
                    .context("selected fixture")?;
                let authority = authority_id_for(registry.metadata_path());
                let _guard = activate_cam_observe_test_harness(CamObserveTestHarness {
                    registry,
                    secondary_adapter: None,
                    adapter: Box::new(SchedulerObserveStub {
                        id: "codex-cli",
                        mode: SchedulerObserveStubMode::ObserveError,
                    }),
                    advertised: None,
                    resolved_auditor: None,
                    _root: root,
                });
                let run = format!("synthetic-secondary-{}", runtime_name(runtime));
                let mut plan = super::test_plan();
                let mut assignment = super::terminal_worker_assignment("secondary-worker");
                assignment.runtime = Some(runtime);
                plan.assignments.push(assignment);
                let before = secondary_command(runtime, &run, "secondary-worker");
                freeze_selected_secondary_managed_launch_bindings(
                    &plan,
                    &[],
                    SupervisorRuntime::Codex,
                    Some(&run),
                )?;
                let carried = secondary_command(runtime, &run, "secondary-worker");
                assert_ne!(before, carried);
                let selected = match runtime {
                    SupervisorRuntime::Grok => {
                        carried.verify_grok_run_account_binding(&run)?;
                        let frozen =
                            crate::account_authority::grok_run_account_binding(&run).unwrap();
                        assert_eq!(frozen.authority_id.as_deref(), Some(authority.as_str()));
                        frozen.to_selected_binding()
                    }
                    SupervisorRuntime::GeminiCli => {
                        let frozen =
                            crate::account_authority::gemini_run_account_binding(&run).unwrap();
                        assert_eq!(frozen.authority_id.as_deref(), Some(authority.as_str()));
                        crate::account_authority::require_carried_gemini_launch_binding(
                            Some(&frozen),
                            false,
                        )?;
                        assert_eq!(
                            carried
                                .clone()
                                .with_gemini_run_account_binding(Some(frozen.clone())),
                            carried
                        );
                        frozen.to_selected_binding()
                    }
                    SupervisorRuntime::Cursor => {
                        let frozen =
                            crate::account_authority::cursor_run_account_binding(&run).unwrap();
                        assert_eq!(frozen.authority_id.as_deref(), Some(authority.as_str()));
                        frozen.to_selected_binding()
                    }
                    _ => unreachable!(),
                };
                assert_eq!(selected, expected);
                CAM_OBSERVE_TEST_OVERRIDE.with(|cell| -> Result<()> {
                    let cell = cell.borrow();
                    let registry = &cell.as_ref().unwrap().registry;
                    registry.begin_add(
                        provider,
                        "other",
                        "Other",
                        AuthKind::OAuth,
                        StoredAccountMaterial::VendorHome,
                    )?;
                    registry.complete_add(provider, "other")?;
                    registry.select_complete_revision(provider, "other", None)?;
                    assert_ne!(
                        registry.selected_binding(provider)?.as_ref(),
                        Some(&expected)
                    );
                    Ok(())
                })?;
                freeze_selected_secondary_managed_launch_bindings(
                    &plan,
                    &[],
                    SupervisorRuntime::Codex,
                    Some(&run),
                )?;
                assert_eq!(
                    secondary_command(runtime, &run, "secondary-worker"),
                    carried
                );
                drop(_guard);

                let (root, registry) = isolated_registry();
                // Incomplete metadata is not a selected account and cannot authorize launch.
                registry.begin_add(
                    provider,
                    "pending",
                    "Pending",
                    AuthKind::OAuth,
                    StoredAccountMaterial::VendorHome,
                )?;
                let _missing = activate_cam_observe_test_harness(CamObserveTestHarness {
                    registry,
                    secondary_adapter: None,
                    adapter: Box::new(SchedulerObserveStub {
                        id: "codex-cli",
                        mode: SchedulerObserveStubMode::ObserveError,
                    }),
                    advertised: None,
                    resolved_auditor: None,
                    _root: root,
                });
                let missing_run = format!("synthetic-secondary-missing-{}", runtime_name(runtime));
                let error = freeze_selected_secondary_managed_launch_bindings(
                    &plan,
                    &[],
                    SupervisorRuntime::Codex,
                    Some(&missing_run),
                )
                .expect_err("missing selected secondary must refuse before command construction");
                assert!(error
                    .to_string()
                    .contains("no complete selected Coding Agent Manager account"));
                assert_eq!(
                    secondary_command(runtime, &missing_run, "secondary-worker"),
                    before.with_agent_lifecycle(
                        "/workspace",
                        "worker",
                        &missing_run,
                        "secondary-worker"
                    )
                );
                // A selected-but-unchosen runtime never creates a slot for this run.
                CAM_OBSERVE_TEST_OVERRIDE.with(|cell| -> Result<()> {
                    let cell = cell.borrow();
                    let registry = &cell.as_ref().unwrap().registry;
                    registry.complete_add(provider, "pending")?;
                    registry.select_complete_revision(provider, "pending", None)?;
                    assert!(registry.selected_binding(provider)?.is_some());
                    Ok(())
                })?;
                let unchosen_run =
                    format!("synthetic-secondary-unchosen-{}", runtime_name(runtime));
                freeze_selected_secondary_managed_launch_bindings(
                    &super::test_plan(),
                    &[],
                    SupervisorRuntime::Codex,
                    Some(&unchosen_run),
                )?;
                match runtime {
                    SupervisorRuntime::Grok => assert!(
                        crate::account_authority::grok_run_account_binding(&unchosen_run).is_none()
                    ),
                    SupervisorRuntime::GeminiCli => assert!(
                        crate::account_authority::gemini_run_account_binding(&unchosen_run)
                            .is_none()
                    ),
                    SupervisorRuntime::Cursor => assert!(
                        crate::account_authority::cursor_run_account_binding(&unchosen_run)
                            .is_none()
                    ),
                    _ => unreachable!(),
                }
            }
            Ok(())
        }

        #[test]
        fn cam_provider_id_maps_supervisor_runtime_and_fake_stays_none() {
            assert_eq!(
                cam_provider_id_for_supervisor_runtime(SupervisorRuntime::Grok),
                Some("grok-cli")
            );
            assert_eq!(
                cam_provider_id_for_supervisor_runtime(SupervisorRuntime::Codex),
                Some("codex-cli")
            );
            assert_eq!(
                cam_provider_id_for_supervisor_runtime(SupervisorRuntime::GeminiCli),
                Some("gemini-cli")
            );
            assert_eq!(
                cam_provider_id_for_supervisor_runtime(SupervisorRuntime::ClaudeCode),
                Some("claude-code")
            );
            assert_eq!(
                cam_provider_id_for_supervisor_runtime(SupervisorRuntime::Cursor),
                Some("cursor")
            );
            assert_eq!(
                cam_provider_id_for_supervisor_runtime(SupervisorRuntime::Fake),
                None
            );
        }

        #[test]
        fn scheduler_account_observe_admits_observed_models() -> Result<()> {
            let _guard = activate_stub(true, SchedulerObserveStubMode::ObservedModels);
            let observation =
                account_observation_for_launch_runtime(SupervisorRuntime::Codex, None)?
                    .context("selected CAM binding must produce Some observation")?;
            assert_eq!(observation.binding.provider_id, "codex-cli");
            let models = observation.models.as_ref().context("models category")?;
            assert_eq!(models.outcome, ObservationOutcome::Observed);
            let quota = observation.quota.as_ref().context("quota category")?;
            assert_eq!(quota.outcome, ObservationOutcome::Unknown);
            assert!(quota.content.is_none());
            let json = serde_json::to_string(&observation)?;
            assert!(!json.contains("utilization"));

            let (temporary, repo, catalog, admission, mut plan, mut plan_metadata) =
                prepared_selection_fixture()?;
            plan.assignments = vec![super::terminal_worker_assignment("observed-model-worker")];
            plan.assignments[0].role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
            let _routing_policy =
                crate::supervise::bind_assessed_injected_plan(&plan, &repo, &mut plan_metadata)?;
            let resolution = initialize_supervisor_selection_from_prepared_metadata(
                &mut plan,
                &mut plan_metadata,
                prepared_codex_request(&repo, &catalog, &admission),
            )?;
            assert!(resolution.selection_preflight_failure.is_none());
            let worker = resolution
                .decisions
                .iter()
                .find(|event| event.role == AgentRole::Worker)
                .context("worker decision")?;
            assert_eq!(worker.provenance.normalized_input.catalogs.len(), 1);
            assert!(worker.provenance.normalized_input.catalogs[0]
                .revision
                .starts_with("account-observe-sha256:"));
            assert_eq!(
                worker.provenance.normalized_input.catalogs[0].models.len(),
                1
            );
            assert_eq!(
                worker.provenance.normalized_input.catalogs[0].models[0].model,
                FRONTIER_PROFILE_MODEL
            );
            let choice = worker
                .provenance
                .choice
                .as_ref()
                .context("observed worker choice")?;
            assert_eq!(choice.candidate.model, FRONTIER_PROFILE_MODEL);
            let pool = worker
                .provenance
                .normalized_input
                .pools
                .iter()
                .find(|pool| pool.runtime == "codex")
                .context("codex pool")?;
            assert!(!pool.entitlement_bounded);
            assert_eq!(pool.marginal_cost_microunits, 0);
            drop(temporary);
            Ok(())
        }

        #[test]
        fn scheduler_account_observe_missing_selection_stays_none() -> Result<()> {
            let (root, registry) = isolated_registry();
            seed_complete_account(&registry, false);
            let _guard = activate_cam_observe_test_harness(CamObserveTestHarness {
                registry,
                secondary_adapter: None,
                adapter: Box::new(SchedulerObserveStub {
                    id: "codex-cli",
                    mode: SchedulerObserveStubMode::ObservedModels,
                }),
                advertised: None,
                resolved_auditor: None,
                _root: root,
            });
            assert!(
                account_observation_for_launch_runtime(SupervisorRuntime::Codex, None)?.is_none()
            );
            assert!(
                account_observation_for_launch_runtime(SupervisorRuntime::Fake, None)?.is_none()
            );

            let (temporary, repo, catalog, admission, mut plan, mut plan_metadata) =
                prepared_selection_fixture()?;
            plan.assignments = vec![super::terminal_worker_assignment(
                "unselected-account-worker",
            )];
            plan.assignments[0].role_category = Some(RoleCategory::NonDelegatingTerminalWorker);
            let _routing_policy =
                crate::supervise::bind_assessed_injected_plan(&plan, &repo, &mut plan_metadata)?;
            let resolution = initialize_supervisor_selection_from_prepared_metadata(
                &mut plan,
                &mut plan_metadata,
                prepared_codex_request(&repo, &catalog, &admission),
            )?;
            assert!(resolution.selection_preflight_failure.is_none());
            let worker = resolution
                .decisions
                .iter()
                .find(|event| event.role == AgentRole::Worker)
                .context("worker decision")?;
            assert!(worker
                .provenance
                .normalized_input
                .catalogs
                .iter()
                .all(|catalog| !catalog.revision.starts_with("account-observe")));
            let pool = worker
                .provenance
                .normalized_input
                .pools
                .iter()
                .find(|pool| pool.runtime == "codex")
                .context("codex pool")?;
            assert!(pool.entitlement_bounded);
            assert!(pool.admission_provenance.contains("unavailable"));
            drop(temporary);
            Ok(())
        }

        #[test]
        fn scheduler_account_observe_error_fails_closed() -> Result<()> {
            let _guard = activate_stub(true, SchedulerObserveStubMode::ObserveError);
            let error = account_observation_for_launch_runtime(SupervisorRuntime::Codex, None)
                .expect_err("observe error must fail closed");
            assert!(error
                .to_string()
                .contains("failed to observe selected Coding Agent Manager account"));

            let (temporary, repo, catalog, admission, mut plan, mut plan_metadata) =
                prepared_selection_fixture()?;
            let error = initialize_supervisor_selection_from_prepared_metadata(
                &mut plan,
                &mut plan_metadata,
                prepared_codex_request(&repo, &catalog, &admission),
            )
            .expect_err("scheduler observe error must not fall back to advertised catalogs");
            assert!(error
                .to_string()
                .contains("failed to observe selected Coding Agent Manager account"));
            assert!(plan.role_models.is_empty());
            drop(temporary);
            Ok(())
        }

        #[test]
        fn scheduler_account_observe_routes_through_configured_authority_socket() -> Result<()> {
            use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;
            use coding_agent_manager_lib::account_authority::{
                listen, resolve_socket_path, AuthorityContext, AuthorityServerConfig,
                CategoryObservation, ModelsObservation, ObservedModel, StoredAccountRegistry,
            };
            use std::fs;
            use std::os::unix::fs::PermissionsExt;
            use std::sync::Arc;
            use std::thread;

            struct SocketEnvGuard {
                _inner: CamAuthoritySocketTestGuard,
            }

            impl SocketEnvGuard {
                fn set(path: &Path) -> Self {
                    Self {
                        _inner: CamAuthoritySocketTestGuard::install(Some(path.as_os_str())),
                    }
                }
            }

            struct SocketObserveAdapter;

            impl ProviderAdapter for SocketObserveAdapter {
                fn id(&self) -> &'static str {
                    "codex-cli"
                }

                fn descriptor(&self) -> ProviderDescriptor {
                    ProviderDescriptor {
                        id: "codex-cli".to_string(),
                        display_name: "codex-cli".to_string(),
                        vendor: "test".to_string(),
                        auth_kinds: vec![AuthKind::OAuth],
                        maturity: Maturity::Experimental,
                        install_state: InstallState::Unknown,
                        capabilities: Vec::new(),
                    }
                }

                fn config_paths(&self) -> Vec<PathBuf> {
                    Vec::new()
                }

                fn detect(&self) -> InstallState {
                    InstallState::Unknown
                }

                fn list_accounts(&self) -> coding_agent_manager_lib::error::Result<Vec<Account>> {
                    Ok(Vec::new())
                }

                fn activate_account(
                    &self,
                    _account_id: &str,
                ) -> coding_agent_manager_lib::error::Result<()> {
                    Err(CamError::NotImplemented("activate"))
                }

                fn observe_models_for_account(
                    &self,
                    _account: &StoredAccountMetadata,
                ) -> coding_agent_manager_lib::error::Result<CategoryObservation<ModelsObservation>>
                {
                    Ok(CategoryObservation::observed(ModelsObservation {
                        provenance: None,
                        models: vec![ObservedModel {
    access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                            model_id: "socket-routed-model".to_string(),
                            supported_efforts: None,
                            default_effort: None,
                        }],
                    }))
                }
            }

            let dir = tempfile::tempdir().expect("tempdir");
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
            let root = fs::canonicalize(dir.path()).expect("canonical");
            let data = root.join("data");
            fs::create_dir_all(&data).expect("data");
            let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
            seed_complete_account(&registry, true);

            let socket = root.join("account.sock");
            let safe = resolve_socket_path(&socket).expect("safe socket path");
            let mut ctx = AuthorityContext::new(registry).without_registry_fallback();
            ctx.adapters.insert(
                "codex-cli".to_string(),
                Arc::new(SocketObserveAdapter) as Arc<dyn ProviderAdapter>,
            );
            let listener =
                listen(safe, AuthorityServerConfig::new(ctx).expect("config")).expect("listen");
            let socket_path = listener.path().to_path_buf();
            thread::spawn(move || {
                let _ = listener.accept_once();
                let _ = listener.accept_once();
            });
            let _env = SocketEnvGuard::set(&socket_path);

            let observation =
                account_observation_for_launch_runtime(SupervisorRuntime::Codex, None)?
                    .context("configured authority socket must observe selected account")?;
            assert_eq!(observation.binding.account_id, "work");
            let models = observation.models.as_ref().context("models category")?;
            assert_eq!(models.outcome, ObservationOutcome::Observed);
            assert_eq!(
                models
                    .content
                    .as_ref()
                    .and_then(|content| content.models.first()),
                Some(&ObservedModel {
    access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                    model_id: "socket-routed-model".to_string(),
                    supported_efforts: None,
                    default_effort: None,
                })
            );
            Ok(())
        }

        #[test]
        fn scheduler_grok_socket_observe_freezes_selected_binding() -> Result<()> {
            use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;
            use crate::account_authority::{
                admit_grok_run_account_binding, frozen_observed_grok_selection,
                grok_run_account_binding, FrozenGrokSelectionGuard, GROK_CLI_PROVIDER_ID,
            };
            use coding_agent_manager_lib::account_authority::{
                authority_id_for, listen, resolve_socket_path, AuthorityContext,
                AuthorityServerConfig, CategoryObservation, ModelsObservation, ObservedModel,
            };
            use std::fs;
            use std::os::unix::fs::PermissionsExt;
            use std::sync::Arc;
            use std::thread;

            struct SocketEnvGuard {
                _inner: CamAuthoritySocketTestGuard,
            }

            impl SocketEnvGuard {
                fn set(path: &Path) -> Self {
                    Self {
                        _inner: CamAuthoritySocketTestGuard::install(Some(path.as_os_str())),
                    }
                }
            }

            struct SocketObserveAdapter;

            impl ProviderAdapter for SocketObserveAdapter {
                fn id(&self) -> &'static str {
                    GROK_CLI_PROVIDER_ID
                }

                fn descriptor(&self) -> ProviderDescriptor {
                    ProviderDescriptor {
                        id: GROK_CLI_PROVIDER_ID.to_string(),
                        display_name: GROK_CLI_PROVIDER_ID.to_string(),
                        vendor: "test".to_string(),
                        auth_kinds: vec![AuthKind::OAuth],
                        maturity: Maturity::Experimental,
                        install_state: InstallState::Unknown,
                        capabilities: Vec::new(),
                    }
                }

                fn config_paths(&self) -> Vec<PathBuf> {
                    Vec::new()
                }

                fn detect(&self) -> InstallState {
                    InstallState::Unknown
                }

                fn list_accounts(&self) -> coding_agent_manager_lib::error::Result<Vec<Account>> {
                    Ok(Vec::new())
                }

                fn activate_account(
                    &self,
                    _account_id: &str,
                ) -> coding_agent_manager_lib::error::Result<()> {
                    Err(CamError::NotImplemented("activate"))
                }

                fn observe_models_for_account(
                    &self,
                    _account: &StoredAccountMetadata,
                ) -> coding_agent_manager_lib::error::Result<CategoryObservation<ModelsObservation>>
                {
                    Ok(CategoryObservation::observed(ModelsObservation {
                        provenance: None,
                        models: vec![ObservedModel {
    access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                            model_id: "socket-grok-model".to_string(),
                            supported_efforts: None,
                            default_effort: None,
                        }],
                    }))
                }
            }

            let _freeze = FrozenGrokSelectionGuard::pin(None);
            let dir = tempfile::tempdir().expect("tempdir");
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
            let root = fs::canonicalize(dir.path()).expect("canonical");
            let data = root.join("data");
            fs::create_dir_all(&data).expect("data");
            let registry = StoredAccountRegistry::new(stored_accounts_path(&data));
            registry
                .begin_add(
                    GROK_CLI_PROVIDER_ID,
                    "work",
                    "Work",
                    AuthKind::OAuth,
                    StoredAccountMaterial::VendorHome,
                )
                .expect("begin add");
            registry
                .complete_add(GROK_CLI_PROVIDER_ID, "work")
                .expect("complete add");
            registry
                .select_complete_revision(GROK_CLI_PROVIDER_ID, "work", None)
                .expect("select");
            let expected_authority = authority_id_for(registry.metadata_path());
            let expected_binding = registry
                .selected_binding(GROK_CLI_PROVIDER_ID)
                .expect("binding")
                .expect("selected");

            let socket = root.join("account.sock");
            let safe = resolve_socket_path(&socket).expect("safe socket path");
            let mut ctx = AuthorityContext::new(registry).without_registry_fallback();
            ctx.adapters.insert(
                GROK_CLI_PROVIDER_ID.to_string(),
                Arc::new(SocketObserveAdapter) as Arc<dyn ProviderAdapter>,
            );
            let listener =
                listen(safe, AuthorityServerConfig::new(ctx).expect("config")).expect("listen");
            let socket_path = listener.path().to_path_buf();
            thread::spawn(move || while listener.accept_once().is_ok() {});
            let _env = SocketEnvGuard::set(&socket_path);

            let observation = account_observation_for_launch_runtime(
                SupervisorRuntime::Grok,
                Some("issue-601-scheduler-observe"),
            )?
            .context("configured authority socket must observe selected Grok account")?;
            assert_eq!(observation.binding.account_id, "work");
            let frozen =
                frozen_observed_grok_selection().context("Grok observation must freeze")?;
            assert_eq!(
                frozen.authority_id.as_deref(),
                Some(expected_authority.as_str())
            );
            assert_eq!(frozen.account_id, expected_binding.account_id);
            assert_eq!(
                frozen.account_incarnation,
                expected_binding.account_incarnation
            );
            assert_eq!(
                frozen.selection_revision,
                expected_binding.selection_revision
            );
            let admitted = grok_run_account_binding("issue-601-scheduler-observe")
                .context("Grok observation must admit a per-run binding")?;
            assert_eq!(admitted, frozen);
            admit_grok_run_account_binding("issue-601-scheduler-observe", None);
            Ok(())
        }
    }
}

#[cfg(test)]
mod decomposition_tests;
