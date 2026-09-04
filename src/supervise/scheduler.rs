use super::*;

mod preclaim;
use preclaim::{
    evaluate_preclaim_viability, parked_preclaim_outcome, persist_preclaim_decision,
    preclaim_assignment, PreclaimDecision, PreclaimRunEvidence,
};

fn require_supervisor_operation(
    session: &SupervisorRunMutationSession,
    operation: MutationOperation,
) -> Result<()> {
    session
        .permit(operation)?
        .verify(operation)
        .map_err(anyhow::Error::from)
}

fn open_scheduler_coordination_stores_authorized(
    repo: &Path,
    permit: &SupervisorOperationPermit<'_>,
) -> Result<(SyncStore, SemanticIntentStore)> {
    permit
        .verify(MutationOperation::SupervisorCoordinationStoreBootstrap)
        .map_err(anyhow::Error::from)?;
    Ok((SyncStore::open(repo)?, SemanticIntentStore::open(repo)?))
}

fn open_scheduler_field_guide_authorized(
    repo: &Path,
    permit: &SupervisorOperationPermit<'_>,
) -> Result<FieldGuideStore> {
    permit
        .verify(MutationOperation::SupervisorFieldGuideMutation)
        .map_err(anyhow::Error::from)?;
    FieldGuideStore::open(repo, FieldGuideLimits::default())
        .context("failed to open authenticated field guide for supervise run")
}

fn initialize_scheduler_orchestration_journal_authorized(
    repo: &Path,
    run_id: &RunId,
    parent_node: Option<&str>,
    permit: &SupervisorOperationPermit<'_>,
) -> Result<Option<OrchestrationEventJournal>> {
    permit
        .verify(MutationOperation::SupervisorOrchestrationJournalLifecycle)
        .map_err(anyhow::Error::from)?;
    Ok(initialize_orchestration_event_journal(
        repo,
        run_id,
        parent_node,
    ))
}

fn release_concurrent_assignment_authorized(
    context: &AssignmentSchedulerContext<'_, '_>,
    outcome: &mut AssignmentExecutionOutcome,
) -> Result<()> {
    let claim_permit = context
        .mutation_session
        .permit(MutationOperation::ClaimRelease)?;
    let semantic_permit = context
        .mutation_session
        .permit(MutationOperation::SemanticIntentRelease)?;
    release_concurrent_assignment(
        outcome,
        context.sync_store,
        context.semantic_store,
        &claim_permit,
        &semantic_permit,
    )
}

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
    mutation_session: &'context SupervisorRunMutationSession,
    release_per_assignment: bool,
}

struct SchedulerProgress {
    indexed_outcomes: Vec<Option<AssignmentExecutionOutcome>>,
    prepared_preclaim_decisions: Option<Vec<PreclaimDecision>>,
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

    fn commit_completed_selection_prefix(&mut self, runtime: SupervisorRuntime) -> Result<()> {
        self.budget_degradation
            .commit_completed_selection_prefix(&self.indexed_outcomes, runtime)
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
}

impl AssignmentBudgetPolicy {
    pub(super) fn apply(&self, plan: &SupervisorPlan) -> SupervisorPlan {
        let mut effective = plan.clone();
        for (role, selection) in &self.model_overrides {
            effective.role_models.insert(*role, selection.clone());
        }
        for role in [
            AgentRole::ChildOrchestrator,
            AgentRole::Worker,
            AgentRole::GateClassifier,
            AgentRole::Auditor,
        ] {
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
        for lens in &mut effective.review_lenses {
            if let ReviewLensBackendConfig::Model {
                reasoning_effort, ..
            } = &mut lens.backend
            {
                let resolved = resolve_reasoning_effort(
                    AgentRole::Auditor,
                    self.assignment_reasoning_effort,
                    reasoning_effort.as_deref(),
                    0,
                );
                *reasoning_effort = Some(resolved.resolved);
            }
        }
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

struct AssignmentBudgetPolicyRequest<'a> {
    assignment: &'a OrchestratorAssignment,
    requested_reasoning_effort: Option<ReasoningEffort>,
    report: &'a RunBudgetReport,
    plan: &'a SupervisorPlan,
    requested_plan: &'a SupervisorPlan,
    assignment_metadata: &'a AssignmentMetadata,
    catalog: &'a RuntimeModelCatalog,
    runtime: SupervisorRuntime,
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
        let (selection_roles, selection_cause, budget_signal) = if budget_trigger {
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
                    })
                    .map(|(index, model)| (index, model.clone()))
                else {
                    bail!(
                        "Worker model degradation refused for assignment '{}': the requested-plan budget_degrade_models ladder has no distinct runtime-advertised authority-eligible target",
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
            let requested = requested_reasoning_effort.or_else(|| {
                lens.backend
                    .reasoning_effort()
                    .and_then(ReasoningEffort::parse)
            });
            push(
                review_lens_auditor_id(assignment, lens_index),
                AgentRole::Auditor,
                requested,
                lens.backend.reasoning_effort(),
                None,
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

fn assignment_mechanical_duties(
    assignment: &OrchestratorAssignment,
    assignment_metadata: &AssignmentMetadata,
) -> Option<Vec<MechanicalTerminalDuty>> {
    if assignment.worker_assignments.is_empty() {
        return None;
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
    let measured_eligible = crate::selection::measured_authority_eligibility(
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
        progress.commit_completed_selection_prefix(context.options.runtime)?;
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
            progress.commit_completed_selection_prefix(context.options.runtime)?;
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
        require_supervisor_operation(
            context.mutation_session,
            MutationOperation::SupervisorCheckpointJournalLifecycle,
        )?;
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
            cancellation: cancellation.clone(),
            external_runner: context.external_runner,
            mutation_session: context.mutation_session,
        });
        drop(concurrency_guard);
        let mut outcome = outcome;
        record_completed_assignment_checkpoint(context, index, &outcome)?;
        if context.release_per_assignment {
            release_concurrent_assignment_authorized(context, &mut outcome)?;
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
        progress.commit_completed_selection_prefix(context.options.runtime)?;
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
                progress.commit_completed_selection_prefix(context.options.runtime)?;
                while active.len() < progress.budget_degradation.effective_fan_out {
                    if !progress.health_breaker.permits_admission() {
                        stop_scheduling = true;
                        break;
                    }
                    let budget_report = context
                        .budget_ledger
                        .report()
                        .context("failed to inspect run budget before concurrent admission")?;
                    if !budget_report.new_dispatch_allowed {
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
                        progress.commit_completed_selection_prefix(context.options.runtime)?;
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
                    require_supervisor_operation(
                        context.mutation_session,
                        MutationOperation::SupervisorCheckpointJournalLifecycle,
                    )?;
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
                    let assignment_cancellation = cancellation.clone();
                    let concurrency = progress.concurrency.clone();
                    let (admission_commit, admission_receiver) = AdmissionCommitSignal::new();
                    let spawn_result = thread::Builder::new().spawn_scoped(scope, move || {
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
                            mutation_session: context.mutation_session,
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
                                    release_concurrent_assignment_authorized(
                                        context,
                                        &mut outcome,
                                    )?;
                                    progress.indexed_outcomes[active_index] = Some(outcome);
                                }
                                progress
                                    .commit_completed_selection_prefix(context.options.runtime)?;
                                return Err(error).context(format!(
                                    "supervisor assignment '{}' ended before committing or declining budget admission",
                                    assignment.id
                                ));
                            }
                        }
                        Err(error) => {
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
                            progress.commit_completed_selection_prefix(context.options.runtime)?;
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
            release_concurrent_assignment_authorized(context, &mut outcome)?;
            if outcome.requires_scheduler_abort() {
                cancellation.cancel();
                stop_scheduling = true;
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
                if outcome.budget_dispatch_stopped
                    || (!pending.is_empty()
                        && !context
                            .budget_ledger
                            .report()
                            .context("failed to inspect run budget after concurrent dispatch")?
                            .new_dispatch_allowed)
                {
                    progress.budget_prevented_dispatch = true;
                    progress
                        .budget_denied_assignment_indices
                        .extend(pending.iter().copied());
                    stop_scheduling = true;
                }
            }
            progress.indexed_outcomes[completed_index] = Some(outcome);
            progress.commit_completed_selection_prefix(context.options.runtime)?;
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
            release_concurrent_assignment_authorized(context, &mut outcome)?;
            progress.indexed_outcomes[index] = Some(outcome);
            progress.commit_completed_selection_prefix(context.options.runtime)?;
        }
        Ok(())
    })
}

fn record_completed_assignment_checkpoint(
    context: &AssignmentSchedulerContext<'_, '_>,
    index: usize,
    outcome: &AssignmentExecutionOutcome,
) -> Result<()> {
    require_supervisor_operation(
        context.mutation_session,
        MutationOperation::SupervisorCheckpointJournalLifecycle,
    )?;
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
                "fake supervisor simulation succeeded but is not publishable or acceptable as real model evidence; {generated_follow_up_task_count} generated dependent update task(s) remain deferred and must be regenerated by an accepted publishable run"
            )
        } else if success && generated_follow_up_task_count > 0 {
            format!(
                "the breaking assignments completed under accepted narrow licenses; {generated_follow_up_task_count} complete generated dependent update plan(s) are eligible for the authenticated command-level queue, whose separate cascade outcome determines whether dispatch occurred"
            )
        } else if success && !publishable {
            "fake supervisor simulation succeeded but is not publishable or acceptable as real model evidence"
                .to_string()
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
            "rerun with the trusted system Codex runtime before treating the generated follow-up records as dispatchable evidence"
                .to_string()
        } else if success && generated_follow_up_task_count > 0 {
            "inspect the authenticated follow-up queue and cascade outcome; any admitted generated plan still passes ordinary claims, budget admission, checkpoints, child gates, and review lenses"
                .to_string()
        } else if success && !publishable {
            "rerun with the trusted system Codex runtime before any real acceptance, merge, or publication"
                .to_string()
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
    claim_permit: &SupervisorOperationPermit<'_>,
    semantic_permit: &SupervisorOperationPermit<'_>,
) -> ReleasedSchedulerResources {
    let (mut released_claims, mut release_errors) = match sync_store {
        Some(store) => release_claims(
            store,
            std::mem::take(&mut collected.acquired_claim_tokens),
            claim_permit,
        ),
        None => (Vec::new(), Vec::new()),
    };
    released_claims.extend(std::mem::take(&mut collected.concurrently_released_claims));
    release_errors.extend(std::mem::take(&mut collected.concurrent_release_errors));
    let (mut released_semantic_intents, mut semantic_release_errors) = match semantic_store {
        Some(store) => release_semantic_intents(
            store,
            std::mem::take(&mut collected.acquired_semantic_tokens),
            semantic_permit,
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
    mutation_session: &SupervisorRunMutationSession,
    release_after_terminal_record: impl FnOnce() -> Result<()>,
) -> Result<SupervisorFinalReport> {
    require_supervisor_operation(
        mutation_session,
        MutationOperation::SupervisorRunArtifactWriteAppend,
    )?;
    require_supervisor_operation(
        mutation_session,
        MutationOperation::SupervisorOrchestrationJournalLifecycle,
    )?;
    if let Some(quiescence) = invocation_scratch_quiescence {
        require_supervisor_operation(
            mutation_session,
            MutationOperation::SupervisorScratchEvidenceCleanup,
        )?;
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
        require_supervisor_operation(
            mutation_session,
            MutationOperation::SupervisorCheckpointJournalLifecycle,
        )?;
        let artifact_binding = artifact_writer
            .resume_binding()
            .context("failed to establish a durable terminal supervisor report boundary")?;
        checkpoint
            .final_report_planned(&final_report, &report_bytes, artifact_binding)
            .context("failed to persist the terminal supervisor report plan")?;
    }
    require_supervisor_operation(mutation_session, MutationOperation::ClaimRelease)?;
    require_supervisor_operation(mutation_session, MutationOperation::SemanticIntentRelease)?;
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
    let finalization_permit =
        mutation_session.permit(MutationOperation::SupervisorRunArtifactAuthenticatedFinalize)?;
    finalize_supervisor_artifact_run(
        artifact_writer,
        &RunArtifactFamily::Supervise.final_report_relative_path(),
        final_report.publishable,
        &finalization_permit,
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
    mutation_session: &'context SupervisorRunMutationSession,
}

fn initialize_scheduler_evidence(
    initialization: &mut SchedulerEvidenceInitialization<'_>,
) -> Result<()> {
    require_supervisor_operation(
        initialization.mutation_session,
        MutationOperation::SupervisorRunArtifactWriteAppend,
    )?;
    require_supervisor_operation(
        initialization.mutation_session,
        MutationOperation::SupervisorCoordinationStoreBootstrap,
    )?;
    require_supervisor_operation(
        initialization.mutation_session,
        MutationOperation::SupervisorOrchestrationJournalLifecycle,
    )?;
    require_supervisor_operation(
        initialization.mutation_session,
        MutationOperation::SupervisorFieldGuideMutation,
    )?;
    let messaging_permit = initialization
        .mutation_session
        .permit(MutationOperation::SupervisorMessagingJournalLifecycle)?;
    let artifact_write_permit = initialization
        .mutation_session
        .permit(MutationOperation::SupervisorRunArtifactWriteAppend)?;
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
        &artifact_write_permit,
        &messaging_permit,
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
    let field_guide_permit = initialization
        .mutation_session
        .permit(MutationOperation::SupervisorFieldGuideMutation)?;
    let field_guide_store =
        open_scheduler_field_guide_authorized(initialization.repo, &field_guide_permit)?;
    let field_guide_prompt = SupervisorFieldGuidePrompt::from_store(&field_guide_store)?;
    *initialization.field_guide_store_slot = Some(field_guide_store);
    *initialization.field_guide_prompt_slot = Some(field_guide_prompt);
    let coordination_permit = initialization
        .mutation_session
        .permit(MutationOperation::SupervisorCoordinationStoreBootstrap)?;
    let (sync_store, semantic_store) =
        open_scheduler_coordination_stores_authorized(initialization.repo, &coordination_permit)?;
    *initialization.sync_store_slot = Some(sync_store);
    *initialization.semantic_store_slot = Some(semantic_store);
    let orchestration_permit = initialization
        .mutation_session
        .permit(MutationOperation::SupervisorOrchestrationJournalLifecycle)?;
    *initialization.orchestration_journal = initialize_scheduler_orchestration_journal_authorized(
        initialization.repo,
        &initialization.options.run_id,
        initialization.options.parent_node.as_deref(),
        &orchestration_permit,
    )?;
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
    repo: &Path,
    runtime: SupervisorRuntime,
    execution_runtime: SupervisorExecutionRuntime,
) -> Vec<PreclaimDecision> {
    let evidence = supervisor_preclaim_run_evidence(repo, runtime, execution_runtime);
    plan.assignments
        .iter()
        .map(|assignment| {
            let risk = evidence.risk_for(&assignment.assigned_paths);
            evaluate_preclaim_viability(
                assignment,
                &requested_plan.assignments,
                evidence.repo_map.as_ref(),
                risk.as_ref(),
                evidence.runtime,
                execution_runtime,
            )
        })
        .collect()
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
        SupervisorWorktreeCreation::Bound(_) | SupervisorWorktreeCreation::PrimaryWorktree(_)
    ) {
        return SupervisorExecutionRuntime::NonpublishableSimulation;
    }

    #[cfg(not(test))]
    let _ = worktree_creation;

    execution_runtime
}

struct PreparedPreclaimPersistence<'a> {
    repo: &'a Path,
    run_id: &'a RunId,
    parent_node: Option<&'a str>,
    artifact_writer: &'a mut ArtifactRunWriter,
    assignments: &'a [OrchestratorAssignment],
    decisions: &'a [PreclaimDecision],
    mutation_session: &'a SupervisorRunMutationSession,
}

fn persist_prepared_preclaim_decisions(request: PreparedPreclaimPersistence<'_>) -> Result<()> {
    let PreparedPreclaimPersistence {
        repo,
        run_id,
        parent_node,
        artifact_writer,
        assignments,
        decisions,
        mutation_session,
    } = request;
    require_supervisor_operation(
        mutation_session,
        MutationOperation::SupervisorRunArtifactWriteAppend,
    )?;
    require_supervisor_operation(
        mutation_session,
        MutationOperation::SupervisorOrchestrationJournalLifecycle,
    )?;
    if assignments.len() != decisions.len() {
        bail!(
            "cannot persist {} pre-claim decisions for {} assignments",
            decisions.len(),
            assignments.len()
        );
    }
    let orchestration_permit =
        mutation_session.permit(MutationOperation::SupervisorOrchestrationJournalLifecycle)?;
    let mut journal = initialize_scheduler_orchestration_journal_authorized(
        repo,
        run_id,
        parent_node,
        &orchestration_permit,
    )?;
    let mut autonomy_kpis = AutonomyKpiCollector::default();
    let artifacts = Mutex::new(SharedSupervisorArtifacts {
        writer: artifact_writer,
        journal: &mut journal,
        autonomy_kpis: &mut autonomy_kpis,
        checkpoint: None,
        mutation_session,
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
    /// Original caller plan retained for selection provenance and follow-up inheritance.
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
    mutation_session: SupervisorRunMutationSession,
    _process_registration: Option<crate::run_ops::SupervisorProcessGuard>,
}

struct SupervisorMutationStartRequest<'run, 'dispatch> {
    repo: &'run Path,
    options: &'run SupervisorRunOptions,
    evidence: EffectiveSupervisorMutationAuditEvidence,
    session: &'run SupervisorRunMutationSession,
    preflight_evidence: Option<EffectiveSupervisorMutationAuditEvidence>,
    preflight_process_evidence: Vec<SupervisorProcessLaunchAuditEvidence>,
    dispatch_started: Option<&'dispatch AtomicBool>,
    dispatch_authorized: Option<&'dispatch mut dyn FnMut() -> Result<()>>,
}

fn begin_supervisor_mutations(
    request: SupervisorMutationStartRequest<'_, '_>,
) -> Result<(
    ArtifactRunWriter,
    Option<crate::run_ops::SupervisorProcessGuard>,
)> {
    let SupervisorMutationStartRequest {
        repo,
        options,
        evidence,
        session,
        preflight_evidence,
        preflight_process_evidence,
        dispatch_started,
        mut dispatch_authorized,
    } = request;
    if session.canonical_manifest_sha256() != evidence.canonical_manifest_sha256() {
        bail!("Supervisor mutation session is bound to different audit evidence");
    }
    let collision = crate::run_ops::refuse_live_run_collision(
        repo,
        RunArtifactFamily::Supervise,
        &options.run_id,
        options.allow_live_run_collision,
    )?;
    if let Some(dispatch_authorized) = dispatch_authorized.as_mut() {
        dispatch_authorized()?;
    }
    if let Some(dispatch_started) = dispatch_started {
        dispatch_started.store(true, Ordering::SeqCst);
    }
    let artifact_reserve_permit =
        session.permit(MutationOperation::SupervisorRunArtifactReserve)?;
    let mut artifact_writer = reserve_supervisor_artifact_run(
        repo,
        RunArtifactFamily::Supervise,
        options.run_id.clone(),
        "maco-supervise",
        &artifact_reserve_permit,
    )?;
    let artifact_write_permit =
        session.permit(MutationOperation::SupervisorRunArtifactWriteAppend)?;
    artifact_write_permit.verify(MutationOperation::SupervisorRunArtifactWriteAppend)?;
    write_artifact_json(
        &mut artifact_writer,
        Path::new("effective-mutation-manifest.json"),
        &evidence,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    if let Some(preflight_evidence) = preflight_evidence {
        write_artifact_json(
            &mut artifact_writer,
            Path::new("preflight-effective-mutation-manifest.json"),
            &preflight_evidence,
            MAX_SUPERVISOR_REPORT_BYTES,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
    }
    for (index, process_evidence) in preflight_process_evidence.iter().enumerate() {
        write_artifact_json(
            &mut artifact_writer,
            &PathBuf::from("preflight-process-launches")
                .join(format!("catalog-probe-{index}.json")),
            process_evidence,
            MAX_SUPERVISOR_REPORT_BYTES,
            ArtifactFileDisposition::PrivateEvidence,
        )?;
    }
    let process_register_permit = session.permit(MutationOperation::SupervisorProcessRegister)?;
    let process_registration = register_current_supervisor_process_authorized(
        repo,
        "supervise",
        &options.run_id,
        &process_register_permit,
    )
    .ok()
    .flatten();
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
        repo,
        &preflight_spec,
        &collision,
    )?;
    crate::run_ops::append_run_heartbeat_best_effort(
        &mut artifact_writer,
        "initialized",
        None,
        "ok",
        None,
    );
    Ok((artifact_writer, process_registration))
}

struct PrepareSupervisorRunRequest<'options, 'worktree, 'dispatch> {
    loaded: LoadedSupervisorPlan,
    options: &'options SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'worktree>,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
    preflight_evidence: Option<EffectiveSupervisorMutationAuditEvidence>,
    catalog_preflight_session: Option<CatalogPreflightMutationSession>,
    preflight_process_evidence: Vec<SupervisorProcessLaunchAuditEvidence>,
    dispatch_started: Option<&'dispatch AtomicBool>,
    dispatch_authorized: Option<&'dispatch mut dyn FnMut() -> Result<()>>,
}

fn prepare_supervisor_run(
    request: PrepareSupervisorRunRequest<'_, '_, '_>,
) -> Result<PreparedSupervisorRun> {
    let PrepareSupervisorRunRequest {
        loaded,
        options,
        max_concurrent_children,
        execution_runtime,
        worktree_creation,
        runtime_model_catalog,
        preflight_evidence,
        catalog_preflight_session,
        mut preflight_process_evidence,
        dispatch_started,
        mut dispatch_authorized,
    } = request;
    let LoadedSupervisorPlan {
        mut plan,
        consultant,
        assignment_metadata,
        mut plan_metadata,
    } = loaded;
    validate_max_concurrent_children(max_concurrent_children)?;
    match worktree_creation {
        SupervisorWorktreeCreation::Bound(_)
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("verified worktree creation capability requires the verified supervisor runtime")
        }
        SupervisorWorktreeCreation::ExistingOnly
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("existing-only worktree execution requires the verified supervisor runtime")
        }
        SupervisorWorktreeCreation::PrimaryWorktree(_)
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
            SupervisorWorktreeCreation::PrimaryWorktree(capability),
            Some(execution_target @ SupervisorExecutionTarget::PrimaryWorktree { .. }),
        ) if capability.matches(execution_target) => {}
        (SupervisorWorktreeCreation::PrimaryWorktree(_), Some(_)) => {
            bail!("primary-worktree double opt-in capability belongs to a different target")
        }
        (SupervisorWorktreeCreation::PrimaryWorktree(_), None) => {
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
    let requested_plan = plan.clone();
    let preclaim_runtime =
        preclaim_assessment_runtime(runtime, execution_runtime, worktree_creation);
    let preclaim_decisions =
        evaluate_supervisor_preclaims(&plan, &requested_plan, &repo, runtime, preclaim_runtime);
    let preflight_evidence = match (&preflight_evidence, &catalog_preflight_session) {
        (Some(evidence), Some(session)) => {
            if session.canonical_manifest_sha256() != evidence.canonical_manifest_sha256() {
                bail!("catalog preflight session is bound to different audit evidence");
            }
            preflight_evidence
        }
        (None, None) if cfg!(test) => None,
        _ => bail!("Supervisor resolution preflight authority is missing or incomplete"),
    };
    let effective_max_duration_seconds = match (
        plan_metadata.run_budget_max_duration_seconds,
        options.budget_max_duration_seconds,
    ) {
        (Some(plan), Some(cli)) => Some(plan.min(cli)),
        (plan, cli) => plan.or(cli),
    };
    let mut budget_ledger = RunBudgetLedger::new_composed(
        plan_metadata.run_budget.limits,
        options.budget_overrides,
        plan_metadata.run_budget_max_duration_seconds,
        options.budget_max_duration_seconds,
    )
    .context("failed to initialize the supervise run budget ledger")?;
    plan_metadata.run_budget.limits = budget_ledger.effective_limits();
    plan_metadata.run_budget_max_duration_seconds = effective_max_duration_seconds;
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
    plan_metadata.admission = admission_policy_input.effective;
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
                runtime,
                execution_runtime,
                runtime_model_catalog: &runtime_model_catalog,
                admission_policy_input: &admission_policy_input,
                quota: SupervisorQuotaSelectionInput {
                    context: quota_context.as_ref(),
                    ledger: quota_context.as_ref().map(|_| &budget_ledger),
                },
                catalog_preflight_session: catalog_preflight_session.as_ref(),
                process_launch_evidence: &mut preflight_process_evidence,
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
            verify_evidence_only_reaudit_source(&repo, operation, assignment)
        })
        .transpose()?;
    let assignment_schedule = validated_scheduler_assignment_schedule(&plan, &plan_metadata)?;
    let primary_base = current_head_oid(&repo)?;
    let primary_baseline_sha256 = primary_worktree_snapshot_sha256(&repo, execution_runtime)?;
    let normalized_plan_sha256 = normalized_supervisor_plan_sha256(
        &plan,
        &consultant,
        &assignment_metadata,
        &plan_metadata,
    )?;
    let effective_loaded = LoadedSupervisorPlan {
        plan: plan.clone(),
        consultant: consultant.clone(),
        assignment_metadata: assignment_metadata.clone(),
        plan_metadata: plan_metadata.clone(),
    };
    let dispatch_identity = effective_supervisor_dispatch_identity(&effective_loaded, options);
    let effective_mutation_manifest =
        effective_supervisor_mutation_manifest(EffectiveSupervisorRunManifestContext {
            loaded: &effective_loaded,
            options,
            dispatch_identity: dispatch_identity.clone(),
            execution_runtime,
            worktree_mode: effective_supervisor_worktree_mode(worktree_creation),
            repository_identity: effective_repository_identity(&repo)?,
            primary_baseline_sha256,
            admission_policy_input: &admission_policy_input,
            max_concurrent_children,
        })?;
    let authorized = authorize_effective_supervisor_manifest(effective_mutation_manifest)?;
    let (mutation_evidence, mutation_session) = authorized.into_supervisor_run()?;
    let (mut artifact_writer, process_registration) =
        begin_supervisor_mutations(SupervisorMutationStartRequest {
            repo: &repo,
            options,
            evidence: mutation_evidence,
            session: &mutation_session,
            preflight_evidence,
            preflight_process_evidence,
            dispatch_started,
            dispatch_authorized: dispatch_authorized.take(),
        })?;
    persist_prepared_preclaim_decisions(PreparedPreclaimPersistence {
        repo: &repo,
        run_id: &options.run_id,
        parent_node: options.parent_node.as_deref(),
        artifact_writer: &mut artifact_writer,
        assignments: &requested_plan.assignments,
        decisions: &preclaim_decisions,
        mutation_session: &mutation_session,
    })?;
    let checkpoint_permit =
        mutation_session.permit(MutationOperation::SupervisorCheckpointJournalLifecycle)?;
    let checkpoint_writer = SupervisorCheckpointWriter::create_authorized(
        &repo,
        SupervisorCheckpointPreparation::new(
            &options.run_id,
            &primary_base,
            normalized_plan_sha256,
            max_concurrent_children,
            &plan,
            artifact_writer.resume_binding()?,
            budget_ledger.report()?,
        )
        .with_parent_node(options.parent_node.clone())
        .with_dispatch_identity(dispatch_identity),
        &checkpoint_permit,
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
        mutation_session,
        _process_registration: process_registration,
    })
}

#[cfg(test)]
fn prepare_supervisor_run_for_test(
    loaded: LoadedSupervisorPlan,
    options: &SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
) -> Result<PreparedSupervisorRun> {
    prepare_supervisor_run(PrepareSupervisorRunRequest {
        loaded,
        options,
        max_concurrent_children,
        execution_runtime,
        worktree_creation,
        runtime_model_catalog,
        preflight_evidence: None,
        catalog_preflight_session: None,
        preflight_process_evidence: Vec::new(),
        dispatch_started: None,
        dispatch_authorized: None,
    })
}

pub(super) struct PreparedSupervisorSelectionRequest<'a> {
    pub(super) repo: &'a Path,
    pub(super) runtime: SupervisorRuntime,
    pub(super) execution_runtime: SupervisorExecutionRuntime,
    pub(super) runtime_model_catalog: &'a RuntimeModelCatalogAcquisition,
    pub(super) admission_policy_input: &'a SupervisorAdmissionPolicyInput,
    pub(super) quota: SupervisorQuotaSelectionInput<'a>,
    pub(super) catalog_preflight_session: Option<&'a CatalogPreflightMutationSession>,
    pub(super) process_launch_evidence: &'a mut Vec<SupervisorProcessLaunchAuditEvidence>,
}

pub(super) fn initialize_supervisor_selection_from_prepared_metadata(
    plan: &mut SupervisorPlan,
    plan_metadata: &mut SupervisorPlanMetadata,
    request: PreparedSupervisorSelectionRequest<'_>,
) -> Result<SupervisorSelectionResolution> {
    let PreparedSupervisorSelectionRequest {
        repo,
        runtime,
        execution_runtime,
        runtime_model_catalog,
        admission_policy_input,
        quota,
        catalog_preflight_session,
        process_launch_evidence,
    } = request;
    if plan_metadata.resolved_objective_profile.is_none() {
        let requested_objective_profile = plan_metadata.objective_profile.clone();
        plan_metadata.resolved_objective_profile = Some(
            resolve_objective_profile(repo, requested_objective_profile.as_deref())
                .context("failed to resolve the supervisor objective profile")?,
        );
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
            let advertised = match advertised_catalogs_for_supervisor_selection(
                repo,
                catalog_preflight_session,
                process_launch_evidence,
            ) {
                Ok(advertised) => advertised,
                Err(error) => {
                    return Ok(SupervisorSelectionResolution {
                        mode: SupervisorSelectionMode::Automatic,
                        decisions: Vec::new(),
                        automatic_state: None,
                        selection_preflight_failure: Some(SupervisorSelectionPreflightFailure {
                            role: AgentRole::Worker,
                            kind: SupervisorSelectionPreflightFailureKind::FailClosed,
                            message: format!(
                                "runtime catalog probe failed after exact admission: {error:#}"
                            ),
                        }),
                    })
                }
            };
            let resolution = initialize_supervisor_selection_with_quota(
                plan,
                runtime,
                catalog,
                admission_policy_input,
                &advertised,
                plan_metadata.resolved_objective_profile.as_ref(),
                quota,
            )?;
            if resolution.selection_preflight_failure.is_none() {
                bind_selected_assignment_runtimes(plan, &resolution.decisions)?;
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
    mutation_session: &'context SupervisorRunMutationSession,
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
        mutation_session,
    } = finalization;
    require_supervisor_operation(
        mutation_session,
        MutationOperation::SupervisorRefusalEvidenceWrite,
    )?;
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
    require_supervisor_operation(
        mutation_session,
        MutationOperation::SupervisorCheckpointJournalLifecycle,
    )?;
    checkpoint_writer.scheduler_closed(binding, run_budget_report)?;
    let mut orchestration_journal = None;
    persist_supervisor_final_report(
        final_report,
        &mut orchestration_journal,
        artifact_writer,
        Some(checkpoint_writer),
        Some(crate::artifacts::ArtifactScratchQuiescence::Verified),
        mutation_session,
        || Ok(()),
    )
}

pub(super) struct SupervisorRunExecution<'worktree, 'dispatch, 'runner> {
    pub(super) loaded: LoadedSupervisorPlan,
    pub(super) options: SupervisorRunOptions,
    pub(super) max_concurrent_children: usize,
    pub(super) execution_runtime: SupervisorExecutionRuntime,
    pub(super) worktree_creation: SupervisorWorktreeCreation<'worktree>,
    pub(super) runtime_model_catalog: RuntimeModelCatalogAcquisition,
    pub(super) preflight_evidence: Option<EffectiveSupervisorMutationAuditEvidence>,
    pub(super) catalog_preflight_session: Option<CatalogPreflightMutationSession>,
    pub(super) preflight_process_evidence: Vec<SupervisorProcessLaunchAuditEvidence>,
    pub(super) dispatch_started: Option<&'dispatch AtomicBool>,
    pub(super) dispatch_authorized: Option<&'dispatch mut dyn FnMut() -> Result<()>>,
    pub(super) external_runner: &'runner CancellableExternalRunner<'runner>,
}

pub(super) fn run_supervisor_plan_with_runner_and_creation(
    execution: SupervisorRunExecution<'_, '_, '_>,
) -> Result<SupervisorFinalReport> {
    let SupervisorRunExecution {
        loaded,
        options,
        max_concurrent_children,
        execution_runtime,
        worktree_creation,
        runtime_model_catalog,
        preflight_evidence,
        catalog_preflight_session,
        preflight_process_evidence,
        dispatch_started,
        dispatch_authorized,
        external_runner,
    } = execution;
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
        mutation_session,
        _process_registration,
    } = prepare_supervisor_run(PrepareSupervisorRunRequest {
        loaded,
        options: &options,
        max_concurrent_children,
        execution_runtime,
        worktree_creation,
        runtime_model_catalog,
        preflight_evidence,
        catalog_preflight_session,
        preflight_process_evidence,
        dispatch_started,
        dispatch_authorized,
    })?;
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
                    mutation_session: &mutation_session,
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
                mutation_session: &mutation_session,
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
            mutation_session: &mutation_session,
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
                mutation_session: &mutation_session,
            });
            let semantic_block_gate = SemanticBlockGate::default();
            let serial_semantic_warn_intents = Mutex::new(Vec::<(usize, SemanticIntent)>::new());
            let mut progress = SchedulerProgress::new_with_selection_state(
                plan.assignments.len(),
                max_concurrent_children,
                automatic_selection_state,
                options.runtime,
            )?;
            progress.install_preclaim_decisions(preclaim_decisions)?;
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
                mutation_session: &mutation_session,
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
            message: "process usage is incomplete because at least one external Codex JSONL capture was missing, truncated, or malformed, or conservatively reconciled because usage was observed but unreliable after its run failed, timed out, or lacked verified completion or containment"
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
    let field_guide_permit =
        mutation_session.permit(MutationOperation::SupervisorFieldGuideMutation)?;
    let field_guide_mutation_failed = match append_accepted_field_guide_drafts_authorized(
        &plan,
        &collected.orchestrator_reports,
        &options.run_id,
        field_guide_store_slot.as_ref(),
        &mut orchestration_journal,
        &mut artifact_writer,
        &field_guide_permit,
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
    let publishable = success && runtime == SupervisorRuntime::Codex;
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
            require_supervisor_operation(
                &mutation_session,
                MutationOperation::SupervisorCheckpointJournalLifecycle,
            )?;
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
            return Err(error).context("failed to write normalized supervisor final report")
        }
    };
    persist_supervisor_final_report(
        final_report,
        &mut orchestration_journal,
        artifact_writer,
        checkpoint_finalization.then_some(&mut checkpoint_writer),
        (!external_containment_failed)
            .then_some(crate::artifacts::ArtifactScratchQuiescence::Verified),
        &mutation_session,
        || {
            let claim_permit = mutation_session.permit(MutationOperation::ClaimRelease)?;
            let semantic_permit =
                mutation_session.permit(MutationOperation::SemanticIntentRelease)?;
            let released = release_collected_scheduler_resources(
                sync_store_slot.as_ref(),
                semantic_store_slot.as_ref(),
                &mut scheduler_resources,
                &claim_permit,
                &semantic_permit,
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
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SELECTOR_TEST_TARGET: &str = "tests/selector.rs";

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

    fn automatic_selection_fixture() -> Result<(
        RuntimeModelCatalog,
        SupervisorAutomaticSelectionState,
        Vec<SupervisorSelectionEvent>,
        SupervisorPlan,
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
        let mut plan = test_plan();
        let resolved_objective_profile = default_resolved_objective_profile()?;
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &AdvertisedCatalogSet::empty(),
            Some(&resolved_objective_profile),
        )?;
        Ok((
            catalog,
            resolution
                .automatic_state
                .context("automatic selector same-run state")?,
            resolution.decisions,
            plan,
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
        let (catalog, _, initial_events, mut plan) = automatic_selection_fixture()?;
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
        let (catalog, _, initial_events, mut plan) = automatic_selection_fixture()?;
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
                "gpt-5.6-sol",
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
    fn real_supervisor_sink_rejects_invalid_permit_before_process_or_artifact() -> Result<()> {
        let (temporary, repo) = initialized_repository();
        let mut options = predispatch_options(&repo, temporary.path(), "supervisor-invalid-permit");
        options.runtime = SupervisorRuntime::Fake;
        let error = reserve_supervisor_artifact_run(
            &repo,
            RunArtifactFamily::Supervise,
            options.run_id.clone(),
            "maco-supervise",
            &crate::mutation_taxonomy::SupervisorOperationPermit::invalid_for_test(),
        )
        .err()
        .context("invalid Supervisor permit must fail at the real mutation sink")?;

        assert!(error
            .to_string()
            .contains("permit for a different operation"));
        assert!(!repo
            .join(RunArtifactFamily::Supervise.run_root())
            .join(options.run_id.as_str())
            .exists());
        Ok(())
    }

    #[test]
    fn preclaim_runtime_is_derived_separately_from_effect_containment() -> Result<()> {
        skip_without_containment!(ok);
        let (_temporary, repo) = initialized_repository();
        let manager = WorktreeManager::new(&repo);
        let cleanliness = manager.acquire_repository_cleanliness()?;
        let primary_execution_target = SupervisorExecutionTarget::PrimaryWorktree {
            claim_paths: Vec::new(),
        };
        let primary_worktree_opt_in = primary_worktree_opt_in_for_test(&primary_execution_target);

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
                SupervisorWorktreeCreation::PrimaryWorktree(&primary_worktree_opt_in),
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
        assert!(active_plan
            .review_lenses
            .iter()
            .all(|lens| { lens.backend.reasoning_effort() == Some("xhigh") }));

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
                Some(ReasoningEffort::Low)
            );
            assert_eq!(auditor.fallback_reasoning_effort, "xhigh");
            assert_eq!(auditor.resolved_reasoning_effort, "xhigh");
            assert_eq!(
                auditor.resolution_observation,
                EffortResolutionObservation::HardFloorClamped
            );
            assert!(auditor
                .unavailable_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("retry-time active effort")));
        }
    }

    #[test]
    fn completed_retry_promotes_matching_execution_override_and_reroute_state() -> Result<()> {
        let (catalog, state, _, plan) = automatic_selection_fixture()?;
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
        controller
            .commit_completed_selection_prefix(&indexed_outcomes, SupervisorRuntime::Codex)?;

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
    fn concurrent_retries_share_predispatch_state_and_commit_in_schedule_order() -> Result<()> {
        let (catalog, state, initial_events, plan) = automatic_selection_fixture()?;
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
                handles.push(scope.spawn(
                    move || -> Result<(usize, SupervisorSelectionEvent, RoleModelSelection)> {
                        barrier.wait();
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
        controller
            .commit_completed_selection_prefix(&indexed_outcomes, SupervisorRuntime::Codex)?;
        assert_eq!(controller.next_selection_commit_index, 0);

        indexed_outcomes[0] = Some(AssignmentExecutionOutcome {
            selection_decisions: vec![completed[0].1.clone()],
            ..AssignmentExecutionOutcome::default()
        });
        controller
            .commit_completed_selection_prefix(&indexed_outcomes, SupervisorRuntime::Codex)?;
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
        let mut plan = test_plan();
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
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &AdvertisedCatalogSet::empty(),
            Some(&resolved_objective_profile),
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
        }];
        let requested_plan = plan.clone();
        let catalog = test_runtime_model_catalog(&plan, SupervisorRuntime::Codex)?;
        let options =
            predispatch_options(&repo, temporary.path(), "automatic-requested-plan-identity");

        let prepared = prepare_supervisor_run_for_test(
            LoadedSupervisorPlan {
                plan,
                consultant: SupervisorConsultantPlan::default(),
                assignment_metadata: AssignmentMetadata::new(),
                plan_metadata: SupervisorPlanMetadata::default(),
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
        assert_eq!(prepared.plan.role_models.len(), 5);
        assert_ne!(prepared.plan, prepared.requested_plan);
        let effective_sha256 = normalized_supervisor_plan_sha256(
            &prepared.plan,
            &prepared.consultant,
            &prepared.assignment_metadata,
            &prepared.plan_metadata,
        )?;
        let mutation_evidence: Value = serde_json::from_slice(&fs::read(
            prepared.run_dir.join("effective-mutation-manifest.json"),
        )?)?;
        assert_eq!(
            mutation_evidence["normalized_plan_sha256"],
            Value::String(effective_sha256)
        );
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
        let admission = SupervisorAdmissionPolicyInput::resolve(
            &repo,
            1,
            SupervisorAdmissionConfig::default(),
            SupervisorAdmissionConfig::default(),
        )?;
        let mut bridge_plan = plan.clone();
        let resolved_objective_profile = default_resolved_objective_profile()?;
        let bridge_resolution = initialize_supervisor_selection(
            &mut bridge_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &AdvertisedCatalogSet::empty(),
            Some(&resolved_objective_profile),
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
        let runner = |_command: &ExternalAgentCommand,
                      _cancellation: &ProcessCancellation,
                      _review_runtime: Option<ExternalPreActionReviewRuntime<'_>>,
                      _authorization: SupervisorProcessLaunchAuthorization| {
            calls.fetch_add(1, Ordering::SeqCst);
            panic!("selection preflight failure must prevent external dispatch")
        };

        let report = authorize_and_run_supervisor_plan_with_runner_and_creation(
            LoadedSupervisorPlan {
                plan,
                consultant: SupervisorConsultantPlan::default(),
                assignment_metadata: AssignmentMetadata::new(),
                plan_metadata: SupervisorPlanMetadata::default(),
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
            normalized_auditor.reasoning_effort.as_deref(),
            Some("xhigh")
        );
        let events = &profile
            .execution
            .as_ref()
            .context("selection failure execution metadata")?
            .selection_decisions;
        assert_eq!(events.len(), provisional_default_role_models().len());
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
}

#[cfg(test)]
mod decomposition_tests;
