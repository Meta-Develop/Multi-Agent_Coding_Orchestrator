use super::*;

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
    plan: &'context SupervisorPlan,
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
    health_breaker: SwarmHealthCircuitBreaker,
    budget_prevented_dispatch: bool,
    budget_denied_assignment_indices: BTreeSet<usize>,
    circuit_breaker_trip: Option<CircuitBreakerTrip>,
    concurrency: SchedulerConcurrencyTracker,
    budget_degradation: BudgetDegradationController,
}

impl SchedulerProgress {
    fn new(assignment_count: usize, max_concurrent_children: usize) -> Self {
        Self {
            indexed_outcomes: (0..assignment_count).map(|_| None).collect(),
            health_breaker: SwarmHealthCircuitBreaker::default(),
            budget_prevented_dispatch: false,
            budget_denied_assignment_indices: BTreeSet::new(),
            circuit_breaker_trip: None,
            concurrency: SchedulerConcurrencyTracker::new(),
            budget_degradation: BudgetDegradationController::new(max_concurrent_children),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct AssignmentBudgetPolicy {
    model_overrides: BTreeMap<AgentRole, RoleModelSelection>,
    child_effort_degradation_steps: usize,
    assignment_reasoning_effort: Option<ReasoningEffort>,
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
                if role == AgentRole::ChildOrchestrator {
                    self.child_effort_degradation_steps
                } else {
                    0
                },
            );
            selection.reasoning_effort = Some(resolved.resolved);
            effective.role_models.insert(role, selection);
        }
        effective
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum BudgetDegradationRung {
    #[default]
    Effort,
    ModelTier,
    FanOut,
    Exhausted,
}

#[derive(Debug, Clone)]
struct BudgetDegradationController {
    rung: BudgetDegradationRung,
    policy: AssignmentBudgetPolicy,
    effective_fan_out: usize,
    records: Vec<BudgetDegradationRecord>,
    assignment_effort_bindings: Vec<AssignmentEffortBinding>,
    last_new_dispatch_allowed: bool,
}

impl BudgetDegradationController {
    fn new(max_concurrent_children: usize) -> Self {
        Self {
            rung: BudgetDegradationRung::Effort,
            policy: AssignmentBudgetPolicy::default(),
            effective_fan_out: max_concurrent_children.max(1),
            records: Vec::new(),
            assignment_effort_bindings: Vec::new(),
            last_new_dispatch_allowed: true,
        }
    }

    fn assignment_policy(
        &mut self,
        assignment: &OrchestratorAssignment,
        requested_reasoning_effort: Option<ReasoningEffort>,
        report: &RunBudgetReport,
        plan: &SupervisorPlan,
        catalog: &RuntimeModelCatalog,
        runtime: SupervisorRuntime,
    ) -> Result<Option<AssignmentBudgetPolicy>> {
        if !report.new_dispatch_allowed || report.action == BudgetAction::OwnerEscalation {
            self.record_halt(&assignment.id, report);
            return Ok(None);
        }
        if report.action == BudgetAction::Degrade
            && report.reasons.iter().any(|reason| {
                matches!(
                    reason,
                    BudgetReason::SoftTokenCeilingReached | BudgetReason::SoftCostCeilingReached
                )
            })
        {
            self.advance(
                assignment,
                requested_reasoning_effort,
                report,
                plan,
                catalog,
                runtime,
            )?;
        }
        self.last_new_dispatch_allowed = report.new_dispatch_allowed;
        let mut policy = self.policy.clone();
        policy.assignment_reasoning_effort = requested_reasoning_effort;
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
        assignment: &OrchestratorAssignment,
        requested_reasoning_effort: Option<ReasoningEffort>,
        report: &RunBudgetReport,
        plan: &SupervisorPlan,
        catalog: &RuntimeModelCatalog,
        runtime: SupervisorRuntime,
    ) -> Result<()> {
        let change = match self.rung {
            BudgetDegradationRung::Effort => {
                let before = resolve_reasoning_effort(
                    AgentRole::ChildOrchestrator,
                    requested_reasoning_effort,
                    effective_role_model_selection(plan, AgentRole::ChildOrchestrator)
                        .reasoning_effort
                        .as_deref(),
                    self.policy.child_effort_degradation_steps,
                )
                .resolved;
                self.policy.child_effort_degradation_steps =
                    self.policy.child_effort_degradation_steps.saturating_add(1);
                let after = resolve_reasoning_effort(
                    AgentRole::ChildOrchestrator,
                    requested_reasoning_effort,
                    effective_role_model_selection(plan, AgentRole::ChildOrchestrator)
                        .reasoning_effort
                        .as_deref(),
                    self.policy.child_effort_degradation_steps,
                )
                .resolved;
                self.rung = BudgetDegradationRung::ModelTier;
                BudgetDegradationChange::ReasoningEffort {
                    role: AgentRole::ChildOrchestrator,
                    before,
                    after,
                }
            }
            BudgetDegradationRung::ModelTier => {
                let configured = self
                    .policy
                    .model_overrides
                    .get(&AgentRole::ChildOrchestrator)
                    .cloned()
                    .unwrap_or_else(|| {
                        effective_role_model_selection(plan, AgentRole::ChildOrchestrator)
                    });
                let resolved = catalog.resolve_role_model_selection(&configured, runtime)?;
                let Some(before) = resolved.selection.model.clone() else {
                    self.rung = BudgetDegradationRung::FanOut;
                    return self.advance(
                        assignment,
                        requested_reasoning_effort,
                        report,
                        plan,
                        catalog,
                        runtime,
                    );
                };
                let candidates = match &configured.unavailable_model_fallback {
                    UnavailableModelFallback::OrderedCatalogChain(chain) => {
                        &chain.budget_degrade_models
                    }
                    _ => {
                        self.rung = BudgetDegradationRung::FanOut;
                        return self.advance(
                            assignment,
                            requested_reasoning_effort,
                            report,
                            plan,
                            catalog,
                            runtime,
                        );
                    }
                };
                let Some((resolved_candidate_index, after)) = candidates
                    .iter()
                    .enumerate()
                    .find(|(_, model)| {
                        model.as_str() != before
                            && catalog
                                .availability(Some(model.as_str()), runtime)
                                .is_ok_and(|availability| {
                                    availability == RoleModelAvailability::Available
                                })
                    })
                    .map(|(index, model)| (index, model.clone()))
                else {
                    self.rung = BudgetDegradationRung::FanOut;
                    return self.advance(
                        assignment,
                        requested_reasoning_effort,
                        report,
                        plan,
                        catalog,
                        runtime,
                    );
                };
                self.policy.model_overrides.insert(
                    AgentRole::ChildOrchestrator,
                    RoleModelSelection {
                        model: Some(after.clone()),
                        reasoning_effort: None,
                        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
                    },
                );
                self.rung = BudgetDegradationRung::FanOut;
                BudgetDegradationChange::ModelTier {
                    role: AgentRole::ChildOrchestrator,
                    before,
                    after,
                    resolved_candidate_index,
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
        let effective = effective_role_model_selection(&effective, AgentRole::ChildOrchestrator);
        let resolved = catalog.resolve_role_model_selection(&effective, runtime)?;
        self.records.push(BudgetDegradationRecord {
            sequence: self.records.len().saturating_add(1),
            assignment_id: assignment.id.clone(),
            budget_action: report.action,
            budget_reasons: report.reasons.clone(),
            change,
            effective_child_model: resolved.selection.model,
            effective_child_reasoning_effort: resolved.selection.reasoning_effort,
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
            budget_action: report.action,
            budget_reasons: report.reasons.clone(),
            change: BudgetDegradationChange::Halt {
                before_new_dispatch_allowed: self.last_new_dispatch_allowed,
                after_new_dispatch_allowed: report.new_dispatch_allowed,
            },
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
        let mut push = |duty_id: String,
                        role: AgentRole,
                        requested: Option<ReasoningEffort>,
                        fallback: Option<&str>,
                        budget_steps: usize,
                        process_observation: ProcessObservation,
                        unavailable_reason: Option<String>| {
            let resolved = resolve_reasoning_effort(role, requested, fallback, budget_steps);
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
        push(
            assignment.id.clone(),
            AgentRole::ChildOrchestrator,
            requested_reasoning_effort,
            child_fallback.as_deref(),
            policy.child_effort_degradation_steps,
            ProcessObservation::SchedulerObserved,
            None,
        );
        let worker_fallback =
            configured_role_model_selection(plan, AgentRole::Worker).reasoning_effort;
        for worker in &assignment.worker_assignments {
            push(
                worker.id.clone(),
                AgentRole::Worker,
                requested_reasoning_effort,
                worker_fallback.as_deref(),
                0,
                ProcessObservation::NotProcessObservable,
                Some(
                    "nested worker effort is resolved in prompt context; no separate worker process is launched"
                        .to_string(),
                ),
            );
        }
        let gate_fallback =
            configured_role_model_selection(plan, AgentRole::GateClassifier).reasoning_effort;
        push(
            format!("{}-acceptance-gate", assignment.id),
            AgentRole::GateClassifier,
            requested_reasoning_effort,
            gate_fallback.as_deref(),
            0,
            ProcessObservation::NotProcessObservable,
            Some(
                "the current acceptance-gate classifier is a deterministic local broker without provider reasoning-effort telemetry"
                    .to_string(),
            ),
        );
        let auditor_fallback =
            configured_role_model_selection(plan, AgentRole::Auditor).reasoning_effort;
        for (lens_index, lens) in plan.review_lenses.iter().enumerate() {
            let requested = requested_reasoning_effort.or_else(|| {
                lens.backend
                    .reasoning_effort()
                    .and_then(ReasoningEffort::parse)
            });
            push(
                review_lens_auditor_id(assignment, lens_index),
                AgentRole::Auditor,
                requested,
                auditor_fallback.as_deref(),
                0,
                ProcessObservation::NotRetained,
                Some(
                    "the scheduler resolved this review-auditor duty; inspect commands_run for launch evidence"
                        .to_string(),
                ),
            );
        }
    }
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

fn run_serial_assignment_schedule(
    context: &AssignmentSchedulerContext<'_, '_>,
    progress: &mut SchedulerProgress,
    cancellation: &ProcessCancellation,
    serial_semantic_warn_intents: &Mutex<Vec<(usize, SemanticIntent)>>,
) -> Result<()> {
    let mut pending = (0..context.plan.assignments.len()).collect::<BTreeSet<_>>();
    while !pending.is_empty() {
        suppress_failed_descendants(
            &mut pending,
            &mut progress.indexed_outcomes,
            context.plan,
            context.assignment_schedule,
            context.artifacts,
        )?;
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
        let Some(budget_policy) = progress.budget_degradation.assignment_policy(
            &context.plan.assignments[index],
            context
                .assignment_metadata
                .reasoning_effort(&context.plan.assignments[index].id),
            &budget_report,
            context.plan,
            context.runtime_model_catalog,
            context.options.runtime,
        )?
        else {
            progress.budget_prevented_dispatch = true;
            progress
                .budget_denied_assignment_indices
                .extend(pending.iter().copied());
            break;
        };
        pending.remove(&index);
        let assignment = &context.plan.assignments[index];
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
                    let Some(budget_policy) = progress.budget_degradation.assignment_policy(
                        &context.plan.assignments[index],
                        context
                            .assignment_metadata
                            .reasoning_effort(&context.plan.assignments[index].id),
                        &budget_report,
                        context.plan,
                        context.runtime_model_catalog,
                        context.options.runtime,
                    )?
                    else {
                        progress.budget_prevented_dispatch |= !pending.is_empty();
                        progress
                            .budget_denied_assignment_indices
                            .extend(pending.iter().copied());
                        stop_scheduling = true;
                        break;
                    };
                    if active.len() >= progress.budget_degradation.effective_fan_out {
                        break;
                    }
                    pending.remove(&index);
                    let assignment = &context.plan.assignments[index];
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
                        execute_supervisor_assignment(AssignmentExecutionContext {
                            index,
                            concurrent_mode: true,
                            plan: context.plan,
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
                            admission_receiver.recv().with_context(|| {
                                format!(
                                    "supervisor assignment '{}' ended before committing or declining budget admission",
                                    assignment.id
                                )
                            })?;
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
            release_concurrent_assignment(&mut outcome, context.sync_store, context.semantic_store);
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
) -> BTreeMap<AgentRole, ResolvedRoleExecutionBinding> {
    [
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ]
    .into_iter()
    .map(|role| {
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
    let generated_follow_up_tasks = collected
        .orchestrator_reports
        .iter()
        .flat_map(|report| report.generated_follow_up_tasks.iter().cloned())
        .collect::<Vec<_>>();
    let generated_follow_up_task_count = generated_follow_up_tasks.len();
    let role_usage = complete_role_usage_reports(role_usage);
    let mut role_economics_profile =
        execution_role_economics_profile(plan, runtime, runtime_model_catalog);
    let mut role_bindings = resolved_role_execution_bindings(plan, runtime, runtime_model_catalog);
    if budget_degradations.iter().any(|record| {
        matches!(
            record.change,
            BudgetDegradationChange::ReasoningEffort { .. }
                | BudgetDegradationChange::ModelTier { .. }
        )
    }) {
        if let Some(binding) = role_bindings.get_mut(&AgentRole::ChildOrchestrator) {
            binding.resolved_model = None;
            binding.resolved_reasoning_effort = None;
            binding.observation = RoleBindingObservation::AssignmentSpecific;
            binding.resolution_observation = ModelResolutionObservation::NotResolved;
            binding.resolved_candidate_index = None;
            binding.unavailable_reason = Some(
                "budget pressure produced assignment-specific child model or effort bindings; inspect budget_degradations for the resolved per-assignment policy and commands_run for process evidence"
                    .to_string(),
            );
        }
    }
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
    role_economics_profile.execution = Some(SupervisorExecutionMetadata {
        assignment_count: plan.assignments.len(),
        started_assignment_count: achieved_concurrency.started_assignment_count,
        completed_assignment_count: achieved_concurrency.completed_assignment_count,
        concurrency: SupervisorConcurrencyReport {
            configured_max_concurrent_children: max_concurrent_children,
            policy_input_observation: ProcessObservation::SchedulerObserved,
            policy_input: Some(
                serde_json::to_string(&admission_policy_input)
                    .expect("admission policy input is JSON serializable"),
            ),
            policy_input_details: Some(admission_policy_input),
            policy_input_unavailable_reason: None,
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

    fn already_released(&self) -> ReleasedSchedulerResources {
        ReleasedSchedulerResources {
            released_claims: self.concurrently_released_claims.clone(),
            release_errors: self.concurrent_release_errors.clone(),
            released_semantic_intents: self.concurrently_released_semantic_intents.clone(),
            semantic_release_errors: self.concurrent_semantic_release_errors.clone(),
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

fn persist_supervisor_final_report(
    mut final_report: SupervisorFinalReport,
    orchestration_journal: &mut Option<OrchestrationEventJournal>,
    mut artifact_writer: ArtifactRunWriter,
    checkpoint_writer: Option<&mut SupervisorCheckpointWriter>,
    release_after_terminal_record: impl FnOnce() -> Result<()>,
) -> Result<SupervisorFinalReport> {
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
    let report_bytes = encode_final_report(&final_report)?;
    let mut checkpoint_writer = checkpoint_writer;
    if let Some(checkpoint) = checkpoint_writer.as_deref_mut() {
        let artifact_binding = artifact_writer
            .resume_binding()
            .context("failed to establish a durable terminal supervisor report boundary")?;
        checkpoint
            .final_report_planned(&final_report, &report_bytes, artifact_binding)
            .context("failed to persist the terminal supervisor report plan")?;
        release_after_terminal_record()
            .context("failed to release scheduler resources after the durable terminal record")?;
    }
    artifact_writer
        .write_bytes(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &report_bytes,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .context("failed to write normalized supervisor final report")?;
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
    write_worker_schema(
        initialization.artifact_writer,
        Path::new("schemas/worker-report.schema.json"),
    )?;
    write_auditor_schema(
        initialization.artifact_writer,
        Path::new("schemas/auditor-report.schema.json"),
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
    record_orchestration_event(
        initialization.orchestration_journal,
        initialization.artifact_writer,
        initialization.options.run_id.as_str(),
        None,
        OrchestrationRole::Supervisor,
        OrchestrationEventKind::Status,
        lifecycle_event_payload("running", None, None),
    );

    let baseline =
        primary_worktree_snapshot(initialization.repo, initialization.execution_runtime)?;
    if let Some(error) = baseline.inspection_problem() {
        bail!(
            "refusing to launch supervised work without a complete primary integrity snapshot: {error}"
        );
    }
    *initialization.primary_run_baseline = Some(baseline);
    Ok(())
}

struct PreparedSupervisorRun {
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    assignment_metadata: AssignmentMetadata,
    plan_metadata: SupervisorPlanMetadata,
    max_concurrent_children: usize,
    admission_policy_input: SupervisorAdmissionPolicyInput,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
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
}

fn prepare_supervisor_run(
    loaded: LoadedSupervisorPlan,
    options: &SupervisorRunOptions,
    max_concurrent_children: usize,
    execution_runtime: SupervisorExecutionRuntime,
    worktree_creation: SupervisorWorktreeCreation<'_>,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
) -> Result<PreparedSupervisorRun> {
    let LoadedSupervisorPlan {
        plan,
        consultant,
        assignment_metadata,
        mut plan_metadata,
    } = loaded;
    validate_max_concurrent_children(max_concurrent_children)?;
    plan_metadata.run_budget.limits = plan_metadata
        .run_budget
        .limits
        .strictest(options.budget_overrides)
        .context("failed to compose plan and CLI run budgets")?;
    let max_duration_seconds = match (
        plan_metadata.run_budget_max_duration_seconds,
        options.budget_max_duration_seconds,
    ) {
        (Some(plan), Some(cli)) => Some(plan.min(cli)),
        (plan, cli) => plan.or(cli),
    };
    let budget_ledger =
        RunBudgetLedger::new_with_duration(plan_metadata.run_budget.limits, max_duration_seconds)
            .context("failed to initialize the supervise run budget ledger")?;
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
        SupervisorWorktreeCreation::PrimaryWorktree
            if execution_runtime != SupervisorExecutionRuntime::Verified =>
        {
            bail!("primary-worktree execution requires the verified supervisor runtime")
        }
        #[cfg(test)]
        SupervisorWorktreeCreation::TestOnly
            if execution_runtime != SupervisorExecutionRuntime::NonpublishableSimulation =>
        {
            bail!("test-only worktree creation requires the simulation supervisor runtime")
        }
        _ => {}
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
    let repo = discover_repo_root(&options.repo)?;
    let admission_policy_input = SupervisorAdmissionPolicyInput::resolve(
        &repo,
        max_concurrent_children,
        plan_metadata.admission,
        options.admission_overrides,
    )?;
    let max_concurrent_children = admission_policy_input.resolved_bound;
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
    let artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        options.run_id.clone(),
        "maco-supervise",
    )?;
    let primary_base = current_head_oid(&repo)?;
    let normalized_plan_sha256 = normalized_supervisor_plan_sha256(
        &plan,
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
            &plan,
            artifact_writer.resume_binding()?,
            budget_ledger.report()?,
        ),
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    let dirs = RunDirs::for_writer(&artifact_writer);
    let manager = WorktreeManager::new(&repo);
    Ok(PreparedSupervisorRun {
        plan,
        consultant,
        assignment_metadata,
        plan_metadata,
        max_concurrent_children,
        admission_policy_input,
        runtime_model_catalog,
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
    })
}

struct RuntimeModelCatalogFailureFinalization<'context, 'checkpoint> {
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
}

fn persist_runtime_model_catalog_environment_failure(
    finalization: RuntimeModelCatalogFailureFinalization<'_, '_>,
    failure: EnvironmentFailure,
) -> Result<SupervisorFinalReport> {
    let RuntimeModelCatalogFailureFinalization {
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
    } = finalization;
    let run_budget_report = budget_ledger.report()?;
    let (report_plan_file, report_run_dir) =
        supervisor_report_paths(repo, &options.plan_file, run_dir, &options.run_id);
    let mut collected = CollectedAssignmentOutcomes::default();
    collected.findings.push(Finding {
        severity: FindingSeverity::Error,
        message: "runtime model catalog preflight blocked supervisor dispatch; inspect the typed environment_failures entry"
            .to_string(),
        paths: Vec::new(),
    });
    let mut final_report = build_supervisor_final_report(SupervisorFinalReportConstruction {
        plan,
        runtime_model_catalog: None,
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
        environment_failures: vec![failure],
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
    apply_execution_target_reporting(&mut final_report, plan_metadata.execution_target.as_ref());
    let binding = artifact_writer
        .resume_binding()
        .context("failed to establish runtime-catalog preflight report boundary")?;
    checkpoint_writer.scheduler_closed(binding, run_budget_report)?;
    let mut orchestration_journal = None;
    persist_supervisor_final_report(
        final_report,
        &mut orchestration_journal,
        artifact_writer,
        Some(checkpoint_writer),
        || Ok(()),
    )
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
        consultant,
        assignment_metadata,
        plan_metadata,
        max_concurrent_children,
        admission_policy_input,
        runtime_model_catalog,
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
    } = prepare_supervisor_run(
        loaded,
        &options,
        max_concurrent_children,
        execution_runtime,
        worktree_creation,
        runtime_model_catalog,
    )?;
    // Runtime catalog acquisition is the first dispatch-capable environment preflight. A typed
    // failure is finalized here and deliberately short-circuits every assignment environment
    // preflight, which can begin only inside `external_runner` below.
    let runtime_model_catalog = match runtime_model_catalog {
        Ok(catalog) => catalog,
        Err(failure) => {
            return persist_runtime_model_catalog_environment_failure(
                RuntimeModelCatalogFailureFinalization {
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
                },
                *failure,
            );
        }
    };
    let budget_config = &plan_metadata.run_budget;
    let mut sync_store_slot = None;
    let mut semantic_store_slot = None;
    let mut field_guide_store_slot = None;
    let mut field_guide_prompt_slot = None;
    let mut orchestration_journal = None;
    let mut autonomy_kpi_collector = AutonomyKpiCollector::default();
    let mut collected = CollectedAssignmentOutcomes::default();
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
            plan: &plan,
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
            let mut progress =
                SchedulerProgress::new(plan.assignments.len(), max_concurrent_children);
            let scheduler_context = AssignmentSchedulerContext {
                plan: &plan,
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
                if let Err(error) = run_serial_assignment_schedule(
                    &scheduler_context,
                    &mut progress,
                    &cancellation,
                    &serial_semantic_warn_intents,
                ) {
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
                    budget_denied_assignment_indices
                        .extend(progress.budget_denied_assignment_indices);
                    budget_degradations.append(&mut progress.budget_degradation.records);
                    assignment_effort_bindings
                        .append(&mut progress.budget_degradation.assignment_effort_bindings);
                    circuit_breaker_trip = progress.circuit_breaker_trip;
                    return Err(error);
                }
                Ok(())
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
        Some(baseline) => match primary_worktree_snapshot(&repo, execution_runtime) {
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
            message: "worker usage is not process-observable because nested workers execute inside child Codex sessions; child-orchestrator and auditor process usage remains reportable, while runtime-side role-tagged usage reporting is required before worker usage or cost can be reported"
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
    apply_execution_target_reporting(&mut final_report, plan_metadata.execution_target.as_ref());
    let checkpoint_finalization = match artifact_writer.resume_binding() {
        Ok(binding) => {
            checkpoint_writer.scheduler_closed(binding, budget_ledger.report()?)?;
            true
        }
        Err(error)
            if error
                .to_string()
                .contains("not at a resumable manifest boundary") =>
        {
            let already_released = scheduler_resources.already_released();
            final_report.claim_tokens = already_released
                .released_claims
                .iter()
                .map(|claim| claim.token.get())
                .collect();
            final_report.semantic_intent_tokens = already_released
                .released_semantic_intents
                .iter()
                .map(|intent| intent.token.get())
                .collect();
            final_report.released_claims = already_released.released_claims;
            final_report.release_errors = already_released.release_errors;
            final_report.released_semantic_intents = already_released.released_semantic_intents;
            final_report.semantic_release_errors = already_released.semantic_release_errors;
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
mod decomposition_tests {
    use super::*;
    use crate::orchestration_event::{OrchestrationEvent, ORCHESTRATION_EVENT_PATH};
    use git2::Signature;

    static TEST_RUNTIME_MODEL_CATALOG: RuntimeModelCatalog =
        RuntimeModelCatalog::LocalDeterministicFake;

    fn test_assignment(id: &str, path: &str) -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: id.to_string(),
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            assigned_paths: vec![PathBuf::from(path)],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        }
    }

    fn test_plan(assignments: Vec<OrchestratorAssignment>) -> SupervisorPlan {
        SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "scheduler decomposition fixture".to_string(),
            task_file: None,
            max_depth: MIN_SUPERVISOR_DEPTH,
            max_child_assignments: assignments.len(),
            max_child_retries: 0,
            max_gate_corrections: 0,
            child_timeout_seconds: 10,
            semantic_coordination: SemanticCoordinationMode::Off,
            role_models: BTreeMap::new(),
            model_pricing: BTreeMap::new(),
            review_lenses: default_supervisor_review_lenses(),
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments,
        }
    }

    #[test]
    fn role_binding_telemetry_retains_catalog_fallback_resolution() {
        let mut plan = test_plan(Vec::new());
        plan.role_models.insert(
            AgentRole::ChildOrchestrator,
            RoleModelSelection {
                model: Some(BALANCED_PROFILE_MODEL.to_string()),
                reasoning_effort: Some("xhigh".to_string()),
                unavailable_model_fallback: UnavailableModelFallback::OrderedCatalogChain(
                    OrderedCatalogFallback {
                        models: vec![
                            FRONTIER_PROFILE_MODEL.to_string(),
                            ECONOMY_PROFILE_MODEL.to_string(),
                        ],
                        budget_degrade_models: vec![ECONOMY_PROFILE_MODEL.to_string()],
                        on_exhausted: TerminalUnavailableModelFallback::RuntimeDefault,
                    },
                ),
            },
        );
        let catalog = RuntimeModelCatalog::Codex(
            CodexRuntimeModelCatalog::from_slugs([FRONTIER_PROFILE_MODEL])
                .expect("fallback catalog"),
        );
        let bindings =
            resolved_role_execution_bindings(&plan, SupervisorRuntime::Codex, Some(&catalog));
        let binding = &bindings[&AgentRole::ChildOrchestrator];
        assert_eq!(
            binding.configured_model.as_deref(),
            Some(BALANCED_PROFILE_MODEL)
        );
        assert_eq!(
            binding.resolved_model.as_deref(),
            Some(FRONTIER_PROFILE_MODEL)
        );
        assert_eq!(
            binding.observation,
            RoleBindingObservation::RuntimeCatalogResolved
        );
        assert_eq!(
            binding.resolution_observation,
            ModelResolutionObservation::CatalogFallback
        );
        assert_eq!(binding.resolved_candidate_index, Some(1));
        assert_eq!(
            binding.configured_model_chain,
            vec![
                BALANCED_PROFILE_MODEL.to_string(),
                FRONTIER_PROFILE_MODEL.to_string(),
                ECONOMY_PROFILE_MODEL.to_string()
            ]
        );
    }

    #[test]
    fn budget_degrade_ladder_applies_effort_model_fanout_then_halts() {
        let plan = test_plan(Vec::new());
        let effort_assignment = test_assignment("effort-assignment", "effort.txt");
        let model_assignment = test_assignment("model-assignment", "model.txt");
        let fanout_assignment = test_assignment("fanout-assignment", "fanout.txt");
        let halted_assignment = test_assignment("halted-assignment", "halted.txt");
        let catalog = RuntimeModelCatalog::Codex(
            CodexRuntimeModelCatalog::from_slugs([
                FRONTIER_PROFILE_MODEL,
                BALANCED_PROFILE_MODEL,
                ECONOMY_PROFILE_MODEL,
            ])
            .expect("degradation catalog"),
        );
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            soft_tokens: Some(1),
            hard_tokens: Some(4),
            soft_cost_usd: None,
            hard_cost_usd: None,
        })
        .expect("degradation ledger");
        let soft = ledger
            .reserve(BudgetReservationRequest {
                role: AgentRole::ChildOrchestrator,
                tokens: 1,
                cost_usd: None,
            })
            .expect("soft reservation")
            .report()
            .clone();
        assert_eq!(soft.action, BudgetAction::Degrade);

        let mut controller = BudgetDegradationController::new(8);
        let effort_policy = controller
            .assignment_policy(
                &effort_assignment,
                None,
                &soft,
                &plan,
                &catalog,
                SupervisorRuntime::Codex,
            )
            .expect("effort degradation")
            .expect("effort admission");
        assert_eq!(
            effort_policy.apply(&plan).role_models[&AgentRole::ChildOrchestrator]
                .reasoning_effort
                .as_deref(),
            Some("high")
        );
        let model_policy = controller
            .assignment_policy(
                &model_assignment,
                None,
                &soft,
                &plan,
                &catalog,
                SupervisorRuntime::Codex,
            )
            .expect("model degradation")
            .expect("model admission");
        assert_eq!(
            model_policy.apply(&plan).role_models[&AgentRole::ChildOrchestrator]
                .model
                .as_deref(),
            Some(BALANCED_PROFILE_MODEL)
        );
        controller
            .assignment_policy(
                &fanout_assignment,
                None,
                &soft,
                &plan,
                &catalog,
                SupervisorRuntime::Codex,
            )
            .expect("fan-out degradation")
            .expect("fan-out admission");
        assert_eq!(controller.effective_fan_out, 4);

        let hard = ledger
            .reserve(BudgetReservationRequest {
                role: AgentRole::ChildOrchestrator,
                tokens: 3,
                cost_usd: None,
            })
            .expect("hard reservation")
            .report()
            .clone();
        assert_eq!(hard.action, BudgetAction::OwnerEscalation);
        assert!(controller
            .assignment_policy(
                &halted_assignment,
                None,
                &hard,
                &plan,
                &catalog,
                SupervisorRuntime::Codex,
            )
            .expect("halt decision")
            .is_none());

        assert_eq!(controller.records.len(), 4);
        assert!(matches!(
            &controller.records[0].change,
            BudgetDegradationChange::ReasoningEffort { before, after, .. }
                if before == "xhigh" && after == "high"
        ));
        assert!(matches!(
            &controller.records[1].change,
            BudgetDegradationChange::ModelTier {
                before,
                after,
                resolved_candidate_index: 0,
                ..
            } if before == FRONTIER_PROFILE_MODEL && after == BALANCED_PROFILE_MODEL
        ));
        assert_eq!(
            controller.records[2].change,
            BudgetDegradationChange::FanOut {
                before: 8,
                after: 4
            }
        );
        assert_eq!(
            controller.records[3].change,
            BudgetDegradationChange::Halt {
                before_new_dispatch_allowed: true,
                after_new_dispatch_allowed: false
            }
        );
        assert_eq!(
            serde_json::to_value(&controller.records).expect("degradation artifact sample"),
            json!([
                {
                    "sequence": 1,
                    "assignment_id": "effort-assignment",
                    "budget_action": "degrade",
                    "budget_reasons": ["soft_token_ceiling_reached", "missing_pricing"],
                    "change": {"kind": "reasoning_effort", "role": "child_orchestrator", "before": "xhigh", "after": "high"},
                    "effective_child_model": FRONTIER_PROFILE_MODEL,
                    "effective_child_reasoning_effort": "high",
                    "effective_fan_out": 8,
                    "observation": "admission_policy_resolved"
                },
                {
                    "sequence": 2,
                    "assignment_id": "model-assignment",
                    "budget_action": "degrade",
                    "budget_reasons": ["soft_token_ceiling_reached", "missing_pricing"],
                    "change": {"kind": "model_tier", "role": "child_orchestrator", "before": FRONTIER_PROFILE_MODEL, "after": BALANCED_PROFILE_MODEL, "resolved_candidate_index": 0},
                    "effective_child_model": BALANCED_PROFILE_MODEL,
                    "effective_child_reasoning_effort": "high",
                    "effective_fan_out": 8,
                    "observation": "admission_policy_resolved"
                },
                {
                    "sequence": 3,
                    "assignment_id": "fanout-assignment",
                    "budget_action": "degrade",
                    "budget_reasons": ["soft_token_ceiling_reached", "missing_pricing"],
                    "change": {"kind": "fan_out", "before": 8, "after": 4},
                    "effective_child_model": BALANCED_PROFILE_MODEL,
                    "effective_child_reasoning_effort": "high",
                    "effective_fan_out": 4,
                    "observation": "admission_policy_resolved"
                },
                {
                    "sequence": 4,
                    "assignment_id": "halted-assignment",
                    "budget_action": "owner_escalation",
                    "budget_reasons": ["soft_token_ceiling_reached", "hard_token_ceiling_reached", "missing_pricing"],
                    "change": {"kind": "halt", "before_new_dispatch_allowed": true, "after_new_dispatch_allowed": false},
                    "effective_child_model": BALANCED_PROFILE_MODEL,
                    "effective_child_reasoning_effort": "high",
                    "effective_fan_out": 4,
                    "observation": "admission_policy_resolved"
                }
            ])
        );
        let mut construction = test_report_construction(
            &plan,
            RunId::new("budget-degradation-artifact").expect("run id"),
        );
        construction.budget_degradations = controller.records.clone();
        let final_report = build_supervisor_final_report(construction);
        assert_eq!(
            final_report
                .role_economics_profile
                .as_ref()
                .and_then(|profile| profile.execution.as_ref())
                .expect("execution telemetry")
                .budget_degradations,
            controller.records
        );
        let schema = supervisor_final_report_schema_value();
        let execution = &schema["properties"]["role_economics_profile"]["properties"]["execution"];
        assert!(execution["required"]
            .as_array()
            .is_some_and(|required| required.iter().any(|field| field == "budget_degradations")));
        assert_eq!(
            execution["properties"]["budget_degradations"]["items"]["properties"]["change"]
                ["oneOf"][2]["properties"]["kind"]["const"],
            "fan_out"
        );
    }

    #[test]
    fn assignment_effort_resolves_per_duty_and_records_hard_floor_clamps() {
        let assignment = test_assignment("bounded-task", "bounded.txt");
        let mut plan = test_plan(vec![assignment.clone()]);
        let ReviewLensBackendConfig::Model {
            reasoning_effort, ..
        } = &mut plan.review_lenses[0].backend
        else {
            panic!("default review lens is model-backed");
        };
        *reasoning_effort = Some("low".to_string());
        let catalog = RuntimeModelCatalog::Codex(
            CodexRuntimeModelCatalog::from_slugs([FRONTIER_PROFILE_MODEL])
                .expect("assignment effort catalog"),
        );
        let report = RunBudgetLedger::new(RunBudgetLimits::default())
            .expect("unbounded ledger")
            .report()
            .expect("unbounded report");
        let mut controller = BudgetDegradationController::new(1);
        let policy = controller
            .assignment_policy(
                &assignment,
                Some(ReasoningEffort::Low),
                &report,
                &plan,
                &catalog,
                SupervisorRuntime::Codex,
            )
            .expect("assignment effort resolution")
            .expect("assignment admission");
        let effective = policy.apply(&plan);
        assert_eq!(
            effective.role_models[&AgentRole::ChildOrchestrator]
                .reasoning_effort
                .as_deref(),
            Some("low")
        );
        assert_eq!(
            effective.role_models[&AgentRole::GateClassifier]
                .reasoning_effort
                .as_deref(),
            Some("high")
        );
        assert_eq!(
            effective.role_models[&AgentRole::Auditor]
                .reasoning_effort
                .as_deref(),
            Some("xhigh")
        );
        let child = controller
            .assignment_effort_bindings
            .iter()
            .find(|binding| binding.role == AgentRole::ChildOrchestrator)
            .expect("child binding");
        assert_eq!(child.requested_reasoning_effort, Some(ReasoningEffort::Low));
        assert_eq!(child.resolved_reasoning_effort, "low");
        assert_eq!(
            child.resolution_observation,
            EffortResolutionObservation::AssignmentOverride
        );
        let gate = controller
            .assignment_effort_bindings
            .iter()
            .find(|binding| binding.role == AgentRole::GateClassifier)
            .expect("gate binding");
        assert_eq!(gate.resolved_reasoning_effort, "high");
        assert_eq!(
            gate.resolution_observation,
            EffortResolutionObservation::HardFloorClamped
        );
        let auditor = controller
            .assignment_effort_bindings
            .iter()
            .find(|binding| binding.role == AgentRole::Auditor)
            .expect("auditor binding");
        assert_eq!(
            auditor.requested_reasoning_effort,
            Some(ReasoningEffort::Low)
        );
        assert_eq!(auditor.resolved_reasoning_effort, "xhigh");
        assert_eq!(
            auditor.resolution_observation,
            EffortResolutionObservation::HardFloorClamped
        );
        let mut construction = test_report_construction(
            &plan,
            RunId::new("assignment-effort-telemetry").expect("run id"),
        );
        construction.assignment_effort_bindings = controller.assignment_effort_bindings.clone();
        let final_report = build_supervisor_final_report(construction);
        assert_eq!(
            final_report
                .role_economics_profile
                .as_ref()
                .and_then(|profile| profile.execution.as_ref())
                .expect("execution telemetry")
                .assignment_effort_bindings,
            controller.assignment_effort_bindings
        );
        println!(
            "assignment_effort_telemetry {}",
            serde_json::to_string(&controller.assignment_effort_bindings)
                .expect("serialize effort telemetry")
        );
    }

    #[test]
    fn protected_duty_floors_bound_budget_effort_degradation() {
        let gate = resolve_reasoning_effort(
            AgentRole::GateClassifier,
            Some(ReasoningEffort::Xhigh),
            Some("high"),
            4,
        );
        assert_eq!(gate.resolved, "high");
        assert_eq!(
            gate.observation,
            EffortResolutionObservation::HardFloorClamped
        );
        let auditor = resolve_reasoning_effort(
            AgentRole::Auditor,
            Some(ReasoningEffort::Ultra),
            Some("xhigh"),
            4,
        );
        assert_eq!(auditor.resolved, "xhigh");
        assert_eq!(
            auditor.observation,
            EffortResolutionObservation::HardFloorClamped
        );
    }

    fn root_schedule(plan: &SupervisorPlan) -> Vec<AssignmentScheduleEntry> {
        plan.assignments
            .iter()
            .enumerate()
            .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
                assignment_id: assignment.id.clone(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index,
            })
            .collect()
    }

    fn test_options(repo: &Path, run_id: &str) -> SupervisorRunOptions {
        SupervisorRunOptions {
            repo: repo.to_path_buf(),
            plan_file: repo.join("plan.json"),
            run_id: RunId::new(run_id).expect("valid scheduler test run id"),
            parent_node: None,
            codex_bin: PathBuf::from("unused-test-codex"),
            runtime: SupervisorRuntime::Fake,
            allow_dirty_primary: true,
            admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
            budget_overrides: crate::supervise::RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: Some(crate::machine_global::MachineGlobalRetentionBinding {
                config: repo.join("unused-machine-global.json"),
                root_id: "runtime".to_string(),
                owner: "maco-supervise-test".to_string(),
                correction_correlation_id: run_id.to_string(),
            }),
        }
    }

    fn test_repository() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("temporary scheduler repository");
        let repo = temp.path().join("repo");
        let repository = Repository::init(&repo).expect("initialize scheduler repository");
        fs::write(repo.join("README.md"), "scheduler fixture\n")
            .expect("write scheduler repository fixture");
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("write second scheduler repository fixture");
        let mut index = repository.index().expect("open scheduler fixture index");
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .expect("stage scheduler fixture");
        index.write().expect("write scheduler fixture index");
        let tree_id = index.write_tree().expect("write scheduler fixture tree");
        let tree = repository
            .find_tree(tree_id)
            .expect("find scheduler fixture tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("fixture signature");
        repository
            .commit(Some("HEAD"), &signature, &signature, "baseline", &tree, &[])
            .expect("commit scheduler fixture");
        (temp, repo)
    }

    macro_rules! with_invalid_schedule_context {
        ($context:ident, $body:block) => {{
            let (_temp, repo) = test_repository();
            let options = test_options(&repo, "direct-scheduler");
            let plan = test_plan(vec![test_assignment("child-a", "README.md")]);
            let schedule = Vec::new();
            let consultant = SupervisorConsultantPlan::default();
            let assignment_metadata = AssignmentMetadata::new();
            let budget_config = SupervisorBudgetConfig::default();
            let budget_ledger =
                RunBudgetLedger::new(budget_config.limits).expect("test budget ledger");
            let mut artifact_writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                options.run_id.clone(),
                "scheduler-decomposition-test",
            )
            .expect("reserve scheduler artifacts");
            let run_dir = artifact_writer.run_dir().to_path_buf();
            let dirs = RunDirs::for_writer(&artifact_writer);
            let manager = WorktreeManager::new(&repo);
            let existing_ids = BTreeSet::new();
            let sync_store = SyncStore::open(&repo).expect("open scheduler sync store");
            let semantic_store =
                SemanticIntentStore::open(&repo).expect("open scheduler semantic store");
            let prepared = vec![PreparedSemanticAssignment::default()];
            let field_guide =
                SupervisorFieldGuidePrompt::empty().expect("empty scheduler field guide");
            let mut journal = initialize_orchestration_event_journal(
                &repo,
                &options.run_id,
                options.parent_node.as_deref(),
            );
            let mut autonomy_kpis = AutonomyKpiCollector::default();
            let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut artifact_writer,
                journal: &mut journal,
                autonomy_kpis: &mut autonomy_kpis,
                checkpoint: None,
            });
            let runtime_model_catalog = RuntimeModelCatalog::LocalDeterministicFake;
            let runner = |_: &ExternalAgentCommand,
                          _: &ProcessCancellation,
                          _: Option<ExternalPreActionReviewRuntime<'_>>|
             -> ExternalAgentRun {
                panic!("invalid schedule must fail before external dispatch")
            };
            let $context = AssignmentSchedulerContext {
                plan: &plan,
                execution_target: None,
                budget_config: &budget_config,
                consultant: &consultant,
                assignment_metadata: &assignment_metadata,
                evidence_only_reaudit: None,
                options: &options,
                repo: &repo,
                run_dir: &run_dir,
                dirs: &dirs,
                execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
                worktree_creation: SupervisorWorktreeCreation::TestOnly,
                manager: &manager,
                existing_ids: &existing_ids,
                sync_store: &sync_store,
                semantic_store: &semantic_store,
                prepared_semantic_assignments: &prepared,
                assignment_schedule: &schedule,
                field_guide: &field_guide,
                artifacts: &shared_artifacts,
                budget_ledger: &budget_ledger,
                runtime_model_catalog: &runtime_model_catalog,
                external_runner: &runner,
                release_per_assignment: false,
            };
            $body
        }};
    }

    macro_rules! with_valid_schedule_context {
        ($context:ident, $assignments:expr, $max_children:expr, $body:block) => {{
            let (_temp, repo) = test_repository();
            let options = test_options(&repo, "direct-valid-scheduler");
            let plan = test_plan($assignments);
            let schedule = root_schedule(&plan);
            let consultant = SupervisorConsultantPlan::default();
            let assignment_metadata = AssignmentMetadata::new();
            let budget_config = SupervisorBudgetConfig::default();
            let budget_ledger =
                RunBudgetLedger::new(budget_config.limits).expect("test budget ledger");
            let mut artifact_writer = ArtifactRunWriter::reserve(
                &repo,
                RunArtifactFamily::Supervise,
                options.run_id.clone(),
                "scheduler-success-test",
            )
            .expect("reserve scheduler artifacts");
            let run_dir = artifact_writer.run_dir().to_path_buf();
            let dirs = RunDirs::for_writer(&artifact_writer);
            let manager = WorktreeManager::new(&repo);
            let existing_ids = BTreeSet::new();
            let sync_store = SyncStore::open(&repo).expect("open scheduler sync store");
            let semantic_store =
                SemanticIntentStore::open(&repo).expect("open scheduler semantic store");
            let prepared = plan
                .assignments
                .iter()
                .map(|_| PreparedSemanticAssignment::default())
                .collect::<Vec<_>>();
            let field_guide =
                SupervisorFieldGuidePrompt::empty().expect("empty scheduler field guide");
            let mut journal = initialize_orchestration_event_journal(
                &repo,
                &options.run_id,
                options.parent_node.as_deref(),
            );
            let mut autonomy_kpis = AutonomyKpiCollector::default();
            let shared_artifacts = Mutex::new(SharedSupervisorArtifacts {
                writer: &mut artifact_writer,
                journal: &mut journal,
                autonomy_kpis: &mut autonomy_kpis,
                checkpoint: None,
            });
            let runtime_model_catalog = RuntimeModelCatalog::LocalDeterministicFake;
            let runner = |_: &ExternalAgentCommand,
                          _: &ProcessCancellation,
                          _: Option<ExternalPreActionReviewRuntime<'_>>|
             -> ExternalAgentRun {
                panic!("fake scheduler success fixture must not invoke the external runner")
            };
            let $context = AssignmentSchedulerContext {
                plan: &plan,
                execution_target: None,
                budget_config: &budget_config,
                consultant: &consultant,
                assignment_metadata: &assignment_metadata,
                evidence_only_reaudit: None,
                options: &options,
                repo: &repo,
                run_dir: &run_dir,
                dirs: &dirs,
                execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
                worktree_creation: SupervisorWorktreeCreation::TestOnly,
                manager: &manager,
                existing_ids: &existing_ids,
                sync_store: &sync_store,
                semantic_store: &semantic_store,
                prepared_semantic_assignments: &prepared,
                assignment_schedule: &schedule,
                field_guide: &field_guide,
                artifacts: &shared_artifacts,
                budget_ledger: &budget_ledger,
                runtime_model_catalog: &runtime_model_catalog,
                external_runner: &runner,
                release_per_assignment: true,
            };
            $body
        }};
    }

    fn test_report_construction(
        plan: &SupervisorPlan,
        run_id: RunId,
    ) -> SupervisorFinalReportConstruction<'_> {
        SupervisorFinalReportConstruction {
            plan,
            runtime_model_catalog: Some(&TEST_RUNTIME_MODEL_CATALOG),
            max_concurrent_children: 1,
            admission_policy_input: SupervisorAdmissionPolicyInput::resolve(
                Path::new("."),
                1,
                SupervisorAdmissionConfig::default(),
                SupervisorAdmissionConfig::default(),
            )
            .expect("test admission policy"),
            achieved_concurrency: AchievedConcurrency::default(),
            has_multiple_independent_assignment_scopes: false,
            run_id,
            report_plan_file: PathBuf::from("plan.json"),
            report_run_dir: PathBuf::from(".maco/o2/runs/test"),
            runtime: SupervisorRuntime::Fake,
            publishable: false,
            success: true,
            run_budget_report: None,
            budget_degradations: Vec::new(),
            assignment_effort_bindings: Vec::new(),
            evidence_only_reaudit: None,
            role_usage: BTreeMap::new(),
            review_lens_usage: Vec::new(),
            review_lens_total_usage: None,
            review_lens_total_cost_usd: None,
            total_usage: None,
            total_cost_usd: None,
            usage_complete: true,
            environment_failures: Vec::new(),
            sandbox_denials: Vec::new(),
            collected: CollectedAssignmentOutcomes::default(),
            bloated_file_flags: Vec::new(),
            decomposition_candidates: Vec::new(),
            assignment_traceability: Vec::new(),
            coverage_gaps: Vec::new(),
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
        }
    }

    #[test]
    fn ready_nonoverlap_selector_skips_active_path_conflict() {
        let plan = test_plan(vec![
            test_assignment("active", "src"),
            test_assignment("overlap", "src/lib.rs"),
            test_assignment("ready", "README.md"),
        ]);
        let schedule = root_schedule(&plan);
        let pending = BTreeSet::from([1, 2]);
        let outcomes = (0..plan.assignments.len())
            .map(|_| None)
            .collect::<Vec<_>>();

        let selected = select_ready_nonoverlapping_assignment(
            &pending,
            &schedule,
            &outcomes,
            &plan,
            std::iter::once(0),
        )
        .expect("select a ready non-overlapping assignment");

        assert_eq!(selected, Some(2));
    }

    #[test]
    fn strict_parent_child_schedule_is_not_independent_fan_out() {
        let schedule = vec![
            AssignmentScheduleEntry {
                assignment_id: "parent".to_string(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: "child".to_string(),
                parent_assignment_id: Some("parent".to_string()),
                depth: MIN_SUPERVISOR_DEPTH + 1,
                flattened_index: 1,
            },
        ];

        assert!(!has_multiple_independent_assignment_scopes(
            &schedule,
            &SupervisorPlanMetadata::default()
        ));

        let metadata = SupervisorPlanMetadata {
            spec_fragment_ids: vec!["scope-a".to_string(), "scope-b".to_string()],
            ..SupervisorPlanMetadata::default()
        };
        assert!(has_multiple_independent_assignment_scopes(
            &schedule, &metadata
        ));
    }

    #[test]
    fn serial_scheduler_preserves_schedule_error_context() {
        with_invalid_schedule_context!(context, {
            let mut progress = SchedulerProgress::new(1, 1);
            let cancellation = ProcessCancellation::new();
            let serial_intents = Mutex::new(Vec::new());
            let error = run_serial_assignment_schedule(
                &context,
                &mut progress,
                &cancellation,
                &serial_intents,
            )
            .expect_err("invalid serial schedule must fail");
            assert_eq!(
                error.to_string(),
                "assignment admission referenced an index outside the validated schedule"
            );
            assert!(progress.indexed_outcomes[0].is_none());
        });
    }

    #[test]
    fn concurrent_scheduler_preserves_schedule_error_context_before_spawning() {
        with_invalid_schedule_context!(context, {
            let mut progress = SchedulerProgress::new(1, 1);
            let cancellation = ProcessCancellation::new();
            let semantic_block_gate = SemanticBlockGate::default();
            let error = run_concurrent_assignment_schedule(
                &context,
                &mut progress,
                &cancellation,
                &semantic_block_gate,
            )
            .expect_err("invalid concurrent schedule must fail");
            assert_eq!(
                error.to_string(),
                "assignment admission referenced an index outside the validated schedule"
            );
            assert!(progress.indexed_outcomes[0].is_none());
        });
    }

    #[test]
    fn serial_scheduler_directly_dispatches_and_completes_fake_assignment() {
        with_valid_schedule_context!(
            context,
            vec![test_assignment("serial-child", "README.md")],
            1,
            {
                let mut progress = SchedulerProgress::new(1, 2);
                let cancellation = ProcessCancellation::new();
                let serial_intents = Mutex::new(Vec::new());

                run_serial_assignment_schedule(
                    &context,
                    &mut progress,
                    &cancellation,
                    &serial_intents,
                )
                .expect("serial scheduler dispatch succeeds");

                let outcome = progress.indexed_outcomes[0]
                    .as_ref()
                    .expect("serial scheduler stores completed outcome");
                assert_eq!(
                    outcome.report.as_ref().map(|report| report.id.as_str()),
                    Some("serial-child")
                );
                assert!(outcome.fatal_error.is_none());
                assert!(!outcome.assignment_failed);
                assert_eq!(outcome.released_claims.len(), 1);
                assert!(outcome.release_errors.is_empty());
                assert!(outcome.semantic_release_errors.is_empty());
                let concurrency = progress.concurrency.finish();
                assert_eq!(concurrency.started_assignment_count, 1);
                assert_eq!(concurrency.completed_assignment_count, 1);
                assert_eq!(concurrency.peak, 1);
                assert!(concurrency
                    .mean
                    .is_some_and(|mean| mean > 0.0 && mean <= 1.0));
            }
        );
    }

    #[test]
    fn concurrency_tracker_measures_live_guards_and_closes_on_unwind() {
        let tracker = SchedulerConcurrencyTracker::new();
        {
            let first = tracker.assignment_started();
            drop(first);
            let second = tracker.assignment_started();
            drop(second);
        }
        let sequential = tracker.finish();
        assert_eq!(sequential.started_assignment_count, 2);
        assert_eq!(sequential.completed_assignment_count, 2);
        assert_eq!(sequential.peak, 1);

        let tracker = SchedulerConcurrencyTracker::new();
        let first = tracker.assignment_started();
        let second = tracker.assignment_started();
        drop(second);
        drop(first);
        let overlapping = tracker.finish();
        assert_eq!(overlapping.started_assignment_count, 2);
        assert_eq!(overlapping.completed_assignment_count, 2);
        assert_eq!(overlapping.peak, 2);

        let tracker = SchedulerConcurrencyTracker::new();
        let unwind_tracker = tracker.clone();
        let _ = std::panic::catch_unwind(move || {
            let _guard = unwind_tracker.assignment_started();
            panic!("test unwind");
        });
        let unwound = tracker.finish();
        assert_eq!(unwound.started_assignment_count, 1);
        assert_eq!(unwound.completed_assignment_count, 1);
        assert_eq!(unwound.peak, 1);
    }

    #[test]
    fn concurrent_scheduler_directly_dispatches_completes_and_orders_fake_assignments() {
        with_valid_schedule_context!(
            context,
            vec![
                test_assignment("concurrent-a", "README.md"),
                test_assignment("concurrent-b", "Cargo.toml"),
            ],
            2,
            {
                let mut progress = SchedulerProgress::new(2, 2);
                let cancellation = ProcessCancellation::new();
                let semantic_block_gate = SemanticBlockGate::default();

                run_concurrent_assignment_schedule(
                    &context,
                    &mut progress,
                    &cancellation,
                    &semantic_block_gate,
                )
                .expect("concurrent scheduler dispatch succeeds");

                assert_eq!(
                    progress
                        .indexed_outcomes
                        .iter()
                        .map(|outcome| {
                            outcome
                                .as_ref()
                                .and_then(|outcome| outcome.report.as_ref())
                                .map(|report| report.id.as_str())
                        })
                        .collect::<Vec<_>>(),
                    vec![Some("concurrent-a"), Some("concurrent-b")]
                );
                assert!(progress.indexed_outcomes.iter().all(|outcome| {
                    outcome.as_ref().is_some_and(|outcome| {
                        outcome.fatal_error.is_none()
                            && !outcome.assignment_failed
                            && outcome.released_claims.len() == 1
                            && outcome.release_errors.is_empty()
                            && outcome.semantic_release_errors.is_empty()
                    })
                }));
                let concurrency = progress.concurrency.finish();
                assert_eq!(concurrency.started_assignment_count, 2);
                assert_eq!(concurrency.completed_assignment_count, 2);
                assert!((1..=2).contains(&concurrency.peak));
                assert!(concurrency
                    .mean
                    .is_some_and(|mean| (1.0..=2.0).contains(&mean)));
            }
        );
    }

    #[test]
    fn indexed_outcome_collection_keeps_plan_order_and_first_fatal() {
        let first = AssignmentExecutionOutcome {
            findings: vec![Finding {
                severity: FindingSeverity::Warning,
                message: "first".to_string(),
                paths: Vec::new(),
            }],
            assignment_failed: true,
            fatal_error: Some("first fatal".to_string()),
            ..AssignmentExecutionOutcome::default()
        };
        let second = AssignmentExecutionOutcome {
            findings: vec![Finding {
                severity: FindingSeverity::Error,
                message: "second".to_string(),
                paths: Vec::new(),
            }],
            external_containment_failed: true,
            fatal_error: Some("second fatal".to_string()),
            ..AssignmentExecutionOutcome::default()
        };
        let mut collected = CollectedAssignmentOutcomes::default();

        let fatal_errors = collect_indexed_assignment_outcomes(
            vec![Some(first), None, Some(second)],
            false,
            &mut collected,
        );

        assert_eq!(fatal_errors, vec!["first fatal", "second fatal"]);
        assert_eq!(
            collected
                .findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert!(collected.assignment_execution_failed);
        assert!(collected.external_containment_failed);
    }

    #[test]
    fn resource_release_collection_preserves_concurrent_release_evidence_without_stores() {
        let released_claim = PathClaim {
            token: ClaimToken::from_u64(7),
            agent_id: "child-a".to_string(),
            paths: vec![PathBuf::from("README.md")],
        };
        let mut collected = CollectedSchedulerResources {
            concurrently_released_claims: vec![released_claim.clone()],
            concurrent_release_errors: vec!["claim release failed".to_string()],
            concurrent_semantic_release_errors: vec!["semantic release failed".to_string()],
            ..CollectedSchedulerResources::default()
        };

        let released = release_collected_scheduler_resources(None, None, &mut collected);

        assert_eq!(released.released_claims, vec![released_claim]);
        assert_eq!(released.release_errors, vec!["claim release failed"]);
        assert!(released.released_semantic_intents.is_empty());
        assert_eq!(
            released.semantic_release_errors,
            vec!["semantic release failed"]
        );
        assert!(collected.concurrently_released_claims.is_empty());
        assert!(collected.concurrent_release_errors.is_empty());
        assert!(collected.concurrent_semantic_release_errors.is_empty());
    }

    #[test]
    fn report_paths_keep_repo_relative_plan_and_fallback_for_external_run_dir() {
        let repo = Path::new("/repo");
        let run_id = RunId::new("direct-report-paths").expect("valid report path run id");

        let (plan_file, run_dir) = supervisor_report_paths(
            repo,
            Path::new("/repo/plans/supervise.json"),
            Path::new("/external/run"),
            &run_id,
        );

        assert_eq!(plan_file, PathBuf::from("plans/supervise.json"));
        assert_eq!(
            run_dir,
            RunArtifactFamily::Supervise
                .run_root()
                .join("direct-report-paths")
        );
    }

    #[test]
    fn report_builder_keeps_fake_success_nonpublishable() {
        let plan = test_plan(vec![
            test_assignment("child-a", "README.md"),
            test_assignment("child-b", "README.md"),
        ]);
        let report = build_supervisor_final_report(test_report_construction(
            &plan,
            RunId::new("direct-report-builder").expect("valid report run id"),
        ));

        assert!(report.success);
        assert!(!report.publishable);
        assert!(!report.accepted);
        assert_eq!(report.assigned_paths, vec![PathBuf::from("README.md")]);
        assert_eq!(
            report.remaining_risk,
            "fake supervisor simulation succeeded but is not publishable or acceptable as real model evidence"
        );
        let profile = report
            .role_economics_profile
            .as_ref()
            .expect("new reports always carry economics metadata");
        assert_eq!(
            profile.schema_version,
            SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION
        );
        assert_eq!(
            profile.model_catalog_observation,
            RuntimeModelCatalogObservation::NotConsulted
        );
        let execution = profile
            .execution
            .as_ref()
            .expect("new reports always carry execution metadata");
        assert_eq!(execution.assignment_count, 2);
        assert_eq!(execution.concurrency.configured_max_concurrent_children, 1);
        assert_eq!(
            execution
                .concurrency
                .policy_input_details
                .as_ref()
                .expect("retained policy input")
                .resolved_bound,
            1
        );
        assert_eq!(
            execution.concurrency.policy_input_observation,
            ProcessObservation::SchedulerObserved
        );
        assert_eq!(execution.concurrency.achieved_max_concurrent_children, 0);
        assert!(execution.role_bindings.values().all(|binding| {
            binding.observation == RoleBindingObservation::SyntheticFake
                && binding.resolved_model.is_none()
                && binding.resolved_reasoning_effort.is_none()
        }));
        assert_eq!(report.role_usage.len(), 5);
    }

    #[test]
    fn admission_resolution_uses_strictest_entrypoint_plan_quota_and_host_bound() {
        let temp = tempfile::tempdir().expect("temporary admission repository");
        let plan = SupervisorAdmissionConfig {
            max_concurrent_children: Some(12),
            provider_inflight_limit: Some(9),
            host_memory_available_mib: Some(8_192),
            host_memory_per_child_mib: Some(1_024),
            host_fd_available: Some(640),
            host_fds_per_child: Some(128),
            host_disk_available_mib: Some(9_000),
            host_disk_per_child_mib: Some(1_000),
            host_fallback_children: Some(2),
        };
        let cli = SupervisorAdmissionConfig {
            max_concurrent_children: Some(10),
            provider_inflight_limit: Some(7),
            host_fd_available: Some(384),
            ..SupervisorAdmissionConfig::default()
        };

        let resolved = SupervisorAdmissionPolicyInput::resolve(temp.path(), 20, plan, cli)
            .expect("resolve admission policy");

        assert_eq!(resolved.effective.max_concurrent_children, Some(10));
        assert_eq!(resolved.provider_inflight_bound, 7);
        assert_eq!(resolved.host.memory_bound, Some(8));
        assert_eq!(resolved.host.fd_bound, Some(3));
        assert_eq!(resolved.host.disk_bound, Some(9));
        assert_eq!(resolved.host.resolved_bound, 3);
        assert_eq!(resolved.resolved_bound, 3);
        assert_eq!(
            resolved.provider_inflight_source,
            AdmissionInputSource::Configured
        );
    }

    #[test]
    fn report_builder_warns_when_independent_scopes_collapse_to_width_one() {
        let plan = test_plan(vec![
            test_assignment("child-a", "README.md"),
            test_assignment("child-b", "Cargo.toml"),
        ]);
        let mut construction = test_report_construction(
            &plan,
            RunId::new("collapsed-fan-out").expect("valid run id"),
        );
        construction.max_concurrent_children = 2;
        construction.achieved_concurrency = AchievedConcurrency {
            started_assignment_count: 2,
            completed_assignment_count: 2,
            peak: 1,
            mean: Some(1.0),
        };
        construction.has_multiple_independent_assignment_scopes = true;

        let report = build_supervisor_final_report(construction);

        assert!(report.findings.iter().any(|finding| {
            finding.severity == FindingSeverity::Warning
                && finding.message.contains("fan-out collapsed")
                && finding.message.contains("achieved width 1")
        }));
        let execution = report
            .role_economics_profile
            .as_ref()
            .and_then(|profile| profile.execution.as_ref())
            .expect("execution metadata");
        assert_eq!(execution.concurrency.configured_max_concurrent_children, 2);
        assert_eq!(execution.concurrency.achieved_max_concurrent_children, 1);
        assert_eq!(
            execution.concurrency.achieved_mean_concurrent_children,
            Some(1.0)
        );
    }

    #[test]
    fn legacy_economics_profile_defaults_to_version_one_without_execution() {
        let plan = test_plan(Vec::new());
        let report = build_supervisor_final_report(test_report_construction(
            &plan,
            RunId::new("legacy-economics-read").expect("valid run id"),
        ));
        let mut value = serde_json::to_value(report).expect("serialize current report");
        let profile = value["role_economics_profile"]
            .as_object_mut()
            .expect("economics profile object");
        profile.remove("schema_version");
        profile.remove("model_catalog_observation");
        profile.remove("execution");

        let legacy: SupervisorFinalReport =
            serde_json::from_value(value).expect("legacy report remains readable");
        let profile = legacy
            .role_economics_profile
            .as_ref()
            .expect("legacy economics block remains readable");
        assert_eq!(profile.schema_version, 1);
        assert_eq!(
            profile.model_catalog_observation,
            RuntimeModelCatalogObservation::NotConsulted
        );
        assert!(profile.execution.is_none());
    }

    #[test]
    fn legacy_v4_model_tier_profile_remains_readable_under_v5_schema() {
        let profile: RoleEconomicsProfile = serde_json::from_str(include_str!(
            "../../tests/fixtures/supervise/supervisor-final-economics-v4.json"
        ))
        .expect("parse supervisor-final economics fixture");

        assert_eq!(profile.schema_version, 4);
        assert_eq!(
            profile.name,
            LEGACY_PROVISIONAL_DEFAULT_MODEL_TIER_PROFILE_NAME
        );
        assert_eq!(
            profile.model_catalog_observation,
            RuntimeModelCatalogObservation::Consulted
        );
        let execution = profile.execution.expect("fixture execution metadata");
        assert_eq!(execution.assignment_count, 2);
        assert_eq!(execution.concurrency.configured_max_concurrent_children, 2);
        assert_eq!(execution.concurrency.achieved_max_concurrent_children, 2);
        assert_eq!(
            execution
                .concurrency
                .policy_input_details
                .expect("typed admission policy input")
                .resolved_bound,
            2
        );
        assert_eq!(execution.role_bindings.len(), 5);
        assert!(execution.assignment_effort_bindings.is_empty());
        assert_eq!(
            execution.usage.total_usage,
            Some(Usage {
                input_tokens: 1_200,
                output_tokens: 300,
                total_tokens: 1_500,
            })
        );

        let schema = supervisor_final_report_schema_value();
        assert_eq!(
            schema["properties"]["role_economics_profile"]["properties"]["schema_version"]["const"],
            SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION
        );
        assert!(
            schema["properties"]["role_economics_profile"]["properties"]["execution"]["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|field| field == "role_bindings"))
        );
        assert!(
            schema["properties"]["role_economics_profile"]["properties"]["execution"]["required"]
                .as_array()
                .is_some_and(|required| {
                    required
                        .iter()
                        .any(|field| field == "assignment_effort_bindings")
                })
        );
    }

    #[test]
    fn preflight_preserves_typed_runtime_catalog_failure_for_materialization() {
        let (_temp, repo) = test_repository();
        let loaded = LoadedSupervisorPlan {
            plan: test_plan(Vec::new()),
            consultant: SupervisorConsultantPlan::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        };
        let options = test_options(&repo, "direct-preflight");
        let failure = Box::new(EnvironmentFailure::runtime_model_catalog(
            "catalog probe failed".to_string(),
        ));

        let prepared = prepare_supervisor_run(
            loaded,
            &options,
            1,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            SupervisorWorktreeCreation::TestOnly,
            Err(failure.clone()),
        )
        .expect("typed catalog failure must survive preparation for final-report materialization");
        let retained = prepared
            .runtime_model_catalog
            .expect_err("catalog failure must remain typed until supervisor finalization");

        assert_eq!(retained, failure);
        assert_eq!(
            retained.category,
            EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
        );
    }

    #[test]
    fn preflight_directly_validates_schedule_and_reserves_artifacts() {
        let (_temp, repo) = test_repository();
        let plan = test_plan(vec![test_assignment("prepared-child", "README.md")]);
        let loaded = LoadedSupervisorPlan {
            plan,
            consultant: SupervisorConsultantPlan::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        };
        let options = test_options(&repo, "direct-preflight-success");

        let prepared = prepare_supervisor_run(
            loaded,
            &options,
            1,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            SupervisorWorktreeCreation::TestOnly,
            Ok(RuntimeModelCatalog::LocalDeterministicFake),
        )
        .expect("prepare scheduler run directly");

        assert_eq!(prepared.repo, repo);
        assert_eq!(prepared.runtime, SupervisorRuntime::Fake);
        assert_eq!(prepared.assignment_schedule.len(), 1);
        assert_eq!(
            prepared.assignment_schedule[0].assignment_id,
            "prepared-child"
        );
        assert!(prepared.run_dir.is_dir());
        assert_eq!(prepared.dirs.run_dir, prepared.run_dir);
        assert!(
            prepared
                .budget_ledger
                .report()
                .expect("prepared budget report")
                .new_dispatch_allowed
        );
    }

    #[test]
    fn preflight_composes_cli_budget_overrides_with_plan_by_strictest_limit() {
        let (_temp, repo) = test_repository();
        let mut metadata = SupervisorPlanMetadata::default();
        metadata.run_budget.limits = RunBudgetLimits {
            soft_tokens: Some(100),
            hard_tokens: Some(200),
            soft_cost_usd: Some(0.5),
            hard_cost_usd: Some(1.0),
        };
        metadata.run_budget_max_duration_seconds = Some(600);
        let loaded = LoadedSupervisorPlan {
            plan: test_plan(vec![test_assignment("budgeted-child", "README.md")]),
            consultant: SupervisorConsultantPlan::default(),
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: metadata,
        };
        let mut options = test_options(&repo, "strictest-cli-plan-budget");
        options.budget_overrides = RunBudgetLimits {
            hard_tokens: Some(50),
            hard_cost_usd: Some(0.4),
            ..RunBudgetLimits::default()
        };
        options.budget_max_duration_seconds = Some(300);

        let prepared = prepare_supervisor_run(
            loaded,
            &options,
            1,
            SupervisorExecutionRuntime::NonpublishableSimulation,
            SupervisorWorktreeCreation::TestOnly,
            Ok(RuntimeModelCatalog::LocalDeterministicFake),
        )
        .expect("prepare run with CLI budget overrides");
        let report = prepared
            .budget_ledger
            .report()
            .expect("composed run budget report");

        assert_eq!(
            report.limits,
            RunBudgetLimits {
                soft_tokens: Some(50),
                hard_tokens: Some(50),
                soft_cost_usd: Some(0.4),
                hard_cost_usd: Some(0.4),
            }
        );
        assert_eq!(report.max_duration_seconds, Some(300));
    }

    #[test]
    fn evidence_initialization_populates_stores_journal_and_baseline() {
        let (_temp, repo) = test_repository();
        let mut options = test_options(&repo, "direct-evidence-initialization");
        options.parent_node = Some("external-root".to_string());
        let plan = test_plan(Vec::new());
        let consultant = SupervisorConsultantPlan::default();
        let assignment_metadata = AssignmentMetadata::new();
        let plan_metadata = SupervisorPlanMetadata::default();
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            options.run_id.clone(),
            "scheduler-initialization-test",
        )
        .expect("reserve initialization artifacts");
        let mut field_guide_store = None;
        let mut field_guide_prompt = None;
        let mut sync_store = None;
        let mut semantic_store = None;
        let mut journal = None;
        let mut baseline = None;

        initialize_scheduler_evidence(&mut SchedulerEvidenceInitialization {
            plan: &plan,
            execution_target: None,
            consultant: &consultant,
            assignment_metadata: &assignment_metadata,
            plan_metadata: &plan_metadata,
            options: &options,
            repo: &repo,
            execution_runtime: SupervisorExecutionRuntime::NonpublishableSimulation,
            artifact_writer: &mut writer,
            field_guide_store_slot: &mut field_guide_store,
            field_guide_prompt_slot: &mut field_guide_prompt,
            sync_store_slot: &mut sync_store,
            semantic_store_slot: &mut semantic_store,
            orchestration_journal: &mut journal,
            primary_run_baseline: &mut baseline,
        })
        .expect("initialize scheduler evidence directly");

        assert!(field_guide_store.is_some());
        assert!(field_guide_prompt.is_some());
        assert!(sync_store.is_some());
        assert!(semantic_store.is_some());
        assert!(journal.is_some());
        assert!(baseline.is_some());
        let root_event = journal
            .as_ref()
            .expect("initialized orchestration journal")
            .create_event(
                options.run_id.as_str(),
                None,
                OrchestrationRole::Supervisor,
                OrchestrationEventKind::Status,
                json!({"status": "running"}),
            )
            .expect("create root supervisor event");
        assert_eq!(root_event.parent.as_deref(), Some("external-root"));
    }

    #[test]
    fn persistence_records_gate_before_status_and_finalizes_report() {
        let (_temp, repo) = test_repository();
        let run_id = RunId::new("direct-report-persistence").expect("valid persistence run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "scheduler-persistence-test",
        )
        .expect("reserve persistence artifacts");
        write_supervisor_final_schema(
            &mut writer,
            Path::new("schemas/supervisor-final-report.schema.json"),
        )
        .expect("write persistence schema fixture");
        let _field_guide_store = FieldGuideStore::open(&repo, FieldGuideLimits::default())
            .expect("initialize authenticated persistence fixture");
        let mut journal = initialize_orchestration_event_journal(&repo, &run_id, None);
        assert!(journal.is_some());
        let plan = test_plan(Vec::new());
        let mut report =
            build_supervisor_final_report(test_report_construction(&plan, run_id.clone()));
        let consultant = SupervisorConsultantPlan::default();
        let assignment_metadata = AssignmentMetadata::new();
        let plan_metadata = SupervisorPlanMetadata::default();
        let budget_ledger =
            RunBudgetLedger::new(RunBudgetLimits::default()).expect("checkpoint budget ledger");
        report.run_budget = Some(
            budget_ledger
                .report()
                .expect("checkpoint final report budget"),
        );
        let mut checkpoint = SupervisorCheckpointWriter::create(
            &repo,
            SupervisorCheckpointPreparation::new(
                &run_id,
                &current_head_oid(&repo).expect("checkpoint primary base"),
                normalized_supervisor_plan_sha256(
                    &plan,
                    &consultant,
                    &assignment_metadata,
                    &plan_metadata,
                )
                .expect("checkpoint normalized plan binding"),
                1,
                &plan,
                writer
                    .resume_binding()
                    .expect("checkpoint artifact binding"),
                budget_ledger.report().expect("checkpoint initial budget"),
            ),
        )
        .expect("create supervise checkpoint");
        checkpoint
            .scheduler_closed(
                writer.resume_binding().expect("scheduler close binding"),
                budget_ledger.report().expect("scheduler close budget"),
            )
            .expect("close checkpoint scheduler");

        let persisted = persist_supervisor_final_report(
            report,
            &mut journal,
            writer,
            Some(&mut checkpoint),
            || Ok(()),
        )
        .expect("persist scheduler final report directly");

        assert_eq!(persisted.run_id, run_id);
        let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized scheduler artifacts");
        let journal_bytes = reader
            .read(ORCHESTRATION_EVENT_PATH)
            .expect("read scheduler orchestration journal");
        let kinds = journal_bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                serde_json::from_slice::<OrchestrationEvent>(line)
                    .expect("parse scheduler orchestration event")
                    .kind
            })
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![OrchestrationEventKind::Gate, OrchestrationEventKind::Status]
        );
    }
}
