impl AssignmentExecutionOutcome {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            fatal_error: Some(message.into()),
            ..Self::default()
        }
    }

    fn requires_scheduler_abort(&self) -> bool {
        self.fatal_error.is_some()
            || self.external_containment_failed
            || !self.release_errors.is_empty()
            || !self.semantic_release_errors.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AssignmentAdmissionState {
    Ready,
    Waiting,
    Suppressed { parent_assignment_id: String },
}

struct AssignmentExecutionContext<'a, 'writer> {
    index: usize,
    concurrent_mode: bool,
    plan: &'a SupervisorPlan,
    requested_plan: &'a SupervisorPlan,
    budget_config: &'a SupervisorBudgetConfig,
    consultant: &'a SupervisorConsultantPlan,
    assignment_metadata: &'a AssignmentMetadata,
    assignment: &'a OrchestratorAssignment,
    evidence_only_reaudit: Option<&'a EvidenceOnlyReauditSource>,
    options: &'a SupervisorRunOptions,
    repo: &'a Path,
    run_dir: &'a Path,
    dirs: &'a RunDirs,
    execution_runtime: SupervisorExecutionRuntime,
    execution_target: Option<&'a SupervisorExecutionTarget>,
    worktree_creation: SupervisorWorktreeCreation<'a>,
    manager: &'a WorktreeManager,
    reused: bool,
    sync_store: &'a SyncStore,
    semantic_store: &'a SemanticIntentStore,
    prepared_semantic_token: Option<u64>,
    prepared_semantic_findings: &'a [Finding],
    prepared_semantic_signals: &'a [SwarmHealthSignal],
    prepared_semantic_failed: bool,
    assignment_schedule: &'a [AssignmentScheduleEntry],
    field_guide: &'a SupervisorFieldGuidePrompt,
    serial_semantic_warn_intents: Option<&'a Mutex<Vec<(usize, SemanticIntent)>>>,
    semantic_block_order: Option<usize>,
    semantic_block_gate: Option<&'a SemanticBlockGate>,
    artifacts: &'a Mutex<SharedSupervisorArtifacts<'writer>>,
    budget_ledger: &'a RunBudgetLedger,
    budget_policy: AssignmentBudgetPolicy,
    admission_commit: Option<AdmissionCommitSignal>,
    runtime_model_catalog: &'a RuntimeModelCatalog,
    cancellation: ProcessCancellation,
    external_runner: &'a CancellableExternalRunner<'a>,
}

#[cfg(test)]
type BudgetAdmissionTestHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

#[cfg(test)]
fn budget_admission_test_hooks() -> &'static Mutex<BTreeMap<String, BudgetAdmissionTestHook>> {
    static HOOKS: std::sync::OnceLock<Mutex<BTreeMap<String, BudgetAdmissionTestHook>>> =
        std::sync::OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
struct BudgetAdmissionTestHookGuard(String);

#[cfg(test)]
impl Drop for BudgetAdmissionTestHookGuard {
    fn drop(&mut self) {
        budget_admission_test_hooks()
            .lock()
            .unwrap()
            .remove(&self.0);
    }
}

#[cfg(test)]
fn install_budget_admission_test_hook(
    run_id: &str,
    hook: BudgetAdmissionTestHook,
) -> BudgetAdmissionTestHookGuard {
    budget_admission_test_hooks()
        .lock()
        .unwrap()
        .insert(run_id.to_string(), hook);
    BudgetAdmissionTestHookGuard(run_id.to_string())
}

#[cfg(test)]
fn observe_budget_admission_for_test(run_id: &str, stage: &str, owner: &str) {
    let hook = budget_admission_test_hooks()
        .lock()
        .unwrap()
        .get(run_id)
        .cloned();
    if let Some(hook) = hook {
        hook(stage, owner);
    }
}

#[derive(Clone)]
struct AdmissionCommitSignal {
    sender: mpsc::SyncSender<()>,
    notified: Arc<AtomicBool>,
}

impl AdmissionCommitSignal {
    fn new() -> (Self, mpsc::Receiver<()>) {
        let (sender, receiver) = mpsc::sync_channel(1);
        (
            Self {
                sender,
                notified: Arc::new(AtomicBool::new(false)),
            },
            receiver,
        )
    }

    fn notify(&self) {
        if !self.notified.swap(true, Ordering::SeqCst) {
            let _ = self.sender.send(());
        }
    }
}

enum DispatchBudgetAdmission<'a> {
    Admitted(DispatchBudgetReservation<'a>),
    Refused(BudgetAdmissionRefusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchBudgetReservationState {
    Reserved(SupervisorRuntime),
    Invoked(SupervisorRuntime),
    Settled,
}

struct DispatchBudgetReservation<'a> {
    ledger: &'a RunBudgetLedger,
    reservation: BudgetReservation,
    pricing: Option<ModelPricing>,
    model_pricing: BTreeMap<String, ModelPricing>,
    state: DispatchBudgetReservationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchUsageReliability {
    Reliable,
    Estimated,
    Missing,
    NotStarted,
}

#[derive(Debug, Clone, PartialEq)]
struct DispatchUsageSettlement {
    observed_usage: Option<Usage>,
    reliability: DispatchUsageReliability,
    model: Option<String>,
    cost_usd: Option<f64>,
}

impl DispatchUsageSettlement {
    fn reliable_usage(&self) -> Option<Usage> {
        (self.reliability == DispatchUsageReliability::Reliable)
            .then_some(self.observed_usage)
            .flatten()
    }

    fn is_degraded(&self) -> bool {
        matches!(
            self.reliability,
            DispatchUsageReliability::Estimated | DispatchUsageReliability::Missing
        )
    }

    fn role_sample(&self, role: AgentRole, lens_id: Option<String>) -> Option<RoleUsageSample> {
        self.reliable_usage().map(|usage| RoleUsageSample {
            role,
            lens_id,
            model: self.model.clone(),
            usage,
            cost_usd: self.cost_usd,
        })
    }
}

#[cfg(test)]
std::thread_local! {
    static DISPATCH_PRE_RUNNER_FAULT: Cell<Option<AgentRole>> = const { Cell::new(None) };
}

#[cfg(test)]
fn set_dispatch_pre_runner_fault(role: AgentRole) {
    DISPATCH_PRE_RUNNER_FAULT.with(|fault| fault.set(Some(role)));
}

impl DispatchBudgetReservation<'_> {
    fn mark_invoked_for_runtime(&mut self, launch_runtime: SupervisorRuntime) -> Result<()> {
        if self.state != DispatchBudgetReservationState::Reserved(launch_runtime) {
            bail!("budget reservation was invoked outside its reserved runtime or state");
        }
        if self.ledger.dispatch_stopped() {
            bail!("run budget stopped before provider invocation");
        }
        #[cfg(test)]
        if DISPATCH_PRE_RUNNER_FAULT
            .with(|fault| fault.replace(None))
            .is_some_and(|role| role == self.reservation.role)
        {
            bail!(
                "injected '{}' pre-runner preparation failure",
                self.reservation.role.as_str()
            );
        }
        self.state = DispatchBudgetReservationState::Invoked(launch_runtime);
        Ok(())
    }

    #[cfg(test)]
    fn mark_invoked(&mut self) -> Result<()> {
        self.mark_invoked_for_runtime(SupervisorRuntime::Codex)
    }

    fn settle_not_started(&mut self) -> Result<()> {
        if self.state == DispatchBudgetReservationState::Settled {
            bail!("budget reservation was already settled");
        }
        self.ledger
            .release(self.reservation.id)
            .context("failed to release budget for a dispatch that never started")?;
        self.state = DispatchBudgetReservationState::Settled;
        Ok(())
    }

    fn settle_bound_runtime(
        &mut self,
        run: &ExternalAgentRun,
        command: &ExternalAgentCommand,
    ) -> Result<DispatchUsageSettlement> {
        let DispatchBudgetReservationState::Invoked(launch_runtime) = self.state else {
            bail!("budget reservation was settled before its dispatch was invoked")
        };
        let usage = external_usage_for_runtime(run, command, launch_runtime);
        // One parent-owned allocation feeds both the ledger and every role/lens report.
        // A reroute notice cannot allocate cumulative turn usage between models.
        let model = if launch_runtime == SupervisorRuntime::Codex {
            run.authenticated_codex_evidence()
                .filter(|evidence| evidence.requested_model == command.model)
                .filter(|_| usage.is_some() && run.authenticated_codex_usage() == usage)
                .and_then(|evidence| evidence.usage_model())
                .map(str::to_owned)
        } else if launch_runtime == SupervisorRuntime::Grok {
            // Native headless usage does not attest the provider's actual model.
            None
        } else {
            command.model.clone()
        };
        let pricing = if launch_runtime == SupervisorRuntime::Codex {
            model.as_deref().and_then(|model| {
                crate::llm::provider::resolve_model_pricing(&self.model_pricing, model)
                    .filter(|resolved| {
                        resolved.provenance
                            == crate::llm::provider::ModelPricingProvenance::PlanOverride
                    })
                    .map(|resolved| resolved.pricing)
            })
        } else if launch_runtime == SupervisorRuntime::Grok {
            None
        } else {
            self.pricing
        };
        let cost_usd = usage
            .and_then(|usage| pricing.map(|pricing| pricing.cost_usd(usage)))
            .filter(|cost| cost.is_finite());
        // Identity acceptance is deliberately separate from complete token accounting.
        // This does not relax external_process_completed or any publication gate.
        let token_process_completed = if launch_runtime == SupervisorRuntime::Grok {
            run.authenticated_grok_usage(command)
                .is_some_and(|(_, complete)| complete)
        } else if run.authenticated_codex_evidence().is_some() {
            run.authenticated_codex_usage_complete()
        } else {
            external_process_completed(run, launch_runtime)
        };
        let settlement = if external_dispatch_may_have_started(run, launch_runtime) {
            let (measurement, reliability) = match usage {
                Some(usage)
                    if token_process_completed
                        && external_safety_verified(run, launch_runtime)
                        && !run.stdout.raw_capture_truncated()
                        && (run.codex_command_execution_evidence().is_none()
                            || run.authenticated_app_server_evidence().is_some_and(|evidence| {
                                run.codex_command_execution_evidence().is_some_and(|commands|
                                    commands.turn_status == crate::external_agent::codex_app_server::TurnTerminalStatus::Completed)
                                    && run.codex_parent_evidence.as_ref() == Some(evidence)
                            })) =>
                {
                    (
                        UsageMeasurement::Reliable {
                            tokens: usage.total_tokens,
                            cost_usd,
                        },
                        DispatchUsageReliability::Reliable,
                    )
                }
                Some(usage) => (
                    UsageMeasurement::Estimated {
                        tokens: usage.total_tokens,
                        cost_usd,
                    },
                    DispatchUsageReliability::Estimated,
                ),
                None => (UsageMeasurement::Missing, DispatchUsageReliability::Missing),
            };
            self.ledger
                .reconcile_for_runtime_if_configured(
                    self.reservation.id,
                    measurement,
                    Some(runtime_name(launch_runtime)),
                )
                .context("failed to reconcile started dispatch budget reservation")?;
            DispatchUsageSettlement {
                observed_usage: usage,
                reliability,
                model,
                cost_usd,
            }
        } else {
            self.ledger
                .release(self.reservation.id)
                .context("failed to release budget for a dispatch that never started")?;
            DispatchUsageSettlement {
                observed_usage: usage,
                reliability: DispatchUsageReliability::NotStarted,
                model: None,
                cost_usd: None,
            }
        };
        self.state = DispatchBudgetReservationState::Settled;
        Ok(settlement)
    }

    #[cfg(test)]
    fn settle(
        &mut self,
        run: &ExternalAgentRun,
        runtime: SupervisorRuntime,
        command: &ExternalAgentCommand,
    ) -> Result<DispatchUsageSettlement> {
        if !matches!(self.state, DispatchBudgetReservationState::Invoked(bound) if bound == runtime)
        {
            bail!("test settlement runtime does not match the retained launch runtime");
        }
        self.settle_bound_runtime(run, command)
    }
}

impl Drop for DispatchBudgetReservation<'_> {
    fn drop(&mut self) {
        let result = match self.state {
            DispatchBudgetReservationState::Reserved(_) => {
                self.ledger.release(self.reservation.id).map(|_| ())
            }
            DispatchBudgetReservationState::Invoked(launch_runtime) => self
                .ledger
                .reconcile_for_runtime_if_configured(
                    self.reservation.id,
                    UsageMeasurement::Missing,
                    Some(runtime_name(launch_runtime)),
                )
                .map(|_| ()),
            DispatchBudgetReservationState::Settled => Ok(()),
        };
        if result.is_ok() {
            self.state = DispatchBudgetReservationState::Settled;
        }
    }
}

#[derive(Default)]
struct SemanticBlockGate {
    next_order: Mutex<usize>,
    changed: std::sync::Condvar,
}

struct SemanticBlockTurn<'a> {
    next_order: std::sync::MutexGuard<'a, usize>,
    gate: &'a SemanticBlockGate,
}

impl Drop for SemanticBlockTurn<'_> {
    fn drop(&mut self) {
        *self.next_order = self.next_order.saturating_add(1);
        self.gate.changed.notify_all();
    }
}

impl SemanticBlockGate {
    fn wait_for_turn(&self, order: usize) -> Result<SemanticBlockTurn<'_>> {
        let mut next_order = match self.next_order.lock() {
            Ok(next_order) => next_order,
            Err(poisoned) => poisoned.into_inner(),
        };
        while *next_order < order {
            next_order = match self.changed.wait(next_order) {
                Ok(next_order) => next_order,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        if *next_order != order {
            bail!(
                "semantic Block dispatch order {order} was already passed at {}",
                *next_order
            );
        }
        Ok(SemanticBlockTurn {
            next_order,
            gate: self,
        })
    }
}

struct CompletionSignal {
    index: usize,
    sender: mpsc::Sender<usize>,
}

impl Drop for CompletionSignal {
    fn drop(&mut self) {
        let _ = self.sender.send(self.index);
    }
}

#[derive(Default)]
struct PreparedSemanticAssignment {
    token: Option<u64>,
    findings: Vec<Finding>,
    health_signals: Vec<SwarmHealthSignal>,
    assignment_failed: bool,
}

#[cfg(test)]
fn test_runtime_model_catalog(
    plan: &SupervisorPlan,
    runtime: SupervisorRuntime,
) -> Result<RuntimeModelCatalog> {
    match runtime {
        SupervisorRuntime::Codex => {
            let mut models = if plan.role_models.is_empty() {
                crate::selection::built_in_prior_dataset()?
                    .models
                    .into_iter()
                    .filter(|prior| prior.runtime == "codex")
                    .map(|prior| prior.model)
                    .collect::<BTreeSet<_>>()
            } else {
                [
                    AgentRole::Supervisor,
                    AgentRole::ChildOrchestrator,
                    AgentRole::Worker,
                    AgentRole::GateClassifier,
                    AgentRole::Auditor,
                ]
                .into_iter()
                .flat_map(|role| {
                    let selection = effective_role_model_selection(plan, role);
                    let mut models = selection.configured_model_chain();
                    if let UnavailableModelFallback::OrderedCatalogChain(chain) =
                        selection.unavailable_model_fallback
                    {
                        models.extend(chain.budget_degrade_models);
                    }
                    models
                })
                .collect::<BTreeSet<_>>()
            };
            models.extend(
                plan.review_lenses
                    .iter()
                    .map(|lens| lens.backend.model().to_string()),
            );
            CodexRuntimeModelCatalog::from_slugs(models).map(RuntimeModelCatalog::Codex)
        }
        SupervisorRuntime::Fake => Ok(RuntimeModelCatalog::LocalDeterministicFake),
        SupervisorRuntime::Grok
        | SupervisorRuntime::Cursor
        | SupervisorRuntime::ClaudeCode
        | SupervisorRuntime::GeminiCli => Ok(RuntimeModelCatalog::OperatorDeclared),
    }
}

#[cfg(test)]
fn run_supervisor_plan_with_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    run_supervisor_plan_with_budget_and_runner(
        plan,
        consultant,
        SupervisorBudgetConfig::default(),
        options,
        execution_runtime,
        external_runner,
    )
}

#[cfg(test)]
fn run_supervisor_plan_with_budget_and_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    run_budget: SupervisorBudgetConfig,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    let runtime_model_catalog = test_runtime_model_catalog(&plan, options.runtime)?;
    run_supervisor_plan_with_budget_catalog_and_runner(
        plan,
        consultant,
        run_budget,
        options,
        execution_runtime,
        Ok(runtime_model_catalog),
        external_runner,
    )
}

#[cfg(test)]
fn run_supervisor_plan_with_runtime_model_catalog_and_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    run_supervisor_plan_with_budget_catalog_and_runner(
        plan,
        consultant,
        SupervisorBudgetConfig::default(),
        options,
        execution_runtime,
        runtime_model_catalog,
        external_runner,
    )
}

#[cfg(test)]
fn run_supervisor_plan_with_budget_catalog_and_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    run_budget: SupervisorBudgetConfig,
    options: SupervisorRunOptions,
    execution_runtime: SupervisorExecutionRuntime,
    runtime_model_catalog: RuntimeModelCatalogAcquisition,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    let serialized_runner = Mutex::new(external_runner);
    let worktree_creation = match execution_runtime {
        SupervisorExecutionRuntime::Verified => SupervisorWorktreeCreation::VerifiedTestOnly,
        SupervisorExecutionRuntime::NonpublishableSimulation => {
            SupervisorWorktreeCreation::TestOnly
        }
    };
    run_supervisor_plan_with_runner_and_creation(
        LoadedSupervisorPlan {
            plan,
            consultant,
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata {
                run_budget,
                ..SupervisorPlanMetadata::default()
            },
        },
        options,
        1,
        execution_runtime,
        worktree_creation,
        runtime_model_catalog,
        &|command, _cancellation, _review_runtime| match serialized_runner.lock() {
            Ok(mut runner) => runner(command),
            Err(poisoned) => poisoned.into_inner()(command),
        },
    )
}

#[cfg(test)]
fn run_loaded_supervisor_plan_with_runner(
    loaded: LoadedSupervisorPlan,
    options: SupervisorRunOptions,
    external_runner: &mut (dyn FnMut(&ExternalAgentCommand, bool) -> ExternalAgentRun + Send),
) -> Result<SupervisorFinalReport> {
    let runtime_model_catalog = test_runtime_model_catalog(&loaded.plan, options.runtime)?;
    let serialized_runner = Mutex::new(external_runner);
    run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        1,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        Ok(runtime_model_catalog),
        &|command, _cancellation, review_runtime| match serialized_runner.lock() {
            Ok(mut runner) => runner(command, review_runtime.is_some()),
            Err(poisoned) => poisoned.into_inner()(command, review_runtime.is_some()),
        },
    )
}

#[cfg(test)]
fn run_supervisor_plan_with_concurrent_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    external_runner: &(dyn Fn(&ExternalAgentCommand) -> ExternalAgentRun + Send + Sync),
) -> Result<SupervisorFinalReport> {
    run_supervisor_plan_with_budget_and_concurrent_runner(
        plan,
        consultant,
        SupervisorBudgetConfig::default(),
        options,
        max_concurrent_children,
        external_runner,
    )
}

#[cfg(test)]
fn run_supervisor_plan_with_budget_and_concurrent_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    run_budget: SupervisorBudgetConfig,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    external_runner: &(dyn Fn(&ExternalAgentCommand) -> ExternalAgentRun + Send + Sync),
) -> Result<SupervisorFinalReport> {
    let runtime_model_catalog = test_runtime_model_catalog(&plan, options.runtime)?;
    run_supervisor_plan_with_runner_and_creation(
        LoadedSupervisorPlan {
            plan,
            consultant,
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata {
                run_budget,
                ..SupervisorPlanMetadata::default()
            },
        },
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        Ok(runtime_model_catalog),
        &|command, _cancellation, _review_runtime| external_runner(command),
    )
}

#[cfg(test)]
fn run_supervisor_plan_with_concurrent_cancellable_runner(
    plan: SupervisorPlan,
    consultant: SupervisorConsultantPlan,
    options: SupervisorRunOptions,
    max_concurrent_children: usize,
    external_runner: &CancellableExternalRunner<'_>,
) -> Result<SupervisorFinalReport> {
    let runtime_model_catalog = test_runtime_model_catalog(&plan, options.runtime)?;
    run_supervisor_plan_with_runner_and_creation(
        LoadedSupervisorPlan {
            plan,
            consultant,
            assignment_metadata: AssignmentMetadata::new(),
            plan_metadata: SupervisorPlanMetadata::default(),
        },
        options,
        max_concurrent_children,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        Ok(runtime_model_catalog),
        external_runner,
    )
}

#[cfg(test)]
fn validate_legacy_supervisor_plan(plan: SupervisorPlan) -> Result<SupervisorPlan> {
    let metadata = SupervisorPlanMetadata {
        assignment_schedule: plan
            .assignments
            .iter()
            .enumerate()
            .map(|(flattened_index, assignment)| AssignmentScheduleEntry {
                assignment_id: assignment.id.trim().to_string(),
                parent_assignment_id: None,
                depth: MIN_SUPERVISOR_DEPTH,
                flattened_index,
            })
            .collect(),
        ..SupervisorPlanMetadata::default()
    };
    validate_supervisor_plan(plan, metadata).map(|(plan, _)| plan)
}

#[derive(Debug, Clone)]
struct AssignmentSemanticScope<'a> {
    label: String,
    semantic_symbols: &'a [String],
    semantic_modules: &'a [String],
}

enum SemanticAssignmentCoordination {
    Ready(Option<u64>),
    Blocked(usize),
}

struct ChildReportCollectionContext<'a> {
    assignment: &'a OrchestratorAssignment,
    assignment_metadata: &'a AssignmentMetadata,
    report_path: &'a Path,
    external_run: &'a ExternalAgentRun,
    external_command: &'a ExternalAgentCommand,
    worktree_path: &'a Path,
    child_base_head: &'a Oid,
    worker_journals: &'a WorkerExecutionJournalEvidenceSet,
    evidence_only_source: Option<&'a OrchestratorReviewReport>,
    observed_changed_paths: Option<&'a [PathBuf]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupervisorCandidateInspection {
    binding: CandidateValidationBinding,
    changed_paths: Vec<PathBuf>,
}

struct AuditorReviewPathCoverage {
    missing_paths: Vec<PathBuf>,
    excluded_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryWorktreeSnapshot {
    head: PrimaryHeadSnapshot,
    index: BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>,
    index_storage: PrimaryIndexStorageSnapshot,
    status: BTreeMap<Vec<u8>, PrimaryStatusState>,
    worktree: BTreeMap<Vec<u8>, PrimaryPathState>,
    inspection_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryHeadSnapshot {
    detached: bool,
    reference_name: Option<Vec<u8>>,
    symbolic_target: Option<Vec<u8>>,
    target: Option<Oid>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrimaryIndexEntryKey {
    path: Vec<u8>,
    stage: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryIndexEntryState {
    id: Oid,
    mode: u32,
    tag: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryStatusState {
    code: [u8; 2],
    original_path: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryIndexStorageSnapshot {
    worktree_index: IndexFileSnapshot,
    shared_index: Option<SharedIndexFileSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SharedIndexFileSnapshot {
    path: PathBuf,
    storage: IndexFileSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IndexFileSnapshot {
    Missing,
    Present { bytes: u64, digest: Oid },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrimaryPathState {
    Missing,
    File {
        id: Oid,
        mode: u32,
    },
    Symlink {
        target: PathBuf,
        mode: u32,
    },
    Directory {
        nested_repository: Option<Box<PrimaryWorktreeSnapshot>>,
        contents_digest: Option<Oid>,
        mode: u32,
    },
    Other {
        mode: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryIntegrityChanges {
    details: Vec<String>,
    paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrimaryScopeSnapshot {
    files: BTreeMap<PathBuf, PrimaryScopedFileState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PrimaryScopedFileState {
    Missing,
    File { id: Oid, mode: u32, bytes: Vec<u8> },
}

impl PrimaryIntegrityChanges {
    fn is_empty(&self) -> bool {
        self.details.is_empty()
    }
}

impl PrimaryWorktreeSnapshot {
    fn inspection_problem(&self) -> Option<String> {
        if let Some(error) = &self.inspection_error {
            return Some(error.clone());
        }
        self.worktree.iter().find_map(|(path, state)| {
            let PrimaryPathState::Directory {
                nested_repository: Some(nested),
                ..
            } = state
            else {
                return None;
            };
            nested.inspection_problem().map(|error| {
                format!(
                    "nested repository {}: {error}",
                    finding_path_from_git_bytes(path).display()
                )
            })
        })
    }
}

#[derive(Debug, Clone)]
struct ClaimConflictDetail {
    path: PathBuf,
    owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedReport<T> {
    report: T,
    recovered: bool,
}

#[cfg(test)]
fn create_invocation_scratches(
    writer: &mut ArtifactRunWriter,
) -> Result<(ArtifactScratchDirectory, ArtifactScratchDirectory)> {
    create_named_invocation_scratches(writer, Path::new("incoming"), Path::new("capture"))
}

struct AcceptedFieldGuideDraft {
    source_node: String,
    source_role: &'static str,
    finding_bytes: usize,
    context_bytes: usize,
    draft: FieldGuideDraft,
}

trait ReportStatus {
    fn accepted(&self) -> bool;
    fn rejected(&self) -> bool;
    fn status(&self) -> ReviewStatus;
}

impl ReportStatus for OrchestratorReviewReport {
    fn accepted(&self) -> bool {
        self.accepted
    }

    fn rejected(&self) -> bool {
        self.rejected
    }

    fn status(&self) -> ReviewStatus {
        self.status
    }
}

impl ReportStatus for WorkerReport {
    fn accepted(&self) -> bool {
        self.accepted
    }

    fn rejected(&self) -> bool {
        self.rejected
    }

    fn status(&self) -> ReviewStatus {
        self.status
    }
}

impl ReportStatus for AuditorReport {
    fn accepted(&self) -> bool {
        self.accepted
    }

    fn rejected(&self) -> bool {
        self.rejected
    }

    fn status(&self) -> ReviewStatus {
        self.status
    }
}

#[derive(Debug, Clone, PartialEq)]
struct RoleUsageSample {
    role: AgentRole,
    lens_id: Option<String>,
    model: Option<String>,
    usage: Usage,
    cost_usd: Option<f64>,
}

struct RoleUsageAggregation {
    reports: BTreeMap<AgentRole, RoleUsageReport>,
    lens_reports: Vec<ReviewLensUsageReport>,
    total_usage: Option<Usage>,
    total_cost_usd: Option<f64>,
    lens_total_usage: Option<Usage>,
    lens_total_cost_usd: Option<f64>,
}

#[derive(Debug)]
struct RunDirs {
    run_dir: PathBuf,
    assignments: PathBuf,
    schemas: PathBuf,
    reports: PathBuf,
}

impl RunDirs {
    fn for_writer(writer: &ArtifactRunWriter) -> Self {
        let run_dir = writer.run_dir().to_path_buf();
        Self {
            assignments: run_dir.join("assignments"),
            schemas: run_dir.join("schemas"),
            reports: run_dir.join("reports"),
            run_dir,
        }
    }

    fn relative(&self, path: &Path) -> Result<PathBuf> {
        path.strip_prefix(&self.run_dir)
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "artifact path {} is outside supervise run {}",
                    path.display(),
                    self.run_dir.display()
                )
            })
    }
}

#[derive(Debug, Clone)]
struct PathOwner {
    id: String,
    path: PathBuf,
}

#[cfg(test)]
mod grok_native_settlement_tests {
    use super::*;
    use crate::process_runner::{
        CapturedBytes, ContainmentBackend, SideEffectConfinementProfileKind,
    };
    use crate::runtime_adapter::RuntimeAdapterConfig;

    fn command(root: &Path) -> ExternalAgentCommand {
        let mut command = ExternalAgentCommand::codex(
            "grok",
            root,
            root.join("prompt"),
            root.join("log"),
            root.join("report"),
            Duration::from_secs(1),
        )
        .with_runtime_adapter(
            SupervisorRuntime::Grok,
            RuntimeAdapterConfig::defaults(SupervisorRuntime::Grok),
        );
        command.model = Some("requested-only-model".into());
        command
    }

    fn capture() -> CapturedBytes {
        CapturedBytes::from_bytes_for_test(b"{\"type\":\"end\",\"stopReason\":\"stop\",\"sessionId\":\"s\",\"requestId\":\"r\",\"usage\":{\"input_tokens\":12,\"output_tokens\":5,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":3,\"reasoning_tokens\":2,\"total_tokens\":24}}\n".to_vec())
    }

    fn native_run(command: &ExternalAgentCommand, complete: bool) -> ExternalAgentRun {
        let mut run = deterministic_fake_run(command, Vec::new());
        // Explicit per-case parent-capture injection; no generic fixture gains custody.
        run.stdout.text = String::from_utf8(capture().as_bytes().to_vec()).unwrap();
        run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ));
        run.side_effects = Some(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::ExternalGrok,
        ));
        run.publishable = true;
        run.retain_grok_native_usage_for_test(command, &capture(), complete);
        run
    }

    fn reserve(ledger: &RunBudgetLedger) -> DispatchBudgetReservation<'_> {
        let reservation = ledger
            .reserve(BudgetReservationRequest {
                role: AgentRole::Worker,
                tokens: 10,
                cost_usd: Some(0.01),
            })
            .unwrap()
            .reservation()
            .expect("admitted")
            .clone();
        DispatchBudgetReservation {
            ledger,
            reservation,
            pricing: Some(ModelPricing {
                input_usd_per_million_tokens: 7.0,
                output_usd_per_million_tokens: 7.0,
            }),
            model_pricing: BTreeMap::new(),
            state: DispatchBudgetReservationState::Reserved(SupervisorRuntime::Grok),
        }
    }

    fn ledger(cost: Option<f64>) -> RunBudgetLedger {
        RunBudgetLedger::new(crate::supervise_budget::RunBudgetLimits {
            hard_tokens: Some(100),
            hard_cost_usd: cost,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn grok_native_settlement_reaches_same_reservation_role_and_total_without_model_price() {
        let temp = tempfile::tempdir().unwrap();
        let command = command(temp.path());
        let mut run = native_run(&command, true);
        // Public output/log replacement cannot erase or replace private counters.
        std::fs::write(
            &command.json_log,
            b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n",
        )
        .unwrap();
        run.stdout.text = "altered public summary".into();
        run.grok_stream_usage_evidence =
            Some(crate::runtime_adapter::grok::GrokStreamUsageEvidence::NotProcessObservable);
        let ledger = ledger(None);
        let mut reservation = reserve(&ledger);
        reservation
            .mark_invoked_for_runtime(SupervisorRuntime::Grok)
            .unwrap();
        let settled = reservation.settle_bound_runtime(&run, &command).unwrap();
        assert_eq!(settled.reliability, DispatchUsageReliability::Reliable);
        assert_eq!(
            settled.observed_usage,
            Some(Usage {
                input_tokens: 19,
                output_tokens: 5,
                total_tokens: 24
            })
        );
        assert_eq!(settled.model, None);
        assert_eq!(settled.cost_usd, None);
        assert!(
            reservation.settle_bound_runtime(&run, &command).is_err(),
            "settle once"
        );
        let budget = ledger.report().unwrap();
        assert_eq!(budget.consumed.tokens, 24);
        assert_eq!(budget.consumed.cost_usd, None);
        assert_eq!(budget.reserved.tokens, 0);
        assert!(budget.usage_complete && budget.new_dispatch_allowed);
        let plan: SupervisorPlan = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(plan.review_lenses.len(), 3);
        let report = role_usage_report(
            &plan,
            vec![settled.role_sample(AgentRole::Worker, None).unwrap()],
        )
        .unwrap();
        assert_eq!(report.total_usage, settled.observed_usage);
        assert_eq!(report.total_cost_usd, None);
        assert_eq!(
            report.reports[&AgentRole::Worker].usage,
            settled.observed_usage
        );
        assert!(report.reports[&AgentRole::Worker].models.is_empty());
        assert!(report.lens_reports.iter().all(|lens| lens.usage.is_none()));
        drop(reserve(&ledger));
        assert_eq!(
            ledger.report().unwrap().reserved.tokens,
            0,
            "ordinary second admission and RAII refund"
        );
    }

    #[test]
    fn grok_native_settlement_unknown_usd_stops_next_invocation() {
        let temp = tempfile::tempdir().unwrap();
        let command = command(temp.path());
        let run = native_run(&command, true);
        let ledger = ledger(Some(1.0));
        let mut reservation = reserve(&ledger);
        reservation
            .mark_invoked_for_runtime(SupervisorRuntime::Grok)
            .unwrap();
        let settled = reservation.settle_bound_runtime(&run, &command).unwrap();
        assert_eq!(
            settled.cost_usd, None,
            "requested model's reservation price is not observed cost"
        );
        let report = ledger.report().unwrap();
        assert_eq!(report.consumed.tokens, 24);
        assert!(report.usage_complete);
        assert!(!report.new_dispatch_allowed);
        assert!(matches!(
            ledger
                .reserve(BudgetReservationRequest {
                    role: AgentRole::Worker,
                    tokens: 1,
                    cost_usd: Some(0.0)
                })
                .unwrap(),
            BudgetAdmission::Refused { .. }
        ));
    }

    #[test]
    fn grok_native_settlement_cancelled_partial_is_charged_without_acceptance_or_price() {
        let temp = tempfile::tempdir().unwrap();
        let command = command(temp.path());
        let mut run = native_run(&command, false);
        run.error = Some("supervisor cancellation".into());
        run.publishable = false;
        let ledger = ledger(None);
        let mut reservation = reserve(&ledger);
        reservation
            .mark_invoked_for_runtime(SupervisorRuntime::Grok)
            .unwrap();
        let settled = reservation.settle_bound_runtime(&run, &command).unwrap();
        assert_eq!(settled.reliability, DispatchUsageReliability::Estimated);
        assert_eq!(settled.observed_usage.unwrap().total_tokens, 24);
        assert_eq!(settled.cost_usd, None);
        assert!(settled.role_sample(AgentRole::Worker, None).is_none());
        assert!(!external_process_completed(&run, SupervisorRuntime::Grok));
        let report = ledger.report().unwrap();
        assert_eq!(report.consumed.tokens, 24);
        assert_eq!(report.reserved.tokens, 0);
        assert!(
            !report.usage_complete,
            "incomplete spend cannot qualify usage"
        );
        assert!(!report.new_dispatch_allowed);
    }

    #[test]
    fn grok_native_settlement_public_log_or_wire_cannot_mint_private_tokens() {
        let temp = tempfile::tempdir().unwrap();
        let command = command(temp.path());
        let original = native_run(&command, true);
        std::fs::write(
            &command.json_log,
            b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":7,\"output_tokens\":3}}\n",
        )
        .unwrap();
        let restored: ExternalAgentRun =
            serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(external_process_completed(
            &restored,
            SupervisorRuntime::Grok
        ));
        assert!(external_usage_for_runtime(&restored, &command, SupervisorRuntime::Grok).is_none());
        let ledger = ledger(None);
        let mut reservation = reserve(&ledger);
        reservation
            .mark_invoked_for_runtime(SupervisorRuntime::Grok)
            .unwrap();
        let settled = reservation
            .settle_bound_runtime(&restored, &command)
            .unwrap();
        assert_eq!(settled.reliability, DispatchUsageReliability::Missing);
        assert_eq!(settled.observed_usage, None);
        let report = ledger.report().unwrap();
        assert_eq!(
            report.consumed.tokens, 10,
            "conservative admission charge, not forged log tokens"
        );
        assert!(!report.usage_complete);
        assert!(!report.new_dispatch_allowed);
    }

    #[test]
    fn grok_native_reservation_preserves_runtime_binding_refund_and_drop_charge() {
        let ledger = ledger(None);
        {
            let mut reservation = reserve(&ledger);
            assert!(reservation
                .mark_invoked_for_runtime(SupervisorRuntime::Codex)
                .is_err());
            reservation.settle_not_started().unwrap();
        }
        assert_eq!(ledger.report().unwrap().consumed.tokens, 0);
        assert_eq!(ledger.report().unwrap().reserved.tokens, 0);
        {
            let mut reservation = reserve(&ledger);
            reservation
                .mark_invoked_for_runtime(SupervisorRuntime::Grok)
                .unwrap();
        }
        let report = ledger.report().unwrap();
        assert_eq!(report.consumed.tokens, 10);
        assert_eq!(report.reserved.tokens, 0);
        assert!(!report.usage_complete);
    }
}
