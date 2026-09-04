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
    mutation_session: &'a SupervisorRunMutationSession,
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
    Reserved,
    Invoked(SupervisorRuntime),
    Settled,
}

struct DispatchBudgetReservation<'a> {
    ledger: &'a RunBudgetLedger,
    reservation: BudgetReservation,
    pricing: Option<ModelPricing>,
    state: DispatchBudgetReservationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DispatchUsageReliability {
    Reliable,
    Estimated,
    Missing,
    NotStarted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DispatchUsageSettlement {
    observed_usage: Option<Usage>,
    reliability: DispatchUsageReliability,
}

impl DispatchUsageSettlement {
    fn reliable_usage(self) -> Option<Usage> {
        (self.reliability == DispatchUsageReliability::Reliable)
            .then_some(self.observed_usage)
            .flatten()
    }

    fn is_degraded(self) -> bool {
        matches!(
            self.reliability,
            DispatchUsageReliability::Estimated | DispatchUsageReliability::Missing
        )
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
        if self.state != DispatchBudgetReservationState::Reserved {
            bail!("budget reservation was invoked outside its reserved state");
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
        let usage = complete_external_codex_usage(run, command);
        let settlement = if external_dispatch_may_have_started(run, launch_runtime) {
            let (measurement, reliability) = match usage {
                Some(usage)
                    if external_process_completed(run, launch_runtime)
                        && external_safety_verified(run, launch_runtime)
                        && !run.stdout.truncated =>
                {
                    (
                        UsageMeasurement::Reliable {
                            tokens: usage.total_tokens,
                            cost_usd: self
                                .pricing
                                .map(|pricing| pricing.cost_usd(usage))
                                .filter(|cost| cost.is_finite()),
                        },
                        DispatchUsageReliability::Reliable,
                    )
                }
                Some(usage) => (
                    UsageMeasurement::Estimated {
                        tokens: usage.total_tokens,
                        cost_usd: self
                            .pricing
                            .map(|pricing| pricing.cost_usd(usage))
                            .filter(|cost| cost.is_finite()),
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
            }
        } else {
            self.ledger
                .release(self.reservation.id)
                .context("failed to release budget for a dispatch that never started")?;
            DispatchUsageSettlement {
                observed_usage: usage,
                reliability: DispatchUsageReliability::NotStarted,
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
            DispatchBudgetReservationState::Reserved => {
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
    authorize_and_run_supervisor_plan_with_runner_and_creation(
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
        &|command, _cancellation, _review_runtime, _authorization| match serialized_runner.lock() {
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
    authorize_and_run_supervisor_plan_with_runner_and_creation(
        loaded,
        options,
        1,
        SupervisorExecutionRuntime::NonpublishableSimulation,
        SupervisorWorktreeCreation::TestOnly,
        Ok(runtime_model_catalog),
        &|command, _cancellation, review_runtime, _authorization| match serialized_runner.lock() {
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
    authorize_and_run_supervisor_plan_with_runner_and_creation(
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
        &|command, _cancellation, _review_runtime, _authorization| external_runner(command),
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
    authorize_and_run_supervisor_plan_with_runner_and_creation(
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleUsageSample {
    role: AgentRole,
    lens_id: Option<String>,
    model: Option<String>,
    usage: Usage,
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
