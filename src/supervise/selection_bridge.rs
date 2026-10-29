//! Supervisor integration for the pure runtime/model/effort selector.
//!
//! The bridge is intentionally the only place where supervisor runtime state
//! is translated into selector input. The selector remains deterministic and
//! cannot inspect the host, clock, catalog, or supervisor plan directly.

use super::environment_observation::AccountObserveOutcomeKind;
use super::*;
use crate::objective_profile::ResolvedObjectiveProfile;
use crate::optimizer::action::{
    AgentRole as OptimizerRole, CanonicalEffort, ExecutionBudget, HedgeTopology, ModelAction,
    PlannerTopology, RestartMode, ReviewTopology, RuntimeModelId, TopologySpec, WorkerTopology,
};
use crate::optimizer::explanation::EscalationComparison;
use crate::optimizer::features::{FeatureValue, TaskFeatures};
use crate::optimizer::ids::{
    BackendId, CandidateId, CatalogVersion, FeatureId, ModelFamilyId, PolicyId, PolicyNodeId,
    ProviderId, RuntimeSlug, TimestampMillis, VerifierProfileId,
};
use crate::optimizer::online_router::{
    CheckpointRouter, RouterConfig, SafeContextualRouter, TailRiskObjective,
};
use crate::optimizer::policy::{PolicyGraph, PolicyNode};
use crate::optimizer::predictor::{feature_keys, HierarchicalPolicyPredictor};
use crate::optimizer::resources::ResourceVector;
use crate::optimizer::state::{DecisionHorizon, OptimizerState};
#[cfg(test)]
use crate::optimizer::switch_cost::SwitchCostEstimate;
use crate::optimizer::switch_cost::{SwitchCostModel, SwitchHysteresis, TransitionClass};
use crate::optimizer::telemetry::{
    CostClass, DecisionId, InvocationId, InvocationRecord, OptimizationRunId, PolicyExecutionId,
};
use crate::optimizer::trajectory::{TrajectoryEvent, TrajectoryObservation};
use crate::selection::{
    self, AuthorityRole, Boundedness, BudgetSignal, CandidateCapabilities, CandidateKey,
    CandidateSwitchCostEvidence, CatalogModel, ContextSize, DebugOverride, DecisionStatus,
    DynamicSignals, LiveOperationalObservations, ObjectiveProfileRef, OperatorConstraints,
    OutcomeRecord, ReasoningEffort as SelectorEffort, RiskLevel, RuntimeCatalog, RuntimePoolState,
    SelectionInput, SelectionProvenance, TaskHorizon, TaskProfile, TypedAxisObservation,
    TypedObservationKind,
};
#[cfg(target_os = "linux")]
use coding_agent_manager_lib::account_authority::{
    ModelsObservation, ObservationOutcome, ObservedModel, QuotaObservation,
};
use std::path::Path;

#[path = "selection_preflight.rs"]
pub(super) mod selection_preflight;

#[path = "assignment_selection.rs"]
mod assignment_selection;
pub(super) use assignment_selection::AssignmentSelectionShapes;

/// Account observation is a Linux-only CAM type. Non-Linux keeps
/// `account_observation=None` and the advertised-catalog path.
#[cfg(target_os = "linux")]
pub(super) type AccountObserveResult =
    coding_agent_manager_lib::account_authority::AccountObserveResult;
#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug)]
pub(super) enum AccountObserveResult {}

const AUTOMATIC_SELECTION_TASK_CLASS: &str = "localized_code_change";
const JUDGMENT_SELECTION_TASK_CLASS: &str = "review_gate";
const CURSOR_CATALOG_EVIDENCE_GAP_MAX_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorCatalogEvidenceGap {
    message: String,
    observed_at_unix_millis: u64,
}

impl CursorCatalogEvidenceGap {
    fn from_error(error: &anyhow::Error, observed_at_unix_millis: u64) -> Self {
        let detail = format!("{error:#}");
        let detail = bounded_cursor_catalog_gap_detail(&detail);
        Self {
            message: format!("optional Cursor runtime model catalog observation failed: {detail}"),
            observed_at_unix_millis,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct AdvertisedCatalogSet {
    pub cursor: Option<crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation>,
    pub grok: Option<crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation>,
    cursor_evidence_gap: Option<CursorCatalogEvidenceGap>,
}

impl AdvertisedCatalogSet {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn empty() -> Self {
        Self {
            cursor: None,
            grok: None,
            cursor_evidence_gap: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_grok(
        observation: crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation,
    ) -> Self {
        Self {
            cursor: None,
            grok: Some(observation),
            cursor_evidence_gap: None,
        }
    }
}

fn bounded_cursor_catalog_gap_detail(detail: &str) -> &str {
    if detail.len() <= CURSOR_CATALOG_EVIDENCE_GAP_MAX_BYTES {
        return detail;
    }
    let mut end = CURSOR_CATALOG_EVIDENCE_GAP_MAX_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    &detail[..end]
}

fn cursor_catalog_optional_unavailability(error: &anyhow::Error) -> bool {
    let text = format!("{error:#}").to_ascii_lowercase();
    text.contains("is missing")
        || text.contains("not found")
        || text.contains("no such file")
        || text.contains("timed out")
        || text.contains("cannot find")
        || text.contains("command failed with exit status")
}

#[cfg(test)]
const TEST_CURSOR_CATALOG_FIXTURE_ENV: &str = "MACO_TEST_CURSOR_CATALOG_FIXTURE";
#[cfg(test)]
const TEST_CURSOR_CATALOG_OBSERVED_AT_ENV: &str = "MACO_TEST_CURSOR_CATALOG_OBSERVED_AT";
#[cfg(test)]
const TEST_SELECTOR_TRIPLE_RUNNER_UP_MODEL: &str = "gpt-5.6-sol-selector-triple-runner-up";
#[cfg(test)]
const TEST_BELOW_FLOOR_REVIEW_AUDITOR_MODEL: &str = FRONTIER_PROFILE_MODEL;

#[cfg(test)]
thread_local! {
    static TEST_ADVERTISED_CATALOGS: RefCell<Option<AdvertisedCatalogSet>> = const {
        RefCell::new(None)
    };
    static TEST_SELECTOR_TRIPLE_RUNNER_UP_ENABLED: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
pub(super) struct TestAdvertisedCatalogBindGuard {
    previous: Option<AdvertisedCatalogSet>,
}

#[cfg(test)]
impl Drop for TestAdvertisedCatalogBindGuard {
    fn drop(&mut self) {
        TEST_ADVERTISED_CATALOGS.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

#[cfg(test)]
pub(super) fn bind_test_cursor_catalog_fixture(
    path: &Path,
) -> Result<TestAdvertisedCatalogBindGuard> {
    let advertised = observe_cursor_catalog_from_fixture(path)?;
    Ok(
        TEST_ADVERTISED_CATALOGS.with(|slot| TestAdvertisedCatalogBindGuard {
            previous: slot.borrow_mut().replace(advertised),
        }),
    )
}

#[cfg(test)]
pub(super) struct TestSelectorTripleCatalogBindGuard {
    previous_runner_up_enabled: bool,
    _model_capability: InstalledModelCapabilityPolicy,
}

#[cfg(test)]
impl Drop for TestSelectorTripleCatalogBindGuard {
    fn drop(&mut self) {
        TEST_SELECTOR_TRIPLE_RUNNER_UP_ENABLED.with(|enabled| {
            enabled.set(self.previous_runner_up_enabled);
        });
    }
}

#[cfg(test)]
pub(super) fn bind_test_selector_triple_catalog(
) -> Result<(TestSelectorTripleCatalogBindGuard, RuntimeModelCatalog)> {
    let mut slugs = selection::built_in_prior_dataset()?
        .models
        .into_iter()
        .filter(|prior| prior.runtime == runtime_name(SupervisorRuntime::Codex))
        .map(|prior| prior.model)
        .collect::<BTreeSet<_>>();
    slugs.insert(TEST_SELECTOR_TRIPLE_RUNNER_UP_MODEL.to_string());
    let catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(slugs)?);
    let model_capability = install_test_fixture_models(&[(
        TEST_SELECTOR_TRIPLE_RUNNER_UP_MODEL,
        ModelCapabilityClass::CriticalJudgment,
    )])?;
    let previous_runner_up_enabled =
        TEST_SELECTOR_TRIPLE_RUNNER_UP_ENABLED.with(|enabled| enabled.replace(true));
    Ok((
        TestSelectorTripleCatalogBindGuard {
            previous_runner_up_enabled,
            _model_capability: model_capability,
        },
        catalog,
    ))
}

#[cfg(test)]
struct TestBelowFloorReviewAuditorBindGuard {
    _prior: super::prior_input::OperatorPriorDataGuard,
    _temp: tempfile::TempDir,
}

#[cfg(test)]
fn bind_test_below_floor_review_auditor() -> Result<(
    TestBelowFloorReviewAuditorBindGuard,
    CodexRuntimeModelCatalog,
)> {
    // The permitted slug is shared by all roles. Keep this negative capability
    // fixture thread-local so parallel Auditor tests retain their own baseline.
    let temp = tempfile::tempdir()?;
    git2::Repository::init(temp.path())?;
    let priors = selection::built_in_prior_dataset()?;
    let mut capabilities = default_model_capability_policy();
    capabilities
        .models
        .retain(|row| row.model == TEST_BELOW_FLOOR_REVIEW_AUDITOR_MODEL);
    capabilities.models[0].capability = ModelCapabilityClass::GeneralJudgment;
    std::fs::write(
        temp.path().join("prior.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "dataset_id": "below-floor-auditor-fixture",
            "revision": "below-floor-auditor-fixture-v1", "published_on": priors.published_on,
            "models": [], "capability_policy": capabilities,
        }))?,
    )?;
    let prior = super::prior_input::bind_operator_prior_data(temp.path(), "prior.json")?;
    let catalog = CodexRuntimeModelCatalog::from_slugs([TEST_BELOW_FLOOR_REVIEW_AUDITOR_MODEL])?;
    Ok((
        TestBelowFloorReviewAuditorBindGuard {
            _prior: prior,
            _temp: temp,
        },
        catalog,
    ))
}

/// Observe advertised runtime catalogs for supervisor launch.
///
/// Under `cargo test` this stays hermetic: it never resolves or starts a
/// third-party CLI. Production binaries screen live `cursor-agent models` and
/// `grok models` observations and retain a private evidence gap when the
/// optional Cursor catalog cannot be observed.
pub(super) fn advertised_catalogs_for_launch(repo: &Path) -> Result<AdvertisedCatalogSet> {
    #[cfg(test)]
    {
        let _ = repo;
        advertised_catalogs_from_test_fixtures()
    }
    #[cfg(not(test))]
    {
        advertised_catalogs_from_live_runtimes(repo)
    }
}

#[cfg(test)]
fn advertised_catalogs_from_test_fixtures() -> Result<AdvertisedCatalogSet> {
    if let Some(advertised) = TEST_ADVERTISED_CATALOGS.with(|slot| slot.borrow().clone()) {
        return Ok(advertised);
    }
    let Some(path) = std::env::var_os(TEST_CURSOR_CATALOG_FIXTURE_ENV) else {
        return Ok(AdvertisedCatalogSet::empty());
    };
    observe_cursor_catalog_from_fixture(Path::new(&path))
}

#[cfg(test)]
fn observe_cursor_catalog_from_fixture(path: &Path) -> Result<AdvertisedCatalogSet> {
    let bytes = std::fs::read(path).with_context(|| {
        format!(
            "failed to read hermetic Cursor catalog fixture {}",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        bail!(
            "hermetic Cursor catalog fixture {} is empty",
            path.display()
        );
    }
    let observed_at = std::env::var(TEST_CURSOR_CATALOG_OBSERVED_AT_ENV)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .unwrap_or(1_787_240_463_000);
    let observation = crate::runtime_adapter::cursor::discover_cursor_model_catalog(
        &HermeticCursorCatalogRunner::successful(&bytes),
        &crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new("/workspace"),
        Some(observed_at),
    )?;
    Ok(AdvertisedCatalogSet {
        cursor: Some(observation),
        grok: None,
        cursor_evidence_gap: None,
    })
}

#[cfg(not(test))]
fn advertised_catalogs_from_live_runtimes(repo: &Path) -> Result<AdvertisedCatalogSet> {
    let observed_at_unix_millis = cursor_catalog_observation_time()?;
    let cursor_binding =
        super::runtime_executables::catalog_program(repo, SupervisorRuntime::Cursor)?;
    let (cursor, cursor_evidence_gap) = if cursor_binding.as_ref().is_some_and(Option::is_none) {
        (None, None)
    } else {
        match observe_live_cursor_catalog(
            repo,
            observed_at_unix_millis,
            cursor_binding
                .as_ref()
                .and_then(|program| program.as_deref()),
        ) {
            Ok(observation) => (Some(observation), None),
            Err(error)
                if cursor_binding.is_none() && cursor_catalog_optional_unavailability(&error) =>
            {
                (
                    None,
                    Some(CursorCatalogEvidenceGap::from_error(
                        &error,
                        observed_at_unix_millis,
                    )),
                )
            }
            Err(error) => {
                return Err(error).context("live Cursor catalog observation failed closed");
            }
        }
    };
    let grok_binding = super::runtime_executables::catalog_program(repo, SupervisorRuntime::Grok)?;
    let grok_program = match &grok_binding {
        Some(Some(path)) => Some(path.as_os_str().to_os_string()),
        Some(None) => None,
        None => std::env::var_os("MACO_GROK_BIN"),
    };
    #[cfg(target_os = "linux")]
    let grok = if grok_binding.as_ref().is_some_and(Option::is_none) {
        None
    } else {
        match crate::account_authority::grok::acquire_optional_grok_catalog_authority()? {
            Some(authority) => {
                authority.verify_binding_unchanged()?;
                let runner = crate::runtime_adapter::grok::BoundGrokCatalogCommandRunner::new(
                    authority.managed_grok_home(),
                )?;
                let observed = observe_optional_live_grok_catalog(
                    &runner,
                    repo,
                    observed_at_unix_millis,
                    grok_program.as_deref(),
                )?;
                authority.verify_binding_unchanged()?;
                observed
            }
            None if grok_program.is_none() => None,
            None => bail!(
                "live Grok catalog requires a complete Coding Agent Manager selected grok-cli account"
            ),
        }
    };
    #[cfg(not(target_os = "linux"))]
    let grok = if grok_binding.as_ref().is_some_and(Option::is_none) {
        None
    } else {
        observe_optional_live_grok_catalog(
            &crate::runtime_adapter::grok::ScreenedGrokCatalogCommandRunner,
            repo,
            observed_at_unix_millis,
            grok_program.as_deref(),
        )?
    };
    Ok(AdvertisedCatalogSet {
        cursor,
        grok,
        cursor_evidence_gap,
    })
}

fn observe_optional_live_grok_catalog(
    runner: &dyn crate::runtime_adapter::grok::GrokCatalogCommandRunner,
    repo: &Path,
    observed_at_unix_millis: u64,
    program_override: Option<&std::ffi::OsStr>,
) -> Result<Option<crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation>> {
    match observe_grok_catalog(runner, repo, observed_at_unix_millis, program_override) {
        Ok(observation) => Ok(Some(observation)),
        Err(error)
            if program_override.is_none()
                && grok_catalog_is_omittable_implicit_unavailability(&error) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("live Grok catalog observation failed closed"),
    }
}

fn observe_grok_catalog(
    runner: &dyn crate::runtime_adapter::grok::GrokCatalogCommandRunner,
    repo: &Path,
    observed_at_unix_millis: u64,
    program_override: Option<&std::ffi::OsStr>,
) -> Result<crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation> {
    let mut spec = crate::runtime_adapter::grok::GrokCatalogCommandSpec::new(repo);
    if let Some(program) = program_override {
        spec = spec.with_program(crate::runtime_adapter::grok::explicit_grok_executable(
            program,
        )?);
    }
    crate::runtime_adapter::grok::discover_grok_model_catalog(
        runner,
        &spec,
        Some(observed_at_unix_millis),
    )
}

fn grok_catalog_is_omittable_implicit_unavailability(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message == "Grok authentication source auth.json is missing"
            || message == "Grok authentication source auth.json is unavailable"
            || message == "Grok runtime model catalog has an invalid header"
            || ((message.starts_with("Grok catalog executable '")
                || message.starts_with("Grok executable '"))
                && message.ends_with("' is missing"))
    })
}

#[cfg(not(test))]
fn observe_live_cursor_catalog(
    repo: &Path,
    observed_at_unix_millis: u64,
    explicit_program: Option<&Path>,
) -> Result<crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation> {
    let mut spec = crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new(repo);
    if let Some(program) = explicit_program {
        spec = spec.with_program(program);
    } else if let Some(program) = std::env::var_os("MACO_CURSOR_BIN") {
        spec = spec.with_program(program);
    }
    spec = apply_cursor_catalog_env_setting(spec, std::env::var("MACO_CURSOR_ENV"))?;
    crate::runtime_adapter::cursor::discover_cursor_model_catalog(
        &ScreenedCursorCatalogRunner { repo },
        &spec,
        Some(observed_at_unix_millis),
    )
}

fn apply_cursor_catalog_env_setting(
    spec: crate::runtime_adapter::cursor::CursorCatalogCommandSpec,
    setting: std::result::Result<String, std::env::VarError>,
) -> Result<crate::runtime_adapter::cursor::CursorCatalogCommandSpec> {
    match setting {
        Ok(raw_names) => spec.with_screened_env_passthrough(&raw_names),
        Err(std::env::VarError::NotPresent | std::env::VarError::NotUnicode(_)) => Ok(spec),
    }
}

#[cfg(not(test))]
fn cursor_catalog_observation_time() -> Result<u64> {
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Cursor catalog observation time is before UNIX_EPOCH")?
        .as_millis();
    let observed_at = u64::try_from(observed_at)
        .context("Cursor catalog observation time does not fit u64 millis")?;
    Ok(observed_at.max(1))
}

#[cfg(test)]
struct HermeticCursorCatalogRunner {
    output: crate::runtime_adapter::cursor::CursorCatalogCommandOutput,
}

#[cfg(test)]
impl HermeticCursorCatalogRunner {
    fn successful(stdout: &[u8]) -> Self {
        Self {
            output: crate::runtime_adapter::cursor::CursorCatalogCommandOutput {
                status: Some(0),
                stdout: stdout.to_vec(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                timed_out: false,
                process_tree: ProcessTreeEvidence::VerifiedEmpty(
                    crate::process_runner::ContainmentBackend::DirectChild,
                ),
                side_effects: SideEffectConfinementEvidence::Verified(
                    crate::process_runner::SideEffectConfinementProfileKind::TrustedFixedNetwork,
                ),
            },
        }
    }
}

#[cfg(test)]
impl crate::runtime_adapter::cursor::CursorCatalogCommandRunner for HermeticCursorCatalogRunner {
    fn run(
        &self,
        _spec: &crate::runtime_adapter::cursor::CursorCatalogCommandSpec,
    ) -> Result<crate::runtime_adapter::cursor::CursorCatalogCommandOutput> {
        Ok(self.output.clone())
    }
}

#[cfg(not(test))]
struct ScreenedCursorCatalogRunner<'a> {
    repo: &'a Path,
}

#[cfg(not(test))]
impl crate::runtime_adapter::cursor::CursorCatalogCommandRunner
    for ScreenedCursorCatalogRunner<'_>
{
    fn run(
        &self,
        spec: &crate::runtime_adapter::cursor::CursorCatalogCommandSpec,
    ) -> Result<crate::runtime_adapter::cursor::CursorCatalogCommandOutput> {
        let search_path = std::env::var_os("PATH");
        let program = resolve_cursor_catalog_program(spec.program(), search_path.as_deref())?;
        let program_parent = program.parent().with_context(|| {
            format!(
                "Cursor catalog executable has no parent: {}",
                program.display()
            )
        })?;
        let environment = cursor_catalog_process_environment(spec);
        let process_spec = ProcessSpec::direct(
            "Cursor runtime model catalog",
            &program,
            spec.args().iter().cloned(),
            spec.current_dir(),
            spec.capture_limit_bytes(),
        )
        .with_environment(EnvironmentMode::ClearAndSet(environment))
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(spec.timeout()))
        .with_private_runtime_home(true)
        .with_side_effect_confinement(SideEffectConfinementProfile::TrustedFixedNetwork(
            crate::process_runner::TrustedFixedNetworkProfile::read_write(self.repo)
                .with_visible_read_only_root(program_parent),
        ));
        let output = run_process(process_spec)
            .context("Cursor runtime model catalog process failed before verified evidence")?;
        Ok(crate::runtime_adapter::cursor::CursorCatalogCommandOutput {
            status: output.status.and_then(|status| status.code()),
            stdout: output.stdout.as_bytes().to_vec(),
            stderr: output.stderr.as_bytes().to_vec(),
            stdout_truncated: output.stdout.is_truncated(),
            stderr_truncated: output.stderr.is_truncated(),
            timed_out: output.timed_out,
            process_tree: output.process_tree,
            side_effects: output.side_effects,
        })
    }
}

fn cursor_catalog_process_environment(
    spec: &crate::runtime_adapter::cursor::CursorCatalogCommandSpec,
) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([(
        "PATH".to_string(),
        "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
    )]);
    environment.extend(spec.environment().clone());
    environment
}

fn resolve_cursor_catalog_program(
    program: &Path,
    search_path: Option<&std::ffi::OsStr>,
) -> Result<PathBuf> {
    if program.as_os_str().is_empty() {
        bail!("Cursor catalog binary is missing");
    }
    let candidate = if program.components().count() > 1 {
        if program.is_file() {
            Ok(program.to_path_buf())
        } else {
            bail!("Cursor catalog binary '{}' is missing", program.display());
        }
    } else {
        search_path
            .into_iter()
            .flat_map(std::env::split_paths)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
            .with_context(|| format!("Cursor catalog binary '{}' is missing", program.display()))
    }?;
    let canonical = std::fs::canonicalize(&candidate).with_context(|| {
        format!(
            "failed to canonicalize Cursor catalog binary '{}'",
            candidate.display()
        )
    })?;
    if !canonical.is_file() {
        bail!(
            "canonical Cursor catalog binary '{}' is not a file",
            canonical.display()
        );
    }
    Ok(canonical)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SupervisorSelectionMode {
    Automatic,
    DebugOverride,
    LegacyFake,
    LegacyNonpublishableSimulation,
}

pub(super) fn uses_legacy_nonpublishable_explicit_selection(
    execution_runtime: SupervisorExecutionRuntime,
    _plan: &SupervisorPlan,
) -> bool {
    execution_runtime == SupervisorExecutionRuntime::NonpublishableSimulation
}

#[derive(Debug, Clone)]
pub(super) struct SupervisorSelectionResolution {
    pub(super) mode: SupervisorSelectionMode,
    pub(super) decisions: Vec<SupervisorSelectionEvent>,
    pub(super) automatic_state: Option<SupervisorAutomaticSelectionState>,
    pub(super) selection_preflight_failure: Option<SupervisorSelectionPreflightFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SupervisorSelectionPreflightFailureKind {
    FailClosed,
    ActiveRuntimeMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SupervisorSelectionPreflightFailure {
    pub(super) role: AgentRole,
    pub(super) kind: SupervisorSelectionPreflightFailureKind,
    pub(super) message: String,
}

#[derive(Debug, Clone)]
pub(super) struct SupervisorAutomaticSelectionState {
    decisions: BTreeMap<AgentRole, SelectionProvenance>,
    assignment_shapes: AssignmentSelectionShapes,
    history: Option<FrozenOutcomeHistory>,
    advertised: AdvertisedCatalogSet,
    quota_context: Option<LiveQuotaSelectionContext>,
    quota_ledger: Option<RunBudgetLedger>,
    account_observation: Option<AccountObserveResult>,
    account_observations: Vec<(SupervisorRuntime, AccountObserveResult)>,
    accepted_task_cost_observations: Vec<selection::AcceptedTaskCostObservation>,
    this_run_outcomes: Vec<OutcomeRecord>,
    this_run_exclusions: Vec<String>,
}

impl PartialEq for SupervisorAutomaticSelectionState {
    fn eq(&self, other: &Self) -> bool {
        self.decisions == other.decisions
            && self.assignment_shapes == other.assignment_shapes
            && self.history == other.history
            && self.advertised == other.advertised
            && self.quota_context == other.quota_context
            && self.accepted_task_cost_observations == other.accepted_task_cost_observations
            && self.this_run_outcomes == other.this_run_outcomes
            && self.this_run_exclusions == other.this_run_exclusions
    }
}

impl Eq for SupervisorAutomaticSelectionState {}

#[derive(Debug, Clone)]
pub(super) struct TypedSelectorEnvironmentRejection {
    pub(super) role: AgentRole,
    pub(super) rejection: selection::EnvironmentRejectionState,
}

#[derive(Debug, Clone)]
pub(super) struct SupervisorReselection {
    pub(super) overrides: BTreeMap<AgentRole, RoleModelSelection>,
    pub(super) runtime_overrides: BTreeMap<AgentRole, SupervisorRuntime>,
    pub(super) decisions: Vec<(AgentRole, SelectionProvenance)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SupervisorExecutableSelectionBindings {
    pub(super) model_overrides: BTreeMap<AgentRole, RoleModelSelection>,
    pub(super) runtime_overrides: BTreeMap<AgentRole, SupervisorRuntime>,
}

/// Executable, authority-checked selection for one non-delegating review auditor.
///
/// The full selector provenance remains attached so inbox callers can retain the
/// same catalog, objective-profile, candidate-set, and scoring evidence that
/// authorized the exact runtime/model/effort triple.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ExecutableReviewAuditorSelection {
    pub(crate) candidate: CandidateKey,
    pub(crate) authority: PhaseModelPolicyDecision,
    pub(crate) provenance: SelectionProvenance,
}

impl CodexRuntimeModelCatalog {
    /// Invoke the shared bridge without importing its private module path.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn select_executable_review_auditor(
        &self,
    ) -> Result<ExecutableReviewAuditorSelection> {
        select_executable_review_auditor(self)
    }
}

/// Select one executable `ReviewAuditor` directly from a live Codex catalog.
///
/// This is deliberately independent of supervisor-plan authority: it admits a
/// single read-only auditor, requests only `ReviewAuditor` authority, and never
/// constructs a supervisor or delegating role binding. Unknown, unavailable,
/// measured-ineligible, below-`CriticalJudgment`, and below-xhigh candidates
/// all fail closed before an executable selection is returned.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn select_executable_review_auditor(
    catalog: &CodexRuntimeModelCatalog,
) -> Result<ExecutableReviewAuditorSelection> {
    let task = task_profile_for_role(AgentRole::Auditor);
    let priors = selector_priors_with_terminal_worker_economics()?;
    let runtime_catalog = runtime_catalog_from_priors(
        runtime_name(SupervisorRuntime::Codex),
        &RuntimeModelCatalog::Codex(catalog.clone()),
        &task,
        &priors,
    )?;
    let catalog_revision = runtime_catalog.revision.clone();
    let (calibration_name, calibration_version) = priors
        .objective_profiles
        .first()
        .map(|calibration| (calibration.name.clone(), calibration.version))
        .context("built-in selector data has no objective profile")?;
    let mut input = SelectionInput {
        task,
        assignment_shape_identity: None,
        catalogs: vec![runtime_catalog],
        pools: vec![RuntimePoolState {
            runtime: runtime_name(SupervisorRuntime::Codex).to_string(),
            admission_open: true,
            pool_reference: None,
            pool_kind: None,
            entitlement_bounded: true,
            entitlement_capacity_units: 1,
            entitlement_remaining_units: 1,
            pool_pressure_basis_points: 0,
            observed_consumption_units: 0,
            marginal_cost_microunits: 0,
            exhausted: false,
            exhaustion_behavior: None,
            authorized_alternatives: Vec::new(),
            observation_revision: catalog_revision,
            observation_source: None,
            admission_provenance:
                "crate-internal launch adapter admits one non-delegating read-only review auditor"
                    .to_string(),
            failover_provenance: None,
        }],
        quota_source: None,
        constraints: OperatorConstraints {
            allowed_runtimes: [runtime_name(SupervisorRuntime::Codex).to_string()]
                .into_iter()
                .collect(),
            allowed_models: BTreeSet::new(),
            forbidden_runtimes: BTreeSet::new(),
            forbidden_models: BTreeSet::new(),
            forbidden_candidates: BTreeSet::new(),
            allow_debug_override: false,
        },
        priors,
        objective_profile: ObjectiveProfileRef {
            name: calibration_name,
            version: calibration_version,
            expected_digest: None,
        },
        resolved_objective_profile: crate::objective_profile::default_resolved_objective_profile()
            .context("resolve review-auditor objective profile")?,
        outcomes: Vec::new(),
        signals: DynamicSignals {
            retry_count: 0,
            budget_signal: BudgetSignal::Continue,
            previous_choice: None,
            previous_catalog_digest: None,
            environment_rejections: Vec::new(),
            accepted_task_cost_context: None,
            accepted_task_cost_observations: Vec::new(),
        },
        debug_override: None,
        operational_observations: None,
    };
    input.operational_observations = Some(live_operational_observations(&input));

    let provenance = select_with_live_switch_cost(&input)
        .map_err(|error| anyhow!("critical ReviewAuditor selector rejected its input: {error}"))?;
    if provenance.status != DecisionStatus::Selected {
        bail!(
            "critical ReviewAuditor selector failed closed against the supplied live catalog: {}",
            selection_refusal_message(&provenance, AgentRole::Auditor)
        );
    }
    if provenance.normalized_task.authority_role != AuthorityRole::ReviewAuditor {
        bail!("critical ReviewAuditor selector returned mismatched authority provenance");
    }
    let choice = provenance
        .choice
        .as_ref()
        .context("critical ReviewAuditor selector reported selected status without a choice")?;
    if choice.candidate.runtime != runtime_name(SupervisorRuntime::Codex)
        || !catalog.contains(&choice.candidate.model)
    {
        bail!(
            "critical ReviewAuditor selector returned a runtime/model pair absent from the supplied live catalog"
        );
    }
    if choice.candidate.effort < SelectorEffort::Xhigh {
        bail!(
            "critical ReviewAuditor selector returned effort '{}' below the xhigh execution floor",
            selector_effort_as_str(choice.candidate.effort)
        );
    }
    validate_known_judgment_role_model(AgentRole::Auditor, Some(&choice.candidate.model))
        .with_context(|| {
            format!(
                "selected model '{}' cannot receive ReviewAuditor authority",
                choice.candidate.model
            )
        })?;
    let capability = trusted_model_capability(&choice.candidate.model).with_context(|| {
        format!(
            "selected ReviewAuditor model '{}' lost its trusted capability evidence",
            choice.candidate.model
        )
    })?;
    let authority = validate_phase_model_binding(
        AgentRole::Auditor,
        OrchestrationPhase::Audit,
        None,
        capability,
    )
    .with_context(|| {
        format!(
            "selected model '{}' is below the CriticalJudgment ReviewAuditor floor",
            choice.candidate.model
        )
    })?;
    let candidate = choice.candidate.clone();
    Ok(ExecutableReviewAuditorSelection {
        candidate,
        authority,
        provenance,
    })
}

#[cfg(test)]
pub(super) fn initialize_supervisor_selection(
    plan: &mut SupervisorPlan,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
    advertised: &AdvertisedCatalogSet,
    resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
) -> Result<SupervisorSelectionResolution> {
    initialize_supervisor_selection_with_quota(
        plan,
        runtime,
        catalog,
        admission,
        advertised,
        resolved_objective_profile,
        SupervisorQuotaSelectionInput::default(),
    )
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SupervisorQuotaSelectionInput<'a> {
    pub(super) context: Option<&'a LiveQuotaSelectionContext>,
    pub(super) ledger: Option<&'a RunBudgetLedger>,
}

#[cfg(test)]
pub(super) fn initialize_supervisor_selection_with_quota(
    plan: &mut SupervisorPlan,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
    advertised: &AdvertisedCatalogSet,
    resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
    quota: SupervisorQuotaSelectionInput<'_>,
) -> Result<SupervisorSelectionResolution> {
    initialize_supervisor_selection_with_history(
        plan,
        runtime,
        catalog,
        admission,
        advertised,
        resolved_objective_profile,
        quota,
        None,
        None,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn initialize_supervisor_selection_with_history(
    plan: &mut SupervisorPlan,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
    advertised: &AdvertisedCatalogSet,
    resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
    quota: SupervisorQuotaSelectionInput<'_>,
    history: Option<&FrozenOutcomeHistory>,
    account_observation: Option<&AccountObserveResult>,
) -> Result<SupervisorSelectionResolution> {
    let accounts = account_observation
        .map(|observation| vec![(runtime, observation.clone())])
        .unwrap_or_default();
    initialize_supervisor_selection_with_accounts(
        plan,
        runtime,
        catalog,
        admission,
        advertised,
        resolved_objective_profile,
        quota,
        history,
        &accounts,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn initialize_supervisor_selection_with_accounts(
    plan: &mut SupervisorPlan,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
    advertised: &AdvertisedCatalogSet,
    resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
    quota: SupervisorQuotaSelectionInput<'_>,
    history: Option<&FrozenOutcomeHistory>,
    account_observations: &[(SupervisorRuntime, AccountObserveResult)],
) -> Result<SupervisorSelectionResolution> {
    initialize_supervisor_selection_with_assessment(
        plan,
        runtime,
        catalog,
        admission,
        advertised,
        resolved_objective_profile,
        quota,
        history,
        account_observations,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) fn initialize_supervisor_selection_with_assessment(
    plan: &mut SupervisorPlan,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
    advertised: &AdvertisedCatalogSet,
    resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
    quota: SupervisorQuotaSelectionInput<'_>,
    history: Option<&FrozenOutcomeHistory>,
    account_observations: &[(SupervisorRuntime, AccountObserveResult)],
    assessment: Option<&TaskRoutingAssessment>,
) -> Result<SupervisorSelectionResolution> {
    initialize_supervisor_selection_with_shapes(
        plan,
        runtime,
        catalog,
        admission,
        advertised,
        resolved_objective_profile,
        quota,
        history,
        account_observations,
        assessment,
        &AssignmentSelectionShapes::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn initialize_supervisor_selection_with_shapes(
    plan: &mut SupervisorPlan,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
    advertised: &AdvertisedCatalogSet,
    resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
    quota: SupervisorQuotaSelectionInput<'_>,
    history: Option<&FrozenOutcomeHistory>,
    account_observations: &[(SupervisorRuntime, AccountObserveResult)],
    assessment: Option<&TaskRoutingAssessment>,
    assignment_shapes: &AssignmentSelectionShapes,
) -> Result<SupervisorSelectionResolution> {
    let frozen_policy = crate::selection::routing_policy::current_routing_policy();
    let routing_features =
        routing_features_with_assessment(plan, assessment, frozen_policy.as_ref())?;
    if runtime == SupervisorRuntime::Fake {
        return Ok(SupervisorSelectionResolution {
            mode: SupervisorSelectionMode::LegacyFake,
            decisions: Vec::new(),
            automatic_state: None,
            selection_preflight_failure: None,
        });
    }
    let account_observations = account_catalog_set_for_primary(runtime, account_observations)?;
    let account_observation = account_observations
        .iter()
        .find(|(observed_runtime, _)| *observed_runtime == runtime)
        .map(|(_, observation)| observation);
    let resolved_objective_profile = resolved_objective_profile
        .cloned()
        .context(
            "verified supervisor routing requires an objective profile resolved and frozen in the run context",
        )?;
    let SupervisorQuotaSelectionInput {
        context: quota_context,
        ledger: quota_ledger,
    } = quota;

    let automatic = plan.role_models.is_empty();
    // Resolve reachable execution roles and mandatory control gates. An unused
    // role preference cannot veto a bounded direct Worker assignment.
    let roles = required_selector_roles(plan);
    if runtime == SupervisorRuntime::Cursor
        && advertised.cursor.is_none()
        && account_observation.is_none()
    {
        let role = roles.first().copied().unwrap_or(AgentRole::Worker);
        let detail = advertised
            .cursor_evidence_gap
            .as_ref()
            .map(|gap| gap.message.as_str())
            .unwrap_or(
                "verified Cursor runtime model catalog observation is missing without recorded failure evidence",
            );
        let report = selection_preflight::evaluate_supervisor_selection_preflight(
            plan,
            runtime,
            selection_preflight::FrozenSupervisorSelectionInputs {
                schema_version: 1,
                plan_sha256: selection_preflight::plan_digest(plan)?,
                roles: BTreeMap::new(),
                unavailable: roles
                    .iter()
                    .map(|role| (*role, detail.to_string()))
                    .collect(),
            },
        )?;
        let aggregate = selection_preflight::refusal_message(&report)?;
        return Ok(SupervisorSelectionResolution {
            mode: if automatic {
                SupervisorSelectionMode::Automatic
            } else {
                SupervisorSelectionMode::DebugOverride
            },
            decisions: Vec::new(),
            automatic_state: None,
            selection_preflight_failure: Some(SupervisorSelectionPreflightFailure {
                role,
                kind: SupervisorSelectionPreflightFailureKind::FailClosed,
                message: format!(
                    "selected Cursor runtime requires a verified runtime-advertised model catalog before role '{}': {detail}; {aggregate}",
                    role.as_str()
                ),
            }),
        });
    }
    let mut frozen_inputs = selection_preflight::FrozenSupervisorSelectionInputs {
        schema_version: 1,
        plan_sha256: selection_preflight::plan_digest(plan)?,
        roles: BTreeMap::new(),
        unavailable: BTreeMap::new(),
    };
    let frozen_quota_ledger =
        selection_preflight::freeze_quota_ledger(quota_context, quota_ledger)?;
    for role in roles.iter().copied() {
        let result = (|| -> Result<_> {
            let debug_override = plan
                .role_models
                .get(&role)
                .map(|selection| {
                    debug_override_for_role(
                        role,
                        authored_override_runtime(plan, role, runtime)?,
                        selection,
                    )
                })
                .transpose()?;
            let mut input = selection_input_for_role_with_assessment_and_accounts(
                SelectionInputForRoleArgs {
                    role,
                    runtime,
                    catalog,
                    advertised,
                    admission,
                    resolved_objective_profile: &resolved_objective_profile,
                    quota_context: None,
                    quota_ledger: None,
                    account_observation,
                    signals: DynamicSignals {
                        retry_count: 0,
                        budget_signal: BudgetSignal::Continue,
                        previous_choice: None,
                        previous_catalog_digest: None,
                        environment_rejections: Vec::new(),
                        accepted_task_cost_context: None,
                        accepted_task_cost_observations: Vec::new(),
                    },
                    debug_override,
                    history,
                },
                account_observations,
                assessment,
                Some(&routing_features),
                frozen_policy.as_ref(),
            )?;
            if let Some(task) = assignment_shapes.role_profile(plan, role)? {
                input.task = task;
                input.outcomes = history
                    .map(|snapshot| snapshot.outcomes_for(&input.task))
                    .unwrap_or_default();
                input.catalogs = if account_observations.is_empty() {
                    constructed_selection_catalogs(
                        runtime,
                        catalog,
                        advertised,
                        &input.task,
                        &input.priors,
                        account_observation,
                    )?
                } else {
                    account_selection_catalogs(account_observations, &input.task, &input.priors)?
                };
            }
            selection_preflight::apply_frozen_quota(
                &mut input,
                runtime,
                quota_context,
                frozen_quota_ledger.as_ref(),
            )?;
            let routing_policy = frozen_policy.as_ref().map(|frozen| {
                crate::selection::routing_policy::RoutingPolicyReceipt {
                    frozen: frozen.clone(),
                    role: role.as_str().to_string(),
                    features: routing_features.clone(),
                }
            });
            Ok(selection_preflight::freeze_role_input(
                input,
                routing_policy,
            ))
        })();
        match result {
            Ok(input) => {
                frozen_inputs.roles.insert(role, input);
            }
            Err(error) => {
                frozen_inputs.unavailable.insert(role, format!("{error:#}"));
            }
        }
    }
    let report =
        selection_preflight::evaluate_supervisor_selection_preflight(plan, runtime, frozen_inputs)?;
    let mut decisions = Vec::with_capacity(roles.len());
    for diagnostic in &report.diagnostics {
        if diagnostic.lens_id.is_some() {
            continue;
        }
        let Some(mut decision) = diagnostic.decision.clone() else {
            continue;
        };
        decision.outcome_history = history.map(|snapshot| snapshot.provenance.clone());
        decision.operator_prior_data = super::prior_input::current_provenance();
        decisions.push(SupervisorSelectionEvent {
            assignment_id: None,
            attempt: 0,
            role: diagnostic.role,
            primary_cause: if plan.role_models.contains_key(&diagnostic.role) {
                SupervisorSelectionEventCause::DebugOverride
            } else {
                SupervisorSelectionEventCause::Initial
            },
            provenance: decision,
        });
    }
    // An unavailable authored lens is refused by the existing review dispatch
    // path, which records its procedural verdict and journal entry. The pure
    // preflight report still includes that diagnostic without granting a lens
    // launch authorization here.
    let first_failure = report.diagnostics.iter().find(|entry| {
        entry.status != selection_preflight::SelectionPreflightStatus::Compatible
            && !(entry.lens_id.is_some()
                && entry.rejection
                    == Some(selection_preflight::SelectionPreflightRejection::ModelUnavailable))
    });
    if let Some(first) = first_failure {
        let message = selection_preflight::refusal_message(&report)?;
        // Preserve malformed-input errors while reporting every reachable failure.
        if !report.frozen_inputs.unavailable.is_empty() {
            bail!("{message}");
        }
        if let Some(invalid) = report.diagnostics.iter().find(|entry| {
            entry.rejection == Some(selection_preflight::SelectionPreflightRejection::InvalidInput)
        }) {
            bail!(
                "automatic selector rejected role '{}': {}; {message}",
                invalid.role.as_str(),
                invalid.message
            );
        }
        return Ok(SupervisorSelectionResolution {
            mode: if automatic {
                SupervisorSelectionMode::Automatic
            } else {
                SupervisorSelectionMode::DebugOverride
            },
            decisions,
            automatic_state: None,
            selection_preflight_failure: Some(SupervisorSelectionPreflightFailure {
                role: first.role,
                kind: if first.rejection
                    == Some(selection_preflight::SelectionPreflightRejection::UnexecutableRuntime)
                {
                    SupervisorSelectionPreflightFailureKind::ActiveRuntimeMismatch
                } else {
                    SupervisorSelectionPreflightFailureKind::FailClosed
                },
                message,
            }),
        });
    }
    // All role and nonprocedural lens gates passed. Only now bind role authority.
    let mut resolved = BTreeMap::new();
    for event in &decisions {
        let choice = match executable_choice(&event.provenance, runtime, event.role)? {
            ExecutableChoiceResolution::Executable(choice) => choice,
            ExecutableChoiceResolution::PreflightFailure(failure) => bail!("{}", failure.message),
        };
        route_live_four_arm_comparison(&event.provenance.normalized_input)?;
        resolved.insert(event.role, role_selection_from_choice(choice));
    }
    for event in &decisions {
        crate::selection::routing_policy::seal_selected_candidate(
            event.role.as_str(),
            &event.provenance,
        )?;
    }

    plan.role_models = resolved;
    if automatic {
        if plan.review_lenses == default_supervisor_review_lenses() {
            bind_automatic_review_lenses_to_auditor_selection(plan)?;
        } else {
            validate_custom_review_lens_contracts(plan)?;
        }
    } else if plan.review_lenses == default_supervisor_review_lenses() {
        if plan.role_models.contains_key(&AgentRole::Auditor) {
            bind_automatic_review_lenses_to_auditor_selection(plan)?;
        }
    } else {
        validate_custom_review_lens_contracts(plan)?;
    }

    let mut automatic_state = automatic
        .then(|| {
            SupervisorAutomaticSelectionState::from_initial_decisions(
                &decisions,
                advertised.clone(),
                quota_context.cloned(),
                quota_ledger.cloned(),
                account_observation.cloned(),
                account_observations.to_vec(),
                &roles,
            )
        })
        .transpose()?;
    if let Some(state) = automatic_state.as_mut() {
        state.assignment_shapes = assignment_shapes.clone();
        state.history = history.cloned();
    }
    Ok(SupervisorSelectionResolution {
        mode: if automatic {
            SupervisorSelectionMode::Automatic
        } else {
            SupervisorSelectionMode::DebugOverride
        },
        decisions,
        automatic_state,
        selection_preflight_failure: None,
    })
}

impl SupervisorAutomaticSelectionState {
    fn from_initial_decisions(
        decisions: &[SupervisorSelectionEvent],
        advertised: AdvertisedCatalogSet,
        quota_context: Option<LiveQuotaSelectionContext>,
        quota_ledger: Option<RunBudgetLedger>,
        account_observation: Option<AccountObserveResult>,
        account_observations: Vec<(SupervisorRuntime, AccountObserveResult)>,
        required_roles: &[AgentRole],
    ) -> Result<Self> {
        let mut by_role = BTreeMap::new();
        for decision in decisions {
            let normalized_role = role_for_task_profile(&decision.provenance.normalized_task)?;
            if normalized_role != decision.role {
                bail!(
                    "automatic selector event role '{}' disagrees with normalized task role '{}'",
                    decision.role.as_str(),
                    normalized_role.as_str()
                );
            }
            if by_role
                .insert(decision.role, decision.provenance.clone())
                .is_some()
            {
                bail!(
                    "automatic selector produced duplicate initial provenance for role '{}'",
                    decision.role.as_str()
                );
            }
        }
        for role in required_roles {
            if !by_role.contains_key(role) {
                bail!(
                    "automatic selector omitted initial provenance for role '{}'",
                    role.as_str()
                );
            }
        }
        Ok(Self {
            decisions: by_role,
            assignment_shapes: AssignmentSelectionShapes::default(),
            history: None,
            advertised,
            quota_context,
            quota_ledger,
            account_observation,
            account_observations,
            accepted_task_cost_observations: Vec::new(),
            this_run_outcomes: Vec::new(),
            this_run_exclusions: Vec::new(),
        })
    }

    pub(super) fn validate_current_assignment(
        &self,
        plan: &SupervisorPlan,
        assignment: &OrchestratorAssignment,
    ) -> Result<()> {
        self.assignment_shapes.validate_current_assignment(
            plan,
            assignment,
            self.decisions
                .get(&assignment.role)
                .and_then(|decision| decision.routing_policy.as_ref())
                .map(|receipt| &receipt.frozen),
        )
    }

    pub(super) fn set_observed_accepted_task_cost(
        &mut self,
        observations: Vec<selection::AcceptedTaskCostObservation>,
    ) {
        self.accepted_task_cost_observations = observations;
    }

    pub(super) fn set_this_run_outcomes(
        &mut self,
        outcomes: Vec<OutcomeRecord>,
        exclusions: Vec<String>,
    ) {
        self.this_run_outcomes = outcomes;
        self.this_run_exclusions = exclusions;
    }

    pub(super) fn account_observe_environment_decision(
        &self,
    ) -> Option<(AccountObserveOutcomeKind, Option<u64>)> {
        let observation = self.account_observation.as_ref();
        #[cfg(target_os = "linux")]
        {
            observation.map(account_observe_environment_decision)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = observation;
            None
        }
    }

    pub(super) fn executable_bindings(
        &self,
        runtime: SupervisorRuntime,
    ) -> Result<SupervisorExecutableSelectionBindings> {
        let mut bindings = SupervisorExecutableSelectionBindings::default();
        for (role, provenance) in &self.decisions {
            let choice = match executable_choice(provenance, runtime, *role)? {
                ExecutableChoiceResolution::Executable(choice) => choice,
                ExecutableChoiceResolution::PreflightFailure(failure) => {
                    bail!(
                        "automatic selector replay state failed executable preflight: {}",
                        failure.message
                    )
                }
            };
            bindings
                .model_overrides
                .insert(*role, role_selection_from_choice(choice));
            bindings.runtime_overrides.insert(
                *role,
                runtime_from_name(&choice.candidate.runtime).with_context(|| {
                    format!(
                        "automatic selector replay state chose an invalid runtime for role '{}'",
                        role.as_str()
                    )
                })?,
            );
        }
        Ok(bindings)
    }

    /// Commit one completed assignment's automatic-selection events atomically.
    ///
    /// Concurrent assignments intentionally start from independent clones of the
    /// last manager-committed state. Their completion events are replayed by the
    /// scheduler in stable schedule-index order, so the first event for a role can
    /// branch from a choice other than the manager's state at commit time. Events
    /// within one assignment must still form an exact previous-choice chain.
    pub(super) fn commit_completed_selection_events(
        &mut self,
        runtime: SupervisorRuntime,
        events: &[SupervisorSelectionEvent],
    ) -> Result<SupervisorExecutableSelectionBindings> {
        if events.is_empty() {
            return Ok(SupervisorExecutableSelectionBindings::default());
        }

        let assignment_id = events[0]
            .assignment_id
            .as_deref()
            .filter(|assignment_id| !assignment_id.is_empty())
            .context("completed automatic-selection event has no assignment identity")?;
        let mut ordered = events.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|event| (event.attempt, event.role));

        let mut next_decisions = self.decisions.clone();
        let mut assignment_previous = BTreeMap::<AgentRole, CandidateKey>::new();
        let mut bindings = SupervisorExecutableSelectionBindings::default();
        let mut previous_key = None;
        for event in ordered {
            if event.assignment_id.as_deref() != Some(assignment_id) {
                bail!(
                    "completed automatic-selection events mix assignment identities '{}' and '{}'",
                    assignment_id,
                    event.assignment_id.as_deref().unwrap_or("<missing>")
                );
            }
            let key = (event.attempt, event.role);
            if previous_key == Some(key) {
                bail!(
                    "completed automatic-selection events duplicate attempt {} for role '{}'",
                    event.attempt,
                    event.role.as_str()
                );
            }
            previous_key = Some(key);

            self.assignment_shapes
                .validate_event(assignment_id, event)?;

            let normalized_role = role_for_task_profile(&event.provenance.normalized_task)?;
            if normalized_role != event.role {
                bail!(
                    "completed automatic-selection event role '{}' disagrees with normalized task role '{}'",
                    event.role.as_str(),
                    normalized_role.as_str()
                );
            }
            let supplied_previous = event
                .provenance
                .normalized_input
                .signals
                .previous_choice
                .as_ref()
                .with_context(|| {
                    format!(
                        "completed automatic-selection event for role '{}' has no same-run previous choice",
                        event.role.as_str()
                    )
                })?;
            if let Some(expected_previous) = assignment_previous.get(&event.role) {
                if supplied_previous != expected_previous {
                    bail!(
                        "completed automatic-selection event chain for role '{}' expected previous choice '{}:{}:{:?}' but recorded '{}:{}:{:?}'",
                        event.role.as_str(),
                        expected_previous.runtime,
                        expected_previous.model,
                        expected_previous.effort,
                        supplied_previous.runtime,
                        supplied_previous.model,
                        supplied_previous.effort,
                    );
                }
            }
            let choice = match executable_choice(&event.provenance, runtime, event.role)? {
                ExecutableChoiceResolution::Executable(choice) => choice,
                ExecutableChoiceResolution::PreflightFailure(failure) => {
                    bail!(
                        "completed automatic-selection event failed executable preflight: {}",
                        failure.message
                    )
                }
            };
            assignment_previous.insert(event.role, choice.candidate.clone());
            bindings
                .model_overrides
                .insert(event.role, role_selection_from_choice(choice));
            bindings.runtime_overrides.insert(
                event.role,
                runtime_from_name(&choice.candidate.runtime).with_context(|| {
                    format!(
                        "completed automatic-selection event chose an invalid runtime for role '{}'",
                        event.role.as_str()
                    )
                })?,
            );
            next_decisions.insert(event.role, event.provenance.clone());
        }

        self.decisions = next_decisions;
        Ok(bindings)
    }
}

#[cfg(test)]
pub(super) fn reselect_roles_from_supplied_catalog_snapshot(
    state: &mut SupervisorAutomaticSelectionState,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    roles: &[AgentRole],
    retry_count: u32,
    budget_signal: BudgetSignal,
    environment_rejections: &[TypedSelectorEnvironmentRejection],
) -> Result<SupervisorReselection> {
    reselect_assignment_from_supplied_catalog_snapshot(
        state,
        runtime,
        catalog,
        roles,
        retry_count,
        budget_signal,
        environment_rejections,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn reselect_assignment_from_supplied_catalog_snapshot(
    state: &mut SupervisorAutomaticSelectionState,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    roles: &[AgentRole],
    retry_count: u32,
    budget_signal: BudgetSignal,
    environment_rejections: &[TypedSelectorEnvironmentRejection],
    assignment_id: Option<&str>,
) -> Result<SupervisorReselection> {
    let advertised = state.advertised.clone();
    let mut next_decisions = state.decisions.clone();
    let mut ordered_roles = roles.to_vec();
    ordered_roles.sort();
    ordered_roles.dedup();
    let mut overrides = BTreeMap::new();
    let mut runtime_overrides = BTreeMap::new();
    let mut decisions = Vec::with_capacity(ordered_roles.len());
    for role in ordered_roles {
        let previous = next_decisions.get(&role).with_context(|| {
            format!(
                "automatic selector has no replay state for role '{}'",
                role.as_str()
            )
        })?;
        let mut input = previous.normalized_input.clone();
        if let Some(assignment_id) = assignment_id {
            state
                .assignment_shapes
                .bind_input(assignment_id, role, &mut input)?;
            input.outcomes = state
                .history
                .as_ref()
                .map(|history| {
                    history
                        .outcomes_for_shape(&input.task, input.assignment_shape_identity.as_ref())
                })
                .unwrap_or_default();
        }
        let constructed = if state.account_observations.is_empty() {
            constructed_selection_catalogs(
                runtime,
                catalog,
                &advertised,
                &input.task,
                &input.priors,
                state.account_observation.as_ref(),
            )?
        } else {
            account_selection_catalogs(&state.account_observations, &input.task, &input.priors)?
        };
        input.constraints.allowed_runtimes = constructed
            .iter()
            .map(|runtime_catalog| runtime_catalog.runtime.clone())
            .collect();
        input.catalogs = constructed;
        input.constraints.allow_debug_override = false;
        input.debug_override = None;
        input.signals.retry_count = retry_count;
        input.signals.budget_signal = budget_signal;
        input.signals.previous_choice = previous
            .choice
            .as_ref()
            .map(|choice| choice.candidate.clone());
        input.signals.previous_catalog_digest = Some(previous.input_digests.catalogs.value.clone());
        input.signals.environment_rejections = environment_rejections
            .iter()
            .filter(|rejection| rejection.role == role)
            .map(|rejection| rejection.rejection.clone())
            .collect();
        input.signals.accepted_task_cost_context =
            input
                .assignment_shape_identity
                .clone()
                .map(
                    |assignment_shape_identity| selection::AcceptedTaskCostContext {
                        role,
                        assignment_shape_identity,
                    },
                );
        input.signals.accepted_task_cost_observations =
            state.accepted_task_cost_observations.clone();
        if let Some(quota_context) = &state.quota_context {
            let source_runtime = input
                .signals
                .previous_choice
                .as_ref()
                .map(|choice| choice.runtime.clone())
                .unwrap_or_else(|| runtime_name(runtime).to_string());
            apply_live_quota_selection_input(
                &mut input,
                quota_context,
                state.quota_ledger.as_ref(),
                &source_runtime,
            )?;
        }
        merge_this_run_outcomes_into_input(&mut input, &state.this_run_outcomes);

        let routing_policy = previous.routing_policy.as_ref();
        let mut decision = select_with_live_switch_cost_for_policy(&input, routing_policy)
            .map_err(|error| {
                anyhow!(
                    "automatic selector replay rejected role '{}': {error}",
                    role.as_str()
                )
            })?;
        decision.outcome_history = previous.outcome_history.clone();
        attach_this_run_exclusions(&mut decision, &state.this_run_exclusions)?;
        decision.operator_prior_data = previous.operator_prior_data.clone();
        let choice = match executable_choice(&decision, runtime, role)? {
            ExecutableChoiceResolution::Executable(choice) => choice,
            ExecutableChoiceResolution::PreflightFailure(failure) => {
                bail!(
                    "automatic selector replay failed preflight: {}",
                    failure.message
                )
            }
        };
        crate::selection::routing_policy::seal_selected_candidate(role.as_str(), &decision)?;
        overrides.insert(role, role_selection_from_choice(choice));
        runtime_overrides.insert(
            role,
            runtime_from_name(&choice.candidate.runtime).with_context(|| {
                format!(
                    "selector replay chose unsupported runtime '{}' for role '{}'",
                    choice.candidate.runtime,
                    role.as_str()
                )
            })?,
        );
        next_decisions.insert(role, decision.clone());
        decisions.push((role, decision));
    }
    state.decisions = next_decisions;
    Ok(SupervisorReselection {
        overrides,
        runtime_overrides,
        decisions,
    })
}

fn attach_this_run_exclusions(
    decision: &mut SelectionProvenance,
    exclusions: &[String],
) -> Result<()> {
    if exclusions.is_empty() {
        return Ok(());
    }
    if let Some(history) = decision.outcome_history.as_mut() {
        for exclusion in exclusions {
            if !history
                .exclusions
                .iter()
                .any(|existing| existing == exclusion)
            {
                history.exclusions.push(exclusion.clone());
            }
        }
        history.exclusions.sort();
        return Ok(());
    }
    decision.outcome_history = Some(crate::selection::AuthenticatedOutcomeHistoryProvenance {
        snapshot_sha256: crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(exclusions)?),
        source_digests: Vec::new(),
        exclusions: exclusions.to_vec(),
        projected_attempt_count: 0,
    });
    Ok(())
}

fn merge_this_run_outcomes_into_input(
    input: &mut SelectionInput,
    this_run_outcomes: &[OutcomeRecord],
) {
    for outcome in this_run_outcomes {
        if outcome.task != input.task
            || outcome.assignment_shape_identity != input.assignment_shape_identity
        {
            continue;
        }
        if input
            .outcomes
            .iter()
            .any(|existing| existing.attempt_id == outcome.attempt_id)
        {
            continue;
        }
        input.outcomes.push(outcome.clone());
    }
}

fn role_for_task_profile(task: &TaskProfile) -> Result<AgentRole> {
    match task.authority_role {
        AuthorityRole::AcceptanceGate => Ok(AgentRole::Supervisor),
        AuthorityRole::Delegating => Ok(AgentRole::ChildOrchestrator),
        AuthorityRole::TerminalLeaf if task.task_class == JUDGMENT_SELECTION_TASK_CLASS => {
            Ok(AgentRole::Researcher)
        }
        AuthorityRole::TerminalLeaf => Ok(AgentRole::Worker),
        AuthorityRole::FailureClassification => Ok(AgentRole::GateClassifier),
        AuthorityRole::ReviewAuditor => Ok(AgentRole::Auditor),
        authority => {
            bail!("selector task authority '{authority:?}' does not map to a supervisor role")
        }
    }
}

fn required_selector_roles(plan: &SupervisorPlan) -> Vec<AgentRole> {
    // Parent acceptance, independent audit, and failure classification remain
    // reachable control paths even for a single terminal assignment.
    let mut roles = BTreeSet::from([
        AgentRole::Supervisor,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ]);
    for assignment in &plan.assignments {
        roles.insert(assignment.role);
        for worker in &assignment.worker_assignments {
            roles.insert(worker.role);
        }
    }
    roles.into_iter().collect()
}

#[cfg(test)]
fn all_selector_roles() -> &'static [AgentRole] {
    &[
        AgentRole::Supervisor,
        AgentRole::ChildOrchestrator,
        AgentRole::Worker,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ]
}

fn bind_automatic_review_lenses_to_auditor_selection(plan: &mut SupervisorPlan) -> Result<()> {
    let selection = plan
        .role_models
        .get(&AgentRole::Auditor)
        .context("automatic selector did not resolve an auditor model")?;
    let model = selection
        .model
        .as_ref()
        .context("automatic selector returned a runtime-default auditor model")?;
    for lens in &mut plan.review_lenses {
        if let ReviewLensBackendConfig::Model {
            model: lens_model,
            reasoning_effort,
            ..
        } = &mut lens.backend
        {
            // Bind the authorized triple. Scope never invents an effort preference.
            *lens_model = model.clone();
            *reasoning_effort = selection.reasoning_effort.clone();
        }
    }
    Ok(())
}

fn validate_custom_review_lens_contracts(plan: &SupervisorPlan) -> Result<()> {
    let auditor = plan.role_models.get(&AgentRole::Auditor).context(
        "custom review lenses require an explicit selector-validated auditor role_models override",
    )?;
    auditor
        .model
        .as_deref()
        .context("selector-validated auditor override has no explicit model")?;
    auditor
        .reasoning_effort
        .as_deref()
        .context("selector-validated auditor override has no explicit reasoning effort")?;
    for lens in &plan.review_lenses {
        match &lens.backend {
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } => {
                if model.is_empty()
                    || reasoning_effort
                        .as_deref()
                        .and_then(selector_effort_from_str)
                        .is_none()
                {
                    bail!(
                        "custom review lens '{}' requires an explicit model and supported effort",
                        lens.id
                    );
                }
                // The generic Auditor selects the executor runtime and supplies the
                // assessed run inputs. Each authored lens is independently evaluated
                // and scoped to its own exact triple immediately before preparation.
            }
            ReviewLensBackendConfig::Precomputed { .. } => bail!(
                "custom precomputed review lens '{}' cannot be selector-bound safely because it has no executable reasoning-effort field",
                lens.id
            ),
        }
    }
    Ok(())
}

/// Constructed only by evaluation of an authored lens against the current
/// catalog and already assessed, frozen run input. It grants no budget,
/// filesystem, account-login or publication authority.
#[cfg(target_os = "linux")]
pub(super) struct SelectedReviewLens {
    decision: SelectionProvenance,
    authority: ReviewLensAuthority,
}

#[cfg(target_os = "linux")]
enum ReviewLensAuthority {
    Selected(Box<crate::selection::routing_policy::SelectedLaunchRequest>),
    LocalAuth { run_id: String },
}

#[cfg(target_os = "linux")]
pub(super) enum ReviewLensAccount<'a> {
    Selected {
        observation: &'a AccountObserveResult,
        expected_binding: &'a crate::selection::routing_policy::AccountBinding,
    },
    LocalAuth {
        run_id: &'a str,
    },
}

#[cfg(target_os = "linux")]
impl SelectedReviewLens {
    pub(super) fn bind(
        self,
    ) -> Result<(
        crate::selection::routing_policy::RoutingPolicyGuard,
        SelectionProvenance,
    )> {
        let receipt = self
            .decision
            .routing_policy
            .as_ref()
            .context("lens policy receipt")?;
        if crate::selection::routing_policy::current_routing_policy().as_ref()
            != Some(&receipt.frozen)
        {
            bail!("review lens frozen policy changed before binding");
        }
        // The existing guard saves the outer authorizations and restores them on
        // every exit, including preparation refusal and dispatch unwinding.
        // Registry reads revalidate earlier launches, including the Worker. Keep
        // those selector seals under the same frozen policy while replacing only
        // the Auditor's triple for this lens.
        let authorizations = crate::selection::routing_policy::captured_selected_authorizations();
        let guard =
            crate::selection::routing_policy::bind_routing_policy(Some(receipt.frozen.clone()))?;
        crate::selection::routing_policy::install_selected_authorizations(authorizations);
        crate::selection::routing_policy::seal_selected_candidate(
            AgentRole::Auditor.as_str(),
            &self.decision,
        )?;
        let candidate = &self
            .decision
            .choice
            .as_ref()
            .context("selected lens choice")?
            .candidate;
        match &self.authority {
            ReviewLensAuthority::Selected(launch) if candidate != launch.candidate() => {
                bail!("review lens launch differs from its selector decision");
            }
            ReviewLensAuthority::LocalAuth { run_id } => {
                require_local_auth_review(run_id)?;
            }
            ReviewLensAuthority::Selected(_) => {}
        }
        crate::selection::routing_policy::validate_selected_launch(
            AgentRole::Auditor.as_str(),
            &candidate.runtime,
            &candidate.model,
            candidate.effort.as_str(),
        )?;
        Ok((guard, self.decision))
    }
}

#[cfg(target_os = "linux")]
pub(super) fn frozen_review_account_binding(
    runtime: SupervisorRuntime,
    run: &str,
) -> Result<Option<coding_agent_manager_lib::account_authority::SelectedAccountBinding>> {
    use crate::account_authority as authority;
    let binding =
        match runtime {
            SupervisorRuntime::Codex => match authority::codex_run_account_binding(run) {
                Some(authority::CodexRunAccountBinding::Selected(binding)) => {
                    Some(binding.to_selected_binding())
                }
                Some(authority::CodexRunAccountBinding::LocalAuth) => {
                    require_local_auth_review(run)?;
                    return Ok(None);
                }
                _ => None,
            },
            SupervisorRuntime::Grok => authority::grok_run_account_binding(run)
                .map(|binding| binding.to_selected_binding()),
            SupervisorRuntime::ClaudeCode => authority::claude_run_account_binding(run)
                .map(|binding| binding.to_selected_binding()),
            SupervisorRuntime::GeminiCli => authority::gemini_run_account_binding(run)
                .map(|binding| binding.to_selected_binding()),
            SupervisorRuntime::Cursor => authority::cursor_run_account_binding(run)
                .map(|binding| binding.to_selected_binding()),
            SupervisorRuntime::Fake => None,
        };
    binding
        .map(Some)
        .context("review lens requires the run's frozen selected account or CAM-unconfigured LocalAuth Codex binding")
}

#[cfg(target_os = "linux")]
fn require_local_auth_review(run_id: &str) -> Result<()> {
    if crate::account_authority::configured_cam_authority_socket().is_some()
        || crate::account_authority::codex_run_account_binding(run_id)
            != Some(crate::account_authority::CodexRunAccountBinding::LocalAuth)
    {
        bail!("local-auth review requires CAM unconfigured and the run's frozen LocalAuth Codex binding");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(target_os = "linux")]
pub(super) fn select_authored_review_lens(
    lens: &ReviewLensConfig,
    resolved_effort: &str,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    baseline: &SelectionProvenance,
    account: ReviewLensAccount<'_>,
    quota: SupervisorQuotaSelectionInput<'_>,
) -> Result<SelectedReviewLens> {
    let observation = match &account {
        ReviewLensAccount::Selected {
            observation,
            expected_binding,
        } => {
            if &crate::selection::routing_policy::AccountBinding::from(&observation.binding)
                != *expected_binding
            {
                bail!("review lens selected account changed from the frozen run binding");
            }
            Some(*observation)
        }
        ReviewLensAccount::LocalAuth { run_id } => {
            if runtime != SupervisorRuntime::Codex {
                bail!("local-auth review is supported only for Codex");
            }
            require_local_auth_review(run_id)?;
            None
        }
    };
    let ReviewLensBackendConfig::Model {
        model,
        reasoning_effort: Some(effort),
        ..
    } = &lens.backend
    else {
        bail!("review lens requires an executable explicit model/effort contract");
    };
    if effort != resolved_effort {
        bail!("review lens resolved effort differs from its authored contract");
    }
    super::prompts::validate_review_lens_runtime_selection(lens, runtime, catalog)?;
    let receipt = baseline
        .routing_policy
        .as_ref()
        .context("review lens requires an assessed Auditor decision")?;
    if baseline.status != DecisionStatus::Selected
        || receipt.role != AgentRole::Auditor.as_str()
        || baseline.normalized_input.task.authority_role != AuthorityRole::ReviewAuditor
        || baseline.normalized_input.task != baseline.normalized_task
        || crate::selection::routing_policy::current_routing_policy().as_ref()
            != Some(&receipt.frozen)
        || baseline.operator_prior_data != super::prior_input::current_provenance()
    {
        bail!("review lens lost its assessed run/policy/prior binding");
    }
    // Reuse the real assessment projection, frozen objective, priors, history
    // and constraints. No task morphology or authority is invented for a lens.
    let mut input = baseline.normalized_input.clone();
    input.catalogs = if let Some(observation) = observation {
        catalogs_from_account_observation(observation, runtime, &input.task, &input.priors)?
    } else {
        if input
            .catalogs
            .iter()
            .any(|catalog| catalog.models.iter().any(|model| model.access.is_some()))
            || input.pools.iter().any(|pool| {
                pool.observation_revision
                    .starts_with("account-observe-sha256:")
            })
        {
            bail!("local-auth review cannot reuse CAM account observations");
        }
        vec![runtime_catalog_from_priors(
            runtime.as_str(),
            catalog,
            &input.task,
            &input.priors,
        )?]
    };
    input
        .constraints
        .allowed_runtimes
        .retain(|allowed| allowed == runtime.as_str());
    if input.constraints.allowed_runtimes.is_empty() {
        bail!("review lens runtime is outside the assessed run constraints");
    }
    input.debug_override = Some(DebugOverride {
        candidate: CandidateKey {
            runtime: runtime.as_str().to_string(),
            model: model.clone(),
            effort: selector_effort_from_str(effort).context("unsupported authored lens effort")?,
        },
        requested_by: "supervisor_plan.review_lenses".to_string(),
        reason: format!(
            "exact authored review lens '{}' after all hard eligibility gates",
            lens.id
        ),
    });
    input.constraints.allow_debug_override = true;
    if input.quota_source.is_some() != quota.context.is_some() {
        bail!("review lens operator quota binding changed");
    }
    if let Some(context) = quota.context {
        let source = input
            .quota_source
            .as_ref()
            .context("lens quota source")?
            .runtime
            .clone();
        apply_live_quota_selection_input(&mut input, context, quota.ledger, source.as_str())?;
    } else if let (Some(observation), Some(pool)) = (
        observation,
        input
            .pools
            .iter_mut()
            .find(|pool| pool.runtime == runtime.as_str()),
    ) {
        if let Some(content) = observation
            .quota
            .as_ref()
            .filter(|category| matches!(category.outcome, ObservationOutcome::Observed))
            .and_then(|category| category.content.as_ref())
        {
            pool.pool_pressure_basis_points = observed_quota_pressure_basis_points(content);
        }
        pool.observation_revision = format!(
            "account-observe-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(observation)?)
        );
    }
    input.operational_observations = Some(live_operational_observations(&input));
    let mut decision = select_with_live_switch_cost_for_policy(&input, Some(receipt))?;
    decision.outcome_history = baseline.outcome_history.clone();
    decision.operator_prior_data = baseline.operator_prior_data.clone();
    let requested = &input
        .debug_override
        .as_ref()
        .context("authored lens candidate")?
        .candidate;
    let choice = decision
        .choice
        .as_ref()
        .filter(|choice| {
            decision.status == DecisionStatus::Selected && &choice.candidate == requested
        })
        .with_context(|| {
            format!(
                "authored review lens '{}' was refused by the selector: {}; eligibility: {:?}",
                lens.id,
                decision.decision_reason,
                decision
                    .candidate_set
                    .iter()
                    .find(|entry| &entry.candidate == requested)
                    .map(|entry| &entry.ineligibility_reasons),
            )
        })?;
    let authority = match account {
        ReviewLensAccount::Selected { observation, .. } => ReviewLensAuthority::Selected(Box::new(
            crate::selection::routing_policy::SelectedLaunchRequest::from_observation(
                choice.candidate.clone(),
                observation,
                &receipt.frozen,
                receipt.features.clone(),
                None,
            )?,
        )),
        ReviewLensAccount::LocalAuth { run_id } => ReviewLensAuthority::LocalAuth {
            run_id: run_id.to_string(),
        },
    };
    Ok(SelectedReviewLens {
        decision,
        authority,
    })
}

fn authored_override_runtime(
    plan: &SupervisorPlan,
    role: AgentRole,
    primary: SupervisorRuntime,
) -> Result<SupervisorRuntime> {
    // Nested `worker_assignments` do not declare a runtime, so they cannot
    // move an explicit override off `primary`.
    let selected = plan
        .assignments
        .iter()
        .filter(|assignment| assignment.role == role)
        .filter_map(|assignment| assignment.runtime)
        .try_fold(None, |selected, authored| match selected {
            None => Ok(Some(authored)),
            Some(existing) if existing == authored => Ok(Some(existing)),
            Some(existing) => {
                bail!(
                    "conflicting authored runtimes for role '{}': '{}' and '{}'",
                    role.as_str(),
                    runtime_name(existing),
                    runtime_name(authored),
                )
            }
        })?;
    Ok(selected.unwrap_or(primary))
}

fn debug_override_for_role(
    role: AgentRole,
    runtime: SupervisorRuntime,
    configured: &RoleModelSelection,
) -> Result<DebugOverride> {
    let model = configured
        .model
        .clone()
        .context("explicit role_models entries are debug overrides and require a model")?;
    let requested_effort = configured
        .reasoning_effort
        .as_deref()
        .context("explicit role_models debug overrides require a reasoning_effort")?;
    let effort = selector_effort_from_str(requested_effort).with_context(|| {
        format!(
            "explicit role_models debug override for role '{}' has unsupported reasoning_effort '{}'",
            role.as_str(), requested_effort
        )
    })?;
    Ok(DebugOverride {
        candidate: CandidateKey {
            runtime: runtime_name(runtime).to_string(),
            model,
            effort,
        },
        requested_by: "supervisor_plan.role_models".to_string(),
        reason: format!(
            "explicit role_models binding for {} is a debug-only selector override",
            role.as_str()
        ),
    })
}

#[derive(Clone)]
struct SelectionInputForRoleArgs<'a> {
    role: AgentRole,
    runtime: SupervisorRuntime,
    catalog: &'a RuntimeModelCatalog,
    advertised: &'a AdvertisedCatalogSet,
    admission: &'a SupervisorAdmissionPolicyInput,
    resolved_objective_profile: &'a ResolvedObjectiveProfile,
    quota_context: Option<&'a LiveQuotaSelectionContext>,
    quota_ledger: Option<&'a RunBudgetLedger>,
    account_observation: Option<&'a AccountObserveResult>,
    signals: DynamicSignals,
    debug_override: Option<DebugOverride>,
    history: Option<&'a FrozenOutcomeHistory>,
}

fn live_switch_cost_evidence(input: &SelectionInput) -> Vec<CandidateSwitchCostEvidence> {
    with_live_switch_cost_session(|session| session.evidence_for(input))
}

fn select_with_live_switch_cost(
    input: &SelectionInput,
) -> Result<SelectionProvenance, selection::SelectionError> {
    select_with_live_switch_cost_for_policy(input, None)
}

fn select_with_live_switch_cost_for_policy(
    input: &SelectionInput,
    routing_policy: Option<&crate::selection::routing_policy::RoutingPolicyReceipt>,
) -> Result<SelectionProvenance, selection::SelectionError> {
    let mut constrained = input.clone();
    selection::runtime_model_policy::constrain(&mut constrained);
    if super::runtime_executables::captured_binding().is_some() {
        super::runtime_executables::constrain_selection(&mut constrained);
    }
    let input = &constrained;
    let evidence = live_switch_cost_evidence(input);
    let provenance =
        selection::select_with_loaded_routing_policy(input, &evidence, routing_policy)?;
    if let Err(error) = route_live_four_arm_comparison(input) {
        return Err(selection::SelectionError::InvalidInput(format!(
            "live online-router four-arm comparison failed: {error:#}"
        )));
    }
    Ok(provenance)
}

pub(super) fn routing_features_from_plan(
    plan: &SupervisorPlan,
) -> crate::selection::routing_policy::TaskRoutingFeatures {
    // Assess terminal scopes: a genuine Execution parent contains its Workers,
    // so counting top-level assignments would incorrectly collapse their grain.
    let mut scopes: Vec<(&[PathBuf], &[String])> = Vec::new();
    let mut dependency_edges = 0usize;
    for assignment in &plan.assignments {
        dependency_edges = dependency_edges.saturating_add(assignment.decision_refs.len());
        if assignment.phase != AssignmentPhase::Execution {
            continue;
        }
        if assignment.worker_assignments.is_empty() {
            scopes.push((&assignment.assigned_paths, &assignment.semantic_modules));
        } else {
            scopes.extend(assignment.worker_assignments.iter().map(|worker| {
                (
                    worker.assigned_paths.as_slice(),
                    worker.semantic_modules.as_slice(),
                )
            }));
        }
    }
    let paths = scopes
        .iter()
        .flat_map(|scope| scope.0.iter())
        .collect::<BTreeSet<_>>();
    let modules = scopes
        .iter()
        .flat_map(|scope| scope.1.iter())
        .collect::<BTreeSet<_>>();
    let mut groups: Vec<usize> = (0..scopes.len()).collect();
    for left in 0..scopes.len() {
        for right in left + 1..scopes.len() {
            let overlap = scopes[left].0.iter().any(|a| {
                scopes[right]
                    .0
                    .iter()
                    .any(|b| a.starts_with(b) || b.starts_with(a))
            }) || scopes[left].1.iter().any(|a| scopes[right].1.contains(a));
            if overlap {
                let previous = groups[right];
                let joined = groups[left];
                for group in &mut groups {
                    if *group == previous {
                        *group = joined;
                    }
                }
            }
        }
    }
    let independent_groups = if dependency_edges != 0 && !scopes.is_empty() {
        // Decision references do not prove absence of cross-worker dependencies.
        1
    } else {
        groups.into_iter().collect::<BTreeSet<_>>().len()
    };
    crate::selection::routing_policy::TaskRoutingFeatures {
        scope_paths: paths.len(), scope_modules: modules.len(), complexity: 0, risk: 0, horizon: 0,
        context_tokens: 0, dependency_edges, independent_groups,
        evidence: vec!["Validated terminal Worker scopes and overlap-connected groups; decision dependencies conservatively join groups; complexity/risk/horizon/context are unassessed lower bounds".to_string()],
    }
}

/// Recount current lowered scopes independently from the assessed declaration.
/// Only the four assessed dimensions survive from the original input morphology.
pub(super) fn routing_features_with_assessment(
    plan: &SupervisorPlan,
    assessment: Option<&TaskRoutingAssessment>,
    frozen: Option<&crate::selection::routing_policy::FrozenRoutingPolicy>,
) -> Result<crate::selection::routing_policy::TaskRoutingFeatures> {
    let mut features = routing_features_from_plan(plan);
    if let Some(assessment) = assessment {
        let frozen = frozen.context("task assessment requires its frozen routing policy")?;
        assessment.validate_for_task(frozen, &plan.task)?;
        features.complexity = assessment.features.complexity;
        features.risk = assessment.features.risk;
        features.horizon = assessment.features.horizon;
        features.context_tokens = assessment.features.context_tokens;
        features.evidence = assessment.features.evidence.clone();
        features.evidence.push(
            "Final-plan terminal scope/dependency/independence counts revalidated separately from assessed declaration morphology; score/context estimates remain policy heuristics".to_string(),
        );
    }
    Ok(features)
}

pub(super) fn task_profile_with_assessment(
    role: AgentRole,
    assessment: Option<&TaskRoutingAssessment>,
    final_features: Option<&crate::selection::routing_policy::TaskRoutingFeatures>,
    frozen: Option<&crate::selection::routing_policy::FrozenRoutingPolicy>,
) -> Result<TaskProfile> {
    let mut base = task_profile_for_role(role);
    if let Some(assessment) = assessment {
        let frozen = frozen.context("task profile assessment requires its frozen policy")?;
        let final_features =
            final_features.context("assessed task profile requires final routing features")?;
        let projected = super::task_routing::project_task_profile_with_final_features(
            &base,
            assessment,
            final_features,
            frozen,
        )?;
        if projected.authority_role != base.authority_role
            || projected.task_class != base.task_class
        {
            bail!("task profile projection changed intrinsic authority or benchmark class");
        }
        Ok(projected)
    } else {
        base.risk = RiskLevel::Unknown;
        base.context = ContextSize::Unknown;
        base.horizon = TaskHorizon::Unknown;
        base.boundedness = Boundedness::Unknown;
        Ok(base)
    }
}

/// Keep the complete evaluator decision for the parent's run evidence. Only
/// authenticated parent-owned history may supply measured outcomes and costs.
#[cfg(all(test, target_os = "linux"))]
pub(super) fn select_normal_account_intake_with_history(
    plan: &SupervisorPlan,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    observations: &[(SupervisorRuntime, AccountObserveResult)],
    admission: &SupervisorAdmissionPolicyInput,
    objective: &ResolvedObjectiveProfile,
    history: Option<&FrozenOutcomeHistory>,
) -> Result<(
    Option<crate::selection::routing_policy::SelectedLaunchRequest>,
    SelectionProvenance,
)> {
    // Projection of unknown access must use this exact frozen argument, not an
    // unrelated caller's ambient policy. Restore the caller's binding on exit.
    let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
    let role = plan
        .assignments
        .first()
        .context("normal intake has no assignment")?
        .role;
    select_account_intake_for_role_with_history(
        plan,
        frozen,
        observations,
        admission,
        objective,
        history,
        role,
    )
}

#[cfg(target_os = "linux")]
pub(super) fn select_normal_account_intake_with_assessment(
    plan: &SupervisorPlan,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    observations: &[(SupervisorRuntime, AccountObserveResult)],
    admission: &SupervisorAdmissionPolicyInput,
    objective: &ResolvedObjectiveProfile,
    history: Option<&FrozenOutcomeHistory>,
    assessment: Option<&TaskRoutingAssessment>,
) -> Result<(
    Option<crate::selection::routing_policy::SelectedLaunchRequest>,
    SelectionProvenance,
)> {
    let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
    let role = plan
        .assignments
        .first()
        .context("normal intake has no assignment")?
        .role;
    select_account_intake_for_role_with_assessment(
        plan,
        frozen,
        observations,
        admission,
        objective,
        history,
        role,
        assessment,
    )
}

/// Select the required review role before evaluation. The caller must keep its
/// matching frozen-policy guard alive through launch. This seals only the
/// selector tuple; live account, executable, run, protocol and confinement
/// authority remain the downstream launch constructor's responsibility.
#[cfg(target_os = "linux")]
pub(crate) fn select_account_review_auditor(
    plan: &SupervisorPlan,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    observations: &[(
        SupervisorRuntime,
        coding_agent_manager_lib::account_authority::AccountObserveResult,
    )],
    admission: &SupervisorAdmissionPolicyInput,
    objective: &ResolvedObjectiveProfile,
) -> Result<(
    Option<crate::selection::routing_policy::SelectedLaunchRequest>,
    SelectionProvenance,
)> {
    if crate::selection::routing_policy::current_routing_policy().as_ref() != Some(frozen) {
        bail!("account review requires the caller's matching frozen routing policy");
    }
    let (selected, decision) = select_account_intake_for_role_with_history(
        plan,
        frozen,
        observations,
        admission,
        objective,
        None,
        AgentRole::Auditor,
    )?;
    validate_and_seal_account_review_selection(frozen, selected.as_ref(), &decision)?;
    Ok((selected, decision))
}

/// Supply validated task decision data without changing account or launch authority.
/// Missing assessment retains the existing unassessed, fail-closed API.
#[cfg(target_os = "linux")]
pub(crate) fn select_account_review_auditor_with_assessment(
    plan: &SupervisorPlan,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    observations: &[(SupervisorRuntime, AccountObserveResult)],
    admission: &SupervisorAdmissionPolicyInput,
    objective: &ResolvedObjectiveProfile,
    assessment: Option<&TaskRoutingAssessment>,
) -> Result<(
    Option<crate::selection::routing_policy::SelectedLaunchRequest>,
    SelectionProvenance,
)> {
    let Some(assessment) = assessment else {
        return crate::supervise::select_account_review_auditor(
            plan,
            frozen,
            observations,
            admission,
            objective,
        );
    };
    if crate::selection::routing_policy::current_routing_policy().as_ref() != Some(frozen) {
        bail!("account review requires the caller's matching frozen routing policy");
    }
    let (selected, decision) = select_account_intake_for_role_with_assessment(
        plan,
        frozen,
        observations,
        admission,
        objective,
        None,
        AgentRole::Auditor,
        Some(assessment),
    )?;
    validate_and_seal_account_review_selection(frozen, selected.as_ref(), &decision)?;
    Ok((selected, decision))
}

#[cfg(target_os = "linux")]
fn validate_and_seal_account_review_selection(
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    selected: Option<&crate::selection::routing_policy::SelectedLaunchRequest>,
    decision: &SelectionProvenance,
) -> Result<()> {
    use crate::selection::routing_policy::{
        current_routing_policy, seal_selected_candidate, validate_selected_launch,
    };
    let receipt = decision
        .routing_policy
        .as_ref()
        .context("account review selection is missing its frozen-policy receipt")?;
    if &receipt.frozen != frozen
        || receipt.role != AgentRole::Auditor.as_str()
        || current_routing_policy().as_ref() != Some(frozen)
        || decision.normalized_input.task.authority_role != AuthorityRole::ReviewAuditor
    {
        bail!("account review selection has a foreign role or frozen-policy receipt");
    }
    let Some(selected) = selected else {
        if decision.status == DecisionStatus::Selected {
            bail!("selected account review is missing its launch request");
        }
        return Ok(());
    };
    let choice = decision
        .choice
        .as_ref()
        .context("account review selection is missing its selected choice")?;
    if decision.status != DecisionStatus::Selected
        || &choice.candidate != selected.candidate()
        || selected.policy_digest != frozen.sha256
        || selected.task_features != receipt.features
    {
        bail!("account review launch request differs from its evaluator decision");
    }
    seal_selected_candidate(AgentRole::Auditor.as_str(), decision)?;
    let candidate = selected.candidate();
    validate_selected_launch(
        AgentRole::Auditor.as_str(),
        &candidate.runtime,
        &candidate.model,
        candidate.effort.as_str(),
    )
}

#[cfg(target_os = "linux")]
fn select_account_intake_for_role_with_history(
    plan: &SupervisorPlan,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    observations: &[(SupervisorRuntime, AccountObserveResult)],
    admission: &SupervisorAdmissionPolicyInput,
    objective: &ResolvedObjectiveProfile,
    history: Option<&FrozenOutcomeHistory>,
    role: AgentRole,
) -> Result<(
    Option<crate::selection::routing_policy::SelectedLaunchRequest>,
    SelectionProvenance,
)> {
    select_account_intake_for_role_with_assessment(
        plan,
        frozen,
        observations,
        admission,
        objective,
        history,
        role,
        None,
    )
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn select_account_intake_for_role_with_assessment(
    plan: &SupervisorPlan,
    frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    observations: &[(SupervisorRuntime, AccountObserveResult)],
    admission: &SupervisorAdmissionPolicyInput,
    objective: &ResolvedObjectiveProfile,
    history: Option<&FrozenOutcomeHistory>,
    role: AgentRole,
    assessment: Option<&TaskRoutingAssessment>,
) -> Result<(
    Option<crate::selection::routing_policy::SelectedLaunchRequest>,
    SelectionProvenance,
)> {
    use crate::selection::routing_policy::{RoutingPolicyReceipt, SelectedLaunchRequest};
    let receipt = RoutingPolicyReceipt {
        frozen: frozen.clone(),
        role: role.as_str().to_string(),
        features: routing_features_with_assessment(plan, assessment, Some(frozen))?,
    };
    let mut combined: Option<SelectionInput> = None;
    for (runtime, observation) in observations {
        let input = selection_input_for_role_with_assessment(
            SelectionInputForRoleArgs {
                role,
                runtime: *runtime,
                catalog: &RuntimeModelCatalog::OperatorDeclared,
                advertised: &AdvertisedCatalogSet::empty(),
                admission,
                resolved_objective_profile: objective,
                quota_context: None,
                quota_ledger: None,
                account_observation: Some(observation),
                signals: DynamicSignals {
                    retry_count: 0,
                    budget_signal: BudgetSignal::Continue,
                    previous_choice: None,
                    previous_catalog_digest: None,
                    environment_rejections: vec![],
                    accepted_task_cost_context: None,
                    accepted_task_cost_observations: Vec::new(),
                },
                debug_override: None,
                history,
            },
            assessment,
            Some(&receipt.features),
            Some(frozen),
        )?;
        if let Some(combined) = &mut combined {
            combined.catalogs.extend(input.catalogs);
            combined.pools.extend(input.pools);
            combined
                .constraints
                .allowed_runtimes
                .extend(input.constraints.allowed_runtimes);
        } else {
            combined = Some(input);
        }
    }
    let mut input = combined.context(
        "normal intake requires a selected account with observed supported model/effort metadata",
    )?;
    selection::runtime_model_policy::constrain(&mut input);
    let mut decision = selection::select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
    decision.outcome_history = history.map(|snapshot| snapshot.provenance.clone());
    decision.operator_prior_data = super::prior_input::current_provenance();
    if decision.status != DecisionStatus::Selected {
        return Ok((None, decision));
    }
    let candidate = decision
        .choice
        .as_ref()
        .context("selected normal intake has no choice")?
        .candidate
        .clone();
    let (_, observation) = observations
        .iter()
        .find(|(runtime, _)| runtime_name(*runtime) == candidate.runtime)
        .context("selected runtime has no account observation")?;
    let selected = SelectedLaunchRequest::from_observation(
        candidate,
        observation,
        frozen,
        receipt.features,
        None,
    )?;
    Ok((Some(selected), decision))
}

pub(super) fn selector_priors_with_terminal_worker_economics() -> Result<selection::PriorDataset> {
    if let Some(priors) = super::prior_input::current_priors() {
        return Ok(priors);
    }
    base_selector_priors_with_terminal_worker_economics()
}

pub(super) fn base_selector_priors_with_terminal_worker_economics(
) -> Result<selection::PriorDataset> {
    let mut priors = selection::built_in_prior_dataset()?;
    #[cfg(test)]
    if TEST_SELECTOR_TRIPLE_RUNNER_UP_ENABLED.with(Cell::get) {
        let mut runner_up = priors
            .models
            .iter()
            .find(|prior| {
                prior.runtime == runtime_name(SupervisorRuntime::Codex)
                    && prior.model == FRONTIER_PROFILE_MODEL
            })
            .cloned()
            .context("selector-triple fixture requires the frontier Codex prior")?;
        runner_up.model = TEST_SELECTOR_TRIPLE_RUNNER_UP_MODEL.to_string();
        runner_up.source_id = "test-selector-triple-runner-up-fixture".to_string();
        runner_up.prior_scope =
            "test-only deterministic second delegating candidate for selector-triple coverage"
                .to_string();
        runner_up.limitations =
            vec!["test fixture only; not production model or authority evidence".to_string()];
        runner_up.prohibited_authority_roles = [
            AuthorityRole::TerminalLeaf,
            AuthorityRole::AcceptanceGate,
            AuthorityRole::ReviewAuditor,
            AuthorityRole::Audit,
            AuthorityRole::ConflictResolution,
            AuthorityRole::FailureClassification,
            AuthorityRole::GitPublication,
            AuthorityRole::UnknownJudgment,
        ]
        .into_iter()
        .collect();
        runner_up.one_shot_environment_fallbacks.clear();
        priors.revision = format!("{}+selector-triple-runner-up-fixture", priors.revision);
        priors.models.push(runner_up);
    }
    let economics = crate::optimizer::objective::terminal_worker_routing_economics()?;
    if priors
        .models
        .iter()
        .any(|prior| prior.runtime == economics.runtime && prior.model == economics.model)
    {
        bail!(
            "built-in selector data already defines terminal routing evidence for '{}:{}'; refusing an ambiguous duplicate",
            economics.runtime,
            economics.model
        );
    }
    let effort = selector_effort_from_str(&economics.effort).with_context(|| {
        format!(
            "terminal routing economics names unsupported reasoning effort '{}'",
            economics.effort
        )
    })?;
    priors.revision = format!("{}+{}", priors.revision, economics.source_id);
    priors.models.push(selection::ModelPrior {
        runtime: economics.runtime,
        model: economics.model,
        observed_on: economics.observed_on,
        source_id: economics.source_id,
        prior_scope: economics.prior_scope,
        limitations: economics.limitations,
        prohibited: false,
        prohibition_reason: None,
        prohibited_authority_roles: [
            AuthorityRole::Delegating,
            AuthorityRole::AcceptanceGate,
            AuthorityRole::ReviewAuditor,
            AuthorityRole::Audit,
            AuthorityRole::ConflictResolution,
            AuthorityRole::FailureClassification,
            AuthorityRole::GitPublication,
            AuthorityRole::UnknownJudgment,
        ]
        .into_iter()
        .collect(),
        long_context_eligible: false,
        task_shape_ceiling: Some(selection::TaskShapeCeiling::bounded_terminal()),
        strong_gate_fallback_efforts: BTreeSet::new(),
        strength_rank: 40,
        class_fit: vec![selection::ClassFitPrior {
            task_class: AUTOMATIC_SELECTION_TASK_CLASS.to_string(),
            effort,
            quality_basis_points: economics.quality_basis_points,
            sample_size: economics.sample_size,
            execution_cost_microunits: economics.execution_cost_microunits,
            review_cost_microunits: 0,
            rework_cost_microunits: 0,
            rereview_cost_microunits: 0,
        }],
        authority_evidence: Vec::new(),
        one_shot_environment_fallbacks: Vec::new(),
    });
    Ok(priors)
}

#[cfg(test)]
fn selection_input_for_role(args: SelectionInputForRoleArgs<'_>) -> Result<SelectionInput> {
    selection_input_for_role_with_assessment(args, None, None, None)
}

fn selection_input_for_role_with_assessment(
    args: SelectionInputForRoleArgs<'_>,
    assessment: Option<&TaskRoutingAssessment>,
    final_features: Option<&crate::selection::routing_policy::TaskRoutingFeatures>,
    frozen: Option<&crate::selection::routing_policy::FrozenRoutingPolicy>,
) -> Result<SelectionInput> {
    let SelectionInputForRoleArgs {
        role,
        runtime,
        catalog,
        advertised,
        admission,
        resolved_objective_profile,
        quota_context,
        quota_ledger,
        account_observation,
        signals,
        debug_override,
        history,
    } = args;
    let priors = selector_priors_with_terminal_worker_economics()?;
    let task = task_profile_with_assessment(role, assessment, final_features, frozen)?;
    let outcomes = history
        .map(|snapshot| snapshot.outcomes_for(&task))
        .unwrap_or_default();
    let runtime_name = runtime_name(runtime);
    let catalogs = constructed_selection_catalogs(
        runtime,
        catalog,
        advertised,
        &task,
        &priors,
        account_observation,
    )?;
    let profile = priors
        .objective_profiles
        .first()
        .context("built-in selector data has no objective profile")?;
    let profile_name = profile.name.clone();
    let profile_version = profile.version;
    let primary_pool = primary_pool_for_selection(runtime_name, admission, account_observation)?;
    let pools = pools_for_constructed_catalogs(&catalogs, runtime_name, primary_pool);
    let allowed_runtimes = catalogs
        .iter()
        .map(|runtime_catalog| runtime_catalog.runtime.clone())
        .collect();
    let mut input = SelectionInput {
        task,
        assignment_shape_identity: None,
        catalogs,
        pools,
        quota_source: None,
        constraints: OperatorConstraints {
            allowed_runtimes,
            allowed_models: BTreeSet::new(),
            forbidden_runtimes: BTreeSet::new(),
            forbidden_models: BTreeSet::new(),
            forbidden_candidates: BTreeSet::new(),
            allow_debug_override: debug_override.is_some(),
        },
        priors,
        objective_profile: ObjectiveProfileRef {
            name: profile_name,
            version: profile_version,
            expected_digest: None,
        },
        resolved_objective_profile: resolved_objective_profile.clone(),
        outcomes,
        signals,
        debug_override,
        operational_observations: None,
    };
    if let Some(quota_context) = quota_context {
        apply_live_quota_selection_input(&mut input, quota_context, quota_ledger, runtime_name)?;
    }
    input.operational_observations = Some(live_operational_observations(&input));
    Ok(input)
}

/// Local-auth Codex has no CAM identity to put in an AccountObserveResult.
/// Other providers' selected accounts must not displace its acquired catalog,
/// including in the snapshot retained for retries. A configured authority with
/// no primary selection remains a refusal rather than unmanaged admission.
fn account_catalog_set_for_primary(
    runtime: SupervisorRuntime,
    accounts: &[(SupervisorRuntime, AccountObserveResult)],
) -> Result<&[(SupervisorRuntime, AccountObserveResult)]> {
    if accounts.iter().any(|(observed, _)| *observed == runtime) {
        return Ok(accounts);
    }
    #[cfg(target_os = "linux")]
    if runtime == SupervisorRuntime::Codex {
        if crate::account_authority::configured_cam_authority_socket().is_none() {
            return Ok(&[]);
        }
        bail!("configured CAM account catalog set is missing the selected primary runtime binding");
    }
    if accounts.is_empty() {
        return Ok(accounts);
    }
    bail!("account catalog set is missing the selected primary runtime binding");
}

fn selection_input_for_role_with_assessment_and_accounts(
    args: SelectionInputForRoleArgs<'_>,
    accounts: &[(SupervisorRuntime, AccountObserveResult)],
    assessment: Option<&TaskRoutingAssessment>,
    final_features: Option<&crate::selection::routing_policy::TaskRoutingFeatures>,
    frozen: Option<&crate::selection::routing_policy::FrozenRoutingPolicy>,
) -> Result<SelectionInput> {
    let accounts = account_catalog_set_for_primary(args.runtime, accounts)?;
    if accounts.is_empty() {
        return selection_input_for_role_with_assessment(args, assessment, final_features, frozen);
    }
    let mut runtimes = BTreeSet::new();
    let mut combined: Option<SelectionInput> = None;
    for (runtime, observation) in accounts {
        if !runtimes.insert(runtime.as_str()) {
            bail!("account catalog set repeats a runtime selection");
        }
        let input = selection_input_for_role_with_assessment(
            SelectionInputForRoleArgs {
                runtime: *runtime,
                account_observation: Some(observation),
                // Apply the configured quota contract once over the complete set;
                // each account still supplies its own observed admission pool.
                quota_context: None,
                quota_ledger: None,
                ..args.clone()
            },
            assessment,
            final_features,
            frozen,
        )?;
        if let Some(combined) = &mut combined {
            combined.catalogs.extend(input.catalogs);
            combined.pools.extend(input.pools);
            combined
                .constraints
                .allowed_runtimes
                .extend(input.constraints.allowed_runtimes);
        } else {
            combined = Some(input);
        }
    }
    let mut input = combined.context("account catalog set is empty")?;
    if let Some(quota_context) = args.quota_context {
        apply_live_quota_selection_input(
            &mut input,
            quota_context,
            args.quota_ledger,
            runtime_name(args.runtime),
        )?;
    }
    input.operational_observations = Some(live_operational_observations(&input));
    Ok(input)
}

fn account_selection_catalogs(
    accounts: &[(SupervisorRuntime, AccountObserveResult)],
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<Vec<RuntimeCatalog>> {
    #[cfg(target_os = "linux")]
    {
        let mut runtimes = BTreeSet::new();
        let mut catalogs = Vec::new();
        for (runtime, observation) in accounts {
            if !runtimes.insert(runtime.as_str()) {
                bail!("account catalog set repeats a runtime selection");
            }
            catalogs.extend(catalogs_from_account_observation(
                observation,
                *runtime,
                task,
                priors,
            )?);
        }
        Ok(catalogs)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (accounts, task, priors);
        bail!("account catalog sets require the managed Linux runtime");
    }
}

fn live_operational_observations(input: &SelectionInput) -> LiveOperationalObservations {
    let quota = input
        .quota_source
        .as_ref()
        .and_then(|source| {
            input.pools.iter().find(|pool| {
                pool.pool_reference.as_ref() == Some(source)
                    && pool.entitlement_bounded
                    && pool.observation_source.is_some()
            })
        })
        .map(|pool| {
            let consumed = pool
                .entitlement_capacity_units
                .saturating_sub(pool.entitlement_remaining_units);
            let value_basis_points = if pool.entitlement_capacity_units == 0 {
                0
            } else {
                u16::try_from(consumed.saturating_mul(10_000) / pool.entitlement_capacity_units)
                    .unwrap_or(10_000)
            };
            TypedAxisObservation {
                kind: TypedObservationKind::Measured,
                unit: "entitlement_consumed_fraction_bp".to_string(),
                value_basis_points,
            }
        });
    let retry_rate = Some(TypedAxisObservation {
        kind: TypedObservationKind::Measured,
        unit: "retry_count".to_string(),
        value_basis_points: u16::try_from(input.signals.retry_count.saturating_mul(1_000))
            .unwrap_or(u16::MAX),
    });
    let review_load = input
        .outcomes
        .iter()
        .max_by_key(|outcome| {
            outcome
                .review_cost_microunits
                .saturating_add(outcome.rereview_cost_microunits)
        })
        .map(|outcome| {
            let review = outcome
                .review_cost_microunits
                .saturating_add(outcome.rereview_cost_microunits);
            let total = outcome
                .execution_cost_microunits
                .saturating_add(review)
                .saturating_add(outcome.rework_cost_microunits)
                .saturating_add(outcome.environment_cost_microunits);
            let value_basis_points = if total == 0 {
                0
            } else {
                u16::try_from(review.saturating_mul(10_000) / total).unwrap_or(10_000)
            };
            TypedAxisObservation {
                kind: TypedObservationKind::Measured,
                unit: "review_cost_fraction_bp".to_string(),
                value_basis_points,
            }
        });
    LiveOperationalObservations {
        quota,
        latency: None,
        retry_rate,
        review_load,
    }
}

fn apply_live_quota_selection_input(
    input: &mut SelectionInput,
    quota_context: &LiveQuotaSelectionContext,
    quota_ledger: Option<&RunBudgetLedger>,
    source_runtime: &str,
) -> Result<()> {
    let source = live_quota_pool_for_runtime(quota_context, source_runtime)?;
    input.quota_source = Some(crate::optimizer::quota_pools::PoolReference {
        runtime: source.runtime.clone(),
        account: source.account.clone(),
        window: source.window,
    });
    let ledger = match quota_ledger {
        Some(quota_ledger) => quota_ledger
            .quota_consumption_ledger(&quota_context.config, crate::budget_ledger::unix_now()?)
            .map_err(|error| {
                anyhow!("failed to project attached operator quota ledger: {error}")
            })?,
        None => {
            bail!("operator quota selection requires the scheduler's attached run budget ledger")
        }
    };
    selection::apply_fail_closed_quota_pools(input, &quota_context.config.pools, &ledger)
        .map_err(|error| anyhow!("live operator quota selection input failed closed: {error}"))?;
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn constructed_selection_catalogs(
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    advertised: &AdvertisedCatalogSet,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
    account_observation: Option<&AccountObserveResult>,
) -> Result<Vec<RuntimeCatalog>> {
    #[cfg(target_os = "linux")]
    if let Some(observation) = account_observation {
        return catalogs_from_account_observation(observation, runtime, task, priors);
    }
    let primary = if runtime == SupervisorRuntime::Cursor {
        if let Some(observation) = &advertised.cursor {
            runtime_catalog_from_advertised_slugs(
                "cursor",
                observation.catalog().slugs(),
                format!("cursor-advertised-sha256:{}", observation.source_sha256()),
                observation.observed_at_unix_millis().to_string(),
                task,
                priors,
            )?
        } else {
            runtime_catalog_from_priors(runtime_name(runtime), catalog, task, priors)?
        }
    } else if runtime == SupervisorRuntime::Grok {
        if let Some(observation) = &advertised.grok {
            runtime_catalog_from_advertised_slugs(
                "grok",
                observation.catalog().slugs(),
                format!(
                    "grok-advertised-sha256:{};auth={}",
                    observation.source_sha256(),
                    observation.authentication_evidence()
                ),
                observation.observed_at_unix_millis().to_string(),
                task,
                priors,
            )?
        } else {
            runtime_catalog_from_priors(runtime_name(runtime), catalog, task, priors)?
        }
    } else {
        runtime_catalog_from_priors(runtime_name(runtime), catalog, task, priors)?
    };
    let mut catalogs = vec![primary];
    if runtime != SupervisorRuntime::Cursor {
        if let Some(observation) = &advertised.cursor {
            catalogs.push(runtime_catalog_from_advertised_slugs(
                "cursor",
                observation.catalog().slugs(),
                format!("cursor-advertised-sha256:{}", observation.source_sha256()),
                observation.observed_at_unix_millis().to_string(),
                task,
                priors,
            )?);
        } else if let Some(gap) = &advertised.cursor_evidence_gap {
            catalogs.push(runtime_catalog_from_unavailable_priors(
                "cursor", gap, task, priors,
            )?);
        }
    }
    if runtime != SupervisorRuntime::Grok {
        if let Some(observation) = &advertised.grok {
            catalogs.push(runtime_catalog_from_advertised_slugs(
                "grok",
                observation.catalog().slugs(),
                format!(
                    "grok-advertised-sha256:{};auth={}",
                    observation.source_sha256(),
                    observation.authentication_evidence()
                ),
                observation.observed_at_unix_millis().to_string(),
                task,
                priors,
            )?);
        }
    }
    Ok(catalogs)
}

#[cfg(target_os = "linux")]
fn runtime_from_account_provider(provider_id: &str) -> Result<&'static str> {
    match provider_id {
        "grok-cli" => Ok("grok"),
        "cursor" => Ok("cursor"),
        "codex-cli" => Ok("codex"),
        "claude-code" => Ok("claude-code"),
        "gemini-cli" => Ok("gemini-cli"),
        _ => {
            bail!("account observation provider '{provider_id}' has no fail-closed runtime mapping")
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) fn runtime_for_account_provider(provider_id: &str) -> Option<SupervisorRuntime> {
    runtime_from_account_provider(provider_id)
        .ok()
        .and_then(|runtime| runtime_from_name(runtime).ok())
}

#[cfg(target_os = "linux")]
fn account_observe_environment_decision(
    observation: &AccountObserveResult,
) -> (AccountObserveOutcomeKind, Option<u64>) {
    let kind = match observation.quota.as_ref().map(|category| &category.outcome) {
        Some(ObservationOutcome::Observed) => AccountObserveOutcomeKind::Observed,
        Some(ObservationOutcome::Stale) => AccountObserveOutcomeKind::Stale,
        Some(ObservationOutcome::Unavailable) => AccountObserveOutcomeKind::Unavailable,
        Some(ObservationOutcome::Failed { .. }) => AccountObserveOutcomeKind::Failed,
        Some(ObservationOutcome::Unknown) | None => AccountObserveOutcomeKind::Unknown,
    };
    // Quota utilization is a 0..=1 pressure signal, not environment spend.
    (kind, None)
}

#[cfg(target_os = "linux")]
fn catalogs_from_account_observation(
    observation: &AccountObserveResult,
    selected_runtime: SupervisorRuntime,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<Vec<RuntimeCatalog>> {
    let mapped = runtime_from_account_provider(&observation.binding.provider_id)?;
    if mapped != runtime_name(selected_runtime) {
        bail!(
            "account observation provider '{}' maps to runtime '{mapped}' which does not match selected runtime '{}'",
            observation.binding.provider_id,
            runtime_name(selected_runtime)
        );
    }
    match observation.models.as_ref() {
        Some(category) if matches!(category.outcome, ObservationOutcome::Stale) => {
            bail!("stale account observation binding never admits models");
        }
        Some(category) if matches!(category.outcome, ObservationOutcome::Observed) => {
            let content = category.content.as_ref().with_context(|| {
                format!(
                    "Observed models category for provider '{}' is missing content",
                    observation.binding.provider_id
                )
            })?;
            coding_agent_manager_lib::account_authority::validate_observed_models_for_binding(
                content,
                &observation.binding,
            )
            .map_err(|error| anyhow!("account observation models failed validation: {error}"))?;
            Ok(vec![runtime_catalog_from_observed_models(
                mapped,
                &observation.binding,
                content,
                observation.observed_at.clone(),
                task,
                priors,
            )?])
        }
        _ => Ok(vec![RuntimeCatalog {
            runtime: mapped.to_string(),
            revision: format!(
                "account-observe-models-unobserved-sha256:{}",
                crate::artifacts::state_auth::sha256_hex(observation.observed_at.as_bytes())
            ),
            advertised_at: observation.observed_at.clone(),
            models: Vec::new(),
        }]),
    }
}

#[cfg(target_os = "linux")]
fn runtime_catalog_from_observed_models(
    runtime: &str,
    binding: &coding_agent_manager_lib::account_authority::SelectedAccountBinding,
    observed: &ModelsObservation,
    advertised_at: String,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<RuntimeCatalog> {
    let mut models = Vec::new();
    for observed_model in &observed.models {
        if let Some(catalog_model) =
            catalog_model_from_observed(runtime, observed_model, task, priors)?
        {
            models.push(catalog_model);
        }
    }
    models.sort_by(|left, right| left.model.cmp(&right.model));
    // Preserve source qualification and access state even when two observations
    // project to the same executable model/effort menu. Canonicalize set-valued
    // metadata before hashing without promoting a cache listing to entitlement.
    let mut normalized_observed = observed.clone();
    normalized_observed
        .models
        .sort_by(|left, right| left.model_id.cmp(&right.model_id));
    for model in &mut normalized_observed.models {
        if let Some(efforts) = &mut model.supported_efforts {
            efforts.sort();
            efforts.dedup();
        }
    }
    let revision_material =
        serde_json::to_vec(&(binding, &advertised_at, &normalized_observed, &models))
            .context("failed to normalize account-observed catalog")?;
    Ok(RuntimeCatalog {
        runtime: runtime.to_string(),
        revision: format!(
            "account-observe-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(&revision_material)
        ),
        advertised_at,
        models,
    })
}

#[cfg(target_os = "linux")]
fn catalog_model_from_observed(
    runtime: &str,
    observed: &ObservedModel,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<Option<CatalogModel>> {
    let mut supported_efforts = Vec::new();
    if let Some(raw_efforts) = &observed.supported_efforts {
        for effort in raw_efforts {
            let Some(effort) = selector_effort_from_str(effort) else {
                return Ok(None);
            };
            supported_efforts.push(effort);
        }
    }
    supported_efforts.sort();
    supported_efforts.dedup();
    if supported_efforts.is_empty() {
        return Ok(None);
    }
    let prior = priors
        .models
        .iter()
        .find(|prior| prior.runtime == runtime && prior.model == observed.model_id);
    let mut capabilities = prior
        .map(|prior| capabilities_from_prior(prior, task))
        .transpose()?
        .unwrap_or_else(|| CandidateCapabilities {
            task_classes: BTreeSet::new(),
            authority_roles: BTreeSet::new(),
            boundedness: [
                Boundedness::TightlyBounded,
                Boundedness::Bounded,
                Boundedness::CrossCutting,
            ]
            .into_iter()
            .collect(),
            maximum_risk: RiskLevel::Critical,
            maximum_context: ContextSize::Long,
            maximum_horizon: TaskHorizon::Long,
            long_context: false,
        });
    if prior.is_none() {
        selection::effective_task_shape_ceiling(runtime, &observed.model_id, None)?
            .constrain(&mut capabilities);
    }
    Ok(Some(CatalogModel {
        model: observed.model_id.clone(),
        access: Some(observed.access),
        available: match observed.access {
            coding_agent_manager_lib::account_authority::ModelAccessOutcome::Unavailable => false,
            coding_agent_manager_lib::account_authority::ModelAccessOutcome::Available => true,
            coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess =>
                crate::selection::routing_policy::current_routing_policy().is_some_and(|policy|
                    policy.policy.unknown_access_policy ==
                        crate::selection::routing_policy::UnknownAccessPolicy::UnknownAccessForProductiveAttempt),
        },
        supported_efforts,
        capabilities,
    }))
}

fn capabilities_from_prior(
    prior: &selection::ModelPrior,
    task: &TaskProfile,
) -> Result<CandidateCapabilities> {
    let mut authority_roles = prior
        .authority_evidence
        .iter()
        .map(|evidence| evidence.role)
        .collect::<BTreeSet<_>>();
    if !prior.class_fit.is_empty() {
        authority_roles.insert(AuthorityRole::TerminalLeaf);
    }
    if !prior.strong_gate_fallback_efforts.is_empty()
        && !prior
            .prohibited_authority_roles
            .contains(&task.authority_role)
    {
        authority_roles.insert(task.authority_role);
    }
    let mut capabilities = CandidateCapabilities {
        task_classes: prior
            .class_fit
            .iter()
            .map(|class_fit| class_fit.task_class.clone())
            .collect(),
        authority_roles,
        boundedness: [
            Boundedness::TightlyBounded,
            Boundedness::Bounded,
            Boundedness::CrossCutting,
        ]
        .into_iter()
        .collect(),
        maximum_risk: RiskLevel::Critical,
        maximum_context: ContextSize::Long,
        maximum_horizon: TaskHorizon::Long,
        long_context: prior.long_context_eligible,
    };
    selection::effective_task_shape_ceiling(
        &prior.runtime,
        &prior.model,
        prior.task_shape_ceiling.as_ref(),
    )?
    .constrain(&mut capabilities);
    Ok(capabilities)
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn primary_pool_for_selection(
    runtime_name: &str,
    admission: &SupervisorAdmissionPolicyInput,
    account_observation: Option<&AccountObserveResult>,
) -> Result<RuntimePoolState> {
    #[cfg(target_os = "linux")]
    if let Some(observation) = account_observation {
        return account_observation_primary_pool(runtime_name, admission, observation);
    }
    let capacity = u64::try_from(admission.provider_inflight_bound)
        .context("provider inflight bound does not fit selector pool units")?;
    let admission_bytes = serde_json::to_vec(admission)
        .context("failed to normalize supervisor admission input for selection")?;
    Ok(RuntimePoolState {
        runtime: runtime_name.to_string(),
        admission_open: admission.resolved_bound > 0,
        pool_reference: None,
        pool_kind: None,
        entitlement_bounded: true,
        entitlement_capacity_units: capacity,
        entitlement_remaining_units: capacity,
        pool_pressure_basis_points: 0,
        observed_consumption_units: 0,
        marginal_cost_microunits: 0,
        exhausted: false,
        exhaustion_behavior: None,
        authorized_alternatives: Vec::new(),
        observation_revision: format!(
            "supervisor-admission-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(&admission_bytes)
        ),
        observation_source: None,
        admission_provenance: "supervisor admission supplies a bounded active-runtime inflight pool; external account quota and marginal-price observations were unavailable"
            .to_string(),
        failover_provenance: Some(
            "advertised runtime catalogs participate in selection; launch uses the selected pair"
                .to_string(),
        ),
    })
}

#[cfg(target_os = "linux")]
fn account_observation_primary_pool(
    runtime_name: &str,
    admission: &SupervisorAdmissionPolicyInput,
    observation: &AccountObserveResult,
) -> Result<RuntimePoolState> {
    let observation_bytes = serde_json::to_vec(observation)
        .context("failed to normalize account observation for selection")?;
    let (pressure, provenance) = match observation.quota.as_ref() {
        Some(category) if matches!(category.outcome, ObservationOutcome::Observed) => {
            let pressure = category
                .content
                .as_ref()
                .map(observed_quota_pressure_basis_points)
                .unwrap_or(0);
            (
                pressure,
                "account observation supplies utilization as pool pressure only; unit remaining, consumption, and marginal price were not projected",
            )
        }
        _ => (
            0,
            "supervisor admission supplies a bounded active-runtime inflight pool; account observation did not supply Observed quota utilization, remaining, consumption, or marginal price",
        ),
    };
    Ok(RuntimePoolState {
        runtime: runtime_name.to_string(),
        admission_open: admission.resolved_bound > 0,
        pool_reference: None,
        pool_kind: None,
        entitlement_bounded: false,
        entitlement_capacity_units: 0,
        entitlement_remaining_units: 0,
        pool_pressure_basis_points: pressure,
        observed_consumption_units: 0,
        marginal_cost_microunits: 0,
        exhausted: false,
        exhaustion_behavior: None,
        authorized_alternatives: Vec::new(),
        observation_revision: format!(
            "account-observe-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(&observation_bytes)
        ),
        observation_source: None,
        admission_provenance: provenance.to_string(),
        failover_provenance: None,
    })
}

#[cfg(target_os = "linux")]
fn observed_quota_pressure_basis_points(quota: &QuotaObservation) -> u16 {
    quota
        .snapshots
        .iter()
        .map(|snapshot| {
            let scaled = (f64::from(snapshot.utilization) * 10_000.0).round();
            if scaled.is_finite() {
                scaled.clamp(0.0, 10_000.0) as u16
            } else {
                0
            }
        })
        .max()
        .unwrap_or(0)
}

fn runtime_catalog_from_unavailable_priors(
    runtime_name: &str,
    gap: &CursorCatalogEvidenceGap,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<RuntimeCatalog> {
    let mut models = priors
        .models
        .iter()
        .filter(|prior| prior.runtime == runtime_name)
        .filter_map(|prior| catalog_model_from_prior(prior, task, false).transpose())
        .collect::<Result<Vec<_>>>()?;
    models.sort_by(|left, right| left.model.cmp(&right.model));
    Ok(RuntimeCatalog {
        runtime: runtime_name.to_string(),
        revision: format!(
            "cursor-unavailable-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(gap.message.as_bytes())
        ),
        advertised_at: gap.observed_at_unix_millis.to_string(),
        models,
    })
}

fn pools_for_constructed_catalogs(
    catalogs: &[RuntimeCatalog],
    primary_runtime: &str,
    primary_pool: RuntimePoolState,
) -> Vec<RuntimePoolState> {
    catalogs
        .iter()
        .map(|runtime_catalog| {
            if runtime_catalog.runtime == primary_runtime {
                RuntimePoolState {
                    runtime: runtime_catalog.runtime.clone(),
                    ..primary_pool.clone()
                }
            } else {
                RuntimePoolState {
                    runtime: runtime_catalog.runtime.clone(),
                    observation_revision: format!(
                        "{}:{}",
                        primary_pool.observation_revision, runtime_catalog.runtime
                    ),
                    pool_pressure_basis_points: 0,
                    failover_provenance: Some(
                        "advertised runtime catalogs participate in selection; launch uses the selected pair"
                            .to_string(),
                    ),
                    ..primary_pool.clone()
                }
            }
        })
        .collect()
}

fn runtime_catalog_from_advertised_slugs<'a>(
    runtime_name: &str,
    advertised_slugs: impl IntoIterator<Item = &'a str>,
    revision: String,
    advertised_at: String,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<RuntimeCatalog> {
    let advertised = advertised_slugs
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let mut models = Vec::new();
    for prior in priors
        .models
        .iter()
        .filter(|prior| prior.runtime == runtime_name)
    {
        if !advertised.contains(&prior.model) {
            continue;
        }
        if let Some(model) = catalog_model_from_prior(prior, task, true)? {
            models.push(model);
        }
    }
    models.sort_by(|left, right| left.model.cmp(&right.model));
    Ok(RuntimeCatalog {
        runtime: runtime_name.to_string(),
        revision,
        advertised_at,
        models,
    })
}

fn catalog_model_from_prior(
    prior: &selection::ModelPrior,
    task: &TaskProfile,
    available: bool,
) -> Result<Option<CatalogModel>> {
    let mut supported_efforts = prior
        .class_fit
        .iter()
        .filter(|class_fit| class_fit.task_class == task.task_class)
        .map(|class_fit| class_fit.effort)
        .chain(
            prior
                .authority_evidence
                .iter()
                .filter(|evidence| {
                    evidence.task_class == task.task_class && evidence.role == task.authority_role
                })
                .map(|evidence| evidence.effort),
        )
        .chain(prior.strong_gate_fallback_efforts.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    supported_efforts.sort();
    if supported_efforts.is_empty() {
        return Ok(None);
    }
    Ok(Some(CatalogModel {
        model: prior.model.clone(),
        available,
        access: None,
        supported_efforts,
        capabilities: capabilities_from_prior(prior, task)?,
    }))
}

pub(super) fn runtime_catalog_from_priors(
    runtime_name: &str,
    catalog: &RuntimeModelCatalog,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<RuntimeCatalog> {
    let mut models = Vec::new();
    for prior in priors
        .models
        .iter()
        .filter(|prior| prior.runtime == runtime_name)
    {
        let available = catalog
            .availability(Some(&prior.model), runtime_from_name(runtime_name)?)?
            == RoleModelAvailability::Available;
        if let Some(model) = catalog_model_from_prior(prior, task, available)? {
            models.push(model);
        }
    }
    models.sort_by(|left, right| left.model.cmp(&right.model));
    let revision_material =
        serde_json::to_vec(&models).context("failed to normalize runtime catalog membership")?;
    Ok(RuntimeCatalog {
        runtime: runtime_name.to_string(),
        revision: format!(
            "prior-backed-membership-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(&revision_material)
        ),
        advertised_at: "live-membership-observation-undated".to_string(),
        models,
    })
}

pub(super) fn task_profile_for_role(role: AgentRole) -> TaskProfile {
    match role {
        AgentRole::Researcher => TaskProfile {
            task_class: JUDGMENT_SELECTION_TASK_CLASS.to_string(),
            risk: RiskLevel::Medium,
            boundedness: Boundedness::Bounded,
            context: ContextSize::Medium,
            horizon: TaskHorizon::Medium,
            authority_role: AuthorityRole::TerminalLeaf,
        },
        AgentRole::Worker => TaskProfile {
            task_class: AUTOMATIC_SELECTION_TASK_CLASS.to_string(),
            risk: RiskLevel::Medium,
            boundedness: Boundedness::Bounded,
            context: ContextSize::Medium,
            horizon: TaskHorizon::Medium,
            authority_role: AuthorityRole::TerminalLeaf,
        },
        AgentRole::ChildOrchestrator => TaskProfile {
            task_class: AUTOMATIC_SELECTION_TASK_CLASS.to_string(),
            risk: RiskLevel::High,
            boundedness: Boundedness::CrossCutting,
            context: ContextSize::Large,
            horizon: TaskHorizon::Long,
            authority_role: AuthorityRole::Delegating,
        },
        AgentRole::Supervisor => judgment_task_profile(AuthorityRole::AcceptanceGate),
        AgentRole::GateClassifier => judgment_task_profile(AuthorityRole::FailureClassification),
        AgentRole::Auditor => judgment_task_profile(AuthorityRole::ReviewAuditor),
    }
}

fn judgment_task_profile(authority_role: AuthorityRole) -> TaskProfile {
    TaskProfile {
        task_class: JUDGMENT_SELECTION_TASK_CLASS.to_string(),
        risk: RiskLevel::Critical,
        boundedness: Boundedness::CrossCutting,
        context: ContextSize::Long,
        horizon: TaskHorizon::Long,
        authority_role,
    }
}

enum ExecutableChoiceResolution<'a> {
    Executable(&'a selection::SelectedChoice),
    PreflightFailure(SupervisorSelectionPreflightFailure),
}

fn selection_refusal_message(decision: &SelectionProvenance, role: AgentRole) -> String {
    let mut message = format!(
        "selector failed closed for role '{}': {}",
        role.as_str(),
        decision.decision_reason
    );
    let input = &decision.normalized_input;
    message.push_str(&selection::runtime_model_policy::missing_model_guidance(
        input,
    ));
    for catalog in &input.catalogs {
        if catalog.models.is_empty()
            && catalog
                .revision
                .starts_with("account-observe-models-unobserved-sha256:")
        {
            message.push_str(&format!(
                "; CAM model/effort metadata is unobserved or unusable for runtime '{}', so no catalog candidates were admitted; completing account login alone does not supply model metadata",
                catalog.runtime
            ));
        }
    }
    let grok_priors = input
        .priors
        .models
        .iter()
        .filter(|prior| prior.runtime == "grok")
        .collect::<Vec<_>>();
    if input
        .catalogs
        .iter()
        .any(|catalog| catalog.runtime == "grok")
        && input.task.authority_role != AuthorityRole::TerminalLeaf
        && !decision
            .candidate_set
            .iter()
            .any(|candidate| candidate.candidate.runtime != "grok")
        && !grok_priors.is_empty()
        && grok_priors.iter().all(|prior| {
            prior.prohibited
                || prior
                    .prohibited_authority_roles
                    .contains(&input.task.authority_role)
        })
    {
        message.push_str(
            "; the loaded Grok priors explicitly prohibit this judgment authority; use --runtime codex for supervision and control roles, with Grok only for qualified direct Worker assignments (see docs/OPERATOR_QUICKSTART.md, Grok runtime)",
        );
    }
    message
}

fn executable_choice<'a>(
    decision: &'a SelectionProvenance,
    runtime: SupervisorRuntime,
    role: AgentRole,
) -> Result<ExecutableChoiceResolution<'a>> {
    if decision.status != DecisionStatus::Selected {
        return Ok(ExecutableChoiceResolution::PreflightFailure(
            SupervisorSelectionPreflightFailure {
                role,
                kind: SupervisorSelectionPreflightFailureKind::FailClosed,
                message: selection_refusal_message(decision, role),
            },
        ));
    }
    let choice = decision.choice.as_ref().with_context(|| {
        format!(
            "selector reported selected status without a choice for role '{}'",
            role.as_str()
        )
    })?;
    if runtime_from_name(&choice.candidate.runtime).is_err() {
        return Ok(ExecutableChoiceResolution::PreflightFailure(
            SupervisorSelectionPreflightFailure {
                role,
                kind: SupervisorSelectionPreflightFailureKind::ActiveRuntimeMismatch,
                message: format!(
                    "selector chose unexecutable runtime '{}' for role '{}' while constructing the assignment-launch binding; run-global runtime was '{}'",
                    choice.candidate.runtime,
                    role.as_str(),
                    runtime_name(runtime)
                ),
            },
        ));
    }
    Ok(ExecutableChoiceResolution::Executable(choice))
}

pub(super) fn bind_selected_assignment_runtimes(
    plan: &mut SupervisorPlan,
    decisions: &[SupervisorSelectionEvent],
) -> Result<()> {
    let mut selected = BTreeMap::new();
    for decision in decisions {
        let Some(choice) = &decision.provenance.choice else {
            continue;
        };
        selected.insert(
            decision.role,
            runtime_from_name(&choice.candidate.runtime).with_context(|| {
                format!(
                    "selector choice for role '{}' used unexecutable runtime '{}'",
                    decision.role.as_str(),
                    choice.candidate.runtime
                )
            })?,
        );
    }
    for assignment in &mut plan.assignments {
        let Some(selected_runtime) = selected.get(&assignment.role).copied() else {
            continue;
        };
        match assignment.runtime {
            Some(existing) if existing != selected_runtime => {
                bail!(
                    "assignment '{}' runtime '{}' contradicts selected runtime '{}' for role '{}'",
                    assignment.id,
                    runtime_name(existing),
                    runtime_name(selected_runtime),
                    assignment.role.as_str()
                );
            }
            Some(_) => {}
            None => assignment.runtime = Some(selected_runtime),
        }
    }
    Ok(())
}

fn role_selection_from_choice(choice: &selection::SelectedChoice) -> RoleModelSelection {
    RoleModelSelection {
        model: Some(choice.candidate.model.clone()),
        reasoning_effort: Some(selector_effort_as_str(choice.candidate.effort).to_string()),
        unavailable_model_fallback: UnavailableModelFallback::FailClosed,
    }
}

pub(super) fn build_assignment_selection_ledger(
    plan: &SupervisorPlan,
    decisions: &[SupervisorSelectionEvent],
    runtime: SupervisorRuntime,
) -> Vec<AssignmentSelectionLedgerEntry> {
    plan.assignments
        .iter()
        .flat_map(|assignment| {
            assignment_ledger_roles(assignment).into_iter().map(|role| {
                ledger_entry_for_assignment(assignment.id.as_str(), role, decisions, runtime, plan)
            })
        })
        .collect()
}

pub(super) fn apply_budget_degradations_to_selection_ledger(
    entries: &mut [AssignmentSelectionLedgerEntry],
    records: &[BudgetDegradationRecord],
) {
    for record in records {
        let Some(transition) = record.role_binding_transition.as_ref() else {
            continue;
        };
        let Some(entry) = entries.iter_mut().find(|entry| {
            entry.assignment_id == record.assignment_id && entry.role == transition.role
        }) else {
            continue;
        };
        if entry.selection_source == AssignmentSelectionSource::Retry {
            continue;
        }
        entry.selection_source = match record.trigger {
            BudgetDegradationTrigger::BudgetPressure => AssignmentSelectionSource::BudgetDegrade,
            BudgetDegradationTrigger::LowDifficultyMechanical => {
                AssignmentSelectionSource::LowDifficultyMechanical
            }
        };
        entry.selected_model = transition.after.model.clone();
        entry.selected_reasoning_effort = transition.after.reasoning_effort.clone();
        entry.catalog_source = AssignmentCatalogSource::RuntimeAdvertised;
        entry.catalog_snapshot_digest = None;
        entry.catalog_revisions.clear();
        entry.rejected_candidates.clear();
        entry.evidence_gap = Some(
            "the budget-degradation record is authoritative for the final Worker binding; selector candidate provenance described the superseded binding and was discarded, and the degradation decision retained no catalog snapshot digest or revisions"
                .to_string(),
        );
    }
}

pub(super) fn write_selection_ledger_from_report(
    writer: &mut crate::artifacts::ArtifactRunWriter,
    report: &SupervisorFinalReport,
) -> Result<()> {
    let Some(execution) = report
        .role_economics_profile
        .as_ref()
        .and_then(|profile| profile.execution.as_ref())
    else {
        return Ok(());
    };
    let ledger = AssignmentSelectionLedger {
        schema_version: ASSIGNMENT_SELECTION_LEDGER_SCHEMA_VERSION,
        entries: execution.assignment_selection_ledger.clone(),
    };
    writer
        .write_json(
            Path::new(SELECTION_LEDGER_RELATIVE),
            &ledger,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .context("failed to persist assignment selection ledger")?;
    write_live_switch_cost_evidence(writer)?;
    Ok(())
}

thread_local! {
    static LIVE_SWITCH_COST_SESSION: RefCell<LiveSwitchCostSession> =
        RefCell::new(LiveSwitchCostSession::default());
}

#[derive(Debug, Clone)]
struct LiveSwitchCostSession {
    config: SupervisorRouterConfig,
    model: SwitchCostModel,
    invocations: Vec<InvocationRecord>,
    trajectory: Vec<String>,
    comparison: Option<EscalationComparison>,
    alarms: Vec<OscillationAlarmEvent>,
}

impl Default for LiveSwitchCostSession {
    fn default() -> Self {
        Self {
            config: SupervisorRouterConfig::default(),
            model: SwitchCostModel::new(),
            invocations: Vec::new(),
            trajectory: Vec::new(),
            comparison: None,
            alarms: Vec::new(),
        }
    }
}

impl LiveSwitchCostSession {
    fn apply_config(&mut self, config: SupervisorRouterConfig) {
        self.config = config;
        self.model = self.model.clone().with_hysteresis(SwitchHysteresis {
            margin_bp: self.config.hysteresis_margin_bp,
        });
    }

    fn observe_record(&mut self, record: InvocationRecord) -> Result<()> {
        record.validate_observation().map_err(|error| {
            anyhow!("live invocation record failed observation validation: {error}")
        })?;
        self.invocations.push(record);
        // Refit the full history once; appending a row must not count every
        // previous observation again.
        self.model = SwitchCostModel::new().with_hysteresis(SwitchHysteresis {
            margin_bp: self.config.hysteresis_margin_bp,
        });
        self.model.observe_invocations(&self.invocations);
        Ok(())
    }

    fn evidence_for(&self, input: &SelectionInput) -> Vec<CandidateSwitchCostEvidence> {
        let previous = input.signals.previous_choice.as_ref();
        let mut evidence = Vec::new();
        for catalog in &input.catalogs {
            for listed in &catalog.models {
                for effort in &listed.supported_efforts {
                    let class = match previous {
                        Some(prev)
                            if prev.runtime == catalog.runtime && prev.model == listed.model =>
                        {
                            TransitionClass::Continue
                        }
                        Some(prev) if prev.runtime == catalog.runtime => {
                            TransitionClass::ModelChangeSameRuntime
                        }
                        Some(_) => TransitionClass::RuntimeAdapterChange,
                        None => TransitionClass::Continue,
                    };
                    evidence.push(CandidateSwitchCostEvidence {
                        candidate: CandidateKey {
                            runtime: catalog.runtime.clone(),
                            model: listed.model.clone(),
                            effort: *effort,
                        },
                        estimate: self.model.estimate(class),
                    });
                }
            }
        }
        evidence
    }

    fn snapshot(&self) -> LiveSwitchCostArtifact {
        LiveSwitchCostArtifact {
            schema_version: LIVE_SWITCH_COST_EVIDENCE_SCHEMA_VERSION,
            router_config: self.config.clone(),
            invocations: self.invocations.clone(),
            router_comparison: self.comparison.clone(),
            oscillation_alarms: self.alarms.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct OscillationAlarmEvent {
    pub sequence: Vec<String>,
    pub oscillation_count: u32,
    pub oscillation_alarm_threshold: u32,
    pub switch_hysteresis_margin_bp: u16,
    pub alarmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct LiveSwitchCostArtifact {
    pub schema_version: u32,
    pub router_config: SupervisorRouterConfig,
    pub invocations: Vec<InvocationRecord>,
    pub router_comparison: Option<EscalationComparison>,
    pub oscillation_alarms: Vec<OscillationAlarmEvent>,
}

fn with_live_switch_cost_session<T>(op: impl FnOnce(&mut LiveSwitchCostSession) -> T) -> T {
    LIVE_SWITCH_COST_SESSION.with(|slot| op(&mut slot.borrow_mut()))
}

pub(crate) fn bind_live_router_config(config: SupervisorRouterConfig) {
    with_live_switch_cost_session(|session| session.apply_config(config));
}

#[cfg(test)]
pub(super) fn reset_live_switch_cost_session() {
    with_live_switch_cost_session(|session| *session = LiveSwitchCostSession::default());
}

#[cfg(test)]
pub(super) fn push_live_router_identity(identity: impl Into<String>) {
    with_live_switch_cost_session(|session| session.trajectory.push(identity.into()));
}

pub(super) fn record_live_invocation(record: InvocationRecord) -> Result<()> {
    with_live_switch_cost_session(|session| session.observe_record(record))
}

pub(super) fn live_switch_cost_artifact() -> LiveSwitchCostArtifact {
    with_live_switch_cost_session(|session| session.snapshot())
}

#[cfg(test)]
pub(super) fn live_fitted_switch_estimate(class: TransitionClass) -> SwitchCostEstimate {
    with_live_switch_cost_session(|session| session.model.estimate(class))
}

pub(super) fn persist_live_switch_cost_snapshot(
    writer: &mut crate::artifacts::ArtifactRunWriter,
) -> Result<()> {
    write_live_switch_cost_evidence(writer)
}

fn write_live_switch_cost_evidence(writer: &mut crate::artifacts::ArtifactRunWriter) -> Result<()> {
    let snapshot = live_switch_cost_artifact();
    if snapshot.invocations.is_empty()
        && snapshot.router_comparison.is_none()
        && snapshot.oscillation_alarms.is_empty()
    {
        return Ok(());
    }
    writer
        .write_json(
            Path::new(LIVE_SWITCH_COST_EVIDENCE_RELATIVE),
            &snapshot,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .context("failed to persist live switch-cost evidence")?;
    Ok(())
}

pub(super) fn persist_live_invocation_row(
    writer: &mut crate::artifacts::ArtifactRunWriter,
    record: &InvocationRecord,
) -> Result<()> {
    writer
        .append_json_line(
            Path::new(LIVE_SWITCH_COST_INVOCATIONS_RELATIVE),
            record,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .context("failed to append live invocation telemetry")?;
    Ok(())
}

pub(super) struct LiveInvocationObservation<'a> {
    pub run_id: &'a str,
    pub assignment_id: &'a str,
    pub attempt: usize,
    pub role: AgentRole,
    pub runtime: SupervisorRuntime,
    pub model: Option<&'a str>,
    pub effort: Option<&'a str>,
    pub worktree_id: &'a str,
    pub usage: Option<&'a Usage>,
    pub duration_ms: Option<u64>,
    pub started_at_unix_millis: u64,
}

pub(super) fn record_supervisor_invocation_observation(
    observation: LiveInvocationObservation<'_>,
) -> Result<InvocationRecord> {
    let invocation_id = format!(
        "{}:{}:{}:{}",
        observation.run_id,
        observation.assignment_id,
        observation.attempt,
        observation.role.as_str()
    );
    let started = TimestampMillis::from_millis(observation.started_at_unix_millis.max(1));
    let mut record = InvocationRecord::new(
        PolicyId::new(format!(
            "supervise:{}:{}",
            observation.assignment_id,
            observation.role.as_str()
        ))
        .map_err(|error| anyhow!("live invocation policy id: {error}"))?,
        CandidateId::new(invocation_id.clone())
            .map_err(|error| anyhow!("live invocation candidate id: {error}"))?,
        started,
        ResourceVector::new().snapshot(started),
    );
    record.finished_at = observation
        .duration_ms
        .and_then(|duration| observation.started_at_unix_millis.checked_add(duration))
        .map(|finished| TimestampMillis::from_millis(finished.max(started.as_millis())));
    record.optimization_run_id = Some(
        OptimizationRunId::new(observation.run_id)
            .map_err(|error| anyhow!("live invocation optimization run id: {error}"))?,
    );
    record.policy_execution_id = Some(
        PolicyExecutionId::new(format!(
            "{}:{}",
            observation.run_id, observation.assignment_id
        ))
        .map_err(|error| anyhow!("live invocation policy execution id: {error}"))?,
    );
    record.invocation_id = Some(
        InvocationId::new(invocation_id).map_err(|error| anyhow!("live invocation id: {error}"))?,
    );
    record.root_decision_id = Some(
        DecisionId::new(format!("{}:root", observation.run_id))
            .map_err(|error| anyhow!("live invocation decision id: {error}"))?,
    );
    record.task_class = Some(if observation.role == AgentRole::Researcher {
        JUDGMENT_SELECTION_TASK_CLASS.to_string()
    } else {
        AUTOMATIC_SELECTION_TASK_CLASS.to_string()
    });
    let backend = backend_id_for_runtime(observation.runtime)?;
    record.backend = Some(backend.clone());
    record.provider = Some(provider_id_for_runtime(observation.runtime)?);
    record.requested_model = observation
        .model
        .filter(|model| !model.trim().is_empty())
        .map(RuntimeSlug::new)
        .transpose()
        .map_err(|error| anyhow!("live invocation model slug: {error}"))?;
    // Command configuration identifies the request, not provider resolution or
    // runtime session identity. Duration measures the whole invocation, not
    // adapter startup. Leave those unobserved fields absent.
    record.worktree_id = Some(observation.worktree_id.to_string());
    record.requested_effort = observation.effort.and_then(canonical_effort_from_label);
    record.role = Some(optimizer_role(observation.role));
    if let Some(usage) = observation.usage {
        record.input_tokens = u64::try_from(usage.input_tokens).ok();
        record.output_tokens = u64::try_from(usage.output_tokens).ok();
        // Cached prefix occupancy is unobservable from Usage; leave None so
        // fitted estimates stay wide/inferred rather than measured-zero.
    }
    record.cost_class = Some(match observation.role {
        AgentRole::Auditor => CostClass::DirectAuditor,
        AgentRole::Worker => CostClass::DirectWorker,
        AgentRole::GateClassifier => CostClass::DirectPlanner,
        AgentRole::Researcher => CostClass::DirectPlanner,
        AgentRole::ChildOrchestrator | AgentRole::Supervisor => CostClass::DirectPlanner,
    });
    record_live_invocation(record.clone())?;
    Ok(record)
}

#[cfg(test)]
pub(super) fn route_live_four_arm_for_test(input: &SelectionInput) -> Result<()> {
    route_live_four_arm_comparison(input)
}

fn route_live_four_arm_comparison(input: &SelectionInput) -> Result<()> {
    let candidates = live_router_candidates(input)?;
    if candidates.len() < 2 {
        return Ok(());
    }
    let (config, model, trajectory) = with_live_switch_cost_session(|session| {
        (
            session.config.clone(),
            session.model.clone(),
            session.trajectory.clone(),
        )
    });
    let mut state = live_router_state(input, &trajectory)?;
    let router = SafeContextualRouter::new(
        Box::new(HierarchicalPolicyPredictor::new()),
        Box::new(TailRiskObjective::new()),
        RouterConfig {
            oscillation_alarm_threshold: config.oscillation_alarm_threshold,
            apply_inferred_switch_priors: false,
            ..RouterConfig::default()
        },
    )
    .with_switch_costs(model.with_hysteresis(SwitchHysteresis {
        margin_bp: config.hysteresis_margin_bp,
    }));
    let decision = CheckpointRouter::new(router)
        .reoptimize(&mut state, &candidates)
        .map_err(|error| anyhow!("online router reoptimize failed: {error}"))?;
    let comparison = decision
        .escalation
        .clone()
        .ok_or_else(|| anyhow!("online router omitted the four-arm comparison"))?;
    let diagnostics = decision.router.diagnostics();
    let alarmed = diagnostics.oscillation_alarm.unwrap_or(false);
    let alarm = OscillationAlarmEvent {
        sequence: trajectory,
        oscillation_count: diagnostics.oscillation_count.unwrap_or(0),
        oscillation_alarm_threshold: diagnostics
            .oscillation_alarm_threshold
            .unwrap_or(config.oscillation_alarm_threshold),
        switch_hysteresis_margin_bp: diagnostics
            .switch_hysteresis_margin_bp
            .unwrap_or(config.hysteresis_margin_bp),
        alarmed,
    };
    with_live_switch_cost_session(|session| {
        if let Some(selected) = decision.router.selected_policy() {
            session.trajectory.push(selected.as_str().to_string());
        }
        session.comparison = Some(comparison);
        if alarm.alarmed {
            session.alarms.push(alarm);
        }
    });
    Ok(())
}

fn live_router_state(input: &SelectionInput, trajectory: &[String]) -> Result<OptimizerState> {
    let now = TimestampMillis::from_millis(1_000);
    let mut state = OptimizerState::new(DecisionHorizon {
        now,
        deadline: Some(TimestampMillis::from_millis(1_000 + 3_600_000)),
        next_reset: None,
    });
    set_feature_bool(
        &mut state.task_features,
        feature_keys::VERIFIER_AVAILABLE,
        true,
    )?;
    set_feature_bool(
        &mut state.task_features,
        feature_keys::MODEL_AVAILABLE,
        true,
    )?;
    set_feature_bool(&mut state.task_features, feature_keys::BACKEND_OK, true)?;
    set_feature_bool(&mut state.task_features, feature_keys::CONTAINMENT_OK, true)?;
    set_feature_text(
        &mut state.task_features,
        feature_keys::TASK_CLASS,
        &input.task.task_class,
    )?;
    if let Some(previous) = input.signals.previous_choice.as_ref() {
        set_feature_text(
            &mut state.task_features,
            feature_keys::CURRENT_POLICY,
            &policy_id_for_candidate(previous),
        )?;
    } else if let Some(first) = trajectory.first() {
        set_feature_text(
            &mut state.task_features,
            feature_keys::CURRENT_POLICY,
            first,
        )?;
    }
    let node = PolicyNodeId::new("start")
        .map_err(|error| anyhow!("live router trajectory node: {error}"))?;
    for (index, identity) in trajectory.iter().enumerate() {
        let policy_id = PolicyId::new(identity.clone())
            .map_err(|error| anyhow!("live router trajectory policy: {error}"))?;
        state.trajectory.push(TrajectoryEvent {
            at: TimestampMillis::from_millis(now.as_millis().saturating_add(index as u64 + 1)),
            policy_id,
            node_id: node.clone(),
            observation: TrajectoryObservation::Progress,
            features: TaskFeatures::new(),
        });
    }
    Ok(state)
}

fn live_router_candidates(input: &SelectionInput) -> Result<Vec<PolicyGraph>> {
    let previous = input.signals.previous_choice.as_ref();
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    let mut repair_source = None;
    for catalog in &input.catalogs {
        for listed in &catalog.models {
            for effort in &listed.supported_efforts {
                let key = CandidateKey {
                    runtime: catalog.runtime.clone(),
                    model: listed.model.clone(),
                    effort: *effort,
                };
                let policy_id = policy_id_for_candidate(&key);
                if !seen.insert(policy_id.clone()) {
                    continue;
                }
                let is_continue = previous == Some(&key);
                if repair_source.is_none() && previous.is_some() && !is_continue {
                    repair_source = Some(key.clone());
                }
                candidates.push(live_policy_graph(
                    &policy_id,
                    PolicyNode::Execute(live_model_action(&key, OptimizerRole::Worker)?),
                    RestartMode::Continuation,
                )?);
                if candidates.len() >= 7 {
                    break;
                }
            }
        }
    }
    if let Some(repair) = repair_source {
        candidates.push(live_policy_graph(
            &format!("repair:{}", policy_id_for_candidate(&repair)),
            PolicyNode::Repair(live_model_action(&repair, OptimizerRole::Repairer)?),
            RestartMode::Continuation,
        )?);
    }
    Ok(candidates)
}

fn live_policy_graph(
    policy_id: &str,
    node: PolicyNode,
    restart: RestartMode,
) -> Result<PolicyGraph> {
    let start =
        PolicyNodeId::new("start").map_err(|error| anyhow!("live router policy node: {error}"))?;
    let mut graph = PolicyGraph::new(
        PolicyId::new(policy_id).map_err(|error| anyhow!("live router policy id: {error}"))?,
        1,
        start.clone(),
        TopologySpec {
            planner: PlannerTopology::Single,
            workers: WorkerTopology::One,
            hedge: HedgeTopology::None,
            review: ReviewTopology::Independent,
            restart,
        },
    );
    graph
        .insert_node(start, node)
        .map_err(|error| anyhow!("live router policy graph: {error}"))?;
    Ok(graph)
}

fn live_model_action(candidate: &CandidateKey, role: OptimizerRole) -> Result<ModelAction> {
    let backend = backend_id_for_runtime_name(&candidate.runtime)?;
    let provider = provider_id_for_runtime_name(&candidate.runtime)?;
    let slug = RuntimeSlug::new(candidate.model.clone())
        .map_err(|error| anyhow!("live router model slug: {error}"))?;
    Ok(ModelAction {
        backend_id: backend.clone(),
        provider_id: provider.clone(),
        runtime_model: RuntimeModelId {
            provider,
            backend,
            model_family: ModelFamilyId::new("live")
                .map_err(|error| anyhow!("live router model family: {error}"))?,
            runtime_slug: slug.clone(),
            catalog_version: CatalogVersion::new("v1")
                .map_err(|error| anyhow!("live router catalog version: {error}"))?,
            observation_timestamp: TimestampMillis::from_millis(1),
        },
        requested_slug: slug,
        effort: selector_effort_to_canonical(candidate.effort),
        role,
        max_turns: ExecutionBudget::default().max_turns,
        timeout_seconds: 60,
        tool_budget: None,
        output_token_budget: None,
        concurrency: 1,
        verifier_profile: VerifierProfileId::new("default")
            .map_err(|error| anyhow!("live router verifier: {error}"))?,
    })
}

fn policy_id_for_candidate(candidate: &CandidateKey) -> String {
    format!(
        "{}:{}:{}",
        candidate.runtime,
        candidate.model,
        selector_effort_label(candidate.effort)
    )
}

fn selector_effort_label(effort: SelectorEffort) -> &'static str {
    match effort {
        SelectorEffort::None => "none",
        SelectorEffort::Minimal => "minimal",
        SelectorEffort::Low => "low",
        SelectorEffort::Medium => "medium",
        SelectorEffort::High => "high",
        SelectorEffort::Xhigh => "xhigh",
        SelectorEffort::Max => "max",
        SelectorEffort::Ultra => "ultra",
    }
}

fn selector_effort_to_canonical(effort: SelectorEffort) -> CanonicalEffort {
    match effort {
        SelectorEffort::None => CanonicalEffort::ProviderNative("none".to_string()),
        SelectorEffort::Minimal => CanonicalEffort::Minimal,
        SelectorEffort::Low => CanonicalEffort::Low,
        SelectorEffort::Medium => CanonicalEffort::Medium,
        SelectorEffort::High => CanonicalEffort::High,
        SelectorEffort::Xhigh => CanonicalEffort::XHigh,
        SelectorEffort::Max => CanonicalEffort::Max,
        SelectorEffort::Ultra => CanonicalEffort::ProviderNative("ultra".to_string()),
    }
}

fn canonical_effort_from_label(label: &str) -> Option<CanonicalEffort> {
    Some(match label {
        "none" => CanonicalEffort::ProviderNative("none".to_string()),
        "minimal" => CanonicalEffort::Minimal,
        "low" => CanonicalEffort::Low,
        "medium" => CanonicalEffort::Medium,
        "high" => CanonicalEffort::High,
        "xhigh" => CanonicalEffort::XHigh,
        "max" => CanonicalEffort::Max,
        _ => return None,
    })
}

fn optimizer_role(role: AgentRole) -> OptimizerRole {
    match role {
        AgentRole::Supervisor => OptimizerRole::Supervisor,
        AgentRole::ChildOrchestrator => OptimizerRole::ChildOrchestrator,
        AgentRole::Worker => OptimizerRole::Worker,
        AgentRole::Researcher => OptimizerRole::Researcher,
        AgentRole::GateClassifier => OptimizerRole::GateClassifier,
        AgentRole::Auditor => OptimizerRole::Auditor,
    }
}

fn backend_id_for_runtime(runtime: SupervisorRuntime) -> Result<BackendId> {
    backend_id_for_runtime_name(runtime_name(runtime))
}

fn backend_id_for_runtime_name(runtime: &str) -> Result<BackendId> {
    let name = match runtime {
        "codex" => BackendId::CODEX_CLI,
        "cursor" => BackendId::CURSOR_AGENT,
        "grok" => BackendId::GROK_BUILD_CLI,
        "fake" => BackendId::FAKE_PROVIDER,
        other => other,
    };
    BackendId::new(name).or_else(|_| Ok(BackendId::well_known(BackendId::FAKE_PROVIDER)))
}

fn provider_id_for_runtime(runtime: SupervisorRuntime) -> Result<ProviderId> {
    provider_id_for_runtime_name(runtime_name(runtime))
}

fn provider_id_for_runtime_name(runtime: &str) -> Result<ProviderId> {
    let name = match runtime {
        "codex" => "openai",
        "cursor" => "cursor",
        "grok" => "xai",
        other => other,
    };
    ProviderId::new(name).map_err(|error| anyhow!("live invocation provider id: {error}"))
}

fn set_feature_bool(features: &mut TaskFeatures, key: &str, value: bool) -> Result<()> {
    let id = FeatureId::new(key).map_err(|error| anyhow!("optimizer feature {key}: {error}"))?;
    features.insert(id, FeatureValue::Boolean(value));
    Ok(())
}

fn set_feature_text(features: &mut TaskFeatures, key: &str, value: &str) -> Result<()> {
    let id = FeatureId::new(key).map_err(|error| anyhow!("optimizer feature {key}: {error}"))?;
    features.insert(id, FeatureValue::Text(value.to_string()));
    Ok(())
}

fn assignment_ledger_roles(assignment: &OrchestratorAssignment) -> Vec<AgentRole> {
    let mut roles = vec![
        assignment.role,
        AgentRole::GateClassifier,
        AgentRole::Auditor,
    ];
    roles.extend(
        assignment
            .worker_assignments
            .iter()
            .map(|worker| worker.role),
    );
    let mut seen = BTreeSet::new();
    roles.retain(|role| seen.insert(*role));
    roles
}

fn decision_for_assignment_role<'a>(
    decisions: &'a [SupervisorSelectionEvent],
    assignment_id: &str,
    role: AgentRole,
) -> Option<&'a SupervisorSelectionEvent> {
    decisions.iter().rev().find(|event| {
        event.role == role
            && event
                .assignment_id
                .as_deref()
                .is_none_or(|id| id == assignment_id)
    })
}

fn recorded_role_assignment(
    assignment_id: &str,
    role: AgentRole,
    plan: &SupervisorPlan,
) -> Option<RoleAssignmentRecord> {
    let category_override = category_override_from_plan(plan, assignment_id, role);
    let provenance = if category_override.is_some() {
        RoleAssignmentProvenance::operator_override()
    } else {
        RoleAssignmentProvenance::granted_by("supervisor")
    };
    assign_role_category_with_provenance(assignment_id, role, category_override, provenance).ok()
}

fn category_override_from_plan(
    plan: &SupervisorPlan,
    assignment_id: &str,
    role: AgentRole,
) -> Option<RoleCategory> {
    let assignment = plan
        .assignments
        .iter()
        .find(|assignment| assignment.id == assignment_id)?;
    if role == AgentRole::Worker {
        return assignment
            .worker_assignments
            .iter()
            .find(|worker| worker.role == AgentRole::Worker)
            .and_then(WorkerAssignment::category_override);
    }
    assignment.category_override()
}

fn ledger_entry_for_assignment(
    assignment_id: &str,
    role: AgentRole,
    decisions: &[SupervisorSelectionEvent],
    runtime: SupervisorRuntime,
    plan: &SupervisorPlan,
) -> AssignmentSelectionLedgerEntry {
    let event = decision_for_assignment_role(decisions, assignment_id, role);
    let role_assignment = recorded_role_assignment(assignment_id, role, plan);
    let source = selection_source_for(
        event,
        runtime,
        role_assignment
            .as_ref()
            .is_some_and(|record| record.source == RoleAssignmentSource::OperatorOverride),
    );
    if source == AssignmentSelectionSource::LegacyFake {
        let configured = plan.role_models.get(&role);
        return AssignmentSelectionLedgerEntry {
            assignment_id: assignment_id.to_string(),
            attempt: event.map(|event| event.attempt).unwrap_or(0),
            role,
            role_assignment,
            selection_source: source,
            selected_runtime: Some(runtime_name(runtime).to_string()),
            selected_model: configured.and_then(|selection| selection.model.clone()),
            selected_reasoning_effort: configured
                .and_then(|selection| selection.reasoning_effort.clone()),
            catalog_source: AssignmentCatalogSource::None,
            catalog_snapshot_digest: None,
            catalog_revisions: Vec::new(),
            rejected_candidates: Vec::new(),
            quota_evidence: None,
            evidence_gap: Some(
                "legacy fake runtime does not consult a catalog or record eligibility evidence"
                    .to_string(),
            ),
        };
    }

    let Some(event) = event else {
        return AssignmentSelectionLedgerEntry {
            assignment_id: assignment_id.to_string(),
            attempt: 0,
            role,
            role_assignment,
            selection_source: source,
            selected_runtime: Some(runtime_name(runtime).to_string()),
            selected_model: None,
            selected_reasoning_effort: None,
            catalog_source: AssignmentCatalogSource::None,
            catalog_snapshot_digest: None,
            catalog_revisions: Vec::new(),
            rejected_candidates: Vec::new(),
            quota_evidence: None,
            evidence_gap: Some(
                "no selector decision was recorded for this assignment role".to_string(),
            ),
        };
    };

    let choice = event.provenance.choice.as_ref();
    let mut rejected_candidates: Vec<AssignmentRejectedCandidate> = event
        .provenance
        .candidate_set
        .iter()
        .filter(|candidate| choice.is_none_or(|choice| choice.candidate != candidate.candidate))
        .map(rejected_candidate_from_evaluation)
        .collect();
    if rejected_candidates.is_empty() {
        rejected_candidates.extend(event.provenance.runner_up_scores.iter().map(|ranked| {
            AssignmentRejectedCandidate {
                runtime: ranked.candidate.runtime.clone(),
                model: ranked.candidate.model.clone(),
                effort: selector_effort_as_str(ranked.candidate.effort).to_string(),
                reasons: vec![AssignmentRejectionReason {
                    code: "runner_up".to_string(),
                    detail: format!(
                        "candidate ranked {} with {} microunits and was not selected",
                        ranked.rank, ranked.total_score_microunits
                    ),
                }],
            }
        }));
    }
    if rejected_candidates.is_empty() {
        rejected_candidates.push(AssignmentRejectedCandidate {
            runtime: choice
                .map(|choice| choice.candidate.runtime.clone())
                .unwrap_or_else(|| runtime_name(runtime).to_string()),
            model: "unselected-alternate".to_string(),
            effort: "high".to_string(),
            reasons: vec![AssignmentRejectionReason {
                code: "no_alternate_recorded".to_string(),
                detail: "selector candidate set contained only the selected choice".to_string(),
            }],
        });
    }
    let evidence_gap = if event.provenance.status == DecisionStatus::FailClosed {
        Some(
            event
                .provenance
                .decision_reason
                .clone()
                .if_empty_then("selector failed closed without a recorded choice"),
        )
    } else if choice.is_none() {
        Some("selector recorded no executable choice".to_string())
    } else {
        cursor_catalog_evidence_gap_for_ledger(&event.provenance)
    };
    let quota_evidence = match choice {
        Some(choice) => event
            .provenance
            .normalized_input
            .pools
            .iter()
            .find(|pool| pool.runtime == choice.candidate.runtime)
            .filter(|pool| pool.pool_reference.is_some())
            .cloned(),
        None => event.provenance.quota.as_ref().and_then(|quota| {
            event
                .provenance
                .normalized_input
                .pools
                .iter()
                .find(|pool| pool.pool_reference.as_ref() == Some(&quota.source_pool))
                .cloned()
        }),
    };

    AssignmentSelectionLedgerEntry {
        assignment_id: assignment_id.to_string(),
        attempt: event.attempt,
        role,
        role_assignment,
        selection_source: source,
        selected_runtime: choice.map(|choice| choice.candidate.runtime.clone()),
        selected_model: choice.map(|choice| choice.candidate.model.clone()),
        selected_reasoning_effort: choice
            .map(|choice| selector_effort_as_str(choice.candidate.effort).to_string()),
        catalog_source: if event.provenance.catalog_revisions.is_empty() {
            AssignmentCatalogSource::None
        } else {
            AssignmentCatalogSource::RuntimeAdvertised
        },
        catalog_snapshot_digest: Some(event.provenance.input_digests.catalogs.value.clone())
            .filter(|digest| !digest.is_empty()),
        catalog_revisions: event.provenance.catalog_revisions.clone(),
        rejected_candidates,
        quota_evidence,
        evidence_gap,
    }
}

fn cursor_catalog_evidence_gap_for_ledger(provenance: &SelectionProvenance) -> Option<String> {
    let unavailable_revision = provenance.catalog_revisions.iter().find(|revision| {
        revision.runtime == "cursor" && revision.revision.starts_with("cursor-unavailable-sha256:")
    })?;
    Some(format!(
        "optional Cursor runtime model catalog evidence was unavailable at observation {}; catalog gap is content-bound by revision '{}'",
        unavailable_revision.advertised_at, unavailable_revision.revision
    ))
}

fn selection_source_for(
    event: Option<&SupervisorSelectionEvent>,
    runtime: SupervisorRuntime,
    operator_category_override: bool,
) -> AssignmentSelectionSource {
    if runtime == SupervisorRuntime::Fake {
        return AssignmentSelectionSource::LegacyFake;
    }
    match event.map(|event| event.primary_cause) {
        Some(SupervisorSelectionEventCause::Initial) if operator_category_override => {
            AssignmentSelectionSource::OperatorOverride
        }
        Some(SupervisorSelectionEventCause::Initial) => AssignmentSelectionSource::Automatic,
        Some(SupervisorSelectionEventCause::DebugOverride) => {
            AssignmentSelectionSource::PlanRoleModels
        }
        Some(SupervisorSelectionEventCause::BudgetDegrade) => {
            AssignmentSelectionSource::BudgetDegrade
        }
        Some(SupervisorSelectionEventCause::Retry) => AssignmentSelectionSource::Retry,
        None if operator_category_override => AssignmentSelectionSource::OperatorOverride,
        None => AssignmentSelectionSource::Automatic,
    }
}

fn rejected_candidate_from_evaluation(
    candidate: &selection::CandidateEvaluation,
) -> AssignmentRejectedCandidate {
    let reasons = if candidate.ineligibility_reasons.is_empty() {
        vec![AssignmentRejectionReason {
            code: "not_selected".to_string(),
            detail: "candidate remained eligible but was not the selected choice".to_string(),
        }]
    } else {
        candidate
            .ineligibility_reasons
            .iter()
            .map(|reason| AssignmentRejectionReason {
                code: ineligibility_code_as_str(reason.code.clone()).to_string(),
                detail: reason.detail.clone(),
            })
            .collect()
    };
    AssignmentRejectedCandidate {
        runtime: candidate.candidate.runtime.clone(),
        model: candidate.candidate.model.clone(),
        effort: selector_effort_as_str(candidate.candidate.effort).to_string(),
        reasons,
    }
}

fn ineligibility_code_as_str(code: selection::IneligibilityCode) -> &'static str {
    match code {
        selection::IneligibilityCode::CatalogUnavailable => "catalog_unavailable",
        selection::IneligibilityCode::OperatorConstraint => "operator_constraint",
        selection::IneligibilityCode::RuntimeAdmissionClosed => "runtime_admission_closed",
        selection::IneligibilityCode::EntitlementExhausted => "entitlement_exhausted",
        selection::IneligibilityCode::QuotaFailClosed => "quota_fail_closed",
        selection::IneligibilityCode::QuotaAlternativeNotAuthorized => {
            "quota_alternative_not_authorized"
        }
        selection::IneligibilityCode::TaskClassNotAdvertised => "task_class_not_advertised",
        selection::IneligibilityCode::TaskShapeNotAdvertised => "task_shape_not_advertised",
        selection::IneligibilityCode::AuthorityNotAdvertised => "authority_not_advertised",
        selection::IneligibilityCode::PolicyProhibited => "policy_prohibited",
        selection::IneligibilityCode::LongContextProhibited => "long_context_prohibited",
        selection::IneligibilityCode::MissingDatedPrior => "missing_dated_prior",
        selection::IneligibilityCode::MissingClassFitEvidence => "missing_class_fit_evidence",
        selection::IneligibilityCode::ClassFitEvidenceInsufficient => {
            "class_fit_evidence_insufficient"
        }
        selection::IneligibilityCode::QualityBarNotMet => "quality_bar_not_met",
        selection::IneligibilityCode::MissingAuthorityEvidence => "missing_authority_evidence",
        selection::IneligibilityCode::AuthorityEvidenceInsufficient => {
            "authority_evidence_insufficient"
        }
        selection::IneligibilityCode::AuthorityQualityBarNotMet => "authority_quality_bar_not_met",
        selection::IneligibilityCode::UnknownJudgmentAuthority => "unknown_judgment_authority",
        selection::IneligibilityCode::EnvironmentRejected => "environment_rejected",
    }
}

trait IfEmptyThen {
    fn if_empty_then(self, fallback: &str) -> String;
}

impl IfEmptyThen for String {
    fn if_empty_then(self, fallback: &str) -> String {
        if self.trim().is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}

pub(super) fn runtime_name(runtime: SupervisorRuntime) -> &'static str {
    runtime.as_str()
}

pub(super) fn runtime_from_name(runtime: &str) -> Result<SupervisorRuntime> {
    match runtime {
        "codex" => Ok(SupervisorRuntime::Codex),
        "fake" => Ok(SupervisorRuntime::Fake),
        "grok" => Ok(SupervisorRuntime::Grok),
        "cursor" => Ok(SupervisorRuntime::Cursor),
        "claude-code" | "claude" => Ok(SupervisorRuntime::ClaudeCode),
        "gemini-cli" | "gemini" => Ok(SupervisorRuntime::GeminiCli),
        _ => bail!("selector runtime '{runtime}' is not executable by the supervisor"),
    }
}

fn selector_effort_from_str(value: &str) -> Option<SelectorEffort> {
    match value {
        "none" => Some(SelectorEffort::None),
        "minimal" => Some(SelectorEffort::Minimal),
        "low" => Some(SelectorEffort::Low),
        "medium" => Some(SelectorEffort::Medium),
        "high" => Some(SelectorEffort::High),
        "xhigh" => Some(SelectorEffort::Xhigh),
        "max" => Some(SelectorEffort::Max),
        "ultra" => Some(SelectorEffort::Ultra),
        _ => None,
    }
}

pub(super) fn selector_effort_as_str(effort: SelectorEffort) -> &'static str {
    match effort {
        SelectorEffort::None => "none",
        SelectorEffort::Minimal => "minimal",
        SelectorEffort::Low => "low",
        SelectorEffort::Medium => "medium",
        SelectorEffort::High => "high",
        SelectorEffort::Xhigh => "xhigh",
        SelectorEffort::Max => "max",
        SelectorEffort::Ultra => "ultra",
    }
}

#[cfg(test)]
pub(super) mod tests {
    #[cfg(target_os = "linux")]
    use super::super::environment_observation::environment_cost_microunits_from_account_observe;
    use super::*;
    include!("assignment_selection_tests.rs");
    #[cfg(target_os = "linux")]
    use coding_agent_manager_lib::account_authority::{
        CategoryObservation, ObservationError, ObservationErrorKind, SelectedAccountBinding,
    };

    fn default_resolved_profile() -> ResolvedObjectiveProfile {
        ResolvedObjectiveProfile {
            profile: crate::objective_profile::default_objective_profile()
                .binding()
                .expect("default objective profile binding"),
            source: crate::objective_profile::ObjectiveProfileSource::BuiltIn,
        }
    }

    pub(in crate::supervise) fn bind_fixture_routing_policy(
    ) -> Result<crate::selection::routing_policy::RoutingPolicyGuard> {
        use crate::selection::routing_policy::{
            bind_routing_policy, FrozenRoutingPolicy, LoadedRoutingPolicy,
        };
        let policy: LoadedRoutingPolicy =
            serde_json::from_str(include_str!("../selection/data/routing-policy.json"))?;
        policy.validate()?;
        let frozen = FrozenRoutingPolicy {
            sha256: crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&policy)?),
            policy,
            source: "bundled-selection-fixture-policy".to_string(),
        };
        bind_routing_policy(Some(frozen))
    }

    fn fixture_task_assessment(
        plan: &SupervisorPlan,
    ) -> Result<(
        TaskRoutingAssessment,
        crate::selection::routing_policy::TaskRoutingFeatures,
        crate::selection::routing_policy::FrozenRoutingPolicy,
    )> {
        let frozen = crate::selection::routing_policy::current_routing_policy().context(
            "selection fixture requires a policy guard held through all follow-up checks",
        )?;
        let (assessment, features) = fixture_task_assessment_for_policy(plan, &frozen)?;
        Ok((assessment, features, frozen))
    }

    pub(in crate::supervise) fn frozen_preflight_fixture(
        plan: &SupervisorPlan,
    ) -> Result<selection_preflight::FrozenSupervisorSelectionInputs> {
        let (assessment, features, policy) = fixture_task_assessment(plan)?;
        let mut roles = BTreeMap::new();
        for role in required_selector_roles(plan) {
            let input = selection_input_for_role_with_assessment_and_accounts(
                SelectionInputForRoleArgs {
                    role,
                    runtime: SupervisorRuntime::Codex,
                    catalog: &codex_catalog()?,
                    advertised: &AdvertisedCatalogSet::empty(),
                    admission: &test_admission(),
                    resolved_objective_profile: &default_resolved_profile(),
                    quota_context: None,
                    quota_ledger: None,
                    account_observation: None,
                    history: None,
                    debug_override: plan
                        .role_models
                        .get(&role)
                        .map(|value| debug_override_for_role(role, SupervisorRuntime::Codex, value))
                        .transpose()?,
                    signals: DynamicSignals {
                        retry_count: 0,
                        budget_signal: BudgetSignal::Continue,
                        previous_choice: None,
                        previous_catalog_digest: None,
                        environment_rejections: Vec::new(),
                        accepted_task_cost_context: None,
                        accepted_task_cost_observations: Vec::new(),
                    },
                },
                &[],
                Some(&assessment),
                Some(&features),
                Some(&policy),
            )?;
            roles.insert(
                role,
                selection_preflight::freeze_role_input(
                    input,
                    Some(crate::selection::routing_policy::RoutingPolicyReceipt {
                        frozen: policy.clone(),
                        role: role.as_str().to_string(),
                        features: features.clone(),
                    }),
                ),
            );
        }
        Ok(selection_preflight::FrozenSupervisorSelectionInputs {
            schema_version: 1,
            plan_sha256: selection_preflight::plan_digest(plan)?,
            roles,
            unavailable: BTreeMap::new(),
        })
    }

    pub(in crate::supervise) fn initialize_preflight_fixture(
        plan: &mut SupervisorPlan,
    ) -> Result<SupervisorSelectionResolution> {
        initialize_supervisor_selection(
            plan,
            SupervisorRuntime::Codex,
            &codex_catalog()?,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )
    }

    fn fixture_task_assessment_for_policy(
        plan: &SupervisorPlan,
        frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
    ) -> Result<(
        TaskRoutingAssessment,
        crate::selection::routing_policy::TaskRoutingFeatures,
    )> {
        let mut paths = BTreeSet::new();
        let mut symbols = BTreeSet::new();
        let mut modules = BTreeSet::new();
        let mut dependencies = BTreeSet::new();
        for assignment in &plan.assignments {
            dependencies.extend(
                assignment
                    .decision_refs
                    .iter()
                    .map(|reference| reference.question_key().to_owned()),
            );
            if assignment.worker_assignments.is_empty() {
                paths.extend(assignment.assigned_paths.iter().cloned());
                symbols.extend(assignment.semantic_symbols.iter().cloned());
                modules.extend(assignment.semantic_modules.iter().cloned());
            } else {
                for worker in &assignment.worker_assignments {
                    paths.extend(worker.assigned_paths.iter().cloned());
                    symbols.extend(worker.semantic_symbols.iter().cloned());
                    modules.extend(worker.semantic_modules.iter().cloned());
                }
            }
        }
        // These selector fixtures declare one bounded task over their real scope union.
        // Repeated ledger subjects do not assert independent ownership or execution.
        // The production estimator validates that declaration; final-plan topology is
        // recounted separately. No score, account fact or launch authority is invented.
        let proposal: crate::planning::TaskDecompositionProposal = serde_json::from_value(json!({
            "fragments":[{"id":"selection-fixture", "text": &plan.task}],
            "assignments":[{"id":"selection-fixture", "task": &plan.task,
                "fragment_ids":["selection-fixture"], "assigned_paths":paths,
                "semantic_symbols":symbols, "semantic_modules":modules,
                "decision_dependencies":dependencies}],
            "diagnostics":{"degraded":false, "notes":[]},
            "disjointness":{"disjoint":true, "conflicts":[]}
        }))?;
        let assessment =
            super::super::task_routing::assess_task_routing(&plan.task, &proposal, frozen)?;
        let features = routing_features_with_assessment(plan, Some(&assessment), Some(frozen))?;
        Ok((assessment, features))
    }

    #[cfg(target_os = "linux")]
    fn select_normal_account_intake_with_history(
        plan: &SupervisorPlan,
        frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
        observations: &[(SupervisorRuntime, AccountObserveResult)],
        admission: &SupervisorAdmissionPolicyInput,
        objective: &ResolvedObjectiveProfile,
        history: Option<&FrozenOutcomeHistory>,
    ) -> Result<(
        Option<crate::selection::routing_policy::SelectedLaunchRequest>,
        SelectionProvenance,
    )> {
        // Assess under the caller's exact policy. The production entry point binds
        // that policy for projection, then restores the caller's ambient binding.
        let (assessment, _) = fixture_task_assessment_for_policy(plan, frozen)?;
        super::select_normal_account_intake_with_assessment(
            plan,
            frozen,
            observations,
            admission,
            objective,
            history,
            Some(&assessment),
        )
    }

    #[cfg(target_os = "linux")]
    fn select_account_intake_for_role_with_history(
        plan: &SupervisorPlan,
        frozen: &crate::selection::routing_policy::FrozenRoutingPolicy,
        observations: &[(SupervisorRuntime, AccountObserveResult)],
        admission: &SupervisorAdmissionPolicyInput,
        objective: &ResolvedObjectiveProfile,
        history: Option<&FrozenOutcomeHistory>,
        role: AgentRole,
    ) -> Result<(
        Option<crate::selection::routing_policy::SelectedLaunchRequest>,
        SelectionProvenance,
    )> {
        let (assessment, _) = fixture_task_assessment_for_policy(plan, frozen)?;
        super::select_account_intake_for_role_with_assessment(
            plan,
            frozen,
            observations,
            admission,
            objective,
            history,
            role,
            Some(&assessment),
        )
    }

    fn initialize_supervisor_selection_with_profile(
        plan: &mut SupervisorPlan,
        runtime: SupervisorRuntime,
        catalog: &RuntimeModelCatalog,
        admission: &SupervisorAdmissionPolicyInput,
        advertised: &AdvertisedCatalogSet,
        resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
    ) -> Result<SupervisorSelectionResolution> {
        initialize_supervisor_selection_with_quota(
            plan,
            runtime,
            catalog,
            admission,
            advertised,
            resolved_objective_profile,
            SupervisorQuotaSelectionInput::default(),
        )
    }

    fn initialize_supervisor_selection_with_quota(
        plan: &mut SupervisorPlan,
        runtime: SupervisorRuntime,
        catalog: &RuntimeModelCatalog,
        admission: &SupervisorAdmissionPolicyInput,
        advertised: &AdvertisedCatalogSet,
        resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
        quota: SupervisorQuotaSelectionInput<'_>,
    ) -> Result<SupervisorSelectionResolution> {
        initialize_supervisor_selection_with_history(
            plan,
            runtime,
            catalog,
            admission,
            advertised,
            resolved_objective_profile,
            quota,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn initialize_supervisor_selection_with_history(
        plan: &mut SupervisorPlan,
        runtime: SupervisorRuntime,
        catalog: &RuntimeModelCatalog,
        admission: &SupervisorAdmissionPolicyInput,
        advertised: &AdvertisedCatalogSet,
        resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
        quota: SupervisorQuotaSelectionInput<'_>,
        history: Option<&FrozenOutcomeHistory>,
        account_observation: Option<&AccountObserveResult>,
    ) -> Result<SupervisorSelectionResolution> {
        let accounts = account_observation
            .map(|observation| vec![(runtime, observation.clone())])
            .unwrap_or_default();
        initialize_supervisor_selection_with_accounts(
            plan,
            runtime,
            catalog,
            admission,
            advertised,
            resolved_objective_profile,
            quota,
            history,
            &accounts,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn initialize_supervisor_selection_with_accounts(
        plan: &mut SupervisorPlan,
        runtime: SupervisorRuntime,
        catalog: &RuntimeModelCatalog,
        admission: &SupervisorAdmissionPolicyInput,
        advertised: &AdvertisedCatalogSet,
        resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
        quota: SupervisorQuotaSelectionInput<'_>,
        history: Option<&FrozenOutcomeHistory>,
        account_observations: &[(SupervisorRuntime, AccountObserveResult)],
    ) -> Result<SupervisorSelectionResolution> {
        let (assessment, _, _) = fixture_task_assessment(plan)?;
        super::initialize_supervisor_selection_with_assessment(
            plan,
            runtime,
            catalog,
            admission,
            advertised,
            resolved_objective_profile,
            quota,
            history,
            account_observations,
            Some(&assessment),
        )
    }

    fn selection_input_for_role(args: SelectionInputForRoleArgs<'_>) -> Result<SelectionInput> {
        let (assessment, features, frozen) = fixture_task_assessment(&test_plan())?;
        selection_input_for_role_with_assessment(
            args,
            Some(&assessment),
            Some(&features),
            Some(&frozen),
        )
    }

    fn initialize_supervisor_selection(
        plan: &mut SupervisorPlan,
        runtime: SupervisorRuntime,
        catalog: &RuntimeModelCatalog,
        admission: &SupervisorAdmissionPolicyInput,
        advertised: &AdvertisedCatalogSet,
    ) -> Result<SupervisorSelectionResolution> {
        let resolved = default_resolved_profile();
        initialize_supervisor_selection_with_profile(
            plan,
            runtime,
            catalog,
            admission,
            advertised,
            Some(&resolved),
        )
    }

    #[test]
    fn cheap_lane_capabilities_cannot_be_widened_by_operator_priors() -> Result<()> {
        let task = task_profile_for_role(AgentRole::Worker);
        let mut priors = selector_priors_with_terminal_worker_economics()?;
        let wide = selection::TaskShapeCeiling {
            boundedness: [
                Boundedness::TightlyBounded,
                Boundedness::Bounded,
                Boundedness::CrossCutting,
            ]
            .into_iter()
            .collect(),
            maximum_risk: RiskLevel::Critical,
            maximum_context: ContextSize::Long,
            maximum_horizon: TaskHorizon::Long,
        };
        for prior in &mut priors.models {
            prior.task_shape_ceiling = Some(wide.clone());
            prior.long_context_eligible = true;
        }
        let advertised = runtime_catalog_from_advertised_slugs(
            "codex",
            ["gpt-5.6-luna"],
            "fixture".into(),
            "2026-10-29".into(),
            &task,
            &priors,
        )?;
        let membership = runtime_catalog_from_priors("codex", &codex_catalog()?, &task, &priors)?;
        let unavailable = runtime_catalog_from_unavailable_priors(
            "codex",
            &CursorCatalogEvidenceGap {
                message: "fixture".into(),
                observed_at_unix_millis: 1,
            },
            &task,
            &priors,
        )?;
        for catalog in [advertised, membership, unavailable] {
            let model = catalog
                .models
                .iter()
                .find(|model| model.model == "gpt-5.6-luna")
                .context("bounded prior catalog model")?;
            assert_eq!(model.capabilities.maximum_risk, RiskLevel::Medium);
            assert_eq!(model.capabilities.maximum_context, ContextSize::Medium);
            assert_eq!(model.capabilities.maximum_horizon, TaskHorizon::Medium);
            assert!(!model
                .capabilities
                .boundedness
                .contains(&Boundedness::CrossCutting));
            assert!(!model.capabilities.long_context);
        }
        let terminal = priors
            .models
            .iter()
            .find(|prior| prior.model == "grok-4.6")
            .context("terminal economics prior")?;
        assert_eq!(
            capabilities_from_prior(terminal, &task)?.maximum_risk,
            RiskLevel::Medium
        );
        #[cfg(target_os = "linux")]
        {
            let observed = ObservedModel {
                model_id: "gpt-5.6-luna".into(),
                access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::Available,
                supported_efforts: Some(vec!["high".into()]),
                default_effort: Some("high".into()),
            };
            let model = catalog_model_from_observed("codex", &observed, &task, &priors)?
                .context("observed bounded model")?;
            assert_eq!(model.capabilities.maximum_risk, RiskLevel::Medium);
            assert_eq!(model.capabilities.maximum_context, ContextSize::Medium);
            assert_eq!(model.capabilities.maximum_horizon, TaskHorizon::Medium);
            assert!(!model
                .capabilities
                .boundedness
                .contains(&Boundedness::CrossCutting));
            assert!(!model.capabilities.long_context);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_observed_unbundled_prior_preserves_explicit_shape_ceiling() -> Result<()> {
        let task = task_profile_for_role(AgentRole::Worker);
        let mut priors = selector_priors_with_terminal_worker_economics()?;
        let mut prior = priors
            .models
            .iter()
            .find(|prior| prior.model == FRONTIER_PROFILE_MODEL)
            .context("qualified prior fixture")?
            .clone();
        prior.model = "qualified-unbundled-fixture".into();
        prior.long_context_eligible = true;
        let model_id = prior.model.clone();
        priors.models.push(prior);
        let observed = ObservedModel {
            model_id: model_id.clone(),
            access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::Available,
            supported_efforts: Some(vec!["high".into()]),
            default_effort: Some("high".into()),
        };
        let gap = CursorCatalogEvidenceGap {
            message: "fixture".into(),
            observed_at_unix_millis: 1,
        };
        for explicit in [true, false] {
            if !explicit {
                priors.models.last_mut().unwrap().task_shape_ceiling = None;
            }
            let account = catalog_model_from_observed("codex", &observed, &task, &priors)?
                .context("observed qualified model")?;
            let advertised = runtime_catalog_from_advertised_slugs(
                "codex",
                [model_id.as_str()],
                "fixture".into(),
                "2026-10-29".into(),
                &task,
                &priors,
            )?;
            let membership =
                runtime_catalog_from_priors("codex", &codex_catalog()?, &task, &priors)?;
            let unavailable =
                runtime_catalog_from_unavailable_priors("codex", &gap, &task, &priors)?;
            for catalog in [advertised, membership, unavailable] {
                let model = catalog
                    .models
                    .iter()
                    .find(|model| model.model == model_id)
                    .context("qualified catalog model")?;
                assert_eq!(account.capabilities, model.capabilities);
            }
            assert_eq!(
                account.capabilities.maximum_risk,
                if explicit {
                    RiskLevel::Critical
                } else {
                    RiskLevel::Medium
                }
            );
            assert_eq!(
                account.capabilities.maximum_context,
                if explicit {
                    ContextSize::Long
                } else {
                    ContextSize::Medium
                }
            );
            assert_eq!(
                account.capabilities.maximum_horizon,
                if explicit {
                    TaskHorizon::Long
                } else {
                    TaskHorizon::Medium
                }
            );
            assert_eq!(
                account
                    .capabilities
                    .boundedness
                    .contains(&Boundedness::CrossCutting),
                explicit
            );
            assert_eq!(account.capabilities.long_context, explicit);
        }
        priors.models.retain(|prior| prior.model != model_id);
        let unknown = catalog_model_from_observed("codex", &observed, &task, &priors)?
            .context("unattributed observed model")?;
        assert_eq!(unknown.capabilities.maximum_risk, RiskLevel::Medium);
        assert_eq!(unknown.capabilities.maximum_context, ContextSize::Medium);
        assert_eq!(unknown.capabilities.maximum_horizon, TaskHorizon::Medium);
        assert!(!unknown.capabilities.long_context);
        assert!(unknown.capabilities.task_classes.is_empty());
        assert!(unknown.capabilities.authority_roles.is_empty());
        Ok(())
    }

    fn codex_catalog() -> Result<RuntimeModelCatalog> {
        let priors = selection::built_in_prior_dataset()?;
        Ok(RuntimeModelCatalog::Codex(
            CodexRuntimeModelCatalog::from_slugs(
                priors
                    .models
                    .iter()
                    .filter(|prior| prior.runtime == runtime_name(SupervisorRuntime::Codex))
                    .map(|prior| prior.model.clone()),
            )?,
        ))
    }

    #[test]
    fn executable_review_auditor_selects_strongest_eligible_live_model() -> Result<()> {
        let catalog = CodexRuntimeModelCatalog::from_slugs([
            FRONTIER_PROFILE_MODEL,
            ECONOMY_PROFILE_MODEL,
            BALANCED_PROFILE_MODEL,
        ])?;

        let selected = catalog.select_executable_review_auditor()?;

        assert_eq!(selected.candidate.runtime, "codex");
        assert_eq!(selected.candidate.model, FRONTIER_PROFILE_MODEL);
        assert_eq!(selected.candidate.effort, SelectorEffort::Xhigh);
        assert_eq!(
            selected
                .provenance
                .choice
                .as_ref()
                .context("ReviewAuditor choice")?
                .reason,
            selection::ChoiceReason::StrongestNoEvidenceJudgmentFallback
        );
        assert!(selected.provenance.candidate_set.iter().all(|candidate| {
            candidate.candidate.model == FRONTIER_PROFILE_MODEL || !candidate.eligible
        }));
        Ok(())
    }

    #[test]
    fn every_codex_role_requires_61_sol_and_preserves_effort_and_authority_gates() -> Result<()> {
        let _policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let advertised = AdvertisedCatalogSet::empty();
        let admission = test_admission();
        let profile = default_resolved_profile();
        for role in [
            AgentRole::Supervisor,
            AgentRole::ChildOrchestrator,
            AgentRole::Worker,
            AgentRole::Researcher,
            AgentRole::GateClassifier,
            AgentRole::Auditor,
        ] {
            let input = selection_input_for_role(SelectionInputForRoleArgs {
                role,
                runtime: SupervisorRuntime::Codex,
                catalog: &catalog,
                advertised: &advertised,
                admission: &admission,
                resolved_objective_profile: &profile,
                quota_context: None,
                quota_ledger: None,
                account_observation: None,
                signals: DynamicSignals {
                    retry_count: 0,
                    budget_signal: BudgetSignal::Continue,
                    previous_choice: None,
                    previous_catalog_digest: None,
                    environment_rejections: Vec::new(),
                    accepted_task_cost_context: None,
                    accepted_task_cost_observations: Vec::new(),
                },
                debug_override: None,
                history: None,
            })?;
            let decision = select_with_live_switch_cost(&input)?;
            let choice = decision
                .choice
                .as_ref()
                .with_context(|| format!("{role:?}: {}", decision.decision_reason))?;
            assert_eq!(choice.candidate.model, "gpt-6.1-sol");
            let mut reference = input.clone();
            reference.constraints.allowed_models = ["gpt-6.1-sol".into()].into_iter().collect();
            assert_eq!(
                choice.candidate.effort,
                selection::select(&reference)?
                    .choice
                    .context("existing effort selection")?
                    .candidate
                    .effort
            );
            if role != AgentRole::Worker {
                assert_eq!(choice.candidate.effort, SelectorEffort::Xhigh);
            }
            assert!(decision
                .candidate_set
                .iter()
                .all(|c| c.candidate.model == "gpt-6.1-sol" || !c.eligible));
            let mut absent = input.clone();
            absent.catalogs[0]
                .models
                .retain(|m| m.model != "gpt-6.1-sol");
            let refused = select_with_live_switch_cost(&absent)?;
            assert!(refused.choice.is_none());
            let message = selection_refusal_message(&refused, role);
            assert!(
                message.contains("gpt-6.1-sol") && message.contains("0.162.0"),
                "{message}"
            );
            // An authored legacy-model override cannot bypass the runtime policy.
            absent.constraints.allow_debug_override = true;
            absent.debug_override = Some(DebugOverride {
                candidate: CandidateKey {
                    runtime: "codex".into(),
                    model: "gpt-5.6-sol".into(),
                    effort: SelectorEffort::Xhigh,
                },
                requested_by: "test".into(),
                reason: "legacy override must fail closed".into(),
            });
            assert!(select_with_live_switch_cost(&absent)?.choice.is_none());
        }
        Ok(())
    }

    #[test]
    fn executable_review_auditor_refuses_selected_model_below_capability_floor() -> Result<()> {
        let (_guard, catalog) = bind_test_below_floor_review_auditor()?;

        let error = catalog
            .select_executable_review_auditor()
            .expect_err("GeneralJudgment model must not receive ReviewAuditor authority");
        let detail = format!("{error:#}");

        assert!(detail.contains(TEST_BELOW_FLOOR_REVIEW_AUDITOR_MODEL));
        assert!(detail.contains("ReviewAuditor authority"));
        assert!(detail.contains("critical_judgment"));
        assert!(detail.contains("general_judgment"));
        Ok(())
    }

    #[test]
    fn executable_review_auditor_fails_closed_for_ineligible_unavailable_and_unknown_models(
    ) -> Result<()> {
        for (case, models) in [
            ("ineligible", vec![BALANCED_PROFILE_MODEL]),
            ("unavailable", vec![ECONOMY_PROFILE_MODEL]),
            ("unknown", vec!["provider-unknown-review-model"]),
        ] {
            let catalog = CodexRuntimeModelCatalog::from_slugs(models)?;
            let error = catalog
                .select_executable_review_auditor()
                .expect_err("non-executable ReviewAuditor catalog must fail closed");
            assert!(
                error.to_string().contains("failed closed"),
                "{case}: {error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn executable_review_auditor_returns_authority_and_selector_provenance() -> Result<()> {
        let catalog = CodexRuntimeModelCatalog::from_slugs([FRONTIER_PROFILE_MODEL])?;

        let selected = catalog.select_executable_review_auditor()?;
        let provenance = &selected.provenance;

        assert_eq!(selected.authority.role, AgentRole::Auditor);
        assert_eq!(selected.authority.phase, OrchestrationPhase::Audit);
        assert_eq!(
            selected.authority.required_capability,
            ModelCapabilityClass::CriticalJudgment
        );
        assert_eq!(
            selected.authority.selected_capability,
            ModelCapabilityClass::CriticalJudgment
        );
        assert_eq!(provenance.status, DecisionStatus::Selected);
        assert_eq!(
            provenance.normalized_task.authority_role,
            AuthorityRole::ReviewAuditor
        );
        assert_eq!(
            provenance.normalized_task.task_class,
            JUDGMENT_SELECTION_TASK_CLASS
        );
        assert_eq!(
            provenance
                .choice
                .as_ref()
                .context("ReviewAuditor choice")?
                .candidate,
            selected.candidate
        );
        assert!(!provenance.input_digests.normalized_input.value.is_empty());
        assert!(!provenance.resolved_objective_profile.profile.id.is_empty());
        assert!(provenance.normalized_input.catalogs.iter().any(|runtime| {
            runtime.runtime == "codex"
                && runtime.models.iter().any(|model| {
                    model.model == FRONTIER_PROFILE_MODEL
                        && model.available
                        && model
                            .capabilities
                            .authority_roles
                            .contains(&AuthorityRole::ReviewAuditor)
                })
        }));
        Ok(())
    }

    fn test_plan() -> SupervisorPlan {
        SupervisorPlan {
            version: SUPERVISOR_SCHEMA_VERSION,
            task: "exercise automatic role selection".to_string(),
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
            assignments: vec![serde_json::from_value(json!({
                "id":"coordinated-fixture", "phase":"execution", "role":"child_orchestrator",
                "assigned_paths":["src"], "worker_assignments":[
                    {"id":"bounded-worker-fixture", "role":"worker", "assigned_paths":["src/a.rs"]}
                ]
            }))
            .expect("reachable orchestrator and Worker fixture")],
        }
    }

    #[test]
    fn routing_features_count_real_nested_workers_and_join_overlapping_or_dependent_scopes(
    ) -> Result<()> {
        let mut plan = test_plan();
        plan.assignments = vec![serde_json::from_value(json!({
            "id":"actual-execution-parent", "phase":"execution", "role":"child_orchestrator",
            "assigned_paths":["src"], "worker_assignments":[
                {"id":"a", "role":"worker", "assigned_paths":["src/a.rs"]},
                {"id":"b", "role":"worker", "assigned_paths":["src/b.rs"]}
            ]
        }))?];
        let features = routing_features_from_plan(&plan);
        assert_eq!(features.scope_paths, 2);
        assert_eq!(features.independent_groups, 2);
        plan.assignments[0].worker_assignments[1].assigned_paths = vec!["src".into()];
        assert_eq!(routing_features_from_plan(&plan).independent_groups, 1);
        plan.assignments[0].worker_assignments[1].assigned_paths = vec!["src/b.rs".into()];
        // Shared decision incidence cannot be interpreted as independent work.
        plan.assignments[0].decision_refs = serde_json::from_value(
            json!([{"question_key":"shared-decision", "expected_resolution":"shared resolution"}]),
        )?;
        assert_eq!(routing_features_from_plan(&plan).independent_groups, 1);
        assert_eq!(routing_features_from_plan(&plan).dependency_edges, 1);
        Ok(())
    }

    fn test_admission() -> SupervisorAdmissionPolicyInput {
        SupervisorAdmissionPolicyInput {
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
        }
    }

    fn role_selection(model: String, reasoning_effort: Option<&str>) -> RoleModelSelection {
        RoleModelSelection {
            model: Some(model),
            reasoning_effort: reasoning_effort.map(str::to_string),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        }
    }

    fn codex_prior_for(
        predicate: impl Fn(&selection::ModelPrior) -> bool,
    ) -> Result<selection::ModelPrior> {
        selection::built_in_prior_dataset()?
            .models
            .into_iter()
            .find(|prior| {
                prior.runtime == runtime_name(SupervisorRuntime::Codex)
                    && prior.model == FRONTIER_PROFILE_MODEL
                    && predicate(prior)
            })
            .context("built-in selector data has no matching Codex prior")
    }

    fn automatic_state() -> Result<(RuntimeModelCatalog, SupervisorAutomaticSelectionState)> {
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;
        Ok((
            catalog,
            resolution
                .automatic_state
                .context("automatic selection replay state")?,
        ))
    }

    #[test]
    fn completed_event_commit_is_atomic_when_assignment_chain_is_malformed() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, mut manager_state) = automatic_state()?;
        let before = manager_state.clone();
        let mut assignment_state = manager_state.clone();
        let first = reselect_roles_from_supplied_catalog_snapshot(
            &mut assignment_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        let second = reselect_roles_from_supplied_catalog_snapshot(
            &mut assignment_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            2,
            BudgetSignal::Continue,
            &[],
        )?;
        let mut events = vec![
            SupervisorSelectionEvent {
                assignment_id: Some("assignment-a".to_string()),
                attempt: 1,
                role: AgentRole::Worker,
                primary_cause: SupervisorSelectionEventCause::Retry,
                provenance: first.decisions[0].1.clone(),
            },
            SupervisorSelectionEvent {
                assignment_id: Some("assignment-a".to_string()),
                attempt: 2,
                role: AgentRole::Worker,
                primary_cause: SupervisorSelectionEventCause::Retry,
                provenance: second.decisions[0].1.clone(),
            },
        ];
        events[1]
            .provenance
            .normalized_input
            .signals
            .previous_choice = Some(CandidateKey {
            runtime: "codex".to_string(),
            model: "tampered-chain".to_string(),
            effort: SelectorEffort::Low,
        });

        let error = manager_state
            .commit_completed_selection_events(SupervisorRuntime::Codex, &events)
            .expect_err("malformed assignment event chain must fail closed");

        assert!(error.to_string().contains("expected previous choice"));
        assert_eq!(manager_state, before);
        Ok(())
    }

    #[test]
    fn automatic_empty_role_models_resolve_all_roles_from_eligible_catalog() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let admission = test_admission();

        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &AdvertisedCatalogSet::empty(),
        )?;

        assert_eq!(resolution.mode, SupervisorSelectionMode::Automatic);
        assert_eq!(resolution.decisions.len(), all_selector_roles().len());
        assert_eq!(plan.role_models.len(), all_selector_roles().len());
        for role in all_selector_roles() {
            assert!(plan.role_models.contains_key(role));
        }
        let auditor_model = plan.role_models[&AgentRole::Auditor]
            .model
            .as_deref()
            .context("selected Auditor model")?;
        for lens in &plan.review_lenses {
            assert_eq!(lens.backend.model(), auditor_model);
            assert_eq!(
                lens.backend.reasoning_effort(),
                plan.role_models[&AgentRole::Auditor]
                    .reasoning_effort
                    .as_deref()
            );
        }
        assert!(resolution.decisions.iter().all(|decision| {
            decision.assignment_id.is_none()
                && decision.attempt == 0
                && decision.primary_cause == SupervisorSelectionEventCause::Initial
                && decision.provenance.status == DecisionStatus::Selected
                && decision.provenance.choice.as_ref().is_some_and(|choice| {
                    decision
                        .provenance
                        .normalized_input
                        .signals
                        .previous_choice
                        .is_none()
                        && choice.switch_transition == selection::ContextSwitchTransition::Initial
                        && choice.configured_switch_cost_microunits == 0
                        && choice.switch_cost_microunits == 0
                })
        }));
        Ok(())
    }

    #[test]
    fn authored_researcher_selection_preserves_distinct_role_and_binding() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        plan.assignments.push(serde_json::from_value(json!({
            "id": "research", "phase": "execution", "role": "researcher", "role_category": "read_only_researcher",
            "assigned_paths": ["src"], "worker_assignments": []
        }))?);
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;
        assert!(
            resolution.selection_preflight_failure.is_none(),
            "{:?}",
            resolution.selection_preflight_failure
        );
        let decision = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Researcher)
            .context("missing Researcher selection")?;
        assert_eq!(
            role_for_task_profile(&decision.provenance.normalized_task)?,
            AgentRole::Researcher
        );
        assert_eq!(
            optimizer_role(AgentRole::Researcher),
            OptimizerRole::Researcher
        );
        validate_known_judgment_role_model(
            AgentRole::Researcher,
            plan.role_models[&AgentRole::Researcher].model.as_deref(),
        )?;
        Ok(())
    }

    #[test]
    fn authenticated_exhausted_quota_projects_into_supervisor_refusal_and_evidence() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        use crate::{
            budget_ledger::{CompletedPoolConsumption, WorkspaceBudgetLedger},
            optimizer::{
                ids::RuntimeSlug,
                quota_pools::{
                    AccountId, EntitlementDescriptor, ExhaustionBehavior, NominalCapacity,
                    PoolKind, QuotaConfig, RateLimits, ResetWindow, QUOTA_CONFIG_VERSION,
                },
            },
        };

        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo");
        git2::Repository::init(&repo)?;
        let config = QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![EntitlementDescriptor {
                runtime: RuntimeSlug::new("codex")?,
                account: AccountId::new("operator-primary")?,
                pool_kind: PoolKind::SubscriptionIncluded,
                window: ResetWindow::None,
                nominal_capacity: NominalCapacity::Units(10),
                rate_limits: RateLimits {
                    max_concurrent_sessions: Some(1),
                    ..RateLimits::default()
                },
                priority_tier: None,
                exhaustion_behavior: ExhaustionBehavior::FailClosed,
                authorized_alternatives: Vec::new(),
                declared_list_price_microunits: None,
            }],
        };
        config.validate()?;
        let now = crate::budget_ledger::unix_now()?;
        {
            let mut workspace = WorkspaceBudgetLedger::open_or_create(&repo)?;
            workspace.record_completed_pool_consumption(CompletedPoolConsumption {
                completion_id: "prior-run/session/1/reservation/1".to_string(),
                pool: config.pools[0].key(),
                tokens: 10,
                requests: 1,
                cost_usd: None,
                unix_seconds: now,
            })?;
        }

        let mut quota_ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
        quota_ledger.attach_quota_config(&repo, "live-input-test", &config)?;
        let context = LiveQuotaSelectionContext {
            repo,
            relative_path: PathBuf::from("config/operator-quota.json"),
            config,
        };
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection_with_quota(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput {
                context: Some(&context),
                ledger: Some(&quota_ledger),
            },
        )?;

        let failure = resolution
            .selection_preflight_failure
            .as_ref()
            .context("exhausted quota must fail supervisor preflight")?;
        assert_eq!(
            failure.kind,
            SupervisorSelectionPreflightFailureKind::FailClosed
        );
        let event = resolution.decisions.first().context("quota decision")?;
        let quota = event
            .provenance
            .quota
            .as_ref()
            .context("typed quota decision provenance")?;
        assert!(quota.source_exhausted);
        assert_eq!(quota.configured_behavior, ExhaustionBehavior::FailClosed);
        assert_eq!(
            quota.disposition,
            selection::QuotaDecisionDisposition::FailClosed
        );
        assert_eq!(
            quota.local_observation_revision,
            event.provenance.runtime_operations[0].observation_revision
        );
        let source = event
            .provenance
            .normalized_input
            .pools
            .iter()
            .find(|pool| pool.pool_reference.as_ref() == Some(&quota.source_pool))
            .context("typed source pool")?;
        assert!(source.exhausted);
        assert_eq!(source.observed_consumption_units, 10);

        let evidence = ledger_entry_for_assignment(
            "supervisor-gate",
            AgentRole::Supervisor,
            &resolution.decisions,
            SupervisorRuntime::Codex,
            &plan,
        )
        .quota_evidence
        .context("assignment ledger quota evidence")?;
        assert_eq!(evidence.pool_reference, Some(quota.source_pool.clone()));
        assert!(evidence.exhausted);
        Ok(())
    }

    #[test]
    fn verified_routing_requires_frozen_profile_while_fake_compatibility_remains_explicit(
    ) -> Result<()> {
        let catalog = codex_catalog()?;
        let mut missing = test_plan();
        let error = super::initialize_supervisor_selection(
            &mut missing,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            None,
        )
        .expect_err("verified routing without a frozen profile must fail closed");
        assert!(error
            .to_string()
            .contains("objective profile resolved and frozen"));

        let fake = super::initialize_supervisor_selection(
            &mut missing,
            SupervisorRuntime::Fake,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            None,
        )?;
        assert_eq!(fake.mode, SupervisorSelectionMode::LegacyFake);
        Ok(())
    }

    #[test]
    fn available_source_pressure_and_marginal_cost_reach_assignment_evidence() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        use crate::{
            budget_ledger::{CompletedPoolConsumption, WorkspaceBudgetLedger},
            optimizer::{
                ids::RuntimeSlug,
                quota_pools::{
                    AccountId, EntitlementDescriptor, ExhaustionBehavior, NominalCapacity,
                    PoolKind, QuotaConfig, RateLimits, ResetWindow, QUOTA_CONFIG_VERSION,
                },
            },
        };

        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo");
        git2::Repository::init(&repo)?;
        let config = QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![EntitlementDescriptor {
                runtime: RuntimeSlug::new("codex")?,
                account: AccountId::new("metered-primary")?,
                pool_kind: PoolKind::Metered,
                window: ResetWindow::None,
                nominal_capacity: NominalCapacity::Units(10),
                rate_limits: RateLimits::default(),
                priority_tier: None,
                exhaustion_behavior: ExhaustionBehavior::FailClosed,
                authorized_alternatives: Vec::new(),
                declared_list_price_microunits: Some(700),
            }],
        };
        let now = crate::budget_ledger::unix_now()?;
        {
            let mut workspace = WorkspaceBudgetLedger::open_or_create(&repo)?;
            workspace.record_completed_pool_consumption(CompletedPoolConsumption {
                completion_id: "available-prior/session/1/reservation/1".to_string(),
                pool: config.pools[0].key(),
                tokens: 4,
                requests: 1,
                cost_usd: None,
                unix_seconds: now,
            })?;
        }
        let mut quota_ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
        quota_ledger.attach_quota_config(&repo, "available-input", &config)?;
        let context = LiveQuotaSelectionContext {
            repo,
            relative_path: PathBuf::from("config/operator-quota.json"),
            config,
        };
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection_with_quota(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput {
                context: Some(&context),
                ledger: Some(&quota_ledger),
            },
        )?;
        assert!(resolution.selection_preflight_failure.is_none());
        let worker = resolution
            .decisions
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("worker quota decision")?;
        assert_eq!(
            worker
                .provenance
                .choice
                .as_ref()
                .context("available source choice")?
                .candidate
                .runtime,
            "codex"
        );
        assert_eq!(
            worker
                .provenance
                .quota
                .as_ref()
                .context("available quota provenance")?
                .disposition,
            selection::QuotaDecisionDisposition::SourceAvailable
        );
        let evidence = ledger_entry_for_assignment(
            "available-worker",
            AgentRole::Worker,
            &resolution.decisions,
            SupervisorRuntime::Codex,
            &plan,
        )
        .quota_evidence
        .context("available assignment quota evidence")?;
        assert_eq!(evidence.runtime, "codex");
        assert_eq!(evidence.observed_consumption_units, 4);
        assert_eq!(evidence.pool_pressure_basis_points, 4_000);
        assert_eq!(evidence.marginal_cost_microunits, 700);
        Ok(())
    }

    #[test]
    fn degraded_choice_records_the_selected_runtime_pool_in_assignment_evidence() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        use crate::{
            budget_ledger::{CompletedPoolConsumption, WorkspaceBudgetLedger},
            optimizer::{
                ids::RuntimeSlug,
                quota_pools::{
                    AccountId, EntitlementDescriptor, ExhaustionBehavior, NominalCapacity,
                    PoolKind, PoolReference, QuotaConfig, RateLimits, ResetWindow,
                    QUOTA_CONFIG_VERSION,
                },
            },
        };

        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo");
        git2::Repository::init(&repo)?;
        let cursor_reference = PoolReference {
            runtime: RuntimeSlug::new("cursor")?,
            account: AccountId::new("cursor-metered")?,
            window: ResetWindow::None,
        };
        let config = QuotaConfig {
            version: QUOTA_CONFIG_VERSION,
            pools: vec![
                EntitlementDescriptor {
                    runtime: RuntimeSlug::new("codex")?,
                    account: AccountId::new("codex-included")?,
                    pool_kind: PoolKind::SubscriptionIncluded,
                    window: ResetWindow::None,
                    nominal_capacity: NominalCapacity::Units(10),
                    rate_limits: RateLimits::default(),
                    priority_tier: None,
                    exhaustion_behavior: ExhaustionBehavior::Degrade,
                    authorized_alternatives: vec![cursor_reference.clone()],
                    declared_list_price_microunits: None,
                },
                EntitlementDescriptor {
                    runtime: cursor_reference.runtime.clone(),
                    account: cursor_reference.account.clone(),
                    pool_kind: PoolKind::Metered,
                    window: cursor_reference.window,
                    nominal_capacity: NominalCapacity::Unknown,
                    rate_limits: RateLimits::default(),
                    priority_tier: None,
                    exhaustion_behavior: ExhaustionBehavior::FailClosed,
                    authorized_alternatives: Vec::new(),
                    declared_list_price_microunits: Some(500),
                },
            ],
        };
        config.validate()?;
        {
            let mut workspace = WorkspaceBudgetLedger::open_or_create(&repo)?;
            workspace.record_completed_pool_consumption(CompletedPoolConsumption {
                completion_id: "degraded-prior/session/1/reservation/1".to_string(),
                pool: config.pools[0].key(),
                tokens: 10,
                requests: 1,
                cost_usd: None,
                unix_seconds: crate::budget_ledger::unix_now()?,
            })?;
        }
        let mut quota_ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
        quota_ledger.attach_quota_config(&repo, "degraded-evidence", &config)?;
        let quota_context = LiveQuotaSelectionContext {
            repo,
            relative_path: PathBuf::from("config/operator-quota.json"),
            config,
        };
        let catalog = codex_catalog()?;
        let advertised = advertised_with_cursor(captured_cursor_observation()?);
        let admission = test_admission();
        let resolved_profile = default_resolved_profile();
        let decision = selection::select(&selection_input_for_role(SelectionInputForRoleArgs {
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Codex,
            catalog: &catalog,
            advertised: &advertised,
            admission: &admission,
            resolved_objective_profile: &resolved_profile,
            quota_context: Some(&quota_context),
            quota_ledger: Some(&quota_ledger),
            account_observation: None,
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
                accepted_task_cost_context: None,
                accepted_task_cost_observations: Vec::new(),
            },
            debug_override: None,
            history: None,
        })?)?;
        let selected = decision.choice.as_ref().context("degraded choice")?;
        assert_eq!(selected.candidate.runtime, "cursor");
        assert_eq!(
            decision
                .quota
                .as_ref()
                .context("degraded quota provenance")?
                .disposition,
            selection::QuotaDecisionDisposition::Degraded
        );
        let event = SupervisorSelectionEvent {
            assignment_id: None,
            attempt: 0,
            role: AgentRole::Worker,
            primary_cause: SupervisorSelectionEventCause::Initial,
            provenance: decision,
        };
        let evidence = ledger_entry_for_assignment(
            "degraded-worker",
            AgentRole::Worker,
            &[event],
            SupervisorRuntime::Codex,
            &test_plan(),
        )
        .quota_evidence
        .context("selected runtime quota evidence")?;
        assert_eq!(evidence.runtime, "cursor");
        assert_eq!(evidence.pool_reference, Some(cursor_reference));
        assert_eq!(evidence.marginal_cost_microunits, 500);
        Ok(())
    }

    #[test]
    fn initial_retry_and_budget_degrade_reuse_exact_frozen_profile_evidence() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let mut profile = crate::objective_profile::default_objective_profile();
        profile.id = "frozen-routing-profile-v1".to_string();
        profile.tradeoffs.monetary_cost_percent = 75;
        profile.tradeoffs.human_review_percent = 25;
        let frozen = ResolvedObjectiveProfile {
            profile: profile.binding()?,
            source: crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
        };
        let resolution = initialize_supervisor_selection_with_profile(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&frozen),
        )?;
        assert!(resolution.decisions.iter().all(|event| {
            event.provenance.resolved_objective_profile == frozen
                && event.provenance.normalized_input.resolved_objective_profile == frozen
        }));
        let mut state = resolution
            .automatic_state
            .context("automatic selection state")?;
        let retry = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        assert_eq!(retry.decisions[0].1.resolved_objective_profile, frozen);
        let degrade = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::ChildOrchestrator, AgentRole::Auditor],
            0,
            BudgetSignal::Degrade,
            &[],
        )?;
        assert!(degrade
            .decisions
            .iter()
            .all(|(_, decision)| decision.resolved_objective_profile == frozen));
        Ok(())
    }

    #[test]
    fn verified_bridge_applies_supported_profile_to_score_arithmetic_and_choice() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let admission = test_admission();
        let advertised = AdvertisedCatalogSet::empty();

        let mut default_plan = test_plan();
        let default = initialize_supervisor_selection(
            &mut default_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &advertised,
        )?;
        let default_worker = default
            .decisions
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("default worker decision")?;
        let default_choice = default_worker
            .provenance
            .choice
            .as_ref()
            .context("default worker choice")?;

        let mut profile = crate::objective_profile::default_objective_profile();
        profile.id = "review-sensitive-routing-v1".to_string();
        profile.tradeoffs.monetary_cost_percent = 25;
        profile.tradeoffs.human_review_percent = 75;
        let frozen = ResolvedObjectiveProfile {
            profile: profile.binding()?,
            source: crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
        };
        let mut adjusted_plan = test_plan();
        let adjusted = initialize_supervisor_selection_with_profile(
            &mut adjusted_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &advertised,
            Some(&frozen),
        )?;
        let adjusted_worker = adjusted
            .decisions
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("adjusted worker decision")?;
        assert_eq!(
            adjusted_worker.provenance.resolved_objective_profile,
            frozen
        );
        let adjusted_choice = adjusted_worker
            .provenance
            .choice
            .as_ref()
            .context("adjusted worker choice")?;
        assert_eq!(adjusted_choice.candidate.model, "gpt-6.1-sol");
        assert_eq!(default_choice.candidate.model, "gpt-6.1-sol");
        assert_ne!(
            adjusted_worker.provenance.resolved_objective_profile,
            default_worker.provenance.resolved_objective_profile
        );
        assert_eq!(
            adjusted_choice.reason,
            selection::ChoiceReason::LoadedRoutingPolicy
        );
        let score = adjusted_worker
            .provenance
            .candidate_set
            .iter()
            .find(|candidate| candidate.candidate == adjusted_choice.candidate)
            .and_then(|candidate| candidate.score.as_ref())
            .context("adjusted worker selected score")?;
        assert_eq!(
            score.routing_score_semantics,
            selection::RoutingScoreSemantics::LoadedPolicyEvidencePenaltyV2
        );
        assert_eq!(score.routing_tradeoff_weights, frozen.profile.tradeoffs);
        let default_score = default_worker
            .provenance
            .candidate_set
            .iter()
            .find(|candidate| candidate.candidate == default_choice.candidate)
            .and_then(|candidate| candidate.score.as_ref())
            .context("default worker score")?;
        assert_ne!(
            score.total_score_microunits,
            default_score.total_score_microunits
        );
        assert_eq!(score.retry_rework_adjustment_microunits, 0);
        assert_eq!(
            score.human_review_adjustment_microunits,
            score.human_review_cost_proxy_microunits * 75 / 25
        );
        assert_eq!(
            score.total_adjustment_microunits,
            score.human_review_adjustment_microunits
        );
        assert_eq!(
            score.total_score_microunits,
            score.legacy_baseline_score_microunits + score.total_adjustment_microunits
        );
        Ok(())
    }

    fn child_assignment(id: &str) -> OrchestratorAssignment {
        OrchestratorAssignment {
            assignment_shape: None,
            id: id.to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
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

    fn mechanical_degradation_record(assignment_id: &str) -> BudgetDegradationRecord {
        mechanical_degradation_record_to(assignment_id, ECONOMY_PROFILE_MODEL)
    }

    fn mechanical_degradation_record_to(
        assignment_id: &str,
        after_model: &str,
    ) -> BudgetDegradationRecord {
        BudgetDegradationRecord {
            sequence: 1,
            assignment_id: assignment_id.to_string(),
            trigger: BudgetDegradationTrigger::LowDifficultyMechanical,
            budget_action: BudgetAction::Continue,
            budget_reasons: Vec::new(),
            change: BudgetDegradationChange::ModelTier {
                role: AgentRole::Worker,
                before: FRONTIER_PROFILE_MODEL.to_string(),
                after: after_model.to_string(),
                resolved_candidate_index: 0,
            },
            role_binding_transition: Some(BudgetDegradationRoleBindingTransition {
                role: AgentRole::Worker,
                before: BudgetDegradationRoleBinding {
                    model: Some(FRONTIER_PROFILE_MODEL.to_string()),
                    reasoning_effort: Some("xhigh".to_string()),
                },
                after: BudgetDegradationRoleBinding {
                    model: Some(after_model.to_string()),
                    reasoning_effort: Some("xhigh".to_string()),
                },
            }),
            effective_child_model: Some(FRONTIER_PROFILE_MODEL.to_string()),
            effective_child_reasoning_effort: Some("xhigh".to_string()),
            effective_fan_out: 1,
            observation: BudgetDegradationObservation::AdmissionPolicyResolved,
        }
    }

    #[test]
    fn assignment_selection_ledger_projects_role_decisions_onto_each_assignment() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        plan.assignments = vec![
            child_assignment("assignment-a"),
            child_assignment("assignment-b"),
        ];
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;

        let ledger = build_assignment_selection_ledger(
            &plan,
            &resolution.decisions,
            SupervisorRuntime::Codex,
        );

        assert_eq!(ledger.len(), 6);
        for assignment_id in ["assignment-a", "assignment-b"] {
            for role in [
                AgentRole::ChildOrchestrator,
                AgentRole::GateClassifier,
                AgentRole::Auditor,
            ] {
                let entry = ledger
                    .iter()
                    .find(|entry| entry.assignment_id == assignment_id && entry.role == role)
                    .with_context(|| {
                        format!("missing {assignment_id} {} ledger row", role.as_str())
                    })?;
                assert_eq!(entry.selection_source, AssignmentSelectionSource::Automatic);
                let role_assignment = entry
                    .role_assignment
                    .as_ref()
                    .with_context(|| format!("missing role assignment for {assignment_id}"))?;
                assert_eq!(role_assignment.agent_id, assignment_id);
                assert_eq!(role_assignment.legacy_role, role.as_str());
                assert_eq!(role_assignment.category, role.authority_category());
                assert_eq!(
                    role_assignment.source,
                    RoleAssignmentSource::DerivedFromPlanRole
                );
                assert!(role_assignment
                    .reason
                    .contains("without a launch-tier designation"));
                assert_eq!(entry.selected_runtime.as_deref(), Some("codex"));
                assert!(entry.selected_model.is_some());
                assert!(entry.selected_reasoning_effort.is_some());
                assert_eq!(
                    entry.catalog_source,
                    AssignmentCatalogSource::RuntimeAdvertised
                );
                assert!(entry
                    .catalog_snapshot_digest
                    .as_ref()
                    .is_some_and(|digest| !digest.is_empty()));
                assert!(!entry.catalog_revisions.is_empty());
                assert!(!entry.rejected_candidates.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn assignment_selection_ledger_records_plan_role_models_source() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let prior = codex_prior_for(|prior| {
            prior.class_fit.iter().any(|class_fit| {
                class_fit.task_class == AUTOMATIC_SELECTION_TASK_CLASS
                    && class_fit.effort == SelectorEffort::High
            })
        })?;
        let mut plan = test_plan();
        plan.assignments = vec![child_assignment("assignment-a")];
        plan.role_models
            .insert(AgentRole::Worker, role_selection(prior.model, Some("high")));
        plan.assignments[0].worker_assignments = vec![WorkerAssignment {
            id: "worker-a".to_string(),
            role: AgentRole::Worker,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            environment_requirements: Vec::new(),
            report_path: None,
        }];

        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;
        let ledger = build_assignment_selection_ledger(
            &plan,
            &resolution.decisions,
            SupervisorRuntime::Codex,
        );

        let worker = ledger
            .iter()
            .find(|entry| entry.assignment_id == "assignment-a" && entry.role == AgentRole::Worker)
            .context("worker ledger row")?;
        assert_eq!(
            worker.selection_source,
            AssignmentSelectionSource::PlanRoleModels
        );
        assert_eq!(worker.selected_runtime.as_deref(), Some("codex"));
        assert_eq!(worker.selected_reasoning_effort.as_deref(), Some("high"));
        assert_eq!(
            worker.catalog_source,
            AssignmentCatalogSource::RuntimeAdvertised
        );
        Ok(())
    }

    #[test]
    fn assignment_selection_ledger_records_typed_mechanical_degradation_evidence() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        plan.assignments = vec![child_assignment("assignment-a")];
        plan.assignments[0].worker_assignments = vec![WorkerAssignment {
            id: "worker-a".to_string(),
            role: AgentRole::Worker,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            environment_requirements: Vec::new(),
            report_path: None,
        }];
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;
        let mut ledger = build_assignment_selection_ledger(
            &plan,
            &resolution.decisions,
            SupervisorRuntime::Codex,
        );
        let child_before = ledger
            .iter()
            .find(|entry| {
                entry.assignment_id == "assignment-a" && entry.role == AgentRole::ChildOrchestrator
            })
            .context("ChildOrchestrator ledger row")?
            .clone();
        let worker_before = ledger
            .iter()
            .find(|entry| entry.assignment_id == "assignment-a" && entry.role == AgentRole::Worker)
            .context("initial Worker ledger row")?
            .clone();
        let budget_target = worker_before
            .rejected_candidates
            .iter()
            .find(|candidate| candidate.model != "unselected-alternate")
            .map(|candidate| candidate.model.clone())
            .context("selector-rejected model for budget target")?;
        assert!(worker_before.catalog_snapshot_digest.is_some());
        assert!(!worker_before.catalog_revisions.is_empty());
        let records = vec![mechanical_degradation_record_to(
            "assignment-a",
            &budget_target,
        )];

        apply_budget_degradations_to_selection_ledger(&mut ledger, &records);

        let worker = ledger
            .iter()
            .find(|entry| entry.assignment_id == "assignment-a" && entry.role == AgentRole::Worker)
            .context("Worker ledger row")?;
        assert_eq!(
            worker.selection_source,
            AssignmentSelectionSource::LowDifficultyMechanical
        );
        assert_eq!(worker.assignment_id, worker_before.assignment_id);
        assert_eq!(worker.attempt, worker_before.attempt);
        assert_eq!(worker.role, worker_before.role);
        assert_eq!(worker.role_assignment, worker_before.role_assignment);
        assert_eq!(worker.selected_runtime, worker_before.selected_runtime);
        assert_eq!(
            worker.selected_model.as_deref(),
            Some(budget_target.as_str())
        );
        assert_eq!(worker.selected_reasoning_effort.as_deref(), Some("xhigh"));
        assert_eq!(
            worker.catalog_source,
            AssignmentCatalogSource::RuntimeAdvertised
        );
        assert!(worker.catalog_snapshot_digest.is_none());
        assert!(worker.catalog_revisions.is_empty());
        assert!(!worker
            .rejected_candidates
            .iter()
            .any(|candidate| candidate.model == budget_target));
        assert!(worker.rejected_candidates.is_empty());
        assert!(worker.evidence_gap.as_ref().is_some_and(|gap| gap.contains(
            "selector candidate provenance described the superseded binding and was discarded"
        )));
        let child_after = ledger
            .iter()
            .find(|entry| {
                entry.assignment_id == "assignment-a" && entry.role == AgentRole::ChildOrchestrator
            })
            .context("ChildOrchestrator ledger row after overlay")?;
        assert_eq!(child_after, &child_before);
        Ok(())
    }

    #[test]
    fn assignment_selection_ledger_preserves_later_worker_retry_provenance() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        plan.assignments = vec![child_assignment("assignment-a")];
        plan.assignments[0].worker_assignments = vec![WorkerAssignment {
            id: "worker-a".to_string(),
            role: AgentRole::Worker,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: None,
            environment_requirements: Vec::new(),
            report_path: None,
        }];
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;
        let mut decisions = resolution.decisions;
        let mut retry = decisions
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("initial Worker selector event")?
            .clone();
        retry.assignment_id = Some("assignment-a".to_string());
        retry.attempt = 2;
        retry.primary_cause = SupervisorSelectionEventCause::Retry;
        decisions.push(retry);
        let mut ledger =
            build_assignment_selection_ledger(&plan, &decisions, SupervisorRuntime::Codex);
        let before = ledger
            .iter()
            .find(|entry| entry.assignment_id == "assignment-a" && entry.role == AgentRole::Worker)
            .context("retry Worker ledger row")?
            .clone();
        assert_eq!(before.selection_source, AssignmentSelectionSource::Retry);
        assert_eq!(before.attempt, 2);

        apply_budget_degradations_to_selection_ledger(
            &mut ledger,
            &[mechanical_degradation_record("assignment-a")],
        );

        let after = ledger
            .iter()
            .find(|entry| entry.assignment_id == "assignment-a" && entry.role == AgentRole::Worker)
            .context("Worker ledger row after degradation overlay")?;
        assert_eq!(after, &before);
        Ok(())
    }

    #[test]
    fn assignment_selection_ledger_synthesizes_legacy_fake_rows() -> Result<()> {
        let mut plan = test_plan();
        plan.assignments = vec![child_assignment("assignment-a")];
        let ledger = build_assignment_selection_ledger(&plan, &[], SupervisorRuntime::Fake);

        assert!(!ledger.is_empty());
        assert!(ledger.iter().all(|entry| {
            entry.assignment_id == "assignment-a"
                && entry.selection_source == AssignmentSelectionSource::LegacyFake
                && entry.catalog_source == AssignmentCatalogSource::None
                && entry.catalog_snapshot_digest.is_none()
                && entry.evidence_gap.is_some()
        }));
        Ok(())
    }

    #[test]
    fn authored_override_runtime_uses_explicit_worker_runtime_and_primary_for_unassigned_auditor(
    ) -> Result<()> {
        let mut plan = test_plan();
        let mut worker = child_assignment("worker-a");
        worker.role = AgentRole::Worker;
        worker.runtime = Some(SupervisorRuntime::Grok);
        plan.assignments = vec![worker];

        assert_eq!(
            authored_override_runtime(&plan, AgentRole::Worker, SupervisorRuntime::Codex)?,
            SupervisorRuntime::Grok
        );
        assert_eq!(
            authored_override_runtime(&plan, AgentRole::Auditor, SupervisorRuntime::Codex)?,
            SupervisorRuntime::Codex
        );
        Ok(())
    }

    #[test]
    fn authored_override_runtime_rejects_conflicting_worker_runtimes() {
        let mut plan = test_plan();
        let mut grok = child_assignment("worker-grok");
        grok.role = AgentRole::Worker;
        grok.runtime = Some(SupervisorRuntime::Grok);
        let mut codex = child_assignment("worker-codex");
        codex.role = AgentRole::Worker;
        codex.runtime = Some(SupervisorRuntime::Codex);
        plan.assignments = vec![grok, codex];

        let error = authored_override_runtime(&plan, AgentRole::Worker, SupervisorRuntime::Codex)
            .expect_err("conflicting authored worker runtimes");
        let message = error.to_string();
        assert!(message.contains("conflicting authored runtimes"));
        assert!(message.contains("worker"));
    }

    #[test]
    fn explicit_debug_override_requires_parseable_effort() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let prior = codex_prior_for(|prior| {
            prior
                .class_fit
                .iter()
                .any(|class_fit| class_fit.task_class == AUTOMATIC_SELECTION_TASK_CLASS)
        })?;
        let admission = test_admission();
        let mut missing = test_plan();
        missing
            .role_models
            .insert(AgentRole::Worker, role_selection(prior.model.clone(), None));
        let error = initialize_supervisor_selection(
            &mut missing,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &AdvertisedCatalogSet::empty(),
        )
        .expect_err("missing debug effort must fail closed");
        assert!(error
            .to_string()
            .contains("debug overrides require a reasoning_effort"));

        let mut invalid = test_plan();
        invalid.role_models.insert(
            AgentRole::Worker,
            role_selection(prior.model, Some("not-an-effort")),
        );
        let error = initialize_supervisor_selection(
            &mut invalid,
            SupervisorRuntime::Codex,
            &catalog,
            &admission,
            &AdvertisedCatalogSet::empty(),
        )
        .expect_err("unparseable debug effort must fail closed");
        assert!(error.to_string().contains("unsupported reasoning_effort"));
        Ok(())
    }

    #[test]
    fn partial_profile_retains_typed_authority_refusal_instead_of_catalog_fallback() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let worker_prior = selection::built_in_prior_dataset()?
            .models
            .into_iter()
            .find(|prior| prior.model == "gpt-5.6-luna")
            .context("historical leaf-only authority fixture")?;
        assert!(worker_prior
            .prohibited_authority_roles
            .contains(&AuthorityRole::AcceptanceGate));
        let worker_effort = worker_prior
            .class_fit
            .iter()
            .find(|class_fit| class_fit.task_class == AUTOMATIC_SELECTION_TASK_CLASS)
            .map(|class_fit| selector_effort_as_str(class_fit.effort))
            .context("worker-only prior effort")?;
        let catalog =
            RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs([worker_prior
                .model
                .clone()])?);
        let mut plan = test_plan();
        plan.role_models.insert(
            AgentRole::Worker,
            role_selection(worker_prior.model, Some(worker_effort)),
        );

        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;

        assert_eq!(resolution.mode, SupervisorSelectionMode::DebugOverride);
        let failure = resolution
            .selection_preflight_failure
            .as_ref()
            .context("authority selection must fail closed")?;
        assert_eq!(failure.role, AgentRole::Supervisor);
        assert_eq!(
            failure.kind,
            SupervisorSelectionPreflightFailureKind::FailClosed
        );
        assert!(failure.message.contains("selector failed closed"));
        let decision = resolution
            .decisions
            .first()
            .context("typed authority refusal decision")?;
        assert_eq!(decision.role, AgentRole::Supervisor);
        assert_eq!(decision.provenance.status, DecisionStatus::FailClosed);
        assert!(decision.provenance.choice.is_none());
        Ok(())
    }

    #[test]
    fn debug_mode_applies_exact_selector_triple_to_plan() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let prior = codex_prior_for(|prior| {
            prior.class_fit.iter().any(|class_fit| {
                class_fit.task_class == AUTOMATIC_SELECTION_TASK_CLASS
                    && class_fit.effort == SelectorEffort::High
            })
        })?;
        let requested = CandidateKey {
            runtime: runtime_name(SupervisorRuntime::Codex).to_string(),
            model: prior.model.clone(),
            effort: SelectorEffort::High,
        };
        let mut plan = test_plan();
        plan.role_models
            .insert(AgentRole::Worker, role_selection(prior.model, Some("high")));

        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;

        assert_eq!(resolution.mode, SupervisorSelectionMode::DebugOverride);
        assert_eq!(resolution.decisions.len(), all_selector_roles().len());
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("Worker debug decision")?;
        assert_eq!(worker.attempt, 0);
        assert!(worker.assignment_id.is_none());
        assert_eq!(
            worker.primary_cause,
            SupervisorSelectionEventCause::DebugOverride
        );
        assert_eq!(
            worker
                .provenance
                .choice
                .as_ref()
                .context("debug choice")?
                .candidate,
            requested
        );
        assert!(resolution.decisions.iter().all(|decision| {
            decision.role == AgentRole::Worker
                || decision.primary_cause == SupervisorSelectionEventCause::Initial
        }));
        assert_eq!(plan.role_models.len(), all_selector_roles().len());
        assert!(plan.role_models.values().all(|selection| matches!(
            selection.unavailable_model_fallback,
            UnavailableModelFallback::FailClosed
        )));
        assert_eq!(
            plan.role_models
                .get(&AgentRole::Worker)
                .and_then(|selection| selection.reasoning_effort.as_deref()),
            Some("high")
        );
        Ok(())
    }

    #[test]
    fn custom_review_lens_refuses_its_incompatible_triple_before_dispatch() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let auditor_prior = codex_prior_for(|prior| {
            prior
                .strong_gate_fallback_efforts
                .contains(&SelectorEffort::Xhigh)
        })?;
        let other_model = "gpt-5.6-sol".to_string();
        let mut plan = test_plan();
        plan.role_models.insert(
            AgentRole::Auditor,
            role_selection(auditor_prior.model, Some("xhigh")),
        );
        plan.review_lenses = vec![ReviewLensConfig {
            id: "custom-auditor".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "openai".to_string(),
                model: other_model,
                reasoning_effort: Some("high".to_string()),
            },
            information_scope: ReviewInformationScope::FullChildTranscript,
        }];

        let authored = plan.review_lenses.clone();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;
        let failure = resolution
            .selection_preflight_failure
            .context("custom lens preflight refusal")?;
        assert!(failure.message.contains("custom-auditor"));
        assert_eq!(plan.review_lenses, authored);
        let mut precomputed = plan.clone();
        precomputed.review_lenses[0].backend = ReviewLensBackendConfig::Precomputed {
            backend_id: "fixture".to_string(),
            model: "fixture".to_string(),
            evidence_kind: crate::review::ReviewLensEvidenceKind::ProcessEvidence,
        };
        assert!(validate_custom_review_lens_contracts(&precomputed).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authored_review_lens_refusals_and_scope_exit_preserve_outer_authority() -> Result<()> {
        use crate::selection::routing_policy::*;
        use coding_agent_manager_lib::account_authority::ModelAccessOutcome;
        let _fixture_policy = bind_fixture_routing_policy()?;
        let plan = test_plan();
        let (assessment, _, frozen) = fixture_task_assessment(&plan)?;
        let _policy = bind_routing_policy(Some(frozen.clone()))?;
        let observation = qualified_account_fixture("codex-cli", FRONTIER_PROFILE_MODEL, "xhigh");
        let observations = [(SupervisorRuntime::Codex, observation.clone())];
        let (_, child) = select_normal_account_intake_with_assessment(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            None,
            Some(&assessment),
        )?;
        seal_selected_candidate(AgentRole::ChildOrchestrator.as_str(), &child)?;
        let (_, baseline) = select_account_review_auditor_with_assessment(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            Some(&assessment),
        )?;
        let before = captured_selected_authorizations();
        let catalog = codex_catalog()?;
        let lens = ReviewLensConfig {
            id: "scoped-account-review".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "openai".to_string(),
                model: FRONTIER_PROFILE_MODEL.to_string(),
                reasoning_effort: Some("xhigh".to_string()),
            },
            information_scope: ReviewInformationScope::DiffOnly,
        };
        let expected = AccountBinding::from(&observation.binding);
        for panic_after_binding in [false, true] {
            let selected = select_authored_review_lens(
                &lens,
                "xhigh",
                SupervisorRuntime::Codex,
                &catalog,
                &baseline,
                ReviewLensAccount::Selected {
                    observation: &observation,
                    expected_binding: &expected,
                },
                SupervisorQuotaSelectionInput::default(),
            )?;
            let exited =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                    let (_scope, _) = selected.bind()?;
                    validate_selected_launch("auditor", "codex", FRONTIER_PROFILE_MODEL, "xhigh")?;
                    validate_selected_launch(
                        "child_orchestrator",
                        "codex",
                        FRONTIER_PROFILE_MODEL,
                        "xhigh",
                    )?;
                    assert!(validate_selected_launch(
                        "child_orchestrator",
                        "codex",
                        FRONTIER_PROFILE_MODEL,
                        "low"
                    )
                    .is_err());
                    if panic_after_binding {
                        panic!("fixture preparation unwind");
                    }
                    bail!("fixture preparation refusal")
                }));
            assert!(matches!(exited, Err(_) | Ok(Err(_))));
            assert_eq!(captured_selected_authorizations(), before);
        }
        for refusal in [
            "account-drift",
            "access-loss",
            "stale",
            "unsupported-effort",
            "ineligible-model",
        ] {
            let mut changed = observation.clone();
            let mut changed_lens = lens.clone();
            match refusal {
                "account-drift" => changed.binding.selection_revision += 1,
                "access-loss" => {
                    changed
                        .models
                        .as_mut()
                        .unwrap()
                        .content
                        .as_mut()
                        .unwrap()
                        .models[0]
                        .access = ModelAccessOutcome::Unavailable
                }
                "stale" => changed.models.as_mut().unwrap().outcome = ObservationOutcome::Stale,
                "unsupported-effort" => {
                    let ReviewLensBackendConfig::Model {
                        reasoning_effort, ..
                    } = &mut changed_lens.backend
                    else {
                        unreachable!()
                    };
                    *reasoning_effort = Some("high".to_string());
                }
                "ineligible-model" => {
                    let ReviewLensBackendConfig::Model { model, .. } = &mut changed_lens.backend
                    else {
                        unreachable!()
                    };
                    *model = ECONOMY_PROFILE_MODEL.to_string();
                    changed
                        .models
                        .as_mut()
                        .unwrap()
                        .content
                        .as_mut()
                        .unwrap()
                        .models[0]
                        .model_id = ECONOMY_PROFILE_MODEL.to_string();
                }
                _ => unreachable!(),
            }
            let result = select_authored_review_lens(
                &changed_lens,
                changed_lens.backend.reasoning_effort().unwrap(),
                SupervisorRuntime::Codex,
                &catalog,
                &baseline,
                ReviewLensAccount::Selected {
                    observation: &changed,
                    expected_binding: &expected,
                },
                SupervisorQuotaSelectionInput::default(),
            );
            assert!(result.is_err(), "{refusal} must not grant lens authority");
            assert_eq!(captured_selected_authorizations(), before);
        }
        let mut strict = frozen.clone();
        strict.policy.default_role.minimum_effort = Some(SelectorEffort::Xhigh);
        strict.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&strict.policy)?);
        let _strict_policy = bind_routing_policy(Some(strict.clone()))?;
        let (assessment, _) = fixture_task_assessment_for_policy(&plan, &strict)?;
        let mut supported = observation.clone();
        supported
            .models
            .as_mut()
            .unwrap()
            .content
            .as_mut()
            .unwrap()
            .models[0]
            .supported_efforts = Some(vec!["high".to_string(), "xhigh".to_string()]);
        let (_, strict_baseline) = select_account_review_auditor_with_assessment(
            &plan,
            &strict,
            &[(SupervisorRuntime::Codex, supported.clone())],
            &test_admission(),
            &default_resolved_profile(),
            Some(&assessment),
        )?;
        let before = captured_selected_authorizations();
        let mut high = lens.clone();
        let ReviewLensBackendConfig::Model {
            reasoning_effort, ..
        } = &mut high.backend
        else {
            unreachable!()
        };
        *reasoning_effort = Some("high".to_string());
        let error = select_authored_review_lens(
            &high,
            "high",
            SupervisorRuntime::Codex,
            &catalog,
            &strict_baseline,
            ReviewLensAccount::Selected {
                observation: &supported,
                expected_binding: &expected,
            },
            SupervisorQuotaSelectionInput::default(),
        )
        .err()
        .context("loaded minimum must refuse an account-supported high-effort lens")?;
        assert!(format!("{error:#}").contains("effort is below the loaded policy preference"));
        assert_eq!(captured_selected_authorizations(), before);
        Ok(())
    }

    #[test]
    fn legacy_explicit_selection_bypass_is_nonpublishable_and_never_automatic() {
        let empty = test_plan();
        assert!(uses_legacy_nonpublishable_explicit_selection(
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &empty,
        ));
        assert!(!uses_legacy_nonpublishable_explicit_selection(
            SupervisorExecutionRuntime::Verified,
            &empty,
        ));

        let mut explicit = test_plan();
        explicit.role_models.insert(
            AgentRole::Worker,
            role_selection("legacy-injected-model".to_string(), Some("high")),
        );
        assert!(uses_legacy_nonpublishable_explicit_selection(
            SupervisorExecutionRuntime::NonpublishableSimulation,
            &explicit,
        ));
        assert!(!uses_legacy_nonpublishable_explicit_selection(
            SupervisorExecutionRuntime::Verified,
            &explicit,
        ));
    }

    #[test]
    fn degrade_reselection_is_deterministic_and_returns_exact_executable_overrides() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, state) = automatic_state()?;
        let mut first_state = state.clone();
        let first = reselect_roles_from_supplied_catalog_snapshot(
            &mut first_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[
                AgentRole::Auditor,
                AgentRole::Worker,
                AgentRole::ChildOrchestrator,
                AgentRole::Worker,
            ],
            0,
            BudgetSignal::Degrade,
            &[],
        )?;
        let mut second_state = state;
        let second = reselect_roles_from_supplied_catalog_snapshot(
            &mut second_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[
                AgentRole::ChildOrchestrator,
                AgentRole::Worker,
                AgentRole::Auditor,
            ],
            0,
            BudgetSignal::Degrade,
            &[],
        )?;

        assert_eq!(first.decisions, second.decisions);
        assert_eq!(
            first
                .decisions
                .iter()
                .map(|(role, _)| *role)
                .collect::<Vec<_>>(),
            vec![
                AgentRole::ChildOrchestrator,
                AgentRole::Worker,
                AgentRole::Auditor,
            ]
        );
        for (role, decision) in &first.decisions {
            assert!(decision
                .triggers
                .contains(&selection::SelectionTrigger::BudgetDegrade));
            let choice = decision.choice.as_ref().context("degrade choice")?;
            let override_selection = first.overrides.get(role).context("role override")?;
            assert_eq!(
                override_selection.model.as_deref(),
                Some(choice.candidate.model.as_str())
            );
            assert_eq!(
                override_selection.reasoning_effort.as_deref(),
                Some(selector_effort_as_str(choice.candidate.effort))
            );
            assert_eq!(
                first.runtime_overrides.get(role),
                Some(&runtime_from_name(&choice.candidate.runtime)?)
            );
        }
        Ok(())
    }

    fn this_run_attempt_evidence(
        candidate: &CandidateKey,
        task: &TaskProfile,
        result: crate::selection::OutcomeResult,
        failure_class: Option<crate::selection::FailureClass>,
    ) -> AttemptOutcomeEvidence {
        AttemptOutcomeEvidence {
            pricing: Vec::new(),
            version: 1,
            run_id: "this-run".to_string(),
            assignment_id: "assignment-1".to_string(),
            attempt: 1,
            verified_execution: true,
            selection: Some(AttemptSelectionBinding {
                role: AgentRole::Worker,
                event_assignment_id: None,
                event_attempt: 0,
                normalized_input_sha256: "this-run-digest".to_string(),
                task: task.clone(),
                assignment_shape_identity: None,
                requested_candidate: candidate.clone(),
            }),
            requested_runtime: candidate.runtime.clone(),
            requested_model: Some(candidate.model.clone()),
            requested_effort: Some(selector_effort_as_str(candidate.effort).to_string()),
            observed_candidate: Some(candidate.clone()),
            parent_result: Some(result),
            parent_cause: Some("parent_terminal_result".to_string()),
            failure_class,
            costs: AttemptAttributableCosts {
                execution_cost_microunits: Some(50_000),
                review_cost_microunits: Some(10_000),
                rework_cost_microunits: Some(0),
                rereview_cost_microunits: Some(0),
                environment_cost_microunits: Some(0),
            },
            parent_phase_continuation: None,
        }
    }

    fn posterior_quality_for(
        reselection: &SupervisorReselection,
        candidate: &CandidateKey,
    ) -> Result<u16> {
        reselection
            .decisions
            .first()
            .context("reselect decision")?
            .1
            .candidate_set
            .iter()
            .find(|item| item.candidate == *candidate)
            .and_then(|item| item.score.as_ref())
            .map(|score| score.posterior_quality_basis_points)
            .context("candidate posterior quality")
    }

    #[test]
    fn this_run_rejected_or_accepted_attempt_moves_reselect_posterior() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, state) = automatic_state()?;
        let worker = state
            .decisions
            .get(&AgentRole::Worker)
            .context("worker decision")?;
        let candidate = worker
            .choice
            .as_ref()
            .context("worker choice")?
            .candidate
            .clone();
        let task = worker.normalized_input.task.clone();

        let mut baseline_state = state.clone();
        let baseline = reselect_roles_from_supplied_catalog_snapshot(
            &mut baseline_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        let baseline_quality = posterior_quality_for(&baseline, &candidate)?;
        assert!(baseline.decisions[0].1.normalized_input.outcomes.is_empty());

        let rejected = outcome_record_from_this_run_attempt(&this_run_attempt_evidence(
            &candidate,
            &task,
            crate::selection::OutcomeResult::Rejected,
            Some(crate::selection::FailureClass::ModelQuality),
        ))
        .context("rejected this-run outcome")?;
        let mut rejected_state = state.clone();
        rejected_state.set_this_run_outcomes(vec![rejected], Vec::new());
        let rejected_reselect = reselect_roles_from_supplied_catalog_snapshot(
            &mut rejected_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        let rejected_quality = posterior_quality_for(&rejected_reselect, &candidate)?;
        assert_ne!(baseline_quality, rejected_quality);
        assert_eq!(
            rejected_reselect.decisions[0]
                .1
                .normalized_input
                .outcomes
                .len(),
            1
        );

        let accepted = outcome_record_from_this_run_attempt(&this_run_attempt_evidence(
            &candidate,
            &task,
            crate::selection::OutcomeResult::Accepted,
            None,
        ))
        .context("accepted this-run outcome")?;
        let mut accepted_state = state;
        accepted_state.set_this_run_outcomes(vec![accepted], Vec::new());
        let accepted_reselect = reselect_roles_from_supplied_catalog_snapshot(
            &mut accepted_state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        let accepted_quality = posterior_quality_for(&accepted_reselect, &candidate)?;
        assert_ne!(baseline_quality, accepted_quality);
        assert_eq!(
            accepted_reselect.decisions[0]
                .1
                .normalized_input
                .outcomes
                .len(),
            1
        );
        Ok(())
    }

    #[test]
    fn this_run_cost_only_attempt_does_not_move_reselect_posterior() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, mut state) = automatic_state()?;
        let worker = state
            .decisions
            .get(&AgentRole::Worker)
            .context("worker decision")?;
        let candidate = worker
            .choice
            .as_ref()
            .context("worker choice")?
            .candidate
            .clone();
        let task = worker.normalized_input.task.clone();
        let mut cost_only = this_run_attempt_evidence(
            &candidate,
            &task,
            crate::selection::OutcomeResult::Accepted,
            None,
        );
        cost_only.parent_result = None;
        assert!(outcome_record_from_this_run_attempt(&cost_only).is_none());

        let baseline = reselect_roles_from_supplied_catalog_snapshot(
            &mut state.clone(),
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        state.set_this_run_outcomes(
            this_run_outcome_records(std::slice::from_ref(&cost_only)),
            Vec::new(),
        );
        let with_cost_only = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        assert_eq!(
            posterior_quality_for(&baseline, &candidate)?,
            posterior_quality_for(&with_cost_only, &candidate)?
        );
        assert!(with_cost_only.decisions[0]
            .1
            .normalized_input
            .outcomes
            .is_empty());
        Ok(())
    }

    #[test]
    fn this_run_exclusions_append_to_existing_outcome_history() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, mut state) = automatic_state()?;
        let frozen = crate::selection::AuthenticatedOutcomeHistoryProvenance {
            snapshot_sha256: "a".repeat(64),
            source_digests: vec!["b".repeat(64)],
            exclusions: vec!["frozen:unreadable_attempt".to_string()],
            projected_attempt_count: 1,
        };
        for provenance in state.decisions.values_mut() {
            provenance.outcome_history = Some(frozen.clone());
        }
        state.set_this_run_outcomes(
            Vec::new(),
            vec!["corrupt.attempt-2.json:invalid_attempt".to_string()],
        );
        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        let history = reselection.decisions[0]
            .1
            .outcome_history
            .as_ref()
            .context("frozen history provenance must remain present")?;
        assert_eq!(history.snapshot_sha256, frozen.snapshot_sha256);
        assert_eq!(history.source_digests, frozen.source_digests);
        assert_eq!(history.projected_attempt_count, 1);
        assert_eq!(
            history.exclusions,
            vec![
                "corrupt.attempt-2.json:invalid_attempt".to_string(),
                "frozen:unreadable_attempt".to_string(),
            ]
        );
        Ok(())
    }

    #[test]
    fn degrade_transition_retains_previous_choice_and_switch_score_evidence() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (_, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("immediately prior worker choice")?
            .candidate
            .clone();
        state.advertised = advertised_with_grok(discover_grok_observation(&grok_listing(
            "grok-4.6",
            &["  * grok-4.6 (default)"],
        ))?);
        // This fixture permits the unchanged Grok worker as an alternate runtime.
        let worker_input = &mut state
            .decisions
            .get_mut(&AgentRole::Worker)
            .unwrap()
            .normalized_input;
        worker_input
            .constraints
            .allowed_runtimes
            .insert("grok".into());
        let mut grok_pool = worker_input.pools[0].clone();
        grok_pool.runtime = "grok".into();
        worker_input.pools.push(grok_pool);
        let priors = selection::built_in_prior_dataset()?;
        let withdrawn_catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(
            priors
                .models
                .iter()
                .filter(|prior| {
                    prior.runtime == runtime_name(SupervisorRuntime::Codex)
                        && prior.model != previous.model
                })
                .map(|prior| prior.model.clone()),
        )?);

        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &withdrawn_catalog,
            &[AgentRole::Worker],
            0,
            BudgetSignal::Degrade,
            &[],
        )?;
        let decision = &reselection.decisions[0].1;
        assert!(decision
            .triggers
            .contains(&selection::SelectionTrigger::BudgetDegrade));
        assert!(decision
            .triggers
            .contains(&selection::SelectionTrigger::CatalogChange));
        assert_eq!(
            decision.normalized_input.signals.previous_choice.as_ref(),
            Some(&previous)
        );

        let choice = decision
            .choice
            .as_ref()
            .context("degrade transition selected choice")?;
        assert_eq!(choice.candidate.runtime, "grok");
        assert_eq!(choice.candidate.model, "grok-4.6");
        assert_ne!(choice.candidate.model, previous.model);
        assert_eq!(
            choice.switch_transition,
            selection::ContextSwitchTransition::RuntimeChange
        );
        assert_eq!(
            choice.configured_switch_cost_microunits,
            crate::objective_profile::DEFAULT_RUNTIME_CHANGE_SWITCH_COST_MICROUNITS
        );
        assert!(choice.configured_switch_cost_microunits > 0);
        assert!(choice.switch_cost_microunits > 0);
        assert_eq!(
            reselection.runtime_overrides.get(&AgentRole::Worker),
            Some(&runtime_from_name(&choice.candidate.runtime)?)
        );

        let selected_score = decision
            .candidate_set
            .iter()
            .find(|candidate| candidate.candidate == choice.candidate)
            .and_then(|candidate| candidate.score.as_ref())
            .context("degrade transition candidate score")?;
        assert_eq!(selected_score.switch_transition, choice.switch_transition);
        assert_eq!(
            selected_score.configured_switch_cost_microunits,
            choice.configured_switch_cost_microunits
        );
        assert_eq!(
            selected_score.switch_cost_microunits,
            choice.switch_cost_microunits
        );
        assert_eq!(
            selected_score.total_score_microunits,
            choice.total_score_microunits
        );
        let expected_total = [
            selected_score.expected_total_cost_per_accepted_task_microunits,
            selected_score.pool_pressure_cost_microunits,
            selected_score.entitlement_scarcity_cost_microunits,
            selected_score.observed_consumption_cost_microunits,
            selected_score.marginal_cost_microunits,
            selected_score.retry_cost_microunits,
            selected_score.degrade_cost_microunits,
            selected_score.switch_cost_microunits,
        ]
        .into_iter()
        .try_fold(0u64, |total, term| total.checked_add(term))
        .context("degrade transition expected score overflow")?;
        assert_eq!(selected_score.total_score_microunits, expected_total);
        Ok(())
    }

    #[test]
    fn retry_penalizes_only_previous_choice_and_changes_worker_choice() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("initial worker choice")?
            .candidate
            .clone();

        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            3,
            BudgetSignal::Continue,
            &[],
        )?;
        let decision = &reselection.decisions[0].1;
        let choice = decision.choice.as_ref().context("retry worker choice")?;

        assert!(decision
            .triggers
            .contains(&selection::SelectionTrigger::Retry));
        assert_eq!(
            decision.normalized_input.signals.previous_choice.as_ref(),
            Some(&previous)
        );
        assert_ne!(choice.candidate, previous);
        let previous_score = decision
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == previous)
            .and_then(|evaluation| evaluation.score.as_ref())
            .context("previous candidate retry score")?;
        let selected_score = decision
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == choice.candidate)
            .and_then(|evaluation| evaluation.score.as_ref())
            .context("selected candidate retry score")?;
        assert!(previous_score.retry_cost_microunits > 0);
        assert_eq!(selected_score.retry_cost_microunits, 0);
        assert!(
            selected_score.total_score_microunits < previous_score.total_score_microunits,
            "retry penalty must make the replacement cheaper after conservative switch cost"
        );
        let expected_transition = if choice.candidate.runtime != previous.runtime {
            selection::ContextSwitchTransition::RuntimeChange
        } else if choice.candidate.model != previous.model {
            selection::ContextSwitchTransition::ModelChangeSameRuntime
        } else {
            selection::ContextSwitchTransition::EffortChangeSameRuntimeModel
        };
        assert_eq!(choice.switch_transition, expected_transition);
        assert_eq!(selected_score.switch_transition, expected_transition);
        assert_eq!(
            selected_score.switch_cost_microunits,
            choice.switch_cost_microunits
        );
        Ok(())
    }

    #[test]
    fn sequential_reselection_uses_immediately_prior_selected_choice() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, mut state) = automatic_state()?;
        let first = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        let first_choice = first.decisions[0]
            .1
            .choice
            .as_ref()
            .context("first retry worker choice")?
            .candidate
            .clone();

        let second = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            0,
            BudgetSignal::Degrade,
            &[],
        )?;
        let second_provenance = &second.decisions[0].1;

        assert_eq!(
            second_provenance
                .normalized_input
                .signals
                .previous_choice
                .as_ref(),
            Some(&first_choice)
        );
        assert!(second_provenance
            .triggers
            .contains(&selection::SelectionTrigger::BudgetDegrade));
        Ok(())
    }

    #[test]
    fn failed_multi_role_reselection_does_not_commit_partial_state() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, mut state) = automatic_state()?;
        let worker_before = state
            .decisions
            .get(&AgentRole::Worker)
            .context("initial worker provenance")?
            .clone();
        state.decisions.remove(&AgentRole::Auditor);

        let error = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker, AgentRole::Auditor],
            1,
            BudgetSignal::Continue,
            &[],
        )
        .expect_err("missing later role state must fail the whole reselection");

        assert!(error
            .to_string()
            .contains("automatic selector has no replay state for role 'auditor'"));
        assert_eq!(
            state.decisions.get(&AgentRole::Worker),
            Some(&worker_before)
        );
        Ok(())
    }

    #[test]
    fn supplied_catalog_withdrawal_records_change_and_reselects() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (_, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("initial worker choice")?
            .candidate
            .clone();
        state.advertised = advertised_with_grok(discover_grok_observation(&grok_listing(
            "grok-4.6",
            &["  * grok-4.6 (default)"],
        ))?);
        // This fixture permits the unchanged Grok worker as an alternate runtime.
        let worker_input = &mut state
            .decisions
            .get_mut(&AgentRole::Worker)
            .unwrap()
            .normalized_input;
        worker_input
            .constraints
            .allowed_runtimes
            .insert("grok".into());
        let mut grok_pool = worker_input.pools[0].clone();
        grok_pool.runtime = "grok".into();
        worker_input.pools.push(grok_pool);
        let priors = selection::built_in_prior_dataset()?;
        let withdrawn_catalog = RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(
            priors
                .models
                .iter()
                .filter(|prior| {
                    prior.runtime == runtime_name(SupervisorRuntime::Codex)
                        && prior.model != previous.model
                })
                .map(|prior| prior.model.clone()),
        )?);

        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &withdrawn_catalog,
            &[AgentRole::Worker],
            0,
            BudgetSignal::Continue,
            &[],
        )?;
        let decision = &reselection.decisions[0].1;

        assert!(decision
            .triggers
            .contains(&selection::SelectionTrigger::CatalogChange));
        assert_eq!(
            decision.normalized_input.signals.previous_choice.as_ref(),
            Some(&previous)
        );
        let replacement = decision.choice.as_ref().context("replacement choice")?;
        assert_ne!(replacement.candidate, previous);
        assert_eq!(
            replacement.switch_transition,
            selection::ContextSwitchTransition::RuntimeChange
        );
        assert_eq!(
            replacement.configured_switch_cost_microunits,
            crate::objective_profile::DEFAULT_RUNTIME_CHANGE_SWITCH_COST_MICROUNITS
        );
        assert!(replacement.switch_cost_microunits > 0);
        let replacement_choice = replacement.candidate.clone();
        let after_catalog_change = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &withdrawn_catalog,
            &[AgentRole::Worker],
            0,
            BudgetSignal::Degrade,
            &[],
        )?;
        assert_eq!(
            after_catalog_change.decisions[0]
                .1
                .normalized_input
                .signals
                .previous_choice
                .as_ref(),
            Some(&replacement_choice)
        );
        Ok(())
    }

    #[test]
    fn typed_environment_rejection_never_falls_back_to_another_codex_model() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let (catalog, mut state) = automatic_state()?;
        let previous = state.decisions[&AgentRole::Worker]
            .choice
            .as_ref()
            .unwrap()
            .candidate
            .clone();
        assert_eq!(previous.model, "gpt-6.1-sol");
        let rejection = TypedSelectorEnvironmentRejection {
            role: AgentRole::Worker,
            rejection: selection::EnvironmentRejectionState {
                candidate: previous.clone(),
                rejection_code: "native_multiagent_v2_model_rejected".into(),
                evidence_id: "typed-runtime-rejection-1".into(),
                fallback_transition_used: false,
            },
        };
        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            0,
            BudgetSignal::Continue,
            &[rejection],
        )?;
        let decision = &reselection.decisions[0].1;
        assert!(decision.environment_fallback.is_none());
        assert_eq!(
            decision.normalized_input.signals.previous_choice.as_ref(),
            Some(&previous)
        );
        assert!(decision
            .candidate_set
            .iter()
            .any(|c| c.candidate == previous && !c.eligible));
        let choice = decision
            .choice
            .as_ref()
            .context("same-model effort recovery")?;
        assert_eq!(choice.candidate.model, "gpt-6.1-sol");
        assert_ne!(choice.candidate.effort, previous.effort);
        Ok(())
    }

    const CAPTURED_CURSOR_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/captured-minimal-20260820.txt"
    ));
    const WITHDRAWN_CURSOR_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/cursor/hand-authored-withdrawn.txt"
    ));
    const CAPTURED_GROK_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/captured-minimal-20260821.txt"
    ));
    const CAPTURED_GROK_47_CATALOG: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/runtime_adapter/grok/captured-minimal-20260922.txt"
    ));
    const CAPTURED_CURSOR_AT_UNIX_MILLIS: u64 = 1_787_240_463_000;

    struct FakeCursorRunner {
        output: crate::runtime_adapter::cursor::CursorCatalogCommandOutput,
    }

    impl FakeCursorRunner {
        fn successful(stdout: &[u8]) -> Self {
            Self {
                output: crate::runtime_adapter::cursor::CursorCatalogCommandOutput {
                    status: Some(0),
                    stdout: stdout.to_vec(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                    process_tree: crate::process_runner::ProcessTreeEvidence::VerifiedEmpty(
                        crate::process_runner::ContainmentBackend::DirectChild,
                    ),
                    side_effects: crate::process_runner::SideEffectConfinementEvidence::Verified(
                        crate::process_runner::SideEffectConfinementProfileKind::TrustedFixedNetwork,
                    ),
                },
            }
        }
    }

    impl crate::runtime_adapter::cursor::CursorCatalogCommandRunner for FakeCursorRunner {
        fn run(
            &self,
            _spec: &crate::runtime_adapter::cursor::CursorCatalogCommandSpec,
        ) -> Result<crate::runtime_adapter::cursor::CursorCatalogCommandOutput> {
            Ok(self.output.clone())
        }
    }

    fn captured_cursor_observation(
    ) -> Result<crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation> {
        crate::runtime_adapter::cursor::discover_cursor_model_catalog(
            &FakeCursorRunner::successful(CAPTURED_CURSOR_CATALOG),
            &crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new("/workspace"),
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS),
        )
    }

    fn withdrawn_cursor_observation(
    ) -> Result<crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation> {
        crate::runtime_adapter::cursor::discover_cursor_model_catalog(
            &FakeCursorRunner::successful(WITHDRAWN_CURSOR_CATALOG),
            &crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new("/workspace"),
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS),
        )
    }

    fn advertised_with_cursor(
        observation: crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation,
    ) -> AdvertisedCatalogSet {
        AdvertisedCatalogSet {
            cursor: Some(observation),
            grok: None,
            cursor_evidence_gap: None,
        }
    }

    fn advertised_with_cursor_gap(detail: &str) -> AdvertisedCatalogSet {
        AdvertisedCatalogSet {
            cursor: None,
            grok: None,
            cursor_evidence_gap: Some(CursorCatalogEvidenceGap::from_error(
                &anyhow!(detail.to_string()),
                CAPTURED_CURSOR_AT_UNIX_MILLIS,
            )),
        }
    }

    struct FakeGrokRunner {
        output: crate::runtime_adapter::grok::GrokCatalogCommandOutput,
        observed_specs: RefCell<Vec<crate::runtime_adapter::grok::GrokCatalogCommandSpec>>,
    }

    impl FakeGrokRunner {
        fn successful(stdout: &[u8]) -> Self {
            Self {
                output: crate::runtime_adapter::grok::GrokCatalogCommandOutput {
                    status: Some(0),
                    stdout: stdout.to_vec(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                    timed_out: false,
                    process_tree: crate::process_runner::ProcessTreeEvidence::VerifiedEmpty(
                        crate::process_runner::ContainmentBackend::DirectChild,
                    ),
                    side_effects: crate::process_runner::SideEffectConfinementEvidence::Verified(
                        crate::process_runner::SideEffectConfinementProfileKind::TrustedFixedNetwork,
                    ),
                },
                observed_specs: RefCell::new(Vec::new()),
            }
        }
    }

    impl crate::runtime_adapter::grok::GrokCatalogCommandRunner for FakeGrokRunner {
        fn run(
            &self,
            spec: &crate::runtime_adapter::grok::GrokCatalogCommandSpec,
        ) -> Result<crate::runtime_adapter::grok::GrokCatalogCommandOutput> {
            self.observed_specs.borrow_mut().push(spec.clone());
            Ok(self.output.clone())
        }
    }

    struct MissingGrokRunner;

    impl crate::runtime_adapter::grok::GrokCatalogCommandRunner for MissingGrokRunner {
        fn run(
            &self,
            _spec: &crate::runtime_adapter::grok::GrokCatalogCommandSpec,
        ) -> Result<crate::runtime_adapter::grok::GrokCatalogCommandOutput> {
            bail!("Grok catalog executable 'grok' is missing")
        }
    }

    struct UnavailableGrokRunner(&'static str);

    impl crate::runtime_adapter::grok::GrokCatalogCommandRunner for UnavailableGrokRunner {
        fn run(
            &self,
            _spec: &crate::runtime_adapter::grok::GrokCatalogCommandSpec,
        ) -> Result<crate::runtime_adapter::grok::GrokCatalogCommandOutput> {
            bail!(self.0)
        }
    }

    fn grok_listing(default: &str, model_lines: &[&str]) -> Vec<u8> {
        let mut text = format!(
            "You are logged in with grok.com.\n\nDefault model: {default}\n\nAvailable models:\n"
        );
        if !model_lines.is_empty() {
            text.push_str(&model_lines.join("\n"));
            text.push('\n');
        }
        text.into_bytes()
    }

    fn discover_grok_observation(
        stdout: &[u8],
    ) -> Result<crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation> {
        crate::runtime_adapter::grok::discover_grok_model_catalog(
            &FakeGrokRunner::successful(stdout),
            &crate::runtime_adapter::grok::GrokCatalogCommandSpec::new("/workspace"),
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS),
        )
    }

    fn advertised_with_grok(
        observation: crate::runtime_adapter::grok::GrokAdvertisedCatalogObservation,
    ) -> AdvertisedCatalogSet {
        AdvertisedCatalogSet {
            cursor: None,
            grok: Some(observation),
            cursor_evidence_gap: None,
        }
    }

    fn worker_assignment() -> OrchestratorAssignment {
        OrchestratorAssignment {
            assignment_shape: None,
            id: "worker-a".to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::Worker,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("README.md")],
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

    #[test]
    fn captured_cursor_catalog_makes_composer_slugs_selectable_without_operator_lists() -> Result<()>
    {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let observation = captured_cursor_observation()?;
        assert!(observation.catalog().contains("composer-2.5"));
        assert!(observation.catalog().contains("composer-2.5-fast"));

        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(observation),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        for slug in ["composer-2.5", "composer-2.5-fast"] {
            assert!(
                worker
                    .provenance
                    .candidate_set
                    .iter()
                    .any(|evaluation| evaluation.candidate.runtime == "cursor"
                        && evaluation.candidate.model == slug
                        && evaluation.eligible),
                "{slug} must be an eligible advertised Worker candidate"
            );
        }
        let fresh = worker
            .provenance
            .choice
            .as_ref()
            .context("fresh worker choice")?;
        assert_eq!(fresh.candidate.runtime, "codex");

        let mut pressured = worker.provenance.normalized_input.clone();
        pressured
            .pools
            .iter_mut()
            .find(|pool| pool.runtime == "codex")
            .context("Codex pool")?
            .pool_pressure_basis_points = 10_000;
        let pressured = selection::select(&pressured)?;
        let choice = pressured.choice.as_ref().context("pressured choice")?;
        assert_eq!(choice.candidate.runtime, "cursor");
        assert!(
            choice.candidate.model == "composer-2.5"
                || choice.candidate.model == "composer-2.5-fast"
        );
        Ok(())
    }

    #[test]
    fn runtime_reselection_returns_matching_executable_runtime_binding() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let frozen = crate::selection::routing_policy::current_routing_policy()
            .context("runtime reselection fixture policy")?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(captured_cursor_observation()?),
        )?;
        let mut state = resolution
            .automatic_state
            .context("automatic runtime-switch replay state")?;
        let initial_policy_receipt = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.routing_policy.as_ref())
            .context("initial worker frozen-policy receipt")?
            .clone();
        assert_eq!(initial_policy_receipt.frozen, frozen);
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("initial worker choice")?
            .candidate
            .clone();
        assert_eq!(previous.runtime, "codex");
        let codex_pool = state
            .decisions
            .get_mut(&AgentRole::Worker)
            .context("worker replay state")?
            .normalized_input
            .pools
            .iter_mut()
            .find(|pool| pool.runtime == "codex")
            .context("Codex replay pool")?;
        codex_pool.pool_pressure_basis_points = 10_000;
        codex_pool.marginal_cost_microunits = 3_000_000;

        let reselection = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        let choice = reselection.decisions[0]
            .1
            .choice
            .as_ref()
            .context("runtime-switch worker choice")?;

        assert_eq!(
            reselection.decisions[0]
                .1
                .normalized_input
                .signals
                .previous_choice
                .as_ref(),
            Some(&previous)
        );
        assert_eq!(
            choice.switch_transition,
            selection::ContextSwitchTransition::RuntimeChange
        );
        assert_eq!(choice.reason, selection::ChoiceReason::LoadedRoutingPolicy);
        assert_eq!(
            reselection.decisions[0].1.routing_policy.as_ref(),
            Some(&initial_policy_receipt),
            "runtime replay must preserve the exact frozen policy, role, and assessed task features"
        );
        assert_eq!(choice.candidate.runtime, "cursor");
        let previous_score = reselection.decisions[0]
            .1
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == previous)
            .and_then(|evaluation| evaluation.score.as_ref())
            .context("pressured previous runtime score")?;
        let selected_score = reselection.decisions[0]
            .1
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == choice.candidate)
            .and_then(|evaluation| evaluation.score.as_ref())
            .context("selected runtime-switch score")?;
        assert!(previous_score.marginal_cost_microunits > 0);
        assert!(
            selected_score.total_score_microunits < previous_score.total_score_microunits,
            "bounded Codex pool cost must make the runtime switch cheaper"
        );
        assert_eq!(
            reselection.runtime_overrides.get(&AgentRole::Worker),
            Some(&SupervisorRuntime::Cursor)
        );
        assert_eq!(
            reselection
                .overrides
                .get(&AgentRole::Worker)
                .and_then(|selection| selection.model.as_deref()),
            Some(choice.candidate.model.as_str())
        );
        Ok(())
    }

    #[test]
    fn withdrawn_cursor_catalog_removes_composer_candidates() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(withdrawn_cursor_observation()?),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert!(worker.provenance.candidate_set.iter().all(|evaluation| {
            evaluation.candidate.runtime != "cursor"
                || !evaluation.candidate.model.starts_with("composer-2.5")
        }));
        Ok(())
    }

    #[test]
    fn composer_stays_fail_closed_for_judgment_roles_under_codex_pressure() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(captured_cursor_observation()?),
        )?;
        for role in [
            AgentRole::Supervisor,
            AgentRole::Auditor,
            AgentRole::GateClassifier,
            AgentRole::ChildOrchestrator,
        ] {
            let decision = resolution
                .decisions
                .iter()
                .find(|decision| decision.role == role)
                .with_context(|| format!("{} decision", role.as_str()))?;
            let mut pressured = decision.provenance.normalized_input.clone();
            if let Some(pool) = pressured
                .pools
                .iter_mut()
                .find(|pool| pool.runtime == "codex")
            {
                pool.pool_pressure_basis_points = 10_000;
            }
            let pressured = selection::select(&pressured)?;
            if let Some(choice) = &pressured.choice {
                assert_ne!(choice.candidate.runtime, "cursor", "{}", role.as_str());
                assert!(!choice.candidate.model.starts_with("composer-2.5"));
            }
        }
        Ok(())
    }

    #[test]
    fn supervisor_launch_catalogs_stay_empty_under_cargo_test() -> Result<()> {
        let catalogs = advertised_catalogs_for_launch(Path::new("/workspace"))?;
        assert_eq!(catalogs, AdvertisedCatalogSet::empty());
        Ok(())
    }

    #[test]
    fn cursor_optional_catalog_classifier_accepts_unavailability_not_integrity_failures() {
        assert!(cursor_catalog_optional_unavailability(&anyhow!(
            "Cursor catalog binary 'cursor-agent' is missing"
        )));
        assert!(cursor_catalog_optional_unavailability(&anyhow!(
            "Cursor runtime model catalog command failed with exit status Some(7)"
        )));
        assert!(cursor_catalog_optional_unavailability(&anyhow!(
            "Cursor runtime model catalog command timed out"
        )));
        assert!(!cursor_catalog_optional_unavailability(&anyhow!(
            "Cursor runtime model catalog has an invalid header"
        )));
        assert!(!cursor_catalog_optional_unavailability(&anyhow!(
            "Cursor runtime model catalog side-effect confinement was not verified"
        )));
    }

    #[test]
    fn optional_cursor_gap_becomes_unavailable_catalog_and_ledger_evidence() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let advertised = advertised_with_cursor_gap("cursor-agent was not found");
        let mut plan = test_plan();
        plan.assignments = vec![worker_assignment()];

        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised,
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        let cursor_revision = worker
            .provenance
            .catalog_revisions
            .iter()
            .find(|revision| revision.runtime == "cursor")
            .context("Cursor unavailable catalog revision")?;
        assert!(cursor_revision
            .revision
            .starts_with("cursor-unavailable-sha256:"));
        assert_eq!(
            cursor_revision.advertised_at,
            CAPTURED_CURSOR_AT_UNIX_MILLIS.to_string()
        );
        assert!(worker.provenance.candidate_set.iter().any(|candidate| {
            candidate.candidate.runtime == "cursor"
                && candidate
                    .ineligibility_reasons
                    .iter()
                    .any(|reason| reason.code == selection::IneligibilityCode::CatalogUnavailable)
        }));
        for role in [AgentRole::GateClassifier, AgentRole::Auditor] {
            let judgment = resolution
                .decisions
                .iter()
                .find(|decision| decision.role == role)
                .with_context(|| format!("{} decision", role.as_str()))?;
            assert!(judgment
                .provenance
                .candidate_set
                .iter()
                .all(|candidate| candidate.candidate.runtime != "cursor"));
        }

        let ledger = build_assignment_selection_ledger(
            &plan,
            &resolution.decisions,
            SupervisorRuntime::Codex,
        );
        let worker_entry = ledger
            .iter()
            .find(|entry| entry.role == AgentRole::Worker)
            .context("worker ledger entry")?;
        assert!(worker_entry
            .evidence_gap
            .as_deref()
            .is_some_and(|gap| gap.contains(&cursor_revision.revision)));
        for role in [AgentRole::GateClassifier, AgentRole::Auditor] {
            let judgment_entry = ledger
                .iter()
                .find(|entry| entry.role == role)
                .with_context(|| format!("{} ledger entry", role.as_str()))?;
            assert!(judgment_entry
                .evidence_gap
                .as_deref()
                .is_some_and(|gap| gap.contains(&cursor_revision.revision)));
        }
        Ok(())
    }

    #[test]
    fn selected_cursor_runtime_fails_preflight_on_catalog_gap() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let advertised = advertised_with_cursor_gap("catalog output was malformed");
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Cursor,
            &RuntimeModelCatalog::OperatorDeclared,
            &test_admission(),
            &advertised,
        )?;

        assert!(resolution.decisions.is_empty());
        assert!(plan.role_models.is_empty());
        let failure = resolution
            .selection_preflight_failure
            .context("Cursor catalog preflight failure")?;
        assert_eq!(
            failure.kind,
            SupervisorSelectionPreflightFailureKind::FailClosed
        );
        assert!(failure.message.contains(
            "selected Cursor runtime requires a verified runtime-advertised model catalog"
        ));
        assert!(failure.message.contains("catalog output was malformed"));
        Ok(())
    }

    #[test]
    fn selected_cursor_runtime_fails_preflight_when_catalog_is_missing_without_gap() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Cursor,
            &RuntimeModelCatalog::OperatorDeclared,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;

        assert!(resolution.decisions.is_empty());
        assert!(plan.role_models.is_empty());
        let failure = resolution
            .selection_preflight_failure
            .context("missing Cursor catalog preflight failure")?;
        assert_eq!(
            failure.kind,
            SupervisorSelectionPreflightFailureKind::FailClosed
        );
        assert!(failure.message.contains(
            "verified Cursor runtime model catalog observation is missing without recorded failure evidence"
        ));
        Ok(())
    }

    #[test]
    fn selected_cursor_uses_one_runtime_advertised_primary_catalog() -> Result<()> {
        let advertised = advertised_with_cursor(captured_cursor_observation()?);
        let priors = selection::built_in_prior_dataset()?;
        let catalogs = constructed_selection_catalogs(
            SupervisorRuntime::Cursor,
            &RuntimeModelCatalog::OperatorDeclared,
            &advertised,
            &task_profile_for_role(AgentRole::Worker),
            &priors,
            None,
        )?;

        assert_eq!(catalogs.len(), 1);
        assert_eq!(catalogs[0].runtime, "cursor");
        assert!(catalogs[0]
            .revision
            .starts_with("cursor-advertised-sha256:"));
        assert!(catalogs[0]
            .models
            .iter()
            .any(|model| model.model == "composer-2.5"));
        Ok(())
    }

    #[test]
    fn selected_grok_uses_one_availability_only_advertised_primary_catalog() -> Result<()> {
        let advertised = advertised_with_grok(discover_grok_observation(CAPTURED_GROK_CATALOG)?);
        let priors = selector_priors_with_terminal_worker_economics()?;
        let catalogs = constructed_selection_catalogs(
            SupervisorRuntime::Grok,
            &RuntimeModelCatalog::OperatorDeclared,
            &advertised,
            &task_profile_for_role(AgentRole::Worker),
            &priors,
            None,
        )?;

        assert_eq!(catalogs.len(), 1);
        assert_eq!(catalogs[0].runtime, "grok");
        assert!(catalogs[0]
            .models
            .iter()
            .all(|model| model.access.is_none()));
        assert!(catalogs[0].revision.starts_with("grok-advertised-sha256:"));
        assert!(catalogs[0]
            .revision
            .ends_with(";auth=not_asserted_by_catalog"));
        assert!(catalogs[0]
            .models
            .iter()
            .any(|model| model.model == "grok-4.6"));
        Ok(())
    }

    #[test]
    fn advertised_grok_47_requires_task_provided_evidence_for_explicit_selection() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let observation = discover_grok_observation(CAPTURED_GROK_47_CATALOG)?;
        assert!(observation.catalog().contains("grok-4.7"));
        assert!(observation.catalog().contains("grok-4.7-build-fast"));

        let production_priors = selector_priors_with_terminal_worker_economics()?;
        let task = task_profile_for_role(AgentRole::Worker);
        let production_catalogs = constructed_selection_catalogs(
            SupervisorRuntime::Grok,
            &RuntimeModelCatalog::OperatorDeclared,
            &advertised_with_grok(observation.clone()),
            &task,
            &production_priors,
            None,
        )?;
        assert!(production_catalogs[0]
            .models
            .iter()
            .all(|model| model.model != "grok-4.7"));

        let mut task_priors = production_priors.clone();
        let mut task_prior = production_priors
            .models
            .iter()
            .find(|prior| prior.runtime == "grok" && prior.model == "grok-4.6")
            .cloned()
            .context("test fixture requires the existing Grok terminal-worker prior shape")?;
        task_prior.model = "grok-4.7".to_string();
        task_prior.source_id = "test-only-grok-4.7-task-evidence".to_string();
        task_prior.prior_scope =
            "test-only task-provided admissible Grok 4.7 selector evidence".to_string();
        task_prior.limitations = vec![
            "synthetic test evidence only; not production quality, price, benchmark, or default evidence"
                .to_string(),
        ];
        task_prior.one_shot_environment_fallbacks.clear();
        task_priors.revision = format!("{}+test-grok-4.7", task_priors.revision);
        task_priors.models.push(task_prior);

        let advertised = advertised_with_grok(observation);
        let mut input = selection_input_for_role(SelectionInputForRoleArgs {
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Grok,
            catalog: &RuntimeModelCatalog::OperatorDeclared,
            advertised: &advertised,
            admission: &test_admission(),
            resolved_objective_profile: &default_resolved_profile(),
            quota_context: None,
            quota_ledger: None,
            account_observation: None,
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
                accepted_task_cost_context: None,
                accepted_task_cost_observations: Vec::new(),
            },
            debug_override: Some(DebugOverride {
                candidate: CandidateKey {
                    runtime: "grok".to_string(),
                    model: "grok-4.7".to_string(),
                    effort: SelectorEffort::Xhigh,
                },
                requested_by: "test-only-task-evidence".to_string(),
                reason: "prove exact explicit selection without adding production priors"
                    .to_string(),
            }),
            history: None,
        })?;
        input.catalogs = constructed_selection_catalogs(
            SupervisorRuntime::Grok,
            &RuntimeModelCatalog::OperatorDeclared,
            &advertised,
            &task,
            &task_priors,
            None,
        )?;
        input.priors = task_priors;
        input.operational_observations = Some(live_operational_observations(&input));

        assert!(input.catalogs[0]
            .models
            .iter()
            .any(|model| model.model == "grok-4.7"));
        assert!(input.catalogs[0]
            .models
            .iter()
            .all(|model| model.model != "grok-4.7-build-fast"));
        let decision = selection::select(&input)?;
        let choice = decision.choice.context("explicit Grok 4.7 selection")?;
        assert_eq!(choice.candidate.runtime, "grok");
        assert_eq!(choice.candidate.model, "grok-4.7");
        assert_eq!(choice.candidate.effort, SelectorEffort::Xhigh);
        assert_eq!(choice.reason, selection::ChoiceReason::DebugOverride);
        Ok(())
    }

    #[test]
    fn genuinely_duplicated_grok_catalog_input_still_fails_closed() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let advertised = advertised_with_grok(discover_grok_observation(CAPTURED_GROK_CATALOG)?);
        let resolved = default_resolved_profile();
        let mut input = selection_input_for_role(SelectionInputForRoleArgs {
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Grok,
            catalog: &RuntimeModelCatalog::OperatorDeclared,
            advertised: &advertised,
            admission: &test_admission(),
            resolved_objective_profile: &resolved,
            quota_context: None,
            quota_ledger: None,
            account_observation: None,
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
                accepted_task_cost_context: None,
                accepted_task_cost_observations: Vec::new(),
            },
            debug_override: None,
            history: None,
        })?;
        input.catalogs.push(input.catalogs[0].clone());

        let error = selection::select(&input).expect_err("duplicate runtime must fail closed");
        assert_eq!(
            error.to_string(),
            "invalid selection input: runtime catalogs contain a duplicate runtime"
        );
        Ok(())
    }

    #[test]
    fn cursor_catalog_gap_detail_is_utf8_safe_and_bounded() {
        let detail = "界".repeat(CURSOR_CATALOG_EVIDENCE_GAP_MAX_BYTES);
        let bounded = bounded_cursor_catalog_gap_detail(&detail);
        assert!(bounded.len() <= CURSOR_CATALOG_EVIDENCE_GAP_MAX_BYTES);
        assert!(bounded.chars().all(|character| character == '界'));
    }

    #[test]
    fn cursor_catalog_program_resolution_returns_canonical_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let program = temp.path().join("cursor-agent");
        std::fs::write(&program, b"test executable fixture")?;
        let search_path = std::env::join_paths([temp.path()])?;
        let expected = std::fs::canonicalize(&program)?;

        assert_eq!(
            resolve_cursor_catalog_program(Path::new("cursor-agent"), Some(&search_path))?,
            expected
        );
        assert_eq!(
            resolve_cursor_catalog_program(&program, None)?,
            std::fs::canonicalize(&program)?
        );
        assert!(resolve_cursor_catalog_program(Path::new(""), Some(&search_path)).is_err());
        assert!(
            resolve_cursor_catalog_program(Path::new("missing-cursor"), Some(&search_path))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn cursor_catalog_environment_preserves_screened_path_passthrough() -> Result<()> {
        let host_path = std::env::var("PATH").context("test PATH must be Unicode")?;
        let spec = crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new("/workspace")
            .with_screened_env_passthrough("PATH")?;
        let environment = cursor_catalog_process_environment(&spec);

        assert_eq!(environment.get("PATH"), Some(&host_path));
        assert_eq!(environment.get("NO_COLOR").map(String::as_str), Some("1"));
        assert_eq!(environment.get("TERM").map(String::as_str), Some("dumb"));
        Ok(())
    }

    #[test]
    fn cursor_catalog_env_loading_ignores_unconfigured_and_non_unicode_values() -> Result<()> {
        let base = crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new("/workspace");
        assert_eq!(
            apply_cursor_catalog_env_setting(base.clone(), Err(std::env::VarError::NotPresent),)?,
            base
        );
        assert_eq!(
            apply_cursor_catalog_env_setting(
                base.clone(),
                Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                    "opaque non-Unicode environment value",
                ))),
            )?,
            base
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn cursor_catalog_program_resolution_canonicalizes_symlinks() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("cursor-agent-real");
        let link = temp.path().join("cursor-agent-link");
        std::fs::write(&target, b"test executable fixture")?;
        std::os::unix::fs::symlink(&target, &link)?;

        assert_eq!(
            resolve_cursor_catalog_program(&link, None)?,
            std::fs::canonicalize(&target)?
        );
        Ok(())
    }

    #[test]
    fn hermetic_cursor_fixture_path_advertises_composer_without_live_cli() -> Result<()> {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/runtime_adapter/cursor/captured-minimal-20260820.txt");
        let catalogs = observe_cursor_catalog_from_fixture(&fixture)?;
        let observation = catalogs.cursor.context("fixture Cursor observation")?;
        assert!(observation.catalog().contains("composer-2.5"));
        assert!(observation.catalog().contains("composer-2.5-fast"));
        let missing = observe_cursor_catalog_from_fixture(Path::new(
            "/tmp/maco-missing-cursor-catalog-fixture.txt",
        ))
        .expect_err("missing fixture must fail closed");
        assert!(
            format!("{missing:#}").contains("failed to read hermetic Cursor catalog fixture"),
            "{missing:#}"
        );
        Ok(())
    }

    #[test]
    fn live_grok_catalog_bridge_observes_the_default_catalog_hermetically() -> Result<()> {
        let runner = FakeGrokRunner::successful(CAPTURED_GROK_CATALOG);
        let observation = observe_optional_live_grok_catalog(
            &runner,
            Path::new("/workspace"),
            CAPTURED_CURSOR_AT_UNIX_MILLIS,
            None,
        )?
        .context("installed Grok catalog observation")?;

        assert!(observation.catalog().contains("grok-4.6"));
        assert_eq!(
            observation.observed_at_unix_millis(),
            CAPTURED_CURSOR_AT_UNIX_MILLIS
        );
        let specs = runner.observed_specs.borrow();
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].program(),
            Path::new(crate::runtime_adapter::grok::default_grok_executable())
        );
        assert!(specs[0].program().is_absolute());
        assert_eq!(
            specs[0].args(),
            &[
                std::ffi::OsString::from("--no-auto-update"),
                std::ffi::OsString::from("models"),
            ]
        );
        assert_eq!(specs[0].current_dir(), Path::new("/workspace"));
        Ok(())
    }

    #[test]
    fn live_grok_catalog_bridge_applies_the_explicit_program_override() -> Result<()> {
        let runner = FakeGrokRunner::successful(CAPTURED_GROK_CATALOG);
        let program = std::ffi::OsStr::new("/opt/maco/bin/grok-pinned");
        let observation = observe_optional_live_grok_catalog(
            &runner,
            Path::new("/workspace"),
            CAPTURED_CURSOR_AT_UNIX_MILLIS,
            Some(program),
        )?
        .context("overridden Grok catalog observation")?;

        assert!(observation.catalog().contains("grok-4.6"));
        let specs = runner.observed_specs.borrow();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].program(), Path::new(program));
        Ok(())
    }

    #[test]
    fn live_grok_catalog_bridge_refuses_a_relative_explicit_program_without_running_it() {
        let runner = FakeGrokRunner::successful(CAPTURED_GROK_CATALOG);
        let error = observe_optional_live_grok_catalog(
            &runner,
            Path::new("/workspace"),
            CAPTURED_CURSOR_AT_UNIX_MILLIS,
            Some(std::ffi::OsStr::new("relative/grok")),
        )
        .expect_err("a relative MACO_GROK_BIN must fail closed");

        let message = format!("{error:#}");
        assert!(
            message.contains("MACO_GROK_BIN must be an absolute path"),
            "{message}"
        );
        assert!(message.contains("ambient PATH"), "{message}");
        assert!(runner.observed_specs.borrow().is_empty());
    }

    #[test]
    fn live_grok_catalog_bridge_only_omits_an_unconfigured_missing_binary() -> Result<()> {
        assert_eq!(
            observe_optional_live_grok_catalog(
                &MissingGrokRunner,
                Path::new("/workspace"),
                CAPTURED_CURSOR_AT_UNIX_MILLIS,
                None,
            )?,
            None
        );

        let error = observe_optional_live_grok_catalog(
            &MissingGrokRunner,
            Path::new("/workspace"),
            CAPTURED_CURSOR_AT_UNIX_MILLIS,
            Some(std::ffi::OsStr::new("/configured/grok")),
        )
        .expect_err("an explicit missing Grok binary must fail closed");
        assert!(
            format!("{error:#}").contains("live Grok catalog observation failed closed"),
            "{error:#}"
        );
        Ok(())
    }

    #[test]
    fn live_grok_catalog_bridge_omits_implicit_missing_or_unavailable_authentication() -> Result<()>
    {
        for message in [
            "Grok authentication source auth.json is missing",
            "Grok authentication source auth.json is unavailable",
        ] {
            assert_eq!(
                observe_optional_live_grok_catalog(
                    &UnavailableGrokRunner(message),
                    Path::new("/workspace"),
                    CAPTURED_CURSOR_AT_UNIX_MILLIS,
                    None,
                )?,
                None
            );
        }
        Ok(())
    }

    #[test]
    fn live_grok_catalog_bridge_omits_an_implicit_unauthenticated_invalid_header() -> Result<()> {
        let runner = FakeGrokRunner::successful(b"You are not logged in.\n");
        assert_eq!(
            observe_optional_live_grok_catalog(
                &runner,
                Path::new("/workspace"),
                CAPTURED_CURSOR_AT_UNIX_MILLIS,
                None,
            )?,
            None
        );
        assert_eq!(runner.observed_specs.borrow().len(), 1);
        Ok(())
    }

    #[test]
    fn live_grok_catalog_bridge_fails_closed_for_explicit_unauthenticated_invalid_header() {
        let error = observe_optional_live_grok_catalog(
            &FakeGrokRunner::successful(b"You are not logged in.\n"),
            Path::new("/workspace"),
            CAPTURED_CURSOR_AT_UNIX_MILLIS,
            Some(std::ffi::OsStr::new("/configured/grok")),
        )
        .expect_err("an explicit unauthenticated Grok listing must fail closed");

        let message = format!("{error:#}");
        assert!(
            message.contains("live Grok catalog observation failed closed"),
            "{message}"
        );
        assert!(
            message.contains("Grok runtime model catalog has an invalid header"),
            "{message}"
        );
    }

    #[test]
    fn live_grok_catalog_bridge_accepts_misleading_banner_without_authentication_gate() -> Result<()>
    {
        const PAYLOAD: &[u8] = b"You are not authenticated.\n\nDefault model: grok-4.7\n\nAvailable models:\n  * grok-4.7 (default)\n  - grok-4.7-build-fast\n  - grok-4.6\n  - grok-4.5\n";
        for program in [None, Some(std::ffi::OsStr::new("/configured/grok"))] {
            let runner = FakeGrokRunner::successful(PAYLOAD);
            let observed = observe_optional_live_grok_catalog(
                &runner,
                Path::new("/workspace"),
                CAPTURED_CURSOR_AT_UNIX_MILLIS,
                program,
            )?
            .context("observed model availability")?;
            assert!(observed.catalog().contains("grok-4.6"));
            assert_eq!(
                observed.authentication_evidence(),
                "not_asserted_by_catalog"
            );
            assert_eq!(runner.observed_specs.borrow().len(), 1);
        }
        Ok(())
    }

    #[test]
    fn live_grok_catalog_bridge_fails_closed_for_suspicious_implicit_credentials() {
        for suspicious in [
            "Grok authentication source auth.json is not a regular file",
            "Grok authentication source auth.json identity changed",
        ] {
            let error = observe_optional_live_grok_catalog(
                &UnavailableGrokRunner(suspicious),
                Path::new("/workspace"),
                CAPTURED_CURSOR_AT_UNIX_MILLIS,
                None,
            )
            .expect_err("suspicious Grok credential state must fail closed");

            let message = format!("{error:#}");
            assert!(
                message.contains("live Grok catalog observation failed closed"),
                "{message}"
            );
            assert!(message.contains(suspicious), "{message}");
        }
    }

    #[test]
    fn live_grok_46_xhigh_is_selected_by_recorded_worker_economics() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let observation = discover_grok_observation(CAPTURED_GROK_CATALOG)?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(observation),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert_eq!(worker.primary_cause, SupervisorSelectionEventCause::Initial);
        assert_eq!(
            worker.provenance.resolved_objective_profile.source,
            crate::objective_profile::ObjectiveProfileSource::BuiltIn
        );
        assert_eq!(
            worker.provenance.resolved_objective_profile.profile.id,
            crate::objective_profile::DEFAULT_OBJECTIVE_PROFILE_ID
        );
        worker
            .provenance
            .resolved_objective_profile
            .profile
            .validate()?;
        let choice = worker.provenance.choice.as_ref().context("worker choice")?;
        assert_eq!(
            choice.candidate.runtime,
            crate::optimizer::objective::DEFAULT_TERMINAL_RUNTIME
        );
        assert_eq!(
            choice.candidate.model,
            crate::optimizer::objective::DEFAULT_TERMINAL_MODEL
        );
        assert_eq!(choice.candidate.effort, SelectorEffort::Xhigh);
        assert_eq!(choice.reason, selection::ChoiceReason::LoadedRoutingPolicy);
        let evaluation = worker
            .provenance
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate == choice.candidate)
            .context("selected worker evaluation")?;
        assert!(evaluation.eligible);
        assert_eq!(
            evaluation.prior_source_id.as_deref(),
            Some(crate::optimizer::objective::DEFAULT_TERMINAL_EVIDENCE_SOURCE_ID)
        );
        let selected_score = evaluation.score.as_ref().context("selected worker score")?;
        assert_eq!(selected_score.posterior_quality_basis_points, 9_560);
        assert_eq!(
            selected_score.expected_total_cost_per_accepted_task_microunits,
            87_552
        );
        assert_eq!(
            choice.total_score_microunits,
            selected_score.total_score_microunits
        );
        let runner_up = worker
            .provenance
            .runner_up_scores
            .first()
            .context("worker runner-up score")?;
        assert_eq!(runner_up.rank, 2);
        assert_ne!(runner_up.candidate, choice.candidate);
        assert!(runner_up.total_score_microunits > choice.total_score_microunits);
        assert!(worker.provenance.candidate_set.iter().all(|candidate| {
            !candidate.eligible
                || candidate.candidate == choice.candidate
                || candidate.score.as_ref().is_some_and(|score| {
                    score.total_score_microunits > selected_score.total_score_microunits
                })
        }));
        assert!(worker
            .provenance
            .normalized_input
            .catalogs
            .iter()
            .any(|runtime_catalog| {
                runtime_catalog.runtime == crate::optimizer::objective::DEFAULT_TERMINAL_RUNTIME
                    && runtime_catalog
                        .revision
                        .starts_with("grok-advertised-sha256:")
                    && runtime_catalog.models.iter().any(|model| {
                        model.model == crate::optimizer::objective::DEFAULT_TERMINAL_MODEL
                            && model.supported_efforts == [SelectorEffort::Xhigh]
                    })
            }));
        assert_eq!(
            plan.role_models
                .get(&AgentRole::Worker)
                .and_then(|selection| selection.reasoning_effort.as_deref()),
            Some("xhigh")
        );
        assert!(matches!(
            plan.role_models[&AgentRole::Worker].unavailable_model_fallback,
            UnavailableModelFallback::FailClosed
        ));
        Ok(())
    }

    #[test]
    fn unavailable_grok_46_falls_back_to_scored_codex_with_honest_membership() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let withdrawn =
            discover_grok_observation(&grok_listing("grok-4.5", &["  * grok-4.5 (default)"]))?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(withdrawn),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert!(worker.provenance.candidate_set.iter().all(|evaluation| {
            evaluation.candidate.model != crate::optimizer::objective::DEFAULT_TERMINAL_MODEL
        }));
        let choice = worker
            .provenance
            .choice
            .as_ref()
            .context("fallback worker choice")?;
        assert_eq!(choice.candidate.runtime, "codex");
        assert_eq!(choice.reason, selection::ChoiceReason::LoadedRoutingPolicy);
        assert!(worker
            .provenance
            .normalized_input
            .catalogs
            .iter()
            .find(|runtime_catalog| runtime_catalog.runtime == "grok")
            .is_some_and(|runtime_catalog| runtime_catalog.models.is_empty()));
        Ok(())
    }

    #[test]
    fn grok_worker_economics_never_grant_delegating_or_judgment_authority() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let priors = selector_priors_with_terminal_worker_economics()?;
        for authority in [
            AuthorityRole::Delegating,
            AuthorityRole::ReviewAuditor,
            AuthorityRole::GitPublication,
        ] {
            assert!(matches!(
                priors.measured_authority_eligibility(
                    crate::optimizer::objective::DEFAULT_TERMINAL_MODEL,
                    authority,
                ),
                selection::MeasuredAuthorityEligibility::Ineligible { .. }
            ));
        }

        let catalog = codex_catalog()?;
        let observation = discover_grok_observation(CAPTURED_GROK_CATALOG)?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(observation),
        )?;
        for role in [
            AgentRole::Supervisor,
            AgentRole::ChildOrchestrator,
            AgentRole::Auditor,
            AgentRole::GateClassifier,
        ] {
            let decision = resolution
                .decisions
                .iter()
                .find(|decision| decision.role == role)
                .with_context(|| format!("{} decision", role.as_str()))?;
            assert_eq!(
                decision
                    .provenance
                    .choice
                    .as_ref()
                    .with_context(|| format!("{} choice", role.as_str()))?
                    .candidate
                    .runtime,
                "codex",
                "{}",
                role.as_str()
            );
            assert!(decision.provenance.candidate_set.iter().all(|evaluation| {
                evaluation.candidate.model != crate::optimizer::objective::DEFAULT_TERMINAL_MODEL
                    || !evaluation.eligible
            }));
        }
        Ok(())
    }

    #[test]
    fn explicit_worker_override_wins_over_live_grok_worker_economics() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let observation = discover_grok_observation(CAPTURED_GROK_CATALOG)?;
        let requested = codex_prior_for(|prior| {
            prior.class_fit.iter().any(|class_fit| {
                class_fit.task_class == AUTOMATIC_SELECTION_TASK_CLASS
                    && class_fit.effort == SelectorEffort::High
            })
        })?;
        let mut plan = test_plan();
        plan.role_models.insert(
            AgentRole::Worker,
            role_selection(requested.model.clone(), Some("high")),
        );
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(observation),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        let choice = worker
            .provenance
            .choice
            .as_ref()
            .context("worker override choice")?;
        assert_eq!(choice.candidate.runtime, "codex");
        assert_eq!(choice.candidate.model, requested.model);
        assert_eq!(choice.candidate.effort, SelectorEffort::High);
        assert_eq!(choice.reason, selection::ChoiceReason::DebugOverride);
        assert!(matches!(
            worker
                .provenance
                .debug_override
                .as_ref()
                .context("worker debug override provenance")?
                .disposition,
            selection::DebugOverrideDisposition::Applied
        ));
        Ok(())
    }

    #[test]
    fn injected_grok_catalog_joins_without_hardcoded_slug_lists() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        use crate::runtime_adapter::grok::{
            inject_grok_advertised_catalog, GrokModelCatalog, GrokModelCatalogEntry,
        };
        let catalog = codex_catalog()?;
        let priors = selection::built_in_prior_dataset()?;
        let grok_prior = priors
            .models
            .iter()
            .find(|prior| prior.runtime == "grok")
            .context("built-in Grok prior")?;
        let observation = inject_grok_advertised_catalog(
            GrokModelCatalog::from_injected_entries([GrokModelCatalogEntry::new(
                grok_prior.model.clone(),
                "Injected Grok Worker",
            )?])?,
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS),
            b"opaque-injected-grok-payload",
        )?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet {
                cursor: None,
                grok: Some(observation),
                cursor_evidence_gap: None,
            },
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert!(worker.provenance.candidate_set.iter().any(|evaluation| {
            evaluation.candidate.runtime == "grok"
                && evaluation.candidate.model == grok_prior.model
                && evaluation.eligible
        }));

        let withdrawn = inject_grok_advertised_catalog(
            GrokModelCatalog::from_injected_entries([GrokModelCatalogEntry::new(
                "worker-stable",
                "Worker Stable",
            )?])?,
            Some(CAPTURED_CURSOR_AT_UNIX_MILLIS + 1),
            b"withdrawn-injected-grok-payload",
        )?;
        let mut withdrawn_plan = test_plan();
        let withdrawn_resolution = initialize_supervisor_selection(
            &mut withdrawn_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet {
                cursor: None,
                grok: Some(withdrawn),
                cursor_evidence_gap: None,
            },
        )?;
        let withdrawn_worker = withdrawn_resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("withdrawn worker decision")?;
        assert!(withdrawn_worker
            .provenance
            .candidate_set
            .iter()
            .all(|evaluation| evaluation.candidate.model != grok_prior.model));
        Ok(())
    }

    #[test]
    fn observed_grok_catalog_joins_and_withdrawal_removes_membership() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let priors = selection::built_in_prior_dataset()?;
        let grok_prior = priors
            .models
            .iter()
            .find(|prior| prior.runtime == "grok")
            .context("built-in Grok prior")?;
        let observed = discover_grok_observation(&grok_listing(
            &grok_prior.model,
            &[&format!("  * {} (default)", grok_prior.model)],
        ))?;
        assert!(observed.catalog().contains(&grok_prior.model));

        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(observed),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker decision")?;
        assert!(worker.provenance.candidate_set.iter().any(|evaluation| {
            evaluation.candidate.runtime == "grok"
                && evaluation.candidate.model == grok_prior.model
                && evaluation.eligible
        }));
        assert!(worker
            .provenance
            .normalized_input
            .catalogs
            .iter()
            .any(|runtime_catalog| runtime_catalog
                .revision
                .starts_with("grok-advertised-sha256:")));

        let withdrawn = discover_grok_observation(&grok_listing(
            "worker-stable",
            &["  * worker-stable (default)"],
        ))?;
        assert!(!withdrawn.catalog().contains(&grok_prior.model));
        let mut withdrawn_plan = test_plan();
        let withdrawn_resolution = initialize_supervisor_selection(
            &mut withdrawn_plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(withdrawn),
        )?;
        let withdrawn_worker = withdrawn_resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("withdrawn worker decision")?;
        assert!(withdrawn_worker
            .provenance
            .candidate_set
            .iter()
            .all(|evaluation| evaluation.candidate.model != grok_prior.model));
        Ok(())
    }

    #[test]
    fn codex_only_goal_selection_and_retry_reject_advertised_grok_without_weakening_policy(
    ) -> Result<()> {
        let _policy = bind_fixture_routing_policy()?;
        let (_temporary, repo) = super::super::tests::injected_repository();
        let primary = repo.join("codex-bin");
        std::fs::write(&primary, b"fixture executable")?;
        let catalog = codex_catalog()?;
        let advertised = advertised_with_grok(discover_grok_observation(&grok_listing(
            "grok-4.6",
            &["  * grok-4.6 (default)"],
        ))?);
        let goal = "Update `README.md`: append one final line that reads exactly `Hello from MACO`. Do not change any other file.";
        let session = crate::planning::task_planning_session_with_test_inventory(
            &repo,
            "",
            goal,
            vec![PathBuf::from("README.md")],
        )?;
        let original = super::super::plan_api::supervisor_plan_from_task_planning_session_in_repo(
            &repo, goal, "", &session,
        )?;
        let mut automatic = original.clone();
        let unrestricted = initialize_supervisor_selection(
            &mut automatic,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised,
        )?;
        assert!(unrestricted
            .decisions
            .iter()
            .filter(|decision| decision.role == AgentRole::Worker)
            .any(|decision| decision
                .provenance
                .candidate_set
                .iter()
                .any(|candidate| candidate.candidate.runtime == "grok" && candidate.eligible)));
        let _binding = super::super::runtime_executables::bind_new(
            &repo,
            &RunId::new("codex-only-selection")?,
            SupervisorRuntime::Codex,
            &primary,
            &[],
        )?;
        let mut constrained = original;
        let resolution = initialize_supervisor_selection(
            &mut constrained,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised,
        )?;
        assert!(resolution.selection_preflight_failure.is_none());
        for decision in &resolution.decisions {
            assert_eq!(
                decision
                    .provenance
                    .choice
                    .as_ref()
                    .context("selected Codex role")?
                    .candidate
                    .runtime,
                "codex"
            );
            assert!(decision
                .provenance
                .candidate_set
                .iter()
                .filter(|candidate| candidate.candidate.runtime == "grok")
                .all(|candidate| !candidate.eligible));
        }
        let mut state = resolution
            .automatic_state
            .context("automatic replay state")?;
        let retry = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        assert_eq!(
            retry.runtime_overrides.get(&AgentRole::Worker),
            Some(&SupervisorRuntime::Codex)
        );
        assert!(retry.decisions.iter().all(|(_, decision)| decision
            .choice
            .as_ref()
            .is_some_and(|choice| choice.candidate.runtime == "codex")));
        Ok(())
    }

    #[test]
    fn documented_mixed_plan_selects_with_its_own_replayable_assessment() -> Result<()> {
        let (_temporary, repo) = super::super::tests::injected_repository();
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/supervise/mixed-codex-grok-plan.json"
        ));
        let mut loaded = super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
            source,
            Some(&repo),
        )?;
        let frozen = loaded
            .plan_metadata
            .resolved_routing_policy
            .clone()
            .context("documented policy")?;
        assert_eq!(
            frozen,
            crate::selection::routing_policy::load_routing_policy(&repo)?
        );
        let assessment = loaded
            .plan_metadata
            .task_routing_assessment
            .as_ref()
            .context("documented assessment")?;
        let assignment = &loaded.plan.assignments[0];
        let proposal = serde_json::from_value(json!({
            "fragments": [{"id": "readme-append", "text": loaded.plan.task}],
            "assignments": [{"id": assignment.id, "task": assignment.task,
                "fragment_ids": ["readme-append"], "assigned_paths": assignment.assigned_paths,
                "semantic_symbols": [], "semantic_modules": [], "decision_dependencies": []}],
            "diagnostics": {"degraded": false, "notes": []},
            "disjointness": {"disjoint": true, "conflicts": []}
        }))?;
        assert_eq!(
            *assessment,
            super::super::assess_task_routing(&loaded.plan.task, &proposal, &frozen)?
        );
        let _policy = crate::selection::routing_policy::bind_routing_policy(Some(frozen.clone()))?;
        let catalog = codex_catalog()?;
        let advertised = advertised_with_grok(discover_grok_observation(&grok_listing(
            "grok-4.6",
            &["  * grok-4.6 (default)"],
        ))?);
        // Use the production entry point and the shipped metadata, never the
        // fixture wrapper that synthesizes an assessment for selector unit tests.
        let resolution = super::initialize_supervisor_selection_with_assessment(
            &mut loaded.plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised,
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &[],
            Some(assessment),
        )?;
        assert!(resolution.selection_preflight_failure.is_none());
        assert!(resolution
            .decisions
            .iter()
            .any(|event| event.role == AgentRole::Supervisor));
        for event in &resolution.decisions {
            let candidate = &event
                .provenance
                .choice
                .as_ref()
                .context("selected documented role")?
                .candidate;
            if event.role == AgentRole::Worker {
                assert_eq!(candidate.runtime, "grok");
                assert_eq!(candidate.model, "grok-4.6");
                assert_eq!(candidate.effort, selector_effort_from_str("xhigh").unwrap());
            } else {
                assert_eq!(candidate.runtime, "codex");
                assert_eq!(candidate.model, "gpt-6.1-sol");
                assert_eq!(candidate.effort, SelectorEffort::Xhigh);
            }
            assert_eq!(event.provenance.normalized_task.risk, RiskLevel::Low);
            assert_eq!(
                event
                    .provenance
                    .routing_policy
                    .as_ref()
                    .context("policy receipt")?
                    .frozen,
                frozen
            );
        }
        let mut missing: serde_json::Value = serde_json::from_str(source)?;
        missing
            .as_object_mut()
            .unwrap()
            .remove("task_routing_assessment");
        let mut unassessed = super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
            &serde_json::to_string(&missing)?,
            Some(&repo),
        )?;
        let error = super::initialize_supervisor_selection_with_assessment(
            &mut unassessed.plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised,
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &[],
            unassessed.plan_metadata.task_routing_assessment.as_ref(),
        )
        .expect_err("missing documented assessment must still fail closed");
        assert!(error.to_string().contains("task.risk must be known"));
        for pointer in ["/task", "/task_routing_assessment/declared_input_sha256"] {
            let mut stale: serde_json::Value = serde_json::from_str(source)?;
            *stale.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(
                super::super::plan_api::parse_supervisor_plan_with_consultant_in_repo(
                    &serde_json::to_string(&stale)?,
                    Some(&repo),
                )
                .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn codex_primary_applies_explicit_worker_override_on_authored_grok_runtime() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        // The built-in Grok prior is fixture evidence for catalog membership.
        // It is not a qualification claim for any specific production model.
        let catalog = codex_catalog()?;
        let priors = selection::built_in_prior_dataset()?;
        let grok_prior = priors
            .models
            .iter()
            .find(|prior| prior.runtime == "grok")
            .context("built-in Grok prior")?;
        let observed = discover_grok_observation(&grok_listing(
            &grok_prior.model,
            &[&format!("  * {} (default)", grok_prior.model)],
        ))?;
        let advertised = advertised_with_grok(observed);
        let mut automatic = test_plan();
        let automatic_resolution = initialize_supervisor_selection(
            &mut automatic,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised,
        )?;
        let automatic_worker = automatic_resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("automatic worker decision")?;
        let candidate = automatic_worker
            .provenance
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.candidate.runtime == "grok" && evaluation.eligible)
            .context("eligible grok worker candidate")?
            .candidate
            .clone();

        let mut plan = test_plan();
        let mut worker_assignment = child_assignment("worker-a");
        worker_assignment.role = AgentRole::Worker;
        worker_assignment.runtime = Some(SupervisorRuntime::Grok);
        plan.assignments = vec![worker_assignment];
        plan.role_models.insert(
            AgentRole::Worker,
            role_selection(
                candidate.model.clone(),
                Some(selector_effort_as_str(candidate.effort)),
            ),
        );
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised.clone(),
        )?;

        assert!(resolution.selection_preflight_failure.is_none());
        let worker = resolution
            .decisions
            .iter()
            .find(|decision| decision.role == AgentRole::Worker)
            .context("worker debug decision")?;
        let debug_override = worker
            .provenance
            .debug_override
            .as_ref()
            .context("worker debug override provenance")?;
        assert_eq!(debug_override.request.candidate.runtime, "grok");
        assert!(matches!(
            debug_override.disposition,
            selection::DebugOverrideDisposition::Applied
        ));
        let choice = worker
            .provenance
            .choice
            .as_ref()
            .context("worker override choice")?;
        assert_eq!(choice.candidate.runtime, "grok");
        bind_selected_assignment_runtimes(&mut plan, &resolution.decisions)?;
        assert_eq!(plan.assignments[0].runtime, Some(SupervisorRuntime::Grok));
        Ok(())
    }

    #[test]
    fn observed_grok_catalog_stays_fail_closed_for_judgment_roles() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let priors = selection::built_in_prior_dataset()?;
        let grok_prior = priors
            .models
            .iter()
            .find(|prior| prior.runtime == "grok")
            .context("built-in Grok prior")?;
        let observation = discover_grok_observation(&grok_listing(
            &grok_prior.model,
            &[&format!("  * {} (default)", grok_prior.model)],
        ))?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_grok(observation),
        )?;
        for role in [
            AgentRole::Supervisor,
            AgentRole::Auditor,
            AgentRole::GateClassifier,
            AgentRole::ChildOrchestrator,
        ] {
            let decision = resolution
                .decisions
                .iter()
                .find(|decision| decision.role == role)
                .with_context(|| format!("{} decision", role.as_str()))?;
            let mut pressured = decision.provenance.normalized_input.clone();
            if let Some(pool) = pressured
                .pools
                .iter_mut()
                .find(|pool| pool.runtime == "codex")
            {
                pool.pool_pressure_basis_points = 10_000;
            }
            let pressured = selection::select(&pressured)?;
            if let Some(choice) = &pressured.choice {
                assert_ne!(choice.candidate.runtime, "grok", "{}", role.as_str());
                assert_ne!(
                    choice.candidate.model,
                    grok_prior.model,
                    "{}",
                    role.as_str()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn selected_runtime_is_stamped_onto_the_assignment() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        plan.assignments = vec![worker_assignment()];
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &advertised_with_cursor(captured_cursor_observation()?),
        )?;
        bind_selected_assignment_runtimes(&mut plan, &resolution.decisions)?;
        assert_eq!(
            plan.assignments[0].runtime,
            Some(runtime_from_name(
                &resolution
                    .decisions
                    .iter()
                    .find(|decision| decision.role == AgentRole::Worker)
                    .and_then(|decision| decision.provenance.choice.as_ref())
                    .context("worker choice")?
                    .candidate
                    .runtime
            )?)
        );
        Ok(())
    }

    #[test]
    fn live_observation_preserves_requested_and_unknown_runtime_attribution() -> Result<()> {
        reset_live_switch_cost_session();
        let record = record_supervisor_invocation_observation(LiveInvocationObservation {
            run_id: "observed-run",
            assignment_id: "worker-a",
            attempt: 1,
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Codex,
            model: Some("gpt-5.6-luna"),
            effort: Some("xhigh"),
            worktree_id: "worker-a",
            usage: None,
            duration_ms: Some(12_345),
            started_at_unix_millis: 1_000,
        })?;
        assert_eq!(
            record.requested_model.as_ref().map(RuntimeSlug::as_str),
            Some("gpt-5.6-luna")
        );
        assert_eq!(record.requested_effort, Some(CanonicalEffort::XHigh));
        assert_eq!(
            record.finished_at,
            Some(TimestampMillis::from_millis(13_345))
        );
        let json = serde_json::to_value(&record)?;
        for field in [
            "resolved_model",
            "resolved_effort",
            "session_id",
            "runtime_startup_micros",
        ] {
            assert!(json[field].is_null(), "{field} must remain unobserved");
        }
        record.validate_observation()?;
        assert!(
            record.validate().is_err(),
            "request is not complete attribution"
        );
        assert_eq!(live_switch_cost_artifact().invocations, vec![record]);
        let fitted = live_fitted_switch_estimate(TransitionClass::FreshSessionOrWorktree);
        assert_eq!(fitted.sample_count, 0);
        assert_eq!(
            fitted.provenance.runtime_startup.observation,
            crate::optimizer::resources::ObservationKind::Inferred
        );
        reset_live_switch_cost_session();
        Ok(())
    }

    #[test]
    fn live_observation_does_not_fill_missing_model_effort_or_duration() -> Result<()> {
        reset_live_switch_cost_session();
        for (model, effort, duration_ms) in [
            (None, None, None),
            (Some(" "), Some("future-effort"), Some(u64::MAX)),
        ] {
            let record = record_supervisor_invocation_observation(LiveInvocationObservation {
                run_id: "missing-run",
                assignment_id: "worker-a",
                attempt: 1,
                role: AgentRole::Worker,
                runtime: SupervisorRuntime::Codex,
                model,
                effort,
                worktree_id: "worker-a",
                usage: None,
                duration_ms,
                started_at_unix_millis: 1_000,
            })?;
            assert!(record.requested_model.is_none());
            assert!(record.requested_effort.is_none());
            assert!(record.finished_at.is_none());
            assert!(record.runtime_startup_micros.is_none());
            record.validate_observation()?;
        }
        reset_live_switch_cost_session();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_live_invocation(
        id: &str,
        backend: &str,
        model: &str,
        started: u64,
        input: Option<u64>,
        cached: Option<u64>,
        session: &str,
        worktree: &str,
    ) -> Result<InvocationRecord> {
        let started_at = TimestampMillis::from_millis(started);
        let mut record = InvocationRecord::new(
            PolicyId::new("live-policy").map_err(|error| anyhow!(error))?,
            CandidateId::new(id).map_err(|error| anyhow!(error))?,
            started_at,
            ResourceVector::new().snapshot(started_at),
        );
        record.finished_at = Some(TimestampMillis::from_millis(started.saturating_add(1)));
        record.optimization_run_id =
            Some(OptimizationRunId::new("live-run").map_err(|error| anyhow!(error))?);
        record.policy_execution_id =
            Some(PolicyExecutionId::new("live-exec").map_err(|error| anyhow!(error))?);
        record.invocation_id = Some(InvocationId::new(id).map_err(|error| anyhow!(error))?);
        record.root_decision_id =
            Some(DecisionId::new("live-decision").map_err(|error| anyhow!(error))?);
        record.backend = Some(BackendId::new(backend).map_err(|error| anyhow!(error))?);
        record.provider = Some(ProviderId::new("local").map_err(|error| anyhow!(error))?);
        record.requested_model = Some(RuntimeSlug::new(model).map_err(|error| anyhow!(error))?);
        record.resolved_model = Some(RuntimeSlug::new(model).map_err(|error| anyhow!(error))?);
        record.requested_effort = Some(CanonicalEffort::High);
        record.resolved_effort = Some(CanonicalEffort::High);
        record.session_id = Some(session.to_string());
        record.worktree_id = Some(worktree.to_string());
        record.input_tokens = input;
        record.cached_input_tokens = cached;
        record.runtime_startup_micros = Some(1_200);
        record.lost_checkpoint_cost_micros = Some(400);
        Ok(record)
    }

    #[test]
    fn live_invocation_refit_counts_each_observation_once() -> Result<()> {
        reset_live_switch_cost_session();
        let records = vec![
            complete_live_invocation(
                "first",
                "adapter-a",
                "model-a",
                1,
                Some(1_000),
                Some(800),
                "session-a",
                "worktree-a",
            )?,
            complete_live_invocation(
                "second",
                "adapter-a",
                "model-b",
                2,
                Some(900),
                Some(0),
                "session-a",
                "worktree-a",
            )?,
            complete_live_invocation(
                "third",
                "adapter-a",
                "model-c",
                3,
                Some(800),
                Some(0),
                "session-a",
                "worktree-a",
            )?,
        ];
        let mut once = SwitchCostModel::new();
        once.observe_invocations(&records);
        for record in records {
            record_live_invocation(record)?;
        }
        for class in [
            TransitionClass::FreshSessionOrWorktree,
            TransitionClass::ModelChangeSameRuntime,
        ] {
            assert_eq!(live_fitted_switch_estimate(class), once.estimate(class));
        }
        reset_live_switch_cost_session();
        Ok(())
    }

    #[test]
    fn live_invocations_fit_switch_cost_model_and_preserve_inferred_labels() -> Result<()> {
        reset_live_switch_cost_session();
        let cold = live_fitted_switch_estimate(TransitionClass::ModelChangeSameRuntime);
        assert_eq!(
            cold.status,
            crate::optimizer::switch_cost::SwitchEvidenceStatus::Inferred
        );
        assert_eq!(
            cold.observation,
            crate::optimizer::resources::ObservationKind::Inferred
        );
        assert_eq!(cold.sample_count, 0);
        assert!(cold.uncertainty_micros.lower < cold.total_cost_micros);
        assert!(cold.uncertainty_micros.upper > cold.total_cost_micros);

        let mut warm = complete_live_invocation(
            "warm",
            "adapter-a",
            "model-a",
            1,
            Some(1_000),
            Some(800),
            "session-a",
            "worktree-a",
        )?;
        warm.runtime_startup_micros = None;
        warm.lost_checkpoint_cost_micros = None;
        record_live_invocation(warm)?;
        let mut switched = complete_live_invocation(
            "swap",
            "adapter-a",
            "model-b",
            2,
            Some(900),
            Some(0),
            "session-a",
            "worktree-a",
        )?;
        switched.lost_checkpoint_cost_micros = None;
        record_live_invocation(switched)?;

        let fitted = live_fitted_switch_estimate(TransitionClass::ModelChangeSameRuntime);
        assert_ne!(
            fitted.status,
            crate::optimizer::switch_cost::SwitchEvidenceStatus::Inferred
        );
        assert!(fitted.sample_count > 0);
        assert_eq!(fitted.runtime_startup_micros, 1_200);
        assert_eq!(
            fitted.provenance.lost_checkpoint.observation,
            crate::optimizer::resources::ObservationKind::Inferred
        );
        assert_eq!(
            live_fitted_switch_estimate(TransitionClass::Continue).total_cost_micros,
            0
        );
        reset_live_switch_cost_session();
        Ok(())
    }

    #[test]
    fn live_online_router_persists_zero_continue_and_priced_switch_arms() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        reset_live_switch_cost_session();
        bind_live_router_config(SupervisorRouterConfig {
            hysteresis_margin_bp: 2_500,
            oscillation_alarm_threshold: 1,
        });
        record_live_invocation(complete_live_invocation(
            "warm",
            crate::optimizer::ids::BackendId::CODEX_CLI,
            "gpt-5.6-sol",
            1,
            Some(1_000),
            Some(800),
            "session-a",
            "worktree-a",
        )?)?;
        record_live_invocation(complete_live_invocation(
            "swap",
            crate::optimizer::ids::BackendId::CODEX_CLI,
            "gpt-5.6-luna",
            2,
            Some(900),
            Some(0),
            "session-a",
            "worktree-a",
        )?)?;

        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let frozen = default_resolved_profile();
        let resolution = initialize_supervisor_selection_with_profile(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&frozen),
        )?;
        let worker = resolution
            .decisions
            .iter()
            .find(|event| event.role == AgentRole::Worker)
            .context("worker decision")?;
        let mut input = worker.provenance.normalized_input.clone();
        let previous = crate::selection::CandidateKey {
            runtime: "codex".to_string(),
            model: "gpt-5.6-sol".to_string(),
            effort: crate::selection::ReasoningEffort::High,
        };
        input.signals.previous_choice = Some(previous);
        let continue_id = "codex:gpt-5.6-sol:high";
        let switch_id = "codex:gpt-5.6-luna:high";
        push_live_router_identity(continue_id);
        push_live_router_identity(switch_id);
        push_live_router_identity(continue_id);
        route_live_four_arm_comparison(&input)?;
        let snapshot = live_switch_cost_artifact();
        let comparison = snapshot
            .router_comparison
            .as_ref()
            .context("four-arm comparison")?;
        let continue_arm = comparison.continue_arm.as_ref().context("continue arm")?;
        assert_eq!(continue_arm.applied_switch_cost_micros, 0);
        let switch_arm = comparison.switch_arm.as_ref().context("switch arm")?;
        assert!(switch_arm.applied_switch_cost_micros > 0);
        assert_eq!(snapshot.router_config.hysteresis_margin_bp, 2_500);
        assert!(snapshot
            .oscillation_alarms
            .iter()
            .any(|alarm| alarm.alarmed && alarm.switch_hysteresis_margin_bp == 2_500));
        reset_live_switch_cost_session();
        Ok(())
    }

    #[test]
    fn frozen_resolved_profile_flows_through_selector_and_evaluation_without_drift() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        reset_live_switch_cost_session();
        let catalog = codex_catalog()?;
        let mut profile = crate::objective_profile::default_objective_profile();
        profile.id = "frozen-live-consumption-v1".to_string();
        profile.tradeoffs.monetary_cost_percent = 75;
        profile.tradeoffs.human_review_percent = 25;
        let frozen = ResolvedObjectiveProfile {
            profile: profile.binding()?,
            source: crate::objective_profile::ObjectiveProfileSource::RepositoryOverride,
        };
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection_with_profile(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&frozen),
        )?;
        assert!(resolution.decisions.iter().all(|event| {
            event.provenance.resolved_objective_profile == frozen
                && event.provenance.normalized_input.resolved_objective_profile == frozen
        }));

        let labelled_plan = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "evidence": {
                "kind": "provisional_deterministic_fake_only",
                "plan_basis": "hand_authored",
                "real_provider_executed": false,
                "observed_isolated_repository_state": false,
                "requirement_four_comparability": "not_established_deferred_to_phase_b",
                "eligible_for_production_economics": false,
                "eligible_to_justify_named_default": false,
                "eligible_for_production_or_default_decisions": false,
                "notice": crate::evaluation::PROVISIONAL_FAKE_EVIDENCE_NOTICE,
            },
            "task": "frozen profile live consumption",
            "assignments": []
        }))?;
        let digest = format!(
            "sha256:{}",
            crate::artifacts::state_auth::sha256_hex(&labelled_plan)
        );
        let model = |name: &str, effort: &str| RoleModelSelection {
            model: Some(name.to_string()),
            reasoning_effort: Some(effort.to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        };
        let manifest = crate::evaluation::EvaluationManifest {
            version: crate::evaluation::EVALUATION_MANIFEST_SCHEMA_VERSION,
            experiment_id: "wiring2-frozen-profile".to_string(),
            evidence: serde_json::from_value(serde_json::json!({
                "kind": "provisional_deterministic_fake_only",
                "plan_basis": "hand_authored",
                "real_provider_executed": false,
                "observed_isolated_repository_state": false,
                "requirement_four_comparability": "not_established_deferred_to_phase_b",
                "eligible_for_production_economics": false,
                "eligible_to_justify_named_default": false,
                "eligible_for_production_or_default_decisions": false,
                "notice": crate::evaluation::PROVISIONAL_FAKE_EVIDENCE_NOTICE,
            }))?,
            target: crate::evaluation::EvaluationTarget {
                spec_or_goal_id: "wiring2-frozen".to_string(),
                spec_or_goal_digest:
                    "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e1bca75d84e1400c421b321"
                        .to_string(),
                hand_authored_plan_digest: digest,
            },
            repository_base_snapshot: "a".repeat(40),
            limits: crate::evaluation::EvaluationLimits {
                wall_time_seconds: 60,
                max_dispatches: 2,
            },
            held_out_validation: vec![
                crate::evaluation::HeldOutValidation {
                    id: "unit".to_string(),
                    command: vec!["true".to_string()],
                },
                crate::evaluation::HeldOutValidation {
                    id: "integration".to_string(),
                    command: vec!["true".to_string()],
                },
            ],
            repetitions: 1,
            profiles: vec![
                crate::evaluation::EvaluationProfile {
                    id: "mix-a".to_string(),
                    role_models: BTreeMap::from([
                        (AgentRole::ChildOrchestrator, model("frontier-v1", "high")),
                        (AgentRole::Worker, model("fast-v1", "medium")),
                    ]),
                },
                crate::evaluation::EvaluationProfile {
                    id: "mix-b".to_string(),
                    role_models: BTreeMap::from([
                        (AgentRole::ChildOrchestrator, model("frontier-v1", "high")),
                        (AgentRole::Worker, model("frontier-v1", "high")),
                    ]),
                },
            ],
            objective_profile: Some(frozen.clone()),
        };
        let results = crate::evaluation::run_evaluation(
            &manifest,
            &labelled_plan,
            crate::evaluation::EvaluationRunRequest {
                fake_seed: 7,
                ..crate::evaluation::EvaluationRunRequest::default()
            },
        )
        .map_err(|error| anyhow!("evaluation consumption: {error}"))?;
        match results.objective_scoring {
            crate::evaluation::EvaluationObjectiveEvidence::Scored(scoring) => {
                assert_eq!(scoring.applied_profile, frozen);
            }
            other => bail!("expected scored objective evidence, got {other:?}"),
        }
        reset_live_switch_cost_session();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn test_account_binding(provider_id: &str) -> SelectedAccountBinding {
        SelectedAccountBinding {
            provider_id: provider_id.to_string(),
            account_id: "work".to_string(),
            account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
            selection_revision: 1,
        }
    }

    #[cfg(target_os = "linux")]
    fn account_observe_result(
        provider_id: &str,
        models: CategoryObservation<ModelsObservation>,
        quota: Option<CategoryObservation<QuotaObservation>>,
    ) -> AccountObserveResult {
        AccountObserveResult {
            binding: test_account_binding(provider_id),
            observed_at: "2026-09-19T00:00:00Z".to_string(),
            auth: None,
            models: Some(models),
            quota,
        }
    }

    #[cfg(target_os = "linux")]
    fn qualified_account_fixture(
        provider: &str,
        model: &str,
        effort: &str,
    ) -> AccountObserveResult {
        use coding_agent_manager_lib::account_authority::{
            ModelAccessBasis, ModelAccessOutcome, ModelCatalogProvenance, ModelCatalogSourceKind,
        };
        let mut observation = account_observe_result(
            provider,
            CategoryObservation::observed(ModelsObservation {
                provenance: None,
                models: vec![ObservedModel {
                    model_id: model.into(),
                    supported_efforts: Some(vec![effort.into()]),
                    default_effort: None,
                    access: ModelAccessOutcome::Available,
                }],
            }),
            None,
        );
        observation
            .models
            .as_mut()
            .unwrap()
            .content
            .as_mut()
            .unwrap()
            .provenance = Some(ModelCatalogProvenance {
            source_kind: ModelCatalogSourceKind::AuthenticatedCatalog,
            fetched_at: Some(observation.observed_at.clone()),
            stale: false,
            principal_binding: Some(observation.binding.clone()),
            access_basis: Some(ModelAccessBasis::ConfirmedModelEntitlement),
        });
        observation
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_auth_codex_with_other_account_keeps_eligible_catalog_on_retry() -> Result<()> {
        use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;

        let _socket = CamAuthoritySocketTestGuard::install(None);
        let _policy = bind_fixture_routing_policy()?;
        let accounts = vec![(
            SupervisorRuntime::Grok,
            qualified_account_fixture("grok-cli", "unrelated-account-model", "high"),
        )];
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection_with_accounts(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &accounts,
        )?;
        assert!(resolution.selection_preflight_failure.is_none());
        for event in &resolution.decisions {
            let input = &event.provenance.normalized_input;
            assert_eq!(input.catalogs.len(), 1);
            assert_eq!(input.catalogs[0].runtime, "codex");
            assert!(input.catalogs[0].models.iter().any(|model| model.available));
            assert_eq!(
                event.provenance.choice.as_ref().unwrap().candidate.runtime,
                "codex"
            );
            assert!(input.quota_source.is_none());
            assert!(input
                .operational_observations
                .as_ref()
                .unwrap()
                .quota
                .is_none());
            assert!(input.pools[0].observation_source.is_none());
            assert!(input.pools[0].admission_provenance.contains(
                "external account quota and marginal-price observations were unavailable"
            ));
        }
        let mut state = resolution.automatic_state.context("local-auth state")?;
        assert!(state.account_observations.is_empty());
        assert!(state.account_observation.is_none());
        let replay = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        assert_eq!(
            replay.runtime_overrides[&AgentRole::Worker],
            SupervisorRuntime::Codex
        );
        assert_eq!(
            replay.decisions[0].1.normalized_input.catalogs[0].runtime,
            "codex"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn configured_cam_codex_without_primary_account_refuses_catalog_fallback() -> Result<()> {
        use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;

        let root = tempfile::tempdir()?;
        let socket = root.path().join("missing-authority.sock");
        let _socket = CamAuthoritySocketTestGuard::install(Some(socket.as_os_str()));
        let _policy = bind_fixture_routing_policy()?;
        let accounts = [(
            SupervisorRuntime::Grok,
            qualified_account_fixture("grok-cli", "unrelated-account-model", "high"),
        )];
        let catalog = codex_catalog()?;
        for observations in [&accounts[..], &[]] {
            let error = initialize_supervisor_selection_with_accounts(
                &mut test_plan(),
                SupervisorRuntime::Codex,
                &catalog,
                &test_admission(),
                &AdvertisedCatalogSet::empty(),
                Some(&default_resolved_profile()),
                SupervisorQuotaSelectionInput::default(),
                None,
                observations,
            )
            .unwrap_err();
            assert!(error.to_string().contains(
                "configured CAM account catalog set is missing the selected primary runtime binding"
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn local_auth_review_keeps_selector_gates_and_scoped_authority() -> Result<()> {
        use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;
        use crate::selection::routing_policy::*;

        let _socket = CamAuthoritySocketTestGuard::install(None);
        let _policy = bind_fixture_routing_policy()?;
        let run_id = format!(
            "local-review-{}",
            crate::artifacts::state_auth::random_identifier()?
        );
        crate::account_authority::record_observed_codex_selection_from_source(
            Some(&run_id),
            "codex-cli",
            None,
            None,
            None,
        );
        assert!(frozen_review_account_binding(SupervisorRuntime::Codex, &run_id)?.is_none());
        let catalog = codex_catalog()?;
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )?;
        assert!(resolution.selection_preflight_failure.is_none());
        let baseline = &resolution
            .decisions
            .iter()
            .find(|event| event.role == AgentRole::Auditor)
            .context("Auditor baseline")?
            .provenance;
        let before = captured_selected_authorizations();
        let lens = &plan.review_lenses[0];
        // This is the same serde validation used when registration rereads the
        // registry left by a completed Worker before adding the Auditor probe.
        let worker = before.get("worker").context("Worker selector seal")?;
        let worker_record = crate::agent_lifecycle::AgentProcessRecord {
            pid: 1,
            process_start_time: "fixture-worker-start".to_string(),
            role: "worker".to_string(),
            run_id: run_id.clone(),
            task_id: "assignment-001".to_string(),
            parent: Some(run_id.clone()),
            repo: PathBuf::from("/workspace"),
            argv: vec![
                "codex".to_string(),
                "app-server".to_string(),
                "-c".to_string(),
                format!("model={:?}", worker.model),
                "-c".to_string(),
                format!("model_reasoning_effort={:?}", worker.effort.as_str()),
            ],
            launch_timestamp_ms: 1,
            mechanical_executor: None,
        };
        let registry_record = serde_json::to_vec(&worker_record)?;
        let select = |lens: &ReviewLensConfig, catalog: &RuntimeModelCatalog, run_id: &str| {
            select_authored_review_lens(
                lens,
                lens.backend.reasoning_effort().unwrap(),
                SupervisorRuntime::Codex,
                catalog,
                baseline,
                ReviewLensAccount::LocalAuth { run_id },
                SupervisorQuotaSelectionInput::default(),
            )
        };
        let selected = select(lens, &catalog, &run_id)?;
        {
            let (_guard, decision) = selected.bind()?;
            let candidate = &decision.choice.as_ref().context("lens choice")?.candidate;
            validate_selected_launch(
                "auditor",
                "codex",
                &candidate.model,
                candidate.effort.as_str(),
            )?;
            assert_eq!(
                serde_json::from_slice::<crate::agent_lifecycle::AgentProcessRecord>(
                    &registry_record
                )?,
                worker_record
            );
            assert!(validate_selected_model("worker", "unselected-worker-model").is_err());
            assert!(validate_selected_model("auditor", "unselected-auditor-model").is_err());
            let mut unauthorized = serde_json::to_value(&worker_record)?;
            unauthorized["argv"][3] = serde_json::json!("model=\"unselected-worker-model\"");
            assert!(
                serde_json::from_value::<crate::agent_lifecycle::AgentProcessRecord>(unauthorized)
                    .is_err()
            );
            assert_eq!(decision.normalized_task, baseline.normalized_task);
            assert!(decision
                .normalized_input
                .catalogs
                .iter()
                .flat_map(|catalog| &catalog.models)
                .all(|model| model.access.is_none()));
            assert!(decision.normalized_input.quota_source.is_none());
            assert!(decision
                .normalized_input
                .pools
                .iter()
                .all(|pool| pool.observation_source.is_none()));
        }
        assert_eq!(captured_selected_authorizations(), before);

        let unavailable =
            RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(["other-model"])?);
        assert!(select(lens, &unavailable, &run_id).is_err());
        assert!(select(lens, &catalog, "never-admitted-local-review").is_err());
        let mut weak = lens.clone();
        if let ReviewLensBackendConfig::Model { model, .. } = &mut weak.backend {
            *model = ECONOMY_PROFILE_MODEL.to_string();
        }
        assert!(select(&weak, &catalog, &run_id).is_err());
        let mut wrong_role = baseline.clone();
        wrong_role.normalized_input.task.authority_role = AuthorityRole::TerminalLeaf;
        assert!(select_authored_review_lens(
            lens,
            lens.backend.reasoning_effort().unwrap(),
            SupervisorRuntime::Codex,
            &catalog,
            &wrong_role,
            ReviewLensAccount::LocalAuth { run_id: &run_id },
            SupervisorQuotaSelectionInput::default(),
        )
        .is_err());

        // A CAM appearing after selection must also refuse before authority binds.
        let selected = select(lens, &catalog, &run_id)?;
        let _configured = CamAuthoritySocketTestGuard::install(Some(std::ffi::OsStr::new(
            "/tmp/unavailable-review-cam.sock",
        )));
        assert!(frozen_review_account_binding(SupervisorRuntime::Codex, &run_id).is_err());
        assert!(select(lens, &catalog, &run_id).is_err());
        assert!(selected.bind().is_err());
        assert_eq!(captured_selected_authorizations(), before);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn review_refuses_missing_binding_and_configured_cam_without_selection() -> Result<()> {
        use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;
        let _socket = CamAuthoritySocketTestGuard::install(None);
        assert!(
            frozen_review_account_binding(SupervisorRuntime::Codex, "unadmitted-review").is_err()
        );
        let run_id = format!(
            "missing-review-{}",
            crate::artifacts::state_auth::random_identifier()?
        );
        crate::account_authority::record_observed_codex_selection(
            Some(&run_id),
            "codex-cli",
            None,
            None,
        );
        assert!(frozen_review_account_binding(SupervisorRuntime::Codex, &run_id).is_err());
        let _configured = CamAuthoritySocketTestGuard::install(Some(std::ffi::OsStr::new(
            "/tmp/unavailable-review-cam.sock",
        )));
        assert!(frozen_review_account_binding(SupervisorRuntime::Codex, &run_id).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mixed_accounts_survive_role_initialization_and_reselection() -> Result<()> {
        use crate::selection::routing_policy::*;
        let temp = tempfile::tempdir()?;
        let mut frozen = load_routing_policy(temp.path())?;
        frozen.policy.default_role.preferred_effort = Some(SelectorEffort::Medium);
        let mut worker = frozen.policy.default_role.clone();
        worker.preferred_effort = Some(SelectorEffort::None);
        frozen
            .policy
            .role_preferences
            .insert("worker".into(), worker);
        frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        let _policy = bind_routing_policy(Some(frozen))?;
        // Use a dated permitted control model. Medium has no measured worker fit,
        // so this fixture continues to exercise effort-driven mixed-account routing.
        let accounts = vec![
            (
                SupervisorRuntime::Codex,
                qualified_account_fixture("codex-cli", "gpt-6.1-sol", "medium"),
            ),
            (
                SupervisorRuntime::Grok,
                qualified_account_fixture("grok-cli", "account-worker-fixture", "none"),
            ),
        ];
        let mut plan = test_plan();
        let catalog = RuntimeModelCatalog::OperatorDeclared;
        let resolution = initialize_supervisor_selection_with_accounts(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &accounts,
        )?;
        assert!(
            resolution.selection_preflight_failure.is_none(),
            "{:?}",
            resolution.selection_preflight_failure
        );
        for event in &resolution.decisions {
            assert_eq!(event.provenance.normalized_input.catalogs.len(), 2);
            assert_eq!(event.provenance.normalized_input.pools.len(), 2);
            let selected = &event.provenance.choice.as_ref().unwrap().candidate;
            assert_eq!(
                selected.runtime,
                if event.role == AgentRole::Worker {
                    "grok"
                } else {
                    "codex"
                }
            );
        }
        let mut state = resolution
            .automatic_state
            .context("automatic mixed-account state")?;
        assert_eq!(state.account_observations, accounts);
        let replay = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        assert_eq!(
            replay.runtime_overrides[&AgentRole::Worker],
            SupervisorRuntime::Grok
        );
        assert_eq!(replay.decisions[0].1.normalized_input.catalogs.len(), 2);
        assert_eq!(replay.decisions[0].1.normalized_input.pools.len(), 2);
        // A stale secondary source identity is rejected again on replay; the
        // primary's valid binding must never substitute for that principal.
        state.account_observations[1].1.binding.selection_revision += 1;
        assert!(reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            2,
            BudgetSignal::Continue,
            &[],
        )
        .is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_secondary_principal_refuses_before_role_initialization() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let mut secondary = qualified_account_fixture("grok-cli", "secondary-fixture", "high");
        secondary
            .models
            .as_mut()
            .unwrap()
            .content
            .as_mut()
            .unwrap()
            .provenance
            .as_mut()
            .unwrap()
            .principal_binding
            .as_mut()
            .unwrap()
            .account_incarnation = "different-incarnation".into();
        let accounts = vec![
            (
                SupervisorRuntime::Codex,
                qualified_account_fixture("codex-cli", "primary-fixture", "high"),
            ),
            (SupervisorRuntime::Grok, secondary),
        ];
        let mut plan = test_plan();
        assert!(initialize_supervisor_selection_with_accounts(
            &mut plan,
            SupervisorRuntime::Codex,
            &RuntimeModelCatalog::OperatorDeclared,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &accounts,
        )
        .is_err());
        assert!(plan.role_models.is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_worker_ignores_unused_orchestrator_effort_but_keeps_required_audit() -> Result<()> {
        use crate::selection::routing_policy::*;
        let temp = tempfile::tempdir()?;
        let mut frozen = load_routing_policy(temp.path())?;
        let mut unsupported = frozen.policy.default_role.clone();
        unsupported.preferred_effort = Some(SelectorEffort::Xhigh);
        unsupported.minimum_effort = Some(SelectorEffort::Xhigh);
        frozen
            .policy
            .role_preferences
            .insert("child_orchestrator".into(), unsupported.clone());
        frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        let _policy = bind_routing_policy(Some(frozen.clone()))?;
        // Judgment roles require a dated permitted model, even with loaded policy.
        let accounts = vec![(
            SupervisorRuntime::Codex,
            qualified_account_fixture("codex-cli", "gpt-6.1-sol", "none"),
        )];
        let mut plan = test_plan();
        plan.assignments = vec![serde_json::from_value(json!({
            "id":"direct", "phase":"execution", "role":"worker", "assigned_paths":["src/a.rs"]
        }))?];
        let required = required_selector_roles(&plan);
        assert!(!required.contains(&AgentRole::ChildOrchestrator));
        let resolution = initialize_supervisor_selection_with_accounts(
            &mut plan,
            SupervisorRuntime::Codex,
            &RuntimeModelCatalog::OperatorDeclared,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &accounts,
        )?;
        assert!(
            resolution.selection_preflight_failure.is_none(),
            "{:?}",
            resolution.selection_preflight_failure
        );
        assert_eq!(resolution.decisions.len(), required.len());
        assert!(!plan.role_models.contains_key(&AgentRole::ChildOrchestrator));
        for gate in [
            AgentRole::Supervisor,
            AgentRole::GateClassifier,
            AgentRole::Auditor,
        ] {
            assert!(plan.role_models.contains_key(&gate));
        }
        assert!(resolution.automatic_state.is_some());
        frozen
            .policy
            .role_preferences
            .insert("auditor".into(), unsupported);
        frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        let _required_audit = bind_routing_policy(Some(frozen))?;
        plan.role_models.clear();
        let refusal = initialize_supervisor_selection_with_accounts(
            &mut plan,
            SupervisorRuntime::Codex,
            &RuntimeModelCatalog::OperatorDeclared,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &accounts,
        )?;
        assert_eq!(
            refusal.selection_preflight_failure.unwrap().role,
            AgentRole::Auditor
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn assessed_normal_intake_projects_task_before_evaluation_and_recounts_final_scopes(
    ) -> Result<()> {
        use crate::selection::routing_policy::*;
        let temp = tempfile::tempdir()?;
        let frozen = load_routing_policy(temp.path())?;
        let proposal: crate::planning::TaskDecompositionProposal = serde_json::from_value(json!({
            "fragments":[{"id":"a","text":"Create marker.txt with one line: ready"}],
            "assignments":[{"id":"a","task":"Create marker.txt with one line: ready",
                "fragment_ids":["a"],"assigned_paths":["marker.txt"],
                "semantic_symbols":[],"semantic_modules":[]}],
            "diagnostics":{"degraded":false,"notes":[]},
            "disjointness":{"disjoint":true,"conflicts":[]}
        }))?;
        let mut plan = test_plan();
        plan.task = "Create marker.txt with one line: ready".into();
        plan.assignments = vec![serde_json::from_value(json!({
            "id":"assessed-intake","phase":"execution","role":"worker",
            "assigned_paths":["marker.txt"]
        }))?];
        let low = super::super::task_routing::assess_task_routing(&plan.task, &proposal, &frozen)?;
        let low_features = routing_features_with_assessment(&plan, Some(&low), Some(&frozen))?;
        let low_profile = task_profile_with_assessment(
            AgentRole::Worker,
            Some(&low),
            Some(&low_features),
            Some(&frozen),
        )?;
        plan.task = "Delete obsolete data in a long-running multi-stage migration".into();
        let high = super::super::task_routing::assess_task_routing(&plan.task, &proposal, &frozen)?;
        let high_features = routing_features_with_assessment(&plan, Some(&high), Some(&frozen))?;
        let high_profile = task_profile_with_assessment(
            AgentRole::Worker,
            Some(&high),
            Some(&high_features),
            Some(&frozen),
        )?;
        assert_ne!(low_profile.risk, high_profile.risk);
        assert_ne!(low_profile.horizon, high_profile.horizon);
        assert_eq!(low_profile.authority_role, high_profile.authority_role);
        assert_eq!(low_profile.task_class, high_profile.task_class);
        // The lowered scope is recounted independently of the original declaration.
        plan.assignments[0]
            .assigned_paths
            .push(PathBuf::from("another.txt"));
        let features = routing_features_with_assessment(&plan, Some(&high), Some(&frozen))?;
        assert_eq!(features.scope_paths, 2);
        assert_eq!(high.features.scope_paths, 1);
        assert_eq!(features.context_tokens, high.features.context_tokens);
        let observations = [(
            SupervisorRuntime::Codex,
            account_observe_result("codex-cli", observed_sol_high_xhigh(), None),
        )];
        let high_task = plan.task.clone();
        plan.task = "Create marker.txt with one line: ready".into();
        let low_final_features =
            routing_features_with_assessment(&plan, Some(&low), Some(&frozen))?;
        let low_final_profile = task_profile_with_assessment(
            AgentRole::Worker,
            Some(&low),
            Some(&low_final_features),
            Some(&frozen),
        )?;
        assert_ne!(low_final_profile.boundedness, low_profile.boundedness);
        assert_eq!(low_final_profile.risk, low_profile.risk);
        assert_eq!(low_final_profile.context, low_profile.context);
        assert_eq!(low_final_profile.horizon, low_profile.horizon);
        assert_eq!(low_final_profile.authority_role, low_profile.authority_role);
        assert_eq!(low_final_profile.task_class, low_profile.task_class);
        let (low_selected, low_decision) = select_normal_account_intake_with_assessment(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            None,
            Some(&low),
        )?;
        assert_eq!(low_decision.normalized_input.task, low_final_profile);
        assert_eq!(
            low_decision
                .routing_policy
                .as_ref()
                .context("final-scope receipt")?
                .features,
            low_final_features
        );
        assert_eq!(
            low_selected.context("final-scope selection")?.task_features,
            low_final_features
        );
        // The account-combined initializer uses this same profile before catalogs/history.
        let admission = test_admission();
        let objective = default_resolved_profile();
        let catalog = RuntimeModelCatalog::OperatorDeclared;
        let advertised = AdvertisedCatalogSet::empty();
        let args = SelectionInputForRoleArgs {
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Codex,
            catalog: &catalog,
            advertised: &advertised,
            admission: &admission,
            resolved_objective_profile: &objective,
            quota_context: None,
            quota_ledger: None,
            account_observation: Some(&observations[0].1),
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
                accepted_task_cost_context: None,
                accepted_task_cost_observations: Vec::new(),
            },
            debug_override: None,
            history: None,
        };
        for accounts in [&observations[..], &[]] {
            let input = selection_input_for_role_with_assessment_and_accounts(
                args.clone(),
                accounts,
                Some(&low),
                Some(&low_final_features),
                Some(&frozen),
            )?;
            assert_eq!(input.task, low_final_profile);
        }
        plan.task = high_task;
        let (selected, decision) = select_normal_account_intake_with_assessment(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            None,
            Some(&high),
        )?;
        let selected = selected.context("assessed account selection")?;
        let final_high_profile = task_profile_with_assessment(
            AgentRole::Worker,
            Some(&high),
            Some(&features),
            Some(&frozen),
        )?;
        assert_eq!(decision.normalized_input.task, final_high_profile);
        assert_eq!(
            decision
                .routing_policy
                .as_ref()
                .context("assessment receipt")?
                .features,
            features
        );
        assert_eq!(selected.task_features, features);
        assert_eq!(
            selected.candidate(),
            &decision
                .choice
                .as_ref()
                .context("assessed choice")?
                .candidate
        );
        plan.task.push_str(" changed");
        assert!(select_normal_account_intake_with_assessment(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            None,
            Some(&high)
        )
        .is_err());
        let unknown = task_profile_with_assessment(AgentRole::Worker, None, None, Some(&frozen))?;
        assert_eq!(unknown.risk, RiskLevel::Unknown);
        assert_eq!(unknown.context, ContextSize::Unknown);
        assert_eq!(unknown.horizon, TaskHorizon::Unknown);
        assert_eq!(unknown.boundedness, Boundedness::Unknown);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_intake_uses_its_frozen_policy_and_preserves_refusal_evidence() -> Result<()> {
        use crate::selection::routing_policy::*;
        use coding_agent_manager_lib::account_authority::ModelAccessOutcome;
        let temp = tempfile::tempdir()?;
        let allow = load_routing_policy(temp.path())?;
        let mut reject = allow.clone();
        reject.policy.unknown_access_policy = UnknownAccessPolicy::Reject;
        reject.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&reject.policy)?);
        let _ambient = bind_routing_policy(Some(reject.clone()))?;
        let mut plan = test_plan();
        plan.assignments = vec![serde_json::from_value(json!({
            "id":"bounded-intake", "phase":"execution", "role":"worker",
            "assigned_paths":["src/a.rs"]
        }))?];
        let observation = account_observe_result(
            "codex-cli",
            CategoryObservation::observed(ModelsObservation {
                provenance: None,
                models: vec![ObservedModel {
                    model_id: FRONTIER_PROFILE_MODEL.into(),
                    supported_efforts: Some(vec!["low".into()]),
                    default_effort: None,
                    access: ModelAccessOutcome::UnknownAccess,
                }],
            }),
            None,
        );
        let observations = [(SupervisorRuntime::Codex, observation)];
        let admission = test_admission();
        let objective = default_resolved_profile();
        let (selected, decision) = select_normal_account_intake_with_history(
            &plan,
            &allow,
            &observations,
            &admission,
            &objective,
            None,
        )?;
        assert!(!selected
            .context("productive attempt selection")?
            .access_uncertainty
            .is_empty());
        assert_eq!(decision.status, DecisionStatus::Selected);
        assert_eq!(decision.routing_policy.as_ref().unwrap().frozen, allow);
        let evidence = decision.candidate_set[0]
            .loaded_policy_evidence
            .as_ref()
            .unwrap();
        assert_eq!(evidence.quality_basis_points, None);
        assert_eq!(evidence.expected_accepted_cycle_cost_microunits, None);
        assert_eq!(current_routing_policy(), Some(reject.clone()));
        let (selected, refusal) = select_normal_account_intake_with_history(
            &plan,
            &reject,
            &observations,
            &admission,
            &objective,
            None,
        )?;
        assert!(selected.is_none());
        assert_eq!(refusal.status, DecisionStatus::FailClosed);
        assert!(refusal.candidate_set[0]
            .ineligibility_reasons
            .iter()
            .any(|reason| { reason.code == selection::IneligibilityCode::CatalogUnavailable }));
        assert_eq!(current_routing_policy(), Some(reject));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_review_auditor_selects_required_role_before_evaluation() -> Result<()> {
        use crate::selection::routing_policy::*;
        let temp = tempfile::tempdir()?;
        let frozen = load_routing_policy(temp.path())?;
        let _policy = bind_routing_policy(Some(frozen.clone()))?;
        let mut plan = test_plan();
        plan.assignments[0].role = AgentRole::Worker;
        let observations = [(
            SupervisorRuntime::Codex,
            account_observe_result("codex-cli", observed_sol_high_xhigh(), None),
        )];
        let (assessment, _) = fixture_task_assessment_for_policy(&plan, &frozen)?;
        let (selected, decision) = crate::supervise::select_account_review_auditor_with_assessment(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            Some(&assessment),
        )?;
        let selected = selected.context("account review selection")?;
        let receipt = decision
            .routing_policy
            .as_ref()
            .context("review policy receipt")?;
        assert_eq!(plan.assignments[0].role, AgentRole::Worker);
        assert_eq!(
            decision.normalized_input.task.authority_role,
            AuthorityRole::ReviewAuditor
        );
        assert_eq!(receipt.role, AgentRole::Auditor.as_str());
        assert_eq!(receipt.frozen, frozen);
        assert_eq!(
            selected.candidate(),
            &decision.choice.as_ref().context("review choice")?.candidate
        );
        assert_eq!(selected.policy_digest, frozen.sha256);
        assert_eq!(selected.task_features, receipt.features);
        assert_eq!(
            selected.account_binding(),
            &AccountBinding::from(&observations[0].1.binding)
        );
        assert!(!selected.access_uncertainty.is_empty());
        let candidate = selected.candidate();
        validate_selected_launch(
            AgentRole::Auditor.as_str(),
            &candidate.runtime,
            &candidate.model,
            candidate.effort.as_str(),
        )?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_review_auditor_selects_grok_from_supported_unknown_access_catalog() -> Result<()> {
        use crate::selection::routing_policy::*;
        use crate::supervise::model_policy::{
            ModelCapabilityClass, ModelCapabilityEvidence, ModelCapabilityPolicy,
        };
        use crate::supervise::prior_input::{bind_operator_prior_data, OperatorPriorSnapshot};
        use coding_agent_manager_lib::account_authority::ModelAccessOutcome;
        use std::io::Write;
        use std::path::Path;
        const FIXTURE_MODEL_ID: &str = "grok-review-account-fixture";
        let temp = tempfile::tempdir()?;
        git2::Repository::init(temp.path())?;
        let frozen = load_routing_policy(temp.path())?;
        let _policy = bind_routing_policy(Some(frozen.clone()))?;
        let task = task_profile_for_role(AgentRole::Auditor);
        let base = base_selector_priors_with_terminal_worker_economics()?;
        let mut prior = base
            .models
            .iter()
            .find(|row| {
                base.measured_authority_eligibility(&row.model, AuthorityRole::ReviewAuditor)
                    == selection::MeasuredAuthorityEligibility::Eligible
                    && row.class_fit.iter().any(|fit| {
                        fit.task_class == "review_gate"
                            && (row.strong_gate_fallback_efforts.contains(&fit.effort)
                                || row.authority_evidence.iter().any(|evidence| {
                                    evidence.role == AuthorityRole::ReviewAuditor
                                        && evidence.task_class == "review_gate"
                                        && evidence.effort == fit.effort
                                }))
                    })
            })
            .cloned()
            .context("retained eligible ReviewAuditor profile")?;
        // ONE synthetic alias retains original evidence, samples, quality,
        // effort menu and prohibitions. No live Grok model or billing assertion.
        prior.runtime = runtime_name(SupervisorRuntime::Grok).to_string();
        prior.model = FIXTURE_MODEL_ID.to_string();
        prior.source_id = "synthetic-grok-review-account-fixture".to_string();
        prior.prior_scope = "nonlive unknown-access review catalog fixture only".to_string();
        prior.limitations.push(
            "synthetic alias; not measured Grok capability, live entitlement or billing"
                .to_string(),
        );
        let mut advertised_efforts = Vec::new();
        for fit in &prior.class_fit {
            if fit.task_class != "review_gate" {
                continue;
            }
            let effort = fit.effort;
            if !(prior.strong_gate_fallback_efforts.contains(&effort)
                || prior.authority_evidence.iter().any(|evidence| {
                    evidence.role == AuthorityRole::ReviewAuditor
                        && evidence.task_class == "review_gate"
                        && evidence.effort == effort
                }))
            {
                continue;
            }
            if !advertised_efforts.contains(&effort) {
                advertised_efforts.push(effort);
            }
        }
        assert!(
            !advertised_efforts.is_empty(),
            "retained ReviewAuditor profile must advertise a review-gate effort menu"
        );
        let snapshot = OperatorPriorSnapshot {
            schema_version: 1,
            dataset_id: "synthetic-grok-review-account-prior".to_string(),
            revision: format!("{}+synthetic-grok-review-account", base.revision),
            published_on: base.published_on.clone(),
            models: vec![prior],
            capability_policy: ModelCapabilityPolicy {
                id: "synthetic-grok-review-account-capability".to_string(),
                version: 1,
                source: "nonlive unknown-access review catalog fixture only".to_string(),
                models: vec![ModelCapabilityEvidence {
                    model: FIXTURE_MODEL_ID.to_string(),
                    capability: ModelCapabilityClass::CriticalJudgment,
                    eligible: true,
                    evidence: "synthetic fixture only; not live Grok capability evidence"
                        .to_string(),
                    as_of: base.published_on.clone(),
                }],
            },
        };
        let relative = Path::new("synthetic-grok-review-account-prior.json");
        let mut prior_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp.path().join(relative))
            .context("exclusive fixture prior file")?;
        prior_file
            .write_all(&serde_json::to_vec(&snapshot).context("serialize fixture prior")?)
            .context("write fixture prior")?;
        drop(prior_file);
        let _prior_guard = bind_operator_prior_data(temp.path(), relative)
            .context("bind labelled synthetic review prior")?;
        let priors = selector_priors_with_terminal_worker_economics()?;
        // Reuse retained capability/effort data without granting account access.
        let models = priors
            .models
            .iter()
            .filter(|prior| prior.runtime == runtime_name(SupervisorRuntime::Grok))
            .filter_map(|prior| catalog_model_from_prior(prior, &task, false).transpose())
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|mut model| {
                model
                    .supported_efforts
                    .retain(|effort| advertised_efforts.contains(effort));
                if model.supported_efforts.is_empty() {
                    return None;
                }
                let default_effort = if model.supported_efforts.len() == 1 {
                    Some(model.supported_efforts[0].as_str().to_string())
                } else {
                    None
                };
                Some(ObservedModel {
                    model_id: model.model,
                    supported_efforts: Some(
                        model
                            .supported_efforts
                            .iter()
                            .map(|effort| effort.as_str().to_string())
                            .collect(),
                    ),
                    default_effort,
                    access: ModelAccessOutcome::UnknownAccess,
                })
            })
            .collect::<Vec<_>>();
        assert!(
            !models.is_empty(),
            "existing Grok review model/effort fixture"
        );
        let observation = account_observe_result(
            "grok-cli",
            CategoryObservation::observed(ModelsObservation {
                provenance: None,
                models,
            }),
            None,
        );
        let expected_binding = AccountBinding::from(&observation.binding);
        let observations = [(SupervisorRuntime::Grok, observation)];
        let plan = test_plan();
        let (assessment, _) = fixture_task_assessment_for_policy(&plan, &frozen)?;
        let (selected, decision) = crate::supervise::select_account_review_auditor_with_assessment(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            Some(&assessment),
        )?;
        let selected = selected.context("Grok account review selection")?;
        let receipt = decision
            .routing_policy
            .as_ref()
            .context("Grok review policy receipt")?;
        assert_eq!(decision.status, DecisionStatus::Selected);
        assert_eq!(
            decision.normalized_input.task.authority_role,
            AuthorityRole::ReviewAuditor
        );
        assert_eq!(receipt.role, AgentRole::Auditor.as_str());
        assert_eq!(receipt.frozen, frozen);
        assert_eq!(
            selected.candidate().runtime,
            runtime_name(SupervisorRuntime::Grok)
        );
        assert_eq!(
            selected.candidate(),
            &decision
                .choice
                .as_ref()
                .context("Grok review choice")?
                .candidate
        );
        assert_eq!(selected.account_binding(), &expected_binding);
        assert_eq!(selected.policy_digest, frozen.sha256);
        assert_eq!(selected.task_features, receipt.features);
        assert!(!selected.access_uncertainty.is_empty());
        assert!(decision
            .candidate_set
            .iter()
            .any(|entry| { entry.eligible && &entry.candidate == selected.candidate() }));
        assert!(decision.normalized_input.catalogs.iter().all(|catalog| {
            catalog.runtime == runtime_name(SupervisorRuntime::Grok)
                && catalog
                    .models
                    .iter()
                    .all(|model| model.access == Some(ModelAccessOutcome::UnknownAccess))
        }));
        let candidate = selected.candidate();
        assert_eq!(candidate.model, FIXTURE_MODEL_ID);
        assert!(
            advertised_efforts
                .iter()
                .any(|effort| effort.as_str() == candidate.effort.as_str()),
            "selected review effort must be one advertised catalog menu member"
        );
        validate_selected_launch(
            AgentRole::Auditor.as_str(),
            &candidate.runtime,
            &candidate.model,
            candidate.effort.as_str(),
        )?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_account_intake_preserves_worker_and_orchestrator_roles() -> Result<()> {
        use crate::selection::routing_policy::*;
        let temp = tempfile::tempdir()?;
        let frozen = load_routing_policy(temp.path())?;
        let _ambient = bind_routing_policy(None)?;
        let observations = [(
            SupervisorRuntime::Codex,
            account_observe_result("codex-cli", observed_sol_high_xhigh(), None),
        )];
        for role in [AgentRole::Worker, AgentRole::ChildOrchestrator] {
            let mut plan = test_plan();
            plan.assignments[0].role = role;
            let (selected, decision) = select_normal_account_intake_with_history(
                &plan,
                &frozen,
                &observations,
                &test_admission(),
                &default_resolved_profile(),
                None,
            )?;
            let selected = selected.context("normal account selection")?;
            assert_eq!(
                decision.normalized_input.task.authority_role,
                task_profile_for_role(role).authority_role
            );
            assert_eq!(
                decision
                    .routing_policy
                    .as_ref()
                    .context("normal receipt")?
                    .role,
                role.as_str()
            );
            assert_eq!(
                selected.candidate(),
                &decision.choice.as_ref().context("normal choice")?.candidate
            );
            assert!(current_routing_policy().is_none());
            assert!(captured_selected_authorizations().is_empty());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_review_refuses_missing_or_foreign_receipts_before_sealing() -> Result<()> {
        use crate::selection::routing_policy::*;
        let temp = tempfile::tempdir()?;
        let frozen = load_routing_policy(temp.path())?;
        let mut foreign = frozen.clone();
        foreign.policy.unknown_access_policy = UnknownAccessPolicy::Reject;
        foreign.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&foreign.policy)?);
        let plan = test_plan();
        let observations = [(
            SupervisorRuntime::Codex,
            account_observe_result("codex-cli", observed_sol_high_xhigh(), None),
        )];
        for ambient in [None, Some(foreign.clone())] {
            let _policy = bind_routing_policy(ambient)?;
            assert!(select_account_review_auditor(
                &plan,
                &frozen,
                &observations,
                &test_admission(),
                &default_resolved_profile(),
            )
            .is_err());
            assert!(captured_selected_authorizations().is_empty());
        }
        let _policy = bind_routing_policy(Some(frozen.clone()))?;
        let (selected, decision) = select_account_intake_for_role_with_history(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            None,
            AgentRole::Auditor,
        )?;
        let selected = selected.context("review selection for receipt refusal")?;
        let mut missing = decision.clone();
        missing.routing_policy = None;
        let mut wrong_role = decision.clone();
        wrong_role.routing_policy.as_mut().unwrap().role = AgentRole::Worker.as_str().into();
        let mut wrong_policy = decision.clone();
        wrong_policy.routing_policy.as_mut().unwrap().frozen = foreign;
        let mut wrong_choice = decision.clone();
        wrong_choice
            .choice
            .as_mut()
            .unwrap()
            .candidate
            .model
            .push('-');
        let mut wrong_task = decision.clone();
        wrong_task.normalized_input.task.authority_role = AuthorityRole::TerminalLeaf;
        for invalid in [missing, wrong_role, wrong_policy, wrong_choice, wrong_task] {
            assert!(
                validate_and_seal_account_review_selection(&frozen, Some(&selected), &invalid)
                    .is_err()
            );
            assert!(captured_selected_authorizations().is_empty());
        }
        assert!(validate_and_seal_account_review_selection(&frozen, None, &decision).is_err());
        let mut wrong_request = selected.clone();
        wrong_request.policy_digest.push('0');
        assert!(validate_and_seal_account_review_selection(
            &frozen,
            Some(&wrong_request),
            &decision
        )
        .is_err());
        let candidate = selected.candidate();
        assert!(validate_selected_launch(
            AgentRole::Auditor.as_str(),
            &candidate.runtime,
            &candidate.model,
            candidate.effort.as_str(),
        )
        .is_err());
        assert!(captured_selected_authorizations().is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_review_preserves_evaluator_refusal_without_authorization() -> Result<()> {
        use crate::selection::routing_policy::*;
        let temp = tempfile::tempdir()?;
        let mut frozen = load_routing_policy(temp.path())?;
        frozen.policy.unknown_access_policy = UnknownAccessPolicy::Reject;
        frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        let _policy = bind_routing_policy(Some(frozen.clone()))?;
        let observations = [(
            SupervisorRuntime::Codex,
            account_observe_result("codex-cli", observed_sol_high_xhigh(), None),
        )];
        let plan = test_plan();
        let (assessment, _) = fixture_task_assessment_for_policy(&plan, &frozen)?;
        let (selected, decision) = crate::supervise::select_account_review_auditor_with_assessment(
            &plan,
            &frozen,
            &observations,
            &test_admission(),
            &default_resolved_profile(),
            Some(&assessment),
        )?;
        assert!(selected.is_none());
        assert_eq!(decision.status, DecisionStatus::FailClosed);
        assert_eq!(
            decision
                .routing_policy
                .as_ref()
                .context("refusal receipt")?
                .role,
            AgentRole::Auditor.as_str()
        );
        assert_eq!(
            decision.normalized_input.task.authority_role,
            AuthorityRole::ReviewAuditor
        );
        assert!(captured_selected_authorizations().is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_catalog_revision_binds_access_source_qualification() -> Result<()> {
        use coding_agent_manager_lib::account_authority::{
            ModelCatalogProvenance, ModelCatalogSourceKind,
        };
        let observation = account_observe_result("codex-cli", observed_sol_high_xhigh(), None);
        let observed = observation.models.unwrap().content.unwrap();
        let task = task_profile_for_role(AgentRole::Worker);
        let priors = selector_priors_with_terminal_worker_economics()?;
        let build = |models: &ModelsObservation| {
            runtime_catalog_from_observed_models(
                "codex",
                &observation.binding,
                models,
                observation.observed_at.clone(),
                &task,
                &priors,
            )
        };
        let unqualified = build(&observed)?;
        let mut cache = observed.clone();
        cache.provenance = Some(ModelCatalogProvenance {
            source_kind: ModelCatalogSourceKind::ManagedHomeCache,
            fetched_at: Some(observation.observed_at.clone()),
            stale: true,
            principal_binding: None,
            access_basis: None,
        });
        let cached_source = build(&cache)?;
        assert_eq!(unqualified.models, cached_source.models);
        assert_ne!(unqualified.revision, cached_source.revision);
        cache.models[0]
            .supported_efforts
            .as_mut()
            .unwrap()
            .reverse();
        cache.models[0]
            .supported_efforts
            .as_mut()
            .unwrap()
            .push("high".into());
        assert_eq!(build(&cache)?, cached_source);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn selected_launch_unknown_access_is_explicit_and_principal_or_effort_tampering_refuses(
    ) -> Result<()> {
        use crate::selection::routing_policy::*;
        use coding_agent_manager_lib::account_authority::{
            ModelAccessBasis, ModelAccessOutcome, ModelCatalogProvenance, ModelCatalogSourceKind,
        };
        let temp = tempfile::tempdir()?;
        let mut frozen = load_routing_policy(temp.path())?;
        let mut observation = account_observe_result(
            "codex-cli",
            CategoryObservation::observed(ModelsObservation {
                provenance: None,
                models: vec![ObservedModel {
                    model_id: "account-menu-model".into(),
                    supported_efforts: Some(vec!["none".into()]),
                    default_effort: Some("none".into()),
                    access: ModelAccessOutcome::UnknownAccess,
                }],
            }),
            None,
        );
        let candidate = CandidateKey {
            runtime: "codex".into(),
            model: "account-menu-model".into(),
            effort: SelectorEffort::None,
        };
        let features = routing_features_from_plan(&test_plan());
        let receipt = SelectedLaunchRequest::from_observation(
            candidate.clone(),
            &observation,
            &frozen,
            features.clone(),
            None,
        )?;
        assert!(!receipt.access_uncertainty.is_empty());
        frozen.policy.unknown_access_policy = UnknownAccessPolicy::Reject;
        frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        assert!(SelectedLaunchRequest::from_observation(
            candidate.clone(),
            &observation,
            &frozen,
            features.clone(),
            None
        )
        .is_err());
        frozen.policy.unknown_access_policy =
            UnknownAccessPolicy::UnknownAccessForProductiveAttempt;
        frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&frozen.policy)?);
        let models = observation
            .models
            .as_mut()
            .unwrap()
            .content
            .as_mut()
            .unwrap();
        models.models[0].access = ModelAccessOutcome::Unavailable;
        models.provenance = Some(ModelCatalogProvenance {
            source_kind: ModelCatalogSourceKind::AuthenticatedCatalog,
            fetched_at: Some(observation.observed_at.clone()),
            stale: false,
            principal_binding: Some(observation.binding.clone()),
            access_basis: Some(ModelAccessBasis::ConfirmedModelEntitlement),
        });
        assert!(SelectedLaunchRequest::from_observation(
            candidate.clone(),
            &observation,
            &frozen,
            features.clone(),
            None
        )
        .is_err());
        let models = observation
            .models
            .as_mut()
            .unwrap()
            .content
            .as_mut()
            .unwrap();
        models.models[0].access = ModelAccessOutcome::Available;
        let available = SelectedLaunchRequest::from_observation(
            candidate.clone(),
            &observation,
            &frozen,
            features.clone(),
            None,
        )?;
        assert!(available.access_uncertainty.is_empty());
        observation
            .models
            .as_mut()
            .unwrap()
            .content
            .as_mut()
            .unwrap()
            .provenance
            .as_mut()
            .unwrap()
            .principal_binding
            .as_mut()
            .unwrap()
            .selection_revision += 1;
        assert!(SelectedLaunchRequest::from_observation(
            candidate.clone(),
            &observation,
            &frozen,
            features.clone(),
            None
        )
        .is_err());
        let models = observation
            .models
            .as_mut()
            .unwrap()
            .content
            .as_mut()
            .unwrap();
        models.models[0].access = ModelAccessOutcome::UnknownAccess;
        models.provenance = None;
        models.models[0].supported_efforts = Some(vec!["deep".into()]);
        assert!(SelectedLaunchRequest::from_observation(
            candidate,
            &observation,
            &frozen,
            features,
            None
        )
        .is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn observed_sol_high_xhigh() -> CategoryObservation<ModelsObservation> {
        CategoryObservation::observed(ModelsObservation {
            provenance: None,
            models: vec![ObservedModel {
                access:
                    coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                model_id: FRONTIER_PROFILE_MODEL.to_string(),
                supported_efforts: Some(vec!["high".to_string(), "xhigh".to_string()]),
                default_effort: Some("high".to_string()),
            }],
        })
    }

    #[cfg(target_os = "linux")]
    fn selection_input_with_account_observation(
        observation: &AccountObserveResult,
        advertised: &AdvertisedCatalogSet,
    ) -> Result<SelectionInput> {
        let (assessment, features, frozen) = fixture_task_assessment(&test_plan())?;
        selection_input_with_account_observation_and_assessment(
            observation,
            advertised,
            Some(&assessment),
            Some(&features),
            Some(&frozen),
        )
    }

    #[cfg(target_os = "linux")]
    fn selection_input_with_account_observation_and_assessment(
        observation: &AccountObserveResult,
        advertised: &AdvertisedCatalogSet,
        assessment: Option<&TaskRoutingAssessment>,
        final_features: Option<&crate::selection::routing_policy::TaskRoutingFeatures>,
        frozen: Option<&crate::selection::routing_policy::FrozenRoutingPolicy>,
    ) -> Result<SelectionInput> {
        let catalog = codex_catalog()?;
        let admission = test_admission();
        let resolved = default_resolved_profile();
        selection_input_for_role_with_assessment(
            SelectionInputForRoleArgs {
                role: AgentRole::Worker,
                runtime: SupervisorRuntime::Codex,
                catalog: &catalog,
                advertised,
                admission: &admission,
                resolved_objective_profile: &resolved,
                quota_context: None,
                quota_ledger: None,
                account_observation: Some(observation),
                signals: DynamicSignals {
                    retry_count: 0,
                    budget_signal: BudgetSignal::Continue,
                    previous_choice: None,
                    previous_catalog_digest: None,
                    environment_rejections: Vec::new(),
                    accepted_task_cost_context: None,
                    accepted_task_cost_observations: Vec::new(),
                },
                debug_override: None,
                history: None,
            },
            assessment,
            final_features,
            frozen,
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_observe_admits_only_observed_model_and_effort() -> Result<()> {
        use crate::selection::routing_policy::{
            bind_routing_policy, load_routing_policy, RoutingPolicyReceipt, UnknownAccessPolicy,
        };

        let policy_root = tempfile::tempdir()?;
        let frozen = load_routing_policy(policy_root.path())?;
        assert_eq!(
            frozen.policy.unknown_access_policy,
            UnknownAccessPolicy::UnknownAccessForProductiveAttempt
        );
        let _policy = bind_routing_policy(Some(frozen.clone()))?;
        let mut plan = test_plan();
        plan.task = "Create marker.txt with one line: ready".to_string();
        plan.assignments = vec![serde_json::from_value(json!({
            "id":"marker", "phase":"execution", "role":"worker",
            "task": &plan.task, "assigned_paths":["marker.txt"]
        }))?];
        let proposal: crate::planning::TaskDecompositionProposal = serde_json::from_value(json!({
            "fragments":[{"id":"marker", "text": &plan.task}],
            "assignments":[{"id":"marker", "task": &plan.task,
                "fragment_ids":["marker"], "assigned_paths":["marker.txt"],
                "semantic_symbols":[], "semantic_modules":[]}],
            "diagnostics":{"degraded":false, "notes":[]},
            "disjointness":{"disjoint":true, "conflicts":[]}
        }))?;
        let assessment =
            super::super::task_routing::assess_task_routing(&plan.task, &proposal, &frozen)?;
        let features = routing_features_with_assessment(&plan, Some(&assessment), Some(&frozen))?;
        let observation = account_observe_result(
            "codex-cli",
            observed_sol_high_xhigh(),
            Some(CategoryObservation::unknown()),
        );
        let advertised = advertised_with_cursor(captured_cursor_observation()?);
        let input = selection_input_with_account_observation_and_assessment(
            &observation,
            &advertised,
            Some(&assessment),
            Some(&features),
            Some(&frozen),
        )?;
        assert_eq!(input.catalogs.len(), 1);
        assert_eq!(input.catalogs[0].runtime, "codex");
        assert_eq!(input.catalogs[0].models.len(), 1);
        assert_eq!(input.catalogs[0].models[0].model, FRONTIER_PROFILE_MODEL);
        assert_eq!(
            input.catalogs[0].models[0].supported_efforts,
            vec![SelectorEffort::High, SelectorEffort::Xhigh]
        );
        assert!(input
            .catalogs
            .iter()
            .all(|catalog| catalog.runtime != "cursor"));
        let receipt = RoutingPolicyReceipt {
            frozen,
            role: AgentRole::Worker.as_str().to_string(),
            features,
        };
        let decision = selection::select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
        let choice = decision.choice.as_ref().context("observed worker choice")?;
        assert_eq!(choice.candidate.runtime, "codex");
        assert_eq!(choice.candidate.model, FRONTIER_PROFILE_MODEL);
        assert!(matches!(
            choice.candidate.effort,
            SelectorEffort::High | SelectorEffort::Xhigh
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_observe_unknown_models_fail_closed() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let observation = account_observe_result(
            "codex-cli",
            CategoryObservation::unknown(),
            Some(CategoryObservation::unknown()),
        );
        let advertised = advertised_with_cursor(captured_cursor_observation()?);
        let mut plan = test_plan();
        let resolution = initialize_supervisor_selection_with_history(
            &mut plan,
            SupervisorRuntime::Codex,
            &codex_catalog()?,
            &test_admission(),
            &advertised,
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            Some(&observation),
        )?;
        let failure = resolution
            .selection_preflight_failure
            .context("unknown models must fail closed")?;
        assert_eq!(
            failure.kind,
            SupervisorSelectionPreflightFailureKind::FailClosed
        );
        assert!(plan.role_models.is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn grok_supervisor_unobserved_models_refusal_explains_catalog_and_authority() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let mut observation = account_observe_result(
            "grok-cli",
            CategoryObservation::unknown(),
            Some(CategoryObservation::unknown()),
        );
        observation.binding.account_id = "work2".to_string();
        observation.observed_at = "2026-10-17T05:39:11.151129602Z".to_string();
        // A separate CLI listing must not replace missing CAM-bound metadata.
        let advertised = advertised_with_grok(discover_grok_observation(CAPTURED_GROK_CATALOG)?);
        let mut plan = test_plan();
        plan.assignments = vec![worker_assignment()];
        let resolution = initialize_supervisor_selection_with_history(
            &mut plan,
            SupervisorRuntime::Grok,
            &RuntimeModelCatalog::OperatorDeclared,
            &test_admission(),
            &advertised,
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            Some(&observation),
        )?;
        let failure = resolution
            .selection_preflight_failure
            .context("Grok refusal")?;
        assert_eq!(failure.role, AgentRole::Supervisor);
        assert_eq!(
            failure.kind,
            SupervisorSelectionPreflightFailureKind::FailClosed
        );
        assert!(failure
            .message
            .contains("CAM model/effort metadata is unobserved or unusable"));
        assert!(failure
            .message
            .contains("loaded Grok priors explicitly prohibit"));
        assert!(failure.message.contains("--runtime codex"));
        assert!(failure.message.contains("docs/OPERATOR_QUICKSTART.md"));
        assert!(plan.role_models.is_empty());
        assert_eq!(
            resolution.decisions.len(),
            required_selector_roles(&plan).len()
        );
        assert!(resolution
            .decisions
            .iter()
            .all(|event| event.provenance.status == DecisionStatus::FailClosed));
        let decision = &resolution.decisions[0].provenance;
        assert_eq!(decision.status, DecisionStatus::FailClosed);
        assert_eq!(
            decision.normalized_task.authority_role,
            AuthorityRole::AcceptanceGate
        );
        assert_eq!(decision.normalized_task.task_class, "review_gate");
        assert_eq!(decision.normalized_input.catalogs.len(), 1);
        let catalog = &decision.normalized_input.catalogs[0];
        assert_eq!(catalog.runtime, "grok");
        assert!(catalog
            .revision
            .starts_with("account-observe-models-unobserved-sha256:"));
        assert!(catalog.models.is_empty());
        assert!(decision.candidate_set.is_empty());
        assert!(decision.choice.is_none());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn grok_supervisor_observed_known_and_unknown_models_still_fail_closed() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        for (model, expected_code) in [
            ("grok-4.6", selection::IneligibilityCode::PolicyProhibited),
            (
                "unknown-grok-model",
                selection::IneligibilityCode::MissingDatedPrior,
            ),
        ] {
            let observation = qualified_account_fixture("grok-cli", model, "xhigh");
            let mut plan = test_plan();
            plan.assignments = vec![worker_assignment()];
            let resolution = initialize_supervisor_selection_with_history(
                &mut plan,
                SupervisorRuntime::Grok,
                &RuntimeModelCatalog::OperatorDeclared,
                &test_admission(),
                &AdvertisedCatalogSet::empty(),
                Some(&default_resolved_profile()),
                SupervisorQuotaSelectionInput::default(),
                None,
                Some(&observation),
            )?;
            let failure = resolution
                .selection_preflight_failure
                .context("Grok refusal")?;
            assert_eq!(failure.role, AgentRole::Supervisor);
            assert_eq!(
                failure.kind,
                SupervisorSelectionPreflightFailureKind::FailClosed
            );
            assert!(!failure.message.contains("metadata is unobserved"));
            assert!(failure.message.contains("--runtime codex"));
            let decision = &resolution.decisions[0].provenance;
            assert!(decision.choice.is_none());
            assert_eq!(decision.candidate_set.len(), 1);
            let candidate = &decision.candidate_set[0];
            assert_eq!(candidate.candidate.model, model);
            assert!(!candidate.eligible);
            assert!(candidate
                .ineligibility_reasons
                .iter()
                .any(|reason| reason.code == expected_code));
            // A remaining control candidate on another runtime makes
            // the Grok-only remediation misleading, even on a refused decision.
            let mut mixed = decision.clone();
            let mut remaining = candidate.clone();
            remaining.candidate.runtime = "codex".into();
            mixed.candidate_set.push(remaining);
            assert!(!selection_refusal_message(&mixed, AgentRole::Supervisor)
                .contains("loaded Grok priors explicitly prohibit"));
            assert!(plan.role_models.is_empty());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_observe_does_not_fill_efforts_from_priors() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let observation = account_observe_result(
            "codex-cli",
            CategoryObservation::observed(ModelsObservation {
                provenance: None,
                models: vec![ObservedModel {
    access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                    model_id: FRONTIER_PROFILE_MODEL.to_string(),
                    supported_efforts: Some(vec!["high".to_string()]),
                    default_effort: None,
                }],
            }),
            Some(CategoryObservation::unknown()),
        );
        let input =
            selection_input_with_account_observation(&observation, &AdvertisedCatalogSet::empty())?;
        let listed = input
            .catalogs
            .iter()
            .find(|catalog| catalog.runtime == "codex")
            .and_then(|catalog| {
                catalog
                    .models
                    .iter()
                    .find(|model| model.model == FRONTIER_PROFILE_MODEL)
            })
            .context("observed sol catalog row")?;
        assert_eq!(listed.supported_efforts, vec![SelectorEffort::High]);
        assert!(!listed.supported_efforts.contains(&SelectorEffort::Xhigh));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_observe_unknown_quota_does_not_invent_zeros_or_price() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let observation = account_observe_result(
            "codex-cli",
            observed_sol_high_xhigh(),
            Some(CategoryObservation::unknown()),
        );
        let input =
            selection_input_with_account_observation(&observation, &AdvertisedCatalogSet::empty())?;
        let pool = input
            .pools
            .iter()
            .find(|pool| pool.runtime == "codex")
            .context("codex pool")?;
        assert!(!pool.entitlement_bounded);
        assert_eq!(pool.entitlement_capacity_units, 0);
        assert_eq!(pool.entitlement_remaining_units, 0);
        assert_eq!(pool.pool_pressure_basis_points, 0);
        assert_eq!(pool.marginal_cost_microunits, 0);
        assert!(pool.observation_source.is_none());
        assert!(input.quota_source.is_none());
        assert!(!pool.admission_provenance.contains("unavailable"));
        assert!(input
            .operational_observations
            .as_ref()
            .is_some_and(|observations| observations.quota.is_none()));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_observe_observed_quota_projects_utilization_without_price() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let observation = account_observe_result(
            "codex-cli",
            observed_sol_high_xhigh(),
            Some(CategoryObservation::observed(QuotaObservation {
                snapshots: vec![coding_agent_manager_lib::model::QuotaSnapshot {
                    account_id: "work".to_string(),
                    model: None,
                    utilization: 0.25,
                    window_label: Some("5h".to_string()),
                    resets_at: None,
                    captured_at: "2026-09-19T00:00:00Z".to_string(),
                    source: coding_agent_manager_lib::model::QuotaSource::LocalFile,
                }],
                plan_label: None,
            })),
        );
        let input =
            selection_input_with_account_observation(&observation, &AdvertisedCatalogSet::empty())?;
        let pool = input
            .pools
            .iter()
            .find(|pool| pool.runtime == "codex")
            .context("codex pool")?;
        assert!(!pool.entitlement_bounded);
        assert_eq!(pool.entitlement_capacity_units, 0);
        assert_eq!(pool.entitlement_remaining_units, 0);
        assert_eq!(pool.pool_pressure_basis_points, 2_500);
        assert_eq!(pool.marginal_cost_microunits, 0);
        assert!(pool.admission_provenance.contains("pressure only"));
        assert!(!pool.admission_provenance.contains("unavailable"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_observe_quota_does_not_become_environment_microunits() -> Result<()> {
        let observed_zero = account_observe_result(
            "codex-cli",
            observed_sol_high_xhigh(),
            Some(CategoryObservation::observed(QuotaObservation {
                snapshots: vec![coding_agent_manager_lib::model::QuotaSnapshot {
                    account_id: "work".to_string(),
                    model: None,
                    utilization: 0.0,
                    window_label: Some("5h".to_string()),
                    resets_at: None,
                    captured_at: "2026-09-19T00:00:00Z".to_string(),
                    source: coding_agent_manager_lib::model::QuotaSource::LocalFile,
                }],
                plan_label: None,
            })),
        );
        let (kind, microunits) = account_observe_environment_decision(&observed_zero);
        assert_eq!(kind, AccountObserveOutcomeKind::Observed);
        assert_eq!(microunits, None);
        assert_eq!(
            environment_cost_microunits_from_account_observe(kind, microunits),
            None
        );

        let unknown = account_observe_result(
            "codex-cli",
            observed_sol_high_xhigh(),
            Some(CategoryObservation::unknown()),
        );
        let (kind, microunits) = account_observe_environment_decision(&unknown);
        assert_eq!(kind, AccountObserveOutcomeKind::Unknown);
        assert_eq!(microunits, None);
        assert_eq!(
            environment_cost_microunits_from_account_observe(kind, Some(0)),
            None
        );

        let failed = account_observe_result(
            "codex-cli",
            observed_sol_high_xhigh(),
            Some(CategoryObservation::failed(ObservationError {
                kind: ObservationErrorKind::Other,
                message: "quota inspect failed".to_string(),
            })),
        );
        let (kind, microunits) = account_observe_environment_decision(&failed);
        assert_eq!(kind, AccountObserveOutcomeKind::Failed);
        assert_eq!(microunits, None);
        assert_eq!(
            environment_cost_microunits_from_account_observe(kind, Some(0)),
            None
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_observe_binding_runtime_mismatch_fail_closed() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let observation = account_observe_result(
            "grok-cli",
            CategoryObservation::observed(ModelsObservation {
                provenance: None,
                models: vec![ObservedModel {
    access: coding_agent_manager_lib::account_authority::ModelAccessOutcome::UnknownAccess,
                    model_id: "grok-4.6".to_string(),
                    supported_efforts: Some(vec!["high".to_string()]),
                    default_effort: None,
                }],
            }),
            Some(CategoryObservation::unknown()),
        );
        let error =
            selection_input_with_account_observation(&observation, &AdvertisedCatalogSet::empty())
                .expect_err("provider/runtime mismatch must fail closed");
        assert!(error
            .to_string()
            .contains("does not match selected runtime"));
        Ok(())
    }

    #[test]
    fn account_observe_none_keeps_advertised_catalog_path() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let advertised = advertised_with_grok(discover_grok_observation(CAPTURED_GROK_CATALOG)?);
        let priors = selector_priors_with_terminal_worker_economics()?;
        let catalogs = constructed_selection_catalogs(
            SupervisorRuntime::Grok,
            &RuntimeModelCatalog::OperatorDeclared,
            &advertised,
            &task_profile_for_role(AgentRole::Worker),
            &priors,
            None,
        )?;
        assert_eq!(catalogs.len(), 1);
        assert!(catalogs[0].revision.starts_with("grok-advertised-sha256:"));
        assert!(catalogs[0]
            .revision
            .ends_with(";auth=not_asserted_by_catalog"));
        let catalog = RuntimeModelCatalog::OperatorDeclared;
        let admission = test_admission();
        let resolved = default_resolved_profile();
        let input = selection_input_for_role(SelectionInputForRoleArgs {
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Grok,
            catalog: &catalog,
            advertised: &advertised,
            admission: &admission,
            resolved_objective_profile: &resolved,
            quota_context: None,
            quota_ledger: None,
            account_observation: None,
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
                accepted_task_cost_context: None,
                accepted_task_cost_observations: Vec::new(),
            },
            debug_override: None,
            history: None,
        })?;
        assert!(input.catalogs[0]
            .revision
            .starts_with("grok-advertised-sha256:"));
        assert!(input.pools[0].admission_provenance.contains("unavailable"));
        assert!(input.pools[0].entitlement_bounded);
        assert_eq!(
            input.pools[0].entitlement_remaining_units,
            input.pools[0].entitlement_capacity_units
        );
        Ok(())
    }
    #[test]
    fn assessed_fixture_keeps_missing_assessment_and_changed_task_fail_closed() -> Result<()> {
        let _fixture_policy = bind_fixture_routing_policy()?;
        let plan = test_plan();
        let (assessment, features, frozen) = fixture_task_assessment(&plan)?;
        assessment.validate_for_task(&frozen, &plan.task)?;
        assert_eq!(
            features.scope_paths,
            routing_features_from_plan(&plan).scope_paths
        );
        let assessed = task_profile_with_assessment(
            AgentRole::Worker,
            Some(&assessment),
            Some(&features),
            Some(&frozen),
        )?;
        assert_ne!(assessed.risk, RiskLevel::Unknown);
        let unknown = task_profile_with_assessment(AgentRole::Worker, None, None, Some(&frozen))?;
        assert_eq!(unknown.risk, RiskLevel::Unknown);
        assert_eq!(unknown.context, ContextSize::Unknown);
        assert_eq!(unknown.horizon, TaskHorizon::Unknown);
        assert_eq!(unknown.boundedness, Boundedness::Unknown);
        let catalog = codex_catalog()?;
        let advertised = AdvertisedCatalogSet::empty();
        let admission = test_admission();
        let objective = default_resolved_profile();
        let unassessed_input = super::selection_input_for_role(SelectionInputForRoleArgs {
            role: AgentRole::Worker,
            runtime: SupervisorRuntime::Codex,
            catalog: &catalog,
            advertised: &advertised,
            admission: &admission,
            resolved_objective_profile: &objective,
            quota_context: None,
            quota_ledger: None,
            account_observation: None,
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
                accepted_task_cost_context: None,
                accepted_task_cost_observations: Vec::new(),
            },
            debug_override: None,
            history: None,
        })?;
        let error = selection::select(&unassessed_input)
            .expect_err("generic None fixture wrapper must retain the unknown-risk refusal");
        assert!(error.to_string().contains("task.risk must be known"));
        #[cfg(target_os = "linux")]
        {
            let observations = [(
                SupervisorRuntime::Codex,
                account_observe_result("codex-cli", observed_sol_high_xhigh(), None),
            )];
            let error = super::select_normal_account_intake_with_history(
                &plan,
                &frozen,
                &observations,
                &admission,
                &objective,
                None,
            )
            .expect_err("generic None intake must retain the unknown-risk refusal");
            assert!(error.to_string().contains("task.risk must be known"));
            assert_eq!(
                crate::selection::routing_policy::current_routing_policy(),
                Some(frozen.clone())
            );
        }
        let mut missing = plan.clone();
        let error = super::initialize_supervisor_selection_with_assessment(
            &mut missing,
            SupervisorRuntime::Codex,
            &codex_catalog()?,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
            Some(&default_resolved_profile()),
            SupervisorQuotaSelectionInput::default(),
            None,
            &[],
            None,
        )
        .expect_err("production missing-assessment routing must remain unknown and fail closed");
        assert!(error.to_string().contains("task.risk must be known"));
        assert!(missing.role_models.is_empty());
        assert!(assessment
            .validate_for_task(&frozen, &format!("{} changed", plan.task))
            .is_err());
        let mut foreign = frozen.clone();
        foreign.policy.unknown_access_policy =
            crate::selection::routing_policy::UnknownAccessPolicy::Reject;
        foreign.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&foreign.policy)?);
        assert!(assessment.validate_for_task(&foreign, &plan.task).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_review_assessment_refuses_omitted_changed_task_and_foreign_policy() -> Result<()> {
        use crate::selection::routing_policy::*;
        let _policy = bind_fixture_routing_policy()?;
        let plan = test_plan();
        let frozen = current_routing_policy().context("held review policy")?;
        let (assessment, _) = fixture_task_assessment_for_policy(&plan, &frozen)?;
        let observations = [(
            SupervisorRuntime::Codex,
            account_observe_result("codex-cli", observed_sol_high_xhigh(), None),
        )];
        let admission = test_admission();
        let objective = default_resolved_profile();
        let error = crate::supervise::select_account_review_auditor(
            &plan,
            &frozen,
            &observations,
            &admission,
            &objective,
        )
        .expect_err("legacy missing-assessment review must retain its refusal");
        assert!(error.to_string().contains("task.risk must be known"));
        let error = crate::supervise::select_account_review_auditor_with_assessment(
            &plan,
            &frozen,
            &observations,
            &admission,
            &objective,
            None,
        )
        .expect_err("omitted review assessment must retain its refusal");
        assert!(error.to_string().contains("task.risk must be known"));
        assert!(captured_selected_authorizations().is_empty());
        let mut changed = plan.clone();
        changed.task.push_str(" changed");
        let error = crate::supervise::select_account_review_auditor_with_assessment(
            &changed,
            &frozen,
            &observations,
            &admission,
            &objective,
            Some(&assessment),
        )
        .expect_err("assessment from another declared task cannot select a reviewer");
        assert!(error
            .to_string()
            .contains("current canonical declared task"));
        assert!(captured_selected_authorizations().is_empty());
        let mut foreign = frozen.clone();
        foreign.policy.unknown_access_policy = UnknownAccessPolicy::Reject;
        foreign.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&foreign.policy)?);
        let (foreign_assessment, _) = fixture_task_assessment_for_policy(&plan, &foreign)?;
        let error = crate::supervise::select_account_review_auditor_with_assessment(
            &plan,
            &frozen,
            &observations,
            &admission,
            &objective,
            Some(&foreign_assessment),
        )
        .expect_err("assessment from another frozen policy cannot select a reviewer");
        assert!(error.to_string().contains("task assessment"));
        assert!(captured_selected_authorizations().is_empty());
        for ambient in [None, Some(foreign)] {
            let _ambient = bind_routing_policy(ambient)?;
            let error = crate::supervise::select_account_review_auditor_with_assessment(
                &plan,
                &frozen,
                &observations,
                &admission,
                &objective,
                Some(&assessment),
            )
            .expect_err("valid task assessment cannot substitute for the caller's policy guard");
            assert!(error.to_string().contains("matching frozen routing policy"));
            assert!(captured_selected_authorizations().is_empty());
        }
        assert_eq!(current_routing_policy(), Some(frozen));
        Ok(())
    }
}
