//! Supervisor integration for the pure runtime/model/effort selector.
//!
//! The bridge is intentionally the only place where supervisor runtime state
//! is translated into selector input. The selector remains deterministic and
//! cannot inspect the host, clock, catalog, or supervisor plan directly.

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
    ReasoningEffort as SelectorEffort, RiskLevel, RuntimeCatalog, RuntimePoolState, SelectionInput,
    SelectionProvenance, TaskHorizon, TaskProfile, TypedAxisObservation, TypedObservationKind,
};
use std::path::Path;

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
thread_local! {
    static TEST_ADVERTISED_CATALOGS: RefCell<Option<AdvertisedCatalogSet>> = const {
        RefCell::new(None)
    };
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

/// Observe advertised runtime catalogs for supervisor launch.
///
/// Under `cargo test` this stays hermetic: it never resolves or starts a
/// third-party CLI. Production binaries screen a live `cursor-agent models`
/// observation and retain a private evidence gap when that optional catalog
/// cannot be observed.
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
    let (cursor, cursor_evidence_gap) =
        match observe_live_cursor_catalog(repo, observed_at_unix_millis) {
            Ok(observation) => (Some(observation), None),
            Err(error) if cursor_catalog_optional_unavailability(&error) => (
                None,
                Some(CursorCatalogEvidenceGap::from_error(
                    &error,
                    observed_at_unix_millis,
                )),
            ),
            Err(error) => {
                return Err(error).context("live Cursor catalog observation failed closed");
            }
        };
    Ok(AdvertisedCatalogSet {
        cursor,
        grok: None,
        cursor_evidence_gap,
    })
}

#[cfg(not(test))]
fn observe_live_cursor_catalog(
    repo: &Path,
    observed_at_unix_millis: u64,
) -> Result<crate::runtime_adapter::cursor::CursorAdvertisedCatalogObservation> {
    let mut spec = crate::runtime_adapter::cursor::CursorCatalogCommandSpec::new(repo);
    if let Some(program) = std::env::var_os("MACO_CURSOR_BIN") {
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
    advertised: AdvertisedCatalogSet,
    quota_context: Option<LiveQuotaSelectionContext>,
    quota_ledger: Option<RunBudgetLedger>,
}

impl PartialEq for SupervisorAutomaticSelectionState {
    fn eq(&self, other: &Self) -> bool {
        self.decisions == other.decisions
            && self.advertised == other.advertised
            && self.quota_context == other.quota_context
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

pub(super) fn initialize_supervisor_selection_with_quota(
    plan: &mut SupervisorPlan,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    admission: &SupervisorAdmissionPolicyInput,
    advertised: &AdvertisedCatalogSet,
    resolved_objective_profile: Option<&ResolvedObjectiveProfile>,
    quota: SupervisorQuotaSelectionInput<'_>,
) -> Result<SupervisorSelectionResolution> {
    if runtime == SupervisorRuntime::Fake {
        return Ok(SupervisorSelectionResolution {
            mode: SupervisorSelectionMode::LegacyFake,
            decisions: Vec::new(),
            automatic_state: None,
            selection_preflight_failure: None,
        });
    }
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
    let roles = if automatic {
        all_selector_roles().to_vec()
    } else {
        plan.role_models.keys().copied().collect()
    };
    if runtime == SupervisorRuntime::Cursor && advertised.cursor.is_none() {
        let role = roles.first().copied().unwrap_or(AgentRole::Worker);
        let detail = advertised
            .cursor_evidence_gap
            .as_ref()
            .map(|gap| gap.message.as_str())
            .unwrap_or(
                "verified Cursor runtime model catalog observation is missing without recorded failure evidence",
            );
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
                    "selected Cursor runtime requires a verified runtime-advertised model catalog before role '{}': {detail}",
                    role.as_str()
                ),
            }),
        });
    }
    let mut resolved = BTreeMap::new();
    let mut decisions = Vec::with_capacity(roles.len());
    for role in roles {
        let configured = plan.role_models.get(&role);
        let debug_override = configured
            .map(|selection| debug_override_for_role(role, runtime, selection))
            .transpose()?;
        let input = selection_input_for_role(SelectionInputForRoleArgs {
            role,
            runtime,
            catalog,
            advertised,
            admission,
            resolved_objective_profile: &resolved_objective_profile,
            quota_context,
            quota_ledger,
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
            },
            debug_override,
        })?;
        let decision = select_with_live_switch_cost(&input).map_err(|error| {
            anyhow!(
                "automatic selector rejected role '{}': {error}",
                role.as_str()
            )
        })?;
        let primary_cause = if automatic {
            SupervisorSelectionEventCause::Initial
        } else {
            SupervisorSelectionEventCause::DebugOverride
        };
        let event = SupervisorSelectionEvent {
            assignment_id: None,
            attempt: 0,
            role,
            primary_cause,
            provenance: decision,
        };
        let choice = match executable_choice(&event.provenance, runtime, role)? {
            ExecutableChoiceResolution::Executable(choice) => choice,
            ExecutableChoiceResolution::PreflightFailure(failure) => {
                decisions.push(event);
                return Ok(SupervisorSelectionResolution {
                    mode: if automatic {
                        SupervisorSelectionMode::Automatic
                    } else {
                        SupervisorSelectionMode::DebugOverride
                    },
                    decisions,
                    automatic_state: None,
                    selection_preflight_failure: Some(failure),
                });
            }
        };
        if configured.is_some() {
            let requested = &input
                .debug_override
                .as_ref()
                .context("explicit role_models entry lost its selector debug override")?
                .candidate;
            if requested != &choice.candidate {
                bail!(
                    "debug runtime/model/effort override for role '{}' was not applied exactly by the selector: requested '{}:{}:{:?}', selected '{}:{}:{:?}'",
                    role.as_str(),
                    requested.runtime,
                    requested.model,
                    requested.effort,
                    choice.candidate.runtime,
                    choice.candidate.model,
                    choice.candidate.effort,
                );
            }
        }
        resolved.insert(role, role_selection_from_choice(choice));
        decisions.push(event);
    }

    plan.role_models = resolved;
    if automatic {
        if plan.review_lenses == default_supervisor_review_lenses() {
            bind_automatic_review_lenses_to_auditor_selection(plan)?;
        } else {
            validate_custom_review_lenses_against_auditor_selection(plan, runtime)?;
        }
    } else if plan.review_lenses == default_supervisor_review_lenses() {
        if plan.role_models.contains_key(&AgentRole::Auditor) {
            bind_automatic_review_lenses_to_auditor_selection(plan)?;
        }
    } else {
        validate_custom_review_lenses_against_auditor_selection(plan, runtime)?;
    }

    let automatic_state = automatic
        .then(|| {
            SupervisorAutomaticSelectionState::from_initial_decisions(
                &decisions,
                advertised.clone(),
                quota_context.cloned(),
                quota_ledger.cloned(),
            )
        })
        .transpose()?;
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
        for role in all_selector_roles() {
            if !by_role.contains_key(role) {
                bail!(
                    "automatic selector omitted initial provenance for role '{}'",
                    role.as_str()
                );
            }
        }
        Ok(Self {
            decisions: by_role,
            advertised,
            quota_context,
            quota_ledger,
        })
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

pub(super) fn reselect_roles_from_supplied_catalog_snapshot(
    state: &mut SupervisorAutomaticSelectionState,
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    roles: &[AgentRole],
    retry_count: u32,
    budget_signal: BudgetSignal,
    environment_rejections: &[TypedSelectorEnvironmentRejection],
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
        let constructed = constructed_selection_catalogs(
            runtime,
            catalog,
            &advertised,
            &input.task,
            &input.priors,
        )?;
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

        let decision = select_with_live_switch_cost(&input).map_err(|error| {
            anyhow!(
                "automatic selector replay rejected role '{}': {error}",
                role.as_str()
            )
        })?;
        let choice = match executable_choice(&decision, runtime, role)? {
            ExecutableChoiceResolution::Executable(choice) => choice,
            ExecutableChoiceResolution::PreflightFailure(failure) => {
                bail!(
                    "automatic selector replay failed preflight: {}",
                    failure.message
                )
            }
        };
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

fn role_for_task_profile(task: &TaskProfile) -> Result<AgentRole> {
    match task.authority_role {
        AuthorityRole::AcceptanceGate => Ok(AgentRole::Supervisor),
        AuthorityRole::Delegating => Ok(AgentRole::ChildOrchestrator),
        AuthorityRole::TerminalLeaf => Ok(AgentRole::Worker),
        AuthorityRole::FailureClassification => Ok(AgentRole::GateClassifier),
        AuthorityRole::ReviewAuditor => Ok(AgentRole::Auditor),
        authority => {
            bail!("selector task authority '{authority:?}' does not map to a supervisor role")
        }
    }
}

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
            *lens_model = model.clone();
            *reasoning_effort = selection.reasoning_effort.clone();
        }
    }
    Ok(())
}

fn validate_custom_review_lenses_against_auditor_selection(
    plan: &SupervisorPlan,
    runtime: SupervisorRuntime,
) -> Result<()> {
    let auditor = plan.role_models.get(&AgentRole::Auditor).context(
        "custom review lenses require an explicit selector-validated auditor role_models override",
    )?;
    let auditor_model = auditor
        .model
        .as_deref()
        .context("selector-validated auditor override has no explicit model")?;
    let auditor_effort = auditor
        .reasoning_effort
        .as_deref()
        .context("selector-validated auditor override has no explicit reasoning effort")?;
    for lens in &plan.review_lenses {
        match &lens.backend {
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } if model == auditor_model
                && reasoning_effort.as_deref() == Some(auditor_effort) => {}
            ReviewLensBackendConfig::Model {
                model,
                reasoning_effort,
                ..
            } => bail!(
                "custom review lens '{}' runtime/model/effort '{}:{}:{}' does not exactly match selector-validated auditor triple '{}:{}:{}'",
                lens.id,
                runtime_name(runtime),
                model,
                reasoning_effort.as_deref().unwrap_or("<missing>"),
                runtime_name(runtime),
                auditor_model,
                auditor_effort,
            ),
            ReviewLensBackendConfig::Precomputed { .. } => bail!(
                "custom precomputed review lens '{}' cannot be selector-bound safely because it has no executable reasoning-effort field",
                lens.id
            ),
        }
    }
    Ok(())
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

struct SelectionInputForRoleArgs<'a> {
    role: AgentRole,
    runtime: SupervisorRuntime,
    catalog: &'a RuntimeModelCatalog,
    advertised: &'a AdvertisedCatalogSet,
    admission: &'a SupervisorAdmissionPolicyInput,
    resolved_objective_profile: &'a ResolvedObjectiveProfile,
    quota_context: Option<&'a LiveQuotaSelectionContext>,
    quota_ledger: Option<&'a RunBudgetLedger>,
    signals: DynamicSignals,
    debug_override: Option<DebugOverride>,
}

fn live_switch_cost_evidence(input: &SelectionInput) -> Vec<CandidateSwitchCostEvidence> {
    with_live_switch_cost_session(|session| session.evidence_for(input))
}

fn select_with_live_switch_cost(
    input: &SelectionInput,
) -> Result<SelectionProvenance, selection::SelectionError> {
    let evidence = live_switch_cost_evidence(input);
    let provenance = selection::select_with_switch_cost_estimates(input, &evidence)?;
    if let Err(error) = route_live_four_arm_comparison(input) {
        return Err(selection::SelectionError::InvalidInput(format!(
            "live online-router four-arm comparison failed: {error:#}"
        )));
    }
    Ok(provenance)
}

fn selection_input_for_role(args: SelectionInputForRoleArgs<'_>) -> Result<SelectionInput> {
    let SelectionInputForRoleArgs {
        role,
        runtime,
        catalog,
        advertised,
        admission,
        resolved_objective_profile,
        quota_context,
        quota_ledger,
        signals,
        debug_override,
    } = args;
    let priors = selection::built_in_prior_dataset()?;
    let task = task_profile_for_role(role);
    let runtime_name = runtime_name(runtime);
    let catalogs = constructed_selection_catalogs(runtime, catalog, advertised, &task, &priors)?;
    let profile = priors
        .objective_profiles
        .first()
        .context("built-in selector data has no objective profile")?;
    let profile_name = profile.name.clone();
    let profile_version = profile.version;
    let capacity = u64::try_from(admission.provider_inflight_bound)
        .context("provider inflight bound does not fit selector pool units")?;
    let admission_bytes = serde_json::to_vec(admission)
        .context("failed to normalize supervisor admission input for selection")?;
    let primary_pool = RuntimePoolState {
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
    };
    let pools = pools_for_constructed_catalogs(&catalogs, runtime_name, primary_pool);
    let allowed_runtimes = catalogs
        .iter()
        .map(|runtime_catalog| runtime_catalog.runtime.clone())
        .collect();
    let mut input = SelectionInput {
        task,
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
        outcomes: Vec::new(),
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

fn constructed_selection_catalogs(
    runtime: SupervisorRuntime,
    catalog: &RuntimeModelCatalog,
    advertised: &AdvertisedCatalogSet,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> Result<Vec<RuntimeCatalog>> {
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
            ));
        }
    }
    if let Some(observation) = &advertised.grok {
        catalogs.push(runtime_catalog_from_advertised_slugs(
            "grok",
            observation.catalog().slugs(),
            format!("grok-advertised-sha256:{}", observation.source_sha256()),
            observation.observed_at_unix_millis().to_string(),
            task,
            priors,
        )?);
    }
    Ok(catalogs)
}

fn runtime_catalog_from_unavailable_priors(
    runtime_name: &str,
    gap: &CursorCatalogEvidenceGap,
    task: &TaskProfile,
    priors: &selection::PriorDataset,
) -> RuntimeCatalog {
    let mut models = priors
        .models
        .iter()
        .filter(|prior| prior.runtime == runtime_name)
        .filter_map(|prior| catalog_model_from_prior(prior, task, false))
        .collect::<Vec<_>>();
    models.sort_by(|left, right| left.model.cmp(&right.model));
    RuntimeCatalog {
        runtime: runtime_name.to_string(),
        revision: format!(
            "cursor-unavailable-sha256:{}",
            crate::artifacts::state_auth::sha256_hex(gap.message.as_bytes())
        ),
        advertised_at: gap.observed_at_unix_millis.to_string(),
        models,
    }
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
        if let Some(model) = catalog_model_from_prior(prior, task, true) {
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
) -> Option<CatalogModel> {
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
        return None;
    }
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
    Some(CatalogModel {
        model: prior.model.clone(),
        available,
        supported_efforts,
        capabilities: CandidateCapabilities {
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
        },
    })
}

fn runtime_catalog_from_priors(
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
                        evidence.task_class == task.task_class
                            && evidence.role == task.authority_role
                    })
                    .map(|evidence| evidence.effort),
            )
            .chain(prior.strong_gate_fallback_efforts.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        supported_efforts.sort();
        if supported_efforts.is_empty() {
            continue;
        }
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
        models.push(CatalogModel {
            model: prior.model.clone(),
            available,
            supported_efforts,
            capabilities: CandidateCapabilities {
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
            },
        });
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

fn task_profile_for_role(role: AgentRole) -> TaskProfile {
    match role {
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
                message: format!(
                    "selector failed closed for role '{}': {}",
                    role.as_str(),
                    decision.decision_reason
                ),
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
        record.validate().map_err(|error| {
            anyhow!("live invocation record failed attribution validation: {error}")
        })?;
        self.invocations.push(record);
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
    let finished_millis = observation
        .duration_ms
        .and_then(|duration| observation.started_at_unix_millis.checked_add(duration))
        .unwrap_or(observation.started_at_unix_millis.max(1));
    record.finished_at = Some(TimestampMillis::from_millis(
        finished_millis.max(started.as_millis()),
    ));
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
    record.task_class = Some(AUTOMATIC_SELECTION_TASK_CLASS.to_string());
    let backend = backend_id_for_runtime(observation.runtime)?;
    record.backend = Some(backend.clone());
    record.provider = Some(provider_id_for_runtime(observation.runtime)?);
    let model = observation
        .model
        .filter(|model| !model.trim().is_empty())
        .unwrap_or("unresolved-live-model");
    let slug =
        RuntimeSlug::new(model).map_err(|error| anyhow!("live invocation model slug: {error}"))?;
    record.requested_model = Some(slug.clone());
    record.resolved_model = Some(slug);
    record.session_id = Some(observation.run_id.to_string());
    record.worktree_id = Some(observation.worktree_id.to_string());
    if let Some(duration_ms) = observation.duration_ms {
        let micros = i64::try_from(duration_ms.saturating_mul(1_000)).unwrap_or(i64::MAX);
        if micros >= 0 {
            record.runtime_startup_micros = Some(micros);
        }
    }
    let effort = canonical_effort_from_label(observation.effort.unwrap_or("high"));
    record.requested_effort = Some(effort.clone());
    record.resolved_effort = Some(effort);
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
        SelectorEffort::Low => CanonicalEffort::Low,
        SelectorEffort::Medium => CanonicalEffort::Medium,
        SelectorEffort::High => CanonicalEffort::High,
        SelectorEffort::Xhigh => CanonicalEffort::XHigh,
        SelectorEffort::Max => CanonicalEffort::Max,
        SelectorEffort::Ultra => CanonicalEffort::Max,
    }
}

fn canonical_effort_from_label(label: &str) -> CanonicalEffort {
    match label {
        "minimal" => CanonicalEffort::Minimal,
        "low" => CanonicalEffort::Low,
        "medium" => CanonicalEffort::Medium,
        "high" => CanonicalEffort::High,
        "xhigh" => CanonicalEffort::XHigh,
        "max" => CanonicalEffort::Max,
        _ => CanonicalEffort::High,
    }
}

fn optimizer_role(role: AgentRole) -> OptimizerRole {
    match role {
        AgentRole::Supervisor => OptimizerRole::Supervisor,
        AgentRole::ChildOrchestrator => OptimizerRole::ChildOrchestrator,
        AgentRole::Worker => OptimizerRole::Worker,
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

fn runtime_from_name(runtime: &str) -> Result<SupervisorRuntime> {
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
        "minimal" | "low" => Some(SelectorEffort::Low),
        "medium" => Some(SelectorEffort::Medium),
        "high" => Some(SelectorEffort::High),
        "xhigh" => Some(SelectorEffort::Xhigh),
        "max" => Some(SelectorEffort::Max),
        "ultra" => Some(SelectorEffort::Ultra),
        _ => None,
    }
}

fn selector_effort_as_str(effort: SelectorEffort) -> &'static str {
    match effort {
        SelectorEffort::Low => "low",
        SelectorEffort::Medium => "medium",
        SelectorEffort::High => "high",
        SelectorEffort::Xhigh => "xhigh",
        SelectorEffort::Max => "max",
        SelectorEffort::Ultra => "ultra",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_resolved_profile() -> ResolvedObjectiveProfile {
        ResolvedObjectiveProfile {
            profile: crate::objective_profile::default_objective_profile()
                .binding()
                .expect("default objective profile binding"),
            source: crate::objective_profile::ObjectiveProfileSource::BuiltIn,
        }
    }

    fn initialize_supervisor_selection(
        plan: &mut SupervisorPlan,
        runtime: SupervisorRuntime,
        catalog: &RuntimeModelCatalog,
        admission: &SupervisorAdmissionPolicyInput,
        advertised: &AdvertisedCatalogSet,
    ) -> Result<SupervisorSelectionResolution> {
        let resolved = default_resolved_profile();
        super::initialize_supervisor_selection(
            plan,
            runtime,
            catalog,
            admission,
            advertised,
            Some(&resolved),
        )
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
            review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
            assignments: Vec::new(),
        }
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
                prior.runtime == runtime_name(SupervisorRuntime::Codex) && predicate(prior)
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
    fn authenticated_exhausted_quota_projects_into_supervisor_refusal_and_evidence() -> Result<()> {
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
            signals: DynamicSignals {
                retry_count: 0,
                budget_signal: BudgetSignal::Continue,
                previous_choice: None,
                previous_catalog_digest: None,
                environment_rejections: Vec::new(),
            },
            debug_override: None,
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
        let resolution = super::initialize_supervisor_selection(
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
        let adjusted = super::initialize_supervisor_selection(
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
        assert_ne!(adjusted_choice.candidate, default_choice.candidate);
        assert_eq!(
            adjusted_choice.reason,
            selection::ChoiceReason::LowestLegacyBaselinePlusCostProxyAdjustments
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
            selection::RoutingScoreSemantics::LegacyBaselinePlusCostProxyAdjustmentsV1
        );
        assert_eq!(score.routing_tradeoff_weights, frozen.profile.tradeoffs);
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
    fn explicit_debug_override_requires_parseable_effort() -> Result<()> {
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
    fn debug_mode_applies_exact_selector_triple_to_plan() -> Result<()> {
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
        assert_eq!(resolution.decisions.len(), 1);
        assert_eq!(resolution.decisions[0].role, AgentRole::Worker);
        assert_eq!(resolution.decisions[0].attempt, 0);
        assert!(resolution.decisions[0].assignment_id.is_none());
        assert_eq!(
            resolution.decisions[0].primary_cause,
            SupervisorSelectionEventCause::DebugOverride
        );
        assert_eq!(
            resolution.decisions[0]
                .provenance
                .choice
                .as_ref()
                .context("debug choice")?
                .candidate,
            requested
        );
        assert_eq!(
            plan.role_models
                .get(&AgentRole::Worker)
                .and_then(|selection| selection.reasoning_effort.as_deref()),
            Some("high")
        );
        Ok(())
    }

    #[test]
    fn custom_review_lens_must_match_selector_validated_auditor() -> Result<()> {
        let catalog = codex_catalog()?;
        let auditor_prior = codex_prior_for(|prior| {
            prior
                .strong_gate_fallback_efforts
                .contains(&SelectorEffort::Xhigh)
        })?;
        let other_prior = codex_prior_for(|prior| prior.model != auditor_prior.model)?;
        let mut plan = test_plan();
        plan.role_models.insert(
            AgentRole::Auditor,
            role_selection(auditor_prior.model, Some("xhigh")),
        );
        plan.review_lenses = vec![ReviewLensConfig {
            id: "custom-auditor".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "openai".to_string(),
                model: other_prior.model,
                reasoning_effort: Some("high".to_string()),
            },
            information_scope: ReviewInformationScope::FullChildTranscript,
        }];

        let error = initialize_supervisor_selection(
            &mut plan,
            SupervisorRuntime::Codex,
            &catalog,
            &test_admission(),
            &AdvertisedCatalogSet::empty(),
        )
        .expect_err("mismatched custom review lens must fail closed");
        assert!(error
            .to_string()
            .contains("does not exactly match selector-validated auditor triple"));
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

    #[test]
    fn degrade_transition_retains_previous_choice_and_switch_score_evidence() -> Result<()> {
        let (_, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("immediately prior worker choice")?
            .candidate
            .clone();
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
        assert_eq!(choice.candidate.runtime, previous.runtime);
        assert_ne!(choice.candidate.model, previous.model);
        assert_eq!(
            choice.switch_transition,
            selection::ContextSwitchTransition::ModelChangeSameRuntime
        );
        assert_eq!(
            choice.configured_switch_cost_microunits,
            crate::objective_profile::DEFAULT_MODEL_CHANGE_SWITCH_COST_MICROUNITS
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
        let (_, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("initial worker choice")?
            .candidate
            .clone();
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
            selection::ContextSwitchTransition::ModelChangeSameRuntime
        );
        assert_eq!(
            replacement.configured_switch_cost_microunits,
            crate::objective_profile::DEFAULT_MODEL_CHANGE_SWITCH_COST_MICROUNITS
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
    fn typed_environment_rejection_uses_one_shot_data_declared_fallback() -> Result<()> {
        let (catalog, mut state) = automatic_state()?;
        let previous = state
            .decisions
            .get(&AgentRole::Worker)
            .and_then(|decision| decision.choice.as_ref())
            .context("initial worker choice")?
            .candidate
            .clone();
        let prior = codex_prior_for(|prior| prior.model == previous.model)?;
        let fallback = prior
            .one_shot_environment_fallbacks
            .first()
            .context("initial worker has no data-declared environment fallback")?;
        let rejection = TypedSelectorEnvironmentRejection {
            role: AgentRole::Worker,
            rejection: selection::EnvironmentRejectionState {
                candidate: previous.clone(),
                rejection_code: fallback.rejection_code.clone(),
                evidence_id: "typed-runtime-rejection-1".to_string(),
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
        let transition = decision
            .environment_fallback
            .as_ref()
            .context("typed one-shot fallback transition")?;

        assert!(decision
            .triggers
            .contains(&selection::SelectionTrigger::EnvironmentFallback));
        assert_eq!(
            decision.normalized_input.signals.previous_choice.as_ref(),
            Some(&previous)
        );
        assert_eq!(transition.source, previous);
        assert_eq!(transition.target.runtime, fallback.target_runtime);
        assert_eq!(transition.target.model, fallback.target_model);
        assert_eq!(transition.target.effort, fallback.target_effort);
        assert_eq!(transition.transition_ordinal, 1);
        assert_eq!(transition.maximum_transitions, 1);
        let choice = decision
            .choice
            .as_ref()
            .context("environment fallback selected choice")?;
        assert_eq!(
            choice.switch_transition,
            selection::ContextSwitchTransition::ModelChangeSameRuntime
        );
        assert_eq!(
            choice.configured_switch_cost_microunits,
            crate::objective_profile::DEFAULT_MODEL_CHANGE_SWITCH_COST_MICROUNITS
        );
        assert!(choice.switch_cost_microunits > 0);
        let target_score = decision
            .candidate_set
            .iter()
            .find(|candidate| candidate.candidate == transition.target)
            .and_then(|candidate| candidate.score.as_ref())
            .context("environment fallback target score")?;
        assert_eq!(target_score.switch_transition, choice.switch_transition);
        assert_eq!(
            target_score.configured_switch_cost_microunits,
            choice.configured_switch_cost_microunits
        );
        assert_eq!(
            target_score.switch_cost_microunits,
            choice.switch_cost_microunits
        );
        let fallback_choice = choice.candidate.clone();
        let after_fallback = reselect_roles_from_supplied_catalog_snapshot(
            &mut state,
            SupervisorRuntime::Codex,
            &catalog,
            &[AgentRole::Worker],
            1,
            BudgetSignal::Continue,
            &[],
        )?;
        assert_eq!(
            after_fallback.decisions[0]
                .1
                .normalized_input
                .signals
                .previous_choice
                .as_ref(),
            Some(&fallback_choice)
        );
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
            }
        }
    }

    impl crate::runtime_adapter::grok::GrokCatalogCommandRunner for FakeGrokRunner {
        fn run(
            &self,
            _spec: &crate::runtime_adapter::grok::GrokCatalogCommandSpec,
        ) -> Result<crate::runtime_adapter::grok::GrokCatalogCommandOutput> {
            Ok(self.output.clone())
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
        }
    }

    #[test]
    fn captured_cursor_catalog_makes_composer_slugs_selectable_without_operator_lists() -> Result<()>
    {
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
        assert_eq!(
            choice.reason,
            selection::ChoiceReason::LowestExpectedTotalCostPerAcceptedTask
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
    fn injected_grok_catalog_joins_without_hardcoded_slug_lists() -> Result<()> {
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
    fn observed_grok_catalog_stays_fail_closed_for_judgment_roles() -> Result<()> {
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
        let resolution = super::initialize_supervisor_selection(
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
        let resolution = super::initialize_supervisor_selection(
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
}
