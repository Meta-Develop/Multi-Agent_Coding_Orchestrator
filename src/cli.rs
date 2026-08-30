use crate::{
    agent::{
        self, AgentRunOptions, AgentRunReport, AgentValidationCommand, AgentWorktreeReusePolicy,
        ProviderCommandPolicy,
    },
    agent_lifecycle::{AgentListFilter, AgentProcessRecord, AgentRegistry, AgentStopReport},
    artifacts::{
        self, ArtifactRetentionFamily, ArtifactRetentionPolicy, ResolvedRunId, RunArtifactFamily,
    },
    autopilot,
    consult::{self, ConsultAskOptions, ConsultantRuntime, DEFAULT_CONSULT_TIMEOUT_SECONDS},
    hierarchy_ledger::{is_coordinator_role_label, observe_hierarchy, ObservedHierarchyNode},
    inbox::{
        self, InboxMachineGlobalInput, InboxPermissionMode, InboxRunOptions, InboxScanOptions,
        InboxWatchOptions, InboxWorkspaceRunOptions, InboxWorkspaceScanOptions,
        InboxWorkspaceWatchOptions,
    },
    live_claim::{self, LiveClock},
    llm::{FakeProvider, PromptContext, ProviderCapabilities, Redactor, RepoExcerpt, WorkProposal},
    machine_global::{
        machine_global_config_content_binding, DestructiveTargetInput, GateOutcome,
        MachineGlobalClaimSummary, MachineGlobalClaimToken, MachineGlobalConfig,
        MachineGlobalRetentionBinding, MachineGlobalStore, RetentionOperationId,
        RetentionOperationToken,
    },
    megafile::{
        MegafileAssessment, MegafileReport, MegafileStore, MegafileThresholdCalibration,
        MegafileThresholds,
    },
    merge::{
        self, ArbitrationSideSpec, CandidateValidationCommand, MegafileMergePolicy,
        MergeApplyOptions, MergeApplyPreview, MergeApplyReport, MergeArbitrationOptions,
        MergeArbitrationReport, MergeCandidate, MergeCollectOptions, MergeForceOptions,
        MergePreviewOptions, ValidationEvidenceBundle, ValidationReport,
    },
    orchestration_event::{
        append_external_orchestration_event, normalize_orchestration_node_id,
        ExternalOrchestrationPayload, OrchestrationEventKind, OrchestrationRole,
    },
    orchestrator::{
        self, AgentRunStatus, OrchestrationResumeOptions, OrchestrationRunControls,
        OrchestrationRunOptions, OrchestrationSummary, RunId, SemanticCoordinationMode,
        WorktreeReusePolicy,
    },
    protected_path::DeclaredPathCoordinate,
    publication::{
        self, ForgeKind, IssuePublicationOptions, PrPublicationOptions, PrPublicationReport,
        PrPublicationStatus,
    },
    repo_map::{self, RepoEntryKind, RepoMap},
    repo_semantic::{self, SemanticRepoMap},
    review::{self, ReviewPrOptions, ReviewerConfig, ReviewerMode},
    safe_state::BoundedRegularReader,
    scope::{self, ScopeServeOptions},
    semantic_coord::{
        SemanticCoordinationReport, SemanticIntentRequest, SemanticIntentStore, SemanticIntentToken,
    },
    state_migration,
    supervise::{self, SupervisorRunOptions},
    sync::{normalize_repo_relative_path, ClaimToken},
    sync_store::{
        ClaimLivenessReport, ClaimStatusReport, ClaimTelemetryOutcome, ClaimTiming,
        MegafileClaimWarning, OwnerReport, SyncStore,
    },
    worktree::{
        install_primary_worktree_guard, sweep_workspace_worktrees,
        uninstall_primary_worktree_guard, verify_primary_worktree_guard, worktree_report_path_text,
        RepositoryInfo, WorktreeCreateOptions, WorktreeGcOptions, WorktreeGcReason,
        WorktreeGcReport, WorktreeGcStatus, WorktreeLifecycleOptions, WorktreeLifecycleReport,
        WorktreeManager, WorktreeRecord, WorktreeRetentionPolicy, WorktreeSweepDiscoveryStatus,
        WorktreeSweepFailureKind, WorktreeSweepOptions, WorktreeSweepReport,
        WorktreeSweepRepositoryStatus, WorktreeSweepRootKind, WorktreeTargetLivenessCause,
        WorktreeTargetLivenessEvidence, WorktreeTargetLivenessSource,
    },
};
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_CONSULT_QUESTION_FILE_BYTES: u64 = 64 * 1024;
const MAX_ISSUE_BODY_FILE_BYTES: u64 = 512 * 1024;
const MAX_ORCHESTRATION_SUMMARY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ORCHESTRATION_SUMMARY_AGENTS: usize = 256;
const MAX_ORCHESTRATION_AGENT_ID_BYTES: usize = 256;
const MAX_ORCHESTRATION_SUMMARY_PATHS: usize = 16 * 1024;
const MAX_VALIDATION_INPUT_FILES: usize = 1024;
const MAX_VALIDATION_INPUT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_VALIDATION_INPUT_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_VALIDATION_REPORTS: usize = 1024;
const MAX_VALIDATION_REPORT_NAME_BYTES: usize = 1024;
const MAX_VALIDATION_REPORT_MESSAGE_BYTES: usize = 64 * 1024;
const MAX_VALIDATION_REPORT_PATHS: usize = 8192;
const MAX_AGENT_TASK_BYTES: u64 = 32 * 1024;
const MAX_FAKE_PROPOSAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FAKE_PROPOSAL_ITEMS: usize = 256;
const MAX_PROMPT_TASK_BYTES: u64 = 32 * 1024;
const MAX_PROMPT_EXCERPT_BYTES: u64 = 32 * 1024;
const MAX_PROMPT_EXCERPT_TOTAL_BYTES: usize = 48 * 1024;
const MAX_PROMPT_PATHS: usize = 64;
const MAX_SUPERVISE_GOAL_FILE_BYTES: u64 = 256 * 1024;
const MAX_DEFAULT_MACHINE_GLOBAL_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_EVALUATION_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EVALUATION_PLAN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXTERNAL_EVENT_PAYLOAD_CLI_BYTES: usize = 4 * 1024;
const RETIRED_AUTOPILOT_EXECUTION_MESSAGE: &str =
    "autopilot plan/run is retired; use literal instruction routing: maco <instruction>";

#[derive(Debug, Parser)]
#[command(name = "maco")]
#[command(about = "Multi-Agent Coding Orchestrator")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Routes a bare instruction into the existing supervised goal/spec entrypoint.
///
/// Explicit subcommand names and option-shaped first arguments retain Clap's
/// normal behavior. `--` can be used as the first argument to force an
/// instruction whose first word is an explicit subcommand name or looks like
/// an option. Every routed argument is joined with one ASCII space and passed
/// as one literal goal/spec, so option-shaped words after the first instruction
/// word remain instruction text rather than becoming MACO options.
pub fn route_literal_instruction_args<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let Some(first) = args.get(1) else {
        return args;
    };

    let instruction_start = if first == OsStr::new("--") {
        if args.len() == 2 {
            return args;
        }
        2
    } else {
        if is_option_shaped(first) || is_explicit_cli_subcommand(first) {
            return args;
        }
        1
    };

    let mut instruction = OsString::new();
    for (index, argument) in args[instruction_start..].iter().enumerate() {
        if index != 0 {
            instruction.push(" ");
        }
        instruction.push(argument);
    }

    vec![
        args[0].clone(),
        OsString::from("supervise"),
        OsString::from("run"),
        OsString::from("--literal-goal"),
        instruction,
    ]
}

fn is_option_shaped(argument: &OsStr) -> bool {
    argument.as_encoded_bytes().starts_with(b"-")
}

fn is_explicit_cli_subcommand(argument: &OsStr) -> bool {
    let Some(argument) = argument.to_str() else {
        return false;
    };
    argument == "help"
        || Cli::command().get_subcommands().any(|subcommand| {
            subcommand.get_name() == argument
                || subcommand.get_all_aliases().any(|alias| alias == argument)
        })
}

fn resolve_supervise_machine_global_binding(
    routed_literal: bool,
    config: Option<PathBuf>,
    runtime_root_id: Option<String>,
) -> Result<(PathBuf, String)> {
    match (config, runtime_root_id) {
        (Some(config), Some(runtime_root_id)) => Ok((config, runtime_root_id)),
        (None, None) if routed_literal => resolve_literal_machine_global_defaults().context(
            "failed to resolve default machine-global binding for routed literal instruction",
        ),
        (None, None) => bail!(
            "explicit supervise run requires --machine-global-config and \
             --machine-global-runtime-root-id"
        ),
        _ => bail!(
            "--machine-global-config and --machine-global-runtime-root-id must be supplied together"
        ),
    }
}

fn physical_xdg_machine_global_config_path() -> Result<PathBuf> {
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                bail!("XDG_CONFIG_HOME must be an absolute physical path");
            }
            path
        }
        _ => {
            let home = std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .context("HOME must be set when XDG_CONFIG_HOME is absent")?;
            let home = PathBuf::from(home);
            if !home.is_absolute() {
                bail!("HOME must be an absolute physical path");
            }
            home.join(".config")
        }
    };
    Ok(config_home.join("maco").join("machine-global.json"))
}

#[cfg(target_os = "linux")]
fn resolve_literal_machine_global_defaults() -> Result<(PathBuf, String)> {
    let config_path = physical_xdg_machine_global_config_path()?;
    let binding_before = machine_global_config_content_binding(&config_path)
        .context("default machine-global config is not a safe physical file")?;
    let bytes = BoundedRegularReader::read_tree_no_follow(
        &config_path,
        MAX_DEFAULT_MACHINE_GLOBAL_CONFIG_BYTES,
    )
    .context("failed to read the default machine-global config without following links")?;
    let store = MachineGlobalStore::open_config(&config_path)
        .context("failed to authenticate the default machine-global config")?;
    let binding_after = machine_global_config_content_binding(&config_path)
        .context("default machine-global config changed after authentication")?;
    if binding_before != binding_after
        || binding_before.0 != crate::artifacts::state_auth::sha256_hex(&bytes)
    {
        bail!("default machine-global config changed while resolving runtime defaults");
    }
    let config: MachineGlobalConfig = serde_json::from_slice(&bytes)
        .context("authenticated default machine-global config is invalid JSON")?;
    let runtime_root = crate::process_runner::trusted_linux_runtime_root()
        .context("current user's runtime staging root is unavailable or unsafe")?;
    let candidates: Vec<_> = config
        .roots
        .iter()
        .filter(|root| runtime_root.starts_with(&root.path))
        .collect();
    let [selected] = candidates.as_slice() else {
        bail!(
            "default machine-global config must declare exactly one reviewed root containing the current user's runtime staging path"
        );
    };
    store
        .revalidate_root(&selected.id)
        .context("selected default machine-global runtime root is no longer safe")?;
    let binding_final = machine_global_config_content_binding(&config_path)
        .context("default machine-global config changed after runtime-root selection")?;
    if binding_after != binding_final {
        bail!("default machine-global config changed while selecting the runtime root");
    }
    Ok((config_path, selected.id.clone()))
}

#[cfg(not(target_os = "linux"))]
fn resolve_literal_machine_global_defaults() -> Result<(PathBuf, String)> {
    bail!("routed literal machine-global defaults require the strict Linux runtime")
}

impl Cli {
    pub fn run(self) -> Result<()> {
        crate::git_repository::configure_libgit2_repository_extensions()
            .context("failed to configure supported Git repository extensions")?;

        match self.command {
            Command::Init(args) => {
                let info = WorktreeManager::init_repository(args.repo, &args.initial_branch)?;
                print_repository_info(&info, args.json)
            }
            Command::Repo(command) => command.run(),
            Command::State(command) => command.run(),
            Command::Worktree(command) => command.run(),
            Command::Merge(command) => command.run(),
            Command::Live(command) => command.run(),
            Command::Pr(command) => command.run(),
            Command::Issue(command) => command.run(),
            Command::Sync(command) => command.run(),
            Command::MachineGlobal(command) => command.run(),
            Command::Coord(command) => command.run(),
            Command::Orchestrate(command) => command.run(),
            Command::Supervise(command) => command.run(),
            Command::Consult(command) => command.run(),
            Command::Inbox(command) => command.run(),
            Command::Scope(command) => command.run(),
            Command::Autopilot(command) => command.run(),
            Command::Artifacts(command) => command.run(),
            Command::Review(command) => command.run(),
            Command::Agent(command) => command.run(),
            Command::Agents(command) => command.run(),
            Command::Llm(command) => command.run(),
            Command::Evaluation(command) => command.run(),
            Command::EvalHarness(command) => command.run(),
            Command::Optimizer(command) => command.run(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a Git repository for orchestrated agent work.
    Init(InitArgs),
    /// Inspect repository structure.
    Repo(RepoCommand),
    /// Inspect or explicitly migrate repository-local durable state.
    State(StateCommand),
    /// Manage linked Git worktrees for sub-agents.
    Worktree(WorktreeCommand),
    /// Collect and apply merge candidates from agent worktrees.
    Merge(MergeCommand),
    /// Inspect and update human-readable live claim files.
    Live(LiveCommand),
    /// Preview and publish agent pull requests through an explicit forge.
    Pr(PrCommand),
    /// Preview and create issues through an explicit forge.
    Issue(IssueCommand),
    /// Manage repository-local sync path claims.
    Sync(SyncCommand),
    /// Manage claims and recoverable retention under explicitly declared machine-global roots.
    MachineGlobal(MachineGlobalCommand),
    /// Manage repository-local semantic coordination intents.
    Coord(CoordCommand),
    /// Run local orchestration plans.
    Orchestrate(OrchestrateCommand),
    /// Run opt-in supervisor-of-orchestrators plans for supported runtimes.
    Supervise(SuperviseCommand),
    /// Ask a read-only cross-runtime consultant for advice.
    Consult(ConsultCommand),
    /// Scan and react to safe GitHub issue and pull request inbox items.
    Inbox(InboxCommand),
    /// Serve read-only real-time orchestration observability APIs.
    Scope(ScopeCommand),
    /// Inspect artifacts from retired autopilot runs.
    Autopilot(AutopilotCommand),
    /// Apply retention to one repository-local bulk artifact family.
    Artifacts(RepositoryArtifactsCommand),
    /// Run independent review adapters.
    Review(ReviewCommand),
    /// Run a provider-backed agent in an isolated worktree.
    Agent(AgentCommand),
    /// Inspect and stop live MACO-launched agent processes.
    Agents(AgentsCommand),
    /// Inspect local LLM adapter boundaries without network calls.
    Llm(LlmCommand),
    /// Generate deterministic model-mix fixture results from a versioned manifest.
    Evaluation(EvaluationCommand),
    /// Run a local fake-provider-backed model-mix harness and record mix plus outcomes.
    EvalHarness(EvalHarnessCommand),
    /// Inspect the optimizer policy library, replay snapshots, and preference profiles.
    Optimizer(OptimizerCommand),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Repository path to initialize.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Initial branch name for a new repository.
    #[arg(long, default_value = "main")]
    initial_branch: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StateCommand {
    #[command(subcommand)]
    command: StateSubcommand,
}

impl StateCommand {
    fn run(self) -> Result<()> {
        match self.command {
            StateSubcommand::Migrate(args) => {
                let use_default_options = !args.acknowledge_unauthenticated_claims_v1
                    && args.expected_claims_v1_sha256.is_none();
                let options = state_migration::StateMigrationOptions {
                    acknowledge_unauthenticated_claims_v1: args
                        .acknowledge_unauthenticated_claims_v1,
                    expected_claims_v1_sha256: args.expected_claims_v1_sha256,
                };
                let report = if use_default_options {
                    state_migration::migrate_repository_state(args.repo, args.apply)?
                } else {
                    state_migration::migrate_repository_state_with_options(
                        args.repo, args.apply, &options,
                    )?
                };
                print_query_report(&report, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum StateSubcommand {
    /// Validate legacy state, or apply its offline authenticated migration.
    Migrate(MigrateStateArgs),
}

#[derive(Debug, Args)]
struct MigrateStateArgs {
    /// Repository path. Dry-run is the default and never changes state.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Apply the validated migration; requires every known state lock to be idle.
    #[arg(long)]
    apply: bool,
    /// Attest that checksum-less claims-v1 provenance and exact bytes were independently verified.
    #[arg(long)]
    acknowledge_unauthenticated_claims_v1: bool,
    /// Independently computed lowercase SHA-256 of the exact checksum-less claims-v1 bytes.
    #[arg(long, value_name = "SHA256")]
    expected_claims_v1_sha256: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RepoCommand {
    #[command(subcommand)]
    command: RepoSubcommand,
}

impl RepoCommand {
    fn run(self) -> Result<()> {
        match self.command {
            RepoSubcommand::Map(args) => {
                if args.semantic {
                    let map = repo_semantic::scan_repository(args.repo)?;
                    print_semantic_repo_map(&map, args.json)
                } else {
                    let map = repo_map::scan_repository(args.repo)?;
                    print_repo_map(&map, args.json)
                }
            }
            RepoSubcommand::Query(command) => command.run(),
            RepoSubcommand::Megafile(command) => command.run(),
        }
    }
}

#[derive(Debug, Args)]
struct RepoMegafileCommand {
    #[command(subcommand)]
    command: RepoMegafileSubcommand,
}

impl RepoMegafileCommand {
    fn run(self) -> Result<()> {
        match self.command {
            RepoMegafileSubcommand::Seed(args) => {
                let samples = repo_map::scan_repository_file_samples(&args.repo)?;
                let seeded_samples = samples.len();
                let sampled_bytes = samples
                    .iter()
                    .try_fold(0_u64, |total, sample| total.checked_add(sample.bytes))
                    .context("sampled repository byte count overflowed")?;
                let store = args.thresholds.open_store(&args.repo)?;
                let assessments = store.record_file_samples(samples)?;
                let telemetry = store.report()?;
                let report = MegafileSeedReport {
                    seeded_samples,
                    sampled_bytes,
                    assessments,
                    telemetry,
                };
                print_query_report(&report, args.json)
            }
            RepoMegafileSubcommand::Query(args) => {
                let store = args.thresholds.open_existing_store(&args.repo)?;
                let initialized = store.is_some();
                if let Some(path) = args.path {
                    let assessment = store
                        .as_ref()
                        .map(|store| store.assess_path(&path))
                        .transpose()?
                        .flatten();
                    let report = MegafilePathQueryReport {
                        initialized,
                        path,
                        assessment,
                    };
                    print_query_report(&report, args.json)
                } else {
                    let telemetry = store.as_ref().map(MegafileStore::report).transpose()?;
                    let report = MegafileQueryReport {
                        initialized,
                        telemetry,
                    };
                    print_query_report(&report, args.json)
                }
            }
        }
    }
}

#[derive(Debug, Args)]
struct RepoQueryCommand {
    #[command(subcommand)]
    command: RepoQuerySubcommand,
}

impl RepoQueryCommand {
    fn run(self) -> Result<()> {
        match self.command {
            RepoQuerySubcommand::Symbol(args) => {
                let map = repo_semantic::scan_repository(args.repo)?;
                let report = SemanticSymbolQueryReport::from_map(&map, &args.name);
                print_query_report(&report, args.json)
            }
            RepoQuerySubcommand::Path(args) => {
                let map = repo_semantic::scan_repository(args.repo)?;
                let report = SemanticPathQueryReport::from_map(&map, &args.path);
                print_query_report(&report, args.json)
            }
            RepoQuerySubcommand::Risk(args) => {
                let map = repo_semantic::scan_repository(&args.repo)?;
                let semantic = repo_semantic::risk_report_for_paths(&map, args.paths);
                let store = args
                    .megafile_thresholds
                    .open_existing_store(&args.repo)
                    .context(
                        "authenticated megafile telemetry could not be opened for risk query",
                    )?;
                let megafile_hotspots = match store {
                    Some(store) => store
                        .report()
                        .context(
                            "authenticated megafile telemetry could not be read for risk query",
                        )?
                        .assessments
                        .into_iter()
                        .filter(|assessment| {
                            assessment.is_megafile
                                && semantic
                                    .changed_paths
                                    .binary_search(&assessment.path)
                                    .is_ok()
                        })
                        .collect(),
                    None => Vec::new(),
                };
                let report = SemanticRiskQueryReport {
                    semantic,
                    megafile_hotspots,
                };
                print_query_report(&report, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum RepoSubcommand {
    /// Print a read-only repository map.
    Map(MapRepoArgs),
    /// Query the semantic repository map.
    Query(RepoQueryCommand),
    /// Explicitly seed and query durable megafile telemetry.
    Megafile(RepoMegafileCommand),
}

#[derive(Debug, Subcommand)]
enum RepoMegafileSubcommand {
    /// Explicitly sample regular repository files and persist their byte/line telemetry.
    Seed(SeedMegafileArgs),
    /// Query the complete telemetry report or one repository-relative path.
    Query(QueryMegafileArgs),
}

#[derive(Debug, Args)]
struct SeedMegafileArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[command(flatten)]
    thresholds: MegafileThresholdArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct QueryMegafileArgs {
    /// Optional repository-relative path. Omit it for the complete bounded report.
    path: Option<PathBuf>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[command(flatten)]
    thresholds: MegafileThresholdArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args, Default)]
struct MegafileThresholdArgs {
    /// Configure the file-size warning threshold in bytes.
    #[arg(long)]
    file_bytes: Option<u64>,
    /// Configure the physical-line warning threshold.
    #[arg(long)]
    file_lines: Option<u64>,
    /// Configure the cross-sample byte-growth warning threshold.
    #[arg(long)]
    growth_bytes: Option<u64>,
    /// Configure the cross-sample line-growth warning threshold.
    #[arg(long)]
    growth_lines: Option<u64>,
    /// Configure the retained-window claim-frequency warning threshold.
    #[arg(long)]
    claim_count: Option<u64>,
    /// Configure the retained-window collision-frequency warning threshold.
    #[arg(long)]
    collision_count: Option<u64>,
    /// Configure how many retained records contribute to activity frequencies.
    #[arg(long)]
    activity_window_records: Option<usize>,
}

impl MegafileThresholdArgs {
    fn open_store(&self, repo: &Path) -> Result<MegafileStore> {
        let Some(thresholds) = self.configured_thresholds() else {
            return MegafileStore::open(repo);
        };
        MegafileStore::open_with_thresholds(repo, thresholds)
    }

    fn open_existing_store(&self, repo: &Path) -> Result<Option<MegafileStore>> {
        let Some(thresholds) = self.configured_thresholds() else {
            return MegafileStore::open_existing(repo);
        };
        MegafileStore::open_existing_with_thresholds(repo, thresholds)
    }

    fn configured_thresholds(&self) -> Option<MegafileThresholds> {
        if self.file_bytes.is_none()
            && self.file_lines.is_none()
            && self.growth_bytes.is_none()
            && self.growth_lines.is_none()
            && self.claim_count.is_none()
            && self.collision_count.is_none()
            && self.activity_window_records.is_none()
        {
            return None;
        }
        let mut thresholds = MegafileThresholds::provisional_bootstrap();
        thresholds.calibration = MegafileThresholdCalibration::Configured;
        if let Some(value) = self.file_bytes {
            thresholds.file_bytes = value;
        }
        if let Some(value) = self.file_lines {
            thresholds.file_lines = value;
        }
        if let Some(value) = self.growth_bytes {
            thresholds.growth_bytes = value;
        }
        if let Some(value) = self.growth_lines {
            thresholds.growth_lines = value;
        }
        if let Some(value) = self.claim_count {
            thresholds.claim_count = value;
        }
        if let Some(value) = self.collision_count {
            thresholds.collision_count = value;
        }
        if let Some(value) = self.activity_window_records {
            thresholds.activity_window_records = value;
        }
        Some(thresholds)
    }
}

#[derive(Debug, Serialize)]
struct MegafileSeedReport {
    seeded_samples: usize,
    sampled_bytes: u64,
    assessments: Vec<MegafileAssessment>,
    telemetry: MegafileReport,
}

#[derive(Debug, Serialize)]
struct MegafileQueryReport {
    initialized: bool,
    telemetry: Option<MegafileReport>,
}

#[derive(Debug, Serialize)]
struct MegafilePathQueryReport {
    initialized: bool,
    path: PathBuf,
    assessment: Option<MegafileAssessment>,
}

#[derive(Debug, Args)]
struct MapRepoArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Build a Rust semantic map instead of the coarse file map.
    #[arg(long)]
    semantic: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum RepoQuerySubcommand {
    /// Find semantic symbols by short or qualified name.
    Symbol(QuerySymbolArgs),
    /// Find semantic map entries connected to a repository path.
    Path(QueryPathArgs),
    /// Report touched symbols and dependency impact for changed paths.
    Risk(QueryRiskArgs),
}

#[derive(Debug, Args)]
struct QuerySymbolArgs {
    /// Symbol short name or qualified path, for example `run` or `crate::api::run`.
    name: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct QueryPathArgs {
    /// Repository-relative path to inspect.
    path: PathBuf,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct QueryRiskArgs {
    /// Changed repository-relative path. Repeat to report multiple changed paths.
    #[arg(long = "path", required = true)]
    paths: Vec<PathBuf>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    #[command(flatten)]
    megafile_thresholds: MegafileThresholdArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OrchestrateCommand {
    #[command(subcommand)]
    command: OrchestrateSubcommand,
}

impl OrchestrateCommand {
    fn run(self) -> Result<()> {
        match self.command {
            OrchestrateSubcommand::Run(args) => {
                let json = args.json;
                let reap_repo = args.repo.clone();
                let outcome = (|| {
                    let summary = orchestrator::run_plan_file_with_controls(
                        OrchestrationRunOptions {
                            repo: args.repo,
                            plan_file: args.plan_file,
                            keep_claims: args.keep_claims,
                            jobs: args.jobs,
                            patch_dir: args.patch_dir,
                        },
                        OrchestrationRunControls {
                            run_id: args.run_id.map(RunId::new).transpose()?,
                            checkpoint_dir: args.checkpoint_dir,
                            worktree_reuse_policy: args.reuse,
                            semantic_coordination: args.semantic_coordination,
                        },
                    )?;
                    print_orchestration_summary(&summary, json)?;
                    if !summary.success {
                        if let Some(agent_id) = summary.first_failed_agent() {
                            bail!("orchestration failed for agent '{agent_id}'");
                        }
                        bail!("orchestration failed");
                    }
                    Ok(())
                })();
                finish_with_merged_worktree_reap(&reap_repo, json, outcome)
            }
            OrchestrateSubcommand::Resume(args) => {
                let json = args.json;
                let reap_repo = args.repo.clone().unwrap_or_else(|| PathBuf::from("."));
                let outcome = (|| {
                    let summary = orchestrator::resume_plan_file(OrchestrationResumeOptions {
                        checkpoint_file: args.checkpoint_file,
                        repo: args.repo,
                        plan_file: args.plan_file,
                        jobs: args.jobs,
                        patch_dir: args.patch_dir,
                    })?;
                    print_orchestration_summary(&summary, json)?;
                    if !summary.success {
                        if let Some(agent_id) = summary.first_failed_agent() {
                            bail!("orchestration failed for agent '{agent_id}'");
                        }
                        bail!("orchestration failed");
                    }
                    Ok(())
                })();
                finish_with_merged_worktree_reap(&reap_repo, json, outcome)
            }
            OrchestrateSubcommand::Collect(args) => {
                let report = collect_orchestration_results(
                    &args.repo,
                    &args.summary_json,
                    merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                )?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("Orchestration collection: {}", args.summary_json.display());
                    for candidate in &report.candidates {
                        println!(
                            "{}\tchanged={}\tunclaimed={}",
                            candidate.metadata.agent_id,
                            candidate.changed_paths.len(),
                            candidate.unclaimed_changed_paths.len()
                        );
                    }
                }
                Ok(())
            }
            OrchestrateSubcommand::Validate(args) => {
                let plan = orchestrator::load_plan(&args.plan_file)?;
                let report = PlanValidationReport {
                    plan_file: args.plan_file,
                    agent_count: plan.agents.len(),
                    path_claim_count: plan.agents.iter().map(|agent| agent.paths.len()).sum(),
                    dependency_count: plan.agents.iter().map(|agent| agent.depends_on.len()).sum(),
                };
                print_plan_validation_report(&report, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum OrchestrateSubcommand {
    /// Run a local JSON orchestration plan.
    Run(RunOrchestrateArgs),
    /// Resume a local orchestration checkpoint.
    Resume(ResumeOrchestrateArgs),
    /// Collect merge candidates from a previous orchestration summary JSON.
    Collect(CollectOrchestrateArgs),
    /// Validate a local JSON orchestration plan without running commands.
    Validate(ValidateOrchestrateArgs),
}

#[derive(Debug, Args)]
struct RunOrchestrateArgs {
    /// JSON plan file to run.
    plan_file: PathBuf,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Keep acquired path claims after the run.
    #[arg(long)]
    keep_claims: bool,
    /// Maximum number of agents to run concurrently when dependencies allow it.
    #[arg(long, default_value_t = 1)]
    jobs: usize,
    /// Write per-agent git patches for changed worktrees.
    #[arg(long)]
    patch_dir: Option<PathBuf>,
    /// Worktree reuse policy for this run.
    #[arg(long, value_parser = parse_worktree_reuse_policy)]
    reuse: Option<WorktreeReusePolicy>,
    /// Stable run id used in summaries and checkpoints.
    #[arg(long)]
    run_id: Option<String>,
    /// Directory where run checkpoints should be written.
    #[arg(long)]
    checkpoint_dir: Option<PathBuf>,
    /// Semantic coordination mode for this run.
    #[arg(long, default_value = "off", value_parser = parse_semantic_coordination_mode)]
    semantic_coordination: SemanticCoordinationMode,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ResumeOrchestrateArgs {
    /// Checkpoint JSON file written by `maco orchestrate run --checkpoint-dir`.
    checkpoint_file: PathBuf,
    /// Repository path. Defaults to the repository recorded in the checkpoint.
    #[arg(long)]
    repo: Option<PathBuf>,
    /// Plan file. Defaults to the plan recorded in the checkpoint.
    #[arg(long)]
    plan_file: Option<PathBuf>,
    /// Maximum number of pending agents to run concurrently when dependencies allow it.
    #[arg(long, default_value_t = 1)]
    jobs: usize,
    /// Write per-agent git patches for pending agents that change worktrees.
    #[arg(long)]
    patch_dir: Option<PathBuf>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CollectOrchestrateArgs {
    /// JSON summary emitted by `maco orchestrate run --json`.
    summary_json: PathBuf,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ValidateOrchestrateArgs {
    /// JSON plan file to validate.
    plan_file: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SuperviseCommand {
    #[command(subcommand)]
    command: SuperviseSubcommand,
}

impl SuperviseCommand {
    fn run(self) -> Result<()> {
        run_supervise_command(self.command)
    }
}

fn emit_supervisor_plan_error(error: anyhow::Error, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&supervise::supervisor_plan_error_envelope(&error))?
        );
    }
    Err(error)
}

fn run_supervise_command(command: SuperviseSubcommand) -> Result<()> {
    match command {
        SuperviseSubcommand::Plan(args) => {
            let PlanSuperviseArgs {
                task_file,
                from_goal,
                repo,
                objective_profile,
                json,
            } = args;
            let mut plan = match (task_file, from_goal) {
                (Some(task_file), None) => {
                    match supervise::supervisor_plan_document_from_task_file(repo, task_file) {
                        Ok(plan) => plan,
                        Err(error) => return emit_supervisor_plan_error(error, json),
                    }
                }
                (None, Some(goal_file)) => {
                    let goal_spec = read_supervise_goal_file(&goal_file)?;
                    match supervise::supervisor_plan_document_from_goal_spec(repo, "", &goal_spec) {
                        Ok(plan) => plan,
                        Err(error) => return emit_supervisor_plan_error(error, json),
                    }
                }
                _ => bail!(
                    "supervise plan requires exactly one positional TASK_FILE or --from-goal <FILE>"
                ),
            };
            if let Some(objective_profile) = objective_profile {
                plan.as_object_mut()
                    .context("normalized supervisor plan must be a JSON object")?
                    .insert(
                        "objective_profile".to_string(),
                        serde_json::Value::String(objective_profile),
                    );
            }
            print_query_report(&plan, json)
        }
        SuperviseSubcommand::Run(args) => {
            let routed_literal = args.literal_goal.is_some();
            let (machine_global_config, machine_global_runtime_root_id) =
                resolve_supervise_machine_global_binding(
                    routed_literal,
                    args.machine_global_config.clone(),
                    args.machine_global_runtime_root_id.clone(),
                )?;
            let quota_config = args.quota_config.clone();
            let rolling_quota = args.budget.rolling_quota();
            let budget_overrides = args.budget.limits();
            let budget_max_duration_seconds = args.budget.max_duration_seconds();
            let (plan_file, goal_spec) =
                match (args.supervisor_plan, args.from_goal, args.literal_goal) {
                (Some(plan_file), None, None) => (plan_file, None),
                (None, Some(goal_file), None) => {
                    let goal_spec = read_supervise_goal_file(&goal_file)?;
                    (goal_file, Some(goal_spec))
                }
                (None, None, Some(goal_spec)) => {
                    (PathBuf::from("<literal-instruction>"), Some(goal_spec))
                }
                _ => bail!(
                    "supervise run requires exactly one positional SUPERVISOR_PLAN, --from-goal <FILE>, or routed literal instruction"
                ),
            };
            let existing = if let Some(explicit) = args.run_id.as_deref() {
                let repo = artifacts::discover_repo_root(&args.repo)?;
                let run_id = RunId::new(explicit)?;
                let run_dir = repo
                    .join(RunArtifactFamily::Supervise.run_root())
                    .join(run_id.as_str());
                match std::fs::symlink_metadata(&run_dir) {
                    Ok(_) => Some((repo, run_id)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("failed to inspect supervise run {}", run_dir.display())
                        })
                    }
                }
            } else {
                None
            };
            let (resolved_repo, resolved_run_id, resume_existing) = match existing {
                Some((repo, run_id)) => (repo, run_id, true),
                None => {
                    let resolved = resolve_run_id_for_run(
                        &args.repo,
                        RunArtifactFamily::Supervise,
                        args.run_id.as_deref(),
                        args.json,
                    )?;
                    (resolved.repo, resolved.run_id, false)
                }
            };
            let admission_overrides = supervise::SupervisorAdmissionConfig {
                max_concurrent_children: args.max_concurrent_children.configured_limit(),
                provider_inflight_limit: args.provider_inflight_limit,
                host_memory_available_mib: args.host_memory_available_mib,
                host_memory_per_child_mib: args.host_memory_per_child_mib,
                host_fd_available: args.host_fd_available,
                host_fds_per_child: args.host_fds_per_child,
                host_disk_available_mib: args.host_disk_available_mib,
                host_disk_per_child_mib: args.host_disk_per_child_mib,
                host_fallback_children: args.host_fallback_children,
            };
            let runtime = args.runtime.unwrap_or_else(|| {
                supervise::load_supervisor_plan_file(&plan_file)
                    .ok()
                    .and_then(|plan| plan.assignments.first().and_then(|a| a.runtime))
                    .unwrap_or(supervise::SupervisorRuntime::Codex)
            });
            let json = args.json;
            let objective_profile_override = args.objective_profile.clone();
            let role_category_override = args.role_category_override.role_category;
            if resume_existing && objective_profile_override.is_some() {
                bail!(
                    "--objective-profile cannot change an existing supervise run; resume uses its frozen objective profile"
                );
            }
            if resume_existing && role_category_override.is_some() {
                bail!(
                    "--role-category cannot change an existing supervise run; resume uses its frozen role categories"
                );
            }
            let (plan_file, goal_spec) = materialize_launch_plan_for_operator_role_category(
                plan_file,
                goal_spec,
                &resolved_repo,
                resolved_run_id.as_str(),
                role_category_override,
            )?;
            let reap_repo = resolved_repo.clone();
            let _rolling_guard = rolling_quota
                .map(|quota| {
                    crate::budget_ledger::bind_rolling_budget(
                        &resolved_repo,
                        quota,
                        resolved_run_id.as_str(),
                    )
                })
                .transpose()?;
            let _quota_config_guard = quota_config
                .as_deref()
                .map(|path| supervise::bind_operator_quota_config(&resolved_repo, path))
                .transpose()?;
            let options = SupervisorRunOptions {
                repo: resolved_repo,
                plan_file,
                run_id: resolved_run_id.clone(),
                parent_node: args.parent_node.map(Into::into),
                codex_bin: args.runtime_bin.unwrap_or_else(|| {
                    if runtime.is_adapter_subprocess() {
                        PathBuf::from(runtime.default_binary())
                    } else {
                        args.codex_bin
                    }
                }),
                runtime,
                allow_dirty_primary: args.allow_dirty_primary,
                allow_live_run_collision: args.force_live_run,
                admission_overrides,
                budget_overrides,
                budget_max_duration_seconds,
                machine_global_retention: Some(MachineGlobalRetentionBinding {
                    config: machine_global_config,
                    root_id: machine_global_runtime_root_id,
                    owner: "maco-supervise".to_string(),
                    correction_correlation_id: resolved_run_id.as_str().to_string(),
                }),
            };
            let outcome = (|| {
                let report = match (goal_spec, resume_existing) {
                    (Some(goal_spec), true) => {
                        supervise::resume_supervisor_goal_spec_cascade_with_concurrency_policy(
                            options,
                            "",
                            &goal_spec,
                            args.max_concurrent_children,
                        )?
                    }
                    (Some(goal_spec), false) => {
                        supervise::run_supervisor_goal_spec_cascade_with_concurrency_policy_and_primary_worktree_opt_in_and_objective_profile_override(
                            options,
                            "",
                            &goal_spec,
                            args.max_concurrent_children,
                            args.allow_primary_worktree,
                            objective_profile_override,
                        )?
                    }
                    (None, true) => {
                        supervise::resume_supervisor_plan_file_cascade_with_concurrency_policy(
                            options,
                            args.max_concurrent_children,
                        )?
                    }
                    (None, false) => {
                        supervise::run_supervisor_plan_file_cascade_with_concurrency_policy_and_primary_worktree_opt_in_and_objective_profile_override(
                            options,
                            args.max_concurrent_children,
                            args.allow_primary_worktree,
                            objective_profile_override,
                        )?
                    }
                };
                print_query_report(&report, json)?;
                if !report.follow_up_cascade_success {
                    bail!("supervise run failed");
                }
                Ok(())
            })();
            finish_with_merged_worktree_reap(&reap_repo, json, outcome)
        }
        SuperviseSubcommand::Reaudit(args) => {
            let resolved = resolve_run_id_for_run(
                &args.repo,
                RunArtifactFamily::Supervise,
                args.run_id.as_deref(),
                args.json,
            )?;
            let report = supervise::reaudit_supervisor_assignment(
                supervise::SupervisorEvidenceOnlyReauditOptions {
                    repo: resolved.repo,
                    source_run_id: RunId::new(&args.source_run_id)?,
                    assignment_id: args.assignment_id,
                    run_id: resolved.run_id.clone(),
                    codex_bin: args.runtime_bin.unwrap_or_else(|| {
                        let runtime = args.runtime.unwrap_or(supervise::SupervisorRuntime::Codex);
                        if runtime.is_adapter_subprocess() {
                            PathBuf::from(runtime.default_binary())
                        } else {
                            args.codex_bin
                        }
                    }),
                    runtime: args.runtime.unwrap_or(supervise::SupervisorRuntime::Codex),
                    allow_dirty_primary: args.allow_dirty_primary,
                    machine_global_retention: Some(MachineGlobalRetentionBinding {
                        config: args.machine_global_config,
                        root_id: args.machine_global_runtime_root_id,
                        owner: "maco-supervise-reaudit".to_string(),
                        correction_correlation_id: resolved.run_id.as_str().to_string(),
                    }),
                },
            )?;
            print_query_report(&report, args.json)?;
            if !report.success {
                bail!("supervise evidence-only re-audit refused or rejected");
            }
            Ok(())
        }
        SuperviseSubcommand::Status(args) => {
            let report = supervise::supervisor_status(args.repo, RunId::new(&args.run_id)?)?;
            print_query_report(&report, args.json)
        }
        SuperviseSubcommand::Resume(args) => {
            let report = supervise::resume_supervisor_run(args.repo, RunId::new(&args.run_id)?)?;
            print_query_report(&report, args.json)?;
            if !report.success {
                bail!("supervise resume refused");
            }
            Ok(())
        }
        SuperviseSubcommand::Collect(args) => {
            let report = supervise::collect_supervisor_run(args.repo, RunId::new(&args.run_id)?)?;
            print_query_report(&report, args.json)?;
            if !report.success {
                bail!("supervise run failed");
            }
            Ok(())
        }
        SuperviseSubcommand::Artifacts(command) => command.run(RunArtifactFamily::Supervise),
    }
}

fn read_supervise_goal_file(goal_file: &Path) -> Result<String> {
    BoundedRegularReader::read_tree_no_follow_utf8(goal_file, MAX_SUPERVISE_GOAL_FILE_BYTES)
        .with_context(|| format!("failed to read goal/spec file {}", goal_file.display()))
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum SuperviseSubcommand {
    /// Build a validated plan from a goal/spec, task file, or JSON supervisor plan.
    Plan(PlanSuperviseArgs),
    /// Run a supervisor plan with child orchestrators for a selected runtime.
    Run(RunSuperviseArgs),
    /// Re-run only evidence/report and parent audit stages for a preserved assignment diff.
    #[command(name = "re-audit")]
    Reaudit(ReauditSuperviseArgs),
    /// Report durable run artifact status.
    Status(StatusSuperviseArgs),
    /// Resume safe finalization from an authenticated scheduler checkpoint.
    Resume(ResumeSuperviseArgs),
    /// Collect the durable supervisor final report.
    Collect(CollectSuperviseArgs),
    /// List, inspect, or prune durable run artifacts.
    Artifacts(ArtifactsCommand),
}

#[derive(Debug, Args)]
struct PlanSuperviseArgs {
    /// Plain-text task/spec file or JSON supervisor plan file.
    #[arg(
        value_name = "TASK_FILE",
        required_unless_present = "from_goal",
        conflicts_with = "from_goal"
    )]
    task_file: Option<PathBuf>,
    /// High-level goal/spec file to decompose, even when its contents are valid JSON.
    #[arg(long, value_name = "FILE", conflicts_with = "task_file")]
    from_goal: Option<PathBuf>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Named objective profile requested in the emitted supervisor plan.
    #[arg(long, value_name = "NAME")]
    objective_profile: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, Default, Args)]
struct RunBudgetArgs {
    /// Hard ceiling for total provider tokens committed by this supervise run.
    ///
    /// Tightens the plan `run_budget` by taking the minimum and is retained on
    /// the run budget ledger as `sources.cli` alongside the original plan values.
    #[arg(
        long = "max-tokens",
        visible_alias = "max-total-tokens",
        value_parser = parse_positive_usize
    )]
    max_tokens: Option<usize>,
    /// Hard ceiling for total provider cost committed by this supervise run, in USD.
    ///
    /// Tightens the plan `run_budget` by taking the minimum and is retained on
    /// the run budget ledger as `sources.cli` alongside the original plan values.
    #[arg(
        long = "max-cost-usd",
        visible_alias = "max-total-cost-usd",
        value_parser = parse_positive_finite_f64
    )]
    max_cost_usd: Option<f64>,
    /// Maximum elapsed duration for admitting new supervise dispatches.
    ///
    /// Tightens `run_budget.max_duration_seconds` by taking the minimum and is
    /// retained on the run budget ledger as `sources.cli`.
    #[arg(
        long = "max-duration-seconds",
        visible_alias = "max-total-duration-seconds",
        value_parser = parse_positive_seconds
    )]
    max_duration_seconds: Option<u64>,
    /// Hard ceiling for provider tokens consumed across supervise/autopilot runs
    /// in the workspace rolling window (default 24h).
    #[arg(
        long = "max-rolling-tokens",
        value_parser = parse_positive_usize
    )]
    max_rolling_tokens: Option<usize>,
    /// Hard ceiling for provider cost consumed across supervise/autopilot runs
    /// in the workspace rolling window, in USD.
    #[arg(
        long = "max-rolling-cost-usd",
        value_parser = parse_positive_finite_f64
    )]
    max_rolling_cost_usd: Option<f64>,
    /// Rolling window used with `--max-rolling-tokens` / `--max-rolling-cost-usd`.
    /// Defaults to 86400 seconds (24 hours) when a rolling ceiling is set.
    #[arg(
        long = "rolling-window-seconds",
        value_parser = parse_positive_seconds
    )]
    rolling_window_seconds: Option<u64>,
}

impl RunBudgetArgs {
    fn limits(self) -> supervise::RunBudgetLimits {
        supervise::RunBudgetLimits {
            soft_tokens: None,
            hard_tokens: self.max_tokens,
            soft_cost_usd: None,
            hard_cost_usd: self.max_cost_usd,
        }
    }

    const fn max_duration_seconds(self) -> Option<u64> {
        self.max_duration_seconds
    }

    fn rolling_quota(self) -> Option<crate::budget_ledger::RollingBudgetQuota> {
        if self.max_rolling_tokens.is_none() && self.max_rolling_cost_usd.is_none() {
            return None;
        }
        Some(crate::budget_ledger::RollingBudgetQuota {
            max_tokens: self.max_rolling_tokens,
            max_cost_usd: self.max_rolling_cost_usd,
            window_seconds: self
                .rolling_window_seconds
                .unwrap_or(crate::budget_ledger::DEFAULT_ROLLING_WINDOW_SECONDS),
        })
    }
}

/// Recorded operator role-category override. Automatic selection stays the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperatorRoleCategory {
    DelegatingCoordinator,
    NonDelegatingTerminalWorker,
    ReadOnlyResearcher,
    ReadOnlyReviewAuditor,
}

impl OperatorRoleCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DelegatingCoordinator => "delegating_coordinator",
            Self::NonDelegatingTerminalWorker => "non_delegating_terminal_worker",
            Self::ReadOnlyResearcher => "read_only_researcher",
            Self::ReadOnlyReviewAuditor => "read_only_review_auditor",
        }
    }
}

fn parse_operator_role_category(value: &str) -> std::result::Result<OperatorRoleCategory, String> {
    match value {
        "delegating_coordinator" | "delegating-coordinator" => {
            Ok(OperatorRoleCategory::DelegatingCoordinator)
        }
        "non_delegating_terminal_worker" | "non-delegating-terminal-worker" => {
            Ok(OperatorRoleCategory::NonDelegatingTerminalWorker)
        }
        "read_only_researcher" | "read-only-researcher" => {
            Ok(OperatorRoleCategory::ReadOnlyResearcher)
        }
        "read_only_review_auditor" | "read-only-review-auditor" => {
            Ok(OperatorRoleCategory::ReadOnlyReviewAuditor)
        }
        other => Err(format!(
            "unknown role category '{other}'; expected delegating_coordinator, non_delegating_terminal_worker, read_only_researcher, or read_only_review_auditor"
        )),
    }
}

#[derive(Debug, Clone, Copy, Default, Args)]
struct OperatorRoleCategoryArgs {
    /// Operator role-category override recorded as `selection_source=operator_override`.
    ///
    /// Omitted keeps automatic selection derived from the plan role. This is the
    /// CLI launch flag; `maco/c26-wiring` `plan_api.rs` consumes the stamped
    /// assignment fields after merge.
    #[arg(
        long = "role-category",
        value_name = "CATEGORY",
        value_parser = parse_operator_role_category
    )]
    role_category: Option<OperatorRoleCategory>,
}

const OPERATOR_OVERRIDE_SELECTION_SOURCE: &str = "operator_override";

fn stamp_operator_role_category_override(
    plan: &mut Value,
    category: OperatorRoleCategory,
) -> Result<()> {
    let assignments = plan
        .get_mut("assignments")
        .and_then(Value::as_array_mut)
        .context("operator --role-category requires a JSON plan with an assignments array")?;
    for assignment in assignments {
        stamp_role_category_on_assignment(assignment, category)?;
    }
    Ok(())
}

fn stamp_role_category_on_assignment(
    assignment: &mut Value,
    category: OperatorRoleCategory,
) -> Result<()> {
    let object = assignment
        .as_object_mut()
        .context("operator --role-category assignment must be a JSON object")?;
    object.insert(
        "role_category".to_string(),
        Value::String(category.as_str().to_string()),
    );
    object.insert(
        "selection_source".to_string(),
        Value::String(OPERATOR_OVERRIDE_SELECTION_SOURCE.to_string()),
    );
    if let Some(workers) = object
        .get_mut("worker_assignments")
        .and_then(Value::as_array_mut)
    {
        for worker in workers {
            let worker_object = worker
                .as_object_mut()
                .context("operator --role-category worker assignment must be a JSON object")?;
            worker_object.insert(
                "role_category".to_string(),
                Value::String(category.as_str().to_string()),
            );
            worker_object.insert(
                "selection_source".to_string(),
                Value::String(OPERATOR_OVERRIDE_SELECTION_SOURCE.to_string()),
            );
        }
    }
    Ok(())
}

fn write_stamped_operator_role_category_plan(run_id: &str, plan: &Value) -> Result<PathBuf> {
    let output = std::env::temp_dir().join(format!("maco-operator-role-category-{run_id}.json"));
    std::fs::write(
        &output,
        serde_json::to_vec_pretty(plan)
            .context("failed to serialize stamped operator-override plan")?,
    )
    .with_context(|| {
        format!(
            "failed to write stamped operator-override plan {}",
            output.display()
        )
    })?;
    Ok(output)
}

fn materialize_operator_role_category_plan(
    source_plan: &Path,
    run_id: &str,
    category: OperatorRoleCategory,
) -> Result<PathBuf> {
    let bytes =
        BoundedRegularReader::read_tree_no_follow(source_plan, MAX_SUPERVISE_GOAL_FILE_BYTES)
            .with_context(|| {
                format!(
                    "failed to read supervisor plan {} for operator --role-category",
                    source_plan.display()
                )
            })?;
    let mut plan: Value = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "operator --role-category requires JSON plan {}",
            source_plan.display()
        )
    })?;
    stamp_operator_role_category_override(&mut plan, category)?;
    write_stamped_operator_role_category_plan(run_id, &plan)
}

fn materialize_launch_plan_for_operator_role_category(
    plan_file: PathBuf,
    goal_spec: Option<String>,
    repo: &Path,
    run_id: &str,
    category: Option<OperatorRoleCategory>,
) -> Result<(PathBuf, Option<String>)> {
    let Some(category) = category else {
        return Ok((plan_file, goal_spec));
    };
    let stamped = match goal_spec {
        Some(spec) => {
            let mut plan = supervise::supervisor_plan_document_from_goal_spec(repo, "", &spec)
                .context("failed to materialize supervisor plan for operator --role-category")?;
            stamp_operator_role_category_override(&mut plan, category)?;
            write_stamped_operator_role_category_plan(run_id, &plan)?
        }
        None => materialize_operator_role_category_plan(&plan_file, run_id, category)?,
    };
    Ok((stamped, None))
}

#[derive(Debug, Args)]
struct RunSuperviseArgs {
    /// JSON supervisor plan file to run.
    #[arg(
        value_name = "SUPERVISOR_PLAN",
        required_unless_present_any = ["from_goal", "literal_goal"],
        conflicts_with_all = ["from_goal", "literal_goal"]
    )]
    supervisor_plan: Option<PathBuf>,
    /// High-level goal/spec file to decompose and run through the supervisor gates.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["supervisor_plan", "literal_goal"]
    )]
    from_goal: Option<PathBuf>,
    /// Internal argv-routing source for a bare literal instruction.
    #[arg(
        long,
        value_name = "TEXT",
        hide = true,
        allow_hyphen_values = true,
        conflicts_with_all = ["supervisor_plan", "from_goal"]
    )]
    literal_goal: Option<String>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable run id for durable `.maco/o2/runs/<run-id>` artifacts. Omit to generate one.
    #[arg(long)]
    run_id: Option<String>,
    /// External orchestration node that directly spawned this supervisor run.
    #[arg(long, value_parser = parse_boxed_orchestration_node_id)]
    parent_node: Option<Box<str>>,
    /// Codex-compatible executable to invoke. Ignored by the deterministic Fake runtime.
    #[arg(long, default_value = "codex")]
    codex_bin: PathBuf,
    /// Selected runtime executable. Defaults to `--codex-bin` for Codex and the adapter default otherwise.
    #[arg(long)]
    runtime_bin: Option<PathBuf>,
    /// Runtime. Fake is deterministic in-process simulation and never executes Codex or publishes.
    #[arg(long, value_enum)]
    runtime: Option<supervise::SupervisorRuntime>,
    /// Named objective profile. Overrides the authored plan selection.
    #[arg(long, value_name = "NAME")]
    objective_profile: Option<String>,
    /// Allow supervise to run when the primary worktree is dirty.
    #[arg(long)]
    allow_dirty_primary: bool,
    /// Launch even when another live supervise or autopilot run still targets this repository.
    /// Launch-only: grants no authority to kill, interrupt, revert, or discard another run.
    #[arg(long)]
    force_live_run: bool,
    /// Acknowledge an exact execution_target.kind=primary_worktree plan declaration.
    #[arg(long)]
    allow_primary_worktree: bool,
    /// Maximum concurrent child assignments: `auto` uses the conservative network-bound default.
    #[arg(long, default_value_t = supervise::SupervisorConcurrencyPolicy::Auto)]
    max_concurrent_children: supervise::SupervisorConcurrencyPolicy,
    /// Configured provider quota for simultaneous in-flight child requests (no live probing).
    #[arg(long, value_parser = parse_positive_usize)]
    provider_inflight_limit: Option<usize>,
    /// Repository-relative strict versioned quota entitlement config. No provider is probed.
    #[arg(long, value_name = "REPO_RELATIVE_FILE")]
    quota_config: Option<PathBuf>,
    /// Explicit host memory available to supervised children, in MiB.
    #[arg(long, value_parser = parse_positive_usize)]
    host_memory_available_mib: Option<usize>,
    /// Conservative memory reservation per supervised child, in MiB.
    #[arg(long, value_parser = parse_positive_usize)]
    host_memory_per_child_mib: Option<usize>,
    /// Explicit file-descriptor capacity available to supervised children.
    #[arg(long, value_parser = parse_positive_usize)]
    host_fd_available: Option<usize>,
    /// Conservative file-descriptor reservation per supervised child.
    #[arg(long, value_parser = parse_positive_usize)]
    host_fds_per_child: Option<usize>,
    /// Explicit disk capacity available to supervised children, in MiB.
    #[arg(long, value_parser = parse_positive_usize)]
    host_disk_available_mib: Option<usize>,
    /// Conservative disk reservation per supervised child, in MiB.
    #[arg(long, value_parser = parse_positive_usize)]
    host_disk_per_child_mib: Option<usize>,
    /// Fallback host bound if memory, file-descriptor, and disk observation all fail.
    #[arg(long, value_parser = parse_positive_usize)]
    host_fallback_children: Option<usize>,
    #[command(flatten)]
    budget: RunBudgetArgs,
    #[command(flatten)]
    role_category_override: OperatorRoleCategoryArgs,
    /// Exact reviewed config used to gate private runtime output-staging cleanup.
    #[arg(
        long,
        env = "MACO_MACHINE_GLOBAL_CONFIG",
        required_unless_present = "literal_goal",
        requires = "machine_global_runtime_root_id"
    )]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root must contain `/run/user/<uid>`.
    #[arg(
        long,
        env = "MACO_MACHINE_GLOBAL_RUNTIME_ROOT_ID",
        required_unless_present = "literal_goal",
        requires = "machine_global_config"
    )]
    machine_global_runtime_root_id: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ReauditSuperviseArgs {
    /// Authenticated finalized supervise run containing the evidence-only rejection.
    source_run_id: String,
    /// Assignment whose preserved candidate should be re-audited.
    assignment_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable run id for the new authenticated re-audit run. Omit to generate one.
    #[arg(long)]
    run_id: Option<String>,
    /// Codex-compatible executable to invoke. Ignored by the deterministic Fake runtime.
    #[arg(long, default_value = "codex")]
    codex_bin: PathBuf,
    /// Selected runtime executable. Defaults to `--codex-bin` for Codex and the adapter default otherwise.
    #[arg(long)]
    runtime_bin: Option<PathBuf>,
    /// Runtime. Fake is deterministic in-process simulation and never publishes.
    #[arg(long, value_enum)]
    runtime: Option<supervise::SupervisorRuntime>,
    /// Allow the primary worktree to be dirty while preserving its exact captured state.
    #[arg(long)]
    allow_dirty_primary: bool,
    /// Exact reviewed config used to gate private runtime output-staging cleanup.
    #[arg(long, required = true)]
    machine_global_config: PathBuf,
    /// Reviewed root id whose canonical root must contain `/run/user/<uid>`.
    #[arg(long, required = true)]
    machine_global_runtime_root_id: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusSuperviseArgs {
    /// Run id to inspect.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ResumeSuperviseArgs {
    /// Interrupted supervise run id to resume.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CollectSuperviseArgs {
    /// Run id to collect.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ConsultCommand {
    #[command(subcommand)]
    command: ConsultSubcommand,
}

impl ConsultCommand {
    fn run(self) -> Result<()> {
        match self.command {
            ConsultSubcommand::Ask(args) => {
                let question = consult_question(&args)?;
                let resolved = resolve_run_id_for_run(
                    &args.repo,
                    RunArtifactFamily::Consult,
                    args.run_id.as_deref(),
                    args.json,
                )?;
                let report = consult::ask_consultant(ConsultAskOptions {
                    repo: resolved.repo,
                    run_id: resolved.run_id,
                    runtime: args.runtime,
                    consultant_bin: args.consultant_bin,
                    question,
                    context_paths: args.context_path,
                    timeout_seconds: args.timeout_seconds,
                })?;
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("consult ask failed");
                }
                Ok(())
            }
            ConsultSubcommand::Artifacts(command) => command.run(RunArtifactFamily::Consult),
        }
    }
}

#[derive(Debug, Subcommand)]
enum ConsultSubcommand {
    /// Ask a read-only terminal consultant for advice.
    Ask(AskConsultArgs),
    /// List, inspect, or prune durable consult run artifacts.
    Artifacts(ArtifactsCommand),
}

#[derive(Debug, Args)]
struct AskConsultArgs {
    /// Question text to send to the consultant after redaction.
    #[arg(long)]
    question: Option<String>,
    /// File containing the question text.
    #[arg(long)]
    question_file: Option<PathBuf>,
    /// Consultant runtime to use. Real runtimes require --consultant-bin.
    #[arg(long, default_value = "fake")]
    runtime: ConsultantRuntime,
    /// Codex- or Claude-compatible executable for real consultant runtimes.
    #[arg(long)]
    consultant_bin: Option<PathBuf>,
    /// Repo-relative existing path to mention as context. Contents are not inlined.
    #[arg(long = "context-path")]
    context_path: Vec<PathBuf>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable run id for durable `.maco/consult/runs/<run-id>` artifacts. Omit to generate one.
    #[arg(long)]
    run_id: Option<String>,
    /// Seconds before a real consultant subprocess is terminated.
    #[arg(long, default_value_t = DEFAULT_CONSULT_TIMEOUT_SECONDS)]
    timeout_seconds: u64,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn consult_question(args: &AskConsultArgs) -> Result<String> {
    match (&args.question, &args.question_file) {
        (Some(_), Some(_)) => bail!("use only one of --question or --question-file"),
        (Some(question), None) => Ok(question.clone()),
        (None, Some(path)) => {
            BoundedRegularReader::read_tree_no_follow_utf8(path, MAX_CONSULT_QUESTION_FILE_BYTES)
                .with_context(|| format!("failed to read question file {}", path.display()))
        }
        (None, None) => bail!("one of --question or --question-file is required"),
    }
}

#[derive(Debug, Args)]
struct InboxCommand {
    #[command(subcommand)]
    command: InboxSubcommand,
}

impl InboxCommand {
    fn run(self) -> Result<()> {
        match self.command {
            InboxSubcommand::Scan(args) => {
                let report = inbox::scan_inbox(InboxScanOptions {
                    repo: args.repo,
                    github: args.github,
                    permission_mode: args.permission,
                    max_items: args.max_items,
                    action_policy_override: None,
                })?;
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("inbox scan refused");
                }
                Ok(())
            }
            InboxSubcommand::Run(args) => {
                let repo = args.repo.clone();
                let resolved = resolve_run_id_for_run(
                    &repo,
                    RunArtifactFamily::Inbox,
                    args.run_id.as_deref(),
                    args.json,
                )?;
                let report = inbox::run_inbox_with_rolling_budget(
                    InboxRunOptions {
                        repo: args.repo,
                        run_id: resolved.run_id,
                        github: args.github,
                        permission_mode: args.permission,
                        dry_run: args.dry_run,
                        max_items: args.max_items,
                        codex_bin: args.codex_bin,
                        machine_global: inbox_machine_global_input(
                            args.machine_global_config,
                            args.machine_global_runtime_root_id,
                        ),
                    },
                    args.rolling_budget.quota(),
                )?;
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("inbox run failed");
                }
                Ok(())
            }
            InboxSubcommand::Status(args) => {
                let report = inbox::inbox_status(args.repo, RunId::new(&args.run_id)?)?;
                print_query_report(&report, args.json)
            }
            InboxSubcommand::Collect(args) => {
                let report = inbox::collect_inbox_run(args.repo, RunId::new(&args.run_id)?)?;
                print_query_report(&report, args.json)?;
                if report
                    .get("success")
                    .and_then(Value::as_bool)
                    .is_some_and(|success| !success)
                {
                    bail!("inbox run failed");
                }
                Ok(())
            }
            InboxSubcommand::Watch(args) => {
                let report = inbox::watch_inbox(InboxWatchOptions {
                    repo: args.repo,
                    poll_seconds: args.poll_seconds,
                    once: args.once,
                    github: args.github,
                    permission_mode: args.permission,
                    dry_run: args.dry_run,
                    max_items: args.max_items,
                    codex_bin: args.codex_bin,
                    machine_global: inbox_machine_global_input(
                        args.machine_global_config,
                        args.machine_global_runtime_root_id,
                    ),
                })?;
                print_query_report(&report, args.json)?;
                if report.runs.iter().any(|run| !run.success) {
                    bail!("inbox watch observed a failed run");
                }
                Ok(())
            }
            InboxSubcommand::Workspace(command) => command.run(),
            InboxSubcommand::Artifacts(command) => command.run(RunArtifactFamily::Inbox),
        }
    }
}

fn inbox_machine_global_input(
    config: Option<PathBuf>,
    runtime_root_id: Option<String>,
) -> Option<InboxMachineGlobalInput> {
    match (config, runtime_root_id) {
        (Some(config), Some(runtime_root_id)) => Some(InboxMachineGlobalInput {
            config,
            runtime_root_id,
        }),
        _ => None,
    }
}

#[derive(Debug, Subcommand)]
enum InboxSubcommand {
    /// Scan safe issue and pull request candidates without launching work.
    Scan(ScanInboxArgs),
    /// Scan and process selected inbox items under a stable run id.
    Run(RunInboxArgs),
    /// Report durable inbox run artifact state.
    Status(StatusInboxArgs),
    /// Collect the durable inbox final report.
    Collect(CollectInboxArgs),
    /// Poll for inbox items and react according to policy.
    Watch(WatchInboxArgs),
    /// Scan or run inbox supervision across multiple repositories.
    Workspace(WorkspaceInboxCommand),
    /// List, inspect, or prune durable run artifacts.
    Artifacts(ArtifactsCommand),
}

#[derive(Debug, Args)]
struct WorkspaceInboxCommand {
    #[command(subcommand)]
    command: WorkspaceInboxSubcommand,
}

impl WorkspaceInboxCommand {
    fn run(self) -> Result<()> {
        match self.command {
            WorkspaceInboxSubcommand::Scan(args) => {
                let report = inbox::scan_workspace_inbox(InboxWorkspaceScanOptions {
                    config: args.config,
                })?;
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("inbox workspace scan failed");
                }
                Ok(())
            }
            WorkspaceInboxSubcommand::Run(args) => {
                let report = inbox::run_workspace_inbox(InboxWorkspaceRunOptions {
                    config: args.config,
                    run_id: RunId::new(&args.run_id)?,
                    dry_run: args.dry_run,
                    codex_bin: args.codex_bin,
                    machine_global: inbox_machine_global_input(
                        args.machine_global_config,
                        args.machine_global_runtime_root_id,
                    ),
                })?;
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("inbox workspace run failed");
                }
                Ok(())
            }
            WorkspaceInboxSubcommand::Watch(args) => {
                let report = inbox::watch_workspace_inbox(InboxWorkspaceWatchOptions {
                    config: args.config,
                    poll_seconds: args.poll_seconds,
                    once: args.once,
                    dry_run: args.dry_run,
                    codex_bin: args.codex_bin,
                    machine_global: inbox_machine_global_input(
                        args.machine_global_config,
                        args.machine_global_runtime_root_id,
                    ),
                })?;
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("inbox workspace watch failed");
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum WorkspaceInboxSubcommand {
    /// Scan configured repositories without launching work.
    Scan(ScanWorkspaceInboxArgs),
    /// Run configured repositories under a workspace run id.
    Run(RunWorkspaceInboxArgs),
    /// Poll configured repositories and run workspace inbox supervision.
    Watch(WatchWorkspaceInboxArgs),
}

#[derive(Debug, Args)]
struct ScopeCommand {
    #[command(subcommand)]
    command: ScopeSubcommand,
}

impl ScopeCommand {
    fn run(self) -> Result<()> {
        match self.command {
            ScopeSubcommand::Serve(args) => scope::serve(ScopeServeOptions {
                repositories: args.repositories,
                workspace: args.workspace,
                bind: args.bind,
            }),
            ScopeSubcommand::Event(args) => {
                let payload = parse_external_event_payload(&args.payload)?;
                let event = append_external_orchestration_event(
                    args.repo,
                    RunId::new(&args.run)?,
                    &args.node,
                    args.parent.as_deref(),
                    args.role.into(),
                    args.kind.into(),
                    payload,
                )?;
                print_query_report(&event, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum ScopeSubcommand {
    /// Serve the localhost-only Scope observability backend.
    Serve(ScopeServeArgs),
    /// Append one disclosure-safe event for an external root or directly spawned child.
    Event(EmitScopeEventArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ExternalEventRoleArg {
    Root,
    Orchestrator,
    Worker,
    Auditor,
}

impl From<ExternalEventRoleArg> for OrchestrationRole {
    fn from(value: ExternalEventRoleArg) -> Self {
        match value {
            ExternalEventRoleArg::Root => Self::Root,
            ExternalEventRoleArg::Orchestrator => Self::Orchestrator,
            ExternalEventRoleArg::Worker => Self::Worker,
            ExternalEventRoleArg::Auditor => Self::Auditor,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ExternalEventKindArg {
    Spawn,
    Status,
    Journal,
}

impl From<ExternalEventKindArg> for OrchestrationEventKind {
    fn from(value: ExternalEventKindArg) -> Self {
        match value {
            ExternalEventKindArg::Spawn => Self::Spawn,
            ExternalEventKindArg::Status => Self::Status,
            ExternalEventKindArg::Journal => Self::Journal,
        }
    }
}

#[derive(Debug, Args)]
struct EmitScopeEventArgs {
    /// Repository whose external root-event stream receives this event.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// External driver run id under `.maco/o2-autopilot/runs`.
    #[arg(long)]
    run: String,
    /// Canonical id for the external root or directly spawned child.
    #[arg(long, value_parser = parse_orchestration_node_id)]
    node: String,
    /// Canonical parent node id. Omit it for the topmost external root.
    #[arg(long, value_parser = parse_orchestration_node_id)]
    parent: Option<String>,
    /// External role. The supervisor role is intentionally unavailable here.
    #[arg(long, value_enum)]
    role: ExternalEventRoleArg,
    /// External event kind. Gate and decision kinds are intentionally unavailable here.
    #[arg(long, value_enum)]
    kind: ExternalEventKindArg,
    /// Disclosure-safe JSON: runtime is required; optional status is a short token.
    #[arg(long)]
    payload: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn parse_orchestration_node_id(value: &str) -> Result<String, String> {
    normalize_orchestration_node_id(value).map_err(|error| format!("{error:#}"))
}

fn parse_boxed_orchestration_node_id(value: &str) -> Result<Box<str>, String> {
    parse_orchestration_node_id(value).map(String::into_boxed_str)
}

fn parse_external_event_payload(value: &str) -> Result<ExternalOrchestrationPayload> {
    if value.len() > MAX_EXTERNAL_EVENT_PAYLOAD_CLI_BYTES {
        bail!(
            "external orchestration payload exceeds its {MAX_EXTERNAL_EVENT_PAYLOAD_CLI_BYTES}-byte CLI limit"
        );
    }
    let payload = serde_json::from_str::<ExternalOrchestrationPayload>(value)
        .context("external orchestration payload must match the disclosure-safe schema")?;
    payload.validate()?;
    Ok(payload)
}

#[derive(Debug, Args)]
struct ScopeServeArgs {
    /// Repository path to watch. Repeat to watch multiple repositories.
    #[arg(long = "repo")]
    repositories: Vec<PathBuf>,
    /// Inbox-shaped workspace JSON listing repositories to watch.
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Loopback address and port for the HTTP server.
    #[arg(long, default_value = "127.0.0.1:7878")]
    bind: String,
}

#[derive(Debug, Args)]
struct ScanWorkspaceInboxArgs {
    /// Workspace inbox JSON config path.
    #[arg(long)]
    config: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RunWorkspaceInboxArgs {
    /// Workspace inbox JSON config path.
    #[arg(long)]
    config: PathBuf,
    /// Stable workspace run id for `.maco/inbox-workspace/runs/<run-id>` artifacts.
    #[arg(long)]
    run_id: String,
    /// Plan item work and reports without launching autopilot.
    #[arg(long)]
    dry_run: bool,
    /// Codex-compatible executable to pass through to per-repository inbox runs.
    #[arg(long)]
    codex_bin: Option<PathBuf>,
    /// Exact reviewed config used to gate private runtime output-staging cleanup for item autopilot dispatch.
    #[arg(long, requires = "machine_global_runtime_root_id")]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root must contain `/run/user/<uid>`.
    #[arg(long, requires = "machine_global_config")]
    machine_global_runtime_root_id: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct WatchWorkspaceInboxArgs {
    /// Workspace inbox JSON config path.
    #[arg(long)]
    config: PathBuf,
    /// Seconds between poll iterations.
    #[arg(long, default_value_t = 60)]
    poll_seconds: u64,
    /// Run one poll iteration and return.
    #[arg(long)]
    once: bool,
    /// Plan item work and reports without launching autopilot.
    #[arg(long)]
    dry_run: bool,
    /// Codex-compatible executable to pass through to per-repository inbox runs.
    #[arg(long)]
    codex_bin: Option<PathBuf>,
    /// Exact reviewed config used to gate private runtime output-staging cleanup for item autopilot dispatch.
    #[arg(long, requires = "machine_global_runtime_root_id")]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root must contain `/run/user/<uid>`.
    #[arg(long, requires = "machine_global_config")]
    machine_global_runtime_root_id: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ScanInboxArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Maximum number of safe items selected for work.
    #[arg(long)]
    max_items: Option<usize>,
    /// Enable real GitHub API reads through the local gh CLI.
    #[arg(long)]
    github: bool,
    /// Select inbox capabilities: fake, github_read, github_local, github_git, github_pr, or github_full.
    #[arg(long, value_parser = parse_inbox_permission_mode)]
    permission: Option<InboxPermissionMode>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RunInboxArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable run id for durable `.maco/inbox/runs/<run-id>` artifacts. Omit to generate one.
    #[arg(long)]
    run_id: Option<String>,
    /// Plan item work and reports without launching autopilot.
    #[arg(long)]
    dry_run: bool,
    /// Maximum number of safe items selected for work.
    #[arg(long)]
    max_items: Option<usize>,
    /// Enable real GitHub API reads/comments and GitHub publication through gh.
    #[arg(long)]
    github: bool,
    /// Select inbox capabilities: fake, github_read, github_local, github_git, github_pr, or github_full.
    #[arg(long, value_parser = parse_inbox_permission_mode)]
    permission: Option<InboxPermissionMode>,
    /// Codex-compatible executable to invoke. Omit for deterministic local fake mode.
    #[arg(long)]
    codex_bin: Option<PathBuf>,
    #[command(flatten)]
    rolling_budget: InboxRollingBudgetArgs,
    /// Exact reviewed config used to gate private runtime output-staging cleanup for item autopilot dispatch.
    #[arg(long, requires = "machine_global_runtime_root_id")]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root must contain `/run/user/<uid>`.
    #[arg(long, requires = "machine_global_config")]
    machine_global_runtime_root_id: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, Default, Args)]
struct InboxRollingBudgetArgs {
    /// Hard ceiling for provider tokens consumed across inbox autopilot runs
    /// in the workspace rolling window (default 24h).
    #[arg(long = "max-rolling-tokens", value_parser = parse_positive_usize)]
    max_rolling_tokens: Option<usize>,
    /// Hard ceiling for provider cost consumed across inbox autopilot runs
    /// in the workspace rolling window, in USD.
    #[arg(
        long = "max-rolling-cost-usd",
        value_parser = parse_positive_finite_f64
    )]
    max_rolling_cost_usd: Option<f64>,
    /// Rolling window used with `--max-rolling-tokens` / `--max-rolling-cost-usd`.
    /// Defaults to 86400 seconds (24 hours) when a rolling ceiling is set.
    #[arg(
        long = "rolling-window-seconds",
        value_parser = parse_positive_seconds
    )]
    rolling_window_seconds: Option<u64>,
}

impl InboxRollingBudgetArgs {
    fn quota(self) -> Option<inbox::InboxRollingBudgetQuota> {
        if self.max_rolling_tokens.is_none() && self.max_rolling_cost_usd.is_none() {
            return None;
        }
        Some(inbox::InboxRollingBudgetQuota {
            max_tokens: self.max_rolling_tokens,
            max_cost_usd: self.max_rolling_cost_usd,
            window_seconds: self
                .rolling_window_seconds
                .unwrap_or(inbox::DEFAULT_ROLLING_WINDOW_SECONDS),
        })
    }
}

#[derive(Debug, Args)]
struct StatusInboxArgs {
    /// Run id to inspect.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CollectInboxArgs {
    /// Run id to collect.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct WatchInboxArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Seconds between poll iterations.
    #[arg(long, default_value_t = 60)]
    poll_seconds: u64,
    /// Run one poll iteration and return.
    #[arg(long)]
    once: bool,
    /// Plan item work and reports without launching autopilot.
    #[arg(long)]
    dry_run: bool,
    /// Maximum number of safe items selected for work.
    #[arg(long)]
    max_items: Option<usize>,
    /// Enable real GitHub API reads/comments and GitHub publication through gh.
    #[arg(long)]
    github: bool,
    /// Select inbox capabilities: fake, github_read, github_local, github_git, github_pr, or github_full.
    #[arg(long, value_parser = parse_inbox_permission_mode)]
    permission: Option<InboxPermissionMode>,
    /// Codex-compatible executable to invoke. Omit for deterministic local fake mode.
    #[arg(long)]
    codex_bin: Option<PathBuf>,
    /// Exact reviewed config used to gate private runtime output-staging cleanup for item autopilot dispatch.
    #[arg(long, requires = "machine_global_runtime_root_id")]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root must contain `/run/user/<uid>`.
    #[arg(long, requires = "machine_global_config")]
    machine_global_runtime_root_id: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AutopilotCommand {
    #[command(subcommand)]
    command: AutopilotSubcommand,
}

impl AutopilotCommand {
    fn run(self) -> Result<()> {
        match self.command {
            AutopilotSubcommand::Plan(_) | AutopilotSubcommand::Run(_) => {
                bail!(RETIRED_AUTOPILOT_EXECUTION_MESSAGE)
            }
            AutopilotSubcommand::Status(args) => {
                let report = autopilot::autopilot_status(args.repo, RunId::new(&args.run_id)?)?;
                print_query_report(&report, args.json)
            }
            AutopilotSubcommand::Collect(args) => {
                let report =
                    autopilot::collect_autopilot_run(args.repo, RunId::new(&args.run_id)?)?;
                print_query_report(&report, args.json)?;
                if report
                    .get("success")
                    .and_then(Value::as_bool)
                    .is_some_and(|success| !success)
                {
                    bail!("autopilot run failed");
                }
                Ok(())
            }
            AutopilotSubcommand::Artifacts(command) => command.run(RunArtifactFamily::Autopilot),
        }
    }
}

#[derive(Debug, Subcommand)]
enum AutopilotSubcommand {
    /// Retired. Use `maco <instruction>`.
    #[command(hide = true)]
    Plan(RetiredAutopilotArgs),
    /// Retired. Use `maco <instruction>`.
    #[command(hide = true)]
    Run(RetiredAutopilotArgs),
    /// Report durable autopilot run artifact state.
    Status(StatusAutopilotArgs),
    /// Collect the durable autopilot final report.
    Collect(CollectAutopilotArgs),
    /// List, inspect, or prune durable run artifacts.
    Artifacts(ArtifactsCommand),
}

#[derive(Debug, Args)]
struct RetiredAutopilotArgs {
    /// Ignored legacy arguments. The command always returns the retirement message.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _legacy_args: Vec<OsString>,
}

#[derive(Debug, Args)]
struct StatusAutopilotArgs {
    /// Run id to inspect.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CollectAutopilotArgs {
    /// Run id to collect.
    run_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ArtifactsCommand {
    #[command(subcommand)]
    command: ArtifactsSubcommand,
}

impl ArtifactsCommand {
    fn run(self, family: RunArtifactFamily) -> Result<()> {
        match self.command {
            ArtifactsSubcommand::List(args) => {
                let report = artifacts::list_runs(args.repo, family)?;
                print_query_report(&report, args.json)
            }
            ArtifactsSubcommand::Latest(args) => {
                let report = artifacts::latest_run(args.repo, family)?;
                print_query_report(&report, args.json)
            }
            ArtifactsSubcommand::Prune(args) => {
                let policy = args.retention_policy();
                let report =
                    artifacts::prune_runs_with_policy(args.repo, family, &policy, args.dry_run)?;
                print_query_report(&report, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum ArtifactsSubcommand {
    /// List run artifact directories newest first.
    List(ListArtifactsArgs),
    /// Show the latest run artifact directory.
    Latest(ListArtifactsArgs),
    /// Delete old run artifact directories under this command family's run root.
    Prune(PruneArtifactsArgs),
}

#[derive(Debug, Args)]
struct ListArtifactsArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PruneArtifactsArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Keep the latest N run directories.
    #[arg(long, default_value_t = 10)]
    keep: usize,
    /// Reclaim artifacts at least this old even when they are within --keep.
    #[arg(long, value_name = "SECONDS")]
    max_age_seconds: Option<u64>,
    /// Retain at most this many apparent regular-file bytes, newest first.
    #[arg(long, value_name = "BYTES")]
    max_total_bytes: Option<u64>,
    /// Allow idle marker-missing or external artifacts to expire after this grace.
    #[arg(long, value_name = "SECONDS", default_value_t = 7 * 24 * 60 * 60)]
    unfinalized_grace_seconds: u64,
    /// Allow grace-based expiry when a present finalization marker is unverifiable.
    #[arg(long)]
    reclaim_unverifiable: bool,
    /// Confirm that non-cooperating program and legacy artifact writers are stopped.
    #[arg(long)]
    acknowledge_external_writers_stopped: bool,
    /// Report deletions without deleting.
    #[arg(long)]
    dry_run: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

impl PruneArtifactsArgs {
    fn retention_policy(&self) -> ArtifactRetentionPolicy {
        ArtifactRetentionPolicy {
            max_count: self.keep,
            max_age: self.max_age_seconds.map(Duration::from_secs),
            max_total_bytes: self.max_total_bytes,
            unfinalized_grace: Some(Duration::from_secs(self.unfinalized_grace_seconds)),
            reclaim_unverifiable: self.reclaim_unverifiable,
            external_writers_stopped: self.acknowledge_external_writers_stopped,
        }
    }
}

#[derive(Debug, Args)]
struct RepositoryArtifactsCommand {
    #[command(subcommand)]
    command: RepositoryArtifactsSubcommand,
}

impl RepositoryArtifactsCommand {
    fn run(self) -> Result<()> {
        match self.command {
            RepositoryArtifactsSubcommand::Prune(args) => {
                let policy = args.policy.retention_policy();
                let report = artifacts::prune_artifacts_with_policy(
                    args.policy.repo,
                    args.family.into(),
                    &policy,
                    args.policy.dry_run,
                )?;
                print_query_report(&report, args.policy.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum RepositoryArtifactsSubcommand {
    /// Reclaim one authenticated, external-driver, legacy, or program-log family.
    Prune(RepositoryPruneArtifactsArgs),
}

#[derive(Debug, Args)]
struct RepositoryPruneArtifactsArgs {
    /// Artifact family to inspect and prune.
    #[arg(long, value_enum)]
    family: ArtifactRetentionFamilyArg,
    #[command(flatten)]
    policy: PruneArtifactsArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ArtifactRetentionFamilyArg {
    Autopilot,
    Consult,
    Inbox,
    Supervise,
    O2Autopilot,
    InboxWorkspace,
    Program,
}

impl From<ArtifactRetentionFamilyArg> for ArtifactRetentionFamily {
    fn from(family: ArtifactRetentionFamilyArg) -> Self {
        match family {
            ArtifactRetentionFamilyArg::Autopilot => Self::Autopilot,
            ArtifactRetentionFamilyArg::Consult => Self::Consult,
            ArtifactRetentionFamilyArg::Inbox => Self::Inbox,
            ArtifactRetentionFamilyArg::Supervise => Self::Supervise,
            ArtifactRetentionFamilyArg::O2Autopilot => Self::O2Autopilot,
            ArtifactRetentionFamilyArg::InboxWorkspace => Self::InboxWorkspace,
            ArtifactRetentionFamilyArg::Program => Self::Program,
        }
    }
}

#[derive(Debug, Args)]
struct ReviewCommand {
    #[command(subcommand)]
    command: ReviewSubcommand,
}

impl ReviewCommand {
    fn run(self) -> Result<()> {
        match self.command {
            ReviewSubcommand::Pr(args) => {
                let target = review::target_from_pr_arg(&args.target)?;
                let reviewer = if let Some(program) = args.reviewer_program {
                    ReviewerConfig {
                        mode: ReviewerMode::ExternalCommand,
                        program: Some(program),
                        args: args.reviewer_args,
                        timeout_seconds: args.timeout_seconds,
                        ..ReviewerConfig::default()
                    }
                } else if let Some(command) = args.reviewer_command {
                    ReviewerConfig {
                        mode: ReviewerMode::ExternalCommand,
                        command: Some(command),
                        timeout_seconds: args.timeout_seconds,
                        ..ReviewerConfig::default()
                    }
                } else {
                    ReviewerConfig {
                        timeout_seconds: args.timeout_seconds,
                        ..ReviewerConfig::default()
                    }
                };
                let report = review::review_pr(ReviewPrOptions {
                    repo: review::repo_path_for_review(args.repo),
                    target,
                    reviewer,
                    attempt: 1,
                    changed_paths: Vec::new(),
                    diff_summary: None,
                })?;
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("review pr failed");
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum ReviewSubcommand {
    /// Review a pull request target with a fake or explicit external reviewer.
    Pr(ReviewPrArgs),
}

#[derive(Debug, Args)]
struct ReviewPrArgs {
    /// Pull request number or URL.
    target: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Direct external reviewer program. Omit for deterministic fake review mode.
    #[arg(long, conflicts_with = "reviewer_command")]
    reviewer_program: Option<PathBuf>,
    /// One literal external reviewer argument. Repeat for multiple arguments.
    #[arg(long = "reviewer-arg", requires = "reviewer_program")]
    reviewer_args: Vec<String>,
    /// Legacy shell-string input; retained only to return a fail-closed error.
    #[arg(long, conflicts_with = "reviewer_program")]
    reviewer_command: Option<String>,
    /// Timeout for the external reviewer program.
    #[arg(long)]
    timeout_seconds: Option<u64>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct AgentCommand {
    #[command(subcommand)]
    command: AgentSubcommand,
}

impl AgentCommand {
    fn run(self) -> Result<()> {
        match self.command {
            AgentSubcommand::Run(args) => {
                let json = args.json;
                let reap_repo = args.repo.clone();
                let outcome = (|| {
                    if json {
                        let failure_context = AgentRunFailureContext::from_args(&args);
                        match run_agent_from_args(args) {
                            Ok(report) => {
                                print_agent_run_report(&report, true)?;
                                if !report.success {
                                    bail!(
                                        "{}",
                                        report.error.as_deref().unwrap_or("agent run failed")
                                    );
                                }
                            }
                            Err(error) => {
                                let report = failure_context.into_report(error.to_string());
                                print_agent_run_failure_report(&report)?;
                                bail!("{}", report.error);
                            }
                        }
                    } else {
                        let report = run_agent_from_args(args)?;
                        print_agent_run_report(&report, false)?;
                        if !report.success {
                            bail!("{}", report.error.as_deref().unwrap_or("agent run failed"));
                        }
                    }
                    Ok(())
                })();
                finish_with_merged_worktree_reap(&reap_repo, json, outcome)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum AgentSubcommand {
    /// Run a local provider-backed agent proposal in an isolated worktree.
    Run(RunAgentArgs),
}

#[derive(Debug, Args)]
struct RunAgentArgs {
    /// Task file to render into the provider-neutral prompt.
    task_file: PathBuf,
    /// Stable agent id for the run and linked worktree.
    #[arg(long)]
    agent_id: String,
    /// Repository-relative path to claim. Repeat for multiple paths.
    #[arg(long = "path", required = true)]
    paths: Vec<PathBuf>,
    /// Provider id. Only `fake` is available without explicit real-provider support.
    #[arg(long, default_value = "fake")]
    provider: String,
    /// Deterministic fake provider proposal JSON file.
    #[arg(long)]
    fake_proposal: Option<PathBuf>,
    /// Request id used to select the fake provider response.
    #[arg(long)]
    request_id: Option<String>,
    /// Model label recorded in the provider-neutral request.
    #[arg(long)]
    model: Option<String>,
    /// Validation shell command to run in the agent worktree after proposal execution.
    #[arg(long = "validation")]
    validation_commands: Vec<String>,
    /// Allow provider-proposed shell commands to run in the agent worktree.
    #[arg(long)]
    allow_provider_commands: bool,
    /// Timeout for each provider or validation command, in seconds.
    #[arg(long, default_value_t = 30, value_parser = parse_positive_seconds)]
    command_timeout_seconds: u64,
    /// Keep acquired path claims after the run.
    #[arg(long)]
    keep_claims: bool,
    /// Worktree reuse policy for this agent run.
    #[arg(long, default_value = "clean", value_parser = parse_agent_worktree_reuse_policy)]
    reuse: AgentWorktreeReusePolicy,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone)]
struct AgentRunFailureContext {
    repo: PathBuf,
    agent_id: String,
    provider_id: String,
    request_id: String,
}

impl AgentRunFailureContext {
    fn from_args(args: &RunAgentArgs) -> Self {
        Self {
            repo: args.repo.clone(),
            agent_id: args.agent_id.clone(),
            provider_id: args.provider.clone(),
            request_id: args
                .request_id
                .clone()
                .unwrap_or_else(|| agent::default_request_id(&args.agent_id)),
        }
    }

    fn into_report(self, error: String) -> AgentRunFailureReport {
        AgentRunFailureReport {
            success: false,
            status: "failed",
            repo: self.repo,
            agent_id: self.agent_id,
            provider_id: self.provider_id,
            request_id: self.request_id,
            error,
        }
    }
}

#[derive(Debug, Serialize)]
struct AgentRunFailureReport {
    success: bool,
    status: &'static str,
    repo: PathBuf,
    agent_id: String,
    provider_id: String,
    request_id: String,
    error: String,
}

#[derive(Debug, Args)]
struct AgentsCommand {
    #[command(subcommand)]
    command: AgentsSubcommand,
}

impl AgentsCommand {
    fn run(self) -> Result<()> {
        match self.command {
            AgentsSubcommand::List(args) => {
                let registry = AgentRegistry::open(args.repo)?;
                let processes = registry.list(&AgentListFilter {
                    run_id: args.run_id,
                })?;
                print_agent_processes(&processes, args.json)
            }
            AgentsSubcommand::Stop(args) => {
                let registry = AgentRegistry::open(args.repo)?;
                let wait = Duration::from_secs(args.wait_seconds);
                let report = if args.all {
                    if args.selector.is_some() {
                        bail!("agents stop --all does not accept a selector");
                    }
                    let run_id = args
                        .run_id
                        .context("agents stop --all requires --run-id ID")?;
                    registry.stop_run(&run_id, wait)?
                } else {
                    if args.run_id.is_some() {
                        bail!("agents stop --run-id requires --all");
                    }
                    let selector = args
                        .selector
                        .context("agents stop requires a selector or --all --run-id ID")?;
                    registry.stop_selector(&selector, wait)?
                };
                print_agent_stop_report(&report, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum AgentsSubcommand {
    /// List live registered MACO agent processes and garbage-collect stale records.
    List(ListAgentsArgs),
    /// Stop one unambiguous process, or every process in one explicitly selected run.
    Stop(StopAgentsArgs),
}

#[derive(Debug, Args)]
struct ListAgentsArgs {
    /// Repository whose .maco/agents registry should be inspected.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Include only processes belonging to this run id.
    #[arg(long)]
    run_id: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StopAgentsArgs {
    /// Run id, task/assignment id, or decimal PID. The selector must match exactly one process.
    selector: Option<String>,
    /// Stop every live process in the run selected by --run-id.
    #[arg(long)]
    all: bool,
    /// Run id used with --all.
    #[arg(long)]
    run_id: Option<String>,
    /// Repository whose .maco/agents registry should be inspected.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Seconds to wait after SIGTERM before escalating to SIGKILL.
    #[arg(long, default_value_t = 3)]
    wait_seconds: u64,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct WorktreeCommand {
    #[command(subcommand)]
    command: WorktreeSubcommand,
}

impl WorktreeCommand {
    fn run(self) -> Result<()> {
        match self.command {
            WorktreeSubcommand::Create(args) => {
                let manager = WorktreeManager::new(args.repo);
                let o2_default = args
                    .o2_launch_retention_defaults
                    .then(crate::worktree::o2_launch_worktree_retention_defaults);
                let retention = WorktreeRetentionPolicy {
                    max_age: args.gc_max_age_seconds.map(Duration::from_secs),
                    max_count: args
                        .gc_max_count
                        .or(o2_default.and_then(|policy| policy.max_count)),
                    max_total_bytes: args.gc_max_total_bytes,
                };
                // The cleanliness capability cannot cross a process boundary, so the
                // CLI derives it here: acquisition succeeds only when the primary
                // repository is observed clean through the bounded status boundary.
                let cleanliness = manager.acquire_repository_cleanliness().context(
                    "managed worktree creation requires a capability-bound repository \
                     cleanliness input; commit, stash, or remove pending changes in the \
                     primary repository, then rerun `maco worktree create`",
                )?;
                let record = manager.create_with_repository_cleanliness_and_retention(
                    WorktreeCreateOptions {
                        agent_id: args.agent_id.clone(),
                        branch: args.branch,
                        base: args.base,
                        worktree_root: args.worktree_root.clone(),
                    },
                    retention,
                    &cleanliness,
                )?;
                if args.supersede_retry_predecessor {
                    let lifecycle = manager
                        .lifecycle(WorktreeLifecycleOptions {
                            apply: args.apply_retry_supersession,
                            retry_successor_agent_id: Some(record.name.clone()),
                            worktree_root: args.worktree_root,
                            ..WorktreeLifecycleOptions::default()
                        })
                        .with_context(|| {
                            format!(
                                "worktree '{}' was created, but retry supersession failed; do not blindly retry creation",
                                record.name
                            )
                        })?;
                    print_worktree_create_lifecycle_report(&record, &lifecycle, args.json)
                } else {
                    print_worktree_record(&record, args.json)
                }
            }
            WorktreeSubcommand::Guard(command) => match command.command {
                WorktreeGuardSubcommand::Install(args) => {
                    print_query_report(&install_primary_worktree_guard(args.repo)?, args.json)
                }
                WorktreeGuardSubcommand::Verify(args) => {
                    print_query_report(&verify_primary_worktree_guard(args.repo)?, args.json)
                }
                WorktreeGuardSubcommand::Uninstall(args) => {
                    print_query_report(&uninstall_primary_worktree_guard(args.repo)?, args.json)
                }
            },
            WorktreeSubcommand::Gc(args) => {
                let manager = WorktreeManager::new(args.repo);
                let machine_global_retention = match (
                    args.machine_global_config,
                    args.machine_global_worktree_root_id,
                    args.machine_global_correlation,
                ) {
                    (Some(config), Some(root_id), Some(correction_correlation_id)) => {
                        Some(MachineGlobalRetentionBinding {
                            config,
                            root_id,
                            owner: "maco-worktree-gc".to_string(),
                            correction_correlation_id,
                        })
                    }
                    (None, None, None) => None,
                    _ => bail!(
                        "--machine-global-config, --machine-global-worktree-root-id, and \
                         --machine-global-correlation must be supplied together"
                    ),
                };
                let report = manager.gc(WorktreeGcOptions {
                    worktree_root: args.worktree_root,
                    dry_run: args.dry_run,
                    remove_targets: !args.keep_targets,
                    targets_only: args.targets_only,
                    retention: WorktreeRetentionPolicy {
                        max_age: args.max_age_seconds.map(Duration::from_secs),
                        max_count: args.max_count,
                        max_total_bytes: args.max_total_bytes,
                    },
                    allowed_untracked_paths: args.allow_untracked_paths,
                    exclude_agent_id: None,
                    candidate_agent_ids: None,
                    merged_into_reference: None,
                    superseded_by_agent_id: std::collections::BTreeMap::new(),
                    machine_global_retention,
                })?;
                print_worktree_gc_report(&report, args.json)
            }
            WorktreeSubcommand::Sweep(args) => {
                let report = sweep_workspace_worktrees(WorktreeSweepOptions {
                    workspace: args.workspace,
                    apply: args.apply,
                    remove_targets: !args.keep_targets,
                    targets_only: args.targets_only,
                    retention: WorktreeRetentionPolicy {
                        max_age: args.max_age_seconds.map(Duration::from_secs),
                        max_count: args.max_count,
                        max_total_bytes: args.max_total_bytes,
                    },
                    allowed_untracked_paths: args.allow_untracked_paths,
                })?;
                print_worktree_sweep_report(&report, args.json)
            }
            WorktreeSubcommand::Lifecycle(args) => {
                let machine_global_retention = match (
                    args.machine_global_config,
                    args.machine_global_worktree_root_id,
                    args.machine_global_correlation,
                ) {
                    (Some(config), Some(root_id), Some(correction_correlation_id)) => {
                        Some(MachineGlobalRetentionBinding {
                            config,
                            root_id,
                            owner: "maco-worktree-lifecycle".to_string(),
                            correction_correlation_id,
                        })
                    }
                    (None, None, None) => None,
                    _ => bail!(
                        "--machine-global-config, --machine-global-worktree-root-id, and \
                         --machine-global-correlation must be supplied together"
                    ),
                };
                let mut options = if args.o2_launch_retention {
                    WorktreeLifecycleOptions::o2_launch_defaults()
                } else {
                    WorktreeLifecycleOptions::default()
                };
                options.apply = args.apply;
                options.auto_reap_merged = args.auto_reap_merged;
                options.merged_into_reference = args.trunk_ref;
                options.retry_successor_agent_id = args.retry_successor;
                options.startup_reconcile = args.startup_reconciliation;
                options.destructive_reconciliation = args.destructive_reconciliation;
                options.worktree_root = args.worktree_root;
                options.remove_targets = !args.keep_targets;
                options.allowed_untracked_paths = args.allow_untracked_paths;
                options.machine_global_retention = machine_global_retention;
                if let Some(max_age_seconds) = args.max_age_seconds {
                    options.worktree_retention.max_age = Some(Duration::from_secs(max_age_seconds));
                }
                if let Some(max_count) = args.max_count {
                    options.worktree_retention.max_count = Some(max_count);
                }
                if let Some(max_total_bytes) = args.max_total_bytes {
                    options.worktree_retention.max_total_bytes = Some(max_total_bytes);
                }
                if let Some(policy) = options.artifact_retention.as_mut() {
                    if let Some(keep) = args.artifact_keep {
                        policy.max_count = keep;
                    }
                    if let Some(max_age_seconds) = args.artifact_max_age_seconds {
                        policy.max_age = Some(Duration::from_secs(max_age_seconds));
                    }
                    if let Some(max_total_bytes) = args.artifact_max_total_bytes {
                        policy.max_total_bytes = Some(max_total_bytes);
                    }
                    if let Some(unfinalized_grace_seconds) = args.artifact_unfinalized_grace_seconds
                    {
                        policy.unfinalized_grace =
                            Some(Duration::from_secs(unfinalized_grace_seconds));
                    }
                    policy.reclaim_unverifiable = args.reclaim_unverifiable;
                    policy.external_writers_stopped = args.acknowledge_external_writers_stopped;
                }
                let report = WorktreeManager::new(args.repo).lifecycle(options)?;
                print_worktree_lifecycle_report(&report, args.json)
            }
            WorktreeSubcommand::Remove(args) => {
                let manager = WorktreeManager::new(args.repo);
                let record = manager.remove(&args.agent_id, args.force, args.delete_branch)?;
                print_worktree_record(&record, args.json)
            }
            WorktreeSubcommand::List(args) => {
                let manager = WorktreeManager::new(args.repo);
                let records = manager.list()?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&records)?);
                } else if records.is_empty() {
                    println!("No worktrees registered.");
                } else {
                    for record in records {
                        println!(
                            "{}\t{}\t{}",
                            record.name,
                            record.branch,
                            record.path.display()
                        );
                    }
                }
                Ok(())
            }
            WorktreeSubcommand::Pending(args) => {
                let manager = WorktreeManager::new(args.repo);
                let operations = manager.pending_operations()?;
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&operations)?);
                } else if operations.is_empty() {
                    println!("No pending worktree operations.");
                } else {
                    for operation in operations {
                        println!(
                            "{}\t{}\t{}\t{}\tforce={}",
                            operation.name,
                            operation.kind,
                            operation.phase,
                            operation.path.display(),
                            operation.force
                        );
                    }
                }
                Ok(())
            }
            WorktreeSubcommand::Diff(args) => {
                let claims = resolve_claims(&args.repo, &args.agent_id, args.claim)?;
                let candidate = merge::collect_agent_result(MergeCollectOptions {
                    repo: args.repo,
                    agent_id: args.agent_id,
                    claimed_paths: claims,
                    include_full_diff: args.full_diff,
                    diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                    validations: Vec::new(),
                })?;
                print_merge_candidate(&candidate, args.json)
            }
        }
    }
}

#[derive(Debug, Args)]
struct SyncCommand {
    #[command(subcommand)]
    command: SyncSubcommand,
}

impl SyncCommand {
    fn run(self) -> Result<()> {
        match self.command {
            SyncSubcommand::Claim(args) => {
                let store = SyncStore::open(args.repo)?;
                let configured_thresholds = args.thresholds.configured_thresholds();
                let timing = args.timing.timing()?.unwrap_or_default();
                let outcome = match configured_thresholds {
                    Some(thresholds) => store.claim_paths_with_telemetry_thresholds_and_timing(
                        &args.agent_id,
                        args.paths,
                        thresholds,
                        timing,
                    )?,
                    None => store.claim_paths_with_timing(&args.agent_id, args.paths, timing)?,
                };
                print_claim_telemetry_outcome(&outcome, args.json)
            }
            SyncSubcommand::Release(args) => {
                let store = SyncStore::open(args.repo)?;
                let released = store.release(ClaimToken::from_u64(args.token))?;
                print_path_claim("Released", &released, args.json)
            }
            SyncSubcommand::ReleaseAgent(args) => {
                let store = SyncStore::open(args.repo)?;
                let released = store.release_by_agent(&args.agent_id)?;
                print_claims(&released, args.json, "No claims released.")
            }
            SyncSubcommand::Owner(args) => {
                let store = SyncStore::open(args.repo)?;
                let report = store.owner_of(args.path)?;
                print_owner_report(&report, args.json)
            }
            SyncSubcommand::Status(args) => {
                let store = SyncStore::open(args.repo)?;
                let claims = store.status_snapshot()?;
                print_claim_statuses(&claims, args.json)
            }
            SyncSubcommand::Liveness(args) => {
                let store = SyncStore::open(args.repo)?;
                let claims = store.liveness_snapshot()?;
                print_claim_liveness(&claims, args.json)
            }
            SyncSubcommand::Heartbeat(args) => {
                let store = SyncStore::open(args.repo)?;
                let report = store.heartbeat(
                    ClaimToken::from_u64(args.token),
                    &args.agent_id,
                    args.timing.timing()?,
                )?;
                print_query_report(&report, args.json)
            }
            SyncSubcommand::Sweep(args) => {
                let store = SyncStore::open(args.repo)?;
                let report = store.sweep_stale()?;
                print_query_report(&report, args.json)
            }
            SyncSubcommand::Takeover(args) => {
                let store = SyncStore::open(args.repo)?;
                let report = store.takeover(
                    ClaimToken::from_u64(args.prior_token),
                    &args.agent_id,
                    args.timing.timing()?,
                )?;
                print_query_report(&report, args.json)
            }
            SyncSubcommand::History(args) => {
                let store = SyncStore::open(args.repo)?;
                let history = store.supersession_history()?;
                print_query_report(&history, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum SyncSubcommand {
    /// Record an exclusive claim for one or more repository-relative paths.
    Claim(ClaimSyncArgs),
    /// Release one claim by token.
    Release(ReleaseSyncArgs),
    /// Release every claim owned by an agent.
    ReleaseAgent(ReleaseAgentSyncArgs),
    /// Report the agent that currently owns a path.
    Owner(OwnerSyncArgs),
    /// List active path claims.
    Status(StatusSyncArgs),
    /// List bounded heartbeat and takeover state for active claims.
    Liveness(StatusSyncArgs),
    /// Refresh one exact-owner claim heartbeat.
    Heartbeat(HeartbeatSyncArgs),
    /// Mark stale claims takeover-eligible without releasing their paths.
    Sweep(SweepSyncArgs),
    /// Atomically replace one takeover-eligible claim with a successor.
    Takeover(TakeoverSyncArgs),
    /// List the bounded durable claim-supersession audit history.
    History(StatusSyncArgs),
}

#[derive(Debug, Args)]
struct ClaimSyncArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable agent id. Allowed characters: ASCII letters, digits, '.', '_' and '-'.
    agent_id: String,
    /// Repository-relative paths to claim.
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    #[command(flatten)]
    thresholds: MegafileThresholdArgs,
    #[command(flatten)]
    timing: ClaimTimingArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ReleaseSyncArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Claim token to release.
    token: u64,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ReleaseAgentSyncArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable agent id whose claims should be released.
    agent_id: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct OwnerSyncArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Repository-relative path to inspect.
    path: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusSyncArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args, Default)]
struct ClaimTimingArgs {
    /// Desired heartbeat interval in seconds. Must be paired with --stale-after-seconds.
    #[arg(long, requires = "stale_after_seconds")]
    heartbeat_interval_seconds: Option<u64>,
    /// Age in seconds at which a claim becomes stale. Must be paired with --heartbeat-interval-seconds.
    #[arg(long, requires = "heartbeat_interval_seconds")]
    stale_after_seconds: Option<u64>,
}

impl ClaimTimingArgs {
    fn timing(&self) -> Result<Option<ClaimTiming>> {
        match (self.heartbeat_interval_seconds, self.stale_after_seconds) {
            (None, None) => Ok(None),
            (Some(heartbeat), Some(stale)) => Ok(Some(ClaimTiming::new(heartbeat, stale)?)),
            _ => bail!("heartbeat interval and stale threshold must be configured together"),
        }
    }
}

#[derive(Debug, Args)]
struct HeartbeatSyncArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Active claim token to refresh.
    token: u64,
    /// Exact stable agent id recorded on the claim.
    agent_id: String,
    #[command(flatten)]
    timing: ClaimTimingArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SweepSyncArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct TakeoverSyncArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Exact active predecessor token observed as takeover-eligible.
    prior_token: u64,
    /// Stable agent id for the successor claim.
    agent_id: String,
    #[command(flatten)]
    timing: ClaimTimingArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MachineGlobalCommand {
    #[command(subcommand)]
    command: MachineGlobalSubcommand,
}

impl MachineGlobalCommand {
    fn run(self) -> Result<()> {
        match self.command {
            MachineGlobalSubcommand::Claim(args) => {
                let store = MachineGlobalStore::open_config(&args.config)?;
                let targets = machine_global_declared_coordinates(&args.root_id, args.paths)?;
                let outcome = store.claim(&args.owner, &args.correlation, targets)?;
                print_machine_global_gate_outcome(outcome, args.json)
            }
            MachineGlobalSubcommand::Release(args) => {
                let store = MachineGlobalStore::open_config(&args.config)?;
                let released = store.release(&args.owner, args.token.clone())?;
                print_query_report(
                    &MachineGlobalReleaseReport {
                        owner: &args.owner,
                        released,
                    },
                    args.json,
                )
            }
            MachineGlobalSubcommand::Owner(args) => {
                let store = MachineGlobalStore::open_config(&args.config)?;
                let target = DeclaredPathCoordinate::new(&args.root_id, &args.path)
                    .context("invalid machine-global owner coordinate")?;
                let claims = store.owner(&target)?;
                print_query_report(&MachineGlobalOwnerReport { target, claims }, args.json)
            }
            MachineGlobalSubcommand::Status(args) => {
                let store = MachineGlobalStore::open_config(&args.config)?;
                print_query_report(&store.status()?, args.json)
            }
            MachineGlobalSubcommand::Retention(command) => command.run(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum MachineGlobalSubcommand {
    /// Claim one or more paths beneath one configured machine-global root.
    Claim(MachineGlobalClaimArgs),
    /// Release one machine-global claim by token.
    Release(MachineGlobalReleaseArgs),
    /// Report claims intersecting one configured machine-global path.
    Owner(MachineGlobalOwnerArgs),
    /// List privacy-safe machine-global claims and retention operations.
    Status(MachineGlobalStatusArgs),
    /// Quarantine, restore, or purge declared external directories.
    Retention(MachineGlobalRetentionCommand),
}

#[derive(Debug, Args)]
struct MachineGlobalClaimArgs {
    /// Stable owner id. Allowed characters: ASCII letters, digits, '.', '_' and '-'.
    owner: String,
    /// Reviewed root id from the explicit machine-global JSON config.
    #[arg(long)]
    root_id: String,
    /// Root-relative paths to claim. Absolute and non-canonical paths are rejected.
    #[arg(long = "path", required = true)]
    paths: Vec<PathBuf>,
    /// Identity of the correction lifecycle that will consume a typed denial.
    #[arg(long)]
    correlation: String,
    /// Exact canonical path to the bounded, no-follow machine-global JSON config.
    #[arg(long)]
    config: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MachineGlobalReleaseArgs {
    /// Stable owner id recorded by the claim.
    owner: String,
    /// Claim token to release.
    token: MachineGlobalClaimToken,
    /// Exact canonical path to the bounded, no-follow machine-global JSON config.
    #[arg(long)]
    config: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MachineGlobalOwnerArgs {
    /// Reviewed root id from the explicit machine-global JSON config.
    #[arg(long)]
    root_id: String,
    /// Root-relative path to inspect.
    #[arg(long)]
    path: PathBuf,
    /// Exact canonical path to the bounded, no-follow machine-global JSON config.
    #[arg(long)]
    config: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MachineGlobalStatusArgs {
    /// Exact canonical path to the bounded, no-follow machine-global JSON config.
    #[arg(long)]
    config: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MachineGlobalRetentionCommand {
    #[command(subcommand)]
    command: MachineGlobalRetentionSubcommand,
}

impl MachineGlobalRetentionCommand {
    fn run(self) -> Result<()> {
        match self.command {
            MachineGlobalRetentionSubcommand::Quarantine(args) => {
                let store = MachineGlobalStore::open_config(&args.config)?;
                let targets = machine_global_destructive_targets(&args.root_id, args.paths)?;
                let outcome = store.quarantine(&args.owner, &args.correlation, targets)?;
                print_machine_global_gate_outcome(outcome, args.json)
            }
            MachineGlobalRetentionSubcommand::Restore(args) => {
                let store = MachineGlobalStore::open_config(&args.config)?;
                let outcome = store.restore(&args.owner, &args.correlation, args.operation_id)?;
                print_machine_global_gate_outcome(outcome, args.json)
            }
            MachineGlobalRetentionSubcommand::Purge(args) => {
                let store = MachineGlobalStore::open_config(&args.config)?;
                let outcome = store.purge(
                    &args.owner,
                    &args.correlation,
                    args.operation_id,
                    &args.token,
                )?;
                print_machine_global_gate_outcome(outcome, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum MachineGlobalRetentionSubcommand {
    /// Atomically quarantine declared directories after a full target-set gate.
    Quarantine(MachineGlobalQuarantineArgs),
    /// Restore a quarantined operation before permanent purge.
    Restore(MachineGlobalRestoreArgs),
    /// Permanently remove a quarantined operation after its configured grace period.
    Purge(MachineGlobalPurgeArgs),
}

#[derive(Debug, Args)]
struct MachineGlobalQuarantineArgs {
    /// Stable destructive-operation owner id.
    owner: String,
    /// Reviewed root id from the explicit machine-global JSON config.
    #[arg(long)]
    root_id: String,
    /// Complete root-relative target set. Absolute values are refused through GateDenial.
    #[arg(long = "path", required = true)]
    paths: Vec<PathBuf>,
    /// Identity of the correction lifecycle that will consume a typed denial.
    #[arg(long)]
    correlation: String,
    /// Exact canonical path to the bounded, no-follow machine-global JSON config.
    #[arg(long)]
    config: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MachineGlobalRestoreArgs {
    /// Stable destructive-operation owner id.
    owner: String,
    /// Retention operation to restore.
    operation_id: RetentionOperationId,
    /// Identity of the correction lifecycle that will consume a typed denial.
    #[arg(long)]
    correlation: String,
    /// Exact canonical path to the bounded, no-follow machine-global JSON config.
    #[arg(long)]
    config: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MachineGlobalPurgeArgs {
    /// Stable destructive-operation owner id.
    owner: String,
    /// Retention operation to purge.
    operation_id: RetentionOperationId,
    /// Secret bearer capability returned by the quarantine operation.
    #[arg(long)]
    token: RetentionOperationToken,
    /// Identity of the correction lifecycle that will consume a typed denial.
    #[arg(long)]
    correlation: String,
    /// Exact canonical path to the bounded, no-follow machine-global JSON config.
    #[arg(long)]
    config: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct MachineGlobalReleaseReport<'a> {
    owner: &'a str,
    released: bool,
}

#[derive(Debug, Serialize)]
struct MachineGlobalOwnerReport {
    target: DeclaredPathCoordinate,
    claims: Vec<MachineGlobalClaimSummary>,
}

fn machine_global_declared_coordinates(
    root_id: &str,
    paths: Vec<PathBuf>,
) -> Result<Vec<DeclaredPathCoordinate>> {
    paths
        .into_iter()
        .map(|path| {
            DeclaredPathCoordinate::new(root_id, &path).with_context(|| {
                format!(
                    "invalid machine-global coordinate {root_id}:{}",
                    path.display()
                )
            })
        })
        .collect()
}

fn machine_global_destructive_targets(
    root_id: &str,
    paths: Vec<PathBuf>,
) -> Result<Vec<DestructiveTargetInput>> {
    paths
        .into_iter()
        .map(|path| {
            if path.is_absolute() {
                Ok(DestructiveTargetInput::UndeclaredAbsolute(path))
            } else {
                DeclaredPathCoordinate::new(root_id, &path)
                    .map(DestructiveTargetInput::Declared)
                    .with_context(|| {
                        format!(
                            "invalid machine-global destructive target {root_id}:{}",
                            path.display()
                        )
                    })
            }
        })
        .collect()
}

fn print_machine_global_gate_outcome<T>(outcome: GateOutcome<T>, json: bool) -> Result<()>
where
    T: Serialize + std::fmt::Debug,
{
    match outcome {
        GateOutcome::Allowed(value) => print_query_report(&value, json),
        GateOutcome::Denied(denial) => {
            print_query_report(&denial, json)?;
            bail!("machine-global operation denied")
        }
    }
}

#[derive(Debug, Args)]
struct LiveCommand {
    #[command(subcommand)]
    command: LiveSubcommand,
}

impl LiveCommand {
    fn run(self) -> Result<()> {
        match self.command {
            LiveSubcommand::Status(args) => {
                let now = live_clock(args.now.as_deref())?;
                let report = live_claim::status(args.repo, &now)?;
                print_query_report(&report, args.json)
            }
            LiveSubcommand::Validate(args) => {
                let now = live_clock(args.now.as_deref())?;
                let report = live_claim::validate(args.repo, &now)?;
                print_query_report(&report, args.json)
            }
            LiveSubcommand::Apply(args) => {
                let report = live_claim::apply(args.repo, args.draft, &args.by)?;
                print_query_report(&report, args.json)
            }
            LiveSubcommand::Heartbeat(args) => {
                let report = live_claim::heartbeat(args.repo, &args.claim_id, &args.by)?;
                print_query_report(&report, args.json)
            }
            LiveSubcommand::OverrideRelease(args) => {
                let report = live_claim::override_release(
                    args.repo,
                    &args.claim_id,
                    &args.by,
                    &args.reason,
                )?;
                print_query_report(&report, args.json)
            }
            LiveSubcommand::Release(args) => {
                let report = live_claim::release(
                    args.repo,
                    &args.claim_id,
                    &args.by,
                    &args.status,
                    &args.reason,
                )?;
                print_query_report(&report, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum LiveSubcommand {
    /// List live claims and liveness state.
    Status(LiveStatusArgs),
    /// Validate live claim file fields.
    Validate(LiveValidateArgs),
    /// Atomically create a new claim from a fresh external Markdown draft.
    Apply(LiveApplyArgs),
    /// Refresh a claim heartbeat timestamp.
    Heartbeat(LiveHeartbeatArgs),
    /// Move a stale active claim to handoff by explicit override.
    OverrideRelease(LiveOverrideReleaseArgs),
    /// Let the exact owner release a claim as done or handoff.
    Release(LiveReleaseArgs),
}

#[derive(Debug, Args)]
struct LiveStatusArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Deterministic current timestamp for tests.
    #[arg(long)]
    now: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LiveValidateArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Deterministic current timestamp for tests.
    #[arg(long)]
    now: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LiveApplyArgs {
    /// Bounded no-follow Markdown draft outside the live claim board.
    draft: PathBuf,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Exact claim owner applying the draft.
    #[arg(long)]
    by: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LiveHeartbeatArgs {
    /// Claim id to refresh.
    claim_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Actor refreshing the claim.
    #[arg(long)]
    by: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LiveOverrideReleaseArgs {
    /// Claim id to move to handoff.
    claim_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Actor performing the override.
    #[arg(long)]
    by: String,
    /// Reason recorded in the audit log.
    #[arg(long)]
    reason: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LiveReleaseArgs {
    /// Claim id to release.
    claim_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Exact recorded owner releasing the claim.
    #[arg(long)]
    by: String,
    /// Terminal release status.
    #[arg(long, default_value = "done", value_parser = ["done", "handoff"])]
    status: String,
    /// Reason recorded in the bounded audit log.
    #[arg(long)]
    reason: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CoordCommand {
    #[command(subcommand)]
    command: CoordSubcommand,
}

impl CoordCommand {
    fn run(self) -> Result<()> {
        match self.command {
            CoordSubcommand::Preview(args) => {
                let json = args.json;
                let store = SemanticIntentStore::open(&args.repo)?;
                let report = store.preview(args.into_request())?;
                print_semantic_coordination_report(&report, json)
            }
            CoordSubcommand::Claim(args) => {
                let json = args.json;
                let store = SemanticIntentStore::open(&args.repo)?;
                let report = store.claim(args.into_request())?;
                print_semantic_coordination_report(&report, json)?;
                if report.has_blocking_conflicts {
                    bail!(
                        "semantic claim refused with {} blocking conflict(s)",
                        report.blocking_conflict_count
                    );
                }
                Ok(())
            }
            CoordSubcommand::Release(args) => {
                let store = SemanticIntentStore::open(args.repo)?;
                let released = store.release(SemanticIntentToken::from_u64(args.token))?;
                print_query_report(&released, args.json)
            }
            CoordSubcommand::ReleaseAgent(args) => {
                let store = SemanticIntentStore::open(args.repo)?;
                let released = store.release_by_agent(&args.agent_id)?;
                print_query_report(&released, args.json)
            }
            CoordSubcommand::Status(args) => {
                let store = SemanticIntentStore::open(args.repo)?;
                let intents = store.status()?;
                print_query_report(&intents, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum CoordSubcommand {
    /// Preview semantic conflicts without persisting an intent.
    Preview(CoordIntentArgs),
    /// Claim a semantic intent if it has no blocking conflicts.
    Claim(CoordIntentArgs),
    /// Release one semantic intent by token.
    Release(ReleaseCoordArgs),
    /// Release every semantic intent owned by an agent.
    ReleaseAgent(ReleaseAgentCoordArgs),
    /// List active semantic intents.
    Status(StatusCoordArgs),
}

#[derive(Debug, Args)]
struct CoordIntentArgs {
    /// Stable agent id. Allowed characters: ASCII letters, digits, '.', '_' and '-'.
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Repository-relative path included in the semantic intent.
    #[arg(long = "path")]
    paths: Vec<PathBuf>,
    /// Rust symbol name, qualified path, or symbol id. Repeat for multiple symbols.
    #[arg(long = "symbol")]
    symbols: Vec<String>,
    /// Rust module path. Repeat for multiple modules.
    #[arg(long = "module")]
    modules: Vec<String>,
    /// Repository-relative task file summarized with the intent.
    #[arg(long = "task")]
    task_file: Option<PathBuf>,
    /// Note attached to the intent. Repeat for multiple notes.
    #[arg(long = "note")]
    notes: Vec<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

impl CoordIntentArgs {
    fn into_request(self) -> SemanticIntentRequest {
        SemanticIntentRequest {
            agent_id: self.agent_id,
            paths: self.paths,
            symbols: self.symbols,
            modules: self.modules,
            task_file: self.task_file,
            notes: self.notes,
        }
    }
}

#[derive(Debug, Args)]
struct ReleaseCoordArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Semantic intent token to release.
    token: u64,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ReleaseAgentCoordArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable agent id whose semantic intents should be released.
    agent_id: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct StatusCoordArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LlmCommand {
    #[command(subcommand)]
    command: LlmSubcommand,
}

impl LlmCommand {
    fn run(self) -> Result<()> {
        match self.command {
            LlmSubcommand::Providers(args) => {
                let providers = LlmProvidersReport {
                    providers: vec![LlmProviderInfo {
                        id: "fake".to_string(),
                        model: "deterministic-fake".to_string(),
                        kind: "local_fake".to_string(),
                        configured: true,
                        network_required: false,
                        notes:
                            "Deterministic test provider for prompt preview and agent run; no credentials or network required."
                                .to_string(),
                        capabilities: ProviderCapabilities::local_fake(),
                    }],
                    network_providers_required: false,
                    network_providers_configured: false,
                };
                print_query_report(&providers, args.json)
            }
            LlmSubcommand::PromptPreview(args) => {
                let json = args.json;
                let report = build_prompt_preview(args)?;
                print_query_report(&report, json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum LlmSubcommand {
    /// List configured provider boundaries without making network calls.
    Providers(LlmProvidersArgs),
    /// Render a provider-neutral prompt preview without calling a provider.
    PromptPreview(LlmPromptPreviewArgs),
}

#[derive(Debug, Args)]
struct LlmProvidersArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LlmPromptPreviewArgs {
    /// Task file to render into the prompt.
    task_file: PathBuf,
    /// Stable agent id for the prompt context.
    #[arg(long)]
    agent_id: String,
    /// Repository-relative path to include as a claimed path and excerpt.
    #[arg(long = "path", required = true)]
    paths: Vec<PathBuf>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct EvaluationCommand {
    #[command(subcommand)]
    command: EvaluationSubcommand,
}

impl EvaluationCommand {
    fn run(self) -> Result<()> {
        match self.command {
            EvaluationSubcommand::Run(args) => run_evaluation_command(args),
            EvaluationSubcommand::Rescore(args) => run_evaluation_rescore_command(
                args.manifest,
                args.results,
                match args.family {
                    RescoreResultsFamily::Evaluation => StoredEvaluationResultsFamily::Evaluation,
                    RescoreResultsFamily::Experiment => StoredEvaluationResultsFamily::Experiment,
                },
                args.objective_profile,
                args.repo,
                args.json,
            ),
            EvaluationSubcommand::Experiment(args) => run_evaluation_experiment_command(args),
        }
    }
}

#[derive(Debug, Subcommand)]
enum EvaluationSubcommand {
    /// Generate deterministic fixture output for every manifest profile and repetition.
    Run(RunEvaluationArgs),
    /// Re-score validated stored results under a different named objective profile.
    Rescore(RescoreEvaluationArgs),
    /// Run the same goal/spec under multiple profiles through isolated Fake supervise.
    Experiment(RunExperimentArgs),
}

#[derive(Debug, Args)]
struct RunEvaluationArgs {
    /// Versioned evaluation manifest JSON.
    manifest: PathBuf,
    /// Hand-authored plan whose exact bytes are bound by the manifest.
    #[arg(long)]
    plan_file: PathBuf,
    /// Reserved source-repository path; unused by the current synthetic fixture runner.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Requested mode; the current runner supports deterministic-fake and refuses real-provider.
    #[arg(
        long,
        default_value = "deterministic-fake",
        value_parser = parse_evaluation_execution
    )]
    execution: crate::evaluation::EvaluationExecution,
    /// Acknowledge future real-provider execution; the current runner still refuses it.
    #[arg(long)]
    allow_real_provider: bool,
    /// Stable seed for deterministic fake evaluation fixtures.
    #[arg(
        long,
        default_value_t = crate::evaluation::COMMITTED_FIXTURE_FAKE_SEED
    )]
    fake_seed: u64,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RescoreResultsFamily {
    /// Stored `EvaluationResults` schema v4 plus an `EvaluationManifest`.
    Evaluation,
    /// Stored `ExperimentResults` schema v2 plus an `ExperimentManifest`.
    Experiment,
}

#[derive(Debug, Args)]
struct RescoreEvaluationArgs {
    /// Versioned manifest matching the selected stored-result family.
    #[arg(value_name = "MANIFEST")]
    manifest: PathBuf,
    /// Validated stored evaluation results to re-score; the input is never overwritten.
    #[arg(long, value_name = "RESULTS")]
    results: PathBuf,
    /// Strict stored-result and manifest schema family.
    #[arg(long, value_enum)]
    family: RescoreResultsFamily,
    /// Named objective profile resolved from the repository override or built-ins.
    #[arg(long, value_name = "NAME")]
    objective_profile: String,
    /// Repository path used only to resolve the named objective profile.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RunExperimentArgs {
    /// Versioned experiment manifest binding goal/spec, profiles, and repetitions.
    manifest: PathBuf,
    /// Reserved source-repository path; unused because each profile uses isolated Fake state.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Requested mode; this command supports deterministic-fake and refuses real-provider.
    #[arg(
        long,
        default_value = "deterministic-fake",
        value_parser = parse_evaluation_execution
    )]
    execution: crate::evaluation::EvaluationExecution,
    /// Acknowledge future real-provider execution; the current runner still refuses it.
    #[arg(long)]
    allow_real_provider: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn run_evaluation_experiment_command(args: RunExperimentArgs) -> Result<()> {
    let manifest_bytes =
        BoundedRegularReader::read_tree_no_follow(&args.manifest, MAX_EVALUATION_MANIFEST_BYTES)
            .with_context(|| {
                format!(
                    "failed to read evaluation experiment manifest {}",
                    args.manifest.display()
                )
            })?;
    let manifest =
        crate::evaluation::parse_experiment_manifest(&manifest_bytes).with_context(|| {
            format!(
                "failed to parse evaluation experiment manifest {}",
                args.manifest.display()
            )
        })?;
    let _repo = args.repo;
    let results = crate::evaluation::run_fake_supervise_experiment(
        &manifest,
        crate::evaluation::ExperimentRunRequest {
            execution: args.execution,
            allow_real_provider: args.allow_real_provider,
        },
    )?;
    print_query_report(&results, args.json)
}

#[derive(Debug, Args)]
struct EvalHarnessCommand {
    #[command(subcommand)]
    command: EvalHarnessSubcommand,
}

impl EvalHarnessCommand {
    fn run(self) -> Result<()> {
        match self.command {
            EvalHarnessSubcommand::Run(args) => run_eval_harness_command(args),
            EvalHarnessSubcommand::RunV2(args) => run_eval_harness_v2_from_args(args),
        }
    }
}

#[derive(Debug, Subcommand)]
enum EvalHarnessSubcommand {
    /// Complete each role in a mix through the local fake provider and record outcomes.
    ///
    /// Version 1 manifests run the v1 local-fake path. Version 2 manifests are
    /// routed to the #26 v2 operator path.
    Run(RunEvalHarnessArgs),
    /// Run the #26 eval-harness v2 local-fake operator path with machine-readable output.
    #[command(name = "run-v2")]
    RunV2(RunEvalHarnessArgs),
}

#[derive(Debug, Args)]
struct RunEvalHarnessArgs {
    /// Versioned eval-harness manifest JSON.
    manifest: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Deserialize)]
struct EvalHarnessManifestVersionProbe {
    version: u32,
}

fn eval_harness_manifest_version(bytes: &[u8]) -> Result<u32> {
    let probe = serde_json::from_slice::<EvalHarnessManifestVersionProbe>(bytes)
        .context("failed to parse eval harness manifest version")?;
    Ok(probe.version)
}

fn run_eval_harness_command(args: RunEvalHarnessArgs) -> Result<()> {
    let manifest_bytes = BoundedRegularReader::read_tree_no_follow(
        &args.manifest,
        crate::eval_harness::MAX_MANIFEST_BYTES,
    )
    .with_context(|| {
        format!(
            "failed to read eval harness manifest {}",
            args.manifest.display()
        )
    })?;
    match eval_harness_manifest_version(&manifest_bytes)? {
        crate::eval_harness::EVAL_HARNESS_MANIFEST_VERSION => {
            let manifest =
                crate::eval_harness::parse_manifest(&manifest_bytes).with_context(|| {
                    format!(
                        "failed to parse eval harness manifest {}",
                        args.manifest.display()
                    )
                })?;
            let results = crate::eval_harness::run_local_fake_harness(&manifest)?;
            print_query_report(&results, args.json)
        }
        crate::eval_harness::EVAL_HARNESS_MANIFEST_V2_VERSION => {
            run_eval_harness_v2_command(&args.manifest, &manifest_bytes, args.json)
        }
        found => bail!(
            "unsupported eval harness manifest version {found}; supported versions are {} and {}",
            crate::eval_harness::EVAL_HARNESS_MANIFEST_VERSION,
            crate::eval_harness::EVAL_HARNESS_MANIFEST_V2_VERSION
        ),
    }
}

fn run_eval_harness_v2_from_args(args: RunEvalHarnessArgs) -> Result<()> {
    let manifest_bytes = BoundedRegularReader::read_tree_no_follow(
        &args.manifest,
        crate::eval_harness::MAX_MANIFEST_BYTES,
    )
    .with_context(|| {
        format!(
            "failed to read eval harness v2 manifest {}",
            args.manifest.display()
        )
    })?;
    run_eval_harness_v2_command(&args.manifest, &manifest_bytes, args.json)
}

fn run_eval_harness_v2_command(path: &Path, manifest_bytes: &[u8], json: bool) -> Result<()> {
    let manifest = crate::eval_harness::parse_manifest_v2(manifest_bytes).with_context(|| {
        format!(
            "failed to parse eval harness v2 manifest {}",
            path.display()
        )
    })?;
    let results = execute_eval_harness_v2_operator_path(&manifest)?;
    print_query_report(&results, json)
}

/// Route the #26 v2 operator path through the comparable local-fake executor.
fn execute_eval_harness_v2_operator_path(
    manifest: &crate::eval_harness::EvalHarnessManifestV2,
) -> Result<Value> {
    let results =
        crate::eval_harness::execute_v2_local_fake(manifest).map_err(anyhow::Error::from)?;
    serde_json::to_value(results).context("failed to serialize eval-harness v2 result")
}

include!("cli/part2.rs");

#[cfg(test)]
mod cli_integration_tests {
    use super::*;

    fn inbox_run_args(argv: &[&str]) -> RunInboxArgs {
        let parsed = Cli::try_parse_from(argv).expect("inbox run arguments should parse");
        let Command::Inbox(InboxCommand {
            command: InboxSubcommand::Run(args),
        }) = parsed.command
        else {
            panic!("expected inbox run command");
        };
        args
    }

    fn rescore_args(argv: &[&str]) -> RescoreEvaluationArgs {
        let parsed = Cli::try_parse_from(argv).expect("evaluation rescore arguments should parse");
        let Command::Evaluation(EvaluationCommand {
            command: EvaluationSubcommand::Rescore(args),
        }) = parsed.command
        else {
            panic!("expected evaluation rescore command");
        };
        args
    }

    #[test]
    fn inbox_run_rolling_quota_maps_default_and_explicit_windows() {
        let default_window = inbox_run_args(&[
            "maco",
            "inbox",
            "run",
            "--max-rolling-tokens",
            "42000",
            "--max-rolling-cost-usd",
            "12.5",
        ]);
        assert_eq!(
            default_window.rolling_budget.quota(),
            Some(inbox::InboxRollingBudgetQuota {
                max_tokens: Some(42_000),
                max_cost_usd: Some(12.5),
                window_seconds: inbox::DEFAULT_ROLLING_WINDOW_SECONDS,
            })
        );

        let explicit_window = inbox_run_args(&[
            "maco",
            "inbox",
            "run",
            "--max-rolling-cost-usd",
            "2.75",
            "--rolling-window-seconds",
            "3600",
        ]);
        assert_eq!(
            explicit_window.rolling_budget.quota(),
            Some(inbox::InboxRollingBudgetQuota {
                max_tokens: None,
                max_cost_usd: Some(2.75),
                window_seconds: 3_600,
            })
        );

        let window_only =
            inbox_run_args(&["maco", "inbox", "run", "--rolling-window-seconds", "3600"]);
        assert_eq!(window_only.rolling_budget.quota(), None);
    }

    #[test]
    fn inbox_run_rolling_quota_rejects_invalid_and_supervise_only_flags() {
        for argv in [
            vec!["maco", "inbox", "run", "--max-rolling-tokens", "0"],
            vec!["maco", "inbox", "run", "--max-rolling-cost-usd", "NaN"],
            vec!["maco", "inbox", "run", "--rolling-window-seconds", "0"],
            vec!["maco", "inbox", "run", "--max-tokens", "100"],
            vec!["maco", "inbox", "run", "--max-cost-usd", "1.0"],
            vec!["maco", "inbox", "run", "--max-duration-seconds", "60"],
        ] {
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "invalid or unrelated inbox budget flag must be rejected"
            );
        }
    }

    #[test]
    fn evaluation_rescore_parses_both_strict_result_families() {
        let evaluation = rescore_args(&[
            "maco",
            "evaluation",
            "rescore",
            "manifest.json",
            "--results",
            "results.json",
            "--family",
            "evaluation",
            "--objective-profile",
            "balanced-v1",
            "--repo",
            "repo",
            "--json",
        ]);
        assert_eq!(evaluation.manifest, PathBuf::from("manifest.json"));
        assert_eq!(evaluation.results, PathBuf::from("results.json"));
        assert_eq!(evaluation.family, RescoreResultsFamily::Evaluation);
        assert_eq!(evaluation.objective_profile, "balanced-v1");
        assert_eq!(evaluation.repo, PathBuf::from("repo"));
        assert!(evaluation.json);

        let experiment = rescore_args(&[
            "maco",
            "evaluation",
            "rescore",
            "experiment-manifest.json",
            "--results",
            "experiment-results.json",
            "--family",
            "experiment",
            "--objective-profile",
            "quality-first-v1",
        ]);
        assert_eq!(experiment.family, RescoreResultsFamily::Experiment);
        assert_eq!(experiment.repo, PathBuf::from("."));
        assert!(!experiment.json);
    }

    #[test]
    fn supervisor_plan_error_envelope_keeps_error_chain() {
        let error = anyhow::anyhow!("bounded-status rejects Git object alternates")
            .context("repository inventory failed");
        let envelope = supervise::supervisor_plan_error_envelope(&error);
        assert!(!envelope.success);
        assert_eq!(envelope.status, "error");
        assert!(envelope.error.contains("repository inventory failed"));
        assert!(envelope
            .causes
            .iter()
            .any(|cause| cause.contains("bounded-status rejects Git object alternates")));
        let value = serde_json::to_value(&envelope).expect("serialize envelope");
        assert_eq!(value["success"], false);
        assert_eq!(value["status"], "error");
        assert!(value["error"].as_str().is_some());
        assert!(value["causes"]
            .as_array()
            .is_some_and(|causes| !causes.is_empty()));
    }

    #[test]
    fn evaluation_rescore_requires_results_family_and_objective_profile() {
        for argv in [
            vec![
                "maco",
                "evaluation",
                "rescore",
                "manifest.json",
                "--family",
                "evaluation",
                "--objective-profile",
                "balanced-v1",
            ],
            vec![
                "maco",
                "evaluation",
                "rescore",
                "manifest.json",
                "--results",
                "results.json",
                "--objective-profile",
                "balanced-v1",
            ],
            vec![
                "maco",
                "evaluation",
                "rescore",
                "manifest.json",
                "--results",
                "results.json",
                "--family",
                "evaluation",
            ],
            vec![
                "maco",
                "evaluation",
                "rescore",
                "manifest.json",
                "--results",
                "results.json",
                "--family",
                "unknown",
                "--objective-profile",
                "balanced-v1",
            ],
        ] {
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "missing or invalid rescore arguments must be rejected"
            );
        }
    }

    fn supervise_run_args(argv: &[&str]) -> RunSuperviseArgs {
        let parsed = Cli::try_parse_from(argv).expect("supervise run arguments should parse");
        let Command::Supervise(SuperviseCommand {
            command: SuperviseSubcommand::Run(args),
        }) = parsed.command
        else {
            panic!("expected supervise run command");
        };
        args
    }

    fn autopilot_run_args(argv: &[&str]) -> Box<RunAutopilotArgs> {
        let parsed = Cli::try_parse_from(argv).expect("autopilot run arguments should parse");
        let Command::Autopilot(AutopilotCommand {
            command: AutopilotSubcommand::Run(args),
        }) = parsed.command
        else {
            panic!("expected autopilot run command");
        };
        args
    }

    const LAUNCH_RETENTION: [&str; 4] = [
        "--machine-global-config",
        "/tmp/maco-machine-global.json",
        "--machine-global-runtime-root-id",
        "runtime",
    ];

    #[test]
    fn supervise_and_autopilot_role_category_override_defaults_to_automatic() {
        let supervise = supervise_run_args(&[
            "maco",
            "supervise",
            "run",
            "plan.json",
            LAUNCH_RETENTION[0],
            LAUNCH_RETENTION[1],
            LAUNCH_RETENTION[2],
            LAUNCH_RETENTION[3],
        ]);
        assert_eq!(supervise.role_category_override.role_category, None);

        let autopilot = autopilot_run_args(&[
            "maco",
            "autopilot",
            "run",
            "plan.json",
            LAUNCH_RETENTION[0],
            LAUNCH_RETENTION[1],
            LAUNCH_RETENTION[2],
            LAUNCH_RETENTION[3],
        ]);
        assert_eq!(autopilot.role_category_override.role_category, None);
    }

    #[test]
    fn supervise_and_autopilot_role_category_override_parses_operator_values() {
        let supervise = supervise_run_args(&[
            "maco",
            "supervise",
            "run",
            "plan.json",
            "--role-category",
            "read_only_researcher",
            LAUNCH_RETENTION[0],
            LAUNCH_RETENTION[1],
            LAUNCH_RETENTION[2],
            LAUNCH_RETENTION[3],
        ]);
        assert_eq!(
            supervise.role_category_override.role_category,
            Some(OperatorRoleCategory::ReadOnlyResearcher)
        );

        let autopilot = autopilot_run_args(&[
            "maco",
            "autopilot",
            "run",
            "plan.json",
            "--role-category",
            "non-delegating-terminal-worker",
            LAUNCH_RETENTION[0],
            LAUNCH_RETENTION[1],
            LAUNCH_RETENTION[2],
            LAUNCH_RETENTION[3],
        ]);
        assert_eq!(
            autopilot.role_category_override.role_category,
            Some(OperatorRoleCategory::NonDelegatingTerminalWorker)
        );
    }

    #[test]
    fn supervise_and_autopilot_reject_unknown_role_category() {
        for command in ["supervise", "autopilot"] {
            let argv = [
                "maco",
                command,
                "run",
                "plan.json",
                "--role-category",
                "weak_model",
                LAUNCH_RETENTION[0],
                LAUNCH_RETENTION[1],
                LAUNCH_RETENTION[2],
                LAUNCH_RETENTION[3],
            ];
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "{command} must reject an unknown role category"
            );
        }
    }

    #[test]
    fn operator_role_category_stamp_records_operator_override_and_keeps_automatic_default() {
        let mut plan = serde_json::json!({
            "assignments": [
                {
                    "id": "child-1",
                    "role": "child_orchestrator",
                    "worker_assignments": [
                        {"id": "worker-1", "role": "worker"}
                    ]
                }
            ]
        });
        stamp_operator_role_category_override(
            &mut plan,
            OperatorRoleCategory::ReadOnlyReviewAuditor,
        )
        .expect("stamp override");

        assert_eq!(
            plan["assignments"][0]["role_category"],
            "read_only_review_auditor"
        );
        assert_eq!(
            plan["assignments"][0]["selection_source"],
            OPERATOR_OVERRIDE_SELECTION_SOURCE
        );
        assert_eq!(
            plan["assignments"][0]["worker_assignments"][0]["role_category"],
            "read_only_review_auditor"
        );
        assert_eq!(
            plan["assignments"][0]["worker_assignments"][0]["selection_source"],
            "operator_override"
        );
        assert_eq!(
            serde_json::to_value(supervise::AssignmentSelectionSource::OperatorOverride)
                .expect("serialize selection source"),
            "operator_override"
        );
        assert_eq!(
            serde_json::to_value(supervise::AssignmentSelectionSource::Automatic)
                .expect("serialize automatic source"),
            "automatic"
        );
    }

    fn eval_harness_run_args(argv: &[&str]) -> RunEvalHarnessArgs {
        let parsed = Cli::try_parse_from(argv).expect("eval-harness arguments should parse");
        match parsed.command {
            Command::EvalHarness(EvalHarnessCommand {
                command: EvalHarnessSubcommand::Run(args) | EvalHarnessSubcommand::RunV2(args),
            }) => args,
            _ => panic!("expected eval-harness run command"),
        }
    }

    #[test]
    fn eval_harness_run_v2_subcommand_parses_manifest_and_json_flag() {
        let run = eval_harness_run_args(&[
            "maco",
            "eval-harness",
            "run-v2",
            "tests/fixtures/eval_harness/manifest-v2.json",
            "--json",
        ]);
        assert_eq!(
            run.manifest,
            PathBuf::from("tests/fixtures/eval_harness/manifest-v2.json")
        );
        assert!(run.json);

        let auto = eval_harness_run_args(&[
            "maco",
            "eval-harness",
            "run",
            "tests/fixtures/eval_harness/manifest-v2.json",
        ]);
        assert!(!auto.json);
    }

    #[test]
    fn eval_harness_v2_version_probe_distinguishes_v1_and_v2() {
        assert_eq!(
            eval_harness_manifest_version(br#"{"version":1,"experiment_id":"x"}"#).expect("v1"),
            1
        );
        assert_eq!(
            eval_harness_manifest_version(br#"{"version":2,"experiment_id":"x"}"#).expect("v2"),
            2
        );
        assert!(eval_harness_manifest_version(br#"{"experiment_id":"x"}"#).is_err());
    }
}

#[cfg(test)]
mod tests;
