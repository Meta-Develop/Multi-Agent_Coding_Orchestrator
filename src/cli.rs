use crate::{
    agent::{
        self, AgentRunOptions, AgentRunReport, AgentValidationCommand, AgentWorktreeReusePolicy,
        ProviderCommandPolicy,
    },
    agent_lifecycle::{AgentListFilter, AgentProcessRecord, AgentRegistry, AgentStopReport},
    artifacts::{
        self, ArtifactRetentionFamily, ArtifactRetentionPolicy, ResolvedRunId, RunArtifactFamily,
    },
    autopilot::{self, AutopilotRunOptions},
    consult::{self, ConsultAskOptions, ConsultantRuntime, DEFAULT_CONSULT_TIMEOUT_SECONDS},
    inbox::{self, InboxPermissionMode, InboxScanOptions, InboxWorkspaceScanOptions},
    live_claim::{self, LiveClock},
    llm::{FakeProvider, PromptContext, ProviderCapabilities, Redactor, RepoExcerpt, WorkProposal},
    machine_global::{
        DestructiveTargetInput, GateOutcome, MachineGlobalClaimSummary, MachineGlobalClaimToken,
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
        ClaimStatusReport, ClaimTelemetryOutcome, MegafileClaimWarning, OwnerReport, SyncStore,
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
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserializer, Serialize,
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
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
const MAX_REVIEWED_MERGE_PREVIEW_BYTES: u64 = 96 * 1024 * 1024;
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
const MAX_EVALUATION_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EVALUATION_PLAN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXTERNAL_EVENT_PAYLOAD_CLI_BYTES: usize = 4 * 1024;

#[derive(Debug, Parser)]
#[command(name = "maco")]
#[command(about = "Multi-Agent Coding Orchestrator")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn run(self) -> Result<()> {
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
    /// Run opt-in Codex CLI supervisor-of-orchestrators plans.
    Supervise(SuperviseCommand),
    /// Ask a read-only cross-runtime consultant for advice.
    Consult(ConsultCommand),
    /// Scan and react to safe GitHub issue and pull request inbox items.
    Inbox(InboxCommand),
    /// Serve read-only real-time orchestration observability APIs.
    Scope(ScopeCommand),
    /// Run local-first autopilot workflow phases.
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
                print_orchestration_summary(&summary, args.json)?;
                if !summary.success {
                    if let Some(agent_id) = summary.first_failed_agent() {
                        bail!("orchestration failed for agent '{agent_id}'");
                    }
                    bail!("orchestration failed");
                }
                Ok(())
            }
            OrchestrateSubcommand::Resume(args) => {
                let summary = orchestrator::resume_plan_file(OrchestrationResumeOptions {
                    checkpoint_file: args.checkpoint_file,
                    repo: args.repo,
                    plan_file: args.plan_file,
                    jobs: args.jobs,
                    patch_dir: args.patch_dir,
                })?;
                print_orchestration_summary(&summary, args.json)?;
                if !summary.success {
                    if let Some(agent_id) = summary.first_failed_agent() {
                        bail!("orchestration failed for agent '{agent_id}'");
                    }
                    bail!("orchestration failed");
                }
                Ok(())
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

fn run_supervise_command(command: SuperviseSubcommand) -> Result<()> {
    match command {
        SuperviseSubcommand::Plan(args) => {
            let PlanSuperviseArgs {
                task_file,
                from_goal,
                repo,
                json,
            } = args;
            let plan = match (task_file, from_goal) {
                (Some(task_file), None) => {
                    supervise::supervisor_plan_document_from_task_file(repo, task_file)?
                }
                (None, Some(goal_file)) => {
                    let goal_spec = read_supervise_goal_file(&goal_file)?;
                    supervise::supervisor_plan_document_from_goal_spec(repo, "", &goal_spec)?
                }
                _ => bail!(
                    "supervise plan requires exactly one positional TASK_FILE or --from-goal <FILE>"
                ),
            };
            print_query_report(&plan, json)
        }
        SuperviseSubcommand::Run(args) => {
            let budget_overrides = args.budget.limits();
            let budget_max_duration_seconds = args.budget.max_duration_seconds();
            let (plan_file, goal_spec) = match (args.supervisor_plan, args.from_goal) {
                (Some(plan_file), None) => (plan_file, None),
                (None, Some(goal_file)) => {
                    let goal_spec = read_supervise_goal_file(&goal_file)?;
                    (goal_file, Some(goal_spec))
                }
                _ => bail!(
                    "supervise run requires exactly one positional SUPERVISOR_PLAN or --from-goal <FILE>"
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
            let options = SupervisorRunOptions {
                repo: resolved_repo,
                plan_file,
                run_id: resolved_run_id.clone(),
                parent_node: args.parent_node.map(Into::into),
                codex_bin: args.codex_bin,
                runtime: args.runtime,
                allow_dirty_primary: args.allow_dirty_primary,
                admission_overrides,
                budget_overrides,
                budget_max_duration_seconds,
                machine_global_retention: Some(MachineGlobalRetentionBinding {
                    config: args.machine_global_config,
                    root_id: args.machine_global_runtime_root_id,
                    owner: "maco-supervise".to_string(),
                    correction_correlation_id: resolved_run_id.as_str().to_string(),
                }),
            };
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
                    supervise::run_supervisor_goal_spec_cascade_with_concurrency_policy_and_primary_worktree_opt_in(
                        options,
                        "",
                        &goal_spec,
                        args.max_concurrent_children,
                        args.allow_primary_worktree,
                    )?
                }
                (None, true) => {
                    supervise::resume_supervisor_plan_file_cascade_with_concurrency_policy(
                        options,
                        args.max_concurrent_children,
                    )?
                }
                (None, false) => {
                    supervise::run_supervisor_plan_file_cascade_with_concurrency_policy_and_primary_worktree_opt_in(
                        options,
                        args.max_concurrent_children,
                        args.allow_primary_worktree,
                    )?
                }
            };
            print_query_report(&report, args.json)?;
            if !report.follow_up_cascade_success {
                bail!("supervise run failed");
            }
            Ok(())
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
                    codex_bin: args.codex_bin,
                    runtime: args.runtime,
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
enum SuperviseSubcommand {
    /// Build a validated plan from a goal/spec, task file, or JSON supervisor plan.
    Plan(PlanSuperviseArgs),
    /// Run a supervisor plan with child Codex CLI orchestrators.
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
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy, Default, Args)]
struct RunBudgetArgs {
    /// Hard ceiling for total provider tokens committed by this supervise run.
    #[arg(
        long = "max-tokens",
        visible_alias = "max-total-tokens",
        value_parser = parse_positive_usize
    )]
    max_tokens: Option<usize>,
    /// Hard ceiling for total provider cost committed by this supervise run, in USD.
    #[arg(
        long = "max-cost-usd",
        visible_alias = "max-total-cost-usd",
        value_parser = parse_positive_finite_f64
    )]
    max_cost_usd: Option<f64>,
    /// Maximum elapsed duration for admitting new supervise dispatches.
    #[arg(
        long = "max-duration-seconds",
        visible_alias = "max-total-duration-seconds",
        value_parser = parse_positive_seconds
    )]
    max_duration_seconds: Option<u64>,
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
}

#[derive(Debug, Args)]
struct RunSuperviseArgs {
    /// JSON supervisor plan file to run.
    #[arg(
        value_name = "SUPERVISOR_PLAN",
        required_unless_present = "from_goal",
        conflicts_with = "from_goal"
    )]
    supervisor_plan: Option<PathBuf>,
    /// High-level goal/spec file to decompose and run through the supervisor gates.
    #[arg(long, value_name = "FILE", conflicts_with = "supervisor_plan")]
    from_goal: Option<PathBuf>,
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
    /// Runtime. Fake is deterministic in-process simulation and never executes Codex or publishes.
    #[arg(long, value_enum, default_value_t = supervise::SupervisorRuntime::Codex)]
    runtime: supervise::SupervisorRuntime,
    /// Allow supervise to run when the primary worktree is dirty.
    #[arg(long)]
    allow_dirty_primary: bool,
    /// Acknowledge an exact execution_target.kind=primary_worktree plan declaration.
    #[arg(long)]
    allow_primary_worktree: bool,
    /// Maximum concurrent child assignments: `auto` uses the conservative network-bound default.
    #[arg(long, default_value_t = supervise::SupervisorConcurrencyPolicy::Auto)]
    max_concurrent_children: supervise::SupervisorConcurrencyPolicy,
    /// Configured provider quota for simultaneous in-flight child requests (no live probing).
    #[arg(long, value_parser = parse_positive_usize)]
    provider_inflight_limit: Option<usize>,
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
    /// Runtime. Fake is deterministic in-process simulation and never publishes.
    #[arg(long, value_enum, default_value_t = supervise::SupervisorRuntime::Codex)]
    runtime: supervise::SupervisorRuntime,
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
            InboxSubcommand::Run(_) => Err(autopilot::effectful_autopilot_unavailable_error()),
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
            InboxSubcommand::Watch(_) => Err(autopilot::effectful_autopilot_unavailable_error()),
            InboxSubcommand::Workspace(command) => command.run(),
            InboxSubcommand::Artifacts(command) => command.run(RunArtifactFamily::Inbox),
        }
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
            WorkspaceInboxSubcommand::Run(_) => {
                Err(autopilot::effectful_autopilot_unavailable_error())
            }
            WorkspaceInboxSubcommand::Watch(_) => {
                Err(autopilot::effectful_autopilot_unavailable_error())
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
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
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
            AutopilotSubcommand::Plan(args) => {
                let plan = autopilot::autopilot_plan_from_task_file(args.repo, args.task_file)?;
                print_query_report(&plan, args.json)
            }
            AutopilotSubcommand::Run(args) => {
                let budget_overrides = args.budget.limits();
                let budget_max_duration_seconds = args.budget.max_duration_seconds();
                let (plan_file, goal_spec) = match (args.task_file, args.from_goal) {
                    (Some(plan_file), None) => (plan_file, None),
                    (None, Some(goal_file)) => {
                        let goal_spec = read_supervise_goal_file(&goal_file)?;
                        (goal_file, Some(goal_spec))
                    }
                    _ => bail!(
                        "autopilot run requires exactly one positional TASK_FILE or --from-goal <FILE>"
                    ),
                };
                let profile = args
                    .profile
                    .as_ref()
                    .map(autopilot::autopilot_profile_from_file)
                    .transpose()?;
                let resolved = resolve_run_id_for_run(
                    &args.repo,
                    RunArtifactFamily::Autopilot,
                    args.run_id.as_deref(),
                    args.json,
                )?;
                let parent_node = args.parent_node.map(Into::into);
                let options = AutopilotRunOptions {
                    repo: resolved.repo,
                    plan_file,
                    run_id: resolved.run_id.clone(),
                    codex_bin: args.codex_bin,
                    reviewer_command: args.reviewer_command,
                    allow_dirty_primary: args.allow_dirty_primary,
                    max_child_dispatches: args.max_child_dispatches,
                    budget_overrides,
                    budget_max_duration_seconds,
                    cancellation: None,
                };
                let retention = Some(MachineGlobalRetentionBinding {
                    config: args.machine_global_config,
                    root_id: args.machine_global_runtime_root_id,
                    owner: "maco-autopilot".to_string(),
                    correction_correlation_id: resolved.run_id.as_str().to_string(),
                });
                let report = match goal_spec {
                    Some(goal_spec) => {
                        autopilot::run_autopilot_goal_spec_with_profile_retention_and_parent(
                            options,
                            "",
                            &goal_spec,
                            profile,
                            retention,
                            parent_node,
                        )?
                    }
                    None => autopilot::run_autopilot_plan_file_with_profile_retention_and_parent(
                        options,
                        profile,
                        retention,
                        parent_node,
                    )?,
                };
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("autopilot run failed");
                }
                Ok(())
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
    /// Normalize a task file or JSON autopilot plan without running it.
    Plan(PlanAutopilotArgs),
    /// Run one depth-2 plan through the live supervise gates without applying to primary.
    Run(Box<RunAutopilotArgs>),
    /// Report durable autopilot run artifact state.
    Status(StatusAutopilotArgs),
    /// Collect the durable autopilot final report.
    Collect(CollectAutopilotArgs),
    /// List, inspect, or prune durable run artifacts.
    Artifacts(ArtifactsCommand),
}

#[derive(Debug, Args)]
struct PlanAutopilotArgs {
    /// Task file or JSON autopilot plan file.
    task_file: PathBuf,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RunAutopilotArgs {
    /// Task file or JSON autopilot plan file.
    #[arg(
        value_name = "TASK_FILE",
        required_unless_present = "from_goal",
        conflicts_with = "from_goal"
    )]
    task_file: Option<PathBuf>,
    /// High-level goal/spec file to decompose and run through the autopilot gates.
    #[arg(long, value_name = "FILE", conflicts_with = "task_file")]
    from_goal: Option<PathBuf>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable run id for durable `.maco/autopilot/runs/<run-id>` artifacts. Omit to generate one.
    #[arg(long)]
    run_id: Option<String>,
    /// External orchestration node that directly spawned this autopilot run.
    #[arg(long, value_parser = parse_boxed_orchestration_node_id)]
    parent_node: Option<Box<str>>,
    /// Codex-compatible executable to invoke. Omit for deterministic local fake mode.
    #[arg(long)]
    codex_bin: Option<PathBuf>,
    /// Versioned role/model, pricing, and review-lens profile manifest.
    #[arg(long)]
    profile: Option<PathBuf>,
    /// Disabled legacy reviewer shell string; supplying it fails closed.
    #[arg(long)]
    reviewer_command: Option<String>,
    /// Allow autopilot to run when the primary worktree is dirty.
    #[arg(long)]
    allow_dirty_primary: bool,
    /// Maximum source plus generated follow-up supervisor-plan dispatches admitted by this run.
    #[arg(long, value_name = "COUNT")]
    max_child_dispatches: Option<usize>,
    #[command(flatten)]
    budget: RunBudgetArgs,
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
                if json {
                    let failure_context = AgentRunFailureContext::from_args(&args);
                    match run_agent_from_args(args) {
                        Ok(report) => {
                            print_agent_run_report(&report, true)?;
                            if !report.success {
                                bail!("{}", report.error.as_deref().unwrap_or("agent run failed"));
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
                let record = manager.create_with_retention(
                    WorktreeCreateOptions {
                        agent_id: args.agent_id.clone(),
                        branch: args.branch,
                        base: args.base,
                        worktree_root: args.worktree_root.clone(),
                    },
                    retention,
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
            WorktreeSubcommand::Guard(command) => command.run(),
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
                let outcome = match configured_thresholds {
                    Some(thresholds) => store.claim_paths_with_telemetry_thresholds(
                        &args.agent_id,
                        args.paths,
                        thresholds,
                    )?,
                    None => store.claim_paths_with_telemetry(&args.agent_id, args.paths)?,
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
        }
    }
}

#[derive(Debug, Subcommand)]
enum EvaluationSubcommand {
    /// Generate deterministic fixture output for every manifest profile and repetition.
    Run(RunEvaluationArgs),
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

fn run_evaluation_command(args: RunEvaluationArgs) -> Result<()> {
    let manifest_bytes =
        BoundedRegularReader::read_tree_no_follow(&args.manifest, MAX_EVALUATION_MANIFEST_BYTES)
            .with_context(|| {
                format!(
                    "failed to read evaluation manifest {}",
                    args.manifest.display()
                )
            })?;
    let manifest = serde_json::from_slice::<crate::evaluation::EvaluationManifest>(&manifest_bytes)
        .with_context(|| {
            format!(
                "failed to parse evaluation manifest {}",
                args.manifest.display()
            )
        })?;
    let plan_bytes =
        BoundedRegularReader::read_tree_no_follow(&args.plan_file, MAX_EVALUATION_PLAN_BYTES)
            .with_context(|| {
                format!(
                    "failed to read hand-authored evaluation plan {}",
                    args.plan_file.display()
                )
            })?;

    // This legacy Phase-A runner generates synthetic fixtures only: it does not inspect the
    // repository or execute a provider, supervisor, held-out command, or isolated workflow.
    // Keep the reserved repository binding explicit so a future isolated runner can replace this
    // single call without silently changing the command contract.
    let _repo = args.repo;
    let results = crate::evaluation::run_evaluation(
        &manifest,
        &plan_bytes,
        crate::evaluation::EvaluationRunRequest {
            execution: args.execution,
            allow_real_provider: args.allow_real_provider,
            fake_seed: args.fake_seed,
        },
    )?;
    print_query_report(&results, args.json)
}

#[derive(Debug, Subcommand)]
enum WorktreeSubcommand {
    /// Create a linked worktree for an agent.
    Create(CreateWorktreeArgs),
    /// Collect an agent worktree diff and claim-boundary report.
    Diff(DiffWorktreeArgs),
    /// Remove clean, inactive managed worktrees and unregistered leftover directories.
    Gc(GcWorktreeArgs),
    /// Sweep managed worktrees across every repository group in a workspace.
    Sweep(SweepWorktreeArgs),
    /// Classify and optionally apply opt-in worktree and artifact lifecycle automation.
    Lifecycle(LifecycleWorktreeArgs),
    /// Remove a linked worktree for an agent.
    Remove(RemoveWorktreeArgs),
    /// List registered worktrees.
    List(ListWorktreesArgs),
    /// Inspect authenticated pending worktree operations without recovering them.
    Pending(ListWorktreesArgs),
    /// Manage the advisory primary-worktree Git guard explicitly.
    Guard(WorktreeGuardCommand),
}

#[derive(Debug, Args)]
struct WorktreeGuardCommand {
    #[command(subcommand)]
    command: WorktreeGuardSubcommand,
}

impl WorktreeGuardCommand {
    fn run(self) -> Result<()> {
        match self.command {
            WorktreeGuardSubcommand::Install(args) => {
                let report = install_primary_worktree_guard(args.repo)?;
                print_query_report(&report, args.json)
            }
            WorktreeGuardSubcommand::Verify(args) => {
                let report = verify_primary_worktree_guard(args.repo)?;
                print_query_report(&report, args.json)
            }
            WorktreeGuardSubcommand::Uninstall(args) => {
                let report = uninstall_primary_worktree_guard(args.repo)?;
                print_query_report(&report, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum WorktreeGuardSubcommand {
    /// Install or idempotently refresh the guard in the primary worktree.
    Install(WorktreeGuardArgs),
    /// Verify the primary-worktree guard without changing repository state.
    Verify(WorktreeGuardArgs),
    /// Remove MACO-owned guard state and restore the prior hook configuration.
    Uninstall(WorktreeGuardArgs),
}

#[derive(Debug, Args)]
struct WorktreeGuardArgs {
    /// Primary repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct CreateWorktreeArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable agent id. Allowed characters: ASCII letters, digits, '.', '_' and '-'.
    agent_id: String,
    /// Branch to check out in the worktree. Defaults to maco/<agent-id>.
    #[arg(long)]
    branch: Option<String>,
    /// Base revision used when creating a new branch. Defaults to HEAD.
    #[arg(long)]
    base: Option<String>,
    /// Parent directory for agent worktrees.
    #[arg(long)]
    worktree_root: Option<PathBuf>,
    /// After creation, remove eligible older clean worktrees older than this many seconds.
    #[arg(long)]
    gc_max_age_seconds: Option<u64>,
    /// After creation, keep at most this many newest eligible clean worktrees.
    #[arg(long)]
    gc_max_count: Option<usize>,
    /// After creation, retain at most this many apparent, not allocated, bytes in newest eligible lanes.
    #[arg(long)]
    gc_max_total_bytes: Option<u64>,
    /// Apply the bounded O2-launch default of retaining the newest 10 lanes after creation.
    #[arg(long)]
    o2_launch_retention_defaults: bool,
    /// Classify this newly created retry lane's exact predecessor for guarded supersession.
    #[arg(long)]
    supersede_retry_predecessor: bool,
    /// Apply eligible retry predecessor reaping after creation.
    #[arg(long, requires = "supersede_retry_predecessor")]
    apply_retry_supersession: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct GcWorktreeArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Parent directory for agent worktrees.
    #[arg(long)]
    worktree_root: Option<PathBuf>,
    /// List cleanup actions without removing anything.
    #[arg(long)]
    dry_run: bool,
    /// Keep per-worktree target/ directories for retained worktrees.
    #[arg(long)]
    keep_targets: bool,
    /// Reclaim eligible target/ directories while retaining every lane and branch; conflicts with retention filters.
    #[arg(long)]
    targets_only: bool,
    /// Remove only eligible clean worktrees older than this many seconds.
    #[arg(long)]
    max_age_seconds: Option<u64>,
    /// Keep at most this many newest eligible clean worktrees.
    #[arg(long)]
    max_count: Option<usize>,
    /// Retain a newest eligible prefix within this many apparent, not allocated, bytes; sizing failure protects a lane.
    #[arg(long)]
    max_total_bytes: Option<u64>,
    /// Exact repository-relative untracked path allowed during full-lane removal. Repeatable.
    #[arg(long = "allow-untracked-path")]
    allow_untracked_paths: Vec<PathBuf>,
    /// Exact reviewed config used to gate nonempty unregistered-directory cleanup.
    #[arg(long)]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root contains the managed worktree root.
    #[arg(long)]
    machine_global_worktree_root_id: Option<String>,
    /// Correction lifecycle identity used by typed machine-global gate denials.
    #[arg(long)]
    machine_global_correlation: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SweepWorktreeArgs {
    /// Workspace containing .maco/worktrees/<repo>/<lane> directories.
    #[arg(long)]
    workspace: PathBuf,
    /// Apply cleanup. Without this flag, the sweep is a dry-run.
    #[arg(long)]
    apply: bool,
    /// Keep per-worktree target/ directories for retained worktrees.
    #[arg(long)]
    keep_targets: bool,
    /// Reclaim eligible target/ directories while retaining every lane and branch; conflicts with retention filters.
    #[arg(long)]
    targets_only: bool,
    /// Remove only eligible clean worktrees older than this many seconds.
    #[arg(long)]
    max_age_seconds: Option<u64>,
    /// Keep at most this many newest eligible clean worktrees per discovered root.
    #[arg(long)]
    max_count: Option<usize>,
    /// Retain a newest eligible prefix within this many apparent, not allocated, bytes per discovered root.
    #[arg(long)]
    max_total_bytes: Option<u64>,
    /// Exact repository-relative untracked path allowed during full-lane removal. Repeatable.
    #[arg(long = "allow-untracked-path")]
    allow_untracked_paths: Vec<PathBuf>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct LifecycleWorktreeArgs {
    /// Repository path. Lifecycle automation is disabled unless a feature flag is supplied.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Apply explicitly enabled lifecycle actions. Without this flag, the pass is a dry-run.
    #[arg(long)]
    apply: bool,
    /// Classify fully merged lanes for guarded automatic reaping.
    #[arg(long, requires = "trunk_ref")]
    auto_reap_merged: bool,
    /// Exact local trunk reference used for merged ancestry, for example refs/heads/main.
    #[arg(long, value_name = "REF", requires = "auto_reap_merged")]
    trunk_ref: Option<String>,
    /// Exact retry-lane successor whose unambiguous predecessor may be superseded.
    #[arg(long, value_name = "AGENT_ID")]
    retry_successor: Option<String>,
    /// Detect metadata/on-disk registration mismatches left by an unclean shutdown.
    #[arg(long)]
    startup_reconciliation: bool,
    /// Permit guarded destructive resolution of startup reconciliation findings.
    #[arg(long, requires_all = ["startup_reconciliation", "apply"])]
    destructive_reconciliation: bool,
    /// Schedule the bounded O2-launch run-artifact retention profile.
    #[arg(long)]
    o2_launch_retention: bool,
    /// Parent directory for agent worktrees.
    #[arg(long)]
    worktree_root: Option<PathBuf>,
    /// Remove only eligible clean worktrees older than this many seconds.
    #[arg(long, requires = "auto_reap_merged")]
    max_age_seconds: Option<u64>,
    /// Keep at most this many newest eligible clean worktrees.
    #[arg(long, requires = "auto_reap_merged")]
    max_count: Option<usize>,
    /// Retain a newest eligible prefix within this many apparent, not allocated, bytes.
    #[arg(long, requires = "auto_reap_merged")]
    max_total_bytes: Option<u64>,
    /// Keep per-worktree target/ directories for retained worktrees.
    #[arg(long)]
    keep_targets: bool,
    /// Exact repository-relative untracked path allowed during full-lane removal. Repeatable.
    #[arg(long = "allow-untracked-path")]
    allow_untracked_paths: Vec<PathBuf>,
    /// Keep the latest N O2-launch run directories instead of the bounded profile default.
    #[arg(long, value_name = "N", requires = "o2_launch_retention")]
    artifact_keep: Option<usize>,
    /// Reclaim O2-launch artifacts at least this old even when within --artifact-keep.
    #[arg(long, value_name = "SECONDS", requires = "o2_launch_retention")]
    artifact_max_age_seconds: Option<u64>,
    /// Retain at most this many apparent artifact bytes, newest first.
    #[arg(long, value_name = "BYTES", requires = "o2_launch_retention")]
    artifact_max_total_bytes: Option<u64>,
    /// Override the grace for idle unfinalized O2-launch artifacts.
    #[arg(long, value_name = "SECONDS", requires = "o2_launch_retention")]
    artifact_unfinalized_grace_seconds: Option<u64>,
    /// Allow grace-based expiry of present but unverifiable finalization evidence.
    #[arg(long, requires = "o2_launch_retention")]
    reclaim_unverifiable: bool,
    /// Confirm that non-cooperating external artifact writers are stopped.
    #[arg(long, requires = "o2_launch_retention")]
    acknowledge_external_writers_stopped: bool,
    /// Exact reviewed config used to gate nonempty unregistered-directory cleanup.
    #[arg(long)]
    machine_global_config: Option<PathBuf>,
    /// Reviewed root id whose canonical root contains the managed worktree root.
    #[arg(long)]
    machine_global_worktree_root_id: Option<String>,
    /// Correction lifecycle identity used by typed machine-global gate denials.
    #[arg(long)]
    machine_global_correlation: Option<String>,
    /// Emit the aggregate lifecycle report as one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DiffWorktreeArgs {
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long)]
    claim: Vec<PathBuf>,
    /// Include the complete binary-safe git diff in JSON output.
    #[arg(long)]
    full_diff: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RemoveWorktreeArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Remove even if the worktree has uncommitted changes or is locked.
    #[arg(long)]
    force: bool,
    /// Delete the worktree branch after removing the worktree.
    #[arg(long)]
    delete_branch: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ListWorktreesArgs {
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn resolve_claims(
    repo: &Path,
    agent_id: &str,
    explicit_claims: Vec<PathBuf>,
) -> Result<Vec<PathBuf>> {
    if !explicit_claims.is_empty() {
        return Ok(explicit_claims);
    }

    let store = SyncStore::open(repo)?;
    let claims = store
        .snapshot()?
        .into_iter()
        .filter(|claim| claim.agent_id == agent_id)
        .flat_map(|claim| claim.paths)
        .collect::<Vec<_>>();
    Ok(claims)
}

fn collect_options_from_claims(
    repo: &Path,
    agent_id: &str,
    claimed_paths: Vec<PathBuf>,
    include_full_diff: bool,
    validations: Vec<ValidationReport>,
) -> MergeCollectOptions {
    MergeCollectOptions {
        repo: repo.to_path_buf(),
        agent_id: agent_id.to_string(),
        claimed_paths,
        include_full_diff,
        diff_summary_char_limit: merge::DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
        validations,
    }
}

fn preview_merge_from_args(
    repo: PathBuf,
    agent_id: String,
    explicit_claims: Vec<PathBuf>,
    validation_report_paths: Vec<PathBuf>,
    forces: MergeForceOptions,
    require_validation: bool,
    megafile_policy: MegafileMergePolicy,
) -> Result<(MergeApplyPreview, merge::MergePreviewFreshnessWatermark)> {
    let claims = resolve_claims(&repo, &agent_id, explicit_claims)?;
    let validation_evidence = load_validation_evidence(&validation_report_paths, &agent_id)?;
    merge::preview_merge_apply_with_freshness_and_megafile_policy(
        MergePreviewOptions {
            collect: collect_options_from_claims(&repo, &agent_id, claims, true, Vec::new()),
            forces,
            require_validation,
        },
        validation_evidence,
        megafile_policy,
    )
}

#[derive(Debug, Args)]
struct MergeCommand {
    #[command(subcommand)]
    command: MergeSubcommand,
}

impl MergeCommand {
    fn run(self) -> Result<()> {
        match self.command {
            MergeSubcommand::Preview(args) => {
                let megafile_policy = args.megafile_policy()?;
                let (preview, freshness_watermark) = preview_merge_from_args(
                    args.repo,
                    args.agent_id,
                    args.claim,
                    args.validation_report,
                    args.forces.into_force_options(),
                    args.require_validation,
                    megafile_policy,
                )?;
                print_merge_preview(&preview, &freshness_watermark, args.json)
            }
            MergeSubcommand::Apply(args) => {
                run_merge_apply_controller(args, |report, json, review_bound| {
                    print_merge_apply_report(report, json, review_bound)
                })
            }
            MergeSubcommand::Arbitrate(args) => {
                let first_side =
                    arbitration_side_from_cli(args.first_side, args.first_claim, "first")?;
                let second_side =
                    arbitration_side_from_cli(args.second_side, args.second_claim, "second")?;
                let report = merge::arbitrate_merge(MergeArbitrationOptions {
                    repo: args.repo,
                    run_id: RunId::new(args.run_id)?,
                    arbiter_agent_id: args.arbiter_id,
                    sides: [first_side, second_side],
                    validation_commands: args
                        .validation_command
                        .into_iter()
                        .map(|command| CandidateValidationCommand { command })
                        .collect(),
                    approve: args.approve,
                    codex_bin: args.codex_bin,
                    timeout: Duration::from_secs(args.timeout_seconds),
                    worktree_root: args.worktree_root,
                    machine_global_config: args.machine_global_config,
                    machine_global_runtime_root_id: args.machine_global_runtime_root_id,
                })?;
                print_merge_arbitration_report(&report, args.json)
            }
        }
    }
}

fn run_merge_apply_controller(
    args: MergeApplyArgs,
    mut deliver_report: impl FnMut(&MergeApplyReport, bool, bool) -> Result<()>,
) -> Result<()> {
    let lifecycle_repo = args.repo.clone();
    let lifecycle_agent_id = args.agent_id.clone();
    let auto_reap_merged = args.auto_reap_merged;
    let apply_auto_reap = args.apply_auto_reap;
    let lifecycle_trunk_ref = args.trunk_ref.clone();
    let json = args.json;
    let reviewed_watermark = match load_reviewed_merge_preview(args.reviewed_preview.as_deref()) {
        Ok(watermark) => watermark,
        Err(error) => {
            if let Some(freshness) = error.downcast_ref::<merge::MergePreviewFreshnessError>() {
                if json {
                    print_merge_preview_freshness_refusal(freshness, true)?;
                }
            }
            return Err(error);
        }
    };
    let megafile_policy = args.megafile_policy()?;
    let claims = resolve_claims(&args.repo, &args.agent_id, args.claim)?;
    let validation_evidence = load_validation_evidence(&args.validation_report, &args.agent_id)?;
    let candidate_validation_commands = args
        .validation_command
        .into_iter()
        .map(|command| CandidateValidationCommand { command })
        .collect::<Vec<_>>();
    let preview_options = MergePreviewOptions {
        collect: collect_options_from_claims(&args.repo, &args.agent_id, claims, true, Vec::new()),
        forces: args.forces.into_force_options(),
        require_validation: args.require_validation,
    };
    let review_requested = reviewed_watermark.is_some();
    let report = merge::merge_apply_report_with_reviewed_preview_and_megafile_policy(
        MergeApplyOptions {
            preview: preview_options,
            candidate_validation_commands,
        },
        validation_evidence,
        megafile_policy,
        reviewed_watermark.as_ref(),
    );
    let mut report = match report {
        Ok(report) => report,
        Err(error) => {
            if let Some(freshness) = error.downcast_ref::<merge::MergePreviewFreshnessError>() {
                if json {
                    print_merge_preview_freshness_refusal(freshness, review_requested)?;
                }
            }
            return Err(error);
        }
    };
    if report.status == merge::MergeApplyReportStatus::Blocked {
        if json {
            deliver_report(&report, true, review_requested)?;
        }
        let message = report
            .error
            .clone()
            .unwrap_or_else(|| "merge apply refused".to_string());
        bail!("{message}");
    }
    if auto_reap_merged {
        let lifecycle_options = WorktreeLifecycleOptions {
            apply: apply_auto_reap,
            auto_reap_merged: true,
            candidate_agent_ids: Some(BTreeSet::from([lifecycle_agent_id])),
            merged_into_reference: lifecycle_trunk_ref,
            // A merge apply does not advance HEAD. Retain the selected lane's target cache
            // unless and until the lane itself is classified as fully merged and reaped.
            remove_targets: false,
            ..WorktreeLifecycleOptions::default()
        };
        match WorktreeManager::new(lifecycle_repo).lifecycle(lifecycle_options) {
            Ok(lifecycle) => report.lifecycle = Some(lifecycle),
            Err(error) => {
                let context = if report.applied {
                    format!(
                        "merge was applied, but merged-lane lifecycle classification failed; \
                         do not retry the merge: {error:#}"
                    )
                } else {
                    format!(
                        "merge was not blocked, but merged-lane lifecycle classification failed: \
                         {error:#}"
                    )
                };
                report.error = Some(context.clone());
                deliver_report(&report, json, review_requested)?;
                bail!("{context}");
            }
        }
    }
    deliver_report(&report, json, review_requested)
}

#[derive(Debug, Serialize)]
struct MergePreviewFreshnessRefusalReport<'a> {
    status: &'static str,
    applied: bool,
    review_requested: bool,
    review_bound: bool,
    review_binding_status: &'static str,
    error_kind: &'static str,
    reason: &'static str,
    drift_axes: &'a [merge::MergePreviewDriftAxis],
    message: String,
    next_action: &'static str,
}

fn print_merge_preview_freshness_refusal(
    error: &merge::MergePreviewFreshnessError,
    review_requested: bool,
) -> Result<()> {
    let report = merge_preview_freshness_refusal_report(error, review_requested);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn merge_preview_freshness_refusal_report(
    error: &merge::MergePreviewFreshnessError,
    review_requested: bool,
) -> MergePreviewFreshnessRefusalReport<'_> {
    MergePreviewFreshnessRefusalReport {
        status: "refused",
        applied: false,
        review_requested,
        review_bound: false,
        review_binding_status: if review_requested {
            "not_bound"
        } else {
            "not_supplied"
        },
        error_kind: "merge_preview_freshness",
        reason: error.reason(),
        drift_axes: error.drift_axes(),
        message: error.to_string(),
        next_action: if review_requested {
            "run merge preview again and review the new freshness_watermark"
        } else {
            "retry merge apply after concurrent repository activity stops"
        },
    }
}

#[derive(Debug, Subcommand)]
enum MergeSubcommand {
    /// Preview whether an agent worktree diff can be applied to the primary worktree.
    Preview(MergePreviewArgs),
    /// Apply an agent worktree diff to the primary worktree after safety checks.
    Apply(MergeApplyArgs),
    /// Ask a structurally neutral arbiter to prepare, but never apply, a collision resolution.
    Arbitrate(MergeArbitrateArgs),
}

#[derive(Debug, Args)]
struct MergePreviewArgs {
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long)]
    claim: Vec<PathBuf>,
    /// Validation JSON. With --require-validation, use an envelope containing the exact current candidate.validation_binding and passed reports; legacy arrays are unbound.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require passed validation evidence bound exactly to the current candidate snapshot.
    #[arg(long)]
    require_validation: bool,
    /// Block threshold-crossing megafiles unless this is their exact typed decomposition.
    #[arg(long)]
    block_megafiles: bool,
    /// Exact threshold-crossing file handled by a typed megafile_decomposition assignment.
    #[arg(long)]
    decomposition_target: Option<PathBuf>,
    /// Finalized accepted supervise run containing the typed decomposition evidence.
    #[arg(long)]
    decomposition_run_id: Option<String>,
    #[command(flatten)]
    megafile_thresholds: MegafileThresholdArgs,
    #[command(flatten)]
    forces: MergeForceArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MergeApplyArgs {
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long)]
    claim: Vec<PathBuf>,
    /// Validation JSON. With --require-validation, use an exact candidate-bound envelope; legacy arrays are unbound. Repeat to supply multiple files.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require an exact candidate-bound passed report or a passed candidate validation command.
    #[arg(long)]
    require_validation: bool,
    /// Validate a temporary merged candidate; recursive candidate or submodule changes block apply.
    #[arg(long = "validation-command")]
    validation_command: Vec<String>,
    /// Reviewed `merge preview --json` file, or its exact nested freshness_watermark object. The bounded file is read without following symlinks; drift refuses apply.
    #[arg(long, value_name = "FILE")]
    reviewed_preview: Option<PathBuf>,
    /// Block threshold-crossing megafiles unless this is their exact typed decomposition.
    #[arg(long)]
    block_megafiles: bool,
    /// Exact threshold-crossing file handled by a typed megafile_decomposition assignment.
    #[arg(long)]
    decomposition_target: Option<PathBuf>,
    /// Finalized accepted supervise run containing the typed decomposition evidence.
    #[arg(long)]
    decomposition_run_id: Option<String>,
    #[command(flatten)]
    megafile_thresholds: MegafileThresholdArgs,
    #[command(flatten)]
    forces: MergeForceArgs,
    /// After a non-blocked merge result, classify this lane for guarded merged-lane reaping.
    #[arg(long, requires = "trunk_ref")]
    auto_reap_merged: bool,
    /// Exact local trunk reference used to verify that the lane is fully merged.
    #[arg(long, value_name = "REF", requires = "auto_reap_merged")]
    trunk_ref: Option<String>,
    /// Apply an eligible merge lifecycle reap; requires --auto-reap-merged.
    #[arg(long, requires = "auto_reap_merged")]
    apply_auto_reap: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct MergeArbitrateArgs {
    /// First collision side: a stable agent id or the reserved literal `primary`.
    #[arg(value_name = "FIRST_SIDE")]
    first_side: String,
    /// Second collision side: a distinct stable agent id or the reserved literal `primary`.
    #[arg(value_name = "SECOND_SIDE")]
    second_side: String,
    /// Stable identity for the fresh neutral arbiter; must differ from both sides.
    #[arg(long)]
    arbiter_id: String,
    /// Stable run id for private, digest-bound arbitration artifacts.
    #[arg(long)]
    run_id: String,
    /// Repository path. Arbitration never mutates its primary worktree.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claim for an agent first side. Repeat to provide multiple claims.
    #[arg(long = "first-claim")]
    first_claim: Vec<PathBuf>,
    /// Explicit claim for an agent second side. Repeat to provide multiple claims.
    #[arg(long = "second-claim")]
    second_claim: Vec<PathBuf>,
    /// Candidate-bound validation command. At least one is required.
    #[arg(long = "validation-command", required = true)]
    validation_command: Vec<String>,
    /// Explicitly accept a preserved, validated proposal. A later ordinary merge apply is still required.
    #[arg(long)]
    approve: bool,
    /// Codex-compatible executable used through the existing trusted local agent boundary.
    #[arg(long, default_value = "codex")]
    codex_bin: PathBuf,
    /// Seconds before the neutral arbiter subprocess is terminated.
    #[arg(long, default_value_t = 600)]
    timeout_seconds: u64,
    /// Optional managed-worktree root for the fresh neutral arbitration worktree.
    #[arg(long)]
    worktree_root: Option<PathBuf>,
    /// Exact reviewed config used to gate cleanup of private runtime output staging.
    #[arg(long)]
    machine_global_config: PathBuf,
    /// Reviewed root id whose canonical root must contain the actual private runtime root.
    #[arg(long)]
    machine_global_runtime_root_id: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn arbitration_side_from_cli(
    participant: String,
    claimed_paths: Vec<PathBuf>,
    position: &str,
) -> Result<ArbitrationSideSpec> {
    if participant == "primary" {
        if !claimed_paths.is_empty() {
            bail!(
                "{position} arbitration side is primary, so --{position}-claim is not applicable"
            );
        }
        Ok(ArbitrationSideSpec::Primary)
    } else {
        Ok(ArbitrationSideSpec::Agent {
            agent_id: participant,
            claimed_paths,
        })
    }
}

impl MergePreviewArgs {
    fn megafile_policy(&self) -> Result<MegafileMergePolicy> {
        let decomposition_run_id = self
            .decomposition_run_id
            .as_deref()
            .map(RunId::new)
            .transpose()?;
        validate_decomposition_cli_pair(
            self.decomposition_target.as_deref(),
            decomposition_run_id.as_ref(),
        )?;
        Ok(MegafileMergePolicy {
            block: self.block_megafiles,
            decomposition_target: self.decomposition_target.clone(),
            decomposition_run_id,
            thresholds: self
                .megafile_thresholds
                .configured_thresholds()
                .unwrap_or_else(MegafileThresholds::provisional_bootstrap),
        })
    }
}

impl MergeApplyArgs {
    fn megafile_policy(&self) -> Result<MegafileMergePolicy> {
        let decomposition_run_id = self
            .decomposition_run_id
            .as_deref()
            .map(RunId::new)
            .transpose()?;
        validate_decomposition_cli_pair(
            self.decomposition_target.as_deref(),
            decomposition_run_id.as_ref(),
        )?;
        Ok(MegafileMergePolicy {
            block: self.block_megafiles,
            decomposition_target: self.decomposition_target.clone(),
            decomposition_run_id,
            thresholds: self
                .megafile_thresholds
                .configured_thresholds()
                .unwrap_or_else(MegafileThresholds::provisional_bootstrap),
        })
    }
}

fn validate_decomposition_cli_pair(target: Option<&Path>, run_id: Option<&RunId>) -> Result<()> {
    match (target, run_id) {
        (Some(_), None) => {
            bail!("--decomposition-target requires --decomposition-run-id with finalized evidence")
        }
        (None, Some(_)) => bail!("--decomposition-run-id requires --decomposition-target"),
        _ => Ok(()),
    }
}

#[derive(Debug, Args)]
struct MergeForceArgs {
    /// Continue when the primary worktree has local changes.
    #[arg(long)]
    force_dirty_primary: bool,
    /// Continue when the agent branch was based on an older primary HEAD.
    #[arg(long)]
    force_stale_base: bool,
    /// Continue when the agent changed paths outside its claims.
    #[arg(long)]
    force_unclaimed_edits: bool,
    /// Continue when supplied validation reports include failures.
    #[arg(long)]
    force_validation_failures: bool,
    /// Allow three-way apply checks when a direct apply check fails.
    #[arg(long)]
    force_apply_conflicts: bool,
}

impl MergeForceArgs {
    fn into_force_options(self) -> MergeForceOptions {
        MergeForceOptions {
            allow_dirty_primary: self.force_dirty_primary,
            allow_stale_base: self.force_stale_base,
            allow_unclaimed_edits: self.force_unclaimed_edits,
            allow_validation_failures: self.force_validation_failures,
            allow_apply_conflicts: self.force_apply_conflicts,
        }
    }
}

#[derive(Debug, Args)]
struct PrCommand {
    #[command(subcommand)]
    command: PrSubcommand,
}

impl PrCommand {
    fn run(self) -> Result<()> {
        match self.command {
            PrSubcommand::Preview(args) => {
                let json = args.json;
                let require_validation = args.require_validation;
                let (options, validation_evidence) = pr_options_from_preview_args(args)?;
                let report = publication::preview_pr_with_validation_evidence(
                    options,
                    require_validation,
                    validation_evidence,
                )?;
                print_pr_publication_report(&report, json)
            }
            PrSubcommand::Publish(args) => {
                let json = args.json;
                let require_validation = args.require_validation;
                let (options, validation_evidence) = pr_options_from_publish_args(args)?;
                let report = publication::publish_pr_with_validation_evidence(
                    options,
                    require_validation,
                    validation_evidence,
                )?;
                let blocked_message = report.next_action.clone();
                print_pr_publication_report(&report, json)?;
                if report.status == PrPublicationStatus::Blocked {
                    bail!("pr publish refused: {blocked_message}");
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum PrSubcommand {
    /// Preview whether an agent worktree is ready to publish as a pull request.
    Preview(PrPreviewArgs),
    /// Publish an exact reviewed commit through an explicit forge with retry reconciliation.
    Publish(PrPublishArgs),
}

#[derive(Debug, Args)]
struct PrPreviewArgs {
    /// Stable agent id used when the worktree was created.
    #[arg(required_unless_present = "from_branch")]
    agent_id: Option<String>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long, required_unless_present = "from_branch")]
    claim: Vec<PathBuf>,
    /// Publish committed work from this local branch instead of a managed agent worktree.
    #[arg(long)]
    from_branch: Option<String>,
    /// Build a deterministic squash import commit on this local base branch before publishing.
    #[arg(long, requires = "from_branch")]
    squash_onto: Option<String>,
    /// Exclude a repository-local path from the published branch snapshot. Repeat for multiple paths.
    #[arg(long = "exclude", requires = "from_branch")]
    exclude: Vec<PathBuf>,
    /// Validation JSON. With --require-validation, copy the exact current preview.candidate.validation_binding into an envelope with passed reports.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require passed validation evidence bound exactly to this PR candidate snapshot.
    #[arg(long)]
    require_validation: bool,
    /// Forge label recorded in the preview report.
    #[arg(long, default_value = "fake", value_parser = parse_forge_kind)]
    forge: ForgeKind,
    /// Mark the eventual pull request ready for review instead of draft.
    #[arg(long)]
    ready: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PrPublishArgs {
    /// Stable agent id used when the worktree was created.
    #[arg(required_unless_present = "from_branch")]
    agent_id: Option<String>,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long, required_unless_present = "from_branch")]
    claim: Vec<PathBuf>,
    /// Publish committed work from this local branch instead of a managed agent worktree.
    #[arg(long)]
    from_branch: Option<String>,
    /// Build a deterministic squash import commit on this local base branch before publishing.
    #[arg(long, requires = "from_branch")]
    squash_onto: Option<String>,
    /// Exclude a repository-local path from the published branch snapshot. Repeat for multiple paths.
    #[arg(long = "exclude", requires = "from_branch")]
    exclude: Vec<PathBuf>,
    /// Candidate-bound validation envelope produced after previewing the clean, committed candidate; legacy report arrays are unbound.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require a clean committed candidate and passed evidence bound exactly to its current preview binding.
    #[arg(long)]
    require_validation: bool,
    /// Forge adapter. `github` binds origin host/owner/repo, verifies the OID receipt, and journals retry state.
    #[arg(long, value_parser = parse_forge_kind)]
    forge: ForgeKind,
    /// Mark the pull request ready for review instead of draft.
    #[arg(long)]
    ready: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct IssueCommand {
    #[command(subcommand)]
    command: IssueSubcommand,
}

impl IssueCommand {
    fn run(self) -> Result<()> {
        match self.command {
            IssueSubcommand::Preview(args) => {
                let json = args.json;
                let report = publication::preview_issue(issue_options_from_args(
                    args.repo,
                    args.title,
                    args.body,
                    args.body_file,
                    args.label,
                    args.forge,
                )?)?;
                print_query_report(&report, json)
            }
            IssueSubcommand::Create(args) => {
                let json = args.json;
                let report = publication::create_issue(issue_options_from_args(
                    args.repo,
                    args.title,
                    args.body,
                    args.body_file,
                    args.label,
                    args.forge,
                )?)?;
                print_query_report(&report, json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum IssueSubcommand {
    /// Preview issue content after redaction.
    Preview(IssuePreviewArgs),
    /// Create an issue through an explicit forge.
    Create(IssueCreateArgs),
}

#[derive(Debug, Args)]
struct IssuePreviewArgs {
    /// Issue title.
    #[arg(long)]
    title: String,
    /// Issue body text.
    #[arg(long, conflicts_with = "body_file")]
    body: Option<String>,
    /// File containing issue body text.
    #[arg(long, conflicts_with = "body")]
    body_file: Option<PathBuf>,
    /// Issue label. Repeat for multiple labels.
    #[arg(long = "label")]
    label: Vec<String>,
    /// Repository path used only by forge adapters that need repository context.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Forge label recorded in the preview report. Preview never creates remote issues.
    #[arg(long, default_value = "fake", value_parser = parse_forge_kind)]
    forge: ForgeKind,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct IssueCreateArgs {
    /// Issue title.
    #[arg(long)]
    title: String,
    /// Issue body text.
    #[arg(long, conflicts_with = "body_file")]
    body: Option<String>,
    /// File containing issue body text.
    #[arg(long, conflicts_with = "body")]
    body_file: Option<PathBuf>,
    /// Issue label. Repeat for multiple labels.
    #[arg(long = "label")]
    label: Vec<String>,
    /// Repository path used only by forge adapters that need repository context.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Forge adapter. `fake` is deterministic and local-only; `github` shells out explicitly.
    #[arg(long, value_parser = parse_forge_kind)]
    forge: ForgeKind,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn pr_options_from_preview_args(
    args: PrPreviewArgs,
) -> Result<(PrPublicationOptions, ValidationEvidenceBundle)> {
    let agent_id = pr_publication_agent_id(args.agent_id, args.from_branch.as_deref())?;
    let validation_evidence = load_validation_evidence(&args.validation_report, &agent_id)?;
    Ok((
        PrPublicationOptions {
            repo: args.repo,
            agent_id,
            claimed_paths: args.claim,
            validations: Vec::new(),
            forge: args.forge,
            draft: !args.ready,
            from_branch: args.from_branch,
            squash_onto: args.squash_onto,
            exclude_paths: args.exclude,
        },
        validation_evidence,
    ))
}

fn pr_options_from_publish_args(
    args: PrPublishArgs,
) -> Result<(PrPublicationOptions, ValidationEvidenceBundle)> {
    let agent_id = pr_publication_agent_id(args.agent_id, args.from_branch.as_deref())?;
    let validation_evidence = load_validation_evidence(&args.validation_report, &agent_id)?;
    Ok((
        PrPublicationOptions {
            repo: args.repo,
            agent_id,
            claimed_paths: args.claim,
            validations: Vec::new(),
            forge: args.forge,
            draft: !args.ready,
            from_branch: args.from_branch,
            squash_onto: args.squash_onto,
            exclude_paths: args.exclude,
        },
        validation_evidence,
    ))
}

fn pr_publication_agent_id(agent_id: Option<String>, from_branch: Option<&str>) -> Result<String> {
    match (agent_id, from_branch) {
        (Some(agent_id), None) => Ok(agent_id),
        (None, Some(branch)) => publication::branch_publication_agent_id(branch),
        (Some(_), Some(_)) => {
            bail!("agent id positional argument cannot be combined with --from-branch")
        }
        (None, None) => bail!("provide an agent id or --from-branch"),
    }
}

fn issue_options_from_args(
    repo: PathBuf,
    title: String,
    body: Option<String>,
    body_file: Option<PathBuf>,
    labels: Vec<String>,
    forge: ForgeKind,
) -> Result<IssuePublicationOptions> {
    let body = match (body, body_file) {
        (Some(body), None) => body,
        (None, Some(path)) => {
            BoundedRegularReader::read_tree_no_follow_utf8(&path, MAX_ISSUE_BODY_FILE_BYTES)
                .with_context(|| format!("failed to read issue body file {}", path.display()))?
        }
        (None, None) => String::new(),
        (Some(_), Some(_)) => bail!("use either --body or --body-file, not both"),
    };
    Ok(IssuePublicationOptions {
        repo,
        title,
        body,
        labels,
        forge,
    })
}

#[derive(Debug, Serialize)]
struct OrchestrationCollectReport {
    repo: PathBuf,
    summary_json: PathBuf,
    candidates: Vec<MergeCandidate>,
}

fn collect_orchestration_results(
    repo: &Path,
    summary_json: &Path,
    diff_summary_char_limit: usize,
) -> Result<OrchestrationCollectReport> {
    let contents =
        BoundedRegularReader::read_tree_no_follow(summary_json, MAX_ORCHESTRATION_SUMMARY_BYTES)
            .with_context(|| format!("failed to read summary JSON {}", summary_json.display()))?;
    let summary: Value = serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse summary JSON {}", summary_json.display()))?;
    let agents = summary
        .get("agents")
        .and_then(Value::as_array)
        .context("summary JSON must contain an agents array")?;
    if agents.len() > MAX_ORCHESTRATION_SUMMARY_AGENTS {
        bail!("orchestration summary exceeds its {MAX_ORCHESTRATION_SUMMARY_AGENTS}-agent limit");
    }
    let mut candidates = Vec::new();
    let mut total_paths = 0_usize;
    let mut total_reports = 0_usize;

    for agent in agents {
        let agent_id = agent
            .get("id")
            .and_then(Value::as_str)
            .context("summary agent is missing string id")?;
        if agent_id.is_empty() || agent_id.len() > MAX_ORCHESTRATION_AGENT_ID_BYTES {
            bail!("summary agent id must contain 1..={MAX_ORCHESTRATION_AGENT_ID_BYTES} bytes");
        }
        let claims = agent_paths_from_summary(agent)
            .with_context(|| format!("summary agent '{agent_id}' has invalid paths"))?;
        total_paths = total_paths
            .checked_add(claims.len())
            .context("orchestration summary path count overflowed")?;
        if total_paths > MAX_ORCHESTRATION_SUMMARY_PATHS {
            bail!("orchestration summary exceeds its {MAX_ORCHESTRATION_SUMMARY_PATHS}-path limit");
        }
        let validations = validation_reports_from_summary(agent).with_context(|| {
            format!("summary agent '{agent_id}' has invalid validation reports")
        })?;
        validate_cli_validation_reports(&validations)?;
        total_reports = total_reports
            .checked_add(validations.len())
            .context("orchestration summary report count overflowed")?;
        if total_reports > MAX_VALIDATION_REPORTS {
            bail!("orchestration summary exceeds its validation report limit");
        }
        candidates.push(merge::collect_agent_result(MergeCollectOptions {
            repo: repo.to_path_buf(),
            agent_id: agent_id.to_string(),
            claimed_paths: claims,
            include_full_diff: false,
            diff_summary_char_limit,
            validations,
        })?);
    }

    candidates.sort_by(|left, right| left.metadata.agent_id.cmp(&right.metadata.agent_id));
    Ok(OrchestrationCollectReport {
        repo: repo.to_path_buf(),
        summary_json: summary_json.to_path_buf(),
        candidates,
    })
}

fn agent_paths_from_summary(agent: &Value) -> Result<Vec<PathBuf>> {
    let paths = agent
        .get("paths")
        .and_then(Value::as_array)
        .context("agent summary must contain paths array")?;
    paths
        .iter()
        .map(|path| {
            let path = path.as_str().context("agent path must be a string")?;
            if path.len() > 4096 || Path::new(path).components().count() > 256 {
                bail!("agent path exceeds its byte or component limit");
            }
            normalize_repo_relative_path(path).map_err(anyhow::Error::from)
        })
        .collect()
}

fn validation_reports_from_summary(agent: &Value) -> Result<Vec<ValidationReport>> {
    if agent.get("validation").is_some()
        || agent.get("validations").is_some()
        || agent.get("reports").is_some()
    {
        merge::validation_reports_from_json(agent)
    } else {
        Ok(Vec::new())
    }
}

fn load_validation_evidence(paths: &[PathBuf], agent_id: &str) -> Result<ValidationEvidenceBundle> {
    if paths.len() > MAX_VALIDATION_INPUT_FILES {
        bail!("validation evidence exceeds its input file count limit");
    }
    let mut evidence = ValidationEvidenceBundle::default();
    let mut total_bytes = 0_u64;
    let mut total_reports = 0_usize;
    for path in paths {
        let contents =
            BoundedRegularReader::read_tree_no_follow(path, MAX_VALIDATION_INPUT_FILE_BYTES)
                .with_context(|| format!("failed to read validation report {}", path.display()))?;
        total_bytes = total_bytes
            .checked_add(u64::try_from(contents.len()).unwrap_or(u64::MAX))
            .context("validation evidence byte count overflowed")?;
        if total_bytes > MAX_VALIDATION_INPUT_TOTAL_BYTES {
            bail!("validation evidence exceeds its aggregate byte limit");
        }
        let value: Value = serde_json::from_slice(&contents)
            .with_context(|| format!("failed to parse validation report {}", path.display()))?;
        let parsed = merge::validation_evidence_from_json_for_agent(&value, Some(agent_id))
            .with_context(|| format!("invalid validation report {}", path.display()))?;
        let reports = parsed.reports();
        validate_cli_validation_reports(&reports)?;
        total_reports = total_reports
            .checked_add(reports.len())
            .context("validation report count overflowed")?;
        if total_reports > MAX_VALIDATION_REPORTS {
            bail!("validation evidence exceeds its report count limit");
        }
        evidence.extend(parsed);
    }
    Ok(evidence)
}

fn load_reviewed_merge_preview(
    path: Option<&Path>,
) -> Result<Option<merge::MergePreviewFreshnessWatermark>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let contents =
        BoundedRegularReader::read_tree_no_follow(path, MAX_REVIEWED_MERGE_PREVIEW_BYTES)
            .with_context(|| format!("failed to read reviewed merge preview {}", path.display()))?;
    let value = parse_duplicate_rejecting_json_value(&contents).map_err(|error| {
        merge::MergePreviewFreshnessError::MalformedWatermark {
            message: format!("reviewed preview is not valid JSON: {error}"),
        }
    })?;
    merge::reviewed_merge_preview_watermark_from_json(&value)
        .map(Some)
        .with_context(|| format!("invalid reviewed merge preview {}", path.display()))
}

#[derive(Debug, Clone, Copy)]
struct DuplicateRejectingJsonValueSeed;

impl<'de> DeserializeSeed<'de> for DuplicateRejectingJsonValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingJsonValueVisitor)
    }
}

#[derive(Debug, Clone, Copy)]
struct DuplicateRejectingJsonValueVisitor;

impl<'de> Visitor<'de> for DuplicateRejectingJsonValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateRejectingJsonValueSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(DuplicateRejectingJsonValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(<A::Error as de::Error>::custom(format!(
                    "duplicate object key {key:?}"
                )));
            }
            let value = object.next_value_seed(DuplicateRejectingJsonValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn parse_duplicate_rejecting_json_value(
    contents: &[u8],
) -> std::result::Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(contents);
    let value = DuplicateRejectingJsonValueSeed.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

fn validate_cli_validation_reports(reports: &[ValidationReport]) -> Result<()> {
    if reports.len() > MAX_VALIDATION_REPORTS {
        bail!("validation evidence exceeds its report count limit");
    }
    for report in reports {
        if report.name.len() > MAX_VALIDATION_REPORT_NAME_BYTES
            || report
                .message
                .as_ref()
                .is_some_and(|message| message.len() > MAX_VALIDATION_REPORT_MESSAGE_BYTES)
            || report.paths.len() > MAX_VALIDATION_REPORT_PATHS
        {
            bail!("validation report exceeds its structural input limits");
        }
        for path in &report.paths {
            if path.as_os_str().len() > 4096 || path.components().count() > 256 {
                bail!("validation report path exceeds its input limits");
            }
            normalize_repo_relative_path(path)
                .context("validation report path must be repository-relative")?;
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct SemanticSymbolQueryReport {
    query: String,
    matches: Vec<repo_semantic::SemanticSymbol>,
}

#[derive(Debug, Serialize)]
struct SemanticRiskQueryReport {
    #[serde(flatten)]
    semantic: repo_semantic::SemanticRiskReport,
    megafile_hotspots: Vec<MegafileAssessment>,
}

impl SemanticSymbolQueryReport {
    fn from_map(map: &SemanticRepoMap, query: &str) -> Self {
        let mut matches = map
            .symbols
            .iter()
            .filter(|symbol| symbol.name == query || symbol.qualified_path.join("::") == query)
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.span.cmp(&right.span))
                .then_with(|| left.name.cmp(&right.name))
        });
        Self {
            query: query.to_string(),
            matches,
        }
    }
}

#[derive(Debug, Serialize)]
struct SemanticPathQueryReport {
    query: PathBuf,
    files: Vec<repo_semantic::SemanticFile>,
    symbols: Vec<repo_semantic::SemanticSymbol>,
    imports: Vec<repo_semantic::SemanticImport>,
    re_exports: Vec<repo_semantic::SemanticReExport>,
    dependencies: Vec<repo_semantic::SemanticDependency>,
    errors: Vec<repo_semantic::SemanticScanError>,
}

impl SemanticPathQueryReport {
    fn from_map(map: &SemanticRepoMap, query: &Path) -> Self {
        let query = normalize_display_path(query);
        Self {
            query: query.clone(),
            files: map
                .files
                .iter()
                .filter(|file| file.path == query)
                .cloned()
                .collect(),
            symbols: map
                .symbols
                .iter()
                .filter(|symbol| symbol.file == query)
                .cloned()
                .collect(),
            imports: map
                .imports
                .iter()
                .filter(|import| import.file == query)
                .cloned()
                .collect(),
            re_exports: map
                .re_exports
                .iter()
                .filter(|export| export.file == query)
                .cloned()
                .collect(),
            dependencies: map
                .dependencies
                .iter()
                .filter(|dependency| {
                    dependency.from_file == query
                        || dependency.to_file.as_deref() == Some(query.as_path())
                })
                .cloned()
                .collect(),
            errors: map
                .errors
                .iter()
                .filter(|error| error.file == query)
                .cloned()
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
struct LlmProvidersReport {
    providers: Vec<LlmProviderInfo>,
    network_providers_required: bool,
    network_providers_configured: bool,
}

#[derive(Debug, Serialize)]
struct LlmProviderInfo {
    id: String,
    model: String,
    kind: String,
    configured: bool,
    network_required: bool,
    notes: String,
    capabilities: ProviderCapabilities,
}

#[derive(Debug, Serialize)]
struct LlmPromptPreviewReport {
    task_file: PathBuf,
    agent_id: String,
    claimed_paths: Vec<PathBuf>,
    prompt: crate::llm::Prompt,
    rendered: String,
    redactions: crate::llm::RedactionSummary,
    provider: LlmProviderInfo,
}

fn build_prompt_preview(args: LlmPromptPreviewArgs) -> Result<LlmPromptPreviewReport> {
    let repo = discover_repo_root(&args.repo)?;
    let task =
        BoundedRegularReader::read_tree_no_follow_utf8(&args.task_file, MAX_PROMPT_TASK_BYTES)
            .with_context(|| format!("failed to read task file {}", args.task_file.display()))?;
    let mut context = PromptContext::new(task, &args.agent_id);
    if args.paths.len() > MAX_PROMPT_PATHS {
        bail!("prompt preview exceeds its {MAX_PROMPT_PATHS}-path input limit");
    }
    let mut claimed_paths = args
        .paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    claimed_paths.sort();
    claimed_paths.dedup();

    let mut excerpt_bytes = 0_usize;
    for path in &claimed_paths {
        context = context.with_claimed_path(path.clone(), "explicit prompt preview path");
        let content = BoundedRegularReader::read_relative_optional_utf8(
            &repo,
            path,
            MAX_PROMPT_EXCERPT_BYTES,
        )
        .with_context(|| format!("failed to read prompt path {}", path.display()))?;
        let Some(content) = content else {
            continue;
        };
        excerpt_bytes = excerpt_bytes
            .checked_add(content.len())
            .context("prompt preview excerpt byte count overflowed")?;
        if excerpt_bytes > MAX_PROMPT_EXCERPT_TOTAL_BYTES {
            bail!(
                "prompt preview excerpts exceed their {MAX_PROMPT_EXCERPT_TOTAL_BYTES}-byte aggregate limit"
            );
        }
        context = context.with_repo_excerpt(
            RepoExcerpt::new(path.clone(), content).with_language(language_for_path(path)),
        );
    }

    let provider = LlmProviderInfo {
        id: "fake".to_string(),
        model: "deterministic-fake".to_string(),
        kind: "local_fake".to_string(),
        configured: true,
        network_required: false,
        notes: "Prompt preview only; no provider call is made.".to_string(),
        capabilities: ProviderCapabilities::local_fake(),
    };
    let prompt = context.assemble_prompt(&Redactor::new());
    let rendered = prompt.render();
    if rendered.chars().count() > context.budget.max_input_chars {
        bail!(
            "prompt preview exceeds its {}-character input budget",
            context.budget.max_input_chars
        );
    }
    let redactions = prompt.redactions.clone();

    Ok(LlmPromptPreviewReport {
        task_file: args.task_file,
        agent_id: args.agent_id,
        claimed_paths,
        prompt,
        rendered,
        redactions,
        provider,
    })
}

fn run_agent_from_args(_args: RunAgentArgs) -> Result<AgentRunReport> {
    bail!(
        "agent assignment creation is temporarily unsupported because managed worktree creation requires a capability-bound repository cleanliness input"
    )
}

#[allow(dead_code)]
fn run_agent_from_args_disabled_legacy(args: RunAgentArgs) -> Result<AgentRunReport> {
    if args.provider != "fake" {
        bail!(
            "provider '{}' is not configured for agent run; only local fake is available",
            args.provider
        );
    }

    let proposal_path = args
        .fake_proposal
        .context("fake provider agent run requires --fake-proposal <proposal.json>")?;
    let proposal = load_fake_proposal(&proposal_path)?;
    let task =
        BoundedRegularReader::read_tree_no_follow_utf8(&args.task_file, MAX_AGENT_TASK_BYTES)
            .with_context(|| format!("failed to read task file {}", args.task_file.display()))?;
    let request_id = args
        .request_id
        .unwrap_or_else(|| agent::default_request_id(&args.agent_id));
    let model = args
        .model
        .unwrap_or_else(|| agent::default_model().to_string());
    let mut provider = FakeProvider::new("fake", model.clone());
    provider.push_response(request_id.clone(), proposal);

    agent::run_agent_with_provider(
        AgentRunOptions {
            repo: args.repo,
            agent_id: args.agent_id,
            task,
            request_id: Some(request_id),
            model: Some(model),
            claimed_paths: args.paths,
            validation_commands: args
                .validation_commands
                .into_iter()
                .map(AgentValidationCommand::required)
                .collect(),
            keep_claims: args.keep_claims,
            worktree_reuse: args.reuse,
            provider_command_policy: if args.allow_provider_commands {
                ProviderCommandPolicy::AllowUnsafeShell
            } else {
                ProviderCommandPolicy::Disabled
            },
            command_timeout: Duration::from_secs(args.command_timeout_seconds),
        },
        &mut provider,
    )
}

fn load_fake_proposal(path: &Path) -> Result<WorkProposal> {
    let contents = BoundedRegularReader::read_tree_no_follow(path, MAX_FAKE_PROPOSAL_BYTES)
        .with_context(|| format!("failed to read fake proposal {}", path.display()))?;
    let proposal: WorkProposal = serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse fake proposal {}", path.display()))?;
    if proposal.commands.len() > MAX_FAKE_PROPOSAL_ITEMS
        || proposal.patches.len() > MAX_FAKE_PROPOSAL_ITEMS
        || proposal.notes.len() > MAX_FAKE_PROPOSAL_ITEMS
        || proposal.rendered_len() > 32 * 1024
    {
        bail!("fake proposal exceeds its structural or output budget");
    }
    Ok(proposal)
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

fn normalize_display_path(path: impl AsRef<Path>) -> PathBuf {
    path.as_ref().components().collect()
}

fn language_for_path(path: &Path) -> String {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("rs") => "rust",
        Some("md") => "markdown",
        Some("toml") => "toml",
        Some("json") => "json",
        Some("yaml" | "yml") => "yaml",
        Some("sh" | "bash") => "shell",
        _ => "text",
    }
    .to_string()
}

fn parse_agent_worktree_reuse_policy(
    value: &str,
) -> std::result::Result<AgentWorktreeReusePolicy, String> {
    match value {
        "clean" => Ok(AgentWorktreeReusePolicy::Clean),
        "required" => Ok(AgentWorktreeReusePolicy::Required),
        "fresh" => Ok(AgentWorktreeReusePolicy::Fresh),
        _ => Err("expected one of: clean, required, fresh".to_string()),
    }
}

fn parse_positive_seconds(value: &str) -> std::result::Result<u64, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| "expected a positive integer number of seconds".to_string())?;
    if seconds == 0 {
        Err("timeout must be greater than zero seconds".to_string())
    } else {
        Ok(seconds)
    }
}

fn parse_positive_usize(value: &str) -> std::result::Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| "expected a positive integer".to_string())?;
    if value == 0 {
        Err("value must be greater than zero".to_string())
    } else {
        Ok(value)
    }
}

fn parse_positive_finite_f64(value: &str) -> std::result::Result<f64, String> {
    let value = value
        .parse::<f64>()
        .map_err(|_| "expected a finite positive number".to_string())?;
    if !value.is_finite() || value <= 0.0 {
        Err("value must be finite and greater than zero".to_string())
    } else {
        Ok(value)
    }
}

fn parse_worktree_reuse_policy(value: &str) -> std::result::Result<WorktreeReusePolicy, String> {
    match value {
        "clean" => Ok(WorktreeReusePolicy::Clean),
        "required" => Ok(WorktreeReusePolicy::Required),
        "fresh" => Ok(WorktreeReusePolicy::Fresh),
        "reset" => Ok(WorktreeReusePolicy::Reset),
        _ => Err("expected one of: clean, required, fresh, reset".to_string()),
    }
}

fn parse_semantic_coordination_mode(
    value: &str,
) -> std::result::Result<SemanticCoordinationMode, String> {
    match value {
        "off" => Ok(SemanticCoordinationMode::Off),
        "warn" => Ok(SemanticCoordinationMode::Warn),
        "block" => Ok(SemanticCoordinationMode::Block),
        _ => Err("expected one of: off, warn, block".to_string()),
    }
}

fn parse_forge_kind(value: &str) -> std::result::Result<ForgeKind, String> {
    ForgeKind::parse(value)
}

fn parse_inbox_permission_mode(value: &str) -> std::result::Result<InboxPermissionMode, String> {
    InboxPermissionMode::parse(value)
}

fn parse_evaluation_execution(
    value: &str,
) -> std::result::Result<crate::evaluation::EvaluationExecution, String> {
    match value {
        "deterministic-fake" => Ok(crate::evaluation::EvaluationExecution::DeterministicFake),
        "real-provider" => Ok(crate::evaluation::EvaluationExecution::RealProvider),
        _ => Err("expected one of: deterministic-fake, real-provider".to_string()),
    }
}

fn live_clock(value: Option<&str>) -> Result<LiveClock> {
    match value {
        Some(value) => LiveClock::parse(value),
        None => Ok(LiveClock::now()),
    }
}

fn print_repository_info(info: &RepositoryInfo, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(info)?);
    } else {
        let head = info.head.as_deref().unwrap_or("<unborn>");
        println!("Repository: {}", info.path.display());
        println!("Git dir: {}", info.git_dir.display());
        println!("HEAD: {head}");
    }
    Ok(())
}

fn print_repo_map(map: &RepoMap, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(map)?);
    } else if map.entries.is_empty() {
        println!("Repository: {}", map.root.display());
        println!("No entries found.");
    } else {
        println!("Repository: {}", map.root.display());
        for entry in &map.entries {
            let size = entry
                .size_bytes
                .map(|size| size.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{}\t{}\t{}\t{}",
                entry.path.display(),
                repo_entry_kind_label(entry.kind),
                size,
                entry.category
            );
        }
    }
    Ok(())
}

fn print_semantic_repo_map(map: &SemanticRepoMap, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(map)?);
    } else {
        println!("Repository: {}", map.root.display());
        println!("Rust files: {}", map.files.len());
        println!("Symbols: {}", map.symbols.len());
        println!("Imports: {}", map.imports.len());
        println!("Re-exports: {}", map.re_exports.len());
        println!("Dependencies: {}", map.dependencies.len());
        if !map.errors.is_empty() {
            println!("Errors: {}", map.errors.len());
        }
        for symbol in &map.symbols {
            println!(
                "{}\t{:?}\t{}",
                symbol.file.display(),
                symbol.kind,
                symbol.qualified_path.join("::")
            );
        }
    }
    Ok(())
}

fn print_query_report<T: Serialize + std::fmt::Debug>(report: &T, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("{report:#?}");
    }
    Ok(())
}

fn resolve_run_id_for_run(
    repo: &Path,
    family: RunArtifactFamily,
    explicit: Option<&str>,
    json: bool,
) -> Result<ResolvedRunId> {
    match artifacts::resolve_run_id(repo, family, explicit) {
        Ok(resolved) => Ok(resolved),
        Err(error) => {
            if json {
                let report = RunArtifactRefusalReport::new(repo, family, explicit, &error);
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            Err(error)
        }
    }
}

#[derive(Debug, Serialize)]
struct RunArtifactRefusalReport {
    family: RunArtifactFamily,
    success: bool,
    status: &'static str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_dir: Option<PathBuf>,
    error_kind: &'static str,
    message: String,
    next_action: &'static str,
}

impl RunArtifactRefusalReport {
    fn new(
        repo: &Path,
        family: RunArtifactFamily,
        explicit: Option<&str>,
        error: &anyhow::Error,
    ) -> Self {
        let run_id = explicit.map(ToOwned::to_owned);
        let run_dir = explicit
            .and_then(|value| RunId::new(value).ok())
            .and_then(|run_id| {
                artifacts::discover_repo_root(repo)
                    .ok()
                    .map(|repo| (repo, run_id))
            })
            .map(|(_, run_id)| family.run_root().join(run_id.as_str()));
        Self {
            family,
            success: false,
            status: "refused",
            run_id,
            run_dir,
            error_kind: "run_artifact_refused",
            message: error.to_string(),
            next_action: "choose a new --run-id or prune old artifacts first",
        }
    }
}

fn print_semantic_coordination_report(
    report: &SemanticCoordinationReport,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("Semantic intent: {}", report.intent.token.get());
        println!("Agent: {}", report.intent.agent_id);
        println!("Persisted: {}", report.persisted);
        println!(
            "Conflicts: blocking={} advisory={}",
            report.blocking_conflict_count, report.advisory_conflict_count
        );
        for conflict in &report.conflicts {
            println!(
                "  {:?}\t{:?}\t{}",
                conflict.severity, conflict.kind, conflict.message
            );
        }
    }
    Ok(())
}

fn print_merge_candidate(candidate: &MergeCandidate, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(candidate)?);
    } else {
        println!("Agent: {}", candidate.metadata.agent_id);
        println!("Worktree: {}", candidate.metadata.worktree_path.display());
        println!("Changed paths: {}", candidate.changed_paths.len());
        for path in &candidate.changed_paths {
            println!("  {}", path.display());
        }
        if !candidate.unclaimed_changed_paths.is_empty() {
            println!("Unclaimed edits:");
            for path in &candidate.unclaimed_changed_paths {
                println!("  {}", path.display());
            }
        }
        if !candidate.diff.summary.text.is_empty() {
            println!("{}", candidate.diff.summary.text);
        }
    }
    Ok(())
}

fn print_merge_preview(
    preview: &MergeApplyPreview,
    freshness_watermark: &merge::MergePreviewFreshnessWatermark,
    json: bool,
) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&merge::MergeApplyPreviewOutput {
                preview,
                freshness_watermark,
            })?
        );
    } else {
        print_merge_candidate(&preview.candidate, false)?;
        println!(
            "Freshness watermark: {}",
            serde_json::to_string(freshness_watermark)?
        );
        println!("Readiness: {:?}", preview.safety.readiness.status);
        if !preview.safety.readiness.blockers.is_empty() {
            println!("Blockers: {:?}", preview.safety.readiness.blockers);
        }
        if !preview.safety.readiness.forced.is_empty() {
            println!("Forced: {:?}", preview.safety.readiness.forced);
        }
        for warning in &preview.safety.megafile_warnings {
            println!(
                "Megafile warning: {} ({:?})",
                warning.path.display(),
                warning.signals
            );
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct MergeApplyReportOutput<'a> {
    #[serde(flatten)]
    report: &'a MergeApplyReport,
    review_bound: bool,
    review_binding_status: &'static str,
}

fn merge_apply_report_output(
    report: &MergeApplyReport,
    review_bound: bool,
) -> MergeApplyReportOutput<'_> {
    MergeApplyReportOutput {
        report,
        review_bound,
        review_binding_status: if review_bound {
            "matched"
        } else {
            "not_supplied"
        },
    }
}

fn print_merge_apply_report(
    report: &MergeApplyReport,
    json: bool,
    review_bound: bool,
) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&merge_apply_report_output(report, review_bound))?
        );
    } else {
        println!(
            "Merge apply: {}",
            if report.applied {
                "applied"
            } else {
                "nothing to apply"
            }
        );
        println!("Readiness: {:?}", report.preview.safety.readiness.status);
        println!(
            "Review-bound: {} ({})",
            review_bound,
            if review_bound {
                "matched"
            } else {
                "not_supplied"
            }
        );
        if !report.recorded_collision_paths.is_empty() {
            println!("Recorded merge collision paths:");
            for path in &report.recorded_collision_paths {
                println!("  {}", path.display());
            }
        }
        if let Some(decomposition) = &report.accepted_decomposition {
            println!(
                "Accepted megafile decomposition: {}",
                decomposition.path.display()
            );
        }
        if let Some(lifecycle) = &report.lifecycle {
            print_worktree_lifecycle_report(lifecycle, false)?;
        }
        if let Some(error) = &report.error {
            println!("Error: {error}");
        }
    }
    Ok(())
}

fn print_merge_arbitration_report(report: &MergeArbitrationReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!("Merge arbitration outcome: {:?}", report.outcome);
    println!("Run: {}", report.run_id);
    println!("Neutral arbiter: {}", report.arbiter_id);
    println!(
        "Neutral worktree: {} ({})",
        report.neutral_worktree.path.display(),
        report.neutral_worktree.branch
    );
    println!("Exact reviewed base: {}", report.reviewed_base_oid);
    println!("First side: {:?}", report.sides[0]);
    println!("Second side: {:?}", report.sides[1]);
    println!("Approved: {}", report.approved);
    println!(
        "Rationale artifact: {} sha256={}",
        report.rationale_artifact, report.rationale_sha256
    );
    if let Some(candidate_artifact) = &report.candidate_artifact {
        let candidate_sha256 = report
            .candidate_sha256
            .as_deref()
            .context("arbitration candidate artifact is missing its digest")?;
        println!(
            "Candidate artifact: {} sha256={}",
            candidate_artifact, candidate_sha256
        );
    } else {
        println!("Candidate artifact: none");
    }
    println!("Candidate status: {:?}", report.candidate_status);
    println!("Validation commands:");
    for command in &report.validation_commands {
        println!("  {command}");
    }
    println!("Primary worktree mutated: {}", report.primary_mutated);
    println!(
        "Later ordinary human-invoked merge apply required: {}",
        report.later_ordinary_merge_apply_required
    );
    println!(
        "Arbitration never applies to primary; use a later ordinary merge preview/apply gate."
    );
    Ok(())
}

fn print_pr_publication_report(report: &PrPublicationReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("PR publication: {:?}", report.status);
        println!("Agent: {}", report.agent_id);
        println!("Branch: {}", report.branch);
        println!("Base: {}", report.base);
        println!("Readiness: {:?}", report.readiness);
        if !report.blockers.is_empty() {
            println!("Blockers: {:?}", report.blockers);
        }
        if let Some(url) = &report.pr_url {
            println!("URL: {url}");
        }
        println!("Next: {}", report.next_action);
    }
    Ok(())
}

fn repo_entry_kind_label(kind: RepoEntryKind) -> &'static str {
    match kind {
        RepoEntryKind::Directory => "dir",
        RepoEntryKind::File => "file",
        RepoEntryKind::Symlink => "symlink",
        RepoEntryKind::Other => "other",
    }
}

#[derive(Debug, Serialize)]
struct PlanValidationReport {
    plan_file: PathBuf,
    agent_count: usize,
    path_claim_count: usize,
    dependency_count: usize,
}

fn print_plan_validation_report(report: &PlanValidationReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("Plan valid: {}", report.plan_file.display());
        println!("Agents: {}", report.agent_count);
        println!("Path claims: {}", report.path_claim_count);
        println!("Dependencies: {}", report.dependency_count);
    }
    Ok(())
}

fn print_orchestration_summary(summary: &OrchestrationSummary, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(summary)?);
    } else {
        let status = if summary.success {
            "succeeded"
        } else {
            "failed"
        };
        println!("Orchestration: {status}");
        println!("Repository: {}", summary.repo.display());
        for agent in &summary.agents {
            let exit = agent
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{}\t{}\texit={}\t{}",
                agent.id,
                agent_status_label(agent.status),
                exit,
                agent
                    .worktree
                    .as_ref()
                    .map(|worktree| worktree.path.display().to_string())
                    .unwrap_or_else(|| "<no worktree>".to_string())
            );
            if let Some(error) = &agent.error {
                println!("  {error}");
            }
        }
        if !summary.release_errors.is_empty() {
            println!("Release errors:");
            for error in &summary.release_errors {
                println!("  {error}");
            }
        }
    }
    Ok(())
}

fn print_agent_run_report(report: &AgentRunReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        let status = if report.success {
            "succeeded"
        } else {
            "failed"
        };
        println!("Agent run: {status}");
        println!("Agent: {}", report.agent_id);
        println!("Provider: {}", report.provider_id);
        println!("Worktree: {}", report.worktree.path.display());
        println!("Changed paths: {}", report.candidate.changed_paths.len());
        for path in &report.candidate.changed_paths {
            println!("  {}", path.display());
        }
        if !report.candidate.unclaimed_changed_paths.is_empty() {
            println!("Unclaimed edits:");
            for path in &report.candidate.unclaimed_changed_paths {
                println!("  {}", path.display());
            }
        }
        if let Some(error) = &report.error {
            println!("  {error}");
        }
    }
    Ok(())
}

fn print_agent_run_failure_report(report: &AgentRunFailureReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn print_agent_processes(processes: &[AgentProcessRecord], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(processes)?);
    } else if processes.is_empty() {
        println!("No live MACO agents registered.");
    } else {
        for process in processes {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                process.pid,
                process.role,
                process.run_id,
                process.task_id,
                process.repo.display(),
                process.launch_timestamp_ms,
                process.argv.join(" ")
            );
        }
    }
    Ok(())
}

fn print_agent_stop_report(report: &AgentStopReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if report.stopped.is_empty() {
        println!("No live MACO agents matched the selected run.");
    } else {
        for stopped in &report.stopped {
            println!(
                "{:?}\t{}\t{}\t{}",
                stopped.outcome,
                stopped.process.pid,
                stopped.process.run_id,
                stopped.process.task_id
            );
        }
    }
    Ok(())
}

fn print_worktree_lifecycle_report(report: &WorktreeLifecycleReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "Worktree lifecycle: {} ({})",
        if report.enabled {
            "enabled"
        } else {
            "disabled"
        },
        if report.dry_run { "dry-run" } else { "apply" }
    );
    println!("Merged auto-reap: {}", report.auto_reap_merged);
    println!(
        "Retry supersession: {:?}{}",
        report.retry.status,
        report
            .retry
            .predecessor_agent_id
            .as_deref()
            .map(|agent_id| format!(" ({agent_id})"))
            .unwrap_or_default()
    );
    if report.reconciliation.enabled {
        println!(
            "Startup reconciliation: {} finding(s), {} record(s) forgotten, {} registration(s) pruned, {} directory(s) quarantined",
            report.reconciliation.entries.len(),
            report.reconciliation.forgotten_record_count,
            report.reconciliation.pruned_registration_count,
            report.reconciliation.quarantined_directory_count,
        );
        for entry in &report.reconciliation.entries {
            println!(
                "  {}\t{:?}\t{:?}\t{}",
                entry.name,
                entry.state,
                entry.action,
                entry.path.display()
            );
        }
    }
    if let Some(gc) = &report.worktree_gc {
        println!(
            "Worktrees: considered={}, {}={}, retained={}, protected={}",
            gc.considered_count,
            if gc.dry_run {
                "would_remove"
            } else {
                "removed"
            },
            gc.removed_count,
            gc.retained_count,
            gc.protected_count
        );
    }
    println!(
        "Git worktree prune: {:?}, stale={}, pruned={}, protected={}",
        report.repository_prune.status,
        report.repository_prune.stale_registration_count,
        report.repository_prune.pruned_registration_count,
        report.repository_prune.protected_registration_count,
    );
    if let Some(artifacts) = &report.artifact_prune {
        println!(
            "O2-launch artifacts: candidates={}, deleted={}, kept={}, refused={}",
            artifacts.delete_candidate_count,
            artifacts.deleted_count,
            artifacts.kept_count,
            artifacts.refused_unfinalized_count
        );
        println!(
            "Artifact safety: reclaim_unverifiable={}, external_writers_stopped={}",
            artifacts.reclaim_unverifiable, artifacts.external_writers_stopped
        );
    }
    println!("Apparent bytes checked: {}", report.apparent_checked_bytes);
    println!(
        "Projected reclaimable bytes: {}",
        report.projected_reclaimable_bytes
    );
    println!(
        "Actually reclaimed bytes: {}",
        report.actual_reclaimed_bytes
    );
    Ok(())
}

fn agent_status_label(status: AgentRunStatus) -> &'static str {
    match status {
        AgentRunStatus::Pending => "pending",
        AgentRunStatus::Succeeded => "succeeded",
        AgentRunStatus::Failed => "failed",
        AgentRunStatus::Skipped => "skipped",
    }
}

fn print_worktree_record(record: &WorktreeRecord, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(record)?);
    } else {
        println!("Worktree: {}", record.name);
        println!("Branch: {}", record.branch);
        println!("Path: {}", record.path.display());
    }
    Ok(())
}

fn print_worktree_create_lifecycle_report(
    record: &WorktreeRecord,
    lifecycle: &WorktreeLifecycleReport,
    json: bool,
) -> Result<()> {
    if json {
        #[derive(Serialize)]
        struct Report<'a> {
            worktree: &'a WorktreeRecord,
            lifecycle: &'a WorktreeLifecycleReport,
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&Report {
                worktree: record,
                lifecycle,
            })?
        );
    } else {
        print_worktree_record(record, false)?;
        print_worktree_lifecycle_report(lifecycle, false)?;
    }
    Ok(())
}

fn print_worktree_gc_report(report: &WorktreeGcReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "Worktree GC: {}{}",
        if report.dry_run { "dry-run" } else { "applied" },
        if report.targets_only {
            " targets-only"
        } else {
            ""
        }
    );
    println!("Considered: {}", report.considered_count);
    println!("Removed: {}", report.removed_count);
    println!("Protected: {}", report.protected_count);
    println!("Retained: {}", report.retained_count);
    println!("Targets cleaned: {}", report.target_removed_count);
    println!("Orphans pruned: {}", report.orphan_removed_count);
    println!(
        "Apparent bytes considered: {}",
        report.apparent_considered_bytes
    );
    println!(
        "Estimated bytes reclaimable: {}",
        report.estimated_reclaimable_bytes
    );
    println!(
        "Estimated bytes reclaimed: {}",
        report.estimated_reclaimed_bytes
    );
    for path in &report.allowed_untracked_paths {
        println!(
            "Allowed untracked path: {}",
            worktree_report_path_text(path)
        );
    }
    for entry in &report.entries {
        let branch = entry.branch.as_deref().unwrap_or("-");
        let target = entry
            .target_path
            .as_ref()
            .map(|path| format!(" target={}", path.display()))
            .unwrap_or_default();
        let gate_denial = entry
            .gate_denial
            .as_ref()
            .map(|denial| format!(" gate-denial={}", denial.denial_id.as_str()))
            .unwrap_or_default();
        let retention = entry
            .retention_operation_id
            .map(|operation_id| format!(" retention-operation={}", operation_id.get()))
            .unwrap_or_default();
        let untracked = worktree_gc_untracked_suffix(&entry.untracked_paths);
        let liveness = worktree_target_liveness_suffix(entry.target_liveness.as_ref());
        println!(
            "{}\t{}\t{}\t{}\t{}{}{}{}{}{}",
            worktree_gc_status_label(entry.status),
            worktree_gc_reason_label(entry.reason),
            entry.name,
            branch,
            entry.path.display(),
            target,
            gate_denial,
            retention,
            untracked,
            liveness
        );
    }
    Ok(())
}

fn print_worktree_sweep_report(report: &WorktreeSweepReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    let removal_label = if report.dry_run {
        "Would remove"
    } else {
        "Removed"
    };
    let target_label = if report.dry_run {
        "Targets would clean"
    } else {
        "Targets cleaned"
    };
    let target_action_count = if report.dry_run {
        report
            .repositories
            .iter()
            .filter_map(|repository| repository.gc_report.as_ref())
            .map(worktree_gc_target_action_count)
            .sum()
    } else {
        report.target_removed_count
    };
    let orphan_label = if report.dry_run {
        "Orphans would prune"
    } else {
        "Orphans pruned"
    };
    println!(
        "Workspace worktree sweep: {}{}",
        if report.dry_run { "dry-run" } else { "applied" },
        if report.targets_only {
            " targets-only"
        } else {
            ""
        }
    );
    println!("Workspace: {}", report.workspace.display());
    println!(
        "Discovery: {} (roots={})",
        worktree_sweep_discovery_status_label(report.discovery_status),
        report.worktree_root_discovered_count
    );
    if let Some(warning) = worktree_sweep_discovery_warning(report.discovery_status) {
        println!("{warning}");
    }
    for path in &report.allowed_untracked_paths {
        println!(
            "Allowed untracked path: {}",
            worktree_report_path_text(path)
        );
    }
    println!(
        "Discovered roots: total={} inspected={} skipped-before-gc={} gc-failed={} total-failures={}",
        report.repository_discovered_count,
        report.repository_inspected_count,
        report.repository_pre_gc_skipped_count,
        report.repository_gc_failed_count,
        report.repository_failure_count
    );
    println!("Considered: {}", report.considered_count);
    println!("{removal_label}: {}", report.removed_count);
    println!("Protected: {}", report.protected_count);
    println!("Retained: {}", report.retained_count);
    println!("{target_label}: {target_action_count}");
    println!("{orphan_label}: {}", report.orphan_removed_count);
    println!(
        "Apparent bytes considered: {}",
        report.apparent_considered_bytes
    );
    println!(
        "Estimated bytes reclaimable: {}",
        report.estimated_reclaimable_bytes
    );
    println!(
        "Estimated bytes reclaimed: {}",
        report.estimated_reclaimed_bytes
    );

    for repository in &report.repositories {
        let resolved_repository = repository
            .repository
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string());
        println!(
            "Repository group={} root-kind={} status={} repository={} worktree-root={} gc-attempted={} effects-may-have-occurred={}",
            repository.group,
            worktree_sweep_root_kind_label(repository.root_kind),
            worktree_sweep_repository_status_label(repository.status),
            resolved_repository,
            repository.worktree_root.display(),
            repository.gc_attempted,
            repository.effects_may_have_occurred
        );
        if let Some(failure) = &repository.failure {
            println!(
                "  Failure: kind={} message={}",
                worktree_sweep_failure_kind_label(failure.kind),
                failure.message
            );
        }
        if let Some(gc_report) = &repository.gc_report {
            let target_action_label = if gc_report.dry_run {
                "targets-would-clean"
            } else {
                "targets-cleaned"
            };
            println!(
                "  GC: considered={} {}={} protected={} retained={} {}={} orphans={} apparent-bytes={} reclaimable-bytes={} reclaimed-bytes={}",
                gc_report.considered_count,
                if gc_report.dry_run {
                    "would-remove"
                } else {
                    "removed"
                },
                gc_report.removed_count,
                gc_report.protected_count,
                gc_report.retained_count,
                target_action_label,
                worktree_gc_target_action_count(gc_report),
                gc_report.orphan_removed_count,
                gc_report.apparent_considered_bytes,
                gc_report.estimated_reclaimable_bytes,
                gc_report.estimated_reclaimed_bytes
            );
            for entry in &gc_report.entries {
                let branch = entry.branch.as_deref().unwrap_or("-");
                let untracked = worktree_gc_untracked_suffix(&entry.untracked_paths);
                let liveness = worktree_target_liveness_suffix(entry.target_liveness.as_ref());
                println!(
                    "    {}\t{}\t{}\t{}\t{}{}{}",
                    worktree_gc_status_label(entry.status),
                    worktree_gc_reason_label(entry.reason),
                    entry.name,
                    branch,
                    entry.path.display(),
                    untracked,
                    liveness
                );
            }
        }
    }
    Ok(())
}

fn worktree_gc_untracked_suffix(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        String::new()
    } else {
        format!(
            " untracked={}",
            paths
                .iter()
                .map(|path| worktree_report_path_text(path))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

fn worktree_target_liveness_suffix(evidence: Option<&WorktreeTargetLivenessEvidence>) -> String {
    let Some(evidence) = evidence else {
        return String::new();
    };
    format!(
        " target-liveness-pid={} target-liveness-source={} target-liveness-cause={}",
        evidence
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "-".to_string()),
        worktree_target_liveness_source_label(evidence.source),
        worktree_target_liveness_cause_label(evidence.cause),
    )
}

fn worktree_target_liveness_source_label(source: WorktreeTargetLivenessSource) -> &'static str {
    match source {
        WorktreeTargetLivenessSource::CargoTargetDir => "cargo-target-dir",
        WorktreeTargetLivenessSource::DefaultCargoTarget => "default-cargo-target",
        WorktreeTargetLivenessSource::ProcessEnvironment => "process-environment",
        WorktreeTargetLivenessSource::ProcessCommandLine => "process-command-line",
        WorktreeTargetLivenessSource::ProcessCwd => "process-cwd",
        WorktreeTargetLivenessSource::ProcessExecutable => "process-executable",
        WorktreeTargetLivenessSource::ProcessFileDescriptor => "process-file-descriptor",
        WorktreeTargetLivenessSource::ProcScan => "proc-scan",
        WorktreeTargetLivenessSource::MountNamespace => "mount-namespace",
        WorktreeTargetLivenessSource::Platform => "platform",
        WorktreeTargetLivenessSource::TargetIdentity => "target-identity",
    }
}

fn worktree_target_liveness_cause_label(cause: WorktreeTargetLivenessCause) -> &'static str {
    match cause {
        WorktreeTargetLivenessCause::PathOverlap => "path-overlap",
        WorktreeTargetLivenessCause::CargoLikeProcessInLane => "cargo-like-process-in-lane",
        WorktreeTargetLivenessCause::ReadFailed => "read-failed",
        WorktreeTargetLivenessCause::InvalidValue => "invalid-value",
        WorktreeTargetLivenessCause::LimitExceeded => "limit-exceeded",
        WorktreeTargetLivenessCause::TimedOut => "timed-out",
        WorktreeTargetLivenessCause::Unsupported => "unsupported",
        WorktreeTargetLivenessCause::NamespaceUnresolved => "namespace-unresolved",
        WorktreeTargetLivenessCause::IdentityChanged => "identity-changed",
    }
}

fn worktree_sweep_discovery_status_label(status: WorktreeSweepDiscoveryStatus) -> &'static str {
    match status {
        WorktreeSweepDiscoveryStatus::NoRootsDiscovered => "no-roots-discovered",
        WorktreeSweepDiscoveryStatus::RootsDiscovered => "roots-discovered",
    }
}

fn worktree_sweep_discovery_warning(status: WorktreeSweepDiscoveryStatus) -> Option<&'static str> {
    match status {
        WorktreeSweepDiscoveryStatus::NoRootsDiscovered => {
            Some("WARNING: no worktree roots were discovered; this is not a clean-sweep result.")
        }
        WorktreeSweepDiscoveryStatus::RootsDiscovered => None,
    }
}

fn worktree_sweep_root_kind_label(kind: WorktreeSweepRootKind) -> &'static str {
    match kind {
        WorktreeSweepRootKind::WorkspaceManaged => "workspace-managed",
        WorktreeSweepRootKind::RepositoryLocal => "repository-local",
    }
}

fn worktree_gc_target_action_count(report: &WorktreeGcReport) -> usize {
    if report.dry_run {
        report
            .entries
            .iter()
            .filter(|entry| entry.reason == WorktreeGcReason::TargetWouldRemove)
            .count()
    } else {
        report.target_removed_count
    }
}

fn worktree_sweep_repository_status_label(status: WorktreeSweepRepositoryStatus) -> &'static str {
    match status {
        WorktreeSweepRepositoryStatus::Inspected => "inspected",
        WorktreeSweepRepositoryStatus::Skipped => "skipped",
        WorktreeSweepRepositoryStatus::Failed => "failed",
    }
}

fn worktree_sweep_failure_kind_label(kind: WorktreeSweepFailureKind) -> &'static str {
    match kind {
        WorktreeSweepFailureKind::RepositoryOpen => "repository_open",
        WorktreeSweepFailureKind::RepositoryAssociation => "repository_association",
        WorktreeSweepFailureKind::AmbiguousRepository => "ambiguous_repository",
        WorktreeSweepFailureKind::GarbageCollection => "garbage_collection",
    }
}

fn worktree_gc_status_label(status: WorktreeGcStatus) -> &'static str {
    match status {
        WorktreeGcStatus::Removed => "removed",
        WorktreeGcStatus::WouldRemove => "would-remove",
        WorktreeGcStatus::Retained => "retained",
        WorktreeGcStatus::Protected => "protected",
        WorktreeGcStatus::OrphanPruned => "orphan-pruned",
        WorktreeGcStatus::OrphanQuarantined => "orphan-quarantined",
        WorktreeGcStatus::OrphanWouldPrune => "orphan-would-prune",
    }
}

fn worktree_gc_reason_label(reason: WorktreeGcReason) -> &'static str {
    match reason {
        WorktreeGcReason::FinishedBranch => "finished-branch",
        WorktreeGcReason::SupersededLane => "superseded-lane",
        WorktreeGcReason::UnmergedBranch => "unmerged-branch",
        WorktreeGcReason::RetentionKeep => "retention-keep",
        WorktreeGcReason::ExcludedCurrentWorktree => "excluded-current-worktree",
        WorktreeGcReason::Dirty => "dirty",
        WorktreeGcReason::UntrackedOnly => "untracked-only",
        WorktreeGcReason::ActiveLease => "active-lease",
        WorktreeGcReason::ActiveClaim => "active-claim",
        WorktreeGcReason::TargetRemoved => "target-removed",
        WorktreeGcReason::TargetWouldRemove => "target-would-remove",
        WorktreeGcReason::LiveTarget => "live-target",
        WorktreeGcReason::TargetLivenessUnknown => "target-liveness-unknown",
        WorktreeGcReason::TargetIdentityChanged => "target-identity-changed",
        WorktreeGcReason::SizeMeasurementFailed => "size-measurement-failed",
        WorktreeGcReason::NoTarget => "no-target",
        WorktreeGcReason::UnregisteredOrphan => "unregistered-orphan",
        WorktreeGcReason::MachineGlobalGate => "machine-global-gate",
    }
}

fn print_path_claim(label: &str, claim: &crate::sync::PathClaim, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(claim)?);
    } else {
        println!("{label}: {}", claim.token.get());
        println!("Agent: {}", claim.agent_id);
        println!("Paths:");
        for path in &claim.paths {
            println!("  {}", path.display());
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ClaimTelemetryCliReport<'a> {
    #[serde(flatten)]
    legacy_claim: &'a crate::sync::PathClaim,
    claim: &'a crate::sync::PathClaim,
    warnings: &'a [MegafileClaimWarning],
}

fn print_claim_telemetry_outcome(outcome: &ClaimTelemetryOutcome, json: bool) -> Result<()> {
    if json {
        let report = ClaimTelemetryCliReport {
            legacy_claim: &outcome.claim,
            claim: &outcome.claim,
            warnings: &outcome.warnings,
        };
        print_query_report(&report, true)
    } else {
        print_path_claim("Claim", &outcome.claim, false)?;
        for warning in &outcome.warnings {
            println!("Warning: {warning:#?}");
        }
        Ok(())
    }
}

fn print_claims(claims: &[crate::sync::PathClaim], json: bool, empty_message: &str) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(claims)?);
    } else if claims.is_empty() {
        println!("{empty_message}");
    } else {
        for claim in claims {
            let paths = claim
                .paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!("{}\t{}\t{}", claim.token.get(), claim.agent_id, paths);
        }
    }
    Ok(())
}

fn print_claim_statuses(claims: &[ClaimStatusReport], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(claims)?);
    } else if claims.is_empty() {
        println!("No active claims.");
    } else {
        for status in claims {
            let paths = status
                .claim
                .paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "{}\t{}\trun={}\tstate={}\t{}",
                status.claim.token.get(),
                status.claim.agent_id,
                status.owner_run_id.as_deref().unwrap_or("<unattributed>"),
                status.owner_run_state.as_str(),
                paths,
            );
        }
    }
    Ok(())
}

fn print_owner_report(report: &OwnerReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if let Some(owner) = &report.owner {
        println!("{}\t{}", report.path.display(), owner);
    } else {
        println!("{}\t<unclaimed>", report.path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use git2::Signature;

    use super::*;

    #[test]
    fn artifact_prune_parses_family_age_size_and_unfinalized_grace() {
        let parsed = Cli::try_parse_from([
            "maco",
            "artifacts",
            "prune",
            "--family",
            "program",
            "--repo",
            "repo",
            "--keep",
            "3",
            "--max-age-seconds",
            "86400",
            "--max-total-bytes",
            "1048576",
            "--unfinalized-grace-seconds",
            "3600",
            "--reclaim-unverifiable",
            "--acknowledge-external-writers-stopped",
            "--dry-run",
            "--json",
        ])
        .expect("artifact retention flags should parse");
        let Command::Artifacts(RepositoryArtifactsCommand {
            command: RepositoryArtifactsSubcommand::Prune(args),
        }) = parsed.command
        else {
            panic!("expected repository artifact prune command");
        };
        assert_eq!(args.family, ArtifactRetentionFamilyArg::Program);
        assert_eq!(args.policy.repo, PathBuf::from("repo"));
        assert_eq!(args.policy.keep, 3);
        assert_eq!(args.policy.max_age_seconds, Some(86_400));
        assert_eq!(args.policy.max_total_bytes, Some(1_048_576));
        assert_eq!(args.policy.unfinalized_grace_seconds, 3_600);
        assert!(args.policy.reclaim_unverifiable);
        assert!(args.policy.acknowledge_external_writers_stopped);
        assert!(args.policy.dry_run);
        assert!(args.policy.json);

        for family in [
            "autopilot",
            "consult",
            "inbox",
            "supervise",
            "o2-autopilot",
            "inbox-workspace",
            "program",
        ] {
            Cli::try_parse_from(["maco", "artifacts", "prune", "--family", family])
                .unwrap_or_else(|error| panic!("retention family {family} must parse: {error}"));
        }
    }

    #[test]
    fn worktree_sweep_defaults_to_dry_run_and_requires_workspace() {
        let parsed =
            Cli::try_parse_from(["maco", "worktree", "sweep", "--workspace", "/srv/workspace"])
                .expect("workspace sweep should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Sweep(args),
        }) = parsed.command
        else {
            panic!("expected worktree sweep command");
        };
        assert_eq!(args.workspace, PathBuf::from("/srv/workspace"));
        assert!(!args.apply, "workspace sweep must default to dry-run");
        assert!(!args.keep_targets);
        assert!(!args.targets_only);
        assert_eq!(args.max_age_seconds, None);
        assert_eq!(args.max_count, None);
        assert_eq!(args.max_total_bytes, None);
        assert!(!args.json);

        let error = Cli::try_parse_from(["maco", "worktree", "sweep"])
            .expect_err("workspace sweep must require --workspace");
        assert!(error.to_string().contains("--workspace"));
    }

    #[test]
    fn worktree_sweep_zero_root_formatter_emits_prominent_warning() {
        let warning =
            worktree_sweep_discovery_warning(WorktreeSweepDiscoveryStatus::NoRootsDiscovered)
                .expect("zero-root sweep warning");
        assert!(warning.starts_with("WARNING:"));
        assert!(warning.contains("not a clean-sweep result"));
        assert_eq!(
            worktree_sweep_discovery_warning(WorktreeSweepDiscoveryStatus::RootsDiscovered),
            None
        );
    }

    #[test]
    fn worktree_sweep_parses_apply_retention_target_and_json_flags() {
        let parsed = Cli::try_parse_from([
            "maco",
            "worktree",
            "sweep",
            "--workspace",
            "workspace",
            "--apply",
            "--max-age-seconds",
            "86400",
            "--max-count",
            "12",
            "--max-total-bytes",
            "10737418240",
            "--keep-targets",
            "--allow-untracked-path",
            "TASK.md",
            "--allow-untracked-path",
            "notes/output.txt",
            "--json",
        ])
        .expect("fully configured workspace sweep should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Sweep(args),
        }) = parsed.command
        else {
            panic!("expected worktree sweep command");
        };
        assert_eq!(args.workspace, PathBuf::from("workspace"));
        assert!(args.apply);
        assert_eq!(args.max_age_seconds, Some(86_400));
        assert_eq!(args.max_count, Some(12));
        assert_eq!(args.max_total_bytes, Some(10_737_418_240));
        assert!(args.keep_targets);
        assert!(!args.targets_only);
        assert_eq!(
            args.allow_untracked_paths,
            vec![PathBuf::from("TASK.md"), PathBuf::from("notes/output.txt")]
        );
        assert!(args.json);
    }

    #[test]
    fn worktree_lifecycle_defaults_all_automation_off_and_dry_run() {
        let parsed = Cli::try_parse_from(["maco", "worktree", "lifecycle"])
            .expect("default lifecycle pass should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Lifecycle(args),
        }) = parsed.command
        else {
            panic!("expected worktree lifecycle command");
        };
        assert_eq!(args.repo, PathBuf::from("."));
        assert!(!args.apply, "lifecycle must default to dry-run");
        assert!(!args.auto_reap_merged);
        assert_eq!(args.trunk_ref, None);
        assert_eq!(args.retry_successor, None);
        assert!(!args.startup_reconciliation);
        assert!(!args.destructive_reconciliation);
        assert!(!args.o2_launch_retention);
        assert_eq!(args.worktree_root, None);
        assert_eq!(args.max_age_seconds, None);
        assert_eq!(args.max_count, None);
        assert_eq!(args.max_total_bytes, None);
        assert!(!args.keep_targets);
        assert!(args.allow_untracked_paths.is_empty());
        assert_eq!(args.artifact_keep, None);
        assert_eq!(args.artifact_max_age_seconds, None);
        assert_eq!(args.artifact_max_total_bytes, None);
        assert_eq!(args.artifact_unfinalized_grace_seconds, None);
        assert!(!args.reclaim_unverifiable);
        assert!(!args.acknowledge_external_writers_stopped);
        assert_eq!(args.machine_global_config, None);
        assert_eq!(args.machine_global_worktree_root_id, None);
        assert_eq!(args.machine_global_correlation, None);
        assert!(!args.json);
    }

    #[test]
    fn worktree_create_retry_supersession_is_explicit_and_apply_is_separate() {
        let parsed = Cli::try_parse_from(["maco", "worktree", "create", "task-r2"])
            .expect("ordinary create should parse unchanged");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Create(args),
        }) = parsed.command
        else {
            panic!("expected worktree create command");
        };
        assert!(!args.supersede_retry_predecessor);
        assert!(!args.apply_retry_supersession);
        assert!(!args.o2_launch_retention_defaults);

        assert!(Cli::try_parse_from([
            "maco",
            "worktree",
            "create",
            "task-r2",
            "--apply-retry-supersession",
        ])
        .is_err());
        let parsed = Cli::try_parse_from([
            "maco",
            "worktree",
            "create",
            "task-r2",
            "--supersede-retry-predecessor",
            "--apply-retry-supersession",
            "--o2-launch-retention-defaults",
        ])
        .expect("explicit retry supersession should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Create(args),
        }) = parsed.command
        else {
            panic!("expected worktree create command");
        };
        assert!(args.supersede_retry_predecessor);
        assert!(args.apply_retry_supersession);
        assert!(args.o2_launch_retention_defaults);
    }

    #[test]
    fn worktree_lifecycle_parses_explicit_automation_and_safety_inputs() {
        let parsed = Cli::try_parse_from([
            "maco",
            "worktree",
            "lifecycle",
            "--repo",
            "repo",
            "--apply",
            "--auto-reap-merged",
            "--trunk-ref",
            "refs/heads/main",
            "--retry-successor",
            "agent-task-r2",
            "--startup-reconciliation",
            "--destructive-reconciliation",
            "--o2-launch-retention",
            "--worktree-root",
            "lanes",
            "--max-age-seconds",
            "86400",
            "--max-count",
            "8",
            "--max-total-bytes",
            "1073741824",
            "--keep-targets",
            "--allow-untracked-path",
            "TASK.md",
            "--artifact-keep",
            "6",
            "--artifact-max-age-seconds",
            "172800",
            "--artifact-max-total-bytes",
            "536870912",
            "--artifact-unfinalized-grace-seconds",
            "604800",
            "--reclaim-unverifiable",
            "--acknowledge-external-writers-stopped",
            "--machine-global-config",
            "machine-global.json",
            "--machine-global-worktree-root-id",
            "worktrees",
            "--machine-global-correlation",
            "startup-65",
            "--json",
        ])
        .expect("explicit lifecycle automation should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Lifecycle(args),
        }) = parsed.command
        else {
            panic!("expected worktree lifecycle command");
        };
        assert_eq!(args.repo, PathBuf::from("repo"));
        assert!(args.apply);
        assert!(args.auto_reap_merged);
        assert_eq!(args.trunk_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(args.retry_successor.as_deref(), Some("agent-task-r2"));
        assert!(args.startup_reconciliation);
        assert!(args.destructive_reconciliation);
        assert!(args.o2_launch_retention);
        assert_eq!(args.worktree_root, Some(PathBuf::from("lanes")));
        assert_eq!(args.max_age_seconds, Some(86_400));
        assert_eq!(args.max_count, Some(8));
        assert_eq!(args.max_total_bytes, Some(1_073_741_824));
        assert!(args.keep_targets);
        assert_eq!(args.allow_untracked_paths, vec![PathBuf::from("TASK.md")]);
        assert_eq!(args.artifact_keep, Some(6));
        assert_eq!(args.artifact_max_age_seconds, Some(172_800));
        assert_eq!(args.artifact_max_total_bytes, Some(536_870_912));
        assert_eq!(args.artifact_unfinalized_grace_seconds, Some(604_800));
        assert!(args.reclaim_unverifiable);
        assert!(args.acknowledge_external_writers_stopped);
        assert_eq!(
            args.machine_global_config,
            Some(PathBuf::from("machine-global.json"))
        );
        assert_eq!(
            args.machine_global_worktree_root_id.as_deref(),
            Some("worktrees")
        );
        assert_eq!(
            args.machine_global_correlation.as_deref(),
            Some("startup-65")
        );
        assert!(args.json);
    }

    #[test]
    fn worktree_lifecycle_rejects_unscoped_destructive_and_artifact_flags() {
        for args in [
            vec![
                "maco",
                "worktree",
                "lifecycle",
                "--destructive-reconciliation",
            ],
            vec![
                "maco",
                "worktree",
                "lifecycle",
                "--startup-reconciliation",
                "--destructive-reconciliation",
            ],
            vec!["maco", "worktree", "lifecycle", "--artifact-keep", "3"],
            vec!["maco", "worktree", "lifecycle", "--reclaim-unverifiable"],
            vec![
                "maco",
                "worktree",
                "lifecycle",
                "--acknowledge-external-writers-stopped",
            ],
        ] {
            assert!(
                Cli::try_parse_from(args).is_err(),
                "dependent safety flag must fail closed"
            );
        }
    }

    #[test]
    fn existing_worktree_gc_keeps_apply_by_default_contract() {
        let parsed = Cli::try_parse_from(["maco", "worktree", "gc", "--repo", "repo"])
            .expect("existing worktree gc command should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Gc(args),
        }) = parsed.command
        else {
            panic!("expected worktree gc command");
        };
        assert_eq!(args.repo, PathBuf::from("repo"));
        assert!(!args.dry_run, "worktree gc must remain apply-by-default");
        assert!(!args.targets_only);
        assert_eq!(args.max_total_bytes, None);
        assert!(args.allow_untracked_paths.is_empty());
    }

    #[test]
    fn worktree_gc_parses_apparent_byte_retention() {
        let parsed =
            Cli::try_parse_from(["maco", "worktree", "gc", "--max-total-bytes", "2147483648"])
                .expect("size retention should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Gc(args),
        }) = parsed.command
        else {
            panic!("expected worktree gc command");
        };
        assert_eq!(args.max_total_bytes, Some(2_147_483_648));
    }

    #[test]
    fn worktree_gc_parses_repeatable_exact_untracked_allowlist() {
        let parsed = Cli::try_parse_from([
            "maco",
            "worktree",
            "gc",
            "--allow-untracked-path",
            "TASK.md",
            "--allow-untracked-path",
            "worker/output.json",
        ])
        .expect("repeatable untracked allowlist should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Gc(args),
        }) = parsed.command
        else {
            panic!("expected worktree gc command");
        };
        assert_eq!(
            args.allow_untracked_paths,
            vec![
                PathBuf::from("TASK.md"),
                PathBuf::from("worker/output.json")
            ]
        );
    }

    #[test]
    fn worktree_gc_and_sweep_parse_targets_only_mode() {
        let gc = Cli::try_parse_from(["maco", "worktree", "gc", "--targets-only"])
            .expect("target-only GC should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Gc(gc),
        }) = gc.command
        else {
            panic!("expected worktree gc command");
        };
        assert!(gc.targets_only);

        let sweep = Cli::try_parse_from([
            "maco",
            "worktree",
            "sweep",
            "--workspace",
            "workspace",
            "--targets-only",
        ])
        .expect("target-only sweep should parse");
        let Command::Worktree(WorktreeCommand {
            command: WorktreeSubcommand::Sweep(sweep),
        }) = sweep.command
        else {
            panic!("expected worktree sweep command");
        };
        assert!(sweep.targets_only);
        assert!(!sweep.apply);
    }

    #[test]
    fn worktree_sweep_dry_run_target_summary_counts_would_remove_entries() {
        let dry_run = WorktreeGcReport {
            dry_run: true,
            remove_targets: true,
            targets_only: false,
            max_age_seconds: None,
            max_count: Some(1),
            max_total_bytes: None,
            allowed_untracked_paths: Vec::new(),
            considered_count: 1,
            removed_count: 0,
            protected_count: 0,
            retained_count: 1,
            target_removed_count: 0,
            orphan_removed_count: 0,
            apparent_considered_bytes: 0,
            estimated_reclaimable_bytes: 0,
            estimated_reclaimed_bytes: 0,
            entries: vec![crate::worktree::WorktreeGcEntry {
                name: "retained-lane".to_string(),
                branch: Some("maco/retained-lane".to_string()),
                path: PathBuf::from("/workspace/.maco/worktrees/repo/retained-lane"),
                status: WorktreeGcStatus::Retained,
                reason: WorktreeGcReason::TargetWouldRemove,
                target_path: Some(PathBuf::from(
                    "/workspace/.maco/worktrees/repo/retained-lane/target",
                )),
                target_liveness: None,
                apparent_worktree_bytes: None,
                apparent_target_bytes: None,
                untracked_paths: Vec::new(),
                gate_denial: None,
                retention_operation_id: None,
            }],
        };
        assert_eq!(worktree_gc_target_action_count(&dry_run), 1);

        let mut applied = dry_run.clone();
        applied.dry_run = false;
        applied.target_removed_count = 2;
        assert_eq!(worktree_gc_target_action_count(&applied), 2);
    }

    #[test]
    fn worktree_target_liveness_evidence_has_actionable_human_rendering() {
        let evidence = WorktreeTargetLivenessEvidence {
            pid: Some(1234),
            source: WorktreeTargetLivenessSource::DefaultCargoTarget,
            cause: WorktreeTargetLivenessCause::CargoLikeProcessInLane,
        };
        assert_eq!(
            worktree_target_liveness_suffix(Some(&evidence)),
            " target-liveness-pid=1234 target-liveness-source=default-cargo-target \
             target-liveness-cause=cargo-like-process-in-lane"
        );
        assert_eq!(worktree_target_liveness_suffix(None), "");
    }

    #[test]
    fn supervise_run_requires_complete_machine_global_binding() {
        let complete = Cli::try_parse_from([
            "maco",
            "supervise",
            "run",
            "plan.json",
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ])
        .expect("complete supervise machine-global binding should parse");
        let Command::Supervise(SuperviseCommand {
            command: SuperviseSubcommand::Run(complete),
        }) = complete.command
        else {
            panic!("expected supervise run command");
        };
        assert_eq!(
            complete.machine_global_config,
            PathBuf::from("/tmp/maco-machine-global.json")
        );
        assert_eq!(complete.machine_global_runtime_root_id, "runtime");

        for incomplete in [
            vec!["maco", "supervise", "run", "plan.json"],
            vec![
                "maco",
                "supervise",
                "run",
                "plan.json",
                "--machine-global-config",
                "/tmp/maco-machine-global.json",
            ],
            vec![
                "maco",
                "supervise",
                "run",
                "plan.json",
                "--machine-global-runtime-root-id",
                "runtime",
            ],
        ] {
            let error = Cli::try_parse_from(incomplete)
                .expect_err("missing or partial supervise binding must fail closed");
            let rendered = error.to_string();
            assert!(
                rendered.contains("--machine-global-config")
                    || rendered.contains("--machine-global-runtime-root-id"),
                "binding refusal must name the missing obligation: {rendered}"
            );
        }
    }

    #[test]
    fn merge_arbitration_is_an_explicit_typed_opt_in() {
        let agent_primary = Cli::try_parse_from([
            "maco",
            "merge",
            "arbitrate",
            "agent-a",
            "primary",
            "--arbiter-id",
            "neutral-review",
            "--run-id",
            "collision-1",
            "--first-claim",
            "src/lib.rs",
            "--validation-command",
            "cargo test",
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
            "--approve",
        ])
        .expect("agent-primary arbitration should parse");
        let Command::Merge(MergeCommand {
            command: MergeSubcommand::Arbitrate(agent_primary),
        }) = agent_primary.command
        else {
            panic!("expected merge arbitrate command");
        };
        assert_eq!(agent_primary.first_side, "agent-a");
        assert_eq!(agent_primary.second_side, "primary");
        assert_eq!(agent_primary.first_claim, vec![PathBuf::from("src/lib.rs")]);
        assert!(agent_primary.second_claim.is_empty());
        assert_eq!(agent_primary.arbiter_id, "neutral-review");
        assert_eq!(agent_primary.validation_command, vec!["cargo test"]);
        assert_eq!(
            agent_primary.machine_global_runtime_root_id,
            "runtime".to_string()
        );
        assert!(agent_primary.approve);

        let agent_agent = Cli::try_parse_from([
            "maco",
            "merge",
            "arbitrate",
            "agent-a",
            "agent-b",
            "--arbiter-id",
            "neutral-review",
            "--run-id",
            "collision-2",
            "--first-claim",
            "src",
            "--second-claim",
            "src/lib.rs",
            "--validation-command",
            "cargo check",
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ])
        .expect("agent-agent arbitration should parse");
        let Command::Merge(MergeCommand {
            command: MergeSubcommand::Arbitrate(agent_agent),
        }) = agent_agent.command
        else {
            panic!("expected merge arbitrate command");
        };
        assert_eq!(agent_agent.first_side, "agent-a");
        assert_eq!(agent_agent.second_side, "agent-b");
        assert_eq!(agent_agent.second_claim, vec![PathBuf::from("src/lib.rs")]);
        assert!(!agent_agent.approve);

        let missing_config = Cli::try_parse_from([
            "maco",
            "merge",
            "arbitrate",
            "agent-a",
            "primary",
            "--arbiter-id",
            "neutral-review",
            "--run-id",
            "collision-missing-config",
            "--first-claim",
            "src",
            "--validation-command",
            "cargo check",
            "--machine-global-runtime-root-id",
            "runtime",
        ])
        .expect_err("merge arbitration must declare a machine-global config");
        assert!(
            missing_config
                .to_string()
                .contains("--machine-global-config"),
            "missing-config refusal must identify the launch obligation"
        );

        let missing_root_id = Cli::try_parse_from([
            "maco",
            "merge",
            "arbitrate",
            "agent-a",
            "primary",
            "--arbiter-id",
            "neutral-review",
            "--run-id",
            "collision-missing-root",
            "--first-claim",
            "src",
            "--validation-command",
            "cargo check",
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
        ])
        .expect_err("merge arbitration must declare a machine-global runtime root id");
        assert!(
            missing_root_id
                .to_string()
                .contains("--machine-global-runtime-root-id"),
            "missing-root refusal must identify the launch obligation"
        );

        assert!(Cli::try_parse_from(["maco", "merge", "arbitrate"]).is_err());
        assert!(Cli::try_parse_from([
            "maco",
            "merge",
            "arbitrate",
            "agent-a",
            "primary",
            "--arbiter-id",
            "neutral-review",
            "--run-id",
            "collision-3",
        ])
        .is_err());
    }

    #[test]
    fn existing_merge_preview_and_apply_parsing_remains_separate_from_arbitration() {
        let preview = Cli::try_parse_from([
            "maco",
            "merge",
            "preview",
            "agent-a",
            "--claim",
            "src/lib.rs",
            "--require-validation",
            "--json",
        ])
        .expect("existing preview command should still parse");
        assert!(matches!(
            preview.command,
            Command::Merge(MergeCommand {
                command: MergeSubcommand::Preview(_)
            })
        ));

        let apply = Cli::try_parse_from([
            "maco",
            "merge",
            "apply",
            "agent-a",
            "--claim",
            "src/lib.rs",
            "--validation-command",
            "cargo test",
            "--reviewed-preview",
            "reviewed-preview.json",
            "--json",
        ])
        .expect("existing apply command should still parse");
        let Command::Merge(MergeCommand {
            command: MergeSubcommand::Apply(args),
        }) = apply.command
        else {
            panic!("expected merge apply command");
        };
        assert_eq!(
            args.reviewed_preview,
            Some(PathBuf::from("reviewed-preview.json"))
        );
    }

    #[test]
    fn no_watermark_freshness_refusal_serialization_is_truthfully_unbound() {
        let error = merge::MergePreviewFreshnessError::Drift {
            axes: vec![merge::MergePreviewDriftAxis::PrimaryHead],
            moved: "primary HEAD".to_string(),
        };
        let report = merge_preview_freshness_refusal_report(&error, false);
        let value = serde_json::to_value(report).expect("serialize unbound freshness refusal");

        assert_eq!(value["review_requested"], false);
        assert_eq!(value["review_bound"], false);
        assert_eq!(value["review_binding_status"], "not_supplied");
        assert_eq!(value["reason"], "preview_freshness_drift");
        assert!(!value["message"]
            .as_str()
            .expect("freshness message")
            .contains("reviewed"));
        assert!(!value["next_action"]
            .as_str()
            .expect("freshness next action")
            .contains("review"));
        assert!(value["next_action"]
            .as_str()
            .expect("freshness next action")
            .contains("concurrent repository activity"));

        let requested = serde_json::to_value(merge_preview_freshness_refusal_report(&error, true))
            .expect("serialize requested freshness refusal");
        assert_eq!(requested["review_requested"], true);
        assert_eq!(requested["review_bound"], false);
        assert_eq!(requested["review_binding_status"], "not_bound");
    }

    #[test]
    fn reviewed_merge_preview_rejects_duplicate_json_keys_at_every_depth_as_malformed() {
        let temp = tempfile::tempdir().expect("tempdir");
        for (name, contents, duplicate_key) in [
            (
                "top-level.json",
                br#"{"freshness_watermark":{},"freshness_watermark":{}}"#.as_slice(),
                "freshness_watermark",
            ),
            (
                "nested.json",
                br#"{"freshness_watermark":{"candidate":{"head":"a","head":"b"}}}"#.as_slice(),
                "head",
            ),
            (
                "array-nested.json",
                br#"{"freshness_watermark":{"items":[{"path":"a","path":"b"}]}}"#.as_slice(),
                "path",
            ),
        ] {
            let path = temp.path().join(name);
            fs::write(&path, contents).expect("write duplicate-key preview fixture");
            let error = load_reviewed_merge_preview(Some(&path))
                .expect_err("duplicate JSON key must refuse reviewed preview");
            let freshness = error
                .downcast_ref::<merge::MergePreviewFreshnessError>()
                .expect("duplicate JSON key must remain a typed freshness refusal");
            let merge::MergePreviewFreshnessError::MalformedWatermark { message } = freshness
            else {
                panic!("duplicate JSON key must be classified as a malformed watermark");
            };
            assert!(message.contains("duplicate object key"));
            assert!(message.contains(duplicate_key));
        }
    }

    #[test]
    fn merge_auto_reap_is_default_off_and_apply_requires_classification() {
        let parsed = Cli::try_parse_from(["maco", "merge", "apply", "agent-a"])
            .expect("default merge apply should parse");
        let Command::Merge(MergeCommand {
            command: MergeSubcommand::Apply(args),
        }) = parsed.command
        else {
            panic!("expected merge apply command");
        };
        assert!(!args.auto_reap_merged);
        assert!(!args.apply_auto_reap);
        assert_eq!(args.trunk_ref, None);

        assert!(
            Cli::try_parse_from(["maco", "merge", "apply", "agent-a", "--apply-auto-reap",])
                .is_err()
        );

        let parsed = Cli::try_parse_from([
            "maco",
            "merge",
            "apply",
            "agent-a",
            "--auto-reap-merged",
            "--trunk-ref",
            "refs/heads/main",
            "--apply-auto-reap",
        ])
        .expect("explicit merge lifecycle apply should parse");
        let Command::Merge(MergeCommand {
            command: MergeSubcommand::Apply(args),
        }) = parsed.command
        else {
            panic!("expected merge apply command");
        };
        assert!(args.auto_reap_merged);
        assert!(args.apply_auto_reap);
        assert_eq!(args.trunk_ref.as_deref(), Some("refs/heads/main"));
    }

    #[test]
    fn merge_apply_json_delivers_unclaimed_edits_denial_to_integration_controller() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("README.md"), "# Smoke\n").expect("write README");
        fs::write(
            repo_path.join("src/lib.rs"),
            "pub fn ok() -> bool { true }\n",
        )
        .expect("write lib");
        let repo = crate::git_repository::open(&repo_path).expect("open repository");
        let mut index = repo.index().expect("open index");
        index
            .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
            .expect("stage fixture");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit fixture");
        drop(tree);
        drop(repo);

        let worktree = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create test worktree");
        fs::write(
            worktree.path.join("README.md"),
            "# Smoke\n\nclaimed change\n",
        )
        .expect("edit claimed path");
        fs::write(
            worktree.path.join("src/lib.rs"),
            "pub fn ok() -> bool { false }\n",
        )
        .expect("edit unclaimed path");

        let args = MergeApplyArgs {
            agent_id: "agent-a".to_string(),
            repo: repo_path.clone(),
            claim: vec![PathBuf::from("README.md")],
            validation_report: Vec::new(),
            require_validation: false,
            validation_command: Vec::new(),
            reviewed_preview: None,
            block_megafiles: false,
            decomposition_target: None,
            decomposition_run_id: None,
            megafile_thresholds: MegafileThresholdArgs::default(),
            forces: MergeForceArgs {
                force_dirty_primary: false,
                force_stale_base: false,
                force_unclaimed_edits: false,
                force_validation_failures: false,
                force_apply_conflicts: false,
            },
            auto_reap_merged: true,
            trunk_ref: Some("refs/heads/main".to_string()),
            apply_auto_reap: false,
            json: true,
        };
        let mut delivered = None;
        let error = run_merge_apply_controller(args, |report, json, review_bound| {
            assert!(json);
            assert!(!review_bound);
            let output = serde_json::to_value(merge_apply_report_output(report, review_bound))
                .expect("serialize ordinary apply report");
            assert_eq!(output["review_bound"], false);
            assert_eq!(output["review_binding_status"], "not_supplied");
            delivered = Some(report.clone());
            Ok(())
        })
        .expect_err("unclaimed merge edit must remain blocked");

        assert!(error.to_string().contains("unclaimed_edits"));
        let report = delivered.expect("integration controller must receive the blocked report");
        assert_eq!(report.status, merge::MergeApplyReportStatus::Blocked);
        assert!(!report.applied);
        assert!(
            report.lifecycle.is_none(),
            "blocked merge must not run its lifecycle hook"
        );
        let denial = report
            .gate_denials
            .iter()
            .find(|denial| {
                matches!(
                    denial.reason,
                    crate::gate_denial::GateDenialReason::MergeRemediation {
                        blocker: merge::ApplyBlocker::UnclaimedEdits
                    }
                )
            })
            .expect("delivered unclaimed-edits merge denial");
        assert_eq!(
            denial.route,
            crate::gate_denial::GateDenialRoute::IntegrationController
        );
        assert_eq!(denial.context.owner, "agent-a");
        assert_eq!(
            denial.context.source,
            crate::gate_denial::GateCheckSource::MergeScope
        );
        assert_eq!(denial.context.paths, vec![PathBuf::from("src/lib.rs")]);
        assert_eq!(
            denial.next_safe_operation,
            crate::gate_denial::NextSafeOperation::RemediateUnclaimedMergeEdits
        );
        let correlation_id = denial.correction_correlation_id.as_str();
        assert!(!correlation_id.is_empty());
        assert!(correlation_id.len() <= 128);
        assert!(correlation_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        }));
    }

    #[test]
    fn merge_apply_auto_reap_waits_for_trunk_then_reaps_on_finalization_rerun() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
        fs::write(repo_path.join("README.md"), "# Before\n").expect("write README");
        let repo = crate::git_repository::open(&repo_path).expect("open repository");
        let mut index = repo.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage README");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit fixture");
        drop(tree);
        drop(repo);

        let worktree = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-merge-hook".to_string(),
                branch: None,
                base: None,
                worktree_root: None,
            })
            .expect("create test worktree");
        fs::write(worktree.path.join("README.md"), "# After\n").expect("edit agent README");
        let agent_repo =
            crate::git_repository::open(&worktree.path).expect("open agent repository");
        let mut index = agent_repo.index().expect("open agent index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage agent README");
        index.write().expect("write agent index");
        let tree_id = index.write_tree().expect("write agent tree");
        let tree = agent_repo.find_tree(tree_id).expect("find agent tree");
        let parent = agent_repo
            .head()
            .expect("agent HEAD")
            .peel_to_commit()
            .expect("agent parent commit");
        agent_repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                "agent change",
                &tree,
                &[&parent],
            )
            .expect("commit agent change");
        drop(parent);
        drop(tree);
        drop(agent_repo);

        let args = MergeApplyArgs {
            agent_id: "agent-merge-hook".to_string(),
            repo: repo_path.clone(),
            claim: vec![PathBuf::from("README.md")],
            validation_report: Vec::new(),
            require_validation: false,
            validation_command: Vec::new(),
            reviewed_preview: None,
            block_megafiles: false,
            decomposition_target: None,
            decomposition_run_id: None,
            megafile_thresholds: MegafileThresholdArgs::default(),
            forces: MergeForceArgs {
                force_dirty_primary: false,
                force_stale_base: false,
                force_unclaimed_edits: false,
                force_validation_failures: false,
                force_apply_conflicts: false,
            },
            auto_reap_merged: true,
            trunk_ref: Some("refs/heads/main".to_string()),
            apply_auto_reap: false,
            json: true,
        };
        let mut delivered = None;
        run_merge_apply_controller(args, |report, json, review_bound| {
            assert!(json);
            assert!(!review_bound);
            delivered = Some(report.clone());
            Ok(())
        })
        .expect("merge and lifecycle classification should succeed");

        let report = delivered.expect("merge report");
        assert_eq!(report.status, merge::MergeApplyReportStatus::Applied);
        assert!(report.applied);
        let lifecycle = report.lifecycle.expect("opt-in lifecycle report");
        assert!(lifecycle.enabled);
        assert!(lifecycle.dry_run);
        let gc = lifecycle
            .worktree_gc
            .expect("targeted worktree classification");
        assert_eq!(gc.considered_count, 1);
        assert_eq!(gc.removed_count, 0);
        assert_eq!(gc.entries.len(), 1);
        assert_eq!(gc.entries[0].reason, WorktreeGcReason::UnmergedBranch);
        assert!(worktree.path.exists(), "unmerged lane must remain present");

        let primary = crate::git_repository::open(&repo_path).expect("reopen primary");
        let lane_oid = primary
            .find_branch("maco/agent-merge-hook", git2::BranchType::Local)
            .expect("lane branch")
            .get()
            .target()
            .expect("lane branch target");
        primary
            .reference("refs/heads/main", lane_oid, true, "test merge finalization")
            .expect("advance trunk to lane commit");
        let lane_commit = primary.find_commit(lane_oid).expect("lane commit");
        primary
            .reset(lane_commit.as_object(), git2::ResetType::Hard, None)
            .expect("refresh primary worktree and index");
        drop(lane_commit);
        drop(primary);

        let args = MergeApplyArgs {
            agent_id: "agent-merge-hook".to_string(),
            repo: repo_path,
            claim: vec![PathBuf::from("README.md")],
            validation_report: Vec::new(),
            require_validation: false,
            validation_command: Vec::new(),
            reviewed_preview: None,
            block_megafiles: false,
            decomposition_target: None,
            decomposition_run_id: None,
            megafile_thresholds: MegafileThresholdArgs::default(),
            forces: MergeForceArgs {
                force_dirty_primary: false,
                force_stale_base: true,
                force_unclaimed_edits: false,
                force_validation_failures: false,
                force_apply_conflicts: false,
            },
            auto_reap_merged: true,
            trunk_ref: Some("refs/heads/main".to_string()),
            apply_auto_reap: true,
            json: true,
        };
        let mut finalized = None;
        run_merge_apply_controller(args, |report, json, review_bound| {
            assert!(json);
            assert!(!review_bound);
            finalized = Some(report.clone());
            Ok(())
        })
        .expect("fully merged finalization rerun should reap the lane");
        let finalized = finalized.expect("finalized report");
        let lifecycle = finalized.lifecycle.expect("final lifecycle report");
        let gc = lifecycle.worktree_gc.expect("final GC report");
        assert_eq!(gc.removed_count, 1, "{gc:#?}");
        assert_eq!(gc.entries[0].status, WorktreeGcStatus::Removed);
        assert_eq!(gc.entries[0].reason, WorktreeGcReason::FinishedBranch);
        assert!(!worktree.path.exists());
    }

    #[test]
    fn primary_arbitration_side_rejects_agent_claims_before_execution() {
        let error = arbitration_side_from_cli(
            "primary".to_string(),
            vec![PathBuf::from("src/lib.rs")],
            "second",
        )
        .expect_err("primary side must not accept an agent claim");
        assert!(error
            .to_string()
            .contains("--second-claim is not applicable"));
    }

    #[test]
    fn supervise_plan_requires_exactly_one_positional_or_goal_source() {
        let positional =
            Cli::try_parse_from(["maco", "supervise", "plan", "task.txt", "--repo", "repo"])
                .expect("positional task source should parse");
        let Command::Supervise(SuperviseCommand {
            command: SuperviseSubcommand::Plan(positional),
        }) = positional.command
        else {
            panic!("expected supervise plan command");
        };
        assert_eq!(positional.task_file, Some(PathBuf::from("task.txt")));
        assert_eq!(positional.from_goal, None);
        assert_eq!(positional.repo, PathBuf::from("repo"));

        let from_goal =
            Cli::try_parse_from(["maco", "supervise", "plan", "--from-goal", "goal.md"])
                .expect("--from-goal source should parse");
        let Command::Supervise(SuperviseCommand {
            command: SuperviseSubcommand::Plan(from_goal),
        }) = from_goal.command
        else {
            panic!("expected supervise plan command");
        };
        assert_eq!(from_goal.task_file, None);
        assert_eq!(from_goal.from_goal, Some(PathBuf::from("goal.md")));

        assert!(Cli::try_parse_from(["maco", "supervise", "plan"]).is_err());
        assert!(Cli::try_parse_from([
            "maco",
            "supervise",
            "plan",
            "task.txt",
            "--from-goal",
            "goal.md",
        ])
        .is_err());
    }

    #[test]
    fn live_goal_entrypoints_require_exactly_one_plan_or_goal_source() {
        let retention = [
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ];
        for command in ["supervise", "autopilot"] {
            let mut positional = vec!["maco", command, "run", "plan.json"];
            positional.extend(retention);
            let positional = Cli::try_parse_from(positional)
                .unwrap_or_else(|error| panic!("{command} positional source must parse: {error}"));
            match positional.command {
                Command::Supervise(SuperviseCommand {
                    command: SuperviseSubcommand::Run(args),
                }) => {
                    assert_eq!(args.supervisor_plan, Some(PathBuf::from("plan.json")));
                    assert_eq!(args.from_goal, None);
                }
                Command::Autopilot(AutopilotCommand {
                    command: AutopilotSubcommand::Run(args),
                }) => {
                    assert_eq!(args.task_file, Some(PathBuf::from("plan.json")));
                    assert_eq!(args.from_goal, None);
                }
                _ => panic!("expected a live run command"),
            }

            let mut from_goal = vec!["maco", command, "run", "--from-goal", "goal.md"];
            from_goal.extend(retention);
            let from_goal = Cli::try_parse_from(from_goal)
                .unwrap_or_else(|error| panic!("{command} goal source must parse: {error}"));
            match from_goal.command {
                Command::Supervise(SuperviseCommand {
                    command: SuperviseSubcommand::Run(args),
                }) => {
                    assert_eq!(args.supervisor_plan, None);
                    assert_eq!(args.from_goal, Some(PathBuf::from("goal.md")));
                }
                Command::Autopilot(AutopilotCommand {
                    command: AutopilotSubcommand::Run(args),
                }) => {
                    assert_eq!(args.task_file, None);
                    assert_eq!(args.from_goal, Some(PathBuf::from("goal.md")));
                }
                _ => panic!("expected a live run command"),
            }

            let mut missing = vec!["maco", command, "run"];
            missing.extend(retention);
            assert!(Cli::try_parse_from(missing).is_err());
            let mut conflicting = vec![
                "maco",
                command,
                "run",
                "plan.json",
                "--from-goal",
                "goal.md",
            ];
            conflicting.extend(retention);
            assert!(Cli::try_parse_from(conflicting).is_err());
        }
    }

    #[test]
    fn supervise_admission_flags_parse_and_reject_zero() {
        let parsed = Cli::try_parse_from([
            "maco",
            "supervise",
            "run",
            "plan.json",
            "--max-concurrent-children",
            "12",
            "--provider-inflight-limit",
            "9",
            "--host-memory-available-mib",
            "8192",
            "--host-memory-per-child-mib",
            "1024",
            "--host-fd-available",
            "640",
            "--host-fds-per-child",
            "128",
            "--host-disk-available-mib",
            "9000",
            "--host-disk-per-child-mib",
            "1000",
            "--host-fallback-children",
            "2",
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ])
        .expect("positive admission flags parse");
        let Command::Supervise(SuperviseCommand {
            command: SuperviseSubcommand::Run(args),
        }) = parsed.command
        else {
            panic!("expected supervise run command");
        };
        assert_eq!(args.max_concurrent_children.configured_limit(), Some(12));
        assert_eq!(args.provider_inflight_limit, Some(9));
        assert_eq!(args.host_memory_available_mib, Some(8_192));
        assert_eq!(args.host_fd_available, Some(640));
        assert_eq!(args.host_disk_available_mib, Some(9_000));

        for flag in [
            "--provider-inflight-limit",
            "--host-memory-available-mib",
            "--host-memory-per-child-mib",
            "--host-fd-available",
            "--host-fds-per-child",
            "--host-disk-available-mib",
            "--host-disk-per-child-mib",
            "--host-fallback-children",
        ] {
            assert!(Cli::try_parse_from([
                "maco",
                "supervise",
                "run",
                "plan.json",
                flag,
                "0",
                "--machine-global-config",
                "/tmp/maco-machine-global.json",
                "--machine-global-runtime-root-id",
                "runtime",
            ])
            .is_err());
        }
    }

    #[test]
    fn supervise_and_autopilot_budget_flags_parse_validate_and_bind_hard_limits() {
        let retention = [
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ];
        for command in ["supervise", "autopilot"] {
            let mut argv = vec![
                "maco",
                command,
                "run",
                "plan.json",
                "--max-tokens",
                "12000",
                "--max-cost-usd",
                "1.25",
                "--max-duration-seconds",
                "900",
            ];
            argv.extend(retention);
            let parsed = Cli::try_parse_from(argv)
                .unwrap_or_else(|error| panic!("{command} budget flags must parse: {error}"));
            let budget = match parsed.command {
                Command::Supervise(SuperviseCommand {
                    command: SuperviseSubcommand::Run(args),
                }) => args.budget,
                Command::Autopilot(AutopilotCommand {
                    command: AutopilotSubcommand::Run(args),
                }) => args.budget,
                _ => panic!("expected {command} run command"),
            };
            assert_eq!(budget.limits().hard_tokens, Some(12_000));
            assert_eq!(budget.limits().hard_cost_usd, Some(1.25));
            assert_eq!(budget.max_duration_seconds(), Some(900));

            for (flag, value) in [
                ("--max-tokens", "0"),
                ("--max-cost-usd", "0"),
                ("--max-cost-usd", "NaN"),
                ("--max-cost-usd", "inf"),
                ("--max-duration-seconds", "0"),
            ] {
                let mut invalid = vec!["maco", command, "run", "plan.json", flag, value];
                invalid.extend(retention);
                assert!(
                    Cli::try_parse_from(invalid).is_err(),
                    "{command} accepted nonsense {flag}={value}"
                );
            }
        }

        let mut aliases = vec![
            "maco",
            "supervise",
            "run",
            "plan.json",
            "--max-total-tokens",
            "2",
            "--max-total-cost-usd",
            "0.5",
            "--max-total-duration-seconds",
            "3",
        ];
        aliases.extend(retention);
        assert!(Cli::try_parse_from(aliases).is_ok());
    }

    #[test]
    fn live_run_entrypoints_accept_only_canonical_parent_nodes() {
        let retention = [
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
        ];
        for command in ["supervise", "autopilot"] {
            let mut valid = vec![
                "maco",
                command,
                "run",
                "plan.json",
                "--parent-node",
                "driver-root",
            ];
            valid.extend(retention);
            let parsed = Cli::try_parse_from(valid)
                .unwrap_or_else(|error| panic!("{command} parent node must parse: {error}"));
            let parent_node = match parsed.command {
                Command::Supervise(SuperviseCommand {
                    command: SuperviseSubcommand::Run(args),
                }) => args.parent_node,
                Command::Autopilot(AutopilotCommand {
                    command: AutopilotSubcommand::Run(args),
                }) => args.parent_node,
                _ => panic!("expected a live run command"),
            };
            assert_eq!(parent_node.as_deref(), Some("driver-root"));

            let mut invalid = vec![
                "maco",
                command,
                "run",
                "plan.json",
                "--parent-node",
                "invalid/parent",
            ];
            invalid.extend(retention);
            assert!(Cli::try_parse_from(invalid).is_err());
        }
    }

    #[test]
    fn supervise_resume_accepts_run_identity_and_query_output_options() {
        let parsed = Cli::try_parse_from([
            "maco",
            "supervise",
            "resume",
            "interrupted-run",
            "--repo",
            "repo",
            "--json",
        ])
        .expect("supervise resume should parse");
        let Command::Supervise(SuperviseCommand {
            command: SuperviseSubcommand::Resume(resume),
        }) = parsed.command
        else {
            panic!("expected supervise resume command");
        };
        assert_eq!(resume.run_id, "interrupted-run");
        assert_eq!(resume.repo, PathBuf::from("repo"));
        assert!(resume.json);
    }

    #[test]
    fn supervise_reaudit_requires_authenticated_source_scope_and_cleanup_binding() {
        let parsed = Cli::try_parse_from([
            "maco",
            "supervise",
            "re-audit",
            "source-run",
            "child-a",
            "--run-id",
            "destination-run",
            "--repo",
            "repo",
            "--machine-global-config",
            "/tmp/maco-machine-global.json",
            "--machine-global-runtime-root-id",
            "runtime",
            "--json",
        ])
        .expect("complete supervise re-audit command should parse");
        let Command::Supervise(SuperviseCommand {
            command: SuperviseSubcommand::Reaudit(reaudit),
        }) = parsed.command
        else {
            panic!("expected supervise re-audit command");
        };
        assert_eq!(reaudit.source_run_id, "source-run");
        assert_eq!(reaudit.assignment_id, "child-a");
        assert_eq!(reaudit.run_id.as_deref(), Some("destination-run"));
        assert_eq!(reaudit.repo, PathBuf::from("repo"));
        assert_eq!(
            reaudit.machine_global_config,
            PathBuf::from("/tmp/maco-machine-global.json")
        );
        assert_eq!(reaudit.machine_global_runtime_root_id, "runtime");
        assert!(reaudit.json);

        assert!(
            Cli::try_parse_from(["maco", "supervise", "re-audit", "source-run", "child-a",])
                .is_err()
        );
    }
}
