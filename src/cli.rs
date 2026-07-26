use crate::{
    agent::{
        self, AgentRunOptions, AgentRunReport, AgentValidationCommand, AgentWorktreeReusePolicy,
        ProviderCommandPolicy,
    },
    agent_lifecycle::{AgentListFilter, AgentProcessRecord, AgentRegistry, AgentStopReport},
    artifacts::{self, ResolvedRunId, RunArtifactFamily},
    autopilot,
    consult::{self, ConsultAskOptions, ConsultantRuntime, DEFAULT_CONSULT_TIMEOUT_SECONDS},
    inbox::{self, InboxPermissionMode, InboxScanOptions, InboxWorkspaceScanOptions},
    live_claim::{self, LiveClock},
    llm::{FakeProvider, PromptContext, ProviderCapabilities, Redactor, RepoExcerpt, WorkProposal},
    megafile::{
        MegafileAssessment, MegafileReport, MegafileStore, MegafileThresholdCalibration,
        MegafileThresholds,
    },
    merge::{
        self, CandidateValidationCommand, MegafileMergePolicy, MergeApplyOptions,
        MergeApplyPreview, MergeApplyReport, MergeCandidate, MergeCollectOptions,
        MergeForceOptions, MergePreviewOptions, ValidationEvidenceBundle, ValidationReport,
    },
    orchestrator::{
        self, AgentRunStatus, OrchestrationResumeOptions, OrchestrationRunControls,
        OrchestrationRunOptions, OrchestrationSummary, RunId, SemanticCoordinationMode,
        WorktreeReusePolicy,
    },
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
    sync_store::{ClaimTelemetryOutcome, MegafileClaimWarning, OwnerReport, SyncStore},
    worktree::{
        RepositoryInfo, WorktreeCreateOptions, WorktreeGcOptions, WorktreeGcReason,
        WorktreeGcReport, WorktreeGcStatus, WorktreeManager, WorktreeRecord,
        WorktreeRetentionPolicy,
    },
};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use git2::Repository;
use serde::Serialize;
use serde_json::Value;
use std::{
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
            Command::Coord(command) => command.run(),
            Command::Orchestrate(command) => command.run(),
            Command::Supervise(command) => command.run(),
            Command::Consult(command) => command.run(),
            Command::Inbox(command) => command.run(),
            Command::Scope(command) => command.run(),
            Command::Autopilot(command) => command.run(),
            Command::Review(command) => command.run(),
            Command::Agent(command) => command.run(),
            Command::Agents(command) => command.run(),
            Command::Llm(command) => command.run(),
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
    /// Run independent review adapters.
    Review(ReviewCommand),
    /// Run a provider-backed agent in an isolated worktree.
    Agent(AgentCommand),
    /// Inspect and stop live MACO-launched agent processes.
    Agents(AgentsCommand),
    /// Inspect local LLM adapter boundaries without network calls.
    Llm(LlmCommand),
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
                    let goal_spec = BoundedRegularReader::read_tree_no_follow_utf8(
                        &goal_file,
                        MAX_SUPERVISE_GOAL_FILE_BYTES,
                    )
                    .with_context(|| {
                        format!("failed to read goal/spec file {}", goal_file.display())
                    })?;
                    supervise::supervisor_plan_document_from_goal_spec(repo, "", &goal_spec)?
                }
                _ => bail!(
                    "supervise plan requires exactly one positional TASK_FILE or --from-goal <FILE>"
                ),
            };
            print_query_report(&plan, json)
        }
        SuperviseSubcommand::Run(args) => {
            let resolved = resolve_run_id_for_run(
                &args.repo,
                RunArtifactFamily::Supervise,
                args.run_id.as_deref(),
                args.json,
            )?;
            let report = supervise::run_supervisor_plan_file_with_concurrency_policy(
                SupervisorRunOptions {
                    repo: resolved.repo,
                    plan_file: args.supervisor_plan,
                    run_id: resolved.run_id,
                    codex_bin: args.codex_bin,
                    runtime: args.runtime,
                    allow_dirty_primary: args.allow_dirty_primary,
                },
                args.max_concurrent_children,
            )?;
            print_query_report(&report, args.json)?;
            if !report.success {
                bail!("supervise run failed");
            }
            Ok(())
        }
        SuperviseSubcommand::Status(args) => {
            let report = supervise::supervisor_status(args.repo, RunId::new(&args.run_id)?)?;
            print_query_report(&report, args.json)
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

#[derive(Debug, Subcommand)]
enum SuperviseSubcommand {
    /// Build a validated plan from a goal/spec, task file, or JSON supervisor plan.
    Plan(PlanSuperviseArgs),
    /// Run a supervisor plan with child Codex CLI orchestrators.
    Run(RunSuperviseArgs),
    /// Report durable run artifact status.
    Status(StatusSuperviseArgs),
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

#[derive(Debug, Args)]
struct RunSuperviseArgs {
    /// JSON supervisor plan file to run.
    supervisor_plan: PathBuf,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable run id for durable `.maco/o2/runs/<run-id>` artifacts. Omit to generate one.
    #[arg(long)]
    run_id: Option<String>,
    /// Codex-compatible executable to invoke. Ignored by the deterministic Fake runtime.
    #[arg(long, default_value = "codex")]
    codex_bin: PathBuf,
    /// Runtime. Fake is deterministic in-process simulation and never executes Codex or publishes.
    #[arg(long, value_enum, default_value_t = supervise::SupervisorRuntime::Codex)]
    runtime: supervise::SupervisorRuntime,
    /// Allow supervise to run when the primary worktree is dirty.
    #[arg(long)]
    allow_dirty_primary: bool,
    /// Maximum concurrent child assignments: `auto` uses measured host capacity.
    #[arg(long, default_value_t = supervise::SupervisorConcurrencyPolicy::Auto)]
    max_concurrent_children: supervise::SupervisorConcurrencyPolicy,
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
        }
    }
}

#[derive(Debug, Subcommand)]
enum ScopeSubcommand {
    /// Serve the localhost-only Scope observability backend.
    Serve(ScopeServeArgs),
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
            AutopilotSubcommand::Run(_) => Err(autopilot::effectful_autopilot_unavailable_error()),
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
    /// Run the fake-first autopilot workflow.
    Run(RunAutopilotArgs),
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
    task_file: PathBuf,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Stable run id for durable `.maco/autopilot/runs/<run-id>` artifacts. Omit to generate one.
    #[arg(long)]
    run_id: Option<String>,
    /// Codex-compatible executable to invoke. Omit for deterministic local fake mode.
    #[arg(long)]
    codex_bin: Option<PathBuf>,
    /// Legacy reviewer shell string; retained only to return a fail-closed error.
    #[arg(long)]
    reviewer_command: Option<String>,
    /// Allow autopilot to run when the primary worktree is dirty.
    #[arg(long)]
    allow_dirty_primary: bool,
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
                let report = artifacts::prune_runs(args.repo, family, args.keep, args.dry_run)?;
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
    /// Report deletions without deleting.
    #[arg(long)]
    dry_run: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
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
                let retention = WorktreeRetentionPolicy {
                    max_age: args.gc_max_age_seconds.map(Duration::from_secs),
                    max_count: args.gc_max_count,
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
                print_worktree_record(&record, args.json)
            }
            WorktreeSubcommand::Gc(args) => {
                let manager = WorktreeManager::new(args.repo);
                let report = manager.gc(WorktreeGcOptions {
                    worktree_root: args.worktree_root,
                    dry_run: args.dry_run,
                    remove_targets: !args.keep_targets,
                    retention: WorktreeRetentionPolicy {
                        max_age: args.max_age_seconds.map(Duration::from_secs),
                        max_count: args.max_count,
                    },
                    exclude_agent_id: None,
                })?;
                print_worktree_gc_report(&report, args.json)
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
                let claims = store.snapshot()?;
                print_claims(&claims, args.json, "No active claims.")
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

#[derive(Debug, Subcommand)]
enum WorktreeSubcommand {
    /// Create a linked worktree for an agent.
    Create(CreateWorktreeArgs),
    /// Collect an agent worktree diff and claim-boundary report.
    Diff(DiffWorktreeArgs),
    /// Remove clean, inactive managed worktrees and unregistered leftover directories.
    Gc(GcWorktreeArgs),
    /// Remove a linked worktree for an agent.
    Remove(RemoveWorktreeArgs),
    /// List registered worktrees.
    List(ListWorktreesArgs),
    /// Inspect authenticated pending worktree operations without recovering them.
    Pending(ListWorktreesArgs),
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
    /// Remove only eligible clean worktrees older than this many seconds.
    #[arg(long)]
    max_age_seconds: Option<u64>,
    /// Keep at most this many newest eligible clean worktrees.
    #[arg(long)]
    max_count: Option<usize>,
    /// Emit machine-readable JSON.
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
) -> Result<MergeApplyPreview> {
    let claims = resolve_claims(&repo, &agent_id, explicit_claims)?;
    let validation_evidence = load_validation_evidence(&validation_report_paths, &agent_id)?;
    merge::preview_merge_apply_with_megafile_policy(
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
                let preview = preview_merge_from_args(
                    args.repo,
                    args.agent_id,
                    args.claim,
                    args.validation_report,
                    args.forces.into_force_options(),
                    args.require_validation,
                    megafile_policy,
                )?;
                print_merge_preview(&preview, args.json)
            }
            MergeSubcommand::Apply(args) => {
                let megafile_policy = args.megafile_policy()?;
                let claims = resolve_claims(&args.repo, &args.agent_id, args.claim)?;
                let validation_evidence =
                    load_validation_evidence(&args.validation_report, &args.agent_id)?;
                let candidate_validation_commands = args
                    .validation_command
                    .into_iter()
                    .map(|command| CandidateValidationCommand { command })
                    .collect::<Vec<_>>();
                let preview_options = MergePreviewOptions {
                    collect: collect_options_from_claims(
                        &args.repo,
                        &args.agent_id,
                        claims,
                        true,
                        Vec::new(),
                    ),
                    forces: args.forces.into_force_options(),
                    require_validation: args.require_validation,
                };
                let report = merge::merge_apply_report_with_megafile_policy(
                    MergeApplyOptions {
                        preview: preview_options,
                        candidate_validation_commands,
                    },
                    validation_evidence,
                    megafile_policy,
                )?;
                if report.status == merge::MergeApplyReportStatus::Blocked {
                    if args.json {
                        print_merge_apply_report(&report, true)?;
                    }
                    let message = report
                        .error
                        .clone()
                        .unwrap_or_else(|| "merge apply refused".to_string());
                    bail!("{message}");
                }
                print_merge_apply_report(&report, args.json)
            }
        }
    }
}

#[derive(Debug, Subcommand)]
enum MergeSubcommand {
    /// Preview whether an agent worktree diff can be applied to the primary worktree.
    Preview(MergePreviewArgs),
    /// Apply an agent worktree diff to the primary worktree after safety checks.
    Apply(MergeApplyArgs),
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
    let repo = Repository::discover(repo_path)
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

fn print_merge_preview(preview: &MergeApplyPreview, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(preview)?);
    } else {
        print_merge_candidate(&preview.candidate, false)?;
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

fn print_merge_apply_report(report: &MergeApplyReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
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
    }
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

fn print_worktree_gc_report(report: &WorktreeGcReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "Worktree GC: {}",
        if report.dry_run { "dry-run" } else { "applied" }
    );
    println!("Considered: {}", report.considered_count);
    println!("Removed: {}", report.removed_count);
    println!("Protected: {}", report.protected_count);
    println!("Retained: {}", report.retained_count);
    println!("Targets cleaned: {}", report.target_removed_count);
    println!("Orphans pruned: {}", report.orphan_removed_count);
    for entry in &report.entries {
        let branch = entry.branch.as_deref().unwrap_or("-");
        let target = entry
            .target_path
            .as_ref()
            .map(|path| format!(" target={}", path.display()))
            .unwrap_or_default();
        println!(
            "{}\t{}\t{}\t{}\t{}{}",
            worktree_gc_status_label(entry.status),
            worktree_gc_reason_label(entry.reason),
            entry.name,
            branch,
            entry.path.display(),
            target
        );
    }
    Ok(())
}

fn worktree_gc_status_label(status: WorktreeGcStatus) -> &'static str {
    match status {
        WorktreeGcStatus::Removed => "removed",
        WorktreeGcStatus::WouldRemove => "would-remove",
        WorktreeGcStatus::Retained => "retained",
        WorktreeGcStatus::Protected => "protected",
        WorktreeGcStatus::OrphanPruned => "orphan-pruned",
        WorktreeGcStatus::OrphanWouldPrune => "orphan-would-prune",
    }
}

fn worktree_gc_reason_label(reason: WorktreeGcReason) -> &'static str {
    match reason {
        WorktreeGcReason::FinishedBranch => "finished-branch",
        WorktreeGcReason::RetentionKeep => "retention-keep",
        WorktreeGcReason::ExcludedCurrentWorktree => "excluded-current-worktree",
        WorktreeGcReason::Dirty => "dirty",
        WorktreeGcReason::ActiveLease => "active-lease",
        WorktreeGcReason::ActiveClaim => "active-claim",
        WorktreeGcReason::TargetRemoved => "target-removed",
        WorktreeGcReason::TargetWouldRemove => "target-would-remove",
        WorktreeGcReason::NoTarget => "no-target",
        WorktreeGcReason::UnregisteredOrphan => "unregistered-orphan",
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
    use super::*;

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
}
