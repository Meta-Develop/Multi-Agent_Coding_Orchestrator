use crate::{
    agent::{
        self, AgentRunOptions, AgentRunReport, AgentValidationCommand, AgentWorktreeReusePolicy,
        ProviderCommandPolicy,
    },
    artifacts::{self, ResolvedRunId, RunArtifactFamily},
    autopilot::{self, AutopilotRunOptions},
    inbox::{self, InboxRunOptions, InboxScanOptions, InboxWatchOptions},
    live_claim::{self, LiveClock},
    llm::{FakeProvider, PromptContext, ProviderCapabilities, Redactor, RepoExcerpt, WorkProposal},
    merge::{
        self, CandidateValidationCommand, MergeApplyOptions, MergeApplyPreview, MergeApplyReport,
        MergeCandidate, MergeCollectOptions, MergeForceOptions, MergePreviewOptions,
        ValidationReport,
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
    semantic_coord::{
        SemanticCoordinationReport, SemanticIntentRequest, SemanticIntentStore, SemanticIntentToken,
    },
    supervise::{self, SupervisorRunOptions},
    sync::ClaimToken,
    sync_store::{OwnerReport, SyncStore},
    worktree::{RepositoryInfo, WorktreeCreateOptions, WorktreeManager, WorktreeRecord},
};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use git2::Repository;
use serde::Serialize;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

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
            Command::Worktree(command) => command.run(),
            Command::Merge(command) => command.run(),
            Command::Live(command) => command.run(),
            Command::Pr(command) => command.run(),
            Command::Issue(command) => command.run(),
            Command::Sync(command) => command.run(),
            Command::Coord(command) => command.run(),
            Command::Orchestrate(command) => command.run(),
            Command::Supervise(command) => command.run(),
            Command::Inbox(command) => command.run(),
            Command::Autopilot(command) => command.run(),
            Command::Review(command) => command.run(),
            Command::Agent(command) => command.run(),
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
    /// Scan and react to safe GitHub issue and pull request inbox items.
    Inbox(InboxCommand),
    /// Run local-first autopilot workflow phases.
    Autopilot(AutopilotCommand),
    /// Run independent review adapters.
    Review(ReviewCommand),
    /// Run a provider-backed agent in an isolated worktree.
    Agent(AgentCommand),
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
                let map = repo_semantic::scan_repository(args.repo)?;
                let report = repo_semantic::risk_report_for_paths(&map, args.paths);
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
        match self.command {
            SuperviseSubcommand::Plan(args) => {
                let plan = supervise::supervisor_plan_from_task_file(args.repo, args.task_file)?;
                print_query_report(&plan, args.json)
            }
            SuperviseSubcommand::Run(args) => {
                let resolved = resolve_run_id_for_run(
                    &args.repo,
                    RunArtifactFamily::Supervise,
                    args.run_id.as_deref(),
                    args.json,
                )?;
                let report = supervise::run_supervisor_plan_file(SupervisorRunOptions {
                    repo: resolved.repo,
                    plan_file: args.supervisor_plan,
                    run_id: resolved.run_id,
                    codex_bin: args.codex_bin,
                    allow_dirty_primary: args.allow_dirty_primary,
                })?;
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
                let report =
                    supervise::collect_supervisor_run(args.repo, RunId::new(&args.run_id)?)?;
                print_query_report(&report, args.json)?;
                if !report.success {
                    bail!("supervise run failed");
                }
                Ok(())
            }
            SuperviseSubcommand::Artifacts(command) => command.run(RunArtifactFamily::Supervise),
        }
    }
}

#[derive(Debug, Subcommand)]
enum SuperviseSubcommand {
    /// Convert a task file or JSON supervisor plan into a normalized supervisor plan.
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
    /// Task file or JSON supervisor plan file.
    task_file: PathBuf,
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
    /// Codex-compatible executable to invoke. Tests should pass a fake executable.
    #[arg(long, default_value = "codex")]
    codex_bin: PathBuf,
    /// Allow supervise to run when the primary worktree is dirty.
    #[arg(long)]
    allow_dirty_primary: bool,
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
                let resolved = resolve_run_id_for_run(
                    &args.repo,
                    RunArtifactFamily::Inbox,
                    args.run_id.as_deref(),
                    args.json,
                )?;
                let report = inbox::run_inbox(InboxRunOptions {
                    repo: resolved.repo,
                    run_id: resolved.run_id,
                    github: args.github,
                    dry_run: args.dry_run,
                    max_items: args.max_items,
                })?;
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
                    dry_run: args.dry_run,
                    max_items: args.max_items,
                })?;
                print_query_report(&report, args.json)?;
                if report.runs.iter().any(|run| !run.success) {
                    bail!("inbox watch observed a failed run");
                }
                Ok(())
            }
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
    /// List, inspect, or prune durable run artifacts.
    Artifacts(ArtifactsCommand),
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
                let resolved = resolve_run_id_for_run(
                    &args.repo,
                    RunArtifactFamily::Autopilot,
                    args.run_id.as_deref(),
                    args.json,
                )?;
                let report = autopilot::run_autopilot_plan_file(AutopilotRunOptions {
                    repo: resolved.repo,
                    plan_file: args.task_file,
                    run_id: resolved.run_id,
                    codex_bin: args.codex_bin,
                    reviewer_command: args.reviewer_command,
                    allow_dirty_primary: args.allow_dirty_primary,
                })?;
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
    /// External reviewer shell command. Omit for deterministic fake review mode.
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
                let reviewer = if let Some(command) = args.reviewer_command {
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
    /// External reviewer shell command. Omit for deterministic fake review mode.
    #[arg(long)]
    reviewer_command: Option<String>,
    /// Timeout for the external reviewer command.
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
struct WorktreeCommand {
    #[command(subcommand)]
    command: WorktreeSubcommand,
}

impl WorktreeCommand {
    fn run(self) -> Result<()> {
        match self.command {
            WorktreeSubcommand::Create(args) => {
                let manager = WorktreeManager::new(args.repo);
                let record = manager.create(WorktreeCreateOptions {
                    agent_id: args.agent_id,
                    branch: args.branch,
                    base: args.base,
                    worktree_root: args.worktree_root,
                })?;
                print_worktree_record(&record, args.json)
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
                let claim = store.claim_paths(&args.agent_id, args.paths)?;
                print_path_claim("Claim", &claim, args.json)
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
            LiveSubcommand::Heartbeat(args) => {
                let now = live_clock(args.now.as_deref())?;
                let report = live_claim::heartbeat(args.repo, &args.claim_id, &args.by, &now)?;
                print_query_report(&report, args.json)
            }
            LiveSubcommand::OverrideRelease(args) => {
                let now = live_clock(args.now.as_deref())?;
                let report = live_claim::override_release(
                    args.repo,
                    &args.claim_id,
                    &args.by,
                    &args.reason,
                    &now,
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
    /// Refresh a claim heartbeat timestamp.
    Heartbeat(LiveHeartbeatArgs),
    /// Move a stale active claim to handoff by explicit override.
    OverrideRelease(LiveOverrideReleaseArgs),
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
struct LiveHeartbeatArgs {
    /// Claim id to refresh.
    claim_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Actor refreshing the claim.
    #[arg(long)]
    by: String,
    /// Deterministic current timestamp for tests.
    #[arg(long)]
    now: Option<String>,
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
    /// Deterministic current timestamp for tests.
    #[arg(long)]
    now: Option<String>,
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
    /// Remove a linked worktree for an agent.
    Remove(RemoveWorktreeArgs),
    /// List registered worktrees.
    List(ListWorktreesArgs),
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
) -> Result<MergeApplyPreview> {
    let claims = resolve_claims(&repo, &agent_id, explicit_claims)?;
    let validations = load_validation_reports(&validation_report_paths, &agent_id)?;
    merge::preview_merge_apply(MergePreviewOptions {
        collect: collect_options_from_claims(&repo, &agent_id, claims, true, validations),
        forces,
        require_validation,
    })
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
                let preview = preview_merge_from_args(
                    args.repo,
                    args.agent_id,
                    args.claim,
                    args.validation_report,
                    args.forces.into_force_options(),
                    args.require_validation,
                )?;
                print_merge_preview(&preview, args.json)
            }
            MergeSubcommand::Apply(args) => {
                let claims = resolve_claims(&args.repo, &args.agent_id, args.claim)?;
                let validations = load_validation_reports(&args.validation_report, &args.agent_id)?;
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
                        validations,
                    ),
                    forces: args.forces.into_force_options(),
                    require_validation: args.require_validation,
                };
                let report = if args.json {
                    let report = merge::merge_apply_report(MergeApplyOptions {
                        preview: preview_options,
                        candidate_validation_commands,
                    })?;
                    if report.status == merge::MergeApplyReportStatus::Blocked {
                        print_merge_apply_report(&report, true)?;
                        let message = report
                            .error
                            .clone()
                            .unwrap_or_else(|| "merge apply refused".to_string());
                        bail!("{message}");
                    }
                    report
                } else {
                    merge::apply_merge_result(MergeApplyOptions {
                        preview: preview_options,
                        candidate_validation_commands,
                    })?
                };
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
    /// JSON validation report file. Repeat to supply multiple reports.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require at least one passed validation report before preview is considered safe.
    #[arg(long)]
    require_validation: bool,
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
    /// JSON validation report file. Repeat to supply multiple reports.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require at least one passed validation report or candidate validation command.
    #[arg(long)]
    require_validation: bool,
    /// Shell command to validate the temporary merged candidate before applying to primary.
    #[arg(long = "validation-command")]
    validation_command: Vec<String>,
    #[command(flatten)]
    forces: MergeForceArgs,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
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
                let report = publication::preview_pr_with_validation_requirement(
                    pr_options_from_preview_args(args)?,
                    require_validation,
                )?;
                print_pr_publication_report(&report, json)
            }
            PrSubcommand::Publish(args) => {
                let json = args.json;
                let require_validation = args.require_validation;
                let report = publication::publish_pr_with_validation_requirement(
                    pr_options_from_publish_args(args)?,
                    require_validation,
                )?;
                print_pr_publication_report(&report, json)?;
                if report.status == PrPublicationStatus::Blocked {
                    bail!("pr publish refused: merge-preview blockers remain");
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
    /// Publish an agent worktree through an explicit forge.
    Publish(PrPublishArgs),
}

#[derive(Debug, Args)]
struct PrPreviewArgs {
    /// Stable agent id used when the worktree was created.
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long, required = true)]
    claim: Vec<PathBuf>,
    /// JSON validation report file. Repeat to supply multiple reports.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require at least one passed validation report before PR preview is publishable.
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
    agent_id: String,
    /// Repository path.
    #[arg(long, default_value = ".")]
    repo: PathBuf,
    /// Explicit claimed path. Repeat to provide multiple claims.
    #[arg(long, required = true)]
    claim: Vec<PathBuf>,
    /// JSON validation report file. Repeat to supply multiple reports.
    #[arg(long)]
    validation_report: Vec<PathBuf>,
    /// Require at least one passed validation report before PR publication.
    #[arg(long)]
    require_validation: bool,
    /// Forge adapter. `fake` is deterministic and local-only; `github` shells out explicitly.
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

fn pr_options_from_preview_args(args: PrPreviewArgs) -> Result<PrPublicationOptions> {
    let validations = load_validation_reports(&args.validation_report, &args.agent_id)?;
    Ok(PrPublicationOptions {
        repo: args.repo,
        agent_id: args.agent_id,
        claimed_paths: args.claim,
        validations,
        forge: args.forge,
        draft: !args.ready,
    })
}

fn pr_options_from_publish_args(args: PrPublishArgs) -> Result<PrPublicationOptions> {
    let validations = load_validation_reports(&args.validation_report, &args.agent_id)?;
    Ok(PrPublicationOptions {
        repo: args.repo,
        agent_id: args.agent_id,
        claimed_paths: args.claim,
        validations,
        forge: args.forge,
        draft: !args.ready,
    })
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
        (None, Some(path)) => fs::read_to_string(&path)
            .with_context(|| format!("failed to read issue body file {}", path.display()))?,
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
    let contents = fs::read_to_string(summary_json)
        .with_context(|| format!("failed to read summary JSON {}", summary_json.display()))?;
    let summary: Value = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse summary JSON {}", summary_json.display()))?;
    let agents = summary
        .get("agents")
        .and_then(Value::as_array)
        .context("summary JSON must contain an agents array")?;
    let mut candidates = Vec::new();

    for agent in agents {
        let agent_id = agent
            .get("id")
            .and_then(Value::as_str)
            .context("summary agent is missing string id")?;
        let claims = agent_paths_from_summary(agent)
            .with_context(|| format!("summary agent '{agent_id}' has invalid paths"))?;
        let validations = validation_reports_from_summary(agent).with_context(|| {
            format!("summary agent '{agent_id}' has invalid validation reports")
        })?;
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
            path.as_str()
                .map(PathBuf::from)
                .context("agent path must be a string")
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

fn load_validation_reports(paths: &[PathBuf], agent_id: &str) -> Result<Vec<ValidationReport>> {
    let mut reports = Vec::new();
    for path in paths {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read validation report {}", path.display()))?;
        let value: Value = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse validation report {}", path.display()))?;
        reports.extend(
            merge::validation_reports_from_json_for_agent(&value, Some(agent_id))
                .with_context(|| format!("invalid validation report {}", path.display()))?,
        );
    }
    reports.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.paths.cmp(&right.paths))
            .then_with(|| left.message.cmp(&right.message))
    });
    Ok(reports)
}

#[derive(Debug, Serialize)]
struct SemanticSymbolQueryReport {
    query: String,
    matches: Vec<repo_semantic::SemanticSymbol>,
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
    let task = fs::read_to_string(&args.task_file)
        .with_context(|| format!("failed to read task file {}", args.task_file.display()))?;
    let mut context = PromptContext::new(task, &args.agent_id);
    let mut claimed_paths = args
        .paths
        .into_iter()
        .map(normalize_display_path)
        .collect::<Vec<_>>();
    claimed_paths.sort();
    claimed_paths.dedup();

    for path in &claimed_paths {
        context = context.with_claimed_path(path.clone(), "explicit prompt preview path");
        let full_path = repo.join(path);
        if full_path.is_file() {
            let content = fs::read_to_string(&full_path)
                .with_context(|| format!("failed to read prompt path {}", path.display()))?;
            context = context.with_repo_excerpt(
                RepoExcerpt::new(path.clone(), content).with_language(language_for_path(path)),
            );
        }
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

fn run_agent_from_args(args: RunAgentArgs) -> Result<AgentRunReport> {
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
    let task = fs::read_to_string(&args.task_file)
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
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read fake proposal {}", path.display()))?;
    serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse fake proposal {}", path.display()))
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
