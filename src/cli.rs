use crate::{
    llm::{PromptContext, ProviderCapabilities, Redactor, RepoExcerpt},
    merge::{
        self, MergeApplyOptions, MergeApplyPreview, MergeApplyReport, MergeCandidate,
        MergeCollectOptions, MergeForceOptions, MergePreviewOptions, ValidationReport,
    },
    orchestrator::{
        self, AgentRunStatus, OrchestrationRunControls, OrchestrationRunOptions,
        OrchestrationSummary, RunId, WorktreeReusePolicy,
    },
    repo_map::{self, RepoEntryKind, RepoMap},
    repo_semantic::{self, SemanticRepoMap},
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
            Command::Sync(command) => command.run(),
            Command::Orchestrate(command) => command.run(),
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
    /// Manage repository-local sync path claims.
    Sync(SyncCommand),
    /// Run local orchestration plans.
    Orchestrate(OrchestrateCommand),
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
                        notes: "Deterministic test provider; no credentials or network required."
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
    forces: MergeForceOptions,
) -> Result<MergeApplyPreview> {
    let claims = resolve_claims(&repo, &agent_id, explicit_claims)?;
    merge::preview_merge_apply(MergePreviewOptions {
        collect: collect_options_from_claims(&repo, &agent_id, claims, true, Vec::new()),
        forces,
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
                    args.forces.into_force_options(),
                )?;
                print_merge_preview(&preview, args.json)
            }
            MergeSubcommand::Apply(args) => {
                let report = merge::apply_merge_result(MergeApplyOptions {
                    preview: MergePreviewOptions {
                        collect: collect_options_from_claims(
                            &args.repo,
                            &args.agent_id,
                            resolve_claims(&args.repo, &args.agent_id, args.claim)?,
                            true,
                            Vec::new(),
                        ),
                        forces: args.forces.into_force_options(),
                    },
                })?;
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
        let validations = validation_reports_from_summary(agent);
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

fn validation_reports_from_summary(agent: &Value) -> Vec<ValidationReport> {
    let mut reports = agent
        .get("validation")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(validation_report_from_value)
        .collect::<Vec<_>>();
    reports.sort_by(|left, right| left.name.cmp(&right.name));
    reports
}

fn validation_report_from_value(value: &Value) -> Option<ValidationReport> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| value.get("command").and_then(Value::as_str))?
        .to_string();
    let status = match value.get("status").and_then(Value::as_str) {
        Some("succeeded") => merge::ValidationStatus::Passed,
        Some("failed") => merge::ValidationStatus::Failed,
        Some("skipped") => merge::ValidationStatus::Skipped,
        Some("pending") => merge::ValidationStatus::NotRun,
        _ => merge::ValidationStatus::NotRun,
    };
    let message = value
        .get("error")
        .and_then(Value::as_str)
        .map(str::to_string);

    Some(ValidationReport {
        name,
        status,
        message,
    })
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

fn parse_worktree_reuse_policy(value: &str) -> std::result::Result<WorktreeReusePolicy, String> {
    match value {
        "clean" => Ok(WorktreeReusePolicy::Clean),
        "required" => Ok(WorktreeReusePolicy::Required),
        "fresh" => Ok(WorktreeReusePolicy::Fresh),
        "reset" => Ok(WorktreeReusePolicy::Reset),
        _ => Err("expected one of: clean, required, fresh, reset".to_string()),
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
