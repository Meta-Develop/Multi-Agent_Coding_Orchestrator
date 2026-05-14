use crate::worktree::{RepositoryInfo, WorktreeCreateOptions, WorktreeManager, WorktreeRecord};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

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
            Command::Worktree(command) => command.run(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a Git repository for orchestrated agent work.
    Init(InitArgs),
    /// Manage linked Git worktrees for sub-agents.
    Worktree(WorktreeCommand),
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
        }
    }
}

#[derive(Debug, Subcommand)]
enum WorktreeSubcommand {
    /// Create a linked worktree for an agent.
    Create(CreateWorktreeArgs),
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
