use anyhow::Result;
use clap::Parser;
use multi_agent_coding_orchestrator::cli::Cli;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    if multi_agent_coding_orchestrator::maybe_run_pinned_helper_from_args()? {
        return Ok(());
    }
    // SAFETY: This is the process's single libgit2 configuration point and it
    // runs before Tokio creates worker threads or any repository is opened.
    unsafe {
        multi_agent_coding_orchestrator::worktree::configure_libgit2_repository_extensions()?;
    }
    run_cli()
}

#[tokio::main]
async fn run_cli() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Cli::parse().run()
}
