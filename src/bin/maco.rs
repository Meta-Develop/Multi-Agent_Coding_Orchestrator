use anyhow::Result;
use clap::Parser;
use multi_agent_coding_orchestrator::cli::{route_literal_instruction_args, Cli};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    if multi_agent_coding_orchestrator::maybe_run_pinned_helper_from_args()? {
        return Ok(());
    }
    multi_agent_coding_orchestrator::configure_libgit2_repository_extensions()?;
    match run_cli() {
        Err(error) => {
            if let Some(exit) = error.downcast_ref::<multi_agent_coding_orchestrator::supervise::WorkerJournalCommandExit>() {
                eprintln!("{error:#}");
                std::process::exit(exit.code());
            }
            Err(error)
        }
        result => result,
    }
}

#[tokio::main]
async fn run_cli() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    Cli::parse_from(route_literal_instruction_args(std::env::args_os())).run()
}
