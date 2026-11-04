//! Owner-operated setup only: this binary never launches Codex or reads stdin.

fn main() -> std::process::ExitCode {
    let args: Result<Vec<_>, _> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect();
    let result = args
        .map_err(|_| "arguments must be valid UTF-8")
        .and_then(|args| coding_agent_manager_lib::providers::codex_cli::device_setup::run(&args));
    match result {
        Ok(output) => {
            print!("{output}");
            std::process::ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("cam-codex-setup: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}
