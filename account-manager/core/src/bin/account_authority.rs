//! Headless account-authority service: Unix socket listen + accept loop.

use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;

use coding_agent_manager_lib::account_authority::{
    listen, resolve_socket_path, AuthorityContext, AuthorityServerConfig, ListenError,
    StoredAccountRegistry,
};
use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::login::LoginService;
use coding_agent_manager_lib::paths;
use coding_agent_manager_lib::providers::gemini_cli::GeminiCliAdapter;

const SOCKET_ENV: &str = "CAM_ACCOUNT_AUTHORITY_SOCKET";

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr(), "{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let configured = configured_socket_path()?;
    let safe = resolve_socket_path(&configured).map_err(|error| error.to_string())?;

    let registry = stored_account_registry().map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let service = LoginService::new(
        StoredAccountRegistry::new(registry.metadata_path().to_path_buf()),
        runtime.handle().clone(),
    );
    let ctx = AuthorityContext::new(registry);
    let config = AuthorityServerConfig::new(ctx)
        .map_err(|error| error.to_string())?
        .with_gemini_login(service, GeminiCliAdapter::default());

    let listener = listen(safe, config).map_err(listen_failure)?;

    #[cfg(unix)]
    {
        let bound = listener.path().display();
        let _ = writeln!(io::stderr(), "account-authority listening on {bound}");
        loop {
            if let Err(error) = listener.accept_once() {
                let _ = writeln!(io::stderr(), "accept failed: {error}");
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = listener;
        Err("unix socket transport is unsupported on this platform".to_string())
    }
}

fn listen_failure(error: ListenError) -> String {
    error.to_string()
}

fn stored_account_registry() -> Result<StoredAccountRegistry, Error> {
    let dirs = paths::project_dirs().ok_or_else(|| Error::ConfigRead {
        provider: "account-metadata".to_string(),
        reason: "the application data directory could not be resolved".to_string(),
    })?;
    Ok(StoredAccountRegistry::new(paths::stored_accounts_path(
        dirs.data_dir(),
    )))
}

/// Operator-supplied socket path from `--socket-path` or [`SOCKET_ENV`].
pub fn configured_socket_path() -> Result<PathBuf, String> {
    configured_socket_path_from(
        env::args().skip(1).collect::<Vec<_>>().as_slice(),
        env::var(SOCKET_ENV).ok(),
    )
}

fn configured_socket_path_from(
    args: &[String],
    env_value: Option<String>,
) -> Result<PathBuf, String> {
    let mut from_flag: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            "--socket-path" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--socket-path requires a value".to_string())?;
                from_flag = Some(PathBuf::from(value));
                index += 2;
            }
            unknown => {
                return Err(format!("unknown argument: {unknown} (try --help)"));
            }
        }
    }

    if let Some(path) = from_flag {
        if path.as_os_str().is_empty() {
            return Err(format!(
                "socket path is required: pass --socket-path PATH or set {SOCKET_ENV}"
            ));
        }
        return Ok(path);
    }
    if let Some(path) = env_value {
        if path.is_empty() {
            return Err(format!(
                "socket path is required: pass --socket-path PATH or set {SOCKET_ENV}"
            ));
        }
        return Ok(PathBuf::from(path));
    }
    Err(format!(
        "socket path is required: pass --socket-path PATH or set {SOCKET_ENV}"
    ))
}

fn print_usage() {
    let _ = writeln!(
        io::stderr(),
        "Usage: account-authority --socket-path PATH\n\
         Environment: {SOCKET_ENV} (used when --socket-path is omitted)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_socket_path_fails_closed() {
        let error = configured_socket_path_from(&[], None).expect_err("missing");
        assert!(error.contains(SOCKET_ENV));
    }

    #[test]
    fn flag_overrides_empty_env() {
        let path = configured_socket_path_from(
            &["--socket-path".to_string(), "/tmp/account.sock".to_string()],
            Some(String::new()),
        )
        .expect("flag");
        assert_eq!(path.as_os_str(), "/tmp/account.sock");
    }

    #[test]
    fn env_used_when_flag_absent() {
        let path =
            configured_socket_path_from(&[], Some("/run/account.sock".to_string())).expect("env");
        assert_eq!(path.as_os_str(), "/run/account.sock");
    }

    #[test]
    fn unknown_argument_is_rejected() {
        let error =
            configured_socket_path_from(&["--verbose".to_string()], None).expect_err("unknown");
        assert!(error.contains("--verbose"));
    }
}
