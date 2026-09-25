//! Headless, owner-operated Grok device-auth setup. No login process or stdin.
//!
//! Only non-secret metadata and derived managed-home paths cross this boundary.
//! Vendor credentials stay in place and are validated by the existing adapter.

use super::*;
use crate::account_authority::PendingLoginBinding;

const USAGE: &str = "Usage: cam-grok-setup [--data-dir ABSOLUTE_PATH] prepare ACCOUNT_ID
       cam-grok-setup [--data-dir ABSOLUTE_PATH] status
       cam-grok-setup [--data-dir ABSOLUTE_PATH] complete ACCOUNT_ID --incarnation INCARNATION

Linux only. Defaults to the CAM application data directory.
prepare creates a new pending home and prints a command for your own terminal;
it never starts login. status shows metadata, including accountIncarnation.
complete validates vendor-written auth and explicitly selects the account,
replacing any previous selection only if no CAM use/login lease is active.
Use the incarnation from status for the pending account you prepared.
No passwords, tokens, auth paths, or default-home import are accepted.
Account IDs cannot contain double underscores or end with an underscore.
";

enum Action<'a> {
    Prepare(&'a str),
    Status,
    Complete { id: &'a str, incarnation: &'a str },
}

fn setup_account_id_is_safe(id: &str) -> bool {
    // The existing lease format is provider__account__incarnation.lock. These
    // IDs would make its splitn(3, "__") parser ambiguous and poison mutations.
    account_id_is_safe(id) && !id.contains("__") && !id.ends_with('_')
}

/// CLI boundary: errors are fixed messages, never vendor bytes, JSON parser
/// diagnostics, or echoed unknown arguments. Success contains metadata only.
pub fn run(args: &[String]) -> std::result::Result<String, &'static str> {
    if matches!(args, [help] if help == "--help" || help == "-h") {
        return Ok(USAGE.to_string());
    }
    let (data_dir, args) = match args {
        [flag, path, rest @ ..] if flag == "--data-dir" => (Some(PathBuf::from(path)), rest),
        _ => (None, args),
    };
    let action = match args {
        [command, id] if command == "prepare" && setup_account_id_is_safe(id) => {
            Action::Prepare(id)
        }
        [command] if command == "status" => Action::Status,
        [command, id, flag, incarnation]
            if command == "complete" && setup_account_id_is_safe(id) && flag == "--incarnation" =>
        {
            Action::Complete { id, incarnation }
        }
        _ => return Err("invalid arguments; see --help"),
    };
    if !cfg!(target_os = "linux") {
        return Err("device-auth setup is supported only on Linux");
    }
    let data_dir = data_dir
        .or_else(|| paths::project_dirs().map(|dirs| dirs.data_dir().to_path_buf()))
        .ok_or("CAM application data directory unavailable")?;
    let adapter = GrokCliAdapter::default().with_data_dir(data_dir);
    execute(&adapter, action).map_err(|error| match error {
        Error::StaleAccount { .. } => "stale pending incarnation; inspect status before retrying",
        Error::AccountAuthorityBusy { .. } => "account authority is in use; no selection changed",
        // A durable write may fail after rename (e.g. directory fsync). Do not
        // claim rollback or blindly retry; status resolves the visible state.
        _ => "setup failed; inspect status before retrying (no login was launched)",
    })
}

fn execute(adapter: &GrokCliAdapter, action: Action<'_>) -> Result<String> {
    match action {
        Action::Prepare(id) | Action::Complete { id, .. } if !setup_account_id_is_safe(id) => {
            return Err(config_write(
                "account id is incompatible with the lease format",
            ));
        }
        _ => {}
    }
    let data_dir = adapter.resolved_data_dir()?;
    validate_data_path(&data_dir)?;
    if !data_dir.exists() && matches!(action, Action::Status) {
        return Ok("[]\n".to_string());
    }
    if matches!(action, Action::Prepare(_)) {
        fsx::create_dir_all_private(&data_dir)?;
        validate_data_path(&data_dir)?;
    }
    validate_directory(&data_dir, "CAM application data directory")?;
    let registry = StoredAccountRegistry::new(paths::stored_accounts_path(&data_dir));
    match fs::symlink_metadata(registry.metadata_path()) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(config_write(
                "CAM metadata is not a regular non-symlink file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match action {
        Action::Prepare(id) => prepare(adapter, &registry, id),
        Action::Status => {
            // Do not use list_accounts: it can discover the ordinary Grok home.
            let accounts: Vec<_> = registry
                .load()?
                .into_iter()
                .filter(|account| account.provider_id == PROVIDER_ID)
                .collect();
            Ok(format!("{}\n", serde_json::to_string_pretty(&accounts)?))
        }
        Action::Complete { id, incarnation } => {
            let binding = PendingLoginBinding {
                provider_id: PROVIDER_ID.to_string(),
                account_id: id.to_string(),
                account_incarnation: incarnation.to_string(),
            };
            registry.complete_pending_oauth_vendor_home_and_select(
                &binding,
                |pending, previous| {
                    // Match the existing switch gate for the old selected home too.
                    if let Some(previous) = previous {
                        let home = adapter.managed_home(previous)?;
                        validate_managed_directories(&data_dir, &home, false)?;
                        let _operation = HomeOperationGuard::acquire(&home)?;
                        gate_managed_home(&home, true)?;
                    }
                    let home = adapter.managed_home(pending)?;
                    validate_managed_directories(&data_dir, &home, false)?;
                    let _operation = HomeOperationGuard::acquire(&home)?;
                    gate_managed_home(&home, true)?;
                    adapter.finish_pending_oauth_login(&home)
                },
            )?;
            Ok("Completed and selected the managed Grok account.\n".to_string())
        }
    }
}

fn prepare(adapter: &GrokCliAdapter, registry: &StoredAccountRegistry, id: &str) -> Result<String> {
    if !setup_account_id_is_safe(id) {
        return Err(config_write("account id is not a safe path component"));
    }
    let data_dir = adapter.resolved_data_dir()?;
    let home = managed_account_dir(&data_dir, PROVIDER_ID, id);
    validate_managed_directories(&data_dir, &home, true)?;
    // This early check avoids unnecessary metadata/lease I/O in the common
    // duplicate case. The exclusive reservation below is the authority gate.
    match fs::symlink_metadata(&home) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => {
            return Err(config_write(
                "managed home already exists or cannot be inspected",
            ))
        }
    }
    prepare_after_absence_check(adapter, registry, id)
}

fn prepare_after_absence_check(
    adapter: &GrokCliAdapter,
    registry: &StoredAccountRegistry,
    id: &str,
) -> Result<String> {
    if !setup_account_id_is_safe(id) {
        return Err(config_write(
            "account id is incompatible with the lease format",
        ));
    }
    let data_dir = adapter.resolved_data_dir()?;
    let home = registry.prepare_pending_oauth_vendor_home(PROVIDER_ID, id, |account| {
        let home = adapter.managed_home(account)?;
        let _operation = HomeOperationGuard::acquire(&home)?;
        reserve_fresh_home(&data_dir, &home)?;
        let prepared = adapter.prepare_pending_oauth_home(account)?;
        if prepared.plan != PendingOAuthHomePlan::NeedsInteractiveOAuth || prepared.path != home {
            return Err(config_write(
                "refusing to recover existing vendor auth during prepare",
            ));
        }
        Ok(home)
    })?;
    let path = home
        .to_str()
        .ok_or_else(|| config_write("managed home is not UTF-8"))?;
    let quoted = format!("'{}'", path.replace('\'', "'\"'\"'"));
    Ok(format!(
        "GROK_HOME={quoted}\nRun in your own terminal:\nenv -u GROK_AUTH_PATH GROK_HOME={quoted} grok login --device-auth\n"
    ))
}

fn reserve_fresh_home(data_dir: &Path, home: &Path) -> Result<()> {
    for parent in [
        data_dir.join("accounts"),
        data_dir.join("accounts").join(PROVIDER_ID),
    ] {
        validate_data_path(&parent)?;
        fsx::create_dir_all_private(&parent)?;
        validate_data_path(&parent)?;
        validate_directory(&parent, "managed Grok parent")?;
    }
    // Non-recursive mkdir is exclusive: even a retained EMPTY home is refused.
    // The caller holds the registry lock and exact-incarnation pending lease;
    // no row is published if this reservation or adapter preparation fails.
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(home)
        .map_err(|error| fsx::io_at(home, error))?;
    validate_managed_directories(data_dir, home, false)
}

fn validate_data_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|path| path.chars().any(char::is_control))
        || path.components().any(|part| {
            !matches!(
                part,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(config_write(
            "CAM data path must be an absolute, plain directory path",
        ));
    }
    // Walk from the trusted root before descending into each component. Missing
    // components are checked again after private creation, before registry I/O.
    let mut ancestor = PathBuf::new();
    for component in path.components() {
        ancestor.push(component.as_os_str());
        match fs::symlink_metadata(&ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(config_write("CAM data path has an unsafe ancestor"));
            }
            Ok(metadata) => {
                #[cfg(unix)]
                crate::account_authority::reject_owner_and_mode(&ancestor, &metadata).map_err(
                    |_| config_write("CAM data path has an untrusted owner or writable ancestor"),
                )?;
                #[cfg(not(unix))]
                let _ = metadata;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_managed_directories(data_dir: &Path, home: &Path, allow_missing: bool) -> Result<()> {
    for directory in [
        data_dir.join("accounts"),
        data_dir.join("accounts").join(PROVIDER_ID),
        home.to_path_buf(),
    ] {
        match fs::symlink_metadata(&directory) {
            Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => {}
            _ => {
                validate_data_path(&directory)?;
                validate_directory(&directory, "managed Grok directory")?;
            }
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
