//! Cursor adapter (editor and `cursor-agent` CLI).
//!
//! Observed layout on Linux, cursor-agent 2026.06.26:
//!
//! - `~/.config/cursor/cli-config.json` [verified-local] — CLI settings only:
//!   `version`, `editor`, `display`, `permissions`, `approvalMode`, `sandbox`,
//!   `network`, `attribution`. No credential material was present in it.
//!   Official 2026-09-20 global path is `~/.cursor/cli-config.json`
//!   [verified-docs]. This adapter does not treat the local XDG-style path as
//!   install evidence.
//! - `~/.cursor/` [verified-local] — `agents/`, `projects/`, `extensions/`,
//!   `skills-cursor/`, `ai-tracking/ai-code-tracking.db`, `argv.json`.
//!
//! Official configuration [verified-docs]
//! (https://cursor.com/docs/cli/reference/configuration):
//!
//! - Global macOS/Linux: `~/.cursor/cli-config.json`
//! - Global Windows: `%USERPROFILE%\.cursor\cli-config.json`
//! - Project: `.cursor/cli.json` (permissions only)
//! - `CURSOR_CONFIG_DIR` relocates Cursor state. MACO pairs it with an isolated
//!   managed `HOME` and the documented file credential store; it never imports
//!   an ambient editor or CLI home.
//!
//! Official schema fields are settings only: `version`, `editor.vimMode`,
//! `permissions.*`, `channel`, `model`, `maxMode`, `hasChangedDefaultModel`,
//! `notifications`, `hints`, `rewind`, `suggestNextPrompt`, `display.*`,
//! `approvalMode`, `sandbox.*`, `network.useHttp1ForAgent`, `attribution.*`.
//! No credential, token, or authInfo fields. Third-party authInfo-in-cli-config
//! claims stay unofficial.
//!
//! File-store path `~/.cursor/auth.json` is [verified-docs] when
//! `AGENT_CLI_CREDENTIAL_STORE=file`. Presence of that regular file, or of
//! official `~/.cursor/cli-config.json`, is install evidence (same grain as
//! Copilot `~/.copilot/config.json`). This adapter never reads, parses, or
//! logs either file. An empty `~/.cursor` directory or a missing file is not
//! credentials and is not install evidence.
//!
//! macOS Keychain service names `cursor-access-token`,
//! `cursor-refresh-token`, and `cursor-api-key` are [verified-docs]. Default
//! Linux/Windows persist remains [unknown]. MACO therefore selects managed
//! accounts only through an explicit launch environment and never mutates the
//! ambient Cursor account.
//!
//! Cursor documents `cursor-agent status` as a read-only authentication check
//! that displays account information [verified-docs]. `list_accounts` uses
//! that vendor surface instead of treating `auth.json` or `cli-config.json` as
//! an account identity. The text markers it recognizes remain [inferred], so
//! an unfamiliar response is an error rather than evidence that no account is
//! configured.
//!
//! See `docs/research/cursor.md`.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{
    account_id_is_safe, binary_on_path, home_dir, managed_account_dir, ActivationMechanism,
    LaunchSpec, ManagedAccountPlan, PendingOAuthHomePlan, PreparedPendingOAuthHome,
    ProviderAdapter, StoredAccountRegistry,
};
use crate::error::{Error, Result};
use crate::model::{
    Account, AuthKind, InstallState, Maturity, ProviderCapability, ProviderDescriptor,
    StoredAccountMaterial, StoredAccountMetadata, StoredAccountState,
};
use crate::{fsx, paths};

const ON_DISK_ACCOUNT_ID: &str = "cursor-cli-on-disk";
const PROVIDER_ID: &str = "cursor";
type LoginRunner = fn(&Path) -> io::Result<i32>;

#[derive(Debug, Default)]
pub struct CursorAdapter {
    /// Injected home directory. `None` means the real user home, which is
    /// what production uses; tests pass a `tempfile::TempDir` path so no
    /// test can read a developer's real credentials (`docs/TESTING.md` §4).
    home: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    working_directory: Option<PathBuf>,
    program: Option<PathBuf>,
    login_runner: Option<LoginRunner>,
    #[doc(hidden)]
    test_oauth_watch_cancel_driver: bool,
}

impl CursorAdapter {
    /// Root this adapter at `home` instead of the real user home.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
            ..Self::default()
        }
    }

    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    pub fn with_working_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(directory.into());
        self
    }

    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = Some(program.into());
        self
    }

    pub fn with_login_runner(mut self, runner: LoginRunner) -> Self {
        self.login_runner = Some(runner);
        self
    }

    #[doc(hidden)]
    pub fn with_test_oauth_watch_cancel_driver(mut self) -> Self {
        self.test_oauth_watch_cancel_driver = true;
        self.login_runner = None;
        self
    }

    pub(crate) fn clone_for_login_task(&self) -> Self {
        Self {
            home: self.home.clone(),
            data_dir: self.data_dir.clone(),
            working_directory: self.working_directory.clone(),
            program: self.program.clone(),
            login_runner: self.login_runner,
            test_oauth_watch_cancel_driver: self.test_oauth_watch_cancel_driver,
        }
    }

    fn resolved_home(&self) -> Option<PathBuf> {
        self.home.clone().or_else(home_dir)
    }

    /// Resolve only inside an injected home during tests. Falling back to the
    /// process `PATH` there could execute a developer's real Cursor install.
    fn cursor_agent_command(&self) -> Option<PathBuf> {
        match self.home.as_deref() {
            Some(home) => injected_binary(home, "cursor-agent"),
            None if binary_on_path_for_platform("cursor-agent") => {
                Some(PathBuf::from("cursor-agent"))
            }
            None => None,
        }
    }

    fn config_read(&self, reason: impl Into<String>) -> Error {
        Error::ConfigRead {
            provider: self.id().to_string(),
            reason: reason.into(),
        }
    }

    fn resolved_data_dir(&self) -> Result<PathBuf> {
        let directory = self.data_dir.clone().or_else(|| {
            if self.home.is_some() {
                None
            } else {
                paths::project_dirs().map(|dirs| dirs.data_dir().to_path_buf())
            }
        });
        let directory =
            directory.ok_or_else(|| config_write("application data directory unavailable"))?;
        if !directory.is_absolute() {
            return Err(config_write("application data directory is not absolute"));
        }
        Ok(directory)
    }

    fn resolved_working_directory(&self) -> Result<PathBuf> {
        let directory = match &self.working_directory {
            Some(directory) => directory.clone(),
            None => std::env::current_dir().map_err(|error| {
                config_write(format!(
                    "launch working directory unavailable ({})",
                    error.kind()
                ))
            })?,
        };
        let metadata = fs::symlink_metadata(&directory).map_err(|error| {
            config_write(format!(
                "launch working directory cannot be inspected ({})",
                error.kind()
            ))
        })?;
        if !directory.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(config_write(
                "launch working directory is not an absolute non-symlink directory",
            ));
        }
        Ok(directory)
    }

    fn program(&self) -> PathBuf {
        self.program
            .clone()
            .unwrap_or_else(|| PathBuf::from("cursor-agent"))
    }

    fn managed_home(&self, account: &StoredAccountMetadata) -> Result<PathBuf> {
        validate_managed_metadata(account)?;
        Ok(managed_account_dir(
            &self.resolved_data_dir()?,
            PROVIDER_ID,
            &account.id,
        ))
    }

    fn validate_pending_oauth_account(&self, account: &StoredAccountMetadata) -> Result<()> {
        validate_managed_metadata(account)?;
        if account.state != StoredAccountState::Pending || account.is_selected {
            return Err(config_write(
                "only an unselected pending Cursor account can begin OAuth login",
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_pending_oauth_home(
        &self,
        account: &StoredAccountMetadata,
    ) -> Result<PreparedPendingOAuthHome> {
        self.validate_pending_oauth_account(account)?;
        let home = self.managed_home(account)?;
        let plan = match fs::symlink_metadata(file_store_auth_json(&home)) {
            Ok(_) => {
                validate_managed_cursor_home(&home, true)?;
                PendingOAuthHomePlan::RecoveredExistingMarker
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ensure_private_managed_cursor_home(&self.resolved_data_dir()?, &home)?;
                PendingOAuthHomePlan::NeedsInteractiveOAuth
            }
            Err(error) => {
                return Err(config_write(format!(
                    "managed Cursor auth.json cannot be inspected ({})",
                    error.kind()
                )))
            }
        };
        Ok(PreparedPendingOAuthHome { path: home, plan })
    }

    pub(crate) async fn run_pending_oauth_login(
        &self,
        home: &Path,
        plan: PendingOAuthHomePlan,
        mut cancel: tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<(), super::OAuthLoginRunError> {
        if *cancel.borrow() {
            return Err(super::OAuthLoginRunError::Cancelled);
        }
        if plan == PendingOAuthHomePlan::RecoveredExistingMarker {
            return Ok(());
        }
        if self.test_oauth_watch_cancel_driver {
            return super::gemini_oauth::run_test_oauth_cancelled_by_watch(&mut cancel).await;
        }
        if self.login_runner.is_none() {
            return self.run_login_cancellable(home, &mut cancel).await;
        }
        let adapter = self.clone_for_login_task();
        let home = home.to_path_buf();
        match tokio::task::spawn_blocking(move || adapter.run_login(&home)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(super::OAuthLoginRunError::Failed(error)),
            Err(_) => Err(super::OAuthLoginRunError::Failed(config_write(
                "Cursor login task failed",
            ))),
        }
    }

    pub(crate) fn finish_pending_oauth_login(&self, home: &Path) -> Result<()> {
        validate_managed_cursor_home(home, true)
    }

    fn run_login(&self, managed_home: &Path) -> Result<()> {
        let status = if let Some(runner) = self.login_runner {
            runner(managed_home).map_err(|error| {
                config_write(format!(
                    "cursor-agent login could not start ({})",
                    error.kind()
                ))
            })?
        } else {
            self.login_command(managed_home)?
                .status()
                .map_err(|error| {
                    config_write(format!(
                        "cursor-agent login could not start ({})",
                        error.kind()
                    ))
                })?
                .code()
                .unwrap_or(-1)
        };
        if status != 0 {
            return Err(config_write(format!(
                "cursor-agent login exited unsuccessfully (status {status})"
            )));
        }
        Ok(())
    }

    fn login_command(&self, managed_home: &Path) -> Result<Command> {
        let mut command = Command::new(self.program());
        command
            .arg("login")
            .current_dir(self.resolved_working_directory()?)
            .env("HOME", managed_home)
            .env("CURSOR_CONFIG_DIR", managed_home.join(".cursor"))
            .env("AGENT_CLI_CREDENTIAL_STORE", "file")
            .env("NO_OPEN_BROWSER", "1")
            .env_remove("CURSOR_API_KEY")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        Ok(command)
    }

    async fn run_login_cancellable(
        &self,
        managed_home: &Path,
        cancel: &mut tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<(), super::OAuthLoginRunError> {
        let mut child = self
            .login_command(managed_home)
            .and_then(|mut command| {
                command.spawn().map_err(|error| {
                    config_write(format!(
                        "cursor-agent login could not start ({})",
                        error.kind()
                    ))
                })
            })
            .map_err(super::OAuthLoginRunError::Failed)?;
        loop {
            if *cancel.borrow() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(super::OAuthLoginRunError::Cancelled);
            }
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => {
                    return Err(super::OAuthLoginRunError::Failed(config_write(format!(
                        "cursor-agent login exited unsuccessfully (status {})",
                        status.code().unwrap_or(-1)
                    ))))
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(super::OAuthLoginRunError::Failed(config_write(format!(
                        "cursor-agent login wait failed ({})",
                        error.kind()
                    ))))
                }
            }
            tokio::select! {
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(super::OAuthLoginRunError::Cancelled);
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
        }
    }

    fn managed_metadata_accounts(&self) -> Result<Vec<Account>> {
        let Some(data_dir) = self.data_dir.clone().or_else(|| {
            if self.home.is_some() {
                None
            } else {
                paths::project_dirs().map(|dirs| dirs.data_dir().to_path_buf())
            }
        }) else {
            return Ok(Vec::new());
        };
        let registry = StoredAccountRegistry::new(paths::stored_accounts_path(&data_dir));
        let mut accounts = registry
            .load()?
            .into_iter()
            .filter(|account| account.provider_id == PROVIDER_ID)
            .map(|account| {
                let binding_matches = account.auth_kind == AuthKind::OAuth
                    && account.material == StoredAccountMaterial::VendorHome;
                Account {
                    id: account.id,
                    provider_id: account.provider_id,
                    label: account.label,
                    masked_identity: None,
                    auth_kind: account.auth_kind,
                    is_active: false,
                    is_selected_for_launch: binding_matches
                        && account.state == StoredAccountState::Complete
                        && account.is_selected,
                    is_stored: true,
                    is_incomplete: !binding_matches
                        || account.state != StoredAccountState::Complete,
                    expires_at: None,
                }
            })
            .collect::<Vec<_>>();
        accounts.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(accounts)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CursorStatus {
    LoggedIn { masked_identity: Option<String> },
    LoggedOut,
    Unknown,
}

fn injected_binary(home: &Path, binary: &str) -> Option<PathBuf> {
    let path = home.join(".local").join("bin").join(binary);
    if path.is_file() {
        return Some(path);
    }

    #[cfg(target_os = "windows")]
    {
        let path = home
            .join(".local")
            .join("bin")
            .join(format!("{binary}.exe"));
        if path.is_file() {
            return Some(path);
        }
    }

    None
}

fn file_store_auth_json(home: &Path) -> PathBuf {
    home.join(".cursor").join("auth.json")
}

fn official_cli_config_json(home: &Path) -> PathBuf {
    home.join(".cursor").join("cli-config.json")
}

fn config_write(reason: impl Into<String>) -> Error {
    Error::ConfigWrite {
        provider: PROVIDER_ID.to_string(),
        reason: reason.into(),
    }
}

fn validate_managed_metadata(account: &StoredAccountMetadata) -> Result<()> {
    if account.provider_id != PROVIDER_ID {
        return Err(Error::UnknownProvider(account.provider_id.clone()));
    }
    if !account_id_is_safe(&account.id) {
        return Err(config_write("account id is not a safe path component"));
    }
    if account.material != StoredAccountMaterial::VendorHome || account.auth_kind != AuthKind::OAuth
    {
        return Err(config_write(
            "stored account metadata does not match Cursor OAuth vendor-home storage",
        ));
    }
    Ok(())
}

fn validate_owner_private_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| config_write(format!("{label} cannot be inspected ({})", error.kind())))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(config_write(format!(
            "{label} is not a non-symlink directory"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and reads no Rust memory.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(config_write(format!("{label} is not owner-only")));
        }
    }
    Ok(())
}

fn validate_managed_cursor_home(home: &Path, require_auth: bool) -> Result<()> {
    validate_owner_private_directory(home, "managed Cursor home")?;
    let cursor_dir = home.join(".cursor");
    validate_owner_private_directory(&cursor_dir, "managed Cursor credential directory")?;
    let auth = file_store_auth_json(home);
    match fs::symlink_metadata(&auth) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
                return Err(config_write(
                    "managed Cursor auth.json is not a non-empty non-symlink regular file",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                // SAFETY: geteuid has no preconditions and reads no Rust memory.
                let uid = unsafe { libc::geteuid() };
                if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
                    return Err(config_write("managed Cursor auth.json is not owner-only"));
                }
            }
            let file = OpenOptions::new().read(true).open(&auth).map_err(|error| {
                config_write(format!(
                    "managed Cursor auth.json cannot be opened ({})",
                    error.kind()
                ))
            })?;
            if !file_identity_matches_path(&file, &auth)? {
                return Err(config_write("managed Cursor auth.json identity changed"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && !require_auth => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(config_write("managed Cursor auth.json is missing"))
        }
        Err(error) => {
            return Err(config_write(format!(
                "managed Cursor auth.json cannot be inspected ({})",
                error.kind()
            )))
        }
    }
    Ok(())
}

fn file_identity_matches_path(file: &File, path: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let held = file.metadata().map_err(|error| {
            config_write(format!(
                "held auth identity cannot be read ({})",
                error.kind()
            ))
        })?;
        let live = fs::symlink_metadata(path).map_err(|error| {
            config_write(format!(
                "auth identity cannot be rechecked ({})",
                error.kind()
            ))
        })?;
        Ok(live.file_type().is_file() && (held.dev(), held.ino()) == (live.dev(), live.ino()))
    }
    #[cfg(windows)]
    {
        let held = file
            .try_clone()
            .and_then(same_file::Handle::from_file)
            .map_err(|error| {
                config_write(format!(
                    "held auth identity cannot be read ({})",
                    error.kind()
                ))
            })?;
        let live = same_file::Handle::from_path(path).map_err(|error| {
            config_write(format!(
                "auth identity cannot be rechecked ({})",
                error.kind()
            ))
        })?;
        Ok(held == live)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, path);
        Err(config_write(
            "auth identity cannot be verified on this platform",
        ))
    }
}

fn ensure_private_managed_cursor_home(data_dir: &Path, home: &Path) -> Result<()> {
    let accounts = data_dir.join("accounts");
    let provider = accounts.join(PROVIDER_ID);
    let cursor_dir = home.join(".cursor");
    for (directory, label) in [
        (data_dir, "application data directory"),
        (accounts.as_path(), "managed accounts directory"),
        (provider.as_path(), "Cursor provider directory"),
        (home, "managed Cursor home"),
        (cursor_dir.as_path(), "managed Cursor credential directory"),
    ] {
        match fs::symlink_metadata(directory) {
            Ok(_) => validate_owner_private_directory(directory, label)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fsx::create_dir_all_private(directory)?;
                validate_owner_private_directory(directory, label)?;
            }
            Err(error) => {
                return Err(config_write(format!(
                    "{label} cannot be inspected ({})",
                    error.kind()
                )))
            }
        }
    }
    Ok(())
}

/// Presence only. Never reads, parses, or logs the file. A directory or
/// missing path is not install evidence.
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn binary_on_path_for_platform(binary: &str) -> bool {
    if binary_on_path(binary) {
        return true;
    }

    #[cfg(target_os = "windows")]
    {
        binary_on_path(&format!("{binary}.exe"))
    }

    #[cfg(not(target_os = "windows"))]
    false
}

/// Mask an email as `a***@example.com`. Only the first local-part character
/// and the domain survive; malformed or decorated status text yields no
/// identity rather than an unmasked fallback (NFR-1).
fn mask_email(email: &str) -> Option<String> {
    if !email.is_ascii() || email.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return None;
    }
    Some(format!("{}***@{domain}", local.chars().next()?))
}

/// Parse only the status markers recorded in `docs/research/cursor.md`.
/// Unknown output stays unknown; it must not be converted into "logged out".
fn parse_status(output: &str) -> CursorStatus {
    let lower = output.to_ascii_lowercase();
    if [
        "not authenticated",
        "authentication required",
        "not logged in",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return CursorStatus::LoggedOut;
    }

    for line in output.lines() {
        if let Some((_, identity)) = line.split_once("Logged in as ") {
            return CursorStatus::LoggedIn {
                masked_identity: mask_email(identity.trim()),
            };
        }
    }

    if output.lines().any(|line| {
        line.contains("Login successful!")
            || line.contains("Logged in (")
            || line.trim_end().ends_with("Logged in")
    }) {
        CursorStatus::LoggedIn {
            masked_identity: None,
        }
    } else {
        CursorStatus::Unknown
    }
}

impl ProviderAdapter for CursorAdapter {
    fn id(&self) -> &'static str {
        PROVIDER_ID
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "Cursor".to_string(),
            vendor: "Anysphere".to_string(),
            auth_kinds: vec![AuthKind::OAuth, AuthKind::ApiKey],
            maturity: Maturity::Experimental,
            install_state: self.detect(),
            capabilities: vec![
                ProviderCapability::AddAccount,
                ProviderCapability::SwitchAccount,
                ProviderCapability::DeleteAccount,
                ProviderCapability::LaunchTool,
            ],
        }
    }

    fn config_paths(&self) -> Vec<PathBuf> {
        let Some(home) = self.resolved_home() else {
            return Vec::new();
        };
        vec![
            home.join(".config").join("cursor").join("cli-config.json"),
            home.join(".cursor"),
            file_store_auth_json(&home),
        ]
    }

    fn detect(&self) -> InstallState {
        let has_config = self.resolved_home().is_some_and(|home| {
            is_regular_file(&file_store_auth_json(&home))
                || is_regular_file(&official_cli_config_json(&home))
        });
        let has_binary = match self.home.as_deref() {
            Some(home) => {
                injected_binary(home, "cursor-agent").is_some()
                    || injected_binary(home, "cursor").is_some()
            }
            None => {
                binary_on_path_for_platform("cursor-agent") || binary_on_path_for_platform("cursor")
            }
        };
        if has_binary || has_config {
            InstallState::Installed
        } else {
            InstallState::NotInstalled
        }
    }

    fn list_accounts(&self) -> Result<Vec<Account>> {
        let mut accounts = Vec::new();
        if let Some(command) = self.cursor_agent_command() {
            let output = Command::new(command)
                .arg("status")
                .output()
                .map_err(|error| {
                    self.config_read(format!(
                        "cursor-agent status could not start ({})",
                        error.kind()
                    ))
                })?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            match parse_status(&format!("{stdout}\n{stderr}")) {
                CursorStatus::LoggedIn { masked_identity } => accounts.push(Account {
                    id: ON_DISK_ACCOUNT_ID.to_string(),
                    provider_id: self.id().to_string(),
                    label: "Cursor CLI".to_string(),
                    auth_kind: AuthKind::Unknown,
                    masked_identity,
                    is_active: true,
                    is_selected_for_launch: false,
                    is_stored: false,
                    is_incomplete: false,
                    expires_at: None,
                }),
                CursorStatus::LoggedOut => {}
                CursorStatus::Unknown => {
                    return Err(self.config_read(if output.status.success() {
                        "cursor-agent status returned an unrecognized response"
                    } else {
                        "cursor-agent status failed without a recognized authentication state"
                    }))
                }
            }
        }
        accounts.extend(self.managed_metadata_accounts()?);
        Ok(accounts)
    }

    fn activation_mechanism(&self) -> ActivationMechanism {
        ActivationMechanism::LaunchEnvironment
    }

    fn launch_spec(&self, account: &StoredAccountMetadata) -> Result<LaunchSpec> {
        if account.state != StoredAccountState::Complete {
            return Err(Error::UnknownAccount(account.id.clone()));
        }
        let home = self.managed_home(account)?;
        validate_managed_cursor_home(&home, true)?;
        Ok(LaunchSpec::new(self.program())
            .current_dir(self.resolved_working_directory()?)
            .set_plain_env("HOME", home.as_os_str())
            .set_plain_env("CURSOR_CONFIG_DIR", home.join(".cursor").as_os_str())
            .set_plain_env("AGENT_CLI_CREDENTIAL_STORE", "file")
            .remove_env("CURSOR_API_KEY"))
    }

    fn managed_account_plan(&self) -> Option<ManagedAccountPlan> {
        Some(ManagedAccountPlan {
            auth_kind: AuthKind::OAuth,
            material: StoredAccountMaterial::VendorHome,
        })
    }

    fn provision_stored_account(
        &self,
        account: &StoredAccountMetadata,
    ) -> Result<Option<crate::storage::Secret>> {
        self.validate_pending_oauth_account(account)?;
        let prepared = self.prepare_pending_oauth_home(account)?;
        if prepared.plan == PendingOAuthHomePlan::NeedsInteractiveOAuth {
            self.run_login(&prepared.path)?;
        }
        self.finish_pending_oauth_login(&prepared.path)?;
        Ok(None)
    }

    fn validate_stored_account_delete(&self, account: &StoredAccountMetadata) -> Result<()> {
        validate_managed_metadata(account)?;
        let home = self.managed_home(account)?;
        match fs::symlink_metadata(&home) {
            Ok(_) => {
                validate_managed_cursor_home(&home, account.state == StoredAccountState::Complete)
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && account.state == StoredAccountState::Pending =>
            {
                Ok(())
            }
            Err(error) => Err(config_write(format!(
                "managed Cursor home cannot be inspected ({})",
                error.kind()
            ))),
        }
    }

    fn quota(&self) -> Result<Vec<crate::model::QuotaSnapshot>> {
        // Cursor's local quota signal is [unknown]; the attribution database
        // must not be treated as quota (`docs/research/cursor.md` section 6).
        Ok(Vec::new())
    }

    fn activate_account(&self, _account_id: &str) -> Result<()> {
        // Core owns launch-environment selection; no ambient Cursor state is changed.
        Err(Error::NotImplemented("cursor::activate_account"))
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderAdapter;
    use super::*;
    use std::fs;
    use std::path::Path;

    fn metadata(id: &str, state: StoredAccountState, selected: bool) -> StoredAccountMetadata {
        StoredAccountMetadata {
            id: id.to_string(),
            provider_id: PROVIDER_ID.to_string(),
            label: "Cursor fixture".to_string(),
            auth_kind: AuthKind::OAuth,
            state,
            material: StoredAccountMaterial::VendorHome,
            is_selected: selected,
            account_incarnation: "0123456789abcdef0123456789abcdef".to_string(),
        }
    }

    fn write_private_auth(home: &Path) {
        let cursor = home.join(".cursor");
        fs::create_dir_all(&cursor).expect("cursor dir");
        let auth = cursor.join("auth.json");
        fs::write(&auth, b"fixture-managed-auth").expect("auth");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(home, fs::Permissions::from_mode(0o700)).expect("home mode");
            fs::set_permissions(&cursor, fs::Permissions::from_mode(0o700)).expect("cursor mode");
            fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).expect("auth mode");
        }
    }

    fn login_writes_private_auth(home: &Path) -> io::Result<i32> {
        write_private_auth(home);
        Ok(0)
    }

    fn write_file(path: &Path, contents: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir");
        }
        fs::write(path, contents).expect("write");
    }

    #[test]
    fn with_home_resolves_config_paths_under_the_injected_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = CursorAdapter::with_home(dir.path());
        let paths = adapter.config_paths();

        assert_eq!(
            paths,
            vec![
                dir.path()
                    .join(".config")
                    .join("cursor")
                    .join("cli-config.json"),
                dir.path().join(".cursor"),
                dir.path().join(".cursor").join("auth.json"),
            ]
        );
        for path in paths {
            assert!(
                path.is_absolute(),
                "{path} must be absolute",
                path = path.display()
            );
            assert!(
                path.starts_with(dir.path()),
                "{path} escaped the injected home {home}",
                path = path.display(),
                home = dir.path().display()
            );
        }
    }

    #[test]
    fn injected_home_never_falls_back_to_the_process_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.cursor_agent_command(), None);
    }

    #[test]
    fn descriptor_and_plan_expose_managed_oauth_without_ambient_activation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = CursorAdapter::with_home(dir.path());
        let descriptor = adapter.descriptor();
        assert!(descriptor.auth_kinds.contains(&AuthKind::OAuth));
        assert_eq!(
            adapter.activation_mechanism(),
            ActivationMechanism::LaunchEnvironment
        );
        assert_eq!(
            adapter.managed_account_plan(),
            Some(ManagedAccountPlan {
                auth_kind: AuthKind::OAuth,
                material: StoredAccountMaterial::VendorHome,
            })
        );
    }

    #[test]
    fn provision_and_launch_bind_only_the_private_cursor_file_store() {
        let live = tempfile::tempdir().expect("live");
        let data = tempfile::tempdir().expect("data");
        let cwd = tempfile::tempdir().expect("cwd");
        let adapter = CursorAdapter::with_home(live.path())
            .with_data_dir(data.path())
            .with_working_directory(cwd.path())
            .with_program("fixture-cursor-agent")
            .with_login_runner(login_writes_private_auth);
        let pending = metadata("work", StoredAccountState::Pending, false);
        assert!(adapter
            .provision_stored_account(&pending)
            .expect("provision")
            .is_none());

        let complete = metadata("work", StoredAccountState::Complete, true);
        let launch = adapter.launch_spec(&complete).expect("launch spec");
        let environment = launch.plain_environment();
        let managed_home = data.path().join("accounts/cursor/work");
        assert_eq!(
            environment,
            vec![
                ("HOME".to_string(), managed_home.clone().into_os_string()),
                (
                    "CURSOR_CONFIG_DIR".to_string(),
                    managed_home.join(".cursor").into_os_string(),
                ),
                ("AGENT_CLI_CREDENTIAL_STORE".to_string(), "file".into(),),
            ]
        );
        assert_eq!(launch.environment_removals(), vec!["CURSOR_API_KEY"]);
        assert!(file_store_auth_json(&managed_home).is_file());
    }

    #[test]
    fn status_email_is_masked_before_it_becomes_an_account_field() {
        assert_eq!(
            parse_status("\u{2713} Logged in as FAKE-user-0001@example.invalid\n"),
            CursorStatus::LoggedIn {
                masked_identity: Some("F***@example.invalid".to_string())
            }
        );
    }

    #[test]
    fn offline_status_still_identifies_the_logged_in_slot() {
        assert_eq!(
            parse_status("\u{2713} Login successful!\nLogged in (unable to fetch user details)\n"),
            CursorStatus::LoggedIn {
                masked_identity: None
            }
        );
    }

    #[test]
    fn logged_out_and_unknown_statuses_are_distinct() {
        assert_eq!(
            parse_status("Authentication required"),
            CursorStatus::LoggedOut
        );
        assert_eq!(parse_status("unexpected response"), CursorStatus::Unknown);
    }

    #[test]
    fn file_store_auth_json_must_be_a_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let auth = file_store_auth_json(dir.path());
        assert!(
            !is_regular_file(&auth),
            "missing path is not a regular file"
        );

        fs::create_dir_all(&auth).expect("mkdir auth.json as directory");
        assert!(
            !is_regular_file(&auth),
            "a directory named auth.json is not file-store presence"
        );

        fs::remove_dir(&auth).expect("rmdir");
        write_file(&auth, b"");
        assert!(
            is_regular_file(&auth),
            "an empty regular file is enough presence"
        );
    }

    #[test]
    fn detect_installed_when_file_store_auth_json_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(
            &file_store_auth_json(dir.path()),
            br#"{"access_token":"FAKE-access-token-0001"}"#,
        );
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::Installed);
    }

    #[test]
    fn detect_not_installed_on_empty_home() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::NotInstalled);
    }

    #[test]
    fn empty_cursor_directory_is_not_credentials() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join(".cursor")).expect("mkdir .cursor");
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::NotInstalled);
        let accounts = adapter.list_accounts().expect("list_accounts");
        assert!(
            accounts.is_empty(),
            "an empty ~/.cursor directory is not an Observed account"
        );
    }

    #[test]
    fn official_cli_config_json_must_be_a_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = official_cli_config_json(dir.path());
        assert!(
            !is_regular_file(&config),
            "missing path is not a regular file"
        );

        fs::create_dir_all(&config).expect("mkdir cli-config.json as directory");
        assert!(
            !is_regular_file(&config),
            "a directory named cli-config.json is not settings presence"
        );

        fs::remove_dir(&config).expect("rmdir");
        write_file(&config, b"");
        assert!(
            is_regular_file(&config),
            "an empty regular file is enough presence"
        );
    }

    #[test]
    fn detect_installed_when_official_cli_config_json_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(&official_cli_config_json(dir.path()), b"");
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::Installed);
    }

    #[test]
    fn official_cli_config_json_presence_is_not_an_observed_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(&official_cli_config_json(dir.path()), b"");
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::Installed);
        let accounts = adapter.list_accounts().expect("list_accounts");
        assert!(
            accounts.is_empty(),
            "cli-config.json presence is install evidence, not account identity"
        );
    }

    #[test]
    fn config_cursor_cli_config_json_is_not_official_install_presence() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(
            &dir.path()
                .join(".config")
                .join("cursor")
                .join("cli-config.json"),
            b"{}",
        );
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::NotInstalled);
    }

    #[test]
    fn detect_not_installed_when_only_ai_code_tracking_database_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(
            &dir.path()
                .join(".cursor")
                .join("ai-tracking")
                .join("ai-code-tracking.db"),
            b"",
        );
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::NotInstalled);
        let accounts = adapter.list_accounts().expect("list_accounts");
        assert!(
            accounts.is_empty(),
            "ai-code-tracking.db is attribution tracking, not account identity"
        );
        let quota = adapter.quota().expect("quota");
        assert!(
            quota.is_empty(),
            "ai-code-tracking.db must not be treated as Observed quota"
        );
    }

    #[test]
    fn auth_json_presence_is_not_an_observed_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(
            &file_store_auth_json(dir.path()),
            b"not-json FAKE-access-token-0001",
        );
        let adapter = CursorAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::Installed);
        let accounts = adapter.list_accounts().expect("list_accounts");
        assert!(
            accounts.is_empty(),
            "auth.json presence is install evidence, not account identity"
        );
    }

    #[test]
    fn activate_account_is_not_implemented() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = CursorAdapter::with_home(dir.path());
        let error = adapter
            .activate_account("any")
            .expect_err("activate_account");
        assert!(matches!(
            error,
            Error::NotImplemented("cursor::activate_account")
        ));
    }
}
