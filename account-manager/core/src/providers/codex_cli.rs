//! Codex CLI (OpenAI) adapter.
//!
//! Observed layout on Linux, codex-cli 0.144.4:
//!
//! - `~/.codex/auth.json` [verified-local] — top-level `auth_mode`,
//!   `OPENAI_API_KEY` (null while signed in through a ChatGPT plan), a `tokens`
//!   object with `id_token` / `access_token` / `refresh_token` / `account_id`,
//!   and `last_refresh`.
//! - `~/.codex/config.toml` [verified-local] — client configuration including
//!   per-project `[projects."<path>"]` trust entries.
//!
//! Because `auth.json` is a single self-contained document, Codex is the
//! cleanest switching target of the initial five: a switch is a validated
//! replacement of that one file. `CODEX_HOME` relocates the whole directory
//! [verified-docs], which gives a second, less invasive switching strategy.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{
    account_id_is_safe, binary_on_path, home_dir, managed_account_dir, process_named_is_running,
    ManagedAccountPlan, PendingOAuthHomePlan, PreparedPendingOAuthHome, ProviderAdapter,
};
use crate::backup::{BackupId, BackupStore};
use crate::error::{Error, Result};
use crate::fsx;
use crate::model::{
    Account, AuthKind, InstallState, Maturity, ProviderCapability, ProviderDescriptor,
    StoredAccountMaterial, StoredAccountMetadata, StoredAccountState,
};
use crate::paths;

/// Application-assigned id for the single on-disk Codex identity.
///
/// Codex stores exactly one identity in one flat document [verified-local], so
/// this names that slot rather than echoing a vendor identifier. SPEC §4
/// assigns `Account.id` here so a vendor changing `tokens.account_id` cannot
/// orphan local state. The same fixture therefore always produces this id.
const ON_DISK_ACCOUNT_ID: &str = "codex-cli-on-disk";

#[derive(Debug, Default)]
pub struct CodexCliAdapter {
    /// Injected home directory. `None` means the real user home, which is
    /// what production uses; tests pass a `tempfile::TempDir` path so no
    /// test can read a developer's real credentials (`docs/TESTING.md` §4).
    home: Option<PathBuf>,
    /// Injected application data directory (per-account homes and backups).
    /// `None` in production means `paths::project_dirs`; tests pass a
    /// `TempDir` so a switch never writes into the developer's real
    /// application-data directory (`docs/TESTING.md` §4).
    data_dir: Option<PathBuf>,
    /// Override for the running-tool check.
    ///
    /// `None` means inspect the host process table, except when `home` is
    /// injected — a fixture home is not the host's Codex, so the host
    /// process table is ignored. `Some(Ok(b))` forces the answer.
    /// `Some(Err(()))` forces the cannot-tell path, which must refuse.
    injected_tool_running: Option<std::result::Result<bool, ()>>,
    /// Override for `codex login`. `None` means spawn the real CLI, except
    /// when `home` is injected — a fixture home is not a reason to open a
    /// browser against a real account (`docs/TESTING.md` §4). Tests pass a
    /// stub so a real login never runs.
    login_runner: Option<fn(&Path) -> std::io::Result<i32>>,
    /// Hermetic login-service tests: honour cancel via async watch only.
    #[doc(hidden)]
    test_oauth_watch_cancel_driver: bool,
    #[cfg(test)]
    fault: SwitchFault,
}

/// Test-only injection that fires during `activate_account`.
///
/// Production builds do not carry this field. The public API has no fault
/// hook; unit tests use it to pin backup-before-write and restore-on-failure
/// (`docs/TESTING.md` §2, `NFR-4`).
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum SwitchFault {
    #[default]
    None,
    AfterSnapshot,
    AfterWrite,
}

impl CodexCliAdapter {
    /// Root this adapter at `home` instead of the real user home.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
            ..Self::default()
        }
    }

    /// Root per-account homes and backups at `data_dir`.
    ///
    /// Production leaves this unset and uses `paths::project_dirs`. Tests
    /// pass a `TempDir` so the snapshot never lands in the developer's
    /// real application-data directory.
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Override the running-tool check.
    ///
    /// Detecting Codex by process name is approximate (see
    /// [`Self::tool_is_running`]). Tests force the answer so the host's
    /// `codex app-server` cannot make a fixture switch refuse, and so the
    /// refusal path can be exercised without spawning a real Codex.
    pub fn with_tool_running(mut self, running: bool) -> Self {
        self.injected_tool_running = Some(Ok(running));
        self
    }

    /// Drive `codex login` with a stub instead of the real CLI.
    ///
    /// The stub receives the managed `CODEX_HOME` path and returns an exit
    /// code (or a spawn-style I/O error). Tests use this so add-account
    /// never opens a browser or touches a real account.
    pub fn with_login_runner(mut self, runner: fn(&Path) -> std::io::Result<i32>) -> Self {
        self.login_runner = Some(runner);
        self
    }

    /// Async OAuth fixture for login-service cancellation tests.
    #[doc(hidden)]
    pub fn with_test_oauth_watch_cancel_driver(mut self) -> Self {
        self.test_oauth_watch_cancel_driver = true;
        self.login_runner = None;
        self
    }

    /// Clone adapter configuration for a background login task.
    pub(crate) fn clone_for_login_task(&self) -> Self {
        Self {
            home: self.home.clone(),
            data_dir: self.data_dir.clone(),
            injected_tool_running: self.injected_tool_running,
            login_runner: self.login_runner,
            test_oauth_watch_cancel_driver: self.test_oauth_watch_cancel_driver,
            #[cfg(test)]
            fault: self.fault,
        }
    }

    fn validate_pending_oauth_account(&self, account: &StoredAccountMetadata) -> Result<()> {
        if account.provider_id != self.id() {
            return Err(Error::UnknownProvider(account.provider_id.clone()));
        }
        if !account_id_is_safe(&account.id) {
            return Err(
                self.config_read("stored account metadata does not match the Codex lifecycle")
            );
        }
        if account.id == ON_DISK_ACCOUNT_ID {
            return Err(
                self.config_read("account id is reserved for the live on-disk Codex identity")
            );
        }
        if account.state != StoredAccountState::Pending || account.is_selected {
            return Err(
                self.config_read("only an unselected pending Codex account can begin OAuth login")
            );
        }
        if account.auth_kind != AuthKind::OAuth
            || account.material != StoredAccountMaterial::VendorHome
        {
            return Err(self.config_read("Codex OAuth login requires an OAuth pending account"));
        }
        Ok(())
    }

    fn required_data_dir(&self) -> Result<PathBuf> {
        let directory = self.resolved_data_dir().ok_or_else(|| {
            self.config_write(
                "application data directory is unavailable; cannot create a managed account",
            )
        })?;
        if !directory.is_absolute() {
            return Err(self.config_write("application data directory is not an absolute path"));
        }
        Ok(directory)
    }

    fn managed_oauth_home(&self, account: &StoredAccountMetadata) -> Result<PathBuf> {
        Ok(managed_account_dir(
            &self.required_data_dir()?,
            self.id(),
            &account.id,
        ))
    }

    /// Prepare an isolated managed `CODEX_HOME` for a pending OAuth account.
    pub(crate) fn prepare_pending_oauth_home(
        &self,
        account: &StoredAccountMetadata,
    ) -> Result<PreparedPendingOAuthHome> {
        self.validate_pending_oauth_account(account)?;
        let home = self.managed_oauth_home(account)?;
        let plan = match fs::symlink_metadata(home.join("auth.json")) {
            Ok(_) => {
                self.require_auth_json(&home)?;
                PendingOAuthHomePlan::RecoveredExistingMarker
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                self.prepare_managed_dir(&home)?;
                PendingOAuthHomePlan::NeedsInteractiveOAuth
            }
            Err(error) => {
                return Err(self.config_write(format!(
                    "managed auth.json cannot be inspected ({})",
                    error.kind()
                )));
            }
        };
        Ok(PreparedPendingOAuthHome { path: home, plan })
    }

    /// Run `codex login` for a prepared managed `CODEX_HOME`.
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
        let adapter = self.clone_for_login_task();
        let home = home.to_path_buf();
        let result = tokio::task::spawn_blocking(move || adapter.run_vendor_login(&home)).await;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(super::OAuthLoginRunError::Failed(error)),
            Err(_) => Err(super::OAuthLoginRunError::Failed(
                self.config_write("Codex login task failed"),
            )),
        }
    }

    /// Validate vendor-issued `auth.json` after login succeeds.
    pub(crate) fn finish_pending_oauth_login(&self, home: &Path) -> Result<()> {
        self.require_auth_json(home)
    }

    #[cfg(test)]
    fn with_tool_undetermined(mut self) -> Self {
        self.injected_tool_running = Some(Err(()));
        self
    }

    #[cfg(test)]
    fn with_fault(mut self, fault: SwitchFault) -> Self {
        self.fault = fault;
        self
    }

    fn resolved_home(&self) -> Option<PathBuf> {
        self.home.clone().or_else(home_dir)
    }

    /// Honours `CODEX_HOME` before falling back to `~/.codex`.
    ///
    /// An injected root wins over `CODEX_HOME` so a test is never affected by
    /// the developer's own `CODEX_HOME` (`docs/TESTING.md` §4). Production
    /// leaves `home` unset, so the documented `[verified-docs]` override still
    /// precedes `~/.codex`. Order: injected root, then `CODEX_HOME`, then
    /// `~/.codex`.
    fn codex_home(&self) -> Option<PathBuf> {
        if self.home.is_some() {
            return self.resolved_home().map(|home| home.join(".codex"));
        }
        if let Some(explicit) = std::env::var_os("CODEX_HOME") {
            return Some(PathBuf::from(explicit));
        }
        self.resolved_home().map(|home| home.join(".codex"))
    }

    fn config_read(&self, reason: impl Into<String>) -> Error {
        Error::ConfigRead {
            provider: self.id().to_string(),
            reason: reason.into(),
        }
    }

    fn config_write(&self, reason: impl Into<String>) -> Error {
        Error::ConfigWrite {
            provider: self.id().to_string(),
            reason: reason.into(),
        }
    }

    /// Application data directory: injected, else isolated under an
    /// injected home, else `paths::project_dirs`.
    ///
    /// The identity triple is spelled only in `paths::project_dirs`. An
    /// injected home without an injected data dir falls back to
    /// `{home}/.coding-agent-manager` so `with_home` (used by the contract
    /// suite) cannot write into the developer's real data directory.
    fn resolved_data_dir(&self) -> Option<PathBuf> {
        if let Some(dir) = &self.data_dir {
            return Some(dir.clone());
        }
        if let Some(home) = &self.home {
            return Some(home.join(".coding-agent-manager"));
        }
        paths::project_dirs().map(|dirs| dirs.data_dir().to_path_buf())
    }

    fn backup_store(&self) -> Result<BackupStore> {
        let Some(data_dir) = self.resolved_data_dir() else {
            return Err(
                self.config_write("application data directory is unavailable; no backup root")
            );
        };
        Ok(BackupStore::new(data_dir.join("backups")))
    }

    fn account_auth_path(&self, account_id: &str) -> Result<PathBuf> {
        if !account_id_is_safe(account_id) {
            return Err(Error::UnknownAccount(account_id.to_string()));
        }
        let Some(data_dir) = self.resolved_data_dir() else {
            return Err(self.config_write(
                "application data directory is unavailable; cannot locate the account",
            ));
        };
        Ok(managed_account_dir(&data_dir, self.id(), account_id).join("auth.json"))
    }

    /// Whether Codex appears to be running.
    ///
    /// Detecting by process name is inherently approximate: a renamed
    /// binary is missed; an unrelated program named `codex` is a false
    /// hit; a pid we cannot inspect is skipped. The check is conservative
    /// about *writes*: when the process table cannot be read, this
    /// returns `Err` and the caller refuses rather than replace
    /// `auth.json` under a possibly-live process (`NFR-4`,
    /// `docs/ARCHITECTURE.md` §8). On this host a VS Code extension
    /// keeps `codex app-server` alive continuously, so "the tool is
    /// running" is the normal state.
    ///
    /// An injected home is a fixture, not the host's Codex: the host
    /// process table is ignored unless `with_tool_running` set an
    /// override. Integration tests compile this crate without
    /// `cfg(test)`, so that skip cannot live only behind `cfg(test)`.
    fn tool_is_running(&self) -> Result<bool> {
        match self.injected_tool_running {
            Some(Ok(running)) => return Ok(running),
            Some(Err(())) => {
                return Err(Error::Io(std::io::Error::other(
                    "cannot inspect the process table",
                )));
            }
            None => {}
        }
        if self.home.is_some() {
            return Ok(false);
        }
        process_named_is_running("codex")
    }

    /// Load the vendor-issued document for `account_id` without inspecting
    /// secret fields. Structure only: the file exists, is a regular file,
    /// and is a JSON object. Bytes are returned so the switch can write
    /// them through `fsx::write_atomic` without parsing tokens.
    fn load_account_auth(&self, account_id: &str) -> Result<(PathBuf, Vec<u8>)> {
        let path = self.account_auth_path(account_id)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(Error::UnknownAccount(account_id.to_string()));
            }
            Err(error) => {
                return Err(self.config_read(format!("{} ({})", path.display(), error.kind())));
            }
        };
        if !metadata.is_file() {
            return Err(self.config_read(format!("{} is not a regular file", path.display())));
        }
        let bytes = fs::read(&path)
            .map_err(|error| self.config_read(format!("{} ({})", path.display(), error.kind())))?;
        // serde's error text can echo a token; never include it (NFR-1).
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| self.config_read(format!("{} is not valid JSON", path.display())))?;
        if !value.is_object() {
            return Err(self.config_read(format!("{} is not a JSON object", path.display())));
        }
        Ok((path, bytes))
    }

    /// Confirm the live `auth.json` is the document we just wrote.
    ///
    /// What this proves: the live home now holds the same bytes as the
    /// per-account file, they form a JSON object, and a reader of that
    /// path sees the whole new document (`fsx::write_atomic`).
    ///
    /// What this does not prove: that `codex login status` would report
    /// the expected identity; that the copied credential still works
    /// against the vendor; that a long-running Codex process will pick
    /// the file up; that the server-side session remains valid. The
    /// 2026-08-19 probe established only that `auth.json` determines
    /// local `login status` for a given `CODEX_HOME` [verified-local],
    /// and explicitly not vendor acceptance (`docs/research/codex-cli.md`
    /// §5). Invoking `codex login status` would add a subprocess and
    /// still only report what the CLI believes. No stronger check is
    /// possible without a network call, which a local switch must not
    /// require (`NFR-3`). Step 4 is therefore this file-level check,
    /// not a CLI invocation.
    fn verify_live_auth(&self, dest: &Path, expected: &[u8]) -> Result<()> {
        let got = fs::read(dest).map_err(|error| {
            self.config_write(format!(
                "could not re-read {} after write ({})",
                dest.display(),
                error.kind()
            ))
        })?;
        if got.as_slice() != expected {
            return Err(self.config_write(format!(
                "{} did not match the account document after write",
                dest.display()
            )));
        }
        let value: serde_json::Value = serde_json::from_slice(&got).map_err(|_| {
            self.config_write(format!("{} is not valid JSON after write", dest.display()))
        })?;
        if !value.is_object() {
            return Err(self.config_write(format!(
                "{} is not a JSON object after write",
                dest.display()
            )));
        }
        Ok(())
    }

    /// Restore `backup` and return a write error that says the previous
    /// account is still active. Never includes file contents (NFR-1).
    fn abort_switch(
        &self,
        store: &BackupStore,
        backup: &BackupId,
        reason: impl Into<String>,
    ) -> Error {
        let reason = reason.into();
        match store.restore(backup) {
            Ok(()) => self.config_write(format!("{reason}; the previous account is still active")),
            Err(restore_error) => self.config_write(format!(
                "{reason}; restore of the previous account also failed: {restore_error}"
            )),
        }
    }

    /// Run `codex login` with `CODEX_HOME` at `managed_dir`.
    ///
    /// Stdio is inherited so the user sees the CLI's own prompts and URL.
    /// The child's output is never captured, logged, or copied into an
    /// error (NFR-1). Spawn failures report `ErrorKind` and the path only.
    fn run_vendor_login(&self, managed_dir: &Path) -> Result<()> {
        let code = match self.login_runner {
            Some(runner) => runner(managed_dir).map_err(|error| {
                self.config_write(format!(
                    "could not start `codex login` with CODEX_HOME at {} ({})",
                    managed_dir.display(),
                    error.kind()
                ))
            })?,
            None if self.home.is_some() => {
                return Err(
                    self.config_write("refusing to spawn `codex login` against an injected home")
                );
            }
            None => self.spawn_codex_login(managed_dir)?,
        };
        if code != 0 {
            return Err(self.config_write(format!(
                "`codex login` exited with status {code}; CODEX_HOME is {}",
                managed_dir.display()
            )));
        }
        Ok(())
    }

    fn spawn_codex_login(&self, managed_dir: &Path) -> Result<i32> {
        let status = Command::new("codex")
            .arg("login")
            .env("CODEX_HOME", managed_dir)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| {
                self.config_write(format!(
                    "could not start `codex login` with CODEX_HOME at {} ({})",
                    managed_dir.display(),
                    error.kind()
                ))
            })?;
        match status.code() {
            Some(code) => Ok(code),
            None => Err(self.config_write(format!(
                "`codex login` was terminated by a signal; CODEX_HOME is {}",
                managed_dir.display()
            ))),
        }
    }

    /// Structure-only: `auth.json` exists, is a regular file, and is a JSON
    /// object. Bytes are not inspected beyond that (NFR-1).
    fn require_auth_json(&self, dir: &Path) -> Result<()> {
        let path = dir.join("auth.json");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(self.config_write(format!(
                    "`codex login` finished but {} was not created",
                    path.display()
                )));
            }
            Err(error) => {
                return Err(self.config_write(format!("{} ({})", path.display(), error.kind())));
            }
        };
        if !metadata.is_file() {
            return Err(self.config_write(format!("{} is not a regular file", path.display())));
        }
        let bytes = fs::read(&path)
            .map_err(|error| self.config_write(format!("{} ({})", path.display(), error.kind())))?;
        // serde's error text can echo a token; never include it (NFR-1).
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| self.config_write(format!("{} is not valid JSON", path.display())))?;
        if !value.is_object() {
            return Err(self.config_write(format!("{} is not a JSON object", path.display())));
        }
        Ok(())
    }

    /// Live `auth.json` bytes plus the Account that file represents, or
    /// the reason the live document cannot be used.
    ///
    /// A missing file is [`LiveSlot::Absent`] — stored copies still list
    /// and nothing is active. A file that exists but is unreadable or
    /// is not a JSON object is [`LiveSlot::Damaged`]: stored copies still
    /// list (the user needs them to repair the live file) and nothing is
    /// active, because there is nothing safe to compare against.
    fn live_slot(&self) -> LiveSlot {
        let Some(path) = self.codex_home().map(|root| root.join("auth.json")) else {
            return LiveSlot::Absent;
        };
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return LiveSlot::Absent,
            Err(error) => {
                return LiveSlot::Damaged(self.config_read(format!(
                    "{} ({})",
                    path.display(),
                    error.kind()
                )));
            }
        };
        let value: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                return LiveSlot::Damaged(
                    self.config_read(format!("{} is not valid JSON", path.display())),
                );
            }
        };
        let Some(object) = value.as_object() else {
            return LiveSlot::Damaged(
                self.config_read(format!("{} is not a JSON object", path.display())),
            );
        };
        LiveSlot::Present {
            bytes,
            account: account_from_auth(
                self.id(),
                ON_DISK_ACCOUNT_ID,
                "Codex CLI",
                object,
                true,
                false,
            ),
        }
    }

    /// Enumerate live and stored accounts. A damaged live document is
    /// reported alongside the stored copies rather than hiding them.
    ///
    /// The second value is `Some` only when the live file exists and
    /// cannot be used as a JSON object. A missing live file is `None`
    /// — that already degrades gracefully. The error never includes
    /// file contents or serde's text (NFR-1).
    pub fn list_accounts_detailed(&self) -> Result<(Vec<Account>, Option<Error>)> {
        let (live_bytes, live_account, live_error) = match self.live_slot() {
            LiveSlot::Absent => (None, None, None),
            LiveSlot::Present { bytes, account } => (Some(bytes), Some(account), None),
            LiveSlot::Damaged(error) => (None, None, Some(error)),
        };
        let mut managed = self.managed_slots(live_bytes.as_deref())?;
        let managed_has_active = managed.iter().any(|account| account.is_active);

        let mut accounts = Vec::new();
        if let Some(account) = live_account {
            if !managed_has_active {
                accounts.push(account);
            }
        }
        accounts.append(&mut managed);
        Ok((accounts, live_error))
    }

    /// Stored per-account directories.
    ///
    /// A real directory with a JSON-object `auth.json` is a usable stored
    /// copy. A real directory with no `auth.json` is an abandoned add:
    /// listed as incomplete so the user can delete it. A directory whose
    /// `auth.json` exists but is unreadable or not a JSON object is
    /// skipped rather than failing the whole list: one corrupt stored
    /// copy must not hide the others. Directory-listing I/O on the
    /// managed root still errors.
    fn managed_slots(&self, live_bytes: Option<&[u8]>) -> Result<Vec<Account>> {
        let Some(data_dir) = self.resolved_data_dir() else {
            return Ok(Vec::new());
        };
        let root = data_dir.join("accounts").join(self.id());
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(self.config_read(format!("{} ({})", root.display(), error.kind())));
            }
        };

        let mut slots = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                self.config_read(format!("{} ({})", root.display(), error.kind()))
            })?;
            let name = entry.file_name();
            let Some(account_id) = name.to_str() else {
                continue;
            };
            if !account_id_is_safe(account_id) {
                continue;
            }
            // `DirEntry::file_type` does not follow symlinks. A file or
            // a planted symlink in this tree is not a stored account;
            // following the link would let it impersonate another slot
            // or the live home.
            let file_type = entry.file_type().map_err(|error| {
                self.config_read(format!("{} ({})", root.display(), error.kind()))
            })?;
            if !file_type.is_dir() {
                continue;
            }
            let path = managed_account_dir(&data_dir, self.id(), account_id).join("auth.json");
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    slots.push(ManagedSlot::Incomplete {
                        account_id: account_id.to_string(),
                    });
                    continue;
                }
                Err(_) => continue,
                Ok(_) => {}
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            let Some(object) = value.as_object() else {
                continue;
            };
            slots.push(ManagedSlot::Complete {
                account_id: account_id.to_string(),
                bytes,
                object: object.clone(),
            });
        }
        slots.sort_by(|left, right| left.account_id().cmp(right.account_id()));

        let mut claimed_active = false;
        let mut accounts = Vec::with_capacity(slots.len());
        for slot in slots {
            match slot {
                ManagedSlot::Incomplete { account_id } => {
                    accounts.push(incomplete_account(self.id(), &account_id));
                }
                ManagedSlot::Complete {
                    account_id,
                    bytes,
                    object,
                } => {
                    let is_active = live_bytes == Some(bytes.as_slice()) && !claimed_active;
                    if is_active {
                        claimed_active = true;
                    }
                    accounts.push(account_from_auth(
                        self.id(),
                        &account_id,
                        &account_id,
                        &object,
                        is_active,
                        true,
                    ));
                }
            }
        }
        Ok(accounts)
    }

    /// Prepare the per-account directory at `dir`.
    ///
    /// A missing leaf is created owner-only. A real directory that holds
    /// no `auth.json` is an abandoned add and is reused. A directory that
    /// already holds an `auth.json`, a symlink (including a dangling one),
    /// or a non-directory is refused. `Path::exists` follows links, so a
    /// dangling symlink would look absent, and `create_dir_all` is
    /// idempotent, so a complete directory would be reused. Either would
    /// let a later failure `remove_dir_all` a path this call did not
    /// create, or walk through a planted link. Parents are created as
    /// needed; only the leaf is exclusive, so cleanup cannot remove the
    /// provider's accounts tree.
    fn prepare_managed_dir(&self, dir: &Path) -> Result<()> {
        match fs::symlink_metadata(dir) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(self.config_write(format!(
                        "{} already exists; refusing to overwrite a managed account directory",
                        dir.display()
                    )));
                }
                if self.slot_holds_auth_json(dir) {
                    return Err(self.config_write(format!(
                        "{} already exists; refusing to overwrite a managed account directory",
                        dir.display()
                    )));
                }
                return Ok(());
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(self.config_write(format!("{} ({})", dir.display(), error.kind())));
            }
        }
        if let Some(parent) = dir.parent() {
            fsx::create_dir_all_private(parent).map_err(|error| {
                self.config_write(format!("could not create {}: {error}", parent.display()))
            })?;
        }
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        builder.create(dir).map_err(|error| {
            if error.kind() == ErrorKind::AlreadyExists {
                self.config_write(format!(
                    "{} already exists; refusing to overwrite a managed account directory",
                    dir.display()
                ))
            } else {
                self.config_write(format!("could not create {}: {error}", dir.display()))
            }
        })
    }

    /// Whether `dir` already holds an `auth.json` directory entry.
    ///
    /// Presence, not parsability: a file, symlink, or unreadable entry
    /// named `auth.json` is someone's (or something's) credential
    /// material, not an abandoned add. An I/O error other than NotFound
    /// is treated as occupied so we do not overwrite what we cannot see.
    fn slot_holds_auth_json(&self, dir: &Path) -> bool {
        match fs::symlink_metadata(dir.join("auth.json")) {
            Ok(_) => true,
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(_) => true,
        }
    }

    /// Remove a half-created managed directory after a failed add.
    ///
    /// When `remove_dir_all` fails or the path is still present, the
    /// original login error is kept and the leftover path is named so
    /// the user can remove credential material by hand. Never includes
    /// file contents (NFR-1).
    fn cleanup_failed_add(&self, dir: &Path, error: Error) -> Error {
        let original = match error {
            Error::ConfigWrite { reason, .. } => reason,
            other => other.to_string(),
        };
        match fs::remove_dir_all(dir) {
            Ok(()) if fs::symlink_metadata(dir).is_err() => self.config_write(original),
            Ok(()) => self.config_write(format!(
                "{original}; could not fully remove {}; credential material may remain at {}",
                dir.display(),
                leftover_managed_path(dir).display()
            )),
            Err(cleanup_error) => self.config_write(format!(
                "{original}; could not fully remove {} ({}); credential material may remain at {}",
                dir.display(),
                cleanup_error.kind(),
                leftover_managed_path(dir).display()
            )),
        }
    }
}

/// A stored per-account directory, complete or abandoned.
enum ManagedSlot {
    Complete {
        account_id: String,
        bytes: Vec<u8>,
        object: serde_json::Map<String, serde_json::Value>,
    },
    Incomplete {
        account_id: String,
    },
}

impl ManagedSlot {
    fn account_id(&self) -> &str {
        match self {
            Self::Complete { account_id, .. } | Self::Incomplete { account_id } => account_id,
        }
    }
}

/// The live Codex identity, or why it cannot be used as a comparison.
enum LiveSlot {
    /// No live `auth.json`. Stored copies list; nothing is active.
    Absent,
    /// A JSON-object live document. `account` is the on-disk row.
    Present { bytes: Vec<u8>, account: Account },
    /// The live file exists but is unreadable or is not a JSON object.
    /// Stored copies still list; nothing is active. Never carries file
    /// contents or serde's text (NFR-1).
    Damaged(Error),
}

/// Mask a vendor identifier for display.
///
/// Keeps the last four characters and replaces the rest with a fixed `****`
/// prefix (e.g. `****ab12`). Returns `None` when the value is absent-as-empty
/// or too short to mask without leaving the original essentially intact.
///
/// The only identity-shaped field in `auth.json` is `tokens.account_id`
/// [verified-local]. Callers must pass that field and never a token or key.
fn mask_identity(raw: &str) -> Option<String> {
    const VISIBLE: usize = 4;
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= VISIBLE {
        return None;
    }
    let tail: String = chars[chars.len() - VISIBLE..].iter().collect();
    Some(format!("****{tail}"))
}

/// Build an `Account` from a parsed `auth.json` object.
///
/// Classification inspects structure only (NFR-1 / threat T2):
/// - `ApiKey` when `OPENAI_API_KEY` is a non-null string [verified-local]
/// - otherwise `OAuth` when a `tokens` object is present [verified-local]
/// - otherwise `AuthKind::Unknown`
///
/// Token, key, and raw `account_id` values are never copied onto the `Account`.
/// `id_token` is a JWT and is not decoded. `is_active` and `is_stored` are
/// supplied by the caller; this helper does not guess them.
fn account_from_auth(
    provider_id: &str,
    account_id: &str,
    label: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    is_active: bool,
    is_stored: bool,
) -> Account {
    let has_api_key = matches!(
        object.get("OPENAI_API_KEY"),
        Some(serde_json::Value::String(_))
    );
    let tokens = object.get("tokens").and_then(serde_json::Value::as_object);
    let auth_kind = if has_api_key {
        AuthKind::ApiKey
    } else if tokens.is_some() {
        AuthKind::OAuth
    } else {
        AuthKind::Unknown
    };
    let masked_identity = tokens
        .and_then(|tokens| tokens.get("account_id"))
        .and_then(serde_json::Value::as_str)
        .and_then(mask_identity);

    Account {
        id: account_id.to_string(),
        provider_id: provider_id.to_string(),
        label: label.to_string(),
        masked_identity,
        auth_kind,
        is_active,
        is_selected_for_launch: false,
        is_stored,
        is_incomplete: false,
        // `last_refresh` is a refresh timestamp, not an expiry [verified-local].
        // Inventing `expires_at` from it would fabricate a capability the file
        // does not provide (NFR-8).
        expires_at: None,
    }
}

/// A managed directory this application created that holds no usable
/// `auth.json`. Listed so it can be deleted; never active; never a
/// guess at identity from an empty folder.
fn incomplete_account(provider_id: &str, account_id: &str) -> Account {
    Account {
        id: account_id.to_string(),
        provider_id: provider_id.to_string(),
        label: account_id.to_string(),
        masked_identity: None,
        auth_kind: AuthKind::Unknown,
        is_active: false,
        is_selected_for_launch: false,
        is_stored: true,
        is_incomplete: true,
        expires_at: None,
    }
}

impl ProviderAdapter for CodexCliAdapter {
    fn id(&self) -> &'static str {
        "codex-cli"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "Codex CLI".to_string(),
            vendor: "OpenAI".to_string(),
            auth_kinds: vec![AuthKind::OAuth, AuthKind::ApiKey],
            // Switching writes a vendor-issued `auth.json` into the live
            // home. That does not prove the copied credential works against
            // the vendor (`docs/research/codex-cli.md` §5), so `Supported`
            // would overstate what this adapter can do (NFR-8).
            maturity: Maturity::Experimental,
            install_state: self.detect(),
            // Capabilities, not maturity, tell the Accounts page which
            // buttons this adapter will honour (NFR-8).
            capabilities: vec![
                ProviderCapability::AddAccount,
                ProviderCapability::SwitchAccount,
                ProviderCapability::DeleteAccount,
            ],
        }
    }

    fn config_paths(&self) -> Vec<PathBuf> {
        let Some(root) = self.codex_home() else {
            return Vec::new();
        };
        vec![root.join("auth.json"), root.join("config.toml")]
    }

    fn detect(&self) -> InstallState {
        let has_config = self.codex_home().map(|dir| dir.is_dir()).unwrap_or(false);
        if binary_on_path("codex") || has_config {
            InstallState::Installed
        } else {
            InstallState::NotInstalled
        }
    }

    fn list_accounts(&self) -> Result<Vec<Account>> {
        // is_active (NFR-8): the live Codex home holds exactly one identity,
        // and that is what the tool will use [verified-local]. A managed
        // directory is a stored copy. We mark a managed account active only
        // when its `auth.json` is byte-identical to the live file — a
        // structure-level comparison, not a token parse, and the one thing
        // we can tell without decoding identity. If a managed document
        // matches, the on-disk live slot is omitted: listing it as a
        // second active account would be a lie, and listing it as inactive
        // would deny that its file is the one in use. If no managed
        // document matches, the live slot is reported active. If there is
        // no live `auth.json`, or the live file is damaged, no account is
        // active — we do not guess that a stored copy is in use, and we
        // cannot compare against bytes we could not read. Two stored
        // copies of the same bytes would both match; only the first in
        // sorted id order is marked active so we never claim two accounts
        // are both active.
        //
        // A damaged live document is not a failed look. Stored copies
        // still list (`list_accounts_detailed`); the live error travels
        // with them so the caller can say the file is damaged instead of
        // hiding either fact.
        self.list_accounts_detailed()
            .map(|(accounts, _live_error)| accounts)
    }

    fn activate_account(&self, account_id: &str) -> Result<()> {
        // `docs/ARCHITECTURE.md` §5, in order. The document being written
        // is one the tool itself issued into a per-account directory; this
        // application does not invent credential JSON. Replacing auth.json
        // in the resolved Codex home is the local identity switch
        // `login status` follows: a 2026-08-19 probe on a full copy of a
        // populated live home showed that file alone decides the reported
        // identity [verified-local] (`docs/research/codex-cli.md` §5).
        // Vendor acceptance of a moved credential is untested; `login
        // status` is not a model request.

        // 1. Refuse if the tool is running. Error has no ToolRunning
        // variant; ConfigWrite is the closest existing one (we are
        // refusing a write). A dedicated variant would be better so the
        // UI can render a distinct "close the tool" recovery path.
        match self.tool_is_running() {
            Ok(true) => {
                return Err(self.config_write(
                    "Codex CLI appears to be running (process name `codex`). \
                     Close the Codex CLI and any VS Code Codex extension \
                     (`codex app-server`) before switching. Replacing \
                     auth.json while the tool is running can corrupt the \
                     credential file",
                ));
            }
            Ok(false) => {}
            Err(_) => {
                return Err(self.config_write(
                    "could not determine whether Codex CLI is running; \
                     refusing to replace auth.json. Close the Codex CLI \
                     and any VS Code Codex extension (`codex app-server`), \
                     then retry",
                ));
            }
        }

        // Structure-only read of the per-account file (exists, regular
        // file, JSON object). Unknown accounts must not snapshot or
        // write. This is not a CredentialStore lookup: we move a file.
        let (_source, bytes) = self.load_account_auth(account_id)?;

        let Some(live_auth) = self.codex_home().map(|root| root.join("auth.json")) else {
            return Err(self.config_write("Codex home directory is unavailable"));
        };

        // 2. Snapshot every path in config_paths() before anything is
        // written anywhere.
        let store = self.backup_store()?;
        let backup = store.snapshot(self.id(), &self.config_paths())?;

        let fail = |reason: String| Err(self.abort_switch(&store, &backup, reason));

        #[cfg(test)]
        if self.fault == SwitchFault::AfterSnapshot {
            return fail("injected failure after snapshot".to_string());
        }

        // 3. Write the target document into the live home atomically.
        // config.toml and every other live-home file are left untouched.
        if let Some(parent) = live_auth.parent() {
            if let Err(error) = fsx::create_dir_all_private(parent) {
                return fail(format!("could not create {}: {error}", parent.display()));
            }
        }
        if let Err(error) = fsx::write_atomic(&live_auth, &bytes) {
            return fail(format!("could not write {}: {error}", live_auth.display()));
        }

        #[cfg(test)]
        if self.fault == SwitchFault::AfterWrite {
            return fail("injected failure after write".to_string());
        }

        // 4. Verify the live file is the document we intended. See
        // `verify_live_auth` for what this does and does not prove.
        if let Err(error) = self.verify_live_auth(&live_auth, &bytes) {
            let reason = match error {
                Error::ConfigWrite { reason, .. } => reason,
                other => other.to_string(),
            };
            return fail(reason);
        }

        Ok(())
    }

    fn add_account(&self, account_id: &str) -> Result<()> {
        // SPEC.md §7 describes an in-app authorization-code + PKCE flow.
        // This adapter instead runs the vendor CLI's own `codex login` with
        // `CODEX_HOME` pointed at a per-account directory. The CLI performs
        // the browser sign-in and writes `auth.json` in whatever shape it
        // currently uses. This application never learns the format, never
        // invents a field, and stays correct if the vendor changes the
        // file. That is the same outcome as §7 without handling the
        // vendor's tokens, which is strictly better for NFR-1. This
        // creates a stored account; it does not switch the live home to
        // it, and it never touches `~/.codex`.
        //
        // Managed directories live under the application data directory,
        // not `/tmp`. With `CODEX_HOME` under the system temporary tree,
        // Codex 0.144.4 refuses to create PATH helper binaries
        // (`docs/research/codex-cli.md` §8). Tests inject the subprocess
        // and never spawn `codex`, so that constraint is not exercised
        // here.

        if !account_id_is_safe(account_id) {
            return Err(self.config_write(
                "account id is not a safe path component; refusing to create a managed directory",
            ));
        }
        if account_id == ON_DISK_ACCOUNT_ID {
            return Err(self.config_write(format!(
                "`{account_id}` is reserved for the live on-disk Codex identity; \
                 choose a different account id"
            )));
        }
        let Some(data_dir) = self.resolved_data_dir() else {
            return Err(self.config_write(
                "application data directory is unavailable; cannot create a managed account",
            ));
        };
        let dir = managed_account_dir(&data_dir, self.id(), account_id);
        self.prepare_managed_dir(&dir)?;

        // `dir` was created by this call, or was an abandoned slot this
        // call reused. Failure after this point removes only that
        // directory, never a parent that may already hold other accounts
        // and never the provider's accounts tree.
        let outcome = self
            .run_vendor_login(&dir)
            .and_then(|()| self.require_auth_json(&dir));
        if let Err(error) = outcome {
            return Err(self.cleanup_failed_add(&dir, error));
        }
        Ok(())
    }

    fn managed_account_plan_for(&self, auth_kind: AuthKind) -> Option<ManagedAccountPlan> {
        match auth_kind {
            AuthKind::OAuth => Some(ManagedAccountPlan {
                auth_kind: AuthKind::OAuth,
                material: StoredAccountMaterial::VendorHome,
            }),
            AuthKind::ApiKey | AuthKind::Unknown => None,
        }
    }

    fn delete_account(&self, account_id: &str) -> Result<()> {
        // Only the per-account directory this application created is
        // removed. The live Codex home is never consulted, so deleting
        // the account that is currently active does not sign the user
        // out of the tool.

        if !account_id_is_safe(account_id) {
            return Err(self.config_write(
                "account id is not a safe path component; refusing to remove a managed directory",
            ));
        }
        let Some(data_dir) = self.resolved_data_dir() else {
            return Err(self.config_write(
                "application data directory is unavailable; cannot delete a managed account",
            ));
        };
        let dir = managed_account_dir(&data_dir, self.id(), account_id);
        let accounts_root = data_dir.join("accounts").join(self.id());
        // `account_id_is_safe` already rejects the empty and `.` forms
        // that would collapse this path onto the provider tree. Keep the
        // equality check so a future helper change cannot turn one
        // delete into wiping every stored account.
        if dir == accounts_root {
            return Err(self.config_write(format!(
                "refusing to remove the provider accounts tree {}",
                accounts_root.display()
            )));
        }

        let metadata = match fs::symlink_metadata(&dir) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(Error::UnknownAccount(account_id.to_string()));
            }
            Err(error) => {
                return Err(self.config_write(format!("{} ({})", dir.display(), error.kind())));
            }
        };
        // `symlink_metadata` does not follow links. A planted symlink is
        // not a directory we created; following it would delete whatever
        // it points at — the live home, another slot, or a path outside
        // this tree.
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(self.config_write(format!(
                "{} is not a managed account directory; refusing to remove it",
                dir.display()
            )));
        }

        match fs::remove_dir_all(&dir) {
            Ok(()) => {
                if fs::symlink_metadata(&dir).is_ok() {
                    return Err(self.config_write(format!(
                        "could not fully remove {}; the path is still present",
                        dir.display()
                    )));
                }
                Ok(())
            }
            Err(error) => {
                let leftover = leftover_managed_path(&dir);
                Err(self.config_write(format!(
                    "could not fully remove {} ({}); credential material remains at {}",
                    dir.display(),
                    error.kind(),
                    leftover.display()
                )))
            }
        }
    }

    fn quota(&self) -> Result<Vec<crate::model::QuotaSnapshot>> {
        // No local quota file was observed [verified-local], and response
        // headers are only [inferred] (`docs/research/codex-cli.md` section 6).
        Ok(Vec::new())
    }
}

/// After a failed `remove_dir_all`, name a path that is still there so
/// the user can remove leftover credential material by hand. Prefer a
/// nested leftover over the directory itself. Never follows a leftover
/// symlink (that would report a path outside the managed tree) and never
/// reads file bytes (NFR-1).
fn leftover_managed_path(dir: &Path) -> PathBuf {
    let mut current = dir.to_path_buf();
    for _ in 0..32 {
        let Ok(mut entries) = fs::read_dir(&current) else {
            return current;
        };
        let Some(Ok(entry)) = entries.next() else {
            return current;
        };
        let child = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&child) else {
            return child;
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return child;
        }
        current = child;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::ProviderAdapter;
    use super::*;
    use std::fs;
    use std::path::Path;

    const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/codex-cli");
    const FAKE_PREFIX: &str = "FAKE-";

    fn staged_home(name: &str) -> tempfile::TempDir {
        let src = Path::new(FIXTURE_ROOT).join(name);
        let temp = tempfile::tempdir().expect("tempdir");
        copy_tree(&src, temp.path());
        temp
    }

    fn copy_tree(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).unwrap_or_else(|error| {
            panic!("create {}: {error}", dst.display());
        });
        for entry in fs::read_dir(src).unwrap_or_else(|error| {
            panic!("read_dir {}: {error}", src.display());
        }) {
            let entry = entry.expect("dirent");
            let to = dst.join(entry.file_name());
            if entry.file_type().expect("file type").is_dir() {
                copy_tree(&entry.path(), &to);
            } else {
                fs::copy(entry.path(), &to).unwrap_or_else(|error| {
                    panic!(
                        "copy {} -> {}: {error}",
                        entry.path().display(),
                        to.display()
                    );
                });
            }
        }
    }

    fn assert_no_fake(where_: &str, text: &str) {
        assert!(
            !text.contains(FAKE_PREFIX),
            "{where_} leaked fixture secret material: {text}"
        );
    }

    #[test]
    fn with_home_resolves_config_paths_under_the_injected_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = CodexCliAdapter::with_home(dir.path());
        let paths = adapter.config_paths();

        assert!(
            !paths.is_empty(),
            "config_paths must not go silent under an injected home"
        );
        for path in paths {
            assert!(
                path.starts_with(dir.path()),
                "{path} escaped the injected home {home}",
                path = path.display(),
                home = dir.path().display()
            );
        }
    }

    #[test]
    fn mask_identity_keeps_only_the_last_four_characters() {
        assert_eq!(mask_identity("ab12cd34"), Some("****cd34".to_string()));
        assert_eq!(mask_identity("wxyz"), None);
        assert_eq!(mask_identity("abc"), None);
        assert_eq!(mask_identity(""), None);
    }

    #[test]
    fn list_accounts_matches_the_oauth_fixture_expectation() {
        let home = staged_home("home");
        let adapter = CodexCliAdapter::with_home(home.path());
        let accounts = adapter.list_accounts().expect("list");

        let expected_path = Path::new(FIXTURE_ROOT).join("expected/accounts.json");
        let mut expected: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&expected_path).expect("expected/accounts.json"),
        )
        .expect("expected json");
        expected[0]["isSelectedForLaunch"] = serde_json::Value::Bool(false);
        let got = serde_json::to_value(&accounts).expect("serialize");
        assert_eq!(got, expected);

        assert_eq!(accounts.len(), 1);
        assert!(accounts[0].is_active);
        assert_eq!(accounts[0].auth_kind, AuthKind::OAuth);
        assert_eq!(accounts[0].masked_identity.as_deref(), Some("****0001"));
        assert_eq!(accounts[0].expires_at, None);
        assert_eq!(accounts[0].id, ON_DISK_ACCOUNT_ID);

        let again = adapter.list_accounts().expect("second list");
        assert_eq!(again[0].id, accounts[0].id);
    }

    #[test]
    fn list_accounts_classifies_a_non_null_api_key_as_api_key() {
        let home = staged_home("home-api-key");
        let adapter = CodexCliAdapter::with_home(home.path());
        let accounts = adapter.list_accounts().expect("list");

        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].auth_kind, AuthKind::ApiKey);
        assert!(accounts[0].is_active);
        assert_eq!(accounts[0].expires_at, None);
        assert_eq!(accounts[0].masked_identity, None);
        assert_no_fake(
            "api-key list_accounts json",
            &serde_json::to_string(&accounts).expect("json"),
        );
    }

    #[test]
    fn list_accounts_returns_empty_when_auth_json_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = CodexCliAdapter::with_home(dir.path());
        let accounts = adapter
            .list_accounts()
            .expect("a missing auth.json is not an error");
        assert!(accounts.is_empty());
    }

    #[test]
    fn list_accounts_treats_malformed_live_auth_json_as_uncomparable() {
        // Written here rather than stored as a `.json` fixture: Prettier parses
        // tracked `*.json` and refuses this intentionally invalid document.
        let home = tempfile::tempdir().expect("tempdir");
        let auth_dir = home.path().join(".codex");
        fs::create_dir_all(&auth_dir).expect("mkdir .codex");
        fs::write(
            auth_dir.join("auth.json"),
            r#"{this is not json, "OPENAI_API_KEY": "FAKE-malformed-key-0001""#,
        )
        .expect("write malformed auth.json");
        let adapter = CodexCliAdapter::with_home(home.path());
        let accounts = adapter
            .list_accounts()
            .expect("a damaged live file must not fail the look");
        assert!(
            accounts.is_empty(),
            "no stored copies and nothing comparable: {accounts:?}"
        );

        let (detailed, live_error) = adapter
            .list_accounts_detailed()
            .expect("damage is reported, not a failed look");
        assert!(detailed.is_empty());
        let error = live_error.expect("the caller must be told the live file is damaged");
        assert!(
            matches!(error, Error::ConfigRead { .. }),
            "expected ConfigRead, got {error:?}"
        );
        assert!(
            error.to_string().contains("auth.json"),
            "user must be told which file is damaged: {error}"
        );
        assert_no_fake("ConfigRead Display", &error.to_string());
        assert_no_fake("ConfigRead Debug", &format!("{error:?}"));
    }

    #[test]
    fn list_accounts_never_returns_fixture_secret_material() {
        let home = staged_home("home");
        let adapter = CodexCliAdapter::with_home(home.path());
        let accounts = adapter.list_accounts().expect("list");

        let auth = fs::read_to_string(home.path().join(".codex/auth.json")).expect("auth.json");
        assert!(
            auth.contains(FAKE_PREFIX),
            "fixture lost its {FAKE_PREFIX} values; the leak grep would be vacuous"
        );

        assert_no_fake(
            "list_accounts json",
            &serde_json::to_string(&accounts).expect("json"),
        );
        assert_no_fake("list_accounts debug", &format!("{accounts:?}"));
        for account in &accounts {
            assert_no_fake("account.id", &account.id);
            assert_no_fake("account.label", &account.label);
            if let Some(identity) = &account.masked_identity {
                assert_no_fake("account.masked_identity", identity);
            }
        }
    }

    #[test]
    fn descriptor_stays_experimental_after_switch_is_implemented() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = CodexCliAdapter::with_home(dir.path());
        assert_eq!(adapter.descriptor().maturity, Maturity::Experimental);
        assert_eq!(
            adapter.descriptor().capabilities,
            vec![
                ProviderCapability::AddAccount,
                ProviderCapability::SwitchAccount,
                ProviderCapability::DeleteAccount,
            ]
        );
        assert!(
            !matches!(
                adapter.activate_account("codex-cli-on-disk"),
                Err(Error::NotImplemented(_))
            ),
            "activate_account is implemented; NotImplemented would be a lie"
        );
    }

    const TARGET_ACCOUNT: &str = "acct-work";
    const TARGET_AUTH: &str = r#"{
  "auth_mode": "plan",
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "FAKE-id-token-0002",
    "access_token": "FAKE-access-token-0002",
    "refresh_token": "FAKE-refresh-token-0002",
    "account_id": "FAKE-account-0002"
  },
  "last_refresh": "2026-08-18T00:00:00.000Z"
}
"#;

    struct SwitchEnv {
        live: tempfile::TempDir,
        data: tempfile::TempDir,
    }

    impl SwitchEnv {
        fn new() -> Self {
            let live = staged_home("home");
            let data = tempfile::tempdir().expect("data dir");
            let account_dir = data.path().join("accounts/codex-cli").join(TARGET_ACCOUNT);
            fs::create_dir_all(&account_dir).expect("account dir");
            fs::write(account_dir.join("auth.json"), TARGET_AUTH).expect("target auth");
            Self { live, data }
        }

        fn adapter(&self) -> CodexCliAdapter {
            CodexCliAdapter::with_home(self.live.path())
                .with_data_dir(self.data.path())
                .with_tool_running(false)
        }

        fn backups(&self) -> BackupStore {
            BackupStore::new(self.data.path().join("backups"))
        }

        fn digest(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
            digest_codex(self.live.path())
        }
    }

    fn digest_codex(home: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        let root = home.join(".codex");
        let mut out = std::collections::BTreeMap::new();
        collect_files(&root, &root, &mut out);
        out
    }

    fn collect_files(
        root: &Path,
        path: &Path,
        out: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) {
        let metadata = fs::symlink_metadata(path).unwrap_or_else(|error| {
            panic!("digest metadata for {}: {error}", path.display());
        });
        if metadata.is_file() {
            let rel = path.strip_prefix(root).expect("path under .codex");
            let key = rel
                .iter()
                .map(|component| component.to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            out.insert(key, fs::read(path).expect("digest read"));
        } else if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("digest read_dir") {
                collect_files(root, &entry.expect("dirent").path(), out);
            }
        }
    }

    fn files_except<'a>(
        tree: &'a std::collections::BTreeMap<String, Vec<u8>>,
        skip: &str,
    ) -> std::collections::BTreeMap<&'a str, &'a [u8]> {
        tree.iter()
            .filter(|(path, _)| path.as_str() != skip)
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
            .collect()
    }

    fn digest_brief(tree: &std::collections::BTreeMap<String, Vec<u8>>) -> String {
        tree.iter()
            .map(|(path, bytes)| format!("{path} {}b", bytes.len()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn assert_switch_error_holds_no_secret(error: &Error) {
        assert_no_fake("activate_account Display", &error.to_string());
        assert_no_fake("activate_account Debug", &format!("{error:?}"));
    }

    #[test]
    fn activate_account_replaces_auth_json_and_leaves_every_other_file_byte_identical() {
        let env = SwitchEnv::new();
        let before = env.digest();
        assert_ne!(
            before.get("auth.json").map(Vec::as_slice),
            Some(TARGET_AUTH.as_bytes()),
            "precondition: live auth.json must differ from the target"
        );
        assert!(
            before.contains_key("config.toml"),
            "precondition: live home must have config.toml"
        );
        assert!(
            before.contains_key("sessions/history.jsonl"),
            "precondition: live home must have a sibling the switch must not touch"
        );

        env.adapter()
            .activate_account(TARGET_ACCOUNT)
            .expect("switch");

        let after = env.digest();
        assert_eq!(
            after.get("auth.json").map(Vec::as_slice),
            Some(TARGET_AUTH.as_bytes()),
            "live auth.json must be the target document"
        );
        assert_eq!(
            files_except(&before, "auth.json"),
            files_except(&after, "auth.json"),
            "every other live-home file must be byte-identical; before={} after={}",
            digest_brief(&before),
            digest_brief(&after)
        );
    }

    #[test]
    fn activate_account_writes_a_backup_before_the_first_mutation() {
        let env = SwitchEnv::new();
        let before = env.digest();

        let error = env
            .adapter()
            .with_fault(SwitchFault::AfterSnapshot)
            .activate_account(TARGET_ACCOUNT)
            .expect_err("injected failure after snapshot");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("previous account is still active"),
            "unexpected error: {error}"
        );
        assert_switch_error_holds_no_secret(&error);

        let after = env.digest();
        assert_eq!(
            before,
            after,
            "a failure after snapshot must not mutate the live home; before={} after={}",
            digest_brief(&before),
            digest_brief(&after)
        );

        let listed = env.backups().list().expect("list backups");
        assert_eq!(
            listed.len(),
            1,
            "a restorable backup must exist before the first write"
        );
        assert_eq!(listed[0].provider_id, "codex-cli");
        assert!(
            env.data
                .path()
                .join("backups")
                .join(listed[0].id.as_str())
                .join("manifest.json")
                .is_file(),
            "backup manifest must already be on disk"
        );
    }

    #[test]
    fn activate_account_restores_the_live_home_after_a_forced_write_failure() {
        let env = SwitchEnv::new();
        let before = env.digest();

        let error = env
            .adapter()
            .with_fault(SwitchFault::AfterWrite)
            .activate_account(TARGET_ACCOUNT)
            .expect_err("injected failure after write");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("previous account is still active"),
            "unexpected error: {error}"
        );
        assert_switch_error_holds_no_secret(&error);

        let after = env.digest();
        assert_eq!(
            before,
            after,
            "restore must return the live home to a byte-identical state; before={} after={}",
            digest_brief(&before),
            digest_brief(&after)
        );
    }

    #[test]
    fn activate_account_rejects_an_unknown_account_without_touching_anything() {
        let env = SwitchEnv::new();
        let before = env.digest();

        let error = env
            .adapter()
            .activate_account("no-such-account")
            .expect_err("unknown account");
        assert!(
            matches!(error, Error::UnknownAccount(ref id) if id == "no-such-account"),
            "expected UnknownAccount, got {error:?}"
        );
        assert_switch_error_holds_no_secret(&error);

        let after = env.digest();
        assert_eq!(
            before,
            after,
            "unknown account must not mutate the live home; before={} after={}",
            digest_brief(&before),
            digest_brief(&after)
        );
        assert!(
            env.backups().list().expect("list").is_empty(),
            "unknown account must not write a backup"
        );
        assert!(
            !env.data.path().join("backups").exists(),
            "unknown account must not create the backup root"
        );
    }

    #[test]
    fn activate_account_rejects_a_path_escape_account_id_without_touching_anything() {
        let env = SwitchEnv::new();
        let before = env.digest();
        let error = env
            .adapter()
            .activate_account("../etc")
            .expect_err("escaped id");
        assert!(
            matches!(error, Error::UnknownAccount(ref id) if id == "../etc"),
            "expected UnknownAccount, got {error:?}"
        );
        assert_eq!(before, env.digest());
        assert!(!env.data.path().join("backups").exists());
    }

    #[test]
    fn activate_account_refuses_while_the_tool_is_running_and_writes_nothing() {
        let env = SwitchEnv::new();
        let before = env.digest();

        let error = env
            .adapter()
            .with_tool_running(true)
            .activate_account(TARGET_ACCOUNT)
            .expect_err("running tool");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        assert!(
            error.to_string().contains("appears to be running"),
            "user must be told what is running: {error}"
        );
        assert!(
            error.to_string().contains("codex app-server"),
            "user must be told what to close: {error}"
        );
        assert_switch_error_holds_no_secret(&error);

        let after = env.digest();
        assert_eq!(
            before,
            after,
            "running-tool refusal must write nothing; before={} after={}",
            digest_brief(&before),
            digest_brief(&after)
        );
        assert!(
            !env.data.path().join("backups").exists(),
            "running-tool refusal must not snapshot"
        );
    }

    #[test]
    fn activate_account_refuses_when_it_cannot_tell_whether_the_tool_is_running() {
        let env = SwitchEnv::new();
        let before = env.digest();

        let error = env
            .adapter()
            .with_tool_undetermined()
            .activate_account(TARGET_ACCOUNT)
            .expect_err("cannot tell");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        assert!(
            error.to_string().contains("could not determine"),
            "user must be told the check failed: {error}"
        );
        assert_switch_error_holds_no_secret(&error);

        let after = env.digest();
        assert_eq!(
            before,
            after,
            "cannot-tell must write nothing; before={} after={}",
            digest_brief(&before),
            digest_brief(&after)
        );
        assert!(
            !env.data.path().join("backups").exists(),
            "cannot-tell must not snapshot"
        );
    }

    const ADDED_ACCOUNT: &str = "acct-new";
    const SIBLING_ACCOUNT: &str = "acct-keep";
    const LOGIN_SPAWN_OUTPUT: &str = "FAKE-subprocess-output-must-never-appear";

    fn managed_oauth_path() -> std::path::PathBuf {
        Path::new(FIXTURE_ROOT).join("managed-oauth/auth.json")
    }

    fn managed_oauth_bytes() -> Vec<u8> {
        fs::read(managed_oauth_path()).expect("managed-oauth fixture")
    }

    fn login_writes_managed_oauth(dir: &Path) -> std::io::Result<i32> {
        fs::copy(managed_oauth_path(), dir.join("auth.json")).expect("copy managed-oauth fixture");
        Ok(0)
    }

    fn login_exits_nonzero(dir: &Path) -> std::io::Result<i32> {
        fs::write(dir.join("partial"), b"incomplete")?;
        Ok(1)
    }

    fn login_ok_without_auth(dir: &Path) -> std::io::Result<i32> {
        fs::write(dir.join("unrelated.txt"), b"no auth.json")?;
        Ok(0)
    }

    fn login_fails_to_start(_dir: &Path) -> std::io::Result<i32> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            LOGIN_SPAWN_OUTPUT,
        ))
    }

    fn login_must_not_run(_dir: &Path) -> std::io::Result<i32> {
        panic!("codex login must not run");
    }

    struct AddEnv {
        live: tempfile::TempDir,
        data: tempfile::TempDir,
    }

    impl AddEnv {
        fn new() -> Self {
            Self {
                live: staged_home("home"),
                data: tempfile::tempdir().expect("data dir"),
            }
        }

        fn empty_live() -> Self {
            let live = tempfile::tempdir().expect("empty live");
            fs::create_dir_all(live.path().join(".codex")).expect("empty .codex");
            Self {
                live,
                data: tempfile::tempdir().expect("data dir"),
            }
        }

        fn adapter(&self, runner: fn(&Path) -> std::io::Result<i32>) -> CodexCliAdapter {
            CodexCliAdapter::with_home(self.live.path())
                .with_data_dir(self.data.path())
                .with_login_runner(runner)
        }

        fn managed_dir(&self, account_id: &str) -> std::path::PathBuf {
            self.data
                .path()
                .join("accounts")
                .join("codex-cli")
                .join(account_id)
        }

        fn digest(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
            digest_codex(self.live.path())
        }

        fn seed_managed(&self, account_id: &str, auth: &[u8]) {
            let dir = self.managed_dir(account_id);
            fs::create_dir_all(&dir).expect("managed dir");
            fs::write(dir.join("auth.json"), auth).expect("managed auth");
        }

        fn seed_incomplete(&self, account_id: &str) {
            fs::create_dir_all(self.managed_dir(account_id)).expect("incomplete managed dir");
        }
    }

    fn assert_add_error_is_clean(error: &Error) {
        assert_no_fake("add_account Display", &error.to_string());
        assert_no_fake("add_account Debug", &format!("{error:?}"));
        assert!(
            !error.to_string().contains(LOGIN_SPAWN_OUTPUT),
            "add_account Display leaked subprocess output: {error}"
        );
        assert!(
            !format!("{error:?}").contains(LOGIN_SPAWN_OUTPUT),
            "add_account Debug leaked subprocess output: {error:?}"
        );
    }

    fn assert_no_managed_leaf(env: &AddEnv, account_id: &str) {
        let dir = env.managed_dir(account_id);
        assert!(
            fs::symlink_metadata(&dir).is_err(),
            "managed path must not remain after a failed add: {}",
            dir.display()
        );
    }

    #[test]
    fn add_account_creates_a_managed_directory_and_lists_it() {
        let env = AddEnv::new();
        let before = env.digest();

        env.adapter(login_writes_managed_oauth)
            .add_account(ADDED_ACCOUNT)
            .expect("add");

        let dir = env.managed_dir(ADDED_ACCOUNT);
        assert!(
            dir.is_dir(),
            "managed directory must exist after a successful add"
        );
        assert_eq!(
            fs::read(dir.join("auth.json")).expect("read added auth.json"),
            managed_oauth_bytes(),
            "managed auth.json must be the document the login stub wrote"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&dir)
                .expect("managed dir metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "managed directory must be owner-only");
        }

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list after add");
        let added = accounts
            .iter()
            .find(|account| account.id == ADDED_ACCOUNT)
            .expect("added account must appear in list_accounts");
        assert_eq!(added.provider_id, "codex-cli");
        assert_eq!(added.auth_kind, AuthKind::OAuth);
        assert_eq!(added.masked_identity.as_deref(), Some("****0003"));
        assert!(
            !added.is_active,
            "a new stored copy is not the live identity"
        );
        assert!(
            !added.is_incomplete,
            "a login that wrote auth.json is a complete stored copy"
        );
        assert!(
            accounts
                .iter()
                .any(|account| { account.id == ON_DISK_ACCOUNT_ID && account.is_active }),
            "live row must remain active when the new copy does not match it"
        );

        assert_eq!(
            before,
            env.digest(),
            "add_account must not touch the live Codex home; before={} after={}",
            digest_brief(&before),
            digest_brief(&env.digest())
        );
        assert_no_fake(
            "list_accounts after add",
            &serde_json::to_string(&accounts).expect("json"),
        );
    }

    #[test]
    fn add_account_removes_the_directory_when_login_exits_nonzero() {
        let env = AddEnv::new();
        env.seed_managed(SIBLING_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();
        let sibling =
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling");

        let error = env
            .adapter(login_exits_nonzero)
            .add_account(ADDED_ACCOUNT)
            .expect_err("nonzero login");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        assert!(
            error.to_string().contains("exited with status 1"),
            "user must be told the exit status: {error}"
        );
        assert_add_error_is_clean(&error);
        assert_no_managed_leaf(&env, ADDED_ACCOUNT);
        assert_eq!(
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling after"),
            sibling,
            "a failed add must not remove a sibling managed account"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn add_account_removes_the_directory_when_login_writes_no_auth_json() {
        let env = AddEnv::new();
        let before = env.digest();

        let error = env
            .adapter(login_ok_without_auth)
            .add_account(ADDED_ACCOUNT)
            .expect_err("missing auth.json");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        let display = error.to_string();
        assert!(
            display.contains("was not created"),
            "user must be told auth.json is missing: {error}"
        );
        assert!(
            display.contains("auth.json"),
            "user must be told which file is missing: {error}"
        );
        assert_add_error_is_clean(&error);
        assert_no_managed_leaf(&env, ADDED_ACCOUNT);
        assert_eq!(before, env.digest());
    }

    #[test]
    fn add_account_reports_a_spawn_failure_by_kind_and_path() {
        let env = AddEnv::new();
        let before = env.digest();
        let expected_dir = env.managed_dir(ADDED_ACCOUNT);
        let kind = std::io::ErrorKind::NotFound;

        let error = env
            .adapter(login_fails_to_start)
            .add_account(ADDED_ACCOUNT)
            .expect_err("spawn failure");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        let display = error.to_string();
        assert!(
            display.contains("could not start"),
            "user must be told the CLI did not start: {error}"
        );
        assert!(
            display.contains(&expected_dir.display().to_string()),
            "user must be told the CODEX_HOME path: {error}"
        );
        assert!(
            display.contains(&format!("{kind}")),
            "user must be told the I/O kind ({kind}): {error}"
        );
        assert_add_error_is_clean(&error);
        assert_no_managed_leaf(&env, ADDED_ACCOUNT);
        assert_eq!(before, env.digest());
    }

    #[cfg(unix)]
    #[test]
    fn add_account_reports_leftover_path_when_cleanup_fails() {
        use std::os::unix::fs::PermissionsExt;

        struct RestorePerms(std::path::PathBuf);
        impl Drop for RestorePerms {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            }
        }

        let env = AddEnv::new();
        let expected_dir = env.managed_dir(ADDED_ACCOUNT);
        let nested = expected_dir.join("nested");

        fn login_leaves_undeletable_tree(dir: &Path) -> std::io::Result<i32> {
            let nested = dir.join("nested");
            fs::create_dir(&nested)?;
            fs::write(nested.join("stuck"), b"x")?;
            fs::set_permissions(&nested, fs::Permissions::from_mode(0o000))?;
            Ok(1)
        }

        let error = env
            .adapter(login_leaves_undeletable_tree)
            .add_account(ADDED_ACCOUNT)
            .expect_err("nonzero login plus failed cleanup");
        let _restore = RestorePerms(nested);
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        let display = error.to_string();
        assert!(
            display.contains("exited with status 1"),
            "user must still be told the login failed: {error}"
        );
        assert!(
            display.contains("credential material may remain"),
            "user must be told leftover material may remain: {error}"
        );
        assert!(
            display.contains(&expected_dir.display().to_string()),
            "user must be told the leftover path: {error}"
        );
        assert_add_error_is_clean(&error);
        assert!(
            fs::symlink_metadata(&expected_dir).is_ok(),
            "the abandoned directory is still there so the leftover path is real"
        );
    }

    #[test]
    fn add_account_refuses_an_existing_managed_directory_without_changing_it() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        let dir = env.managed_dir(ADDED_ACCOUNT);
        fs::write(dir.join("sentinel.txt"), b"leave me").expect("sentinel");
        let before_auth = fs::read(dir.join("auth.json")).expect("auth before");
        let before_live = env.digest();

        let error = env
            .adapter(login_must_not_run)
            .add_account(ADDED_ACCOUNT)
            .expect_err("existing directory");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        assert!(
            error.to_string().contains("already exists"),
            "user must be told the directory already exists: {error}"
        );
        assert_add_error_is_clean(&error);
        assert_eq!(
            fs::read(dir.join("auth.json")).expect("auth after"),
            before_auth,
            "existing managed auth.json must be unchanged"
        );
        assert_eq!(
            fs::read(dir.join("sentinel.txt")).expect("sentinel after"),
            b"leave me",
            "existing managed directory contents must be unchanged"
        );
        assert_eq!(before_live, env.digest());
    }

    #[test]
    fn add_account_reuses_an_incomplete_slot_that_holds_no_auth_json() {
        let env = AddEnv::new();
        env.seed_incomplete(ADDED_ACCOUNT);
        fs::write(env.managed_dir(ADDED_ACCOUNT).join("partial"), b"leftover").expect("partial");
        let before = env.digest();

        env.adapter(login_writes_managed_oauth)
            .add_account(ADDED_ACCOUNT)
            .expect("reuse abandoned slot");

        let dir = env.managed_dir(ADDED_ACCOUNT);
        assert_eq!(
            fs::read(dir.join("auth.json")).expect("read added auth.json"),
            managed_oauth_bytes(),
            "login must write auth.json into the reused directory"
        );
        let added = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list after reuse")
            .into_iter()
            .find(|account| account.id == ADDED_ACCOUNT)
            .expect("reused slot must list as a complete account");
        assert!(!added.is_incomplete);
        assert!(added.is_stored);
        assert!(!added.is_active);
        assert_eq!(before, env.digest());
    }

    #[test]
    fn add_account_refuses_the_live_on_disk_id() {
        let env = AddEnv::new();
        let before = env.digest();

        let error = env
            .adapter(login_must_not_run)
            .add_account(ON_DISK_ACCOUNT_ID)
            .expect_err("reserved id");
        assert!(
            matches!(error, Error::ConfigWrite { .. }),
            "expected ConfigWrite, got {error:?}"
        );
        let display = error.to_string();
        assert!(
            display.contains(ON_DISK_ACCOUNT_ID),
            "user must be told which id is reserved: {error}"
        );
        assert!(
            display.contains("reserved"),
            "user must be told the id is reserved: {error}"
        );
        assert_add_error_is_clean(&error);
        assert_no_managed_leaf(&env, ON_DISK_ACCOUNT_ID);
        assert_eq!(before, env.digest());
    }

    #[test]
    fn add_account_refuses_an_unsafe_id_before_creating_anything() {
        let env = AddEnv::new();
        env.seed_managed(SIBLING_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();
        let sibling =
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling");

        for unsafe_id in ["../etc", "acct/work", ""] {
            let error = env
                .adapter(login_must_not_run)
                .add_account(unsafe_id)
                .expect_err("unsafe id");
            assert!(
                matches!(error, Error::ConfigWrite { .. }),
                "expected ConfigWrite for {unsafe_id:?}, got {error:?}"
            );
            assert!(
                error.to_string().contains("not a safe path component"),
                "user must be told the id is unsafe ({unsafe_id:?}): {error}"
            );
            assert_add_error_is_clean(&error);
        }

        assert_eq!(
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling after"),
            sibling,
            "an unsafe id must not touch a sibling managed account"
        );
        assert!(
            !env.data.path().join("accounts/etc").exists(),
            "../etc must not escape into a sibling of the provider tree"
        );
        assert_eq!(before, env.digest());
    }

    #[cfg(unix)]
    #[test]
    fn add_account_refuses_a_dangling_symlink_at_the_managed_path() {
        let env = AddEnv::new();
        let dir = env.managed_dir(ADDED_ACCOUNT);
        fs::create_dir_all(dir.parent().expect("parent")).expect("provider tree");
        std::os::unix::fs::symlink(dir.with_file_name("missing-target"), &dir)
            .expect("dangling symlink");
        let before = env.digest();

        let error = env
            .adapter(login_must_not_run)
            .add_account(ADDED_ACCOUNT)
            .expect_err("dangling symlink");
        assert!(
            error.to_string().contains("already exists"),
            "a dangling symlink is an existing directory entry: {error}"
        );
        assert_add_error_is_clean(&error);
        let metadata = fs::symlink_metadata(&dir).expect("symlink remains");
        assert!(
            metadata.file_type().is_symlink(),
            "refusing the slot must not replace a symlink we did not create"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn add_account_refuses_a_file_at_the_managed_path() {
        let env = AddEnv::new();
        let dir = env.managed_dir(ADDED_ACCOUNT);
        fs::create_dir_all(dir.parent().expect("parent")).expect("provider tree");
        fs::write(&dir, b"not a directory").expect("file at slot");
        let before = env.digest();

        let error = env
            .adapter(login_must_not_run)
            .add_account(ADDED_ACCOUNT)
            .expect_err("file at slot");
        assert!(
            error.to_string().contains("already exists"),
            "a file at the slot is an existing directory entry: {error}"
        );
        assert_add_error_is_clean(&error);
        assert_eq!(
            fs::read(&dir).expect("file after"),
            b"not a directory",
            "refusing the slot must not replace a file we did not create"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn list_accounts_marks_a_byte_identical_managed_copy_active_and_omits_the_live_row() {
        let env = AddEnv::new();
        let live_auth = fs::read(env.live.path().join(".codex/auth.json")).expect("live auth");
        env.seed_managed(TARGET_ACCOUNT, &live_auth);
        let before = env.digest();

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list");
        assert_eq!(
            accounts.iter().filter(|account| account.is_active).count(),
            1,
            "exactly one account must be active"
        );
        let managed = accounts
            .iter()
            .find(|account| account.id == TARGET_ACCOUNT)
            .expect("managed account");
        assert!(managed.is_active);
        assert!(
            accounts
                .iter()
                .all(|account| account.id != ON_DISK_ACCOUNT_ID),
            "the anonymous live row must be omitted when a managed copy matches"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn list_accounts_reports_the_live_row_when_no_managed_copy_matches() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list");
        let live = accounts
            .iter()
            .find(|account| account.id == ON_DISK_ACCOUNT_ID)
            .expect("live row");
        assert!(live.is_active);
        let managed = accounts
            .iter()
            .find(|account| account.id == ADDED_ACCOUNT)
            .expect("managed account");
        assert!(!managed.is_active);
        assert_eq!(before, env.digest());
    }

    #[test]
    fn list_accounts_marks_stored_copies_and_the_live_row() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list");
        let live = accounts
            .iter()
            .find(|account| account.id == ON_DISK_ACCOUNT_ID)
            .expect("live row");
        assert!(
            !live.is_stored,
            "the on-disk identity is not a stored copy this application can act on"
        );
        let managed = accounts
            .iter()
            .find(|account| account.id == ADDED_ACCOUNT)
            .expect("managed account");
        assert!(
            managed.is_stored,
            "a per-account directory this application created is stored"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn list_accounts_claims_nothing_active_when_there_is_no_live_auth_json() {
        let env = AddEnv::empty_live();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list");
        assert!(
            accounts.iter().all(|account| !account.is_active),
            "a stored copy is not in use when the live file is missing"
        );
        assert!(
            accounts.iter().any(|account| account.id == ADDED_ACCOUNT),
            "the stored account must still be listed"
        );
        assert!(
            accounts
                .iter()
                .all(|account| account.id != ON_DISK_ACCOUNT_ID),
            "no live row without a live auth.json"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn list_accounts_skips_a_malformed_managed_auth_json_without_hiding_others() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        env.seed_managed("acct-bad", b"{this is not json");
        let before = env.digest();

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list");
        let ids: Vec<&str> = accounts.iter().map(|account| account.id.as_str()).collect();
        assert!(
            ids.contains(&ADDED_ACCOUNT),
            "a readable managed account must still be listed: {ids:?}"
        );
        assert!(
            ids.contains(&ON_DISK_ACCOUNT_ID),
            "the live row must still be listed: {ids:?}"
        );
        assert!(
            !ids.contains(&"acct-bad"),
            "a malformed managed auth.json must be skipped: {ids:?}"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn list_accounts_lists_an_incomplete_slot_so_it_can_be_deleted() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        fs::create_dir_all(env.managed_dir("acct-empty")).expect("empty managed dir");
        let before = env.digest();

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list");
        let incomplete = accounts
            .iter()
            .find(|account| account.id == "acct-empty")
            .expect("an abandoned add must be listed so it can be deleted");
        assert!(
            incomplete.is_incomplete,
            "an empty managed directory is not a usable account"
        );
        assert!(
            incomplete.is_stored,
            "delete_account can remove the abandoned directory"
        );
        assert!(
            !incomplete.is_active,
            "an incomplete slot cannot be the live identity"
        );
        assert_eq!(incomplete.auth_kind, AuthKind::Unknown);
        assert_eq!(incomplete.masked_identity, None);
        assert!(
            !accounts
                .iter()
                .find(|account| account.id == ADDED_ACCOUNT)
                .expect("complete sibling")
                .is_incomplete,
            "a usable stored copy is not incomplete"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn list_accounts_skips_a_file_or_symlink_in_the_managed_root() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        let root = env.data.path().join("accounts/codex-cli");
        fs::write(root.join("acct-file"), b"not a directory").expect("file in root");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(env.managed_dir(ADDED_ACCOUNT), root.join("acct-link"))
                .expect("symlink in root");
        }
        let before = env.digest();

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list");
        let ids: Vec<&str> = accounts.iter().map(|account| account.id.as_str()).collect();
        assert!(
            ids.contains(&ADDED_ACCOUNT),
            "real managed account missing: {ids:?}"
        );
        assert!(
            !ids.contains(&"acct-file"),
            "a file must not be listed: {ids:?}"
        );
        assert!(
            !ids.contains(&"acct-link"),
            "a symlink must not be listed as a stored account: {ids:?}"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn list_accounts_lists_stored_copies_when_live_auth_json_is_malformed() {
        // Previously this failed the whole look, which hid the stored
        // copies the user needs to repair the live file. A damaged live
        // document is now a warning on the listing, not an empty Failed.
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        fs::write(
            env.live.path().join(".codex/auth.json"),
            r#"{this is not json, "OPENAI_API_KEY": "FAKE-malformed-key-0001""#,
        )
        .expect("malformed live auth.json");

        let adapter = env.adapter(login_must_not_run);
        let accounts = adapter
            .list_accounts()
            .expect("a damaged live file must not hide stored copies");
        let ids: Vec<&str> = accounts.iter().map(|account| account.id.as_str()).collect();
        assert!(
            ids.contains(&ADDED_ACCOUNT),
            "stored copy missing while live is damaged: {ids:?}"
        );
        assert!(
            accounts.iter().all(|account| !account.is_active),
            "nothing can be compared against a damaged live file"
        );
        assert!(
            accounts
                .iter()
                .all(|account| account.id != ON_DISK_ACCOUNT_ID),
            "a damaged live file is not a live row: {ids:?}"
        );

        let (_accounts, live_error) = adapter
            .list_accounts_detailed()
            .expect("damage is reported, not a failed look");
        let error = live_error.expect("the caller must be told the live file is damaged");
        assert!(
            matches!(error, Error::ConfigRead { .. }),
            "expected ConfigRead, got {error:?}"
        );
        assert!(
            error.to_string().contains("auth.json"),
            "user must be told which file is damaged: {error}"
        );
        assert_no_fake("ConfigRead Display", &error.to_string());
        assert_no_fake("ConfigRead Debug", &format!("{error:?}"));
    }

    #[test]
    fn list_accounts_marks_only_the_first_matching_managed_copy_active() {
        let env = AddEnv::new();
        let live_auth = fs::read(env.live.path().join(".codex/auth.json")).expect("live auth");
        env.seed_managed("acct-a", &live_auth);
        env.seed_managed("acct-b", &live_auth);
        let before = env.digest();

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list");
        let a = accounts
            .iter()
            .find(|account| account.id == "acct-a")
            .expect("acct-a");
        let b = accounts
            .iter()
            .find(|account| account.id == "acct-b")
            .expect("acct-b");
        assert!(a.is_active, "first in sorted id order claims the live slot");
        assert!(
            !b.is_active,
            "a second copy of the same bytes is not also active"
        );
        assert!(
            accounts
                .iter()
                .all(|account| account.id != ON_DISK_ACCOUNT_ID),
            "the live row is omitted once a managed copy matches"
        );
        assert_eq!(before, env.digest());
    }

    fn assert_delete_error_is_clean(error: &Error) {
        assert_no_fake("delete_account Display", &error.to_string());
        assert_no_fake("delete_account Debug", &format!("{error:?}"));
    }

    #[test]
    fn delete_account_removes_an_incomplete_slot() {
        let env = AddEnv::new();
        env.seed_incomplete(ADDED_ACCOUNT);
        env.seed_managed(SIBLING_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();

        env.adapter(login_must_not_run)
            .delete_account(ADDED_ACCOUNT)
            .expect("delete incomplete");

        assert!(
            fs::symlink_metadata(env.managed_dir(ADDED_ACCOUNT)).is_err(),
            "abandoned directory must be gone after delete"
        );
        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list after delete");
        assert!(
            accounts.iter().all(|account| account.id != ADDED_ACCOUNT),
            "deleted incomplete slot must stop being listed"
        );
        assert!(
            accounts.iter().any(|account| account.id == SIBLING_ACCOUNT),
            "sibling account must still be listed"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn activate_account_rejects_an_incomplete_slot_without_touching_the_live_home() {
        let env = AddEnv::new();
        env.seed_incomplete(ADDED_ACCOUNT);
        let before = env.digest();

        let error = env
            .adapter(login_must_not_run)
            .with_tool_running(false)
            .activate_account(ADDED_ACCOUNT)
            .expect_err("incomplete slot cannot be activated");
        assert!(
            matches!(error, Error::UnknownAccount(ref id) if id == ADDED_ACCOUNT),
            "expected UnknownAccount, got {error:?}"
        );
        assert_eq!(before, env.digest());
        assert!(
            !env.data.path().join("backups").exists(),
            "incomplete slot must not write a backup"
        );
    }

    #[test]
    fn delete_account_removes_the_directory_and_stops_listing_it() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT, &managed_oauth_bytes());
        env.seed_managed(SIBLING_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();
        let sibling =
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling");

        env.adapter(login_must_not_run)
            .delete_account(ADDED_ACCOUNT)
            .expect("delete");

        assert!(
            fs::symlink_metadata(env.managed_dir(ADDED_ACCOUNT)).is_err(),
            "managed directory must be gone after delete"
        );
        assert_eq!(
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling after"),
            sibling,
            "deleting one account must not touch a sibling"
        );

        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list after delete");
        assert!(
            accounts.iter().all(|account| account.id != ADDED_ACCOUNT),
            "deleted account must stop being listed"
        );
        assert!(
            accounts.iter().any(|account| account.id == SIBLING_ACCOUNT),
            "sibling account must still be listed"
        );
        assert_eq!(
            before,
            env.digest(),
            "delete_account must not touch the live Codex home; before={} after={}",
            digest_brief(&before),
            digest_brief(&env.digest())
        );
    }

    #[test]
    fn delete_account_rejects_an_unknown_id_without_changing_anything() {
        let env = AddEnv::new();
        env.seed_managed(SIBLING_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();
        let sibling =
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling");

        let error = env
            .adapter(login_must_not_run)
            .delete_account("no-such-account")
            .expect_err("unknown account");
        assert!(
            matches!(error, Error::UnknownAccount(ref id) if id == "no-such-account"),
            "expected UnknownAccount, got {error:?}"
        );
        assert_delete_error_is_clean(&error);
        assert_eq!(
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling after"),
            sibling,
            "an unknown id must not touch a sibling managed account"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn delete_account_rejects_an_unsafe_id_without_touching_anything() {
        let env = AddEnv::new();
        env.seed_managed(SIBLING_ACCOUNT, &managed_oauth_bytes());
        let before = env.digest();
        let sibling =
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling");

        for unsafe_id in ["../etc", "acct/work", ""] {
            let error = env
                .adapter(login_must_not_run)
                .delete_account(unsafe_id)
                .expect_err("unsafe id");
            assert!(
                matches!(error, Error::ConfigWrite { .. }),
                "expected ConfigWrite for {unsafe_id:?}, got {error:?}"
            );
            assert!(
                error.to_string().contains("not a safe path component"),
                "user must be told the id is unsafe ({unsafe_id:?}): {error}"
            );
            assert_delete_error_is_clean(&error);
        }

        assert_eq!(
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join("auth.json")).expect("sibling after"),
            sibling,
            "an unsafe id must not touch a sibling managed account"
        );
        assert!(
            !env.data.path().join("accounts/etc").exists(),
            "../etc must not escape into a sibling of the provider tree"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn delete_account_does_not_sign_out_when_the_deleted_account_is_active() {
        let env = AddEnv::new();
        let live_auth = fs::read(env.live.path().join(".codex/auth.json")).expect("live auth");
        env.seed_managed(TARGET_ACCOUNT, &live_auth);
        let before = env.digest();

        env.adapter(login_must_not_run)
            .delete_account(TARGET_ACCOUNT)
            .expect("delete active stored copy");

        assert_eq!(
            before,
            env.digest(),
            "deleting the active stored copy must not sign the tool out; before={} after={}",
            digest_brief(&before),
            digest_brief(&env.digest())
        );
        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list after delete");
        assert!(
            accounts.iter().all(|account| account.id != TARGET_ACCOUNT),
            "deleted stored copy must stop being listed"
        );
        let live = accounts
            .iter()
            .find(|account| account.id == ON_DISK_ACCOUNT_ID)
            .expect("live row must remain after its stored copy is forgotten");
        assert!(
            live.is_active,
            "the live home still holds the identity; deleting the copy is not a sign-out"
        );
    }

    #[cfg(unix)]
    #[test]
    fn delete_account_refuses_a_symlink_at_the_managed_path() {
        let env = AddEnv::new();
        let dir = env.managed_dir(ADDED_ACCOUNT);
        fs::create_dir_all(dir.parent().expect("parent")).expect("provider tree");
        // Point at the live home so following the link would destroy it.
        std::os::unix::fs::symlink(env.live.path().join(".codex"), &dir).expect("symlink");
        let before = env.digest();

        let error = env
            .adapter(login_must_not_run)
            .delete_account(ADDED_ACCOUNT)
            .expect_err("symlink");
        assert!(
            error
                .to_string()
                .contains("not a managed account directory"),
            "a symlink is not a directory we created: {error}"
        );
        assert_delete_error_is_clean(&error);
        let metadata = fs::symlink_metadata(&dir).expect("symlink remains");
        assert!(
            metadata.file_type().is_symlink(),
            "refusing the slot must not remove a symlink we did not create"
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn delete_account_refuses_a_file_at_the_managed_path() {
        let env = AddEnv::new();
        let dir = env.managed_dir(ADDED_ACCOUNT);
        fs::create_dir_all(dir.parent().expect("parent")).expect("provider tree");
        fs::write(&dir, b"not a directory").expect("file at slot");
        let before = env.digest();

        let error = env
            .adapter(login_must_not_run)
            .delete_account(ADDED_ACCOUNT)
            .expect_err("file at slot");
        assert!(
            error
                .to_string()
                .contains("not a managed account directory"),
            "a file at the slot is not a directory we created: {error}"
        );
        assert_delete_error_is_clean(&error);
        assert_eq!(
            fs::read(&dir).expect("file after"),
            b"not a directory",
            "refusing the slot must not remove a file we did not create"
        );
        assert_eq!(before, env.digest());
    }
}
