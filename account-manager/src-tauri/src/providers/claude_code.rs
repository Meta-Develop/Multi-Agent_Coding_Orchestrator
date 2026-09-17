//! Claude Code (Anthropic) adapter.
//!
//! Observed layout on Linux, Claude Code 2.1.212:
//!
//! - `~/.claude/.credentials.json` [verified-local] — OAuth material under a
//!   `claudeAiOauth` object with the key names `accessToken`, `refreshToken`,
//!   `expiresAt`, `refreshTokenExpiresAt`, `scopes`, `subscriptionType`,
//!   `rateLimitTier`, plus a sibling `organizationUuid`.
//! - `~/.claude.json` [verified-local] — global client state: `oauthAccount`,
//!   `mcpServers`, `projects`, caches, and onboarding flags. Large and rewritten
//!   frequently by the tool.
//! - `~/.claude/settings.json` [verified-local] — user settings.
//! - `~/.claude/` also holds `projects/`, `history.jsonl`, `sessions/`,
//!   `shell-snapshots/`, `plugins/`, and caches [verified-local]. These are
//!   session data, not credentials, and must not be moved by a switch.
//!
//! Identity is split across those first two files (`docs/research/claude-code.md`
//! §5). Isolated add sets `CLAUDE_CONFIG_DIR` and
//! `CLAUDE_SECURESTORAGE_CONFIG_DIR` to the same new managed directory and
//! runs `claude auth login`. A switch copies the stored `claudeAiOauth` and
//! `oauthAccount` objects into the live files and preserves every other
//! top-level member. Maturity stays Experimental: a copied token is not a
//! verified-local vendor-acceptance claim (NFR-8).
//!
//! Which file supplies each `Account` field:
//!
//! - Existence of an account — `.credentials.json`. A missing credentials file
//!   is "no account configured", even when `~/.claude.json` is present (leftover
//!   client state is not a login).
//! - `auth_kind` — presence of a `claudeAiOauth` *object* in `.credentials.json`
//!   [verified-local]. `ANTHROPIC_API_KEY` is an env-only path [verified-docs]
//!   and is never read (NFR-1).
//! - `expires_at` — `claudeAiOauth.expiresAt` when it is a number, recorded as
//!   epoch milliseconds [verified-local]. `refreshTokenExpiresAt` is the refresh
//!   lifetime, not the access expiry, and is left alone. `rateLimitTier` is a
//!   tier name, not an expiry (NFR-8).
//! - `masked_identity` — `organizationUuid` from `.credentials.json` when it is
//!   a string [verified-local], after [`mask_identity`]. It is the only
//!   identity-shaped field whose key and location are in the recorded schema.
//! - Nothing is taken from `oauthAccount` internals for IPC. Listing
//!   tolerates a present-but-unparsable live identity file the same way it
//!   tolerates a missing one. A damaged live credentials file is not treated
//!   as a login; stored copies still list.

#[path = "claude_switch.rs"]
mod claude_switch;

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Map, Value};

use super::{
    account_id_is_safe, binary_on_path, home_dir, managed_account_dir, process_named_is_running,
    ProviderAdapter,
};
use crate::backup::BackupStore;
use crate::error::{Error, Result};
use crate::fsx;
use crate::model::{
    Account, AuthKind, InstallState, Maturity, ProviderCapability, ProviderDescriptor,
};
use crate::paths;
use claude_switch::{ACCOUNT_KEY, OAUTH_KEY};

#[cfg(test)]
use claude_switch::SwitchFault;

/// Application-assigned id for the single on-disk Claude Code identity.
///
/// Claude Code stores one login split across two files [verified-local], so
/// this names that slot rather than echoing `organizationUuid` or anything
/// inside `oauthAccount`. SPEC §4 assigns `Account.id` here so a vendor
/// changing its identifier scheme cannot orphan local state. The same fixture
/// therefore always produces this id.
const ON_DISK_ACCOUNT_ID: &str = "claude-code-on-disk";

#[derive(Debug, Default)]
pub struct ClaudeCodeAdapter {
    /// Injected home directory. `None` means the real user home, which is
    /// what production uses; tests pass a `tempfile::TempDir` path so no
    /// test can read a developer's real credentials (`docs/TESTING.md` §4).
    home: Option<PathBuf>,
    /// Injected application data directory (per-account homes and backups).
    data_dir: Option<PathBuf>,
    /// Override for the running-tool check.
    ///
    /// `None` means inspect the host process table, except when `home` is
    /// injected. `Some(Ok(b))` forces the answer. `Some(Err(()))` forces
    /// the cannot-tell path, which must refuse.
    injected_tool_running: Option<std::result::Result<bool, ()>>,
    /// Override for `claude auth login`. `None` means spawn the real CLI,
    /// except when `home` is injected.
    login_runner: Option<fn(&Path) -> std::io::Result<i32>>,
    #[cfg(test)]
    fault: SwitchFault,
}

impl ClaudeCodeAdapter {
    /// Root this adapter at `home` instead of the real user home.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
            ..Self::default()
        }
    }

    /// Root per-account homes and backups at `data_dir`.
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Override the running-tool check.
    pub fn with_tool_running(mut self, running: bool) -> Self {
        self.injected_tool_running = Some(Ok(running));
        self
    }

    /// Drive `claude auth login` with a stub instead of the real CLI.
    pub fn with_login_runner(mut self, runner: fn(&Path) -> std::io::Result<i32>) -> Self {
        self.login_runner = Some(runner);
        self
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

    fn config_read(&self, reason: impl Into<String>) -> Error {
        claude_switch::config_read(self.id(), reason)
    }

    fn config_write(&self, reason: impl Into<String>) -> Error {
        claude_switch::config_write(self.id(), reason)
    }

    /// Read a JSON object if the file exists.
    ///
    /// Missing → `Ok(None)`. Present but unreadable, not JSON, or not an
    /// object → `Error::ConfigRead`. Reason strings name the path and the
    /// kind of failure only. The serde error text can echo a token from the
    /// file; never include it (NFR-1).
    fn read_optional_object(&self, path: &Path) -> Result<Option<Map<String, Value>>> {
        claude_switch::read_optional_object(path, self.id())
    }

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

    fn recover_crashed_switch(&self) -> Result<()> {
        let Some(data_dir) = self.resolved_data_dir() else {
            return Ok(());
        };
        let journal = claude_switch::journal_path(&data_dir);
        match fs::symlink_metadata(&journal) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(self.config_read(format!("{} ({})", journal.display(), error.kind())));
            }
            Ok(_) => {}
        }
        let store = self.backup_store()?;
        claude_switch::recover(&store, &journal, self.id())
    }

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
        process_named_is_running("claude")
    }
}

/// Mask a vendor identifier for display.
///
/// Keeps the last four characters and replaces the rest with a fixed `****`
/// prefix (e.g. `****ab12`). Returns `None` when the value is absent-as-empty
/// or too short to mask without leaving the original essentially intact.
///
/// The only identity-shaped field this adapter will pass in is
/// `organizationUuid` from `.credentials.json` [verified-local]. Callers must
/// never pass a token, a key, or a field whose shape is `[unknown]`.
fn mask_identity(raw: &str) -> Option<String> {
    const VISIBLE: usize = 4;
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= VISIBLE {
        return None;
    }
    let tail: String = chars[chars.len() - VISIBLE..].iter().collect();
    Some(format!("****{tail}"))
}

/// Convert epoch milliseconds to RFC 3339. Returns `None` on overflow or
/// if the instant cannot be formatted; the caller then leaves `expires_at`
/// unset rather than inventing a timestamp (NFR-8).
fn rfc3339_from_epoch_millis(millis: i64) -> Option<String> {
    let seconds = millis.div_euclid(1_000);
    let nanos = u32::try_from(millis.rem_euclid(1_000).saturating_mul(1_000_000)).ok()?;
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .replace_nanosecond(nanos)
        .ok()?
        .format(&time::format_description::well_known::Rfc3339)
        .ok()
}

/// Build an `Account` from a parsed `.credentials.json` object.
///
/// Classification inspects structure only (NFR-1 / threat T2):
/// - `OAuth` when `claudeAiOauth` is an object [verified-local]
/// - otherwise `AuthKind::Unknown`
///
/// Token values, `subscriptionType`, `rateLimitTier`, and `oauthAccount`
/// internals are never copied onto the `Account`.
fn account_from_credentials(
    provider_id: &str,
    account_id: &str,
    label: &str,
    credentials: &Map<String, Value>,
    is_active: bool,
    is_stored: bool,
) -> Account {
    let oauth = credentials.get(OAUTH_KEY).and_then(Value::as_object);
    let auth_kind = if oauth.is_some() {
        AuthKind::OAuth
    } else {
        AuthKind::Unknown
    };
    let expires_at = oauth
        .and_then(|oauth| oauth.get("expiresAt"))
        .and_then(Value::as_i64)
        .and_then(rfc3339_from_epoch_millis);
    let masked_identity = credentials
        .get("organizationUuid")
        .and_then(Value::as_str)
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
        expires_at,
    }
}

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

enum ManagedSlot {
    Complete {
        account_id: String,
        pair: claude_switch::StoredPair,
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

enum LiveSlot {
    Absent,
    Present {
        credentials: Map<String, Value>,
        identity: Option<Map<String, Value>>,
        account: Account,
    },
    Damaged(Error),
}

fn write_reason(error: Error) -> String {
    match error {
        Error::ConfigWrite { reason, .. } | Error::ConfigRead { reason, .. } => reason,
        other => other.to_string(),
    }
}

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

impl ClaudeCodeAdapter {
    fn live_slot(&self) -> LiveSlot {
        let Some(home) = self.resolved_home() else {
            return LiveSlot::Absent;
        };
        let paths = claude_switch::live_paths(&home);
        let credentials = match self.read_optional_object(&paths.credentials) {
            Ok(Some(object)) => object,
            Ok(None) => return LiveSlot::Absent,
            Err(error) => return LiveSlot::Damaged(error),
        };
        if let Some(oauth) = credentials.get(OAUTH_KEY) {
            if !oauth.is_object() {
                return LiveSlot::Damaged(self.config_read(format!(
                    "{} {OAUTH_KEY} is not an object",
                    paths.credentials.display()
                )));
            }
        }
        let identity = match self.read_optional_object(&paths.identity) {
            Ok(value) => value,
            Err(Error::ConfigRead { .. }) => None,
            Err(error) => return LiveSlot::Damaged(error),
        };
        LiveSlot::Present {
            credentials: credentials.clone(),
            identity: identity.clone(),
            account: account_from_credentials(
                self.id(),
                ON_DISK_ACCOUNT_ID,
                "Claude Code",
                &credentials,
                true,
                false,
            ),
        }
    }

    /// Enumerate live and stored accounts. A damaged live document is
    /// reported alongside the stored copies rather than hiding them.
    pub fn list_accounts_detailed(&self) -> Result<(Vec<Account>, Option<Error>)> {
        self.recover_crashed_switch()?;
        let (live_credentials, live_identity, live_account, live_error) = match self.live_slot() {
            LiveSlot::Absent => (None, None, None, None),
            LiveSlot::Present {
                credentials,
                identity,
                account,
            } => (Some(credentials), identity, Some(account), None),
            LiveSlot::Damaged(error) => (None, None, None, Some(error)),
        };
        let mut managed = self.managed_slots(live_credentials.as_ref(), live_identity.as_ref())?;
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

    fn managed_slots(
        &self,
        live_credentials: Option<&Map<String, Value>>,
        live_identity: Option<&Map<String, Value>>,
    ) -> Result<Vec<Account>> {
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
            let file_type = entry.file_type().map_err(|error| {
                self.config_read(format!("{} ({})", root.display(), error.kind()))
            })?;
            if !file_type.is_dir() {
                continue;
            }
            let dir = managed_account_dir(&data_dir, self.id(), account_id);
            match claude_switch::load_stored_pair(&dir, self.id()) {
                Ok(Some(pair)) => slots.push(ManagedSlot::Complete {
                    account_id: account_id.to_string(),
                    pair,
                }),
                Ok(None) | Err(_) => slots.push(ManagedSlot::Incomplete {
                    account_id: account_id.to_string(),
                }),
            }
        }
        slots.sort_by(|left, right| left.account_id().cmp(right.account_id()));

        let mut claimed_active = false;
        let mut accounts = Vec::with_capacity(slots.len());
        for slot in slots {
            match slot {
                ManagedSlot::Incomplete { account_id } => {
                    accounts.push(incomplete_account(self.id(), &account_id));
                }
                ManagedSlot::Complete { account_id, pair } => {
                    let is_active = live_credentials.is_some_and(|credentials| {
                        claude_switch::live_matches_stored(credentials, live_identity, &pair)
                    }) && !claimed_active;
                    if is_active {
                        claimed_active = true;
                    }
                    accounts.push(account_from_credentials(
                        self.id(),
                        &account_id,
                        &account_id,
                        &pair.credentials,
                        is_active,
                        true,
                    ));
                }
            }
        }
        Ok(accounts)
    }

    fn prepare_managed_dir(&self, dir: &Path) -> Result<()> {
        match fs::symlink_metadata(dir) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(self.config_write(format!(
                        "{} already exists; refusing to overwrite a managed account directory",
                        dir.display()
                    )));
                }
                if self.slot_holds_identity(dir) {
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

    fn slot_holds_identity(&self, dir: &Path) -> bool {
        let paths = claude_switch::stored_paths(dir);
        for path in [paths.credentials, paths.identity] {
            match fs::symlink_metadata(path) {
                Ok(_) => return true,
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(_) => return true,
            }
        }
        false
    }

    fn run_vendor_login(&self, managed_dir: &Path) -> Result<()> {
        let code = match self.login_runner {
            Some(runner) => runner(managed_dir).map_err(|error| {
                self.config_write(format!(
                    "could not start `claude auth login` with CLAUDE_CONFIG_DIR at {} ({})",
                    managed_dir.display(),
                    error.kind()
                ))
            })?,
            None if self.home.is_some() => {
                return Err(self.config_write(
                    "refusing to spawn `claude auth login` against an injected home",
                ));
            }
            None => self.spawn_claude_login(managed_dir)?,
        };
        if code != 0 {
            return Err(self.config_write(format!(
                "`claude auth login` exited with status {code}; CLAUDE_CONFIG_DIR is {}",
                managed_dir.display()
            )));
        }
        Ok(())
    }

    fn spawn_claude_login(&self, managed_dir: &Path) -> Result<i32> {
        let status = Command::new("claude")
            .args(["auth", "login"])
            .env("CLAUDE_CONFIG_DIR", managed_dir)
            .env("CLAUDE_SECURESTORAGE_CONFIG_DIR", managed_dir)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| {
                self.config_write(format!(
                    "could not start `claude auth login` with CLAUDE_CONFIG_DIR at {} ({})",
                    managed_dir.display(),
                    error.kind()
                ))
            })?;
        match status.code() {
            Some(code) => Ok(code),
            None => Err(self.config_write(format!(
                "`claude auth login` was terminated by a signal; CLAUDE_CONFIG_DIR is {}",
                managed_dir.display()
            ))),
        }
    }

    fn require_managed_identity(&self, dir: &Path) -> Result<()> {
        let paths = claude_switch::stored_paths(dir);
        for path in [&paths.credentials, &paths.identity] {
            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    return Err(self.config_write(format!(
                        "`claude auth login` finished but {} was not created",
                        path.display()
                    )));
                }
                Err(error) => {
                    return Err(self.config_write(format!(
                        "{} ({})",
                        path.display(),
                        error.kind()
                    )));
                }
            };
            if !metadata.is_file() {
                return Err(self.config_write(format!("{} is not a regular file", path.display())));
            }
        }
        claude_switch::load_stored_pair(dir, self.id())?.ok_or_else(|| {
            self.config_write(format!(
                "`claude auth login` finished but {} was not a complete stored pair",
                dir.display()
            ))
        })?;
        Ok(())
    }

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

impl ProviderAdapter for ClaudeCodeAdapter {
    fn id(&self) -> &'static str {
        "claude-code"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "Claude Code".to_string(),
            vendor: "Anthropic".to_string(),
            auth_kinds: vec![AuthKind::OAuth, AuthKind::ApiKey],
            // Switching copies vendor-issued objects into the live home.
            // That does not prove the copied credential works against the
            // vendor, so `Supported` would overstate this adapter (NFR-8).
            maturity: Maturity::Experimental,
            install_state: self.detect(),
            capabilities: vec![
                ProviderCapability::AddAccount,
                ProviderCapability::SwitchAccount,
                ProviderCapability::DeleteAccount,
            ],
        }
    }

    fn config_paths(&self) -> Vec<PathBuf> {
        let Some(home) = self.resolved_home() else {
            return Vec::new();
        };
        let claude_dir = home.join(".claude");
        vec![
            home.join(".claude.json"),
            claude_dir.join(".credentials.json"),
            claude_dir.join("settings.json"),
        ]
    }

    fn detect(&self) -> InstallState {
        let has_config = self
            .resolved_home()
            .map(|home| home.join(".claude").is_dir())
            .unwrap_or(false);
        if binary_on_path("claude") || has_config {
            InstallState::Installed
        } else {
            InstallState::NotInstalled
        }
    }

    fn list_accounts(&self) -> Result<Vec<Account>> {
        self.list_accounts_detailed()
            .map(|(accounts, _live_error)| accounts)
    }

    fn quota(&self) -> Result<Vec<crate::model::QuotaSnapshot>> {
        // `rateLimitTier` is a tier, and cached utilization is not a
        // dependable signal (`docs/research/claude-code.md` section 6).
        Ok(Vec::new())
    }

    fn plan_label(&self) -> Result<Option<String>> {
        let Some(home) = self.resolved_home() else {
            return Ok(None);
        };
        let identity_path = home.join(".claude.json");
        let Some(identity) = self.read_optional_object(&identity_path)? else {
            return Ok(None);
        };
        let Some(oauth_account) = identity.get("oauthAccount") else {
            return Ok(None);
        };
        if oauth_account.is_null() {
            return Ok(None);
        }
        let Some(oauth_account) = oauth_account.as_object() else {
            return Err(self.config_read(format!(
                "{} oauthAccount is not an object",
                identity_path.display()
            )));
        };
        let plan_label = match oauth_account.get("billingType") {
            None | Some(Value::Null) => None,
            Some(Value::String(label)) if !label.trim().is_empty() => {
                Some(label.trim().to_string())
            }
            Some(Value::String(_)) => {
                return Err(self.config_read(format!(
                    "{} oauthAccount.billingType is empty",
                    identity_path.display()
                )));
            }
            Some(_) => {
                return Err(self.config_read(format!(
                    "{} oauthAccount.billingType is not a string",
                    identity_path.display()
                )));
            }
        };
        Ok(plan_label)
    }

    fn activate_account(&self, account_id: &str) -> Result<()> {
        self.recover_crashed_switch()?;

        match self.tool_is_running() {
            Ok(true) => {
                return Err(self.config_write(
                    "Claude Code appears to be running (process name `claude`). \
                     Close Claude Code before switching. Replacing the live \
                     identity pair while the tool is running can leave the \
                     two files inconsistent",
                ));
            }
            Ok(false) => {}
            Err(_) => {
                return Err(self.config_write(
                    "could not determine whether Claude Code is running; \
                     refusing to replace the live identity pair. Close \
                     Claude Code, then retry",
                ));
            }
        }

        if !account_id_is_safe(account_id) {
            return Err(Error::UnknownAccount(account_id.to_string()));
        }
        let Some(data_dir) = self.resolved_data_dir() else {
            return Err(self.config_write(
                "application data directory is unavailable; cannot locate the account",
            ));
        };
        let dir = managed_account_dir(&data_dir, self.id(), account_id);
        let stored = match claude_switch::load_stored_pair(&dir, self.id())? {
            Some(pair) => pair,
            None => return Err(Error::UnknownAccount(account_id.to_string())),
        };
        let Some(home) = self.resolved_home() else {
            return Err(self.config_write("home directory is unavailable"));
        };
        let paths = claude_switch::live_paths(&home);
        let live = claude_switch::load_live_for_switch(&paths, self.id())?;
        let next_credentials =
            claude_switch::apply_member(&live.credentials, OAUTH_KEY, stored.oauth);
        let next_identity =
            claude_switch::apply_member(&live.identity, ACCOUNT_KEY, stored.account);

        let store = self.backup_store()?;
        let backup = store.snapshot(self.id(), &self.config_paths())?;
        let journal = claude_switch::journal_path(&data_dir);
        if let Err(error) = claude_switch::write_journal(&journal, &backup, self.id()) {
            let _ = claude_switch::clear_journal(&journal, self.id());
            return Err(error);
        }

        let fail = |reason: String| {
            Err(claude_switch::abort_switch(
                &store,
                &backup,
                &journal,
                self.id(),
                reason,
            ))
        };

        #[cfg(test)]
        if self.fault == SwitchFault::AfterSnapshot {
            return fail("injected failure after snapshot".to_string());
        }

        if let Err(error) =
            claude_switch::write_json_object(&paths.credentials, &next_credentials, self.id())
        {
            return fail(write_reason(error));
        }

        #[cfg(test)]
        if self.fault == SwitchFault::AfterFirstWrite {
            return fail("injected failure after first write".to_string());
        }

        if let Err(error) =
            claude_switch::write_json_object(&paths.identity, &next_identity, self.id())
        {
            return fail(write_reason(error));
        }

        #[cfg(test)]
        if self.fault == SwitchFault::AfterWrite {
            return fail("injected failure after write".to_string());
        }

        if let Err(error) =
            claude_switch::verify_json_object(&paths.credentials, &next_credentials, self.id())
        {
            return fail(write_reason(error));
        }
        if let Err(error) =
            claude_switch::verify_json_object(&paths.identity, &next_identity, self.id())
        {
            return fail(write_reason(error));
        }
        if let Err(error) = claude_switch::clear_journal(&journal, self.id()) {
            return fail(write_reason(error));
        }
        Ok(())
    }

    fn add_account(&self, account_id: &str) -> Result<()> {
        if !account_id_is_safe(account_id) {
            return Err(self.config_write(
                "account id is not a safe path component; refusing to create a managed directory",
            ));
        }
        if account_id == ON_DISK_ACCOUNT_ID {
            return Err(self.config_write(format!(
                "`{account_id}` is reserved for the live on-disk Claude Code identity; \
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
        let outcome = self
            .run_vendor_login(&dir)
            .and_then(|()| self.require_managed_identity(&dir));
        if let Err(error) = outcome {
            return Err(self.cleanup_failed_add(&dir, error));
        }
        Ok(())
    }

    fn delete_account(&self, account_id: &str) -> Result<()> {
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
}

#[cfg(test)]
mod tests {
    use super::claude_switch::{self, SwitchFault};
    use super::ProviderAdapter;
    use super::*;
    use crate::backup::BackupStore;
    use crate::model::ProviderCapability;
    use std::fs;
    use std::path::Path;

    const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/claude-code");
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

    fn write_credentials(home: &Path, body: &str) {
        let dir = home.join(".claude");
        fs::create_dir_all(&dir).expect("mkdir .claude");
        fs::write(dir.join(".credentials.json"), body).expect("write .credentials.json");
    }

    fn write_identity(home: &Path, body: &str) {
        fs::write(home.join(".claude.json"), body).expect("write .claude.json");
    }

    #[test]
    fn with_home_resolves_config_paths_under_the_injected_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = ClaudeCodeAdapter::with_home(dir.path());
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
    fn rfc3339_from_epoch_millis_formats_a_known_instant() {
        assert_eq!(
            rfc3339_from_epoch_millis(1_893_456_000_000).as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
        assert_eq!(rfc3339_from_epoch_millis(i64::MAX), None);
    }

    #[test]
    fn list_accounts_matches_the_full_fixture_expectation() {
        let home = staged_home("home");
        let adapter = ClaudeCodeAdapter::with_home(home.path());
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
        assert_eq!(
            accounts[0].expires_at.as_deref(),
            Some("2030-01-01T00:00:00Z")
        );
        assert_eq!(accounts[0].id, ON_DISK_ACCOUNT_ID);

        let again = adapter.list_accounts().expect("second list");
        assert_eq!(again[0].id, accounts[0].id);
    }

    #[test]
    fn list_accounts_credentials_only_still_returns_the_account() {
        let home = staged_home("credentials-only");
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let accounts = adapter.list_accounts().expect("list");

        // Facts come from `.credentials.json`. A missing identity file is
        // not an error and does not drop the login.
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, ON_DISK_ACCOUNT_ID);
        assert_eq!(accounts[0].auth_kind, AuthKind::OAuth);
        assert_eq!(accounts[0].masked_identity.as_deref(), Some("****0001"));
        assert!(accounts[0].is_active);
        assert_no_fake(
            "credentials-only list_accounts json",
            &serde_json::to_string(&accounts).expect("json"),
        );
    }

    #[test]
    fn list_accounts_identity_only_returns_empty() {
        let home = staged_home("identity-only");
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let accounts = adapter
            .list_accounts()
            .expect("leftover ~/.claude.json is not an account");
        assert!(accounts.is_empty());
    }

    #[test]
    fn list_accounts_returns_empty_when_both_files_are_missing() {
        let home = staged_home("missing-files");
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let accounts = adapter
            .list_accounts()
            .expect("missing files are not an error");
        assert!(accounts.is_empty());
    }

    #[test]
    fn list_accounts_does_not_guess_malformed_credentials() {
        // Written here rather than stored as a `.json` fixture: Prettier parses
        // tracked `*.json` and refuses this intentionally invalid document.
        let home = tempfile::tempdir().expect("tempdir");
        write_credentials(
            home.path(),
            r#"{this is not json, "accessToken": "FAKE-malformed-token-0001""#,
        );
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let (accounts, live_error) = adapter
            .list_accounts_detailed()
            .expect("stored copies must still list when live credentials are damaged");
        assert!(accounts.is_empty());
        let error = live_error.expect("damaged live credentials must be reported");
        assert!(
            matches!(error, Error::ConfigRead { .. }),
            "expected ConfigRead, got {error:?}"
        );
        assert_no_fake("ConfigRead Display", &error.to_string());
        assert_no_fake("ConfigRead Debug", &format!("{error:?}"));
    }

    #[test]
    fn list_accounts_does_not_guess_malformed_credentials_even_with_identity() {
        // The unused identity file being intact does not license guessing at
        // the credentials document. Malformed bytes written here, not stored
        // as a `.json` fixture (Prettier).
        let home = staged_home("unparsable-credentials");
        write_credentials(
            home.path(),
            r#"{this is not json, "accessToken": "FAKE-malformed-token-0001""#,
        );
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let (accounts, live_error) = adapter
            .list_accounts_detailed()
            .expect("unparsable live credentials must not hide the look");
        assert!(accounts.is_empty());
        let error = live_error.expect("damaged live credentials must be reported");
        assert!(
            matches!(error, Error::ConfigRead { .. }),
            "expected ConfigRead, got {error:?}"
        );
        assert_no_fake("credentials ConfigRead Display", &error.to_string());
        assert_no_fake("credentials ConfigRead Debug", &format!("{error:?}"));
    }

    #[test]
    fn list_accounts_lists_when_identity_file_is_unparsable() {
        // Malformed bytes are written here, not stored as a `.json` fixture:
        // Prettier parses tracked `*.json` and refuses this document.
        let home = staged_home("unparsable-identity");
        write_identity(
            home.path(),
            r#"{this is not json, "userID": "FAKE-user-0001""#,
        );
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let accounts = adapter
            .list_accounts()
            .expect("unparsable ~/.claude.json must not hide a valid login");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, ON_DISK_ACCOUNT_ID);
        assert_eq!(accounts[0].auth_kind, AuthKind::OAuth);
        assert_eq!(accounts[0].masked_identity.as_deref(), Some("****0001"));
        assert!(accounts[0].is_active);
        assert_no_fake(
            "unparsable-identity list_accounts json",
            &serde_json::to_string(&accounts).expect("json"),
        );
    }

    #[test]
    fn list_accounts_unparsable_identity_only_returns_empty() {
        // Leftover client state is not a login, even when that leftover is
        // damaged. Written here rather than stored as a `.json` fixture.
        let home = staged_home("missing-files");
        write_identity(
            home.path(),
            r#"{this is not json, "userID": "FAKE-user-0001""#,
        );
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let accounts = adapter
            .list_accounts()
            .expect("damaged leftover ~/.claude.json is still not an account");
        assert!(accounts.is_empty());
    }

    #[test]
    fn list_accounts_does_not_treat_non_object_claude_ai_oauth_as_a_login() {
        let home = tempfile::tempdir().expect("tempdir");
        write_credentials(
            home.path(),
            r#"{"claudeAiOauth":"FAKE-not-an-object","organizationUuid":"FAKE-organization-uuid-0001"}"#,
        );
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let (accounts, live_error) = adapter
            .list_accounts_detailed()
            .expect("non-object oauth is not a login");
        assert!(accounts.is_empty());
        let error = live_error.expect("non-object oauth must be reported");
        assert!(
            matches!(error, Error::ConfigRead { .. }),
            "expected ConfigRead, got {error:?}"
        );
        assert_no_fake("non-object oauth ConfigRead", &format!("{error} {error:?}"));
    }

    #[test]
    fn list_accounts_never_reads_oauth_account_internals() {
        // `oauthAccount` internals are [unknown] (research §9). A nested
        // email in the identity file must not become `masked_identity`.
        let home = tempfile::tempdir().expect("tempdir");
        write_credentials(
            home.path(),
            r#"{"claudeAiOauth":{"expiresAt":1893456000000},"organizationUuid":"FAKE-organization-uuid-0001"}"#,
        );
        write_identity(
            home.path(),
            r#"{"oauthAccount":{"email":"FAKE-user-0001@example.invalid"},"userID":"FAKE-user-0001"}"#,
        );
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let accounts = adapter.list_accounts().expect("list");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].masked_identity.as_deref(), Some("****0001"));
        let json = serde_json::to_string(&accounts).expect("json");
        assert!(
            !json.contains('@'),
            "oauthAccount.email leaked into the account: {json}"
        );
        assert_no_fake("oauthAccount internals", &json);
    }

    #[test]
    fn list_accounts_never_returns_fixture_secret_material() {
        let home = staged_home("home");
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let accounts = adapter.list_accounts().expect("list");

        let credentials = fs::read_to_string(home.path().join(".claude/.credentials.json"))
            .expect(".credentials.json");
        assert!(
            credentials.contains(FAKE_PREFIX),
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
            if let Some(expires) = &account.expires_at {
                assert_no_fake("account.expires_at", expires);
            }
        }
    }

    #[test]
    fn quota_is_empty_even_when_rate_limit_tier_is_present() {
        let home = staged_home("home");
        let adapter = ClaudeCodeAdapter::with_home(home.path());
        let snapshots = adapter.quota().expect("quota");
        assert!(
            snapshots.is_empty(),
            "rateLimitTier must not be invented into a QuotaSnapshot: {snapshots:?}"
        );
    }

    #[test]
    fn quota_reads_plan_only_from_non_credential_client_state() {
        let home = tempfile::tempdir().expect("tempdir");
        write_credentials(home.path(), "{not valid credential JSON");
        write_identity(home.path(), r#"{"oauthAccount":{"billingType":"pro"}}"#);
        let plan = ClaudeCodeAdapter::with_home(home.path())
            .plan_label()
            .expect("plan lookup must not read .credentials.json");
        assert_eq!(plan.as_deref(), Some("pro"));
    }

    #[test]
    fn quota_rejects_malformed_plan_state_without_echoing_it() {
        let home = tempfile::tempdir().expect("tempdir");
        write_identity(
            home.path(),
            r#"{"oauthAccount":{"billingType":{"value":"FAKE-secret"}}}"#,
        );
        let error = ClaudeCodeAdapter::with_home(home.path())
            .plan_label()
            .expect_err("malformed plan state must fail");
        assert!(matches!(error, Error::ConfigRead { .. }));
        assert_no_fake("quota ConfigRead", &format!("{error} {error:?}"));
    }

    #[test]
    fn descriptor_stays_experimental_after_switch_is_implemented() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = ClaudeCodeAdapter::with_home(dir.path());
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
                adapter.activate_account("claude-code-on-disk"),
                Err(Error::NotImplemented(_))
            ),
            "activate_account is implemented; NotImplemented would be a lie"
        );
    }

    const TARGET_ACCOUNT: &str = "acct-work";
    const ADDED_ACCOUNT: &str = "acct-new";
    const SIBLING_ACCOUNT: &str = "acct-keep";
    const LOGIN_SPAWN_OUTPUT: &str = "FAKE-subprocess-output-must-never-appear";

    fn managed_oauth_dir() -> std::path::PathBuf {
        Path::new(FIXTURE_ROOT).join("managed-oauth")
    }

    fn copy_managed_oauth(dir: &Path) {
        let src = managed_oauth_dir();
        fs::create_dir_all(dir).expect("managed dir");
        fs::copy(src.join(".credentials.json"), dir.join(".credentials.json"))
            .expect("copy credentials");
        fs::copy(src.join(".claude.json"), dir.join(".claude.json")).expect("copy identity");
    }

    fn login_writes_managed_oauth(dir: &Path) -> std::io::Result<i32> {
        copy_managed_oauth(dir);
        Ok(0)
    }

    fn login_exits_nonzero(dir: &Path) -> std::io::Result<i32> {
        fs::write(dir.join("partial"), b"incomplete")?;
        Ok(1)
    }

    fn login_ok_without_identity(dir: &Path) -> std::io::Result<i32> {
        fs::write(dir.join("unrelated.txt"), b"no identity pair")?;
        Ok(0)
    }

    fn login_fails_to_start(_dir: &Path) -> std::io::Result<i32> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            LOGIN_SPAWN_OUTPUT,
        ))
    }

    fn login_must_not_run(_dir: &Path) -> std::io::Result<i32> {
        panic!("claude auth login must not run");
    }

    fn login_records_env(dir: &Path) -> std::io::Result<i32> {
        fs::write(dir.join("login-dir.txt"), dir.to_string_lossy().as_bytes())?;
        copy_managed_oauth(dir);
        Ok(0)
    }

    struct SwitchEnv {
        live: tempfile::TempDir,
        data: tempfile::TempDir,
    }

    impl SwitchEnv {
        fn new() -> Self {
            let live = staged_home("switch-live");
            let data = tempfile::tempdir().expect("data dir");
            copy_managed_oauth(
                &data
                    .path()
                    .join("accounts/claude-code")
                    .join(TARGET_ACCOUNT),
            );
            Self { live, data }
        }

        fn adapter(&self) -> ClaudeCodeAdapter {
            ClaudeCodeAdapter::with_home(self.live.path())
                .with_data_dir(self.data.path())
                .with_tool_running(false)
        }

        fn backups(&self) -> BackupStore {
            BackupStore::new(self.data.path().join("backups"))
        }

        fn digest(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
            digest_claude(self.live.path())
        }

        fn live_objects(&self) -> (Map<String, Value>, Map<String, Value>) {
            let paths = claude_switch::live_paths(self.live.path());
            let credentials = ClaudeCodeAdapter::with_home(self.live.path())
                .read_optional_object(&paths.credentials)
                .expect("credentials")
                .expect("credentials present");
            let identity = ClaudeCodeAdapter::with_home(self.live.path())
                .read_optional_object(&paths.identity)
                .expect("identity")
                .expect("identity present");
            (credentials, identity)
        }
    }

    struct AddEnv {
        live: tempfile::TempDir,
        data: tempfile::TempDir,
    }

    impl AddEnv {
        fn new() -> Self {
            Self {
                live: staged_home("switch-live"),
                data: tempfile::tempdir().expect("data dir"),
            }
        }

        fn adapter(&self, runner: fn(&Path) -> std::io::Result<i32>) -> ClaudeCodeAdapter {
            ClaudeCodeAdapter::with_home(self.live.path())
                .with_data_dir(self.data.path())
                .with_login_runner(runner)
        }

        fn managed_dir(&self, account_id: &str) -> PathBuf {
            self.data
                .path()
                .join("accounts")
                .join("claude-code")
                .join(account_id)
        }

        fn digest(&self) -> std::collections::BTreeMap<String, Vec<u8>> {
            digest_claude(self.live.path())
        }

        fn seed_managed(&self, account_id: &str) {
            copy_managed_oauth(&self.managed_dir(account_id));
        }

        fn seed_incomplete(&self, account_id: &str) {
            fs::create_dir_all(self.managed_dir(account_id)).expect("incomplete managed dir");
        }
    }

    fn digest_claude(home: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        collect_files(home, home, &mut out);
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
            let rel = path.strip_prefix(root).expect("path under home");
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
        skip: &[&str],
    ) -> std::collections::BTreeMap<&'a str, &'a [u8]> {
        tree.iter()
            .filter(|(path, _)| !skip.contains(&path.as_str()))
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

    fn assert_add_error_is_clean(error: &Error) {
        assert_no_fake("add_account Display", &error.to_string());
        assert_no_fake("add_account Debug", &format!("{error:?}"));
        assert!(
            !error.to_string().contains(LOGIN_SPAWN_OUTPUT),
            "add_account Display leaked subprocess output: {error}"
        );
    }

    fn assert_preserved_machine_fields(before: &Map<String, Value>, after: &Map<String, Value>) {
        for key in [
            "userID",
            "machineID",
            "mcpServers",
            "projects",
            "cachedUsageUtilization",
            "futureIdentityKey",
        ] {
            assert_eq!(
                before.get(key),
                after.get(key),
                "machine-scoped field {key} must be preserved"
            );
        }
    }

    #[test]
    fn activate_account_replaces_only_the_allowlisted_objects() {
        let env = SwitchEnv::new();
        let before = env.digest();
        let (before_credentials, before_identity) = env.live_objects();

        env.adapter()
            .activate_account(TARGET_ACCOUNT)
            .expect("switch");

        let after = env.digest();
        let (after_credentials, after_identity) = env.live_objects();
        let stored = claude_switch::load_stored_pair(
            &env.data
                .path()
                .join("accounts/claude-code")
                .join(TARGET_ACCOUNT),
            "claude-code",
        )
        .expect("load stored")
        .expect("stored pair");

        assert_eq!(after_credentials.get(OAUTH_KEY), Some(&stored.oauth));
        assert_eq!(after_identity.get(ACCOUNT_KEY), Some(&stored.account));
        assert_eq!(
            after_credentials.get("organizationUuid"),
            before_credentials.get("organizationUuid")
        );
        assert_eq!(
            after_credentials.get("futureCredentialKey"),
            before_credentials.get("futureCredentialKey")
        );
        assert_preserved_machine_fields(&before_identity, &after_identity);
        assert_eq!(
            files_except(&before, &[".claude/.credentials.json", ".claude.json"]),
            files_except(&after, &[".claude/.credentials.json", ".claude.json"]),
            "every other live-home file must be byte-identical; before={} after={}",
            digest_brief(&before),
            digest_brief(&after)
        );

        let accounts = env.adapter().list_accounts().expect("list after switch");
        let active = accounts
            .iter()
            .find(|account| account.id == TARGET_ACCOUNT)
            .expect("stored account");
        assert!(active.is_active);
        assert!(active.is_stored);
        assert_eq!(active.masked_identity.as_deref(), Some("****0002"));
        assert!(
            accounts
                .iter()
                .all(|account| account.id != ON_DISK_ACCOUNT_ID),
            "matching stored copy must replace the live row"
        );
        let json = serde_json::to_string(&accounts).expect("json");
        assert!(!json.contains('@'), "oauthAccount email leaked: {json}");
        assert_no_fake("list after switch", &json);
        assert!(
            !env.data.path().join("claude-code/switch.journal").exists(),
            "journal must be cleared after a successful switch"
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
        assert_eq!(
            before,
            env.digest(),
            "a failure after snapshot must not mutate the live home"
        );
        let listed = env.backups().list().expect("list backups");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].provider_id, "claude-code");
    }

    #[test]
    fn activate_account_restores_both_files_after_a_forced_first_write_failure() {
        let env = SwitchEnv::new();
        let before = env.digest();

        let error = env
            .adapter()
            .with_fault(SwitchFault::AfterFirstWrite)
            .activate_account(TARGET_ACCOUNT)
            .expect_err("injected failure after first write");
        assert!(
            error
                .to_string()
                .contains("previous account is still active"),
            "unexpected error: {error}"
        );
        assert_switch_error_holds_no_secret(&error);
        assert_eq!(
            before,
            env.digest(),
            "restore must return both live files after a mid-pair failure"
        );
    }

    #[test]
    fn activate_account_restores_both_files_after_a_forced_write_failure() {
        let env = SwitchEnv::new();
        let before = env.digest();

        let error = env
            .adapter()
            .with_fault(SwitchFault::AfterWrite)
            .activate_account(TARGET_ACCOUNT)
            .expect_err("injected failure after write");
        assert!(
            error
                .to_string()
                .contains("previous account is still active"),
            "unexpected error: {error}"
        );
        assert_switch_error_holds_no_secret(&error);
        assert_eq!(before, env.digest());
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
        assert_eq!(before, env.digest());
        assert!(!env.data.path().join("backups").exists());
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
            error.to_string().contains("appears to be running"),
            "user must be told what is running: {error}"
        );
        assert_switch_error_holds_no_secret(&error);
        assert_eq!(before, env.digest());
        assert!(!env.data.path().join("backups").exists());
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
            error.to_string().contains("could not determine"),
            "user must be told the check failed: {error}"
        );
        assert_switch_error_holds_no_secret(&error);
        assert_eq!(before, env.digest());
        assert!(!env.data.path().join("backups").exists());
    }

    #[test]
    fn activate_account_refuses_when_the_live_identity_file_is_missing() {
        let env = SwitchEnv::new();
        fs::remove_file(env.live.path().join(".claude.json")).expect("remove identity");
        let before = env.digest();
        let error = env
            .adapter()
            .activate_account(TARGET_ACCOUNT)
            .expect_err("missing identity");
        assert!(
            error.to_string().contains("refusing to invent"),
            "missing ~/.claude.json must refuse: {error}"
        );
        assert_switch_error_holds_no_secret(&error);
        assert_eq!(before, env.digest());
        assert!(!env.data.path().join("backups").exists());
    }

    #[test]
    fn activate_account_creates_credentials_when_the_live_file_is_missing() {
        let env = SwitchEnv::new();
        fs::remove_file(env.live.path().join(".claude/.credentials.json")).expect("remove creds");
        let (_, before_identity) = {
            let paths = claude_switch::live_paths(env.live.path());
            let identity = ClaudeCodeAdapter::with_home(env.live.path())
                .read_optional_object(&paths.identity)
                .expect("identity")
                .expect("identity present");
            ((), identity)
        };

        env.adapter()
            .activate_account(TARGET_ACCOUNT)
            .expect("switch into empty credentials");

        let (after_credentials, after_identity) = env.live_objects();
        assert_eq!(after_credentials.len(), 1);
        assert!(after_credentials.get(OAUTH_KEY).is_some());
        assert_preserved_machine_fields(&before_identity, &after_identity);
    }

    #[test]
    fn list_accounts_recovers_a_crashed_switch_from_the_journal() {
        let env = SwitchEnv::new();
        let before = env.digest();
        let store = env.backups();
        let paths = claude_switch::live_paths(env.live.path());
        let backup = store
            .snapshot(
                "claude-code",
                &[
                    paths.credentials.clone(),
                    paths.identity.clone(),
                    env.live.path().join(".claude/settings.json"),
                ],
            )
            .expect("snapshot");
        fs::write(
            &paths.credentials,
            r#"{"claudeAiOauth":{"accessToken":"FAKE-partial"}}"#,
        )
        .expect("partial credentials");
        fs::write(
            &paths.identity,
            r#"{"oauthAccount":{},"userID":"FAKE-partial"}"#,
        )
        .expect("partial identity");
        claude_switch::write_journal(
            &claude_switch::journal_path(env.data.path()),
            &backup,
            "claude-code",
        )
        .expect("journal");

        let accounts = env.adapter().list_accounts().expect("recover on list");
        assert_eq!(
            before,
            env.digest(),
            "list_accounts must restore both files from the journaled backup"
        );
        assert!(!env.data.path().join("claude-code/switch.journal").exists());
        assert!(accounts.iter().any(|account| account.is_active));
        assert_no_fake(
            "list after journal recover",
            &serde_json::to_string(&accounts).expect("json"),
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
        assert!(dir.is_dir());
        assert!(dir.join(".credentials.json").is_file());
        assert!(dir.join(".claude.json").is_file());
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
            .expect("added account");
        assert_eq!(added.auth_kind, AuthKind::OAuth);
        assert_eq!(added.masked_identity.as_deref(), Some("****0002"));
        assert!(!added.is_active);
        assert!(added.is_stored);
        assert!(accounts
            .iter()
            .any(|account| account.id == ON_DISK_ACCOUNT_ID && account.is_active));
        assert_eq!(before, env.digest());
        assert_no_fake(
            "list after add",
            &serde_json::to_string(&accounts).expect("json"),
        );
    }

    #[test]
    fn add_account_sets_both_isolated_config_directories() {
        let env = AddEnv::new();
        env.adapter(login_records_env)
            .add_account(ADDED_ACCOUNT)
            .expect("add");
        let recorded = env.managed_dir(ADDED_ACCOUNT).join("login-dir.txt");
        assert_eq!(
            fs::read_to_string(&recorded).expect("login dir"),
            env.managed_dir(ADDED_ACCOUNT).to_string_lossy()
        );
    }

    #[test]
    fn add_account_removes_the_directory_when_login_exits_nonzero() {
        let env = AddEnv::new();
        env.seed_managed(SIBLING_ACCOUNT);
        let before = env.digest();
        let sibling =
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join(".credentials.json")).expect("sibling");

        let error = env
            .adapter(login_exits_nonzero)
            .add_account(ADDED_ACCOUNT)
            .expect_err("nonzero login");
        assert!(
            error.to_string().contains("exited with status 1"),
            "{error}"
        );
        assert_add_error_is_clean(&error);
        assert!(fs::symlink_metadata(env.managed_dir(ADDED_ACCOUNT)).is_err());
        assert_eq!(
            fs::read(env.managed_dir(SIBLING_ACCOUNT).join(".credentials.json")).expect("sibling"),
            sibling
        );
        assert_eq!(before, env.digest());
    }

    #[test]
    fn add_account_removes_the_directory_when_login_writes_no_identity_pair() {
        let env = AddEnv::new();
        let error = env
            .adapter(login_ok_without_identity)
            .add_account(ADDED_ACCOUNT)
            .expect_err("missing pair");
        assert!(error.to_string().contains("was not created"), "{error}");
        assert_add_error_is_clean(&error);
        assert!(fs::symlink_metadata(env.managed_dir(ADDED_ACCOUNT)).is_err());
    }

    #[test]
    fn add_account_reports_a_spawn_failure_by_kind_and_path() {
        let env = AddEnv::new();
        let error = env
            .adapter(login_fails_to_start)
            .add_account(ADDED_ACCOUNT)
            .expect_err("spawn");
        assert!(error.to_string().contains("could not start"), "{error}");
        assert!(
            error
                .to_string()
                .contains(&env.managed_dir(ADDED_ACCOUNT).display().to_string()),
            "{error}"
        );
        assert_add_error_is_clean(&error);
        assert!(fs::symlink_metadata(env.managed_dir(ADDED_ACCOUNT)).is_err());
    }

    #[test]
    fn add_account_reuses_an_incomplete_slot_that_holds_no_identity_files() {
        let env = AddEnv::new();
        env.seed_incomplete(ADDED_ACCOUNT);
        env.adapter(login_writes_managed_oauth)
            .add_account(ADDED_ACCOUNT)
            .expect("reuse incomplete");
        assert!(env
            .managed_dir(ADDED_ACCOUNT)
            .join(".credentials.json")
            .is_file());
    }

    #[test]
    fn add_account_refuses_the_live_on_disk_id() {
        let env = AddEnv::new();
        let error = env
            .adapter(login_must_not_run)
            .add_account(ON_DISK_ACCOUNT_ID)
            .expect_err("reserved id");
        assert!(error.to_string().contains("reserved"), "{error}");
        assert_add_error_is_clean(&error);
    }

    #[test]
    fn add_account_refuses_an_unsafe_id_before_creating_anything() {
        let env = AddEnv::new();
        let error = env
            .adapter(login_must_not_run)
            .add_account("../etc")
            .expect_err("unsafe id");
        assert!(
            error.to_string().contains("not a safe path component"),
            "{error}"
        );
        assert_add_error_is_clean(&error);
        assert!(!env.data.path().join("accounts").exists());
    }

    #[test]
    fn add_account_refuses_an_existing_managed_directory_without_changing_it() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT);
        let before =
            fs::read(env.managed_dir(ADDED_ACCOUNT).join(".credentials.json")).expect("before");
        let error = env
            .adapter(login_must_not_run)
            .add_account(ADDED_ACCOUNT)
            .expect_err("exists");
        assert!(error.to_string().contains("already exists"), "{error}");
        assert_eq!(
            fs::read(env.managed_dir(ADDED_ACCOUNT).join(".credentials.json")).expect("after"),
            before
        );
    }

    #[test]
    fn delete_account_removes_the_directory_and_does_not_sign_out() {
        let env = AddEnv::new();
        env.seed_managed(ADDED_ACCOUNT);
        env.seed_managed(SIBLING_ACCOUNT);
        let before = env.digest();

        env.adapter(login_must_not_run)
            .delete_account(ADDED_ACCOUNT)
            .expect("delete");

        assert!(fs::symlink_metadata(env.managed_dir(ADDED_ACCOUNT)).is_err());
        assert!(env
            .managed_dir(SIBLING_ACCOUNT)
            .join(".credentials.json")
            .is_file());
        assert_eq!(before, env.digest());
        let accounts = env
            .adapter(login_must_not_run)
            .list_accounts()
            .expect("list after delete");
        assert!(accounts.iter().all(|account| account.id != ADDED_ACCOUNT));
        assert!(accounts
            .iter()
            .any(|account| account.id == ON_DISK_ACCOUNT_ID && account.is_active));
    }

    #[test]
    fn delete_account_removes_an_incomplete_slot() {
        let env = AddEnv::new();
        env.seed_incomplete(ADDED_ACCOUNT);
        env.adapter(login_must_not_run)
            .delete_account(ADDED_ACCOUNT)
            .expect("delete incomplete");
        assert!(fs::symlink_metadata(env.managed_dir(ADDED_ACCOUNT)).is_err());
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
            .expect_err("incomplete");
        assert!(
            matches!(error, Error::UnknownAccount(ref id) if id == ADDED_ACCOUNT),
            "expected UnknownAccount, got {error:?}"
        );
        assert_eq!(before, env.digest());
        assert!(!env.data.path().join("backups").exists());
    }

    #[test]
    fn delete_account_rejects_an_unknown_id_without_changing_anything() {
        let env = AddEnv::new();
        let error = env
            .adapter(login_must_not_run)
            .delete_account("no-such-account")
            .expect_err("unknown");
        assert!(matches!(error, Error::UnknownAccount(_)));
    }
}
