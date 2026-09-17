//! Grok CLI (xAI) adapter.
//!
//! Observed layout on Linux, grok 0.2.93:
//!
//! - `~/.grok/auth.json` [verified-local] — a map keyed by provider scope
//!   `"{issuer}::{client_id}"`. OIDC entries carry `key`, `auth_mode`,
//!   `create_time`, `user_id`, `email`, `first_name`,
//!   `profile_image_asset_id`, `principal_type`, `principal_id`, `team_id`,
//!   `coding_data_retention_opt_out`, `refresh_token`, `expires_at`,
//!   `oidc_issuer`, and `oidc_client_id`. Reserved non-OIDC keys
//!   (`xai::api_key`, `https://accounts.x.ai/sign-in`) also live in that
//!   map [verified-docs].
//! - `~/.grok/config.toml` [verified-local] — client configuration, including
//!   `[marketplace]` and `[[marketplace.sources]]`.
//! - `~/.grok/auth.json.lock`, `~/.grok/active_sessions.json`,
//!   `~/.grok/active_sessions.lock` [verified-local] — the CLI takes advisory
//!   locks, so any write must respect them rather than clobbering the file.
//! - `~/.grok/models_cache.json` [verified-local] — may expose model
//!   availability; not confirmed to carry quota.
//!
//! `$GROK_HOME` relocates the whole client home when it is set and non-empty
//! [verified-source] (`docs/research/grok-cli.md` §2). `$GROK_AUTH_PATH`, when
//! set, overrides the credential file independently of that home — a
//! relocated home does not move `auth.json`. Keys are not user identities:
//! the default client id is a configuration constant, so a second login
//! overwrites the first. A switch is therefore one home per account, not
//! selecting an active map entry.
//!
//! Manager-owned accounts keep each vendor-written home in place. Selection is
//! non-secret metadata; core starts `grok` with `GROK_HOME` set to the selected
//! derived home and removes `GROK_AUTH_PATH`. This adapter never copies,
//! restores, rewrites, or deletes `auth.json`.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};

use fs2::FileExt;
use serde::de::{Error as _, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{
    account_id_is_safe, binary_on_path, home_dir, managed_account_dir, ActivationMechanism,
    LaunchSpec, ManagedAccountPlan, ProviderAdapter, StoredAccountRegistry,
};
use crate::error::{Error, Result};
use crate::model::{
    Account, AuthKind, InstallState, Maturity, ProviderCapability, ProviderDescriptor,
    StoredAccountMaterial, StoredAccountMetadata, StoredAccountState,
};
use crate::{fsx, paths};

const PROVIDER_ID: &str = "grok-cli";

/// Map keys that live in `auth.json` but are not a signed-in identity.
///
/// `xai::api_key` is the API-key auth scope (`grok login --api-key`).
/// `https://accounts.x.ai/sign-in` is the legacy pre-OIDC scope; the CLI
/// skips a WebLogin token under it. Listing either as an account would
/// present a reserved entry as a user identity
/// (`docs/research/grok-cli.md` §3).
const RESERVED_SCOPES: &[&str] = &["xai::api_key", "https://accounts.x.ai/sign-in"];

type LoginRunner = fn(&Path) -> io::Result<i32>;

#[derive(Debug, Default)]
pub struct GrokCliAdapter {
    /// Injected home directory. `None` means the real user home, which is
    /// what production uses; tests pass a `tempfile::TempDir` path so no
    /// test can read a developer's real credentials (`docs/TESTING.md` §4).
    home: Option<PathBuf>,
    /// Application data directory containing derived per-account homes.
    /// Tests inject this so they never inspect or write production metadata.
    data_dir: Option<PathBuf>,
    /// Exact child working directory. Production resolves the app's current
    /// directory; tests inject an isolated absolute directory.
    working_directory: Option<PathBuf>,
    /// `None` means the fixed production executable name `grok`.
    program: Option<PathBuf>,
    /// Test seam for interactive login. Production always inherits stdio and
    /// starts the fixed `grok login` command itself.
    login_runner: Option<LoginRunner>,
}

impl GrokCliAdapter {
    /// Root this adapter at `home` instead of the real user home.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
            ..Self::default()
        }
    }

    /// Root manager metadata and vendor homes at `data_dir`.
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Set the exact absolute working directory used for login and launch.
    pub fn with_working_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(directory.into());
        self
    }

    /// Replace `grok` with an executable fixture while preserving fixed args.
    pub fn with_program(mut self, program: impl Into<PathBuf>) -> Self {
        self.program = Some(program.into());
        self
    }

    /// Complete an isolated login without starting a real browser in tests.
    pub fn with_login_runner(mut self, runner: LoginRunner) -> Self {
        self.login_runner = Some(runner);
        self
    }

    fn grok_home(&self) -> Option<PathBuf> {
        resolve_grok_home(
            self.home.as_deref(),
            std::env::var_os("GROK_HOME").as_deref(),
            home_dir().as_deref(),
        )
    }

    fn auth_json_path(&self) -> Option<PathBuf> {
        resolve_auth_json_path(
            self.home.as_deref(),
            std::env::var_os("GROK_HOME").as_deref(),
            std::env::var_os("GROK_AUTH_PATH").as_deref(),
            home_dir().as_deref(),
        )
    }

    fn resolved_data_dir(&self) -> Result<PathBuf> {
        let directory = self.data_dir.clone().or_else(|| {
            if self.home.is_some() {
                // A fixture home alone must never make a unit or contract test
                // discover the developer's real manager metadata.
                None
            } else {
                paths::project_dirs().map(|dirs| dirs.data_dir().to_path_buf())
            }
        });
        let directory =
            directory.ok_or_else(|| config_write("application data directory unavailable"))?;
        if !directory.is_absolute() {
            return Err(config_write(
                "application data directory is not an absolute path",
            ));
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
        if !directory.is_absolute() {
            return Err(config_write("launch working directory is not absolute"));
        }
        let metadata = fs::symlink_metadata(&directory).map_err(|error| {
            config_write(format!(
                "launch working directory cannot be inspected ({})",
                error.kind()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(config_write(
                "launch working directory is not a non-symlink directory",
            ));
        }
        Ok(directory)
    }

    fn managed_home(&self, account: &StoredAccountMetadata) -> Result<PathBuf> {
        validate_managed_metadata(account)?;
        Ok(managed_account_dir(
            &self.resolved_data_dir()?,
            PROVIDER_ID,
            &account.id,
        ))
    }

    fn program(&self) -> PathBuf {
        self.program
            .clone()
            .unwrap_or_else(|| PathBuf::from("grok"))
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

    fn run_login(&self, managed_home: &Path) -> Result<()> {
        let status = if let Some(runner) = self.login_runner {
            runner(managed_home).map_err(|error| {
                config_write(format!("grok login could not start ({})", error.kind()))
            })?
        } else {
            Command::new(self.program())
                .arg("login")
                .current_dir(self.resolved_working_directory()?)
                .env("GROK_HOME", managed_home)
                .env_remove("GROK_AUTH_PATH")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .map_err(|error| {
                    config_write(format!("grok login could not start ({})", error.kind()))
                })?
                .code()
                .unwrap_or(-1)
        };
        if status != 0 {
            return Err(config_write(format!(
                "grok login exited unsuccessfully (status {status})"
            )));
        }
        Ok(())
    }
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
            "stored account metadata does not match Grok OAuth vendor-home storage",
        ));
    }
    Ok(())
}

fn validate_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| config_write(format!("{label} cannot be inspected ({})", error.kind())))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(config_write(format!(
            "{label} is not a non-symlink directory"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(config_write(format!("{label} is not owner-only")));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn metadata_identity_matches(
    left: &fs::Metadata,
    right: &fs::Metadata,
    label: &str,
) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = label;
        Ok((left.dev(), left.ino()) == (right.dev(), right.ino()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (left, right);
        Err(config_write(format!(
            "{label} identity cannot be verified on this platform"
        )))
    }
}

#[cfg(windows)]
fn file_identity_matches_path(file: &File, path: &Path, label: &str) -> Result<bool> {
    let file_identity = file
        .try_clone()
        .and_then(same_file::Handle::from_file)
        .map_err(|error| {
            config_write(format!(
                "{label} identity cannot be read ({})",
                error.kind()
            ))
        })?;
    let path_identity = same_file::Handle::from_path(path).map_err(|error| {
        config_write(format!(
            "{label} identity cannot be rechecked ({})",
            error.kind()
        ))
    })?;
    Ok(file_identity == path_identity)
}

fn ensure_private_managed_home(data_dir: &Path, home: &Path) -> Result<()> {
    let accounts = data_dir.join("accounts");
    let provider = accounts.join(PROVIDER_ID);
    for (directory, label) in [
        (data_dir, "application data directory"),
        (accounts.as_path(), "managed accounts directory"),
        (provider.as_path(), "Grok provider directory"),
        (home, "managed Grok home"),
    ] {
        match fs::symlink_metadata(directory) {
            Ok(_) => validate_directory(directory, label)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fsx::create_dir_all_private(directory)?;
                validate_directory(directory, label)?;
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

struct JsonObjectShape;

struct StringShape;

impl<'de> Deserialize<'de> for StringShape {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringVisitor;

        impl<'de> Visitor<'de> for StringVisitor {
            type Value = StringShape;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_borrowed_str<E>(
                self,
                _value: &'de str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StringShape)
            }

            fn visit_str<E>(self, _value: &str) -> std::result::Result<Self::Value, E> {
                Ok(StringShape)
            }

            fn visit_string<E>(self, mut value: String) -> std::result::Result<Self::Value, E> {
                use zeroize::Zeroize;
                value.zeroize();
                Ok(StringShape)
            }
        }

        deserializer.deserialize_str(StringVisitor)
    }
}

struct OAuthEntryShape {
    has_required_strings: bool,
}

impl<'de> Deserialize<'de> for OAuthEntryShape {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EntryVisitor;

        impl<'de> Visitor<'de> for EntryVisitor {
            type Value = OAuthEntryShape;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an OAuth account object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut issuer = false;
                let mut client_id = false;
                let mut refresh_token = false;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "oidc_issuer" => {
                            let _ = map.next_value::<StringShape>()?;
                            issuer = true;
                        }
                        "oidc_client_id" => {
                            let _ = map.next_value::<StringShape>()?;
                            client_id = true;
                        }
                        "refresh_token" => {
                            let _ = map.next_value::<StringShape>()?;
                            refresh_token = true;
                        }
                        _ => {
                            let _ = map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(OAuthEntryShape {
                    has_required_strings: issuer && client_id && refresh_token,
                })
            }
        }

        deserializer.deserialize_map(EntryVisitor)
    }
}

impl<'de> Deserialize<'de> for JsonObjectShape {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = JsonObjectShape;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut has_oauth_entry = false;
                while let Some(key) = map.next_key::<String>()? {
                    if is_oidc_identity_scope(&key) {
                        has_oauth_entry |=
                            map.next_value::<OAuthEntryShape>()?.has_required_strings;
                    } else {
                        let _ = map.next_value::<IgnoredAny>()?;
                    }
                }
                if !has_oauth_entry {
                    return Err(A::Error::custom(
                        "no OAuth identity entry with required string fields",
                    ));
                }
                Ok(JsonObjectShape)
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

fn validate_auth_json(home: &Path) -> Result<()> {
    let path = home.join("auth.json");
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        config_write(format!(
            "managed auth.json cannot be inspected ({})",
            error.kind()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(config_write(
            "managed auth.json is not a regular non-symlink file",
        ));
    }
    let mut file = File::open(&path).map_err(|error| {
        config_write(format!(
            "managed auth.json cannot be opened ({})",
            error.kind()
        ))
    })?;
    validate_open_file_identity(&file, &path, "managed auth.json")?;
    // Parse only keys and structure. Values are deserialized as `IgnoredAny`,
    // and the transient byte buffer is zeroed on every return path.
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes).map_err(|error| {
        config_write(format!(
            "managed auth.json cannot be read ({})",
            error.kind()
        ))
    })?;
    validate_open_file_identity(&file, &path, "managed auth.json")?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    JsonObjectShape::deserialize(&mut deserializer)
        .and_then(|_| deserializer.end())
        .map_err(|_| config_write("managed auth.json is not exactly one JSON object"))
}

#[derive(Deserialize)]
struct ActiveSession {
    session_id: String,
    pid: u64,
    cwd: String,
    opened_at: String,
}

enum PidState {
    Live,
    #[cfg(target_os = "linux")]
    Dead,
    Unknown,
}

fn pid_state(pid: u32) -> PidState {
    if pid == std::process::id() {
        return PidState::Live;
    }
    #[cfg(target_os = "linux")]
    {
        match fs::metadata(Path::new("/proc").join(pid.to_string())) {
            Ok(_) => PidState::Live,
            Err(error) if error.kind() == io::ErrorKind::NotFound => PidState::Dead,
            Err(_) => PidState::Unknown,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        PidState::Unknown
    }
}

fn check_active_sessions(home: &Path) -> Result<()> {
    let path = home.join("active_sessions.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(config_write(format!(
                "active session registry cannot be inspected ({})",
                error.kind()
            )))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(config_write(
            "active session registry is not a regular non-symlink file",
        ));
    }
    let mut file = File::open(&path).map_err(|error| {
        config_write(format!(
            "active session registry cannot be opened ({})",
            error.kind()
        ))
    })?;
    validate_open_file_identity(&file, &path, "active session registry")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        config_write(format!(
            "active session registry cannot be read ({})",
            error.kind()
        ))
    })?;
    validate_open_file_identity(&file, &path, "active session registry")?;
    let sessions: Vec<ActiveSession> = serde_json::from_slice(&bytes)
        .map_err(|_| config_write("active session registry is malformed"))?;
    sessions.into_iter().try_for_each(|session| {
        if session.session_id.is_empty()
            || session.cwd.is_empty()
            || time::OffsetDateTime::parse(
                &session.opened_at,
                &time::format_description::well_known::Rfc3339,
            )
            .is_err()
            || session.pid == 0
            || session.pid > u64::from(u32::MAX)
        {
            return Err(config_write(
                "active session registry contains an invalid session",
            ));
        }
        match pid_state(session.pid as u32) {
            PidState::Live => Err(config_write(
                "a Grok session recorded for this home is still active",
            )),
            #[cfg(target_os = "linux")]
            PidState::Dead => Ok(()),
            PidState::Unknown => Err(config_write(
                "a Grok session PID could not be verified as stopped",
            )),
        }
    })
}

fn validate_open_file_identity(file: &File, path: &Path, label: &str) -> Result<()> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| config_write(format!("{label} cannot be rechecked ({})", error.kind())))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(config_write(format!(
            "{label} is not a regular non-symlink file"
        )));
    }
    #[cfg(not(windows))]
    let identity_matches = {
        let handle_metadata = file.metadata().map_err(|error| {
            config_write(format!(
                "{label} identity cannot be read ({})",
                error.kind()
            ))
        })?;
        metadata_identity_matches(&path_metadata, &handle_metadata, label)?
    };
    #[cfg(windows)]
    let identity_matches = file_identity_matches_path(file, path, label)?;
    if !identity_matches {
        return Err(config_write(format!(
            "{label} was replaced during validation"
        )));
    }
    Ok(())
}

static ACTIVE_HOME_OPERATIONS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

struct HomeOperationGuard {
    home: PathBuf,
}

impl HomeOperationGuard {
    fn acquire(home: &Path) -> Result<Self> {
        let mut active = active_home_operations()?;
        if !active.insert(home.to_path_buf()) {
            return Err(config_write(
                "another manager operation is already using this Grok home",
            ));
        }
        Ok(Self {
            home: home.to_path_buf(),
        })
    }
}

impl Drop for HomeOperationGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = active_home_operations() {
            active.remove(&self.home);
        }
    }
}

fn active_home_operations() -> Result<MutexGuard<'static, HashSet<PathBuf>>> {
    ACTIVE_HOME_OPERATIONS
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .map_err(|_| config_write("Grok home operation lock is poisoned"))
}

struct ExistingFileLock {
    path: PathBuf,
    file: File,
}

impl ExistingFileLock {
    fn acquire(path: &Path, label: &str) -> Result<Option<Self>> {
        let before = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(config_write(format!(
                    "{label} cannot be inspected ({})",
                    error.kind()
                )))
            }
        };
        if before.file_type().is_symlink() || !before.is_file() {
            return Err(config_write(format!(
                "{label} is not a regular non-symlink file"
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| {
                config_write(format!("{label} cannot be opened ({})", error.kind()))
            })?;
        FileExt::try_lock_exclusive(&file).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                config_write(format!("{label} is held by another process"))
            } else {
                config_write(format!("{label} cannot be locked ({})", error.kind()))
            }
        })?;
        let held = Self {
            path: path.to_path_buf(),
            file,
        };
        held.validate_identity(label)?;
        Ok(Some(held))
    }

    fn validate_identity(&self, label: &str) -> Result<()> {
        let path_metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            config_write(format!("{label} changed while locked ({})", error.kind()))
        })?;
        if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
            return Err(config_write(format!("{label} changed while locked")));
        }
        #[cfg(not(windows))]
        let identity_matches = {
            let handle_metadata = self.file.metadata().map_err(|error| {
                config_write(format!(
                    "{label} identity cannot be read ({})",
                    error.kind()
                ))
            })?;
            metadata_identity_matches(&path_metadata, &handle_metadata, label)?
        };
        #[cfg(windows)]
        let identity_matches = file_identity_matches_path(&self.file, &self.path, label)?;
        if !identity_matches {
            return Err(config_write(format!("{label} was replaced while locked")));
        }
        Ok(())
    }
}

impl Drop for ExistingFileLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn gate_managed_home(home: &Path, require_auth: bool) -> Result<()> {
    validate_directory(home, "managed Grok home")?;
    #[cfg(not(windows))]
    let home_before = fs::symlink_metadata(home).map_err(|error| {
        config_write(format!(
            "managed Grok home cannot be inspected ({})",
            error.kind()
        ))
    })?;
    #[cfg(windows)]
    let home_before = same_file::Handle::from_path(home).map_err(|error| {
        config_write(format!(
            "managed Grok home identity cannot be inspected ({})",
            error.kind()
        ))
    })?;
    let auth_lock = ExistingFileLock::acquire(&home.join("auth.json.lock"), "Grok auth lock")?;
    let sessions_lock = ExistingFileLock::acquire(
        &home.join("active_sessions.lock"),
        "Grok active-session lock",
    )?;
    check_active_sessions(home)?;
    if require_auth {
        validate_auth_json(home)?;
    }
    if let Some(lock) = sessions_lock.as_ref() {
        lock.validate_identity("Grok active-session lock")?;
    } else {
        ensure_lock_still_absent(
            &home.join("active_sessions.lock"),
            "Grok active-session lock",
        )?;
    }
    if let Some(lock) = auth_lock.as_ref() {
        lock.validate_identity("Grok auth lock")?;
    } else {
        ensure_lock_still_absent(&home.join("auth.json.lock"), "Grok auth lock")?;
    }
    validate_directory(home, "managed Grok home")?;
    #[cfg(not(windows))]
    let home_after = fs::symlink_metadata(home).map_err(|error| {
        config_write(format!(
            "managed Grok home cannot be rechecked ({})",
            error.kind()
        ))
    })?;
    #[cfg(windows)]
    let home_after = same_file::Handle::from_path(home).map_err(|error| {
        config_write(format!(
            "managed Grok home identity cannot be rechecked ({})",
            error.kind()
        ))
    })?;
    #[cfg(not(windows))]
    let identity_matches =
        metadata_identity_matches(&home_before, &home_after, "managed Grok home")?;
    #[cfg(windows)]
    let identity_matches = home_before == home_after;
    if !identity_matches {
        return Err(config_write(
            "managed Grok home was replaced during validation",
        ));
    }
    Ok(())
}

fn ensure_lock_still_absent(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(config_write(format!("{label} appeared during validation"))),
        Err(error) => Err(config_write(format!(
            "{label} cannot be rechecked ({})",
            error.kind()
        ))),
    }
}

/// Resolve the grok home the way the vendor home crate does, with an injected
/// test root in front so no test can be affected by a developer's environment
/// (`docs/TESTING.md` §4).
///
/// Precedence (`docs/research/grok-cli.md` §2):
/// 1. Injected root → `{injected}/.grok`. Tests pass a `TempDir`; production
///    leaves this `None`.
/// 2. `$GROK_HOME` when it is set **and non-empty**, returned verbatim (not
///    canonicalized). Empty is treated as unset: the vendor crate filters it
///    the same way, and `GROK_HOME=` would otherwise become a relative path
///    from the process cwd.
/// 3. `{os_home}/.grok`.
fn resolve_grok_home(
    injected_root: Option<&Path>,
    grok_home_env: Option<&OsStr>,
    os_home: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(root) = injected_root {
        return Some(root.join(".grok"));
    }
    if let Some(explicit) = grok_home_env.filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(explicit));
    }
    os_home.map(|home| home.join(".grok"))
}

/// Path of the credential file this adapter reads.
///
/// `$GROK_AUTH_PATH`, when set, overrides `auth.json` independently of the
/// grok home (`docs/research/grok-cli.md` §2). A `$GROK_HOME` relocation
/// then no longer moves the credential file. The note says "when set", not
/// "when set and non-empty" (unlike `$GROK_HOME`), so an empty value is
/// still an override.
///
/// An injected test root still wins: a developer's `$GROK_AUTH_PATH` must
/// not point a test at a live credential (`docs/TESTING.md` §4).
fn resolve_auth_json_path(
    injected_root: Option<&Path>,
    grok_home_env: Option<&OsStr>,
    grok_auth_path_env: Option<&OsStr>,
    os_home: Option<&Path>,
) -> Option<PathBuf> {
    match (injected_root, grok_auth_path_env) {
        (None, Some(explicit)) => Some(PathBuf::from(explicit)),
        _ => resolve_grok_home(injected_root, grok_home_env, os_home)
            .map(|root| root.join("auth.json")),
    }
}

/// Paths this adapter actually reads. Backup and diagnostics use this list
/// (`docs/ARCHITECTURE.md` §4), so a `$GROK_AUTH_PATH` override must appear
/// here instead of `{grok_home}/auth.json`.
fn resolve_config_paths(
    injected_root: Option<&Path>,
    grok_home_env: Option<&OsStr>,
    grok_auth_path_env: Option<&OsStr>,
    os_home: Option<&Path>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(auth) =
        resolve_auth_json_path(injected_root, grok_home_env, grok_auth_path_env, os_home)
    {
        paths.push(auth);
    }
    if let Some(root) = resolve_grok_home(injected_root, grok_home_env, os_home) {
        paths.push(root.join("config.toml"));
        paths.push(root.join("models_cache.json"));
    }
    paths
}

/// True for an `auth.json` key that represents a signed-in OIDC identity.
///
/// OIDC scopes are `"{issuer}::{client_id}"`. The reserved API-key scope
/// also contains `::`, so membership in [`RESERVED_SCOPES`] is excluded
/// first (`docs/research/grok-cli.md` §3).
fn is_oidc_identity_scope(key: &str) -> bool {
    !RESERVED_SCOPES.contains(&key) && key.contains("::")
}

/// Mask an email for display in the shape `docs/SPEC.md` uses: `a***@example.com`.
///
/// Guarantees:
/// - the returned string is never the input
/// - the local part is reduced to its first character plus `***`
/// - a missing, empty, or unparseable value yields `None`, never an unmasked
///   fallback (`NFR-1`; `docs/research/grok-cli.md` §8)
fn mask_email(email: &str) -> Option<String> {
    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    let first = local.chars().next()?;
    Some(format!("{first}***@{domain}"))
}

/// `Account.id` is assigned by this application (`docs/SPEC.md` §4), never
/// taken from the vendor. The map key (`<issuer>::<client-uuid>`) is vendor
/// material: using it verbatim would couple stored state to a scheme xAI can
/// change. We therefore hash the key with FNV-1a 64-bit (stable across rustc
/// versions, unlike `DefaultHasher`; no hash crate is in this package) and
/// prefix `grok-cli-` so the id is recognisably ours. A CLI home holds a
/// handful of scopes, so 64-bit collision resistance is enough.
/// ponytail: upgrade to SHA-256 if a hash crate is added to this package.
fn derive_account_id(identity_key: &str) -> String {
    format!("{PROVIDER_ID}-{:016x}", fnv1a64(identity_key.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Carry `expires_at` only when it is already RFC 3339. Do not reformat or
/// compute a timestamp from `create_time` or anything else.
fn rfc3339_if_already(value: &str) -> Option<String> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|_| value.to_string())
}

fn config_read(reason: impl Into<String>) -> Error {
    Error::ConfigRead {
        provider: PROVIDER_ID.to_string(),
        reason: reason.into(),
    }
}

/// Classify from fields that are `[verified-local]` OIDC evidence only.
///
/// `docs/research/grok-cli.md` §4: an OIDC entry carries `oidc_issuer`,
/// `oidc_client_id`, and `refresh_token`. API-key auth is first-class
/// `[verified-docs]` but lives under the reserved `xai::api_key` scope,
/// which `list_accounts` excludes. This function does not read
/// `auth_mode` and never returns `AuthKind::ApiKey`. Anything not
/// recognisably OIDC is `Unknown`. Presence is checked without copying
/// secret values.
fn auth_kind_of(entry: &Map<String, Value>) -> AuthKind {
    let is_string = |key: &str| entry.get(key).is_some_and(Value::is_string);
    if is_string("oidc_issuer") && is_string("oidc_client_id") && is_string("refresh_token") {
        AuthKind::OAuth
    } else {
        AuthKind::Unknown
    }
}

/// Build one `Account` from a single `auth.json` entry.
///
/// A value that is not an object is not the documented shape
/// (`docs/research/grok-cli.md` §3). We fail the whole read rather than
/// skip the entry: skipping would make an identity vanish from the UI, and
/// a partial list would look safe to write later. `ConfigRead` forces the
/// caller to look. Objects that omit `email` or the OIDC fields still
/// become an `Account` — we never invent a field we did not read.
fn account_from_entry(identity_key: &str, value: &Value) -> Result<Account> {
    let Some(entry) = value.as_object() else {
        return Err(config_read(
            "auth.json contains an entry that is not an object",
        ));
    };

    let masked_identity = entry
        .get("email")
        .and_then(Value::as_str)
        .and_then(mask_email);
    let expires_at = entry
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(rfc3339_if_already);

    Ok(Account {
        id: derive_account_id(identity_key),
        provider_id: PROVIDER_ID.to_string(),
        label: String::new(),
        masked_identity,
        auth_kind: auth_kind_of(entry),
        // There is no in-file selection (`docs/research/grok-cli.md` §5).
        // NFR-8 forbids marking an entry active. Not most-recently-created,
        // not file order, not "the only one".
        is_active: false,
        is_selected_for_launch: false,
        // Entries live in the tool's own auth.json. This adapter stores
        // nothing, so mutating operations have nothing to act on.
        is_stored: false,
        is_incomplete: false,
        expires_at,
    })
}

impl ProviderAdapter for GrokCliAdapter {
    fn id(&self) -> &'static str {
        PROVIDER_ID
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "Grok CLI".to_string(),
            vendor: "xAI".to_string(),
            auth_kinds: vec![AuthKind::OAuth, AuthKind::ApiKey],
            // Environment selection is implemented for app-owned launches,
            // but the pinned source has not been matched to the host binary.
            // Keep maturity experimental while advertising only real paths.
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
        let mut config_paths = resolve_config_paths(
            self.home.as_deref(),
            std::env::var_os("GROK_HOME").as_deref(),
            std::env::var_os("GROK_AUTH_PATH").as_deref(),
            home_dir().as_deref(),
        );
        if let Ok(data_dir) = self.resolved_data_dir() {
            let registry = StoredAccountRegistry::new(paths::stored_accounts_path(&data_dir));
            if let Ok(accounts) = registry.load() {
                for account in accounts
                    .into_iter()
                    .filter(|account| account.provider_id == PROVIDER_ID)
                {
                    let home = managed_account_dir(&data_dir, PROVIDER_ID, &account.id);
                    config_paths.extend([
                        home.join("auth.json"),
                        home.join("auth.json.lock"),
                        home.join("active_sessions.json"),
                        home.join("active_sessions.lock"),
                    ]);
                }
            }
        }
        config_paths
    }

    fn detect(&self) -> InstallState {
        // `~/.grok` is also used by the unaffiliated community CLI
        // `superagent-ai/grok-cli`, which stores `grok.db` and
        // `user-settings.json` rather than `auth.json` / `config.toml`
        // (`docs/research/grok-cli.md` §8). The directory name is not
        // evidence of the official CLI.
        // Official-CLI evidence is the credential file this adapter actually
        // reads (`$GROK_AUTH_PATH` when set, else `{grok_home}/auth.json`) or
        // `{grok_home}/config.toml` (`docs/research/grok-cli.md` §2, §8).
        let has_official_config = self.auth_json_path().is_some_and(|path| path.is_file())
            || self
                .grok_home()
                .is_some_and(|root| root.join("config.toml").is_file());
        if binary_on_path("grok") || has_official_config {
            InstallState::Installed
        } else {
            InstallState::NotInstalled
        }
    }

    /// Signed-in OIDC identities visible in the default `auth.json`, followed
    /// by manager-owned non-secret metadata rows.
    ///
    /// Reserved scopes (`xai::api_key`, the legacy pre-OIDC key) are
    /// skipped: they are not user identities (`docs/research/grok-cli.md`
    /// §3). Every returned account has `is_active: false`: launch selection is
    /// surfaced separately and makes no claim about external shells.
    fn list_accounts(&self) -> Result<Vec<Account>> {
        let mut accounts = Vec::new();
        if let Some(path) = self.auth_json_path() {
            let bytes = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(err) if err.kind() == io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(config_read(format!(
                        "auth.json could not be read ({})",
                        err.kind()
                    )));
                }
            };
            if let Some(bytes) = bytes {
                let value: Value = serde_json::from_slice(&bytes)
                    .map_err(|_| config_read("auth.json is not valid JSON"))?;
                let Some(map) = value.as_object() else {
                    return Err(config_read(
                        "auth.json is not a JSON object keyed by provider scope",
                    ));
                };

                // Sort explicitly so two identities always come back in the
                // same order regardless of serde_json map representation.
                let mut keys: Vec<&String> = map
                    .keys()
                    .filter(|key| is_oidc_identity_scope(key))
                    .collect();
                keys.sort();
                accounts.reserve(keys.len());
                for key in keys {
                    accounts.push(account_from_entry(key, &map[key])?);
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
        let _operation = HomeOperationGuard::acquire(&home)?;
        gate_managed_home(&home, true)?;
        Ok(LaunchSpec::new(self.program())
            .current_dir(self.resolved_working_directory()?)
            .set_plain_env("GROK_HOME", home.as_os_str())
            .remove_env("GROK_AUTH_PATH"))
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
        validate_managed_metadata(account)?;
        if account.state != StoredAccountState::Pending {
            return Err(config_write("Grok account is not pending provisioning"));
        }
        let home = self.managed_home(account)?;
        let _operation = HomeOperationGuard::acquire(&home)?;
        ensure_private_managed_home(&self.resolved_data_dir()?, &home)?;

        match fs::symlink_metadata(home.join("auth.json")) {
            Ok(_) => {
                // Recovery seam: a crash after vendor login but before core's
                // complete write can revalidate without spending credentials
                // or starting a second login. Core does not yet call this seam
                // automatically for preserved pending vendor homes.
                gate_managed_home(&home, true)?;
                return Ok(None);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(config_write(format!(
                    "managed auth.json cannot be inspected ({})",
                    error.kind()
                )))
            }
        }

        gate_managed_home(&home, false)?;
        self.run_login(&home)?;
        gate_managed_home(&home, true)?;
        Ok(None)
    }

    fn validate_stored_account_delete(&self, account: &StoredAccountMetadata) -> Result<()> {
        validate_managed_metadata(account)?;
        let home = self.managed_home(account)?;
        match fs::symlink_metadata(&home) {
            Ok(_) => {
                let _operation = HomeOperationGuard::acquire(&home)?;
                // Delete means forget metadata. The vendor home and auth file
                // remain byte-for-byte in place, including for pending rows.
                gate_managed_home(&home, false)
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && account.state == StoredAccountState::Pending =>
            {
                Ok(())
            }
            Err(error) => Err(config_write(format!(
                "managed Grok home cannot be inspected ({})",
                error.kind()
            ))),
        }
    }

    fn quota(&self) -> Result<Vec<crate::model::QuotaSnapshot>> {
        // No quota counter was observed [verified-local]; models_cache.json
        // remains [unknown] (`docs/research/grok-cli.md` section 6).
        Ok(Vec::new())
    }

    fn activate_account(&self, _account_id: &str) -> Result<()> {
        // Core owns environment selection; there is intentionally no in-file
        // activation path for this adapter.
        Err(Error::NotImplemented("grok-cli::activate_account"))
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderAdapter;
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/grok-cli");

    fn fixture_dir(name: &str) -> PathBuf {
        PathBuf::from(FIXTURE_ROOT).join(name)
    }

    fn copy_tree(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).expect("create dest");
        for entry in fs::read_dir(src).expect("read fixture") {
            let entry = entry.expect("dirent");
            let to = dst.join(entry.file_name());
            let file_type = entry.file_type().expect("file type");
            if file_type.is_dir() {
                copy_tree(&entry.path(), &to);
            } else if file_type.is_file() {
                fs::copy(entry.path(), &to).expect("copy file");
            } else {
                panic!(
                    "fixture {} is not a regular file or directory",
                    entry.path().display()
                );
            }
        }
    }

    fn adapter_over_fixture(name: &str) -> (tempfile::TempDir, GrokCliAdapter) {
        let temp = tempfile::tempdir().expect("tempdir");
        copy_tree(&fixture_dir(name), temp.path());
        let adapter = GrokCliAdapter::with_home(temp.path());
        (temp, adapter)
    }

    fn write_auth(home: &Path, body: &str) {
        let dir = home.join(".grok");
        fs::create_dir_all(&dir).expect("mkdir .grok");
        fs::write(dir.join("auth.json"), body).expect("write auth.json");
    }

    fn assert_no_fake(where_: &str, text: &str) {
        assert!(
            !text.contains("FAKE-"),
            "{where_} leaked fixture secret material: {text}"
        );
    }

    fn surfaces(accounts: &[Account]) -> String {
        format!(
            "{}\n{accounts:?}",
            serde_json::to_string(accounts).expect("serialize accounts")
        )
    }

    #[test]
    fn empty_grok_home_is_not_an_override() {
        let os_home = Path::new("/home/u");
        assert_eq!(
            resolve_grok_home(None, Some(OsStr::new("")), Some(os_home)),
            Some(os_home.join(".grok"))
        );
        assert_eq!(
            resolve_grok_home(None, None, Some(os_home)),
            Some(os_home.join(".grok"))
        );
    }

    #[test]
    fn non_empty_grok_home_wins_over_the_default_home() {
        assert_eq!(
            resolve_grok_home(
                None,
                Some(OsStr::new("/custom/grok")),
                Some(Path::new("/home/u")),
            ),
            Some(PathBuf::from("/custom/grok"))
        );
    }

    #[test]
    fn injected_root_beats_grok_home_auth_path_and_the_default_home() {
        let injected = Path::new("/tmp/fixture-home");
        assert_eq!(
            resolve_grok_home(
                Some(injected),
                Some(OsStr::new("/custom/grok")),
                Some(Path::new("/home/u")),
            ),
            Some(injected.join(".grok"))
        );
        assert_eq!(
            resolve_auth_json_path(
                Some(injected),
                Some(OsStr::new("/custom/grok")),
                Some(OsStr::new("/elsewhere/auth.json")),
                Some(Path::new("/home/u")),
            ),
            Some(injected.join(".grok").join("auth.json"))
        );
        let paths = resolve_config_paths(
            Some(injected),
            Some(OsStr::new("/custom/grok")),
            Some(OsStr::new("/elsewhere/auth.json")),
            Some(Path::new("/home/u")),
        );
        assert!(
            paths.iter().all(|path| path.starts_with(injected)),
            "injected config_paths escaped the fixture root: {paths:?}"
        );
    }

    #[test]
    fn grok_auth_path_does_not_move_with_grok_home() {
        // `docs/research/grok-cli.md` §2: when set, `$GROK_AUTH_PATH` overrides
        // independently of the grok home. Relocating `$GROK_HOME` then no
        // longer moves the credential file.
        assert_eq!(
            resolve_auth_json_path(
                None,
                Some(OsStr::new("/relocated/grok")),
                Some(OsStr::new("/elsewhere/auth.json")),
                Some(Path::new("/home/u")),
            ),
            Some(PathBuf::from("/elsewhere/auth.json"))
        );
        assert_eq!(
            resolve_grok_home(
                None,
                Some(OsStr::new("/relocated/grok")),
                Some(Path::new("/home/u")),
            ),
            Some(PathBuf::from("/relocated/grok"))
        );
        assert_eq!(
            resolve_auth_json_path(
                None,
                Some(OsStr::new("/relocated/grok")),
                None,
                Some(Path::new("/home/u")),
            ),
            Some(PathBuf::from("/relocated/grok/auth.json"))
        );
        assert_eq!(
            resolve_config_paths(
                None,
                Some(OsStr::new("/relocated/grok")),
                Some(OsStr::new("/elsewhere/auth.json")),
                Some(Path::new("/home/u")),
            ),
            vec![
                PathBuf::from("/elsewhere/auth.json"),
                PathBuf::from("/relocated/grok/config.toml"),
                PathBuf::from("/relocated/grok/models_cache.json"),
            ]
        );
    }

    #[test]
    fn empty_grok_auth_path_is_still_an_override() {
        // The note says "when set" for `$GROK_AUTH_PATH`, not "when set and
        // non-empty" as it does for `$GROK_HOME` (`docs/research/grok-cli.md`
        // §2). The vendor `AuthManager` uses `std::env::var`, which treats
        // empty as present.
        assert_eq!(
            resolve_auth_json_path(
                None,
                Some(OsStr::new("/relocated/grok")),
                Some(OsStr::new("")),
                Some(Path::new("/home/u")),
            ),
            Some(PathBuf::from(""))
        );
    }

    #[test]
    fn grok_auth_path_alone_is_enough_to_report_the_credential_file() {
        assert_eq!(resolve_grok_home(None, None, None), None);
        assert_eq!(resolve_auth_json_path(None, None, None, None), None);
        assert!(resolve_config_paths(None, None, None, None).is_empty());
        assert_eq!(
            resolve_config_paths(None, None, Some(OsStr::new("/elsewhere/auth.json")), None,),
            vec![PathBuf::from("/elsewhere/auth.json")]
        );
    }

    #[test]
    fn with_home_resolves_config_paths_under_the_injected_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = GrokCliAdapter::with_home(dir.path());
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
    fn descriptor_is_experimental_while_activate_account_is_unimplemented() {
        let adapter = GrokCliAdapter::with_home("/nonexistent-grok-fixture-home");
        assert_eq!(adapter.descriptor().maturity, Maturity::Experimental);
        assert!(matches!(
            adapter.activate_account("unused"),
            Err(Error::NotImplemented("grok-cli::activate_account"))
        ));
    }

    #[test]
    fn list_accounts_returns_two_identities_sorted_masked_and_inactive() {
        let (_tmp, adapter) = adapter_over_fixture("home");
        let accounts = adapter.list_accounts().expect("list_accounts");

        let got = serde_json::to_value(&accounts).expect("serialize");
        let mut expected: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/grok-cli/expected/accounts.json"
        ))
        .expect("expected/accounts.json");
        for account in expected
            .as_array_mut()
            .expect("expected Grok account array")
        {
            account
                .as_object_mut()
                .expect("expected Grok account object")
                .insert("isSelectedForLaunch".to_string(), Value::Bool(false));
        }
        assert_eq!(got, expected);

        assert_eq!(accounts.len(), 2);
        assert!(accounts.iter().all(|account| !account.is_active));
        for account in &accounts {
            let masked = account
                .masked_identity
                .as_deref()
                .expect("fixture entries have emails");
            assert!(masked.contains("***@"), "identity was not masked: {masked}");
        }
        assert_no_fake("list_accounts", &surfaces(&accounts));
    }

    #[test]
    fn missing_auth_json_yields_no_accounts() {
        let (_tmp, adapter) = adapter_over_fixture("missing-file");
        let accounts = adapter.list_accounts().expect("missing file is empty");
        assert!(accounts.is_empty());
    }

    #[test]
    fn malformed_auth_json_is_config_read() {
        // Written here rather than stored as a `.json` fixture: Prettier parses
        // tracked `*.json` and refuses this intentionally invalid document.
        let temp = tempfile::tempdir().expect("tempdir");
        write_auth(
            temp.path(),
            r#"{"https://auth.example.invalid::aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaa0001":{"refresh_token":"FAKE-refresh-token-malformed""#,
        );
        let adapter = GrokCliAdapter::with_home(temp.path());
        let err = adapter.list_accounts().expect_err("malformed must fail");
        assert!(
            matches!(err, Error::ConfigRead { ref provider, .. } if provider == PROVIDER_ID),
            "expected ConfigRead, got {err:?}"
        );
        assert_no_fake("malformed ConfigRead Display", &err.to_string());
        assert_no_fake("malformed ConfigRead Debug", &format!("{err:?}"));
    }

    #[test]
    fn entry_without_email_has_no_masked_identity() {
        let (_tmp, adapter) = adapter_over_fixture("no-email");
        let accounts = adapter.list_accounts().expect("list_accounts");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].masked_identity, None);
        assert!(!accounts[0].is_active);
        assert_no_fake("no-email list_accounts", &surfaces(&accounts));
    }

    #[test]
    fn non_object_entry_fails_the_whole_read() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_auth(
            temp.path(),
            r#"{"https://auth.example.invalid::aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaa0001":"FAKE-not-an-object"}"#,
        );
        let adapter = GrokCliAdapter::with_home(temp.path());
        let err = adapter.list_accounts().expect_err("non-object entry");
        assert!(matches!(err, Error::ConfigRead { .. }));
        assert_no_fake("non-object ConfigRead", &format!("{err} {err:?}"));
    }

    #[test]
    fn auth_mode_alone_is_unknown_not_api_key() {
        // API-key auth lives under the reserved `xai::api_key` scope, not
        // under an OIDC key's `auth_mode` field. We must not branch on
        // that field.
        let temp = tempfile::tempdir().expect("tempdir");
        write_auth(
            temp.path(),
            r#"{
              "https://auth.example.invalid::aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaa0001": {
                "auth_mode": "FAKE-auth-mode-apikey",
                "email": "FAKE-user-0001@example.invalid"
              }
            }"#,
        );
        let adapter = GrokCliAdapter::with_home(temp.path());
        let accounts = adapter.list_accounts().expect("list_accounts");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].auth_kind, AuthKind::Unknown);
        assert_eq!(
            accounts[0].masked_identity.as_deref(),
            Some("F***@example.invalid")
        );
        assert_no_fake("unknown-auth list_accounts", &surfaces(&accounts));
    }

    #[test]
    fn expires_at_is_carried_only_when_already_rfc3339() {
        let temp = tempfile::tempdir().expect("tempdir");
        write_auth(
            temp.path(),
            r#"{
              "https://auth.example.invalid::aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaa0001": {
                "email": "a@example.invalid",
                "expires_at": "not-a-timestamp",
                "oidc_issuer": "https://auth.example.invalid",
                "oidc_client_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaa0001",
                "refresh_token": "FAKE-refresh-token-0001"
              }
            }"#,
        );
        let adapter = GrokCliAdapter::with_home(temp.path());
        let accounts = adapter.list_accounts().expect("list_accounts");
        assert_eq!(accounts[0].expires_at, None);
        assert_no_fake("bad expires_at", &surfaces(&accounts));
    }

    #[test]
    fn list_accounts_skips_reserved_scopes() {
        let (_tmp, adapter) = adapter_over_fixture("reserved-scopes");
        let accounts = adapter.list_accounts().expect("list_accounts");

        assert_eq!(accounts.len(), 1);
        assert_eq!(
            accounts[0].id,
            derive_account_id("https://auth.example.invalid::aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaa0001")
        );
        assert_eq!(accounts[0].auth_kind, AuthKind::OAuth);
        assert!(!accounts[0].is_active);
        assert_no_fake("reserved-scopes list_accounts", &surfaces(&accounts));
    }

    #[test]
    fn detect_does_not_treat_a_community_cli_home_as_official() {
        let empty = tempfile::tempdir().expect("tempdir");
        let empty_state = GrokCliAdapter::with_home(empty.path()).detect();

        let community = tempfile::tempdir().expect("tempdir");
        let dir = community.path().join(".grok");
        fs::create_dir_all(&dir).expect("mkdir .grok");
        fs::write(dir.join("grok.db"), b"").expect("grok.db");
        fs::write(
            dir.join("user-settings.json"),
            r#"{"apiKey":"FAKE-community-api-key"}"#,
        )
        .expect("user-settings.json");
        let community_state = GrokCliAdapter::with_home(community.path()).detect();
        assert_eq!(
            community_state, empty_state,
            "community ~/.grok must not count as the official CLI"
        );

        let official = tempfile::tempdir().expect("tempdir");
        write_auth(official.path(), "{}");
        assert_eq!(
            GrokCliAdapter::with_home(official.path()).detect(),
            InstallState::Installed
        );
    }

    #[test]
    fn mask_email_matches_spec_shape_and_never_returns_the_input() {
        assert_eq!(
            mask_email("alice@example.com").as_deref(),
            Some("a***@example.com")
        );
        assert_eq!(
            mask_email("FAKE-user-0001@example.invalid").as_deref(),
            Some("F***@example.invalid")
        );
        assert_eq!(
            mask_email("a@example.com").as_deref(),
            Some("a***@example.com")
        );
        assert_eq!(mask_email(""), None);
        assert_eq!(mask_email("not-an-email"), None);
        assert_eq!(mask_email("@example.com"), None);
        assert_eq!(mask_email("user@"), None);
        assert_eq!(mask_email("a@b@c"), None);

        let original = "alice@example.com";
        let masked = mask_email(original).expect("maskable");
        assert_ne!(masked, original);
        assert!(!masked.contains("alice"));
    }
}
