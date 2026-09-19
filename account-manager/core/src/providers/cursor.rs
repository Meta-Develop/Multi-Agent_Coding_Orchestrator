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
//! - `CURSOR_CONFIG_DIR` / `XDG_CONFIG_HOME` relocate settings, not a named
//!   credential home. Isolated HOME / login.start remain blocked (no
//!   `GROK_HOME` equivalent).
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
//! Linux/Windows persist remains [unknown]. Isolated HOME relocation is not
//! officially documented (no `GROK_HOME` equivalent). Switching stays
//! [unknown]; this adapter stays read-only.
//!
//! Cursor documents `cursor-agent status` as a read-only authentication check
//! that displays account information [verified-docs]. `list_accounts` uses
//! that vendor surface instead of treating `auth.json` or `cli-config.json` as
//! an account identity. The text markers it recognizes remain [inferred], so
//! an unfamiliar response is an error rather than evidence that no account is
//! configured.
//!
//! See `docs/research/cursor.md`.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{binary_on_path, home_dir, ProviderAdapter};
use crate::error::{Error, Result};
use crate::model::{Account, AuthKind, InstallState, Maturity, ProviderDescriptor};

const ON_DISK_ACCOUNT_ID: &str = "cursor-cli-on-disk";

#[derive(Debug, Default)]
pub struct CursorAdapter {
    /// Injected home directory. `None` means the real user home, which is
    /// what production uses; tests pass a `tempfile::TempDir` path so no
    /// test can read a developer's real credentials (`docs/TESTING.md` §4).
    home: Option<PathBuf>,
}

impl CursorAdapter {
    /// Root this adapter at `home` instead of the real user home.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
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
        "cursor"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "Cursor".to_string(),
            vendor: "Anysphere".to_string(),
            // Browser authentication is documented, but its protocol is not;
            // do not promote it to OAuth without evidence (NFR-8).
            auth_kinds: vec![AuthKind::Unknown, AuthKind::ApiKey],
            // The CLI account can be listed through `cursor-agent status`, but
            // no write-safe credential-store or mutation path is established
            // (NFR-8). File-store and official cli-config presence is detect-only.
            maturity: Maturity::Experimental,
            install_state: self.detect(),
            capabilities: Vec::new(),
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
        let Some(command) = self.cursor_agent_command() else {
            // Cursor Editor and Cursor CLI may authenticate independently
            // [unknown]. Without the CLI's documented status surface there is
            // no evidence-backed identity source to inspect.
            return Ok(Vec::new());
        };
        let output = Command::new(command)
            .arg("status")
            .output()
            .map_err(|error| {
                self.config_read(format!(
                    "cursor-agent status could not start ({})",
                    error.kind()
                ))
            })?;

        // Official documentation says `status` displays account information,
        // not credential material [verified-docs]. Never include its raw
        // stdout or stderr in an Account or error (NFR-1).
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let status = parse_status(&format!("{stdout}\n{stderr}"));
        match status {
            CursorStatus::LoggedIn { masked_identity } => Ok(vec![Account {
                id: ON_DISK_ACCOUNT_ID.to_string(),
                provider_id: self.id().to_string(),
                label: "Cursor CLI".to_string(),
                // `status` does not identify whether browser OAuth or an API
                // key supplied the current session [unknown].
                auth_kind: AuthKind::Unknown,
                masked_identity,
                is_active: true,
                is_selected_for_launch: false,
                is_stored: false,
                is_incomplete: false,
                expires_at: None,
            }]),
            CursorStatus::LoggedOut => Ok(Vec::new()),
            CursorStatus::Unknown => Err(self.config_read(if output.status.success() {
                "cursor-agent status returned an unrecognized response"
            } else {
                "cursor-agent status failed without a recognized authentication state"
            })),
        }
    }

    fn quota(&self) -> Result<Vec<crate::model::QuotaSnapshot>> {
        // Cursor's local quota signal is [unknown]; the attribution database
        // must not be treated as quota (`docs/research/cursor.md` section 6).
        Ok(Vec::new())
    }

    fn activate_account(&self, _account_id: &str) -> Result<()> {
        Err(Error::NotImplemented("cursor::activate_account"))
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderAdapter;
    use super::*;
    use std::fs;
    use std::path::Path;

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
