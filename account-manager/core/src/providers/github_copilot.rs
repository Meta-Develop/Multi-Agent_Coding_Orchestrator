//! GitHub Copilot CLI adapter (`copilot`, npm `@github/copilot`).
//!
//! Evidence is `docs/research/github-copilot.md` (research PR 498). This
//! slice is detect-only. It does not parse `config.json`, does not open the
//! OS keychain, and does not run `copilot` or `gh`.
//!
//! Documented detect surfaces `[verified-docs]`:
//!
//! - the `copilot` binary (not the retired `gh copilot` extension)
//! - `~/.copilot/config.json` (application state; may hold plaintext tokens)
//! - `~/.copilot/settings.json` (user-editable settings)
//!
//! An empty `~/.copilot` directory is **not** install evidence. Other tools
//! can reuse that directory name `[inferred]`.
//!
//! `list_accounts` stays empty: `/user list` is interactive, keychain
//! contents are out of scope, and `loggedInUsers` has no proven schema.
//! `activate_account` stays [`Error::NotImplemented`]. Quota stays empty;
//! vendor list prices must not be hard-coded.

use std::path::{Path, PathBuf};

use super::{binary_on_path, home_dir, ProviderAdapter};
use crate::error::{Error, Result};
use crate::model::{Account, AuthKind, InstallState, Maturity, ProviderDescriptor};

#[derive(Debug, Default)]
pub struct GithubCopilotAdapter {
    /// Injected home directory. `None` means the real user home, which is
    /// what production uses; tests pass a `tempfile::TempDir` path so no
    /// test can read a developer's real credentials (`docs/TESTING.md` §4).
    home: Option<PathBuf>,
}

impl GithubCopilotAdapter {
    /// Root this adapter at `home` instead of the real user home.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
        }
    }

    fn resolved_home(&self) -> Option<PathBuf> {
        self.home.clone().or_else(home_dir)
    }

    fn documented_config_files(home: &Path) -> [PathBuf; 2] {
        let root = home.join(".copilot");
        [root.join("config.json"), root.join("settings.json")]
    }

    fn has_documented_config_file(&self) -> bool {
        self.resolved_home().is_some_and(|home| {
            Self::documented_config_files(&home)
                .iter()
                .any(|path| path.is_file())
        })
    }

    fn has_copilot_binary(&self) -> bool {
        match self.home.as_deref() {
            Some(home) => injected_binary(home, "copilot").is_some(),
            None => binary_on_path_for_platform("copilot"),
        }
    }
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

impl ProviderAdapter for GithubCopilotAdapter {
    fn id(&self) -> &'static str {
        "github-copilot"
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "GitHub Copilot".to_string(),
            vendor: "GitHub".to_string(),
            // Interactive login is documented as OAuth (browser or device
            // code) `[verified-docs]`. This adapter does not implement it.
            auth_kinds: vec![AuthKind::OAuth],
            maturity: Maturity::Planned,
            install_state: self.detect(),
            capabilities: Vec::new(),
        }
    }

    fn config_paths(&self) -> Vec<PathBuf> {
        let Some(home) = self.resolved_home() else {
            return Vec::new();
        };
        Self::documented_config_files(&home).to_vec()
    }

    fn detect(&self) -> InstallState {
        if self.has_copilot_binary() || self.has_documented_config_file() {
            InstallState::Installed
        } else {
            InstallState::NotInstalled
        }
    }

    fn list_accounts(&self) -> Result<Vec<Account>> {
        // No proven non-interactive identity surface. Do not parse
        // config.json, do not open the keychain, and do not run `copilot`.
        Ok(Vec::new())
    }

    fn quota(&self) -> Result<Vec<crate::model::QuotaSnapshot>> {
        Ok(Vec::new())
    }

    fn activate_account(&self, _account_id: &str) -> Result<()> {
        Err(Error::NotImplemented("github-copilot::activate_account"))
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
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        let paths = adapter.config_paths();

        assert_eq!(
            paths,
            vec![
                dir.path().join(".copilot").join("config.json"),
                dir.path().join(".copilot").join("settings.json"),
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
    fn detect_installed_when_config_json_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(&dir.path().join(".copilot").join("config.json"), b"{}");
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::Installed);
    }

    #[test]
    fn detect_installed_when_settings_json_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(&dir.path().join(".copilot").join("settings.json"), b"{}");
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::Installed);
    }

    #[test]
    fn detect_installed_when_injected_copilot_binary_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(&dir.path().join(".local").join("bin").join("copilot"), b"");
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::Installed);
    }

    #[test]
    fn detect_not_installed_on_empty_home() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::NotInstalled);
    }

    #[test]
    fn detect_not_installed_on_empty_copilot_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join(".copilot")).expect("mkdir .copilot");
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::NotInstalled);
    }

    #[test]
    fn detect_does_not_treat_an_injected_gh_binary_as_copilot() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(&dir.path().join(".local").join("bin").join("gh"), b"");
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        assert_eq!(adapter.detect(), InstallState::NotInstalled);
    }

    #[test]
    fn list_accounts_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_file(
            &dir.path().join(".copilot").join("config.json"),
            b"not-json loggedInUsers",
        );
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        let accounts = adapter.list_accounts().expect("list_accounts");
        assert!(accounts.is_empty());
    }

    #[test]
    fn activate_account_is_not_implemented() {
        let dir = tempfile::tempdir().expect("tempdir");
        let adapter = GithubCopilotAdapter::with_home(dir.path());
        let error = adapter
            .activate_account("any")
            .expect_err("activate_account");
        assert!(matches!(
            error,
            Error::NotImplemented("github-copilot::activate_account")
        ));
    }
}
