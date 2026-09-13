//! Gemini CLI (Google) adapter.
//!
//! API-key switching is launch-only: core stores the key in a
//! [`CredentialStore`](crate::storage::CredentialStore), persists only
//! non-secret selection metadata, and sets `GEMINI_API_KEY` on the selected
//! child. No Gemini-owned file is written.
//!
//! OAuth add writes an isolated `GEMINI_CLI_HOME` with Gemini CLI's
//! `oauth_creds.json` / `google_accounts.json` pair via in-app Google
//! loopback, and writes `settings.json` `security.auth.selectedType:
//! oauth-personal` into that isolated home only. This adapter never
//! writes the live `~/.gemini` tree. Listing may include a read-only
//! on-disk OAuth row when live `oauth_creds.json` exists. The effective
//! auth-mode gate follows the pinned first-party source in
//! `docs/research/gemini-cli.md` `[verified-source]`.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::{
    account_id_is_safe, binary_on_path, home_dir, managed_account_dir, ActivationMechanism,
    LaunchSpec, ManagedAccountPlan, ProviderAdapter, StoredAccountRegistry,
};
use crate::error::{Error, Result};
use crate::fsx;
use crate::model::{
    Account, AuthKind, InstallState, Maturity, ProviderCapability, ProviderDescriptor,
    StoredAccountMaterial, StoredAccountMetadata, StoredAccountState,
};
use crate::storage::Secret;

const PROVIDER_ID: &str = "gemini-cli";
const API_KEY_ENV: &str = "GEMINI_API_KEY";
const HOME_ENV: &str = "GEMINI_CLI_HOME";
const GCA_ENV: &str = "GOOGLE_GENAI_USE_GCA";
const API_KEY_AUTH_TYPE: &str = "gemini-api-key";
const OAUTH_AUTH_TYPE: &str = "oauth-personal";
const AMBIENT_API_KEY_ACCOUNT_ID: &str = "gemini-cli-ambient-api-key";
const LIVE_OAUTH_ACCOUNT_ID: &str = "gemini-cli-on-disk";

const REMOVED_AUTH_ENVIRONMENT: &[&str] = &[
    "GOOGLE_GENAI_USE_GCA",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_GEMINI_BASE_URL",
    "GOOGLE_API_KEY",
    "CLOUD_SHELL",
    "GEMINI_CLI_USE_COMPUTE_ADC",
];

const OAUTH_REMOVED_AUTH_ENVIRONMENT: &[&str] = &[
    "GEMINI_API_KEY",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_GEMINI_BASE_URL",
    "GOOGLE_API_KEY",
    "CLOUD_SHELL",
    "GEMINI_CLI_USE_COMPUTE_ADC",
];

type OAuthCompleter = fn(&Path) -> Result<()>;

/// `None` is production and reads process state. `Some` is a hermetic test
/// context: every environment-derived value must come from injected fields.
struct InjectedContext {
    data_dir: PathBuf,
    cwd: PathBuf,
    system_settings_path: PathBuf,
    system_defaults_path: PathBuf,
    api_key: Option<Vec<u8>>,
}

#[derive(Default)]
pub struct GeminiCliAdapter {
    /// An injected home wins over `GEMINI_CLI_HOME` and the OS home. The
    /// existing `with_home` contract also activates hermetic environment mode.
    home: Option<PathBuf>,
    injected: Option<InjectedContext>,
    test_program: Option<PathBuf>,
    /// Test seam that writes isolated OAuth files and never opens a browser.
    oauth_completer: Option<OAuthCompleter>,
}

impl fmt::Debug for GeminiCliAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GeminiCliAdapter")
            .field("home", &self.home)
            .field("injected", &self.injected.as_ref().map(|_| "<hermetic>"))
            .finish()
    }
}

impl GeminiCliAdapter {
    /// Root all test-visible state below `home` and do not inspect any process
    /// environment value. This constructor is also used by the shared adapter
    /// contract suite.
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        Self {
            injected: Some(InjectedContext {
                data_dir: home.join(".coding-agent-manager"),
                cwd: home.clone(),
                system_settings_path: home.join(".gemini-system/settings.json"),
                system_defaults_path: home.join(".gemini-system/system-defaults.json"),
                api_key: None,
            }),
            home: Some(home),
            test_program: None,
            oauth_completer: None,
        }
    }

    /// Fully injected constructor for integration fixtures. It deliberately
    /// exists outside `cfg(test)` because Rust integration tests compile the
    /// library as a dependency. Production uses `Default`.
    #[doc(hidden)]
    pub fn with_test_context(
        home: PathBuf,
        data_dir: PathBuf,
        cwd: PathBuf,
        system_settings_path: PathBuf,
        system_defaults_path: PathBuf,
        api_key: Option<&str>,
    ) -> Self {
        Self {
            home: Some(home),
            injected: Some(InjectedContext {
                data_dir,
                cwd,
                system_settings_path,
                system_defaults_path,
                api_key: api_key.map(|value| value.as_bytes().to_vec()),
            }),
            test_program: None,
            oauth_completer: None,
        }
    }

    /// Complete isolated Google sign-in without a browser or the network.
    pub fn with_oauth_completer(mut self, completer: OAuthCompleter) -> Self {
        self.oauth_completer = Some(completer);
        self
    }

    /// Replace the fixed `gemini` executable only inside an already-hermetic
    /// test adapter. This is a native test seam, never an IPC input.
    #[doc(hidden)]
    pub fn with_test_program(mut self, program: PathBuf) -> Self {
        if self.injected.is_some() {
            self.test_program = Some(program);
        }
        self
    }

    fn cwd(&self) -> Result<PathBuf> {
        let cwd = match &self.injected {
            Some(context) => context.cwd.clone(),
            None => std::env::current_dir().map_err(|error| Error::ConfigRead {
                provider: PROVIDER_ID.to_string(),
                reason: format!("the launch working directory is unavailable: {error}"),
            })?,
        };
        if !cwd.is_absolute() {
            return Err(config_read("the launch working directory is not absolute"));
        }
        Ok(cwd)
    }

    fn resolved_home_for(&self, cwd: &Path) -> Result<PathBuf> {
        let raw = if let Some(home) = &self.home {
            Some(home.clone())
        } else if let Some(env_home) = std::env::var_os("GEMINI_CLI_HOME") {
            (!env_home.is_empty()).then(|| PathBuf::from(env_home))
        } else {
            home_dir()
        }
        .ok_or_else(|| config_read("the Gemini CLI home directory could not be resolved"))?;
        Ok(absolutize(cwd, raw))
    }

    fn resolved_data_dir(&self) -> Option<PathBuf> {
        match &self.injected {
            Some(context) => Some(context.data_dir.clone()),
            None => crate::paths::project_dirs().map(|dirs| dirs.data_dir().to_path_buf()),
        }
    }

    fn settings_paths(&self, cwd: &Path, home: &Path) -> SettingsPaths {
        if let Some(context) = &self.injected {
            return SettingsPaths {
                system_defaults: absolutize(cwd, context.system_defaults_path.clone()),
                user: home.join(".gemini/settings.json"),
                workspace: cwd.join(".gemini/settings.json"),
                system: absolutize(cwd, context.system_settings_path.clone()),
            };
        }

        let (system, system_defaults) = resolve_system_settings_paths(
            cwd,
            std::env::var_os("GEMINI_CLI_SYSTEM_SETTINGS_PATH").as_deref(),
            std::env::var_os("GEMINI_CLI_SYSTEM_DEFAULTS_PATH").as_deref(),
        );
        SettingsPaths {
            system_defaults,
            user: home.join(".gemini/settings.json"),
            workspace: cwd.join(".gemini/settings.json"),
            system,
        }
    }

    fn stored_accounts(&self) -> Result<Vec<StoredAccountMetadata>> {
        let Some(data_dir) = self.resolved_data_dir() else {
            return Ok(Vec::new());
        };
        let registry = StoredAccountRegistry::new(crate::paths::stored_accounts_path(&data_dir));
        Ok(registry
            .load()?
            .into_iter()
            .filter(|account| account.provider_id == PROVIDER_ID)
            .collect())
    }

    fn api_key_is_present(&self) -> bool {
        match &self.injected {
            Some(context) => context
                .api_key
                .as_ref()
                .is_some_and(|bytes| !bytes.is_empty()),
            None => std::env::var_os(API_KEY_ENV).is_some_and(|value| !value.is_empty()),
        }
    }

    fn import_api_key(&self) -> Result<Secret> {
        let bytes = match &self.injected {
            Some(context) => context.api_key.clone(),
            None => std::env::var(API_KEY_ENV).ok().map(String::into_bytes),
        }
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| {
            Error::CredentialStoreUnavailable(
                "GEMINI_API_KEY is not set for this native process".to_string(),
            )
        })?;
        if std::str::from_utf8(&bytes).is_err() {
            return Err(Error::CredentialStoreUnavailable(
                "GEMINI_API_KEY is not valid UTF-8".to_string(),
            ));
        }
        Ok(Secret::new(bytes))
    }

    fn required_data_dir(&self) -> Result<PathBuf> {
        let directory = self
            .resolved_data_dir()
            .ok_or_else(|| config_write("application data directory unavailable"))?;
        if !directory.is_absolute() {
            return Err(config_write(
                "application data directory is not an absolute path",
            ));
        }
        Ok(directory)
    }

    fn managed_home(&self, account: &StoredAccountMetadata) -> Result<PathBuf> {
        self.validate_metadata(account)?;
        Ok(managed_account_dir(
            &self.required_data_dir()?,
            PROVIDER_ID,
            &account.id,
        ))
    }

    fn complete_oauth(&self, home: &Path) -> Result<()> {
        if let Some(completer) = self.oauth_completer {
            return completer(home);
        }
        if self.injected.is_some() {
            return Err(config_write(
                "hermetic Gemini OAuth requires an injected completer",
            ));
        }
        super::gemini_oauth::provision_managed_home(home)
    }

    fn provision_oauth_home(&self, account: &StoredAccountMetadata) -> Result<()> {
        let home = self.managed_home(account)?;
        ensure_private_managed_home(&self.required_data_dir()?, &home)?;
        match fs::symlink_metadata(oauth_creds_path(&home)) {
            Ok(_) => {
                validate_oauth_creds(&home)?;
                super::gemini_oauth::write_managed_oauth_settings(&home)?;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(config_write(format!(
                    "managed oauth_creds.json cannot be inspected ({})",
                    error.kind()
                )))
            }
        }
        self.complete_oauth(&home)?;
        validate_oauth_creds(&home)?;
        super::gemini_oauth::write_managed_oauth_settings(&home)
    }

    fn masked_oauth_identity(&self, account: &StoredAccountMetadata) -> Option<String> {
        let home = self.managed_home(account).ok()?;
        masked_active_email(&google_accounts_path(&home))
    }

    fn validate_effective_auth(&self, cwd: &Path, home: &Path, expected: &str) -> Result<()> {
        let paths = self.settings_paths(cwd, home);
        let system_defaults = read_auth_settings(&paths.system_defaults)?;
        let user = read_auth_settings(&paths.user)?;
        let workspace = if same_location(cwd, home) {
            AuthSettings::default()
        } else {
            read_auth_settings(&paths.workspace)?
        };
        let system = read_auth_settings(&paths.system)?;

        // Workspace trust is intentionally not inferred. Requiring both
        // possible merge outcomes to agree prevents an untrusted workspace
        // override from producing a false allow.
        let mut without_workspace = AuthSettings::default();
        without_workspace.overlay(system_defaults.clone());
        without_workspace.overlay(user.clone());
        without_workspace.overlay(system.clone());

        let mut with_workspace = AuthSettings::default();
        with_workspace.overlay(system_defaults);
        with_workspace.overlay(user);
        with_workspace.overlay(workspace);
        with_workspace.overlay(system);

        validate_auth_outcome(&without_workspace, expected)?;
        validate_auth_outcome(&with_workspace, expected)
    }

    fn validate_metadata(&self, account: &StoredAccountMetadata) -> Result<()> {
        if account.provider_id != PROVIDER_ID {
            return Err(Error::UnknownProvider(account.provider_id.clone()));
        }
        if !account_id_is_safe(&account.id) {
            return Err(config_read(
                "stored account metadata does not match the Gemini lifecycle",
            ));
        }
        let matches_api_key = account.auth_kind == AuthKind::ApiKey
            && account.material == StoredAccountMaterial::CredentialStore;
        let matches_oauth = account.auth_kind == AuthKind::OAuth
            && account.material == StoredAccountMaterial::VendorHome;
        if !matches_api_key && !matches_oauth {
            return Err(config_read(
                "stored account metadata does not match a Gemini lifecycle",
            ));
        }
        if account.id == LIVE_OAUTH_ACCOUNT_ID || account.id == AMBIENT_API_KEY_ACCOUNT_ID {
            return Err(config_read(
                "account id is reserved for an on-disk Gemini identity",
            ));
        }
        Ok(())
    }

    fn live_oauth_row(&self) -> Option<Account> {
        let cwd = self.cwd().ok()?;
        let home = self.resolved_home_for(&cwd).ok()?;
        if !live_oauth_creds_present(&home) {
            return None;
        }
        Some(Account {
            id: LIVE_OAUTH_ACCOUNT_ID.to_string(),
            provider_id: PROVIDER_ID.to_string(),
            label: "On-disk Gemini OAuth (not manager-stored)".to_string(),
            masked_identity: masked_active_email(&google_accounts_path(&home)),
            auth_kind: AuthKind::OAuth,
            // Presence of the live token file is not a claim about an
            // independently launched Gemini process or a file-swap switch.
            is_active: false,
            is_selected_for_launch: false,
            is_stored: false,
            is_incomplete: false,
            expires_at: None,
        })
    }

    fn stored_oauth_expiry(&self, account: &StoredAccountMetadata) -> Option<String> {
        if account.auth_kind != AuthKind::OAuth {
            return None;
        }
        let home = self.managed_home(account).ok()?;
        super::gemini_oauth::expiry_rfc3339_from_oauth_creds(&oauth_creds_path(&home))
    }
}

impl ProviderAdapter for GeminiCliAdapter {
    fn id(&self) -> &'static str {
        PROVIDER_ID
    }

    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.id().to_string(),
            display_name: "Gemini CLI".to_string(),
            vendor: "Google".to_string(),
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
        let Ok(cwd) = self.cwd() else {
            return Vec::new();
        };
        let Ok(home) = self.resolved_home_for(&cwd) else {
            return Vec::new();
        };
        let settings = self.settings_paths(&cwd, &home);
        let mut paths = vec![
            home.join(".gemini/projects.json"),
            settings.system_defaults,
            settings.user,
            settings.workspace,
            settings.system,
        ];
        paths.sort();
        paths.dedup();
        paths
    }

    fn detect(&self) -> InstallState {
        let has_config = self
            .cwd()
            .ok()
            .and_then(|cwd| self.resolved_home_for(&cwd).ok())
            .is_some_and(|home| home.join(".gemini").is_dir());
        // Hermetic adapters must not consult the real PATH (or any process
        // environment); their injected config tree is the entire test world.
        let has_binary = self.injected.is_none() && binary_on_path("gemini");
        if has_binary || has_config {
            InstallState::Installed
        } else {
            InstallState::NotInstalled
        }
    }

    fn list_accounts(&self) -> Result<Vec<Account>> {
        let metadata = self.stored_accounts()?;
        let mut accounts: Vec<Account> = metadata
            .iter()
            .map(|stored| {
                let binding_matches = matches!(
                    (stored.auth_kind, stored.material),
                    (AuthKind::ApiKey, StoredAccountMaterial::CredentialStore)
                        | (AuthKind::OAuth, StoredAccountMaterial::VendorHome)
                );
                let complete = stored.state == StoredAccountState::Complete && binding_matches;
                Account {
                    id: stored.id.clone(),
                    provider_id: PROVIDER_ID.to_string(),
                    label: stored.label.clone(),
                    masked_identity: if stored.auth_kind == AuthKind::OAuth {
                        self.masked_oauth_identity(stored)
                    } else {
                        None
                    },
                    auth_kind: stored.auth_kind,
                    // Manager selection does not claim what an independently
                    // launched Gemini process is currently using.
                    is_active: false,
                    is_selected_for_launch: complete && stored.is_selected,
                    is_stored: true,
                    is_incomplete: !complete,
                    expires_at: self.stored_oauth_expiry(stored),
                }
            })
            .collect();
        if let Some(live) = self.live_oauth_row() {
            if !accounts.iter().any(|account| account.id == live.id) {
                accounts.push(live);
            }
        }
        accounts.sort_by(|left, right| left.id.cmp(&right.id));

        // Keep the old ambient observation only when it cannot be mistaken
        // for one of the manager's durable accounts or a live on-disk OAuth
        // row. No key fragment crosses IPC, and `is_active` stays false
        // because effective cwd/settings are not established by mere
        // environment presence.
        if accounts.is_empty() && self.api_key_is_present() {
            accounts.push(Account {
                id: AMBIENT_API_KEY_ACCOUNT_ID.to_string(),
                provider_id: PROVIDER_ID.to_string(),
                label: "Ambient GEMINI_API_KEY (not manager-stored)".to_string(),
                masked_identity: None,
                auth_kind: AuthKind::ApiKey,
                is_active: false,
                is_selected_for_launch: false,
                is_stored: false,
                is_incomplete: false,
                expires_at: None,
            });
        }
        Ok(accounts)
    }

    fn activation_mechanism(&self) -> ActivationMechanism {
        ActivationMechanism::LaunchEnvironment
    }

    fn launch_spec(&self, account: &StoredAccountMetadata) -> Result<LaunchSpec> {
        self.validate_metadata(account)?;
        if account.state != StoredAccountState::Complete {
            return Err(Error::UnknownAccount(account.id.clone()));
        }
        let cwd = self.cwd()?;
        if account.auth_kind == AuthKind::OAuth {
            let home = self.managed_home(account)?;
            validate_oauth_creds(&home)?;
            self.validate_effective_auth(&cwd, &home, OAUTH_AUTH_TYPE)?;
            let mut spec = LaunchSpec::new(
                self.test_program
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("gemini")),
            )
            .current_dir(cwd)
            .set_plain_env(HOME_ENV, home.as_os_str())
            .set_plain_env(GCA_ENV, "true");
            for name in OAUTH_REMOVED_AUTH_ENVIRONMENT {
                spec = spec.remove_env(*name);
            }
            return Ok(spec);
        }

        let home = self.resolved_home_for(&cwd)?;
        self.validate_effective_auth(&cwd, &home, API_KEY_AUTH_TYPE)?;
        let mut spec = LaunchSpec::new(
            self.test_program
                .clone()
                .unwrap_or_else(|| PathBuf::from("gemini")),
        )
        .current_dir(cwd)
        .set_secret_env(API_KEY_ENV);
        for name in REMOVED_AUTH_ENVIRONMENT {
            spec = spec.remove_env(*name);
        }
        Ok(spec)
    }

    fn managed_account_plan(&self) -> Option<ManagedAccountPlan> {
        Some(ManagedAccountPlan {
            auth_kind: AuthKind::OAuth,
            material: StoredAccountMaterial::VendorHome,
        })
    }

    fn managed_account_plan_for(&self, auth_kind: AuthKind) -> Option<ManagedAccountPlan> {
        match auth_kind {
            AuthKind::OAuth => Some(ManagedAccountPlan {
                auth_kind: AuthKind::OAuth,
                material: StoredAccountMaterial::VendorHome,
            }),
            AuthKind::ApiKey => Some(ManagedAccountPlan {
                auth_kind: AuthKind::ApiKey,
                material: StoredAccountMaterial::CredentialStore,
            }),
            AuthKind::Unknown => None,
        }
    }

    fn provision_stored_account(&self, account: &StoredAccountMetadata) -> Result<Option<Secret>> {
        self.validate_metadata(account)?;
        if account.state != StoredAccountState::Pending || account.is_selected {
            return Err(config_read(
                "only an unselected pending Gemini account can be provisioned",
            ));
        }
        if account.auth_kind == AuthKind::OAuth {
            self.provision_oauth_home(account)?;
            return Ok(None);
        }
        self.import_api_key().map(Some)
    }

    fn validate_stored_account_delete(&self, account: &StoredAccountMetadata) -> Result<()> {
        self.validate_metadata(account)?;
        if account.auth_kind != AuthKind::OAuth {
            return Ok(());
        }
        let home = self.managed_home(account)?;
        match fs::symlink_metadata(&home) {
            Ok(_) => validate_directory(&home, "managed Gemini home"),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    && account.state == StoredAccountState::Pending =>
            {
                Ok(())
            }
            Err(error) => Err(config_write(format!(
                "managed Gemini home cannot be inspected ({})",
                error.kind()
            ))),
        }
    }

    fn activate_account(&self, _account_id: &str) -> Result<()> {
        // Environment-selected activation belongs to core. Direct adapter
        // activation would have no child to receive the selected key.
        Err(Error::NotImplemented("gemini-cli::activate_account"))
    }

    fn quota(&self) -> Result<Vec<crate::model::QuotaSnapshot>> {
        // Published limits do not establish a local usage signal; none was
        // observed (`docs/research/gemini-cli.md` section 6).
        Ok(Vec::new())
    }
}

#[derive(Clone, Default)]
struct AuthSettings {
    selected_type: Option<String>,
    enforced_type: Option<String>,
    use_external: Option<bool>,
}

impl AuthSettings {
    fn overlay(&mut self, later: Self) {
        if later.selected_type.is_some() {
            self.selected_type = later.selected_type;
        }
        if later.enforced_type.is_some() {
            self.enforced_type = later.enforced_type;
        }
        if later.use_external.is_some() {
            self.use_external = later.use_external;
        }
    }
}

struct SettingsPaths {
    system_defaults: PathBuf,
    user: PathBuf,
    workspace: PathBuf,
    system: PathBuf,
}

fn validate_auth_outcome(settings: &AuthSettings, expected: &str) -> Result<()> {
    if expected == API_KEY_AUTH_TYPE {
        if settings.selected_type.as_deref() != Some(API_KEY_AUTH_TYPE) {
            return Err(config_read(
                "effective security.auth.selectedType must be `gemini-api-key`",
            ));
        }
    } else if settings
        .selected_type
        .as_deref()
        .is_some_and(|value| value != expected)
    {
        return Err(config_read(
            "effective security.auth.selectedType conflicts with `oauth-personal`",
        ));
    }
    if settings
        .enforced_type
        .as_deref()
        .is_some_and(|value| value != expected)
    {
        return Err(config_read(format!(
            "effective security.auth.enforcedType conflicts with `{expected}`"
        )));
    }
    if settings.use_external == Some(true) {
        return Err(config_read(
            "effective security.auth.useExternal must not be true",
        ));
    }
    Ok(())
}

fn read_auth_settings(path: &Path) -> Result<AuthSettings> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AuthSettings::default())
        }
        Err(error) => {
            return Err(Error::ConfigRead {
                provider: PROVIDER_ID.to_string(),
                reason: format!("could not read {}: {error}", path.display()),
            })
        }
    };
    let jsonc = strip_json_comments(&raw).map_err(|reason| Error::ConfigRead {
        provider: PROVIDER_ID.to_string(),
        reason: format!(
            "{} is not valid JSON with comments: {reason}",
            path.display()
        ),
    })?;
    let value: Value = serde_json::from_str(&jsonc).map_err(|error| Error::ConfigRead {
        provider: PROVIDER_ID.to_string(),
        reason: format!("{} is not valid settings JSON: {error}", path.display()),
    })?;
    let root = value.as_object().ok_or_else(|| Error::ConfigRead {
        provider: PROVIDER_ID.to_string(),
        reason: format!("{} does not contain a settings object", path.display()),
    })?;
    extract_auth_settings(path, root)
}

fn extract_auth_settings(path: &Path, root: &Map<String, Value>) -> Result<AuthSettings> {
    let Some(security) = root.get("security") else {
        return Ok(AuthSettings::default());
    };
    let security = security
        .as_object()
        .ok_or_else(|| invalid_auth_shape(path, "security"))?;
    let Some(auth) = security.get("auth") else {
        return Ok(AuthSettings::default());
    };
    let auth = auth
        .as_object()
        .ok_or_else(|| invalid_auth_shape(path, "security.auth"))?;
    Ok(AuthSettings {
        selected_type: optional_auth_string(path, auth, "selectedType")?,
        enforced_type: optional_auth_string(path, auth, "enforcedType")?,
        use_external: optional_auth_bool(path, auth, "useExternal")?,
    })
}

fn optional_auth_string(
    path: &Path,
    auth: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>> {
    let Some(value) = auth.get(name) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid_auth_shape(path, &format!("security.auth.{name}")))?;
    if value.contains('$') {
        return Err(Error::ConfigRead {
            provider: PROVIDER_ID.to_string(),
            reason: format!(
                "{} contains an unresolved environment expression in security.auth.{name}",
                path.display()
            ),
        });
    }
    Ok(Some(value.to_string()))
}

fn optional_auth_bool(path: &Path, auth: &Map<String, Value>, name: &str) -> Result<Option<bool>> {
    let Some(value) = auth.get(name) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| invalid_auth_shape(path, &format!("security.auth.{name}")))
}

fn invalid_auth_shape(path: &Path, field: &str) -> Error {
    Error::ConfigRead {
        provider: PROVIDER_ID.to_string(),
        reason: format!("{} has unsupported {field} settings", path.display()),
    }
}

/// Strip JSON line/block comments while preserving strings and line breaks.
/// Gemini itself uses `strip-json-comments`; keeping the source length stable
/// preserves useful serde line/column diagnostics.
fn strip_json_comments(input: &str) -> std::result::Result<String, &'static str> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        String,
        LineComment,
        BlockComment,
    }

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut state = State::Normal;
    let mut escaped = false;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::Normal if byte == b'"' => {
                output.push(byte);
                state = State::String;
            }
            State::Normal if byte == b'/' && next == Some(b'/') => {
                output.extend_from_slice(b"  ");
                state = State::LineComment;
                index += 1;
            }
            State::Normal if byte == b'/' && next == Some(b'*') => {
                output.extend_from_slice(b"  ");
                state = State::BlockComment;
                index += 1;
            }
            State::String => {
                output.push(byte);
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    state = State::Normal;
                }
            }
            State::LineComment if byte == b'\n' || byte == b'\r' => {
                output.push(byte);
                state = State::Normal;
            }
            State::LineComment | State::BlockComment => {
                if state == State::BlockComment && byte == b'*' && next == Some(b'/') {
                    output.extend_from_slice(b"  ");
                    state = State::Normal;
                    index += 1;
                } else if byte == b'\n' || byte == b'\r' {
                    output.push(byte);
                } else {
                    output.push(b' ');
                }
            }
            State::Normal => output.push(byte),
        }
        index += 1;
    }
    match state {
        State::BlockComment => Err("unterminated block comment"),
        State::String => Err("unterminated string"),
        State::Normal | State::LineComment => {
            String::from_utf8(output).map_err(|_| "settings are not UTF-8")
        }
    }
}

fn absolutize(cwd: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn same_location(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

/// Pinned Gemini source (`settings.ts`) resolves the system settings override
/// first. Unless `GEMINI_CLI_SYSTEM_DEFAULTS_PATH` is explicitly present, its
/// sibling `system-defaults.json` is the defaults source. Relative overrides
/// are interpreted from the exact child cwd, as Node file I/O would do.
fn resolve_system_settings_paths(
    cwd: &Path,
    settings_override: Option<&std::ffi::OsStr>,
    defaults_override: Option<&std::ffi::OsStr>,
) -> (PathBuf, PathBuf) {
    let system = settings_override
        .map(PathBuf::from)
        .unwrap_or_else(default_system_settings_path);
    let system_defaults = defaults_override.map(PathBuf::from).unwrap_or_else(|| {
        system
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join("system-defaults.json")
    });
    (absolutize(cwd, system), absolutize(cwd, system_defaults))
}

#[cfg(target_os = "macos")]
fn default_system_settings_path() -> PathBuf {
    PathBuf::from("/Library/Application Support/GeminiCli/settings.json")
}

#[cfg(target_os = "windows")]
fn default_system_settings_path() -> PathBuf {
    PathBuf::from(r"C:\ProgramData\gemini-cli\settings.json")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn default_system_settings_path() -> PathBuf {
    PathBuf::from("/etc/gemini-cli/settings.json")
}

fn config_read(reason: impl Into<String>) -> Error {
    Error::ConfigRead {
        provider: PROVIDER_ID.to_string(),
        reason: reason.into(),
    }
}

fn config_write(reason: impl Into<String>) -> Error {
    Error::ConfigWrite {
        provider: PROVIDER_ID.to_string(),
        reason: reason.into(),
    }
}

fn oauth_creds_path(home: &Path) -> PathBuf {
    home.join(".gemini/oauth_creds.json")
}

fn google_accounts_path(home: &Path) -> PathBuf {
    home.join(".gemini/google_accounts.json")
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

fn ensure_private_managed_home(data_dir: &Path, home: &Path) -> Result<()> {
    let accounts = data_dir.join("accounts");
    let provider = accounts.join(PROVIDER_ID);
    for (directory, label) in [
        (data_dir, "application data directory"),
        (accounts.as_path(), "managed accounts directory"),
        (provider.as_path(), "Gemini provider directory"),
        (home, "managed Gemini home"),
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

/// Presence and type only. Token bytes are never read into errors or logs.
fn live_oauth_creds_present(home: &Path) -> bool {
    match fs::symlink_metadata(oauth_creds_path(home)) {
        Ok(metadata) => !metadata.file_type().is_symlink() && metadata.is_file(),
        Err(_) => false,
    }
}

/// Presence and type only. Token bytes are never read into errors or logs.
fn validate_oauth_creds(home: &Path) -> Result<()> {
    let path = oauth_creds_path(home);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        config_write(format!(
            "managed oauth_creds.json cannot be inspected ({})",
            error.kind()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(config_write(
            "managed oauth_creds.json is not a regular non-symlink file",
        ));
    }
    Ok(())
}

fn masked_active_email(path: &Path) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let value: Value = serde_json::from_str(&raw).ok()?;
    let email = value.get("active").and_then(Value::as_str)?;
    super::gemini_oauth::mask_email(email)
}

#[cfg(test)]
mod tests {
    use super::super::{add_managed_account_for, LaunchEnvironment, StoredAccountRegistry};
    use super::*;

    const TEST_KEY: &str = "FAKE-gemini-key-0001";

    fn context(api_key: Option<&str>) -> (tempfile::TempDir, GeminiCliAdapter) {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let data = dir.path().join("data");
        let cwd = dir.path().join("workspace");
        fs::create_dir_all(home.join(".gemini")).expect("home settings dir");
        fs::create_dir_all(cwd.join(".gemini")).expect("workspace settings dir");
        fs::write(
            home.join(".gemini/settings.json"),
            r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
        )
        .expect("settings");
        let adapter = GeminiCliAdapter::with_test_context(
            home,
            data,
            cwd,
            dir.path().join("system/settings.json"),
            dir.path().join("system/system-defaults.json"),
            api_key,
        );
        (dir, adapter)
    }

    fn metadata(id: &str, state: StoredAccountState) -> StoredAccountMetadata {
        StoredAccountMetadata {
            id: id.to_string(),
            provider_id: PROVIDER_ID.to_string(),
            label: "Fixture".to_string(),
            auth_kind: AuthKind::ApiKey,
            state,
            material: StoredAccountMaterial::CredentialStore,
            is_selected: false,
        }
    }

    #[test]
    fn injected_context_never_exposes_key_in_debug_or_account_output() {
        let (_dir, adapter) = context(Some(TEST_KEY));
        assert!(!format!("{adapter:?}").contains(TEST_KEY));
        let accounts = adapter.list_accounts().expect("accounts");
        let output = format!(
            "{:?} {}",
            accounts,
            serde_json::to_string(&accounts).expect("json")
        );
        assert!(!output.contains(TEST_KEY));
        assert!(!output.contains("FAKE-"));
    }

    #[test]
    fn provision_returns_native_secret_only_for_pending_bound_metadata() {
        let (_dir, adapter) = context(Some(TEST_KEY));
        let secret = adapter
            .provision_stored_account(&metadata("work", StoredAccountState::Pending))
            .expect("provision")
            .expect("secret");
        assert_eq!(secret.expose(), TEST_KEY.as_bytes());

        assert!(adapter
            .provision_stored_account(&metadata("work", StoredAccountState::Complete))
            .is_err());
        let mut wrong = metadata("work", StoredAccountState::Pending);
        wrong.provider_id = "other".to_string();
        assert!(adapter.provision_stored_account(&wrong).is_err());
    }

    #[test]
    fn launch_declaration_has_fixed_program_exact_cwd_and_child_only_env() {
        let (_dir, adapter) = context(None);
        let account = metadata("work", StoredAccountState::Complete);
        let spec = adapter.launch_spec(&account).expect("launch spec");

        assert_eq!(spec.program, PathBuf::from("gemini"));
        assert!(spec.args.is_empty());
        assert_eq!(
            spec.working_directory.as_deref(),
            adapter.cwd().ok().as_deref()
        );
        let mut secret = Vec::new();
        let mut removed = Vec::new();
        for entry in spec.environment {
            match entry {
                LaunchEnvironment::SetSecret { name } => secret.push(name),
                LaunchEnvironment::Remove { name } => removed.push(name),
                LaunchEnvironment::SetPlain { name, .. } => {
                    panic!("unexpected public environment {name}")
                }
            }
        }
        assert_eq!(secret, vec![API_KEY_ENV.to_string()]);
        assert_eq!(removed, REMOVED_AUTH_ENVIRONMENT);
    }

    #[test]
    fn system_defaults_are_sibling_unless_explicitly_overridden() {
        let cwd = Path::new("/fixture/workspace");
        let (system, defaults) = resolve_system_settings_paths(
            cwd,
            Some(std::ffi::OsStr::new("policy/settings.json")),
            None,
        );
        assert_eq!(system, cwd.join("policy/settings.json"));
        assert_eq!(defaults, cwd.join("policy/system-defaults.json"));

        let (system, defaults) = resolve_system_settings_paths(
            cwd,
            Some(std::ffi::OsStr::new("policy/settings.json")),
            Some(std::ffi::OsStr::new("defaults/locked.json")),
        );
        assert_eq!(system, cwd.join("policy/settings.json"));
        assert_eq!(defaults, cwd.join("defaults/locked.json"));
    }

    #[test]
    fn settings_precedence_and_workspace_trust_both_fail_closed() {
        let (dir, adapter) = context(None);
        let account = metadata("work", StoredAccountState::Complete);
        let workspace = adapter.cwd().expect("cwd").join(".gemini/settings.json");
        fs::write(
            &workspace,
            r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#,
        )
        .expect("workspace settings");
        assert!(adapter.launch_spec(&account).is_err());

        fs::create_dir_all(dir.path().join("system")).expect("system dir");
        fs::write(
            dir.path().join("system/settings.json"),
            r#"{"security":{"auth":{"selectedType":"gemini-api-key","enforcedType":"gemini-api-key"}}}"#,
        )
        .expect("system settings");
        assert!(adapter.launch_spec(&account).is_ok());
    }

    #[test]
    fn json_comments_are_supported_but_malformed_or_dynamic_auth_refuses() {
        let (_dir, adapter) = context(None);
        let account = metadata("work", StoredAccountState::Complete);
        let user = adapter
            .resolved_home_for(&adapter.cwd().expect("cwd"))
            .expect("home")
            .join(".gemini/settings.json");
        fs::write(
            &user,
            "{ // comment\n\"security\": {\"auth\": {\"selectedType\": \"gemini-api-key\"}}}\n",
        )
        .expect("jsonc");
        assert!(adapter.launch_spec(&account).is_ok());

        fs::write(&user, "{ /* unterminated").expect("malformed");
        assert!(adapter.launch_spec(&account).is_err());

        fs::write(
            &user,
            r#"{"security":{"auth":{"selectedType":"${GEMINI_DEFAULT_AUTH_TYPE}"}}}"#,
        )
        .expect("dynamic");
        assert!(adapter.launch_spec(&account).is_err());
    }

    fn oauth_metadata(id: &str, state: StoredAccountState) -> StoredAccountMetadata {
        StoredAccountMetadata {
            id: id.to_string(),
            provider_id: PROVIDER_ID.to_string(),
            label: "Fixture".to_string(),
            auth_kind: AuthKind::OAuth,
            state,
            material: StoredAccountMaterial::VendorHome,
            is_selected: false,
        }
    }

    fn write_oauth_files(home: &Path) -> Result<()> {
        super::super::gemini_oauth::write_fake_oauth_home(home, None)
    }

    fn write_oauth_files_with_email(home: &Path) -> Result<()> {
        super::super::gemini_oauth::write_fake_oauth_home(
            home,
            Some("FAKE-user-0001@example.invalid"),
        )
    }

    fn fail_oauth(_home: &Path) -> Result<()> {
        Err(config_write("injected Gemini OAuth completer failed"))
    }

    fn empty_oauth(_home: &Path) -> Result<()> {
        Ok(())
    }

    fn panic_oauth(_home: &Path) -> Result<()> {
        panic!("a structurally complete pending home must not run OAuth again")
    }

    fn oauth_adapter(completer: OAuthCompleter) -> (tempfile::TempDir, GeminiCliAdapter) {
        let (dir, adapter) = context(None);
        (dir, adapter.with_oauth_completer(completer))
    }

    fn registry_for(adapter: &GeminiCliAdapter) -> StoredAccountRegistry {
        StoredAccountRegistry::new(crate::paths::stored_accounts_path(
            &adapter.resolved_data_dir().expect("data dir"),
        ))
    }

    fn assert_no_fake(where_: &str, text: &str) {
        assert!(
            !text.contains("FAKE-"),
            "{where_} leaked fixture secret material: {text}"
        );
    }

    #[test]
    fn oauth_completer_lists_complete_account_without_leaking() {
        let (_dir, adapter) = oauth_adapter(write_oauth_files);
        add_managed_account_for(
            &registry_for(&adapter),
            &adapter,
            "work",
            "Work",
            None,
            Some(AuthKind::OAuth),
        )
        .expect("oauth add");
        let accounts = adapter.list_accounts().expect("list");
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].auth_kind, AuthKind::OAuth);
        assert!(accounts[0].is_stored);
        assert!(!accounts[0].is_incomplete);
        assert_eq!(accounts[0].masked_identity, None);
        assert_eq!(
            accounts[0].expires_at.as_deref(),
            Some("2023-11-14T22:13:20Z")
        );
        let surfaces = format!(
            "{accounts:?} {}",
            serde_json::to_string(&accounts).expect("json")
        );
        assert_no_fake("oauth list", &surfaces);
        assert!(!format!("{adapter:?}").contains("FAKE-"));
    }

    #[test]
    fn oauth_active_email_is_masked_and_old_is_not_a_second_account() {
        let (_dir, adapter) = oauth_adapter(write_oauth_files_with_email);
        add_managed_account_for(
            &registry_for(&adapter),
            &adapter,
            "work",
            "Work",
            None,
            Some(AuthKind::OAuth),
        )
        .expect("oauth add");
        let accounts = adapter.list_accounts().expect("list");
        assert_eq!(accounts.len(), 1);
        let masked = accounts[0]
            .masked_identity
            .as_deref()
            .expect("masked identity");
        assert!(masked.contains("***@"), "identity was not masked: {masked}");
        assert!(!masked.contains("FAKE-user-0001"));
        assert_ne!(masked, "FAKE-user-0001@example.invalid");
        let surfaces = format!(
            "{accounts:?} {}",
            serde_json::to_string(&accounts).expect("json")
        );
        assert_no_fake("masked oauth list", &surfaces);
        assert!(!surfaces.contains("FAKE-user-0001@example.invalid"));
    }

    #[test]
    fn oauth_failure_or_missing_creds_is_not_complete() {
        let (_dir, adapter) = oauth_adapter(fail_oauth);
        let error = add_managed_account_for(
            &registry_for(&adapter),
            &adapter,
            "work",
            "Work",
            None,
            Some(AuthKind::OAuth),
        )
        .expect_err("failed oauth");
        assert_no_fake("oauth failure", &format!("{error} {error:?}"));
        let accounts = adapter.list_accounts().expect("list pending");
        assert!(accounts.iter().all(|account| account.is_incomplete));
        assert!(accounts
            .iter()
            .all(|account| !account.is_selected_for_launch));

        let (_dir, adapter) = oauth_adapter(empty_oauth);
        let error = add_managed_account_for(
            &registry_for(&adapter),
            &adapter,
            "missing",
            "Missing",
            None,
            Some(AuthKind::OAuth),
        )
        .expect_err("missing creds");
        assert_no_fake("missing creds", &format!("{error} {error:?}"));
        let accounts = adapter.list_accounts().expect("list missing");
        assert!(accounts
            .iter()
            .find(|account| account.id == "missing")
            .is_some_and(|account| account.is_incomplete));
    }

    #[test]
    fn oauth_recovery_revalidates_without_a_second_flow() {
        let (dir, adapter) = oauth_adapter(panic_oauth);
        let home = managed_account_dir(
            &adapter.resolved_data_dir().expect("data dir"),
            PROVIDER_ID,
            "work",
        );
        ensure_private_managed_home(&adapter.resolved_data_dir().expect("data dir"), &home)
            .expect("home");
        write_oauth_files(&home).expect("existing creds");
        let _ = dir;
        adapter
            .provision_stored_account(&oauth_metadata("work", StoredAccountState::Pending))
            .expect("recovery");
        let settings: Value = serde_json::from_slice(
            &fs::read(home.join(".gemini/settings.json")).expect("recovered settings"),
        )
        .expect("settings json");
        assert_eq!(
            settings["security"]["auth"]["selectedType"],
            "oauth-personal"
        );
    }

    #[test]
    fn oauth_add_writes_only_the_managed_directory() {
        let (_dir, adapter) = oauth_adapter(write_oauth_files);
        let home = managed_account_dir(
            &adapter.resolved_data_dir().expect("data dir"),
            PROVIDER_ID,
            "work",
        );
        adapter
            .provision_stored_account(&oauth_metadata("work", StoredAccountState::Pending))
            .expect("provision");
        assert!(oauth_creds_path(&home).is_file());
        let managed_settings: Value = serde_json::from_slice(
            &fs::read(home.join(".gemini/settings.json")).expect("managed settings"),
        )
        .expect("settings json");
        assert_eq!(
            managed_settings["security"]["auth"]["selectedType"],
            "oauth-personal"
        );
        let live = adapter
            .resolved_home_for(&adapter.cwd().expect("cwd"))
            .expect("live home");
        assert!(!oauth_creds_path(&live).exists());
        let live_settings = fs::read_to_string(live.join(".gemini/settings.json")).expect("live");
        assert!(live_settings.contains("gemini-api-key"));
        assert!(!live_settings.contains("oauth-personal"));
    }

    fn write_live_oauth_files(home: &Path, email: Option<&str>) {
        let dir = home.join(".gemini");
        fs::create_dir_all(&dir).expect("live gemini dir");
        fs::write(
            dir.join("oauth_creds.json"),
            br#"{"access_token":"FAKE-live-oauth-access-0001","expiry_date":1700000000000}"#,
        )
        .expect("live creds");
        if let Some(email) = email {
            let document = serde_json::json!({
                "active": email,
                "old": ["FAKE-old-user-0002@example.invalid"]
            });
            fs::write(
                dir.join("google_accounts.json"),
                serde_json::to_vec_pretty(&document).expect("accounts json"),
            )
            .expect("live accounts");
        }
    }

    fn live_tree(home: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        let root = home.join(".gemini");
        let mut entries: Vec<_> = fs::read_dir(&root)
            .expect("live dir")
            .map(|entry| entry.expect("entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_file() {
                files.push((
                    path.strip_prefix(home).expect("relative").to_path_buf(),
                    fs::read(&path).expect("read"),
                ));
            }
        }
        files
    }

    #[test]
    fn live_oauth_lists_one_on_disk_row_and_does_not_write() {
        let (_dir, adapter) = context(None);
        let live = adapter
            .resolved_home_for(&adapter.cwd().expect("cwd"))
            .expect("live home");
        write_live_oauth_files(&live, Some("FAKE-user-0001@example.invalid"));
        let before = live_tree(&live);
        let accounts = adapter.list_accounts().expect("list");
        assert_eq!(after_list_ids(&accounts), vec![LIVE_OAUTH_ACCOUNT_ID]);
        assert_eq!(accounts[0].auth_kind, AuthKind::OAuth);
        assert!(!accounts[0].is_stored);
        assert!(!accounts[0].is_selected_for_launch);
        assert!(!accounts[0].is_active);
        assert!(!accounts[0].is_incomplete);
        assert_eq!(accounts[0].expires_at, None);
        let masked = accounts[0]
            .masked_identity
            .as_deref()
            .expect("masked identity");
        assert!(masked.contains("***@"), "identity was not masked: {masked}");
        assert!(!masked.contains("FAKE-user-0001"));
        let surfaces = format!(
            "{accounts:?} {}",
            serde_json::to_string(&accounts).expect("json")
        );
        assert_no_fake("live oauth list", &surfaces);
        assert!(!surfaces.contains("FAKE-old-user-0002@example.invalid"));
        assert_eq!(before, live_tree(&live));
    }

    #[test]
    fn live_oauth_and_stored_oauth_list_as_separate_rows() {
        let (_dir, adapter) = oauth_adapter(write_oauth_files_with_email);
        add_managed_account_for(
            &registry_for(&adapter),
            &adapter,
            "work",
            "Work",
            None,
            Some(AuthKind::OAuth),
        )
        .expect("oauth add");
        let live = adapter
            .resolved_home_for(&adapter.cwd().expect("cwd"))
            .expect("live home");
        write_live_oauth_files(&live, Some("FAKE-live-0003@example.invalid"));
        let accounts = adapter.list_accounts().expect("list");
        assert_eq!(
            after_list_ids(&accounts),
            vec![LIVE_OAUTH_ACCOUNT_ID, "work"]
        );
        let live_row = accounts
            .iter()
            .find(|account| account.id == LIVE_OAUTH_ACCOUNT_ID)
            .expect("live");
        let stored = accounts
            .iter()
            .find(|account| account.id == "work")
            .expect("stored");
        assert!(!live_row.is_stored);
        assert!(stored.is_stored);
        assert_eq!(stored.expires_at.as_deref(), Some("2023-11-14T22:13:20Z"));
        let surfaces = format!(
            "{accounts:?} {}",
            serde_json::to_string(&accounts).expect("json")
        );
        assert_no_fake("live plus stored", &surfaces);
    }

    #[test]
    fn reserved_on_disk_ids_cannot_be_stored() {
        let (_dir, adapter) = oauth_adapter(write_oauth_files);
        let mut live_id = oauth_metadata(LIVE_OAUTH_ACCOUNT_ID, StoredAccountState::Pending);
        assert!(adapter.provision_stored_account(&live_id).is_err());
        live_id.id = AMBIENT_API_KEY_ACCOUNT_ID.to_string();
        assert!(adapter.provision_stored_account(&live_id).is_err());
    }

    fn after_list_ids(accounts: &[Account]) -> Vec<&str> {
        accounts.iter().map(|account| account.id.as_str()).collect()
    }

    #[test]
    fn oauth_launch_spec_sets_home_and_gca_and_removes_competing_auth() {
        let (_dir, adapter) = oauth_adapter(write_oauth_files);
        add_managed_account_for(
            &registry_for(&adapter),
            &adapter,
            "work",
            "Work",
            None,
            Some(AuthKind::OAuth),
        )
        .expect("oauth add");
        let mut account = oauth_metadata("work", StoredAccountState::Complete);
        account.is_selected = true;
        let spec = adapter.launch_spec(&account).expect("oauth launch");
        assert_eq!(spec.program, PathBuf::from("gemini"));
        assert!(spec.args.is_empty());
        assert_eq!(
            spec.working_directory.as_deref(),
            adapter.cwd().ok().as_deref()
        );
        let home = managed_account_dir(
            &adapter.resolved_data_dir().expect("data dir"),
            PROVIDER_ID,
            "work",
        );
        let mut plain = Vec::new();
        let mut removed = Vec::new();
        for entry in spec.environment {
            match entry {
                LaunchEnvironment::SetPlain { name, value } => {
                    plain.push((name, value));
                }
                LaunchEnvironment::Remove { name } => removed.push(name),
                LaunchEnvironment::SetSecret { name } => {
                    panic!("unexpected secret environment {name}")
                }
            }
        }
        assert_eq!(
            plain,
            vec![
                (HOME_ENV.to_string(), home.into_os_string()),
                (GCA_ENV.to_string(), "true".into()),
            ]
        );
        assert_eq!(removed, OAUTH_REMOVED_AUTH_ENVIRONMENT);
        assert!(!removed.iter().any(|name| name == GCA_ENV));
    }

    #[test]
    fn oauth_launch_refuses_conflicting_or_external_auth() {
        let (dir, adapter) = oauth_adapter(write_oauth_files);
        add_managed_account_for(
            &registry_for(&adapter),
            &adapter,
            "work",
            "Work",
            None,
            Some(AuthKind::OAuth),
        )
        .expect("oauth add");
        let account = oauth_metadata("work", StoredAccountState::Complete);
        assert!(adapter.launch_spec(&account).is_ok());

        let workspace = adapter.cwd().expect("cwd").join(".gemini/settings.json");
        fs::write(
            &workspace,
            r#"{"security":{"auth":{"selectedType":"gemini-api-key"}}}"#,
        )
        .expect("workspace api-key");
        assert!(adapter.launch_spec(&account).is_err());

        fs::write(
            &workspace,
            r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#,
        )
        .expect("workspace oauth");
        assert!(adapter.launch_spec(&account).is_ok());

        fs::create_dir_all(dir.path().join("system")).expect("system dir");
        fs::write(
            dir.path().join("system/settings.json"),
            r#"{"security":{"auth":{"enforcedType":"gemini-api-key"}}}"#,
        )
        .expect("enforced api-key");
        assert!(adapter.launch_spec(&account).is_err());

        fs::write(
            dir.path().join("system/settings.json"),
            r#"{"security":{"auth":{"selectedType":"oauth-personal","useExternal":true}}}"#,
        )
        .expect("external");
        assert!(adapter.launch_spec(&account).is_err());
    }

    #[test]
    fn default_plan_is_oauth_and_api_key_plan_remains_available() {
        let (_dir, adapter) = context(None);
        let default = adapter.managed_account_plan().expect("default");
        assert_eq!(default.auth_kind, AuthKind::OAuth);
        assert_eq!(default.material, StoredAccountMaterial::VendorHome);
        let api_key = adapter
            .managed_account_plan_for(AuthKind::ApiKey)
            .expect("api-key");
        assert_eq!(api_key.auth_kind, AuthKind::ApiKey);
        assert_eq!(api_key.material, StoredAccountMaterial::CredentialStore);
        assert!(adapter
            .provision_stored_account(&oauth_metadata("work", StoredAccountState::Pending))
            .is_err());
    }
}
