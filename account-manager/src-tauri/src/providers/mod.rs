//! Provider adapters.
//!
//! Every managed agent tool is reached through exactly one [`ProviderAdapter`].
//! Core code never special-cases a vendor; adding a tool means adding a module
//! here and one line in [`registry`]. See `docs/ARCHITECTURE.md`.
//!
//! Config-path claims in these modules carry a confidence marker matching
//! `docs/research/`:
//! `[verified-local]` observed on a real installation, `[verified-docs]` from
//! official documentation, `[inferred]` reasoned but unconfirmed,
//! `[unknown]` not yet established. Never upgrade a marker without evidence.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::error::{Error, Result};
use crate::model::{
    Account, AuthKind, InstallState, ProviderDescriptor, QuotaSnapshot, StoredAccountMaterial,
    StoredAccountMetadata, StoredAccountState,
};
use crate::storage::{CredentialStore, Secret, SecretRef};

pub use crate::account_authority::{
    SelectedAccountBinding, SelectedUseLease, StoredAccountRegistry,
};

pub mod claude_code;
pub mod codex_cli;
pub mod cursor;
pub mod gemini_cli;
mod gemini_oauth;
pub mod grok_cli;

/// How activating an account changes what the provider tool will use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationMechanism {
    /// The adapter atomically updates the vendor's live configuration.
    ToolConfiguration,
    /// Core persists a selection which is consumed only by an app-launched
    /// child process through [`ProviderAdapter::launch_spec`].
    LaunchEnvironment,
}

/// Non-secret declaration for the core-owned account lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedAccountPlan {
    pub auth_kind: AuthKind,
    pub material: StoredAccountMaterial,
}

/// One environment action declared by an adapter for a launched child.
///
/// Secret material is never carried here. `Secret` means core derives a
/// [`SecretRef`] from the selected account and resolves it immediately before
/// spawning the child.
#[derive(Clone)]
enum LaunchEnvironment {
    SetPlain { name: String, value: OsString },
    SetSecret { name: String },
    Remove { name: String },
}

/// Complete adapter-declared command for an environment-selected account.
///
/// This type deliberately implements neither `Serialize` nor `Debug`: program
/// arguments and environment values are native-core data, never IPC payloads.
#[derive(Clone)]
pub struct LaunchSpec {
    program: PathBuf,
    args: Vec<OsString>,
    environment: Vec<LaunchEnvironment>,
    working_directory: Option<PathBuf>,
}

impl LaunchSpec {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            environment: Vec::new(),
            working_directory: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Set the exact workspace whose provider settings apply to this launch.
    pub fn current_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(directory.into());
        self
    }

    /// Set public, non-secret environment data such as a selected home path.
    pub fn set_plain_env(mut self, name: impl Into<String>, value: impl Into<OsString>) -> Self {
        self.environment.push(LaunchEnvironment::SetPlain {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    /// Set one variable from the selected account's credential at spawn time.
    pub fn set_secret_env(mut self, name: impl Into<String>) -> Self {
        self.environment
            .push(LaunchEnvironment::SetSecret { name: name.into() });
        self
    }

    /// Remove an inherited variable which would override the selected account.
    pub fn remove_env(mut self, name: impl Into<String>) -> Self {
        self.environment
            .push(LaunchEnvironment::Remove { name: name.into() });
        self
    }

    pub fn requires_credential(&self) -> bool {
        self.environment
            .iter()
            .any(|entry| matches!(entry, LaunchEnvironment::SetSecret { .. }))
    }
}

/// The contract every managed tool must satisfy.
///
/// Implementations must be side-effect free except in [`activate_account`],
/// [`add_account`], [`delete_account`], and [`provision_stored_account`].
/// [`activate_account`] must write a recoverable backup before it replaces any
/// file the user's tool owns (NFR-4 in `docs/SPEC.md`). Core-managed lifecycle
/// hooks are journaled by [`StoredAccountRegistry`].
pub trait ProviderAdapter: Send + Sync {
    /// Stable identifier used in config, IPC, and on disk. Never renamed.
    fn id(&self) -> &'static str;

    /// Static description of the provider, independent of machine state.
    fn descriptor(&self) -> ProviderDescriptor;

    /// Files and directories this adapter reads or writes on this host.
    ///
    /// Used by diagnostics and by the backup subsystem. Paths that do not exist
    /// are still returned, so the caller can report what was expected.
    fn config_paths(&self) -> Vec<PathBuf>;

    /// Whether the tool appears to be installed on this machine.
    fn detect(&self) -> InstallState;

    /// Accounts the adapter can see, including the currently active one.
    fn list_accounts(&self) -> Result<Vec<Account>>;

    /// Whether activation writes vendor config or selects launch environment.
    ///
    /// Existing adapters keep their file-based behaviour by default. An
    /// environment-selected adapter must also implement [`launch_spec`].
    fn activation_mechanism(&self) -> ActivationMechanism {
        ActivationMechanism::ToolConfiguration
    }

    /// Declare the child command and exact environment selection for `account`.
    ///
    /// Core owns applying this declaration to a child process. Implementations
    /// must never mutate the application process environment.
    fn launch_spec(&self, _account: &StoredAccountMetadata) -> Result<LaunchSpec> {
        Err(Error::NotImplemented("launch_account"))
    }

    /// Opt into the core-owned stored-account lifecycle.
    ///
    /// `None` preserves legacy adapter-owned add/delete behavior. Managed
    /// adapters must implement both lifecycle hooks below.
    fn managed_account_plan(&self) -> Option<ManagedAccountPlan> {
        None
    }

    /// Plan for one requested auth kind, if this adapter manages that kind.
    ///
    /// The default keeps a single-plan adapter working: it returns the
    /// adapter's only plan when the kind matches, otherwise `None`.
    fn managed_account_plan_for(&self, auth_kind: AuthKind) -> Option<ManagedAccountPlan> {
        self.managed_account_plan()
            .filter(|plan| plan.auth_kind == auth_kind)
    }

    /// Provision material for a core-owned pending account.
    ///
    /// A credential-backed provider returns a `Secret` acquired entirely in
    /// native code. A vendor-home provider writes only its managed vendor home
    /// and returns `None`. The default fails closed.
    fn provision_stored_account(&self, _account: &StoredAccountMetadata) -> Result<Option<Secret>> {
        Err(Error::NotImplemented("provision_stored_account"))
    }

    /// Read-only refusal/gating hook run before deletion becomes durable.
    ///
    /// A vendor-home implementation may check locks or active sessions, but
    /// must retain that home. Core deletes credential-store material and then
    /// forgets metadata. The default fails closed.
    fn validate_stored_account_delete(&self, _account: &StoredAccountMetadata) -> Result<()> {
        Err(Error::NotImplemented("validate_stored_account_delete"))
    }

    /// Make `account_id` the account the tool will use on its next start.
    ///
    /// Must be atomic from the tool's point of view: either the switch fully
    /// happened or the previous state is intact.
    fn activate_account(&self, account_id: &str) -> Result<()>;

    /// Legacy adapter-owned creation of a stored account named `account_id`.
    ///
    /// May be long-running and interactive: an implementation may spawn the
    /// vendor tool's own login so the user can complete a browser sign-in at
    /// that tool's prompts. Stdio is inherited; this application does not
    /// compose, parse, or log credential material.
    ///
    /// A provider may create an isolated vendor-written managed home, but must
    /// not mutate the home currently used by externally launched tools. A
    /// failed attempt must remain recoverable.
    ///
    /// The default returns [`Error::NotImplemented`] so an adapter that has
    /// not grown this method cannot be mistaken for one that has (NFR-8).
    fn add_account(&self, _account_id: &str) -> Result<()> {
        Err(Error::NotImplemented("add_account"))
    }

    /// Legacy adapter-owned deletion. Provider-specific semantics apply; core-
    /// managed environment accounts use the hook above and retain vendor homes.
    ///
    /// The default returns [`Error::NotImplemented`] so an adapter that has
    /// not grown this method cannot be mistaken for one that has (NFR-8).
    fn delete_account(&self, _account_id: &str) -> Result<()> {
        Err(Error::NotImplemented("delete_account"))
    }

    /// Quota signals the provider exposes, if any.
    ///
    /// Returning an empty vector is correct and expected for providers that
    /// publish no usable signal. Never synthesise a number.
    fn quota(&self) -> Result<Vec<QuotaSnapshot>> {
        Ok(Vec::new())
    }

    /// Optional non-secret plan label sourced independently of quota usage.
    ///
    /// A plan name never implies that a numeric quota signal exists.
    fn plan_label(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Spawn an adapter-declared provider process for a selected account.
///
/// Stdio is inherited and never captured. Secret values are retrieved only for
/// `SetSecret` entries immediately before `spawn`, applied only to this
/// `Command`, and never included in an error or return value.
pub fn spawn_launch(
    spec: LaunchSpec,
    account: &StoredAccountMetadata,
    credential_store: Option<&dyn CredentialStore>,
) -> Result<Child> {
    if account.state != StoredAccountState::Complete || !account.is_selected {
        return Err(Error::ConfigWrite {
            provider: account.provider_id.clone(),
            reason: format!(
                "account `{}` is not a selected complete account",
                account.id
            ),
        });
    }

    validate_launch_environment(&spec, account)?;

    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .current_dir(
            spec.working_directory
                .as_ref()
                .expect("validated launch working directory"),
        )
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    for entry in spec.environment {
        match entry {
            LaunchEnvironment::SetPlain { name, value } => {
                command.env(name, value);
            }
            LaunchEnvironment::SetSecret { name } => {
                let store = credential_store.ok_or_else(|| {
                    Error::CredentialStoreUnavailable(
                        "the selected launch requires a credential store".to_string(),
                    )
                })?;
                let key = SecretRef::for_account(&account.provider_id, &account.id);
                let secret = store
                    .get(&key)?
                    .ok_or_else(|| Error::UnknownAccount(account.id.clone()))?;
                let value = std::str::from_utf8(secret.expose()).map_err(|_| {
                    Error::CredentialStoreUnavailable(
                        "the selected credential is not valid UTF-8".to_string(),
                    )
                })?;
                command.env(name, value);
            }
            LaunchEnvironment::Remove { name } => {
                command.env_remove(name);
            }
        }
    }

    command.spawn().map_err(|error| Error::ConfigWrite {
        provider: account.provider_id.clone(),
        reason: format!(
            "could not start {}: {error}",
            spec.program
                .file_name()
                .unwrap_or_else(|| OsStr::new("provider tool"))
                .to_string_lossy()
        ),
    })
}

/// Validate the adapter/account binding before asking an adapter to declare a
/// launch. This prevents metadata for one provider from selecting another
/// provider's credential or home.
pub fn launch_spec_for(
    adapter: &dyn ProviderAdapter,
    account: &StoredAccountMetadata,
) -> Result<LaunchSpec> {
    if adapter.activation_mechanism() != ActivationMechanism::LaunchEnvironment {
        return Err(Error::NotImplemented("launch_provider"));
    }
    if account.state != StoredAccountState::Complete {
        return Err(Error::UnknownAccount(account.id.clone()));
    }
    if account.provider_id != adapter.id() {
        return Err(Error::UnknownProvider(account.provider_id.clone()));
    }
    let spec = adapter.launch_spec(account)?;
    validate_launch_environment(&spec, account)?;
    Ok(spec)
}

/// Validate an environment-driven selection before persisting it.
///
/// Adapters may use `launch_spec` to refuse a vendor lock, active session, or
/// incompatible local setting. Selection is written only after that read-only
/// validation succeeds. Launch validates again to close the staleness window.
pub fn select_launch_account(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    account_id: &str,
) -> Result<()> {
    let target = registry.complete(adapter.id(), account_id)?;
    if let Some(current) = registry.selected(adapter.id())? {
        if current.id != target.id {
            let _validated_current = launch_spec_for(adapter, &current)?;
        }
    }
    let _validated_target = launch_spec_for(adapter, &target)?;
    registry.select_complete(adapter.id(), account_id)
}

/// Run the provider-neutral add transaction around adapter provisioning.
pub fn add_managed_account(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    account_id: &str,
    label: &str,
    credential_store: Option<&dyn CredentialStore>,
) -> Result<()> {
    add_managed_account_for(registry, adapter, account_id, label, credential_store, None)
}

/// Pending metadata is durable before a provider can create material. Secrets
/// returned by native provider code go directly to `CredentialStore`; they are
/// never serialized or returned to commands/UI.
///
/// `None` uses [`ProviderAdapter::managed_account_plan`]. A supplied kind uses
/// [`ProviderAdapter::managed_account_plan_for`].
pub fn add_managed_account_for(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    account_id: &str,
    label: &str,
    credential_store: Option<&dyn CredentialStore>,
    auth_kind: Option<AuthKind>,
) -> Result<()> {
    let plan = match auth_kind {
        Some(kind) => adapter
            .managed_account_plan_for(kind)
            .ok_or(Error::NotImplemented("add_managed_account"))?,
        None => adapter
            .managed_account_plan()
            .ok_or(Error::NotImplemented("add_managed_account"))?,
    };
    let account = registry.begin_add(
        adapter.id(),
        account_id,
        label,
        plan.auth_kind,
        plan.material,
    )?;
    let provisioned = adapter.provision_stored_account(&account)?;
    match (plan.material, provisioned) {
        (StoredAccountMaterial::CredentialStore, Some(secret)) => {
            let store = credential_store.ok_or_else(|| {
                Error::CredentialStoreUnavailable(
                    "adding this account requires a credential store".to_string(),
                )
            })?;
            store.put(&SecretRef::for_account(adapter.id(), account_id), &secret)?;
        }
        (StoredAccountMaterial::CredentialStore, None) => {
            return Err(metadata_write_error(
                adapter.id(),
                "provider did not return required credential material",
            ));
        }
        (StoredAccountMaterial::VendorHome, None) => {}
        (StoredAccountMaterial::VendorHome, Some(_secret)) => {
            return Err(metadata_write_error(
                adapter.id(),
                "provider returned credential material for a vendor-home account",
            ));
        }
    }
    registry.complete_add(adapter.id(), account_id)
}

/// Run the provider-neutral delete transaction while retaining vendor homes.
pub fn delete_managed_account(
    registry: &StoredAccountRegistry,
    adapter: &dyn ProviderAdapter,
    account_id: &str,
    credential_store: Option<&dyn CredentialStore>,
) -> Result<()> {
    let account = registry.account(adapter.id(), account_id)?;
    let plan = adapter
        .managed_account_plan_for(account.auth_kind)
        .ok_or(Error::NotImplemented("delete_managed_account"))?;
    if account.material != plan.material || account.auth_kind != plan.auth_kind {
        return Err(metadata_write_error(
            adapter.id(),
            "stored account metadata does not match the adapter lifecycle",
        ));
    }
    adapter.validate_stored_account_delete(&account)?;
    registry.begin_delete(adapter.id(), account_id)?;
    if account.material == StoredAccountMaterial::CredentialStore {
        let store = credential_store.ok_or_else(|| {
            Error::CredentialStoreUnavailable(
                "deleting this account requires a credential store".to_string(),
            )
        })?;
        store.delete(&SecretRef::for_account(adapter.id(), account_id))?;
    }
    registry.finish_delete(adapter.id(), account_id)
}

fn environment_name_is_safe(name: &str) -> bool {
    !name.is_empty() && !name.contains(['=', '\0'])
}

fn validate_launch_environment(spec: &LaunchSpec, account: &StoredAccountMetadata) -> Result<()> {
    if !spec
        .working_directory
        .as_ref()
        .is_some_and(|directory| directory.is_absolute())
    {
        return Err(metadata_write_error(
            &account.provider_id,
            "adapter did not declare an absolute launch working directory",
        ));
    }
    let mut names = HashSet::new();
    for entry in &spec.environment {
        let name = match entry {
            LaunchEnvironment::SetPlain { name, .. }
            | LaunchEnvironment::SetSecret { name }
            | LaunchEnvironment::Remove { name } => name,
        };
        if !environment_name_is_safe(name) || !names.insert(name) {
            return Err(metadata_write_error(
                &account.provider_id,
                "adapter declared an invalid or duplicate environment variable",
            ));
        }
    }
    let expects_credential = account.material == StoredAccountMaterial::CredentialStore;
    if spec.requires_credential() != expects_credential {
        return Err(metadata_write_error(
            &account.provider_id,
            "adapter launch environment does not match stored account material",
        ));
    }
    Ok(())
}

fn metadata_write_error(provider_id: &str, reason: impl Into<String>) -> Error {
    Error::ConfigWrite {
        provider: provider_id.to_string(),
        reason: reason.into(),
    }
}

/// All adapters known to this build, in display order.
pub fn registry() -> Vec<Box<dyn ProviderAdapter>> {
    vec![
        Box::new(claude_code::ClaudeCodeAdapter::default()),
        Box::new(codex_cli::CodexCliAdapter::default()),
        Box::new(cursor::CursorAdapter::default()),
        Box::new(grok_cli::GrokCliAdapter::default()),
        Box::new(gemini_cli::GeminiCliAdapter::default()),
    ]
}

/// Look up a single adapter by its stable id.
pub fn find(id: &str) -> Option<Box<dyn ProviderAdapter>> {
    registry().into_iter().find(|adapter| adapter.id() == id)
}

/// Home directory helper shared by adapters.
///
/// Returns `None` rather than panicking so a headless or unusual environment
/// degrades into "not installed" instead of crashing the application.
pub(crate) fn home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
}

/// `true` when the named executable resolves on `PATH`.
pub(crate) fn binary_on_path(binary: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(binary).is_file())
}

/// Directory that holds one managed account's vendor-issued files.
///
/// `{data_dir}/accounts/{provider_id}/{account_id}`. Callers pass
/// `paths::project_dirs().data_dir()` in production so the identity triple
/// is never spelled a second time. The live tool home (`~/.codex` and
/// friends) is not one of these directories.
pub(crate) fn managed_account_dir(data_dir: &Path, provider_id: &str, account_id: &str) -> PathBuf {
    data_dir.join("accounts").join(provider_id).join(account_id)
}

/// Application-assigned account ids are path components. Reject anything
/// that could escape the managed-account tree.
pub(crate) fn account_id_is_safe(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() <= 128
        && !account_id.contains("..")
        && account_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

/// Whether a process whose `comm` or argv0 file name equals `name` appears
/// to be running.
///
/// Detecting by process name is inherently approximate: a renamed binary
/// is a false negative; an unrelated program that reused the name is a
/// false positive. A pid whose `comm` and cmdline are both unreadable is
/// skipped (another false-negative window). When the process table itself
/// cannot be read, this returns `Err` so a writer can refuse rather than
/// guess. Off Linux there is no `/proc` scan, so this always returns `Err`.
pub(crate) fn process_named_is_running(name: &str) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        linux_process_named_is_running(name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "cannot inspect the process table on this platform",
        )))
    }
}

/// `comm` (trimmed) or the argv0 file name equals `name` (or `name.exe`).
///
/// Substring matches are rejected: `codex-helper` is not `codex`. `comm`
/// is Linux's 15-character process name; `codex` fits.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn process_name_matches(name: &str, comm: &str, argv0: &str) -> bool {
    if comm == name {
        return true;
    }
    let exe = Path::new(argv0)
        .file_name()
        .and_then(|component| component.to_str())
        .unwrap_or("");
    exe == name || exe.strip_suffix(".exe") == Some(name)
}

#[cfg(target_os = "linux")]
fn linux_process_named_is_running(name: &str) -> Result<bool> {
    let proc = Path::new("/proc");
    let entries = std::fs::read_dir(proc).map_err(|error| {
        Error::Io(std::io::Error::new(
            error.kind(),
            format!("reading /proc: {error}"),
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            Error::Io(std::io::Error::new(
                error.kind(),
                format!("reading /proc: {error}"),
            ))
        })?;
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .filter(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
        else {
            continue;
        };
        let dir = proc.join(pid);
        let comm = std::fs::read_to_string(dir.join("comm")).unwrap_or_default();
        let cmdline = std::fs::read(dir.join("cmdline")).unwrap_or_default();
        if comm.is_empty() && cmdline.is_empty() {
            // Unreadable pid: cannot tell whether it is `name`. Skipping
            // it is a known false-negative window (see the function doc).
            continue;
        }
        let argv0 = cmdline
            .split(|byte| *byte == 0)
            .next()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .unwrap_or("");
        if process_name_matches(name, comm.trim(), argv0) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_is_safe_rejects_path_escape() {
        assert!(account_id_is_safe("acct-work"));
        assert!(account_id_is_safe("codex-cli-on-disk"));
        assert!(!account_id_is_safe(""));
        assert!(!account_id_is_safe("../etc"));
        assert!(!account_id_is_safe("acct/work"));
        assert!(!account_id_is_safe("acct work"));
    }

    #[test]
    fn managed_account_dir_nests_provider_then_account() {
        let root = Path::new("/data");
        assert_eq!(
            managed_account_dir(root, "codex-cli", "acct-work"),
            PathBuf::from("/data/accounts/codex-cli/acct-work")
        );
    }

    #[test]
    fn process_name_matches_is_exact() {
        assert!(process_name_matches("codex", "codex", ""));
        assert!(process_name_matches("codex", "", "/usr/bin/codex"));
        assert!(process_name_matches("codex", "", "/usr/bin/codex.exe"));
        assert!(!process_name_matches("codex", "codex-helper", ""));
        assert!(!process_name_matches("codex", "", "/usr/bin/codex-helper"));
        assert!(!process_name_matches(
            "codex",
            "cargo",
            "/path/M4-codex-switch/target/debug/deps/foo"
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_named_is_running_is_false_for_an_absent_name() {
        assert!(!process_named_is_running("cam-absent-process-9f3a2c").unwrap());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn process_named_is_running_cannot_tell_off_linux() {
        assert!(process_named_is_running("codex").is_err());
    }
}
