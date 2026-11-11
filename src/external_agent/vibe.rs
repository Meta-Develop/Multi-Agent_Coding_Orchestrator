//! Parent-held Vibe launch staging, credential handling, and export usage custody.
//!
//! Vibe is admitted only for the writable execution-phase non-delegating terminal
//! Worker. This module owns the per-attempt private `VIBE_HOME` (with a fresh
//! `config.toml`), the private shell/XDG directories, the private export directory,
//! and the no-follow bounded reads of the child-written `export.json`.
//! The raw export (effective config/transcript) is never published.
use super::*;

/// Child environment key carrying the Mistral credential. Never argv/prompt/report.
pub(super) const CREDENTIAL_ENV: &str = "MISTRAL_API_KEY";
/// Operator-only dotenv source for the Mistral credential.
pub(super) const CREDENTIAL_FILE_ENV: &str = "MACO_VIBE_CREDENTIAL_FILE";
/// Bounded read limit for the operator credential source.
const CREDENTIAL_FILE_LIMIT_BYTES: usize = 64 * 1024;
/// Bounded read limit for the child-written export leaf.
const VIBE_EXPORT_LIMIT_BYTES: usize = 1024 * 1024;
/// Name of the export leaf Vibe writes inside the private export directory.
const EXPORT_LEAF_NAME: &str = "export.json";

/// Parent-owned token counts captured from the held export leaf. The served model
/// remains UNKNOWN; only the requested model is recorded. Cost is never derived.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VibeUsageCapture {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub total_tokens: u64,
}

impl VibeUsageCapture {
    fn from_parsed(usage: crate::runtime_adapter::vibe::VibeUsage) -> Self {
        Self {
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cached_input_tokens: usage.cached_input_tokens,
            total_tokens: usage.total_tokens,
        }
    }
}

/// Descriptive launch evidence; only the live parent holds the staging capability.
/// Never carries credential bytes or a credential source path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VibeLaunchEvidence {
    pub model: String,
    pub config_sha256: String,
    pub export_dir: PathBuf,
    /// Original command request fields, retained so held usage can be bound
    /// back to the exact launch via [`VibeLaunchEvidence::matches`].
    pub program: PathBuf,
    pub cwd: PathBuf,
    pub prompt: PathBuf,
    pub output_last_message: PathBuf,
    pub reasoning_effort: Option<String>,
}

impl VibeLaunchEvidence {
    /// Whether this evidence describes exactly the given command's Vibe
    /// invocation and request. The manager binds retained usage to the original
    /// launch with this check instead of rereading mutable export state.
    pub(super) fn matches(&self, command: &ExternalAgentCommand) -> bool {
        if !matches!(command.invocation, ExternalAgentInvocation::Vibe) {
            return false;
        }
        command.program == self.program
            && command.cwd == self.cwd
            && command.prompt == self.prompt
            && command.output_last_message == self.output_last_message
            && command.reasoning_effort == self.reasoning_effort
            && command.model.as_deref() == Some(self.model.as_str())
    }
}

/// Held private directories and leaves for one Vibe attempt. Lives inside
/// [`ExternalOutputStaging`] so cleanup owns it with the staging root.
pub(crate) struct VibeStaging {
    /// Private `VIBE_HOME` (0700 held child of the staging root).
    pub(crate) home: SecureOutputRoot,
    /// Fresh `config.toml` inside `VIBE_HOME` pinning the requested model.
    /// Held for capability lifetime only; the digest lives in `evidence`.
    pub(crate) config: ReservedOutputFile,
    #[cfg(target_os = "linux")]
    pub(super) journal_shell: Option<JournalShell>,
    /// Private export directory created before launch and held by inode.
    pub(crate) export: SecureOutputRoot,
    /// Private shell HOME/TMPDIR and XDG directories.
    pub(crate) shell_directories: Vec<SecureOutputRoot>,
    pub(crate) evidence: VibeLaunchEvidence,
}

impl VibeStaging {
    /// Remove held leaves and directories only after target quiescence. XDG
    /// directories are removed before their containing VIBE_HOME.
    pub(super) fn cleanup(self) -> Result<()> {
        self.home.verify_path_identity()?;
        #[cfg(target_os = "linux")]
        if let Some(shell) = self.journal_shell {
            shell.verify()?;
            fs::remove_file(&shell.path)?;
        }
        self.config
            .remove()
            .context("failed to remove the held Vibe config")?;
        for directory in self.shell_directories {
            remove_directory(directory)?;
        }
        remove_directory(self.export)?;
        remove_directory(self.home)
    }
}

fn remove_directory(directory: SecureOutputRoot) -> Result<()> {
    directory
        .verify_path_identity()
        .context("staged Vibe directory identity changed before removal")?;
    fs::remove_dir_all(directory.path()).with_context(|| {
        format!(
            "failed to remove staged Vibe directory {}",
            directory.path().display()
        )
    })
}

/// Journal argv is execution evidence: redacting it would change its meaning.
/// Withhold the entire capture if it contains a runtime credential instead.
pub(super) fn withhold_credential_journals(
    captures: &mut [WorkerJournalArtifactCapture],
    redactor: &CredentialRedactor,
) {
    for capture in captures {
        if let WorkerJournalArtifactCaptureStatus::Loaded(bytes) = &capture.status {
            if redactor.redact_bytes(bytes) != *bytes {
                capture.status = WorkerJournalArtifactCaptureStatus::Invalid(
                    "worker journal contained the runtime credential and was withheld".to_string(),
                );
            }
        }
    }
}

/// The export directory Vibe writes to, derived from the staged output leaf.
pub(super) fn export_dir_for(staged_output: &Path) -> PathBuf {
    crate::runtime_adapter::vibe::export_directory(staged_output)
}

/// File name of the export directory below the staging root (single component).
pub(super) fn export_dir_name(staged_output: &Path) -> Result<std::ffi::OsString> {
    let name = export_dir_for(staged_output)
        .file_name()
        .context("Vibe export directory has no single-component name")?
        .to_os_string();
    if name.is_empty() || export_dir_for(staged_output).parent() != staged_output.parent() {
        bail!("Vibe export directory must be a sibling of the staged output leaf");
    }
    Ok(name)
}

/// Privacy pins for the sanitized child environment. The fresh config.toml and
/// these booleans together keep subagents, MCP, connectors, telemetry, update
/// checks, and background processes disabled, and pin the requested model.
pub(super) fn privacy_environment(model: &str) -> Vec<(String, String)> {
    let allowed = serde_json::to_string(&[model]).unwrap_or_else(|_| format!("[\"{model}\"]"));
    // Pin the models map so a project config alias cannot redefine the
    // requested model or its provider. The alias key is the model id itself
    // with a fixed Mistral provider; utility models reuse the same pin.
    let models = serde_json::to_string(&serde_json::json!({
        model: {
            "name": model,
            "alias": model,
            "provider": "mistral",
        }
    }))
    .unwrap_or_else(|_| {
        format!(
        "{{\"{model}\":{{\"name\":\"{model}\",\"alias\":\"{model}\",\"provider\":\"mistral\"}}}}"
    )
    });
    let utility = serde_json::to_string(&serde_json::json!({
        "title": model,
        "smart_approve": model,
    }))
    .unwrap_or_else(|_| format!("{{\"title\":\"{model}\",\"smart_approve\":\"{model}\"}}"));
    [
        ("VIBE_ENABLE_SUBAGENTS", "false"),
        ("VIBE_ENABLE_MCP", "false"),
        ("VIBE_ENABLE_CONNECTORS", "false"),
        ("VIBE_ENABLE_TELEMETRY", "false"),
        ("VIBE_ENABLE_OTEL", "false"),
        ("VIBE_ENABLE_UPDATE_CHECKS", "false"),
        ("VIBE_ENABLE_AUTO_UPDATE", "false"),
        ("VIBE_ENABLE_BACKGROUND_PROCESSES", "false"),
        ("VIBE_SESSION_LOGGING__GENERATE_TITLES", "false"),
        ("VIBE_ACTIVE_MODEL", model),
        ("VIBE_ALLOWED_MODELS", &allowed),
        ("VIBE_MODELS", &models),
        ("VIBE_UTILITY_MODELS", &utility),
        ("VIBE_TEST_DISABLE_KEYRING", "1"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

/// Pure dotenv parsing: returns the single `MISTRAL_API_KEY` value.
///
/// Safe parsing only: no shell expansion, no `export` inheritance, no source
/// interpolation. Duplicate or conflicting keys are refused.
pub(super) fn parse_dotenv_mistral_key(bytes: &[u8]) -> Result<String> {
    if bytes.contains(&0) {
        bail!("Vibe credential source contains a NUL byte");
    }
    let text = std::str::from_utf8(bytes).context("Vibe credential source is not valid UTF-8")?;
    let mut found: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("Vibe credential source contains a non-assignment line");
        };
        if key.trim() != CREDENTIAL_ENV {
            continue;
        }
        let mut value = value.trim();
        if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
        {
            value = &value[1..value.len() - 1];
        }
        if found.is_some() {
            bail!("Vibe credential source declares {CREDENTIAL_ENV} more than once");
        }
        found = Some(value.to_string());
    }
    let value = found.context("Vibe credential source has no MISTRAL_API_KEY assignment")?;
    if !(MIN_CREDENTIAL_BYTES..=MAX_CREDENTIAL_BYTES).contains(&value.len())
        || value.contains(['\n', '\r', '\0'])
    {
        bail!("Vibe credential value is absent or malformed");
    }
    Ok(value)
}

/// Reads the explicit operator credential source with no-follow bounded safe parsing.
/// There is no ambient fallback: absent `MACO_VIBE_CREDENTIAL_FILE` is `Ok(None)`.
pub(super) fn load_credential() -> Result<Option<String>> {
    let source = match std::env::var_os(CREDENTIAL_FILE_ENV) {
        Some(source) => source,
        None => return Ok(None),
    };
    let source = PathBuf::from(&source);
    if !source.is_absolute() {
        bail!("{CREDENTIAL_FILE_ENV} must be an absolute path");
    }
    let bytes = read_credential_source(&source)?;
    let value = parse_dotenv_mistral_key(&bytes)?;
    Ok(Some(value))
}

/// No-follow bounded read of an owner-only 0600 regular dotenv source.
///
/// The leaf is opened with `O_NOFOLLOW|O_NONBLOCK` so a FIFO cannot block the
/// parent, metadata is verified, and the read itself is bounded with
/// [`std::io::Read::take`]: an overbound source is rejected, never slurped.
/// Errors never include file bytes or the credential value.
fn read_credential_source(path: &Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .with_context(|| {
                format!("Vibe credential source is unavailable: {}", path.display())
            })?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            bail!("Vibe credential source is not a regular file");
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!("Vibe credential source must be owner-only 0600");
        }
        if metadata.uid() != unsafe { libc::getuid() } {
            bail!("Vibe credential source must be owned by the current user");
        }
        let mut bytes = Vec::new();
        file.take(CREDENTIAL_FILE_LIMIT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > CREDENTIAL_FILE_LIMIT_BYTES {
            bail!("Vibe credential source exceeds the bounded read limit");
        }
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("Vibe credential source requires a Unix host");
    }
}

/// Stages the per-attempt private Vibe directories below the output staging root
/// and returns the held capability set. The export directory is created fresh
/// before launch so its inode identity is established prelaunch.
pub(super) fn stage(
    spec: &ExternalAgentCommand,
    staging_root: &mut SecureOutputRoot,
    staged_output: &Path,
) -> Result<VibeStaging> {
    let model = crate::runtime_adapter::vibe::validate_model(spec.model.as_deref())?;
    let document = crate::runtime_adapter::vibe::config_document(model)?;
    let export_name = export_dir_name(staged_output)?;
    staging_root.verify_path_identity()?;
    let home = staging_root
        .create_child(OsStr::new("vibe-home"))
        .context("failed to stage the private Vibe home")?;
    let config = home
        .reserve(OsStr::new("config.toml"))
        .context("failed to reserve the fresh Vibe config.toml")?;
    let mut config = config;
    config.write_bytes_atomic(document.as_bytes(), MAX_PROMPT_BYTES)?;
    let export = staging_root
        .create_child(&export_name)
        .context("failed to stage the private Vibe export directory")?;
    export.verify_path_identity()?;
    let mut shell_directories = Vec::new();
    for name in ["vibe-shell-home", "vibe-shell-tmp"] {
        let directory = staging_root
            .create_child(OsStr::new(name))
            .with_context(|| format!("failed to stage the private Vibe {name} directory"))?;
        shell_directories.push(directory);
    }
    for name in ["vibe-xdg-config", "vibe-xdg-cache", "vibe-xdg-data"] {
        let directory = home
            .create_child(OsStr::new(name))
            .with_context(|| format!("failed to stage the private Vibe {name} directory"))?;
        shell_directories.push(directory);
    }
    Ok(VibeStaging {
        evidence: VibeLaunchEvidence {
            model: model.to_string(),
            config_sha256: sha256_hex(document.as_bytes()),
            export_dir: export.path().to_path_buf(),
            program: spec.program.clone(),
            cwd: spec.cwd.clone(),
            prompt: spec.prompt.clone(),
            output_last_message: spec.output_last_message.clone(),
            reasoning_effort: spec.reasoning_effort.clone(),
        },
        home,
        config,
        #[cfg(target_os = "linux")]
        journal_shell: None,
        export,
        shell_directories,
    })
}

/// Executable control leaf retained by descriptor and digest for the attempt.
#[cfg(target_os = "linux")]
pub(super) struct JournalShell {
    pub(super) path: PathBuf,
    file: fs::File,
    digest: String,
}

#[cfg(target_os = "linux")]
impl JournalShell {
    fn verify(&self) -> Result<()> {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let held = self.file.metadata()?;
        let path = fs::symlink_metadata(&self.path)?;
        let mut bytes = vec![0; usize::try_from(held.len())?];
        self.file.read_exact_at(&mut bytes, 0)?;
        if !path.is_file()
            || held.dev() != path.dev()
            || held.ino() != path.ino()
            || path.mode() & 0o7777 != 0o700
            || path.nlink() != 1
            || sha256_hex(&bytes) != self.digest
        {
            bail!("Vibe journal shell identity or bytes changed");
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Vibe also invokes this shell with -lc to snapshot its environment. Refuse
/// that setup silently, without executing or journaling the environment dump.
#[cfg(target_os = "linux")]
fn journal_shell_document(binding: &BoundWorkerJournalAppend, cwd: &Path) -> Result<String> {
    if !Path::new("/bin/bash").is_file() {
        bail!("Vibe journal shell requires the absolute system /bin/bash");
    }
    let mut argv = binding.command_prefix()?;
    argv.extend([
        "--cwd".into(),
        cwd.to_str()
            .context("Vibe journal cwd requires UTF-8")?
            .into(),
        "--auto-timestamps".into(),
        "--".into(),
        "/bin/bash".into(),
        "-c".into(),
    ]);
    let command = argv
        .iter()
        .map(|value| shell_quote(value))
        .collect::<Vec<_>>()
        .join(" ");
    Ok(format!(
        "#!/bin/bash\nif [ \"$#\" -ne 2 ] || [ \"$1\" != '-c' ]; then\n  exit 64\nfi\nexec {command} \"$2\"\n"
    ))
}

/// Vibe 3.1.0's default_orchestrator.py puts project TOML above user TOML.
/// Match layers/project.py::project_config_candidates: cwd and each ancestor,
/// stopping BEFORE VIBE_HOME's parent. With --trust these can override the held
/// shell and other fixed settings. Reject project config rather than merge it.
/// Independently, agents/registry.py discovers builtin profile overrides via
/// HarnessFilesManager.project_agents_dirs and paths/_local_config_files.py.
/// Native argv has no --add-dir: that discovery checks only cwd/.vibe/agents,
/// without requiring config.toml. Refuse that directory without reading profiles.
#[cfg(target_os = "linux")]
fn reject_project_config(cwd: &Path, home: &Path) -> Result<()> {
    let stop = home.parent().context("Vibe home requires a parent")?;
    let configs = cwd
        .ancestors()
        .take_while(|directory| *directory != stop)
        .map(|directory| {
            (
                directory.join(".vibe/config.toml"),
                "trusted project TOML can override the managed shell and fixed settings",
            )
        });
    let agents = std::iter::once((
        cwd.join(".vibe/agents"),
        "project agent profiles can override the managed shell",
    ));
    for (path, reason) in configs.chain(agents) {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context(format!(
                    "cannot exclude Vibe project configuration at {}",
                    path.display()
                ));
            }
            // Conservatively reject links and non-files too; never read or
            // interpret project-controlled configuration for this managed path.
            Ok(_) => bail!(
                "automatic Vibe journal refuses project configuration at {}: {reason}",
                path.display()
            ),
        }
    }
    Ok(())
}

/// Runs after native argv authentication and effective prompt staging, before
/// process construction. The existing binding alone supplies helper custody.
#[cfg(target_os = "linux")]
pub(super) fn prepare_journal_shell(
    staging: &mut VibeStaging,
    spec: &ExternalAgentCommand,
    binding: Option<&BoundWorkerJournalAppend>,
    argv: &mut Vec<OsString>,
    profile: &mut Option<SideEffectConfinementProfile>,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if spec.invocation != ExternalAgentInvocation::Vibe
        || spec.workspace_access != WorkspaceAccess::ReadWrite
        || spec.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree
        || spec
            .agent_lifecycle
            .as_ref()
            .is_none_or(|id| id.role != "worker")
    {
        return Ok(());
    }
    let binding = binding.context("Vibe writable Worker requires a bound execution journal")?;
    binding.revalidate()?;
    let cwd = fs::canonicalize(&spec.cwd)?;
    if cwd != spec.cwd || staging.evidence.cwd != cwd {
        bail!("Vibe journal shell requires the exact canonical assigned worktree");
    }
    reject_project_config(&cwd, staging.home.path())?;
    if staging.journal_shell.is_some() {
        bail!("Vibe journal shell is already staged");
    }
    if *argv != runtime_adapter_argv(spec)? {
        bail!("Vibe journal shell requires the exact native argv");
    }
    let Some(SideEffectConfinementProfile::ExternalCodex(mounted)) = profile else {
        bail!("Vibe journal shell requires the existing ExternalCodex profile");
    };
    staging.home.verify_path_identity()?;
    let path = staging.home.path().join("journal-shell");
    let document = journal_shell_document(binding, &cwd)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&path)?;
    file.write_all(document.as_bytes())?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(0o700))?;
    drop(file);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let shell = JournalShell {
        path,
        file,
        digest: sha256_hex(document.as_bytes()),
    };
    shell.verify()?;
    staging.journal_shell = Some(shell);
    let shell = staging.journal_shell.as_ref().unwrap();
    let document = crate::runtime_adapter::vibe::journaled_config_document(
        &staging.evidence.model,
        &shell.path,
    )?;
    staging
        .config
        .write_bytes_atomic(document.as_bytes(), MAX_PROMPT_BYTES)?;
    staging.evidence.config_sha256 = sha256_hex(document.as_bytes());
    *mounted = mounted
        .clone()
        .with_visible_read_only_file(&binding.helper_path)
        .with_visible_read_only_file(staging.config.path())
        .with_visible_read_only_file(&shell.path);
    crate::runtime_adapter::vibe::journaled_worker_arguments(argv);
    // One explicit initial observation per attempt, through the existing core.
    // This records retained edits against HEAD without executing or reapplying
    // them. Never repeat this before individual commands: later unobserved
    // mutations must still fail the core's baseline continuity check.
    binding.revalidate()?;
    crate::supervise::run_worker_execution_journal_command_with_clock(
        &binding.journal.path,
        &crate::safe_state::FileIdentity {
            device: binding.journal.identity.device,
            file: binding.journal.identity.inode,
        },
        &crate::supervise::WorkerExecutionJournalEntry {
            command: vec!["true".into()],
            cwd,
            start_timestamp: String::new(),
            end_timestamp: String::new(),
            changed_paths: Vec::new(),
            observation: None,
        },
        true,
        true,
    )
    .context("Vibe initial journal observation failed before launch")?;
    binding.revalidate()?;
    Ok(())
}

/// Recheck held controls immediately before target release.
#[cfg(target_os = "linux")]
pub(super) fn verify_journal_shell(staging: &VibeStaging) -> Result<()> {
    if let Some(shell) = &staging.journal_shell {
        staging.home.verify_path_identity()?;
        reject_project_config(&staging.evidence.cwd, staging.home.path())?;
        shell.verify()?;
        let document = staging.config.read_bounded(MAX_PROMPT_BYTES)?;
        if sha256_hex(&document) != staging.evidence.config_sha256 {
            bail!("Vibe journal config bytes changed");
        }
    }
    Ok(())
}

/// Applies the private Vibe environment to the sanitized child environment map.
/// The credential travels only as `MISTRAL_API_KEY`; it never reaches argv,
/// the prompt, or public evidence. Production requires the operator credential
/// source: a missing `MACO_VIBE_CREDENTIAL_FILE` fails closed instead of
/// launching an unauthenticated child.
pub(super) fn apply_environment(
    staging: &VibeStaging,
    environment: &mut BTreeMap<String, String>,
) -> Result<()> {
    let credential = load_credential()?.with_context(|| {
        format!("{CREDENTIAL_FILE_ENV} must name an operator credential source for the Vibe launch")
    })?;
    apply_environment_with_credential(staging, environment, &credential)
}

/// Pure credential-injected variant of [`apply_environment`]. Tests use a
/// synthetic key and never read ambient credential paths.
pub(super) fn apply_environment_with_credential(
    staging: &VibeStaging,
    environment: &mut BTreeMap<String, String>,
    credential: &str,
) -> Result<()> {
    let home = staging
        .home
        .path()
        .to_str()
        .context("private Vibe home is not valid UTF-8")?;
    let shell_home = staging.shell_directories[0]
        .path()
        .to_str()
        .context("private Vibe shell home is not valid UTF-8")?;
    let shell_tmp = staging.shell_directories[1]
        .path()
        .to_str()
        .context("private Vibe shell tmp is not valid UTF-8")?;
    let xdg_config = staging.shell_directories[2]
        .path()
        .to_str()
        .context("private Vibe XDG config is not valid UTF-8")?;
    let xdg_cache = staging.shell_directories[3]
        .path()
        .to_str()
        .context("private Vibe XDG cache is not valid UTF-8")?;
    let xdg_data = staging.shell_directories[4]
        .path()
        .to_str()
        .context("private Vibe XDG data is not valid UTF-8")?;
    environment.insert("VIBE_HOME".to_string(), home.to_string());
    environment.insert("HOME".to_string(), shell_home.to_string());
    environment.insert("TMPDIR".to_string(), shell_tmp.to_string());
    environment.insert("XDG_CONFIG_HOME".to_string(), xdg_config.to_string());
    environment.insert("XDG_CACHE_HOME".to_string(), xdg_cache.to_string());
    environment.insert("XDG_DATA_HOME".to_string(), xdg_data.to_string());
    for (key, value) in privacy_environment(&staging.evidence.model) {
        environment.insert(key, value);
    }
    environment.insert(CREDENTIAL_ENV.to_string(), credential.to_string());
    Ok(())
}

/// Seals the private runtime home: the shared runner must not overwrite the
/// explicitly projected HOME/XDG/TMPDIR control directories.
pub(super) fn seal_private_runtime_home(
    spec: &mut crate::process_runner::ProcessSpec,
) -> Result<()> {
    let EnvironmentMode::ClearAndSet(environment) = &spec.environment else {
        bail!("private Vibe directories require a sanitized environment");
    };
    for key in ["VIBE_HOME", "HOME", "TMPDIR", "XDG_CONFIG_HOME"] {
        if !environment.contains_key(key) {
            bail!("private Vibe environment is missing {key}");
        }
    }
    spec.private_runtime_home = false;
    Ok(())
}

/// Captures usage from the held export directory after verified process quiescence.
///
/// The leaf is captured once and its identity verified while reading: a missing,
/// replaced, oversized, or malformed export means usage is unavailable.
pub(super) fn capture_usage(export: &SecureOutputRoot) -> Result<VibeUsageCapture> {
    export.verify_path_identity()?;
    let leaf = export
        .open_existing_leaf(OsStr::new(EXPORT_LEAF_NAME))
        .context("Vibe export.json is missing from the held export directory")?;
    let bytes = leaf
        .read_bounded(VIBE_EXPORT_LIMIT_BYTES)
        .context("Vibe export.json could not be read from the held leaf")?;
    let usage = crate::runtime_adapter::vibe::parse_usage(&bytes)?;
    Ok(VibeUsageCapture::from_parsed(usage))
}

/// Extracts the final assistant text from the captured NDJSON stdout stream.
pub(super) fn capture_report_text(stdout: &[u8]) -> Result<Vec<u8>> {
    let text = crate::runtime_adapter::vibe::final_assistant_text(stdout)?;
    Ok(text.into_bytes())
}
