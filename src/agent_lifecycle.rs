use crate::{
    artifacts::discover_repo_root,
    hierarchy_ledger::RoleCategory,
    safe_state::{AtomicStateWriter, BoundedRegularReader, KernelStateLock, SafeRoot},
    supervise::{
        trusted_model_capability, validate_known_judgment_role_model, AgentRole,
        ModelCapabilityClass,
    },
};
use anyhow::{bail, Context, Result};
use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MACO_RUN_ID_ENV: &str = "MACO_RUN_ID";
pub const MACO_TASK_ID_ENV: &str = "MACO_TASK_ID";

const REGISTRY_VERSION: u32 = 1;
const REGISTRY_FILE: &str = "registry.json";
const REGISTRY_LOCK: &str = "registry.lock";
const MAX_REGISTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REGISTRY_RECORDS: usize = 4096;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_ROLE_BYTES: usize = 128;
const MAX_ARGV_ENTRIES: usize = 4096;
const MAX_ARG_BYTES: usize = 64 * 1024;
const MAX_STOP_WAIT: Duration = Duration::from_secs(60);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(20);
const KILL_CONFIRMATION_WAIT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLaunchMetadata {
    pub role: String,
    pub run_id: String,
    pub task_id: String,
    pub repo: PathBuf,
    pub parent: Option<String>,
}

impl AgentLaunchMetadata {
    pub fn new(
        repo: impl AsRef<Path>,
        role: impl Into<String>,
        run_id: impl Into<String>,
        task_id: impl Into<String>,
    ) -> Result<Self> {
        let metadata = Self {
            role: role.into(),
            run_id: run_id.into(),
            task_id: task_id.into(),
            repo: discover_repo_root(repo)?,
            parent: None,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    pub fn with_parent(mut self, parent: impl Into<String>) -> Result<Self> {
        self.parent = Some(parent.into());
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_text_field("agent role", &self.role, MAX_ROLE_BYTES)?;
        validate_text_field("run id", &self.run_id, MAX_IDENTIFIER_BYTES)?;
        validate_text_field("task id", &self.task_id, MAX_IDENTIFIER_BYTES)?;
        if let Some(parent) = &self.parent {
            validate_text_field("parent agent id", parent, MAX_IDENTIFIER_BYTES)?;
        }
        if !self.repo.is_absolute() {
            bail!("agent lifecycle repository path must be absolute");
        }
        Ok(())
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    pub fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProcessRecord {
    pub pid: u32,
    pub process_start_time: String,
    pub role: String,
    pub run_id: String,
    pub task_id: String,
    pub parent: Option<String>,
    pub repo: PathBuf,
    pub argv: Vec<String>,
    pub launch_timestamp_ms: u64,
}

/// Authority MACO derived from the declared lifecycle role and the exact
/// launched argv. This is deliberately not caller-authored lifecycle input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAuthorityBinding {
    pub category: RoleCategory,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_capability: Option<ModelCapabilityClass>,
    pub may_delegate: bool,
    pub may_write: bool,
    pub may_judge_acceptance: bool,
    pub may_mutate_git_history: bool,
    pub probe_only: bool,
    pub source: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentProcessRecordWire {
    pid: u32,
    process_start_time: String,
    role: String,
    run_id: String,
    task_id: String,
    #[serde(default)]
    parent: Option<String>,
    repo: PathBuf,
    argv: Vec<String>,
    launch_timestamp_ms: u64,
    #[serde(default)]
    launch_authority: Option<LaunchAuthorityBinding>,
}

impl AgentProcessRecord {
    fn validate(&self, expected_repo: &Path) -> Result<()> {
        if self.pid == 0 {
            bail!("agent registry record contains PID 0");
        }
        validate_text_field(
            "process start-time token",
            &self.process_start_time,
            MAX_IDENTIFIER_BYTES,
        )?;
        validate_text_field("agent role", &self.role, MAX_ROLE_BYTES)?;
        validate_text_field("run id", &self.run_id, MAX_IDENTIFIER_BYTES)?;
        validate_text_field("task id", &self.task_id, MAX_IDENTIFIER_BYTES)?;
        if let Some(parent) = &self.parent {
            validate_text_field("parent agent id", parent, MAX_IDENTIFIER_BYTES)?;
        }
        if self.repo != expected_repo {
            bail!(
                "agent registry record repository {} does not match {}",
                self.repo.display(),
                expected_repo.display()
            );
        }
        if self.argv.is_empty() || self.argv.len() > MAX_ARGV_ENTRIES {
            bail!("agent registry argv is empty or exceeds its entry bound");
        }
        for argument in &self.argv {
            if argument.len() > MAX_ARG_BYTES || argument.contains('\0') {
                bail!("agent registry argv entry exceeds its safety bound");
            }
        }
        self.launch_authority()?;
        Ok(())
    }

    /// Reconstruct and validate launch authority from immutable record fields.
    ///
    /// Version probes carry no authority. Actual coordinator and acceptance
    /// judge launches require an explicit model accepted by the model policy.
    /// Git mutation is never granted by lifecycle registration alone.
    pub fn launch_authority(&self) -> Result<LaunchAuthorityBinding> {
        derive_launch_authority(&self.role, &self.argv)
    }

    fn summary(&self) -> String {
        format!(
            "pid={} role={} run_id={} task_id={} parent={}",
            self.pid,
            self.role,
            self.run_id,
            self.task_id,
            self.parent.as_deref().unwrap_or("-")
        )
    }
}

impl Serialize for AgentProcessRecord {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let launch_authority = self.launch_authority().map_err(serde::ser::Error::custom)?;
        let mut state = serializer.serialize_struct("AgentProcessRecord", 10)?;
        state.serialize_field("pid", &self.pid)?;
        state.serialize_field("process_start_time", &self.process_start_time)?;
        state.serialize_field("role", &self.role)?;
        state.serialize_field("run_id", &self.run_id)?;
        state.serialize_field("task_id", &self.task_id)?;
        if self.parent.is_some() {
            state.serialize_field("parent", &self.parent)?;
        }
        state.serialize_field("repo", &self.repo)?;
        state.serialize_field("argv", &self.argv)?;
        state.serialize_field("launch_timestamp_ms", &self.launch_timestamp_ms)?;
        state.serialize_field("launch_authority", &launch_authority)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AgentProcessRecord {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AgentProcessRecordWire::deserialize(deserializer)?;
        let supplied_authority = wire.launch_authority;
        let record = Self {
            pid: wire.pid,
            process_start_time: wire.process_start_time,
            role: wire.role,
            run_id: wire.run_id,
            task_id: wire.task_id,
            parent: wire.parent,
            repo: wire.repo,
            argv: wire.argv,
            launch_timestamp_ms: wire.launch_timestamp_ms,
        };
        if let Some(supplied_authority) = supplied_authority {
            let reconstructed = record
                .launch_authority()
                .map_err(serde::de::Error::custom)?;
            if supplied_authority != reconstructed {
                return Err(serde::de::Error::custom(
                    "agent launch authority does not match immutable role/argv evidence",
                ));
            }
        }
        Ok(record)
    }
}

fn derive_launch_authority(role: &str, argv: &[String]) -> Result<LaunchAuthorityBinding> {
    let category = lifecycle_role_category(role)?;
    if is_version_probe(argv) {
        return Ok(LaunchAuthorityBinding {
            category,
            requested_model: None,
            model_capability: None,
            may_delegate: false,
            may_write: false,
            may_judge_acceptance: false,
            may_mutate_git_history: false,
            probe_only: true,
            source: "verified_version_probe".to_string(),
        });
    }
    if matches!(role, "supervise" | "autopilot") {
        return Ok(LaunchAuthorityBinding {
            category,
            requested_model: None,
            model_capability: None,
            may_delegate: true,
            may_write: true,
            may_judge_acceptance: false,
            may_mutate_git_history: false,
            probe_only: false,
            source: "host_control_plane".to_string(),
        });
    }

    if !is_agent_runtime_program(&argv[0]) {
        return Ok(LaunchAuthorityBinding {
            category,
            requested_model: None,
            model_capability: None,
            may_delegate: false,
            may_write: false,
            may_judge_acceptance: false,
            may_mutate_git_history: false,
            probe_only: false,
            source: "non_agent_simulation".to_string(),
        });
    }

    let model = configured_model_from_argv(argv)?;
    let policy_role = lifecycle_policy_role(role);
    match (role, policy_role, model.as_deref()) {
        ("researcher", None, Some(model)) => {
            validate_known_judgment_role_model(AgentRole::Worker, Some(model))?;
        }
        ("researcher", None, None) | (_, Some(AgentRole::Worker), None) => {}
        (_, Some(policy_role), model) => {
            validate_known_judgment_role_model(policy_role, model)?;
        }
        _ => bail!("agent lifecycle role {role:?} has no launch authority policy"),
    }
    let model_capability = model.as_deref().and_then(trusted_model_capability);
    Ok(LaunchAuthorityBinding {
        category,
        requested_model: model,
        model_capability,
        may_delegate: category == RoleCategory::DelegatingCoordinator,
        may_write: matches!(
            category,
            RoleCategory::DelegatingCoordinator | RoleCategory::NonDelegatingTerminalWorker
        ),
        may_judge_acceptance: category == RoleCategory::ReadOnlyReviewAuditor,
        may_mutate_git_history: false,
        probe_only: false,
        source: "role_and_exact_requested_argv".to_string(),
    })
}

fn is_agent_runtime_program(program: &str) -> bool {
    Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "codex" | "claude" | "gemini"
            )
        })
}

fn lifecycle_role_category(role: &str) -> Result<RoleCategory> {
    match role {
        "supervise" | "autopilot" => Ok(RoleCategory::DelegatingCoordinator),
        other => RoleCategory::from_legacy_role(other),
    }
}

fn lifecycle_policy_role(role: &str) -> Option<AgentRole> {
    match role {
        "supervisor" => Some(AgentRole::Supervisor),
        "child_orchestrator" | "orchestrator" | "root" => Some(AgentRole::ChildOrchestrator),
        "worker" => Some(AgentRole::Worker),
        "gate_classifier" => Some(AgentRole::GateClassifier),
        "auditor" => Some(AgentRole::Auditor),
        _ => None,
    }
}

fn is_version_probe(argv: &[String]) -> bool {
    let args = argv.iter().skip(1).map(String::as_str).collect::<Vec<_>>();
    args.len() <= 3
        && args
            .iter()
            .any(|argument| matches!(*argument, "--version" | "-V" | "version"))
        && !args
            .iter()
            .any(|argument| matches!(*argument, "exec" | "app-server"))
}

fn configured_model_from_argv(argv: &[String]) -> Result<Option<String>> {
    let mut resolved = None;
    let mut index = 1;
    while index < argv.len() {
        let argument = argv[index].as_str();
        let candidate = if matches!(argument, "-m" | "--model") {
            index += 1;
            Some(
                argv.get(index)
                    .context("model option in agent argv is missing its value")?
                    .as_str(),
            )
        } else if let Some(model) = argument.strip_prefix("--model=") {
            Some(model)
        } else if matches!(argument, "-c" | "--config") {
            index += 1;
            argv.get(index)
                .context("config option in agent argv is missing its value")?
                .split_once('=')
                .filter(|(key, _)| key.trim() == "model")
                .map(|(_, value)| value.trim())
        } else {
            None
        };
        if let Some(candidate) = candidate {
            let candidate = candidate
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or(candidate);
            if candidate.is_empty() {
                bail!("agent argv contains an empty model identity");
            }
            match &resolved {
                Some(existing) if existing != candidate => {
                    bail!("agent argv contains conflicting model identities")
                }
                Some(_) => {}
                None => resolved = Some(candidate.to_string()),
            }
        }
        index += 1;
    }
    Ok(resolved)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentIdentityLiveness {
    Live,
    Stale,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentProcessInspection {
    pub process: AgentProcessRecord,
    pub identity: AgentIdentityLiveness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncertainty_reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentListFilter {
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStopOutcome {
    Terminated,
    Killed,
    AlreadyExited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentStopEntry {
    pub process: AgentProcessRecord,
    pub outcome: AgentStopOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentStopReport {
    pub stopped: Vec<AgentStopEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryState {
    version: u32,
    processes: Vec<AgentProcessRecord>,
}

impl Default for RegistryState {
    fn default() -> Self {
        Self {
            version: REGISTRY_VERSION,
            processes: Vec::new(),
        }
    }
}

impl RegistryState {
    fn validate(&self, expected_repo: &Path) -> Result<()> {
        if self.version != REGISTRY_VERSION {
            bail!(
                "unsupported agent registry version {}; expected {}",
                self.version,
                REGISTRY_VERSION
            );
        }
        if self.processes.len() > MAX_REGISTRY_RECORDS {
            bail!("agent registry exceeds its record bound");
        }
        let mut identities = std::collections::BTreeSet::new();
        for process in &self.processes {
            process.validate(expected_repo)?;
            if !identities.insert((process.pid, process.process_start_time.as_str())) {
                bail!(
                    "agent registry contains a duplicate PID/start-time identity for PID {}",
                    process.pid
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AgentRegistry {
    repo: PathBuf,
}

impl AgentRegistry {
    pub fn open(repo: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            repo: discover_repo_root(repo)?,
        })
    }

    pub fn repo(&self) -> &Path {
        &self.repo
    }

    pub fn registry_path(&self) -> PathBuf {
        self.repo.join(".maco").join("agents").join(REGISTRY_FILE)
    }

    pub fn register(
        &self,
        metadata: &AgentLaunchMetadata,
        pid: u32,
        argv: Vec<String>,
    ) -> Result<AgentProcessRecord> {
        metadata.validate()?;
        if metadata.repo != self.repo {
            bail!(
                "agent launch repository {} does not match registry repository {}",
                metadata.repo.display(),
                self.repo.display()
            );
        }
        if argv.is_empty() {
            bail!("agent lifecycle registration requires a non-empty argv");
        }
        let record = AgentProcessRecord {
            pid,
            process_start_time: process_start_time(pid)
                .with_context(|| format!("failed to identify launched agent PID {pid}"))?,
            role: metadata.role.clone(),
            run_id: metadata.run_id.clone(),
            task_id: metadata.task_id.clone(),
            parent: metadata.parent.clone(),
            repo: self.repo.clone(),
            argv,
            launch_timestamp_ms: unix_timestamp_ms()?,
        };
        record.validate(&self.repo)?;
        self.update_state(|state| {
            state.processes.retain(|existing| existing.pid != pid);
            if state.processes.len() >= MAX_REGISTRY_RECORDS {
                bail!("agent registry is full");
            }
            state.processes.push(record.clone());
            state.processes.sort_by_key(|process| {
                (
                    process.launch_timestamp_ms,
                    process.pid,
                    process.process_start_time.clone(),
                )
            });
            Ok(())
        })?;
        Ok(record)
    }

    /// Inspect every durable registry record without pruning.
    ///
    /// Each record is classified as live, stale (gone or PID reuse), or uncertain.
    /// Process-enumeration failures are reported per record and never collapsed
    /// into an empty list.
    pub fn inspect(&self) -> Result<Vec<AgentProcessInspection>> {
        let records = self.snapshot_records()?;
        let mut inspections = Vec::with_capacity(records.len());
        for process in records {
            let (identity, uncertainty_reason) =
                match process_state(process.pid, &process.process_start_time) {
                    Ok(ProcessIdentityState::Live) => (AgentIdentityLiveness::Live, None),
                    Ok(ProcessIdentityState::Gone | ProcessIdentityState::Reused) => {
                        (AgentIdentityLiveness::Stale, None)
                    }
                    Err(error) => (AgentIdentityLiveness::Uncertain, Some(error.to_string())),
                };
            inspections.push(AgentProcessInspection {
                process,
                identity,
                uncertainty_reason,
            });
        }
        Ok(inspections)
    }

    pub fn unregister(&self, pid: u32, start_time: &str) -> Result<()> {
        self.remove_identity(pid, start_time)
    }

    pub fn list(&self, filter: &AgentListFilter) -> Result<Vec<AgentProcessRecord>> {
        if let Some(run_id) = &filter.run_id {
            validate_text_field("run id", run_id, MAX_IDENTIFIER_BYTES)?;
        }
        let mut live = Vec::new();
        self.update_state(|state| {
            let mut retained = Vec::with_capacity(state.processes.len());
            for record in std::mem::take(&mut state.processes) {
                match process_state(record.pid, &record.process_start_time)? {
                    ProcessIdentityState::Live => {
                        if filter
                            .run_id
                            .as_ref()
                            .is_none_or(|run_id| run_id == &record.run_id)
                        {
                            live.push(record.clone());
                        }
                        retained.push(record);
                    }
                    ProcessIdentityState::Gone | ProcessIdentityState::Reused => {}
                }
            }
            state.processes = retained;
            Ok(())
        })?;
        live.sort_by_key(|process| {
            (
                process.launch_timestamp_ms,
                process.pid,
                process.process_start_time.clone(),
            )
        });
        Ok(live)
    }

    pub fn stop_selector(&self, selector: &str, wait: Duration) -> Result<AgentStopReport> {
        validate_text_field("agent selector", selector, MAX_IDENTIFIER_BYTES)?;
        let live = self.list(&AgentListFilter::default())?;
        let matches = live
            .into_iter()
            .filter(|process| {
                process.pid.to_string() == selector
                    || process.run_id == selector
                    || process.task_id == selector
            })
            .collect::<Vec<_>>();
        if matches.is_empty() {
            bail!("no live MACO agent matches selector '{selector}'");
        }
        if matches.len() > 1 {
            let details = matches
                .iter()
                .map(AgentProcessRecord::summary)
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "agent selector '{selector}' is ambiguous; {} matches: {details}",
                matches.len()
            );
        }
        self.stop_records(matches, wait)
    }

    pub fn stop_run(&self, run_id: &str, wait: Duration) -> Result<AgentStopReport> {
        validate_text_field("run id", run_id, MAX_IDENTIFIER_BYTES)?;
        let matches = self.list(&AgentListFilter {
            run_id: Some(run_id.to_string()),
        })?;
        self.stop_records(matches, wait)
    }

    fn stop_records(
        &self,
        records: Vec<AgentProcessRecord>,
        wait: Duration,
    ) -> Result<AgentStopReport> {
        if wait > MAX_STOP_WAIT {
            bail!(
                "agent stop wait exceeds the maximum {} seconds",
                MAX_STOP_WAIT.as_secs()
            );
        }
        let mut stopped = Vec::with_capacity(records.len());
        for process in records {
            let outcome = terminate_process(&process, wait)
                .with_context(|| format!("failed to stop {}", process.summary()))?;
            self.remove_identity(process.pid, &process.process_start_time)?;
            stopped.push(AgentStopEntry { process, outcome });
        }
        Ok(AgentStopReport { stopped })
    }

    fn remove_identity(&self, pid: u32, start_time: &str) -> Result<()> {
        self.update_state(|state| {
            state.processes.retain(|process| {
                !(process.pid == pid && process.process_start_time == start_time)
            });
            Ok(())
        })
    }

    fn update_state(&self, operation: impl FnOnce(&mut RegistryState) -> Result<()>) -> Result<()> {
        let root = SafeRoot::open_or_create(self.repo.join(".maco").join("agents"))?;
        let lock = KernelStateLock::acquire_direct(&root, REGISTRY_LOCK)?;
        AtomicStateWriter::scavenge_direct_temps(&root, REGISTRY_FILE)?;
        let mut state = read_state(&root, &self.repo)?;
        operation(&mut state)?;
        state.validate(&self.repo)?;
        let mut contents =
            serde_json::to_vec_pretty(&state).context("failed to serialize agent registry")?;
        contents.push(b'\n');
        AtomicStateWriter::write_direct_fenced(&root, REGISTRY_FILE, &contents, || {
            lock.verify_direct_binding(&root)
        })
        .context("failed to commit agent registry")
    }

    #[cfg(test)]
    fn replace_records(&self, records: Vec<AgentProcessRecord>) -> Result<()> {
        self.update_state(|state| {
            state.processes = records;
            Ok(())
        })
    }

    fn snapshot_records(&self) -> Result<Vec<AgentProcessRecord>> {
        let root = SafeRoot::open_or_create(self.repo.join(".maco").join("agents"))?;
        let _lock = KernelStateLock::acquire_direct(&root, REGISTRY_LOCK)?;
        Ok(read_state(&root, &self.repo)?.processes)
    }

    #[cfg(test)]
    fn snapshot_all(&self) -> Result<Vec<AgentProcessRecord>> {
        self.snapshot_records()
    }
}

fn read_state(root: &SafeRoot, repo: &Path) -> Result<RegistryState> {
    if !root.direct_child_exists(REGISTRY_FILE)? {
        return Ok(RegistryState::default());
    }
    let contents = BoundedRegularReader::read_direct(root, REGISTRY_FILE, MAX_REGISTRY_BYTES)
        .context("failed to read agent registry")?;
    let state: RegistryState =
        serde_json::from_slice(&contents).context("agent registry is not valid JSON")?;
    state.validate(repo)?;
    Ok(state)
}

fn validate_text_field(label: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        bail!("{label} is empty or exceeds its safety bound");
    }
    Ok(())
}

fn unix_timestamp_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    u64::try_from(elapsed.as_millis()).context("launch timestamp does not fit u64")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessIdentityState {
    Live,
    Gone,
    Reused,
}

fn process_state(pid: u32, expected_start_time: &str) -> Result<ProcessIdentityState> {
    if !process_exists(pid)? {
        return Ok(ProcessIdentityState::Gone);
    }
    match process_identity(pid) {
        Ok(('Z' | 'X', _)) => Ok(ProcessIdentityState::Gone),
        Ok((_, observed)) if observed == expected_start_time => Ok(ProcessIdentityState::Live),
        Ok(_) => Ok(ProcessIdentityState::Reused),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(ProcessIdentityState::Gone)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn process_exists(pid: u32) -> Result<bool> {
    let pid = libc::pid_t::try_from(pid).context("PID does not fit Unix pid_t")?;
    // SAFETY: signal 0 performs an existence/permission check and does not access Rust memory.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error).context("failed to probe process liveness"),
    }
}

#[cfg(not(unix))]
fn process_exists(_pid: u32) -> Result<bool> {
    bail!("agent process liveness checks are not implemented on this platform")
}

#[cfg(target_os = "linux")]
pub fn process_start_time(pid: u32) -> Result<String> {
    process_identity(pid).map(|(_, start_time)| start_time)
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> Result<(char, String)> {
    let path = PathBuf::from("/proc").join(pid.to_string()).join("stat");
    let stat = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read process identity {}", path.display()))?;
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .context("process stat identity is malformed")?;
    let mut fields = fields.split_ascii_whitespace();
    let state = fields
        .next()
        .and_then(|value| value.chars().next())
        .context("process stat omits the state field")?;
    let token = fields
        .nth(18)
        .context("process stat omits the start-time field")?;
    let token = token
        .parse::<u64>()
        .context("process start-time field is not an integer")?;
    let boot_time = linux_boot_time()?;
    Ok((state, format!("{boot_time}:{token}")))
}

#[cfg(target_os = "linux")]
fn linux_boot_time() -> Result<u64> {
    let stat = std::fs::read_to_string("/proc/stat")
        .context("failed to read Linux boot-time identity /proc/stat")?;
    parse_linux_boot_time(&stat)
}

#[cfg(target_os = "linux")]
fn parse_linux_boot_time(stat: &str) -> Result<u64> {
    let value = stat
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .context("Linux /proc/stat omits the btime field")?;
    let boot_time = value
        .trim()
        .parse::<u64>()
        .context("Linux /proc/stat btime field is not an integer")?;
    if boot_time == 0 {
        bail!("Linux /proc/stat btime field is zero");
    }
    Ok(boot_time)
}

#[cfg(not(target_os = "linux"))]
fn process_identity(_pid: u32) -> Result<(char, String)> {
    bail!("PID start-time identity is not implemented on this platform")
}

#[cfg(not(target_os = "linux"))]
pub fn process_start_time(_pid: u32) -> Result<String> {
    bail!("PID start-time identity is not implemented on this platform")
}

#[cfg(unix)]
fn signal_process(pid: u32, signal: libc::c_int) -> Result<bool> {
    let pid = libc::pid_t::try_from(pid).context("PID does not fit Unix pid_t")?;
    // SAFETY: kill sends the caller-supplied valid signal to one positive PID and does not access
    // Rust memory.
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(error).context("failed to signal agent process")
    }
}

#[cfg(not(unix))]
fn signal_process(_pid: u32, _signal: libc::c_int) -> Result<bool> {
    bail!("agent process signals are not implemented on this platform")
}

#[cfg(target_os = "linux")]
enum LinuxSignalTarget {
    Pidfd(std::os::fd::OwnedFd),
    RawPid(u32),
}

#[cfg(target_os = "linux")]
enum PidfdOpen {
    Open(std::os::fd::OwnedFd),
    Gone,
    Unsupported,
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: u32) -> Result<PidfdOpen> {
    let pid = libc::pid_t::try_from(pid).context("PID does not fit Unix pid_t")?;
    // SAFETY: pidfd_open only consumes a positive PID and flags; it does not access Rust memory.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) => Ok(PidfdOpen::Gone),
            Some(libc::ENOSYS) => Ok(PidfdOpen::Unsupported),
            _ => Err(error).context("failed to open a pidfd for the recorded agent process"),
        };
    }
    let fd = i32::try_from(fd).context("pidfd did not fit a file descriptor")?;
    // SAFETY: pidfd_open returned a new owned file descriptor on success.
    Ok(PidfdOpen::Open(unsafe {
        std::os::fd::FromRawFd::from_raw_fd(fd)
    }))
}

#[cfg(target_os = "linux")]
fn bind_linux_signal_target(record: &AgentProcessRecord) -> Result<Option<LinuxSignalTarget>> {
    match process_state(record.pid, &record.process_start_time)? {
        ProcessIdentityState::Gone | ProcessIdentityState::Reused => return Ok(None),
        ProcessIdentityState::Live => {}
    }
    match open_pidfd(record.pid)? {
        PidfdOpen::Gone => Ok(None),
        PidfdOpen::Unsupported => Ok(Some(LinuxSignalTarget::RawPid(record.pid))),
        PidfdOpen::Open(pidfd) => match process_state(record.pid, &record.process_start_time)? {
            ProcessIdentityState::Reused => Ok(None),
            ProcessIdentityState::Live | ProcessIdentityState::Gone => {
                Ok(Some(LinuxSignalTarget::Pidfd(pidfd)))
            }
        },
    }
}

#[cfg(target_os = "linux")]
fn signal_linux_target(target: &LinuxSignalTarget, signal: libc::c_int) -> Result<bool> {
    match target {
        LinuxSignalTarget::RawPid(pid) => signal_process(*pid, signal),
        LinuxSignalTarget::Pidfd(pidfd) => {
            use std::os::fd::AsRawFd;
            // SAFETY: pidfd is an owned pidfd; a null siginfo and zero flags request a
            // plain signal to that process instance, not a recycled PID.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::c_void>(),
                    0_u32,
                )
            };
            if rc == 0 {
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(false)
            } else {
                Err(error).context("failed to signal agent process through its pidfd")
            }
        }
    }
}

fn terminate_process(record: &AgentProcessRecord, wait: Duration) -> Result<AgentStopOutcome> {
    #[cfg(target_os = "linux")]
    {
        let Some(target) = bind_linux_signal_target(record)? else {
            return Ok(AgentStopOutcome::AlreadyExited);
        };
        if !signal_linux_target(&target, libc::SIGTERM)? {
            return Ok(AgentStopOutcome::AlreadyExited);
        }
        if wait_until_identity_gone(record, wait)? {
            return Ok(AgentStopOutcome::Terminated);
        }
        match process_state(record.pid, &record.process_start_time)? {
            ProcessIdentityState::Gone | ProcessIdentityState::Reused => {
                return Ok(AgentStopOutcome::Terminated);
            }
            ProcessIdentityState::Live => {}
        }
        if !signal_linux_target(&target, libc::SIGKILL)? {
            return Ok(AgentStopOutcome::Killed);
        }
        if wait_until_identity_gone(record, KILL_CONFIRMATION_WAIT)? {
            Ok(AgentStopOutcome::Killed)
        } else {
            bail!("PID {} remained live after SIGKILL escalation", record.pid)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        match process_state(record.pid, &record.process_start_time)? {
            ProcessIdentityState::Gone | ProcessIdentityState::Reused => {
                return Ok(AgentStopOutcome::AlreadyExited);
            }
            ProcessIdentityState::Live => {}
        }
        #[cfg(unix)]
        let term_signal = libc::SIGTERM;
        #[cfg(not(unix))]
        let term_signal = 0;
        if !signal_process(record.pid, term_signal)? {
            return Ok(AgentStopOutcome::AlreadyExited);
        }
        if wait_until_identity_gone(record, wait)? {
            return Ok(AgentStopOutcome::Terminated);
        }
        match process_state(record.pid, &record.process_start_time)? {
            ProcessIdentityState::Gone | ProcessIdentityState::Reused => {
                return Ok(AgentStopOutcome::Terminated);
            }
            ProcessIdentityState::Live => {}
        }
        #[cfg(unix)]
        let kill_signal = libc::SIGKILL;
        #[cfg(not(unix))]
        let kill_signal = 0;
        if !signal_process(record.pid, kill_signal)? {
            return Ok(AgentStopOutcome::Killed);
        }
        if wait_until_identity_gone(record, KILL_CONFIRMATION_WAIT)? {
            Ok(AgentStopOutcome::Killed)
        } else {
            bail!("PID {} remained live after SIGKILL escalation", record.pid)
        }
    }
}

fn wait_until_identity_gone(record: &AgentProcessRecord, duration: Duration) -> Result<bool> {
    let deadline = Instant::now()
        .checked_add(duration)
        .context("agent stop wait exceeds the platform Instant range")?;
    loop {
        if !matches!(
            process_state(record.pid, &record.process_start_time)?,
            ProcessIdentityState::Live
        ) {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(STOP_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Repository;
    use std::process::{Child, Command};
    use tempfile::TempDir;

    struct SleepChild(Child);

    impl SleepChild {
        fn spawn() -> Result<Self> {
            let program = [
                "/run/current-system/sw/bin/sleep",
                "/usr/bin/sleep",
                "/bin/sleep",
            ]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .context("sleep executable")?;
            Ok(Self(
                Command::new(program)
                    .arg("60")
                    .spawn()
                    .context("spawn sleep")?,
            ))
        }

        fn pid(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for SleepChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn registry() -> Result<(TempDir, AgentRegistry)> {
        let temp = TempDir::new().context("tempdir")?;
        Repository::init(temp.path()).context("init repository")?;
        let registry = AgentRegistry::open(temp.path())?;
        Ok((temp, registry))
    }

    fn metadata(
        registry: &AgentRegistry,
        run_id: &str,
        task_id: &str,
    ) -> Result<AgentLaunchMetadata> {
        AgentLaunchMetadata::new(registry.repo(), "worker", run_id, task_id)
    }

    #[test]
    fn registry_round_trip_preserves_process_record() -> Result<()> {
        let (_temp, registry) = registry()?;
        let child = SleepChild::spawn()?;
        let expected = registry.register(
            &metadata(&registry, "run-round-trip", "task-a")?,
            child.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;

        let listed = registry.list(&AgentListFilter::default())?;
        assert_eq!(listed, vec![expected]);
        Ok(())
    }

    #[test]
    fn stale_gc_removes_dead_and_reused_pid_records() -> Result<()> {
        let (_temp, registry) = registry()?;
        let mut dead = SleepChild::spawn()?;
        let dead_record = registry.register(
            &metadata(&registry, "run-stale", "dead")?,
            dead.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        dead.0.kill().context("kill dead fixture")?;
        dead.0.wait().context("wait dead fixture")?;

        let current_pid = std::process::id();
        let mut reused = AgentProcessRecord {
            pid: current_pid,
            process_start_time: process_start_time(current_pid)?,
            role: "worker".to_string(),
            run_id: "run-stale".to_string(),
            task_id: "reused".to_string(),
            parent: None,
            repo: registry.repo().to_path_buf(),
            argv: vec!["test".to_string()],
            launch_timestamp_ms: unix_timestamp_ms()?,
        };
        reused.process_start_time.push('0');
        registry.replace_records(vec![dead_record, reused])?;

        assert!(registry.list(&AgentListFilter::default())?.is_empty());
        assert!(registry.snapshot_all()?.is_empty());
        Ok(())
    }

    #[test]
    fn inspect_reports_live_and_stale_without_pruning() -> Result<()> {
        let (_temp, registry) = registry()?;
        let live = SleepChild::spawn()?;
        let live_record = registry.register(
            &metadata(&registry, "run-inspect", "live")?,
            live.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        let mut dead = SleepChild::spawn()?;
        let dead_record = registry.register(
            &metadata(&registry, "run-inspect", "dead")?,
            dead.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        dead.0.kill().context("kill inspect fixture")?;
        dead.0.wait().context("wait inspect fixture")?;

        let inspections = registry.inspect()?;
        assert_eq!(inspections.len(), 2);
        let live_inspection = inspections
            .iter()
            .find(|inspection| inspection.process.pid == live_record.pid)
            .context("live inspection")?;
        let stale_inspection = inspections
            .iter()
            .find(|inspection| inspection.process.pid == dead_record.pid)
            .context("stale inspection")?;
        assert_eq!(live_inspection.identity, AgentIdentityLiveness::Live);
        assert_eq!(stale_inspection.identity, AgentIdentityLiveness::Stale);
        assert_eq!(registry.snapshot_all()?.len(), 2);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_process_start_time_is_boot_scoped() -> Result<()> {
        let token = process_start_time(std::process::id())?;
        let (boot_time, start_ticks) = token
            .split_once(':')
            .context("boot-scoped process identity separator")?;
        assert_eq!(boot_time.parse::<u64>()?, linux_boot_time()?);
        assert!(start_ticks.parse::<u64>()? > 0);
        assert_eq!(parse_linux_boot_time("cpu 1 2 3\nbtime 12345\n")?, 12345);
        assert!(parse_linux_boot_time("cpu 1 2 3\n").is_err());
        Ok(())
    }

    #[test]
    fn list_filters_by_run_id() -> Result<()> {
        let (_temp, registry) = registry()?;
        let first = SleepChild::spawn()?;
        let second = SleepChild::spawn()?;
        registry.register(
            &metadata(&registry, "run-one", "task-one")?,
            first.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        let expected = registry.register(
            &metadata(&registry, "run-two", "task-two")?,
            second.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;

        assert_eq!(
            registry.list(&AgentListFilter {
                run_id: Some("run-two".to_string())
            })?,
            vec![expected]
        );
        Ok(())
    }

    #[test]
    fn registry_preserves_parent_linkage() -> Result<()> {
        let (_temp, registry) = registry()?;
        let child = SleepChild::spawn()?;
        let expected = registry.register(
            &metadata(&registry, "run-parented", "task-child")?.with_parent("run-parented")?,
            child.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;
        assert_eq!(expected.parent.as_deref(), Some("run-parented"));
        assert_eq!(
            registry.list(&AgentListFilter {
                run_id: Some("run-parented".to_string())
            })?,
            vec![expected]
        );
        Ok(())
    }

    #[test]
    fn stop_refuses_ambiguous_selector_and_lists_matches() -> Result<()> {
        let (_temp, registry) = registry()?;
        let first = SleepChild::spawn()?;
        let second = SleepChild::spawn()?;
        for (task, child) in [("task-one", &first), ("task-two", &second)] {
            registry.register(
                &metadata(&registry, "shared-run", task)?,
                child.pid(),
                vec!["sleep".to_string(), "60".to_string()],
            )?;
        }

        let error = registry
            .stop_selector("shared-run", Duration::from_millis(50))
            .expect_err("selector must be ambiguous");
        let message = error.to_string();
        assert!(message.contains("ambiguous"));
        assert!(message.contains(&first.pid().to_string()));
        assert!(message.contains(&second.pid().to_string()));
        assert!(process_exists(first.pid())?);
        assert!(process_exists(second.pid())?);
        Ok(())
    }

    #[test]
    fn stop_terminates_spawned_long_running_child() -> Result<()> {
        let (_temp, registry) = registry()?;
        let mut child = SleepChild::spawn()?;
        registry.register(
            &metadata(&registry, "run-stop", "task-stop")?,
            child.pid(),
            vec!["sleep".to_string(), "60".to_string()],
        )?;

        let report = registry.stop_selector("task-stop", Duration::from_secs(1))?;
        assert_eq!(report.stopped.len(), 1);
        assert_eq!(report.stopped[0].outcome, AgentStopOutcome::Terminated);
        let status = child.0.wait().context("wait stopped child")?;
        assert!(!status.success());
        assert!(registry.snapshot_all()?.is_empty());
        Ok(())
    }

    #[test]
    fn terminate_process_does_not_signal_a_reused_pid() -> Result<()> {
        let current_pid = std::process::id();
        let record = AgentProcessRecord {
            pid: current_pid,
            process_start_time: "0:1".to_string(),
            role: "worker".to_string(),
            run_id: "run-reused".to_string(),
            task_id: "reused".to_string(),
            parent: None,
            repo: PathBuf::from("/tmp/maco-agent-lifecycle-reused"),
            argv: vec!["test".to_string()],
            launch_timestamp_ms: unix_timestamp_ms()?,
        };
        let outcome = terminate_process(&record, Duration::from_millis(10))?;
        assert_eq!(outcome, AgentStopOutcome::AlreadyExited);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_stop_binds_a_pidfd_for_the_recorded_start_time() -> Result<()> {
        let child = SleepChild::spawn()?;
        let record = AgentProcessRecord {
            pid: child.pid(),
            process_start_time: process_start_time(child.pid())?,
            role: "worker".to_string(),
            run_id: "run-pidfd".to_string(),
            task_id: "pidfd".to_string(),
            parent: None,
            repo: PathBuf::from("/tmp/maco-agent-lifecycle-pidfd"),
            argv: vec!["sleep".to_string()],
            launch_timestamp_ms: unix_timestamp_ms()?,
        };
        let target = bind_linux_signal_target(&record)?.context("live process must bind")?;
        assert!(matches!(target, LinuxSignalTarget::Pidfd(_)));
        Ok(())
    }
}
