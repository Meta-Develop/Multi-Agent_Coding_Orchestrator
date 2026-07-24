use crate::{
    artifacts::discover_repo_root,
    safe_state::{AtomicStateWriter, BoundedRegularReader, KernelStateLock, SafeRoot},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
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
        };
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<()> {
        validate_text_field("agent role", &self.role, MAX_ROLE_BYTES)?;
        validate_text_field("run id", &self.run_id, MAX_IDENTIFIER_BYTES)?;
        validate_text_field("task id", &self.task_id, MAX_IDENTIFIER_BYTES)?;
        if !self.repo.is_absolute() {
            bail!("agent lifecycle repository path must be absolute");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentProcessRecord {
    pub pid: u32,
    pub process_start_time: String,
    pub role: String,
    pub run_id: String,
    pub task_id: String,
    pub repo: PathBuf,
    pub argv: Vec<String>,
    pub launch_timestamp_ms: u64,
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
        Ok(())
    }

    fn summary(&self) -> String {
        format!(
            "pid={} role={} run_id={} task_id={}",
            self.pid, self.role, self.run_id, self.task_id
        )
    }
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

    #[cfg(test)]
    fn snapshot_all(&self) -> Result<Vec<AgentProcessRecord>> {
        let root = SafeRoot::open_or_create(self.repo.join(".maco").join("agents"))?;
        let _lock = KernelStateLock::acquire_direct(&root, REGISTRY_LOCK)?;
        Ok(read_state(&root, &self.repo)?.processes)
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
        Ok((state, _)) if matches!(state, 'Z' | 'X') => Ok(ProcessIdentityState::Gone),
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
    Ok((state, token.to_string()))
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

fn terminate_process(record: &AgentProcessRecord, wait: Duration) -> Result<AgentStopOutcome> {
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
}
