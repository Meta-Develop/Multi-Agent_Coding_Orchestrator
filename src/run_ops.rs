//! Shared supervise/autopilot run-artifact operations.
//!
//! Owns launch preflight evidence, same-repository live-run collision
//! preflight, the append-only heartbeat ledger, and the operator-facing
//! end-of-run summary sidecar.

use crate::{
    agent_lifecycle::{
        process_start_time, AgentIdentityLiveness, AgentLaunchMetadata, AgentProcessInspection,
        AgentProcessRecord, AgentRegistry,
    },
    artifacts::{
        discover_repo_root, ArtifactFileDisposition, ArtifactRunWriter, RunArtifactFamily,
    },
    orchestrator::RunId,
    repo_map,
    runtime_adapter::AdapterId,
    safe_state::BoundedRegularReader,
    sync_store::SyncStore,
};
use anyhow::{bail, Context, Result};
use git2::{Repository, Status, StatusOptions};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const HEARTBEAT_RELATIVE: &str = "liveness/heartbeat.jsonl";
pub const OPERATOR_SUMMARY_RELATIVE: &str = "SUMMARY.md";
pub const PREFLIGHT_INDEX_RELATIVE: &str = "preflight/index.json";
const PREFLIGHT_GIT_STATUS_RELATIVE: &str = "preflight/git-status.txt";
const PREFLIGHT_GIT_STATUS_MARKER: &str = "preflight/git-status.status";
const PREFLIGHT_REPO_MAP_RELATIVE: &str = "preflight/repo-map.json";
const PREFLIGHT_REPO_MAP_MARKER: &str = "preflight/repo-map.status";
const PREFLIGHT_SYNC_STATUS_RELATIVE: &str = "preflight/sync-status.json";
const PREFLIGHT_SYNC_STATUS_MARKER: &str = "preflight/sync-status.status";
const PREFLIGHT_RUNTIME_RELATIVE: &str = "preflight/runtime.json";
const PREFLIGHT_RUNTIME_MARKER: &str = "preflight/runtime.status";
const PREFLIGHT_RUN_RELATIVE: &str = "preflight/run.json";
const PREFLIGHT_LIVE_RUNS_RELATIVE: &str = "preflight/live-runs.json";
const MAX_HEARTBEAT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_HEARTBEAT_NOTE_BYTES: usize = 4 * 1024;
const SUPERVISOR_PROCESS_ROLES: &[&str] = &["supervise", "supervisor", "autopilot"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatRecord {
    pub timestamp: String,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureOutcome {
    pub name: String,
    pub status: CaptureStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureStatus {
    Ok,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPreflightIndex {
    pub version: u32,
    pub family: String,
    pub run_id: String,
    pub captures: Vec<CaptureOutcome>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LaunchPreflightSpec {
    pub family: RunArtifactFamily,
    pub run_id: RunId,
    pub runtime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_bin: Option<PathBuf>,
    pub allow_dirty_primary: bool,
    pub allow_live_run_collision: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveRunCollisionReport {
    pub live: Vec<AgentProcessRecord>,
    pub stale: Vec<AgentProcessRecord>,
    pub uncertain: Vec<AgentProcessInspection>,
}

impl LiveRunCollisionReport {
    fn empty() -> Self {
        Self {
            live: Vec::new(),
            stale: Vec::new(),
            uncertain: Vec::new(),
        }
    }

    pub fn blocks_launch(&self) -> bool {
        !self.live.is_empty() || !self.uncertain.is_empty()
    }
}

/// Drops the current-process supervisor registration unless a parent already
/// owned the same PID identity.
pub struct SupervisorProcessGuard {
    registry: AgentRegistry,
    pid: u32,
    start_time: String,
}

impl Drop for SupervisorProcessGuard {
    fn drop(&mut self) {
        let _ = self.registry.unregister(self.pid, &self.start_time);
    }
}

pub fn heartbeat_relative_path() -> PathBuf {
    PathBuf::from(HEARTBEAT_RELATIVE)
}

pub fn operator_summary_relative_path() -> PathBuf {
    PathBuf::from(OPERATOR_SUMMARY_RELATIVE)
}

pub fn is_supervisor_process_role(role: &str) -> bool {
    SUPERVISOR_PROCESS_ROLES
        .iter()
        .any(|expected| role.eq_ignore_ascii_case(expected))
}

pub fn current_process_identity() -> Result<(u32, String)> {
    let pid = std::process::id();
    Ok((pid, process_start_time(pid)?))
}

pub fn inspect_supervisor_process_collisions(
    repo: impl AsRef<Path>,
) -> Result<LiveRunCollisionReport> {
    let repo = discover_repo_root(repo.as_ref())?;
    let registry = AgentRegistry::open(&repo)?;
    let inspections = registry.inspect()?;
    let current = current_process_identity().ok();
    let mut report = LiveRunCollisionReport::empty();
    for inspection in inspections {
        if !is_supervisor_process_role(&inspection.process.role) {
            continue;
        }
        if current.as_ref().is_some_and(|(pid, start_time)| {
            inspection.process.pid == *pid && inspection.process.process_start_time == *start_time
        }) {
            continue;
        }
        match inspection.identity {
            AgentIdentityLiveness::Live => report.live.push(inspection.process),
            AgentIdentityLiveness::Stale => report.stale.push(inspection.process),
            AgentIdentityLiveness::Uncertain => report.uncertain.push(inspection),
        }
    }
    Ok(report)
}

pub fn refuse_live_run_collision(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
    run_id: &RunId,
    allow_live_run_collision: bool,
) -> Result<LiveRunCollisionReport> {
    let report = inspect_supervisor_process_collisions(repo)?;
    if report.blocks_launch() && !allow_live_run_collision {
        bail!("{}", live_run_collision_message(family, run_id, &report));
    }
    Ok(report)
}

pub fn register_current_supervisor_process(
    repo: impl AsRef<Path>,
    role: &str,
    run_id: &RunId,
) -> Result<Option<SupervisorProcessGuard>> {
    if !is_supervisor_process_role(role) {
        bail!("supervisor process role '{role}' is not a supervise/autopilot role");
    }
    let repo = discover_repo_root(repo.as_ref())?;
    let registry = AgentRegistry::open(&repo)?;
    let (pid, start_time) = current_process_identity()?;
    if registry.inspect()?.iter().any(|inspection| {
        inspection.process.pid == pid && inspection.process.process_start_time == start_time
    }) {
        return Ok(None);
    }
    let metadata = AgentLaunchMetadata::new(&repo, role, run_id.as_str(), role)?;
    let argv = supervisor_process_argv();
    let record = registry.register(&metadata, pid, argv)?;
    Ok(Some(SupervisorProcessGuard {
        registry,
        pid: record.pid,
        start_time: record.process_start_time,
    }))
}

pub fn persist_launch_preflight(
    writer: &mut ArtifactRunWriter,
    repo: impl AsRef<Path>,
    spec: &LaunchPreflightSpec,
    collision: &LiveRunCollisionReport,
) -> Result<LaunchPreflightIndex> {
    let repo = discover_repo_root(repo.as_ref())?;
    let captures = vec![
        write_capture(
            writer,
            "git_status",
            PREFLIGHT_GIT_STATUS_RELATIVE,
            PREFLIGHT_GIT_STATUS_MARKER,
            capture_git_status_text(&repo),
        )?,
        write_json_capture(
            writer,
            "repo_map",
            PREFLIGHT_REPO_MAP_RELATIVE,
            PREFLIGHT_REPO_MAP_MARKER,
            capture_repo_map(&repo),
        )?,
        write_json_capture(
            writer,
            "sync_status",
            PREFLIGHT_SYNC_STATUS_RELATIVE,
            PREFLIGHT_SYNC_STATUS_MARKER,
            capture_sync_status(&repo),
        )?,
        write_json_capture(
            writer,
            "runtime",
            PREFLIGHT_RUNTIME_RELATIVE,
            PREFLIGHT_RUNTIME_MARKER,
            capture_runtime_probe(spec),
        )?,
        {
            write_json_artifact(writer, PREFLIGHT_RUN_RELATIVE, spec)?;
            write_json_artifact(writer, PREFLIGHT_LIVE_RUNS_RELATIVE, collision)?;
            CaptureOutcome {
                name: "run_parameters".to_string(),
                status: CaptureStatus::Ok,
                error: None,
            }
        },
        CaptureOutcome {
            name: "live_runs".to_string(),
            status: CaptureStatus::Ok,
            error: None,
        },
    ];

    let index = LaunchPreflightIndex {
        version: 1,
        family: spec.family.label().to_string(),
        run_id: spec.run_id.as_str().to_string(),
        captures,
    };
    write_json_artifact(writer, PREFLIGHT_INDEX_RELATIVE, &index)?;
    Ok(index)
}

pub fn append_run_heartbeat(
    writer: &mut ArtifactRunWriter,
    phase: impl Into<String>,
    assignment_id: Option<String>,
    status: impl Into<String>,
    note: Option<String>,
) -> Result<()> {
    let record = HeartbeatRecord {
        timestamp: unix_timestamp()?,
        phase: phase.into(),
        assignment_id,
        status: status.into(),
        note: note.and_then(truncate_note),
    };
    writer
        .append_json_line(
            HEARTBEAT_RELATIVE,
            &record,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .context("failed to append run heartbeat")?;
    Ok(())
}

pub fn append_run_heartbeat_best_effort(
    writer: &mut ArtifactRunWriter,
    phase: impl Into<String>,
    assignment_id: Option<String>,
    status: impl Into<String>,
    note: Option<String>,
) {
    if let Err(error) = append_run_heartbeat(writer, phase, assignment_id, status, note) {
        tracing::warn!(error = %error, "failed to append supervise/autopilot heartbeat");
    }
}

pub fn write_operator_summary(writer: &mut ArtifactRunWriter, markdown: &str) -> Result<()> {
    let mut contents = markdown.as_bytes().to_vec();
    if !contents.ends_with(b"\n") {
        contents.push(b'\n');
    }
    writer
        .write_bytes(
            OPERATOR_SUMMARY_RELATIVE,
            &contents,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .context("failed to write operator-facing end-of-run summary")?;
    Ok(())
}

pub fn read_heartbeat_ledger(run_dir: impl AsRef<Path>) -> Result<Vec<HeartbeatRecord>> {
    let bytes = match BoundedRegularReader::read_relative(
        run_dir.as_ref(),
        HEARTBEAT_RELATIVE,
        MAX_HEARTBEAT_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if path_is_missing(&error) => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let text = String::from_utf8(bytes).context("heartbeat ledger is not UTF-8")?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<HeartbeatRecord>(trimmed) {
            Ok(record) => records.push(record),
            Err(error) if index + 1 == text.lines().count() => {
                // A concurrent append may leave the last line incomplete.
                tracing::debug!(error = %error, "ignored trailing partial heartbeat line");
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to parse heartbeat ledger line {}", index + 1)
                })
            }
        }
    }
    Ok(records)
}

pub fn last_heartbeat(run_dir: impl AsRef<Path>) -> Result<Option<HeartbeatRecord>> {
    Ok(read_heartbeat_ledger(run_dir)?.pop())
}

pub fn operator_summary_exists(run_dir: impl AsRef<Path>) -> bool {
    run_dir.as_ref().join(OPERATOR_SUMMARY_RELATIVE).is_file()
}

pub fn live_run_collision_message(
    family: RunArtifactFamily,
    run_id: &RunId,
    report: &LiveRunCollisionReport,
) -> String {
    let mut details = Vec::new();
    for process in &report.live {
        details.push(format!(
            "live {} run '{}' pid={} start={}",
            process.role, process.run_id, process.pid, process.process_start_time
        ));
    }
    for inspection in &report.uncertain {
        details.push(format!(
            "uncertain {} run '{}' pid={} start={}: {}",
            inspection.process.role,
            inspection.process.run_id,
            inspection.process.pid,
            inspection.process.process_start_time,
            inspection
                .uncertainty_reason
                .as_deref()
                .unwrap_or("process enumeration failed")
        ));
    }
    format!(
        "refusing to launch {} run '{}' while another supervise/autopilot run still targets this repository ({}); rerun with --force-live-run to override. --force-live-run is launch-only and grants no authority to kill, interrupt, revert, or discard another run",
        family.label(),
        run_id.as_str(),
        details.join("; ")
    )
}

fn write_capture(
    writer: &mut ArtifactRunWriter,
    name: &str,
    relative: &str,
    marker: &str,
    captured: Result<String>,
) -> Result<CaptureOutcome> {
    match captured {
        Ok(body) => {
            writer.write_bytes(
                relative,
                body.as_bytes(),
                ArtifactFileDisposition::PrivateEvidence,
            )?;
            writer.write_bytes(marker, b"ok\n", ArtifactFileDisposition::PrivateEvidence)?;
            Ok(CaptureOutcome {
                name: name.to_string(),
                status: CaptureStatus::Ok,
                error: None,
            })
        }
        Err(error) => {
            let message = format!("failed: {error}");
            writer.write_bytes(
                marker,
                format!("{message}\n").as_bytes(),
                ArtifactFileDisposition::PrivateEvidence,
            )?;
            Ok(CaptureOutcome {
                name: name.to_string(),
                status: CaptureStatus::Failed,
                error: Some(error.to_string()),
            })
        }
    }
}

fn write_json_capture(
    writer: &mut ArtifactRunWriter,
    name: &str,
    relative: &str,
    marker: &str,
    captured: Result<Value>,
) -> Result<CaptureOutcome> {
    match captured {
        Ok(value) => {
            write_json_artifact(writer, relative, &value)?;
            writer.write_bytes(marker, b"ok\n", ArtifactFileDisposition::PrivateEvidence)?;
            Ok(CaptureOutcome {
                name: name.to_string(),
                status: CaptureStatus::Ok,
                error: None,
            })
        }
        Err(error) => {
            writer.write_bytes(
                marker,
                format!("failed: {error}\n").as_bytes(),
                ArtifactFileDisposition::PrivateEvidence,
            )?;
            Ok(CaptureOutcome {
                name: name.to_string(),
                status: CaptureStatus::Failed,
                error: Some(error.to_string()),
            })
        }
    }
}

fn write_json_artifact<T: Serialize>(
    writer: &mut ArtifactRunWriter,
    relative: &str,
    value: &T,
) -> Result<()> {
    writer
        .write_json(relative, value, ArtifactFileDisposition::PrivateEvidence)
        .with_context(|| format!("failed to write launch preflight artifact {relative}"))?;
    Ok(())
}

fn capture_git_status_text(repo: &Path) -> Result<String> {
    let repository = crate::git_repository::discover(repo)
        .with_context(|| format!("failed to open repository {}", repo.display()))?;
    format_git_status(&repository)
}

fn format_git_status(repo: &Repository) -> Result<String> {
    let head = repo.head().ok();
    let branch = head
        .as_ref()
        .and_then(|head| head.shorthand().ok())
        .unwrap_or("HEAD");
    let mut lines = vec![format!("## {branch}")];
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to capture git status")?;
    for entry in statuses.iter() {
        let path = entry.path().unwrap_or("<non-utf8>");
        lines.push(format!("{} {path}", short_status(entry.status())));
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn short_status(status: Status) -> String {
    let index = if status.is_index_new() {
        'A'
    } else if status.is_index_modified() {
        'M'
    } else if status.is_index_deleted() {
        'D'
    } else if status.is_index_renamed() {
        'R'
    } else if status.is_conflicted() {
        'U'
    } else {
        ' '
    };
    let worktree = if status.is_wt_new() {
        '?'
    } else if status.is_wt_modified() {
        'M'
    } else if status.is_wt_deleted() {
        'D'
    } else if status.is_wt_renamed() {
        'R'
    } else {
        ' '
    };
    if index == ' ' && worktree == '?' {
        "??".to_string()
    } else {
        format!("{index}{worktree}")
    }
}

fn capture_repo_map(repo: &Path) -> Result<Value> {
    let map = repo_map::scan_repository(repo).context("failed to capture repository map")?;
    serde_json::to_value(map).context("failed to serialize repository map")
}

fn capture_sync_status(repo: &Path) -> Result<Value> {
    let store = SyncStore::open(repo).context("failed to open sync store")?;
    let claims = store
        .status_snapshot()
        .context("failed to capture sync status")?;
    serde_json::to_value(claims).context("failed to serialize sync status")
}

fn capture_runtime_probe(spec: &LaunchPreflightSpec) -> Result<Value> {
    let adapter = AdapterId::parse(&spec.runtime);
    let capabilities = adapter.map(AdapterId::capabilities);
    let binary = spec
        .runtime_bin
        .clone()
        .or_else(|| adapter.map(|id| PathBuf::from(id.default_binary())));
    let binary_exists = binary.as_ref().is_some_and(|path| path.exists());
    serde_json::to_value(serde_json::json!({
        "runtime": spec.runtime,
        "binary_path": binary,
        "binary_exists": binary_exists,
        "version_status": "not_probed",
        "capabilities": capabilities,
        "ask_for_approval": capabilities.map(|caps| {
            match caps.blocking_pre_action_callback {
                crate::runtime_adapter::BlockingPreActionCallback::All => "supported",
                crate::runtime_adapter::BlockingPreActionCallback::CommandsOnly => "partial",
                crate::runtime_adapter::BlockingPreActionCallback::None => "unsupported",
            }
        }),
    }))
    .context("failed to serialize runtime probe")
}

fn supervisor_process_argv() -> Vec<String> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.is_empty() {
        vec!["maco".to_string()]
    } else {
        args
    }
}

fn unix_timestamp() -> Result<String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(format!("{}", elapsed.as_secs()))
}

fn truncate_note(note: String) -> Option<String> {
    if note.is_empty() {
        None
    } else if note.len() > MAX_HEARTBEAT_NOTE_BYTES {
        Some(note.chars().take(MAX_HEARTBEAT_NOTE_BYTES).collect())
    } else {
        Some(note)
    }
}

fn path_is_missing(error: &anyhow::Error) -> bool {
    error.to_string().contains("not found")
        || error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::RunId;
    use git2::{Repository, Signature};
    use std::{fs, process::Command};

    fn test_repo() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("repo");
        Repository::init(&path).expect("init repo");
        fs::write(path.join("README.md"), "baseline\n").expect("write readme");
        let repo = crate::git_repository::open(&path).expect("open repo");
        let mut index = repo.index().expect("index");
        index
            .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
            .expect("stage");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repo.commit(Some("HEAD"), &signature, &signature, "baseline", &tree, &[])
            .expect("commit");
        (temp, path)
    }

    fn reserve_writer(repo: &Path, family: RunArtifactFamily, run_id: &str) -> ArtifactRunWriter {
        ArtifactRunWriter::reserve(
            repo,
            family,
            RunId::new(run_id).expect("run id"),
            "run-ops-test",
        )
        .expect("reserve artifacts")
    }

    #[test]
    fn launch_preflight_records_success_and_failure_markers() {
        let (_temp, repo) = test_repo();
        fs::write(repo.join("dirty.txt"), "dirty\n").expect("dirty file");
        let mut writer = reserve_writer(&repo, RunArtifactFamily::Supervise, "preflight-ok");
        let spec = LaunchPreflightSpec {
            family: RunArtifactFamily::Supervise,
            run_id: RunId::new("preflight-ok").expect("run id"),
            runtime: "fake".to_string(),
            runtime_bin: Some(PathBuf::from("fake")),
            allow_dirty_primary: true,
            allow_live_run_collision: false,
        };
        let index =
            persist_launch_preflight(&mut writer, &repo, &spec, &LiveRunCollisionReport::empty())
                .expect("persist preflight");
        assert!(index
            .captures
            .iter()
            .any(|capture| capture.name == "git_status" && capture.status == CaptureStatus::Ok));
        assert!(index
            .captures
            .iter()
            .any(|capture| capture.name == "repo_map" && capture.status == CaptureStatus::Ok));
        assert!(index
            .captures
            .iter()
            .any(|capture| capture.name == "runtime" && capture.status == CaptureStatus::Ok));
        let git_status = fs::read_to_string(writer.run_dir().join(PREFLIGHT_GIT_STATUS_RELATIVE))
            .expect("git status");
        assert!(git_status.contains("dirty.txt"), "{git_status}");
        assert_eq!(
            fs::read_to_string(writer.run_dir().join(PREFLIGHT_GIT_STATUS_MARKER))
                .expect("git status marker"),
            "ok\n"
        );
    }

    #[test]
    fn heartbeat_ledger_appends_and_status_can_read_last_record() {
        let (_temp, repo) = test_repo();
        let mut writer = reserve_writer(&repo, RunArtifactFamily::Supervise, "heartbeat-ok");
        append_run_heartbeat(
            &mut writer,
            "initialized",
            None,
            "ok",
            Some("launch".to_string()),
        )
        .expect("initialized");
        append_run_heartbeat(
            &mut writer,
            "assignment_running",
            Some("child-a".to_string()),
            "running",
            None,
        )
        .expect("running");
        write_operator_summary(
            &mut writer,
            "# Supervise run heartbeat-ok\n\nNext: collect\n",
        )
        .expect("summary");
        let records = read_heartbeat_ledger(writer.run_dir()).expect("read ledger");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].phase, "initialized");
        assert_eq!(records[1].assignment_id.as_deref(), Some("child-a"));
        let last = last_heartbeat(writer.run_dir())
            .expect("last")
            .expect("present");
        assert_eq!(last.phase, "assignment_running");
        assert!(operator_summary_exists(writer.run_dir()));
    }

    fn spawn_sleep() -> std::process::Child {
        Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep from PATH")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_supervisor_identity_blocks_without_force() {
        let (_temp, repo) = test_repo();
        let run_id = RunId::new("collision-live").expect("run id");
        let mut child = spawn_sleep();
        let registry = AgentRegistry::open(&repo).expect("registry");
        let metadata = AgentLaunchMetadata::new(&repo, "supervise", run_id.as_str(), "supervise")
            .expect("metadata");
        registry
            .register(
                &metadata,
                child.id(),
                vec!["sleep".to_string(), "60".to_string()],
            )
            .expect("register live sibling");
        let other = RunId::new("collision-other").expect("other id");
        let error = refuse_live_run_collision(&repo, RunArtifactFamily::Supervise, &other, false)
            .expect_err("live collision");
        assert!(error.to_string().contains("--force-live-run"), "{error:#}");
        let forced = refuse_live_run_collision(&repo, RunArtifactFamily::Supervise, &other, true)
            .expect("forced launch");
        child.kill().expect("kill live sibling");
        let _ = child.wait();
        assert_eq!(forced.live.len(), 1);
        assert_eq!(forced.live[0].run_id, run_id.as_str());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_supervisor_identity_is_reported_without_blocking() {
        let (_temp, repo) = test_repo();
        let mut child = spawn_sleep();
        let registry = AgentRegistry::open(&repo).expect("registry");
        let metadata = AgentLaunchMetadata::new(&repo, "supervise", "stale-run", "supervise")
            .expect("metadata");
        registry
            .register(
                &metadata,
                child.id(),
                vec!["sleep".to_string(), "60".to_string()],
            )
            .expect("register stale candidate");
        child.kill().expect("kill");
        child.wait().expect("wait");
        let report = refuse_live_run_collision(
            &repo,
            RunArtifactFamily::Autopilot,
            &RunId::new("fresh-run").expect("fresh"),
            false,
        )
        .expect("stale must not block");
        assert!(report.live.is_empty());
        assert_eq!(report.stale.len(), 1);
        assert_eq!(report.stale[0].run_id, "stale-run");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_process_is_excluded_from_collision() {
        let (_temp, repo) = test_repo();
        let run_id = RunId::new("self-run").expect("run id");
        let _guard = register_current_supervisor_process(&repo, "autopilot", &run_id)
            .expect("register")
            .expect("new registration");
        let report = refuse_live_run_collision(&repo, RunArtifactFamily::Autopilot, &run_id, false)
            .expect("self identity is not a collision");
        assert!(report.live.is_empty());
        assert!(report.uncertain.is_empty());
    }
}
