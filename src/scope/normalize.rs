use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::orchestration_event::{OrchestrationEvent, OrchestrationEventKind, OrchestrationRole};

const RUN_FAMILIES: [(&str, &str); 5] = [
    ("o2", "o2"),
    ("autopilot", "autopilot"),
    ("inbox", "inbox"),
    ("consult", "consult"),
    ("o2-autopilot", "o2-autopilot"),
];
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_LOG_TAIL_BYTES: u64 = 128 * 1024;
const MAX_DISCOVERY_DEPTH: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryTarget {
    pub id: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct ScopeSnapshot {
    pub projects: Vec<ProjectSnapshot>,
}

impl ScopeSnapshot {
    pub fn events_for_run(
        &self,
        repo_id: &str,
        family: &str,
        run_id: &str,
    ) -> Option<&[NormalizedEvent]> {
        self.projects
            .iter()
            .find(|project| project.id == repo_id)
            .and_then(|project| {
                project
                    .runs
                    .iter()
                    .find(|run| run.family == family && run.run == run_id)
            })
            .map(|run| run.events.as_slice())
    }

    pub fn all_events(&self) -> Vec<NormalizedEvent> {
        let mut events = self
            .projects
            .iter()
            .flat_map(|project| project.runs.iter())
            .flat_map(|run| run.events.iter().cloned())
            .collect::<Vec<_>>();
        sort_and_deduplicate(&mut events);
        events
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ProjectSnapshot {
    pub id: String,
    pub path: PathBuf,
    pub runs: Vec<RunSummary>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RunSummary {
    pub family: String,
    pub run: String,
    pub run_dir: PathBuf,
    pub final_report_exists: bool,
    pub modified_unix_seconds: u64,
    pub event_count: usize,
    #[serde(skip)]
    pub events: Vec<NormalizedEvent>,
}

pub type NormalizedEvent = OrchestrationEvent;

pub fn scan_repositories(repositories: &[RepositoryTarget]) -> io::Result<ScopeSnapshot> {
    let mut targets = repositories.to_vec();
    targets.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.path.cmp(&right.path))
    });

    let mut projects = Vec::with_capacity(targets.len());
    for target in targets {
        projects.push(scan_repository(&target)?);
    }
    Ok(ScopeSnapshot { projects })
}

fn scan_repository(target: &RepositoryTarget) -> io::Result<ProjectSnapshot> {
    let mut discovered = Vec::new();
    for (family, directory) in RUN_FAMILIES {
        let run_root = target.path.join(".maco").join(directory).join("runs");
        for run_dir in read_child_directories(&run_root)? {
            let Some(run_name) = run_dir.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if run_name.is_empty() {
                continue;
            }
            let modified = no_follow_metadata(&run_dir)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(UNIX_EPOCH);
            let mut events = scan_run_events(target, run_name, &run_dir)?;
            sort_and_deduplicate(&mut events);
            discovered.push((
                RunSummary {
                    family: family.to_string(),
                    run: run_name.to_string(),
                    run_dir: run_dir.clone(),
                    final_report_exists: final_report_exists(family, &run_dir)?,
                    modified_unix_seconds: unix_seconds(modified),
                    event_count: events.len(),
                    events,
                },
                modified,
            ));
        }
    }

    discovered.sort_by(|(left, left_time), (right, right_time)| {
        right_time
            .cmp(left_time)
            .then_with(|| right.run.cmp(&left.run))
            .then_with(|| left.family.cmp(&right.family))
    });

    Ok(ProjectSnapshot {
        id: target.id.clone(),
        path: target.path.clone(),
        runs: discovered.into_iter().map(|(run, _)| run).collect(),
    })
}

fn scan_run_events(
    target: &RepositoryTarget,
    run_id: &str,
    run_dir: &Path,
) -> io::Result<Vec<NormalizedEvent>> {
    let journal = run_dir.join("events").join("orchestration.jsonl");
    if is_regular_file(&journal)? {
        return read_journal(&journal, &target.id, run_id);
    }

    let mut events = Vec::new();
    let mut parents = BTreeMap::new();
    let mut roles = BTreeMap::new();
    read_supervisor_plan(
        &run_dir.join("assignments").join("supervisor-plan.json"),
        &target.id,
        run_id,
        &mut events,
        &mut parents,
        &mut roles,
    )?;
    read_reports(
        &run_dir.join("reports"),
        &target.id,
        run_id,
        &parents,
        &roles,
        &mut events,
    )?;
    read_log_tails(
        &run_dir.join("logs"),
        &target.id,
        run_id,
        &parents,
        &roles,
        &mut events,
    )?;
    read_state_tsv(&run_dir.join("STATE.tsv"), &target.id, run_id, &mut events)?;
    read_heartbeat_tsv(
        &run_dir.join("HEARTBEAT.tsv"),
        &target.id,
        run_id,
        &mut events,
    )?;
    read_queue_tsv(&run_dir.join("queue.tsv"), &target.id, run_id, &mut events)?;
    read_escalations(run_dir, &target.id, run_id, &mut events)?;
    Ok(events)
}

fn read_journal(path: &Path, repo_id: &str, run_id: &str) -> io::Result<Vec<NormalizedEvent>> {
    let Some(bytes) = read_bounded(path, MAX_JOURNAL_BYTES)? else {
        return Ok(Vec::new());
    };
    let mut events = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(mut event) = serde_json::from_slice::<NormalizedEvent>(line) else {
            continue;
        };
        if event.ts.is_empty() || event.node.is_empty() {
            continue;
        }
        event.repo = repo_id.to_string();
        event.run = run_id.to_string();
        events.push(event);
    }
    sort_and_deduplicate(&mut events);
    Ok(events)
}

fn read_supervisor_plan(
    path: &Path,
    repo_id: &str,
    run_id: &str,
    events: &mut Vec<NormalizedEvent>,
    parents: &mut BTreeMap<String, Option<String>>,
    roles: &mut BTreeMap<String, OrchestrationRole>,
) -> io::Result<()> {
    let Some(value) = read_json(path)? else {
        return Ok(());
    };
    let ts = file_timestamp(path);
    if let Some(assignments) = value.get("assignments").and_then(Value::as_array) {
        for assignment in assignments {
            collect_assignment(
                assignment, None, repo_id, run_id, &ts, events, parents, roles,
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_assignment(
    assignment: &Value,
    parent: Option<&str>,
    repo_id: &str,
    run_id: &str,
    ts: &str,
    events: &mut Vec<NormalizedEvent>,
    parents: &mut BTreeMap<String, Option<String>>,
    roles: &mut BTreeMap<String, OrchestrationRole>,
) {
    let Some(node) = assignment.get("id").and_then(Value::as_str) else {
        return;
    };
    if node.is_empty() {
        return;
    }
    let role = scope_role(assignment.get("role").and_then(Value::as_str));
    let parent = parent.map(str::to_owned);
    parents.insert(node.to_string(), parent.clone());
    roles.insert(node.to_string(), role);
    events.push(NormalizedEvent {
        ts: ts.to_string(),
        repo: repo_id.to_string(),
        run: run_id.to_string(),
        node: node.to_string(),
        parent: parent.clone(),
        role,
        kind: OrchestrationEventKind::Spawn,
        payload: json!({"source": "assignments/supervisor-plan.json", "assignment": assignment}),
    });

    for child_key in ["assignments", "worker_assignments"] {
        if let Some(children) = assignment.get(child_key).and_then(Value::as_array) {
            for child in children {
                collect_assignment(
                    child,
                    Some(node),
                    repo_id,
                    run_id,
                    ts,
                    events,
                    parents,
                    roles,
                );
            }
        }
    }
}

fn read_reports(
    directory: &Path,
    repo_id: &str,
    run_id: &str,
    parents: &BTreeMap<String, Option<String>>,
    roles: &BTreeMap<String, OrchestrationRole>,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    for path in read_child_files(directory, Some("json"))? {
        let Some(report) = read_json(&path)? else {
            continue;
        };
        let fallback_node = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or(run_id);
        let node = report
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| report.get("run_id").and_then(Value::as_str))
            .unwrap_or(fallback_node);
        if node.is_empty() {
            continue;
        }
        let role = report
            .get("role")
            .and_then(Value::as_str)
            .map(|value| scope_role(Some(value)))
            .or_else(|| roles.get(node).copied())
            .unwrap_or_else(|| {
                if node == run_id || fallback_node == "supervisor-final" {
                    OrchestrationRole::Supervisor
                } else {
                    OrchestrationRole::Worker
                }
            });
        let parent = parents.get(node).cloned().flatten();
        let kind = report_kind(&report);
        let source = relative_source(directory, &path, "reports");
        let ts = file_timestamp(&path);
        events.push(NormalizedEvent {
            ts: ts.clone(),
            repo: repo_id.to_string(),
            run: run_id.to_string(),
            node: node.to_string(),
            parent: parent.clone(),
            role,
            kind,
            payload: json!({"source": source, "report": report}),
        });

        if let Some(token) = report.get("claim_token").filter(|token| !token.is_null()) {
            events.push(NormalizedEvent {
                ts: ts.clone(),
                repo: repo_id.to_string(),
                run: run_id.to_string(),
                node: node.to_string(),
                parent: parent.clone(),
                role,
                kind: OrchestrationEventKind::Claim,
                payload: json!({
                    "source": source,
                    "claim_token": token,
                    "assigned_paths": report.get("assigned_paths").cloned().unwrap_or(Value::Null),
                }),
            });
        }
        if let Some(validations) = report.get("validation_results").and_then(Value::as_array) {
            for validation in validations {
                events.push(NormalizedEvent {
                    ts: ts.clone(),
                    repo: repo_id.to_string(),
                    run: run_id.to_string(),
                    node: node.to_string(),
                    parent: parent.clone(),
                    role,
                    kind: OrchestrationEventKind::Gate,
                    payload: json!({"source": source, "validation": validation}),
                });
            }
        }
    }
    Ok(())
}

fn read_log_tails(
    directory: &Path,
    repo_id: &str,
    run_id: &str,
    parents: &BTreeMap<String, Option<String>>,
    roles: &BTreeMap<String, OrchestrationRole>,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    for path in read_child_files(directory, Some("jsonl"))? {
        let Some(record) = read_last_json_line(&path)? else {
            continue;
        };
        let Some(node) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        events.push(NormalizedEvent {
            ts: record
                .get("ts")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| file_timestamp(&path)),
            repo: repo_id.to_string(),
            run: run_id.to_string(),
            node: node.to_string(),
            parent: parents.get(node).cloned().flatten(),
            role: roles
                .get(node)
                .copied()
                .unwrap_or(OrchestrationRole::Worker),
            kind: OrchestrationEventKind::Journal,
            payload: json!({
                "source": relative_source(directory, &path, "logs"),
                "tail": record,
            }),
        });
    }
    Ok(())
}

fn read_state_tsv(
    path: &Path,
    repo_id: &str,
    run_id: &str,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    let Some(contents) = read_text(path)? else {
        return Ok(());
    };
    let mut state = Map::new();
    for line in contents.lines().skip(1) {
        let mut fields = line.splitn(2, '\t');
        let Some(key) = fields.next().filter(|value| !value.is_empty()) else {
            continue;
        };
        let value = fields.next().unwrap_or_default();
        state.insert(key.to_string(), Value::String(value.to_string()));
    }
    if state.is_empty() {
        return Ok(());
    }
    let ts = state
        .get("updated_at")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| file_timestamp(path));
    events.push(NormalizedEvent {
        ts,
        repo: repo_id.to_string(),
        run: run_id.to_string(),
        node: run_id.to_string(),
        parent: None,
        role: OrchestrationRole::Supervisor,
        kind: OrchestrationEventKind::Status,
        payload: json!({"source": "STATE.tsv", "state": state}),
    });
    Ok(())
}

fn read_heartbeat_tsv(
    path: &Path,
    repo_id: &str,
    run_id: &str,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    for row in read_tsv_rows(path)? {
        let node = row
            .get("task_id")
            .filter(|value| !value.is_empty())
            .map(String::as_str)
            .unwrap_or(run_id);
        let ts = row
            .get("timestamp")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| file_timestamp(path));
        events.push(NormalizedEvent {
            ts,
            repo: repo_id.to_string(),
            run: run_id.to_string(),
            node: node.to_string(),
            parent: None,
            role: OrchestrationRole::Supervisor,
            kind: OrchestrationEventKind::Status,
            payload: json!({"source": "HEARTBEAT.tsv", "heartbeat": row}),
        });
    }
    Ok(())
}

fn read_queue_tsv(
    path: &Path,
    repo_id: &str,
    run_id: &str,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    let ts = file_timestamp(path);
    for row in read_tsv_rows(path)? {
        let Some(node) = row.get("task_id").filter(|value| !value.is_empty()) else {
            continue;
        };
        let parent = row
            .get("parent_task_id")
            .filter(|value| !value.is_empty())
            .cloned();
        events.push(NormalizedEvent {
            ts: ts.clone(),
            repo: repo_id.to_string(),
            run: run_id.to_string(),
            node: node.clone(),
            parent,
            role: OrchestrationRole::Supervisor,
            kind: OrchestrationEventKind::Spawn,
            payload: json!({"source": "queue.tsv", "task": row}),
        });
    }
    Ok(())
}

fn read_escalations(
    run_dir: &Path,
    repo_id: &str,
    run_id: &str,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    for path in find_named_files(run_dir, "NEXT_O2_TASKS.tsv", MAX_DISCOVERY_DEPTH)? {
        let Some(contents) = read_text(&path)? else {
            continue;
        };
        let parent = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .filter(|name| *name != run_id)
            .map(str::to_owned);
        let ts = file_timestamp(&path);
        for (index, line) in contents.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let fields = line.split('\t').collect::<Vec<_>>();
            if !(3..=4).contains(&fields.len()) {
                continue;
            }
            let scope_key = fields[0];
            let task_file = fields[1];
            let reason = fields[2];
            let origin = fields.get(3).copied().unwrap_or_default();
            let node = if !scope_key.is_empty() {
                scope_key.to_string()
            } else if let Some(stem) = Path::new(task_file)
                .file_stem()
                .and_then(|name| name.to_str())
            {
                stem.to_string()
            } else {
                format!("escalation-{}", index + 1)
            };
            events.push(NormalizedEvent {
                ts: ts.clone(),
                repo: repo_id.to_string(),
                run: run_id.to_string(),
                node,
                parent: parent.clone(),
                role: OrchestrationRole::Supervisor,
                kind: OrchestrationEventKind::Escalate,
                payload: json!({
                    "source": "NEXT_O2_TASKS.tsv",
                    "scope_key": scope_key,
                    "task_file": task_file,
                    "reason": reason,
                    "origin": origin,
                    "inferred": true,
                }),
            });
        }
    }
    Ok(())
}

fn report_kind(report: &Value) -> OrchestrationEventKind {
    if report.get("accepted").and_then(Value::as_bool) == Some(true) {
        return OrchestrationEventKind::Accept;
    }
    if report.get("rejected").and_then(Value::as_bool) == Some(true)
        || report.get("accepted").and_then(Value::as_bool) == Some(false)
    {
        return OrchestrationEventKind::Reject;
    }
    match report.get("status").and_then(Value::as_str) {
        Some("succeeded" | "completed" | "accepted" | "done") => OrchestrationEventKind::Accept,
        Some("failed" | "rejected" | "blocked") => OrchestrationEventKind::Reject,
        _ => OrchestrationEventKind::Status,
    }
}

fn scope_role(role: Option<&str>) -> OrchestrationRole {
    match role.unwrap_or_default() {
        "supervisor" | "o2" | "top_supervisor" => OrchestrationRole::Supervisor,
        "orchestrator" | "child_orchestrator" | "o1" => OrchestrationRole::Orchestrator,
        "auditor" | "review_auditor" | "review-auditor" => OrchestrationRole::Auditor,
        _ => OrchestrationRole::Worker,
    }
}

fn final_report_exists(family: &str, run_dir: &Path) -> io::Result<bool> {
    let candidates = match family {
        "o2" => vec![run_dir.join("reports").join("supervisor-final.json")],
        "autopilot" | "inbox" => vec![run_dir.join("final-report.json")],
        "consult" => vec![
            run_dir.join("trusted").join("consultant-report.json"),
            run_dir.join("consultant-report.json"),
        ],
        "o2-autopilot" => vec![run_dir.join("SUMMARY.md")],
        _ => Vec::new(),
    };
    for path in candidates {
        if is_regular_file(&path)? {
            return Ok(true);
        }
    }
    if family == "o2-autopilot" {
        return Ok(!find_named_files(run_dir, "final.md", MAX_DISCOVERY_DEPTH)?.is_empty());
    }
    Ok(false)
}

fn read_json(path: &Path) -> io::Result<Option<Value>> {
    let Some(bytes) = read_bounded(path, MAX_ARTIFACT_BYTES)? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

fn read_text(path: &Path) -> io::Result<Option<String>> {
    let Some(bytes) = read_bounded(path, MAX_ARTIFACT_BYTES)? else {
        return Ok(None);
    };
    Ok(String::from_utf8(bytes).ok())
}

fn read_bounded(path: &Path, max_bytes: u64) -> io::Result<Option<Vec<u8>>> {
    if !is_regular_file(path)? {
        return Ok(None);
    }
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn read_last_json_line(path: &Path) -> io::Result<Option<Value>> {
    if !is_regular_file(path)? {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    let start = length.saturating_sub(MAX_LOG_TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(file);
    if start > 0 {
        let mut partial = String::new();
        reader.read_line(&mut partial)?;
    }
    let mut last = None;
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        if let Ok(value) = serde_json::from_str(&line) {
            last = Some(value);
        }
    }
    Ok(last)
}

fn read_tsv_rows(path: &Path) -> io::Result<Vec<BTreeMap<String, String>>> {
    let Some(contents) = read_text(path)? else {
        return Ok(Vec::new());
    };
    let mut lines = contents.lines();
    let Some(header) = lines.next() else {
        return Ok(Vec::new());
    };
    let columns = header.split('\t').collect::<Vec<_>>();
    let mut rows = Vec::new();
    for line in lines.filter(|line| !line.trim().is_empty()) {
        let values = line.split('\t').collect::<Vec<_>>();
        if values.len() != columns.len() {
            continue;
        }
        let row = columns
            .iter()
            .zip(values)
            .map(|(key, value)| ((*key).to_string(), value.to_string()))
            .collect::<BTreeMap<_, _>>();
        rows.push(row);
    }
    Ok(rows)
}

fn read_child_directories(directory: &Path) -> io::Result<Vec<PathBuf>> {
    read_children(directory, |metadata, _| metadata.file_type().is_dir())
}

fn read_child_files(directory: &Path, extension: Option<&str>) -> io::Result<Vec<PathBuf>> {
    read_children(directory, |metadata, path| {
        metadata.file_type().is_file()
            && extension.is_none_or(|expected| {
                path.extension().and_then(|value| value.to_str()) == Some(expected)
            })
    })
}

fn read_children(
    directory: &Path,
    include: impl Fn(&fs::Metadata, &Path) -> bool,
) -> io::Result<Vec<PathBuf>> {
    let metadata = match fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_dir() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if include(&metadata, &path) {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn find_named_files(root: &Path, name: &str, max_depth: usize) -> io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    while let Some((directory, depth)) = pending.pop() {
        for path in read_children(&directory, |_, _| true)? {
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.file_type().is_file()
                && path.file_name().and_then(|value| value.to_str()) == Some(name)
            {
                found.push(path);
            } else if metadata.file_type().is_dir() && depth < max_depth {
                pending.push((path, depth + 1));
            }
        }
    }
    found.sort();
    Ok(found)
}

fn is_regular_file(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn no_follow_metadata(path: &Path) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
}

fn relative_source(directory: &Path, path: &Path, prefix: &str) -> String {
    let relative = path.strip_prefix(directory).unwrap_or(path);
    format!("{prefix}/{}", relative.to_string_lossy())
}

fn sort_and_deduplicate(events: &mut Vec<NormalizedEvent>) {
    events.sort_by(|left, right| {
        left.ts
            .cmp(&right.ts)
            .then_with(|| left.repo.cmp(&right.repo))
            .then_with(|| left.run.cmp(&right.run))
            .then_with(|| left.node.cmp(&right.node))
            .then_with(|| left.parent.cmp(&right.parent))
            .then_with(|| role_rank(left.role).cmp(&role_rank(right.role)))
            .then_with(|| event_kind_rank(left.kind).cmp(&event_kind_rank(right.kind)))
            .then_with(|| left.payload.to_string().cmp(&right.payload.to_string()))
    });
    let mut seen = BTreeSet::new();
    events.retain(|event| {
        let Ok(encoded) = serde_json::to_string(event) else {
            return false;
        };
        seen.insert(encoded)
    });
}

fn role_rank(role: OrchestrationRole) -> u8 {
    match role {
        OrchestrationRole::Supervisor => 0,
        OrchestrationRole::Orchestrator => 1,
        OrchestrationRole::Worker => 2,
        OrchestrationRole::Auditor => 3,
    }
}

fn event_kind_rank(kind: OrchestrationEventKind) -> u8 {
    match kind {
        OrchestrationEventKind::Spawn => 0,
        OrchestrationEventKind::Status => 1,
        OrchestrationEventKind::Journal => 2,
        OrchestrationEventKind::Accept => 3,
        OrchestrationEventKind::Reject => 4,
        OrchestrationEventKind::Escalate => 5,
        OrchestrationEventKind::Gate => 6,
        OrchestrationEventKind::Claim => 7,
    }
}

fn file_timestamp(path: &Path) -> String {
    no_follow_metadata(path)
        .and_then(|metadata| metadata.modified())
        .map(format_rfc3339_utc)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn unix_seconds(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn format_rfc3339_utc(timestamp: SystemTime) -> String {
    let total_seconds = unix_seconds(timestamp);
    let days = i64::try_from(total_seconds / 86_400).unwrap_or(i64::MAX);
    let seconds_in_day = total_seconds % 86_400;
    let (year, month, day) = civil_date_from_unix_days(days);
    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_date_from_unix_days(days: i64) -> (i64, i64, i64) {
    let shifted_days = days.saturating_add(719_468);
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = month_position + if month_position < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(repo: &Path) -> RepositoryTarget {
        RepositoryTarget {
            id: "repo-one".to_string(),
            path: repo.to_path_buf(),
        }
    }

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(path, contents).expect("write fixture");
    }

    #[test]
    fn journal_is_primary_and_deduplicates_valid_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let run = temp.path().join(".maco/o2/runs/run-journal");
        let event = json!({
            "ts": "2026-07-20T00:00:00Z",
            "repo": "journal-repository-hash",
            "run": "journal-run",
            "node": "worker-a",
            "parent": "orchestrator-a",
            "role": "worker",
            "kind": "claim",
            "payload": {"token": 7}
        })
        .to_string();
        write(
            &run.join("events/orchestration.jsonl"),
            &format!("{event}\n{event}\n{{not-json\n"),
        );
        write(
            &run.join("assignments/supervisor-plan.json"),
            r#"{"assignments":[{"id":"must-not-appear","role":"worker"}]}"#,
        );

        let snapshot = scan_repositories(&[target(temp.path())]).expect("scan journal");
        let events = snapshot
            .events_for_run("repo-one", "o2", "run-journal")
            .expect("journal run");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].repo, "repo-one");
        assert_eq!(events[0].run, "run-journal");
        assert_eq!(events[0].kind, OrchestrationEventKind::Claim);
        assert!(!events.iter().any(|event| event.node == "must-not-appear"));
    }

    #[test]
    fn fallback_reconstructs_tree_acceptance_liveness_and_inferred_escalation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let run = temp.path().join(".maco/o2-autopilot/runs/run-fallback");
        write(
            &run.join("assignments/supervisor-plan.json"),
            r#"{
                "assignments":[{
                    "id":"o1-a","role":"child_orchestrator",
                    "worker_assignments":[{"id":"worker-a","role":"worker"}]
                }]
            }"#,
        );
        write(
            &run.join("reports/worker-a.json"),
            r#"{
                "id":"worker-a","role":"worker","status":"succeeded",
                "accepted":true,"claim_token":42,
                "assigned_paths":["src/a.rs"],
                "validation_results":[{"name":"unit","passed":true}]
            }"#,
        );
        write(
            &run.join("logs/worker-a.jsonl"),
            "not json\n{\"type\":\"turn.started\"}\n",
        );
        write(
            &run.join("STATE.tsv"),
            "key\tvalue\nupdated_at\t2026-07-20T01:00:00Z\ncurrent_phase\trunning\n",
        );
        write(
            &run.join("HEARTBEAT.tsv"),
            "timestamp\tphase\ttask_id\tstatus\tnote\n2026-07-20T01:01:00Z\ttask_running\to2-0001\trunning\t\n",
        );
        write(
            &run.join("queue.tsv"),
            "task_id\tdepth\tscope_key\ttask_file\treason\tstatus\tnote\tparent_task_id\torigin\no2-0001\t0\troot\ttask.md\tinitial\trunning\t\t\t\n",
        );
        write(
            &run.join("tasks/o2-0001/NEXT_O2_TASKS.tsv"),
            "peer-scope\tpeer.md\tcross-cutting follow-up\tfinding-node\n",
        );

        let snapshot = scan_repositories(&[target(temp.path())]).expect("scan fallbacks");
        let events = snapshot
            .events_for_run("repo-one", "o2-autopilot", "run-fallback")
            .expect("fallback run");
        assert!(events.iter().any(|event| {
            event.node == "worker-a"
                && event.parent.as_deref() == Some("o1-a")
                && event.kind == OrchestrationEventKind::Spawn
        }));
        assert!(events.iter().any(|event| {
            event.node == "worker-a" && event.kind == OrchestrationEventKind::Accept
        }));
        assert!(events
            .iter()
            .any(|event| event.kind == OrchestrationEventKind::Claim));
        assert!(events
            .iter()
            .any(|event| event.kind == OrchestrationEventKind::Gate));
        assert!(events
            .iter()
            .any(|event| event.kind == OrchestrationEventKind::Journal));
        let escalation = events
            .iter()
            .find(|event| event.kind == OrchestrationEventKind::Escalate)
            .expect("escalation event");
        assert_eq!(escalation.node, "peer-scope");
        assert_eq!(escalation.parent.as_deref(), Some("o2-0001"));
        assert_eq!(escalation.payload["origin"], "finding-node");
        assert_eq!(escalation.payload["inferred"], true);
    }

    #[test]
    fn summaries_cover_all_families_and_detect_final_reports() {
        let temp = tempfile::tempdir().expect("tempdir");
        write(
            &temp
                .path()
                .join(".maco/o2/runs/o2-run/reports/supervisor-final.json"),
            "{}",
        );
        write(
            &temp
                .path()
                .join(".maco/autopilot/runs/autopilot-run/final-report.json"),
            "{}",
        );
        write(
            &temp
                .path()
                .join(".maco/inbox/runs/inbox-run/final-report.json"),
            "{}",
        );
        write(
            &temp
                .path()
                .join(".maco/consult/runs/consult-run/trusted/consultant-report.json"),
            "{}",
        );
        write(
            &temp
                .path()
                .join(".maco/o2-autopilot/runs/o2-auto-run/SUMMARY.md"),
            "complete",
        );
        fs::create_dir_all(temp.path().join(".maco/o2/runs/unfinalized")).expect("unfinalized run");

        let snapshot = scan_repositories(&[target(temp.path())]).expect("scan summaries");
        let runs = &snapshot.projects[0].runs;
        for (family, run_id) in [
            ("o2", "o2-run"),
            ("autopilot", "autopilot-run"),
            ("inbox", "inbox-run"),
            ("consult", "consult-run"),
            ("o2-autopilot", "o2-auto-run"),
        ] {
            assert!(runs.iter().any(|run| {
                run.family == family && run.run == run_id && run.final_report_exists
            }));
        }
        assert!(runs.iter().any(|run| {
            run.family == "o2" && run.run == "unfinalized" && !run.final_report_exists
        }));
        assert_eq!(snapshot.all_events().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn scanning_skips_symlinked_artifacts() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let outside = temp.path().join("outside.jsonl");
        write(
            &outside,
            r#"{"ts":"2026-07-20T00:00:00Z","repo":"x","run":"x","node":"x","parent":null,"role":"worker","kind":"status","payload":{}}"#,
        );
        let events_dir = temp.path().join(".maco/o2/runs/symlinked/events");
        fs::create_dir_all(&events_dir).expect("events dir");
        symlink(&outside, events_dir.join("orchestration.jsonl")).expect("journal symlink");

        let snapshot = scan_repositories(&[target(temp.path())]).expect("scan symlink");
        assert!(snapshot
            .events_for_run("repo-one", "o2", "symlinked")
            .expect("symlinked run")
            .is_empty());
    }
}
