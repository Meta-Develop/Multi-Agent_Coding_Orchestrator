use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

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
const MAX_REPOSITORIES: usize = 64;
const MAX_RUNS_PER_REPOSITORY: usize = 4_096;
const MAX_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_DISCOVERY_ENTRIES: usize = 16_384;
const MAX_NAMED_FILES: usize = 4_096;
const MAX_EVENTS_PER_RUN: usize = 16_384;
const MAX_ASSIGNMENTS_PER_RUN: usize = 4_096;
const MAX_ASSIGNMENT_DEPTH: usize = 16;
const MAX_EMBEDDED_REPORTS: usize = 4_096;
const MAX_REPORT_DEPTH: usize = 16;
const MAX_JOURNAL_RECORDS: usize = 32_768;
const MAX_JOURNAL_LINE_BYTES: usize = 1024 * 1024;

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

    pub fn all_events(&self) -> Vec<FamilyEvent> {
        let mut events = self
            .projects
            .iter()
            .flat_map(|project| project.runs.iter())
            .flat_map(|run| {
                run.events.iter().cloned().map(|event| FamilyEvent {
                    family: run.family.clone(),
                    event,
                })
            })
            .collect::<Vec<_>>();
        sort_and_deduplicate_family_events(&mut events);
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
    #[serde(skip)]
    journal: Option<JournalPosition>,
}

pub type NormalizedEvent = OrchestrationEvent;

#[derive(Clone, Debug, PartialEq)]
pub struct FamilyEvent {
    pub family: String,
    pub event: NormalizedEvent,
}

#[derive(Clone, Debug)]
pub struct CachedScope {
    repositories: Vec<RepositoryTarget>,
    snapshot: Option<ScopeSnapshot>,
    run_roots: Vec<RunRootWatch>,
    journals: BTreeMap<RunKey, JournalWatch>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RunKey {
    repo: String,
    family: String,
    run: String,
}

#[derive(Clone, Debug)]
struct RunRootWatch {
    repo: String,
    repository_root: PathBuf,
    family_directory: &'static str,
    path: PathBuf,
    fingerprint: Option<FileFingerprint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JournalPosition {
    path: PathBuf,
    offset: u64,
    record_count: usize,
    fingerprint: FileFingerprint,
}

#[derive(Clone, Debug)]
struct JournalWatch {
    repository_root: PathBuf,
    family_directory: &'static str,
    position: JournalPosition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileFingerprint {
    length: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl CachedScope {
    pub fn new(repositories: Vec<RepositoryTarget>) -> Self {
        Self {
            repositories,
            snapshot: None,
            run_roots: Vec::new(),
            journals: BTreeMap::new(),
        }
    }

    pub fn refresh(&mut self) -> io::Result<bool> {
        if self.snapshot.is_none() {
            self.rebuild_all()?;
            return Ok(true);
        }

        let mut rebuild_repositories = BTreeSet::new();
        for watch in &self.run_roots {
            let fingerprint = watch.current_fingerprint()?;
            if fingerprint != watch.fingerprint {
                rebuild_repositories.insert(watch.repo.clone());
            }
        }

        for (key, watch) in &self.journals {
            if rebuild_repositories.contains(&key.repo) {
                continue;
            }
            match watch.fingerprint(key)? {
                Some(fingerprint)
                    if same_file_identity(&fingerprint, &watch.position.fingerprint)
                        && fingerprint.length >= watch.position.offset =>
                {
                    if fingerprint.length == watch.position.offset
                        && fingerprint != watch.position.fingerprint
                    {
                        rebuild_repositories.insert(key.repo.clone());
                    }
                }
                _ => {
                    rebuild_repositories.insert(key.repo.clone());
                }
            }
        }

        let mut changed = !rebuild_repositories.is_empty();
        for repo_id in &rebuild_repositories {
            self.rebuild_repository(repo_id)?;
        }

        let keys = self.journals.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            if rebuild_repositories.contains(&key.repo) {
                continue;
            }
            let Some(watch) = self.journals.get(&key).cloned() else {
                continue;
            };
            let Some(fingerprint) = watch.fingerprint(&key)? else {
                self.rebuild_repository(&key.repo)?;
                changed = true;
                continue;
            };
            if fingerprint.length <= watch.position.offset {
                continue;
            }
            let path = watch.validated_path(&key)?.ok_or_else(|| {
                invalid_data(format!(
                    "Scope journal disappeared for '{}/{}/{}'",
                    key.repo, key.family, key.run
                ))
            })?;
            let (events, position) =
                read_journal_suffix(&path, &key.repo, &key.run, &watch.position)?;
            self.append_run_events(&key, events)?;
            if let Some(current) = self.journals.get_mut(&key) {
                current.position = position;
            }
            changed = true;
        }

        self.refresh_run_root_fingerprints()?;
        Ok(changed)
    }

    pub fn snapshot(&self) -> io::Result<&ScopeSnapshot> {
        self.snapshot
            .as_ref()
            .ok_or_else(|| invalid_data("Scope cache has not been initialized"))
    }

    fn rebuild_all(&mut self) -> io::Result<()> {
        let snapshot = scan_repositories(&self.repositories)?;
        self.snapshot = Some(snapshot);
        self.rebuild_journal_watches();
        self.run_roots = run_root_watches(&self.repositories)?;
        Ok(())
    }

    fn rebuild_repository(&mut self, repo_id: &str) -> io::Result<()> {
        let Some(target) = self
            .repositories
            .iter()
            .find(|target| target.id == repo_id)
            .cloned()
        else {
            return Err(invalid_data(format!(
                "Scope cache lost repository target '{repo_id}'"
            )));
        };
        let project = scan_repository(&target)?;
        let snapshot = self
            .snapshot
            .as_mut()
            .ok_or_else(|| invalid_data("Scope cache has not been initialized"))?;
        if let Some(existing) = snapshot
            .projects
            .iter_mut()
            .find(|existing| existing.id == repo_id)
        {
            *existing = project;
        } else {
            snapshot.projects.push(project);
            snapshot.projects.sort_by(|left, right| {
                left.id
                    .cmp(&right.id)
                    .then_with(|| left.path.cmp(&right.path))
            });
        }
        self.journals.retain(|key, _| key.repo != repo_id);
        self.extend_journal_watches_for(repo_id);
        Ok(())
    }

    fn append_run_events(&mut self, key: &RunKey, events: Vec<NormalizedEvent>) -> io::Result<()> {
        let snapshot = self
            .snapshot
            .as_mut()
            .ok_or_else(|| invalid_data("Scope cache has not been initialized"))?;
        let Some(run) = snapshot
            .projects
            .iter_mut()
            .find(|project| project.id == key.repo)
            .and_then(|project| {
                project
                    .runs
                    .iter_mut()
                    .find(|run| run.family == key.family && run.run == key.run)
            })
        else {
            return Err(invalid_data(format!(
                "Scope cache lost run '{}/{}/{}'",
                key.repo, key.family, key.run
            )));
        };

        for event in events {
            match run
                .events
                .binary_search_by(|existing| compare_events(existing, &event))
            {
                Ok(_) => {}
                Err(index) => run.events.insert(index, event),
            }
        }
        ensure_event_limit(&run.events)?;
        run.event_count = run.events.len();
        run.final_report_exists = final_report_exists(&run.family, &run.run_dir)?;
        Ok(())
    }

    fn rebuild_journal_watches(&mut self) {
        self.journals.clear();
        let repo_ids = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .projects
                    .iter()
                    .map(|project| project.id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for repo_id in repo_ids {
            self.extend_journal_watches_for(&repo_id);
        }
    }

    fn extend_journal_watches_for(&mut self, repo_id: &str) {
        let Some(snapshot) = self.snapshot.as_ref() else {
            return;
        };
        let Some(project) = snapshot
            .projects
            .iter()
            .find(|project| project.id == repo_id)
        else {
            return;
        };
        let Some(target) = self.repositories.iter().find(|target| target.id == repo_id) else {
            return;
        };
        for run in &project.runs {
            let Some(position) = run.journal.clone() else {
                continue;
            };
            let Some((_, family_directory)) = RUN_FAMILIES
                .iter()
                .find(|(family, _)| *family == run.family)
            else {
                continue;
            };
            self.journals.insert(
                RunKey {
                    repo: repo_id.to_string(),
                    family: run.family.clone(),
                    run: run.run.clone(),
                },
                JournalWatch {
                    repository_root: target.path.clone(),
                    family_directory: *family_directory,
                    position,
                },
            );
        }
    }

    fn refresh_run_root_fingerprints(&mut self) -> io::Result<()> {
        for watch in &mut self.run_roots {
            watch.fingerprint = watch.current_fingerprint()?;
        }
        Ok(())
    }
}

impl RunRootWatch {
    fn current_fingerprint(&self) -> io::Result<Option<FileFingerprint>> {
        let components = [".maco", self.family_directory, "runs"];
        let Some(path) = validate_directory_chain(&self.repository_root, &components)? else {
            return Ok(None);
        };
        if path != self.path {
            return Err(invalid_data(format!(
                "Scope run root path changed for repository '{}'",
                self.repo
            )));
        }
        directory_fingerprint(&path)
    }
}

impl JournalWatch {
    fn validated_path(&self, key: &RunKey) -> io::Result<Option<PathBuf>> {
        let components = [
            ".maco",
            self.family_directory,
            "runs",
            key.run.as_str(),
            "events",
        ];
        let Some(events_directory) = validate_directory_chain(&self.repository_root, &components)?
        else {
            return Ok(None);
        };
        let path = events_directory.join("orchestration.jsonl");
        if path != self.position.path {
            return Err(invalid_data(format!(
                "Scope journal path changed for '{}/{}/{}'",
                key.repo, key.family, key.run
            )));
        }
        Ok(Some(path))
    }

    fn fingerprint(&self, key: &RunKey) -> io::Result<Option<FileFingerprint>> {
        let Some(path) = self.validated_path(key)? else {
            return Ok(None);
        };
        journal_fingerprint(&path)
    }
}

fn run_root_watches(repositories: &[RepositoryTarget]) -> io::Result<Vec<RunRootWatch>> {
    let mut watches = Vec::with_capacity(repositories.len().saturating_mul(RUN_FAMILIES.len()));
    for target in repositories {
        for (_, family_directory) in RUN_FAMILIES {
            let path = target
                .path
                .join(".maco")
                .join(family_directory)
                .join("runs");
            let components = [".maco", family_directory, "runs"];
            let fingerprint = match validate_directory_chain(&target.path, &components)? {
                Some(validated) => {
                    if validated != path {
                        return Err(invalid_data(format!(
                            "Scope run root path changed for repository '{}'",
                            target.id
                        )));
                    }
                    directory_fingerprint(&validated)?
                }
                None => None,
            };
            watches.push(RunRootWatch {
                repo: target.id.clone(),
                repository_root: target.path.clone(),
                family_directory,
                path,
                fingerprint,
            });
        }
    }
    Ok(watches)
}

fn directory_fingerprint(path: &Path) -> io::Result<Option<FileFingerprint>> {
    let metadata = match no_follow_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(invalid_data(format!(
            "Scope refuses symlinked directory {}",
            path.display()
        )));
    }
    if !metadata.file_type().is_dir() {
        return Err(invalid_data(format!(
            "Scope expected a directory at {}",
            path.display()
        )));
    }
    Ok(Some(fingerprint(&metadata)))
}

fn journal_fingerprint(path: &Path) -> io::Result<Option<FileFingerprint>> {
    let Some(file) = open_regular_file(path)? else {
        return Ok(None);
    };
    Ok(Some(fingerprint(&file.metadata()?)))
}

fn fingerprint(metadata: &fs::Metadata) -> FileFingerprint {
    FileFingerprint {
        length: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    }
}

fn same_file_identity(left: &FileFingerprint, right: &FileFingerprint) -> bool {
    #[cfg(unix)]
    {
        left.device == right.device && left.inode == right.inode
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        true
    }
}

pub fn scan_repositories(repositories: &[RepositoryTarget]) -> io::Result<ScopeSnapshot> {
    if repositories.len() > MAX_REPOSITORIES {
        return Err(invalid_data(format!(
            "Scope repository scan exceeds the {MAX_REPOSITORIES} repository limit"
        )));
    }
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
    let repository_root = fs::canonicalize(&target.path)?;
    if repository_root != target.path {
        return Err(invalid_data(format!(
            "Scope repository path must be canonical: {}",
            target.path.display()
        )));
    }
    let mut discovered = Vec::new();
    for (family, directory) in RUN_FAMILIES {
        let Some(run_root) =
            validate_directory_chain(&repository_root, &[".maco", directory, "runs"])?
        else {
            continue;
        };
        for run_dir in read_child_directories(&run_root)? {
            if discovered.len() >= MAX_RUNS_PER_REPOSITORY {
                return Err(invalid_data(format!(
                    "Scope run discovery exceeds the {MAX_RUNS_PER_REPOSITORY} run limit in {}",
                    repository_root.display()
                )));
            }
            let canonical_run = fs::canonicalize(&run_dir)?;
            if canonical_run != run_dir || !canonical_run.starts_with(&repository_root) {
                return Err(invalid_data(format!(
                    "Scope run directory escapes its canonical repository root: {}",
                    run_dir.display()
                )));
            }
            let Some(run_name) = run_dir.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if run_name.is_empty() {
                continue;
            }
            let modified = no_follow_metadata(&run_dir)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(UNIX_EPOCH);
            let (mut events, journal) = scan_run_events(target, family, run_name, &run_dir)?;
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
                    journal,
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
    family: &str,
    run_id: &str,
    run_dir: &Path,
) -> io::Result<(Vec<NormalizedEvent>, Option<JournalPosition>)> {
    if let Some(events_dir) = validate_directory_chain(run_dir, &["events"])? {
        let journal = events_dir.join("orchestration.jsonl");
        if is_regular_file(&journal)? {
            let journal = read_journal_with_position(&journal, &target.id, run_id)?;
            return Ok((journal.events, Some(journal.position)));
        }
    }

    let mut events = Vec::new();
    let mut parents = BTreeMap::new();
    let mut roles = BTreeMap::new();
    parents.insert(run_id.to_string(), None);
    roles.insert(run_id.to_string(), OrchestrationRole::Supervisor);
    push_event(
        &mut events,
        NormalizedEvent {
            ts: file_timestamp(run_dir),
            repo: target.id.clone(),
            run: run_id.to_string(),
            node: run_id.to_string(),
            parent: None,
            role: OrchestrationRole::Supervisor,
            kind: OrchestrationEventKind::Spawn,
            payload: json!({"source": "fallback", "family": family, "synthetic": true}),
        },
    )?;
    if let Some(assignments_dir) = validate_directory_chain(run_dir, &["assignments"])? {
        read_supervisor_plan(
            &assignments_dir.join("supervisor-plan.json"),
            &target.id,
            run_id,
            Some(run_id),
            &mut events,
            &mut parents,
            &mut roles,
        )?;
    }
    if let Some(reports_dir) = validate_directory_chain(run_dir, &["reports"])? {
        read_reports(
            &reports_dir,
            &target.id,
            run_id,
            &mut parents,
            &mut roles,
            &mut events,
        )?;
    }
    read_family_reports(
        run_dir,
        family,
        &target.id,
        run_id,
        &mut parents,
        &mut roles,
        &mut events,
    )?;
    if let Some(logs_dir) = validate_directory_chain(run_dir, &["logs"])? {
        read_log_tails(&logs_dir, &target.id, run_id, &parents, &roles, &mut events)?;
    }
    read_state_tsv(&run_dir.join("STATE.tsv"), &target.id, run_id, &mut events)?;
    read_heartbeat_tsv(
        &run_dir.join("HEARTBEAT.tsv"),
        &target.id,
        run_id,
        &mut events,
    )?;
    read_queue_tsv(&run_dir.join("queue.tsv"), &target.id, run_id, &mut events)?;
    read_escalations(run_dir, &target.id, run_id, &mut events)?;
    ensure_event_limit(&events)?;
    Ok((events, None))
}

#[cfg(test)]
fn read_journal(path: &Path, repo_id: &str, run_id: &str) -> io::Result<Vec<NormalizedEvent>> {
    Ok(read_journal_with_position(path, repo_id, run_id)?.events)
}

struct JournalRead {
    events: Vec<NormalizedEvent>,
    position: JournalPosition,
}

fn read_journal_with_position(path: &Path, repo_id: &str, run_id: &str) -> io::Result<JournalRead> {
    let Some(file) = open_regular_file(path)? else {
        return Err(invalid_data(format!(
            "Scope journal disappeared while reading {}",
            path.display()
        )));
    };
    let metadata = file.metadata()?;
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(invalid_data(format!(
            "Scope orchestration journal exceeds the {MAX_JOURNAL_BYTES} byte limit: {}",
            path.display()
        )));
    }
    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut line = Vec::new();
    let mut total_bytes = 0_u64;
    let mut record_count = 0_usize;
    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            break;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(bytes_read).unwrap_or(u64::MAX));
        if total_bytes > MAX_JOURNAL_BYTES {
            return Err(invalid_data(format!(
                "Scope orchestration journal grew beyond the {MAX_JOURNAL_BYTES} byte limit: {}",
                path.display()
            )));
        }
        if line.len() > MAX_JOURNAL_LINE_BYTES {
            return Err(invalid_data(format!(
                "Scope orchestration journal line exceeds the {MAX_JOURNAL_LINE_BYTES} byte limit: {}",
                path.display()
            )));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        record_count += 1;
        if record_count > MAX_JOURNAL_RECORDS {
            return Err(invalid_data(format!(
                "Scope orchestration journal exceeds the {MAX_JOURNAL_RECORDS} record limit: {}",
                path.display()
            )));
        }
        let Ok(mut event) = serde_json::from_slice::<NormalizedEvent>(&line) else {
            continue;
        };
        if event.ts.is_empty() || event.node.is_empty() {
            continue;
        }
        event.repo = repo_id.to_string();
        event.run = run_id.to_string();
        push_event(&mut events, event)?;
    }
    sort_and_deduplicate(&mut events);
    let metadata = reader.into_inner().metadata()?;
    Ok(JournalRead {
        events,
        position: JournalPosition {
            path: path.to_path_buf(),
            offset: total_bytes,
            record_count,
            fingerprint: fingerprint(&metadata),
        },
    })
}

fn read_journal_suffix(
    path: &Path,
    repo_id: &str,
    run_id: &str,
    previous: &JournalPosition,
) -> io::Result<(Vec<NormalizedEvent>, JournalPosition)> {
    let Some(mut file) = open_regular_file(path)? else {
        return Err(invalid_data(format!(
            "Scope journal disappeared while reading {}",
            path.display()
        )));
    };
    let metadata = file.metadata()?;
    let current_fingerprint = fingerprint(&metadata);
    if !same_file_identity(&current_fingerprint, &previous.fingerprint)
        || metadata.len() < previous.offset
    {
        return Err(invalid_data(format!(
            "Scope journal changed identity or was truncated while reading {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_JOURNAL_BYTES {
        return Err(invalid_data(format!(
            "Scope orchestration journal exceeds the {MAX_JOURNAL_BYTES} byte limit: {}",
            path.display()
        )));
    }

    file.seek(SeekFrom::Start(previous.offset))?;
    let available = metadata.len().saturating_sub(previous.offset);
    let mut reader = BufReader::new(file.take(available));
    let mut events = Vec::new();
    let mut line = Vec::new();
    let mut consumed = 0_u64;
    let mut record_count = previous.record_count;
    loop {
        line.clear();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            break;
        }
        consumed = consumed.saturating_add(u64::try_from(bytes_read).unwrap_or(u64::MAX));
        if line.len() > MAX_JOURNAL_LINE_BYTES {
            return Err(invalid_data(format!(
                "Scope orchestration journal line exceeds the {MAX_JOURNAL_LINE_BYTES} byte limit: {}",
                path.display()
            )));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        record_count += 1;
        if record_count > MAX_JOURNAL_RECORDS {
            return Err(invalid_data(format!(
                "Scope orchestration journal exceeds the {MAX_JOURNAL_RECORDS} record limit: {}",
                path.display()
            )));
        }
        let Ok(mut event) = serde_json::from_slice::<NormalizedEvent>(&line) else {
            continue;
        };
        if event.ts.is_empty() || event.node.is_empty() {
            continue;
        }
        event.repo = repo_id.to_string();
        event.run = run_id.to_string();
        push_event(&mut events, event)?;
    }

    let offset = previous.offset.saturating_add(consumed);
    if offset > MAX_JOURNAL_BYTES {
        return Err(invalid_data(format!(
            "Scope orchestration journal grew beyond the {MAX_JOURNAL_BYTES} byte limit: {}",
            path.display()
        )));
    }
    Ok((
        events,
        JournalPosition {
            path: path.to_path_buf(),
            offset,
            record_count,
            fingerprint: current_fingerprint,
        },
    ))
}

fn read_supervisor_plan(
    path: &Path,
    repo_id: &str,
    run_id: &str,
    root_parent: Option<&str>,
    events: &mut Vec<NormalizedEvent>,
    parents: &mut BTreeMap<String, Option<String>>,
    roles: &mut BTreeMap<String, OrchestrationRole>,
) -> io::Result<()> {
    let Some(value) = read_json(path)? else {
        return Ok(());
    };
    let ts = file_timestamp(path);
    let mut assignment_count = 0_usize;
    if let Some(assignments) = value.get("assignments").and_then(Value::as_array) {
        for assignment in assignments {
            collect_assignment(
                assignment,
                root_parent,
                OrchestrationRole::Orchestrator,
                0,
                &mut assignment_count,
                repo_id,
                run_id,
                &ts,
                events,
                parents,
                roles,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_assignment(
    assignment: &Value,
    parent: Option<&str>,
    default_role: OrchestrationRole,
    depth: usize,
    assignment_count: &mut usize,
    repo_id: &str,
    run_id: &str,
    ts: &str,
    events: &mut Vec<NormalizedEvent>,
    parents: &mut BTreeMap<String, Option<String>>,
    roles: &mut BTreeMap<String, OrchestrationRole>,
) -> io::Result<()> {
    if depth > MAX_ASSIGNMENT_DEPTH {
        return Err(invalid_data(format!(
            "Scope supervisor plan exceeds the {MAX_ASSIGNMENT_DEPTH} assignment depth limit"
        )));
    }
    *assignment_count += 1;
    if *assignment_count > MAX_ASSIGNMENTS_PER_RUN {
        return Err(invalid_data(format!(
            "Scope supervisor plan exceeds the {MAX_ASSIGNMENTS_PER_RUN} assignment limit"
        )));
    }
    let Some(node) = assignment.get("id").and_then(Value::as_str) else {
        return Ok(());
    };
    if node.is_empty() {
        return Ok(());
    }
    let role = assignment
        .get("role")
        .and_then(Value::as_str)
        .map(|value| scope_role(Some(value)))
        .unwrap_or(default_role);
    let parent = parent.map(str::to_owned);
    parents.insert(node.to_string(), parent.clone());
    roles.insert(node.to_string(), role);
    push_event(
        events,
        NormalizedEvent {
            ts: ts.to_string(),
            repo: repo_id.to_string(),
            run: run_id.to_string(),
            node: node.to_string(),
            parent: parent.clone(),
            role,
            kind: OrchestrationEventKind::Spawn,
            payload: json!({"source": "assignments/supervisor-plan.json", "assignment": assignment}),
        },
    )?;

    for (child_key, child_role) in [
        ("assignments", OrchestrationRole::Orchestrator),
        ("worker_assignments", OrchestrationRole::Worker),
    ] {
        if let Some(children) = assignment.get(child_key).and_then(Value::as_array) {
            for child in children {
                collect_assignment(
                    child,
                    Some(node),
                    child_role,
                    depth + 1,
                    assignment_count,
                    repo_id,
                    run_id,
                    ts,
                    events,
                    parents,
                    roles,
                )?;
            }
        }
    }
    Ok(())
}

fn read_reports(
    directory: &Path,
    repo_id: &str,
    run_id: &str,
    parents: &mut BTreeMap<String, Option<String>>,
    roles: &mut BTreeMap<String, OrchestrationRole>,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    let mut report_count = 0_usize;
    for path in read_child_files(directory, Some("json"))? {
        let Some(report) = read_json(&path)? else {
            continue;
        };
        let fallback_node = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or(run_id);
        let source = relative_source(directory, &path, "reports");
        let ts = file_timestamp(&path);
        collect_report(
            &report,
            fallback_node,
            None,
            None,
            0,
            &mut report_count,
            &source,
            &ts,
            repo_id,
            run_id,
            parents,
            roles,
            events,
        )?;
    }
    Ok(())
}

fn read_family_reports(
    run_dir: &Path,
    family: &str,
    repo_id: &str,
    run_id: &str,
    parents: &mut BTreeMap<String, Option<String>>,
    roles: &mut BTreeMap<String, OrchestrationRole>,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    let mut report_count = 0_usize;
    match family {
        "autopilot" => {
            normalize_known_report(
                &run_dir.join("final-report.json"),
                run_id,
                None,
                Some(OrchestrationRole::Supervisor),
                "final-report.json",
                &mut report_count,
                repo_id,
                run_id,
                parents,
                roles,
                events,
            )?;
            let parent = Some(run_id);
            for (name, suffix, role) in [
                (
                    "supervisor-report.json",
                    "supervisor",
                    OrchestrationRole::Supervisor,
                ),
                ("review-report.json", "review", OrchestrationRole::Auditor),
                (
                    "pr-report.json",
                    "publication",
                    OrchestrationRole::Orchestrator,
                ),
            ] {
                normalize_known_report(
                    &run_dir.join(name),
                    &format!("{run_id}-{suffix}"),
                    parent,
                    Some(role),
                    name,
                    &mut report_count,
                    repo_id,
                    run_id,
                    parents,
                    roles,
                    events,
                )?;
            }
        }
        "inbox" => {
            normalize_known_report(
                &run_dir.join("final-report.json"),
                run_id,
                None,
                Some(OrchestrationRole::Supervisor),
                "final-report.json",
                &mut report_count,
                repo_id,
                run_id,
                parents,
                roles,
                events,
            )?;
            let parent = Some(run_id);
            normalize_known_report(
                &run_dir.join("scan-report.json"),
                &format!("{run_id}-scan"),
                parent,
                Some(OrchestrationRole::Supervisor),
                "scan-report.json",
                &mut report_count,
                repo_id,
                run_id,
                parents,
                roles,
                events,
            )?;
            for path in read_child_files(run_dir, Some("json"))? {
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                let Some(role) = inbox_item_report_role(name) else {
                    continue;
                };
                let fallback = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or(run_id);
                normalize_known_report(
                    &path,
                    fallback,
                    parent,
                    Some(role),
                    name,
                    &mut report_count,
                    repo_id,
                    run_id,
                    parents,
                    roles,
                    events,
                )?;
            }
        }
        "consult" => {
            let trusted = validate_directory_chain(run_dir, &["trusted"])?
                .map(|directory| directory.join("consultant-report.json"));
            let trusted_found = if let Some(path) = trusted {
                normalize_known_report(
                    &path,
                    run_id,
                    None,
                    Some(OrchestrationRole::Auditor),
                    "trusted/consultant-report.json",
                    &mut report_count,
                    repo_id,
                    run_id,
                    parents,
                    roles,
                    events,
                )?
            } else {
                false
            };
            if !trusted_found {
                normalize_known_report(
                    &run_dir.join("consultant-report.json"),
                    run_id,
                    None,
                    Some(OrchestrationRole::Auditor),
                    "consultant-report.json",
                    &mut report_count,
                    repo_id,
                    run_id,
                    parents,
                    roles,
                    events,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn normalize_known_report(
    path: &Path,
    fallback_node: &str,
    parent_hint: Option<&str>,
    role_hint: Option<OrchestrationRole>,
    source: &str,
    report_count: &mut usize,
    repo_id: &str,
    run_id: &str,
    parents: &mut BTreeMap<String, Option<String>>,
    roles: &mut BTreeMap<String, OrchestrationRole>,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<bool> {
    let Some(report) = read_json(path)? else {
        return Ok(false);
    };
    collect_report(
        &report,
        fallback_node,
        parent_hint,
        role_hint,
        0,
        report_count,
        source,
        &file_timestamp(path),
        repo_id,
        run_id,
        parents,
        roles,
        events,
    )?;
    Ok(true)
}

fn inbox_item_report_role(name: &str) -> Option<OrchestrationRole> {
    for (suffix, role) in [
        ("-autopilot-report.json", OrchestrationRole::Orchestrator),
        ("-github-report.json", OrchestrationRole::Worker),
    ] {
        if let Some(index) = name
            .strip_prefix("item-")
            .and_then(|value| value.strip_suffix(suffix))
        {
            if !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit()) {
                return Some(role);
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn collect_report(
    report: &Value,
    fallback_node: &str,
    parent_hint: Option<&str>,
    role_hint: Option<OrchestrationRole>,
    depth: usize,
    report_count: &mut usize,
    source: &str,
    ts: &str,
    repo_id: &str,
    run_id: &str,
    parents: &mut BTreeMap<String, Option<String>>,
    roles: &mut BTreeMap<String, OrchestrationRole>,
    events: &mut Vec<NormalizedEvent>,
) -> io::Result<()> {
    if depth > MAX_REPORT_DEPTH {
        return Err(invalid_data(format!(
            "Scope embedded reports exceed the {MAX_REPORT_DEPTH} depth limit"
        )));
    }
    *report_count += 1;
    if *report_count > MAX_EMBEDDED_REPORTS {
        return Err(invalid_data(format!(
            "Scope reports exceed the {MAX_EMBEDDED_REPORTS} report limit"
        )));
    }
    let node = report
        .get("id")
        .and_then(Value::as_str)
        .or_else(|| report.get("run_id").and_then(Value::as_str))
        .unwrap_or(fallback_node);
    if node.is_empty() {
        return Ok(());
    }
    let role = report
        .get("role")
        .and_then(Value::as_str)
        .map(|value| scope_role(Some(value)))
        .or(role_hint)
        .or_else(|| roles.get(node).copied())
        .unwrap_or_else(|| infer_report_role(node, fallback_node, run_id));
    let parent = parent_hint
        .map(str::to_owned)
        .or_else(|| parents.get(node).cloned().flatten())
        .or_else(|| infer_auditor_parent(node, role));
    parents.insert(node.to_string(), parent.clone());
    roles.insert(node.to_string(), role);
    push_event(
        events,
        NormalizedEvent {
            ts: ts.to_string(),
            repo: repo_id.to_string(),
            run: run_id.to_string(),
            node: node.to_string(),
            parent: parent.clone(),
            role,
            kind: report_kind(report),
            payload: json!({"source": source, "report": report}),
        },
    )?;

    if let Some(token) = report.get("claim_token").filter(|token| !token.is_null()) {
        push_claim_event(
            events, report, token, source, ts, repo_id, run_id, node, &parent, role,
        )?;
    }
    if let Some(tokens) = report.get("claim_tokens").and_then(Value::as_array) {
        for token in tokens.iter().filter(|token| !token.is_null()) {
            push_claim_event(
                events, report, token, source, ts, repo_id, run_id, node, &parent, role,
            )?;
        }
    }
    if let Some(validations) = report.get("validation_results").and_then(Value::as_array) {
        for validation in validations {
            push_event(
                events,
                NormalizedEvent {
                    ts: ts.to_string(),
                    repo: repo_id.to_string(),
                    run: run_id.to_string(),
                    node: node.to_string(),
                    parent: parent.clone(),
                    role,
                    kind: OrchestrationEventKind::Gate,
                    payload: json!({"source": source, "validation": validation}),
                },
            )?;
        }
    }

    for (key, child_role) in [
        ("orchestrator_reports", OrchestrationRole::Orchestrator),
        ("worker_reports", OrchestrationRole::Worker),
        ("audit_reports", OrchestrationRole::Auditor),
    ] {
        if let Some(children) = report.get(key).and_then(Value::as_array) {
            for (index, child) in children.iter().enumerate() {
                let child_fallback = format!("{node}-{key}-{}", index + 1);
                collect_report(
                    child,
                    &child_fallback,
                    Some(node),
                    Some(child_role),
                    depth + 1,
                    report_count,
                    source,
                    ts,
                    repo_id,
                    run_id,
                    parents,
                    roles,
                    events,
                )?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_claim_event(
    events: &mut Vec<NormalizedEvent>,
    report: &Value,
    token: &Value,
    source: &str,
    ts: &str,
    repo_id: &str,
    run_id: &str,
    node: &str,
    parent: &Option<String>,
    role: OrchestrationRole,
) -> io::Result<()> {
    push_event(
        events,
        NormalizedEvent {
            ts: ts.to_string(),
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
        },
    )
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
        let Some(raw_node) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        let node = normalize_log_node(raw_node);
        push_event(
            events,
            NormalizedEvent {
                ts: record
                    .get("ts")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| file_timestamp(&path)),
                repo: repo_id.to_string(),
                run: run_id.to_string(),
                node: node.clone(),
                parent: parents.get(&node).cloned().flatten(),
                role: roles
                    .get(&node)
                    .copied()
                    .unwrap_or_else(|| infer_report_role(&node, &node, run_id)),
                kind: OrchestrationEventKind::Journal,
                payload: json!({
                    "source": relative_source(directory, &path, "logs"),
                    "tail": record,
                }),
            },
        )?;
    }
    Ok(())
}

fn normalize_log_node(stem: &str) -> String {
    let Some((node, attempt)) = stem.rsplit_once(".attempt-") else {
        return stem.to_string();
    };
    let positive_attempt = attempt
        .parse::<u64>()
        .ok()
        .is_some_and(|attempt| attempt > 0);
    if !node.is_empty() && positive_attempt {
        node.to_string()
    } else {
        stem.to_string()
    }
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
    push_event(
        events,
        NormalizedEvent {
            ts,
            repo: repo_id.to_string(),
            run: run_id.to_string(),
            node: run_id.to_string(),
            parent: None,
            role: OrchestrationRole::Supervisor,
            kind: OrchestrationEventKind::Status,
            payload: json!({"source": "STATE.tsv", "state": state}),
        },
    )?;
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
        push_event(
            events,
            NormalizedEvent {
                ts,
                repo: repo_id.to_string(),
                run: run_id.to_string(),
                node: node.to_string(),
                parent: None,
                role: OrchestrationRole::Supervisor,
                kind: OrchestrationEventKind::Status,
                payload: json!({"source": "HEARTBEAT.tsv", "heartbeat": row}),
            },
        )?;
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
        push_event(
            events,
            NormalizedEvent {
                ts: ts.clone(),
                repo: repo_id.to_string(),
                run: run_id.to_string(),
                node: node.clone(),
                parent,
                role: OrchestrationRole::Supervisor,
                kind: OrchestrationEventKind::Spawn,
                payload: json!({"source": "queue.tsv", "task": row}),
            },
        )?;
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
            push_event(
                events,
                NormalizedEvent {
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
                },
            )?;
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
    if report.get("success").and_then(Value::as_bool) == Some(true) {
        return OrchestrationEventKind::Accept;
    }
    if report.get("success").and_then(Value::as_bool) == Some(false) {
        return OrchestrationEventKind::Reject;
    }
    match report.get("status").and_then(Value::as_str) {
        Some("succeeded" | "completed" | "accepted" | "done") => OrchestrationEventKind::Accept,
        Some("failed" | "rejected" | "blocked") => OrchestrationEventKind::Reject,
        _ => OrchestrationEventKind::Status,
    }
}

fn infer_report_role(node: &str, fallback_node: &str, run_id: &str) -> OrchestrationRole {
    if node.ends_with("-review-auditor") || fallback_node.ends_with("-review-auditor") {
        OrchestrationRole::Auditor
    } else if node == run_id || fallback_node == "supervisor-final" {
        OrchestrationRole::Supervisor
    } else {
        OrchestrationRole::Worker
    }
}

fn infer_auditor_parent(node: &str, role: OrchestrationRole) -> Option<String> {
    if role != OrchestrationRole::Auditor {
        return None;
    }
    node.strip_suffix("-review-auditor")
        .filter(|parent| !parent.is_empty())
        .map(str::to_owned)
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
        "o2" => validate_directory_chain(run_dir, &["reports"])?
            .map(|directory| vec![directory.join("supervisor-final.json")])
            .unwrap_or_default(),
        "autopilot" | "inbox" => vec![run_dir.join("final-report.json")],
        "consult" => {
            let mut candidates = vec![run_dir.join("consultant-report.json")];
            if let Some(directory) = validate_directory_chain(run_dir, &["trusted"])? {
                candidates.push(directory.join("consultant-report.json"));
            }
            candidates
        }
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
    let Some(file) = open_regular_file(path)? else {
        return Ok(None);
    };
    if file.metadata()?.len() > max_bytes {
        return Err(invalid_data(format!(
            "Scope artifact exceeds the {max_bytes} byte limit: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(invalid_data(format!(
            "Scope artifact grew beyond the {max_bytes} byte limit: {}",
            path.display()
        )));
    }
    Ok(Some(bytes))
}

fn read_last_json_line(path: &Path) -> io::Result<Option<Value>> {
    let Some(mut file) = open_regular_file(path)? else {
        return Ok(None);
    };
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
    if metadata.file_type().is_symlink() {
        return Err(invalid_data(format!(
            "Scope refuses symlinked directory {}",
            directory.display()
        )));
    }
    if !metadata.file_type().is_dir() {
        return Err(invalid_data(format!(
            "Scope expected a directory at {}",
            directory.display()
        )));
    }
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(directory)?.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            return Err(invalid_data(format!(
                "Scope directory exceeds the {MAX_DIRECTORY_ENTRIES} entry limit: {}",
                directory.display()
            )));
        }
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid_data(format!(
                "Scope refuses symlinked artifact {}",
                path.display()
            )));
        }
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
    let mut visited = 0_usize;
    while let Some((directory, depth)) = pending.pop() {
        for path in read_children(&directory, |_, _| true)? {
            visited += 1;
            if visited > MAX_DISCOVERY_ENTRIES {
                return Err(invalid_data(format!(
                    "Scope recursive discovery exceeds the {MAX_DISCOVERY_ENTRIES} entry limit under {}",
                    root.display()
                )));
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_file()
                && path.file_name().and_then(|value| value.to_str()) == Some(name)
            {
                if found.len() >= MAX_NAMED_FILES {
                    return Err(invalid_data(format!(
                        "Scope recursive discovery exceeds the {MAX_NAMED_FILES} named-file limit under {}",
                        root.display()
                    )));
                }
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
        Ok(metadata) if metadata.file_type().is_symlink() => Err(invalid_data(format!(
            "Scope refuses symlinked artifact {}",
            path.display()
        ))),
        Ok(metadata) => Ok(metadata.file_type().is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn no_follow_metadata(path: &Path) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
}

fn open_regular_file(path: &Path) -> io::Result<Option<File>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(invalid_data(format!(
            "Scope refuses symlinked artifact {}",
            path.display()
        )));
    }
    if !metadata.file_type().is_file() {
        return Err(invalid_data(format!(
            "Scope expected a regular file at {}",
            path.display()
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(invalid_data(format!(
            "Scope artifact changed type while opening {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
        return Err(invalid_data(format!(
            "Scope artifact changed identity while opening {}",
            path.display()
        )));
    }
    Ok(Some(file))
}

fn validate_directory_chain(root: &Path, components: &[&str]) -> io::Result<Option<PathBuf>> {
    let canonical_root = fs::canonicalize(root)?;
    if canonical_root != root {
        return Err(invalid_data(format!(
            "Scope directory root must be canonical: {}",
            root.display()
        )));
    }
    let mut current = root.to_path_buf();
    for component in components {
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            return Err(invalid_data(format!(
                "Scope refuses symlinked intermediate directory {}",
                current.display()
            )));
        }
        if !metadata.file_type().is_dir() {
            return Err(invalid_data(format!(
                "Scope expected a directory at {}",
                current.display()
            )));
        }
        let canonical = fs::canonicalize(&current)?;
        if canonical != current || !canonical.starts_with(&canonical_root) {
            return Err(invalid_data(format!(
                "Scope directory escapes its canonical root: {}",
                current.display()
            )));
        }
    }
    Ok(Some(current))
}

fn push_event(events: &mut Vec<NormalizedEvent>, event: NormalizedEvent) -> io::Result<()> {
    if events.len() >= MAX_EVENTS_PER_RUN {
        return Err(invalid_data(format!(
            "Scope run exceeds the {MAX_EVENTS_PER_RUN} normalized event limit"
        )));
    }
    events.push(event);
    Ok(())
}

fn ensure_event_limit(events: &[NormalizedEvent]) -> io::Result<()> {
    if events.len() > MAX_EVENTS_PER_RUN {
        return Err(invalid_data(format!(
            "Scope run exceeds the {MAX_EVENTS_PER_RUN} normalized event limit"
        )));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn relative_source(directory: &Path, path: &Path, prefix: &str) -> String {
    let relative = path.strip_prefix(directory).unwrap_or(path);
    format!("{prefix}/{}", relative.to_string_lossy())
}

fn sort_and_deduplicate(events: &mut Vec<NormalizedEvent>) {
    events.sort_by(compare_events);
    let mut seen = BTreeSet::new();
    events.retain(|event| {
        let Ok(encoded) = serde_json::to_string(event) else {
            return false;
        };
        seen.insert(encoded)
    });
}

fn sort_and_deduplicate_family_events(events: &mut Vec<FamilyEvent>) {
    events.sort_by(|left, right| {
        compare_events(&left.event, &right.event).then_with(|| left.family.cmp(&right.family))
    });
    let mut seen = BTreeSet::new();
    events.retain(|event| {
        let Ok(encoded) = serde_json::to_string(&event.event) else {
            return false;
        };
        seen.insert((event.family.clone(), encoded))
    });
}

fn compare_events(left: &NormalizedEvent, right: &NormalizedEvent) -> std::cmp::Ordering {
    left.ts
        .cmp(&right.ts)
        .then_with(|| left.repo.cmp(&right.repo))
        .then_with(|| left.run.cmp(&right.run))
        .then_with(|| left.node.cmp(&right.node))
        .then_with(|| left.parent.cmp(&right.parent))
        .then_with(|| role_rank(left.role).cmp(&role_rank(right.role)))
        .then_with(|| event_kind_rank(left.kind).cmp(&event_kind_rank(right.kind)))
        .then_with(|| left.payload.to_string().cmp(&right.payload.to_string()))
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
    use std::io::Write as _;

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

    fn journal_event(node: &str) -> String {
        format!(
            "{{\"ts\":\"2026-07-20T00:00:00Z\",\"repo\":\"journal-repo\",\"run\":\"journal-run\",\"node\":\"{node}\",\"parent\":null,\"role\":\"worker\",\"kind\":\"status\",\"payload\":{{}}}}\n"
        )
    }

    #[test]
    fn cached_scope_reads_appended_journal_suffix_and_rebuilds_truncation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let journal = temp
            .path()
            .join(".maco/o2/runs/cached/events/orchestration.jsonl");
        write(&journal, &journal_event("first"));
        let mut cache = CachedScope::new(vec![target(temp.path())]);

        assert!(cache.refresh().expect("initial cache refresh"));
        assert!(!cache.refresh().expect("unchanged cache refresh"));
        assert_eq!(
            cache
                .snapshot()
                .expect("cached snapshot")
                .events_for_run("repo-one", "o2", "cached")
                .expect("cached run")
                .len(),
            1
        );

        let mut file = OpenOptions::new()
            .append(true)
            .open(&journal)
            .expect("append journal");
        file.write_all(journal_event("second").as_bytes())
            .expect("append event");
        drop(file);

        assert!(cache.refresh().expect("appended cache refresh"));
        let events = cache
            .snapshot()
            .expect("appended snapshot")
            .events_for_run("repo-one", "o2", "cached")
            .expect("appended run");
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|event| event.node == "second"));
        let key = RunKey {
            repo: "repo-one".to_string(),
            family: "o2".to_string(),
            run: "cached".to_string(),
        };
        assert_eq!(
            cache
                .journals
                .get(&key)
                .expect("journal watch")
                .position
                .offset,
            fs::metadata(&journal).expect("journal metadata").len()
        );

        fs::write(&journal, b"{}\n").expect("truncate journal");
        assert!(cache.refresh().expect("truncated cache refresh"));
        assert!(cache
            .snapshot()
            .expect("rebuilt snapshot")
            .events_for_run("repo-one", "o2", "cached")
            .expect("rebuilt run")
            .is_empty());
    }

    #[test]
    fn all_events_keeps_identical_records_from_distinct_families() {
        let temp = tempfile::tempdir().expect("tempdir");
        let event = concat!(
            r#"{"ts":"2026-07-20T00:00:00Z","repo":"journal-repo","run":"shared-run","node":"worker-a","parent":null,"role":"worker","kind":"status","payload":{"status":"running"}}"#,
            "\n"
        );
        write(
            &temp
                .path()
                .join(".maco/autopilot/runs/shared-run/events/orchestration.jsonl"),
            event,
        );
        write(
            &temp
                .path()
                .join(".maco/o2/runs/shared-run/events/orchestration.jsonl"),
            event,
        );

        let snapshot = scan_repositories(&[target(temp.path())]).expect("scan duplicate families");
        let events = snapshot.all_events();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].family, "autopilot");
        assert_eq!(events[1].family, "o2");
        assert_eq!(events[0].event, events[1].event);
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
    fn repository_scan_breadth_overflow_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repositories = (0..=MAX_REPOSITORIES)
            .map(|index| RepositoryTarget {
                id: format!("repo-{index}"),
                path: temp.path().to_path_buf(),
            })
            .collect::<Vec<_>>();
        let error = scan_repositories(&repositories).expect_err("reject repository overflow");
        assert!(error.to_string().contains("repository limit"));
    }

    #[test]
    fn fallback_reconstructs_tree_acceptance_liveness_and_inferred_escalation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let run = temp.path().join(".maco/o2/runs/run-fallback");
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
            &run.join("reports/o1-a.json"),
            r#"{
                "id":"o1-a","role":"child_orchestrator","status":"succeeded",
                "accepted":true,
                "worker_reports":[{
                    "id":"worker-a","role":"worker","status":"succeeded",
                    "accepted":true,"claim_token":42,
                    "assigned_paths":["src/a.rs"],
                    "validation_results":[{"name":"unit","status":"succeeded"}]
                }],
                "audit_reports":[{
                    "id":"auditor-a","role":"auditor","status":"failed",
                    "accepted":false,"rejected":true,
                    "validation_results":[{"name":"coverage","status":"failed"}]
                }]
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
            .events_for_run("repo-one", "o2", "run-fallback")
            .expect("fallback run");
        assert!(events.iter().any(|event| {
            event.node == "run-fallback"
                && event.parent.is_none()
                && event.role == OrchestrationRole::Supervisor
                && event.kind == OrchestrationEventKind::Spawn
                && event.payload["synthetic"] == true
        }));
        assert!(events.iter().any(|event| {
            event.node == "o1-a"
                && event.parent.as_deref() == Some("run-fallback")
                && event.role == OrchestrationRole::Orchestrator
                && event.kind == OrchestrationEventKind::Spawn
        }));
        assert!(events.iter().any(|event| {
            event.node == "worker-a"
                && event.parent.as_deref() == Some("o1-a")
                && event.role == OrchestrationRole::Worker
                && event.kind == OrchestrationEventKind::Spawn
        }));
        assert!(events.iter().any(|event| {
            event.node == "worker-a"
                && event.parent.as_deref() == Some("o1-a")
                && event.role == OrchestrationRole::Worker
                && event.kind == OrchestrationEventKind::Accept
        }));
        assert!(events.iter().any(|event| {
            event.node == "auditor-a"
                && event.parent.as_deref() == Some("o1-a")
                && event.role == OrchestrationRole::Auditor
                && event.kind == OrchestrationEventKind::Reject
        }));
        assert!(events.iter().any(|event| {
            event.node == "worker-a" && event.kind == OrchestrationEventKind::Claim
        }));
        assert!(events.iter().any(|event| {
            event.node == "worker-a" && event.kind == OrchestrationEventKind::Gate
        }));
        assert!(events.iter().any(|event| {
            event.node == "auditor-a" && event.kind == OrchestrationEventKind::Gate
        }));
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
    fn legacy_root_reports_replay_autopilot_inbox_and_consult_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let autopilot = temp.path().join(".maco/autopilot/runs/auto-run");
        write(
            &autopilot.join("final-report.json"),
            r#"{"run_id":"auto-run","status":"succeeded","success":true}"#,
        );
        write(
            &autopilot.join("review-report.json"),
            r#"{"status":"failed","success":false}"#,
        );
        write(
            &autopilot.join("supervisor-report.json"),
            r#"{"status":"running"}"#,
        );

        let partial = temp.path().join(".maco/autopilot/runs/auto-partial");
        write(
            &partial.join("supervisor-report.json"),
            r#"{"status":"running"}"#,
        );

        let inbox = temp.path().join(".maco/inbox/runs/inbox-run");
        write(
            &inbox.join("final-report.json"),
            r#"{"run_id":"inbox-run","status":"failed","success":false}"#,
        );
        write(&inbox.join("scan-report.json"), r#"{"status":"running"}"#);
        write(
            &inbox.join("item-1-autopilot-report.json"),
            r#"{"status":"succeeded","success":true}"#,
        );
        write(
            &inbox.join("item-1-github-report.json"),
            r#"{"status":"failed","success":false}"#,
        );
        write(
            &inbox.join("selected-items.json"),
            r#"{"id":"must-not-be-an-event","status":"succeeded"}"#,
        );

        let trusted_consult = temp.path().join(".maco/consult/runs/consult-trusted");
        write(
            &trusted_consult.join("trusted/consultant-report.json"),
            r#"{"run_id":"consult-trusted","status":"succeeded","success":true}"#,
        );
        let root_consult = temp.path().join(".maco/consult/runs/consult-root");
        write(
            &root_consult.join("consultant-report.json"),
            r#"{"run_id":"consult-root","status":"failed","success":false}"#,
        );

        let snapshot = scan_repositories(&[target(temp.path())]).expect("scan legacy reports");
        let auto_events = snapshot
            .events_for_run("repo-one", "autopilot", "auto-run")
            .expect("autopilot run");
        assert!(auto_events.iter().any(|event| {
            event.node == "auto-run"
                && event.role == OrchestrationRole::Supervisor
                && event.kind == OrchestrationEventKind::Accept
        }));
        assert!(auto_events.iter().any(|event| {
            event.node == "auto-run-review"
                && event.parent.as_deref() == Some("auto-run")
                && event.role == OrchestrationRole::Auditor
                && event.kind == OrchestrationEventKind::Reject
        }));
        assert!(auto_events.iter().any(|event| {
            event.node == "auto-run-supervisor"
                && event.parent.as_deref() == Some("auto-run")
                && event.kind == OrchestrationEventKind::Status
        }));
        let partial_events = snapshot
            .events_for_run("repo-one", "autopilot", "auto-partial")
            .expect("partial autopilot run");
        assert!(partial_events.iter().any(|event| {
            event.node == "auto-partial-supervisor"
                && event.parent.as_deref() == Some("auto-partial")
                && event.kind == OrchestrationEventKind::Status
        }));

        let inbox_events = snapshot
            .events_for_run("repo-one", "inbox", "inbox-run")
            .expect("inbox run");
        assert!(inbox_events.iter().any(|event| {
            event.node == "inbox-run"
                && event.role == OrchestrationRole::Supervisor
                && event.kind == OrchestrationEventKind::Reject
        }));
        assert!(inbox_events.iter().any(|event| {
            event.node == "item-1-autopilot-report"
                && event.parent.as_deref() == Some("inbox-run")
                && event.role == OrchestrationRole::Orchestrator
                && event.kind == OrchestrationEventKind::Accept
        }));
        assert!(inbox_events.iter().any(|event| {
            event.node == "item-1-github-report"
                && event.parent.as_deref() == Some("inbox-run")
                && event.role == OrchestrationRole::Worker
                && event.kind == OrchestrationEventKind::Reject
        }));
        assert!(!inbox_events
            .iter()
            .any(|event| event.node == "must-not-be-an-event"));

        for (run_id, kind) in [
            ("consult-trusted", OrchestrationEventKind::Accept),
            ("consult-root", OrchestrationEventKind::Reject),
        ] {
            let events = snapshot
                .events_for_run("repo-one", "consult", run_id)
                .expect("consult run");
            assert!(events.iter().any(|event| {
                event.node == run_id
                    && event.role == OrchestrationRole::Auditor
                    && event.kind == kind
            }));
        }
    }

    #[test]
    fn report_identity_drives_attempt_log_liveness_roles_and_parents() {
        let temp = tempfile::tempdir().expect("tempdir");
        let run = temp.path().join(".maco/o2/runs/o2-log-run");
        write(
            &run.join("assignments/supervisor-plan.json"),
            r#"{"assignments":[{"id":"child","role":"child_orchestrator"}]}"#,
        );
        write(
            &run.join("reports/child.json"),
            r#"{"id":"child","status":"succeeded","accepted":true}"#,
        );
        write(
            &run.join("reports/child-review-auditor.json"),
            r#"{"id":"child-review-auditor","status":"succeeded","accepted":true}"#,
        );
        write(
            &run.join("logs/child.attempt-1.jsonl"),
            "{\"ts\":\"2026-07-20T01:00:00Z\",\"status\":\"running\"}\n",
        );
        write(
            &run.join("logs/child-review-auditor.attempt-2.jsonl"),
            "{\"ts\":\"2026-07-20T01:01:00Z\",\"status\":\"running\"}\n",
        );

        let snapshot = scan_repositories(&[target(temp.path())]).expect("scan attempt logs");
        let events = snapshot
            .events_for_run("repo-one", "o2", "o2-log-run")
            .expect("O2 run");
        assert!(events.iter().any(|event| {
            event.node == "child"
                && event.parent.as_deref() == Some("o2-log-run")
                && event.role == OrchestrationRole::Orchestrator
                && event.kind == OrchestrationEventKind::Journal
        }));
        assert!(events.iter().any(|event| {
            event.node == "child-review-auditor"
                && event.parent.as_deref() == Some("child")
                && event.role == OrchestrationRole::Auditor
                && event.kind == OrchestrationEventKind::Journal
        }));
        assert!(!events.iter().any(|event| event.node.contains(".attempt-")));
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
        assert!(snapshot.all_events().len() >= runs.len());
    }

    #[cfg(unix)]
    #[test]
    fn scanning_rejects_symlinked_artifacts() {
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

        let error = scan_repositories(&[target(temp.path())]).expect_err("reject journal symlink");
        assert!(error.to_string().contains("symlinked artifact"));
    }

    #[test]
    fn primary_journal_bound_overflows_fail_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let oversized = temp.path().join("oversized.jsonl");
        write(&oversized, "{}");
        fs::OpenOptions::new()
            .write(true)
            .open(&oversized)
            .expect("open oversized journal")
            .set_len(MAX_JOURNAL_BYTES + 1)
            .expect("extend oversized journal");
        let error = read_journal(&oversized, "repo", "run").expect_err("reject byte overflow");
        assert!(error.to_string().contains("byte limit"));

        let long_line = temp.path().join("long-line.jsonl");
        write(&long_line, &"x".repeat(MAX_JOURNAL_LINE_BYTES + 1));
        let error = read_journal(&long_line, "repo", "run").expect_err("reject long line");
        assert!(error.to_string().contains("line exceeds"));

        let excessive_records = temp.path().join("too-many-records.jsonl");
        write(&excessive_records, &"{}\n".repeat(MAX_JOURNAL_RECORDS + 1));
        let error =
            read_journal(&excessive_records, "repo", "run").expect_err("reject record overflow");
        assert!(error.to_string().contains("record limit"));
    }

    #[cfg(unix)]
    #[test]
    fn scanning_rejects_symlinked_fixed_intermediate_directories() {
        use std::os::unix::fs::symlink;

        let maco_temp = tempfile::tempdir().expect("maco tempdir");
        let outside_maco = maco_temp.path().join("outside-maco");
        fs::create_dir(&outside_maco).expect("outside maco");
        let watched = maco_temp.path().join("watched");
        fs::create_dir(&watched).expect("watched repo");
        symlink(&outside_maco, watched.join(".maco")).expect("maco symlink");
        let error = scan_repositories(&[target(&watched)]).expect_err("reject maco symlink");
        assert!(error.to_string().contains("intermediate directory"));

        let events_temp = tempfile::tempdir().expect("events tempdir");
        let run = events_temp.path().join(".maco/o2/runs/run/events-parent");
        fs::create_dir_all(&run).expect("run directory");
        let run_root = events_temp.path().join(".maco/o2/runs/run");
        symlink(&run, run_root.join("events")).expect("events symlink");
        let error =
            scan_repositories(&[target(events_temp.path())]).expect_err("reject events symlink");
        assert!(error.to_string().contains("intermediate directory"));
    }
}
