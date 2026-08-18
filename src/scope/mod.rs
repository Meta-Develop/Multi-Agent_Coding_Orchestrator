mod normalize;
mod server;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::inbox::load_workspace_repositories;
use normalize::{
    CachedScope, NormalizedEvent, RepositoryTarget, StreamBatch, StreamCursor, StreamFilter,
};
use server::ScopeDataSource;

const CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeServeOptions {
    pub repositories: Vec<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub bind: String,
}

#[derive(Debug)]
struct ScanningDataSource {
    state: Mutex<ScanningDataSourceState>,
}

#[derive(Debug)]
struct ScanningDataSourceState {
    cache: CachedScope,
    projects: Option<Value>,
    refresh_after: Option<Instant>,
}

impl ScanningDataSource {
    fn new(repositories: Vec<RepositoryTarget>) -> Self {
        Self {
            state: Mutex::new(ScanningDataSourceState {
                cache: CachedScope::new(repositories),
                projects: None,
                refresh_after: None,
            }),
        }
    }

    fn state(&self) -> Result<MutexGuard<'_, ScanningDataSourceState>> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("Scope cache lock is poisoned"))
    }
}

impl ScanningDataSourceState {
    fn refresh_if_due(&mut self) -> Result<bool> {
        if self
            .refresh_after
            .is_some_and(|refresh_after| Instant::now() < refresh_after)
        {
            return Ok(false);
        }
        let refresh = self
            .cache
            .refresh()
            .context("failed to refresh Scope repositories");
        self.refresh_after = Some(Instant::now() + CACHE_REFRESH_INTERVAL);
        refresh
    }
}

impl ScopeDataSource for ScanningDataSource {
    fn projects(&self) -> Result<Value> {
        let mut state = self.state()?;
        let changed = state.refresh_if_due()?;
        if changed || state.projects.is_none() {
            state.projects = Some(
                serde_json::to_value(state.cache.snapshot()?)
                    .context("failed to serialize Scope projects")?,
            );
        }
        state
            .projects
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Scope projects cache was not initialized"))
    }

    fn events(
        &self,
        repo_id: &str,
        family: &str,
        run_id: &str,
    ) -> Result<Option<Vec<NormalizedEvent>>> {
        let mut state = self.state()?;
        state.refresh_if_due()?;
        Ok(state
            .cache
            .snapshot()?
            .events_for_run(repo_id, family, run_id)
            .map(<[NormalizedEvent]>::to_vec))
    }

    fn stream_events(
        &self,
        filter: &StreamFilter,
        cursor: StreamCursor,
        limit: usize,
    ) -> Result<StreamBatch> {
        let mut state = self.state()?;
        state.refresh_if_due()?;
        Ok(state.cache.stream_events(filter, cursor, limit))
    }
}

pub fn serve(options: ScopeServeOptions) -> Result<()> {
    server::validate_loopback_bind(&options.bind)?;
    let repositories = resolve_repositories(&options)?;
    let source: Arc<dyn ScopeDataSource> = Arc::new(ScanningDataSource::new(repositories));
    server::bind_and_serve(&options.bind, source)
}

fn resolve_repositories(options: &ScopeServeOptions) -> Result<Vec<RepositoryTarget>> {
    let explicit_paths = if options.repositories.is_empty() && options.workspace.is_none() {
        vec![PathBuf::from(".")]
    } else {
        options.repositories.clone()
    };

    let mut targets = Vec::new();
    let mut ids = BTreeMap::new();
    let mut paths = BTreeMap::new();

    if let Some(workspace) = &options.workspace {
        for repository in load_workspace_repositories(workspace)? {
            if !repository.enabled {
                continue;
            }
            let path = canonical_repository_path(&repository.path)?;
            insert_repository_target(
                &mut targets,
                &mut ids,
                &mut paths,
                RepositoryTarget {
                    id: repository.id,
                    path,
                },
            )?;
        }
    }

    for path in explicit_paths {
        let path = canonical_repository_path(&path)?;
        let id = explicit_repository_id(&path);
        insert_repository_target(
            &mut targets,
            &mut ids,
            &mut paths,
            RepositoryTarget { id, path },
        )?;
    }

    Ok(targets)
}

fn canonical_repository_path(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve Scope repository {}", path.display()))?;
    if !canonical.is_dir() {
        bail!("Scope repository {} is not a directory", path.display());
    }
    Ok(canonical)
}

fn explicit_repository_id(path: &Path) -> String {
    let candidate = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo");
    let mut id = String::new();
    let mut previous_separator = false;
    for character in candidate.chars() {
        let safe = if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            character
        } else {
            '-'
        };
        if safe == '-' {
            if previous_separator {
                continue;
            }
            previous_separator = true;
        } else {
            previous_separator = false;
        }
        id.push(safe);
    }
    let id = id.trim_matches(|character| matches!(character, '.' | '_' | '-'));
    if id.is_empty() {
        "repo".to_string()
    } else {
        id.to_string()
    }
}

fn insert_repository_target(
    targets: &mut Vec<RepositoryTarget>,
    ids: &mut BTreeMap<String, usize>,
    paths: &mut BTreeMap<PathBuf, usize>,
    target: RepositoryTarget,
) -> Result<()> {
    if let Some(index) = paths.get(&target.path).copied() {
        let existing = &targets[index];
        if existing.id == target.id {
            return Ok(());
        }
        bail!(
            "Scope repository path {} has conflicting ids '{}' and '{}'",
            target.path.display(),
            existing.id,
            target.id
        );
    }

    let folded_id = target.id.to_ascii_lowercase();
    if let Some(index) = ids.get(&folded_id).copied() {
        let existing = &targets[index];
        bail!(
            "Scope repository id '{}' refers to both {} and {}",
            target.id,
            existing.path.display(),
            target.path.display()
        );
    }

    let index = targets.len();
    ids.insert(folded_id, index);
    paths.insert(target.path.clone(), index);
    targets.push(target);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::{SocketAddr, TcpListener, TcpStream},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
        time::Duration,
    };

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    fn options(repositories: Vec<PathBuf>, workspace: Option<PathBuf>) -> ScopeServeOptions {
        ScopeServeOptions {
            repositories,
            workspace,
            bind: "127.0.0.1:0".to_string(),
        }
    }

    #[test]
    fn defaults_to_current_directory_only_without_other_sources() {
        let targets = resolve_repositories(&options(Vec::new(), None)).expect("default target");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].path, fs::canonicalize(".").expect("current dir"));
    }

    #[test]
    fn combines_explicit_and_enabled_workspace_repositories() {
        let temp = TempDir::new().expect("tempdir");
        let explicit = temp.path().join("explicit repo");
        let workspace_repo = temp.path().join("workspace-repo");
        let disabled = temp.path().join("disabled");
        fs::create_dir(&explicit).expect("explicit repo");
        fs::create_dir(&workspace_repo).expect("workspace repo");
        fs::create_dir(&disabled).expect("disabled repo");
        let workspace = temp.path().join("workspace.json");
        fs::write(
            &workspace,
            serde_json::to_vec(&json!({
                "repositories": [
                    {"id": "workspace-id", "path": "workspace-repo"},
                    {"id": "disabled-id", "path": "disabled", "enabled": false}
                ]
            }))
            .expect("workspace JSON"),
        )
        .expect("workspace config");

        let targets = resolve_repositories(&options(vec![explicit.clone()], Some(workspace)))
            .expect("resolve repositories");

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].id, "workspace-id");
        assert_eq!(targets[0].path, fs::canonicalize(workspace_repo).unwrap());
        assert_eq!(targets[1].id, "explicit-repo");
        assert_eq!(targets[1].path, fs::canonicalize(explicit).unwrap());
    }

    #[test]
    fn workspace_only_does_not_inject_current_directory() {
        let temp = TempDir::new().expect("tempdir");
        let disabled = temp.path().join("disabled");
        fs::create_dir(&disabled).expect("disabled repo");
        let workspace = temp.path().join("workspace.json");
        fs::write(
            &workspace,
            serde_json::to_vec(&json!({
                "repositories": [
                    {"id": "disabled", "path": "disabled", "enabled": false}
                ]
            }))
            .expect("workspace JSON"),
        )
        .expect("workspace config");

        let targets =
            resolve_repositories(&options(Vec::new(), Some(workspace))).expect("workspace");
        assert!(targets.is_empty());
    }

    #[test]
    fn rejects_id_collisions_and_path_aliases() {
        let temp = TempDir::new().expect("tempdir");
        let first = temp.path().join("same");
        let second_parent = temp.path().join("other");
        let second = second_parent.join("same");
        fs::create_dir(&first).expect("first repo");
        fs::create_dir_all(&second).expect("second repo");
        assert!(resolve_repositories(&options(vec![first, second], None)).is_err());

        let repo = temp.path().join("aliased");
        fs::create_dir(&repo).expect("aliased repo");
        let workspace = temp.path().join("workspace.json");
        fs::write(
            &workspace,
            serde_json::to_vec(&json!({
                "repositories": [{"id": "workspace-id", "path": "aliased"}]
            }))
            .expect("workspace JSON"),
        )
        .expect("workspace config");
        assert!(resolve_repositories(&options(vec![repo], Some(workspace))).is_err());
    }

    #[test]
    fn deduplicates_repeated_explicit_canonical_paths() {
        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join("repeated");
        fs::create_dir(&repo).expect("repeated repo");

        let targets = resolve_repositories(&options(vec![repo.clone(), repo], None))
            .expect("deduplicate explicit repository");

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, "repeated");
    }

    #[test]
    fn coalesces_cache_validation_within_the_refresh_interval() {
        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join("fixture-repo");
        let journal = repo.join(".maco/o2/runs/run-1/events/orchestration.jsonl");
        fs::create_dir_all(journal.parent().expect("journal parent"))
            .expect("fixture event directory");
        let first_event = concat!(
            r#"{"ts":"2026-07-20T12:00:00Z","repo":"fixture-repo","run":"run-1","node":"worker-1","parent":null,"role":"worker","kind":"status","payload":{}}"#,
            "\n"
        );
        let second_event = concat!(
            r#"{"ts":"2026-07-20T12:00:01Z","repo":"fixture-repo","run":"run-1","node":"worker-2","parent":null,"role":"worker","kind":"status","payload":{}}"#,
            "\n"
        );
        fs::write(&journal, first_event).expect("fixture journal");

        let targets = resolve_repositories(&options(vec![repo], None)).expect("fixture target");
        let source = ScanningDataSource::new(targets);
        let mut state = source.state().expect("source state");
        assert!(state.refresh_if_due().expect("initial refresh"));

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&journal)
            .expect("append journal");
        file.write_all(second_event.as_bytes())
            .expect("append event");
        drop(file);

        assert!(!state.refresh_if_due().expect("coalesced refresh"));
        assert_eq!(
            state
                .cache
                .snapshot()
                .expect("cached snapshot")
                .events_for_run("fixture-repo", "o2", "run-1")
                .expect("cached run")
                .len(),
            1
        );

        state.refresh_after = None;
        assert!(state.refresh_if_due().expect("due refresh"));
        assert_eq!(
            state
                .cache
                .snapshot()
                .expect("refreshed snapshot")
                .events_for_run("fixture-repo", "o2", "run-1")
                .expect("refreshed run")
                .len(),
            2
        );
    }

    #[test]
    fn serves_project_summaries_and_run_events_from_a_fixture_repository() {
        let temp = TempDir::new().expect("tempdir");
        let repo = temp.path().join("fixture-repo");
        let events_dir = repo
            .join(".maco")
            .join("o2")
            .join("runs")
            .join("run-1")
            .join("events");
        fs::create_dir_all(&events_dir).expect("fixture event directory");
        fs::write(
            events_dir.join("orchestration.jsonl"),
            concat!(
                r#"{"ts":"2026-07-20T12:00:00Z","repo":"journal-repo","run":"journal-run","node":"worker-1","parent":"o1-1","role":"worker","kind":"spawn","payload":{"task":"fixture"}}"#,
                "\n"
            ),
        )
        .expect("fixture event journal");

        let scope_options = options(vec![repo], None);
        let targets = resolve_repositories(&scope_options).expect("fixture target");
        let source: Arc<dyn ScopeDataSource> = Arc::new(ScanningDataSource::new(targets));
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral listener");
        let address = listener.local_addr().expect("listener address");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let server =
            thread::spawn(move || server::serve_listener(listener, source, server_shutdown));

        let projects_response = http_get(address, "/api/projects");
        assert!(projects_response.starts_with("HTTP/1.1 200"));
        let projects: Value =
            serde_json::from_str(http_body(&projects_response)).expect("projects response JSON");
        let project = &projects["projects"][0];
        assert_eq!(project["id"], "fixture-repo");
        assert_eq!(project["runs"][0]["family"], "o2");
        assert_eq!(project["runs"][0]["run"], "run-1");
        assert_eq!(project["runs"][0]["final_report_exists"], false);
        assert!(project["runs"][0].get("events").is_none());

        let events_response = http_get(address, "/api/runs/fixture-repo/o2/run-1/events");
        assert!(events_response.starts_with("HTTP/1.1 200"));
        let events: Value =
            serde_json::from_str(http_body(&events_response)).expect("events response JSON");
        let events = events.as_array().expect("events array");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["family"], "o2");
        assert_eq!(events[0]["repo"], "fixture-repo");
        assert_eq!(events[0]["run"], "run-1");
        assert_eq!(events[0]["node"], "worker-1");
        assert_eq!(events[0]["kind"], "spawn");
        assert_eq!(events[0]["payload"]["task"], "fixture");

        let mut event_stream = TcpStream::connect(address).expect("connect to fixture SSE");
        event_stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set SSE read timeout");
        event_stream
            .write_all(b"GET /api/stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .expect("write SSE request");
        let mut stream_response = Vec::new();
        let mut buffer = [0_u8; 4096];
        while !has_complete_sse_event(&stream_response) {
            let count = event_stream.read(&mut buffer).expect("read SSE response");
            if count == 0 {
                break;
            }
            stream_response.extend_from_slice(&buffer[..count]);
        }
        let stream_response = String::from_utf8(stream_response).expect("SSE response UTF-8");
        assert!(stream_response.starts_with("HTTP/1.1 200"));
        assert!(stream_response.contains("Content-Type: text/event-stream"));
        let data = stream_response
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .expect("SSE data line");
        let event: Value = serde_json::from_str(data).expect("SSE event JSON");
        assert_eq!(event["family"], "o2");
        assert_eq!(event["repo"], "fixture-repo");
        assert_eq!(event["node"], "worker-1");

        shutdown.store(true, Ordering::Release);
        wake_server(address);
        let mut remainder = Vec::new();
        event_stream
            .read_to_end(&mut remainder)
            .expect("close fixture SSE stream");
        server
            .join()
            .expect("join fixture server")
            .expect("serve fixture repository");
    }

    fn http_get(address: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(address).expect("connect to fixture server");
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .expect("write fixture HTTP request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read fixture HTTP response");
        response
    }

    fn http_body(response: &str) -> &str {
        response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("HTTP response body")
    }

    fn has_complete_sse_event(response: &[u8]) -> bool {
        response
            .windows(6)
            .position(|window| window == b"data: ")
            .is_some_and(|start| {
                response[start + 6..]
                    .windows(2)
                    .any(|window| window == b"\n\n")
            })
    }

    fn wake_server(address: SocketAddr) {
        if let Ok(mut stream) = TcpStream::connect(address) {
            let _ =
                stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        }
    }
}
