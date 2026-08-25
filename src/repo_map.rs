use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::megafile::FileSizeSample;
use crate::safe_state::{
    BoundedTreeEntry, BoundedTreeEntryKind, BoundedTreeWalkAction, BoundedTreeWalkLimits,
    BoundedTreeWalker,
};

const REPOSITORY_MAP_MAX_DEPTH: usize = 128;
const REPOSITORY_MAP_MAX_ENTRIES: usize = 100_000;
const REPOSITORY_MAP_MAX_PATH_BYTES: usize = 4096;
const REPOSITORY_MAP_MAX_TOTAL_PATH_BYTES: usize = 64 * 1024 * 1024;
const REPOSITORY_SAMPLE_MAX_FILES: usize = 4_096;
const REPOSITORY_SAMPLE_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(not(test))]
const REPOSITORY_MAP_MAX_DURATION: Duration = Duration::from_secs(30);
#[cfg(test)]
const REPOSITORY_MAP_MAX_DURATION: Duration = Duration::from_secs(120);
type RepositoryMapSnapshot = (BTreeMap<PathBuf, [u8; 2]>, Vec<BoundedTreeEntry>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepoMap {
    pub root: PathBuf,
    pub entries: Vec<RepoMapEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RepoMapEntry {
    pub path: PathBuf,
    pub kind: RepoEntryKind,
    pub size_bytes: Option<u64>,
    pub category: String,
    pub git_status: RepoGitStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoGitStatus {
    Directory,
    Clean,
    Modified,
    Added,
    Deleted,
    Renamed,
    Untracked,
    Conflicted,
}

pub fn scan_repository(repo_path: impl AsRef<Path>) -> Result<RepoMap> {
    let repo = crate::git_repository::discover(repo_path.as_ref()).with_context(|| {
        format!(
            "failed to discover repository from {}",
            repo_path.as_ref().display()
        )
    })?;
    let root = repo
        .workdir()
        .context("repository map requires a non-bare repository")?
        .to_path_buf();
    let repository_binding = crate::worktree::RepositoryBindingGuard::bind(&root)?;
    let mut deadline = Instant::now()
        .checked_add(REPOSITORY_MAP_MAX_DURATION)
        .context("repository map deadline overflowed")?;
    let first = capture_repository_map_snapshot(&repository_binding, &mut deadline)?;
    let second = capture_repository_map_snapshot(&repository_binding, &mut deadline)?;
    let (statuses, inventory) = if first == second {
        second
    } else {
        let retry = capture_repository_map_snapshot(&repository_binding, &mut deadline)?;
        if second != retry {
            anyhow::bail!("repository map changed across its bounded retry");
        }
        retry
    };
    let entries = inventory
        .into_iter()
        .map(|entry| map_inventory_entry(&statuses, entry, deadline))
        .collect::<Result<Vec<_>>>()?;
    repository_binding.verify()?;
    remaining_map_time(deadline, "after repository map")?;

    Ok(RepoMap { root, entries })
}

/// Explicitly reads every regular file in a bounded coarse repository map and
/// returns language-agnostic byte/line samples. Unlike [`scan_repository`],
/// callers use this only when they intend to seed durable megafile telemetry.
pub fn scan_repository_file_samples(repo_path: impl AsRef<Path>) -> Result<Vec<FileSizeSample>> {
    let map = scan_repository(repo_path)?;
    let repository_binding = crate::worktree::RepositoryBindingGuard::bind(&map.root)?;
    let deadline = Instant::now()
        .checked_add(REPOSITORY_MAP_MAX_DURATION)
        .context("repository file sampling deadline overflowed")?;
    let entries = map
        .entries
        .into_iter()
        .filter(|entry| entry.kind == RepoEntryKind::File)
        .collect::<Vec<_>>();
    if entries.len() > REPOSITORY_SAMPLE_MAX_FILES {
        anyhow::bail!(
            "repository file sampling exceeds its {}-file update limit",
            REPOSITORY_SAMPLE_MAX_FILES
        );
    }
    let mut total_bytes = 0_u64;
    let mut samples = Vec::new();

    for entry in entries {
        if Instant::now() >= deadline {
            anyhow::bail!("repository file sampling exceeded its total time limit");
        }
        let expected_bytes = entry
            .size_bytes
            .context("regular repository file is missing its byte size")?;
        total_bytes = total_bytes
            .checked_add(expected_bytes)
            .context("repository file sample byte count overflowed")?;
        if total_bytes > REPOSITORY_SAMPLE_MAX_TOTAL_BYTES {
            anyhow::bail!(
                "repository file sampling exceeds its {}-byte aggregate content limit",
                REPOSITORY_SAMPLE_MAX_TOTAL_BYTES
            );
        }
        let contents = repository_binding
            .worktree_binding()
            .read_relative(&entry.path, expected_bytes)?;
        let observed_bytes =
            u64::try_from(contents.len()).context("sampled file size does not fit u64")?;
        if observed_bytes != expected_bytes {
            anyhow::bail!(
                "repository file size changed after map capture: {}",
                entry.path.display()
            );
        }
        samples.push(FileSizeSample {
            path: entry.path,
            bytes: observed_bytes,
            lines: physical_line_count(&contents)?,
        });
    }

    repository_binding.verify()?;
    if Instant::now() >= deadline {
        anyhow::bail!("repository file sampling exceeded its total time limit");
    }
    Ok(samples)
}

fn physical_line_count(contents: &[u8]) -> Result<u64> {
    let newline_count = contents.iter().filter(|byte| **byte == b'\n').count();
    let lines = newline_count.saturating_add(usize::from(
        !contents.is_empty() && contents.last() != Some(&b'\n'),
    ));
    u64::try_from(lines).context("sampled file line count does not fit u64")
}

fn capture_repository_map_snapshot(
    binding: &crate::worktree::RepositoryBindingGuard,
    deadline: &mut Instant,
) -> Result<RepositoryMapSnapshot> {
    let (statuses, process_queue_wait) =
        crate::worktree::bounded_repository_status_paths_bound_with_process_wait(
            binding,
            REPOSITORY_MAP_MAX_ENTRIES,
            REPOSITORY_MAP_MAX_TOTAL_PATH_BYTES,
            remaining_map_time(*deadline, "before bounded Git status")?,
        )?;
    // The worktree status path excludes only process-local serializer queue
    // wait from its own budget. Keep repository-map's outer deadline aligned
    // so unrelated in-process status callers do not spend this map's real
    // status, descriptor-walk, and classification budget.
    extend_map_deadline(
        deadline,
        process_queue_wait,
        "bounded Git status queue wait",
    )?;
    let statuses = statuses.into_iter().collect::<BTreeMap<_, _>>();
    let inventory = BoundedTreeWalker::walk_bound_with(
        binding.worktree_binding(),
        BoundedTreeWalkLimits {
            max_depth: REPOSITORY_MAP_MAX_DEPTH,
            max_entries: REPOSITORY_MAP_MAX_ENTRIES,
            max_path_bytes: REPOSITORY_MAP_MAX_PATH_BYTES,
            max_total_path_bytes: REPOSITORY_MAP_MAX_TOTAL_PATH_BYTES,
            max_duration: remaining_map_time(*deadline, "before descriptor inventory")?,
            same_device: true,
        },
        |entry| {
            Ok(if is_ignored_path(&entry.relative_path) {
                BoundedTreeWalkAction::Skip
            } else if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Record
            })
        },
    )?;
    binding.verify()?;
    Ok((statuses, inventory))
}

fn extend_map_deadline(deadline: &mut Instant, duration: Duration, phase: &str) -> Result<()> {
    if duration.is_zero() {
        return Ok(());
    }
    *deadline = deadline
        .checked_add(duration)
        .with_context(|| format!("repository map deadline overflowed while excluding {phase}"))?;
    Ok(())
}

fn remaining_map_time(deadline: Instant, phase: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .with_context(|| format!("repository map exceeded its total time limit {phase}"))
}

fn map_inventory_entry(
    statuses: &BTreeMap<PathBuf, [u8; 2]>,
    entry: BoundedTreeEntry,
    deadline: Instant,
) -> Result<RepoMapEntry> {
    if Instant::now() >= deadline {
        anyhow::bail!("repository status inspection exceeded its time limit");
    }
    let kind = entry_kind(entry.kind);
    let git_status = match kind {
        RepoEntryKind::Directory => RepoGitStatus::Directory,
        RepoEntryKind::Other => RepoGitStatus::Untracked,
        RepoEntryKind::File | RepoEntryKind::Symlink => statuses
            .get(&entry.relative_path)
            .copied()
            .map(classify_porcelain_status)
            .unwrap_or(RepoGitStatus::Clean),
    };
    Ok(RepoMapEntry {
        path: entry.relative_path.clone(),
        kind,
        size_bytes: size_bytes(&entry, kind),
        category: category_for(&entry.relative_path, kind),
        git_status,
    })
}

fn classify_porcelain_status(status: [u8; 2]) -> RepoGitStatus {
    let [index, worktree] = status;
    if index == b'U' || worktree == b'U' || matches!((index, worktree), (b'A', b'A') | (b'D', b'D'))
    {
        RepoGitStatus::Conflicted
    } else if index == b'?' && worktree == b'?' {
        RepoGitStatus::Untracked
    } else if index == b'A' {
        RepoGitStatus::Added
    } else if index == b'D' || worktree == b'D' {
        RepoGitStatus::Deleted
    } else if index == b'R' || worktree == b'R' {
        RepoGitStatus::Renamed
    } else if matches!(index, b'M' | b'T' | b'C') || matches!(worktree, b'M' | b'T' | b'C') {
        RepoGitStatus::Modified
    } else {
        RepoGitStatus::Clean
    }
}

fn entry_kind(kind: BoundedTreeEntryKind) -> RepoEntryKind {
    match kind {
        BoundedTreeEntryKind::Directory => RepoEntryKind::Directory,
        BoundedTreeEntryKind::RegularFile => RepoEntryKind::File,
        BoundedTreeEntryKind::Symlink => RepoEntryKind::Symlink,
        BoundedTreeEntryKind::Special => RepoEntryKind::Other,
    }
}

fn size_bytes(entry: &BoundedTreeEntry, kind: RepoEntryKind) -> Option<u64> {
    match kind {
        RepoEntryKind::File | RepoEntryKind::Symlink => Some(entry.size_bytes),
        RepoEntryKind::Directory | RepoEntryKind::Other => None,
    }
}

/// Runtime/control roots skipped by repository scans and merge dirty-primary
/// checks. `.maco` does not match `.maco-cache` under component-wise
/// `Path::starts_with`, so both must be listed.
pub const REPOSITORY_RUNTIME_ROOTS: &[&str] = &[".maco", ".maco-cache", ".codex", ".agents/live"];

const REPOSITORY_SCAN_IGNORED_ROOTS: &[&str] = &[
    ".git",
    "target",
    ".agent/temp",
    ".agent/storage",
    ".agents/temp",
    ".agents/storage",
];

/// Repository-local managed-worktree stores. These trees contain nested Git
/// worktree markers and must stay walk boundaries so mapping and raw
/// prevalidation neither reject the markers nor descend tens of GiB of lane
/// state. `Path::starts_with(".worktrees")` does not match dated
/// `.worktrees-quarantine-*` leftovers, so first-component matching is required.
pub fn is_ignored_worktree_store_path(path: &Path) -> bool {
    path.components().next().is_some_and(|component| {
        let name = component.as_os_str();
        name == ".worktrees"
            || name
                .to_str()
                .is_some_and(|name| name.starts_with(".worktrees-quarantine"))
    })
}

pub fn is_runtime_control_path(path: &Path) -> bool {
    path_is_under_any(path, REPOSITORY_RUNTIME_ROOTS)
}

pub fn is_ignored_scan_path(path: &Path) -> bool {
    is_runtime_control_path(path)
        || path_is_under_any(path, REPOSITORY_SCAN_IGNORED_ROOTS)
        || is_ignored_worktree_store_path(path)
}

fn is_ignored_path(path: &Path) -> bool {
    is_ignored_scan_path(path)
}

fn path_is_under_any(path: &Path, roots: &[&str]) -> bool {
    roots
        .iter()
        .any(|root| path == Path::new(root) || path.starts_with(root))
}

fn category_for(path: &Path, kind: RepoEntryKind) -> String {
    if kind == RepoEntryKind::Directory {
        return "directory".to_string();
    }

    if path.starts_with(".agent") || path.starts_with(".agents") {
        return "agent_context".to_string();
    }

    match path.file_name().and_then(|name| name.to_str()) {
        Some(".gitignore") => return "git".to_string(),
        Some("Cargo.lock") => return "lockfile".to_string(),
        _ => {}
    }

    match path.extension().and_then(|extension| extension.to_str()) {
        Some("rs") => "rust",
        Some("md") => "markdown",
        Some("toml") => "toml",
        Some("json") => "json",
        Some("nix") => "nix",
        Some("yaml" | "yml") => "yaml",
        Some("sh" | "bash") => "shell",
        Some("txt") => "text",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::WorktreeManager;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn scan_returns_stable_sorted_entries_and_categories() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::create_dir_all(repo_path.join("src")).expect("create src");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        fs::write(repo_path.join("Cargo.toml"), "[package]\n").expect("write cargo");
        fs::write(repo_path.join("src/lib.rs"), "pub fn ok() {}\n").expect("write lib");

        let map = scan_repository(&repo_path).expect("scan");
        let paths = map
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            paths,
            vec![
                PathBuf::from("Cargo.toml"),
                PathBuf::from("README.md"),
                PathBuf::from("src"),
                PathBuf::from("src/lib.rs")
            ]
        );
        assert_eq!(map.entries[0].category, "toml");
        assert_eq!(map.entries[2].git_status, RepoGitStatus::Directory);
        assert_eq!(map.entries[3].category, "rust");
        assert_eq!(map.entries[3].git_status, RepoGitStatus::Untracked);
        assert_eq!(map.entries[3].size_bytes, Some(15));
    }

    #[test]
    fn explicit_file_sampling_is_language_agnostic_and_does_not_create_state() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::create_dir_all(repo_path.join("assets")).expect("create assets");
        fs::write(repo_path.join("README.md"), b"one\ntwo\n").expect("write text");
        fs::write(repo_path.join("assets/blob.bin"), b"\0one\n\0two").expect("write binary");

        let samples = scan_repository_file_samples(&repo_path).expect("sample files");

        assert_eq!(
            samples
                .iter()
                .map(|sample| sample.path.clone())
                .collect::<Vec<_>>(),
            vec![PathBuf::from("README.md"), PathBuf::from("assets/blob.bin")]
        );
        assert_eq!(samples[0].bytes, 8);
        assert_eq!(samples[0].lines, 2);
        assert_eq!(samples[1].bytes, 9);
        assert_eq!(samples[1].lines, 2);
        assert!(!repo_path.join(".git/maco/state").exists());
    }

    #[test]
    fn scan_excludes_generated_and_local_state_paths() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::create_dir_all(repo_path.join(".agent/docs")).expect("create agent docs");
        fs::create_dir_all(repo_path.join(".agent/temp")).expect("create agent temp");
        fs::create_dir_all(repo_path.join(".agent/storage")).expect("create agent storage");
        fs::create_dir_all(repo_path.join(".agents/docs")).expect("create agents docs");
        fs::create_dir_all(repo_path.join(".agents/temp")).expect("create agents temp");
        fs::create_dir_all(repo_path.join(".agents/storage")).expect("create agents storage");
        fs::create_dir_all(repo_path.join(".agents/live/claims")).expect("create live claims");
        fs::create_dir_all(repo_path.join(".maco/state")).expect("create state");
        fs::create_dir_all(repo_path.join("target/debug")).expect("create target");
        fs::write(repo_path.join(".agent/docs/rules.md"), "# Rules\n").expect("write rules");
        fs::write(repo_path.join(".agent/temp/scratch"), "tmp\n").expect("write temp");
        fs::write(repo_path.join(".agent/storage/cache"), "cache\n").expect("write cache");
        fs::write(repo_path.join(".agents/docs/rules.md"), "# Rules\n")
            .expect("write agents rules");
        fs::write(repo_path.join(".agents/temp/scratch"), "tmp\n").expect("write agents temp");
        fs::write(repo_path.join(".agents/storage/cache"), "cache\n").expect("write agents cache");
        fs::write(repo_path.join(".agents/live/claims/worker.md"), "# Claim\n")
            .expect("write live claim");
        fs::write(repo_path.join(".maco/state/claims.json"), "{}\n").expect("write state");
        fs::write(repo_path.join("target/debug/output"), "generated\n").expect("write target");
        fs::create_dir_all(repo_path.join(".maco-cache/objects")).expect("create cache");
        fs::create_dir_all(repo_path.join(".codex/tmp")).expect("create codex");
        fs::write(repo_path.join(".maco-cache/objects/blob"), "cache\n").expect("write cache blob");
        fs::write(repo_path.join(".codex/tmp/session.rs"), "fn skip() {}\n").expect("write codex");

        let map = scan_repository(&repo_path).expect("scan");
        let paths = map
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();

        assert!(paths.contains(&PathBuf::from(".agent")));
        assert!(paths.contains(&PathBuf::from(".agent/docs/rules.md")));
        assert!(paths.contains(&PathBuf::from(".agents")));
        assert!(paths.contains(&PathBuf::from(".agents/docs/rules.md")));
        assert!(!paths.iter().any(|path| path.starts_with(".git")));
        assert!(!paths.iter().any(|path| path.starts_with(".maco")));
        assert!(!paths.iter().any(|path| path.starts_with("target")));
        assert!(!paths.iter().any(|path| path.starts_with(".agent/temp")));
        assert!(!paths.iter().any(|path| path.starts_with(".agent/storage")));
        assert!(!paths.iter().any(|path| path.starts_with(".agents/temp")));
        assert!(!paths.iter().any(|path| path.starts_with(".agents/storage")));
        assert!(!paths.iter().any(|path| path.starts_with(".agents/live")));
        assert!(!paths.iter().any(|path| path.starts_with(".maco-cache")));
        assert!(!paths.iter().any(|path| path.starts_with(".codex")));
    }

    #[test]
    fn scan_treats_worktree_stores_as_boundaries_and_ignores_nested_git_markers() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write readme");
        fs::create_dir_all(repo_path.join(".worktrees/lane/src")).expect("create lane");
        fs::write(
            repo_path.join(".worktrees/lane/.git"),
            "gitdir: /tmp/fake-worktree\n",
        )
        .expect("write nested gitfile");
        fs::write(
            repo_path.join(".worktrees/lane/src/lib.rs"),
            "fn skip() {}\n",
        )
        .expect("write lane source");
        fs::create_dir_all(repo_path.join(".worktrees-quarantine-20260811/old"))
            .expect("create quarantine");
        fs::write(
            repo_path.join(".worktrees-quarantine-20260811/old/.git"),
            "gitdir: /tmp/fake-quarantine\n",
        )
        .expect("write quarantine gitfile");

        let map = scan_repository(&repo_path).expect("scan with nested worktree markers");
        let paths = map
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();

        assert!(paths.contains(&PathBuf::from("README.md")));
        assert!(!paths.iter().any(|path| path.starts_with(".worktrees")));
        assert!(!paths
            .iter()
            .any(|path| path.starts_with(".worktrees-quarantine-20260811")));
    }

    #[test]
    fn runtime_control_roots_do_not_treat_maco_as_maco_cache() {
        assert!(is_runtime_control_path(Path::new(".maco")));
        assert!(is_runtime_control_path(Path::new(".maco/state")));
        assert!(is_runtime_control_path(Path::new(".maco-cache")));
        assert!(is_runtime_control_path(Path::new(".maco-cache/objects")));
        assert!(is_runtime_control_path(Path::new(".codex/session.json")));
        assert!(is_runtime_control_path(Path::new(".agents/live/claims")));
        assert!(!is_runtime_control_path(Path::new(".agents/docs")));
        assert!(!is_runtime_control_path(Path::new("src/lib.rs")));
        assert!(!is_ignored_scan_path(Path::new(".agents/docs/rules.md")));
        assert!(is_ignored_scan_path(Path::new(".maco-cache/index")));
        assert!(is_ignored_worktree_store_path(Path::new(".worktrees")));
        assert!(is_ignored_worktree_store_path(Path::new(
            ".worktrees/lane/.git"
        )));
        assert!(is_ignored_worktree_store_path(Path::new(
            ".worktrees-quarantine-20260811/old/.git"
        )));
        assert!(!is_ignored_worktree_store_path(Path::new(
            "src/.worktrees/nested"
        )));
        assert!(!is_ignored_worktree_store_path(Path::new(
            ".worktrees-backup"
        )));
        assert!(is_ignored_scan_path(Path::new(
            ".worktrees/lane/src/lib.rs"
        )));
        assert!(is_ignored_scan_path(Path::new(
            ".worktrees-quarantine-20260811/old/README.md"
        )));
        assert!(!is_runtime_control_path(Path::new(".worktrees/lane")));
    }

    #[cfg(unix)]
    #[test]
    fn scan_reports_but_never_follows_links_or_special_files() {
        skip_without_containment!();
        use std::os::unix::fs::{symlink, FileTypeExt};

        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let outside = temp.path().join("outside");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("secret"), "secret\n").expect("secret");
        symlink(&outside, repo_path.join("outside-link")).expect("outside link");
        let socket_path = repo_path.join("socket");
        let _socket = crate::test_support::bind_test_unix_socket(&socket_path).expect("socket");
        assert!(
            fs::symlink_metadata(&socket_path)
                .expect("socket metadata")
                .file_type()
                .is_socket(),
            "fixture socket must remain a socket entry"
        );

        let map = scan_repository(&repo_path).expect("scan");
        assert!(map.entries.iter().any(|entry| {
            entry.path == Path::new("outside-link") && entry.kind == RepoEntryKind::Symlink
        }));
        assert!(map.entries.iter().any(|entry| {
            entry.path == Path::new("socket") && entry.kind == RepoEntryKind::Other
        }));
        assert!(!map
            .entries
            .iter()
            .any(|entry| entry.path == Path::new("outside-link/secret")));
    }
}
