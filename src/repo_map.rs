use anyhow::{Context, Result};
use git2::{Repository, Status};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crate::safe_state::{
    BoundedTreeEntry, BoundedTreeEntryKind, BoundedTreeWalkAction, BoundedTreeWalkLimits,
    BoundedTreeWalker,
};

const REPOSITORY_MAP_MAX_DEPTH: usize = 128;
const REPOSITORY_MAP_MAX_ENTRIES: usize = 100_000;
const REPOSITORY_MAP_MAX_PATH_BYTES: usize = 4096;
const REPOSITORY_MAP_MAX_TOTAL_PATH_BYTES: usize = 64 * 1024 * 1024;
const REPOSITORY_MAP_MAX_DURATION: Duration = Duration::from_secs(10);

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
    let repo = Repository::discover(repo_path.as_ref()).with_context(|| {
        format!(
            "failed to discover repository from {}",
            repo_path.as_ref().display()
        )
    })?;
    let root = repo
        .workdir()
        .context("repository map requires a non-bare repository")?
        .to_path_buf();

    let inventory = BoundedTreeWalker::walk_with(
        &root,
        BoundedTreeWalkLimits {
            max_depth: REPOSITORY_MAP_MAX_DEPTH,
            max_entries: REPOSITORY_MAP_MAX_ENTRIES,
            max_path_bytes: REPOSITORY_MAP_MAX_PATH_BYTES,
            max_total_path_bytes: REPOSITORY_MAP_MAX_TOTAL_PATH_BYTES,
            max_duration: REPOSITORY_MAP_MAX_DURATION,
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
    let deadline = Instant::now()
        .checked_add(REPOSITORY_MAP_MAX_DURATION)
        .context("repository status deadline overflowed")?;
    let entries = inventory
        .into_iter()
        .map(|entry| map_inventory_entry(&repo, entry, deadline))
        .collect::<Result<Vec<_>>>()?;

    Ok(RepoMap { root, entries })
}

fn map_inventory_entry(
    repo: &Repository,
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
        RepoEntryKind::File | RepoEntryKind::Symlink => {
            classify_git_status(repo.status_file(&entry.relative_path).with_context(|| {
                format!(
                    "failed to inspect Git status for {}",
                    entry.relative_path.display()
                )
            })?)
        }
    };
    Ok(RepoMapEntry {
        path: entry.relative_path.clone(),
        kind,
        size_bytes: size_bytes(&entry, kind),
        category: category_for(&entry.relative_path, kind),
        git_status,
    })
}

fn classify_git_status(status: Status) -> RepoGitStatus {
    if status.is_conflicted() {
        RepoGitStatus::Conflicted
    } else if status.intersects(Status::WT_NEW) {
        RepoGitStatus::Untracked
    } else if status.intersects(Status::INDEX_NEW) {
        RepoGitStatus::Added
    } else if status.intersects(Status::WT_DELETED | Status::INDEX_DELETED) {
        RepoGitStatus::Deleted
    } else if status.intersects(Status::WT_RENAMED | Status::INDEX_RENAMED) {
        RepoGitStatus::Renamed
    } else if status.intersects(
        Status::WT_MODIFIED
            | Status::INDEX_MODIFIED
            | Status::WT_TYPECHANGE
            | Status::INDEX_TYPECHANGE,
    ) {
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

fn is_ignored_path(path: &Path) -> bool {
    path == Path::new(".git")
        || path.starts_with(".git")
        || path == Path::new(".maco")
        || path.starts_with(".maco")
        || path == Path::new("target")
        || path.starts_with("target")
        || path == Path::new(".agent/temp")
        || path.starts_with(".agent/temp")
        || path == Path::new(".agent/storage")
        || path.starts_with(".agent/storage")
        || path == Path::new(".agents/temp")
        || path.starts_with(".agents/temp")
        || path == Path::new(".agents/storage")
        || path.starts_with(".agents/storage")
        || path == Path::new(".agents/live")
        || path.starts_with(".agents/live")
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
    fn scan_excludes_generated_and_local_state_paths() {
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
    }

    #[cfg(unix)]
    #[test]
    fn scan_reports_but_never_follows_links_or_special_files() {
        use std::os::unix::{fs::symlink, net::UnixListener};

        let temp = tempfile::tempdir().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let outside = temp.path().join("outside");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("secret"), "secret\n").expect("secret");
        symlink(&outside, repo_path.join("outside-link")).expect("outside link");
        let _socket = UnixListener::bind(repo_path.join("socket")).expect("socket");

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
