use anyhow::{Context, Result};
use git2::{Repository, Status};
use serde::Serialize;
use std::collections::BTreeMap;
use std::{
    fs,
    path::{Path, PathBuf},
};

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

    let git_statuses = collect_git_statuses(&repo)?;
    let mut entries = Vec::new();
    walk_directory(&root, &root, &git_statuses, &mut entries)?;

    Ok(RepoMap { root, entries })
}

fn walk_directory(
    root: &Path,
    directory: &Path,
    git_statuses: &BTreeMap<PathBuf, RepoGitStatus>,
    entries: &mut Vec<RepoMapEntry>,
) -> Result<()> {
    let mut children = fs::read_dir(directory)
        .with_context(|| format!("failed to read directory {}", directory.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("failed to read directory entry in {}", directory.display()))?;

    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("failed to relativize {}", path.display()))?
            .to_path_buf();

        if is_ignored_path(&relative) {
            continue;
        }

        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        let kind = entry_kind(&metadata);
        entries.push(RepoMapEntry {
            path: relative.clone(),
            kind,
            size_bytes: size_bytes(&metadata, kind),
            category: category_for(&relative, kind),
            git_status: git_status_for(&relative, kind, git_statuses),
        });

        if kind == RepoEntryKind::Directory {
            walk_directory(root, &path, git_statuses, entries)?;
        }
    }

    Ok(())
}

fn collect_git_statuses(repo: &Repository) -> Result<BTreeMap<PathBuf, RepoGitStatus>> {
    let mut options = git2::StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect repository git status")?;
    let mut by_path = BTreeMap::new();

    for entry in statuses.iter() {
        let path = entry.path().context("git status path is not valid UTF-8")?;
        by_path.insert(PathBuf::from(path), classify_git_status(entry.status()));
    }

    Ok(by_path)
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

fn git_status_for(
    path: &Path,
    kind: RepoEntryKind,
    git_statuses: &BTreeMap<PathBuf, RepoGitStatus>,
) -> RepoGitStatus {
    if kind == RepoEntryKind::Directory {
        return RepoGitStatus::Directory;
    }

    git_statuses
        .get(path)
        .copied()
        .unwrap_or(RepoGitStatus::Clean)
}

fn entry_kind(metadata: &fs::Metadata) -> RepoEntryKind {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        RepoEntryKind::Directory
    } else if file_type.is_file() {
        RepoEntryKind::File
    } else if file_type.is_symlink() {
        RepoEntryKind::Symlink
    } else {
        RepoEntryKind::Other
    }
}

fn size_bytes(metadata: &fs::Metadata, kind: RepoEntryKind) -> Option<u64> {
    match kind {
        RepoEntryKind::File | RepoEntryKind::Symlink => Some(metadata.len()),
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
}
