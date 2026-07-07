use anyhow::{bail, Context, Result};
use git2::{
    Branch, BranchType, ErrorCode, ObjectType, Repository, RepositoryInitOptions, StatusOptions,
    WorktreeAddOptions, WorktreePruneOptions,
};
use serde::Serialize;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

const DEFAULT_BRANCH_PREFIX: &str = "maco";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RepositoryInfo {
    pub path: PathBuf,
    pub git_dir: PathBuf,
    pub head: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorktreeRecord {
    pub name: String,
    pub path: PathBuf,
    pub branch: String,
}

#[derive(Debug, Clone)]
pub struct WorktreeManager {
    repo_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WorktreeCreateOptions {
    pub agent_id: String,
    pub branch: Option<String>,
    pub base: Option<String>,
    pub worktree_root: Option<PathBuf>,
}

impl WorktreeManager {
    pub fn new(repo_path: impl Into<PathBuf>) -> Self {
        Self {
            repo_path: repo_path.into(),
        }
    }

    pub fn init_repository(path: impl AsRef<Path>, initial_branch: &str) -> Result<RepositoryInfo> {
        let path = path.as_ref();
        fs::create_dir_all(path)
            .with_context(|| format!("failed to create repository directory {}", path.display()))?;

        let repo = if path.join(".git").exists() {
            Repository::open(path)
                .with_context(|| format!("failed to open repository {}", path.display()))?
        } else {
            let mut options = RepositoryInitOptions::new();
            options.initial_head(initial_branch);
            Repository::init_opts(path, &options)
                .with_context(|| format!("failed to initialize repository {}", path.display()))?
        };

        repository_info(&repo)
    }

    pub fn create(&self, options: WorktreeCreateOptions) -> Result<WorktreeRecord> {
        let repo = self.open_repository()?;
        let name = normalize_agent_id(&options.agent_id)?;
        let branch_name = options.branch.unwrap_or_else(|| default_branch_name(&name));
        validate_branch_name(&branch_name)?;
        let root = options
            .worktree_root
            .unwrap_or_else(|| default_worktree_root(&repo));
        let worktree_path = root.join(&name);

        if find_worktree(&repo, &name)?.is_some() {
            bail!("worktree '{name}' is already registered");
        }
        ensure_available_path(&worktree_path)?;
        if let Some(parent) = worktree_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create worktree parent directory {}",
                    parent.display()
                )
            })?;
        }

        let commit = resolve_base_commit(&repo, options.base.as_deref())?;
        let branch = ensure_branch(&repo, &branch_name, &commit)?;
        let reference = branch.into_reference();

        let mut add_options = WorktreeAddOptions::new();
        add_options.reference(Some(&reference));

        let worktree = repo
            .worktree(&name, &worktree_path, Some(&add_options))
            .with_context(|| {
                format!(
                    "failed to create worktree '{name}' at {}",
                    worktree_path.display()
                )
            })?;

        Ok(WorktreeRecord {
            name,
            path: worktree.path().to_path_buf(),
            branch: branch_name,
        })
    }

    pub fn remove(
        &self,
        agent_id: &str,
        force: bool,
        delete_branch: bool,
    ) -> Result<WorktreeRecord> {
        let repo = self.open_repository()?;
        let name = normalize_agent_id(agent_id)?;
        let metadata = read_registered_worktree_metadata(&repo, &name)?;
        let worktree = match repo.find_worktree(&name) {
            Ok(worktree) => Some(worktree),
            Err(error) if error.code() == ErrorCode::NotFound => {
                bail!("worktree '{name}' is not registered");
            }
            Err(_) if force && metadata.is_some() => None,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect worktree '{name}'"));
            }
        };
        let path = worktree
            .as_ref()
            .map(|worktree| worktree.path().to_path_buf())
            .or_else(|| metadata.as_ref().map(|metadata| metadata.path.clone()))
            .with_context(|| format!("worktree '{name}' is not registered"))?;
        let branch = read_worktree_branch(&path)
            .or_else(|| {
                metadata
                    .as_ref()
                    .and_then(|metadata| metadata.branch.clone())
            })
            .unwrap_or_else(|| default_branch_name(&name));

        if path.exists() && !force {
            ensure_clean_worktree(&path)?;
        }

        if let Some(worktree) = worktree {
            let mut prune_options = WorktreePruneOptions::new();
            prune_options.valid(true).working_tree(true).locked(force);
            if let Err(error) = worktree.prune(Some(&mut prune_options)) {
                if !force {
                    return Err(error)
                        .with_context(|| format!("failed to prune worktree '{name}'"));
                }
                remove_registered_worktree_fallback(&repo, &name, &path, &error)?;
            }
        } else if force {
            remove_registered_worktree_fallback(
                &repo,
                &name,
                &path,
                &git2::Error::from_str("registered worktree metadata could not be opened"),
            )?;
        }

        if delete_branch {
            delete_local_branch(&repo, &branch)?;
        }

        Ok(WorktreeRecord { name, path, branch })
    }

    pub fn list(&self) -> Result<Vec<WorktreeRecord>> {
        let repo = self.open_repository()?;
        let names = repo.worktrees().context("failed to list worktrees")?;
        let mut records = Vec::new();

        for name in names.iter().flatten() {
            let worktree = repo
                .find_worktree(name)
                .with_context(|| format!("failed to open worktree '{name}'"))?;
            let path = worktree.path().to_path_buf();
            records.push(WorktreeRecord {
                name: name.to_string(),
                branch: read_worktree_branch(&path).unwrap_or_else(|| default_branch_name(name)),
                path,
            });
        }

        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
    }

    fn open_repository(&self) -> Result<Repository> {
        Repository::open(&self.repo_path)
            .with_context(|| format!("failed to open repository {}", self.repo_path.display()))
    }
}

fn repository_info(repo: &Repository) -> Result<RepositoryInfo> {
    let path = repo
        .workdir()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| repo.path().to_path_buf());
    let head = match repo.head() {
        Ok(head) => head.shorthand().map(ToOwned::to_owned),
        Err(error) if error.code() == ErrorCode::UnbornBranch => None,
        Err(error) if error.code() == ErrorCode::NotFound => None,
        Err(error) => return Err(error).context("failed to read repository HEAD"),
    };

    Ok(RepositoryInfo {
        path,
        git_dir: repo.path().to_path_buf(),
        head,
    })
}

pub fn normalize_agent_id(agent_id: &str) -> Result<String> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        bail!("agent id cannot be empty");
    }
    if matches!(trimmed, "." | "..") {
        bail!("agent id cannot be '.' or '..'");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("agent id may only contain ASCII letters, digits, '.', '_' and '-'");
    }

    Ok(trimmed.to_string())
}

fn default_branch_name(name: &str) -> String {
    format!("{DEFAULT_BRANCH_PREFIX}/{name}")
}

fn validate_branch_name(branch_name: &str) -> Result<()> {
    if !Branch::name_is_valid(branch_name).context("failed to validate branch name")? {
        bail!("branch name is not a valid Git branch: {branch_name}");
    }

    Ok(())
}

fn default_worktree_root(repo: &Repository) -> PathBuf {
    let repo_root = repo.workdir().unwrap_or_else(|| repo.path());
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_path_segment)
        .unwrap_or_else(|| "repository".to_string());
    repo_root
        .parent()
        .unwrap_or(repo_root)
        .join(".maco")
        .join("worktrees")
        .join(repo_name)
}

fn read_worktree_branch(path: &Path) -> Option<String> {
    let repo = Repository::open(path).ok()?;
    let head = repo.head().ok()?;
    head.shorthand().map(ToOwned::to_owned)
}

#[derive(Debug, Clone)]
struct RegisteredWorktreeMetadata {
    path: PathBuf,
    branch: Option<String>,
}

fn read_registered_worktree_metadata(
    repo: &Repository,
    name: &str,
) -> Result<Option<RegisteredWorktreeMetadata>> {
    let metadata_dir = worktree_metadata_dir(repo, name);
    if !metadata_dir.exists() {
        return Ok(None);
    }

    let gitdir_file = metadata_dir.join("gitdir");
    let gitdir = fs::read_to_string(&gitdir_file)
        .with_context(|| format!("failed to read worktree gitdir {}", gitdir_file.display()))?;
    let gitdir = gitdir.trim();
    if gitdir.is_empty() {
        bail!("registered worktree '{name}' has empty gitdir metadata");
    }
    let gitdir_path = resolve_metadata_path(&metadata_dir, Path::new(gitdir));
    let path = gitdir_path
        .parent()
        .with_context(|| format!("registered worktree '{name}' gitdir has no parent"))?
        .to_path_buf();
    let branch = read_worktree_metadata_branch(&metadata_dir)?;

    Ok(Some(RegisteredWorktreeMetadata { path, branch }))
}

fn resolve_metadata_path(metadata_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        metadata_dir.join(path)
    }
}

fn read_worktree_metadata_branch(metadata_dir: &Path) -> Result<Option<String>> {
    let head_file = metadata_dir.join("HEAD");
    let head = match fs::read_to_string(&head_file) {
        Ok(head) => head,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read worktree HEAD {}", head_file.display()));
        }
    };
    let Some(reference) = head.trim().strip_prefix("ref: refs/heads/") else {
        return Ok(None);
    };
    if reference.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(reference.trim().to_string()))
}

fn sanitize_path_segment(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn ensure_available_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(path)
        .with_context(|| format!("failed to inspect existing path {}", path.display()))?;
    if entries.next().is_some() {
        bail!(
            "worktree path already exists and is not empty: {}",
            path.display()
        );
    }

    Ok(())
}

fn resolve_base_commit<'repo>(
    repo: &'repo Repository,
    base: Option<&str>,
) -> Result<git2::Commit<'repo>> {
    let object = match base {
        Some(base) => repo
            .revparse_single(base)
            .with_context(|| format!("failed to resolve base revision '{base}'"))?,
        None => repo
            .head()
            .context("repository has no committed HEAD; create an initial commit first")?
            .peel(ObjectType::Commit)
            .context("failed to peel HEAD to a commit")?,
    };

    object
        .peel_to_commit()
        .context("base revision does not resolve to a commit")
}

fn ensure_branch<'repo>(
    repo: &'repo Repository,
    branch_name: &str,
    commit: &git2::Commit<'repo>,
) -> Result<git2::Branch<'repo>> {
    match repo.find_branch(branch_name, BranchType::Local) {
        Ok(branch) => Ok(branch),
        Err(error) if error.code() == ErrorCode::NotFound => repo
            .branch(branch_name, commit, false)
            .with_context(|| format!("failed to create local branch '{branch_name}'")),
        Err(error) => Err(error).with_context(|| format!("failed to open branch '{branch_name}'")),
    }
}

fn find_worktree(repo: &Repository, name: &str) -> Result<Option<git2::Worktree>> {
    match repo.find_worktree(name) {
        Ok(worktree) => Ok(Some(worktree)),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect worktree '{name}'")),
    }
}

fn ensure_clean_worktree(path: &Path) -> Result<()> {
    let repo = Repository::open(path)
        .with_context(|| format!("failed to open worktree repository {}", path.display()))?;
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect worktree status")?;

    if !statuses.is_empty() {
        bail!("worktree is dirty; rerun with --force to remove it anyway");
    }

    Ok(())
}

fn delete_local_branch(repo: &Repository, branch_name: &str) -> Result<()> {
    match repo.find_branch(branch_name, BranchType::Local) {
        Ok(mut branch) => branch
            .delete()
            .with_context(|| format!("failed to delete local branch '{branch_name}'")),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to open branch '{branch_name}'")),
    }
}

fn remove_registered_worktree_fallback(
    repo: &Repository,
    name: &str,
    path: &Path,
    prune_error: &git2::Error,
) -> Result<()> {
    ensure_safe_registered_worktree_path(repo, name, path)?;

    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to remove worktree directory {} after git2 prune failed: {prune_error}",
                    path.display()
                )
            });
        }
    }

    prune_or_remove_worktree_metadata(repo, name)
        .with_context(|| format!("failed to prune worktree metadata for '{name}'"))?;
    Ok(())
}

fn ensure_safe_registered_worktree_path(repo: &Repository, name: &str, path: &Path) -> Result<()> {
    ensure_registered_worktree_name(repo, name)?;

    let primary = repo
        .workdir()
        .with_context(|| "worktree removal requires a repository with a primary worktree")?;
    if path.exists() {
        let worktree_path = fs::canonicalize(path)
            .with_context(|| format!("failed to resolve worktree path {}", path.display()))?;
        let primary_path = fs::canonicalize(primary)
            .with_context(|| format!("failed to resolve primary worktree {}", primary.display()))?;
        if worktree_path == primary_path {
            bail!(
                "refusing to remove registered worktree '{name}' because it resolves to the primary worktree"
            );
        }
    }

    Ok(())
}

fn ensure_registered_worktree_name(repo: &Repository, name: &str) -> Result<()> {
    let is_listed = repo
        .worktrees()
        .with_context(|| "failed to list registered worktrees")?
        .iter()
        .flatten()
        .any(|registered| registered == name);
    if !is_listed && !worktree_metadata_dir(repo, name).is_dir() {
        bail!("worktree '{name}' is not a registered linked worktree of this repo");
    }

    Ok(())
}

fn prune_or_remove_worktree_metadata(repo: &Repository, name: &str) -> Result<()> {
    match repo.find_worktree(name) {
        Ok(worktree) => {
            let mut prune_options = WorktreePruneOptions::new();
            prune_options.locked(true);
            if worktree.prune(Some(&mut prune_options)).is_ok() {
                return Ok(());
            }
        }
        Err(error) if error.code() == ErrorCode::NotFound => return Ok(()),
        Err(_) => {}
    }

    let metadata_dir = worktree_metadata_dir(repo, name);
    match fs::remove_dir_all(&metadata_dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to remove worktree metadata directory {}",
                metadata_dir.display()
            )
        }),
    }
}

fn worktree_metadata_dir(repo: &Repository, name: &str) -> PathBuf {
    repo.commondir().join("worktrees").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Oid, Signature};
    use tempfile::TempDir;

    #[test]
    fn initializes_repository_with_requested_initial_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");

        let info = WorktreeManager::init_repository(&repo_path, "main").expect("init repo");

        assert_eq!(info.path, repo_path);
        assert_eq!(info.head, None);
        assert!(info.git_dir.ends_with(".git"));
    }

    #[test]
    fn creates_lists_and_removes_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        assert_eq!(created.name, "agent-a");
        assert_eq!(created.branch, "maco/agent-a");
        assert!(created.path.join("README.md").exists());

        let listed = manager.list().expect("list worktrees");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "agent-a");

        let removed = manager
            .remove("agent-a", false, true)
            .expect("remove worktree");
        assert_eq!(removed.name, "agent-a");
        assert!(!removed.path.exists());
        assert!(repo.find_branch("maco/agent-a", BranchType::Local).is_err());
    }

    #[test]
    fn rejects_unsafe_agent_id() {
        let error = normalize_agent_id("../agent").expect_err("unsafe id should fail");
        assert!(error.to_string().contains("ASCII letters"));
    }

    #[test]
    fn rejects_path_segment_agent_id() {
        let dot_error = normalize_agent_id(".").expect_err("dot id should fail");
        assert!(dot_error.to_string().contains("cannot be"));

        let parent_error = normalize_agent_id("..").expect_err("parent id should fail");
        assert!(parent_error.to_string().contains("cannot be"));
    }

    #[test]
    fn rejects_invalid_custom_branch_name() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let error = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-invalid".to_string(),
                branch: Some("bad branch".to_string()),
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect_err("invalid branch should fail");

        assert!(error.to_string().contains("valid Git branch"));
        assert!(!worktree_root.join("agent-invalid").exists());
    }

    #[test]
    fn remove_refuses_dirty_worktree_without_force() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-dirty".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::write(created.path.join("scratch.txt"), "local edits\n").expect("write scratch");

        let error = manager
            .remove("agent-dirty", false, true)
            .expect_err("dirty worktree should require force");

        assert!(error.to_string().contains("worktree is dirty"));
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-dirty", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn force_removes_dirty_worktree_and_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-force".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::write(created.path.join("scratch.txt"), "local edits\n").expect("write scratch");

        let removed = manager
            .remove("agent-force", true, true)
            .expect("force remove worktree");

        assert_eq!(removed.name, "agent-force");
        assert!(!removed.path.exists());
        assert!(repo
            .find_branch("maco/agent-force", BranchType::Local)
            .is_err());
    }

    #[test]
    fn force_removes_worktree_with_untracked_nested_directory() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-residue".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let residue = created.path.join("target/debug/deps");
        fs::create_dir_all(&residue).expect("create residue directory");
        fs::write(residue.join("artifact.d"), "ignored build output\n").expect("write residue");

        let removed = manager
            .remove("agent-residue", true, true)
            .expect("force remove worktree with residue");

        assert_eq!(removed.name, "agent-residue");
        assert!(!removed.path.exists());
        assert!(repo
            .find_branch("maco/agent-residue", BranchType::Local)
            .is_err());
    }

    #[test]
    fn repeated_force_remove_reports_clean_not_registered_error() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-repeat".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::create_dir_all(created.path.join("target/debug/deps"))
            .expect("create residue directory");
        fs::remove_file(created.path.join(".git")).expect("remove worktree git file");

        manager
            .remove("agent-repeat", true, true)
            .expect("force remove partially deleted worktree");
        let error = manager
            .remove("agent-repeat", true, true)
            .expect_err("second remove should report not registered");
        let message = error.to_string();

        assert!(message.contains("worktree 'agent-repeat' is not registered"));
        assert!(!message.contains("shallow"));
    }

    #[test]
    fn remove_reports_custom_worktree_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: Some("topic/agent-b".to_string()),
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let removed = manager
            .remove("agent-b", false, true)
            .expect("remove worktree");

        assert_eq!(removed.branch, "topic/agent-b");
        assert!(repo
            .find_branch("topic/agent-b", BranchType::Local)
            .is_err());
    }

    fn commit_readme(repo: &Repository) -> Result<Oid> {
        let workdir = repo.workdir().context("test repo must have workdir")?;
        fs::write(workdir.join("README.md"), "# Test\n").context("write README")?;

        let mut index = repo.index().context("open index")?;
        index
            .add_path(Path::new("README.md"))
            .context("add README")?;
        index.write().context("write index")?;
        let tree_id = index.write_tree().context("write tree")?;
        let tree = repo.find_tree(tree_id).context("find tree")?;
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "initial commit",
            &tree,
            &[],
        )
        .context("commit")
    }
}
