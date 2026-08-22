//! Capability-bound repository cleanliness input for effectful execution (#117).
//!
//! Managed worktree creation already requires
//! [`RepositoryCleanlinessCapability`]. This module is the typed surface
//! other execution entrypoints (orchestration, agent run, autopilot,
//! supervise, inbox) should acquire before creating worktrees, instead of
//! short-circuiting with "temporarily unsupported".
//!
//! Holding the token is not a permanent cleanliness assertion: every
//! effectful create revalidates the repository association and status.

use anyhow::Result;

use crate::worktree::{
    RepositoryCleanlinessCapability, WorktreeCreateOptions, WorktreeManager, WorktreeRecord,
};

/// Opaque proof that a specific managed repository was bound and observed
/// clean through the bounded status boundary.
#[derive(Debug)]
pub struct EffectfulExecutionCapability {
    cleanliness: RepositoryCleanlinessCapability,
}

impl EffectfulExecutionCapability {
    /// Capture cleanliness evidence for `manager`'s repository.
    ///
    /// Fails closed when the repository is missing, dirty, or cannot be
    /// rebound. Callers must keep this value for the duration of the
    /// effectful create they intend to perform.
    pub fn acquire(manager: &WorktreeManager) -> Result<Self> {
        Ok(Self {
            cleanliness: manager.acquire_repository_cleanliness()?,
        })
    }

    pub(crate) fn cleanliness(&self) -> &RepositoryCleanlinessCapability {
        &self.cleanliness
    }

    /// Create a managed worktree using this capability as the cleanliness
    /// input. Public `WorktreeManager::create` now derives the same
    /// cleanliness evidence when the target repository is already clean;
    /// this remains the explicit capability-bearing path.
    pub fn create_managed_worktree(
        &self,
        manager: &WorktreeManager,
        options: WorktreeCreateOptions,
    ) -> Result<WorktreeRecord> {
        manager.create_with_repository_cleanliness(options, self.cleanliness())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result};
    use git2::{Repository, Signature};
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn commit_readme(repo: &Repository) -> Result<git2::Oid> {
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

    fn clean_repo(temp: &TempDir) -> Result<(std::path::PathBuf, WorktreeManager)> {
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main")?;
        let repo = crate::git_repository::open(&repo_path)?;
        commit_readme(&repo)?;
        Ok((repo_path.clone(), WorktreeManager::new(&repo_path)))
    }

    #[test]
    fn acquire_fails_closed_when_the_repository_does_not_exist() {
        let temp = TempDir::new().expect("tempdir");
        let manager = WorktreeManager::new(temp.path().join("missing"));
        let error = EffectfulExecutionCapability::acquire(&manager)
            .expect_err("missing repository must fail closed");
        let message = format!("{error:#}");
        assert!(
            message.contains("failed to open")
                || message.contains("not a git repository")
                || message.contains("No such file"),
            "unexpected acquire error: {message}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn acquire_fails_closed_when_the_primary_repository_is_dirty() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let (repo_path, manager) = clean_repo(&temp).expect("clean repo");
        fs::write(repo_path.join("README.md"), "dirty\n").expect("dirty");
        let error = EffectfulExecutionCapability::acquire(&manager)
            .expect_err("dirty repository must fail closed");
        assert!(
            error.to_string().contains("dirty"),
            "unexpected dirty error: {error:#}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_bound_create_succeeds_on_a_clean_repository() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let (_, manager) = clean_repo(&temp).expect("clean repo");
        let capability =
            EffectfulExecutionCapability::acquire(&manager).expect("acquire cleanliness");
        let record = capability
            .create_managed_worktree(
                &manager,
                WorktreeCreateOptions {
                    agent_id: "capability-surface".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(temp.path().join("worktrees")),
                },
            )
            .expect("create via capability");
        assert_eq!(record.name, "capability-surface");
        assert!(record.path.join("README.md").is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn public_create_without_the_capability_still_fails_closed() {
        skip_without_containment!();
        let dirty = TempDir::new().expect("tempdir");
        let (dirty_repo, dirty_manager) = clean_repo(&dirty).expect("clean repo");
        fs::write(dirty_repo.join("README.md"), "dirty\n").expect("dirty");
        let error = dirty_manager
            .create(WorktreeCreateOptions {
                agent_id: "must-not-exist".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(dirty.path().join("worktrees")),
            })
            .expect_err("public create remains fail-closed when cleanliness cannot be derived");
        let message = error.to_string();
        assert!(
            message.contains("dirty") || message.contains("clean"),
            "unexpected public create error: {error:#}"
        );
        assert!(!dirty.path().join("worktrees").exists());

        // The worktree lane now derives cleanliness for public create on an
        // already-clean repository. That is the intended combined contract;
        // a pre-acquired capability token is no longer required for create.
        let clean = TempDir::new().expect("tempdir");
        let (_, clean_manager) = clean_repo(&clean).expect("clean repo");
        let record = clean_manager
            .create(WorktreeCreateOptions {
                agent_id: "must-not-exist".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(clean.path().join("worktrees")),
            })
            .expect("public create derives cleanliness from a clean repository");
        assert_eq!(record.name, "must-not-exist");
        assert!(record.path.join("README.md").is_file());
    }
}
