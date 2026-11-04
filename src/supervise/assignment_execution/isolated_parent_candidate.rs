//! Supervisor-only tentative view. No child commit or acceptance is created here.
use super::*;

pub(super) struct IsolatedParentCandidate {
    pub tree: Oid,
    pub paths: Vec<PathBuf>,
    pub workers: Vec<crate::merge::ExactBaseWorktreeSnapshot>,
    pub snapshot: PrimaryWorktreeSnapshot,
}

impl IsolatedParentCandidate {
    pub(super) fn materialize(
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        workers: &[bound_parent_turn::IsolatedWorkerAttemptEvidence],
    ) -> Result<Self> {
        let parent = crate::git_repository::open(&preflight.worktree.path)?;
        let base = parent.find_commit(preflight.child_base_head)?.tree()?;
        let mut tree = base.id();
        let mut candidates = Vec::new();
        let mut paths = BTreeSet::new();
        for worker in workers {
            let captured = crate::merge::capture_exact_base_worktree_with_write_lease(
                context.repo,
                &worker.report().id,
                &worker.report().assigned_paths,
                worker.lease(),
                preflight.child_base_head,
            )?;
            if captured.changed_paths != worker.report().files_changed
                || captured
                    .changed_paths
                    .iter()
                    .any(|path| !paths.insert(path.clone()))
            {
                bail!("isolated candidate paths differ from reports or overlap");
            }
            // Rebuild in the parent's object database without importing a child
            // commit. Content-addressed trees bind the exact patch to its capture.
            let patch = git2::Diff::from_buffer(&captured.raw_diff)?;
            let mut index = parent.apply_to_tree(&base, &patch, None)?;
            let child_tree = index.write_tree_to(&parent)?;
            if child_tree != captured.snapshot_tree {
                bail!("isolated candidate patch differs from its captured tree");
            }
            let aggregate = parent.find_tree(tree)?;
            let child = parent.find_tree(child_tree)?;
            let mut merged = parent.merge_trees(&base, &aggregate, &child, None)?;
            if merged.has_conflicts() {
                bail!("isolated scoped candidate integration has conflicts");
            }
            tree = merged.write_tree_to(&parent)?;
            candidates.push(captured);
        }
        context.manager.verify_write_execution_lease(
            &preflight.assignment.id,
            preflight
                .worktree_write_lease
                .as_ref()
                .context("isolated parent lease missing")?,
        )?;
        let aggregate = parent.find_tree(tree)?;
        if context.cancellation.is_cancelled()
            || !context.sync_store.snapshot()?.contains(&preflight.claim)
        {
            bail!("isolated tentative materialization lost its held parent union claim");
        }
        // Only supervisor code writes the tentative view. HEAD/index stay at base;
        // the external final turn still receives the normal read-only admission.
        apply_candidate_delta(&parent, &base, &aggregate)?;
        let snapshot =
            primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?;
        if snapshot.inspection_problem().is_some() {
            bail!("isolated tentative parent snapshot is incomplete");
        }
        let captured = crate::merge::capture_exact_base_worktree_with_write_lease(
            context.repo,
            &preflight.assignment.id,
            &preflight.assignment.assigned_paths,
            preflight
                .worktree_write_lease
                .as_ref()
                .context("isolated parent lease missing")?,
            preflight.child_base_head,
        )?;
        if captured.snapshot_tree != tree
            || captured.changed_paths != paths.iter().cloned().collect::<Vec<_>>()
        {
            bail!("isolated tentative checkout differs from its ordered candidate trees");
        }
        Ok(Self {
            tree,
            paths: paths.into_iter().collect(),
            workers: candidates,
            snapshot,
        })
    }

    pub(super) fn discard(
        &self,
        context: &AssignmentExecutionContext<'_, '_>,
        preflight: &AssignmentExecutionPreflight<'_>,
        original: &PrimaryWorktreeSnapshot,
    ) -> Result<()> {
        if !context.sync_store.snapshot()?.contains(&preflight.claim)
            || primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?
                != self.snapshot
        {
            bail!("isolated tentative candidate drifted; refusing rollback");
        }
        context.manager.verify_write_execution_lease(
            &preflight.assignment.id,
            preflight
                .worktree_write_lease
                .as_ref()
                .context("isolated parent lease missing")?,
        )?;
        let parent = crate::git_repository::open(&preflight.worktree.path)?;
        let aggregate = parent.find_tree(self.tree)?;
        let base = parent.find_commit(preflight.child_base_head)?.tree()?;
        apply_candidate_delta(&parent, &aggregate, &base)?;
        if primary_worktree_snapshot(&preflight.worktree.path, context.execution_runtime)?
            != *original
        {
            bail!("isolated tentative candidate rollback differs from its held base");
        }
        Ok(())
    }
}

fn apply_candidate_delta(
    repo: &git2::Repository,
    from: &git2::Tree<'_>,
    to: &git2::Tree<'_>,
) -> Result<()> {
    let mut options = git2::DiffOptions::new();
    options.show_binary(true);
    let diff = repo.diff_tree_to_tree(Some(from), Some(to), Some(&mut options))?;
    repo.apply(&diff, git2::ApplyLocation::WorkDir, None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tentative_binary_candidate_round_trip_preserves_index() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = git2::Repository::init(temp.path())?;
        let before = b"before\0binary\xff";
        let after = b"after\0binary\xfe";
        let mut builder = repo.treebuilder(None)?;
        builder.insert("data.bin", repo.blob(before)?, 0o100644)?;
        let base = repo.find_tree(builder.write()?)?;
        builder.insert("data.bin", repo.blob(after)?, 0o100644)?;
        let candidate = repo.find_tree(builder.write()?)?;
        let mut index = repo.index()?;
        index.read_tree(&base)?;
        index.write()?;
        fs::write(temp.path().join("data.bin"), before)?;
        let index_before = fs::read(repo.path().join("index"))?;
        apply_candidate_delta(&repo, &base, &candidate)?;
        assert_eq!(fs::read(temp.path().join("data.bin"))?, after);
        apply_candidate_delta(&repo, &candidate, &base)?;
        assert_eq!(fs::read(temp.path().join("data.bin"))?, before);
        assert_eq!(fs::read(repo.path().join("index"))?, index_before);
        Ok(())
    }
}
