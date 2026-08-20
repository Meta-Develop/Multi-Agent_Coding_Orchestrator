    #[test]
    fn startup_reconciliation_prunes_only_exact_authenticated_missing_path_registration() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "registered-missing", &root);
        fs::remove_dir_all(&lane.path).expect("remove registered path");

        let report = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                startup_reconcile: true,
                destructive_reconciliation: true,
                worktree_root: Some(root),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("exact stale registration reconciliation");
        assert_eq!(report.reconciliation.pruned_registration_count, 1);
        assert_eq!(report.reconciliation.forgotten_record_count, 1);
        assert_eq!(
            report.reconciliation.entries[0].action,
            WorktreeReconciliationAction::PrunedRegistrationAndForgotRecord
        );
        assert!(repo.find_worktree(&lane.name).is_err());
        assert!(repo.find_branch(&lane.branch, BranchType::Local).is_ok());
    }

    #[test]
    fn startup_reconciliation_active_claim_preserves_registered_missing_path_state() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "claimed-missing-path", &root);
        SyncStore::open(&repo_path)
            .expect("claims")
            .claim_paths(&lane.name, ["src"])
            .expect("claim lane");
        fs::remove_dir_all(&lane.path).expect("remove registered path");

        let report = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                startup_reconcile: true,
                destructive_reconciliation: true,
                worktree_root: Some(root),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("claimed missing-path reconciliation");
        let entry = report
            .reconciliation
            .entries
            .iter()
            .find(|entry| entry.name == lane.name)
            .expect("claimed missing-path entry");
        assert_eq!(
            entry.state,
            WorktreeReconciliationState::RegisteredMissingPath
        );
        assert_eq!(entry.action, WorktreeReconciliationAction::Protected);
        assert!(entry.detail.contains("active durable claim"));
        assert!(repo.find_worktree(&lane.name).is_ok());
    }

    #[test]
    fn post_reap_prune_preserves_unrelated_stale_registration() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let selected = create_gc_worktree(&manager, "selected-stale", &root);
        let unrelated = create_gc_worktree(&manager, "unrelated-stale", &root);
        fs::remove_dir_all(&selected.path).expect("remove selected path");
        fs::remove_dir_all(&unrelated.path).expect("remove unrelated path");

        let report = prune_stale_worktree_registrations(
            &repo,
            &BTreeSet::from([selected.name.clone()]),
            true,
        )
        .expect("scoped prune");
        assert_eq!(report.stale_registration_count, 2);
        assert_eq!(report.pruned_registration_count, 1);
        assert_eq!(report.protected_registration_count, 1);
        assert!(repo.find_worktree(&selected.name).is_err());
        assert!(repo.find_worktree(&unrelated.name).is_ok());
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

    fn commit_descendant(repo: &Repository, path: &str, contents: &str) -> Result<Oid> {
        let workdir = repo.workdir().context("test repo must have workdir")?;
        fs::write(workdir.join(path), contents).context("write descendant contents")?;
        let mut index = repo.index().context("open index")?;
        index.add_path(Path::new(path)).context("add path")?;
        index.write().context("write index")?;
        let tree_id = index.write_tree().context("write tree")?;
        let tree = repo.find_tree(tree_id).context("find tree")?;
        let parent = repo
            .head()
            .context("find parent HEAD")?
            .peel_to_commit()
            .context("peel parent commit")?;
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "descendant commit",
            &tree,
            &[&parent],
        )
        .context("commit descendant")
    }
