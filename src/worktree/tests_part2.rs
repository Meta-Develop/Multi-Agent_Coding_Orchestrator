    #[cfg(target_os = "linux")]
    #[test]
    fn different_mount_namespace_process_path_uses_rooted_identity_ancestry() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let lane = temp.path().join("lane");
        fs::create_dir_all(lane.join("target/debug")).expect("target");
        let process_root = temp.path().join("proc-entry");
        fs::create_dir(&process_root).expect("process root");
        symlink("/", process_root.join("root")).expect("root link");
        let target = gc_target_if_present(&lane)
            .expect("bind target")
            .expect("target exists");
        let view = LinuxProcessView::for_test(&process_root, false);
        let resolved = view
            .resolve_configured_path(&lane.join("target/debug"))
            .expect("rooted process path");
        assert!(resolved.observer_canonical_path.is_none());
        assert_eq!(
            process_path_overlaps_target(&resolved, &target),
            WorktreePathOverlap::Overlap
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn first_managed_worktree_from_fresh_clone_preserves_repository_binding() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let origin_path = temp.path().join("origin");
        WorktreeManager::init_repository(&origin_path, "main").expect("init origin");
        let origin = crate::git_repository::open(&origin_path).expect("open origin");
        commit_readme(&origin).expect("initial commit");
        drop(origin);

        let clone_path = temp.path().join("fresh-clone");
        let cloned = git2::Repository::clone(
            origin_path.to_str().expect("UTF-8 origin path"),
            &clone_path,
        )
        .expect("clone repository");
        assert!(
            !cloned.commondir().join("worktrees").exists(),
            "fresh clone must exercise creation of the worktrees metadata directory"
        );
        drop(cloned);

        let manager = WorktreeManager::new(&clone_path);
        let cleanliness = manager
            .acquire_repository_cleanliness()
            .expect("bind clean fresh clone");
        assert!(
            !clone_path.join(".git/worktrees").exists(),
            "cleanliness capture must not pre-create worktree metadata"
        );
        let record = manager
            .create_with_repository_cleanliness(
                WorktreeCreateOptions {
                    agent_id: "first-bound".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(temp.path().join("worktrees")),
                },
                &cleanliness,
            )
            .expect("create first capability-bound managed worktree");

        assert!(record.path.is_dir());
        assert!(clone_path.join(".git/worktrees/first-bound").is_dir());
        assert_eq!(
            manager.list_managed_verified().expect("list managed lanes"),
            vec![record]
        );
    }

    #[test]
    fn target_only_mode_rejects_conflicting_gc_policies() {
        let retention = WorktreeRetentionPolicy {
            max_age: None,
            max_count: Some(1),
            max_total_bytes: None,
        };
        assert!(validate_worktree_gc_mode(true, true, retention, &[], false)
            .expect_err("retention conflict")
            .to_string()
            .contains("retention filters"));
        assert!(validate_worktree_gc_mode(
            true,
            true,
            WorktreeRetentionPolicy {
                max_age: None,
                max_count: None,
                max_total_bytes: Some(1),
            },
            &[],
            false,
        )
        .expect_err("size retention conflict")
        .to_string()
        .contains("retention filters"));
        assert!(validate_worktree_gc_mode(
            true,
            true,
            WorktreeRetentionPolicy::default(),
            &[PathBuf::from("TASK.md")],
            false,
        )
        .expect_err("allowlist conflict")
        .to_string()
        .contains("untracked-path allowances"));
        assert!(validate_worktree_gc_mode(
            true,
            false,
            WorktreeRetentionPolicy::default(),
            &[],
            false,
        )
        .expect_err("keep target conflict")
        .to_string()
        .contains("keeping target"));
        assert!(validate_worktree_gc_mode(
            true,
            true,
            WorktreeRetentionPolicy::default(),
            &[],
            true,
        )
        .expect_err("machine-global conflict")
        .to_string()
        .contains("machine-global"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unreadable_process_liveness_protects_even_without_prior_build_association() {
        let WorktreeTargetLiveness::Unknown(evidence) = bounded_association_failure(42) else {
            panic!("unreadable process association must be unknown");
        };
        assert_eq!(evidence.pid, Some(42));
        assert_eq!(
            evidence.source,
            WorktreeTargetLivenessSource::ProcessFileDescriptor
        );
        assert_eq!(evidence.cause, WorktreeTargetLivenessCause::ReadFailed);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_retention_applies_after_new_worktree_creation() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let old = create_gc_worktree(&manager, "agent-create-old", &worktree_root);

        let new = manager
            .create_for_test_with_retention(
                WorktreeCreateOptions {
                    agent_id: "agent-create-new".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                },
                WorktreeRetentionPolicy {
                    max_age: None,
                    max_count: Some(1),
                    max_total_bytes: None,
                },
            )
            .expect("create with retention");

        assert!(!old.path.exists());
        assert!(new.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_size_retention_reserves_the_new_lane_before_reclaiming_older_lanes() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let old = create_gc_worktree(&manager, "size-create-old", &worktree_root);
        fs::create_dir(old.path.join(".maco")).expect("old runtime directory");
        fs::write(old.path.join(".maco/cache"), vec![b'o'; 1024]).expect("old runtime artifact");

        let new = manager
            .create_for_test_with_retention(
                WorktreeCreateOptions {
                    agent_id: "size-create-new".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                },
                WorktreeRetentionPolicy {
                    max_age: None,
                    max_count: None,
                    max_total_bytes: Some(0),
                },
            )
            .expect("create with size retention");

        assert!(!old.path.exists());
        assert!(
            new.path.exists(),
            "the just-created lane is always reserved"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_prunes_unregistered_leftover_directory_second_pass() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let orphan = worktree_root.join("agent-orphan-gc");
        fs::create_dir_all(orphan.join("target/debug")).expect("orphan directory");
        fs::write(orphan.join("leftover.txt"), "partial delete residue\n").expect("orphan file");
        let manager = WorktreeManager::new(&repo_path);
        let mut options = gc_options(Some(worktree_root.clone()), false);
        options.machine_global_retention = Some(machine_global_gc_binding(
            temp.path(),
            &worktree_root,
            "orphan-quarantine",
        ));

        let report = manager.gc(options).expect("gc orphan");

        assert_eq!(report.orphan_removed_count, 1);
        assert!(report.entries.iter().any(|entry| {
            entry.name == "agent-orphan-gc"
                && entry.status == WorktreeGcStatus::OrphanQuarantined
                && entry.reason == WorktreeGcReason::UnregisteredOrphan
                && entry.retention_operation_id.is_some()
        }));
        let public_wire = serde_json::to_string(&report).expect("serialize public GC report");
        assert!(public_wire.contains("retention_operation_id"));
        assert!(
            !public_wire.contains("\"token\""),
            "public GC report must not expose the bearer purge token"
        );
        assert!(!orphan.exists());
    }

    #[test]
    fn gc_full_apply_reports_removal_despite_stale_git_registration() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let removable = create_gc_worktree(&manager, "removable-lane", &worktree_root);
        let commit = repo.find_commit(oid).expect("commit");
        let branch = repo
            .branch("topic/stale-registration", &commit, false)
            .expect("stale registration branch");
        let reference = branch.into_reference();
        let mut add = WorktreeAddOptions::new();
        add.reference(Some(&reference));
        let stale_path = worktree_root.join("stale-registration");
        repo.worktree("stale-registration", &stale_path, Some(&add))
            .expect("registered worktree");
        fs::remove_dir_all(&stale_path).expect("delete registered worktree out of band");

        let report = manager
            .gc(gc_options(Some(worktree_root), false))
            .unwrap_or_else(|error| {
                panic!(
                    "full GC discarded its report after durable removal (removable_exists={}): {error:#}",
                    removable.path.exists()
                )
            });

        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert!(report.entries.iter().any(|entry| {
            entry.name == removable.name && entry.status == WorktreeGcStatus::Removed
        }));
        assert!(!removable.path.exists());
        assert!(repo.find_worktree("stale-registration").is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn machine_global_claim_refuses_unregistered_worktree_gc_before_any_orphan_moves() {
        use crate::gate_denial::{DestructiveTargetDenial, GateDenialReason};

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let first = worktree_root.join("agent-orphan-first");
        let second = worktree_root.join("agent-orphan-second");
        for orphan in [&first, &second] {
            fs::create_dir_all(orphan).expect("orphan directory");
            fs::write(orphan.join("sentinel"), b"must survive").expect("orphan sentinel");
        }
        let binding = machine_global_gc_binding(temp.path(), &worktree_root, "claimed-orphan-gc");
        let store =
            MachineGlobalStore::open_config(&binding.config).expect("open machine-global config");
        let claimed = store
            .coordinate_for_existing_directory(&binding.root_id, &second)
            .expect("second orphan coordinate");
        let claim = store
            .claim("repair-agent", "repairing-orphan", vec![claimed.clone()])
            .expect("claim orphan");
        assert!(matches!(claim, GateOutcome::Allowed(_)));

        let manager = WorktreeManager::new(&repo_path);
        let mut options = gc_options(Some(worktree_root), false);
        options.machine_global_retention = Some(binding);
        let report = manager.gc(options).expect("refused orphan GC report");

        assert_eq!(report.orphan_removed_count, 0);
        assert_eq!(report.protected_count, 2);
        assert!(report.entries.iter().all(|entry| {
            entry.status == WorktreeGcStatus::Protected
                && entry.reason == WorktreeGcReason::MachineGlobalGate
        }));
        let denial = report
            .entries
            .first()
            .and_then(|entry| entry.gate_denial.as_ref())
            .expect("typed gate denial");
        assert!(matches!(
            denial.reason,
            GateDenialReason::DestructiveTarget {
                denial: ref target_denial
            } if matches!(
                target_denial.as_ref(),
                DestructiveTargetDenial::ActiveClaimIntersection {
                    target,
                    active_claim
                } if target == &claimed && active_claim == &claimed
            )
        ));
        for orphan in [&first, &second] {
            assert_eq!(
                fs::read(orphan.join("sentinel")).expect("read preserved sentinel"),
                b"must survive"
            );
        }
        assert!(store
            .status()
            .expect("machine-global status")
            .retention_operations
            .is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn destructive_unregistered_worktree_gc_refuses_without_machine_global_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let orphan = worktree_root.join("agent-unbound-orphan");
        fs::create_dir_all(&orphan).expect("orphan directory");
        fs::write(orphan.join("sentinel"), b"must survive").expect("orphan sentinel");

        let error = WorktreeManager::new(&repo_path)
            .gc(gc_options(Some(worktree_root), false))
            .expect_err("unbound destructive orphan GC must fail closed");

        assert!(error.to_string().contains(
            "destructive worktree orphan GC requires an explicit machine-global config/root binding"
        ));
        assert_eq!(
            fs::read(orphan.join("sentinel")).expect("read preserved sentinel"),
            b"must survive"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gc_dry_run_reports_without_removing_worktree_or_target() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "agent-dry-run-gc", &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");

        let report = manager
            .gc_with_target_liveness(gc_options(Some(worktree_root), true), |_| {
                WorktreeTargetLiveness::Clear
            })
            .expect("dry-run gc");

        assert!(report.dry_run);
        assert_eq!(report.removed_count, 1, "{report:#?}");
        assert_eq!(report.entries[0].status, WorktreeGcStatus::WouldRemove);
        assert_eq!(report.entries[0].reason, WorktreeGcReason::FinishedBranch);
        let lane_bytes = report.entries[0]
            .apparent_worktree_bytes
            .expect("dry-run lane byte estimate");
        assert_eq!(report.apparent_considered_bytes, lane_bytes);
        assert_eq!(report.estimated_reclaimable_bytes, lane_bytes);
        assert_eq!(report.estimated_reclaimed_bytes, 0);
        assert!(created.path.exists());
        assert!(created.path.join("target").exists());
    }

    #[cfg(unix)]
    #[test]
    fn shared_read_execution_leases_coexist_and_block_remove_before_intent() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-leased".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let first = manager
            .acquire_read_execution_lease("agent-leased")
            .expect("first shared lease");
        let second = manager
            .acquire_read_execution_lease("agent-leased")
            .expect("second shared lease");
        let compatibility = manager
            .acquire_execution_lease("agent-leased")
            .expect("compatibility shared lease");
        assert_eq!(first.record(), &created);
        assert_eq!(second.record(), &created);
        assert_eq!(compatibility.path(), created.path);
        let error = manager
            .remove("agent-leased", true, true)
            .expect_err("active shared lease must block removal");
        assert!(error
            .to_string()
            .contains("active cooperative execution lease"));
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-leased", BranchType::Local)
            .is_ok());
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        assert!(store.load(&lock).expect("registry").operations.is_empty());
        drop(lock);

        drop(compatibility);
        drop(second);
        drop(first);
        manager
            .remove("agent-leased", true, true)
            .expect("force remove after shared leases release");
    }

    #[cfg(unix)]
    #[test]
    fn read_and_write_execution_leases_exclude_mutating_overlap() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-write-exclusion".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let read = manager
            .acquire_read_execution_lease("agent-write-exclusion")
            .expect("shared read lease");
        let error = manager
            .acquire_write_execution_lease("agent-write-exclusion")
            .expect_err("reader must exclude writer");
        assert!(format!("{error:#}").contains("kernel state lock is already held"));
        drop(read);

        let write = manager
            .acquire_write_execution_lease("agent-write-exclusion")
            .expect("exclusive write lease");
        assert_eq!(write.record(), &created);
        assert_eq!(write.path(), created.path);
        let read_error = manager
            .acquire_read_execution_lease("agent-write-exclusion")
            .expect_err("writer must exclude reader");
        assert!(format!("{read_error:#}").contains("kernel state lock is already held"));
        let write_error = manager
            .acquire_write_execution_lease("agent-write-exclusion")
            .expect_err("writer must exclude another writer");
        assert!(format!("{write_error:#}").contains("kernel state lock is already held"));
        drop(write);

        let _read_after = manager
            .acquire_read_execution_lease("agent-write-exclusion")
            .expect("reader after writer release");
    }

    #[cfg(unix)]
    #[test]
    fn write_execution_lease_blocks_remove_before_intent_is_persisted() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-writer-removal".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let write = manager
            .acquire_write_execution_lease("agent-writer-removal")
            .expect("exclusive write lease");

        let error = manager
            .remove("agent-writer-removal", true, true)
            .expect_err("writer must block removal");
        assert!(error
            .to_string()
            .contains("active cooperative execution lease"));
        assert!(created.path.exists());
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        assert!(store.load(&lock).expect("registry").operations.is_empty());
        drop(lock);

        drop(write);
        manager
            .remove("agent-writer-removal", true, true)
            .expect("force remove after writer release");
    }

    #[cfg(unix)]
    #[test]
    fn execution_leases_for_unrelated_worktrees_are_independent() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        for agent_id in ["agent-independent-a", "agent-independent-b"] {
            manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: agent_id.to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root.clone()),
                })
                .expect("create independent worktree");
        }

        let write_a = manager
            .acquire_write_execution_lease("agent-independent-a")
            .expect("writer for first worktree");
        let read_b = manager
            .acquire_read_execution_lease("agent-independent-b")
            .expect("reader for unrelated worktree");
        drop(read_b);
        let write_b = manager
            .acquire_write_execution_lease("agent-independent-b")
            .expect("writer for unrelated worktree");

        assert_ne!(write_a.path(), write_b.path());
    }

    #[test]
    fn recreated_worktree_uses_new_incarnation_and_rejects_stale_removal_lease() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let options = || WorktreeCreateOptions {
            agent_id: "agent-incarnation".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root.clone()),
        };
        manager
            .create_for_test(options())
            .expect("first incarnation");

        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        let first = store
            .active_incarnation(&lock, "agent-incarnation")
            .expect("first incarnation evidence");
        drop(lock);
        manager
            .remove("agent-incarnation", true, true)
            .expect("remove first incarnation");
        let old_lease_name =
            managed_worktree_lease_name("agent-incarnation", &first).expect("old lease name");
        let stale_lock =
            KernelStateLock::try_acquire_exclusive_direct(&store.state_root, &old_lease_name)
                .expect("stale incarnation lock");

        manager
            .create_for_test(options())
            .expect("second incarnation");
        let lock = store.lock().expect("registry lock");
        let second = store
            .active_incarnation(&lock, "agent-incarnation")
            .expect("second incarnation evidence");
        assert_eq!(second.generation, 1);
        assert_ne!(second.nonce, first.nonce);
        let stale_lease_name =
            managed_worktree_lease_name("agent-incarnation", &first).expect("stale lease name");
        let stale_process_lease =
            ManagedProcessLease::acquire_exclusive(&stale_lease_name, stale_lock.path())
                .expect("stale process lease");
        let stale = ManagedWorktreeRemovalLease {
            name: "agent-incarnation".to_string(),
            incarnation_generation: first.generation,
            incarnation_nonce: first.nonce,
            _lock: stale_lock,
            _process_lease: stale_process_lease,
        };
        let error = store
            .verify_removal_lease_current(&lock, &stale)
            .expect_err("stale removal lease must not authorize the new incarnation");
        assert!(error.to_string().contains("stale incarnation"));
        let authenticated = store
            .open_authenticated_state(&lock)
            .expect("authenticated managed state");
        assert_eq!(authenticated.current().value.incarnations.len(), 1);
        assert!(authenticated
            .current()
            .value
            .retired_leases
            .contains_key(old_lease_name.to_str().expect("UTF-8 lease name")));
        drop(authenticated);
        drop(lock);

        let _current = manager
            .acquire_read_execution_lease("agent-incarnation")
            .expect("old-incarnation lock must not block current lease");
        assert!(store.state_root.path().join(&old_lease_name).exists());
        drop(stale);
        manager.list().expect("scavenge released retired lease");
        assert!(!store.state_root.path().join(&old_lease_name).exists());
    }

    #[test]
    fn inactive_incarnation_churn_is_pruned_instead_of_exhausting_the_registry() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let registry = store.empty_registry();
        let mut incarnations = BTreeMap::new();

        for index in 0..MAX_MANAGED_RECORDS.saturating_mul(4) {
            let name = format!("retired-{index}");
            incarnations.insert(
                name.clone(),
                ManagedIncarnation {
                    generation: 1,
                    nonce: format!("{index:064x}"),
                    active: true,
                },
            );
            let retired = reconcile_managed_incarnations(&mut incarnations, &registry)
                .expect("prune inactive incarnation");
            assert_eq!(retired.len(), 1);
            assert_eq!(retired[0].0, name);
            assert!(incarnations.is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn retired_lease_scavenger_refuses_rebound_or_foreign_inode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-retired-rebind".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let lock = store.lock().expect("registry lock");
        let incarnation = store
            .active_incarnation(&lock, "agent-retired-rebind")
            .expect("incarnation");
        drop(lock);
        manager
            .remove("agent-retired-rebind", true, true)
            .expect("remove worktree");
        let lease_name =
            managed_worktree_lease_name("agent-retired-rebind", &incarnation).expect("lease name");
        let lease_path = store.state_root.path().join(&lease_name);
        let moved_path = store.state_root.path().join("retired-lease-original");
        crate::safe_state::set_kernel_lock_after_flock_hook({
            let lease_name = lease_name.clone();
            let moved_path = moved_path.clone();
            move |path| {
                if path.file_name() != Some(lease_name.as_os_str()) {
                    return false;
                }
                fs::rename(path, &moved_path).expect("move expected retired lease");
                fs::write(path, b"").expect("foreign replacement");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .expect("replacement mode");
                true
            }
        });

        let error = manager
            .list()
            .expect_err("rebound retired lease must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("does not name its opened descriptor") || chain.contains("rebound"),
            "unexpected error: {chain}"
        );
        assert!(
            lease_path.exists(),
            "foreign replacement must not be deleted"
        );
        assert!(
            moved_path.exists(),
            "expected inode must remain for inspection"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_execution_lease_rejects_lock_path_rebind_after_flock() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-write-rebind".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let registry_lock = store.lock().expect("registry lock");
        let incarnation = store
            .active_incarnation(&registry_lock, "agent-write-rebind")
            .expect("active incarnation");
        drop(registry_lock);
        let lease_name =
            managed_worktree_lease_name("agent-write-rebind", &incarnation).expect("lease name");
        let moved_path = store
            .state_root
            .path()
            .join("managed-worktree-agent-write-rebind.execution.lock.original");
        crate::safe_state::set_kernel_lock_after_flock_hook({
            let lease_name = lease_name.clone();
            let moved_path = moved_path.clone();
            move |path| {
                if path.file_name() != Some(lease_name.as_os_str()) {
                    return false;
                }
                fs::rename(path, &moved_path).expect("move acquired lease inode");
                fs::write(path, b"").expect("create replacement lease inode");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .expect("private replacement mode");
                true
            }
        });

        let error = manager
            .acquire_write_execution_lease("agent-write-rebind")
            .expect_err("rebound write-lease path must fail closed");
        let chain = format!("{error:#}");
        assert!(
            chain.contains("does not name its opened descriptor") || chain.contains("was rebound"),
            "unexpected error: {chain}"
        );
        let replacement_path = store.state_root.path().join(&lease_name);
        assert_ne!(
            identity_for_path(&replacement_path).expect("replacement identity"),
            identity_for_path(&moved_path).expect("original identity")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pending_remove_refuses_active_lease_then_recovers_after_release() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-pending-lease".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let execution = manager
            .acquire_read_execution_lease("agent-pending-lease")
            .expect("shared execution lease");
        let worktree_quarantine = {
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("registry");
            let (_, worktree_quarantine, _, _) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
            worktree_quarantine
        };

        let assert_still_bound = |error: anyhow::Error| {
            assert!(error
                .to_string()
                .contains("pending removal remains durable"));
            assert!(created.path.exists());
            assert!(!worktree_quarantine.exists());
            assert!(repo.find_worktree("agent-pending-lease").is_ok());
        };
        assert!(manager
            .list()
            .expect("list must stay read-only during pending removal")
            .is_empty());
        assert!(created.path.exists());
        assert!(!worktree_quarantine.exists());
        assert!(repo.find_worktree("agent-pending-lease").is_ok());
        assert_still_bound(
            manager
                .get_managed_verified("agent-pending-lease")
                .expect_err("get must refuse active execution lease"),
        );
        assert_still_bound(
            manager
                .acquire_execution_lease("agent-pending-lease")
                .expect_err("new execution lease must refuse pending removal"),
        );
        assert_still_bound(
            manager
                .acquire_write_execution_lease("agent-pending-lease")
                .expect_err("new writer must refuse pending removal"),
        );
        assert_still_bound(
            manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "unrelated-create".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: None,
                })
                .expect_err("create entrypoint must refuse active pending removal"),
        );
        assert_still_bound(
            manager
                .remove("agent-pending-lease", true, true)
                .expect_err("remove entrypoint must refuse active pending removal"),
        );

        drop(execution);
        assert!(manager
            .list()
            .expect("list stays read-only after lease release")
            .is_empty());
        assert!(created.path.exists());
        manager
            .remove("agent-pending-lease", true, true)
            .expect("recover pending removal after lease release");
        assert!(!created.path.exists());
        assert!(repo
            .find_branch("maco/agent-pending-lease", BranchType::Local)
            .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn persisted_paths_round_trip_non_utf8_and_reject_noncanonical_wire_values() {
        let path = PathBuf::from(std::ffi::OsString::from_vec(
            b"/tmp/maco-path-\xff".to_vec(),
        ));
        let wire = encode_persisted_path(&path).expect("encode non-UTF-8 path");
        assert_eq!(
            decode_persisted_path(wire).expect("decode non-UTF-8 path"),
            path
        );

        let wrong_platform = PersistedPathWire {
            platform: "wrong-platform".to_string(),
            encoding: "unix-bytes-hex-v1".to_string(),
            data: "2f746d70".to_string(),
        };
        assert!(decode_persisted_path(wrong_platform)
            .expect_err("wrong platform must fail")
            .contains("does not match"));
        let uppercase = PersistedPathWire {
            platform: std::env::consts::OS.to_string(),
            encoding: "unix-bytes-hex-v1".to_string(),
            data: "2F746d70".to_string(),
        };
        assert!(decode_persisted_path(uppercase)
            .expect_err("uppercase hex must fail")
            .contains("noncanonical"));
        assert!(encode_persisted_path(Path::new("/tmp/../escape"))
            .expect_err("parent component must fail")
            .contains("canonical"));
        let oversized = PathBuf::from(format!(
            "/{}",
            "x/".repeat(MAX_PERSISTED_PATH_BYTES).trim_end_matches('/')
        ));
        assert!(encode_persisted_path(&oversized)
            .expect_err("oversized path must fail")
            .contains("byte limit"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_repository_registry_survives_reopen_recovery_and_remove() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp
            .path()
            .join(std::ffi::OsString::from_vec(b"repo-non-utf8-\xff".to_vec()));
        let worktree_root = temp.path().join(std::ffi::OsString::from_vec(
            b"worktrees-non-utf8-\xfe".to_vec(),
        ));
        WorktreeManager::init_repository(&repo_path, "main").expect("init non-UTF-8 repo");
        let repo = crate::git_repository::open(&repo_path).expect("open non-UTF-8 repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "non-utf8-agent".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create non-UTF-8 managed worktree");
        let write = manager
            .acquire_write_execution_lease("non-utf8-agent")
            .expect("acquire writer in non-UTF-8 repository");
        assert_eq!(write.record(), &created);
        assert_eq!(write.path(), created.path);
        drop(write);

        {
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("open registry");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("load registry");
            repo.find_worktree("non-utf8-agent")
                .expect("managed worktree")
                .lock(Some("simulate crash before lock completion"))
                .expect("re-lock worktree");
            registry
                .records
                .get_mut("non-utf8-agent")
                .expect("managed binding")
                .creation_lock_pending = true;
            let bytes = serde_json::to_vec(&registry).expect("serialize registry bytes");
            assert!(bytes
                .windows(b"unix-bytes-hex-v1".len())
                .any(|window| { window == b"unix-bytes-hex-v1" }));
            assert!(!bytes.windows(3).any(|window| window == [0xef, 0xbf, 0xbd]));
            store
                .save(&lock, &mut registry)
                .expect("persist crash fixture");
        }

        let recovered = manager
            .get_managed_verified("non-utf8-agent")
            .expect("recover non-UTF-8 worktree");
        assert_eq!(recovered.path, created.path);
        let listed = manager.list().expect("list recovered non-UTF-8 worktree");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].path, created.path);
        manager
            .remove("non-utf8-agent", true, true)
            .expect("force remove non-UTF-8 worktree");
        assert!(manager.list().expect("empty verified list").is_empty());
    }

    #[test]
    fn recovers_durable_creation_lock_before_returning_managed_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-lock".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let worktree = repo.find_worktree("agent-lock").expect("worktree");
        assert_eq!(
            worktree.is_locked().expect("initial lock status"),
            WorktreeLockStatus::Unlocked
        );
        worktree
            .lock(Some("simulate crash before creation-lock completion"))
            .expect("re-lock worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("registry lock");
        let mut registry = store.load(&lock).expect("registry");
        registry
            .records
            .get_mut("agent-lock")
            .expect("binding")
            .creation_lock_pending = true;
        store.save(&lock, &mut registry).expect("save pending lock");

        recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect("recover creation lock");

        assert!(
            !registry
                .records
                .get("agent-lock")
                .expect("binding after recovery")
                .creation_lock_pending
        );
        assert_eq!(
            repo.find_worktree("agent-lock")
                .expect("worktree after recovery")
                .is_locked()
                .expect("recovered lock status"),
            WorktreeLockStatus::Unlocked
        );
    }

    #[test]
    fn verified_list_excludes_unbound_git_worktrees() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let managed_root = temp.path().join("managed");
        let unbound_path = temp.path().join("external-unbound");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "managed-agent".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(managed_root),
            })
            .expect("create managed worktree");
        let commit = repo.find_commit(oid).expect("commit");
        let branch = repo
            .branch("topic/unbound", &commit, false)
            .expect("unbound branch");
        let reference = branch.into_reference();
        let mut options = WorktreeAddOptions::new();
        options.reference(Some(&reference));
        repo.worktree("unbound-agent", &unbound_path, Some(&options))
            .expect("unbound worktree");

        let listed = manager.list().expect("verified list");

        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "managed-agent");
        let error = manager
            .get_managed_verified("unbound-agent")
            .expect_err("unbound worktree must require adoption");
        assert!(error.to_string().contains("explicit adoption"));
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
    fn rejects_oversized_agent_and_branch_names() {
        let agent = "a".repeat(MAX_AGENT_ID_BYTES + 1);
        let error = normalize_agent_id(&agent).expect_err("oversized agent id");
        assert!(error.to_string().contains("byte limit"));

        let branch = "b".repeat(MAX_BRANCH_NAME_BYTES + 1);
        let error = validate_branch_name(&branch).expect_err("oversized branch");
        assert!(error.to_string().contains("byte limit"));
    }

    #[test]
    fn bounded_status_refuses_entry_output_and_time_budget_exhaustion() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        for index in 0..3 {
            fs::write(repo_path.join(format!("untracked-{index}")), "dirty")
                .expect("untracked file");
        }

        let index_entries = bounded_worktree_is_clean(
            &repo_path,
            0,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_STATUS_TIMEOUT,
        )
        .expect_err("tracked index entry budget must fail");
        assert!(
            index_entries.to_string().contains("entries"),
            "unexpected bounded index error: {index_entries:#}"
        );

        let entries = bounded_worktree_is_clean(
            &repo_path,
            2,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_STATUS_TIMEOUT,
        )
        .expect_err("entry budget must fail");
        assert!(
            entries.to_string().contains("entries"),
            "unexpected bounded status error: {entries:#}"
        );

        let output = bounded_worktree_is_clean(&repo_path, 10, 1, WORKTREE_STATUS_TIMEOUT)
            .expect_err("output budget must fail");
        assert!(output.to_string().contains("output budget"));

        bounded_worktree_is_clean(
            &repo_path,
            10,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            Duration::ZERO,
        )
        .expect_err("zero time budget must fail before unbounded traversal");
    }

    #[test]
    fn bounded_status_accepts_reuc_without_hiding_dirtiness_or_mutating_the_index() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let readme_blob = repo
            .index()
            .expect("open index")
            .get_path(Path::new("README.md"), 0)
            .expect("README index entry")
            .id;
        let mut resolve_undo = b"README.md\x00100644\x000\x000\x00".to_vec();
        resolve_undo.extend_from_slice(readme_blob.as_bytes());
        let index_path = repo.path().join("index");
        let original = fs::read(&index_path).expect("read ordinary index");
        let index_with_reuc = append_bounded_index_extension(&original, b"REUC", &resolve_undo);
        fs::write(&index_path, &index_with_reuc).expect("write faithful REUC index");

        assert!(
            bounded_worktree_is_clean(
                &repo_path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
            )
            .expect("clean bounded status with REUC"),
            "resolve-undo metadata must not make an otherwise clean repository dirty"
        );
        assert_eq!(
            fs::read(&index_path).expect("read source index after clean status"),
            index_with_reuc,
            "bounded status mutated the source REUC index"
        );

        fs::write(repo_path.join("README.md"), "tracked drift\n")
            .expect("change tracked contents");
        assert!(
            !bounded_worktree_is_clean(
                &repo_path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
            )
            .expect("dirty bounded status with REUC"),
            "resolve-undo metadata must not hide tracked worktree dirtiness"
        );
        assert_eq!(
            fs::read(&index_path).expect("read source index after dirty status"),
            index_with_reuc,
            "bounded status mutated the source REUC index"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_honors_only_canonical_local_core_filemode() {
        skip_without_containment!();
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let readme = repo_path.join("README.md");
        fs::set_permissions(&readme, fs::Permissions::from_mode(0o755))
            .expect("make tracked worktree file executable");
        let mut config = repo.config().expect("open repository config");

        config
            .set_bool("core.filemode", false)
            .expect("disable filemode tracking");
        assert!(
            bounded_worktree_is_clean(
                &repo_path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
            )
            .expect("bounded status with core.filemode=false"),
            "100644 index versus 0755 worktree must be clean when local core.filemode=false"
        );
        fs::write(&readme, "content drift remains visible\n")
            .expect("change content while filemode tracking is disabled");
        assert!(
            !bounded_worktree_is_clean(
                &repo_path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
            )
            .expect("bounded status content drift with core.filemode=false"),
            "core.filemode=false must not hide content changes"
        );
        fs::write(&readme, "# Test\n").expect("restore tracked contents");

        config
            .set_bool("core.filemode", true)
            .expect("enable filemode tracking");
        assert!(
            !bounded_worktree_is_clean(
                &repo_path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
            )
            .expect("bounded status with core.filemode=true"),
            "explicit core.filemode=true must preserve executable-mode dirtiness"
        );

        config
            .remove("core.filemode")
            .expect("remove local core.filemode");
        assert!(
            !bounded_worktree_is_clean(
                &repo_path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
            )
            .expect("bounded status with default core.filemode"),
            "absent core.filemode must fail closed to mode-sensitive status"
        );
    }

    #[test]
    fn bounded_local_git_config_policy_is_narrow_and_fail_closed() {
        let disabled = parse_bounded_local_git_config(Some(
            b"[core]\n\tfilemode = false\n[include]\n\tpath = /must/not/be/read\n",
        ))
        .expect("canonical local filemode");
        assert!(!disabled.core_filemode);
        assert!(!disabled.core_hooks_path_present);

        let hooks = parse_bounded_local_git_config(Some(
            b"[core]\n\tfilemode = true\n\thooksPath = private-hooks\n",
        ))
        .expect("detect local hooksPath without resolving it");
        assert!(hooks.core_filemode);
        assert!(hooks.core_hooks_path_present);

        for malformed in [
            b"[core]\nfilemode = yes\n".as_slice(),
            b"[core]\nfilemode = false\nfilemode = true\n".as_slice(),
            b"[core\nfilemode = false\n".as_slice(),
        ] {
            parse_bounded_local_git_config(Some(malformed))
                .expect_err("malformed or duplicate local policy must fail closed");
        }
        assert!(parse_bounded_local_git_config(None)
            .expect("absent local config")
            .core_filemode);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_ignores_ambient_and_repository_process_helpers() {
        skip_without_containment!();
        use std::os::unix::fs::PermissionsExt;

        struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);

        impl EnvGuard {
            fn set(values: &[(&'static str, &str)]) -> Self {
                let prior = values
                    .iter()
                    .map(|(name, value)| {
                        let prior = std::env::var_os(name);
                        std::env::set_var(name, value);
                        (*name, prior)
                    })
                    .collect();
                Self(prior)
            }
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                for (name, prior) in self.0.drain(..) {
                    match prior {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let marker = temp.path().join("helper-ran");
        let helper = temp.path().join("malicious-fsmonitor");
        fs::write(
            &helper,
            format!(
                "#!/bin/sh\ntouch '{}'\n/usr/bin/setsid /bin/true\nexit 0\n",
                marker.display()
            ),
        )
        .expect("write malicious helper");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))
            .expect("chmod malicious helper");
        let mut config = repo.config().expect("open local config");
        config
            .set_str("core.fsmonitor", helper.to_str().expect("UTF-8 helper"))
            .expect("configure fsmonitor helper");
        config
            .set_str(
                "filter.evil.clean",
                &format!(
                    "sh -c \"touch '{}'; /usr/bin/setsid /bin/true; cat\"",
                    marker.display()
                ),
            )
            .expect("configure filter helper");
        fs::write(repo_path.join(".gitattributes"), "README.md filter=evil\n")
            .expect("write malicious attributes");
        fs::write(repo_path.join("README.md"), "changed\n").expect("change filtered file");

        let count = "1";
        let key = "core.fsmonitor";
        let value = helper.to_str().expect("UTF-8 helper");
        let _ambient = EnvGuard::set(&[
            ("GIT_CONFIG_COUNT", count),
            ("GIT_CONFIG_KEY_0", key),
            ("GIT_CONFIG_VALUE_0", value),
            ("GIT_DIR", "/definitely/not/the/repository"),
        ]);
        assert!(
            !bounded_worktree_is_clean(
                &repo_path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
            )
            .expect("bounded private status"),
            "changed worktree must remain dirty"
        );
        assert!(
            !marker.exists(),
            "ambient or repository-configured helper executed"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_setup_failure_cleans_large_index_snapshot() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let payload_len = usize::try_from(MAX_WORKTREE_INDEX_BYTES)
            .expect("index limit fits usize")
            .saturating_sub(12 + 8 + 20 + 4096);
        let mut index = b"DIRC".to_vec();
        index.extend_from_slice(&2_u32.to_be_bytes());
        index.extend_from_slice(&0_u32.to_be_bytes());
        index.extend_from_slice(b"TREE");
        index.extend_from_slice(
            &u32::try_from(payload_len)
                .expect("payload length fits u32")
                .to_be_bytes(),
        );
        index.extend(std::iter::repeat_n(b't', payload_len));
        let checksum = sha1_digest(&index).expect("index checksum");
        index.extend_from_slice(&checksum);
        fs::write(repo.path().join("index"), index).expect("write valid large index");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");

        let error = bounded_worktree_is_clean_in_runtime(
            &repo_path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_STATUS_TIMEOUT,
            &runtime_root,
            |_| bail!("injected setup failure after index snapshot"),
        )
        .expect_err("injected setup failure");

        assert!(error.to_string().contains("injected setup failure"));
        assert_status_root_contains_only_lock(&runtime_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_total_deadline_caps_lock_wait() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");
        let _held = KernelStateLock::acquire_direct(&runtime_root, WORKTREE_STATUS_RUNTIME_LOCK)
            .expect("hold runtime lock");

        let started = Instant::now();
        let error = bounded_worktree_is_clean_in_runtime_unlocked(
            &repo_path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            Duration::from_millis(50),
            &runtime_root,
            |_| Ok(()),
        )
        .expect_err("total deadline must cap lock acquisition");
        assert!(format!("{error:#}").contains("runtime lock"));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "lock wait ignored the total operation deadline"
        );
    }

    #[test]
    fn bounded_status_process_lock_wait_does_not_consume_execution_budget() {
        let held = lock_bounded_status_process();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || -> Result<()> {
            ready_tx
                .send(())
                .context("failed to signal bounded-status process-lock wait")?;
            let (_guard, deadline, _process_queue_wait) =
                enter_bounded_status_process_scope(Duration::from_millis(100))?;
            ensure_worktree_status_deadline(
                deadline,
                "immediately after bounded-status process lock acquisition",
            )
        });

        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker started waiting for process lock");
        std::thread::sleep(Duration::from_millis(150));
        drop(held);
        worker
            .join()
            .expect("bounded-status process-lock worker panicked")
            .expect("process-lock queue wait must be excluded from execution budget");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_expired_setup_leaves_resumable_runtime() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");

        let error = bounded_worktree_is_clean_in_runtime_unlocked(
            &repo_path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            Duration::from_millis(500),
            &runtime_root,
            |_| {
                std::thread::sleep(Duration::from_millis(600));
                Ok(())
            },
        )
        .expect_err("setup callback must consume the same total deadline");
        assert!(format!("{error:#}").contains("total time budget"));
        assert!(
            fs::read_dir(runtime_root.path())
                .expect("runtime entries")
                .count()
                > 1,
            "expired cleanup should leave an authenticated resumable residue"
        );

        let _lock = KernelStateLock::acquire_direct(&runtime_root, WORKTREE_STATUS_RUNTIME_LOCK)
            .expect("recovery lock");
        scavenge_bounded_status_runtimes(&runtime_root, WORKTREE_STATUS_SCAVENGE_LIMITS)
            .expect("resume cleanup");
        assert_status_root_contains_only_lock(&runtime_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_scavenges_prior_crash_index_and_symlink_tree() {
        skip_without_containment!();
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");
        let residue = runtime_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("crash residue");
        let residue_root = SafeRoot::open_existing(residue.path()).expect("residue root");
        residue_root
            .reserve_direct_child_directory("home")
            .expect("home");
        residue_root
            .reserve_direct_child_directory("tmp")
            .expect("tmp");
        let git = residue_root
            .reserve_direct_child_directory("git")
            .expect("git");
        let git_root = SafeRoot::open_existing(git.path()).expect("git root");
        git_root
            .reserve_direct_child_directory("refs")
            .expect("refs");
        AtomicStateWriter::write_direct(&git_root, "index", b"stale index\n").expect("stale index");
        AtomicStateWriter::write_direct(&git_root, "HEAD", b"deadbeef\n").expect("stale HEAD");
        let external = temp.path().join("external");
        fs::create_dir(&external).expect("external");
        fs::write(external.join("sentinel"), b"keep\n").expect("sentinel");
        symlink(&external, git_root.path().join("objects")).expect("objects link");
        symlink(&repo_path, residue_root.path().join("worktree")).expect("worktree link");
        let residue_path = residue.path().to_path_buf();

        assert!(bounded_worktree_is_clean_in_runtime(
            &repo_path,
            MAX_WORKTREE_STATUS_ENTRIES,
            MAX_WORKTREE_STATUS_OUTPUT_BYTES,
            WORKTREE_STATUS_TIMEOUT,
            &runtime_root,
            |_| Ok(()),
        )
        .expect("status after crash recovery"));

        assert!(!residue_path.exists());
        assert!(external.join("sentinel").exists());
        assert_status_root_contains_only_lock(&runtime_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_scavenger_refuses_unexpected_and_symlink_prefix_entries() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let unexpected_root =
            SafeRoot::open_or_create(temp.path().join("unexpected-root")).expect("root");
        let _unexpected_lock =
            KernelStateLock::acquire_direct(&unexpected_root, WORKTREE_STATUS_RUNTIME_LOCK)
                .expect("lock");
        AtomicStateWriter::write_direct(&unexpected_root, "foreign", b"inspect\n")
            .expect("unexpected file");
        let error =
            scavenge_bounded_status_runtimes(&unexpected_root, WORKTREE_STATUS_SCAVENGE_LIMITS)
                .expect_err("unexpected entry must fail closed");
        assert!(error.to_string().contains("unexpected entry"));
        assert!(unexpected_root.path().join("foreign").exists());

        let symlink_root =
            SafeRoot::open_or_create(temp.path().join("symlink-root")).expect("root");
        let _symlink_lock =
            KernelStateLock::acquire_direct(&symlink_root, WORKTREE_STATUS_RUNTIME_LOCK)
                .expect("lock");
        let external = temp.path().join("external-directory");
        fs::create_dir(&external).expect("external");
        let matching_name = ".git-status.1-2.tmp";
        symlink(&external, symlink_root.path().join(matching_name)).expect("matching symlink");
        let error =
            scavenge_bounded_status_runtimes(&symlink_root, WORKTREE_STATUS_SCAVENGE_LIMITS)
                .expect_err("matching symlink must fail closed");
        assert!(error.to_string().contains("owner-private directory"));
        assert!(symlink_root.path().join(matching_name).exists());
        assert!(external.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_scavenger_enforces_root_directory_tree_and_byte_budgets() {
        let temp = TempDir::new().expect("tempdir");

        let root_entry_root =
            SafeRoot::open_or_create(temp.path().join("root-entry-budget")).expect("root");
        let _root_entry_lock =
            KernelStateLock::acquire_direct(&root_entry_root, WORKTREE_STATUS_RUNTIME_LOCK)
                .expect("lock");
        let root_entry_residue = root_entry_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("residue");
        let error = scavenge_bounded_status_runtimes(
            &root_entry_root,
            PrivateDirectoryScavengeLimits {
                max_root_entries: 1,
                max_directories: 1,
                max_tree_entries: 1,
                max_total_bytes: 1,
                max_duration: Duration::from_secs(10),
            },
        )
        .expect_err("root entry budget");
        assert!(error.to_string().contains("entry budget"));
        assert!(root_entry_residue.path().exists());

        let directory_root =
            SafeRoot::open_or_create(temp.path().join("directory-budget")).expect("root");
        let _directory_lock =
            KernelStateLock::acquire_direct(&directory_root, WORKTREE_STATUS_RUNTIME_LOCK)
                .expect("lock");
        let first = directory_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("first residue");
        let second = directory_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("second residue");
        let error = scavenge_bounded_status_runtimes(
            &directory_root,
            PrivateDirectoryScavengeLimits {
                max_root_entries: 3,
                max_directories: 1,
                max_tree_entries: 1,
                max_total_bytes: 1,
                max_duration: Duration::from_secs(10),
            },
        )
        .expect_err("directory work budget");
        assert!(error.to_string().contains("cleanup limit"));
        assert!(first.path().exists());
        assert!(second.path().exists());

        let tree_root = SafeRoot::open_or_create(temp.path().join("tree-budget")).expect("root");
        let _tree_lock = KernelStateLock::acquire_direct(&tree_root, WORKTREE_STATUS_RUNTIME_LOCK)
            .expect("lock");
        let tree_residue = tree_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("residue");
        let tree_residue_root = SafeRoot::open_existing(tree_residue.path()).expect("residue root");
        AtomicStateWriter::write_direct(&tree_residue_root, "first", b"1").expect("first");
        AtomicStateWriter::write_direct(&tree_residue_root, "second", b"2").expect("second");
        let error = scavenge_bounded_status_runtimes(
            &tree_root,
            PrivateDirectoryScavengeLimits {
                max_root_entries: 2,
                max_directories: 1,
                max_tree_entries: 1,
                max_total_bytes: 2,
                max_duration: Duration::from_secs(10),
            },
        )
        .expect_err("tree entry budget");
        assert!(error.to_string().contains("bounded safety contract"));
        assert!(tree_residue.path().exists());

        let byte_root = SafeRoot::open_or_create(temp.path().join("byte-budget")).expect("root");
        let _byte_lock = KernelStateLock::acquire_direct(&byte_root, WORKTREE_STATUS_RUNTIME_LOCK)
            .expect("lock");
        let byte_residue = byte_root
            .reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)
            .expect("residue");
        let byte_residue_root = SafeRoot::open_existing(byte_residue.path()).expect("residue root");
        AtomicStateWriter::write_direct(&byte_residue_root, "large", b"123456789")
            .expect("large file");
        let error = scavenge_bounded_status_runtimes(
            &byte_root,
            PrivateDirectoryScavengeLimits {
                max_root_entries: 2,
                max_directories: 1,
                max_tree_entries: 1,
                max_total_bytes: 8,
                max_duration: Duration::from_secs(10),
            },
        )
        .expect_err("byte budget");
        assert!(format!("{error:#}").contains("byte cleanup budget"));
        assert!(byte_residue.path().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_status_concurrent_lifecycles_serialize_without_cross_deletion() {
        skip_without_containment!();
        use std::{sync::mpsc, thread};

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let runtime_root =
            SafeRoot::open_or_create(temp.path().join("status-root")).expect("runtime root");
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let first_repo = repo_path.clone();
        let first_root = runtime_root.clone();
        let first = thread::spawn(move || {
            bounded_worktree_is_clean_in_runtime_unlocked(
                &first_repo,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
                &first_root,
                move |runtime| {
                    first_entered_tx
                        .send(runtime.path().to_path_buf())
                        .context("send first runtime")?;
                    release_first_rx.recv().context("release first runtime")?;
                    Ok(())
                },
            )
        });
        let first_runtime = first_entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("first lifecycle entered");
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second_repo = repo_path.clone();
        let second_root = runtime_root.clone();
        let second = thread::spawn(move || {
            bounded_worktree_is_clean_in_runtime_unlocked(
                &second_repo,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_STATUS_TIMEOUT,
                &second_root,
                move |_| {
                    second_entered_tx.send(()).context("send second entry")?;
                    Ok(())
                },
            )
        });

        assert!(matches!(
            second_entered_rx.recv_timeout(Duration::from_millis(200)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(first_runtime.exists());
        release_first_tx.send(()).expect("release first lifecycle");
        assert!(first.join().expect("first thread").expect("first status"));
        second_entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("second lifecycle entered after first cleanup");
        assert!(second
            .join()
            .expect("second thread")
            .expect("second status"));
        assert_status_root_contains_only_lock(&runtime_root);
    }

    #[test]
    fn rejects_invalid_custom_branch_name() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let error = manager
            .create_for_test(WorktreeCreateOptions {
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
    fn refuses_separate_git_directory_before_worktree_mutation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        drop(repo);
        let separate_git_dir = temp.path().join("separate.git");
        fs::rename(repo_path.join(".git"), &separate_git_dir).expect("move git directory");
        fs::write(
            repo_path.join(".git"),
            format!("gitdir: {}\n", separate_git_dir.display()),
        )
        .expect("write gitdir file");

        let error = WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-separated".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect_err("separate git dir must fail closed");
        assert!(error.to_string().contains("--separate-git-dir"));
        assert!(!worktree_root.exists());
        let reopened = crate::git_repository::open(&repo_path).expect("reopen repo");
        assert!(reopened
            .find_branch("maco/agent-separated", BranchType::Local)
            .is_err());
    }

    #[test]
    fn non_force_remove_is_unsupported_without_inspecting_dirty_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-dirty".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::write(created.path.join("scratch.txt"), "local edits\n").expect("write scratch");

        let error = manager
            .remove("agent-dirty", false, true)
            .expect_err("non-force removal must be unsupported");

        assert!(error.to_string().contains("capability-bound"));
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
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
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
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-residue".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let residue = created.path.join("scratch/nested/deps");
        fs::create_dir_all(&residue).expect("create residue directory");
        fs::write(residue.join("artifact.d"), "untracked worker output\n").expect("write residue");

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
    fn force_remove_refuses_missing_create_time_metadata_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-repeat".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        fs::create_dir_all(created.path.join("target/debug/deps"))
            .expect("create residue directory");
        fs::remove_file(created.path.join(".git")).expect("remove worktree git file");

        let error = manager
            .remove("agent-repeat", true, true)
            .expect_err("force must not bypass missing metadata binding");
        let message = error.to_string();

        assert!(message.contains("without following links"));
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-repeat", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn delete_branch_fails_closed_when_create_time_registry_binding_is_missing() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-unbound-delete".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("open registry");
        let lock = store.lock().expect("lock registry");
        let mut registry = store.load(&lock).expect("load registry");
        registry
            .records
            .remove("agent-unbound-delete")
            .expect("remove create-time binding");
        store
            .save(&lock, &mut registry)
            .expect("persist missing binding state");
        drop(lock);
        drop(store);

        let error = manager
            .remove("agent-unbound-delete", true, true)
            .expect_err("missing binding must refuse every destructive phase");

        assert!(error.to_string().contains("no create-time managed binding"));
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-unbound-delete", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn remove_reports_custom_worktree_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");

        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-b".to_string(),
                branch: Some("topic/agent-b".to_string()),
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let removed = manager
            .remove("agent-b", true, true)
            .expect("force remove worktree");

        assert_eq!(removed.branch, "topic/agent-b");
        assert!(repo
            .find_branch("topic/agent-b", BranchType::Local)
            .is_err());
    }

    #[test]
    fn force_remove_refuses_forged_gitdir_backlink_and_preserves_victim() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-forged".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let victim = temp.path().join("victim");
        fs::create_dir(&victim).expect("victim");
        fs::write(victim.join("keep"), "keep").expect("victim file");
        let metadata_gitdir = repo
            .commondir()
            .join("worktrees")
            .join("agent-forged")
            .join("gitdir");
        fs::write(
            &metadata_gitdir,
            format!("{}\n", victim.join(".git").display()),
        )
        .expect("forge gitdir");

        manager
            .list_managed_verified()
            .expect_err("verified list must reject forged metadata");

        let error = manager
            .remove("agent-forged", true, true)
            .expect_err("forged backlink must be refused");
        assert!(error.to_string().contains("gitdir"));
        assert!(victim.join("keep").exists());
        assert!(created.path.exists());
        assert!(repo
            .find_branch("maco/agent-forged", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn force_remove_refuses_forged_head_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-head".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let metadata_head = repo
            .commondir()
            .join("worktrees")
            .join("agent-head")
            .join("HEAD");
        fs::write(&metadata_head, "ref: refs/heads/main\n").expect("forge HEAD");

        let error = manager
            .remove("agent-head", true, true)
            .expect_err("forged HEAD must be refused");
        assert!(error.to_string().contains("HEAD binding mismatch"));
        assert!(created.path.exists());
        assert!(repo.find_branch("main", BranchType::Local).is_ok());
        assert!(repo
            .find_branch("maco/agent-head", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn delete_branch_refuses_branch_that_predated_managed_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("topic/shared", &commit, false)
            .expect("pre-existing branch");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-shared".to_string(),
                branch: Some("topic/shared".to_string()),
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");

        let error = manager
            .remove("agent-shared", true, true)
            .expect_err("pre-existing branch deletion must be refused");
        assert!(error.to_string().contains("predated"));
        assert!(created.path.exists());
        assert!(repo.find_branch("topic/shared", BranchType::Local).is_ok());
    }

    #[test]
    fn transactional_branch_delete_refuses_concurrent_ref_lock_and_preserves_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("topic/locked-delete", &commit, false)
            .expect("branch");
        let mut concurrent = repo.transaction().expect("concurrent transaction");
        concurrent
            .lock_ref("refs/heads/topic/locked-delete")
            .expect("concurrent ref lock");

        let error = compare_and_delete_local_branch(
            &repo,
            "topic/locked-delete",
            oid,
            false,
            "test deletion",
        )
        .expect_err("concurrent ref lock must refuse deletion");

        assert!(error.to_string().contains("failed to lock branch"));
        assert_eq!(
            local_branch_oid(&repo, "topic/locked-delete").expect("branch oid"),
            Some(oid)
        );
        drop(concurrent);
        compare_and_delete_local_branch(&repo, "topic/locked-delete", oid, false, "test deletion")
            .expect("delete after lock release");
        assert!(local_branch_oid(&repo, "topic/locked-delete")
            .expect("missing branch")
            .is_none());

        let commit = repo.find_commit(oid).expect("commit for advanced branch");
        repo.branch("topic/advanced-delete", &commit, false)
            .expect("advanced branch");
        let advanced =
            commit_descendant(&repo, "README.md", "# Ref advanced\n").expect("advanced commit");
        repo.find_branch("topic/advanced-delete", BranchType::Local)
            .expect("advanced branch ref")
            .into_reference()
            .set_target(advanced, "simulate concurrent update-ref")
            .expect("advance deletion target");
        let error = compare_and_delete_local_branch(
            &repo,
            "topic/advanced-delete",
            oid,
            false,
            "test deletion",
        )
        .expect_err("changed branch must be preserved");
        assert!(error.to_string().contains("preserving it"));
        assert_eq!(
            local_branch_oid(&repo, "topic/advanced-delete").expect("advanced oid"),
            Some(advanced)
        );
    }

    #[test]
    fn recovers_create_prepare_by_cleaning_only_unchanged_new_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
        let reserved = root
            .reserve_direct_child_directory("agent-crash")
            .expect("reserve path");
        let staging = root
            .reserve_random_direct_child_directory("test-stage")
            .expect("staging root");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let name = "agent-crash".to_string();
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreatePrepared,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: root.path().join(&name),
                prepared_path_identity: Some(reserved.identity().clone()),
                staging_root: Some(staging.path().to_path_buf()),
                staging_root_identity: Some(staging.identity().clone()),
                staging_path: Some(staging.path().join(&name)),
                staged_path_identity: None,
                staged_metadata: None,
                branch: "maco/agent-crash".to_string(),
                base_oid: oid.to_string(),
                branch_preexisting_oid: None,
                branch_ownership: ManagedBranchOwnership::CreatedByMaco,
                owned_branch_oid: Some(oid.to_string()),
                binding: None,
                delete_branch: false,
                force: false,
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        store.save(&lock, &mut registry).expect("save prepare");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("maco/agent-crash", &commit, false)
            .expect("create branch before crash");

        recover_pending_operations(&repo, &store, &lock, &mut registry).expect("recover create");
        assert!(registry.operations.is_empty());
        assert!(registry.records.is_empty());
        assert!(repo
            .find_branch("maco/agent-crash", BranchType::Local)
            .is_err());
    }

    #[test]
    fn create_prepared_preserves_foreign_empty_staging_child_without_persisted_identity() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
        let name = "agent-prepared-foreign".to_string();
        let reserved = root
            .reserve_direct_child_directory(&name)
            .expect("reserve exact final child");
        let staging = root
            .reserve_random_direct_child_directory("test-stage")
            .expect("staging root");
        let staging_root = SafeRoot::open_existing(staging.path()).expect("open staging root");
        let foreign = staging_root
            .reserve_direct_child_directory(&name)
            .expect("foreign empty staging child");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreatePrepared,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: root.path().join(&name),
                prepared_path_identity: Some(reserved.identity().clone()),
                staging_root: Some(staging.path().to_path_buf()),
                staging_root_identity: Some(staging.identity().clone()),
                staging_path: Some(staging.path().join(&name)),
                staged_path_identity: None,
                staged_metadata: None,
                branch: "maco/agent-prepared-foreign".to_string(),
                base_oid: oid.to_string(),
                branch_preexisting_oid: None,
                branch_ownership: ManagedBranchOwnership::Unknown,
                owned_branch_oid: None,
                binding: None,
                delete_branch: false,
                force: true,
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        store
            .save(&lock, &mut registry)
            .expect("save prepared operation");

        let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect_err("foreign staging child must be preserved");

        assert!(error.to_string().contains("manual recovery"));
        assert!(foreign.path().exists());
        assert_eq!(
            identity_for_path(foreign.path()).expect("foreign identity"),
            *foreign.identity()
        );
        assert!(reserved.path().exists());
        assert!(registry.operations.contains_key(&name));
    }

    #[test]
    fn create_intent_preserves_foreign_empty_target_and_staging_directories() {
        for with_staging in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            let oid = commit_readme(&repo).expect("initial commit");
            let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
            let name = "agent-intent".to_string();
            let staging_name = "stage-intent";
            let staging_root_path = root.path().join(staging_name);
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("lock");
            let mut registry = store.load(&lock).expect("registry");
            registry.operations.insert(
                name.clone(),
                ManagedWorktreeOperation {
                    kind: ManagedWorktreeOperationKind::Create,
                    phase: ManagedWorktreeOperationPhase::CreateIntent,
                    name: name.clone(),
                    root: root.path().to_path_buf(),
                    root_identity: root.identity().clone(),
                    path: root.path().join(&name),
                    prepared_path_identity: None,
                    staging_root: Some(staging_root_path.clone()),
                    staging_root_identity: None,
                    staging_path: Some(staging_root_path.join(&name)),
                    staged_path_identity: None,
                    staged_metadata: None,
                    branch: "maco/agent-intent".to_string(),
                    base_oid: oid.to_string(),
                    branch_preexisting_oid: None,
                    branch_ownership: ManagedBranchOwnership::Unknown,
                    owned_branch_oid: None,
                    binding: None,
                    delete_branch: false,
                    force: true,
                    expected_branch_oid: None,
                    gc_dirtiness_checksum: None,
                    removal_safety: None,
                    worktree_quarantine_path: None,
                    worktree_quarantine_identity: None,
                    metadata_quarantine_path: None,
                    metadata_quarantine_identity: None,
                },
            );
            store.save(&lock, &mut registry).expect("save intent");
            root.reserve_direct_child_directory(&name)
                .expect("simulate final mkdir");
            if with_staging {
                root.reserve_direct_child_directory(staging_name)
                    .expect("simulate staging mkdir");
            }

            let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect_err("identity-free directories require manual recovery");
            assert!(error.to_string().contains("manual recovery"));
            assert!(root.path().join(&name).exists());
            assert_eq!(staging_root_path.exists(), with_staging);
            assert!(registry.operations.contains_key(&name));
        }
    }

    #[test]
    fn unknown_branch_ownership_is_preserved_during_intent_recovery() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let name = "agent-branch-race".to_string();
        let staging_root_path = root.path().join("stage-branch-race");
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreateIntent,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: root.path().join(&name),
                prepared_path_identity: None,
                staging_root: Some(staging_root_path.clone()),
                staging_root_identity: None,
                staging_path: Some(staging_root_path.join(&name)),
                staged_path_identity: None,
                staged_metadata: None,
                branch: "maco/agent-branch-race".to_string(),
                base_oid: oid.to_string(),
                branch_preexisting_oid: None,
                branch_ownership: ManagedBranchOwnership::Unknown,
                owned_branch_oid: None,
                binding: None,
                delete_branch: false,
                force: false,
                expected_branch_oid: None,
                gc_dirtiness_checksum: None,
                removal_safety: None,
                worktree_quarantine_path: None,
                worktree_quarantine_identity: None,
                metadata_quarantine_path: None,
                metadata_quarantine_identity: None,
            },
        );
        store.save(&lock, &mut registry).expect("save intent");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("maco/agent-branch-race", &commit, false)
            .expect("external branch creation");

        let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect_err("unknown ownership must not be inferred");
        assert!(error.to_string().contains("unexpectedly created branch"));
        assert!(repo
            .find_branch("maco/agent-branch-race", BranchType::Local)
            .is_ok());
        assert!(registry.operations.contains_key(&name));
    }

    #[test]
    fn creation_lock_recovery_refuses_descendant_branch_movement() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-advanced".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let worktree = repo.find_worktree("agent-advanced").expect("worktree");
        worktree
            .lock(Some("simulate incomplete handoff"))
            .expect("lock worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("registry lock");
        let mut registry = store.load(&lock).expect("registry");
        registry
            .records
            .get_mut("agent-advanced")
            .expect("binding")
            .creation_lock_pending = true;
        store
            .save(&lock, &mut registry)
            .expect("save pending handoff");

        let advanced =
            commit_descendant(&repo, "README.md", "# Advanced\n").expect("descendant commit");
        repo.find_branch("maco/agent-advanced", BranchType::Local)
            .expect("managed branch")
            .into_reference()
            .set_target(advanced, "simulate concurrent update-ref")
            .expect("advance managed branch");

        let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect_err("branch advancement must block incomplete handoff");

        assert!(error
            .to_string()
            .contains("changed during worktree creation"));
        assert!(
            registry
                .records
                .get("agent-advanced")
                .expect("binding after refusal")
                .creation_lock_pending
        );
        assert!(matches!(
            repo.find_worktree("agent-advanced")
                .expect("worktree after refusal")
                .is_locked()
                .expect("lock status"),
            WorktreeLockStatus::Locked(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn registry_store_refuses_state_root_replacement_after_lock() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let old_root = store.state_root.path().with_file_name("state-old");
        fs::rename(store.state_root.path(), &old_root).expect("rename state root");
        fs::create_dir(store.state_root.path()).expect("replacement root");
        fs::set_permissions(store.state_root.path(), fs::Permissions::from_mode(0o700))
            .expect("replacement mode");

        let error = store
            .load(&lock)
            .expect_err("replaced state root must fail");
        assert!(error.to_string().contains("replaced"));
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_managed_worktree_creations_wait_for_registry_and_serialize() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let blocker = store.lock().expect("initial registry lock");

        assert!(MANAGED_WORKTREE_REGISTRY_LOCK_TIMEOUT > Duration::from_secs(5));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let records = std::thread::scope(|scope| {
            let handles = ["concurrent-a", "concurrent-b"].map(|agent_id| {
                let barrier = std::sync::Arc::clone(&barrier);
                let repo_path = repo_path.clone();
                let worktree_root = worktree_root.clone();
                scope.spawn(move || {
                    barrier.wait();
                    WorktreeManager::new(repo_path).create_for_test(WorktreeCreateOptions {
                        agent_id: agent_id.to_string(),
                        branch: None,
                        base: None,
                        worktree_root: Some(worktree_root),
                    })
                })
            });

            barrier.wait();
            // Keep both creators queued beyond the generic five-second state
            // lock budget that caused the NTFS parallel-launch regression.
            std::thread::sleep(Duration::from_millis(5_250));
            drop(blocker);
            handles.map(|handle| {
                handle
                    .join()
                    .expect("managed creation thread panicked")
                    .expect("contending managed creation")
            })
        });

        let mut names = records.map(|record| record.name);
        names.sort();
        assert_eq!(names, ["concurrent-a", "concurrent-b"]);
        let listed = WorktreeManager::new(&repo_path)
            .list()
            .expect("serialized registry remains readable");
        assert_eq!(listed.len(), 2);
        let lock = store.lock().expect("registry lock after serialized creates");
        let registry = store.load(&lock).expect("authenticated registry");
        assert!(registry.operations.is_empty());
        assert_eq!(
            registry.records.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["concurrent-a", "concurrent-b"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn registry_lock_contention_and_corruption_fail_closed_within_bounds() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
        let active = store.lock().expect("active registry lock");

        let active_started = Instant::now();
        let active_error = store
            .lock_with_timeout(Duration::from_millis(100))
            .expect_err("active registry lock must time out");
        assert!(
            active_started.elapsed() < Duration::from_secs(2),
            "active registry lock exceeded its bounded test wait"
        );
        assert!(
            active_error.to_string().contains("timed out"),
            "unexpected active-lock error: {active_error:#}"
        );

        let lock_path = active.lock.path().to_path_buf();
        drop(active);
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640))
            .expect("corrupt stable lock mode");
        let corrupt_started = Instant::now();
        let corrupt_error = store
            .lock_with_timeout(Duration::from_millis(100))
            .expect_err("corrupt registry lock must fail closed");
        assert!(
            corrupt_started.elapsed() < Duration::from_secs(2),
            "corrupt registry lock exceeded its bounded test wait"
        );
        assert!(
            corrupt_error.to_string().contains("unsafe mode")
                || corrupt_error.to_string().contains("owner-private"),
            "unexpected corrupt-lock error: {corrupt_error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn registry_lock_rebind_after_precheck_preserves_newer_record_and_live_temp() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-a".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect("create initial worktree");

        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let stale_lock = store.lock().expect("stale lock");
        let mut stale_registry = store.load(&stale_lock).expect("stale registry");
        let mut newer_binding = stale_registry
            .records
            .get("agent-a")
            .cloned()
            .expect("initial binding");
        newer_binding.name = "agent-b".to_string();
        newer_binding.branch = "maco/agent-b".to_string();
        let lock_path = stale_lock.lock.path().to_path_buf();
        let moved_lock = lock_path.with_file_name("managed_worktrees.lock.stale-original");
        let live_temp = store
            .state_root
            .path()
            .join(".managed_worktrees.json.live-writer.tmp");
        set_managed_registry_after_precheck_hook({
            let live_temp = live_temp.clone();
            let repo_path = repo_path.clone();
            move || {
                fs::rename(&lock_path, &moved_lock).expect("move held registry lock");
                fs::write(&lock_path, b"").expect("create replacement registry lock");
                fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
                    .expect("private replacement lock");
                let replacement_repo =
                    crate::git_repository::open(&repo_path).expect("replacement repo");
                let replacement_store = ManagedWorktreeRegistryStore::open(&replacement_repo)
                    .expect("replacement store");
                let replacement_lock = replacement_store.lock().expect("replacement lock");
                let mut newer_registry = replacement_store
                    .load(&replacement_lock)
                    .expect("replacement registry");
                newer_registry
                    .records
                    .insert("agent-b".to_string(), newer_binding);
                replacement_store
                    .save(&replacement_lock, &mut newer_registry)
                    .expect("commit newer replacement-domain record");
                fs::write(&live_temp, b"live writer staging").expect("create live temp");
                fs::set_permissions(&live_temp, fs::Permissions::from_mode(0o600))
                    .expect("private live temp");
            }
        });

        let error = store
            .save(&stale_lock, &mut stale_registry)
            .expect_err("stale lock-domain save must fail before temp scavenging");
        assert!(
            error
                .to_string()
                .contains("does not name its opened descriptor")
                || error.to_string().contains("was rebound"),
            "unexpected stale-save error: {error:#}"
        );
        assert!(
            live_temp.exists(),
            "stale writer deleted a live-domain temp"
        );
        drop(stale_lock);

        let fresh_lock = store.lock().expect("fresh lock");
        let current = store.load(&fresh_lock).expect("newer registry");
        assert!(current.records.contains_key("agent-a"));
        assert!(current.records.contains_key("agent-b"));
        assert_eq!(
            current.checksum,
            managed_registry_checksum(&current).expect("current checksum")
        );
        assert!(
            live_temp.exists(),
            "read path unexpectedly scavenged live temp"
        );
    }

    #[test]
    fn registry_store_enforces_record_operation_and_serialized_size_limits() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        WorktreeManager::new(&repo_path)
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-limits".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("registry lock");
        let loaded = store.load(&lock).expect("registry");
        let binding = loaded
            .records
            .get("agent-limits")
            .cloned()
            .expect("binding");

        let mut too_many_records = store.empty_registry();
        for index in 0..=MAX_MANAGED_RECORDS {
            too_many_records
                .records
                .insert(format!("record-{index}"), binding.clone());
        }
        let error = store
            .save(&lock, &mut too_many_records)
            .expect_err("record count limit");
        assert!(error.to_string().contains("records"));

        let template_operation = ManagedWorktreeOperation {
            kind: ManagedWorktreeOperationKind::Create,
            phase: ManagedWorktreeOperationPhase::CreateIntent,
            name: "template".to_string(),
            root: binding.root.clone(),
            root_identity: binding.root_identity.clone(),
            path: binding.path.clone(),
            prepared_path_identity: None,
            staging_root: None,
            staging_root_identity: None,
            staging_path: None,
            staged_path_identity: None,
            staged_metadata: None,
            branch: "maco/template".to_string(),
            base_oid: binding.base_oid.clone(),
            branch_preexisting_oid: None,
            branch_ownership: ManagedBranchOwnership::Unknown,
            owned_branch_oid: None,
            binding: None,
            delete_branch: false,
            force: false,
            expected_branch_oid: None,
            gc_dirtiness_checksum: None,
            removal_safety: None,
            worktree_quarantine_path: None,
            worktree_quarantine_identity: None,
            metadata_quarantine_path: None,
            metadata_quarantine_identity: None,
        };
        let mut too_many_operations = store.empty_registry();
        for index in 0..=MAX_MANAGED_OPERATIONS {
            too_many_operations
                .operations
                .insert(format!("operation-{index}"), template_operation.clone());
        }
        let error = store
            .save(&lock, &mut too_many_operations)
            .expect_err("operation count limit");
        assert!(error.to_string().contains("operations"));

        let mut oversized = store.empty_registry();
        let large_path = PathBuf::from(format!("/{}", "x/".repeat(7_000).trim_end_matches('/')));
        for index in 0..400 {
            let mut oversized_binding = binding.clone();
            oversized_binding.name = format!("oversized-{index}");
            oversized_binding.root = large_path.clone();
            oversized
                .records
                .insert(oversized_binding.name.clone(), oversized_binding);
        }
        let error = store
            .save(&lock, &mut oversized)
            .expect_err("serialized size limit");
        assert!(error.to_string().contains("serialized size"));

        AtomicStateWriter::write_direct(
            &store.state_root,
            "managed_worktrees.json",
            &vec![b' '; MAX_MANAGED_REGISTRY_BYTES as usize + 1],
        )
        .expect("write oversized registry fixture");
        store.load(&lock).expect_err("load size limit");
    }

    #[test]
    fn recovers_remove_after_worktree_quarantine_rename_before_phase_save() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: "agent-remove-crash".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let binding = registry
            .records
            .get("agent-remove-crash")
            .cloned()
            .expect("binding");
        let verified = verify_managed_worktree_binding(&repo, &store.repository, &binding, true)
            .expect("verify");
        let worktree_quarantine_path = deterministic_remove_quarantine_path(
            &binding.root,
            "worktree",
            &binding.name,
            &binding.path_identity,
        );
        let metadata_quarantine_path = deterministic_remove_quarantine_path(
            &store.repository.common_dir.join("worktrees"),
            "metadata",
            &binding.name,
            &binding.metadata_dir_identity,
        );
        registry.operations.insert(
            binding.name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Remove,
                phase: ManagedWorktreeOperationPhase::RemovePrepared,
                name: binding.name.clone(),
                root: binding.root.clone(),
                root_identity: binding.root_identity.clone(),
                path: binding.path.clone(),
                prepared_path_identity: Some(binding.path_identity.clone()),
                staging_root: None,
                staging_root_identity: None,
                staging_path: None,
                staged_path_identity: None,
                staged_metadata: None,
                branch: binding.branch.clone(),
                base_oid: binding.base_oid.clone(),
                branch_preexisting_oid: None,
                branch_ownership: if binding.branch_created_by_maco {
                    ManagedBranchOwnership::CreatedByMaco
                } else {
                    ManagedBranchOwnership::Preexisting
                },
                owned_branch_oid: binding
                    .branch_created_by_maco
                    .then(|| binding.created_branch_oid.clone()),
                binding: Some(binding.clone()),
                delete_branch: true,
                force: true,
                expected_branch_oid: Some(verified.branch_oid.to_string()),
                gc_dirtiness_checksum: None,
                removal_safety: Some(ManagedRemovalSafety::Explicit),
                worktree_quarantine_path: Some(worktree_quarantine_path.clone()),
                worktree_quarantine_identity: None,
                metadata_quarantine_path: Some(metadata_quarantine_path),
                metadata_quarantine_identity: None,
            },
        );
        store
            .save(&lock, &mut registry)
            .expect("save remove prepare");
        ensure_removal_worktree_lock(&repo, &binding).expect("lock before quarantine");
        quarantine_bound_directory(
            &binding.root,
            &binding.path,
            &worktree_quarantine_path,
            &binding.path_identity,
        )
        .expect("simulate worktree quarantine rename before phase save");

        recover_pending_operations(&repo, &store, &lock, &mut registry).expect("recover remove");
        assert!(!created.path.exists());
        assert!(!binding.metadata_dir.exists());
        assert!(repo
            .find_branch("maco/agent-remove-crash", BranchType::Local)
            .is_err());
        assert!(registry.records.is_empty());
        assert!(registry.operations.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remove_recovery_resumes_every_durable_quarantine_boundary() {
        let boundaries = [
            "worktree_persisted",
            "metadata_renamed",
            "metadata_persisted",
            "partial_worktree_cleanup",
            "worktree_deleted_persisted",
            "partial_metadata_cleanup",
            "metadata_deleted_persisted",
            "branch_deleted_before_persist",
        ];
        for boundary in boundaries {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            commit_readme(&repo).expect("initial commit");
            let manager = WorktreeManager::new(&repo_path);
            manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "agent-boundary".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                })
                .expect("create worktree");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("registry");
            let (binding, worktree_quarantine, metadata_quarantine, expected_oid) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);

            ensure_removal_worktree_lock(&repo, &binding).expect("removal lock");
            quarantine_bound_directory(
                &binding.root,
                &binding.path,
                &worktree_quarantine,
                &binding.path_identity,
            )
            .expect("quarantine worktree");
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("remove operation");
                operation.phase = ManagedWorktreeOperationPhase::WorktreeQuarantined;
                operation.worktree_quarantine_identity = Some(binding.path_identity.clone());
            }
            store
                .save(&lock, &mut registry)
                .expect("persist worktree quarantine");
            if boundary == "worktree_persisted" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover after worktree persist");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }

            verify_metadata_binding_after_worktree_removal(&store.repository, &binding)
                .expect("metadata binding");
            quarantine_bound_directory(
                &store.repository.common_dir.join("worktrees"),
                &binding.metadata_dir,
                &metadata_quarantine,
                &binding.metadata_dir_identity,
            )
            .expect("quarantine metadata");
            if boundary == "metadata_renamed" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover metadata rename before phase save");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("remove operation");
                operation.phase = ManagedWorktreeOperationPhase::MetadataQuarantined;
                operation.metadata_quarantine_identity =
                    Some(binding.metadata_dir_identity.clone());
            }
            store
                .save(&lock, &mut registry)
                .expect("persist metadata quarantine");
            if boundary == "metadata_persisted" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover after metadata persist");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }
            if boundary == "partial_worktree_cleanup" {
                fs::remove_file(worktree_quarantine.join("README.md"))
                    .expect("simulate partial worktree cleanup");
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("resume partial worktree cleanup");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }

            remove_quarantined_bound_directory(
                &binding.root,
                &worktree_quarantine,
                &binding.path_identity,
            )
            .expect("delete worktree quarantine");
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("remove operation");
                operation.phase = ManagedWorktreeOperationPhase::WorktreeDeleted;
            }
            store
                .save(&lock, &mut registry)
                .expect("persist worktree deletion");
            if boundary == "worktree_deleted_persisted" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover after worktree deletion persist");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }
            if boundary == "partial_metadata_cleanup" {
                let removable = fs::read_dir(&metadata_quarantine)
                    .expect("metadata quarantine entries")
                    .filter_map(std::result::Result::ok)
                    .find(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
                    .expect("metadata regular file");
                fs::remove_file(removable.path()).expect("simulate partial metadata cleanup");
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("resume partial metadata cleanup");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }

            remove_quarantined_bound_directory(
                &store.repository.common_dir.join("worktrees"),
                &metadata_quarantine,
                &binding.metadata_dir_identity,
            )
            .expect("delete metadata quarantine");
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("remove operation");
                operation.phase = ManagedWorktreeOperationPhase::MetadataDeleted;
            }
            store
                .save(&lock, &mut registry)
                .expect("persist metadata deletion");
            if boundary == "metadata_deleted_persisted" {
                recover_pending_operations(&repo, &store, &lock, &mut registry)
                    .expect("recover after metadata deletion persist");
                assert_completed_remove(&repo, &registry, &binding);
                continue;
            }

            compare_and_delete_local_branch(
                &repo,
                &binding.branch,
                expected_oid,
                true,
                "test crash before branch phase persist",
            )
            .expect("delete branch before phase persist");
            recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect("recover branch deletion before phase save");
            assert_completed_remove(&repo, &registry, &binding);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remove_prepared_refuses_both_absent_and_both_present_states() {
        for both_present in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            commit_readme(&repo).expect("initial commit");
            let manager = WorktreeManager::new(&repo_path);
            manager
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "agent-ambiguous".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                })
                .expect("create worktree");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("registry");
            let (binding, worktree_quarantine, _, _) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
            if both_present {
                fs::create_dir(&worktree_quarantine).expect("ambiguous quarantine");
            } else {
                fs::remove_dir_all(&binding.path).expect("simulate missing source");
            }

            let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect_err("ambiguous remove state must fail closed");
            assert!(error.to_string().contains("exactly one"));
            assert!(registry.operations.contains_key(&binding.name));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn worktree_quarantined_refuses_ambiguous_metadata_states() {
        for both_present in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = crate::git_repository::open(&repo_path).expect("open repo");
            commit_readme(&repo).expect("initial commit");
            WorktreeManager::new(&repo_path)
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "agent-metadata-state".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                })
                .expect("create worktree");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let lock = store.lock().expect("registry lock");
            let mut registry = store.load(&lock).expect("registry");
            let (binding, worktree_quarantine, metadata_quarantine, _) =
                prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
            ensure_removal_worktree_lock(&repo, &binding).expect("removal lock");
            quarantine_bound_directory(
                &binding.root,
                &binding.path,
                &worktree_quarantine,
                &binding.path_identity,
            )
            .expect("worktree quarantine");
            {
                let operation = registry
                    .operations
                    .get_mut(&binding.name)
                    .expect("operation");
                operation.phase = ManagedWorktreeOperationPhase::WorktreeQuarantined;
                operation.worktree_quarantine_identity = Some(binding.path_identity.clone());
            }
            store
                .save(&lock, &mut registry)
                .expect("persist worktree phase");
            if both_present {
                fs::create_dir(&metadata_quarantine).expect("ambiguous metadata quarantine");
            } else {
                fs::remove_dir_all(&binding.metadata_dir).expect("simulate missing metadata");
            }

            let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect_err("ambiguous metadata state must fail closed");
            assert!(error.to_string().contains("exactly one"));
            assert!(registry.operations.contains_key(&binding.name));
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_status_root_contains_only_lock(root: &SafeRoot) {
        let mut names = fs::read_dir(root.path())
            .expect("read status root")
            .map(|entry| entry.expect("status entry").file_name())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, vec![OsString::from(WORKTREE_STATUS_RUNTIME_LOCK)]);
    }

    fn prepare_remove_operation_for_test(
        repo: &Repository,
        store: &ManagedWorktreeRegistryStore,
        lock: &ManagedWorktreeRegistryLock,
        registry: &mut ManagedWorktreeRegistry,
    ) -> (ManagedWorktreeBinding, PathBuf, PathBuf, Oid) {
        let binding = registry
            .records
            .values()
            .next()
            .cloned()
            .expect("managed binding");
        let verified = verify_managed_worktree_binding(repo, &store.repository, &binding, true)
            .expect("verify binding");
        let worktree_quarantine = deterministic_remove_quarantine_path(
            &binding.root,
            "worktree",
            &binding.name,
            &binding.path_identity,
        );
        let metadata_quarantine = deterministic_remove_quarantine_path(
            &store.repository.common_dir.join("worktrees"),
            "metadata",
            &binding.name,
            &binding.metadata_dir_identity,
        );
        registry.operations.insert(
            binding.name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Remove,
                phase: ManagedWorktreeOperationPhase::RemovePrepared,
                name: binding.name.clone(),
                root: binding.root.clone(),
                root_identity: binding.root_identity.clone(),
                path: binding.path.clone(),
                prepared_path_identity: Some(binding.path_identity.clone()),
                staging_root: None,
                staging_root_identity: None,
                staging_path: None,
                staged_path_identity: None,
                staged_metadata: None,
                branch: binding.branch.clone(),
                base_oid: binding.base_oid.clone(),
                branch_preexisting_oid: None,
                branch_ownership: if binding.branch_created_by_maco {
                    ManagedBranchOwnership::CreatedByMaco
                } else {
                    ManagedBranchOwnership::Preexisting
                },
                owned_branch_oid: binding
                    .branch_created_by_maco
                    .then(|| binding.created_branch_oid.clone()),
                binding: Some(binding.clone()),
                delete_branch: true,
                force: true,
                expected_branch_oid: Some(verified.branch_oid.to_string()),
                gc_dirtiness_checksum: None,
                removal_safety: Some(ManagedRemovalSafety::Explicit),
                worktree_quarantine_path: Some(worktree_quarantine.clone()),
                worktree_quarantine_identity: None,
                metadata_quarantine_path: Some(metadata_quarantine.clone()),
                metadata_quarantine_identity: None,
            },
        );
        store.save(lock, registry).expect("persist remove prepare");
        (
            binding,
            worktree_quarantine,
            metadata_quarantine,
            verified.branch_oid,
        )
    }

    fn assert_completed_remove(
        repo: &Repository,
        registry: &ManagedWorktreeRegistry,
        binding: &ManagedWorktreeBinding,
    ) {
        assert!(!binding.path.exists());
        assert!(!binding.metadata_dir.exists());
        assert!(repo
            .find_branch(&binding.branch, BranchType::Local)
            .is_err());
        assert!(!registry.records.contains_key(&binding.name));
        assert!(!registry.operations.contains_key(&binding.name));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_writes_lane_build_config_outside_the_lane_and_gc_does_not_prune_it() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(&manager, "lane-build-config", &worktree_root);

        let config_path = crate::lane_build::lane_build_config_path(&worktree_root);
        let contents = fs::read_to_string(&config_path).expect("lane cargo config");
        assert_eq!(contents, crate::lane_build::lane_cargo_config_contents());
        assert!(
            !created.path.join(".cargo/config.toml").exists()
                || fs::read_to_string(created.path.join(".cargo/config.toml"))
                    .expect("lane checkout cargo config")
                    == fs::read_to_string(
                        Path::new(env!("CARGO_MANIFEST_DIR")).join(".cargo/config.toml")
                    )
                    .expect("primary cargo config"),
            "lane checkout must keep the tracked primary Cargo config"
        );
        assert!(
            !config_path.starts_with(&created.path),
            "lane build config must not live inside the disposable checkout"
        );

        let report = manager
            .gc(gc_options(Some(worktree_root.clone()), false))
            .expect("gc after lane create");
        assert!(
            config_path.exists(),
            "reserved .cargo sibling must survive orphan prune"
        );
        assert!(
            !report
                .entries
                .iter()
                .any(|entry| entry.name == crate::lane_build::LANE_BUILD_CONFIG_DIR),
            "lane Cargo config must not be classified as a worktree: {report:#?}"
        );
    }

    fn create_gc_worktree(
        manager: &WorktreeManager,
        agent_id: &str,
        worktree_root: &Path,
    ) -> WorktreeRecord {
        manager
            .create_for_test(WorktreeCreateOptions {
                agent_id: agent_id.to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.to_path_buf()),
            })
            .expect("create GC worktree")
    }

    fn gc_options(worktree_root: Option<PathBuf>, dry_run: bool) -> WorktreeGcOptions {
        WorktreeGcOptions {
            worktree_root,
            dry_run,
            remove_targets: true,
            targets_only: false,
            retention: WorktreeRetentionPolicy::default(),
            allowed_untracked_paths: Vec::new(),
            exclude_agent_id: None,
            candidate_agent_ids: None,
            merged_into_reference: None,
            superseded_by_agent_id: BTreeMap::new(),
            machine_global_retention: None,
        }
    }

    fn gc_targets_only_options(worktree_root: Option<PathBuf>, dry_run: bool) -> WorktreeGcOptions {
        let mut options = gc_options(worktree_root, dry_run);
        options.targets_only = true;
        options
    }

    fn test_live_target_liveness() -> WorktreeTargetLiveness {
        WorktreeTargetLiveness::Live(target_liveness_evidence(
            Some(42),
            WorktreeTargetLivenessSource::CargoTargetDir,
            WorktreeTargetLivenessCause::PathOverlap,
        ))
    }

    fn test_unknown_target_liveness() -> WorktreeTargetLiveness {
        WorktreeTargetLiveness::Unknown(target_liveness_evidence(
            Some(43),
            WorktreeTargetLivenessSource::MountNamespace,
            WorktreeTargetLivenessCause::NamespaceUnresolved,
        ))
    }

    fn workspace_sweep_options(workspace: &Path, apply: bool) -> WorktreeSweepOptions {
        WorktreeSweepOptions {
            workspace: workspace.to_path_buf(),
            apply,
            remove_targets: true,
            targets_only: false,
            retention: WorktreeRetentionPolicy::default(),
            allowed_untracked_paths: Vec::new(),
        }
    }

    #[cfg(target_os = "linux")]
    fn machine_global_gc_binding(
        test_root: &Path,
        worktree_root: &Path,
        correlation: &str,
    ) -> MachineGlobalRetentionBinding {
        use std::os::unix::fs::PermissionsExt;

        let state_root = test_root.join(format!("machine-global-state-{correlation}"));
        fs::create_dir(&state_root).expect("machine-global state root");
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
            .expect("private machine-global state root");
        let config = test_root.join(format!("machine-global-{correlation}.json"));
        fs::write(
            &config,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "state_root": state_root,
                "roots": [{
                    "id": "worktrees",
                    "path": worktree_root,
                    "protected_paths": [],
                    "quarantine_grace_seconds": 60
                }]
            }))
            .expect("serialize machine-global config"),
        )
        .expect("write machine-global config");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
            .expect("private machine-global config");
        MachineGlobalRetentionBinding {
            config,
            root_id: "worktrees".to_string(),
            owner: "maco-worktree-gc".to_string(),
            correction_correlation_id: correlation.to_string(),
        }
    }

    #[test]
    fn lifecycle_defaults_are_inert_and_o2_defaults_are_bounded_and_conservative() {
        let missing = WorktreeManager::new("/definitely/missing/lifecycle-default-off");
        let report = missing
            .lifecycle(WorktreeLifecycleOptions::default())
            .expect("disabled lifecycle must not inspect repository state");
        assert!(!report.enabled);
        assert!(report.worktree_gc.is_none());
        assert!(report.artifact_prune.is_none());
        assert_eq!(report.actual_reclaimed_bytes, 0);

        let defaults = WorktreeLifecycleOptions::o2_launch_defaults();
        assert!(!defaults.auto_reap_merged);
        assert!(!defaults.apply);
        assert!(!defaults.remove_targets);
        assert_eq!(
            defaults.worktree_retention,
            WorktreeRetentionPolicy::default()
        );
        assert_eq!(O2_LAUNCH_WORKTREE_MAX_COUNT, 10);
        let policy = defaults.artifact_retention.expect("O2 artifact policy");
        assert_eq!(policy.max_count, O2_LAUNCH_ARTIFACT_KEEP_COUNT);
        assert_eq!(policy.unfinalized_grace, Some(O2_LAUNCH_UNFINALIZED_GRACE));
        assert!(!policy.reclaim_unverifiable);
        assert!(!policy.external_writers_stopped);
    }

    #[test]
    fn retry_suffix_parser_accepts_only_canonical_generations() {
        assert_eq!(parse_retry_predecessor("foo-r2"), Ok(Some("foo".into())));
        assert_eq!(parse_retry_predecessor("foo-r3"), Ok(Some("foo-r2".into())));
        assert_eq!(
            parse_retry_predecessor("foo-round2"),
            Ok(Some("foo".into()))
        );
        assert_eq!(parse_retry_predecessor("foo"), Ok(None));
        for malformed in ["foo-r0", "foo-r1", "foo-r02", "foo-rx", "foo-round3"] {
            assert!(parse_retry_predecessor(malformed).is_err(), "{malformed}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_requires_explicit_trunk_containment_without_changing_manual_gc() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "merge-lane", &root);
        let lane_repo = crate::git_repository::open(&lane.path).expect("open lane");
        let lane_oid =
            commit_descendant(&lane_repo, "lane.txt", "unmerged\n").expect("lane descendant");

        let manual = manager
            .gc_with_target_liveness(gc_options(Some(root.clone()), true), |_| {
                WorktreeTargetLiveness::Clear
            })
            .expect("manual preview");
        assert_eq!(
            manual.removed_count, 1,
            "manual GC behavior changed: {manual:#?}"
        );

        let mut lifecycle_options = gc_options(Some(root.clone()), true);
        lifecycle_options.merged_into_reference = Some("refs/heads/main".to_string());
        let retained = manager
            .gc_with_target_liveness(lifecycle_options, |_| WorktreeTargetLiveness::Clear)
            .expect("unmerged lifecycle preview");
        assert_eq!(retained.removed_count, 0, "{retained:#?}");
        assert_eq!(retained.entries[0].status, WorktreeGcStatus::Retained);
        assert_eq!(retained.entries[0].reason, WorktreeGcReason::UnmergedBranch);
        assert!(lane.path.exists());

        repo.reference("refs/heads/main", lane_oid, true, "test fast-forward")
            .expect("advance primary HEAD");
        let mut lifecycle_options = gc_options(Some(root.clone()), true);
        lifecycle_options.merged_into_reference = Some("refs/heads/main".to_string());
        let preview = manager
            .gc_with_target_liveness(lifecycle_options, |_| WorktreeTargetLiveness::Clear)
            .expect("merged preview");
        assert_eq!(preview.removed_count, 1, "{preview:#?}");
        assert_eq!(preview.entries[0].status, WorktreeGcStatus::WouldRemove);
        assert_eq!(preview.entries[0].reason, WorktreeGcReason::FinishedBranch);
        assert!(lane.path.exists(), "dry-run must preserve the lane");

        let mut lifecycle_options = gc_options(Some(root), false);
        lifecycle_options.merged_into_reference = Some("refs/heads/main".to_string());
        let applied = manager
            .gc_with_target_liveness(lifecycle_options, |_| WorktreeTargetLiveness::Clear)
            .expect("merged apply");
        assert_eq!(applied.removed_count, 1, "{applied:#?}");
        assert_eq!(applied.entries[0].status, WorktreeGcStatus::Removed);
        assert!(!lane.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_retry_supersedes_exact_authenticated_predecessor_despite_retention() {
        skip_without_containment!();
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let predecessor = create_gc_worktree(&manager, "retry-task", &root);
        let successor = create_gc_worktree(&manager, "retry-task-r2", &root);
        let predecessor_repo =
            crate::git_repository::open(&predecessor.path).expect("predecessor repo");
        commit_descendant(&predecessor_repo, "attempt.txt", "unmerged attempt\n")
            .expect("unmerged predecessor commit");

        let mut options = WorktreeLifecycleOptions {
            retry_successor_agent_id: Some(successor.name.clone()),
            worktree_root: Some(root.clone()),
            worktree_retention: WorktreeRetentionPolicy {
                max_count: Some(10),
                ..WorktreeRetentionPolicy::default()
            },
            ..WorktreeLifecycleOptions::default()
        };
        let preview = manager.lifecycle(options.clone()).expect("retry preview");
        assert_eq!(preview.retry.status, RetrySupersessionStatus::Selected);
        let gc = preview.worktree_gc.as_ref().expect("retry GC");
        assert_eq!(gc.considered_count, 1, "{gc:#?}");
        assert_eq!(gc.removed_count, 1, "{gc:#?}");
        assert_eq!(gc.entries[0].reason, WorktreeGcReason::SupersededLane);
        assert!(predecessor.path.exists());
        assert!(successor.path.exists());

        options.apply = true;
        let applied = manager.lifecycle(options).expect("retry apply");
        assert_eq!(applied.worktree_gc.expect("GC").removed_count, 1);
        assert!(!predecessor.path.exists());
        assert!(successor.path.exists());
        assert!(repo
            .find_branch("maco/retry-task-r2", BranchType::Local)
            .is_ok());
    }

    #[test]
    fn retry_supersession_requires_exact_authenticated_successor_and_root() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        create_gc_worktree(&manager, "isolated", &temp.path().join("root-a"));

        let missing = resolve_retry_supersession(&repo, "isolated-r2").expect("classification");
        assert_eq!(missing.status, RetrySupersessionStatus::Ambiguous);
        assert!(missing
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("successor")));

        create_gc_worktree(&manager, "isolated-r2", &temp.path().join("root-b"));
        let different_root =
            resolve_retry_supersession(&repo, "isolated-r2").expect("classification");
        assert_eq!(
            different_root.status,
            RetrySupersessionStatus::PredecessorNotFound
        );
    }

    #[test]
    fn retry_supersession_refuses_a_crash_orphaned_successor_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let predecessor = create_gc_worktree(&manager, "stale-retry", &root);
        let successor = create_gc_worktree(&manager, "stale-retry-r2", &root);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let registry = store.load(&lock).expect("registry");
        let successor_binding = registry
            .records
            .get(&successor.name)
            .cloned()
            .expect("successor binding");
        drop(lock);
        fs::remove_dir_all(&successor_binding.path).expect("remove successor path");
        fs::remove_dir_all(&successor_binding.metadata_dir).expect("remove successor metadata");

        let classification =
            resolve_retry_supersession(&repo, &successor.name).expect("classification");
        assert_eq!(classification.status, RetrySupersessionStatus::Ambiguous);
        assert!(classification
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("not live and verified")));
        let report = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                retry_successor_agent_id: Some(successor.name),
                worktree_root: Some(root),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("fail-closed retry lifecycle report");
        assert!(report.worktree_gc.is_none());
        assert!(predecessor.path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_dry_run_aggregates_worktree_and_explicit_o2_artifact_policy() {
        skip_without_containment!();
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "aggregate-lane", &root);
        let run = repo_path.join(".maco/o2-autopilot/runs/run-a");
        fs::create_dir_all(&run).expect("O2 run");
        fs::set_permissions(
            repo_path.join(".maco/o2-autopilot/runs"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private O2 root");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).expect("private O2 run");
        fs::write(run.join("events.jsonl"), b"events\n").expect("O2 artifact");
        let mut policy = ArtifactRetentionPolicy {
            max_count: 0,
            max_age: None,
            max_total_bytes: None,
            unfinalized_grace: Some(Duration::ZERO),
            reclaim_unverifiable: false,
            external_writers_stopped: false,
        };
        let mut options = WorktreeLifecycleOptions {
            auto_reap_merged: true,
            candidate_agent_ids: Some(BTreeSet::from([lane.name.clone()])),
            merged_into_reference: Some("refs/heads/main".to_string()),
            worktree_root: Some(root),
            artifact_retention: Some(policy.clone()),
            ..WorktreeLifecycleOptions::default()
        };
        let refused = manager.lifecycle(options.clone()).expect("refused preview");
        assert_eq!(refused.worktree_gc.as_ref().expect("GC").removed_count, 1);
        let refused_artifact = refused.artifact_prune.as_ref().expect("artifact report");
        assert_eq!(refused_artifact.refused_unfinalized_count, 1);
        assert_eq!(refused_artifact.would_reclaim_bytes, 0);
        assert!(lane.path.exists());
        assert!(run.exists());

        policy.external_writers_stopped = true;
        options.artifact_retention = Some(policy);
        let aggregate = manager.lifecycle(options).expect("explicit preview");
        let gc = aggregate.worktree_gc.as_ref().expect("GC");
        let artifacts = aggregate.artifact_prune.as_ref().expect("artifacts");
        assert_eq!(
            aggregate.apparent_checked_bytes,
            gc.apparent_considered_bytes + artifacts.scanned_bytes
        );
        assert_eq!(
            aggregate.projected_reclaimable_bytes,
            gc.estimated_reclaimable_bytes + artifacts.would_reclaim_bytes
        );
        assert_eq!(aggregate.actual_reclaimed_bytes, 0);
        assert!(aggregate.projected_reclaimable_bytes > gc.estimated_reclaimable_bytes);
        let output = serde_json::to_string_pretty(&aggregate).expect("serialize lifecycle report");
        println!("LIFECYCLE_DRY_RUN_REPORT={output}");
        assert!(lane.path.exists());
        assert!(run.exists());
    }

    #[test]
    fn startup_reconciliation_is_report_only_then_forgets_exact_missing_both_record() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "crash-orphan", &root);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let registry = store.load(&lock).expect("registry");
        let binding = registry.records.get(&lane.name).cloned().expect("binding");
        drop(lock);
        fs::remove_dir_all(&binding.path).expect("simulate missing worktree path");
        fs::remove_dir_all(&binding.metadata_dir).expect("simulate missing Git metadata");

        let mut options = WorktreeLifecycleOptions {
            startup_reconcile: true,
            ..WorktreeLifecycleOptions::default()
        };
        let preview = manager
            .lifecycle(options.clone())
            .expect("reconciliation preview");
        assert_eq!(preview.reconciliation.forgotten_record_count, 0);
        assert_eq!(
            preview.reconciliation.entries[0].state,
            WorktreeReconciliationState::AuthenticatedMissingBoth
        );
        assert_eq!(
            preview.reconciliation.entries[0].action,
            WorktreeReconciliationAction::ReportOnly
        );
        assert!(ManagedWorktreeRegistryStore::open(&repo)
            .expect("store")
            .load(
                &ManagedWorktreeRegistryStore::open(&repo)
                    .expect("store")
                    .lock()
                    .expect("lock")
            )
            .expect("registry")
            .records
            .contains_key(&lane.name));

        options.apply = true;
        options.destructive_reconciliation = true;
        let applied = manager.lifecycle(options).expect("reconciliation apply");
        assert_eq!(applied.reconciliation.forgotten_record_count, 1);
        assert_eq!(
            applied.reconciliation.entries[0].action,
            WorktreeReconciliationAction::ForgotAuthenticatedRecord
        );
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        assert!(!store
            .load(&lock)
            .expect("registry")
            .records
            .contains_key(&lane.name));
        assert!(repo.find_branch(&lane.branch, BranchType::Local).is_ok());
    }

    #[test]
    fn startup_reconciliation_active_claim_protects_missing_both_record() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let lane = create_gc_worktree(&manager, "claimed-crash-orphan", &root);
        SyncStore::open(&repo_path)
            .expect("claims")
            .claim_paths(&lane.name, ["src"])
            .expect("claim lane");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let binding = store
            .load(&lock)
            .expect("registry")
            .records
            .get(&lane.name)
            .cloned()
            .expect("binding");
        drop(lock);
        fs::remove_dir_all(&binding.path).expect("remove path");
        fs::remove_dir_all(&binding.metadata_dir).expect("remove metadata");

        let report = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                startup_reconcile: true,
                destructive_reconciliation: true,
                worktree_root: Some(root),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("claimed reconciliation report");
        let entry = report
            .reconciliation
            .entries
            .iter()
            .find(|entry| entry.name == lane.name)
            .expect("claimed entry");
        assert_eq!(
            entry.state,
            WorktreeReconciliationState::AuthenticatedMissingBoth
        );
        assert_eq!(entry.action, WorktreeReconciliationAction::Protected);
        assert!(entry.detail.contains("active durable claim"));
        let lock = store.lock().expect("lock");
        assert!(store
            .load(&lock)
            .expect("registry")
            .records
            .contains_key(&lane.name));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_reconciliation_quarantines_unregistered_on_disk_lane_with_explicit_binding() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let orphan = root.join("deregistered-lane");
        fs::create_dir_all(orphan.join("target/debug")).expect("orphan tree");
        fs::write(orphan.join("sentinel"), b"crash residue").expect("orphan sentinel");
        let binding = machine_global_gc_binding(temp.path(), &root, "startup-orphan");
        let manager = WorktreeManager::new(&repo_path);

        let preview = manager
            .lifecycle(WorktreeLifecycleOptions {
                startup_reconcile: true,
                worktree_root: Some(root.clone()),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("startup preview");
        let preview_entry = preview
            .reconciliation
            .entries
            .iter()
            .find(|entry| entry.name == "deregistered-lane")
            .expect("orphan preview");
        assert_eq!(
            preview_entry.state,
            WorktreeReconciliationState::PresentDeregistered
        );
        assert_eq!(
            preview_entry.action,
            WorktreeReconciliationAction::ReportOnly
        );
        assert!(orphan.exists());

        let applied = manager
            .lifecycle(WorktreeLifecycleOptions {
                apply: true,
                startup_reconcile: true,
                destructive_reconciliation: true,
                worktree_root: Some(root),
                machine_global_retention: Some(binding),
                ..WorktreeLifecycleOptions::default()
            })
            .expect("startup quarantine");
        assert_eq!(applied.reconciliation.quarantined_directory_count, 1);
        assert_eq!(
            applied.reconciliation.entries[0].action,
            WorktreeReconciliationAction::QuarantinedDirectory
        );
        assert!(!orphan.exists());
    }
