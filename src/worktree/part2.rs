fn validate_retry_supersession_authorities(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    registry: &ManagedWorktreeRegistry,
    superseded_by: &BTreeMap<String, String>,
) -> Result<()> {
    for (predecessor, successor) in superseded_by {
        if parse_retry_predecessor(successor)
            .map_err(anyhow::Error::msg)?
            .as_deref()
            != Some(predecessor.as_str())
        {
            bail!(
                "retry supersession authority '{predecessor}' -> '{successor}' is not a canonical adjacent generation"
            );
        }
        if registry.operations.contains_key(predecessor)
            || registry.operations.contains_key(successor)
        {
            bail!("retry supersession authority changed to a pending lifecycle operation");
        }
        let predecessor_binding = registry
            .records
            .get(predecessor)
            .with_context(|| format!("retry predecessor '{predecessor}' disappeared before GC"))?;
        let successor_binding = registry
            .records
            .get(successor)
            .with_context(|| format!("retry successor '{successor}' disappeared before GC"))?;
        verify_managed_worktree_binding(repo, repository, predecessor_binding, false)
            .context("retry predecessor binding changed before GC")?;
        verify_managed_worktree_binding(repo, repository, successor_binding, false)
            .context("retry successor binding changed before GC")?;
        if predecessor_binding.root != successor_binding.root {
            bail!("retry generations no longer share one authenticated worktree root");
        }
        let successor_branch_predecessor = parse_retry_predecessor(&successor_binding.branch)
            .ok()
            .flatten();
        if successor_branch_predecessor.as_deref() != Some(predecessor_binding.branch.as_str())
            && successor_branch_predecessor
                .as_deref()
                .and_then(|branch| branch.rsplit('/').next())
                != predecessor_binding.branch.rsplit('/').next()
        {
            bail!("retry generations no longer share one canonical branch family");
        }
    }
    Ok(())
}

fn reconcile_managed_worktree_lifecycle(
    repo: &Repository,
    requested_root: Option<PathBuf>,
    apply: bool,
    destructive_reconciliation: bool,
    machine_global_retention: Option<&MachineGlobalRetentionBinding>,
) -> Result<WorktreeReconciliationReport> {
    let mut report = WorktreeReconciliationReport {
        enabled: true,
        apply,
        destructive_reconciliation,
        forgotten_record_count: 0,
        pruned_registration_count: 0,
        quarantined_directory_count: 0,
        entries: Vec::new(),
    };
    let active_claims = active_claim_agent_ids(repo)?;
    let managed_store = ManagedWorktreeRegistryStore::open_existing(repo)?;
    let snapshot = match managed_store.as_ref() {
        Some(store) => store.load_existing_read_only()?,
        None => None,
    };
    let mut resolutions = Vec::new();
    let mut authenticated_names = BTreeSet::new();
    let mut roots = BTreeSet::from([resolve_worktree_root(repo, requested_root)?]);

    if let (Some(store), Some(snapshot)) = (managed_store.as_ref(), snapshot.as_ref()) {
        for binding in snapshot.records.values() {
            authenticated_names.insert(binding.name.clone());
            roots.insert(binding.root.clone());
            let mut entry =
                classify_worktree_reconciliation(repo, &store.repository, snapshot, binding);
            let state = entry.state;
            let claimed = active_claims.contains(&binding.name);
            if claimed && state != WorktreeReconciliationState::Consistent {
                entry.action = WorktreeReconciliationAction::Protected;
                entry
                    .detail
                    .push_str("; an active durable claim protects this lane");
            } else if matches!(
                state,
                WorktreeReconciliationState::AuthenticatedMissingBoth
                    | WorktreeReconciliationState::RegisteredMissingPath
                    | WorktreeReconciliationState::PresentDeregistered
            ) {
                if apply && destructive_reconciliation {
                    resolutions.push(WorktreeReconciliationResolution::Authenticated {
                        entry_index: report.entries.len(),
                        state,
                        binding: Box::new(binding.clone()),
                    });
                } else {
                    entry.action = WorktreeReconciliationAction::ReportOnly;
                    entry.detail.push_str(
                        "; resolution requires both apply and destructive reconciliation",
                    );
                }
            }
            report.entries.push(entry);
        }
        for operation in snapshot.operations.values() {
            if snapshot.records.contains_key(&operation.name) {
                continue;
            }
            report.entries.push(WorktreeReconciliationEntry {
                name: operation.name.clone(),
                branch: Some(operation.branch.clone()),
                path: operation.path.clone(),
                state: WorktreeReconciliationState::PendingOperation,
                action: WorktreeReconciliationAction::Protected,
                detail: format!(
                    "authenticated {} operation remains in phase {}; startup reconciliation reports it without bypassing recovery",
                    managed_operation_kind_label(operation.kind),
                    managed_operation_phase_label(operation.phase),
                ),
            });
        }
    }

    let mut unregistered_name_paths = BTreeMap::<String, Vec<(usize, FileIdentity)>>::new();
    for root_path in roots {
        if !path_entry_exists(&root_path)? {
            continue;
        }
        let root = SafeRoot::open_existing(&root_path)?;
        let git_registered = git_registered_worktree_names_for_reconciliation(repo, root.path())?;
        for child_name in root.direct_child_names_bounded(MAX_MANAGED_RECORDS)? {
            if is_reserved_worktree_root_child(&child_name) {
                continue;
            }
            let Some(name) = child_name.to_str() else {
                bail!("managed worktree root contains a non-UTF-8 child name");
            };
            if normalize_agent_id(name)? != name || authenticated_names.contains(name) {
                continue;
            }
            let path = root.direct_child(&child_name)?;
            let identity = identity_for_path(&path)?;
            let registered = git_registered.contains(name);
            let claimed = active_claims.contains(name);
            let entry_index = report.entries.len();
            report.entries.push(WorktreeReconciliationEntry {
                name: name.to_string(),
                branch: None,
                path: path.clone(),
                state: if registered {
                    WorktreeReconciliationState::Ambiguous
                } else {
                    WorktreeReconciliationState::PresentDeregistered
                },
                action: if claimed || registered {
                    WorktreeReconciliationAction::Protected
                } else {
                    WorktreeReconciliationAction::ReportOnly
                },
                detail: if claimed {
                    "unregistered on-disk lane is protected by an active durable claim".to_string()
                } else if registered {
                    "Git-registered lane lacks authenticated MACO ownership; startup reconciliation will not adopt or remove it".to_string()
                } else if apply && destructive_reconciliation {
                    "unregistered on-disk lane is eligible only for machine-global quarantine".to_string()
                } else {
                    "unregistered on-disk lane detected; quarantine requires apply plus destructive reconciliation and a reviewed machine-global binding".to_string()
                },
            });
            if !claimed && !registered && apply && destructive_reconciliation {
                unregistered_name_paths
                    .entry(name.to_string())
                    .or_default()
                    .push((entry_index, identity));
            }
        }
    }
    for (name, candidates) in unregistered_name_paths {
        if candidates.len() != 1 {
            for (entry_index, _) in candidates {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "same unregistered lane name appears under multiple managed roots",
                );
            }
            continue;
        }
        let (entry_index, identity) = candidates
            .into_iter()
            .next()
            .context("one reconciliation candidate disappeared")?;
        let path = report.entries[entry_index].path.clone();
        resolutions.push(WorktreeReconciliationResolution::UnregisteredDirectory {
            entry_index,
            name,
            path,
            identity,
        });
    }

    if apply && destructive_reconciliation {
        apply_worktree_reconciliation_resolutions(
            repo,
            managed_store.as_ref(),
            &active_claims,
            machine_global_retention,
            resolutions,
            &mut report,
        )?;
    }
    report.entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(report)
}

enum WorktreeReconciliationResolution {
    Authenticated {
        entry_index: usize,
        state: WorktreeReconciliationState,
        binding: Box<ManagedWorktreeBinding>,
    },
    UnregisteredDirectory {
        entry_index: usize,
        name: String,
        path: PathBuf,
        identity: FileIdentity,
    },
}

struct WorktreeReconciliationQuarantine {
    entry_index: usize,
    name: String,
    path: PathBuf,
    identity: FileIdentity,
    authenticated_binding: Option<ManagedWorktreeBinding>,
}

fn apply_worktree_reconciliation_resolutions(
    repo: &Repository,
    managed_store: Option<&ManagedWorktreeRegistryStore>,
    observed_claims: &BTreeSet<String>,
    machine_global_retention: Option<&MachineGlobalRetentionBinding>,
    resolutions: Vec<WorktreeReconciliationResolution>,
    report: &mut WorktreeReconciliationReport,
) -> Result<()> {
    let current_claims = active_claim_agent_ids(repo)?;
    let mut authenticated = Vec::new();
    let mut quarantine = Vec::new();
    for resolution in resolutions {
        match resolution {
            WorktreeReconciliationResolution::Authenticated {
                entry_index,
                state,
                binding,
            } => authenticated.push((entry_index, state, *binding)),
            WorktreeReconciliationResolution::UnregisteredDirectory {
                entry_index,
                name,
                path,
                identity,
            } => quarantine.push(WorktreeReconciliationQuarantine {
                entry_index,
                name,
                path,
                identity,
                authenticated_binding: None,
            }),
        }
    }

    let mut managed_state = None;
    if !authenticated.is_empty() {
        let store = managed_store
            .context("authenticated reconciliation candidates lost their managed registry store")?;
        let lock = store.lock_existing()?;
        let current = store.load(&lock)?;
        managed_state = Some((store, lock, current));
    }

    if let Some((store, lock, current)) = managed_state.as_mut() {
        for (entry_index, state, expected) in authenticated {
            if observed_claims.contains(&expected.name) || current_claims.contains(&expected.name) {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "an active durable claim appeared before destructive reconciliation",
                );
                continue;
            }
            let Some(observed) = current.records.get(&expected.name) else {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "authenticated record disappeared before destructive reconciliation",
                );
                continue;
            };
            if observed != &expected
                || current.operations.contains_key(&expected.name)
                || store.worktree_has_active_execution_lease(lock, &expected.name)?
            {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "authenticated identity, operation state, or execution lease changed before apply",
                );
                continue;
            }
            match state {
                WorktreeReconciliationState::AuthenticatedMissingBoth => {
                    if path_entry_exists(&expected.path)?
                        || path_entry_exists(&expected.metadata_dir)?
                        || repo.find_worktree(&expected.name).is_ok()
                    {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "missing-both state changed before apply",
                        );
                        continue;
                    }
                    current.records.remove(&expected.name);
                    let entry = &mut report.entries[entry_index];
                    entry.action = WorktreeReconciliationAction::ForgotAuthenticatedRecord;
                    entry.detail = "forgot exact authenticated missing-both record; branch and claims were preserved".to_string();
                    report.forgotten_record_count = report
                        .forgotten_record_count
                        .checked_add(1)
                        .context("forgotten reconciliation record count overflowed")?;
                }
                WorktreeReconciliationState::RegisteredMissingPath => {
                    if path_entry_exists(&expected.path)?
                        || identity_for_path(&expected.metadata_dir).ok().as_ref()
                            != Some(&expected.metadata_dir_identity)
                        || BoundedRegularReader::identity(expected.metadata_dir.join("gitdir"))
                            .ok()
                            .as_ref()
                            != Some(&expected.metadata_gitdir_file_identity)
                        || BoundedRegularReader::identity(expected.metadata_dir.join("HEAD"))
                            .ok()
                            .as_ref()
                            != Some(&expected.metadata_head_file_identity)
                    {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "registered-missing-path metadata identity changed before apply",
                        );
                        continue;
                    }
                    let worktree = match repo.find_worktree(&expected.name) {
                        Ok(worktree) => worktree,
                        Err(_) => {
                            mark_reconciliation_index_protected(
                                &mut report.entries,
                                entry_index,
                                "Git registration disappeared before exact prune",
                            );
                            continue;
                        }
                    };
                    if worktree.path() != expected.path {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "Git registration no longer names the authenticated path",
                        );
                        continue;
                    }
                    let mut options = WorktreePruneOptions::new();
                    if !worktree
                        .is_prunable(Some(&mut options))
                        .context("failed to classify exact stale worktree registration")?
                    {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "Git refused to classify the missing-path registration as prunable",
                        );
                        continue;
                    }
                    let mut options = WorktreePruneOptions::new();
                    worktree
                        .prune(Some(&mut options))
                        .context("failed to prune exact authenticated stale registration")?;
                    current.records.remove(&expected.name);
                    let entry = &mut report.entries[entry_index];
                    entry.action = WorktreeReconciliationAction::PrunedRegistrationAndForgotRecord;
                    entry.detail = "pruned the exact authenticated stale Git registration and forgot its record; branch and claims were preserved".to_string();
                    report.pruned_registration_count = report
                        .pruned_registration_count
                        .checked_add(1)
                        .context("reconciliation pruned registration count overflowed")?;
                    report.forgotten_record_count = report
                        .forgotten_record_count
                        .checked_add(1)
                        .context("forgotten reconciliation record count overflowed")?;
                }
                WorktreeReconciliationState::PresentDeregistered => {
                    if identity_for_path(&expected.path).ok().as_ref()
                        != Some(&expected.path_identity)
                        || path_entry_exists(&expected.metadata_dir)?
                        || repo.find_worktree(&expected.name).is_ok()
                    {
                        mark_reconciliation_index_protected(
                            &mut report.entries,
                            entry_index,
                            "present-deregistered identity or registration state changed before quarantine",
                        );
                        continue;
                    }
                    quarantine.push(WorktreeReconciliationQuarantine {
                        entry_index,
                        name: expected.name.clone(),
                        path: expected.path.clone(),
                        identity: expected.path_identity.clone(),
                        authenticated_binding: Some(expected),
                    });
                }
                _ => mark_reconciliation_index_protected(
                    &mut report.entries,
                    entry_index,
                    "reconciliation resolution no longer has a destructive action",
                ),
            }
        }
        store.save(lock, current)?;
    }

    if quarantine.is_empty() {
        return Ok(());
    }
    let Some(binding) = machine_global_retention else {
        for candidate in quarantine {
            mark_reconciliation_index_protected(
                &mut report.entries,
                candidate.entry_index,
                "destructive reconciliation of an on-disk directory requires an explicit machine-global config/root binding",
            );
        }
        return Ok(());
    };
    for candidate in &quarantine {
        if current_claims.contains(&candidate.name)
            || identity_for_path(&candidate.path).ok().as_ref() != Some(&candidate.identity)
        {
            mark_reconciliation_index_protected(
                &mut report.entries,
                candidate.entry_index,
                "claim or directory identity changed before machine-global quarantine",
            );
        }
    }
    quarantine.retain(|candidate| {
        report.entries[candidate.entry_index].action != WorktreeReconciliationAction::Protected
    });
    if quarantine.is_empty() {
        return Ok(());
    }
    let machine_store = MachineGlobalStore::open_config(&binding.config)
        .context("failed to open machine-global binding for startup reconciliation")?;
    let targets = quarantine
        .iter()
        .map(|candidate| {
            machine_store
                .coordinate_for_existing_directory(&binding.root_id, &candidate.path)
                .map(DestructiveTargetInput::Declared)
        })
        .collect::<Result<Vec<_>>>()
        .context("startup reconciliation target is outside the reviewed machine-global root")?;
    match machine_store.quarantine(&binding.owner, &binding.correction_correlation_id, targets)? {
        GateOutcome::Denied(denial) => {
            for candidate in quarantine {
                mark_reconciliation_index_protected(
                    &mut report.entries,
                    candidate.entry_index,
                    &format!("machine-global quarantine was denied: {denial:?}"),
                );
            }
        }
        GateOutcome::Allowed(operation) => {
            if quarantine
                .iter()
                .any(|candidate| candidate.authenticated_binding.is_some())
            {
                let (store, lock, current) = managed_state
                    .as_mut()
                    .context("authenticated quarantines lost their locked managed registry")?;
                for candidate in &quarantine {
                    if let Some(expected) = candidate.authenticated_binding.as_ref() {
                        if current.records.get(&expected.name) != Some(expected) {
                            bail!(
                                "authenticated reconciliation record changed after its directory was quarantined; manual recovery is required"
                            );
                        }
                        current.records.remove(&expected.name);
                        report.forgotten_record_count = report
                            .forgotten_record_count
                            .checked_add(1)
                            .context("forgotten reconciliation record count overflowed")?;
                    }
                }
                store.save(lock, current)?;
            }
            for candidate in quarantine {
                let entry = &mut report.entries[candidate.entry_index];
                entry.action = if candidate.authenticated_binding.is_some() {
                    WorktreeReconciliationAction::QuarantinedDirectoryAndForgotRecord
                } else {
                    WorktreeReconciliationAction::QuarantinedDirectory
                };
                entry.detail = format!(
                    "moved exact crash-orphan directory into recoverable machine-global quarantine operation {}",
                    operation.id.get()
                );
                report.quarantined_directory_count = report
                    .quarantined_directory_count
                    .checked_add(1)
                    .context("reconciliation quarantined directory count overflowed")?;
            }
        }
    }
    Ok(())
}

fn classify_worktree_reconciliation(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    registry: &ManagedWorktreeRegistry,
    binding: &ManagedWorktreeBinding,
) -> WorktreeReconciliationEntry {
    let base = |state, action, detail: String| WorktreeReconciliationEntry {
        name: binding.name.clone(),
        branch: Some(binding.branch.clone()),
        path: binding.path.clone(),
        state,
        action,
        detail,
    };
    if registry.operations.contains_key(&binding.name) {
        return base(
            WorktreeReconciliationState::PendingOperation,
            WorktreeReconciliationAction::Protected,
            "authenticated lifecycle operation is pending; startup reconciliation does not bypass operation recovery".to_string(),
        );
    }
    let path = fs::symlink_metadata(&binding.path);
    let metadata = fs::symlink_metadata(&binding.metadata_dir);
    let registered = repo.find_worktree(&binding.name).is_ok();
    match (path, metadata, registered) {
        (Err(path_error), Err(metadata_error), false)
            if path_error.kind() == ErrorKind::NotFound
                && metadata_error.kind() == ErrorKind::NotFound =>
        {
            base(
                WorktreeReconciliationState::AuthenticatedMissingBoth,
                WorktreeReconciliationAction::ReportOnly,
                "authenticated record remains but its worktree and Git registration metadata are absent".to_string(),
            )
        }
        (Err(path_error), Ok(_), true) if path_error.kind() == ErrorKind::NotFound => base(
            WorktreeReconciliationState::RegisteredMissingPath,
            WorktreeReconciliationAction::Protected,
            "Git registration remains but the authenticated worktree path is missing".to_string(),
        ),
        (Ok(path_metadata), Err(metadata_error), false)
            if path_metadata.is_dir()
                && !path_metadata.file_type().is_symlink()
                && metadata_error.kind() == ErrorKind::NotFound =>
        {
            base(
                WorktreeReconciliationState::PresentDeregistered,
                WorktreeReconciliationAction::Protected,
                "authenticated path is present but deregistered; dirtiness and metadata cleanup are not inferred"
                    .to_string(),
            )
        }
        (Ok(_), Ok(_), true) => match verify_managed_worktree_binding(
            repo,
            repository,
            binding,
            false,
        ) {
            Ok(_) => base(
                WorktreeReconciliationState::Consistent,
                WorktreeReconciliationAction::None,
                "authenticated path and Git registration are consistent".to_string(),
            ),
            Err(error) => base(
                WorktreeReconciliationState::Ambiguous,
                WorktreeReconciliationAction::Protected,
                format!("authenticated binding could not be verified: {error:#}"),
            ),
        },
        (path, metadata, registered) => base(
            WorktreeReconciliationState::Ambiguous,
            WorktreeReconciliationAction::Protected,
            format!(
                "path/metadata/registration state is not safely reconcilable (path={}, metadata={}, registered={registered})",
                path.is_ok(),
                metadata.is_ok(),
            ),
        ),
    }
}

fn mark_reconciliation_index_protected(
    entries: &mut [WorktreeReconciliationEntry],
    entry_index: usize,
    detail: &str,
) {
    if let Some(entry) = entries.get_mut(entry_index) {
        entry.action = WorktreeReconciliationAction::Protected;
        entry.detail = detail.to_string();
    }
}

fn prune_stale_worktree_registrations(
    repo: &Repository,
    allowed_names: &BTreeSet<String>,
    apply: bool,
) -> Result<WorktreeRepositoryPruneReport> {
    let names = repo
        .worktrees()
        .context("failed to enumerate stale Git worktree registrations")?;
    if names.len() > MAX_MANAGED_RECORDS {
        bail!("Git worktree prune exceeds its bounded registration limit");
    }
    let mut report = WorktreeRepositoryPruneReport {
        status: if apply {
            WorktreeRepositoryPruneStatus::Completed
        } else {
            WorktreeRepositoryPruneStatus::DryRun
        },
        stale_registration_count: 0,
        pruned_registration_count: 0,
        protected_registration_count: 0,
    };
    for index in 0..names.len() {
        let Some(name) = names
            .get(index)
            .context("failed to read Git worktree registration during prune")?
        else {
            continue;
        };
        let worktree = repo
            .find_worktree(name)
            .with_context(|| format!("failed to inspect Git worktree '{name}' during prune"))?;
        let mut options = WorktreePruneOptions::new();
        if !worktree
            .is_prunable(Some(&mut options))
            .with_context(|| format!("failed to classify Git worktree '{name}' for prune"))?
        {
            continue;
        }
        report.stale_registration_count = report
            .stale_registration_count
            .checked_add(1)
            .context("stale Git worktree count overflowed")?;
        if !allowed_names.contains(name) {
            report.protected_registration_count = report
                .protected_registration_count
                .checked_add(1)
                .context("protected stale Git worktree count overflowed")?;
            continue;
        }
        if !apply {
            continue;
        }
        let mut options = WorktreePruneOptions::new();
        worktree
            .prune(Some(&mut options))
            .with_context(|| format!("failed to prune stale Git worktree '{name}'"))?;
        report.pruned_registration_count = report
            .pruned_registration_count
            .checked_add(1)
            .context("pruned Git worktree count overflowed")?;
    }
    Ok(report)
}

fn validate_worktree_gc_mode(
    targets_only: bool,
    remove_targets: bool,
    retention: WorktreeRetentionPolicy,
    allowed_untracked_paths: &[PathBuf],
    has_machine_global_retention: bool,
) -> Result<()> {
    if !targets_only {
        return Ok(());
    }
    if !remove_targets {
        bail!("target-only GC conflicts with keeping target directories");
    }
    if worktree_retention_is_configured(retention) {
        bail!("target-only GC does not accept worktree retention filters");
    }
    if !allowed_untracked_paths.is_empty() {
        bail!("target-only GC does not accept full-lane untracked-path allowances");
    }
    if has_machine_global_retention {
        bail!("target-only GC does not accept machine-global orphan cleanup bindings");
    }
    Ok(())
}

#[derive(Debug)]
struct WorktreeSweepRootCandidate {
    group: String,
    root_kind: WorktreeSweepRootKind,
    worktree_root: PathBuf,
    plain_directory: bool,
    repository_hint: Option<PathBuf>,
}

fn discover_workspace_managed_sweep_roots(
    workspace: &Path,
) -> Result<Vec<WorktreeSweepRootCandidate>> {
    let metadata_root = workspace.join(".maco");
    let worktrees_root = metadata_root.join("worktrees");
    let group_entries = match fs::symlink_metadata(&metadata_root) {
        Ok(_) => {
            require_plain_directory(&metadata_root, "workspace metadata root")?;
            match fs::symlink_metadata(&worktrees_root) {
                Ok(_) => bounded_workspace_sweep_group_entries(
                    &worktrees_root,
                    MAX_WORKSPACE_SWEEP_GROUPS,
                    "workspace worktree root",
                )?,
                Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect workspace worktree root {}",
                            worktrees_root.display()
                        )
                    })
                }
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect workspace metadata root {}",
                    metadata_root.display()
                )
            })
        }
    };
    let mut roots = Vec::new();
    for group_entry in group_entries {
        let group = group_entry
            .name
            .to_str()
            .context("workspace worktree group name is not valid UTF-8")?;
        if group.is_empty() || group.len() > MAX_WORKSPACE_SWEEP_GROUP_NAME_BYTES {
            bail!("workspace worktree group name is invalid or out of bounds");
        }
        roots.push(WorktreeSweepRootCandidate {
            group: group.to_string(),
            root_kind: WorktreeSweepRootKind::WorkspaceManaged,
            worktree_root: worktrees_root.join(group),
            plain_directory: group_entry.plain_directory,
            repository_hint: None,
        });
    }
    Ok(roots)
}

fn discover_repository_local_sweep_roots(
    workspace: &Path,
) -> Result<Vec<WorktreeSweepRootCandidate>> {
    let mut roots = Vec::new();
    if path_entry_exists(&workspace.join(".git"))? {
        add_repository_local_sweep_root(workspace, &mut roots)?;
    }

    for child in
        bounded_workspace_sweep_group_entries(workspace, MAX_WORKSPACE_SWEEP_CHILDREN, "workspace")?
    {
        if !child.plain_directory || matches!(child.name.to_str(), Some(".maco" | ".worktrees")) {
            continue;
        }
        let repository = workspace.join(&child.name);
        if path_entry_exists(&repository.join(".git"))? {
            add_repository_local_sweep_root(&repository, &mut roots)?;
        }
    }
    Ok(roots)
}

fn add_repository_local_sweep_root(
    repository: &Path,
    roots: &mut Vec<WorktreeSweepRootCandidate>,
) -> Result<()> {
    let worktree_root = repository.join(".worktrees");
    let metadata = match fs::symlink_metadata(&worktree_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect repository-local worktree root {}",
                    worktree_root.display()
                )
            })
        }
    };
    let group = repository
        .file_name()
        .and_then(OsStr::to_str)
        .context("repository-local worktree repository name is not valid UTF-8")?;
    if group.is_empty() || group.len() > MAX_WORKSPACE_SWEEP_GROUP_NAME_BYTES {
        bail!("repository-local worktree repository name is invalid or out of bounds");
    }
    roots.push(WorktreeSweepRootCandidate {
        group: group.to_string(),
        root_kind: WorktreeSweepRootKind::RepositoryLocal,
        worktree_root,
        plain_directory: metadata.is_dir() && !metadata.file_type().is_symlink(),
        repository_hint: Some(repository.to_path_buf()),
    });
    Ok(())
}

fn add_sweep_pre_gc_failure(
    report: &mut WorktreeSweepReport,
    group: String,
    root_kind: WorktreeSweepRootKind,
    worktree_root: PathBuf,
    failure: WorktreeSweepFailure,
) -> Result<()> {
    report.repository_pre_gc_skipped_count = report
        .repository_pre_gc_skipped_count
        .checked_add(1)
        .context("workspace sweep skipped repository count overflowed")?;
    report.repository_failure_count = report
        .repository_failure_count
        .checked_add(1)
        .context("workspace sweep repository failure count overflowed")?;
    report.repositories.push(WorktreeSweepRepositoryReport {
        group,
        root_kind,
        worktree_root,
        repository: None,
        status: WorktreeSweepRepositoryStatus::Skipped,
        gc_attempted: false,
        effects_may_have_occurred: false,
        failure: Some(failure),
        gc_report: None,
    });
    Ok(())
}

fn add_sweep_gc_counts(sweep: &mut WorktreeSweepReport, gc: &WorktreeGcReport) -> Result<()> {
    sweep.considered_count = sweep
        .considered_count
        .checked_add(gc.considered_count)
        .context("workspace sweep considered count overflowed")?;
    sweep.removed_count = sweep
        .removed_count
        .checked_add(gc.removed_count)
        .context("workspace sweep removed count overflowed")?;
    sweep.protected_count = sweep
        .protected_count
        .checked_add(gc.protected_count)
        .context("workspace sweep protected count overflowed")?;
    sweep.retained_count = sweep
        .retained_count
        .checked_add(gc.retained_count)
        .context("workspace sweep retained count overflowed")?;
    sweep.target_removed_count = sweep
        .target_removed_count
        .checked_add(gc.target_removed_count)
        .context("workspace sweep target count overflowed")?;
    sweep.orphan_removed_count = sweep
        .orphan_removed_count
        .checked_add(gc.orphan_removed_count)
        .context("workspace sweep orphan count overflowed")?;
    sweep.apparent_considered_bytes = sweep
        .apparent_considered_bytes
        .checked_add(gc.apparent_considered_bytes)
        .context("workspace sweep apparent considered bytes overflowed")?;
    sweep.estimated_reclaimable_bytes = sweep
        .estimated_reclaimable_bytes
        .checked_add(gc.estimated_reclaimable_bytes)
        .context("workspace sweep estimated reclaimable bytes overflowed")?;
    sweep.estimated_reclaimed_bytes = sweep
        .estimated_reclaimed_bytes
        .checked_add(gc.estimated_reclaimed_bytes)
        .context("workspace sweep estimated reclaimed bytes overflowed")?;
    Ok(())
}

fn merge_worktree_gc_preview(
    report: &mut WorktreeGcReport,
    mut preview: WorktreeGcReport,
) -> Result<()> {
    report.considered_count = report
        .considered_count
        .checked_add(preview.considered_count)
        .context("worktree GC considered count overflowed")?;
    report.removed_count = report
        .removed_count
        .checked_add(preview.removed_count)
        .context("worktree GC removed count overflowed")?;
    report.protected_count = report
        .protected_count
        .checked_add(preview.protected_count)
        .context("worktree GC protected count overflowed")?;
    report.retained_count = report
        .retained_count
        .checked_add(preview.retained_count)
        .context("worktree GC retained count overflowed")?;
    report.target_removed_count = report
        .target_removed_count
        .checked_add(preview.target_removed_count)
        .context("worktree GC target count overflowed")?;
    report.orphan_removed_count = report
        .orphan_removed_count
        .checked_add(preview.orphan_removed_count)
        .context("worktree GC orphan count overflowed")?;
    report.apparent_considered_bytes = report
        .apparent_considered_bytes
        .checked_add(preview.apparent_considered_bytes)
        .context("worktree GC apparent considered bytes overflowed")?;
    report.estimated_reclaimable_bytes = report
        .estimated_reclaimable_bytes
        .checked_add(preview.estimated_reclaimable_bytes)
        .context("worktree GC estimated reclaimable bytes overflowed")?;
    report.estimated_reclaimed_bytes = report
        .estimated_reclaimed_bytes
        .checked_add(preview.estimated_reclaimed_bytes)
        .context("worktree GC estimated reclaimed bytes overflowed")?;
    report.entries.append(&mut preview.entries);
    report.entries.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(())
}

struct RegisteredWorktreePreviewCandidate {
    name: String,
    branch: Option<String>,
    branch_merged: bool,
    path: PathBuf,
    created_at_unix_nanos: i64,
    untracked_paths: Vec<PathBuf>,
    size: WorktreeGcSizeEstimate,
    rebuild_cost_ms: Option<u64>,
}

/// Classifies Git-registered repository-local lanes that predate the
/// authenticated MACO registry. This path is deliberately preview-only: it
/// makes legacy disk usage visible without granting destructive authority from
/// pathnames alone. Apply mode continues to require an authenticated binding.
fn preview_registered_repository_local_worktrees(
    repository: &Path,
    worktree_root: &Path,
    options: &WorktreeSweepOptions,
    excluded_names: &BTreeSet<String>,
) -> Result<WorktreeGcReport> {
    let allowed_untracked_paths =
        normalize_gc_allowed_untracked_paths(&options.allowed_untracked_paths)?;
    let repo = crate::git_repository::open(repository)
        .with_context(|| format!("failed to open repository {}", repository.display()))?;
    let worktree_root = fs::canonicalize(worktree_root).with_context(|| {
        format!(
            "failed to resolve repository-local worktree root {}",
            worktree_root.display()
        )
    })?;
    require_plain_directory(&worktree_root, "repository-local worktree root")?;
    let primary_head = repo
        .head()
        .context("repository-local preview requires a committed primary HEAD")?
        .peel_to_commit()
        .context("repository-local primary HEAD is not a commit")?
        .id();
    let now = unix_now_nanos()?;
    let mut report = WorktreeGcReport {
        dry_run: true,
        remove_targets: options.remove_targets,
        targets_only: options.targets_only,
        max_age_seconds: options.retention.max_age.map(|age| age.as_secs()),
        max_count: options.retention.max_count,
        max_total_bytes: options.retention.max_total_bytes,
        allowed_untracked_paths: allowed_untracked_paths.iter().cloned().collect(),
        considered_count: 0,
        removed_count: 0,
        protected_count: 0,
        retained_count: 0,
        target_removed_count: 0,
        orphan_removed_count: 0,
        apparent_considered_bytes: 0,
        estimated_reclaimable_bytes: 0,
        estimated_reclaimed_bytes: 0,
        entries: Vec::new(),
    };
    let names = repo
        .worktrees()
        .context("failed to list Git worktrees for repository-local preview")?;
    if names.len() > MAX_WORKSPACE_SWEEP_LANES_PER_GROUP {
        bail!(
            "repository-local preview exceeds its {}-worktree limit",
            MAX_WORKSPACE_SWEEP_LANES_PER_GROUP
        );
    }
    let mut candidates = Vec::new();
    for index in 0..names.len() {
        let Some(name) = names
            .get(index)
            .context("failed to read Git worktree name for repository-local preview")?
        else {
            continue;
        };
        if excluded_names.contains(name) || normalize_agent_id(name).ok().as_deref() != Some(name) {
            continue;
        }
        let worktree = match repo.find_worktree(name) {
            Ok(worktree) => worktree,
            Err(_) => continue,
        };
        if worktree.validate().is_err() {
            continue;
        }
        let path = match fs::canonicalize(worktree.path()) {
            Ok(path) => path,
            Err(_) => continue,
        };
        if path.parent() != Some(worktree_root.as_path()) {
            continue;
        }
        let lane_repo = match crate::git_repository::open(&path) {
            Ok(repo) => repo,
            Err(_) => continue,
        };
        let head = match lane_repo.head().and_then(|head| head.peel_to_commit()) {
            Ok(head) => head,
            Err(_) => continue,
        };
        let branch_oid = head.id();
        let branch = lane_repo
            .head()
            .ok()
            .and_then(|head| head.name().ok().map(str::to_owned))
            .and_then(|name| name.strip_prefix("refs/heads/").map(str::to_owned));
        let branch_merged = branch_oid == primary_head
            || repo
                .graph_descendant_of(primary_head, branch_oid)
                .context("failed to inspect repository-local branch ancestry")?;
        report.considered_count = report
            .considered_count
            .checked_add(1)
            .context("worktree GC considered count overflowed")?;
        let size = match gc_worktree_size_estimate(&path) {
            Ok(size) => size,
            Err(_) => {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: name.to_string(),
                    branch,
                    path,
                    status: WorktreeGcStatus::Protected,
                    reason: WorktreeGcReason::SizeMeasurementFailed,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: None,
                    apparent_target_bytes: None,
                    untracked_paths: Vec::new(),
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }
        };
        report.apparent_considered_bytes = report
            .apparent_considered_bytes
            .checked_add(size.worktree_bytes)
            .context("worktree GC apparent considered bytes overflowed")?;
        let untracked_paths = match preview_registered_worktree_dirtiness(&path)? {
            WorktreeGcDirtiness::Clean => Vec::new(),
            WorktreeGcDirtiness::TrackedDirty => {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: name.to_string(),
                    branch,
                    path,
                    status: WorktreeGcStatus::Protected,
                    reason: WorktreeGcReason::Dirty,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: Some(size.worktree_bytes),
                    apparent_target_bytes: size.target_bytes,
                    untracked_paths: Vec::new(),
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }
            WorktreeGcDirtiness::UntrackedOnly(paths)
                if options.targets_only
                    || paths
                        .iter()
                        .all(|path| allowed_untracked_paths.contains(path)) =>
            {
                paths
            }
            WorktreeGcDirtiness::UntrackedOnly(paths) => {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: name.to_string(),
                    branch,
                    path,
                    status: WorktreeGcStatus::Protected,
                    reason: WorktreeGcReason::UntrackedOnly,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: Some(size.worktree_bytes),
                    apparent_target_bytes: size.target_bytes,
                    untracked_paths: paths,
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }
        };
        let created_at_unix_nanos = fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .and_then(|duration| i64::try_from(duration.as_nanos()).ok())
            .unwrap_or(0);
        candidates.push(RegisteredWorktreePreviewCandidate {
            name: name.to_string(),
            branch,
            branch_merged,
            path: path.clone(),
            created_at_unix_nanos,
            untracked_paths,
            size,
            rebuild_cost_ms: load_lane_rebuild_cost(&path),
        });
    }

    candidates.sort_by(|left, right| {
        cmp_retention_keep_order(
            &RetentionKeepKey {
                rebuild_cost_ms: left.rebuild_cost_ms,
                apparent_bytes: left.size.worktree_bytes,
                created_at_unix_nanos: left.created_at_unix_nanos,
                name: &left.name,
            },
            &RetentionKeepKey {
                rebuild_cost_ms: right.rebuild_cost_ms,
                apparent_bytes: right.size.worktree_bytes,
                created_at_unix_nanos: right.created_at_unix_nanos,
                name: &right.name,
            },
        )
    });
    let mut retention_state = WorktreeGcRetentionState::default();
    for candidate in candidates {
        let target = gc_target_if_present(&candidate.path)?;
        let should_remove = if options.targets_only || !candidate.branch_merged {
            false
        } else {
            let count_expired = options
                .retention
                .max_count
                .is_some_and(|max_count| retention_state.eligible_count >= max_count);
            let age_expired = options.retention.max_age.is_some_and(|max_age| {
                now.checked_sub(candidate.created_at_unix_nanos)
                    .and_then(|age| u128::try_from(age.max(0)).ok())
                    .is_some_and(|age| age >= max_age.as_nanos())
            });
            let mut size_expired = false;
            if !count_expired && !age_expired {
                if let Some(max_total_bytes) = options.retention.max_total_bytes {
                    if retention_state.size_budget_exhausted {
                        size_expired = true;
                    } else {
                        let retained = retention_state
                            .retained_apparent_bytes
                            .checked_add(candidate.size.worktree_bytes)
                            .context("worktree GC retained apparent byte count overflowed")?;
                        if retained <= max_total_bytes {
                            retention_state.retained_apparent_bytes = retained;
                        } else {
                            retention_state.size_budget_exhausted = true;
                            size_expired = true;
                        }
                    }
                }
            }
            retention_state.eligible_count = retention_state
                .eligible_count
                .checked_add(1)
                .context("worktree GC eligible count overflowed")?;
            !worktree_retention_is_configured(options.retention)
                || count_expired
                || age_expired
                || size_expired
        };
        let target_cleanup = options.remove_targets && target.is_some();
        if should_remove || target_cleanup {
            if let Some((reason, evidence)) = target
                .as_ref()
                .and_then(|target| gc_target_liveness_protection(target, &worktree_target_liveness))
            {
                report.protected_count = report
                    .protected_count
                    .checked_add(1)
                    .context("worktree GC protected count overflowed")?;
                report.entries.push(WorktreeGcEntry {
                    name: candidate.name,
                    branch: candidate.branch,
                    path: candidate.path,
                    status: WorktreeGcStatus::Protected,
                    reason,
                    target_path: target.map(|target| target.path),
                    target_liveness: Some(evidence),
                    apparent_worktree_bytes: Some(candidate.size.worktree_bytes),
                    apparent_target_bytes: candidate.size.target_bytes,
                    untracked_paths: candidate.untracked_paths,
                    gate_denial: None,
                    retention_operation_id: None,
                });
                continue;
            }
        }
        if should_remove {
            report.removed_count = report
                .removed_count
                .checked_add(1)
                .context("worktree GC removed count overflowed")?;
            report.estimated_reclaimable_bytes = report
                .estimated_reclaimable_bytes
                .checked_add(candidate.size.worktree_bytes)
                .context("worktree GC estimated reclaimable bytes overflowed")?;
            report.entries.push(WorktreeGcEntry {
                name: candidate.name,
                branch: candidate.branch,
                path: candidate.path,
                status: WorktreeGcStatus::WouldRemove,
                reason: WorktreeGcReason::FinishedBranch,
                target_path: target.map(|target| target.path),
                target_liveness: None,
                apparent_worktree_bytes: Some(candidate.size.worktree_bytes),
                apparent_target_bytes: candidate.size.target_bytes,
                untracked_paths: candidate.untracked_paths,
                gate_denial: None,
                retention_operation_id: None,
            });
            continue;
        }
        report.retained_count = report
            .retained_count
            .checked_add(1)
            .context("worktree GC retained count overflowed")?;
        let (reason, target_path) = match (target, candidate.size.target_bytes) {
            (Some(target), Some(target_bytes)) if options.remove_targets => {
                report.estimated_reclaimable_bytes = report
                    .estimated_reclaimable_bytes
                    .checked_add(target_bytes)
                    .context("worktree GC estimated reclaimable bytes overflowed")?;
                (WorktreeGcReason::TargetWouldRemove, Some(target.path))
            }
            _ if !candidate.branch_merged && !options.targets_only => {
                (WorktreeGcReason::UnmergedBranch, None)
            }
            _ if options.remove_targets => (WorktreeGcReason::NoTarget, None),
            _ => (WorktreeGcReason::RetentionKeep, None),
        };
        report.entries.push(WorktreeGcEntry {
            name: candidate.name,
            branch: candidate.branch,
            path: candidate.path,
            status: WorktreeGcStatus::Retained,
            reason,
            target_path,
            target_liveness: None,
            apparent_worktree_bytes: Some(candidate.size.worktree_bytes),
            apparent_target_bytes: candidate.size.target_bytes,
            untracked_paths: candidate.untracked_paths,
            gate_denial: None,
            retention_operation_id: None,
        });
    }
    Ok(report)
}

fn resolve_sweep_repository(
    workspace: &Path,
    group_root: &Path,
    group: &str,
    root_kind: WorktreeSweepRootKind,
    repository_hint: Option<&Path>,
) -> std::result::Result<PathBuf, WorktreeSweepFailure> {
    // A repository-local root is discovered from an exact primary repository
    // path. Validate that authority directly instead of letting a stale linked
    // worktree registration prevent every healthy sibling from being swept.
    if root_kind == WorktreeSweepRootKind::RepositoryLocal {
        return resolve_sweep_repository_from_workspace(
            workspace,
            group_root,
            group,
            root_kind,
            repository_hint,
        );
    }
    let lane_names = bounded_plain_direct_child_names(
        group_root,
        MAX_WORKSPACE_SWEEP_LANES_PER_GROUP,
        "workspace worktree group",
    )
    .map_err(|error| sweep_failure(WorktreeSweepFailureKind::RepositoryAssociation, error))?;
    let mut lane_associations = BTreeMap::new();
    for lane_name in lane_names {
        if is_reserved_worktree_root_child(&lane_name) {
            continue;
        }
        let lane_path = group_root.join(&lane_name);
        let git_marker = lane_path.join(".git");
        match fs::symlink_metadata(&git_marker) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(sweep_failure(
                    WorktreeSweepFailureKind::RepositoryOpen,
                    anyhow::Error::new(error).context(format!(
                        "failed to inspect lane Git metadata {}",
                        git_marker.display()
                    )),
                ))
            }
        }
        let lane_repo = crate::git_repository::open(&lane_path).map_err(|error| {
            sweep_failure(
                WorktreeSweepFailureKind::RepositoryOpen,
                anyhow::Error::new(error).context(format!(
                    "failed to open lane repository {}",
                    lane_path.display()
                )),
            )
        })?;
        let (common_dir, primary) = validate_lane_sweep_association(
            workspace, group_root, &lane_path, &lane_repo, root_kind,
        )?;
        lane_associations.insert(common_dir, primary);
        if lane_associations.len() > 1 {
            return Err(WorktreeSweepFailure {
                kind: WorktreeSweepFailureKind::AmbiguousRepository,
                message: format!(
                    "workspace worktree group '{}' is associated with multiple primary repositories",
                    group
                ),
            });
        }
    }
    if let Some(primary) = lane_associations.into_values().next() {
        let workspace_primary = resolve_sweep_repository_from_workspace(
            workspace,
            group_root,
            group,
            root_kind,
            repository_hint,
        )?;
        if workspace_primary != primary {
            return Err(WorktreeSweepFailure {
                kind: WorktreeSweepFailureKind::RepositoryAssociation,
                message: format!(
                    "workspace worktree group '{}' resolves to different lane and workspace repositories",
                    group
                ),
            });
        }
        return Ok(primary);
    }

    resolve_sweep_repository_from_workspace(
        workspace,
        group_root,
        group,
        root_kind,
        repository_hint,
    )
}

fn resolve_sweep_repository_from_workspace(
    workspace: &Path,
    group_root: &Path,
    group: &str,
    root_kind: WorktreeSweepRootKind,
    repository_hint: Option<&Path>,
) -> std::result::Result<PathBuf, WorktreeSweepFailure> {
    if root_kind == WorktreeSweepRootKind::RepositoryLocal {
        let candidate_path = repository_hint.ok_or_else(|| WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "repository-local worktree root lacks a primary repository hint".to_string(),
        })?;
        let primary = crate::git_repository::open(candidate_path).map_err(|error| {
            sweep_failure(
                WorktreeSweepFailureKind::RepositoryOpen,
                anyhow::Error::new(error).context(format!(
                    "failed to open primary repository {}",
                    candidate_path.display()
                )),
            )
        })?;
        return validate_primary_sweep_association(
            workspace,
            group_root,
            candidate_path,
            &primary,
            None,
            root_kind,
        )
        .map(|(_, path)| path);
    }

    let child_names =
        bounded_plain_direct_child_names(workspace, MAX_WORKSPACE_SWEEP_CHILDREN, "workspace")
            .map_err(|error| {
                sweep_failure(WorktreeSweepFailureKind::RepositoryAssociation, error)
            })?;
    let mut candidates = Vec::new();
    for child_name in child_names {
        if child_name == OsStr::new(".maco") {
            continue;
        }
        let candidate_group = match child_name.to_str() {
            Some(name) => sanitize_path_segment(name),
            None => "repository".to_string(),
        };
        if candidate_group != group {
            continue;
        }
        let candidate_path = workspace.join(&child_name);
        match fs::symlink_metadata(candidate_path.join(".git")) {
            Ok(_) => candidates.push(candidate_path),
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(sweep_failure(
                    WorktreeSweepFailureKind::RepositoryOpen,
                    anyhow::Error::new(error)
                        .context("failed to inspect primary repository Git metadata"),
                ))
            }
        }
    }
    if candidates.len() > 1 {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::AmbiguousRepository,
            message: format!(
                "workspace worktree group '{}' matches multiple primary repository paths",
                group
            ),
        });
    }
    let Some(candidate_path) = candidates.pop() else {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: format!(
                "workspace worktree group '{}' has no resolvable primary repository",
                group
            ),
        });
    };
    let primary = crate::git_repository::open(&candidate_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryOpen,
            anyhow::Error::new(error).context(format!(
                "failed to open primary repository {}",
                candidate_path.display()
            )),
        )
    })?;
    validate_primary_sweep_association(
        workspace,
        group_root,
        &candidate_path,
        &primary,
        None,
        root_kind,
    )
    .map(|(_, path)| path)
}

fn validate_lane_sweep_association(
    workspace: &Path,
    group_root: &Path,
    lane_path: &Path,
    lane: &Repository,
    root_kind: WorktreeSweepRootKind,
) -> std::result::Result<(PathBuf, PathBuf), WorktreeSweepFailure> {
    let lane_workdir = lane.workdir().ok_or_else(|| WorktreeSweepFailure {
        kind: WorktreeSweepFailureKind::RepositoryAssociation,
        message: format!("lane repository {} is bare", lane_path.display()),
    })?;
    let canonical_lane = fs::canonicalize(lane_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve lane path"),
        )
    })?;
    let canonical_workdir = fs::canonicalize(lane_workdir).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve lane workdir"),
        )
    })?;
    if canonical_workdir != canonical_lane {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: format!(
                "lane repository workdir does not match its exact group child {}",
                lane_path.display()
            ),
        });
    }
    let common_dir = fs::canonicalize(lane.commondir()).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve lane repository common directory"),
        )
    })?;
    let primary_path = common_dir
        .parent()
        .ok_or_else(|| WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "lane repository common directory has no primary parent".to_string(),
        })?
        .to_path_buf();
    let primary = crate::git_repository::open(&primary_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryOpen,
            anyhow::Error::new(error).context(format!(
                "failed to open primary repository {}",
                primary_path.display()
            )),
        )
    })?;
    validate_primary_sweep_association(
        workspace,
        group_root,
        &primary_path,
        &primary,
        Some(&common_dir),
        root_kind,
    )
}

fn validate_primary_sweep_association(
    workspace: &Path,
    group_root: &Path,
    primary_path: &Path,
    primary: &Repository,
    expected_common_dir: Option<&Path>,
    root_kind: WorktreeSweepRootKind,
) -> std::result::Result<(PathBuf, PathBuf), WorktreeSweepFailure> {
    let primary_workdir = primary.workdir().ok_or_else(|| WorktreeSweepFailure {
        kind: WorktreeSweepFailureKind::RepositoryAssociation,
        message: format!("primary repository {} is bare", primary_path.display()),
    })?;
    let canonical_primary = fs::canonicalize(primary_path).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve primary repository path"),
        )
    })?;
    let canonical_workdir = fs::canonicalize(primary_workdir).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve primary repository workdir"),
        )
    })?;
    let canonical_common = fs::canonicalize(primary.commondir()).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error)
                .context("failed to resolve primary repository common directory"),
        )
    })?;
    let embedded_git = canonical_primary.join(".git");
    let embedded_git_metadata = fs::symlink_metadata(&embedded_git).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to inspect primary repository .git"),
        )
    })?;
    if !embedded_git_metadata.is_dir() || embedded_git_metadata.file_type().is_symlink() {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "resolved primary repository does not have a plain embedded .git directory"
                .to_string(),
        });
    }
    let canonical_embedded_git = fs::canonicalize(&embedded_git).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve primary repository .git"),
        )
    })?;
    if canonical_primary != canonical_workdir
        || canonical_common != canonical_embedded_git
        || canonical_common.parent() != Some(canonical_primary.as_path())
        || primary.path() != primary.commondir()
    {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "resolved repository is not an embedded-Git primary worktree".to_string(),
        });
    }
    if expected_common_dir.is_some_and(|expected| expected != canonical_common) {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "lane and primary repository common directories do not match".to_string(),
        });
    }
    let primary_is_in_scope = match root_kind {
        WorktreeSweepRootKind::WorkspaceManaged => canonical_primary.parent() == Some(workspace),
        WorktreeSweepRootKind::RepositoryLocal => {
            canonical_primary == workspace || canonical_primary.parent() == Some(workspace)
        }
    };
    if !primary_is_in_scope {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "primary repository is neither the workspace nor a direct workspace child"
                .to_string(),
        });
    }
    let canonical_group_root = fs::canonicalize(group_root).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error).context("failed to resolve workspace worktree group"),
        )
    })?;
    let expected_group_root = match root_kind {
        WorktreeSweepRootKind::WorkspaceManaged => default_worktree_root(primary),
        WorktreeSweepRootKind::RepositoryLocal => canonical_primary.join(".worktrees"),
    };
    let canonical_expected_root = fs::canonicalize(&expected_group_root).map_err(|error| {
        sweep_failure(
            WorktreeSweepFailureKind::RepositoryAssociation,
            anyhow::Error::new(error)
                .context("failed to resolve primary repository default worktree root"),
        )
    })?;
    if canonical_group_root != canonical_expected_root {
        return Err(WorktreeSweepFailure {
            kind: WorktreeSweepFailureKind::RepositoryAssociation,
            message: "primary repository is not associated with the exact worktree group"
                .to_string(),
        });
    }
    Ok((canonical_common, canonical_primary))
}

fn sweep_failure(kind: WorktreeSweepFailureKind, error: anyhow::Error) -> WorktreeSweepFailure {
    WorktreeSweepFailure {
        kind,
        message: format!("{error:#}"),
    }
}

fn require_plain_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("{label} is not a plain directory: {}", path.display());
    }
    Ok(())
}

struct WorkspaceSweepGroupEntry {
    name: OsString,
    plain_directory: bool,
}

fn bounded_workspace_sweep_group_entries(
    root: &Path,
    limit: usize,
    label: &str,
) -> Result<Vec<WorkspaceSweepGroupEntry>> {
    require_plain_directory(root, label)?;
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(root).with_context(|| format!("failed to read {label} {}", root.display()))?
    {
        if entries.len() >= limit {
            bail!("{label} exceeds the {limit} entry limit");
        }
        let entry = entry.with_context(|| format!("failed to read an entry in {label}"))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect an entry in {label}"))?;
        entries.push(WorkspaceSweepGroupEntry {
            name: entry.file_name(),
            plain_directory: file_type.is_dir() && !file_type.is_symlink(),
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn bounded_plain_direct_child_names(
    root: &Path,
    limit: usize,
    label: &str,
) -> Result<Vec<OsString>> {
    require_plain_directory(root, label)?;
    let mut names = Vec::new();
    let mut observed_entries = 0usize;
    for entry in
        fs::read_dir(root).with_context(|| format!("failed to read {label} {}", root.display()))?
    {
        observed_entries = observed_entries
            .checked_add(1)
            .context("workspace sweep direct entry count overflowed")?;
        if observed_entries > limit {
            bail!("{label} exceeds the {limit} entry limit");
        }
        let entry = entry.with_context(|| format!("failed to read an entry in {label}"))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect an entry in {label}"))?;
        if file_type.is_dir() && !file_type.is_symlink() {
            names.push(entry.file_name());
        }
    }
    names.sort();
    Ok(names)
}

struct WorktreeGcCandidate {
    binding: ManagedWorktreeBinding,
    branch_oid: Oid,
    branch_merged: bool,
    superseded: bool,
    merged_into_reference: Option<String>,
    removal_lease: Option<ManagedWorktreeRemovalLease>,
    untracked_paths: Vec<PathBuf>,
    apparent_worktree_bytes: u64,
    apparent_target_bytes: Option<u64>,
    rebuild_cost_ms: Option<u64>,
}

/// Running retention budget for candidates that take a keep/remove exit.
/// Protected candidates do not update this state: a safety hold must not evict
/// an older finished lane, so `max_count` / `max_total_bytes` can under-count
/// on-disk usage.
#[derive(Clone, Copy, Default)]
struct WorktreeGcRetentionState {
    eligible_count: usize,
    retained_apparent_bytes: u64,
    size_budget_exhausted: bool,
}

struct WorktreeGcRetentionDecision {
    should_remove: bool,
    committed_state: WorktreeGcRetentionState,
}

enum WorktreeGcDirtinessDisposition {
    Eligible(Vec<PathBuf>),
    Protected {
        reason: WorktreeGcReason,
        untracked_paths: Vec<PathBuf>,
    },
}

enum WorktreeGcRemovalOutcome {
    Removed {
        untracked_paths: Vec<PathBuf>,
    },
    TargetIdentityChanged,
    DirtinessChanged {
        reason: WorktreeGcReason,
        untracked_paths: Vec<PathBuf>,
    },
}

struct WorktreeGcRemovalChecks<'a> {
    allowed_untracked_paths: &'a BTreeSet<PathBuf>,
    target_liveness: &'a dyn Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
}

fn remove_gc_candidate(
    repo: &Repository,
    registry_store: &ManagedWorktreeRegistryStore,
    registry_lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    candidate: &WorktreeGcCandidate,
    target: Option<&WorktreeGcTarget>,
    checks: WorktreeGcRemovalChecks<'_>,
) -> Result<WorktreeGcRemovalOutcome> {
    if registry.operations.len() >= MAX_MANAGED_OPERATIONS {
        bail!("managed worktree registry has no remaining operation capacity");
    }
    let removal_lease = candidate
        .removal_lease
        .as_ref()
        .context("worktree GC removal candidate lacks removal authority")?;
    let binding = &candidate.binding;
    let worktree_quarantine_path = deterministic_remove_quarantine_path(
        &binding.root,
        "worktree",
        &binding.name,
        &binding.path_identity,
    );
    let metadata_root = registry_store.repository.common_dir.join("worktrees");
    let metadata_quarantine_path = deterministic_remove_quarantine_path(
        &metadata_root,
        "metadata",
        &binding.name,
        &binding.metadata_dir_identity,
    );
    if target.is_some_and(|target| !worktree_gc_target_identity_is_current(target)) {
        return Ok(WorktreeGcRemovalOutcome::TargetIdentityChanged);
    }
    let final_dirtiness = gc_worktree_dirtiness(&binding.path)?;
    match &final_dirtiness {
        WorktreeGcDirtiness::TrackedDirty => {
            return Ok(WorktreeGcRemovalOutcome::DirtinessChanged {
                reason: WorktreeGcReason::Dirty,
                untracked_paths: Vec::new(),
            })
        }
        WorktreeGcDirtiness::UntrackedOnly(paths)
            if !paths
                .iter()
                .all(|path| checks.allowed_untracked_paths.contains(path)) =>
        {
            return Ok(WorktreeGcRemovalOutcome::DirtinessChanged {
                reason: WorktreeGcReason::UntrackedOnly,
                untracked_paths: paths.clone(),
            })
        }
        WorktreeGcDirtiness::Clean | WorktreeGcDirtiness::UntrackedOnly(_) => {}
    }
    let final_untracked_paths = match &final_dirtiness {
        WorktreeGcDirtiness::UntrackedOnly(paths) => paths.clone(),
        WorktreeGcDirtiness::Clean | WorktreeGcDirtiness::TrackedDirty => Vec::new(),
    };
    let dirtiness = managed_gc_dirtiness_snapshot(&final_dirtiness)?;
    let target_snapshot = match target {
        Some(target) => ManagedGcTargetSnapshot::Present {
            identity: target.identity.clone(),
        },
        None => ManagedGcTargetSnapshot::Absent,
    };
    let operation = ManagedWorktreeOperation {
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
        delete_branch: false,
        force: true,
        expected_branch_oid: Some(candidate.branch_oid.to_string()),
        gc_dirtiness_checksum: None,
        removal_safety: Some(ManagedRemovalSafety::GarbageCollection {
            dirtiness,
            target: target_snapshot,
        }),
        worktree_quarantine_path: Some(worktree_quarantine_path),
        worktree_quarantine_identity: None,
        metadata_quarantine_path: Some(metadata_quarantine_path),
        metadata_quarantine_identity: None,
    };
    registry
        .operations
        .insert(binding.name.clone(), operation.clone());
    registry_store.save(registry_lock, registry)?;
    recover_remove_operation_with_lease_using_target_liveness(
        repo,
        registry_store,
        registry_lock,
        registry,
        operation,
        Some(removal_lease),
        checks.target_liveness,
    )?;
    Ok(WorktreeGcRemovalOutcome::Removed {
        untracked_paths: final_untracked_paths,
    })
}

fn resolve_worktree_root(repo: &Repository, requested_root: Option<PathBuf>) -> Result<PathBuf> {
    let root = requested_root.unwrap_or_else(|| default_worktree_root(repo));
    let root = if root.is_absolute() {
        root
    } else {
        repo.workdir()
            .context("worktree GC requires a non-bare repository")?
            .join(root)
    };
    match fs::symlink_metadata(&root) {
        Ok(_) => SafeRoot::open_existing(&root)
            .map(|root| root.path().to_path_buf())
            .with_context(|| format!("failed to bind worktree root {}", root.display())),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(root),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect worktree root {}", root.display())),
    }
}

fn active_claim_agent_ids(repo: &Repository) -> Result<BTreeSet<String>> {
    let state_root = repo.commondir().join("maco").join("state");
    if !path_entry_exists(&state_root.join(ClaimsStatePresence::Authenticated.root_name()))?
        && !path_entry_exists(&state_root.join(ClaimsStatePresence::Legacy.file_name()))?
    {
        return Ok(BTreeSet::new());
    }
    let repo_path = repo.workdir().unwrap_or_else(|| repo.path());
    let claims = SyncStore::open(repo_path)?.snapshot()?;
    Ok(claims
        .into_iter()
        .map(|claim| claim.agent_id)
        .collect::<BTreeSet<_>>())
}

enum ClaimsStatePresence {
    Authenticated,
    Legacy,
}

impl ClaimsStatePresence {
    fn root_name(&self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated-claims-state-v1",
            Self::Legacy => "claims.json",
        }
    }

    fn file_name(&self) -> &'static str {
        self.root_name()
    }
}

fn is_active_lease_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message.contains("already held")
        || message.contains("active cooperative execution lease")
        || message.contains("state lock")
}

enum WorktreeGcDirtiness {
    Clean,
    TrackedDirty,
    UntrackedOnly(Vec<PathBuf>),
}

fn gc_worktree_dirtiness(path: &Path) -> Result<WorktreeGcDirtiness> {
    let status = match bounded_repository_gc_status_paths(
        path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_GC_STATUS_TIMEOUT,
    ) {
        Ok(status) => status,
        Err(error) if gc_status_failed_without_delegated_user_manager(&error) => {
            bounded_repository_gc_status_paths_trusted(
                path,
                MAX_WORKTREE_STATUS_ENTRIES,
                MAX_WORKTREE_STATUS_OUTPUT_BYTES,
                WORKTREE_GC_STATUS_TIMEOUT,
            )
            .with_context(|| {
                format!(
                    "verified GC dirtiness is unavailable without a delegated systemd user manager; trusted fallback also failed for {}",
                    path.display()
                )
            })?
        }
        Err(error) => return Err(error),
    };
    gc_dirtiness_from_status(status)
}

fn gc_status_failed_without_delegated_user_manager(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<ProcessRunError>()
            .is_some_and(ProcessRunError::is_missing_delegated_user_manager)
            || cause
                .to_string()
                .contains("is not inside a delegated systemd user manager")
    })
}

fn gc_dirtiness_from_status(status: BoundedStatusPathRecords) -> Result<WorktreeGcDirtiness> {
    if status.is_empty() {
        return Ok(WorktreeGcDirtiness::Clean);
    }
    if status.iter().any(|(_, status)| *status != [b'?', b'?']) {
        return Ok(WorktreeGcDirtiness::TrackedDirty);
    }
    Ok(WorktreeGcDirtiness::UntrackedOnly(
        status.into_iter().map(|(path, _)| path).collect(),
    ))
}

fn preview_registered_worktree_dirtiness(path: &Path) -> Result<WorktreeGcDirtiness> {
    match bounded_repository_status_paths(
        path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_GC_STATUS_TIMEOUT,
    ) {
        Ok(status) => gc_dirtiness_from_status(status),
        Err(_) => {
            // This fallback is restricted to the non-destructive legacy
            // preview. It cannot authorize apply-mode removal. Some hosts
            // cannot provide the process-containment mount layout required by
            // the bounded Git subprocess, but libgit2 can still expose the
            // ordinary tracked/untracked status needed to make old registered
            // lanes visible.
            let repo = crate::git_repository::open(path).with_context(|| {
                format!(
                    "failed to open registered worktree preview {}",
                    path.display()
                )
            })?;
            let mut options = StatusOptions::new();
            options
                .include_untracked(true)
                .recurse_untracked_dirs(true)
                .include_ignored(false)
                .include_unmodified(false)
                .renames_head_to_index(false)
                .renames_index_to_workdir(false);
            let statuses = repo
                .statuses(Some(&mut options))
                .context("failed to inspect registered worktree preview status")?;
            if statuses.len() > MAX_WORKTREE_STATUS_ENTRIES {
                bail!("registered worktree preview status exceeds its entry limit");
            }
            let mut total_bytes = 0usize;
            let mut untracked = Vec::new();
            for entry in statuses.iter() {
                let entry_path = entry
                    .path()
                    .context("registered worktree preview status path is not valid UTF-8")?;
                total_bytes = total_bytes
                    .checked_add(entry_path.len())
                    .context("registered worktree preview status byte count overflowed")?;
                if total_bytes > MAX_WORKTREE_STATUS_OUTPUT_BYTES {
                    bail!("registered worktree preview status exceeds its output limit");
                }
                if entry.status() != Status::WT_NEW {
                    return Ok(WorktreeGcDirtiness::TrackedDirty);
                }
                let path = PathBuf::from(entry_path);
                if path.is_absolute()
                    || path
                        .components()
                        .any(|component| !matches!(component, std::path::Component::Normal(_)))
                {
                    bail!("registered worktree preview returned an unsafe status path");
                }
                untracked.push(path);
            }
            untracked.sort();
            untracked.dedup();
            if untracked.is_empty() {
                Ok(WorktreeGcDirtiness::Clean)
            } else {
                Ok(WorktreeGcDirtiness::UntrackedOnly(untracked))
            }
        }
    }
}

fn managed_gc_dirtiness_snapshot(
    dirtiness: &WorktreeGcDirtiness,
) -> Result<ManagedGcDirtinessSnapshot> {
    match dirtiness {
        WorktreeGcDirtiness::Clean => Ok(ManagedGcDirtinessSnapshot::Clean),
        WorktreeGcDirtiness::TrackedDirty => {
            bail!("tracked-dirty worktree state cannot be approved for GC")
        }
        WorktreeGcDirtiness::UntrackedOnly(paths) => {
            Ok(ManagedGcDirtinessSnapshot::UntrackedOnly {
                paths: paths
                    .iter()
                    .map(|path| worktree_report_path_wire(path))
                    .collect(),
            })
        }
    }
}

fn normalize_gc_allowed_untracked_paths(paths: &[PathBuf]) -> Result<BTreeSet<PathBuf>> {
    if paths.len() > MAX_GC_ALLOWED_UNTRACKED_PATHS {
        bail!("untracked path allowlist exceeds its {MAX_GC_ALLOWED_UNTRACKED_PATHS}-entry limit");
    }
    let mut normalized = BTreeSet::new();
    let mut total_bytes = 0usize;
    for path in paths {
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!(
                "allowed untracked path must be an exact repository-relative path: {}",
                path.display()
            );
        }
        let path_bytes = worktree_path_native_bytes(path);
        if path_bytes > MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES {
            bail!(
                "allowed untracked path exceeds its {MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES}-byte limit"
            );
        }
        total_bytes = total_bytes
            .checked_add(path_bytes)
            .context("untracked path allowlist byte count overflowed")?;
        if total_bytes > MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES {
            bail!(
                "untracked path allowlist exceeds its {MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES}-byte aggregate limit"
            );
        }
        normalized.insert(path.clone());
    }
    Ok(normalized)
}

fn worktree_path_native_bytes(path: &Path) -> usize {
    #[cfg(unix)]
    {
        return path.as_os_str().as_bytes().len();
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        return path.as_os_str().encode_wide().count().saturating_mul(2);
    }

    #[allow(unreachable_code)]
    path.to_string_lossy().len()
}

fn gc_created_at(binding: &ManagedWorktreeBinding) -> i64 {
    binding.created_at_unix_nanos.unwrap_or(0)
}

const LANE_REBUILD_COST_RELATIVE: &str = ".maco/lane-rebuild-cost.json";
const MAX_LANE_REBUILD_COST_BYTES: u64 = 4096;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaneRebuildCostRecord {
    rebuild_cost_ms: u64,
}

/// Records the measured wall-clock of the build that produced a lane `target/`.
///
/// The sidecar lives under `.maco/`, which worktree status already excludes, so
/// recording cost does not dirty the lane against GC.
pub fn record_lane_rebuild_cost(worktree_path: &Path, rebuild_cost_ms: u64) -> Result<()> {
    let path = worktree_path.join(LANE_REBUILD_COST_RELATIVE);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create lane rebuild-cost directory {}",
                parent.display()
            )
        })?;
    }
    let encoded = serde_json::to_vec(&LaneRebuildCostRecord { rebuild_cost_ms })
        .context("failed to encode lane rebuild cost")?;
    fs::write(&path, encoded)
        .with_context(|| format!("failed to write lane rebuild cost {}", path.display()))?;
    Ok(())
}

/// Loads a recorded rebuild cost, or `None` when the lane has no usable record.
pub fn load_lane_rebuild_cost(worktree_path: &Path) -> Option<u64> {
    let path = worktree_path.join(LANE_REBUILD_COST_RELATIVE);
    let metadata = fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_LANE_REBUILD_COST_BYTES {
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    serde_json::from_slice::<LaneRebuildCostRecord>(&bytes)
        .ok()
        .map(|record| record.rebuild_cost_ms)
}

/// Landlord / GreedyDual-Size keep order: higher rebuild-cost per byte first.
///
/// Unknown cost falls back to recency so existing age/count/size tests keep
/// their newest-prefix behavior until a lane records a rebuild cost.
#[derive(Clone, Copy)]
struct RetentionKeepKey<'a> {
    rebuild_cost_ms: Option<u64>,
    apparent_bytes: u64,
    created_at_unix_nanos: i64,
    name: &'a str,
}

fn cmp_retention_keep_order(
    left: &RetentionKeepKey<'_>,
    right: &RetentionKeepKey<'_>,
) -> std::cmp::Ordering {
    match (left.rebuild_cost_ms, right.rebuild_cost_ms) {
        (Some(left_cost), Some(right_cost)) => {
            let left_density =
                u128::from(left_cost).saturating_mul(u128::from(right.apparent_bytes.max(1)));
            let right_density =
                u128::from(right_cost).saturating_mul(u128::from(left.apparent_bytes.max(1)));
            right_density
                .cmp(&left_density)
                .then_with(|| {
                    left.created_at_unix_nanos
                        .cmp(&right.created_at_unix_nanos)
                        .reverse()
                })
                .then_with(|| left.name.cmp(right.name))
        }
        _ => left
            .created_at_unix_nanos
            .cmp(&right.created_at_unix_nanos)
            .reverse()
            .then_with(|| left.name.cmp(right.name)),
    }
}

fn worktree_retention_is_configured(retention: WorktreeRetentionPolicy) -> bool {
    retention.max_age.is_some()
        || retention.max_count.is_some()
        || retention.max_total_bytes.is_some()
}

fn retention_age_or_count_selects_gc_candidate(
    binding: &ManagedWorktreeBinding,
    index: usize,
    now: i64,
    retention: WorktreeRetentionPolicy,
) -> bool {
    let count_expired = retention
        .max_count
        .is_some_and(|max_count| index >= max_count);
    let age_expired = retention.max_age.is_some_and(|max_age| {
        binding
            .created_at_unix_nanos
            .and_then(|created| now.checked_sub(created))
            .and_then(|age_nanos| u128::try_from(age_nanos.max(0)).ok())
            .is_some_and(|age_nanos| age_nanos >= max_age.as_nanos())
    });
    count_expired || age_expired
}

fn worktree_gc_retention_decision(
    candidate: &WorktreeGcCandidate,
    now: i64,
    targets_only: bool,
    retention: WorktreeRetentionPolicy,
    state: WorktreeGcRetentionState,
) -> Result<WorktreeGcRetentionDecision> {
    if candidate.superseded && !targets_only {
        return Ok(WorktreeGcRetentionDecision {
            should_remove: true,
            committed_state: state,
        });
    }
    if !candidate.branch_merged && !candidate.superseded && !targets_only {
        return Ok(WorktreeGcRetentionDecision {
            should_remove: false,
            committed_state: state,
        });
    }
    let age_or_count_selects = retention_age_or_count_selects_gc_candidate(
        &candidate.binding,
        state.eligible_count,
        now,
        retention,
    );
    let mut committed_state = state;
    committed_state.eligible_count = committed_state
        .eligible_count
        .checked_add(1)
        .context("worktree GC eligible count overflowed")?;
    let size_selects = if age_or_count_selects {
        false
    } else if let Some(max_total_bytes) = retention.max_total_bytes {
        if state.size_budget_exhausted {
            true
        } else {
            let retained_bytes = state
                .retained_apparent_bytes
                .checked_add(candidate.apparent_worktree_bytes)
                .context("worktree GC retained apparent byte count overflowed")?;
            if retained_bytes <= max_total_bytes {
                committed_state.retained_apparent_bytes = retained_bytes;
                false
            } else {
                committed_state.size_budget_exhausted = true;
                true
            }
        }
    } else {
        false
    };
    Ok(WorktreeGcRetentionDecision {
        should_remove: !targets_only
            && (!worktree_retention_is_configured(retention)
                || age_or_count_selects
                || size_selects),
        committed_state,
    })
}

fn worktree_gc_completion_reason(candidate: &WorktreeGcCandidate) -> WorktreeGcReason {
    if candidate.superseded {
        WorktreeGcReason::SupersededLane
    } else {
        WorktreeGcReason::FinishedBranch
    }
}

fn normalize_gc_agent_id_set(ids: &BTreeSet<String>, label: &str) -> Result<BTreeSet<String>> {
    ids.iter()
        .map(|id| {
            let normalized = normalize_agent_id(id)?;
            if normalized != *id {
                bail!("{label} worktree selector '{id}' is not canonical");
            }
            Ok(normalized)
        })
        .collect()
}

fn normalize_gc_supersession_map(
    superseded_by: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    superseded_by
        .iter()
        .map(|(predecessor, successor)| {
            let normalized_predecessor = normalize_agent_id(predecessor)?;
            let normalized_successor = normalize_agent_id(successor)?;
            if normalized_predecessor != *predecessor || normalized_successor != *successor {
                bail!(
                    "retry supersession selectors '{predecessor}' -> '{successor}' are not canonical"
                );
            }
            Ok((normalized_predecessor, normalized_successor))
        })
        .collect()
}

fn resolve_lifecycle_trunk_tip(repo: &Repository, reference: &str) -> Result<(String, Oid)> {
    if !reference.starts_with("refs/heads/")
        || reference.trim() != reference
        || reference.contains("..")
    {
        bail!("lifecycle trunk reference must be an exact local reference such as refs/heads/main");
    }
    let reference_name =
        git2::Reference::normalize_name(reference, git2::ReferenceFormat::ALLOW_ONELEVEL)
            .context("lifecycle trunk reference is invalid")?;
    if reference_name != reference {
        bail!("lifecycle trunk reference is not canonical");
    }
    let trunk = repo
        .find_reference(reference)
        .with_context(|| format!("lifecycle trunk reference '{reference}' was not found"))?;
    if !trunk.is_branch() {
        bail!("lifecycle trunk reference is not a local branch");
    }
    let oid = trunk
        .peel_to_commit()
        .with_context(|| format!("lifecycle trunk reference '{reference}' is not a commit"))?
        .id();
    Ok((reference.to_string(), oid))
}

fn worktree_gc_candidate_remains_merged(
    repo: &Repository,
    candidate: &WorktreeGcCandidate,
) -> Result<bool> {
    let Some(reference) = candidate.merged_into_reference.as_deref() else {
        return Ok(true);
    };
    let (_, trunk_oid) = resolve_lifecycle_trunk_tip(repo, reference)?;
    Ok(candidate.branch_oid == trunk_oid
        || repo
            .graph_descendant_of(trunk_oid, candidate.branch_oid)
            .context("failed to recheck managed branch ancestry from trunk at apply boundary")?)
}

fn worktree_gc_dirtiness_disposition(
    dirtiness: WorktreeGcDirtiness,
    targets_only: bool,
    allowed_untracked_paths: &BTreeSet<PathBuf>,
) -> WorktreeGcDirtinessDisposition {
    match dirtiness {
        WorktreeGcDirtiness::Clean => WorktreeGcDirtinessDisposition::Eligible(Vec::new()),
        WorktreeGcDirtiness::TrackedDirty => WorktreeGcDirtinessDisposition::Protected {
            reason: WorktreeGcReason::Dirty,
            untracked_paths: Vec::new(),
        },
        WorktreeGcDirtiness::UntrackedOnly(paths)
            if targets_only
                || paths
                    .iter()
                    .all(|path| allowed_untracked_paths.contains(path)) =>
        {
            WorktreeGcDirtinessDisposition::Eligible(paths)
        }
        WorktreeGcDirtiness::UntrackedOnly(paths) => WorktreeGcDirtinessDisposition::Protected {
            reason: WorktreeGcReason::UntrackedOnly,
            untracked_paths: paths,
        },
    }
}

fn worktree_gc_target_bindings_match(
    expected: Option<&WorktreeGcTarget>,
    observed: Option<&WorktreeGcTarget>,
) -> bool {
    match (expected, observed) {
        (None, None) => true,
        (Some(expected), Some(observed)) => {
            expected.path == observed.path
                && expected.canonical_path == observed.canonical_path
                && expected.identity == observed.identity
                && expected.lane_canonical_path == observed.lane_canonical_path
                && expected.lane_identity == observed.lane_identity
        }
        (None, Some(_)) | (Some(_), None) => false,
    }
}

fn add_gc_candidate_protection(
    report: &mut WorktreeGcReport,
    candidate: &WorktreeGcCandidate,
    reason: WorktreeGcReason,
    target_path: Option<PathBuf>,
    target_liveness: Option<WorktreeTargetLivenessEvidence>,
    untracked_paths: Vec<PathBuf>,
) -> Result<()> {
    report.protected_count = report
        .protected_count
        .checked_add(1)
        .context("worktree GC protected count overflowed")?;
    report.entries.push(WorktreeGcEntry {
        name: candidate.binding.name.clone(),
        branch: Some(candidate.binding.branch.clone()),
        path: candidate.binding.path.clone(),
        status: WorktreeGcStatus::Protected,
        reason,
        target_path,
        target_liveness,
        apparent_worktree_bytes: Some(candidate.apparent_worktree_bytes),
        apparent_target_bytes: candidate.apparent_target_bytes,
        untracked_paths,
        gate_denial: None,
        retention_operation_id: None,
    });
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorktreeGcSizeEstimate {
    worktree_bytes: u64,
    target_bytes: Option<u64>,
}

fn gc_worktree_size_estimate(worktree_path: &Path) -> Result<WorktreeGcSizeEstimate> {
    let target = gc_target_if_present(worktree_path)?;
    let mut worktree_bytes = 0u64;
    let mut target_bytes = 0u64;
    BoundedTreeWalker::walk_with(
        worktree_path,
        BoundedTreeWalkLimits {
            max_depth: 128,
            max_entries: MAX_WORKTREE_GC_SIZE_ENTRIES,
            max_path_bytes: MAX_PERSISTED_PATH_BYTES,
            max_total_path_bytes: MAX_WORKTREE_GC_SIZE_TOTAL_PATH_BYTES,
            max_duration: WORKTREE_GC_SIZE_TIMEOUT,
            // Linux supplies statx mount identities for strict mount confinement.
            // Other Unix platforms still get descriptor-relative, no-follow walking.
            same_device: cfg!(target_os = "linux"),
        },
        |entry| {
            worktree_bytes = worktree_bytes
                .checked_add(entry.size_bytes)
                .context("worktree apparent byte estimate overflowed")?;
            if target.is_some() && entry.relative_path.starts_with(Path::new("target")) {
                target_bytes = target_bytes
                    .checked_add(entry.size_bytes)
                    .context("worktree target apparent byte estimate overflowed")?;
            }
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Skip
            })
        },
    )
    .with_context(|| {
        format!(
            "failed to measure apparent bytes beneath managed worktree {}",
            worktree_path.display()
        )
    })?;
    Ok(WorktreeGcSizeEstimate {
        worktree_bytes,
        target_bytes: target.map(|_| target_bytes),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorktreeGcTarget {
    path: PathBuf,
    canonical_path: PathBuf,
    identity: FileIdentity,
    lane_canonical_path: PathBuf,
    lane_identity: FileIdentity,
}

fn gc_target_if_present(worktree_path: &Path) -> Result<Option<WorktreeGcTarget>> {
    let target_path = worktree_path.join("target");
    match fs::symlink_metadata(&target_path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            let identity = identity_for_path(&target_path)?;
            let canonical_path = fs::canonicalize(&target_path).with_context(|| {
                format!(
                    "failed to resolve worktree target {}",
                    target_path.display()
                )
            })?;
            let lane_canonical_path = fs::canonicalize(worktree_path).with_context(|| {
                format!(
                    "failed to resolve managed worktree {}",
                    worktree_path.display()
                )
            })?;
            let lane_identity = identity_for_path(worktree_path)?;
            Ok(Some(WorktreeGcTarget {
                path: target_path,
                canonical_path,
                identity,
                lane_canonical_path,
                lane_identity,
            }))
        }
        Ok(_) => bail!(
            "worktree target path is not a plain directory: {}",
            target_path.display()
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {}", target_path.display()))
        }
    }
}

fn gc_target_at_apply_boundary(
    worktree_path: &Path,
    preflight_target: Option<&WorktreeGcTarget>,
) -> Result<Option<WorktreeGcTarget>> {
    match gc_target_if_present(worktree_path) {
        Ok(target) => Ok(target),
        Err(error) if preflight_target.is_some() => {
            let target_path = worktree_path.join("target");
            match fs::symlink_metadata(&target_path) {
                Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => Ok(None),
                Err(inspect_error) if inspect_error.kind() == ErrorKind::NotFound => Ok(None),
                Ok(_) | Err(_) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn worktree_gc_target_identity_is_current(target: &WorktreeGcTarget) -> bool {
    identity_for_path(&target.path)
        .ok()
        .is_some_and(|identity| identity == target.identity)
}

fn target_identity_changed_evidence() -> WorktreeTargetLivenessEvidence {
    target_liveness_evidence(
        None,
        WorktreeTargetLivenessSource::TargetIdentity,
        WorktreeTargetLivenessCause::IdentityChanged,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WorktreeTargetLiveness {
    Clear,
    Live(WorktreeTargetLivenessEvidence),
    Unknown(WorktreeTargetLivenessEvidence),
}

fn gc_target_liveness_protection<F>(
    target: &WorktreeGcTarget,
    target_liveness: &F,
) -> Option<(WorktreeGcReason, WorktreeTargetLivenessEvidence)>
where
    F: Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
{
    match target_liveness(target) {
        WorktreeTargetLiveness::Clear => None,
        WorktreeTargetLiveness::Live(evidence) => Some((WorktreeGcReason::LiveTarget, evidence)),
        WorktreeTargetLiveness::Unknown(evidence) => {
            Some((WorktreeGcReason::TargetLivenessUnknown, evidence))
        }
    }
}

fn target_liveness_evidence(
    pid: Option<u32>,
    source: WorktreeTargetLivenessSource,
    cause: WorktreeTargetLivenessCause,
) -> WorktreeTargetLivenessEvidence {
    WorktreeTargetLivenessEvidence { pid, source, cause }
}

#[cfg(target_os = "linux")]
fn worktree_target_liveness(target: &WorktreeGcTarget) -> WorktreeTargetLiveness {
    if identity_for_path(&target.path)
        .ok()
        .as_ref()
        .is_none_or(|identity| identity != &target.identity)
    {
        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
            None,
            WorktreeTargetLivenessSource::TargetIdentity,
            WorktreeTargetLivenessCause::IdentityChanged,
        ));
    }
    let deadline = match Instant::now().checked_add(WORKTREE_GC_PROC_SCAN_TIMEOUT) {
        Some(deadline) => deadline,
        None => {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                None,
                WorktreeTargetLivenessSource::ProcScan,
                WorktreeTargetLivenessCause::LimitExceeded,
            ))
        }
    };
    let entries = match fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                None,
                WorktreeTargetLivenessSource::ProcScan,
                WorktreeTargetLivenessCause::ReadFailed,
            ))
        }
    };
    let current_uid = unsafe { libc::geteuid() };
    let mut observed = 0usize;
    let mut scan_unknown = None;
    for entry in entries {
        if Instant::now() >= deadline {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                None,
                WorktreeTargetLivenessSource::ProcScan,
                WorktreeTargetLivenessCause::TimedOut,
            ));
        }
        observed = match observed.checked_add(1) {
            Some(observed) if observed <= MAX_WORKTREE_GC_PROC_ENTRIES => observed,
            _ => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    None,
                    WorktreeTargetLivenessSource::ProcScan,
                    WorktreeTargetLivenessCause::LimitExceeded,
                ))
            }
        };
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    None,
                    WorktreeTargetLivenessSource::ProcScan,
                    WorktreeTargetLivenessCause::ReadFailed,
                ))
            }
        };
        let pid = match entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            Some(pid) => pid,
            None => continue,
        };
        let process_root = PathBuf::from("/proc").join(pid.to_string());
        let metadata = match fs::metadata(&process_root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    Some(pid),
                    WorktreeTargetLivenessSource::ProcScan,
                    WorktreeTargetLivenessCause::ReadFailed,
                ))
            }
        };
        if metadata.uid() != current_uid {
            continue;
        }
        match linux_process_target_liveness(&process_root, pid, target, deadline) {
            WorktreeTargetLiveness::Clear => {}
            WorktreeTargetLiveness::Live(evidence) => {
                return WorktreeTargetLiveness::Live(evidence)
            }
            WorktreeTargetLiveness::Unknown(evidence) => {
                scan_unknown.get_or_insert(evidence);
            }
        }
    }
    match scan_unknown {
        Some(evidence) => WorktreeTargetLiveness::Unknown(evidence),
        None => WorktreeTargetLiveness::Clear,
    }
}

#[cfg(target_os = "linux")]
fn linux_process_target_liveness(
    process_root: &Path,
    pid: u32,
    target: &WorktreeGcTarget,
    deadline: Instant,
) -> WorktreeTargetLiveness {
    if linux_process_is_inert_user_manager(process_root) {
        // The per-user systemd manager can be non-dumpable even to its owner,
        // which makes environ/root/ns reads fail. It does not execute build
        // work itself; any spawned build process is enumerated independently.
        // Recognize only the exact init.scope manager shape so unrelated
        // unreadable processes continue to fail closed.
        return WorktreeTargetLiveness::Clear;
    }
    let cargo_like = linux_process_is_cargo_like(process_root);
    let environment = linux_process_environ(process_root);
    let (has_explicit_target_dir, has_empty_target_dir) = match &environment {
        Ok(Some(environ)) => environ.split(|byte| *byte == 0).fold(
            (false, false),
            |(has_explicit, has_empty), variable| {
                let Some(value) = variable.strip_prefix(b"CARGO_TARGET_DIR=") else {
                    return (has_explicit, has_empty);
                };
                (true, has_empty || value.is_empty())
            },
        ),
        Ok(None) | Err(_) => (false, false),
    };
    if has_empty_target_dir {
        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
            Some(pid),
            WorktreeTargetLivenessSource::ProcessEnvironment,
            WorktreeTargetLivenessCause::InvalidValue,
        ));
    }
    if !cargo_like
        && !has_explicit_target_dir
        && linux_process_is_non_build_user_service(process_root)
    {
        // Non-dumpable user services commonly deny environ/root/ns reads. The
        // service process itself is not a build process; any cargo/rustc child
        // remains a separate /proc entry and is scanned normally. A readable
        // explicit target directory means the service-launched process itself
        // carries build-target authority and must be evaluated. Limit this
        // exception to an exact systemd user-service cgroup, no such explicit
        // target, and a readable, non-empty command line.
        return WorktreeTargetLiveness::Clear;
    }
    let process_view = match LinuxProcessView::open(process_root) {
        Ok(Some(view)) => view,
        Ok(None) => return WorktreeTargetLiveness::Clear,
        Err(_)
            if !cargo_like
                && !has_explicit_target_dir
                && linux_process_cmdline(process_root)
                    .ok()
                    .flatten()
                    .is_some_and(|cmdline| !cmdline.is_empty()) =>
        {
            // A readable non-build command line plus an unreadable namespace
            // is the common non-dumpable desktop-application shape. It cannot
            // resolve paths for build work itself; any cargo/rustc descendant
            // is scanned independently.
            return WorktreeTargetLiveness::Clear;
        }
        Err(cause) => {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                Some(pid),
                WorktreeTargetLivenessSource::MountNamespace,
                cause,
            ))
        }
    };
    let mut environment_unknown = None;
    match environment {
        Ok(Some(environ)) => {
            for variable in environ.split(|byte| *byte == 0) {
                let Some(value) = variable.strip_prefix(b"CARGO_TARGET_DIR=") else {
                    continue;
                };
                if value.is_empty() {
                    environment_unknown.get_or_insert_with(|| {
                        target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::ProcessEnvironment,
                            WorktreeTargetLivenessCause::InvalidValue,
                        )
                    });
                    continue;
                }
                let configured = PathBuf::from(OsString::from_vec(value.to_vec()));
                let configured = match process_view.resolve_configured_path(&configured) {
                    Ok(configured) => configured,
                    Err(cause) => {
                        environment_unknown.get_or_insert_with(|| {
                            target_liveness_evidence(
                                Some(pid),
                                WorktreeTargetLivenessSource::MountNamespace,
                                cause,
                            )
                        });
                        continue;
                    }
                };
                match process_path_overlaps_target(&configured, target) {
                    WorktreePathOverlap::Overlap => {
                        return WorktreeTargetLiveness::Live(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::CargoTargetDir,
                            WorktreeTargetLivenessCause::PathOverlap,
                        ));
                    }
                    WorktreePathOverlap::Unknown => {
                        environment_unknown.get_or_insert_with(|| {
                            target_liveness_evidence(
                                Some(pid),
                                WorktreeTargetLivenessSource::MountNamespace,
                                WorktreeTargetLivenessCause::NamespaceUnresolved,
                            )
                        });
                    }
                    WorktreePathOverlap::Separate => {}
                }
            }
        }
        Ok(None) => return WorktreeTargetLiveness::Clear,
        Err(cause) => {
            environment_unknown = Some(target_liveness_evidence(
                Some(pid),
                WorktreeTargetLivenessSource::ProcessEnvironment,
                cause,
            ));
        }
    }

    let mut unknown = environment_unknown;
    match linux_process_cmdline_liveness(&process_view, pid, target, cargo_like) {
        WorktreeTargetLiveness::Live(evidence) => return WorktreeTargetLiveness::Live(evidence),
        WorktreeTargetLiveness::Unknown(evidence) => {
            unknown.get_or_insert(evidence);
        }
        WorktreeTargetLiveness::Clear => {}
    }

    match linux_process_target_association(&process_view, pid, target, deadline, cargo_like) {
        WorktreeTargetLiveness::Live(evidence) => WorktreeTargetLiveness::Live(evidence),
        WorktreeTargetLiveness::Unknown(evidence) => WorktreeTargetLiveness::Unknown(evidence),
        WorktreeTargetLiveness::Clear => match unknown {
            Some(evidence) => WorktreeTargetLiveness::Unknown(evidence),
            None => WorktreeTargetLiveness::Clear,
        },
    }
}

#[cfg(target_os = "linux")]
fn linux_process_is_non_build_user_service(process_root: &Path) -> bool {
    if linux_process_cmdline(process_root)
        .ok()
        .flatten()
        .is_none_or(|cmdline| cmdline.is_empty())
    {
        return false;
    }
    let mut cgroup = Vec::new();
    if fs::File::open(process_root.join("cgroup"))
        .and_then(|file| file.take(4097).read_to_end(&mut cgroup))
        .is_err()
        || cgroup.len() > 4096
    {
        return false;
    }
    cgroup.split(|byte| *byte == b'\n').any(|line| {
        line.starts_with(b"0::/user.slice/user-")
            && line
                .rsplit(|byte| *byte == b'/')
                .next()
                .is_some_and(|unit| unit.ends_with(b".service"))
    })
}

#[cfg(target_os = "linux")]
fn linux_process_is_inert_user_manager(process_root: &Path) -> bool {
    let mut comm = Vec::new();
    if fs::File::open(process_root.join("comm"))
        .and_then(|file| file.take(64).read_to_end(&mut comm))
        .is_err()
    {
        return false;
    }
    while matches!(comm.last(), Some(b'\n' | b'\r')) {
        comm.pop();
    }
    let cmdline = linux_process_cmdline(process_root).ok().flatten();
    let recognized_manager_process = if comm == b"systemd" {
        cmdline.as_deref().is_some_and(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .any(|argument| argument == b"--user")
        })
    } else if comm == b"(sd-pam)" {
        cmdline
            .as_deref()
            .is_some_and(|bytes| bytes == b"(sd-pam)\0")
    } else {
        false
    };
    if !recognized_manager_process {
        return false;
    }
    let mut cgroup = Vec::new();
    if fs::File::open(process_root.join("cgroup"))
        .and_then(|file| file.take(4097).read_to_end(&mut cgroup))
        .is_err()
        || cgroup.len() > 4096
    {
        return false;
    }
    cgroup.split(|byte| *byte == b'\n').any(|line| {
        line.starts_with(b"0::/user.slice/user-") && line.ends_with(b".service/init.scope")
    })
}

#[cfg(target_os = "linux")]
fn linux_process_environ(
    process_root: &Path,
) -> std::result::Result<Option<Vec<u8>>, WorktreeTargetLivenessCause> {
    let mut environ = Vec::new();
    let file = match fs::File::open(process_root.join("environ")) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WorktreeTargetLivenessCause::ReadFailed),
    };
    file.take(MAX_WORKTREE_GC_PROC_ENVIRON_BYTES.saturating_add(1))
        .read_to_end(&mut environ)
        .map_err(|_| WorktreeTargetLivenessCause::ReadFailed)?;
    if u64::try_from(environ.len())
        .ok()
        .is_none_or(|length| length > MAX_WORKTREE_GC_PROC_ENVIRON_BYTES)
    {
        return Err(WorktreeTargetLivenessCause::LimitExceeded);
    }
    Ok(Some(environ))
}

#[cfg(target_os = "linux")]
fn linux_process_cmdline(
    process_root: &Path,
) -> std::result::Result<Option<Vec<u8>>, WorktreeTargetLivenessCause> {
    let mut cmdline = Vec::new();
    let file = match fs::File::open(process_root.join("cmdline")) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(WorktreeTargetLivenessCause::ReadFailed),
    };
    file.take(MAX_WORKTREE_GC_PROC_CMDLINE_BYTES.saturating_add(1))
        .read_to_end(&mut cmdline)
        .map_err(|_| WorktreeTargetLivenessCause::ReadFailed)?;
    if u64::try_from(cmdline.len())
        .ok()
        .is_none_or(|length| length > MAX_WORKTREE_GC_PROC_CMDLINE_BYTES)
    {
        return Err(WorktreeTargetLivenessCause::LimitExceeded);
    }
    Ok(Some(cmdline))
}

#[cfg(target_os = "linux")]
fn linux_process_cmdline_liveness(
    process_view: &LinuxProcessView,
    pid: u32,
    target: &WorktreeGcTarget,
    cargo_like: bool,
) -> WorktreeTargetLiveness {
    let cmdline = match linux_process_cmdline(&process_view.process_root) {
        Ok(Some(cmdline)) => cmdline,
        Ok(None) => return WorktreeTargetLiveness::Clear,
        Err(cause) => {
            return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                Some(pid),
                WorktreeTargetLivenessSource::ProcessCommandLine,
                cause,
            ))
        }
    };
    let arguments = cmdline
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .take(MAX_WORKTREE_GC_PROC_CMDLINE_ARGS.saturating_add(1))
        .collect::<Vec<_>>();
    if arguments.len() > MAX_WORKTREE_GC_PROC_CMDLINE_ARGS {
        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
            Some(pid),
            WorktreeTargetLivenessSource::ProcessCommandLine,
            WorktreeTargetLivenessCause::LimitExceeded,
        ));
    }
    let cargo_like = cargo_like
        || arguments
            .first()
            .and_then(|argument| argument.rsplit(|byte| *byte == b'/').next())
            .is_some_and(linux_build_process_name);
    if !cargo_like {
        return WorktreeTargetLiveness::Clear;
    }

    let mut explicit_output_seen = false;
    let mut manifest_in_lane = false;
    let mut unknown = None;
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = arguments[index];
        let mut consumed_value = false;
        let directive = [b"--target-dir".as_slice(), b"--out-dir".as_slice()]
            .into_iter()
            .find_map(|flag| {
                command_line_directive_value(argument, flag).map(|value| (flag, value))
            })
            .map(|(_, value)| (true, value))
            .or_else(|| {
                command_line_directive_value(argument, b"--manifest-path")
                    .map(|value| (false, value))
            });
        let Some((is_output, inline_value)) = directive else {
            index += 1;
            continue;
        };
        if is_output {
            explicit_output_seen = true;
        }
        let value = match inline_value {
            Some(value) if !value.is_empty() => value,
            Some(_) => {
                unknown.get_or_insert_with(|| {
                    target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::ProcessCommandLine,
                        WorktreeTargetLivenessCause::InvalidValue,
                    )
                });
                index += 1;
                continue;
            }
            None => match arguments.get(index.saturating_add(1)).copied() {
                Some(value) if !value.is_empty() => {
                    consumed_value = true;
                    value
                }
                _ => {
                    unknown.get_or_insert_with(|| {
                        target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::ProcessCommandLine,
                            WorktreeTargetLivenessCause::InvalidValue,
                        )
                    });
                    index += 1;
                    continue;
                }
            },
        };
        let configured = PathBuf::from(OsString::from_vec(value.to_vec()));
        let resolved = match process_view.resolve_configured_path(&configured) {
            Ok(resolved) => resolved,
            Err(cause) => {
                unknown.get_or_insert_with(|| {
                    target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::MountNamespace,
                        cause,
                    )
                });
                index += if consumed_value { 2 } else { 1 };
                continue;
            }
        };
        let overlap = if is_output {
            process_path_overlaps_target(&resolved, target)
        } else {
            process_path_is_within_or_identical_to_lane(&resolved, target)
        };
        match overlap {
            WorktreePathOverlap::Overlap if is_output => {
                return WorktreeTargetLiveness::Live(target_liveness_evidence(
                    Some(pid),
                    WorktreeTargetLivenessSource::ProcessCommandLine,
                    WorktreeTargetLivenessCause::PathOverlap,
                ));
            }
            WorktreePathOverlap::Overlap => manifest_in_lane = true,
            WorktreePathOverlap::Unknown => {
                unknown.get_or_insert_with(|| {
                    target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::MountNamespace,
                        WorktreeTargetLivenessCause::NamespaceUnresolved,
                    )
                });
            }
            WorktreePathOverlap::Separate => {}
        }
        index += if consumed_value { 2 } else { 1 };
    }

    if manifest_in_lane && !explicit_output_seen {
        WorktreeTargetLiveness::Live(target_liveness_evidence(
            Some(pid),
            WorktreeTargetLivenessSource::DefaultCargoTarget,
            WorktreeTargetLivenessCause::CargoLikeProcessInLane,
        ))
    } else {
        match unknown {
            Some(evidence) => WorktreeTargetLiveness::Unknown(evidence),
            None => WorktreeTargetLiveness::Clear,
        }
    }
}

#[cfg(target_os = "linux")]
fn command_line_directive_value<'a>(argument: &'a [u8], flag: &[u8]) -> Option<Option<&'a [u8]>> {
    if argument == flag {
        return Some(None);
    }
    argument
        .strip_prefix(flag)
        .and_then(|value| value.strip_prefix(b"="))
        .map(Some)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct LinuxProcessView {
    process_root: PathBuf,
    same_mount_namespace: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct LinuxProcessPath {
    rooted_access_path: PathBuf,
    observer_canonical_path: Option<PathBuf>,
    process_path: PathBuf,
    deleted: bool,
    same_mount_namespace: bool,
}

#[cfg(target_os = "linux")]
enum LinuxProcLinkTarget {
    Pseudo,
    Filesystem { path: PathBuf, deleted: bool },
}

#[cfg(target_os = "linux")]
impl LinuxProcessView {
    fn open(process_root: &Path) -> std::result::Result<Option<Self>, WorktreeTargetLivenessCause> {
        let process_namespace = match fs::metadata(process_root.join("ns/mnt")) {
            Ok(metadata) => FileIdentity {
                device: metadata.dev(),
                file: metadata.ino(),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(WorktreeTargetLivenessCause::ReadFailed),
        };
        let observer_namespace = fs::metadata("/proc/self/ns/mnt")
            .map(|metadata| FileIdentity {
                device: metadata.dev(),
                file: metadata.ino(),
            })
            .map_err(|_| WorktreeTargetLivenessCause::ReadFailed)?;
        Ok(Some(Self {
            process_root: process_root.to_path_buf(),
            same_mount_namespace: process_namespace == observer_namespace,
        }))
    }

    #[cfg(test)]
    fn for_test(process_root: &Path, same_mount_namespace: bool) -> Self {
        Self {
            process_root: process_root.to_path_buf(),
            same_mount_namespace,
        }
    }

    fn resolve_configured_path(
        &self,
        configured: &Path,
    ) -> std::result::Result<LinuxProcessPath, WorktreeTargetLivenessCause> {
        if configured.is_absolute() {
            return self.resolve_absolute_process_path(configured, false);
        }
        let cwd = match self.read_link("cwd")? {
            LinuxProcLinkTarget::Filesystem {
                path,
                deleted: false,
            } => path,
            LinuxProcLinkTarget::Filesystem { deleted: true, .. } | LinuxProcLinkTarget::Pseudo => {
                return Err(WorktreeTargetLivenessCause::NamespaceUnresolved)
            }
        };
        self.resolve_absolute_process_path(&cwd.join(configured), false)
    }

    fn resolve_filesystem_link_target(
        &self,
        target: &Path,
    ) -> std::result::Result<Option<LinuxProcessPath>, WorktreeTargetLivenessCause> {
        match classify_linux_proc_link_target(target)? {
            LinuxProcLinkTarget::Pseudo => Ok(None),
            LinuxProcLinkTarget::Filesystem { path, deleted } => {
                self.resolve_absolute_process_path(&path, deleted).map(Some)
            }
        }
    }

    fn read_link(
        &self,
        link: &str,
    ) -> std::result::Result<LinuxProcLinkTarget, WorktreeTargetLivenessCause> {
        let target = fs::read_link(self.process_root.join(link))
            .map_err(|_| WorktreeTargetLivenessCause::ReadFailed)?;
        classify_linux_proc_link_target(&target)
    }

    fn resolve_absolute_process_path(
        &self,
        process_path: &Path,
        deleted: bool,
    ) -> std::result::Result<LinuxProcessPath, WorktreeTargetLivenessCause> {
        let process_path = normalize_proc_target_path(process_path)
            .ok_or(WorktreeTargetLivenessCause::InvalidValue)?;
        let relative = process_path
            .strip_prefix(Path::new("/"))
            .map_err(|_| WorktreeTargetLivenessCause::InvalidValue)?;
        let rooted_access_path = self.process_root.join("root").join(relative);
        let observer_canonical_path = if self.same_mount_namespace && !deleted {
            Some(
                fs::canonicalize(&rooted_access_path)
                    .map_err(|_| WorktreeTargetLivenessCause::NamespaceUnresolved)?,
            )
        } else {
            None
        };
        Ok(LinuxProcessPath {
            rooted_access_path,
            observer_canonical_path,
            process_path,
            deleted,
            same_mount_namespace: self.same_mount_namespace,
        })
    }
}

#[cfg(target_os = "linux")]
fn classify_linux_proc_link_target(
    target: &Path,
) -> std::result::Result<LinuxProcLinkTarget, WorktreeTargetLivenessCause> {
    let bytes = target.as_os_str().as_bytes();
    if [b"pipe:[".as_slice(), b"socket:[", b"anon_inode:"]
        .into_iter()
        .any(|prefix| bytes.starts_with(prefix))
        || bytes.starts_with(b"memfd:")
        || bytes.starts_with(b"/memfd:")
        || bytes.starts_with(b"/dmabuf:")
    {
        return Ok(LinuxProcLinkTarget::Pseudo);
    }
    let (path, deleted) = match bytes.strip_suffix(b" (deleted)") {
        Some(path) => (path, true),
        None => (bytes, false),
    };
    let path = PathBuf::from(OsString::from_vec(path.to_vec()));
    if !path.is_absolute() {
        return Err(WorktreeTargetLivenessCause::InvalidValue);
    }
    Ok(LinuxProcLinkTarget::Filesystem { path, deleted })
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorktreePathOverlap {
    Overlap,
    Separate,
    Unknown,
}

#[cfg(target_os = "linux")]
fn identity_ancestry_contains<I>(expected: &FileIdentity, ancestry: I) -> Result<bool>
where
    I: IntoIterator<Item = Result<FileIdentity>>,
{
    let mut observed = 0usize;
    for identity in ancestry {
        observed = observed
            .checked_add(1)
            .context("target identity ancestry count overflowed")?;
        if observed > MAX_WORKTREE_GC_IDENTITY_ANCESTORS {
            bail!("target identity ancestry exceeds its bound");
        }
        if identity? == *expected {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn path_overlaps_bound_directory(
    path: &Path,
    bound_path: &Path,
    bound_identity: &FileIdentity,
    bidirectional: bool,
) -> WorktreePathOverlap {
    if path.starts_with(bound_path) || (bidirectional && bound_path.starts_with(path)) {
        return WorktreePathOverlap::Overlap;
    }
    let path_identity = match identity_for_path(path) {
        Ok(identity) => identity,
        Err(_) => return WorktreePathOverlap::Unknown,
    };
    let path_contains_bound =
        identity_ancestry_contains(bound_identity, path.ancestors().map(identity_for_path));
    match path_contains_bound {
        Ok(true) => return WorktreePathOverlap::Overlap,
        Ok(false) => {}
        Err(_) => return WorktreePathOverlap::Unknown,
    }
    if bidirectional {
        match identity_ancestry_contains(
            &path_identity,
            bound_path.ancestors().map(identity_for_path),
        ) {
            Ok(true) => return WorktreePathOverlap::Overlap,
            Ok(false) => {}
            Err(_) => return WorktreePathOverlap::Unknown,
        }
    }
    WorktreePathOverlap::Separate
}

#[cfg(target_os = "linux")]
fn process_path_overlaps_bound_directory(
    path: &LinuxProcessPath,
    bound_path: &Path,
    bound_identity: &FileIdentity,
    bidirectional: bool,
) -> WorktreePathOverlap {
    if path.deleted {
        if path.same_mount_namespace {
            return if path.process_path.starts_with(bound_path)
                || (bidirectional && bound_path.starts_with(&path.process_path))
            {
                WorktreePathOverlap::Overlap
            } else {
                WorktreePathOverlap::Separate
            };
        }
        return WorktreePathOverlap::Unknown;
    }
    if let Some(observer_path) = path.observer_canonical_path.as_deref() {
        return path_overlaps_bound_directory(
            observer_path,
            bound_path,
            bound_identity,
            bidirectional,
        );
    }
    path_overlaps_bound_directory_by_identity(
        &path.rooted_access_path,
        bound_path,
        bound_identity,
        bidirectional,
    )
}

#[cfg(target_os = "linux")]
fn path_overlaps_bound_directory_by_identity(
    path: &Path,
    bound_path: &Path,
    bound_identity: &FileIdentity,
    bidirectional: bool,
) -> WorktreePathOverlap {
    let path_identity = match identity_for_path(path) {
        Ok(identity) => identity,
        Err(_) => return WorktreePathOverlap::Unknown,
    };
    match identity_ancestry_contains(bound_identity, path.ancestors().map(identity_for_path)) {
        Ok(true) => return WorktreePathOverlap::Overlap,
        Ok(false) => {}
        Err(_) => return WorktreePathOverlap::Unknown,
    }
    if bidirectional {
        match identity_ancestry_contains(
            &path_identity,
            bound_path.ancestors().map(identity_for_path),
        ) {
            Ok(true) => return WorktreePathOverlap::Overlap,
            Ok(false) => {}
            Err(_) => return WorktreePathOverlap::Unknown,
        }
    }
    WorktreePathOverlap::Separate
}

#[cfg(target_os = "linux")]
fn process_path_overlaps_target(
    path: &LinuxProcessPath,
    target: &WorktreeGcTarget,
) -> WorktreePathOverlap {
    process_path_overlaps_bound_directory(path, &target.canonical_path, &target.identity, true)
}

#[cfg(target_os = "linux")]
fn process_path_is_within_or_identical_to_target(
    path: &LinuxProcessPath,
    target: &WorktreeGcTarget,
) -> WorktreePathOverlap {
    process_path_overlaps_bound_directory(path, &target.canonical_path, &target.identity, false)
}

#[cfg(target_os = "linux")]
fn process_path_is_within_or_identical_to_lane(
    path: &LinuxProcessPath,
    target: &WorktreeGcTarget,
) -> WorktreePathOverlap {
    process_path_overlaps_bound_directory(
        path,
        &target.lane_canonical_path,
        &target.lane_identity,
        false,
    )
}

#[cfg(target_os = "linux")]
fn linux_process_is_cargo_like(process_root: &Path) -> bool {
    let mut comm = Vec::new();
    if let Ok(file) = fs::File::open(process_root.join("comm")) {
        let _ = file.take(64).read_to_end(&mut comm);
    }
    while matches!(comm.last(), Some(b'\n' | b'\r')) {
        comm.pop();
    }
    if linux_build_process_name(&comm) {
        return true;
    }
    fs::read_link(process_root.join("exe"))
        .ok()
        .and_then(|path| path.file_name().map(|name| name.as_bytes().to_vec()))
        .is_some_and(|name| linux_build_process_name(&name))
        || linux_process_cmdline(process_root)
            .ok()
            .flatten()
            .and_then(|cmdline| {
                cmdline
                    .split(|byte| *byte == 0)
                    .find(|argument| !argument.is_empty())
                    .map(|argument| argument.to_vec())
            })
            .and_then(|argument| {
                argument
                    .rsplit(|byte| *byte == b'/')
                    .next()
                    .map(|name| name.to_vec())
            })
            .is_some_and(|name| linux_build_process_name(&name))
}

#[cfg(target_os = "linux")]
fn linux_build_process_name(name: &[u8]) -> bool {
    matches!(name, b"cargo" | b"rustc" | b"rustdoc" | b"sccache")
        || name.starts_with(b"cargo-")
        || name.starts_with(b"rustc-")
}

#[cfg(target_os = "linux")]
fn linux_process_target_association(
    process_view: &LinuxProcessView,
    pid: u32,
    target: &WorktreeGcTarget,
    deadline: Instant,
    cargo_like: bool,
) -> WorktreeTargetLiveness {
    for (link, source) in [
        ("cwd", WorktreeTargetLivenessSource::ProcessCwd),
        ("exe", WorktreeTargetLivenessSource::ProcessExecutable),
    ] {
        match process_view.read_link(link) {
            Ok(LinuxProcLinkTarget::Filesystem { path, deleted }) => {
                let path = match process_view.resolve_absolute_process_path(&path, deleted) {
                    Ok(path) => path,
                    Err(cause) => {
                        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::MountNamespace,
                            cause,
                        ))
                    }
                };
                match process_path_is_within_or_identical_to_target(&path, target) {
                    WorktreePathOverlap::Overlap => {
                        return WorktreeTargetLiveness::Live(target_liveness_evidence(
                            Some(pid),
                            source,
                            WorktreeTargetLivenessCause::PathOverlap,
                        ));
                    }
                    WorktreePathOverlap::Unknown => {
                        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::MountNamespace,
                            WorktreeTargetLivenessCause::NamespaceUnresolved,
                        ));
                    }
                    WorktreePathOverlap::Separate => {}
                }
                match process_path_is_within_or_identical_to_lane(&path, target) {
                    WorktreePathOverlap::Overlap if cargo_like => {
                        return WorktreeTargetLiveness::Live(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::DefaultCargoTarget,
                            WorktreeTargetLivenessCause::CargoLikeProcessInLane,
                        ));
                    }
                    WorktreePathOverlap::Overlap => {
                        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                            Some(pid),
                            source,
                            WorktreeTargetLivenessCause::PathOverlap,
                        ));
                    }
                    WorktreePathOverlap::Unknown => {
                        return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                            Some(pid),
                            WorktreeTargetLivenessSource::MountNamespace,
                            WorktreeTargetLivenessCause::NamespaceUnresolved,
                        ));
                    }
                    WorktreePathOverlap::Separate => {}
                }
            }
            Ok(LinuxProcLinkTarget::Pseudo) => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    Some(pid),
                    source,
                    WorktreeTargetLivenessCause::InvalidValue,
                ));
            }
            Err(cause) => {
                return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                    Some(pid),
                    source,
                    cause,
                ));
            }
        }
    }

    let descriptors = match fs::read_dir(process_view.process_root.join("fd")) {
        Ok(descriptors) => descriptors,
        Err(_) => return bounded_association_failure(pid),
    };
    let mut observed = 0usize;
    for descriptor in descriptors {
        if Instant::now() >= deadline {
            return bounded_association_failure_with_cause(
                pid,
                WorktreeTargetLivenessCause::TimedOut,
            );
        }
        observed = match observed.checked_add(1) {
            Some(observed) if observed <= MAX_WORKTREE_GC_PROC_FDS => observed,
            _ => {
                return bounded_association_failure_with_cause(
                    pid,
                    WorktreeTargetLivenessCause::LimitExceeded,
                )
            }
        };
        let descriptor = match descriptor {
            Ok(descriptor) => descriptor,
            Err(_) => return bounded_association_failure(pid),
        };
        let link_target = match fs::read_link(descriptor.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return bounded_association_failure(pid),
        };
        match process_view.resolve_filesystem_link_target(&link_target) {
            Ok(None) => continue,
            Ok(Some(path)) => match process_path_is_within_or_identical_to_target(&path, target) {
                WorktreePathOverlap::Overlap => {
                    return WorktreeTargetLiveness::Live(target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::ProcessFileDescriptor,
                        WorktreeTargetLivenessCause::PathOverlap,
                    ));
                }
                WorktreePathOverlap::Unknown => {
                    return WorktreeTargetLiveness::Unknown(target_liveness_evidence(
                        Some(pid),
                        WorktreeTargetLivenessSource::MountNamespace,
                        WorktreeTargetLivenessCause::NamespaceUnresolved,
                    ));
                }
                WorktreePathOverlap::Separate => {}
            },
            Err(cause) => return bounded_association_failure_with_cause(pid, cause),
        }
    }
    WorktreeTargetLiveness::Clear
}
