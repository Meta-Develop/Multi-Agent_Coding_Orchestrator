#[cfg(target_os = "linux")]
fn bounded_association_failure(pid: u32) -> WorktreeTargetLiveness {
    bounded_association_failure_with_cause(pid, WorktreeTargetLivenessCause::ReadFailed)
}

#[cfg(target_os = "linux")]
fn bounded_association_failure_with_cause(
    pid: u32,
    cause: WorktreeTargetLivenessCause,
) -> WorktreeTargetLiveness {
    WorktreeTargetLiveness::Unknown(target_liveness_evidence(
        Some(pid),
        WorktreeTargetLivenessSource::ProcessFileDescriptor,
        cause,
    ))
}

#[cfg(target_os = "linux")]
fn normalize_proc_target_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {
                normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR));
            }
            std::path::Component::Normal(segment) => normalized.push(segment),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            std::path::Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

#[cfg(not(target_os = "linux"))]
fn worktree_target_liveness(_target: &WorktreeGcTarget) -> WorktreeTargetLiveness {
    WorktreeTargetLiveness::Unknown(target_liveness_evidence(
        None,
        WorktreeTargetLivenessSource::Platform,
        WorktreeTargetLivenessCause::Unsupported,
    ))
}

enum WorktreeTargetRemovalOutcome {
    Removed,
    IdentityChanged,
}

fn remove_worktree_target_dir(
    worktree_path: &Path,
    target: &WorktreeGcTarget,
) -> Result<WorktreeTargetRemovalOutcome> {
    let root = SafeRoot::open_existing(worktree_path)?;
    match remove_direct_child_tree(
        &root,
        "target",
        Some(&target.identity),
        TreeLinkPolicy::UnlinkLinks,
    ) {
        Ok(()) => Ok(WorktreeTargetRemovalOutcome::Removed),
        Err(_error)
            if identity_for_path(&target.path)
                .ok()
                .as_ref()
                .is_none_or(|identity| identity != &target.identity) =>
        {
            Ok(WorktreeTargetRemovalOutcome::IdentityChanged)
        }
        Err(error) => Err(error),
    }
}

fn prune_unregistered_worktree_directories(
    repo: &Repository,
    worktree_root: &Path,
    registered_names: &BTreeSet<String>,
    dry_run: bool,
    machine_global_retention: Option<&MachineGlobalRetentionBinding>,
    report: &mut WorktreeGcReport,
) -> Result<()> {
    if !path_entry_exists(worktree_root)? {
        return Ok(());
    }
    let root = SafeRoot::open_existing(worktree_root)?;
    let git_registered = git_registered_worktree_names(repo, root.path())?;
    let mut orphans = Vec::new();
    for child_name in root.direct_child_names_bounded(MAX_MANAGED_RECORDS)? {
        if is_reserved_worktree_root_child(&child_name) {
            continue;
        }
        let Some(name) = child_name.to_str() else {
            bail!("managed worktree root contains a non-UTF-8 child name");
        };
        if normalize_agent_id(name)? != name {
            bail!("managed worktree root contains a noncanonical child name: {name}");
        }
        if registered_names.contains(name) || git_registered.contains(name) {
            continue;
        }
        let path = root.direct_child(&child_name)?;
        orphans.push((name.to_string(), path));
    }
    if orphans.is_empty() {
        return Ok(());
    }
    if dry_run {
        for (name, path) in orphans {
            report.orphan_removed_count = report
                .orphan_removed_count
                .checked_add(1)
                .context("worktree GC orphan count overflowed")?;
            report.entries.push(WorktreeGcEntry {
                name,
                branch: None,
                path,
                status: WorktreeGcStatus::OrphanWouldPrune,
                reason: WorktreeGcReason::UnregisteredOrphan,
                target_path: None,
                target_liveness: None,
                apparent_worktree_bytes: None,
                apparent_target_bytes: None,
                untracked_paths: Vec::new(),
                gate_denial: None,
                retention_operation_id: None,
            });
        }
        return Ok(());
    }

    let binding = machine_global_retention.context(
        "destructive worktree orphan GC requires an explicit machine-global config/root binding",
    )?;
    let store = MachineGlobalStore::open_config(&binding.config)
        .context("failed to open machine-global binding for worktree orphan GC")?;
    let targets = orphans
        .iter()
        .map(|(_, path)| {
            store
                .coordinate_for_existing_directory(&binding.root_id, path)
                .map(DestructiveTargetInput::Declared)
        })
        .collect::<Result<Vec<_>>>()
        .context("worktree orphan GC target is outside the reviewed machine-global root")?;
    match store.quarantine(&binding.owner, &binding.correction_correlation_id, targets)? {
        GateOutcome::Allowed(operation) => {
            let operation_id = operation.id;
            report.orphan_removed_count = report
                .orphan_removed_count
                .checked_add(orphans.len())
                .context("worktree GC orphan count overflowed")?;
            for (name, path) in orphans {
                report.entries.push(WorktreeGcEntry {
                    name,
                    branch: None,
                    path,
                    status: WorktreeGcStatus::OrphanQuarantined,
                    reason: WorktreeGcReason::UnregisteredOrphan,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: None,
                    apparent_target_bytes: None,
                    untracked_paths: Vec::new(),
                    gate_denial: None,
                    retention_operation_id: Some(operation_id),
                });
            }
        }
        GateOutcome::Denied(denial) => {
            report.protected_count = report
                .protected_count
                .checked_add(orphans.len())
                .context("worktree GC protected count overflowed")?;
            for (name, path) in orphans {
                report.entries.push(WorktreeGcEntry {
                    name,
                    branch: None,
                    path,
                    status: WorktreeGcStatus::Protected,
                    reason: WorktreeGcReason::MachineGlobalGate,
                    target_path: None,
                    target_liveness: None,
                    apparent_worktree_bytes: None,
                    apparent_target_bytes: None,
                    untracked_paths: Vec::new(),
                    gate_denial: Some(denial.clone()),
                    retention_operation_id: None,
                });
            }
        }
    }
    Ok(())
}

fn git_registered_worktree_names(
    repo: &Repository,
    worktree_root: &Path,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let list = repo.worktrees().context("failed to list Git worktrees")?;
    for index in 0..list.len() {
        let Some(name) = list
            .get(index)
            .context("failed to read Git worktree name")?
        else {
            continue;
        };
        let worktree = repo
            .find_worktree(name)
            .with_context(|| format!("failed to inspect Git worktree '{name}'"))?;
        let path = match fs::canonicalize(worktree.path()) {
            Ok(path) => path,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to resolve Git worktree path {}",
                        worktree.path().display()
                    )
                })
            }
        };
        if path.parent() == Some(worktree_root) {
            names.insert(name.to_string());
        }
    }
    Ok(names)
}

fn git_registered_worktree_names_for_reconciliation(
    repo: &Repository,
    worktree_root: &Path,
) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let list = repo
        .worktrees()
        .context("failed to list Git worktrees during startup reconciliation")?;
    if list.len() > MAX_MANAGED_RECORDS {
        bail!("startup reconciliation exceeds its bounded Git registration limit");
    }
    for index in 0..list.len() {
        let Some(name) = list
            .get(index)
            .context("failed to read a Git worktree name during startup reconciliation")?
        else {
            continue;
        };
        let worktree = repo.find_worktree(name).with_context(|| {
            format!("failed to inspect Git worktree '{name}' during startup reconciliation")
        })?;
        let path = worktree.path();
        let belongs_to_root = path.parent() == Some(worktree_root)
            || fs::canonicalize(path)
                .ok()
                .is_some_and(|canonical| canonical.parent() == Some(worktree_root));
        if belongs_to_root {
            names.insert(name.to_string());
        }
    }
    Ok(names)
}

fn unix_now_nanos() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    i64::try_from(duration.as_nanos()).context("current Unix time exceeds supported range")
}

struct VerifiedManagedWorktree {
    path: PathBuf,
    branch_oid: Oid,
}

fn verified_worktree_record(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    binding: &ManagedWorktreeBinding,
) -> Result<WorktreeRecord> {
    if binding.creation_lock_pending {
        bail!(
            "managed worktree '{}' still has an incomplete creation lock",
            binding.name
        );
    }
    let verified = verify_managed_worktree_binding(repo, repository, binding, false)?;
    let worktree = repo
        .find_worktree(&binding.name)
        .with_context(|| format!("managed worktree '{}' is not registered", binding.name))?;
    worktree
        .validate()
        .with_context(|| format!("managed worktree '{}' failed Git validation", binding.name))?;
    let registered_name = worktree
        .name()
        .context("managed worktree registration name is not valid UTF-8")?;
    if registered_name != Some(binding.name.as_str()) {
        bail!("managed worktree registration name changed");
    }
    let registered_path = fs::canonicalize(worktree.path()).with_context(|| {
        format!(
            "failed to resolve registered path for managed worktree '{}'",
            binding.name
        )
    })?;
    if registered_path != verified.path {
        bail!(
            "managed worktree '{}' Git registration points outside its verified binding",
            binding.name
        );
    }
    Ok(WorktreeRecord {
        name: binding.name.clone(),
        path: verified.path,
        branch: binding.branch.clone(),
    })
}

impl ManagedWorktreeRegistryStore {
    fn open(repo: &Repository) -> Result<Self> {
        let repository = managed_repository_binding(repo)?;
        let state_root = repository.common_dir.join("maco").join("state");
        Ok(Self {
            repo_path: repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf(),
            state_root: SafeRoot::open_or_create(state_root)?,
            repository,
        })
    }

    fn open_existing(repo: &Repository) -> Result<Option<Self>> {
        let repository = managed_repository_binding(repo)?;
        let state_path = repository.common_dir.join("maco").join("state");
        match fs::symlink_metadata(&state_path) {
            Ok(_) => Ok(Some(Self {
                repo_path: repo.workdir().unwrap_or_else(|| repo.path()).to_path_buf(),
                state_root: SafeRoot::open_existing(&state_path)
                    .context("existing MACO state root is unsafe")?,
                repository,
            })),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to inspect existing MACO state root {}",
                    state_path.display()
                )
            }),
        }
    }

    fn lock(&self) -> Result<ManagedWorktreeRegistryLock> {
        self.lock_with_timeout(MANAGED_WORKTREE_REGISTRY_LOCK_TIMEOUT)
    }

    fn lock_with_timeout(&self, timeout: Duration) -> Result<ManagedWorktreeRegistryLock> {
        let lock = KernelStateLock::acquire_direct_with_timeout(
            &self.state_root,
            "managed_worktrees.lock",
            timeout,
        )?;
        let bound = ManagedWorktreeRegistryLock {
            root_identity: self.state_root.identity().clone(),
            lock_identity: lock.identity().clone(),
            lock,
        };
        self.verify_lock(&bound)?;
        Ok(bound)
    }

    fn lock_existing(&self) -> Result<ManagedWorktreeRegistryLock> {
        let lock = match KernelStateLock::try_acquire_existing_exclusive_direct(
            &self.state_root,
            "managed_worktrees.lock",
        )? {
            ExistingExclusiveLock::Acquired(lock) => lock,
            ExistingExclusiveLock::Busy => {
                bail!("managed worktree registry is active elsewhere")
            }
            ExistingExclusiveLock::Missing => {
                bail!("authenticated managed worktree state is missing its stable registry lock")
            }
        };
        let bound = ManagedWorktreeRegistryLock {
            root_identity: self.state_root.identity().clone(),
            lock_identity: lock.identity().clone(),
            lock,
        };
        self.verify_lock(&bound)?;
        Ok(bound)
    }

    fn load_existing_read_only(&self) -> Result<Option<ManagedWorktreeRegistry>> {
        if !self
            .state_root
            .direct_child_exists(ManagedSnapshotSpec::ROOT_NAME)?
        {
            if self
                .state_root
                .direct_child_exists("managed_worktrees.json")?
            {
                bail!("legacy managed worktree state requires explicit migration before read-only inspection");
            }
            return Ok(None);
        }
        let lock = self.lock_existing()?;
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let auth_binding = authenticator.binding().clone();
        let snapshot = AuthenticatedSnapshotStore::<
            ManagedSnapshotSpec,
            AuthenticatedManagedState,
        >::read_existing_current(authenticator, MANAGED_LOGICAL_ID)?;
        self.validate_authenticated_snapshot(&snapshot, &auth_binding)?;
        self.verify_lock(&lock)?;
        Ok(Some(snapshot.value.registry))
    }

    fn try_acquire_shared_worktree_read_lock(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<(KernelStateLock, ManagedProcessLease)> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lease_name = managed_worktree_lease_name(name, &incarnation)?;
        let lock = KernelStateLock::try_acquire_shared_direct(&self.state_root, &lease_name)?;
        let process_lease = ManagedProcessLease::acquire_shared(&lease_name, lock.path())?;
        Ok((lock, process_lease))
    }

    fn try_acquire_exclusive_worktree_write_lock(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<(KernelStateLock, ManagedProcessLease)> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lease_name = managed_worktree_lease_name(name, &incarnation)?;
        let lock = KernelStateLock::try_acquire_exclusive_direct(&self.state_root, &lease_name)?;
        let process_lease = ManagedProcessLease::acquire_exclusive(&lease_name, lock.path())?;
        Ok((lock, process_lease))
    }

    fn try_acquire_worktree_removal_lease(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<ManagedWorktreeRemovalLease> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lease_name = managed_worktree_lease_name(name, &incarnation)?;
        let lock = KernelStateLock::try_acquire_exclusive_direct(&self.state_root, &lease_name)?;
        let process_lease = ManagedProcessLease::acquire_exclusive(&lease_name, lock.path())?;
        Ok(ManagedWorktreeRemovalLease {
            name: name.to_string(),
            incarnation_generation: incarnation.generation,
            incarnation_nonce: incarnation.nonce,
            _lock: lock,
            _process_lease: process_lease,
        })
    }

    fn worktree_has_active_execution_lease(
        &self,
        registry_lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<bool> {
        let incarnation = self.active_incarnation(registry_lock, name)?;
        let lease_name = managed_worktree_lease_name(name, &incarnation)?;
        if ManagedProcessLease::is_active(&lease_name) {
            return Ok(true);
        }
        match KernelStateLock::try_acquire_existing_exclusive_direct(&self.state_root, &lease_name)?
        {
            ExistingExclusiveLock::Missing => Ok(false),
            ExistingExclusiveLock::Busy => Ok(true),
            ExistingExclusiveLock::Acquired(_lock) => Ok(false),
        }
    }

    fn load(&self, lock: &ManagedWorktreeRegistryLock) -> Result<ManagedWorktreeRegistry> {
        self.verify_lock(lock)?;
        let result = self
            .ensure_authenticated_state(lock)
            .map(|store| store.current().value.registry.clone());
        finish_with_registry_lock_verification(result, self.verify_lock(lock))
    }

    fn save(
        &self,
        lock: &ManagedWorktreeRegistryLock,
        registry: &mut ManagedWorktreeRegistry,
    ) -> Result<()> {
        self.verify_lock(lock)?;
        run_managed_registry_after_precheck_hook();
        let result = (|| -> Result<()> {
            self.verify_lock(lock)?;
            normalize_managed_registry(registry, &self.repository)?;
            let mut store = self.ensure_authenticated_state(lock)?;
            let mut incarnations = store.current().value.incarnations.clone();
            let retired_incarnations = reconcile_managed_incarnations(&mut incarnations, registry)?;
            let mut retired_leases = store.current().value.retired_leases.clone();
            self.queue_retired_leases(&retired_incarnations, &incarnations, &mut retired_leases)?;
            let revision = store
                .current()
                .value
                .snapshot_revision
                .checked_add(1)
                .context("authenticated managed registry revision exhausted")?;
            let value = AuthenticatedManagedState {
                version: 1,
                snapshot_revision: revision,
                repository: store.current().value.repository.clone(),
                registry: registry.clone(),
                incarnations,
                retired_leases,
            };
            self.verify_lock(lock)?;
            if revision % 4_096 == 0 {
                let authenticator = repository_authenticator_key_only(&self.repo_path)?;
                store = store.rollover(authenticator, revision, value)?;
            } else {
                store.commit(revision, value)?;
            }
            store = self.scavenge_retired_leases(store, lock)?;
            self.validate_authenticated_state(&store)?;
            self.finalize_legacy_retirement(&store, lock)?;
            self.verify_lock(lock)
        })();
        finish_with_registry_lock_verification(result, self.verify_lock(lock))
    }

    fn verify_lock(&self, lock: &ManagedWorktreeRegistryLock) -> Result<()> {
        if lock.root_identity != *self.state_root.identity() {
            bail!("managed worktree registry lock belongs to a different state root");
        }
        lock.lock.verify_direct_binding(&self.state_root)?;
        if lock.lock.identity() != &lock.lock_identity {
            bail!("managed worktree registry lock identity changed unexpectedly");
        }
        Ok(())
    }

    fn empty_registry(&self) -> ManagedWorktreeRegistry {
        ManagedWorktreeRegistry {
            version: MANAGED_WORKTREE_REGISTRY_VERSION,
            checksum: String::new(),
            repository: self.repository.clone(),
            records: BTreeMap::new(),
            operations: BTreeMap::new(),
        }
    }

    fn ensure_authenticated_state(
        &self,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>> {
        self.verify_lock(lock)?;
        if self
            .state_root
            .direct_child_exists(ManagedSnapshotSpec::ROOT_NAME)?
        {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            if AuthenticatedSnapshotStore::<ManagedSnapshotSpec, AuthenticatedManagedState>::initialized(
                &authenticator,
                MANAGED_LOGICAL_ID,
            )? {
                let store = AuthenticatedSnapshotStore::open_instance(
                    authenticator,
                    MANAGED_LOGICAL_ID,
                )?;
                let store = self.scavenge_retired_leases(store, lock)?;
                self.validate_authenticated_state(&store)?;
                self.finalize_legacy_retirement(&store, lock)?;
                self.verify_lock(lock)?;
                return Ok(store);
            }
        }
        let preparation = prepare_legacy_retirement::<ManagedSnapshotSpec>(
            &self.repo_path,
            "managed_worktrees",
            "managed_worktrees.json",
            LEGACY_RETIREMENT_DOMAIN,
            &|| self.verify_lock(lock),
        )?;
        let (adoption, writer) = preparation.into_parts();
        let mut registry = match adoption {
            LegacyAdoption::Missing => self.empty_registry(),
            LegacyAdoption::Present(bytes) => {
                let registry: ManagedWorktreeRegistry = serde_json::from_slice(&bytes)
                    .context("signed legacy managed worktree registry is malformed")?;
                if registry.version != MANAGED_WORKTREE_REGISTRY_VERSION
                    || registry.repository != self.repository
                    || registry.checksum != managed_registry_checksum(&registry)?
                {
                    bail!("signed legacy managed registry failed repository/checksum validation");
                }
                if !registry.operations.is_empty() {
                    bail!("legacy managed registry contains in-flight operations; complete or recover them with the old binary before authenticated adoption");
                }
                registry
            }
        };
        normalize_managed_registry(&mut registry, &self.repository)?;
        let mut incarnations = BTreeMap::new();
        let retired = reconcile_managed_incarnations(&mut incarnations, &registry)?;
        if !retired.is_empty() {
            bail!("new authenticated managed state unexpectedly retired an incarnation");
        }
        let initial = AuthenticatedManagedState {
            version: 1,
            snapshot_revision: 1,
            repository: writer.authenticator().binding().clone(),
            registry,
            incarnations,
            retired_leases: BTreeMap::new(),
        };
        let store = AuthenticatedSnapshotStore::create(
            writer.into_authenticator()?,
            MANAGED_LOGICAL_ID,
            1,
            initial,
        )?;
        self.validate_authenticated_state(&store)?;
        self.finalize_legacy_retirement(&store, lock)?;
        self.verify_lock(lock)?;
        Ok(store)
    }

    fn open_authenticated_state(
        &self,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>> {
        self.verify_lock(lock)?;
        let authenticator = repository_authenticator_key_only(&self.repo_path)?;
        let store = AuthenticatedSnapshotStore::open_instance(authenticator, MANAGED_LOGICAL_ID)?;
        let store = self.scavenge_retired_leases(store, lock)?;
        self.validate_authenticated_state(&store)?;
        self.finalize_legacy_retirement(&store, lock)?;
        self.verify_lock(lock)?;
        Ok(store)
    }

    fn validate_authenticated_state(
        &self,
        store: &AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>,
    ) -> Result<()> {
        let snapshot = store.current();
        self.validate_authenticated_snapshot(snapshot, &store.identity().repository)
    }

    fn validate_authenticated_snapshot(
        &self,
        snapshot: &AuthenticatedSnapshot<AuthenticatedManagedState>,
        repository_binding: &RepositoryAuthBinding,
    ) -> Result<()> {
        if snapshot.value.version != 1
            || snapshot.value.snapshot_revision != snapshot.generation
            || snapshot.value.snapshot_revision != snapshot.token
            || snapshot.value.repository != *repository_binding
        {
            bail!("authenticated managed registry binding or revision is inconsistent");
        }
        if snapshot.value.registry.repository != self.repository
            || snapshot.value.registry.version != MANAGED_WORKTREE_REGISTRY_VERSION
            || snapshot.value.registry.checksum
                != managed_registry_checksum(&snapshot.value.registry)?
        {
            bail!("authenticated managed registry repository/checksum binding is inconsistent");
        }
        validate_registry_bounds(&snapshot.value.registry)?;
        validate_managed_incarnations(&snapshot.value.incarnations, &snapshot.value.registry)?;
        validate_retired_managed_leases(
            &snapshot.value.retired_leases,
            &snapshot.value.incarnations,
        )
    }

    fn finalize_legacy_retirement(
        &self,
        store: &AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<()> {
        finalize_legacy_retirement::<ManagedSnapshotSpec>(
            &self.repo_path,
            "managed_worktrees",
            "managed_worktrees.json",
            LEGACY_RETIREMENT_DOMAIN,
            store.identity(),
            store.current().generation,
            &|| self.verify_lock(lock),
        )
    }

    fn active_incarnation(
        &self,
        lock: &ManagedWorktreeRegistryLock,
        name: &str,
    ) -> Result<ManagedIncarnation> {
        let store = self.open_authenticated_state(lock)?;
        let incarnation = store
            .current()
            .value
            .incarnations
            .get(name)
            .filter(|incarnation| incarnation.active)
            .cloned()
            .with_context(|| {
                format!("managed worktree '{name}' has no active signed incarnation")
            })?;
        Ok(incarnation)
    }

    fn verify_authenticated_registry(
        &self,
        lock: &ManagedWorktreeRegistryLock,
        registry: &ManagedWorktreeRegistry,
    ) -> Result<()> {
        self.verify_lock(lock)?;
        let store = self.open_authenticated_state(lock)?;
        if &store.current().value.registry != registry {
            bail!("managed worktree registry changed since its authenticated destructive precheck");
        }
        self.verify_lock(lock)
    }

    fn verify_removal_lease_current(
        &self,
        lock: &ManagedWorktreeRegistryLock,
        lease: &ManagedWorktreeRemovalLease,
    ) -> Result<()> {
        let incarnation = self.active_incarnation(lock, &lease.name)?;
        if incarnation.generation != lease.incarnation_generation
            || incarnation.nonce != lease.incarnation_nonce
        {
            bail!("managed worktree removal lease belongs to a stale incarnation");
        }
        Ok(())
    }

    fn queue_retired_leases(
        &self,
        retired: &[(String, ManagedIncarnation)],
        active: &BTreeMap<String, ManagedIncarnation>,
        queue: &mut BTreeMap<String, FileIdentity>,
    ) -> Result<()> {
        for (name, incarnation) in retired {
            let lease_name = managed_worktree_lease_name(name, incarnation)?;
            let lease_name = lease_name
                .into_string()
                .map_err(|_| anyhow::anyhow!("managed worktree lease name is not UTF-8"))?;
            if active.iter().any(|(active_name, active_incarnation)| {
                managed_worktree_lease_name(active_name, active_incarnation)
                    .ok()
                    .is_some_and(|candidate| candidate == OsStr::new(&lease_name))
            }) {
                bail!("retired managed lease collides with an active incarnation");
            }
            let path = self.state_root.direct_child(&lease_name)?;
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let identity = identity_for_path(&path)?;
                    if queue.insert(lease_name, identity).is_some() {
                        bail!("managed worktree retired lease was queued twice");
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("failed to inspect retired lease file"),
            }
        }
        validate_retired_managed_leases(queue, active)
    }

    fn scavenge_retired_leases(
        &self,
        mut store: AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>,
        lock: &ManagedWorktreeRegistryLock,
    ) -> Result<AuthenticatedSnapshotStore<ManagedSnapshotSpec, AuthenticatedManagedState>> {
        self.verify_lock(lock)?;
        let active = store.current().value.incarnations.clone();
        let mut queue = store.current().value.retired_leases.clone();
        validate_retired_managed_leases(&queue, &active)?;
        let mut cleaned = false;
        for (name, expected_identity) in store.current().value.retired_leases.clone() {
            let acquired =
                KernelStateLock::try_acquire_existing_exclusive_direct(&self.state_root, &name)
                    .context("failed to inspect retired managed lease")?;
            match acquired {
                ExistingExclusiveLock::Busy => continue,
                ExistingExclusiveLock::Missing => {
                    queue.remove(&name);
                    cleaned = true;
                }
                ExistingExclusiveLock::Acquired(lease) => {
                    if lease.identity() != &expected_identity {
                        bail!("retired managed lease path has a foreign or rebound identity");
                    }
                    lease.unlink_exact_direct(&self.state_root)?;
                    queue.remove(&name);
                    cleaned = true;
                }
            }
        }
        if !cleaned {
            return Ok(store);
        }
        let revision = store
            .current()
            .value
            .snapshot_revision
            .checked_add(1)
            .context("authenticated managed registry revision exhausted")?;
        let mut value = store.current().value.clone();
        value.snapshot_revision = revision;
        value.retired_leases = queue;
        self.verify_lock(lock)?;
        if revision % 4_096 == 0 {
            let authenticator = repository_authenticator_key_only(&self.repo_path)?;
            store = store.rollover(authenticator, revision, value)?;
        } else {
            store.commit(revision, value)?;
        }
        self.verify_lock(lock)?;
        Ok(store)
    }
}

fn finish_with_registry_lock_verification<T>(
    result: Result<T>,
    verification: Result<()>,
) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "operation also lost its managed registry lock-path binding: {lock_error:#}"
        ))),
    }
}

#[cfg(test)]
thread_local! {
    static MANAGED_REGISTRY_AFTER_PRECHECK_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_managed_registry_after_precheck_hook(hook: impl FnOnce() + 'static) {
    MANAGED_REGISTRY_AFTER_PRECHECK_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_managed_registry_after_precheck_hook() {
    let hook = MANAGED_REGISTRY_AFTER_PRECHECK_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_managed_registry_after_precheck_hook() {}

fn managed_worktree_lease_name(name: &str, incarnation: &ManagedIncarnation) -> Result<OsString> {
    let normalized = normalize_agent_id(name)?;
    if normalized != name {
        bail!("managed worktree lease name is not canonical");
    }
    validate_managed_incarnation(incarnation)?;
    Ok(OsString::from(format!(
        "managed-worktree-{name}-{}-{}.execution.lock",
        incarnation.generation, incarnation.nonce
    )))
}

fn normalize_managed_registry(
    registry: &mut ManagedWorktreeRegistry,
    repository: &ManagedRepositoryBinding,
) -> Result<()> {
    registry.version = MANAGED_WORKTREE_REGISTRY_VERSION;
    registry.repository = repository.clone();
    validate_registry_bounds(registry)?;
    registry.checksum = managed_registry_checksum(registry)?;
    let bytes = serde_json::to_vec(registry)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANAGED_REGISTRY_BYTES {
        bail!("managed worktree registry exceeds its serialized size limit");
    }
    Ok(())
}

fn reconcile_managed_incarnations(
    incarnations: &mut BTreeMap<String, ManagedIncarnation>,
    registry: &ManagedWorktreeRegistry,
) -> Result<Vec<(String, ManagedIncarnation)>> {
    let active = registry
        .records
        .keys()
        .chain(registry.operations.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let retired_names = incarnations
        .keys()
        .filter(|name| !active.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let mut retired = Vec::with_capacity(retired_names.len());
    for name in retired_names {
        let incarnation = incarnations
            .remove(&name)
            .context("managed worktree incarnation disappeared during pruning")?;
        retired.push((name, incarnation));
    }
    for name in active {
        match incarnations.get_mut(&name) {
            Some(incarnation) if incarnation.active => {}
            Some(_) => bail!("active managed incarnation is marked inactive"),
            None => {
                incarnations.insert(
                    name,
                    ManagedIncarnation {
                        generation: 1,
                        nonce: random_identifier()?,
                        active: true,
                    },
                );
            }
        }
    }
    validate_managed_incarnations(incarnations, registry)?;
    Ok(retired)
}

fn validate_managed_incarnation(incarnation: &ManagedIncarnation) -> Result<()> {
    if incarnation.generation == 0
        || incarnation.nonce.len() != 64
        || !incarnation
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("managed worktree incarnation is malformed");
    }
    Ok(())
}

fn validate_managed_incarnations(
    incarnations: &BTreeMap<String, ManagedIncarnation>,
    registry: &ManagedWorktreeRegistry,
) -> Result<()> {
    if incarnations.len() > MAX_MANAGED_RECORDS.saturating_add(MAX_MANAGED_OPERATIONS) {
        bail!("managed worktree incarnation registry exceeds its bound");
    }
    for (name, incarnation) in incarnations {
        if normalize_agent_id(name)? != *name {
            bail!("managed worktree incarnation key is not canonical");
        }
        validate_managed_incarnation(incarnation)?;
        let expected_active =
            registry.records.contains_key(name) || registry.operations.contains_key(name);
        if !incarnation.active || !expected_active {
            bail!("managed worktree incarnation activity does not match the signed registry");
        }
    }
    for name in registry.records.keys().chain(registry.operations.keys()) {
        if !incarnations
            .get(name)
            .is_some_and(|incarnation| incarnation.active)
        {
            bail!("signed managed registry entry has no active incarnation");
        }
    }
    Ok(())
}

fn validate_retired_managed_leases(
    leases: &BTreeMap<String, FileIdentity>,
    active: &BTreeMap<String, ManagedIncarnation>,
) -> Result<()> {
    if leases.len() > MAX_MANAGED_RECORDS.saturating_add(MAX_MANAGED_OPERATIONS) {
        bail!("retired managed lease cleanup queue exceeds its bound");
    }
    let active_names = active
        .iter()
        .map(|(name, incarnation)| managed_worktree_lease_name(name, incarnation))
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    for (name, identity) in leases {
        let parsed = parse_managed_worktree_lease_name(name)?;
        if active_names.contains(OsStr::new(name))
            || identity.device == 0
            || identity.file == 0
            || parsed.0.is_empty()
        {
            bail!("retired managed lease cleanup entry is malformed or active");
        }
    }
    Ok(())
}

fn parse_managed_worktree_lease_name(name: &str) -> Result<(String, ManagedIncarnation)> {
    let body = name
        .strip_prefix("managed-worktree-")
        .and_then(|value| value.strip_suffix(".execution.lock"))
        .context("retired managed lease name is not canonical")?;
    let (prefix, nonce) = body
        .rsplit_once('-')
        .context("retired managed lease nonce is missing")?;
    let (agent_id, generation) = prefix
        .rsplit_once('-')
        .context("retired managed lease generation is missing")?;
    let generation = generation
        .parse::<u64>()
        .context("retired managed lease generation is malformed")?;
    let incarnation = ManagedIncarnation {
        generation,
        nonce: nonce.to_string(),
        active: true,
    };
    if managed_worktree_lease_name(agent_id, &incarnation)?.to_str() != Some(name) {
        bail!("retired managed lease name is not canonical");
    }
    Ok((agent_id.to_string(), incarnation))
}

fn managed_registry_checksum(registry: &ManagedWorktreeRegistry) -> Result<String> {
    let payload = serde_json::to_vec(&(
        registry.version,
        &registry.repository,
        &registry.records,
        &registry.operations,
    ))
    .context("failed to encode managed worktree registry checksum payload")?;
    Ok(stable_checksum(&payload))
}

fn validate_registry_bounds(registry: &ManagedWorktreeRegistry) -> Result<()> {
    if registry.records.len() > MAX_MANAGED_RECORDS {
        bail!(
            "managed worktree registry has {} records, exceeding its limit of {MAX_MANAGED_RECORDS}",
            registry.records.len()
        );
    }
    if registry.operations.len() > MAX_MANAGED_OPERATIONS {
        bail!(
            "managed worktree registry has {} operations, exceeding its limit of {MAX_MANAGED_OPERATIONS}",
            registry.operations.len()
        );
    }
    for (name, binding) in &registry.records {
        if normalize_agent_id(name)? != *name || binding.name != *name {
            bail!("managed worktree registry record key/name is not canonical");
        }
        validate_branch_name(&binding.branch)?;
    }
    for (name, operation) in &registry.operations {
        if normalize_agent_id(name)? != *name || operation.name != *name {
            bail!("managed worktree registry operation key/name is not canonical");
        }
        validate_branch_name(&operation.branch)?;
        if let Some(checksum) = operation.gc_dirtiness_checksum.as_deref() {
            if operation.kind != ManagedWorktreeOperationKind::Remove
                || checksum.len() > 128
                || !checksum.starts_with("maco-v1-")
                || !checksum.bytes().all(|byte| byte.is_ascii_graphic())
                || operation.removal_safety.is_some()
            {
                bail!("managed worktree operation has invalid legacy GC safety state");
            }
        }
        if let Some(safety) = operation.removal_safety.as_ref() {
            if operation.kind != ManagedWorktreeOperationKind::Remove {
                bail!("managed worktree create operation has removal safety state");
            }
            validate_managed_removal_safety(operation, safety)?;
        }
    }
    Ok(())
}

fn validate_managed_removal_safety(
    operation: &ManagedWorktreeOperation,
    safety: &ManagedRemovalSafety,
) -> Result<()> {
    match safety {
        ManagedRemovalSafety::Explicit => Ok(()),
        ManagedRemovalSafety::GarbageCollection { dirtiness, target } => {
            if !operation.force || operation.delete_branch {
                bail!("managed GC removal safety state has incompatible removal flags");
            }
            match dirtiness {
                ManagedGcDirtinessSnapshot::Clean => {}
                ManagedGcDirtinessSnapshot::UntrackedOnly { paths } => {
                    if paths.is_empty() || paths.len() > MAX_GC_ALLOWED_UNTRACKED_PATHS {
                        bail!("managed GC dirtiness snapshot path count is out of bounds");
                    }
                    let mut total_bytes = 0usize;
                    let mut previous = None;
                    for wire in paths {
                        let path = worktree_report_path_from_wire(wire)?;
                        if previous
                            .as_ref()
                            .is_some_and(|prior: &PathBuf| prior >= &path)
                        {
                            bail!("managed GC dirtiness snapshot paths are not canonical");
                        }
                        total_bytes = total_bytes
                            .checked_add(worktree_path_native_bytes(&path))
                            .context("managed GC dirtiness snapshot byte count overflowed")?;
                        if total_bytes > MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES {
                            bail!("managed GC dirtiness snapshot exceeds its aggregate byte bound");
                        }
                        previous = Some(path);
                    }
                }
            }
            if let ManagedGcTargetSnapshot::Present { identity } = target {
                if identity.device == 0 || identity.file == 0 {
                    bail!("managed GC target snapshot has an invalid filesystem identity");
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
fn recover_pending_operations(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
) -> Result<()> {
    recover_pending_operations_with_authority(
        repo,
        store,
        lock,
        registry,
        None,
        CreationCleanliness::TestOnly,
    )
}

#[cfg(not(test))]
fn recover_pending_operations(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
) -> Result<()> {
    recover_pending_operations_without_creation_cleanliness(repo, store, lock, registry, None)
}

fn recover_pending_operations_with_creation_cleanliness(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    recover_pending_operations_with_authority(repo, store, lock, registry, None, cleanliness)
}

#[cfg(test)]
fn recover_pending_operations_with_held_removal_lease(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
) -> Result<()> {
    recover_pending_operations_with_authority(
        repo,
        store,
        lock,
        registry,
        held_removal_lease,
        CreationCleanliness::TestOnly,
    )
}

#[cfg(not(test))]
fn recover_pending_operations_with_held_removal_lease(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
) -> Result<()> {
    recover_pending_operations_without_creation_cleanliness(
        repo,
        store,
        lock,
        registry,
        held_removal_lease,
    )
}

#[cfg(not(test))]
fn recover_pending_operations_without_creation_cleanliness(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
) -> Result<()> {
    if registry
        .operations
        .values()
        .any(|operation| operation.kind == ManagedWorktreeOperationKind::Create)
        || registry
            .records
            .values()
            .any(|binding| binding.creation_lock_pending)
    {
        bail!(
            "managed worktree create recovery requires a capability-bound repository cleanliness input"
        );
    }

    let names = registry.operations.keys().cloned().collect::<Vec<_>>();
    for name in names {
        store.verify_authenticated_registry(lock, registry)?;
        let operation = registry
            .operations
            .get(&name)
            .cloned()
            .context("managed worktree operation disappeared during recovery")?;
        if operation.name != name {
            bail!("managed worktree operation key/name mismatch for '{name}'");
        }
        if operation.kind != ManagedWorktreeOperationKind::Remove {
            bail!("managed worktree create recovery reached an unbound recovery path");
        }
        recover_remove_operation_with_lease(
            repo,
            store,
            lock,
            registry,
            operation,
            held_removal_lease,
        )?;
    }
    store.verify_authenticated_registry(lock, registry)
}

fn recover_pending_operations_with_authority(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    let names = registry.operations.keys().cloned().collect::<Vec<_>>();
    for name in names {
        store.verify_authenticated_registry(lock, registry)?;
        let operation = registry
            .operations
            .get(&name)
            .cloned()
            .context("managed worktree operation disappeared during recovery")?;
        if operation.name != name {
            bail!("managed worktree operation key/name mismatch for '{name}'");
        }
        match operation.kind {
            ManagedWorktreeOperationKind::Create => {
                recover_create_operation(repo, store, lock, registry, operation, cleanliness)?
            }
            ManagedWorktreeOperationKind::Remove => recover_remove_operation_with_lease(
                repo,
                store,
                lock,
                registry,
                operation,
                held_removal_lease,
            )?,
        }
    }
    reconcile_creation_locks(repo, store, lock, registry, cleanliness)
}

fn recover_remove_operation_with_lease(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    operation: ManagedWorktreeOperation,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
) -> Result<()> {
    recover_remove_operation_with_lease_using_target_liveness(
        repo,
        store,
        lock,
        registry,
        operation,
        held_removal_lease,
        &worktree_target_liveness,
    )
}

fn recover_remove_operation_with_lease_using_target_liveness(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    operation: ManagedWorktreeOperation,
    held_removal_lease: Option<&ManagedWorktreeRemovalLease>,
    target_liveness: &dyn Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
) -> Result<()> {
    let name = operation.name.clone();
    let _lease = if let Some(lease) =
        held_removal_lease.filter(|lease| lease.name.as_str() == name.as_str())
    {
        store.verify_removal_lease_current(lock, lease)?;
        None
    } else {
        Some(
            store
                .try_acquire_worktree_removal_lease(lock, &name)
                .with_context(|| {
                    format!(
                        "managed worktree '{name}' has an active cooperative execution lease; pending removal remains durable"
                    )
                })?,
        )
    };
    recover_remove_operation(repo, store, lock, registry, operation, target_liveness)
}

fn recover_create_operation(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    mut operation: ManagedWorktreeOperation,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    if operation.phase == ManagedWorktreeOperationPhase::CreateIntent {
        store.verify_authenticated_registry(lock, registry)?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity
            || root.direct_child(&operation.name)? != operation.path
        {
            bail!(
                "create intent '{}' root/path binding changed; refusing recovery",
                operation.name
            );
        }
        let metadata_dir = store
            .repository
            .common_dir
            .join("worktrees")
            .join(&operation.name);
        if path_entry_exists(&metadata_dir)? {
            bail!(
                "create intent '{}' unexpectedly has Git metadata; refusing recovery",
                operation.name
            );
        }
        match (
            operation.branch_preexisting_oid.as_deref(),
            local_branch_oid(repo, &operation.branch)?,
        ) {
            (Some(expected), Some(observed))
                if Oid::from_str(expected)
                    .context("create intent has malformed pre-existing branch OID")?
                    == observed => {}
            (Some(_), _) => bail!(
                "pre-existing branch '{}' changed during create-intent recovery",
                operation.branch
            ),
            (None, None) => {}
            (None, Some(_)) => bail!(
                "create intent '{}' unexpectedly created branch '{}' before reservation was durable",
                operation.name,
                operation.branch
            ),
        }
        if let Some(staging_root_path) = operation.staging_root.as_ref() {
            if staging_root_path.parent() != Some(root.path()) {
                bail!("create intent staging root escaped its managed root");
            }
            if let Some(staging_path) = operation.staging_path.as_ref() {
                if staging_path.parent() != Some(staging_root_path.as_path())
                    || staging_path.file_name() != Some(OsStr::new(&operation.name))
                {
                    bail!("create intent staging path binding is inconsistent");
                }
            }
            if path_entry_exists(staging_root_path)? {
                bail!(
                    "create intent '{}' found an unbound staging directory with no persisted child identity; preserving it for manual recovery",
                    operation.name
                );
            }
        }
        if path_entry_exists(&operation.path)? {
            bail!(
                "create intent '{}' found an unbound target directory with no persisted child identity; preserving it for manual recovery",
                operation.name
            );
        }
        registry.operations.remove(&operation.name);
        store.save(lock, registry)?;
        return Ok(());
    }

    if !matches!(
        operation.phase,
        ManagedWorktreeOperationPhase::CreatePrepared
            | ManagedWorktreeOperationPhase::CreateStaged
            | ManagedWorktreeOperationPhase::CreateObserved
    ) {
        bail!(
            "create operation '{}' has invalid phase {:?}",
            operation.name,
            operation.phase
        );
    }

    if operation.phase == ManagedWorktreeOperationPhase::CreatePrepared {
        store.verify_authenticated_registry(lock, registry)?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity {
            bail!(
                "create operation '{}' root identity changed; refusing recovery",
                operation.name
            );
        }
        if root.direct_child(&operation.name)? != operation.path {
            bail!(
                "create operation '{}' path binding is inconsistent",
                operation.name
            );
        }
        let metadata_dir = store
            .repository
            .common_dir
            .join("worktrees")
            .join(&operation.name);
        let metadata_exists = path_entry_exists(&metadata_dir)?;
        let final_path_exists = path_entry_exists(&operation.path)?;
        let prepared_identity = operation.prepared_path_identity.as_ref().with_context(|| {
            format!(
                "create operation '{}' has no prepared directory identity",
                operation.name
            )
        })?;
        let (staging_root, staging_path, staging_root_identity) =
            open_operation_staging_root(&root, &operation)?;
        let staging_path_exists = path_entry_exists(&staging_path)?;

        if !metadata_exists {
            if staging_path_exists {
                bail!(
                    "create operation '{}' left an unbound staging child with no persisted identity; preserving it for manual recovery",
                    operation.name
                );
            }
            if final_path_exists {
                let reserved = root.bind_existing_direct_child_directory(&operation.name)?;
                if reserved.identity() != prepared_identity || !reserved.is_empty()? {
                    bail!(
                        "create operation '{}' left a changed or non-empty unbound path; preserving it for manual recovery",
                        operation.name
                    );
                }
                record_pre_worktree_bypass(
                    &operation.name,
                    "delete_empty_pre_worktree_reservation_recovery",
                    reserved.path(),
                );
                remove_direct_child_tree(
                    &root,
                    &operation.name,
                    Some(prepared_identity),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
            }
            remove_staging_root_if_empty(
                &root,
                &staging_root,
                &staging_root_identity,
                &operation.name,
            )?;
            cleanup_create_branch_if_owned(repo, &operation)?;
            registry.operations.remove(&operation.name);
            store.save(lock, registry)?;
            return Ok(());
        }
        if !staging_path_exists {
            bail!(
                "create operation '{}' has Git metadata but no staged worktree path; refusing automatic recovery",
                operation.name
            );
        }
        if !final_path_exists
            || root
                .bind_existing_direct_child_directory(&operation.name)?
                .identity()
                != prepared_identity
        {
            bail!(
                "create operation '{}' final reservation identity changed before recovery",
                operation.name
            );
        }
        ensure_creation_worktree_locked(repo, &operation.name)?;
        let _branch_guard = lock_branch_reference(repo, &operation.branch)?;
        let expected_branch_oid = verify_create_branch_exact(repo, &operation)?;
        verify_worktree_clean_at(
            &staging_path,
            &operation.branch,
            expected_branch_oid,
            cleanliness,
        )?;
        let staged = staging_root.bind_existing_managed_direct_child_directory(&operation.name)?;
        let staged_metadata = capture_staged_worktree_metadata(
            &store.repository,
            &operation.name,
            &operation.branch,
            &staging_path,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::CreateStaged;
        operation.staged_path_identity = Some(staged.identity().clone());
        operation.staged_metadata = Some(staged_metadata);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::CreateStaged {
        store.verify_authenticated_registry(lock, registry)?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity {
            bail!(
                "create-staged root identity changed for '{}'",
                operation.name
            );
        }
        ensure_creation_worktree_locked(repo, &operation.name)?;
        let _branch_guard = lock_branch_reference(repo, &operation.branch)?;
        let expected_branch_oid = verify_create_branch_exact(repo, &operation)?;
        let prepared_identity = operation
            .prepared_path_identity
            .as_ref()
            .context("create-staged operation lacks final reservation identity")?;
        let staged_identity = operation
            .staged_path_identity
            .as_ref()
            .context("create-staged operation lacks staged worktree identity")?;
        let (staging_root, staging_path, _staging_root_identity) =
            open_operation_staging_root(&root, &operation)?;
        let metadata_dir = store
            .repository
            .common_dir
            .join("worktrees")
            .join(&operation.name);
        if !path_entry_exists(&metadata_dir)? {
            bail!(
                "create-staged operation '{}' lost Git metadata",
                operation.name
            );
        }
        let staged_metadata = operation
            .staged_metadata
            .as_ref()
            .context("create-staged operation lacks staged metadata identity")?;
        let worktree_git_file = staging_path.join(".git");
        let metadata_gitdir_file = metadata_dir.join("gitdir");
        let staging_exists = path_entry_exists(&staging_path)?;
        let current_worktree_path = if staging_exists {
            staging_path.as_path()
        } else {
            operation.path.as_path()
        };
        let original_gitdir_identity = verify_staged_worktree_metadata(
            staged_metadata,
            &store.repository,
            &operation.branch,
            current_worktree_path,
        )?;
        if !original_gitdir_identity {
            if staging_exists {
                bail!("staged gitdir metadata changed before the final directory rename");
            }
            verify_gitdir_backlinks(
                &operation.path.join(".git"),
                &metadata_dir,
                &metadata_gitdir_file,
                &operation.path,
            )?;
        }
        if staging_exists {
            let final_reserved = root.bind_existing_direct_child_directory(&operation.name)?;
            if final_reserved.identity() != prepared_identity {
                bail!("final worktree reservation changed before staged rename");
            }
            let staged =
                staging_root.bind_existing_managed_direct_child_directory(&operation.name)?;
            if staged.identity() != staged_identity {
                bail!("staged worktree identity changed before final rename");
            }
            verify_gitdir_backlinks(
                &worktree_git_file,
                &metadata_dir,
                &metadata_gitdir_file,
                &staging_path,
            )?;
            record_pre_worktree_bypass(
                &operation.name,
                "replace_empty_pre_worktree_reservation_with_staged_worktree",
                final_reserved.path(),
            );
            let moved_identity =
                replace_reserved_directory_from(&root, &final_reserved, &staging_root, &staged)?;
            if &moved_identity != staged_identity {
                bail!("staged worktree identity changed during final rename");
            }
        } else {
            let final_worktree =
                root.bind_existing_managed_direct_child_directory(&operation.name)?;
            if final_worktree.identity() != staged_identity {
                bail!("neither staging nor final path matches the staged worktree identity");
            }
        }

        let metadata_root = SafeRoot::open_existing(&metadata_dir)?;
        let backlink = gitdir_backlink_bytes(&operation.path.join(".git"))?;
        AtomicStateWriter::write_direct(&metadata_root, "gitdir", &backlink)?;
        verify_gitdir_backlinks(
            &operation.path.join(".git"),
            &metadata_dir,
            &metadata_gitdir_file,
            &operation.path,
        )?;
        verify_worktree_clean_at(
            &operation.path,
            &operation.branch,
            expected_branch_oid,
            cleanliness,
        )?;
        verify_local_branch_oid(repo, &operation.branch, expected_branch_oid)?;
        let base_oid =
            Oid::from_str(&operation.base_oid).context("create operation base OID is malformed")?;
        let mut binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
        binding.created_at_unix_nanos = Some(unix_now_nanos()?);
        operation.phase = ManagedWorktreeOperationPhase::CreateObserved;
        operation.binding = Some(binding);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::CreateObserved {
        store.verify_authenticated_registry(lock, registry)?;
        ensure_creation_worktree_locked(repo, &operation.name)?;
        let _branch_guard = lock_branch_reference(repo, &operation.branch)?;
        let expected_branch_oid = verify_create_branch_exact(repo, &operation)?;
        verify_worktree_clean_at(
            &operation.path,
            &operation.branch,
            expected_branch_oid,
            cleanliness,
        )?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity {
            bail!("create-observed root identity changed before finalization");
        }
        let base_oid =
            Oid::from_str(&operation.base_oid).context("create operation base OID is malformed")?;
        let binding = operation.binding.clone().with_context(|| {
            format!(
                "create operation '{}' reached observed phase without a binding",
                operation.name
            )
        })?;
        let mut observed_binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
        observed_binding.created_at_unix_nanos = binding.created_at_unix_nanos;
        if binding != observed_binding {
            bail!(
                "create operation '{}' binding changed before finalization",
                operation.name
            );
        }
        if let (Some(staging_root_path), Some(staging_root_identity)) = (
            operation.staging_root.as_ref(),
            operation.staging_root_identity.as_ref(),
        ) {
            if path_entry_exists(staging_root_path)? {
                let staging_root = SafeRoot::open_existing(staging_root_path)?;
                if staging_root.identity() != staging_root_identity {
                    bail!("create-observed staging root identity changed before cleanup");
                }
                remove_staging_root_if_empty(
                    &root,
                    &staging_root,
                    staging_root_identity,
                    &operation.name,
                )?;
            }
        }
        if let Some(existing) = registry.records.get(&operation.name) {
            if existing != &binding {
                bail!(
                    "create operation '{}' conflicts with a different finalized binding",
                    operation.name
                );
            }
        } else {
            registry.records.insert(operation.name.clone(), binding);
        }
        registry.operations.remove(&operation.name);
        store.save(lock, registry)?;
        complete_creation_lock(repo, store, lock, registry, &operation.name, cleanliness)?;
        return Ok(());
    }

    bail!(
        "create operation '{}' did not reach its observed phase",
        operation.name
    )
}

fn open_operation_staging_root(
    root: &SafeRoot,
    operation: &ManagedWorktreeOperation,
) -> Result<(SafeRoot, PathBuf, FileIdentity)> {
    let staging_root_path = operation
        .staging_root
        .as_ref()
        .context("create operation lacks a staging root")?;
    let staging_root_identity = operation
        .staging_root_identity
        .as_ref()
        .context("create operation lacks a staging root identity")?;
    if staging_root_path.parent() != Some(root.path()) {
        bail!("create operation staging root escaped its managed root");
    }
    let staging_root = SafeRoot::open_existing(staging_root_path)?;
    if staging_root.identity() != staging_root_identity {
        bail!("create operation staging root identity changed");
    }
    let staging_path = operation
        .staging_path
        .clone()
        .context("create operation lacks a staging path")?;
    if staging_path.parent() != Some(staging_root.path())
        || staging_path.file_name() != Some(OsStr::new(&operation.name))
    {
        bail!("create operation staging path binding is inconsistent");
    }
    Ok((staging_root, staging_path, staging_root_identity.clone()))
}

fn remove_staging_root_if_empty(
    managed_root: &SafeRoot,
    staging_root: &SafeRoot,
    expected: &FileIdentity,
    actor: &str,
) -> Result<()> {
    if !staging_root.is_empty()? {
        bail!(
            "staging root is not empty after worktree recovery: {}",
            staging_root.path().display()
        );
    }
    let name = staging_root
        .path()
        .file_name()
        .context("staging root has no final component")?;
    record_pre_worktree_bypass(
        actor,
        "delete_empty_pre_worktree_staging_recovery_or_finalize",
        staging_root.path(),
    );
    remove_direct_child_tree(
        managed_root,
        name,
        Some(expected),
        TreeLinkPolicy::UnlinkLinks,
    )
}

fn record_pre_worktree_bypass(actor: &str, operation: &str, path: &Path) {
    tracing::warn!(
        actor,
        operation,
        target = %path.display(),
        process_attribution = "not_process_observable",
        "machine-global cleanup bypass"
    );
}

#[cfg(unix)]
fn gitdir_backlink_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        bail!("Git metadata backlink path contains a newline");
    }
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(not(unix))]
fn gitdir_backlink_bytes(path: &Path) -> Result<Vec<u8>> {
    let _ = path;
    bail!("byte-exact Git metadata backlink writes are unsupported on this platform")
}

fn lock_branch_reference<'repo>(
    repo: &'repo Repository,
    branch: &str,
) -> Result<Transaction<'repo>> {
    validate_branch_name(branch)?;
    let reference_name = format!("refs/heads/{branch}");
    let mut transaction = repo
        .transaction()
        .context("failed to start Git reference transaction")?;
    transaction
        .lock_ref(&reference_name)
        .with_context(|| format!("failed to lock branch '{branch}' during worktree creation"))?;
    Ok(transaction)
}

fn expected_create_branch_oid(operation: &ManagedWorktreeOperation) -> Result<Oid> {
    match operation.branch_ownership {
        ManagedBranchOwnership::Unknown => {
            bail!("create operation branch ownership is unknown; refusing finalization")
        }
        ManagedBranchOwnership::CreatedByMaco => {
            let expected = operation
                .owned_branch_oid
                .as_deref()
                .map(Oid::from_str)
                .transpose()
                .context("create operation owned branch OID is malformed")?
                .context("create operation lacks its owned branch OID")?;
            let base = Oid::from_str(&operation.base_oid)
                .context("create operation base OID is malformed")?;
            if expected != base {
                bail!("MACO-created branch did not remain at its requested base OID");
            }
            Ok(expected)
        }
        ManagedBranchOwnership::Preexisting => operation
            .branch_preexisting_oid
            .as_deref()
            .map(Oid::from_str)
            .transpose()
            .context("create operation has malformed pre-existing branch OID")?
            .context("create operation lacks its pre-existing branch OID"),
    }
}

fn verify_local_branch_oid(repo: &Repository, branch: &str, expected: Oid) -> Result<Oid> {
    let current = local_branch_oid(repo, branch)?
        .with_context(|| format!("create operation has no local branch '{branch}'"))?;
    if current != expected {
        bail!(
            "branch '{branch}' changed during worktree creation: expected {expected}, observed {current}"
        );
    }
    Ok(current)
}

fn verify_create_branch_exact(
    repo: &Repository,
    operation: &ManagedWorktreeOperation,
) -> Result<Oid> {
    let expected = expected_create_branch_oid(operation)?;
    verify_local_branch_oid(repo, &operation.branch, expected)
}

fn ensure_creation_worktree_locked(repo: &Repository, name: &str) -> Result<()> {
    let worktree = repo
        .find_worktree(name)
        .with_context(|| format!("failed to find in-progress worktree '{name}'"))?;
    match worktree
        .is_locked()
        .with_context(|| format!("failed to inspect creation lock for worktree '{name}'"))?
    {
        WorktreeLockStatus::Locked(_) => Ok(()),
        WorktreeLockStatus::Unlocked => {
            bail!("in-progress worktree '{name}' lost its Git creation lock")
        }
    }
}

fn verify_worktree_clean_at(
    path: &Path,
    branch: &str,
    expected: Oid,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    let worktree_repo = crate::git_repository::open(path)
        .with_context(|| format!("failed to open created worktree {}", path.display()))?;
    let expected_reference = format!("refs/heads/{branch}");
    let verify_head = || -> Result<()> {
        let head = worktree_repo
            .head()
            .context("failed to inspect created worktree HEAD")?;
        let head_name = head
            .name()
            .context("created worktree HEAD name is not valid UTF-8")?;
        if !head.is_branch() || head_name != expected_reference {
            bail!("created worktree HEAD is not bound to '{expected_reference}'");
        }
        let observed = head
            .target()
            .context("created worktree HEAD has no direct target")?;
        if observed != expected {
            bail!(
                "created worktree HEAD changed during finalization: expected {expected}, observed {observed}"
            );
        }
        Ok(())
    };
    verify_head()?;
    cleanliness
        .require_clean_related_worktree(path)
        .context("created worktree is not clean at its persisted branch OID")?;

    let mut index = worktree_repo
        .index()
        .context("failed to open created worktree index")?;
    if index.len() > MAX_WORKTREE_STATUS_ENTRIES {
        bail!(
            "created worktree index has {} entries, exceeding its limit of {MAX_WORKTREE_STATUS_ENTRIES}",
            index.len()
        );
    }
    let index_tree = index
        .write_tree()
        .context("failed to materialize created worktree index tree")?;
    let expected_tree = worktree_repo
        .find_commit(expected)
        .context("failed to find created worktree commit")?
        .tree_id();
    if index_tree != expected_tree {
        bail!("created worktree index does not match its persisted branch OID");
    }

    verify_head()
}

fn complete_creation_lock(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    name: &str,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    let binding = registry
        .records
        .get(name)
        .cloned()
        .with_context(|| format!("creation lock binding disappeared for '{name}'"))?;
    if !binding.creation_lock_pending {
        return Ok(());
    }
    let verified = verify_managed_worktree_binding(repo, &store.repository, &binding, false)?;
    let expected = Oid::from_str(&binding.created_branch_oid)
        .context("managed creation-lock branch OID is malformed")?;
    verify_local_branch_oid(repo, &binding.branch, expected)?;
    verify_worktree_clean_at(&verified.path, &binding.branch, expected, cleanliness)?;
    let worktree = repo
        .find_worktree(name)
        .with_context(|| format!("failed to find finalized worktree '{name}'"))?;
    match worktree
        .is_locked()
        .with_context(|| format!("failed to inspect finalized worktree lock for '{name}'"))?
    {
        WorktreeLockStatus::Locked(_) => worktree
            .unlock()
            .with_context(|| format!("failed to release creation lock for worktree '{name}'"))?,
        WorktreeLockStatus::Unlocked => {}
    }
    registry
        .records
        .get_mut(name)
        .context("creation lock binding disappeared before completion")?
        .creation_lock_pending = false;
    store.save(lock, registry)
}

fn reconcile_creation_locks(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    cleanliness: CreationCleanliness<'_>,
) -> Result<()> {
    let names = registry
        .records
        .iter()
        .filter(|(_, binding)| binding.creation_lock_pending)
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    for name in names {
        let branch = registry
            .records
            .get(&name)
            .context("creation lock binding disappeared during recovery")?
            .branch
            .clone();
        let _branch_guard = lock_branch_reference(repo, &branch)?;
        complete_creation_lock(repo, store, lock, registry, &name, cleanliness)?;
    }
    Ok(())
}

fn ensure_gc_target_snapshot_matches(
    operation_name: &str,
    expected: &ManagedGcTargetSnapshot,
    current: Option<&WorktreeGcTarget>,
) -> Result<()> {
    match (expected, current) {
        (ManagedGcTargetSnapshot::Absent, None) => Ok(()),
        (ManagedGcTargetSnapshot::Present { identity }, Some(target))
            if identity == &target.identity =>
        {
            Ok(())
        }
        (ManagedGcTargetSnapshot::Absent, Some(_)) => bail!(
            "pending GC removal '{}' target changed from absent to present before quarantine",
            operation_name
        ),
        (ManagedGcTargetSnapshot::Present { .. }, None) => bail!(
            "pending GC removal '{}' target changed from present to absent before quarantine",
            operation_name
        ),
        (ManagedGcTargetSnapshot::Present { .. }, Some(_)) => bail!(
            "pending GC removal '{}' target filesystem identity changed before quarantine",
            operation_name
        ),
    }
}

fn recover_remove_operation(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    registry: &mut ManagedWorktreeRegistry,
    mut operation: ManagedWorktreeOperation,
    target_liveness: &dyn Fn(&WorktreeGcTarget) -> WorktreeTargetLiveness,
) -> Result<()> {
    let binding = operation.binding.clone().with_context(|| {
        format!(
            "remove operation '{}' has no create-time binding",
            operation.name
        )
    })?;
    if operation.removal_safety.is_none() {
        bail!(
            "legacy pending removal '{}' has ambiguous safety state in phase {}; rerun explicit remove --force to reauthorize it",
            operation.name,
            managed_operation_phase_label(operation.phase)
        );
    }
    let expected_branch_oid = operation
        .expected_branch_oid
        .as_deref()
        .map(Oid::from_str)
        .transpose()
        .context("remove operation has malformed expected branch OID")?;
    if operation.delete_branch && !binding.branch_created_by_maco {
        bail!(
            "remove operation '{}' cannot delete a branch that predates MACO",
            operation.name
        );
    }

    if operation.phase == ManagedWorktreeOperationPhase::RemovePrepared {
        store.verify_authenticated_registry(lock, registry)?;
        let worktree_quarantine = operation_worktree_quarantine_path(&operation)?;
        let path_exists = path_entry_exists(&binding.path)?;
        let quarantine_exists = path_entry_exists(&worktree_quarantine)?;
        if path_exists == quarantine_exists {
            bail!(
                "remove operation '{}' requires exactly one of its worktree source and quarantine to exist",
                operation.name
            );
        }
        let metadata_quarantine = operation_metadata_quarantine_path(&operation)?;
        let metadata_exists = path_entry_exists(&binding.metadata_dir)?;
        let metadata_quarantine_exists = path_entry_exists(&metadata_quarantine)?;
        if !metadata_exists || metadata_quarantine_exists {
            bail!(
                "remove operation '{}' metadata state is inconsistent before worktree quarantine",
                operation.name
            );
        }
        verify_recovering_branch(
            repo,
            &binding,
            expected_branch_oid,
            operation.delete_branch,
            true,
        )?;
        if path_exists {
            let verified = verify_managed_worktree_binding(
                repo,
                &store.repository,
                &binding,
                operation.delete_branch,
            )?;
            let current_target = gc_target_if_present(&verified.path)?;
            if let Some(ManagedRemovalSafety::GarbageCollection { target, .. }) =
                operation.removal_safety.as_ref()
            {
                ensure_gc_target_snapshot_matches(
                    &operation.name,
                    target,
                    current_target.as_ref(),
                )?;
            }
            if let Some(target) = current_target.as_ref() {
                match target_liveness(target) {
                    WorktreeTargetLiveness::Clear => {}
                    WorktreeTargetLiveness::Live(evidence) => bail!(
                        "pending removal '{}' refused target liveness state=live before quarantine: {}",
                        operation.name,
                        serde_json::to_string(&evidence)
                            .context("failed to encode target liveness evidence")?
                    ),
                    WorktreeTargetLiveness::Unknown(evidence) => bail!(
                        "pending removal '{}' refused target liveness state=unknown before quarantine: {}",
                        operation.name,
                        serde_json::to_string(&evidence)
                            .context("failed to encode target liveness evidence")?
                    ),
                }
            }
            match operation.removal_safety.as_ref() {
                Some(ManagedRemovalSafety::GarbageCollection { dirtiness, .. }) => {
                    let current = gc_worktree_dirtiness(&verified.path)?;
                    let current_snapshot =
                        managed_gc_dirtiness_snapshot(&current).with_context(|| {
                            format!(
                            "pending GC removal '{}' observed tracked changes before quarantine",
                            operation.name
                        )
                        })?;
                    if &current_snapshot != dirtiness {
                        bail!(
                            "pending GC removal '{}' dirtiness changed before quarantine",
                            operation.name
                        );
                    }
                }
                Some(ManagedRemovalSafety::Explicit) if operation.force => {}
                Some(ManagedRemovalSafety::Explicit) => {
                    ensure_clean_worktree(&verified.path).with_context(|| {
                        format!(
                            "pending explicit removal '{}' requires a clean worktree",
                            operation.name
                        )
                    })?;
                }
                None => bail!(
                    "legacy pending removal '{}' has ambiguous safety state; rerun explicit remove --force to reauthorize it",
                    operation.name
                ),
            }
        }
        ensure_removal_worktree_lock(repo, &binding)?;
        let quarantined = quarantine_bound_directory(
            &binding.root,
            &binding.path,
            &worktree_quarantine,
            &binding.path_identity,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::WorktreeQuarantined;
        operation.worktree_quarantine_identity = Some(quarantined);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::WorktreeQuarantined {
        store.verify_authenticated_registry(lock, registry)?;
        let worktree_quarantine = operation_worktree_quarantine_path(&operation)?;
        let worktree_quarantine_identity = operation
            .worktree_quarantine_identity
            .as_ref()
            .context("worktree-quarantined operation lacks its quarantine identity")?;
        if worktree_quarantine_identity != &binding.path_identity {
            bail!("worktree quarantine identity differs from its create-time binding");
        }
        quarantine_bound_directory(
            &binding.root,
            &binding.path,
            &worktree_quarantine,
            worktree_quarantine_identity,
        )?;
        let metadata_quarantine = operation_metadata_quarantine_path(&operation)?;
        let metadata_exists = path_entry_exists(&binding.metadata_dir)?;
        let metadata_quarantine_exists = path_entry_exists(&metadata_quarantine)?;
        if metadata_exists == metadata_quarantine_exists {
            bail!(
                "remove operation '{}' requires exactly one of its metadata source and quarantine to exist",
                operation.name
            );
        }
        if metadata_exists {
            verify_metadata_binding_after_worktree_removal(&store.repository, &binding)?;
            ensure_removal_worktree_lock(repo, &binding)?;
        }
        let metadata_root = store.repository.common_dir.join("worktrees");
        let quarantined = quarantine_bound_directory(
            &metadata_root,
            &binding.metadata_dir,
            &metadata_quarantine,
            &binding.metadata_dir_identity,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::MetadataQuarantined;
        operation.metadata_quarantine_identity = Some(quarantined);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::MetadataQuarantined {
        store.verify_authenticated_registry(lock, registry)?;
        ensure_original_binding_absent(&binding.path, "worktree")?;
        ensure_original_binding_absent(&binding.metadata_dir, "metadata")?;
        let worktree_quarantine = operation_worktree_quarantine_path(&operation)?;
        let worktree_quarantine_identity = operation
            .worktree_quarantine_identity
            .as_ref()
            .context("metadata-quarantined operation lacks worktree quarantine identity")?;
        remove_quarantined_bound_directory(
            &binding.root,
            &worktree_quarantine,
            worktree_quarantine_identity,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::WorktreeDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::WorktreeDeleted {
        store.verify_authenticated_registry(lock, registry)?;
        ensure_original_binding_absent(&binding.path, "worktree")?;
        ensure_original_binding_absent(&binding.metadata_dir, "metadata")?;
        let metadata_quarantine = operation_metadata_quarantine_path(&operation)?;
        let metadata_quarantine_identity = operation
            .metadata_quarantine_identity
            .as_ref()
            .context("worktree-deleted operation lacks metadata quarantine identity")?;
        remove_quarantined_bound_directory(
            &store.repository.common_dir.join("worktrees"),
            &metadata_quarantine,
            metadata_quarantine_identity,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::MetadataDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::MetadataDeleted {
        store.verify_authenticated_registry(lock, registry)?;
        ensure_original_binding_absent(&binding.path, "worktree")?;
        ensure_original_binding_absent(&binding.metadata_dir, "metadata")?;
        if operation.delete_branch {
            compare_and_delete_local_branch(
                repo,
                &binding.branch,
                expected_branch_oid.context("remove operation lacks expected branch OID")?,
                true,
                "managed worktree removal",
            )?;
        }
        operation.phase = ManagedWorktreeOperationPhase::BranchDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(lock, registry)?;
    }

    if operation.phase != ManagedWorktreeOperationPhase::BranchDeleted {
        bail!(
            "remove operation '{}' has invalid phase {:?}",
            operation.name,
            operation.phase
        );
    }
    store.verify_authenticated_registry(lock, registry)?;
    registry.records.remove(&operation.name);
    registry.operations.remove(&operation.name);
    store.save(lock, registry)
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn deterministic_remove_quarantine_path(
    root: &Path,
    kind: &str,
    name: &str,
    identity: &FileIdentity,
) -> PathBuf {
    let payload = format!(
        "{kind}\0{name}\0{:016x}\0{:016x}",
        identity.device, identity.file
    );
    root.join(format!(
        ".maco-remove-{kind}-{}",
        stable_checksum(payload.as_bytes())
    ))
}

fn operation_worktree_quarantine_path(operation: &ManagedWorktreeOperation) -> Result<PathBuf> {
    let binding = operation
        .binding
        .as_ref()
        .context("remove operation lacks its managed binding")?;
    let expected = deterministic_remove_quarantine_path(
        &binding.root,
        "worktree",
        &binding.name,
        &binding.path_identity,
    );
    let observed = operation
        .worktree_quarantine_path
        .as_ref()
        .context("remove operation lacks its worktree quarantine path")?;
    if observed != &expected {
        bail!("remove operation worktree quarantine path is not deterministic");
    }
    Ok(expected)
}

fn operation_metadata_quarantine_path(operation: &ManagedWorktreeOperation) -> Result<PathBuf> {
    let binding = operation
        .binding
        .as_ref()
        .context("remove operation lacks its managed binding")?;
    let metadata_root = binding
        .metadata_dir
        .parent()
        .context("managed metadata binding has no parent")?;
    let expected = deterministic_remove_quarantine_path(
        metadata_root,
        "metadata",
        &binding.name,
        &binding.metadata_dir_identity,
    );
    let observed = operation
        .metadata_quarantine_path
        .as_ref()
        .context("remove operation lacks its metadata quarantine path")?;
    if observed != &expected {
        bail!("remove operation metadata quarantine path is not deterministic");
    }
    Ok(expected)
}

fn quarantine_bound_directory(
    root_path: &Path,
    source_path: &Path,
    quarantine_path: &Path,
    expected: &FileIdentity,
) -> Result<FileIdentity> {
    let root = SafeRoot::open_existing(root_path)?;
    if source_path.parent() != Some(root.path()) || quarantine_path.parent() != Some(root.path()) {
        bail!("bound source or quarantine is not a direct child of its recorded root");
    }
    let source_name = source_path
        .file_name()
        .context("bound source directory has no final component")?;
    let quarantine_name = quarantine_path
        .file_name()
        .context("bound quarantine directory has no final component")?;
    quarantine_direct_child_directory(&root, source_name, quarantine_name, expected)
}

fn remove_quarantined_bound_directory(
    root_path: &Path,
    quarantine_path: &Path,
    expected: &FileIdentity,
) -> Result<bool> {
    let root = SafeRoot::open_existing(root_path)?;
    if quarantine_path.parent() != Some(root.path()) {
        bail!("bound quarantine is not a direct child of its recorded root");
    }
    let quarantine_name = quarantine_path
        .file_name()
        .context("bound quarantine directory has no final component")?;
    remove_quarantined_direct_child_tree(
        &root,
        quarantine_name,
        expected,
        TreeLinkPolicy::UnlinkLinks,
    )
}

fn ensure_original_binding_absent(path: &Path, kind: &str) -> Result<()> {
    if path_entry_exists(path)? {
        bail!("{kind} source path reappeared after durable quarantine");
    }
    Ok(())
}

fn ensure_removal_worktree_lock(repo: &Repository, binding: &ManagedWorktreeBinding) -> Result<()> {
    if path_entry_exists(&binding.metadata_dir.join("index.lock"))? {
        bail!(
            "managed worktree '{}' has an active Git index lock; stop the child before removal",
            binding.name
        );
    }
    let worktree = repo.find_worktree(&binding.name).with_context(|| {
        format!(
            "failed to find worktree '{}' before quarantine",
            binding.name
        )
    })?;
    match worktree
        .is_locked()
        .with_context(|| format!("failed to inspect worktree lock for '{}'", binding.name))?
    {
        WorktreeLockStatus::Unlocked => worktree
            .lock(Some(REMOVAL_LOCK_REASON))
            .with_context(|| format!("failed to lock worktree '{}' for removal", binding.name))?,
        WorktreeLockStatus::Locked(Some(reason)) if reason == REMOVAL_LOCK_REASON => {}
        WorktreeLockStatus::Locked(_) => bail!(
            "managed worktree '{}' is locked by another owner; stop it before removal",
            binding.name
        ),
    }
    match worktree
        .is_locked()
        .with_context(|| format!("failed to recheck worktree lock for '{}'", binding.name))?
    {
        WorktreeLockStatus::Locked(Some(reason)) if reason == REMOVAL_LOCK_REASON => Ok(()),
        _ => bail!("managed worktree removal lock was not retained"),
    }
}

fn cleanup_create_branch_if_owned(
    repo: &Repository,
    operation: &ManagedWorktreeOperation,
) -> Result<()> {
    if operation.branch_ownership != ManagedBranchOwnership::CreatedByMaco {
        return Ok(());
    }
    let expected = operation
        .owned_branch_oid
        .as_deref()
        .map(Oid::from_str)
        .transpose()
        .context("create operation owned branch OID is malformed")?
        .context("create operation marked branch-owned without an owned OID")?;
    compare_and_delete_local_branch(
        repo,
        &operation.branch,
        expected,
        true,
        "failed worktree creation cleanup",
    )
}

fn compare_and_delete_local_branch(
    repo: &Repository,
    branch: &str,
    expected: Oid,
    missing_ok: bool,
    action: &str,
) -> Result<()> {
    validate_branch_name(branch)?;
    let reference_name = format!("refs/heads/{branch}");
    let mut transaction = repo
        .transaction()
        .with_context(|| format!("failed to start ref transaction for {action}"))?;
    transaction
        .lock_ref(&reference_name)
        .with_context(|| format!("failed to lock branch '{branch}' for {action}"))?;
    match local_branch_oid(repo, branch)? {
        None if missing_ok => return Ok(()),
        None => bail!("branch '{branch}' disappeared before {action}"),
        Some(observed) if observed != expected => bail!(
            "branch '{branch}' changed before {action}; expected {expected}, observed {observed}; preserving it"
        ),
        Some(_) => {}
    }
    transaction
        .remove(&reference_name)
        .with_context(|| format!("failed to stage branch '{branch}' deletion for {action}"))?;
    transaction
        .commit()
        .with_context(|| format!("failed to commit branch '{branch}' deletion for {action}"))
}

fn local_branch_oid(repo: &Repository, branch: &str) -> Result<Option<Oid>> {
    match repo.find_branch(branch, BranchType::Local) {
        Ok(branch) => Ok(branch.get().target()),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect local branch '{branch}'"))
        }
    }
}

fn verify_recovering_branch(
    repo: &Repository,
    binding: &ManagedWorktreeBinding,
    expected_oid: Option<Oid>,
    delete_branch: bool,
    worktree_or_metadata_exists: bool,
) -> Result<()> {
    if !delete_branch {
        return Ok(());
    }
    match local_branch_oid(repo, &binding.branch)? {
        Some(observed) if Some(observed) == expected_oid => Ok(()),
        Some(_) => bail!(
            "managed branch '{}' changed during remove recovery",
            binding.branch
        ),
        None if !worktree_or_metadata_exists => Ok(()),
        None => bail!(
            "managed branch '{}' disappeared before bound directories were removed",
            binding.branch
        ),
    }
}

fn verify_metadata_binding_after_worktree_removal(
    repository: &ManagedRepositoryBinding,
    binding: &ManagedWorktreeBinding,
) -> Result<()> {
    let metadata_root = SafeRoot::open_existing(repository.common_dir.join("worktrees"))?;
    if binding.metadata_dir.parent() != Some(metadata_root.path())
        || identity_for_path(&binding.metadata_dir)? != binding.metadata_dir_identity
    {
        bail!("managed metadata directory changed during remove recovery");
    }
    let gitdir = binding.metadata_dir.join("gitdir");
    let head = binding.metadata_dir.join("HEAD");
    if BoundedRegularReader::identity(&gitdir)? != binding.metadata_gitdir_file_identity
        || BoundedRegularReader::identity(&head)? != binding.metadata_head_file_identity
    {
        bail!("managed metadata file identity changed during remove recovery");
    }
    verify_metadata_branch(&head, &binding.branch)?;
    let backlink = read_git_metadata_path(&gitdir, false)?;
    let backlink = resolve_metadata_path(&binding.metadata_dir, &backlink);
    if backlink != binding.path.join(".git") {
        bail!("managed metadata gitdir backlink changed during remove recovery");
    }
    Ok(())
}

fn managed_repository_binding(repo: &Repository) -> Result<ManagedRepositoryBinding> {
    let common_dir = fs::canonicalize(repo.commondir()).with_context(|| {
        format!(
            "failed to resolve Git common directory {}",
            repo.commondir().display()
        )
    })?;
    let repository_workdir = repo
        .workdir()
        .context("managed worktrees require a non-bare repository")?;
    let repository_workdir = fs::canonicalize(repository_workdir).with_context(|| {
        format!(
            "failed to resolve repository workdir {}",
            repository_workdir.display()
        )
    })?;
    if common_dir.parent() != Some(repository_workdir.as_path()) || repo.path() != repo.commondir()
    {
        bail!(
            "managed worktree mutation currently requires invocation from the primary worktree with an embedded .git common directory; linked-worktree and --separate-git-dir mutation are refused"
        );
    }
    Ok(ManagedRepositoryBinding {
        common_dir_identity: identity_for_path(&common_dir)?,
        repository_workdir_identity: identity_for_path(&repository_workdir)?,
        common_dir,
        repository_workdir,
    })
}

fn capture_staged_worktree_metadata(
    repository: &ManagedRepositoryBinding,
    name: &str,
    branch: &str,
    staged_path: &Path,
) -> Result<StagedWorktreeMetadata> {
    let metadata_parent = repository.common_dir.join("worktrees");
    let metadata_root = SafeRoot::open_existing(&metadata_parent)?;
    let metadata_binding = metadata_root.bind_existing_managed_direct_child_directory(name)?;
    let metadata_dir = metadata_binding.path().to_path_buf();
    let worktree_git_file = staged_path.join(".git");
    let metadata_gitdir_file = metadata_dir.join("gitdir");
    let metadata_head_file = metadata_dir.join("HEAD");
    verify_gitdir_backlinks(
        &worktree_git_file,
        &metadata_dir,
        &metadata_gitdir_file,
        staged_path,
    )?;
    verify_metadata_branch(&metadata_head_file, branch)?;
    Ok(StagedWorktreeMetadata {
        metadata_dir_identity: metadata_binding.identity().clone(),
        worktree_git_file_identity: BoundedRegularReader::identity(&worktree_git_file)?,
        metadata_gitdir_file_identity: BoundedRegularReader::identity(&metadata_gitdir_file)?,
        metadata_head_file_identity: BoundedRegularReader::identity(&metadata_head_file)?,
        metadata_dir,
    })
}

fn verify_staged_worktree_metadata(
    expected: &StagedWorktreeMetadata,
    repository: &ManagedRepositoryBinding,
    branch: &str,
    current_worktree_path: &Path,
) -> Result<bool> {
    let metadata_root = SafeRoot::open_existing(repository.common_dir.join("worktrees"))?;
    let name = expected
        .metadata_dir
        .file_name()
        .context("staged metadata directory has no final component")?;
    let metadata_binding = metadata_root.bind_existing_managed_direct_child_directory(name)?;
    if expected.metadata_dir.parent() != Some(metadata_root.path())
        || metadata_binding.path() != expected.metadata_dir
        || metadata_binding.identity() != &expected.metadata_dir_identity
    {
        bail!("staged worktree metadata directory identity changed");
    }
    let worktree_git_file = current_worktree_path.join(".git");
    let metadata_gitdir_file = expected.metadata_dir.join("gitdir");
    let metadata_head_file = expected.metadata_dir.join("HEAD");
    if BoundedRegularReader::identity(&worktree_git_file)? != expected.worktree_git_file_identity
        || BoundedRegularReader::identity(&metadata_head_file)?
            != expected.metadata_head_file_identity
    {
        bail!("staged worktree metadata file identity changed");
    }
    verify_metadata_branch(&metadata_head_file, branch)?;
    Ok(BoundedRegularReader::identity(&metadata_gitdir_file)?
        == expected.metadata_gitdir_file_identity)
}

#[allow(clippy::too_many_arguments)]
fn capture_managed_worktree_binding(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    root: &SafeRoot,
    name: &str,
    branch: &str,
    branch_created_by_maco: bool,
    base_oid: Oid,
    created_branch_oid: Oid,
) -> Result<ManagedWorktreeBinding> {
    root.verify()?;
    let path = fs::canonicalize(root.path().join(name))
        .with_context(|| format!("failed to resolve created worktree path for '{name}'"))?;
    if path.parent() != Some(root.path()) || path.file_name() != Some(OsStr::new(name)) {
        bail!("created worktree path is not a direct child of its managed root");
    }
    let metadata_parent = repository.common_dir.join("worktrees");
    let metadata_root = SafeRoot::open_existing(&metadata_parent)?;
    let metadata_dir = fs::canonicalize(metadata_parent.join(name))
        .with_context(|| format!("failed to resolve created worktree metadata for '{name}'"))?;
    if metadata_dir.parent() != Some(metadata_root.path())
        || metadata_dir.file_name() != Some(OsStr::new(name))
    {
        bail!("created worktree metadata is not bound beneath the Git common directory");
    }

    let worktree_git_file = path.join(".git");
    let metadata_gitdir_file = metadata_dir.join("gitdir");
    let metadata_head_file = metadata_dir.join("HEAD");
    verify_gitdir_backlinks(
        &worktree_git_file,
        &metadata_dir,
        &metadata_gitdir_file,
        &path,
    )?;
    verify_metadata_branch(&metadata_head_file, branch)?;
    let observed_branch = repo
        .find_branch(branch, BranchType::Local)
        .with_context(|| format!("failed to find created branch '{branch}'"))?
        .get()
        .target()
        .with_context(|| format!("created branch '{branch}' has no direct target"))?;
    if observed_branch != created_branch_oid {
        bail!("created branch OID changed while recording worktree binding");
    }

    Ok(ManagedWorktreeBinding {
        name: name.to_string(),
        root: root.path().to_path_buf(),
        root_identity: root.identity().clone(),
        path_identity: identity_for_path(&path)?,
        path,
        metadata_dir_identity: identity_for_path(&metadata_dir)?,
        metadata_dir,
        worktree_git_file_identity: BoundedRegularReader::identity(&worktree_git_file)?,
        metadata_gitdir_file_identity: BoundedRegularReader::identity(&metadata_gitdir_file)?,
        metadata_head_file_identity: BoundedRegularReader::identity(&metadata_head_file)?,
        branch: branch.to_string(),
        branch_created_by_maco,
        base_oid: base_oid.to_string(),
        created_branch_oid: created_branch_oid.to_string(),
        created_at_unix_nanos: None,
        creation_lock_pending: true,
    })
}

fn verify_managed_worktree_binding(
    repo: &Repository,
    repository: &ManagedRepositoryBinding,
    binding: &ManagedWorktreeBinding,
    delete_branch: bool,
) -> Result<VerifiedManagedWorktree> {
    if managed_repository_binding(repo)? != *repository {
        bail!("repository identity changed since the managed worktree registry was opened");
    }
    let normalized_name = normalize_agent_id(&binding.name)?;
    if normalized_name != binding.name {
        bail!("managed worktree name is not canonical");
    }
    let root = SafeRoot::open_existing(&binding.root)?;
    if root.identity() != &binding.root_identity {
        bail!(
            "managed worktree root identity changed for '{}'",
            binding.name
        );
    }
    let path = fs::canonicalize(&binding.path)
        .with_context(|| format!("managed worktree path is missing for '{}'", binding.name))?;
    if path != binding.path
        || path.parent() != Some(root.path())
        || path.file_name() != Some(OsStr::new(&binding.name))
        || identity_for_path(&path)? != binding.path_identity
    {
        bail!(
            "managed worktree path binding changed for '{}'; --force cannot bypass this check",
            binding.name
        );
    }

    let metadata_parent = repository.common_dir.join("worktrees");
    let metadata_root = SafeRoot::open_existing(&metadata_parent)?;
    let metadata_dir = fs::canonicalize(&binding.metadata_dir).with_context(|| {
        format!(
            "managed worktree metadata is missing for '{}'",
            binding.name
        )
    })?;
    if metadata_dir != binding.metadata_dir
        || metadata_dir.parent() != Some(metadata_root.path())
        || metadata_dir.file_name() != Some(OsStr::new(&binding.name))
        || identity_for_path(&metadata_dir)? != binding.metadata_dir_identity
    {
        bail!(
            "managed worktree metadata binding changed for '{}'; --force cannot bypass this check",
            binding.name
        );
    }

    let worktree_git_file = path.join(".git");
    let metadata_gitdir_file = metadata_dir.join("gitdir");
    let metadata_head_file = metadata_dir.join("HEAD");
    if BoundedRegularReader::identity(&worktree_git_file)? != binding.worktree_git_file_identity
        || BoundedRegularReader::identity(&metadata_gitdir_file)?
            != binding.metadata_gitdir_file_identity
        || BoundedRegularReader::identity(&metadata_head_file)?
            != binding.metadata_head_file_identity
    {
        bail!(
            "managed worktree metadata file identity changed for '{}'; refusing removal",
            binding.name
        );
    }
    verify_gitdir_backlinks(
        &worktree_git_file,
        &metadata_dir,
        &metadata_gitdir_file,
        &path,
    )?;
    verify_metadata_branch(&metadata_head_file, &binding.branch)?;

    let branch_oid = repo
        .find_branch(&binding.branch, BranchType::Local)
        .with_context(|| format!("managed branch '{}' is missing", binding.branch))?
        .get()
        .target()
        .with_context(|| format!("managed branch '{}' has no direct target", binding.branch))?;
    let base_oid = Oid::from_str(&binding.base_oid).context("managed base OID is malformed")?;
    let created_oid =
        Oid::from_str(&binding.created_branch_oid).context("managed branch OID is malformed")?;
    if binding.branch_created_by_maco
        && created_oid != base_oid
        && !repo
            .graph_descendant_of(created_oid, base_oid)
            .context("failed to verify create-time branch ancestry")?
    {
        bail!("create-time branch OID is not derived from the recorded base OID");
    }
    if branch_oid != created_oid
        && !repo
            .graph_descendant_of(branch_oid, created_oid)
            .context("failed to verify current managed branch ancestry")?
    {
        bail!(
            "managed branch '{}' was rewritten outside its recorded ancestry; refusing removal",
            binding.branch
        );
    }
    if delete_branch && !binding.branch_created_by_maco {
        bail!(
            "refusing to delete branch '{}' because it predated this managed worktree",
            binding.branch
        );
    }

    Ok(VerifiedManagedWorktree { path, branch_oid })
}

fn verify_gitdir_backlinks(
    worktree_git_file: &Path,
    metadata_dir: &Path,
    metadata_gitdir_file: &Path,
    worktree_path: &Path,
) -> Result<()> {
    let worktree_target = read_git_metadata_path(worktree_git_file, true)?;
    let worktree_target = resolve_metadata_path(worktree_path, &worktree_target);
    let worktree_target = fs::canonicalize(&worktree_target).with_context(|| {
        format!(
            "failed to resolve worktree gitdir backlink {}",
            worktree_target.display()
        )
    })?;
    if worktree_target != metadata_dir {
        bail!("worktree .git file does not point to its recorded metadata directory");
    }

    let metadata_target = read_git_metadata_path(metadata_gitdir_file, false)?;
    let metadata_target = resolve_metadata_path(metadata_dir, &metadata_target);
    let metadata_target = fs::canonicalize(&metadata_target).with_context(|| {
        format!(
            "failed to resolve metadata gitdir backlink {}",
            metadata_target.display()
        )
    })?;
    if metadata_target != worktree_git_file {
        bail!("worktree metadata gitdir does not point back to the recorded .git file");
    }
    Ok(())
}

#[cfg(unix)]
fn read_git_metadata_path(path: &Path, worktree_git_file: bool) -> Result<PathBuf> {
    let mut bytes = BoundedRegularReader::read(path, MAX_WORKTREE_METADATA_BYTES)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if worktree_git_file {
        bytes = bytes
            .strip_prefix(b"gitdir: ")
            .context("worktree .git file has no canonical gitdir prefix")?
            .to_vec();
    }
    if bytes.is_empty() || bytes.iter().any(|byte| matches!(byte, 0 | b'\n' | b'\r')) {
        bail!("Git metadata path is empty or contains an unrepresentable byte");
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(not(unix))]
fn read_git_metadata_path(path: &Path, _worktree_git_file: bool) -> Result<PathBuf> {
    bail!(
        "lossless Git metadata path decoding is unsupported on this platform: {}",
        path.display()
    )
}

fn verify_metadata_branch(head_file: &Path, branch: &str) -> Result<()> {
    let head = BoundedRegularReader::read_utf8(head_file, MAX_WORKTREE_METADATA_BYTES)?;
    let expected = format!("ref: refs/heads/{branch}");
    if head.trim() != expected {
        bail!(
            "managed worktree HEAD binding mismatch: expected '{expected}', observed '{}'",
            head.trim()
        );
    }
    Ok(())
}

fn repository_info(repo: &Repository) -> Result<RepositoryInfo> {
    let path = repo
        .workdir()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| repo.path().to_path_buf());
    repo.find_reference("HEAD")
        .context("failed to inspect repository HEAD backlink")?
        .symbolic_target()
        .context("repository HEAD symbolic target is not valid UTF-8")?;
    let head = match repo.head() {
        Ok(head) => Some(
            head.shorthand()
                .map(ToOwned::to_owned)
                .context("repository HEAD shorthand is not valid UTF-8")?,
        ),
        Err(error) if error.code() == ErrorCode::UnbornBranch => None,
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
    if trimmed.len() > MAX_AGENT_ID_BYTES {
        bail!("agent id exceeds its {MAX_AGENT_ID_BYTES}-byte limit");
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
    if branch_name.len() > MAX_BRANCH_NAME_BYTES {
        bail!("branch name exceeds its {MAX_BRANCH_NAME_BYTES}-byte limit");
    }
    if !Branch::name_is_valid(branch_name).context("failed to validate branch name")? {
        bail!("branch name is not a valid Git branch: {branch_name}");
    }

    Ok(())
}

fn is_reserved_worktree_root_child(name: impl AsRef<OsStr>) -> bool {
    let name = name.as_ref();
    name.to_string_lossy().starts_with(".maco-")
        || crate::lane_build::is_lane_build_config_directory(name)
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

fn resolve_metadata_path(metadata_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        metadata_dir.join(path)
    }
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
) -> Result<(git2::Branch<'repo>, bool)> {
    match repo.find_branch(branch_name, BranchType::Local) {
        Ok(branch) => Ok((branch, false)),
        Err(error) if error.code() == ErrorCode::NotFound => repo
            .branch(branch_name, commit, false)
            .map(|branch| (branch, true))
            .with_context(|| format!("failed to create local branch '{branch_name}'")),
        Err(error) => Err(error).with_context(|| format!("failed to open branch '{branch_name}'")),
    }
}

fn ensure_branch_for_creation<'repo>(
    repo: &'repo Repository,
    branch_name: &str,
    commit: &git2::Commit<'repo>,
    creation_policy: WorktreeCreationPolicy,
) -> Result<(git2::Branch<'repo>, bool)> {
    match creation_policy {
        WorktreeCreationPolicy::Standard => ensure_branch(repo, branch_name, commit),
        WorktreeCreationPolicy::NeutralFresh { .. } => repo
            .branch(branch_name, commit, false)
            .map(|branch| (branch, true))
            .with_context(|| {
                format!("failed to create fresh neutral worktree branch '{branch_name}'")
            }),
    }
}

fn find_worktree(repo: &Repository, name: &str) -> Result<Option<git2::Worktree>> {
    match repo.find_worktree(name) {
        Ok(worktree) => Ok(Some(worktree)),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect worktree '{name}'")),
    }
}

#[cfg(not(test))]
fn ensure_clean_worktree(_path: &Path) -> Result<()> {
    bail!(
        "effectful worktree cleanliness decisions are unsupported without a capability-bound repository input"
    )
}

#[cfg(test)]
fn ensure_clean_worktree(path: &Path) -> Result<()> {
    if !bounded_worktree_is_clean(
        path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_STATUS_TIMEOUT,
    )? {
        bail!("worktree is dirty; rerun with --force to remove it anyway");
    }
    Ok(())
}

#[derive(Debug)]
enum GitAssociationMarker {
    Directory(DirectoryBindingGuard),
    File(Box<RegularFileBindingGuard>),
}

impl GitAssociationMarker {
    fn bind(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).with_context(|| {
            format!(
                "failed to inspect Git association marker {}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            bail!(
                "Git association marker must not be a symbolic link: {}",
                path.display()
            );
        }
        if metadata.is_dir() {
            return DirectoryBindingGuard::bind(path).map(Self::Directory);
        }
        if metadata.is_file() {
            return RegularFileBindingGuard::bind(path, MAX_WORKTREE_GIT_TEXT_FILE_BYTES)
                .map(|binding| Self::File(Box::new(binding)));
        }
        bail!(
            "Git association marker has an unsupported file type: {}",
            path.display()
        )
    }

    fn verify(&self) -> Result<()> {
        match self {
            Self::Directory(binding) => {
                if identity_for_path(binding.path())? != *binding.identity() {
                    bail!("Git directory association marker changed");
                }
                Ok(())
            }
            Self::File(binding) => binding.verify(),
        }
    }
}

/// Binds the complete repository pathname association, including the
/// worktree `.git` marker and an optional linked-worktree `commondir` file.
/// Reopening the repository must resolve to the exact held Git and common
/// directories before any security decision may be accepted.
#[derive(Debug)]
pub(crate) struct RepositoryBindingGuard {
    worktree: DirectoryBindingGuard,
    git_marker: GitAssociationMarker,
    git_dir: DirectoryBindingGuard,
    common_dir: DirectoryBindingGuard,
    objects_dir: DirectoryBindingGuard,
    commondir_marker: Option<RegularFileBindingGuard>,
}

impl RepositoryBindingGuard {
    pub(crate) fn bind(path: &Path) -> Result<Self> {
        let worktree =
            DirectoryBindingGuard::bind(path).context("failed to bind repository worktree")?;
        let git_marker = GitAssociationMarker::bind(&worktree.path().join(".git"))?;
        let repository = crate::git_repository::open(worktree.path()).with_context(|| {
            format!(
                "failed to open bound repository {}",
                worktree.path().display()
            )
        })?;
        let repository_worktree = repository
            .workdir()
            .context("repository binding requires a non-bare worktree")?;
        if identity_for_path(repository_worktree)? != *worktree.identity() {
            bail!("Git repository worktree does not match the bound worktree directory");
        }
        let git_dir = DirectoryBindingGuard::bind(repository.path())?;
        let common_dir = DirectoryBindingGuard::bind(repository.commondir())?;
        let objects_dir = DirectoryBindingGuard::bind(repository.commondir().join("objects"))?;
        let commondir_path = git_dir.path().join("commondir");
        let commondir_marker = match fs::symlink_metadata(&commondir_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Some(
                RegularFileBindingGuard::bind(&commondir_path, MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?,
            ),
            Ok(_) => bail!(
                "Git commondir association marker has an unsupported file type: {}",
                commondir_path.display()
            ),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect Git commondir marker {}",
                        commondir_path.display()
                    )
                })
            }
        };
        let binding = Self {
            worktree,
            git_marker,
            git_dir,
            common_dir,
            objects_dir,
            commondir_marker,
        };
        binding.verify()?;
        Ok(binding)
    }

    pub(crate) fn worktree(&self) -> &Path {
        self.worktree.path()
    }

    pub(crate) fn worktree_binding(&self) -> &DirectoryBindingGuard {
        &self.worktree
    }

    pub(crate) fn git_dir(&self) -> &Path {
        self.git_dir.path()
    }

    pub(crate) fn common_dir(&self) -> &Path {
        self.common_dir.path()
    }

    pub(crate) fn read_git_relative(&self, relative: &Path, max_bytes: u64) -> Result<Vec<u8>> {
        self.git_dir.read_relative(relative, max_bytes)
    }

    pub(crate) fn read_git_relative_optional(
        &self,
        relative: &Path,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        self.git_dir.read_relative_optional(relative, max_bytes)
    }

    pub(crate) fn read_common_relative_optional(
        &self,
        relative: &Path,
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>> {
        self.common_dir.read_relative_optional(relative, max_bytes)
    }

    pub(crate) fn verify(&self) -> Result<()> {
        self.worktree
            .verify()
            .context("repository worktree changed")?;
        self.git_marker
            .verify()
            .context("repository .git association changed")?;
        if identity_for_path(self.git_dir.path())? != *self.git_dir.identity()
            || identity_for_path(self.common_dir.path())? != *self.common_dir.identity()
            || identity_for_path(self.objects_dir.path())? != *self.objects_dir.identity()
        {
            bail!("repository Git directory association changed");
        }
        let commondir_path = self.git_dir.path().join("commondir");
        match &self.commondir_marker {
            Some(binding) => binding
                .verify()
                .context("repository commondir association changed")?,
            None => match fs::symlink_metadata(&commondir_path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Ok(_) => bail!("repository commondir association appeared during operation"),
                Err(error) => return Err(error).context("failed to recheck repository commondir"),
            },
        }
        let reopened = crate::git_repository::open(self.worktree.path())
            .context("failed to reopen bound repository association")?;
        let reopened_worktree = reopened
            .workdir()
            .context("reopened repository is unexpectedly bare")?;
        if identity_for_path(reopened_worktree)? != *self.worktree.identity()
            || identity_for_path(reopened.path())? != *self.git_dir.identity()
            || identity_for_path(reopened.commondir())? != *self.common_dir.identity()
            || identity_for_path(reopened.commondir().join("objects"))?
                != *self.objects_dir.identity()
        {
            bail!("repository pathname association resolved to different filesystem objects");
        }
        self.git_marker
            .verify()
            .context("repository .git association changed after reopen")?;
        if let Some(binding) = &self.commondir_marker {
            binding
                .verify()
                .context("repository commondir association changed after reopen")?;
        }
        Ok(())
    }

    pub(crate) fn verify_status_generation(&self) -> Result<()> {
        self.worktree.verify()?;
        self.git_dir.verify()?;
        self.common_dir.verify()?;
        self.objects_dir.verify()?;
        self.git_marker.verify()?;
        if let Some(binding) = &self.commondir_marker {
            binding.verify()?;
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl RepositoryCleanlinessCapability {
    fn capture(manager: &WorktreeManager) -> Result<Self> {
        let repository_handle = manager.open_repository()?;
        let repository = managed_repository_binding(&repository_handle)?;
        let capability = Self { repository };
        capability.require_clean_for_manager(manager)?;
        Ok(capability)
    }

    fn require_clean_for_manager(&self, manager: &WorktreeManager) -> Result<()> {
        let repository_handle = manager.open_repository()?;
        let repository = managed_repository_binding(&repository_handle)?;
        self.require_clean_for_repository(&repository)
    }

    fn require_clean_for_repository(&self, repository: &ManagedRepositoryBinding) -> Result<()> {
        if repository != &self.repository {
            bail!("repository cleanliness capability belongs to a different managed repository");
        }
        let binding = RepositoryBindingGuard::bind(&repository.repository_workdir)
            .context("failed to rebind managed repository cleanliness capability")?;
        self.verify_primary_association(repository, &binding)?;
        require_bound_repository_clean(&binding, "primary repository")?;
        self.verify_primary_association(repository, &binding)
    }

    fn require_clean_related_worktree(&self, path: &Path) -> Result<()> {
        let primary = RepositoryBindingGuard::bind(&self.repository.repository_workdir)
            .context("failed to rebind managed repository cleanliness capability")?;
        self.verify_primary_association(&self.repository, &primary)?;
        let worktree = RepositoryBindingGuard::bind(path)
            .context("failed to bind created managed worktree cleanliness")?;
        if worktree.common_dir.path() != self.repository.common_dir
            || worktree.common_dir.identity() != &self.repository.common_dir_identity
        {
            bail!(
                "created managed worktree does not belong to the repository cleanliness capability"
            );
        }
        require_bound_repository_clean(&worktree, "created managed worktree")?;
        primary.verify()?;
        self.verify_primary_association(&self.repository, &primary)
    }

    fn verify_primary_association(
        &self,
        repository: &ManagedRepositoryBinding,
        binding: &RepositoryBindingGuard,
    ) -> Result<()> {
        binding.verify()?;
        if binding.worktree.path() != repository.repository_workdir
            || binding.worktree.identity() != &repository.repository_workdir_identity
            || binding.git_dir.path() != repository.common_dir
            || binding.git_dir.identity() != &repository.common_dir_identity
            || binding.common_dir.path() != repository.common_dir
            || binding.common_dir.identity() != &repository.common_dir_identity
        {
            bail!("repository cleanliness capability binding no longer matches its repository");
        }
        Ok(())
    }
}

impl CreationCleanliness<'_> {
    fn require_clean_for_repository(&self, repository: &ManagedRepositoryBinding) -> Result<()> {
        match self {
            Self::Bound(cleanliness) => cleanliness.require_clean_for_repository(repository),
            Self::NonpublishableSimulation => Ok(()),
            #[cfg(test)]
            Self::TestOnly => Ok(()),
        }
    }

    fn require_clean_related_worktree(&self, path: &Path) -> Result<()> {
        match self {
            Self::Bound(cleanliness) => cleanliness.require_clean_related_worktree(path),
            Self::NonpublishableSimulation => Ok(()),
            #[cfg(test)]
            Self::TestOnly => Ok(()),
        }
    }
}

fn require_bound_repository_clean(binding: &RepositoryBindingGuard, label: &str) -> Result<()> {
    let dirty = bounded_repository_status_paths_bound(
        binding,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_GC_STATUS_TIMEOUT,
    )?;
    if !dirty.is_empty() {
        bail!("{label} is dirty; managed worktree creation requires clean repository state");
    }
    binding.verify()
}

#[cfg(test)]
fn bounded_worktree_is_clean(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<bool> {
    Ok(
        bounded_worktree_records(path, max_entries, max_output_bytes, timeout)?
            .status
            .is_empty(),
    )
}

/// Returns a fail-closed, output-bounded Git porcelain status snapshot.  Git
/// runs as a killable trusted subprocess instead of in an in-process libgit2
/// call whose wall-clock work cannot be interrupted. Inventory and repository
/// map scans use process-group ownership so they function without a delegated
/// user-systemd session. Live GC dirtiness prefers verified containment and
/// falls back to the same trusted path when a delegated user manager is
/// absent, so Fake completion-hook reaping can finish on GitHub runners.
pub(crate) fn bounded_repository_status_paths(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedStatusPathRecords> {
    let binding = RepositoryBindingGuard::bind(path)?;
    bounded_repository_status_paths_bound(&binding, max_entries, max_output_bytes, timeout)
}

fn bounded_repository_gc_status_paths(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedStatusPathRecords> {
    bounded_repository_gc_status_paths_with_isolation(
        path,
        max_entries,
        max_output_bytes,
        timeout,
        BoundedGitIsolation::Verified,
    )
}

fn bounded_repository_gc_status_paths_trusted(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedStatusPathRecords> {
    bounded_repository_gc_status_paths_with_isolation(
        path,
        max_entries,
        max_output_bytes,
        timeout,
        BoundedGitIsolation::Trusted,
    )
}

fn bounded_repository_gc_status_paths_with_isolation(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
    isolation: BoundedGitIsolation,
) -> Result<BoundedStatusPathRecords> {
    let binding = RepositoryBindingGuard::bind(path)?;
    binding.verify()?;
    let records = match isolation {
        BoundedGitIsolation::Verified => {
            bounded_worktree_records_with_ignored(path, max_entries, max_output_bytes, timeout)?
        }
        BoundedGitIsolation::Trusted => bounded_worktree_records_with_ignored_trusted(
            path,
            max_entries,
            max_output_bytes,
            timeout,
        )?,
    };
    let mut merged = parse_porcelain_v1_z(&records.status, max_entries)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let ignored = parse_nul_paths(&records.ignored, max_entries)?;
    for path in ignored {
        if is_bounded_status_runtime_path(&path) {
            continue;
        }
        merged.entry(path).or_insert([b'?', b'?']);
        if merged.len() > max_entries {
            bail!("bounded GC status exceeded its combined parsed entry limit");
        }
    }
    binding.verify()?;
    Ok(merged.into_iter().collect())
}

type BoundedStatusPathRecords = Vec<(PathBuf, [u8; 2])>;

pub(crate) fn bounded_repository_status_paths_bound(
    binding: &RepositoryBindingGuard,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedStatusPathRecords> {
    let (paths, _) = bounded_repository_status_paths_bound_with_process_wait(
        binding,
        max_entries,
        max_output_bytes,
        timeout,
    )?;
    Ok(paths)
}

pub(crate) fn bounded_repository_status_paths_bound_with_process_wait(
    binding: &RepositoryBindingGuard,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<(BoundedStatusPathRecords, Duration)> {
    binding.verify()?;
    let records =
        bounded_worktree_records(binding.worktree(), max_entries, max_output_bytes, timeout)?;
    binding.verify()?;
    Ok((
        parse_porcelain_v1_z(&records.status, max_entries)?,
        records.process_queue_wait,
    ))
}

pub(crate) fn bounded_repository_status_paths_bound_with_process_wait_trusted(
    binding: &RepositoryBindingGuard,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<(BoundedStatusPathRecords, Duration)> {
    binding.verify()?;
    let records = bounded_worktree_records_trusted(
        binding.worktree(),
        max_entries,
        max_output_bytes,
        timeout,
    )?;
    binding.verify()?;
    Ok((
        parse_porcelain_v1_z(&records.status, max_entries)?,
        records.process_queue_wait,
    ))
}

pub(crate) fn bounded_repository_visible_paths_bound_with_process_wait(
    binding: &RepositoryBindingGuard,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<(Vec<PathBuf>, Duration)> {
    binding.verify()?;
    let records = bounded_worktree_records_trusted(
        binding.worktree(),
        max_entries,
        max_output_bytes,
        timeout,
    )?;
    binding.verify()?;
    Ok((
        parse_nul_paths(&records.visible, max_entries)?,
        records.process_queue_wait,
    ))
}

struct BoundedWorktreeRecords {
    visible: Vec<u8>,
    status: Vec<u8>,
    ignored: Vec<u8>,
    process_queue_wait: Duration,
}
