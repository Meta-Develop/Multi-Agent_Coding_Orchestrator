use crate::safe_state::{
    identity_for_path, remove_direct_child_tree, replace_reserved_directory_from, stable_checksum,
    AtomicStateWriter, BoundedRegularReader, FileIdentity, KernelStateLock, SafeRoot,
    TreeLinkPolicy, DEFAULT_MAX_STATE_BYTES,
};
use anyhow::{bail, Context, Result};
use git2::{
    Branch, BranchType, ErrorCode, ObjectType, Oid, Repository, RepositoryInitOptions,
    StatusOptions, Transaction, WorktreeAddOptions, WorktreeLockStatus,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

const DEFAULT_BRANCH_PREFIX: &str = "maco";
const MANAGED_WORKTREE_REGISTRY_VERSION: u32 = 1;
const MAX_WORKTREE_METADATA_BYTES: u64 = 64 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedRepositoryBinding {
    common_dir: PathBuf,
    common_dir_identity: FileIdentity,
    repository_workdir: PathBuf,
    repository_workdir_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeBinding {
    name: String,
    root: PathBuf,
    root_identity: FileIdentity,
    path: PathBuf,
    path_identity: FileIdentity,
    metadata_dir: PathBuf,
    metadata_dir_identity: FileIdentity,
    worktree_git_file_identity: FileIdentity,
    metadata_gitdir_file_identity: FileIdentity,
    metadata_head_file_identity: FileIdentity,
    branch: String,
    branch_created_by_maco: bool,
    base_oid: String,
    created_branch_oid: String,
    #[serde(default, skip_serializing_if = "is_false")]
    creation_lock_pending: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeRegistry {
    version: u32,
    checksum: String,
    repository: ManagedRepositoryBinding,
    records: BTreeMap<String, ManagedWorktreeBinding>,
    operations: BTreeMap<String, ManagedWorktreeOperation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedWorktreeOperationKind {
    Create,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedWorktreeOperationPhase {
    CreateIntent,
    CreatePrepared,
    CreateStaged,
    CreateObserved,
    RemovePrepared,
    WorktreeDeleted,
    MetadataDeleted,
    BranchDeleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ManagedBranchOwnership {
    Unknown,
    Preexisting,
    CreatedByMaco,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedWorktreeOperation {
    kind: ManagedWorktreeOperationKind,
    phase: ManagedWorktreeOperationPhase,
    name: String,
    root: PathBuf,
    root_identity: FileIdentity,
    path: PathBuf,
    prepared_path_identity: Option<FileIdentity>,
    staging_root: Option<PathBuf>,
    staging_root_identity: Option<FileIdentity>,
    staging_path: Option<PathBuf>,
    staged_path_identity: Option<FileIdentity>,
    staged_metadata: Option<StagedWorktreeMetadata>,
    branch: String,
    base_oid: String,
    branch_preexisting_oid: Option<String>,
    branch_ownership: ManagedBranchOwnership,
    owned_branch_oid: Option<String>,
    binding: Option<ManagedWorktreeBinding>,
    delete_branch: bool,
    force: bool,
    expected_branch_oid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StagedWorktreeMetadata {
    metadata_dir: PathBuf,
    metadata_dir_identity: FileIdentity,
    worktree_git_file_identity: FileIdentity,
    metadata_gitdir_file_identity: FileIdentity,
    metadata_head_file_identity: FileIdentity,
}

struct ManagedWorktreeRegistryStore {
    state_root: SafeRoot,
    repository: ManagedRepositoryBinding,
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
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let _registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load()?;
        recover_pending_operations(&repo, &registry_store, &mut registry)?;
        let name = normalize_agent_id(&options.agent_id)?;
        let branch_name = options.branch.unwrap_or_else(|| default_branch_name(&name));
        validate_branch_name(&branch_name)?;
        if registry.records.contains_key(&name) {
            bail!("managed worktree '{name}' already has a registry binding");
        }
        let requested_root = options
            .worktree_root
            .unwrap_or_else(|| default_worktree_root(&repo));
        let requested_root = if requested_root.is_absolute() {
            requested_root
        } else {
            repo.workdir()
                .context("worktree creation requires a non-bare repository")?
                .join(requested_root)
        };
        let root = SafeRoot::open_or_create_managed(&requested_root)?;
        let worktree_path = root.direct_child(&name)?;

        if find_worktree(&repo, &name)?.is_some() {
            bail!("worktree '{name}' is already registered");
        }
        root.ensure_direct_child_absent(&name)?;

        let commit = resolve_base_commit(&repo, options.base.as_deref())?;
        let branch_preexisting_oid =
            local_branch_oid(&repo, &branch_name)?.map(|oid| oid.to_string());
        let branch_ownership = if branch_preexisting_oid.is_some() {
            ManagedBranchOwnership::Preexisting
        } else {
            ManagedBranchOwnership::Unknown
        };
        let staging_name = root.random_direct_child_name("maco-stage")?;
        let staging_root_path = root.direct_child(&staging_name)?;
        let staging_path = staging_root_path.join(&name);
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Create,
                phase: ManagedWorktreeOperationPhase::CreateIntent,
                name: name.clone(),
                root: root.path().to_path_buf(),
                root_identity: root.identity().clone(),
                path: worktree_path.clone(),
                prepared_path_identity: None,
                staging_root: Some(staging_root_path.clone()),
                staging_root_identity: None,
                staging_path: Some(staging_path.clone()),
                staged_path_identity: None,
                staged_metadata: None,
                branch: branch_name.clone(),
                base_oid: commit.id().to_string(),
                branch_preexisting_oid,
                branch_ownership,
                owned_branch_oid: None,
                binding: None,
                delete_branch: false,
                force: false,
                expected_branch_oid: None,
            },
        );
        registry_store.save(&mut registry)?;

        let reserved = match root.reserve_direct_child_directory(&name) {
            Ok(reserved) => reserved,
            Err(error) => {
                recover_pending_operations(&repo, &registry_store, &mut registry)?;
                return Err(error);
            }
        };
        let staging_reserved = match root.reserve_direct_child_directory(&staging_name) {
            Ok(reserved) => reserved,
            Err(error) => {
                remove_direct_child_tree(
                    &root,
                    &name,
                    Some(reserved.identity()),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
                recover_pending_operations(&repo, &registry_store, &mut registry)?;
                return Err(error);
            }
        };
        let staging_root = SafeRoot::open_existing(staging_reserved.path())?;
        if staging_root.path() != staging_root_path {
            bail!("reserved staging root path changed before create preparation");
        }
        staging_root.ensure_direct_child_absent(&name)?;
        let prepared_save = (|| -> Result<()> {
            let operation = registry
                .operations
                .get_mut(&name)
                .context("create intent disappeared before reservation was persisted")?;
            operation.phase = ManagedWorktreeOperationPhase::CreatePrepared;
            operation.prepared_path_identity = Some(reserved.identity().clone());
            operation.staging_root = Some(staging_root.path().to_path_buf());
            operation.staging_root_identity = Some(staging_root.identity().clone());
            operation.staging_path = Some(staging_path.clone());
            registry_store.save(&mut registry)
        })();
        if let Err(error) = prepared_save {
            remove_direct_child_tree(
                &root,
                staging_reserved
                    .path()
                    .file_name()
                    .context("staging reservation has no final name")?,
                Some(staging_reserved.identity()),
                TreeLinkPolicy::UnlinkLinks,
            )?;
            let cleanup = remove_direct_child_tree(
                &root,
                &name,
                Some(reserved.identity()),
                TreeLinkPolicy::UnlinkLinks,
            );
            cleanup.context("failed to clean reserved directory after registry save failure")?;
            return Err(error);
        }

        let create_result =
            (|| -> Result<()> {
                reserved.verify(&root)?;
                let (branch, created_by_maco) = ensure_branch(&repo, &branch_name, &commit)?;
                let branch_oid = branch.get().target().with_context(|| {
                    format!("local branch '{branch_name}' has no direct target")
                })?;
                let preexisting_oid = registry
                    .operations
                    .get(&name)
                    .and_then(|operation| operation.branch_preexisting_oid.as_deref())
                    .map(Oid::from_str)
                    .transpose()
                    .context("create operation has malformed pre-existing branch OID")?;
                match (created_by_maco, preexisting_oid) {
                    (true, None) if branch_oid == commit.id() => {}
                    (true, None) => {
                        bail!("newly created branch changed before ownership was persisted")
                    }
                    (true, Some(_)) => {
                        bail!("a pre-existing branch disappeared during worktree creation")
                    }
                    (false, Some(expected)) if branch_oid == expected => {}
                    (false, Some(_)) => {
                        bail!("pre-existing branch changed before worktree creation")
                    }
                    (false, None) => {
                        bail!("branch appeared concurrently before worktree creation")
                    }
                }
                let operation = registry.operations.get_mut(&name).context(
                    "create operation disappeared before branch ownership was persisted",
                )?;
                operation.branch_ownership = if created_by_maco {
                    ManagedBranchOwnership::CreatedByMaco
                } else {
                    ManagedBranchOwnership::Preexisting
                };
                operation.owned_branch_oid = created_by_maco.then(|| branch_oid.to_string());
                registry_store.save(&mut registry)?;
                let _branch_guard = lock_branch_reference(&repo, &branch_name)?;
                verify_local_branch_oid(&repo, &branch_name, branch_oid)?;
                let reference = branch.into_reference();
                let mut add_options = WorktreeAddOptions::new();
                add_options.reference(Some(&reference)).lock(true);
                repo.worktree(&name, &staging_path, Some(&add_options))
                    .with_context(|| {
                        format!(
                            "failed to create worktree '{name}' at {}",
                            staging_path.display()
                        )
                    })?;
                ensure_creation_worktree_locked(&repo, &name)?;
                reserved.verify(&root)?;
                staging_reserved.verify(&root)?;
                let staged = staging_root.bind_existing_managed_direct_child_directory(&name)?;
                verify_worktree_clean_at(&staging_path, &branch_name, branch_oid)?;
                let staged_metadata = capture_staged_worktree_metadata(
                    &registry_store.repository,
                    &name,
                    &branch_name,
                    &staging_path,
                )?;
                let operation = registry
                    .operations
                    .get_mut(&name)
                    .context("create operation disappeared before staged identity was persisted")?;
                operation.phase = ManagedWorktreeOperationPhase::CreateStaged;
                operation.staged_path_identity = Some(staged.identity().clone());
                operation.staged_metadata = Some(staged_metadata);
                registry_store.save(&mut registry)?;
                Ok(())
            })();
        let recovery_result = recover_pending_operations(&repo, &registry_store, &mut registry);
        if let Err(create_error) = create_result {
            recovery_result.with_context(|| {
                format!(
                    "worktree creation failed and its durable create operation could not be recovered: {create_error:#}"
                )
            })?;
            return Err(create_error);
        }
        recovery_result?;
        let binding = registry.records.get(&name).with_context(|| {
            format!("managed worktree '{name}' was not finalized after create recovery")
        })?;

        Ok(WorktreeRecord {
            name,
            path: binding.path.clone(),
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
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let _registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load()?;
        recover_pending_operations(&repo, &registry_store, &mut registry)?;
        let binding = registry.records.get(&name).cloned().with_context(|| {
            format!(
                "worktree '{name}' has no create-time managed binding; refusing filesystem or branch deletion even with --force"
            )
        })?;
        let verified = verify_managed_worktree_binding(
            &repo,
            &registry_store.repository,
            &binding,
            delete_branch,
        )?;

        if !force {
            ensure_clean_worktree(&verified.path)?;
        }
        registry.operations.insert(
            name.clone(),
            ManagedWorktreeOperation {
                kind: ManagedWorktreeOperationKind::Remove,
                phase: ManagedWorktreeOperationPhase::RemovePrepared,
                name: name.clone(),
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
                delete_branch,
                force,
                expected_branch_oid: Some(verified.branch_oid.to_string()),
            },
        );
        registry_store.save(&mut registry)?;
        recover_pending_operations(&repo, &registry_store, &mut registry)?;

        Ok(WorktreeRecord {
            name,
            path: binding.path,
            branch: binding.branch,
        })
    }

    pub fn list(&self) -> Result<Vec<WorktreeRecord>> {
        self.list_managed_verified()
    }

    /// Returns only worktrees with a durable MACO binding that still matches
    /// their repository, filesystem identities, Git metadata, and backlinks.
    /// Git-registered legacy worktrees are intentionally not adopted here.
    pub fn list_managed_verified(&self) -> Result<Vec<WorktreeRecord>> {
        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let _registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load()?;
        recover_pending_operations(&repo, &registry_store, &mut registry)?;
        let mut records = Vec::with_capacity(registry.records.len());
        for binding in registry.records.values() {
            records.push(verified_worktree_record(
                &repo,
                &registry_store.repository,
                binding,
            )?);
        }
        records.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(records)
    }

    /// Resolves one execution-facing worktree through the durable MACO
    /// registry. An unbound Git worktree is rejected instead of being adopted
    /// implicitly.
    pub fn get_managed_verified(&self, agent_id: &str) -> Result<WorktreeRecord> {
        let name = normalize_agent_id(agent_id)?;
        let repo = self.open_repository()?;
        let registry_store = ManagedWorktreeRegistryStore::open(&repo)?;
        let _registry_lock = registry_store.lock()?;
        let mut registry = registry_store.load()?;
        recover_pending_operations(&repo, &registry_store, &mut registry)?;
        let binding = registry.records.get(&name).with_context(|| {
            format!("worktree '{name}' has no verified MACO binding; explicit adoption is required")
        })?;
        verified_worktree_record(&repo, &registry_store.repository, binding)
    }

    fn open_repository(&self) -> Result<Repository> {
        Repository::open(&self.repo_path)
            .with_context(|| format!("failed to open repository {}", self.repo_path.display()))
    }
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
    if worktree.name() != Some(binding.name.as_str()) {
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
            state_root: SafeRoot::open_or_create(state_root)?,
            repository,
        })
    }

    fn lock(&self) -> Result<KernelStateLock> {
        KernelStateLock::acquire_direct(&self.state_root, "managed_worktrees.lock")
    }

    fn load(&self) -> Result<ManagedWorktreeRegistry> {
        if !self
            .state_root
            .direct_child_exists("managed_worktrees.json")?
        {
            return Ok(self.empty_registry());
        }
        let contents = BoundedRegularReader::read_direct(
            &self.state_root,
            "managed_worktrees.json",
            DEFAULT_MAX_STATE_BYTES,
        )?;
        let registry: ManagedWorktreeRegistry =
            serde_json::from_slice(&contents).with_context(|| {
                format!(
                    "failed to parse managed worktree registry {}",
                    self.state_root
                        .path()
                        .join("managed_worktrees.json")
                        .display()
                )
            })?;
        if registry.version != MANAGED_WORKTREE_REGISTRY_VERSION {
            bail!(
                "unsupported managed worktree registry version {} in {}",
                registry.version,
                self.state_root
                    .path()
                    .join("managed_worktrees.json")
                    .display()
            );
        }
        if registry.repository != self.repository {
            bail!(
                "managed worktree registry repository binding does not match the current repository"
            );
        }
        let expected_checksum = managed_registry_checksum(&registry)?;
        if registry.checksum != expected_checksum {
            bail!(
                "managed worktree registry checksum mismatch in {}; refusing destructive operations",
                self.state_root.path().join("managed_worktrees.json").display()
            );
        }
        Ok(registry)
    }

    fn save(&self, registry: &mut ManagedWorktreeRegistry) -> Result<()> {
        registry.version = MANAGED_WORKTREE_REGISTRY_VERSION;
        registry.repository = self.repository.clone();
        registry.checksum = managed_registry_checksum(registry)?;
        let mut contents = serde_json::to_vec_pretty(registry)
            .context("failed to serialize managed worktree registry")?;
        contents.push(b'\n');
        AtomicStateWriter::scavenge_direct_temps(&self.state_root, "managed_worktrees.json")?;
        AtomicStateWriter::write_direct(&self.state_root, "managed_worktrees.json", &contents)
            .with_context(|| {
                format!(
                    "failed to save managed worktree registry {}",
                    self.state_root
                        .path()
                        .join("managed_worktrees.json")
                        .display()
                )
            })
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

fn recover_pending_operations(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    registry: &mut ManagedWorktreeRegistry,
) -> Result<()> {
    let names = registry.operations.keys().cloned().collect::<Vec<_>>();
    for name in names {
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
                recover_create_operation(repo, store, registry, operation)?
            }
            ManagedWorktreeOperationKind::Remove => {
                recover_remove_operation(repo, store, registry, operation)?
            }
        }
    }
    reconcile_creation_locks(repo, store, registry)
}

fn recover_create_operation(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    registry: &mut ManagedWorktreeRegistry,
    mut operation: ManagedWorktreeOperation,
) -> Result<()> {
    if operation.phase == ManagedWorktreeOperationPhase::CreateIntent {
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
                let staging_name = staging_root_path
                    .file_name()
                    .context("create intent staging root has no final name")?;
                let staging = root.bind_existing_direct_child_directory(staging_name)?;
                if !staging.is_empty()? {
                    bail!(
                        "create intent '{}' found a non-empty unbound staging directory; preserving it",
                        operation.name
                    );
                }
                remove_direct_child_tree(
                    &root,
                    staging_name,
                    Some(staging.identity()),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
            }
        }
        if path_entry_exists(&operation.path)? {
            let reserved = root.bind_existing_direct_child_directory(&operation.name)?;
            if !reserved.is_empty()? {
                bail!(
                    "create intent '{}' found a non-empty unbound directory; preserving it",
                    operation.name
                );
            }
            remove_direct_child_tree(
                &root,
                &operation.name,
                Some(reserved.identity()),
                TreeLinkPolicy::UnlinkLinks,
            )?;
        }
        registry.operations.remove(&operation.name);
        store.save(registry)?;
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
                let staged =
                    staging_root.bind_existing_managed_direct_child_directory(&operation.name)?;
                if !staged.is_empty()? {
                    bail!(
                        "create operation '{}' left a non-empty unbound staging path; preserving it for manual recovery",
                        operation.name
                    );
                }
                remove_direct_child_tree(
                    &staging_root,
                    &operation.name,
                    Some(staged.identity()),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
            }
            if final_path_exists {
                let reserved = root.bind_existing_direct_child_directory(&operation.name)?;
                if reserved.identity() != prepared_identity || !reserved.is_empty()? {
                    bail!(
                        "create operation '{}' left a changed or non-empty unbound path; preserving it for manual recovery",
                        operation.name
                    );
                }
                remove_direct_child_tree(
                    &root,
                    &operation.name,
                    Some(prepared_identity),
                    TreeLinkPolicy::UnlinkLinks,
                )?;
            }
            remove_staging_root_if_empty(&root, &staging_root, &staging_root_identity)?;
            cleanup_create_branch_if_owned(repo, &operation)?;
            registry.operations.remove(&operation.name);
            store.save(registry)?;
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
        verify_worktree_clean_at(&staging_path, &operation.branch, expected_branch_oid)?;
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
        store.save(registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::CreateStaged {
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
        verify_worktree_clean_at(&operation.path, &operation.branch, expected_branch_oid)?;
        verify_local_branch_oid(repo, &operation.branch, expected_branch_oid)?;
        let base_oid =
            Oid::from_str(&operation.base_oid).context("create operation base OID is malformed")?;
        let binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
        operation.phase = ManagedWorktreeOperationPhase::CreateObserved;
        operation.binding = Some(binding);
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::CreateObserved {
        ensure_creation_worktree_locked(repo, &operation.name)?;
        let _branch_guard = lock_branch_reference(repo, &operation.branch)?;
        let expected_branch_oid = verify_create_branch_exact(repo, &operation)?;
        verify_worktree_clean_at(&operation.path, &operation.branch, expected_branch_oid)?;
        let root = SafeRoot::open_existing(&operation.root)?;
        if root.identity() != &operation.root_identity {
            bail!("create-observed root identity changed before finalization");
        }
        let base_oid =
            Oid::from_str(&operation.base_oid).context("create operation base OID is malformed")?;
        let observed_binding = capture_managed_worktree_binding(
            repo,
            &store.repository,
            &root,
            &operation.name,
            &operation.branch,
            operation.branch_ownership == ManagedBranchOwnership::CreatedByMaco,
            base_oid,
            expected_branch_oid,
        )?;
        let binding = operation.binding.clone().with_context(|| {
            format!(
                "create operation '{}' reached observed phase without a binding",
                operation.name
            )
        })?;
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
                remove_staging_root_if_empty(&root, &staging_root, staging_root_identity)?;
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
        store.save(registry)?;
        complete_creation_lock(repo, store, registry, &operation.name)?;
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
    remove_direct_child_tree(
        managed_root,
        name,
        Some(expected),
        TreeLinkPolicy::UnlinkLinks,
    )
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

fn verify_worktree_clean_at(path: &Path, branch: &str, expected: Oid) -> Result<()> {
    let worktree_repo = Repository::open(path)
        .with_context(|| format!("failed to open created worktree {}", path.display()))?;
    let expected_reference = format!("refs/heads/{branch}");
    let verify_head = || -> Result<()> {
        let head = worktree_repo
            .head()
            .context("failed to inspect created worktree HEAD")?;
        if !head.is_branch() || head.name() != Some(expected_reference.as_str()) {
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

    let mut index = worktree_repo
        .index()
        .context("failed to open created worktree index")?;
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

    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = worktree_repo
        .statuses(Some(&mut options))
        .context("failed to inspect created worktree status")?;
    if !statuses.is_empty() {
        bail!("created worktree is not clean at its persisted branch OID");
    }
    verify_head()
}

fn complete_creation_lock(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    registry: &mut ManagedWorktreeRegistry,
    name: &str,
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
    verify_worktree_clean_at(&verified.path, &binding.branch, expected)?;
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
    store.save(registry)
}

fn reconcile_creation_locks(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    registry: &mut ManagedWorktreeRegistry,
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
        complete_creation_lock(repo, store, registry, &name)?;
    }
    Ok(())
}

fn recover_remove_operation(
    repo: &Repository,
    store: &ManagedWorktreeRegistryStore,
    registry: &mut ManagedWorktreeRegistry,
    mut operation: ManagedWorktreeOperation,
) -> Result<()> {
    let binding = operation.binding.clone().with_context(|| {
        format!(
            "remove operation '{}' has no create-time binding",
            operation.name
        )
    })?;
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
        let path_exists = path_entry_exists(&binding.path)?;
        let metadata_exists = path_entry_exists(&binding.metadata_dir)?;
        verify_recovering_branch(
            repo,
            &binding,
            expected_branch_oid,
            operation.delete_branch,
            path_exists || metadata_exists,
        )?;
        if path_exists {
            if !metadata_exists {
                bail!(
                    "remove operation '{}' lost metadata while its worktree still exists",
                    operation.name
                );
            }
            let verified = verify_managed_worktree_binding(
                repo,
                &store.repository,
                &binding,
                operation.delete_branch,
            )?;
            if !operation.force {
                ensure_clean_worktree(&verified.path)?;
            }
            remove_bound_directory(&binding.root, &binding.path, &binding.path_identity)?;
        }
        operation.phase = ManagedWorktreeOperationPhase::WorktreeDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::WorktreeDeleted {
        if path_entry_exists(&binding.metadata_dir)? {
            verify_metadata_binding_after_worktree_removal(&store.repository, &binding)?;
            let metadata_root = store.repository.common_dir.join("worktrees");
            remove_bound_directory(
                &metadata_root,
                &binding.metadata_dir,
                &binding.metadata_dir_identity,
            )?;
        }
        operation.phase = ManagedWorktreeOperationPhase::MetadataDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(registry)?;
    }

    if operation.phase == ManagedWorktreeOperationPhase::MetadataDeleted {
        if operation.delete_branch {
            delete_bound_local_branch_if_present(
                repo,
                &binding,
                expected_branch_oid.context("remove operation lacks expected branch OID")?,
            )?;
        }
        operation.phase = ManagedWorktreeOperationPhase::BranchDeleted;
        registry
            .operations
            .insert(operation.name.clone(), operation.clone());
        store.save(registry)?;
    }

    if operation.phase != ManagedWorktreeOperationPhase::BranchDeleted {
        bail!(
            "remove operation '{}' has invalid phase {:?}",
            operation.name,
            operation.phase
        );
    }
    registry.records.remove(&operation.name);
    registry.operations.remove(&operation.name);
    store.save(registry)
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

fn cleanup_create_branch_if_owned(
    repo: &Repository,
    operation: &ManagedWorktreeOperation,
) -> Result<()> {
    if operation.branch_ownership != ManagedBranchOwnership::CreatedByMaco {
        return Ok(());
    }
    let Some(observed) = local_branch_oid(repo, &operation.branch)? else {
        return Ok(());
    };
    let expected = operation
        .owned_branch_oid
        .as_deref()
        .map(Oid::from_str)
        .transpose()
        .context("create operation owned branch OID is malformed")?
        .context("create operation marked branch-owned without an owned OID")?;
    if observed != expected {
        bail!(
            "newly-created branch '{}' changed after create failure; preserving it",
            operation.branch
        );
    }
    let mut branch = repo
        .find_branch(&operation.branch, BranchType::Local)
        .with_context(|| {
            format!(
                "failed to open create-operation branch '{}'",
                operation.branch
            )
        })?;
    branch.delete().with_context(|| {
        format!(
            "failed to clean up create-operation branch '{}'",
            operation.branch
        )
    })
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

fn remove_bound_directory(root_path: &Path, path: &Path, identity: &FileIdentity) -> Result<()> {
    let root = SafeRoot::open_existing(root_path)?;
    if path.parent() != Some(root.path()) {
        bail!("bound directory is not a direct child of its recorded root");
    }
    let name = path
        .file_name()
        .context("bound directory has no final component")?;
    remove_direct_child_tree(&root, name, Some(identity), TreeLinkPolicy::UnlinkLinks)
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
    let backlink = BoundedRegularReader::read_utf8(&gitdir, MAX_WORKTREE_METADATA_BYTES)?;
    let backlink = resolve_metadata_path(&binding.metadata_dir, Path::new(backlink.trim()));
    if backlink != binding.path.join(".git") {
        bail!("managed metadata gitdir backlink changed during remove recovery");
    }
    Ok(())
}

fn delete_bound_local_branch_if_present(
    repo: &Repository,
    binding: &ManagedWorktreeBinding,
    expected_oid: Oid,
) -> Result<()> {
    match local_branch_oid(repo, &binding.branch)? {
        Some(observed) if observed == expected_oid => {
            delete_bound_local_branch(repo, binding, expected_oid)
        }
        Some(_) => bail!(
            "managed branch '{}' changed before idempotent deletion",
            binding.branch
        ),
        None => Ok(()),
    }
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
    let worktree_git =
        BoundedRegularReader::read_utf8(worktree_git_file, MAX_WORKTREE_METADATA_BYTES)?;
    let worktree_target = worktree_git
        .trim()
        .strip_prefix("gitdir:")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("worktree .git file has no gitdir target")?;
    let worktree_target = resolve_metadata_path(worktree_path, Path::new(worktree_target));
    let worktree_target = fs::canonicalize(&worktree_target).with_context(|| {
        format!(
            "failed to resolve worktree gitdir backlink {}",
            worktree_target.display()
        )
    })?;
    if worktree_target != metadata_dir {
        bail!("worktree .git file does not point to its recorded metadata directory");
    }

    let metadata_gitdir =
        BoundedRegularReader::read_utf8(metadata_gitdir_file, MAX_WORKTREE_METADATA_BYTES)?;
    let metadata_target = metadata_gitdir.trim();
    if metadata_target.is_empty() {
        bail!("worktree metadata gitdir backlink is empty");
    }
    let metadata_target = resolve_metadata_path(metadata_dir, Path::new(metadata_target));
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

fn delete_bound_local_branch(
    repo: &Repository,
    binding: &ManagedWorktreeBinding,
    expected_oid: Oid,
) -> Result<()> {
    if !binding.branch_created_by_maco {
        bail!("refusing to delete a branch not created by this managed worktree");
    }
    let mut branch = repo
        .find_branch(&binding.branch, BranchType::Local)
        .with_context(|| format!("failed to open managed branch '{}'", binding.branch))?;
    let observed = branch
        .get()
        .target()
        .with_context(|| format!("managed branch '{}' has no direct target", binding.branch))?;
    if observed != expected_oid {
        bail!(
            "managed branch '{}' changed after removal preflight; refusing deletion",
            binding.branch
        );
    }
    branch
        .delete()
        .with_context(|| format!("failed to delete managed branch '{}'", binding.branch))
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
    fn recovers_durable_creation_lock_before_returning_managed_worktree() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create(WorktreeCreateOptions {
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
        let _lock = store.lock().expect("registry lock");
        let mut registry = store.load().expect("registry");
        registry
            .records
            .get_mut("agent-lock")
            .expect("binding")
            .creation_lock_pending = true;
        store.save(&mut registry).expect("save pending lock");

        recover_pending_operations(&repo, &store, &mut registry).expect("recover creation lock");

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
        let repo = Repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create(WorktreeCreateOptions {
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
    fn refuses_separate_git_directory_before_worktree_mutation() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
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
            .create(WorktreeCreateOptions {
                agent_id: "agent-separated".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect_err("separate git dir must fail closed");
        assert!(error.to_string().contains("--separate-git-dir"));
        assert!(!worktree_root.exists());
        let reopened = Repository::open(&repo_path).expect("reopen repo");
        assert!(reopened
            .find_branch("maco/agent-separated", BranchType::Local)
            .is_err());
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
    fn force_remove_refuses_missing_create_time_metadata_binding() {
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

    #[test]
    fn force_remove_refuses_forged_gitdir_backlink_and_preserves_victim() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
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
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
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
        let repo = Repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("topic/shared", &commit, false)
            .expect("pre-existing branch");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
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
    fn recovers_create_prepare_by_cleaning_only_unchanged_new_branch() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
        let reserved = root
            .reserve_direct_child_directory("agent-crash")
            .expect("reserve path");
        let staging = root
            .reserve_random_direct_child_directory("test-stage")
            .expect("staging root");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let _lock = store.lock().expect("lock");
        let mut registry = store.load().expect("registry");
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
            },
        );
        store.save(&mut registry).expect("save prepare");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("maco/agent-crash", &commit, false)
            .expect("create branch before crash");

        recover_pending_operations(&repo, &store, &mut registry).expect("recover create");
        assert!(registry.operations.is_empty());
        assert!(registry.records.is_empty());
        assert!(repo
            .find_branch("maco/agent-crash", BranchType::Local)
            .is_err());
    }

    #[test]
    fn recovers_create_intent_at_final_and_staging_mkdir_boundaries() {
        for with_staging in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            let repo_path = temp.path().join("repo");
            let worktree_root = temp.path().join("worktrees");
            WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
            let repo = Repository::open(&repo_path).expect("open repo");
            let oid = commit_readme(&repo).expect("initial commit");
            let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
            let name = "agent-intent".to_string();
            let staging_name = "stage-intent";
            let staging_root_path = root.path().join(staging_name);
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
            let _lock = store.lock().expect("lock");
            let mut registry = store.load().expect("registry");
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
                    force: false,
                    expected_branch_oid: None,
                },
            );
            store.save(&mut registry).expect("save intent");
            root.reserve_direct_child_directory(&name)
                .expect("simulate final mkdir");
            if with_staging {
                root.reserve_direct_child_directory(staging_name)
                    .expect("simulate staging mkdir");
            }

            recover_pending_operations(&repo, &store, &mut registry).expect("recover intent");
            assert!(!root.path().join(&name).exists());
            assert!(!staging_root_path.exists());
            assert!(registry.operations.is_empty());
        }
    }

    #[test]
    fn unknown_branch_ownership_is_preserved_during_intent_recovery() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        let oid = commit_readme(&repo).expect("initial commit");
        let root = SafeRoot::open_or_create_managed(&worktree_root).expect("root");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let _lock = store.lock().expect("lock");
        let mut registry = store.load().expect("registry");
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
            },
        );
        store.save(&mut registry).expect("save intent");
        let commit = repo.find_commit(oid).expect("commit");
        repo.branch("maco/agent-branch-race", &commit, false)
            .expect("external branch creation");

        let error = recover_pending_operations(&repo, &store, &mut registry)
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
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        manager
            .create(WorktreeCreateOptions {
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
        let _lock = store.lock().expect("registry lock");
        let mut registry = store.load().expect("registry");
        registry
            .records
            .get_mut("agent-advanced")
            .expect("binding")
            .creation_lock_pending = true;
        store.save(&mut registry).expect("save pending handoff");

        let advanced =
            commit_descendant(&repo, "README.md", "# Advanced\n").expect("descendant commit");
        repo.find_branch("maco/agent-advanced", BranchType::Local)
            .expect("managed branch")
            .into_reference()
            .set_target(advanced, "simulate concurrent update-ref")
            .expect("advance managed branch");

        let error = recover_pending_operations(&repo, &store, &mut registry)
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
        let repo = Repository::open(&repo_path).expect("open repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let _lock = store.lock().expect("lock");
        let old_root = store.state_root.path().with_file_name("state-old");
        fs::rename(store.state_root.path(), &old_root).expect("rename state root");
        fs::create_dir(store.state_root.path()).expect("replacement root");
        fs::set_permissions(store.state_root.path(), fs::Permissions::from_mode(0o700))
            .expect("replacement mode");

        let error = store.load().expect_err("replaced state root must fail");
        assert!(error.to_string().contains("replaced"));
    }

    #[test]
    fn recovers_remove_after_worktree_directory_was_already_deleted() {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = Repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = manager
            .create(WorktreeCreateOptions {
                agent_id: "agent-remove-crash".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            })
            .expect("create worktree");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let _lock = store.lock().expect("lock");
        let mut registry = store.load().expect("registry");
        let binding = registry
            .records
            .get("agent-remove-crash")
            .cloned()
            .expect("binding");
        let verified = verify_managed_worktree_binding(&repo, &store.repository, &binding, true)
            .expect("verify");
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
            },
        );
        store.save(&mut registry).expect("save remove prepare");
        remove_bound_directory(&binding.root, &binding.path, &binding.path_identity)
            .expect("simulate directory deletion before phase save");

        recover_pending_operations(&repo, &store, &mut registry).expect("recover remove");
        assert!(!created.path.exists());
        assert!(!binding.metadata_dir.exists());
        assert!(repo
            .find_branch("maco/agent-remove-crash", BranchType::Local)
            .is_err());
        assert!(registry.records.is_empty());
        assert!(registry.operations.is_empty());
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
}
