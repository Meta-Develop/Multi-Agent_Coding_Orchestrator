fn collect_candidate_snapshot_entries(
    index: &TemporaryIndex,
    snapshot_tree: Oid,
    changes: &[ChangedPath],
) -> Result<BTreeMap<PathBuf, CandidateSnapshotEntry>> {
    let snapshot_repo = crate::git_repository::open_bare(&index.directory)
        .context("failed to open private candidate snapshot object database")?;
    let tree = snapshot_repo
        .find_tree(snapshot_tree)
        .context("failed to read private candidate snapshot tree")?;
    let mut entries = BTreeMap::new();
    for change in changes {
        let entry = match tree.get_path(&change.path) {
            Ok(entry) => entry,
            Err(error) if error.code() == ErrorCode::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect candidate snapshot path '{}'",
                        change.path.display()
                    )
                })
            }
        };
        let snapshot_entry = if entry.kind() == Some(ObjectType::Blob)
            && matches!(entry.filemode(), 0o100644 | 0o100755)
        {
            let blob = snapshot_repo.find_blob(entry.id()).with_context(|| {
                format!(
                    "failed to read candidate snapshot blob '{}'",
                    change.path.display()
                )
            })?;
            CandidateSnapshotEntry::RegularFile { bytes: blob.size() }
        } else {
            CandidateSnapshotEntry::Other {
                filemode: entry.filemode(),
            }
        };
        entries.insert(change.path.clone(), snapshot_entry);
    }
    Ok(entries)
}

fn temporary_base_tree_oid(
    repo: &Repository,
    worktree_path: &Path,
    base_commit: Option<Oid>,
    index: &TemporaryIndex,
) -> Result<Oid> {
    if let Some(commit) = base_commit {
        let tree_id = repo
            .find_commit(commit)
            .with_context(|| format!("failed to find base commit {commit}"))?
            .tree_id();
        return Ok(tree_id);
    }

    let output = run_isolated_git_process(
        index,
        worktree_path,
        &["mktree"],
        StdinMode::Null,
        "create empty base tree",
    )?;
    if !output.success {
        bail!(
            "failed to create empty base tree: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let oid = String::from_utf8(output.stdout).context("empty tree id was not UTF-8")?;
    Oid::from_str(oid.trim()).context("empty tree id was invalid")
}

fn collect_snapshot_changes(
    worktree_path: &Path,
    base_tree: Oid,
    snapshot_tree: Oid,
    index: &TemporaryIndex,
) -> Result<Vec<ChangedPath>> {
    let base = base_tree.to_string();
    let snapshot = snapshot_tree.to_string();
    let output = run_isolated_git_process(
        index,
        worktree_path,
        &[
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            &base,
            &snapshot,
            "--",
        ],
        StdinMode::Null,
        "collect candidate snapshot paths",
    )?;
    if !output.success {
        bail!(
            "failed to collect candidate snapshot paths: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_name_status_z(&output.stdout)
}

fn parse_name_status_z(bytes: &[u8]) -> Result<Vec<ChangedPath>> {
    let mut fields = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty());
    let mut changes = BTreeMap::new();
    while let Some(status) = fields.next() {
        let path = fields
            .next()
            .context("git diff --name-status returned a status without a path")?;
        let kind = match status.first().copied() {
            Some(b'A') => ChangeKind::Added,
            Some(b'M') => ChangeKind::Modified,
            Some(b'D') => ChangeKind::Deleted,
            Some(b'T') => ChangeKind::Typechange,
            Some(b'U') => ChangeKind::Conflicted,
            Some(_) => ChangeKind::Unknown,
            None => bail!("git diff --name-status returned an empty status"),
        };
        changes.insert(path_buf_from_git_bytes(path)?, kind);
    }
    Ok(changes
        .into_iter()
        .map(|(path, kind)| ChangedPath { path, kind })
        .collect())
}

fn collect_snapshot_diff(
    worktree_path: &Path,
    base_tree: Oid,
    snapshot_tree: Oid,
    index: &TemporaryIndex,
) -> Result<Vec<u8>> {
    let base = base_tree.to_string();
    let snapshot = snapshot_tree.to_string();
    let output = run_isolated_git_process(
        index,
        worktree_path,
        &[
            "diff",
            "--binary",
            "--full-index",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            &base,
            &snapshot,
            "--",
        ],
        StdinMode::Null,
        "collect candidate snapshot diff",
    )?;
    if !output.success {
        bail!(
            "failed to collect candidate snapshot diff: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

impl TemporaryIndex {
    fn create(common_dir: &Path) -> Result<Self> {
        let runtime_directory =
            PrivateRuntimeDirectory::create(common_dir, PrivateRuntimeKind::CandidateCapture)?;
        let directory = runtime_directory.path().to_path_buf();
        Self::initialize_existing(&directory, common_dir, Some(runtime_directory))
            .map_err(anyhow::Error::from)
            .context("failed to initialize candidate capture directory")
    }

    fn create_in_managed(
        runtime_directory: &PrivateRuntimeDirectory,
        common_dir: &Path,
    ) -> std::io::Result<Self> {
        let directory = runtime_directory.path().join(".git");
        Self::initialize_existing(&directory, common_dir, None)
    }

    fn initialize_existing(
        directory: &Path,
        common_dir: &Path,
        runtime_directory: Option<PrivateRuntimeDirectory>,
    ) -> std::io::Result<Self> {
        let alternate_object_directory = fs::canonicalize(common_dir.join("objects"))?;
        let result = (|| -> Result<()> {
            let object_directory = directory.join("objects");
            let refs_heads = directory.join("refs/heads");
            let refs_tags = directory.join("refs/tags");
            create_private_directory(&object_directory)?;
            create_private_directory(&directory.join("refs"))?;
            create_private_directory(&refs_heads)?;
            create_private_directory(&refs_tags)?;
            write_git_alternates_file(&object_directory, &alternate_object_directory)?;
            write_private_file(&directory.join("HEAD"), b"ref: refs/heads/maco-isolated\n")?;
            let hooks = directory.join("disabled-hooks");
            create_private_directory(&hooks)?;
            let config_path = directory.join("config");
            write_private_file(&config_path, b"")?;
            let mut config =
                git2::Config::open(&config_path).context("failed to open isolated Git config")?;
            config
                .set_i32("core.repositoryformatversion", 0)
                .context("failed to set isolated repository version")?;
            config
                .set_bool("core.bare", false)
                .context("failed to set isolated repository worktree mode")?;
            config
                .set_bool("core.logallrefupdates", false)
                .context("failed to disable isolated reflogs")?;
            config
                .set_bool("core.fsmonitor", false)
                .context("failed to disable isolated fsmonitor")?;
            config
                .set_bool("core.untrackedcache", false)
                .context("failed to disable isolated untracked cache")?;
            config
                .set_str(
                    "core.hookspath",
                    hooks
                        .to_str()
                        .context("isolated hooks path was not UTF-8")?,
                )
                .context("failed to disable isolated hooks")?;
            config
                .set_str("protocol.ext.allow", "never")
                .context("failed to disable external Git transports")?;
            drop(config);
            Ok(())
        })();
        match result {
            Ok(()) => Ok(Self {
                directory: directory.to_path_buf(),
                alternate_object_directory,
                _runtime_directory: runtime_directory,
            }),
            Err(error) => Err(std::io::Error::other(error.to_string())),
        }
    }

    fn command_args(&self, worktree_path: &Path, operation: &[&str]) -> Vec<OsString> {
        self.command_args_os(
            worktree_path,
            operation.iter().map(OsString::from).collect(),
        )
    }

    fn command_args_os(&self, worktree_path: &Path, operation: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--git-dir"),
            self.directory.as_os_str().to_os_string(),
            OsString::from("--work-tree"),
            worktree_path.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from("core.fsmonitor=false"),
            OsString::from("-c"),
            OsString::from("core.untrackedCache=false"),
            OsString::from("-c"),
            OsString::from("protocol.ext.allow=never"),
        ];
        args.extend(operation);
        args
    }

    fn set_detached_head(&self, oid: Oid) -> Result<()> {
        fs::write(self.directory.join("HEAD"), format!("{oid}\n"))
            .context("failed to set isolated detached HEAD")
    }
}

impl PrivateRuntimeDirectory {
    pub(crate) fn create(repo_root: &Path, kind: PrivateRuntimeKind) -> Result<Self> {
        let runtime_root = trusted_runtime_root(repo_root)?;
        Self::create_in_root(&runtime_root, kind)
    }

    #[cfg(unix)]
    fn create_in_root(runtime_root: &Path, kind: PrivateRuntimeKind) -> Result<Self> {
        validate_private_runtime_root(runtime_root)?;
        let _runtime_lock = PrivateRuntimeRootLock::acquire(runtime_root)?;
        let current_boot_id = private_runtime_boot_id()?;
        scavenge_private_runtime_orphans_locked_with(
            runtime_root,
            current_boot_id.as_deref(),
            process_start_identity,
        )?;
        let pid = std::process::id();
        let process_start = private_runtime_current_process_start_identity()?;
        let boot_id = current_boot_id;
        let created_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch while reserving private runtime")?
            .as_secs();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch while naming private runtime")?
            .as_nanos();
        for attempt in 0..32_u32 {
            let nonce = format!("{nanos}-{attempt}");
            let path = runtime_root.join(format!("{}{pid}-{nonce}", kind.prefix()));
            match reserve_owner_only_directory(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to reserve private runtime {}", path.display())
                    })
                }
            }
            let owner = PrivateRuntimeOwner {
                version: PRIVATE_RUNTIME_OWNER_VERSION,
                pid,
                process_start: process_start.clone(),
                boot_id: boot_id.clone(),
                created_unix_seconds,
                kind,
                nonce,
            };
            let directory_metadata = validate_private_runtime_directory(&path)?;
            if let Err(error) = write_private_runtime_owner(&path, &owner) {
                let _ = remove_private_runtime_directory_by_identity(
                    runtime_root,
                    &path,
                    &directory_metadata,
                );
                return Err(error);
            }
            return Ok(Self {
                runtime_root: runtime_root.to_path_buf(),
                path,
                owner,
                directory_metadata,
                closed: false,
            });
        }
        bail!("failed to reserve a unique private runtime directory")
    }

    #[cfg(not(unix))]
    fn create_in_root(_runtime_root: &Path, _kind: PrivateRuntimeKind) -> Result<Self> {
        bail!(
            "safe handle-relative private runtime cleanup is unavailable on this platform; refusing temporary context creation"
        )
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn verify_identity(&self) -> Result<()> {
        if self.closed {
            bail!("managed private runtime was already closed");
        }
        let directory_metadata = validate_private_runtime_directory(&self.path)?;
        if !same_filesystem_identity(&self.directory_metadata, &directory_metadata) {
            bail!(
                "managed private runtime {} changed identity while in use",
                self.path.display()
            );
        }
        let (owner, _) = read_private_runtime_owner(&self.path, self.owner.kind)?;
        if owner != self.owner {
            bail!(
                "managed private runtime {} owner record changed while in use",
                self.path.display()
            );
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.verify_identity()?;
        let _runtime_lock = PrivateRuntimeRootLock::acquire(&self.runtime_root)?;
        remove_owned_private_runtime_directory(
            &self.runtime_root,
            &self.path,
            &self.owner,
            &self.directory_metadata,
        )?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for PrivateRuntimeDirectory {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        let Ok(_runtime_lock) = PrivateRuntimeRootLock::acquire(&self.runtime_root) else {
            return;
        };
        let _ = remove_owned_private_runtime_directory(
            &self.runtime_root,
            &self.path,
            &self.owner,
            &self.directory_metadata,
        );
    }
}

impl PrivateRuntimeRootLock {
    fn acquire(runtime_root: &Path) -> Result<Self> {
        validate_private_runtime_root(runtime_root)?;
        let path = runtime_root.join(PRIVATE_RUNTIME_LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("failed to open private runtime lock {}", path.display()))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(fs::TryLockError::WouldBlock) => {
                    bail!(
                        "timed out acquiring private runtime lock {}; refusing concurrent cleanup",
                        path.display()
                    );
                }
                Err(fs::TryLockError::Error(error)) => {
                    return Err(error).with_context(|| {
                        format!("failed to acquire private runtime lock {}", path.display())
                    });
                }
            }
        }
        let path_metadata = fs::symlink_metadata(&path).with_context(|| {
            format!("failed to inspect private runtime lock {}", path.display())
        })?;
        let file_metadata = file.metadata().with_context(|| {
            format!(
                "failed to inspect open private runtime lock {}",
                path.display()
            )
        })?;
        if path_metadata.file_type().is_symlink()
            || metadata_is_windows_reparse_point(&path_metadata)
            || !path_metadata.file_type().is_file()
            || !same_filesystem_identity(&path_metadata, &file_metadata)
        {
            bail!(
                "private runtime lock {} changed while it was opened",
                path.display()
            );
        }
        validate_private_runtime_owner_file_metadata(&path, &path_metadata, None)?;
        validate_private_runtime_owner_file_metadata(&path, &file_metadata, Some(&file))?;
        Ok(Self { file })
    }
}

impl Drop for PrivateRuntimeRootLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn reserve_owner_only_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn write_private_runtime_owner(directory: &Path, owner: &PrivateRuntimeOwner) -> Result<()> {
    let owner_path = owner.kind.owner_path(directory);
    let owner_parent = owner_path
        .parent()
        .context("private runtime owner path omitted parent")?;
    if owner.kind == PrivateRuntimeKind::CandidateValidation {
        create_private_directory(owner_parent)?;
    }
    let mut bytes =
        serde_json::to_vec(owner).context("failed to serialize private runtime owner")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > PRIVATE_RUNTIME_OWNER_MAX_BYTES {
        bail!("private runtime owner record exceeded its size limit");
    }
    let temporary = owner_parent.join(format!(".{PRIVATE_RUNTIME_OWNER_FILE}.{}.tmp", owner.nonce));
    write_private_file(&temporary, &bytes)?;
    fs::rename(&temporary, &owner_path).with_context(|| {
        format!(
            "failed to publish private runtime owner {}",
            owner_path.display()
        )
    })?;
    sync_managed_directory(owner_parent)?;
    if owner_parent != directory {
        sync_managed_directory(directory)?;
    }
    Ok(())
}

#[cfg(test)]
fn scavenge_private_runtime_orphans(runtime_root: &Path) -> Result<PrivateRuntimeScavengeReport> {
    let boot_id = private_runtime_boot_id()?;
    scavenge_private_runtime_orphans_with(runtime_root, boot_id.as_deref(), |pid| {
        process_start_identity(pid)
    })
}

#[cfg(test)]
fn scavenge_private_runtime_orphans_with(
    runtime_root: &Path,
    current_boot_id: Option<&str>,
    process_identity: impl FnMut(u32) -> Result<Option<ProcessStartIdentity>>,
) -> Result<PrivateRuntimeScavengeReport> {
    validate_private_runtime_root(runtime_root)?;
    let _runtime_lock = PrivateRuntimeRootLock::acquire(runtime_root)?;
    scavenge_private_runtime_orphans_locked_with(runtime_root, current_boot_id, process_identity)
}

fn scavenge_private_runtime_orphans_locked_with(
    runtime_root: &Path,
    current_boot_id: Option<&str>,
    mut process_identity: impl FnMut(u32) -> Result<Option<ProcessStartIdentity>>,
) -> Result<PrivateRuntimeScavengeReport> {
    let mut managed = Vec::new();
    for entry in fs::read_dir(runtime_root)
        .with_context(|| format!("failed to scan private runtime {}", runtime_root.display()))?
    {
        let entry = entry.context("failed to read private runtime entry")?;
        let Some(kind) = private_runtime_kind_for_name(&entry.file_name())? else {
            continue;
        };
        managed.push((entry.path(), kind));
        if managed.len() > PRIVATE_RUNTIME_SCAN_MAX_DIRECTORIES {
            bail!(
                "private runtime contains more than {} managed directories; refusing unbounded scavenging",
                PRIVATE_RUNTIME_SCAN_MAX_DIRECTORIES
            );
        }
    }
    managed.sort_by(|left, right| left.0.cmp(&right.0));

    let mut report = PrivateRuntimeScavengeReport {
        removed: 0,
        retained: 0,
    };
    for (path, expected_kind) in managed {
        let outcome = (|| -> Result<bool> {
            let directory_metadata = validate_private_runtime_directory(&path)?;
            let owner_path = expected_kind.owner_path(&path);
            match fs::symlink_metadata(&owner_path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    validate_incomplete_private_runtime_name(&path, expected_kind)?;
                    remove_private_runtime_directory_by_identity(
                        runtime_root,
                        &path,
                        &directory_metadata,
                    )?;
                    return Ok(true);
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect private runtime owner {}",
                            owner_path.display()
                        )
                    })
                }
            }
            let (owner, owner_metadata) = read_private_runtime_owner(&path, expected_kind)?;
            validate_private_runtime_owner(&path, &owner, expected_kind, current_boot_id)?;

            let owner_is_live = if private_runtime_owner_boot_matches(&owner, current_boot_id)? {
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    match process_identity(owner.pid).with_context(|| {
                        format!(
                            "failed to verify owner process {} for private runtime {}",
                            owner.pid,
                            path.display()
                        )
                    })? {
                        Some(identity) => owner.process_start.as_ref() == Some(&identity),
                        None => false,
                    }
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                {
                    if owner.pid == std::process::id() {
                        true
                    } else {
                        bail!(
                            "cannot safely reclaim private runtime {} without process start identity support",
                            path.display()
                        );
                    }
                }
            } else {
                false
            };
            if owner_is_live {
                return Ok(false);
            }

            let current_directory_metadata = validate_private_runtime_directory(&path)?;
            if !same_filesystem_identity(&directory_metadata, &current_directory_metadata) {
                bail!(
                    "private runtime directory {} changed while it was being reclaimed",
                    path.display()
                );
            }
            let (current_owner, current_owner_metadata) =
                read_private_runtime_owner(&path, expected_kind)?;
            if current_owner != owner
                || !same_filesystem_identity(&owner_metadata, &current_owner_metadata)
            {
                bail!(
                    "private runtime owner {} changed while it was being reclaimed",
                    expected_kind.owner_path(&path).display()
                );
            }
            remove_owned_private_runtime_directory(
                runtime_root,
                &path,
                &owner,
                &directory_metadata,
            )?;
            Ok(true)
        })();
        match outcome {
            Ok(true) => report.removed += 1,
            Ok(false) => {}
            Err(error) => {
                report.retained += 1;
                tracing::warn!(
                    kind = ?expected_kind,
                    error = %error,
                    "retained unsafe or unverifiable private runtime entry"
                );
            }
        }
    }
    if report.removed > 0 {
        sync_managed_directory(runtime_root)?;
    }
    if report.retained > 0 {
        tracing::warn!(
            removed = report.removed,
            retained = report.retained,
            "private runtime scavenger completed with retained entries"
        );
    }
    Ok(report)
}

fn validate_incomplete_private_runtime_name(path: &Path, kind: PrivateRuntimeKind) -> Result<()> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("incomplete private runtime name was not UTF-8")?;
    let remainder = name
        .strip_prefix(kind.prefix())
        .context("incomplete private runtime kind prefix changed")?;
    let (pid, nonce) = remainder
        .split_once('-')
        .context("incomplete private runtime name omitted owner identity")?;
    let pid = pid
        .parse::<u32>()
        .context("incomplete private runtime PID was invalid")?;
    let mut nonce_fields = nonce.split('-');
    let nanos = nonce_fields.next().unwrap_or_default();
    let attempt = nonce_fields.next().unwrap_or_default();
    if pid == 0
        || nanos.is_empty()
        || attempt.is_empty()
        || nonce_fields.next().is_some()
        || !nanos.bytes().all(|byte| byte.is_ascii_digit())
        || !attempt.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!(
            "incomplete private runtime {} has an invalid reservation name; refusing reclamation",
            path.display()
        );
    }
    Ok(())
}

fn private_runtime_kind_for_name(name: &OsStr) -> Result<Option<PrivateRuntimeKind>> {
    let kinds = [
        PrivateRuntimeKind::CandidateCapture,
        PrivateRuntimeKind::CandidateValidation,
        PrivateRuntimeKind::PublicationGit,
        PrivateRuntimeKind::GhConfig,
    ];
    let Some(name) = name.to_str() else {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            return Ok(kinds
                .iter()
                .copied()
                .find(|kind| name.as_bytes().starts_with(kind.prefix().as_bytes())));
        }
        #[cfg(not(unix))]
        return Ok(None);
    };
    Ok(kinds
        .into_iter()
        .find(|kind| name.starts_with(kind.prefix())))
}

fn validate_private_runtime_root(runtime_root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(runtime_root).with_context(|| {
        format!(
            "failed to inspect private runtime root {}",
            runtime_root.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "private runtime root {} is not a real directory",
            runtime_root.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "private runtime root {} is not owner-only",
                runtime_root.display()
            );
        }
    }
    Ok(())
}

fn validate_private_runtime_directory(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private runtime {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "managed private runtime {} is not a real directory; refusing reclamation",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "managed private runtime {} has a foreign owner or unsafe mode; refusing reclamation",
                path.display()
            );
        }
    }
    Ok(metadata)
}

fn read_private_runtime_owner(
    directory: &Path,
    kind: PrivateRuntimeKind,
) -> Result<(PrivateRuntimeOwner, fs::Metadata)> {
    let path = kind.owner_path(directory);
    let path_metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("private runtime owner {} is missing", path.display()))?;
    if path_metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&path_metadata)
        || !path_metadata.file_type().is_file()
    {
        bail!(
            "private runtime owner {} is not a regular file; refusing reclamation",
            path.display()
        );
    }
    validate_private_runtime_owner_file_metadata(&path, &path_metadata, None)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("failed to open private runtime owner {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect private runtime owner {}", path.display()))?;
    validate_private_runtime_owner_file_metadata(&path, &file_metadata, Some(&file))?;
    if !same_filesystem_identity(&path_metadata, &file_metadata) {
        bail!(
            "private runtime owner {} changed while it was opened",
            path.display()
        );
    }
    if file_metadata.len() == 0 || file_metadata.len() > PRIVATE_RUNTIME_OWNER_MAX_BYTES {
        bail!(
            "private runtime owner {} has an invalid size",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.take(PRIVATE_RUNTIME_OWNER_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read private runtime owner {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > PRIVATE_RUNTIME_OWNER_MAX_BYTES {
        bail!(
            "private runtime owner {} changed size while read",
            path.display()
        );
    }
    let owner = serde_json::from_slice(&bytes)
        .with_context(|| format!("private runtime owner {} is malformed", path.display()))?;
    Ok((owner, file_metadata))
}

fn validate_private_runtime_owner_file_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    opened_file: Option<&fs::File>,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!(
                "private runtime owner {} has a foreign owner, unsafe mode, or multiple links",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        let _ = metadata;
        let number_of_links = match opened_file {
            Some(file) => {
                crate::file_identity::windows_file_link_count(file).with_context(|| {
                    format!(
                        "failed to inspect open Windows link count for {}",
                        path.display()
                    )
                })?
            }
            None => windows_path_link_count(path)?,
        };
        if number_of_links != 1 {
            bail!(
                "private runtime owner {} has multiple links",
                path.display()
            );
        }
    }
    #[cfg(not(target_os = "windows"))]
    let _ = opened_file;
    Ok(())
}

fn validate_private_runtime_owner(
    directory: &Path,
    owner: &PrivateRuntimeOwner,
    expected_kind: PrivateRuntimeKind,
    current_boot_id: Option<&str>,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch while validating private runtime")?
        .as_secs();
    let expected_name = format!("{}{}-{}", owner.kind.prefix(), owner.pid, owner.nonce);
    if owner.version != PRIVATE_RUNTIME_OWNER_VERSION
        || owner.pid == 0
        || owner.kind != expected_kind
        || owner.nonce.is_empty()
        || owner.nonce.len() > 96
        || !owner
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
        || owner.created_unix_seconds == 0
        || owner.created_unix_seconds > now.saturating_add(300)
        || !valid_process_start_identity(owner.process_start.as_ref())
        || directory.file_name().and_then(OsStr::to_str) != Some(expected_name.as_str())
    {
        bail!(
            "private runtime owner for {} is invalid; refusing reclamation",
            directory.display()
        );
    }
    private_runtime_owner_boot_matches(owner, current_boot_id)?;
    Ok(())
}

fn private_runtime_owner_boot_matches(
    owner: &PrivateRuntimeOwner,
    current_boot_id: Option<&str>,
) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let recorded = owner
            .boot_id
            .as_deref()
            .context("Linux private runtime owner omitted boot identity")?;
        let current = current_boot_id.context("current Linux boot identity is unavailable")?;
        validate_linux_boot_id(recorded)?;
        validate_linux_boot_id(current)?;
        Ok(recorded == current)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if owner.boot_id.is_some() || current_boot_id.is_some() {
            bail!("private runtime owner contained an unsupported boot identity");
        }
        Ok(true)
    }
}

#[cfg(target_os = "linux")]
fn validate_linux_boot_id(value: &str) -> Result<()> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        bail!("Linux boot identity was invalid");
    }
    Ok(())
}

fn remove_owned_private_runtime_directory(
    runtime_root: &Path,
    path: &Path,
    expected_owner: &PrivateRuntimeOwner,
    expected_directory_metadata: &fs::Metadata,
) -> Result<()> {
    let expected_kind = expected_owner.kind;
    let current_directory_metadata = validate_private_runtime_directory(path)?;
    if !same_filesystem_identity(expected_directory_metadata, &current_directory_metadata) {
        bail!(
            "private runtime directory {} changed before cleanup",
            path.display()
        );
    }
    let (current_owner, _) = read_private_runtime_owner(path, expected_kind)?;
    if &current_owner != expected_owner {
        bail!(
            "private runtime owner {} changed before cleanup",
            expected_kind.owner_path(path).display()
        );
    }
    remove_private_runtime_directory_by_identity(runtime_root, path, expected_directory_metadata)
}

fn remove_private_runtime_directory_by_identity(
    runtime_root: &Path,
    path: &Path,
    expected_directory_metadata: &fs::Metadata,
) -> Result<()> {
    let parent = path
        .parent()
        .context("private runtime directory omitted parent")?;
    if parent != runtime_root {
        bail!(
            "private runtime {} is not a direct child of {}",
            path.display(),
            runtime_root.display()
        );
    }
    validate_private_runtime_root(runtime_root)?;
    #[cfg(unix)]
    {
        remove_private_runtime_directory_unix(runtime_root, path, expected_directory_metadata)?;
    }
    #[cfg(not(unix))]
    {
        let _ = expected_directory_metadata;
        bail!(
            "safe handle-relative private runtime cleanup is unavailable on this platform; preserving {}",
            path.display()
        );
    }
    sync_managed_directory(runtime_root)?;
    Ok(())
}

#[cfg(unix)]
fn remove_private_runtime_directory_unix(
    runtime_root: &Path,
    path: &Path,
    expected_directory_metadata: &fs::Metadata,
) -> Result<()> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    };

    let mut root_options = OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let root_file = root_options.open(runtime_root).with_context(|| {
        format!(
            "failed to open private runtime root {} for cleanup",
            runtime_root.display()
        )
    })?;
    let name = path
        .file_name()
        .context("private runtime directory omitted name")?;
    let name = std::ffi::CString::new(name.as_bytes())
        .context("private runtime directory name contained NUL")?;
    let raw = unsafe {
        libc::openat(
            root_file.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open private runtime {}", path.display()));
    }
    // SAFETY: openat returned a new owned descriptor on success.
    let directory = unsafe { fs::File::from_raw_fd(raw) };
    let opened_metadata = directory.metadata().with_context(|| {
        format!(
            "failed to inspect opened private runtime {}",
            path.display()
        )
    })?;
    if opened_metadata.dev() != expected_directory_metadata.dev()
        || opened_metadata.ino() != expected_directory_metadata.ino()
    {
        bail!(
            "private runtime directory {} changed while it was opened for cleanup",
            path.display()
        );
    }

    let mut validation_entries = 1_usize;
    validate_private_runtime_contents_unix(
        directory.as_raw_fd(),
        opened_metadata.dev() as libc::dev_t,
        &mut validation_entries,
        PRIVATE_RUNTIME_REMOVAL_MAX_ENTRIES,
        PRIVATE_RUNTIME_REMOVAL_MAX_DEPTH,
        0,
    )?;
    let mut entries = 1_usize;
    remove_private_runtime_contents_unix(
        directory.as_raw_fd(),
        opened_metadata.dev() as libc::dev_t,
        &mut entries,
        0,
    )?;

    let current = fstatat_unix(root_file.as_raw_fd(), &name)?;
    if current.st_dev != opened_metadata.dev() as libc::dev_t
        || current.st_ino != opened_metadata.ino() as libc::ino_t
        || (current.st_mode & libc::S_IFMT) != libc::S_IFDIR
    {
        bail!(
            "private runtime directory {} changed before final unlink",
            path.display()
        );
    }
    let result =
        unsafe { libc::unlinkat(root_file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to unlink private runtime {}", path.display()));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_runtime_contents_unix(
    directory_fd: i32,
    root_device: libc::dev_t,
    entries: &mut usize,
    max_entries: usize,
    max_depth: usize,
    depth: usize,
) -> Result<()> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };

    let remaining = max_entries.saturating_sub(*entries);
    let names = read_directory_names_unix(directory_fd, remaining)?;
    for name in names {
        *entries += 1;
        let name = std::ffi::CString::new(name.as_bytes())
            .context("private runtime entry name contained NUL")?;
        let before = fstatat_unix(directory_fd, &name)?;
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if before.st_uid != uid || before.st_dev != root_device {
            bail!("private runtime entry has a foreign owner or filesystem; refusing cleanup");
        }
        if (before.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            if depth >= max_depth {
                bail!("private runtime exceeded the {max_depth}-level cleanup depth limit");
            }
            let raw = unsafe {
                libc::openat(
                    directory_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to open private runtime child during bounded validation");
            }
            // SAFETY: openat returned a new owned descriptor on success.
            let child = unsafe { fs::File::from_raw_fd(raw) };
            let opened = fstat_unix(child.as_raw_fd())?;
            if opened.st_dev != root_device
                || opened.st_dev != before.st_dev
                || opened.st_ino != before.st_ino
            {
                bail!("private runtime child changed during bounded validation");
            }
            validate_private_runtime_contents_unix(
                child.as_raw_fd(),
                root_device,
                entries,
                max_entries,
                max_depth,
                depth + 1,
            )?;
            let current = fstatat_unix(directory_fd, &name)?;
            if current.st_dev != opened.st_dev || current.st_ino != opened.st_ino {
                bail!("private runtime child changed during bounded validation");
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn remove_private_runtime_contents_unix(
    directory_fd: i32,
    root_device: libc::dev_t,
    entries: &mut usize,
    depth: usize,
) -> Result<()> {
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };

    let remaining = PRIVATE_RUNTIME_REMOVAL_MAX_ENTRIES.saturating_sub(*entries);
    let names = read_directory_names_unix(directory_fd, remaining)?;
    for name in names {
        *entries += 1;
        let name = std::ffi::CString::new(name.as_bytes())
            .context("private runtime entry name contained NUL")?;
        let before = fstatat_unix(directory_fd, &name)?;
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if before.st_uid != uid || before.st_dev != root_device {
            bail!("private runtime entry has a foreign owner or filesystem; refusing cleanup");
        }
        if (before.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            if depth >= PRIVATE_RUNTIME_REMOVAL_MAX_DEPTH {
                bail!(
                    "private runtime exceeded the {}-level cleanup depth limit",
                    PRIVATE_RUNTIME_REMOVAL_MAX_DEPTH
                );
            }
            let raw = unsafe {
                libc::openat(
                    directory_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };
            if raw < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to open private runtime child directory");
            }
            // SAFETY: openat returned a new owned descriptor on success.
            let child = unsafe { fs::File::from_raw_fd(raw) };
            let opened = fstat_unix(child.as_raw_fd())?;
            if opened.st_dev != root_device
                || opened.st_dev != before.st_dev
                || opened.st_ino != before.st_ino
            {
                bail!("private runtime child changed while it was opened");
            }
            remove_private_runtime_contents_unix(
                child.as_raw_fd(),
                root_device,
                entries,
                depth + 1,
            )?;
            let current = fstatat_unix(directory_fd, &name)?;
            if current.st_dev != opened.st_dev
                || current.st_ino != opened.st_ino
                || (current.st_mode & libc::S_IFMT) != libc::S_IFDIR
            {
                bail!("private runtime child changed before directory unlink");
            }
            let result = unsafe { libc::unlinkat(directory_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to unlink private runtime child directory");
            }
        } else {
            let result = unsafe { libc::unlinkat(directory_fd, name.as_ptr(), 0) };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to unlink private runtime child entry");
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
struct UnixDirectoryStream(*mut libc::DIR);

#[cfg(unix)]
impl Drop for UnixDirectoryStream {
    fn drop(&mut self) {
        // SAFETY: fdopendir returned this stream and closedir consumes it once.
        let _ = unsafe { libc::closedir(self.0) };
    }
}

#[cfg(unix)]
fn read_directory_names_unix(directory_fd: i32, max_names: usize) -> Result<Vec<OsString>> {
    use std::os::unix::ffi::OsStringExt;

    let current = c".";
    // SAFETY: openat creates a new file description with an independent
    // directory-stream offset while remaining anchored to directory_fd.
    let duplicate = unsafe {
        libc::openat(
            directory_fd,
            current.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to reopen private runtime directory descriptor");
    }
    // SAFETY: fdopendir takes ownership of duplicate on success.
    let raw_stream = unsafe { libc::fdopendir(duplicate) };
    if raw_stream.is_null() {
        let error = std::io::Error::last_os_error();
        // SAFETY: fdopendir did not take ownership on failure.
        let _ = unsafe { libc::close(duplicate) };
        return Err(error).context("failed to open private runtime directory stream");
    }
    let stream = UnixDirectoryStream(raw_stream);
    let mut names = Vec::new();
    loop {
        set_unix_errno(0);
        // SAFETY: stream remains valid for the duration of this loop.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let errno = get_unix_errno();
            if errno != 0 {
                return Err(std::io::Error::from_raw_os_error(errno))
                    .context("failed to enumerate private runtime directory");
            }
            break;
        }
        // SAFETY: readdir returns a dirent whose d_name is NUL-terminated.
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if names.len() >= max_names {
            bail!("private runtime exceeded the bounded directory-entry limit");
        }
        names.push(OsString::from_vec(name.to_vec()));
    }
    names.sort();
    Ok(names)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_unix_errno(value: i32) {
    // SAFETY: errno is thread-local writable process state.
    unsafe { *libc::__errno_location() = value };
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_unix_errno() -> i32 {
    // SAFETY: errno is thread-local readable process state.
    unsafe { *libc::__errno_location() }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn set_unix_errno(value: i32) {
    // SAFETY: errno is thread-local writable process state.
    unsafe { *libc::__error() = value };
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn get_unix_errno() -> i32 {
    // SAFETY: errno is thread-local readable process state.
    unsafe { *libc::__error() }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn set_unix_errno(_value: i32) {}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn get_unix_errno() -> i32 {
    0
}

#[cfg(unix)]
fn fstatat_unix(directory_fd: i32, name: &std::ffi::CStr) -> Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            directory_fd,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect private runtime entry");
    }
    // SAFETY: fstatat initialized metadata when it returned success.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn fstat_unix(fd: i32) -> Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(fd, metadata.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect opened private runtime entry");
    }
    // SAFETY: fstat initialized metadata when it returned success.
    Ok(unsafe { metadata.assume_init() })
}

fn same_filesystem_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

fn private_runtime_current_process_start_identity() -> Result<Option<ProcessStartIdentity>> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        process_start_identity(std::process::id())?
            .context("current process identity disappeared while reserving private runtime")
            .map(Some)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(None)
    }
}

#[cfg(target_os = "linux")]
fn private_runtime_boot_id() -> Result<Option<String>> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("failed to read Linux boot identity")?;
    let value = value.trim().to_ascii_lowercase();
    validate_linux_boot_id(&value)?;
    Ok(Some(value))
}

#[cfg(not(target_os = "linux"))]
fn private_runtime_boot_id() -> Result<Option<String>> {
    Ok(None)
}

pub(crate) fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("failed to create private directory {}", path.display()))
}

pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create private file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write private file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to persist private file {}", path.display()))
}

pub(crate) fn write_git_alternates_file(object_directory: &Path, alternate: &Path) -> Result<()> {
    let alternate = fs::canonicalize(alternate).with_context(|| {
        format!(
            "failed to resolve Git object alternate {}",
            alternate.display()
        )
    })?;
    let info = object_directory.join("info");
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&info)
        .with_context(|| format!("failed to create Git object info dir {}", info.display()))?;
    let path = info.join("alternates");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("failed to create Git alternates file {}", path.display()))?;
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        alternate.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let bytes = alternate.to_string_lossy().as_bytes().to_vec();
    if bytes.iter().any(|byte| matches!(byte, b'\n' | b'\r' | 0)) {
        bail!("Git object alternate path contains an unsupported control byte");
    }
    file.write_all(&bytes)
        .context("failed to write Git object alternate")?;
    file.write_all(b"\n")
        .context("failed to terminate Git object alternate")?;
    file.sync_all()
        .context("failed to persist Git object alternate")
}

fn require_git_success(output: GitCommandOutput, label: &str) -> Result<()> {
    if !output.success {
        bail!(
            "failed to {label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn hash_optional_file(path: &Path) -> Result<Option<Oid>> {
    #[cfg(windows)]
    let path_snapshot = match crate::file_identity::open_windows_path_identity(path) {
        Ok(snapshot) => snapshot,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    };
    #[cfg(windows)]
    let path_metadata = &path_snapshot.metadata;
    #[cfg(not(windows))]
    let path_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    };
    validate_repository_index_metadata(path, &path_metadata, None)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened {}", path.display()))?;
    validate_repository_index_metadata(path, &file_metadata, Some(&file))?;
    #[cfg(windows)]
    let file_identity = crate::file_identity::windows_file_identity(&file)
        .with_context(|| format!("failed to inspect opened file identity {}", path.display()))?;
    #[cfg(windows)]
    let identity_matches = path_snapshot.identity == file_identity;
    #[cfg(not(windows))]
    let identity_matches = same_filesystem_identity(&path_metadata, &file_metadata);
    if !identity_matches {
        bail!(
            "repository index {} changed while it was opened",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    #[cfg(windows)]
    (&file)
        .take(REPOSITORY_INDEX_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    #[cfg(not(windows))]
    file.take(REPOSITORY_INDEX_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() as u64 > REPOSITORY_INDEX_MAX_BYTES || bytes.len() as u64 != file_metadata.len()
    {
        bail!(
            "repository index {} changed size while read",
            path.display()
        );
    }
    #[cfg(windows)]
    let after_snapshot = crate::file_identity::open_windows_path_identity(path)
        .with_context(|| format!("failed to recheck {}", path.display()))?;
    #[cfg(windows)]
    let after = &after_snapshot.metadata;
    #[cfg(not(windows))]
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to recheck {}", path.display()))?;
    validate_repository_index_metadata(path, &after, None)?;
    #[cfg(windows)]
    let identity_matches = file_identity == after_snapshot.identity;
    #[cfg(not(windows))]
    let identity_matches = same_filesystem_identity(&file_metadata, &after);
    if !identity_matches || after.len() != file_metadata.len() {
        bail!(
            "repository index {} changed after it was read",
            path.display()
        );
    }
    Oid::hash_object(ObjectType::Blob, &bytes)
        .context("failed to hash repository state file")
        .map(Some)
}

fn validate_repository_index_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    opened_file: Option<&fs::File>,
) -> Result<()> {
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(metadata)
        || !metadata.file_type().is_file()
        || metadata.len() > REPOSITORY_INDEX_MAX_BYTES
    {
        bail!(
            "repository index {} is not a bounded real regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!(
                "repository index {} has a foreign owner, multiple links, or unsafe write mode",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        let number_of_links = match opened_file {
            Some(file) => {
                crate::file_identity::windows_file_link_count(file).with_context(|| {
                    format!(
                        "failed to inspect open Windows link count for {}",
                        path.display()
                    )
                })?
            }
            None => windows_path_link_count(path)?,
        };
        if number_of_links != 1 {
            bail!("repository index {} has multiple links", path.display());
        }
    }
    #[cfg(not(target_os = "windows"))]
    let _ = opened_file;
    Ok(())
}

fn passed_safety_check() -> SafetyCheck {
    SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    }
}

fn validation_evidence_check(
    evidence: &ValidationEvidenceBundle,
    expected: &CandidateValidationBinding,
    require_validation: bool,
    changed_paths: &[PathBuf],
) -> ValidationEvidenceCheck {
    if !require_validation {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Skipped,
            binding_status: ValidationBindingStatus::NotRequired,
            message: Some("candidate-bound validation evidence was not required".to_string()),
            paths: Vec::new(),
        };
    }

    let passing_groups = evidence
        .groups
        .iter()
        .filter(|group| {
            group
                .reports
                .iter()
                .any(|report| report.status == ValidationStatus::Passed)
        })
        .collect::<Vec<_>>();
    if passing_groups.is_empty() {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Skipped,
            binding_status: ValidationBindingStatus::NoPassedReport,
            message: Some("no passed validation report was available to bind".to_string()),
            paths: Vec::new(),
        };
    }
    if passing_groups
        .iter()
        .any(|group| group.binding.as_ref() == Some(expected))
    {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Passed,
            binding_status: ValidationBindingStatus::Bound,
            message: None,
            paths: Vec::new(),
        };
    }
    if passing_groups.iter().any(|group| group.binding.is_some()) {
        return ValidationEvidenceCheck {
            status: SafetyCheckStatus::Failed,
            binding_status: ValidationBindingStatus::Mismatched,
            message: Some(
                "passed validation evidence is bound to a different candidate; rerun validation for the current candidate.validation_binding"
                    .to_string(),
            ),
            paths: changed_paths.to_vec(),
        };
    }

    ValidationEvidenceCheck {
        status: SafetyCheckStatus::Failed,
        binding_status: ValidationBindingStatus::Unbound,
        message: Some(
            "passed validation evidence uses the legacy unbound format; include the current candidate.validation_binding in the validation report envelope"
                .to_string(),
        ),
        paths: changed_paths.to_vec(),
    }
}

fn dirty_primary_check(repo_root: &Path) -> Result<SafetyCheck> {
    let repo = crate::git_repository::open(repo_root)
        .with_context(|| format!("failed to open primary repository {}", repo_root.display()))?;
    let paths = collect_changed_paths(&repo)?
        .into_iter()
        .map(|change| change.path)
        .filter(|path| !is_local_runtime_path(path))
        .collect::<Vec<_>>();

    if paths.is_empty() {
        Ok(SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths,
        })
    } else {
        Ok(SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("primary worktree has local changes".to_string()),
            paths,
        })
    }
}

fn is_local_runtime_path(path: &Path) -> bool {
    crate::repo_map::is_runtime_control_path(path)
}

fn stale_base_check(metadata: &WorktreeMergeMetadata) -> SafetyCheck {
    match metadata.base_matches_primary {
        Some(true) => SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        },
        Some(false) => SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("agent base is stale relative to primary HEAD".to_string()),
            paths: Vec::new(),
        },
        None => SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("base freshness could not be determined".to_string()),
            paths: Vec::new(),
        },
    }
}

fn stale_base_check_for_current_head(
    metadata: &WorktreeMergeMetadata,
    current_head: Option<Oid>,
) -> SafetyCheck {
    let candidate_base = metadata
        .merge_base
        .as_deref()
        .or(metadata.primary_head.as_deref());
    let current_head = current_head.map(|oid| oid.to_string());
    match (candidate_base, current_head.as_deref()) {
        (Some(base), Some(current)) if base == current => passed_safety_check(),
        (None, None) => passed_safety_check(),
        (Some(_), Some(_)) => SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(
                "candidate base is stale relative to the current primary HEAD".to_string(),
            ),
            paths: Vec::new(),
        },
        _ => SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("base freshness could not be determined".to_string()),
            paths: Vec::new(),
        },
    }
}

fn primary_state_check(
    expected: &PrimaryRepositoryState,
    current: &PrimaryRepositoryState,
) -> SafetyCheck {
    if expected == current {
        return passed_safety_check();
    }
    let mut changed = Vec::new();
    if expected.head != current.head {
        changed.push("HEAD");
    }
    if expected.index_digest != current.index_digest {
        changed.push("index");
    }
    if expected.worktree_digest != current.worktree_digest {
        changed.push("worktree");
    }
    SafetyCheck {
        status: SafetyCheckStatus::Failed,
        message: Some(format!(
            "primary repository state changed after the merge safety preview ({})",
            changed.join(", ")
        )),
        paths: Vec::new(),
    }
}

fn refresh_apply_safety(
    preview: &mut MergeApplyPreview,
    expected_primary_state: &PrimaryRepositoryState,
) -> Result<()> {
    let repo_root = &preview.candidate.metadata.primary_repo_root;
    let current_primary_state = PrimaryRepositoryState::capture(repo_root)?;
    let dirty_primary = dirty_primary_check(repo_root)?;
    let stale_base =
        stale_base_check_for_current_head(&preview.candidate.metadata, current_primary_state.head);
    let unclaimed_edits = unclaimed_edits_check(&preview.candidate.unclaimed_changed_paths);
    let validation_required = preview.safety.validation_required;
    let validation = validation_check(&preview.candidate.validations, validation_required);
    let validation_evidence = validation_evidence_check(
        &preview.candidate.validation_evidence,
        &preview.candidate.validation_binding,
        validation_required,
        &preview.candidate.changed_paths,
    );
    let patch = preview.candidate.raw_diff.clone();
    let (apply_check, apply_mode) = apply_check(
        repo_root,
        &patch,
        preview.safety.force_options.allow_apply_conflicts,
    )?;
    let semantic_conflicts = classify_semantic_conflicts(&preview.candidate, &apply_check);
    let verified_primary_state = PrimaryRepositoryState::capture(repo_root)?;
    let primary_state_unchanged = if current_primary_state == verified_primary_state {
        primary_state_check(expected_primary_state, &verified_primary_state)
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(
                "primary repository state changed while apply-time safety checks were running"
                    .to_string(),
            ),
            paths: Vec::new(),
        }
    };
    let checks = SafetyChecks {
        primary_state_unchanged: &primary_state_unchanged,
        dirty_primary: &dirty_primary,
        stale_base: &stale_base,
        apply_check: &apply_check,
        unclaimed_edits: &unclaimed_edits,
        validation: &validation,
        validation_evidence: &validation_evidence,
        megafile: &preview.safety.megafile,
        validations: &preview.candidate.validations,
        require_validation: validation_required,
        validation_commands: &preview.safety.candidate_validation_commands,
        validation_related_paths: &preview.candidate.changed_paths,
    };
    let readiness = classify_apply_safety(checks, &preview.safety.force_options);

    preview.safety.primary_state_unchanged = primary_state_unchanged;
    preview.safety.dirty_primary = dirty_primary;
    preview.safety.stale_base = stale_base;
    preview.safety.apply_check = apply_check;
    preview.safety.unclaimed_edits = unclaimed_edits;
    preview.safety.validation = validation;
    preview.safety.validation_evidence = validation_evidence;
    preview.safety.apply_mode = apply_mode;
    preview.safety.semantic_conflicts = semantic_conflicts;
    preview.safety.readiness = readiness;
    Ok(())
}

fn unclaimed_edits_check(paths: &[PathBuf]) -> SafetyCheck {
    if paths.is_empty() {
        SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        }
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("agent changed paths outside its claims".to_string()),
            paths: paths.to_vec(),
        }
    }
}

fn validation_check(validations: &[ValidationReport], require_validation: bool) -> SafetyCheck {
    let failed = failed_validation_paths(validations);

    if !failed.is_empty() {
        return SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some("one or more validation checks failed".to_string()),
            paths: failed,
        };
    }
    if require_validation {
        if validations.is_empty() {
            return SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some("required validation evidence was not supplied".to_string()),
                paths: Vec::new(),
            };
        }
        if validations
            .iter()
            .all(|validation| validation.status != ValidationStatus::Passed)
        {
            let message = if validations
                .iter()
                .any(|validation| validation.status == ValidationStatus::NotRun)
            {
                "required validation evidence has not run"
            } else if validations
                .iter()
                .any(|validation| validation.status == ValidationStatus::Skipped)
            {
                "required validation evidence was skipped"
            } else {
                "required validation evidence has no passing checks"
            };
            return SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some(message.to_string()),
                paths: failed_validation_paths(validations),
            };
        }
    }
    if validations
        .iter()
        .any(|validation| validation.status == ValidationStatus::Passed)
    {
        SafetyCheck {
            status: SafetyCheckStatus::Passed,
            message: None,
            paths: Vec::new(),
        }
    } else {
        SafetyCheck {
            status: SafetyCheckStatus::Skipped,
            message: Some("no passing validation checks were supplied".to_string()),
            paths: Vec::new(),
        }
    }
}

fn failed_validation_paths(validations: &[ValidationReport]) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    let mut failed_without_paths = Vec::new();

    for validation in validations
        .iter()
        .filter(|validation| validation.status == ValidationStatus::Failed)
    {
        if validation.paths.is_empty() {
            failed_without_paths.push(PathBuf::from(&validation.name));
        } else {
            paths.extend(validation.paths.iter().cloned());
        }
    }

    if paths.is_empty() {
        failed_without_paths.sort();
        failed_without_paths.dedup();
        return failed_without_paths;
    }

    paths.into_iter().collect()
}

fn apply_check(
    repo_root: &Path,
    patch: &[u8],
    allow_apply_conflicts: bool,
) -> Result<(SafetyCheck, ApplyMode)> {
    if patch.is_empty() {
        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Skipped,
                message: Some("candidate has no diff to apply".to_string()),
                paths: Vec::new(),
            },
            ApplyMode::None,
        ));
    }

    let direct = run_git_with_input(repo_root, &["apply", "--check", "--binary"], patch)
        .context("failed to run git apply --check")?;
    let direct_stderr = git_stderr_text(&direct);
    let direct_paths = parse_git_apply_error_paths(&direct_stderr);
    if direct.success {
        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Passed,
                message: None,
                paths: Vec::new(),
            },
            ApplyMode::Direct,
        ));
    }

    if allow_apply_conflicts {
        let three_way = run_git_with_input(
            repo_root,
            &["apply", "--3way", "--check", "--binary"],
            patch,
        )
        .context("failed to run git apply --3way --check")?;
        let three_way_stderr = git_stderr_text(&three_way);
        let paths = merge_path_sets(
            &direct_paths,
            &parse_git_apply_error_paths(&three_way_stderr),
        );
        if three_way.success {
            return Ok((
                SafetyCheck {
                    status: SafetyCheckStatus::Passed,
                    message: Some(
                        "direct apply check failed; three-way apply check passed".to_string(),
                    ),
                    paths,
                },
                ApplyMode::ThreeWay,
            ));
        }

        return Ok((
            SafetyCheck {
                status: SafetyCheckStatus::Failed,
                message: Some(format!(
                    "direct check failed: {}; three-way check failed: {}",
                    direct_stderr.trim(),
                    three_way_stderr.trim()
                )),
                paths,
            },
            ApplyMode::None,
        ));
    }

    Ok((
        SafetyCheck {
            status: SafetyCheckStatus::Failed,
            message: Some(direct_stderr.trim().to_string()),
            paths: direct_paths,
        },
        ApplyMode::None,
    ))
}

fn run_candidate_validation_commands(
    preview: &MergeApplyPreview,
    commands: &[CandidateValidationCommand],
) -> Result<Vec<ValidationReport>> {
    let mut reports = Vec::new();
    for (index, command) in commands.iter().enumerate() {
        let sandbox = CandidateValidationSandbox::create(preview)?;
        let environment_root = sandbox.validation_environment_root();
        let redactor = validation_diagnostics_redactor(&environment_root);
        let report = run_candidate_validation_command(
            sandbox.path(),
            &environment_root,
            command,
            index,
            &preview.candidate.changed_paths,
        );
        let mut report = sandbox.enforce_candidate_integrity(preview, report);
        if let Some(message) = report.message.as_mut() {
            *message = redact_validation_diagnostic(&redactor, message);
        }
        reports.push(report);
    }
    Ok(reports)
}

struct CandidateValidationSandbox {
    runtime_directory: PrivateRuntimeDirectory,
    git_context: TemporaryIndex,
    baseline_integrity: Option<CandidateValidationSandboxIntegrity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateValidationSandboxIntegrity {
    binding: CandidateValidationBinding,
    repository: ValidationRepositoryFingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationRepositoryFingerprint {
    head: Option<Oid>,
    index_digest: Option<Oid>,
    status: Vec<u8>,
    snapshot_tree: Oid,
    submodules: Vec<ValidationSubmoduleFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationSubmoduleFingerprint {
    path: PathBuf,
    expected_gitlink: Oid,
    initialized: bool,
    filesystem: ValidationFilesystemFingerprint,
    repository: Option<Box<ValidationRepositoryFingerprint>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationFilesystemFingerprint {
    exists: bool,
    entries: Vec<ValidationFilesystemEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidationFilesystemEntry {
    path: PathBuf,
    kind: ValidationFilesystemEntryKind,
    mode: u32,
    content_digest: Option<Oid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationFilesystemEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Debug, thiserror::Error)]
enum ValidationFilesystemFingerprintError {
    #[error("validation submodule raw fingerprint exceeded the {limit}-entry limit at {path:?}")]
    EntryCountExceeded { path: PathBuf, limit: usize },
    #[error(
        "validation submodule raw fingerprint file {path:?} exceeded the {limit}-byte single-file limit"
    )]
    SingleFileTooLarge { path: PathBuf, limit: u64 },
    #[error(
        "validation submodule raw fingerprint exceeded the {limit}-byte total-content limit at {path:?}"
    )]
    TotalContentTooLarge { path: PathBuf, limit: u64 },
}

#[derive(Debug, thiserror::Error)]
enum CandidateCaptureQuotaError {
    #[error("candidate capture exceeded the {limit}-entry limit")]
    EntryCountExceeded { limit: usize },
    #[error("candidate file {path:?} exceeded the {limit}-byte single-file limit")]
    SingleFileTooLarge { path: PathBuf, limit: u64 },
    #[error("candidate capture exceeded the {limit}-byte total-content limit at {path:?}")]
    TotalContentTooLarge { path: PathBuf, limit: u64 },
}

struct ValidationFilesystemBudget {
    entries: usize,
    total_bytes: u64,
    max_entries: usize,
    max_total_bytes: u64,
    max_single_file_bytes: u64,
}

impl CandidateValidationSandbox {
    fn create(preview: &MergeApplyPreview) -> Result<Self> {
        let primary_repo_root = preview.candidate.metadata.primary_repo_root.clone();
        let runtime_directory = PrivateRuntimeDirectory::create(
            &primary_repo_root,
            PrivateRuntimeKind::CandidateValidation,
        )?;
        let primary_repo = crate::git_repository::open(&primary_repo_root).with_context(|| {
            format!(
                "failed to open primary repository {}",
                primary_repo_root.display()
            )
        })?;
        let base_oid = preview
            .candidate
            .metadata
            .primary_head
            .as_deref()
            .map(Oid::from_str)
            .transpose()
            .context("candidate validation base OID was invalid")?;
        let git_context =
            TemporaryIndex::create_in_managed(&runtime_directory, primary_repo.commondir())
                .map_err(anyhow::Error::from)
                .context("failed to create isolated candidate validation repository")?;
        let mut sandbox = Self {
            runtime_directory,
            git_context,
            baseline_integrity: None,
        };
        initialize_isolated_index(&sandbox.git_context, sandbox.path(), base_oid)?;
        if let Some(base_oid) = base_oid {
            sandbox.git_context.set_detached_head(base_oid)?;
        }
        let checkout = run_isolated_git_process_with_writable_worktree(
            &sandbox.git_context,
            sandbox.path(),
            &["checkout-index", "--all", "--force"],
            StdinMode::Null,
            "materialize candidate validation base",
        )?;
        require_git_success(checkout, "materialize candidate validation base")?;

        let patch = preview.candidate.raw_diff.as_slice();
        let args = match preview.safety.apply_mode {
            ApplyMode::Direct => vec!["apply", "--binary"],
            ApplyMode::ThreeWay => vec!["apply", "--3way", "--binary"],
            ApplyMode::None => Vec::new(),
        };
        if !args.is_empty() {
            let apply_output = run_isolated_git_process_with_writable_worktree(
                &sandbox.git_context,
                sandbox.path(),
                &args,
                StdinMode::Bytes(patch.to_vec()),
                "apply candidate patch to validation repository",
            )
            .context("failed to apply candidate patch to validation worktree")?;
            if !apply_output.success {
                bail!(
                    "failed to apply candidate patch to validation worktree: {}",
                    String::from_utf8_lossy(&apply_output.stderr).trim()
                );
            }
        }

        sandbox.baseline_integrity = Some(sandbox.current_integrity(preview)?);

        Ok(sandbox)
    }

    fn path(&self) -> &Path {
        self.runtime_directory.path()
    }

    fn validation_environment_root(&self) -> PathBuf {
        self.git_context.directory.join("validation-environment")
    }

    fn enforce_candidate_integrity(
        &self,
        preview: &MergeApplyPreview,
        mut report: ValidationReport,
    ) -> ValidationReport {
        let integrity = self.current_integrity(preview);
        match integrity {
            Ok(integrity) if Some(&integrity) == self.baseline_integrity.as_ref() => report,
            Ok(_) => {
                report.status = ValidationStatus::Failed;
                report.message = append_validation_message(
                    report.message,
                    "validation command mutated tracked or non-ignored candidate state; its result was rejected",
                );
                report.paths = merge_path_sets(&report.paths, &preview.candidate.changed_paths);
                report
            }
            Err(error) => {
                report.status = ValidationStatus::Failed;
                report.message = append_validation_message(
                    report.message,
                    &format!("failed to verify validation sandbox integrity: {error}"),
                );
                report.paths = merge_path_sets(&report.paths, &preview.candidate.changed_paths);
                report
            }
        }
    }

    fn current_integrity(
        &self,
        preview: &MergeApplyPreview,
    ) -> Result<CandidateValidationSandboxIntegrity> {
        let repo = crate::git_repository::open(self.path()).with_context(|| {
            format!(
                "failed to open validation sandbox {}",
                self.path().display()
            )
        })?;
        let base = collection_base_oid(&preview.candidate.metadata)?;
        capture_two_matching(|| {
            let head = head_oid(&repo).context("failed to read validation sandbox HEAD")?;
            let captured = snapshot_worktree_candidate_from_base_with_index(
                &repo,
                self.path(),
                head,
                base,
                &self.git_context,
            )?;
            let binding =
                candidate_validation_binding(&preview.candidate.metadata, &captured.raw_diff)?;
            let repository =
                validation_repository_fingerprint(&repo, self.path(), Some(captured.oid), 0)?;
            Ok(Some(CandidateValidationSandboxIntegrity {
                binding,
                repository,
            }))
        })
    }
}

fn validation_repository_fingerprint(
    repo: &Repository,
    worktree_path: &Path,
    known_snapshot_tree: Option<Oid>,
    depth: usize,
) -> Result<ValidationRepositoryFingerprint> {
    if depth > 32 {
        bail!("validation sandbox submodule nesting exceeded 32 levels");
    }
    let head = head_oid(repo).context("failed to read validation repository HEAD")?;
    let index_digest = hash_optional_file(&repo.path().join("index"))?;
    let status = capture_repository_status(repo)
        .context("failed to capture recursive validation repository status")?;
    let snapshot_tree = match known_snapshot_tree {
        Some(snapshot_tree) => snapshot_tree,
        None => snapshot_worktree_candidate(repo, worktree_path, head)?.oid,
    };

    let mut submodules = Vec::new();
    for (path, expected_gitlink) in validation_gitlinks(worktree_path)? {
        let submodule_path = worktree_path.join(&path);
        let marker = submodule_path.join(".git");
        let marker_present = match fs::symlink_metadata(&marker) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect submodule marker {}", marker.display())
                })
            }
        };
        if !marker_present {
            let filesystem = validation_filesystem_fingerprint(&submodule_path)?;
            submodules.push(ValidationSubmoduleFingerprint {
                path,
                expected_gitlink,
                initialized: false,
                filesystem,
                repository: None,
            });
            continue;
        }
        let filesystem = validation_submodule_marker_fingerprint(&marker)?;
        let submodule_repo = crate::git_repository::open(&submodule_path).with_context(|| {
            format!(
                "initialized validation submodule {} could not be opened",
                path_json_text(&path)
            )
        })?;
        let repository =
            validation_repository_fingerprint(&submodule_repo, &submodule_path, None, depth + 1)?;
        submodules.push(ValidationSubmoduleFingerprint {
            path,
            expected_gitlink,
            initialized: true,
            filesystem,
            repository: Some(Box::new(repository)),
        });
    }

    Ok(ValidationRepositoryFingerprint {
        head,
        index_digest,
        status,
        snapshot_tree,
        submodules,
    })
}

fn validation_gitlinks(worktree_path: &Path) -> Result<Vec<(PathBuf, Oid)>> {
    let repo = crate::git_repository::open(worktree_path).with_context(|| {
        format!(
            "failed to open validation repository {}",
            worktree_path.display()
        )
    })?;
    let index = repo
        .index()
        .context("failed to read validation repository index")?;
    let mut gitlinks = BTreeMap::new();
    for entry in index.iter() {
        if entry.mode != 0o160000 {
            continue;
        }
        let stage = (entry.flags >> 12) & 0x3;
        if stage != 0 {
            bail!(
                "validation repository contains a conflicted submodule gitlink; refusing incomplete integrity capture"
            );
        }
        let path = normalize_repo_relative_path(path_buf_from_git_bytes(&entry.path)?)?;
        if gitlinks.insert(path.clone(), entry.id).is_some() {
            bail!(
                "validation repository reported duplicate gitlink {}",
                path_json_text(&path)
            );
        }
    }
    Ok(gitlinks.into_iter().collect())
}

fn validation_filesystem_fingerprint(root: &Path) -> Result<ValidationFilesystemFingerprint> {
    match fs::symlink_metadata(root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ValidationFilesystemFingerprint {
                exists: false,
                entries: Vec::new(),
            })
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect submodule filesystem {}", root.display())
            })
        }
    }
    let mut entries = Vec::new();
    let mut budget = ValidationFilesystemBudget {
        entries: 0,
        total_bytes: 0,
        max_entries: VALIDATION_RAW_MAX_ENTRIES,
        max_total_bytes: VALIDATION_RAW_MAX_TOTAL_BYTES,
        max_single_file_bytes: VALIDATION_RAW_MAX_SINGLE_FILE_BYTES,
    };
    collect_validation_filesystem_entries(root, root, &mut entries, &mut budget)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(ValidationFilesystemFingerprint {
        exists: true,
        entries,
    })
}

fn validation_submodule_marker_fingerprint(
    marker: &Path,
) -> Result<ValidationFilesystemFingerprint> {
    let metadata = fs::symlink_metadata(marker)
        .with_context(|| format!("failed to inspect submodule marker {}", marker.display()))?;
    let mut budget = ValidationFilesystemBudget {
        entries: 0,
        total_bytes: 0,
        max_entries: 1,
        max_total_bytes: VALIDATION_MARKER_MAX_BYTES,
        max_single_file_bytes: VALIDATION_MARKER_MAX_BYTES,
    };
    let entry = validation_filesystem_entry(marker, PathBuf::from(".git"), &metadata, &mut budget)?;
    Ok(ValidationFilesystemFingerprint {
        exists: true,
        entries: vec![entry],
    })
}

fn collect_validation_filesystem_entries(
    root: &Path,
    path: &Path,
    entries: &mut Vec<ValidationFilesystemEntry>,
    budget: &mut ValidationFilesystemBudget,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect validation path {}", path.display()))?;
    let relative = path
        .strip_prefix(root)
        .context("validation filesystem path escaped submodule root")?
        .to_path_buf();
    let file_type = metadata.file_type();
    entries.push(validation_filesystem_entry(
        path, relative, &metadata, budget,
    )?);

    if file_type.is_dir() {
        let mut children = Vec::new();
        for entry in fs::read_dir(path)
            .with_context(|| format!("failed to list validation directory {}", path.display()))?
        {
            let child = entry
                .with_context(|| {
                    format!(
                        "failed to read validation directory entry in {}",
                        path.display()
                    )
                })?
                .path();
            if budget
                .entries
                .saturating_add(children.len())
                .saturating_add(1)
                > budget.max_entries
            {
                return Err(ValidationFilesystemFingerprintError::EntryCountExceeded {
                    path: child,
                    limit: budget.max_entries,
                }
                .into());
            }
            children.push(child);
        }
        children.sort();
        for child in children {
            collect_validation_filesystem_entries(root, &child, entries, budget)?;
        }
    }
    Ok(())
}

fn validation_filesystem_entry(
    path: &Path,
    relative: PathBuf,
    metadata: &fs::Metadata,
    budget: &mut ValidationFilesystemBudget,
) -> Result<ValidationFilesystemEntry> {
    budget.entries = budget.entries.saturating_add(1);
    if budget.entries > budget.max_entries {
        return Err(ValidationFilesystemFingerprintError::EntryCountExceeded {
            path: relative,
            limit: budget.max_entries,
        }
        .into());
    }
    let file_type = metadata.file_type();
    let (kind, content_digest) = if file_type.is_dir() {
        (ValidationFilesystemEntryKind::Directory, None)
    } else if file_type.is_file() {
        (
            ValidationFilesystemEntryKind::File,
            Some(validation_file_content_digest(
                path, &relative, metadata, budget,
            )?),
        )
    } else if file_type.is_symlink() {
        let target = fs::read_link(path)
            .with_context(|| format!("failed to read validation symlink {}", path.display()))?;
        let target = raw_path_bytes(&target);
        budget.add_content_bytes(&relative, target.len() as u64)?;
        (
            ValidationFilesystemEntryKind::Symlink,
            Some(
                Oid::hash_object(ObjectType::Blob, &target)
                    .context("failed to hash validation symlink target")?,
            ),
        )
    } else {
        (ValidationFilesystemEntryKind::Other, None)
    };
    Ok(ValidationFilesystemEntry {
        path: relative,
        kind,
        mode: validation_file_mode(metadata),
        content_digest,
    })
}

fn validation_file_content_digest(
    path: &Path,
    relative: &Path,
    metadata: &fs::Metadata,
    budget: &mut ValidationFilesystemBudget,
) -> Result<Oid> {
    if metadata.len() > budget.max_single_file_bytes {
        return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
            path: relative.to_path_buf(),
            limit: budget.max_single_file_bytes,
        }
        .into());
    }
    let remaining_total = budget.max_total_bytes.saturating_sub(budget.total_bytes);
    let read_limit = budget
        .max_single_file_bytes
        .min(remaining_total)
        .saturating_add(1);
    let mut content = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("failed to open validation file {}", path.display()))?
        .take(read_limit)
        .read_to_end(&mut content)
        .with_context(|| format!("failed to read validation file {}", path.display()))?;
    let content_len = content.len() as u64;
    if content_len > budget.max_single_file_bytes {
        return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
            path: relative.to_path_buf(),
            limit: budget.max_single_file_bytes,
        }
        .into());
    }
    budget.add_content_bytes(relative, content_len)?;
    Oid::hash_object(ObjectType::Blob, &content).context("failed to hash validation file content")
}

impl ValidationFilesystemBudget {
    fn add_content_bytes(&mut self, path: &Path, bytes: u64) -> Result<()> {
        if bytes > self.max_single_file_bytes {
            return Err(ValidationFilesystemFingerprintError::SingleFileTooLarge {
                path: path.to_path_buf(),
                limit: self.max_single_file_bytes,
            }
            .into());
        }
        let Some(total) = self.total_bytes.checked_add(bytes) else {
            return Err(ValidationFilesystemFingerprintError::TotalContentTooLarge {
                path: path.to_path_buf(),
                limit: self.max_total_bytes,
            }
            .into());
        };
        if total > self.max_total_bytes {
            return Err(ValidationFilesystemFingerprintError::TotalContentTooLarge {
                path: path.to_path_buf(),
                limit: self.max_total_bytes,
            }
            .into());
        }
        self.total_bytes = total;
        Ok(())
    }
}

fn validation_file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        u32::from(metadata.permissions().readonly())
    }
}

fn run_candidate_validation_command(
    worktree_path: &Path,
    environment_root: &Path,
    validation: &CandidateValidationCommand,
    index: usize,
    changed_paths: &[PathBuf],
) -> ValidationReport {
    run_candidate_validation_command_with_timeout(
        worktree_path,
        environment_root,
        validation,
        index,
        changed_paths,
        CANDIDATE_VALIDATION_PROCESS_TIMEOUT,
    )
}

fn run_candidate_validation_command_with_timeout(
    worktree_path: &Path,
    environment_root: &Path,
    validation: &CandidateValidationCommand,
    index: usize,
    changed_paths: &[PathBuf],
    timeout: Duration,
) -> ValidationReport {
    let redactor = validation_diagnostics_redactor(environment_root);
    let environment = match validation_command_environment(environment_root) {
        Ok(environment) => environment,
        Err(error) => {
            return failed_candidate_validation_report(
                index,
                changed_paths,
                &redactor,
                format!("failed to prepare validation environment: {error:#}"),
            )
        }
    };
    let output = run_process(
        ProcessSpec::shell(
            "candidate validation command",
            Shell::for_current_platform(),
            &validation.command,
            worktree_path,
            VALIDATION_CAPTURE_LIMIT_BYTES,
        )
        .with_environment(EnvironmentMode::ClearAndSet(environment))
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(timeout)),
    );

    match output {
        Ok(output) => {
            let evidence = require_verified_process_output(
                "candidate validation command",
                &output,
                SideEffectConfinementProfileKind::StrictOfflineWorkspace,
            );
            let passed = evidence.is_ok()
                && output.status.is_some_and(|status| status.success())
                && !output.timed_out;
            ValidationReport {
                name: format!("candidate validation {}", index + 1),
                status: if passed {
                    ValidationStatus::Passed
                } else {
                    ValidationStatus::Failed
                },
                message: evidence
                    .err()
                    .map(|error| redact_validation_diagnostic(&redactor, &error.to_string()))
                    .or_else(|| candidate_validation_message(&output, &redactor)),
                paths: if passed {
                    Vec::new()
                } else {
                    changed_paths.to_vec()
                },
            }
        }
        Err(error) => failed_candidate_validation_report(
            index,
            changed_paths,
            &redactor,
            format!("failed to run validation command: {error}"),
        ),
    }
}

fn failed_candidate_validation_report(
    index: usize,
    changed_paths: &[PathBuf],
    redactor: &Redactor,
    message: String,
) -> ValidationReport {
    ValidationReport {
        name: format!("candidate validation {}", index + 1),
        status: ValidationStatus::Failed,
        message: Some(redact_validation_diagnostic(redactor, &message)),
        paths: changed_paths.to_vec(),
    }
}

fn candidate_validation_message(output: &ProcessOutput, redactor: &Redactor) -> Option<String> {
    if output.status.is_some_and(|status| status.success()) {
        return None;
    }
    let stderr = String::from_utf8_lossy(output.stderr.as_bytes());
    let stdout = String::from_utf8_lossy(output.stdout.as_bytes());
    let text = if !stderr.trim().is_empty() {
        stderr.trim()
    } else if !stdout.trim().is_empty() {
        stdout.trim()
    } else {
        "candidate validation command failed"
    };
    let exit = output
        .status
        .and_then(|status| status.code())
        .map(|code| format!("exited with status {code}"))
        .unwrap_or_else(|| "terminated without an exit code".to_string());
    let text = redact_validation_diagnostic(redactor, text);
    Some(format!("{exit}: {}", summarize_text(&text, 1024).text))
}

fn redact_validation_diagnostic(redactor: &Redactor, message: &str) -> String {
    redactor.redact(message).text
}

fn append_validation_message(existing: Option<String>, next: &str) -> Option<String> {
    Some(match existing {
        Some(existing) => format!("{existing}; {next}"),
        None => next.to_string(),
    })
}

struct SafetyChecks<'a> {
    primary_state_unchanged: &'a SafetyCheck,
    dirty_primary: &'a SafetyCheck,
    stale_base: &'a SafetyCheck,
    apply_check: &'a SafetyCheck,
    unclaimed_edits: &'a SafetyCheck,
    validation: &'a SafetyCheck,
    validation_evidence: &'a ValidationEvidenceCheck,
    megafile: &'a SafetyCheck,
    validations: &'a [ValidationReport],
    require_validation: bool,
    validation_commands: &'a [String],
    validation_related_paths: &'a [PathBuf],
}

fn classify_apply_safety(checks: SafetyChecks<'_>, forces: &MergeForceOptions) -> ApplyReadiness {
    let candidates = [
        (
            checks.primary_state_unchanged,
            ApplyBlocker::PrimaryStateChanged,
            false,
        ),
        (
            checks.dirty_primary,
            ApplyBlocker::DirtyPrimary,
            forces.allow_dirty_primary,
        ),
        (
            checks.stale_base,
            ApplyBlocker::StaleBase,
            forces.allow_stale_base,
        ),
        (checks.apply_check, ApplyBlocker::ApplyCheckFailed, false),
        (
            checks.unclaimed_edits,
            ApplyBlocker::UnclaimedEdits,
            forces.allow_unclaimed_edits,
        ),
    ];
    let mut blockers = Vec::new();
    let mut forced = Vec::new();
    let mut details = Vec::new();

    for (check, blocker, force_allowed) in candidates {
        if check.status != SafetyCheckStatus::Failed {
            continue;
        }
        let disposition = if force_allowed {
            forced.push(blocker);
            ApplyBlockerDisposition::Forced
        } else {
            blockers.push(blocker);
            ApplyBlockerDisposition::Blocked
        };
        details.push(ApplyBlockerDetail {
            kind: blocker,
            disposition,
            check_status: check.status,
            paths: check.paths.clone(),
            message: check.message.clone(),
            validation_reports: Vec::new(),
            validation_commands: Vec::new(),
            next_safe_operation: None,
        });
    }

    if checks.megafile.status == SafetyCheckStatus::Failed {
        blockers.push(ApplyBlocker::ExcludedReference);
        details.push(ApplyBlockerDetail {
            kind: ApplyBlocker::ExcludedReference,
            disposition: ApplyBlockerDisposition::Blocked,
            check_status: checks.megafile.status,
            paths: checks.megafile.paths.clone(),
            message: checks.megafile.message.clone(),
            validation_reports: checks.validations.to_vec(),
            validation_commands: checks.validation_commands.to_vec(),
            next_safe_operation: Some(
                "run an isolated megafile_decomposition assignment for the exact blocked path through the normal claim, validation, review, and merge gates"
                    .to_string(),
            ),
        });
    }

    if let Some(detail) = validation_evidence_blocker_detail(&checks) {
        blockers.push(detail.kind);
        details.push(detail);
    }

    for detail in validation_blocker_details(&checks, forces) {
        match detail.disposition {
            ApplyBlockerDisposition::Blocked => blockers.push(detail.kind),
            ApplyBlockerDisposition::Forced => forced.push(detail.kind),
        }
        details.push(detail);
    }

    blockers.sort();
    blockers.dedup();
    forced.sort();
    forced.dedup();

    let status = if !blockers.is_empty() {
        ApplyReadinessStatus::Blocked
    } else if !forced.is_empty() {
        ApplyReadinessStatus::Forced
    } else {
        ApplyReadinessStatus::Safe
    };

    ApplyReadiness {
        status,
        blockers,
        forced,
        details,
    }
}

fn validation_evidence_blocker_detail(checks: &SafetyChecks<'_>) -> Option<ApplyBlockerDetail> {
    if checks.validation_evidence.status != SafetyCheckStatus::Failed {
        return None;
    }
    let (kind, next_safe_operation) = match checks.validation_evidence.binding_status {
        ValidationBindingStatus::Unbound => (
            ApplyBlocker::ValidationMissing,
            "regenerate the validation report as an envelope containing the current candidate.validation_binding and its reports",
        ),
        ValidationBindingStatus::Mismatched => (
            ApplyBlocker::ValidationMissing,
            "rerun validation for the current candidate.validation_binding and replace stale evidence",
        ),
        _ => return None,
    };
    Some(ApplyBlockerDetail {
        kind,
        disposition: ApplyBlockerDisposition::Blocked,
        check_status: checks.validation_evidence.status,
        paths: checks.validation_evidence.paths.clone(),
        message: checks.validation_evidence.message.clone(),
        validation_reports: checks
            .validations
            .iter()
            .filter(|report| report.status == ValidationStatus::Passed)
            .cloned()
            .collect(),
        validation_commands: checks.validation_commands.to_vec(),
        next_safe_operation: Some(next_safe_operation.to_string()),
    })
}

fn validation_blocker_details(
    checks: &SafetyChecks<'_>,
    forces: &MergeForceOptions,
) -> Vec<ApplyBlockerDetail> {
    if checks.validation.status != SafetyCheckStatus::Failed {
        return Vec::new();
    }

    let mut details = Vec::new();
    let failed = reports_with_status(checks.validations, ValidationStatus::Failed);
    if !failed.is_empty() {
        details.push(validation_blocker_detail(
            ApplyBlocker::ValidationFailed,
            checks,
            failed,
            !checks.require_validation && forces.allow_validation_failures,
            "run the failing validation command again after fixing the reported paths",
        ));
    }

    if checks.require_validation {
        if checks.validations.is_empty() {
            details.push(validation_blocker_detail(
                ApplyBlocker::ValidationMissing,
                checks,
                Vec::new(),
                false,
                "supply --validation-report with at least one passed check or run merge apply --validation-command <command>",
            ));
            return details;
        }

        if !checks
            .validations
            .iter()
            .any(|validation| validation.status == ValidationStatus::Passed)
        {
            let not_run = reports_with_status(checks.validations, ValidationStatus::NotRun);
            if !not_run.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationNotRun,
                    checks,
                    not_run,
                    false,
                    "run the pending validation command and provide a passed validation report",
                ));
            }
            let skipped = reports_with_status(checks.validations, ValidationStatus::Skipped);
            if !skipped.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationSkipped,
                    checks,
                    skipped,
                    false,
                    "run the skipped validation command and provide a passed validation report",
                ));
            }
            if details.is_empty() {
                details.push(validation_blocker_detail(
                    ApplyBlocker::ValidationMissing,
                    checks,
                    checks.validations.to_vec(),
                    false,
                    "provide at least one passed validation report",
                ));
            }
        }
    }

    details
}

fn validation_blocker_detail(
    kind: ApplyBlocker,
    checks: &SafetyChecks<'_>,
    reports: Vec<ValidationReport>,
    force_allowed: bool,
    next_safe_operation: &str,
) -> ApplyBlockerDetail {
    let paths = validation_detail_paths(&reports, checks.validation_related_paths);
    ApplyBlockerDetail {
        kind,
        disposition: if force_allowed {
            ApplyBlockerDisposition::Forced
        } else {
            ApplyBlockerDisposition::Blocked
        },
        check_status: checks.validation.status,
        paths,
        message: checks.validation.message.clone(),
        validation_reports: reports,
        validation_commands: checks.validation_commands.to_vec(),
        next_safe_operation: Some(next_safe_operation.to_string()),
    }
}

fn validation_detail_paths(
    reports: &[ValidationReport],
    validation_related_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let mut paths = reports
        .iter()
        .flat_map(|report| report.paths.iter().cloned())
        .collect::<BTreeSet<_>>();
    if paths.is_empty() {
        paths.extend(validation_related_paths.iter().cloned());
    }
    paths.into_iter().collect()
}

fn reports_with_status(
    validations: &[ValidationReport],
    status: ValidationStatus,
) -> Vec<ValidationReport> {
    validations
        .iter()
        .filter(|validation| validation.status == status)
        .cloned()
        .collect()
}

pub(crate) fn unclaimed_paths(
    changed_paths: &[PathBuf],
    claimed_paths: &[PathBuf],
) -> Vec<PathBuf> {
    changed_paths
        .iter()
        .filter(|path| {
            !claimed_paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
        })
        .cloned()
        .collect()
}

pub(crate) fn normalize_claim_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
    let paths = paths
        .into_iter()
        .map(normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    Ok(collapse_covered_paths(paths))
}

fn collapse_covered_paths(paths: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut collapsed: Vec<PathBuf> = Vec::new();
    for path in paths {
        if collapsed.iter().any(|existing| path.starts_with(existing)) {
            continue;
        }
        collapsed.retain(|existing| !existing.starts_with(&path));
        collapsed.push(path);
    }

    collapsed
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn classify_status(status: Status) -> ChangeKind {
    if status.contains(Status::CONFLICTED) {
        ChangeKind::Conflicted
    } else if status.contains(Status::WT_NEW) {
        ChangeKind::Untracked
    } else if status.contains(Status::INDEX_RENAMED) || status.contains(Status::WT_RENAMED) {
        ChangeKind::Renamed
    } else if status.contains(Status::INDEX_DELETED) || status.contains(Status::WT_DELETED) {
        ChangeKind::Deleted
    } else if status.contains(Status::INDEX_NEW) {
        ChangeKind::Added
    } else if status.contains(Status::INDEX_TYPECHANGE) || status.contains(Status::WT_TYPECHANGE) {
        ChangeKind::Typechange
    } else if status.contains(Status::INDEX_MODIFIED) || status.contains(Status::WT_MODIFIED) {
        ChangeKind::Modified
    } else {
        ChangeKind::Unknown
    }
}

pub(crate) fn serialize_path<S>(path: &Path, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&path_json_text(path))
}

pub(crate) fn serialize_paths<S>(
    paths: &[PathBuf],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| path_json_text(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

fn serialize_optional_path<S>(
    path: &Option<PathBuf>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    path.as_deref().map(path_json_text).serialize(serializer)
}

pub(crate) fn path_json_text(path: &Path) -> String {
    if let Some(path) = path.to_str() {
        return path.to_string();
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return escape_bytes_ascii(path.as_os_str().as_bytes());
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut escaped = String::new();
        for unit in path.as_os_str().encode_wide() {
            if matches!(unit, 0x20..=0x7e) && unit != u16::from(b'\\') {
                escaped.push(char::from_u32(u32::from(unit)).unwrap_or('?'));
            } else {
                let _ = write!(&mut escaped, "\\u{unit:04X}");
            }
        }
        return escaped;
    }

    #[allow(unreachable_code)]
    "<non-unicode-path>".to_string()
}

pub(crate) fn raw_path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        return path.as_os_str().as_bytes().to_vec();
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::ffi::OsStrExt;
        return path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect();
    }

    #[allow(unreachable_code)]
    path.as_os_str()
        .to_str()
        .map(str::as_bytes)
        .unwrap_or_default()
        .to_vec()
}

fn path_buf_from_git_bytes(bytes: &[u8]) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
    }

    #[cfg(not(unix))]
    {
        let path = String::from_utf8(bytes.to_vec())
            .context("Git returned a repository path that is not valid UTF-8 on this platform")?;
        Ok(PathBuf::from(path))
    }
}

pub(crate) fn patch_text_for_json(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap_or_else(|error| escape_bytes_ascii(error.as_bytes()))
}

fn escape_bytes_ascii(bytes: &[u8]) -> String {
    let mut escaped = String::new();
    for byte in bytes {
        match *byte {
            b'\n' => escaped.push('\n'),
            b'\r' => escaped.push('\r'),
            b'\t' => escaped.push('\t'),
            0x20..=0x7e if *byte != b'\\' => escaped.push(char::from(*byte)),
            b'\\' => escaped.push_str("\\\\"),
            _ => {
                let _ = write!(&mut escaped, "\\x{byte:02X}");
            }
        }
    }
    escaped
}

fn summarize_text(text: &str, limit: usize) -> OutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    OutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn head_oid(repo: &Repository) -> Result<Option<Oid>, git2::Error> {
    match repo.head() {
        Ok(head) => head.peel_to_commit().map(|commit| Some(commit.id())),
        Err(error) if error.code() == ErrorCode::UnbornBranch => Ok(None),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn merge_base_oid(repo: &Repository, primary: Oid, agent: Oid) -> Result<Option<Oid>> {
    match repo.merge_base(primary, agent) {
        Ok(oid) => Ok(Some(oid)),
        Err(error) if error.code() == ErrorCode::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to compute merge base"),
    }
}

fn discover_primary_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("merge operations require a non-bare primary repository")
}

impl RepoCommonLock {
    pub(crate) fn acquire(repo_root: &Path, operation: &str) -> Result<Self> {
        if operation.is_empty()
            || !operation
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("repository lock operation name is invalid");
        }
        let repo = crate::git_repository::open(repo_root).with_context(|| {
            format!(
                "failed to open repository for {operation} lock {}",
                repo_root.display()
            )
        })?;
        let state_dir = ensure_repo_common_state_directory(&repo)
            .with_context(|| format!("failed to prepare {operation} lock directory"))?;
        let path = state_dir.join(REPOSITORY_MUTATION_LOCK_FILE);
        let mut file = open_repo_lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return repository_lock_contention(&mut file, &path, operation)
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(error).with_context(|| {
                    format!(
                        "{operation} could not acquire kernel repository mutation lock {}; refusing to continue",
                        path.display()
                    )
                })
            }
        }

        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch")?;
        let process_start = lock_owner_process_start_identity()?;
        let owner = RepoLockOwner {
            version: LOCK_RECORD_VERSION,
            pid: std::process::id(),
            nonce: format!("{}-{}", std::process::id(), duration.as_nanos()),
            created_unix_seconds: duration.as_secs(),
            operation: operation.to_string(),
            process_start,
        };
        let mut owner_bytes = serde_json::to_vec(&owner).context("failed to encode lock owner")?;
        owner_bytes.push(b'\n');
        write_lock_owner(&mut file, &path, operation, &owner_bytes)?;
        Ok(Self { file })
    }
}

fn open_repo_lock_file(path: &Path) -> Result<fs::File> {
    let mut create_options = OpenOptions::new();
    create_options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let (file, created) = match create_options.open(path) {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            reject_unsafe_lock_path(path)?;
            let mut existing_options = OpenOptions::new();
            existing_options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                existing_options
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                existing_options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            (
                existing_options.open(path).with_context(|| {
                    format!("failed to open repository lock {}", path.display())
                })?,
                false,
            )
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create repository lock {}", path.display()))
        }
    };
    validate_open_lock_file(path, &file)?;
    if created {
        let parent = path
            .parent()
            .context("repository mutation lock has no parent directory")?;
        sync_managed_directory(parent)?;
    }
    Ok(file)
}

pub(crate) fn ensure_repo_common_state_directory(repo: &Repository) -> Result<PathBuf> {
    let common_dir = repo.commondir();
    validate_managed_directory(common_dir).with_context(|| {
        format!(
            "repository common directory {} is unsafe",
            common_dir.display()
        )
    })?;
    let maco = ensure_private_managed_directory(common_dir, "maco")?;
    ensure_private_managed_directory(&maco, "state")
}

pub(crate) fn ensure_private_managed_directory(parent: &Path, name: &str) -> Result<PathBuf> {
    validate_managed_directory(parent)?;
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("managed directory component is invalid");
    }
    let path = parent.join(name);
    let created = match fs::create_dir(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to create managed directory {}", path.display()))
        }
    };
    validate_managed_directory(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure managed directory {}", path.display()))?;
        validate_managed_directory(&path)?;
    }
    sync_managed_directory(&path)?;
    if created {
        sync_managed_directory(parent)?;
    }
    Ok(path)
}

fn validate_managed_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect managed directory {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "managed directory {} is not a real directory; refusing symbolic links and non-directory paths",
            path.display()
        );
    }
    #[cfg(target_os = "windows")]
    {
        if windows_path_link_count(path)? != 1 {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(target_os = "windows")]
fn windows_path_link_count(path: &Path) -> Result<u32> {
    crate::file_identity::open_windows_path_identity(path)
        .with_context(|| {
            format!(
                "failed to inspect Windows link count for {}",
                path.display()
            )
        })
        .map(|snapshot| snapshot.number_of_links)
}

#[cfg(not(target_os = "windows"))]
fn metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn sync_managed_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("failed to open managed directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to persist managed directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_managed_directory(_path: &Path) -> Result<()> {
    Ok(())
}
