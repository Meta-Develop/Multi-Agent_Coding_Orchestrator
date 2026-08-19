impl ReviewStateBinding {
    fn verify(&self, common_root: &SafeRoot) -> Result<()> {
        match self {
            Self::MissingMaco => {
                if common_root.direct_child_exists("maco")? {
                    bail!("review Git state root appeared during review");
                }
            }
            Self::MissingState { maco_root } => {
                maco_root
                    .verify()
                    .map_err(|_| anyhow::anyhow!("review Git state parent changed"))?;
                if maco_root.direct_child_exists("state")? {
                    bail!("review Git state root appeared during review");
                }
            }
            Self::Bound {
                maco_root,
                state_root,
            } => {
                maco_root
                    .verify()
                    .map_err(|_| anyhow::anyhow!("review Git state parent changed"))?;
                state_root
                    .verify()
                    .map_err(|_| anyhow::anyhow!("review Git state root changed"))?;
            }
        }
        Ok(())
    }

    fn identity(&self) -> Option<FileIdentity> {
        match self {
            Self::Bound { state_root, .. } => Some(state_root.identity().clone()),
            Self::MissingMaco | Self::MissingState { .. } => None,
        }
    }
}

fn minimal_sanitized_hidden_roots(roots: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    let mut roots = roots.into_iter().collect::<Vec<_>>();
    roots.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    let mut minimal = Vec::<PathBuf>::new();
    for root in roots {
        if minimal.iter().any(|ancestor| root.starts_with(ancestor)) {
            continue;
        }
        minimal.push(root);
    }
    minimal
}

fn bind_review_state(common_root: &SafeRoot) -> Result<ReviewStateBinding> {
    if !common_root.direct_child_exists("maco")? {
        return Ok(ReviewStateBinding::MissingMaco);
    }
    let maco = common_root
        .bind_existing_managed_direct_child_directory("maco")
        .map_err(|_| anyhow::anyhow!("review Git state parent is unsafe"))?;
    let maco_root = SafeRoot::open_existing(maco.path())
        .map_err(|_| anyhow::anyhow!("review Git state parent binding is unsafe"))?;
    if !maco_root.direct_child_exists("state")? {
        return Ok(ReviewStateBinding::MissingState { maco_root });
    }
    let state = maco_root
        .bind_existing_managed_direct_child_directory("state")
        .map_err(|_| anyhow::anyhow!("review Git state root is unsafe"))?;
    let state_root = SafeRoot::open_existing(state.path())
        .map_err(|_| anyhow::anyhow!("review Git state root binding is unsafe"))?;
    Ok(ReviewStateBinding::Bound {
        maco_root,
        state_root,
    })
}

#[derive(Debug, Default, Clone, Copy)]
struct SnapshotPathOrigin {
    tracked: bool,
    untracked: bool,
    ignored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum SnapshotTreeEntry {
    Missing,
    Regular {
        mode: u32,
        length: u64,
        sha256: [u8; 32],
        identity: FileIdentity,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    },
    Symlink {
        mode: u32,
        target: Vec<u8>,
        identity: FileIdentity,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundReviewDirectory {
    mode: u32,
    identity: FileIdentity,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl SnapshotTreeEntry {
    fn append_canonical(&self, output: &mut Vec<u8>) {
        match self {
            Self::Missing => output.push(0),
            Self::Regular {
                mode,
                length,
                sha256,
                identity,
                modified_seconds,
                modified_nanoseconds,
                changed_seconds,
                changed_nanoseconds,
            } => {
                output.push(1);
                output.extend_from_slice(&mode.to_be_bytes());
                output.extend_from_slice(&length.to_be_bytes());
                output.extend_from_slice(sha256);
                append_file_generation(
                    output,
                    identity,
                    *modified_seconds,
                    *modified_nanoseconds,
                    *changed_seconds,
                    *changed_nanoseconds,
                );
            }
            Self::Symlink {
                mode,
                target,
                identity,
                modified_seconds,
                modified_nanoseconds,
                changed_seconds,
                changed_nanoseconds,
            } => {
                output.push(2);
                output.extend_from_slice(&mode.to_be_bytes());
                output.extend_from_slice(
                    &u64::try_from(target.len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                output.extend_from_slice(target);
                append_file_generation(
                    output,
                    identity,
                    *modified_seconds,
                    *modified_nanoseconds,
                    *changed_seconds,
                    *changed_nanoseconds,
                );
            }
        }
    }
}

fn append_file_generation(
    output: &mut Vec<u8>,
    identity: &FileIdentity,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
) {
    output.extend_from_slice(&identity.device.to_be_bytes());
    output.extend_from_slice(&identity.file.to_be_bytes());
    output.extend_from_slice(&modified_seconds.to_be_bytes());
    output.extend_from_slice(&modified_nanoseconds.to_be_bytes());
    output.extend_from_slice(&changed_seconds.to_be_bytes());
    output.extend_from_slice(&changed_nanoseconds.to_be_bytes());
}

#[derive(Debug)]
struct ReviewTreeReader {
    #[cfg(unix)]
    root: File,
    identity: FileIdentity,
}

impl ReviewTreeReader {
    fn bind(root: &SafeRoot) -> Result<Self> {
        root.verify()
            .map_err(|_| anyhow::anyhow!("review worktree root is unsafe"))?;
        #[cfg(unix)]
        {
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let file = options
                .open(root.path())
                .context("failed to open bound review worktree")?;
            let metadata = file
                .metadata()
                .context("failed to inspect bound review worktree")?;
            let identity = file_identity_from_metadata(&metadata);
            if &identity != root.identity() {
                bail!("review worktree descriptor does not match its safe root");
            }
            Ok(Self {
                root: file,
                identity,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = root;
            bail!("exact no-follow review snapshots are unsupported on this platform")
        }
    }

    fn verify(&self, root: &SafeRoot) -> Result<()> {
        root.verify()
            .map_err(|_| anyhow::anyhow!("review worktree root changed"))?;
        if &self.identity != root.identity() {
            bail!("review worktree root identity changed");
        }
        #[cfg(unix)]
        {
            let metadata = self
                .root
                .metadata()
                .context("failed to revalidate review worktree descriptor")?;
            if file_identity_from_metadata(&metadata) != self.identity {
                bail!("review worktree descriptor identity changed");
            }
            Ok(())
        }
        #[cfg(not(unix))]
        bail!("exact no-follow review snapshots are unsupported on this platform")
    }

    fn snapshot_directory(&self, path: &Path) -> Result<BoundReviewDirectory> {
        validate_snapshot_relative_path(path)?;
        #[cfg(unix)]
        {
            let (parent, name) = self
                .open_parent(path)?
                .context("review directory parent is missing or unsafe")?;
            let name_c = c_string(&name)?;
            let before =
                stat_at_nofollow(&parent, &name_c).context("failed to inspect review directory")?;
            if before.st_uid != unsafe { libc::geteuid() }
                || before.st_mode & libc::S_IFMT != libc::S_IFDIR
            {
                bail!("review directory identity or ownership is unsafe");
            }
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to bind review directory without following links");
            }
            let directory = unsafe { File::from_raw_fd(fd) };
            let opened = fstat_file(&directory)?;
            if !same_stat_generation(&before, &opened) {
                bail!("review directory changed during binding");
            }
            Ok(BoundReviewDirectory {
                mode: unsigned_to_u32(opened.st_mode),
                identity: file_identity_from_stat(&opened),
                modified_seconds: opened.st_mtime,
                modified_nanoseconds: stat_modified_nanoseconds(&opened),
                changed_seconds: opened.st_ctime,
                changed_nanoseconds: stat_changed_nanoseconds(&opened),
            })
        }
        #[cfg(not(unix))]
        bail!("exact no-follow review directories are unsupported on this platform")
    }

    fn prewalk(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let deadline = Instant::now()
                .checked_add(REVIEW_PREWALK_TIMEOUT)
                .context("review prewalk deadline overflow")?;
            let root_stat = fstat_file(&self.root)?;
            let mut entry_count = 0usize;
            let mut total_bytes = 0u64;
            prewalk_review_directory(
                &self.root,
                Path::new(""),
                root_stat.st_dev,
                0,
                &mut entry_count,
                &mut total_bytes,
                deadline,
            )
        }
        #[cfg(not(target_os = "linux"))]
        bail!("bounded descriptor review prewalk is unsupported on this platform")
    }

    fn snapshot_entry(
        &self,
        path: &Path,
        total_content_bytes: &mut u64,
    ) -> Result<SnapshotTreeEntry> {
        validate_snapshot_relative_path(path)?;
        #[cfg(unix)]
        {
            let Some((parent, name)) = self.open_parent(path)? else {
                return Ok(SnapshotTreeEntry::Missing);
            };
            let name_c = c_string(&name)?;
            let before = match stat_at_nofollow(&parent, &name_c) {
                Ok(stat) => stat,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(SnapshotTreeEntry::Missing)
                }
                Err(error) => return Err(error).context("failed to inspect review worktree entry"),
            };
            validate_snapshot_entry_owner_and_links(&before)?;
            let file_type = before.st_mode & libc::S_IFMT;
            let mode = unsigned_to_u32(before.st_mode);
            if file_type == libc::S_IFREG {
                let length = u64::try_from(before.st_size)
                    .context("review worktree file has a negative length")?;
                if length > REVIEW_SNAPSHOT_FILE_LIMIT_BYTES {
                    bail!(
                        "review worktree file exceeds its {} byte limit",
                        REVIEW_SNAPSHOT_FILE_LIMIT_BYTES
                    );
                }
                let next_total = total_content_bytes
                    .checked_add(length)
                    .context("review snapshot content-byte total overflow")?;
                if next_total > REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES {
                    bail!(
                        "review worktree exceeds its {} byte total snapshot limit",
                        REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES
                    );
                }
                let fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name_c.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to open review worktree file without following links");
                }
                let mut file = unsafe { File::from_raw_fd(fd) };
                let opened = fstat_file(&file)?;
                if !same_stat_generation(&before, &opened) {
                    bail!("review worktree file changed before bounded read");
                }
                let capacity = usize::try_from(length)
                    .context("review worktree file length does not fit memory")?;
                let mut contents = Vec::with_capacity(capacity);
                (&mut file)
                    .take(REVIEW_SNAPSHOT_FILE_LIMIT_BYTES.saturating_add(1))
                    .read_to_end(&mut contents)
                    .context("failed to read review worktree file")?;
                if u64::try_from(contents.len()).unwrap_or(u64::MAX) != length {
                    bail!("review worktree file changed during bounded read");
                }
                let after = fstat_file(&file)?;
                if !same_stat_generation(&opened, &after) {
                    bail!("review worktree file changed during bounded read");
                }
                *total_content_bytes = next_total;
                Ok(SnapshotTreeEntry::Regular {
                    mode,
                    length,
                    sha256: sha256_bytes(&contents),
                    identity: file_identity_from_stat(&opened),
                    modified_seconds: opened.st_mtime,
                    modified_nanoseconds: stat_modified_nanoseconds(&opened),
                    changed_seconds: opened.st_ctime,
                    changed_nanoseconds: stat_changed_nanoseconds(&opened),
                })
            } else if file_type == libc::S_IFLNK {
                let mut target = vec![0u8; REVIEW_SYMLINK_LIMIT_BYTES.saturating_add(1)];
                let read = unsafe {
                    libc::readlinkat(
                        parent.as_raw_fd(),
                        name_c.as_ptr(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                if read < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to read review worktree symlink without following it");
                }
                let read = usize::try_from(read).context("review symlink length overflow")?;
                if read > REVIEW_SYMLINK_LIMIT_BYTES {
                    bail!(
                        "review worktree symlink exceeds its {} byte target limit",
                        REVIEW_SYMLINK_LIMIT_BYTES
                    );
                }
                target.truncate(read);
                let after = stat_at_nofollow(&parent, &name_c)
                    .context("failed to revalidate review worktree symlink")?;
                if !same_stat_generation(&before, &after) {
                    bail!("review worktree symlink changed during snapshot");
                }
                validate_internal_symlink_target(path, &target)?;
                Ok(SnapshotTreeEntry::Symlink {
                    mode,
                    target,
                    identity: file_identity_from_stat(&before),
                    modified_seconds: before.st_mtime,
                    modified_nanoseconds: stat_modified_nanoseconds(&before),
                    changed_seconds: before.st_ctime,
                    changed_nanoseconds: stat_changed_nanoseconds(&before),
                })
            } else {
                bail!("review worktree contains an unsupported special or directory entry");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = total_content_bytes;
            bail!("exact no-follow review snapshots are unsupported on this platform")
        }
    }

    fn snapshot_git_backlink(&self) -> Result<GitBacklinkSnapshot> {
        #[cfg(unix)]
        {
            let name = c_string(OsStr::new(".git"))?;
            let before = stat_at_nofollow(&self.root, &name)
                .context("review worktree Git backlink is missing or unsafe")?;
            if before.st_uid != unsafe { libc::geteuid() } {
                bail!("review worktree Git backlink ownership is unsafe");
            }
            let identity = file_identity_from_stat(&before);
            let file_type = before.st_mode & libc::S_IFMT;
            if file_type == libc::S_IFDIR {
                return Ok(GitBacklinkSnapshot {
                    kind: "directory".to_string(),
                    mode: unsigned_to_u32(before.st_mode),
                    identity,
                    modified_seconds: before.st_mtime,
                    modified_nanoseconds: stat_modified_nanoseconds(&before),
                    changed_seconds: before.st_ctime,
                    changed_nanoseconds: stat_changed_nanoseconds(&before),
                    content_sha256: None,
                });
            }
            if file_type != libc::S_IFREG {
                bail!("review worktree Git backlink has an unsupported file type");
            }
            if before.st_nlink != 1 {
                bail!("review worktree Git backlink link count is unsafe");
            }
            let fd = unsafe {
                libc::openat(
                    self.root.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("failed to open review worktree Git backlink safely");
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            let opened = fstat_file(&file)?;
            if !same_stat_generation(&before, &opened) {
                bail!("review worktree Git backlink changed before read");
            }
            let length = u64::try_from(opened.st_size)
                .context("review worktree Git backlink has a negative length")?;
            if length > REVIEW_PATH_LIMIT_BYTES as u64 {
                bail!("review worktree Git backlink exceeds its bounded length");
            }
            let mut contents = Vec::with_capacity(usize::try_from(length).unwrap_or_default());
            (&mut file)
                .take((REVIEW_PATH_LIMIT_BYTES as u64).saturating_add(1))
                .read_to_end(&mut contents)
                .context("failed to read review worktree Git backlink")?;
            let after = fstat_file(&file)?;
            if u64::try_from(contents.len()).unwrap_or(u64::MAX) != length
                || !same_stat_generation(&opened, &after)
            {
                bail!("review worktree Git backlink changed during read");
            }
            Ok(GitBacklinkSnapshot {
                kind: "file".to_string(),
                mode: unsigned_to_u32(before.st_mode),
                identity,
                modified_seconds: before.st_mtime,
                modified_nanoseconds: stat_modified_nanoseconds(&before),
                changed_seconds: before.st_ctime,
                changed_nanoseconds: stat_changed_nanoseconds(&before),
                content_sha256: Some(sha256_hex(&contents)),
            })
        }
        #[cfg(not(unix))]
        bail!("exact no-follow review snapshots are unsupported on this platform")
    }

    #[cfg(unix)]
    fn open_parent(&self, path: &Path) -> Result<Option<(File, OsString)>> {
        let components = path
            .components()
            .map(|component| match component {
                std::path::Component::Normal(value) => Ok(value.to_os_string()),
                _ => bail!("review snapshot path is not canonical repository-relative form"),
            })
            .collect::<Result<Vec<_>>>()?;
        let (name, parents) = components
            .split_last()
            .context("review snapshot path has no final component")?;
        let mut directory = self
            .root
            .try_clone()
            .context("failed to clone review worktree descriptor")?;
        for component in parents {
            let component_c = c_string(component)?;
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    component_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(error).context("review snapshot parent component is missing or unsafe");
            }
            directory = unsafe { File::from_raw_fd(fd) };
        }
        Ok(Some((directory, name.clone())))
    }
}

#[cfg(target_os = "linux")]
fn prewalk_review_directory(
    directory: &File,
    relative: &Path,
    device: libc::dev_t,
    depth: usize,
    entry_count: &mut usize,
    total_bytes: &mut u64,
    deadline: Instant,
) -> Result<()> {
    if Instant::now() > deadline {
        bail!("review descriptor prewalk exceeded its bounded deadline");
    }
    if depth > REVIEW_PREWALK_MAX_DEPTH {
        bail!("review descriptor prewalk exceeded its depth limit");
    }
    for name in review_directory_entries(directory, deadline)? {
        if Instant::now() > deadline {
            bail!("review descriptor prewalk exceeded its bounded deadline");
        }
        if relative.as_os_str().is_empty() && name == OsStr::new(".git") {
            continue;
        }
        *entry_count = entry_count.saturating_add(1);
        if *entry_count > REVIEW_SNAPSHOT_ENTRY_LIMIT {
            bail!("review descriptor prewalk exceeded its entry limit");
        }
        let path = relative.join(&name);
        validate_snapshot_relative_path(&path)?;
        let name_c = c_string(&name)?;
        let stat = stat_at_nofollow(directory, &name_c)
            .context("failed to inspect review descriptor prewalk entry")?;
        if stat.st_dev != device || stat.st_uid != unsafe { libc::geteuid() } {
            bail!("review descriptor prewalk crossed an unsafe filesystem or owner boundary");
        }
        match stat.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        name_c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to bind review descriptor prewalk directory");
                }
                let child = unsafe { File::from_raw_fd(fd) };
                let opened = fstat_file(&child)?;
                if !same_stat_generation(&stat, &opened) {
                    bail!("review descriptor prewalk directory changed while binding");
                }
                prewalk_review_directory(
                    &child,
                    &path,
                    device,
                    depth.saturating_add(1),
                    entry_count,
                    total_bytes,
                    deadline,
                )?;
            }
            libc::S_IFREG => {
                if stat.st_nlink != 1 {
                    bail!("review descriptor prewalk found an unsafe hard link");
                }
                let length = u64::try_from(stat.st_size)
                    .context("review descriptor prewalk found a negative file length")?;
                if length > REVIEW_SNAPSHOT_FILE_LIMIT_BYTES {
                    bail!("review descriptor prewalk found an oversized file");
                }
                *total_bytes = total_bytes
                    .checked_add(length)
                    .context("review descriptor prewalk byte total overflow")?;
                if *total_bytes > REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES {
                    bail!("review descriptor prewalk exceeded its total byte limit");
                }
            }
            libc::S_IFLNK => {
                let mut target = vec![0u8; REVIEW_SYMLINK_LIMIT_BYTES.saturating_add(1)];
                let read = unsafe {
                    libc::readlinkat(
                        directory.as_raw_fd(),
                        name_c.as_ptr(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                if read < 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("failed to read review descriptor prewalk symlink");
                }
                let read = usize::try_from(read).context("review symlink length overflow")?;
                if read > REVIEW_SYMLINK_LIMIT_BYTES {
                    bail!("review descriptor prewalk found an oversized symlink target");
                }
                target.truncate(read);
                let after = stat_at_nofollow(directory, &name_c)
                    .context("failed to revalidate review descriptor prewalk symlink")?;
                if !same_stat_generation(&stat, &after) {
                    bail!("review descriptor prewalk symlink changed during inspection");
                }
                validate_internal_symlink_target(&path, &target)?;
            }
            _ => bail!("review descriptor prewalk found an unsupported special file"),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn review_directory_entries(directory: &File, deadline: Instant) -> Result<Vec<OsString>> {
    let duplicated = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicated < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to duplicate review directory descriptor");
    }
    let stream = unsafe { libc::fdopendir(duplicated) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(duplicated);
        }
        return Err(error).context("failed to enumerate review directory descriptor");
    }
    let mut names = Vec::new();
    loop {
        if Instant::now() > deadline {
            unsafe {
                libc::closedir(stream);
            }
            bail!("review descriptor prewalk exceeded its bounded deadline");
        }
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::closedir(stream);
            }
            if error.raw_os_error().unwrap_or_default() != 0 {
                return Err(error).context("failed during review directory enumeration");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        names.push(OsString::from_vec(name.to_vec()));
        if names.len() > REVIEW_SNAPSHOT_ENTRY_LIMIT {
            unsafe {
                libc::closedir(stream);
            }
            bail!("review descriptor prewalk directory exceeded its entry limit");
        }
    }
    names.sort();
    Ok(names)
}

fn validate_snapshot_relative_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!("review snapshot path is not repository-relative");
    }
    if path_bytes(path).len() > REVIEW_PATH_LIMIT_BYTES {
        bail!(
            "review snapshot path exceeds its {} byte limit",
            REVIEW_PATH_LIMIT_BYTES
        );
    }
    let mut components = path.components();
    let Some(std::path::Component::Normal(first)) = components.next() else {
        bail!("review snapshot path is not canonical");
    };
    if first == OsStr::new(".git") {
        bail!("review snapshot path must not enter Git administrative state");
    }
    for component in components {
        if !matches!(component, std::path::Component::Normal(_)) {
            bail!("review snapshot path is not canonical");
        }
    }
    Ok(())
}

fn validate_git_reference_path(reference: &str) -> Result<()> {
    if reference.len() > REVIEW_PATH_LIMIT_BYTES || !reference.starts_with("refs/") {
        bail!("review HEAD reference path is not canonical");
    }
    validate_snapshot_relative_path(Path::new(reference))
        .context("review HEAD reference path is not canonical")
}

fn snapshot_regular_entry_digest(
    reader: &ReviewTreeReader,
    path: &Path,
    total_content_bytes: &mut u64,
    max_bytes: u64,
    required: bool,
    label: &str,
) -> Result<Option<String>> {
    match reader.snapshot_entry(path, total_content_bytes)? {
        SnapshotTreeEntry::Missing if required => bail!("{label} is missing"),
        SnapshotTreeEntry::Missing => Ok(None),
        entry @ SnapshotTreeEntry::Regular { length, .. } => {
            if length > max_bytes {
                bail!("{label} exceeds its bounded size");
            }
            let mut canonical = Vec::new();
            entry.append_canonical(&mut canonical);
            Ok(Some(sha256_hex(&canonical)))
        }
        SnapshotTreeEntry::Symlink { .. } => {
            bail!("{label} must be a regular no-follow file")
        }
    }
}

fn append_snapshot_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).context("review snapshot field length overflow")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

#[cfg(unix)]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf> {
    if bytes.contains(&0) {
        bail!("review Git path contains a NUL byte");
    }
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(not(unix))]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf> {
    let path = std::str::from_utf8(bytes).context("review Git path is not valid UTF-8")?;
    Ok(PathBuf::from(path))
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    match path.to_str() {
        Some(value) => value.as_bytes().to_vec(),
        None => Vec::new(),
    }
}

#[cfg(unix)]
fn c_string(value: &OsStr) -> Result<std::ffi::CString> {
    std::ffi::CString::new(value.as_bytes()).context("review path contains a NUL byte")
}

#[cfg(unix)]
fn stat_at_nofollow(directory: &File, name: &std::ffi::CStr) -> std::io::Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stat)
}

#[cfg(unix)]
fn fstat_file(file: &File) -> Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect review snapshot file descriptor");
    }
    Ok(stat)
}

#[cfg(unix)]
fn file_identity_from_stat(stat: &libc::stat) -> FileIdentity {
    FileIdentity {
        device: device_id_to_u64(stat.st_dev),
        file: unsigned_to_u64(stat.st_ino),
    }
}

#[cfg(unix)]
fn file_identity_from_metadata(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    }
}

#[cfg(unix)]
fn same_stat_generation(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_uid == right.st_uid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && stat_modified_nanoseconds(left) == stat_modified_nanoseconds(right)
        && left.st_ctime == right.st_ctime
        && stat_changed_nanoseconds(left) == stat_changed_nanoseconds(right)
}

#[cfg(target_os = "linux")]
fn stat_modified_nanoseconds(stat: &libc::stat) -> i64 {
    stat.st_mtime_nsec
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_modified_nanoseconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(target_os = "linux")]
fn stat_changed_nanoseconds(stat: &libc::stat) -> i64 {
    stat.st_ctime_nsec
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_changed_nanoseconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(unix)]
fn validate_snapshot_entry_owner_and_links(stat: &libc::stat) -> Result<()> {
    if stat.st_uid != unsafe { libc::geteuid() } {
        bail!("review worktree entry is not owned by the current user");
    }
    if stat.st_nlink != 1 {
        bail!("review worktree entry must have exactly one hard link");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_internal_symlink_target(path: &Path, target: &[u8]) -> Result<()> {
    resolve_internal_symlink_target(path, target).map(|_| ())
}

#[cfg(unix)]
fn resolve_internal_symlink_target(path: &Path, target: &[u8]) -> Result<PathBuf> {
    if target.is_empty() {
        bail!("review worktree symlink target cannot be empty");
    }
    let target_path = PathBuf::from(OsString::from_vec(target.to_vec()));
    if target_path.is_absolute() {
        bail!("review worktree symlink must not target an external absolute path");
    }
    let mut resolved = Vec::new();
    for component in path.parent().unwrap_or_else(|| Path::new("")).components() {
        let std::path::Component::Normal(value) = component else {
            bail!("review worktree symlink parent is not canonical");
        };
        resolved.push(value.to_os_string());
    }
    for component in target_path.components() {
        match component {
            std::path::Component::Normal(value) => resolved.push(value.to_os_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if resolved.pop().is_none() {
                    bail!("review worktree symlink escapes the repository root");
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                bail!("review worktree symlink escapes the repository root")
            }
        }
    }
    if resolved
        .first()
        .is_some_and(|component| component == ".git")
    {
        bail!("review worktree symlink must not enter Git administrative state");
    }
    Ok(resolved.into_iter().collect())
}

enum ParsedExternalReview {
    Accepted(Box<ReviewReport>),
    RejectedSensitive,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewReportWire {
    version: u32,
    status: ReviewReportStatus,
    success: bool,
    target: String,
    reviewer: ExternalReviewerIdentityWire,
    attempt: usize,
    request_binding: String,
    findings: Vec<ExternalReviewFindingWire>,
    blocking_finding_count: usize,
    changed_paths: Vec<PathBuf>,
    diff_source: String,
    ci_reaction_supported: bool,
    ci_reaction: String,
    #[serde(default)]
    diagnostics: Option<ExternalReviewDiagnosticsWire>,
    next_action: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewerIdentityWire {
    mode: String,
    reviewer_id: String,
    model: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewFindingWire {
    severity: String,
    #[serde(default)]
    path: Option<PathBuf>,
    summary: String,
    suggested_fix: String,
    blocking: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewDiagnosticsWire {
    timed_out: bool,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    exit_code: Option<i32>,
    stdout: ExternalReviewOutputWire,
    stderr: ExternalReviewOutputWire,
    #[serde(default)]
    process_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalReviewOutputWire {
    text: String,
    truncated: bool,
}

fn parse_external_review_report(
    bytes: &[u8],
    options: &ReviewPrOptions,
    expected_reviewer: &ReviewerIdentity,
    expected_request_binding: &str,
) -> Result<ParsedExternalReview> {
    if bytes.len() > REVIEW_JSON_LIMIT_BYTES {
        bail!(
            "external reviewer JSON exceeds its {} byte limit",
            REVIEW_JSON_LIMIT_BYTES
        );
    }
    let text = std::str::from_utf8(bytes)
        .context("external reviewer command output must be strict UTF-8 JSON")?;
    let wire: ExternalReviewReportWire = serde_json::from_str(text)
        .context("external reviewer command must emit a strict review report JSON object")?;

    if wire.version != REVIEW_SCHEMA_VERSION {
        bail!("external reviewer report version is unsupported");
    }
    if wire.target != options.target {
        bail!("external reviewer report target does not match the requested target");
    }
    if wire.attempt != options.attempt {
        bail!("external reviewer report attempt does not match the requested attempt");
    }
    if wire.changed_paths != options.changed_paths {
        bail!("external reviewer report changed_paths do not exactly match the review input");
    }
    if wire.changed_paths.len() > REVIEW_CHANGED_PATH_LIMIT {
        bail!("external reviewer report changed_paths exceeds its item limit");
    }
    for path in &wire.changed_paths {
        validate_repo_relative_path(path, "external reviewer changed path")?;
    }
    if wire.findings.len() > REVIEW_FINDING_LIMIT {
        bail!(
            "external reviewer report exceeds its {} finding limit",
            REVIEW_FINDING_LIMIT
        );
    }
    if wire.request_binding != expected_request_binding {
        bail!("external reviewer request_binding does not match the bound review request");
    }
    if wire.reviewer.mode != "external_command"
        || wire.reviewer.reviewer_id != expected_reviewer.reviewer_id
        || wire.reviewer.model != expected_reviewer.model
    {
        bail!("external reviewer identity does not match the parent-bound reviewer");
    }
    if wire.ci_reaction_supported || wire.ci_reaction != "unsupported" {
        bail!("external reviewer report must preserve unsupported CI reaction semantics");
    }
    let expected_diff_source = if options.diff_summary.is_some() {
        "sanitized_merge_candidate_summary"
    } else {
        "pr_target_only"
    };
    if wire.diff_source != expected_diff_source {
        bail!("external reviewer report diff_source does not match the review input");
    }

    let mut sensitive = false;
    sensitive |= external_text_is_sensitive(
        &wire.reviewer.reviewer_id,
        "external reviewer id",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    sensitive |= external_text_is_sensitive(
        &wire.reviewer.model,
        "external reviewer model",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    sensitive |= external_text_is_sensitive(
        &wire.diff_source,
        "external reviewer diff_source",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    sensitive |= external_text_is_sensitive(
        &wire.ci_reaction,
        "external reviewer ci_reaction",
        REVIEW_SHORT_TEXT_LIMIT_BYTES,
        false,
    )?;
    sensitive |= external_text_is_sensitive(
        &wire.next_action,
        "external reviewer next_action",
        REVIEW_LONG_TEXT_LIMIT_BYTES,
        false,
    )?;

    let mut findings = Vec::with_capacity(wire.findings.len());
    for finding in wire.findings {
        if let Some(path) = &finding.path {
            if validate_repo_relative_path(path, "external reviewer finding path").is_err() {
                sensitive = true;
            }
        }
        sensitive |= external_text_is_sensitive(
            &finding.severity,
            "external reviewer finding severity",
            REVIEW_SHORT_TEXT_LIMIT_BYTES,
            false,
        )?;
        let severity_requires_blocking = validate_review_severity(&finding.severity)?;
        if severity_requires_blocking && !finding.blocking {
            bail!("external reviewer finding severity and blocking flag are inconsistent");
        }
        sensitive |= external_text_is_sensitive(
            &finding.summary,
            "external reviewer finding summary",
            REVIEW_LONG_TEXT_LIMIT_BYTES,
            false,
        )?;
        sensitive |= external_text_is_sensitive(
            &finding.suggested_fix,
            "external reviewer finding suggested_fix",
            REVIEW_LONG_TEXT_LIMIT_BYTES,
            false,
        )?;
        findings.push(ReviewFinding {
            severity: finding.severity,
            path: finding.path,
            summary: finding.summary,
            suggested_fix: finding.suggested_fix,
            blocking: finding.blocking,
        });
    }
    if let Some(diagnostics) = &wire.diagnostics {
        if diagnostics
            .timeout_seconds
            .is_some_and(|timeout| timeout == 0 || timeout > REVIEW_TIMEOUT_LIMIT_SECONDS)
        {
            bail!("external reviewer diagnostics timeout_seconds is out of bounds");
        }
        sensitive |= external_text_is_sensitive(
            &diagnostics.stdout.text,
            "external reviewer diagnostics stdout",
            REVIEW_OUTPUT_LIMIT,
            true,
        )?;
        sensitive |= external_text_is_sensitive(
            &diagnostics.stderr.text,
            "external reviewer diagnostics stderr",
            REVIEW_OUTPUT_LIMIT,
            true,
        )?;
        if let Some(process_error) = &diagnostics.process_error {
            sensitive |= external_text_is_sensitive(
                process_error,
                "external reviewer diagnostics process_error",
                REVIEW_LONG_TEXT_LIMIT_BYTES,
                true,
            )?;
        }
        let _ = (
            diagnostics.timed_out,
            diagnostics.exit_code,
            diagnostics.stdout.truncated,
            diagnostics.stderr.truncated,
        );
    }

    let blocking_count = findings.iter().filter(|finding| finding.blocking).count();
    if wire.blocking_finding_count != blocking_count {
        bail!("external reviewer blocking_finding_count is inconsistent with findings");
    }
    match wire.status {
        ReviewReportStatus::Passed if wire.success && blocking_count == 0 => {}
        ReviewReportStatus::Blocked | ReviewReportStatus::Failed
            if !wire.success && blocking_count > 0 => {}
        _ => bail!("external reviewer status, success, and blocking findings are inconsistent"),
    }

    if sensitive {
        return Ok(ParsedExternalReview::RejectedSensitive);
    }
    Ok(ParsedExternalReview::Accepted(Box::new(ReviewReport {
        version: wire.version,
        status: wire.status,
        success: wire.success,
        target: wire.target,
        reviewer: ReviewerIdentity {
            mode: ReviewerMode::ExternalCommand,
            reviewer_id: wire.reviewer.reviewer_id,
            model: wire.reviewer.model,
        },
        attempt: wire.attempt,
        request_binding: wire.request_binding,
        findings,
        blocking_finding_count: wire.blocking_finding_count,
        changed_paths: wire.changed_paths,
        diff_source: wire.diff_source,
        ci_reaction_supported: wire.ci_reaction_supported,
        ci_reaction: wire.ci_reaction,
        diagnostics: None,
        next_action: wire.next_action,
    })))
}

fn external_text_is_sensitive(
    value: &str,
    label: &str,
    max_bytes: usize,
    allow_newlines: bool,
) -> Result<bool> {
    if value.len() > max_bytes {
        bail!("{label} exceeds its {max_bytes} byte limit");
    }
    if value.is_empty() && !label.contains("diagnostics") {
        bail!("{label} cannot be empty");
    }
    let contains_control = value.chars().any(|character| {
        character.is_control() && !(allow_newlines && matches!(character, '\n' | '\r' | '\t'))
    });
    Ok(contains_control
        || contains_private_key_material(value)
        || Redactor::new().redact(value).summary.total_replacements > 0
        || contains_external_absolute_path(value))
}

fn contains_private_key_material(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    upper.contains("PRIVATE KEY") && (upper.contains("-----BEGIN") || upper.contains("BEGIN "))
}

fn contains_external_absolute_path(text: &str) -> bool {
    text.split(|character: char| {
        character.is_whitespace()
            || character == char::from(96)
            || matches!(
                character,
                '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
    .map(|token| token.trim_end_matches([':', '.']))
    .filter(|token| !token.is_empty())
    .any(|token| {
        token.starts_with('/')
            || token.starts_with("\\\\")
            || token
                .as_bytes()
                .get(1)
                .is_some_and(|separator| *separator == b':')
                && token
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
    })
}

fn accepted_external_diagnostics(
    mut diagnostics: ReviewCommandDiagnostics,
) -> ReviewCommandDiagnostics {
    diagnostics.stdout = ReviewOutputSummary {
        text: "<validated:external-review-report>".to_string(),
        truncated: false,
    };
    diagnostics
}

fn redact_untrusted_report_diagnostics(
    mut diagnostics: ReviewCommandDiagnostics,
) -> ReviewCommandDiagnostics {
    diagnostics.stdout = ReviewOutputSummary {
        text: "<redacted:unsafe-external-review-report>".to_string(),
        truncated: true,
    };
    diagnostics.stderr = ReviewOutputSummary {
        text: "<redacted:unsafe-external-review-diagnostics>".to_string(),
        truncated: true,
    };
    if diagnostics.process_error.is_some() {
        diagnostics.process_error = Some("<redacted:unsafe-process-diagnostic>".to_string());
    }
    diagnostics
}

fn sandbox_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "PATH".to_string(),
            "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
        ),
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
    ])
}

fn failed_external_review(
    reviewer: &ReviewerIdentity,
    options: ReviewPrOptions,
    request_binding: &str,
    reason: &str,
    diagnostics: ReviewCommandDiagnostics,
) -> ReviewReport {
    ReviewReport {
        version: REVIEW_SCHEMA_VERSION,
        status: ReviewReportStatus::Failed,
        success: false,
        target: options.target,
        reviewer: reviewer.clone(),
        attempt: options.attempt,
        request_binding: request_binding.to_string(),
        findings: vec![ReviewFinding {
            severity: "error".to_string(),
            path: options.changed_paths.first().cloned(),
            summary: reason.to_string(),
            suggested_fix: "inspect reviewer diagnostics and rerun after fixing the command"
                .to_string(),
            blocking: true,
        }],
        blocking_finding_count: 1,
        changed_paths: options.changed_paths,
        diff_source: if options.diff_summary.is_some() {
            "sanitized_merge_candidate_summary".to_string()
        } else {
            "pr_target_only".to_string()
        },
        ci_reaction_supported: false,
        ci_reaction: "unsupported".to_string(),
        diagnostics: Some(diagnostics),
        next_action: "repair or rerun the external reviewer command before proceeding".to_string(),
    }
}

fn diagnostics_from_output(
    repo: &Path,
    output: &ProcessOutput,
    timeout_seconds: Option<u64>,
) -> ReviewCommandDiagnostics {
    ReviewCommandDiagnostics {
        timed_out: output.timed_out,
        timeout_seconds,
        exit_code: output.status.and_then(|status| status.code()),
        stdout: sanitize_review_output(repo, output.stdout.as_bytes()),
        stderr: sanitize_review_output(repo, output.stderr.as_bytes()),
        process_error: output
            .process_error
            .as_deref()
            .map(|error| sanitize_review_output(repo, error.as_bytes()).text),
    }
}

fn sanitize_review_output(repo: &Path, output: &[u8]) -> ReviewOutputSummary {
    let text = String::from_utf8_lossy(output);
    if contains_private_key_material(&text) {
        return ReviewOutputSummary {
            text: "<redacted:private-key-material>".to_string(),
            truncated: true,
        };
    }
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return ReviewOutputSummary {
            text: "<redacted:control-character-diagnostic>".to_string(),
            truncated: true,
        };
    }
    let mut sanitized = Redactor::new().redact(&text).text;
    redact_known_repository_paths(repo, &mut sanitized);
    if contains_external_absolute_path(&sanitized) {
        sanitized = "<redacted:absolute-path-diagnostic>".to_string();
    }
    summarize_review_text(&redact_token_like_words(&sanitized), REVIEW_OUTPUT_LIMIT)
}

fn review_diagnostic_contains_unsafe_evidence(repo: &Path, output: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(output) else {
        return true;
    };
    if contains_private_key_material(text)
        || text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        || Redactor::new().redact(text).summary.total_replacements > 0
    {
        return true;
    }
    let mut sanitized = text.to_string();
    redact_known_repository_paths(repo, &mut sanitized);
    contains_external_absolute_path(&sanitized) || contains_token_like_word(&sanitized)
}

fn redact_known_repository_paths(repo: &Path, text: &mut String) {
    if let Ok(canonical_repo) = repo.canonicalize() {
        replace_nonempty_path(text, &canonical_repo, ".");
        if let Some(parent) = canonical_repo.parent() {
            replace_nonempty_path(text, parent, "<repo-parent>");
        }
    }
    replace_nonempty_path(text, repo, ".");
    if let Some(parent) = repo.parent() {
        replace_nonempty_path(text, parent, "<repo-parent>");
    }
}

fn replace_nonempty_path(text: &mut String, path: &Path, replacement: &str) {
    let path = path.display().to_string();
    if !path.is_empty() {
        *text = text.replace(&path, replacement);
    }
}

fn summarize_review_text(text: &str, limit: usize) -> ReviewOutputSummary {
    let mut chars = text.chars();
    let value = chars.by_ref().take(limit).collect::<String>();
    ReviewOutputSummary {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn redact_token_like_words(text: &str) -> String {
    let mut output = String::new();
    let mut token = String::new();
    for character in text.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
            token.push(character);
        } else {
            push_redacted_token(&mut output, &token);
            token.clear();
            output.push(character);
        }
    }
    push_redacted_token(&mut output, &token);
    output
}

fn contains_token_like_word(text: &str) -> bool {
    text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.'))
    })
    .any(|token| {
        token.len() >= 32
            && token
                .chars()
                .any(|character| character.is_ascii_alphabetic())
            && token.chars().any(|character| character.is_ascii_digit())
    })
}

fn push_redacted_token(output: &mut String, token: &str) {
    if token.len() >= 32
        && token.chars().any(|c| c.is_ascii_alphabetic())
        && token.chars().any(|c| c.is_ascii_digit())
    {
        output.push_str("<redacted:token>");
    } else {
        output.push_str(token);
    }
}

fn fake_finding(options: &ReviewPrOptions) -> ReviewFinding {
    if let Some(template) = &options.reviewer.finding {
        return ReviewFinding {
            severity: template.severity.clone(),
            path: template
                .path
                .clone()
                .or_else(|| options.changed_paths.first().cloned()),
            summary: template.summary.clone(),
            suggested_fix: template.suggested_fix.clone(),
            blocking: true,
        };
    }
    ReviewFinding {
        severity: "error".to_string(),
        path: options.changed_paths.first().cloned(),
        summary: format!(
            "deterministic fake blocker for review attempt {}",
            options.attempt
        ),
        suggested_fix: "rerun the worker with the review finding as repair context".to_string(),
        blocking: true,
    }
}

#[derive(Serialize)]
struct ExternalReviewInput<'a> {
    version: u32,
    target: &'a str,
    attempt: usize,
    changed_paths: &'a [PathBuf],
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_summary: Option<&'a str>,
    reviewer: &'a ReviewerIdentity,
    request_binding: &'a str,
}

#[derive(Serialize)]
struct ExternalReviewRequestBindingPayload<'a> {
    version: u32,
    target: &'a str,
    attempt: usize,
    changed_paths: &'a [PathBuf],
    diff_summary: Option<&'a str>,
    reviewer: &'a ReviewerIdentity,
    program: &'a MaterializedReviewerBinding,
    args: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    sanitized_view_binding: Option<&'a str>,
    effective_timeout_seconds: u64,
    sandbox_policy_version: u32,
    repository_snapshot: &'a ReviewRepoSnapshot,
}

#[derive(Serialize)]
struct ExternalReviewerLaunchBinding<'a> {
    version: u32,
    program: &'a MaterializedReviewerBinding,
    args: &'a [String],
}

fn bound_external_reviewer_identity(
    program: &MaterializedReviewerBinding,
    args: &[String],
) -> Result<ReviewerIdentity> {
    let launch = serde_json::to_vec(&ExternalReviewerLaunchBinding {
        version: REVIEW_SCHEMA_VERSION,
        program,
        args,
    })
    .context("failed to serialize external reviewer launch identity")?;
    let command_binding = domain_sha256(EXTERNAL_REVIEWER_BINDING_DOMAIN, &launch);
    Ok(ReviewerIdentity {
        mode: ReviewerMode::ExternalCommand,
        reviewer_id: format!("external-program-{}", &command_binding[..32]),
        model: "parent-bound-direct-program-v1".to_string(),
    })
}

fn external_review_request_binding(
    options: &ReviewPrOptions,
    snapshot: &ReviewRepoSnapshot,
    reviewer: &ReviewerIdentity,
    program: &MaterializedReviewerBinding,
    sanitized_view_binding: Option<&str>,
    effective_timeout_seconds: u64,
) -> Result<String> {
    let payload = serde_json::to_vec(&ExternalReviewRequestBindingPayload {
        version: REVIEW_SCHEMA_VERSION,
        target: &options.target,
        attempt: options.attempt,
        changed_paths: &options.changed_paths,
        diff_summary: options.diff_summary.as_deref(),
        reviewer,
        program,
        args: &options.reviewer.args,
        sanitized_view_binding,
        effective_timeout_seconds,
        sandbox_policy_version: REVIEW_SANDBOX_POLICY_VERSION,
        repository_snapshot: snapshot,
    })
    .context("failed to serialize external review request binding")?;
    Ok(domain_sha256(EXTERNAL_REVIEW_REQUEST_DOMAIN, &payload))
}

fn fake_review_request_binding(options: &ReviewPrOptions) -> String {
    let mut payload = Vec::new();
    payload.push(REVIEW_SCHEMA_VERSION as u8);
    payload.push(1);
    payload.extend_from_slice(
        &u64::try_from(options.attempt)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    payload.push(2);
    append_binding_field(&mut payload, options.target.as_bytes());
    payload.push(3);
    payload.extend_from_slice(
        &u64::try_from(options.changed_paths.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for path in &options.changed_paths {
        payload.push(4);
        append_binding_field(&mut payload, &path_bytes(path));
    }
    match &options.diff_summary {
        Some(diff_summary) => {
            payload.push(5);
            append_binding_field(&mut payload, diff_summary.as_bytes());
        }
        None => payload.push(6),
    }
    payload.push(7);
    payload.extend_from_slice(
        &u64::try_from(options.reviewer.blocking_attempts)
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    match &options.reviewer.finding {
        Some(finding) => {
            payload.push(8);
            append_binding_field(&mut payload, finding.severity.as_bytes());
            match &finding.path {
                Some(path) => {
                    payload.push(9);
                    append_binding_field(&mut payload, &path_bytes(path));
                }
                None => payload.push(10),
            }
            append_binding_field(&mut payload, finding.summary.as_bytes());
            append_binding_field(&mut payload, finding.suggested_fix.as_bytes());
        }
        None => payload.push(11),
    }
    domain_sha256(FAKE_REVIEW_REQUEST_DOMAIN, &payload)
}

fn append_binding_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(value);
}

fn domain_sha256(domain: &[u8], payload: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len().saturating_add(payload.len()));
    input.extend_from_slice(domain);
    input.extend_from_slice(payload);
    sha256_hex(&input)
}

fn review_schema_version() -> u32 {
    REVIEW_SCHEMA_VERSION
}

fn deserialize_review_schema_version<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != REVIEW_SCHEMA_VERSION {
        return Err(D::Error::custom(
            "review wire version is unsupported; expected version 1",
        ));
    }
    Ok(version)
}

fn sha256_hex(input: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in sha256_bytes(input) {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let bit_len = u64::try_from(input.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let mut hash = INITIAL;
    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let small_zero = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let small_one = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(small_zero)
                .wrapping_add(words[index - 7])
                .wrapping_add(small_one);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = hash;
        for index in 0..64 {
            let sum_one = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp_one = h
                .wrapping_add(sum_one)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(words[index]);
            let sum_zero = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp_two = sum_zero.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp_one);
            d = c;
            c = b;
            b = a;
            a = temp_one.wrapping_add(temp_two);
        }
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }
    let mut output = [0u8; 32];
    for (index, word) in hash.iter().enumerate() {
        let offset = index.saturating_mul(4);
        output[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn default_review_severity() -> String {
    "error".to_string()
}

fn default_review_summary() -> String {
    "deterministic fake blocker".to_string()
}

fn default_suggested_fix() -> String {
    "repair the reported issue".to_string()
}

pub fn target_label(target: &str) -> String {
    let target = target.trim();
    if target.is_empty() {
        "unknown".to_string()
    } else {
        target.to_string()
    }
}

pub fn target_from_pr_arg(arg: &str) -> Result<String> {
    let target = arg.trim();
    if target.is_empty() {
        bail!("pull request target cannot be empty");
    }
    if target.chars().all(|c| c.is_ascii_digit()) {
        return Ok(format!("#{target}"));
    }
    Ok(target.to_string())
}

pub fn diff_summary_from_text(text: impl AsRef<str>) -> Option<String> {
    let text = text.as_ref().trim();
    if text.is_empty() {
        None
    } else {
        Some(text.chars().take(32 * 1024).collect())
    }
}

pub fn normalize_changed_paths(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

pub fn repo_path_for_review(repo: impl AsRef<Path>) -> PathBuf {
    repo.as_ref().to_path_buf()
}
