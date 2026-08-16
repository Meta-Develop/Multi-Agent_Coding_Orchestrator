use super::*;

#[cfg(unix)]
pub(super) fn worktree_control_identity_from_metadata(
    metadata: &fs::Metadata,
) -> WorktreeControlIdentity {
    WorktreeControlIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        file_type: metadata.mode() & crate::safe_state::unsigned_to_u32(libc::S_IFMT),
    }
}

#[cfg(unix)]
pub(super) fn direct_worktree_control_identity(
    workspace: &fs::File,
    relative: &str,
) -> Result<WorktreeControlIdentity> {
    let name = std::ffi::CString::new(relative)
        .with_context(|| format!("mandatory worktree control name is invalid: {relative}"))?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `workspace` is a held directory descriptor, `name` is NUL-terminated, and `stat`
    // points to writable storage. `AT_SYMLINK_NOFOLLOW` ensures a direct-child symlink is observed
    // as a symlink rather than followed.
    if unsafe {
        libc::fstatat(
            workspace.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to inspect mandatory worktree control {relative}"));
    }
    // SAFETY: `fstatat` succeeded and initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    Ok(WorktreeControlIdentity {
        device: crate::safe_state::device_id_to_u64(stat.st_dev),
        inode: crate::safe_state::unsigned_to_u64(stat.st_ino),
        file_type: crate::safe_state::unsigned_to_u32(stat.st_mode & libc::S_IFMT),
    })
}

#[cfg(unix)]
fn open_direct_worktree_directory(
    workspace: &fs::File,
    relative: &'static str,
) -> Result<fs::File> {
    let name = std::ffi::CString::new(relative)
        .with_context(|| format!("mandatory worktree control name is invalid: {relative}"))?;
    let open = || {
        // SAFETY: `workspace` is a held directory descriptor and `name` is NUL-terminated.
        let descriptor = unsafe {
            libc::openat(
                workspace.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            // SAFETY: `openat` returned a new owned descriptor.
            Ok(unsafe { fs::File::from_raw_fd(descriptor) })
        }
    };
    match open() {
        Ok(directory) => Ok(directory),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // SAFETY: `workspace` is a held directory descriptor and `name` is NUL-terminated.
            let result = unsafe { libc::mkdirat(workspace.as_raw_fd(), name.as_ptr(), 0o700) };
            if result != 0 {
                let mkdir_error = std::io::Error::last_os_error();
                if mkdir_error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(mkdir_error).with_context(|| {
                        format!("failed to provision mandatory worktree control {relative}")
                    });
                }
            }
            open().with_context(|| {
                format!("mandatory worktree control is not a non-symlink directory: {relative}")
            })
        }
        Err(error) => Err(error).with_context(|| {
            format!("mandatory worktree control is not a non-symlink directory: {relative}")
        }),
    }
}

#[cfg(unix)]
fn ensure_registered_worktree_guard_if_repository(workspace_path: &Path) -> Result<()> {
    match crate::git_repository::open(workspace_path) {
        Ok(repository) => {
            drop(repository);
            crate::worktree::ensure_registered_managed_worktree_guard(workspace_path)
                .context("failed to install advisory managed-worktree Git guard")?;
        }
        Err(error)
            if error.code() == git2::ErrorCode::NotFound
                && allow_synthetic_unresolved_git_marker(workspace_path)? =>
        {
            // Mandatory-control unit fixtures deliberately use a fully
            // unresolved absolute marker. A marker whose target, worktrees
            // parent, or common-directory candidate exists is plausibly a
            // damaged real lane and must not receive this exception.
        }
        Err(error) => {
            return Err(error).context(
                "failed to open linked worktree repository for advisory Git guard installation",
            );
        }
    }
    Ok(())
}

#[cfg(all(unix, test))]
fn allow_synthetic_unresolved_git_marker(workspace_path: &Path) -> Result<bool> {
    unresolved_git_marker_is_synthetic(workspace_path)
}

#[cfg(all(unix, not(test)))]
fn allow_synthetic_unresolved_git_marker(_workspace_path: &Path) -> Result<bool> {
    // Production supervisor bootstrap never treats a missing Git ancestry as
    // synthetic. A damaged or substituted real lane therefore fails closed.
    Ok(false)
}

#[cfg(all(unix, test))]
fn unresolved_git_marker_is_synthetic(workspace_path: &Path) -> Result<bool> {
    let marker_path = workspace_path.join(".git");
    let bytes = BoundedRegularReader::read_tree_no_follow(&marker_path, 4096)
        .context("failed to inspect unresolved linked-worktree marker")?;
    let line = bytes
        .strip_suffix(b"\n")
        .and_then(|line| line.strip_prefix(b"gitdir: "))
        .context("unresolved linked-worktree marker is malformed")?;
    if line.is_empty() || line.contains(&b'\n') || line.contains(&b'\r') {
        bail!("unresolved linked-worktree marker is malformed");
    }
    let text =
        std::str::from_utf8(line).context("unresolved linked-worktree marker is not UTF-8")?;
    let target = Path::new(text);
    if !target.is_absolute() {
        return Ok(false);
    }
    let parent_exists = target.parent().is_some_and(Path::exists);
    let common_candidate_exists = target
        .parent()
        .and_then(Path::parent)
        .is_some_and(Path::exists);
    Ok(!target.exists() && !parent_exists && !common_candidate_exists)
}

#[cfg(unix)]
pub(super) fn provision_mandatory_worktree_controls(
    workspace_path: &Path,
) -> Result<MandatoryWorktreeControls> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let workspace = options
        .open(workspace_path)
        .context("failed to bind managed worktree root for control bootstrap")?;
    let path_metadata = fs::symlink_metadata(workspace_path)
        .context("failed to inspect managed worktree root for control bootstrap")?;
    let workspace_identity = worktree_control_identity_from_metadata(&workspace.metadata()?);
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || worktree_control_identity_from_metadata(&path_metadata) != workspace_identity
    {
        bail!("managed worktree root is not an identity-stable non-symlink directory");
    }

    let git_identity = direct_worktree_control_identity(&workspace, ".git")
        .context("linked worktree .git marker must already exist")?;
    if git_identity.file_type != crate::safe_state::unsigned_to_u32(libc::S_IFREG)
        && git_identity.file_type != crate::safe_state::unsigned_to_u32(libc::S_IFDIR)
    {
        bail!("linked worktree .git marker must be a regular file or directory");
    }

    let mut directories = Vec::with_capacity(MANDATORY_WORKTREE_DIRECTORY_CONTROLS.len());
    for &relative in MANDATORY_WORKTREE_DIRECTORY_CONTROLS {
        let directory = open_direct_worktree_directory(&workspace, relative)?;
        let identity = worktree_control_identity_from_metadata(&directory.metadata()?);
        if identity.file_type != crate::safe_state::unsigned_to_u32(libc::S_IFDIR) {
            bail!("mandatory worktree control is not a directory: {relative}");
        }
        if direct_worktree_control_identity(&workspace, relative)? != identity {
            bail!("mandatory worktree control identity changed while provisioning: {relative}");
        }
        directories.push(HeldWorktreeDirectoryControl {
            relative,
            directory,
            identity,
        });
    }
    let controls = MandatoryWorktreeControls {
        workspace_path: workspace_path.to_path_buf(),
        workspace,
        workspace_identity,
        git_identity,
        directories,
    };
    controls.revalidate()?;
    // Older registered lanes may predate the creation-time guard. Bootstrap
    // installs it only after every mandatory control is bound and validated;
    // a second validation prevents an unsafe success if the named workspace
    // changes while the advisory guard is being checked. The primary path uses
    // `bind_primary_worktree_controls` and never reaches implicit installation.
    ensure_registered_worktree_guard_if_repository(workspace_path)?;
    controls.revalidate()?;
    Ok(controls)
}

/// Binds the existing primary checkout without provisioning any control
/// directory. Primary-target execution must not create `.agents`, `.codex`, or
/// other out-of-scope paths as a side effect of supervisor bootstrap.
#[cfg(unix)]
pub(super) fn bind_primary_worktree_controls(
    workspace_path: &Path,
) -> Result<MandatoryWorktreeControls> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let workspace = options
        .open(workspace_path)
        .context("failed to bind primary worktree root")?;
    let path_metadata =
        fs::symlink_metadata(workspace_path).context("failed to inspect primary worktree root")?;
    let workspace_identity = worktree_control_identity_from_metadata(&workspace.metadata()?);
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || worktree_control_identity_from_metadata(&path_metadata) != workspace_identity
    {
        bail!("primary worktree root is not an identity-stable non-symlink directory");
    }
    let git_identity = direct_worktree_control_identity(&workspace, ".git")
        .context("primary worktree .git metadata must already exist")?;
    if git_identity.file_type != crate::safe_state::unsigned_to_u32(libc::S_IFREG)
        && git_identity.file_type != crate::safe_state::unsigned_to_u32(libc::S_IFDIR)
    {
        bail!("primary worktree .git marker must be a regular file or directory");
    }
    let controls = MandatoryWorktreeControls {
        workspace_path: workspace_path.to_path_buf(),
        workspace,
        workspace_identity,
        git_identity,
        directories: Vec::new(),
    };
    controls.revalidate()?;
    Ok(controls)
}

#[cfg(not(unix))]
pub(super) fn bind_primary_worktree_controls(
    _workspace_path: &Path,
) -> Result<MandatoryWorktreeControls> {
    bail!("primary-worktree control binding is unsupported on this platform")
}

#[cfg(not(unix))]
pub(super) fn provision_mandatory_worktree_controls(
    _workspace_path: &Path,
) -> Result<MandatoryWorktreeControls> {
    bail!("mandatory worktree control provisioning is unsupported on this platform")
}

pub(super) fn assignment_worktree_control_exceptions(
    assigned_paths: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let mut exceptions = BTreeSet::new();
    for assigned in assigned_paths {
        let normalized = normalize_repo_relative_path(assigned).with_context(|| {
            format!(
                "assigned path cannot be used for a worktree control exception: {}",
                assigned.display()
            )
        })?;
        if normalized != *assigned {
            bail!(
                "assigned path must already be normalized before control exception derivation: {}",
                assigned.display()
            );
        }
        if PERMANENT_WORKTREE_CONTROL_ROOTS
            .iter()
            .any(|root| normalized.starts_with(root))
        {
            bail!(
                "assigned path targets a permanently read-only worktree control: {}",
                normalized.display()
            );
        }
        if normalized == Path::new(".agents") {
            bail!("the .agents policy root cannot be assigned as a writable exception");
        }
        if normalized.starts_with(".agents")
            || POLICY_WORKTREE_CONTROL_FILES
                .iter()
                .any(|policy| normalized == Path::new(policy))
        {
            exceptions.insert(normalized);
        }
    }
    Ok(exceptions.into_iter().collect())
}

pub(super) fn configure_writable_child_command(
    mut command: ExternalAgentCommand,
    assigned_paths: &[PathBuf],
) -> Result<ExternalAgentCommand> {
    if command.workspace_access != WorkspaceAccess::ReadWrite {
        bail!("child orchestrator command must use read-write workspace access");
    }
    if !command.worktree_control_exceptions.is_empty() {
        bail!("child orchestrator command already contains undeclared control exceptions");
    }
    for exception in assignment_worktree_control_exceptions(assigned_paths)? {
        command = command.with_worktree_control_exception(exception);
    }
    Ok(command)
}

pub(super) fn pre_action_review_context(
    options: &SupervisorRunOptions,
    assignment: &OrchestratorAssignment,
    worktree: &Path,
) -> Result<ReviewContext> {
    let claims = assignment
        .assigned_paths
        .iter()
        .map(|path| {
            if worktree.join(path).is_dir() {
                RepoPathRule::subtree(path)
            } else {
                RepoPathRule::exact(path)
            }
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to bind pre-action review claims")?;
    let intent = assignment
        .task
        .as_deref()
        .or(assignment.notes.as_deref())
        .unwrap_or(&assignment.id);
    ReviewContext::new(
        options.run_id.as_str(),
        &assignment.id,
        intent,
        claims,
        std::iter::empty::<RepoPathRule>(),
    )
    .context("failed to construct pre-action review context")
}

pub(super) fn configure_read_only_auditor_command(
    command: ExternalAgentCommand,
) -> Result<ExternalAgentCommand> {
    if !command.worktree_control_exceptions.is_empty() {
        bail!("read-only auditor command may not contain worktree control exceptions");
    }
    Ok(command.with_workspace_access(WorkspaceAccess::ReadOnly))
}
