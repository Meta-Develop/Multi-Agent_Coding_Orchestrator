use super::*;

const PRE_ACTION_INTENT_SUMMARY_MAX_BYTES: usize = 1024;
const PRE_ACTION_INTENT_SUMMARY_FALLBACK: &str = "assigned work";

fn normalize_pre_action_intent_candidate(candidate: &str) -> String {
    let mut normalized = String::with_capacity(candidate.len());
    let mut separator_pending = false;
    for character in candidate.chars() {
        if character.is_whitespace() || character.is_control() {
            separator_pending = !normalized.is_empty();
            continue;
        }

        if separator_pending {
            normalized.push(' ');
            separator_pending = false;
        }
        normalized.push(character);
    }
    normalized
}

fn normalized_pre_action_intent(task: Option<&str>, notes: Option<&str>, id: &str) -> String {
    for candidate in task.into_iter().chain(notes).chain(Some(id)) {
        let normalized = normalize_pre_action_intent_candidate(candidate);
        if !normalized.is_empty() {
            return normalized;
        }
    }
    PRE_ACTION_INTENT_SUMMARY_FALLBACK.to_string()
}

fn bound_pre_action_intent_summary(normalized: &str) -> String {
    let end = normalized
        .char_indices()
        .map(|(index, character)| index.saturating_add(character.len_utf8()))
        .take_while(|end| *end <= PRE_ACTION_INTENT_SUMMARY_MAX_BYTES)
        .last()
        .unwrap_or_default();
    normalized[..end].trim_end_matches(' ').to_string()
}

fn sanitize_pre_action_intent_candidate(candidate: &str) -> String {
    bound_pre_action_intent_summary(&normalize_pre_action_intent_candidate(candidate))
}

fn pre_action_intent_summary(task: Option<&str>, notes: Option<&str>, id: &str) -> String {
    sanitize_pre_action_intent_candidate(&normalized_pre_action_intent(task, notes, id))
}

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
    let normalized_intent = normalized_pre_action_intent(
        assignment.task.as_deref(),
        assignment.notes.as_deref(),
        &assignment.id,
    );
    let intent_summary = if normalized_intent.len() > PRE_ACTION_INTENT_SUMMARY_MAX_BYTES {
        pre_action_intent_summary(
            assignment.task.as_deref(),
            assignment.notes.as_deref(),
            &assignment.id,
        )
    } else {
        normalized_intent
    };
    ReviewContext::new(
        options.run_id.as_str(),
        &assignment.id,
        &intent_summary,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn review_options(run_id: &str) -> SupervisorRunOptions {
        SupervisorRunOptions {
            repo: PathBuf::from("."),
            plan_file: PathBuf::from("unused-plan.json"),
            run_id: RunId::new(run_id).expect("valid review test run id"),
            parent_node: None,
            codex_bin: PathBuf::from("unused-codex"),
            runtime: SupervisorRuntime::Codex,
            allow_dirty_primary: false,
            allow_live_run_collision: false,
            admission_overrides: SupervisorAdmissionConfig::default(),
            budget_overrides: RunBudgetLimits::default(),
            budget_max_duration_seconds: None,
            machine_global_retention: None,
        }
    }

    fn review_assignment(id: &str, task: String) -> OrchestratorAssignment {
        OrchestratorAssignment {
            id: id.to_string(),
            phase: AssignmentPhase::Execution,
            runtime: None,
            role: AgentRole::ChildOrchestrator,
            role_category: None,
            selection_source: None,
            assigned_paths: vec![PathBuf::from("src/pre_action_review.rs")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            task: Some(task),
            worker_assignments: Vec::new(),
            environment_requirements: Vec::new(),
            licensed_breakage: None,
            notes: None,
        }
    }

    #[test]
    fn pre_action_intent_summary_flattens_unicode_whitespace_and_controls() {
        let summary = sanitize_pre_action_intent_candidate(
            "\n  Plan\t多言語\r\nvalidation\u{0085}\u{0000} safely  ",
        );

        assert_eq!(summary, "Plan 多言語 validation safely");
        assert!(!summary.chars().any(char::is_control));
        assert!(summary
            .chars()
            .filter(|character| character.is_whitespace())
            .all(|character| character == ' '));
    }

    #[test]
    fn pre_action_intent_summary_bounds_unicode_on_a_character_boundary() {
        let summary =
            sanitize_pre_action_intent_candidate(&"界".repeat(PRE_ACTION_INTENT_SUMMARY_MAX_BYTES));

        assert!(summary.len() <= PRE_ACTION_INTENT_SUMMARY_MAX_BYTES);
        assert_eq!(
            summary.chars().count(),
            PRE_ACTION_INTENT_SUMMARY_MAX_BYTES / '界'.len_utf8()
        );
        assert!(summary.chars().all(|character| character == '界'));

        let separated = sanitize_pre_action_intent_candidate(&format!(
            "{} 界",
            "x".repeat(PRE_ACTION_INTENT_SUMMARY_MAX_BYTES - 1)
        ));
        assert_eq!(
            separated,
            "x".repeat(PRE_ACTION_INTENT_SUMMARY_MAX_BYTES - 1)
        );
        assert!(!separated.ends_with(' '));
    }

    #[test]
    fn pre_action_intent_summary_uses_non_empty_fallbacks() {
        assert_eq!(
            pre_action_intent_summary(Some("\n\t\u{0000}"), Some("  useful\tnotes "), "child-a"),
            "useful notes"
        );
        assert_eq!(
            pre_action_intent_summary(Some(" \r\n"), Some("\u{0007}"), "child-a"),
            "child-a"
        );
        assert_eq!(
            pre_action_intent_summary(Some("\n"), Some("\t"), "\u{0000}"),
            PRE_ACTION_INTENT_SUMMARY_FALLBACK
        );
    }

    #[test]
    fn pre_action_review_context_bounds_oversized_normalized_task_before_validation() {
        let task = "界".repeat((8 * 1024 / '界'.len_utf8()) + 1);
        assert!(normalize_pre_action_intent_candidate(&task).len() > 8 * 1024);
        let assignment = review_assignment("child-a", task);

        let context = pre_action_review_context(
            &review_options("run-long-intent"),
            &assignment,
            Path::new("."),
        )
        .expect("oversized normalized task must use the bounded intent summary");
        let expected = "界".repeat(PRE_ACTION_INTENT_SUMMARY_MAX_BYTES / '界'.len_utf8());

        assert_eq!(context.intent_summary(), expected);
        assert!(context.intent_summary().len() <= PRE_ACTION_INTENT_SUMMARY_MAX_BYTES);
    }

    #[test]
    fn pre_action_review_context_preserves_typed_non_size_validation_error() {
        let assignment = review_assignment("invalid/owner", "bounded task".to_string());

        let error = pre_action_review_context(
            &review_options("run-invalid-owner"),
            &assignment,
            Path::new("."),
        )
        .expect_err("malformed non-size context data must fail closed");
        let typed = error
            .chain()
            .find_map(|cause| {
                cause.downcast_ref::<crate::pre_action_review::PreActionReviewError>()
            })
            .expect("anyhow chain must preserve the typed pre-action review error");

        assert!(matches!(
            typed,
            crate::pre_action_review::PreActionReviewError::Invalid(message)
                if message.contains("review owner is invalid")
        ));
    }
}
