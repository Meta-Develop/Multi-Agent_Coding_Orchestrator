use super::*;

pub(super) fn primary_worktree_snapshot(
    repo_path: &Path,
    runtime: SupervisorExecutionRuntime,
) -> Result<PrimaryWorktreeSnapshot> {
    let mut visited_gitdirs = BTreeSet::new();
    primary_worktree_snapshot_at_depth(repo_path, 0, &mut visited_gitdirs, runtime)
}

/// Stable within this supervisor schema version and deliberately covers the
/// complete snapshot rather than only HEAD or configured dirty-path policy.
pub(super) fn primary_worktree_snapshot_sha256(
    repo_path: &Path,
    runtime: SupervisorExecutionRuntime,
) -> Result<String> {
    let snapshot = primary_worktree_snapshot(repo_path, runtime)?;
    let framed = format!("maco-primary-worktree-snapshot-v1\n{snapshot:?}");
    Ok(crate::artifacts::state_auth::sha256_hex(framed.as_bytes()))
}

fn primary_worktree_snapshot_at_depth(
    repo_path: &Path,
    depth: usize,
    visited_gitdirs: &mut BTreeSet<PathBuf>,
    runtime: SupervisorExecutionRuntime,
) -> Result<PrimaryWorktreeSnapshot> {
    if depth > MAX_NESTED_REPOSITORY_DEPTH {
        bail!(
            "primary integrity snapshot exceeded the nested-repository safety limit of {} at {}",
            MAX_NESTED_REPOSITORY_DEPTH,
            repo_path.display()
        );
    }
    let repo = Repository::open(repo_path)
        .with_context(|| format!("failed to open repository {}", repo_path.display()))?;
    let gitdir_identity = fs::canonicalize(repo.path()).with_context(|| {
        format!(
            "failed to resolve canonical Git directory identity {}",
            repo.path().display()
        )
    })?;
    if !visited_gitdirs.insert(gitdir_identity.clone()) {
        bail!(
            "primary integrity snapshot detected a nested repository cycle at {} (Git directory {})",
            repo_path.display(),
            gitdir_identity.display()
        );
    }

    let result = (|| {
        let workdir = repo
            .workdir()
            .context("primary integrity snapshot requires a non-bare repository")?
            .to_path_buf();
        let head = primary_head_snapshot(&repo)?;
        let index_storage_before = primary_index_storage_snapshot(&repo, runtime)?;
        let status = primary_status_snapshot(&workdir, runtime)?;
        let index = primary_index_snapshot(&workdir, runtime)?;
        let index_storage = primary_index_storage_snapshot(&repo, runtime)?;
        let inspection_error = (index_storage_before != index_storage).then(|| {
            "primary index storage changed while the Git CLI integrity snapshot was being captured"
                .to_string()
        });

        let gitlink_paths = index
            .iter()
            .filter(|(_, state)| state.mode == GITLINK_MODE)
            .map(|(key, _)| key.path.clone())
            .collect::<BTreeSet<_>>();
        let sparse_directory_paths = index
            .iter()
            .filter(|(_, state)| state.mode == SPARSE_DIRECTORY_MODE)
            .map(|(key, _)| key.path.clone())
            .collect::<BTreeSet<_>>();
        let mut fingerprint_paths = status.keys().cloned().collect::<BTreeSet<_>>();
        fingerprint_paths.extend(
            status
                .values()
                .filter_map(|state| state.original_path.clone()),
        );
        fingerprint_paths.extend(gitlink_paths.iter().cloned());
        fingerprint_paths.extend(sparse_directory_paths.iter().cloned());
        fingerprint_paths.extend(
            index
                .iter()
                .filter(|(_, state)| index_entry_requires_fingerprint(state))
                .map(|(key, _)| key.path.clone()),
        );

        let mut worktree = BTreeMap::new();
        for path in fingerprint_paths {
            let relative_path = repo_relative_path_from_git_bytes(&path);
            let state = primary_path_state(
                &workdir.join(&relative_path),
                gitlink_paths.contains(&path),
                sparse_directory_paths.contains(&path),
                depth,
                visited_gitdirs,
                runtime,
            )
            .with_context(|| {
                format!(
                    "failed to fingerprint primary worktree path {}",
                    relative_path.display()
                )
            })?;
            worktree.insert(path, state);
        }

        Ok(PrimaryWorktreeSnapshot {
            head,
            index,
            index_storage,
            status,
            worktree,
            inspection_error,
        })
    })();
    visited_gitdirs.remove(&gitdir_identity);
    result
}

fn primary_head_snapshot(repo: &Repository) -> Result<PrimaryHeadSnapshot> {
    let detached = repo.head_detached().unwrap_or(false);
    match repo.head() {
        Ok(head) => Ok(PrimaryHeadSnapshot {
            detached,
            reference_name: Some(head.name_bytes().to_vec()),
            symbolic_target: head.symbolic_target_bytes().map(<[u8]>::to_vec),
            target: head.target(),
        }),
        Err(error) if matches!(error.code(), ErrorCode::NotFound | ErrorCode::UnbornBranch) => {
            Ok(PrimaryHeadSnapshot {
                detached,
                reference_name: None,
                symbolic_target: None,
                target: None,
            })
        }
        Err(error) => Err(error).context("failed to inspect primary HEAD/reference"),
    }
}

pub(super) fn primary_status_snapshot(
    workdir: &Path,
    runtime: SupervisorExecutionRuntime,
) -> Result<BTreeMap<Vec<u8>, PrimaryStatusState>> {
    let output = sanitized_git_output(
        workdir,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        runtime,
    )
    .context("failed to run Git CLI primary status snapshot")?;
    if !output.status.success() {
        bail!(
            "Git CLI primary status snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let records = output.stdout.split(|byte| *byte == 0).collect::<Vec<_>>();
    let mut entries = BTreeMap::new();
    let mut index = 0usize;
    while index < records.len() {
        let record = records[index];
        index = index.saturating_add(1);
        if record.is_empty() {
            continue;
        }
        if record.len() < 4 || record[2] != b' ' {
            bail!("Git CLI primary status returned a malformed porcelain record");
        }
        let code = [record[0], record[1]];
        let path = record[3..].to_vec();
        let renamed_or_copied = code.iter().any(|status| matches!(status, b'R' | b'C'));
        let original_path = if renamed_or_copied {
            let original = records
                .get(index)
                .filter(|path| !path.is_empty())
                .context("Git CLI primary status omitted a rename/copy source path")?;
            index = index.saturating_add(1);
            Some((*original).to_vec())
        } else {
            None
        };
        if code == *b"??" && is_untracked_runtime_artifact_bytes(&path) {
            continue;
        }
        entries.insert(
            path,
            PrimaryStatusState {
                code,
                original_path,
            },
        );
    }
    Ok(entries)
}

fn primary_index_snapshot(
    workdir: &Path,
    runtime: SupervisorExecutionRuntime,
) -> Result<BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>> {
    let output = sanitized_git_output(
        workdir,
        &["ls-files", "--stage", "-v", "-z", "--sparse"],
        runtime,
    )
    .context("failed to run Git CLI primary index snapshot")?;
    if !output.status.success() {
        bail!(
            "Git CLI primary index snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let mut entries = BTreeMap::new();
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .context("Git CLI primary index returned a malformed entry without a path")?;
        let (header, path_with_separator) = record.split_at(separator);
        let path = &path_with_separator[1..];
        if header.len() < 3 || header[1] != b' ' {
            bail!("Git CLI primary index returned a malformed entry header");
        }
        let tag = header[0];
        let header = std::str::from_utf8(&header[2..])
            .context("Git CLI primary index returned a non-ASCII entry header")?;
        let mut fields = header.split_ascii_whitespace();
        let mode = u32::from_str_radix(
            fields.next().context("primary index entry omitted mode")?,
            8,
        )
        .context("primary index entry has invalid mode")?;
        let id = Oid::from_str(
            fields
                .next()
                .context("primary index entry omitted object id")?,
        )
        .context("primary index entry has invalid object id")?;
        let stage = fields
            .next()
            .context("primary index entry omitted stage")?
            .parse::<u16>()
            .context("primary index entry has invalid stage")?;
        if fields.next().is_some() {
            bail!("primary index entry has unexpected header fields");
        }
        let key = PrimaryIndexEntryKey {
            path: path.to_vec(),
            stage,
        };
        let state = PrimaryIndexEntryState { id, mode, tag };
        entries.insert(key, state);
    }
    Ok(entries)
}

fn index_entry_requires_fingerprint(state: &PrimaryIndexEntryState) -> bool {
    state.tag == b'S'
        || state.tag.is_ascii_lowercase()
        || matches!(state.mode, GITLINK_MODE | SPARSE_DIRECTORY_MODE)
}

fn primary_index_storage_snapshot(
    repo: &Repository,
    runtime: SupervisorExecutionRuntime,
) -> Result<PrimaryIndexStorageSnapshot> {
    let worktree_index = index_file_snapshot(&repo.path().join("index"))?;
    let shared_index = shared_index_path(repo, runtime)?
        .map(|path| {
            let storage = index_file_snapshot(&path)?;
            if storage == IndexFileSnapshot::Missing {
                bail!(
                    "Git reported split-index dependency {} but the file is missing",
                    path.display()
                );
            }
            Ok(SharedIndexFileSnapshot { path, storage })
        })
        .transpose()?;
    Ok(PrimaryIndexStorageSnapshot {
        worktree_index,
        shared_index,
    })
}

fn index_file_snapshot(path: &Path) -> Result<IndexFileSnapshot> {
    let bytes = match read_bounded_regular_file_nofollow(path, PRIMARY_INDEX_MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(IndexFileSnapshot::Missing);
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read index storage {}", path.display()));
        }
    };
    Ok(IndexFileSnapshot::Present {
        bytes: bytes.len().try_into().unwrap_or(u64::MAX),
        digest: Oid::hash_object(ObjectType::Blob, &bytes)
            .context("failed to digest index storage")?,
    })
}

fn shared_index_path(
    repo: &Repository,
    runtime: SupervisorExecutionRuntime,
) -> Result<Option<PathBuf>> {
    let workdir = repo
        .workdir()
        .context("shared-index discovery requires a non-bare repository")?;
    let output = sanitized_git_output(
        workdir,
        &["rev-parse", "--path-format=absolute", "--shared-index-path"],
        runtime,
    )
    .context("failed to inspect split-index dependency")?;
    if !output.status.success() {
        bail!(
            "failed to inspect split-index dependency: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut path = output.stdout;
    while path
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        path.pop();
    }
    if path.is_empty() {
        return Ok(None);
    }
    let path = repo_relative_path_from_git_bytes(&path);
    Ok(Some(if path.is_absolute() {
        path
    } else {
        repo.path().join(path)
    }))
}

fn sanitized_git_output(
    workdir: &Path,
    args: &[&str],
    runtime: SupervisorExecutionRuntime,
) -> Result<std::process::Output> {
    let git = trusted_system_executable(
        "git",
        &["/run/current-system/sw/bin/git", "/usr/bin/git", "/bin/git"],
    )?;
    let environment = BTreeMap::from([
        (
            "PATH".to_string(),
            "/run/current-system/sw/bin:/usr/bin:/bin".to_string(),
        ),
        ("LANG".to_string(), "C".to_string()),
        ("LC_ALL".to_string(), "C".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        (
            "GIT_CONFIG_GLOBAL".to_string(),
            git_null_device().to_string(),
        ),
        ("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string()),
    ]);
    let mut command_args = vec![
        "--no-pager".to_string(),
        "--no-optional-locks".to_string(),
        "-c".to_string(),
        "core.fsmonitor=false".to_string(),
        "-c".to_string(),
        "core.untrackedCache=false".to_string(),
    ];
    command_args.extend(args.iter().map(|arg| (*arg).to_string()));
    let process_spec = ProcessSpec::direct(
        "supervisor Git snapshot",
        git,
        command_args,
        workdir,
        SNAPSHOT_GIT_CAPTURE_MAX_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(SNAPSHOT_GIT_TIMEOUT));
    let output = run_process(match runtime {
        SupervisorExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                StrictOfflineWorkspaceProfile::read_only(workdir),
            )),
        #[cfg(test)]
        SupervisorExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    })?;
    if output.timed_out
        || output.process_error.is_some()
        || output.stdin_error.is_some()
        || (runtime == SupervisorExecutionRuntime::Verified && !output.safety_evidence_verified())
    {
        bail!(
            "supervisor Git snapshot was not safely verified: process_tree={:?}; side_effects={:?}; process_error={:?}; stdin_error={:?}",
            output.process_tree,
            output.side_effects,
            output.process_error,
            output.stdin_error
        );
    }
    if output.stdout.is_truncated() || output.stderr.is_truncated() {
        bail!(
            "supervisor Git snapshot output exceeded the {} byte limit",
            SNAPSHOT_GIT_CAPTURE_MAX_BYTES
        );
    }
    let status = output
        .status
        .context("supervisor Git snapshot terminated without status")?;
    Ok(std::process::Output {
        status,
        stdout: output.stdout.as_bytes().to_vec(),
        stderr: output.stderr.as_bytes().to_vec(),
    })
}

#[cfg(target_os = "windows")]
fn git_null_device() -> &'static str {
    "NUL"
}

#[cfg(not(target_os = "windows"))]
fn git_null_device() -> &'static str {
    "/dev/null"
}

fn primary_path_state(
    path: &Path,
    capture_nested_repository: bool,
    fingerprint_directory_contents: bool,
    depth: usize,
    visited_gitdirs: &mut BTreeSet<PathBuf>,
    runtime: SupervisorExecutionRuntime,
) -> Result<PrimaryPathState> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PrimaryPathState::Missing);
        }
        Err(error) => return Err(error.into()),
    };
    let mode = primary_path_mode(&metadata);
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Ok(PrimaryPathState::Symlink {
            target: fs::read_link(path)?,
            mode,
        });
    }
    if file_type.is_file() {
        return Ok(PrimaryPathState::File {
            id: Oid::hash_file(ObjectType::Blob, path)?,
            mode,
        });
    }
    if file_type.is_dir() {
        let nested_repository = if capture_nested_repository {
            match Repository::open(path) {
                Ok(_) => Some(Box::new(primary_worktree_snapshot_at_depth(
                    path,
                    depth.saturating_add(1),
                    visited_gitdirs,
                    runtime,
                )?)),
                Err(error) if error.code() == ErrorCode::NotFound => None,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to inspect nested repository {}", path.display())
                    });
                }
            }
        } else {
            None
        };
        let contents_digest = fingerprint_directory_contents
            .then(|| directory_content_digest(path, 0))
            .transpose()?;
        return Ok(PrimaryPathState::Directory {
            nested_repository,
            contents_digest,
            mode,
        });
    }
    Ok(PrimaryPathState::Other { mode })
}

fn directory_content_digest(path: &Path, depth: usize) -> Result<Oid> {
    if depth > MAX_DIRECTORY_FINGERPRINT_DEPTH {
        bail!(
            "directory fingerprint exceeded the safety limit of {} at {}",
            MAX_DIRECTORY_FINGERPRINT_DEPTH,
            path.display()
        );
    }
    let mut entries = fs::read_dir(path)
        .with_context(|| format!("failed to read sparse directory {}", path.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| snapshot_os_str_bytes(&entry.file_name()));

    let mut fingerprint = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        let name_bytes = snapshot_os_str_bytes(&name);
        append_fingerprint_bytes(&mut fingerprint, &name_bytes);
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path).with_context(|| {
            format!(
                "failed to inspect sparse directory entry {}",
                entry_path.display()
            )
        })?;
        fingerprint.extend_from_slice(&primary_path_mode(&metadata).to_le_bytes());
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            fingerprint.push(b'l');
            let target = fs::read_link(&entry_path)?;
            append_fingerprint_bytes(&mut fingerprint, &snapshot_os_str_bytes(target.as_os_str()));
        } else if file_type.is_file() {
            fingerprint.push(b'f');
            let id = Oid::hash_file(ObjectType::Blob, &entry_path)?;
            fingerprint.extend_from_slice(id.as_bytes());
        } else if file_type.is_dir() {
            fingerprint.push(b'd');
            if name == OsStr::new(".git") {
                fingerprint.extend_from_slice(b"git-metadata-directory");
            } else {
                let id = directory_content_digest(&entry_path, depth.saturating_add(1))?;
                fingerprint.extend_from_slice(id.as_bytes());
            }
        } else {
            fingerprint.push(b'o');
        }
    }
    Oid::hash_object(ObjectType::Blob, &fingerprint)
        .context("failed to digest sparse directory contents")
}

fn append_fingerprint_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}

#[cfg(unix)]
fn snapshot_os_str_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(target_os = "windows")]
fn snapshot_os_str_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, target_os = "windows")))]
fn snapshot_os_str_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn primary_path_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode()
}

#[cfg(not(unix))]
fn primary_path_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

pub(super) fn primary_integrity_changes(
    before: &PrimaryWorktreeSnapshot,
    after: &PrimaryWorktreeSnapshot,
) -> PrimaryIntegrityChanges {
    let mut details = Vec::new();
    let mut paths = BTreeSet::new();

    if before.head != after.head {
        details.push(format!(
            "HEAD/reference changed from {} to {}",
            display_primary_head(&before.head),
            display_primary_head(&after.head)
        ));
        paths.insert(PathBuf::from(".git/HEAD"));
    }

    let index_paths = changed_index_paths(&before.index, &after.index);
    if !index_paths.is_empty() {
        details.push(format!(
            "index changed for {}",
            display_git_paths(&index_paths)
        ));
        paths.extend(
            index_paths
                .iter()
                .map(|path| finding_path_from_git_bytes(path)),
        );
    }

    if before.index_storage != after.index_storage {
        details.push("raw worktree index or split-index storage changed".to_string());
        paths.insert(PathBuf::from(".git/index"));
    }

    if before.inspection_error != after.inspection_error {
        details.push("primary index/status inspectability changed".to_string());
        paths.insert(PathBuf::from(".git/index"));
    }

    let status_paths = changed_snapshot_paths(&before.status, &after.status);
    if !status_paths.is_empty() {
        details.push(format!(
            "Git status changed for {}",
            display_git_paths(&status_paths)
        ));
        paths.extend(
            status_paths
                .iter()
                .map(|path| finding_path_from_git_bytes(path)),
        );
    }

    let worktree_paths = changed_snapshot_paths(&before.worktree, &after.worktree);
    if !worktree_paths.is_empty() {
        details.push(format!(
            "worktree content/type changed for {}",
            display_git_paths(&worktree_paths)
        ));
        paths.extend(
            worktree_paths
                .iter()
                .map(|path| finding_path_from_git_bytes(path)),
        );
    }

    PrimaryIntegrityChanges {
        details,
        paths: paths.into_iter().collect(),
    }
}

fn changed_index_paths(
    before: &BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>,
    after: &BTreeMap<PrimaryIndexEntryKey, PrimaryIndexEntryState>,
) -> BTreeSet<Vec<u8>> {
    before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .map(|key| key.path.clone())
        .collect()
}

fn changed_snapshot_paths<T: PartialEq>(
    before: &BTreeMap<Vec<u8>, T>,
    after: &BTreeMap<Vec<u8>, T>,
) -> BTreeSet<Vec<u8>> {
    before
        .keys()
        .chain(after.keys())
        .filter(|path| before.get(*path) != after.get(*path))
        .cloned()
        .collect()
}

fn display_primary_head(head: &PrimaryHeadSnapshot) -> String {
    let reference = head
        .reference_name
        .as_deref()
        .map(String::from_utf8_lossy)
        .map(|name| name.into_owned())
        .unwrap_or_else(|| "<missing>".to_string());
    let target = head
        .target
        .map(|target| target.to_string())
        .unwrap_or_else(|| "<missing>".to_string());
    let mode = if head.detached {
        "detached"
    } else {
        "attached"
    };
    format!("{reference}@{target} ({mode})")
}

fn display_git_paths(paths: &BTreeSet<Vec<u8>>) -> String {
    paths
        .iter()
        .map(|path| finding_path_from_git_bytes(path).display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn finding_path_from_git_bytes(path: &[u8]) -> PathBuf {
    match std::str::from_utf8(path) {
        Ok(path) => PathBuf::from(path),
        Err(_) => PathBuf::from(format!("<non-utf8-git-path>/{}", hex_encode(path))),
    }
}

pub(super) fn serialize_path<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&serializable_path(path))
}

pub(super) fn serialize_optional_path<S>(
    path: &Option<PathBuf>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    path.as_deref().map(serializable_path).serialize(serializer)
}

pub(super) fn serialize_paths<S>(paths: &[PathBuf], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    paths
        .iter()
        .map(|path| serializable_path(path))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

pub(super) fn serializable_path(path: &Path) -> String {
    if let Some(path) = path.to_str() {
        return path.to_string();
    }
    serializable_non_utf8_path(path)
}

#[cfg(unix)]
fn serializable_non_utf8_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    format!(
        "<non-utf8-git-path>/{}",
        hex_encode(path.as_os_str().as_bytes())
    )
}

#[cfg(target_os = "windows")]
fn serializable_non_utf8_path(path: &Path) -> String {
    use std::os::windows::ffi::OsStrExt;
    format!(
        "<non-unicode-windows-path>/{}",
        path.as_os_str()
            .encode_wide()
            .map(|unit| format!("{unit:04x}"))
            .collect::<String>()
    )
}

#[cfg(not(any(unix, target_os = "windows")))]
fn serializable_non_utf8_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(super) fn claim_failure_finding(
    sync_store: &SyncStore,
    assignment: &OrchestratorAssignment,
    error: &anyhow::Error,
) -> Finding {
    let conflicts = claim_conflict_details(sync_store, &assignment.assigned_paths);
    let paths = conflicts
        .iter()
        .map(|conflict| conflict.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let detail = if conflicts.is_empty() {
        error.to_string()
    } else {
        conflicts
            .iter()
            .map(|conflict| {
                format!(
                    "{} currently claimed by {}",
                    conflict.path.display(),
                    conflict.owner
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    Finding {
        severity: FindingSeverity::Error,
        message: format!("failed to claim paths for '{}': {}", assignment.id, detail),
        paths,
    }
}

pub(super) fn claim_conflict_details(
    sync_store: &SyncStore,
    requested_paths: &[PathBuf],
) -> Vec<ClaimConflictDetail> {
    match sync_store.status_snapshot() {
        Ok(claims) => claims
            .iter()
            .flat_map(|claim| {
                claim.claim.paths.iter().filter_map(|claimed| {
                    requested_paths
                        .iter()
                        .find(|requested| paths_overlap(claimed, requested))
                        .map(|requested| ClaimConflictDetail {
                            path: requested.clone(),
                            owner: format!(
                                "{} (token {}, run {}, owner_run_state={})",
                                claim.claim.agent_id,
                                claim.claim.token.get(),
                                claim.owner_run_id.as_deref().unwrap_or("<unattributed>"),
                                claim.owner_run_state.as_str(),
                            ),
                        })
                })
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}
