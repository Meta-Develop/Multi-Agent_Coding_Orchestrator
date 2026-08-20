fn summary_status_by_id(summaries: &[AgentRunSummary], agent_id: &str) -> Option<AgentRunStatus> {
    summaries
        .iter()
        .find(|summary| summary.id == agent_id)
        .map(|summary| summary.status)
}

fn agent_status_label(status: AgentRunStatus) -> &'static str {
    match status {
        AgentRunStatus::Pending => "pending",
        AgentRunStatus::Succeeded => "succeeded",
        AgentRunStatus::Failed => "failed",
        AgentRunStatus::Skipped => "skipped",
    }
}

fn run_ready_agents(
    manager: &WorktreeManager,
    plan: &OrchestrationPlan,
    summaries: &[AgentRunSummary],
    worktrees: &[SelectedWorktree],
    ready: &[usize],
    runtime: OrchestrationExecutionRuntime,
) -> Result<Vec<(usize, Result<CommandRunResult, ProcessRunError>)>> {
    if ready.len() == 1 {
        let index = ready[0];
        verify_selected_worktree_binding(
            manager,
            &plan.agents[index],
            &summaries[index],
            &worktrees[index],
        )?;
        let _revalidation =
            revalidate_ready_agent(&plan.agents[index], &summaries[index], &worktrees[index])?;
        let spec = command_spec(
            &plan.agents[index],
            &summaries[index],
            &worktrees[index],
            runtime,
        )?;
        return Ok(vec![(index, run_agent_command(spec))]);
    }

    let mut prepared = Vec::with_capacity(ready.len());
    for index in ready {
        verify_selected_worktree_binding(
            manager,
            &plan.agents[*index],
            &summaries[*index],
            &worktrees[*index],
        )?;
        let _revalidation =
            revalidate_ready_agent(&plan.agents[*index], &summaries[*index], &worktrees[*index])?;
        let spec = command_spec(
            &plan.agents[*index],
            &summaries[*index],
            &worktrees[*index],
            runtime,
        )?;
        prepared.push((*index, spec));
    }

    let mut handles = Vec::with_capacity(prepared.len());
    for (index, spec) in prepared {
        handles.push((
            index,
            thread::spawn(move || (index, run_agent_command(spec))),
        ));
        #[cfg(test)]
        if let Err(error) = fail_after_ready_agent_spawn(&plan.agents[index].id) {
            let _ = join_ready_agent_handles(handles);
            return Err(error);
        }
    }
    Ok(join_ready_agent_handles(handles))
}

type ReadyAgentHandle = (
    usize,
    std::thread::JoinHandle<(usize, Result<CommandRunResult, ProcessRunError>)>,
);

fn join_ready_agent_handles(
    handles: Vec<ReadyAgentHandle>,
) -> Vec<(usize, Result<CommandRunResult, ProcessRunError>)> {
    let mut outcomes = Vec::with_capacity(handles.len());
    for (index, handle) in handles {
        let outcome = handle.join().unwrap_or_else(|_| {
            (
                index,
                Ok(CommandRunResult {
                    status: None,
                    duration_ms: 0,
                    timed_out: false,
                    stdout: OutputSummary::default(),
                    stderr: OutputSummary::default(),
                    process_error: Some("agent command runner panicked".to_string()),
                }),
            )
        });
        outcomes.push(outcome);
    }

    outcomes.sort_by_key(|(index, _)| *index);
    outcomes
}

fn inspect_captured_agent_changes(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    captured: &CapturedCandidate,
    patch_output: Option<ReservedOutputFile>,
) {
    let mut patch_output = patch_output.map(PatchOutputGuard::new);
    if summary.worktree.is_none() {
        fail_summary(summary, "agent has no selected worktree");
        return;
    }
    summary.changed_paths = captured.binding.changed_paths.clone();
    summary.unclaimed_changed_paths = summary
        .changed_paths
        .iter()
        .filter(|path| {
            !agent
                .paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
        })
        .cloned()
        .collect::<Vec<_>>();

    if !summary.unclaimed_changed_paths.is_empty() {
        let paths = summary
            .unclaimed_changed_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        fail_summary(
            summary,
            format!("agent changed paths outside its claims: {paths}"),
        );
    }

    if let Some(patch_output) = patch_output.as_mut().and_then(PatchOutputGuard::take) {
        match write_captured_agent_patch(patch_output, &captured.patch) {
            Ok(Some(path)) => summary.patch_path = Some(path),
            Ok(None) => {}
            Err(error) => fail_summary(summary, format!("failed to write patch: {error}")),
        }
    }
}

fn inspect_agent_paths_without_patch(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    manager: &WorktreeManager,
    worktree: &SelectedWorktree,
    base_oid: &Oid,
    patch_output: Option<ReservedOutputFile>,
) {
    let _patch_output = patch_output.map(PatchOutputGuard::new);
    if let Err(error) = verify_selected_worktree_binding(manager, agent, summary, worktree) {
        fail_summary(
            summary,
            format!("refusing rejected-candidate inspection: {error}"),
        );
        return;
    }
    let repo = match crate::git_repository::open(worktree.path()) {
        Ok(repo) => repo,
        Err(error) => {
            fail_summary(
                summary,
                format!("failed to inspect rejected candidate: {error}"),
            );
            return;
        }
    };
    let changed_paths = match collect_paths_changed_since_base(&repo, base_oid) {
        Ok(paths) => paths,
        Err(error) => {
            fail_summary(
                summary,
                format!("failed to collect rejected candidate paths: {error}"),
            );
            return;
        }
    };
    if let Err(error) = verify_selected_worktree_binding(manager, agent, summary, worktree) {
        fail_summary(
            summary,
            format!("rejected candidate binding changed during inspection: {error}"),
        );
        return;
    }
    summary.changed_paths = changed_paths;
    summary.unclaimed_changed_paths = summary
        .changed_paths
        .iter()
        .filter(|path| {
            !agent
                .paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
        })
        .cloned()
        .collect();
}

fn fail_summary(summary: &mut AgentRunSummary, message: impl Into<String>) {
    summary.status = AgentRunStatus::Failed;
    let message = message.into();
    summary.error = match summary.error.take() {
        Some(existing) => Some(format!("{existing}; {message}")),
        None => Some(message),
    };
}

fn collect_status_paths(repo: &Repository) -> Result<Vec<PathBuf>> {
    let mut options = git2::StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to inspect git status")?;
    let mut paths = BTreeSet::new();
    for entry in statuses.iter() {
        let path = entry.path().context("git status path is not valid UTF-8")?;
        paths.insert(PathBuf::from(path));
    }
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn collect_paths_changed_since_base(repo: &Repository, base_oid: &Oid) -> Result<Vec<PathBuf>> {
    let base_commit = repo
        .find_commit(*base_oid)
        .with_context(|| format!("failed to find base commit {base_oid}"))?;
    let base_tree = base_commit
        .tree()
        .with_context(|| format!("failed to read tree for base commit {base_oid}"))?;
    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_typechange(true);
    let diff = repo
        .diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut options))
        .context("failed to diff worktree against base commit")?;
    let mut paths = BTreeSet::new();
    diff.foreach(
        &mut |delta, _| {
            collect_delta_paths(delta, &mut paths);
            true
        },
        None,
        None,
        None,
    )
    .context("failed to inspect changed paths")?;

    Ok(paths.into_iter().collect())
}

fn collect_delta_paths(delta: git2::DiffDelta<'_>, paths: &mut BTreeSet<PathBuf>) {
    match delta.status() {
        Delta::Deleted => {
            insert_delta_path(delta.old_file().path(), paths);
        }
        Delta::Renamed | Delta::Copied => {
            insert_delta_path(delta.old_file().path(), paths);
            insert_delta_path(delta.new_file().path(), paths);
        }
        _ => {
            insert_delta_path(delta.new_file().path(), paths);
        }
    }
}

fn capture_consistent_candidate_state(
    worktree_path: &Path,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CandidateStateSnapshot> {
    for _ in 0..CANDIDATE_CAPTURE_ATTEMPTS {
        let first = capture_candidate_state_once(worktree_path, base_oid, runtime)?;
        let second = capture_candidate_state_once(worktree_path, base_oid, runtime)?;
        if first == second {
            return Ok(second);
        }
    }
    bail!(
        "candidate state changed while its validation binding was captured; retry after worktree activity stops"
    )
}

fn capture_candidate_state_once(
    worktree_path: &Path,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CandidateStateSnapshot> {
    let repo =
        crate::git_repository::open(worktree_path).context("failed to open candidate worktree")?;
    let head_oid = head_oid(&repo).context("failed to capture candidate HEAD")?;
    let merge_base = repo
        .merge_base(*base_oid, head_oid)
        .context("failed to verify candidate ancestry from the captured run base")?;
    if merge_base != *base_oid {
        bail!("candidate HEAD no longer descends from the captured run base");
    }
    let base = base_oid.to_string();
    let index_entries = capture_fixed_git_stdout(
        worktree_path,
        ["ls-files", "--stage", "-z"],
        runtime,
        "candidate index entries",
    )?;
    let index_flags = capture_fixed_git_stdout(
        worktree_path,
        ["ls-files", "-v", "-z"],
        runtime,
        "candidate index flags",
    )?;
    let index_diff = capture_fixed_git_stdout(
        worktree_path,
        [
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            base.as_str(),
        ],
        runtime,
        "candidate index diff",
    )?;
    let worktree_diff = capture_fixed_git_stdout(
        worktree_path,
        ["diff", "--no-ext-diff", "--no-textconv", "--binary"],
        runtime,
        "candidate worktree diff",
    )?;
    let status = capture_candidate_status(&repo)?;
    let untracked = capture_untracked_manifest(worktree_path, runtime)?;
    let changed_paths = collect_paths_changed_since_base(&repo, base_oid)?
        .into_iter()
        .map(|path| normalize_repo_relative_path(&path).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    if changed_paths.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "candidate changed-path count exceeded the configured {} entry limit",
            CANDIDATE_MAX_CHANGED_PATHS
        );
    }

    Ok(CandidateStateSnapshot {
        base_oid: *base_oid,
        head_oid,
        index_entries_oid: hash_candidate_component(&index_entries)?,
        index_flags_oid: hash_candidate_component(&index_flags)?,
        index_diff_oid: hash_candidate_component(&index_diff)?,
        worktree_diff_oid: hash_candidate_component(&worktree_diff)?,
        status_oid: hash_candidate_component(&status)?,
        untracked_oid: hash_candidate_component(&untracked)?,
        changed_paths,
    })
}

fn capture_fixed_git_stdout(
    worktree_path: &Path,
    args: impl IntoIterator<Item = impl Into<OsString>>,
    runtime: OrchestrationExecutionRuntime,
    label: &str,
) -> Result<Vec<u8>> {
    let output = run_fixed_git(worktree_path, args, WorkspaceAccess::ReadOnly, runtime)
        .with_context(|| format!("failed to capture {label}"))?;
    if !output.status.success() {
        bail!(
            "failed to capture {label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn capture_candidate_status(repo: &Repository) -> Result<Vec<u8>> {
    let mut options = git2::StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .renames_head_to_index(true)
        .renames_index_to_workdir(true)
        .include_unmodified(false);
    let statuses = repo
        .statuses(Some(&mut options))
        .context("failed to capture candidate status")?;
    if statuses.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "candidate status exceeded the configured {} entry limit",
            CANDIDATE_MAX_CHANGED_PATHS
        );
    }
    let mut records = statuses
        .iter()
        .map(|entry| (entry.path_bytes().to_vec(), entry.status().bits()))
        .collect::<Vec<_>>();
    records.sort();
    let mut encoded = Vec::new();
    for (path, status) in records {
        extend_bounded_candidate_bytes(&mut encoded, &status.to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut encoded, &(path.len() as u64).to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut encoded, &path)?;
    }
    Ok(encoded)
}

fn capture_untracked_manifest(
    worktree_path: &Path,
    runtime: OrchestrationExecutionRuntime,
) -> Result<Vec<u8>> {
    let output = capture_fixed_git_stdout(
        worktree_path,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        runtime,
        "candidate untracked paths",
    )?;
    let paths = output
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    if paths.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "candidate untracked-path count exceeded the configured {} entry limit",
            CANDIDATE_MAX_CHANGED_PATHS
        );
    }

    let mut manifest = Vec::new();
    extend_bounded_candidate_bytes(&mut manifest, b"MACO\0untracked-manifest\0v2\0")?;
    let mut total_content_bytes = 0_usize;
    for raw_path in paths {
        let path = normalize_repo_relative_path(Path::new(&git_path_argument(raw_path)?))?;
        let absolute = worktree_path.join(&path);
        let metadata = fs::symlink_metadata(&absolute).with_context(|| {
            format!(
                "failed to inspect untracked candidate path {}",
                path.display()
            )
        })?;
        let (kind, git_mode, content) = if metadata.file_type().is_file() {
            let bytes = BoundedRegularReader::read_relative(
                worktree_path,
                &path,
                CANDIDATE_MAX_SINGLE_FILE_BYTES as u64,
            )?;
            (b'f', normalized_untracked_git_mode(&metadata)?, bytes)
        } else if metadata.file_type().is_symlink() {
            (
                b'l',
                0o120000_u32,
                read_candidate_symlink(&absolute, &metadata)?,
            )
        } else {
            bail!(
                "candidate untracked path is not a regular file or symlink: {}",
                path.display()
            );
        };
        if content.len() > CANDIDATE_MAX_SINGLE_FILE_BYTES {
            bail!(
                "candidate path '{}' exceeded the configured {} byte per-file limit",
                path.display(),
                CANDIDATE_MAX_SINGLE_FILE_BYTES
            );
        }
        total_content_bytes = total_content_bytes
            .checked_add(content.len())
            .context("candidate content byte count overflowed")?;
        if total_content_bytes > CANDIDATE_MAX_TOTAL_BYTES {
            bail!(
                "candidate untracked content exceeded the configured {} byte aggregate limit",
                CANDIDATE_MAX_TOTAL_BYTES
            );
        }
        let path_bytes = candidate_path_bytes(&path);
        let content_oid = hash_candidate_component(&content)?;
        extend_bounded_candidate_bytes(&mut manifest, &(path_bytes.len() as u64).to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut manifest, &path_bytes)?;
        extend_bounded_candidate_bytes(&mut manifest, &[kind])?;
        extend_bounded_candidate_bytes(&mut manifest, &git_mode.to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut manifest, &(content.len() as u64).to_le_bytes())?;
        extend_bounded_candidate_bytes(&mut manifest, content_oid.as_bytes())?;
    }
    Ok(manifest)
}

#[cfg(unix)]
fn normalized_untracked_git_mode(metadata: &fs::Metadata) -> Result<u32> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.file_type().is_file() {
        bail!("untracked Git mode is only defined for regular files");
    }
    Ok(if metadata.mode() & 0o111 == 0 {
        0o100644
    } else {
        0o100755
    })
}

#[cfg(windows)]
fn normalized_untracked_git_mode(metadata: &fs::Metadata) -> Result<u32> {
    if !metadata.file_type().is_file() {
        bail!("untracked Git mode is only defined for regular files");
    }
    Ok(0o100644)
}

#[cfg(not(any(unix, windows)))]
fn normalized_untracked_git_mode(metadata: &fs::Metadata) -> Result<u32> {
    if !metadata.file_type().is_file() {
        bail!("untracked Git mode is only defined for regular files");
    }
    Ok(0o100644)
}

fn read_candidate_symlink(path: &Path, before: &fs::Metadata) -> Result<Vec<u8>> {
    let target = fs::read_link(path)
        .with_context(|| format!("failed to read candidate symlink {}", path.display()))?;
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to recheck candidate symlink {}", path.display()))?;
    if !same_candidate_file_identity(before, &after) || !after.file_type().is_symlink() {
        bail!("candidate symlink changed while it was captured");
    }
    Ok(candidate_path_bytes(&target))
}

#[cfg(unix)]
fn same_candidate_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.len() == right.len()
}

#[cfg(not(unix))]
fn same_candidate_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type() && left.len() == right.len()
}

#[cfg(unix)]
fn candidate_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn candidate_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn candidate_path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}

fn extend_bounded_candidate_bytes(target: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let next = target
        .len()
        .checked_add(bytes.len())
        .context("candidate binding byte count overflowed")?;
    if next > CANDIDATE_MAX_TOTAL_BYTES {
        bail!(
            "candidate binding exceeded the configured {} byte limit",
            CANDIDATE_MAX_TOTAL_BYTES
        );
    }
    target.extend_from_slice(bytes);
    Ok(())
}

fn hash_candidate_component(bytes: &[u8]) -> Result<Oid> {
    Oid::hash_object(git2::ObjectType::Blob, bytes)
        .context("failed to hash candidate binding component")
}

impl CandidateStateSnapshot {
    fn state_oid(&self) -> Result<Oid> {
        let mut binding = Vec::new();
        extend_bounded_candidate_bytes(&mut binding, b"MACO\0candidate-state\0v1\0")?;
        for oid in [
            self.base_oid,
            self.head_oid,
            self.index_entries_oid,
            self.index_flags_oid,
            self.index_diff_oid,
            self.worktree_diff_oid,
            self.status_oid,
            self.untracked_oid,
        ] {
            extend_bounded_candidate_bytes(&mut binding, oid.as_bytes())?;
        }
        for path in &self.changed_paths {
            let bytes = candidate_path_bytes(path);
            extend_bounded_candidate_bytes(&mut binding, &(bytes.len() as u64).to_le_bytes())?;
            extend_bounded_candidate_bytes(&mut binding, &bytes)?;
        }
        hash_candidate_component(&binding)
    }

    fn drift_from(&self, previous: &Self) -> Option<String> {
        let mut components = Vec::new();
        if self.head_oid != previous.head_oid {
            components.push("HEAD");
        }
        if self.index_entries_oid != previous.index_entries_oid
            || self.index_flags_oid != previous.index_flags_oid
            || self.index_diff_oid != previous.index_diff_oid
        {
            components.push("index");
        }
        if self.worktree_diff_oid != previous.worktree_diff_oid {
            components.push("tracked worktree content");
        }
        if self.untracked_oid != previous.untracked_oid {
            components.push("untracked content");
        }
        if self.status_oid != previous.status_oid || self.changed_paths != previous.changed_paths {
            components.push("changed paths/status");
        }
        (!components.is_empty()).then(|| {
            let before = previous
                .changed_paths
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let after = self.changed_paths.iter().cloned().collect::<BTreeSet<_>>();
            let path_detail = before
                .symmetric_difference(&after)
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            let path_detail = if path_detail.is_empty() {
                String::new()
            } else {
                format!("; affected paths: {}", path_detail.join(", "))
            };
            format!(
                "candidate-relevant state changed after the agent command: {}{path_detail}",
                components.join(", ")
            )
        })
    }
}

impl CompletedCommandStateBinding {
    fn from_state(state: &CandidateStateSnapshot) -> Result<Self> {
        Ok(Self {
            version: CANDIDATE_BINDING_VERSION,
            base_oid: state.base_oid.to_string(),
            head_oid: state.head_oid.to_string(),
            state_oid: state.state_oid()?.to_string(),
            changed_paths: state.changed_paths.clone(),
        })
    }

    fn verify_state(&self, state: &CandidateStateSnapshot) -> Result<()> {
        if self.version != CANDIDATE_BINDING_VERSION
            || self.base_oid != state.base_oid.to_string()
            || self.head_oid != state.head_oid.to_string()
            || self.state_oid != state.state_oid()?.to_string()
            || self.changed_paths != state.changed_paths
        {
            bail!("completed command state no longer matches its authenticated exact binding");
        }
        Ok(())
    }
}

fn capture_bound_candidate(
    worktree_path: &Path,
    base_oid: &Oid,
    expected_state: &CandidateStateSnapshot,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CapturedCandidate> {
    let before = capture_consistent_candidate_state(worktree_path, base_oid, runtime)?;
    if let Some(drift) = before.drift_from(expected_state) {
        bail!("{drift}");
    }
    let repo =
        crate::git_repository::open(worktree_path).context("failed to open candidate worktree")?;
    let (changed_paths, patch) = match runtime {
        OrchestrationExecutionRuntime::Verified => {
            capture_worktree_diff_from_commit(&repo, worktree_path, *base_oid)
                .context("failed to capture the exact bounded candidate patch")?
        }
        #[cfg(test)]
        OrchestrationExecutionRuntime::NonpublishableSimulation => {
            capture_simulation_candidate_patch(&repo, worktree_path, base_oid, runtime)?
        }
    };
    validate_patch_output_size(patch.len())?;
    let changed_paths = changed_paths
        .into_iter()
        .map(|path| normalize_repo_relative_path(&path).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    if changed_paths != before.changed_paths {
        bail!("candidate patch paths did not match the bound candidate state");
    }
    let after = capture_consistent_candidate_state(worktree_path, base_oid, runtime)?;
    if let Some(drift) = after.drift_from(&before) {
        bail!("candidate changed while its exact patch was captured: {drift}");
    }
    let patch_bytes = u64::try_from(patch.len()).context("candidate patch length overflowed")?;
    let binding = AgentCandidateBinding {
        version: CANDIDATE_BINDING_VERSION,
        base_oid: base_oid.to_string(),
        head_oid: before.head_oid.to_string(),
        state_oid: before.state_oid()?.to_string(),
        diff_oid: hash_candidate_component(&patch)?.to_string(),
        changed_paths: before.changed_paths.clone(),
        patch_bytes,
    };
    Ok(CapturedCandidate { binding, patch })
}

#[cfg(test)]
fn capture_simulation_candidate_patch(
    repo: &Repository,
    worktree_path: &Path,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> Result<(Vec<PathBuf>, Vec<u8>)> {
    let base = base_oid.to_string();
    let mut patch = capture_fixed_git_stdout(
        worktree_path,
        [
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            base.as_str(),
        ],
        runtime,
        "simulation candidate tracked patch",
    )?;
    let untracked = capture_fixed_git_stdout(
        worktree_path,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        runtime,
        "simulation candidate untracked paths",
    )?;
    for raw_path in untracked
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = normalize_repo_relative_path(Path::new(&git_path_argument(raw_path)?))?;
        let _ = BoundedRegularReader::read_relative(
            worktree_path,
            &path,
            CANDIDATE_MAX_SINGLE_FILE_BYTES as u64,
        )?;
        let output = run_fixed_git(
            worktree_path,
            vec![
                OsString::from("diff"),
                OsString::from("--no-index"),
                OsString::from("--no-ext-diff"),
                OsString::from("--no-textconv"),
                OsString::from("--binary"),
                OsString::from("--"),
                OsString::from(git_null_device()),
                path.as_os_str().to_os_string(),
            ],
            WorkspaceAccess::ReadOnly,
            runtime,
        )
        .context("failed to capture simulation untracked patch")?;
        if output.status.code() != Some(1) && !output.status.success() {
            bail!("simulation untracked patch capture failed");
        }
        extend_bounded_candidate_bytes(&mut patch, &output.stdout)?;
    }
    let changed_paths = collect_paths_changed_since_base(repo, base_oid)?;
    Ok((changed_paths, patch))
}

fn ensure_candidate_binding_matches_state(
    binding: &AgentCandidateBinding,
    state: &CandidateStateSnapshot,
) -> Result<()> {
    if binding.version != CANDIDATE_BINDING_VERSION {
        bail!(
            "unsupported candidate binding version {}; start a new run",
            binding.version
        );
    }
    if binding.base_oid != state.base_oid.to_string()
        || binding.head_oid != state.head_oid.to_string()
        || binding.state_oid != state.state_oid()?.to_string()
        || binding.changed_paths != state.changed_paths
    {
        bail!("candidate state no longer matches its serialized validation binding");
    }
    Ok(())
}

fn insert_delta_path(path: Option<&Path>, paths: &mut BTreeSet<PathBuf>) {
    if let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) {
        paths.insert(path.to_path_buf());
    }
}

fn path_is_covered_by_claim(path: &Path, claim: &Path) -> bool {
    path == claim || path.starts_with(claim)
}

fn write_captured_agent_patch(
    mut patch_output: ReservedOutputFile,
    bytes: &[u8],
) -> Result<Option<PathBuf>> {
    if bytes.is_empty() {
        patch_output.remove()?;
        return Ok(None);
    }
    if let Err(error) = validate_patch_output_size(bytes.len()) {
        let patch_path = patch_output.path().to_path_buf();
        let cleanup = patch_output.remove();
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "also failed to clean reserved patch {}: {cleanup:#}",
                patch_path.display()
            ))),
        };
    }
    let patch_path = patch_output.path().to_path_buf();
    if let Err(error) = patch_output.write_bytes_atomic(bytes, PATCH_OUTPUT_MAX_BYTES) {
        let cleanup = patch_output.remove();
        return match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "also failed to clean reserved patch {}: {cleanup:#}",
                patch_path.display()
            ))),
        };
    }
    Ok(Some(patch_path))
}

fn validate_patch_output_size(bytes: usize) -> Result<()> {
    if bytes >= PATCH_OUTPUT_MAX_BYTES {
        bail!(
            "patch output reached the configured {} byte capture boundary",
            PATCH_OUTPUT_MAX_BYTES
        );
    }
    Ok(())
}

#[cfg(unix)]
fn git_path_argument(path: &[u8]) -> Result<OsString> {
    use std::os::unix::ffi::OsStringExt;
    Ok(OsString::from_vec(path.to_vec()))
}

#[cfg(not(unix))]
fn git_path_argument(path: &[u8]) -> Result<OsString> {
    String::from_utf8(path.to_vec())
        .map(OsString::from)
        .context("Git returned a non-UTF-8 path that this platform cannot represent losslessly")
}

fn run_fixed_git(
    worktree_path: &Path,
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    access: WorkspaceAccess,
    runtime: OrchestrationExecutionRuntime,
) -> Result<std::process::Output> {
    run_fixed_git_with_stdin(worktree_path, args, access, StdinMode::Null, runtime)
}

fn run_fixed_git_with_stdin(
    worktree_path: &Path,
    args: impl IntoIterator<Item = impl Into<std::ffi::OsString>>,
    access: WorkspaceAccess,
    stdin: StdinMode,
    runtime: OrchestrationExecutionRuntime,
) -> Result<std::process::Output> {
    if let StdinMode::Bytes(bytes) = &stdin {
        if bytes.len() >= COMBINED_CANDIDATE_MAX_BYTES {
            bail!(
                "orchestrator Git stdin reached the configured {} byte boundary",
                COMBINED_CANDIDATE_MAX_BYTES
            );
        }
    }
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
        std::ffi::OsString::from("--no-pager"),
        std::ffi::OsString::from("--no-optional-locks"),
        std::ffi::OsString::from("--literal-pathspecs"),
        std::ffi::OsString::from("-c"),
        std::ffi::OsString::from("core.fsmonitor=false"),
        std::ffi::OsString::from("-c"),
        std::ffi::OsString::from("core.untrackedCache=false"),
        std::ffi::OsString::from("-c"),
        std::ffi::OsString::from("core.splitIndex=false"),
        std::ffi::OsString::from("-c"),
        std::ffi::OsString::from("core.hooksPath=/dev/null"),
    ];
    command_args.extend(args.into_iter().map(Into::into));
    let process_spec = ProcessSpec::direct(
        "orchestrator Git command",
        git,
        command_args,
        worktree_path,
        GIT_COMMAND_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_stdin(stdin)
    .with_stdin_limit(COMBINED_CANDIDATE_MAX_BYTES)
    .with_timeout(Some(GIT_COMMAND_TIMEOUT));
    let run_result = run_process(match runtime {
        OrchestrationExecutionRuntime::Verified => {
            let profile = match access {
                WorkspaceAccess::ReadOnly => {
                    StrictOfflineWorkspaceProfile::read_only(worktree_path)
                }
                WorkspaceAccess::ReadWrite => {
                    StrictOfflineWorkspaceProfile::read_write(worktree_path)
                }
            };
            let repository = crate::git_repository::open(worktree_path)
                .context("failed to resolve Git administration roots for fixed command")?;
            let profile = profile
                .with_visible_read_only_root(repository.commondir())
                .with_hidden_root(sensitive_state_root(repository.commondir())?);
            process_spec
                .with_private_runtime_home(true)
                .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                    profile,
                ))
        }
        #[cfg(test)]
        OrchestrationExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    });
    let output = run_result?;
    if output.timed_out
        || output.process_error.is_some()
        || output.stdin_error.is_some()
        || (runtime == OrchestrationExecutionRuntime::Verified
            && !output.safety_evidence_verified())
        || output.stdout.is_truncated()
        || output.stderr.is_truncated()
    {
        bail!(
            "orchestrator Git command was not safely bounded: process_tree={:?}; side_effects={:?}; process_error={:?}; stdin_error={:?}",
            output.process_tree,
            output.side_effects,
            output.process_error,
            output.stdin_error
        );
    }
    Ok(std::process::Output {
        status: output
            .status
            .context("orchestrator Git command terminated without status")?,
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

fn command_spec(
    agent: &AgentPlan,
    summary: &AgentRunSummary,
    worktree: &SelectedWorktree,
    runtime: OrchestrationExecutionRuntime,
) -> Result<CommandRunSpec> {
    #[cfg(test)]
    if take_ready_agent_setup_fault(&agent.id) {
        bail!("injected ready-agent setup failure for '{}'", agent.id);
    }
    let recorded = summary
        .worktree
        .as_ref()
        .with_context(|| format!("agent '{}' has no selected worktree", summary.id))?;
    if recorded != worktree.record() || worktree.record().name != agent.id {
        bail!(
            "agent '{}' selected worktree does not match its exclusive execution lease",
            agent.id
        );
    }
    let working_directory = agent
        .working_directory
        .as_ref()
        .map(|path| worktree.path().join(path))
        .unwrap_or_else(|| worktree.path().to_path_buf());
    let (git_common_root, sensitive_root) = orchestration_sandbox_roots(worktree.path())?;

    Ok(CommandRunSpec {
        command: agent.command.clone(),
        workspace_root: worktree.path().to_path_buf(),
        working_directory,
        env: agent.env.clone(),
        timeout: agent.timeout,
        visible_read_only_roots: vec![git_common_root],
        hidden_roots: vec![sensitive_root],
        runtime,
    })
}

fn orchestration_sandbox_roots(worktree: &Path) -> Result<(PathBuf, PathBuf)> {
    let repository = crate::git_repository::open(worktree).with_context(|| {
        format!(
            "failed to resolve the repository common directory for {}",
            worktree.display()
        )
    })?;
    let common_dir = repository.commondir().to_path_buf();
    let sensitive = sensitive_state_root(&common_dir)
        .context("repository sensitive state could not be bound for child-process masking")?;
    Ok((common_dir, sensitive))
}

fn run_agent_validation_commands(
    agent: &AgentPlan,
    summary: &mut AgentRunSummary,
    worktree: &SelectedWorktree,
    manager: &WorktreeManager,
    expected_state: &CandidateStateSnapshot,
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
) -> bool {
    let Some(recorded) = summary.worktree.as_ref() else {
        fail_summary(summary, "agent has no selected worktree for validation");
        return false;
    };
    if recorded != worktree.record() || worktree.record().name != agent.id {
        fail_summary(
            summary,
            format!(
                "agent '{}' selected worktree does not match its exclusive execution lease",
                agent.id
            ),
        );
        return false;
    }
    let worktree_path = worktree.path().to_path_buf();
    let mut state_intact = true;

    for validation in &agent.validation_commands {
        let (run_summary, binding_intact) = run_candidate_bound_validation_command(
            validation,
            &worktree_path,
            base_oid,
            expected_state,
            runtime,
            || verify_selected_worktree_binding(manager, agent, summary, worktree),
        );
        #[cfg(test)]
        if !binding_intact {
            notify_candidate_boundary_failure(&agent.id);
        }
        state_intact &= binding_intact;
        if run_summary.status != AgentRunStatus::Succeeded {
            fail_summary(
                summary,
                validation_failure_message("agent validation", &run_summary),
            );
        }
        summary.validation.push(run_summary);
        if summary.status != AgentRunStatus::Succeeded {
            break;
        }
    }
    state_intact
}

fn run_candidate_bound_validation_command(
    validation: &ValidationCommandPlan,
    root: &Path,
    base_oid: &Oid,
    expected_state: &CandidateStateSnapshot,
    runtime: OrchestrationExecutionRuntime,
    mut verify_binding: impl FnMut() -> Result<()>,
) -> (ValidationRunSummary, bool) {
    if let Err(error) = verify_binding() {
        return (
            internal_validation_failure(
                validation,
                format!("managed worktree binding is invalid before validation: {error}"),
            ),
            false,
        );
    }
    let mut run_summary = run_validation_command(validation, root, runtime);
    if let Err(error) = verify_binding() {
        append_validation_error(
            &mut run_summary,
            format!("managed worktree binding changed during validation: {error}"),
        );
        return (run_summary, false);
    }
    match capture_consistent_candidate_state(root, base_oid, runtime) {
        Ok(after) => {
            if let Some(drift) = after.drift_from(expected_state) {
                append_validation_error(&mut run_summary, drift);
                return (run_summary, false);
            }
        }
        Err(error) => {
            append_validation_error(
                &mut run_summary,
                format!("failed to verify candidate immutability: {error}"),
            );
            return (run_summary, false);
        }
    }
    if let Err(error) = verify_binding() {
        append_validation_error(
            &mut run_summary,
            format!("managed worktree binding changed after validation capture: {error}"),
        );
        return (run_summary, false);
    }
    (run_summary, true)
}

fn append_validation_error(summary: &mut ValidationRunSummary, message: String) {
    summary.status = AgentRunStatus::Failed;
    summary.error = Some(match summary.error.take() {
        Some(existing) => format!("{existing}; {message}"),
        None => message,
    });
}

fn internal_validation_failure(
    validation: &ValidationCommandPlan,
    message: String,
) -> ValidationRunSummary {
    ValidationRunSummary {
        name: validation.name.clone(),
        command: validation.command.clone(),
        working_directory: validation.working_directory.clone(),
        timeout_seconds: validation.timeout.map(|timeout| timeout.as_secs()),
        status: AgentRunStatus::Failed,
        exit_code: None,
        duration_ms: None,
        timed_out: false,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error: Some(message),
    }
}

struct RepoValidationOutcome {
    summaries: Vec<ValidationRunSummary>,
    target: Option<RepoValidationTargetBinding>,
}

#[derive(Debug)]
struct CombinedCandidateStats {
    candidate_count: usize,
    patch_count: usize,
    aggregate_patch_bytes: usize,
    changed_paths: Vec<PathBuf>,
}

struct DisposableValidationWorktree<'a> {
    manager: &'a WorktreeManager,
    name: String,
    lease: Option<ManagedWorktreeWriteLease>,
    removed: bool,
}

impl<'a> DisposableValidationWorktree<'a> {
    fn create(manager: &'a WorktreeManager, base_oid: &Oid) -> Result<Self> {
        let sequence = REPO_VALIDATION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = normalize_agent_id(&format!("repo-validation-{}-{sequence}", process::id()))?;
        let create_options = WorktreeCreateOptions {
            agent_id: name.clone(),
            branch: None,
            base: Some(base_oid.to_string()),
            worktree_root: None,
        };
        #[cfg(test)]
        manager
            .create_for_test(create_options)
            .context("combined candidate managed worktree creation failed")?;
        #[cfg(not(test))]
        manager
            .create(create_options)
            .context("combined candidate managed worktree creation failed")?;
        let lease = match manager.acquire_write_execution_lease(&name) {
            Ok(lease) => lease,
            Err(error) => {
                let cleanup = manager.remove(&name, true, true);
                return match cleanup {
                    Ok(_) => Err(error)
                        .context("combined candidate exclusive write lease acquisition failed"),
                    Err(_) => bail!(
                        "combined candidate exclusive write lease acquisition and cleanup failed"
                    ),
                };
            }
        };
        let mut guard = Self {
            manager,
            name,
            lease: Some(lease),
            removed: false,
        };
        let verification = (|| -> Result<()> {
            guard.verify_binding()?;
            let repo = crate::git_repository::open(guard.path()?)
                .context("combined candidate managed worktree could not be opened")?;
            let head =
                head_oid(&repo).context("combined candidate worktree HEAD capture failed")?;
            let dirty = collect_status_paths(&repo)
                .context("combined candidate initial cleanliness inspection failed")?;
            if &head != base_oid || !dirty.is_empty() {
                bail!("combined candidate worktree was not clean at the captured run base");
            }
            guard.verify_binding()?;
            Ok(())
        })();
        match verification {
            Ok(()) => Ok(guard),
            Err(error) => {
                let cleanup = guard.cleanup();
                match cleanup {
                    Ok(()) => Err(error),
                    Err(_) => Err(error.context("combined candidate verification cleanup failed")),
                }
            }
        }
    }

    fn path(&self) -> Result<&Path> {
        self.lease
            .as_ref()
            .map(ManagedWorktreeWriteLease::path)
            .context("combined candidate write lease was released too early")
    }

    fn verify_binding(&self) -> Result<()> {
        let lease = self
            .lease
            .as_ref()
            .context("combined candidate write lease was released too early")?;
        let verified = self
            .manager
            .get_managed_verified(&self.name)
            .context("combined candidate managed worktree binding is invalid")?;
        if &verified != lease.record() {
            bail!(
                "combined candidate managed worktree record or Git backlink changed while its write lease was held"
            );
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        self.lease.take();
        self.manager
            .remove(&self.name, true, true)
            .context("combined candidate secure removal failed")?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for DisposableValidationWorktree<'_> {
    fn drop(&mut self) {
        if !self.removed {
            self.lease.take();
            let _ = self.manager.remove(&self.name, true, true);
        }
    }
}

fn run_repo_validation_commands(
    plan: &OrchestrationPlan,
    repo: &Path,
    manager: &WorktreeManager,
    worktrees: &[SelectedWorktree],
    base_oid: &Oid,
    candidates: &[Option<CapturedCandidate>],
    runtime: OrchestrationExecutionRuntime,
) -> RepoValidationOutcome {
    let primary_before = match capture_consistent_candidate_state(repo, base_oid, runtime) {
        Ok(state) => state,
        Err(_) => {
            return RepoValidationOutcome {
                summaries: vec![internal_repo_validation_failure(
                    "primary boundary capture",
                    "could not bind the primary worktree before combined-candidate validation",
                )],
                target: None,
            }
        }
    };
    let stats = match validate_combined_candidate_set(plan, candidates, base_oid) {
        Ok(stats) => stats,
        Err(error) => {
            return RepoValidationOutcome {
                summaries: vec![internal_repo_validation_failure(
                    "combined candidate bounds",
                    &error.to_string(),
                )],
                target: None,
            }
        }
    };
    let mut validation_worktree = match DisposableValidationWorktree::create(manager, base_oid) {
        Ok(worktree) => worktree,
        Err(error) => {
            return RepoValidationOutcome {
                summaries: vec![internal_repo_validation_failure(
                    "combined candidate construction",
                    &error.to_string(),
                )],
                target: None,
            }
        }
    };

    let execution = execute_combined_candidate_validation(
        plan,
        &validation_worktree,
        base_oid,
        candidates,
        &stats,
        runtime,
    );
    let mut outcome = match execution {
        Ok(outcome) => outcome,
        Err(error) => RepoValidationOutcome {
            summaries: vec![internal_repo_validation_failure(
                "combined candidate construction",
                &error.to_string(),
            )],
            target: None,
        },
    };

    if validation_worktree.cleanup().is_err() {
        outcome.summaries.push(internal_repo_validation_failure(
            "combined candidate cleanup",
            "exclusive removal of the disposable validation target failed",
        ));
    }

    match capture_consistent_candidate_state(repo, base_oid, runtime) {
        Ok(after) => {
            if let Some(drift) = after.drift_from(&primary_before) {
                outcome.summaries.push(internal_repo_validation_failure(
                    "primary boundary verification",
                    &format!("primary worktree changed during repo validation: {drift}"),
                ));
            }
        }
        Err(_) => outcome.summaries.push(internal_repo_validation_failure(
            "primary boundary verification",
            "could not verify the primary worktree after repo validation",
        )),
    }
    verify_agent_worktrees_after_repo_validation(
        manager,
        plan,
        worktrees,
        candidates,
        base_oid,
        runtime,
        &mut outcome.summaries,
    );
    outcome
}

fn validate_combined_candidate_set(
    plan: &OrchestrationPlan,
    candidates: &[Option<CapturedCandidate>],
    base_oid: &Oid,
) -> Result<CombinedCandidateStats> {
    if candidates.len() != plan.agents.len() {
        bail!("combined candidate set does not match the orchestration plan");
    }
    if candidates.len() > COMBINED_CANDIDATE_MAX_PATCHES {
        bail!(
            "combined candidate count exceeded the configured {} limit",
            COMBINED_CANDIDATE_MAX_PATCHES
        );
    }
    let mut candidate_count = 0_usize;
    let mut patch_count = 0_usize;
    let mut aggregate_patch_bytes = 0_usize;
    let mut changed_paths = BTreeSet::new();
    for (agent, candidate) in plan.agents.iter().zip(candidates) {
        let candidate = candidate.as_ref().with_context(|| {
            format!("successful agent '{}' has no captured candidate", agent.id)
        })?;
        candidate_count += 1;
        if candidate.binding.version != CANDIDATE_BINDING_VERSION
            || candidate.binding.base_oid != base_oid.to_string()
            || candidate.binding.diff_oid != hash_candidate_component(&candidate.patch)?.to_string()
            || candidate.binding.patch_bytes != candidate.patch.len() as u64
        {
            bail!("candidate binding for agent '{}' drifted", agent.id);
        }
        if !candidate.patch.is_empty() {
            patch_count += 1;
        }
        aggregate_patch_bytes = aggregate_patch_bytes
            .checked_add(candidate.patch.len())
            .context("combined candidate patch bytes overflowed")?;
        if aggregate_patch_bytes >= COMBINED_CANDIDATE_MAX_BYTES {
            bail!(
                "combined candidate reached the configured {} byte aggregate boundary",
                COMBINED_CANDIDATE_MAX_BYTES
            );
        }
        for path in &candidate.binding.changed_paths {
            if !agent
                .paths
                .iter()
                .any(|claim| path_is_covered_by_claim(path, claim))
            {
                bail!(
                    "candidate for agent '{}' contains unclaimed path '{}'",
                    agent.id,
                    path.display()
                );
            }
            if !changed_paths.insert(path.clone()) {
                bail!(
                    "combined candidate contains duplicate changed path '{}'",
                    path.display()
                );
            }
        }
    }
    if changed_paths.len() > CANDIDATE_MAX_CHANGED_PATHS {
        bail!(
            "combined candidate changed-path count exceeded the configured {} limit",
            CANDIDATE_MAX_CHANGED_PATHS
        );
    }
    Ok(CombinedCandidateStats {
        candidate_count,
        patch_count,
        aggregate_patch_bytes,
        changed_paths: changed_paths.into_iter().collect(),
    })
}

fn execute_combined_candidate_validation(
    plan: &OrchestrationPlan,
    validation_worktree: &DisposableValidationWorktree<'_>,
    base_oid: &Oid,
    candidates: &[Option<CapturedCandidate>],
    stats: &CombinedCandidateStats,
    runtime: OrchestrationExecutionRuntime,
) -> Result<RepoValidationOutcome> {
    validation_worktree.verify_binding()?;
    let validation_path = validation_worktree.path()?;
    apply_captured_candidate_patches(plan, validation_path, candidates, runtime, || {
        validation_worktree.verify_binding()
    })?;

    validation_worktree.verify_binding()?;
    let combined_state = capture_consistent_candidate_state(validation_path, base_oid, runtime)
        .context("combined candidate binding capture failed")?;
    validation_worktree.verify_binding()?;
    if combined_state.changed_paths != stats.changed_paths {
        bail!("materialized combined candidate paths did not match the captured union");
    }
    let combined = capture_bound_candidate(validation_path, base_oid, &combined_state, runtime)
        .context("materialized combined candidate diff capture failed")?;
    validation_worktree.verify_binding()?;
    let target = repo_validation_target_binding(stats, base_oid, &combined);
    let summaries = run_bound_repo_validation_commands(
        plan,
        validation_worktree,
        base_oid,
        &combined_state,
        runtime,
    );
    Ok(RepoValidationOutcome {
        summaries,
        target: Some(target),
    })
}

fn apply_captured_candidate_patches(
    plan: &OrchestrationPlan,
    validation_path: &Path,
    candidates: &[Option<CapturedCandidate>],
    runtime: OrchestrationExecutionRuntime,
    mut verify_binding: impl FnMut() -> Result<()>,
) -> Result<()> {
    for (agent, candidate) in plan.agents.iter().zip(candidates) {
        let candidate = candidate
            .as_ref()
            .with_context(|| format!("candidate for agent '{}' disappeared", agent.id))?;
        if candidate.patch.is_empty() {
            continue;
        }
        verify_binding()?;
        let output = run_fixed_git_with_stdin(
            validation_path,
            ["apply", "--binary", "--whitespace=nowarn", "-"],
            WorkspaceAccess::ReadWrite,
            StdinMode::Bytes(candidate.patch.clone()),
            runtime,
        )
        .with_context(|| {
            format!(
                "combined candidate patch application failed for agent '{}'",
                agent.id
            )
        })?;
        if !output.status.success() {
            bail!(
                "combined candidate patch conflicted for agent '{}'",
                agent.id
            );
        }
        verify_binding()?;
    }
    Ok(())
}

fn repo_validation_target_binding(
    stats: &CombinedCandidateStats,
    base_oid: &Oid,
    combined: &CapturedCandidate,
) -> RepoValidationTargetBinding {
    RepoValidationTargetBinding {
        version: CANDIDATE_BINDING_VERSION,
        kind: if stats.changed_paths.is_empty() {
            RepoValidationTargetKind::BaseNoChanges
        } else {
            RepoValidationTargetKind::CombinedCandidate
        },
        base_oid: base_oid.to_string(),
        combined_diff_oid: combined.binding.diff_oid.clone(),
        changed_paths: stats.changed_paths.clone(),
        candidate_count: stats.candidate_count,
        patch_count: stats.patch_count,
        aggregate_patch_bytes: stats.aggregate_patch_bytes as u64,
    }
}

fn run_bound_repo_validation_commands(
    plan: &OrchestrationPlan,
    validation_worktree: &DisposableValidationWorktree<'_>,
    base_oid: &Oid,
    expected_state: &CandidateStateSnapshot,
    runtime: OrchestrationExecutionRuntime,
) -> Vec<ValidationRunSummary> {
    let mut summaries = Vec::new();
    let validation_path = match validation_worktree.path() {
        Ok(path) => path,
        Err(error) => {
            return vec![internal_repo_validation_failure(
                "combined candidate lease",
                &error.to_string(),
            )]
        }
    };
    for validation in &plan.repo_validation_commands {
        let (mut run_summary, binding_intact) = run_candidate_bound_validation_command(
            validation,
            validation_path,
            base_oid,
            expected_state,
            runtime,
            || validation_worktree.verify_binding(),
        );
        if !binding_intact
            && run_summary
                .error
                .as_deref()
                .is_some_and(|error| error.contains("candidate-relevant state changed"))
        {
            let drift = run_summary.error.take().unwrap_or_default();
            run_summary.error = Some(format!(
                "repo validation mutated the combined candidate: {drift}"
            ));
        }
        let failed = run_summary.status != AgentRunStatus::Succeeded;
        summaries.push(run_summary);
        if failed {
            break;
        }
    }
    summaries
}

fn verify_agent_worktrees_after_repo_validation(
    manager: &WorktreeManager,
    plan: &OrchestrationPlan,
    worktrees: &[SelectedWorktree],
    candidates: &[Option<CapturedCandidate>],
    base_oid: &Oid,
    runtime: OrchestrationExecutionRuntime,
    summaries: &mut Vec<ValidationRunSummary>,
) {
    if worktrees.len() != candidates.len() || worktrees.len() != plan.agents.len() {
        summaries.push(internal_repo_validation_failure(
            "agent candidate verification",
            "agent worktree lease set no longer matches the candidate set",
        ));
        return;
    }
    for ((agent, worktree), candidate) in plan.agents.iter().zip(worktrees).zip(candidates) {
        let Some(candidate) = candidate else {
            continue;
        };
        let verified = manager
            .get_managed_verified(&agent.id)
            .and_then(|record| {
                if &record != worktree.record() {
                    bail!("managed worktree record drifted");
                }
                Ok(())
            })
            .and_then(|()| capture_consistent_candidate_state(worktree.path(), base_oid, runtime))
            .and_then(|state| ensure_candidate_binding_matches_state(&candidate.binding, &state))
            .and_then(|()| {
                let record = manager.get_managed_verified(&agent.id)?;
                if &record != worktree.record() {
                    bail!("managed worktree record drifted after capture");
                }
                Ok(())
            });
        if verified.is_err() {
            summaries.push(internal_repo_validation_failure(
                "agent candidate verification",
                "an agent worktree changed while the combined candidate was validated",
            ));
            break;
        }
    }
}

fn internal_repo_validation_failure(name: &str, message: &str) -> ValidationRunSummary {
    ValidationRunSummary {
        name: Some(name.to_string()),
        command: "maco internal combined-candidate gate".to_string(),
        working_directory: None,
        timeout_seconds: None,
        status: AgentRunStatus::Failed,
        exit_code: None,
        duration_ms: None,
        timed_out: false,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error: Some(message.to_string()),
    }
}

fn run_validation_command(
    validation: &ValidationCommandPlan,
    root: &Path,
    runtime: OrchestrationExecutionRuntime,
) -> ValidationRunSummary {
    let working_directory = validation
        .working_directory
        .as_ref()
        .map(|path| root.join(path))
        .unwrap_or_else(|| root.to_path_buf());
    let (visible_read_only_roots, hidden_roots) = match orchestration_sandbox_roots(root) {
        Ok((common_dir, state_root)) => (vec![common_dir], vec![state_root]),
        Err(error) => {
            let mut summary = validation_summary_from_result(
                validation,
                Err(ProcessRunError::Spawn {
                    label: "validation state masking".to_string(),
                    command: validation.command.clone(),
                    current_dir: working_directory.clone(),
                    source: std::io::Error::other(error.to_string()),
                }),
            );
            summary.error = Some(format!(
                "failed to bind repository sensitive state before validation: {error:#}"
            ));
            return summary;
        }
    };
    let result = run_agent_command(CommandRunSpec {
        command: validation.command.clone(),
        workspace_root: root.to_path_buf(),
        working_directory,
        env: validation.env.clone(),
        timeout: validation.timeout,
        visible_read_only_roots,
        hidden_roots,
        runtime,
    });
    validation_summary_from_result(validation, result)
}

fn validation_summary_from_result(
    validation: &ValidationCommandPlan,
    result: Result<CommandRunResult, ProcessRunError>,
) -> ValidationRunSummary {
    let mut summary = ValidationRunSummary {
        name: validation.name.clone(),
        command: validation.command.clone(),
        working_directory: validation.working_directory.clone(),
        timeout_seconds: validation.timeout.map(|timeout| timeout.as_secs()),
        status: AgentRunStatus::Pending,
        exit_code: None,
        duration_ms: None,
        timed_out: false,
        stdout: OutputSummary::default(),
        stderr: OutputSummary::default(),
        error: None,
    };

    match result {
        Ok(result) => {
            summary.exit_code = result.status.and_then(|status| status.code());
            summary.duration_ms = Some(result.duration_ms);
            summary.timed_out = result.timed_out;
            summary.stdout = result.stdout;
            summary.stderr = result.stderr;
            if let Some(error) = result.process_error {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(error);
            } else if result.timed_out {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match summary.timeout_seconds {
                    Some(seconds) => {
                        format!("validation command timed out after {seconds} seconds")
                    }
                    None => "validation command timed out".to_string(),
                });
            } else if result.status.is_some_and(|status| status.success()) {
                summary.status = AgentRunStatus::Succeeded;
            } else {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match result.status.and_then(|status| status.code()) {
                    Some(code) => format!("validation command exited with status {code}"),
                    None => "validation command terminated without an exit code".to_string(),
                });
            }
        }
        Err(error) => {
            summary.status = AgentRunStatus::Failed;
            summary.error = Some(format!("failed to run validation command: {error}"));
        }
    }

    summary
}

fn validation_failure_message(scope: &str, summary: &ValidationRunSummary) -> String {
    let label = summary.name.as_deref().unwrap_or(summary.command.as_str());
    let reason = summary
        .error
        .as_deref()
        .unwrap_or("validation command failed");
    format!("{scope} '{label}' failed: {reason}")
}

#[derive(Debug, Clone)]
struct CommandRunSpec {
    command: String,
    workspace_root: PathBuf,
    working_directory: PathBuf,
    env: BTreeMap<String, String>,
    timeout: Option<Duration>,
    visible_read_only_roots: Vec<PathBuf>,
    hidden_roots: Vec<PathBuf>,
    runtime: OrchestrationExecutionRuntime,
}

fn strict_command_profile(spec: &CommandRunSpec) -> StrictOfflineWorkspaceProfile {
    let profile = spec.visible_read_only_roots.iter().fold(
        StrictOfflineWorkspaceProfile::read_write(&spec.workspace_root),
        |profile, visible| profile.with_visible_read_only_root(visible),
    );
    spec.hidden_roots
        .iter()
        .fold(profile, |profile, hidden| profile.with_hidden_root(hidden))
}

fn run_agent_command(spec: CommandRunSpec) -> Result<CommandRunResult, ProcessRunError> {
    let strict_profile = strict_command_profile(&spec);
    let mut environment = sandbox_environment();
    environment.extend(spec.env);
    let process_spec = ProcessSpec::shell(
        "agent command",
        Shell::for_current_platform(),
        spec.command,
        spec.working_directory,
        OUTPUT_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_timeout(spec.timeout);
    let mut output = run_process(match spec.runtime {
        OrchestrationExecutionRuntime::Verified => process_spec
            .with_private_runtime_home(true)
            .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
                strict_profile,
            )),
        #[cfg(test)]
        OrchestrationExecutionRuntime::NonpublishableSimulation => process_spec
            .with_containment(crate::process_runner::ContainmentPolicy::TrustedBestEffort),
    })?;

    let safety_verified = output.safety_evidence_verified();
    let safety_evidence = (output.process_tree, output.side_effects);
    let mut process_error = output.process_error.take();
    if let Some(stdin_error) = output.stdin_error.take() {
        process_error = Some(match process_error {
            Some(existing) => format!("{existing}; {stdin_error}"),
            None => stdin_error,
        });
    }
    if spec.runtime == OrchestrationExecutionRuntime::Verified && !safety_verified {
        let safety_error = format!(
            "process safety evidence was not verified: process_tree={:?}; side_effects={:?}",
            safety_evidence.0, safety_evidence.1
        );
        process_error = Some(match process_error {
            Some(existing) => format!("{existing}; {safety_error}"),
            None => safety_error,
        });
    }

    Ok(CommandRunResult {
        status: output.status,
        duration_ms: output.duration_ms(),
        timed_out: output.timed_out,
        stdout: summarize_output(&output.stdout),
        stderr: summarize_output(&output.stderr),
        process_error,
    })
}

#[derive(Debug, Clone)]
struct CommandRunResult {
    status: Option<ExitStatus>,
    duration_ms: u64,
    timed_out: bool,
    stdout: OutputSummary,
    stderr: OutputSummary,
    process_error: Option<String>,
}

fn apply_command_result(
    summary: &mut AgentRunSummary,
    result: Result<CommandRunResult, ProcessRunError>,
) {
    match result {
        Ok(result) => {
            summary.exit_code = result.status.and_then(|status| status.code());
            summary.duration_ms = Some(result.duration_ms);
            summary.timed_out = result.timed_out;
            summary.stdout = result.stdout;
            summary.stderr = result.stderr;
            if let Some(error) = result.process_error {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(error);
            } else if result.timed_out {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match summary.timeout_seconds {
                    Some(seconds) => format!("command timed out after {seconds} seconds"),
                    None => "command timed out".to_string(),
                });
            } else if result.status.is_some_and(|status| status.success()) {
                summary.status = AgentRunStatus::Succeeded;
                summary.error = None;
            } else {
                summary.status = AgentRunStatus::Failed;
                summary.error = Some(match result.status.and_then(|status| status.code()) {
                    Some(code) => format!("command exited with status {code}"),
                    None => "command terminated without an exit code".to_string(),
                });
            }
        }
        Err(error) => {
            summary.status = AgentRunStatus::Failed;
            summary.error = Some(format!("failed to run command: {error}"));
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    if millis > u64::MAX as u128 {
        u64::MAX
    } else {
        millis as u64
    }
}

fn summarize_output(output: &CapturedBytes) -> OutputSummary {
    let summary = output.summarize_chars(OUTPUT_CHAR_LIMIT);
    OutputSummary {
        text: summary.text,
        truncated: summary.truncated,
    }
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

struct CheckpointView<'a> {
    repo: &'a Path,
    repo_head: &'a Oid,
    plan_file: &'a Path,
    plan: &'a OrchestrationPlan,
    keep_claims: bool,
    worktree_reuse_policy: WorktreeReusePolicy,
    success: bool,
    agents: &'a [AgentRunSummary],
    repo_validation: &'a [ValidationRunSummary],
    repo_validation_target: Option<&'a RepoValidationTargetBinding>,
    released_claims: &'a [PathClaim],
    release_errors: &'a [String],
    released_semantic_intents: &'a [SemanticIntent],
    semantic_release_errors: &'a [String],
}

struct RunCheckpointWriter {
    slot: ReservedOutputFile,
    reference: AuthenticatedCheckpointReference,
    journal: StateJournal,
}

struct CheckpointReferenceReservation {
    slot: Option<ReservedOutputFile>,
}

impl CheckpointReferenceReservation {
    fn new(slot: ReservedOutputFile) -> Self {
        Self { slot: Some(slot) }
    }

    fn slot_mut(&mut self) -> Result<&mut ReservedOutputFile> {
        self.slot
            .as_mut()
            .context("checkpoint reference reservation was consumed")
    }

    fn take(&mut self) -> Result<ReservedOutputFile> {
        self.slot
            .take()
            .context("checkpoint reference reservation was consumed")
    }

    fn cleanup(&mut self) -> Result<()> {
        match self.slot.take() {
            Some(slot) => slot.remove(),
            None => Ok(()),
        }
    }
}

impl Drop for CheckpointReferenceReservation {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

impl RunCheckpointWriter {
    fn write(&mut self, checkpoint: &RunCheckpoint) -> Result<()> {
        self.verify_external_reference()?;
        let phase = if checkpoint.stage == RunCheckpointStage::Final {
            PHASE_FINAL.to_string()
        } else {
            format!(
                "{CHECKPOINT_SNAPSHOT_PHASE_PREFIX}{}",
                checkpoint_stage_name(checkpoint.stage)
            )
        };
        self.journal
            .append(&phase, None, &encode_run_checkpoint(checkpoint)?)?;
        self.verify_external_reference()
    }

    fn agent_event(&mut self, phase: &str, subject: &str, agent: &AgentCheckpoint) -> Result<()> {
        self.event(phase, Some(subject), &encode_agent_checkpoint(agent)?)
    }

    fn event<T: Serialize>(
        &mut self,
        phase: &str,
        subject: Option<&str>,
        payload: &T,
    ) -> Result<()> {
        #[cfg(test)]
        if take_checkpoint_event_failure(&self.reference.journal.run_id, phase) {
            bail!("injected checkpoint event failure at phase '{phase}'");
        }
        self.verify_external_reference()?;
        self.journal.append(phase, subject, payload)?;
        #[cfg(test)]
        if take_checkpoint_event_failure(&self.reference.journal.run_id, &format!("after:{phase}"))
        {
            bail!("injected post-append checkpoint failure at phase '{phase}'");
        }
        self.verify_external_reference()
    }

    fn verify_external_reference(&self) -> Result<()> {
        let contents = self.slot.read_bounded(CHECKPOINT_REFERENCE_MAX_BYTES)?;
        let observed: AuthenticatedCheckpointReference = serde_json::from_slice(&contents)
            .with_context(|| {
                format!(
                    "failed to re-read authenticated checkpoint reference {}",
                    self.slot.path().display()
                )
            })?;
        if observed != self.reference {
            bail!("external checkpoint reference changed during the active run");
        }
        verify_checkpoint_reference(self.journal.authenticator(), &observed)
    }

    fn reject_inside_worktrees(&self, worktrees: &[SelectedWorktree]) -> Result<()> {
        let checkpoint_root = self
            .slot
            .path()
            .parent()
            .context("checkpoint reference has no parent directory")?
            .canonicalize()
            .context("failed to canonicalize checkpoint reference root")?;
        for worktree in worktrees {
            let worktree_root = worktree.path().canonicalize().with_context(|| {
                format!(
                    "failed to canonicalize selected worktree {}",
                    worktree.path().display()
                )
            })?;
            if checkpoint_root.starts_with(&worktree_root) {
                bail!(
                    "checkpoint reference root {} must not be inside untrusted worktree {}",
                    checkpoint_root.display(),
                    worktree_root.display()
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn install_checkpoint_event_failure(run_id: &str, phase: &str) {
    let hook = CHECKPOINT_EVENT_FAILURE_HOOK.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut hooks = hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        !hooks
            .iter()
            .any(|hook| hook.run_id == run_id && hook.phase == phase),
        "checkpoint event failure hook already installed"
    );
    hooks.push(CheckpointEventFailureHook {
        run_id: run_id.to_string(),
        phase: phase.to_string(),
    });
}

#[cfg(test)]
fn take_checkpoint_event_failure(run_id: &str, phase: &str) -> bool {
    let hook = CHECKPOINT_EVENT_FAILURE_HOOK.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut hooks = hook.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(position) = hooks
        .iter()
        .position(|hook| hook.run_id == run_id && hook.phase == phase)
    {
        hooks.remove(position);
        true
    } else {
        false
    }
}

fn prepare_run_checkpoint_writer(
    controls: &OrchestrationRunControls,
    run_id: &Option<RunId>,
    repo: &Path,
    summaries: &[AgentRunSummary],
) -> Result<Option<RunCheckpointWriter>> {
    let Some(directory) = controls.checkpoint_dir.as_deref() else {
        return Ok(None);
    };
    let run_id = run_id
        .as_ref()
        .context("checkpoint directory requires a resolved run id")?;
    let root = SecureOutputRoot::open_or_create(directory)?;
    for summary in summaries {
        if let Some(worktree) = &summary.worktree {
            root.reject_inside(&worktree.path)?;
        }
    }
    let name = checkpoint_file_name(run_id);
    let slot = root.reserve(OsStr::new(&name)).with_context(|| {
        format!(
            "checkpoint '{}' already exists or cannot be reserved for a fresh run; use `maco orchestrate resume --checkpoint {}` for an existing run",
            run_id.as_str(),
            root.path().join(&name).display()
        )
    })?;
    let mut reservation = CheckpointReferenceReservation::new(slot);
    let result = (|| -> Result<RunCheckpointWriter> {
        let auth = repository_auth_writer(repo)?.into_authenticator()?;
        let journal = StateJournal::create(auth, run_id.as_str())?;
        let reference =
            signed_checkpoint_reference(journal.authenticator(), repo, journal.identity())?;
        let reference_path = reservation
            .slot
            .as_ref()
            .map(|slot| slot.path().to_path_buf())
            .context("checkpoint reference reservation was consumed")?;
        reservation
            .slot_mut()?
            .write_json_atomic(&reference, CHECKPOINT_REFERENCE_MAX_BYTES)
            .with_context(|| {
                format!(
                    "failed to write authenticated checkpoint reference {}",
                    reference_path.display()
                )
            })?;
        let slot = reservation.take()?;
        let writer = RunCheckpointWriter {
            slot,
            reference,
            journal,
        };
        writer.verify_external_reference()?;
        Ok(writer)
    })();
    match result {
        Ok(writer) => Ok(Some(writer)),
        Err(error) => match reservation.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "also failed to clean checkpoint reference reservation: {cleanup:#}"
            ))),
        },
    }
}

pub fn write_run_checkpoint(directory: &Path, checkpoint: &RunCheckpoint) -> Result<PathBuf> {
    if checkpoint.version != CHECKPOINT_STATE_VERSION {
        bail!(
            "checkpoint version {} is not writable; create a new v{} run",
            checkpoint.version,
            CHECKPOINT_STATE_VERSION
        );
    }
    let controls = OrchestrationRunControls {
        run_id: Some(checkpoint.run_id.clone()),
        checkpoint_dir: Some(directory.to_path_buf()),
        worktree_reuse_policy: Some(checkpoint.worktree_reuse_policy),
        semantic_coordination: checkpoint.semantic_coordination,
    };
    let mut writer = prepare_run_checkpoint_writer(
        &controls,
        &Some(checkpoint.run_id.clone()),
        &checkpoint.repo,
        &[],
    )?
    .context("checkpoint writer was not prepared")?;
    writer.write(checkpoint)?;
    Ok(writer.slot.path().to_path_buf())
}

pub fn read_run_checkpoint(path: &Path) -> Result<RunCheckpoint> {
    let opened = open_run_checkpoint(path, None)?;
    Ok(opened.checkpoint)
}

struct OpenedRunCheckpoint {
    checkpoint: RunCheckpoint,
    repo: PathBuf,
    writer: RunCheckpointWriter,
}

fn open_run_checkpoint(path: &Path, repo_override: Option<&Path>) -> Result<OpenedRunCheckpoint> {
    let parent = path
        .parent()
        .with_context(|| format!("checkpoint must have a parent: {}", path.display()))?;
    let name = path
        .file_name()
        .with_context(|| format!("checkpoint must have a file name: {}", path.display()))?;
    let root = SecureOutputRoot::open_private(parent)?;
    let slot = root.open_existing_leaf(name)?;
    let contents = slot.read_bounded(CHECKPOINT_REFERENCE_MAX_BYTES)?;
    let value: serde_json::Value = serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse checkpoint envelope {}", path.display()))?;
    let version = value.get("version").and_then(serde_json::Value::as_u64);
    if version != Some(u64::from(CHECKPOINT_STATE_VERSION)) {
        let observed = version
            .map(|value| value.to_string())
            .unwrap_or_else(|| "missing".to_string());
        bail!(
            "checkpoint version {} in {} is unauthenticated or unsupported; start a new run using v{}",
            observed,
            path.display(),
            CHECKPOINT_STATE_VERSION
        );
    }
    let reference: AuthenticatedCheckpointReference = serde_json::from_value(value)
        .with_context(|| format!("invalid v3 checkpoint envelope {}", path.display()))?;
    validate_checkpoint_reference_bounds(&reference)?;

    // The repository hint is used only to locate a candidate key. No run id,
    // plan path, journal path, or checkpoint payload is authoritative yet.
    let hinted_repo = reference.repository_hint.to_path_buf()?;
    let repo = discover_repo_root(repo_override.unwrap_or(&hinted_repo))?;
    let authenticator = repository_authenticator_key_only(&repo)?;
    verify_checkpoint_reference(&authenticator, &reference)?;
    validate_repository_authenticated_state(&repo, &authenticator)?;
    let journal = StateJournal::open(authenticator, &reference.journal)?;
    let checkpoint = latest_authenticated_checkpoint(&journal)?;
    if checkpoint.run_id.as_str() != reference.journal.run_id {
        bail!("authenticated checkpoint snapshot run id does not match its journal");
    }
    let expected_path = checkpoint_path(parent, &checkpoint.run_id);
    if expected_path != path {
        bail!(
            "authenticated checkpoint file {} does not match run id '{}'; expected {}",
            path.display(),
            checkpoint.run_id.as_str(),
            expected_path.display()
        );
    }
    let signed_repo = discover_repo_root(&hinted_repo)?;
    if signed_repo != repo || checkpoint.repo != repo {
        bail!("authenticated checkpoint belongs to a different repository path");
    }
    let writer = RunCheckpointWriter {
        slot,
        reference,
        journal,
    };
    writer.verify_external_reference()?;
    Ok(OpenedRunCheckpoint {
        checkpoint,
        repo,
        writer,
    })
}

fn signed_checkpoint_reference(
    authenticator: &RepositoryAuthenticator,
    repo: &Path,
    journal: &JournalIdentity,
) -> Result<AuthenticatedCheckpointReference> {
    let repository_hint = LosslessPath::from_path(&discover_repo_root(repo)?)?;
    let mut reference = AuthenticatedCheckpointReference {
        version: CHECKPOINT_STATE_VERSION,
        repository_hint,
        journal: journal.clone(),
        mac: AuthenticationTag::zero(),
    };
    validate_checkpoint_reference_bounds(&reference)?;
    reference.mac = authenticator.sign(
        CHECKPOINT_REFERENCE_DOMAIN,
        &checkpoint_reference_mac_payload(&reference)?,
    )?;
    Ok(reference)
}

fn verify_checkpoint_reference(
    authenticator: &RepositoryAuthenticator,
    reference: &AuthenticatedCheckpointReference,
) -> Result<()> {
    validate_checkpoint_reference_bounds(reference)?;
    authenticator.verify_repository_binding(&reference.journal.repository)?;
    authenticator.verify_tag(
        CHECKPOINT_REFERENCE_DOMAIN,
        &checkpoint_reference_mac_payload(reference)?,
        &reference.mac,
    )
}

fn checkpoint_reference_mac_payload(
    reference: &AuthenticatedCheckpointReference,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&CheckpointReferenceMacPayload {
        version: reference.version,
        repository_hint: &reference.repository_hint,
        journal: &reference.journal,
    })
    .context("failed to encode checkpoint reference MAC payload")
}

fn validate_checkpoint_reference_bounds(
    reference: &AuthenticatedCheckpointReference,
) -> Result<()> {
    if reference.version != CHECKPOINT_STATE_VERSION {
        bail!("checkpoint reference exceeds its bounded canonical format");
    }
    let repository_hint = reference.repository_hint.to_path_buf()?;
    if reference.repository_hint.storage_bytes() > 4096
        || repository_hint.components().count() > 256
    {
        bail!("checkpoint reference exceeds its bounded canonical format");
    }
    reference.mac.validate()?;
    crate::state_journal::validate_journal_identity(&reference.journal)
}

fn latest_authenticated_checkpoint(journal: &StateJournal) -> Result<RunCheckpoint> {
    validate_command_phase_history(journal)?;
    let (snapshot_index, record) = journal
        .records()
        .iter()
        .enumerate()
        .rev()
        .find(|(_, record)| {
            record.phase == PHASE_FINAL
                || record.phase.starts_with(CHECKPOINT_SNAPSHOT_PHASE_PREFIX)
        })
        .context("authenticated checkpoint journal has no resumable snapshot; start a new run")?;
    let mut checkpoint = decode_run_checkpoint(record.payload.clone())
        .context("authenticated checkpoint snapshot is malformed")?;
    if checkpoint.version != CHECKPOINT_STATE_VERSION {
        bail!("authenticated checkpoint snapshot is not v3; start a new run");
    }
    for record in &journal.records()[snapshot_index.saturating_add(1)..] {
        if !matches!(
            record.phase.as_str(),
            PHASE_COMMAND_COMPLETED | PHASE_CANDIDATE_CAPTURED
        ) {
            continue;
        }
        let agent = decode_agent_checkpoint(record.payload.clone())
            .context("authenticated candidate checkpoint payload is malformed")?;
        let slot = checkpoint
            .agents
            .iter_mut()
            .find(|candidate| candidate.id == agent.id)
            .with_context(|| {
                format!(
                    "authenticated candidate event references unknown agent '{}'",
                    agent.id
                )
            })?;
        *slot = agent;
    }
    Ok(checkpoint)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandJournalState {
    Started,
    Completed,
    CandidateCaptured,
}

fn validate_command_phase_history(journal: &StateJournal) -> Result<()> {
    let mut states = BTreeMap::<String, CommandJournalState>::new();
    for record in journal.records() {
        let Some(subject) = record.subject.as_ref() else {
            continue;
        };
        match record.phase.as_str() {
            PHASE_COMMAND_STARTED => {
                if states.contains_key(subject) {
                    bail!(
                        "checkpoint records a second command start for agent '{}'; refusing possible double execution",
                        subject
                    );
                }
                states.insert(subject.clone(), CommandJournalState::Started);
            }
            PHASE_COMMAND_COMPLETED => {
                if states.get(subject) != Some(&CommandJournalState::Started) {
                    bail!(
                        "checkpoint command completion for agent '{}' has no unique preceding start",
                        subject
                    );
                }
                let completed = decode_agent_checkpoint(record.payload.clone())
                    .context("authenticated command completion payload is malformed")?;
                if completed.id != *subject || completed.command_completed_binding.is_none() {
                    bail!(
                        "checkpoint command completion for agent '{}' lacks exact worktree state binding evidence",
                        subject
                    );
                }
                states.insert(subject.clone(), CommandJournalState::Completed);
            }
            PHASE_CANDIDATE_CAPTURED => match states.get(subject) {
                Some(CommandJournalState::Completed)
                | Some(CommandJournalState::CandidateCaptured) => {
                    states.insert(subject.clone(), CommandJournalState::CandidateCaptured);
                }
                None => {
                    // A completed candidate may be recaptured and revalidated during resume.
                }
                Some(CommandJournalState::Started) => {
                    bail!(
                        "checkpoint candidate for agent '{}' was captured without a completed command",
                        subject
                    );
                }
            },
            _ => {}
        }
    }
    for (agent, state) in states {
        match state {
            CommandJournalState::Started => bail!(
                "checkpoint shows command_started for agent '{}' without durable completion; execution outcome is uncertain and will not be rerun automatically, start a new run",
                agent
            ),
            CommandJournalState::Completed => {}
            CommandJournalState::CandidateCaptured => {}
        }
    }
    Ok(())
}

fn checkpoint_stage_name(stage: RunCheckpointStage) -> &'static str {
    match stage {
        RunCheckpointStage::WorktreesSelected => "worktrees_selected",
        RunCheckpointStage::ClaimsAcquired => "claims_acquired",
        RunCheckpointStage::AgentsCompleted => "agents_completed",
        RunCheckpointStage::Final => PHASE_FINAL,
    }
}

pub fn checkpoint_path(directory: &Path, run_id: &RunId) -> PathBuf {
    directory.join(checkpoint_file_name(run_id))
}

fn checkpoint_file_name(run_id: &RunId) -> String {
    format!("{}.json", run_id.as_str())
}

fn write_checkpoint_if_configured(
    controls: &OrchestrationRunControls,
    stage: RunCheckpointStage,
    run_id: &Option<RunId>,
    writer: Option<&mut RunCheckpointWriter>,
    view: CheckpointView<'_>,
) -> Result<()> {
    if controls.checkpoint_dir.is_none() {
        return Ok(());
    }
    let Some(run_id) = run_id.clone() else {
        return Ok(());
    };
    let writer = writer.context("checkpoint controls omitted a prepared secure writer")?;

    let checkpoint = RunCheckpoint {
        version: CHECKPOINT_STATE_VERSION,
        run_id,
        stage,
        repo: view.repo.to_path_buf(),
        repo_head: Some(view.repo_head.to_string()),
        plan_file: view.plan_file.to_path_buf(),
        plan_snapshot: Some(CheckpointPlanSnapshot::from(view.plan)),
        keep_claims: view.keep_claims,
        worktree_reuse_policy: view.worktree_reuse_policy,
        semantic_coordination: controls.semantic_coordination,
        success: view.success,
        agents: view.agents.iter().map(AgentCheckpoint::from).collect(),
        repo_validation: view.repo_validation.to_vec(),
        repo_validation_target: view.repo_validation_target.cloned(),
        released_claims: view.released_claims.to_vec(),
        release_errors: view.release_errors.to_vec(),
        released_semantic_intents: view.released_semantic_intents.to_vec(),
        semantic_release_errors: view.semantic_release_errors.to_vec(),
        updated_unix_ms: unix_time_millis(),
    };
    writer.write(&checkpoint)
}

impl From<&AgentRunSummary> for AgentCheckpoint {
    fn from(summary: &AgentRunSummary) -> Self {
        Self {
            id: summary.id.clone(),
            status: summary.status,
            worktree: summary
                .worktree
                .as_ref()
                .map(CheckpointWorktreeRecord::from),
            claim: summary.claim.clone(),
            semantic_intent: summary.semantic_intent.clone(),
            semantic_conflicts: summary.semantic_conflicts.clone(),
            changed_paths: summary.changed_paths.clone(),
            unclaimed_changed_paths: summary.unclaimed_changed_paths.clone(),
            validation: summary.validation.clone(),
            candidate_binding: summary.candidate_binding.clone(),
            command_completed_binding: summary.command_completed_binding.clone(),
            error: summary.error.clone(),
        }
    }
}

impl From<&WorktreeRecord> for CheckpointWorktreeRecord {
    fn from(record: &WorktreeRecord) -> Self {
        Self {
            name: record.name.clone(),
            path: record.path.clone(),
            branch: record.branch.clone(),
        }
    }
}

impl From<&CheckpointWorktreeRecord> for WorktreeRecord {
    fn from(record: &CheckpointWorktreeRecord) -> Self {
        Self {
            name: record.name.clone(),
            path: record.path.clone(),
            branch: record.branch.clone(),
        }
    }
}

fn resolve_run_id(controls: &OrchestrationRunControls) -> Result<Option<RunId>> {
    match (&controls.run_id, &controls.checkpoint_dir) {
        (Some(run_id), _) => Ok(Some(run_id.clone())),
        (None, Some(_)) => generated_run_id().map(Some),
        (None, None) => Ok(None),
    }
}

fn generated_run_id() -> Result<RunId> {
    RunId::new(format!("run-{}-{}", unix_time_millis(), process::id()))
}

fn unix_time_millis() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration_millis(duration),
        Err(_) => 0,
    }
}

struct ClaimCleanupGuard {
    store: SyncStore,
    tokens: Vec<ClaimToken>,
    armed: bool,
    early_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl ClaimCleanupGuard {
    fn new(store: SyncStore, early_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> Self {
        Self {
            store,
            tokens: Vec::new(),
            armed: true,
            early_errors,
        }
    }

    fn track(&mut self, token: ClaimToken) {
        self.tokens.push(token);
    }

    fn set_tokens(&mut self, tokens: Vec<ClaimToken>) {
        self.tokens = tokens;
    }

    fn release(&mut self) -> (Vec<PathClaim>, Vec<String>) {
        self.armed = false;
        release_claims(&self.store, std::mem::take(&mut self.tokens))
    }

    fn disarm_keep(&mut self) {
        self.armed = false;
        self.tokens.clear();
    }
}

impl Drop for ClaimCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (_, errors) = release_claims(&self.store, std::mem::take(&mut self.tokens));
        if !errors.is_empty() {
            let mut retained = self
                .early_errors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            retained.extend(errors);
        }
    }
}

struct SemanticCleanupGuard {
    store: SemanticIntentStore,
    tokens: Vec<SemanticIntentToken>,
    armed: bool,
    early_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl SemanticCleanupGuard {
    fn new(
        store: SemanticIntentStore,
        early_errors: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            store,
            tokens: Vec::new(),
            armed: true,
            early_errors,
        }
    }

    fn tokens_mut(&mut self) -> &mut Vec<SemanticIntentToken> {
        &mut self.tokens
    }

    fn set_tokens(&mut self, tokens: Vec<SemanticIntentToken>) {
        self.tokens = tokens;
    }

    fn release(&mut self) -> (Vec<SemanticIntent>, Vec<String>) {
        self.armed = false;
        release_semantic_intents(&self.store, std::mem::take(&mut self.tokens))
    }

    fn disarm_keep(&mut self) {
        self.armed = false;
        self.tokens.clear();
    }
}

impl Drop for SemanticCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (_, errors) = release_semantic_intents(&self.store, std::mem::take(&mut self.tokens));
        if !errors.is_empty() {
            let mut retained = self
                .early_errors
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            retained.extend(errors);
        }
    }
}

fn finish_with_early_cleanup<T>(
    result: Result<T>,
    errors: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) -> Result<T> {
    let retained = errors
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    match (result, retained.is_empty()) {
        (Ok(value), true) => Ok(value),
        (Ok(_), false) => bail!(
            "early orchestration cleanup failed: {}",
            retained.join("; ")
        ),
        (Err(error), true) => Err(error),
        (Err(error), false) => Err(error.context(format!(
            "early orchestration cleanup also failed: {}",
            retained.join("; ")
        ))),
    }
}

fn release_claims(store: &SyncStore, tokens: Vec<ClaimToken>) -> (Vec<PathClaim>, Vec<String>) {
    let mut released = Vec::new();
    let mut errors = Vec::new();

    for token in tokens {
        match store.release(token) {
            Ok(claim) => released.push(claim),
            Err(error) => errors.push(format!("failed to release claim {}: {error}", token.get())),
        }
    }

    (released, errors)
}

fn release_semantic_intents(
    store: &SemanticIntentStore,
    tokens: Vec<SemanticIntentToken>,
) -> (Vec<SemanticIntent>, Vec<String>) {
    let mut released = Vec::new();
    let mut errors = Vec::new();

    for token in tokens {
        match store.release(token) {
            Ok(intent) => released.push(intent),
            Err(error) => errors.push(format!(
                "failed to release semantic intent {}: {error}",
                token.get()
            )),
        }
    }

    (released, errors)
}

fn discover_repo_root(repo_path: &Path) -> Result<PathBuf> {
    let repo = crate::git_repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("orchestration requires a non-bare repository")
}

fn current_head_oid(repo_path: &Path) -> Result<Oid> {
    let repo = crate::git_repository::open(repo_path)
        .with_context(|| format!("failed to open repository {}", repo_path.display()))?;
    head_oid(&repo)
}

fn head_oid(repo: &Repository) -> Result<Oid> {
    let head = repo
        .head()
        .context("repository has no committed HEAD; create an initial commit first")?;
    let commit = head
        .peel_to_commit()
        .context("failed to peel HEAD to a commit")?;
    Ok(commit.id())
}
