use super::*;

pub(super) fn planned_claim_releases(
    store: &SyncStore,
    tokens: &[ClaimToken],
) -> Result<Vec<PathClaim>> {
    let mut active = store
        .snapshot()?
        .into_iter()
        .map(|claim| (claim.token, claim))
        .collect::<BTreeMap<_, _>>();
    tokens
        .iter()
        .map(|token| {
            let mut claim = active.remove(token).with_context(|| {
                format!(
                    "claim token {} is not active while planning terminal cleanup",
                    token.get()
                )
            })?;
            sanitize_serialized_paths(&mut claim.paths);
            Ok(claim)
        })
        .collect()
}

pub(super) fn release_claims(
    store: &SyncStore,
    tokens: Vec<ClaimToken>,
    permit: &SupervisorOperationPermit<'_>,
) -> (Vec<PathClaim>, Vec<String>) {
    if let Err(error) = permit.verify(MutationOperation::ClaimRelease) {
        return (
            Vec::new(),
            vec![format!("claim release authorization refused: {error}")],
        );
    }
    let mut released = Vec::new();
    let mut errors = Vec::new();
    for token in tokens {
        match store.release(token) {
            Ok(mut claim) => {
                sanitize_serialized_paths(&mut claim.paths);
                released.push(claim);
            }
            Err(error) => errors.push(format!("failed to release claim {}: {error}", token.get())),
        }
    }
    (released, errors)
}

pub(super) fn planned_semantic_intent_releases(
    store: &SemanticIntentStore,
    tokens: &[crate::semantic_coord::SemanticIntentToken],
) -> Result<Vec<SemanticIntent>> {
    let mut active = store
        .snapshot()?
        .into_iter()
        .map(|intent| (intent.token, intent))
        .collect::<BTreeMap<_, _>>();
    tokens
        .iter()
        .map(|token| {
            let mut intent = active.remove(token).with_context(|| {
                format!(
                    "semantic intent token {} is not active while planning terminal cleanup",
                    token.get()
                )
            })?;
            sanitize_semantic_intent(&mut intent);
            Ok(intent)
        })
        .collect()
}

pub(super) fn release_semantic_intents(
    store: &SemanticIntentStore,
    tokens: Vec<crate::semantic_coord::SemanticIntentToken>,
    permit: &SupervisorOperationPermit<'_>,
) -> (Vec<SemanticIntent>, Vec<String>) {
    if let Err(error) = permit.verify(MutationOperation::SemanticIntentRelease) {
        return (
            Vec::new(),
            vec![format!(
                "semantic intent release authorization refused: {error}"
            )],
        );
    }
    let mut released = Vec::new();
    let mut errors = Vec::new();
    for token in tokens {
        match store.release(token) {
            Ok(mut intent) => {
                sanitize_semantic_intent(&mut intent);
                released.push(intent);
            }
            Err(error) => errors.push(format!(
                "failed to release semantic intent {}: {error}",
                token.get()
            )),
        }
    }
    (released, errors)
}

pub(super) fn complete_planned_scheduler_resource_release(
    sync_store: &SyncStore,
    semantic_store: &SemanticIntentStore,
    report: &SupervisorFinalReport,
    claim_permit: &SupervisorOperationPermit<'_>,
    semantic_permit: &SupervisorOperationPermit<'_>,
) -> Result<()> {
    claim_permit
        .verify(MutationOperation::ClaimRelease)
        .map_err(anyhow::Error::from)?;
    semantic_permit
        .verify(MutationOperation::SemanticIntentRelease)
        .map_err(anyhow::Error::from)?;
    if report.claim_tokens.iter().copied().collect::<BTreeSet<_>>()
        != report
            .released_claims
            .iter()
            .map(|claim| claim.token.get())
            .collect()
    {
        bail!("terminal report claim cleanup plan is internally inconsistent");
    }
    let mut active_claims = sync_store
        .snapshot()?
        .into_iter()
        .map(|claim| (claim.token, claim))
        .collect::<BTreeMap<_, _>>();
    for expected in &report.released_claims {
        let Some(active) = active_claims.remove(&expected.token) else {
            continue;
        };
        let mut comparable_active = active.clone();
        sanitize_serialized_paths(&mut comparable_active.paths);
        if comparable_active != *expected {
            bail!(
                "active claim token {} differs from its terminal release plan",
                expected.token.get()
            );
        }
        let mut released = sync_store.release(expected.token)?;
        sanitize_serialized_paths(&mut released.paths);
        if released != *expected {
            bail!(
                "released claim token {} differs from its terminal release plan",
                expected.token.get()
            );
        }
    }

    if report
        .semantic_intent_tokens
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        != report
            .released_semantic_intents
            .iter()
            .map(|intent| intent.token.get())
            .collect()
    {
        bail!("terminal report semantic cleanup plan is internally inconsistent");
    }
    let mut active_intents = semantic_store
        .snapshot()?
        .into_iter()
        .map(|intent| (intent.token, intent))
        .collect::<BTreeMap<_, _>>();
    for expected in &report.released_semantic_intents {
        let Some(active) = active_intents.remove(&expected.token) else {
            continue;
        };
        let mut comparable_active = active.clone();
        sanitize_semantic_intent(&mut comparable_active);
        if comparable_active != *expected {
            bail!(
                "active semantic intent token {} differs from its terminal release plan",
                expected.token.get()
            );
        }
        let mut released = semantic_store.release(expected.token)?;
        sanitize_semantic_intent(&mut released);
        if released != *expected {
            bail!(
                "released semantic intent token {} differs from its terminal release plan",
                expected.token.get()
            );
        }
    }
    Ok(())
}

fn sanitize_semantic_intent(intent: &mut SemanticIntent) {
    sanitize_serialized_paths(&mut intent.paths);
    sanitize_serialized_paths(&mut intent.impacted_files);
    for symbol in &mut intent.symbols {
        symbol.file = serializable_path_buf(&symbol.file);
    }
}

fn sanitize_serialized_paths(paths: &mut [PathBuf]) {
    for path in paths {
        *path = serializable_path_buf(path);
    }
}

fn serializable_path_buf(path: &Path) -> PathBuf {
    PathBuf::from(serializable_path(path))
}

pub(super) fn ensure_clean_primary(repo: &Path, runtime: SupervisorExecutionRuntime) -> Result<()> {
    if primary_is_dirty(repo, runtime)? {
        bail!("refusing to run supervise with a dirty primary worktree; rerun with --allow-dirty-primary to override");
    }
    Ok(())
}

fn primary_is_dirty(repo: &Path, runtime: SupervisorExecutionRuntime) -> Result<bool> {
    Ok(!primary_status_snapshot(repo, runtime)?.is_empty())
}

pub(super) fn ensure_reusable_child_worktree(
    record: &WorktreeRecord,
    primary_head: &Oid,
) -> Result<()> {
    let repo = crate::git_repository::open(&record.path).with_context(|| {
        format!(
            "failed to inspect existing child worktree '{}' at {}",
            record.name,
            record.path.display()
        )
    })?;
    if repository_is_dirty(&repo, "failed to inspect child worktree status")? {
        bail!(
            "refusing to reuse dirty child worktree '{}' at {}; clean it or use a new child id",
            record.name,
            record.path.display()
        );
    }

    let child_head = head_oid(&repo).with_context(|| {
        format!(
            "failed to inspect HEAD for child worktree '{}'",
            record.name
        )
    })?;
    if &child_head != primary_head {
        bail!(
            "refusing to reuse stale child worktree '{}' at {}; stale-base: child HEAD {} does not match current primary HEAD {}. Remove the child worktree or choose a new child id; supervise does not reset child worktrees",
            record.name,
            record.path.display(),
            child_head,
            primary_head
        );
    }

    Ok(())
}

pub(super) fn repository_is_dirty(repo: &Repository, context: &'static str) -> Result<bool> {
    Ok(!repository_dirty_paths(repo, context)?.is_empty())
}

fn repository_dirty_paths(repo: &Repository, context: &'static str) -> Result<Vec<PathBuf>> {
    Ok(repository_status_snapshot(repo, context)?
        .keys()
        .map(|path| repo_relative_path_from_git_bytes(path))
        .collect())
}

fn repository_status_snapshot(
    repo: &Repository,
    context: &'static str,
) -> Result<BTreeMap<Vec<u8>, Status>> {
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    let statuses = repo.statuses(Some(&mut options)).context(context)?;
    let mut paths = BTreeMap::new();
    for entry in statuses.iter() {
        let path = entry.path_bytes();
        let status = entry.status();
        if is_untracked_runtime_artifact(path, status) {
            continue;
        }
        paths
            .entry(path.to_vec())
            .and_modify(|existing| *existing |= status)
            .or_insert(status);
    }
    Ok(paths)
}

fn is_untracked_runtime_artifact(path: &[u8], status: Status) -> bool {
    status == Status::WT_NEW && is_untracked_runtime_artifact_bytes(path)
}

pub(super) fn is_untracked_runtime_artifact_bytes(path: &[u8]) -> bool {
    LOCAL_RUNTIME_ROOTS
        .iter()
        .any(|root| path_is_at_or_below(path, root))
}

fn path_is_at_or_below(path: &[u8], root: &[u8]) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

#[cfg(unix)]
pub(super) fn repo_relative_path_from_git_bytes(path: &[u8]) -> PathBuf {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    PathBuf::from(OsString::from_vec(path.to_vec()))
}

#[cfg(not(unix))]
pub(super) fn repo_relative_path_from_git_bytes(path: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(path).into_owned())
}

pub(super) fn current_head_oid(repo_path: &Path) -> Result<Oid> {
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

pub(super) fn collect_paths_changed_since_base(
    worktree_path: &Path,
    base_oid: &Oid,
) -> Result<Vec<PathBuf>> {
    let repo = crate::git_repository::open(worktree_path)
        .with_context(|| format!("failed to open child worktree {}", worktree_path.display()))?;
    let base_commit = repo
        .find_commit(*base_oid)
        .with_context(|| format!("failed to find child base commit {base_oid}"))?;
    let base_tree = base_commit
        .tree()
        .with_context(|| format!("failed to read tree for child base commit {base_oid}"))?;
    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_typechange(true);
    let mut diff = repo
        .diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut options))
        .context("failed to diff child worktree against child base commit")?;
    let mut find_options = DiffFindOptions::new();
    find_options.renames(true);
    diff.find_similar(Some(&mut find_options))
        .context("failed to detect renamed child worktree paths")?;

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
    .context("failed to inspect child worktree changed paths")?;

    Ok(paths.into_iter().collect())
}

pub(super) fn collect_diff_since_base(
    worktree_path: &Path,
    base_oid: &Oid,
    max_bytes: usize,
) -> Result<String> {
    let repo = crate::git_repository::open(worktree_path)
        .with_context(|| format!("failed to open child worktree {}", worktree_path.display()))?;
    let base_commit = repo
        .find_commit(*base_oid)
        .with_context(|| format!("failed to find child base commit {base_oid}"))?;
    let base_tree = base_commit
        .tree()
        .with_context(|| format!("failed to read tree for child base commit {base_oid}"))?;
    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .show_untracked_content(true)
        .include_typechange(true);
    let mut diff = repo
        .diff_tree_to_workdir_with_index(Some(&base_tree), Some(&mut options))
        .context("failed to diff child worktree against child base commit")?;
    let mut find_options = DiffFindOptions::new();
    find_options.renames(true);
    diff.find_similar(Some(&mut find_options))
        .context("failed to detect renamed child worktree paths")?;
    let mut bytes = Vec::new();
    let mut exceeded = false;
    let print_result = diff.print(DiffFormat::Patch, |_delta, _hunk, line| {
        let origin = line.origin();
        let origin_len = usize::from(matches!(origin, ' ' | '+' | '-'));
        let Some(next_len) = bytes
            .len()
            .checked_add(origin_len)
            .and_then(|length| length.checked_add(line.content().len()))
        else {
            exceeded = true;
            return false;
        };
        if next_len > max_bytes {
            exceeded = true;
            return false;
        }
        if origin_len == 1 {
            bytes.push(origin as u8);
        }
        bytes.extend_from_slice(line.content());
        true
    });
    if exceeded {
        bail!("child diff exceeds its {max_bytes} byte review-lens input limit");
    }
    print_result.context("failed to render child worktree diff")?;
    String::from_utf8(bytes).context("child worktree diff is not valid UTF-8")
}

fn collect_delta_paths(delta: git2::DiffDelta<'_>, paths: &mut BTreeSet<PathBuf>) {
    match delta.status() {
        Delta::Deleted => insert_delta_path(delta.old_file().path(), paths),
        Delta::Renamed | Delta::Copied => {
            insert_delta_path(delta.old_file().path(), paths);
            insert_delta_path(delta.new_file().path(), paths);
        }
        _ => insert_delta_path(delta.new_file().path(), paths),
    }
}

fn insert_delta_path(path: Option<&Path>, paths: &mut BTreeSet<PathBuf>) {
    if let Some(path) = path.filter(|path| !path.as_os_str().is_empty()) {
        paths.insert(path.to_path_buf());
    }
}

pub(super) fn union_paths(left: &[PathBuf], right: &[PathBuf]) -> Vec<PathBuf> {
    left.iter()
        .chain(right)
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
