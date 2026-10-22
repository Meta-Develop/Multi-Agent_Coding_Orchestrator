use super::*;

const MAX_OBSERVED_PATHS: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_OBSERVED_FILE_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_OBSERVED_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

fn changed_paths(
    before: &BTreeMap<PathBuf, String>,
    after: &BTreeMap<PathBuf, String>,
) -> Vec<PathBuf> {
    before
        .keys()
        .chain(after.keys())
        .filter(|path| before.get(*path) != after.get(*path))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Legacy journals remain readable. Observed records must form a continuous,
/// worktree/HEAD-bound chain, and declarations never override the observed delta.
pub(crate) fn validate_worker_journal_observations(
    entries: &[WorkerExecutionJournalEntry],
) -> Result<()> {
    let mut previous: Option<&WorkerJournalObservation> = None;
    let mut pending: Option<&WorkerExecutionJournalEntry> = None;
    let empty = BTreeMap::new();
    for entry in entries {
        let Some(observation) = &entry.observation else {
            if previous.is_some() {
                bail!("unobserved journal record after observed attribution began");
            }
            continue;
        };
        // A terminal failure preserves the last trusted snapshot, not an
        // invented post-command observation. It poisons further append/import.
        if observation.phase == WorkerJournalObservationPhase::Failed {
            bail!(
                "worker journal contains a terminal observation failure: {}",
                observation
                    .failure
                    .as_deref()
                    .unwrap_or("missing failure diagnostic")
            );
        }
        if observation.failure.is_some() {
            bail!("successful journal observation contains a failure diagnostic");
        }
        if observation.worktree != entry.cwd || !entry.cwd.is_absolute() {
            bail!("journal observation cwd differs from its bound worktree");
        }
        for snapshot in [&observation.before, &observation.after] {
            if snapshot.len() > MAX_OBSERVED_PATHS {
                bail!("journal observation exceeds the path limit");
            }
            for (path, digest) in snapshot {
                if normalize_paths(vec![path.clone()])? != vec![path.clone()]
                    || digest.len() != 64
                    || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    bail!("journal observation has an invalid path or content digest");
                }
            }
        }
        if let Some(last) = previous {
            if last.worktree != observation.worktree
                || last.worktree_identity != observation.worktree_identity
                || last.head_oid != observation.head_oid
            {
                bail!("journal observation changed its bound worktree identity or HEAD");
            }
        }
        let expected_before = previous.map_or(&empty, |last| &last.after);
        if &observation.before != expected_before {
            bail!("journal observation snapshot continuity failed");
        }
        if entry.changed_paths != changed_paths(&observation.before, &observation.after) {
            bail!("journal changed_paths differ from the observed content delta");
        }
        match observation.phase {
            WorkerJournalObservationPhase::Started => {
                if pending.is_some() || observation.before != observation.after {
                    bail!("journal command start has an unfinished command or mutation");
                }
                pending = Some(entry);
            }
            WorkerJournalObservationPhase::Completed => {
                let start = pending
                    .take()
                    .context("journal completion has no command start")?;
                if start.command != entry.command
                    || start.cwd != entry.cwd
                    || start.start_timestamp != entry.start_timestamp
                    || start
                        .observation
                        .as_ref()
                        .map(|value| &value.declared_paths)
                        != Some(&observation.declared_paths)
                {
                    bail!("journal command completion differs from its start");
                }
            }
            WorkerJournalObservationPhase::NativeEdit => {
                if pending.is_some() {
                    bail!("native edit observation interrupts an unfinished command");
                }
            }
            WorkerJournalObservationPhase::Failed => unreachable!("checked above"),
        }
        if observation.phase != WorkerJournalObservationPhase::Started
            && !observation.declared_paths.is_empty()
            && normalize_paths(observation.declared_paths.clone())? != entry.changed_paths
        {
            bail!("declared --changed-path values do not match observed changed paths");
        }
        previous = Some(observation);
    }
    if pending.is_some() {
        bail!("worker journal contains an unfinished wrapped command");
    }
    Ok(())
}

/// Execute shell argv under the existing confinement, or observe an immediately
/// preceding native edit. The journal lock is held across observation and action.
#[cfg(test)]
pub(crate) fn run_worker_execution_journal_command(
    path: &Path,
    expected: &crate::safe_state::FileIdentity,
    entry: &WorkerExecutionJournalEntry,
    observe_changes: bool,
) -> Result<()> {
    run_worker_execution_journal_command_with_clock(path, expected, entry, observe_changes, false)
}

pub(crate) fn run_worker_execution_journal_command_with_clock(
    path: &Path,
    expected: &crate::safe_state::FileIdentity,
    entry: &WorkerExecutionJournalEntry,
    observe_changes: bool,
    auto_timestamps: bool,
) -> Result<()> {
    let mut timed_entry = entry.clone();
    if auto_timestamps {
        if !entry.start_timestamp.is_empty() || !entry.end_timestamp.is_empty() {
            bail!("automatic journal timestamps cannot be combined with supplied timestamps");
        }
        timed_entry.start_timestamp = journal_timestamp()?;
        timed_entry.end_timestamp = timed_entry.start_timestamp.clone();
    }
    let entry = &timed_entry;
    // Keep semantic validation before opening any append descriptor or running argv.
    let mut encoded = Vec::new();
    append_worker_execution_journal_record(&mut encoded, entry)?;
    // Reject a duplicated CLI separator before recording intent or attempting
    // spawn. Never infer retry safety from a spawn error or a command's exit.
    if !observe_changes && entry.command[0] == "--" {
        bail!("WorkerJournalPrelaunchRejected: no command launched; journal unchanged; duplicate -- separator: pass exactly one -- before the executable, for example -- bash -lc 'git diff --check'");
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;

        let file = open_worker_journal_no_follow(path, true)?;
        verify_worker_journal_identity(&file.metadata()?, expected)?;
        let mut locked = WorkerJournalAppendLock::acquire(file)?;
        let file = &mut locked.file;
        let mut reader = open_worker_journal_no_follow(path, false)?;
        verify_worker_journal_identity(&reader.metadata()?, expected)?;
        let original_len = file.metadata()?.len();
        if original_len >= MAX_WORKER_EXECUTION_JOURNAL_BYTES as u64 {
            bail!("worker journal append exceeds the existing capture byte limit");
        }
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take(MAX_WORKER_EXECUTION_JOURNAL_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != original_len || file.metadata()?.len() != original_len {
            bail!("worker journal length changed before observation");
        }
        let entries = parse_worker_execution_journal(&bytes, path)?;
        let previous = entries
            .iter()
            .rev()
            .find_map(|record| record.observation.as_ref());
        if let Err(error) = fs::canonicalize(&entry.cwd) {
            if error.kind() == std::io::ErrorKind::NotFound {
                bail!("WorkerJournalPrelaunchRejected: no command launched; journal unchanged; --cwd does not exist; copy the exact absolute Assigned worktree into both --cwd and the execution tool workdir; retry only this rejected invocation");
            }
            return Err(error).context("cannot resolve journal worktree; stop");
        }
        let repository = Repository::open(&entry.cwd)
            .context("journal observation requires the assigned Git worktree root")?;
        let root = repository
            .workdir()
            .context("journal observation refuses bare repositories")?;
        let binding = crate::safe_state::DirectoryBindingGuard::bind(root)?;
        if root != entry.cwd || fs::canonicalize(root)? != entry.cwd {
            bail!("journal cwd must be the exact canonical assigned worktree root");
        }
        if path.starts_with(root) {
            bail!("worker journal must be outside the observed source worktree");
        }
        let head_oid = journal_head(&repository)?;
        if let Some(last) = previous {
            if last.worktree != entry.cwd
                || last.worktree_identity != *binding.identity()
                || last.head_oid != head_oid
            {
                bail!("worker journal changed its bound worktree identity or HEAD");
            }
        }
        let baseline = previous.map(|last| last.after.clone()).unwrap_or_default();
        let before = snapshot(&repository, &binding)?;
        if !observe_changes && before != baseline {
            bail!("unobserved edits precede this command; journal the native edit immediately with --observe-changes");
        }
        let mut record = entry.clone();
        record.changed_paths.clear();
        record.observation = Some(WorkerJournalObservation {
            worktree: entry.cwd.clone(),
            worktree_identity: binding.identity().clone(),
            head_oid: head_oid.clone(),
            phase: if observe_changes {
                WorkerJournalObservationPhase::NativeEdit
            } else {
                WorkerJournalObservationPhase::Started
            },
            before: baseline,
            after: before.clone(),
            declared_paths: normalize_paths(entry.changed_paths.clone())?,
            failure: None,
        });
        let status = if observe_changes {
            None
        } else {
            // Durable intent precedes argv execution. Missing completion is rejected.
            encoded.clear();
            append_worker_execution_journal_record(&mut encoded, &record)?;
            // Leave room for a bounded terminal failure even when a later
            // observation/completion would exceed the journal capture limit.
            let reserved = encode_observation_failure(&record, "\0".repeat(1024))?;
            if original_len + encoded.len() as u64 + reserved.len() as u64
                > MAX_WORKER_EXECUTION_JOURNAL_BYTES as u64
            {
                bail!("worker journal has no room for command start and terminal failure");
            }
            append_locked_worker_journal(path, expected, file, &encoded)?;
            Some(
                std::process::Command::new(&entry.command[0])
                    .args(&entry.command[1..])
                    .current_dir(&entry.cwd)
                    .status(),
            )
        };
        // Capture the end after execution (or at observation time for a native
        // edit). A failed clock read is a terminal observation failure too.
        let completion = (|| -> Result<_> {
            if auto_timestamps {
                record.end_timestamp = journal_timestamp()?;
            }
            let after = if observe_changes {
                before
            } else {
                snapshot(&repository, &binding)?
            };
            binding.verify()?;
            if journal_head(&repository)? != head_oid {
                bail!("worker command changed HEAD; stop without repairing the journal");
            }
            let mut completed = record.clone();
            let observation = completed
                .observation
                .as_mut()
                .expect("observation set above");
            if !observe_changes {
                observation.phase = WorkerJournalObservationPhase::Completed;
            }
            observation.after = after;
            completed.changed_paths = changed_paths(&observation.before, &observation.after);
            let mismatch = !observation.declared_paths.is_empty()
                && observation.declared_paths != completed.changed_paths;
            let mut encoded = Vec::new();
            append_worker_execution_journal_record(&mut encoded, &completed)?;
            if file.metadata()?.len() + encoded.len() as u64
                > MAX_WORKER_EXECUTION_JOURNAL_BYTES as u64
            {
                bail!("worker journal completion exceeds the capture byte limit");
            }
            Ok((encoded, mismatch))
        })();
        let (encoded, mismatch) = match completion {
            Ok(completion) => completion,
            Err(error) => {
                let failure = format!("{error:#}").chars().take(1024).collect();
                let terminal = encode_observation_failure(&record, failure)?;
                append_locked_worker_journal(path, expected, file, &terminal)
                    .context("observation failed and terminal failure could not be appended")?;
                return Err(error)
                    .context("journal observation failed; terminal failure preserved; stop");
            }
        };
        append_locked_worker_journal(path, expected, file, &encoded)?;
        if mismatch {
            bail!("declared --changed-path values do not match observed changed paths; mismatch preserved in journal; stop");
        }
        if let Some(status) = status {
            let status = status.context("wrapped command failed to launch; journal retained")?;
            if !status.success() {
                bail!("wrapped command failed with {status}; journal retained");
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, expected, observe_changes);
        bail!("observed worker journal append requires the qualified Linux file contract")
    }
}

fn journal_timestamp() -> Result<String> {
    crate::orchestration_event::format_rfc3339_utc(std::time::SystemTime::now())
        .context("worker journal UTC clock is unavailable")
}

#[cfg(target_os = "linux")]
fn encode_observation_failure(
    record: &WorkerExecutionJournalEntry,
    failure: String,
) -> Result<Vec<u8>> {
    let mut failed = record.clone();
    let observation = failed
        .observation
        .as_mut()
        .expect("observation set before execution");
    observation.phase = WorkerJournalObservationPhase::Failed;
    observation.after = observation.before.clone();
    failed.changed_paths.clear();
    observation.failure = Some(failure);
    let mut encoded = Vec::new();
    append_worker_execution_journal_record(&mut encoded, &failed)?;
    Ok(encoded)
}

#[cfg(target_os = "linux")]
fn journal_head(repository: &Repository) -> Result<Option<String>> {
    match repository.head() {
        Ok(head) => Ok(Some(head.peel_to_commit()?.id().to_string())),
        Err(error) if error.code() == ErrorCode::UnbornBranch => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(target_os = "linux")]
fn snapshot(
    repository: &Repository,
    binding: &crate::safe_state::DirectoryBindingGuard,
) -> Result<BTreeMap<PathBuf, String>> {
    use crate::artifacts::state_auth::sha256_hex;
    use std::os::unix::fs::MetadataExt;

    binding.verify()?;
    let head = journal_head(repository)?;
    let tree = head
        .as_ref()
        .map(|oid| repository.find_commit(Oid::from_str(oid)?)?.tree())
        .transpose()?;
    let mut options = DiffOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(true)
        .include_typechange(true);
    let diff = repository.diff_tree_to_workdir_with_index(tree.as_ref(), Some(&mut options))?;
    let mut paths = BTreeSet::new();
    for delta in diff.deltas() {
        for path in [delta.old_file().path(), delta.new_file().path()]
            .into_iter()
            .flatten()
        {
            paths.insert(path.to_path_buf());
            if paths.len() > MAX_OBSERVED_PATHS {
                bail!("journal observation exceeds its {MAX_OBSERVED_PATHS} path limit");
            }
        }
    }
    let paths = normalize_paths(paths.into_iter().collect())?;
    let mut state = BTreeMap::new();
    let mut total = 0u64;
    for path in paths {
        let mut material = Vec::new();
        match binding.read_relative_optional_with_metadata(&path, MAX_OBSERVED_FILE_BYTES)? {
            Some((contents, metadata)) => {
                total = total
                    .checked_add(contents.len() as u64)
                    .filter(|bytes| *bytes <= MAX_OBSERVED_TOTAL_BYTES)
                    .context("journal observation exceeds its total content byte limit")?;
                if !metadata.is_file() || metadata.nlink() != 1 {
                    bail!("journal observation refuses linked or special files");
                }
                material.extend_from_slice(&(metadata.mode() & 0o111).to_be_bytes());
                material.extend_from_slice(&contents);
            }
            None => {
                // Directories/submodules are not silently treated as deleted files.
                match fs::symlink_metadata(binding.path().join(&path)) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => bail!(
                        "journal observation refuses directories, submodules, or unreadable paths"
                    ),
                }
                material.extend_from_slice(b"deleted");
            }
        }
        state.insert(path, sha256_hex(&material));
    }
    binding.verify()?;
    Ok(state)
}
