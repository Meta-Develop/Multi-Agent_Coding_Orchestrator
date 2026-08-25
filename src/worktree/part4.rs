fn bounded_worktree_records(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedWorktreeRecords> {
    bounded_worktree_records_mode(path, max_entries, max_output_bytes, timeout, false)
}

fn bounded_worktree_records_with_ignored(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
) -> Result<BoundedWorktreeRecords> {
    bounded_worktree_records_mode(path, max_entries, max_output_bytes, timeout, true)
}

fn bounded_worktree_records_mode(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
    collect_ignored: bool,
) -> Result<BoundedWorktreeRecords> {
    let (_process_lock, deadline, process_queue_wait) =
        enter_bounded_status_process_scope(timeout)?;
    ensure_worktree_status_deadline(deadline, "before bounded-status runtime-root setup")?;
    let state_root = bounded_status_runtime_root(path)?;
    ensure_worktree_status_deadline(deadline, "after bounded-status runtime-root setup")?;
    let mut records = bounded_worktree_status_in_runtime_until(
        path,
        max_entries,
        max_output_bytes,
        &state_root,
        |_| Ok(()),
        deadline,
        collect_ignored,
    )?;
    records.process_queue_wait = process_queue_wait;
    Ok(records)
}

fn enter_bounded_status_process_scope(
    timeout: Duration,
) -> Result<(std::sync::MutexGuard<'static, ()>, Instant, Duration)> {
    validate_worktree_status_timeout(timeout)?;
    let queued_at = Instant::now();
    let process_lock = lock_bounded_status_process();
    let process_queue_wait = queued_at.elapsed();
    let deadline = worktree_status_deadline(timeout)?;
    Ok((process_lock, deadline, process_queue_wait))
}

fn lock_bounded_status_process() -> std::sync::MutexGuard<'static, ()> {
    let lock = BOUNDED_STATUS_PROCESS_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
fn bounded_worktree_is_clean_in_runtime<F>(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
    state_root: &SafeRoot,
    after_index_snapshot: F,
) -> Result<bool>
where
    F: FnOnce(&SafeRoot) -> Result<()>,
{
    let (_process_lock, deadline, _) = enter_bounded_status_process_scope(timeout)?;
    bounded_worktree_status_in_runtime_until(
        path,
        max_entries,
        max_output_bytes,
        state_root,
        after_index_snapshot,
        deadline,
        false,
    )
    .map(|records| records.status.is_empty())
}

#[cfg(test)]
fn bounded_worktree_is_clean_in_runtime_unlocked<F>(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    timeout: Duration,
    state_root: &SafeRoot,
    after_index_snapshot: F,
) -> Result<bool>
where
    F: FnOnce(&SafeRoot) -> Result<()>,
{
    let deadline = worktree_status_deadline(timeout)?;
    bounded_worktree_status_in_runtime_until(
        path,
        max_entries,
        max_output_bytes,
        state_root,
        after_index_snapshot,
        deadline,
        false,
    )
    .map(|records| records.status.is_empty())
}

fn bounded_worktree_status_in_runtime_until<F>(
    path: &Path,
    max_entries: usize,
    max_output_bytes: usize,
    state_root: &SafeRoot,
    after_index_snapshot: F,
    deadline: Instant,
    collect_ignored: bool,
) -> Result<BoundedWorktreeRecords>
where
    F: FnOnce(&SafeRoot) -> Result<()>,
{
    let repository_binding = RepositoryBindingGuard::bind(path)
        .context("failed to bind bounded-status repository association")?;
    let worktree_binding = repository_binding.worktree_binding();
    let lock_timeout = remaining_worktree_status_time(
        deadline,
        "before global bounded-status runtime lock acquisition",
    )?
    .min(WORKTREE_STATUS_LOCK_TIMEOUT);
    let status_lock = KernelStateLock::acquire_direct_with_timeout(
        state_root,
        WORKTREE_STATUS_RUNTIME_LOCK,
        lock_timeout,
    )
    .context("failed to acquire global bounded-status runtime lock")?;
    ensure_worktree_status_deadline(deadline, "after bounded-status runtime lock acquisition")?;
    status_lock.verify_direct_binding(state_root)?;
    scavenge_bounded_status_runtimes_until(state_root, WORKTREE_STATUS_SCAVENGE_LIMITS, deadline)
        .context("failed to scavenge bounded-status crash residue")?;
    status_lock.verify_direct_binding(state_root)?;
    ensure_worktree_status_deadline(deadline, "after bounded-status startup cleanup")?;
    let git_dir_binding = DirectoryBindingGuard::bind(repository_binding.git_dir())
        .context("failed to bind bounded-status Git directory")?;
    let common_dir_binding = DirectoryBindingGuard::bind(repository_binding.common_dir())
        .context("failed to bind bounded-status Git common directory")?;
    verify_repository_status_bindings(worktree_binding, &git_dir_binding, &common_dir_binding)?;
    let git_text_inputs = validate_bounded_git_text_inputs_bound(&repository_binding, deadline)?;
    ensure_worktree_status_deadline(deadline, "after opening bounded-status repository")?;
    let raw_head = repository_binding
        .read_git_relative(Path::new("HEAD"), MAX_WORKTREE_HEAD_BYTES)
        .context("failed to capture bounded-status HEAD")?;
    validate_bounded_head(&raw_head)?;
    let head = resolve_bounded_head(&repository_binding, &raw_head)?;
    ensure_worktree_status_deadline(deadline, "after capturing bounded-status HEAD")?;
    let index = repository_binding
        .read_git_relative_optional(Path::new("index"), MAX_WORKTREE_INDEX_BYTES)
        .context("failed to capture bounded-status index")?;
    if let Some(index) = &index {
        validate_bounded_index_bytes(index)?;
    }
    ensure_worktree_status_deadline(deadline, "after capturing bounded-status index")?;
    let common_objects = SafeRoot::open_existing(repository_binding.common_dir().join("objects"))?;
    ensure_worktree_status_deadline(deadline, "after binding bounded-status objects")?;
    let runtime = state_root.reserve_random_direct_child_directory(WORKTREE_STATUS_RUNTIME_SEED)?;
    ensure_worktree_status_deadline(deadline, "after reserving bounded-status runtime")?;
    let result = (|| -> Result<BoundedWorktreeRecords> {
        let runtime_root = SafeRoot::open_existing(runtime.path())?;
        ensure_worktree_status_deadline(deadline, "after opening bounded-status runtime")?;
        runtime_root.reserve_direct_child_directory("home")?;
        ensure_worktree_status_deadline(deadline, "after bounded-status HOME setup")?;
        runtime_root.reserve_direct_child_directory("tmp")?;
        ensure_worktree_status_deadline(deadline, "after bounded-status TMP setup")?;
        let git_dir = runtime_root.reserve_direct_child_directory("git")?;
        let git_root = SafeRoot::open_existing(git_dir.path())?;
        git_root.reserve_direct_child_directory("refs")?;
        let info_dir = git_root.reserve_direct_child_directory("info")?;
        if let Some(exclude) = &git_text_inputs.info_exclude {
            let info_root = SafeRoot::open_existing(info_dir.path())?;
            AtomicStateWriter::write_direct(&info_root, "exclude", exclude)?;
        }
        ensure_worktree_status_deadline(deadline, "after bounded-status Git root setup")?;
        if let Some(index) = &index {
            AtomicStateWriter::write_direct(&git_root, "index", index)?;
        }
        ensure_worktree_status_deadline(deadline, "after bounded-status index staging")?;
        after_index_snapshot(&runtime_root)?;
        ensure_worktree_status_deadline(deadline, "after bounded-status setup callback")?;
        AtomicStateWriter::write_direct(&git_root, "HEAD", &head)?;
        ensure_worktree_status_deadline(deadline, "after bounded-status HEAD staging")?;
        create_validated_object_link(&git_root, common_objects.path())?;
        ensure_worktree_status_deadline(deadline, "after bounded-status object-link setup")?;
        let worktree_alias = create_bounded_status_worktree_link(&runtime_root, path)?;
        ensure_worktree_status_deadline(deadline, "after bounded-status worktree-link setup")?;
        let git_context = BoundedGitContext {
            worktree: &worktree_alias,
            worktree_target: path,
            runtime_root: &runtime_root,
            git_dir: git_dir.path(),
            objects_target: common_objects.path(),
            core_filemode: git_text_inputs.core_filemode,
        };
        let visible = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree index listing",
        )?;
        ensure_worktree_status_deadline(deadline, "after bounded managed-worktree index listing")?;
        let index_flags = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "ls-files",
                "--stage",
                "-v",
                "-z",
                "--sparse",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree index flag validation",
        )?;
        validate_bounded_git_index_records(&index_flags, max_entries)?;
        let fsmonitor_flags = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "ls-files",
                "--stage",
                "-f",
                "-z",
                "--sparse",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree fsmonitor flag validation",
        )?;
        validate_bounded_git_index_records(&fsmonitor_flags, max_entries)?;
        let bytes = run_bounded_git_records(
            &git_context,
            [
                "--no-optional-locks",
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--no-renames",
                "--ignore-submodules=all",
            ],
            max_entries,
            max_output_bytes,
            deadline,
            "bounded managed-worktree status",
        )?;
        ensure_worktree_status_deadline(deadline, "after bounded managed-worktree status")?;
        let status_entries = bytes.iter().filter(|byte| **byte == 0).count();
        let remaining_entries = max_entries
            .checked_sub(status_entries)
            .context("bounded worktree status exceeded its combined entry limit")?;
        let remaining_output_bytes = max_output_bytes
            .checked_sub(bytes.len())
            .context("bounded worktree status exceeded its combined output limit")?;
        let ignored = if collect_ignored {
            let ignored = run_bounded_git_records(
                &git_context,
                [
                    "--no-optional-locks",
                    "ls-files",
                    "-z",
                    "--others",
                    "--ignored",
                    "--exclude-standard",
                    "--exclude=!.maco",
                    "--exclude=!.maco/**",
                    "--exclude=!.maco-cache",
                    "--exclude=!.maco-cache/**",
                    "--exclude=!target",
                    "--exclude=!target/**",
                    "--exclude=!.agent/temp",
                    "--exclude=!.agent/temp/**",
                    "--exclude=!.agent/storage",
                    "--exclude=!.agent/storage/**",
                    "--exclude=!.agents/live",
                    "--exclude=!.agents/live/**",
                    "--exclude=!.agents/temp",
                    "--exclude=!.agents/temp/**",
                    "--exclude=!.agents/storage",
                    "--exclude=!.agents/storage/**",
                ],
                remaining_entries,
                remaining_output_bytes,
                deadline,
                "bounded managed-worktree ignored listing",
            )?;
            ensure_worktree_status_deadline(deadline, "after bounded ignored listing")?;
            ignored
        } else {
            Vec::new()
        };
        verify_repository_status_bindings(worktree_binding, &git_dir_binding, &common_dir_binding)?;
        Ok(BoundedWorktreeRecords {
            visible,
            status: bytes,
            ignored,
            process_queue_wait: Duration::ZERO,
        })
    })();
    let cleanup = (|| -> Result<usize> {
        status_lock.verify_direct_binding(state_root)?;
        let removed = scavenge_bounded_status_runtimes_until(
            state_root,
            WORKTREE_STATUS_SCAVENGE_LIMITS,
            deadline,
        )
        .context("failed to remove bounded-status private runtime")?;
        status_lock.verify_direct_binding(state_root)?;
        Ok(removed)
    })();
    let finished = match (result, cleanup) {
        (Ok(clean), Ok(_)) => Ok(clean),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => Err(error.context(format!(
            "bounded-status runtime cleanup also failed: {cleanup_error:#}"
        ))),
    };
    let finished = finish_with_status_lock_verification(
        finished,
        status_lock.verify_direct_binding(state_root),
    );
    finish_with_repository_binding_verification(
        finished,
        repository_binding.verify_status_generation(),
    )
}

fn validate_bounded_head(bytes: &[u8]) -> Result<()> {
    let value = std::str::from_utf8(bytes)
        .context("bounded-status HEAD is not UTF-8")?
        .trim();
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("bounded-status supports only SHA-1 repositories");
    }
    let Some(reference) = value.strip_prefix("ref: ") else {
        bail!("bounded-status HEAD is neither an object id nor symbolic reference");
    };
    if !reference.starts_with("refs/heads/")
        || reference.ends_with(['/', '.'])
        || reference.contains("..")
        || reference.contains("@{")
        || reference.contains("//")
        || reference.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte == b' '
                || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        bail!("bounded-status HEAD contains an unsafe symbolic reference");
    }
    Ok(())
}

fn verify_repository_status_bindings(
    worktree: &DirectoryBindingGuard,
    git_dir: &DirectoryBindingGuard,
    common_dir: &DirectoryBindingGuard,
) -> Result<()> {
    worktree
        .verify()
        .context("bounded-status worktree changed")?;
    git_dir
        .verify()
        .context("bounded-status Git directory changed")?;
    common_dir
        .verify()
        .context("bounded-status Git common directory changed")
}

fn finish_with_repository_binding_verification<T>(
    result: Result<T>,
    verification: Result<()>,
) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(binding_error)) => Err(binding_error),
        (Err(error), Err(binding_error)) => Err(error.context(format!(
            "operation also lost its repository pathname binding: {binding_error:#}"
        ))),
    }
}

fn resolve_bounded_head(repository: &RepositoryBindingGuard, head: &[u8]) -> Result<Vec<u8>> {
    let value = std::str::from_utf8(head)
        .context("bounded-status HEAD is not UTF-8")?
        .trim();
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(format!("{}\n", value.to_ascii_lowercase()).into_bytes());
    }
    let reference = value
        .strip_prefix("ref: ")
        .context("bounded-status HEAD has no supported target")?;
    let reference_path = Path::new(reference);
    if repository.git_dir() != repository.common_dir()
        && repository
            .read_git_relative_optional(reference_path, MAX_WORKTREE_HEAD_BYTES)?
            .is_some()
    {
        bail!("bounded-status rejects a linked-worktree shadow branch reference");
    }
    let loose =
        repository.read_common_relative_optional(reference_path, MAX_WORKTREE_HEAD_BYTES)?;
    if let Some(loose) = loose {
        let oid = parse_bounded_loose_reference(&loose)?;
        return Ok(format!("{oid}\n").into_bytes());
    }
    if let Some(packed) = repository
        .read_common_relative_optional(Path::new("packed-refs"), MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?
    {
        if let Some(oid) = parse_bounded_packed_reference(&packed, reference)? {
            return Ok(format!("{oid}\n").into_bytes());
        }
    }
    // A symbolic target absent from both loose and packed refs is the exact
    // unborn-branch representation. Preserve it only after bounded lookup.
    Ok(format!("ref: {reference}\n").into_bytes())
}

fn parse_bounded_loose_reference(bytes: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(bytes)
        .context("bounded-status loose reference is not UTF-8")?
        .trim();
    if value.starts_with("ref: ") {
        bail!("bounded-status rejects symbolic loose-reference chains");
    }
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("bounded-status loose reference is not a SHA-1 object id");
    }
    Ok(value.to_ascii_lowercase())
}

fn parse_bounded_packed_reference(bytes: &[u8], reference: &str) -> Result<Option<String>> {
    let contents = std::str::from_utf8(bytes).context("bounded-status packed-refs is not UTF-8")?;
    let mut found = None;
    for line in contents.lines() {
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let mut fields = line.split(' ');
        let oid = fields
            .next()
            .context("packed-refs entry omitted object id")?;
        let name = fields
            .next()
            .context("packed-refs entry omitted reference name")?;
        if fields.next().is_some()
            || oid.len() != 40
            || !oid.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !name.starts_with("refs/")
        {
            bail!("bounded-status packed-refs contains a malformed entry");
        }
        if name == reference && found.replace(oid.to_ascii_lowercase()).is_some() {
            bail!("bounded-status packed-refs contains a duplicate reference");
        }
    }
    Ok(found)
}

fn validate_bounded_index_bytes(bytes: &[u8]) -> Result<()> {
    const HEADER_BYTES: usize = 12;
    const ENTRY_FIXED_BYTES: usize = 62;
    const CHECKSUM_BYTES: usize = 20;
    const CE_EXTENDED: u16 = 0x4000;
    const CE_VALID: u16 = 0x8000;
    const SPARSE_DIRECTORY_MODE: u32 = 0o040000;

    if bytes.len() < HEADER_BYTES.saturating_add(CHECKSUM_BYTES) || &bytes[..4] != b"DIRC" {
        bail!("bounded-status SHA-1 index has an invalid header");
    }
    let payload_end = bytes.len() - CHECKSUM_BYTES;
    let expected_checksum = sha1_digest(&bytes[..payload_end])?;
    let checksum_mismatch = expected_checksum
        .iter()
        .zip(&bytes[payload_end..])
        .fold(0_u8, |difference, (expected, observed)| {
            difference | (expected ^ observed)
        });
    if checksum_mismatch != 0 {
        bail!("bounded-status index checksum is invalid");
    }
    let version = bounded_index_u32(bytes, 4)?;
    if !matches!(version, 2 | 3) {
        bail!("bounded-status index version {version} is unsupported");
    }
    let entry_count = usize::try_from(bounded_index_u32(bytes, 8)?)
        .context("bounded-status index entry count overflowed")?;
    if entry_count > MAX_WORKTREE_STATUS_ENTRIES {
        bail!("bounded-status index exceeds its entry limit");
    }
    let mut cursor = HEADER_BYTES;
    for _ in 0..entry_count {
        let fixed_end = cursor
            .checked_add(ENTRY_FIXED_BYTES)
            .context("bounded-status index entry offset overflowed")?;
        if fixed_end > payload_end {
            bail!("bounded-status index entry is truncated");
        }
        let mode = bounded_index_u32(bytes, cursor + 24)?;
        if mode == SPARSE_DIRECTORY_MODE {
            bail!("bounded-status rejects sparse-directory index entries");
        }
        let flags = bounded_index_u16(bytes, cursor + 60)?;
        if flags & CE_VALID != 0 {
            bail!("bounded-status rejects assume-unchanged index entries");
        }
        if flags & CE_EXTENDED != 0 {
            bail!("bounded-status rejects extended index flags");
        }
        let path_end = bytes[fixed_end..payload_end]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| fixed_end + offset)
            .context("bounded-status index entry path is not terminated")?;
        let path_len = path_end.saturating_sub(fixed_end);
        let encoded_len = usize::from(flags & 0x0fff);
        if path_len == 0 || (encoded_len < 0x0fff && encoded_len != path_len) {
            bail!("bounded-status index entry path length is invalid");
        }
        let unpadded = path_end
            .checked_add(1)
            .and_then(|end| end.checked_sub(cursor))
            .context("bounded-status index entry length overflowed")?;
        let padded = unpadded
            .checked_add((8 - (unpadded % 8)) % 8)
            .context("bounded-status index padding overflowed")?;
        cursor = cursor
            .checked_add(padded)
            .context("bounded-status index cursor overflowed")?;
        if cursor > payload_end {
            bail!("bounded-status index entry padding is truncated");
        }
    }
    let mut saw_tree = false;
    let mut saw_resolve_undo = false;
    while cursor < payload_end {
        let header_end = cursor
            .checked_add(8)
            .context("bounded-status index extension offset overflowed")?;
        if header_end > payload_end {
            bail!("bounded-status index extension header is truncated");
        }
        let signature = &bytes[cursor..cursor + 4];
        let length = usize::try_from(bounded_index_u32(bytes, cursor + 4)?)
            .context("bounded-status index extension length overflowed")?;
        let extension_end = header_end
            .checked_add(length)
            .context("bounded-status index extension length overflowed")?;
        if extension_end > payload_end {
            bail!("bounded-status index extension payload is truncated");
        }
        if !signature[0].is_ascii_uppercase() {
            bail!("bounded-status rejects required or stateful index extensions");
        }
        let already_seen = match signature {
            b"TREE" => &mut saw_tree,
            b"REUC" => &mut saw_resolve_undo,
            _ => bail!("bounded-status rejects unsupported or stateful optional index extensions"),
        };
        if *already_seen {
            bail!("bounded-status rejects duplicate index extensions");
        }
        *already_seen = true;

        // TREE and REUC are optional derived caches, not sources of stage-0
        // tracked state. The checksum-bound index is copied byte-for-byte into
        // the private runtime, where ordinary Git commands derive status from
        // the entries above. In particular, REUC only retains removed conflict
        // stages for an explicit future `checkout -m`; bounded status neither
        // consumes nor trusts that payload. A malformed payload therefore
        // makes private Git fail closed without changing the captured index.
        cursor = extension_end;
    }
    Ok(())
}

fn sha1_digest(bytes: &[u8]) -> Result<[u8; 20]> {
    let byte_length = u64::try_from(bytes.len()).context("SHA-1 input length overflowed")?;
    let bit_length = byte_length
        .checked_mul(8)
        .context("SHA-1 bit length overflowed")?;
    let mut state = [
        0x6745_2301_u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut chunks = bytes.chunks_exact(64);
    for chunk in &mut chunks {
        let mut block = [0_u8; 64];
        block.copy_from_slice(chunk);
        sha1_compress(&mut state, &block);
    }
    let remainder = chunks.remainder();
    let tail_blocks = if remainder.len() < 56 { 1 } else { 2 };
    let tail_len = tail_blocks * 64;
    let mut tail = [0_u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_length.to_be_bytes());
    for block in tail[..tail_len].chunks_exact(64) {
        let mut block_array = [0_u8; 64];
        block_array.copy_from_slice(block);
        sha1_compress(&mut state, &block_array);
    }
    let mut digest = [0_u8; 20];
    for (word, output) in state.iter().zip(digest.chunks_exact_mut(4)) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    Ok(digest)
}

fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut words = [0_u32; 80];
    for (index, bytes) in block.chunks_exact(4).enumerate() {
        words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    for index in 16..80 {
        words[index] =
            (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                .rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (index, word) in words.iter().enumerate() {
        let (function, constant) = match index {
            0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(function)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

fn bounded_index_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .context("bounded-status index integer offset overflowed")?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .context("bounded-status index integer is truncated")?
        .try_into()
        .context("bounded-status index integer has the wrong width")?;
    Ok(u32::from_be_bytes(raw))
}

fn bounded_index_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .context("bounded-status index integer offset overflowed")?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .context("bounded-status index integer is truncated")?
        .try_into()
        .context("bounded-status index integer has the wrong width")?;
    Ok(u16::from_be_bytes(raw))
}

fn validate_bounded_git_index_records(bytes: &[u8], max_entries: usize) -> Result<()> {
    let mut entries = 0usize;
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        entries = entries.saturating_add(1);
        if entries > max_entries {
            bail!("bounded-status index validation exceeded its entry limit");
        }
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .context("bounded-status index validation omitted a path separator")?;
        let header = &record[..separator];
        if header.len() < 3 || header[1] != b' ' {
            bail!("bounded-status index validation returned a malformed header");
        }
        let tag = header[0];
        let header = std::str::from_utf8(&header[2..])
            .context("bounded-status index validation header is not ASCII")?;
        let mode = header
            .split_ascii_whitespace()
            .next()
            .context("bounded-status index validation omitted an entry mode")?;
        if mode == "040000" {
            bail!("bounded-status rejects sparse-directory index entries");
        }
        if tag == b'S' || tag.is_ascii_lowercase() {
            bail!("bounded-status rejects hidden index-entry state");
        }
    }
    Ok(())
}

struct BoundedGitTextInputs {
    info_exclude: Option<Vec<u8>>,
    core_filemode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundedLocalGitConfig {
    pub(crate) core_filemode: bool,
    pub(crate) core_hooks_path_present: bool,
}

pub(crate) fn parse_bounded_local_git_config(bytes: Option<&[u8]>) -> Result<BoundedLocalGitConfig> {
    let Some(bytes) = bytes else {
        return Ok(BoundedLocalGitConfig {
            core_filemode: true,
            core_hooks_path_present: false,
        });
    };
    if bytes.contains(&0) {
        bail!("repository-local Git config contains a NUL byte");
    }

    let mut in_core = false;
    let mut core_filemode = None;
    let mut core_hooks_path_present = false;
    for raw_line in bytes.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let line = raw_line.trim_ascii();
        if line.is_empty() || matches!(line.first(), Some(b'#' | b';')) {
            continue;
        }
        if line.first() == Some(&b'[') {
            let close = line
                .iter()
                .position(|byte| *byte == b']')
                .context("repository-local Git config contains a malformed section")?;
            let trailing = line[close.saturating_add(1)..].trim_ascii();
            if !trailing.is_empty() && !matches!(trailing.first(), Some(b'#' | b';')) {
                bail!("repository-local Git config contains a malformed section suffix");
            }
            in_core = line[1..close].trim_ascii().eq_ignore_ascii_case(b"core");
            continue;
        }
        if !in_core {
            continue;
        }

        let key_end = line
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || *byte == b'=')
            .unwrap_or(line.len());
        let key = &line[..key_end];
        if !key.eq_ignore_ascii_case(b"filemode")
            && !key.eq_ignore_ascii_case(b"hookspath")
        {
            continue;
        }
        let rest = line[key_end..].trim_ascii();
        let value = rest
            .strip_prefix(b"=")
            .context("repository-local Git config policy entry must use an explicit value")?
            .trim_ascii();
        if key.eq_ignore_ascii_case(b"hookspath") {
            core_hooks_path_present = true;
            continue;
        }
        if core_filemode.is_some() {
            bail!("repository-local core.filemode must appear at most once");
        }
        core_filemode = Some(match value {
            b"true" => true,
            b"false" => false,
            _ => bail!("repository-local core.filemode must be exactly true or false"),
        });
    }

    Ok(BoundedLocalGitConfig {
        core_filemode: core_filemode.unwrap_or(true),
        core_hooks_path_present,
    })
}

const MACO_STATUS_EXCLUDES: &[u8] = b"\n.maco/\n.maco-cache/\n.agent/temp/\n.agent/storage/\n.agents/live/\n.agents/temp/\n.agents/storage/\ntarget/\n.worktrees/\n.worktrees-quarantine-*/\n";

fn is_bounded_status_runtime_path(path: &Path) -> bool {
    path.starts_with(".maco")
        || path.starts_with(".maco-cache")
        || path.starts_with("target")
        || path.starts_with(".agent/temp")
        || path.starts_with(".agent/storage")
        || path.starts_with(".agents/live")
        || path.starts_with(".agents/temp")
        || path.starts_with(".agents/storage")
        || crate::repo_map::is_ignored_worktree_store_path(path)
}

#[cfg(test)]
fn validate_bounded_git_text_inputs(
    worktree: &Path,
    git_dir: &Path,
    common_dir: &Path,
    deadline: Instant,
) -> Result<BoundedGitTextInputs> {
    let binding = RepositoryBindingGuard::bind(worktree)?;
    if binding.git_dir() != git_dir || binding.common_dir() != common_dir {
        bail!("bounded-status repository metadata paths changed before prevalidation");
    }
    validate_bounded_git_text_inputs_bound(&binding, deadline)
}

fn validate_bounded_git_text_inputs_bound(
    repository: &RepositoryBindingGuard,
    deadline: Instant,
) -> Result<BoundedGitTextInputs> {
    let git_dir = repository.git_dir();
    let common_dir = repository.common_dir();
    if repository
        .read_common_relative_optional(
            Path::new("objects/info/alternates"),
            MAX_WORKTREE_GIT_TEXT_FILE_BYTES,
        )?
        .is_some_and(|bytes| !bytes.is_empty())
    {
        bail!("bounded-status rejects Git object alternates");
    }
    let inventory = BoundedTreeWalker::walk_bound_with_options(
        repository.worktree_binding(),
        BoundedTreeWalkLimits {
            max_depth: 128,
            max_entries: MAX_WORKTREE_STATUS_ENTRIES,
            max_path_bytes: MAX_PERSISTED_PATH_BYTES,
            max_total_path_bytes: MAX_WORKTREE_STATUS_OUTPUT_BYTES.saturating_mul(32),
            max_duration: remaining_worktree_status_time(
                deadline,
                "before Git ignore prevalidation",
            )?,
            same_device: true,
        },
        crate::safe_state::BoundedTreeWalkOptions {
            stop_at_nested_repositories: true,
        },
        |entry| {
            if entry.relative_path == Path::new(".git") {
                return Ok(BoundedTreeWalkAction::Skip);
            }
            // Treat managed-worktree stores and other runtime roots as walk
            // boundaries so the walker never descends those trees.
            if is_bounded_status_runtime_path(&entry.relative_path) {
                return Ok(BoundedTreeWalkAction::Skip);
            }
            if entry.kind == BoundedTreeEntryKind::Directory {
                return Ok(BoundedTreeWalkAction::RecordAndDescend);
            }
            let file_name = entry.relative_path.file_name();
            let is_gitignore = file_name == Some(OsStr::new(".gitignore"));
            let is_gitmodules = file_name == Some(OsStr::new(".gitmodules"));
            if is_gitignore || is_gitmodules {
                if !entry.is_safe_regular_file() {
                    if is_gitignore {
                        bail!("Git ignore input is not a safe single-link regular file");
                    }
                    bail!("Git submodule metadata is not a safe single-link regular file");
                }
                return Ok(BoundedTreeWalkAction::Record);
            }
            Ok(BoundedTreeWalkAction::Skip)
        },
    )?;
    if inventory
        .iter()
        .filter(|entry| entry.kind == BoundedTreeEntryKind::RegularFile)
        .count()
        > MAX_WORKTREE_GIT_TEXT_FILES
    {
        bail!("repository exceeds its Git ignore file count limit");
    }
    let mut total = 0_u64;
    for entry in inventory
        .iter()
        .filter(|entry| entry.kind == BoundedTreeEntryKind::RegularFile)
    {
        let bytes = repository
            .worktree_binding()
            .read_relative(&entry.relative_path, MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?;
        total = total
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .context("Git ignore aggregate byte count overflowed")?;
        if total > MAX_WORKTREE_GIT_TEXT_TOTAL_BYTES {
            bail!("repository exceeds its Git ignore aggregate byte limit");
        }
        ensure_worktree_status_deadline(deadline, "during Git ignore prevalidation")?;
    }
    if common_dir != git_dir
        && repository
            .read_git_relative_optional(
                Path::new("info/exclude"),
                MAX_WORKTREE_GIT_TEXT_FILE_BYTES,
            )?
            .is_some()
    {
        bail!("bounded-status rejects a linked-worktree shadow info/exclude");
    }
    let info_exclude = repository
        .read_common_relative_optional(Path::new("info/exclude"), MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?
        .map(|bytes| String::from_utf8(bytes).context("Git exclude file is not UTF-8"))
        .transpose()?
        .map(String::into_bytes);
    for bytes in info_exclude.iter() {
        total = total
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .context("Git metadata aggregate byte count overflowed")?;
    }
    let common_config = repository
        .read_common_relative_optional(Path::new("config"), MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?;
    let local_config = parse_bounded_local_git_config(common_config.as_deref())?;
    for bytes in [
        repository
            .read_git_relative_optional(Path::new("config"), MAX_WORKTREE_GIT_TEXT_FILE_BYTES)?,
        common_config,
        repository.read_common_relative_optional(
            Path::new("config.worktree"),
            MAX_WORKTREE_GIT_TEXT_FILE_BYTES,
        )?,
    ]
    .into_iter()
    .flatten()
    {
        total = total
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .context("Git metadata aggregate byte count overflowed")?;
        if total > MAX_WORKTREE_GIT_TEXT_TOTAL_BYTES {
            bail!("repository exceeds its Git metadata aggregate byte limit");
        }
    }
    if total > MAX_WORKTREE_GIT_TEXT_TOTAL_BYTES {
        bail!("repository exceeds its Git metadata aggregate byte limit");
    }
    ensure_worktree_status_deadline(deadline, "after Git metadata prevalidation")?;
    let mut effective_exclude = info_exclude.unwrap_or_default();
    effective_exclude.extend_from_slice(MACO_STATUS_EXCLUDES);
    Ok(BoundedGitTextInputs {
        info_exclude: Some(effective_exclude),
        core_filemode: local_config.core_filemode,
    })
}

fn path_from_git_bytes(raw: &[u8]) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        Ok(PathBuf::from(OsString::from_vec(raw.to_vec())))
    }
    #[cfg(not(unix))]
    {
        let text = std::str::from_utf8(raw).context("Git path is not valid UTF-8")?;
        Ok(PathBuf::from(text))
    }
}

fn parse_porcelain_v1_z(bytes: &[u8], max_entries: usize) -> Result<Vec<(PathBuf, [u8; 2])>> {
    let mut records = Vec::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if raw.len() < 4 || raw[2] != b' ' {
            bail!("bounded worktree status returned a malformed porcelain record");
        }
        let status = [raw[0], raw[1]];
        if !status
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
        {
            bail!("bounded worktree status returned malformed status bytes");
        }
        let path = path_from_git_bytes(&raw[3..])?;
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("bounded worktree status returned an unsafe repository path");
        }
        records.push((path, status));
        if records.len() > max_entries {
            bail!("bounded worktree status exceeded its parsed entry limit");
        }
    }
    Ok(records)
}

fn parse_nul_paths(bytes: &[u8], max_entries: usize) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let path = path_from_git_bytes(raw)?;
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            bail!("bounded Git inventory returned an unsafe repository path");
        }
        paths.push(path);
        if paths.len() > max_entries {
            bail!("bounded Git inventory exceeded its parsed entry limit");
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn finish_with_status_lock_verification<T>(
    result: Result<T>,
    verification: Result<()>,
) -> Result<T> {
    match (result, verification) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(lock_error)) => Err(lock_error),
        (Err(error), Err(lock_error)) => Err(error.context(format!(
            "operation also lost its bounded-status lock-path binding: {lock_error:#}"
        ))),
    }
}

#[cfg(test)]
fn scavenge_bounded_status_runtimes(
    state_root: &SafeRoot,
    limits: PrivateDirectoryScavengeLimits,
) -> Result<usize> {
    scavenge_private_random_directories(
        state_root,
        WORKTREE_STATUS_RUNTIME_LOCK,
        WORKTREE_STATUS_RUNTIME_SEED,
        limits,
    )
}

fn scavenge_bounded_status_runtimes_until(
    state_root: &SafeRoot,
    mut limits: PrivateDirectoryScavengeLimits,
    deadline: Instant,
) -> Result<usize> {
    limits.max_duration =
        remaining_worktree_status_time(deadline, "before bounded-status runtime scavenging")?;
    scavenge_private_random_directories_until(
        state_root,
        WORKTREE_STATUS_RUNTIME_LOCK,
        WORKTREE_STATUS_RUNTIME_SEED,
        limits,
        deadline,
    )
}

fn validate_worktree_status_timeout(timeout: Duration) -> Result<()> {
    if timeout.is_zero() {
        bail!("worktree status total time budget must be non-zero");
    }
    Ok(())
}

fn worktree_status_deadline(timeout: Duration) -> Result<Instant> {
    validate_worktree_status_timeout(timeout)?;
    Instant::now()
        .checked_add(timeout)
        .context("worktree status total time budget overflowed")
}

fn remaining_worktree_status_time(deadline: Instant, phase: &str) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .with_context(|| format!("worktree status exhausted its total time budget {phase}"))
}

fn ensure_worktree_status_deadline(deadline: Instant, phase: &str) -> Result<()> {
    remaining_worktree_status_time(deadline, phase).map(|_| ())
}

struct BoundedGitContext<'a> {
    worktree: &'a Path,
    worktree_target: &'a Path,
    runtime_root: &'a SafeRoot,
    git_dir: &'a Path,
    objects_target: &'a Path,
    core_filemode: bool,
}

#[cfg(target_os = "linux")]
const BOUNDED_STATUS_RUNTIME_ROOT_ENV: &str = "MACO_BOUNDED_STATUS_RUNTIME_ROOT";

#[cfg(target_os = "linux")]
struct BoundedStatusRuntimeRootConfig {
    explicit_root: Option<PathBuf>,
    tmpdir: Option<PathBuf>,
    prefer_shared_tmp: bool,
}

#[cfg(target_os = "linux")]
impl BoundedStatusRuntimeRootConfig {
    fn from_env() -> Self {
        Self {
            explicit_root: std::env::var_os(BOUNDED_STATUS_RUNTIME_ROOT_ENV).map(PathBuf::from),
            tmpdir: std::env::var_os("TMPDIR").map(PathBuf::from),
            // Tests keep a per-worktree root so they do not share /tmp with one another.
            prefer_shared_tmp: !cfg!(test),
        }
    }

    fn candidate_paths(&self, worktree: &Path) -> Result<Vec<PathBuf>> {
        if let Some(path) = &self.explicit_root {
            return Ok(vec![require_configured_bounded_status_runtime_root(
                path,
                BOUNDED_STATUS_RUNTIME_ROOT_ENV,
            )?]);
        }
        let mut candidates = Vec::new();
        if self.prefer_shared_tmp {
            if let Some(tmpdir) = &self.tmpdir {
                if !tmpdir.as_os_str().is_empty() {
                    push_unique_path(
                        &mut candidates,
                        tmpdir.join(shared_bounded_status_runtime_root_name()),
                    );
                }
            }
            if existing_paths_share_device(Path::new("/tmp"), worktree) {
                push_unique_path(
                    &mut candidates,
                    PathBuf::from(format!(
                        "/tmp/{}",
                        shared_bounded_status_runtime_root_name()
                    )),
                );
            }
        }
        push_unique_path(
            &mut candidates,
            worktree_local_bounded_status_runtime_root(worktree)?,
        );
        Ok(candidates)
    }
}

#[cfg(target_os = "linux")]
fn bounded_status_runtime_user_id() -> u32 {
    // SAFETY: geteuid is a pure credential query with no memory side effects.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn shared_bounded_status_runtime_root_name() -> String {
    format!("maco-worktree-status-{}", bounded_status_runtime_user_id())
}

#[cfg(target_os = "linux")]
fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| existing == &path) {
        paths.push(path);
    }
}

#[cfg(target_os = "linux")]
fn require_configured_bounded_status_runtime_root(path: &Path, source: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!(
            "{source} is set but empty; bounded-status runtime root must be a directory on the same filesystem as the worktree"
        );
    }
    Ok(path.to_path_buf())
}

#[cfg(target_os = "linux")]
fn existing_path_device(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()
        .map(|metadata| crate::safe_state::device_id_to_u64(metadata.dev()))
}

#[cfg(target_os = "linux")]
fn existing_paths_share_device(left: &Path, right: &Path) -> bool {
    match (existing_path_device(left), existing_path_device(right)) {
        (Some(left_device), Some(right_device)) => left_device == right_device,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn worktree_local_bounded_status_runtime_root(worktree: &Path) -> Result<PathBuf> {
    let repository = crate::git_repository::open(worktree).with_context(|| {
        format!(
            "failed to open bounded-status repository {} while placing a same-filesystem runtime root",
            worktree.display()
        )
    })?;
    let common_dir = repository.commondir();
    let common_ancestor = worktree
        .ancestors()
        .find(|ancestor| common_dir.starts_with(ancestor))
        .context(
            "worktree and Git common directory have no common ancestor for bounded-status runtime root",
        )?;
    let outside_worktree = if common_ancestor == worktree {
        common_ancestor
            .parent()
            .context("worktree common ancestor has no parent for bounded-status runtime root")?
    } else {
        common_ancestor
    };
    let anchor = outside_worktree
        .ancestors()
        .find(|ancestor| ancestor.to_str().is_some())
        .context("worktree has no UTF-8 ancestor for its private status alias")?;
    let binding = stable_checksum(worktree.as_os_str().as_bytes());
    let directory_name = if cfg!(test) {
        format!(".maco-test-worktree-status-{binding}")
    } else {
        format!(
            ".maco-worktree-status-{}-{binding}",
            bounded_status_runtime_user_id()
        )
    };
    Ok(anchor.join(directory_name))
}

#[cfg(target_os = "linux")]
fn ensure_bounded_status_runtime_root_on_worktree_filesystem(
    worktree: &Path,
    root: &SafeRoot,
) -> Result<()> {
    let Some(worktree_device) = existing_path_device(worktree) else {
        bail!(
            "failed to inspect worktree {} while validating bounded-status runtime root {}",
            worktree.display(),
            root.path().display()
        );
    };
    if worktree_device == root.identity().device {
        return Ok(());
    }
    bail!(
        "bounded-status runtime root {} is on a different filesystem from worktree {} \
         (runtime-root device {}, worktree device {}). \
         Containment requires the staged worktree symlink to stay on one filesystem. \
         Set {BOUNDED_STATUS_RUNTIME_ROOT_ENV} to a directory on the worktree filesystem, \
         or set TMPDIR to a directory on that filesystem.",
        root.path().display(),
        worktree.display(),
        root.identity().device,
        worktree_device
    );
}

#[cfg(target_os = "linux")]
fn open_usable_bounded_status_runtime_root(worktree: &Path, path: &Path) -> Result<SafeRoot> {
    let root = SafeRoot::open_or_create(path).with_context(|| {
        format!(
            "bounded-status runtime root {} is unusable; set {BOUNDED_STATUS_RUNTIME_ROOT_ENV} \
             to a writable directory on the same filesystem as {}",
            path.display(),
            worktree.display()
        )
    })?;
    ensure_bounded_status_runtime_root_on_worktree_filesystem(worktree, &root).with_context(
        || {
            format!(
                "bounded-status runtime root {} cannot be used for worktree {}",
                root.path().display(),
                worktree.display()
            )
        },
    )?;
    Ok(root)
}

#[cfg(target_os = "linux")]
fn open_bounded_status_runtime_root(
    worktree: &Path,
    config: &BoundedStatusRuntimeRootConfig,
) -> Result<SafeRoot> {
    let candidates = config.candidate_paths(worktree)?;
    let explicit = config.explicit_root.is_some();
    let mut last_error: Option<anyhow::Error> = None;
    for path in &candidates {
        match open_usable_bounded_status_runtime_root(worktree, path) {
            Ok(root) => return Ok(root),
            Err(error) if explicit => {
                return Err(error.context(format!(
                    "{BOUNDED_STATUS_RUNTIME_ROOT_ENV}={path} is unusable",
                    path = path.display()
                )));
            }
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error).context(format!(
            "no usable bounded-status runtime root for worktree {}; set {BOUNDED_STATUS_RUNTIME_ROOT_ENV} \
             to a writable directory on the worktree filesystem",
            worktree.display()
        )),
        None => bail!(
            "no bounded-status runtime root candidate for worktree {}; set {BOUNDED_STATUS_RUNTIME_ROOT_ENV}",
            worktree.display()
        ),
    }
}

#[cfg(target_os = "linux")]
fn bounded_status_runtime_root(worktree: &Path) -> Result<SafeRoot> {
    open_bounded_status_runtime_root(worktree, &BoundedStatusRuntimeRootConfig::from_env())
}

#[cfg(not(target_os = "linux"))]
fn bounded_status_runtime_root(_worktree: &Path) -> Result<SafeRoot> {
    bail!("bounded worktree status requires the verified Linux containment boundary")
}

#[cfg(unix)]
fn create_bounded_status_worktree_link(runtime: &SafeRoot, worktree: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::symlink;

    runtime.ensure_direct_child_absent("worktree")?;
    let alias = runtime.direct_child("worktree")?;
    symlink(worktree, &alias).with_context(|| {
        format!(
            "failed to bind private status context to worktree {}",
            worktree.display()
        )
    })?;
    Ok(alias)
}

#[cfg(not(unix))]
fn create_bounded_status_worktree_link(_runtime: &SafeRoot, worktree: &Path) -> Result<PathBuf> {
    bail!(
        "lossless private Git worktree binding is unsupported on this platform: {}",
        worktree.display()
    )
}

#[cfg(unix)]
fn create_validated_object_link(git_root: &SafeRoot, object_directory: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    git_root.ensure_direct_child_absent("objects")?;
    symlink(object_directory, git_root.path().join("objects")).with_context(|| {
        format!(
            "failed to link private Git context to validated objects {}",
            object_directory.display()
        )
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn create_validated_object_link(_git_root: &SafeRoot, object_directory: &Path) -> Result<()> {
    bail!(
        "lossless private Git object binding is unsupported on this platform: {}",
        object_directory.display()
    )
}

fn run_bounded_git_records<const N: usize>(
    context: &BoundedGitContext<'_>,
    args: [&str; N],
    max_entries: usize,
    max_output_bytes: usize,
    deadline: Instant,
    label: &str,
) -> Result<Vec<u8>> {
    let git = crate::merge::resolve_trusted_executable("git")
        .context("failed to resolve trusted Git for bounded worktree status")?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .context("worktree status exhausted its total time budget")?
        .min(WORKTREE_STATUS_COMMAND_TIMEOUT);
    context.runtime_root.verify()?;
    let mut environment = BTreeMap::new();
    environment.insert("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string());
    environment.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    environment.insert("GIT_PAGER".to_string(), "cat".to_string());
    environment.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    environment.insert("HOME".to_string(), "home".to_string());
    environment.insert("LANG".to_string(), "C".to_string());
    environment.insert("LC_ALL".to_string(), "C".to_string());
    environment.insert("PAGER".to_string(), "cat".to_string());
    environment.insert("TEMP".to_string(), "tmp".to_string());
    environment.insert("TMP".to_string(), "tmp".to_string());
    environment.insert("TMPDIR".to_string(), "tmp".to_string());
    environment.insert("XDG_CACHE_HOME".to_string(), "home/cache".to_string());
    environment.insert("XDG_CONFIG_HOME".to_string(), "home/config".to_string());
    let mut command_args = Vec::with_capacity(args.len().saturating_add(20));
    for config in [
        "core.fsmonitor=false",
        "core.untrackedCache=false",
        "core.splitIndex=false",
        "index.sparse=false",
        "submodule.recurse=false",
        "fetch.recurseSubmodules=false",
        "status.submoduleSummary=false",
        "extensions.objectFormat=sha1",
    ] {
        command_args.push(std::ffi::OsString::from("-c"));
        command_args.push(std::ffi::OsString::from(config));
    }
    command_args.push(std::ffi::OsString::from("-c"));
    command_args.push(std::ffi::OsString::from(format!(
        "core.filemode={}",
        if context.core_filemode {
            "true"
        } else {
            "false"
        }
    )));
    command_args.push(std::ffi::OsString::from("--git-dir"));
    command_args.push(context.git_dir.as_os_str().to_os_string());
    command_args.push(std::ffi::OsString::from("--work-tree"));
    command_args.push(context.worktree.as_os_str().to_os_string());
    command_args.extend(args.into_iter().map(std::ffi::OsString::from));
    let mut side_effects = StrictOfflineWorkspaceProfile::read_write(context.runtime_root.path())
        .with_visible_read_only_root(context.worktree_target);
    if !context.objects_target.starts_with(context.worktree_target) {
        side_effects = side_effects.with_visible_read_only_root(context.objects_target);
    }
    let spec = ProcessSpec::direct(
        label,
        git,
        command_args,
        context.runtime_root.path(),
        max_output_bytes,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_containment(ContainmentPolicy::Required)
    .with_side_effect_confinement(SideEffectConfinementProfile::StrictOfflineWorkspace(
        side_effects,
    ))
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(remaining));
    let output = run_process(spec).context("bounded worktree status command failed")?;
    if output.timed_out {
        bail!(
            "worktree status exceeded its {} millisecond time budget",
            remaining.as_millis()
        );
    }
    if output.stdout.is_truncated() || output.stderr.is_truncated() {
        bail!("worktree status exceeded its {max_output_bytes}-byte output budget");
    }
    require_verified_worktree_status_process(&output)?;
    let status = output
        .status
        .context("worktree status command returned no exit status")?;
    if !status.success() {
        let stderr = output.stderr.summarize_chars(512);
        bail!("worktree status command failed: {}", stderr.text);
    }
    let bytes = output.stdout.as_bytes();
    if !bytes.is_empty() && !bytes.ends_with(&[0]) {
        bail!("worktree status returned a malformed non-NUL-terminated record");
    }
    let entries = bytes.iter().filter(|byte| **byte == 0).count();
    if entries > max_entries {
        bail!("worktree status reported {entries} entries, exceeding its limit of {max_entries}");
    }
    Ok(bytes.to_vec())
}

fn require_verified_worktree_status_process(output: &ProcessOutput) -> Result<()> {
    if output.process_error.is_some() || output.stdin_error.is_some() {
        bail!("worktree status process cleanup was not verified");
    }
    if !output.safety_evidence_verified() {
        bail!("worktree status process safety evidence was not verified");
    }
    Ok(())
}
