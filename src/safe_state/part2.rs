#[cfg(unix)]
fn open_existing_stable_private_file_at(
    root: &SafeRoot,
    file_name: &OsStr,
) -> Result<Option<File>> {
    let name = c_string(file_name)?;
    let fd = unsafe {
        libc::openat(
            root.directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).with_context(|| {
            format!(
                "failed to open existing stable lock file {}",
                root.path().join(file_name).display()
            )
        });
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    ensure_regular_single_link_metadata(&root.path().join(file_name), &metadata)?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        bail!(
            "existing stable lock file is not owner-private mode 0600: {}",
            root.path().join(file_name).display()
        );
    }
    Ok(Some(file))
}

#[cfg(not(unix))]
fn open_stable_private_file_at(
    root: &SafeRoot,
    file_name: &OsStr,
    _policy: LockFilePolicy,
) -> Result<File> {
    bail!(
        "handle-relative stable lock files are unsupported on this platform: {}",
        root.path().join(file_name).display()
    )
}

#[cfg(not(unix))]
fn open_existing_stable_private_file_at(
    root: &SafeRoot,
    file_name: &OsStr,
) -> Result<Option<File>> {
    bail!(
        "handle-relative existing lock files are unsupported on this platform: {}",
        root.path().join(file_name).display()
    )
}

#[cfg(unix)]
fn lock_file(file: &File, path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("kernel state lock timeout overflowed")?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error)
                .with_context(|| format!("failed to acquire kernel lock {}", path.display()));
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {} seconds waiting for kernel state lock {}",
                timeout.as_secs(),
                path.display()
            );
        }
        thread::sleep(LOCK_RETRY_INTERVAL);
    }
}

#[cfg(unix)]
fn try_lock_file(file: &File, path: &Path, operation: KernelLockOperation) -> Result<()> {
    let operation = match operation {
        KernelLockOperation::Shared => libc::LOCK_SH,
        KernelLockOperation::Exclusive => libc::LOCK_EX,
    };
    if unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        bail!("kernel state lock is already held: {}", path.display());
    }
    Err(error).with_context(|| format!("failed to acquire kernel state lock {}", path.display()))
}

#[cfg(unix)]
fn try_lock_file_if_idle(file: &File, path: &Path) -> Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(false);
    }
    Err(error).with_context(|| format!("failed to acquire kernel state lock {}", path.display()))
}

#[cfg(not(unix))]
fn try_lock_file(_file: &File, path: &Path, _operation: KernelLockOperation) -> Result<()> {
    bail!(
        "shared/exclusive cooperative kernel locks are unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(not(unix))]
fn try_lock_file_if_idle(_file: &File, path: &Path) -> Result<bool> {
    bail!(
        "exclusive cooperative kernel lock probing is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn unlock_file(file: &File) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to release kernel lock");
    }
    Ok(())
}

#[cfg(windows)]
fn lock_file(file: &File, path: &Path, timeout: Duration) -> Result<()> {
    use windows_sys::Win32::{
        Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
        System::IO::OVERLAPPED,
    };
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("kernel state lock timeout overflowed")?;
    loop {
        let result = unsafe {
            LockFileEx(
                file.as_raw_handle() as _,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        };
        if result != 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {} seconds waiting for kernel state lock {}",
                timeout.as_secs(),
                path.display()
            );
        }
        thread::sleep(LOCK_RETRY_INTERVAL);
    }
}

#[cfg(windows)]
fn unlock_file(file: &File) -> Result<()> {
    use windows_sys::Win32::{Storage::FileSystem::UnlockFileEx, System::IO::OVERLAPPED};
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let result = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as _,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to release kernel lock");
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn lock_file(_file: &File, path: &Path, _timeout: Duration) -> Result<()> {
    bail!("kernel state locks are unsupported: {}", path.display())
}

#[cfg(not(any(unix, windows)))]
fn unlock_file(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn atomic_replace_at(root: &SafeRoot, source: &OsStr, destination: &OsStr) -> Result<()> {
    let source_name = c_string(source)?;
    let destination_name = c_string(destination)?;
    if unsafe {
        libc::renameat(
            root.directory.as_raw_fd(),
            source_name.as_ptr(),
            root.directory.as_raw_fd(),
            destination_name.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                root.path().join(destination).display(),
                root.path().join(source).display()
            )
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_noreplace_at(root: &SafeRoot, source: &OsStr, destination: &OsStr) -> Result<()> {
    let source_name = c_string(source)?;
    let destination_name = c_string(destination)?;
    if let Err(error) =
        rename_noreplace_fd(root.directory.as_raw_fd(), &source_name, &destination_name)
    {
        return Err(error).with_context(|| {
            format!(
                "failed atomic no-replace quarantine rename from {} to {}",
                root.path().join(source).display(),
                root.path().join(destination).display()
            )
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_noreplace_fd(
    fd: RawFd,
    source: &std::ffi::CStr,
    destination: &std::ffi::CStr,
) -> std::io::Result<()> {
    if unsafe {
        libc::renameat2(
            fd,
            source.as_ptr(),
            fd,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn quarantine_regular_file(
    root: &SafeRoot,
    source: &OsStr,
    quarantine: &OsStr,
    expected: &FileIdentity,
) -> Result<()> {
    let source_name = c_string(source)?;
    let quarantine_name = c_string(quarantine)?;
    let source_stat = fstatat_optional_no_follow(root.directory.as_raw_fd(), &source_name)?;
    let quarantine_stat = fstatat_optional_no_follow(root.directory.as_raw_fd(), &quarantine_name)?;
    match (source_stat, quarantine_stat) {
        (Some(_), Some(_)) => bail!("state temp source and quarantine both exist"),
        (None, None) => bail!("state temp source and quarantine are both absent"),
        (None, Some(stat)) => {
            validate_private_regular_quarantine(&stat, expected)?;
            Ok(())
        }
        (Some(stat), None) => {
            validate_private_regular_quarantine(&stat, expected)?;
            rename_noreplace_at(root, source, quarantine)?;
            let rebound = fstatat_no_follow(root.directory.as_raw_fd(), &quarantine_name)?;
            validate_private_regular_quarantine(&rebound, expected)?;
            if fstatat_optional_no_follow(root.directory.as_raw_fd(), &source_name)?.is_some() {
                bail!("state temp source name reappeared during quarantine");
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_private_regular_quarantine(stat: &libc::stat, expected: &FileIdentity) -> Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o600
        || identity_from_stat(stat) != *expected
    {
        bail!("state temp quarantine is unsafe or changed");
    }
    Ok(())
}

#[cfg(unix)]
fn component_checksum(name: &OsStr) -> String {
    stable_checksum(name.as_bytes())
}

#[cfg(unix)]
fn deletion_quarantine_name(name: &OsStr, identity: &FileIdentity) -> OsString {
    let source = base64url_encode(name.as_bytes());
    let tag = deletion_quarantine_tag(name, identity);
    OsString::from(format!(
        "{DELETION_QUARANTINE_V2_PREFIX}{source}-{tag}-{:016x}-{:016x}",
        identity.device, identity.file
    ))
}

#[cfg(unix)]
fn deletion_quarantine_tag(name: &OsStr, identity: &FileIdentity) -> String {
    let mut payload = Vec::with_capacity(
        DELETION_QUARANTINE_V2_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(name.as_bytes().len())
            .saturating_add(16),
    );
    payload.extend_from_slice(DELETION_QUARANTINE_V2_DOMAIN);
    payload.extend_from_slice(
        &u64::try_from(name.as_bytes().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&identity.device.to_be_bytes());
    payload.extend_from_slice(&identity.file.to_be_bytes());
    let checksum = stable_checksum(&payload);
    // stable_checksum has a fixed `maco-v1-` prefix followed by two u64s.
    checksum[8..40].to_string()
}

#[cfg(unix)]
fn base64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().saturating_add(2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        encoded.push(char::from(ALPHABET[usize::from(first >> 2)]));
        let second_index = (first & 0x03) << 4 | chunk.get(1).copied().unwrap_or(0) >> 4;
        encoded.push(char::from(ALPHABET[usize::from(second_index)]));
        if let Some(second) = chunk.get(1).copied() {
            let third_index = (second & 0x0f) << 2 | chunk.get(2).copied().unwrap_or(0) >> 6;
            encoded.push(char::from(ALPHABET[usize::from(third_index)]));
        }
        if let Some(third) = chunk.get(2).copied() {
            encoded.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        }
    }
    encoded
}

#[cfg(unix)]
fn base64url_decode(encoded: &[u8]) -> Result<Vec<u8>> {
    if encoded.is_empty() || encoded.len() % 4 == 1 {
        bail!("private residue quarantine source encoding is malformed");
    }
    let mut decoded = Vec::with_capacity(encoded.len() / 4 * 3 + 2);
    for chunk in encoded.chunks(4) {
        let mut values = [0u8; 4];
        for (index, byte) in chunk.iter().copied().enumerate() {
            values[index] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => bail!("private residue quarantine source is not canonical base64url"),
            };
        }
        decoded.push(values[0] << 2 | values[1] >> 4);
        if chunk.len() >= 3 {
            decoded.push(values[1] << 4 | values[2] >> 2);
        }
        if chunk.len() == 4 {
            decoded.push(values[2] << 6 | values[3]);
        }
    }
    if base64url_encode(&decoded).as_bytes() != encoded {
        bail!("private residue quarantine source encoding is not canonical");
    }
    Ok(decoded)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct DeletionQuarantineBinding {
    source: OsString,
    identity: FileIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PrivateRandomDirectoryResidue {
    name: OsString,
    identity: FileIdentity,
    already_quarantined: bool,
}

#[cfg(target_os = "linux")]
fn scavenge_private_random_directories_linux(
    root: &SafeRoot,
    stable_lock_file: &OsStr,
    random_name_seed: &OsStr,
    limits: PrivateDirectoryScavengeLimits,
    deadline: Instant,
) -> Result<usize> {
    if limits.max_root_entries == 0
        || limits.max_directories == 0
        || limits.max_tree_entries == 0
        || limits.max_duration.is_zero()
    {
        bail!("private directory scavenging limits must be non-zero");
    }
    ensure_before_deadline(Some(deadline), "before private residue root verification")?;
    root.verify()?;
    let root_stat = fstat(root.directory.as_raw_fd())?;
    let mut root_budget = TreeBudget {
        remaining_entries: limits.max_root_entries,
    };
    let names =
        directory_entries_until(root.directory.as_raw_fd(), &mut root_budget, Some(deadline))
            .with_context(|| {
                format!(
                    "private residue root exceeded its {} entry budget",
                    limits.max_root_entries
                )
            })?;
    let mut saw_lock = false;
    let mut residues = Vec::new();
    let mut identities = BTreeMap::new();

    for name in names {
        ensure_before_deadline(Some(deadline), "during private residue root scan")?;
        let name_c = c_string(&name)?;
        let stat = fstatat_no_follow(root.directory.as_raw_fd(), &name_c)?;
        if name == stable_lock_file {
            validate_private_scavenge_lock(root, &name, &stat, root_stat.st_dev)?;
            saw_lock = true;
            continue;
        }

        let live = is_canonical_random_temp_name(random_name_seed, &name);
        let quarantined = deletion_quarantine_binding(&name)?;
        if !live && quarantined.is_none() {
            bail!(
                "unexpected entry in private residue root requires manual inspection: {}",
                root.path().join(&name).display()
            );
        }
        validate_private_scavenge_directory(root, &name, &stat, root_stat.st_dev)?;
        let identity = identity_from_stat(&stat);
        if let Some(encoded) = quarantined {
            if !is_canonical_random_temp_name(random_name_seed, &encoded.source) {
                bail!(
                    "private residue quarantine does not encode a canonical source name: {}",
                    root.path().join(&name).display()
                );
            }
            if encoded.identity != identity {
                bail!(
                    "private residue quarantine identity is malformed or changed: {}",
                    root.path().join(&name).display()
                );
            }
        }
        let binding = root.bind_existing_direct_child_directory(&name)?;
        if binding.identity() != &identity {
            bail!(
                "private residue directory identity changed while binding: {}",
                root.path().join(&name).display()
            );
        }
        if identities
            .insert((identity.device, identity.file), name.clone())
            .is_some()
        {
            bail!("private residue root contains duplicate directory identities");
        }
        residues.push(PrivateRandomDirectoryResidue {
            name,
            identity,
            already_quarantined: !live,
        });
    }

    if !saw_lock {
        bail!("private residue root is missing its held stable lock file");
    }
    if residues.len() > limits.max_directories {
        bail!(
            "private residue root contains {} directories, exceeding its cleanup limit of {}",
            residues.len(),
            limits.max_directories
        );
    }

    let mut tree_budget = TreeBudget {
        remaining_entries: limits.max_tree_entries,
    };
    let mut remaining_bytes = limits.max_total_bytes;
    for residue in &residues {
        ensure_before_deadline(Some(deadline), "before private residue tree audit")?;
        let name_c = c_string(&residue.name)?;
        let directory = openat_directory(root.directory.as_raw_fd(), &name_c)?;
        let opened = fstat(directory.as_raw_fd())?;
        if identity_from_stat(&opened) != residue.identity {
            bail!(
                "private residue directory changed before bounded audit: {}",
                root.path().join(&residue.name).display()
            );
        }
        audit_private_residue_tree(
            directory.as_raw_fd(),
            root_stat.st_dev,
            0,
            &mut tree_budget,
            &mut remaining_bytes,
            Some(deadline),
        )
        .with_context(|| {
            format!(
                "private residue tree exceeded its bounded safety contract: {}",
                root.path().join(&residue.name).display()
            )
        })?;
    }

    let mut removed = 0usize;
    for residue in residues {
        ensure_before_deadline(Some(deadline), "before top-level residue quarantine")?;
        let cleanup_name = if residue.already_quarantined {
            residue.name
        } else {
            let cleanup_name = deletion_quarantine_name(&residue.name, &residue.identity);
            quarantine_direct_child_directory_linux(
                root,
                &residue.name,
                &cleanup_name,
                &residue.identity,
            )?;
            cleanup_name
        };
        remove_tree_at_name_linux_with_deadline(
            root,
            &cleanup_name,
            &residue.identity,
            TreeLinkPolicy::UnlinkLinks,
            Some(deadline),
        )?;
        removed = removed.saturating_add(1);
    }
    ensure_before_deadline(Some(deadline), "after private residue cleanup")?;
    root.verify()?;
    Ok(removed)
}

#[cfg(target_os = "linux")]
fn validate_private_scavenge_lock(
    root: &SafeRoot,
    name: &OsStr,
    stat: &libc::stat,
    root_device: libc::dev_t,
) -> Result<()> {
    if stat.st_dev != root_device
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_nlink != 1
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o600
    {
        bail!(
            "private residue lock is unsafe or changed: {}",
            root.path().join(name).display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private_scavenge_directory(
    root: &SafeRoot,
    name: &OsStr,
    stat: &libc::stat,
    root_device: libc::dev_t,
) -> Result<()> {
    if stat.st_dev != root_device
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode & 0o777 != 0o700
    {
        bail!(
            "private residue entry is not an owner-private directory: {}",
            root.path().join(name).display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_canonical_random_temp_name(seed: &OsStr, name: &OsStr) -> bool {
    let seed = seed.as_bytes();
    let name = name.as_bytes();
    let prefix_len = seed.len().saturating_add(2);
    if name.len() <= prefix_len.saturating_add(4)
        || name.first() != Some(&b'.')
        || name.get(1..1 + seed.len()) != Some(seed)
        || name.get(1 + seed.len()) != Some(&b'.')
        || !name.ends_with(b".tmp")
    {
        return false;
    }
    let middle = &name[prefix_len..name.len() - 4];
    let Some(separator) = middle.iter().position(|byte| *byte == b'-') else {
        return false;
    };
    if middle[separator + 1..].contains(&b'-') {
        return false;
    }
    canonical_decimal_u64(&middle[..separator]) && canonical_decimal_u64(&middle[separator + 1..])
}

#[cfg(target_os = "linux")]
fn canonical_decimal_u64(bytes: &[u8]) -> bool {
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes.first() == Some(&b'0'))
    {
        return false;
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some()
}

#[cfg(target_os = "linux")]
fn deletion_quarantine_binding(name: &OsStr) -> Result<Option<DeletionQuarantineBinding>> {
    let bytes = name.as_bytes();
    let prefix = DELETION_QUARANTINE_PREFIX.as_bytes();
    if !bytes.starts_with(prefix) {
        return Ok(None);
    }
    let v2_prefix = DELETION_QUARANTINE_V2_PREFIX.as_bytes();
    if !bytes.starts_with(v2_prefix) {
        bail!("private residue deletion quarantine version is unsupported");
    }
    let body = &bytes[v2_prefix.len()..];
    if body.len() < 2 + 32 + 1 + 16 + 1 + 16 {
        bail!("private residue deletion quarantine name is malformed");
    }
    let inode_separator = body
        .len()
        .checked_sub(17)
        .context("private residue quarantine name underflow")?;
    let device_separator = inode_separator
        .checked_sub(17)
        .context("private residue quarantine name underflow")?;
    if body.get(inode_separator) != Some(&b'-') || body.get(device_separator) != Some(&b'-') {
        bail!("private residue deletion quarantine identity is malformed");
    }
    let source_and_tag = &body[..device_separator];
    let tag_separator = source_and_tag
        .len()
        .checked_sub(33)
        .context("private residue quarantine tag underflow")?;
    if source_and_tag.get(tag_separator) != Some(&b'-') {
        bail!("private residue deletion quarantine tag is malformed");
    }
    let encoded_source = &source_and_tag[..tag_separator];
    let tag = &source_and_tag[tag_separator + 1..];
    if tag.len() != 32
        || !tag
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("private residue deletion quarantine tag is not canonical lowercase hex");
    }
    let source = OsString::from_vec(base64url_decode(encoded_source)?);
    validate_single_component(&source)?;
    let device = parse_fixed_lower_hex_u64(&body[device_separator + 1..inode_separator])?;
    let file = parse_fixed_lower_hex_u64(&body[inode_separator + 1..])?;
    let identity = FileIdentity { device, file };
    let expected = deletion_quarantine_name(&source, &identity);
    if expected.as_bytes() != bytes {
        bail!("private residue deletion quarantine authentication tag does not match");
    }
    Ok(Some(DeletionQuarantineBinding { source, identity }))
}

#[cfg(unix)]
fn parse_fixed_lower_hex_u64(bytes: &[u8]) -> Result<u64> {
    if bytes.len() != 16
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("private residue quarantine identity is not canonical lowercase hex");
    }
    u64::from_str_radix(std::str::from_utf8(bytes)?, 16)
        .context("private residue quarantine identity overflow")
}

#[cfg(target_os = "linux")]
fn audit_private_residue_tree(
    fd: RawFd,
    device: libc::dev_t,
    depth: usize,
    entry_budget: &mut TreeBudget,
    remaining_bytes: &mut u64,
    deadline: Option<Instant>,
) -> Result<()> {
    ensure_before_deadline(deadline, "during private residue tree audit")?;
    if depth > MAX_TREE_DEPTH {
        bail!("private residue tree exceeded its maximum depth of {MAX_TREE_DEPTH}");
    }
    for name in directory_entries_until(fd, entry_budget, deadline)? {
        ensure_before_deadline(deadline, "during private residue tree audit")?;
        let name_c = c_string(&name)?;
        let stat = fstatat_no_follow(fd, &name_c)?;
        if stat.st_dev != device || stat.st_uid != unsafe { libc::geteuid() } {
            bail!(
                "private residue entry changed owner or filesystem: {}",
                name.to_string_lossy()
            );
        }
        let kind = stat.st_mode & libc::S_IFMT;
        match kind {
            libc::S_IFDIR => {
                if stat.st_mode & 0o777 != 0o700 {
                    bail!(
                        "private residue directory has unsafe mode: {}",
                        name.to_string_lossy()
                    );
                }
                let child = openat_directory(fd, &name_c)?;
                let opened = fstat(child.as_raw_fd())?;
                if identity_from_stat(&opened) != identity_from_stat(&stat) {
                    bail!(
                        "private residue directory identity changed: {}",
                        name.to_string_lossy()
                    );
                }
                audit_private_residue_tree(
                    child.as_raw_fd(),
                    device,
                    depth.saturating_add(1),
                    entry_budget,
                    remaining_bytes,
                    deadline,
                )?;
            }
            libc::S_IFREG => {
                if stat.st_nlink != 1 || stat.st_mode & 0o777 != 0o600 {
                    bail!(
                        "private residue file is not owner-private and single-link: {}",
                        name.to_string_lossy()
                    );
                }
                consume_private_residue_bytes(stat.st_size, remaining_bytes)?;
            }
            libc::S_IFLNK => {
                if stat.st_nlink != 1 {
                    bail!(
                        "private residue symlink has an unsafe link count: {}",
                        name.to_string_lossy()
                    );
                }
                consume_private_residue_bytes(stat.st_size, remaining_bytes)?;
            }
            _ => bail!(
                "private residue contains a special file: {}",
                name.to_string_lossy()
            ),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn consume_private_residue_bytes(size: libc::off_t, remaining: &mut u64) -> Result<()> {
    let size = u64::try_from(size).context("private residue entry has a negative size")?;
    *remaining = remaining.checked_sub(size).with_context(|| {
        format!(
            "private residue trees exceed their {} byte cleanup budget",
            remaining.saturating_add(size)
        )
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn entry_quarantine_name(name: &OsStr, identity: &FileIdentity) -> OsString {
    OsString::from(format!(
        "{ENTRY_QUARANTINE_PREFIX}{}-{:016x}-{:016x}",
        component_checksum(name),
        identity.device,
        identity.file
    ))
}

#[cfg(target_os = "linux")]
fn temp_quarantine_name(file_name: &OsStr, source: &OsStr, identity: &FileIdentity) -> OsString {
    let encoded_target = base64url_encode(file_name.as_bytes());
    let source_checksum = component_checksum_tag(source);
    let binding = temp_quarantine_binding_tag(file_name, &source_checksum, identity);
    OsString::from(format!(
        "{TEMP_QUARANTINE_V2_PREFIX}{encoded_target}-{source_checksum}-{binding}-{:016x}-{:016x}",
        identity.device, identity.file
    ))
}

#[cfg(unix)]
fn component_checksum_tag(name: &OsStr) -> String {
    component_checksum(name)[8..40].to_string()
}

#[cfg(unix)]
fn temp_quarantine_binding_tag(
    file_name: &OsStr,
    source_checksum: &str,
    identity: &FileIdentity,
) -> String {
    let mut payload = Vec::with_capacity(
        TEMP_QUARANTINE_V2_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(file_name.as_bytes().len())
            .saturating_add(source_checksum.len())
            .saturating_add(16),
    );
    payload.extend_from_slice(TEMP_QUARANTINE_V2_DOMAIN);
    payload.extend_from_slice(
        &u64::try_from(file_name.as_bytes().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    payload.extend_from_slice(file_name.as_bytes());
    payload.extend_from_slice(source_checksum.as_bytes());
    payload.extend_from_slice(&identity.device.to_be_bytes());
    payload.extend_from_slice(&identity.file.to_be_bytes());
    stable_checksum(&payload)[8..40].to_string()
}

#[cfg(unix)]
fn canonical_random_temp_target(name: &OsStr) -> Option<OsString> {
    let bytes = name.as_bytes();
    let body = bytes.strip_prefix(b".")?.strip_suffix(b".tmp")?;
    let separator = body.iter().rposition(|byte| *byte == b'.')?;
    let target = body.get(..separator)?;
    let random = body.get(separator + 1..)?;
    if target.is_empty() || random.is_empty() {
        return None;
    }
    let dash = random.iter().position(|byte| *byte == b'-')?;
    if random.get(dash + 1..)?.contains(&b'-') {
        return None;
    }
    let first = std::str::from_utf8(random.get(..dash)?).ok()?;
    let second = std::str::from_utf8(random.get(dash + 1..)?).ok()?;
    if !is_canonical_decimal_u64(first) || !is_canonical_decimal_u64(second) {
        return None;
    }
    Some(OsString::from_vec(target.to_vec()))
}

#[cfg(unix)]
fn is_canonical_decimal_u64(value: &str) -> bool {
    value
        .parse::<u64>()
        .ok()
        .is_some_and(|parsed| parsed.to_string() == value)
}

#[cfg(unix)]
struct TempQuarantineBinding {
    target: OsString,
    identity: FileIdentity,
}

#[cfg(unix)]
fn canonical_temp_quarantine_binding(name: &OsStr) -> Result<Option<TempQuarantineBinding>> {
    let bytes = name.as_bytes();
    if !bytes.starts_with(TEMP_QUARANTINE_PREFIX.as_bytes()) {
        return Ok(None);
    }
    let body = bytes
        .strip_prefix(TEMP_QUARANTINE_V2_PREFIX.as_bytes())
        .context("state temp quarantine version is unsupported")?;
    let inode_separator = body
        .len()
        .checked_sub(17)
        .context("state temp quarantine name is malformed")?;
    let device_separator = inode_separator
        .checked_sub(17)
        .context("state temp quarantine identity is malformed")?;
    let binding_separator = device_separator
        .checked_sub(33)
        .context("state temp quarantine binding is malformed")?;
    let source_separator = binding_separator
        .checked_sub(33)
        .context("state temp quarantine source checksum is malformed")?;
    for separator in [
        source_separator,
        binding_separator,
        device_separator,
        inode_separator,
    ] {
        if body.get(separator) != Some(&b'-') {
            bail!("state temp quarantine framing is malformed");
        }
    }
    let encoded_target = &body[..source_separator];
    let source_checksum = &body[source_separator + 1..binding_separator];
    let binding = &body[binding_separator + 1..device_separator];
    if !is_lower_hex_bytes_width(source_checksum, 32) || !is_lower_hex_bytes_width(binding, 32) {
        bail!("state temp quarantine checksums are not canonical lowercase hex");
    }
    let target = OsString::from_vec(base64url_decode(encoded_target)?);
    validate_single_component(&target)?;
    let device = parse_fixed_lower_hex_u64(&body[device_separator + 1..inode_separator])?;
    let file = parse_fixed_lower_hex_u64(&body[inode_separator + 1..])?;
    let identity = FileIdentity { device, file };
    let source_checksum = std::str::from_utf8(source_checksum)?;
    let expected_binding = temp_quarantine_binding_tag(&target, source_checksum, &identity);
    if expected_binding.as_bytes() != binding {
        bail!("state temp quarantine target/source/identity binding does not match");
    }
    Ok(Some(TempQuarantineBinding { target, identity }))
}

#[cfg(unix)]
fn is_lower_hex_bytes_width(value: &[u8], width: usize) -> bool {
    value.len() == width
        && value
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(not(unix))]
fn atomic_replace_at(root: &SafeRoot, source: &OsStr, destination: &OsStr) -> Result<()> {
    let _ = source;
    bail!(
        "handle-relative atomic state replacement is unsupported on this platform: {}",
        root.path().join(destination).display()
    )
}

fn sync_directory(root: &SafeRoot) -> Result<()> {
    root.directory
        .sync_all()
        .with_context(|| format!("failed to flush state directory {}", root.path().display()))
}

#[cfg(target_os = "linux")]
fn quarantine_direct_child_directory_linux(
    root: &SafeRoot,
    child_name: &OsStr,
    quarantine_name: &OsStr,
    expected: &FileIdentity,
) -> Result<FileIdentity> {
    let parent_fd = root.directory.as_raw_fd();
    let source = c_string(child_name)?;
    let quarantine = c_string(quarantine_name)?;
    let source_stat = fstatat_optional_no_follow(parent_fd, &source)?;
    let quarantine_stat = fstatat_optional_no_follow(parent_fd, &quarantine)?;
    match (source_stat, quarantine_stat) {
        (Some(_), Some(_)) => bail!(
            "source and quarantine both exist; refusing ambiguous recovery for {}",
            root.path().join(child_name).display()
        ),
        (None, None) => bail!(
            "source and quarantine are both absent; refusing ambiguous recovery for {}",
            root.path().join(child_name).display()
        ),
        (None, Some(stat)) => {
            validate_private_quarantine_directory(root, quarantine_name, &stat, expected)?;
            Ok(expected.clone())
        }
        (Some(stat), None) => {
            validate_private_quarantine_directory(root, child_name, &stat, expected)?;
            rename_noreplace_at(root, child_name, quarantine_name)?;
            let rebound = fstatat_no_follow(parent_fd, &quarantine)?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != *expected
            {
                bail!(
                    "quarantine identity mismatch after atomic rename for {}",
                    root.path().join(child_name).display()
                );
            }
            if fstatat_optional_no_follow(parent_fd, &source)?.is_some() {
                bail!("source name reappeared during directory quarantine");
            }
            sync_directory(root)?;
            Ok(expected.clone())
        }
    }
}

#[cfg(target_os = "linux")]
fn restore_quarantined_direct_child_directory_linux(
    root: &SafeRoot,
    child_name: &OsStr,
    quarantine_name: &OsStr,
    expected: &FileIdentity,
) -> Result<FileIdentity> {
    let parent_fd = root.directory.as_raw_fd();
    let source = c_string(child_name)?;
    let quarantine = c_string(quarantine_name)?;
    let source_stat = fstatat_optional_no_follow(parent_fd, &source)?;
    let quarantine_stat = fstatat_optional_no_follow(parent_fd, &quarantine)?;
    match (source_stat, quarantine_stat) {
        (Some(_), Some(_)) => bail!(
            "source and quarantine both exist; refusing ambiguous restore for {}",
            root.path().join(child_name).display()
        ),
        (None, None) => bail!(
            "source and quarantine are both absent; refusing ambiguous restore for {}",
            root.path().join(child_name).display()
        ),
        (Some(stat), None) => {
            validate_private_quarantine_directory(root, child_name, &stat, expected)?;
            Ok(expected.clone())
        }
        (None, Some(stat)) => {
            validate_private_quarantine_directory(root, quarantine_name, &stat, expected)?;
            rename_noreplace_at(root, quarantine_name, child_name)?;
            let rebound = fstatat_no_follow(parent_fd, &source)?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != *expected
            {
                bail!(
                    "restored directory identity mismatch after atomic rename for {}",
                    root.path().join(child_name).display()
                );
            }
            if fstatat_optional_no_follow(parent_fd, &quarantine)?.is_some() {
                bail!("quarantine name reappeared during directory restore");
            }
            sync_directory(root)?;
            Ok(expected.clone())
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_private_quarantine_directory(
    root: &SafeRoot,
    name: &OsStr,
    stat: &libc::stat,
    expected: &FileIdentity,
) -> Result<()> {
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || identity_from_stat(stat) != *expected
        || stat.st_uid != unsafe { libc::geteuid() }
    {
        bail!(
            "quarantine directory binding is unsafe or changed: {}",
            root.path().join(name).display()
        );
    }
    let cname = c_string(name)?;
    let root_mount_id = linux_mount_identity_for_fd(root.directory.as_raw_fd())?.mount_id;
    verify_linux_mount_at(
        root.directory.as_raw_fd(),
        &cname,
        stat,
        root_mount_id,
        "quarantine directory entry",
    )?;
    let directory = openat_directory(root.directory.as_raw_fd(), &cname)?;
    let opened = fstat(directory.as_raw_fd())?;
    if identity_from_stat(&opened) != *expected {
        bail!("quarantine directory changed while opening its handle");
    }
    verify_linux_mount_for_fd(
        directory.as_raw_fd(),
        root_mount_id,
        "opened quarantine directory",
    )?;
    if opened.st_mode & 0o777 != 0o700 {
        if unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to tighten quarantine directory permissions at {}",
                    root.path().join(name).display()
                )
            });
        }
        let tightened = fstat(directory.as_raw_fd())?;
        if identity_from_stat(&tightened) != *expected || tightened.st_mode & 0o777 != 0o700 {
            bail!("quarantine directory did not become owner-private");
        }
        directory
            .sync_all()
            .context("failed to flush owner-private quarantine directory")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_quarantined_direct_child_tree_linux(
    root: &SafeRoot,
    quarantine_name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
) -> Result<bool> {
    let cleanup_name = quarantined_direct_child_cleanup_name(quarantine_name, expected)?;
    let quarantine = c_string(quarantine_name)?;
    let cleanup = c_string(&cleanup_name)?;
    let source_exists =
        fstatat_optional_no_follow(root.directory.as_raw_fd(), &quarantine)?.is_some();
    let cleanup_exists =
        fstatat_optional_no_follow(root.directory.as_raw_fd(), &cleanup)?.is_some();
    if !source_exists && !cleanup_exists {
        return Ok(false);
    }
    if source_exists && cleanup_exists {
        bail!(
            "quarantine and cleanup residue both exist; refusing ambiguous removal for {}",
            root.path().join(quarantine_name).display()
        );
    }
    let expected_mount_id = linux_mount_identity_for_fd(root.directory.as_raw_fd())?.mount_id;
    let preaudit_name = if source_exists {
        quarantine_name
    } else {
        cleanup_name.as_os_str()
    };
    audit_tree_at_name_linux_on_mount(
        root,
        preaudit_name,
        expected,
        policy,
        None,
        expected_mount_id,
    )?;
    quarantine_direct_child_directory_linux(root, quarantine_name, &cleanup_name, expected)?;
    remove_tree_at_name_linux(root, &cleanup_name, expected, policy)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn remove_direct_child_tree_unix(
    root: &SafeRoot,
    child_name: &OsStr,
    expected: Option<&FileIdentity>,
    policy: TreeLinkPolicy,
) -> Result<()> {
    let expected = match expected {
        Some(expected) => expected.clone(),
        None => {
            let name = c_string(child_name)?;
            let stat = fstatat_no_follow(root.directory.as_raw_fd(), &name)?;
            identity_from_stat(&stat)
        }
    };
    let quarantine_name = deletion_quarantine_name(child_name, &expected);
    quarantine_direct_child_directory_linux(root, child_name, &quarantine_name, &expected)?;
    remove_tree_at_name_linux(root, &quarantine_name, &expected, policy)
}

#[cfg(target_os = "linux")]
fn remove_tree_at_name_linux(
    root: &SafeRoot,
    name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
) -> Result<()> {
    remove_tree_at_name_linux_with_deadline(root, name, expected, policy, None)
}

#[cfg(target_os = "linux")]
fn remove_tree_at_name_linux_with_deadline(
    root: &SafeRoot,
    name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
    deadline: Option<Instant>,
) -> Result<()> {
    let expected_mount_id = linux_mount_identity_for_fd(root.directory.as_raw_fd())?.mount_id;
    remove_tree_at_name_linux_with_deadline_on_mount(
        root,
        name,
        expected,
        policy,
        deadline,
        expected_mount_id,
    )
}

#[cfg(target_os = "linux")]
fn audit_tree_at_name_linux_on_mount(
    root: &SafeRoot,
    name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
    deadline: Option<Instant>,
    expected_mount_id: u64,
) -> Result<()> {
    ensure_before_deadline(deadline, "before opening quarantine tree for audit")?;
    let directory = root.directory.as_ref();
    verify_linux_mount_for_fd(
        directory.as_raw_fd(),
        expected_mount_id,
        "quarantine audit root",
    )?;
    let root_stat = fstat(directory.as_raw_fd())?;
    let cname = c_string(name)?;
    let child_path_stat = fstatat_no_follow(directory.as_raw_fd(), &cname)?;
    verify_linux_mount_at(
        directory.as_raw_fd(),
        &cname,
        &child_path_stat,
        expected_mount_id,
        "top-level quarantine tree during pre-audit",
    )?;
    let child = openat_directory(directory.as_raw_fd(), &cname)?;
    let child_stat = fstat(child.as_raw_fd())?;
    if child_stat.st_dev != root_stat.st_dev {
        bail!(
            "refusing to cross a filesystem boundary while auditing {}",
            root.path().join(name).display()
        );
    }
    verify_linux_mount_for_fd(
        child.as_raw_fd(),
        expected_mount_id,
        "opened top-level quarantine tree during pre-audit",
    )?;
    if identity_from_stat(&child_stat) != *expected {
        bail!(
            "directory identity changed before deletion audit at {}",
            root.path().join(name).display()
        );
    }
    let mut audit_budget = TreeBudget::new();
    audit_directory_unix(
        child.as_raw_fd(),
        child_stat.st_dev,
        expected_mount_id,
        policy,
        0,
        &mut audit_budget,
        deadline,
    )
}

#[cfg(target_os = "linux")]
fn remove_tree_at_name_linux_with_deadline_on_mount(
    root: &SafeRoot,
    name: &OsStr,
    expected: &FileIdentity,
    policy: TreeLinkPolicy,
    deadline: Option<Instant>,
    expected_mount_id: u64,
) -> Result<()> {
    ensure_before_deadline(deadline, "before opening quarantined tree")?;
    let directory = root.directory.as_ref();
    verify_linux_mount_for_fd(
        directory.as_raw_fd(),
        expected_mount_id,
        "quarantine cleanup root",
    )?;
    let root_stat = fstat(directory.as_raw_fd())?;
    let cname = c_string(name)?;
    let child_path_stat = fstatat_no_follow(directory.as_raw_fd(), &cname)?;
    verify_linux_mount_at(
        directory.as_raw_fd(),
        &cname,
        &child_path_stat,
        expected_mount_id,
        "top-level quarantine tree",
    )?;
    let child = openat_directory(directory.as_raw_fd(), &cname)?;
    let child_stat = fstat(child.as_raw_fd())?;
    if child_stat.st_dev != root_stat.st_dev {
        bail!(
            "refusing to cross a filesystem boundary while deleting {}",
            root.path().join(name).display()
        );
    }
    verify_linux_mount_for_fd(
        child.as_raw_fd(),
        expected_mount_id,
        "opened top-level quarantine tree",
    )?;
    let observed = identity_from_stat(&child_stat);
    if expected != &observed {
        bail!(
            "directory identity changed before deletion at {}",
            root.path().join(name).display()
        );
    }
    let mut audit_budget = TreeBudget::new();
    audit_directory_unix(
        child.as_raw_fd(),
        child_stat.st_dev,
        expected_mount_id,
        policy,
        0,
        &mut audit_budget,
        deadline,
    )?;
    let mut removal_budget = TreeBudget::new();
    remove_directory_contents_unix(
        child.as_raw_fd(),
        child_stat.st_dev,
        expected_mount_id,
        policy,
        0,
        &mut removal_budget,
        deadline,
    )?;
    drop(child);
    ensure_before_deadline(deadline, "before top-level quarantine removal")?;
    let rebound = fstatat_no_follow(directory.as_raw_fd(), &cname)?;
    if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR || identity_from_stat(&rebound) != observed {
        bail!(
            "top-level directory binding changed immediately before removal: {}",
            root.path().join(name).display()
        );
    }
    verify_linux_mount_at(
        directory.as_raw_fd(),
        &cname,
        &rebound,
        expected_mount_id,
        "top-level quarantine tree before removal",
    )?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to remove verified directory {}",
                root.path().join(name).display()
            )
        });
    }
    sync_directory(root)?;
    root.verify()?;
    Ok(())
}

#[cfg(unix)]
struct TreeBudget {
    remaining_entries: usize,
}

struct InventoryBudget {
    remaining_entries: usize,
    total_path_bytes: usize,
    deadline: Instant,
}

impl InventoryBudget {
    fn consume_entry(&mut self) -> Result<()> {
        self.remaining_entries = self
            .remaining_entries
            .checked_sub(1)
            .context("repository inventory exceeded its global entry limit")?;
        Ok(())
    }

    fn consume_path(&mut self, path: &Path, limits: BoundedTreeWalkLimits) -> Result<()> {
        let bytes = path.as_os_str().len();
        if bytes == 0 || bytes > limits.max_path_bytes {
            bail!(
                "repository inventory path exceeds its {}-byte limit: {}",
                limits.max_path_bytes,
                path.display()
            );
        }
        self.total_path_bytes = self
            .total_path_bytes
            .checked_add(bytes)
            .context("repository inventory path byte count overflowed")?;
        if self.total_path_bytes > limits.max_total_path_bytes {
            bail!(
                "repository inventory paths exceed their {}-byte aggregate limit",
                limits.max_total_path_bytes
            );
        }
        Ok(())
    }

    fn ensure_before_deadline(&self, phase: &str) -> Result<()> {
        if Instant::now() >= self.deadline {
            bail!("repository inventory exceeded its time limit {phase}");
        }
        Ok(())
    }
}

#[cfg(unix)]
struct InventoryWalkState<'a, F> {
    root_device: libc::dev_t,
    #[cfg(target_os = "linux")]
    root_mount_id: Option<u64>,
    limits: BoundedTreeWalkLimits,
    options: BoundedTreeWalkOptions,
    budget: &'a mut InventoryBudget,
    action: &'a mut F,
    entries: &'a mut Vec<BoundedTreeEntry>,
    nested_repository_boundaries: &'a mut Vec<PathBuf>,
}

pub(crate) fn unsigned_to_u64<T>(value: T) -> u64
where
    T: TryInto<u64>,
{
    value.try_into().unwrap_or(u64::MAX)
}

#[cfg(any(unix, test))]
const fn device_id_bits_to_u64(value: i64) -> u64 {
    value as u64
}

/// Converts `stat::st_dev` to the representation returned by
/// `std::os::unix::fs::MetadataExt::dev`.
///
/// Unix targets vary in the width and signedness of `dev_t`. Converting through
/// `i64` sign-extends signed values, widens narrower unsigned values, and
/// round-trips every `u64` bit pattern before preserving it modulo 2^64.
#[cfg(unix)]
pub(crate) const fn device_id_to_u64(value: libc::dev_t) -> u64 {
    device_id_bits_to_u64(value as i64)
}

pub(crate) fn unsigned_to_u32<T>(value: T) -> u32
where
    T: TryInto<u32>,
{
    value.try_into().unwrap_or(u32::MAX)
}

#[cfg(unix)]
fn inventory_entry_size_bytes(value: libc::off_t) -> Result<u64> {
    u64::try_from(value).context("repository inventory entry size is negative or unrepresentable")
}

#[cfg(target_os = "linux")]
fn stat_mtime_seconds(stat: &libc::stat) -> i64 {
    stat.st_mtime
}

#[cfg(target_os = "linux")]
fn stat_mtime_nanoseconds(stat: &libc::stat) -> i64 {
    stat.st_mtime_nsec
}

#[cfg(target_os = "linux")]
fn stat_ctime_seconds(stat: &libc::stat) -> i64 {
    stat.st_ctime
}

#[cfg(target_os = "linux")]
fn stat_ctime_nanoseconds(stat: &libc::stat) -> i64 {
    stat.st_ctime_nsec
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_mtime_seconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_mtime_nanoseconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_ctime_seconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn stat_ctime_nanoseconds(_stat: &libc::stat) -> i64 {
    0
}

#[cfg(unix)]
impl<F> InventoryWalkState<'_, F>
where
    F: FnMut(&BoundedTreeEntry) -> Result<BoundedTreeWalkAction>,
{
    fn walk(&mut self, directory_fd: RawFd, relative_directory: &Path, depth: usize) -> Result<()> {
        self.budget
            .ensure_before_deadline("before directory enumeration")?;
        if nested_repository_boundary_enabled(depth, self.options)
            && inventory_nested_repository_marker_exists(directory_fd)?
        {
            self.budget
                .ensure_before_deadline("after nested repository marker probe")?;
            self.nested_repository_boundaries
                .push(relative_directory.to_path_buf());
            return Ok(());
        }
        if depth >= self.limits.max_depth {
            bail!(
                "repository inventory refused to descend beyond depth {} at {}",
                self.limits.max_depth,
                relative_directory.display()
            );
        }
        let names = inventory_directory_entries(directory_fd, self.budget)?;
        for name in names {
            self.budget
                .ensure_before_deadline("during entry inspection")?;
            let relative = relative_directory.join(&name);
            let entry_depth = depth.saturating_add(1);
            if entry_depth > self.limits.max_depth {
                bail!(
                    "repository inventory exceeded its maximum depth of {} at {}",
                    self.limits.max_depth,
                    relative.display()
                );
            }
            self.budget.consume_path(&relative, self.limits)?;
            let name_c = c_string(&name)?;
            let stat = fstatat_no_follow(directory_fd, &name_c).with_context(|| {
                format!("failed to inspect repository entry {}", relative.display())
            })?;
            if self.limits.same_device && stat.st_dev != self.root_device {
                bail!(
                    "repository inventory refused a cross-device entry: {}",
                    relative.display()
                );
            }
            #[cfg(target_os = "linux")]
            if let Some(root_mount_id) = self.root_mount_id {
                let entry_mount = linux_mount_identity_at(directory_fd, &name_c, &stat)?;
                if entry_mount.mount_id != root_mount_id {
                    bail!(
                        "repository inventory refused a mounted entry: {}",
                        relative.display()
                    );
                }
            }
            let file_kind = stat.st_mode & libc::S_IFMT;
            let kind = if file_kind == libc::S_IFDIR {
                BoundedTreeEntryKind::Directory
            } else if file_kind == libc::S_IFREG {
                BoundedTreeEntryKind::RegularFile
            } else if file_kind == libc::S_IFLNK {
                BoundedTreeEntryKind::Symlink
            } else {
                BoundedTreeEntryKind::Special
            };
            let entry = BoundedTreeEntry {
                relative_path: relative.clone(),
                kind,
                size_bytes: inventory_entry_size_bytes(stat.st_size)?,
                hard_link_count: unsigned_to_u64(stat.st_nlink),
                unix_mode: unsigned_to_u32(stat.st_mode & 0o7777),
                identity: identity_from_stat(&stat),
                modified_seconds: stat_mtime_seconds(&stat),
                modified_nanoseconds: stat_mtime_nanoseconds(&stat),
                changed_seconds: stat_ctime_seconds(&stat),
                changed_nanoseconds: stat_ctime_nanoseconds(&stat),
            };
            let decision = (self.action)(&entry)?;
            self.budget
                .ensure_before_deadline("after repository inventory callback")?;
            if matches!(
                decision,
                BoundedTreeWalkAction::Record | BoundedTreeWalkAction::RecordAndDescend
            ) {
                self.entries.push(entry.clone());
            }
            if decision == BoundedTreeWalkAction::RecordAndDescend {
                if kind != BoundedTreeEntryKind::Directory {
                    bail!(
                        "bounded tree walk requested descent through a non-directory: {}",
                        relative.display()
                    );
                }
                let child = openat_directory(directory_fd, &name_c).with_context(|| {
                    format!(
                        "failed to open repository directory without following links: {}",
                        relative.display()
                    )
                })?;
                let opened = fstat(child.as_raw_fd())?;
                if opened.st_mode & libc::S_IFMT != libc::S_IFDIR
                    || identity_from_stat(&opened) != entry.identity
                    || (self.limits.same_device && opened.st_dev != self.root_device)
                {
                    bail!(
                        "repository directory changed during bounded traversal: {}",
                        relative.display()
                    );
                }
                #[cfg(target_os = "linux")]
                if let Some(root_mount_id) = self.root_mount_id {
                    if linux_mount_identity_for_fd(child.as_raw_fd())?.mount_id != root_mount_id {
                        bail!(
                            "repository directory crossed a mount boundary while opening: {}",
                            relative.display()
                        );
                    }
                }
                self.walk(child.as_raw_fd(), &relative, entry_depth)?;
            }
            let rebound = fstatat_no_follow(directory_fd, &name_c).with_context(|| {
                format!(
                    "failed to revalidate repository entry after traversal: {}",
                    relative.display()
                )
            })?;
            if rebound.st_mode & libc::S_IFMT != file_kind
                || identity_from_stat(&rebound) != entry.identity
            {
                bail!(
                    "repository entry changed during bounded traversal: {}",
                    relative.display()
                );
            }
            #[cfg(target_os = "linux")]
            if let Some(root_mount_id) = self.root_mount_id {
                if linux_mount_identity_at(directory_fd, &name_c, &rebound)?.mount_id
                    != root_mount_id
                {
                    bail!(
                        "repository entry crossed a mount boundary during traversal: {}",
                        relative.display()
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn inventory_nested_repository_marker_exists(fd: RawFd) -> Result<bool> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(fd, c".git".as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(error).context("failed to probe nested repository marker without following links")
    }
}

#[cfg(unix)]
fn inventory_directory_entries(fd: RawFd, budget: &mut InventoryBudget) -> Result<Vec<OsString>> {
    budget.ensure_before_deadline("before directory stream open")?;
    let dot = c".";
    let stream_fd = unsafe {
        libc::openat(
            fd,
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if stream_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open an independent repository directory stream");
    }
    let directory = unsafe { libc::fdopendir(stream_fd) };
    if directory.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(stream_fd) };
        return Err(error).context("failed to open repository directory stream");
    }
    let mut entries = Vec::new();
    loop {
        if let Err(error) = budget.ensure_before_deadline("during directory enumeration") {
            unsafe { libc::closedir(directory) };
            return Err(error);
        }
        clear_thread_errno()?;
        let raw = unsafe { libc::readdir(directory) };
        if raw.is_null() {
            let errno = std::io::Error::last_os_error();
            unsafe { libc::closedir(directory) };
            if errno.raw_os_error().unwrap_or(0) != 0 {
                return Err(errno).context("failed while reading repository directory stream");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*raw).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if let Err(error) = budget.consume_entry() {
            unsafe { libc::closedir(directory) };
            return Err(error);
        }
        entries.push(OsString::from_vec(name.to_bytes().to_vec()));
    }
    entries.sort();
    budget.ensure_before_deadline("after directory entry sorting")?;
    Ok(entries)
}

#[cfg(unix)]
impl TreeBudget {
    fn new() -> Self {
        Self {
            remaining_entries: MAX_TREE_ENTRIES,
        }
    }

    fn consume(&mut self) -> Result<()> {
        self.remaining_entries = self
            .remaining_entries
            .checked_sub(1)
            .context("recursive deletion exceeded its global entry budget")?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn audit_directory_unix(
    fd: RawFd,
    device: libc::dev_t,
    expected_mount_id: u64,
    policy: TreeLinkPolicy,
    depth: usize,
    budget: &mut TreeBudget,
    deadline: Option<Instant>,
) -> Result<()> {
    ensure_before_deadline(deadline, "during recursive deletion audit")?;
    verify_linux_mount_for_fd(fd, expected_mount_id, "audited quarantine directory")?;
    if depth > MAX_TREE_DEPTH {
        bail!("recursive deletion exceeded its maximum depth of {MAX_TREE_DEPTH}");
    }
    for name in directory_entries_until(fd, budget, deadline)? {
        ensure_before_deadline(deadline, "during recursive deletion audit")?;
        let cname = c_string(&name)?;
        let stat = fstatat_no_follow(fd, &cname)?;
        if stat.st_dev != device {
            bail!(
                "refusing to traverse a mounted filesystem entry: {}",
                name.to_string_lossy()
            );
        }
        verify_linux_mount_at(
            fd,
            &cname,
            &stat,
            expected_mount_id,
            "quarantine tree entry during deletion audit",
        )?;
        let kind = stat.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            let child = openat_directory(fd, &cname)?;
            let opened = fstat(child.as_raw_fd())?;
            if identity_from_stat(&opened) != identity_from_stat(&stat) {
                bail!(
                    "directory entry changed during deletion preflight: {}",
                    name.to_string_lossy()
                );
            }
            verify_linux_mount_for_fd(
                child.as_raw_fd(),
                expected_mount_id,
                "opened quarantine child during deletion audit",
            )?;
            audit_directory_unix(
                child.as_raw_fd(),
                device,
                expected_mount_id,
                policy,
                depth.saturating_add(1),
                budget,
                deadline,
            )?;
        } else if kind == libc::S_IFLNK {
            if policy == TreeLinkPolicy::RejectLinksAndSpecialFiles {
                bail!(
                    "refusing symbolic link in artifact tree: {}",
                    name.to_string_lossy()
                );
            }
        } else if kind == libc::S_IFREG {
            if policy == TreeLinkPolicy::RejectLinksAndSpecialFiles && stat.st_nlink != 1 {
                bail!(
                    "refusing hard-linked file in artifact tree: {}",
                    name.to_string_lossy()
                );
            }
        } else if policy == TreeLinkPolicy::RejectLinksAndSpecialFiles {
            bail!(
                "refusing special file in artifact tree: {}",
                name.to_string_lossy()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_directory_contents_unix(
    fd: RawFd,
    device: libc::dev_t,
    expected_mount_id: u64,
    policy: TreeLinkPolicy,
    depth: usize,
    budget: &mut TreeBudget,
    deadline: Option<Instant>,
) -> Result<()> {
    ensure_before_deadline(deadline, "during recursive deletion")?;
    verify_linux_mount_for_fd(fd, expected_mount_id, "quarantine removal directory")?;
    if depth > MAX_TREE_DEPTH {
        bail!("recursive deletion exceeded its maximum depth of {MAX_TREE_DEPTH}");
    }
    for name in directory_entries_until(fd, budget, deadline)? {
        ensure_before_deadline(deadline, "before child quarantine")?;
        let source_name = c_string(&name)?;
        let stat = fstatat_no_follow(fd, &source_name)?;
        if stat.st_dev != device {
            bail!(
                "filesystem entry changed across devices during deletion: {}",
                name.to_string_lossy()
            );
        }
        verify_linux_mount_at(
            fd,
            &source_name,
            &stat,
            expected_mount_id,
            "quarantine tree entry before child rename",
        )?;
        let expected = identity_from_stat(&stat);
        let quarantine_name = entry_quarantine_name(&name, &expected);
        let quarantine_c = c_string(&quarantine_name)?;
        rename_noreplace_fd(fd, &source_name, &quarantine_c).with_context(|| {
            format!(
                "failed to quarantine child entry {} before deletion",
                name.to_string_lossy()
            )
        })?;
        let rebound = fstatat_no_follow(fd, &quarantine_c)?;
        if identity_from_stat(&rebound) != expected
            || rebound.st_mode & libc::S_IFMT != stat.st_mode & libc::S_IFMT
        {
            bail!(
                "child entry identity changed during quarantine: {}",
                name.to_string_lossy()
            );
        }
        verify_linux_mount_at(
            fd,
            &quarantine_c,
            &rebound,
            expected_mount_id,
            "quarantined child after rename",
        )?;
        if fstatat_optional_no_follow(fd, &source_name)?.is_some() {
            bail!("child source name reappeared during quarantine");
        }
        let cname = c_string(&quarantine_name)?;
        let quarantined = fstatat_no_follow(fd, &cname)?;
        if identity_from_stat(&quarantined) != expected {
            bail!("quarantined child identity changed before deletion");
        }
        verify_linux_mount_at(
            fd,
            &cname,
            &quarantined,
            expected_mount_id,
            "quarantined child before deletion",
        )?;
        let kind = quarantined.st_mode & libc::S_IFMT;
        if kind == libc::S_IFDIR {
            let child = openat_directory(fd, &cname)?;
            let opened = fstat(child.as_raw_fd())?;
            if identity_from_stat(&opened) != expected {
                bail!(
                    "directory entry changed during deletion: {}",
                    name.to_string_lossy()
                );
            }
            verify_linux_mount_for_fd(
                child.as_raw_fd(),
                expected_mount_id,
                "opened quarantine child during deletion",
            )?;
            remove_directory_contents_unix(
                child.as_raw_fd(),
                device,
                expected_mount_id,
                policy,
                depth.saturating_add(1),
                budget,
                deadline,
            )?;
            drop(child);
            ensure_before_deadline(deadline, "before child directory unlink")?;
            let rebound = fstatat_no_follow(fd, &cname)?;
            if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity_from_stat(&rebound) != expected
            {
                bail!(
                    "child directory binding changed immediately before removal: {}",
                    name.to_string_lossy()
                );
            }
            verify_linux_mount_at(
                fd,
                &cname,
                &rebound,
                expected_mount_id,
                "quarantine child directory before removal",
            )?;
            if unsafe { libc::unlinkat(fd, cname.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to remove child directory {}",
                        name.to_string_lossy()
                    )
                });
            }
        } else {
            if policy == TreeLinkPolicy::RejectLinksAndSpecialFiles
                && (kind == libc::S_IFLNK || kind != libc::S_IFREG || quarantined.st_nlink != 1)
            {
                bail!(
                    "artifact entry changed to an unsafe type: {}",
                    name.to_string_lossy()
                );
            }
            let rebound = fstatat_no_follow(fd, &cname)?;
            if identity_from_stat(&rebound) != expected || rebound.st_mode & libc::S_IFMT != kind {
                bail!(
                    "child entry binding changed immediately before unlink: {}",
                    name.to_string_lossy()
                );
            }
            verify_linux_mount_at(
                fd,
                &cname,
                &rebound,
                expected_mount_id,
                "quarantine child entry before unlink",
            )?;
            ensure_before_deadline(deadline, "before child unlink")?;
            if unsafe { libc::unlinkat(fd, cname.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to unlink child {}", name.to_string_lossy()));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn directory_entries(fd: RawFd, budget: &mut TreeBudget) -> Result<Vec<OsString>> {
    directory_entries_until(fd, budget, None)
}

#[cfg(unix)]
fn directory_entries_until(
    fd: RawFd,
    budget: &mut TreeBudget,
    deadline: Option<Instant>,
) -> Result<Vec<OsString>> {
    ensure_before_deadline(deadline, "before directory enumeration")?;
    let dot = c".";
    let stream_fd = unsafe {
        libc::openat(
            fd,
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if stream_fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open an independent directory stream handle");
    }
    let directory = unsafe { libc::fdopendir(stream_fd) };
    if directory.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(stream_fd) };
        return Err(error).context("failed to open directory stream");
    }
    let mut entries = Vec::new();
    loop {
        if let Err(error) = ensure_before_deadline(deadline, "during directory enumeration") {
            unsafe { libc::closedir(directory) };
            return Err(error);
        }
        clear_thread_errno()?;
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            let errno = std::io::Error::last_os_error();
            unsafe { libc::closedir(directory) };
            if errno.raw_os_error().unwrap_or(0) != 0 {
                return Err(errno).context("failed while reading directory stream");
            }
            break;
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        if let Err(error) = budget.consume() {
            unsafe { libc::closedir(directory) };
            return Err(error);
        }
        entries.push(OsString::from_vec(name.to_bytes().to_vec()));
    }
    entries.sort();
    Ok(entries)
}

fn ensure_before_deadline(deadline: Option<Instant>, phase: &str) -> Result<()> {
    #[cfg(test)]
    {
        let forced = SCAVENGE_DEADLINE_HOOK.with(|slot| {
            let mut slot = slot.borrow_mut();
            let triggered = slot.as_mut().is_some_and(|hook| hook(phase));
            if triggered {
                slot.take();
            }
            triggered
        });
        if forced {
            bail!("private directory scavenging exceeded its total time budget at {phase}");
        }
    }
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        bail!("private directory scavenging exceeded its total time budget at {phase}");
    }
    Ok(())
}

#[cfg(test)]
type ScavengeDeadlineHook = Box<dyn FnMut(&str) -> bool>;

#[cfg(test)]
thread_local! {
    static SCAVENGE_DEADLINE_HOOK: std::cell::RefCell<Option<ScavengeDeadlineHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_scavenge_deadline_hook(hook: impl FnMut(&str) -> bool + 'static) {
    SCAVENGE_DEADLINE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(target_os = "linux")]
fn clear_thread_errno() -> Result<()> {
    unsafe { *libc::__errno_location() = 0 };
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_thread_errno() -> Result<()> {
    unsafe { *libc::__error() = 0 };
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn clear_thread_errno() -> Result<()> {
    bail!("directory iteration is unsupported for this Unix errno ABI")
}

#[cfg(unix)]
fn openat_directory(fd: RawFd, name: &std::ffi::CStr) -> Result<File> {
    let opened = unsafe {
        libc::openat(
            fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if opened < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open directory entry without following links");
    }
    Ok(unsafe { File::from_raw_fd(opened) })
}

#[cfg(unix)]
fn validate_owned_direct_child_stat(
    stat: &libc::stat,
    expected_identity: &FileIdentity,
    kind: DirectChildType,
) -> Result<()> {
    let observed_kind = stat.st_mode & libc::S_IFMT;
    let kind_is_safe = match kind {
        DirectChildType::SingleLinkRegularFile => {
            observed_kind == libc::S_IFREG && stat.st_nlink == 1
        }
        DirectChildType::Directory => observed_kind == libc::S_IFDIR && stat.st_nlink != 0,
    };
    if !kind_is_safe
        || stat.st_uid != unsafe { libc::geteuid() }
        || identity_from_stat(stat) != *expected_identity
    {
        bail!("bound direct child type, ownership, linkage, or identity changed");
    }
    Ok(())
}

#[cfg(unix)]
fn fstat(fd: RawFd) -> Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to inspect file handle");
    }
    Ok(stat)
}

#[cfg(unix)]
fn fstatat_no_follow(fd: RawFd, name: &std::ffi::CStr) -> Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect directory entry without following links");
    }
    Ok(stat)
}

#[cfg(target_os = "linux")]
fn fstatat_optional_no_follow(fd: RawFd, name: &std::ffi::CStr) -> Result<Option<libc::stat>> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        return Ok(Some(stat));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error).context("failed to inspect optional directory entry without following links")
    }
}

#[cfg(unix)]
fn identity_from_stat(stat: &libc::stat) -> FileIdentity {
    FileIdentity {
        device: device_id_to_u64(stat.st_dev),
        file: unsigned_to_u64(stat.st_ino),
    }
}
