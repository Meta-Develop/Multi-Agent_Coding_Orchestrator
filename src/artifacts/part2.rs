fn validate_finalization(finalization: &ArtifactFinalization) -> Result<()> {
    if finalization.version != ARTIFACT_FORMAT_VERSION {
        bail!("artifact finalization format version is unsupported");
    }
    validate_producer(&finalization.provenance.producer)?;
    validate_writer_evidence(&finalization.writer_evidence)?;
    if !is_canonical_lower_hex_64(&finalization.mac_key_id)
        || finalization.mac_key_identity.file == 0
    {
        bail!("artifact finalization MAC key evidence is malformed");
    }
    if !is_canonical_lower_hex_64(&finalization.hmac_sha256) {
        bail!("artifact finalization HMAC is malformed");
    }
    let run_id = RunId::new(&finalization.run_id)?;
    if run_id.as_str() != finalization.run_id {
        bail!("artifact finalization run id is not canonical");
    }
    let final_report = validate_artifact_relative_path(&finalization.final_report)?;
    if final_report != finalization.family.final_report_relative_path() {
        bail!("artifact finalization has the wrong final report path");
    }
    if let Some(revision) = &finalization.provenance.source_revision {
        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("artifact source revision is not a full Git object id");
        }
    }
    if finalization.files.is_empty() || finalization.files.len() > MAX_ARTIFACT_FILES {
        bail!(
            "artifact finalization must contain 1 to {} files",
            MAX_ARTIFACT_FILES
        );
    }
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    for record in &finalization.files {
        let path = validate_artifact_relative_path(&record.path)?;
        if path != record.path || !seen.insert(path) {
            bail!("artifact finalization contains a duplicate or noncanonical path");
        }
        if record.bytes > MAX_ARTIFACT_FILE_BYTES {
            bail!("artifact file record exceeds the per-file byte limit");
        }
        total = total
            .checked_add(record.bytes)
            .context("artifact manifest byte total overflow")?;
        if total > MAX_ARTIFACT_TOTAL_BYTES {
            bail!("artifact manifest exceeds its aggregate byte limit");
        }
        if !is_canonical_lower_hex_64(&record.sha256) {
            bail!("artifact file record has an invalid SHA-256 digest");
        }
    }
    if !seen.contains(&final_report) {
        bail!("artifact final report is missing from the manifest");
    }
    let expected_publishable = finalization.publish_requested
        && finalization.provenance.source_revision.is_some()
        && finalization
            .files
            .iter()
            .all(|file| file.disposition == ArtifactFileDisposition::Publishable);
    if finalization.publishable != expected_publishable {
        bail!("artifact publishability does not match its provenance/file dispositions");
    }
    Ok(())
}

fn validate_writer_evidence(evidence: &ArtifactWriterEvidence) -> Result<()> {
    const PREFIX: &str = "maco-reservation-v1-";
    if evidence.run_root_identity.file == 0
        || evidence.run_identity.file == 0
        || evidence.writer_lock_identity.file == 0
    {
        bail!("artifact writer evidence contains an invalid zero inode identity");
    }
    let suffix = evidence
        .reservation_id
        .strip_prefix(PREFIX)
        .context("artifact reservation evidence has an unsupported format")?;
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("artifact reservation evidence is malformed");
    }
    Ok(())
}

fn verify_writer_evidence(
    evidence: &ArtifactWriterEvidence,
    run_root: &SafeRoot,
    run: &SafeRoot,
) -> Result<()> {
    validate_writer_evidence(evidence)?;
    run_root.verify()?;
    run.verify()?;
    if evidence.run_root_identity != *run_root.identity()
        || evidence.run_identity != *run.identity()
    {
        bail!("artifact writer evidence does not match the reserved run directories");
    }
    let observed_lock = ensure_private_regular_file(&run.path().join(RUN_LOCK_FILE))?;
    if observed_lock != evidence.writer_lock_identity {
        bail!("artifact writer lock identity does not match finalization evidence");
    }
    Ok(())
}

fn reservation_evidence_id(run_id: &str, run_identity: &FileIdentity) -> String {
    let counter = RESERVATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut first = RandomState::new().build_hasher();
    run_id.hash(&mut first);
    run_identity.device.hash(&mut first);
    run_identity.file.hash(&mut first);
    process::id().hash(&mut first);
    counter.hash(&mut first);
    now.hash(&mut first);
    let first = first.finish();
    let mut second = RandomState::new().build_hasher();
    first.hash(&mut second);
    now.rotate_left(31).hash(&mut second);
    let second = second.finish();
    format!("maco-reservation-v1-{first:016x}{second:016x}")
}

fn finalization_checksum(finalization: &ArtifactFinalization) -> Result<String> {
    let payload = serde_json::to_vec(&(
        finalization.version,
        &finalization.repository,
        finalization.family,
        &finalization.run_id,
        &finalization.provenance,
        &finalization.writer_evidence,
        &finalization.mac_key_id,
        &finalization.mac_key_identity,
        &finalization.final_report,
        &finalization.files,
        finalization.publish_requested,
        finalization.publishable,
    ))
    .context("failed to encode artifact finalization checksum payload")?;
    Ok(stable_checksum(&payload))
}

fn verify_manifest_paths(
    records: &BTreeMap<PathBuf, ArtifactFileRecord>,
    audited: &BTreeSet<PathBuf>,
) -> Result<()> {
    let expected = records.keys().cloned().collect::<BTreeSet<_>>();
    if &expected != audited {
        bail!("artifact tree does not exactly match its in-memory manifest");
    }
    Ok(())
}

fn verify_manifest_paths_with_marker(
    records: &[ArtifactFileRecord],
    audited: &BTreeSet<PathBuf>,
) -> Result<()> {
    let expected = records
        .iter()
        .map(|record| record.path.clone())
        .collect::<BTreeSet<_>>();
    if &expected != audited {
        bail!("artifact tree does not exactly match its finalized manifest");
    }
    Ok(())
}

fn verify_manifest_contents<'a>(
    run: &SafeRoot,
    records: impl IntoIterator<Item = &'a ArtifactFileRecord>,
) -> Result<()> {
    for record in records {
        read_and_verify_record(run, record)?;
    }
    Ok(())
}

fn read_and_verify_record(run: &SafeRoot, record: &ArtifactFileRecord) -> Result<Vec<u8>> {
    let (_parent, _file_name) = artifact_parent_and_name(run, &record.path, false)?;
    ensure_private_regular_file(&run.path().join(&record.path))?;
    let contents =
        BoundedRegularReader::read_relative(run.path(), &record.path, MAX_ARTIFACT_FILE_BYTES)?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) != record.bytes
        || sha256_hex(&contents) != record.sha256
    {
        bail!(
            "artifact file digest/length does not match its manifest: {}",
            record.path.display()
        );
    }
    Ok(contents)
}

fn audit_artifact_tree(run: &SafeRoot, require_private: bool) -> Result<BTreeSet<PathBuf>> {
    run.verify()?;
    let metadata = fs::symlink_metadata(run.path())?;
    #[cfg(unix)]
    let device = metadata.dev();
    #[cfg(not(unix))]
    let device = 0u64;
    let mut entries = 0usize;
    let mut files = BTreeSet::new();
    audit_artifact_directory(
        run.path(),
        Path::new(""),
        device,
        0,
        &mut entries,
        require_private,
        &mut files,
    )?;
    run.verify()?;
    Ok(files)
}

fn audit_artifact_directory(
    directory: &Path,
    relative: &Path,
    device: u64,
    depth: usize,
    entries: &mut usize,
    require_private: bool,
    files: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    if depth > MAX_ARTIFACT_PATH_COMPONENTS {
        bail!("artifact tree exceeds its maximum depth");
    }
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to audit artifact directory {}", directory.display()))?
    {
        *entries = entries
            .checked_add(1)
            .context("artifact tree entry count overflow")?;
        if *entries > MAX_ARTIFACT_FILES.saturating_mul(2).saturating_add(128) {
            bail!("artifact tree exceeds its global entry budget");
        }
        let entry = entry.context("failed to inspect artifact tree entry")?;
        let name = entry.file_name();
        let child_relative = relative.join(&name);
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure_same_device(&metadata, device, &entry.path())?;
        if metadata.file_type().is_symlink() {
            bail!(
                "artifact tree contains a symbolic link: {}",
                child_relative.display()
            );
        }
        if metadata.file_type().is_dir() {
            if require_private {
                ensure_private_directory(&entry.path())?;
            }
            audit_artifact_directory(
                &entry.path(),
                &child_relative,
                device,
                depth.saturating_add(1),
                entries,
                require_private,
                files,
            )?;
            continue;
        }
        if !metadata.file_type().is_file() {
            bail!(
                "artifact tree contains a special file: {}",
                child_relative.display()
            );
        }
        if child_relative == Path::new(RUN_LOCK_FILE)
            || child_relative == Path::new(FINALIZATION_MARKER)
        {
            ensure_private_regular_file(&entry.path())?;
            continue;
        }
        if require_private {
            ensure_private_regular_file(&entry.path())?;
        } else {
            ensure_regular_single_link(&entry.path())?;
        }
        validate_artifact_relative_path(&child_relative)?;
        files.insert(child_relative);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_same_device(metadata: &fs::Metadata, device: u64, path: &Path) -> Result<()> {
    if metadata.dev() != device {
        bail!(
            "artifact tree crosses a filesystem boundary: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_same_device(_metadata: &fs::Metadata, _device: u64, path: &Path) -> Result<()> {
    bail!(
        "artifact device-boundary validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private directory {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        bail!(
            "artifact directory is not a no-follow directory: {}",
            path.display()
        );
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "artifact directory is not owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o700 {
        bail!(
            "artifact directory is not owner-private (expected 0700, observed {:04o}): {}",
            mode,
            path.display()
        );
    }
    identity_for_path(path)
}

#[cfg(not(unix))]
fn ensure_private_directory(path: &Path) -> Result<FileIdentity> {
    bail!(
        "artifact directory ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn ensure_regular_single_link(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect artifact file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!(
            "artifact entry is not a regular no-follow file: {}",
            path.display()
        );
    }
    if metadata.nlink() != 1 {
        bail!(
            "artifact file must have exactly one hard link (observed {}): {}",
            metadata.nlink(),
            path.display()
        );
    }
    identity_for_path(path)
}

#[cfg(not(unix))]
fn ensure_regular_single_link(path: &Path) -> Result<FileIdentity> {
    bail!(
        "artifact regular-file validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn ensure_private_regular_file(path: &Path) -> Result<FileIdentity> {
    let identity = ensure_regular_single_link(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "artifact file is not owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "artifact file is not owner-private (expected 0600, observed {:04o}): {}",
            mode,
            path.display()
        );
    }
    Ok(identity)
}

#[cfg(not(unix))]
fn ensure_private_regular_file(path: &Path) -> Result<FileIdentity> {
    bail!(
        "artifact file ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn ensure_private_regular_file_handle(file: &File, path: &Path) -> Result<FileIdentity> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened artifact file {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        bail!(
            "opened artifact file is not an owner-private single-link regular file: {}",
            path.display()
        );
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn ensure_private_regular_file_handle(_file: &File, path: &Path) -> Result<FileIdentity> {
    bail!(
        "opened artifact file ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn open_private_artifact_append_file(
    parent: &SafeRoot,
    file_name: &OsStr,
    create: bool,
) -> Result<File> {
    parent.verify()?;
    let directory = open_safe_root_handle(parent)?;
    let name = CString::new(file_name.as_bytes()).context("artifact file name contains NUL")?;
    let mut flags =
        libc::O_WRONLY | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    if create {
        flags |= libc::O_CREAT | libc::O_EXCL;
    }
    let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to open private artifact for append: {}",
                parent.path().join(file_name).display()
            )
        });
    }
    let file = unsafe { File::from_raw_fd(fd) };
    ensure_private_regular_file_handle(&file, &parent.path().join(file_name))?;
    parent.verify()?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_artifact_append_file(
    _parent: &SafeRoot,
    file_name: &OsStr,
    _create: bool,
) -> Result<File> {
    bail!(
        "no-follow artifact append is unsupported on this platform: {}",
        Path::new(file_name).display()
    )
}

#[cfg(unix)]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

#[cfg(not(unix))]
fn filesystem_path_bytes(path: &Path) -> Vec<u8> {
    path.as_os_str().to_string_lossy().as_bytes().to_vec()
}

#[cfg(unix)]
fn rename_bound_directory(
    source_root: &SafeRoot,
    source_name: &OsStr,
    expected: &FileIdentity,
    destination_root: &SafeRoot,
    destination_name: &OsStr,
) -> Result<()> {
    source_root.verify()?;
    destination_root.verify()?;
    let source = open_safe_root_handle(source_root)?;
    let destination = open_safe_root_handle(destination_root)?;
    let source_name = CString::new(source_name.as_bytes()).context("source name contains NUL")?;
    let destination_name =
        CString::new(destination_name.as_bytes()).context("destination name contains NUL")?;
    let source_stat = fstatat_no_follow(source.as_raw_fd(), &source_name)?;
    if source_stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || identity_from_stat(&source_stat) != *expected
    {
        bail!("artifact source directory identity changed before quarantine");
    }
    let mut destination_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::fstatat(
            destination.as_raw_fd(),
            destination_name.as_ptr(),
            &mut destination_stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        bail!("artifact quarantine destination already exists");
    }
    let missing = std::io::Error::last_os_error();
    if missing.kind() != std::io::ErrorKind::NotFound {
        return Err(missing).context("failed to inspect artifact quarantine destination");
    }
    if unsafe {
        libc::renameat(
            source.as_raw_fd(),
            source_name.as_ptr(),
            destination.as_raw_fd(),
            destination_name.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to atomically quarantine artifact run");
    }
    let rebound = fstatat_no_follow(destination.as_raw_fd(), &destination_name)?;
    if rebound.st_mode & libc::S_IFMT != libc::S_IFDIR || identity_from_stat(&rebound) != *expected
    {
        bail!("artifact quarantine destination does not match the inspected run inode");
    }
    source
        .sync_all()
        .context("failed to flush artifact run root")?;
    destination
        .sync_all()
        .context("failed to flush artifact quarantine")?;
    destination_root.verify()?;
    Ok(())
}

#[cfg(not(unix))]
fn rename_bound_directory(
    _source_root: &SafeRoot,
    _source_name: &std::ffi::OsStr,
    _expected: &FileIdentity,
    _destination_root: &SafeRoot,
    _destination_name: &std::ffi::OsStr,
) -> Result<()> {
    bail!("handle-relative artifact quarantine is unsupported on this platform")
}

#[cfg(unix)]
fn open_safe_root_handle(root: &SafeRoot) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.path())
        .with_context(|| format!("failed to open safe root handle {}", root.path().display()))?;
    let metadata = file.metadata()?;
    let identity = FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    };
    if identity != *root.identity() {
        bail!("safe root path changed before handle-relative artifact operation");
    }
    Ok(file)
}

#[cfg(unix)]
fn fstatat_no_follow(fd: i32, name: &CStr) -> Result<libc::stat> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(fd, name.as_ptr(), &mut stat, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect artifact directory entry without following links");
    }
    Ok(stat)
}

#[cfg(unix)]
fn identity_from_stat(stat: &libc::stat) -> FileIdentity {
    FileIdentity {
        device: device_id_to_u64(stat.st_dev),
        file: unsigned_to_u64(stat.st_ino),
    }
}

fn finalization_hmac_payload(finalization: &ArtifactFinalization) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        finalization.version,
        &finalization.checksum,
        &finalization.repository,
        finalization.family,
        &finalization.run_id,
        &finalization.provenance,
        &finalization.writer_evidence,
        &finalization.mac_key_id,
        &finalization.mac_key_identity,
        &finalization.final_report,
        &finalization.files,
        finalization.publish_requested,
        finalization.publishable,
    ))
    .context("failed to encode canonical artifact HMAC payload")
}

fn finalization_hmac(
    authenticator: &RepositoryAuthenticator,
    finalization: &ArtifactFinalization,
) -> Result<String> {
    let payload = finalization_hmac_payload(finalization)?;
    Ok(authenticator
        .sign_legacy_artifact_finalization_v2(&payload)?
        .as_str()
        .to_string())
}

fn verify_finalization_hmac(
    authenticator: &RepositoryAuthenticator,
    finalization: &ArtifactFinalization,
) -> Result<()> {
    let payload = finalization_hmac_payload(finalization)?;
    let tag = AuthenticationTag::parse(finalization.hmac_sha256.clone())?;
    authenticator.verify_legacy_artifact_finalization_v2(&payload, &tag)
}

fn is_canonical_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
