fn github_repository_identity(remote_url: &str) -> Result<GithubRepositoryIdentity> {
    let PublicationRemoteTransport::Https { host, path, .. } =
        publication_remote_transport(remote_url)?;
    let mut components = path.split('/');
    let owner = components
        .next()
        .filter(|component| !component.is_empty())
        .context("GitHub origin URL omitted owner")?;
    let raw_name = components
        .next()
        .filter(|component| !component.is_empty())
        .context("GitHub origin URL omitted repository")?;
    if components.next().is_some() {
        bail!("GitHub origin URL must contain exactly owner/repository");
    }
    let name = raw_name.strip_suffix(".git").unwrap_or(raw_name);
    validate_github_slug(owner, "owner")?;
    validate_github_slug(name, "repository")?;
    Ok(GithubRepositoryIdentity {
        host,
        owner: owner.to_ascii_lowercase(),
        name: name.to_ascii_lowercase(),
    })
}

fn normalize_github_host(host: &str) -> Result<String> {
    let (hostname, port) = host
        .rsplit_once(':')
        .map_or((host, None), |(hostname, port)| (hostname, Some(port)));
    if hostname.is_empty()
        || hostname.len() > MAX_PUBLICATION_HOST_BYTES
        || hostname.contains(':')
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
    {
        bail!("GitHub origin URL host is invalid");
    }
    if hostname.split('.').any(|label| {
        label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
    }) {
        bail!("GitHub origin URL DNS label is invalid");
    }
    let port = port
        .map(|port| {
            let parsed = port
                .parse::<u16>()
                .ok()
                .filter(|parsed| *parsed != 0)
                .context("GitHub origin URL port is invalid")?;
            if port != parsed.to_string() {
                bail!("GitHub origin URL port was not canonical");
            }
            Ok(parsed)
        })
        .transpose()?;
    let hostname = hostname.to_ascii_lowercase();
    if hostname == "github.com" {
        if port.is_some_and(|port| port != 443) {
            bail!("github.com publication permits only the canonical HTTPS port");
        }
        return Ok(hostname);
    }
    if let Some(port) = port {
        return Ok(format!("{hostname}:{port}"));
    }
    Ok(hostname)
}

fn validate_github_slug(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_GITHUB_SLUG_BYTES
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("GitHub {label} component is invalid");
    }
    Ok(())
}

fn canonical_github_author_login(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > MAX_GITHUB_SLUG_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'[' | b']'))
    {
        bail!("GitHub expected author is empty, malformed, or oversized");
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_github_receipt_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    expected_number: u64,
) -> Result<()> {
    if expected_number == 0 {
        bail!("GitHub PR receipt number was zero");
    }
    validate_github_receipt_url_text(url)?;
    let (scheme, remainder) = url
        .split_once("://")
        .context("GitHub PR receipt URL was not absolute")?;
    if scheme != "https" {
        bail!("GitHub PR receipt URL was not HTTPS");
    }
    let slash = remainder
        .find('/')
        .context("GitHub PR receipt URL omitted repository path")?;
    let authority = &remainder[..slash];
    let host = normalize_github_host(authority)?;
    if host != authority {
        bail!("GitHub PR receipt URL host was not canonical");
    }
    let components = remainder[slash + 1..].split('/').collect::<Vec<_>>();
    if components.len() != 4
        || components[2] != "pull"
        || components[3] != expected_number.to_string()
    {
        bail!("GitHub PR receipt URL did not identify the expected pull request");
    }
    if host != expected.host
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
    {
        bail!("GitHub PR receipt URL did not match the bound forge repository");
    }
    Ok(())
}

fn validate_github_issue_receipt_url(
    url: &str,
    expected: &GithubRepositoryIdentity,
    expected_number: u64,
) -> Result<String> {
    if expected_number == 0 {
        bail!("GitHub issue receipt number was zero");
    }
    validate_github_receipt_url_text(url)?;
    let (scheme, remainder) = url
        .split_once("://")
        .context("GitHub issue receipt URL was not absolute")?;
    if scheme != "https" {
        bail!("GitHub issue receipt URL was not HTTPS");
    }
    let slash = remainder
        .find('/')
        .context("GitHub issue receipt URL omitted repository path")?;
    let authority = &remainder[..slash];
    let host = normalize_github_host(authority)?;
    let components = remainder[slash + 1..].split('/').collect::<Vec<_>>();
    let issue_number = components
        .get(3)
        .and_then(|component| component.parse::<u64>().ok())
        .filter(|number| *number > 0);
    if host != authority
        || components.len() != 4
        || components[2] != "issues"
        || issue_number != Some(expected_number)
        || components[3] != expected_number.to_string()
        || host != expected.host
        || !components[0].eq_ignore_ascii_case(&expected.owner)
        || !components[1].eq_ignore_ascii_case(&expected.name)
    {
        bail!("GitHub issue receipt URL did not match the bound repository and issue");
    }
    Ok(url.to_string())
}

fn validate_github_receipt_url_text(url: &str) -> Result<()> {
    if url.is_empty()
        || url.len() > MAX_GITHUB_RECEIPT_URL_BYTES
        || url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || url.contains(['?', '#', '%', '\\', '@'])
    {
        bail!("GitHub receipt URL was empty, noncanonical, or oversized");
    }
    Ok(())
}

#[cfg(test)]
fn publication_remote_binding_digest(
    secret: &[u8],
    remote_name: &str,
    remote_url: &str,
) -> Result<String> {
    if secret.len() != REMOTE_BINDING_SECRET_BYTES {
        bail!("publication remote binding secret has an invalid length");
    }
    let mut input = ZeroizingBytes(b"maco-publication-remote-binding-v1\0".to_vec());
    input.0.extend_from_slice(secret);
    input.0.push(0);
    input.0.extend_from_slice(remote_name.as_bytes());
    input.0.push(0);
    input.0.extend_from_slice(remote_url.as_bytes());
    Ok(Oid::hash_object(ObjectType::Blob, input.as_slice())
        .context("failed to digest publication remote binding")?
        .to_string())
}

#[cfg(test)]
fn load_or_create_remote_binding_secret(state_directory: &Path) -> Result<ZeroizingBytes> {
    let path = state_directory.join(REMOTE_BINDING_SECRET_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => return read_remote_binding_secret(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect publication remote binding key {}",
                    path.display()
                )
            })
        }
    }
    refuse_missing_binding_key_with_existing_transactions(state_directory)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch")?;
    let temporary_path = state_directory.join(format!(
        ".{REMOTE_BINDING_SECRET_FILE}-{}-{}.tmp",
        std::process::id(),
        timestamp.as_nanos()
    ));
    let mut secret = ZeroizingBytes(vec![0_u8; REMOTE_BINDING_SECRET_BYTES]);
    fill_os_random(secret.as_mut_slice())?;
    let result = (|| -> Result<ZeroizingBytes> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options.open(&temporary_path).with_context(|| {
            format!(
                "failed to create publication binding key temp file {}",
                temporary_path.display()
            )
        })?;
        file.write_all(secret.as_slice())
            .context("failed to write publication remote binding key")?;
        file.sync_all()
            .context("failed to persist publication remote binding key")?;
        match publish_remote_binding_secret_temp(&temporary_path, &path)? {
            RemoteBindingSecretPublish::Published { temp_is_link } => {
                sync_journal_directory(state_directory)?;
                if temp_is_link {
                    match fs::remove_file(&temporary_path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!(
                                    "failed to remove publication binding key temp file {}",
                                    temporary_path.display()
                                )
                            })
                        }
                    }
                    sync_journal_directory(state_directory)?;
                }
                read_remote_binding_secret(&path)
            }
            RemoteBindingSecretPublish::Existing => {
                fs::remove_file(&temporary_path).with_context(|| {
                    format!(
                        "failed to remove losing publication binding key temp file {}",
                        temporary_path.display()
                    )
                })?;
                read_remote_binding_secret(&path)
            }
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(test)]
enum RemoteBindingSecretPublish {
    Published { temp_is_link: bool },
    Existing,
}

#[cfg(all(test, unix))]
fn publish_remote_binding_secret_temp(
    temporary_path: &Path,
    final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    match fs::hard_link(temporary_path, final_path) {
        Ok(()) => Ok(RemoteBindingSecretPublish::Published { temp_is_link: true }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(RemoteBindingSecretPublish::Existing)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to publish publication remote binding key {}",
                final_path.display()
            )
        }),
    }
}

#[cfg(all(test, target_os = "windows"))]
fn publish_remote_binding_secret_temp(
    temporary_path: &Path,
    final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    const ERROR_FILE_EXISTS: i32 = 80;
    const ERROR_ALREADY_EXISTS: i32 = 183;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let existing = temporary_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let new = final_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: Both paths are NUL-terminated UTF-16 buffers that remain alive
    // for the call. MOVEFILE_REPLACE_EXISTING is deliberately not supplied.
    let moved = unsafe { MoveFileExW(existing.as_ptr(), new.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    if moved != 0 {
        return Ok(RemoteBindingSecretPublish::Published {
            temp_is_link: false,
        });
    }
    let error = std::io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(ERROR_FILE_EXISTS) | Some(ERROR_ALREADY_EXISTS)
    ) {
        Ok(RemoteBindingSecretPublish::Existing)
    } else {
        Err(error).with_context(|| {
            format!(
                "failed to publish publication remote binding key {}",
                final_path.display()
            )
        })
    }
}

#[cfg(all(test, not(any(unix, target_os = "windows"))))]
fn publish_remote_binding_secret_temp(
    _temporary_path: &Path,
    _final_path: &Path,
) -> Result<RemoteBindingSecretPublish> {
    bail!("atomic publication remote binding key creation is unsupported on this platform")
}

#[cfg(test)]
fn refuse_missing_binding_key_with_existing_transactions(state_directory: &Path) -> Result<()> {
    let transactions = state_directory.join("publication-transactions");
    match fs::symlink_metadata(&transactions) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || publication_metadata_is_windows_reparse_point(&metadata)
                || !metadata.file_type().is_dir()
            {
                bail!(
                    "publication transaction root {} is unsafe while the remote binding key is missing",
                    transactions.display()
                );
            }
            let mut entries = fs::read_dir(&transactions).with_context(|| {
                format!(
                    "failed to inspect existing publication transactions {}",
                    transactions.display()
                )
            })?;
            if entries.next().transpose()?.is_some() {
                bail!(
                    "publication remote binding key is missing while prior transaction entries exist; refusing to generate a replacement key"
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect publication transaction root {}",
                transactions.display()
            )
        }),
    }
}

fn refuse_legacy_publication_journals(repository: &Repository) -> Result<()> {
    let legacy_root = repository
        .commondir()
        .join("maco")
        .join("state")
        .join("publication-transactions");
    let metadata = match fs::symlink_metadata(&legacy_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).context("failed to inspect legacy publication journal root")
        }
    };
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(&metadata)
        || !metadata.is_dir()
    {
        bail!("legacy publication journal root is unsafe; signed migration is required");
    }
    let mut entries = fs::read_dir(&legacy_root)
        .context("failed to enumerate legacy publication journal root")?;
    if entries.next().transpose()?.is_some() {
        bail!(
            "legacy publication journals require explicit signed migration before authenticated external effects can run"
        );
    }
    Ok(())
}

#[cfg(test)]
fn read_remote_binding_secret(path: &Path) -> Result<ZeroizingBytes> {
    #[cfg(unix)]
    recover_remote_binding_secret_temp_link(path)?;
    let path_metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect publication remote binding key {}",
            path.display()
        )
    })?;
    validate_remote_binding_secret_metadata(path, &path_metadata, None)?;
    let mut file = open_remote_binding_secret_file(path)
        .with_context(|| format!("failed to open publication binding key {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open binding key {}", path.display()))?;
    validate_remote_binding_secret_metadata(path, &file_metadata, Some(&file))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            bail!(
                "publication remote binding key {} changed while being opened",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        let path_snapshot =
            crate::file_identity::open_windows_path_identity(path).with_context(|| {
                format!(
                    "failed to open publication binding key identity {}",
                    path.display()
                )
            })?;
        validate_remote_binding_secret_metadata(path, &path_snapshot.metadata, None)?;
        let file_identity = crate::file_identity::windows_file_identity(&file)
            .context("failed to inspect open publication binding key identity")?;
        if path_snapshot.identity != file_identity {
            bail!(
                "publication remote binding key {} changed while being opened",
                path.display()
            );
        }
    }
    let mut secret = ZeroizingBytes(Vec::new());
    Read::by_ref(&mut file)
        .take((REMOTE_BINDING_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut secret.0)
        .with_context(|| format!("failed to read publication binding key {}", path.display()))?;
    if secret.len() != REMOTE_BINDING_SECRET_BYTES {
        bail!(
            "publication remote binding key {} has invalid length {}; expected {}",
            path.display(),
            secret.len(),
            REMOTE_BINDING_SECRET_BYTES
        );
    }
    Ok(secret)
}

#[cfg(all(test, target_os = "windows"))]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(all(test, unix))]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(all(test, not(any(unix, target_os = "windows"))))]
fn open_remote_binding_secret_file(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(all(test, unix))]
fn recover_remote_binding_secret_temp_link(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect publication remote binding key {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() || metadata.nlink() == 1
    {
        return Ok(());
    }
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid has no arguments and returns the effective numeric uid.
    let effective_uid = unsafe { geteuid() };
    if metadata.nlink() != 2
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != REMOTE_BINDING_SECRET_BYTES as u64
    {
        return Ok(());
    }
    let parent = path
        .parent()
        .context("publication remote binding key has no parent directory")?;
    let mut matching_temp = None;
    for entry in fs::read_dir(parent).with_context(|| {
        format!(
            "failed to inspect publication binding key directory {}",
            parent.display()
        )
    })? {
        let entry = entry.with_context(|| {
            format!(
                "failed to read publication binding key directory entry in {}",
                parent.display()
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_remote_binding_secret_temp_name(name) {
            continue;
        }
        let candidate = entry.path();
        let candidate_metadata = fs::symlink_metadata(&candidate).with_context(|| {
            format!(
                "failed to inspect publication binding key temp link {}",
                candidate.display()
            )
        })?;
        if candidate_metadata.file_type().is_file()
            && !candidate_metadata.file_type().is_symlink()
            && candidate_metadata.dev() == metadata.dev()
            && candidate_metadata.ino() == metadata.ino()
            && candidate_metadata.uid() == effective_uid
            && candidate_metadata.permissions().mode() & 0o777 == 0o600
            && candidate_metadata.len() == REMOTE_BINDING_SECRET_BYTES as u64
            && matching_temp.replace(candidate).is_some()
        {
            bail!(
                "publication remote binding key has multiple matching temp hard links; refusing recovery"
            );
        }
    }
    let Some(matching_temp) = matching_temp else {
        return Ok(());
    };
    fs::remove_file(&matching_temp).with_context(|| {
        format!(
            "failed to recover publication binding key temp link {}",
            matching_temp.display()
        )
    })?;
    sync_journal_directory(parent)?;
    let recovered = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to verify recovered publication binding key {}",
            path.display()
        )
    })?;
    if recovered.dev() != metadata.dev()
        || recovered.ino() != metadata.ino()
        || recovered.nlink() != 1
    {
        bail!(
            "publication remote binding key {} did not recover to one link",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
fn is_remote_binding_secret_temp_name(name: &str) -> bool {
    let prefix = format!(".{REMOTE_BINDING_SECRET_FILE}-");
    let Some(stem) = name
        .strip_prefix(&prefix)
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, nanos)) = stem.split_once('-') else {
        return false;
    };
    !pid.is_empty()
        && !nanos.is_empty()
        && !nanos.contains('-')
        && pid.parse::<u32>().is_ok_and(|pid| pid > 0)
        && nanos.parse::<u128>().is_ok_and(|nanos| nanos > 0)
}

#[cfg(test)]
fn validate_remote_binding_secret_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    opened_file: Option<&fs::File>,
) -> Result<()> {
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(metadata)
        || !metadata.file_type().is_file()
    {
        bail!(
            "publication remote binding key {} is not a regular non-reparse file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let effective_uid = unsafe { geteuid() };
        if metadata.uid() != effective_uid {
            bail!(
                "publication remote binding key {} is not owned by the current effective user",
                path.display()
            );
        }
        if metadata.nlink() != 1 {
            bail!(
                "publication remote binding key {} has multiple hard links",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o777 != 0o600 {
            bail!(
                "publication remote binding key {} must have Unix mode 0600",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        let number_of_links = match opened_file {
            Some(file) => {
                crate::file_identity::windows_file_link_count(file).with_context(|| {
                    format!(
                        "failed to inspect open Windows link count for {}",
                        path.display()
                    )
                })?
            }
            None => publication_windows_path_link_count(path)?,
        };
        if number_of_links != 1 {
            bail!(
                "publication remote binding key {} must have exactly one hard link",
                path.display()
            );
        }
    }
    #[cfg(not(target_os = "windows"))]
    let _ = opened_file;
    Ok(())
}

#[cfg(target_os = "windows")]
fn publication_metadata_is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(target_os = "windows")]
fn publication_windows_path_link_count(path: &Path) -> Result<u32> {
    crate::file_identity::open_windows_path_identity(path)
        .with_context(|| {
            format!(
                "failed to inspect Windows link count for {}",
                path.display()
            )
        })
        .map(|snapshot| snapshot.number_of_links)
}

#[cfg(not(target_os = "windows"))]
fn publication_metadata_is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(all(test, unix))]
fn fill_os_random(destination: &mut [u8]) -> Result<()> {
    fs::File::open("/dev/urandom")
        .context("failed to open operating-system random source")?
        .read_exact(destination)
        .context("failed to read operating-system random source")
}

#[cfg(all(test, target_os = "windows"))]
fn fill_os_random(destination: &mut [u8]) -> Result<()> {
    use std::ffi::c_void;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            buffer_length: u32,
            flags: u32,
        ) -> i32;
    }
    let length = u32::try_from(destination.len()).context("random buffer was too large")?;
    // SAFETY: destination is writable for `length` bytes, a null algorithm
    // handle is required with BCRYPT_USE_SYSTEM_PREFERRED_RNG, and NTSTATUS is checked.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            destination.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        bail!("Windows BCryptGenRandom failed with NTSTATUS {status:#x}");
    }
    Ok(())
}

#[cfg(all(test, not(any(unix, target_os = "windows"))))]
fn fill_os_random(_destination: &mut [u8]) -> Result<()> {
    bail!("publication remote binding keys are unsupported on this platform")
}

impl PublicationTransaction {
    fn open(
        repo_root: &Path,
        report: &PrPublicationReport,
        remote_name: &str,
        remote_url: &str,
        expected_oid: &str,
        source_guard: Option<ExternalSourceGuard>,
    ) -> Result<Self> {
        let expected =
            Oid::from_str(expected_oid).context("publication expected OID was invalid")?;
        if expected.to_string() != expected_oid {
            bail!("publication expected OID was not canonical lowercase hexadecimal");
        }
        validate_publication_remote_url(remote_url)?;
        if matches!(report.forge, ForgeKind::Git | ForgeKind::Github) {
            publication_remote_transport(remote_url)?;
        }
        let expected_base_oid = report
            .base_head
            .as_deref()
            .map(Oid::from_str)
            .transpose()
            .context("publication expected base OID was invalid")?
            .map(|oid| oid.to_string());
        if report.forge == ForgeKind::Github && expected_base_oid.is_none() {
            bail!("GitHub publication requires an exact reviewed base OID");
        }
        let github_repository = match report.forge {
            ForgeKind::Github => Some(github_repository_identity(remote_url)?),
            ForgeKind::Git | ForgeKind::Fake => None,
        };
        let source_repository = source_guard
            .as_ref()
            .map(|source| -> Result<GithubRepositoryIdentity> {
                let repository = github_repository_identity(remote_url)?;
                if repository.host != source.repository_host
                    || repository.selector() != source.repository_selector
                {
                    bail!("publication origin changed from the exact guarded source repository");
                }
                Ok(repository)
            })
            .transpose()?;
        let expected_pr_author = match report.forge {
            ForgeKind::Github => Some(select_github_expected_author_with(|key| {
                env::var(key).ok()
            })?),
            ForgeKind::Git | ForgeKind::Fake => None,
        };
        let expected_pr_title = (report.forge == ForgeKind::Github).then(|| report.title.clone());
        let unmarked_pr_body =
            (report.forge == ForgeKind::Github).then(|| pr_body(&report.preview));
        let repo = crate::git_repository::open(repo_root).with_context(|| {
            format!(
                "failed to open repository for publication journal {}",
                repo_root.display()
            )
        })?;
        refuse_legacy_publication_journals(&repo)?;
        let auth = repository_auth_writer(repo_root)?
            .into_authenticator()
            .context("failed to establish authenticated publication effect ledger")?;
        let repository_identity = auth.binding().repository_id.clone();
        let repository_selector = source_repository
            .as_ref()
            .or(github_repository.as_ref())
            .map(GithubRepositoryIdentity::selector)
            .unwrap_or_else(|| redact_remote_url(remote_url));
        drop(auth);
        let remote_display = redact_remote_url(remote_url);
        let push_effect_request = ExternalEffectRequest::new(
            "git",
            &repository_selector,
            &repository_identity,
            source_guard.clone(),
            ExternalEffectOperation::GitPush,
            serde_json::json!({
                "version": 1,
                "repository": repository_selector,
                "remote_name": remote_name,
                "remote_url": remote_url,
                "base": report.base,
                "expected_base_oid": expected_base_oid,
            }),
            serde_json::json!({
                "version": 1,
                "expected_oid": expected_oid,
            }),
        )?;
        let remote_branch = format!("maco/effects/{}", &push_effect_request.effect_id[..32]);
        let remote_ref = format!("refs/heads/{remote_branch}");
        let pr_effect_request = match report.forge {
            ForgeKind::Github => Some(ExternalEffectRequest::new(
                "github",
                &repository_selector,
                &repository_identity,
                source_guard,
                ExternalEffectOperation::GithubPullRequest,
                serde_json::json!({
                    "version": 1,
                    "repository": repository_selector,
                    "expected_oid": expected_oid,
                    "expected_base_oid": expected_base_oid,
                    "base": report.base,
                }),
                serde_json::json!({
                    "version": 1,
                    "title": expected_pr_title,
                    "body": unmarked_pr_body,
                    "draft": report.draft,
                    "expected_author": expected_pr_author,
                }),
            )?),
            ForgeKind::Git | ForgeKind::Fake => None,
        };
        let pr_marker_nonce = pr_effect_request
            .as_ref()
            .map(|request| request.effect_id.clone());
        let expected_pr_body = match (&pr_effect_request, &unmarked_pr_body) {
            (Some(request), Some(body)) => {
                Some(external_effect_marked_body(body, &request.marker)?)
            }
            (None, None) => None,
            _ => bail!("publication transaction marker did not match its forge"),
        };

        let transaction_id = format!("effect-{}", push_effect_request.effect_id);
        let remote_binding_digest = stable_json_digest(&(
            "maco_publication_remote_binding_v1",
            remote_name,
            remote_url,
        ))?;
        Ok(Self {
            directory: PathBuf::new(),
            journal: PublicationTransactionJournal {
                version: PUBLICATION_JOURNAL_VERSION,
                transaction_id,
                sequence: 0,
                agent_id: report.agent_id.clone(),
                forge: report.forge,
                expected_oid: expected_oid.to_string(),
                expected_base_oid,
                remote_name: remote_name.to_string(),
                remote_binding_digest,
                remote_display,
                remote_ref,
                remote_branch,
                github_repository,
                pr_marker_nonce,
                expected_pr_title,
                expected_pr_body,
                expected_pr_author,
                base: report.base.clone(),
                draft: report.draft,
                phase: PublicationTransactionPhase::Prepared,
                push_observed_oid: None,
                pr_url: None,
                pr_head_oid: None,
                pr_base: None,
                pr_state: None,
                pr_is_draft: None,
                pr_number: None,
                pr_title: None,
                pr_body: None,
                pr_head_ref_name: None,
                pr_head_repository_owner: None,
                pr_head_repository_name: None,
                pr_is_cross_repository: None,
                pr_author: None,
                create_attempted: false,
                created_by_transaction: false,
                observed_existing_pr: false,
                last_error: None,
                updated_unix_seconds: 0,
            },
            remote_url: remote_url.to_string(),
            push_effect_request: Some(push_effect_request),
            pr_effect_request,
        })
    }

    fn persist(&mut self) -> Result<()> {
        if self.push_effect_request.is_some() {
            self.journal.sequence = self
                .journal
                .sequence
                .checked_add(1)
                .context("publication receipt sequence overflow")?;
            self.journal.updated_unix_seconds = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system time before UNIX epoch")?
                .as_secs();
            return Ok(());
        }
        self.journal.sequence = self
            .journal
            .sequence
            .checked_add(1)
            .context("publication journal sequence overflow")?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX epoch")?;
        self.journal.updated_unix_seconds = timestamp.as_secs();
        let final_path = self
            .directory
            .join(format!("{:020}.json", self.journal.sequence));
        let temporary_path = self.directory.join(format!(
            ".{:020}-{}-{}.tmp",
            self.journal.sequence,
            std::process::id(),
            timestamp.as_nanos()
        ));
        let mut bytes = serde_json::to_vec_pretty(&self.journal)
            .context("failed to encode publication transaction journal")?;
        bytes.push(b'\n');
        if bytes.len() as u64 > PUBLICATION_JOURNAL_MAX_RECORD_BYTES {
            self.journal.sequence = self.journal.sequence.saturating_sub(1);
            bail!(
                "publication journal record exceeded the {}-byte safety limit",
                PUBLICATION_JOURNAL_MAX_RECORD_BYTES
            );
        }
        let mut published = false;
        let write_result = (|| -> Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary_path).with_context(|| {
                format!(
                    "failed to create publication journal temp file {}",
                    temporary_path.display()
                )
            })?;
            file.write_all(&bytes)
                .context("failed to write publication transaction journal")?;
            file.sync_all()
                .context("failed to persist publication transaction journal")?;
            fs::hard_link(&temporary_path, &final_path).with_context(|| {
                format!(
                    "failed to atomically publish journal record {}",
                    final_path.display()
                )
            })?;
            published = true;
            sync_journal_directory(&self.directory)?;
            fs::remove_file(&temporary_path).with_context(|| {
                format!(
                    "failed to remove published journal temp file {}",
                    temporary_path.display()
                )
            })?;
            sync_journal_directory(&self.directory)?;
            prune_publication_journal(&self.directory, 32)?;
            Ok(())
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
            if !published {
                self.journal.sequence = self.journal.sequence.saturating_sub(1);
            }
        }
        write_result
    }

    fn persist_if_changed(&mut self, previous: &PublicationTransactionJournal) -> Result<()> {
        if &self.journal == previous {
            Ok(())
        } else {
            self.persist()
        }
    }

    fn advance_phase(&mut self, phase: PublicationTransactionPhase) {
        if phase > self.journal.phase {
            self.journal.phase = phase;
        }
    }

    fn receipt(&self) -> PrPublicationReceipt {
        PrPublicationReceipt {
            version: self.journal.version,
            transaction_id: self.journal.transaction_id.clone(),
            sequence: self.journal.sequence,
            phase: self.journal.phase,
            expected_oid: self.journal.expected_oid.clone(),
            expected_base_oid: self.journal.expected_base_oid.clone(),
            remote_ref: self.journal.remote_ref.clone(),
            github_repository: self
                .journal
                .github_repository
                .as_ref()
                .map(GithubRepositoryIdentity::selector),
            push_observed_oid: self.journal.push_observed_oid.clone(),
            pr_url: self.journal.pr_url.clone(),
            pr_head_oid: self.journal.pr_head_oid.clone(),
            pr_base: self.journal.pr_base.clone(),
            pr_state: self.journal.pr_state.clone(),
            pr_is_draft: self.journal.pr_is_draft,
            create_attempted: self.journal.create_attempted,
            created_by_transaction: self.journal.created_by_transaction,
            observed_existing_pr: self.journal.observed_existing_pr,
            last_error: self.journal.last_error.clone(),
        }
    }
}

#[cfg(test)]
fn load_latest_publication_journal(
    directory: &Path,
) -> Result<Option<PublicationTransactionJournal>> {
    let records = publication_journal_records(directory)?;
    let mut latest = None;
    for (sequence, path) in records {
        let bytes = read_publication_journal_record(&path)?;
        let journal: PublicationTransactionJournal = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid journal record {}", path.display()))?;
        if journal.sequence != sequence {
            bail!(
                "publication journal record {} has a mismatched sequence",
                path.display()
            );
        }
        validate_publication_journal(&journal)?;
        if let Some(previous) = latest.as_ref() {
            validate_publication_journal_transition(previous, &journal)?;
        }
        latest = Some(journal);
    }
    Ok(latest)
}

fn prune_publication_journal(directory: &Path, retain: usize) -> Result<()> {
    let records = publication_journal_records(directory)?;
    let remove_count = records.len().saturating_sub(retain.max(1));
    for (_, path) in records.into_iter().take(remove_count) {
        fs::remove_file(&path)
            .with_context(|| format!("failed to prune journal record {}", path.display()))?;
    }
    if remove_count > 0 {
        sync_journal_directory(directory)?;
    }
    Ok(())
}

fn publication_journal_records(directory: &Path) -> Result<Vec<(u64, PathBuf)>> {
    #[cfg(not(windows))]
    let directory_metadata = validate_publication_journal_directory(directory)?;
    #[cfg(windows)]
    let directory_identity = {
        validate_publication_journal_directory(directory)?;
        windows_publication_journal_directory_identity(directory)?
    };
    let mut paths = Vec::new();
    let mut entry_count = 0_usize;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("failed to list journal directory {}", directory.display()))?
    {
        entry_count = entry_count
            .checked_add(1)
            .context("publication journal directory entry count overflow")?;
        if entry_count > PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES {
            bail!(
                "publication journal directory exceeded the {}-entry safety limit",
                PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES
            );
        }
        let entry = entry.with_context(|| {
            format!(
                "failed to read journal directory entry in {}",
                directory.display()
            )
        })?;
        paths.push(entry.path());
    }
    #[cfg(not(windows))]
    let listed = validate_publication_journal_directory(directory)?;
    #[cfg(windows)]
    validate_publication_journal_directory(directory)?;
    #[cfg(windows)]
    let identity_matches =
        directory_identity == windows_publication_journal_directory_identity(directory)?;
    #[cfg(not(windows))]
    let identity_matches = publication_same_filesystem_identity(&directory_metadata, &listed);
    if !identity_matches {
        bail!("publication journal directory changed identity while it was listed");
    }

    let mut records = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("failed to inspect journal record {}", path.display()))?;
        validate_publication_journal_record_metadata(&path, &metadata, None)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("publication journal filename was not UTF-8")?;
        if is_publication_journal_temp_name(name) {
            bail!(
                "publication journal contains incomplete temporary record {}",
                path.display()
            );
        }
        let sequence = name
            .strip_suffix(".json")
            .filter(|sequence| {
                sequence.len() == 20 && sequence.bytes().all(|byte| byte.is_ascii_digit())
            })
            .context("publication journal JSON filename was not a canonical sequence")?
            .parse::<u64>()
            .context("publication journal sequence was invalid")?;
        records.push((sequence, path));
        if records.len() > PUBLICATION_JOURNAL_MAX_RECORDS {
            bail!(
                "publication journal exceeded the {}-record safety limit",
                PUBLICATION_JOURNAL_MAX_RECORDS
            );
        }
    }
    records.sort_by_key(|(sequence, _)| *sequence);
    #[cfg(not(windows))]
    let after = validate_publication_journal_directory(directory)?;
    #[cfg(windows)]
    validate_publication_journal_directory(directory)?;
    #[cfg(windows)]
    let identity_matches =
        directory_identity == windows_publication_journal_directory_identity(directory)?;
    #[cfg(not(windows))]
    let identity_matches = publication_same_filesystem_identity(&directory_metadata, &after);
    if !identity_matches {
        bail!("publication journal directory changed identity while records were inspected");
    }
    Ok(records)
}

fn is_publication_journal_temp_name(name: &str) -> bool {
    let Some(remainder) = name.strip_prefix('.') else {
        return false;
    };
    let Some(remainder) = remainder.strip_suffix(".tmp") else {
        return false;
    };
    let mut fields = remainder.split('-');
    fields.next().is_some_and(|sequence| {
        sequence.len() == 20 && sequence.bytes().all(|byte| byte.is_ascii_digit())
    }) && fields
        .next()
        .is_some_and(|pid| !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()))
        && fields.next().is_some_and(|nanos| {
            !nanos.is_empty() && nanos.bytes().all(|byte| byte.is_ascii_digit())
        })
        && fields.next().is_none()
}

fn validate_publication_journal_directory(directory: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(directory).with_context(|| {
        format!(
            "failed to inspect publication journal directory {}",
            directory.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(&metadata)
        || !metadata.file_type().is_dir()
    {
        bail!(
            "publication journal directory {} is not a real directory",
            directory.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "publication journal directory {} has a foreign owner or unsafe mode",
                directory.display()
            );
        }
    }
    Ok(metadata)
}

#[cfg(windows)]
fn windows_publication_journal_directory_identity(
    directory: &Path,
) -> Result<crate::file_identity::WindowsFileIdentity> {
    let snapshot =
        crate::file_identity::open_windows_path_identity(directory).with_context(|| {
            format!(
                "failed to open publication journal directory identity {}",
                directory.display()
            )
        })?;
    if snapshot.metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(&snapshot.metadata)
        || !snapshot.metadata.file_type().is_dir()
    {
        bail!(
            "publication journal directory {} is not a real directory",
            directory.display()
        );
    }
    Ok(snapshot.identity)
}

fn validate_publication_journal_record_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    opened_file: Option<&fs::File>,
) -> Result<()> {
    if metadata.file_type().is_symlink()
        || publication_metadata_is_windows_reparse_point(metadata)
        || !metadata.file_type().is_file()
    {
        bail!(
            "publication journal record {} is not a real regular file",
            path.display()
        );
    }
    if metadata.len() == 0 || metadata.len() > PUBLICATION_JOURNAL_MAX_RECORD_BYTES {
        bail!(
            "publication journal record {} has an invalid size",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no arguments and returns the effective numeric uid.
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!(
                "publication journal record {} has a foreign owner, unsafe mode, or multiple links",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        let number_of_links = match opened_file {
            Some(file) => {
                crate::file_identity::windows_file_link_count(file).with_context(|| {
                    format!(
                        "failed to inspect open Windows link count for {}",
                        path.display()
                    )
                })?
            }
            None => publication_windows_path_link_count(path)?,
        };
        if number_of_links != 1 {
            bail!(
                "publication journal record {} has multiple links",
                path.display()
            );
        }
    }
    #[cfg(not(target_os = "windows"))]
    let _ = opened_file;
    Ok(())
}

#[cfg(test)]
fn read_publication_journal_record(path: &Path) -> Result<Vec<u8>> {
    #[cfg(windows)]
    let path_snapshot = crate::file_identity::open_windows_path_identity(path)
        .with_context(|| format!("failed to inspect journal record {}", path.display()))?;
    #[cfg(windows)]
    let path_metadata = &path_snapshot.metadata;
    #[cfg(not(windows))]
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &path_metadata, None)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open journal record {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect opened journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &file_metadata, Some(&file))?;
    #[cfg(windows)]
    let file_identity = crate::file_identity::windows_file_identity(&file).with_context(|| {
        format!(
            "failed to inspect opened journal record identity {}",
            path.display()
        )
    })?;
    #[cfg(windows)]
    let identity_matches = path_snapshot.identity == file_identity;
    #[cfg(not(windows))]
    let identity_matches = publication_same_filesystem_identity(&path_metadata, &file_metadata);
    if !identity_matches {
        bail!(
            "publication journal record {} changed while it was opened",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    #[cfg(windows)]
    (&file)
        .take(PUBLICATION_JOURNAL_MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read journal record {}", path.display()))?;
    #[cfg(not(windows))]
    file.take(PUBLICATION_JOURNAL_MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read journal record {}", path.display()))?;
    if bytes.is_empty()
        || bytes.len() as u64 > PUBLICATION_JOURNAL_MAX_RECORD_BYTES
        || bytes.len() as u64 != file_metadata.len()
    {
        bail!(
            "publication journal record {} changed size while it was read",
            path.display()
        );
    }
    #[cfg(windows)]
    let after_snapshot = crate::file_identity::open_windows_path_identity(path)
        .with_context(|| format!("failed to recheck journal record {}", path.display()))?;
    #[cfg(windows)]
    let after = &after_snapshot.metadata;
    #[cfg(not(windows))]
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("failed to recheck journal record {}", path.display()))?;
    validate_publication_journal_record_metadata(path, &after, None)?;
    #[cfg(windows)]
    let identity_matches = file_identity == after_snapshot.identity;
    #[cfg(not(windows))]
    let identity_matches = publication_same_filesystem_identity(&file_metadata, &after);
    if !identity_matches || after.len() != file_metadata.len() {
        bail!(
            "publication journal record {} changed after it was read",
            path.display()
        );
    }
    Ok(bytes)
}

fn publication_same_filesystem_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (left, right);
        false
    }
}

#[cfg(test)]
fn validate_publication_journal(journal: &PublicationTransactionJournal) -> Result<()> {
    if journal.version != PUBLICATION_JOURNAL_VERSION || journal.sequence == 0 {
        bail!("publication journal version or sequence was invalid");
    }
    Oid::from_str(&journal.expected_oid).context("publication journal expected OID was invalid")?;
    if let Some(oid) = journal.expected_base_oid.as_deref() {
        Oid::from_str(oid).context("publication journal expected base OID was invalid")?;
    }
    let is_external_effect_receipt = journal.transaction_id.starts_with("effect-");
    if is_external_effect_receipt {
        validate_external_digest(
            &journal.remote_binding_digest,
            "publication receipt remote binding digest",
        )?;
    } else {
        Oid::from_str(&journal.remote_binding_digest)
            .context("legacy publication journal remote binding digest was invalid")?;
    }
    if let Some(oid) = journal.push_observed_oid.as_deref() {
        Oid::from_str(oid).context("publication journal observed push OID was invalid")?;
    }
    if let Some(oid) = journal.pr_head_oid.as_deref() {
        Oid::from_str(oid).context("publication journal PR head OID was invalid")?;
    }
    if journal.phase >= PublicationTransactionPhase::PushObserved
        && journal.push_observed_oid.as_deref() != Some(journal.expected_oid.as_str())
    {
        bail!("publication journal push phase did not contain the expected observed OID");
    }
    if journal.phase < PublicationTransactionPhase::PushObserved
        && journal.push_observed_oid.is_some()
    {
        bail!("publication journal recorded a push receipt before the push phase");
    }
    if journal.forge == ForgeKind::Github {
        if journal.expected_base_oid.is_none() {
            bail!("GitHub publication journal omitted the exact reviewed base OID");
        }
        let marker = journal
            .pr_marker_nonce
            .as_deref()
            .context("GitHub publication journal omitted its unpredictable PR marker")?;
        validate_publication_pr_marker_nonce(marker)?;
        let expected_title = journal
            .expected_pr_title
            .as_deref()
            .context("GitHub publication journal omitted its exact PR title")?;
        let expected_body = journal
            .expected_pr_body
            .as_deref()
            .context("GitHub publication journal omitted its marker-bound PR body")?;
        let expected_author = journal
            .expected_pr_author
            .as_deref()
            .context("GitHub publication journal omitted its explicit expected author")?;
        let canonical_author = canonical_github_author_login(expected_author)
            .context("GitHub publication journal expected author was malformed")?;
        let marker_literal = if is_external_effect_receipt {
            format!("<!-- {EXTERNAL_EFFECT_MARKER_PREFIX}:v2:{marker} -->")
        } else {
            format!("<!-- maco-publication-marker:{marker} -->")
        };
        if expected_title.is_empty()
            || expected_title.len() > MAX_GITHUB_RECEIPT_STRING_BYTES
            || expected_body.len() > MAX_GITHUB_RECEIPT_BODY_BYTES
            || expected_body.matches(&marker_literal).count() != 1
            || canonical_author != expected_author
        {
            bail!("GitHub publication journal PR identity fields were invalid");
        }
        if journal.phase >= PublicationTransactionPhase::PrObserved {
            if !journal.created_by_transaction || journal.observed_existing_pr {
                bail!(
                    "publication journal PR phase did not prove marker-bound transaction creation"
                );
            }
            let repository = journal
                .github_repository
                .as_ref()
                .context("GitHub publication journal omitted its bound repository")?;
            let url = journal
                .pr_url
                .as_deref()
                .context("publication journal PR phase omitted its URL")?;
            let head = journal
                .pr_head_oid
                .as_deref()
                .context("publication journal PR phase omitted its head OID")?;
            let base = journal
                .pr_base
                .as_deref()
                .context("publication journal PR phase omitted its base branch")?;
            let state = journal
                .pr_state
                .as_deref()
                .context("publication journal PR phase omitted its state")?;
            let is_draft = journal
                .pr_is_draft
                .context("publication journal PR phase omitted its draft state")?;
            let number = journal
                .pr_number
                .filter(|number| *number > 0)
                .context("publication journal PR phase omitted its number")?;
            let title = journal
                .pr_title
                .as_deref()
                .context("publication journal PR phase omitted its title")?;
            let body = journal
                .pr_body
                .as_deref()
                .context("publication journal PR phase omitted its body")?;
            let head_ref_name = journal
                .pr_head_ref_name
                .as_deref()
                .context("publication journal PR phase omitted its head ref")?;
            let head_owner = journal
                .pr_head_repository_owner
                .as_deref()
                .context("publication journal PR phase omitted its head owner")?;
            let head_name = journal
                .pr_head_repository_name
                .as_deref()
                .context("publication journal PR phase omitted its head repository")?;
            let is_cross_repository = journal
                .pr_is_cross_repository
                .context("publication journal PR phase omitted its cross-repository state")?;
            let author = journal
                .pr_author
                .as_deref()
                .context("publication journal PR phase omitted its author")?;
            if head != journal.expected_oid {
                bail!("publication journal PR head did not match the expected OID");
            }
            if base != journal.base {
                bail!("publication journal PR base did not match the requested base");
            }
            if state != "OPEN" {
                bail!("publication journal PR state was not OPEN");
            }
            if is_draft != journal.draft {
                bail!("publication journal PR draft state changed from the request");
            }
            if title != expected_title
                || body != expected_body
                || head_ref_name != journal.remote_branch
                || head_owner != repository.owner
                || head_name != repository.name
                || is_cross_repository
                || author != expected_author
            {
                bail!(
                    "publication journal PR provenance changed from its exact transaction binding"
                );
            }
            validate_github_receipt_url(url, repository, number)?;
        } else if journal.pr_url.is_some()
            || journal.pr_head_oid.is_some()
            || journal.pr_base.is_some()
            || journal.pr_state.is_some()
            || journal.pr_is_draft.is_some()
            || journal.pr_number.is_some()
            || journal.pr_title.is_some()
            || journal.pr_body.is_some()
            || journal.pr_head_ref_name.is_some()
            || journal.pr_head_repository_owner.is_some()
            || journal.pr_head_repository_name.is_some()
            || journal.pr_is_cross_repository.is_some()
            || journal.pr_author.is_some()
            || journal.created_by_transaction
            || journal.observed_existing_pr
        {
            bail!("publication journal recorded PR receipt fields before the PR phase");
        }
    } else if journal.pr_url.is_some()
        || journal.pr_head_oid.is_some()
        || journal.pr_base.is_some()
        || journal.pr_state.is_some()
        || journal.pr_is_draft.is_some()
        || journal.pr_number.is_some()
        || journal.pr_marker_nonce.is_some()
        || journal.expected_pr_title.is_some()
        || journal.expected_pr_body.is_some()
        || journal.expected_pr_author.is_some()
        || journal.pr_title.is_some()
        || journal.pr_body.is_some()
        || journal.pr_head_ref_name.is_some()
        || journal.pr_head_repository_owner.is_some()
        || journal.pr_head_repository_name.is_some()
        || journal.pr_is_cross_repository.is_some()
        || journal.pr_author.is_some()
        || journal.create_attempted
        || journal.created_by_transaction
        || journal.observed_existing_pr
    {
        bail!("non-GitHub publication journal contained GitHub PR state");
    }
    if (journal.forge == ForgeKind::Github) != journal.github_repository.is_some() {
        bail!("publication journal forge repository binding was inconsistent");
    }
    if journal.created_by_transaction && !journal.create_attempted {
        bail!("publication journal attributed PR creation without a recorded create attempt");
    }
    if journal.created_by_transaction && journal.observed_existing_pr {
        bail!("publication journal contains contradictory PR creation provenance");
    }
    Ok(())
}

#[cfg(test)]
fn validate_publication_journal_transition(
    previous: &PublicationTransactionJournal,
    current: &PublicationTransactionJournal,
) -> Result<()> {
    if current.sequence
        != previous
            .sequence
            .checked_add(1)
            .context("publication journal sequence overflow while validating retained records")?
    {
        bail!("publication journal retained sequence was not contiguous");
    }
    if previous.version != current.version
        || previous.transaction_id != current.transaction_id
        || previous.agent_id != current.agent_id
        || previous.forge != current.forge
        || previous.expected_oid != current.expected_oid
        || previous.expected_base_oid != current.expected_base_oid
        || previous.remote_name != current.remote_name
        || previous.remote_binding_digest != current.remote_binding_digest
        || previous.remote_display != current.remote_display
        || previous.remote_ref != current.remote_ref
        || previous.remote_branch != current.remote_branch
        || previous.github_repository != current.github_repository
        || previous.pr_marker_nonce != current.pr_marker_nonce
        || previous.expected_pr_title != current.expected_pr_title
        || previous.expected_pr_body != current.expected_pr_body
        || previous.expected_pr_author != current.expected_pr_author
        || previous.base != current.base
        || previous.draft != current.draft
    {
        bail!("publication journal immutable transaction identity changed between records");
    }
    if current.phase < previous.phase {
        bail!("publication journal phase regressed between records");
    }
    if previous.push_observed_oid.is_some()
        && previous.push_observed_oid != current.push_observed_oid
    {
        bail!("publication journal push receipt changed between records");
    }
    if (previous.pr_url.is_some() && previous.pr_url != current.pr_url)
        || (previous.pr_head_oid.is_some() && previous.pr_head_oid != current.pr_head_oid)
        || (previous.pr_base.is_some() && previous.pr_base != current.pr_base)
        || (previous.pr_state.is_some() && previous.pr_state != current.pr_state)
        || (previous.pr_is_draft.is_some() && previous.pr_is_draft != current.pr_is_draft)
        || (previous.pr_number.is_some() && previous.pr_number != current.pr_number)
        || (previous.pr_title.is_some() && previous.pr_title != current.pr_title)
        || (previous.pr_body.is_some() && previous.pr_body != current.pr_body)
        || (previous.pr_head_ref_name.is_some()
            && previous.pr_head_ref_name != current.pr_head_ref_name)
        || (previous.pr_head_repository_owner.is_some()
            && previous.pr_head_repository_owner != current.pr_head_repository_owner)
        || (previous.pr_head_repository_name.is_some()
            && previous.pr_head_repository_name != current.pr_head_repository_name)
        || (previous.pr_is_cross_repository.is_some()
            && previous.pr_is_cross_repository != current.pr_is_cross_repository)
        || (previous.pr_author.is_some() && previous.pr_author != current.pr_author)
    {
        bail!("publication journal immutable PR receipt changed between records");
    }
    if (previous.create_attempted && !current.create_attempted)
        || (previous.created_by_transaction && !current.created_by_transaction)
        || (previous.observed_existing_pr && !current.observed_existing_pr)
    {
        bail!("publication journal PR provenance regressed between records");
    }
    Ok(())
}

#[cfg(unix)]
fn sync_journal_directory(directory: &Path) -> Result<()> {
    fs::File::open(directory)
        .with_context(|| format!("failed to open journal directory {}", directory.display()))?
        .sync_all()
        .with_context(|| {
            format!(
                "failed to persist journal directory {}",
                directory.display()
            )
        })
}

#[cfg(not(unix))]
fn sync_journal_directory(_directory: &Path) -> Result<()> {
    Ok(())
}

fn validate_publication_object_store_is_self_contained(
    repo: &Repository,
    common_objects: &Path,
) -> Result<()> {
    for alternate in [
        common_objects.join("info/alternates"),
        common_objects.join("info/http-alternates"),
    ] {
        match fs::symlink_metadata(&alternate) {
            Ok(_) => {
                bail!("HTTPS publication refuses object stores with alternate object directories")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect publication object alternate {}",
                        alternate.display()
                    )
                })
            }
        }
    }

    let config_path = repo.commondir().join("config");
    #[cfg(windows)]
    let path_snapshot = crate::file_identity::open_windows_path_identity(&config_path)
        .with_context(|| {
            format!(
                "failed to inspect publication source config {}",
                config_path.display()
            )
        })?;
    #[cfg(windows)]
    let path_metadata = &path_snapshot.metadata;
    #[cfg(not(windows))]
    let path_metadata = fs::symlink_metadata(&config_path).with_context(|| {
        format!(
            "failed to inspect publication source config {}",
            config_path.display()
        )
    })?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.len() > MAX_PUBLICATION_SOURCE_CONFIG_BYTES
    {
        bail!("HTTPS publication source config is not a bounded real regular file");
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut config_file = options.open(&config_path).with_context(|| {
        format!(
            "failed to open publication source config {}",
            config_path.display()
        )
    })?;
    let file_metadata = config_file
        .metadata()
        .context("failed to inspect open publication source config")?;
    #[cfg(windows)]
    let file_identity = crate::file_identity::windows_file_identity(&config_file)
        .context("failed to inspect open publication source config identity")?;
    #[cfg(windows)]
    let identity_matches = path_snapshot.identity == file_identity;
    #[cfg(not(windows))]
    let identity_matches = publication_same_filesystem_identity(&path_metadata, &file_metadata);
    if !identity_matches || file_metadata.len() != path_metadata.len() {
        bail!("HTTPS publication source config changed while it was opened");
    }
    let mut config_bytes = Vec::new();
    Read::by_ref(&mut config_file)
        .take(MAX_PUBLICATION_SOURCE_CONFIG_BYTES + 1)
        .read_to_end(&mut config_bytes)
        .context("failed to read publication source config")?;
    #[cfg(windows)]
    let after_snapshot = crate::file_identity::open_windows_path_identity(&config_path)
        .context("failed to recheck publication source config")?;
    #[cfg(windows)]
    let after = &after_snapshot.metadata;
    #[cfg(not(windows))]
    let after = fs::symlink_metadata(&config_path)
        .context("failed to recheck publication source config")?;
    #[cfg(windows)]
    let identity_matches = file_identity == after_snapshot.identity;
    #[cfg(not(windows))]
    let identity_matches = publication_same_filesystem_identity(&file_metadata, &after);
    if config_bytes.len() as u64 != file_metadata.len()
        || !identity_matches
        || after.len() != file_metadata.len()
    {
        bail!("HTTPS publication source config changed while it was read");
    }
    let config_text = std::str::from_utf8(&config_bytes)
        .map(str::to_ascii_lowercase)
        .context("publication source config was not UTF-8");
    zeroize_bytes(&mut config_bytes);
    let config_text = ZeroizingString(config_text?);
    if config_text.as_str().contains("partialclone") || config_text.as_str().contains("promisor") {
        bail!("HTTPS publication refuses partial-clone or promisor object stores");
    }

    let mut pending = vec![(common_objects.to_path_buf(), 0usize)];
    let mut entry_count = 0usize;
    while let Some((directory, depth)) = pending.pop() {
        for entry in fs::read_dir(&directory).with_context(|| {
            format!(
                "failed to inspect publication object directory {}",
                directory.display()
            )
        })? {
            let entry = entry.context("failed to read publication object entry")?;
            entry_count = entry_count
                .checked_add(1)
                .context("publication object entry count overflow")?;
            if entry_count > MAX_PUBLICATION_OBJECT_ENTRIES {
                bail!("HTTPS publication object store exceeded its entry safety bound");
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).with_context(|| {
                format!("failed to inspect publication object {}", path.display())
            })?;
            if metadata.file_type().is_symlink()
                || (!metadata.file_type().is_file() && !metadata.file_type().is_dir())
            {
                bail!("HTTPS publication object store contains a special or linked entry");
            }
            if path
                .extension()
                .is_some_and(|extension| extension == "promisor")
            {
                bail!("HTTPS publication refuses promisor pack metadata");
            }
            if metadata.file_type().is_dir() {
                if depth >= MAX_PUBLICATION_OBJECT_DEPTH {
                    bail!("HTTPS publication object store exceeded its depth safety bound");
                }
                pending.push((path, depth + 1));
            }
        }
    }
    Ok(())
}

fn materialize_publication_object_closure(
    source: &Repository,
    private: &Repository,
    expected_oid: &str,
) -> Result<PrivateObjectClosureSeal> {
    let expected_text = expected_oid;
    let expected_oid =
        Oid::from_str(expected_text).context("publication closure OID was invalid")?;
    if expected_oid.to_string() != expected_text {
        bail!("publication closure OID was not canonical");
    }
    let destination_odb = private
        .odb()
        .context("failed to open private publication object database")?;
    let seal = walk_publication_object_closure(source, expected_oid, Some(&destination_odb))?;
    verify_private_publication_object_closure(private, &seal)?;
    Ok(seal)
}

fn verify_private_publication_object_closure(
    private: &Repository,
    expected: &PrivateObjectClosureSeal,
) -> Result<()> {
    let observed = walk_publication_object_closure(private, expected.expected_oid, None)?;
    if observed.object_ids != expected.object_ids || observed.total_bytes != expected.total_bytes {
        bail!("private publication object closure changed after materialization");
    }
    let odb = private
        .odb()
        .context("failed to reopen private publication object database")?;
    let mut all_objects = BTreeSet::new();
    odb.foreach(|oid| {
        all_objects.insert(*oid);
        all_objects.len() <= MAX_PUBLICATION_CLOSURE_OBJECTS
    })
    .context("failed to enumerate private publication object database")?;
    if all_objects != expected.object_ids {
        bail!("private publication object database contained objects outside the exact closure");
    }
    for forbidden in [
        private.path().join("objects/info/alternates"),
        private.path().join("objects/info/http-alternates"),
    ] {
        if fs::symlink_metadata(&forbidden).is_ok() {
            bail!("private publication object database acquired an alternate object source");
        }
    }
    Ok(())
}

fn walk_publication_object_closure(
    source: &Repository,
    expected_oid: Oid,
    destination: Option<&git2::Odb<'_>>,
) -> Result<PrivateObjectClosureSeal> {
    let source_odb = source
        .odb()
        .context("failed to open publication source object database")?;
    let mut pending = vec![ClosureObject::Commit(expected_oid)];
    let mut object_ids = BTreeSet::new();
    let mut object_kinds = BTreeMap::<Oid, ObjectType>::new();
    let mut commit_edges = BTreeMap::<Oid, Vec<Oid>>::new();
    let mut tree_depths = BTreeMap::<Oid, usize>::new();
    let mut total_bytes = 0_u64;
    let mut traversal_steps = 0usize;

    while let Some(next) = pending.pop() {
        traversal_steps = traversal_steps
            .checked_add(1)
            .context("publication closure traversal count overflow")?;
        if traversal_steps > MAX_PUBLICATION_CLOSURE_OBJECTS.saturating_mul(4) {
            bail!("publication closure graph exceeded its traversal safety bound");
        }
        let (oid, expected_kind) = match next {
            ClosureObject::Commit(oid) => (oid, ObjectType::Commit),
            ClosureObject::Tree { oid, depth } => {
                if depth > MAX_PUBLICATION_TREE_DEPTH {
                    bail!("publication tree closure exceeded its depth safety bound");
                }
                if tree_depths
                    .get(&oid)
                    .is_some_and(|prior_depth| *prior_depth >= depth)
                {
                    continue;
                }
                tree_depths.insert(oid, depth);
                (oid, ObjectType::Tree)
            }
            ClosureObject::Blob(oid) => (oid, ObjectType::Blob),
        };
        if let Some(prior_kind) = object_kinds.get(&oid) {
            if *prior_kind != expected_kind {
                bail!("publication closure reused an object with contradictory kinds");
            }
            if expected_kind != ObjectType::Tree {
                continue;
            }
        }

        let is_new = !object_ids.contains(&oid);
        if is_new && object_ids.len() >= MAX_PUBLICATION_CLOSURE_OBJECTS {
            bail!("publication object closure exceeded its object-count bound");
        }
        let (declared_size, declared_kind) = source_odb
            .read_header(oid)
            .with_context(|| format!("publication closure omitted object header {oid}"))?;
        if declared_kind != expected_kind {
            bail!("publication closure object {oid} had an unexpected kind");
        }
        let declared_size = u64::try_from(declared_size)
            .context("publication closure object size did not fit its byte bound")?;
        if is_new {
            let projected_bytes = total_bytes
                .checked_add(declared_size)
                .context("publication object closure byte count overflow")?;
            if projected_bytes > MAX_PUBLICATION_CLOSURE_BYTES {
                bail!("publication object closure exceeded its aggregate byte bound");
            }
        }
        let object = source_odb
            .read(oid)
            .with_context(|| format!("publication closure omitted object {oid}"))?;
        if object.kind() != expected_kind || object.data().len() as u64 != declared_size {
            bail!("publication closure object changed after its bounded header was read");
        }
        if object_ids.insert(oid) {
            total_bytes = total_bytes
                .checked_add(declared_size)
                .context("publication object closure byte count overflow")?;
            object_kinds.insert(oid, expected_kind);
            if let Some(destination) = destination {
                let written = destination
                    .write(expected_kind, object.data())
                    .with_context(|| format!("failed to materialize publication object {oid}"))?;
                if written != oid {
                    bail!("private publication object materialization changed an object ID");
                }
            }
        }

        match expected_kind {
            ObjectType::Commit => {
                let commit = source
                    .find_commit(oid)
                    .with_context(|| format!("failed to parse publication commit {oid}"))?;
                let mut parents = Vec::new();
                let mut unique_parents = BTreeSet::new();
                for parent in commit.parent_ids() {
                    if parent == oid || !unique_parents.insert(parent) {
                        bail!("publication commit graph contained a self or duplicate parent");
                    }
                    parents.push(parent);
                    pending.push(ClosureObject::Commit(parent));
                }
                commit_edges.insert(oid, parents);
                pending.push(ClosureObject::Tree {
                    oid: commit.tree_id(),
                    depth: 0,
                });
            }
            ObjectType::Tree => {
                let tree = source
                    .find_tree(oid)
                    .with_context(|| format!("failed to parse publication tree {oid}"))?;
                let depth = *tree_depths
                    .get(&oid)
                    .context("publication tree depth tracking was missing")?;
                for entry in tree.iter() {
                    let entry_oid = entry.id();
                    match entry.filemode() {
                        0o160000 => {
                            // A gitlink names a commit in another repository. It is provenance
                            // metadata only and must never make publication read that repository.
                        }
                        0o040000 => pending.push(ClosureObject::Tree {
                            oid: entry_oid,
                            depth: depth + 1,
                        }),
                        _ => pending.push(ClosureObject::Blob(entry_oid)),
                    }
                }
            }
            ObjectType::Blob => {}
            _ => bail!("publication closure contained an unsupported object kind"),
        }
    }

    validate_publication_commit_graph(&commit_edges, expected_oid)?;
    Ok(PrivateObjectClosureSeal {
        expected_oid,
        object_ids,
        total_bytes,
    })
}

fn validate_publication_commit_graph(edges: &BTreeMap<Oid, Vec<Oid>>, root: Oid) -> Result<()> {
    let mut stack = vec![(root, false, 0usize)];
    let mut active = BTreeSet::new();
    let mut complete = BTreeSet::new();
    while let Some((oid, exiting, depth)) = stack.pop() {
        if depth > MAX_PUBLICATION_COMMIT_DEPTH {
            bail!("publication commit graph exceeded its depth safety bound");
        }
        if exiting {
            active.remove(&oid);
            complete.insert(oid);
            continue;
        }
        if complete.contains(&oid) {
            continue;
        }
        if !active.insert(oid) {
            bail!("publication commit graph contained a cycle");
        }
        stack.push((oid, true, depth));
        let parents = edges
            .get(&oid)
            .with_context(|| format!("publication commit graph omitted {oid}"))?;
        for parent in parents.iter().rev() {
            stack.push((*parent, false, depth + 1));
        }
    }
    Ok(())
}

impl PublicationGitContext {
    fn create(
        worktree_path: &Path,
        remote_url: &str,
        operation: PublicationGitOperation,
    ) -> Result<Self> {
        Self::create_with_token_source(worktree_path, remote_url, operation, |key| {
            env::var(key).ok()
        })
    }

    fn create_with_token_source(
        worktree_path: &Path,
        remote_url: &str,
        operation: PublicationGitOperation,
        value_for: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        Self::create_with_token_source_and_runtime_observer(
            worktree_path,
            remote_url,
            operation,
            value_for,
            |_| {},
        )
    }

    fn create_with_token_source_and_runtime_observer(
        worktree_path: &Path,
        remote_url: &str,
        operation: PublicationGitOperation,
        mut value_for: impl FnMut(&str) -> Option<String>,
        mut observe_runtime: impl FnMut(&Path),
    ) -> Result<Self> {
        let transport = publication_remote_transport(remote_url)?;
        let repo = crate::git_repository::open(worktree_path).with_context(|| {
            format!(
                "failed to open publication worktree {}",
                worktree_path.display()
            )
        })?;
        let mut runtime_directory = merge::PrivateRuntimeDirectory::create(
            worktree_path,
            merge::PrivateRuntimeKind::PublicationGit,
        )?;
        let directory = runtime_directory.path().to_path_buf();
        // Production supplies a no-op observer. Tests can bind cleanup assertions to this exact
        // allocation instead of sampling the host-global runtime root while peers use it.
        observe_runtime(&directory);
        let result = (|| -> Result<PublicationGitContextSetup> {
            let objects = directory.join("objects");
            merge::create_private_directory(&objects)?;
            merge::create_private_directory(&directory.join("refs"))?;
            merge::create_private_directory(&directory.join("refs/heads"))?;
            merge::create_private_directory(&directory.join("refs/tags"))?;
            merge::create_private_directory(&directory.join("disabled-hooks"))?;
            merge::write_private_file(
                &directory.join("HEAD"),
                b"ref: refs/heads/maco-publication\n",
            )?;
            let config_path = directory.join("config");
            merge::write_private_file(&config_path, b"")?;
            let mut config = git2::Config::open(&config_path)
                .context("failed to open private publication Git config")?;
            config
                .set_i32("core.repositoryformatversion", 0)
                .context("failed to set publication repository version")?;
            config
                .set_bool("core.bare", true)
                .context("failed to set publication repository bare mode")?;
            config
                .set_bool("core.fsmonitor", false)
                .context("failed to disable publication fsmonitor")?;
            config
                .set_bool("core.untrackedcache", false)
                .context("failed to disable publication untracked cache")?;
            config
                .set_str(
                    "core.hookspath",
                    directory
                        .join("disabled-hooks")
                        .to_str()
                        .context("publication hooks path was not UTF-8")?,
                )
                .context("failed to disable publication hooks")?;
            config
                .set_str("protocol.ext.allow", "never")
                .context("failed to disable external publication protocol")?;
            let global_config = directory.join("disabled-global-config");
            merge::write_private_file(&global_config, b"")?;
            drop(config);

            let object_seal = match operation.requires_object_closure() {
                Some(expected_oid) => {
                    let common_objects = fs::canonicalize(repo.commondir().join("objects"))
                        .context("failed to resolve publication source object directory")?;
                    validate_publication_object_store_is_self_contained(&repo, &common_objects)?;
                    let private = crate::git_repository::open_bare(&directory)
                        .context("failed to open private publication Git repository")?;
                    Some(materialize_publication_object_closure(
                        &repo,
                        &private,
                        expected_oid,
                    )?)
                }
                None => None,
            };
            let common_state = fs::canonicalize(merge::ensure_repo_common_state_directory(&repo)?)
                .context("failed to resolve publication repository state directory")?;
            let common_directory = fs::canonicalize(repo.commondir())
                .context("failed to resolve publication common Git directory")?;
            let primary_worktree = common_directory
                .parent()
                .context("publication common Git directory omitted its repository root")?
                .to_path_buf();
            let source_worktree = fs::canonicalize(worktree_path).with_context(|| {
                format!(
                    "failed to resolve publication source worktree {}",
                    worktree_path.display()
                )
            })?;

            let PublicationRemoteTransport::Https {
                host, command_url, ..
            } = &transport;
            let token = select_network_token_with(host, &mut value_for)?;
            let mut config = git2::Config::open(&config_path)
                .context("failed to reopen private publication Git config")?;
            let auth_scope_key = format!("http.{command_url}.extraheader");
            let authorization_header =
                ZeroizingString(format!("Authorization: Basic {}", token.basic_str()?));
            config
                .set_str(&auth_scope_key, authorization_header.as_str())
                .context("failed to bind the host-and-repository HTTPS authorization header")?;
            config
                .set_str("http.followredirects", "false")
                .context("failed to constrain publication redirects")?;
            config
                .set_bool("http.sslverify", true)
                .context("failed to require publication TLS verification")?;
            config
                .set_str("http.proxy", "")
                .context("failed to disable publication proxy discovery")?;
            config
                .set_str("credential.helper", "")
                .context("failed to disable publication credential helpers")?;
            config
                .set_str("core.askpass", "")
                .context("failed to disable publication askpass helpers")?;
            let command_url = command_url.clone();
            config
                .set_str("remote.maco-publication.url", &command_url)
                .context("failed to bind the validated publication remote")?;
            drop(config);
            harden_private_config_mode(&config_path)?;

            let config_files = vec![
                capture_private_config_file(&config_path)?,
                capture_private_config_file(&global_config)?,
            ];
            let mut environment = merge::minimal_network_environment()?;
            environment.insert(
                "GIT_CONFIG_GLOBAL".to_string(),
                global_config
                    .to_str()
                    .context("publication global config path was not UTF-8")?
                    .to_string(),
            );
            validate_publication_git_environment(&environment, &global_config)?;

            let profile = TrustedFixedNetworkProfile::read_write(&directory)
                .with_resource_limits(Default::default())
                .with_visible_read_only_root(&objects)
                .with_visible_read_only_file(&config_path)
                .with_visible_read_only_file(&global_config)
                .with_hidden_root(&primary_worktree)
                .with_hidden_root(&source_worktree)
                .with_hidden_root(&common_state);
            Ok((
                environment,
                PublicationGitBoundary::Https(profile),
                config_files,
                Some(token),
                object_seal,
            ))
        })();
        match result {
            Ok((environment, boundary, config_files, token, object_seal)) => Ok(Self {
                directory,
                runtime_directory,
                environment,
                boundary,
                config_files,
                token,
                operation,
                object_seal,
            }),
            Err(error) => {
                let erase = erase_private_config_paths_if_present(&[
                    directory.join("config"),
                    directory.join("disabled-global-config"),
                ]);
                let close = runtime_directory.close();
                match (erase, close) {
                    (Ok(()), Ok(())) => Err(error),
                    (erase, close) => Err(anyhow::anyhow!(
                        "{error:#}; publication setup cleanup failed: erase={:?}, close={:?}",
                        erase.err().map(|error| format!("{error:#}")),
                        close.err().map(|error| format!("{error:#}")),
                    )),
                }
            }
        }
    }

    fn run(mut self) -> Result<merge::RequiredCommandOutput> {
        let execution = self.run_inner();
        let cleanup = self.close();
        match (execution, cleanup) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(cleanup
                .context("publication command completed but private token runtime cleanup failed")),
            (Err(error), Err(cleanup)) => Err(anyhow::anyhow!(
                "{error:#}; private token runtime cleanup also failed: {cleanup:#}"
            )),
        }
    }

    fn run_inner(&self) -> Result<merge::RequiredCommandOutput> {
        let label = self.operation.label();
        self.runtime_directory
            .verify_identity()
            .context("private publication Git runtime changed before command execution")?;
        verify_private_config_files(&self.config_files)?;
        let global_config = self.directory.join("disabled-global-config");
        validate_publication_git_environment(&self.environment, &global_config)?;
        self.verify_object_seal()?;
        let operation = self.operation.arguments();
        validate_publication_git_operation(&operation)?;
        let args = self.command_args(operation);
        let output = match &self.boundary {
            PublicationGitBoundary::Https(profile) => merge::run_required_network_direct(
                label,
                merge::resolve_trusted_executable("git")?,
                args,
                &self.directory,
                self.environment.clone(),
                StdinMode::Null,
                merge::NETWORK_PROCESS_TIMEOUT,
                GH_CAPTURE_LIMIT_BYTES,
                0,
                profile.clone(),
            ),
        };
        let mut output = output.map_err(|error| self.redact_error(error))?;
        self.runtime_directory
            .verify_identity()
            .context("private publication Git runtime changed during command execution")?;
        verify_private_config_files(&self.config_files)?;
        self.verify_object_seal()?;
        self.redact_output(&mut output);
        Ok(output)
    }

    fn close(&mut self) -> Result<()> {
        let erase = erase_private_config_files(&mut self.config_files);
        self.environment.clear();
        drop(self.token.take());
        let close = self.runtime_directory.close();
        match (erase, close) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(erase), Err(close)) => Err(anyhow::anyhow!(
                "private config erasure failed: {erase:#}; private runtime close failed: {close:#}"
            )),
        }
    }

    fn verify_object_seal(&self) -> Result<()> {
        if let Some(seal) = &self.object_seal {
            let private = crate::git_repository::open_bare(&self.directory)
                .context("failed to reopen private publication object database")?;
            verify_private_publication_object_closure(&private, seal)?;
        } else {
            let private = crate::git_repository::open_bare(&self.directory)
                .context("failed to inspect observation-only publication object database")?;
            let odb = private
                .odb()
                .context("failed to open observation-only publication object database")?;
            let mut found = false;
            odb.foreach(|_| {
                found = true;
                false
            })
            .context("failed to inspect observation-only publication object database")?;
            if found {
                bail!("observation-only publication context unexpectedly contained Git objects");
            }
        }
        Ok(())
    }

    fn command_args(&self, operation: Vec<OsString>) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("--git-dir"),
            self.directory.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from("core.fsmonitor=false"),
            OsString::from("-c"),
            OsString::from("core.untrackedCache=false"),
            OsString::from("-c"),
            OsString::from("protocol.ext.allow=never"),
            OsString::from("-c"),
            OsString::from(format!(
                "core.hooksPath={}",
                self.directory.join("disabled-hooks").display()
            )),
        ];
        args.extend(operation);
        args
    }

    fn redact_output(&self, output: &mut merge::RequiredCommandOutput) {
        if let Some(token) = &self.token {
            redact_private_bytes(&mut output.stdout, &token.bytes);
            redact_private_bytes(&mut output.stderr, &token.bytes);
            redact_private_bytes(&mut output.stdout, &token.basic);
            redact_private_bytes(&mut output.stderr, &token.basic);
        }
    }

    fn redact_error(&self, error: anyhow::Error) -> anyhow::Error {
        let mut text = format!("{error:#}");
        if let Some(token) = &self.token {
            if let Ok(private) = token.as_str() {
                text = text.replace(private, "<redacted:network-token>");
            }
            if let Ok(private) = token.basic_str() {
                text = text.replace(private, "<redacted:network-token>");
            }
        }
        anyhow::anyhow!(text)
    }
}

impl Drop for PublicationGitContext {
    fn drop(&mut self) {
        self.environment.clear();
    }
}

impl PrivateNetworkToken {
    fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.bytes).context("network token was not UTF-8")
    }

    fn basic_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.basic).context("encoded network token was not UTF-8")
    }
}

fn select_network_token_with(
    host: &str,
    mut value_for: impl FnMut(&str) -> Option<String>,
) -> Result<PrivateNetworkToken> {
    authorize_network_host_with(host, &mut value_for)?;
    let keys = if host == "github.com" {
        ["GH_TOKEN", "GITHUB_TOKEN"]
    } else {
        ["GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"]
    };
    let values = keys
        .into_iter()
        .filter_map(|key| value_for(key).map(|value| (key, ZeroizingString(value))))
        .filter(|(_, value)| !value.as_str().is_empty())
        .collect::<Vec<_>>();
    let (_, first) = values.first().with_context(|| {
        format!(
            "HTTPS publication to {host} requires {} or {} before any remote effect",
            keys[0], keys[1]
        )
    })?;
    if values
        .iter()
        .any(|(_, value)| value.as_str() != first.as_str())
    {
        bail!(
            "HTTPS publication token variables {} and {} disagree; refusing ambiguous authentication",
            keys[0], keys[1]
        );
    }
    if first.as_str().len() < 4
        || first.as_str().len() > MAX_NETWORK_TOKEN_BYTES
        || first
            .as_str()
            .as_bytes()
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-' | b'.'))
    {
        bail!("HTTPS publication token is empty, malformed, or exceeds its safety bound");
    }
    let mut basic_source = b"x-access-token:".to_vec();
    basic_source.extend_from_slice(first.as_bytes());
    let basic = encode_base64(&basic_source).into_bytes();
    zeroize_bytes(&mut basic_source);
    Ok(PrivateNetworkToken {
        bytes: first.as_bytes().to_vec(),
        basic,
    })
}

fn authorize_network_host_with(
    host: &str,
    mut value_for: impl FnMut(&str) -> Option<String>,
) -> Result<()> {
    let canonical = normalize_github_host(host)?;
    if canonical != host {
        bail!("HTTPS publication host authority was not canonical");
    }
    if host == "github.com" {
        return Ok(());
    }
    let keys = ["GH_HOST", "GITHUB_HOST"];
    let values = keys
        .into_iter()
        .filter_map(|key| value_for(key).map(|value| (key, value)))
        .filter(|(_, value)| !value.is_empty())
        .collect::<Vec<_>>();
    let (_, first) = values.first().with_context(|| {
        format!(
            "enterprise HTTPS publication to {host} requires an explicit exact {} or {} host allowlist entry before token selection",
            keys[0], keys[1]
        )
    })?;
    if values.iter().any(|(_, value)| value != first) {
        bail!(
            "enterprise publication host variables {} and {} disagree",
            keys[0],
            keys[1]
        );
    }
    let approved = normalize_github_host(first)
        .context("enterprise publication host allowlist entry was invalid")?;
    if approved != *first || approved != host {
        bail!(
            "enterprise publication host allowlist entry must exactly match the canonical remote authority"
        );
    }
    Ok(())
}

fn select_github_expected_author_with(
    mut value_for: impl FnMut(&str) -> Option<String>,
) -> Result<String> {
    let keys = ["GH_EXPECTED_AUTHOR", "GITHUB_EXPECTED_AUTHOR"];
    let values = keys
        .into_iter()
        .filter_map(|key| value_for(key).map(|value| (key, value)))
        .filter(|(_, value)| !value.is_empty())
        .collect::<Vec<_>>();
    let (_, first) = values.first().with_context(|| {
        format!(
            "GitHub publication requires an explicit {} or {} provenance binding before token selection",
            keys[0], keys[1]
        )
    })?;
    if values.iter().any(|(_, value)| value != first) {
        bail!(
            "GitHub expected-author variables {} and {} disagree",
            keys[0],
            keys[1]
        );
    }
    canonical_github_author_login(first)
}

fn encode_base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[usize::from(first >> 2)] as char);
        output.push(ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[usize::from(third & 0x3f)] as char
        } else {
            '='
        });
    }
    output
}

fn capture_private_config_file(path: &Path) -> Result<PrivateConfigFileIdentity> {
    capture_bound_config_file(path, true)
}

fn harden_private_config_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut options = OpenOptions::new();
        options.read(true).write(true);
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let file = options
            .open(path)
            .with_context(|| format!("failed to reopen private config {}", path.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to harden private config {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to persist private config {}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("private network config hardening is unsupported on this platform")
    }
}

fn capture_bound_config_file(
    path: &Path,
    private_owner_only: bool,
) -> Result<PrivateConfigFileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let path_metadata_before = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect private config {}", path.display()))?;
        let mut options = OpenOptions::new();
        options.read(true);
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options
            .open(path)
            .with_context(|| format!("failed to open private config {}", path.display()))?;
        let file_metadata = file
            .metadata()
            .with_context(|| format!("failed to inspect open private config {}", path.display()))?;
        let path_metadata_after = fs::symlink_metadata(path).with_context(|| {
            format!(
                "failed to re-inspect private config {} after open",
                path.display()
            )
        })?;
        let safe = |metadata: &fs::Metadata| {
            let mode = metadata.permissions().mode() & 0o777;
            let owner_is_trusted = metadata.uid() == unsafe { libc::geteuid() }
                || (!private_owner_only && metadata.uid() == 0);
            !metadata.file_type().is_symlink()
                && metadata.file_type().is_file()
                && if private_owner_only {
                    mode == 0o600
                } else {
                    mode & 0o022 == 0
                }
                && owner_is_trusted
                && metadata.nlink() == 1
        };
        let same_identity = |left: &fs::Metadata, right: &fs::Metadata| {
            left.dev() == right.dev() && left.ino() == right.ino()
        };
        if !safe(&path_metadata_before)
            || !safe(&file_metadata)
            || !safe(&path_metadata_after)
            || !same_identity(&path_metadata_before, &file_metadata)
            || !same_identity(&file_metadata, &path_metadata_after)
        {
            bail!(
                "private config {} is not a single-link, owner-only, path-bound regular file",
                path.display()
            );
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_NETWORK_TOKEN_BYTES * 4 + 64 * 1024 + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("failed to read private config {}", path.display()))?;
        if bytes.len() > MAX_NETWORK_TOKEN_BYTES * 4 + 64 * 1024 {
            zeroize_bytes(&mut bytes);
            bail!("private config {} exceeds its safety bound", path.display());
        }
        Ok(PrivateConfigFileIdentity {
            path: path.to_path_buf(),
            private_owner_only,
            device: file_metadata.dev(),
            inode: file_metadata.ino(),
            bytes,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, private_owner_only);
        bail!("private network config identity verification is unsupported on this platform")
    }
}

fn verify_private_config_files(files: &[PrivateConfigFileIdentity]) -> Result<()> {
    for expected in files {
        let actual = capture_bound_config_file(&expected.path, expected.private_owner_only)?;
        #[cfg(unix)]
        let identity_matches = actual.device == expected.device && actual.inode == expected.inode;
        #[cfg(not(unix))]
        let identity_matches = false;
        if !identity_matches || actual.bytes != expected.bytes {
            bail!(
                "private network config {} changed identity or contents while in use",
                expected.path.display()
            );
        }
    }
    Ok(())
}

fn erase_private_config_files(files: &mut [PrivateConfigFileIdentity]) -> Result<()> {
    verify_private_config_files(files)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        for expected in files {
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            let mut file = options.open(&expected.path).with_context(|| {
                format!(
                    "failed to reopen private config for erasure {}",
                    expected.path.display()
                )
            })?;
            let metadata = file.metadata().with_context(|| {
                format!(
                    "failed to inspect private config for erasure {}",
                    expected.path.display()
                )
            })?;
            if metadata.dev() != expected.device
                || metadata.ino() != expected.inode
                || metadata.len() != expected.bytes.len() as u64
            {
                bail!(
                    "private config {} changed before explicit erasure",
                    expected.path.display()
                );
            }
            file.seek(SeekFrom::Start(0))
                .context("failed to seek private config for erasure")?;
            let zeros = vec![0_u8; expected.bytes.len()];
            file.write_all(&zeros)
                .context("failed to overwrite private config during erasure")?;
            file.sync_all()
                .context("failed to persist private config erasure")?;
            zeroize_bytes(&mut expected.bytes);
            expected.bytes.clear();
            expected.bytes.resize(zeros.len(), 0);
            let erased = capture_bound_config_file(&expected.path, expected.private_owner_only)?;
            if erased.device != expected.device
                || erased.inode != expected.inode
                || erased.bytes != expected.bytes
            {
                bail!(
                    "private config {} did not verify as erased",
                    expected.path.display()
                );
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = files;
        bail!("explicit private config erasure is unsupported on this platform")
    }
}

fn erase_private_config_paths_if_present(paths: &[PathBuf]) -> Result<()> {
    let mut files = Vec::new();
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                harden_private_config_mode(path)?;
                files.push(capture_private_config_file(path)?);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect setup config for erasure {}",
                        path.display()
                    )
                })
            }
        }
    }
    erase_private_config_files(&mut files)
}

fn redact_private_bytes(output: &mut Vec<u8>, private: &[u8]) {
    if private.is_empty() || private.len() > output.len() {
        return;
    }
    const REPLACEMENT: &[u8] = b"<redacted:network-token>";
    let mut redacted = Vec::with_capacity(output.len());
    let mut offset = 0usize;
    while let Some(position) = output[offset..]
        .windows(private.len())
        .position(|window| window == private)
    {
        let absolute = offset + position;
        redacted.extend_from_slice(&output[offset..absolute]);
        redacted.extend_from_slice(REPLACEMENT);
        offset = absolute + private.len();
    }
    if offset != 0 {
        redacted.extend_from_slice(&output[offset..]);
        zeroize_bytes(output);
        *output = redacted;
    }
}

fn validate_publication_git_environment(
    environment: &BTreeMap<String, String>,
    global_config: &Path,
) -> Result<()> {
    let required = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_ATTR_NOSYSTEM", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ];
    for (key, expected) in required {
        if environment.get(key).map(String::as_str) != Some(expected) {
            bail!("publication Git environment omitted the exact required {key}={expected}");
        }
    }
    let expected_global = global_config
        .to_str()
        .context("publication global Git config path was not UTF-8")?;
    if environment.get("GIT_CONFIG_GLOBAL").map(String::as_str) != Some(expected_global) {
        bail!("publication Git environment changed its private global config binding");
    }
    if environment
        .keys()
        .any(|key| key.starts_with("GH_") || key.starts_with("GITHUB_"))
    {
        bail!("publication Git environment may not contain gh authentication inputs");
    }
    Ok(())
}

fn validate_publication_git_operation(operation: &[OsString]) -> Result<()> {
    let operation = operation
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .context("publication Git argument was not strict UTF-8")
        })
        .collect::<Result<Vec<_>>>()?;
    match operation.as_slice() {
        ["ls-remote", "--refs", "maco-publication", remote_ref] => {
            validate_publication_ref(remote_ref)
        }
        ["push", "--no-verify", lease, "maco-publication", refspec] => {
            let leased_ref = lease
                .strip_prefix("--force-with-lease=")
                .and_then(|value| value.strip_suffix(':'))
                .context("publication Git push omitted its create-only lease")?;
            validate_publication_ref(leased_ref)?;
            let (oid, remote_ref) = refspec
                .split_once(':')
                .context("publication Git push omitted its bound refspec")?;
            if remote_ref != leased_ref
                || oid.len() != 40
                || !oid
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                || Oid::from_str(oid).is_err()
            {
                bail!("publication Git push refspec did not match its exact create-only lease");
            }
            Ok(())
        }
        _ => bail!("publication Git command is outside the fixed ls-remote/push allowlist"),
    }
}

fn validate_publication_ref(value: &str) -> Result<()> {
    if value.len() > MAX_PUBLICATION_REF_BYTES {
        bail!("publication ref exceeds its safety bound");
    }
    let suffix = value
        .strip_prefix("refs/heads/")
        .context("publication ref is outside refs/heads")?;
    if suffix.is_empty()
        || suffix.starts_with('/')
        || suffix.ends_with(['/', '.'])
        || suffix.contains("..")
        || suffix.contains("//")
        || suffix.contains("@{")
        || suffix.split('/').count() > MAX_PUBLICATION_REF_COMPONENTS
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
    {
        bail!("publication ref is malformed");
    }
    Ok(())
}

fn validate_publication_remote_url(remote_url: &str) -> Result<()> {
    if remote_url.is_empty()
        || remote_url.len() > MAX_PUBLICATION_REMOTE_URL_BYTES
        || remote_url
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control())
    {
        bail!("publication remote URL is empty or contains control bytes");
    }
    if remote_url.contains(['?', '#']) {
        bail!("publication remote URLs may not contain a query or fragment");
    }
    if remote_url.contains(['%', '\\', '@']) {
        bail!("publication remote URLs may not contain escapes, backslashes, or userinfo");
    }
    Ok(())
}

fn publication_remote_transport(remote_url: &str) -> Result<PublicationRemoteTransport> {
    validate_publication_remote_url(remote_url)?;
    if remote_url.starts_with("file://") || remote_url.starts_with('/') {
        bail!(
            "local/file publication is disabled because a concurrent same-UID process could mutate bare-repository config during receive-pack; use a canonical HTTPS remote"
        );
    }
    let remainder = remote_url.strip_prefix("https://").context(
        "publication supports only canonical HTTPS remotes; local/file, SSH, HTTP, git, helpers, and SCP syntax are refused",
    )?;
    if remote_url.contains('%') || remote_url.contains('\\') {
        bail!("HTTPS publication remote may not contain escapes or backslashes");
    }
    let (authority, path) = remainder
        .split_once('/')
        .context("HTTPS publication remote omitted a repository path")?;
    if authority.contains('@') {
        bail!("HTTPS publication remote may not contain userinfo");
    }
    let host = normalize_github_host(authority)?;
    let authority_is_canonical =
        host == authority || (host == "github.com" && authority == "github.com:443");
    if !authority_is_canonical
        || path.is_empty()
        || path.len() > MAX_PUBLICATION_PATH_BYTES
        || path.split('/').count() > MAX_PUBLICATION_PATH_COMPONENTS
        || path.starts_with('/')
        || path.ends_with('/')
    {
        bail!("HTTPS publication remote is not canonical");
    }
    for component in path.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || !component.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
            })
        {
            bail!("HTTPS publication repository path is malformed");
        }
    }
    let path = if path.ends_with(".git") {
        path.to_string()
    } else {
        format!("{path}.git")
    };
    let command_url = format!("https://{host}/{path}");
    Ok(PublicationRemoteTransport::Https {
        host,
        path,
        command_url,
    })
}

fn ensure_remote_expected_commit(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<()> {
    if let Some(request) = transaction.push_effect_request.clone() {
        let mut provider = GitPushExternalEffectProvider {
            worktree_path,
            remote_url: &transaction.remote_url,
            remote_ref: &transaction.journal.remote_ref,
            expected_oid: &transaction.journal.expected_oid,
            source_guard: request.source.as_ref(),
        };
        let receipt =
            execute_external_effect_exactly_once(worktree_path, request.clone(), &mut provider)?;
        if receipt.provider_id != transaction.journal.expected_oid {
            bail!("authenticated push receipt did not contain the expected remote OID");
        }
        transaction.journal.push_observed_oid = Some(receipt.provider_id);
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist()?;
        return Ok(());
    }
    let previous = transaction.journal.clone();
    let before = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    if let Some(observed) = before {
        if observed != transaction.journal.expected_oid {
            bail!(
                "unique publication ref {} points to {}, expected {}; refusing overwrite",
                transaction.journal.remote_ref,
                observed,
                transaction.journal.expected_oid
            );
        }
        transaction.journal.push_observed_oid = Some(observed);
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist_if_changed(&previous)?;
        return Ok(());
    }

    let push = push_git_commit_create_only(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
        &transaction.journal.expected_oid,
    )?;
    let after = observe_remote_ref(
        worktree_path,
        &transaction.remote_url,
        &transaction.journal.remote_ref,
    )?;
    if after.as_deref() == Some(transaction.journal.expected_oid.as_str()) {
        transaction.journal.push_observed_oid = after;
        transaction.advance_phase(PublicationTransactionPhase::PushObserved);
        transaction.journal.last_error = None;
        transaction.persist_if_changed(&previous)?;
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&push.stderr).trim().to_string();
    if push.success {
        bail!(
            "git push returned success but remote ref {} was not bound to expected OID {}",
            transaction.journal.remote_ref,
            transaction.journal.expected_oid
        );
    }
    bail!(
        "git push failed and expected remote OID was not observed: {}",
        if stderr.is_empty() {
            "no stderr was returned"
        } else {
            &stderr
        }
    )
}

struct GitPushExternalEffectProvider<'a> {
    worktree_path: &'a Path,
    remote_url: &'a str,
    remote_ref: &'a str,
    expected_oid: &'a str,
    source_guard: Option<&'a ExternalSourceGuard>,
}

impl GitPushExternalEffectProvider<'_> {
    fn revalidate_source_full(&self) -> Result<()> {
        if let Some(source) = self.source_guard {
            revalidate_external_source(self.worktree_path, source)?;
        }
        Ok(())
    }

    fn revalidate_source_action_revision(&self) -> Result<()> {
        if let Some(source) = self.source_guard {
            revalidate_external_source_action_revision(self.worktree_path, source)?;
        }
        Ok(())
    }

    fn exact_receipt(&self, request: &ExternalEffectRequest) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: self.expected_oid.to_string(),
            url: format!("{}#{}", redact_remote_url(self.remote_url), self.remote_ref),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }
}

impl ExternalEffectProvider for GitPushExternalEffectProvider<'_> {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        self.revalidate_source_full()
    }

    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        self.revalidate_source_action_revision()?;
        match observe_remote_ref(self.worktree_path, self.remote_url, self.remote_ref)? {
            None => Ok(Vec::new()),
            Some(observed) if observed == self.expected_oid => {
                Ok(vec![self.exact_receipt(request)])
            }
            Some(_) => bail!("stable external-effect remote ref points to a different OID"),
        }
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        self.revalidate_source_full()?;
        let output = push_git_commit_create_only(
            self.worktree_path,
            self.remote_url,
            self.remote_ref,
            self.expected_oid,
        )?;
        if !output.success {
            bail!("git push did not return success");
        }
        let matches = self.lookup(request)?;
        if matches.len() != 1 {
            bail!("git push response could not be reconciled to its stable remote ref");
        }
        Ok(matches[0].clone())
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        let matches = self.lookup(request)?;
        if matches.as_slice() != [receipt.clone()] {
            bail!("git push receipt no longer matches the exact remote ref observation");
        }
        Ok(receipt.clone())
    }
}

fn ensure_github_remote_expected_commit(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<()> {
    require_remote_expected_base(
        worktree_path,
        transaction,
        "before publication ref creation",
    )?;
    ensure_remote_expected_commit(worktree_path, transaction)
}

fn observe_remote_ref(
    worktree_path: &Path,
    remote_url: &str,
    remote_ref: &str,
) -> Result<Option<String>> {
    let operation = PublicationGitOperation::observe(remote_ref)?;
    let context = PublicationGitContext::create(worktree_path, remote_url, operation)?;
    let output = context.run()?;
    if !output.success {
        bail!(
            "git ls-remote failed for {}: {}",
            remote_ref,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut observed = None;
    for line in output.stdout.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(|byte| byte.is_ascii_whitespace());
        let oid = fields.next().context("git ls-remote omitted object id")?;
        let reported_ref = fields.next().context("git ls-remote omitted ref name")?;
        if fields.any(|field| !field.is_empty()) {
            bail!("git ls-remote returned unexpected extra fields");
        }
        if reported_ref != remote_ref.as_bytes() {
            bail!("git ls-remote returned an unexpected ref");
        }
        let oid = std::str::from_utf8(oid).context("remote OID was not ASCII")?;
        let oid = Oid::from_str(oid)
            .context("remote OID was invalid")?
            .to_string();
        if observed.replace(oid).is_some() {
            bail!("git ls-remote returned duplicate publication refs");
        }
    }
    Ok(observed)
}

fn push_git_commit_create_only(
    worktree_path: &Path,
    remote_url: &str,
    remote_ref: &str,
    expected_oid: &str,
) -> Result<merge::RequiredCommandOutput> {
    let operation = PublicationGitOperation::push_create_only(expected_oid, remote_ref)?;
    let context = PublicationGitContext::create(worktree_path, remote_url, operation)?;
    context.run()
}

fn reconcile_github_pr(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
) -> Result<GithubPrResult> {
    if let Some(request) = transaction.pr_effect_request.clone() {
        let mut api = CliGithubApi;
        let mut provider = GithubPrExternalEffectProvider {
            worktree_path,
            remote_url: &transaction.remote_url,
            journal: transaction.journal.clone(),
            api: &mut api,
            source_guard: request.source.as_ref(),
        };
        let receipt =
            execute_external_effect_exactly_once(worktree_path, request.clone(), &mut provider)?;
        let result = provider.view_exact_receipt(&receipt)?;
        return verify_github_receipt_with_remote_check(
            worktree_path,
            transaction,
            result,
            true,
            false,
            |_, _, _| Ok(()),
        );
    }
    reconcile_github_pr_with_api(worktree_path, transaction, &mut CliGithubApi)
}

struct GithubPrExternalEffectProvider<'a, A: GithubApi> {
    worktree_path: &'a Path,
    remote_url: &'a str,
    journal: PublicationTransactionJournal,
    api: &'a mut A,
    source_guard: Option<&'a ExternalSourceGuard>,
}

impl<A: GithubApi> GithubPrExternalEffectProvider<'_, A> {
    fn revalidate_bound_inputs(&mut self, require_full_source: bool) -> Result<()> {
        if let Some(source) = self.source_guard {
            if require_full_source {
                revalidate_external_source(self.worktree_path, source)?;
            } else {
                revalidate_external_source_action_revision(self.worktree_path, source)?;
            }
        }
        let base_oid = self
            .journal
            .expected_base_oid
            .as_deref()
            .context("GitHub PR effect omitted exact base OID")?;
        let base_ref = format!("refs/heads/{}", self.journal.base);
        if observe_remote_ref(self.worktree_path, self.remote_url, &base_ref)?.as_deref()
            != Some(base_oid)
        {
            bail!("GitHub PR effect base ref changed from its exact reviewed OID");
        }
        if observe_remote_ref(
            self.worktree_path,
            self.remote_url,
            &self.journal.remote_ref,
        )?
        .as_deref()
            != Some(self.journal.expected_oid.as_str())
        {
            bail!("GitHub PR effect head ref changed from its stable expected OID");
        }
        Ok(())
    }

    fn repository(&self) -> Result<&GithubRepositoryIdentity> {
        self.journal
            .github_repository
            .as_ref()
            .context("GitHub PR effect omitted repository identity")
    }

    fn receipt_from_result(
        &self,
        request: &ExternalEffectRequest,
        result: &GithubPrResult,
    ) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: result.number.to_string(),
            url: result.url.clone(),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }

    fn exact_remote_results(&mut self) -> Result<Vec<GithubPrResult>> {
        self.revalidate_bound_inputs(false)?;
        let repository = self.repository()?.clone();
        let candidates =
            self.api
                .list(self.worktree_path, &self.journal.remote_branch, &repository)?;
        if candidates.len() > MAX_GITHUB_PR_LIST_RECEIPTS {
            bail!("GitHub PR effect lookup returned too many candidates");
        }
        let mut exact = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let viewed = self.api.view(
                self.worktree_path,
                &candidate.number.to_string(),
                &repository,
            )?;
            validate_github_receipt_contract(&viewed, &self.journal)?;
            exact.push(viewed);
        }
        exact.sort_by_key(|result| result.number);
        exact.dedup_by_key(|result| result.number);
        Ok(exact)
    }

    fn view_exact_receipt(&mut self, receipt: &ExternalEffectReceipt) -> Result<GithubPrResult> {
        self.revalidate_bound_inputs(false)?;
        let repository = self.repository()?.clone();
        let viewed = self
            .api
            .view(self.worktree_path, &receipt.provider_id, &repository)?;
        validate_github_receipt_contract(&viewed, &self.journal)?;
        if viewed.url != receipt.url {
            bail!("GitHub PR exact view URL changed from authenticated receipt");
        }
        Ok(viewed)
    }
}

impl<A: GithubApi> ExternalEffectProvider for GithubPrExternalEffectProvider<'_, A> {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        self.revalidate_bound_inputs(true)
    }

    fn lookup(&mut self, request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        Ok(self
            .exact_remote_results()?
            .iter()
            .map(|result| self.receipt_from_result(request, result))
            .collect())
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        self.revalidate_bound_inputs(true)?;
        let repository = self.repository()?.clone();
        let title = self
            .journal
            .expected_pr_title
            .as_deref()
            .context("GitHub PR effect omitted title")?;
        let body = self
            .journal
            .expected_pr_body
            .as_deref()
            .context("GitHub PR effect omitted marker-bound body")?;
        let output = self.api.create(
            self.worktree_path,
            &self.journal.remote_branch,
            &self.journal.base,
            title,
            body,
            self.journal.draft,
            &repository,
        )?;
        if !output.stderr.is_empty() && output.stdout.is_empty() {
            bail!("GitHub PR provider returned no usable creation response");
        }
        let matches = self.exact_remote_results()?;
        if matches.len() != 1 {
            bail!("GitHub PR creation response could not be reconciled exactly");
        }
        Ok(self.receipt_from_result(request, &matches[0]))
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        let viewed = self.view_exact_receipt(receipt)?;
        Ok(self.receipt_from_result(request, &viewed))
    }
}

fn reconcile_github_pr_with_api(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    api: &mut impl GithubApi,
) -> Result<GithubPrResult> {
    reconcile_github_pr_with_api_and_remote_check(
        worktree_path,
        transaction,
        api,
        require_remote_expected,
    )
}

fn reconcile_github_pr_with_api_and_remote_check(
    worktree_path: &Path,
    transaction: &mut PublicationTransaction,
    api: &mut impl GithubApi,
    mut remote_check: impl FnMut(&Path, &PublicationTransaction, &str) -> Result<()>,
) -> Result<GithubPrResult> {
    let github_repository = transaction
        .journal
        .github_repository
        .clone()
        .context("GitHub publication transaction omitted forge repository binding")?;
    remote_check(
        worktree_path,
        transaction,
        "before GitHub PR reconciliation",
    )?;

    if transaction.journal.pr_url.is_some() {
        let selector = transaction
            .journal
            .pr_number
            .map(|number| number.to_string())
            .unwrap_or_else(|| transaction.journal.remote_branch.clone());
        if let Ok(receipt) = api.view(worktree_path, &selector, &github_repository) {
            return verify_github_receipt_with_remote_check(
                worktree_path,
                transaction,
                receipt,
                transaction.journal.created_by_transaction,
                transaction.journal.observed_existing_pr,
                &mut remote_check,
            );
        }
    }

    let existing = api.list(
        worktree_path,
        &transaction.journal.remote_branch,
        &github_repository,
    )?;
    if existing.len() > 1 {
        bail!(
            "multiple GitHub PRs exist for unique publication branch {}",
            transaction.journal.remote_branch
        );
    }
    if let Some(existing) = existing.into_iter().next() {
        if !transaction.journal.create_attempted {
            bail!(
                "a GitHub PR already exists for the publication branch before this transaction attempted creation; refusing front-run reconciliation"
            );
        }
        let selector = existing.number.to_string();
        let receipt = api.view(worktree_path, &selector, &github_repository)?;
        return verify_github_receipt_with_remote_check(
            worktree_path,
            transaction,
            receipt,
            true,
            false,
            &mut remote_check,
        );
    }

    remote_check(
        worktree_path,
        transaction,
        "immediately before gh pr create",
    )?;
    transaction.journal.create_attempted = true;
    transaction.persist()?;
    let title = transaction
        .journal
        .expected_pr_title
        .as_deref()
        .context("GitHub publication transaction omitted its bound title")?;
    let body = transaction
        .journal
        .expected_pr_body
        .as_deref()
        .context("GitHub publication transaction omitted its marker-bound body")?;
    let create = api.create(
        worktree_path,
        &transaction.journal.remote_branch,
        &transaction.journal.base,
        title,
        body,
        transaction.journal.draft,
        &github_repository,
    )?;
    let hinted_url = first_non_empty_line(&String::from_utf8_lossy(&create.stdout));

    let receipt = if hinted_url.is_some() {
        api.view(
            worktree_path,
            &transaction.journal.remote_branch,
            &github_repository,
        )
        .ok()
    } else {
        None
    };
    let receipt = match receipt {
        Some(receipt) => receipt,
        None => {
            let recovered = api.list(
                worktree_path,
                &transaction.journal.remote_branch,
                &github_repository,
            )?;
            if recovered.len() > 1 {
                bail!("gh pr create outcome is ambiguous: multiple matching PRs were observed");
            }
            let Some(recovered) = recovered.into_iter().next() else {
                let stderr = String::from_utf8_lossy(&create.stderr).trim().to_string();
                bail!(
                    "gh pr create outcome could not be reconciled: {}",
                    if stderr.is_empty() {
                        "no PR receipt was returned or discovered"
                    } else {
                        &stderr
                    }
                );
            };
            let selector = recovered.number.to_string();
            api.view(worktree_path, &selector, &github_repository)?
        }
    };
    verify_github_receipt_with_remote_check(
        worktree_path,
        transaction,
        receipt,
        true,
        false,
        &mut remote_check,
    )
}
