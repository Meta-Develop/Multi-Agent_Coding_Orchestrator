fn reject_unsafe_lock_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect repository lock {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata_is_windows_reparse_point(&metadata)
    {
        bail!(
            "repository mutation lock {} is not a regular file; refusing to follow it",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        if windows_path_link_count(path)? != 1 {
            bail!(
                "repository mutation lock {} has multiple hard links; refusing to trust it",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_open_lock_file(path: &Path, file: &fs::File) -> Result<()> {
    reject_unsafe_lock_path(path)?;
    #[cfg(unix)]
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to re-inspect repository lock {}", path.display()))?;
    let file_metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect open repository lock {}", path.display()))?;
    if !file_metadata.file_type().is_file() || metadata_is_windows_reparse_point(&file_metadata) {
        bail!(
            "repository mutation lock {} changed type while being opened",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev()
            || path_metadata.ino() != file_metadata.ino()
            || file_metadata.nlink() != 1
        {
            bail!(
                "repository mutation lock {} changed while being opened",
                path.display()
            );
        }
    }
    #[cfg(target_os = "windows")]
    {
        let path_snapshot =
            crate::file_identity::open_windows_path_identity(path).with_context(|| {
                format!("failed to open repository lock identity {}", path.display())
            })?;
        let path_metadata = &path_snapshot.metadata;
        let file_identity = crate::file_identity::windows_file_identity(file)
            .context("failed to inspect open repository lock identity")?;
        let file_link_count = crate::file_identity::windows_file_link_count(file)
            .context("failed to inspect open repository lock link count")?;
        if !path_metadata.file_type().is_file()
            || path_metadata.file_type().is_symlink()
            || metadata_is_windows_reparse_point(path_metadata)
            || path_snapshot.number_of_links != 1
            || path_snapshot.identity != file_identity
            || file_link_count != 1
        {
            bail!(
                "repository mutation lock {} changed while being opened",
                path.display()
            );
        }
    }
    Ok(())
}

fn write_lock_owner(
    file: &mut fs::File,
    path: &Path,
    operation: &str,
    owner_bytes: &[u8],
) -> Result<()> {
    file.set_len(0)
        .with_context(|| format!("failed to truncate {operation} lock owner record"))?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek {operation} lock owner record"))?;
    file.write_all(owner_bytes)
        .with_context(|| format!("failed to record {operation} lock owner"))?;
    file.sync_all().with_context(|| {
        format!(
            "failed to persist {operation} lock owner record {}",
            path.display()
        )
    })
}

fn repository_lock_contention<T>(file: &mut fs::File, path: &Path, operation: &str) -> Result<T> {
    let current = read_lock_record(file, path)
        .and_then(|bytes| {
            serde_json::from_slice::<RepoLockOwner>(&bytes)
                .context("active repository lock owner JSON is malformed")
        })
        .and_then(|owner| {
            validate_lock_owner(&owner, operation)?;
            Ok(owner)
        });
    match current {
        Ok(owner) => bail!(
            "{operation} cannot acquire repository mutation lock: kernel lock is held for {} by pid {} (nonce {}, created {})",
            owner.operation,
            owner.pid,
            owner.nonce,
            owner.created_unix_seconds
        ),
        Err(error) => bail!(
            "{operation} cannot acquire repository mutation lock {}: an active kernel lock has an invalid owner record ({error:#})",
            path.display()
        ),
    }
}

fn validate_lock_owner(owner: &RepoLockOwner, operation: &str) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch while validating repository lock")?
        .as_secs();
    if owner.version != LOCK_RECORD_VERSION
        || owner.pid == 0
        || owner.nonce.is_empty()
        || owner.nonce.len() > 128
        || !owner
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || owner.created_unix_seconds == 0
        || owner.created_unix_seconds > now.saturating_add(300)
        || owner.operation.is_empty()
        || owner.operation.len() > 64
        || !owner
            .operation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !valid_process_start_identity(owner.process_start.as_ref())
    {
        bail!(
            "{operation} repository mutation lock owner record is invalid and will not be reclaimed automatically"
        );
    }
    Ok(())
}

fn valid_process_start_identity(identity: Option<&ProcessStartIdentity>) -> bool {
    #[cfg(target_os = "linux")]
    {
        matches!(identity, Some(ProcessStartIdentity::LinuxProcStartTicks(value)) if *value > 0)
    }
    #[cfg(target_os = "windows")]
    {
        matches!(identity, Some(ProcessStartIdentity::WindowsCreationFiletime(value)) if *value > 0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        identity.is_none()
    }
}

fn read_lock_record(file: &mut fs::File, path: &Path) -> Result<Vec<u8>> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect repository lock {}", path.display()))?;
    if metadata.len() == 0 || metadata.len() > MAX_LOCK_RECORD_BYTES {
        bail!("active repository lock owner record has an invalid size");
    }
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("failed to seek repository lock {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_LOCK_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read repository lock {}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_LOCK_RECORD_BYTES {
        bail!("active repository lock owner record changed size while being read");
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read process identity {}", path.display()))
        }
    };
    let closing_paren = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .context("Linux process stat did not contain a command terminator")?;
    let fields = bytes[closing_paren + 1..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let start_ticks = fields
        .get(19)
        .context("Linux process stat did not contain starttime")?;
    let start_ticks = std::str::from_utf8(start_ticks)
        .context("Linux process starttime was not ASCII")?
        .parse::<u64>()
        .context("Linux process starttime was invalid")?;
    if start_ticks == 0 {
        bail!("Linux process starttime was zero");
    }
    Ok(Some(ProcessStartIdentity::LinuxProcStartTicks(start_ticks)))
}

#[cfg(target_os = "windows")]
fn process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    windows_process_start_identity(pid)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn process_start_identity(_pid: u32) -> Result<Option<ProcessStartIdentity>> {
    Ok(None)
}

fn lock_owner_process_start_identity() -> Result<Option<ProcessStartIdentity>> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        process_start_identity(std::process::id())?
            .with_context(|| {
                "current process start identity disappeared while acquiring repository lock"
            })
            .map(Some)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(None)
    }
}

#[cfg(target_os = "windows")]
fn windows_process_start_identity(pid: u32) -> Result<Option<ProcessStartIdentity>> {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    // SAFETY: The Windows API calls use a PID-sized integer, checked null
    // handles, initialized FILETIME outputs, and close every acquired handle.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER) {
                Ok(None)
            } else {
                Err(error).context("failed to open process for creation-time identity")
            };
        }
        let mut creation = FileTime { low: 0, high: 0 };
        let mut exit = FileTime { low: 0, high: 0 };
        let mut kernel = FileTime { low: 0, high: 0 };
        let mut user = FileTime { low: 0, high: 0 };
        let result = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
        let times_error = (result == 0).then(std::io::Error::last_os_error);
        let close_result = CloseHandle(handle);
        if let Some(error) = times_error {
            return Err(error).context("failed to read process creation-time identity");
        }
        if close_result == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to close process identity handle");
        }
        let value = (u64::from(creation.high) << 32) | u64::from(creation.low);
        if value == 0 {
            bail!("Windows process creation time was zero");
        }
        Ok(Some(ProcessStartIdentity::WindowsCreationFiletime(value)))
    }
}

impl Drop for RepoCommonLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

impl PrimaryRepositoryState {
    fn capture(repo_root: &Path) -> Result<Self> {
        let first = Self::capture_once(repo_root)?;
        let second = Self::capture_once(repo_root)?;
        if first != second {
            bail!(
                "primary repository state changed while it was being captured; retry merge apply after concurrent repository activity stops"
            );
        }
        Ok(second)
    }

    fn capture_once(repo_root: &Path) -> Result<Self> {
        let repo = crate::git_repository::open(repo_root).with_context(|| {
            format!("failed to open primary repository {}", repo_root.display())
        })?;
        let head = head_oid(&repo).context("failed to read primary HEAD for merge transaction")?;
        let index_digest = hash_optional_file(&repo.path().join("index"))?;
        let worktree_digest = snapshot_worktree_candidate(&repo, repo_root, head)?.oid;
        Ok(Self {
            head,
            index_digest,
            worktree_digest,
        })
    }
}

fn run_git_with_input(repo_root: &Path, args: &[&str], input: &[u8]) -> Result<GitCommandOutput> {
    let repo = crate::git_repository::open(repo_root)
        .with_context(|| format!("failed to open Git worktree {}", repo_root.display()))?;
    let context = TemporaryIndex::create(repo.commondir())?;
    initialize_isolated_index(&context, repo_root, head_oid(&repo)?)?;
    run_isolated_git_process(
        &context,
        repo_root,
        args,
        StdinMode::Bytes(input.to_vec()),
        "git patch command",
    )
}

fn run_git_with_input_with_writable_worktree(
    repo_root: &Path,
    args: &[&str],
    input: &[u8],
) -> Result<GitCommandOutput> {
    let repo = crate::git_repository::open(repo_root)
        .with_context(|| format!("failed to open Git worktree {}", repo_root.display()))?;
    let context = TemporaryIndex::create(repo.commondir())?;
    initialize_isolated_index(&context, repo_root, head_oid(&repo)?)?;
    run_isolated_git_process_with_writable_worktree(
        &context,
        repo_root,
        args,
        StdinMode::Bytes(input.to_vec()),
        "git patch command",
    )
}

fn run_isolated_git_process(
    context: &TemporaryIndex,
    worktree_path: &Path,
    operation: &[&str],
    stdin: StdinMode,
    label: &str,
) -> Result<GitCommandOutput> {
    run_isolated_git_process_os(
        context,
        worktree_path,
        context.command_args(worktree_path, operation),
        stdin,
        label,
    )
}

fn run_isolated_git_process_with_timeout(
    context: &TemporaryIndex,
    worktree_path: &Path,
    operation: &[&str],
    stdin: StdinMode,
    label: &str,
    timeout: Duration,
    deadline_knobs: Option<(&str, &str)>,
) -> Result<GitCommandOutput> {
    let profile = isolated_git_workspace_profile(context, worktree_path)?;
    run_isolated_git_process_os_with_profile_and_timeout(
        worktree_path,
        context.command_args(worktree_path, operation),
        stdin,
        label,
        profile,
        timeout,
        deadline_knobs,
    )
}

fn run_isolated_git_process_with_writable_worktree(
    context: &TemporaryIndex,
    worktree_path: &Path,
    operation: &[&str],
    stdin: StdinMode,
    label: &str,
) -> Result<GitCommandOutput> {
    let profile =
        isolated_git_workspace_profile_with_writable_worktree(context, worktree_path)?;
    run_isolated_git_process_os_with_profile(
        worktree_path,
        context.command_args(worktree_path, operation),
        stdin,
        label,
        profile,
    )
}

fn run_isolated_git_process_os(
    context: &TemporaryIndex,
    worktree_path: &Path,
    command_args: Vec<OsString>,
    stdin: StdinMode,
    label: &str,
) -> Result<GitCommandOutput> {
    let profile = isolated_git_workspace_profile(context, worktree_path)?;
    run_isolated_git_process_os_with_profile(
        worktree_path,
        command_args,
        stdin,
        label,
        profile,
    )
}

fn run_isolated_git_process_os_with_profile(
    worktree_path: &Path,
    command_args: Vec<OsString>,
    stdin: StdinMode,
    label: &str,
    profile: StrictOfflineWorkspaceProfile,
) -> Result<GitCommandOutput> {
    run_isolated_git_process_os_with_profile_and_timeout(
        worktree_path,
        command_args,
        stdin,
        label,
        profile,
        LOCAL_GIT_PROCESS_TIMEOUT,
        None,
    )
}

fn run_isolated_git_process_os_with_profile_and_timeout(
    worktree_path: &Path,
    command_args: Vec<OsString>,
    stdin: StdinMode,
    label: &str,
    profile: StrictOfflineWorkspaceProfile,
    timeout: Duration,
    deadline_knobs: Option<(&str, &str)>,
) -> Result<GitCommandOutput> {
    run_required_local_git_direct(
        label,
        resolve_trusted_executable("git")?,
        command_args,
        worktree_path,
        capture_git_environment(worktree_path)?,
        stdin,
        timeout,
        GIT_CAPTURE_LIMIT_BYTES,
        GIT_STDIN_LIMIT_BYTES,
        profile,
        deadline_knobs,
    )
}

fn isolated_git_workspace_profile(
    context: &TemporaryIndex,
    worktree_path: &Path,
) -> Result<StrictOfflineWorkspaceProfile> {
    configure_isolated_git_workspace_profile(
        context,
        worktree_path,
        StrictOfflineWorkspaceProfile::read_only(worktree_path),
    )
}

fn isolated_git_workspace_profile_with_writable_worktree(
    context: &TemporaryIndex,
    worktree_path: &Path,
) -> Result<StrictOfflineWorkspaceProfile> {
    configure_isolated_git_workspace_profile(
        context,
        worktree_path,
        StrictOfflineWorkspaceProfile::read_write(worktree_path),
    )
}

fn configure_isolated_git_workspace_profile(
    context: &TemporaryIndex,
    worktree_path: &Path,
    profile: StrictOfflineWorkspaceProfile,
) -> Result<StrictOfflineWorkspaceProfile> {
    let common_dir = context
        .alternate_object_directory
        .parent()
        .context("alternate object directory omitted its Git common directory")?;
    let common_dir = fs::canonicalize(common_dir).with_context(|| {
        format!(
            "failed to resolve Git common directory {}",
            common_dir.display()
        )
    })?;
    let repository_root = common_dir
        .parent()
        .context("Git common directory omitted its parent repository root")?;
    let repository_root = fs::canonicalize(repository_root).with_context(|| {
        format!(
            "failed to resolve Git repository root {}",
            repository_root.display()
        )
    })?;
    let worktree_root = fs::canonicalize(worktree_path).with_context(|| {
        format!(
            "failed to resolve Git worktree {}",
            worktree_path.display()
        )
    })?;
    let mut profile = profile
        .with_writable_artifact_root(&context.directory)
        .with_visible_read_only_root(&context.alternate_object_directory)
        .with_visible_read_only_root(&common_dir);
    if repository_root != worktree_root {
        profile = profile.with_visible_read_only_root(&repository_root);
    }
    hide_sensitive_state_if_present(profile, &common_dir)
}

fn hide_sensitive_state_if_present(
    profile: StrictOfflineWorkspaceProfile,
    common_dir: &Path,
) -> Result<StrictOfflineWorkspaceProfile> {
    let state_path = common_dir.join("maco").join("state");
    match fs::symlink_metadata(&state_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(profile),
        Err(error) => Err(error).context(format!(
            "failed to inspect repository sensitive state {}",
            state_path.display()
        )),
        Ok(_) => Ok(profile.with_hidden_root(
            crate::artifacts::state_auth::sensitive_state_root(common_dir).context(
                "repository sensitive state could not be bound for child-process masking",
            )?,
        )),
    }
}

fn initialize_isolated_index(
    context: &TemporaryIndex,
    worktree_path: &Path,
    head: Option<Oid>,
) -> Result<()> {
    let head_text = head.map(|oid| oid.to_string());
    let args = match head_text.as_deref() {
        Some(oid) => vec!["read-tree", oid],
        None => vec!["read-tree", "--empty"],
    };
    let output = run_isolated_git_process(
        context,
        worktree_path,
        &args,
        StdinMode::Null,
        "initialize isolated Git index",
    )?;
    require_git_success(output, "initialize isolated Git index")
}

fn capture_git_environment(repo_root: &Path) -> Result<BTreeMap<String, String>> {
    let allowed = ["SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"];
    let mut environment = explicit_environment(&allowed);
    pin_parsed_git_locale(&mut environment);
    let runtime_root = trusted_runtime_root(repo_root)?;
    environment.insert("PATH".to_string(), trusted_path_text()?);
    environment.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    environment.insert(
        "GIT_CONFIG_GLOBAL".to_string(),
        path_environment_value(&disabled_git_path(&runtime_root, "global-config"))?,
    );
    environment.insert("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    environment.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    let runtime = path_environment_value(&runtime_root)?;
    environment.insert("TMPDIR".to_string(), runtime.clone());
    environment.insert("TMP".to_string(), runtime.clone());
    environment.insert("TEMP".to_string(), runtime);
    Ok(environment)
}

fn pin_parsed_git_locale(environment: &mut BTreeMap<String, String>) {
    // git apply stderr is parsed with English-only patterns. Do not inherit
    // ambient LANG/LC_* or those messages localize and path attribution is lost.
    environment.remove("LANG");
    environment.remove("LC_ALL");
    environment.remove("LC_CTYPE");
    environment.remove("LC_MESSAGES");
    environment.insert("LC_ALL".to_string(), "C".to_string());
    environment.insert("LANG".to_string(), "C".to_string());
}

fn validation_command_environment(environment_root: &Path) -> Result<BTreeMap<String, String>> {
    create_private_directory(environment_root)?;
    let home = environment_root.join("home");
    let temporary = environment_root.join("tmp");
    let xdg_config = environment_root.join("xdg-config");
    let xdg_cache = environment_root.join("xdg-cache");
    let xdg_state = environment_root.join("xdg-state");
    for directory in [&home, &temporary, &xdg_config, &xdg_cache, &xdg_state] {
        create_private_directory(directory)?;
    }
    let global_git_config = environment_root.join("gitconfig");
    write_private_file(&global_git_config, b"")?;
    let mut environment = explicit_environment(&[
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ]);
    environment.insert("PATH".to_string(), trusted_path_text()?);
    environment.insert("HOME".to_string(), path_environment_value(&home)?);
    environment.insert(
        "XDG_CONFIG_HOME".to_string(),
        path_environment_value(&xdg_config)?,
    );
    environment.insert(
        "XDG_CACHE_HOME".to_string(),
        path_environment_value(&xdg_cache)?,
    );
    environment.insert(
        "XDG_STATE_HOME".to_string(),
        path_environment_value(&xdg_state)?,
    );
    let temporary = path_environment_value(&temporary)?;
    environment.insert("TMPDIR".to_string(), temporary.clone());
    environment.insert("TMP".to_string(), temporary.clone());
    environment.insert("TEMP".to_string(), temporary);
    environment.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    environment.insert(
        "GIT_CONFIG_GLOBAL".to_string(),
        path_environment_value(&global_git_config)?,
    );
    environment.insert("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    environment.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    Ok(environment)
}

fn validation_diagnostics_redactor(environment_root: &Path) -> Redactor {
    let mut redactor = Redactor::new().with_private_value(
        "validation-runtime",
        environment_root.to_string_lossy().into_owned(),
    );
    for (key, value) in env::vars() {
        if validation_private_environment_key(&key) && value.len() >= 4 {
            redactor = redactor.with_private_value("validation-private-env", value);
        }
    }
    redactor
}

fn validation_private_environment_key(key: &str) -> bool {
    let key = key.to_ascii_uppercase();
    key == "BASH_ENV"
        || key == "ENV"
        || key == "SSH_AUTH_SOCK"
        || key == "ALL_PROXY"
        || key == "NO_PROXY"
        || key.ends_with("_PROXY")
        || matches!(
            key.as_str(),
            "SSL_CERT_FILE"
                | "SSL_CERT_DIR"
                | "CURL_CA_BUNDLE"
                | "REQUESTS_CA_BUNDLE"
                | "NODE_EXTRA_CA_CERTS"
                | "GIT_SSL_CAINFO"
                | "GIT_SSL_CAPATH"
        )
        || key.contains("SECRET")
        || key.contains("TOKEN")
        || key.contains("PASSWORD")
        || key.contains("PRIVATE_KEY")
        || key.contains("API_KEY")
        || key.contains("ACCESS_KEY")
        || key.contains("CREDENTIAL")
        || key.contains("COOKIE")
        || key.contains("SESSION")
        || key == "AUTH"
        || key.starts_with("AUTH_")
        || key.ends_with("_AUTH")
        || key.contains("_AUTH_")
        || (key.ends_with("_KEY") && !key.ends_with("_PUBLIC_KEY"))
        || [
            "AWS_",
            "AZURE_",
            "GOOGLE_",
            "OPENAI_",
            "ANTHROPIC_",
            "GH_",
            "GITHUB_",
            "GITLAB_",
            "HF_",
        ]
        .iter()
        .any(|prefix| key.starts_with(prefix))
}

pub(crate) fn minimal_network_environment() -> Result<BTreeMap<String, String>> {
    let allowed = [
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
    ];
    let mut environment = explicit_environment(&allowed);
    environment.insert("PATH".to_string(), trusted_path_text()?);
    environment.insert("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_ATTR_NOSYSTEM".to_string(), "1".to_string());
    environment.insert("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string());
    environment.insert("GIT_TERMINAL_PROMPT".to_string(), "0".to_string());
    Ok(environment)
}

fn explicit_environment(keys: &[&str]) -> BTreeMap<String, String> {
    keys.iter()
        .filter_map(|key| env::var(key).ok().map(|value| ((*key).to_string(), value)))
        .collect()
}

fn trusted_path_text() -> Result<String> {
    trusted_executable_search_path()?
        .into_string()
        .map_err(|_| anyhow::anyhow!("trusted executable PATH was not valid UTF-8"))
}

fn path_environment_value(path: &Path) -> Result<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("environment path was not UTF-8: {}", path.display()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_required_direct(
    label: &str,
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: &Path,
    environment: BTreeMap<String, String>,
    stdin: StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
    profile: StrictOfflineWorkspaceProfile,
) -> Result<RequiredCommandOutput> {
    run_required_direct_with_profile(
        label,
        program,
        args,
        current_dir,
        environment,
        stdin,
        timeout,
        capture_limit_bytes,
        stdin_limit_bytes,
        SideEffectConfinementProfile::StrictOfflineWorkspace(profile),
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_required_local_git_direct(
    label: &str,
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: &Path,
    environment: BTreeMap<String, String>,
    stdin: StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
    profile: StrictOfflineWorkspaceProfile,
    deadline_knobs: Option<(&str, &str)>,
) -> Result<RequiredCommandOutput> {
    run_required_direct_with_profile(
        label,
        program,
        args,
        current_dir,
        environment,
        stdin,
        timeout,
        capture_limit_bytes,
        stdin_limit_bytes,
        SideEffectConfinementProfile::StrictOfflineWorkspace(profile),
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        deadline_knobs,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_required_network_direct(
    label: &str,
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: &Path,
    environment: BTreeMap<String, String>,
    stdin: StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
    profile: TrustedFixedNetworkProfile,
) -> Result<RequiredCommandOutput> {
    validate_fixed_network_command(
        label,
        &program,
        &args,
        current_dir,
        &environment,
        &stdin,
        timeout,
        capture_limit_bytes,
        stdin_limit_bytes,
    )?;
    run_required_direct_with_profile(
        label,
        program,
        args,
        current_dir,
        environment,
        stdin,
        timeout,
        capture_limit_bytes,
        stdin_limit_bytes,
        SideEffectConfinementProfile::TrustedFixedNetwork(profile),
        SideEffectConfinementProfileKind::TrustedFixedNetwork,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_required_direct_with_profile(
    label: &str,
    program: PathBuf,
    args: Vec<OsString>,
    current_dir: &Path,
    environment: BTreeMap<String, String>,
    stdin: StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
    profile: SideEffectConfinementProfile,
    expected_profile: SideEffectConfinementProfileKind,
    deadline_knobs: Option<(&str, &str)>,
) -> Result<RequiredCommandOutput> {
    if let StdinMode::Bytes(bytes) = &stdin {
        if bytes.len() > stdin_limit_bytes {
            bail!("{label} stdin exceeded the {stdin_limit_bytes}-byte safety limit");
        }
    }
    let output = run_process(
        ProcessSpec::direct(label, program, args, current_dir, capture_limit_bytes)
            .with_environment(EnvironmentMode::ClearAndSet(environment))
            .with_side_effect_confinement(profile)
            .with_stdin(stdin)
            .with_timeout(Some(timeout)),
    )
    .with_context(|| format!("failed to run {label}"))?;
    require_verified_process_output_with_deadline_hint(
        label,
        &output,
        expected_profile,
        deadline_knobs.map(|(flag, environment)| (timeout, flag, environment)),
    )?;
    Ok(RequiredCommandOutput {
        success: output.status.is_some_and(|status| status.success()),
        stdout: output.stdout.as_bytes().to_vec(),
        stderr: output.stderr.as_bytes().to_vec(),
    })
}

fn require_verified_process_output(
    label: &str,
    output: &ProcessOutput,
    expected_profile: SideEffectConfinementProfileKind,
) -> Result<()> {
    require_verified_process_output_with_deadline_hint(label, output, expected_profile, None)
}

fn require_verified_process_output_with_deadline_hint(
    label: &str,
    output: &ProcessOutput,
    expected_profile: SideEffectConfinementProfileKind,
    deadline_hint: Option<(Duration, &str, &str)>,
) -> Result<()> {
    require_verified_containment(label, output.process_tree)?;
    if output.side_effects != SideEffectConfinementEvidence::Verified(expected_profile) {
        bail!(
            "{label} returned without exact verified {expected_profile:?} side-effect confinement: {:?}",
            output.side_effects,
        );
    }
    if output.timed_out {
        if let Some((timeout, flag, environment)) = deadline_hint {
            bail!(
                "{label} exceeded its effective {}-second total operation deadline; raise {flag} or {environment} to allow more time",
                timeout.as_secs()
            );
        }
        bail!("{label} exceeded its total operation deadline");
    }
    if let Some(error) = &output.process_error {
        bail!("{label} process cleanup failed: {error}");
    }
    if let Some(error) = &output.stdin_error {
        bail!("{label} stdin failed: {error}");
    }
    if output.stdout.is_truncated() || output.stderr.is_truncated() {
        bail!("{label} exceeded its bounded output capture limit");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_fixed_network_command(
    label: &str,
    program: &Path,
    args: &[OsString],
    current_dir: &Path,
    environment: &BTreeMap<String, String>,
    stdin: &StdinMode,
    timeout: Duration,
    capture_limit_bytes: usize,
    stdin_limit_bytes: usize,
) -> Result<()> {
    if label.is_empty()
        || label.len() > 1024
        || label.as_bytes().iter().any(|byte| byte.is_ascii_control())
    {
        bail!("trusted network command label is empty or oversized");
    }
    let program_text = program
        .to_str()
        .context("trusted network executable path was not strict UTF-8")?;
    if program_text.len() > 4096
        || program_text
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control())
    {
        bail!("trusted network executable path is malformed or oversized");
    }
    let executable_name = program
        .file_name()
        .and_then(OsStr::to_str)
        .context("trusted network executable name was not UTF-8")?;
    if !program.is_absolute() || !matches!(executable_name, "git" | "gh") {
        bail!("trusted network command requires an absolute fixed git or gh executable");
    }
    let expected = resolve_trusted_executable(executable_name)?;
    if expected != program {
        bail!("trusted network executable did not match its fixed resolved identity");
    }
    if timeout.is_zero() || timeout > Duration::from_secs(10 * 60) {
        bail!("trusted network command deadline is zero or exceeds ten minutes");
    }
    if capture_limit_bytes == 0
        || capture_limit_bytes > 64 * 1024 * 1024
        || stdin_limit_bytes > 64 * 1024 * 1024
    {
        bail!("trusted network stream bounds are zero or oversized");
    }
    if args.len() > 2048 {
        bail!("trusted network argument vector is oversized");
    }
    let mut total_argument_bytes = 0usize;
    for argument in args {
        let argument = argument
            .to_str()
            .context("trusted network command argument was not strict UTF-8")?;
        if argument.len() > 64 * 1024
            || argument
                .as_bytes()
                .iter()
                .any(|byte| byte.is_ascii_control())
        {
            bail!("trusted network command argument is malformed or oversized");
        }
        total_argument_bytes = total_argument_bytes
            .checked_add(argument.len())
            .context("trusted network argument size overflow")?;
    }
    if total_argument_bytes > 2 * 1024 * 1024 {
        bail!("trusted network argument vector exceeds its aggregate bound");
    }
    if let StdinMode::Bytes(bytes) = stdin {
        if bytes.len() > stdin_limit_bytes {
            bail!("trusted network stdin exceeds its declared bound");
        }
    }
    if matches!(stdin, StdinMode::Inherit) {
        bail!("trusted network commands may not inherit stdin");
    }
    if !current_dir.is_absolute() {
        bail!("trusted network working directory must be absolute");
    }
    validate_fixed_network_environment(environment, current_dir)
}

fn validate_fixed_network_environment(
    environment: &BTreeMap<String, String>,
    current_dir: &Path,
) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "SystemRoot",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_ATTR_NOSYSTEM",
        "GIT_OPTIONAL_LOCKS",
        "GIT_TERMINAL_PROMPT",
        "GH_CONFIG_DIR",
        "GH_PROMPT_DISABLED",
    ];
    if environment.len() > 32 {
        bail!("trusted network environment exceeds its entry bound");
    }
    for (key, value) in environment {
        if !ALLOWED.contains(&key.as_str())
            || key.len() > 128
            || value.len() > 1024 * 1024
            || key
                .as_bytes()
                .iter()
                .chain(value.as_bytes())
                .any(|byte| byte.is_ascii_control())
        {
            bail!("trusted network environment contains an unapproved or oversized entry");
        }
    }
    let trusted_path = trusted_path_text()?;
    if environment.get("PATH").map(String::as_str) != Some(trusted_path.as_str()) {
        bail!("trusted network PATH differs from the fixed system executable path");
    }
    for key in ["GIT_CONFIG_GLOBAL", "GH_CONFIG_DIR"] {
        if let Some(value) = environment.get(key) {
            let path = Path::new(value);
            if !path.is_absolute() || !path.starts_with(current_dir) {
                bail!("trusted network private config escaped its fixed runtime directory");
            }
        }
    }
    Ok(())
}

fn require_verified_containment(label: &str, evidence: ContainmentEvidence) -> Result<()> {
    if !evidence.is_verified_empty() {
        bail!("{label} returned without verified-empty process containment: {evidence:?}");
    }
    Ok(())
}

#[cfg(test)]
fn is_git_injection_environment_key(key: &str) -> bool {
    matches!(
        key,
        "GIT_DIR"
            | "GIT_WORK_TREE"
            | "GIT_INDEX_FILE"
            | "GIT_COMMON_DIR"
            | "GIT_OBJECT_DIRECTORY"
            | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
            | "GIT_REDIRECT_STDERR"
            | "GIT_EXEC_PATH"
            | "GIT_NAMESPACE"
            | "GIT_REPLACE_REF_BASE"
            | "GIT_SHALLOW_FILE"
            | "GIT_GRAFT_FILE"
            | "GIT_QUARANTINE_PATH"
            | "GIT_CEILING_DIRECTORIES"
            | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
            | "GIT_TEMPLATE_DIR"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_ASKPASS"
            | "SSH_ASKPASS"
            | "SSH_ASKPASS_REQUIRE"
            | "GIT_PROXY_COMMAND"
            | "GIT_ALLOW_PROTOCOL"
            | "GIT_PROTOCOL_FROM_USER"
            | "GIT_CURL_VERBOSE"
            | "GIT_SSL_NO_VERIFY"
    ) || key.starts_with("GIT_CONFIG_")
        || key.starts_with("GIT_TRACE")
}

pub(crate) fn resolve_trusted_executable(name: &str) -> Result<PathBuf> {
    if !matches!(name, "git" | "gh") {
        bail!("unsupported trusted executable name '{name}'");
    }
    #[cfg(target_os = "windows")]
    {
        let _ = name;
        bail!(
            "trusted Windows executable and ACL resolution is not implemented; refusing external command execution"
        );
    }
    #[cfg(unix)]
    {
        let mut inspected = BTreeSet::new();
        for candidate in trusted_executable_entry_candidates(name) {
            let Ok(canonical) = fs::canonicalize(&candidate) else {
                continue;
            };
            if !inspected.insert(canonical.clone()) {
                continue;
            }
            if validate_trusted_unix_executable(&canonical).is_ok() {
                return Ok(canonical);
            }
        }
        bail!(
            "no trusted root-owned, non-writable executable was found for '{name}' through a fixed system entry"
        );
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = name;
        bail!("trusted executable resolution is unsupported on this platform")
    }
}

#[cfg(unix)]
fn trusted_executable_entry_candidates(name: &str) -> [PathBuf; 3] {
    [
        Path::new("/run/current-system/sw/bin").join(name),
        Path::new("/usr/bin").join(name),
        Path::new("/bin").join(name),
    ]
}

#[cfg(unix)]
fn validate_trusted_unix_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect executable {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        bail!("trusted executable candidate is not a regular file");
    }
    let mode = metadata.permissions().mode();
    if metadata.uid() != 0 || mode & 0o022 != 0 || mode & 0o111 == 0 {
        bail!("trusted executable candidate has unsafe owner or mode");
    }
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let directory_metadata = fs::metadata(directory).with_context(|| {
            format!(
                "failed to inspect executable ancestor {}",
                directory.display()
            )
        })?;
        let immutable_nix_store_root = directory == Path::new("/nix/store")
            && directory_metadata.uid() == 0
            && directory_metadata.permissions().mode() & 0o1000 != 0;
        if !directory_metadata.file_type().is_dir()
            || directory_metadata.uid() != 0
            || (!immutable_nix_store_root && directory_metadata.permissions().mode() & 0o022 != 0)
        {
            bail!("trusted executable candidate has a writable or non-root ancestor");
        }
        ancestor = directory.parent();
    }
    let mut magic = [0_u8; 4];
    fs::File::open(path)
        .with_context(|| format!("failed to open executable {}", path.display()))?
        .read_exact(&mut magic)
        .with_context(|| format!("failed to inspect executable header {}", path.display()))?;
    if !is_native_executable_magic(magic) {
        if magic[..2] != *b"#!" {
            bail!("trusted executable candidate has an unsupported executable format");
        }
        validate_trusted_shebang(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_shebang(path: &Path) -> Result<()> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("failed to open executable script {}", path.display()))?
        .take(4096)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read executable script {}", path.display()))?;
    let first_line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .context("trusted executable script omitted shebang")?;
    let interpreter = first_line
        .strip_prefix(b"#!")
        .context("trusted executable script omitted shebang marker")?;
    let interpreter = std::str::from_utf8(interpreter)
        .context("trusted executable script shebang was not UTF-8")?
        .trim()
        .split_ascii_whitespace()
        .next()
        .context("trusted executable script shebang omitted interpreter")?;
    let interpreter = Path::new(interpreter);
    if !interpreter.is_absolute() {
        bail!("trusted executable script shebang was not absolute");
    }
    let interpreter = fs::canonicalize(interpreter).with_context(|| {
        format!(
            "failed to resolve trusted script interpreter {}",
            interpreter.display()
        )
    })?;
    if interpreter == path {
        bail!("trusted executable script shebang referenced itself");
    }
    validate_trusted_unix_executable(&interpreter)
        .context("trusted executable script interpreter was unsafe")
}

fn is_native_executable_magic(magic: [u8; 4]) -> bool {
    magic == *b"\x7fELF"
        || matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        )
        || magic[..2] == *b"MZ"
}

fn trusted_executable_search_path() -> Result<OsString> {
    #[cfg(unix)]
    {
        let directories = [
            PathBuf::from("/run/current-system/sw/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ]
        .into_iter()
        .filter_map(|path| trusted_unix_search_directory(&path).ok())
        .collect::<Vec<_>>();
        if directories.is_empty() {
            bail!("no trusted system executable directories were available");
        }
        env::join_paths(directories).context("failed to build trusted executable PATH")
    }
    #[cfg(target_os = "windows")]
    {
        bail!("trusted Windows executable PATH is not implemented")
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        bail!("trusted executable PATH is unsupported on this platform")
    }
}

#[cfg(unix)]
fn trusted_unix_search_directory(path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve executable directory {}", path.display()))?;
    let mut current = Some(canonical.as_path());
    while let Some(directory) = current {
        let metadata = fs::metadata(directory).with_context(|| {
            format!(
                "failed to inspect executable directory {}",
                directory.display()
            )
        })?;
        let immutable_nix_store_root = directory == Path::new("/nix/store")
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o1000 != 0;
        if !metadata.file_type().is_dir()
            || metadata.uid() != 0
            || (!immutable_nix_store_root && metadata.permissions().mode() & 0o022 != 0)
        {
            bail!("executable search directory has unsafe owner or mode");
        }
        current = directory.parent();
    }
    Ok(canonical)
}

fn disabled_git_path(runtime_root: &Path, label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    runtime_root.join(format!(
        "maco-disabled-{label}-{}-{nanos}",
        std::process::id()
    ))
}

pub(crate) fn trusted_runtime_root(repo_root: &Path) -> Result<PathBuf> {
    #[cfg(unix)]
    let candidate = private_unix_runtime_root()?;
    #[cfg(target_os = "windows")]
    let candidate = windows_temp_path()?;
    #[cfg(not(any(unix, target_os = "windows")))]
    let candidate = env::temp_dir();

    let runtime_root = fs::canonicalize(&candidate).with_context(|| {
        format!(
            "failed to resolve trusted runtime directory {}",
            candidate.display()
        )
    })?;
    if !runtime_root.is_dir() {
        bail!(
            "trusted runtime path {} is not a directory",
            runtime_root.display()
        );
    }
    let repo_root = fs::canonicalize(repo_root)
        .with_context(|| format!("failed to resolve repository path {}", repo_root.display()))?;
    if runtime_root.starts_with(&repo_root) {
        bail!(
            "trusted runtime directory {} is inside repository {}; refusing capture-time writes",
            runtime_root.display(),
            repo_root.display()
        );
    }
    Ok(runtime_root)
}

#[cfg(unix)]
fn private_unix_runtime_root() -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no arguments and returns the effective numeric uid.
    let uid = unsafe { libc::geteuid() };
    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    let parent = match validate_private_unix_directory(&run_user, uid) {
        Ok(()) => run_user,
        Err(_) => {
            let temporary =
                fs::canonicalize("/tmp").context("failed to resolve /tmp runtime fallback")?;
            let metadata = fs::symlink_metadata(&temporary)
                .context("failed to inspect /tmp runtime fallback")?;
            let mode = metadata.permissions().mode();
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_dir()
                || metadata.uid() != 0
                || mode & 0o1000 == 0
            {
                bail!("/tmp is not a root-owned sticky directory; refusing runtime fallback");
            }
            temporary
        }
    };
    let directory = parent.join(format!("maco-runtime-{uid}"));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to create private runtime {}", directory.display())
            })
        }
    }
    validate_private_unix_directory(&directory, uid)?;
    Ok(directory)
}

#[cfg(unix)]
fn validate_private_unix_directory(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private runtime {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!(
            "private runtime {} is not an owner-only real directory",
            path.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_temp_path() -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetTempPathW(buffer_length: u32, buffer: *mut u16) -> u32;
    }

    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: The buffer is writable for its declared length and the returned
    // length is checked before constructing the Windows path.
    let length = unsafe { GetTempPathW(buffer.len() as u32, buffer.as_mut_ptr()) };
    if length == 0 || length as usize >= buffer.len() {
        bail!("Windows GetTempPathW failed or returned an oversized path");
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

fn format_blockers(blockers: &[ApplyBlocker]) -> String {
    blockers
        .iter()
        .map(|blocker| blocker_label(*blocker))
        .collect::<Vec<_>>()
        .join(", ")
}

fn blocker_label(blocker: ApplyBlocker) -> &'static str {
    match blocker {
        ApplyBlocker::DirtyPrimary => "dirty_primary",
        ApplyBlocker::StaleBase => "stale_base",
        ApplyBlocker::PrimaryStateChanged => "primary_state_changed",
        ApplyBlocker::ApplyCheckFailed => "apply_check_failed",
        ApplyBlocker::ExcludedReference => "excluded_reference",
        ApplyBlocker::UnclaimedEdits => "unclaimed_edits",
        ApplyBlocker::ValidationMissing => "validation_missing",
        ApplyBlocker::ValidationNotRun => "validation_not_run",
        ApplyBlocker::ValidationSkipped => "validation_skipped",
        ApplyBlocker::ValidationFailed => "validation_failed",
    }
}

fn git_stderr_text(output: &GitCommandOutput) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn merge_path_sets(left: &[PathBuf], right: &[PathBuf]) -> Vec<PathBuf> {
    left.iter()
        .chain(right.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn parse_git_apply_error_paths(stderr: &str) -> Vec<PathBuf> {
    let mut paths = BTreeSet::new();
    for line in stderr.lines().map(str::trim) {
        if let Some(path) = parse_patch_failed_path(line) {
            paths.insert(path);
            continue;
        }
        if let Some(path) = parse_error_suffix_path(line) {
            paths.insert(path);
            continue;
        }
        if let Some(path) = parse_quoted_error_path(line, "error: invalid path ") {
            paths.insert(path);
        }
    }
    paths.into_iter().collect()
}

fn parse_patch_failed_path(line: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix("error: patch failed: ")?;
    let (path, line_number) = rest.rsplit_once(':')?;
    if line_number.chars().all(|c| c.is_ascii_digit()) && !path.is_empty() {
        Some(PathBuf::from(path))
    } else {
        None
    }
}

fn parse_error_suffix_path(line: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix("error: ")?;
    const SUFFIXES: [&str; 8] = [
        ": patch does not apply",
        ": already exists in working directory",
        ": already exists in index",
        ": does not exist in index",
        ": No such file or directory",
        ": does not match index",
        ": cannot checkout",
        ": needs merge",
    ];
    SUFFIXES
        .iter()
        .find_map(|suffix| rest.strip_suffix(suffix))
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

fn parse_quoted_error_path(line: &str, prefix: &str) -> Option<PathBuf> {
    let rest = line.strip_prefix(prefix)?;
    let path = rest.strip_prefix('\'')?.strip_suffix('\'')?;
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn validation_binding_from_json(value: &Value) -> Result<Option<CandidateValidationBinding>> {
    let Some(binding) = value.get("validation_binding") else {
        return Ok(None);
    };
    let binding: CandidateValidationBinding = serde_json::from_value(binding.clone())
        .context("validation_binding must match the candidate validation binding schema")?;
    binding.canonicalized().map(Some)
}

fn validation_report_from_json(value: &Value) -> Result<ValidationReport> {
    let object = value
        .as_object()
        .context("validation report must be an object")?;
    let name = ["name", "command", "id"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .unwrap_or("validation")
        .to_string();
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .map(parse_validation_status)
        .transpose()?
        .unwrap_or(ValidationStatus::NotRun);
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| object.get("error").and_then(Value::as_str))
        .or_else(|| {
            object
                .get("stderr")
                .and_then(|stderr| stderr.get("text"))
                .and_then(Value::as_str)
        })
        .filter(|message| !message.is_empty())
        .map(str::to_string);
    let paths = validation_paths_from_json(value)?;

    Ok(ValidationReport {
        name,
        status,
        message,
        paths,
    })
}

fn parse_validation_status(value: &str) -> Result<ValidationStatus> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "not_run" | "not-run" | "pending" => Ok(ValidationStatus::NotRun),
        "passed" | "pass" | "succeeded" | "success" => Ok(ValidationStatus::Passed),
        "failed" | "fail" | "failure" => Ok(ValidationStatus::Failed),
        "skipped" | "skip" => Ok(ValidationStatus::Skipped),
        other => bail!("unknown validation status '{other}'"),
    }
}

fn validation_paths_from_json(value: &Value) -> Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::new();
    if let Some(path) = value.get("path").and_then(Value::as_str) {
        paths.insert(PathBuf::from(path));
    }
    if let Some(items) = value.get("paths").and_then(Value::as_array) {
        for item in items {
            let path = item
                .as_str()
                .context("validation report paths must be strings")?;
            paths.insert(PathBuf::from(path));
        }
    }

    Ok(paths.into_iter().collect())
}

fn sort_validation_reports(reports: &mut [ValidationReport]) {
    reports.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.paths.cmp(&right.paths))
            .then_with(|| left.message.cmp(&right.message))
    });
}
