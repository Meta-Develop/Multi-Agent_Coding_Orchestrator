fn preflight_tee(
    label: &str,
    stream: &'static str,
    path: &Path,
    reject_existing: bool,
) -> Result<TeePreflight, ProcessRunError> {
    let mut create_options = OpenOptions::new();
    create_options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        create_options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        create_options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let create_result = create_options.open(path);
    let (file, created) = match create_result {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if reject_existing {
                return Err(ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream,
                    path: path.to_path_buf(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "required confinement refuses an existing tee target",
                    ),
                });
            }
            let mut existing_options = OpenOptions::new();
            existing_options.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                existing_options
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::OpenOptionsExt;
                use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
                existing_options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            let file = existing_options
                .open(path)
                .map_err(|source| ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream,
                    path: path.to_path_buf(),
                    source,
                })?;
            (file, false)
        }
        Err(source) => {
            return Err(ProcessRunError::OpenTee {
                label: label.to_string(),
                stream,
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let mut created_guard = created.then(|| CreatedTeeGuard {
        file: &file,
        path,
        armed: true,
    });

    #[cfg(unix)]
    if created {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|source| ProcessRunError::OpenTee {
                label: label.to_string(),
                stream,
                path: path.to_path_buf(),
                source,
            })?;
    }
    #[cfg(test)]
    if created && env::var_os("MACO_TEST_FAIL_NEW_TEE_PREFLIGHT").is_some() {
        return Err(ProcessRunError::OpenTee {
            label: label.to_string(),
            stream,
            path: path.to_path_buf(),
            source: std::io::Error::other("synthetic new tee preflight failure"),
        });
    }
    let identity_matches =
        tee_path_matches_file(path, &file).map_err(|source| ProcessRunError::OpenTee {
            label: label.to_string(),
            stream,
            path: path.to_path_buf(),
            source,
        })?;
    if !identity_matches {
        return Err(ProcessRunError::OpenTee {
            label: label.to_string(),
            stream,
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tee target must be a regular file and may not be a symlink",
            ),
        });
    }
    if let Some(guard) = created_guard.as_mut() {
        guard.disarm();
    }
    drop(created_guard);

    Ok(TeePreflight {
        file,
        path: path.to_path_buf(),
        created,
    })
}

fn rollback_created_tee(tee: Option<TeePreflight>) {
    let Some(tee) = tee else {
        return;
    };
    let created = tee.created;
    let path = tee.path.clone();
    let matches = created && tee_path_matches_file(&path, &tee.file).unwrap_or(false);
    drop(tee);
    if matches {
        let _ = fs::remove_file(path);
    }
}

#[cfg(unix)]
fn tee_path_matches_file(path: &Path, file: &File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let path_metadata = fs::symlink_metadata(path)?;
    let file_metadata = file.metadata()?;
    Ok(path_metadata.file_type().is_file()
        && file_metadata.file_type().is_file()
        && path_metadata.dev() == file_metadata.dev()
        && path_metadata.ino() == file_metadata.ino())
}

#[cfg(target_os = "windows")]
fn tee_path_matches_file(path: &Path, file: &File) -> std::io::Result<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let path_file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let path_identity = windows_file_identity(&path_file)?;
    let file_identity = windows_file_identity(file)?;
    Ok(path_identity.2 & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && file_identity.2 & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && path_identity.0 == file_identity.0
        && path_identity.1 == file_identity.1)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn tee_path_matches_file(path: &Path, file: &File) -> std::io::Result<bool> {
    Ok(fs::symlink_metadata(path)?.file_type().is_file() && file.metadata()?.file_type().is_file())
}

#[cfg(unix)]
fn tee_files_are_same(left: &TeePreflight, right: &TeePreflight) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let left = left.file.metadata()?;
    let right = right.file.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(target_os = "windows")]
fn tee_files_are_same(left: &TeePreflight, right: &TeePreflight) -> std::io::Result<bool> {
    let left = windows_file_identity(&left.file)?;
    let right = windows_file_identity(&right.file)?;
    Ok(left.0 == right.0 && left.1 == right.1)
}

#[cfg(target_os = "windows")]
fn windows_file_identity(file: &File) -> std::io::Result<(u32, u64, u32)> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: `information` points to writable storage and the borrowed file handle remains valid
    // for the duration of this call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr()) }
        == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((
        information.dwVolumeSerialNumber,
        index,
        information.dwFileAttributes,
    ))
}

#[cfg(not(any(unix, target_os = "windows")))]
fn tee_files_are_same(left: &TeePreflight, right: &TeePreflight) -> std::io::Result<bool> {
    Ok(left.path.canonicalize()? == right.path.canonicalize()?)
}

struct TeeBackup {
    file: Option<File>,
    path: PathBuf,
}

impl TeeBackup {
    fn create(source_file: &File, source_path: &Path) -> std::io::Result<Self> {
        let mut source = source_file.try_clone()?;
        source.seek(SeekFrom::Start(0))?;
        for _ in 0..32 {
            let id = NEXT_TEE_BACKUP_ID.fetch_add(1, Ordering::Relaxed);
            let directory = source_path.parent().unwrap_or_else(|| Path::new("."));
            let path = directory.join(format!(".maco-tee-backup-{}-{id}.tmp", std::process::id()));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    let prepared = std::io::copy(&mut source, &mut file)
                        .and_then(|_| file.sync_all())
                        .and_then(|_| source.seek(SeekFrom::Start(0)))
                        .and_then(|_| file.seek(SeekFrom::Start(0)))
                        .map(|_| ());
                    if let Err(error) = prepared {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok(Self {
                        file: Some(file),
                        path,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate a unique tee rollback file",
        ))
    }

    fn restore(&self, destination: &mut File) -> std::io::Result<()> {
        #[cfg(test)]
        if env::var_os("MACO_TEST_FAIL_TEE_RESTORE").is_some() {
            return Err(std::io::Error::other(
                "synthetic tee backup restore failure",
            ));
        }
        let mut source = self
            .file
            .as_ref()
            .ok_or_else(|| std::io::Error::other("tee rollback file was already closed"))?
            .try_clone()?;
        source.seek(SeekFrom::Start(0))?;
        destination.set_len(0)?;
        destination.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut source, destination)?;
        destination.sync_all()?;
        destination.seek(SeekFrom::Start(0)).map(|_| ())
    }
}

impl Drop for TeeBackup {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

struct TeeWriter {
    sink: TeeSink,
    #[cfg(unix)]
    helper: TeeHelper,
    path: PathBuf,
}

impl TeeWriter {
    fn start(file: File, path: PathBuf, max_bytes: usize) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let (helper, input) = TeeHelper::start(file, &path)?;
            Ok(Self {
                sink: TeeSink {
                    input,
                    remaining: max_bytes,
                    limit_reported: false,
                },
                helper,
                path,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {
                sink: TeeSink {
                    file,
                    remaining: max_bytes,
                    limit_reported: false,
                },
                path,
            })
        }
    }

    fn split(self) -> (TeeSink, Option<TeeHelperHandle>, PathBuf) {
        #[cfg(unix)]
        {
            let helper = TeeHelperHandle(self.helper);
            (self.sink, Some(helper), self.path)
        }

        #[cfg(not(unix))]
        {
            (self.sink, None, self.path)
        }
    }
}

struct TeeSink {
    #[cfg(unix)]
    input: ChildStdin,
    #[cfg(not(unix))]
    file: File,
    remaining: usize,
    limit_reported: bool,
}

impl TeeSink {
    /// Returns `true` once when bytes were discarded because the configured tee cap was reached.
    fn write_all_cancellable(
        &mut self,
        bytes: &[u8],
        cancel: &AtomicBool,
    ) -> std::io::Result<bool> {
        let accepted = bytes.len().min(self.remaining);
        let bytes_to_write = &bytes[..accepted];
        self.remaining -= accepted;
        let exceeded = accepted < bytes.len() && !self.limit_reported;
        if exceeded {
            self.limit_reported = true;
        }
        #[cfg(unix)]
        {
            let mut written = 0;
            while written < bytes_to_write.len() {
                if cancel.load(Ordering::Acquire) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "tee write cancelled",
                    ));
                }
                match self.input.write(&bytes_to_write[written..]) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "tee helper input returned a zero-length write",
                        ));
                    }
                    Ok(count) => written += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(IO_CANCEL_POLL_INTERVAL);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            Ok(exceeded)
        }

        #[cfg(not(unix))]
        {
            self.file.write_all(bytes_to_write).map(|()| exceeded)
        }
    }
}

struct TeeHelperHandle(#[cfg(unix)] TeeHelper, #[cfg(not(unix))] ());

impl TeeHelperHandle {
    fn finish(self, label: &str, stream: &str) -> Option<String> {
        #[cfg(unix)]
        {
            self.0.finish(label, stream)
        }
        #[cfg(not(unix))]
        {
            let _ = (self, label, stream);
            None
        }
    }
}

#[cfg(unix)]
struct TeeHelper {
    child: Child,
    path: PathBuf,
    reaped: bool,
}

#[cfg(unix)]
impl TeeHelper {
    fn start(file: File, path: &Path) -> std::io::Result<(Self, ChildStdin)> {
        use std::os::unix::process::CommandExt;

        let cat = find_trusted_unix_executable(
            "cat",
            &["/bin/cat", "/usr/bin/cat", "/run/current-system/sw/bin/cat"],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "tee capture requires a root-owned, non-writable cat helper",
            )
        })?;
        let mut command = Command::new(cat);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::from(file))
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = command.spawn()?;
        let input = match child.stdin.take() {
            Some(input) => input,
            None => {
                let cleanup = rollback_tee_helper_start(&mut child, path);
                return Err(std::io::Error::other(format!(
                    "failed to open tee helper stdin{cleanup}"
                )));
            }
        };
        if let Err(error) = configure_cancellable_io(&input) {
            drop(input);
            let cleanup = rollback_tee_helper_start(&mut child, path);
            return Err(std::io::Error::new(
                error.kind(),
                format!("failed to configure tee helper stdin: {error}{cleanup}"),
            ));
        }
        Ok((
            Self {
                child,
                path: path.to_path_buf(),
                reaped: false,
            },
            input,
        ))
    }

    fn finish(mut self, label: &str, stream: &str) -> Option<String> {
        let deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
        let mut error = None;
        let status = match wait_for_exit_until(&mut self.child, deadline) {
            Ok(Some(status)) => Some(status),
            Ok(None) => {
                error = Some(format!(
                    "{label} {stream} tee helper for {} did not finish within {} ms",
                    self.path.display(),
                    EXIT_AND_DRAIN_GRACE.as_millis()
                ));
                error = append_error(
                    error,
                    terminate_unix_process_group(&mut self.child, false, label),
                );
                match wait_for_exit_until(&mut self.child, Instant::now() + EXIT_AND_DRAIN_GRACE) {
                    Ok(Some(status)) => Some(status),
                    Ok(None) => fail_closed_stuck_owner(&format!(
                        "{label} {stream} tee helper for {}",
                        self.path.display()
                    )),
                    Err(wait_error) => {
                        error = append_error(
                            error,
                            Some(format!("failed to reap tee helper: {wait_error}")),
                        );
                        match self.child.try_wait() {
                            Ok(Some(status)) => Some(status),
                            _ => fail_closed_stuck_owner(&format!(
                                "{label} {stream} tee helper for {}",
                                self.path.display()
                            )),
                        }
                    }
                }
            }
            Err(wait_error) => {
                error = Some(format!("failed to wait for tee helper: {wait_error}"));
                let _ = terminate_unix_process_group(&mut self.child, false, label);
                match wait_for_exit_until(&mut self.child, Instant::now() + EXIT_AND_DRAIN_GRACE) {
                    Ok(Some(status)) => Some(status),
                    _ => fail_closed_stuck_owner(&format!(
                        "{label} {stream} tee helper for {}",
                        self.path.display()
                    )),
                }
            }
        };
        self.reaped = true;
        if status.is_some_and(|status| !status.success()) {
            error = append_error(
                error,
                Some(format!(
                    "{label} {stream} tee helper for {} exited unsuccessfully",
                    self.path.display()
                )),
            );
        }
        error
    }
}

#[cfg(unix)]
fn rollback_tee_helper_start(child: &mut Child, path: &Path) -> String {
    let error = terminate_unix_process_group(child, false, "tee helper startup rollback");
    match wait_for_exit_until(child, Instant::now() + EXIT_AND_DRAIN_GRACE) {
        Ok(Some(_)) => error
            .map(|error| format!("; cleanup diagnostic: {error}"))
            .unwrap_or_default(),
        Ok(None) => fail_closed_stuck_owner(&format!(
            "tee helper for {} during startup rollback",
            path.display()
        )),
        Err(wait_error) => match child.try_wait() {
            Ok(Some(_)) => format!("; cleanup wait diagnostic: {wait_error}"),
            _ => fail_closed_stuck_owner(&format!(
                "tee helper for {} during startup rollback",
                path.display()
            )),
        },
    }
}

#[cfg(unix)]
impl Drop for TeeHelper {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = terminate_unix_process_group(&mut self.child, false, "tee helper drop");
            if !matches!(
                wait_for_exit_until(&mut self.child, Instant::now() + EXIT_AND_DRAIN_GRACE),
                Ok(Some(_))
            ) {
                fail_closed_stuck_owner(&format!(
                    "tee helper for {} during drop",
                    self.path.display()
                ));
            }
        }
        self.reaped = true;
    }
}

fn fail_closed_stuck_owner(label: &str) -> ! {
    eprintln!(
        "fatal: {label} remained live past its bounded cleanup deadline; aborting rather than detaching owned execution"
    );
    std::process::abort()
}

fn stamp_agent_lifecycle_environment(
    environment: &mut EnvironmentMode,
    metadata: &AgentLaunchMetadata,
) {
    if matches!(environment, EnvironmentMode::Inherit) {
        *environment = EnvironmentMode::InheritAndSet(BTreeMap::new());
    }
    let values = match environment {
        EnvironmentMode::InheritAndSet(values) | EnvironmentMode::ClearAndSet(values) => values,
        EnvironmentMode::Inherit => return,
    };
    values.insert(MACO_RUN_ID_ENV.to_string(), metadata.run_id().to_string());
    values.insert(MACO_TASK_ID_ENV.to_string(), metadata.task_id().to_string());
}

fn configure_environment(command: &mut Command, environment: &EnvironmentMode) {
    match environment {
        EnvironmentMode::Inherit => {}
        EnvironmentMode::InheritAndSet(values) => {
            command.envs(values);
        }
        EnvironmentMode::ClearAndSet(values) => {
            command.env_clear().envs(values);
        }
    }
}

fn configure_stdin(command: &mut Command, stdin: &StdinMode) {
    match stdin {
        StdinMode::Inherit => {
            command.stdin(Stdio::inherit());
        }
        StdinMode::Null => {
            command.stdin(Stdio::null());
        }
        StdinMode::Bytes(_) | StdinMode::Interactive => {
            command.stdin(Stdio::piped());
        }
    }
}

#[cfg(target_os = "windows")]
const WINDOWS_PROCESS_CREATION_FLAGS: u32 = 0x0000_0200 | 0x0000_0004;

include!("containment_platform.rs");

struct PreparedProcessTree {
    backend: PreparedContainmentBackend,
    side_effects: SideEffectConfinementEvidence,
}

enum PreparedContainmentBackend {
    #[cfg(target_os = "linux")]
    Systemd(Box<SystemdUnit>),
    #[cfg(target_os = "windows")]
    WindowsJob,
    #[cfg(unix)]
    UnixProcessGroup,
    #[cfg(not(any(unix, target_os = "windows")))]
    DirectChild,
}

impl PreparedProcessTree {
    fn prepare(
        policy: ContainmentPolicy,
        side_effect_profile: &SideEffectConfinementProfile,
        label: &str,
        command: &str,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> Result<Self, ProcessRunError> {
        let unavailable = |source| ProcessRunError::ContainmentUnavailable {
            label: label.to_string(),
            command: command.to_string(),
            source,
        };
        if policy == ContainmentPolicy::TrustedBestEffort
            && !matches!(
                side_effect_profile,
                SideEffectConfinementProfile::TrustedCompatibility
            )
        {
            return Err(unavailable(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TrustedBestEffort process ownership cannot claim a strict side-effect profile",
            )));
        }
        let side_effects = if matches!(
            side_effect_profile,
            SideEffectConfinementProfile::TrustedCompatibility
        ) {
            SideEffectConfinementEvidence::TrustedBestEffort(
                SideEffectConfinementProfileKind::TrustedCompatibility,
            )
        } else {
            SideEffectConfinementEvidence::Unverified(side_effect_profile.kind())
        };
        ensure_not_cancelled(cancellation, label, command, "containment slot acquisition")?;
        match policy {
            ContainmentPolicy::Required => {
                let backend = select_required_containment_backend(
                    RequiredContainmentPlatform::current(),
                    label,
                    command,
                )?;
                match backend {
                    ReviewedRequiredContainmentBackend::LinuxSystemdCgroupV2 => {
                        #[cfg(target_os = "linux")]
                        {
                            match SystemdUnit::prepare(operation_deadline, cancellation) {
                                Ok(unit) => Ok(Self {
                                    backend: PreparedContainmentBackend::Systemd(Box::new(unit)),
                                    side_effects,
                                }),
                                Err(_source) if cancellation.is_cancelled() => {
                                    Err(ProcessRunError::Cancelled {
                                        label: label.to_string(),
                                        command: command.to_string(),
                                        phase: "containment slot acquisition",
                                        evidence: None,
                                    })
                                }
                                Err(source)
                                    if operation_deadline
                                        .is_some_and(|deadline| Instant::now() >= deadline) =>
                                {
                                    Err(setup_timeout_error(
                                        label,
                                        command,
                                        "strict containment slot acquisition",
                                        source.to_string(),
                                    ))
                                }
                                Err(source) => Err(containment_setup_error(
                                    label.to_string(),
                                    command.to_string(),
                                    source,
                                )),
                            }
                        }
                        #[cfg(not(target_os = "linux"))]
                        {
                            Err(unavailable(
                                RequiredContainmentRefusal::ReviewedBackendPlatformMismatch
                                    .into_io_error(),
                            ))
                        }
                    }
                }
            }
            ContainmentPolicy::TrustedBestEffort => {
                #[cfg(unix)]
                {
                    Ok(Self {
                        backend: PreparedContainmentBackend::UnixProcessGroup,
                        side_effects,
                    })
                }
                #[cfg(target_os = "windows")]
                {
                    Ok(Self {
                        backend: PreparedContainmentBackend::WindowsJob,
                        side_effects,
                    })
                }
                #[cfg(not(any(unix, target_os = "windows")))]
                {
                    Ok(Self {
                        backend: PreparedContainmentBackend::DirectChild,
                        side_effects,
                    })
                }
            }
        }
    }

    fn build_command(&mut self, spec: &ProcessSpec) -> std::io::Result<Command> {
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            PreparedContainmentBackend::Systemd(unit) => unit.build_command(spec),
            #[cfg(target_os = "windows")]
            PreparedContainmentBackend::WindowsJob => {
                if spec.private_runtime_home || spec.private_runtime_codex_home {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "private runtime HOME requires the strict Linux systemd backend",
                    ));
                }
                use std::os::windows::process::CommandExt;
                let mut command = spec.command.build();
                command.creation_flags(WINDOWS_PROCESS_CREATION_FLAGS);
                command.current_dir(&spec.current_dir);
                configure_environment(&mut command, &spec.environment);
                Ok(command)
            }
            #[cfg(unix)]
            PreparedContainmentBackend::UnixProcessGroup => {
                if spec.private_runtime_home || spec.private_runtime_codex_home {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "private runtime HOME requires the strict Linux systemd backend",
                    ));
                }
                use std::os::unix::process::CommandExt;
                let mut command = spec.command.build();
                command.process_group(0);
                command.current_dir(&spec.current_dir);
                configure_environment(&mut command, &spec.environment);
                Ok(command)
            }
            #[cfg(not(any(unix, target_os = "windows")))]
            PreparedContainmentBackend::DirectChild => {
                if spec.private_runtime_home || spec.private_runtime_codex_home {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "private runtime HOME requires the strict Linux systemd backend",
                    ));
                }
                let mut command = spec.command.build();
                command.current_dir(&spec.current_dir);
                configure_environment(&mut command, &spec.environment);
                Ok(command)
            }
        }
    }

    fn attach(
        self,
        child: &mut Child,
        label: &str,
        command: &str,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> Result<AttachedProcessTree, ProcessRunError> {
        match self.backend {
            #[cfg(target_os = "linux")]
            PreparedContainmentBackend::Systemd(mut unit) => {
                unit.launcher_spawned = true;
                if let Err(source) = unit.confirm_attached(child, operation_deadline, cancellation)
                {
                    if let Err(error) = unit.rollback_startup(label) {
                        fail_closed_stuck_owner(&format!(
                            "{label} systemd containment startup rollback: {error}"
                        ));
                    }
                    return if cancellation.is_cancelled() {
                        Err(ProcessRunError::Cancelled {
                            label: label.to_string(),
                            command: command.to_string(),
                            phase: "strict containment attachment gate",
                            evidence: Some(Box::new(ProcessFailureEvidence {
                                stdout: CapturedBytes::default(),
                                stderr: CapturedBytes::default(),
                                process_tree: ProcessTreeEvidence::VerifiedEmpty(
                                    ContainmentBackend::SystemdUserService,
                                ),
                                side_effects: self.side_effects,
                                process_error: Some(format!(
                                    "{label} was cancelled by its run supervisor"
                                )),
                                stdin_error: None,
                            })),
                        })
                    } else if environment_failure_from_source(&source).is_some() {
                        Err(process_ownership_error(
                            label.to_string(),
                            command.to_string(),
                            source,
                        ))
                    } else if operation_deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        Err(setup_timeout_error(
                            label,
                            command,
                            "strict containment start gate",
                            source.to_string(),
                        ))
                    } else {
                        Err(process_ownership_error(
                            label.to_string(),
                            command.to_string(),
                            source,
                        ))
                    };
                }
                let side_effects = unit.side_effect_evidence();
                Ok(AttachedProcessTree {
                    backend: ProcessTreeBackend::Systemd(unit),
                    side_effects,
                })
            }
            #[cfg(target_os = "windows")]
            PreparedContainmentBackend::WindowsJob => {
                let job = WindowsJob::create_and_assign(child).map_err(|source| {
                    ProcessRunError::ProcessOwnership {
                        label: label.to_string(),
                        command: command.to_string(),
                        source,
                    }
                })?;
                Ok(AttachedProcessTree {
                    backend: ProcessTreeBackend::WindowsJob(job),
                    side_effects: self.side_effects,
                })
            }
            #[cfg(unix)]
            PreparedContainmentBackend::UnixProcessGroup => Ok(AttachedProcessTree {
                backend: ProcessTreeBackend::UnixProcessGroup,
                side_effects: self.side_effects,
            }),
            #[cfg(not(any(unix, target_os = "windows")))]
            PreparedContainmentBackend::DirectChild => Ok(AttachedProcessTree {
                backend: ProcessTreeBackend::DirectChild,
                side_effects: self.side_effects,
            }),
        }
    }
}

struct AttachedProcessTree {
    backend: ProcessTreeBackend,
    side_effects: SideEffectConfinementEvidence,
}

impl AttachedProcessTree {
    fn agent_lifecycle_pid(
        &mut self,
        child: &mut Child,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<u32> {
        if cancellation.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "agent lifecycle PID capture was cancelled",
            ));
        }
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            ProcessTreeBackend::Systemd(unit) => {
                unit.target_pid(child, operation_deadline, cancellation)
            }
            #[cfg(unix)]
            ProcessTreeBackend::UnixProcessGroup => Ok(child.id()),
            #[cfg(target_os = "windows")]
            ProcessTreeBackend::WindowsJob(_) => Ok(child.id()),
            #[cfg(not(any(unix, target_os = "windows")))]
            ProcessTreeBackend::DirectChild => Ok(child.id()),
        }
    }

    fn cleanup(&mut self, child: &mut Child, label: &str, context: &str) -> TreeCleanup {
        cleanup_process_tree_backend(
            &mut self.backend,
            self.side_effects,
            child,
            false,
            label,
            context,
        )
    }

    fn release(
        mut self,
        child: &mut Child,
        label: &str,
        command: &str,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> Result<ProcessTree, ProcessRunError> {
        if cancellation.is_cancelled() {
            let cleanup = self.cleanup(child, label, "containment start-gate cancellation");
            return Err(ProcessRunError::Cancelled {
                label: label.to_string(),
                command: command.to_string(),
                phase: "containment start gate",
                evidence: Some(Box::new(ProcessFailureEvidence {
                    stdout: CapturedBytes::default(),
                    stderr: CapturedBytes::default(),
                    process_tree: cleanup.process_tree,
                    side_effects: cleanup.side_effects,
                    process_error: append_error(
                        Some(format!("{label} was cancelled by its run supervisor")),
                        cleanup.error,
                    ),
                    stdin_error: None,
                })),
            });
        }
        match &mut self.backend {
            #[cfg(target_os = "linux")]
            ProcessTreeBackend::Systemd(unit) => {
                if let Err(source) =
                    unit.release_start_gate(child, operation_deadline, cancellation)
                {
                    if let Err(error) = unit.rollback_startup(label) {
                        fail_closed_stuck_owner(&format!(
                            "{label} systemd containment start-gate rollback: {error}"
                        ));
                    }
                    return if cancellation.is_cancelled() {
                        Err(ProcessRunError::Cancelled {
                            label: label.to_string(),
                            command: command.to_string(),
                            phase: "strict containment start gate",
                            evidence: Some(Box::new(ProcessFailureEvidence {
                                stdout: CapturedBytes::default(),
                                stderr: CapturedBytes::default(),
                                process_tree: ProcessTreeEvidence::VerifiedEmpty(
                                    ContainmentBackend::SystemdUserService,
                                ),
                                side_effects: self.side_effects,
                                process_error: Some(format!(
                                    "{label} was cancelled by its run supervisor"
                                )),
                                stdin_error: None,
                            })),
                        })
                    } else if environment_failure_from_source(&source).is_some() {
                        Err(process_ownership_error(
                            label.to_string(),
                            command.to_string(),
                            source,
                        ))
                    } else if operation_deadline.is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        Err(setup_timeout_error(
                            label,
                            command,
                            "strict containment start gate",
                            source.to_string(),
                        ))
                    } else {
                        Err(process_ownership_error(
                            label.to_string(),
                            command.to_string(),
                            source,
                        ))
                    };
                }
            }
            #[cfg(target_os = "windows")]
            ProcessTreeBackend::WindowsJob(job) => {
                if operation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    let cleanup = job.cleanup(label, "startup timeout rollback", self.side_effects);
                    if cleanup.error.is_some() || !cleanup.process_tree.is_verified_empty() {
                        fail_closed_stuck_owner(&format!(
                            "{label} Windows Job Object startup-timeout rollback: {}",
                            cleanup.error.unwrap_or_else(|| {
                                "job did not report verified-empty containment".to_string()
                            })
                        ));
                    }
                    return Err(setup_timeout_error(
                        label,
                        command,
                        "Windows Job Object attachment",
                        "the total operation deadline expired before the suspended child was resumed",
                    ));
                }
                if let Err(source) = resume_suspended_child(child) {
                    let cleanup = job.cleanup(label, "startup rollback", self.side_effects);
                    if cleanup.error.is_some() || !cleanup.process_tree.is_verified_empty() {
                        fail_closed_stuck_owner(&format!(
                            "{label} Windows Job Object resume rollback: {}",
                            cleanup.error.unwrap_or_else(|| {
                                "job did not report verified-empty containment".to_string()
                            })
                        ));
                    }
                    return Err(ProcessRunError::ProcessOwnership {
                        label: label.to_string(),
                        command: command.to_string(),
                        source,
                    });
                }
            }
            #[cfg(unix)]
            ProcessTreeBackend::UnixProcessGroup => {}
            #[cfg(not(any(unix, target_os = "windows")))]
            ProcessTreeBackend::DirectChild => {}
        }
        Ok(ProcessTree {
            backend: self.backend,
            side_effects: self.side_effects,
        })
    }
}

struct ProcessTree {
    backend: ProcessTreeBackend,
    side_effects: SideEffectConfinementEvidence,
}

enum ProcessTreeBackend {
    #[cfg(target_os = "linux")]
    Systemd(Box<SystemdUnit>),
    #[cfg(target_os = "windows")]
    WindowsJob(WindowsJob),
    #[cfg(unix)]
    UnixProcessGroup,
    #[cfg(not(any(unix, target_os = "windows")))]
    DirectChild,
}

struct TreeCleanup {
    error: Option<String>,
    process_tree: ProcessTreeEvidence,
    side_effects: SideEffectConfinementEvidence,
}

impl ProcessTree {
    fn cleanup(
        &mut self,
        child: &mut Child,
        child_already_exited: bool,
        label: &str,
        context: &str,
    ) -> TreeCleanup {
        cleanup_process_tree_backend(
            &mut self.backend,
            self.side_effects,
            child,
            child_already_exited,
            label,
            context,
        )
    }
}

fn cleanup_process_tree_backend(
    backend: &mut ProcessTreeBackend,
    side_effects: SideEffectConfinementEvidence,
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
    context: &str,
) -> TreeCleanup {
    match backend {
        #[cfg(target_os = "linux")]
        ProcessTreeBackend::Systemd(unit) => {
            let mut cleanup = unit.cleanup(child, label, context);
            cleanup.side_effects = side_effects;
            cleanup
        }
        #[cfg(target_os = "windows")]
        ProcessTreeBackend::WindowsJob(job) => job.cleanup(label, context, side_effects),
        #[cfg(unix)]
        ProcessTreeBackend::UnixProcessGroup => TreeCleanup {
            error: terminate_unix_process_group(child, child_already_exited, label),
            process_tree: ProcessTreeEvidence::TrustedBestEffort(
                ContainmentBackend::UnixProcessGroup,
            ),
            side_effects,
        },
        #[cfg(not(any(unix, target_os = "windows")))]
        ProcessTreeBackend::DirectChild => TreeCleanup {
            error: if child_already_exited {
                None
            } else {
                child
                    .kill()
                    .err()
                    .map(|error| format!("{label} {context} direct process kill failed: {error}"))
            },
            process_tree: ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::DirectChild),
            side_effects,
        },
    }
}

#[cfg(target_os = "linux")]
struct ResolvedSystemdSandbox {
    kind: SideEffectConfinementProfileKind,
    workspace_root: PathBuf,
    current_dir: PathBuf,
    workspace_access: WorkspaceAccess,
    visible_read_only_roots: Vec<PathBuf>,
    visible_read_only_files: Vec<PathBuf>,
    visible_read_write_roots: Vec<PathBuf>,
    visible_read_write_files: Vec<PathBuf>,
    external_codex_writable_file_capabilities: Vec<ExternalCodexWritableFileCapability>,
    writable_artifact_roots: Vec<PathBuf>,
    hidden_roots: Vec<PathBuf>,
    isolated_host_view: bool,
    resource_limits: ProcessResourceLimits,
    path_identities: Vec<SandboxPathIdentity>,
    mount_checks: Vec<SandboxMountCheck>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct EnvironmentFailureSource {
    failure: EnvironmentFailure,
    target_process_started: bool,
}

#[cfg(target_os = "linux")]
impl fmt::Display for EnvironmentFailureSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.failure, formatter)
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for EnvironmentFailureSource {}

#[cfg(target_os = "linux")]
fn environment_failure_io(
    failure: EnvironmentFailure,
    target_process_started: bool,
) -> std::io::Error {
    std::io::Error::other(EnvironmentFailureSource {
        failure,
        target_process_started,
    })
}

#[cfg(target_os = "linux")]
struct SandboxPathIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SandboxMountAccess {
    ReadOnly,
    ReadWrite,
    PrivateRuntime,
    Inaccessible,
    IsolatedRoot,
}

#[cfg(target_os = "linux")]
struct SandboxMountCheck {
    path: PathBuf,
    device: u64,
    inode: u64,
    access: SandboxMountAccess,
    optional: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxMountInfo {
    mount_id: u64,
    device_major: u64,
    device_minor: u64,
    root: PathBuf,
    mount_point: PathBuf,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SandboxMountRegion {
    visible_path: PathBuf,
    device_major: u64,
    device_minor: u64,
    backing_path: PathBuf,
    access: SandboxMountAccess,
}

#[cfg(target_os = "linux")]
impl ResolvedSystemdSandbox {
    fn explicitly_binds_program(&self, program: &Path) -> bool {
        std::iter::once(&self.workspace_root)
            .chain(self.visible_read_only_roots.iter())
            .chain(self.visible_read_write_roots.iter())
            .chain(self.writable_artifact_roots.iter())
            .any(|root| program.starts_with(root))
            || self
                .visible_read_only_files
                .iter()
                .chain(self.visible_read_write_files.iter())
                .any(|file| program == file)
    }

    fn validate_program_visibility(&self, program: &Path) -> std::io::Result<()> {
        if let Some(hidden_root) = self
            .hidden_roots
            .iter()
            .find(|root| program.starts_with(root))
        {
            return Err(environment_failure_io(
                EnvironmentFailure::sandbox_unavailable(format!(
                    "the sandbox cannot start program {} because sandbox.hidden_roots makes that root inaccessible inside the transient unit: {}; place the executable outside the hidden root before retrying",
                    program.display(),
                    hidden_root.display(),
                )),
                false,
            ));
        }
        let Some(private_tmp_root) = [Path::new("/tmp"), Path::new("/var/tmp")]
            .into_iter()
            .find(|root| program.starts_with(root))
        else {
            return Ok(());
        };
        if self.explicitly_binds_program(program) {
            return Ok(());
        }
        Err(environment_failure_io(
            EnvironmentFailure::sandbox_unavailable(format!(
                "the sandbox cannot start program {} because PrivateTmp=yes replaces that root inside the transient unit: {}; place the executable outside the hidden root before retrying",
                program.display(),
                private_tmp_root.display(),
            )),
            false,
        ))
    }

    fn add_isolated_runtime_file(&mut self, file: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if !self.isolated_host_view {
            return Ok(());
        }
        validate_systemd_path_syntax(file, "isolated runtime helper")?;
        let canonical = fs::canonicalize(file)?;
        if !canonical.starts_with("/nix/store") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "isolated reviewer runtime helper is outside /nix/store",
            ));
        }
        let metadata = fs::metadata(file)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "isolated reviewer runtime helper is not a trusted executable",
            ));
        }
        if self
            .hidden_roots
            .iter()
            .any(|hidden| file.starts_with(hidden) || hidden.starts_with(file))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "isolated reviewer runtime helper overlaps an inaccessible root",
            ));
        }
        if self.visible_read_only_files.contains(&file.to_path_buf()) {
            return Ok(());
        }
        self.visible_read_only_files.push(file.to_path_buf());
        self.visible_read_only_files.sort();
        self.path_identities
            .push(capture_sandbox_path_identity(&canonical)?);
        self.mount_checks.push(SandboxMountCheck {
            path: file.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            access: SandboxMountAccess::ReadOnly,
            optional: false,
        });
        if self.visible_read_only_files.len() > MAX_SANDBOX_PATHS_PER_CLASS
            || self.mount_checks.len() > MAX_SANDBOX_MOUNT_CHECKS
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "isolated reviewer runtime helper vector exceeds its safety bound",
            ));
        }
        Ok(())
    }

    fn add_private_runtime_root(&mut self, root: &Path) -> std::io::Result<()> {
        validate_systemd_path_syntax(root, "private unit runtime root")?;
        if !root.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private unit runtime root must be absolute",
            ));
        }
        if self
            .hidden_roots
            .iter()
            .any(|hidden| root.starts_with(hidden) || hidden.starts_with(root))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private unit runtime root overlaps an inaccessible sandbox root",
            ));
        }
        self.mount_checks.push(SandboxMountCheck {
            path: root.to_path_buf(),
            device: 0,
            inode: 0,
            access: SandboxMountAccess::PrivateRuntime,
            optional: false,
        });
        if self.mount_checks.len() > MAX_SANDBOX_MOUNT_CHECKS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sandbox mount-check vector exceeds its safety bound",
            ));
        }
        Ok(())
    }

    fn verify_path_identities(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        for capability in &self.external_codex_writable_file_capabilities {
            capability.verify_path()?;
        }
        for identity in &self.path_identities {
            let metadata = fs::symlink_metadata(&identity.path)?;
            if metadata.file_type().is_symlink()
                || metadata.dev() != identity.device
                || metadata.ino() != identity.inode
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox path identity changed before target release: {}",
                        identity.path.display()
                    ),
                ));
            }
        }
        self.verify_no_special_entries()?;
        Ok(())
    }

    fn verify_no_special_entries(&self) -> std::io::Result<()> {
        self.verify_mount_alias_conflicts()?;
        let mut roots = vec![(
            self.workspace_root.clone(),
            self.workspace_access == WorkspaceAccess::ReadWrite,
        )];
        roots.extend(
            self.visible_read_write_roots
                .iter()
                .cloned()
                .map(|root| (root, true)),
        );
        roots.extend(
            self.writable_artifact_roots
                .iter()
                .cloned()
                .map(|root| (root, true)),
        );
        roots.sort_by(|left, right| left.0.cmp(&right.0));
        roots.dedup_by(|left, right| {
            if left.0 == right.0 {
                left.1 |= right.1;
                true
            } else {
                false
            }
        });
        let mut minimal_roots: Vec<(PathBuf, bool)> = Vec::new();
        for (root, writable) in roots {
            if let Some((_, ancestor_writable)) = minimal_roots
                .iter()
                .find(|(ancestor, _)| root.starts_with(ancestor))
            {
                if *ancestor_writable || !writable {
                    continue;
                }
            }
            minimal_roots.push((root, writable));
        }
        let mut remaining = MAX_SANDBOX_ENTRY_SCAN;
        let mut writable_links: BTreeMap<(u64, u64), (u64, u64, PathBuf)> = BTreeMap::new();
        for (root, writable) in minimal_roots {
            scan_sandbox_tree(&root, writable, &mut remaining, &mut writable_links)?;
        }
        for (_, (expected, observed, path)) in writable_links {
            if observed < expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "writable sandbox file has a hard-link alias outside the writable roots: {} ({observed}/{expected} links observed)",
                        path.display()
                    ),
                ));
            }
        }
        self.verify_narrow_writable_hardlink_scope()?;
        self.verify_protected_read_only_hardlink_scope()
    }

    fn verify_narrow_writable_hardlink_scope(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        for file in &self.visible_read_write_files {
            let metadata = fs::symlink_metadata(file)?;
            if metadata.nlink() != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "writable sandbox exception file must not have hard-link aliases: {}",
                        file.display()
                    ),
                ));
            }
        }

        let mut roots = self.visible_read_write_roots.clone();
        roots.sort();
        roots.dedup();
        let mut minimal_roots: Vec<PathBuf> = Vec::new();
        for root in roots {
            if !minimal_roots
                .iter()
                .any(|ancestor| root.starts_with(ancestor))
            {
                minimal_roots.push(root);
            }
        }
        let mut remaining = MAX_SANDBOX_ENTRY_SCAN;
        for root in minimal_roots {
            let mut writable_links = BTreeMap::new();
            scan_sandbox_tree(&root, true, &mut remaining, &mut writable_links)?;
            for (_, (expected, observed, path)) in writable_links {
                if observed < expected {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "writable sandbox exception has a hard-link alias outside its exact root: {} ({observed}/{expected} links observed)",
                            path.display()
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn effective_path_access(&self, path: &Path) -> std::io::Result<Option<SandboxMountAccess>> {
        let mut selected: Option<(usize, SandboxMountAccess)> = None;
        let mut consider =
            |boundary: &Path, exact: bool, access: SandboxMountAccess| -> std::io::Result<()> {
                if (exact && path != boundary) || (!exact && !path.starts_with(boundary)) {
                    return Ok(());
                }
                let specificity = boundary.components().count();
                match selected {
                    Some((existing_specificity, existing_access))
                        if existing_specificity == specificity && existing_access != access =>
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "sandbox path has conflicting effective access: {}",
                                path.display()
                            ),
                        ));
                    }
                    Some((existing_specificity, _)) if existing_specificity > specificity => {}
                    _ => selected = Some((specificity, access)),
                }
                Ok(())
            };

        consider(
            &self.workspace_root,
            false,
            match self.workspace_access {
                WorkspaceAccess::ReadOnly => SandboxMountAccess::ReadOnly,
                WorkspaceAccess::ReadWrite => SandboxMountAccess::ReadWrite,
            },
        )?;
        for root in &self.visible_read_only_roots {
            consider(root, false, SandboxMountAccess::ReadOnly)?;
        }
        for file in &self.visible_read_only_files {
            consider(file, true, SandboxMountAccess::ReadOnly)?;
        }
        for root in self
            .visible_read_write_roots
            .iter()
            .chain(&self.writable_artifact_roots)
        {
            consider(root, false, SandboxMountAccess::ReadWrite)?;
        }
        for file in &self.visible_read_write_files {
            consider(file, true, SandboxMountAccess::ReadWrite)?;
        }
        Ok(selected.map(|(_, access)| access))
    }

    fn verify_protected_read_only_hardlink_scope(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let mut protected_roots = self.visible_read_only_roots.clone();
        if self.workspace_access == WorkspaceAccess::ReadOnly {
            protected_roots.push(self.workspace_root.clone());
        }
        minimize_sandbox_roots(&mut protected_roots);

        let mut writable_roots = self.visible_read_write_roots.clone();
        writable_roots.extend(self.writable_artifact_roots.iter().cloned());
        if self.workspace_access == WorkspaceAccess::ReadWrite {
            writable_roots.push(self.workspace_root.clone());
        }
        minimize_sandbox_roots(&mut writable_roots);
        if writable_roots.is_empty() && self.visible_read_write_files.is_empty() {
            return Ok(());
        }

        // Inventory writable files first. A hard-link alias is impossible unless some
        // writable regular file already has nlink>1, so skip walking (possibly huge)
        // disjoint read-only trees such as a whole repository mounted only for Git.
        let mut remaining = MAX_SANDBOX_ENTRY_SCAN;
        let mut writable_multilink_inodes: BTreeMap<(u64, u64), PathBuf> = BTreeMap::new();
        for root in &writable_roots {
            scan_sandbox_regular_files(root, true, &mut remaining, |path, metadata| {
                if self.effective_path_access(path)? == Some(SandboxMountAccess::ReadWrite)
                    && metadata.nlink() > 1
                {
                    writable_multilink_inodes
                        .entry((metadata.dev(), metadata.ino()))
                        .or_insert_with(|| path.to_path_buf());
                }
                Ok(())
            })?;
        }
        for file in &self.visible_read_write_files {
            let metadata = fs::symlink_metadata(file)?;
            if self.effective_path_access(file)? == Some(SandboxMountAccess::ReadWrite)
                && metadata.nlink() > 1
            {
                writable_multilink_inodes
                    .entry((metadata.dev(), metadata.ino()))
                    .or_insert(file.clone());
            }
        }
        if writable_multilink_inodes.is_empty() {
            return Ok(());
        }

        let reject_protected_alias = |path: &Path, metadata: &fs::Metadata| -> std::io::Result<()> {
            if self.effective_path_access(path)? != Some(SandboxMountAccess::ReadOnly) {
                return Ok(());
            }
            if writable_multilink_inodes.contains_key(&(metadata.dev(), metadata.ino())) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "protected read-only sandbox file has a writable hard-link alias: {}",
                        path.display()
                    ),
                ));
            }
            Ok(())
        };
        for root in protected_roots {
            scan_sandbox_regular_files(&root, false, &mut remaining, |path, metadata| {
                reject_protected_alias(path, metadata)
            })?;
        }
        for file in &self.visible_read_only_files {
            let metadata = fs::symlink_metadata(file)?;
            reject_protected_alias(file, &metadata)?;
        }
        Ok(())
    }

    fn verify_mount_alias_conflicts(&self) -> std::io::Result<()> {
        let mountinfo = read_sandbox_mountinfo()?;
        verify_sandbox_mount_alias_conflicts(self, &mountinfo)
    }
}

#[cfg(target_os = "linux")]
fn minimize_sandbox_roots(roots: &mut Vec<PathBuf>) {
    roots.sort();
    roots.dedup();
    let mut minimal: Vec<PathBuf> = Vec::new();
    for root in roots.drain(..) {
        if !minimal.iter().any(|ancestor| root.starts_with(ancestor)) {
            minimal.push(root);
        }
    }
    *roots = minimal;
}

#[cfg(target_os = "linux")]
fn scan_sandbox_regular_files(
    root: &Path,
    reject_special_entries: bool,
    remaining: &mut usize,
    mut visit: impl FnMut(&Path, &fs::Metadata) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let root_device = fs::symlink_metadata(root)?.dev();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if *remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "sandbox protected-file scan exceeded the fail-closed {MAX_SANDBOX_ENTRY_SCAN} entry limit"
                ),
            ));
        }
        *remaining -= 1;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "failed to inspect sandbox entry {}: {error}",
                    path.display()
                ),
            )
        })?;
        if metadata.dev() != root_device {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox tree crosses a filesystem or mount boundary: {}",
                    path.display()
                ),
            ));
        }
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to enumerate sandbox directory {}: {error}",
                        path.display()
                    ),
                )
            })? {
                pending.push(entry?.path());
            }
        } else if file_type.is_file() {
            visit(&path, &metadata)?;
        } else if reject_special_entries {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox contains a socket, FIFO, or device node: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn scan_sandbox_tree(
    root: &Path,
    writable: bool,
    remaining: &mut usize,
    writable_links: &mut BTreeMap<(u64, u64), (u64, u64, PathBuf)>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let root_device = fs::symlink_metadata(root)?.dev();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if *remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "sandbox tree scan exceeded the fail-closed {MAX_SANDBOX_ENTRY_SCAN} entry limit"
                ),
            ));
        }
        *remaining -= 1;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "failed to inspect sandbox entry {}: {error}",
                    path.display()
                ),
            )
        })?;
        let file_type = metadata.file_type();
        if metadata.dev() != root_device {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox tree crosses a filesystem or mount boundary: {}",
                    path.display()
                ),
            ));
        }
        if file_type.is_symlink() {
            let target = fs::metadata(&path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "sandbox symlink must resolve to a regular file or directory {}: {error}",
                        path.display()
                    ),
                )
            })?;
            if !target.is_file() && !target.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox symlink resolves to a special file: {}",
                        path.display()
                    ),
                ));
            }
            if target.dev() != root_device {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox symlink crosses a filesystem boundary: {}",
                        path.display()
                    ),
                ));
            }
            continue;
        }
        if file_type.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to enumerate sandbox directory {}: {error}",
                        path.display()
                    ),
                )
            })? {
                pending.push(entry?.path());
            }
            continue;
        }
        if !file_type.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox contains a socket, FIFO, or device node: {}",
                    path.display()
                ),
            ));
        }
        if writable && metadata.nlink() > 1 {
            let entry = writable_links
                .entry((metadata.dev(), metadata.ino()))
                .or_insert_with(|| (metadata.nlink(), 0, path.clone()));
            entry.0 = entry.0.max(metadata.nlink());
            entry.1 = entry.1.saturating_add(1);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_sandbox_mountinfo() -> std::io::Result<Vec<SandboxMountInfo>> {
    let file = File::open("/proc/self/mountinfo")?;
    let mut bytes = Vec::new();
    file.take((MAX_SANDBOX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SANDBOX_MOUNTINFO_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("mountinfo exceeds the fail-closed {MAX_SANDBOX_MOUNTINFO_BYTES} byte limit"),
        ));
    }
    parse_sandbox_mountinfo(&bytes)
}

#[cfg(target_os = "linux")]
fn parse_sandbox_mountinfo(bytes: &[u8]) -> std::io::Result<Vec<SandboxMountInfo>> {
    let mut entries = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_SANDBOX_MOUNTINFO_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "mountinfo line exceeds the fail-closed {MAX_SANDBOX_MOUNTINFO_LINE_BYTES} byte limit"
                ),
            ));
        }
        if entries.len() >= MAX_SANDBOX_MOUNTINFO_ENTRIES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "mountinfo exceeds the fail-closed {MAX_SANDBOX_MOUNTINFO_ENTRIES} entry limit"
                ),
            ));
        }
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mountinfo entry omitted the filesystem separator",
                )
            })?;
        if separator < 6 || separator + 3 >= fields.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mountinfo entry has an invalid field count",
            ));
        }
        let mount_id = parse_mountinfo_u64(fields[0], "mount id")?;
        let _parent_mount_id = parse_mountinfo_u64(fields[1], "parent mount id")?;
        let device = std::str::from_utf8(fields[2]).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mountinfo device identity is not ASCII",
            )
        })?;
        let (device_major, device_minor) = device.split_once(':').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mountinfo device identity omitted ':'",
            )
        })?;
        let device_major = device_major.parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid mountinfo device major: {error}"),
            )
        })?;
        let device_minor = device_minor.parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid mountinfo device minor: {error}"),
            )
        })?;
        let root = decode_mountinfo_path(fields[3], "mount root")?;
        let mount_point = decode_mountinfo_path(fields[4], "mount point")?;
        entries.push(SandboxMountInfo {
            mount_id,
            device_major,
            device_minor,
            root,
            mount_point,
        });
    }
    let mut mount_ids = BTreeSet::new();
    if entries
        .iter()
        .any(|entry| !mount_ids.insert(entry.mount_id))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mountinfo contains duplicate mount ids",
        ));
    }
    if entries.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mountinfo contained no entries",
        ));
    }
    Ok(entries)
}

#[cfg(target_os = "linux")]
fn parse_mountinfo_u64(field: &[u8], label: &str) -> std::io::Result<u64> {
    let text = std::str::from_utf8(field).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("mountinfo {label} is not ASCII"),
        )
    })?;
    text.parse::<u64>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid mountinfo {label}: {error}"),
        )
    })
}

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(field: &[u8], label: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let mut decoded = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        if field[index] != b'\\' {
            decoded.push(field[index]);
            index += 1;
            continue;
        }
        if index + 3 >= field.len()
            || !field[index + 1..=index + 3]
                .iter()
                .all(|byte| matches!(*byte, b'0'..=b'7'))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("mountinfo {label} contains an invalid escape"),
            ));
        }
        let value = (field[index + 1] - b'0') * 64
            + (field[index + 2] - b'0') * 8
            + (field[index + 3] - b'0');
        if !matches!(value, b' ' | b'\t' | b'\n' | b'\\') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("mountinfo {label} contains an unsupported escape"),
            ));
        }
        decoded.push(value);
        index += 4;
    }
    let path = PathBuf::from(OsString::from_vec(decoded));
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("mountinfo {label} is not a normalized absolute path"),
        ));
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn sandbox_mount_backing_region(
    path: &Path,
    mountinfo: &[SandboxMountInfo],
) -> std::io::Result<(u64, u64, PathBuf)> {
    let max_specificity = mountinfo
        .iter()
        .filter(|entry| path.starts_with(&entry.mount_point))
        .map(|entry| entry.mount_point.components().count())
        .max()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "mountinfo did not contain an authoritative mount for sandbox path {}",
                    path.display()
                ),
            )
        })?;
    let mut identities = mountinfo
        .iter()
        .filter(|entry| {
            entry.mount_point.components().count() == max_specificity
                && path.starts_with(&entry.mount_point)
        })
        .map(|entry| {
            let relative = path.strip_prefix(&entry.mount_point).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to derive mount-relative sandbox path: {error}"),
                )
            })?;
            Ok((
                entry.device_major,
                entry.device_minor,
                entry.root.join(relative),
                entry.mount_id,
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    identities.sort();
    identities.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1 && left.2 == right.2);
    if identities.len() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "mountinfo contains ambiguous authoritative mounts for sandbox path {}",
                path.display()
            ),
        ));
    }
    let (major, minor, backing, _) = identities.remove(0);
    Ok((major, minor, backing))
}

#[cfg(target_os = "linux")]
fn verify_sandbox_mount_alias_conflicts(
    sandbox: &ResolvedSystemdSandbox,
    mountinfo: &[SandboxMountInfo],
) -> std::io::Result<()> {
    let mut boundaries = vec![(
        sandbox.workspace_root.clone(),
        match sandbox.workspace_access {
            WorkspaceAccess::ReadOnly => SandboxMountAccess::ReadOnly,
            WorkspaceAccess::ReadWrite => SandboxMountAccess::ReadWrite,
        },
    )];
    boundaries.extend(
        sandbox
            .visible_read_only_roots
            .iter()
            .chain(&sandbox.visible_read_only_files)
            .cloned()
            .map(|path| (path, SandboxMountAccess::ReadOnly)),
    );
    boundaries.extend(
        sandbox
            .visible_read_write_roots
            .iter()
            .chain(&sandbox.visible_read_write_files)
            .chain(&sandbox.writable_artifact_roots)
            .cloned()
            .map(|path| (path, SandboxMountAccess::ReadWrite)),
    );
    for entry in mountinfo {
        if sandbox.effective_path_access(&entry.mount_point)?.is_some() {
            boundaries.push((
                entry.mount_point.clone(),
                sandbox
                    .effective_path_access(&entry.mount_point)?
                    .ok_or_else(|| std::io::Error::other("sandbox mount access disappeared"))?,
            ));
        }
    }
    boundaries.sort();
    boundaries.dedup();
    if boundaries.len() > MAX_SANDBOX_MOUNT_CHECKS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sandbox mount-region vector exceeds its safety bound",
        ));
    }

    let mut regions = boundaries
        .into_iter()
        .map(|(visible_path, access)| {
            let (device_major, device_minor, backing_path) =
                sandbox_mount_backing_region(&visible_path, mountinfo)?;
            Ok(SandboxMountRegion {
                visible_path,
                device_major,
                device_minor,
                backing_path,
                access,
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    regions.sort_by(|left, right| {
        left.visible_path
            .cmp(&right.visible_path)
            .then(left.access.cmp(&right.access))
            .then(left.device_major.cmp(&right.device_major))
            .then(left.device_minor.cmp(&right.device_minor))
            .then(left.backing_path.cmp(&right.backing_path))
    });
    regions.dedup();

    for (index, left) in regions.iter().enumerate() {
        for right in regions.iter().skip(index + 1) {
            if left.access == right.access {
                continue;
            }
            if sandbox_mount_regions_conflict(left, right) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox read-only and writable paths have a mount identity conflict: {} and {}",
                        left.visible_path.display(),
                        right.visible_path.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sandbox_mount_regions_conflict(left: &SandboxMountRegion, right: &SandboxMountRegion) -> bool {
    if left.visible_path == right.visible_path {
        return true;
    }
    if let Ok(relative) = left.visible_path.strip_prefix(&right.visible_path) {
        return left.device_major != right.device_major
            || left.device_minor != right.device_minor
            || left.backing_path != right.backing_path.join(relative);
    }
    if let Ok(relative) = right.visible_path.strip_prefix(&left.visible_path) {
        return left.device_major != right.device_major
            || left.device_minor != right.device_minor
            || right.backing_path != left.backing_path.join(relative);
    }
    left.device_major == right.device_major
        && left.device_minor == right.device_minor
        && (left.backing_path.starts_with(&right.backing_path)
            || right.backing_path.starts_with(&left.backing_path))
}

#[cfg(target_os = "linux")]
fn normalized_absolute_program_invocation(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if normalized != Path::new("/") {
                    normalized.pop();
                }
            }
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::Prefix(_) => {}
        }
    }
    normalized
}

#[cfg(target_os = "linux")]
fn resolved_direct_program_paths(
    spec: &ProcessSpec,
    current_dir: &Path,
) -> std::io::Result<Vec<PathBuf>> {
    let ProcessCommand::Direct { program, .. } = &spec.command else {
        return Ok(Vec::new());
    };
    let candidate = if program.is_absolute() {
        program.clone()
    } else if program.components().count() > 1 {
        current_dir.join(program)
    } else {
        // The guardian's eventual exec applies the target environment's PATH semantics. Avoid a
        // partial local reimplementation here; status 226 remains typed defense in depth for a
        // bare name whose selected executable cannot be established before launch.
        return Ok(Vec::new());
    };
    let invocation = normalized_absolute_program_invocation(&candidate);
    let mut paths = vec![invocation];
    match fs::canonicalize(&candidate) {
        Ok(canonical) if !paths.contains(&canonical) => paths.push(canonical),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(std::io::Error::new(
                error.kind(),
                format!(
                    "failed to resolve sandbox program path {}: {error}",
                    candidate.display()
                ),
            ));
        }
    }
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn resolve_systemd_sandbox(spec: &ProcessSpec) -> std::io::Result<Option<ResolvedSystemdSandbox>> {
    let Some(config) = spec.side_effects.workspace_config() else {
        return Ok(None);
    };
    let workspace_root = canonical_sandbox_directory(&config.workspace_root, "workspace root")?;
    if workspace_root == Path::new("/") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as the workspace root",
        ));
    }
    let current_dir = canonical_sandbox_directory(&spec.current_dir, "working directory")?;
    if !current_dir.starts_with(&workspace_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "working directory {} resolves outside strict workspace root {}",
                current_dir.display(),
                workspace_root.display()
            ),
        ));
    }

    let mut visible_read_only_roots = config
        .visible_read_only_roots
        .iter()
        .map(|root| canonical_sandbox_directory(root, "visible read-only root"))
        .collect::<std::io::Result<Vec<_>>>()?;
    visible_read_only_roots.sort();
    visible_read_only_roots.dedup();
    if visible_read_only_roots
        .iter()
        .any(|root| root == Path::new("/"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as a visible read-only root",
        ));
    }
    let mut visible_read_only_files = config
        .visible_read_only_files
        .iter()
        .map(|file| canonical_sandbox_file(file, "visible read-only file"))
        .collect::<std::io::Result<Vec<_>>>()?;
    visible_read_only_files.sort();
    visible_read_only_files.dedup();
    let mut writable_artifact_roots = config
        .writable_artifact_roots
        .iter()
        .map(|root| canonical_sandbox_directory(root, "writable artifact root"))
        .collect::<std::io::Result<Vec<_>>>()?;
    writable_artifact_roots.sort();
    writable_artifact_roots.dedup();
    if writable_artifact_roots
        .iter()
        .any(|root| root == Path::new("/"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as a writable artifact root",
        ));
    }
    let mut visible_read_write_roots = config
        .visible_read_write_roots
        .iter()
        .map(|root| canonical_sandbox_directory(root, "visible read-write root"))
        .collect::<std::io::Result<Vec<_>>>()?;
    visible_read_write_roots.sort();
    visible_read_write_roots.dedup();
    if visible_read_write_roots
        .iter()
        .any(|root| root == Path::new("/"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as a visible read-write root",
        ));
    }
    let mut visible_read_write_files = config
        .visible_read_write_files
        .iter()
        .map(|file| canonical_sandbox_file(file, "visible read-write file"))
        .collect::<std::io::Result<Vec<_>>>()?;
    visible_read_write_files.sort();
    visible_read_write_files.dedup();
    let mut external_codex_writable_file_capabilities = Vec::new();
    let mut capability_paths = BTreeSet::new();
    for capability in &config.external_codex_writable_file_capabilities {
        let canonical_path =
            canonical_sandbox_file(&capability.path, "ExternalCodex writable file capability")?;
        if !visible_read_write_files.contains(&canonical_path)
            || !capability_paths.insert(canonical_path.clone())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "ExternalCodex writable file capability is duplicate or lacks an exact writable file",
            ));
        }
        let resolved_capability = capability.with_resolved_path(canonical_path);
        resolved_capability.verify_path()?;
        external_codex_writable_file_capabilities.push(resolved_capability);
    }

    let mut hidden_roots = config
        .hidden_roots
        .iter()
        .map(|root| canonical_sandbox_directory(root, "hidden root"))
        .collect::<std::io::Result<Vec<_>>>()?;
    hidden_roots.sort();
    hidden_roots.dedup();
    let mut minimal_hidden_roots: Vec<PathBuf> = Vec::new();
    for root in hidden_roots {
        if minimal_hidden_roots
            .iter()
            .any(|ancestor| root.starts_with(ancestor))
        {
            continue;
        }
        minimal_hidden_roots.push(root);
    }
    let hidden_roots = minimal_hidden_roots;
    if hidden_roots.iter().any(|root| root == Path::new("/")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "strict workspace confinement refuses '/' as a hidden root",
        ));
    }
    if config.isolated_host_view {
        let nix_store = canonical_sandbox_directory(Path::new("/nix/store"), "Nix store root")?;
        if !visible_read_only_roots.contains(&nix_store) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "isolated host view requires an explicit read-only /nix/store binding",
            ));
        }
        for hidden in &hidden_roots {
            for visible in std::iter::once(&workspace_root)
                .chain(std::iter::once(&current_dir))
                .chain(visible_read_only_roots.iter())
                .chain(visible_read_only_files.iter())
                .chain(visible_read_write_roots.iter())
                .chain(visible_read_write_files.iter())
                .chain(writable_artifact_roots.iter())
            {
                if visible.starts_with(hidden) || hidden.starts_with(visible) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "isolated host view refuses overlapping visible and inaccessible roots",
                    ));
                }
            }
        }
    }
    let mut identity_paths = vec![workspace_root.clone(), current_dir.clone()];
    identity_paths.extend(visible_read_only_roots.iter().cloned());
    identity_paths.extend(visible_read_only_files.iter().cloned());
    identity_paths.extend(visible_read_write_roots.iter().cloned());
    identity_paths.extend(visible_read_write_files.iter().cloned());
    identity_paths.extend(writable_artifact_roots.iter().cloned());
    identity_paths.extend(hidden_roots.iter().cloned());
    identity_paths.sort();
    identity_paths.dedup();
    let path_identities = identity_paths
        .iter()
        .map(|path| capture_sandbox_path_identity(path))
        .collect::<std::io::Result<Vec<_>>>()?;
    let mount_checks = build_sandbox_mount_checks(SandboxMountPaths {
        workspace_root: &workspace_root,
        workspace_access: config.workspace_access,
        visible_read_only_roots: &visible_read_only_roots,
        visible_read_only_files: &visible_read_only_files,
        visible_read_write_roots: &visible_read_write_roots,
        visible_read_write_files: &visible_read_write_files,
        writable_artifact_roots: &writable_artifact_roots,
        hidden_roots: &hidden_roots,
        isolated_host_view: config.isolated_host_view,
    })?;
    if mount_checks.len() > MAX_SANDBOX_MOUNT_CHECKS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sandbox mount-check vector exceeds its safety bound",
        ));
    }

    let sandbox = ResolvedSystemdSandbox {
        kind: spec.side_effects.kind(),
        workspace_root,
        current_dir,
        workspace_access: config.workspace_access,
        visible_read_only_roots,
        visible_read_only_files,
        visible_read_write_roots,
        visible_read_write_files,
        external_codex_writable_file_capabilities,
        writable_artifact_roots,
        hidden_roots,
        isolated_host_view: config.isolated_host_view,
        resource_limits: config.resource_limits,
        path_identities,
        mount_checks,
    };
    for program in resolved_direct_program_paths(spec, &sandbox.current_dir)? {
        sandbox.validate_program_visibility(&program)?;
    }
    sandbox.verify_no_special_entries()?;
    Ok(Some(sandbox))
}

#[cfg(target_os = "linux")]
fn canonical_sandbox_directory(path: &Path, label: &str) -> std::io::Result<PathBuf> {
    validate_systemd_path_syntax(path, label)?;
    reject_symlink_ancestors(path, label)?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("failed to canonicalize {label} {}: {error}", path.display()),
        )
    })?;
    if !canonical.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} {} is not a directory", canonical.display()),
        ));
    }
    validate_systemd_path_syntax(&canonical, label)?;
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn canonical_sandbox_file(path: &Path, label: &str) -> std::io::Result<PathBuf> {
    validate_systemd_path_syntax(path, label)?;
    reject_symlink_ancestors(path, label)?;
    let canonical = fs::canonicalize(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("failed to canonicalize {label} {}: {error}", path.display()),
        )
    })?;
    if !canonical.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} {} is not a regular file", canonical.display()),
        ));
    }
    validate_systemd_path_syntax(&canonical, label)?;
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn validate_systemd_path_syntax(path: &Path, label: &str) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    if path.as_os_str().as_bytes().iter().any(|byte| {
        byte.is_ascii_whitespace() || byte.is_ascii_control() || matches!(*byte, b':' | b'\\')
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{label} contains whitespace or systemd path-list syntax that cannot be verified exactly: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_symlink_ancestors(path: &Path, label: &str) -> std::io::Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(_) => current.push(component.as_os_str()),
            std::path::Component::RootDir => current.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{label} may not contain '..': {}", path.display()),
                ));
            }
            std::path::Component::Normal(component) => {
                current.push(component);
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    std::io::Error::new(
                        error.kind(),
                        format!(
                            "failed to inspect {label} ancestor {}: {error}",
                            current.display()
                        ),
                    )
                })?;
                if metadata.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "{label} may not traverse a symlink ancestor: {}",
                            current.display()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn capture_sandbox_path_identity(path: &Path) -> std::io::Result<SandboxPathIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("sandbox path may not be a symlink: {}", path.display()),
        ));
    }
    Ok(SandboxPathIdentity {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
struct SandboxMountPaths<'a> {
    workspace_root: &'a Path,
    workspace_access: WorkspaceAccess,
    visible_read_only_roots: &'a [PathBuf],
    visible_read_only_files: &'a [PathBuf],
    visible_read_write_roots: &'a [PathBuf],
    visible_read_write_files: &'a [PathBuf],
    writable_artifact_roots: &'a [PathBuf],
    hidden_roots: &'a [PathBuf],
    isolated_host_view: bool,
}

#[cfg(target_os = "linux")]
fn build_sandbox_mount_checks(
    paths: SandboxMountPaths<'_>,
) -> std::io::Result<Vec<SandboxMountCheck>> {
    use std::os::unix::fs::MetadataExt;

    let mut requested = BTreeMap::new();
    // ProtectSystem=strict is the foundation that keeps same-filesystem symlink targets outside
    // explicitly writable binds read-only. Verify the unit's actual root mount rather than
    // trusting only the configured property.
    requested.insert(
        PathBuf::from("/"),
        if paths.isolated_host_view {
            SandboxMountAccess::IsolatedRoot
        } else {
            SandboxMountAccess::ReadOnly
        },
    );
    let workspace_mount_access = match paths.workspace_access {
        WorkspaceAccess::ReadOnly => SandboxMountAccess::ReadOnly,
        WorkspaceAccess::ReadWrite => SandboxMountAccess::ReadWrite,
    };
    requested.insert(paths.workspace_root.to_path_buf(), workspace_mount_access);
    for path in paths
        .visible_read_only_roots
        .iter()
        .chain(paths.visible_read_only_files)
    {
        if requested
            .insert(path.clone(), SandboxMountAccess::ReadOnly)
            .is_some_and(|existing| existing != SandboxMountAccess::ReadOnly)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "sandbox path was requested both read-only and read-write: {}",
                    path.display()
                ),
            ));
        }
    }
    for path in paths
        .visible_read_write_roots
        .iter()
        .chain(paths.visible_read_write_files)
        .chain(paths.writable_artifact_roots)
    {
        if requested
            .insert(path.clone(), SandboxMountAccess::ReadWrite)
            .is_some_and(|existing| existing != SandboxMountAccess::ReadWrite)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "sandbox path was requested both read-only and read-write: {}",
                    path.display()
                ),
            ));
        }
    }
    let mut checks = requested
        .into_iter()
        .map(|(path, access)| {
            let (device, inode) = if access == SandboxMountAccess::IsolatedRoot {
                (0, 0)
            } else {
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("sandbox mount check path is a symlink: {}", path.display()),
                    ));
                }
                (metadata.dev(), metadata.ino())
            };
            Ok(SandboxMountCheck {
                path,
                device,
                inode,
                access,
                optional: false,
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut inaccessible = known_sensitive_socket_paths()
        .into_iter()
        .map(|path| (path, true))
        .collect::<BTreeMap<_, _>>();
    for path in paths.hidden_roots {
        inaccessible.insert(path.clone(), false);
    }
    for (path, optional) in inaccessible {
        checks.push(SandboxMountCheck {
            path,
            device: 0,
            inode: 0,
            access: SandboxMountAccess::Inaccessible,
            optional,
        });
    }
    Ok(checks)
}

#[cfg(target_os = "linux")]
fn apply_systemd_sandbox_properties(command: &mut Command, sandbox: &ResolvedSystemdSandbox) {
    command.args([
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=tmpfs",
        "--property=NoNewPrivileges=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=LockPersonality=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=PrivateIPC=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectClock=yes",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectProc=invisible",
        "--property=ProcSubset=pid",
        "--property=SystemCallArchitectures=native",
        "--property=SystemCallErrorNumber=EPERM",
        "--property=RestrictRealtime=yes",
        "--property=KeyringMode=private",
        "--property=UMask=0077",
        "--property=MemorySwapMax=0",
        "--property=LimitCORE=0",
        "--property=OOMPolicy=kill",
    ]);
    command.arg(
        if sandbox.kind == SideEffectConfinementProfileKind::ExternalCodex {
            // Codex's native Linux sandbox establishes an inner bubblewrap namespace. The outer
            // unit still verifies every other fixed confinement property and its exact path mounts.
            "--property=RestrictNamespaces=no"
        } else {
            "--property=RestrictNamespaces=yes"
        },
    );
    if sandbox.isolated_host_view {
        command.arg("--property=TemporaryFileSystem=/:ro");
    }
    if sandbox.kind == SideEffectConfinementProfileKind::StrictOfflineWorkspace {
        command.args([
            "--property=PrivateNetwork=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=SystemCallFilter=~@clock @debug @module @mount @obsolete @raw-io @reboot @swap bpf fanotify_init fanotify_mark ipc mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink msgctl msgget msgrcv msgsnd open_by_handle_at process_madvise process_vm_readv process_vm_writev quotactl quotactl_fd semctl semget semop semtimedop semtimedop_time64 shmat shmctl shmdt shmget link linkat mknod mknodat socket socketpair socketcall",
        ]);
    } else if sandbox.kind == SideEffectConfinementProfileKind::ExternalCodex {
        command.args([
            "--property=PrivateNetwork=no",
            // Codex's inner bubblewrap sandbox needs AF_NETLINK while constructing its network
            // namespace and configuring loopback. Keep this exception exclusive to ExternalCodex.
            "--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK",
            // Bubblewrap must construct the inner mount tree. Keep the rest of the ordinary
            // networked deny list intact and relax @mount only for ExternalCodex.
            "--property=SystemCallFilter=~@clock @debug @module @obsolete @raw-io @reboot @swap bpf fanotify_init fanotify_mark ipc mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink msgctl msgget msgrcv msgsnd open_by_handle_at process_madvise process_vm_readv process_vm_writev quotactl quotactl_fd semctl semget semop semtimedop semtimedop_time64 shmat shmctl shmdt shmget link linkat mknod mknodat",
        ]);
    } else {
        command.args([
            "--property=PrivateNetwork=no",
            "--property=RestrictAddressFamilies=AF_INET AF_INET6",
            "--property=SystemCallFilter=~@clock @debug @module @mount @obsolete @raw-io @reboot @swap bpf fanotify_init fanotify_mark ipc mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink msgctl msgget msgrcv msgsnd open_by_handle_at process_madvise process_vm_readv process_vm_writev quotactl quotactl_fd semctl semget semop semtimedop semtimedop_time64 shmat shmctl shmdt shmget link linkat mknod mknodat",
        ]);
    }

    let limits = sandbox.resource_limits;
    command
        .arg(format!("--property=MemoryMax={}", limits.memory_max_bytes))
        .arg(format!("--property=TasksMax={}", limits.tasks_max))
        .arg(format!("--property=CPUQuota={}%", limits.cpu_quota_percent))
        .arg(format!("--property=LimitNOFILE={}", limits.open_files_max))
        .arg(format!(
            "--property=LimitFSIZE={}",
            limits.file_size_max_bytes
        ));

    for root in &sandbox.hidden_roots {
        command.arg(systemd_path_property("InaccessiblePaths=", root, false));
    }
    for path in known_sensitive_socket_paths() {
        command.arg(systemd_path_property("InaccessiblePaths=", &path, true));
    }

    for root in &sandbox.visible_read_only_roots {
        command
            .arg(systemd_path_property("BindReadOnlyPaths=", root, false))
            .arg(systemd_path_property("ReadOnlyPaths=", root, false));
    }
    for file in &sandbox.visible_read_only_files {
        command
            .arg(systemd_path_property("BindReadOnlyPaths=", file, false))
            .arg(systemd_path_property("ReadOnlyPaths=", file, false));
    }
    for root in &sandbox.visible_read_write_roots {
        command
            .arg(systemd_path_property("BindPaths=", root, false))
            .arg(systemd_path_property("ReadWritePaths=", root, false));
    }
    for file in &sandbox.visible_read_write_files {
        command
            .arg(systemd_path_property("BindPaths=", file, false))
            .arg(systemd_path_property("ReadWritePaths=", file, false));
    }

    match sandbox.workspace_access {
        WorkspaceAccess::ReadOnly => {
            command
                .arg(systemd_path_property(
                    "BindReadOnlyPaths=",
                    &sandbox.workspace_root,
                    false,
                ))
                .arg(systemd_path_property(
                    "ReadOnlyPaths=",
                    &sandbox.workspace_root,
                    false,
                ));
        }
        WorkspaceAccess::ReadWrite => {
            command
                .arg(systemd_path_property(
                    "BindPaths=",
                    &sandbox.workspace_root,
                    false,
                ))
                .arg(systemd_path_property(
                    "ReadWritePaths=",
                    &sandbox.workspace_root,
                    false,
                ));
        }
    }
    for root in &sandbox.writable_artifact_roots {
        command
            .arg(systemd_path_property("BindPaths=", root, false))
            .arg(systemd_path_property("ReadWritePaths=", root, false));
    }
}

#[cfg(target_os = "linux")]
fn verify_systemd_sandbox_properties(
    sandbox: &ResolvedSystemdSandbox,
    properties: &BTreeMap<String, String>,
    runtime_dir: &Path,
) -> std::io::Result<()> {
    for (name, expected) in [
        ("ProtectSystem", "strict"),
        ("ProtectHome", "tmpfs"),
        ("NoNewPrivileges", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("LockPersonality", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateDevices", "yes"),
        ("PrivateIPC", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectKernelLogs", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectProc", "invisible"),
        ("ProcSubset", "pid"),
        ("SystemCallArchitectures", "native"),
        ("RestrictRealtime", "yes"),
        ("KeyringMode", "private"),
        ("UMask", "0077"),
        ("MemorySwapMax", "0"),
        ("LimitCORE", "0"),
        ("OOMPolicy", "kill"),
    ] {
        require_effective_property(properties, name, |value| value == expected, expected)?;
    }
    verify_system_call_error_number(property_value(properties, "SystemCallErrorNumber")?)?;
    require_effective_property(
        properties,
        "SystemCallFilter",
        |value| !value.trim().is_empty(),
        "a non-empty syscall filter",
    )?;
    verify_effective_system_call_filter(
        sandbox.kind,
        property_value(properties, "SystemCallFilter")?,
    )?;
    verify_effective_namespace_restriction(
        sandbox.kind,
        property_value(properties, "RestrictNamespaces")?,
    )?;

    verify_systemd_network_properties(sandbox.kind, properties)?;
    verify_isolated_host_view_property(sandbox, properties)?;

    let limits = sandbox.resource_limits;
    for (name, expected) in [
        ("MemoryMax", limits.memory_max_bytes.to_string()),
        ("TasksMax", limits.tasks_max.to_string()),
        ("LimitNOFILE", limits.open_files_max.to_string()),
        ("LimitFSIZE", limits.file_size_max_bytes.to_string()),
    ] {
        require_effective_property(properties, name, |value| value == expected, &expected)?;
    }
    if sandbox.kind == SideEffectConfinementProfileKind::TrustedFixedNetwork {
        let expected_quota_micros = u64::from(limits.cpu_quota_percent) * 10_000;
        require_effective_property(
            properties,
            "CPUQuotaPerSecUSec",
            |value| parse_systemd_duration_micros(value) == Some(expected_quota_micros),
            &format!("exactly {expected_quota_micros} microseconds per second"),
        )?;
    } else {
        require_effective_property(
            properties,
            "CPUQuotaPerSecUSec",
            |value| !value.is_empty() && value != "infinity",
            "a finite quota",
        )?;
    }

    let inaccessible = property_value(properties, "InaccessiblePaths")?;
    for root in &sandbox.hidden_roots {
        require_property_path("InaccessiblePaths", inaccessible, root)?;
    }
    // Mask known same-user IPC endpoints and the Nix daemon. The complete runtime root cannot be
    // masked because it contains systemd's unit-lifetime guardian directory; AF_UNIX/socket
    // restrictions are independently verified for target isolation.
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let uid = unsafe { libc::geteuid() };
    for path in [
        PathBuf::from(format!("/run/user/{uid}/bus")),
        PathBuf::from(format!("/run/user/{uid}/systemd")),
        PathBuf::from("/nix/var/nix/daemon-socket/socket"),
    ] {
        require_property_path("InaccessiblePaths", inaccessible, &path)?;
    }
    require_property_path(
        "BindPaths",
        property_value(properties, "BindPaths")?,
        runtime_dir,
    )?;
    require_property_path(
        "ReadWritePaths",
        property_value(properties, "ReadWritePaths")?,
        runtime_dir,
    )?;

    match sandbox.workspace_access {
        WorkspaceAccess::ReadOnly => {
            require_property_path(
                "BindReadOnlyPaths",
                property_value(properties, "BindReadOnlyPaths")?,
                &sandbox.workspace_root,
            )?;
            require_property_path(
                "ReadOnlyPaths",
                property_value(properties, "ReadOnlyPaths")?,
                &sandbox.workspace_root,
            )?;
        }
        WorkspaceAccess::ReadWrite => {
            require_property_path(
                "BindPaths",
                property_value(properties, "BindPaths")?,
                &sandbox.workspace_root,
            )?;
            require_property_path(
                "ReadWritePaths",
                property_value(properties, "ReadWritePaths")?,
                &sandbox.workspace_root,
            )?;
        }
    }
    for root in &sandbox.visible_read_only_roots {
        require_property_path(
            "BindReadOnlyPaths",
            property_value(properties, "BindReadOnlyPaths")?,
            root,
        )?;
    }
    for file in &sandbox.visible_read_only_files {
        require_property_path(
            "BindReadOnlyPaths",
            property_value(properties, "BindReadOnlyPaths")?,
            file,
        )?;
        require_property_path(
            "ReadOnlyPaths",
            property_value(properties, "ReadOnlyPaths")?,
            file,
        )?;
    }
    for root in &sandbox.visible_read_write_roots {
        require_property_path("BindPaths", property_value(properties, "BindPaths")?, root)?;
        require_property_path(
            "ReadWritePaths",
            property_value(properties, "ReadWritePaths")?,
            root,
        )?;
    }
    for file in &sandbox.visible_read_write_files {
        require_property_path("BindPaths", property_value(properties, "BindPaths")?, file)?;
        require_property_path(
            "ReadWritePaths",
            property_value(properties, "ReadWritePaths")?,
            file,
        )?;
    }
    for root in &sandbox.writable_artifact_roots {
        require_property_path("BindPaths", property_value(properties, "BindPaths")?, root)?;
        require_property_path(
            "ReadWritePaths",
            property_value(properties, "ReadWritePaths")?,
            root,
        )?;
    }
    verify_exact_systemd_path_properties(sandbox, properties, runtime_dir)
}

#[cfg(target_os = "linux")]
fn verify_exact_systemd_path_properties(
    sandbox: &ResolvedSystemdSandbox,
    properties: &BTreeMap<String, String>,
    runtime_dir: &Path,
) -> std::io::Result<()> {
    if !matches!(
        sandbox.kind,
        SideEffectConfinementProfileKind::TrustedFixedNetwork
            | SideEffectConfinementProfileKind::ExternalCodex
    ) && !sandbox.isolated_host_view
    {
        return Ok(());
    }

    let mut inaccessible = sandbox
        .hidden_roots
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    inaccessible.extend(known_sensitive_socket_paths());
    verify_exact_property_paths(
        "InaccessiblePaths",
        property_value(properties, "InaccessiblePaths")?,
        &inaccessible,
    )?;

    let mut read_only = sandbox
        .visible_read_only_roots
        .iter()
        .chain(&sandbox.visible_read_only_files)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut read_only_bindings = sandbox
        .visible_read_only_roots
        .iter()
        .chain(&sandbox.visible_read_only_files)
        .map(|path| (path.clone(), path.clone()))
        .collect::<BTreeSet<_>>();
    let mut read_write = sandbox
        .visible_read_write_roots
        .iter()
        .chain(&sandbox.visible_read_write_files)
        .chain(&sandbox.writable_artifact_roots)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut read_write_bindings = sandbox
        .visible_read_write_roots
        .iter()
        .chain(&sandbox.visible_read_write_files)
        .chain(&sandbox.writable_artifact_roots)
        .map(|path| (path.clone(), path.clone()))
        .collect::<BTreeSet<_>>();
    match sandbox.workspace_access {
        WorkspaceAccess::ReadOnly => {
            read_only.insert(sandbox.workspace_root.clone());
            read_only_bindings.insert((
                sandbox.workspace_root.clone(),
                sandbox.workspace_root.clone(),
            ));
        }
        WorkspaceAccess::ReadWrite => {
            read_write.insert(sandbox.workspace_root.clone());
            read_write_bindings.insert((
                sandbox.workspace_root.clone(),
                sandbox.workspace_root.clone(),
            ));
        }
    }
    read_write.insert(runtime_dir.to_path_buf());
    read_write_bindings.insert((runtime_dir.to_path_buf(), runtime_dir.to_path_buf()));
    verify_exact_property_bindings(
        "BindReadOnlyPaths",
        property_value(properties, "BindReadOnlyPaths")?,
        &read_only_bindings,
    )?;
    verify_exact_property_paths(
        "ReadOnlyPaths",
        property_value(properties, "ReadOnlyPaths")?,
        &read_only,
    )?;
    verify_exact_property_bindings(
        "BindPaths",
        property_value(properties, "BindPaths")?,
        &read_write_bindings,
    )?;
    verify_exact_property_paths(
        "ReadWritePaths",
        property_value(properties, "ReadWritePaths")?,
        &read_write,
    )
}

#[cfg(target_os = "linux")]
fn is_exact_isolated_host_view_property(value: &str) -> bool {
    let mut entries = value.split_whitespace();
    entries.next() == Some("/:ro") && entries.next().is_none()
}

#[cfg(target_os = "linux")]
fn verify_isolated_host_view_property(
    sandbox: &ResolvedSystemdSandbox,
    properties: &BTreeMap<String, String>,
) -> std::io::Result<()> {
    let value = property_value(properties, "TemporaryFileSystem")?;
    if !sandbox.isolated_host_view {
        return if value.trim().is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "effective TemporaryFileSystem unexpectedly changed the ordinary sandbox root",
            ))
        };
    }
    if is_exact_isolated_host_view_property(value) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "effective TemporaryFileSystem did not exactly match the isolated read-only root",
        ))
    }
}

#[cfg(target_os = "linux")]
fn verify_systemd_network_properties(
    kind: SideEffectConfinementProfileKind,
    properties: &BTreeMap<String, String>,
) -> std::io::Result<()> {
    let address_families = property_value(properties, "RestrictAddressFamilies")?;
    let actual_families = address_families.split_whitespace().collect::<BTreeSet<_>>();
    let expected_families = match kind {
        SideEffectConfinementProfileKind::StrictOfflineWorkspace => BTreeSet::from(["AF_UNIX"]),
        SideEffectConfinementProfileKind::ExternalCodex => {
            BTreeSet::from(["AF_INET", "AF_INET6", "AF_NETLINK"])
        }
        SideEffectConfinementProfileKind::TrustedFixedNetwork
        | SideEffectConfinementProfileKind::TrustedCompatibility => {
            BTreeSet::from(["AF_INET", "AF_INET6"])
        }
    };
    if actual_families != expected_families {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "effective RestrictAddressFamilies does not match {:?}: {address_families:?}",
                kind
            ),
        ));
    }
    if kind == SideEffectConfinementProfileKind::StrictOfflineWorkspace {
        require_effective_property(properties, "PrivateNetwork", |value| value == "yes", "yes")?;
    } else {
        require_effective_property(properties, "PrivateNetwork", |value| value == "no", "no")?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_sandbox_mount_report(path: &Path, checks: &[SandboxMountCheck]) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unsafe sandbox mount report {}", path.display()),
        ));
    }
    let bytes = read_bounded_regular_file_nofollow(path, 64 * 1024)?;
    let report = std::str::from_utf8(&bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("sandbox mount report is not UTF-8: {error}"),
        )
    })?;
    let lines = report.lines().collect::<Vec<_>>();
    if lines.len() != checks.len() + 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "sandbox mount report has {} entries; expected {}",
                lines.len(),
                checks.len() + 1
            ),
        ));
    }
    let security = lines[0].split_whitespace().collect::<Vec<_>>();
    if security.len() != 7
        || security[0] != "security"
        || security[1..=4]
            .iter()
            .any(|value| *value != "0000000000000000")
        || security[5] != "1"
        || security[6] != "2"
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unit security state was not capability-free, no-new-privileges, and seccomp-filtered: {:?}", lines[0]),
        ));
    }
    for (line, check) in lines[1..].iter().copied().zip(checks) {
        if check.access == SandboxMountAccess::Inaccessible {
            let accepted =
                line == "inaccessible" || (check.optional && line == "inaccessible-missing");
            if !accepted {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "sandbox path remained visible inside unit mount namespace: {}",
                        check.path.display()
                    ),
                ));
            }
            continue;
        }
        if check.access == SandboxMountAccess::IsolatedRoot {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() != 4
                || fields[0] != "isolated-root"
                || fields[2] != "tmpfs"
                || !fields[3].split(',').any(|option| option == "ro")
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "sandbox root was not an isolated read-only tmpfs",
                ));
            }
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != "mounted" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("malformed sandbox mount report line: {line:?}"),
            ));
        }
        let device = fields[1].parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid mount report device: {error}"),
            )
        })?;
        let inode = fields[2].parse::<u64>().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid mount report inode: {error}"),
            )
        })?;
        let (expected_device, expected_inode) =
            if check.access == SandboxMountAccess::PrivateRuntime {
                let runtime = fs::symlink_metadata(&check.path)?;
                if runtime.file_type().is_symlink()
                    || !runtime.is_dir()
                    || runtime.uid() != effective_uid
                    || runtime.permissions().mode() & 0o777 != 0o700
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "private unit runtime mount identity or mode was unsafe",
                    ));
                }
                (runtime.dev(), runtime.ino())
            } else {
                (check.device, check.inode)
            };
        if device != expected_device || inode != expected_inode {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "systemd bound the wrong inode for {}: expected {}:{}, observed {device}:{inode}",
                    check.path.display(),
                    expected_device,
                    expected_inode
                ),
            ));
        }
        let options = fields[3].split(',').collect::<Vec<_>>();
        let expected = match check.access {
            SandboxMountAccess::ReadOnly => "ro",
            SandboxMountAccess::ReadWrite => "rw",
            SandboxMountAccess::PrivateRuntime => "rw",
            SandboxMountAccess::Inaccessible => continue,
            SandboxMountAccess::IsolatedRoot => continue,
        };
        if !options.contains(&expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sandbox mount access for {} was not {expected}: {:?}",
                    check.path.display(),
                    fields[3]
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn property_value<'a>(
    properties: &'a BTreeMap<String, String>,
    name: &str,
) -> std::io::Result<&'a str> {
    properties.get(name).map(String::as_str).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("systemd show omitted effective property {name}"),
        )
    })
}

#[cfg(target_os = "linux")]
fn require_effective_property(
    properties: &BTreeMap<String, String>,
    name: &str,
    predicate: impl FnOnce(&str) -> bool,
    expected: &str,
) -> std::io::Result<()> {
    let value = property_value(properties, name)?;
    if predicate(value) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("effective {name}={value:?}; required {expected}"),
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_systemd_duration_micros(value: &str) -> Option<u64> {
    for (suffix, multiplier) in [
        ("us", 1u64),
        ("ms", 1_000u64),
        ("s", 1_000_000u64),
        ("min", 60_000_000u64),
    ] {
        if let Some(number) = value.strip_suffix(suffix) {
            return number
                .parse::<u64>()
                .ok()
                .and_then(|number| number.checked_mul(multiplier));
        }
    }
    value.parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn require_property_path(name: &str, value: &str, path: &Path) -> std::io::Result<()> {
    let path = path.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{name} path is not valid UTF-8: {}", path.display()),
        )
    })?;
    let matches = value.split_whitespace().any(|entry| {
        let entry = entry.strip_prefix('-').unwrap_or(entry);
        let source = entry.split(':').next().unwrap_or(entry);
        source == path
    });
    if matches {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("effective {name} omitted required path {path}"),
        ))
    }
}

#[cfg(target_os = "linux")]
fn parse_property_bindings(value: &str) -> BTreeSet<(PathBuf, PathBuf)> {
    value
        .split_whitespace()
        .filter_map(|entry| {
            let entry = entry.strip_prefix('-').unwrap_or(entry);
            let mut parts = entry.split(':');
            let source = parts.next()?;
            let destination = parts
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or(source);
            Some((PathBuf::from(source), PathBuf::from(destination)))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn verify_exact_property_bindings(
    name: &str,
    value: &str,
    expected: &BTreeSet<(PathBuf, PathBuf)>,
) -> std::io::Result<()> {
    let actual = parse_property_bindings(value);
    if &actual == expected {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "effective {name} binding set differed from the exact requested set: expected {expected:?}, observed {actual:?}"
            ),
        ))
    }
}

#[cfg(target_os = "linux")]
fn verify_exact_property_paths(
    name: &str,
    value: &str,
    expected: &BTreeSet<PathBuf>,
) -> std::io::Result<()> {
    let actual = value
        .split_whitespace()
        .map(|entry| {
            let entry = entry.strip_prefix('-').unwrap_or(entry);
            PathBuf::from(entry.split(':').next().unwrap_or(entry))
        })
        .collect::<BTreeSet<_>>();
    if &actual == expected {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "effective {name} path set differed from the exact requested set: expected {expected:?}, observed {actual:?}"
            ),
        ))
    }
}

#[cfg(target_os = "linux")]
fn verify_system_call_error_number(value: &str) -> std::io::Result<()> {
    if value == "EPERM" || value == libc::EPERM.to_string() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("effective SystemCallErrorNumber={value:?}; required EPERM"),
        ))
    }
}

#[cfg(target_os = "linux")]
const REQUIRED_DENIED_SYSCALLS: &[&str] = &[
    "bpf",
    "fanotify_init",
    "fanotify_mark",
    "ipc",
    "mq_getsetattr",
    "mq_notify",
    "mq_open",
    "mq_timedreceive",
    "mq_timedreceive_time64",
    "mq_timedsend",
    "mq_timedsend_time64",
    "mq_unlink",
    "msgctl",
    "msgget",
    "msgrcv",
    "msgsnd",
    "open_by_handle_at",
    "process_madvise",
    "process_vm_readv",
    "process_vm_writev",
    "quotactl",
    "quotactl_fd",
    "semctl",
    "semget",
    "semop",
    "semtimedop",
    "semtimedop_time64",
    "shmat",
    "shmctl",
    "shmdt",
    "shmget",
    "link",
    "linkat",
    "mknod",
    "mknodat",
];

#[cfg(target_os = "linux")]
fn required_denied_group_representatives() -> [(&'static str, &'static [&'static str]); 8] {
    let raw_io_representatives: &[&str] = if cfg!(any(target_arch = "x86", target_arch = "x86_64"))
    {
        &["ioperm", "iopl"]
    } else if cfg!(target_arch = "s390x") {
        &[
            "s390_pci_mmio_read",
            "s390_pci_mmio_write",
            "s390_runtime_instr",
        ]
    } else {
        // Linux exposes no architecture-common raw-I/O syscall outside the families above. A
        // systemd version that expands this group on another architecture therefore fails closed;
        // versions retaining the requested group token remain supported.
        &[]
    };
    [
        (
            "@clock",
            &["adjtimex", "clock_adjtime", "clock_settime", "settimeofday"],
        ),
        (
            "@debug",
            &[
                "perf_event_open",
                "ptrace",
                "process_vm_readv",
                "process_vm_writev",
            ],
        ),
        ("@module", &["delete_module", "finit_module", "init_module"]),
        (
            "@mount",
            &[
                "fsconfig",
                "fsmount",
                "fsopen",
                "fspick",
                "mount",
                "mount_setattr",
                "move_mount",
                "pivot_root",
                "umount2",
            ],
        ),
        ("@obsolete", &["_sysctl", "sysfs"]),
        ("@raw-io", raw_io_representatives),
        ("@reboot", &["kexec_load", "reboot"]),
        ("@swap", &["swapon", "swapoff"]),
    ]
}
