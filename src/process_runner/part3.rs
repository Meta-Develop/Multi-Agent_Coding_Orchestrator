#[cfg(target_os = "linux")]
fn verify_effective_system_call_filter(
    kind: SideEffectConfinementProfileKind,
    value: &str,
) -> std::io::Result<()> {
    let tokens = value.split_whitespace().collect::<Vec<_>>();
    let configured_as_deny_list = tokens.first().is_some_and(|token| token.starts_with('~'));
    if !configured_as_deny_list {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "effective SystemCallFilter was not a deny list",
        ));
    }

    // Older systemd releases may retain group names here, while newer releases expose their
    // architecture-specific expansion. Require either the group token or every selected
    // architecture-common member from each requested group.
    for (group, representatives) in required_denied_group_representatives() {
        if kind == SideEffectConfinementProfileKind::ExternalCodex && group == "@mount" {
            let denied_group = tokens
                .iter()
                .any(|token| token.trim_start_matches('~') == group);
            let denied_member = representatives.iter().find(|representative| {
                tokens
                    .iter()
                    .any(|token| token.trim_start_matches('~') == **representative)
            });
            if denied_group || denied_member.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "effective SystemCallFilter denied ExternalCodex inner bubblewrap mount operations: {}",
                        denied_member.copied().unwrap_or(group)
                    ),
                ));
            }
            continue;
        }
        let retained_group = tokens
            .iter()
            .any(|token| token.trim_start_matches('~') == group);
        let expanded_group = !representatives.is_empty()
            && representatives.iter().all(|representative| {
                tokens
                    .iter()
                    .any(|token| token.trim_start_matches('~') == *representative)
            });
        if !retained_group && !expanded_group {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "effective SystemCallFilter omitted denied group {group} and its complete representative expansion"
                ),
            ));
        }
    }

    for syscall in REQUIRED_DENIED_SYSCALLS {
        if !tokens
            .iter()
            .any(|token| token.trim_start_matches('~') == *syscall)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("effective SystemCallFilter omitted denied syscall {syscall}"),
            ));
        }
    }
    if kind == SideEffectConfinementProfileKind::StrictOfflineWorkspace {
        for syscall in ["socket", "socketpair", "socketcall"] {
            if !tokens
                .iter()
                .any(|token| token.trim_start_matches('~') == syscall)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("effective SystemCallFilter omitted denied syscall {syscall}"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_effective_namespace_restriction(
    kind: SideEffectConfinementProfileKind,
    value: &str,
) -> std::io::Result<()> {
    let expected = if kind == SideEffectConfinementProfileKind::ExternalCodex {
        "no"
    } else {
        "yes"
    };
    if value == expected {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("effective RestrictNamespaces={value:?}; required {expected:?} for {kind:?}"),
        ))
    }
}

#[cfg(target_os = "linux")]
fn systemd_path_property(name: &str, path: &Path, optional: bool) -> OsString {
    let mut property = OsString::from("--property=");
    property.push(name);
    if optional {
        property.push("-");
    }
    property.push(path.as_os_str());
    property
}

#[cfg(target_os = "linux")]
fn known_sensitive_socket_paths() -> Vec<PathBuf> {
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let uid = unsafe { libc::geteuid() };
    let user_runtime = PathBuf::from(format!("/run/user/{uid}"));
    [
        user_runtime.join("bus"),
        user_runtime.join("systemd"),
        user_runtime.join("gnupg"),
        user_runtime.join("keyring"),
        user_runtime.join("wayland-0"),
        user_runtime.join("pipewire-0"),
        user_runtime.join("pulse"),
        user_runtime.join("ssh-agent"),
        user_runtime.join("docker.sock"),
        user_runtime.join("podman"),
        user_runtime.join("libvirt"),
        PathBuf::from("/run/dbus/system_bus_socket"),
        PathBuf::from("/var/run/dbus/system_bus_socket"),
        PathBuf::from("/run/docker.sock"),
        PathBuf::from("/var/run/docker.sock"),
        PathBuf::from("/run/podman"),
        PathBuf::from("/run/libvirt"),
        PathBuf::from("/var/run/libvirt"),
        PathBuf::from("/run/credentials"),
        PathBuf::from("/run/secrets"),
        PathBuf::from("/run/keys"),
        PathBuf::from("/nix/var/nix/daemon-socket/socket"),
    ]
    .into_iter()
    .collect()
}

#[cfg(target_os = "linux")]
struct SystemdUnit {
    _permit: SystemdUnitPermit,
    systemd_run: PathBuf,
    systemctl: PathBuf,
    env_program: PathBuf,
    shell: PathBuf,
    sleep_program: PathBuf,
    stat_program: PathBuf,
    findmnt_program: PathBuf,
    name: String,
    cgroup_path: PathBuf,
    runtime_dir: PathBuf,
    client_runtime: PathBuf,
    environment_file: PathBuf,
    ready_path: PathBuf,
    waiting_path: PathBuf,
    environment_fifo_path: PathBuf,
    start_fifo_path: PathBuf,
    target_pid_path: PathBuf,
    owner_fifo_path: PathBuf,
    fifo_waiting_path: PathBuf,
    sandbox_report_path: PathBuf,
    owner_channel: Option<File>,
    pending_environment: Option<EnvironmentMode>,
    pending_runtime_files: Vec<PrivateRuntimeFile>,
    runtime_file_paths: Vec<PathBuf>,
    target_program_path: Option<PathBuf>,
    sandbox: Option<ResolvedSystemdSandbox>,
    sandbox_verified: bool,
    environment_published: bool,
    environment_released: bool,
    fifos_prepared: bool,
    launcher_spawned: bool,
    launcher_completed: bool,
    observed_owned: bool,
    cleaned: bool,
}

#[cfg(target_os = "linux")]
struct SystemdUnitPermit {
    file: File,
}

#[cfg(target_os = "linux")]
impl SystemdUnitPermit {
    fn acquire(
        runtime_root: &Path,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<Self> {
        use std::os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            io::AsRawFd,
        };

        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let effective_uid = unsafe { libc::geteuid() };
        let deadline = bounded_operation_deadline(SYSTEMD_SLOT_WAIT, operation_deadline)?;
        let max_concurrent_units = HostProcessCapacity::measured().systemd_unit_slots();
        loop {
            if cancellation.is_cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "systemd containment slot acquisition was cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no systemd containment execution slot became available before the bounded setup deadline",
                ));
            }
            let first_slot = if operation_deadline.is_some_and(|deadline| {
                deadline.saturating_duration_since(Instant::now())
                    <= EXPEDITED_SYSTEMD_SLOT_THRESHOLD
            }) {
                0
            } else {
                RESERVED_EXPEDITED_SYSTEMD_SLOTS
            };
            // Slot zero stays available for operations whose total deadline is at most one second;
            // longer and unbounded runs share the remaining slots.
            for slot in first_slot..max_concurrent_units {
                let path = runtime_root.join(format!("maco-process-runner-slot-{slot}.lock"));
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)?;
                let metadata = file.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != effective_uid
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("unsafe systemd containment slot file {}", path.display()),
                    ));
                }
                // SAFETY: flock operates on this live owned descriptor and does not access memory.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                    if cancellation.is_cancelled() {
                        drop(file);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "systemd containment slot acquisition was cancelled",
                        ));
                    }
                    if Instant::now() >= deadline {
                        drop(file);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "a systemd containment execution slot became available only after the bounded setup deadline",
                        ));
                    }
                    return Ok(Self { file });
                }
                let error = std::io::Error::last_os_error();
                let code = error.raw_os_error();
                if code != Some(libc::EWOULDBLOCK) && code != Some(libc::EAGAIN) {
                    return Err(error);
                }
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "no systemd containment execution slot became available within {} seconds",
                        SYSTEMD_SLOT_WAIT.as_secs()
                    ),
                ));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for SystemdUnitPermit {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;

        // SAFETY: unlocking this live descriptor is advisory cleanup; closing also releases it.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(target_os = "linux")]
impl SystemdUnit {
    fn prepare(
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<Self> {
        #[cfg(test)]
        if env::var_os("MACO_TEST_DISABLE_STRICT_CONTAINMENT").is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "strict containment disabled by isolated regression test",
            ));
        }
        let client_runtime = trusted_linux_runtime_root()?;
        let permit = SystemdUnitPermit::acquire(&client_runtime, operation_deadline, cancellation)?;
        let systemd_run = find_trusted_unix_executable(
            "systemd-run",
            &[
                "/usr/bin/systemd-run",
                "/bin/systemd-run",
                "/run/current-system/sw/bin/systemd-run",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable systemd-run at a trusted system path",
            )
        })?;
        let shell = find_trusted_unix_executable(
            "sh",
            &["/bin/sh", "/usr/bin/sh", "/run/current-system/sw/bin/sh"],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable POSIX shell at a trusted system path",
            )
        })?;
        let systemctl = find_trusted_unix_executable(
            "systemctl",
            &[
                "/usr/bin/systemctl",
                "/bin/systemctl",
                "/run/current-system/sw/bin/systemctl",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable systemctl at a trusted system path",
            )
        })?;
        let env_program = find_trusted_unix_executable(
            "env",
            &["/usr/bin/env", "/bin/env", "/run/current-system/sw/bin/env"],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable env helper at a trusted system path",
            )
        })?;
        let sleep_program = find_trusted_unix_executable(
            "sleep",
            &[
                "/usr/bin/sleep",
                "/bin/sleep",
                "/run/current-system/sw/bin/sleep",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable sleep helper at a trusted system path",
            )
        })?;
        let stat_program = find_trusted_unix_executable(
            "stat",
            &[
                "/usr/bin/stat",
                "/bin/stat",
                "/run/current-system/sw/bin/stat",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable stat helper at a trusted system path",
            )
        })?;
        let findmnt_program = find_trusted_unix_executable(
            "findmnt",
            &[
                "/usr/bin/findmnt",
                "/bin/findmnt",
                "/run/current-system/sw/bin/findmnt",
            ],
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "strict containment requires a root-owned, non-writable findmnt helper at a trusted system path",
            )
        })?;
        let manager_cgroup = systemd_user_manager_cgroup()?;
        let manager_path = Path::new("/sys/fs/cgroup").join(
            manager_cgroup
                .strip_prefix("/")
                .unwrap_or(manager_cgroup.as_path()),
        );
        if !manager_path.join("cgroup.controllers").is_file()
            || !manager_path.join("cgroup.kill").is_file()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "systemd user manager cgroup {} does not expose cgroup v2 kill/verification controls",
                    manager_path.display()
                ),
            ));
        }
        let sequence = NEXT_SYSTEMD_UNIT_ID.fetch_add(1, Ordering::Relaxed);
        let runner_pid = std::process::id();
        let name = format!("maco-process-{runner_pid}-{sequence}.service");
        #[cfg(test)]
        record_systemd_unit_name_for_test(&name);
        let cgroup_path = manager_path.join("app.slice").join(&name);
        let runtime_dir = client_runtime
            .clone()
            .join(format!("maco-process-{runner_pid}-{sequence}"));
        let environment_file = runtime_dir.join("environment");
        let ready_path = runtime_dir.join("environment-ready");
        let waiting_path = runtime_dir.join("guardian-waiting");
        let environment_fifo_path = runtime_dir.join("environment-gate");
        let start_fifo_path = runtime_dir.join("start-gate");
        let target_pid_path = runtime_dir.join("target-pid");
        let owner_fifo_path = runtime_dir.join("owner-liveness");
        let fifo_waiting_path = runtime_dir.join("fifo-waiting");
        let sandbox_report_path = runtime_dir.join("sandbox-mount-report");
        Ok(Self {
            _permit: permit,
            systemd_run,
            systemctl,
            env_program,
            shell,
            sleep_program,
            stat_program,
            findmnt_program,
            name,
            cgroup_path,
            runtime_dir,
            client_runtime,
            environment_file,
            ready_path,
            waiting_path,
            environment_fifo_path,
            start_fifo_path,
            target_pid_path,
            owner_fifo_path,
            fifo_waiting_path,
            sandbox_report_path,
            owner_channel: None,
            pending_environment: None,
            pending_runtime_files: Vec::new(),
            runtime_file_paths: Vec::new(),
            target_program_path: None,
            sandbox: None,
            sandbox_verified: false,
            environment_published: false,
            environment_released: false,
            fifos_prepared: false,
            launcher_spawned: false,
            launcher_completed: false,
            observed_owned: false,
            cleaned: false,
        })
    }

    fn build_command(&mut self, spec: &ProcessSpec) -> std::io::Result<Command> {
        let target_environment = if spec.private_runtime_home || spec.private_runtime_codex_home {
            environment_with_private_runtime_home(
                &spec.environment,
                &self.runtime_dir,
                spec.private_runtime_home,
                spec.private_runtime_codex_home,
            )?
        } else {
            spec.environment.clone()
        };
        let mut private_runtime_files = spec.private_runtime_files.clone();
        let pinned_launch = if let Some(pinned) = &spec.pinned_direct {
            pinned.validate_command(&spec.command)?;
            let ProcessCommand::Direct { args, .. } = &spec.command else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pinned executable capability requires a direct command",
                ));
            };
            let helper = pinned_exec::validated_current_helper_path()?;
            let environment = effective_environment(&target_environment)
                .into_iter()
                .collect::<Vec<_>>();
            let descriptor = pinned.executable.encode_descriptor(args, &environment)?;
            let (bytes, digest) = descriptor.into_parts();
            private_runtime_files.push(PrivateRuntimeFile {
                name: PINNED_EXEC_DESCRIPTOR_NAME.to_string(),
                bytes,
            });
            Some((helper, digest))
        } else {
            None
        };
        validate_private_runtime_files(&private_runtime_files)?;
        self.pending_runtime_files = private_runtime_files;
        self.pending_environment = Some(if pinned_launch.is_some() {
            EnvironmentMode::ClearAndSet(BTreeMap::new())
        } else {
            target_environment
        });
        let mut sandbox = resolve_systemd_sandbox(spec)?;
        let target_current_dir = sandbox
            .as_ref()
            .map_or(spec.current_dir.as_path(), |sandbox| {
                sandbox.current_dir.as_path()
            });
        let target_program_path = match &pinned_launch {
            Some((helper, _)) => helper.clone(),
            None => match &spec.command {
                ProcessCommand::Shell { .. } => self.shell.clone(),
                ProcessCommand::Direct { program, .. } if program.is_absolute() => {
                    normalized_absolute_program_invocation(program)
                }
                ProcessCommand::Direct { program, .. } if program.components().count() > 1 => {
                    normalized_absolute_program_invocation(&target_current_dir.join(program))
                }
                ProcessCommand::Direct { program, .. } => program.clone(),
            },
        };
        if let Some(sandbox) = sandbox.as_mut() {
            if pinned_launch.is_some() || matches!(&spec.command, ProcessCommand::Shell { .. }) {
                sandbox.validate_program_visibility(&target_program_path)?;
            }
            for helper in [
                &self.env_program,
                &self.shell,
                &self.sleep_program,
                &self.stat_program,
                &self.findmnt_program,
            ] {
                sandbox.add_isolated_runtime_file(helper)?;
            }
            if let Some((helper, _)) = &pinned_launch {
                sandbox.add_isolated_runtime_file(helper)?;
            }
            sandbox.add_private_runtime_root(&self.runtime_dir)?;
        }
        self.target_program_path = Some(target_program_path);
        let working_directory = sandbox
            .as_ref()
            .map(|sandbox| sandbox.current_dir.clone())
            .unwrap_or_else(|| spec.current_dir.clone());
        let runtime_name = self
            .runtime_dir
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "systemd containment runtime directory name is not valid UTF-8",
                )
            })?;
        let runtime_max = systemd_runtime_max(spec.timeout)?;
        let mut command = Command::new(&self.systemd_run);
        command
            .env_clear()
            .env("XDG_RUNTIME_DIR", &self.client_runtime)
            .args([
                "--user",
                "--quiet",
                "--pipe",
                "--wait",
                "--collect",
                "--service-type=exec",
                "--slice=app.slice",
                "--expand-environment=no",
                "--property=KillMode=control-group",
                "--property=KillSignal=SIGKILL",
                "--property=FinalKillSignal=SIGKILL",
                "--property=ProtectControlGroups=yes",
                "--property=TimeoutStopSec=100ms",
                "--property=RuntimeDirectoryPreserve=no",
                "--property=RuntimeDirectoryMode=0700",
            ])
            .arg(format!("--property=RuntimeDirectory={runtime_name}"))
            .arg(format!(
                "--property=RuntimeMaxSec={}ms",
                runtime_max.as_millis()
            ));
        if let Some(sandbox) = &sandbox {
            apply_systemd_sandbox_properties(&mut command, sandbox);
            command
                .arg(systemd_path_property(
                    "BindPaths=",
                    &self.runtime_dir,
                    false,
                ))
                .arg(systemd_path_property(
                    "ReadWritePaths=",
                    &self.runtime_dir,
                    false,
                ));
        }
        self.sandbox = sandbox;
        command
            .arg("--unit")
            .arg(&self.name)
            .arg("--working-directory")
            .arg(&working_directory)
            .arg("--")
            .arg(&self.env_program)
            .arg("-i")
            .arg(&self.shell)
            .args([
                OsStr::new("-c"),
                OsStr::new(SYSTEMD_GUARDIAN_SCRIPT),
                OsStr::new("maco-containment-guardian"),
            ])
            .arg(&self.environment_file)
            .arg(&self.ready_path)
            .arg(&self.waiting_path)
            .arg(&self.environment_fifo_path)
            .arg(&self.start_fifo_path)
            .arg(&self.target_pid_path)
            .arg(&self.owner_fifo_path)
            .arg(&self.fifo_waiting_path)
            .arg(&self.sleep_program)
            .arg(&self.sandbox_report_path)
            .arg(&self.stat_program)
            .arg(&self.findmnt_program)
            .arg(&self.env_program)
            .arg(if pinned_launch.is_some() {
                "descriptor"
            } else {
                "source"
            })
            .arg(
                self.sandbox
                    .as_ref()
                    .map_or(0, |sandbox| sandbox.mount_checks.len())
                    .to_string(),
            );
        if let Some(sandbox) = &self.sandbox {
            for check in &sandbox.mount_checks {
                command
                    .arg(match check.access {
                        SandboxMountAccess::ReadOnly => "ro",
                        SandboxMountAccess::ReadWrite => "rw",
                        SandboxMountAccess::PrivateRuntime => "rw",
                        SandboxMountAccess::Inaccessible if check.optional => {
                            "inaccessible-optional"
                        }
                        SandboxMountAccess::Inaccessible => "inaccessible-required",
                        SandboxMountAccess::IsolatedRoot => "isolated-root",
                    })
                    .arg(&check.path);
            }
        }
        if let Some((helper, digest)) = pinned_launch {
            command
                .arg(helper)
                .arg(HIDDEN_PINNED_EXEC_ARGUMENT)
                .arg(self.runtime_dir.join(PINNED_EXEC_DESCRIPTOR_NAME))
                .arg(digest);
        } else {
            match &spec.command {
                ProcessCommand::Shell {
                    shell,
                    command: text,
                } => match shell {
                    Shell::UnixSh => {
                        command.arg(&self.shell).arg("-c").arg(text);
                    }
                    Shell::WindowsCmd => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Windows cmd shell cannot run through Linux systemd containment",
                        ));
                    }
                },
                ProcessCommand::Direct { program, args } => {
                    command.arg(program).args(args);
                }
            }
        }
        Ok(command)
    }

    fn confirm_attached(
        &mut self,
        child: &mut Child,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<()> {
        let deadline = bounded_operation_deadline(SYSTEMD_OPERATION_GRACE, operation_deadline)?;
        loop {
            if cancellation.is_cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "systemd containment attachment was cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "systemd transient unit {} did not reach its start gate before the bounded setup deadline",
                        self.name
                    ),
                ));
            }
            if matches!(cgroup_populated(&self.cgroup_path)?, Some(true)) {
                self.observed_owned = true;
            }
            if !self.fifos_prepared && self.fifo_waiting_path.is_file() {
                prepare_systemd_gate_fifos(
                    &self.runtime_dir,
                    &self.fifo_waiting_path,
                    [
                        &self.environment_fifo_path,
                        &self.start_fifo_path,
                        &self.owner_fifo_path,
                    ],
                )?;
                self.fifos_prepared = true;
            }
            if self.observed_owned && self.owner_channel.is_none() && self.owner_fifo_path.exists()
            {
                match open_systemd_owner_fifo(&self.owner_fifo_path) {
                    Ok(channel) => self.owner_channel = Some(channel),
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                    Err(error) => return Err(error),
                }
            }
            if self.owner_channel.is_some()
                && self.waiting_path.is_file()
                && !self.environment_published
            {
                for private_file in std::mem::take(&mut self.pending_runtime_files) {
                    let path = self.runtime_dir.join(&private_file.name);
                    self.runtime_file_paths.push(path.clone());
                    publish_private_runtime_file(&path, &private_file.bytes)?;
                }
                let environment = self.pending_environment.take().ok_or_else(|| {
                    std::io::Error::other("systemd containment omitted pending environment")
                })?;
                publish_systemd_environment_file(&self.environment_file, &environment)?;
                self.environment_published = true;
                #[cfg(test)]
                if let Some(marker) = env::var_os("MACO_TEST_ENVIRONMENT_PUBLISHED_MARKER") {
                    fs::write(marker, b"published")?;
                    while env::var_os("MACO_TEST_HOLD_AFTER_ENVIRONMENT_PUBLISH").is_some() {
                        thread::sleep(POLL_INTERVAL);
                    }
                }
            }
            if self.environment_published && !self.environment_released {
                match signal_systemd_fifo(&self.environment_fifo_path, b"environment\n") {
                    Ok(()) => self.environment_released = true,
                    Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                    Err(error) => return Err(error),
                }
            }
            if self.environment_released && self.ready_path.is_file() {
                if self.sandbox.is_some() && !self.sandbox_verified {
                    self.verify_effective_sandbox()?;
                    self.sandbox_verified = true;
                }
                #[cfg(test)]
                if env::var_os("MACO_TEST_ABORT_BEFORE_START_RELEASE").is_some() {
                    std::process::abort();
                }
                return Ok(());
            }
            if let Some(status) = child.try_wait()? {
                self.launcher_completed = true;
                let startup_output = collect_exited_child_startup_output(child);
                return Err(systemd_launcher_exit_error(
                    status,
                    &startup_output,
                    self.target_program_path.as_deref(),
                    "before transient-unit ownership was observed",
                ));
            }
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }
    }

    fn side_effect_evidence(&self) -> SideEffectConfinementEvidence {
        match &self.sandbox {
            Some(sandbox) if self.sandbox_verified => {
                SideEffectConfinementEvidence::Verified(sandbox.kind)
            }
            Some(sandbox) => SideEffectConfinementEvidence::Unverified(sandbox.kind),
            None => SideEffectConfinementEvidence::TrustedBestEffort(
                SideEffectConfinementProfileKind::TrustedCompatibility,
            ),
        }
    }

    fn verify_effective_sandbox(&self) -> std::io::Result<()> {
        let sandbox = self.sandbox.as_ref().ok_or_else(|| {
            std::io::Error::other("strict sandbox verification omitted requested profile")
        })?;
        sandbox.verify_path_identities()?;
        verify_sandbox_mount_report(&self.sandbox_report_path, &sandbox.mount_checks)?;
        let properties = systemd_show_properties(
            &self.systemctl,
            &self.client_runtime,
            &self.name,
            SYSTEMD_SANDBOX_SHOW_PROPERTIES,
        )?;
        verify_systemd_sandbox_properties(sandbox, &properties, &self.runtime_dir)
    }

    fn release_start_gate(
        &mut self,
        child: &mut Child,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<()> {
        let deadline = bounded_operation_deadline(SYSTEMD_OPERATION_GRACE, operation_deadline)?;
        remove_file_if_present(&self.environment_file).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "failed to remove consumed private environment file before releasing containment gate: {error}"
                ),
            )
        })?;
        remove_file_if_present(&self.owner_fifo_path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("failed to unlink confirmed systemd owner-liveness FIFO: {error}"),
            )
        })?;
        loop {
            if cancellation.is_cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "systemd containment start-gate release was cancelled",
                ));
            }
            match signal_systemd_fifo(&self.start_fifo_path, b"start\n") {
                Ok(()) => return Ok(()),
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                Err(error) => return Err(error),
            }
            if let Some(status) = child.try_wait()? {
                self.launcher_completed = true;
                let startup_output = collect_exited_child_startup_output(child);
                return Err(systemd_launcher_exit_error(
                    status,
                    &startup_output,
                    self.target_program_path.as_deref(),
                    "before the execution gate was released",
                ));
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "systemd transient unit {} did not consume its start gate before the bounded setup deadline",
                        self.name
                    ),
                ));
            }
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }
    }

    fn target_pid(
        &mut self,
        child: &mut Child,
        operation_deadline: Option<Instant>,
        cancellation: &ProcessCancellation,
    ) -> std::io::Result<u32> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let deadline = bounded_operation_deadline(SYSTEMD_OPERATION_GRACE, operation_deadline)?;
        loop {
            if cancellation.is_cancelled() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "systemd target PID capture was cancelled",
                ));
            }
            let mut file = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&self.target_pid_path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if let Some(status) = child.try_wait()? {
                        self.launcher_completed = true;
                        let startup_output = collect_exited_child_startup_output(child);
                        return Err(systemd_launcher_exit_error(
                            status,
                            &startup_output,
                            self.target_program_path.as_deref(),
                            "before target PID publication",
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "systemd target PID was not published before the setup deadline",
                        ));
                    }
                    thread::sleep(IO_CANCEL_POLL_INTERVAL);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let metadata = file.metadata()?;
            // SAFETY: geteuid has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            if !metadata.is_file()
                || metadata.uid() != effective_uid
                || metadata.nlink() != 1
                || metadata.mode() & 0o077 != 0
                || metadata.len() > 32
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "systemd target PID record is not a bounded owner-private regular file",
                ));
            }
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            let pid = contents.trim().parse::<u32>().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("systemd target PID record is invalid: {error}"),
                )
            })?;
            if pid == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "systemd target PID record contains PID 0",
                ));
            }
            let rebound = fs::symlink_metadata(&self.target_pid_path)?;
            if !rebound.is_file()
                || rebound.dev() != metadata.dev()
                || rebound.ino() != metadata.ino()
            {
                return Err(std::io::Error::other(
                    "systemd target PID record changed while it was read",
                ));
            }
            let cgroup_processes = fs::read_to_string(self.cgroup_path.join("cgroup.procs"))?;
            let pid_text = pid.to_string();
            if !cgroup_processes
                .lines()
                .any(|entry| entry.trim() == pid_text)
            {
                return Err(std::io::Error::other(format!(
                    "systemd target PID {pid} is not owned by the prepared containment cgroup"
                )));
            }
            crate::agent_lifecycle::process_start_time(pid)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let descriptor_metadata = file.metadata()?;
            if descriptor_metadata.dev() != metadata.dev()
                || descriptor_metadata.ino() != metadata.ino()
            {
                return Err(std::io::Error::other(
                    "systemd target PID descriptor changed unexpectedly",
                ));
            }
            return Ok(pid);
        }
    }

    fn cleanup(&mut self, _child: &mut Child, label: &str, context: &str) -> TreeCleanup {
        if self.cleaned {
            return TreeCleanup {
                error: None,
                process_tree: ProcessTreeEvidence::VerifiedEmpty(
                    ContainmentBackend::SystemdUserService,
                ),
                side_effects: SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::TrustedCompatibility,
                ),
            };
        }
        let error = self.kill_and_verify(label, context).err().map(|error| {
            format!(
                "{label} {context} could not verify empty systemd containment unit {}: {error}",
                self.name
            )
        });
        if error.is_none() && self.observed_owned {
            self.cleaned = true;
            self.remove_runtime_files();
        }
        TreeCleanup {
            process_tree: if error.is_none() && self.observed_owned {
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService)
            } else {
                ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService)
            },
            side_effects: SideEffectConfinementEvidence::Unverified(
                SideEffectConfinementProfileKind::TrustedCompatibility,
            ),
            error,
        }
    }

    fn rollback_startup(&mut self, label: &str) -> std::io::Result<()> {
        self.owner_channel.take();
        if !self.launcher_spawned {
            self.cleaned = true;
            self.remove_runtime_files();
            return Ok(());
        }
        if self.observed_owned {
            self.kill_and_verify(label, "startup rollback")?;
            self.cleaned = true;
            self.remove_runtime_files();
            return Ok(());
        }
        if self.launcher_completed && cgroup_populated(&self.cgroup_path)?.is_none() {
            self.cleaned = true;
            self.remove_runtime_files();
            return Ok(());
        }
        let status = run_control_command_bounded(
            &self.systemctl,
            [
                OsStr::new("--user"),
                OsStr::new("--no-block"),
                OsStr::new("stop"),
                self.name.as_ref(),
            ],
            "systemctl startup rollback",
            &self.client_runtime,
        )?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "systemctl stop for {} exited with {status}",
                self.name
            )));
        }
        let deadline = Instant::now() + SYSTEMD_OPERATION_GRACE;
        loop {
            match cgroup_populated(&self.cgroup_path)? {
                Some(true) => {
                    self.observed_owned = true;
                    return self.kill_and_verify(label, "startup rollback");
                }
                Some(false) => {
                    self.observed_owned = true;
                }
                None => {
                    self.cleaned = true;
                    self.remove_runtime_files();
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "systemd startup rollback did not collect the transient unit",
                ));
            }
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }
    }

    fn kill_and_verify(&mut self, _label: &str, _context: &str) -> std::io::Result<()> {
        if !self.observed_owned {
            return Err(std::io::Error::other(
                "systemd transient-unit ownership was never observed",
            ));
        }
        self.owner_channel.take();
        if matches!(cgroup_populated(&self.cgroup_path)?, Some(true)) {
            match OpenOptions::new()
                .write(true)
                .open(self.cgroup_path.join("cgroup.kill"))
                .and_then(|mut kill| kill.write_all(b"1\n"))
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        let deadline = Instant::now() + SYSTEMD_OPERATION_GRACE;
        loop {
            match cgroup_populated(&self.cgroup_path)? {
                None => return Ok(()),
                Some(false) if Instant::now() >= deadline => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "cgroup became empty but the transient unit was not collected/inactive after {} ms",
                            SYSTEMD_OPERATION_GRACE.as_millis()
                        ),
                    ));
                }
                Some(false) => wait_for_lifecycle_progress(IO_CANCEL_POLL_INTERVAL),
                Some(true) if Instant::now() >= deadline => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "cgroup remained populated after {} ms",
                            SYSTEMD_OPERATION_GRACE.as_millis()
                        ),
                    ));
                }
                Some(true) => wait_for_lifecycle_progress(IO_CANCEL_POLL_INTERVAL),
            }
        }
    }

    fn remove_runtime_files(&self) {
        for path in &self.runtime_file_paths {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(&self.sandbox_report_path);
        let _ = fs::remove_file(&self.start_fifo_path);
        let _ = fs::remove_file(&self.target_pid_path);
        let _ = fs::remove_file(&self.owner_fifo_path);
        let _ = fs::remove_file(&self.environment_fifo_path);
        let _ = fs::remove_file(&self.fifo_waiting_path);
        let _ = fs::remove_file(&self.waiting_path);
        let _ = fs::remove_file(&self.ready_path);
        let _ = fs::remove_file(&self.environment_file);
        let _ = fs::remove_dir(&self.runtime_dir);
    }
}

#[cfg(target_os = "linux")]
fn systemd_show_properties(
    systemctl: &Path,
    client_runtime: &Path,
    unit: &str,
    names: &[&str],
) -> std::io::Result<BTreeMap<String, String>> {
    let mut args = vec![
        OsString::from("--user"),
        OsString::from("show"),
        OsString::from("--no-pager"),
    ];
    args.extend(
        names
            .iter()
            .map(|name| OsString::from(format!("--property={name}"))),
    );
    args.push(OsString::from(unit));
    let (status, stdout, stderr) = run_control_command_capture_bounded(
        systemctl,
        &args,
        "systemctl sandbox verification",
        client_runtime,
    )?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "systemctl show for {unit} exited with {status}: {}",
            String::from_utf8_lossy(stderr.as_bytes()).trim()
        )));
    }
    if stdout.is_truncated() || stderr.is_truncated() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "systemctl sandbox verification output exceeded its bounded capture",
        ));
    }
    let stdout = std::str::from_utf8(stdout.as_bytes()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("systemctl sandbox verification output was not UTF-8: {error}"),
        )
    })?;
    let properties = stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect::<BTreeMap<_, _>>();
    Ok(properties)
}

#[cfg(target_os = "linux")]
fn run_control_command_capture_bounded(
    program: &Path,
    args: &[OsString],
    label: &str,
    client_runtime: &Path,
) -> std::io::Result<(ExitStatus, CapturedBytes, CapturedBytes)> {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(program);
    command
        .env_clear()
        .env("XDG_RUNTIME_DIR", client_runtime)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("systemctl stdout pipe was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("systemctl stderr pipe was unavailable"))?;
    configure_cancellable_io(&stdout)?;
    configure_cancellable_io(&stderr)?;
    let mut drainers =
        OutputDrainers::start(stdout, stderr, label, 64 * 1024, 64 * 1024, None, None);
    let deadline = Instant::now() + SYSTEMD_OPERATION_GRACE;
    let status = loop {
        let backlog = drainers.drain_ready();
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let cleanup = terminate_unix_process_group(&mut child, false, label);
            let status = wait_for_exit_until(&mut child, Instant::now() + SYSTEMD_OPERATION_GRACE)?
                .unwrap_or_else(|| fail_closed_stuck_owner(label));
            let detail = cleanup.unwrap_or_else(|| {
                format!("{label} exceeded its bounded deadline and was terminated with {status}")
            });
            let _ = finish_output_drainers_after_exit(&mut drainers, EXIT_AND_DRAIN_GRACE);
            let _ = drainers.cancel_incomplete(label);
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, detail));
        }
        if !backlog {
            thread::sleep(POLL_INTERVAL);
        }
    };
    if !finish_output_drainers_after_exit(&mut drainers, EXIT_AND_DRAIN_GRACE) {
        let cleanup = drainers.cancel_incomplete(label);
        return Err(std::io::Error::other(
            cleanup.unwrap_or_else(|| format!("{label} output pipes did not close")),
        ));
    }
    let (stdout, stderr, output_error) = drainers.into_outputs();
    if let Some(error) = output_error {
        return Err(std::io::Error::other(error));
    }
    Ok((status, stdout, stderr))
}

#[cfg(target_os = "linux")]
fn run_control_command_bounded<'a>(
    program: &Path,
    args: impl IntoIterator<Item = &'a OsStr>,
    label: &str,
    client_runtime: &Path,
) -> std::io::Result<ExitStatus> {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(program);
    command
        .env_clear()
        .env("XDG_RUNTIME_DIR", client_runtime)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn()?;
    match wait_for_exit_until(&mut child, Instant::now() + SYSTEMD_OPERATION_GRACE)? {
        Some(status) => Ok(status),
        None => {
            let cleanup = terminate_unix_process_group(&mut child, false, label);
            match wait_for_exit_until(&mut child, Instant::now() + SYSTEMD_OPERATION_GRACE)? {
                Some(status) => {
                    if let Some(cleanup) = cleanup {
                        Err(std::io::Error::other(cleanup))
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("{label} exceeded its bounded deadline and was terminated with {status}"),
                        ))
                    }
                }
                None => fail_closed_stuck_owner(label),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn classify_systemd_namespace_failure(
    status: ExitStatus,
    startup_output: &str,
    program: &Path,
) -> Option<EnvironmentFailure> {
    if status.code() != Some(226) {
        return None;
    }
    let namespace_corroborated = startup_output.to_ascii_uppercase().contains("NAMESPACE");
    let corroboration = if namespace_corroborated {
        "startup output also reported NAMESPACE"
    } else {
        "startup output did not repeat NAMESPACE"
    };
    Some(EnvironmentFailure::sandbox_unavailable(format!(
        "systemd reported exit status 226/NAMESPACE while preparing the sandbox for program {}; namespace setup failed before the program executed ({corroboration})",
        program.display(),
    )))
}

#[cfg(target_os = "linux")]
fn systemd_launcher_exit_error(
    status: ExitStatus,
    startup_output: &str,
    program: Option<&Path>,
    phase: &str,
) -> std::io::Error {
    let program = program.unwrap_or_else(|| Path::new("<unknown sandbox program>"));
    if let Some(failure) = classify_systemd_namespace_failure(status, startup_output, program) {
        return environment_failure_io(failure, false);
    }
    std::io::Error::other(format!(
        "systemd-run exited with {status} {phase}{startup_output}"
    ))
}

#[cfg(target_os = "linux")]
fn collect_exited_child_startup_output(child: &mut Child) -> String {
    fn read(stream: Option<impl Read>) -> String {
        let Some(stream) = stream else {
            return String::new();
        };
        let mut bytes = Vec::new();
        let _ = stream
            .take((PIPE_READ_CHUNK_SIZE * 4) as u64)
            .read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).trim().to_string()
    }

    let stdout = read(child.stdout.take());
    let stderr = read(child.stderr.take());
    let mut details = Vec::new();
    if !stdout.is_empty() {
        details.push(format!("stdout={stdout:?}"));
    }
    if !stderr.is_empty() {
        details.push(format!("stderr={stderr:?}"));
    }
    if details.is_empty() {
        String::new()
    } else {
        format!("; startup output: {}", details.join("; "))
    }
}

#[cfg(target_os = "linux")]
impl Drop for SystemdUnit {
    fn drop(&mut self) {
        if !self.cleaned && self.launcher_spawned {
            if let Err(error) = self.rollback_startup("process") {
                fail_closed_stuck_owner(&format!(
                    "systemd containment drop rollback for {}: {error}",
                    self.name
                ));
            }
        }
        self.remove_runtime_files();
    }
}

#[cfg(target_os = "linux")]
fn systemd_user_manager_cgroup() -> std::io::Result<PathBuf> {
    let contents = fs::read_to_string("/proc/self/cgroup")?;
    delegated_systemd_user_manager_cgroup(&contents)
}

#[cfg(target_os = "linux")]
fn delegated_systemd_user_manager_cgroup(contents: &str) -> std::io::Result<PathBuf> {
    let current = contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "strict containment requires a unified cgroup v2 hierarchy",
            )
        })?;
    let mut manager = PathBuf::from("/");
    for component in Path::new(current).components() {
        let std::path::Component::Normal(component) = component else {
            continue;
        };
        manager.push(component);
        let component = component.to_string_lossy();
        if component.starts_with("user@") && component.ends_with(".service") {
            return Ok(manager);
        }
    }
    Err(environment_failure_io(
        EnvironmentFailure::sandbox_unavailable(format!(
            "current cgroup {current} is not inside a delegated systemd user manager"
        )),
        false,
    ))
}

#[cfg(target_os = "linux")]
fn cgroup_populated(path: &Path) -> std::io::Result<Option<bool>> {
    let events = match fs::read_to_string(path.join("cgroup.events")) {
        Ok(events) => events,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    events
        .lines()
        .find_map(|line| line.strip_prefix("populated "))
        .map(|value| match value {
            "0" => Ok(false),
            "1" => Ok(true),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected cgroup populated value {other:?}"),
            )),
        })
        .transpose()?
        .map(Some)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "cgroup.events omitted populated state",
            )
        })
}

#[cfg(unix)]
fn find_trusted_unix_executable(_name: &str, candidates: &[&str]) -> Option<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    candidates.iter().find_map(|candidate| {
        let canonical = fs::canonicalize(candidate).ok()?;
        let metadata = canonical.metadata().ok()?;
        (metadata.is_file()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o111 != 0
            && metadata.permissions().mode() & 0o022 == 0)
            .then(|| PathBuf::from(candidate))
    })
}

pub(crate) fn trusted_system_executable(
    name: &str,
    candidates: &[&str],
) -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        find_trusted_unix_executable(name, candidates).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "trusted root-owned, non-writable executable {name} was not found at a fixed path"
                ),
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (name, candidates);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "fixed trusted executable resolution is not implemented on this platform",
        ))
    }
}

#[cfg(target_os = "linux")]
fn environment_with_private_runtime_home(
    mode: &EnvironmentMode,
    runtime_dir: &Path,
    set_home: bool,
    set_codex_home: bool,
) -> std::io::Result<EnvironmentMode> {
    let runtime_dir = runtime_dir.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "private systemd runtime HOME is not valid UTF-8: {}",
                runtime_dir.display()
            ),
        )
    })?;
    let (clear, mut values) = match mode {
        EnvironmentMode::Inherit => (false, BTreeMap::new()),
        EnvironmentMode::InheritAndSet(values) => (false, values.clone()),
        EnvironmentMode::ClearAndSet(values) => (true, values.clone()),
    };
    if set_home {
        values.insert("HOME".to_string(), runtime_dir.to_string());
        values.insert("TMPDIR".to_string(), runtime_dir.to_string());
    }
    if set_codex_home {
        values.insert("CODEX_HOME".to_string(), runtime_dir.to_string());
    }
    Ok(if clear {
        EnvironmentMode::ClearAndSet(values)
    } else {
        EnvironmentMode::InheritAndSet(values)
    })
}

#[cfg(target_os = "linux")]
fn effective_environment(mode: &EnvironmentMode) -> BTreeMap<OsString, OsString> {
    let mut environment = match mode {
        EnvironmentMode::Inherit | EnvironmentMode::InheritAndSet(_) => env::vars_os().collect(),
        EnvironmentMode::ClearAndSet(_) => BTreeMap::new(),
    };
    match mode {
        EnvironmentMode::Inherit => {}
        EnvironmentMode::InheritAndSet(values) | EnvironmentMode::ClearAndSet(values) => {
            environment.extend(
                values
                    .iter()
                    .map(|(name, value)| (OsString::from(name), OsString::from(value))),
            );
        }
    }
    environment
}

#[cfg(target_os = "linux")]
fn prepare_systemd_gate_fifos<'a>(
    runtime_dir: &Path,
    waiting_marker: &Path,
    fifo_paths: impl IntoIterator<Item = &'a PathBuf>,
) -> std::io::Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::FileTypeExt, fs::MetadataExt, fs::PermissionsExt};

    let metadata = fs::symlink_metadata(runtime_dir)?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unsafe systemd runtime directory {}", runtime_dir.display()),
        ));
    }
    let waiting_metadata = fs::symlink_metadata(waiting_marker)?;
    if waiting_marker.parent() != Some(runtime_dir)
        || waiting_metadata.file_type().is_symlink()
        || !waiting_metadata.is_file()
        || waiting_metadata.uid() != effective_uid
        || waiting_metadata.permissions().mode() & 0o777 != 0o600
        || waiting_metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "unsafe systemd FIFO-wait marker {}",
                waiting_marker.display()
            ),
        ));
    }

    for path in fifo_paths {
        if path.parent() != Some(runtime_dir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "systemd gate FIFO escaped its private runtime directory",
            ));
        }
        let fifo = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "systemd gate FIFO path contains a NUL byte",
            )
        })?;
        // SAFETY: fifo is a valid NUL-terminated path and the mode contains only permission bits.
        if unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_fifo()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("unsafe systemd gate FIFO {}", path.display()),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_systemd_owner_fifo(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_fifo()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unsafe systemd owner-liveness FIFO {}", path.display()),
        ));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn signal_systemd_fifo(path: &Path, token: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut gate = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = gate.metadata()?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_fifo()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("systemd containment gate {} is not a FIFO", path.display()),
        ));
    }
    gate.write_all(token)
}

#[cfg(target_os = "linux")]
fn remove_file_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn systemd_runtime_max(timeout: Option<Duration>) -> std::io::Result<Duration> {
    match timeout {
        Some(timeout) => timeout
            .checked_add(SYSTEMD_RUNTIME_OVERHEAD)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "process timeout is too large to add the systemd cleanup allowance",
                )
            }),
        None => Ok(SYSTEMD_ORPHAN_SAFETY_FUSE),
    }
}

#[cfg(target_os = "linux")]
fn bounded_operation_deadline(
    platform_grace: Duration,
    operation_deadline: Option<Instant>,
) -> std::io::Result<Instant> {
    let now = Instant::now();
    if operation_deadline.is_some_and(|deadline| now >= deadline) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the total operation deadline was exhausted during containment setup",
        ));
    }
    let platform_deadline = now.checked_add(platform_grace).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "platform containment grace exceeds the Instant range",
        )
    })?;
    Ok(operation_deadline
        .map(|deadline| deadline.min(platform_deadline))
        .unwrap_or(platform_deadline))
}

#[cfg(target_os = "linux")]
pub(crate) fn trusted_linux_runtime_root() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    let user_runtime = PathBuf::from(format!("/run/user/{effective_uid}"));
    if user_runtime.metadata().is_ok_and(|metadata| {
        metadata.is_dir()
            && metadata.uid() == effective_uid
            && metadata.permissions().mode() & 0o077 == 0
    }) {
        return Ok(user_runtime);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "strict systemd containment requires an owner-private /run/user/<uid> runtime root",
    ))
}

#[cfg(target_os = "linux")]
fn validate_private_runtime_files(files: &[PrivateRuntimeFile]) -> std::io::Result<()> {
    if files.len() > MAX_PRIVATE_RUNTIME_FILES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private runtime file vector exceeds its safety bound",
        ));
    }
    let mut names = std::collections::BTreeSet::new();
    for file in files {
        let path = Path::new(&file.name);
        if file.name.is_empty()
            || path.components().count() != 1
            || !matches!(
                path.components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "private runtime filename must be one safe component: {:?}",
                    file.name
                ),
            ));
        }
        if file.bytes.len() > MAX_PRIVATE_RUNTIME_FILE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::FileTooLarge,
                format!(
                    "private runtime file {:?} exceeds the {} byte limit",
                    file.name, MAX_PRIVATE_RUNTIME_FILE_BYTES
                ),
            ));
        }
        if !names.insert(file.name.as_str()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("duplicate private runtime filename {:?}", file.name),
            ));
        }
        if matches!(
            file.name.as_str(),
            "environment"
                | "environment-ready"
                | "guardian-waiting"
                | "environment-gate"
                | "start-gate"
                | "target-pid"
                | "owner-liveness"
                | "fifo-waiting"
                | "sandbox-mount-report"
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("private runtime filename is reserved: {:?}", file.name),
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_private_runtime_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("unsafe private runtime file {}", path.display()),
        ));
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(target_os = "linux")]
fn publish_systemd_environment_file(path: &Path, mode: &EnvironmentMode) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let published = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let effective_uid = unsafe { libc::geteuid() };
        if !metadata.is_file()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("unsafe systemd environment file {}", path.display()),
            ));
        }
        for (name, value) in effective_environment(mode) {
            let name = name.to_str().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "strict systemd containment cannot project a non-UTF-8 environment name",
                )
            })?;
            let valid_name = name.bytes().enumerate().all(|(index, byte)| {
                byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
            });
            if name.is_empty() || !valid_name {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid environment variable name {name:?}"),
                ));
            }
            let value = value.to_str().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("strict systemd containment cannot project non-UTF-8 value for {name}"),
                )
            })?;
            let escaped = value.replace('\'', "'\\''");
            writeln!(file, "{name}='{escaped}'")?;
        }
        file.sync_all()?;
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
    })();
    if published.is_err() {
        let matches = tee_path_matches_file(path, &file).unwrap_or(false);
        drop(file);
        if matches {
            let _ = fs::remove_file(path);
        }
    }
    published
}

#[cfg(unix)]
fn terminate_unix_process_group(
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
) -> Option<String> {
    terminate_unix_process_group_with_wait(
        child,
        child_already_exited,
        label,
        wait_for_lifecycle_progress,
    )
}

#[cfg(unix)]
fn wait_for_lifecycle_progress(duration: Duration) {
    thread::sleep(duration);
}

#[cfg(unix)]
fn terminate_unix_process_group_with_wait<F>(
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
    mut wait: F,
) -> Option<String>
where
    F: FnMut(Duration),
{
    let pid = child.id();
    match send_unix_process_group_signal(pid, libc::SIGTERM) {
        Ok(GroupSignalResult::Sent) => {
            wait(TERMINATE_GRACE);
            match send_unix_process_group_signal(pid, libc::SIGKILL) {
                Ok(GroupSignalResult::Sent | GroupSignalResult::Missing) => None,
                Err(group_error) => direct_child_kill_after_group_error(
                    child,
                    child_already_exited,
                    label,
                    group_error,
                ),
            }
        }
        Ok(GroupSignalResult::Missing) if child_already_exited => None,
        Ok(GroupSignalResult::Missing) if matches!(child.try_wait(), Ok(Some(_))) => None,
        Ok(GroupSignalResult::Missing) => child.kill().err().map(|error| {
            format!("{label} process group was missing and direct process kill failed: {error}")
        }),
        Err(group_error) => {
            direct_child_kill_after_group_error(child, child_already_exited, label, group_error)
        }
    }
}

#[cfg(unix)]
fn direct_child_kill_after_group_error(
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
    group_error: std::io::Error,
) -> Option<String> {
    if child_already_exited || matches!(child.try_wait(), Ok(Some(_))) {
        return Some(format!(
            "{label} process group termination failed: {group_error}"
        ));
    }
    match child.kill() {
        Ok(()) => Some(format!(
            "{label} process group termination failed: {group_error}; direct child was killed"
        )),
        Err(child_error) => Some(format!(
            "{label} process group termination failed: {group_error}; direct process kill failed: {child_error}"
        )),
    }
}

#[cfg(unix)]
enum GroupSignalResult {
    Sent,
    Missing,
}

#[cfg(unix)]
fn send_unix_process_group_signal(
    pid: u32,
    signal: libc::c_int,
) -> std::io::Result<GroupSignalResult> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("process id {pid} cannot be represented as a Unix process group"),
        )
    })?;
    // SAFETY: a negative nonzero pid addresses the child-created process group; no Rust memory is
    // accessed and `signal` is a valid libc signal constant supplied by the caller.
    if unsafe { libc::kill(-pid, signal) } == 0 {
        return Ok(GroupSignalResult::Sent);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(GroupSignalResult::Missing)
    } else {
        Err(error)
    }
}

#[cfg(target_os = "windows")]
struct WindowsJob {
    handle: WindowsOwnedHandle,
}

#[cfg(target_os = "windows")]
impl WindowsJob {
    fn create_and_assign(child: &Child) -> std::io::Result<Self> {
        use std::{mem::size_of, os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::{
            Foundation::HANDLE,
            System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };

        // SAFETY: null security attributes/name request an unnamed job owned by this process.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::other(format!(
                "CreateJobObjectW failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let job = Self {
            handle: WindowsOwnedHandle { handle },
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is initialized for the requested information class and valid for the
        // duration of the call; `job.handle` remains owned by `job`.
        let configured = unsafe {
            SetInformationJobObject(
                job.handle.raw(),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(std::io::Error::other(format!(
                "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let process_handle = child.as_raw_handle() as HANDLE;
        // SAFETY: `process_handle` is borrowed from the live child and `job.handle` is valid.
        if unsafe { AssignProcessToJobObject(job.handle.raw(), process_handle) } == 0 {
            return Err(std::io::Error::other(format!(
                "AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(job)
    }

    fn terminate(&self, label: &str, context: &str) -> Option<String> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: the handle is valid while `self` is alive. The exit code is diagnostic only.
        if unsafe { TerminateJobObject(self.handle.raw(), 1) } != 0 {
            None
        } else {
            Some(format!(
                "{label} {context} failed in TerminateJobObject: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    fn cleanup(
        &self,
        label: &str,
        context: &str,
        side_effects: SideEffectConfinementEvidence,
    ) -> TreeCleanup {
        let error = append_error(
            self.terminate(label, context),
            self.wait_until_empty(label, context),
        );
        TreeCleanup {
            process_tree: if error.is_none() {
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::WindowsJobObject)
            } else {
                ProcessTreeEvidence::Unverified(ContainmentBackend::WindowsJobObject)
            },
            side_effects,
            error,
        }
    }

    fn wait_until_empty(&self, label: &str, context: &str) -> Option<String> {
        use std::{mem::size_of, ptr};
        use windows_sys::Win32::System::JobObjects::{
            JobObjectBasicAccountingInformation, QueryInformationJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        };

        let deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
        loop {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            // SAFETY: `accounting` is valid writable storage for the requested information class.
            let queried = unsafe {
                QueryInformationJobObject(
                    self.handle.raw(),
                    JobObjectBasicAccountingInformation,
                    ptr::from_mut(&mut accounting).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    ptr::null_mut(),
                )
            };
            if queried == 0 {
                return Some(format!(
                    "{label} {context} failed to query Windows Job emptiness: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if accounting.ActiveProcesses == 0 {
                return None;
            }
            if Instant::now() >= deadline {
                return Some(format!(
                    "{label} {context} Windows Job remained populated after {} ms",
                    EXIT_AND_DRAIN_GRACE.as_millis()
                ));
            }
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }
    }
}

#[cfg(target_os = "windows")]
struct WindowsOwnedHandle {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(target_os = "windows")]
impl WindowsOwnedHandle {
    fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.handle
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsOwnedHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        // SAFETY: this RAII owner closes its valid handle exactly once.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

#[cfg(target_os = "windows")]
fn resume_suspended_child(child: &Child) -> std::io::Result<()> {
    use std::mem::size_of;
    use windows_sys::Win32::{
        Foundation::{ERROR_NO_MORE_FILES, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                THREADENTRY32,
            },
            Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
        },
    };

    // SAFETY: the snapshot API has no borrowed pointer inputs and returns an owned handle.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other(format!(
            "CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let snapshot = WindowsOwnedHandle { handle: snapshot };
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..THREADENTRY32::default()
    };
    // SAFETY: `entry` is correctly sized writable storage and the snapshot handle is valid.
    if unsafe { Thread32First(snapshot.raw(), &mut entry) } == 0 {
        return Err(std::io::Error::other(format!(
            "Thread32First failed while locating suspended child thread: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut thread_ids = Vec::new();
    loop {
        if entry.th32OwnerProcessID == child.id() {
            thread_ids.push(entry.th32ThreadID);
        }
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        // SAFETY: the same valid snapshot and writable entry storage are reused for iteration.
        if unsafe { Thread32Next(snapshot.raw(), &mut entry) } != 0 {
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
            return Err(std::io::Error::other(format!(
                "Thread32Next failed while locating suspended child thread: {error}"
            )));
        }
        break;
    }
    if thread_ids.len() != 1 {
        return Err(std::io::Error::other(format!(
            "expected exactly one suspended primary thread for child {}, found {}",
            child.id(),
            thread_ids.len()
        )));
    }

    // SAFETY: the enumerated thread id belongs to the still-suspended child process; the returned
    // handle is owned locally and is not inheritable.
    let thread_handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_ids[0]) };
    if thread_handle.is_null() {
        return Err(std::io::Error::other(format!(
            "OpenThread(THREAD_SUSPEND_RESUME) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let thread_handle = WindowsOwnedHandle {
        handle: thread_handle,
    };
    // SAFETY: the handle identifies the unique suspended primary thread owned by the child.
    let previous_suspend_count = unsafe { ResumeThread(thread_handle.raw()) };
    if previous_suspend_count == u32::MAX {
        return Err(std::io::Error::other(format!(
            "ResumeThread failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    if previous_suspend_count != 1 {
        return Err(std::io::Error::other(format!(
            "ResumeThread observed unexpected suspend count {previous_suspend_count}; refusing to run child"
        )));
    }
    Ok(())
}

fn wait_for_exit_until(
    child: &mut Child,
    deadline: Instant,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn append_error(existing: Option<String>, next: Option<String>) -> Option<String> {
    match (existing, next) {
        (Some(existing), Some(next)) => Some(format!("{existing}; {next}")),
        (Some(existing), None) => Some(existing),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

struct PreparedChildIo {
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

impl PreparedChildIo {
    fn take(child: &mut Child, stdin_mode: &StdinMode) -> std::io::Result<Self> {
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("failed to open child stdout pipe"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("failed to open child stderr pipe"))?;
        let stdin = if matches!(stdin_mode, StdinMode::Bytes(_) | StdinMode::Interactive) {
            Some(
                child
                    .stdin
                    .take()
                    .ok_or_else(|| std::io::Error::other("failed to open child stdin pipe"))?,
            )
        } else {
            None
        };

        configure_cancellable_io(&stdout)?;
        configure_cancellable_io(&stderr)?;
        if let Some(stdin) = &stdin {
            configure_cancellable_io(stdin)?;
        }
        Ok(Self {
            stdin,
            stdout,
            stderr,
        })
    }

    fn start(
        self,
        label: &str,
        stdin_mode: StdinMode,
        stdout_limit: usize,
        stderr_limit: usize,
        stdout_tee: Option<TeeWriter>,
        stderr_tee: Option<TeeWriter>,
    ) -> (InputWriter, OutputDrainers) {
        let input_writer = InputWriter::start(self.stdin, label, stdin_mode);
        let output_drainers = OutputDrainers::start(
            self.stdout,
            self.stderr,
            label,
            stdout_limit,
            stderr_limit,
            stdout_tee,
            stderr_tee,
        );
        (input_writer, output_drainers)
    }

    #[allow(clippy::too_many_arguments)]
    fn start_interactive<'a>(
        self,
        label: &str,
        cancellation: &'a ProcessCancellation,
        operation_deadline: Option<Instant>,
        max_stdin_bytes: usize,
        stdout_limit: usize,
        stderr_limit: usize,
        stdout_tee: Option<TeeWriter>,
        stderr_tee: Option<TeeWriter>,
    ) -> std::io::Result<ContainedProcessSession<'a>> {
        let stdin = self.stdin.ok_or_else(|| {
            std::io::Error::other("failed to open contained interactive stdin pipe")
        })?;
        Ok(ContainedProcessSession {
            label: label.to_string(),
            cancellation,
            operation_deadline,
            stdin: Some(stdin),
            stdin_bytes_written: 0,
            max_stdin_bytes,
            pending_stdout: Vec::new(),
            stdout_eof: false,
            io_error: None,
            output_drainers: OutputDrainers::start(
                self.stdout,
                self.stderr,
                label,
                stdout_limit,
                stderr_limit,
                stdout_tee,
                stderr_tee,
            ),
        })
    }
}

/// Borrowed line-oriented access to one contained child.
///
/// All fields are private and the value is constructed only after containment attachment and the
/// start gate. The callback receives `&mut ContainedProcessSession`, so neither this value nor any
/// stdio handle can be retained after [`run_process_interactive`] returns.
pub(crate) struct ContainedProcessSession<'a> {
    label: String,
    cancellation: &'a ProcessCancellation,
    operation_deadline: Option<Instant>,
    stdin: Option<ChildStdin>,
    stdin_bytes_written: usize,
    max_stdin_bytes: usize,
    pending_stdout: Vec<u8>,
    stdout_eof: bool,
    io_error: Option<String>,
    output_drainers: OutputDrainers,
}

impl ContainedProcessSession<'_> {
    pub(crate) fn receive_line(
        &mut self,
        wait: Duration,
        max_line_bytes: usize,
        destination: &mut Vec<u8>,
    ) -> Result<InteractiveProcessRead, String> {
        destination.clear();
        if max_line_bytes == 0 || max_line_bytes > MAX_REQUIRED_STREAM_BYTES {
            return self.fail_io("interactive line bound is zero or exceeds the hard ceiling");
        }
        if let Some(line) = self.take_pending_line(max_line_bytes)? {
            destination.extend_from_slice(&line);
            return Ok(InteractiveProcessRead::Line);
        }
        if self.stdout_eof {
            return Ok(InteractiveProcessRead::Eof);
        }

        let requested_deadline = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        let deadline = self
            .operation_deadline
            .map_or(requested_deadline, |operation| {
                operation.min(requested_deadline)
            });
        loop {
            self.ensure_interactive_live()?;
            let now = Instant::now();
            if now >= deadline {
                return Ok(InteractiveProcessRead::Timeout);
            }
            self.output_drainers.stderr.drain_ready(&self.label);
            let remaining = deadline.saturating_duration_since(now);
            match self
                .output_drainers
                .stdout
                .receive_interactive(remaining, &self.label)?
            {
                InteractivePipeRead::Chunk(chunk) => {
                    self.pending_stdout.extend_from_slice(&chunk);
                    if let Some(line) = self.take_pending_line(max_line_bytes)? {
                        destination.extend_from_slice(&line);
                        return Ok(InteractiveProcessRead::Line);
                    }
                }
                InteractivePipeRead::Timeout => return Ok(InteractiveProcessRead::Timeout),
                InteractivePipeRead::Eof => {
                    self.stdout_eof = true;
                    if self.pending_stdout.is_empty() {
                        return Ok(InteractiveProcessRead::Eof);
                    }
                    if self.pending_stdout.len() > max_line_bytes {
                        return self.fail_io(
                            "contained interactive message exceeded its configured line bound",
                        );
                    }
                    destination.extend_from_slice(&self.pending_stdout);
                    self.pending_stdout.clear();
                    return Ok(InteractiveProcessRead::Line);
                }
            }
        }
    }

    pub(crate) fn send_line(&mut self, line: &[u8]) -> Result<(), String> {
        if line.contains(&b'\n') || line.contains(&b'\r') {
            return self.fail_io("contained interactive line contains a raw newline");
        }
        let framed_len = line.len().checked_add(1).ok_or_else(|| {
            "contained interactive stdin byte count overflowed its bound".to_string()
        })?;
        let next_total = self
            .stdin_bytes_written
            .checked_add(framed_len)
            .ok_or_else(|| {
                "contained interactive stdin byte count overflowed its bound".to_string()
            })?;
        if next_total > self.max_stdin_bytes {
            return self
                .fail_io("contained interactive stdin exceeded its configured aggregate bound");
        }
        let mut framed = Vec::with_capacity(framed_len);
        framed.extend_from_slice(line);
        framed.push(b'\n');
        let mut written = 0usize;
        while written < framed.len() {
            self.ensure_interactive_live()?;
            self.output_drainers.stderr.drain_ready(&self.label);
            let Some(stdin) = self.stdin.as_mut() else {
                return self.fail_io("contained interactive stdin was already closed");
            };
            match stdin.write(&framed[written..]) {
                Ok(0) => {
                    return self
                        .fail_io("contained interactive stdin returned a zero-length write");
                }
                Ok(count) => written = written.saturating_add(count),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(IO_CANCEL_POLL_INTERVAL);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return self.fail_io(format!(
                        "failed to write contained interactive stdin: {error}"
                    ));
                }
            }
        }
        self.stdin_bytes_written = next_total;
        Ok(())
    }

    fn take_pending_line(&mut self, max_line_bytes: usize) -> Result<Option<Vec<u8>>, String> {
        let Some(newline) = self.pending_stdout.iter().position(|byte| *byte == b'\n') else {
            if self.pending_stdout.len() > max_line_bytes {
                return self
                    .fail_io("contained interactive message exceeded its configured line bound");
            }
            return Ok(None);
        };
        if newline > max_line_bytes {
            return self
                .fail_io("contained interactive message exceeded its configured line bound");
        }
        let mut line = self.pending_stdout.drain(..=newline).collect::<Vec<_>>();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(Some(line))
    }

    fn ensure_interactive_live(&mut self) -> Result<(), String> {
        if self.cancellation.is_cancelled() {
            return self.fail_io("contained interactive session was cancelled");
        }
        if self
            .operation_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return self.fail_io("contained interactive session reached its operation deadline");
        }
        Ok(())
    }

    fn fail_io<T>(&mut self, message: impl Into<String>) -> Result<T, String> {
        let message = message.into();
        if self.io_error.is_none() {
            self.io_error = Some(message.clone());
        }
        Err(message)
    }

    fn into_runner_io(mut self) -> (InputWriter, OutputDrainers) {
        drop(self.stdin.take());
        (InputWriter::completed(self.io_error), self.output_drainers)
    }
}

#[cfg(unix)]
fn configure_cancellable_io<T: std::os::fd::AsRawFd>(io: &T) -> std::io::Result<()> {
    let fd = io.as_raw_fd();
    // SAFETY: `fd` is borrowed from a live child pipe and both fcntl operations preserve ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the same live descriptor is updated only to add nonblocking mode.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn configure_cancellable_io<T>(_io: &T) -> std::io::Result<()> {
    Ok(())
}

#[derive(Debug, Error)]
enum IoThreadCleanupError {
    #[error("{label} synchronous I/O cancellation failed: {source}")]
    Cancellation {
        label: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{label} thread panicked during cleanup")]
    Panicked { label: String },
}

struct OwnedIoThread {
    handle: thread::JoinHandle<()>,
    cancel: Arc<AtomicBool>,
}

trait IoThreadClock {
    type Deadline;

    fn deadline_after(&self, duration: Duration) -> Self::Deadline;
    fn before(&self, deadline: &Self::Deadline) -> bool;
    fn wait(&self, duration: Duration);
}

struct RealIoThreadClock;

impl IoThreadClock for RealIoThreadClock {
    type Deadline = Instant;

    fn deadline_after(&self, duration: Duration) -> Self::Deadline {
        Instant::now()
            .checked_add(duration)
            .unwrap_or_else(Instant::now)
    }

    fn before(&self, deadline: &Self::Deadline) -> bool {
        Instant::now() < *deadline
    }

    fn wait(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// Unit-test finalization advances by the waits the poller requested, excluding time when the
/// poller itself was descheduled by unrelated host load. Production always uses
/// `RealIoThreadClock`, while focused deadline tests can inject their own clocks directly.
#[cfg(test)]
#[derive(Default)]
struct TestIoFinalizationClock {
    elapsed: std::cell::Cell<Duration>,
}

#[cfg(test)]
impl IoThreadClock for TestIoFinalizationClock {
    type Deadline = Duration;

    fn deadline_after(&self, duration: Duration) -> Self::Deadline {
        self.elapsed.get().saturating_add(duration)
    }

    fn before(&self, deadline: &Self::Deadline) -> bool {
        self.elapsed.get() < *deadline
    }

    fn wait(&self, duration: Duration) {
        thread::sleep(duration);
        self.elapsed
            .set(self.elapsed.get().saturating_add(duration));
    }
}

impl OwnedIoThread {
    fn request_cancel(&self, label: &str) -> Option<IoThreadCleanupError> {
        self.cancel.store(true, Ordering::Release);
        cancel_synchronous_io(&self.handle)
            .err()
            .map(|source| IoThreadCleanupError::Cancellation {
                label: label.to_string(),
                source,
            })
    }

    fn finish(self, completion_observed: bool, label: &str) -> Vec<IoThreadCleanupError> {
        self.finish_with_clock(completion_observed, label, &RealIoThreadClock)
    }

    fn finish_with_clock<C: IoThreadClock>(
        self,
        completion_observed: bool,
        label: &str,
        clock: &C,
    ) -> Vec<IoThreadCleanupError> {
        let mut errors = Vec::new();
        if !completion_observed {
            if let Some(error) = self.request_cancel(label) {
                errors.push(error);
            }
        }
        let Self { handle, .. } = self;
        let deadline = clock.deadline_after(THREAD_JOIN_GRACE);
        while !handle.is_finished() && clock.before(&deadline) {
            clock.wait(IO_CANCEL_POLL_INTERVAL);
        }
        if !handle.is_finished() {
            fail_closed_stuck_owner(label);
        }
        if handle.join().is_err() {
            errors.push(IoThreadCleanupError::Panicked {
                label: label.to_string(),
            });
        }
        errors
    }
}

#[cfg(target_os = "windows")]
fn cancel_synchronous_io(handle: &thread::JoinHandle<()>) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Foundation::ERROR_NOT_FOUND, System::IO::CancelSynchronousIo};

    let deadline = Instant::now() + THREAD_JOIN_GRACE;
    loop {
        if handle.is_finished() {
            return Ok(());
        }
        // SAFETY: the raw handle is borrowed from the live owned JoinHandle and identifies the
        // exact thread whose synchronous pipe operation must be cancelled.
        if unsafe { CancelSynchronousIo(handle.as_raw_handle().cast()) } != 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "thread never exposed a cancellable synchronous I/O operation",
            ));
        }
        thread::sleep(IO_CANCEL_POLL_INTERVAL);
    }
}

#[cfg(not(target_os = "windows"))]
fn cancel_synchronous_io(_handle: &thread::JoinHandle<()>) -> std::io::Result<()> {
    Ok(())
}

fn cleanup_errors(errors: Vec<IoThreadCleanupError>) -> Option<String> {
    let errors = errors
        .into_iter()
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    (!errors.is_empty()).then(|| errors.join("; "))
}

struct InputWriter {
    state: InputWriterState,
}

enum InputWriterState {
    None,
    Complete {
        error: Option<String>,
    },
    Thread {
        receiver: Receiver<Option<String>>,
        thread: OwnedIoThread,
        error: Option<String>,
        complete: bool,
    },
}

impl InputWriter {
    fn completed(error: Option<String>) -> Self {
        Self {
            state: InputWriterState::Complete { error },
        }
    }

    fn start(child_stdin: Option<ChildStdin>, label: &str, stdin: StdinMode) -> Self {
        let StdinMode::Bytes(input) = stdin else {
            return Self {
                state: InputWriterState::None,
            };
        };
        let Some(mut child_stdin) = child_stdin else {
            return Self {
                state: InputWriterState::Complete {
                    error: Some(format!("failed to open {label} stdin")),
                },
            };
        };
        let (sender, receiver) = mpsc::channel();
        let label = label.to_string();
        let cancel = Arc::new(AtomicBool::new(false));
        let thread_cancel = Arc::clone(&cancel);
        let handle = thread::spawn(move || {
            let error = write_stdin_cancellable(&mut child_stdin, &input, &thread_cancel, &label);
            let _ = sender.send(error);
        });
        Self {
            state: InputWriterState::Thread {
                receiver,
                thread: OwnedIoThread { handle, cancel },
                error: None,
                complete: false,
            },
        }
    }

    fn drain_ready(&mut self) {
        let InputWriterState::Thread {
            receiver,
            error,
            complete,
            ..
        } = &mut self.state
        else {
            return;
        };
        if *complete {
            return;
        }
        match receiver.try_recv() {
            Ok(next_error) => {
                *error = next_error;
                *complete = true;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                *error = Some("stdin writer thread stopped unexpectedly".to_string());
                *complete = true;
            }
        }
    }

    fn is_complete(&self) -> bool {
        match &self.state {
            InputWriterState::None | InputWriterState::Complete { .. } => true,
            InputWriterState::Thread { complete, .. } => *complete,
        }
    }

    fn finish_with_clock<C: IoThreadClock>(&mut self, clock: &C, deadline: &C::Deadline) -> bool {
        loop {
            self.drain_ready();
            if self.is_complete() {
                return true;
            }
            if !clock.before(deadline) {
                return false;
            }
            clock.wait(POLL_INTERVAL);
        }
    }

    fn cancel_incomplete(&mut self, label: &str) -> Option<String> {
        let InputWriterState::Thread {
            thread, complete, ..
        } = &self.state
        else {
            return None;
        };
        if *complete {
            None
        } else {
            cleanup_errors(
                thread
                    .request_cancel(&format!("{label} stdin writer"))
                    .into_iter()
                    .collect(),
            )
        }
    }

    fn into_result(self, label: &str) -> (Option<String>, Option<String>) {
        match self.state {
            InputWriterState::None => (None, None),
            InputWriterState::Complete { error } => (error, None),
            InputWriterState::Thread {
                receiver,
                thread,
                mut error,
                complete,
            } => {
                let cleanup_error =
                    cleanup_errors(thread.finish(complete, &format!("{label} stdin writer")));
                if !complete {
                    match receiver.try_recv() {
                        Ok(next_error) => error = next_error,
                        Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
                    }
                }
                (error, cleanup_error)
            }
        }
    }
}

fn write_stdin_cancellable(
    child_stdin: &mut ChildStdin,
    input: &[u8],
    cancel: &AtomicBool,
    label: &str,
) -> Option<String> {
    let mut written = 0;
    while written < input.len() {
        if cancel.load(Ordering::Acquire) {
            return Some(format!(
                "cancelled {label} stdin after writing {written} of {} bytes",
                input.len()
            ));
        }
        match child_stdin.write(&input[written..]) {
            Ok(0) => {
                return Some(format!(
                    "failed to write {label} stdin: write returned zero after {written} bytes"
                ));
            }
            Ok(bytes) => written += bytes,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(IO_CANCEL_POLL_INTERVAL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if cancel.load(Ordering::Acquire) => {
                return Some(format!(
                    "cancelled {label} stdin after writing {written} of {} bytes: {error}",
                    input.len()
                ));
            }
            Err(error) => return Some(format!("failed to write {label} stdin: {error}")),
        }
    }
    None
}

struct OutputDrainers {
    stdout: PipeReader,
    stderr: PipeReader,
    label: String,
}

impl OutputDrainers {
    fn start(
        stdout: ChildStdout,
        stderr: ChildStderr,
        label: &str,
        stdout_limit: usize,
        stderr_limit: usize,
        stdout_tee: Option<TeeWriter>,
        stderr_tee: Option<TeeWriter>,
    ) -> Self {
        Self {
            stdout: start_pipe_reader("stdout", stdout, stdout_tee, label, stdout_limit),
            stderr: start_pipe_reader("stderr", stderr, stderr_tee, label, stderr_limit),
            label: label.to_string(),
        }
    }

    fn drain_ready(&mut self) -> bool {
        let stdout_backlog = self.stdout.drain_ready(&self.label);
        let stderr_backlog = self.stderr.drain_ready(&self.label);
        stdout_backlog || stderr_backlog
    }

    fn is_complete(&self) -> bool {
        self.stdout.complete && self.stderr.complete
    }

    fn finish_with_clock<C: IoThreadClock>(&mut self, clock: &C, deadline: &C::Deadline) -> bool {
        loop {
            let backlog = self.drain_ready();
            if self.is_complete() {
                return true;
            }
            if !clock.before(deadline) {
                return false;
            }
            if !backlog {
                clock.wait(POLL_INTERVAL);
            }
        }
    }

    fn cancel_incomplete(&mut self, label: &str) -> Option<String> {
        append_error(
            self.stdout.cancel_incomplete(label),
            self.stderr.cancel_incomplete(label),
        )
    }

    fn into_outputs(self) -> (CapturedBytes, CapturedBytes, Option<String>) {
        let (stdout, stdout_error) = self.stdout.into_output(&self.label);
        let (stderr, stderr_error) = self.stderr.into_output(&self.label);
        (stdout, stderr, append_error(stdout_error, stderr_error))
    }
}

struct PipeReader {
    stream: &'static str,
    receiver: Option<Receiver<PipeReadEvent>>,
    thread: Option<OwnedIoThread>,
    tee_helper: Option<TeeHelperHandle>,
    capture: BoundedBuffer,
    complete: bool,
    error: Option<String>,
}

enum InteractivePipeRead {
    Chunk(Vec<u8>),
    Timeout,
    Eof,
}

impl PipeReader {
    fn receive_interactive(
        &mut self,
        wait: Duration,
        label: &str,
    ) -> Result<InteractivePipeRead, String> {
        if self.complete {
            return match &self.error {
                Some(error) => Err(error.clone()),
                None => Ok(InteractivePipeRead::Eof),
            };
        }
        let deadline = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        loop {
            let Some(receiver) = &self.receiver else {
                let message = format!("{label} {} receiver is unavailable", self.stream);
                self.error = Some(message.clone());
                self.complete = true;
                return Err(message);
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = match receiver.recv_timeout(remaining) {
                Ok(event) => event,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Ok(InteractivePipeRead::Timeout);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let message =
                        format!("{label} {} reader thread stopped unexpectedly", self.stream);
                    self.error = Some(message.clone());
                    self.complete = true;
                    return Err(message);
                }
            };
            match event {
                PipeReadEvent::Chunk(chunk) => {
                    self.capture.push(&chunk);
                    return Ok(InteractivePipeRead::Chunk(chunk));
                }
                PipeReadEvent::Finished => {
                    self.complete = true;
                    return Ok(InteractivePipeRead::Eof);
                }
                PipeReadEvent::Error(error) => {
                    self.error = Some(error.clone());
                    self.complete = true;
                    return Err(error);
                }
                PipeReadEvent::TeeLimitExceeded(error) => {
                    self.error = append_error(self.error.take(), Some(error));
                    if Instant::now() >= deadline {
                        return Ok(InteractivePipeRead::Timeout);
                    }
                }
            }
        }
    }

    fn cancel_incomplete(&mut self, label: &str) -> Option<String> {
        if self.complete {
            return None;
        }
        self.thread.as_ref().and_then(|thread| {
            cleanup_errors(
                thread
                    .request_cancel(&format!("{label} {} reader", self.stream))
                    .into_iter()
                    .collect(),
            )
        })
    }

    fn drain_ready(&mut self, label: &str) -> bool {
        let Some(receiver) = &self.receiver else {
            return false;
        };
        let mut processed = 0;
        while !self.complete && processed < MAX_PIPE_EVENTS_PER_POLL {
            match receiver.try_recv() {
                Ok(PipeReadEvent::Chunk(chunk)) => {
                    processed += 1;
                    self.capture.push(&chunk);
                }
                Ok(PipeReadEvent::Finished) => {
                    processed += 1;
                    self.complete = true;
                }
                Ok(PipeReadEvent::Error(error)) => {
                    processed += 1;
                    self.error = Some(error);
                    self.complete = true;
                }
                Ok(PipeReadEvent::TeeLimitExceeded(error)) => {
                    processed += 1;
                    self.error = append_error(self.error.take(), Some(error));
                }
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => {
                    self.error = Some(format!(
                        "{label} {} reader thread stopped unexpectedly",
                        self.stream
                    ));
                    self.complete = true;
                }
            }
        }
        !self.complete && processed == MAX_PIPE_EVENTS_PER_POLL
    }

    fn into_output(mut self, label: &str) -> (CapturedBytes, Option<String>) {
        let cleanup_error = self.thread.take().and_then(|thread| {
            cleanup_errors(thread.finish(self.complete, &format!("{label} {} reader", self.stream)))
        });
        self.drain_after_join();
        let tee_error = self
            .tee_helper
            .take()
            .and_then(|helper| helper.finish(label, self.stream));
        (
            self.capture.into_captured(),
            append_error(append_error(self.error, cleanup_error), tee_error),
        )
    }

    fn drain_after_join(&mut self) {
        let Some(receiver) = &self.receiver else {
            return;
        };
        loop {
            match receiver.try_recv() {
                Ok(PipeReadEvent::Chunk(chunk)) => self.capture.push(&chunk),
                Ok(PipeReadEvent::Finished) => self.complete = true,
                Ok(PipeReadEvent::Error(error)) => {
                    self.error = Some(error);
                    self.complete = true;
                }
                Ok(PipeReadEvent::TeeLimitExceeded(error)) => {
                    self.error = append_error(self.error.take(), Some(error));
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
    }
}

enum PipeReadEvent {
    Chunk(Vec<u8>),
    Finished,
    Error(String),
    TeeLimitExceeded(String),
}

fn start_pipe_reader<R>(
    stream: &'static str,
    mut reader: R,
    tee: Option<TeeWriter>,
    label: &str,
    capture_limit: usize,
) -> PipeReader
where
    R: Read + Send + 'static,
{
    let (mut tee, tee_helper, tee_path) = match tee {
        Some(tee) => {
            let (sink, helper, path) = tee.split();
            (Some(sink), helper, Some(path))
        }
        None => (None, None, None),
    };
    let (sender, receiver) = mpsc::sync_channel(PIPE_CHANNEL_CAPACITY);
    let label = label.to_string();
    let cancel = Arc::new(AtomicBool::new(false));
    let thread_cancel = Arc::clone(&cancel);
    let handle = thread::spawn(move || loop {
        let mut buffer = vec![0_u8; PIPE_READ_CHUNK_SIZE];
        if thread_cancel.load(Ordering::Acquire) {
            break;
        }
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = send_pipe_event(&sender, &thread_cancel, PipeReadEvent::Finished);
                break;
            }
            Ok(bytes_read) => {
                buffer.truncate(bytes_read);
                if let Some(tee) = tee.as_mut() {
                    match tee.write_all_cancellable(&buffer, &thread_cancel) {
                        Ok(true) => {
                            let _ = send_pipe_event(
                                &sender,
                                &thread_cancel,
                                PipeReadEvent::TeeLimitExceeded(format!(
                                    "{label} {stream} tee {} exceeded its configured byte limit",
                                    tee_path
                                        .as_deref()
                                        .map(Path::display)
                                        .map(|path| path.to_string())
                                        .unwrap_or_else(|| "<unknown>".to_string())
                                )),
                            );
                        }
                        Ok(false) => {}
                        Err(error) => {
                            if thread_cancel.load(Ordering::Acquire) {
                                break;
                            }
                            if send_pipe_event(
                                &sender,
                                &thread_cancel,
                                PipeReadEvent::Chunk(buffer),
                            )
                            .is_ok()
                            {
                                let _ = send_pipe_event(
                                    &sender,
                                    &thread_cancel,
                                    PipeReadEvent::Error(format!(
                                        "failed to write {label} {stream} tee {}: {error}",
                                        tee_path
                                            .as_deref()
                                            .map(Path::display)
                                            .map(|path| path.to_string())
                                            .unwrap_or_else(|| "<unknown>".to_string())
                                    )),
                                );
                            }
                            break;
                        }
                    }
                }
                if send_pipe_event(&sender, &thread_cancel, PipeReadEvent::Chunk(buffer)).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(IO_CANCEL_POLL_INTERVAL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_error) if thread_cancel.load(Ordering::Acquire) => break,
            Err(error) => {
                let _ = send_pipe_event(
                    &sender,
                    &thread_cancel,
                    PipeReadEvent::Error(format!("failed to read {label} {stream}: {error}")),
                );
                break;
            }
        }
    });

    PipeReader {
        stream,
        receiver: Some(receiver),
        thread: Some(OwnedIoThread { handle, cancel }),
        tee_helper,
        capture: BoundedBuffer::new(capture_limit),
        complete: false,
        error: None,
    }
}

fn send_pipe_event(
    sender: &SyncSender<PipeReadEvent>,
    cancel: &AtomicBool,
    mut event: PipeReadEvent,
) -> Result<(), ()> {
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(());
        }
        match sender.try_send(event) {
            Ok(()) => return Ok(()),
            Err(TrySendError::Full(next)) => {
                event = next;
                thread::sleep(IO_CANCEL_POLL_INTERVAL);
            }
            Err(TrySendError::Disconnected(_)) => return Err(()),
        }
    }
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(PIPE_READ_CHUNK_SIZE)),
            limit,
            truncated: false,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        let remaining = self.limit.saturating_sub(self.bytes.len());
        let keep = remaining.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..keep]);
        if keep < chunk.len() {
            self.truncated = true;
        }
    }

    fn into_captured(self) -> CapturedBytes {
        CapturedBytes {
            bytes: self.bytes,
            truncated: self.truncated,
        }
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}
