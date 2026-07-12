use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const PIPE_READ_CHUNK_SIZE: usize = 8 * 1024;
const PIPE_CHANNEL_CAPACITY: usize = 8;
const MAX_PIPE_EVENTS_PER_POLL: usize = PIPE_CHANNEL_CAPACITY * 2;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const THREAD_JOIN_GRACE: Duration = Duration::from_millis(50);
const IO_CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(unix)]
const TERMINATE_GRACE: Duration = Duration::from_millis(100);
const EXIT_AND_DRAIN_GRACE: Duration = Duration::from_millis(500);
static NEXT_TEE_BACKUP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    UnixSh,
    WindowsCmd,
}

impl Shell {
    pub const fn for_current_platform() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::WindowsCmd
        }

        #[cfg(not(target_os = "windows"))]
        {
            Self::UnixSh
        }
    }

    fn command(self, command_text: &str) -> Command {
        match self {
            Self::UnixSh => {
                let mut command = Command::new("sh");
                command.arg("-c").arg(command_text);
                command
            }
            Self::WindowsCmd => {
                let mut command = Command::new("cmd");
                command.arg("/C").arg(command_text);
                command
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessCommand {
    Shell {
        shell: Shell,
        command: String,
    },
    Direct {
        program: PathBuf,
        args: Vec<OsString>,
    },
}

impl ProcessCommand {
    fn build(&self) -> Command {
        match self {
            Self::Shell { shell, command } => shell.command(command),
            Self::Direct { program, args } => {
                let mut command = Command::new(program);
                command.args(args);
                command
            }
        }
    }

    fn display(&self) -> String {
        match self {
            Self::Shell { shell, command } => match shell {
                Shell::UnixSh => format!("sh -c {command}"),
                Shell::WindowsCmd => format!("cmd /C {command}"),
            },
            Self::Direct { program, args } => {
                let mut parts = Vec::with_capacity(args.len() + 1);
                parts.push(program.display().to_string());
                parts.extend(
                    args.iter()
                        .map(|argument| argument.to_string_lossy().into_owned()),
                );
                parts.join(" ")
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum EnvironmentMode {
    #[default]
    Inherit,
    InheritAndSet(BTreeMap<String, String>),
    ClearAndSet(BTreeMap<String, String>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StdinMode {
    #[default]
    Inherit,
    Null,
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCapture {
    pub max_bytes: usize,
    pub tee_path: Option<PathBuf>,
}

impl StreamCapture {
    pub const fn bounded(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            tee_path: None,
        }
    }

    pub fn tee_to(mut self, path: impl Into<PathBuf>) -> Self {
        self.tee_path = Some(path.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    pub label: String,
    pub command: ProcessCommand,
    pub current_dir: PathBuf,
    pub environment: EnvironmentMode,
    pub stdin: StdinMode,
    pub timeout: Option<Duration>,
    pub stdout: StreamCapture,
    pub stderr: StreamCapture,
}

impl ProcessSpec {
    pub fn shell(
        label: impl Into<String>,
        shell: Shell,
        command: impl Into<String>,
        current_dir: impl Into<PathBuf>,
        capture_limit_bytes: usize,
    ) -> Self {
        Self {
            label: label.into(),
            command: ProcessCommand::Shell {
                shell,
                command: command.into(),
            },
            current_dir: current_dir.into(),
            environment: EnvironmentMode::Inherit,
            stdin: StdinMode::Inherit,
            timeout: None,
            stdout: StreamCapture::bounded(capture_limit_bytes),
            stderr: StreamCapture::bounded(capture_limit_bytes),
        }
    }

    pub fn direct(
        label: impl Into<String>,
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
        current_dir: impl Into<PathBuf>,
        capture_limit_bytes: usize,
    ) -> Self {
        Self {
            label: label.into(),
            command: ProcessCommand::Direct {
                program: program.into(),
                args: args.into_iter().map(Into::into).collect(),
            },
            current_dir: current_dir.into(),
            environment: EnvironmentMode::Inherit,
            stdin: StdinMode::Inherit,
            timeout: None,
            stdout: StreamCapture::bounded(capture_limit_bytes),
            stderr: StreamCapture::bounded(capture_limit_bytes),
        }
    }

    pub fn with_environment(mut self, environment: EnvironmentMode) -> Self {
        self.environment = environment;
        self
    }

    pub fn with_stdin(mut self, stdin: StdinMode) -> Self {
        self.stdin = stdin;
        self
    }

    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_stdout(mut self, stdout: StreamCapture) -> Self {
        self.stdout = stdout;
        self
    }

    pub fn with_stderr(mut self, stderr: StreamCapture) -> Self {
        self.stderr = stderr;
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

impl CapturedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub fn summarize_chars(&self, max_chars: usize) -> CapturedText {
        let text = String::from_utf8_lossy(&self.bytes);
        let mut chars = text.chars();
        let value = chars.by_ref().take(max_chars).collect::<String>();
        CapturedText {
            text: value,
            truncated: self.truncated || chars.next().is_some(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedText {
    pub text: String,
    pub truncated: bool,
}

#[derive(Debug)]
pub struct ProcessOutput {
    pub status: Option<ExitStatus>,
    pub duration: Duration,
    pub timed_out: bool,
    pub stdout: CapturedBytes,
    pub stderr: CapturedBytes,
    pub process_error: Option<String>,
    pub stdin_error: Option<String>,
}

#[derive(Debug)]
pub struct ProcessFailureEvidence {
    pub stdout: CapturedBytes,
    pub stderr: CapturedBytes,
    pub process_error: Option<String>,
    pub stdin_error: Option<String>,
}

impl fmt::Display for ProcessFailureEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stdout = self.stdout.summarize_chars(512);
        let stderr = self.stderr.summarize_chars(512);
        write!(
            formatter,
            "stdout={:?}{}; stderr={:?}{}",
            stdout.text,
            if stdout.truncated { " (truncated)" } else { "" },
            stderr.text,
            if stderr.truncated { " (truncated)" } else { "" }
        )?;
        if let Some(error) = &self.process_error {
            write!(formatter, "; process cleanup: {error}")?;
        }
        if let Some(error) = &self.stdin_error {
            write!(formatter, "; stdin: {error}")?;
        }
        Ok(())
    }
}

impl ProcessOutput {
    pub fn duration_ms(&self) -> u64 {
        duration_millis(self.duration)
    }
}

#[derive(Debug, Error)]
pub enum ProcessRunError {
    #[error("failed to open {stream} tee for {label} at {path}: {source}")]
    OpenTee {
        label: String,
        stream: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "stdout and stderr tee paths for {label} refer to the same file: {stdout} and {stderr}"
    )]
    TeeConflict {
        label: String,
        stdout: PathBuf,
        stderr: PathBuf,
    },
    #[error("failed to spawn {label} ({command}) in {current_dir}: {source}")]
    Spawn {
        label: String,
        command: String,
        current_dir: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to query {label} ({command}) status: {source}; retained evidence: {evidence}")]
    Wait {
        label: String,
        command: String,
        evidence: Box<ProcessFailureEvidence>,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to establish process-tree ownership for {label} ({command}): {source}")]
    ProcessOwnership {
        label: String,
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to prepare cancellable child I/O for {label} ({command}): {source}")]
    IoSetup {
        label: String,
        command: String,
        #[source]
        source: std::io::Error,
    },
}

pub fn run_process(spec: ProcessSpec) -> Result<ProcessOutput, ProcessRunError> {
    let started = Instant::now();
    let command_display = spec.command.display();
    let (stdout_tee, stderr_tee) = prepare_tees(&spec.label, &spec.stdout, &spec.stderr)?;
    let mut command = spec.command.build();
    configure_process_tree(&mut command);
    command.current_dir(&spec.current_dir);
    configure_environment(&mut command, &spec.environment);
    configure_stdin(&mut command, &spec.stdin);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|source| ProcessRunError::Spawn {
        label: spec.label.clone(),
        command: command_display.clone(),
        current_dir: spec.current_dir.clone(),
        source,
    })?;
    let process_tree =
        match ProcessTree::attach_and_start(&mut child, &spec.label, &command_display) {
            Ok(process_tree) => process_tree,
            Err(error) => {
                terminate_unowned_child(&mut child);
                return Err(error);
            }
        };
    let prepared_io = match PreparedChildIo::take(&mut child, &spec.stdin) {
        Ok(prepared_io) => prepared_io,
        Err(source) => {
            let _ = process_tree.terminate(&mut child, false, &spec.label);
            let _ = wait_for_exit_until(&mut child, Instant::now() + EXIT_AND_DRAIN_GRACE);
            return Err(ProcessRunError::IoSetup {
                label: spec.label.clone(),
                command: command_display,
                source,
            });
        }
    };
    let (mut input_writer, mut output_drainers) = prepared_io.start(
        &spec.label,
        spec.stdin,
        spec.stdout.max_bytes,
        spec.stderr.max_bytes,
        stdout_tee,
        stderr_tee,
    );
    let mut status = None;
    let mut timed_out = false;
    let mut process_error = None;

    loop {
        let output_backlog = output_drainers.drain_ready();
        input_writer.drain_ready();

        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(source) => {
                    let evidence = cleanup_after_wait_error(
                        &mut child,
                        &process_tree,
                        &spec.label,
                        output_drainers,
                        input_writer,
                    );
                    return Err(ProcessRunError::Wait {
                        label: spec.label.clone(),
                        command: command_display.clone(),
                        evidence: Box::new(evidence),
                        source,
                    });
                }
            };
        }

        if spec
            .timeout
            .is_some_and(|timeout| started.elapsed() >= timeout)
        {
            timed_out = true;
            process_error = append_error(
                process_error,
                process_tree.terminate(&mut child, status.is_some(), &spec.label),
            );

            let exit_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
            if status.is_none() {
                status = match wait_for_exit_until(&mut child, exit_deadline) {
                    Ok(status) => status,
                    Err(source) => {
                        let evidence = cleanup_after_wait_error(
                            &mut child,
                            &process_tree,
                            &spec.label,
                            output_drainers,
                            input_writer,
                        );
                        return Err(ProcessRunError::Wait {
                            label: spec.label.clone(),
                            command: command_display.clone(),
                            evidence: Box::new(evidence),
                            source,
                        });
                    }
                };
                if status.is_none() {
                    process_error = append_error(
                        process_error,
                        Some(format!(
                            "{} timed out and did not exit within {} ms after termination",
                            spec.label,
                            EXIT_AND_DRAIN_GRACE.as_millis()
                        )),
                    );
                }
            }

            finish_child_io(
                &spec.label,
                "after timeout termination",
                &mut output_drainers,
                &mut input_writer,
                &mut process_error,
            );
            break;
        }

        if status.is_some() {
            process_error = append_error(
                process_error,
                process_tree.finalize(&mut child, &spec.label),
            );
            finish_child_io(
                &spec.label,
                "after normal process exit",
                &mut output_drainers,
                &mut input_writer,
                &mut process_error,
            );
            break;
        }

        if !output_backlog {
            thread::sleep(POLL_INTERVAL);
        }
    }

    output_drainers.drain_ready();
    input_writer.drain_ready();
    let (stdout, stderr, output_error) = output_drainers.into_outputs();
    process_error = append_error(process_error, output_error);
    let (stdin_error, input_cleanup_error) = input_writer.into_result(&spec.label);
    process_error = append_error(process_error, input_cleanup_error);

    Ok(ProcessOutput {
        status,
        duration: started.elapsed(),
        timed_out,
        stdout,
        stderr,
        process_error,
        stdin_error,
    })
}

fn terminate_unowned_child(child: &mut Child) {
    let _ = child.kill();
    let _ = wait_for_exit_until(child, Instant::now() + EXIT_AND_DRAIN_GRACE);
}

fn cleanup_after_wait_error(
    child: &mut Child,
    process_tree: &ProcessTree,
    label: &str,
    mut output_drainers: OutputDrainers,
    mut input_writer: InputWriter,
) -> ProcessFailureEvidence {
    let mut process_error = process_tree.terminate(child, false, label);
    let exit_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
    match wait_for_exit_until(child, exit_deadline) {
        Ok(Some(_)) => {}
        Ok(None) => {
            process_error = append_error(
                process_error,
                Some(format!(
                    "{label} did not exit within {} ms during error cleanup",
                    EXIT_AND_DRAIN_GRACE.as_millis()
                )),
            );
        }
        Err(error) => {
            process_error = append_error(
                process_error,
                Some(format!(
                    "failed to wait for {label} during error cleanup: {error}"
                )),
            );
        }
    }
    finish_child_io(
        label,
        "during wait-error cleanup",
        &mut output_drainers,
        &mut input_writer,
        &mut process_error,
    );
    let (stdout, stderr, output_error) = output_drainers.into_outputs();
    process_error = append_error(process_error, output_error);
    let (stdin_error, input_cleanup_error) = input_writer.into_result(label);
    process_error = append_error(process_error, input_cleanup_error);
    ProcessFailureEvidence {
        stdout,
        stderr,
        process_error,
        stdin_error,
    }
}

fn finish_child_io(
    label: &str,
    context: &str,
    output_drainers: &mut OutputDrainers,
    input_writer: &mut InputWriter,
    process_error: &mut Option<String>,
) {
    let output_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
    if !output_drainers.finish_until(output_deadline) {
        *process_error = append_error(
            process_error.take(),
            Some(format!(
                "{label} output pipes did not close within {} ms {context}",
                EXIT_AND_DRAIN_GRACE.as_millis()
            )),
        );
        *process_error = append_error(
            process_error.take(),
            output_drainers.cancel_incomplete(label),
        );
    }
    let input_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
    if !input_writer.finish_until(input_deadline) {
        *process_error = append_error(
            process_error.take(),
            Some(format!(
                "{label} stdin writer did not finish within {} ms {context}",
                EXIT_AND_DRAIN_GRACE.as_millis()
            )),
        );
        *process_error = append_error(process_error.take(), input_writer.cancel_incomplete(label));
    }
}

fn prepare_tees(
    label: &str,
    stdout: &StreamCapture,
    stderr: &StreamCapture,
) -> Result<(Option<TeeWriter>, Option<TeeWriter>), ProcessRunError> {
    if let (Some(stdout), Some(stderr)) = (&stdout.tee_path, &stderr.tee_path) {
        if stdout == stderr {
            return Err(ProcessRunError::TeeConflict {
                label: label.to_string(),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            });
        }
    }

    let mut stdout = match stdout.tee_path.as_ref() {
        Some(path) => Some(preflight_tee(label, "stdout", path)?),
        None => None,
    };
    let mut stderr = match stderr.tee_path.as_ref() {
        Some(path) => match preflight_tee(label, "stderr", path) {
            Ok(tee) => Some(tee),
            Err(error) => {
                rollback_created_tee(stdout.take());
                return Err(error);
            }
        },
        None => None,
    };

    if let (Some(stdout_tee), Some(stderr_tee)) = (&stdout, &stderr) {
        let same_file = match tee_files_are_same(stdout_tee, stderr_tee) {
            Ok(same_file) => same_file,
            Err(source) => {
                let path = stdout_tee.path.clone();
                rollback_created_tee(stdout.take());
                rollback_created_tee(stderr.take());
                return Err(ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream: "stdout/stderr",
                    path,
                    source,
                });
            }
        };
        if same_file {
            let stdout_path = stdout_tee.path.clone();
            let stderr_path = stderr_tee.path.clone();
            rollback_created_tee(stdout.take());
            rollback_created_tee(stderr.take());
            return Err(ProcessRunError::TeeConflict {
                label: label.to_string(),
                stdout: stdout_path,
                stderr: stderr_path,
            });
        }
    }

    let stdout_backup = match stdout.as_ref().filter(|tee| !tee.created) {
        Some(tee) if stderr.is_some() => match TeeBackup::create(&tee.path) {
            Ok(backup) => Some(backup),
            Err(source) => {
                let path = tee.path.clone();
                rollback_created_tee(stdout.take());
                rollback_created_tee(stderr.take());
                return Err(ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream: "stdout",
                    path,
                    source,
                });
            }
        },
        _ => None,
    };

    if let Some(tee) = stdout.as_mut() {
        if let Err(source) = tee.file.set_len(0) {
            let path = tee.path.clone();
            rollback_created_tee(stdout.take());
            rollback_created_tee(stderr.take());
            return Err(ProcessRunError::OpenTee {
                label: label.to_string(),
                stream: "stdout",
                path,
                source,
            });
        }
    }
    if let Some(tee) = stderr.as_mut() {
        if let Err(source) = tee.file.set_len(0) {
            let path = tee.path.clone();
            let rollback_error = match (&mut stdout, stdout_backup.as_ref()) {
                (Some(stdout), Some(backup)) => backup.restore(&mut stdout.file).err(),
                _ => None,
            };
            rollback_created_tee(stdout.take());
            rollback_created_tee(stderr.take());
            let source = match rollback_error {
                Some(rollback_error) => std::io::Error::other(format!(
                    "{source}; failed to restore stdout tee after transactional truncate failure: {rollback_error}"
                )),
                None => source,
            };
            return Err(ProcessRunError::OpenTee {
                label: label.to_string(),
                stream: "stderr",
                path,
                source,
            });
        }
    }

    Ok((
        stdout.map(TeePreflight::commit),
        stderr.map(TeePreflight::commit),
    ))
}

struct TeePreflight {
    file: File,
    path: PathBuf,
    created: bool,
}

impl TeePreflight {
    fn commit(self) -> TeeWriter {
        TeeWriter {
            file: self.file,
            path: self.path,
        }
    }
}

fn preflight_tee(
    label: &str,
    stream: &'static str,
    path: &Path,
) -> Result<TeePreflight, ProcessRunError> {
    let create_result = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path);
    let (file, created) = match create_result {
        Ok(file) => (file, true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
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

    let regular = fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
        && file
            .metadata()
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false);
    if !regular {
        drop(file);
        if created {
            let _ = fs::remove_file(path);
        }
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
    drop(tee);
    if created {
        let _ = fs::remove_file(path);
    }
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
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    fn identity(file: &File) -> std::io::Result<(u32, u64)> {
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        // SAFETY: `information` points to writable storage and the borrowed file handle remains
        // valid for the duration of this call.
        if unsafe {
            GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr())
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a successful call initialized the complete structure.
        let information = unsafe { information.assume_init() };
        let index =
            (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
        Ok((information.dwVolumeSerialNumber, index))
    }

    Ok(identity(&left.file)? == identity(&right.file)?)
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
    fn create(source_path: &Path) -> std::io::Result<Self> {
        let mut source = File::open(source_path)?;
        for _ in 0..32 {
            let id = NEXT_TEE_BACKUP_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("maco-tee-backup-{}-{id}.tmp", std::process::id()));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    let prepared = std::io::copy(&mut source, &mut file)
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
        let mut source = self
            .file
            .as_ref()
            .ok_or_else(|| std::io::Error::other("tee rollback file was already closed"))?
            .try_clone()?;
        source.seek(SeekFrom::Start(0))?;
        destination.set_len(0)?;
        destination.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut source, destination)?;
        Ok(())
    }
}

impl Drop for TeeBackup {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

struct TeeWriter {
    file: File,
    path: PathBuf,
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
        StdinMode::Bytes(_) => {
            command.stdin(Stdio::piped());
        }
    }
}

fn configure_process_tree(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(WINDOWS_PROCESS_CREATION_FLAGS);
    }
}

#[cfg(target_os = "windows")]
const WINDOWS_PROCESS_CREATION_FLAGS: u32 = 0x0000_0200 | 0x0000_0004;

struct ProcessTree {
    #[cfg(target_os = "windows")]
    job: WindowsJob,
}

impl ProcessTree {
    fn attach_and_start(
        child: &mut Child,
        label: &str,
        command: &str,
    ) -> Result<Self, ProcessRunError> {
        #[cfg(target_os = "windows")]
        {
            let job = WindowsJob::create_and_assign(child).map_err(|source| {
                ProcessRunError::ProcessOwnership {
                    label: label.to_string(),
                    command: command.to_string(),
                    source,
                }
            })?;
            if let Err(source) = resume_suspended_child(child) {
                let termination_error = job.terminate(label, "startup rollback");
                let wait_error = wait_for_exit_until(child, Instant::now() + EXIT_AND_DRAIN_GRACE)
                    .err()
                    .map(|error| format!("failed to wait for suspended child rollback: {error}"));
                let source = append_error(
                    Some(source.to_string()),
                    append_error(termination_error, wait_error),
                )
                .map(std::io::Error::other)
                .unwrap_or(source);
                return Err(ProcessRunError::ProcessOwnership {
                    label: label.to_string(),
                    command: command.to_string(),
                    source,
                });
            }
            Ok(Self { job })
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (child, label, command);
            Ok(Self {})
        }
    }

    fn finalize(&self, child: &mut Child, label: &str) -> Option<String> {
        #[cfg(unix)]
        {
            let _ = self;
            finalize_unix_process_group(child.id(), label)
        }

        #[cfg(target_os = "windows")]
        {
            let _ = child;
            self.job
                .terminate(label, "normal process-tree finalization")
        }

        #[cfg(not(any(unix, target_os = "windows")))]
        {
            let _ = (self, child, label);
            None
        }
    }

    fn terminate(
        &self,
        child: &mut Child,
        child_already_exited: bool,
        label: &str,
    ) -> Option<String> {
        #[cfg(unix)]
        {
            let _ = self;
            terminate_unix_process_group(child, child_already_exited, label)
        }

        #[cfg(target_os = "windows")]
        {
            match self.job.terminate(label, "process termination") {
                None => None,
                Some(job_error) if child_already_exited => Some(job_error),
                Some(job_error) => match child.kill() {
                    Ok(()) => Some(format!("{job_error}; direct child was killed")),
                    Err(error) => Some(format!("{job_error}; direct process kill failed: {error}")),
                },
            }
        }

        #[cfg(not(any(unix, target_os = "windows")))]
        {
            let _ = self;
            if child_already_exited {
                None
            } else {
                child
                    .kill()
                    .err()
                    .map(|error| format!("{label} timed out but process kill failed: {error}"))
            }
        }
    }
}

#[cfg(unix)]
fn terminate_unix_process_group(
    child: &mut Child,
    child_already_exited: bool,
    label: &str,
) -> Option<String> {
    let pid = child.id();
    match send_unix_process_group_signal(pid, libc::SIGTERM) {
        Ok(GroupSignalResult::Sent) => {
            thread::sleep(TERMINATE_GRACE);
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
fn finalize_unix_process_group(pid: u32, label: &str) -> Option<String> {
    match send_unix_process_group_signal(pid, libc::SIGTERM) {
        Ok(GroupSignalResult::Missing) => None,
        Ok(GroupSignalResult::Sent) => {
            thread::sleep(TERMINATE_GRACE);
            match send_unix_process_group_signal(pid, libc::SIGKILL) {
                Ok(GroupSignalResult::Sent | GroupSignalResult::Missing) => None,
                Err(error) => Some(format!(
                    "{label} failed to kill remaining process-group descendants: {error}"
                )),
            }
        }
        Err(error) => Some(format!(
            "{label} failed to terminate remaining process-group descendants: {error}"
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
        let stdin = if matches!(stdin_mode, StdinMode::Bytes(_)) {
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
    #[error("{label} did not stop within {} ms after cancellation; joined after the cleanup deadline", THREAD_JOIN_GRACE.as_millis())]
    Deadline { label: String },
    #[error("{label} thread panicked during cleanup")]
    Panicked { label: String },
}

struct OwnedIoThread {
    handle: thread::JoinHandle<()>,
    cancel: Arc<AtomicBool>,
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
        let mut errors = Vec::new();
        if !completion_observed {
            if let Some(error) = self.request_cancel(label) {
                errors.push(error);
            }
        }
        let Self { handle, .. } = self;
        if !completion_observed {
            let deadline = Instant::now() + THREAD_JOIN_GRACE;
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(IO_CANCEL_POLL_INTERVAL);
            }
            if !handle.is_finished() {
                errors.push(IoThreadCleanupError::Deadline {
                    label: label.to_string(),
                });
            }
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

    fn finish_until(&mut self, deadline: Instant) -> bool {
        loop {
            self.drain_ready();
            if self.is_complete() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(POLL_INTERVAL);
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

    fn finish_until(&mut self, deadline: Instant) -> bool {
        loop {
            let backlog = self.drain_ready();
            if self.is_complete() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            if !backlog {
                thread::sleep(POLL_INTERVAL);
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
    capture: BoundedBuffer,
    complete: bool,
    error: Option<String>,
}

impl PipeReader {
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
        (
            self.capture.into_captured(),
            append_error(self.error, cleanup_error),
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
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
    }
}

enum PipeReadEvent {
    Chunk(Vec<u8>),
    Finished,
    Error(String),
}

fn start_pipe_reader<R>(
    stream: &'static str,
    mut reader: R,
    mut tee: Option<TeeWriter>,
    label: &str,
    capture_limit: usize,
) -> PipeReader
where
    R: Read + Send + 'static,
{
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
                    if let Err(error) = tee.file.write_all(&buffer) {
                        if send_pipe_event(&sender, &thread_cancel, PipeReadEvent::Chunk(buffer))
                            .is_ok()
                        {
                            let _ = send_pipe_event(
                                &sender,
                                &thread_cancel,
                                PipeReadEvent::Error(format!(
                                    "failed to write {label} {stream} tee {}: {error}",
                                    tee.path.display()
                                )),
                            );
                        }
                        break;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn drains_large_stdout_and_stderr_without_false_timeout() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output_log = temp.path().join("stdout.log");
        let spec = ProcessSpec::shell(
            "large-output command",
            Shell::UnixSh,
            "i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' O; i=$((i + 1)); done; i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' E >&2; i=$((i + 1)); done",
            temp.path(),
            16 * 1024,
        )
        .with_timeout(Some(Duration::from_secs(3)))
        .with_stdout(StreamCapture::bounded(16 * 1024).tee_to(&output_log));

        let output = run_process(spec).expect("run large-output command");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(!output.timed_out);
        assert!(output.stdout.is_truncated());
        assert!(output.stderr.is_truncated());
        assert_eq!(output.stdout.as_bytes().len(), 16 * 1024);
        assert_eq!(output.stderr.as_bytes().len(), 16 * 1024);
        assert!(
            std::fs::metadata(output_log)
                .expect("stdout log metadata")
                .len()
                >= 256 * 4096
        );
    }

    #[cfg(unix)]
    #[test]
    fn continuous_output_does_not_starve_timeout_polling() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::shell(
            "continuous-output command",
            Shell::UnixSh,
            "trap '' TERM; while :; do printf '%4096s' O; printf '%4096s' E >&2; done",
            temp.path(),
            1024,
        )
        .with_timeout(Some(Duration::from_secs(1)));
        let started = Instant::now();

        let output = run_process(spec).expect("run continuous-output command");
        let elapsed = started.elapsed();

        assert!(output.timed_out);
        assert!(output.stdout.is_truncated());
        assert!(output.stderr.is_truncated());
        assert!(elapsed >= Duration::from_millis(900));
        assert!(
            elapsed < Duration::from_secs(2),
            "continuous output delayed the one-second timeout for {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn completion_first_observed_after_deadline_is_a_timeout() {
        let temp = tempfile::tempdir().expect("tempdir");
        let spec = ProcessSpec::shell(
            "deadline-racing command",
            Shell::UnixSh,
            "sleep 0.002",
            temp.path(),
            128,
        )
        .with_timeout(Some(Duration::from_millis(1)));

        let output = run_process(spec).expect("run deadline-racing command");

        assert!(output.timed_out);
    }

    #[cfg(unix)]
    #[test]
    fn normal_exit_terminates_descendants_holding_pipes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let descendant_pid = temp.path().join("descendant.pid");
        let command = format!(
            "(trap '' TERM; echo descendant-started; echo descendant-error >&2; while :; do sleep 1; done) & descendant=$!; echo \"$descendant\" > '{}'; echo parent-exiting",
            descendant_pid.display()
        );
        let spec = ProcessSpec::shell(
            "hung command",
            Shell::UnixSh,
            command,
            temp.path(),
            8 * 1024,
        )
        .with_timeout(Some(Duration::from_millis(200)));
        let started = Instant::now();

        let output = run_process(spec).expect("run descendant-spawning command");

        assert!(!output.timed_out);
        assert!(output.status.is_some_and(|status| status.success()));
        assert_eq!(output.process_error, None);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(output
            .stdout
            .summarize_chars(8 * 1024)
            .text
            .contains("descendant-started"));
        assert!(output
            .stderr
            .summarize_chars(8 * 1024)
            .text
            .contains("descendant-error"));
        let pid = std::fs::read_to_string(descendant_pid).expect("descendant pid");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let status = Command::new("kill")
                .args(["-0", pid.trim()])
                .output()
                .expect("probe descendant")
                .status;
            if !status.success() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "descendant process should be terminated"
            );
            thread::sleep(POLL_INTERVAL);
        }
    }

    #[cfg(unix)]
    #[test]
    fn normal_exit_kills_delayed_background_mutation_before_return() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("delayed-mutation");
        let command = format!(
            "(sleep 0.3; touch '{}') >/dev/null 2>&1 &",
            marker.display()
        );
        let spec = ProcessSpec::shell(
            "delayed descendant command",
            Shell::UnixSh,
            command,
            temp.path(),
            1024,
        )
        .with_timeout(Some(Duration::from_secs(2)));

        let output = run_process(spec).expect("run delayed descendant command");

        assert!(output.status.is_some_and(|status| status.success()));
        assert!(!output.timed_out);
        thread::sleep(Duration::from_millis(400));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn absent_process_group_skips_termination_grace() {
        let mut command = Command::new("sh");
        command.args(["-c", "exit 0"]);
        configure_process_tree(&mut command);
        let mut child = command.spawn().expect("spawn short-lived child");
        child.wait().expect("wait for short-lived child");
        let started = Instant::now();

        let error = finalize_unix_process_group(child.id(), "short-lived child");

        assert_eq!(error, None);
        assert!(
            started.elapsed() < TERMINATE_GRACE,
            "missing process group should not incur TERM grace: {:?}",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn escaped_pipe_and_stdin_holders_are_cancelled_without_detaching_threads() {
        let temp = tempfile::tempdir().expect("tempdir");
        let escaped_pid_path = temp.path().join("escaped.pid");
        let command = format!(
            "exec 3<&0; setsid sh -c 'echo $$ > \"{}\"; sleep 30' <&3 & i=0; while [ ! -s \"{}\" ] && [ \"$i\" -lt 100 ]; do sleep 0.01; i=$((i + 1)); done",
            escaped_pid_path.display(),
            escaped_pid_path.display(),
        );
        let spec = ProcessSpec::shell(
            "escaped pipe holder",
            Shell::UnixSh,
            command,
            temp.path(),
            1024,
        )
        .with_stdin(StdinMode::Bytes(vec![b'x'; 4 * 1024 * 1024]))
        .with_timeout(Some(Duration::from_secs(3)));
        let started = Instant::now();

        let output = run_process(spec).expect("run escaped pipe holder");

        let escaped_pid = std::fs::read_to_string(&escaped_pid_path)
            .expect("escaped process pid")
            .trim()
            .parse::<u32>()
            .expect("numeric escaped process pid");
        let _ = send_unix_process_group_signal(escaped_pid, libc::SIGKILL);
        assert!(output.status.is_some_and(|status| status.success()));
        assert!(!output.timed_out);
        assert!(
            output
                .process_error
                .as_deref()
                .is_some_and(|error| error.contains("output pipes did not close")),
            "expected bounded output cleanup evidence: {:?}",
            output.process_error
        );
        assert!(
            output
                .stdin_error
                .as_deref()
                .is_some_and(|error| error.contains("cancelled")),
            "expected stdin cancellation evidence: {:?}",
            output.stdin_error
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn stdin_and_environment_modes_are_explicit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut environment = BTreeMap::new();
        environment.insert("MACO_PROCESS_TEST".to_string(), "present".to_string());
        let spec = ProcessSpec::shell(
            "stdin/env command",
            Shell::UnixSh,
            "read value; printf '%s:%s:%s' \"$MACO_PROCESS_TEST\" \"$value\" \"${HOME-unset}\"",
            temp.path(),
            1024,
        )
        .with_environment(EnvironmentMode::ClearAndSet(environment))
        .with_stdin(StdinMode::Bytes(b"payload\n".to_vec()))
        .with_timeout(Some(Duration::from_secs(1)));

        let output = run_process(spec).expect("run stdin/env command");

        assert!(output.status.is_some_and(|status| status.success()));
        assert_eq!(
            output.stdout.summarize_chars(1024).text,
            "present:payload:unset"
        );
        assert_eq!(output.stdin_error, None);
    }

    #[test]
    fn spawn_error_identifies_command_label_and_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing_program = temp.path().join("missing-program");
        let spec = ProcessSpec::direct(
            "missing command",
            &missing_program,
            Vec::<OsString>::new(),
            temp.path(),
            128,
        );

        let error = run_process(spec).expect_err("missing command must fail to spawn");

        match &error {
            ProcessRunError::Spawn {
                label,
                command,
                current_dir,
                ..
            } => {
                assert_eq!(label, "missing command");
                assert!(command.contains(&missing_program.display().to_string()));
                assert_eq!(current_dir, temp.path());
            }
            other => panic!("expected spawn error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn invalid_tee_path_prevents_child_side_effects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let marker = temp.path().join("child-ran");
        let missing_tee_parent = temp.path().join("missing").join("stdout.log");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell(
            "command with invalid tee",
            Shell::UnixSh,
            command,
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(missing_tee_parent));

        let error = run_process(spec).expect_err("invalid tee must fail before spawn");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn same_tee_file_is_rejected_before_child_spawn() {
        let temp = tempfile::tempdir().expect("tempdir");
        let tee_path = temp.path().join("combined.log");
        let marker = temp.path().join("child-ran");
        std::fs::write(&tee_path, "preserve me").expect("write existing tee");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell("same tee command", Shell::UnixSh, command, temp.path(), 128)
            .with_stdout(StreamCapture::bounded(128).tee_to(&tee_path))
            .with_stderr(StreamCapture::bounded(128).tee_to(&tee_path));

        let error = run_process(spec).expect_err("same tee must be rejected");

        assert!(matches!(error, ProcessRunError::TeeConflict { .. }));
        assert_eq!(
            std::fs::read_to_string(&tee_path).expect("read preserved tee"),
            "preserve me"
        );
        assert!(!marker.exists());
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_tee_files_are_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stdout_path = temp.path().join("stdout.log");
        let stderr_path = temp.path().join("stderr.log");
        std::fs::write(&stdout_path, "preserve me").expect("write stdout tee");
        std::fs::hard_link(&stdout_path, &stderr_path).expect("hard link stderr tee");
        let spec = ProcessSpec::shell(
            "hard-linked tee command",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&stderr_path));

        let error = run_process(spec).expect_err("hard-linked tees must be rejected");

        assert!(matches!(error, ProcessRunError::TeeConflict { .. }));
        assert_eq!(
            std::fs::read_to_string(&stdout_path).expect("read preserved tee"),
            "preserve me"
        );
    }

    #[cfg(unix)]
    #[test]
    fn second_tee_preflight_failure_preserves_first_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stdout_path = temp.path().join("stdout.log");
        let invalid_stderr_path = temp.path().join("stderr-directory");
        let marker = temp.path().join("child-ran");
        std::fs::write(&stdout_path, "preserve me").expect("write stdout tee");
        std::fs::create_dir(&invalid_stderr_path).expect("create invalid stderr directory");
        let command = format!("touch '{}'", marker.display());
        let spec = ProcessSpec::shell(
            "transactional tee command",
            Shell::UnixSh,
            command,
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&invalid_stderr_path));

        let error = run_process(spec).expect_err("invalid second tee must fail preflight");

        assert!(matches!(error, ProcessRunError::OpenTee { .. }));
        assert_eq!(
            std::fs::read_to_string(&stdout_path).expect("read preserved stdout tee"),
            "preserve me"
        );
        assert!(!marker.exists());

        let new_stdout_path = temp.path().join("new-stdout.log");
        let second_spec = ProcessSpec::shell(
            "new tee rollback command",
            Shell::UnixSh,
            ":",
            temp.path(),
            128,
        )
        .with_stdout(StreamCapture::bounded(128).tee_to(&new_stdout_path))
        .with_stderr(StreamCapture::bounded(128).tee_to(&invalid_stderr_path));
        let second_error =
            run_process(second_spec).expect_err("new first tee must roll back on second failure");
        assert!(matches!(second_error, ProcessRunError::OpenTee { .. }));
        assert!(!new_stdout_path.exists());
    }

    #[test]
    fn tee_backup_restores_content_and_removes_temporary_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("tee.log");
        std::fs::write(&path, "original tee contents").expect("write tee source");
        let backup = TeeBackup::create(&path).expect("create tee backup");
        let backup_path = backup.path.clone();
        let mut destination = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open tee destination");
        destination.set_len(0).expect("truncate destination");
        destination
            .write_all(b"partial")
            .expect("write partial tee");

        backup
            .restore(&mut destination)
            .expect("restore tee backup");
        drop(destination);
        drop(backup);

        assert_eq!(
            std::fs::read_to_string(&path).expect("read restored tee"),
            "original tee contents"
        );
        assert!(!backup_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn wait_error_evidence_retains_captured_output_and_cleanup_diagnostics() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf retained-stdout; printf retained-stderr >&2; sleep 30",
        ]);
        configure_process_tree(&mut command);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn evidence child");
        let process_tree = ProcessTree::attach_and_start(&mut child, "evidence child", "sh")
            .expect("attach evidence child");
        let prepared = PreparedChildIo::take(&mut child, &StdinMode::Null)
            .expect("prepare evidence child I/O");
        let (input_writer, mut output_drainers) =
            prepared.start("evidence child", StdinMode::Null, 1024, 1024, None, None);
        let deadline = Instant::now() + Duration::from_secs(1);
        while output_drainers.stdout.capture.bytes.is_empty()
            || output_drainers.stderr.capture.bytes.is_empty()
        {
            output_drainers.drain_ready();
            assert!(Instant::now() < deadline, "child output was not captured");
            thread::sleep(IO_CANCEL_POLL_INTERVAL);
        }

        let evidence = cleanup_after_wait_error(
            &mut child,
            &process_tree,
            "evidence child",
            output_drainers,
            input_writer,
        );

        assert_eq!(evidence.stdout.as_bytes(), b"retained-stdout");
        assert_eq!(evidence.stderr.as_bytes(), b"retained-stderr");
        let error = ProcessRunError::Wait {
            label: "evidence child".to_string(),
            command: "sh".to_string(),
            evidence: Box::new(evidence),
            source: std::io::Error::other("synthetic wait failure"),
        };
        assert!(error.to_string().contains("retained-stdout"));
        assert!(error.to_string().contains("retained-stderr"));
    }

    #[test]
    fn platform_shell_is_concrete() {
        #[cfg(target_os = "windows")]
        assert_eq!(Shell::for_current_platform(), Shell::WindowsCmd);

        #[cfg(not(target_os = "windows"))]
        assert_eq!(Shell::for_current_platform(), Shell::UnixSh);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_children_start_suspended_in_a_new_process_group() {
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        assert_ne!(WINDOWS_PROCESS_CREATION_FLAGS & CREATE_SUSPENDED, 0);
        assert_ne!(WINDOWS_PROCESS_CREATION_FLAGS & CREATE_NEW_PROCESS_GROUP, 0);
    }

    #[test]
    fn bounded_buffer_never_grows_past_limit() {
        let mut buffer = BoundedBuffer::new(3);
        buffer.push(b"abcdef");
        buffer.push(b"ghij");
        let captured = buffer.into_captured();
        assert_eq!(captured.as_bytes(), b"abc");
        assert!(captured.is_truncated());
    }

    #[test]
    fn direct_command_constructor_preserves_arguments() {
        let spec = ProcessSpec::direct(
            "direct",
            PathBuf::from("program"),
            ["one", "two"],
            PathBuf::from("."),
            128,
        );
        assert_eq!(
            spec.command,
            ProcessCommand::Direct {
                program: PathBuf::from("program"),
                args: vec![OsString::from("one"), OsString::from("two")],
            }
        );
    }
}
