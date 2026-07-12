use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

const PIPE_READ_CHUNK_SIZE: usize = 8 * 1024;
const PIPE_CHANNEL_CAPACITY: usize = 8;
const MAX_PIPE_EVENTS_PER_POLL: usize = PIPE_CHANNEL_CAPACITY * 2;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const THREAD_JOIN_GRACE: Duration = Duration::from_millis(50);
#[cfg(unix)]
const TERMINATE_GRACE: Duration = Duration::from_millis(100);
const EXIT_AND_DRAIN_GRACE: Duration = Duration::from_millis(500);

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
    #[error("failed to spawn {label} ({command}) in {current_dir}: {source}")]
    Spawn {
        label: String,
        command: String,
        current_dir: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to query {label} ({command}) status: {source}")]
    Wait {
        label: String,
        command: String,
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
}

pub fn run_process(spec: ProcessSpec) -> Result<ProcessOutput, ProcessRunError> {
    let started = Instant::now();
    let command_display = spec.command.display();
    let stdout_tee = open_tee(&spec.label, "stdout", &spec.stdout)?;
    let stderr_tee = open_tee(&spec.label, "stderr", &spec.stderr)?;
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
    let process_tree = match ProcessTree::attach(&child, &spec.label, &command_display) {
        Ok(process_tree) => process_tree,
        Err(error) => {
            terminate_unowned_child(&mut child);
            return Err(error);
        }
    };
    let mut input_writer = InputWriter::start(&mut child, &spec.label, spec.stdin);
    let mut output_drainers = OutputDrainers::start(
        &mut child,
        &spec.label,
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
                    let cleanup_error = cleanup_after_wait_error(
                        &mut child,
                        &process_tree,
                        &spec.label,
                        output_drainers,
                        input_writer,
                    );
                    return Err(ProcessRunError::Wait {
                        label: spec.label.clone(),
                        command: command_display.clone(),
                        source: with_cleanup_error(source, cleanup_error),
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
                        let cleanup_error = cleanup_after_wait_error(
                            &mut child,
                            &process_tree,
                            &spec.label,
                            output_drainers,
                            input_writer,
                        );
                        return Err(ProcessRunError::Wait {
                            label: spec.label.clone(),
                            command: command_display.clone(),
                            source: with_cleanup_error(source, cleanup_error),
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

            let drain_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
            if !output_drainers.finish_until(drain_deadline) {
                process_error = append_error(
                    process_error,
                    Some(format!(
                        "{} timed out and output pipes did not close within {} ms",
                        spec.label,
                        EXIT_AND_DRAIN_GRACE.as_millis()
                    )),
                );
            }
            if !input_writer.finish_until(drain_deadline) {
                process_error = append_error(
                    process_error,
                    Some(format!(
                        "{} timed out and stdin writer did not finish within {} ms",
                        spec.label,
                        EXIT_AND_DRAIN_GRACE.as_millis()
                    )),
                );
            }
            break;
        }

        if status.is_some() && output_drainers.is_complete() && input_writer.is_complete() {
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
) -> Option<String> {
    let mut cleanup_error = process_tree.terminate(child, false, label);
    let exit_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
    match wait_for_exit_until(child, exit_deadline) {
        Ok(Some(_)) => {}
        Ok(None) => {
            cleanup_error = append_error(
                cleanup_error,
                Some(format!(
                    "{label} did not exit within {} ms during error cleanup",
                    EXIT_AND_DRAIN_GRACE.as_millis()
                )),
            );
        }
        Err(error) => {
            cleanup_error = append_error(
                cleanup_error,
                Some(format!(
                    "failed to wait for {label} during error cleanup: {error}"
                )),
            );
        }
    }

    let drain_deadline = Instant::now() + EXIT_AND_DRAIN_GRACE;
    if !output_drainers.finish_until(drain_deadline) {
        cleanup_error = append_error(
            cleanup_error,
            Some(format!(
                "{label} output pipes did not close within {} ms during error cleanup",
                EXIT_AND_DRAIN_GRACE.as_millis()
            )),
        );
    }
    if !input_writer.finish_until(drain_deadline) {
        cleanup_error = append_error(
            cleanup_error,
            Some(format!(
                "{label} stdin writer did not finish within {} ms during error cleanup",
                EXIT_AND_DRAIN_GRACE.as_millis()
            )),
        );
    }
    let (_, _, output_error) = output_drainers.into_outputs();
    cleanup_error = append_error(cleanup_error, output_error);
    let (stdin_error, input_cleanup_error) = input_writer.into_result(label);
    cleanup_error = append_error(cleanup_error, stdin_error);
    append_error(cleanup_error, input_cleanup_error)
}

fn with_cleanup_error(source: std::io::Error, cleanup_error: Option<String>) -> std::io::Error {
    match cleanup_error {
        Some(cleanup_error) => std::io::Error::new(
            source.kind(),
            format!("{source}; process cleanup also reported: {cleanup_error}"),
        ),
        None => source,
    }
}

fn open_tee(
    label: &str,
    stream: &'static str,
    capture: &StreamCapture,
) -> Result<Option<TeeWriter>, ProcessRunError> {
    capture
        .tee_path
        .as_ref()
        .map(|path| {
            File::create(path)
                .map(|file| TeeWriter {
                    file,
                    path: path.clone(),
                })
                .map_err(|source| ProcessRunError::OpenTee {
                    label: label.to_string(),
                    stream,
                    path: path.clone(),
                    source,
                })
        })
        .transpose()
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
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
}

struct ProcessTree {
    #[cfg(target_os = "windows")]
    job: WindowsJob,
}

impl ProcessTree {
    fn attach(child: &Child, label: &str, command: &str) -> Result<Self, ProcessRunError> {
        #[cfg(target_os = "windows")]
        {
            let job = WindowsJob::create_and_assign(child).map_err(|source| {
                ProcessRunError::ProcessOwnership {
                    label: label.to_string(),
                    command: command.to_string(),
                    source,
                }
            })?;
            Ok(Self { job })
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = (child, label, command);
            Ok(Self {})
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
            match self.job.terminate(label) {
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
    let _ = send_unix_process_group_signal(pid, "TERM");
    thread::sleep(TERMINATE_GRACE);
    match send_unix_process_group_signal(pid, "KILL") {
        Ok(()) => None,
        Err(_) if child_already_exited => None,
        Err(_) if matches!(child.try_wait(), Ok(Some(_))) => None,
        Err(group_error) => match child.kill() {
            Ok(()) => Some(format!(
                "{label} timed out; process group kill failed: {group_error}; direct child was killed"
            )),
            Err(child_error) => Some(format!(
                "{label} timed out; process group kill failed: {group_error}; direct process kill failed: {child_error}"
            )),
        },
    }
}

#[cfg(unix)]
fn send_unix_process_group_signal(pid: u32, signal: &str) -> std::io::Result<()> {
    let target = format!("-{pid}");
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(&target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "kill -{signal} {target} exited with {status}"
        )))
    }
}

#[cfg(target_os = "windows")]
struct WindowsJob {
    handle: windows_sys::Win32::Foundation::HANDLE,
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
        let job = Self { handle };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is initialized for the requested information class and valid for the
        // duration of the call; `job.handle` remains owned by `job`.
        let configured = unsafe {
            SetInformationJobObject(
                job.handle,
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
        if unsafe { AssignProcessToJobObject(job.handle, process_handle) } == 0 {
            return Err(std::io::Error::other(format!(
                "AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(job)
    }

    fn terminate(&self, label: &str) -> Option<String> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: the handle is valid while `self` is alive. The exit code is diagnostic only.
        if unsafe { TerminateJobObject(self.handle, 1) } != 0 {
            None
        } else {
            Some(format!(
                "{label} timed out but TerminateJobObject failed: {}",
                std::io::Error::last_os_error()
            ))
        }
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        // SAFETY: this RAII owner closes its handle exactly once. KILL_ON_JOB_CLOSE ensures any
        // surviving assigned descendants are terminated when ownership ends.
        let _ = unsafe { CloseHandle(self.handle) };
    }
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

fn finish_owned_thread(
    handle: thread::JoinHandle<()>,
    completion_observed: bool,
    label: &str,
) -> Option<String> {
    if completion_observed {
        return handle
            .join()
            .err()
            .map(|_| format!("{label} thread panicked during cleanup"));
    }

    let deadline = Instant::now() + THREAD_JOIN_GRACE;
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    if handle.is_finished() {
        return handle
            .join()
            .err()
            .map(|_| format!("{label} thread panicked during cleanup"));
    }
    drop(handle);
    Some(format!(
        "{label} remained active without reporting completion for more than {} ms during bounded cleanup and was detached",
        THREAD_JOIN_GRACE.as_millis()
    ))
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
        handle: thread::JoinHandle<()>,
        error: Option<String>,
        complete: bool,
    },
}

impl InputWriter {
    fn start(child: &mut Child, label: &str, stdin: StdinMode) -> Self {
        let StdinMode::Bytes(input) = stdin else {
            return Self {
                state: InputWriterState::None,
            };
        };
        let Some(mut child_stdin) = child.stdin.take() else {
            return Self {
                state: InputWriterState::Complete {
                    error: Some(format!("failed to open {label} stdin")),
                },
            };
        };
        let (sender, receiver) = mpsc::channel();
        let label = label.to_string();
        let handle = thread::spawn(move || {
            let error = child_stdin
                .write_all(&input)
                .err()
                .map(|error| format!("failed to write {label} stdin: {error}"));
            let _ = sender.send(error);
        });
        Self {
            state: InputWriterState::Thread {
                receiver,
                handle,
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

    fn into_result(self, label: &str) -> (Option<String>, Option<String>) {
        match self.state {
            InputWriterState::None => (None, None),
            InputWriterState::Complete { error } => (error, None),
            InputWriterState::Thread {
                receiver,
                handle,
                error,
                complete,
            } => {
                drop(receiver);
                let cleanup_error =
                    finish_owned_thread(handle, complete, &format!("{label} stdin writer"));
                (error, cleanup_error)
            }
        }
    }
}

struct OutputDrainers {
    stdout: PipeReader,
    stderr: PipeReader,
    label: String,
}

impl OutputDrainers {
    fn start(
        child: &mut Child,
        label: &str,
        stdout_limit: usize,
        stderr_limit: usize,
        stdout_tee: Option<TeeWriter>,
        stderr_tee: Option<TeeWriter>,
    ) -> Self {
        Self {
            stdout: child
                .stdout
                .take()
                .map(|stdout| start_pipe_reader("stdout", stdout, stdout_tee, label, stdout_limit))
                .unwrap_or_else(|| PipeReader::missing(stdout_limit, "stdout")),
            stderr: child
                .stderr
                .take()
                .map(|stderr| start_pipe_reader("stderr", stderr, stderr_tee, label, stderr_limit))
                .unwrap_or_else(|| PipeReader::missing(stderr_limit, "stderr")),
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

    fn into_outputs(self) -> (CapturedBytes, CapturedBytes, Option<String>) {
        let (stdout, stdout_error) = self.stdout.into_output(&self.label);
        let (stderr, stderr_error) = self.stderr.into_output(&self.label);
        (stdout, stderr, append_error(stdout_error, stderr_error))
    }
}

struct PipeReader {
    stream: &'static str,
    receiver: Option<Receiver<PipeReadEvent>>,
    handle: Option<thread::JoinHandle<()>>,
    capture: BoundedBuffer,
    complete: bool,
    error: Option<String>,
}

impl PipeReader {
    fn missing(limit: usize, stream: &'static str) -> Self {
        Self {
            stream,
            receiver: None,
            handle: None,
            capture: BoundedBuffer::new(limit),
            complete: true,
            error: Some(format!("failed to open child {stream} pipe")),
        }
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

    fn into_output(self, label: &str) -> (CapturedBytes, Option<String>) {
        let Self {
            stream,
            receiver,
            handle,
            capture,
            complete,
            error,
        } = self;
        drop(receiver);
        let cleanup_error = handle.and_then(|handle| {
            finish_owned_thread(handle, complete, &format!("{label} {stream} reader"))
        });
        (capture.into_captured(), append_error(error, cleanup_error))
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
    let handle = thread::spawn(move || loop {
        let mut buffer = vec![0_u8; PIPE_READ_CHUNK_SIZE];
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ = sender.send(PipeReadEvent::Finished);
                break;
            }
            Ok(bytes_read) => {
                buffer.truncate(bytes_read);
                if let Some(tee) = tee.as_mut() {
                    if let Err(error) = tee.file.write_all(&buffer) {
                        if send_chunk(&sender, buffer).is_ok() {
                            let _ = sender.send(PipeReadEvent::Error(format!(
                                "failed to write {label} {stream} tee {}: {error}",
                                tee.path.display()
                            )));
                        }
                        break;
                    }
                }
                if send_chunk(&sender, buffer).is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = sender.send(PipeReadEvent::Error(format!(
                    "failed to read {label} {stream}: {error}"
                )));
                break;
            }
        }
    });

    PipeReader {
        stream,
        receiver: Some(receiver),
        handle: Some(handle),
        capture: BoundedBuffer::new(capture_limit),
        complete: false,
        error: None,
    }
}

fn send_chunk(sender: &SyncSender<PipeReadEvent>, chunk: Vec<u8>) -> Result<(), ()> {
    sender.send(PipeReadEvent::Chunk(chunk)).map_err(|_| ())
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
    fn true_timeout_terminates_descendants_holding_pipes() {
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

        let output = run_process(spec).expect("run hung command");

        assert!(output.timed_out);
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

    #[test]
    fn platform_shell_is_concrete() {
        #[cfg(target_os = "windows")]
        assert_eq!(Shell::for_current_platform(), Shell::WindowsCmd);

        #[cfg(not(target_os = "windows"))]
        assert_eq!(Shell::for_current_platform(), Shell::UnixSh);
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
