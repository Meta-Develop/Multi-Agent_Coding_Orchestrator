use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;
const PIPE_READ_CHUNK_SIZE: usize = 8 * 1024;
const TIMEOUT_OUTPUT_DRAIN_GRACE_MS: u64 = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAgentCommand {
    pub invocation: ExternalAgentInvocation,
    pub program: PathBuf,
    pub cwd: PathBuf,
    pub prompt: PathBuf,
    pub json_log: PathBuf,
    pub output_last_message: PathBuf,
    pub output_schema: Option<PathBuf>,
    pub timeout: Duration,
    pub env_allowlist: Vec<String>,
    pub sandbox_mode: String,
    pub approval_mode: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAgentInvocation {
    CodexSupervisor,
    CodexConsultant,
    ClaudeConsultant,
}

impl ExternalAgentCommand {
    pub fn codex(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::CodexSupervisor,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            timeout,
            env_allowlist: default_env_allowlist(),
            sandbox_mode: "danger-full-access".to_string(),
            approval_mode: None,
        }
    }

    pub fn codex_read_only_consultant(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::CodexConsultant,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            timeout,
            env_allowlist: default_env_allowlist(),
            sandbox_mode: "read-only".to_string(),
            approval_mode: None,
        }
    }

    pub fn claude_consultant(
        program: impl Into<PathBuf>,
        cwd: impl Into<PathBuf>,
        prompt: impl Into<PathBuf>,
        json_log: impl Into<PathBuf>,
        output_last_message: impl Into<PathBuf>,
        timeout: Duration,
    ) -> Self {
        Self {
            invocation: ExternalAgentInvocation::ClaudeConsultant,
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            timeout,
            env_allowlist: default_env_allowlist(),
            sandbox_mode: "read-only".to_string(),
            approval_mode: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExternalAgentRun {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_seconds: u64,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
    pub error: Option<String>,
}

impl ExternalAgentRun {
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out && self.error.is_none()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CapturedOutput {
    pub text: String,
    pub truncated: bool,
}

pub fn default_env_allowlist() -> Vec<String> {
    [
        "HOME", "PATH", "USER", "USERNAME", "SHELL", "TMPDIR", "TMP", "TEMP", "RUST_LOG",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

pub fn run_external_agent(spec: &ExternalAgentCommand) -> ExternalAgentRun {
    let started = Instant::now();
    let argv = command_argv(spec);
    let mut command = Command::new(&spec.program);
    configure_timeout_process_control(&mut command);
    command
        .args(&argv)
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(allowed_env(&spec.env_allowlist))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut report = ExternalAgentRun {
        command: command_display(&spec.program, &argv),
        cwd: spec.cwd.clone(),
        timeout_seconds: spec.timeout.as_secs(),
        exit_code: None,
        duration_ms: 0,
        timed_out: false,
        stdout: CapturedOutput::default(),
        stderr: CapturedOutput::default(),
        error: None,
    };

    if let Err(error) = ensure_parent_dir(&spec.json_log)
        .and_then(|_| ensure_parent_dir(&spec.output_last_message))
        .and_then(|_| match &spec.output_schema {
            Some(path) => ensure_parent_dir(path),
            None => Ok(()),
        })
    {
        report.duration_ms = duration_millis(started.elapsed());
        report.error = Some(error.to_string());
        return report;
    }

    let prompt = match fs::read(&spec.prompt) {
        Ok(prompt) => prompt,
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            report.error = Some(format!(
                "failed to read prompt file {}: {error}",
                spec.prompt.display()
            ));
            return report;
        }
    };

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            report.duration_ms = duration_millis(started.elapsed());
            report.error = Some(format!("failed to spawn external agent: {error}"));
            return report;
        }
    };

    let prompt_writer = start_prompt_writer(&mut child, prompt);

    match wait_for_child(child, started, spec.timeout) {
        Ok(output) => {
            report.exit_code = output.status.and_then(|status| status.code());
            report.timed_out = output.timed_out;
            report.stdout = summarize_output(&output.stdout);
            report.stderr = summarize_output(&output.stderr);
            let stdin_error = prompt_writer.finish();
            report.error = stdin_error.or(output.process_error);
            if let Err(error) = fs::write(&spec.json_log, &output.stdout) {
                let message = format!(
                    "failed to write JSON event log {}: {error}",
                    spec.json_log.display()
                );
                report.error = match report.error.take() {
                    Some(existing) => Some(format!("{existing}; {message}")),
                    None => Some(message),
                };
            }
            if output.timed_out && report.error.is_none() {
                report.error = Some(format!(
                    "external agent timed out after {} seconds",
                    spec.timeout.as_secs()
                ));
            } else if !output.timed_out && !output.status.is_some_and(|status| status.success()) {
                report.error = Some(match output.status.and_then(|status| status.code()) {
                    Some(code) => format!("external agent exited with status {code}"),
                    None => "external agent terminated without an exit code".to_string(),
                });
            }
        }
        Err(error) => {
            let _prompt_writer = prompt_writer;
            report.error = Some(format!("failed to wait for external agent: {error}"));
        }
    }
    report.duration_ms = duration_millis(started.elapsed());
    report
}

fn command_argv(spec: &ExternalAgentCommand) -> Vec<String> {
    match spec.invocation {
        ExternalAgentInvocation::CodexSupervisor => codex_supervisor_argv(spec),
        ExternalAgentInvocation::CodexConsultant => codex_consultant_argv(spec),
        ExternalAgentInvocation::ClaudeConsultant => claude_consultant_argv(),
    }
}

fn codex_supervisor_argv(spec: &ExternalAgentCommand) -> Vec<String> {
    let mut argv = vec![
        "exec".to_string(),
        "--cd".to_string(),
        spec.cwd.display().to_string(),
        "--sandbox".to_string(),
        spec.sandbox_mode.clone(),
        "--enable".to_string(),
        "goals".to_string(),
        "--enable".to_string(),
        "multi_agent".to_string(),
    ];
    if let Some(approval_mode) = &spec.approval_mode {
        argv.push("-c".to_string());
        argv.push(format!("approval_policy=\"{approval_mode}\""));
    }
    argv.extend([
        "--json".to_string(),
        "--output-last-message".to_string(),
        spec.output_last_message.display().to_string(),
    ]);
    if let Some(schema) = &spec.output_schema {
        argv.push("--output-schema".to_string());
        argv.push(schema.display().to_string());
    }
    argv.push("-".to_string());
    argv
}

fn codex_consultant_argv(spec: &ExternalAgentCommand) -> Vec<String> {
    vec![
        "exec".to_string(),
        "--sandbox".to_string(),
        spec.sandbox_mode.clone(),
        "--cd".to_string(),
        spec.cwd.display().to_string(),
        "--output-last-message".to_string(),
        spec.output_last_message.display().to_string(),
        "-".to_string(),
    ]
}

fn claude_consultant_argv() -> Vec<String> {
    vec![
        "-p".to_string(),
        "--output-format".to_string(),
        "json".to_string(),
    ]
}

enum PromptWriter {
    Thread(thread::JoinHandle<Option<String>>),
    Immediate(Option<String>),
}

impl PromptWriter {
    fn finish(self) -> Option<String> {
        match self {
            Self::Thread(handle) => match handle.join() {
                Ok(error) => error,
                Err(_) => Some("prompt writer thread panicked".to_string()),
            },
            Self::Immediate(error) => error,
        }
    }
}

fn start_prompt_writer(child: &mut Child, prompt: Vec<u8>) -> PromptWriter {
    match child.stdin.take() {
        Some(mut stdin) => PromptWriter::Thread(thread::spawn(move || {
            stdin
                .write_all(&prompt)
                .err()
                .map(|error| format!("failed to write prompt to external agent stdin: {error}"))
        })),
        None => PromptWriter::Immediate(Some("failed to open external agent stdin".to_string())),
    }
}

fn allowed_env(allowlist: &[String]) -> BTreeMap<String, String> {
    allowlist
        .iter()
        .filter_map(|key| env::var(key).ok().map(|value| (key.clone(), value)))
        .collect()
}

fn command_display(program: &Path, argv: &[String]) -> Vec<String> {
    let mut command = Vec::with_capacity(argv.len() + 1);
    command.push(program.display().to_string());
    command.extend(argv.iter().cloned());
    command
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))
}

fn wait_for_child(
    mut child: Child,
    started: Instant,
    timeout: Duration,
) -> std::io::Result<TimedOutput> {
    let mut output_drainers = start_output_drainers(&mut child);
    let mut status = None;
    loop {
        output_drainers.drain_ready()?;

        if status.is_none() {
            status = child.try_wait()?;
        }

        if status.is_some() && output_drainers.is_complete() {
            let (stdout, stderr) = output_drainers.into_outputs();
            return Ok(TimedOutput {
                status,
                timed_out: false,
                stdout,
                stderr,
                process_error: None,
            });
        }

        if started.elapsed() >= timeout {
            let mut process_error = terminate_child_on_timeout(&mut child);
            if status.is_none() {
                status = Some(child.wait()?);
            }
            let drain_deadline =
                Instant::now() + Duration::from_millis(TIMEOUT_OUTPUT_DRAIN_GRACE_MS);
            if !output_drainers.finish_until(drain_deadline)? {
                process_error = append_process_error(
                    process_error,
                    format!(
                        "external agent timed out and output pipes did not close within {} ms",
                        TIMEOUT_OUTPUT_DRAIN_GRACE_MS
                    ),
                );
            }
            let (stdout, stderr) = output_drainers.into_outputs();
            return Ok(TimedOutput {
                status,
                timed_out: true,
                stdout,
                stderr,
                process_error,
            });
        }

        thread::sleep(Duration::from_millis(25));
    }
}

struct OutputDrainers {
    stdout: PipeReader,
    stderr: PipeReader,
}

impl OutputDrainers {
    fn drain_ready(&mut self) -> std::io::Result<()> {
        self.stdout.drain_ready()?;
        self.stderr.drain_ready()
    }

    fn is_complete(&self) -> bool {
        self.stdout.is_complete() && self.stderr.is_complete()
    }

    fn finish_until(&mut self, deadline: Instant) -> std::io::Result<bool> {
        loop {
            self.drain_ready()?;
            if self.is_complete() {
                return Ok(true);
            }

            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }

            let remaining = deadline.saturating_duration_since(now);
            let wait = remaining.min(Duration::from_millis(10));
            if !self.stdout.is_complete() {
                self.stdout.wait_for_event(wait)?;
            } else if !self.stderr.is_complete() {
                self.stderr.wait_for_event(wait)?;
            }
            self.stderr.drain_ready()?;
        }
    }

    fn into_outputs(self) -> (Vec<u8>, Vec<u8>) {
        (self.stdout.into_output(), self.stderr.into_output())
    }
}

enum PipeReader {
    Thread {
        stream_name: &'static str,
        receiver: Receiver<PipeReadEvent>,
        output: Vec<u8>,
        complete: bool,
    },
    Missing,
}

impl PipeReader {
    fn is_complete(&self) -> bool {
        match self {
            Self::Thread { complete, .. } => *complete,
            Self::Missing => true,
        }
    }

    fn drain_ready(&mut self) -> std::io::Result<()> {
        let Self::Thread {
            stream_name,
            receiver,
            output,
            complete,
        } = self
        else {
            return Ok(());
        };

        while !*complete {
            match receiver.try_recv() {
                Ok(event) => apply_pipe_event(stream_name, output, complete, event)?,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(std::io::Error::other(format!(
                        "external agent {stream_name} reader thread stopped unexpectedly"
                    )));
                }
            }
        }
        Ok(())
    }

    fn wait_for_event(&mut self, timeout: Duration) -> std::io::Result<()> {
        let Self::Thread {
            stream_name,
            receiver,
            output,
            complete,
        } = self
        else {
            return Ok(());
        };

        if *complete {
            return Ok(());
        }

        match receiver.recv_timeout(timeout) {
            Ok(event) => apply_pipe_event(stream_name, output, complete, event),
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Err(RecvTimeoutError::Disconnected) => Err(std::io::Error::other(format!(
                "external agent {stream_name} reader thread stopped unexpectedly"
            ))),
        }
    }

    fn into_output(self) -> Vec<u8> {
        match self {
            Self::Thread { output, .. } => output,
            Self::Missing => Vec::new(),
        }
    }
}

enum PipeReadEvent {
    Chunk(Vec<u8>),
    Finished,
    Error(std::io::Error),
}

fn apply_pipe_event(
    stream_name: &'static str,
    output: &mut Vec<u8>,
    complete: &mut bool,
    event: PipeReadEvent,
) -> std::io::Result<()> {
    match event {
        PipeReadEvent::Chunk(chunk) => output.extend(chunk),
        PipeReadEvent::Finished => *complete = true,
        PipeReadEvent::Error(error) => {
            *complete = true;
            return Err(std::io::Error::other(format!(
                "failed to read external agent {stream_name}: {error}"
            )));
        }
    }
    Ok(())
}

fn start_output_drainers(child: &mut Child) -> OutputDrainers {
    OutputDrainers {
        stdout: child
            .stdout
            .take()
            .map(|stdout| start_pipe_reader("stdout", stdout))
            .unwrap_or(PipeReader::Missing),
        stderr: child
            .stderr
            .take()
            .map(|stderr| start_pipe_reader("stderr", stderr))
            .unwrap_or(PipeReader::Missing),
    }
}

fn start_pipe_reader<R>(stream_name: &'static str, mut stream: R) -> PipeReader
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || loop {
        let mut buffer = vec![0_u8; PIPE_READ_CHUNK_SIZE];
        match stream.read(&mut buffer) {
            Ok(0) => {
                let _ = sender.send(PipeReadEvent::Finished);
                break;
            }
            Ok(bytes_read) => {
                buffer.truncate(bytes_read);
                if sender.send(PipeReadEvent::Chunk(buffer)).is_err() {
                    break;
                }
            }
            Err(error) => {
                let _ = sender.send(PipeReadEvent::Error(error));
                break;
            }
        }
    });

    PipeReader::Thread {
        stream_name,
        receiver,
        output: Vec::new(),
        complete: false,
    }
}

#[derive(Debug)]
struct TimedOutput {
    status: Option<ExitStatus>,
    timed_out: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    process_error: Option<String>,
}

fn configure_timeout_process_control(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    #[cfg(not(unix))]
    {
        let _ = command;
    }
}

fn terminate_child_on_timeout(child: &mut Child) -> Option<String> {
    #[cfg(unix)]
    {
        terminate_unix_process_group(child)
    }

    #[cfg(not(unix))]
    {
        child
            .kill()
            .err()
            .map(|error| format!("external agent timed out but process kill failed: {error}"))
    }
}

#[cfg(unix)]
fn terminate_unix_process_group(child: &mut Child) -> Option<String> {
    let pid = child.id();
    let term_error = send_unix_process_group_signal(pid, "TERM").err();
    thread::sleep(Duration::from_millis(100));
    let kill_result = send_unix_process_group_signal(pid, "KILL").or_else(|_| child.kill());
    kill_result.err().map(|error| {
        if let Some(term_error) = term_error {
            format!(
                "external agent timed out but process group termination failed: {term_error}; kill failed: {error}"
            )
        } else {
            format!("external agent timed out but process group kill failed: {error}")
        }
    })
}

fn append_process_error(existing: Option<String>, message: String) -> Option<String> {
    match existing {
        Some(existing) => Some(format!("{existing}; {message}")),
        None => Some(message),
    }
}

#[cfg(unix)]
fn send_unix_process_group_signal(pid: u32, signal: &str) -> std::io::Result<()> {
    let target = format!("-{pid}");
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(&target)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "kill -{signal} {target} exited with {status}"
        )))
    }
}

fn summarize_output(output: &[u8]) -> CapturedOutput {
    let text = String::from_utf8_lossy(output);
    let mut chars = text.chars();
    let value = chars.by_ref().take(OUTPUT_CHAR_LIMIT).collect::<String>();
    CapturedOutput {
        text: value,
        truncated: chars.next().is_some(),
    }
}

fn duration_millis(duration: Duration) -> u64 {
    let millis = duration.as_millis();
    if millis > u64::MAX as u128 {
        u64::MAX
    } else {
        millis as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn run_external_agent_drains_large_stdout_and_stderr_while_child_runs() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            r#"#!/bin/sh
while IFS= read -r _line; do
    :
done
i=0
while [ "$i" -lt 256 ]; do
    printf '%4096s' 'O'
    i=$((i + 1))
done
i=0
while [ "$i" -lt 256 ]; do
    printf '%4096s' 'E' >&2
    i=$((i + 1))
done
printf '\n{"type":"done"}\n'
"#,
        )?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agent, permissions)?;

        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "run the fake external agent\n")?;

        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            temp.path().join("last-message.txt"),
            Duration::from_secs(3),
        );

        let report = run_external_agent(&spec);

        assert_eq!(report.exit_code, Some(0));
        assert!(
            !report.timed_out,
            "large output child should exit before timeout: {report:?}"
        );
        assert_eq!(report.error, None);
        assert!(report.succeeded());
        assert!(report.stdout.truncated);
        assert!(report.stderr.truncated);
        assert!(report.stdout.text.len() >= OUTPUT_CHAR_LIMIT);
        assert!(report.stderr.text.len() >= OUTPUT_CHAR_LIMIT);
        assert!(fs::metadata(&spec.json_log)?.len() > (OUTPUT_CHAR_LIMIT as u64 * 2));

        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn run_external_agent_times_out_when_descendant_holds_output_pipes_open() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        let agent = temp.path().join("fake-agent.sh");
        fs::write(
            &agent,
            r#"#!/bin/sh
while IFS= read -r _line; do
    :
done
(
    trap '' TERM
    printf 'descendant started\n'
    printf 'descendant stderr started\n' >&2
    while :; do
        sleep 1
    done
) &
printf 'parent exiting\n'
exit 0
"#,
        )?;
        let mut permissions = fs::metadata(&agent)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&agent, permissions)?;

        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "run the fake external agent\n")?;

        let spec = ExternalAgentCommand::codex(
            &agent,
            temp.path(),
            &prompt,
            temp.path().join("events.jsonl"),
            temp.path().join("last-message.txt"),
            Duration::from_millis(200),
        );

        let started = Instant::now();
        let report = run_external_agent(&spec);

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timeout path should return promptly instead of hanging: {report:?}"
        );
        assert!(
            report.timed_out,
            "descendant-held output pipes should be treated as timeout: {report:?}"
        );
        assert!(report.stdout.text.contains("parent exiting"));
        assert!(report.stdout.text.contains("descendant started"));
        assert!(report.stderr.text.contains("descendant stderr started"));

        Ok(())
    }
}
