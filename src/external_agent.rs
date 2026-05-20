use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAgentCommand {
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
            program: program.into(),
            cwd: cwd.into(),
            prompt: prompt.into(),
            json_log: json_log.into(),
            output_last_message: output_last_message.into(),
            output_schema: None,
            timeout,
            env_allowlist: default_env_allowlist(),
            sandbox_mode: "workspace-write".to_string(),
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
    let argv = codex_argv(spec);
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

fn codex_argv(spec: &ExternalAgentCommand) -> Vec<String> {
    let mut argv = vec![
        "exec".to_string(),
        "--cd".to_string(),
        spec.cwd.display().to_string(),
        "--sandbox".to_string(),
        spec.sandbox_mode.clone(),
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
    loop {
        if child.try_wait()?.is_some() {
            let output = child.wait_with_output()?;
            return Ok(TimedOutput {
                status: Some(output.status),
                timed_out: false,
                stdout: output.stdout,
                stderr: output.stderr,
                process_error: None,
            });
        }

        if started.elapsed() >= timeout {
            let process_error = terminate_child_on_timeout(&mut child);
            let output = child.wait_with_output()?;
            return Ok(TimedOutput {
                status: Some(output.status),
                timed_out: true,
                stdout: output.stdout,
                stderr: output.stderr,
                process_error,
            });
        }

        thread::sleep(Duration::from_millis(25));
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
    let deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return term_error.map(|error| error.to_string()),
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => {
                return Some(format!(
                    "external agent timed out but process wait failed: {error}"
                ))
            }
        }
    }

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
