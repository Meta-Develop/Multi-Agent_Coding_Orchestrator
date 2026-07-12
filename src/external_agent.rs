use crate::process_runner::{
    run_process, CapturedBytes, EnvironmentMode, ProcessSpec, StdinMode, StreamCapture,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const OUTPUT_CHAR_LIMIT: usize = 32 * 1024;
const OUTPUT_CAPTURE_LIMIT_BYTES: usize = OUTPUT_CHAR_LIMIT * 4;

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

    let timeout = spec.timeout.saturating_sub(started.elapsed());
    let process_spec = ProcessSpec::direct(
        "external agent",
        &spec.program,
        argv.clone(),
        &spec.cwd,
        OUTPUT_CAPTURE_LIMIT_BYTES,
    )
    .with_environment(EnvironmentMode::ClearAndSet(allowed_env(
        &spec.env_allowlist,
    )))
    .with_stdin(StdinMode::Bytes(prompt))
    .with_timeout(Some(timeout))
    .with_stdout(StreamCapture::bounded(OUTPUT_CAPTURE_LIMIT_BYTES).tee_to(&spec.json_log));

    match run_process(process_spec) {
        Ok(output) => {
            report.exit_code = output.status.and_then(|status| status.code());
            report.timed_out = output.timed_out;
            report.stdout = summarize_output(&output.stdout);
            report.stderr = summarize_output(&output.stderr);
            report.error = output.stdin_error.or(output.process_error);
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
            report.error = Some(error.to_string());
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

fn summarize_output(output: &CapturedBytes) -> CapturedOutput {
    let summary = output.summarize_chars(OUTPUT_CHAR_LIMIT);
    CapturedOutput {
        text: summary.text,
        truncated: summary.truncated,
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
