//! Runtime-neutral launch configuration for subprocess agent runtimes.
//!
//! The adapter deliberately owns only the portable launch contract. Runtime-specific
//! containment and event protocols can be added behind this boundary without making the
//! supervisor's runtime selection a vendor enum again.

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeId {
    #[default]
    Codex,
    Fake,
    Grok,
    Cursor,
}

/// Common launch boundary implemented by every subprocess runtime adapter.
pub trait AgentRuntimeAdapter {
    fn runtime(&self) -> RuntimeId;
    fn config(&self) -> &RuntimeAdapterConfig;

    fn launch(&self, context: &LaunchContext<'_>) -> Result<LaunchSpec> {
        self.config().render(context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrokAdapter {
    config: RuntimeAdapterConfig,
}

impl GrokAdapter {
    pub fn from_environment() -> Self {
        Self {
            config: RuntimeAdapterConfig::from_environment(RuntimeId::Grok),
        }
    }
}

impl AgentRuntimeAdapter for GrokAdapter {
    fn runtime(&self) -> RuntimeId {
        RuntimeId::Grok
    }

    fn config(&self) -> &RuntimeAdapterConfig {
        &self.config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorAdapter {
    config: RuntimeAdapterConfig,
}

impl CursorAdapter {
    pub fn from_environment() -> Self {
        Self {
            config: RuntimeAdapterConfig::from_environment(RuntimeId::Cursor),
        }
    }
}

impl AgentRuntimeAdapter for CursorAdapter {
    fn runtime(&self) -> RuntimeId {
        RuntimeId::Cursor
    }

    fn config(&self) -> &RuntimeAdapterConfig {
        &self.config
    }
}

impl RuntimeId {
    pub const fn default_binary(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Fake => "fake",
            Self::Grok => "grok",
            Self::Cursor => "cursor-agent",
        }
    }

    pub const fn is_subprocess(self) -> bool {
        matches!(self, Self::Codex | Self::Grok | Self::Cursor)
    }
}

/// CLI selection wins over an assignment selection; absent both, Codex remains the default.
pub const fn resolve_runtime(
    cli_override: Option<RuntimeId>,
    assignment_runtime: Option<RuntimeId>,
) -> RuntimeId {
    match cli_override {
        Some(runtime) => runtime,
        None => match assignment_runtime {
            Some(runtime) => runtime,
            None => RuntimeId::Codex,
        },
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputCaptureMode {
    #[default]
    OutputFile,
    Stdout,
    StdoutAndStderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdapterConfig {
    #[serde(default)]
    pub binary: Option<PathBuf>,
    #[serde(default)]
    pub argument_template: Vec<String>,
    #[serde(default)]
    pub env_passthrough: Vec<String>,
    #[serde(default)]
    pub working_dir_flag: Option<String>,
    #[serde(default)]
    pub output_capture: OutputCaptureMode,
}

impl RuntimeAdapterConfig {
    pub fn defaults(runtime: RuntimeId) -> Self {
        let (binary, template, output_capture) = match runtime {
            RuntimeId::Grok => (
                "grok",
                vec![
                    "-p".into(),
                    "{prompt}".into(),
                    "--model".into(),
                    "{model}".into(),
                    "--effort".into(),
                    "{effort}".into(),
                    "--cwd".into(),
                    "{cwd}".into(),
                    "--output-format".into(),
                    "plain".into(),
                ],
                // grok prints the headless response to stdout; there is no --output file flag.
                OutputCaptureMode::Stdout,
            ),
            RuntimeId::Cursor => (
                "cursor-agent",
                vec![
                    "-p".into(),
                    "{prompt}".into(),
                    "--model".into(),
                    "{model}".into(),
                    "--effort".into(),
                    "{effort}".into(),
                    "--workspace".into(),
                    "{cwd}".into(),
                    "--output".into(),
                    "{output}".into(),
                ],
                OutputCaptureMode::default(),
            ),
            _ => (
                runtime.default_binary(),
                Vec::new(),
                OutputCaptureMode::default(),
            ),
        };
        Self {
            binary: Some(PathBuf::from(binary)),
            argument_template: template,
            env_passthrough: Vec::new(),
            working_dir_flag: None,
            output_capture,
        }
    }

    /// Load operator overrides from environment without requiring a code change.
    /// `MACO_<RUNTIME>_ARGS` is whitespace-separated and supports the same placeholders.
    pub fn from_environment(runtime: RuntimeId) -> Self {
        let mut config = Self::defaults(runtime);
        let prefix = match runtime {
            RuntimeId::Grok => "MACO_GROK",
            RuntimeId::Cursor => "MACO_CURSOR",
            _ => return config,
        };
        if let Ok(binary) = env::var(format!("{prefix}_BIN")) {
            config.binary = Some(PathBuf::from(binary));
        }
        if let Ok(args) = env::var(format!("{prefix}_ARGS")) {
            config.argument_template = args.split_whitespace().map(str::to_string).collect();
        }
        if let Ok(names) = env::var(format!("{prefix}_ENV")) {
            config.env_passthrough = names
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect();
        }
        if let Ok(flag) = env::var(format!("{prefix}_CWD_FLAG")) {
            config.working_dir_flag = Some(flag);
        }
        if let Ok(mode) = env::var(format!("{prefix}_OUTPUT_CAPTURE")) {
            config.output_capture = match mode.as_str() {
                "stdout" => OutputCaptureMode::Stdout,
                "stdout_and_stderr" => OutputCaptureMode::StdoutAndStderr,
                _ => OutputCaptureMode::OutputFile,
            };
        }
        config
    }

    pub fn binary_path(&self) -> &Path {
        self.binary.as_deref().unwrap_or_else(|| Path::new(""))
    }

    pub fn render(&self, context: &LaunchContext<'_>) -> Result<LaunchSpec> {
        let binary = self.binary_path();
        if binary.as_os_str().is_empty() {
            bail!("runtime adapter binary is not configured")
        }
        let mut values = BTreeMap::from([
            ("prompt", context.prompt.display().to_string()),
            ("model", context.model.unwrap_or_default().to_string()),
            ("effort", context.effort.unwrap_or_default().to_string()),
            ("cwd", context.cwd.display().to_string()),
            ("output", context.output.display().to_string()),
        ]);
        let mut argv = Vec::new();
        for token in &self.argument_template {
            let Some(name) = token.strip_prefix('{').and_then(|v| v.strip_suffix('}')) else {
                argv.push(token.clone());
                continue;
            };
            let value = values
                .remove(name)
                .with_context(|| format!("unknown runtime adapter placeholder '{{{name}}}'"))?;
            if !value.is_empty() {
                argv.push(value);
            }
        }
        if let Some(flag) = &self.working_dir_flag {
            argv.extend([flag.clone(), context.cwd.display().to_string()]);
        }
        let env = self
            .env_passthrough
            .iter()
            .filter_map(|name| env::var(name).ok().map(|value| (name.clone(), value)))
            .collect();
        Ok(LaunchSpec {
            program: binary.to_path_buf(),
            argv,
            cwd: context.cwd.to_path_buf(),
            env,
            output_capture: self.output_capture,
        })
    }

    /// Small scripted-transport seam used by adapter conformance tests and diagnostics.
    pub fn execute(&self, context: &LaunchContext<'_>) -> Result<AdapterRun> {
        let launch = self.render(context)?;
        let resolved = resolve_binary(&launch.program)?;
        let output = Command::new(&resolved)
            .args(&launch.argv)
            .current_dir(&launch.cwd)
            .envs(&launch.env)
            .output()
            .with_context(|| {
                format!(
                    "failed to launch runtime binary {}",
                    launch.program.display()
                )
            })?;
        let captured = match launch.output_capture {
            OutputCaptureMode::OutputFile => std::fs::read(context.output).unwrap_or_default(),
            OutputCaptureMode::Stdout => output.stdout.clone(),
            OutputCaptureMode::StdoutAndStderr => {
                [output.stdout.clone(), output.stderr.clone()].concat()
            }
        };
        Ok(AdapterRun {
            argv: launch.argv,
            status: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
            captured,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchContext<'a> {
    pub prompt: &'a Path,
    pub model: Option<&'a str>,
    pub effort: Option<&'a str>,
    pub cwd: &'a Path,
    pub output: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    pub program: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub output_capture: OutputCaptureMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRun {
    pub argv: Vec<String>,
    pub status: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub captured: Vec<u8>,
}

fn resolve_binary(binary: &Path) -> Result<PathBuf> {
    if binary.components().count() > 1 {
        if binary.is_file() {
            return Ok(binary.to_path_buf());
        }
        bail!("runtime binary '{}' is missing", binary.display());
    }
    env::var_os("PATH")
        .as_deref()
        .into_iter()
        .flat_map(env::split_paths)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
        .with_context(|| format!("runtime binary '{}' is missing", binary.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn selection_precedence_is_cli_then_assignment_then_codex() {
        assert_eq!(resolve_runtime(None, None), RuntimeId::Codex);
        assert_eq!(
            resolve_runtime(None, Some(RuntimeId::Grok)),
            RuntimeId::Grok
        );
        assert_eq!(
            resolve_runtime(Some(RuntimeId::Cursor), Some(RuntimeId::Grok)),
            RuntimeId::Cursor
        );
    }

    fn launch_context<'a>(
        prompt: &'a Path,
        model: Option<&'a str>,
        effort: Option<&'a str>,
        cwd: &'a Path,
        output: &'a Path,
    ) -> LaunchContext<'a> {
        LaunchContext {
            prompt,
            model,
            effort,
            cwd,
            output,
        }
    }

    #[test]
    fn grok_defaults_match_real_cli_and_capture_stdout() -> Result<()> {
        let config = RuntimeAdapterConfig::defaults(RuntimeId::Grok);
        assert_eq!(config.binary_path(), Path::new("grok"));
        assert_eq!(config.output_capture, OutputCaptureMode::Stdout);
        assert_eq!(
            config.argument_template,
            [
                "-p",
                "{prompt}",
                "--model",
                "{model}",
                "--effort",
                "{effort}",
                "--cwd",
                "{cwd}",
                "--output-format",
                "plain",
            ]
        );

        let spec = config.render(&launch_context(
            Path::new("prompt.txt"),
            Some("grok-4.6"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(
            spec.argv,
            [
                "-p",
                "prompt.txt",
                "--model",
                "grok-4.6",
                "--effort",
                "high",
                "--cwd",
                "/tmp/work",
                "--output-format",
                "plain",
            ]
        );
        assert_eq!(spec.output_capture, OutputCaptureMode::Stdout);
        assert!(!spec
            .argv
            .iter()
            .any(|arg| arg == "--prompt" || arg == "--output"));
        Ok(())
    }

    #[test]
    fn grok_argument_template_override_replaces_the_whole_default() -> Result<()> {
        let config = RuntimeAdapterConfig {
            argument_template: vec!["--prompt-file".into(), "{prompt}".into()],
            ..RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        };
        let spec = config.render(&launch_context(
            Path::new("prompt.txt"),
            Some("grok-4.6"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(spec.argv, ["--prompt-file", "prompt.txt"]);
        assert_eq!(spec.output_capture, OutputCaptureMode::Stdout);
        Ok(())
    }

    #[test]
    fn grok_from_environment_keeps_defaults_without_overrides() {
        assert_eq!(
            RuntimeAdapterConfig::from_environment(RuntimeId::Grok),
            RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        );
    }

    #[test]
    fn cursor_defaults_keep_file_output_capture() {
        let config = RuntimeAdapterConfig::defaults(RuntimeId::Cursor);
        assert_eq!(config.binary_path(), Path::new("cursor-agent"));
        assert_eq!(config.output_capture, OutputCaptureMode::OutputFile);
        assert_eq!(
            config.argument_template,
            [
                "-p",
                "{prompt}",
                "--model",
                "{model}",
                "--effort",
                "{effort}",
                "--workspace",
                "{cwd}",
                "--output",
                "{output}",
            ]
        );
    }

    #[test]
    fn renders_placeholders_and_passthrough_environment() -> Result<()> {
        let config = RuntimeAdapterConfig {
            binary: Some("scripted".into()),
            argument_template: vec!["{prompt}".into(), "{model}".into(), "{effort}".into()],
            env_passthrough: vec!["PATH".into()],
            working_dir_flag: Some("--cwd".into()),
            output_capture: OutputCaptureMode::Stdout,
        };
        let spec = config.render(&LaunchContext {
            prompt: Path::new("prompt.txt"),
            model: Some("grok-model"),
            effort: Some("high"),
            cwd: Path::new("/tmp/work"),
            output: Path::new("out.txt"),
        })?;
        assert_eq!(
            spec.argv,
            ["prompt.txt", "grok-model", "high", "--cwd", "/tmp/work"]
        );
        assert!(spec.env.contains_key("PATH"));
        Ok(())
    }

    #[test]
    fn missing_binary_is_fail_closed() {
        let config = RuntimeAdapterConfig {
            binary: Some("maco-definitely-missing-runtime".into()),
            ..RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        };
        let error = config
            .execute(&LaunchContext {
                prompt: Path::new("p"),
                model: None,
                effort: None,
                cwd: Path::new("."),
                output: Path::new("o"),
            })
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("maco-definitely-missing-runtime"));
    }

    #[cfg(unix)]
    #[test]
    fn scripted_transport_captures_output_and_nonzero_exit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let script = dir.path().join("runtime");
        fs::write(&script, "#!/bin/sh\nprintf 'captured'\nexit 7\n")?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))?;
        let config = RuntimeAdapterConfig {
            binary: Some(script),
            argument_template: Vec::new(),
            output_capture: OutputCaptureMode::Stdout,
            ..RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        };
        let run = config.execute(&LaunchContext {
            prompt: Path::new("p"),
            model: None,
            effort: None,
            cwd: dir.path(),
            output: &dir.path().join("o"),
        })?;
        assert_eq!(run.status, Some(7));
        assert_eq!(run.captured, b"captured");
        Ok(())
    }
}
