//! Runtime-neutral launch configuration for subprocess agent runtimes.
//!
//! The adapter deliberately owns only the portable launch contract and the
//! per-runtime capability matrix. Runtime-specific containment and event
//! protocols can be added behind this boundary without making the supervisor's
//! runtime selection a vendor enum again.

mod capabilities;

pub use capabilities::{
    parse_adapter_allowlist, registered_adapter_ids, AdapterId, BlockingPreActionCallback,
    CapabilityMatrix, CapabilityMatrixCell, CapabilityMatrixRow, MatrixStatus, ModelCatalogSource,
    RuntimeCapabilities, SessionResume, SideEffectConfinement, UsageReporting,
    WorkspaceWritability,
};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
    fn adapter_id(&self) -> AdapterId;
    fn config(&self) -> &RuntimeAdapterConfig;

    fn capabilities(&self) -> RuntimeCapabilities {
        self.adapter_id().capabilities()
    }

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
    fn adapter_id(&self) -> AdapterId {
        AdapterId::Grok
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
    fn adapter_id(&self) -> AdapterId {
        AdapterId::Cursor
    }

    fn config(&self) -> &RuntimeAdapterConfig {
        &self.config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeminiAdapter {
    config: RuntimeAdapterConfig,
}

impl GeminiAdapter {
    pub fn from_environment() -> Self {
        Self {
            config: RuntimeAdapterConfig::from_adapter_environment(AdapterId::GeminiCli),
        }
    }
}

impl AgentRuntimeAdapter for GeminiAdapter {
    fn adapter_id(&self) -> AdapterId {
        AdapterId::GeminiCli
    }

    fn config(&self) -> &RuntimeAdapterConfig {
        &self.config
    }
}

impl RuntimeId {
    pub const fn default_binary(self) -> &'static str {
        AdapterId::from_runtime(self).default_binary()
    }

    pub const fn is_subprocess(self) -> bool {
        AdapterId::from_runtime(self).is_subprocess()
    }

    pub const fn capabilities(self) -> RuntimeCapabilities {
        AdapterId::from_runtime(self).capabilities()
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
    /// When true, [`RuntimeAdapterConfig::execute`] writes the prompt file to stdin.
    /// Headless CLIs that take the prompt as a string can then keep the text off argv.
    #[serde(default)]
    pub feed_prompt_on_stdin: bool,
}

impl RuntimeAdapterConfig {
    pub fn defaults(runtime: RuntimeId) -> Self {
        Self::defaults_for(AdapterId::from_runtime(runtime))
    }

    pub fn defaults_for(adapter: AdapterId) -> Self {
        let (template, output_capture, feed_prompt_on_stdin) = match adapter {
            AdapterId::Grok => (
                vec![
                    "--prompt-file".into(),
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
                false,
            ),
            AdapterId::Cursor => (
                vec![
                    "-p".into(),
                    "--trust".into(),
                    "--model".into(),
                    "{model}".into(),
                    "--workspace".into(),
                    "{cwd}".into(),
                    "--output-format".into(),
                    "text".into(),
                ],
                // cursor-agent --print writes to stdout; there is no --output file flag
                // and no standalone --effort flag.
                OutputCaptureMode::Stdout,
                true,
            ),
            AdapterId::GeminiCli => (
                vec![
                    "--prompt".into(),
                    "{prompt_text}".into(),
                    "--model".into(),
                    "{model}".into(),
                    "--output-format".into(),
                    "text".into(),
                ],
                OutputCaptureMode::Stdout,
                false,
            ),
            AdapterId::Codex | AdapterId::Fake => (Vec::new(), OutputCaptureMode::default(), false),
        };
        Self {
            binary: Some(PathBuf::from(adapter.default_binary())),
            argument_template: template,
            env_passthrough: Vec::new(),
            working_dir_flag: None,
            output_capture,
            feed_prompt_on_stdin,
        }
    }

    /// Load operator overrides from environment without requiring a code change.
    /// `MACO_<RUNTIME>_ARGS` is whitespace-separated and supports the same placeholders.
    pub fn from_environment(runtime: RuntimeId) -> Self {
        Self::from_adapter_environment(AdapterId::from_runtime(runtime))
    }

    pub fn from_adapter_environment(adapter: AdapterId) -> Self {
        let mut config = Self::defaults_for(adapter);
        let Some(prefix) = adapter.env_prefix() else {
            return config;
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
        if let Ok(stdin) = env::var(format!("{prefix}_STDIN_PROMPT")) {
            config.feed_prompt_on_stdin = matches!(stdin.as_str(), "1" | "true" | "stdin");
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
        let prompt_text = if self
            .argument_template
            .iter()
            .any(|token| token == "{prompt_text}")
        {
            std::fs::read_to_string(context.prompt).with_context(|| {
                format!(
                    "failed to read prompt file {} for {{prompt_text}}",
                    context.prompt.display()
                )
            })?
        } else {
            String::new()
        };
        let mut values = BTreeMap::from([
            ("prompt", context.prompt.display().to_string()),
            ("prompt_text", prompt_text),
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
        let mut command = Command::new(&resolved);
        command
            .args(&launch.argv)
            .current_dir(&launch.cwd)
            .envs(&launch.env)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if self.feed_prompt_on_stdin {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to launch runtime binary {}",
                launch.program.display()
            )
        })?;
        if self.feed_prompt_on_stdin {
            let prompt = std::fs::read(context.prompt).with_context(|| {
                format!(
                    "failed to read prompt file {} for stdin",
                    context.prompt.display()
                )
            })?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(&prompt).with_context(|| {
                    format!(
                        "failed to write prompt stdin for {}",
                        launch.program.display()
                    )
                })?;
            }
        }
        let output = child.wait_with_output().with_context(|| {
            format!(
                "failed to wait for runtime binary {}",
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
        assert!(!config.feed_prompt_on_stdin);
        assert_eq!(
            config.argument_template,
            [
                "--prompt-file",
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
                "--prompt-file",
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
        assert!(!spec.argv.iter().any(|arg| arg == "--output"));
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
    fn cursor_defaults_match_print_mode_and_capture_stdout() -> Result<()> {
        let config = RuntimeAdapterConfig::defaults(RuntimeId::Cursor);
        assert_eq!(config.binary_path(), Path::new("cursor-agent"));
        assert_eq!(config.output_capture, OutputCaptureMode::Stdout);
        assert!(config.feed_prompt_on_stdin);
        assert_eq!(
            config.argument_template,
            [
                "-p",
                "--trust",
                "--model",
                "{model}",
                "--workspace",
                "{cwd}",
                "--output-format",
                "text",
            ]
        );
        assert!(!config
            .argument_template
            .iter()
            .any(|arg| arg == "--effort" || arg == "--output" || arg == "{output}"));

        let spec = config.render(&launch_context(
            Path::new("prompt.txt"),
            Some("sonnet-4"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(
            spec.argv,
            [
                "-p",
                "--trust",
                "--model",
                "sonnet-4",
                "--workspace",
                "/tmp/work",
                "--output-format",
                "text",
            ]
        );
        Ok(())
    }

    #[test]
    fn gemini_defaults_expand_prompt_text_and_capture_stdout() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let prompt = dir.path().join("prompt.txt");
        fs::write(&prompt, "list the workspace files")?;
        let adapter = GeminiAdapter::from_environment();
        assert_eq!(adapter.adapter_id(), AdapterId::GeminiCli);
        assert_eq!(adapter.capabilities(), RuntimeCapabilities::GEMINI_CLI);
        let config = adapter.config();
        assert_eq!(config.binary_path(), Path::new("gemini"));
        assert_eq!(config.output_capture, OutputCaptureMode::Stdout);
        assert_eq!(
            config.argument_template,
            [
                "--prompt",
                "{prompt_text}",
                "--model",
                "{model}",
                "--output-format",
                "text",
            ]
        );

        let spec = config.render(&launch_context(
            &prompt,
            Some("gemini-2.5-pro"),
            None,
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(
            spec.argv,
            [
                "--prompt",
                "list the workspace files",
                "--model",
                "gemini-2.5-pro",
                "--output-format",
                "text",
            ]
        );
        Ok(())
    }

    #[test]
    fn gemini_prompt_text_fails_closed_when_the_file_is_missing() {
        let config = RuntimeAdapterConfig::defaults_for(AdapterId::GeminiCli);
        let error = config
            .render(&launch_context(
                Path::new("maco-missing-gemini-prompt.txt"),
                None,
                None,
                Path::new("."),
                Path::new("o"),
            ))
            .unwrap_err();
        assert!(error.to_string().contains("maco-missing-gemini-prompt.txt"));
    }

    #[test]
    fn codex_defaults_stay_empty_so_the_existing_execution_path_is_untouched() {
        let config = RuntimeAdapterConfig::defaults(RuntimeId::Codex);
        assert_eq!(config.binary_path(), Path::new("codex"));
        assert!(config.argument_template.is_empty());
        assert_eq!(config.output_capture, OutputCaptureMode::OutputFile);
        assert!(!config.feed_prompt_on_stdin);
    }

    #[test]
    fn renders_placeholders_and_passthrough_environment() -> Result<()> {
        let config = RuntimeAdapterConfig {
            binary: Some("scripted".into()),
            argument_template: vec!["{prompt}".into(), "{model}".into(), "{effort}".into()],
            env_passthrough: vec!["PATH".into()],
            working_dir_flag: Some("--cwd".into()),
            output_capture: OutputCaptureMode::Stdout,
            feed_prompt_on_stdin: false,
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

    #[cfg(unix)]
    #[test]
    fn scripted_transport_can_feed_prompt_on_stdin() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let script = dir.path().join("runtime");
        let prompt = dir.path().join("prompt");
        fs::write(&script, "#!/bin/sh\ncat\n")?;
        fs::write(&prompt, "stdin-prompt")?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))?;
        let config = RuntimeAdapterConfig {
            binary: Some(script),
            argument_template: Vec::new(),
            output_capture: OutputCaptureMode::Stdout,
            feed_prompt_on_stdin: true,
            ..RuntimeAdapterConfig::defaults(RuntimeId::Cursor)
        };
        let run = config.execute(&LaunchContext {
            prompt: &prompt,
            model: None,
            effort: None,
            cwd: dir.path(),
            output: &dir.path().join("o"),
        })?;
        assert_eq!(run.status, Some(0));
        assert_eq!(run.captured, b"stdin-prompt");
        Ok(())
    }

    #[test]
    fn shared_conformance_suite_covers_every_known_adapter() -> Result<()> {
        for adapter in AdapterId::ALL {
            let config = RuntimeAdapterConfig::defaults_for(adapter);
            assert_eq!(config.binary_path(), Path::new(adapter.default_binary()));
            assert!(
                adapter.capabilities().writable_refusal().is_some(),
                "{adapter} must refuse writable release until a blocking callback is hosted"
            );
            let capabilities = adapter.capabilities();
            assert_eq!(
                capabilities,
                AdapterId::parse(adapter.as_str()).unwrap().capabilities()
            );
            if adapter == AdapterId::GeminiCli {
                continue;
            }
            let spec = config.render(&launch_context(
                Path::new("prompt.txt"),
                Some("model"),
                Some("high"),
                Path::new("/tmp/work"),
                Path::new("out.txt"),
            ))?;
            assert_eq!(spec.program, PathBuf::from(adapter.default_binary()));
            assert_eq!(spec.cwd, PathBuf::from("/tmp/work"));
        }
        Ok(())
    }

    fn installed_cli_help(binary: &str) -> Option<String> {
        let output = Command::new(binary).arg("--help").output().ok()?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        if text.trim().is_empty() {
            None
        } else {
            Some(text)
        }
    }

    #[test]
    fn grok_template_flags_are_present_on_the_installed_cli() {
        let Some(help) = installed_cli_help("grok") else {
            return;
        };
        for flag in ["--prompt-file", "--model", "--cwd", "--output-format"] {
            assert!(help.contains(flag), "installed grok help missing {flag}");
        }
        assert!(
            help.contains("--effort") || help.contains("--reasoning-effort"),
            "installed grok help missing effort flag"
        );
        assert!(
            help.contains("models"),
            "installed grok help missing models catalog command"
        );
    }

    #[test]
    fn cursor_template_flags_are_present_on_the_installed_cli() {
        let Some(help) = installed_cli_help("cursor-agent") else {
            return;
        };
        for flag in [
            "--print",
            "--model",
            "--workspace",
            "--output-format",
            "--trust",
        ] {
            assert!(
                help.contains(flag),
                "installed cursor-agent help missing {flag}"
            );
        }
        assert!(
            !help.contains("--effort <"),
            "cursor-agent grew a standalone --effort flag; revisit the adapter template"
        );
    }

    #[test]
    fn gemini_template_flags_are_present_on_the_installed_cli() {
        let Some(help) = installed_cli_help("gemini") else {
            return;
        };
        for flag in ["--prompt", "--model", "--output-format"] {
            assert!(help.contains(flag), "installed gemini help missing {flag}");
        }
        assert!(
            help.contains("--resume"),
            "installed gemini help missing session resume"
        );
    }
}
