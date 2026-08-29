//! Runtime-neutral launch configuration for subprocess agent runtimes.
//!
//! The adapter deliberately owns only the portable launch contract and the
//! per-runtime capability matrix. Runtime-specific containment and event
//! protocols can be added behind this boundary without making the supervisor's
//! runtime selection a vendor enum again.

mod capabilities;
pub mod cursor;
pub mod grok;
pub mod hosted_callback;

pub use capabilities::{
    parse_adapter_allowlist, registered_adapter_ids, AdapterId, AdapterTrustClass,
    BlockingPreActionCallback, CapabilityMatrix, CapabilityMatrixCell, CapabilityMatrixRow,
    MatrixStatus, ModelCatalogSource, PrivateRuntimeStateHome, RuntimeCapabilities, SessionResume,
    SideEffectConfinement, UsageReporting, WorkspaceWritability, WritableLaunchTarget,
};
pub use hosted_callback::{
    capabilities_with_hosted_callback, review_pretooluse, writable_leaf_launch_refusal_with_host,
    ClaudePreToolUseHost, HostedActionKind, HostedCallbackAttachment, HostedCallbackDecision,
    HostedCallbackFixtureRunner, HostedCallbackPolicy, HostedHookResult, HostedPreActionGate,
    ProposedHostedAction,
};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
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
    #[serde(rename = "claude-code")]
    ClaudeCode,
    #[serde(rename = "gemini-cli")]
    GeminiCli,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeCodeAdapter {
    config: RuntimeAdapterConfig,
    hosted_callback: Option<HostedCallbackAttachment>,
}

impl ClaudeCodeAdapter {
    pub fn from_environment() -> Self {
        Self {
            config: RuntimeAdapterConfig::from_adapter_environment(AdapterId::ClaudeCode),
            hosted_callback: None,
        }
    }

    pub fn attach_hosted_pretooluse(
        &mut self,
        root: impl AsRef<Path>,
    ) -> Result<&HostedCallbackAttachment> {
        let host = ClaudePreToolUseHost::attach(root.as_ref())?;
        self.hosted_callback = Some(host.into_attachment());
        self.hosted_callback
            .as_ref()
            .context("hosted PreToolUse attachment vanished after install")
    }

    pub fn hosted_callback(&self) -> Option<&HostedCallbackAttachment> {
        self.hosted_callback.as_ref()
    }

    pub fn require_writable_release(&self) -> Result<()> {
        if let Some(reason) = self.capabilities().writable_refusal() {
            bail!("writable Claude Code launch failed closed: {reason}");
        }
        Ok(())
    }
}

impl AgentRuntimeAdapter for ClaudeCodeAdapter {
    fn adapter_id(&self) -> AdapterId {
        AdapterId::ClaudeCode
    }

    fn config(&self) -> &RuntimeAdapterConfig {
        &self.config
    }

    fn capabilities(&self) -> RuntimeCapabilities {
        capabilities_with_hosted_callback(self.hosted_callback.as_ref())
    }

    fn launch(&self, context: &LaunchContext<'_>) -> Result<LaunchSpec> {
        let mut spec = self.config().render(context)?;
        if let Some(host) = &self.hosted_callback {
            if !host.covers_all_actions() {
                bail!(
                    "Claude Code launch failed closed: hosted PreToolUse callback does not cover every action"
                );
            }
            spec.env.insert(
                "CLAUDE_CONFIG_DIR".to_string(),
                host.claude_config_dir().display().to_string(),
            );
            spec.env.insert(
                "MACO_HOSTED_CALLBACK_DIR".to_string(),
                host.callback_dir().display().to_string(),
            );
            if !spec.argv.iter().any(|arg| arg == "--permission-mode") {
                spec.argv
                    .extend(["--permission-mode".to_string(), "dontAsk".to_string()]);
            }
        }
        Ok(spec)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAdapter {
    config: RuntimeAdapterConfig,
}

impl CodexAdapter {
    pub fn from_environment() -> Self {
        Self {
            config: RuntimeAdapterConfig::from_adapter_environment(AdapterId::Codex),
        }
    }
}

impl AgentRuntimeAdapter for CodexAdapter {
    fn adapter_id(&self) -> AdapterId {
        AdapterId::Codex
    }

    fn config(&self) -> &RuntimeAdapterConfig {
        &self.config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeAdapter {
    config: RuntimeAdapterConfig,
}

impl FakeAdapter {
    pub fn from_environment() -> Self {
        Self {
            config: RuntimeAdapterConfig::from_adapter_environment(AdapterId::Fake),
        }
    }
}

impl AgentRuntimeAdapter for FakeAdapter {
    fn adapter_id(&self) -> AdapterId {
        AdapterId::Fake
    }

    fn config(&self) -> &RuntimeAdapterConfig {
        &self.config
    }
}

/// Construct the adapter for a registered id. Codex keeps an empty launch
/// template so the existing execution path continues to own its argv.
pub fn adapter_for(id: AdapterId) -> Box<dyn AgentRuntimeAdapter> {
    match id {
        AdapterId::Codex => Box::new(CodexAdapter::from_environment()),
        AdapterId::Fake => Box::new(FakeAdapter::from_environment()),
        AdapterId::Grok => Box::new(GrokAdapter::from_environment()),
        AdapterId::Cursor => Box::new(CursorAdapter::from_environment()),
        AdapterId::ClaudeCode => Box::new(ClaudeCodeAdapter::from_environment()),
        AdapterId::GeminiCli => Box::new(GeminiAdapter::from_environment()),
    }
}

impl RuntimeId {
    pub const fn as_str(self) -> &'static str {
        AdapterId::from_runtime(self).as_str()
    }

    pub const fn default_binary(self) -> &'static str {
        AdapterId::from_runtime(self).default_binary()
    }

    pub const fn is_subprocess(self) -> bool {
        AdapterId::from_runtime(self).is_subprocess()
    }

    pub const fn capabilities(self) -> RuntimeCapabilities {
        AdapterId::from_runtime(self).capabilities()
    }

    /// Non-Codex, non-Fake subprocess CLIs launched through the adapter boundary.
    pub const fn is_adapter_subprocess(self) -> bool {
        !matches!(self, Self::Codex | Self::Fake)
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

const GROK_NO_SUBAGENTS_ARG: &str = "--no-subagents";

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
                    GROK_NO_SUBAGENTS_ARG.into(),
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
            AdapterId::ClaudeCode => (
                vec![
                    "-p".into(),
                    "--output-format".into(),
                    "json".into(),
                    "--model".into(),
                    "{model}".into(),
                    "--effort".into(),
                    "{effort}".into(),
                ],
                // claude --print writes the JSON envelope to stdout; there is no
                // --output file flag and no --cwd flag. Prompt text is fed on stdin.
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
    /// Grok's non-delegation flag is restored after this mutable operator template.
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
            config.replace_operator_argument_template(adapter, &args);
        }
        if let Ok(names) = env::var(format!("{prefix}_ENV")) {
            // Drop denied names here so the live insert in external_agent.rs
            // cannot reinstate them. Remaining names are still refused at
            // render if a caller constructs the config directly.
            config.env_passthrough = env_passthrough_names_from_operator_list(&names);
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

    fn replace_operator_argument_template(&mut self, adapter: AdapterId, args: &str) {
        self.argument_template = args.split_whitespace().map(str::to_string).collect();
        if adapter == AdapterId::Grok {
            self.argument_template
                .retain(|argument| argument != GROK_NO_SUBAGENTS_ARG);
            self.argument_template.push(GROK_NO_SUBAGENTS_ARG.into());
        }
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
            read_prompt_text_for_argv(context.prompt)?
        } else {
            String::new()
        };
        let values = BTreeMap::from([
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
                .get(name)
                .cloned()
                .with_context(|| format!("unknown runtime adapter placeholder '{{{name}}}'"))?;
            if value.is_empty() {
                drop_empty_placeholder_pair(&mut argv);
                continue;
            }
            argv.push(value);
        }
        if let Some(flag) = &self.working_dir_flag {
            argv.extend([flag.clone(), context.cwd.display().to_string()]);
        }
        let env = collect_screened_passthrough_env(&self.env_passthrough)?;
        Ok(LaunchSpec {
            program: binary.to_path_buf(),
            argv,
            cwd: context.cwd.to_path_buf(),
            env,
            output_capture: self.output_capture,
        })
    }

    /// Fail-closed argv for a subprocess runtime. Callers must propagate the
    /// error: an empty vector is a successful Codex/empty-template render, not a
    /// substitute for a configuration failure.
    pub fn render_os_argv(&self, context: &LaunchContext<'_>) -> Result<Vec<OsString>> {
        Ok(self
            .render(context)?
            .argv
            .into_iter()
            .map(OsString::from)
            .collect())
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

/// Linux `MAX_ARG_STRLEN` is 32 pages (131072). Stay one byte under so a
/// `{prompt_text}` argv element cannot hit `E2BIG` on that cap.
const MAX_PROMPT_TEXT_ARGV_BYTES: u64 = 131_072 - 1;

fn read_prompt_text_for_argv(path: &Path) -> Result<String> {
    let text = crate::safe_state::BoundedRegularReader::read_utf8(path, MAX_PROMPT_TEXT_ARGV_BYTES)
        .with_context(|| {
            format!(
                "failed to read prompt file {} for {{prompt_text}}",
                path.display()
            )
        })?;
    if text.contains('\0') {
        bail!(
            "prompt file {} for {{prompt_text}} contains a NUL byte and cannot be passed as argv",
            path.display()
        );
    }
    Ok(text)
}

fn drop_empty_placeholder_pair(argv: &mut Vec<String>) {
    if argv
        .last()
        .is_some_and(|token| is_paired_option_flag(token))
    {
        argv.pop();
    }
}

fn is_paired_option_flag(token: &str) -> bool {
    token.starts_with('-') && token != "-" && token != "--" && !token.contains('=')
}

/// Operator `MACO_<RUNTIME>_ENV` lists are comma-separated. Empty names are
/// dropped; denied names are omitted so a live insert after `allowed_env`
/// cannot reinstate them.
fn env_passthrough_names_from_operator_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .filter(|name| denied_passthrough_env_reason(name).is_none())
        .map(str::to_string)
        .collect()
}

/// Parse a comma-separated passthrough list and refuse any denied name.
pub fn parse_env_passthrough_list(raw: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for name in raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        screen_env_passthrough_name(name)?;
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_string());
        }
    }
    Ok(names)
}

/// Refuse a passthrough name that would undo worker environment hardening.
pub fn screen_env_passthrough_name(name: &str) -> Result<()> {
    if let Some(reason) = denied_passthrough_env_reason(name) {
        bail!("refused runtime adapter env passthrough '{name}': {reason}");
    }
    Ok(())
}

fn collect_screened_passthrough_env(names: &[String]) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::new();
    for name in names {
        screen_env_passthrough_name(name)?;
        if let Ok(value) = env::var(name) {
            environment.insert(name.clone(), value);
        }
    }
    Ok(environment)
}

fn denied_passthrough_env_reason(name: &str) -> Option<&'static str> {
    if name.is_empty()
        || name.len() > 256
        || name.contains('=')
        || name.contains('\0')
        || name.bytes().any(|byte| byte.is_ascii_control())
    {
        return Some("malformed environment variable name");
    }
    let bytes = name.as_bytes();
    if bytes.starts_with(b"LD_") || bytes.starts_with(b"DYLD_") || bytes.starts_with(b"MALLOC_") {
        return Some("dynamic-loader or allocator hook");
    }
    match name {
        "BASH_ENV"
        | "ENV"
        | "SHELLOPTS"
        | "BASHOPTS"
        | "KSH_ENV"
        | "ZDOTDIR"
        | "PYTHONPATH"
        | "PYTHONHOME"
        | "PYTHONSTARTUP"
        | "PYTHONINSPECT"
        | "PYTHONUSERBASE"
        | "PERL5OPT"
        | "PERL5LIB"
        | "PERLLIB"
        | "PERL5DB"
        | "RUBYOPT"
        | "RUBYLIB"
        | "NODE_OPTIONS"
        | "NODE_PATH"
        | "GCONV_PATH"
        | "LOCPATH"
        | "JAVA_TOOL_OPTIONS"
        | "_JAVA_OPTIONS"
        | "JDK_JAVA_OPTIONS"
        | "CLASSPATH"
        | "LUA_PATH"
        | "LUA_CPATH"
        | "LUA_INIT"
        | "PHPRC"
        | "PHP_INI_SCAN_DIR"
        | "RUSTC_WRAPPER"
        | "RUSTC_WORKSPACE_WRAPPER"
        | "GIT_EXEC_PATH"
        | "GIT_TEMPLATE_DIR" => Some("shell-startup or interpreter code-loading hook"),
        "OPENAI_API_KEY" | "CODEX_API_KEY" | "CODEX_ACCESS_TOKEN" => {
            Some("credential name tracked by the redactor")
        }
        _ => None,
    }
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
                "--no-subagents",
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
                "--no-subagents",
            ]
        );
        assert_eq!(spec.output_capture, OutputCaptureMode::Stdout);
        assert!(!spec.argv.iter().any(|arg| arg == "--output"));
        Ok(())
    }

    #[test]
    fn empty_model_drops_the_preceding_flag_instead_of_shifting_argv() -> Result<()> {
        let spec = RuntimeAdapterConfig::defaults(RuntimeId::Grok).render(&launch_context(
            Path::new("prompt.txt"),
            None,
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(
            spec.argv,
            [
                "--prompt-file",
                "prompt.txt",
                "--effort",
                "high",
                "--cwd",
                "/tmp/work",
                "--output-format",
                "plain",
                "--no-subagents",
            ]
        );
        Ok(())
    }

    #[test]
    fn empty_model_and_effort_drop_both_flag_pairs() -> Result<()> {
        let spec = RuntimeAdapterConfig::defaults(RuntimeId::Grok).render(&launch_context(
            Path::new("prompt.txt"),
            None,
            None,
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(
            spec.argv,
            [
                "--prompt-file",
                "prompt.txt",
                "--cwd",
                "/tmp/work",
                "--output-format",
                "plain",
                "--no-subagents",
            ]
        );
        Ok(())
    }

    #[test]
    fn empty_cursor_model_drops_the_preceding_flag() -> Result<()> {
        let spec = RuntimeAdapterConfig::defaults(RuntimeId::Cursor).render(&launch_context(
            Path::new("prompt.txt"),
            None,
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(
            spec.argv,
            [
                "-p",
                "--trust",
                "--workspace",
                "/tmp/work",
                "--output-format",
                "text",
            ]
        );
        Ok(())
    }

    #[test]
    fn repeated_placeholders_render_the_same_value() -> Result<()> {
        let config = RuntimeAdapterConfig {
            argument_template: vec![
                "--model".into(),
                "{model}".into(),
                "--fallback-model".into(),
                "{model}".into(),
            ],
            ..RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        };
        let spec = config.render(&launch_context(
            Path::new("prompt.txt"),
            Some("grok-4.6"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(
            spec.argv,
            ["--model", "grok-4.6", "--fallback-model", "grok-4.6"]
        );
        Ok(())
    }

    #[test]
    fn prompt_text_refuses_an_argv_oversized_file() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let prompt = dir.path().join("prompt.txt");
        fs::write(
            &prompt,
            vec![b'a'; (MAX_PROMPT_TEXT_ARGV_BYTES as usize) + 1],
        )?;
        let config = RuntimeAdapterConfig::defaults_for(AdapterId::GeminiCli);
        let error = config
            .render(&launch_context(
                &prompt,
                Some("gemini-2.5-pro"),
                None,
                Path::new("/tmp/work"),
                Path::new("out.txt"),
            ))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("bounded read limit") || error.contains("{prompt_text}"),
            "unexpected render error: {error}"
        );
        Ok(())
    }

    #[test]
    fn grok_operator_argument_override_preserves_immutable_no_subagents() -> Result<()> {
        let mut config = RuntimeAdapterConfig::defaults(RuntimeId::Grok);
        config.replace_operator_argument_template(AdapterId::Grok, "--prompt-file {prompt}");
        let spec = config.render(&launch_context(
            Path::new("prompt.txt"),
            Some("grok-4.6"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(spec.argv, ["--prompt-file", "prompt.txt", "--no-subagents"]);
        assert_eq!(spec.output_capture, OutputCaptureMode::Stdout);

        config.replace_operator_argument_template(
            AdapterId::Grok,
            "--no-subagents --prompt-file {prompt} --no-subagents",
        );
        assert_eq!(
            config
                .argument_template
                .iter()
                .filter(|argument| argument.as_str() == GROK_NO_SUBAGENTS_ARG)
                .count(),
            1
        );
        assert_eq!(
            config.argument_template.last().map(String::as_str),
            Some(GROK_NO_SUBAGENTS_ARG)
        );

        let mut cursor = RuntimeAdapterConfig::defaults(RuntimeId::Cursor);
        cursor.replace_operator_argument_template(AdapterId::Cursor, "--prompt-file {prompt}");
        let cursor_spec = cursor.render(&launch_context(
            Path::new("prompt.txt"),
            Some("sonnet-4"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(cursor_spec.argv, ["--prompt-file", "prompt.txt"]);
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
    fn claude_defaults_match_print_json_and_feed_prompt_on_stdin() -> Result<()> {
        let adapter = ClaudeCodeAdapter::from_environment();
        assert_eq!(adapter.adapter_id(), AdapterId::ClaudeCode);
        assert_eq!(adapter.capabilities(), RuntimeCapabilities::CLAUDE_CODE);
        assert!(!adapter.capabilities().admits_writable_release());
        let config = adapter.config();
        assert_eq!(config.binary_path(), Path::new("claude"));
        assert_eq!(config.output_capture, OutputCaptureMode::Stdout);
        assert!(config.feed_prompt_on_stdin);
        assert_eq!(
            config.argument_template,
            [
                "-p",
                "--output-format",
                "json",
                "--model",
                "{model}",
                "--effort",
                "{effort}",
            ]
        );

        let spec = config.render(&launch_context(
            Path::new("prompt.txt"),
            Some("sonnet"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert_eq!(
            spec.argv,
            [
                "-p",
                "--output-format",
                "json",
                "--model",
                "sonnet",
                "--effort",
                "high",
            ]
        );
        assert!(!spec
            .argv
            .iter()
            .any(|arg| arg == "--output" || arg == "--cwd"));
        Ok(())
    }

    #[test]
    fn attached_claude_launch_injects_hosted_pretooluse_env() -> Result<()> {
        let mut adapter = ClaudeCodeAdapter::from_environment();
        let unattached = adapter.launch(&launch_context(
            Path::new("prompt.txt"),
            Some("sonnet"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        assert!(!unattached.env.contains_key("CLAUDE_CONFIG_DIR"));
        assert!(!unattached.argv.iter().any(|arg| arg == "--permission-mode"));

        let temp = tempfile::tempdir()?;
        adapter.attach_hosted_pretooluse(temp.path())?;
        let spec = adapter.launch(&launch_context(
            Path::new("prompt.txt"),
            Some("sonnet"),
            Some("high"),
            Path::new("/tmp/work"),
            Path::new("out.txt"),
        ))?;
        let host = adapter.hosted_callback().expect("attached host");
        assert_eq!(
            spec.env.get("CLAUDE_CONFIG_DIR"),
            Some(&host.claude_config_dir().display().to_string())
        );
        assert_eq!(
            spec.env.get("MACO_HOSTED_CALLBACK_DIR"),
            Some(&host.callback_dir().display().to_string())
        );
        assert!(spec
            .argv
            .windows(2)
            .any(|pair| pair == ["--permission-mode", "dontAsk"]));
        assert!(adapter.capabilities().admits_writable_release());
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
    fn operator_env_list_drops_shell_startup_and_loader_hooks() {
        assert_eq!(
            env_passthrough_names_from_operator_list(
                "PATH,BASH_ENV, ENV, LD_PRELOAD,,DYLD_INSERT_LIBRARIES"
            ),
            vec!["PATH".to_string()]
        );
        assert!(env_passthrough_names_from_operator_list("BASH_ENV,LD_LIBRARY_PATH").is_empty());
    }

    #[test]
    fn parse_env_passthrough_list_refuses_denied_names() {
        assert_eq!(parse_env_passthrough_list("PATH").unwrap(), vec!["PATH"]);
        let error = parse_env_passthrough_list("PATH,BASH_ENV")
            .unwrap_err()
            .to_string();
        assert!(error.contains("BASH_ENV"), "{error}");
        assert!(
            error.contains("refused runtime adapter env passthrough"),
            "{error}"
        );
        let preload = parse_env_passthrough_list("LD_PRELOAD")
            .unwrap_err()
            .to_string();
        assert!(preload.contains("LD_PRELOAD"), "{preload}");
        let dyld = parse_env_passthrough_list("DYLD_LIBRARY_PATH")
            .unwrap_err()
            .to_string();
        assert!(dyld.contains("DYLD_LIBRARY_PATH"), "{dyld}");
        let credential = parse_env_passthrough_list("OPENAI_API_KEY")
            .unwrap_err()
            .to_string();
        assert!(credential.contains("OPENAI_API_KEY"), "{credential}");
    }

    #[test]
    fn render_refuses_unscreened_passthrough_environment() {
        let config = RuntimeAdapterConfig {
            env_passthrough: vec!["BASH_ENV".into()],
            ..RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        };
        let error = config
            .render(&launch_context(
                Path::new("prompt.txt"),
                Some("grok-4.6"),
                Some("high"),
                Path::new("/tmp/work"),
                Path::new("out.txt"),
            ))
            .unwrap_err()
            .to_string();
        assert!(error.contains("BASH_ENV"), "{error}");
        assert!(
            error.contains("refused runtime adapter env passthrough"),
            "{error}"
        );
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

    #[test]
    fn unconfigured_binary_render_is_an_error_not_an_empty_argv() {
        let config = RuntimeAdapterConfig {
            binary: Some(PathBuf::new()),
            ..RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        };
        let error = config
            .render_os_argv(&launch_context(
                Path::new("prompt.txt"),
                Some("grok-4.6"),
                Some("high"),
                Path::new("/tmp/work"),
                Path::new("out.txt"),
            ))
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("runtime adapter binary is not configured"));
    }

    #[test]
    fn unknown_placeholder_render_is_an_error_not_an_empty_argv() {
        let config = RuntimeAdapterConfig {
            argument_template: vec!["--flag".into(), "{unknown}".into()],
            ..RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        };
        let error = config
            .render_os_argv(&launch_context(
                Path::new("prompt.txt"),
                Some("grok-4.6"),
                Some("high"),
                Path::new("/tmp/work"),
                Path::new("out.txt"),
            ))
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown runtime adapter placeholder '{unknown}'"));
    }

    #[test]
    fn missing_prompt_text_file_render_is_an_error_not_an_empty_argv() {
        let config = RuntimeAdapterConfig {
            argument_template: vec!["--prompt".into(), "{prompt_text}".into()],
            ..RuntimeAdapterConfig::defaults(RuntimeId::Grok)
        };
        let error = config
            .render_os_argv(&launch_context(
                Path::new("maco-missing-adapter-prompt.txt"),
                Some("grok-4.6"),
                Some("high"),
                Path::new("/tmp/work"),
                Path::new("out.txt"),
            ))
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("maco-missing-adapter-prompt.txt"),
            "unexpected render error: {message}"
        );
        assert!(
            message.contains("{prompt_text}") || message.contains("prompt"),
            "unexpected render error: {message}"
        );
    }

    #[test]
    fn successful_render_os_argv_preserves_the_template() -> Result<()> {
        let argv =
            RuntimeAdapterConfig::defaults(RuntimeId::Grok).render_os_argv(&launch_context(
                Path::new("prompt.txt"),
                Some("grok-4.6"),
                Some("high"),
                Path::new("/tmp/work"),
                Path::new("out.txt"),
            ))?;
        assert_eq!(
            argv,
            [
                OsString::from("--prompt-file"),
                OsString::from("prompt.txt"),
                OsString::from("--model"),
                OsString::from("grok-4.6"),
                OsString::from("--effort"),
                OsString::from("high"),
                OsString::from("--cwd"),
                OsString::from("/tmp/work"),
                OsString::from("--output-format"),
                OsString::from("plain"),
                OsString::from("--no-subagents"),
            ]
        );
        Ok(())
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
    fn non_codex_adapters_do_not_hardcode_codex_launch_or_writable_gates() -> Result<()> {
        for id in AdapterId::ALL {
            if id == AdapterId::Codex {
                continue;
            }
            let config = RuntimeAdapterConfig::defaults_for(id);
            assert_ne!(
                config.binary_path(),
                Path::new("codex"),
                "{id} must not launch the Codex binary"
            );
            assert!(
                config
                    .argument_template
                    .iter()
                    .all(|token| !token.to_ascii_lowercase().contains("codex")),
                "{id} launch template still names Codex"
            );
            assert_eq!(
                id.capabilities().writable_refusal(),
                Some("blocking_pre_action_callback != All"),
                "{id} writable gate must be capability-derived, not vendor-named"
            );
            let expected = if id == AdapterId::Fake {
                "writable_workspace == unsupported"
            } else {
                "side_effect_confinement != verified"
            };
            assert_eq!(
                id.writable_leaf_launch_refusal(),
                Some(expected),
                "{id} must not advertise unverified worktree writability"
            );
        }
        // Codex remains the unresolved default by operator policy.
        assert_eq!(resolve_runtime(None, None), RuntimeId::Codex);
        Ok(())
    }

    #[test]
    fn registry_constructs_every_known_adapter_without_vendor_gates() -> Result<()> {
        for id in AdapterId::ALL {
            let adapter = adapter_for(id);
            assert_eq!(adapter.adapter_id(), id);
            assert_eq!(adapter.capabilities(), id.capabilities());
            assert_eq!(
                adapter.config().binary_path(),
                Path::new(id.default_binary())
            );
            assert!(
                !adapter.capabilities().admits_writable_release(),
                "{id} writable admission must come from the capability descriptor"
            );
        }
        let codex = adapter_for(AdapterId::Codex);
        assert!(codex.config().argument_template.is_empty());
        assert_eq!(codex.config().output_capture, OutputCaptureMode::OutputFile);
        Ok(())
    }

    #[test]
    fn shared_conformance_suite_covers_every_known_adapter() -> Result<()> {
        for adapter in AdapterId::ALL {
            let config = RuntimeAdapterConfig::defaults_for(adapter);
            assert_eq!(config.binary_path(), Path::new(adapter.default_binary()));
            assert!(
                adapter.capabilities().writable_refusal().is_some(),
                "{adapter} must refuse primary-writable release until a hosted All-callback exists"
            );
            if adapter == AdapterId::Codex {
                assert!(
                    adapter.capabilities().admits_worktree_writable(),
                    "Codex must retain verified managed-worktree admission"
                );
            } else {
                assert!(
                    adapter.capabilities().worktree_writable_refusal().is_some(),
                    "{adapter} must not claim managed-worktree writability without verified confinement"
                );
            }
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

    const VERIFY_INSTALLED_CLIS_ENV: &str = "MACO_VERIFY_INSTALLED_CLIS";

    fn installed_cli_verification_enabled() -> bool {
        matches!(
            env::var(VERIFY_INSTALLED_CLIS_ENV).as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
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

    fn require_installed_cli_help(binary: &str) -> String {
        installed_cli_help(binary)
            .unwrap_or_else(|| panic!("{VERIFY_INSTALLED_CLIS_ENV}=1 requires `{binary}` on PATH"))
    }

    fn assert_help_contains(help: &str, flags: &[&str], label: &str) {
        for flag in flags {
            assert!(help.contains(flag), "{label} missing {flag}");
        }
    }

    fn assert_grok_help_contract(help: &str, label: &str) {
        assert_help_contains(
            help,
            &["--prompt-file", "--model", "--cwd", "--output-format"],
            label,
        );
        assert!(
            help.contains("--effort") || help.contains("--reasoning-effort"),
            "{label} missing effort flag"
        );
        assert!(
            help.contains("models"),
            "{label} missing models catalog command"
        );
    }

    fn assert_cursor_help_contract(help: &str, label: &str) {
        assert_help_contains(
            help,
            &[
                "--print",
                "--model",
                "--workspace",
                "--output-format",
                "--trust",
            ],
            label,
        );
        assert!(
            !help.contains("--effort <"),
            "{label} grew a standalone --effort flag; revisit the adapter template"
        );
    }

    fn assert_claude_help_contract(help: &str, label: &str) {
        assert_help_contains(
            help,
            &[
                "--print",
                "--output-format",
                "--model",
                "--effort",
                "--resume",
                "--permission-mode",
            ],
            label,
        );
    }

    fn assert_gemini_help_contract(help: &str, label: &str) {
        assert_help_contains(
            help,
            &["--prompt", "--model", "--output-format", "--resume"],
            label,
        );
    }

    #[test]
    fn grok_template_flags_are_present_in_the_pinned_help_fixture() {
        assert_grok_help_contract(
            include_str!("fixtures/grok-help.txt"),
            "pinned grok help fixture",
        );
    }

    #[test]
    fn cursor_template_flags_are_present_in_the_pinned_help_fixture() {
        assert_cursor_help_contract(
            include_str!("fixtures/cursor-agent-help.txt"),
            "pinned cursor-agent help fixture",
        );
    }

    #[test]
    fn claude_template_flags_are_present_in_the_pinned_help_fixture() {
        assert_claude_help_contract(
            include_str!("fixtures/claude-help.txt"),
            "pinned claude help fixture",
        );
    }

    #[test]
    fn gemini_template_flags_are_present_in_the_pinned_help_fixture() {
        assert_gemini_help_contract(
            include_str!("fixtures/gemini-help.txt"),
            "pinned gemini help fixture",
        );
    }

    #[test]
    fn grok_template_flags_are_present_on_the_installed_cli() {
        if !installed_cli_verification_enabled() {
            return;
        }
        let help = require_installed_cli_help("grok");
        assert_grok_help_contract(&help, "installed grok help");
        assert_help_contains(&help, &["--no-subagents"], "installed grok help");
    }

    #[test]
    fn cursor_template_flags_are_present_on_the_installed_cli() {
        if !installed_cli_verification_enabled() {
            return;
        }
        assert_cursor_help_contract(
            &require_installed_cli_help("cursor-agent"),
            "installed cursor-agent help",
        );
    }

    #[test]
    fn claude_template_flags_are_present_on_the_installed_cli() {
        if !installed_cli_verification_enabled() {
            return;
        }
        assert_claude_help_contract(
            &require_installed_cli_help("claude"),
            "installed claude help",
        );
    }

    #[test]
    fn gemini_template_flags_are_present_on_the_installed_cli() {
        if !installed_cli_verification_enabled() {
            return;
        }
        assert_gemini_help_contract(
            &require_installed_cli_help("gemini"),
            "installed gemini help",
        );
    }
}
