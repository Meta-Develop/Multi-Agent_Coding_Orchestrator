//! Official Devin CLI print-mode launch construction.
//!
//! Rendering argv does not qualify native sandboxing or MACO containment. No
//! streamed JSON, reasoning-effort, resume, or model-catalog protocol is claimed.

use std::{collections::BTreeMap, path::Path};

use anyhow::{bail, Context, Result};

use super::{
    AdapterId, AgentRuntimeAdapter, LaunchContext, LaunchSpec, OutputCaptureMode,
    RuntimeAdapterConfig,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevinAdapter {
    config: RuntimeAdapterConfig,
}

impl DevinAdapter {
    pub fn from_environment() -> Self {
        Self {
            config: RuntimeAdapterConfig::from_adapter_environment(AdapterId::Devin),
        }
    }
}

impl AgentRuntimeAdapter for DevinAdapter {
    fn adapter_id(&self) -> AdapterId {
        AdapterId::Devin
    }

    fn config(&self) -> &RuntimeAdapterConfig {
        &self.config
    }

    fn launch(&self, context: &LaunchContext<'_>) -> Result<LaunchSpec> {
        render(&self.config, context, None)
    }
}

/// The private placeholder selects Devin validation at the shared render seam.
/// It is replaced with a pathname and is never passed to the official CLI.
pub fn immutable_argument_template() -> Vec<String> {
    [
        "--print",
        "--prompt-file",
        "{devin_prompt}",
        "--model",
        "{model}",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Render a fresh local print invocation. `config_path`, when supplied, must
/// refer to a caller-owned user config, not a project or global config. Ownership
/// and delivery to a contained process remain the integration caller's duties.
/// The default launch leaves workspace trust at its official true default.
pub fn render(
    config: &RuntimeAdapterConfig,
    context: &LaunchContext<'_>,
    config_path: Option<&Path>,
) -> Result<LaunchSpec> {
    let mut expected = RuntimeAdapterConfig::defaults_for(AdapterId::Devin);
    expected.binary = config.binary.clone();
    if config != &expected {
        bail!("Devin refuses launch overrides other than MACO_DEVIN_BIN");
    }
    let binary = config.binary_path();
    let binary_text = binary.to_str().context("Devin binary path must be UTF-8")?;
    if binary_text.is_empty() || binary_text.contains('\0') {
        bail!("Devin binary path must be nonempty and contain no NUL");
    }
    // No documented reasoning-effort command-line option exists, including none.
    if context.effort.is_some() {
        bail!("Devin CLI does not support command-line reasoning effort");
    }
    let model = validate_model(context.model)?;
    validate_path(context.cwd, "workspace")?;
    let prompt = validate_path(context.prompt, "prompt file")?;
    let mut argv = vec![
        "--print".to_string(),
        "--prompt-file".to_string(),
        prompt.to_string(),
        "--model".to_string(),
        model.to_string(),
    ];
    if let Some(path) = config_path {
        let config_arg = validate_path(path, "config file")?;
        validate_user_config(path)?;
        argv.extend(["--config".to_string(), config_arg.to_string()]);
    }
    Ok(LaunchSpec {
        program: binary.to_path_buf(),
        argv,
        cwd: context.cwd.to_path_buf(),
        env: BTreeMap::new(),
        output_capture: OutputCaptureMode::Stdout,
    })
}

pub(crate) fn validate_model(model: Option<&str>) -> Result<&str> {
    let model = model.context("Devin requires an explicit exact model slug")?;
    if model.is_empty()
        || !model.as_bytes()[0].is_ascii_alphanumeric()
        || !model.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
    {
        bail!("Devin requires an explicit exact model slug without whitespace or flags");
    }
    let normalized = model.to_ascii_lowercase();
    if normalized
        .split(['-', '_', '.', '/', ':'])
        .any(|part| matches!(part, "auto" | "default" | "latest" | "astra" | "fusion"))
    {
        bail!(
            "Devin requires an exact model slug; automatic selection, Astra and Fusion are refused"
        );
    }
    // This is syntax validation, not a runtime catalog or account-access claim.
    Ok(model)
}

fn validate_path<'a>(path: &'a Path, label: &str) -> Result<&'a str> {
    let text = path
        .to_str()
        .with_context(|| format!("Devin {label} path must be UTF-8"))?;
    if !path.is_absolute() || text.contains('\0') {
        bail!("Devin {label} path must be absolute and contain no NUL");
    }
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        bail!("Devin {label} path must not contain parent traversal");
    }
    Ok(text)
}

/// MACO-owned user policy. Project overrides must also be hidden by the launcher.
pub(crate) fn pinned_user_config() -> serde_json::Value {
    serde_json::json!({
        "subagents_enabled": false, "attribution": false, "auto_update": false,
        "notify": "never", "permission_mode": "normal",
        "read_config_from": {
            "agents_standard": false, "cursor": false, "windsurf": false,
            "claude": false, "copilot": false, "opencode": false,
            "zed": false, "cloud": false
        }
    })
}

fn validate_user_config(path: &Path) -> Result<()> {
    let text = crate::safe_state::BoundedRegularReader::read_utf8(path, 65_536)
        .context("Devin run-owned user config must be a bounded regular UTF-8 file")?;
    let value: serde_json::Value =
        serde_json::from_str(&text).context("Devin user config must be valid JSON")?;
    if value != pinned_user_config() {
        bail!("Devin user config must equal the MACO pinned six-setting contract");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_adapter::{
        adapter_for, BlockingPreActionCallback, ModelCatalogSource, RuntimeId, SessionResume,
        SideEffectConfinement, UsageReporting,
    };

    fn context() -> LaunchContext<'static> {
        LaunchContext {
            prompt: Path::new("/work/task prompt.txt"),
            model: Some("provider/exact-model-v1"),
            effort: None,
            cwd: Path::new("/work"),
            output: Path::new("/work/output.txt"),
        }
    }

    fn config() -> RuntimeAdapterConfig {
        RuntimeAdapterConfig::defaults_for(AdapterId::Devin)
    }

    #[test]
    fn identity_selection_and_factory_are_registered() {
        assert_eq!(AdapterId::parse("devin"), Some(AdapterId::Devin));
        assert_eq!(RuntimeId::Devin.as_str(), "devin");
        assert_eq!(AdapterId::Devin.to_runtime_id(), Some(RuntimeId::Devin));
        assert!(AdapterId::ALL.contains(&AdapterId::Devin));
        assert_eq!(AdapterId::Devin.env_prefix(), Some("MACO_DEVIN"));
        assert_eq!(adapter_for(AdapterId::Devin).adapter_id(), AdapterId::Devin);
        assert_eq!(
            serde_json::to_string(&RuntimeId::Devin).unwrap(),
            "\"devin\""
        );
        assert_eq!(
            serde_json::from_str::<RuntimeId>("\"devin\"").unwrap(),
            RuntimeId::Devin
        );
        assert_eq!(
            serde_json::from_str::<AdapterId>("\"devin\"").unwrap(),
            AdapterId::Devin
        );
        assert!(RuntimeId::Devin.is_adapter_subprocess());
    }

    #[cfg(unix)] // These argv fixtures use absolute Unix paths; native launch is Linux-only.
    #[test]
    fn official_print_args_keep_prompt_in_file_and_trust_default() -> Result<()> {
        let spec = config().render(&context())?;
        assert_eq!(
            spec.argv,
            [
                "--print",
                "--prompt-file",
                "/work/task prompt.txt",
                "--model",
                "provider/exact-model-v1"
            ]
        );
        assert_eq!(spec.program, Path::new("devin"));
        assert_eq!(spec.cwd, context().cwd);
        assert_eq!(spec.output_capture, OutputCaptureMode::Stdout);
        assert!(spec.env.is_empty());
        assert!(!config().feed_prompt_on_stdin);
        // Exact argv excludes JSON/effort/trust bypass/dangerous/resume/cloud flags.
        assert_eq!(config().render_os_argv(&context())?.len(), 5);
        Ok(())
    }

    #[cfg(unix)] // These argv fixtures use absolute Unix paths; native launch is Linux-only.
    #[test]
    fn operator_overrides_cannot_replace_launch_contract() -> Result<()> {
        let loaded = RuntimeAdapterConfig::try_from_adapter_environment_vars(
            AdapterId::Devin,
            &[
                ("MACO_DEVIN_BIN", "/opt/devin"),
                (
                    "MACO_DEVIN_ARGS",
                    "--permission-mode dangerous --respect-workspace-trust false --continue",
                ),
                ("MACO_DEVIN_ENV", "DEVIN_CONFIG,HOME"),
                ("MACO_DEVIN_CWD_FLAG", "--cwd"),
                ("MACO_DEVIN_OUTPUT_CAPTURE", "output_file"),
                ("MACO_DEVIN_STDIN_PROMPT", "true"),
            ],
        )?;
        let mut expected = config();
        expected.binary = Some("/opt/devin".into());
        assert_eq!(loaded, expected);
        assert_eq!(loaded.render(&context())?.program, Path::new("/opt/devin"));
        Ok(())
    }

    #[test]
    fn refuses_all_effort_values_and_nonexact_models() {
        for effort in ["", "none", "low", "high", "xhigh", "max"] {
            let mut ctx = context();
            ctx.effort = Some(effort);
            assert!(render(&config(), &ctx, None)
                .unwrap_err()
                .to_string()
                .contains("reasoning effort"));
        }
        for model in [
            None,
            Some(""),
            Some("auto"),
            Some("default"),
            Some("provider/latest"),
            Some("--model"),
            Some("model with space"),
            Some("model\0"),
            Some("gpt-6-astra"),
            Some("fusion"),
        ] {
            let mut ctx = context();
            ctx.model = model;
            assert!(render(&config(), &ctx, None).is_err(), "accepted {model:?}");
        }
    }

    #[test]
    fn refuses_mutated_configs_and_ambiguous_paths() {
        let mut altered = config();
        altered
            .argument_template
            .push("--output-format=json".into());
        assert!(render(&altered, &context(), None).is_err());
        altered = config();
        altered.feed_prompt_on_stdin = true;
        assert!(render(&altered, &context(), None).is_err());
        altered = config();
        altered.binary = Some("".into());
        assert!(render(&altered, &context(), None).is_err());
        for path in ["relative", "/work/../prompt", "/work/prompt\0"] {
            let mut ctx = context();
            ctx.prompt = Path::new(path);
            assert!(render(&config(), &ctx, None).is_err());
            ctx = context();
            ctx.cwd = Path::new(path);
            assert!(render(&config(), &ctx, None).is_err());
            assert!(render(&config(), &context(), Some(Path::new(path))).is_err());
        }
    }

    #[cfg(unix)] // These argv fixtures use absolute Unix paths; native launch is Linux-only.
    #[test]
    fn explicit_config_requires_user_safety_settings() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.json");
        let required = pinned_user_config();
        std::fs::write(&path, serde_json::to_vec(&required)?)?;
        let launch = render(&config(), &context(), Some(&path))?;
        assert_eq!(
            &launch.argv[5..],
            &["--config".to_string(), path.to_str().unwrap().to_string()]
        );
        for key in [
            "subagents_enabled",
            "attribution",
            "auto_update",
            "notify",
            "permission_mode",
            "read_config_from",
        ] {
            let mut missing = required.clone();
            missing.as_object_mut().unwrap().remove(key);
            std::fs::write(&path, serde_json::to_vec(&missing)?)?;
            assert!(render(&config(), &context(), Some(&path)).is_err());
            let mut wrong = required.clone();
            wrong[key] = serde_json::Value::Bool(true);
            std::fs::write(&path, serde_json::to_vec(&wrong)?)?;
            assert!(render(&config(), &context(), Some(&path)).is_err());
        }
        for key in required["read_config_from"].as_object().unwrap().keys() {
            let mut changed = required.clone();
            changed["read_config_from"][key] = serde_json::Value::Bool(true);
            std::fs::write(&path, serde_json::to_vec(&changed)?)?;
            assert!(render(&config(), &context(), Some(&path)).is_err());
        }
        let mut extra = required.clone();
        extra["respect_workspace_trust"] = serde_json::Value::Bool(false);
        std::fs::write(&path, serde_json::to_vec(&extra)?)?;
        assert!(render(&config(), &context(), Some(&path)).is_err());
        for invalid in ["not json", "[]", "null"] {
            std::fs::write(&path, invalid)?;
            assert!(render(&config(), &context(), Some(&path)).is_err());
        }
        assert!(render(&config(), &context(), Some(dir.path())).is_err());
        assert!(render(
            &config(),
            &context(),
            Some(&dir.path().join("missing.json"))
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn direct_execution_is_refused_before_binary_resolution() {
        let error = config().execute(&context()).unwrap_err().to_string();
        assert!(error.contains("qualified containment runner"));
    }

    #[test]
    fn static_capabilities_preserve_unverified_live_gate() {
        let caps = AdapterId::Devin.capabilities();
        assert_eq!(
            caps.blocking_pre_action_callback,
            BlockingPreActionCallback::None
        );
        assert_eq!(
            caps.side_effect_confinement,
            SideEffectConfinement::Unverified
        );
        assert_eq!(caps.model_catalog, ModelCatalogSource::OperatorDeclared);
        assert_eq!(caps.usage_reporting, UsageReporting::None);
        assert_eq!(caps.session_resume, SessionResume::Unsupported);
        assert!(caps.read_only_inner_contract_refusal().is_some());
        assert!(caps.worktree_writable_refusal().is_some());
        assert!(caps.writable_refusal().is_some());
        assert_eq!(AdapterId::Devin.private_state_home(), None);
        assert!(config()
            .typed_runtime_contract(AdapterId::Devin, &context())
            .is_none());
    }
}
