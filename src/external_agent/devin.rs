//! Native Devin credential custody for one read-only launch. No ambient directory is shared.

use super::*;
use crate::safe_state::BoundedRegularReader;
use std::{
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    sync::Arc,
};

const MAX_NATIVE_CREDENTIAL_BYTES: u64 = 64 * 1024;

pub(super) struct DevinSession {
    root: tempfile::TempDir,
    ambient_root: Option<PathBuf>,
    config: PathBuf,
    config_file: Arc<fs::File>,
    credentials: PathBuf,
    credentials_file: Arc<fs::File>,
    redactor: CredentialRedactor,
}

impl DevinSession {
    pub(super) fn prepare(spec: &ExternalAgentCommand) -> Result<Self> {
        let source = credential_source(env::var_os("XDG_DATA_HOME"), env::var_os("HOME"))?;
        Self::prepare_from(spec, &source)
    }

    fn prepare_from(spec: &ExternalAgentCommand, source: &Path) -> Result<Self> {
        let repo = fs::canonicalize(&spec.cwd)?;
        if spec.workspace_access != WorkspaceAccess::ReadOnly
            || spec.devin_reviewed_workspace.as_deref() != Some(repo.as_path())
            || !spec.worktree_control_exceptions.is_empty()
            || !spec.worker_journal_artifacts.is_empty()
        {
            bail!("Devin requires explicit canonical reviewed workspace and no write capabilities");
        }
        crate::runtime_adapter::devin::validate_model(spec.model.as_deref())?;
        if spec.reasoning_effort.is_some() || spec.model_provider.is_some() {
            bail!("Devin does not support effort or provider overrides");
        }
        let mut bytes = BoundedRegularReader::read_tree_no_follow_validated(
            source,
            MAX_NATIVE_CREDENTIAL_BYTES,
            |meta| {
                // SAFETY: geteuid has no arguments or side effects.
                if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
                    bail!("unsafe native credential ownership or permissions");
                }
                Ok(())
            },
        )
        .map_err(|_| anyhow::anyhow!("native Devin credentials unavailable or unsafe"))?;
        let result = Self::from_bytes(&bytes).map(|mut session| {
            session.ambient_root = source.parent().map(Path::to_path_buf);
            session
        });
        bytes.fill(0);
        result
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Do not propagate parser diagnostics: TOML errors can quote secret source lines.
        let text = std::str::from_utf8(bytes)
            .map_err(|_| anyhow::anyhow!("native credentials must be UTF-8 TOML"))?;
        let value: toml::Value = text
            .parse()
            .map_err(|_| anyhow::anyhow!("native credentials must be valid TOML"))?;
        let mut redactor = CredentialRedactor {
            patterns: Vec::new(),
        };
        collect_strings(&value, &mut redactor.patterns, 0, false)?;
        if redactor.patterns.is_empty() {
            bail!("native credentials have no bounded string values for redaction");
        }
        add_credential_pattern(&mut redactor.patterns, bytes)?;
        redactor
            .patterns
            .sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
        let root = tempfile::Builder::new()
            .prefix("maco-devin-private-")
            .tempdir()?;
        let (config, config_file) = snapshot(
            root.path(),
            "config.json",
            &serde_json::to_vec(&crate::runtime_adapter::devin::pinned_user_config())?,
        )?;
        let (credentials, credentials_file) = snapshot(root.path(), "credentials.toml", bytes)?;
        Ok(Self {
            root,
            ambient_root: None,
            config,
            config_file,
            credentials,
            credentials_file,
            redactor,
        })
    }

    pub(super) fn config_path(&self) -> &Path {
        &self.config
    }

    pub(super) fn bind(&self, profile: ExternalDevinProfile) -> Result<ExternalDevinProfile> {
        let profile = match &self.ambient_root {
            Some(root) => profile.with_hidden_root(root),
            None => profile,
        };
        Ok(profile
            .with_hidden_root(self.root.path())
            .with_private_file(self.config.clone(), Arc::clone(&self.config_file), true)?
            .with_private_file(
                self.credentials.clone(),
                Arc::clone(&self.credentials_file),
                false,
            )?)
    }

    pub(super) fn extend_redactor(&self, target: &mut CredentialRedactor) -> Result<()> {
        for pattern in &self.redactor.patterns {
            add_credential_pattern(&mut target.patterns, pattern)?;
        }
        target
            .patterns
            .sort_by_key(|pattern| std::cmp::Reverse(pattern.len()));
        Ok(())
    }
}

/// Prove this exact profile with a fixed no-op before releasing the native provider.
#[allow(clippy::too_many_arguments)]
pub(super) fn preflight(
    spec: &ExternalAgentCommand,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    environment: &BTreeMap<String, String>,
    profile: &SideEffectConfinementProfile,
    lifecycle: Option<&AgentLaunchMetadata>,
    redactor: &CredentialRedactor,
) -> EnvironmentPreflightReport {
    let mut report = EnvironmentPreflightReport::default();
    if validate_environment_requirements(&spec.environment_requirements).is_err() {
        report.failures.push(environment_failure(
            EnvironmentFailureCategory::ProbeFailed,
            None,
            "invalid Devin environment requirements".into(),
        ));
        return report;
    }
    let started = Instant::now();
    let program = [
        "/usr/bin/true",
        "/bin/true",
        "/run/current-system/sw/bin/true",
    ]
    .into_iter()
    .map(Path::new)
    .find(|path| path.is_file())
    .unwrap_or_else(|| Path::new("/usr/bin/true"));
    let probe = with_external_runtime_context(
        ProcessSpec::direct(
            "Devin sandbox preflight",
            program,
            std::iter::empty::<&str>(),
            &spec.cwd,
            4096,
        )
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(timeout)),
        environment.clone(),
        profile.clone(),
        ExternalAgentInvocation::Devin,
        None,
        lifecycle,
        None,
    );
    match run_process_cancellable(probe, cancellation) {
        Ok(output) => {
            report.process_evidence.record_output(&output);
            report.timed_out = output.timed_out;
            if output.safety_sensitive_succeeded()
                && output.side_effects
                    == SideEffectConfinementEvidence::Verified(
                        SideEffectConfinementProfileKind::ExternalDevin,
                    )
            {
                report.verified_confinement = Some(SideEffectConfinementProfileKind::ExternalDevin);
            }
        }
        Err(error) => {
            report.process_evidence.record_error(&error);
            report.timed_out = matches!(error, ProcessRunError::SetupTimeout { .. });
            report.failures.push(environment_failure(
                EnvironmentFailureCategory::SandboxUnavailable,
                Some(external_sandbox_requirement(ExternalAgentInvocation::Devin)),
                redactor.redact_string(&format!("Devin sandbox no-op preflight failed: {error}")),
            ));
            return report;
        }
    }
    let sandbox = external_sandbox_requirement(ExternalAgentInvocation::Devin);
    let network = EnvironmentRequirement::network(EnvironmentNetworkAccess::Enabled);
    for requirement in [&sandbox, &network].into_iter().chain(
        spec.environment_requirements
            .iter()
            .filter(|r| **r != sandbox && **r != network),
    ) {
        let (result, failure, timed_out) = evaluate_environment_requirement(
            requirement,
            ExternalAgentInvocation::Devin,
            &spec.cwd,
            timeout.saturating_sub(started.elapsed()),
            cancellation,
            environment,
            profile,
            None,
            None,
            None,
            report.verified_confinement,
            lifecycle,
            Some(redactor),
            &mut report.process_evidence,
        );
        report.results.push(result);
        if let Some(failure) = failure {
            report.failures.push(failure);
        }
        report.timed_out |= timed_out;
        if !report.failures.is_empty() {
            break;
        }
    }
    report
}

fn credential_source(xdg: Option<OsString>, home: Option<OsString>) -> Result<PathBuf> {
    let root = match xdg.filter(|value| !value.is_empty()) {
        Some(root) => PathBuf::from(root),
        None => {
            PathBuf::from(home.context("native Devin credentials require HOME or XDG_DATA_HOME")?)
                .join(".local/share")
        }
    };
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        bail!("native Devin data home must be absolute and normalized");
    }
    Ok(root.join("devin/credentials.toml"))
}

fn snapshot(root: &Path, name: &str, bytes: &[u8]) -> Result<(PathBuf, Arc<fs::File>)> {
    let path = root.join(name);
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    drop(file);
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    Ok((path, Arc::new(file)))
}

fn collect_strings(
    value: &toml::Value,
    patterns: &mut Vec<Vec<u8>>,
    depth: usize,
    credential_bearing: bool,
) -> Result<()> {
    if depth > 32 {
        bail!("native credential TOML exceeds redaction nesting bound");
    }
    match value {
        toml::Value::String(value) => {
            if credential_bearing && value.len() < MIN_CREDENTIAL_BYTES {
                bail!("native credential value is too short for bounded redaction");
            }
            add_credential_pattern(patterns, value.as_bytes())?;
            let escaped = serde_json::to_string(value)?;
            add_credential_pattern(patterns, &escaped.as_bytes()[1..escaped.len() - 1])?;
        }
        toml::Value::Array(values) => {
            for value in values {
                collect_strings(value, patterns, depth + 1, credential_bearing)?;
            }
        }
        toml::Value::Table(values) => {
            for (key, value) in values {
                let key = key.to_ascii_lowercase();
                let secret = ["token", "secret", "password", "key", "credential"]
                    .iter()
                    .any(|part| key.contains(part));
                collect_strings(value, patterns, depth + 1, secret)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(repo: &Path) -> ExternalAgentCommand {
        ExternalAgentCommand::codex(
            "devin",
            repo,
            repo.join("prompt"),
            repo.join("log"),
            repo.join("out"),
            Duration::from_secs(10),
        )
        .with_runtime_adapter(
            RuntimeId::Devin,
            RuntimeAdapterConfig::defaults(RuntimeId::Devin),
        )
        .with_workspace_access(WorkspaceAccess::ReadOnly)
        .with_model_selection(Some("provider/exact-model-v1".into()), None)
        .with_devin_reviewed_workspace(repo)
    }

    fn auth(root: &Path, contents: &[u8]) -> Result<PathBuf> {
        let path = root.join("credentials.toml");
        fs::write(&path, contents)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }

    #[test]
    fn devin_native_source_obeys_xdg_and_home_without_aliases() -> Result<()> {
        assert_eq!(
            credential_source(Some("/data".into()), Some("/home/fixture".into()))?,
            Path::new("/data/devin/credentials.toml")
        );
        assert_eq!(
            credential_source(None, Some("/home/fixture".into()))?,
            Path::new("/home/fixture/.local/share/devin/credentials.toml")
        );
        assert!(credential_source(Some("relative".into()), None).is_err());
        assert!(credential_source(Some("/data/../other".into()), None).is_err());
        assert!(credential_source(None, None).is_err());
        Ok(())
    }

    #[test]
    fn devin_toml_redacts_decoded_literal_multiline_nested_and_json_escaped_values() -> Result<()> {
        let synthetic = br#"kind = 'devin'
[credentials]
kind = 'devin'
token = "synthetic-escaped-\u0074oken-0123456789"
refresh_token = 'synthetic-literal-token-0123456789'
extra = ["""synthetic-multiline-
token-0123456789"""]
"#;
        let session = DevinSession::from_bytes(synthetic)?;
        let mut redactor = CredentialRedactor {
            patterns: Vec::new(),
        };
        session.extend_redactor(&mut redactor)?;
        for secret in [
            "synthetic-escaped-token-0123456789",
            "synthetic-literal-token-0123456789",
            "synthetic-multiline-\ntoken-0123456789",
        ] {
            assert_eq!(
                redactor.redact_bytes(secret.as_bytes()),
                CREDENTIAL_REDACTION
            );
            let escaped = serde_json::to_string(secret)?;
            assert!(!redactor.redact_string(&escaped).contains("0123456789"));
        }
        assert!(!format!("{redactor:?}").contains("synthetic"));
        for bytes in [
            b"token='short'".as_slice(),
            b"token = 'unterminated",
            b"token = 4",
        ] {
            assert!(DevinSession::from_bytes(bytes).is_err());
        }
        Ok(())
    }

    #[test]
    fn devin_preparation_rejects_missing_unsafe_symlink_credentials_and_unreviewed_repo(
    ) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = fs::canonicalize(temp.path())?;
        let mut spec = command(&repo);
        let path = repo.join("missing.toml");
        assert!(DevinSession::prepare_from(&spec, &path).is_err());
        let path = auth(&repo, b"token='synthetic-fixture-token-0123456789'")?;
        assert!(DevinSession::prepare_from(&spec, &path).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(DevinSession::prepare_from(&spec, &path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let link = repo.join("link.toml");
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(DevinSession::prepare_from(&spec, &link).is_err());
        spec.devin_reviewed_workspace = None;
        assert!(DevinSession::prepare_from(&spec, &path).is_err());
        spec.devin_reviewed_workspace = Some(repo.join("other"));
        assert!(DevinSession::prepare_from(&spec, &path).is_err());
        spec = command(&repo).with_workspace_access(WorkspaceAccess::ReadWrite);
        assert!(DevinSession::prepare_from(&spec, &path).is_err());
        Ok(())
    }

    #[test]
    fn devin_argv_requires_pinned_config_and_reviewed_repo_and_has_only_documented_flags(
    ) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = fs::canonicalize(temp.path())?;
        let session = DevinSession::from_bytes(b"token='synthetic-fixture-token-0123456789'")?;
        let mut spec = command(&repo);
        assert!(runtime_adapter_argv(&spec).is_err());
        spec.devin_config = Some(session.config.clone());
        let argv = runtime_adapter_argv(&spec)?;
        assert_eq!(
            argv,
            [
                "--print",
                "--prompt-file",
                repo.join("prompt").to_str().unwrap(),
                "--model",
                "provider/exact-model-v1",
                "--config",
                session.config.to_str().unwrap(),
                "--respect-workspace-trust=false"
            ]
            .map(OsString::from)
        );
        assert!(matches!(
            external_agent_stdin_mode(&spec, false, Vec::new()),
            StdinMode::Null
        ));
        assert_eq!(
            external_sandbox_requirement(spec.invocation),
            EnvironmentRequirement::sandbox(EnvironmentSandboxCapability::VerifiedExternalDevin)
        );
        assert!(spec.reasoning_effort.is_none());
        assert!(
            allowed_env(spec.invocation, ExternalProgramTrust::ExplicitCustom, false)
                .keys()
                .all(|key| !key.contains("TOKEN") && !key.contains("KEY"))
        );
        for key in [
            "HOME",
            "TMPDIR",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "WINDSURF_API_KEY",
            "DEVIN_MODEL",
            "DEVIN_PERMISSION_MODE",
        ] {
            assert!(
                !runtime_environment_passthrough_allowed(spec.invocation, key),
                "{key}"
            );
        }
        spec.devin_reviewed_workspace = None;
        assert!(runtime_adapter_argv(&spec).is_err());
        spec = command(&repo);
        spec.devin_config = Some(repo.join("missing-config.json"));
        assert!(runtime_adapter_argv(&spec).is_err());
        Ok(())
    }

    #[test]
    fn devin_private_profile_projects_exact_files_and_refuses_writes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = fs::canonicalize(temp.path())?;
        let native = tempfile::tempdir()?;
        let native_path = auth(native.path(), b"token='synthetic-fixture-token-0123456789'")?;
        let session = DevinSession::prepare_from(&command(&repo), &native_path)?;
        fs::write(repo.join("prompt"), "fixture")?;
        let mut spec = command(&repo);
        spec.program = fs::canonicalize("/bin/true")?;
        let controls = ProtectedWorktreeControls {
            writable_artifact_root: Some(repo.clone()),
            ..Default::default()
        };
        let profile = external_side_effect_profile(
            &spec,
            &spec.program,
            ExternalProgramTrust::ExplicitCustom,
            &controls,
        )?;
        assert_eq!(
            profile.kind(),
            SideEffectConfinementProfileKind::ExternalDevin
        );
        let SideEffectConfinementProfile::ExternalDevin(profile) = profile else {
            unreachable!()
        };
        let profile = session.bind(profile)?;
        let properties = crate::process_runner::external_devin_systemd_properties_for_test(
            profile,
            &spec.program,
            &repo,
        )?;
        for property in [
            "ProtectSystem=strict",
            "ProtectHome=tmpfs",
            "PrivateNetwork=no",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "RestrictNamespaces=yes",
            "KeyringMode=private",
            "NoNewPrivileges=yes",
            "ReadOnlyPaths=/run/user/1000/maco-test-runtime/.config",
        ] {
            assert!(
                properties.contains(&format!("--property={property}")),
                "{property}"
            );
        }
        assert!(properties
            .iter()
            .any(|value| value.starts_with("--property=SystemCallFilter=")
                && value.contains("@mount")));
        for (source, target) in [
            (&session.config, ".config/devin/config.json"),
            (&session.credentials, ".local/share/devin/credentials.toml"),
        ] {
            assert!(properties.contains(&format!(
                "--property=BindReadOnlyPaths={}:{}",
                source.display(),
                Path::new("/run/user/1000/maco-test-runtime")
                    .join(target)
                    .display()
            )));
        }
        assert!(properties.contains(&format!("--property=ReadOnlyPaths={}", repo.display())));
        assert!(properties.iter().any(|property| {
            property
                .strip_prefix("--property=InaccessiblePaths=")
                .map(|path| path.strip_prefix('-').unwrap_or(path))
                == native.path().to_str()
        }));

        assert!(properties
            .iter()
            .any(|value| value.contains("InaccessiblePaths=") && value.ends_with("/.devin")));
        assert!(!properties
            .iter()
            .any(|value| value.starts_with("--property=ReadWritePaths=")));
        spec.workspace_access = WorkspaceAccess::ReadWrite;
        assert!(
            ExternalProviderProfile::for_command(&spec, ClaudeProfileBinding::default()).is_err()
        );
        Ok(())
    }

    #[test]
    fn devin_snapshots_survive_source_changes_but_refuse_snapshot_rebinding() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = fs::canonicalize(temp.path())?;
        let path = auth(&repo, b"token='synthetic-original-token-0123456789'")?;
        let session = DevinSession::prepare_from(&command(&repo), &path)?;
        fs::write(&path, b"token='synthetic-replaced-token-0123456789'")?;
        assert_eq!(
            fs::read(&session.credentials)?,
            b"token='synthetic-original-token-0123456789'"
        );
        let descriptor = session.credentials_file.metadata()?;
        assert_eq!(descriptor.mode() & 0o777, 0o400);
        fs::rename(&session.config, session.root.path().join("old-config"))?;
        fs::write(&session.config, b"{}")?;
        assert!(session
            .bind(ExternalDevinProfile::read_only(&repo))
            .is_err());
        Ok(())
    }

    #[test]
    fn devin_network_preflight_rejects_other_vendor_evidence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = fs::canonicalize(temp.path())?;
        let profile =
            SideEffectConfinementProfile::ExternalDevin(ExternalDevinProfile::read_only(&repo));
        let requirement = EnvironmentRequirement::network(EnvironmentNetworkAccess::Enabled);
        for (observed, expected) in [
            (SideEffectConfinementProfileKind::ExternalCursor, false),
            (SideEffectConfinementProfileKind::ExternalCodex, false),
            (SideEffectConfinementProfileKind::ExternalDevin, true),
        ] {
            let (result, failure, _) = evaluate_environment_requirement(
                &requirement,
                ExternalAgentInvocation::Devin,
                &repo,
                Duration::from_secs(1),
                &ProcessCancellation::default(),
                &BTreeMap::new(),
                &profile,
                None,
                None,
                None,
                Some(observed),
                None,
                None,
                &mut EnvironmentPreflightProcessEvidence::default(),
            );
            assert_eq!(
                result.status == EnvironmentPreflightStatus::Satisfied,
                expected
            );
            assert_eq!(failure.is_none(), expected);
        }
        Ok(())
    }
}
