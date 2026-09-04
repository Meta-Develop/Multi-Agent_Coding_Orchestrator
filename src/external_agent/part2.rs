pub(crate) fn validate_environment_requirements(
    requirements: &[EnvironmentRequirement],
) -> Result<()> {
    if requirements.len() > MAX_ENVIRONMENT_REQUIREMENTS {
        bail!("environment requirements exceed the fixed limit of {MAX_ENVIRONMENT_REQUIREMENTS}");
    }
    let mut executables = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    let mut configurations = BTreeSet::new();
    let mut network = false;
    let mut sandbox = false;
    for requirement in requirements {
        match requirement {
            EnvironmentRequirement::Executable {
                executable,
                version,
            } => {
                if !executables.insert(*executable) {
                    bail!(
                        "duplicate executable requirement for {}",
                        executable.program_name()
                    );
                }
                if let Some(version) = version {
                    version.validate()?;
                }
            }
            EnvironmentRequirement::Credential { credential } => {
                if !credentials.insert(*credential) {
                    bail!(
                        "duplicate credential requirement for {}",
                        credential_name(*credential)
                    );
                }
            }
            EnvironmentRequirement::Configuration { configuration } => {
                if !configurations.insert(*configuration) {
                    bail!(
                        "duplicate configuration requirement for {}",
                        configuration_name(*configuration)
                    );
                }
            }
            EnvironmentRequirement::Network { .. } => {
                if network {
                    bail!("only one canonical network requirement may be declared");
                }
                network = true;
            }
            EnvironmentRequirement::Sandbox { .. } => {
                if sandbox {
                    bail!("only one canonical sandbox requirement may be declared");
                }
                sandbox = true;
            }
        }
    }
    Ok(())
}

fn codex_environment_requirement() -> EnvironmentRequirement {
    EnvironmentRequirement::executable(
        EnvironmentExecutable::Codex,
        Some(EnvironmentVersionConstraint::at_least(
            EnvironmentVersion::new(
                CODEX_MINIMUM_VERSION.0,
                CODEX_MINIMUM_VERSION.1,
                CODEX_MINIMUM_VERSION.2,
            ),
        )),
    )
}

fn resolve_environment_executable(
    executable: EnvironmentExecutable,
) -> std::result::Result<PathBuf, EnvironmentProbeFailure> {
    for directory in TRUSTED_PATH.split(':') {
        let candidate = Path::new(directory).join(executable.program_name());
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
                let canonical =
                    fs::canonicalize(&candidate).map_err(|error| EnvironmentProbeFailure {
                        category: EnvironmentFailureCategory::ProbeFailed,
                        summary: format!(
                            "failed to resolve fixed {} version probe: {error}",
                            executable.program_name()
                        ),
                        timed_out: false,
                    })?;
                validate_external_program_identity(&canonical, false).map_err(|error| {
                    EnvironmentProbeFailure {
                        category: EnvironmentFailureCategory::ProbeFailed,
                        summary: format!(
                            "fixed {} version probe executable was not trusted: {error}",
                            executable.program_name()
                        ),
                        timed_out: false,
                    }
                })?;
                return Ok(canonical);
            }
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(EnvironmentProbeFailure {
                    category: EnvironmentFailureCategory::ProbeFailed,
                    summary: format!(
                        "failed to inspect fixed {} version probe: {error}",
                        executable.program_name()
                    ),
                    timed_out: false,
                });
            }
        }
    }
    Err(EnvironmentProbeFailure {
        category: EnvironmentFailureCategory::MissingExecutable,
        summary: format!(
            "required executable {} was not found on the sanitized child PATH",
            executable.program_name()
        ),
        timed_out: false,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_fixed_version_probe(
    executable: EnvironmentExecutable,
    program: &Path,
    cwd: &Path,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    environment: &BTreeMap<String, String>,
    side_effect_profile: &SideEffectConfinementProfile,
    codex_auth: Option<&ValidatedCodexAuth>,
    agent_lifecycle: Option<&AgentLaunchMetadata>,
    process_evidence: &mut EnvironmentPreflightProcessEvidence,
) -> std::result::Result<EnvironmentVersionProbe, EnvironmentProbeFailure> {
    let label = format!("{} version preflight", executable.program_name());
    let process_spec = ProcessSpec::direct(
        label,
        program,
        executable.version_arguments().iter().copied(),
        cwd,
        4096,
    )
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(timeout));
    let process_spec = with_external_runtime_context(
        process_spec,
        environment.clone(),
        side_effect_profile.clone(),
        ExternalAgentInvocation::CodexSupervisor,
        codex_auth,
        agent_lifecycle,
    );
    let output = match run_process_cancellable(process_spec, cancellation) {
        Ok(output) => {
            process_evidence.record_output(&output);
            output
        }
        Err(error) => {
            process_evidence.record_error(&error);
            let sandbox_unavailable = matches!(
                &error,
                ProcessRunError::ContainmentUnavailable { .. }
                    | ProcessRunError::ProcessOwnership { .. }
            ) || matches!(
                &error,
                ProcessRunError::EnvironmentFailure { failure, .. }
                    if failure.category == EnvironmentFailureCategory::SandboxUnavailable
            );
            return Err(EnvironmentProbeFailure {
                category: if sandbox_unavailable {
                    EnvironmentFailureCategory::SandboxUnavailable
                } else {
                    EnvironmentFailureCategory::ProbeFailed
                },
                timed_out: matches!(error, ProcessRunError::SetupTimeout { .. }),
                summary: if sandbox_unavailable {
                    format!(
                        "{} version preflight could not establish the fixed child sandbox: {error}",
                        executable.program_name(),
                    )
                } else {
                    format!(
                        "{} version preflight failed before target execution: {error}",
                        executable.program_name()
                    )
                },
            });
        }
    };
    if !output.safety_sensitive_succeeded() {
        let sandbox_unavailable =
            !output.process_tree.is_verified_empty() || !output.side_effects.is_verified();
        return Err(EnvironmentProbeFailure {
            category: if sandbox_unavailable {
                EnvironmentFailureCategory::SandboxUnavailable
            } else {
                EnvironmentFailureCategory::ProbeFailed
            },
            timed_out: output.timed_out,
            summary: if sandbox_unavailable {
                format!(
                    "{} version preflight did not verify the fixed child sandbox",
                    executable.program_name()
                )
            } else {
                format!(
                    "{} version preflight was not safely verified: exit={:?}",
                    executable.program_name(),
                    output.status.and_then(|status| status.code())
                )
            },
        });
    }
    let stdout = output.stdout.summarize_chars(4096).text;
    let stderr = output.stderr.summarize_chars(4096).text;
    let version_text = format!("{stdout}\n{stderr}");
    let parsed = if executable == EnvironmentExecutable::Codex {
        parse_codex_version(&version_text)
            .map(|(major, minor, patch)| EnvironmentVersion::new(major, minor, patch))
    } else {
        parse_environment_version(executable, &version_text)
    };
    let version = parsed.ok_or_else(|| EnvironmentProbeFailure {
        category: EnvironmentFailureCategory::ProbeFailed,
        summary: format!(
            "{} version preflight returned an unknown version",
            executable.program_name()
        ),
        timed_out: false,
    })?;
    let SideEffectConfinementEvidence::Verified(verified_confinement) = output.side_effects else {
        return Err(EnvironmentProbeFailure {
            category: EnvironmentFailureCategory::SandboxUnavailable,
            summary: format!(
                "{} version preflight did not return verified confinement evidence",
                executable.program_name()
            ),
            timed_out: false,
        });
    };
    Ok(EnvironmentVersionProbe {
        version,
        verified_confinement,
    })
}

fn with_external_runtime_context(
    process_spec: ProcessSpec,
    environment: BTreeMap<String, String>,
    side_effect_profile: SideEffectConfinementProfile,
    invocation: ExternalAgentInvocation,
    codex_auth: Option<&ValidatedCodexAuth>,
    agent_lifecycle: Option<&AgentLaunchMetadata>,
) -> ProcessSpec {
    let prepared = process_spec
        .with_environment(EnvironmentMode::ClearAndSet(environment))
        .with_private_runtime_home(true)
        .with_private_runtime_codex_home(matches!(
            invocation,
            ExternalAgentInvocation::CodexSupervisor | ExternalAgentInvocation::CodexConsultant
        ))
        .with_private_runtime_grok_home(invocation == ExternalAgentInvocation::Grok)
        .with_side_effect_confinement(side_effect_profile);
    let prepared = match agent_lifecycle {
        Some(metadata) => prepared.with_agent_lifecycle(metadata.clone()),
        None => prepared,
    };
    #[cfg(target_os = "linux")]
    {
        match codex_auth {
            Some(auth) => prepared.with_private_runtime_file("auth.json", auth.bytes.clone()),
            None => prepared,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = codex_auth;
        prepared
    }
}

fn credential_present(
    credential: EnvironmentCredential,
    environment: &BTreeMap<String, String>,
) -> bool {
    match credential {
        EnvironmentCredential::OpenAiApiKey => environment.contains_key("OPENAI_API_KEY"),
        EnvironmentCredential::CodexApiKey => environment.contains_key("CODEX_API_KEY"),
        EnvironmentCredential::CodexAccessToken => environment.contains_key("CODEX_ACCESS_TOKEN"),
    }
}

fn configuration_present(
    configuration: EnvironmentConfiguration,
    codex_auth: Option<&ValidatedCodexAuth>,
) -> bool {
    match configuration {
        EnvironmentConfiguration::CodexAuthFile => codex_auth.is_some(),
        EnvironmentConfiguration::GrokAuthFile => false,
    }
}

const fn credential_name(credential: EnvironmentCredential) -> &'static str {
    match credential {
        EnvironmentCredential::OpenAiApiKey => "OPENAI_API_KEY",
        EnvironmentCredential::CodexApiKey => "CODEX_API_KEY",
        EnvironmentCredential::CodexAccessToken => "CODEX_ACCESS_TOKEN",
    }
}

const fn configuration_name(configuration: EnvironmentConfiguration) -> &'static str {
    match configuration {
        EnvironmentConfiguration::CodexAuthFile => "Codex auth file",
        EnvironmentConfiguration::GrokAuthFile => "Grok auth file",
    }
}

const fn external_sandbox_requirement(
    invocation: ExternalAgentInvocation,
) -> EnvironmentRequirement {
    let capability = match invocation {
        ExternalAgentInvocation::Grok => EnvironmentSandboxCapability::VerifiedExternalGrok,
        ExternalAgentInvocation::CodexSupervisor
        | ExternalAgentInvocation::CodexConsultant
        | ExternalAgentInvocation::ClaudeConsultant
        | ExternalAgentInvocation::Cursor
        | ExternalAgentInvocation::ClaudeCode
        | ExternalAgentInvocation::GeminiCli => EnvironmentSandboxCapability::VerifiedExternalCodex,
    };
    EnvironmentRequirement::sandbox(capability)
}

const fn grok_auth_environment_requirement() -> EnvironmentRequirement {
    EnvironmentRequirement::configuration(EnvironmentConfiguration::GrokAuthFile)
}

fn sanitized_grok_credential_validation_summary(error: &anyhow::Error) -> &'static str {
    let summary = error.to_string();
    [
        "Grok credential source requires HOME or GROK_HOME",
        "Grok credential state home must be an absolute normalized path",
        "Grok credential state home is not valid UTF-8",
        "Grok authentication source auth.json is missing",
        "Grok authentication source auth.json is unavailable",
        "Grok authentication source auth.json is not a regular file",
        "Grok authentication source auth.json identity changed",
        "Grok configuration source config.toml is unavailable",
        "Grok configuration source config.toml is not a regular file",
        "Grok configuration source config.toml identity changed",
    ]
    .into_iter()
    .find(|known| summary.contains(known))
    .unwrap_or("Grok credential source is unavailable")
}

fn record_grok_credential_environment_failure(
    report: &mut ExternalAgentRun,
    error: &anyhow::Error,
) {
    let summary = format!(
        "Grok credential/configuration preflight failed closed before launch: {}",
        sanitized_grok_credential_validation_summary(error)
    );
    record_environment_failure(
        report,
        EnvironmentFailureCategory::MissingCredential,
        Some(grok_auth_environment_requirement()),
        summary,
    );
}

fn insert_admitted_grok_home_environment(
    environment: &mut BTreeMap<String, String>,
    credentials: &AdmittedGrokCredentials,
) -> Result<()> {
    // Retain the normalized ambient source for preflight redaction. The shared runner replaces
    // this value with the per-launch RuntimeDirectory before publishing the target environment.
    environment.insert(
        "GROK_HOME".to_string(),
        credentials.grok_home_environment()?.to_string(),
    );
    Ok(())
}

fn runtime_environment_passthrough_allowed(invocation: ExternalAgentInvocation, key: &str) -> bool {
    invocation != ExternalAgentInvocation::Grok || !matches!(key, "HOME" | "GROK_HOME")
}

fn environment_failure(
    category: EnvironmentFailureCategory,
    requirement: Option<EnvironmentRequirement>,
    summary: String,
) -> EnvironmentFailure {
    EnvironmentFailure {
        category,
        requirement,
        summary,
        remediation: environment_remediation(category),
    }
}

fn record_environment_failure(
    report: &mut ExternalAgentRun,
    category: EnvironmentFailureCategory,
    requirement: Option<EnvironmentRequirement>,
    summary: String,
) {
    report.error = Some(summary.clone());
    if let Some(requirement) = requirement.as_ref() {
        report
            .stdout
            .run_metadata
            .environment_preflight_results
            .push(EnvironmentPreflightResult {
                requirement: requirement.clone(),
                status: EnvironmentPreflightStatus::Blocked,
                observation: None,
            });
    }
    report
        .stdout
        .run_metadata
        .environment_failures
        .push(environment_failure(category, requirement, summary));
}

fn record_external_error(report: &mut ExternalAgentRun, summary: String) {
    report.error = Some(summary);
}

fn environment_blocked_message(failures: &[EnvironmentFailure]) -> String {
    let summaries = failures
        .iter()
        .map(|failure| failure.summary.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    format!("external agent environment preflight blocked target execution: {summaries}")
}

fn environment_remediation(category: EnvironmentFailureCategory) -> Vec<EnvironmentRemediation> {
    match category {
        EnvironmentFailureCategory::MissingExecutable
        | EnvironmentFailureCategory::VersionMismatch => vec![
            EnvironmentRemediation {
                scope: EnvironmentRemediationScope::ProjectLocal,
                guidance: "Declare the required executable and version in the repository dev shell or flake, then recreate the assignment worktree environment."
                    .to_string(),
            },
            EnvironmentRemediation {
                scope: EnvironmentRemediationScope::PersistentNixosHostSoftware,
                guidance: "If the dependency must be host-wide, hand it off to the declarative NixOS host-software workflow and rebuild the host configuration."
                    .to_string(),
            },
        ],
        EnvironmentFailureCategory::MissingCredential => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::CredentialConfiguration,
            guidance: "Configure the named credential or configuration source for the supervised runner without committing or copying secret material into the repository."
                .to_string(),
        }],
        EnvironmentFailureCategory::NetworkForbidden => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::CapabilityPolicy,
            guidance: "Use an offline workflow or an approved host-side integration; this preflight will not enable network access or broaden confinement."
                .to_string(),
        }],
        EnvironmentFailureCategory::SandboxUnavailable => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::PersistentNixosHostSoftware,
            guidance: "Repair the required user-service sandbox support through the declarative NixOS host configuration before retrying."
                .to_string(),
        }],
        EnvironmentFailureCategory::ProbeFailed => vec![EnvironmentRemediation {
            scope: EnvironmentRemediationScope::ProjectLocal,
            guidance: "Correct the bounded requirement or fixed project environment, then rerun preflight; MACO will not install software or relax policy automatically."
                .to_string(),
        }],
        EnvironmentFailureCategory::RuntimeModelCatalogUnavailable => vec![
            EnvironmentRemediation {
                scope: EnvironmentRemediationScope::CapabilityPolicy,
                guidance: "Restore the trusted system Codex runtime-catalog path and its verified confinement; do not substitute a custom executable or broaden the sandbox."
                    .to_string(),
            },
            EnvironmentRemediation {
                scope: EnvironmentRemediationScope::CredentialConfiguration,
                guidance: "Validate the existing Codex auth source without copying secret material into the repository or plan."
                    .to_string(),
            },
        ],
    }
}

fn parse_environment_version(
    executable: EnvironmentExecutable,
    text: &str,
) -> Option<EnvironmentVersion> {
    let prefixes: &[&str] = match executable {
        EnvironmentExecutable::Bash => &["gnu bash, version "],
        EnvironmentExecutable::Cargo => &["cargo "],
        EnvironmentExecutable::Cmake => &["cmake version "],
        EnvironmentExecutable::Git => &["git version "],
        EnvironmentExecutable::Nix => &["nix (nix) "],
        EnvironmentExecutable::Python3 => &["python "],
        EnvironmentExecutable::Rustc => &["rustc "],
        EnvironmentExecutable::Node | EnvironmentExecutable::Npm => {
            return unique_version_candidate(text.lines().filter_map(parse_standalone_version));
        }
        EnvironmentExecutable::Codex => return None,
    };
    unique_version_candidate(
        text.lines()
            .filter_map(|line| parse_prefixed_version(line, prefixes)),
    )
}

fn parse_codex_version(text: &str) -> Option<(u64, u64, u64)> {
    let version = unique_version_candidate(
        text.lines()
            .filter_map(|line| parse_prefixed_version(line, &["codex-cli ", "codex "])),
    )?;
    Some((version.major, version.minor, version.patch))
}

fn parse_prefixed_version(line: &str, prefixes: &[&str]) -> Option<EnvironmentVersion> {
    let line = line.trim();
    let lower = line.to_ascii_lowercase();
    let prefix = prefixes.iter().find(|prefix| lower.starts_with(**prefix))?;
    let version_word = line[prefix.len()..].split_whitespace().next()?;
    parse_version_candidate(version_word)
}

fn parse_standalone_version(line: &str) -> Option<EnvironmentVersion> {
    let line = line.trim();
    (!line.is_empty() && !line.contains(char::is_whitespace))
        .then(|| parse_version_candidate(line))
        .flatten()
}

fn unique_version_candidate(
    mut candidates: impl Iterator<Item = EnvironmentVersion>,
) -> Option<EnvironmentVersion> {
    let candidate = candidates.next()?;
    candidates.next().is_none().then_some(candidate)
}

fn parse_version_candidate(text: &str) -> Option<EnvironmentVersion> {
    text.split_whitespace().find_map(|word| {
        let unprefixed =
            word.trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
        let candidate = unprefixed
            .split_once(|character: char| !character.is_ascii_digit() && character != '.')
            .map_or(unprefixed, |(numeric, _)| numeric);
        let mut components = candidate.split('.');
        let major = components.next()?.parse().ok()?;
        let minor = components.next()?.parse().ok()?;
        let patch = components.next()?.parse().ok()?;
        components
            .next()
            .is_none()
            .then_some(EnvironmentVersion::new(major, minor, patch))
    })
}

pub(crate) fn load_codex_runtime_model_catalog(
    program: &Path,
    cwd: &Path,
    timeout: Duration,
) -> std::result::Result<CodexRuntimeModelCatalog, Box<EnvironmentFailure>> {
    load_codex_runtime_model_catalog_inner(program, cwd, timeout, None).0
}

pub(crate) fn load_codex_runtime_model_catalog_authorized(
    program: &Path,
    cwd: &Path,
    timeout: Duration,
    run_id: &str,
    session: &crate::mutation_taxonomy::CatalogPreflightMutationSession,
) -> (
    std::result::Result<CodexRuntimeModelCatalog, Box<EnvironmentFailure>>,
    Option<crate::mutation_taxonomy::SupervisorProcessLaunchAuditEvidence>,
) {
    let (catalog, evidence) =
        load_codex_runtime_model_catalog_inner(program, cwd, timeout, Some((run_id, session)));
    let catalog = if catalog.is_ok() && evidence.is_none() {
        Err(Box::new(EnvironmentFailure::runtime_model_catalog(
            "authorized Codex catalog probe produced no launch evidence".to_string(),
        )))
    } else {
        catalog
    };
    (catalog, evidence)
}

fn load_codex_runtime_model_catalog_inner(
    program: &Path,
    cwd: &Path,
    timeout: Duration,
    authorization: Option<(
        &str,
        &crate::mutation_taxonomy::CatalogPreflightMutationSession,
    )>,
) -> (
    std::result::Result<CodexRuntimeModelCatalog, Box<EnvironmentFailure>>,
    Option<crate::mutation_taxonomy::SupervisorProcessLaunchAuditEvidence>,
) {
    #[allow(unused_mut)]
    let mut launch_evidence = None;
    let catalog = (|| -> Result<_> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (program, cwd, timeout);
            return Err(CodexRuntimeModelCatalogFailureCause::UnsupportedPlatform.into());
        }

        #[cfg(target_os = "linux")]
        {
            if program != Path::new("codex") {
                return Err(CodexRuntimeModelCatalogFailureCause::UntrustedCustomExecutable.into());
            }
            if timeout.is_zero() {
                return Err(CodexRuntimeModelCatalogFailureCause::InvalidTimeout.into());
            }
            let resolved_program = resolve_external_program(program, cwd)
                .context(CodexRuntimeModelCatalogFailureCause::ExecutableResolutionFailed)?;
            let program_parent = codex_runtime_model_catalog_process_root(&resolved_program)?;
            let program_identity = external_program_identity(&resolved_program)
                .context(CodexRuntimeModelCatalogFailureCause::ExecutableIdentityFailed)?;
            let auth = ValidatedCodexAuth::load()
                .context(CodexRuntimeModelCatalogFailureCause::AuthValidationFailed)?
                .context(CodexAuthValidationFailureCause::AuthFileMissing)?;
            auth.verify_source_unchanged()
                .context(CodexRuntimeModelCatalogFailureCause::AuthRevalidationFailed)?;

            let environment = allowed_env(
                ExternalAgentInvocation::CodexSupervisor,
                ExternalProgramTrust::TrustedSystemCodex,
            );
            let process_spec = ProcessSpec::direct(
                "Codex runtime model catalog preflight",
                &resolved_program,
                ["debug", "models"],
                program_parent,
                CODEX_MODEL_CATALOG_MAX_BYTES,
            )
            .with_environment(EnvironmentMode::ClearAndSet(environment.clone()))
            .with_stdin(StdinMode::Null)
            .with_timeout(Some(timeout))
            .with_private_runtime_home(true)
            .with_private_runtime_codex_home(true)
            .with_private_runtime_file("auth.json", auth.bytes.clone())
            .with_side_effect_confinement(SideEffectConfinementProfile::ExternalCodex(
                ExternalCodexProfile::read_only(program_parent),
            ));

            if let Some((run_id, session)) = authorization {
                let identity = crate::mutation_taxonomy::ExactSupervisorProcessLaunchIdentity {
                    run_id: run_id.to_string(),
                    subject_id: "catalog-codex".to_string(),
                    attempt: 1,
                    adapter: "codex".to_string(),
                    model: None,
                    reasoning_effort: None,
                    program_identity: format!(
                        "{};{}",
                        resolved_program.display(),
                        program_identity.display()
                    ),
                    execution_mode: "verified-catalog-preflight".to_string(),
                    delivery_identity: serde_json::to_string(&(
                        ["debug", "models"],
                        cwd,
                        timeout.as_millis(),
                        &environment,
                        auth.binding_sha256()?,
                    ))?,
                    kind: crate::mutation_taxonomy::SupervisorProcessLaunchKind::CatalogCodexProbe,
                };
                let (evidence, authorization) =
                    session.authorize_process_launch(identity.clone())?;
                let current_identity = external_program_identity(&resolved_program)
                    .context(CodexRuntimeModelCatalogFailureCause::ExecutableRevalidationFailed)?;
                if current_identity != program_identity {
                    return Err(CodexRuntimeModelCatalogFailureCause::ExecutableChanged.into());
                }
                auth.verify_source_unchanged()
                    .context(CodexRuntimeModelCatalogFailureCause::AuthRevalidationFailed)?;
                authorization.consume()?;
                launch_evidence = Some(evidence);
            }
            let process_result = run_process_cancellable(process_spec, &ProcessCancellation::new());
            let current_identity = external_program_identity(&resolved_program)
                .context(CodexRuntimeModelCatalogFailureCause::ExecutableRevalidationFailed)?;
            let auth_result = auth
                .verify_source_unchanged()
                .context(CodexRuntimeModelCatalogFailureCause::AuthRevalidationFailed);
            if current_identity != program_identity {
                return Err(CodexRuntimeModelCatalogFailureCause::ExecutableChanged.into());
            }
            auth_result?;
            let output = process_result
                .map_err(|error| codex_runtime_model_catalog_process_failure_cause(&error))?;
            if !output.safety_sensitive_succeeded() {
                return Err(CodexRuntimeModelCatalogFailureCause::UnsafeProcessResult.into());
            }
            if output.stdout.is_truncated() || output.stderr.is_truncated() {
                return Err(CodexRuntimeModelCatalogFailureCause::OutputLimitExceeded.into());
            }
            parse_codex_runtime_model_catalog(output.stdout.as_bytes())
                .context(CodexRuntimeModelCatalogFailureCause::InvalidOutput)
        }
    })();

    (
        catalog.map_err(|error| codex_runtime_model_catalog_failure(&error)),
        launch_evidence,
    )
}

fn codex_runtime_model_catalog_process_root(resolved_program: &Path) -> Result<&Path> {
    resolved_program
        .parent()
        .context(CodexRuntimeModelCatalogFailureCause::ExecutableHasNoParent)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum CodexRuntimeModelCatalogFailureCause {
    #[cfg(not(target_os = "linux"))]
    #[error("unsupported_platform")]
    UnsupportedPlatform,
    #[error("untrusted_custom_executable")]
    UntrustedCustomExecutable,
    #[error("invalid_timeout")]
    InvalidTimeout,
    #[error("trusted_executable_resolution_failed")]
    ExecutableResolutionFailed,
    #[error("trusted_executable_has_no_parent")]
    ExecutableHasNoParent,
    #[error("trusted_executable_identity_failed")]
    ExecutableIdentityFailed,
    #[error("codex_auth_validation_failed")]
    AuthValidationFailed,
    #[error("codex_auth_revalidation_failed")]
    AuthRevalidationFailed,
    #[error("trusted_executable_revalidation_failed")]
    ExecutableRevalidationFailed,
    #[error("trusted_executable_changed")]
    ExecutableChanged,
    #[error("catalog_process_cancelled")]
    ProcessCancelled,
    #[error("catalog_process_tee_failed")]
    ProcessTeeFailed,
    #[error("catalog_process_spawn_failed")]
    ProcessSpawnFailed,
    #[error("catalog_process_containment_unavailable")]
    ProcessContainmentUnavailable,
    #[error("catalog_process_setup_timed_out")]
    ProcessSetupTimedOut,
    #[error("catalog_process_wait_failed")]
    ProcessWaitFailed,
    #[error("catalog_process_ownership_failed")]
    ProcessOwnershipFailed,
    #[error("catalog_process_environment_failed")]
    ProcessEnvironmentFailed,
    #[error("catalog_process_io_setup_failed")]
    ProcessIoSetupFailed,
    #[error("catalog_process_stdin_too_large")]
    ProcessStdinTooLarge,
    #[error("catalog_process_result_unverified")]
    UnsafeProcessResult,
    #[error("catalog_output_limit_exceeded")]
    OutputLimitExceeded,
    #[error("catalog_output_invalid")]
    InvalidOutput,
}

fn codex_runtime_model_catalog_process_failure_cause(
    error: &ProcessRunError,
) -> CodexRuntimeModelCatalogFailureCause {
    match error {
        ProcessRunError::Cancelled { .. } => CodexRuntimeModelCatalogFailureCause::ProcessCancelled,
        ProcessRunError::OpenTee { .. } | ProcessRunError::TeeConflict { .. } => {
            CodexRuntimeModelCatalogFailureCause::ProcessTeeFailed
        }
        ProcessRunError::Spawn { .. } => CodexRuntimeModelCatalogFailureCause::ProcessSpawnFailed,
        ProcessRunError::ContainmentUnavailable { .. } => {
            CodexRuntimeModelCatalogFailureCause::ProcessContainmentUnavailable
        }
        ProcessRunError::SetupTimeout { .. } => {
            CodexRuntimeModelCatalogFailureCause::ProcessSetupTimedOut
        }
        ProcessRunError::Wait { .. } => CodexRuntimeModelCatalogFailureCause::ProcessWaitFailed,
        ProcessRunError::ProcessOwnership { .. } => {
            CodexRuntimeModelCatalogFailureCause::ProcessOwnershipFailed
        }
        ProcessRunError::EnvironmentFailure { .. } => {
            CodexRuntimeModelCatalogFailureCause::ProcessEnvironmentFailed
        }
        ProcessRunError::IoSetup { .. } => {
            CodexRuntimeModelCatalogFailureCause::ProcessIoSetupFailed
        }
        ProcessRunError::StdinTooLarge { .. } => {
            CodexRuntimeModelCatalogFailureCause::ProcessStdinTooLarge
        }
    }
}

fn codex_runtime_model_catalog_failure(error: &anyhow::Error) -> Box<EnvironmentFailure> {
    let cause = error
        .downcast_ref::<CodexAuthValidationFailureCause>()
        .map(ToString::to_string)
        .or_else(|| {
            error
                .downcast_ref::<CodexRuntimeModelCatalogFailureCause>()
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "unexpected_failure".to_string());
    Box::new(EnvironmentFailure::runtime_model_catalog(format!(
        "Codex runtime model catalog acquisition failed: cause={cause}"
    )))
}

fn parse_codex_runtime_model_catalog(bytes: &[u8]) -> Result<CodexRuntimeModelCatalog> {
    if bytes.is_empty() {
        bail!("Codex runtime model catalog output was empty");
    }
    if bytes.len() > CODEX_MODEL_CATALOG_MAX_BYTES {
        bail!(
            "Codex runtime model catalog output exceeds the {} byte limit",
            CODEX_MODEL_CATALOG_MAX_BYTES
        );
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("Codex runtime model catalog is not valid JSON")?;
    let object = value
        .as_object()
        .context("Codex runtime model catalog must be a JSON object")?;
    let models = object
        .get("models")
        .and_then(serde_json::Value::as_array)
        .context("Codex runtime model catalog must contain a models array")?;
    let mut slugs = Vec::with_capacity(models.len());
    for (index, model) in models.iter().enumerate() {
        let slug = model
            .as_object()
            .and_then(|model| model.get("slug"))
            .and_then(serde_json::Value::as_str)
            .with_context(|| {
                format!("Codex runtime model catalog entry {index} must contain a string slug")
            })?;
        slugs.push(slug.to_string());
    }
    CodexRuntimeModelCatalog::from_slugs(slugs)
}

fn validate_codex_model_slug(slug: &str) -> Result<()> {
    if slug.is_empty() {
        bail!("Codex runtime model catalog contains an empty slug");
    }
    if slug.len() > CODEX_MODEL_SLUG_MAX_BYTES {
        bail!(
            "Codex runtime model slug exceeds the {} byte limit",
            CODEX_MODEL_SLUG_MAX_BYTES
        );
    }
    let mut bytes = slug.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':')
        })
    {
        bail!(
            "Codex runtime model slug must start with an ASCII alphanumeric character and contain only ASCII alphanumerics or - _ . / :"
        );
    }
    Ok(())
}

fn external_program_trust(spec: &ExternalAgentCommand) -> ExternalProgramTrust {
    if spec.program == Path::new("codex") {
        ExternalProgramTrust::TrustedSystemCodex
    } else {
        ExternalProgramTrust::ExplicitCustom
    }
}

fn codex_permission_evidence(
    version: (u64, u64, u64),
    spec: &ExternalAgentCommand,
    argv_digest: &str,
    identity: &ExternalProgramIdentity,
) -> CodexPermissionEvidence {
    CodexPermissionEvidence {
        codex_version: format!("{}.{}.{}", version.0, version.1, version.2),
        minimum_version: format!(
            "{}.{}.{}",
            CODEX_MINIMUM_VERSION.0, CODEX_MINIMUM_VERSION.1, CODEX_MINIMUM_VERSION.2
        ),
        permission_profile: "maco_external_codex".to_string(),
        workspace_access: spec.workspace_access,
        network_enabled: false,
        argv_digest: argv_digest.to_string(),
        executable_identity: identity.display(),
    }
}

fn argv_digest(argv: &[OsString]) -> Result<String> {
    let mut bytes = b"maco-external-agent-argv-v2\0".to_vec();
    let encoding = os_argument_encoding_tag();
    bytes.extend_from_slice(&(encoding.len() as u64).to_be_bytes());
    bytes.extend_from_slice(encoding);
    bytes.extend_from_slice(&(argv.len() as u64).to_be_bytes());
    for argument in argv {
        let argument = os_argument_bytes(argument.as_os_str());
        bytes.extend_from_slice(&(argument.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&argument);
    }
    git2::Oid::hash_object(git2::ObjectType::Blob, &bytes)
        .map(|oid| oid.to_string())
        .context("failed to hash external-agent argv")
}

#[cfg(unix)]
const fn os_argument_encoding_tag() -> &'static [u8] {
    b"unix-bytes"
}

#[cfg(target_os = "windows")]
const fn os_argument_encoding_tag() -> &'static [u8] {
    b"windows-utf16le"
}

#[cfg(not(any(unix, target_os = "windows")))]
const fn os_argument_encoding_tag() -> &'static [u8] {
    b"portable-lossy-utf8"
}

fn trusted_codex_fixed_candidate_exists() -> bool {
    [
        "/run/current-system/sw/bin/codex",
        "/usr/bin/codex",
        "/bin/codex",
    ]
    .into_iter()
    .any(|candidate| Path::new(candidate).exists())
}

fn resolve_external_program(program: &Path, cwd: &Path) -> Result<PathBuf> {
    let require_root_owned = program == Path::new("codex");
    let candidate = if require_root_owned {
        [
            "/run/current-system/sw/bin/codex",
            "/usr/bin/codex",
            "/bin/codex",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.exists())
        .context("trusted Codex executable was not found at a fixed system path")?
    } else if program.is_absolute() {
        if fs::symlink_metadata(program)?.file_type().is_symlink() {
            bail!(
                "explicit external executable may not be a symlink: {}",
                program.display()
            );
        }
        program.to_path_buf()
    } else {
        bail!(
            "explicit external executable must be an absolute path; ambient PATH and relative resolution are refused (requested {} from {})",
            program.display(),
            cwd.display()
        );
    };
    let canonical = fs::canonicalize(&candidate)
        .with_context(|| format!("failed to canonicalize {}", candidate.display()))?;
    validate_external_program_identity(&canonical, require_root_owned)?;
    Ok(canonical)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutableAncestorPermissionDecision {
    Accept,
    RejectWritable,
    RejectOwnership,
}

#[cfg(unix)]
fn executable_ancestor_permission_decision(
    mode: u32,
    uid: u32,
    is_directory: bool,
    require_root_owned: bool,
) -> ExecutableAncestorPermissionDecision {
    let root_sticky_directory =
        uid == 0 && is_directory && mode & unsigned_to_u32(libc::S_ISVTX) != 0;
    if mode & 0o022 != 0 && !root_sticky_directory {
        ExecutableAncestorPermissionDecision::RejectWritable
    } else if require_root_owned && uid != 0 {
        ExecutableAncestorPermissionDecision::RejectOwnership
    } else {
        ExecutableAncestorPermissionDecision::Accept
    }
}

fn validate_external_program_identity(path: &Path, require_root_owned: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "external executable is not a non-symlink regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            bail!(
                "external executable must be executable and not group/world-writable: {}",
                path.display()
            );
        }
        if require_root_owned && metadata.uid() != 0 {
            bail!(
                "default Codex executable must be root-owned: {}",
                path.display()
            );
        }
        for ancestor in path.ancestors().skip(1) {
            let metadata = fs::symlink_metadata(ancestor).with_context(|| {
                format!(
                    "failed to inspect executable ancestor {}",
                    ancestor.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "external executable ancestor may not be a symlink: {}",
                    ancestor.display()
                );
            }
            match executable_ancestor_permission_decision(
                metadata.permissions().mode(),
                metadata.uid(),
                metadata.is_dir(),
                require_root_owned,
            ) {
                ExecutableAncestorPermissionDecision::Accept => {}
                ExecutableAncestorPermissionDecision::RejectWritable => {
                    bail!(
                        "external executable ancestor is group/world-writable: {}",
                        ancestor.display()
                    );
                }
                ExecutableAncestorPermissionDecision::RejectOwnership => {
                    bail!(
                        "default Codex executable ancestor is not root-owned: {}",
                        ancestor.display()
                    );
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExternalProgramIdentity {
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ExternalProgramIdentity {
    fn display(&self) -> String {
        let modified = self
            .modified
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        #[cfg(unix)]
        {
            format!(
                "dev={};ino={};len={};mtime_ns={modified}",
                self.device, self.inode, self.length
            )
        }
        #[cfg(not(unix))]
        {
            format!("len={};mtime_ns={modified}", self.length)
        }
    }
}

fn external_program_identity(path: &Path) -> Result<ExternalProgramIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect executable identity {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("external executable identity is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(ExternalProgramIdentity {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(ExternalProgramIdentity {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

pub(crate) fn exact_external_process_launch_binding(
    command: &ExternalAgentCommand,
) -> Result<(String, String)> {
    let (program, argv, cwd, environment) = if let Some(config) = &command.runtime_adapter {
        let launch = config.render(&crate::runtime_adapter::LaunchContext {
            prompt: &command.prompt,
            model: command.model.as_deref(),
            effort: command.reasoning_effort.as_deref(),
            cwd: &command.cwd,
            output: &command.output_last_message,
        })?;
        (launch.program, launch.argv, launch.cwd, launch.env)
    } else {
        (
            command.program.clone(),
            Vec::new(),
            command.cwd.clone(),
            BTreeMap::new(),
        )
    };
    let resolved = resolve_external_program(&program, &cwd)?;
    let identity = external_program_identity(&resolved)?;
    let program_identity = format!("{};{}", resolved.display(), identity.display());
    let delivery_identity = serde_json::to_string(&(
        argv,
        cwd,
        environment,
        &command.prompt,
        &command.json_log,
        &command.output_last_message,
        &command.output_schema,
        command.timeout.as_millis(),
        command.workspace_access,
        command.writable_launch_target,
    ))
    .context("failed to encode exact external process delivery identity")?;
    Ok((program_identity, delivery_identity))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProtectedWorktreeControls {
    read_only_roots: Vec<ProtectedWorktreeControl>,
    read_only_files: Vec<ProtectedWorktreeControl>,
    read_write_roots: Vec<ProtectedWorktreeControl>,
    read_write_files: Vec<ProtectedWorktreeControl>,
    managed_git: Option<ManagedWorktreeGitMetadata>,
    exact_read_only_input_files: Vec<PathBuf>,
    exact_writable_artifact_files: Vec<ExactWritableArtifactFile>,
    writable_artifact_root: Option<PathBuf>,
}

#[derive(Clone)]
struct ExactWritableArtifactFile {
    worker_id: String,
    path: PathBuf,
    #[cfg(target_os = "linux")]
    held_file: std::sync::Arc<fs::File>,
    #[cfg(target_os = "linux")]
    identity: ExactWritableArtifactIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactWritableArtifactIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

impl std::fmt::Debug for ExactWritableArtifactFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExactWritableArtifactFile")
            .field("worker_id", &self.worker_id)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ExactWritableArtifactFile {
    fn eq(&self, other: &Self) -> bool {
        self.worker_id == other.worker_id && self.path == other.path
    }
}

impl Eq for ExactWritableArtifactFile {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedWorktreeGitMetadata {
    worktree_git_dir: PathBuf,
    private_git_dir: PathBuf,
    private_object_dir: PathBuf,
    shared_object_dir: PathBuf,
    common_config: PathBuf,
    active_commit_hook: Option<PathBuf>,
    fixed_private_read_only_files: Vec<PathBuf>,
    common_read_only_roots: Vec<PathBuf>,
    common_read_only_files: Vec<PathBuf>,
}

/// A collection-time binding to an already-created managed child Git boundary.
///
/// Construction never creates or repairs storage. Callers receive only the
/// exact paths needed to validate and import the private object closure; the
/// layout and ref literals remain owned by this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedChildGitBoundary {
    workspace: PathBuf,
    metadata: ManagedWorktreeGitMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedChildGitImport {
    pub(crate) base_oid: Oid,
    pub(crate) head_oid: Oid,
    pub(crate) head_tree_oid: Oid,
    pub(crate) touched_paths: Vec<PathBuf>,
    pub(crate) final_changed_paths: Vec<PathBuf>,
    pub(crate) closure_object_count: usize,
    pub(crate) closure_bytes: u64,
    pub(crate) imported_object_count: usize,
    pub(crate) imported_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedChildGitClosureSeal {
    base_oid: Oid,
    head_oid: Oid,
    object_kinds: BTreeMap<Oid, git2::ObjectType>,
    object_bytes: BTreeMap<Oid, u64>,
    touched_paths: BTreeSet<PathBuf>,
    final_changed_paths: BTreeSet<PathBuf>,
}

const MAX_MANAGED_CHILD_IMPORT_COMMITS: usize = 256;
const MAX_MANAGED_CHILD_IMPORT_OBJECTS: usize = 262_144;
const MAX_MANAGED_CHILD_IMPORT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_MANAGED_CHILD_IMPORT_TREE_DEPTH: usize = 256;

impl ManagedChildGitBoundary {
    pub(crate) fn private_git_dir(&self) -> &Path {
        &self.metadata.private_git_dir
    }

    pub(crate) fn private_object_dir(&self) -> &Path {
        &self.metadata.private_object_dir
    }

    pub(crate) fn shared_object_dir(&self) -> &Path {
        &self.metadata.shared_object_dir
    }

    pub(crate) fn revalidate(&self) -> Result<Oid> {
        let observed = managed_worktree_git_metadata_with_mode(&self.workspace, false)?
            .context("managed child collection requires an existing linked Git boundary")?;
        if observed != self.metadata {
            bail!("managed child Git boundary changed after its collection-time binding");
        }
        verify_managed_git_boundary_after_launch(&observed)?;
        read_managed_child_private_ref_oid(&observed.private_git_dir)
    }
}

pub(crate) fn bind_existing_managed_child_git_boundary(
    workspace: &Path,
) -> Result<ManagedChildGitBoundary> {
    let workspace = fs::canonicalize(workspace)
        .context("managed child collection workspace could not be resolved")?;
    let metadata = managed_worktree_git_metadata_with_mode(&workspace, false)?
        .context("managed child collection requires an existing linked Git boundary")?;
    verify_managed_git_boundary_after_launch(&metadata)?;
    Ok(ManagedChildGitBoundary {
        workspace,
        metadata,
    })
}

#[cfg(test)]
pub(crate) fn prepare_managed_child_git_boundary_for_test(workspace: &Path) -> Result<()> {
    managed_worktree_git_metadata(workspace)?
        .context("test fixture expected a managed linked-worktree Git boundary")?;
    Ok(())
}

/// Materializes one supervisor-captured worktree candidate into the fixed
/// managed-child private ref when the child left that ref at its captured base.
///
/// The caller must retain the managed-worktree write lease that protected the
/// candidate capture for this complete operation. This function independently
/// rebinds the private Git boundary, verifies both repository heads and the
/// fixed private ref, stages only the normalized candidate paths into an index
/// reset to the captured base, and advances the ref only after the resulting
/// tree exactly matches the supervisor-captured tree. The ordinary Git commit
/// path is intentional: repository-projected attribution and the validated
/// commit-msg hook remain authoritative and are never bypassed.
pub(crate) struct ManagedChildCommitAuthorization<'borrow, 'session> {
    write_lease: &'borrow crate::worktree::ManagedWorktreeWriteLease,
    permit: &'borrow crate::mutation_taxonomy::SupervisorOperationPermit<'session>,
}

impl<'borrow, 'session> ManagedChildCommitAuthorization<'borrow, 'session> {
    pub(crate) fn new(
        write_lease: &'borrow crate::worktree::ManagedWorktreeWriteLease,
        permit: &'borrow crate::mutation_taxonomy::SupervisorOperationPermit<'session>,
    ) -> Result<Self> {
        permit
            .verify(crate::mutation_taxonomy::MutationOperation::SandboxWorktreeCommit)
            .map_err(anyhow::Error::from)?;
        Ok(Self {
            write_lease,
            permit,
        })
    }
}

pub(crate) fn materialize_managed_child_git_commit_authorized(
    primary_repo: &Path,
    workspace: &Path,
    captured_base: Oid,
    claimed_paths: &[PathBuf],
    candidate_paths: &[PathBuf],
    candidate_tree: Oid,
    authorization: ManagedChildCommitAuthorization<'_, '_>,
) -> Result<Option<Oid>> {
    authorization
        .permit
        .verify(crate::mutation_taxonomy::MutationOperation::SandboxWorktreeCommit)
        .map_err(anyhow::Error::from)?;
    if authorization.write_lease.path() != workspace {
        bail!("managed child commit write lease does not bind the selected workspace");
    }
    materialize_managed_child_git_commit_impl(
        primary_repo,
        workspace,
        captured_base,
        claimed_paths,
        candidate_paths,
        candidate_tree,
    )
}

#[cfg(test)]
pub(crate) fn materialize_managed_child_git_commit(
    primary_repo: &Path,
    workspace: &Path,
    captured_base: Oid,
    claimed_paths: &[PathBuf],
    candidate_paths: &[PathBuf],
    candidate_tree: Oid,
) -> Result<Option<Oid>> {
    materialize_managed_child_git_commit_impl(
        primary_repo,
        workspace,
        captured_base,
        claimed_paths,
        candidate_paths,
        candidate_tree,
    )
}

fn materialize_managed_child_git_commit_impl(
    primary_repo: &Path,
    workspace: &Path,
    captured_base: Oid,
    claimed_paths: &[PathBuf],
    candidate_paths: &[PathBuf],
    candidate_tree: Oid,
) -> Result<Option<Oid>> {
    let boundary = bind_existing_managed_child_git_boundary(workspace)?;
    let primary_repo = fs::canonicalize(primary_repo)
        .context("managed child materialization primary repository could not be resolved")?;
    let primary = crate::git_repository::open(&primary_repo)
        .context("managed child materialization could not open the primary repository")?;
    let primary_head = primary
        .head()
        .context("managed child materialization primary repository has no HEAD")?
        .peel_to_commit()
        .context("managed child materialization primary HEAD is not a commit")?
        .id();
    if primary_head != captured_base {
        bail!(
            "managed child materialization captured base changed: expected {captured_base}, observed {primary_head}"
        );
    }
    let linked = crate::git_repository::open(workspace)
        .context("managed child materialization could not reopen the linked worktree")?;
    let linked_head = linked
        .head()
        .context("managed child materialization linked worktree has no shared HEAD")?
        .peel_to_commit()
        .context("managed child materialization linked worktree HEAD is not a commit")?
        .id();
    if linked_head != captured_base {
        bail!(
            "managed child materialization linked worktree base changed: expected {captured_base}, observed {linked_head}"
        );
    }
    let primary_objects = canonical_git_directory(
        &primary.commondir().join("objects"),
        "managed child materialization primary object directory",
    )?;
    if primary_objects != boundary.shared_object_dir() {
        bail!(
            "managed child materialization shared object directory does not belong to the primary repository"
        );
    }

    let claimed_paths = claimed_paths
        .iter()
        .map(crate::sync::normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()
        .context("managed child materialization claims are invalid")?;
    if claimed_paths.is_empty() {
        bail!("managed child materialization requires at least one exact claimed path");
    }
    let candidate_paths = candidate_paths
        .iter()
        .map(crate::sync::normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()
        .context("managed child materialization candidate paths are invalid")?;
    if let Some(unclaimed) = candidate_paths.iter().find(|path| {
        !claimed_paths
            .iter()
            .any(|claim| *path == claim || path.starts_with(claim))
    }) {
        bail!(
            "managed child materialization candidate contains unclaimed path '{}'",
            unclaimed.display()
        );
    }

    let initial_private_head = boundary.revalidate()?;
    if initial_private_head != captured_base {
        // A child-created private commit remains subject to the existing fsck
        // and import path. Never overwrite it or synthesize a second commit.
        return Ok(None);
    }
    let base_tree = primary
        .find_commit(captured_base)
        .context("managed child materialization captured base commit is missing")?
        .tree_id();
    if candidate_paths.is_empty() {
        if candidate_tree != base_tree {
            bail!(
                "managed child materialization empty candidate tree {candidate_tree} differs from captured base tree {base_tree}"
            );
        }
        return Ok(None);
    }
    for path in &candidate_paths {
        validate_managed_child_candidate_path(&boundary.workspace, path)?;
    }

    run_managed_child_git_command(
        &boundary,
        vec![OsString::from("read-tree"), OsString::from(captured_base.to_string())],
        StdinMode::Null,
        "initialize managed child materialization index",
    )?;
    require_managed_child_private_base(&boundary, captured_base, "after index initialization")?;

    let pathspec_input = managed_child_literal_pathspec_input(&candidate_paths)?;
    run_managed_child_git_command(
        &boundary,
        vec![
            OsString::from("--literal-pathspecs"),
            OsString::from("-c"),
            OsString::from("core.fileMode=true"),
            OsString::from("add"),
            OsString::from("--all"),
            OsString::from("--pathspec-from-file=-"),
            OsString::from("--pathspec-file-nul"),
        ],
        StdinMode::Bytes(pathspec_input),
        "stage managed child materialization candidate",
    )?;
    require_managed_child_private_base(&boundary, captured_base, "after candidate staging")?;

    let tree_output = run_managed_child_git_command(
        &boundary,
        vec![OsString::from("write-tree")],
        StdinMode::Null,
        "write managed child materialization tree",
    )?;
    let tree_text = std::str::from_utf8(&tree_output)
        .context("managed child materialization tree output is not UTF-8")?;
    let materialized_tree = Oid::from_str(tree_text.trim())
        .context("managed child materialization tree output is not an object id")?;
    if materialized_tree != candidate_tree {
        bail!(
            "managed child materialization tree {materialized_tree} differs from supervisor-captured candidate tree {candidate_tree}"
        );
    }

    let private = open_managed_child_private_repository(&boundary)?;
    let base = private
        .find_commit(captured_base)
        .context("managed child materialization private view omitted the captured base")?;
    let tree = private
        .find_tree(materialized_tree)
        .context("managed child materialization private tree is missing")?;
    let materialized_paths = managed_child_tree_edge_paths(&private, &base.tree()?, &tree)?;
    if materialized_paths != candidate_paths {
        bail!(
            "managed child materialization staged paths [{}] differ from supervisor-captured candidate paths [{}]",
            materialized_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            candidate_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    require_managed_child_clean_unstaged_worktree(&boundary)?;
    require_managed_child_private_base(&boundary, captured_base, "before private commit")?;
    require_managed_child_repository_bases(
        &primary,
        &linked,
        captured_base,
        "before private commit",
    )?;

    run_managed_child_git_command(
        &boundary,
        vec![
            OsString::from("commit"),
            OsString::from("--quiet"),
            OsString::from("-m"),
            OsString::from("Materialize verified managed child candidate"),
        ],
        StdinMode::Null,
        "commit managed child materialization candidate",
    )?;
    let head = boundary.revalidate()?;
    if head == captured_base {
        bail!("managed child materialization commit did not advance the fixed private ref");
    }
    let commit = private
        .find_commit(head)
        .context("managed child materialization fixed private ref is not a commit")?;
    if commit.parent_count() != 1
        || commit.parent_id(0).ok() != Some(captured_base)
        || commit.tree_id() != candidate_tree
    {
        bail!(
            "managed child materialization commit does not preserve the captured base and exact candidate tree"
        );
    }
    require_managed_child_repository_bases(
        &primary,
        &linked,
        captured_base,
        "after private commit",
    )?;
    Ok(Some(head))
}

fn require_managed_child_private_base(
    boundary: &ManagedChildGitBoundary,
    captured_base: Oid,
    phase: &str,
) -> Result<()> {
    let observed = boundary.revalidate()?;
    if observed != captured_base {
        bail!(
            "managed child fixed private ref changed {phase}: expected {captured_base}, observed {observed}"
        );
    }
    Ok(())
}

fn require_managed_child_repository_bases(
    primary: &git2::Repository,
    linked: &git2::Repository,
    captured_base: Oid,
    phase: &str,
) -> Result<()> {
    let primary_head = primary
        .head()
        .with_context(|| format!("managed child primary HEAD disappeared {phase}"))?
        .peel_to_commit()
        .with_context(|| format!("managed child primary HEAD is not a commit {phase}"))?
        .id();
    let linked_head = linked
        .head()
        .with_context(|| format!("managed child linked HEAD disappeared {phase}"))?
        .peel_to_commit()
        .with_context(|| format!("managed child linked HEAD is not a commit {phase}"))?
        .id();
    if primary_head != captured_base || linked_head != captured_base {
        bail!(
            "managed child repository base changed {phase}: expected {captured_base}, primary {primary_head}, linked {linked_head}"
        );
    }
    Ok(())
}

fn validate_managed_child_candidate_path(workspace: &Path, relative: &Path) -> Result<()> {
    let mut current = workspace.to_path_buf();
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        let std::path::Component::Normal(component) = component else {
            bail!("managed child materialization candidate path is not normalized");
        };
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect managed child materialization path {}",
                        relative.display()
                    )
                })
            }
        };
        if metadata.file_type().is_symlink() {
            bail!(
                "managed child materialization candidate path '{}' contains a symlink",
                relative.display()
            );
        }
        let is_final = index.saturating_add(1) == component_count;
        if !is_final && !metadata.is_dir() {
            bail!(
                "managed child materialization candidate path '{}' has a non-directory parent",
                relative.display()
            );
        }
        if is_final && !metadata.is_file() {
            bail!(
                "managed child materialization candidate path '{}' is not a regular file or deletion",
                relative.display()
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
fn managed_child_literal_pathspec_input(paths: &BTreeSet<PathBuf>) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    const MAX_PATHSPEC_INPUT_BYTES: usize = 64 * 1024 * 1024;
    let mut input = Vec::new();
    for path in paths {
        input.extend_from_slice(path.as_os_str().as_bytes());
        input.push(0);
        if input.len() > MAX_PATHSPEC_INPUT_BYTES {
            bail!(
                "managed child materialization pathspec exceeds its {MAX_PATHSPEC_INPUT_BYTES}-byte bound"
            );
        }
    }
    Ok(input)
}

#[cfg(not(unix))]
fn managed_child_literal_pathspec_input(_paths: &BTreeSet<PathBuf>) -> Result<Vec<u8>> {
    bail!("managed child materialization path routing is unsupported on this platform")
}

fn managed_child_tree_edge_paths(
    source: &git2::Repository,
    parent: &git2::Tree<'_>,
    child: &git2::Tree<'_>,
) -> Result<BTreeSet<PathBuf>> {
    let mut options = git2::DiffOptions::new();
    options
        .include_typechange(true)
        .include_typechange_trees(true);
    let diff = source
        .diff_tree_to_tree(Some(parent), Some(child), Some(&mut options))
        .context("managed child materialization tree diff could not be computed")?;
    let mut paths = BTreeSet::new();
    for delta in diff.deltas() {
        for path in [delta.old_file().path(), delta.new_file().path()]
            .into_iter()
            .flatten()
        {
            paths.insert(
                crate::sync::normalize_repo_relative_path(path)
                    .context("managed child materialization tree diff contains an invalid path")?,
            );
        }
    }
    Ok(paths)
}

fn require_managed_child_clean_unstaged_worktree(
    boundary: &ManagedChildGitBoundary,
) -> Result<()> {
    let unstaged = run_managed_child_git_command_allow_status(
        boundary,
        vec![
            OsString::from("-c"),
            OsString::from("core.fileMode=true"),
            OsString::from("diff"),
            OsString::from("--quiet"),
            OsString::from("--ignore-submodules=none"),
            OsString::from("--"),
        ],
        StdinMode::Null,
        "revalidate managed child tracked worktree",
    )?;
    if !unstaged.success {
        bail!("managed child worktree changed after its supervisor candidate capture");
    }
    let untracked = run_managed_child_git_command(
        boundary,
        vec![
            OsString::from("ls-files"),
            OsString::from("--others"),
            OsString::from("--exclude-standard"),
            OsString::from("-z"),
        ],
        StdinMode::Null,
        "revalidate managed child untracked worktree",
    )?;
    if !untracked.is_empty() {
        bail!("managed child worktree gained an unstaged untracked path during materialization");
    }
    Ok(())
}

fn run_managed_child_git_command(
    boundary: &ManagedChildGitBoundary,
    args: Vec<OsString>,
    stdin: StdinMode,
    label: &str,
) -> Result<Vec<u8>> {
    let output = run_managed_child_git_command_allow_status(boundary, args, stdin, label)?;
    if !output.success {
        bail!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

fn run_managed_child_git_command_allow_status(
    boundary: &ManagedChildGitBoundary,
    args: Vec<OsString>,
    stdin: StdinMode,
    label: &str,
) -> Result<crate::merge::RequiredCommandOutput> {
    const MATERIALIZATION_GIT_TIMEOUT: Duration = Duration::from_secs(120);
    const MATERIALIZATION_GIT_CAPTURE_BYTES: usize = 1024 * 1024;
    const MATERIALIZATION_GIT_STDIN_BYTES: usize = 64 * 1024 * 1024;

    let mut environment = crate::merge::minimal_network_environment()?;
    environment.extend(managed_git_environment(&boundary.metadata)?);
    environment.insert(
        "GIT_WORK_TREE".to_string(),
        boundary
            .workspace
            .to_str()
            .context("managed child materialization workspace is not UTF-8")?
            .to_string(),
    );
    let mut profile = StrictOfflineWorkspaceProfile::read_only(&boundary.workspace)
        .with_writable_artifact_root(boundary.private_git_dir())
        .with_visible_read_only_root(boundary.shared_object_dir());
    if let Some(hook) = &boundary.metadata.active_commit_hook {
        profile = profile.with_visible_read_only_file(hook);
    }
    crate::merge::run_required_direct(
        label,
        crate::merge::resolve_trusted_executable("git")?,
        args,
        &boundary.workspace,
        environment,
        stdin,
        MATERIALIZATION_GIT_TIMEOUT,
        MATERIALIZATION_GIT_CAPTURE_BYTES,
        MATERIALIZATION_GIT_STDIN_BYTES,
        profile,
    )
}

/// Validates and imports one managed child's private commit closure.
///
/// The complete private chain and reachable commit/tree/blob graph are checked
/// before the primary object database is mutated. Only missing, content-addressed
/// objects from that verified closure are written; refs, HEAD, indexes, reflogs,
/// and other Git metadata are never import targets.
pub(crate) struct ManagedChildImportAuthorization<'borrow, 'session> {
    write_lease: &'borrow crate::worktree::ManagedWorktreeWriteLease,
    permit: &'borrow crate::mutation_taxonomy::SupervisorOperationPermit<'session>,
}

impl<'borrow, 'session> ManagedChildImportAuthorization<'borrow, 'session> {
    pub(crate) fn new(
        write_lease: &'borrow crate::worktree::ManagedWorktreeWriteLease,
        permit: &'borrow crate::mutation_taxonomy::SupervisorOperationPermit<'session>,
    ) -> Result<Self> {
        permit
            .verify(
                crate::mutation_taxonomy::MutationOperation::SupervisorPrimaryObjectDatabaseImport,
            )
            .map_err(anyhow::Error::from)?;
        Ok(Self {
            write_lease,
            permit,
        })
    }
}

pub(crate) fn collect_and_import_managed_child_git_commit_authorized(
    primary_repo: &Path,
    workspace: &Path,
    captured_base: Oid,
    claimed_paths: &[PathBuf],
    authorization: ManagedChildImportAuthorization<'_, '_>,
) -> Result<ManagedChildGitImport> {
    authorization
        .permit
        .verify(
            crate::mutation_taxonomy::MutationOperation::SupervisorPrimaryObjectDatabaseImport,
        )
        .map_err(anyhow::Error::from)?;
    if authorization.write_lease.path() != workspace {
        bail!("managed child import write lease does not bind the selected workspace");
    }
    collect_and_import_managed_child_git_commit_impl(
        primary_repo,
        workspace,
        captured_base,
        claimed_paths,
    )
}

#[cfg(test)]
pub(crate) fn collect_and_import_managed_child_git_commit(
    primary_repo: &Path,
    workspace: &Path,
    captured_base: Oid,
    claimed_paths: &[PathBuf],
) -> Result<ManagedChildGitImport> {
    collect_and_import_managed_child_git_commit_impl(
        primary_repo,
        workspace,
        captured_base,
        claimed_paths,
    )
}

fn collect_and_import_managed_child_git_commit_impl(
    primary_repo: &Path,
    workspace: &Path,
    captured_base: Oid,
    claimed_paths: &[PathBuf],
) -> Result<ManagedChildGitImport> {
    let boundary = bind_existing_managed_child_git_boundary(workspace)?;
    let initial_head = boundary.revalidate()?;
    let primary_repo = fs::canonicalize(primary_repo)
        .context("managed child import primary repository could not be resolved")?;
    let primary = crate::git_repository::open(&primary_repo)
        .context("managed child import could not open the primary repository")?;
    let primary_head = primary
        .head()
        .context("managed child import primary repository has no HEAD")?
        .peel_to_commit()
        .context("managed child import primary HEAD is not a commit")?
        .id();
    if primary_head != captured_base {
        bail!(
            "managed child import captured base changed: expected {captured_base}, observed {primary_head}"
        );
    }
    let linked = crate::git_repository::open(workspace)
        .context("managed child import could not reopen the linked worktree")?;
    let linked_head = linked
        .head()
        .context("managed child import linked worktree has no shared HEAD")?
        .peel_to_commit()
        .context("managed child import linked worktree HEAD is not a commit")?
        .id();
    if linked_head != captured_base {
        bail!(
            "managed child import linked worktree base changed: expected {captured_base}, observed {linked_head}"
        );
    }
    let primary_objects = canonical_git_directory(
        &primary.commondir().join("objects"),
        "managed child import primary object directory",
    )?;
    if primary_objects != boundary.shared_object_dir() {
        bail!("managed child import shared object directory does not belong to the primary repository");
    }

    let claimed_paths = claimed_paths
        .iter()
        .map(crate::sync::normalize_repo_relative_path)
        .collect::<std::result::Result<BTreeSet<_>, _>>()
        .context("managed child import claims are invalid")?;
    if claimed_paths.is_empty() {
        bail!("managed child import requires at least one exact claimed path");
    }

    let source = open_managed_child_private_repository(&boundary)?;
    let private_only = private_only_managed_child_odb(&boundary)?;
    let destination = primary
        .odb()
        .context("managed child import could not open the primary object database")?;
    let seal = fsck_managed_child_private_closure(
        &source,
        &private_only,
        &destination,
        captured_base,
        initial_head,
        &claimed_paths,
    )?;
    if boundary.revalidate()? != seal.head_oid {
        bail!("managed child private ref changed after fsck and before object import");
    }

    let mut imported_object_count = 0usize;
    let mut imported_bytes = 0u64;
    let source_odb = source
        .odb()
        .context("managed child import could not reopen the private object database")?;
    for (oid, expected_kind) in &seal.object_kinds {
        let object = source_odb
            .read(*oid)
            .with_context(|| format!("managed child import source object {oid} disappeared"))?;
        if object.kind() != *expected_kind {
            bail!("managed child import source object {oid} changed kind after fsck");
        }
        if destination.exists(*oid) {
            let existing = destination.read(*oid).with_context(|| {
                format!("managed child import could not re-read existing object {oid}")
            })?;
            if existing.kind() != object.kind() || existing.data() != object.data() {
                bail!("managed child import existing object {oid} did not preserve its bytes");
            }
            continue;
        }
        let written = destination
            .write(*expected_kind, object.data())
            .with_context(|| {
                format!("managed child import failed to write verified object {oid}")
            })?;
        if written != *oid {
            bail!("managed child import changed the object id for {oid}");
        }
        imported_object_count = imported_object_count
            .checked_add(1)
            .context("managed child imported object count overflow")?;
        imported_bytes = imported_bytes
            .checked_add(
                u64::try_from(object.data().len())
                    .context("managed child imported object size did not fit its byte counter")?,
            )
            .context("managed child imported object byte count overflow")?;
    }

    if boundary.revalidate()? != seal.head_oid {
        bail!("managed child private ref changed during object import");
    }
    let observed = fsck_managed_child_private_closure(
        &source,
        &private_only,
        &destination,
        captured_base,
        seal.head_oid,
        &claimed_paths,
    )?;
    if observed != seal {
        bail!("managed child private closure changed after object import");
    }
    let final_primary_head = primary
        .head()
        .context("managed child import primary repository lost HEAD during import")?
        .peel_to_commit()
        .context("managed child import primary HEAD stopped resolving to a commit")?
        .id();
    if final_primary_head != captured_base {
        bail!(
            "managed child import primary HEAD changed during import: expected {captured_base}, observed {final_primary_head}"
        );
    }
    primary
        .find_commit(seal.head_oid)
        .context("managed child imported head is not resolvable from the primary object store")?;

    let closure_bytes = seal.object_bytes.values().try_fold(0u64, |total, bytes| {
        total
            .checked_add(*bytes)
            .context("managed child closure byte count overflow")
    })?;
    let head_tree_oid = source
        .find_commit(seal.head_oid)
        .context("managed child imported head could not be reparsed")?
        .tree_id();
    Ok(ManagedChildGitImport {
        base_oid: seal.base_oid,
        head_oid: seal.head_oid,
        head_tree_oid,
        touched_paths: seal.touched_paths.into_iter().collect(),
        final_changed_paths: seal.final_changed_paths.into_iter().collect(),
        closure_object_count: seal.object_kinds.len(),
        closure_bytes,
        imported_object_count,
        imported_bytes,
    })
}

fn open_managed_child_private_repository(
    boundary: &ManagedChildGitBoundary,
) -> Result<git2::Repository> {
    let repository = git2::Repository::open_bare(boundary.private_git_dir())
        .context("managed child import could not open the private Git directory")?;
    let shared_objects = boundary
        .shared_object_dir()
        .to_str()
        .context("managed child shared object directory is not UTF-8")?;
    repository
        .odb()
        .context("managed child import could not open the private object database")?
        .add_disk_alternate(shared_objects)
        .context("managed child import could not attach the verified shared object alternate")?;
    Ok(repository)
}

fn private_only_managed_child_odb(
    boundary: &ManagedChildGitBoundary,
) -> Result<git2::Odb<'static>> {
    let private_objects = boundary
        .private_object_dir()
        .to_str()
        .context("managed child private object directory is not UTF-8")?;
    let odb =
        git2::Odb::new().context("managed child import could not create a private-only ODB")?;
    odb.add_disk_alternate(private_objects)
        .context("managed child import could not attach the private-only object backend")?;
    Ok(odb)
}

fn fsck_managed_child_private_closure(
    source: &git2::Repository,
    private_only: &git2::Odb<'_>,
    destination: &git2::Odb<'_>,
    base_oid: Oid,
    head_oid: Oid,
    claimed_paths: &BTreeSet<PathBuf>,
) -> Result<ManagedChildGitClosureSeal> {
    let base = source.find_commit(base_oid).with_context(|| {
        format!("managed child private closure omitted captured base {base_oid}")
    })?;
    let head = source.find_commit(head_oid).with_context(|| {
        format!("managed child private ref does not resolve to commit {head_oid}")
    })?;
    let mut chain = Vec::new();
    let mut touched_paths = BTreeSet::new();
    let mut visited_commits = BTreeSet::new();
    let mut current = head;
    while current.id() != base_oid {
        if chain.len() >= MAX_MANAGED_CHILD_IMPORT_COMMITS {
            bail!(
                "managed child commit chain exceeded its {MAX_MANAGED_CHILD_IMPORT_COMMITS}-commit bound"
            );
        }
        if !visited_commits.insert(current.id()) {
            bail!("managed child commit chain contains a cycle");
        }
        if !private_only.exists(current.id()) {
            bail!(
                "managed child commit {} is not stored in the private object directory",
                current.id()
            );
        }
        if current.parent_count() != 1 {
            bail!(
                "managed child commit {} must have exactly one parent before the captured base",
                current.id()
            );
        }
        let parent = current
            .parent(0)
            .with_context(|| format!("managed child commit {} omitted its parent", current.id()))?;
        if parent.id() == current.id() {
            bail!("managed child commit chain contains a self parent");
        }
        let edge_paths = managed_child_commit_edge_paths(source, &parent, &current)?;
        for path in edge_paths {
            if !claimed_paths
                .iter()
                .any(|claimed| path == *claimed || path.starts_with(claimed))
            {
                bail!(
                    "managed child commit {} changed unclaimed path '{}'",
                    current.id(),
                    path.display()
                );
            }
            touched_paths.insert(path);
        }
        chain.push(current.id());
        current = parent;
    }
    if current.id() != base_oid {
        bail!("managed child private ref does not descend linearly from the captured base");
    }

    let final_changed_paths =
        managed_child_commit_edge_paths(source, &base, &source.find_commit(head_oid)?)?
            .into_iter()
            .collect::<BTreeSet<_>>();
    for path in &final_changed_paths {
        if !claimed_paths
            .iter()
            .any(|claimed| path == claimed || path.starts_with(claimed))
        {
            bail!(
                "managed child final tree changed unclaimed path '{}'",
                path.display()
            );
        }
    }

    let source_odb = source
        .odb()
        .context("managed child fsck could not open its source object database")?;
    let mut object_kinds = BTreeMap::new();
    let mut object_bytes = BTreeMap::new();
    let mut pending = chain
        .iter()
        .copied()
        .map(|oid| (oid, git2::ObjectType::Commit, 0usize))
        .collect::<Vec<_>>();
    let mut traversal_steps = 0usize;
    let mut aggregate_bytes = 0u64;
    while let Some((oid, expected_kind, depth)) = pending.pop() {
        traversal_steps = traversal_steps
            .checked_add(1)
            .context("managed child closure traversal count overflow")?;
        if traversal_steps > MAX_MANAGED_CHILD_IMPORT_OBJECTS.saturating_mul(4) {
            bail!("managed child closure exceeded its traversal safety bound");
        }
        if let Some(previous_kind) = object_kinds.get(&oid) {
            if *previous_kind != expected_kind {
                bail!("managed child closure reused object {oid} with contradictory kinds");
            }
            continue;
        }
        if object_kinds.len() >= MAX_MANAGED_CHILD_IMPORT_OBJECTS {
            bail!(
                "managed child closure exceeded its {MAX_MANAGED_CHILD_IMPORT_OBJECTS}-object bound"
            );
        }
        let (declared_size, declared_kind) = source_odb
            .read_header(oid)
            .with_context(|| format!("managed child closure omitted object header {oid}"))?;
        if declared_kind != expected_kind {
            bail!("managed child closure object {oid} had an unexpected kind");
        }
        let declared_size = u64::try_from(declared_size)
            .context("managed child closure object size did not fit its byte bound")?;
        aggregate_bytes = aggregate_bytes
            .checked_add(declared_size)
            .context("managed child closure byte count overflow")?;
        if aggregate_bytes > MAX_MANAGED_CHILD_IMPORT_BYTES {
            bail!("managed child closure exceeded its {MAX_MANAGED_CHILD_IMPORT_BYTES}-byte bound");
        }
        let object = source_odb
            .read(oid)
            .with_context(|| format!("managed child closure omitted object {oid}"))?;
        if object.kind() != expected_kind
            || u64::try_from(object.data().len())
                .context("managed child closure object length did not fit its byte bound")?
                != declared_size
        {
            bail!("managed child closure object {oid} changed during fsck");
        }
        if !destination.exists(oid) && !private_only.exists(oid) {
            bail!("managed child closure object {oid} exists outside both verified object stores");
        }
        object_kinds.insert(oid, expected_kind);
        object_bytes.insert(oid, declared_size);

        match expected_kind {
            git2::ObjectType::Commit => {
                let commit = source
                    .find_commit(oid)
                    .with_context(|| format!("managed child closure commit {oid} is malformed"))?;
                pending.push((commit.tree_id(), git2::ObjectType::Tree, 0));
            }
            git2::ObjectType::Tree => {
                if depth > MAX_MANAGED_CHILD_IMPORT_TREE_DEPTH {
                    bail!(
                        "managed child closure exceeded its {MAX_MANAGED_CHILD_IMPORT_TREE_DEPTH}-level tree bound"
                    );
                }
                let tree = source
                    .find_tree(oid)
                    .with_context(|| format!("managed child closure tree {oid} is malformed"))?;
                for entry in tree.iter() {
                    match entry.filemode() {
                        0o160000 => {}
                        0o040000 => pending.push((
                            entry.id(),
                            git2::ObjectType::Tree,
                            depth.saturating_add(1),
                        )),
                        _ => pending.push((entry.id(), git2::ObjectType::Blob, depth)),
                    }
                }
            }
            git2::ObjectType::Blob => {}
            _ => bail!("managed child closure contains an unsupported object kind"),
        }
    }

    Ok(ManagedChildGitClosureSeal {
        base_oid,
        head_oid,
        object_kinds,
        object_bytes,
        touched_paths,
        final_changed_paths,
    })
}

fn managed_child_commit_edge_paths(
    source: &git2::Repository,
    parent: &git2::Commit<'_>,
    child: &git2::Commit<'_>,
) -> Result<Vec<PathBuf>> {
    let parent_tree = parent
        .tree()
        .with_context(|| format!("managed child parent tree {} is missing", parent.tree_id()))?;
    let child_tree = child
        .tree()
        .with_context(|| format!("managed child commit tree {} is missing", child.tree_id()))?;
    let mut options = git2::DiffOptions::new();
    options
        .include_typechange(true)
        .include_typechange_trees(true);
    let diff = source
        .diff_tree_to_tree(Some(&parent_tree), Some(&child_tree), Some(&mut options))
        .context("managed child commit edge diff could not be computed")?;
    let mut paths = BTreeSet::new();
    for delta in diff.deltas() {
        for path in [delta.old_file().path(), delta.new_file().path()]
            .into_iter()
            .flatten()
        {
            paths.insert(
                crate::sync::normalize_repo_relative_path(path)
                    .context("managed child commit edge contains an invalid path")?,
            );
        }
    }
    Ok(paths.into_iter().collect())
}

const MANAGED_CHILD_PRIVATE_GIT_DIR: &str = "maco-private-git-v1";
const MANAGED_CHILD_PRIVATE_REF: &str = "refs/heads/maco-managed-child";

#[cfg(unix)]
fn validate_managed_child_private_ref_surface(private_git_dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    fn validate_exact_directory(path: &Path, label: &str, expected: &[&str]) -> Result<()> {
        let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is missing"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("{label} is not a non-symlink directory");
        }
        let mut observed = BTreeSet::new();
        for entry in fs::read_dir(path).with_context(|| format!("failed to inspect {label}"))? {
            let entry = entry.with_context(|| format!("failed to inspect {label} entry"))?;
            let name = entry.file_name();
            if !expected.iter().any(|expected| name == OsStr::new(expected)) {
                bail!("{label} contains an unexpected private ref entry");
            }
            if !observed.insert(name) {
                bail!("{label} contains a duplicate private ref entry");
            }
        }
        if observed.len() != expected.len() {
            bail!("{label} omitted an expected private ref entry");
        }
        Ok(())
    }

    fn validate_regular_file(path: &Path, label: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is missing"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() > max_bytes
        {
            bail!("{label} is not a bounded single-link regular file");
        }
        fs::read(path).with_context(|| format!("failed to read {label}"))
    }

    for forbidden in [
        "packed-refs",
        "packed-refs.lock",
        "packed-refs.new",
        "HEAD.lock",
    ] {
        match fs::symlink_metadata(private_git_dir.join(forbidden)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).context("failed to inspect managed child private ref surface")
            }
            Ok(_) => {
                bail!("managed child private ref surface contains forbidden packed or lock state")
            }
        }
    }

    let refs = private_git_dir.join("refs");
    validate_exact_directory(
        &refs,
        "managed child private refs directory",
        &["heads", "tags"],
    )?;
    validate_exact_directory(
        &refs.join("heads"),
        "managed child private heads directory",
        &["maco-managed-child"],
    )?;
    validate_exact_directory(
        &refs.join("tags"),
        "managed child private tags directory",
        &[],
    )?;
    let ref_bytes = validate_regular_file(
        &private_git_dir.join(MANAGED_CHILD_PRIVATE_REF),
        "managed child private Git ref",
        1024,
    )?;
    let ref_text = std::str::from_utf8(&ref_bytes)
        .context("managed child private Git ref is not UTF-8")?
        .trim_end_matches(['\r', '\n']);
    Oid::from_str(ref_text).context("managed child private Git ref is not an object id")?;

    let logs = private_git_dir.join("logs");
    match fs::symlink_metadata(&logs) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).context("failed to inspect managed child private reflog surface")
        }
        Ok(_) => {
            validate_exact_directory(
                &logs,
                "managed child private logs directory",
                &["HEAD", "refs"],
            )?;
            validate_regular_file(
                &logs.join("HEAD"),
                "managed child private HEAD reflog",
                4 * 1024 * 1024,
            )?;
            validate_exact_directory(
                &logs.join("refs"),
                "managed child private ref logs directory",
                &["heads"],
            )?;
            validate_exact_directory(
                &logs.join("refs/heads"),
                "managed child private head logs directory",
                &["maco-managed-child"],
            )?;
            validate_regular_file(
                &logs.join(MANAGED_CHILD_PRIVATE_REF),
                "managed child private branch reflog",
                4 * 1024 * 1024,
            )?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_managed_child_private_ref_surface(_private_git_dir: &Path) -> Result<()> {
    bail!("managed child private ref validation is unsupported on this platform")
}

fn read_managed_child_private_ref_oid(private_git_dir: &Path) -> Result<Oid> {
    let ref_bytes =
        read_bounded_regular_file_nofollow(&private_git_dir.join(MANAGED_CHILD_PRIVATE_REF), 1024)
            .context("failed to read managed child private Git ref")?;
    let ref_text = std::str::from_utf8(&ref_bytes)
        .context("managed child private Git ref is not UTF-8")?
        .trim_end_matches(['\r', '\n']);
    Oid::from_str(ref_text).context("managed child private Git ref is not an object id")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectedWorktreeControl {
    absolute: PathBuf,
    protected: ProtectedPathSpec,
    #[cfg(unix)]
    held_file: Option<HeldWorktreeControlFile>,
}

impl ProtectedWorktreeControl {
    fn relative(&self) -> &Path {
        self.protected.coordinate().relative()
    }

    fn retryability(&self) -> SandboxDenialRetryability {
        self.protected.retryability()
    }
}

#[cfg(unix)]
#[derive(Clone)]
struct HeldWorktreeControlFile {
    _file: std::sync::Arc<fs::File>,
    identity: WorktreeControlFileIdentity,
    requires_private_materialization: bool,
}

#[cfg(unix)]
impl PartialEq for HeldWorktreeControlFile {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
            && self.requires_private_materialization == other.requires_private_materialization
    }
}

#[cfg(unix)]
impl Eq for HeldWorktreeControlFile {}

#[cfg(unix)]
impl std::fmt::Debug for HeldWorktreeControlFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeldWorktreeControlFile")
            .field("identity", &self.identity)
            .field(
                "requires_private_materialization",
                &self.requires_private_materialization,
            )
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorktreeControlFileIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlExceptionKind {
    ExistingDirectory,
    ExistingRegularFile,
    AbsentRegularFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlExceptionTarget {
    kind: ControlExceptionKind,
    #[cfg(unix)]
    held_file: Option<HeldWorktreeControlFile>,
}

impl ProtectedWorktreeControls {
    fn iter(&self) -> impl Iterator<Item = &ProtectedWorktreeControl> {
        self.read_only_roots
            .iter()
            .chain(&self.read_only_files)
            .chain(&self.read_write_roots)
            .chain(&self.read_write_files)
    }
}

fn protected_worktree_controls(spec: &ExternalAgentCommand) -> Result<ProtectedWorktreeControls> {
    let mut controls =
        protected_worktree_controls_for(&spec.cwd, &spec.worktree_control_exceptions)?;
    let managed_git_runtime = spec
        .invocation
        .adapter_id()
        .and_then(AdapterId::to_runtime_id);
    let prepare_managed_git = (spec.invocation == ExternalAgentInvocation::CodexSupervisor
        && spec.writable_launch_target == WritableLaunchTarget::ManagedChildWorktree
        && spec.agent_lifecycle.is_some())
        || (spec.workspace_access == WorkspaceAccess::ReadWrite
            && spec.writable_launch_target == WritableLaunchTarget::ManagedChildWorktree
            && spec.agent_lifecycle.is_some()
            && managed_git_runtime.is_some_and(|runtime| {
                spec.verified_writable_capabilities(runtime)
                    .is_ok_and(|capabilities| {
                        capabilities
                            .writable_launch_refusal(spec.writable_launch_target)
                            .is_none()
                    })
            }));
    if prepare_managed_git {
        controls.managed_git = managed_worktree_git_metadata(&spec.cwd)?;
    }
    controls.exact_read_only_input_files = validate_exact_read_only_input_files(spec, &controls)?;
    controls.exact_writable_artifact_files =
        validate_exact_writable_artifact_files(spec, &controls)?;
    controls.writable_artifact_root = Some(validate_artifact_parent_disjoint(spec, &controls)?);
    Ok(controls)
}

fn validate_exact_read_only_input_files(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Result<Vec<PathBuf>> {
    const MAX_EXACT_INPUT_FILES: usize = 16;
    if spec.read_only_input_files.len() > MAX_EXACT_INPUT_FILES {
        bail!("exact read-only input files exceed the fixed limit of {MAX_EXACT_INPUT_FILES}");
    }
    let workspace =
        fs::canonicalize(&spec.cwd).context("external-agent workspace could not be resolved")?;
    let artifact_root = normalized_absolute_path(
        required_parent(&spec.output_last_message)?,
        "external-agent output parent",
    )?;
    let mut validated = BTreeSet::new();
    for declared in &spec.read_only_input_files {
        let normalized = normalized_absolute_path(declared, "exact read-only input file")?;
        ensure_safe_read_target(&normalized)?;
        let canonical = fs::canonicalize(&normalized)
            .context("exact read-only input file could not be resolved")?;
        if canonical != normalized {
            bail!("exact read-only input file must already be canonical");
        }
        let metadata = fs::symlink_metadata(&canonical)
            .context("failed to inspect exact read-only input file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                bail!("exact read-only input file has a hard-link alias");
            }
        }
        if (canonical.starts_with(&workspace) || workspace.starts_with(&canonical))
            && spec.workspace_access == WorkspaceAccess::ReadWrite
        {
            bail!("exact read-only input file overlaps the writable external-agent workspace");
        }
        if canonical.starts_with(&artifact_root) || artifact_root.starts_with(&canonical) {
            bail!("exact read-only input file overlaps writable artifact staging");
        }
        for control in controls.iter() {
            if canonical.starts_with(&control.absolute) || control.absolute.starts_with(&canonical)
            {
                bail!("exact read-only input file overlaps a protected worktree control");
            }
        }
        if let Some(git) = &controls.managed_git {
            for protected in std::iter::once(&git.worktree_git_dir)
                .chain(&git.common_read_only_roots)
                .chain(&git.common_read_only_files)
            {
                if canonical.starts_with(protected) || protected.starts_with(&canonical) {
                    bail!("exact read-only input file overlaps managed Git metadata");
                }
            }
        }
        for hidden in &spec.hidden_roots {
            let hidden = normalized_absolute_path(hidden, "hidden root")?;
            if canonical.starts_with(&hidden) || hidden.starts_with(&canonical) {
                bail!("exact read-only input file overlaps a hidden root");
            }
        }
        if !validated.insert(canonical) {
            bail!("exact read-only input file is declared more than once");
        }
    }
    Ok(validated.into_iter().collect())
}

fn validate_exact_writable_artifact_files(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Result<Vec<ExactWritableArtifactFile>> {
    // Match the process runner's fixed per-class sandbox path bound.
    const MAX_EXACT_WRITABLE_ARTIFACT_FILES: usize = 128;
    if spec.worker_journal_artifacts.len() > MAX_EXACT_WRITABLE_ARTIFACT_FILES {
        bail!(
            "exact writable artifact files exceed the fixed limit of {MAX_EXACT_WRITABLE_ARTIFACT_FILES}"
        );
    }
    let workspace =
        fs::canonicalize(&spec.cwd).context("external-agent workspace could not be resolved")?;
    let incoming_root = normalized_absolute_path(
        required_parent(&spec.output_last_message)?,
        "external-agent incoming report root",
    )?;
    let incoming_root = fs::canonicalize(&incoming_root)
        .context("external-agent incoming report root could not be resolved")?;
    let read_only_inputs = controls
        .exact_read_only_input_files
        .iter()
        .collect::<BTreeSet<_>>();
    let mut paths = BTreeSet::new();
    let mut worker_ids = BTreeSet::new();
    let mut validated = Vec::with_capacity(spec.worker_journal_artifacts.len());
    for declared in &spec.worker_journal_artifacts {
        let worker_id = normalize_agent_id(&declared.worker_id)
            .context("worker journal artifact has an invalid worker id")?;
        if worker_id != declared.worker_id || !worker_ids.insert(worker_id.clone()) {
            bail!("worker journal artifact has a noncanonical or duplicate worker id");
        }
        let declared_root =
            normalized_absolute_path(&declared.incoming_root, "worker journal incoming root")?;
        let declared_root = fs::canonicalize(&declared_root)
            .context("worker journal incoming root could not be resolved")?;
        if declared_root != incoming_root {
            bail!("worker journal artifact is outside the configured incoming report root");
        }
        let expected_parent = incoming_root.join("worker-journals");
        let expected_path = expected_parent.join(format!("{worker_id}.jsonl"));
        let normalized = normalized_absolute_path(&declared.path, "worker journal artifact file")?;
        if normalized != expected_path {
            bail!(
                "worker journal artifact must be the exact worker-journals/<worker-id>.jsonl contract path"
            );
        }
        let canonical = fs::canonicalize(&normalized)
            .context("exact writable artifact file could not be resolved")?;
        if canonical != normalized {
            bail!("exact writable artifact file must already be canonical");
        }
        if !paths.insert(canonical.clone()) {
            bail!("exact writable artifact file is declared more than once");
        }
        let metadata = fs::symlink_metadata(&canonical)
            .context("failed to inspect exact writable artifact file")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("exact writable artifact file must be a non-symlink regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            if metadata.uid() != effective_uid
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                bail!(
                    "exact writable artifact file must be current-user-owned, mode 0600, and single-link"
                );
            }
            let parent = canonical
                .parent()
                .context("exact writable artifact file has no parent")?;
            let parent_metadata = fs::symlink_metadata(parent)
                .context("failed to inspect exact writable artifact parent")?;
            if parent_metadata.file_type().is_symlink()
                || !parent_metadata.is_dir()
                || parent_metadata.uid() != effective_uid
                || parent_metadata.permissions().mode() & 0o777 != 0o700
            {
                bail!(
                    "exact writable artifact parent must be a current-user-owned non-symlink 0700 directory"
                );
            }
        }
        if canonical.starts_with(&workspace) || workspace.starts_with(&canonical) {
            bail!("exact writable artifact file overlaps the external-agent workspace");
        }
        if read_only_inputs.contains(&canonical) {
            bail!("exact writable artifact file is also declared read-only");
        }
        for control in controls.iter() {
            if canonical.starts_with(&control.absolute) || control.absolute.starts_with(&canonical)
            {
                bail!("exact writable artifact file overlaps a protected worktree control");
            }
        }
        if let Some(git) = &controls.managed_git {
            for protected in std::iter::once(&git.worktree_git_dir)
                .chain(&git.common_read_only_roots)
                .chain(&git.common_read_only_files)
            {
                if canonical.starts_with(protected) || protected.starts_with(&canonical) {
                    bail!("exact writable artifact file overlaps managed Git metadata");
                }
            }
        }
        for hidden in &spec.hidden_roots {
            let hidden = normalized_absolute_path(hidden, "hidden root")?;
            if canonical.starts_with(&hidden) || hidden.starts_with(&canonical) {
                bail!("exact writable artifact file overlaps a hidden root");
            }
        }

        #[cfg(target_os = "linux")]
        let (held_file, identity) = {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
            let file = options
                .open(&canonical)
                .context("failed to hold exact writable artifact file")?;
            let held_metadata = file.metadata()?;
            let identity = ExactWritableArtifactIdentity {
                device: held_metadata.dev(),
                inode: held_metadata.ino(),
                owner: held_metadata.uid(),
                mode: held_metadata.mode() & 0o7777,
                links: held_metadata.nlink(),
            };
            let inspected_identity = ExactWritableArtifactIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
                owner: metadata.uid(),
                mode: metadata.mode() & 0o7777,
                links: metadata.nlink(),
            };
            validate_exact_writable_artifact_identity(identity)?;
            if identity != inspected_identity {
                bail!("exact writable artifact file identity changed during validation");
            }
            (std::sync::Arc::new(file), identity)
        };
        validated.push(ExactWritableArtifactFile {
            worker_id,
            path: canonical,
            #[cfg(target_os = "linux")]
            held_file,
            #[cfg(target_os = "linux")]
            identity,
        });
    }
    validated.sort_by(|left, right| left.path.cmp(&right.path));
    #[cfg(target_os = "linux")]
    if !validated.is_empty() {
        validate_codex_writable_artifact_carrier(&incoming_root, &validated)?;
    }
    Ok(validated)
}

#[cfg(target_os = "linux")]
fn validate_codex_writable_artifact_carrier(
    incoming_root: &Path,
    artifacts: &[ExactWritableArtifactFile],
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let carrier = incoming_root.join("worker-journals");
    let expected_files = artifacts
        .iter()
        .map(|artifact| {
            artifact
                .path
                .file_name()
                .map(OsStr::to_os_string)
                .context("exact writable artifact has no file name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected_mount_targets = CODEX_WRITABLE_ROOT_PROTECTED_MOUNT_TARGETS
        .iter()
        .map(OsString::from)
        .collect::<BTreeSet<_>>();
    let mut seen_files = BTreeSet::new();
    let mut seen_mount_targets = BTreeSet::new();
    // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    for entry in fs::read_dir(&carrier)
        .context("failed to inspect the private Codex worker-journal carrier")?
    {
        let entry = entry.context("failed to enumerate the private worker-journal carrier")?;
        let name = entry.file_name();
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .context("failed to inspect a private worker-journal carrier entry")?;
        if expected_files.contains(&name) {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("worker-journal carrier contains a non-regular journal entry");
            }
            seen_files.insert(name);
            continue;
        }
        if expected_mount_targets.contains(&name) {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != effective_uid
                || metadata.permissions().mode() & 0o777 != 0o700
            {
                bail!(
                    "Codex protected mount target must be a current-user-owned non-symlink 0700 directory"
                );
            }
            if fs::read_dir(&path)
                .with_context(|| {
                    format!(
                        "failed to inspect protected mount target {}",
                        path.display()
                    )
                })?
                .next()
                .is_some()
            {
                bail!("Codex protected mount target must be empty before launch");
            }
            seen_mount_targets.insert(name);
            continue;
        }
        bail!(
            "worker-journal carrier contains an undeclared entry: {}",
            path.display()
        );
    }
    if seen_files != expected_files {
        bail!("worker-journal carrier is missing a declared exact journal file");
    }
    if seen_mount_targets != expected_mount_targets {
        bail!("worker-journal carrier is missing a required Codex protected mount target");
    }
    Ok(())
}

fn capture_worker_journal_artifacts(
    controls: &ProtectedWorktreeControls,
    process_quiescent: bool,
) -> Vec<WorkerJournalArtifactCapture> {
    controls
        .exact_writable_artifact_files
        .iter()
        .map(|artifact| {
            let status = if !process_quiescent {
                WorkerJournalArtifactCaptureStatus::Invalid(
                    "worker journal was not read because external process quiescence was not verified"
                        .to_string(),
                )
            } else {
                match capture_worker_journal_artifact(artifact) {
                    Ok(bytes) => WorkerJournalArtifactCaptureStatus::Loaded(bytes),
                    Err(error) => WorkerJournalArtifactCaptureStatus::Invalid(format!(
                        "failed trusted worker journal capture after verified quiescence: {error:#}"
                    )),
                }
            };
            WorkerJournalArtifactCapture {
                worker_id: artifact.worker_id.clone(),
                path: artifact.path.clone(),
                status,
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn capture_worker_journal_artifact(artifact: &ExactWritableArtifactFile) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;

    let held_before = exact_writable_artifact_identity(&artifact.held_file.metadata()?)?;
    let path_before = exact_writable_artifact_identity(
        &fs::symlink_metadata(&artifact.path)
            .context("worker journal path could not be revalidated")?,
    )?;
    validate_exact_writable_artifact_identity(held_before)?;
    if held_before != artifact.identity || path_before != artifact.identity {
        bail!("worker journal path or held descriptor identity changed after launch");
    }
    let length = usize::try_from(artifact.held_file.metadata()?.len())
        .context("worker journal length does not fit this platform")?;
    if length > MAX_WORKER_JOURNAL_ARTIFACT_BYTES {
        bail!(
            "worker journal exceeds the bounded {} byte capture limit",
            MAX_WORKER_JOURNAL_ARTIFACT_BYTES
        );
    }
    let mut bytes = vec![0_u8; length];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let read = artifact
            .held_file
            .read_at(&mut bytes[offset..], offset as u64)
            .context("failed to read held worker journal descriptor")?;
        if read == 0 {
            bail!("held worker journal shrank during bounded capture");
        }
        offset = offset.saturating_add(read);
    }
    let held_after_metadata = artifact.held_file.metadata()?;
    let held_after = exact_writable_artifact_identity(&held_after_metadata)?;
    let path_after = exact_writable_artifact_identity(
        &fs::symlink_metadata(&artifact.path)
            .context("worker journal path disappeared during bounded capture")?,
    )?;
    if held_after != artifact.identity
        || path_after != artifact.identity
        || usize::try_from(held_after_metadata.len()).ok() != Some(length)
    {
        bail!("worker journal identity or length changed during bounded capture");
    }
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn capture_worker_journal_artifact(_artifact: &ExactWritableArtifactFile) -> Result<Vec<u8>> {
    bail!("trusted held worker journal capture is unavailable on this platform")
}

#[cfg(target_os = "linux")]
fn exact_writable_artifact_identity(
    metadata: &fs::Metadata,
) -> Result<ExactWritableArtifactIdentity> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file() {
        bail!("worker journal artifact is not a regular file");
    }
    Ok(ExactWritableArtifactIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        links: metadata.nlink(),
    })
}

#[cfg(target_os = "linux")]
fn validate_exact_writable_artifact_identity(
    identity: ExactWritableArtifactIdentity,
) -> Result<()> {
    // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if identity.owner != effective_uid || identity.mode != 0o600 || identity.links != 1 {
        bail!(
            "worker journal held descriptor must remain current-user-owned, mode 0600, and single-link"
        );
    }
    Ok(())
}

fn managed_worktree_git_metadata(workspace: &Path) -> Result<Option<ManagedWorktreeGitMetadata>> {
    managed_worktree_git_metadata_with_mode(workspace, true)
}

fn managed_worktree_git_metadata_with_mode(
    workspace: &Path,
    prepare_private_storage: bool,
) -> Result<Option<ManagedWorktreeGitMetadata>> {
    let marker = workspace.join(".git");
    let marker_metadata = fs::symlink_metadata(&marker)
        .context("managed child worktree is missing its .git marker")?;
    if marker_metadata.file_type().is_symlink() {
        bail!("managed child worktree .git marker may not be a symlink");
    }
    if marker_metadata.is_dir() {
        return Ok(None);
    }
    if !marker_metadata.is_file() {
        bail!("managed child worktree .git marker is not a regular file");
    }
    #[cfg(unix)]
    let marker_has_hard_link_alias = {
        use std::os::unix::fs::MetadataExt;
        marker_metadata.nlink() != 1
    };
    #[cfg(unix)]
    if marker_has_hard_link_alias {
        bail!("managed child worktree .git marker has a hard-link alias");
    }

    let canonical_workspace =
        fs::canonicalize(workspace).context("managed child worktree root could not be resolved")?;
    let marker_target = parse_git_path_file(&marker, Some("gitdir: "), "worktree .git marker")?;
    let worktree_git_dir = canonicalize_git_path(&canonical_workspace, &marker_target)
        .context("managed child worktree .git marker target could not be resolved")?;
    let repository = crate::git_repository::open(&canonical_workspace)
        .map_err(|_| anyhow::anyhow!("managed child worktree could not be opened by libgit2"))?;
    let repository_workdir = repository
        .workdir()
        .context("managed child Git repository has no worktree")?;
    let repository_workdir = fs::canonicalize(repository_workdir)
        .context("managed child Git worktree could not be resolved")?;
    let repository_git_dir = fs::canonicalize(repository.path())
        .context("managed child Git directory could not be resolved")?;
    let common_dir = fs::canonicalize(repository.commondir())
        .context("managed child Git common directory could not be resolved")?;
    if repository_workdir != canonical_workspace || repository_git_dir != worktree_git_dir {
        bail!("managed child .git marker does not match the libgit2 repository binding");
    }

    let commondir_target = parse_git_path_file(
        &worktree_git_dir.join("commondir"),
        None,
        "linked-worktree commondir",
    )?;
    let marker_common_dir = canonicalize_git_path(&worktree_git_dir, &commondir_target)
        .context("linked-worktree commondir target could not be resolved")?;
    if marker_common_dir != common_dir {
        bail!("linked-worktree commondir does not match the libgit2 common directory");
    }
    let expected_worktrees_root = common_dir.join("worktrees");
    if worktree_git_dir.parent() != Some(expected_worktrees_root.as_path()) {
        bail!(
            "managed child Git directory is not an exact child of the common worktrees directory"
        );
    }

    let backlink_target = parse_git_path_file(
        &worktree_git_dir.join("gitdir"),
        None,
        "linked-worktree backlink",
    )?;
    let backlink = canonicalize_git_path(&worktree_git_dir, &backlink_target)
        .context("linked-worktree backlink target could not be resolved")?;
    let canonical_marker = fs::canonicalize(&marker)
        .context("managed child worktree .git marker could not be rebound")?;
    if backlink != canonical_marker {
        bail!("linked-worktree backlink does not name the managed child .git marker");
    }

    let objects = canonical_git_directory(&common_dir.join("objects"), "Git object directory")?;
    reject_git_object_aliases(&objects)?;
    let refs = canonical_git_directory(&common_dir.join("refs"), "Git refs directory")?;
    reject_git_read_only_tree_aliases(&refs, "Git refs")?;
    let config = canonical_git_file(&common_dir.join("config"), "Git common config")?;
    reject_managed_git_hooks_path(&config, "Git common config")?;
    if let Some(worktree_config) = canonical_optional_git_file(
        &worktree_git_dir.join("config.worktree"),
        "Git worktree config",
    )? {
        reject_managed_git_hooks_path(&worktree_config, "Git worktree config")?;
    }
    let mut common_read_only_files = vec![config.clone()];
    let active_commit_hook = canonical_optional_active_git_hook(
        &common_dir.join("hooks/commit-msg"),
        "Git commit-msg hook",
    )?;
    if let Some(commit_msg_hook) = &active_commit_hook {
        common_read_only_files.push(commit_msg_hook.clone());
    }
    for (relative, label) in [
        ("packed-refs", "Git packed refs"),
        ("info/exclude", "Git exclude file"),
        ("shallow", "Git shallow boundary"),
    ] {
        if let Some(file) = canonical_optional_git_file(&common_dir.join(relative), label)? {
            common_read_only_files.push(file);
        }
    }
    common_read_only_files.sort();
    common_read_only_files.dedup();
    let mut common_read_only_roots = vec![objects, refs];
    common_read_only_roots.sort();
    common_read_only_roots.dedup();

    for read_only in common_read_only_roots
        .iter()
        .chain(common_read_only_files.iter())
    {
        if read_only.starts_with(&worktree_git_dir) || worktree_git_dir.starts_with(read_only) {
            bail!("managed child writable Git metadata overlaps common read-only metadata");
        }
    }
    for forbidden in [
        common_dir.join("HEAD"),
        common_dir.join("index"),
        common_dir.join("maco"),
        expected_worktrees_root,
    ] {
        if common_read_only_roots
            .iter()
            .chain(common_read_only_files.iter())
            .any(|allowed| allowed == &forbidden || allowed.starts_with(&forbidden))
        {
            bail!("managed child Git metadata allowlist includes private common metadata");
        }
    }

    let base_oid = repository
        .head()
        .context("managed child Git repository has no HEAD")?
        .peel_to_commit()
        .context("managed child Git HEAD is not a commit")?
        .id();
    let private_git_dir = prepare_managed_child_private_git_dir(
        &canonical_workspace,
        &worktree_git_dir,
        &config,
        base_oid,
        prepare_private_storage,
    )?;
    let private_object_dir = canonical_git_directory(
        &private_git_dir.join("objects"),
        "managed child private Git object directory",
    )?;
    if private_git_dir.starts_with(&common_dir) && !private_git_dir.starts_with(&worktree_git_dir) {
        bail!("managed child private Git directory escaped its per-worktree Git directory");
    }
    for read_only in common_read_only_roots
        .iter()
        .chain(common_read_only_files.iter())
    {
        if private_git_dir.starts_with(read_only) || read_only.starts_with(&private_git_dir) {
            bail!("managed child private Git directory overlaps shared read-only metadata");
        }
    }

    let fixed_private_read_only_files =
        vec![private_git_dir.join("HEAD"), private_git_dir.join("config")];
    Ok(Some(ManagedWorktreeGitMetadata {
        worktree_git_dir,
        private_git_dir,
        private_object_dir,
        shared_object_dir: common_dir.join("objects"),
        common_config: config,
        active_commit_hook,
        fixed_private_read_only_files,
        common_read_only_roots,
        common_read_only_files,
    }))
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ManagedChildProjectedIdentity {
    user_name: Option<String>,
    user_email: Option<String>,
    approved_name: Option<String>,
    approved_email: Option<String>,
    approved_login: Option<String>,
}

fn managed_child_private_config(common_config: &[u8], filemode: &str) -> Result<Vec<u8>> {
    let identity = parse_managed_child_projected_identity(common_config)?;
    let mut config = format!(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tfilemode = {filemode}\n\tlogallrefupdates = true\n"
    );
    if let (Some(name), Some(email)) = (&identity.user_name, &identity.user_email) {
        config.push_str("[user]\n\tname = \"");
        config.push_str(&escape_managed_child_config_value(name));
        config.push_str("\"\n\temail = \"");
        config.push_str(&escape_managed_child_config_value(email));
        config.push_str("\"\n");
    }
    if let (Some(name), Some(email), Some(login)) = (
        &identity.approved_name,
        &identity.approved_email,
        &identity.approved_login,
    ) {
        config.push_str("[agentFiles]\n\tapprovedGitAuthorName = \"");
        config.push_str(&escape_managed_child_config_value(name));
        config.push_str("\"\n\tapprovedGitAuthorEmail = \"");
        config.push_str(&escape_managed_child_config_value(email));
        config.push_str("\"\n\tapprovedGitHubLogin = \"");
        config.push_str(&escape_managed_child_config_value(login));
        config.push_str("\"\n");
    }
    config.push_str("[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n");
    Ok(config.into_bytes())
}

fn escape_managed_child_config_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn parse_managed_child_projected_identity(bytes: &[u8]) -> Result<ManagedChildProjectedIdentity> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Section {
        User,
        AgentFiles,
        Other,
    }

    fn set_once(slot: &mut Option<String>, value: String, key: &str) -> Result<()> {
        if slot.replace(value).is_some() {
            bail!("repository-local {key} must appear at most once");
        }
        Ok(())
    }

    let mut projected = ManagedChildProjectedIdentity::default();
    let mut section = Section::Other;
    for raw_line in bytes.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let line = raw_line.trim_ascii();
        if line.is_empty() || matches!(line.first(), Some(b'#' | b';')) {
            continue;
        }
        if line.first() == Some(&b'[') {
            let close = line
                .iter()
                .position(|byte| *byte == b']')
                .context("repository-local Git config contains a malformed section")?;
            let name = line[1..close].trim_ascii();
            section = if name.eq_ignore_ascii_case(b"user") {
                Section::User
            } else if name.eq_ignore_ascii_case(b"agentFiles") {
                Section::AgentFiles
            } else {
                Section::Other
            };
            continue;
        }
        if section == Section::Other {
            continue;
        }
        let key_end = line
            .iter()
            .position(|byte| byte.is_ascii_whitespace() || *byte == b'=')
            .unwrap_or(line.len());
        let key = &line[..key_end];
        let recognized = match section {
            Section::User => {
                key.eq_ignore_ascii_case(b"name") || key.eq_ignore_ascii_case(b"email")
            }
            Section::AgentFiles => {
                key.eq_ignore_ascii_case(b"approvedGitAuthorName")
                    || key.eq_ignore_ascii_case(b"approvedGitAuthorEmail")
                    || key.eq_ignore_ascii_case(b"approvedGitHubLogin")
            }
            Section::Other => false,
        };
        if !recognized {
            continue;
        }
        let rest = line[key_end..].trim_ascii();
        let raw_value = rest
            .strip_prefix(b"=")
            .context("projected repository-local Git config entry must use an explicit value")?
            .trim_ascii();
        let value = decode_managed_child_config_value(raw_value)?;
        let key_label =
            std::str::from_utf8(key).context("projected Git config key is not ASCII")?;
        match section {
            Section::User if key.eq_ignore_ascii_case(b"name") => {
                set_once(&mut projected.user_name, value, "user.name")?
            }
            Section::User => set_once(&mut projected.user_email, value, "user.email")?,
            Section::AgentFiles if key.eq_ignore_ascii_case(b"approvedGitAuthorName") => {
                set_once(&mut projected.approved_name, value, key_label)?
            }
            Section::AgentFiles if key.eq_ignore_ascii_case(b"approvedGitAuthorEmail") => {
                set_once(&mut projected.approved_email, value, key_label)?
            }
            Section::AgentFiles => set_once(&mut projected.approved_login, value, key_label)?,
            Section::Other => {}
        }
    }

    let user_count =
        usize::from(projected.user_name.is_some()) + usize::from(projected.user_email.is_some());
    if user_count == 1 {
        bail!("repository-local user identity must contain both name and email");
    }
    let approved_count = usize::from(projected.approved_name.is_some())
        + usize::from(projected.approved_email.is_some())
        + usize::from(projected.approved_login.is_some());
    if approved_count != 0 && approved_count != 3 {
        bail!("repository-local approved identity must contain its exact three-value tuple");
    }
    if approved_count == 3
        && (projected.user_name != projected.approved_name
            || projected.user_email != projected.approved_email)
    {
        bail!("repository-local user identity does not match the approved identity tuple");
    }
    Ok(projected)
}

fn decode_managed_child_config_value(raw: &[u8]) -> Result<String> {
    let raw = std::str::from_utf8(raw).context("projected Git config value is not UTF-8")?;
    let value = if let Some(quoted) = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        let mut decoded = String::new();
        let mut escaped = false;
        for character in quoted.chars() {
            if escaped {
                match character {
                    '\\' | '"' => decoded.push(character),
                    _ => bail!("projected Git config value contains an unsupported escape"),
                }
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else {
                decoded.push(character);
            }
        }
        if escaped {
            bail!("projected Git config value ends with an incomplete escape");
        }
        decoded
    } else {
        raw.to_string()
    };
    if value.is_empty()
        || value.len() > 1024
        || value.chars().any(char::is_control)
        || value.contains(['#', ';'])
    {
        bail!("projected Git config value is empty, oversized, or contains unsafe syntax");
    }
    Ok(value)
}

#[cfg(unix)]
fn prepare_managed_child_private_git_dir(
    workspace: &Path,
    worktree_git_dir: &Path,
    common_config: &Path,
    base_oid: Oid,
    create_if_missing: bool,
) -> Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    fn create_private_directory(path: &Path) -> Result<()> {
        fs::create_dir(path).with_context(|| {
            format!("failed to create private Git directory {}", path.display())
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to harden private Git directory {}", path.display()))
    }

    fn create_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to create private Git file {}", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write private Git file {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync private Git file {}", path.display()))
    }

    fn validate_private_regular_file(path: &Path, label: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is missing"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() > max_bytes
        {
            bail!("{label} is not a bounded single-link regular file");
        }
        fs::read(path).with_context(|| format!("failed to read {label}"))
    }

    let common_config_bytes = read_bounded_regular_file_nofollow(common_config, 1024 * 1024)
        .context("failed to read managed child common Git config")?;
    let common_policy =
        crate::worktree::parse_bounded_local_git_config(Some(&common_config_bytes))?;
    let filemode = if common_policy.core_filemode {
        "true"
    } else {
        "false"
    };
    let expected_config = managed_child_private_config(&common_config_bytes, filemode)?;
    let private_git_dir = worktree_git_dir.join(MANAGED_CHILD_PRIVATE_GIT_DIR);
    match fs::symlink_metadata(&private_git_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create_if_missing => {
            bail!("managed child private Git directory is missing at collection time")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(&private_git_dir)?;
            for relative in [
                "objects",
                "objects/info",
                "objects/pack",
                "refs",
                "refs/heads",
                "refs/tags",
            ] {
                create_private_directory(&private_git_dir.join(relative))?;
            }
            let source_index = canonical_git_file(
                &worktree_git_dir.join("index"),
                "managed child linked-worktree index",
            )?;
            let index_bytes = read_bounded_regular_file_nofollow(&source_index, 16 * 1024 * 1024)
                .context("failed to read managed child linked-worktree index")?;
            create_private_file(&private_git_dir.join("index"), &index_bytes)?;
            create_private_file(
                &private_git_dir.join("HEAD"),
                format!("ref: {MANAGED_CHILD_PRIVATE_REF}\n").as_bytes(),
            )?;
            create_private_file(
                &private_git_dir.join(MANAGED_CHILD_PRIVATE_REF),
                format!("{base_oid}\n").as_bytes(),
            )?;
            create_private_file(&private_git_dir.join("config"), &expected_config)?;
        }
        Err(error) => {
            return Err(error).context("failed to inspect managed child private Git directory")
        }
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("managed child private Git path is not a non-symlink directory")
        }
        Ok(_) => {}
    }

    let private_git_dir = fs::canonicalize(&private_git_dir)
        .context("managed child private Git directory could not be resolved")?;
    if private_git_dir.parent() != Some(worktree_git_dir) {
        bail!("managed child private Git directory is not an exact child of its worktree Git directory");
    }
    let metadata = fs::symlink_metadata(&private_git_dir)
        .context("failed to rebind managed child private Git directory")?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        bail!("managed child private Git directory is not owner-private");
    }
    reject_git_read_only_tree_aliases(&private_git_dir, "private Git storage")?;
    for alternate in ["objects/info/alternates", "objects/info/http-alternates"] {
        if fs::symlink_metadata(private_git_dir.join(alternate)).is_ok() {
            bail!("managed child private Git storage contains a persistent object alternate");
        }
    }
    validate_managed_child_private_ref_surface(&private_git_dir)?;
    let expected_head = format!("ref: {MANAGED_CHILD_PRIVATE_REF}\n").into_bytes();
    if validate_private_regular_file(
        &private_git_dir.join("HEAD"),
        "managed child private Git HEAD",
        1024,
    )? != expected_head
    {
        bail!("managed child private Git HEAD changed from its fixed private ref");
    }
    let ref_bytes = validate_private_regular_file(
        &private_git_dir.join(MANAGED_CHILD_PRIVATE_REF),
        "managed child private Git ref",
        1024,
    )?;
    let ref_text = std::str::from_utf8(&ref_bytes)
        .context("managed child private Git ref is not UTF-8")?
        .trim_end_matches(['\r', '\n']);
    Oid::from_str(ref_text).context("managed child private Git ref is not an object id")?;
    if validate_private_regular_file(
        &private_git_dir.join("config"),
        "managed child private Git config",
        16 * 1024,
    )? != expected_config
    {
        bail!("managed child private Git config changed from its fixed policy");
    }
    validate_private_regular_file(
        &private_git_dir.join("index"),
        "managed child private Git index",
        16 * 1024 * 1024,
    )?;
    let canonical_workspace = fs::canonicalize(workspace)
        .context("managed child workspace changed during private Git setup")?;
    if canonical_workspace != workspace {
        bail!("managed child workspace must remain canonical during private Git setup");
    }
    Ok(private_git_dir)
}

#[cfg(not(unix))]
fn prepare_managed_child_private_git_dir(
    _workspace: &Path,
    _worktree_git_dir: &Path,
    _common_config: &Path,
    _base_oid: Oid,
    _create_if_missing: bool,
) -> Result<PathBuf> {
    bail!("managed child private Git storage is unsupported on this platform")
}

fn managed_git_environment(git: &ManagedWorktreeGitMetadata) -> Result<BTreeMap<String, String>> {
    let mut environment = BTreeMap::from([
        (
            "GIT_DIR".to_string(),
            git.private_git_dir
                .to_str()
                .context("managed child private Git directory is not UTF-8")?
                .to_string(),
        ),
        (
            "GIT_OBJECT_DIRECTORY".to_string(),
            git.private_object_dir
                .to_str()
                .context("managed child private object directory is not UTF-8")?
                .to_string(),
        ),
        (
            "GIT_ALTERNATE_OBJECT_DIRECTORIES".to_string(),
            git.shared_object_dir
                .to_str()
                .context("managed child shared object directory is not UTF-8")?
                .to_string(),
        ),
        ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
    ]);
    let mut config_entries = Vec::new();
    if let Some(hook) = &git.active_commit_hook {
        config_entries.push((
            "core.hooksPath",
            hook.parent()
                .context("managed child commit hook has no parent")?,
        ));
    }
    config_entries.push(("gc.auto", Path::new("0")));
    config_entries.push(("maintenance.auto", Path::new("false")));
    environment.insert(
        "GIT_CONFIG_COUNT".to_string(),
        config_entries.len().to_string(),
    );
    for (index, (key, value)) in config_entries.into_iter().enumerate() {
        environment.insert(format!("GIT_CONFIG_KEY_{index}"), key.to_string());
        environment.insert(
            format!("GIT_CONFIG_VALUE_{index}"),
            value
                .to_str()
                .context("managed child Git config input is not UTF-8")?
                .to_string(),
        );
    }
    Ok(environment)
}

#[cfg(unix)]
fn verify_managed_git_boundary_after_launch(git: &ManagedWorktreeGitMetadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let worktree_git_dir = fs::canonicalize(&git.worktree_git_dir)
        .context("managed child linked-worktree Git directory disappeared after launch")?;
    if worktree_git_dir != git.worktree_git_dir {
        bail!("managed child linked-worktree Git directory changed after launch");
    }
    let private_git_dir = fs::canonicalize(&git.private_git_dir)
        .context("managed child private Git directory disappeared after launch")?;
    if private_git_dir != git.private_git_dir
        || private_git_dir.parent() != Some(git.worktree_git_dir.as_path())
    {
        bail!("managed child private Git directory changed after launch");
    }
    let metadata = fs::symlink_metadata(&private_git_dir)
        .context("failed to inspect managed child private Git directory after launch")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!("managed child private Git directory lost its owner-private binding after launch");
    }
    reject_git_read_only_tree_aliases(&private_git_dir, "private Git storage")?;
    for alternate in ["objects/info/alternates", "objects/info/http-alternates"] {
        if fs::symlink_metadata(private_git_dir.join(alternate)).is_ok() {
            bail!("managed child private Git storage gained a persistent object alternate");
        }
    }
    validate_managed_child_private_ref_surface(&private_git_dir)?;
    let head = read_bounded_regular_file_nofollow(&private_git_dir.join("HEAD"), 1024)
        .context("failed to revalidate managed child private Git HEAD")?;
    if head != format!("ref: {MANAGED_CHILD_PRIVATE_REF}\n").as_bytes() {
        bail!("managed child private Git HEAD changed from its fixed private ref after launch");
    }
    let ref_bytes =
        read_bounded_regular_file_nofollow(&private_git_dir.join(MANAGED_CHILD_PRIVATE_REF), 1024)
            .context("failed to revalidate managed child private Git ref")?;
    let ref_text = std::str::from_utf8(&ref_bytes)
        .context("managed child private Git ref is not UTF-8 after launch")?
        .trim_end_matches(['\r', '\n']);
    Oid::from_str(ref_text)
        .context("managed child private Git ref is not an object id after launch")?;
    let common_config = canonical_git_file(&git.common_config, "Git common config")?;
    if common_config != git.common_config {
        bail!("managed child common Git config changed after launch");
    }
    let common_policy = crate::worktree::parse_bounded_local_git_config(Some(
        &read_bounded_regular_file_nofollow(&common_config, 1024 * 1024)
            .context("failed to re-read managed child common Git config")?,
    ))?;
    let filemode = if common_policy.core_filemode {
        "true"
    } else {
        "false"
    };
    let common_config_bytes = read_bounded_regular_file_nofollow(&common_config, 1024 * 1024)
        .context("failed to re-read managed child common Git config")?;
    let expected_config = managed_child_private_config(&common_config_bytes, filemode)?;
    let private_config =
        read_bounded_regular_file_nofollow(&private_git_dir.join("config"), 16 * 1024)
            .context("failed to revalidate managed child private Git config")?;
    if private_config != expected_config {
        bail!("managed child private Git config changed from its fixed policy after launch");
    }
    let private_object_dir = fs::canonicalize(&git.private_object_dir)
        .context("managed child private object directory disappeared after launch")?;
    if private_object_dir != git.private_object_dir
        || private_object_dir.parent() != Some(git.private_git_dir.as_path())
    {
        bail!("managed child private object directory changed after launch");
    }
    let shared_object_dir = fs::canonicalize(&git.shared_object_dir)
        .context("managed child shared object directory disappeared after launch")?;
    if shared_object_dir != git.shared_object_dir {
        bail!("managed child shared object directory changed after launch");
    }
    reject_git_object_aliases(&shared_object_dir)?;
    if let Some(hook) = &git.active_commit_hook {
        let rebound = canonical_optional_active_git_hook(hook, "Git commit-msg hook")?
            .context("managed child active commit-msg hook disappeared after launch")?;
        if rebound != *hook {
            bail!("managed child active commit-msg hook changed after launch");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_managed_git_boundary_after_launch(_git: &ManagedWorktreeGitMetadata) -> Result<()> {
    bail!("managed child private Git revalidation is unsupported on this platform")
}

fn parse_git_path_file(path: &Path, prefix: Option<&str>, label: &str) -> Result<PathBuf> {
    const MAX_GIT_PATH_FILE_BYTES: u64 = 16 * 1024;
    let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is missing"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_GIT_PATH_FILE_BYTES
    {
        bail!("{label} is not a bounded regular file");
    }
    #[cfg(unix)]
    let path_file_has_hard_link_alias = {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() != 1
    };
    #[cfg(unix)]
    if path_file_has_hard_link_alias {
        bail!("{label} has a hard-link alias");
    }
    let bytes = fs::read(path).with_context(|| format!("failed to read {label}"))?;
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    let value = match prefix {
        Some(prefix) => text
            .strip_prefix(prefix)
            .with_context(|| format!("{label} has an invalid prefix"))?,
        None => text,
    };
    if value.is_empty() || value.chars().any(char::is_control) {
        bail!("{label} contains an invalid path");
    }
    Ok(PathBuf::from(value))
}

fn canonicalize_git_path(base: &Path, value: &Path) -> std::io::Result<PathBuf> {
    if value.is_absolute() {
        fs::canonicalize(value)
    } else {
        fs::canonicalize(base.join(value))
    }
}

fn canonical_git_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is missing"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{label} is not a non-symlink directory");
    }
    fs::canonicalize(path).with_context(|| format!("{label} could not be resolved"))
}

fn canonical_git_file(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("{label} is missing"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} is not a non-symlink regular file");
    }
    #[cfg(unix)]
    let common_file_has_hard_link_alias = {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() != 1
    };
    #[cfg(unix)]
    if common_file_has_hard_link_alias {
        bail!(
            "{label} has a hard-link alias; recreate the launch repository with --no-hardlinks before retrying"
        );
    }
    fs::canonicalize(path).with_context(|| format!("{label} could not be resolved"))
}

fn canonical_optional_git_file(path: &Path, label: &str) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {label}")),
        Ok(_) => canonical_git_file(path, label).map(Some),
    }
}

fn reject_managed_git_hooks_path(config: &Path, label: &str) -> Result<()> {
    const MAX_MANAGED_GIT_CONFIG_BYTES: usize = 1024 * 1024;
    let bytes = read_bounded_regular_file_nofollow(config, MAX_MANAGED_GIT_CONFIG_BYTES)
        .with_context(|| format!("failed to read bounded {label}"))?;
    let policy = crate::worktree::parse_bounded_local_git_config(Some(&bytes))?;
    if policy.core_hooks_path_present {
        bail!(
            "managed child Git commits require repository-local core.hooksPath to be absent; remove the custom hook path and install the commit-msg hook in the default Git hooks directory"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn canonical_optional_active_git_hook(path: &Path, label: &str) -> Result<Option<PathBuf>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("failed to inspect {label}")),
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} is not a non-symlink regular file");
    }
    if metadata.nlink() != 1 {
        bail!("{label} has a hard-link alias; reinstall the repository hook before retrying");
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Ok(None);
    }
    fs::canonicalize(path)
        .map(Some)
        .with_context(|| format!("{label} could not be resolved"))
}

#[cfg(not(unix))]
fn canonical_optional_active_git_hook(_path: &Path, _label: &str) -> Result<Option<PathBuf>> {
    bail!("managed child Git hook validation is unsupported on this platform")
}

#[cfg(unix)]
fn reject_git_object_aliases(objects: &Path) -> Result<()> {
    for alternate in ["info/alternates", "info/http-alternates"] {
        match fs::symlink_metadata(objects.join(alternate)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("failed to inspect Git object alternates"),
            Ok(_) => bail!(
                "managed child Git object alternates are unsupported; recreate the launch repository without --reference before retrying"
            ),
        }
    }

    reject_git_read_only_tree_aliases(objects, "Git object storage")
}

#[cfg(unix)]
fn reject_git_read_only_tree_aliases(root: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    const MAX_GIT_METADATA_ENTRIES: usize = 200_000;
    let mut remaining = MAX_GIT_METADATA_ENTRIES;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries =
            fs::read_dir(&directory).with_context(|| format!("failed to inspect {label}"))?;
        for entry in entries {
            if remaining == 0 {
                bail!(
                    "managed child {label} alias inspection exceeded its {MAX_GIT_METADATA_ENTRIES}-entry safety bound"
                );
            }
            remaining -= 1;
            let entry = entry.with_context(|| format!("failed to inspect {label} entry"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .with_context(|| format!("failed to inspect {label} entry type"))?;
            if metadata.file_type().is_symlink() {
                bail!("managed child {label} contains a symlink alias");
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                if metadata.nlink() != 1 {
                    bail!(
                        "managed child {label} contains hard-link aliases; recreate the launch repository with --no-hardlinks and without --reference before retrying"
                    );
                }
            } else {
                bail!("managed child {label} contains a special file");
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_git_object_aliases(_objects: &Path) -> Result<()> {
    bail!("managed child Git object alias validation is unsupported on this platform")
}

#[cfg(not(unix))]
fn reject_git_read_only_tree_aliases(_root: &Path, _label: &str) -> Result<()> {
    bail!("managed child Git metadata alias validation is unsupported on this platform")
}

fn protected_worktree_controls_for(
    workspace: &Path,
    declared_exceptions: &[PathBuf],
) -> Result<ProtectedWorktreeControls> {
    if declared_exceptions.len() > MAX_WORKTREE_CONTROL_EXCEPTIONS {
        bail!(
            "worktree control exception count exceeds the fail-closed limit of {MAX_WORKTREE_CONTROL_EXCEPTIONS}"
        );
    }
    let mut controls = ProtectedWorktreeControls::default();
    collect_protected_control(
        workspace,
        Path::new(".git"),
        SandboxDenialRetryability::NotRetryable,
        true,
        &mut controls,
    )?;
    for relative in PERMANENT_CONTROL_ROOTS {
        collect_protected_control(
            workspace,
            Path::new(relative),
            SandboxDenialRetryability::NotRetryable,
            true,
            &mut controls,
        )?;
    }
    for relative in POLICY_CONTROL_ROOTS {
        collect_protected_control(
            workspace,
            Path::new(relative),
            SandboxDenialRetryability::RequiresDeclaredException,
            true,
            &mut controls,
        )?;
    }
    for relative in POLICY_CONTROL_FILES {
        collect_protected_control(
            workspace,
            Path::new(relative),
            SandboxDenialRetryability::RequiresDeclaredException,
            false,
            &mut controls,
        )?;
    }

    let mut normalized_exceptions = Vec::with_capacity(declared_exceptions.len());
    for declared in declared_exceptions {
        let relative = normalize_control_exception(declared)?;
        let target = validate_control_exception_target(workspace, &relative)?;
        if normalized_exceptions
            .iter()
            .any(|(existing, _): &(PathBuf, ControlExceptionTarget)| {
                existing == &relative
                    || existing.starts_with(&relative)
                    || relative.starts_with(existing)
            })
        {
            bail!(
                "worktree control exceptions may not duplicate or overlap: {}",
                relative.display()
            );
        }
        normalized_exceptions.push((relative, target));
    }
    for (relative, target) in normalized_exceptions {
        controls
            .read_only_roots
            .retain(|control| control.relative() != relative);
        controls
            .read_only_files
            .retain(|control| control.relative() != relative);
        collect_control_exception(workspace, &relative, target, &mut controls)?;
    }
    controls.read_only_roots.sort_by(control_path_order);
    controls.read_only_files.sort_by(control_path_order);
    controls.read_write_roots.sort_by(control_path_order);
    controls.read_write_files.sort_by(control_path_order);
    Ok(controls)
}

fn control_path_order(
    left: &ProtectedWorktreeControl,
    right: &ProtectedWorktreeControl,
) -> std::cmp::Ordering {
    left.absolute.cmp(&right.absolute)
}

fn collect_protected_control(
    workspace: &Path,
    relative: &Path,
    retryability: SandboxDenialRetryability,
    required: bool,
    controls: &mut ProtectedWorktreeControls,
) -> Result<()> {
    let path = workspace.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "mandatory protected worktree control is absent: {}",
                relative.display()
            );
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect protected worktree control {}",
                    relative.display()
                )
            });
        }
    };
    if metadata.file_type().is_symlink() {
        bail!(
            "protected worktree control may not be a symlink: {}",
            relative.display()
        );
    }
    let control = ProtectedWorktreeControl {
        absolute: path,
        protected: ProtectedPathSpec::new(
            DeclaredPathCoordinate::new(WORKTREE_DECLARED_ROOT_ID, relative)
                .context("protected worktree control path is invalid")?,
            retryability,
        ),
        #[cfg(unix)]
        held_file: None,
    };
    if metadata.is_dir() {
        controls.read_only_roots.push(control);
    } else if metadata.is_file() {
        controls.read_only_files.push(control);
    } else {
        bail!(
            "protected worktree control is not a regular file or directory: {}",
            control.relative().display()
        );
    }
    Ok(())
}

fn validate_artifact_parent_disjoint(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Result<PathBuf> {
    let parent = normalized_absolute_path(
        required_parent(&spec.output_last_message)?,
        "external-agent output parent",
    )?;
    for control in controls.iter() {
        let protected = normalized_absolute_path(&control.absolute, "protected worktree control")?;
        if !parent.starts_with(&protected) && !protected.starts_with(&parent) {
            continue;
        }
        if control.relative() == Path::new(".maco")
            && matches!(
                spec.invocation,
                ExternalAgentInvocation::CodexConsultant
                    | ExternalAgentInvocation::ClaudeConsultant
            )
            && is_designated_maco_incoming_parent(&parent, &protected)
        {
            continue;
        }
        bail!("external-agent output parent overlaps a protected worktree control");
    }
    if let Some(git) = &controls.managed_git {
        for protected in std::iter::once(&git.worktree_git_dir)
            .chain(&git.common_read_only_roots)
            .chain(&git.common_read_only_files)
        {
            let protected = normalized_absolute_path(protected, "managed Git metadata")?;
            if parent.starts_with(&protected) || protected.starts_with(&parent) {
                bail!("external-agent output parent overlaps managed Git metadata");
            }
        }
    }
    Ok(parent)
}

fn is_designated_maco_incoming_parent(parent: &Path, maco_root: &Path) -> bool {
    let Ok(relative) = parent.strip_prefix(maco_root) else {
        return false;
    };
    let mut components = relative.components();
    let (
        Some(std::path::Component::Normal(consult)),
        Some(std::path::Component::Normal(runs)),
        Some(std::path::Component::Normal(run_id)),
        Some(std::path::Component::Normal(incoming_name)),
        None,
    ) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    )
    else {
        return false;
    };
    if runs != OsStr::new("runs") {
        return false;
    }
    let Some(run_id) = run_id.to_str() else {
        return false;
    };
    if !crate::orchestrator::RunId::new(run_id).is_ok_and(|validated| validated.as_str() == run_id)
    {
        return false;
    }
    consult == OsStr::new("consult") && incoming_name == OsStr::new("incoming")
}

fn normalized_absolute_path(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("{label} must be absolute");
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                bail!("{label} must already be normalized");
            }
        }
    }
    Ok(normalized)
}

fn normalize_control_exception(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        bail!(
            "worktree control exception must be a non-empty workspace-relative path: {}",
            path.display()
        );
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(component) => normalized.push(component),
            std::path::Component::CurDir => {
                bail!(
                    "worktree control exception must already be normalized: {}",
                    path.display()
                );
            }
            std::path::Component::ParentDir => {
                bail!(
                    "worktree control exception may not contain '..': {}",
                    path.display()
                );
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                bail!(
                    "worktree control exception must be workspace-relative: {}",
                    path.display()
                );
            }
        }
    }
    if normalized.as_os_str().is_empty() || normalized == Path::new(".") {
        bail!("worktree control exception may not be empty or '.'");
    }
    if normalized.to_str().is_none() {
        bail!("worktree control exception must be valid UTF-8 for Codex permissions");
    }
    Ok(normalized)
}

fn validate_control_exception_target(
    workspace: &Path,
    relative: &Path,
) -> Result<ControlExceptionTarget> {
    if relative.starts_with(".git")
        || PERMANENT_CONTROL_ROOTS
            .iter()
            .any(|root| relative.starts_with(root))
    {
        bail!(
            "worktree control is permanently read-only and cannot be excepted: {}",
            relative.display()
        );
    }
    if POLICY_CONTROL_ROOTS
        .iter()
        .any(|root| relative == Path::new(root))
    {
        bail!(
            "worktree policy root is an ancestor boundary and cannot be excepted directly: {}",
            relative.display()
        );
    }
    let protected_policy_path = POLICY_CONTROL_ROOTS
        .iter()
        .any(|root| relative.starts_with(root))
        || POLICY_CONTROL_FILES
            .iter()
            .any(|file| relative == Path::new(file));
    if !protected_policy_path {
        bail!(
            "worktree control exception is outside the protected policy set: {}",
            relative.display()
        );
    }

    let workspace_metadata = fs::symlink_metadata(workspace)
        .context("failed to inspect worktree control exception workspace")?;
    if workspace_metadata.file_type().is_symlink() || !workspace_metadata.is_dir() {
        bail!("worktree control exception workspace must be a non-symlink directory");
    }

    let component_count = relative.components().count();
    let mut current = workspace.to_path_buf();
    for (index, component) in relative.components().enumerate() {
        let std::path::Component::Normal(component) = component else {
            bail!(
                "worktree control exception is not normalized: {}",
                relative.display()
            );
        };
        current.push(component);
        let is_final = index + 1 == component_count;
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && is_final => {
                return Ok(ControlExceptionTarget {
                    kind: ControlExceptionKind::AbsentRegularFile,
                    #[cfg(unix)]
                    held_file: None,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                bail!(
                    "worktree control exception parent chain must already exist: {}",
                    relative.display()
                );
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect worktree control exception parent: {}",
                        relative.display()
                    )
                });
            }
        };
        if metadata.file_type().is_symlink() {
            bail!(
                "worktree control exception may not traverse or name a symlink: {}",
                relative.display()
            );
        }
        if !is_final && !metadata.is_dir() {
            bail!(
                "worktree control exception parent chain must contain only directories: {}",
                relative.display()
            );
        }
        if is_final && !metadata.is_file() && !metadata.is_dir() {
            bail!(
                "worktree control exception must name a regular file or directory: {}",
                relative.display()
            );
        }
        if is_final && metadata.is_file() {
            #[cfg(unix)]
            let held_file = Some(
                hold_existing_control_exception_file(workspace, relative, &metadata).with_context(
                    || {
                        format!(
                            "failed to hold exact worktree control exception: {}",
                            relative.display()
                        )
                    },
                )?,
            );
            return Ok(ControlExceptionTarget {
                kind: ControlExceptionKind::ExistingRegularFile,
                #[cfg(unix)]
                held_file,
            });
        }
        if is_final {
            return Ok(ControlExceptionTarget {
                kind: ControlExceptionKind::ExistingDirectory,
                #[cfg(unix)]
                held_file: None,
            });
        }
    }
    bail!(
        "worktree control exception did not resolve to a target: {}",
        relative.display()
    )
}

fn collect_control_exception(
    workspace: &Path,
    relative: &Path,
    target: ControlExceptionTarget,
    controls: &mut ProtectedWorktreeControls,
) -> Result<()> {
    let absolute = workspace.join(relative);
    #[cfg(unix)]
    let held_file = match target.kind {
        ControlExceptionKind::AbsentRegularFile => Some(
            materialize_control_exception_file(workspace, relative).with_context(|| {
                format!(
                    "failed to materialize exact worktree control exception: {}",
                    relative.display()
                )
            })?,
        ),
        ControlExceptionKind::ExistingRegularFile => target.held_file,
        ControlExceptionKind::ExistingDirectory => None,
    };
    #[cfg(not(unix))]
    if target.kind == ControlExceptionKind::AbsentRegularFile {
        materialize_control_exception_file(workspace, relative).with_context(|| {
            format!(
                "failed to materialize exact worktree control exception: {}",
                relative.display()
            )
        })?;
    }
    let metadata = fs::symlink_metadata(&absolute).with_context(|| {
        format!(
            "failed to inspect exact worktree control exception: {}",
            relative.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        bail!(
            "worktree control exception may not name a symlink: {}",
            relative.display()
        );
    }
    let expected_type_matches = match target.kind {
        ControlExceptionKind::ExistingDirectory => metadata.is_dir(),
        ControlExceptionKind::ExistingRegularFile | ControlExceptionKind::AbsentRegularFile => {
            metadata.is_file()
        }
    };
    if !expected_type_matches {
        bail!(
            "worktree control exception type changed during classification: {}",
            relative.display()
        );
    }
    #[cfg(unix)]
    if let Some(held) = &held_file {
        held.verify_path(workspace, relative).with_context(|| {
            format!(
                "held worktree control changed during classification: {}",
                relative.display()
            )
        })?;
    }
    let control = ProtectedWorktreeControl {
        absolute,
        protected: ProtectedPathSpec::new(
            DeclaredPathCoordinate::new(WORKTREE_DECLARED_ROOT_ID, relative)
                .context("worktree control exception path is invalid")?,
            SandboxDenialRetryability::NotRetryable,
        ),
        #[cfg(unix)]
        held_file,
    };
    if metadata.is_dir() {
        controls.read_write_roots.push(control);
    } else if metadata.is_file() {
        controls.read_write_files.push(control);
    } else {
        bail!(
            "worktree control exception must name a regular file or directory: {}",
            relative.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
impl HeldWorktreeControlFile {
    fn verify_path(&self, workspace: &Path, relative: &Path) -> std::io::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let held_identity = worktree_control_file_identity(&self._file)?;
        if held_identity != self.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "held worktree control identity changed",
            ));
        }
        if self.requires_private_materialization {
            validate_materialized_control_file_identity(held_identity)?;
        }
        let (parent, name) = open_control_exception_parent_nofollow(workspace, relative)?;
        let observed_fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if observed_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a new owned descriptor.
        let observed = unsafe { fs::File::from_raw_fd(observed_fd) };
        let observed_identity = worktree_control_file_identity(&observed)?;
        if self.requires_private_materialization {
            validate_materialized_control_file_identity(observed_identity)?;
        }
        if observed_identity != self.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "worktree control path no longer names the held file",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn worktree_control_file_identity(file: &fs::File) -> std::io::Result<WorktreeControlFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "held worktree control is not a regular file",
        ));
    }
    Ok(WorktreeControlFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        links: metadata.nlink(),
    })
}

#[cfg(unix)]
fn worktree_control_file_identity_from_metadata(
    metadata: &fs::Metadata,
) -> std::io::Result<WorktreeControlFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "worktree control metadata is not a regular file",
        ));
    }
    Ok(WorktreeControlFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        links: metadata.nlink(),
    })
}

#[cfg(unix)]
fn validate_materialized_control_file_identity(
    identity: WorktreeControlFileIdentity,
) -> std::io::Result<()> {
    // SAFETY: `geteuid` has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    if identity.owner != effective_uid || identity.mode != 0o600 || identity.links != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "materialized worktree control must be current-user-owned, mode 0600, and single-link",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn materialized_control_file_identity(
    file: &fs::File,
) -> std::io::Result<WorktreeControlFileIdentity> {
    let identity = worktree_control_file_identity(file)?;
    validate_materialized_control_file_identity(identity)?;
    Ok(identity)
}

#[cfg(unix)]
fn open_control_exception_parent_nofollow(
    workspace: &Path,
    relative: &Path,
) -> std::io::Result<(fs::File, std::ffi::CString)> {
    use std::ffi::CString;
    use std::os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    };

    let invalid_path = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "worktree control exception contains an invalid path component",
        )
    };
    let workspace_name =
        CString::new(workspace.as_os_str().as_bytes()).map_err(|_| invalid_path())?;
    let workspace_fd = unsafe {
        libc::open(
            workspace_name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
        )
    };
    if workspace_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `open` returned a new owned descriptor.
    let mut parent = unsafe { fs::File::from_raw_fd(workspace_fd) };
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(component) = component else {
            return Err(invalid_path());
        };
        let name = CString::new(component.as_bytes()).map_err(|_| invalid_path())?;
        if components.peek().is_none() {
            return Ok((parent, name));
        }
        let directory_fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        };
        if directory_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a new owned descriptor.
        parent = unsafe { fs::File::from_raw_fd(directory_fd) };
    }
    Err(invalid_path())
}

#[cfg(unix)]
fn hold_existing_control_exception_file(
    workspace: &Path,
    relative: &Path,
    classified_metadata: &fs::Metadata,
) -> std::io::Result<HeldWorktreeControlFile> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let classified_identity = worktree_control_file_identity_from_metadata(classified_metadata)?;
    let (parent, name) = open_control_exception_parent_nofollow(workspace, relative)?;
    let file_fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if file_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new owned descriptor.
    let file = unsafe { fs::File::from_raw_fd(file_fd) };
    let held_identity = worktree_control_file_identity(&file)?;
    if held_identity != classified_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "worktree control changed while its held capability was acquired",
        ));
    }
    let held = HeldWorktreeControlFile {
        _file: std::sync::Arc::new(file),
        identity: held_identity,
        requires_private_materialization: false,
    };
    held.verify_path(workspace, relative)?;
    Ok(held)
}

#[cfg(unix)]
fn materialize_control_exception_file(
    workspace: &Path,
    relative: &Path,
) -> std::io::Result<HeldWorktreeControlFile> {
    materialize_control_exception_file_with(workspace, relative, || Ok(()))
}

#[cfg(all(test, unix))]
fn materialize_control_exception_file_with_hook(
    workspace: &Path,
    relative: &Path,
    after_create: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<HeldWorktreeControlFile> {
    materialize_control_exception_file_with(workspace, relative, after_create)
}

#[cfg(unix)]
fn materialize_control_exception_file_with(
    workspace: &Path,
    relative: &Path,
    after_create: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<HeldWorktreeControlFile> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let (parent, name) = open_control_exception_parent_nofollow(workspace, relative)?;
    let file_fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600 as libc::c_uint,
        )
    };
    if file_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new owned descriptor.
    let file = unsafe { fs::File::from_raw_fd(file_fd) };
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600 as libc::mode_t) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    after_create()?;
    let identity = materialized_control_file_identity(&file)?;

    let observed_fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if observed_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a new owned descriptor.
    let observed = unsafe { fs::File::from_raw_fd(observed_fd) };
    if materialized_control_file_identity(&observed)? != identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "materialized worktree control path does not match the created file",
        ));
    }

    Ok(HeldWorktreeControlFile {
        _file: std::sync::Arc::new(file),
        identity,
        requires_private_materialization: true,
    })
}

#[cfg(not(unix))]
fn materialize_control_exception_file(
    workspace: &Path,
    relative: &Path,
) -> std::io::Result<fs::File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(workspace.join(relative))
}

enum ExternalProviderProfile {
    Codex(ExternalCodexProfile),
    Grok(ExternalGrokProfile),
}

impl ExternalProviderProfile {
    fn for_command(spec: &ExternalAgentCommand) -> Result<Self> {
        Ok(match (
            spec.invocation,
            spec.workspace_access,
            spec.writable_runtime_selection.as_ref(),
        ) {
            (ExternalAgentInvocation::Grok, _, Some(_)) => Self::Grok(
                ExternalGrokProfile::read_write(spec.selected_grok_writable_workspace()?),
            ),
            (ExternalAgentInvocation::Grok, WorkspaceAccess::ReadOnly, None) => {
                Self::Grok(ExternalGrokProfile::read_only(&spec.cwd))
            }
            // Direct profile unit tests exercise lower-level Grok inputs. Production writable
            // Grok reaches this point only after the external boundary has required supervisor
            // selection and confinement evidence.
            (ExternalAgentInvocation::Grok, WorkspaceAccess::ReadWrite, None) => {
                Self::Grok(ExternalGrokProfile::read_write(&spec.cwd))
            }
            (_, WorkspaceAccess::ReadOnly, _) => {
                Self::Codex(ExternalCodexProfile::read_only(&spec.cwd))
            }
            (_, WorkspaceAccess::ReadWrite, _) => {
                Self::Codex(ExternalCodexProfile::read_write(&spec.cwd))
            }
        })
    }

    fn with_visible_read_only_root(self, root: impl Into<PathBuf>) -> Self {
        match self {
            Self::Codex(profile) => Self::Codex(profile.with_visible_read_only_root(root.into())),
            Self::Grok(profile) => Self::Grok(profile.with_visible_read_only_root(root.into())),
        }
    }

    fn with_visible_read_only_file(self, file: impl Into<PathBuf>) -> Self {
        match self {
            Self::Codex(profile) => Self::Codex(profile.with_visible_read_only_file(file.into())),
            Self::Grok(profile) => Self::Grok(profile.with_visible_read_only_file(file.into())),
        }
    }

    fn with_visible_read_write_root(self, root: impl Into<PathBuf>) -> Self {
        match self {
            Self::Codex(profile) => Self::Codex(profile.with_visible_read_write_root(root.into())),
            Self::Grok(profile) => Self::Grok(profile.with_visible_read_write_root(root.into())),
        }
    }

    fn with_visible_read_write_file(self, file: impl Into<PathBuf>) -> Self {
        match self {
            Self::Codex(profile) => Self::Codex(profile.with_visible_read_write_file(file.into())),
            Self::Grok(profile) => Self::Grok(profile.with_visible_read_write_file(file.into())),
        }
    }

    #[cfg(target_os = "linux")]
    fn with_visible_read_write_file_capability(
        self,
        file: impl Into<PathBuf>,
        held_file: std::sync::Arc<fs::File>,
    ) -> std::io::Result<Self> {
        match self {
            Self::Codex(profile) => profile
                .with_visible_read_write_file_capability(file.into(), held_file)
                .map(Self::Codex),
            Self::Grok(profile) => profile
                .with_visible_read_write_file_capability(file.into(), held_file)
                .map(Self::Grok),
        }
    }

    fn with_writable_artifact_root(self, root: impl Into<PathBuf>) -> Self {
        match self {
            Self::Codex(profile) => Self::Codex(profile.with_writable_artifact_root(root.into())),
            Self::Grok(profile) => Self::Grok(profile),
        }
    }

    fn with_hidden_root(self, root: impl Into<PathBuf>) -> Self {
        match self {
            Self::Codex(profile) => Self::Codex(profile.with_hidden_root(root.into())),
            Self::Grok(profile) => Self::Grok(profile.with_hidden_root(root.into())),
        }
    }

    fn finish(self) -> SideEffectConfinementProfile {
        match self {
            Self::Codex(profile) => SideEffectConfinementProfile::ExternalCodex(profile),
            Self::Grok(profile) => SideEffectConfinementProfile::ExternalGrok(profile),
        }
    }
}

fn external_side_effect_profile(
    spec: &ExternalAgentCommand,
    program: &Path,
    program_trust: ExternalProgramTrust,
    protected_controls: &ProtectedWorktreeControls,
) -> Result<SideEffectConfinementProfile> {
    if program_trust != ExternalProgramTrust::TrustedSystemCodex
        && !spec.invocation.is_adapter_subprocess()
    {
        bail!("provider-network confinement is reserved for the trusted system Codex executable");
    }
    let program_parent = program
        .parent()
        .with_context(|| format!("executable has no parent: {}", program.display()))?;
    // The parent tee owns and holds `json_log`; the child never needs that directory writable.
    // Only the validated, disjoint incoming final-message directory can become a child artifact
    // root. Grok is excluded below because MACO captures its stdout and owns publication.
    let artifact_root = protected_controls
        .writable_artifact_root
        .as_ref()
        .context("external-agent output parent was not validated against protected controls")?;
    match spec.invocation {
        ExternalAgentInvocation::CodexSupervisor
        | ExternalAgentInvocation::CodexConsultant
        | ExternalAgentInvocation::Grok
        | ExternalAgentInvocation::Cursor
        | ExternalAgentInvocation::ClaudeCode
        | ExternalAgentInvocation::GeminiCli => {
            let mut profile = ExternalProviderProfile::for_command(spec)?;
            for control in &protected_controls.read_only_roots {
                profile = profile.with_visible_read_only_root(&control.absolute);
            }
            for control in &protected_controls.read_only_files {
                profile = profile.with_visible_read_only_file(&control.absolute);
            }
            for control in &protected_controls.read_write_roots {
                profile = profile.with_visible_read_write_root(&control.absolute);
            }
            for control in &protected_controls.read_write_files {
                #[cfg(target_os = "linux")]
                if let Some(held) = &control.held_file {
                    held.verify_path(&spec.cwd, control.relative())
                        .with_context(|| {
                            format!(
                                "held worktree control changed before sandbox admission: {}",
                                control.relative().display()
                            )
                        })?;
                    profile = profile
                        .with_visible_read_write_file_capability(
                            &control.absolute,
                            std::sync::Arc::clone(&held._file),
                        )
                        .with_context(|| {
                            format!(
                                "held worktree control capability is invalid: {}",
                                control.relative().display()
                            )
                        })?;
                    continue;
                }
                #[cfg(all(unix, not(target_os = "linux")))]
                if let Some(held) = &control.held_file {
                    held.verify_path(&spec.cwd, control.relative())
                        .with_context(|| {
                            format!(
                                "held worktree control changed before sandbox admission: {}",
                                control.relative().display()
                            )
                        })?;
                }
                profile = profile.with_visible_read_write_file(&control.absolute);
            }
            if let Some(git) = &protected_controls.managed_git {
                for root in &git.common_read_only_roots {
                    profile = profile.with_visible_read_only_root(root);
                }
                for file in &git.common_read_only_files {
                    profile = profile.with_visible_read_only_file(file);
                }
                profile = profile.with_visible_read_only_root(&git.worktree_git_dir);
                if spec.workspace_access == WorkspaceAccess::ReadWrite {
                    profile = profile.with_visible_read_write_root(&git.private_git_dir);
                    for file in &git.fixed_private_read_only_files {
                        profile = profile.with_visible_read_only_file(file);
                    }
                }
            }
            let canonical_workspace = fs::canonicalize(&spec.cwd)?;
            if !program.starts_with(&canonical_workspace) {
                profile = profile.with_visible_read_only_root(program_parent);
            }
            if let Some(schema) = &spec.output_schema {
                if !protected_controls
                    .exact_read_only_input_files
                    .contains(schema)
                {
                    profile = profile.with_visible_read_only_file(schema);
                }
            }
            if spec.invocation == ExternalAgentInvocation::Grok {
                // Grok's pinned headless protocol reads the prompt by pathname. The shared
                // runner still owns prompt validation; expose only that exact held input to the
                // contained child instead of its parent directory.
                profile = profile.with_visible_read_only_file(&spec.prompt);
            }
            for input in &protected_controls.exact_read_only_input_files {
                profile = profile.with_visible_read_only_file(input);
            }
            for artifact in &protected_controls.exact_writable_artifact_files {
                #[cfg(target_os = "linux")]
                {
                    profile = profile
                        .with_visible_read_write_file_capability(
                            &artifact.path,
                            std::sync::Arc::clone(&artifact.held_file),
                        )
                        .with_context(|| {
                            format!(
                                "exact writable artifact capability is invalid: {}",
                                artifact.path.display()
                            )
                        })?;
                }
                #[cfg(not(target_os = "linux"))]
                {
                    profile = profile.with_visible_read_write_file(&artifact.path);
                }
            }
            // Grok's bounded streaming-json response is captured and published by the MACO
            // parent. The child needs only its exact precreated journal file capabilities; it
            // must never receive the incoming publication directory as a writable root.
            if spec.invocation != ExternalAgentInvocation::Grok {
                profile = profile.with_writable_artifact_root(artifact_root);
            }
            for root in &spec.hidden_roots {
                profile = profile.with_hidden_root(root);
            }
            Ok(profile.finish())
        }
        ExternalAgentInvocation::ClaudeConsultant => {
            let capability = crate::runtime_adapter::AdapterId::ClaudeCode
                .capabilities()
                .read_only_inner_contract_refusal()
                .unwrap_or("side_effect_confinement != verified");
            bail!("Claude consultant has no enforceable fixed-network capability ({capability})")
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) struct ExternalGrokProfileProjection {
    pub(crate) workspace_access: WorkspaceAccess,
    pub(crate) systemd_properties: Vec<String>,
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn selected_grok_profile_projection_for_test(
    spec: &ExternalAgentCommand,
) -> Result<ExternalGrokProfileProjection> {
    let output_parent = required_parent(&spec.output_last_message)?;
    let controls = ProtectedWorktreeControls {
        writable_artifact_root: Some(fs::canonicalize(output_parent)?),
        ..ProtectedWorktreeControls::default()
    };
    let profile = external_side_effect_profile(
        spec,
        &spec.program,
        ExternalProgramTrust::ExplicitCustom,
        &controls,
    )?;
    let SideEffectConfinementProfile::ExternalGrok(profile) = profile else {
        bail!("selected Grok command did not produce an ExternalGrok profile");
    };
    let workspace_access = profile.workspace_access();
    let systemd_properties = crate::process_runner::external_grok_systemd_properties_for_test(
        profile,
        &spec.program,
        &spec.cwd,
    )?;
    Ok(ExternalGrokProfileProjection {
        workspace_access,
        systemd_properties,
    })
}

fn sandbox_denials_from_codex_jsonl(
    controls: &ProtectedWorktreeControls,
    jsonl: &[u8],
) -> Vec<SandboxDenialEvidence> {
    let mut evidence = BTreeSet::new();
    for line in jsonl.split(|byte| *byte == b'\n') {
        if line.is_empty() || line.len() > MAX_CODEX_JSONL_EVENT_BYTES {
            continue;
        }
        let Ok(event) = serde_json::from_slice::<serde_json::Value>(line) else {
            continue;
        };
        let Some((command, output)) = failed_command_event_fields(&event) else {
            continue;
        };
        if !contains_sandbox_denial_marker(output) {
            continue;
        }
        let mut known = controls.iter().collect::<Vec<_>>();
        known.sort_by(|left, right| {
            right
                .relative()
                .as_os_str()
                .len()
                .cmp(&left.relative().as_os_str().len())
        });
        for control in known {
            let Some(relative) = control.relative().to_str() else {
                continue;
            };
            let Some(absolute) = control.absolute.to_str() else {
                continue;
            };
            if [command, output].iter().any(|text| {
                contains_exact_path(text, relative) || contains_exact_path(text, absolute)
            }) {
                evidence.insert(SandboxDenialEvidence {
                    boundary: SandboxDenialBoundary::InnerCodex,
                    policy_id: INNER_CODEX_POLICY_ID.to_string(),
                    operation: SandboxDeniedOperation::Write,
                    path: Some(control.relative().to_path_buf()),
                    retryability: control.retryability(),
                });
                break;
            }
        }
    }
    evidence.into_iter().collect()
}

fn failed_command_event_fields(event: &serde_json::Value) -> Option<(&str, &str)> {
    if event.get("type")?.as_str()? != "item.completed" {
        return None;
    }
    let item = event.get("item")?.as_object()?;
    if item.get("id")?.as_str()?.is_empty()
        || item.get("type")?.as_str()? != "command_execution"
        || item.get("status")?.as_str()? != "failed"
        || item.get("exit_code")?.as_i64()? == 0
    {
        return None;
    }
    let command = item.get("command")?.as_str()?;
    let output = item.get("aggregated_output")?.as_str()?;
    (command.len() <= MAX_CODEX_EVENT_TEXT_BYTES && output.len() <= MAX_CODEX_EVENT_TEXT_BYTES)
        .then_some((command, output))
}

fn contains_exact_path(text: &str, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    text.match_indices(path).any(|(offset, matched)| {
        let before = text[..offset].chars().next_back();
        let after = text[offset + matched.len()..].chars().next();
        !before.is_some_and(is_path_character) && !after.is_some_and(is_path_character)
    })
}

fn is_path_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-' | '.' | '/' | '\\')
}

fn sandbox_denial_from_process_error(error: &ProcessRunError) -> Option<SandboxDenialEvidence> {
    matches!(
        error,
        ProcessRunError::ContainmentUnavailable { .. } | ProcessRunError::ProcessOwnership { .. }
    )
    .then(|| SandboxDenialEvidence {
        boundary: SandboxDenialBoundary::OuterSystemd,
        policy_id: OUTER_SYSTEMD_POLICY_ID.to_string(),
        operation: SandboxDeniedOperation::EstablishBoundary,
        path: None,
        retryability: SandboxDenialRetryability::NotRetryable,
    })
}

fn contains_sandbox_denial_marker(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "permission denied",
        "read-only file system",
        "operation not permitted",
        "sandbox denied",
        "sandbox_denied",
        "denied by sandbox",
        "denied by policy",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn required_parent(path: &Path) -> Result<&Path> {
    path.parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum CodexAuthValidationFailureCause {
    #[error("auth_home_not_absolute")]
    HomeNotAbsolute,
    #[error("auth_home_canonicalization_failed")]
    HomeCanonicalizationFailed,
    #[error("auth_home_not_directory")]
    HomeNotDirectory,
    #[error("auth_home_ancestor_inspection_failed")]
    HomeAncestorInspectionFailed,
    #[error("auth_home_ancestor_not_directory")]
    HomeAncestorNotDirectory,
    #[error("auth_home_ancestor_writable")]
    HomeAncestorWritable,
    #[error("auth_home_ancestor_owner_mismatch")]
    HomeAncestorOwnerMismatch,
    #[error("auth_file_missing")]
    AuthFileMissing,
    #[error("auth_file_inspection_failed")]
    AuthFileInspectionFailed,
    #[error("auth_file_symlink")]
    AuthFileSymlink,
    #[error("auth_file_open_failed")]
    AuthFileOpenFailed,
    #[error("auth_file_metadata_failed")]
    AuthFileMetadataFailed,
    #[error("auth_file_not_bounded_regular")]
    AuthFileNotBoundedRegular,
    #[error("auth_file_owner_mismatch")]
    AuthFileOwnerMismatch,
    #[error("auth_file_mode_too_broad")]
    AuthFileModeTooBroad,
    #[error("auth_file_link_count_invalid")]
    AuthFileLinkCountInvalid,
    #[error("auth_file_read_failed")]
    AuthFileReadFailed,
    #[error("auth_file_grew_during_read")]
    AuthFileGrewDuringRead,
    #[error("auth_file_changed_during_read")]
    AuthFileChangedDuringRead,
    #[error("auth_file_identity_changed_during_read")]
    AuthFileIdentityChangedDuringRead,
    #[error("auth_file_revalidation_inspection_failed")]
    AuthFileRevalidationInspectionFailed,
    #[error("auth_file_revalidation_metadata_changed")]
    AuthFileRevalidationMetadataChanged,
    #[error("auth_file_revalidation_identity_changed")]
    AuthFileRevalidationIdentityChanged,
    #[cfg(not(unix))]
    #[error("auth_file_unsupported_platform")]
    AuthFileUnsupportedPlatform,
}

fn sanitized_codex_auth_validation_summary(error: &anyhow::Error) -> String {
    let cause = error
        .downcast_ref::<CodexAuthValidationFailureCause>()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unexpected_failure".to_string());
    format!("codex_auth_preflight_cause={cause}")
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexAuthDirectoryTrustDecision {
    Accept,
    RejectNotDirectory,
    RejectWritable,
    RejectOwnership,
}

#[cfg(unix)]
fn codex_auth_directory_trust_decision(
    mode: u32,
    uid: u32,
    is_directory: bool,
    effective_uid: u32,
) -> CodexAuthDirectoryTrustDecision {
    if !is_directory {
        return CodexAuthDirectoryTrustDecision::RejectNotDirectory;
    }
    if mode & 0o022 != 0 {
        CodexAuthDirectoryTrustDecision::RejectWritable
    } else if uid != 0 && uid != effective_uid {
        CodexAuthDirectoryTrustDecision::RejectOwnership
    } else {
        CodexAuthDirectoryTrustDecision::Accept
    }
}

#[cfg(unix)]
fn ensure_trusted_codex_auth_home(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // SAFETY: geteuid has no preconditions and does not access Rust memory.
    let effective_uid = unsafe { libc::geteuid() };
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .context(CodexAuthValidationFailureCause::HomeAncestorInspectionFailed)?;
        if metadata.file_type().is_symlink() {
            return Err(CodexAuthValidationFailureCause::HomeAncestorNotDirectory.into());
        }
        match codex_auth_directory_trust_decision(
            metadata.permissions().mode(),
            metadata.uid(),
            metadata.is_dir(),
            effective_uid,
        ) {
            CodexAuthDirectoryTrustDecision::Accept => {}
            CodexAuthDirectoryTrustDecision::RejectNotDirectory => {
                return Err(CodexAuthValidationFailureCause::HomeAncestorNotDirectory.into());
            }
            CodexAuthDirectoryTrustDecision::RejectWritable => {
                return Err(CodexAuthValidationFailureCause::HomeAncestorWritable.into());
            }
            CodexAuthDirectoryTrustDecision::RejectOwnership => {
                return Err(CodexAuthValidationFailureCause::HomeAncestorOwnerMismatch.into());
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_trusted_codex_auth_home(path: &Path) -> Result<()> {
    ensure_existing_directory_without_symlinks(path)
        .context(CodexAuthValidationFailureCause::HomeAncestorInspectionFailed)
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexAuthFileTrustDecision {
    Accept,
    RejectNotRegular,
    RejectOwnership,
    RejectMode,
    RejectLinkCount,
}

#[cfg(unix)]
fn codex_auth_file_trust_decision(
    is_regular_file: bool,
    uid: u32,
    effective_uid: u32,
    mode: u32,
    link_count: u64,
) -> CodexAuthFileTrustDecision {
    if !is_regular_file {
        CodexAuthFileTrustDecision::RejectNotRegular
    } else if uid != effective_uid {
        CodexAuthFileTrustDecision::RejectOwnership
    } else if mode & 0o077 != 0 {
        CodexAuthFileTrustDecision::RejectMode
    } else if link_count != 1 {
        CodexAuthFileTrustDecision::RejectLinkCount
    } else {
        CodexAuthFileTrustDecision::Accept
    }
}

#[cfg(unix)]
fn ensure_trusted_codex_auth_file_metadata(
    metadata: &fs::Metadata,
    effective_uid: u32,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    match codex_auth_file_trust_decision(
        metadata.is_file(),
        metadata.uid(),
        effective_uid,
        metadata.permissions().mode(),
        metadata.nlink(),
    ) {
        CodexAuthFileTrustDecision::Accept => Ok(()),
        CodexAuthFileTrustDecision::RejectNotRegular => {
            Err(CodexAuthValidationFailureCause::AuthFileNotBoundedRegular.into())
        }
        CodexAuthFileTrustDecision::RejectOwnership => {
            Err(CodexAuthValidationFailureCause::AuthFileOwnerMismatch.into())
        }
        CodexAuthFileTrustDecision::RejectMode => {
            Err(CodexAuthValidationFailureCause::AuthFileModeTooBroad.into())
        }
        CodexAuthFileTrustDecision::RejectLinkCount => {
            Err(CodexAuthValidationFailureCause::AuthFileLinkCountInvalid.into())
        }
    }
}

#[derive(Debug)]
struct ValidatedCodexAuth {
    path: PathBuf,
    bytes: Vec<u8>,
    length: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ValidatedCodexAuth {
    fn binding_sha256(&self) -> Result<String> {
        #[cfg(unix)]
        let identity = serde_json::to_vec(&(
            &self.path,
            self.length,
            self.modified,
            self.device,
            self.inode,
            sha256_hex(&self.bytes),
        ))?;
        #[cfg(not(unix))]
        let identity = serde_json::to_vec(&(
            &self.path,
            self.length,
            self.modified,
            sha256_hex(&self.bytes),
        ))?;
        Ok(sha256_hex(&identity))
    }

    fn load() -> Result<Option<Self>> {
        let Some(home) = env::var_os("CODEX_HOME").map(PathBuf::from).or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".codex"))
        }) else {
            return Ok(None);
        };
        Self::load_from_home(&home)
    }

    fn load_from_home(home: &Path) -> Result<Option<Self>> {
        if !home.is_absolute() {
            return Err(CodexAuthValidationFailureCause::HomeNotAbsolute.into());
        }
        let home = match fs::canonicalize(home) {
            Ok(home) => home,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .context(CodexAuthValidationFailureCause::HomeCanonicalizationFailed);
            }
        };
        match fs::symlink_metadata(&home) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(CodexAuthValidationFailureCause::HomeNotDirectory.into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .context(CodexAuthValidationFailureCause::HomeAncestorInspectionFailed);
            }
        }
        ensure_trusted_codex_auth_home(&home)?;
        let path = home.join("auth.json");
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CodexAuthValidationFailureCause::AuthFileSymlink.into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .context(CodexAuthValidationFailureCause::AuthFileInspectionFailed);
            }
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&path)
            .context(CodexAuthValidationFailureCause::AuthFileOpenFailed)?;
        let metadata = file
            .metadata()
            .context(CodexAuthValidationFailureCause::AuthFileMetadataFailed)?;
        if !metadata.is_file() || metadata.len() > MAX_PROMPT_BYTES as u64 {
            return Err(CodexAuthValidationFailureCause::AuthFileNotBoundedRegular.into());
        }
        #[cfg(unix)]
        {
            // SAFETY: geteuid has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            ensure_trusted_codex_auth_file_metadata(&metadata, effective_uid)?;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take((MAX_PROMPT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .context(CodexAuthValidationFailureCause::AuthFileReadFailed)?;
        if bytes.len() > MAX_PROMPT_BYTES {
            return Err(CodexAuthValidationFailureCause::AuthFileGrewDuringRead.into());
        }
        let after = file
            .metadata()
            .context(CodexAuthValidationFailureCause::AuthFileMetadataFailed)?;
        if after.len() != metadata.len() || after.modified().ok() != metadata.modified().ok() {
            return Err(CodexAuthValidationFailureCause::AuthFileChangedDuringRead.into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if after.dev() != metadata.dev() || after.ino() != metadata.ino() {
                return Err(
                    CodexAuthValidationFailureCause::AuthFileIdentityChangedDuringRead.into(),
                );
            }
            Ok(Some(Self {
                path,
                bytes,
                length: metadata.len(),
                modified: metadata.modified().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
            }))
        }
        #[cfg(not(unix))]
        {
            Err(CodexAuthValidationFailureCause::AuthFileUnsupportedPlatform.into())
        }
    }

    fn verify_source_unchanged(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.path)
            .context(CodexAuthValidationFailureCause::AuthFileRevalidationInspectionFailed)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != self.length
            || metadata.modified().ok() != self.modified
        {
            return Err(
                CodexAuthValidationFailureCause::AuthFileRevalidationMetadataChanged.into(),
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no preconditions and does not access Rust memory.
            let effective_uid = unsafe { libc::geteuid() };
            ensure_trusted_codex_auth_file_metadata(&metadata, effective_uid)?;
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(
                    CodexAuthValidationFailureCause::AuthFileRevalidationIdentityChanged.into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct CredentialRedactor {
    patterns: Vec<Vec<u8>>,
}

impl std::fmt::Debug for CredentialRedactor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialRedactor")
            .field("patterns", &RedactedByteCount(self.patterns.len()))
            .finish()
    }
}

impl CredentialRedactor {
    fn from_runtime(
        environment: &BTreeMap<String, String>,
        codex_auth: Option<&ValidatedCodexAuth>,
    ) -> Result<Self> {
        let mut patterns = Vec::new();
        for key in ["OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"] {
            if let Some(value) = environment.get(key) {
                add_credential_pattern(&mut patterns, value.as_bytes())?;
                if let Ok(quoted) = serde_json::to_string(value) {
                    if let Some(escaped) = quoted
                        .strip_prefix('"')
                        .and_then(|value| value.strip_suffix('"'))
                    {
                        add_credential_pattern(&mut patterns, escaped.as_bytes())?;
                    }
                }
            }
        }
        if let Some(grok_home) = environment.get("GROK_HOME") {
            add_sensitive_runtime_path_pattern(&mut patterns, grok_home.as_bytes())?;
            if let Ok(quoted) = serde_json::to_string(grok_home) {
                if let Some(escaped) = quoted
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                {
                    add_sensitive_runtime_path_pattern(&mut patterns, escaped.as_bytes())?;
                }
            }
        }
        if let Some(auth) = codex_auth {
            let auth_pattern_start = patterns.len();
            if auth.bytes.len() <= MAX_CREDENTIAL_BYTES {
                add_credential_pattern(&mut patterns, &auth.bytes)?;
            }
            let value = serde_json::from_slice::<serde_json::Value>(&auth.bytes)
                .context("Codex auth material is not valid JSON for bounded redaction")?;
            collect_json_credential_patterns(&value, false, &mut patterns)?;
            if auth.bytes.len() > MAX_CREDENTIAL_BYTES && patterns.len() == auth_pattern_start {
                bail!(
                    "oversized Codex auth material did not expose any bounded redaction patterns"
                );
            }
        }
        patterns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        Ok(Self { patterns })
    }

    fn redact_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        self.patterns
            .iter()
            .fold(bytes.to_vec(), |redacted, pattern| {
                replace_bounded_bytes(&redacted, pattern, CREDENTIAL_REDACTION)
            })
    }

    fn redact_string(&self, value: &str) -> String {
        String::from_utf8_lossy(&self.redact_bytes(value.as_bytes())).into_owned()
    }
}

fn add_sensitive_runtime_path_pattern(patterns: &mut Vec<Vec<u8>>, value: &[u8]) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_BYTES
        || patterns.iter().any(|existing| existing == value)
    {
        return Ok(());
    }
    let aggregate_bytes = patterns
        .iter()
        .try_fold(0usize, |total, pattern| total.checked_add(pattern.len()))
        .and_then(|total| total.checked_add(value.len()))
        .context("sensitive runtime path redaction pattern size overflow")?;
    if patterns.len() >= MAX_CREDENTIAL_REDACTION_PATTERNS
        || aggregate_bytes > MAX_CREDENTIAL_REDACTION_PATTERN_BYTES
    {
        bail!("sensitive runtime path redaction patterns exceed the bounded limit");
    }
    patterns.push(value.to_vec());
    Ok(())
}

fn add_credential_pattern(patterns: &mut Vec<Vec<u8>>, value: &[u8]) -> Result<()> {
    if !(MIN_CREDENTIAL_BYTES..=MAX_CREDENTIAL_BYTES).contains(&value.len())
        || patterns.iter().any(|existing| existing == value)
    {
        return Ok(());
    }
    let aggregate_bytes = patterns
        .iter()
        .try_fold(0usize, |total, pattern| total.checked_add(pattern.len()))
        .and_then(|total| total.checked_add(value.len()))
        .context("credential redaction pattern size overflow")?;
    if patterns.len() >= MAX_CREDENTIAL_REDACTION_PATTERNS
        || aggregate_bytes > MAX_CREDENTIAL_REDACTION_PATTERN_BYTES
    {
        bail!(
            "credential redaction patterns exceed the fixed count or aggregate-byte safety bound"
        );
    }
    patterns.push(value.to_vec());
    Ok(())
}

fn collect_json_credential_patterns(
    value: &serde_json::Value,
    credential_bearing: bool,
    patterns: &mut Vec<Vec<u8>>,
) -> Result<()> {
    match value {
        serde_json::Value::String(value) => {
            if credential_bearing && !value.is_empty() && value.len() < MIN_CREDENTIAL_BYTES {
                bail!(
                    "credential-bearing Codex auth value is shorter than the safe redaction bound"
                );
            }
            if credential_bearing && value.len() > MAX_CREDENTIAL_BYTES {
                bail!("credential-bearing Codex auth value exceeds the safe redaction byte bound");
            }
            add_credential_pattern(patterns, value.as_bytes())?;
            if let Ok(quoted) = serde_json::to_string(value) {
                if let Some(escaped) = quoted
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                {
                    add_credential_pattern(patterns, escaped.as_bytes())?;
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_credential_patterns(value, credential_bearing, patterns)?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                let key = key.to_ascii_lowercase();
                let nested_credential_bearing = credential_bearing
                    || ["token", "key", "secret", "password", "authorization"]
                        .iter()
                        .any(|marker| key.contains(marker));
                collect_json_credential_patterns(value, nested_credential_bearing, patterns)?;
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn replace_bounded_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return haystack.to_vec();
    }
    let mut output = Vec::with_capacity(haystack.len());
    let mut offset = 0;
    while let Some(relative) = haystack[offset..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let matched = offset + relative;
        output.extend_from_slice(&haystack[offset..matched]);
        output.extend_from_slice(replacement);
        offset = matched + needle.len();
    }
    output.extend_from_slice(&haystack[offset..]);
    output
}

fn ensure_safe_read_target(path: &Path) -> Result<()> {
    ensure_existing_output_parent(path)?;
    read_bounded_regular_file_nofollow(path, MAX_PROMPT_BYTES)
        .map(|_| ())
        .with_context(|| format!("unsafe external-agent input {}", path.display()))
}

fn append_external_error(existing: Option<String>, next: Option<String>) -> Option<String> {
    match (existing, next) {
        (Some(existing), Some(next)) => Some(format!("{existing}; {next}")),
        (Some(existing), None) => Some(existing),
        (None, Some(next)) => Some(next),
        (None, None) => None,
    }
}

#[cfg(test)]
pub(crate) fn command_argv(spec: &ExternalAgentCommand) -> Vec<OsString> {
    let controls =
        protected_worktree_controls(spec).unwrap_or_else(|_| ProtectedWorktreeControls {
            writable_artifact_root: required_parent(&spec.output_last_message)
                .ok()
                .map(PathBuf::from),
            ..ProtectedWorktreeControls::default()
        });
    command_argv_with_controls_and_service_tier_input(spec, &controls, None).expect("command argv")
}

#[cfg(test)]
pub(crate) fn app_server_command_argv(spec: &ExternalAgentCommand) -> Vec<OsString> {
    let controls =
        protected_worktree_controls(spec).unwrap_or_else(|_| ProtectedWorktreeControls {
            writable_artifact_root: required_parent(&spec.output_last_message)
                .ok()
                .map(PathBuf::from),
            ..ProtectedWorktreeControls::default()
        });
    codex_app_server_argv(spec, &controls)
}

fn command_argv_with_controls(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Result<Vec<OsString>> {
    let service_tier = env::var_os("MACO_CODEX_SERVICE_TIER");
    command_argv_with_controls_and_service_tier_input(spec, controls, service_tier.as_deref())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexServiceTierOverride {
    Priority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodexMultiAgentMode {
    Enabled,
    Disabled,
}

fn parse_codex_service_tier_override(
    value: Option<&OsStr>,
) -> Result<Option<CodexServiceTierOverride>> {
    match value {
        None => Ok(None),
        Some(value) if value == OsStr::new("priority") => {
            Ok(Some(CodexServiceTierOverride::Priority))
        }
        Some(_) => bail!("MACO_CODEX_SERVICE_TIER must be unset or exactly 'priority'"),
    }
}

fn command_argv_with_controls_and_service_tier_input(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
    service_tier_input: Option<&OsStr>,
) -> Result<Vec<OsString>> {
    match spec.invocation {
        ExternalAgentInvocation::CodexSupervisor => Ok(codex_supervisor_argv(
            spec,
            controls,
            parse_codex_service_tier_override(service_tier_input)?,
        )),
        ExternalAgentInvocation::CodexConsultant => Ok(codex_consultant_argv(spec, controls)),
        ExternalAgentInvocation::ClaudeConsultant => Ok(claude_consultant_argv()),
        ExternalAgentInvocation::Grok
        | ExternalAgentInvocation::Cursor
        | ExternalAgentInvocation::ClaudeCode
        | ExternalAgentInvocation::GeminiCli => runtime_adapter_argv(spec),
    }
}

fn external_agent_stdin_mode(
    spec: &ExternalAgentCommand,
    duplex_review_required: bool,
    prompt: Vec<u8>,
) -> StdinMode {
    if duplex_review_required {
        StdinMode::Interactive
    } else if spec
        .runtime_adapter
        .as_ref()
        .is_some_and(|config| !config.feed_prompt_on_stdin)
    {
        StdinMode::Null
    } else {
        StdinMode::Bytes(prompt)
    }
}

fn runtime_adapter_argv(spec: &ExternalAgentCommand) -> Result<Vec<OsString>> {
    let config = spec.runtime_adapter.clone().unwrap_or_else(|| {
        RuntimeAdapterConfig::defaults(match spec.invocation {
            ExternalAgentInvocation::Grok => RuntimeId::Grok,
            ExternalAgentInvocation::Cursor => RuntimeId::Cursor,
            ExternalAgentInvocation::ClaudeCode => RuntimeId::ClaudeCode,
            ExternalAgentInvocation::GeminiCli => RuntimeId::GeminiCli,
            _ => RuntimeId::Codex,
        })
    });
    let context = LaunchContext {
        prompt: &spec.prompt,
        model: spec.model.as_deref(),
        effort: spec.reasoning_effort.as_deref(),
        cwd: &spec.cwd,
        output: &spec.output_last_message,
    };
    if spec.invocation == ExternalAgentInvocation::Grok {
        config.render_grok_os_argv(&context, spec.output_schema.as_deref())
    } else {
        config.render_os_argv(&context)
    }
}

fn codex_supervisor_argv(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
    service_tier: Option<CodexServiceTierOverride>,
) -> Vec<OsString> {
    let mut argv = codex_hardened_argv_with_service_tier(
        spec,
        controls,
        CodexMultiAgentMode::Enabled,
        service_tier,
    );
    argv.extend([
        OsString::from("--enable"),
        OsString::from("goals"),
        OsString::from("--json"),
        OsString::from("--output-last-message"),
        spec.output_last_message.as_os_str().to_os_string(),
    ]);
    if let Some(schema) = &spec.output_schema {
        argv.push(OsString::from("--output-schema"));
        argv.push(schema.as_os_str().to_os_string());
    }
    argv.push(OsString::from("-"));
    argv
}

fn codex_consultant_argv(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Vec<OsString> {
    let mut argv = codex_hardened_argv(spec, controls);
    argv.extend([
        OsString::from("--output-last-message"),
        spec.output_last_message.as_os_str().to_os_string(),
        OsString::from("-"),
    ]);
    argv
}

fn codex_hardened_argv(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Vec<OsString> {
    codex_hardened_argv_with_service_tier(
        spec,
        controls,
        CodexMultiAgentMode::Disabled,
        None,
    )
}

fn codex_hardened_argv_with_service_tier(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
    multi_agent: CodexMultiAgentMode,
    service_tier: Option<CodexServiceTierOverride>,
) -> Vec<OsString> {
    let filesystem_permissions = codex_filesystem_permissions(spec, controls);
    let shell_environment_include_only = codex_shell_environment_include_only(controls);
    let mut argv = vec![
        OsString::from("-a"),
        OsString::from("never"),
        OsString::from("exec"),
        OsString::from("--strict-config"),
        OsString::from("--ignore-user-config"),
        OsString::from("--ignore-rules"),
    ];
    if multi_agent == CodexMultiAgentMode::Disabled {
        // Codex CLI 0.144.4 cannot find the calling thread when collab spawn runs from an
        // ephemeral session, so multi_agent launches must retain their session state.
        argv.push(OsString::from("--ephemeral"));
    }
    argv.extend([
        OsString::from("--cd"),
        spec.cwd.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from("default_permissions=\"maco_external_codex\""),
        OsString::from("-c"),
        OsString::from("permissions.maco_external_codex.network={enabled=false}"),
        OsString::from("-c"),
        OsString::from(filesystem_permissions),
        OsString::from("-c"),
        OsString::from("shell_environment_policy.inherit=\"core\""),
        OsString::from("-c"),
        OsString::from("shell_environment_policy.ignore_default_excludes=false"),
        OsString::from("-c"),
        OsString::from(shell_environment_include_only),
        OsString::from("-c"),
        OsString::from("web_search=\"disabled\""),
    ]);
    for feature in [
        "apps",
        "plugins",
        "hooks",
        "in_app_browser",
        "browser_use",
        "browser_use_full_cdp_access",
        "browser_use_external",
        "computer_use",
        "image_generation",
    ] {
        argv.push(OsString::from("--disable"));
        argv.push(OsString::from(feature));
    }
    argv.push(OsString::from(match multi_agent {
        CodexMultiAgentMode::Enabled => "--enable",
        CodexMultiAgentMode::Disabled => "--disable",
    }));
    argv.push(OsString::from("multi_agent"));
    if let Some(model) = &spec.model {
        argv.push(OsString::from("-m"));
        argv.push(OsString::from(model));
    }
    if let Some(model_provider) = &spec.model_provider {
        argv.push(OsString::from("-c"));
        argv.push(OsString::from(format!(
            "model_provider={}",
            toml_basic_string(model_provider)
        )));
    }
    if let Some(reasoning_effort) = &spec.reasoning_effort {
        argv.push(OsString::from("-c"));
        argv.push(OsString::from(format!(
            "model_reasoning_effort={}",
            toml_basic_string(reasoning_effort)
        )));
    }
    if service_tier == Some(CodexServiceTierOverride::Priority) {
        argv.push(OsString::from("-c"));
        argv.push(OsString::from("service_tier=\"priority\""));
    }
    argv
}

/// Production writable-Codex app-server launch arguments.
fn codex_app_server_argv(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> Vec<OsString> {
    let filesystem_permissions = codex_filesystem_permissions(spec, controls);
    let shell_environment_include_only = codex_shell_environment_include_only(controls);
    let mut argv = vec![
        OsString::from("app-server"),
        OsString::from("--stdio"),
        OsString::from("--strict-config"),
        OsString::from("-c"),
        OsString::from("approval_policy=\"on-request\""),
        OsString::from("-c"),
        OsString::from("approvals_reviewer=\"user\""),
        OsString::from("-c"),
        OsString::from("default_permissions=\"maco_external_codex\""),
        OsString::from("-c"),
        OsString::from("permissions.maco_external_codex.network={enabled=false}"),
        OsString::from("-c"),
        OsString::from(filesystem_permissions),
        OsString::from("-c"),
        OsString::from("shell_environment_policy.inherit=\"core\""),
        OsString::from("-c"),
        OsString::from("shell_environment_policy.ignore_default_excludes=false"),
        OsString::from("-c"),
        OsString::from(shell_environment_include_only),
        OsString::from("-c"),
        OsString::from("web_search=\"disabled\""),
        // app-server has no --ignore-rules flag. A private CODEX_HOME prevents ambient user config,
        // while a zero project-doc budget prevents workspace rule discovery.
        OsString::from("-c"),
        OsString::from("project_doc_max_bytes=0"),
    ];
    for feature in [
        "apps",
        "plugins",
        "hooks",
        "in_app_browser",
        "browser_use",
        "browser_use_full_cdp_access",
        "browser_use_external",
        "computer_use",
        "image_generation",
        "multi_agent",
    ] {
        argv.push(OsString::from("--disable"));
        argv.push(OsString::from(feature));
    }
    if let Some(model) = &spec.model {
        argv.push(OsString::from("-c"));
        argv.push(OsString::from(format!(
            "model={}",
            toml_basic_string(model)
        )));
    }
    if let Some(model_provider) = &spec.model_provider {
        argv.push(OsString::from("-c"));
        argv.push(OsString::from(format!(
            "model_provider={}",
            toml_basic_string(model_provider)
        )));
    }
    if let Some(reasoning_effort) = &spec.reasoning_effort {
        argv.push(OsString::from("-c"));
        argv.push(OsString::from(format!(
            "model_reasoning_effort={}",
            toml_basic_string(reasoning_effort)
        )));
    }
    argv
}

fn codex_shell_environment_include_only(controls: &ProtectedWorktreeControls) -> String {
    let mut keys = vec!["PATH".to_string()];
    if let Some(git) = &controls.managed_git {
        keys.extend(
            [
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_NOSYSTEM",
                "GIT_DIR",
                "GIT_OBJECT_DIRECTORY",
                "GIT_TERMINAL_PROMPT",
                "GIT_WORK_TREE",
            ]
            .into_iter()
            .map(str::to_string),
        );
        let config_count = 2 + usize::from(git.active_commit_hook.is_some());
        for index in 0..config_count {
            keys.push(format!("GIT_CONFIG_KEY_{index}"));
            keys.push(format!("GIT_CONFIG_VALUE_{index}"));
        }
    }
    keys.sort();
    keys.dedup();
    format!(
        "shell_environment_policy.include_only=[{}]",
        keys.iter()
            .map(|key| toml_basic_string(key))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn codex_filesystem_permissions(
    spec: &ExternalAgentCommand,
    controls: &ProtectedWorktreeControls,
) -> String {
    let mut path_permissions = BTreeMap::<String, &'static str>::new();
    for control in controls
        .read_only_roots
        .iter()
        .chain(&controls.read_only_files)
    {
        if let Some(absolute) = control.absolute.to_str() {
            path_permissions.insert(absolute.to_string(), "read");
        }
    }
    if let Some(git) = &controls.managed_git {
        for path in git
            .common_read_only_roots
            .iter()
            .chain(&git.common_read_only_files)
        {
            if let Some(path) = path.to_str() {
                path_permissions.insert(path.to_string(), "read");
            }
        }
        if let Some(path) = git.worktree_git_dir.to_str() {
            path_permissions.insert(path.to_string(), "read");
        }
        if spec.workspace_access == WorkspaceAccess::ReadWrite {
            if let Some(path) = git.private_git_dir.to_str() {
                path_permissions.insert(path.to_string(), "write");
            }
            for path in &git.fixed_private_read_only_files {
                if let Some(path) = path.to_str() {
                    path_permissions.insert(path.to_string(), "read");
                }
            }
        }
    }
    for path in &controls.exact_read_only_input_files {
        if let Some(path) = path.to_str() {
            path_permissions.insert(path.to_string(), "read");
        }
    }
    for artifact in &controls.exact_writable_artifact_files {
        #[cfg(target_os = "linux")]
        if let Some(path) = artifact.path.parent().and_then(Path::to_str) {
            // Codex's Linux bwrap backend currently treats every direct write rule as a
            // writable root and probes protected descendants below it. A regular-file rule
            // therefore cannot become an executable inner capability. Use the validated private
            // carrier directory for Codex while the independently verified outer systemd layer
            // keeps the carrier read-only and bind-mounts only these held files read-write.
            path_permissions.insert(path.to_string(), "write");
        }
        #[cfg(not(target_os = "linux"))]
        if let Some(path) = artifact.path.to_str() {
            path_permissions.insert(path.to_string(), "write");
        }
    }
    for control in controls
        .read_write_roots
        .iter()
        .chain(&controls.read_write_files)
    {
        if let Some(absolute) = control.absolute.to_str() {
            path_permissions.insert(absolute.to_string(), "write");
        }
    }
    if let Some(parent) = &controls.writable_artifact_root {
        if let Some(path) = parent.to_str() {
            path_permissions.insert(path.to_string(), "write");
        }
    }

    let workspace_access = match spec.workspace_access {
        WorkspaceAccess::ReadOnly => "read",
        WorkspaceAccess::ReadWrite => "write",
    };
    let mut entries = vec![
        "\":minimal\"=\"read\"".to_string(),
        format!("\":workspace_roots\"={{\".\"=\"{workspace_access}\"}}"),
    ];
    entries.extend(path_permissions.into_iter().map(|(path, access)| {
        format!("{}={}", toml_basic_string(&path), toml_basic_string(access))
    }));
    format!(
        "permissions.maco_external_codex.filesystem={{{}}}",
        entries.join(",")
    )
}

fn toml_basic_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len().saturating_add(2));
    escaped.push('"');
    for character in value.chars() {
        match character {
            '\u{0008}' => escaped.push_str("\\b"),
            '\t' => escaped.push_str("\\t"),
            '\n' => escaped.push_str("\\n"),
            '\u{000c}' => escaped.push_str("\\f"),
            '\r' => escaped.push_str("\\r"),
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            character if character.is_control() && u32::from(character) <= 0xffff => {
                escaped.push_str(&format!("\\u{:04X}", u32::from(character)));
            }
            character if character.is_control() => {
                escaped.push_str(&format!("\\U{:08X}", u32::from(character)));
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

pub(crate) fn codex_usage_from_jsonl(bytes: &[u8]) -> Result<Option<Usage>> {
    let contents =
        std::str::from_utf8(bytes).context("Codex JSONL usage capture is not valid UTF-8")?;
    let mut aggregate = Usage::default();
    let mut observed = false;
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: serde_json::Value = serde_json::from_str(line).with_context(|| {
            format!(
                "Codex JSONL usage capture line {} is not valid JSON",
                index.saturating_add(1)
            )
        })?;
        if event.get("type").and_then(serde_json::Value::as_str) != Some("turn.completed") {
            continue;
        }
        let usage = event
            .get("usage")
            .and_then(serde_json::Value::as_object)
            .context("Codex turn.completed event omitted its usage object")?;
        let input_tokens = usage
            .get("input_tokens")
            .and_then(serde_json::Value::as_u64)
            .context("Codex turn.completed usage omitted input_tokens")?;
        let output_tokens = usage
            .get("output_tokens")
            .and_then(serde_json::Value::as_u64)
            .context("Codex turn.completed usage omitted output_tokens")?;
        let usage = Usage {
            input_tokens: usize::try_from(input_tokens)
                .context("Codex input token count does not fit this platform")?,
            output_tokens: usize::try_from(output_tokens)
                .context("Codex output token count does not fit this platform")?,
            total_tokens: 0,
        };
        aggregate = aggregate.saturating_add(usage);
        observed = true;
    }
    Ok(observed.then_some(aggregate))
}

fn claude_consultant_argv() -> Vec<OsString> {
    vec![
        OsString::from("-p"),
        OsString::from("--output-format"),
        OsString::from("json"),
    ]
}

fn allowed_env(
    invocation: ExternalAgentInvocation,
    program_trust: ExternalProgramTrust,
) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        ("TERM".to_string(), "dumb".to_string()),
    ]);
    if program_trust == ExternalProgramTrust::TrustedSystemCodex
        && matches!(
            invocation,
            ExternalAgentInvocation::CodexSupervisor | ExternalAgentInvocation::CodexConsultant
        )
    {
        for key in ["OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"] {
            if let Ok(value) = env::var(key) {
                if (MIN_CREDENTIAL_BYTES..=MAX_CREDENTIAL_BYTES).contains(&value.len())
                    && !value.contains(['\n', '\r', '\0'])
                {
                    environment.insert(key.to_string(), value);
                }
            }
        }
    }
    environment.insert("PATH".to_string(), TRUSTED_PATH.to_string());
    let trusted_ca = Path::new("/etc/ssl/certs/ca-bundle.crt");
    if trusted_ca.is_file() {
        environment.insert(
            "SSL_CERT_FILE".to_string(),
            trusted_ca.display().to_string(),
        );
        environment.insert(
            "NIX_SSL_CERT_FILE".to_string(),
            trusted_ca.display().to_string(),
        );
    }
    environment
}

fn command_display(program: &Path, argv: &[OsString]) -> Vec<String> {
    let mut command = Vec::with_capacity(argv.len() + 1);
    command.push(display_os_argument(program.as_os_str()));
    command.extend(
        argv.iter()
            .map(|argument| display_os_argument(argument.as_os_str())),
    );
    command
}

#[cfg(unix)]
fn os_argument_bytes(argument: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    argument.as_bytes().to_vec()
}

#[cfg(target_os = "windows")]
fn os_argument_bytes(argument: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    argument.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(not(any(unix, target_os = "windows")))]
fn os_argument_bytes(argument: &OsStr) -> Vec<u8> {
    argument.to_string_lossy().as_bytes().to_vec()
}

fn display_os_argument(argument: &OsStr) -> String {
    argument.to_str().map(str::to_string).unwrap_or_else(|| {
        let bytes = os_argument_bytes(argument);
        let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        format!("<non-unicode-argv:{encoded}>")
    })
}

fn ensure_existing_output_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!(
            "external-agent artifact path must be absolute: {}",
            path.display()
        );
    }
    let parent = path
        .parent()
        .with_context(|| format!("path must have a parent directory: {}", path.display()))?;
    ensure_existing_directory_without_symlinks(parent)
}

fn ensure_existing_directory_without_symlinks(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                current.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                bail!(
                    "external-agent path may not contain '..': {}",
                    path.display()
                );
            }
            std::path::Component::Normal(component) => {
                current.push(component);
                let metadata = fs::symlink_metadata(&current).with_context(|| {
                    format!("failed to inspect artifact ancestor {}", current.display())
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!(
                        "external-agent artifact ancestor is not a non-symlink directory: {}",
                        current.display()
                    );
                }
            }
        }
    }
    Ok(())
}

fn summarize_redacted_output(
    output: &CapturedBytes,
    credential_redactor: &CredentialRedactor,
) -> CapturedOutput {
    let bytes = credential_redactor.redact_bytes(output.as_bytes());
    let text = String::from_utf8_lossy(&bytes);
    let mut chars = text.chars();
    let value = chars.by_ref().take(OUTPUT_CHAR_LIMIT).collect::<String>();
    CapturedOutput {
        text: value,
        truncated: output.is_truncated() || chars.next().is_some(),
        bytes,
        target_launch_attempted: false,
        run_metadata: ExternalAgentRunMetadata::default(),
    }
}

fn write_redacted_json_log(
    reservation: &mut ReservedOutputFile,
    bytes: &[u8],
    credential_redactor: &CredentialRedactor,
) -> Result<()> {
    let redacted = credential_redactor.redact_bytes(bytes);
    reservation.write_bytes_atomic(&redacted, OUTPUT_TEE_LIMIT_BYTES)
}

fn replace_report_stdout(report: &mut ExternalAgentRun, mut stdout: CapturedOutput) {
    stdout.run_metadata = std::mem::take(&mut report.stdout.run_metadata);
    report.stdout = stdout;
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
mod nixos_identity_regression_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn trusted_ancestor_permission_decision_allows_only_root_owned_sticky_writable_directories() {
        use ExecutableAncestorPermissionDecision::{Accept, RejectOwnership, RejectWritable};

        assert_eq!(
            executable_ancestor_permission_decision(0o1775, 0, true, true),
            Accept
        );
        assert_eq!(
            executable_ancestor_permission_decision(0o0775, 0, true, true),
            RejectWritable
        );
        assert_eq!(
            executable_ancestor_permission_decision(0o0757, 0, true, true),
            RejectWritable
        );
        assert_eq!(
            executable_ancestor_permission_decision(0o1775, 1000, true, true),
            RejectWritable
        );
        assert_eq!(
            executable_ancestor_permission_decision(0o1775, 0, false, true),
            RejectWritable
        );
        assert_eq!(
            executable_ancestor_permission_decision(0o0755, 1000, true, true),
            RejectOwnership
        );
        assert_eq!(
            executable_ancestor_permission_decision(0o0755, 0, true, true),
            Accept
        );
    }

    #[cfg(unix)]
    #[test]
    fn codex_auth_symlinked_home_canonical_target_metadata_is_trusted() -> Result<()> {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir()?;
        let target = temp.path().join("codex-home-target");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
        let selected = temp.path().join("selected-codex-home");
        symlink(&target, &selected)?;

        let canonical_target = fs::canonicalize(&selected)?;
        assert_eq!(canonical_target, fs::canonicalize(&target)?);
        let metadata = fs::symlink_metadata(&canonical_target)?;
        assert!(!metadata.file_type().is_symlink());
        // SAFETY: geteuid has no preconditions and does not access Rust memory.
        let effective_uid = unsafe { libc::geteuid() };
        assert_eq!(
            codex_auth_directory_trust_decision(
                metadata.permissions().mode(),
                metadata.uid(),
                metadata.is_dir(),
                effective_uid,
            ),
            CodexAuthDirectoryTrustDecision::Accept
        );
        assert_eq!(
            codex_auth_directory_trust_decision(0o755, 0, true, effective_uid),
            CodexAuthDirectoryTrustDecision::Accept
        );

        let replacement = temp.path().join("replacement-codex-home");
        fs::create_dir(&replacement)?;
        fs::remove_file(&selected)?;
        symlink(&replacement, &selected)?;
        assert_ne!(fs::canonicalize(&selected)?, canonical_target);
        assert_eq!(canonical_target, fs::canonicalize(&target)?);
        Ok(())
    }

    #[test]
    fn codex_exec_and_app_server_argv_use_exact_path_only_legacy_shell_policy() {
        let command = ExternalAgentCommand::codex(
            "codex",
            "/workspace",
            "/run/prompt.md",
            "/run/events.jsonl",
            "/run/report.json",
            Duration::from_secs(1),
        );
        let controls = ProtectedWorktreeControls::default();
        let expected = vec![
            OsString::from("-c"),
            OsString::from("shell_environment_policy.inherit=\"core\""),
            OsString::from("-c"),
            OsString::from("shell_environment_policy.ignore_default_excludes=false"),
            OsString::from("-c"),
            OsString::from("shell_environment_policy.include_only=[\"PATH\"]"),
        ];

        for (label, argv) in [
            ("exec", codex_hardened_argv(&command, &controls)),
            ("app-server", codex_app_server_argv(&command, &controls)),
        ] {
            let inherit_index = argv
                .iter()
                .position(|argument| argument == "shell_environment_policy.inherit=\"core\"")
                .expect("path-only shell policy inherit override");
            let policy_start = inherit_index
                .checked_sub(1)
                .expect("shell policy inherit override must follow -c");
            assert_eq!(
                argv.get(policy_start..policy_start + expected.len()),
                Some(expected.as_slice()),
                "unexpected {label} shell policy argv"
            );
            assert_eq!(
                argv.iter()
                    .filter(|argument| {
                        argument
                            .to_string_lossy()
                            .starts_with("shell_environment_policy.")
                    })
                    .count(),
                3,
                "unexpected additional {label} shell policy override"
            );
            assert!(!argv.iter().any(|argument| {
                argument
                    .to_string_lossy()
                    .starts_with("shell_environment_policy.set=")
            }));
        }
    }
}
