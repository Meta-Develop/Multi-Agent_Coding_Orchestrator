//! Operator declarations refer only to exact files already in the managed snapshot.
//! A task's prose and a restored receipt confer no file access or launch authority.
use super::*;
use crate::process_runner::resolve_existing_path_without_symlinks;

const MAX_SOURCE_INPUTS: usize = 8;
#[cfg(test)]
thread_local! {
    static TEST_EMPTY_SOURCE_READER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TEST_SKIP_INNER_SOURCE_SANDBOX: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResearcherSourceInput {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

/// Parent observations only; deserializing this record never grants file access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResearcherInputReceipt {
    path: PathBuf,
    sha256: String,
    bytes: usize,
    identity: Option<(u64, u64)>,
    child_profile_visible: bool,
    #[serde(default)]
    input_path: String,
    #[serde(default)]
    expected_sha256: String,
    #[serde(default)]
    regular_file: bool,
    #[serde(default)]
    symlink: Option<bool>,
    #[serde(default)]
    outer_preflight: SourceInputCheck,
    #[serde(default)]
    inner_preflight: SourceInputCheck,
    #[serde(default)]
    pre_provider_revalidation: SourceInputCheck,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum SourceInputCheck {
    #[default]
    NotAttempted,
    Passed {
        sha256: String,
        bytes: usize,
    },
    Refused {
        reason: SourceInputRefusal,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed_sha256: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        observed_bytes: Option<usize>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
enum SourceInputRefusal {
    #[error("preparation_failed")]
    PreparationFailed,
    #[error("process_failed")]
    ProcessFailed,
    #[error("read_mismatch")]
    ReadMismatch,
    #[error("identity_or_content_changed")]
    IdentityOrContentChanged,
    #[error("packaged_codex_runtime_not_visible: codex-resources/bwrap and the package executable are not covered by the sandbox runtime bindings")]
    PackagedRuntimeNotVisible,
    #[error("sandbox_helper_unavailable: codex-resources/bwrap")]
    SandboxHelperUnavailable,
    #[error("sandbox_executable_unavailable")]
    SandboxExecutableUnavailable,
    #[error("sandbox_permission_denied")]
    SandboxPermissionDenied,
    #[error("process_timed_out")]
    ProcessTimedOut,
    #[error("process_cancelled")]
    ProcessCancelled,
    #[error("process_spawn_failed")]
    ProcessSpawnFailed,
    #[error("containment_unverified")]
    ContainmentUnverified,
}

#[derive(Debug, thiserror::Error)]
#[error("declared source input inner Codex sandbox refused: {0}")]
struct InnerSourceInputRefusal(SourceInputRefusal);

// Child text is untrusted. Inspect only a bounded prefix, then retain a fixed
// failure class, never stderr, argv, helper paths, or configuration contents.
fn inner_source_input_failure(output: &ProcessOutput) -> SourceInputRefusal {
    if output.timed_out {
        return SourceInputRefusal::ProcessTimedOut;
    }
    if !output.process_tree.is_verified_empty() || !output.side_effects.is_verified() {
        return SourceInputRefusal::ContainmentUnverified;
    }
    let stderr = output.stderr.as_bytes();
    let stderr = &stderr[..stderr.len().min(8192)];
    let contains = |needle: &[u8]| stderr.windows(needle.len()).any(|part| part == needle);
    if contains(b"bubblewrap is unavailable") {
        SourceInputRefusal::SandboxHelperUnavailable
    } else if contains(b"bwrap: execvp") && contains(b"No such file or directory") {
        SourceInputRefusal::SandboxExecutableUnavailable
    } else if contains(b"bwrap:")
        && (contains(b"Permission denied") || contains(b"Operation not permitted"))
    {
        SourceInputRefusal::SandboxPermissionDenied
    } else {
        SourceInputRefusal::ProcessFailed
    }
}

impl ResearcherInputReceipt {
    /// Export only the operator's already-retained snapshot-relative path.
    pub(crate) fn retained(&self) -> Self {
        let mut receipt = self.clone();
        receipt.path = PathBuf::from(&self.input_path);
        receipt
    }

    pub(crate) fn matches_declaration(&self, input: &ResearcherSourceInput) -> bool {
        self.path == Path::new(&input.path)
            && self.input_path == input.path
            && self.expected_sha256 == input.sha256
    }

    pub(crate) fn proves_release(&self) -> bool {
        let passed = SourceInputCheck::Passed {
            sha256: self.sha256.clone(),
            bytes: self.bytes,
        };
        self.sha256 == self.expected_sha256
            && self.bytes > 0
            && self.bytes <= MAX_PROMPT_BYTES
            && self.identity.is_some()
            && self.regular_file
            && self.symlink == Some(false)
            && self.child_profile_visible
            && self.outer_preflight == passed
            && self.inner_preflight == passed
            && self.pre_provider_revalidation == passed
    }

    fn observed_read(&self, succeeded: bool, bytes: &[u8]) -> SourceInputCheck {
        let sha256 = sha256_hex(bytes);
        if succeeded && bytes.len() == self.bytes && sha256 == self.sha256 {
            SourceInputCheck::Passed {
                sha256,
                bytes: bytes.len(),
            }
        } else {
            SourceInputCheck::Refused {
                reason: if succeeded {
                    SourceInputRefusal::ReadMismatch
                } else {
                    SourceInputRefusal::ProcessFailed
                },
                observed_sha256: Some(sha256),
                observed_bytes: Some(bytes.len()),
            }
        }
    }

    fn observed_inner_read(&self, output: &ProcessOutput) -> SourceInputCheck {
        let succeeded = output.safety_sensitive_succeeded();
        let mut check = self.observed_read(succeeded, output.stdout.as_bytes());
        if !succeeded {
            if let SourceInputCheck::Refused { reason, .. } = &mut check {
                *reason = inner_source_input_failure(output);
            }
        }
        check
    }

    fn passed(&self) -> SourceInputCheck {
        SourceInputCheck::Passed {
            sha256: self.sha256.clone(),
            bytes: self.bytes,
        }
    }
}

pub(crate) fn validate_declarations(inputs: &[ResearcherSourceInput]) -> Result<()> {
    if inputs.len() > MAX_SOURCE_INPUTS {
        bail!("Researcher source_inputs exceeds {MAX_SOURCE_INPUTS} exact files");
    }
    let mut paths = BTreeSet::new();
    for input in inputs {
        // Use portable path syntax; Windows separators/drive prefixes must not become
        // innocent file names when an operator plan is normalized on Linux.
        if input.path.is_empty()
            || input.path.len() > 1024
            || input.path.contains(['\\', ':'])
            || input.path.chars().any(char::is_control)
            || input
                .path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".." || part.starts_with('.'))
            || !paths.insert(&input.path)
        {
            bail!(
                "source input must be a unique, non-hidden snapshot-relative file: {:?}",
                input.path
            );
        }
        if input.sha256.len() != 64
            || !input
                .sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            bail!("source input requires a lowercase SHA256: {:?}", input.path);
        }
    }
    Ok(())
}

pub(crate) fn validate_snapshot(
    workspace: &Path,
    inputs: &[ResearcherSourceInput],
) -> Result<Vec<ResearcherInputReceipt>> {
    validate_declarations(inputs)?;
    inputs
        .iter()
        .map(|input| {
            let path = resolve_existing_path_without_symlinks(workspace, Path::new(&input.path))
                .with_context(|| {
                    format!(
                        "declared Researcher source input is unavailable: {}",
                        input.path
                    )
                })?;
            let metadata = fs::symlink_metadata(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() != 1 {
                    bail!(
                        "source input must not have hard-link aliases: {}",
                        input.path
                    );
                }
            }
            if !metadata.is_file() {
                bail!("source input is not a regular file: {}", input.path);
            }
            #[cfg(unix)]
            let identity = {
                use std::os::unix::fs::MetadataExt;
                Some((metadata.dev(), metadata.ino()))
            };
            #[cfg(not(unix))]
            let identity = None;
            let bytes = read_bounded_regular_file_nofollow(&path, MAX_PROMPT_BYTES)?;
            let observed_sha256 = sha256_hex(&bytes);
            if bytes.is_empty() || observed_sha256 != input.sha256 {
                bail!(
                    "source input is empty or its SHA256 changed: {}",
                    input.path
                );
            }
            Ok(ResearcherInputReceipt {
                path,
                sha256: observed_sha256,
                bytes: bytes.len(),
                identity,
                child_profile_visible: false,
                input_path: input.path.clone(),
                expected_sha256: input.sha256.clone(),
                regular_file: metadata.is_file(),
                symlink: Some(metadata.file_type().is_symlink()),
                outer_preflight: SourceInputCheck::NotAttempted,
                inner_preflight: SourceInputCheck::NotAttempted,
                pre_provider_revalidation: SourceInputCheck::NotAttempted,
            })
        })
        .collect()
}

pub(super) fn validate_command(spec: &ExternalAgentCommand) -> Result<Vec<ResearcherInputReceipt>> {
    if spec.researcher_source_inputs.is_empty() {
        return Ok(Vec::new());
    }
    if spec.workspace_access != WorkspaceAccess::ReadOnly
        || spec.invocation != ExternalAgentInvocation::CodexSupervisor
        || spec
            .agent_lifecycle
            .as_ref()
            .is_none_or(|lifecycle| lifecycle.role != "researcher")
    {
        bail!("source inputs require a read-only Codex Researcher launch");
    }
    let receipts = validate_snapshot(&spec.cwd, &spec.researcher_source_inputs)?;
    for receipt in &receipts {
        if !spec.read_only_input_files.contains(&receipt.path) {
            bail!("source input is missing its exact read-only launch permission");
        }
    }
    Ok(receipts)
}

pub(super) fn prepare_source_inputs(
    spec: &ExternalAgentCommand,
    profile: Option<&SideEffectConfinementProfile>,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    report: &mut ExternalAgentRun,
) -> Result<()> {
    if spec.researcher_source_inputs.is_empty() {
        return Ok(());
    }
    // Preserve the fixed version observation and aggregate quiescence across ALL
    // probes. A later reader must not erase earlier unverified process ownership.
    let mut evidence = EnvironmentPreflightProcessEvidence {
        started: report
            .stdout
            .run_metadata
            .environment_preflight_process_started,
        unconfirmed_child: report
            .stdout
            .run_metadata
            .environment_preflight_process_started
            && !report
                .process_tree
                .is_some_and(ProcessTreeEvidence::is_verified_empty),
        process_tree: report.process_tree,
        side_effects: report.side_effects,
        fixed_version_probe_evidence: report
            .stdout
            .run_metadata
            .fixed_version_probe_evidence
            .clone(),
        version_probe_receipts: report.stdout.run_metadata.version_probe_receipts.clone(),
    };
    let started = Instant::now();
    let mut receipts = Vec::new();
    let result = (|| {
        receipts = validate_command(spec)?;
        let snapshots = probe_source_inputs(
            spec,
            profile,
            timeout,
            cancellation,
            &mut evidence,
            &mut receipts,
        )?;
        // Mark setup refusals too, without retaining helper paths or diagnostics.
        for receipt in &mut receipts {
            receipt.inner_preflight = SourceInputCheck::Refused {
                reason: SourceInputRefusal::PreparationFailed,
                observed_sha256: None,
                observed_bytes: None,
            };
        }
        probe_source_inputs_in_inner_sandbox(
            spec,
            profile,
            timeout.saturating_sub(started.elapsed()),
            cancellation,
            &mut receipts,
            &snapshots,
            &mut evidence,
        )?;
        Ok(snapshots)
    })();
    report.stdout.run_metadata.researcher_input_receipts = receipts;
    retain_environment_preflight_process_evidence(report, &evidence);
    // This private witness also covers later preparation/bookkeeping refusals.
    // The target-launch boundary must discard it before attempting any release.
    report
        .stdout
        .run_metadata
        .local_source_probe_refusal_quiescent = !report.stdout.target_launch_attempted
        && report
            .stdout
            .run_metadata
            .environment_preflight_quiescence_verified;
    match result {
        Ok(snapshots) => {
            report.stdout.run_metadata.read_only_input_snapshots = snapshots;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn probe_source_inputs_in_inner_sandbox(
    spec: &ExternalAgentCommand,
    profile: Option<&SideEffectConfinementProfile>,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    receipts: &mut [ResearcherInputReceipt],
    snapshots: &[crate::process_runner::ReadOnlyInputSnapshot],
    evidence: &mut EnvironmentPreflightProcessEvidence,
) -> Result<()> {
    if receipts.is_empty() {
        return Ok(());
    }
    #[cfg(test)]
    if TEST_SKIP_INNER_SOURCE_SANDBOX.with(|flag| flag.replace(false)) {
        for receipt in receipts {
            receipt.inner_preflight = SourceInputCheck::NotAttempted;
        }
        return Ok(());
    }
    let profile = profile.context("inner source input visibility requires verified containment")?;
    let program = match resolve_external_program(&spec.program, &spec.cwd) {
        Ok(program) => program,
        Err(error) if error.is::<PackagedCodexRuntimeNotVisible>() => {
            for receipt in receipts {
                receipt.inner_preflight = SourceInputCheck::Refused {
                    reason: SourceInputRefusal::PackagedRuntimeNotVisible,
                    observed_sha256: None,
                    observed_bytes: None,
                };
            }
            return Err(
                InnerSourceInputRefusal(SourceInputRefusal::PackagedRuntimeNotVisible).into(),
            );
        }
        Err(error) => {
            return Err(error.context("selected Codex sandbox helper could not be resolved"))
        }
    };
    let trusted = external_program_trust_for_resolved_executable(spec, &program)
        == ExternalProgramTrust::TrustedSystemCodex;
    #[cfg(test)]
    let trusted = trusted || pinned_test_sandbox_program(&program)?;
    if !trusted {
        bail!("inner source input visibility requires the selected TrustedSystemCodex executable");
    }
    validate_external_program_identity(&program, false)
        .context("selected Codex sandbox helper identity was rejected")?;
    let controls = protected_worktree_controls(spec)?;
    let permissions = codex_filesystem_permissions(spec, &controls);
    let reader = ["/usr/bin/cat", "/bin/cat", "/run/current-system/sw/bin/cat"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .context("trusted inner source-input reader is unavailable")?;
    let reader = fs::canonicalize(reader)?;
    validate_external_program_identity(&reader, false)?;
    let started = Instant::now();
    for receipt in receipts.iter_mut() {
        receipt.inner_preflight = SourceInputCheck::NotAttempted;
    }
    for receipt in receipts {
        receipt.inner_preflight = SourceInputCheck::Refused {
            reason: SourceInputRefusal::ProcessFailed,
            observed_sha256: None,
            observed_bytes: None,
        };
        let args = vec![
            OsString::from("sandbox"),
            OsString::from("--permission-profile"),
            OsString::from("maco_external_codex"),
            OsString::from("--cd"),
            spec.cwd.as_os_str().to_os_string(),
            OsString::from("-c"),
            OsString::from("permissions.maco_external_codex.network={enabled=false}"),
            OsString::from("-c"),
            OsString::from(&permissions),
            OsString::from("--"),
            reader.as_os_str().to_os_string(),
            OsString::from("--"),
            receipt.path.as_os_str().to_os_string(),
        ];
        let mut probe = ProcessSpec::direct(
            "Researcher source input inner sandbox visibility",
            &program,
            &args,
            &spec.cwd,
            MAX_PROMPT_BYTES + 1,
        )
        .with_stdin(StdinMode::Null)
        .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
        .with_private_runtime_home(true)
        .with_private_runtime_codex_home(true)
        .with_side_effect_confinement(profile.clone())
        .with_timeout(Some(timeout.saturating_sub(started.elapsed())));
        probe.read_only_input_snapshots = snapshots.to_vec();
        let output = match run_process_cancellable(probe, cancellation) {
            Ok(output) => {
                evidence.record_output(&output);
                output
            }
            Err(error) => {
                evidence.record_error(&error);
                let reason = match error {
                    ProcessRunError::Cancelled { .. } => SourceInputRefusal::ProcessCancelled,
                    ProcessRunError::SetupTimeout { .. } => SourceInputRefusal::ProcessTimedOut,
                    ProcessRunError::Spawn { .. } => SourceInputRefusal::ProcessSpawnFailed,
                    ProcessRunError::ContainmentUnavailable { .. }
                    | ProcessRunError::ProcessOwnership { .. }
                    | ProcessRunError::EnvironmentFailure { .. } => {
                        SourceInputRefusal::ContainmentUnverified
                    }
                    _ => SourceInputRefusal::ProcessFailed,
                };
                receipt.inner_preflight = SourceInputCheck::Refused {
                    reason,
                    observed_sha256: None,
                    observed_bytes: None,
                };
                return Err(InnerSourceInputRefusal(reason).into());
            }
        };
        receipt.inner_preflight = receipt.observed_inner_read(&output);
        if let SourceInputCheck::Refused { reason, .. } = receipt.inner_preflight {
            return Err(InnerSourceInputRefusal(reason).into());
        }
    }
    Ok(())
}

#[cfg(test)]
fn pinned_test_sandbox_program(program: &Path) -> Result<bool> {
    let Some(expected) = env::var_os("MACO_TEST_CODEX_SANDBOX_PROGRAM") else {
        return Ok(false);
    };
    let expected = fs::canonicalize(expected)?;
    if expected != program {
        return Ok(false);
    }
    Ok(sha256_hex(&fs::read(program)?)
        == "2b3edc9cdfd1717fba3dbc92817205a8a2c7511d459e456d4817eeff6f78ed7a")
}

fn probe_source_inputs(
    spec: &ExternalAgentCommand,
    profile: Option<&SideEffectConfinementProfile>,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    evidence: &mut EnvironmentPreflightProcessEvidence,
    receipts: &mut [ResearcherInputReceipt],
) -> Result<Vec<crate::process_runner::ReadOnlyInputSnapshot>> {
    if receipts.is_empty() {
        return Ok(Vec::new());
    }
    for receipt in receipts.iter_mut() {
        receipt.outer_preflight = SourceInputCheck::Refused {
            reason: SourceInputRefusal::PreparationFailed,
            observed_sha256: None,
            observed_bytes: None,
        };
    }
    let snapshots = receipts
        .iter()
        .map(|receipt| {
            crate::process_runner::ReadOnlyInputSnapshot::capture(&receipt.path, &receipt.sha256)
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let profile = profile.context("source input visibility requires verified containment")?;
    let program = ["/usr/bin/cat", "/bin/cat", "/run/current-system/sw/bin/cat"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .context("trusted local source-input reader is unavailable")?;
    #[cfg(test)]
    let program = if TEST_EMPTY_SOURCE_READER.with(|flag| flag.replace(false)) {
        Path::new("/usr/bin/true")
    } else {
        program
    };
    let program = fs::canonicalize(program)?;
    validate_external_program_identity(&program, false)?;
    let started = Instant::now();
    for receipt in receipts.iter_mut() {
        receipt.outer_preflight = SourceInputCheck::NotAttempted;
    }
    for receipt in receipts.iter_mut() {
        receipt.outer_preflight = SourceInputCheck::Refused {
            reason: SourceInputRefusal::ProcessFailed,
            observed_sha256: None,
            observed_bytes: None,
        };
        let mut probe = ProcessSpec::direct(
            "Researcher source input visibility",
            &program,
            [OsStr::new("--"), receipt.path.as_os_str()],
            &spec.cwd,
            MAX_PROMPT_BYTES + 1,
        )
        .with_stdin(StdinMode::Null)
        .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
        .with_private_runtime_home(true)
        .with_private_runtime_codex_home(true)
        .with_side_effect_confinement(profile.clone())
        .with_timeout(Some(timeout.saturating_sub(started.elapsed())));
        probe.read_only_input_snapshots = snapshots.clone();
        let output = match run_process_cancellable(probe, cancellation) {
            Ok(output) => {
                evidence.record_output(&output);
                output
            }
            Err(error) => {
                evidence.record_error(&error);
                return Err(error.into());
            }
        };
        receipt.outer_preflight = receipt.observed_read(
            output.safety_sensitive_succeeded(),
            output.stdout.as_bytes(),
        );
        if !matches!(receipt.outer_preflight, SourceInputCheck::Passed { .. }) {
            bail!("declared source input is not readable with its bound hash in the child profile: {}", receipt.path.display());
        }
        receipt.child_profile_visible = true;
    }
    revalidate_source_inputs(spec, receipts)?;
    Ok(snapshots)
}

pub(super) fn revalidate_source_inputs(
    spec: &ExternalAgentCommand,
    receipts: &[ResearcherInputReceipt],
) -> Result<()> {
    let current = validate_command(spec)?;
    if current.len() != receipts.len()
        || current.iter().zip(receipts).any(|(a, b)| {
            a.path != b.path
                || a.sha256 != b.sha256
                || a.bytes != b.bytes
                || a.identity != b.identity
                || !b.child_profile_visible
        })
    {
        bail!("source input declaration, content or visibility receipt changed");
    }
    Ok(())
}

/// Called at the actual provider boundary, separately from the earlier probe check.
pub(super) fn revalidate_before_provider(
    spec: &ExternalAgentCommand,
    receipts: &mut [ResearcherInputReceipt],
) -> Result<()> {
    let result = revalidate_source_inputs(spec, receipts);
    for receipt in receipts {
        receipt.pre_provider_revalidation = if result.is_ok() {
            receipt.passed()
        } else {
            SourceInputCheck::Refused {
                reason: SourceInputRefusal::IdentityOrContentChanged,
                observed_sha256: None,
                observed_bytes: None,
            }
        };
    }
    result
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use anyhow::ensure;

    const SOURCE: &[u8] = b"diff --git a/src/budget.rs b/src/budget.rs\n--- a/src/budget.rs\n+++ b/src/budget.rs\n@@ -1 +1 @@\n-total.saturating_add(next)\n+total.checked_add(next).ok_or(BudgetOverflow)?\n";

    /// Synthetic successful read observations for custody/serialization tests only.
    #[cfg(target_os = "linux")]
    pub(crate) fn attach_synthetic_receipts(
        run: &mut ExternalAgentRun,
        command: &ExternalAgentCommand,
    ) -> Result<()> {
        let mut receipts = validate_snapshot(&command.cwd, &command.researcher_source_inputs)?;
        for receipt in &mut receipts {
            receipt.child_profile_visible = true;
            receipt.outer_preflight = receipt.passed();
            receipt.inner_preflight = receipt.passed();
        }
        revalidate_before_provider(command, &mut receipts)?;
        run.stdout.run_metadata.researcher_input_receipts = receipts;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn source_inputs_read_outcomes_and_release_receipts_are_independent() -> Result<()> {
        let (_root, command) = fixture()?;
        let mut receipts = validate_command(&command)?;
        let receipt = &mut receipts[0];
        assert!(matches!(
            receipt.observed_read(true, SOURCE),
            SourceInputCheck::Passed { .. }
        ));
        assert!(matches!(
            receipt.observed_read(true, b""),
            SourceInputCheck::Refused {
                reason: SourceInputRefusal::ReadMismatch,
                observed_bytes: Some(0),
                ..
            }
        ));
        assert!(matches!(
            receipt.observed_read(false, SOURCE),
            SourceInputCheck::Refused {
                reason: SourceInputRefusal::ProcessFailed,
                ..
            }
        ));
        receipt.outer_preflight = receipt.observed_read(true, SOURCE);
        receipt.child_profile_visible = true;
        revalidate_before_provider(&command, &mut receipts)?;
        assert!(
            !receipts[0].proves_release(),
            "outer read cannot stand in for inner read"
        );
        receipts[0].inner_preflight = receipts[0].observed_read(true, SOURCE);
        assert!(receipts[0].proves_release());
        let retained = receipts[0].retained();
        assert!(retained.matches_declaration(&command.researcher_source_inputs[0]));
        assert!(!retained.path.is_absolute());
        Ok(())
    }

    pub(crate) fn fixture() -> Result<(tempfile::TempDir, ExternalAgentCommand)> {
        let root = tempfile::tempdir()?;
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace)?;
        let path = workspace.join("source.diff");
        fs::write(&path, SOURCE)?;
        let mut command = ExternalAgentCommand::codex(
            "/provider-must-not-be-invoked",
            &workspace,
            root.path().join("prompt"),
            root.path().join("log"),
            root.path().join("result"),
            Duration::from_secs(30),
        )
        .with_workspace_access(WorkspaceAccess::ReadOnly)
        .with_read_only_input_file(path)
        .with_agent_lifecycle(&workspace, "researcher", "source-input-test", "researcher");
        command.researcher_source_inputs = vec![ResearcherSourceInput {
            path: "source.diff".into(),
            sha256: sha256_hex(SOURCE),
        }];
        Ok((root, command))
    }

    #[cfg(target_os = "linux")]
    fn packaged_runtime(root: &Path) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let package = root.join("home/user/codex-package");
        fs::create_dir_all(package.join("bin"))?;
        fs::create_dir(package.join("codex-resources"))?;
        fs::create_dir(package.join("codex-path"))?;
        fs::write(
            package.join("codex-package.json"),
            br#"{"layoutVersion":1,"version":"0.144.4","target":"x86_64-unknown-linux-musl","variant":"codex","entrypoint":"bin/codex","resourcesDir":"codex-resources","pathDir":"codex-path"}"#,
        )?;
        let program = package.join("bin/codex");
        fs::write(&program, b"#!/bin/sh\nexit 99\n")?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700))?;
        fs::write(package.join("codex-resources/bwrap"), b"fake helper")?;
        Ok(program)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_inputs_packaged_runtime_outer_refuses_before_launch() -> Result<()> {
        let (root, mut command) = fixture()?;
        command.program = packaged_runtime(root.path())?;
        let controls = ProtectedWorktreeControls {
            writable_artifact_root: Some(root.path().to_path_buf()),
            ..ProtectedWorktreeControls::default()
        };
        let error = external_side_effect_profile(
            &command,
            &command.program,
            ExternalProgramTrust::TrustedSystemCodex,
            &controls,
        )
        .expect_err("the outer bin-only binding must not admit a packaged runtime");
        assert!(error
            .to_string()
            .contains("packaged_codex_runtime_not_visible"));
        assert!(error.to_string().contains("codex-resources/bwrap"));
        assert!(!command.json_log.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_inputs_packaged_runtime_inner_refuses_before_launch() -> Result<()> {
        let (root, mut command) = fixture()?;
        command.program = packaged_runtime(root.path())?;
        let profile = SideEffectConfinementProfile::ExternalCodex(ExternalCodexProfile::read_only(
            &command.cwd,
        ));
        let mut receipts = validate_command(&command)?;
        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        let error = probe_source_inputs_in_inner_sandbox(
            &command,
            Some(&profile),
            Duration::from_secs(1),
            &ProcessCancellation::new(),
            &mut receipts,
            &[],
            &mut evidence,
        )
        .expect_err("the inner minimal policy cannot execute this package");
        assert!(format!("{error:#}").contains("packaged_codex_runtime_not_visible"));
        assert!(matches!(
            receipts[0].inner_preflight,
            SourceInputCheck::Refused {
                reason: SourceInputRefusal::PackagedRuntimeNotVisible,
                ..
            }
        ));
        assert!(!evidence.started);
        assert!(!command.json_log.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_inputs_packaged_runtime_version_refuses_before_launch() -> Result<()> {
        let (root, command) = fixture()?;
        let program = packaged_runtime(root.path())?;
        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        let failure = preflight_custom_codex_version(
            &program,
            &command.cwd,
            Duration::from_secs(1),
            &ProcessCancellation::new(),
            None,
            &mut evidence,
        )
        .expect_err("a version helper must not bypass package visibility admission");
        assert_eq!(
            failure.failure.category,
            EnvironmentFailureCategory::SandboxUnavailable
        );
        assert!(failure
            .failure
            .summary
            .contains("packaged_codex_runtime_not_visible"));
        assert!(!evidence.started);
        let error = resolve_external_program(&program, &command.cwd).unwrap_err();
        assert!(error.is::<PackagedCodexRuntimeNotVisible>());
        assert!(codex_runtime_model_catalog_failure(&error)
            .summary
            .contains("codex-resources/bwrap"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_inputs_inner_failure_classes_are_bounded_and_redacted() -> Result<()> {
        use std::os::unix::process::ExitStatusExt;
        let (_root, command) = fixture()?;
        let receipt = validate_command(&command)?.remove(0);
        let cases = [
            (
                "bubblewrap is unavailable: no bundled codex-resources/bwrap binary was found /home/private/secret",
                SourceInputRefusal::SandboxHelperUnavailable,
            ),
            (
                "bwrap: execvp /home/private/secret/bin/codex: No such file or directory",
                SourceInputRefusal::SandboxExecutableUnavailable,
            ),
            (
                "bwrap: Creating new namespace failed: Operation not permitted /home/private/secret",
                SourceInputRefusal::SandboxPermissionDenied,
            ),
            ("unrecognized failure /home/private/secret", SourceInputRefusal::ProcessFailed),
        ];
        for (stderr, reason) in cases {
            let mut output = ProcessOutput {
                status: Some(std::process::ExitStatus::from_raw(256)),
                duration: Duration::ZERO,
                timed_out: false,
                process_tree: ProcessTreeEvidence::VerifiedEmpty(
                    ContainmentBackend::SystemdUserService,
                ),
                side_effects: SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::ExternalCodex,
                ),
                stdout: CapturedBytes::default(),
                stderr: CapturedBytes::from_bytes_for_test(stderr.as_bytes()),
                process_error: None,
                stdin_error: None,
            };
            let check = receipt.observed_inner_read(&output);
            assert!(
                matches!(check, SourceInputCheck::Refused { reason: actual, .. } if actual == reason)
            );
            let encoded = serde_json::to_string(&check)?;
            let message = InnerSourceInputRefusal(reason).to_string();
            assert!(!encoded.contains("/home/private"));
            assert!(!message.contains("/home/private"));
            assert!(message.len() < 256);

            output.timed_out = true;
            assert_eq!(
                inner_source_input_failure(&output),
                SourceInputRefusal::ProcessTimedOut
            );
            output.timed_out = false;
            output.side_effects = SideEffectConfinementEvidence::Unverified(
                SideEffectConfinementProfileKind::ExternalCodex,
            );
            assert_eq!(
                inner_source_input_failure(&output),
                SourceInputRefusal::ContainmentUnverified
            );
            output.side_effects = SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            );
            output.stderr = CapturedBytes::from_bytes_for_test(
                format!("{}bubblewrap is unavailable", "x".repeat(8192)).into_bytes(),
            );
            assert_eq!(
                inner_source_input_failure(&output),
                SourceInputRefusal::ProcessFailed
            );
            output.status = Some(std::process::ExitStatus::from_raw(0));
            assert!(matches!(
                receipt.observed_inner_read(&output),
                SourceInputCheck::Refused {
                    reason: SourceInputRefusal::ReadMismatch,
                    ..
                }
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_inputs_packaged_runtime_rejects_unverified_layouts() -> Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};
        for mutation in ["root_symlink", "writable_resources", "manifest_mismatch"] {
            let (root, command) = fixture()?;
            let mut program = packaged_runtime(root.path())?;
            let package = program.parent().unwrap().parent().unwrap();
            match mutation {
                "root_symlink" => {
                    let alias = root.path().join("package-alias");
                    symlink(package, &alias)?;
                    program = alias.join("bin/codex");
                }
                "writable_resources" => fs::set_permissions(
                    package.join("codex-resources"),
                    fs::Permissions::from_mode(0o777),
                )?,
                "manifest_mismatch" => fs::write(
                    package.join("codex-package.json"),
                    br#"{"version":"9.9.9","target":"aarch64-apple-darwin"}"#,
                )?,
                _ => unreachable!(),
            }
            let error = resolve_external_program(&program, &command.cwd)
                .expect_err("unsupported packages must never be admitted on manifest claims");
            assert!(
                format!("{error:#}").contains("packaged_codex_runtime_not_visible"),
                "{mutation}: {error:#}"
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_inputs_snapshot_refusal_preserves_preflight_quiescence() -> Result<()> {
        let (_root, command) = fixture()?;
        let mut report = failed_external_run(
            &command,
            Instant::now(),
            Vec::new(),
            false,
            "preflight".into(),
        );
        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        evidence.record(
            ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService),
            SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            ),
            true,
        );
        retain_environment_preflight_process_evidence(&mut report, &evidence);
        fs::remove_file(command.cwd.join("source.diff"))?;
        prepare_source_inputs(
            &command,
            None,
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut report,
        )
        .expect_err("missing snapshot must refuse before a source reader starts");
        assert!(
            report
                .stdout
                .run_metadata
                .environment_preflight_quiescence_verified
        );
        assert!(
            report
                .stdout
                .run_metadata
                .local_source_probe_refusal_quiescent
        );
        assert!(report
            .stdout
            .run_metadata
            .researcher_input_receipts
            .is_empty());
        assert!(!report.stdout.target_launch_attempted);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_inputs_inner_setup_refusal_preserves_outer_receipt() -> Result<()> {
        let (_root, command) = fixture()?;
        let profile = SideEffectConfinementProfile::ExternalCodex(
            ExternalCodexProfile::read_only(&command.cwd)
                .with_visible_read_only_file(command.cwd.join("source.diff")),
        );
        let mut report = failed_external_run(
            &command,
            Instant::now(),
            Vec::new(),
            false,
            "preflight".into(),
        );
        prepare_source_inputs(
            &command,
            Some(&profile),
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut report,
        )
        .expect_err("nonexistent inner helper must refuse without a provider call");
        let receipt = &report.stdout.run_metadata.researcher_input_receipts[0];
        assert_eq!(receipt.outer_preflight, receipt.passed());
        assert!(matches!(
            receipt.inner_preflight,
            SourceInputCheck::Refused {
                reason: SourceInputRefusal::PreparationFailed,
                ..
            }
        ));
        assert_eq!(
            receipt.pre_provider_revalidation,
            SourceInputCheck::NotAttempted
        );
        assert!(!report.stdout.target_launch_attempted);
        assert!(!command.json_log.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn failed_local_probe(
        command: &ExternalAgentCommand,
        unknown_prior_helper: bool,
    ) -> Result<ExternalAgentRun> {
        let mut profile = ExternalCodexProfile::read_only(&command.cwd);
        for input in &command.researcher_source_inputs {
            profile = profile.with_visible_read_only_file(command.cwd.join(&input.path));
        }
        let profile = SideEffectConfinementProfile::ExternalCodex(profile);
        let mut report = failed_external_run(
            command,
            Instant::now(),
            Vec::new(),
            false,
            "preflight".into(),
        );
        if unknown_prior_helper {
            let mut evidence = EnvironmentPreflightProcessEvidence::default();
            evidence.record(
                ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService),
                SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::ExternalCodex,
                ),
                false,
            );
            retain_environment_preflight_process_evidence(&mut report, &evidence);
        }
        // A successful, contained local reader returning no packet bytes models
        // an actual visibility/hash failure, without running a provider executable.
        TEST_EMPTY_SOURCE_READER.with(|flag| flag.set(true));
        let error = prepare_source_inputs(
            command,
            Some(&profile),
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut report,
        )
        .expect_err("empty local reader must refuse");
        report.error = Some(error.to_string());
        assert!(
            report.error.as_deref().unwrap().contains("not readable"),
            "unexpected local probe refusal: {:?}",
            report.error
        );
        assert!(!report.stdout.target_launch_attempted);
        assert!(!report.publishable);
        let receipt = &report.stdout.run_metadata.researcher_input_receipts[0];
        assert!(matches!(
            receipt.outer_preflight,
            SourceInputCheck::Refused {
                reason: SourceInputRefusal::ReadMismatch,
                ..
            }
        ));
        assert_eq!(receipt.inner_preflight, SourceInputCheck::NotAttempted);
        assert_eq!(
            receipt.pre_provider_revalidation,
            SourceInputCheck::NotAttempted
        );
        Ok(report)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn late_source_refusal(
        command: &ExternalAgentCommand,
        mutation: &str,
        unknown_prior_helper: bool,
    ) -> Result<ExternalAgentRun> {
        let profile = SideEffectConfinementProfile::ExternalCodex(
            ExternalCodexProfile::read_only(&command.cwd)
                .with_visible_read_only_file(command.cwd.join("source.diff")),
        );
        let mut report = failed_external_run(
            command,
            Instant::now(),
            Vec::new(),
            false,
            "preflight".into(),
        );
        if unknown_prior_helper {
            let mut evidence = EnvironmentPreflightProcessEvidence::default();
            evidence.record(
                ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService),
                SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::ExternalCodex,
                ),
                false,
            );
            retain_environment_preflight_process_evidence(&mut report, &evidence);
        }
        TEST_SKIP_INNER_SOURCE_SANDBOX.with(|flag| flag.set(true));
        prepare_source_inputs(
            command,
            Some(&profile),
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut report,
        )?;
        assert!(report.stdout.run_metadata.researcher_input_receipts[0].child_profile_visible);
        let path = command.cwd.join("source.diff");
        match mutation {
            "changed" => fs::write(&path, b"unverified changed source")?,
            "missing" => fs::rename(&path, command.cwd.join("moved.diff"))?,
            "rebound" => {
                fs::rename(&path, command.cwd.join("moved.diff"))?;
                fs::write(&path, SOURCE)?;
            }
            _ => panic!("unknown mutation"),
        }
        let error = revalidate_before_provider(
            command,
            &mut report.stdout.run_metadata.researcher_input_receipts,
        )
        .expect_err("late source mutation must refuse target release");
        record_external_error(
            &mut report,
            format!("Researcher source input changed before target release: {error:#}"),
        );
        assert!(!report.stdout.target_launch_attempted);
        assert!(!report.publishable);
        assert!(!command.json_log.exists());
        assert!(!command.output_last_message.exists());
        assert!(matches!(
            report.stdout.run_metadata.researcher_input_receipts[0].pre_provider_revalidation,
            SourceInputCheck::Refused {
                reason: SourceInputRefusal::IdentityOrContentChanged,
                ..
            }
        ));
        Ok(report)
    }

    #[test]
    fn source_inputs_refuse_missing_changed_undeclared_and_writable_before_launch() -> Result<()> {
        for mutation in ["missing", "changed", "undeclared", "writable"] {
            let (_root, mut command) = fixture()?;
            match mutation {
                "missing" => fs::rename(command.cwd.join("source.diff"), command.cwd.join("away"))?,
                "changed" => fs::write(command.cwd.join("source.diff"), b"different source")?,
                "undeclared" => command.read_only_input_files.clear(),
                "writable" => command.workspace_access = WorkspaceAccess::ReadWrite,
                _ => unreachable!(),
            }
            let run = run_external_agent(&command);
            assert!(
                run.error
                    .as_deref()
                    .is_some_and(|e| e.contains("source input preparation refused")),
                "{mutation}: {run:?}"
            );
            assert!(!run.stdout.target_launch_attempted);
            assert!(!run.publishable);
            assert!(run.codex_parent_evidence.is_none());
            assert!(!command.json_log.exists());
            assert!(!command.output_last_message.exists());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn source_inputs_refuse_symlink_alias_and_replaced_identity() -> Result<()> {
        let (_root, command) = fixture()?;
        let original = command.cwd.join("source.diff");
        let held = command.cwd.join("held.diff");
        let mut receipts = validate_command(&command)?;
        receipts[0].child_profile_visible = true;
        fs::rename(&original, &held)?;
        std::os::unix::fs::symlink(&held, &original)?;
        assert!(validate_command(&command).is_err());
        fs::remove_file(&original)?;
        fs::hard_link(&held, &original)?;
        assert!(validate_command(&command).is_err());
        fs::remove_file(&original)?;
        fs::copy(&held, &original)?;
        assert!(revalidate_source_inputs(&command, &receipts).is_err());
        Ok(())
    }

    #[test]
    fn source_inputs_bound_paths_hashes_and_receipts_are_not_authority() -> Result<()> {
        let (_root, command) = fixture()?;
        let receipts = validate_command(&command)?;
        assert!(
            revalidate_source_inputs(&command, &receipts).is_err(),
            "parent read is not child visibility"
        );
        for path in [
            "/outside.diff",
            "../outside.diff",
            ".agents/private",
            "C:/packet",
            "a\\b",
            "a//b",
        ] {
            let mut inputs = command.researcher_source_inputs.clone();
            inputs[0].path = path.into();
            assert!(validate_declarations(&inputs).is_err(), "{path}");
        }
        let input = &command.researcher_source_inputs[0];
        assert!(validate_declarations(&vec![input.clone(); MAX_SOURCE_INPUTS + 1]).is_err());
        assert!(
            serde_json::from_value::<ResearcherSourceInput>(serde_json::json!({
                "path": input.path, "sha256": input.sha256, "writable": true
            }))
            .is_err()
        );
        let bound = WorktreeConfinementSnapshot::from_command(&command, true);
        let mut tampered = command.clone();
        tampered.researcher_source_inputs[0].sha256 = "0".repeat(64);
        assert_ne!(
            bound,
            WorktreeConfinementSnapshot::from_command(&tampered, true)
        );
        Ok(())
    }

    #[test]
    fn source_inputs_live_grant_rejects_removed_or_rebound_declaration() -> Result<()> {
        use crate::supervise_budget::{
            BudgetAdmission, BudgetReservationRequest, RunBudgetLedger, RunBudgetLimits,
        };
        let (_root, mut command) = fixture()?;
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            hard_tokens: Some(220_000),
            ..Default::default()
        })?;
        let BudgetAdmission::Admitted { reservation, .. } =
            ledger.reserve(BudgetReservationRequest {
                role: AgentRole::Researcher,
                tokens: 16_384,
                cost_usd: None,
            })?
        else {
            panic!("admitted Researcher");
        };
        command.bind_live_token_grant(ledger.live_token_grant(reservation.id)?);
        assert!(command.verified_live_token_grant().is_ok());
        for remove in [true, false] {
            let mut changed = command.clone();
            if remove {
                changed.researcher_source_inputs.clear();
            } else {
                changed.researcher_source_inputs[0].sha256 = "0".repeat(64);
            }
            let run = run_external_agent(&changed);
            assert!(run
                .error
                .as_deref()
                .is_some_and(|e| e.contains("launch binding changed")));
            assert!(!run.stdout.target_launch_attempted);
            assert!(!run.publishable);
            assert!(run.codex_parent_evidence.is_none());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_inputs_substantive_read_in_actual_profile_and_hidden_packet_refusal() -> Result<()> {
        let (root, command) = fixture()?;
        let profile = SideEffectConfinementProfile::ExternalCodex(
            ExternalCodexProfile::read_only(&command.cwd)
                .with_visible_read_only_file(command.cwd.join("source.diff")),
        );
        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        let mut receipts = validate_command(&command)?;
        let snapshots = probe_source_inputs(
            &command,
            Some(&profile),
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut evidence,
            &mut receipts,
        )?;
        assert_eq!(receipts[0].bytes, SOURCE.len());
        assert_eq!(receipts[0].sha256, sha256_hex(SOURCE));
        assert!(receipts[0].child_profile_visible);
        assert!(evidence.started);
        assert!(evidence
            .process_tree
            .is_some_and(ProcessTreeEvidence::is_verified_empty));
        assert!(evidence
            .side_effects
            .is_some_and(SideEffectConfinementEvidence::is_verified));
        revalidate_source_inputs(&command, &receipts)?;
        let version = EnvironmentFixedVersionProbeEvidence {
            executable: EnvironmentExecutable::Codex,
            exit_code: Some(0),
            timed_out: false,
            stdout: EnvironmentFixedVersionProbeStream {
                text: "codex-cli 0.144.4".into(),
                truncated: false,
            },
            stderr: EnvironmentFixedVersionProbeStream {
                text: String::new(),
                truncated: false,
            },
            process_tree: evidence.process_tree.context("probe tree")?,
            side_effects: evidence.side_effects.context("probe confinement")?,
        };
        let mut report = failed_external_run(
            &command,
            Instant::now(),
            Vec::new(),
            false,
            "not dispatched".into(),
        );
        evidence.fixed_version_probe_evidence = Some(version.clone());
        retain_environment_preflight_process_evidence(&mut report, &evidence);
        TEST_SKIP_INNER_SOURCE_SANDBOX.with(|flag| flag.set(true));
        prepare_source_inputs(
            &command,
            Some(&profile),
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut report,
        )?;
        assert_eq!(report.fixed_version_probe_evidence(), Some(&version));
        let wire = serde_json::to_value(&report)?;
        assert_eq!(
            wire["researcher_input_receipts"][0]["sha256"],
            sha256_hex(SOURCE)
        );
        assert!(!report.stdout.target_launch_attempted);

        let sibling = root.path().join("not-declared.diff");
        fs::write(&sibling, b"private sibling source")?;
        for (script, path) in [
            (
                "printf forbidden >> \"$1\"",
                command.cwd.join("source.diff"),
            ),
            ("cat -- \"$1\"", sibling),
        ] {
            let probe = ProcessSpec::direct(
                "source input boundary negative",
                "/bin/sh",
                [
                    OsStr::new("-c"),
                    OsStr::new(script),
                    OsStr::new("boundary-probe"),
                    path.as_os_str(),
                ],
                &command.cwd,
                4096,
            )
            .with_stdin(StdinMode::Null)
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
            .with_private_runtime_home(true)
            .with_private_runtime_codex_home(true)
            .with_side_effect_confinement(profile.clone())
            .with_timeout(Some(Duration::from_secs(30)));
            let output = run_process_cancellable(probe, &ProcessCancellation::new())?;
            assert!(output.safety_evidence_verified());
            assert!(output.status.is_some_and(|status| !status.success()));
            assert!(output.stdout.as_bytes().is_empty());
        }
        let hidden = SideEffectConfinementProfile::ExternalCodex(
            ExternalCodexProfile::read_only(&command.cwd)
                .with_hidden_root(command.cwd.join("source.diff")),
        );
        assert!(probe_source_inputs(
            &command,
            Some(&hidden),
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut EnvironmentPreflightProcessEvidence::default(),
            &mut validate_command(&command)?,
        )
        .is_err());
        assert_eq!(fs::read(command.cwd.join("source.diff"))?, SOURCE);
        // Mutation after the final external input check, immediately before a
        // target is dispatched: its private snapshot must still expose verified bytes.
        revalidate_source_inputs(&command, &receipts)?;
        fs::write(
            command.cwd.join("source.diff"),
            b"unverified replacement in the same inode",
        )?;
        let mut target = ProcessSpec::direct(
            "source snapshot target",
            "/usr/bin/cat",
            [command.cwd.join("source.diff")],
            &command.cwd,
            4096,
        )
        .with_stdin(StdinMode::Null)
        .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
        .with_private_runtime_home(true)
        .with_private_runtime_codex_home(true)
        .with_side_effect_confinement(profile.clone())
        .with_timeout(Some(Duration::from_secs(30)));
        target.read_only_input_snapshots = snapshots;
        let output = run_process_cancellable(target, &ProcessCancellation::new())?;
        assert!(output.safety_sensitive_succeeded(), "{output:?}");
        assert_eq!(output.stdout.as_bytes(), SOURCE);

        assert!(!command.json_log.exists());
        Ok(())
    }

    /// Run explicitly with --ignored in the pinned Linux qualification lane.
    /// This invokes only `codex sandbox`, never exec/app-server or a provider.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the pinned providerless Codex 0.144.4 sandbox and delegated Linux containment"]
    fn source_inputs_pinned_inner_sandbox_preserves_unlinked_snapshot_and_denials() -> Result<()> {
        let sandbox_program = PathBuf::from(
            env::var_os("MACO_TEST_CODEX_SANDBOX_PROGRAM")
                .context("explicit pinned sandbox program is required; no PATH fallback")?,
        );
        validate_external_program_identity(&sandbox_program, false)?;
        let metadata = fs::metadata(&sandbox_program)?;
        ensure!(
            metadata.len() <= 512 * 1024 * 1024,
            "sandbox executable exceeds qualification bound"
        );
        ensure!(
            sha256_hex(&fs::read(&sandbox_program)?)
                == "2b3edc9cdfd1717fba3dbc92817205a8a2c7511d459e456d4817eeff6f78ed7a",
            "sandbox executable is not the admitted 0.144.4 pin"
        );
        let (root, mut command) = fixture()?;
        git2::Repository::init(&command.cwd)?;
        for control in [".maco", ".maco-cache", ".codex", ".agents"] {
            fs::create_dir(command.cwd.join(control))?;
        }
        let incoming = root.path().join("incoming");
        fs::create_dir(&incoming)?;
        command.output_last_message = incoming.join("report.json");
        command.program = sandbox_program.clone();
        let source = command.cwd.join("src/runtime_adapter/source.rs");
        fs::create_dir_all(source.parent().unwrap())?;
        fs::write(&source, SOURCE)?;
        let schemas = root.path().join("private-schemas");
        fs::create_dir(&schemas)?;
        let schema = schemas.join("schema.json");
        let schema_sibling = schemas.join("sibling.json");
        fs::write(&schema, b"{\"type\":\"object\"}\n")?;
        fs::write(&schema_sibling, b"hidden sibling bytes")?;
        command.read_only_input_files = vec![source.clone(), schema.clone()];
        command.researcher_source_inputs = vec![ResearcherSourceInput {
            path: "src/runtime_adapter/source.rs".into(),
            sha256: sha256_hex(SOURCE),
        }];
        let hidden = command.cwd.join("hidden-packets");
        fs::create_dir(&hidden)?;
        fs::write(hidden.join("secret"), b"hidden unit-test bytes")?;
        command.hidden_roots.push(hidden.clone());
        let receipts = validate_command(&command)?;
        let snapshots = vec![crate::process_runner::ReadOnlyInputSnapshot::capture(
            &source,
            &receipts[0].sha256,
        )?];
        let controls = protected_worktree_controls(&command)?;
        let permissions = codex_filesystem_permissions(&command, &controls);
        let mut legacy = command.clone();
        legacy.researcher_source_inputs.clear();
        let legacy_permissions = codex_filesystem_permissions(&legacy, &controls);
        let profile = external_side_effect_profile(
            &command,
            &sandbox_program,
            ExternalProgramTrust::TrustedSystemCodex,
            &controls,
        )?;
        TEST_SKIP_INNER_SOURCE_SANDBOX.with(|flag| flag.set(false));
        let mut production_report = failed_external_run(
            &command,
            Instant::now(),
            Vec::new(),
            false,
            "providerless inner preflight".into(),
        );
        prepare_source_inputs(
            &command,
            Some(&profile),
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut production_report,
        )?;
        revalidate_before_provider(
            &command,
            &mut production_report
                .stdout
                .run_metadata
                .researcher_input_receipts,
        )?;
        ensure!(production_report
            .stdout
            .run_metadata
            .researcher_input_receipts
            .iter()
            .all(ResearcherInputReceipt::proves_release));
        ensure!(!production_report.stdout.target_launch_attempted);
        ensure!(!command.json_log.exists());
        // All checks run inside the actual inner namespace after the outer
        // runner has unlinked the private backing file. Only source bytes reach
        // stdout; a broken nested mount cannot pass via the direct-cat probe.
        let script = r#"set -eu; test "$(/usr/bin/stat -c %h -- "$1")" = 0; /usr/bin/cat -- "$1"; if (printf forbidden >> "$1") 2>/dev/null; then exit 90; fi; /usr/bin/cat -- "$2" >/dev/null; if /usr/bin/cat -- "$3" >/dev/null 2>&1; then exit 91; fi; if /usr/bin/cat -- "$4" >/dev/null 2>&1; then exit 92; fi; if (printf forbidden > "$5") 2>/dev/null; then exit 93; fi"#;
        for stage in ["legacy-rebind", "original", "mutated", "replaced"] {
            match stage {
                "mutated" => fs::write(&source, b"unverified same-inode mutation")?,
                "replaced" => {
                    fs::rename(&source, command.cwd.join("replaced-original"))?;
                    fs::write(&source, b"unverified replacement inode")?;
                }
                _ => {}
            }
            let args = vec![
                OsString::from("sandbox"),
                OsString::from("--permission-profile"),
                OsString::from("maco_external_codex"),
                OsString::from("--cd"),
                command.cwd.as_os_str().to_os_string(),
                OsString::from("-c"),
                OsString::from("permissions.maco_external_codex.network={enabled=false}"),
                OsString::from("-c"),
                OsString::from(if stage == "legacy-rebind" {
                    &legacy_permissions
                } else {
                    &permissions
                }),
                OsString::from("--"),
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from(script),
                OsString::from("source-input-inner-boundary"),
                source.as_os_str().to_os_string(),
                schema.as_os_str().to_os_string(),
                schema_sibling.as_os_str().to_os_string(),
                hidden.join("secret").into_os_string(),
                command.cwd.join("write-forbidden").into_os_string(),
            ];
            let mut target = ProcessSpec::direct(
                "providerless source input inner sandbox",
                &sandbox_program,
                &args,
                &command.cwd,
                8192,
            )
            .with_stdin(StdinMode::Null)
            .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
            .with_private_runtime_home(true)
            .with_private_runtime_codex_home(true)
            .with_side_effect_confinement(profile.clone())
            .with_timeout(Some(Duration::from_secs(30)));
            target.read_only_input_snapshots = snapshots.clone();
            let output = run_process_cancellable(target, &ProcessCancellation::new())?;
            if stage == "legacy-rebind" {
                ensure!(
                    output.safety_evidence_verified(),
                    "legacy refusal must unwind safely: {output:?}"
                );
                ensure!(output.status.is_some_and(|status| !status.success()));
                let stderr = String::from_utf8_lossy(output.stderr.as_bytes());
                ensure!(
                    stderr.contains("Can't bind mount")
                        && stderr.contains("No such file or directory"),
                    "legacy case did not reproduce the admitted defect: {stderr}"
                );
                println!("INNER_SANDBOX_STAGE legacy-rebind=enoent");
                continue;
            }
            ensure!(
                output.safety_sensitive_succeeded(),
                "{stage} nested sandbox failed: {output:?}"
            );
            ensure!(
                output.stdout.as_bytes() == SOURCE,
                "{stage} did not read immutable source bytes"
            );
            ensure!(sha256_hex(output.stdout.as_bytes()) == receipts[0].sha256);
            println!("INNER_SANDBOX_STAGE {stage}=immutable-read-and-denials");
        }
        ensure!(
            fs::read(&source)? == b"unverified replacement inode",
            "inner command wrote the original path"
        );
        ensure!(
            !command.cwd.join("write-forbidden").exists(),
            "inner command wrote the read-only workspace"
        );
        ensure!(
            fs::read(&schema)? == b"{\"type\":\"object\"}\n",
            "inner command changed the exact schema"
        );
        ensure!(
            fs::read(&schema_sibling)? == b"hidden sibling bytes",
            "inner command changed the schema sibling"
        );
        ensure!(
            fs::read(hidden.join("secret"))? == b"hidden unit-test bytes",
            "inner command changed hidden bytes"
        );
        println!(
            "INNER_SANDBOX_BOUNDARY_RECEIPT source_unlinked=true writes_denied=true \
             hidden_denied=true outside_exact_readable=true outside_sibling_denied=true"
        );
        ensure!(
            !command.json_log.exists(),
            "no provider run or report was created"
        );
        Ok(())
    }
}
