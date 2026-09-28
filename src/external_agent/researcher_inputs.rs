//! Operator declarations refer only to exact files already in the managed snapshot.
//! A task's prose and a restored receipt confer no file access or launch authority.
use super::*;
use crate::process_runner::resolve_existing_path_without_symlinks;

const MAX_SOURCE_INPUTS: usize = 8;
#[cfg(test)]
thread_local! {
    static TEST_EMPTY_SOURCE_READER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResearcherSourceInput {
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResearcherInputReceipt {
    path: PathBuf,
    sha256: String,
    bytes: usize,
    identity: Option<(u64, u64)>,
    /// The same bytes were read through the launch's actual outer profile.
    child_profile_visible: bool,
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
            if bytes.is_empty() || sha256_hex(&bytes) != input.sha256 {
                bail!(
                    "source input is empty or its SHA256 changed: {}",
                    input.path
                );
            }
            Ok(ResearcherInputReceipt {
                path,
                sha256: input.sha256.clone(),
                bytes: bytes.len(),
                identity,
                child_profile_visible: false,
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
        process_tree: report.process_tree,
        side_effects: report.side_effects,
        fixed_version_probe_evidence: report
            .stdout
            .run_metadata
            .fixed_version_probe_evidence
            .clone(),
    };
    let result = probe_source_inputs(spec, profile, timeout, cancellation, &mut evidence);
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
        Ok((receipts, snapshots)) => {
            report.stdout.run_metadata.researcher_input_receipts = receipts;
            report.stdout.run_metadata.read_only_input_snapshots = snapshots;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn probe_source_inputs(
    spec: &ExternalAgentCommand,
    profile: Option<&SideEffectConfinementProfile>,
    timeout: Duration,
    cancellation: &ProcessCancellation,
    evidence: &mut EnvironmentPreflightProcessEvidence,
) -> Result<(
    Vec<ResearcherInputReceipt>,
    Vec<crate::process_runner::ReadOnlyInputSnapshot>,
)> {
    let mut receipts = validate_command(spec)?;
    if receipts.is_empty() {
        return Ok((receipts, Vec::new()));
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
    for receipt in &mut receipts {
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
        if !output.safety_sensitive_succeeded()
            || output.stdout.as_bytes().len() != receipt.bytes
            || sha256_hex(output.stdout.as_bytes()) != receipt.sha256
        {
            bail!("declared source input is not readable with its bound hash in the child profile: {}", receipt.path.display());
        }
        receipt.child_profile_visible = true;
    }
    revalidate_source_inputs(spec, &receipts)?;
    Ok((receipts, snapshots))
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const SOURCE: &[u8] = b"diff --git a/src/budget.rs b/src/budget.rs\n--- a/src/budget.rs\n+++ b/src/budget.rs\n@@ -1 +1 @@\n-total.saturating_add(next)\n+total.checked_add(next).ok_or(BudgetOverflow)?\n";

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
    pub(crate) fn failed_local_probe(
        command: &ExternalAgentCommand,
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
        assert!(report.error.as_deref().unwrap().contains("not readable"));
        assert!(!report.stdout.target_launch_attempted);
        assert!(!report.publishable);
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
        let error = revalidate_source_inputs(
            command,
            &report.stdout.run_metadata.researcher_input_receipts,
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
        let bound = WorktreeConfinementSnapshot::from_command(&command);
        let mut tampered = command.clone();
        tampered.researcher_source_inputs[0].sha256 = "0".repeat(64);
        assert_ne!(bound, WorktreeConfinementSnapshot::from_command(&tampered));
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
        let (receipts, snapshots) = probe_source_inputs(
            &command,
            Some(&profile),
            Duration::from_secs(30),
            &ProcessCancellation::new(),
            &mut evidence,
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
            &mut EnvironmentPreflightProcessEvidence::default()
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
}
