//! Private diagnostic receipts. Restored observations never carry execution authority.

use super::*;
use crate::artifacts::state_auth::sha256_hex;

const VERSION: u32 = 1;
const MAX_RECEIPT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetBinding {
    run_id: String,
    task_id: String,
    parent: Option<String>,
    attempt: usize,
    role: String,
    runtime: SupervisorRuntime,
    command_summary: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "status", content = "evidence", rename_all = "snake_case")]
enum Observation<T> {
    Unknown,
    Observed(T),
}

impl<T> From<Option<T>> for Observation<T> {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Unknown, Self::Observed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetContainmentReceipt {
    version: u32,
    binding: TargetBinding,
    command_summary_sha256: String,
    target_launch_attempted: bool,
    target_process_tree: Observation<ProcessTreeEvidence>,
    target_side_effects: Observation<SideEffectConfinementEvidence>,
}

fn receipt_path(summary: &Path) -> PathBuf {
    summary.with_extension("target-containment.json")
}

fn binding(
    run_dir: &Path,
    artifacts: &ChildAttemptArtifacts,
    command: &ExternalAgentCommand,
    runtime: SupervisorRuntime,
) -> Result<TargetBinding> {
    let identity = command
        .agent_lifecycle
        .as_ref()
        .context("target receipt requires supervisor lifecycle identity")?;
    let attempt = command
        .assignment_process_launch_attempt
        .filter(|attempt| *attempt > 0)
        .context("target receipt requires a supervisor launch attempt")?;
    if run_dir.file_name().and_then(|name| name.to_str()) != Some(&identity.run_id)
        || normalize_agent_id(&identity.task_id)? != identity.task_id
        || identity.role.trim().is_empty()
        || command.prompt != artifacts.prompt_path
        || command.json_log != artifacts.log_path
        || command.output_last_message != artifacts.report_path
        || (runtime != SupervisorRuntime::Fake
            && command
                .invocation
                .adapter_id()
                .and_then(|id| id.to_runtime_id())
                != Some(runtime))
    {
        bail!("target receipt lifecycle, command, or runtime binding mismatch");
    }
    let summary = &artifacts.command_record_relative;
    let plain = PathBuf::from("logs").join(format!("{}.summary.json", identity.task_id));
    let numbered = PathBuf::from("logs").join(format!(
        "{}.attempt-{attempt}.summary.json",
        identity.task_id
    ));
    let nested = identity.parent.as_ref().map(|parent| {
        PathBuf::from("nested")
            .join(parent)
            .join(format!("attempt-{attempt}"))
            .join(&identity.task_id)
            .join("command.json")
    });
    if summary != &plain && summary != &numbered && nested.as_ref() != Some(summary) {
        bail!("target receipt command summary does not match the lifecycle attempt");
    }
    Ok(TargetBinding {
        run_id: identity.run_id.clone(),
        task_id: identity.task_id.clone(),
        parent: identity.parent.clone(),
        attempt,
        role: identity.role.clone(),
        runtime,
        command_summary: summary.clone(),
    })
}

pub(super) fn persist(
    writer: &mut ArtifactRunWriter,
    artifacts: &ChildAttemptArtifacts,
    command: &ExternalAgentCommand,
    runtime: SupervisorRuntime,
    run: &ExternalAgentRun,
) -> Result<()> {
    let binding = binding(writer.run_dir(), artifacts, command, runtime)?;
    let record = command_record_from_external_for_runtime(run, command, runtime);
    let mut summary = serde_json::to_vec_pretty(&record)?;
    summary.push(b'\n');
    if summary.len() > MAX_SUPERVISOR_REPORT_BYTES {
        bail!("target command summary exceeds its configured byte limit");
    }
    let receipt = TargetContainmentReceipt {
        version: VERSION,
        binding,
        command_summary_sha256: sha256_hex(&summary),
        target_launch_attempted: run.stdout.target_launch_attempted,
        target_process_tree: run.process_tree.into(),
        target_side_effects: run.side_effects.into(),
    };
    let relative = receipt_path(&artifacts.command_record_relative);
    // Returned-parent capture and ordinary import can observe the same held run.
    // Refuse contradictory repeats rather than replacing the earlier observation.
    match fs::symlink_metadata(writer.run_dir().join(&relative)) {
        Ok(_) => {
            let bytes = writer.read_authenticated(&relative, MAX_RECEIPT_BYTES)?;
            let retained_summary = writer.read_authenticated(
                &artifacts.command_record_relative,
                MAX_SUPERVISOR_REPORT_BYTES,
            )?;
            let existing = validate(&bytes, &receipt.binding, &retained_summary)?;
            if existing != receipt {
                bail!("target receipt contradicts a previously retained observation");
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    writer.write_bytes(
        &artifacts.command_record_relative,
        &summary,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    write_artifact_json(
        writer,
        &relative,
        &receipt,
        MAX_RECEIPT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    let summary = writer.read_authenticated(
        &artifacts.command_record_relative,
        MAX_SUPERVISOR_REPORT_BYTES,
    )?;
    let bytes = writer.read_authenticated(&relative, MAX_RECEIPT_BYTES)?;
    validate(&bytes, &receipt.binding, &summary)?;
    Ok(())
}

fn validate(
    bytes: &[u8],
    expected: &TargetBinding,
    summary: &[u8],
) -> Result<TargetContainmentReceipt> {
    let receipt: TargetContainmentReceipt = serde_json::from_slice(bytes)?;
    if receipt.version != VERSION
        || &receipt.binding != expected
        || receipt.command_summary_sha256 != sha256_hex(summary)
    {
        bail!("target receipt version, attempt identity, or command summary hash mismatch");
    }
    Ok(receipt)
}

// Diagnostic readback only. In particular, neither this type nor the receipt can
// be converted to a launch grant, cleanup proof, lease release, or accepted report.
#[derive(Debug, PartialEq, Eq)]
enum RestoredTargetContainment {
    UnknownLegacy,
    Retained(TargetContainmentReceipt),
}

#[allow(dead_code)] // Kept private until an operator diagnostic consumer needs readback.
fn read(reader: &ArtifactRunReader, expected: &TargetBinding) -> Result<RestoredTargetContainment> {
    if reader.finalization().run_id != expected.run_id {
        bail!("target receipt expected run does not match the authenticated manifest");
    }
    let summary_record = reader
        .finalization()
        .files
        .iter()
        .find(|file| file.path == expected.command_summary)
        .context("target command summary is absent from the authenticated manifest")?;
    if summary_record.disposition != ArtifactFileDisposition::PrivateEvidence
        || summary_record.bytes > MAX_SUPERVISOR_REPORT_BYTES as u64
    {
        bail!("target command summary must be bounded private evidence");
    }
    let summary = reader.read(&expected.command_summary)?;
    let relative = receipt_path(&expected.command_summary);
    let record = reader
        .finalization()
        .files
        .iter()
        .find(|file| file.path == relative);
    let Some(record) = record else {
        return Ok(RestoredTargetContainment::UnknownLegacy);
    };
    if record.disposition != ArtifactFileDisposition::PrivateEvidence
        || record.bytes > MAX_RECEIPT_BYTES as u64
    {
        bail!("target receipt must be bounded private evidence");
    }
    let receipt = validate(&reader.read(relative)?, expected, &summary)?;
    Ok(RestoredTargetContainment::Retained(receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        external_agent::{
            EnvironmentExecutable, EnvironmentFixedVersionProbeEvidence,
            EnvironmentFixedVersionProbeStream,
        },
        process_runner::{ContainmentBackend, SideEffectConfinementProfileKind},
    };

    struct Fixture {
        _temp: tempfile::TempDir,
        repo: PathBuf,
        run_id: RunId,
        writer: ArtifactRunWriter,
        artifacts: ChildAttemptArtifacts,
        command: ExternalAgentCommand,
    }

    fn fixture() -> Fixture {
        let (temp, repo) = super::super::tests::injected_repository();
        let run_id = RunId::new("target-receipt-test").unwrap();
        let writer =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Supervise, run_id.clone(), "test")
                .unwrap();
        let dirs = RunDirs::for_writer(&writer);
        let artifacts = child_attempt_artifacts(
            &dirs,
            &dirs.run_dir.join("incoming"),
            &dirs.run_dir.join("capture"),
            "research",
            2,
            true,
        );
        let mut command = ExternalAgentCommand::codex(
            "unused-codex",
            &repo,
            &artifacts.prompt_path,
            &artifacts.log_path,
            &artifacts.report_path,
            Duration::from_secs(1),
        )
        .with_agent_lifecycle(&repo, "researcher", run_id.as_str(), "research");
        command.assignment_process_launch_attempt = Some(2);
        Fixture {
            _temp: temp,
            repo,
            run_id,
            writer,
            artifacts,
            command,
        }
    }

    fn finalize(mut writer: ArtifactRunWriter, repo: &Path, run_id: &RunId) -> ArtifactRunReader {
        let report = super::super::tests::artifact_test_final_report(run_id);
        write_final_report(&mut writer, &report).unwrap();
        writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .unwrap();
        ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, run_id).unwrap()
    }

    #[test]
    fn target_receipt_binds_attempt_and_distinguishes_probe() {
        let mut fixture = fixture();
        let mut run = deterministic_fake_run(&fixture.command, Vec::new());
        run.process_tree = Some(ProcessTreeEvidence::Unverified(
            ContainmentBackend::SystemdUserService,
        ));
        run.side_effects = Some(SideEffectConfinementEvidence::Unverified(
            SideEffectConfinementProfileKind::ExternalCodex,
        ));
        let stream = EnvironmentFixedVersionProbeStream {
            text: String::new(),
            truncated: false,
        };
        run.attach_fixed_version_probe_evidence_for_test(EnvironmentFixedVersionProbeEvidence {
            executable: EnvironmentExecutable::Git,
            exit_code: Some(0),
            timed_out: false,
            stdout: stream.clone(),
            stderr: stream,
            process_tree: ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            ),
            side_effects: SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::TrustedFixedNetwork,
            ),
        });
        let expected = binding(
            fixture.writer.run_dir(),
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
        )
        .unwrap();
        persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
            &run,
        )
        .unwrap();
        persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
            &run,
        )
        .unwrap();
        let reader = finalize(fixture.writer, &fixture.repo, &fixture.run_id);
        let RestoredTargetContainment::Retained(receipt) = read(&reader, &expected).unwrap() else {
            panic!("missing target receipt")
        };
        assert_eq!(receipt.binding.attempt, 2);
        assert_eq!(receipt.binding.role, "researcher");
        assert_eq!(
            receipt.target_process_tree,
            Observation::Observed(run.process_tree.unwrap())
        );
        assert_eq!(
            receipt.target_side_effects,
            Observation::Observed(run.side_effects.unwrap())
        );
        let summary: CommandRunRecord =
            serde_json::from_slice(&reader.read(&expected.command_summary).unwrap()).unwrap();
        assert!(summary
            .fixed_version_probe_evidence
            .unwrap()
            .process_tree
            .is_verified_empty());
        assert!(!external_containment_verified(
            &run,
            SupervisorRuntime::Codex
        ));
        assert!(reader
            .finalization()
            .files
            .iter()
            .all(|record| record.disposition == ArtifactFileDisposition::PrivateEvidence));
    }

    #[test]
    fn missing_legacy_target_is_unknown() {
        let mut legacy = fixture();
        let run = deterministic_fake_run(&legacy.command, Vec::new());
        let expected = binding(
            legacy.writer.run_dir(),
            &legacy.artifacts,
            &legacy.command,
            SupervisorRuntime::Codex,
        )
        .unwrap();
        let record = command_record_from_external_for_runtime(
            &run,
            &legacy.command,
            SupervisorRuntime::Codex,
        );
        legacy
            .writer
            .write_json(
                &expected.command_summary,
                &record,
                ArtifactFileDisposition::PrivateEvidence,
            )
            .unwrap();
        let reader = finalize(legacy.writer, &legacy.repo, &legacy.run_id);
        assert_eq!(
            read(&reader, &expected).unwrap(),
            RestoredTargetContainment::UnknownLegacy
        );

        let mut current = fixture();
        persist(
            &mut current.writer,
            &current.artifacts,
            &current.command,
            SupervisorRuntime::Codex,
            &run,
        )
        .unwrap();
        let reader = finalize(current.writer, &current.repo, &current.run_id);
        let RestoredTargetContainment::Retained(receipt) = read(&reader, &expected).unwrap() else {
            panic!("missing current receipt")
        };
        assert_eq!(receipt.target_process_tree, Observation::Unknown);
        assert_eq!(receipt.target_side_effects, Observation::Unknown);
    }

    #[test]
    fn tampered_or_cross_attempt_receipt_is_rejected() {
        let mut fixture = fixture();
        let run_dir = fixture.writer.run_dir().to_path_buf();
        let run = deterministic_fake_run(&fixture.command, Vec::new());
        let expected = binding(
            fixture.writer.run_dir(),
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
        )
        .unwrap();
        persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
            &run,
        )
        .unwrap();
        let reader = finalize(fixture.writer, &fixture.repo, &fixture.run_id);
        for field in ["run", "task", "attempt", "role", "runtime", "parent"] {
            let mut other = expected.clone();
            match field {
                "run" => other.run_id = "other-run".into(),
                "task" => other.task_id = "other-task".into(),
                "attempt" => other.attempt += 1,
                "role" => other.role = "worker".into(),
                "runtime" => other.runtime = SupervisorRuntime::Grok,
                "parent" => other.parent = Some("other-parent".into()),
                _ => unreachable!(),
            }
            assert!(read(&reader, &other).is_err(), "accepted wrong {field}");
        }
        let relative = receipt_path(&expected.command_summary);
        let bytes = reader.read(&relative).unwrap();
        let summary = reader.read(&expected.command_summary).unwrap();
        assert!(validate(&bytes, &expected, b"different command summary").is_err());
        let mut altered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        altered["version"] = json!(2);
        assert!(validate(&serde_json::to_vec(&altered).unwrap(), &expected, &summary).is_err());
        altered["version"] = json!(1);
        altered["child_claim"] = json!("verified");
        assert!(validate(&serde_json::to_vec(&altered).unwrap(), &expected, &summary).is_err());
        fs::write(run_dir.join(relative), b"{}").unwrap();
        assert!(read(&reader, &expected).is_err());
        assert!(ArtifactRunReader::open(
            &fixture.repo,
            RunArtifactFamily::Supervise,
            &fixture.run_id
        )
        .is_err());
    }

    #[test]
    fn failed_timeout_without_valid_report_retains_target_before_scratch_disposal() {
        let mut fixture = fixture();
        let (incoming, capture) = create_invocation_scratches(&mut fixture.writer).unwrap();
        let mut run = deterministic_fake_run(&fixture.command, b"invalid report".to_vec());
        run.exit_code = Some(1);
        run.timed_out = true;
        run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ));
        run.side_effects = Some(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::ExternalCodex,
        ));
        let expected = binding(
            fixture.writer.run_dir(),
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Fake,
        )
        .unwrap();
        import_external_attempt_evidence(
            &mut fixture.writer,
            ExternalAttemptEvidenceContext {
                incoming_scratch: &incoming,
                capture_scratch: &capture,
                artifacts: &fixture.artifacts,
                external_run: &run,
                external_command: &fixture.command,
                raw_report_validated: false,
                runtime: SupervisorRuntime::Fake,
            },
        )
        .unwrap();
        assert!(!incoming.path().exists());
        assert!(!capture.path().exists());
        let reader = finalize(fixture.writer, &fixture.repo, &fixture.run_id);
        let RestoredTargetContainment::Retained(receipt) = read(&reader, &expected).unwrap() else {
            panic!("missing failed target receipt")
        };
        assert_eq!(
            receipt.target_process_tree,
            Observation::Observed(run.process_tree.unwrap())
        );
        assert_eq!(
            receipt.target_side_effects,
            Observation::Observed(run.side_effects.unwrap())
        );
        let summary: CommandRunRecord =
            serde_json::from_slice(&reader.read(&expected.command_summary).unwrap()).unwrap();
        assert!(summary.timed_out);
        assert_eq!(summary.exit_code, Some(1));
        assert!(reader.read(&fixture.artifacts.raw_report_relative).is_err());
        assert!(!external_containment_verified(
            &run,
            SupervisorRuntime::Codex
        ));
    }

    #[test]
    fn missing_or_contradictory_lifecycle_and_repeated_observations_are_refused() {
        let mut fixture = fixture();
        let mut run = deterministic_fake_run(&fixture.command, Vec::new());
        let mut command = fixture.command.clone();
        command.agent_lifecycle = None;
        assert!(persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &command,
            SupervisorRuntime::Codex,
            &run
        )
        .is_err());
        command = fixture.command.clone();
        command.assignment_process_launch_attempt = None;
        assert!(persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &command,
            SupervisorRuntime::Codex,
            &run
        )
        .is_err());
        command = fixture.command.clone();
        command.assignment_process_launch_attempt = Some(3);
        assert!(persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &command,
            SupervisorRuntime::Codex,
            &run
        )
        .is_err());
        assert!(persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Grok,
            &run
        )
        .is_err());
        persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
            &run,
        )
        .unwrap();
        run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ));
        assert!(persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
            &run
        )
        .is_err());
        run.process_tree = None;
        fs::write(
            fixture
                .writer
                .run_dir()
                .join(&fixture.artifacts.command_record_relative),
            b"tampered summary",
        )
        .unwrap();
        assert!(persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
            &run
        )
        .is_err());
    }
}
