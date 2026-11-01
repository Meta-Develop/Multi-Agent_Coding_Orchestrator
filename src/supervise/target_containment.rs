//! Private diagnostic receipts. Restored observations never carry execution authority.

use super::*;
use crate::artifacts::state_auth::sha256_hex;

const VERSION: u32 = 1;
const MAX_RECEIPT_BYTES: usize = 16 * 1024;

#[path = "observed_identity.rs"]
mod observed_identity;
pub(crate) use observed_identity::observed_role_identity;

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

/// Additive private-summary fields; the public CommandRunRecord contract is unchanged.
#[derive(Serialize)]
struct RetainedCommandSummary<'a> {
    #[serde(flatten)]
    command: &'a CommandRunRecord,
    runtime_identity: observed_identity::RuntimeIdentityObservation,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_seal_snapshot: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    researcher_input_receipts:
        Vec<crate::external_agent::researcher_inputs::ResearcherInputReceipt>,
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
    let mut summary = serde_json::to_vec_pretty(&RetainedCommandSummary {
        command: &record,
        runtime_identity: observed_identity::RuntimeIdentityObservation::capture(
            run, command, runtime,
        ),
        researcher_input_receipts: run.retained_researcher_input_receipts(),
        command_seal_snapshot: command
            .live_budget_command_seal_snapshot()
            .map_err(|error| anyhow!(error))?,
    })?;
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

/// Verify preparation observations against declarations in the digest-bound plan.
/// These checks authenticate historical evidence only, never restored launch authority.
pub(super) fn verify_researcher_inputs(
    reader: &ArtifactRunReader,
    report: &SupervisorFinalReport,
) -> Result<()> {
    use crate::external_agent::researcher_inputs::{
        validate_declarations, ResearcherInputReceipt, ResearcherSourceInput,
    };
    const PLAN: &str = "assignments/supervisor-plan.json";
    let files = &reader.finalization().files;
    let mut declarations = BTreeMap::<String, Vec<ResearcherSourceInput>>::new();
    fn collect(
        value: &Value,
        declarations: &mut BTreeMap<String, Vec<ResearcherSourceInput>>,
    ) -> Result<()> {
        if let Some(assignments) = value
            .get("assignments")
            .or_else(|| value.get("child_assignments"))
        {
            for assignment in assignments
                .as_array()
                .context("retained assignments must be an array")?
            {
                if let Some(inputs) = assignment.get("source_inputs") {
                    let inputs: Vec<ResearcherSourceInput> =
                        serde_json::from_value(inputs.clone())?;
                    validate_declarations(&inputs)?;
                    if !inputs.is_empty() {
                        let id = assignment["id"]
                            .as_str()
                            .context("source input assignment has no id")?;
                        if assignment["role"] != "researcher"
                            || normalize_agent_id(id)? != id
                            || declarations.insert(id.to_owned(), inputs).is_some()
                        {
                            bail!("retained source input assignment identity is inconsistent");
                        }
                    }
                }
                collect(assignment, declarations)?;
            }
        }
        Ok(())
    }
    if let Some(file) = files.iter().find(|file| file.path == Path::new(PLAN)) {
        if file.bytes > MAX_SUPERVISOR_REPORT_BYTES as u64
            || file.disposition != ArtifactFileDisposition::PrivateEvidence
        {
            bail!("retained source input plan must be bounded private evidence");
        }
        collect(
            &serde_json::from_slice::<Value>(&reader.read(PLAN)?)?,
            &mut declarations,
        )?;
    } else if report.accepted && report.role_usage.contains_key(&AgentRole::Researcher) {
        bail!("accepted Researcher evidence requires its retained plan");
    }

    // Orphan target receipts also reveal missing process summaries.
    for file in files {
        let Some(stem) = file
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".target-containment.json"))
        else {
            continue;
        };
        if !stem.ends_with(".summary")
            || files
                .iter()
                .any(|candidate| candidate.path == file.path.with_file_name(format!("{stem}.json")))
        {
            continue;
        }
        if file.bytes > MAX_RECEIPT_BYTES as u64
            || file.disposition != ArtifactFileDisposition::PrivateEvidence
        {
            bail!("orphan target receipt must be bounded private evidence");
        }
        let receipt: TargetContainmentReceipt = serde_json::from_slice(&reader.read(&file.path)?)?;
        if declarations.contains_key(&receipt.binding.task_id) {
            bail!("Researcher target receipt lacks its process summary");
        }
    }
    let mut proven = BTreeSet::new();
    // Every process summary belonging to a declared assignment needs its own
    // bound receipt, including retries. A single good attempt cannot hide another.
    for file in files {
        let Some(name) = file.path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".summary.json") {
            continue;
        }
        let relative = receipt_path(&file.path);
        let bound_receipt = if let Some(record) = files.iter().find(|file| file.path == relative) {
            if record.bytes > MAX_RECEIPT_BYTES as u64
                || record.disposition != ArtifactFileDisposition::PrivateEvidence
            {
                bail!("target receipt must be bounded private evidence");
            }
            let bytes = reader.read(&relative)?;
            let receipt: TargetContainmentReceipt = serde_json::from_slice(&bytes)?;
            Some((bytes, receipt))
        } else {
            None
        };
        // Task IDs may themselves contain `.attempt-`, including numeric suffixes.
        // Only the authenticated binding identifies the owner of an existing receipt.
        let expected = bound_receipt
            .as_ref()
            .and_then(|(_, receipt)| declarations.get_key_value(&receipt.binding.task_id));
        let Some((id, inputs)) = expected else {
            // Without a binding, fail closed for any exact canonical source filename.
            // This is only a missing-evidence check, never an ownership decision.
            let stem = name.strip_suffix(".summary.json").expect("summary suffix");
            let source_filename = declarations.contains_key(stem)
                || stem.rsplit_once(".attempt-").is_some_and(|(id, number)| {
                    number.parse::<usize>().is_ok_and(|attempt| {
                        attempt > 0
                            && number == attempt.to_string()
                            && declarations.contains_key(id)
                    })
                });
            if bound_receipt.is_none()
                && file.path.parent() == Some(Path::new("logs"))
                && source_filename
            {
                bail!("Researcher input summary lacks its bound target receipt");
            }

            if name.ends_with(".summary.json") {
                if file.bytes > MAX_SUPERVISOR_REPORT_BYTES as u64 {
                    bail!("process summary exceeds its byte limit");
                }
                let summary: Value = serde_json::from_slice(&reader.read(&file.path)?)?;
                if let Some(receipts) = summary.get("researcher_input_receipts") {
                    if receipts
                        .as_array()
                        .is_none_or(|receipts| !receipts.is_empty())
                    {
                        bail!("Researcher input receipts have no matching source declaration");
                    }
                }
            }
            continue;
        };
        if file.bytes > MAX_SUPERVISOR_REPORT_BYTES as u64
            || file.disposition != ArtifactFileDisposition::PrivateEvidence
        {
            bail!("Researcher input summary must be bounded private evidence");
        }
        let summary = reader.read(&file.path)?;
        let (bytes, receipt) = bound_receipt
            .as_ref()
            .context("Researcher input summary lacks its bound target receipt")?;
        validate(bytes, &receipt.binding, &summary)?;
        if receipt.binding.run_id != report.run_id.as_str()
            || receipt.binding.task_id != *id
            || receipt.binding.role != "researcher"
            || receipt.binding.runtime != SupervisorRuntime::Codex
            || receipt.binding.attempt == 0
            || receipt.binding.command_summary != file.path
            || (file.path != PathBuf::from("logs").join(format!("{id}.summary.json"))
                && file.path
                    != PathBuf::from("logs").join(format!(
                        "{id}.attempt-{}.summary.json",
                        receipt.binding.attempt
                    )))
        {
            bail!("Researcher source input attempt binding mismatch");
        }
        let value: Value = serde_json::from_slice(&summary)?;
        let retained: Vec<ResearcherInputReceipt> = value
            .get("researcher_input_receipts")
            .map(|receipts| serde_json::from_value(receipts.clone()))
            .transpose()?
            .unwrap_or_default();
        if retained.len() != inputs.len()
            || retained
                .iter()
                .zip(inputs)
                .any(|(receipt, input)| !receipt.matches_declaration(input))
        {
            // Prelaunch validation may fail before an identity can be observed.
            if receipt.target_launch_attempted || report.accepted || !retained.is_empty() {
                bail!("Researcher source input receipts are missing or disagree with declarations");
            }
            continue;
        }
        let complete = retained.iter().all(ResearcherInputReceipt::proves_release);
        if receipt.target_launch_attempted && !complete {
            bail!("launched Researcher lacks complete input preflight and revalidation evidence");
        }
        if complete && receipt.target_launch_attempted {
            proven.insert(id.clone());
        }
    }
    if report.accepted && declarations.keys().any(|id| !proven.contains(id)) {
        bail!("accepted Researcher lacks retained input release evidence");
    }
    Ok(())
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
