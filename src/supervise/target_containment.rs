//! Private diagnostic receipts. Restored observations never carry execution authority.

use super::*;
use crate::artifacts::state_auth::sha256_hex;

const VERSION: u32 = 1;
const MAX_RECEIPT_BYTES: usize = 16 * 1024;

#[path = "review_command_evidence.rs"]
mod review_commands;

#[path = "observed_identity.rs"]
mod observed_identity;
pub(crate) use observed_identity::observed_role_identity;
pub(super) use observed_identity::RuntimeIdentityObservation;

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
    review_commands: review_commands::ReviewCommandCapture,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_seal_snapshot: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    researcher_input_receipts:
        Vec<crate::external_agent::researcher_inputs::ResearcherInputReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    budget_interruption: Option<&'a crate::external_agent::codex_app_server::BudgetInterruption>,
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
        review_commands: review_commands::ReviewCommandCapture::capture(
            artifacts, command, runtime, run,
        )?,
        researcher_input_receipts: run.retained_researcher_input_receipts(),
        budget_interruption: run.budget_interruption(),
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
            return super::helper_inventory::persist_target(
                writer,
                &artifacts.command_record_relative,
                &serde_json::to_value(&receipt.binding)?,
                run,
            );
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
    super::helper_inventory::persist_target(
        writer,
        &artifacts.command_record_relative,
        &serde_json::to_value(&receipt.binding)?,
        run,
    )
}

/// Descriptive source identity only; no command, grant, or process-control
/// object is retained across the review boundary.
pub(super) struct ReviewAttemptSource {
    expected: TargetBinding,
    transcript: PathBuf,
}

impl ReviewAttemptSource {
    pub(super) fn bind(
        writer: &ArtifactRunWriter,
        artifacts: &ChildAttemptArtifacts,
        command: &ExternalAgentCommand,
        runtime: SupervisorRuntime,
    ) -> Result<Self> {
        Ok(Self {
            expected: binding(writer.run_dir(), artifacts, command, runtime)?,
            transcript: artifacts.raw_stdout_relative.clone(),
        })
    }

    pub(super) fn matches_assignment(&self, assignment: &OrchestratorAssignment) -> bool {
        self.expected.task_id == assignment.id && self.expected.role == assignment.role.as_str()
    }
}

pub(super) fn bound_review_evidence(
    writer: &ArtifactRunWriter,
    source: &ReviewAttemptSource,
) -> Result<Value> {
    review_commands::read_review_evidence(writer, &source.expected, &source.transcript)
}

#[cfg(test)]
fn review_evidence(
    writer: &ArtifactRunWriter,
    artifacts: &ChildAttemptArtifacts,
    command: &ExternalAgentCommand,
    runtime: SupervisorRuntime,
) -> Result<Value> {
    bound_review_evidence(
        writer,
        &ReviewAttemptSource::bind(writer, artifacts, command, runtime)?,
    )
}

/// Nested sources come only from the imported journal set and authored Worker
/// identity. The parent source attempt is checked before reading any receipt.
pub(super) fn nested_review_evidence(
    writer: &ArtifactRunWriter,
    parent: &str,
    worker: &str,
    attempt: usize,
) -> Result<Value> {
    let root = PathBuf::from("nested")
        .join(parent)
        .join(format!("attempt-{attempt}"))
        .join(worker);
    let summary = root.join("command.json");
    let bytes = writer.read_authenticated(&receipt_path(&summary), MAX_RECEIPT_BYTES)?;
    let receipt: TargetContainmentReceipt = serde_json::from_slice(&bytes)?;
    let expected = TargetBinding {
        run_id: writer
            .run_dir()
            .file_name()
            .and_then(|name| name.to_str())
            .context("review run directory has no identity")?
            .to_owned(),
        task_id: worker.to_owned(),
        parent: Some(parent.to_owned()),
        attempt,
        role: "worker".to_owned(),
        runtime: receipt.binding.runtime,
        command_summary: summary,
    };
    review_commands::read_review_evidence(writer, &expected, &root.join("stdout.jsonl"))
}

/// Same authenticated summary/receipt projection as a current capture. The
/// expected source run and physical Worker attempt are never rewritten.
pub(super) fn historical_nested_review_evidence(
    reader: &ArtifactRunReader,
    parent: &str,
    worker: &str,
    attempt: usize,
) -> Result<Value> {
    let root = PathBuf::from("nested")
        .join(parent)
        .join(format!("attempt-{attempt}"))
        .join(worker);
    let expected = TargetBinding {
        run_id: reader.finalization().run_id.clone(),
        task_id: worker.to_owned(),
        parent: Some(parent.to_owned()),
        attempt,
        role: "worker".to_owned(),
        runtime: SupervisorRuntime::Codex,
        command_summary: root.join("command.json"),
    };
    review_commands::read_finalized_review_evidence(reader, &expected, &root.join("stdout.jsonl"))
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
    fn helper_inventory_retains_owner_and_refuses_missing_target_receipt() {
        let mut missing = fixture();
        let mut fixture = fixture();
        let mut run = super::super::tests::injected_verified_run(&fixture.command);
        run.stdout.target_launch_attempted = true;
        run.attach_fixed_version_probe_evidence_for_test(EnvironmentFixedVersionProbeEvidence {
            executable: EnvironmentExecutable::Codex,
            exit_code: Some(0),
            timed_out: false,
            stdout: EnvironmentFixedVersionProbeStream {
                text: "codex test".into(),
                truncated: false,
            },
            stderr: EnvironmentFixedVersionProbeStream {
                text: String::new(),
                truncated: false,
            },
            process_tree: run.process_tree.unwrap(),
            side_effects: run.side_effects.unwrap(),
        });
        persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
            &run,
        )
        .unwrap();
        let path = fixture
            .artifacts
            .command_record_relative
            .with_extension("helper-inventory.json");
        let inventory: Value = serde_json::from_slice(
            &fixture
                .writer
                .read_authenticated(&path, MAX_SUPERVISOR_REPORT_BYTES)
                .expect("retained helper inventory"),
        )
        .unwrap();
        assert_eq!(inventory["owner"]["task_id"], "research");
        assert_eq!(inventory["helpers"][0]["kind"], "version_probe");
        assert_eq!(inventory["helpers"][1]["kind"], "target");
        assert_eq!(inventory["complete"], true);
        assert_eq!(inventory["quiescence_verified"], true);
        assert_eq!(
            inventory["helpers"][0]["process_tree"]["status"],
            "verified_empty"
        );
        run.process_tree = None;
        assert!(
            persist(
                &mut missing.writer,
                &missing.artifacts,
                &missing.command,
                SupervisorRuntime::Codex,
                &run
            )
            .is_err(),
            "spawned helper without a typed receipt must refuse"
        );
        let refused: Value = serde_json::from_slice(
            &missing
                .writer
                .read_authenticated(&path, MAX_SUPERVISOR_REPORT_BYTES)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(refused["complete"], false);
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

    // This is an offline capture fixture. It launches no provider or command.
    #[cfg(unix)]
    fn native_review_run(
        fixture: &Fixture,
        transcript: &str,
        output: Option<&str>,
    ) -> ExternalAgentRun {
        use crate::external_agent::codex_app_server::{
            CommandExecutionEvidence, CommandExecutionObservation, CommandExecutionSnapshot,
            CommandExecutionStatus, TurnTerminalStatus,
        };
        let mut run = super::super::tests::injected_verified_run(&fixture.command);
        let bytes =
            crate::process_runner::CapturedBytes::from_bytes_for_test(transcript.as_bytes());
        run.stdout = crate::external_agent::CapturedOutput::from_captured_bytes_for_test(&bytes);
        run.stdout.target_launch_attempted = true;
        let started = CommandExecutionSnapshot {
            command: "/bin/bash -lc 'diagnostic'".to_owned(),
            cwd: fixture.command.cwd.to_string_lossy().into_owned(),
            status: CommandExecutionStatus::InProgress,
            exit_code: None,
            aggregated_output: None,
            review_redacted: false,
        };
        run.set_codex_command_execution_evidence_for_test(CommandExecutionEvidence {
            thread_id: "private-thread-id".to_owned(),
            turn_id: "private-turn-id".to_owned(),
            turn_status: TurnTerminalStatus::Completed,
            observations: vec![CommandExecutionObservation::Complete {
                item_id: "native-command-id".to_owned(),
                started: started.clone(),
                completed: CommandExecutionSnapshot {
                    status: CommandExecutionStatus::Failed,
                    exit_code: Some(7),
                    aggregated_output: output.map(str::to_owned),
                    ..started
                },
            }],
        });
        run
    }

    #[cfg(unix)]
    fn retain_review_fixture(fixture: &mut Fixture, run: &ExternalAgentRun) -> Result<()> {
        // The real importer writes the held stream after persisting the existing
        // command summary and target receipt.
        persist(
            &mut fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
            run,
        )?;
        fixture.writer.write_bytes(
            &fixture.artifacts.raw_stdout_relative,
            run.stdout_bytes(),
            ArtifactFileDisposition::PrivateEvidence,
        )?;
        Ok(())
    }

    #[cfg(unix)]
    fn read_review_fixture(fixture: &Fixture) -> Result<Value> {
        review_evidence(
            &fixture.writer,
            &fixture.artifacts,
            &fixture.command,
            SupervisorRuntime::Codex,
        )
    }

    #[test]
    #[cfg(unix)] // Uses the existing owned-pipe CapturedBytes injection seam.
    fn bounded_review_preserves_native_result_when_only_raw_result_is_in_omitted_middle(
    ) -> Result<()> {
        use crate::review::{
            build_bounded_review_lens_request, BoundedReviewLensRequestSources,
            ReviewLensBindingMaterial, ReviewLensScopedInformation,
        };
        let mut fixture = fixture();
        let output = "{\"first\":1}\n{\"second\":2}\n";
        let middle = json!({
            "method":"item/completed",
            "params":{"threadId":"private-thread-id","turnId":"private-turn-id",
                "item":{"id":"native-command-id","type":"commandExecution",
                    "command":"/bin/bash -lc 'diagnostic'",
                    "cwd":fixture.command.cwd,"status":"failed","exitCode":7,
                    "aggregatedOutput":output}}
        })
        .to_string();
        let pad = "irrelevant reasoning\n".repeat(REVIEW_LENS_REQUEST_LIMIT_BYTES / 10);
        let transcript = format!("{pad}{middle}\n{pad}");
        let run = native_review_run(&fixture, &transcript, Some(output));
        retain_review_fixture(&mut fixture, &run)?;
        let evidence = read_review_fixture(&fixture)?;
        assert_eq!(evidence["review_complete"], true);
        assert_eq!(evidence["target_quiescence_verified"], true);
        let observed = &evidence["commands"]["commands"][0];
        assert_eq!(
            observed["native_command"]["text"],
            "/bin/bash -lc 'diagnostic'"
        );
        assert_eq!(observed["cwd"]["text"], json!(fixture.command.cwd));
        assert_eq!(observed["status"], "failed");
        assert_eq!(observed["exit_code"], 7);
        assert_eq!(observed["aggregated_output"]["text"], output);
        assert_eq!(observed["stdout"], "unavailable");
        assert_eq!(observed["stderr"], "unavailable");
        assert_eq!(observed["argv"], json!(["/bin/bash", "-lc", "diagnostic"]));
        assert_eq!(observed["argv_status"], "captured");
        assert_eq!(
            super::super::researcher::observed_command_argv("/bin/bash -c '  diagnostic\n'"),
            Some(vec![
                "/bin/bash".to_owned(),
                "-c".to_owned(),
                "  diagnostic\n".to_owned()
            ])
        );
        assert_eq!(
            super::super::researcher::observed_command_argv("/bin/bash -lc '$UNEXPANDED' extra"),
            None
        );
        assert_eq!(evidence["acceptance_authority"], false);
        let semantic = serde_json::to_string(&evidence)?;
        for excluded in [
            "irrelevant reasoning",
            "private-thread-id",
            "private-turn-id",
            "codex_permissions",
            "command_seal_snapshot",
            "budget_interruption",
        ] {
            assert!(
                !semantic.contains(excluded),
                "unexpected field/content: {excluded}"
            );
        }
        let binding = json!({"agent_id":"research","diff_oid":"candidate"});
        let bindings = ReviewLensBindingMaterial {
            candidate_binding: json!({"supervisor_inspected":binding}),
            path_bindings: json!({"assigned_paths":["README.md"]}),
            validation_bindings: json!({"native_execution_evidence":{
                "required_for_acceptance":true,"candidate_binding":binding,
                "review_complete":true,"targets":[evidence]
            }}),
        };
        let lens = super::super::tests::single_parent_acceptance_review_lenses().remove(0);
        let sources = BoundedReviewLensRequestSources {
            child_transcript: &transcript,
            authoritative_transcript_path: &fixture.artifacts.raw_stdout_relative,
            diff: "+diagnostic review\n",
            output_report: "{\"claim\":\"success\"}",
            bindings: &bindings,
        };
        let request = build_bounded_review_lens_request(&lens, sources)?;
        let ReviewLensScopedInformation::BoundedFullChildTranscript {
            child_transcript,
            bindings: received,
            ..
        } = &request.information
        else {
            panic!("missing bounded full transcript")
        };
        assert!(child_transcript.truncated);
        assert!(child_transcript.omitted_bytes > 0);
        assert!(!child_transcript.head_excerpt.contains("native-command-id"));
        assert!(!child_transcript.tail_excerpt.contains("native-command-id"));
        assert_eq!(received, &bindings);
        // A changed result must change the request identity, even when the raw
        // result would be entirely outside the selected transcript excerpts.
        let mut changed = bindings.clone();
        changed.validation_bindings["native_execution_evidence"]["targets"][0]["commands"]
            ["commands"][0]["exit_code"] = json!(9);
        let altered = build_bounded_review_lens_request(
            &lens,
            BoundedReviewLensRequestSources {
                bindings: &changed,
                ..sources
            },
        )?;
        assert_ne!(request.request_binding, altered.request_binding);
        for scope in [
            ReviewInformationScope::DiffOnly,
            ReviewInformationScope::OutputReportOnly,
        ] {
            let mut narrow = lens.clone();
            narrow.information_scope = scope;
            let request = build_bounded_review_lens_request(&narrow, sources)?;
            let serialized = serde_json::to_string(&request)?;
            for excluded in [
                "native_execution_evidence",
                "target_quiescence_verified",
                "aggregated_output",
                "native-command-id",
            ] {
                assert!(!serialized.contains(excluded));
            }
        }
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn native_large_fields_remain_reviewable_with_all_commands_and_bounded_honest_views(
    ) -> Result<()> {
        use crate::review::{
            build_bounded_review_lens_request, BoundedReviewLensRequestSources,
            ReviewLensBindingMaterial, ReviewLensScopedInformation,
        };
        let mut fixture = fixture();
        fixture.command = fixture
            .command
            .clone()
            .with_workspace_access(WorkspaceAccess::ReadOnly)
            .with_model_selection(Some("fixture-model".into()), None);
        // Explicit protocol fixture custody; no provider/process is launched.
        for path in [
            &fixture.artifacts.prompt_path,
            &fixture.artifacts.log_path,
            &fixture.artifacts.report_path,
        ] {
            fs::create_dir_all(path.parent().unwrap())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700))?;
            }
        }
        fs::write(
            &fixture.artifacts.prompt_path,
            "inspect the controlled native field fixture",
        )?;
        fs::write(&fixture.artifacts.report_path, "{}")?;
        let sizes = [26895, 16849, 43076, 20676, 44002, 27527, 36772, 19012];
        let outputs = sizes
            .iter()
            .enumerate()
            .map(|(index, size)| {
                format!(
                    "native field {index}\n{}",
                    "x".repeat(*size - format!("native field {index}\n").len())
                )
            })
            .collect::<Vec<_>>();
        assert!(outputs.iter().map(String::len).sum::<usize>() > 64 * 1024);
        let mut items = Vec::new();
        for (index, output) in outputs.iter().enumerate() {
            items.extend(super::super::tests::review_command_items(
                &fixture.command,
                &format!("native-result-{index}"),
                &format!("/bin/bash -lc 'inspect-{index}'"),
                0,
                Some(output),
            ));
        }
        let mut run = super::super::tests::injected_verified_run(&fixture.command);
        super::super::tests::retained_review_turn_fixture(&fixture.command, &mut run, items, 8, 3);
        assert_eq!(
            run.codex_command_execution_evidence()
                .unwrap()
                .observations
                .len(),
            sizes.len()
        );
        retain_review_fixture(&mut fixture, &run)?;
        let evidence = read_review_fixture(&fixture)?;
        assert_eq!(evidence["review_complete"], true);
        assert_eq!(evidence["source_bytes"], run.stdout_bytes().len());
        assert_eq!(evidence["source_sha256"], sha256_hex(run.stdout_bytes()));
        let commands = evidence["commands"]["commands"].as_array().unwrap();
        assert_eq!(
            commands.len(),
            sizes.len(),
            "a large view must not drop command identities"
        );
        assert!(serde_json::to_vec(&evidence["commands"])?.len() <= 64 * 1024);
        for (index, observed) in commands.iter().enumerate() {
            assert_eq!(
                observed["item_id_sha256"],
                sha256_hex(format!("native-result-{index}").as_bytes())
            );
            assert_eq!(
                observed["native_command"]["text"],
                format!("/bin/bash -lc 'inspect-{index}'")
            );
            assert_eq!(
                observed["argv"],
                json!(["/bin/bash", "-lc", format!("inspect-{index}")])
            );
            assert_eq!(observed["cwd"]["text"], json!(fixture.command.cwd));
            assert_eq!(observed["status"], "completed");
            assert_eq!(observed["exit_code"], 0);
            let output = &observed["aggregated_output"];
            assert_eq!(
                output["status"], "captured",
                "native field is fully observed"
            );
            assert_eq!(output["original_bytes"], sizes[index]);
            assert_eq!(output["sha256"], sha256_hex(outputs[index].as_bytes()));
            assert_eq!(output["view_truncated"], true, "review view is an excerpt");
            assert!(output["omitted_bytes"].as_u64().unwrap() > 0);
            let text = output["text"].as_str().unwrap();
            assert!(text.len() < 3 * 1024);
            assert!(text.contains("omitted from review view"));
            assert_ne!(text, outputs[index]);
            assert_eq!(output["view_sha256"], sha256_hex(text.as_bytes()));
            assert_eq!(observed["stdout"], "unavailable");
            assert_eq!(observed["stderr"], "unavailable");
        }
        let candidate = json!({"agent_id":"research","diff_oid":"large-field-candidate"});
        let bindings = ReviewLensBindingMaterial {
            candidate_binding: json!({"supervisor_inspected":candidate}),
            path_bindings: json!({"assigned_paths":["README.md"]}),
            validation_bindings: json!({"native_execution_evidence":{
                "required_for_acceptance":true, "candidate_binding":candidate,
                "review_complete":evidence["review_complete"], "targets":[evidence]
            }}),
        };
        let lens = super::super::tests::single_parent_acceptance_review_lenses().remove(0);
        let transcript = std::str::from_utf8(run.stdout_bytes())?;
        let sources = BoundedReviewLensRequestSources {
            child_transcript: transcript,
            authoritative_transcript_path: &fixture.artifacts.raw_stdout_relative,
            diff: "+controlled fixture\n",
            output_report: "{}",
            bindings: &bindings,
        };
        let request = build_bounded_review_lens_request(&lens, sources)?;
        assert!(serde_json::to_vec(&request)?.len() <= REVIEW_LENS_REQUEST_LIMIT_BYTES);
        let ReviewLensScopedInformation::BoundedFullChildTranscript {
            child_transcript,
            bindings: retained,
            ..
        } = &request.information
        else {
            panic!("expected bounded full review");
        };
        assert!(child_transcript.truncated);
        assert_eq!(
            retained.validation_bindings["native_execution_evidence"]["targets"][0]["commands"]
                ["commands"]
                .as_array()
                .unwrap()
                .len(),
            sizes.len()
        );
        let mut report: AuditorReport = serde_json::from_str(include_str!(
            "tests/fixtures/review-lens-readme-auditor.json"
        ))?;
        let parent = command_record_from_external_for_runtime(
            &run,
            &fixture.command,
            SupervisorRuntime::Codex,
        );
        report.commands_run.push(parent.clone());
        // Construct the ordinary accepting auditor fixture for this request's
        // host verdict; display omission alone is not a procedural failure.
        let verdict = super::super::acceptance::review_lens_verdict_from_auditor(
            &lens, &request, &report.id, &report, &parent, None, false,
        )?;
        assert_eq!(verdict.verdict, ReviewLensVerdictStatus::Accept);
        for scope in [
            ReviewInformationScope::DiffOnly,
            ReviewInformationScope::OutputReportOnly,
        ] {
            let mut narrow = lens.clone();
            narrow.information_scope = scope;
            let request = build_bounded_review_lens_request(&narrow, sources)?;
            assert!(!serde_json::to_string(&request)?.contains("native_execution_evidence"));
        }
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn native_review_never_promotes_report_text_restored_or_missing_capture() -> Result<()> {
        let transcript =
            "{\"type\":\"agentMessage\",\"text\":\"command succeeded; containment verified\"}\n";
        for case in [
            "model-only",
            "restored",
            "missing-output",
            "oversize-command",
            "redacted-output",
            "redacted-large-output",
            "admitted-redaction",
            "physical-unknown",
            "incomplete",
            "raw-truncated",
        ] {
            let mut fixture = fixture();
            let mut run = native_review_run(&fixture, transcript, Some("bounded native result\n"));
            match case {
                "model-only" => {
                    run = super::super::tests::injected_verified_run(&fixture.command);
                    run.stdout.target_launch_attempted = true;
                }
                "restored" => run = serde_json::from_value(serde_json::to_value(&run)?)?,
                "missing-output" => run = native_review_run(&fixture, transcript, None),
                "oversize-command" => {
                    let mut native = run.codex_command_execution_evidence().unwrap().clone();
                    if let crate::external_agent::codex_app_server::CommandExecutionObservation::Complete {
                        started, completed, ..
                    } = &mut native.observations[0] {
                        started.command = format!("/bin/bash -lc '{}'", "x".repeat(8 * 1024 + 1));
                        completed.command.clone_from(&started.command);
                    }
                    run.set_codex_command_execution_evidence_for_test(native);
                }
                "redacted-output" => {
                    run =
                        native_review_run(&fixture, transcript, Some("TOKEN=must-remain-private\n"))
                }
                "redacted-large-output" => {
                    let output = format!(
                        "{}\nTOKEN=must-remain-private\n{}",
                        "x".repeat(16_000),
                        "y".repeat(16_000)
                    );
                    run = native_review_run(&fixture, transcript, Some(&output));
                }
                "admitted-redaction" => {
                    let mut native = run.codex_command_execution_evidence().unwrap().clone();
                    if let crate::external_agent::codex_app_server::CommandExecutionObservation::Complete {
                        completed, ..
                    } = &mut native.observations[0] {
                        completed.review_redacted = true;
                        completed.aggregated_output = Some("<redacted>".to_owned());
                    }
                    run.set_codex_command_execution_evidence_for_test(native);
                }
                "physical-unknown" => {
                    run.process_tree = None;
                    run.side_effects = None;
                }
                "incomplete" => {
                    use crate::external_agent::codex_app_server::{
                        CommandExecutionEvidence, CommandExecutionObservation,
                        CommandExecutionObservationIssue, TurnTerminalStatus,
                    };
                    run.set_codex_command_execution_evidence_for_test(CommandExecutionEvidence {
                        thread_id: "thread".into(),
                        turn_id: "turn".into(),
                        turn_status: TurnTerminalStatus::Completed,
                        observations: vec![CommandExecutionObservation::Incomplete {
                            item_id: "missing-result".into(),
                            started: None,
                            reason:
                                CommandExecutionObservationIssue::MissingOrInvalidCompletedFields,
                        }],
                    });
                }
                "raw-truncated" => {
                    let bytes =
                        crate::process_runner::CapturedBytes::from_bytes_with_truncation_for_test(
                            transcript.as_bytes(),
                            true,
                        );
                    // Preserve the held semantic observations while replacing
                    // only their source capture with explicitly lossy bytes.
                    let native = run.codex_command_execution_evidence().unwrap().clone();
                    run.stdout =
                        crate::external_agent::CapturedOutput::from_captured_bytes_for_test(&bytes);
                    run.stdout.target_launch_attempted = true;
                    run.set_codex_command_execution_evidence_for_test(native);
                }
                _ => unreachable!(),
            }
            let retained = retain_review_fixture(&mut fixture, &run);
            if case == "physical-unknown" {
                // Existing helper-inventory refusal stays binding, after the
                // summary and unknown target facts have been retained.
                assert!(retained.is_err());
                fixture.writer.write_bytes(
                    &fixture.artifacts.raw_stdout_relative,
                    run.stdout_bytes(),
                    ArtifactFileDisposition::PrivateEvidence,
                )?;
            } else {
                retained?;
            }
            let evidence = read_review_fixture(&fixture)?;
            assert_eq!(evidence["review_complete"], false, "{case}");
            assert_eq!(evidence["acceptance_authority"], false);
            if matches!(case, "model-only" | "restored" | "physical-unknown") {
                assert_eq!(evidence["target_quiescence_verified"], false);
                assert_eq!(evidence["target_process_tree"]["status"], "unknown");
                assert_eq!(evidence["target_side_effects"]["status"], "unknown");
            }
            assert!(!serde_json::to_string(&evidence)?.contains("must-remain-private"));
            let expected = binding(
                fixture.writer.run_dir(),
                &fixture.artifacts,
                &fixture.command,
                SupervisorRuntime::Codex,
            )?;
            let reader = finalize(fixture.writer, &fixture.repo, &fixture.run_id);
            let historical = review_commands::read_finalized_review_evidence(
                &reader,
                &expected,
                &fixture.artifacts.raw_stdout_relative,
            )?;
            assert_eq!(historical, evidence, "finalization promoted {case}");
            assert_eq!(historical["review_complete"], false, "{case}");
        }
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn native_review_refuses_foreign_attempt_and_missing_or_changed_authenticated_source(
    ) -> Result<()> {
        let mut fixture = fixture();
        let run = native_review_run(&fixture, "native capture\n", Some("observed output"));
        retain_review_fixture(&mut fixture, &run)?;
        let mut foreign = fixture.command.clone();
        foreign.assignment_process_launch_attempt = Some(3);
        assert!(review_evidence(
            &fixture.writer,
            &fixture.artifacts,
            &foreign,
            SupervisorRuntime::Codex
        )
        .is_err());
        let source = fixture
            .writer
            .run_dir()
            .join(&fixture.artifacts.raw_stdout_relative);
        let bytes = fs::read(&source)?;
        fs::write(&source, b"changed native capture")?;
        assert!(read_review_fixture(&fixture).is_err());
        fs::write(&source, bytes)?;
        fs::remove_file(&source)?;
        assert!(read_review_fixture(&fixture).is_err());
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn nested_review_keeps_native_facts_bound_to_parent_worker_and_attempt() -> Result<()> {
        let mut fixture = fixture();
        let root = PathBuf::from("nested/parent/attempt-2/research");
        fixture.artifacts = ChildAttemptArtifacts {
            prompt_path: fixture.writer.run_dir().join(&root).join("prompt.md"),
            report_path: fixture.writer.run_dir().join("incoming/report.json"),
            log_path: fixture.writer.run_dir().join("capture/events.jsonl"),
            raw_report_relative: root.join("report.json"),
            raw_stdout_relative: root.join("stdout.jsonl"),
            command_record_relative: root.join("command.json"),
        };
        fixture.command = ExternalAgentCommand::codex(
            "unused-codex",
            &fixture.repo,
            &fixture.artifacts.prompt_path,
            &fixture.artifacts.log_path,
            &fixture.artifacts.report_path,
            Duration::from_secs(1),
        )
        .with_agent_lifecycle(&fixture.repo, "worker", fixture.run_id.as_str(), "research")
        .with_agent_parent("parent");
        fixture.command.assignment_process_launch_attempt = Some(2);
        let run = native_review_run(
            &fixture,
            "native Worker source\n",
            Some("native Worker output"),
        );
        retain_review_fixture(&mut fixture, &run)?;
        let evidence = nested_review_evidence(&fixture.writer, "parent", "research", 2)?;
        assert_eq!(evidence["binding"]["parent"], "parent");
        assert_eq!(evidence["binding"]["task_id"], "research");
        assert_eq!(evidence["binding"]["attempt"], 2);
        assert_eq!(evidence["review_complete"], true);
        for (parent, worker, attempt) in [
            ("foreign", "research", 2),
            ("parent", "foreign", 2),
            ("parent", "research", 3),
        ] {
            assert!(nested_review_evidence(&fixture.writer, parent, worker, attempt).is_err());
        }
        let reader = finalize(fixture.writer, &fixture.repo, &fixture.run_id);
        assert_eq!(
            historical_nested_review_evidence(&reader, "parent", "research", 2)?,
            evidence,
        );
        for (parent, worker, attempt) in [
            ("foreign", "research", 2),
            ("parent", "foreign", 2),
            ("parent", "research", 3),
        ] {
            assert!(historical_nested_review_evidence(&reader, parent, worker, attempt).is_err());
        }
        let source =
            crate::artifacts::run_dir(&fixture.repo, RunArtifactFamily::Supervise, &fixture.run_id)
                .join(&fixture.artifacts.raw_stdout_relative);
        fs::write(&source, b"corrupt historical capture")?;
        assert!(historical_nested_review_evidence(&reader, "parent", "research", 2).is_err());
        fs::remove_file(&source)?;
        assert!(historical_nested_review_evidence(&reader, "parent", "research", 2).is_err());
        Ok(())
    }
}
