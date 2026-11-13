//! Descriptive review projection of held native observations, never launch or
//! cleanup authority. The private command summary is the existing storage path.

use super::*;
use crate::external_agent::codex_app_server::{
    CommandExecutionObservation, CommandExecutionStatus, TurnTerminalStatus,
};

const MAX_COMMAND_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_COMMAND_TEXT_BYTES: usize = 8 * 1024;
// Bounded display of an authenticated native field, distinct from capture loss.
const MAX_OUTPUT_VIEW_BYTES: usize = 2 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaptureStatus {
    Captured,
    Unavailable,
    Incomplete,
    Oversize,
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewText {
    status: CaptureStatus,
    original_bytes: Option<usize>,
    sha256: Option<String>,
    text: Option<String>,
    view_truncated: bool,
    omitted_bytes: usize,
    view_sha256: Option<String>,
}

impl ReviewText {
    fn capture(text: Option<&str>) -> Self {
        let Some(text) = text else {
            return Self {
                status: CaptureStatus::Unavailable,
                original_bytes: None,
                sha256: None,
                text: None,
                view_truncated: false,
                omitted_bytes: 0,
                view_sha256: None,
            };
        };
        let redacted = crate::llm::Redactor::new().redact(text).text != text;
        let status = if text.len() > MAX_COMMAND_TEXT_BYTES {
            CaptureStatus::Oversize
        } else if redacted {
            CaptureStatus::Redacted
        } else {
            CaptureStatus::Captured
        };
        Self {
            text: (status == CaptureStatus::Captured).then(|| text.to_owned()),
            view_truncated: false,
            omitted_bytes: 0,
            view_sha256: (status == CaptureStatus::Captured).then(|| sha256_hex(text.as_bytes())),
            status,
            original_bytes: Some(text.len()),
            sha256: (!redacted).then(|| sha256_hex(text.as_bytes())),
        }
    }

    fn redacted() -> Self {
        Self {
            status: CaptureStatus::Redacted,
            original_bytes: None,
            sha256: None,
            text: None,
            view_truncated: false,
            omitted_bytes: 0,
            view_sha256: None,
        }
    }

    fn capture_output(text: Option<&str>) -> Result<Self> {
        let Some(text) = text else {
            return Ok(Self::capture(None));
        };
        // Redaction precedes hashes and excerpts, including secrets in the
        // omitted middle. No digest of a raw secret is retained.
        if crate::llm::Redactor::new().redact(text).text != text {
            return Ok(Self::redacted());
        }
        if text.len() <= MAX_OUTPUT_VIEW_BYTES {
            return Ok(Self::capture(Some(text)));
        }
        let sha256 = sha256_hex(text.as_bytes());
        let view = crate::review::bounded_review_transcript(
            text,
            Path::new("native/aggregated-output"),
            &sha256,
            MAX_OUTPUT_VIEW_BYTES,
            true,
        )?;
        let excerpt = format!(
            "{}\n[... {} native field bytes omitted from review view ...]\n{}",
            view.head_excerpt, view.omitted_bytes, view.tail_excerpt
        );
        Ok(Self {
            status: CaptureStatus::Captured,
            original_bytes: Some(text.len()),
            sha256: Some(sha256),
            view_sha256: Some(sha256_hex(excerpt.as_bytes())),
            text: Some(excerpt),
            view_truncated: true,
            omitted_bytes: usize::try_from(view.omitted_bytes)?,
        })
    }

    fn complete(&self) -> bool {
        self.status == CaptureStatus::Captured
            && self.text.is_some()
            && self.original_bytes.is_some()
            && self.sha256.is_some()
            && self.view_sha256.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReviewCommand {
    item_id_sha256: String,
    native_command: ReviewText,
    // Only the existing literal wrapper decoder can supply an argv. Unknown
    // shell syntax stays unavailable and cannot satisfy complete evidence.
    argv: Option<Vec<String>>,
    argv_status: CaptureStatus,
    cwd: ReviewText,
    status: String,
    exit_code: Option<i32>,
    // The protocol combines stdout/stderr. Never label it as separate streams.
    aggregated_output: ReviewText,
    stdout: CaptureStatus,
    stderr: CaptureStatus,
}

impl ReviewCommand {
    fn complete(&self) -> bool {
        self.native_command.complete()
            && self.argv_status == CaptureStatus::Captured
            && self.argv.is_some()
            && self.cwd.complete()
            && self.aggregated_output.complete()
            && match self.status.as_str() {
                "completed" => self.exit_code == Some(0),
                "failed" => self.exit_code.is_some_and(|code| code != 0),
                _ => false,
            }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewCommandCapture {
    version: u32,
    status: CaptureStatus,
    source: PathBuf,
    source_bytes: usize,
    source_sha256: String,
    source_truncated: bool,
    thread_id_sha256: Option<String>,
    turn_id_sha256: Option<String>,
    turn_status: Option<TurnTerminalStatus>,
    host_process_completed: bool,
    observation_count: usize,
    commands: Vec<ReviewCommand>,
}

impl ReviewCommandCapture {
    pub(super) fn capture(
        artifacts: &ChildAttemptArtifacts,
        command: &ExternalAgentCommand,
        runtime: SupervisorRuntime,
        run: &ExternalAgentRun,
    ) -> Result<Self> {
        let mut capture = Self {
            version: 1,
            status: CaptureStatus::Unavailable,
            source: artifacts.raw_stdout_relative.clone(),
            source_bytes: run.stdout_bytes().len(),
            source_sha256: sha256_hex(run.stdout_bytes()),
            source_truncated: run.stdout.raw_capture_truncated(),
            thread_id_sha256: None,
            turn_id_sha256: None,
            turn_status: None,
            host_process_completed: false,
            observation_count: 0,
            commands: Vec::new(),
        };
        let Some(native) = run.codex_command_execution_evidence() else {
            return Ok(capture);
        };
        capture.thread_id_sha256 = Some(sha256_hex(native.thread_id.as_bytes()));
        capture.turn_id_sha256 = Some(sha256_hex(native.turn_id.as_bytes()));
        capture.turn_status = Some(native.turn_status);
        capture.observation_count = native.observations.len();
        capture.host_process_completed = runtime == SupervisorRuntime::Codex
            && run.cwd == command.cwd
            && run.stdout.target_launch_attempted
            && external_process_completed(run, runtime);
        capture.status = if capture.host_process_completed
            && !capture.source_truncated
            && !native.thread_id.is_empty()
            && !native.turn_id.is_empty()
            && native.turn_status == TurnTerminalStatus::Completed
        {
            CaptureStatus::Captured
        } else {
            CaptureStatus::Incomplete
        };
        for observation in &native.observations {
            let CommandExecutionObservation::Complete {
                item_id,
                started,
                completed,
            } = observation
            else {
                capture.status = CaptureStatus::Incomplete;
                continue;
            };
            let status = match completed.status {
                CommandExecutionStatus::Completed => "completed",
                CommandExecutionStatus::Failed => "failed",
                CommandExecutionStatus::Declined => "declined",
                CommandExecutionStatus::InProgress => "in_progress",
            };
            let argv = crate::supervise::researcher::observed_command_argv(&completed.command);
            let mut result = ReviewCommand {
                item_id_sha256: sha256_hex(item_id.as_bytes()),
                native_command: ReviewText::capture(Some(&completed.command)),
                argv_status: if argv.is_some() {
                    CaptureStatus::Captured
                } else {
                    CaptureStatus::Unavailable
                },
                argv,
                cwd: ReviewText::capture(Some(&completed.cwd)),
                status: status.to_owned(),
                exit_code: completed.exit_code,
                aggregated_output: ReviewText::capture_output(
                    completed.aggregated_output.as_deref(),
                )?,
                stdout: CaptureStatus::Unavailable,
                stderr: CaptureStatus::Unavailable,
            };
            if !result.native_command.complete() {
                result.argv = None;
                result.argv_status = result.native_command.status.clone();
            }
            if started.review_redacted || completed.review_redacted {
                result.argv = None;
                result.argv_status = CaptureStatus::Redacted;
                result.native_command = ReviewText::redacted();
                result.cwd = ReviewText::redacted();
                result.aggregated_output = ReviewText::redacted();
            }
            // Recheck the descriptive projection at its trust boundary. Failed
            // commands retain their actual nonzero exits; they are complete
            // evidence of failure, never evidence of useful task success.
            if started.command != completed.command
                || started.cwd != completed.cwd
                || started.status != CommandExecutionStatus::InProgress
                || started.exit_code.is_some()
                || !result.complete()
            {
                capture.status = CaptureStatus::Incomplete;
            }
            capture.commands.push(result);
            if serde_json::to_vec(&capture)?.len() > MAX_COMMAND_CAPTURE_BYTES {
                bail!("native review command metadata exceeds the bounded 64 KiB projection");
            }
        }
        Ok(capture)
    }

    fn complete(&self) -> bool {
        self.version == 1
            && self.status == CaptureStatus::Captured
            && self.host_process_completed
            && !self.source_truncated
            && self.turn_status == Some(TurnTerminalStatus::Completed)
            && self.thread_id_sha256.is_some()
            && self.turn_id_sha256.is_some()
            && self.commands.len() == self.observation_count
            && self.commands.iter().all(ReviewCommand::complete)
    }
}

/// Only these named semantic fields may cross the full-transcript boundary.
/// In particular, command seals, provider/account metadata and raw summary
/// stdout are never copied. Authenticated history remains descriptive.
#[derive(Deserialize)]
struct SummaryProjection {
    #[serde(default)]
    review_commands: Option<ReviewCommandCapture>,
}

pub(super) fn read_review_evidence(
    writer: &ArtifactRunWriter,
    expected: &TargetBinding,
    transcript: &Path,
) -> Result<Value> {
    read_review_evidence_with(
        &|path, limit| writer.read_authenticated(path, limit),
        expected,
        transcript,
    )
}

pub(super) fn read_finalized_review_evidence(
    reader: &ArtifactRunReader,
    expected: &TargetBinding,
    transcript: &Path,
) -> Result<Value> {
    if reader.finalization().run_id != expected.run_id {
        bail!("historical native review run differs from its authenticated source");
    }
    read_review_evidence_with(
        &|path, limit| {
            let record = reader
                .finalization()
                .files
                .iter()
                .find(|record| record.path == path)
                .context("historical native review source is absent from its manifest")?;
            if record.disposition != ArtifactFileDisposition::PrivateEvidence
                || record.bytes > u64::try_from(limit)?
            {
                bail!("historical native review source privacy or size mismatch");
            }
            reader.read(path)
        },
        expected,
        transcript,
    )
}

fn read_review_evidence_with(
    read: &dyn Fn(&Path, usize) -> Result<Vec<u8>>,
    expected: &TargetBinding,
    transcript: &Path,
) -> Result<Value> {
    let summary = read(&expected.command_summary, MAX_SUPERVISOR_REPORT_BYTES)?;
    let receipt_bytes = read(&receipt_path(&expected.command_summary), MAX_RECEIPT_BYTES)?;
    let receipt = validate(&receipt_bytes, expected, &summary)?;
    let projection: SummaryProjection = serde_json::from_slice(&summary)?;
    let source = read(transcript, MAX_SUPERVISOR_REPORT_BYTES)?;
    let commands = projection.review_commands;
    if let Some(commands) = &commands {
        if commands.version != 1
            || commands.source != transcript
            || commands.source_bytes != source.len()
            || commands.source_sha256 != sha256_hex(&source)
            || serde_json::to_vec(commands)?.len() > MAX_COMMAND_CAPTURE_BYTES
        {
            bail!("native review command capture source, version, or size mismatch");
        }
    }
    // Public run JSON can restore descriptive process/side-effect labels, but
    // loses the private protocol capture. Do not promote those restored labels
    // into native physical facts in a new review packet.
    let native_custody = commands.as_ref().is_some_and(|capture| {
        capture.version == 1
            && capture.thread_id_sha256.is_some()
            && capture.turn_id_sha256.is_some()
            && capture.turn_status.is_some()
    });
    let target_process_tree = if native_custody {
        receipt.target_process_tree
    } else {
        Observation::Unknown
    };
    let target_side_effects = if native_custody {
        receipt.target_side_effects
    } else {
        Observation::Unknown
    };
    let quiescence_verified = receipt.target_launch_attempted
        && matches!(target_process_tree, Observation::Observed(tree) if tree.is_verified_empty())
        && matches!(target_side_effects, Observation::Observed(effects) if effects.is_verified());
    let complete = quiescence_verified
        && commands
            .as_ref()
            .is_some_and(ReviewCommandCapture::complete);
    Ok(json!({
        "binding": receipt.binding,
        "command_summary_sha256": receipt.command_summary_sha256,
        "source": transcript,
        "source_sha256": sha256_hex(&source),
        "source_bytes": source.len(),
        "target_launch_attempted": receipt.target_launch_attempted,
        "native_capture_available": native_custody,
        "target_process_tree": target_process_tree,
        "target_side_effects": target_side_effects,
        "target_quiescence_verified": quiescence_verified,
        "physical_scope": "native target owned process boundary; no independent descendant PID or root external quiescence claim",
        "stream_layout": "native shell command string plus literal Bash argv when decodable; aggregated stdout/stderr, separate streams unavailable",
        "output_capture_scope": "captured native aggregatedOutput field only; upstream pipe completeness is not attested",
        "output_view": "bounded UTF-8 head/tail excerpts; native field hash/length and view omission/digest are separate",
        "commands_status": if commands.is_some() {"retained_native_capture"} else {"unavailable_legacy"},
        "commands": commands,
        "review_complete": complete,
        "acceptance_authority": false,
    }))
}
