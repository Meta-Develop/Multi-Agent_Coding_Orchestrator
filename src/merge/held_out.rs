//! Parent-owned argv validation of an already captured candidate.
use super::*;
use crate::process_runner::{run_process_cancellable, ProcessCancellation};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandObservationStatus {
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandObservation {
    pub status: CommandObservationStatus,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub message: Option<String>,
}

impl CommandObservation {
    pub(crate) fn unknown(message: impl Into<String>) -> Self {
        Self {
            status: CommandObservationStatus::Unknown,
            exit_code: None,
            timed_out: false,
            duration_ms: 0,
            message: Some(message.into()),
        }
    }
}

/// The caller must hold the candidate's write lease and bind this observation to
/// the preview and operator-owned argv. This function grants no merge authority.
pub(crate) fn run(
    preview: &MergeApplyPreview,
    argv: &[String],
    deadline: Instant,
    cancellation: &ProcessCancellation,
) -> CommandObservation {
    let started = Instant::now();
    let result = (|| -> Result<CommandObservation> {
        let (program, args) = argv.split_first().context("validation argv is empty")?;
        if program.is_empty() || argv.iter().any(|arg| arg.contains('\0')) {
            bail!("validation argv contains an invalid program or NUL");
        }
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            bail!("validation deadline or cancellation prevents candidate preparation");
        }
        let sandbox = CandidateValidationSandbox::create_with_local_git_options(
            preview,
            MergeLocalGitOptions::default(),
        )?;
        let environment_root = sandbox.validation_environment_root();
        let redactor = validation_diagnostics_redactor(&environment_root);
        let environment = validation_command_environment(&environment_root)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || cancellation.is_cancelled() {
            bail!("validation deadline or cancellation prevents command dispatch");
        }
        let output = run_process_cancellable(
            ProcessSpec::direct(
                "parent held-out validation",
                program,
                args,
                sandbox.path(),
                VALIDATION_CAPTURE_LIMIT_BYTES,
            )
            .with_environment(EnvironmentMode::ClearAndSet(environment))
            .with_stdin(StdinMode::Null)
            .with_timeout(Some(remaining.min(CANDIDATE_VALIDATION_PROCESS_TIMEOUT))),
            cancellation,
        );
        let mut observation = match output {
            Ok(output) => {
                let verified = require_verified_process_output(
                    "parent held-out validation",
                    &output,
                    SideEffectConfinementProfileKind::StrictOfflineWorkspace,
                );
                let completed = verified.is_ok()
                    && !output.timed_out
                    && !cancellation.is_cancelled()
                    && Instant::now() < deadline
                    && output.status.is_some()
                    && output.process_error.is_none()
                    && output.stdin_error.is_none();
                CommandObservation {
                    status: if !completed {
                        CommandObservationStatus::Unknown
                    } else if output.status.is_some_and(|status| status.success()) {
                        CommandObservationStatus::Passed
                    } else {
                        CommandObservationStatus::Failed
                    },
                    exit_code: output.status.and_then(|status| status.code()),
                    timed_out: output.timed_out,
                    duration_ms: output.duration_ms(),
                    message: verified
                        .err()
                        .map(|error| error.to_string())
                        .or_else(|| candidate_validation_message(&output, &redactor)),
                }
            }
            Err(error) => {
                CommandObservation::unknown(format!("validation process unavailable: {error}"))
            }
        };
        // Integrity is independent of exit status, including failed or interrupted commands.
        let integrity = sandbox.enforce_candidate_integrity(
            preview,
            ValidationReport {
                name: "held-out candidate integrity".into(),
                status: ValidationStatus::Passed,
                message: None,
                paths: Vec::new(),
            },
        );
        if integrity.status != ValidationStatus::Passed {
            observation.status = CommandObservationStatus::Failed;
            observation.message = integrity.message;
        }
        if let Some(message) = observation.message.as_mut() {
            *message = redact_validation_diagnostic(&redactor, message);
        }
        Ok(observation)
    })();
    let mut observation = result.unwrap_or_else(|_| {
        // Preparation errors may contain private repository paths; retain only the failure class.
        CommandObservation::unknown("candidate validation preparation or deadline unavailable")
    });
    if observation.status == CommandObservationStatus::Passed
        && (cancellation.is_cancelled() || Instant::now() >= deadline)
    {
        observation.status = CommandObservationStatus::Unknown;
        observation.message =
            Some("validation integrity completed after cancellation or deadline".into());
    }
    observation.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    observation
}
