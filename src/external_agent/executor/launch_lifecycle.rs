//! Live process evidence is the only external-runner finalization authority.

use coding_agent_manager_lib::providers::launch_lifecycle::{
    ExternalLaunchCustody, LaunchFinalization,
};

use crate::process_runner::{ProcessCancellation, ProcessOutput, ProcessRunError};

/// Invoke the real runner exactly once after admission; settle from its live
/// result before output materialization or protocol validation can fail.
pub(crate) fn execute<T>(
    mut custody: Option<&mut ExternalLaunchCustody>,
    cancellation: &ProcessCancellation,
    run: impl FnOnce() -> Result<T, ProcessRunError>,
    output: impl FnOnce(&T) -> &ProcessOutput,
) -> Result<T, ProcessRunError> {
    if let Some(custody) = custody.as_deref_mut() {
        custody
            .begin_spawn()
            .map_err(|_| ProcessRunError::EnvironmentFailure {
                label: "external launch".into(),
                command: "declared provider".into(),
                failure: Box::new(super::super::environment_failure(
                    super::super::EnvironmentFailureCategory::MissingCredential,
                    None,
                    "declared launch admission was refused".into(),
                )),
                target_process_started: false,
            })?;
    }
    let result = run();
    match &result {
        Ok(value) => observe_output(custody, output(value), cancellation.is_cancelled()),
        Err(error) => observe_error(custody, error),
    }
    result
}

/// Settle custody before report/output processing can fail or discard evidence.
pub(crate) fn observe_output(
    custody: Option<&mut ExternalLaunchCustody>,
    output: &ProcessOutput,
    cancelled: bool,
) {
    let Some(custody) = custody else { return };
    if !output.process_tree.is_verified_empty() {
        custody.exit_unknown();
        return;
    }
    let reason = if output.timed_out || cancelled {
        LaunchFinalization::Cancelled
    } else if let Some(status) = output.status {
        if status.success() {
            LaunchFinalization::Exited
        } else {
            LaunchFinalization::AbnormalExit
        }
    } else {
        custody.exit_unknown();
        return;
    };
    custody.finalize(reason);
}

pub(crate) fn observe_error(custody: Option<&mut ExternalLaunchCustody>, error: &ProcessRunError) {
    let Some(custody) = custody else { return };
    if let ProcessRunError::Wait { evidence, .. } = error {
        if evidence.process_tree.is_verified_empty() {
            custody.finalize(LaunchFinalization::AbnormalExit);
        } else {
            custody.exit_unknown();
        }
        return;
    }
    if let Some(evidence) = error.registration_rollback_evidence() {
        if evidence.process_tree.is_verified_empty() {
            custody.finalize(LaunchFinalization::Refused);
        } else {
            custody.exit_unknown();
        }
        return;
    }
    if let Some(evidence) = error.cancellation_evidence() {
        if evidence.process_tree.is_verified_empty() {
            custody.finalize(LaunchFinalization::Cancelled);
        } else {
            custody.exit_unknown();
        }
        return;
    }
    match error {
        ProcessRunError::Spawn { .. } => custody.finalize(LaunchFinalization::SpawnFailed),
        ProcessRunError::SetupTimeout { .. }
        | ProcessRunError::TeeConflict { .. }
        | ProcessRunError::StdinTooLarge { .. }
        | ProcessRunError::ContainmentUnavailable { .. }
        | ProcessRunError::EnvironmentFailure {
            target_process_started: false,
            ..
        }
        | ProcessRunError::Cancelled { evidence: None, .. } => {
            custody.finalize(LaunchFinalization::Refused)
        }
        _ => custody.exit_unknown(),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
