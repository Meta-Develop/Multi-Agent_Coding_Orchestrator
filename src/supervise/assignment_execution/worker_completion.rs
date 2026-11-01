//! A stopped native turn is incomplete evidence, not a malformed Worker report.

use super::*;

#[derive(Debug)]
struct IncompleteWorkerSet(Vec<anyhow::Error>);

impl std::fmt::Display for IncompleteWorkerSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "isolated Worker set failed; no continuation or replay authorized: {}",
            self.0
                .iter()
                .map(|error| format!("{error:#}"))
                .collect::<Vec<_>>()
                .join("; ")
        )
    }
}

impl std::error::Error for IncompleteWorkerSet {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0
            .iter()
            .find(|error| error.is::<IncompleteWorkerOutcome>())
            .or_else(|| self.0.first())
            .map(|error| error.as_ref())
    }
}

pub(super) fn incomplete_set(errors: Vec<anyhow::Error>) -> anyhow::Error {
    IncompleteWorkerSet(errors).into()
}

#[derive(Debug, serde::Serialize, thiserror::Error)]
#[error("isolated Worker incomplete: {cause}")]
pub(super) struct IncompleteWorkerOutcome {
    status: &'static str,
    usage_complete: bool,
    assignment_id: String,
    reservation_id: crate::supervise_budget::BudgetReservationId,
    cause: IncompleteWorkerCause,
}

#[derive(Debug, serde::Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum IncompleteWorkerCause {
    #[error("budget interruption: grant={grant}, observed_floor={observed_floor}, terminal_acknowledgement={terminal_acknowledgement:?}")]
    BudgetInterruption {
        grant: u64,
        observed_floor: u64,
        thread_id: String,
        turn_id: String,
        terminal_acknowledgement:
            Option<crate::external_agent::codex_app_server::TurnTerminalStatus>,
    },
    #[error(
        "process did not complete successfully: exit_code={exit_code:?}, timed_out={timed_out}"
    )]
    Process {
        exit_code: Option<i32>,
        timed_out: bool,
    },
}

pub(super) fn require_completed(
    context: &AssignmentExecutionContext<'_, '_>,
    capture: &CapturedChildAttempt<'_>,
) -> Result<()> {
    if external_process_completed(&capture.external_run, capture.launch_runtime) {
        return Ok(());
    }
    let cause = match capture.external_run.budget_interruption() {
        Some(interruption) => IncompleteWorkerCause::BudgetInterruption {
            grant: interruption.grant,
            observed_floor: interruption.observed_floor,
            thread_id: interruption.thread_id.clone(),
            turn_id: interruption.turn_id.clone(),
            terminal_acknowledgement: interruption.terminal_acknowledgement,
        },
        None => IncompleteWorkerCause::Process {
            exit_code: capture.external_run.exit_code,
            timed_out: capture.external_run.timed_out,
        },
    };
    let rejected = IncompleteWorkerOutcome {
        status: "rejected_incomplete",
        usage_complete: false,
        assignment_id: context.assignment.id.clone(),
        reservation_id: capture.budget_reservation.reservation.id,
        cause,
    };
    with_supervisor_artifacts(context.artifacts, |writer, _| {
        write_artifact_json(
            writer,
            &capture
                .attempt_artifacts
                .raw_report_relative
                .with_extension("outcome.json"),
            &rejected,
            MAX_SUPERVISOR_REPORT_BYTES,
            ArtifactFileDisposition::PrivateEvidence,
        )
    })
    .with_context(|| rejected.to_string())?;
    Err(rejected.into())
}
