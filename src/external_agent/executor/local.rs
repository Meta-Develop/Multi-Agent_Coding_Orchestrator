/// Compatibility adapter for the existing local external-agent callback.
///
/// The adapter deliberately does not reconstruct command execution, containment,
/// review, cancellation, output capture, or evidence. It forwards the caller's
/// command, cancellation token, and optional borrowed review value exactly once and
/// returns the existing runner's value unchanged.
///
/// This type intentionally does not implement the six-phase [`super::AgentExecutor`]
/// remote lifecycle. The current local contract is one synchronous higher-ranked
/// callback carrying a borrowed review runtime and returning the concrete local run
/// report. Claiming lifecycle parity here would require type erasure or fabricated
/// local stage/launch state. The integration wave must register an outer synchronous
/// seam with those real parent types; local selection then forwards here unchanged,
/// while remote selection may internally drive the six typed operations.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalExecutor;

impl LocalExecutor {
    pub fn forward_existing_run<Command, Cancellation, Review, Run, Runner>(
        &self,
        runner: &Runner,
        command: &Command,
        cancellation: &Cancellation,
        review: Option<Review>,
    ) -> Run
    where
        Runner: Fn(&Command, &Cancellation, Option<Review>) -> Run + ?Sized,
    {
        runner(command, cancellation, review)
    }
}
