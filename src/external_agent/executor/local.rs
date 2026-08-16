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
/// local stage/launch state. The real crate's existing synchronous reviewed entrypoint
/// now forwards through this adapter with those concrete parent types. Production
/// selection and remote transport wiring remain separate integration work.
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
