//! Attempt-scoped adapter for an explicitly trusted lifecycle transport.
//!
//! This seam does not create local run evidence from remote bytes. Its events
//! must be persisted by the coordinator before advancing across effects. Durable
//! resume, candidate import/recapture, and cleanup authorization belong to that
//! coordinator; cleanup is deliberately absent from this adapter.

use super::*;
use crate::executor::{SshConfig, SshConfigInput};
use crate::process_runner::ProcessCancellation;
use std::{
    num::NonZeroU32,
    path::{Component, Path, PathBuf},
};

/// Coordinator-owned identity. Reuse the nonce only when resuming this attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisedAttemptId {
    pub run_id: RunId,
    pub assignment_id: AssignmentId,
    pub attempt: NonZeroU32,
    pub nonce: Nonce,
}

/// Lexical translation only: callers supply bytes from their existing secure
/// input readers. This type neither follows links nor reads a local workspace.
#[derive(Debug)]
pub struct SupervisedPaths {
    root: PathBuf,
}

impl SupervisedPaths {
    pub fn new(root: PathBuf) -> ExecutorResult<Self> {
        require_absolute_normalized(&root)?;
        Ok(Self { root })
    }

    pub fn logical(&self, path: &Path) -> ExecutorResult<LogicalPath> {
        require_absolute_normalized(path)?;
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| invalid("translated path is outside its declared local root"))?;
        let mut parts = Vec::new();
        for component in relative.components() {
            let Component::Normal(part) = component else {
                return Err(invalid("translated path is not normalized"));
            };
            parts.push(
                part.to_str()
                    .ok_or_else(|| invalid("translated path is not UTF-8"))?,
            );
        }
        LogicalPath::new(parts.join("/"))
    }

    pub fn input(
        &self,
        path: &Path,
        purpose: ManifestPurpose,
        bytes: Vec<u8>,
    ) -> ExecutorResult<ManifestEntry> {
        ManifestEntry::input_file(self.logical(path)?, purpose, bytes)
    }

    pub fn output(
        &self,
        path: &Path,
        purpose: ManifestPurpose,
        max_bytes: u64,
    ) -> ExecutorResult<ManifestEntry> {
        ManifestEntry::output_path(self.logical(path)?, purpose, max_bytes)
    }

    pub fn argument(&self, path: &Path) -> ExecutorResult<TypedArg> {
        Ok(TypedArg::ManifestPath(self.logical(path)?))
    }
}

fn require_absolute_normalized(path: &Path) -> ExecutorResult<()> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("local path is not UTF-8"))?;
    if !path.is_absolute()
        || text
            .split(['/', '\\'])
            .any(|part| matches!(part, "." | ".."))
    {
        return Err(invalid(
            "local path must be absolute without dot components",
        ));
    }
    Ok(())
}

/// The factory must construct a noninteractive lifecycle transport using the
/// supplied trust configuration, including strict host keys and explicit identity.
/// It must not launch a remote assignment during construction. The atomic SSH
/// executor is a different protocol and cannot be used as this factory's transport.
pub struct SupervisedSshExecutor<T> {
    trust: SshConfig,
    executor: SshExecutor<T>,
}

impl<T: SshTransport> SupervisedSshExecutor<T> {
    pub fn configure(
        selection: &ExecutorSelection,
        trust: Option<SshConfig>,
        factory: impl FnOnce(&SshConfig) -> ExecutorResult<T>,
    ) -> ExecutorResult<Self> {
        let target = selection
            .ssh_target()
            .ok_or_else(|| invalid("SSH bridge requires an explicit SSH selection"))?;
        let trust = trust.ok_or_else(|| invalid("SSH target has no trusted configuration"))?;
        if target.host_id.as_str() != trust.host_id()
            || target.endpoint.as_str() != trust.host()
            || target.user.as_str() != trust.user()
            || target.port.get() != trust.port()
            || target.root.as_str() != trust.remote_root()
            || target.helper.as_str() != trust.helper_path()
        {
            return Err(invalid(
                "SSH selection does not match its trusted configuration",
            ));
        }
        revalidate_trust(&trust)?;
        let transport = factory(&trust)?;
        Ok(Self {
            trust,
            executor: SshExecutor::new(target.clone(), transport),
        })
    }

    pub fn prepare(
        &self,
        binding: SupervisedAttemptId,
        manifest: InputManifest,
        launch: LaunchSpec,
        outputs: OutputPolicy,
        cancellation: ProcessCancellation,
        termination: TerminationPolicy,
    ) -> ExecutorResult<SupervisedSshAttempt<'_, T>> {
        // Keep the attempt number and coordinator nonce inside every existing
        // lifecycle key without changing the underlying wire identity contract.
        let nonce = Nonce::new(format!(
            "attempt-{}-{}",
            binding.attempt,
            Digest::for_bytes(binding.nonce.as_str().as_bytes()).as_str()
        ))?;
        super::ssh::validate_manifest_launch_spec(&manifest, &launch)?;
        let request = StageRequest::new(
            AssignmentIdentity::new(
                self.executor.target().host_id.clone(),
                binding.run_id.clone(),
                binding.assignment_id.clone(),
                nonce,
            ),
            manifest,
            launch,
            outputs,
        )?;
        Ok(SupervisedSshAttempt {
            owner: self,
            binding,
            request,
            cancellation,
            termination,
            state: State::Prepared,
        })
    }
}

fn revalidate_trust(trust: &SshConfig) -> ExecutorResult<()> {
    SshConfig::new(SshConfigInput {
        host_id: trust.host_id().to_string(),
        host: trust.host().to_string(),
        user: trust.user().to_string(),
        port: trust.port(),
        identity_file: trust.identity_file().to_path_buf(),
        known_hosts_file: trust.known_hosts_file().to_path_buf(),
        remote_root: trust.remote_root().to_string(),
        helper_path: trust.helper_path().to_string(),
        limits: trust.limits().clone(),
    })
    .map(|_| ())
    .map_err(|_| invalid("SSH trust configuration is unavailable or no longer valid"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SupervisedEvent {
    CancelledBeforeLaunch,
    Staged(Effect<SubmittedLaunchIdentity>),
    Launched(Effect<LaunchReceipt>),
    Reconciled(ExecutionStatus),
    Waited(WaitOutcome),
    Terminated(Effect<TerminationReceipt>),
    Collected(Effect<CollectedResult>),
}

#[allow(clippy::large_enum_variant)]
enum State {
    Prepared,
    Staged(StagedAssignment),
    StageUncertain(Box<UncertainEffect>),
    Submitted(SubmittedLaunchIdentity),
    Running(ExecutionIdentity),
    Terminal(ExecutionIdentity),
    Collected(CollectedResult),
    CancelledBeforeLaunch,
    Failed,
}

/// One in-memory attempt, deliberately neither cloneable nor deserializable.
/// Dropping it does not establish remote quiescence. The coordinator must retain
/// custody on errors/uncertain effects and persist bindings before dispatch.
pub struct SupervisedSshAttempt<'a, T> {
    owner: &'a SupervisedSshExecutor<T>,
    binding: SupervisedAttemptId,
    request: StageRequest,
    cancellation: ProcessCancellation,
    termination: TerminationPolicy,
    state: State,
}

impl<T: SshTransport> SupervisedSshAttempt<'_, T> {
    pub fn binding(&self) -> &SupervisedAttemptId {
        &self.binding
    }

    /// Immutable pre-effect binding for the coordinator's durable intent record.
    pub fn stage_request(&self) -> &StageRequest {
        &self.request
    }

    /// Exact launch intent, available after staging and before launch. A
    /// coordinator must persist this query before calling `advance` again.
    pub fn execution_query(&self) -> Option<ExecutionQuery> {
        match &self.state {
            State::Staged(staged) => Some(ExecutionQuery::Submitted(
                SubmittedLaunchIdentity::for_launch(staged),
            )),
            State::Submitted(submitted) => Some(ExecutionQuery::Submitted(submitted.clone())),
            State::Running(identity) | State::Terminal(identity) => {
                Some(ExecutionQuery::Known(identity.clone()))
            }
            State::Collected(result) => Some(ExecutionQuery::Known(result.identity().clone())),
            _ => None,
        }
    }

    /// Advance at most one lifecycle operation. A wait is limited to 100 ms so
    /// inherited cancellation is observed between bounded transport operations.
    /// Transport implementations must also bound their own connection/read time.
    pub fn advance(&mut self) -> ExecutorResult<SupervisedEvent> {
        if matches!(self.state, State::Prepared | State::Staged(_))
            && self.cancellation.is_cancelled()
        {
            self.state = State::CancelledBeforeLaunch;
        }
        if matches!(self.state, State::CancelledBeforeLaunch) {
            return Ok(SupervisedEvent::CancelledBeforeLaunch);
        }
        revalidate_trust(&self.owner.trust)?;
        match &self.state {
            State::Prepared => {
                // Do not blindly retry even if the lifecycle call returns an error.
                self.state = State::Failed;
                let effect = self.owner.executor.stage(self.request.clone())?;
                match effect {
                    Effect::Confirmed(staged) => {
                        let submitted = SubmittedLaunchIdentity::for_launch(&staged);
                        self.state = State::Staged(staged);
                        Ok(SupervisedEvent::Staged(Effect::Confirmed(submitted)))
                    }
                    Effect::Uncertain(uncertain) => {
                        self.state = State::StageUncertain(uncertain.clone());
                        Ok(SupervisedEvent::Staged(Effect::Uncertain(uncertain)))
                    }
                }
            }
            State::StageUncertain(uncertain) => {
                // Stage reconciliation is explicitly operator-only in this protocol.
                Ok(SupervisedEvent::Staged(Effect::Uncertain(
                    uncertain.clone(),
                )))
            }
            State::Staged(staged) => {
                // Retain the exact submitted identity before crossing the effect.
                // Every subsequent advance queries it rather than launching again.
                let submitted = SubmittedLaunchIdentity::for_launch(staged);
                let State::Staged(staged) =
                    std::mem::replace(&mut self.state, State::Submitted(submitted))
                else {
                    unreachable!();
                };
                let effect = self.owner.executor.launch(LaunchRequest::new(staged))?;
                if let Effect::Confirmed(receipt) = &effect {
                    self.state = State::Running(receipt.identity().clone());
                }
                Ok(SupervisedEvent::Launched(effect))
            }
            State::Submitted(submitted) => {
                let status = self.owner.executor.status(StatusRequest {
                    query: ExecutionQuery::Submitted(submitted.clone()),
                })?;
                self.observe_status(&status);
                // NotFound leaves submission uncertain: it never authorizes replay.
                Ok(SupervisedEvent::Reconciled(status))
            }
            State::Running(identity) => {
                let identity = identity.clone();
                if self.cancellation.is_cancelled() {
                    let effect = self.owner.executor.terminate(TerminateRequest::new(
                        identity.clone(),
                        self.termination.clone(),
                    ))?;
                    if let Effect::Confirmed(receipt) = &effect {
                        let outcome = receipt.after_kill.as_ref().unwrap_or(&receipt.after_term);
                        if !outcome.is_running() {
                            self.state = State::Terminal(identity);
                        }
                    }
                    return Ok(SupervisedEvent::Terminated(effect));
                }
                let outcome = self.owner.executor.wait(WaitRequest::new(
                    identity.clone(),
                    WaitSpec::new(BoundedMillis::new(100)?),
                ))?;
                if !outcome.is_running() {
                    self.state = State::Terminal(identity);
                }
                Ok(SupervisedEvent::Waited(outcome))
            }
            State::Terminal(identity) => {
                // Lost collection replies may be replayed only with this exact
                // identity and its pre-bound collection authority/key.
                let effect = self
                    .owner
                    .executor
                    .collect(CollectRequest::new(identity.clone()))?;
                if let Effect::Confirmed(result) = &effect {
                    self.state = State::Collected(result.clone());
                }
                Ok(SupervisedEvent::Collected(effect))
            }
            State::Collected(result) => Ok(SupervisedEvent::Collected(Effect::Confirmed(
                result.clone(),
            ))),
            State::CancelledBeforeLaunch => unreachable!(),
            State::Failed => Err(invalid(
                "failed attempt requires coordinator reconciliation",
            )),
        }
    }

    fn observe_status(&mut self, status: &ExecutionStatus) {
        match status {
            ExecutionStatus::NotFound => {}
            ExecutionStatus::Running(identity) => self.state = State::Running(identity.clone()),
            ExecutionStatus::Exited { identity, .. }
            | ExecutionStatus::Signaled { identity, .. } => {
                self.state = State::Terminal(identity.clone());
            }
        }
    }
}

fn invalid(reason: &str) -> ExecutorError {
    ExecutorError::InvalidField {
        field: "supervised SSH attempt",
        reason: reason.to_string(),
    }
}
