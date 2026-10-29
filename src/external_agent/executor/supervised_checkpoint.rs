//! Coordinator-only recovery DTOs. These carry no local execution authority.
use super::{supervised::State, *};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SupervisedCheckpoint {
    pub(crate) binding: SupervisedAttemptId,
    stage_key: IdempotencyKey,
    state: ResumeState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum ResumeState {
    Prepared,
    StageUncertain,
    Staged(Session),
    Submitted(Session),
    Running(Process),
    Terminal(Process),
    Collected(Process),
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    session: SessionId,
    workspace: WorkspaceId,
    launch_key: IdempotencyKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Process {
    session: Session,
    pid: u32,
    pgid: u32,
    start: StartToken,
}

impl SupervisedCheckpoint {
    pub(crate) fn may_have_launched(&self) -> bool {
        matches!(
            self.state,
            ResumeState::Submitted(_)
                | ResumeState::Running(_)
                | ResumeState::Terminal(_)
                | ResumeState::Collected(_)
        )
    }
}

impl Session {
    fn submitted(identity: &SubmittedLaunchIdentity) -> Self {
        Self {
            session: identity.session_id().clone(),
            workspace: identity.workspace_id().clone(),
            launch_key: identity.launch_key().clone(),
        }
    }

    fn staged(&self, request: &StageRequest) -> ExecutorResult<StagedAssignment> {
        let staged = StagedAssignment {
            identity: request.identity.clone(),
            staged_digest: request.manifest.digest().clone(),
            session_id: self.session.clone(),
            workspace_id: self.workspace.clone(),
            manifest: request.manifest.clone(),
            launch_spec: request.launch_spec.clone(),
            collection: request.collection.clone(),
        };
        if SubmittedLaunchIdentity::for_launch(&staged).launch_key() != &self.launch_key {
            return Err(invalid(
                "checkpoint launch identity differs from the staged request",
            ));
        }
        Ok(staged)
    }
}

impl Process {
    fn capture(identity: &ExecutionIdentity) -> Self {
        Self {
            session: Session {
                session: identity.session_id().clone(),
                workspace: identity.workspace_id().clone(),
                launch_key: identity.launch_key().clone(),
            },
            pid: identity.pid(),
            pgid: identity.pgid(),
            start: identity.start_token().clone(),
        }
    }

    fn restore(&self, request: &StageRequest) -> ExecutorResult<ExecutionIdentity> {
        self.session.staged(request)?;
        ExecutionIdentity::from_wire(
            request.identity.host_id.clone(),
            request.identity.run_id.clone(),
            request.identity.assignment_id.clone(),
            request.identity.nonce.clone(),
            request.manifest.digest().clone(),
            self.session.session.clone(),
            self.session.workspace.clone(),
            request.launch_spec.digest().clone(),
            request.collection.clone(),
            self.pid,
            self.pgid,
            self.start.clone(),
            self.session.launch_key.clone(),
        )
    }
}

impl<T: SshTransport> SupervisedSshAttempt<'_, T> {
    pub(crate) fn checkpoint(&self) -> SupervisedCheckpoint {
        let state = match &self.state {
            State::Prepared => ResumeState::Prepared,
            State::Staged(staged) => ResumeState::Staged(Session::submitted(
                &SubmittedLaunchIdentity::for_launch(staged),
            )),
            State::Submitted(submitted) => ResumeState::Submitted(Session::submitted(submitted)),
            State::Running(identity) => ResumeState::Running(Process::capture(identity)),
            State::Terminal(identity) => ResumeState::Terminal(Process::capture(identity)),
            State::Collected(result) => ResumeState::Collected(Process::capture(result.identity())),
            State::CancelledBeforeLaunch => ResumeState::Cancelled,
            State::StageUncertain(_) | State::Failed => ResumeState::StageUncertain,
        };
        SupervisedCheckpoint {
            binding: self.binding.clone(),
            stage_key: self.request.key().clone(),
            state,
        }
    }

    /// Persist this *before* advance. A crash across launch must query rather
    /// than replay; a crash across stage retains the protocol's operator gate.
    pub(crate) fn write_ahead_checkpoint(&mut self) -> SupervisedCheckpoint {
        self.observe_prelaunch_cancellation();
        let mut checkpoint = self.checkpoint();
        checkpoint.state = match checkpoint.state {
            ResumeState::Prepared => ResumeState::StageUncertain,
            ResumeState::Staged(session) => ResumeState::Submitted(session),
            state => state,
        };
        checkpoint
    }

    pub(crate) fn restore_checkpoint(
        &mut self,
        checkpoint: &SupervisedCheckpoint,
        collection: Option<&DurableCollection>,
    ) -> ExecutorResult<()> {
        if checkpoint.binding != self.binding || checkpoint.stage_key != *self.request.key() {
            return Err(invalid(
                "checkpoint differs from the exact attempt and staged request",
            ));
        }
        self.state = match &checkpoint.state {
            ResumeState::Prepared => State::Prepared,
            ResumeState::StageUncertain => {
                return Err(invalid(
                    "stage reply is uncertain; operator reconciliation required",
                ));
            }
            ResumeState::Staged(session) => State::Staged(session.staged(&self.request)?),
            ResumeState::Submitted(session) => State::Submitted(
                SubmittedLaunchIdentity::for_launch(&session.staged(&self.request)?),
            ),
            ResumeState::Running(process) => State::Running(process.restore(&self.request)?),
            ResumeState::Terminal(process) => State::Terminal(process.restore(&self.request)?),
            ResumeState::Collected(process) => {
                let identity = process.restore(&self.request)?;
                let collection =
                    collection.ok_or_else(|| invalid("collected bytes are missing"))?;
                State::Collected(collection.restore(&identity)?)
            }
            ResumeState::Cancelled => State::CancelledBeforeLaunch,
        };
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableCollection {
    patch: Vec<u8>,
    changed_paths: Vec<String>,
    outputs: Vec<Output>,
    manifest_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    path: String,
    media_type: String,
    bytes: Vec<u8>,
}

impl DurableCollection {
    pub(crate) fn capture(result: &CollectedResult) -> Self {
        Self {
            patch: result.patch().to_vec(),
            changed_paths: result
                .changed_paths()
                .iter()
                .map(ToString::to_string)
                .collect(),
            outputs: result
                .outputs()
                .iter()
                .map(|output| Output {
                    path: output.path().to_string(),
                    media_type: output.media_type().into(),
                    bytes: output.bytes().to_vec(),
                })
                .collect(),
            manifest_digest: result.binding().manifest_digest().clone(),
        }
    }

    fn restore(&self, identity: &ExecutionIdentity) -> ExecutorResult<CollectedResult> {
        let authority = identity.collection_authority();
        let limits = TransportReadLimits::for_policy(authority.policy())?;
        let patch = CollectedBlob::checksummed(self.patch.clone(), limits.patch_max_bytes())?;
        let outputs = self
            .outputs
            .iter()
            .map(|output| {
                CollectedOutputEnvelope::from_wire(
                    output.path.clone(),
                    output.media_type.clone(),
                    CollectedBlob::checksummed(
                        output.bytes.clone(),
                        limits.output_file_max_bytes(),
                    )?,
                )
            })
            .collect::<ExecutorResult<Vec<_>>>()?;
        let receipt = CollectionReceipt::from_wire_bounded(
            EXECUTOR_PROTOCOL_VERSION,
            authority.collection_key().clone(),
            identity.clone(),
            authority.policy_digest().clone(),
            patch,
            self.changed_paths.clone(),
            outputs,
            self.manifest_digest.clone(),
            &limits,
        )?;
        super::ssh::restore_collection_receipt(identity, receipt)
    }
}

fn invalid(reason: &str) -> ExecutorError {
    ExecutorError::InvalidField {
        field: "supervised SSH checkpoint",
        reason: reason.into(),
    }
}
