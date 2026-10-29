//! Explicitly configured SSH dispatch with authenticated write-ahead recovery.
//!
//! This is an embedding API, not a trust-config loader or an SSH wire client.
//! Plan data cannot install a transport or grant local capture authority.
use super::*;
use crate::{
    artifacts::{repository_auth_writer, state_auth::AuthenticationDomain},
    external_agent::executor::{
        AssignmentId, BoundedMillis, CollectedResult, DurableCollection, Effect, InputManifest,
        LaunchSpec, Nonce, OutputPolicy, SshTransport, SupervisedAttemptId, SupervisedCheckpoint,
        SupervisedEvent, SupervisedSshExecutor, TerminationPolicy,
    },
    state_journal::{AuthenticatedStateJournal, JournalSpec},
};
use std::{num::NonZeroU32, time::Instant};

/// Stable coordinator identity. Reentry with this tuple resumes the same attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshDispatchIdentity {
    pub run_id: String,
    pub assignment_id: String,
    pub worker_id: Option<String>,
    pub attempt: NonZeroU32,
}

/// Bounded inputs from the coordinator's secure readers, using `workspace/` for
/// source paths. The same frozen inputs must remain available during recovery.
pub struct SupervisedSshInputs {
    pub manifest: InputManifest,
    pub launch: LaunchSpec,
    pub outputs: OutputPolicy,
}

/// Trusted coordinator integration, installed by code rather than deserialized.
/// Import must be idempotent for the collection key, including a crash after its
/// effect. Recapture must inspect the imported candidate and held local runtime
/// evidence; it must not deserialize remote bytes into an `ExternalAgentRun`.
/// Returning a run does not bypass the supervisor's normal accounting, native
/// evidence, containment, claim, validation, or acceptance checks.
pub trait SupervisedSshCoordinator: Send + Sync {
    fn prepare(&self, command: &ExternalAgentCommand) -> Result<SupervisedSshInputs>;
    fn import_candidate(
        &self,
        command: &ExternalAgentCommand,
        result: &CollectedResult,
    ) -> Result<()>;
    fn recapture(
        &self,
        command: &ExternalAgentCommand,
        result: &CollectedResult,
    ) -> Result<ExternalAgentRun>;
}

trait HostDispatch: Send + Sync {
    fn validate_trust(&self) -> Result<()>;
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &self,
        repo: &Path,
        identity: SshDispatchIdentity,
        scopes: &[PathBuf],
        command: &ExternalAgentCommand,
        cancellation: &ProcessCancellation,
        custody: &std::cell::Cell<bool>,
    ) -> Result<ExternalAgentRun>;
}

#[derive(Clone)]
pub struct SupervisedSshHost {
    selection: ExecutorSelection,
    dispatch: Arc<dyn HostDispatch>,
}

impl fmt::Debug for SupervisedSshHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisedSshHost")
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SupervisedSshHost {
    fn eq(&self, other: &Self) -> bool {
        self.selection == other.selection && Arc::ptr_eq(&self.dispatch, &other.dispatch)
    }
}
impl Eq for SupervisedSshHost {}

impl SupervisedSshHost {
    pub fn configure<T: SshTransport + 'static>(
        selection: ExecutorSelection,
        trust: Option<crate::executor::SshConfig>,
        factory: impl FnOnce(
            &crate::executor::SshConfig,
        ) -> crate::external_agent::executor::ExecutorResult<T>,
        coordinator: Arc<dyn SupervisedSshCoordinator>,
    ) -> Result<Self> {
        let executor = SupervisedSshExecutor::configure(&selection, trust, factory)?;
        Ok(Self {
            selection: selection.clone(),
            dispatch: Arc::new(ConfiguredHost {
                selection,
                executor,
                coordinator,
            }),
        })
    }

    pub fn selection(&self) -> &ExecutorSelection {
        &self.selection
    }

    pub fn validate_trust(&self) -> Result<()> {
        self.dispatch.validate_trust()
    }

    /// May also be called to reconcile the identical interrupted assignment.
    /// It holds the authenticated attempt lock through capture and cleanup.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        repo: &Path,
        identity: SshDispatchIdentity,
        scopes: &[PathBuf],
        command: &ExternalAgentCommand,
        cancellation: &ProcessCancellation,
    ) -> Result<ExternalAgentRun> {
        let custody = std::cell::Cell::new(false);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.dispatch
                .dispatch(repo, identity, scopes, command, cancellation, &custody)
        }))
        .unwrap_or_else(|_| Err(anyhow!("SSH coordinator panicked")));
        result.map_err(|error| {
            if custody.get() {
                error.context(LaunchedSshCustody)
            } else {
                error
            }
        })
    }
}

#[derive(Debug)]
struct LaunchedSshCustody;

impl fmt::Display for LaunchedSshCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SSH launch may have started; checkpoint reconciliation required")
    }
}

impl std::error::Error for LaunchedSshCustody {}

pub(super) fn launch_may_have_started(error: &anyhow::Error) -> bool {
    error.is::<LaunchedSshCustody>()
}

thread_local! {
    static HOSTS: RefCell<Vec<SupervisedSshHost>> = const { RefCell::new(Vec::new()) };
}

/// Scoped embedding configuration; plans capture it before scheduler dispatch.
pub struct SupervisedSshBindGuard {
    previous: Vec<SupervisedSshHost>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for SupervisedSshBindGuard {
    fn drop(&mut self) {
        HOSTS.with(|hosts| *hosts.borrow_mut() = std::mem::take(&mut self.previous));
    }
}

pub fn bind_supervised_ssh_hosts(hosts: Vec<SupervisedSshHost>) -> Result<SupervisedSshBindGuard> {
    let mut seen = BTreeSet::new();
    for host in &hosts {
        host.validate_trust()?;
        let target = host
            .selection
            .ssh_target()
            .context("SSH host needs an SSH selection")?;
        if !seen.insert(target.host_id.clone()) {
            bail!("duplicate trusted SSH host ID");
        }
    }
    Ok(SupervisedSshBindGuard {
        previous: HOSTS.with(|slot| slot.replace(hosts)),
        _thread: std::marker::PhantomData,
    })
}

pub(super) fn current_hosts() -> Vec<SupervisedSshHost> {
    HOSTS.with(|hosts| hosts.borrow().clone())
}

struct ConfiguredHost<T> {
    selection: ExecutorSelection,
    executor: SupervisedSshExecutor<T>,
    coordinator: Arc<dyn SupervisedSshCoordinator>,
}

enum RemoteJournalSpec {}
impl JournalSpec for RemoteJournalSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "supervised_ssh";
    const ROOT_NAME: &'static str = "supervised-ssh-v1";
    const ROOT_LOCK_NAME: &'static str = ".supervised-ssh.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".resume.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0supervised-ssh-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0supervised-ssh-head\0v1\0");
    const MAX_RECORDS: usize = 4096;
    const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 64;
    const MAX_SUBJECT_BYTES: usize = 256;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}
type RemoteJournal = AuthenticatedStateJournal<RemoteJournalSpec>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    identity: SshDispatchIdentity,
    selection: ExecutorSelection,
    command_digest: String,
    scopes: Vec<PathBuf>,
    checkpoint: SupervisedCheckpoint,
    termination: DurableTermination,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableTermination {
    term_grace_ms: u64,
    kill_wait_ms: u64,
}

impl DurableTermination {
    fn policy(&self) -> Result<TerminationPolicy> {
        Ok(TerminationPolicy::new(
            BoundedMillis::new(self.term_grace_ms)?,
            BoundedMillis::new(self.kill_wait_ms)?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    checkpoint: SupervisedCheckpoint,
    receipt: String,
    cancelled: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectionCommit {
    digest: String,
    chunks: usize,
    checkpoint: SupervisedCheckpoint,
}

impl<T: SshTransport> HostDispatch for ConfiguredHost<T> {
    fn validate_trust(&self) -> Result<()> {
        Ok(self.executor.validate_trust()?)
    }

    fn dispatch(
        &self,
        repo: &Path,
        identity: SshDispatchIdentity,
        scopes: &[PathBuf],
        command: &ExternalAgentCommand,
        cancellation: &ProcessCancellation,
        custody: &std::cell::Cell<bool>,
    ) -> Result<ExternalAgentRun> {
        self.validate_trust()?;
        let journal_id = crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&identity)?);
        let authenticator = repository_auth_writer(repo)?.into_authenticator()?;
        let mut journal = RemoteJournal::open_or_initialize(authenticator, &journal_id)?;
        // Reentry can already own a submitted launch even if this invocation
        // refuses before another transport operation. Decode only authenticated records.
        for record in journal.records().iter().skip(1) {
            let checkpoint = match record.phase.as_str() {
                "before_effect" | "receipt" => {
                    Some(serde_json::from_value::<Progress>(record.payload.clone())?.checkpoint)
                }
                "collection_committed" => Some(
                    serde_json::from_value::<CollectionCommit>(record.payload.clone())?.checkpoint,
                ),
                _ => None,
            };
            if let Some(checkpoint) = checkpoint {
                custody.set(checkpoint.may_have_launched());
            }
        }
        let inputs = self.coordinator.prepare(command)?;
        let expected_scopes = normalize_paths(scopes.to_vec())?
            .into_iter()
            .map(|path| {
                crate::external_agent::executor::LogicalPath::new(format!(
                    "workspace/{}",
                    path.to_string_lossy().replace('\\', "/")
                ))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if inputs.outputs.assignment_scopes() != expected_scopes {
            bail!("SSH output policy differs from the coordinator's assignment scopes");
        }
        let command_digest =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&json!({
                "program": command.program, "cwd": command.cwd, "prompt": command.prompt,
                "output": command.output_last_message, "log": command.json_log,
                "schema": command.output_schema, "model": command.model,
                "provider": command.model_provider, "effort": command.reasoning_effort,
                "invocation": format!("{:?}", command.invocation),
                "access": format!("{:?}", command.workspace_access),
                "timeout_ms": command.timeout.as_millis(),
            }))?);
        let existing = journal
            .records()
            .first()
            .map(|record| {
                if record.phase != "intent" {
                    bail!("SSH checkpoint has no initial intent");
                }
                serde_json::from_value::<Intent>(record.payload.clone())
                    .context("invalid SSH intent")
            })
            .transpose()?;
        let binding = if let Some(intent) = &existing {
            if intent.identity != identity
                || intent.selection != self.selection
                || intent.command_digest != command_digest
                || intent.scopes != scopes
            {
                bail!("SSH resume identity, command, trust selection, or scopes changed");
            }
            intent.checkpoint.binding.clone()
        } else {
            SupervisedAttemptId {
                run_id: crate::external_agent::executor::RunId::new(identity.run_id.clone())?,
                assignment_id: AssignmentId::new(
                    identity
                        .worker_id
                        .as_ref()
                        .unwrap_or(&identity.assignment_id)
                        .clone(),
                )?,
                attempt: identity.attempt,
                nonce: Nonce::new(random_identifier()?)?,
            }
        };
        let termination = existing
            .as_ref()
            .map(|intent| intent.termination.clone())
            .unwrap_or_else(|| {
                let grace = self.executor.cancellation_grace_millis();
                DurableTermination {
                    term_grace_ms: grace,
                    kill_wait_ms: grace,
                }
            });
        let mut attempt = self.executor.prepare(
            binding,
            inputs.manifest,
            inputs.launch,
            inputs.outputs,
            cancellation.clone(),
            termination.policy()?,
        )?;
        if let Some(intent) = &existing {
            // Validate the prepared request even when the last checkpoint is later.
            attempt.restore_checkpoint(&intent.checkpoint, None)?;
        } else {
            attempt.observe_prelaunch_cancellation();
            append_remote(
                &mut journal,
                "intent",
                None,
                &Intent {
                    identity,
                    selection: self.selection.clone(),
                    command_digest,
                    scopes: scopes.to_vec(),
                    checkpoint: attempt.checkpoint(),
                    termination,
                },
            )?;
        }
        let mut checkpoint = attempt.checkpoint();
        let mut chunks = Vec::new();
        let mut chunk_count = 0;
        let mut collection = None;
        let mut collection_digest = None;
        let mut imported = false;
        let mut recaptured = false;
        let mut cleaned = false;
        let mut last_receipt = String::new();
        for record in journal.records().iter().skip(1) {
            match record.phase.as_str() {
                "before_effect" | "receipt" => {
                    let progress: Progress = serde_json::from_value(record.payload.clone())?;
                    checkpoint = progress.checkpoint;
                    if progress.cancelled {
                        cancellation.cancel();
                    }
                    last_receipt = progress.receipt;
                }
                "collection_started" => {
                    chunks.clear();
                    chunk_count = 0;
                }
                "collection_chunk" => {
                    let chunk: Vec<u8> = serde_json::from_value(record.payload.clone())?;
                    chunks.extend_from_slice(&chunk);
                    chunk_count += 1;
                }
                "collection_committed" => {
                    let commit: CollectionCommit = serde_json::from_value(record.payload.clone())?;
                    if commit.chunks != chunk_count
                        || commit.digest != crate::artifacts::state_auth::sha256_hex(&chunks)
                    {
                        bail!("SSH collection checkpoint bytes differ from their receipt");
                    }
                    collection = Some(serde_json::from_slice::<DurableCollection>(&chunks)?);
                    collection_digest = Some(commit.digest);
                    checkpoint = commit.checkpoint;
                }
                "before_import"
                | "candidate_imported"
                | "candidate_recaptured"
                | "before_cleanup"
                | "cleanup_uncertain"
                | "cleanup_receipt" => {
                    let digest: String =
                        serde_json::from_value(record.payload["collection_digest"].clone())?;
                    if Some(digest) != collection_digest {
                        bail!("SSH import/cleanup has no matching persisted collection");
                    }
                    if record.phase == "candidate_imported" {
                        imported = true;
                    }
                    if !matches!(
                        record.phase.as_str(),
                        "before_import" | "candidate_imported"
                    ) && !imported
                    {
                        bail!("SSH cleanup/recapture precedes import");
                    }
                    if record.phase == "candidate_recaptured" {
                        recaptured = true;
                    }
                    if matches!(
                        record.phase.as_str(),
                        "before_cleanup" | "cleanup_uncertain" | "cleanup_receipt"
                    ) && !recaptured
                    {
                        bail!("SSH cleanup precedes local recapture");
                    }
                    if record.phase == "cleanup_receipt" {
                        cleaned = true;
                    }
                }
                phase => bail!("unknown SSH checkpoint phase '{phase}'"),
            }
        }
        attempt.restore_checkpoint(&checkpoint, collection.as_ref())?;
        let started = Instant::now();
        let mut last_cancelled = cancellation.is_cancelled();
        let result = loop {
            if started.elapsed() >= command.timeout {
                cancellation.cancel();
            }
            let before = attempt.write_ahead_checkpoint();
            if before != checkpoint || cancellation.is_cancelled() != last_cancelled {
                append_remote(
                    &mut journal,
                    "before_effect",
                    None,
                    &Progress {
                        checkpoint: before.clone(),
                        receipt: "intent".into(),
                        cancelled: cancellation.is_cancelled(),
                    },
                )?;
                checkpoint = before;
                last_cancelled = cancellation.is_cancelled();
            }
            custody.set(checkpoint.may_have_launched());
            let event = attempt.advance()?;
            if matches!(event, SupervisedEvent::CancelledBeforeLaunch) {
                custody.set(false);
            }
            if let SupervisedEvent::Collected(Effect::Confirmed(result)) = event {
                if collection.is_none() {
                    // Large bundles use bounded journal records; only the final
                    // authenticated commit makes any of these bytes importable.
                    let bytes = serde_json::to_vec(&DurableCollection::capture(&result))?;
                    append_remote(&mut journal, "collection_started", None, &json!({}))?;
                    for chunk in bytes.chunks(64 * 1024) {
                        append_remote(&mut journal, "collection_chunk", None, &chunk)?;
                    }
                    let digest = crate::artifacts::state_auth::sha256_hex(&bytes);
                    append_remote(
                        &mut journal,
                        "collection_committed",
                        None,
                        &CollectionCommit {
                            digest: digest.clone(),
                            chunks: bytes.chunks(64 * 1024).len(),
                            checkpoint: attempt.checkpoint(),
                        },
                    )?;
                    collection_digest = Some(digest);
                }
                break result;
            }
            let after = attempt.checkpoint();
            let receipt = format!("{event:?}");
            if after != checkpoint || receipt != last_receipt {
                append_remote(
                    &mut journal,
                    "receipt",
                    None,
                    &Progress {
                        checkpoint: after.clone(),
                        receipt: receipt.clone(),
                        cancelled: cancellation.is_cancelled(),
                    },
                )?;
                checkpoint = after;
                last_receipt = receipt;
            }
            match event {
                SupervisedEvent::CancelledBeforeLaunch => {
                    bail!("SSH assignment cancelled before launch")
                }
                SupervisedEvent::Staged(Effect::Uncertain(_))
                | SupervisedEvent::Launched(Effect::Uncertain(_))
                | SupervisedEvent::Collected(Effect::Uncertain(_))
                | SupervisedEvent::Terminated(Effect::Uncertain(_))
                | SupervisedEvent::Reconciled(
                    crate::external_agent::executor::ExecutionStatus::NotFound,
                ) => {
                    bail!(
                        "SSH effect is uncertain; resume the identical checkpoint without relaunch"
                    );
                }
                _ => {}
            }
        };
        let barrier = json!({"collection_digest": collection_digest.context("SSH collection has no persistence receipt")?});
        if !imported {
            append_remote(&mut journal, "before_import", None, &barrier)?;
            self.coordinator.import_candidate(command, &result)?;
            append_remote(&mut journal, "candidate_imported", None, &barrier)?;
        }
        // Always recapture after restart; serialized run flags are not authority.
        let mut run = self.coordinator.recapture(command, &result)?;
        let completion = (|| -> Result<()> {
            if run.cwd != command.cwd {
                bail!("SSH local recapture returned a different worktree");
            }
            if !recaptured {
                append_remote(&mut journal, "candidate_recaptured", None, &barrier)?;
            }
            if !cleaned {
                append_remote(&mut journal, "before_cleanup", None, &barrier)?;
                match attempt.cleanup_collected()? {
                    Effect::Confirmed(receipt) if receipt.workspace_removed() => {
                        append_remote(
                            &mut journal,
                            "cleanup_receipt",
                            None,
                            &json!({
                                "collection_digest": barrier["collection_digest"],
                                "key": receipt.key(), "workspace": receipt.workspace_id(),
                                "receipt": format!("{receipt:?}"),
                            }),
                        )?;
                    }
                    effect => {
                        append_remote(
                            &mut journal,
                            "cleanup_uncertain",
                            None,
                            &json!({
                                "collection_digest": barrier["collection_digest"],
                                "receipt": format!("{effect:?}"),
                            }),
                        )?;
                        bail!("SSH cleanup is uncertain; preserve the imported collection and reconcile its exact key");
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = completion {
            // Return held observations for the supervisor's exactly-once usage
            // settlement even when a later receipt or cleanup effect fails.
            run.publishable = false;
            run.error = Some(format!(
                "{}SSH completion requires reconciliation: {error:#}",
                run.error
                    .as_ref()
                    .map(|error| format!("{error}; "))
                    .unwrap_or_default(),
            ));
        }
        Ok(run)
    }
}

#[cfg(test)]
#[path = "remote_execution_tests.rs"]
mod tests;

#[cfg(test)]
thread_local! {
    static FAIL_PHASE: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn append_remote<T: Serialize>(
    journal: &mut RemoteJournal,
    phase: &str,
    subject: Option<&str>,
    payload: &T,
) -> Result<()> {
    #[cfg(test)]
    FAIL_PHASE.with(|slot| -> Result<()> {
        let cancelled_receipt = phase == "receipt"
            && serde_json::to_value(payload)?["receipt"] == "CancelledBeforeLaunch";
        if slot.borrow().as_deref() == Some(phase)
            || (cancelled_receipt && slot.borrow().as_deref() == Some("cancelled_receipt"))
        {
            slot.replace(None);
            bail!("injected SSH checkpoint publication failure: {phase}");
        }
        Ok(())
    })?;
    journal.append(phase, subject, payload)?;
    Ok(())
}
