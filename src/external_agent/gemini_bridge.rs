//! Parent-held Gemini bootstrap observations. No wire-restorable authority,
//! observed provider identity, complete invocation usage, or priced cost.
use super::*;
use crate::runtime_adapter::GeminiBootstrapDescriptor as Descriptor;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HeldEvidence {
    pub(crate) tokens: Option<usize>,
    pub(crate) provider_released: bool,
    pub(crate) no_release_quiescent: bool,
    pub(crate) managed_worker_completed: bool,
    pub(crate) managed_read_only_completed: bool,
    pub(crate) tool_mutation_observed: bool,
    pub(crate) read_only_journal: Option<Vec<u8>>,
    read_only_launch: Option<ReadOnlyLaunchBinding>,
    read_only_result_sha256: Option<String>,
    native_tool_records: Vec<NativeToolRecord>,
    ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadOnlyLaunchBinding {
    cwd: PathBuf,
    prompt: PathBuf,
    output: PathBuf,
    model: String,
    role: String,
    run_id: String,
    subject: String,
    kind: AssignmentProcessLaunchKind,
    attempt: usize,
    process_grant: AssignmentProcessLaunchGrant,
    selected: FrozenGeminiSelectedBinding,
    grant: crate::supervise_budget::LiveTokenGrant,
}

impl ReadOnlyLaunchBinding {
    fn bind(command: &ExternalAgentCommand) -> Result<Self> {
        command
            .verified_live_token_grant()
            .map_err(anyhow::Error::msg)?
            .context("missing finite Gemini read-only live token grant")?;
        Self::snapshot(command)
    }

    fn snapshot(command: &ExternalAgentCommand) -> Result<Self> {
        let identity = command
            .agent_lifecycle
            .as_ref()
            .context("missing Gemini read-only role identity")?;
        let kind = command
            .assignment_process_launch_kind
            .context("missing Gemini read-only process intent")?;
        if !command.uses_gemini_bridge()
            || command.workspace_access != WorkspaceAccess::ReadOnly
            || !command.worktree_control_exceptions.is_empty()
            || !matches!(
                (kind, identity.role.as_str()),
                (AssignmentProcessLaunchKind::ConsultGemini, "researcher")
                    | (AssignmentProcessLaunchKind::ParentAuditor, "auditor")
                    | (
                        AssignmentProcessLaunchKind::AssignmentChild,
                        "researcher" | "auditor" | "gate_classifier"
                    )
            )
        {
            bail!("Gemini read-only role/intent/profile mismatch");
        }
        Ok(Self {
            cwd: command.cwd.clone(),
            prompt: command.prompt.clone(),
            output: command.output_last_message.clone(),
            model: command
                .model
                .clone()
                .context("missing Gemini read-only model input")?,
            role: identity.role.clone(),
            run_id: identity.run_id.clone(),
            subject: identity.task_id.clone(),
            kind,
            attempt: command
                .assignment_process_launch_attempt
                .context("missing Gemini read-only attempt")?,
            process_grant: command
                .assignment_process_launch_grant
                .clone()
                .context("missing Gemini read-only process grant")?,
            selected: command
                .gemini_run_account_binding
                .clone()
                .context("missing frozen Gemini selected account")?,
            grant: command
                .bound_live_token_grant()
                .map_err(anyhow::Error::msg)?
                .cloned()
                .context("missing finite Gemini read-only live token grant")?,
        })
    }
}

impl HeldEvidence {
    pub(crate) fn read_only_completion_valid(&self, run: &ExternalAgentRun) -> bool {
        let Some(binding) = &self.read_only_launch else {
            return false;
        };
        run.exit_code == Some(0)
            && !run.timed_out
            && run.error.is_none()
            && run.publishable
            && run.cwd == binding.cwd
            && run
                .process_tree
                .is_some_and(ProcessTreeEvidence::is_verified_empty)
            && run.scratch_quiescence_verified()
            && run.side_effects
                == Some(SideEffectConfinementEvidence::Verified(
                    SideEffectConfinementProfileKind::GeminiOnlineBridge,
                ))
            && run
                .managed_gemini_selection_evidence()
                .is_some_and(|s| binding.selected.matches_selection_evidence(s))
            && run.output_last_message().is_some_and(|result| {
                !result.is_empty()
                    && self.read_only_result_sha256.as_deref() == Some(sha256_hex(result).as_str())
            })
            && read_only_native_paths(self, &binding.cwd).is_ok()
    }
}

// Live custody only. Serialized model reports cannot restore these correlations.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeToolRecord {
    action_id: u64,
    sequence: u64,
    kind: String,
    begin_offset: usize,
    record_offset: usize,
}

/// Only live parent custody can supply this evidence; restored report JSON cannot.
pub(crate) fn verify_read_only_evidence(
    run: &ExternalAgentRun,
    command: &ExternalAgentCommand,
    require_read: bool,
) -> Result<Vec<PathBuf>> {
    let evidence = run
        .gemini_bridge_evidence()
        .context("missing held Gemini read-only evidence")?;
    if !evidence.read_only_completion_valid(run)
        || evidence.read_only_launch.as_ref() != Some(&ReadOnlyLaunchBinding::snapshot(command)?)
    {
        bail!("Gemini read-only result lacks successful confined native custody");
    }
    let paths = read_only_native_paths(evidence, &command.cwd)?;
    if require_read && paths.is_empty() {
        bail!("Gemini read-only result omitted required native inspection")
    }
    Ok(paths)
}

fn read_only_native_paths(evidence: &HeldEvidence, cwd: &Path) -> Result<Vec<PathBuf>> {
    if !evidence.provider_released
        || !evidence.managed_read_only_completed
        || evidence.managed_worker_completed
        || evidence.tool_mutation_observed
    {
        bail!("Gemini read-only completion mode changed");
    }
    let bytes = evidence
        .read_only_journal
        .as_deref()
        .context("missing held Gemini read-only journal")?;
    let entries = crate::supervise::parse_worker_execution_journal(bytes, cwd)?;
    if entries.len() != evidence.native_tool_records.len() || entries.len() % 2 != 0 {
        bail!("Gemini read-only journal lacks correlated native reads");
    }
    let mut paths = BTreeSet::new();
    for (entries, records) in entries
        .chunks_exact(2)
        .zip(evidence.native_tool_records.chunks_exact(2))
    {
        if records[0].kind != "begin"
            || records[1].kind != "completed"
            || records[0].action_id != records[1].action_id
            || records[0].sequence >= records[1].sequence
            || records[0].begin_offset != records[1].begin_offset
            || records[0].record_offset >= records[1].record_offset
            || entries[0].command != entries[1].command
            || entries[0].cwd != entries[1].cwd
            || entries[0].cwd != cwd
            || entries[0].start_timestamp != entries[1].start_timestamp
            || entries[0].command.len() != 2
            || entries[0].command[0] != "read_file"
            || !entries[0].changed_paths.is_empty()
            || !entries[1].changed_paths.is_empty()
        {
            bail!("Gemini read-only native correlation changed");
        }
        let params: serde_json::Value = serde_json::from_str(&entries[0].command[1])?;
        let relative = params
            .get("file_path")
            .and_then(serde_json::Value::as_str)
            .context("Gemini native read omitted its path")?;
        let relative = Path::new(relative);
        if relative.is_absolute()
            || relative.components().any(|c| match c {
                std::path::Component::Normal(v) => v.to_string_lossy().starts_with('.'),
                _ => true,
            })
        {
            bail!("Gemini native read path is outside its candidate");
        }
        paths.insert(relative.to_path_buf());
    }
    Ok(paths.into_iter().collect())
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeToolEvent {
    action_id: u64,
    kind: String,
    tool: String,
    cwd: PathBuf,
    arguments_json: String,
    before_sha256: Option<String>,
    after_sha256: Option<String>,
}

#[cfg(target_os = "linux")]
enum NativeJournalArtifact {
    Worker(ExactWritableArtifactFile),
    ReadOnly(ReservedOutputFile),
}

#[cfg(target_os = "linux")]
struct NativeToolJournal {
    artifact: NativeJournalArtifact,
    candidate: PathBuf,
    bytes: Vec<u8>,
    last_action: u64,
    pending: Option<(NativeToolEvent, String, usize)>,
    failure: Option<String>,
    mutation_observed: bool,
    records: Vec<NativeToolRecord>,
}

#[cfg(target_os = "linux")]
impl NativeToolJournal {
    fn bind(controls: &ProtectedWorktreeControls, candidate: &Path) -> Result<Option<Self>> {
        let [artifact] = controls.exact_writable_artifact_files.as_slice() else {
            if controls.exact_writable_artifact_files.is_empty() {
                return Ok(None);
            }
            bail!("Gemini requires one exact Worker journal subject");
        };
        if !capture_worker_journal_artifact(artifact)?.is_empty() {
            bail!("Gemini native journal was not empty at parent binding");
        }
        Ok(Some(Self {
            artifact: NativeJournalArtifact::Worker(artifact.clone()),
            candidate: fs::canonicalize(candidate)?,
            bytes: Vec::new(),
            last_action: 0,
            pending: None,
            failure: None,
            mutation_observed: false,
            records: Vec::new(),
        }))
    }

    fn bind_read_only(file: ReservedOutputFile, candidate: &Path) -> Result<Self> {
        if !file
            .read_bounded(MAX_WORKER_JOURNAL_ARTIFACT_BYTES)?
            .is_empty()
        {
            bail!("Gemini read-only journal was not empty at parent binding");
        }
        Ok(Self {
            artifact: NativeJournalArtifact::ReadOnly(file),
            candidate: fs::canonicalize(candidate)?,
            bytes: Vec::new(),
            last_action: 0,
            pending: None,
            failure: None,
            mutation_observed: false,
            records: Vec::new(),
        })
    }

    fn is_read_only(&self) -> bool {
        matches!(&self.artifact, NativeJournalArtifact::ReadOnly(_))
    }

    fn held_bytes(&self) -> Result<Vec<u8>> {
        match &self.artifact {
            NativeJournalArtifact::Worker(file) => capture_worker_journal_artifact(file),
            NativeJournalArtifact::ReadOnly(file) => {
                file.read_bounded(MAX_WORKER_JOURNAL_ARTIFACT_BYTES)
            }
        }
    }

    fn capture_read_only(&self, quiescent: bool) -> Result<Vec<u8>> {
        if !self.is_read_only() || !quiescent || self.pending.is_some() || self.failure.is_some() {
            bail!("Gemini read-only journal lacks successful quiescent custody");
        }
        let bytes = self.held_bytes()?;
        if bytes != self.bytes {
            bail!("Gemini read-only journal changed outside its parent producer");
        }
        Ok(bytes)
    }

    fn observe(&mut self, event: NativeToolEvent, sequence: u64) -> Result<()> {
        let result = self.observe_inner(event, sequence);
        if let Err(error) = &result {
            self.failure.get_or_insert_with(|| error.to_string());
        }
        result
    }

    fn observe_inner(&mut self, event: NativeToolEvent, sequence: u64) -> Result<()> {
        if self.failure.is_some()
            || event.action_id == 0
            || event.action_id > 1024
            || event.cwd != self.candidate
            || event.arguments_json.len() > 8192
            || !matches!(event.tool.as_str(), "read_file" | "write_file" | "replace")
            || (self.is_read_only()
                && (event.tool != "read_file" || event.before_sha256 != event.after_sha256))
            || !matches!(
                event.kind.as_str(),
                "begin" | "completed" | "failed" | "cancelled"
            )
            || [&event.before_sha256, &event.after_sha256]
                .into_iter()
                .flatten()
                .any(|v| !is_digest(v))
        {
            bail!("Gemini native tool observation binding mismatch");
        }
        let parameters: serde_json::Value = serde_json::from_str(&event.arguments_json)?;
        let relative = parameters
            .as_object()
            .and_then(|p| p.get("file_path"))
            .and_then(serde_json::Value::as_str)
            .context("Gemini native tool omitted its file argument")?;
        let relative = Path::new(relative);
        if relative.is_absolute()
            || relative.components().any(|c| match c {
                std::path::Component::Normal(v) => v.to_string_lossy().starts_with('.'),
                _ => true,
            })
        {
            bail!("Gemini native tool path is outside the admitted candidate");
        }
        let absolute = self.candidate.join(relative);
        let digest = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!("Gemini native tool path is not a regular non-symlink file");
                }
                if fs::canonicalize(&absolute)? != absolute {
                    bail!("Gemini native tool path is aliased");
                }
                Some(sha256_hex(&read_bounded_regular_file_nofollow(
                    &absolute,
                    4 * 1024 * 1024,
                )?))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let parent = absolute
                    .parent()
                    .context("Gemini native tool path has no parent")?;
                if fs::canonicalize(parent)? != parent || event.tool != "write_file" {
                    bail!("Gemini native tool path is unavailable");
                }
                None
            }
            Err(error) => return Err(error.into()),
        };
        let timestamp = native_observation_timestamp()?;
        let (start, begin_offset) = if event.kind == "begin" {
            if self.pending.is_some()
                || event.action_id != self.last_action + 1
                || event.before_sha256 != digest
                || event.after_sha256 != digest
            {
                bail!("Gemini native tool begin is replayed, overlapping or mismatched");
            }
            (timestamp.clone(), self.bytes.len())
        } else {
            let (begin, start, offset) = self
                .pending
                .as_ref()
                .context("Gemini native tool terminal has no begin")?;
            if event.action_id != begin.action_id
                || event.tool != begin.tool
                || event.arguments_json != begin.arguments_json
                || event.before_sha256 != begin.before_sha256
                || event.after_sha256 != digest
                || timestamp < *start
            {
                bail!("Gemini native tool terminal correlation or file observation changed");
            }
            (start.clone(), *offset)
        };
        let changed = event.kind != "begin"
            && event.tool != "read_file"
            && event.before_sha256 != event.after_sha256;
        let entry = crate::supervise::WorkerExecutionJournalEntry {
            // Actual native tool identity and original JSON argument, never a shell/check command.
            command: vec![event.tool.clone(), event.arguments_json.clone()],
            cwd: self.candidate.clone(),
            start_timestamp: start.clone(),
            end_timestamp: timestamp,
            changed_paths: if changed {
                vec![relative.to_path_buf()]
            } else {
                Vec::new()
            },
        };
        let offset = self.bytes.len();
        self.append(&entry)?;
        self.records.push(NativeToolRecord {
            action_id: event.action_id,
            sequence,
            kind: event.kind.clone(),
            begin_offset,
            record_offset: offset,
        });
        if event.kind == "begin" {
            self.last_action = event.action_id;
            self.pending = Some((event, start, offset));
        } else {
            self.pending = None;
            self.mutation_observed |= changed;
            if event.kind != "completed" {
                self.failure = Some(format!(
                    "Gemini native tool action {} ended {}",
                    event.action_id, event.kind
                ));
            }
        }
        Ok(())
    }

    fn append(&mut self, entry: &crate::supervise::WorkerExecutionJournalEntry) -> Result<()> {
        use std::os::unix::fs::FileExt;
        if self.held_bytes()? != self.bytes {
            bail!("Gemini native journal bytes changed outside its parent producer");
        }
        let mut record = Vec::new();
        crate::supervise::append_worker_execution_journal_record(&mut record, entry)?;
        if self
            .bytes
            .len()
            .checked_add(record.len())
            .is_none_or(|n| n > MAX_WORKER_JOURNAL_ARTIFACT_BYTES)
        {
            bail!("Gemini native journal exceeded its existing capture bound");
        }
        match &mut self.artifact {
            NativeJournalArtifact::Worker(file) => {
                file.held_file
                    .write_all_at(&record, self.bytes.len() as u64)?;
                file.held_file.sync_data()?;
            }
            NativeJournalArtifact::ReadOnly(file) => {
                let mut bytes = self.bytes.clone();
                bytes.extend_from_slice(&record);
                file.write_bytes_atomic(&bytes, MAX_WORKER_JOURNAL_ARTIFACT_BYTES)?;
            }
        }
        self.bytes.extend(record);
        if self.held_bytes()? != self.bytes {
            bail!("Gemini native journal changed during durable append");
        }
        Ok(())
    }

    fn capture(
        &self,
        controls: &ProtectedWorktreeControls,
        quiescent: bool,
    ) -> Vec<WorkerJournalArtifactCapture> {
        let mut captures = capture_worker_journal_artifacts(controls, quiescent);
        for capture in &mut captures {
            if let WorkerJournalArtifactCaptureStatus::Loaded(bytes) = &capture.status {
                let error = self.failure.clone().or_else(|| {
                    if bytes != &self.bytes {
                        Some(
                            "Gemini native journal changed after its last durable observation"
                                .into(),
                        )
                    } else if self.pending.is_some() {
                        Some("Gemini native tool has no observed terminal before quiescence".into())
                    } else {
                        None
                    }
                });
                if let Some(error) = error {
                    capture.status = WorkerJournalArtifactCaptureStatus::Invalid(error);
                }
            }
            // Existing capture Invalid causes (identity, permissions, quiescence) win unchanged.
        }
        captures
    }
}

#[cfg(target_os = "linux")]
fn native_observation_timestamp() -> Result<String> {
    let since_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let seconds = libc::time_t::try_from(since_epoch.as_secs())?;
    // SAFETY: both pointers reference valid initialized storage for the call.
    let mut utc: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&seconds, &mut utc) }.is_null() {
        bail!("Gemini parent observation clock is unavailable");
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        utc.tm_year + 1900,
        utc.tm_mon + 1,
        utc.tm_mday,
        utc.tm_hour,
        utc.tm_min,
        utc.tm_sec,
        since_epoch.subsec_nanos()
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    nonce: String,
    sequence: u64,
    message: Body,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Hello {
        #[serde(rename = "bootstrapSha256")]
        bootstrap_sha256: String,
        #[serde(rename = "wireSha256")]
        wire_sha256: String,
        #[serde(rename = "promptSha256")]
        prompt_sha256: String,
    },
    Ready {
        closure: Vec<ClosureEntry>,
    },
    Refused {
        reason: String,
    },
    Event {
        event: Box<WireEvent>,
    },
    NativeTool {
        event: NativeToolEvent,
    },
    Completed {
        #[serde(rename = "resultSha256")]
        result_sha256: String,
        #[serde(rename = "toolMutationObserved")]
        tool_mutation_observed: bool,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClosureEntry {
    path: String,
    original_sha256: String,
    instrumented_sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireEvent {
    kind: String,
    call_id: u64,
    attempt_id: u64,
    mode: String,
    request_class: String,
    released: bool,
    terminal: Option<String>,
    terminal_ack: Option<String>,
    frames: u64,
    wire_bytes: u64,
    usage: Option<WireUsage>,
    observed_model_version: Option<String>,
    usage_lower_bound: Option<u64>,
    usage_coverage: String,
    identity_authority: String,
    actual_effort: Option<String>,
    cost: Option<f64>,
    qualified: bool,
    quiescence: String,
    #[serde(default)]
    envelope_sha256: Option<String>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireUsage {
    prompt_token_count: Option<u64>,
    candidates_token_count: Option<u64>,
    total_token_count: Option<u64>,
    cached_content_token_count: Option<u64>,
    thoughts_token_count: Option<u64>,
    tool_use_prompt_token_count: Option<u64>,
}

impl WireUsage {
    fn counters(&self) -> [Option<u64>; 6] {
        [
            self.prompt_token_count,
            self.candidates_token_count,
            self.total_token_count,
            self.cached_content_token_count,
            self.thoughts_token_count,
            self.tool_use_prompt_token_count,
        ]
    }
    fn validate(&self, previous: Option<&Self>) -> Result<()> {
        if self
            .counters()
            .into_iter()
            .flatten()
            .any(|n| n > 9_007_199_254_740_991)
            || self
                .cached_content_token_count
                .is_some_and(|n| self.prompt_token_count.is_none_or(|input| n > input))
            || self
                .total_token_count
                .is_some_and(|total| self.counters().into_iter().flatten().any(|n| n > total))
            || previous.is_some_and(|old| {
                old.counters()
                    .into_iter()
                    .zip(self.counters())
                    .any(|(old, new)| old.is_some_and(|old| new.is_none_or(|new| new < old)))
            })
        {
            bail!("Gemini usage counters are malformed or regressed");
        }
        Ok(())
    }
}

struct Protocol {
    nonce: String,
    prompt_sha256: String,
    sequence: u64,
    hello: bool,
    stopped: bool,
    terminal: bool,
    attempts: BTreeMap<u64, WireEvent>,
    evidence: HeldEvidence,
    grant: Option<crate::supervise_budget::LiveTokenGrant>,
    release_authority: ReleaseAuthority,
    release_requires_revalidation: bool,
    read_only: bool,
    result_sha256: Option<String>,
    #[cfg(target_os = "linux")]
    native_journal: Option<NativeToolJournal>,
}

enum ReleaseAuthority {
    Unavailable,
    ManagedOAuth,
    // This seam drives deterministic state tests only. No launch manifest,
    // environment variable or deserializer can construct it.
    #[cfg(test)]
    DeterministicTransport,
}

impl Protocol {
    fn new(
        nonce: String,
        prompt_sha256: String,
        grant: Option<crate::supervise_budget::LiveTokenGrant>,
    ) -> Self {
        Self {
            nonce,
            prompt_sha256,
            sequence: 0,
            hello: false,
            stopped: false,
            terminal: false,
            attempts: BTreeMap::new(),
            evidence: HeldEvidence::default(),
            grant,
            release_authority: ReleaseAuthority::Unavailable,
            release_requires_revalidation: false,
            read_only: false,
            result_sha256: None,
            #[cfg(target_os = "linux")]
            native_journal: None,
        }
    }

    fn receive(&mut self, bytes: &[u8]) -> Result<()> {
        let result = self.receive_inner(bytes);
        if result.is_err() {
            self.stopped = true;
        }
        result
    }

    fn receive_inner(&mut self, bytes: &[u8]) -> Result<()> {
        if self.stopped
            || self.terminal
            || bytes.len() > 16384
            || self.sequence >= 16384
            || self.grant.as_ref().is_some_and(|grant| grant.stopped())
        {
            bail!("Gemini private bridge is stopped or exceeded its bound");
        }
        let message: Message = serde_json::from_slice(bytes)?;
        if message.nonce != self.nonce || message.sequence != self.sequence + 1 {
            bail!("Gemini private bridge nonce/sequence mismatch");
        }
        self.sequence = message.sequence;
        match message.message {
            Body::Hello {
                bootstrap_sha256,
                wire_sha256,
                prompt_sha256,
            } => {
                if self.hello
                    || self.sequence != 1
                    || bootstrap_sha256 != sha256_hex(Descriptor::BOOTSTRAP.as_bytes())
                    || wire_sha256 != sha256_hex(Descriptor::WIRE.as_bytes())
                    || prompt_sha256 != self.prompt_sha256
                {
                    bail!("Gemini bootstrap binding mismatch");
                }
                self.hello = true;
            }
            Body::Ready { closure } => {
                if !self.hello || self.evidence.ready {
                    bail!("Gemini duplicate or premature readiness");
                }
                verify_closure(&closure)?;
                self.evidence.ready = true;
            }
            Body::Refused { reason } => {
                if !self.evidence.ready
                    || reason != "auth_not_authorized"
                    || !self.attempts.is_empty()
                {
                    bail!("Gemini invalid bootstrap refusal");
                }
                self.terminal = true;
            }
            Body::Event { event } => self.event(*event)?,
            Body::NativeTool { event } => {
                if !self.evidence.ready || !self.evidence.provider_released {
                    bail!("Gemini native tool observation preceded provider release");
                }
                #[cfg(target_os = "linux")]
                {
                    let journal = self
                        .native_journal
                        .as_mut()
                        .context("Gemini native tool lacks a held Worker journal")?;
                    journal.observe(event, self.sequence)?;
                    self.evidence.native_tool_records = journal.records.clone();
                    // The terminal observation may be ACKed, but no subsequent
                    // native action or provider admission survives its failure.
                    self.stopped = journal.failure.is_some();
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = event;
                    bail!("Gemini native journal requires Linux parent custody");
                }
            }
            Body::Completed {
                result_sha256,
                tool_mutation_observed,
            } => {
                #[cfg(target_os = "linux")]
                if !self.native_journal.as_ref().is_some_and(|j| {
                    j.pending.is_none()
                        && j.failure.is_none()
                        && j.is_read_only() == self.read_only
                        && j.mutation_observed == tool_mutation_observed
                        && (self.read_only || j.mutation_observed)
                        && ((self.read_only
                            && self.evidence.provider_released
                            && j.last_action == 0
                            && j.records.is_empty()
                            && j.bytes.is_empty()
                            && j.held_bytes().is_ok_and(|bytes| bytes.is_empty()))
                            || j.records.last().is_some_and(|record| {
                                record.kind == "completed"
                                    && record.action_id == j.last_action
                                    && record.sequence < self.sequence
                                    && record.record_offset > record.begin_offset
                            }))
                }) {
                    bail!("Gemini managed completion lacks quiescent native tool observations");
                }
                if !self.evidence.ready
                    || self.terminal
                    || !is_digest(&result_sha256)
                    || self.attempts.is_empty()
                    || self
                        .attempts
                        .values()
                        .any(|attempt| attempt.terminal.is_none())
                    || !self
                        .attempts
                        .values()
                        .any(|attempt| attempt.request_class == "generation")
                {
                    bail!("Gemini invalid managed worker completion");
                }
                self.result_sha256 = Some(result_sha256);
                self.evidence.managed_worker_completed = !self.read_only;
                self.evidence.managed_read_only_completed = self.read_only;
                if self.read_only {
                    self.evidence.read_only_result_sha256 = self.result_sha256.clone();
                }
                self.evidence.tool_mutation_observed = tool_mutation_observed;
                self.terminal = true;
            }
        }
        Ok(())
    }

    fn event(&mut self, event: WireEvent) -> Result<()> {
        if !self.evidence.ready
            || event.call_id == 0
            || event.call_id > 64
            || event.attempt_id == 0
            || event.attempt_id > 128
            || !matches!(event.mode.as_str(), "unary" | "stream")
            || !matches!(
                event.request_class.as_str(),
                "generation"
                    | "oauth_refresh"
                    | "oauth_token_info"
                    | "oauth_userinfo"
                    | "setup_user"
                    | "experiments"
                    | "quota"
                    | "admin_control"
            )
            || event.usage_coverage != "observed_lower_bound_only"
            || event.identity_authority != "unverified_response_field"
            || event.actual_effort.is_some()
            || event.cost.is_some()
            || event.qualified
            || event.quiescence != "unproven"
            || event.frames > 4096
            || event.wire_bytes > 4 * 1024 * 1024
            || event.observed_model_version.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > 128
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
            })
        {
            bail!("Gemini invalid wire observation");
        }
        if event.kind == "admission" {
            if self.attempts.len() >= 128
                || event.attempt_id != self.attempts.len() as u64 + 1
                || event.released
                || event.terminal.is_some()
                || event.terminal_ack.is_some()
                || event.frames != 0
                || event.wire_bytes != 0
                || event.usage.is_some()
                || event.usage_lower_bound.is_some()
                || event.observed_model_version.is_some()
                || event.envelope_sha256.is_some()
                || self.attempts.values().any(|prior| {
                    prior.terminal.is_none()
                        || (prior.request_class == "generation"
                            && prior.usage_lower_bound.is_none())
                })
            {
                bail!("Gemini overlapping/replayed/unknown-usage admission");
            }
            // Admission is useful only while a retained launch authority can
            // still be revalidated before the separate release ACK.
            if matches!(self.release_authority, ReleaseAuthority::Unavailable) {
                bail!("Gemini provider authorization is unavailable");
            }
            self.attempts.insert(event.attempt_id, event);
            return Ok(());
        }
        self.retain_event(event)
    }

    fn retain_event(&mut self, event: WireEvent) -> Result<()> {
        let old = self
            .attempts
            .get(&event.attempt_id)
            .context("Gemini attempt was not admitted")?;
        if old.terminal.is_some()
            || old.call_id != event.call_id
            || old.mode != event.mode
            || old.request_class != event.request_class
            || event.frames < old.frames
            || event.wire_bytes < old.wire_bytes
            || old
                .observed_model_version
                .as_ref()
                .is_some_and(|model| event.observed_model_version.as_ref() != Some(model))
            || old.released && !event.released
        {
            bail!("Gemini attempt lifecycle regressed");
        }
        match event.kind.as_str() {
            "release" if !old.released && !event.released && event.terminal.is_none() => {
                // Mark conservatively BEFORE ACK. Lost ACK cannot refund a
                // potentially released request, even if no usage arrived.
                self.evidence.provider_released = true;
                self.release_requires_revalidation = true;
            }
            "observation"
                if old.released
                    && event.released
                    && event.terminal.is_none()
                    && event
                        .envelope_sha256
                        .as_ref()
                        .is_some_and(|hash| is_digest(hash)) => {}
            "terminal"
                if event.terminal_ack.as_deref() == Some("pending")
                    && event.terminal.as_deref().is_some_and(|value| {
                        matches!(
                            value,
                            "eof"
                                | "decode_error"
                                | "cancelled"
                                | "consumer_return"
                                | "consumer_error"
                                | "http_error"
                                | "transport_error"
                                | "not_released"
                                | "client_error"
                                | "aborted"
                                | "stream_error"
                                | "send_failed"
                        )
                    }) => {}
            _ => bail!("Gemini invalid attempt transition"),
        }
        if let Some(usage) = &event.usage {
            usage.validate(old.usage.as_ref())?;
        } else if old.usage.is_some() {
            bail!("Gemini usage disappeared");
        }
        if event.usage_lower_bound
            != event
                .usage
                .as_ref()
                .and_then(|usage| usage.total_token_count)
        {
            bail!("Gemini lower bound disagrees with retained usage");
        }
        let mut total = 0usize;
        let mut known = false;
        for (id, prior) in &self.attempts {
            let value = if *id == event.attempt_id {
                &event
            } else {
                prior
            };
            if let Some(tokens) = value.usage_lower_bound {
                total = total
                    .checked_add(usize::try_from(tokens)?)
                    .context("Gemini aggregate overflow")?;
                known = true;
            }
        }
        let mut retained = event;
        if retained.kind == "release" {
            retained.released = true;
        }
        self.attempts.insert(retained.attempt_id, retained);
        self.evidence.tokens = known.then_some(total);
        if self
            .grant
            .as_ref()
            .is_some_and(|grant| total as u64 >= grant.tokens())
        {
            if let Some(grant) = &self.grant {
                grant.exhaust();
            }
            bail!("Gemini observed token grant exceeded; in-flight overshoot is retained");
        }
        Ok(())
    }

    fn take_release_revalidation(&mut self) -> bool {
        std::mem::take(&mut self.release_requires_revalidation)
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn verify_closure(closure: &[ClosureEntry]) -> Result<()> {
    const ROOT: &str =
        "/nix/store/xxd1smzi0a54ldwpc3l8d4v7k2bgjcpl-gemini-cli-0.41.2/share/gemini-cli/";
    let expected: BTreeMap<_, _> = Descriptor::BOOTSTRAP
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.trim().split('"').collect();
            (fields.len() == 5 && fields[1].ends_with(".js") && is_digest(fields[3]))
                .then(|| (fields[1], fields[3]))
        })
        .collect();
    if expected.len() != 12 || closure.len() != 12 {
        bail!("Gemini import closure count mismatch");
    }
    let mut seen = BTreeSet::new();
    for entry in closure {
        let name = entry
            .path
            .strip_prefix(ROOT)
            .context("Gemini foreign import path")?;
        let original = expected.get(name).context("Gemini unknown import")?;
        let instrumented = match name {
            "chunk-ZP3RCUP6.js" => {
                "630ec3672e310cf731d9b626349fe1116a2b306b525499d57b79030b73438998"
            }
            "chunk-XRLFHCHC.js" => {
                "3b243cff49df9b10dd1ce4abf9bdb381727598e76454b470b25f99f99b98a187"
            }
            _ => original,
        };
        if !seen.insert(name)
            || entry.original_sha256 != *original
            || entry.instrumented_sha256 != instrumented
        {
            bail!("Gemini import source binding mismatch");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_selected_personal_oauth(home: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    fn private_directory(path: &Path, owner: u32) -> Result<()> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| "managed Gemini credential directory is unavailable")?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner
            || metadata.mode() & 0o077 != 0
            || fs::canonicalize(path)? != path
        {
            bail!("managed Gemini credential directory is not private and source-bound");
        }
        Ok(())
    }

    if !home.is_absolute() {
        bail!("managed Gemini home is not absolute");
    }
    let owner = unsafe { libc::geteuid() };
    private_directory(home, owner)?;
    let gemini = home.join(".gemini");
    private_directory(&gemini, owner)?;
    let credential_path = gemini.join("oauth_creds.json");
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(&credential_path)
        .context("selected Gemini personal OAuth credential is unavailable")?;
    let held = file.metadata()?;
    let named = fs::symlink_metadata(&credential_path)?;
    if !held.is_file()
        || named.file_type().is_symlink()
        || held.dev() != named.dev()
        || held.ino() != named.ino()
        || held.uid() != owner
        || held.nlink() != 1
        || held.mode() & 0o077 != 0
        || held.len() > 65_536
    {
        bail!("selected Gemini personal OAuth credential is not a private regular file");
    }
    let mut bytes = Vec::with_capacity(held.len() as usize);
    file.by_ref().take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        bail!("selected Gemini personal OAuth credential exceeds its bound");
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("selected Gemini personal OAuth credential is malformed"))?;
    let object = value
        .as_object()
        .context("selected Gemini personal OAuth credential must be a JSON object")?;
    const ALLOWED: [&str; 6] = [
        "refresh_token",
        "access_token",
        "expiry_date",
        "token_type",
        "scope",
        "id_token",
    ];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str()))
        || object
            .get("refresh_token")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|value| value.is_empty() || value.len() > 16_384)
        || object.get("access_token").is_some_and(|value| {
            value
                .as_str()
                .is_none_or(|value| value.is_empty() || value.len() > 16_384)
        })
        || object.get("expiry_date").is_some_and(|value| {
            value
                .as_u64()
                .is_none_or(|value| value > 9_007_199_254_740_991)
        })
        || ["token_type", "scope", "id_token"].into_iter().any(|key| {
            object
                .get(key)
                .is_some_and(|value| value.as_str().is_none_or(|value| value.len() > 16_384))
        })
    {
        bail!("selected Gemini credential is not the admitted personal OAuth shape");
    }
    Ok(bytes)
}

pub(super) fn run(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    started: Instant,
) -> ExternalAgentRun {
    let mut report = failed_external_run(
        spec,
        started,
        vec!["Gemini managed OAuth bootstrap".into()],
        false,
        "Gemini managed Worker did not complete".into(),
    );
    #[cfg(target_os = "linux")]
    if let Err(error) = run_linux(spec, cancellation, started, &mut report) {
        record_external_error(&mut report, format!("Gemini bootstrap refused: {error:#}"));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cancellation;
    report.duration_ms = duration_millis(started.elapsed());
    report
}

#[cfg(all(target_os = "linux", test))]
fn bootstrap_startup_category(stderr: &CapturedBytes) -> Option<&'static str> {
    if stderr.is_truncated() {
        return None;
    }
    match stderr.as_bytes() {
        b"bootstrap: pre_handshake\n" => Some("pre_handshake"),
        b"bootstrap: pre_handshake_manifest\n" => Some("pre_handshake_manifest"),
        b"bootstrap: pre_handshake_profile\n" => Some("pre_handshake_profile"),
        b"bootstrap: pre_handshake_parent_connect\n" => Some("pre_handshake_parent_connect"),
        b"bootstrap: pre_handshake_hello_ack\n" => Some("pre_handshake_hello_ack"),
        b"bootstrap: post_handshake\n" => Some("post_handshake"),
        _ => None,
    }
}

#[cfg(all(target_os = "linux", test))]
fn bootstrap_startup_error(error: Option<String>, stderr: &CapturedBytes) -> Option<String> {
    let Some(category) = bootstrap_startup_category(stderr) else {
        return error;
    };
    Some(match error {
        Some(error) => format!("{error}; Gemini bootstrap startup: {category}"),
        None => format!("Gemini bootstrap startup: {category}"),
    })
}

#[cfg(target_os = "linux")]
fn run_linux(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    started: Instant,
    report: &mut ExternalAgentRun,
) -> Result<()> {
    run_linux_online(spec, cancellation, started, report)
}

#[cfg(all(target_os = "linux", test))]
fn run_linux_offline(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    started: Instant,
    report: &mut ExternalAgentRun,
) -> Result<()> {
    use crate::process_runner::GeminiOfflineBridgeProfile;
    use std::io::Write;
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    Descriptor::select(
        spec.runtime_adapter
            .as_ref()
            .context("Gemini adapter configuration missing")?,
        &spec.program,
    )?;
    if fs::canonicalize(Descriptor::NODE)? != Path::new(Descriptor::NODE_RESOLVED) {
        bail!("Gemini pinned Node entry changed target");
    }
    let node = read_bounded_regular_file_nofollow(
        Path::new(Descriptor::NODE_RESOLVED),
        128 * 1024 * 1024,
    )?;
    if sha256_hex(&node) != Descriptor::NODE_SHA256 {
        bail!("Gemini pinned Node identity mismatch");
    }
    let grant = spec
        .verified_live_token_grant()
        .map_err(anyhow::Error::msg)?
        .cloned();
    let prompt = read_bounded_regular_file_nofollow(&spec.prompt, MAX_PROMPT_BYTES)?;
    let _controls = protected_worktree_controls(spec)?;
    let mut staging =
        ExternalOutputStaging::create(&spec.cwd, spec.machine_global_retention.clone())?;
    // Until quiescence is proven the staging owner must retain all control files.
    staging.preserve_unquiescent = true;
    let root = SecureOutputRoot::open_private(staging.root_path())?;
    let control = root.create_child(OsStr::new("gemini-bridge"))?;
    let profile = control.create_child(OsStr::new("profile"))?;
    let mut held_files = Vec::new();
    for (directory, name, bytes) in [
        (
            &control,
            "gemini_managed_bootstrap.mjs",
            Descriptor::BOOTSTRAP.as_bytes(),
        ),
        (
            &control,
            "gemini_code_assist_wire.mjs",
            Descriptor::WIRE.as_bytes(),
        ),
        (&profile, "system.json", b"{}\n".as_slice()),
        (&profile, "defaults.json", b"{}\n".as_slice()),
    ] {
        let mut file = directory.reserve(OsStr::new(name))?;
        file.write_bytes_atomic(bytes, MAX_PROMPT_BYTES)?;
        held_files.push(file);
    }
    let socket_path = control.path().join("parent.sock");
    if socket_path.as_os_str().len() >= 108 {
        bail!("Gemini private socket path exceeds Unix bound");
    }
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let mut random = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let nonce = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let prompt_hash = sha256_hex(&prompt);
    let manifest = serde_json::to_vec(&serde_json::json!({ "nonce": nonce,
        "candidate": fs::canonicalize(&spec.cwd)?, "model": spec.model.as_deref().context("Gemini requested model missing")?,
        "promptSha256": prompt_hash, "bootstrapSha256": sha256_hex(Descriptor::BOOTSTRAP.as_bytes()), "wireSha256": sha256_hex(Descriptor::WIRE.as_bytes()) }))?;
    let mut file = control.reserve(OsStr::new("launch.json"))?;
    file.write_bytes_atomic(&manifest, 16384)?;
    let argv: Vec<OsString> = vec![
        control
            .path()
            .join("gemini_managed_bootstrap.mjs")
            .into_os_string(),
        "--maco-managed".into(),
        file.path().as_os_str().to_owned(),
    ];
    held_files.push(file);
    let mut confinement =
        GeminiOfflineBridgeProfile::new(&spec.cwd, control.path(), profile.path());
    for hidden in &spec.hidden_roots {
        confinement = confinement.with_hidden_root(hidden);
    }
    // Never expose ambient candidate configuration to vendor discovery.
    for name in [".env", ".gemini", ".agents", ".git"] {
        if spec.cwd.join(name).exists() {
            confinement = confinement.with_hidden_root(spec.cwd.join(name));
        }
    }
    let home = profile.path().to_string_lossy().into_owned();
    let environment = BTreeMap::from([
        ("HOME".into(), home.clone()),
        ("GEMINI_CLI_HOME".into(), home.clone()),
        (
            "GEMINI_CLI_SYSTEM_SETTINGS_PATH".into(),
            format!("{home}/system.json"),
        ),
        (
            "GEMINI_CLI_SYSTEM_DEFAULTS_PATH".into(),
            format!("{home}/defaults.json"),
        ),
        ("PATH".into(), "/nonexistent".into()),
        ("LANG".into(), "C.UTF-8".into()),
    ]);
    let sealed = seal_assignment_process_launch_grant(
        spec,
        Path::new(Descriptor::NODE),
        &argv,
        staging.path()?,
        &spec.cwd,
    )?;
    let mut process = ProcessSpec::direct(
        "Gemini managed bootstrap",
        Descriptor::NODE,
        argv,
        &spec.cwd,
        65536,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_timeout(Some(spec.timeout.saturating_sub(started.elapsed())))
    .with_side_effect_confinement(SideEffectConfinementProfile::GeminiOfflineBridge(
        confinement,
    ));
    if let Some(identity) = &spec.agent_lifecycle {
        let mut lifecycle = AgentLaunchMetadata::new(
            &identity.registry_repo,
            &identity.role,
            &identity.run_id,
            &identity.task_id,
        )?;
        if let Some(parent) = &identity.parent {
            lifecycle = lifecycle.with_parent(parent.clone())?;
        }
        process = process.with_agent_lifecycle(lifecycle);
    }
    if let Some(sealed) = sealed {
        consume_assignment_process_launch_grant(spec, sealed, &mut process, staging.path()?)?;
    }
    let child_cancel = cancellation.child_scope();
    let mut protocol = Protocol::new(nonce.clone(), prompt_hash, grant);
    report.stdout.target_launch_attempted = true;
    let output = run_process_interactive(process, &child_cancel, |session| {
        let result = (|| -> Result<(), String> {
            let mut stream = loop {
                session.check_private_channel_live()?;
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => return Err("Gemini private listener failed".into()),
                }
            };
            session.verify_private_peer(&stream)?;
            stream
                .set_nonblocking(true)
                .map_err(|_| "Gemini private socket setup failed")?;
            let mut buffer = Vec::new();
            while !protocol.terminal {
                session.check_private_channel_live()?;
                session.verify_private_peer(&stream)?;
                let mut byte = [0u8; 1];
                match stream.read(&mut byte) {
                    Ok(0) => return Err("Gemini private channel lost".into()),
                    Ok(_) if byte[0] != b'\n' => {
                        buffer.push(byte[0]);
                        if buffer.len() > 16384 {
                            return Err("Gemini private frame exceeded bound".into());
                        }
                    }
                    Ok(_) => {
                        protocol
                            .receive(&buffer)
                            .map_err(|error| error.to_string())?;
                        buffer.clear();
                        // Conservative release state is committed before this write.
                        let reply = format!(
                            "{{\"nonce\":\"{}\",\"sequence\":{},\"ok\":true}}\n",
                            nonce, protocol.sequence
                        );
                        let mut sent = 0;
                        while sent < reply.len() {
                            session.check_private_channel_live()?;
                            match stream.write(&reply.as_bytes()[sent..]) {
                                Ok(0) => return Err("Gemini ACK lost".into()),
                                Ok(n) => sent += n,
                                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                    std::thread::sleep(Duration::from_millis(2))
                                }
                                Err(_) => return Err("Gemini ACK lost".into()),
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => return Err("Gemini private receive failed".into()),
                }
            }
            Ok(())
        })();
        if result.is_err() {
            protocol.stopped = true;
            child_cancel.cancel();
        }
        result
    });
    match output {
        Ok(output) => {
            report.exit_code = output.process.status.and_then(|status| status.code());
            report.timed_out = output.process.timed_out;
            report.process_tree = Some(output.process.process_tree);
            report.side_effects = Some(output.process.side_effects);
            protocol.evidence.no_release_quiescent =
                !protocol.evidence.provider_released && output.process.safety_evidence_verified();
            if let Some(error) =
                bootstrap_startup_error(output.interaction.err(), &output.process.stderr)
            {
                record_external_error(report, error);
            }
        }
        Err(error) => record_external_error(report, error.to_string()),
    }
    report.stdout.run_metadata.gemini_bridge = Some(protocol.evidence);
    if report.scratch_quiescence_verified() {
        staging.preserve_unquiescent = false;
        drop(listener);
        fs::remove_file(&socket_path)?;
        for file in held_files {
            file.remove()?;
        }
        fs::remove_dir(profile.path())?;
        fs::remove_dir(control.path())?;
        match staging.cleanup()? {
            ExternalOutputCleanup::Quarantined(operation) => {
                persist_machine_global_retention_receipt(&spec.json_log, &operation)?;
                report
                    .stdout
                    .run_metadata
                    .machine_global_retention_operation_id = Some(operation.id);
            }
            ExternalOutputCleanup::Denied(denial) => {
                report.stdout.run_metadata.gate_denials.push(denial)
            }
            ExternalOutputCleanup::Bypassed(attribution) => report
                .stdout
                .run_metadata
                .machine_global_bypasses
                .push(attribution),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_linux_online(
    spec: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    started: Instant,
    report: &mut ExternalAgentRun,
) -> Result<()> {
    use crate::process_runner::GeminiOnlineBridgeProfile;
    use std::io::Write;
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    Descriptor::select(
        spec.runtime_adapter
            .as_ref()
            .context("Gemini adapter configuration missing")?,
        &spec.program,
    )?;
    if fs::canonicalize(Descriptor::NODE)? != Path::new(Descriptor::NODE_RESOLVED) {
        bail!("Gemini pinned Node entry changed target");
    }
    let node = read_bounded_regular_file_nofollow(
        Path::new(Descriptor::NODE_RESOLVED),
        128 * 1024 * 1024,
    )?;
    if sha256_hex(&node) != Descriptor::NODE_SHA256 {
        bail!("Gemini pinned Node identity mismatch");
    }
    let read_only = spec.workspace_access == WorkspaceAccess::ReadOnly;
    if !read_only && spec.writable_launch_target != WritableLaunchTarget::ManagedChildWorktree {
        bail!("managed Gemini OAuth is restricted to a writable managed child worktree");
    }
    if read_only
        && (spec.gemini_run_account_binding.is_none()
            || !spec.worktree_control_exceptions.is_empty())
    {
        bail!(
            "managed read-only Gemini requires a frozen selected binding and no control exceptions"
        );
    }
    if read_only
        && (!matches!(
            spec.assignment_process_launch_kind,
            Some(
                AssignmentProcessLaunchKind::AssignmentChild
                    | AssignmentProcessLaunchKind::ParentAuditor
                    | AssignmentProcessLaunchKind::ConsultGemini
            )
        ) || !spec.agent_lifecycle.as_ref().is_some_and(|identity| {
            matches!(
                identity.role.as_str(),
                "researcher" | "auditor" | "gate_classifier" | "consultant"
            )
        }))
    {
        bail!("managed read-only Gemini requires an existing non-delegating role and its typed process intent");
    }
    let frozen = spec.gemini_run_account_binding.as_ref();
    let grant = spec
        .verified_live_token_grant()
        .map_err(anyhow::Error::msg)?
        .cloned();
    if read_only && grant.is_none() {
        bail!("managed read-only Gemini requires its existing finite live token reservation");
    }
    let authority = crate::account_authority::gemini::acquire_gemini_launch_authority(frozen)?;
    let selection = authority.selection_evidence();
    if frozen.is_some_and(|binding| !binding.matches_selection_evidence(&selection)) {
        bail!("managed Gemini selection does not match its frozen launch binding");
    }
    let credential = read_selected_personal_oauth(authority.managed_gemini_home())?;
    report.stdout.run_metadata.managed_gemini_selection = Some(selection);
    let prompt = read_bounded_regular_file_nofollow(&spec.prompt, MAX_PROMPT_BYTES)?;
    let controls = protected_worktree_controls(spec)?;
    let mut native_journal = if read_only {
        if !controls.exact_writable_artifact_files.is_empty() {
            bail!("read-only Gemini cannot receive a writable Worker journal");
        }
        None
    } else {
        NativeToolJournal::bind(&controls, &spec.cwd)?
    };
    let mut output_reservation = reserve_external_output(&spec.output_last_message)?;
    let mut staging =
        ExternalOutputStaging::create(&spec.cwd, spec.machine_global_retention.clone())?;
    // Until quiescence is proven the staging owner must retain all control files.
    staging.preserve_unquiescent = true;
    let root = SecureOutputRoot::open_private(staging.root_path())?;
    let control = root.create_child(OsStr::new("gemini-bridge"))?;
    let profile = control.create_child(OsStr::new("profile"))?;
    let credential_directory = profile.create_child(OsStr::new(".gemini"))?;
    if read_only {
        native_journal = Some(NativeToolJournal::bind_read_only(
            control.reserve(OsStr::new("native-read-only.jsonl"))?,
            &spec.cwd,
        )?);
    }
    let mut held_files = Vec::new();
    for (directory, name, bytes) in [
        (
            &control,
            "gemini_managed_bootstrap.mjs",
            Descriptor::BOOTSTRAP.as_bytes(),
        ),
        (
            &control,
            "gemini_code_assist_wire.mjs",
            Descriptor::WIRE.as_bytes(),
        ),
        (&profile, "system.json", b"{}\n".as_slice()),
        (&profile, "defaults.json", b"{}\n".as_slice()),
        (&control, "prompt.txt", prompt.as_slice()),
    ] {
        let mut file = directory.reserve(OsStr::new(name))?;
        file.write_bytes_atomic(bytes, MAX_PROMPT_BYTES)?;
        held_files.push(file);
    }
    let mut credential_file = credential_directory.reserve(OsStr::new("oauth_creds.json"))?;
    credential_file.write_bytes_atomic(&credential, 65_536)?;
    let result_file = profile.reserve(OsStr::new("result.txt"))?;
    let socket_path = control.path().join("parent.sock");
    if socket_path.as_os_str().len() >= 108 {
        bail!("Gemini private socket path exceeds Unix bound");
    }
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let mut random = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let nonce = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let prompt_hash = sha256_hex(&prompt);
    let manifest = serde_json::to_vec(&serde_json::json!({ "nonce": nonce,
        "candidate": fs::canonicalize(&spec.cwd)?, "model": spec.model.as_deref().context("Gemini requested model missing")?,
        "workspaceAccess": if read_only { "read_only" } else { "read_write" }, "promptPath": control.path().join("prompt.txt"),
        "resultPath": result_file.path(), "promptSha256": prompt_hash,
        "bootstrapSha256": sha256_hex(Descriptor::BOOTSTRAP.as_bytes()),
        "wireSha256": sha256_hex(Descriptor::WIRE.as_bytes()) }))?;
    let mut file = control.reserve(OsStr::new("launch.json"))?;
    file.write_bytes_atomic(&manifest, 16384)?;
    let argv: Vec<OsString> = vec![
        control
            .path()
            .join("gemini_managed_bootstrap.mjs")
            .into_os_string(),
        "--maco-managed".into(),
        file.path().as_os_str().to_owned(),
    ];
    held_files.push(file);
    let mut confinement = GeminiOnlineBridgeProfile::new(
        &spec.cwd,
        spec.workspace_access,
        control.path(),
        profile.path(),
    )?;
    for hidden in &spec.hidden_roots {
        confinement = confinement.with_hidden_root(hidden);
    }
    // Never expose ambient candidate configuration to vendor discovery.
    for name in [".env", ".gemini", ".agents", ".git"] {
        if spec.cwd.join(name).exists() {
            confinement = confinement.with_hidden_root(spec.cwd.join(name));
        }
    }
    let home = profile.path().to_string_lossy().into_owned();
    let mut environment = BTreeMap::from([
        ("HOME".into(), home.clone()),
        ("GEMINI_CLI_HOME".into(), home.clone()),
        (
            "GEMINI_CLI_SYSTEM_SETTINGS_PATH".into(),
            format!("{home}/system.json"),
        ),
        (
            "GEMINI_CLI_SYSTEM_DEFAULTS_PATH".into(),
            format!("{home}/defaults.json"),
        ),
        ("PATH".into(), "/nonexistent".into()),
        ("LANG".into(), "C.UTF-8".into()),
    ]);
    authority.apply_launch_environment(&mut environment);
    for required in [
        "HOME",
        "GEMINI_CLI_HOME",
        "GOOGLE_GENAI_USE_GCA",
        "GEMINI_CLI_SYSTEM_SETTINGS_PATH",
        "GEMINI_CLI_SYSTEM_DEFAULTS_PATH",
        "PATH",
        "LANG",
    ] {
        if !environment.contains_key(required) {
            bail!("managed Gemini launch spec removed a required private environment binding");
        }
    }
    let sealed = seal_assignment_process_launch_grant(
        spec,
        Path::new(Descriptor::NODE),
        &argv,
        staging.path()?,
        &spec.cwd,
    )?;
    let mut process = ProcessSpec::direct(
        "Gemini managed bootstrap",
        Descriptor::NODE,
        argv,
        &spec.cwd,
        65536,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_timeout(Some(spec.timeout.saturating_sub(started.elapsed())))
    .with_side_effect_confinement(SideEffectConfinementProfile::GeminiOnlineBridge(
        confinement,
    ));
    if let Some(identity) = &spec.agent_lifecycle {
        let mut lifecycle = AgentLaunchMetadata::new(
            &identity.registry_repo,
            &identity.role,
            &identity.run_id,
            &identity.task_id,
        )?;
        if let Some(parent) = &identity.parent {
            lifecycle = lifecycle.with_parent(parent.clone())?;
        }
        process = process.with_agent_lifecycle(lifecycle);
    }
    if let Some(sealed) = sealed {
        consume_assignment_process_launch_grant(spec, sealed, &mut process, staging.path()?)?;
    }
    authority.verify_binding_unchanged()?;
    let child_cancel = cancellation.child_scope();
    let mut protocol = Protocol::new(nonce.clone(), prompt_hash, grant);
    protocol.release_authority = ReleaseAuthority::ManagedOAuth;
    protocol.read_only = read_only;
    let read_only_launch = if read_only {
        Some(ReadOnlyLaunchBinding::bind(spec)?)
    } else {
        None
    };
    protocol.native_journal = native_journal;
    report.error = None;
    report.stdout.target_launch_attempted = true;
    let output = run_process_interactive(process, &child_cancel, |session| {
        let result = (|| -> Result<(), String> {
            let mut stream = loop {
                session.check_private_channel_live()?;
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => return Err("Gemini private listener failed".into()),
                }
            };
            session.verify_private_peer(&stream)?;
            protocol.evidence.read_only_launch = read_only_launch.clone();
            stream
                .set_nonblocking(true)
                .map_err(|_| "Gemini private socket setup failed")?;
            let mut buffer = Vec::new();
            while !protocol.terminal {
                session.check_private_channel_live()?;
                session.verify_private_peer(&stream)?;
                let mut byte = [0u8; 1];
                match stream.read(&mut byte) {
                    Ok(0) => return Err("Gemini private channel lost".into()),
                    Ok(_) if byte[0] != b'\n' => {
                        buffer.push(byte[0]);
                        if buffer.len() > 16384 {
                            return Err("Gemini private frame exceeded bound".into());
                        }
                    }
                    Ok(_) => {
                        protocol
                            .receive(&buffer)
                            .map_err(|error| error.to_string())?;
                        buffer.clear();
                        if protocol.take_release_revalidation() {
                            authority.verify_binding_unchanged().map_err(|_| {
                                "Gemini launch authority changed before release".to_string()
                            })?;
                        }
                        // Conservative release state is committed before this write.
                        let reply = format!(
                            "{{\"nonce\":\"{}\",\"sequence\":{},\"ok\":true}}\n",
                            nonce, protocol.sequence
                        );
                        let mut sent = 0;
                        while sent < reply.len() {
                            session.check_private_channel_live()?;
                            match stream.write(&reply.as_bytes()[sent..]) {
                                Ok(0) => return Err("Gemini ACK lost".into()),
                                Ok(n) => sent += n,
                                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                    std::thread::sleep(Duration::from_millis(2))
                                }
                                Err(_) => return Err("Gemini ACK lost".into()),
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => return Err("Gemini private receive failed".into()),
                }
            }
            Ok(())
        })();
        if result.is_err() {
            protocol.stopped = true;
            child_cancel.cancel();
        }
        result
    });
    match output {
        Ok(output) => {
            report.exit_code = output.process.status.and_then(|status| status.code());
            report.timed_out = output.process.timed_out;
            report.process_tree = Some(output.process.process_tree);
            report.side_effects = Some(output.process.side_effects);
            protocol.evidence.no_release_quiescent =
                !protocol.evidence.provider_released && output.process.safety_evidence_verified();
            if let Err(error) = output.interaction {
                record_external_error(report, error);
            }
            if output.process.timed_out {
                record_external_error(report, "Gemini managed Worker timed out".into());
            } else if !output.process.status.is_some_and(|status| status.success()) {
                record_external_error(report, "Gemini managed Worker exited unsuccessfully".into());
            }
        }
        Err(error) => record_external_error(report, error.to_string()),
    }
    // Capture before fallible result/cleanup I/O, using the original held file.
    let captures = protocol.native_journal.as_ref().map_or_else(
        || capture_worker_journal_artifacts(&controls, report.scratch_quiescence_verified()),
        |journal| journal.capture(&controls, report.scratch_quiescence_verified()),
    );
    report.replace_worker_journal_artifacts(captures);
    if read_only {
        match protocol
            .native_journal
            .as_ref()
            .context("Gemini read-only journal missing")?
            .capture_read_only(report.scratch_quiescence_verified())
        {
            Ok(bytes) => protocol.evidence.read_only_journal = Some(bytes),
            Err(error) => record_external_error(report, error.to_string()),
        }
    }
    report.stdout.run_metadata.gemini_bridge = Some(protocol.evidence.clone());
    if (if read_only {
        protocol.evidence.managed_read_only_completed
            && protocol.evidence.read_only_journal.is_some()
    } else {
        protocol.evidence.managed_worker_completed && protocol.evidence.tool_mutation_observed
    }) && report.exit_code == Some(0)
        && !report.timed_out
    {
        let result = result_file.read_bounded(OUTPUT_TEE_LIMIT_BYTES)?;
        let result_sha256 = sha256_hex(&result);
        if result.is_empty() || protocol.result_sha256.as_deref() != Some(result_sha256.as_str()) {
            record_external_error(report, "Gemini managed result binding changed".into());
        } else {
            staging
                .reservation_mut()?
                .write_bytes_atomic(&result, OUTPUT_TEE_LIMIT_BYTES)?;
            output_reservation.write_bytes_atomic(&result, OUTPUT_TEE_LIMIT_BYTES)?;
            report.output_last_message = Some(result);
        }
    }
    report.publishable = report.exit_code == Some(0)
        && !report.timed_out
        && report.error.is_none()
        && report.output_last_message.is_some()
        && report.scratch_quiescence_verified()
        && report
            .stdout
            .run_metadata
            .gemini_bridge
            .as_ref()
            .is_some_and(|evidence| {
                evidence.provider_released
                    && if read_only {
                        evidence.managed_read_only_completed
                            && evidence.read_only_journal.is_some()
                            && !evidence.tool_mutation_observed
                    } else {
                        evidence.managed_worker_completed && evidence.tool_mutation_observed
                    }
            });
    if report.scratch_quiescence_verified() {
        staging.preserve_unquiescent = false;
        drop(listener);
        fs::remove_file(&socket_path)?;
        for file in held_files {
            file.remove()?;
        }
        credential_file.remove()?;
        result_file.remove()?;
        if let Some(journal) = protocol.native_journal.take() {
            if let NativeJournalArtifact::ReadOnly(file) = journal.artifact {
                file.remove()?;
            }
        }
        drop(credential_directory);
        remove_staged_codex_home(profile)?;
        fs::remove_dir(control.path())?;
        match staging.cleanup()? {
            ExternalOutputCleanup::Quarantined(operation) => {
                persist_machine_global_retention_receipt(&spec.json_log, &operation)?;
                report
                    .stdout
                    .run_metadata
                    .machine_global_retention_operation_id = Some(operation.id);
            }
            ExternalOutputCleanup::Denied(denial) => {
                report.stdout.run_metadata.gate_denials.push(denial)
            }
            ExternalOutputCleanup::Bypassed(attribution) => report
                .stdout
                .run_metadata
                .machine_global_bypasses
                .push(attribution),
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn test_validate_read_only_launch(command: &ExternalAgentCommand) -> Result<()> {
    refuse_assignment_process_launch_before_preflight(command)?;
    ReadOnlyLaunchBinding::bind(command)?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn test_read_only_completion_consumer(
    consume: impl Fn(&ExternalAgentRun) -> bool,
) -> Result<()> {
    tests::read_only_receiver_consumer_fixture(
        &consume,
        true,
        AssignmentProcessLaunchKind::ConsultGemini,
    )?;
    tests::read_only_receiver_consumer_fixture(
        &consume,
        false,
        AssignmentProcessLaunchKind::ConsultGemini,
    )?;
    tests::read_only_receiver_consumer_fixture(
        consume,
        false,
        AssignmentProcessLaunchKind::ParentAuditor,
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::supervise_budget::{
        BudgetAdmission, BudgetReservationRequest, RunBudgetLedger, RunBudgetLimits,
    };

    type NativeJournalFixture = (
        tempfile::TempDir,
        ProtectedWorktreeControls,
        PathBuf,
        crate::artifacts::ArtifactRunWriter,
        crate::artifacts::ArtifactScratchDirectory,
    );

    fn native_journal_fixture() -> Result<NativeJournalFixture> {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir()?;
        let candidate = temp.path().join("candidate");
        for name in [".git", ".maco", ".maco-cache", ".codex", ".agents"] {
            fs::create_dir_all(candidate.join(name))?;
        }
        let primary = temp.path().join("primary");
        git2::Repository::init(&primary)?;
        let mut writer = crate::artifacts::ArtifactRunWriter::reserve(
            &primary,
            crate::artifacts::RunArtifactFamily::Supervise,
            crate::orchestrator::RunId::new("native-tool-journal")?,
            "journal-test",
        )?;
        let incoming_scratch = writer.create_scratch_dir("incoming")?;
        let incoming = incoming_scratch.path().to_path_buf();
        let journals = incoming.join("worker-journals");
        fs::create_dir_all(&journals)?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&journals, fs::Permissions::from_mode(0o700))?;
        for name in CODEX_WRITABLE_ROOT_PROTECTED_MOUNT_TARGETS {
            fs::create_dir(journals.join(name))?;
            fs::set_permissions(journals.join(name), fs::Permissions::from_mode(0o700))?;
        }
        let path = journals.join("worker.jsonl");
        fs::write(&path, b"")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let candidate = fs::canonicalize(candidate)?;
        let spec = ExternalAgentCommand::codex(
            Descriptor::GEMINI,
            &candidate,
            temp.path().join("prompt"),
            incoming.join("log"),
            incoming.join("report"),
            Duration::from_secs(5),
        )
        .with_worker_journal_artifact("worker", &incoming, &path);
        Ok((
            temp,
            protected_worktree_controls(&spec)?,
            candidate,
            writer,
            incoming_scratch,
        ))
    }

    fn native_frame(
        sequence: u64,
        kind: &str,
        action: u64,
        candidate: &Path,
        after: Option<String>,
    ) -> Vec<u8> {
        serde_json::to_vec(
            &serde_json::json!({"nonce": "a".repeat(64), "sequence": sequence,
            "message": {"type": "native_tool", "event": {"actionId": action, "kind": kind,
                "tool": "write_file", "cwd": candidate,
                "argumentsJson": "{\"file_path\":\"sample.txt\",\"content\":\"native\\n\"}",
                "beforeSha256": null, "afterSha256": after}}}),
        )
        .unwrap()
    }

    #[test]
    fn gemini_read_only_native_receiver_capture_and_consumer_require_live_custody() -> Result<()> {
        read_only_receiver_consumer_fixture(
            |run| {
                run.gemini_bridge_evidence()
                    .is_some_and(|evidence| evidence.read_only_completion_valid(run))
            },
            true,
            AssignmentProcessLaunchKind::ConsultGemini,
        )
    }

    #[test]
    fn gemini_read_only_zero_action_completion_requires_bound_quiescent_live_custody() -> Result<()>
    {
        for kind in [
            AssignmentProcessLaunchKind::ConsultGemini,
            AssignmentProcessLaunchKind::ParentAuditor,
        ] {
            read_only_receiver_consumer_fixture(
                |run| {
                    run.gemini_bridge_evidence()
                        .is_some_and(|evidence| evidence.read_only_completion_valid(run))
                },
                false,
                kind,
            )?;
        }
        for case in [
            "missing",
            "unreleased",
            "unfinished",
            "pending",
            "failed",
            "altered",
            "worker",
            "digest",
        ] {
            let (_temp, controls, candidate, _writer, incoming) = native_journal_fixture()?;
            fs::write(candidate.join("sample.txt"), b"native\n")?;
            let root = SecureOutputRoot::open_private(incoming.path())?;
            let mut p = protocol();
            p.read_only = case != "worker";
            p.native_journal = match case {
                "missing" => None,
                "worker" => NativeToolJournal::bind(&controls, &candidate)?,
                _ => Some(NativeToolJournal::bind_read_only(
                    root.reserve(OsStr::new("read-only.jsonl"))?,
                    &candidate,
                )?),
            };
            if case != "unreleased" {
                for kind in ["admission", "release", "terminal"] {
                    if case == "unfinished" && kind == "terminal" {
                        break;
                    }
                    p.receive(&serde_json::to_vec(&serde_json::json!({
                        "nonce": "a".repeat(64), "sequence": p.sequence + 1,
                        "message": {"type": "event", "event": event_value(kind, 1, None)}
                    }))?)?;
                }
            }
            if matches!(case, "pending" | "failed") {
                let frame = serde_json::to_vec(&serde_json::json!({
                    "nonce": "a".repeat(64), "sequence": p.sequence + 1,
                    "message": {"type": "native_tool", "event": {"actionId": 1, "kind": "begin",
                        "tool": if case == "pending" { "read_file" } else { "write_file" },
                        "cwd": candidate, "argumentsJson": "{\"file_path\":\"sample.txt\"}",
                        "beforeSha256": sha256_hex(b"native\n"), "afterSha256": sha256_hex(b"native\n")}}
                }))?;
                let result = p.receive(&frame);
                assert_eq!(result.is_err(), case == "failed");
                assert!(p
                    .native_journal
                    .as_ref()
                    .unwrap()
                    .capture_read_only(true)
                    .is_err());
            }
            if case == "altered" {
                let NativeJournalArtifact::ReadOnly(file) =
                    &mut p.native_journal.as_mut().unwrap().artifact
                else {
                    unreachable!()
                };
                file.write_bytes_atomic(b"forged\n", MAX_WORKER_JOURNAL_ARTIFACT_BYTES)?;
                assert!(p
                    .native_journal
                    .as_ref()
                    .unwrap()
                    .capture_read_only(true)
                    .is_err());
            }
            assert!(p.receive(&serde_json::to_vec(&serde_json::json!({
                "nonce": "a".repeat(64), "sequence": p.sequence + 1,
                "message": {"type": "completed",
                    "resultSha256": if case == "digest" { "invalid".to_string() } else { sha256_hex(b"{}\n") },
                    "toolMutationObserved": false}
            }))?).is_err(), "accepted {case}");
            assert!(!p.evidence.managed_read_only_completed, "accepted {case}");
            assert!(!p.evidence.managed_worker_completed, "accepted {case}");
        }
        Ok(())
    }

    pub(super) fn read_only_receiver_consumer_fixture(
        consume: impl Fn(&ExternalAgentRun) -> bool,
        with_read: bool,
        kind: AssignmentProcessLaunchKind,
    ) -> Result<()> {
        let (_temp, _controls, candidate, _writer, incoming) = native_journal_fixture()?;
        fs::write(candidate.join("sample.txt"), b"native\n")?;
        let root = SecureOutputRoot::open_private(incoming.path())?;
        let mut p = protocol();
        p.read_only = true;
        p.native_journal = Some(NativeToolJournal::bind_read_only(
            root.reserve(OsStr::new("read-only.jsonl"))?,
            &candidate,
        )?);
        let command = ExternalAgentCommand::codex(
            Descriptor::GEMINI,
            &candidate,
            "prompt",
            "log",
            "result",
            Duration::from_secs(1),
        )
        .with_workspace_access(WorkspaceAccess::ReadOnly)
        .with_runtime_adapter(
            RuntimeId::GeminiCli,
            RuntimeAdapterConfig::defaults(RuntimeId::GeminiCli),
        )
        .with_model_selection(Some("gemini-2.5-pro".into()), None)
        .with_agent_lifecycle(
            &candidate,
            if kind == AssignmentProcessLaunchKind::ParentAuditor {
                "auditor"
            } else {
                "researcher"
            },
            "read-only",
            "read-only",
        )
        .with_gemini_run_account_binding(Some(FrozenGeminiSelectedBinding {
            authority_id: Some("synthetic-offline-authority".into()),
            provider_id: "gemini-cli".into(),
            account_id: "synthetic-account".into(),
            account_incarnation: "synthetic-incarnation".into(),
            selection_revision: 1,
        }));
        let issuer = match kind {
            AssignmentProcessLaunchKind::ConsultGemini => {
                crate::mutation_taxonomy::admit_consult_gemini_process_intent
            }
            AssignmentProcessLaunchKind::ParentAuditor => {
                crate::mutation_taxonomy::admit_parent_auditor_process_intent
            }
            _ => bail!("unsupported read-only fixture intent"),
        };
        let intent = issuer(
            "read-only",
            "read-only",
            1,
            Path::new(kind.trusted_program_spelling()),
            command.model.as_deref(),
            "read-only fixture",
        )?;
        let mut command = command.with_assignment_process_launch(kind, intent);
        let ledger = crate::supervise_budget::RunBudgetLedger::new(
            crate::supervise_budget::RunBudgetLimits {
                hard_tokens: Some(100),
                ..Default::default()
            },
        )?;
        let crate::supervise_budget::BudgetAdmission::Admitted { reservation, .. } = ledger
            .reserve(crate::supervise_budget::BudgetReservationRequest {
                role: crate::supervise::AgentRole::Researcher,
                tokens: 100,
                cost_usd: None,
            })?
        else {
            bail!("fixture budget refused")
        };
        command.bind_live_token_grant(ledger.live_token_grant(reservation.id)?);
        p.evidence.read_only_launch = Some(ReadOnlyLaunchBinding::bind(&command)?);
        p.grant = command
            .verified_live_token_grant()
            .map_err(anyhow::Error::msg)?
            .cloned();
        // Deterministic physical state receiver; no actual provider or child is
        // launched and this is not runtime qualification evidence.
        for (index, kind) in ["admission", "release", "terminal"].into_iter().enumerate() {
            p.receive(&serde_json::to_vec(&serde_json::json!({
                "nonce": "a".repeat(64), "sequence": index + 1,
                "message": {"type": "event", "event": event_value(kind, 1, None)}
            }))?)?;
        }
        let read_frame = |sequence, kind| {
            serde_json::to_vec(&serde_json::json!({
                "nonce": "a".repeat(64), "sequence": sequence,
                "message": {"type": "native_tool", "event": {"actionId": 1, "kind": kind,
                    "tool": "read_file", "cwd": candidate, "argumentsJson": "{\"file_path\":\"sample.txt\"}",
                    "beforeSha256": sha256_hex(b"native\n"), "afterSha256": sha256_hex(b"native\n")}}
            }))
        };
        let completion_sequence = if with_read {
            p.receive(&read_frame(4, "begin")?)?;
            assert!(p
                .native_journal
                .as_ref()
                .unwrap()
                .capture_read_only(true)
                .is_err());
            p.receive(&read_frame(5, "completed")?)?;
            6
        } else {
            let journal = p.native_journal.as_ref().unwrap();
            assert_eq!(journal.last_action, 0);
            assert!(journal.records.is_empty());
            assert!(journal.bytes.is_empty());
            4
        };
        assert!(p
            .native_journal
            .as_ref()
            .unwrap()
            .capture_read_only(false)
            .is_err());
        p.receive(&serde_json::to_vec(&serde_json::json!({"nonce": "a".repeat(64), "sequence": completion_sequence,
            "message": {"type": "completed", "resultSha256": sha256_hex(b"{}\n"), "toolMutationObserved": false}}))?)?;
        assert!(p.terminal);
        assert!(p.evidence.managed_read_only_completed);
        assert!(!p.evidence.managed_worker_completed);
        let bytes = p.native_journal.as_ref().unwrap().capture_read_only(true)?;
        assert_eq!(bytes.is_empty(), !with_read);
        p.evidence.read_only_journal = Some(bytes);
        let mut run = failed_external_run(
            &command,
            Instant::now(),
            Vec::new(),
            false,
            "fixture".into(),
        );
        run.error = None;
        run.exit_code = Some(0);
        run.publishable = true;
        run.output_last_message = Some(b"{}\n".to_vec());
        run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ));
        run.side_effects = Some(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::GeminiOnlineBridge,
        ));
        run.stdout.run_metadata.managed_gemini_selection =
            Some(ManagedGeminiAccountSelectionEvidence {
                authority_id: Some("synthetic-offline-authority".into()),
                provider_id: "gemini-cli".into(),
                account_id: "synthetic-account".into(),
                account_incarnation: "synthetic-incarnation".into(),
                selection_revision: 1,
            });
        run.stdout.run_metadata.gemini_bridge = Some(p.evidence.clone());
        let expected_paths = if with_read {
            vec![PathBuf::from("sample.txt")]
        } else {
            Vec::new()
        };
        assert_eq!(
            verify_read_only_evidence(&run, &command, false)?,
            expected_paths
        );
        if with_read {
            assert_eq!(
                verify_read_only_evidence(&run, &command, true)?,
                expected_paths
            );
        } else {
            assert!(verify_read_only_evidence(&run, &command, true).is_err());
        }
        assert!(run
            .gemini_bridge_evidence()
            .unwrap()
            .read_only_completion_valid(&run));
        assert!(consume(&run));
        ledger.reconcile(
            reservation.id,
            crate::supervise_budget::UsageMeasurement::Missing,
        )?;
        assert!(command.verified_live_token_grant().is_err()); // no new release after settlement
        assert_eq!(
            verify_read_only_evidence(&run, &command, false)?,
            expected_paths
        );
        assert!(consume(&run));
        let mut wrong_command = command.clone();
        wrong_command.cwd = candidate.join("other");
        assert!(verify_read_only_evidence(&run, &wrong_command, false).is_err());
        let mut wrong_command = command.clone();
        wrong_command.workspace_access = WorkspaceAccess::ReadWrite;
        assert!(verify_read_only_evidence(&run, &wrong_command, false).is_err());
        let mut wrong = run.clone();
        wrong.output_last_message = Some(Vec::new());
        assert!(!wrong
            .gemini_bridge_evidence()
            .unwrap()
            .read_only_completion_valid(&wrong));
        assert!(!consume(&wrong));
        let mut wrong = run.clone();
        wrong.side_effects = Some(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::GeminiOfflineBridge,
        ));
        assert!(!wrong
            .gemini_bridge_evidence()
            .unwrap()
            .read_only_completion_valid(&wrong));
        assert!(!consume(&wrong));
        if with_read {
            let mut wrong = run.clone();
            wrong
                .stdout
                .run_metadata
                .gemini_bridge
                .as_mut()
                .unwrap()
                .read_only_journal = Some(Vec::new());
            assert!(!wrong
                .gemini_bridge_evidence()
                .unwrap()
                .read_only_completion_valid(&wrong));
            assert!(!consume(&wrong));
        }
        let mut wrong = run.clone();
        wrong.output_last_message = Some(b"changed\n".to_vec());
        assert!(verify_read_only_evidence(&wrong, &command, false).is_err());
        assert!(!consume(&wrong));
        let restored: ExternalAgentRun = serde_json::from_slice(&serde_json::to_vec(&run)?)?;
        assert!(verify_read_only_evidence(&restored, &command, false).is_err());
        assert!(!consume(&restored));
        run.stdout.target_launch_attempted = true;
        run.process_tree = None; // no verified target quiescence
        assert!(verify_read_only_evidence(&run, &command, false).is_err());
        assert!(!consume(&run));
        run.stdout.target_launch_attempted = false;
        run.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ));
        for alteration in [
            "missing",
            "mismatched",
            "mutation",
            "cancelled",
            "unfinished",
        ] {
            if !with_read && alteration == "mismatched" {
                continue;
            }
            let mut wrong = run.clone();
            let held = wrong.stdout.run_metadata.gemini_bridge.as_mut().unwrap();
            match alteration {
                "missing" => held.read_only_journal = None,
                "mismatched" => held.native_tool_records[1].action_id = 2,
                "mutation" => held.tool_mutation_observed = true,
                "cancelled" => held.managed_read_only_completed = false,
                "unfinished" => held.read_only_result_sha256 = None,
                _ => unreachable!(),
            }
            assert!(
                verify_read_only_evidence(&wrong, &command, false).is_err(),
                "accepted {alteration}"
            );
            assert!(!consume(&wrong), "accepted {alteration}");
        }
        if with_read {
            let mut truncated = p.native_journal.as_ref().unwrap().bytes.clone();
            assert!(truncated.pop().is_some());
            let NativeJournalArtifact::ReadOnly(file) =
                &mut p.native_journal.as_mut().unwrap().artifact
            else {
                unreachable!()
            };
            file.write_bytes_atomic(&truncated, MAX_WORKER_JOURNAL_ARTIFACT_BYTES)?;
            assert!(p
                .native_journal
                .as_ref()
                .unwrap()
                .capture_read_only(true)
                .is_err());
        }
        let NativeJournalArtifact::ReadOnly(file) =
            &mut p.native_journal.as_mut().unwrap().artifact
        else {
            unreachable!()
        };
        file.write_bytes_atomic(b"forged\n", MAX_WORKER_JOURNAL_ARTIFACT_BYTES)?;
        assert!(p
            .native_journal
            .as_ref()
            .unwrap()
            .capture_read_only(true)
            .is_err());
        Ok(())
    }

    #[test]
    fn gemini_read_only_native_journal_refuses_mutating_tools_and_cancelled_actions() -> Result<()>
    {
        let (_temp, _controls, candidate, _writer, incoming) = native_journal_fixture()?;
        fs::write(candidate.join("sample.txt"), b"native\n")?;
        let root = SecureOutputRoot::open_private(incoming.path())?;
        let read = NativeToolEvent {
            action_id: 1,
            kind: "begin".into(),
            tool: "read_file".into(),
            cwd: candidate.clone(),
            arguments_json: "{\"file_path\":\"sample.txt\"}".into(),
            before_sha256: Some(sha256_hex(b"native\n")),
            after_sha256: Some(sha256_hex(b"native\n")),
        };
        for (index, tool) in [
            "write_file",
            "replace",
            "run_shell_command",
            "delegate_to_agent",
        ]
        .iter()
        .enumerate()
        {
            let mut journal = NativeToolJournal::bind_read_only(
                root.reserve(OsStr::new(&format!("refused-{index}.jsonl")))?,
                &candidate,
            )?;
            let mut wrong = read.clone();
            wrong.tool = (*tool).into();
            assert!(journal.observe(wrong, 1).is_err());
            assert!(journal.capture_read_only(true).is_err());
        }
        let mut journal = NativeToolJournal::bind_read_only(
            root.reserve(OsStr::new("cancelled.jsonl"))?,
            &candidate,
        )?;
        journal.observe(read.clone(), 1)?;
        let mut cancelled = read;
        cancelled.kind = "cancelled".into();
        journal.observe(cancelled, 2)?;
        assert!(journal.capture_read_only(true).is_err());
        let entries = crate::supervise::parse_worker_execution_journal(
            &journal.held_bytes()?,
            Path::new("held"),
        )?;
        assert_eq!(entries.len(), 2);
        assert!(journal.failure.as_deref().unwrap().contains("cancelled"));
        Ok(())
    }

    #[test]
    fn gemini_native_journal_actual_receiver_capture_and_import_parser() -> Result<()> {
        let (_temp, controls, candidate, mut writer, incoming) = native_journal_fixture()?;
        let mut p = protocol();
        p.evidence.provider_released = true;
        p.native_journal = NativeToolJournal::bind(&controls, &candidate)?;
        p.receive(&native_frame(1, "begin", 1, &candidate, None))?;
        assert!(!candidate.join("sample.txt").exists());
        fs::write(candidate.join("sample.txt"), b"native\n")?;
        p.receive(&native_frame(
            2,
            "completed",
            1,
            &candidate,
            Some(sha256_hex(b"native\n")),
        ))?;
        let captures = p.native_journal.as_ref().unwrap().capture(&controls, true);
        assert_eq!(captures[0].worker_id, "worker");
        assert_eq!(
            captures[0].path,
            controls.exact_writable_artifact_files[0].path
        );
        let WorkerJournalArtifactCaptureStatus::Loaded(bytes) = &captures[0].status else {
            panic!("trusted native capture refused")
        };
        // This is the exact parser used by import_worker_execution_journals_at,
        // not model report JSON or an alternative native serializer.
        let entries = crate::supervise::parse_worker_execution_journal(bytes, &captures[0].path)?;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, entries[1].command);
        assert_eq!(entries[1].command[0], "write_file");
        assert_eq!(entries[1].cwd, candidate);
        assert_eq!(entries[0].start_timestamp, entries[1].start_timestamp);
        assert!(entries[0].changed_paths.is_empty());
        assert_eq!(entries[1].changed_paths, vec![PathBuf::from("sample.txt")]);
        assert_eq!(p.evidence.native_tool_records.len(), 2);
        assert_eq!(p.evidence.native_tool_records[1].begin_offset, 0);
        assert!(p.evidence.native_tool_records[1].record_offset > 0);
        let assignment: crate::supervise::OrchestratorAssignment = serde_json::from_value(
            serde_json::json!({"id": "worker", "phase": "execution", "role": "worker"}),
        )?;
        let spec = ExternalAgentCommand::codex(
            Descriptor::GEMINI,
            &candidate,
            "prompt",
            "log",
            "report",
            Duration::from_secs(1),
        );
        // No child exists in this deterministic receiver fixture: quiescence is
        // actual, not a deserialized containment witness or model report claim.
        let mut report =
            failed_external_run(&spec, Instant::now(), Vec::new(), false, "fixture".into());
        report.replace_worker_journal_artifacts(captures);
        let imported = crate::supervise::import_worker_execution_journals_at(
            &mut writer,
            &assignment,
            &incoming,
            &report,
            None,
        )?;
        assert!(
            matches!(&imported["worker"].status, crate::supervise::WorkerExecutionJournalStatus::Loaded(imported) if imported == &entries)
        );
        let restored: ExternalAgentRun = serde_json::from_slice(&serde_json::to_vec(&report)?)?;
        assert!(restored.worker_journal_artifacts().is_empty());
        assert!(!restored.scratch_quiescence_verified());
        let imported = crate::supervise::import_worker_execution_journals_at(
            &mut writer,
            &assignment,
            &incoming,
            &restored,
            None,
        )?;
        assert!(matches!(
            &imported["worker"].status,
            crate::supervise::WorkerExecutionJournalStatus::Invalid(cause)
                if cause == "worker journal evidence was not imported because external process quiescence was not verified"
        ));
        Ok(())
    }

    #[test]
    fn gemini_native_journal_refuses_forged_missing_mismatched_and_unquiescent_custody(
    ) -> Result<()> {
        let (_temp, mut controls, candidate, mut writer, incoming) = native_journal_fixture()?;
        let mut journal = NativeToolJournal::bind(&controls, &candidate)?.unwrap();
        let event =
            serde_json::from_slice::<Message>(&native_frame(1, "begin", 1, &candidate, None))?;
        let Body::NativeTool { event } = event.message else {
            unreachable!()
        };
        journal.observe(event.clone(), 1)?;
        let captures = journal.capture(&controls, false);
        let WorkerJournalArtifactCaptureStatus::Invalid(cause) = &captures[0].status else {
            panic!("unquiescent capture accepted")
        };
        assert!(cause.contains("quiescence was not verified"));
        let assignment: crate::supervise::OrchestratorAssignment = serde_json::from_value(
            serde_json::json!({"id": "worker", "phase": "execution", "role": "worker"}),
        )?;
        let spec = ExternalAgentCommand::codex(
            Descriptor::GEMINI,
            &candidate,
            "prompt",
            "log",
            "report",
            Duration::from_secs(1),
        );
        let mut report =
            failed_external_run(&spec, Instant::now(), Vec::new(), false, "fixture".into());
        report.stdout.target_launch_attempted = true;
        report.replace_worker_journal_artifacts(captures);
        let imported = crate::supervise::import_worker_execution_journals_at(
            &mut writer,
            &assignment,
            &incoming,
            &report,
            None,
        )?;
        assert!(
            matches!(&imported["worker"].status, crate::supervise::WorkerExecutionJournalStatus::Invalid(cause) if cause.contains("quiescence was not verified"))
        );
        let mut wrong = event;
        wrong.kind = "completed".into();
        wrong.action_id = 2;
        assert!(journal.observe(wrong, 2).is_err());
        let captures = journal.capture(&controls, true);
        let WorkerJournalArtifactCaptureStatus::Invalid(cause) = &captures[0].status else {
            panic!("mismatched capture accepted")
        };
        assert!(cause.contains("correlation"));
        let original_cause = cause.clone();
        report.stdout.target_launch_attempted = false;
        report.replace_worker_journal_artifacts(captures);
        let imported = crate::supervise::import_worker_execution_journals_at(
            &mut writer,
            &assignment,
            &incoming,
            &report,
            None,
        )?;
        assert!(
            matches!(&imported["worker"].status, crate::supervise::WorkerExecutionJournalStatus::Invalid(cause) if cause == &original_cause)
        );
        let mut forged = Vec::new();
        crate::supervise::append_worker_execution_journal_record(
            &mut forged,
            &crate::supervise::WorkerExecutionJournalEntry {
                command: vec!["forged-model-check".into()],
                cwd: candidate.clone(),
                start_timestamp: "2026-09-30T00:00:00Z".into(),
                end_timestamp: "2026-09-30T00:00:01Z".into(),
                changed_paths: Vec::new(),
            },
        )?;
        let NativeJournalArtifact::Worker(artifact) = &journal.artifact else {
            panic!("Worker journal fixture changed kind")
        };
        fs::write(&artifact.path, forged)?;
        assert!(NativeToolJournal::bind(&controls, &candidate).is_err());
        fs::remove_file(&artifact.path)?;
        let captures = journal.capture(&controls, true);
        let WorkerJournalArtifactCaptureStatus::Invalid(cause) = &captures[0].status else {
            panic!("missing held path accepted")
        };
        assert!(cause.contains("could not be revalidated")); // original capture cause wins
        let original_cause = cause.clone();
        report.replace_worker_journal_artifacts(captures);
        let imported = crate::supervise::import_worker_execution_journals_at(
            &mut writer,
            &assignment,
            &incoming,
            &report,
            None,
        )?;
        assert!(
            matches!(&imported["worker"].status, crate::supervise::WorkerExecutionJournalStatus::Invalid(cause) if cause == &original_cause)
        );
        controls.exact_writable_artifact_files.clear();
        assert!(NativeToolJournal::bind(&controls, &candidate)?.is_none());
        let captures = capture_worker_journal_artifacts(&controls, true);
        assert!(captures.is_empty());
        report.replace_worker_journal_artifacts(captures);
        let imported = crate::supervise::import_worker_execution_journals_at(
            &mut writer,
            &assignment,
            &incoming,
            &report,
            None,
        )?;
        assert!(matches!(
            &imported["worker"].status,
            crate::supervise::WorkerExecutionJournalStatus::Missing
        ));
        Ok(())
    }

    #[test]
    fn gemini_native_journal_cancelled_terminal_remains_invalid_and_cannot_complete() -> Result<()>
    {
        let (_temp, controls, candidate, _writer, _incoming) = native_journal_fixture()?;
        let mut p = protocol();
        p.evidence.provider_released = true;
        p.native_journal = NativeToolJournal::bind(&controls, &candidate)?;
        p.receive(&native_frame(1, "begin", 1, &candidate, None))?;
        p.receive(&native_frame(2, "cancelled", 1, &candidate, None))?;
        let journal = p.native_journal.as_ref().unwrap();
        assert!(journal.pending.is_none());
        assert_eq!(journal.records[1].kind, "cancelled");
        let captures = journal.capture(&controls, true);
        let WorkerJournalArtifactCaptureStatus::Invalid(cause) = &captures[0].status else {
            panic!("cancelled journal certified completion")
        };
        assert!(cause.contains("ended cancelled"));
        assert!(p.receive(&serde_json::to_vec(&serde_json::json!({"nonce": "a".repeat(64), "sequence": 3,
            "message": {"type": "completed", "resultSha256": "b".repeat(64), "toolMutationObserved": true}}))?).is_err());
        assert!(!p.evidence.managed_worker_completed);
        Ok(())
    }

    fn event(kind: &str, attempt: u64, total: Option<u64>) -> WireEvent {
        serde_json::from_value(event_value(kind, attempt, total)).unwrap()
    }

    fn event_value(kind: &str, attempt: u64, total: Option<u64>) -> serde_json::Value {
        serde_json::json!({
            "kind": kind, "callId": 1, "attemptId": attempt, "mode": "stream", "requestClass": "generation",
            "released": matches!(kind, "observation" | "terminal"),
            "terminal": (kind == "terminal").then_some("eof"), "terminalAck": (kind == "terminal").then_some("pending"),
            "frames": u64::from(total.is_some()), "wireBytes": if total.is_some() { 512 } else { 0 },
            "usage": total.map(|total| serde_json::json!({"promptTokenCount": total - 10, "candidatesTokenCount": 8,
                "thoughtsTokenCount": 2, "cachedContentTokenCount": 4, "totalTokenCount": total})),
            "observedModelVersion": null, "usageLowerBound": total, "usageCoverage": "observed_lower_bound_only",
            "identityAuthority": "unverified_response_field", "actualEffort": null, "cost": null, "qualified": false,
            "quiescence": "unproven", "envelopeSha256": (kind == "observation").then(|| "a".repeat(64))
        })
    }

    fn protocol() -> Protocol {
        let mut protocol = Protocol::new("a".repeat(64), "b".repeat(64), None);
        protocol.hello = true;
        protocol.evidence.ready = true;
        protocol.release_authority = ReleaseAuthority::DeterministicTransport;
        protocol
    }

    #[test]
    fn gemini_bridge_snapshot_lower_bounds_and_distinct_attempts_never_overlap() {
        let mut p = protocol();
        p.event(event("admission", 1, None)).unwrap();
        p.event(event("release", 1, None)).unwrap();
        p.event(event("observation", 1, Some(100))).unwrap();
        p.event(event("observation", 1, Some(150))).unwrap();
        assert_eq!(p.evidence.tokens, Some(150));
        p.event(event("terminal", 1, Some(150))).unwrap();
        p.event(event("admission", 2, None)).unwrap();
        p.event(event("release", 2, None)).unwrap();
        p.event(event("observation", 2, Some(100))).unwrap();
        assert_eq!(p.evidence.tokens, Some(250));
        let mut malformed = event("observation", 2, Some(120));
        malformed.usage.as_mut().unwrap().cached_content_token_count = Some(500);
        assert!(p.event(malformed).is_err());
        assert_eq!(p.evidence.tokens, Some(250));
    }

    #[test]
    fn gemini_bridge_private_nonce_replay_and_duplicate_keys_latch_before_release() {
        let mut p = Protocol::new("a".repeat(64), "b".repeat(64), None);
        let hello = serde_json::json!({"nonce": "a".repeat(64), "sequence": 1, "message": {"type": "hello",
            "bootstrapSha256": sha256_hex(Descriptor::BOOTSTRAP.as_bytes()), "wireSha256": sha256_hex(Descriptor::WIRE.as_bytes()), "promptSha256": "b".repeat(64)}});
        let bytes = serde_json::to_vec(&hello).unwrap();
        p.receive(&bytes).unwrap();
        assert!(p.receive(&bytes).is_err());
        assert!(p.stopped);
        assert!(!p.evidence.provider_released);
        let mut wrong = Protocol::new("c".repeat(64), "b".repeat(64), None);
        assert!(wrong.receive(&bytes).is_err());
        assert!(wrong.stopped);
        let mut duplicate = Protocol::new("a".repeat(64), "b".repeat(64), None);
        let text = String::from_utf8(bytes).unwrap().replacen(
            "\"sequence\":1",
            "\"sequence\":0,\"sequence\":1",
            1,
        );
        assert!(duplicate.receive(text.as_bytes()).is_err());
        assert!(duplicate.stopped);
    }

    #[test]
    fn gemini_bridge_admission_requires_authority_and_does_not_recycle_missing_usage() {
        let mut p = protocol();
        p.release_authority = ReleaseAuthority::Unavailable;
        assert!(p.event(event("admission", 1, None)).is_err());
        assert!(p.attempts.is_empty());
        assert_eq!(p.evidence.tokens, None);
        let mut p = protocol();
        p.event(event("admission", 1, None)).unwrap();
        assert!(p.event(event("admission", 2, None)).is_err());
        p.event(event("release", 1, None)).unwrap();
        assert!(p.evidence.provider_released); // ACK loss must be conservative.
        assert!(p.take_release_revalidation());
        assert!(!p.take_release_revalidation());
        p.event(event("terminal", 1, None)).unwrap();
        assert!(p.event(event("admission", 2, None)).is_err());
        assert_eq!(p.evidence.tokens, None);
        assert!(!p.evidence.no_release_quiescent);
    }

    #[test]
    fn gemini_selected_personal_oauth_requires_exact_private_file_without_fallback() -> Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temp = tempfile::tempdir()?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        let gemini = temp.path().join(".gemini");
        fs::create_dir(&gemini)?;
        fs::set_permissions(&gemini, fs::Permissions::from_mode(0o700))?;
        let credential = gemini.join("oauth_creds.json");
        let accepted = br#"{"refresh_token":"synthetic-refresh","access_token":"synthetic-access","expiry_date":1,"token_type":"Bearer","scope":"scope","id_token":"synthetic-id"}"#;
        fs::write(&credential, accepted)?;
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o600))?;
        assert_eq!(read_selected_personal_oauth(temp.path())?, accepted);

        fs::write(
            &credential,
            br#"{"refresh_token":"synthetic-refresh","api_key":"credential-secret"}"#,
        )?;
        let malformed = read_selected_personal_oauth(temp.path()).unwrap_err();
        assert!(malformed
            .to_string()
            .contains("admitted personal OAuth shape"));
        assert!(!malformed.to_string().contains("credential-secret"));

        fs::remove_file(&credential)?;
        let target = temp.path().join("held-oauth.json");
        fs::write(&target, accepted)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        symlink(&target, &credential)?;
        assert!(read_selected_personal_oauth(temp.path()).is_err());

        fs::remove_file(&credential)?;
        fs::write(temp.path().join("oauth_creds.json"), accepted)?;
        assert!(read_selected_personal_oauth(temp.path()).is_err());
        Ok(())
    }

    #[test]
    fn gemini_native_profile_cleanup_removes_confined_runtime_storage() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        let root = SecureOutputRoot::open_private(temp.path())?;
        let profile = root.create_child(OsStr::new("profile"))?;
        let project = profile.path().join(".gemini/projects/project-hash");
        fs::create_dir_all(&project)?;
        fs::write(profile.path().join(".gemini/projects.json"), b"{}\n")?;
        fs::write(project.join("state.json"), b"{}\n")?;

        let profile_path = profile.path().to_path_buf();
        remove_staged_codex_home(profile)?;
        assert!(!profile_path.exists());
        root.verify_path_identity()?;
        Ok(())
    }

    #[test]
    fn gemini_bridge_breach_retains_observed_overshoot_and_stops_shared_grant() {
        let ledger = RunBudgetLedger::new(RunBudgetLimits {
            hard_tokens: Some(120),
            ..RunBudgetLimits::default()
        })
        .unwrap();
        let BudgetAdmission::Admitted { reservation, .. } = ledger
            .reserve(BudgetReservationRequest {
                role: AgentRole::Worker,
                tokens: 10,
                cost_usd: None,
            })
            .unwrap()
        else {
            panic!("reservation");
        };
        let grant = ledger.live_token_grant(reservation.id).unwrap().unwrap();
        let mut p = protocol();
        p.grant = Some(grant.clone());
        p.event(event("admission", 1, None)).unwrap();
        p.event(event("release", 1, None)).unwrap();
        assert!(p.event(event("observation", 1, Some(150))).is_err());
        assert_eq!(p.evidence.tokens, Some(150));
        assert!(grant.stopped());
        assert!(ledger.dispatch_stopped());
    }

    #[test]
    fn gemini_bootstrap_startup_category_rejects_raw_or_truncated_output() {
        for category in [
            "pre_handshake",
            "pre_handshake_manifest",
            "pre_handshake_profile",
            "pre_handshake_parent_connect",
            "pre_handshake_hello_ack",
            "post_handshake",
        ] {
            let bytes = format!("bootstrap: {category}\n");
            let captured = CapturedBytes::from_bytes_for_test(bytes.as_bytes());
            assert_eq!(bootstrap_startup_category(&captured), Some(category));
            assert_eq!(
                bootstrap_startup_error(None, &captured),
                Some(format!("Gemini bootstrap startup: {category}"))
            );
            assert_eq!(
                bootstrap_startup_error(Some("operation deadline".into()), &captured),
                Some(format!(
                    "operation deadline; Gemini bootstrap startup: {category}"
                ))
            );
            let truncated =
                CapturedBytes::from_bytes_with_truncation_for_test(bytes.as_bytes(), true);
            assert_eq!(bootstrap_startup_category(&truncated), None);
        }
        for bytes in [
            b"bootstrap: pre_handshake_profile\ncredential-secret\n".as_slice(),
            b"credential-secret\nbootstrap: pre_handshake_profile\n".as_slice(),
            b"bootstrap: pre_handshake_credential-secret\n".as_slice(),
            b"bootstrap: pre_handshake_profile".as_slice(),
            b"".as_slice(),
        ] {
            let captured = CapturedBytes::from_bytes_for_test(bytes);
            assert_eq!(bootstrap_startup_category(&captured), None);
            assert_eq!(
                bootstrap_startup_error(Some("operation deadline".into()), &captured),
                Some("operation deadline".into())
            );
        }
    }

    #[test]
    fn gemini_bridge_real_installed_bootstrap_retains_quiescent_no_release() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        for control in [".gemini", ".maco", ".maco-cache", ".codex", ".agents"] {
            fs::create_dir_all(repo.join(control))?;
        }
        fs::create_dir_all(temp.path().join("gitdir"))?;
        let artifacts = temp.path().join("artifacts");
        fs::create_dir_all(&artifacts)?;
        fs::write(repo.join(".env"), "GEMINI_API_KEY=ambient\n")?;
        fs::write(repo.join(".git"), "gitdir: ../gitdir\n")?;
        fs::write(
            repo.join("source.rs"),
            "pub fn reviewed_source() -> u32 { 42 }\n",
        )?;
        let prompt = temp.path().join("prompt.txt");
        fs::write(&prompt, "Read source.rs; no changes or delegation.")?;
        let command = ExternalAgentCommand::codex(
            Descriptor::GEMINI,
            &repo,
            &prompt,
            artifacts.join("log.jsonl"),
            artifacts.join("report.json"),
            Duration::from_secs(60),
        )
        .with_workspace_access(WorkspaceAccess::ReadOnly)
        .with_model_selection(Some("gemini-2.5-pro".into()), None)
        .with_runtime_adapter(
            RuntimeId::GeminiCli,
            RuntimeAdapterConfig::defaults(RuntimeId::GeminiCli),
        );
        let started = Instant::now();
        let mut run = failed_external_run(
            &command,
            started,
            vec!["Gemini offline bootstrap fixture".into()],
            false,
            "Gemini offline fixture has no provider authority".into(),
        );
        run_linux_offline(&command, &ProcessCancellation::default(), started, &mut run)?;
        let held = run
            .gemini_bridge_evidence()
            .with_context(|| format!("no held bridge evidence: {:?}", run.error))?;
        assert!(held.ready, "{:?}", run.error);
        assert!(held.no_release_quiescent, "{:?}", run.error);
        assert!(!held.provider_released);
        assert_eq!(held.tokens, None);
        assert!(run.scratch_quiescence_verified());
        assert!(!run.succeeded());
        assert!(!run.publishable);
        assert_eq!(run.exit_code, Some(0));
        let restored: ExternalAgentRun = serde_json::from_slice(&serde_json::to_vec(&run)?)?;
        assert!(restored.gemini_bridge_evidence().is_none());
        Ok(())
    }
}
