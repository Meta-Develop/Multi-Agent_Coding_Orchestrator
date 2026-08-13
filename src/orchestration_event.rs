use std::{
    path::Path,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use crate::artifacts::{
    discover_repo_root, repository_auth_writer, ArtifactFileDisposition, ArtifactRunWriter,
};
use crate::{
    merge::{CandidateValidationBinding, ValidationStatus},
    orchestrator::RunId,
    safe_state::{AtomicStateWriter, BoundedRegularReader, KernelStateLock, SafeRoot},
    sync::normalize_repo_relative_path,
    worktree::normalize_agent_id,
};
use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const ORCHESTRATION_EVENT_PATH: &str = "events/orchestration.jsonl";
const EXTERNAL_EVENT_RUN_ROOT: &str = ".maco/o2-autopilot/runs";
const EXTERNAL_EVENT_DIRECTORY: &str = "events";
const EXTERNAL_EVENT_JOURNAL: &str = "orchestration.jsonl";
const EXTERNAL_EVENT_LOCK: &str = "orchestration.lock";
const MAX_EXTERNAL_EVENT_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXTERNAL_EVENT_LINE_BYTES: usize = 1024 * 1024;
const MAX_EXTERNAL_EVENT_RECORDS: usize = 32 * 1024;
const MAX_EXTERNAL_EVENT_PAYLOAD_BYTES: usize = 4 * 1024;
const MAX_EXTERNAL_EVENT_STATUS_BYTES: usize = 64;
const MAX_ORCHESTRATION_NODE_ID_BYTES: usize = 256;
const MAX_ARBITRATION_REASON_BYTES: usize = 4 * 1024;
const MAX_ARBITRATION_REPORT_PATH_BYTES: usize = 4 * 1024;

#[cfg(test)]
thread_local! {
    static APPEND_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrchestrationRole {
    Root,
    Supervisor,
    Orchestrator,
    Worker,
    Auditor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrchestrationEventKind {
    Spawn,
    Status,
    Journal,
    Accept,
    Reject,
    Escalate,
    Gate,
    Claim,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalAgentRuntime {
    ClaudeCode,
    Codex,
    Human,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalOrchestrationPayload {
    pub runtime: ExternalAgentRuntime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl ExternalOrchestrationPayload {
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(status) = &self.status {
            let normalized = normalize_external_status(status)?;
            if normalized != *status {
                bail!("external orchestration status must be canonical");
            }
        }
        let encoded = serde_json::to_vec(self)
            .context("failed to encode external orchestration event payload")?;
        if encoded.len() > MAX_EXTERNAL_EVENT_PAYLOAD_BYTES {
            bail!(
                "external orchestration payload exceeds its {MAX_EXTERNAL_EVENT_PAYLOAD_BYTES}-byte limit"
            );
        }
        Ok(())
    }
}

pub fn normalize_orchestration_node_id(value: &str) -> anyhow::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("orchestration node id cannot be empty");
    }
    if matches!(trimmed, "." | "..") {
        bail!("orchestration node id cannot be '.' or '..'");
    }
    if trimmed.len() > MAX_ORCHESTRATION_NODE_ID_BYTES {
        bail!("orchestration node id exceeds its {MAX_ORCHESTRATION_NODE_ID_BYTES}-byte limit");
    }
    if !trimmed
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        bail!("orchestration node id may only contain ASCII letters, digits, '.', '_' and '-'");
    }
    Ok(trimmed.to_string())
}

fn normalize_external_status(value: &str) -> anyhow::Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("external orchestration status cannot be empty");
    }
    if trimmed.len() > MAX_EXTERNAL_EVENT_STATUS_BYTES {
        bail!(
            "external orchestration status exceeds its {MAX_EXTERNAL_EVENT_STATUS_BYTES}-byte limit"
        );
    }
    if !trimmed
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
    {
        bail!(
            "external orchestration status may only contain ASCII letters, digits, '.', '_' and '-'"
        );
    }
    Ok(trimmed.to_string())
}

/// Field-guide provenance actions carried by a [`OrchestrationEventKind::Journal`]
/// event's private JSON payload.
///
/// This subordinate vocabulary keeps the top-level event-kind schema backward
/// compatible while allowing callers to distinguish append mutations,
/// deterministic curation, and prompt-injection evidence. Callers must journal
/// only redacted metadata summaries for these actions, never field-guide
/// finding or context text, secrets, or local paths.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldGuideEventKind {
    AppendMutation,
    DeterministicCuration,
    PromptInjectionEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationOutcome {
    Accepted,
    Rejected,
    Escalated,
}

impl ArbitrationOutcome {
    pub const fn event_kind(self) -> OrchestrationEventKind {
        match self {
            Self::Accepted => OrchestrationEventKind::Accept,
            Self::Rejected => OrchestrationEventKind::Reject,
            Self::Escalated => OrchestrationEventKind::Escalate,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArbitrationSide {
    Agent { id: String },
    Primary,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArbitrationOutcomeDetails {
    pub outcome: ArbitrationOutcome,
    pub arbiter_id: String,
    pub sides: [ArbitrationSide; 2],
    pub candidate_binding: Option<CandidateValidationBinding>,
    pub candidate_status: ValidationStatus,
    pub rationale_report: Option<String>,
    pub rationale_sha256: Option<String>,
    pub reason: String,
}

impl ArbitrationOutcomeDetails {
    fn validate(&self) -> Result<(), String> {
        let arbiter_id = canonical_arbitration_agent_id(&self.arbiter_id, "arbiter_id")?;
        let mut side_ids = Vec::with_capacity(2);
        let mut primary_count = 0usize;
        for (index, side) in self.sides.iter().enumerate() {
            match side {
                ArbitrationSide::Agent { id } => {
                    let side_id =
                        canonical_arbitration_agent_id(id, &format!("sides[{index}].id"))?;
                    if side_id == arbiter_id {
                        return Err("neutral arbiter id must differ from both arbitration sides"
                            .to_string());
                    }
                    side_ids.push(side_id);
                }
                ArbitrationSide::Primary => {
                    primary_count += 1;
                }
            }
        }
        if primary_count > 1
            || (side_ids.len() == 2 && side_ids.first() == side_ids.get(1))
            || side_ids.is_empty()
        {
            return Err("arbitration sides must be two distinct participants".to_string());
        }

        let binding_required = match (self.outcome, self.candidate_status) {
            (ArbitrationOutcome::Accepted, ValidationStatus::Passed)
            | (ArbitrationOutcome::Rejected, ValidationStatus::Failed)
            | (ArbitrationOutcome::Rejected, ValidationStatus::Skipped)
            | (ArbitrationOutcome::Escalated, ValidationStatus::Skipped) => true,
            (ArbitrationOutcome::Escalated, ValidationStatus::NotRun) => false,
            _ => {
                return Err(format!(
                    "arbitration outcome {:?} is inconsistent with candidate status {:?}",
                    self.outcome, self.candidate_status
                ));
            }
        };
        if self.candidate_binding.is_some() != binding_required {
            return Err(format!(
                "candidate binding presence is inconsistent with candidate status {:?}",
                self.candidate_status
            ));
        }
        if let Some(binding) = &self.candidate_binding {
            binding
                .clone()
                .canonicalized()
                .map_err(|error| format!("candidate binding is not canonical: {error:#}"))?;
            if binding.agent_id != arbiter_id {
                return Err(
                    "candidate binding agent_id must equal the neutral arbiter id".to_string(),
                );
            }
        }

        let report = paired_arbitration_rationale(
            self.rationale_report.as_deref(),
            self.rationale_sha256.as_deref(),
        )?;
        if report.len() > MAX_ARBITRATION_REPORT_PATH_BYTES {
            return Err(format!(
                "arbitration rationale report path exceeds its {MAX_ARBITRATION_REPORT_PATH_BYTES}-byte limit"
            ));
        }
        let normalized = normalize_repo_relative_path(Path::new(report))
            .map_err(|error| format!("arbitration rationale report path is invalid: {error:#}"))?;
        if normalized != Path::new(report) {
            return Err("arbitration rationale report path must be canonical".to_string());
        }

        let reason = self.reason.trim();
        if reason.is_empty() {
            return Err("arbitration outcome reason cannot be empty".to_string());
        }
        if reason != self.reason {
            return Err(
                "arbitration outcome reason must not have surrounding whitespace".to_string(),
            );
        }
        if reason.len() > MAX_ARBITRATION_REASON_BYTES {
            return Err(format!(
                "arbitration outcome reason exceeds its {MAX_ARBITRATION_REASON_BYTES}-byte limit"
            ));
        }
        if reason.chars().any(char::is_control) {
            return Err("arbitration outcome reason cannot contain control characters".to_string());
        }
        Ok(())
    }
}

fn canonical_arbitration_agent_id(value: &str, field: &str) -> Result<String, String> {
    let normalized =
        normalize_agent_id(value).map_err(|error| format!("{field} is invalid: {error:#}"))?;
    if normalized != value {
        return Err(format!("{field} must be canonical"));
    }
    Ok(normalized)
}

fn paired_arbitration_rationale<'a>(
    report: Option<&'a str>,
    digest: Option<&str>,
) -> Result<&'a str, String> {
    let (Some(report), Some(digest)) = (report, digest) else {
        return Err(
            "arbitration rationale report and SHA-256 digest must both be present".to_string(),
        );
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("arbitration rationale digest must be canonical lowercase SHA-256".to_string());
    }
    Ok(report)
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct OrchestrationEvent {
    pub ts: String,
    pub repo: String,
    pub run: String,
    pub node: String,
    pub parent: Option<String>,
    pub role: OrchestrationRole,
    pub kind: OrchestrationEventKind,
    /// Arbitrary private JSON evidence. Field-guide callers must include only
    /// redacted metadata summaries as described by [`FieldGuideEventKind`].
    pub payload: Value,
}

#[derive(Debug, Error)]
pub enum OrchestrationEventError {
    #[error("system clock is before the Unix epoch")]
    Clock(#[from] SystemTimeError),
    #[error("event timestamp is outside the supported RFC3339 range")]
    TimestampOutOfRange,
    #[error("failed to encode orchestration event payload: {0}")]
    PayloadEncode(#[from] serde_json::Error),
    #[error("invalid arbitration outcome details: {0}")]
    InvalidArbitration(String),
    #[error("failed to append orchestration event journal: {0}")]
    ArtifactAppend(String),
    #[cfg(test)]
    #[error("injected orchestration event append failure")]
    InjectedAppend,
}

#[derive(Clone, Debug)]
pub struct OrchestrationEventJournal {
    repository_id: String,
    run_id: String,
    root_parent: Option<String>,
    enabled: bool,
}

impl OrchestrationEventJournal {
    pub fn new(repository_id: impl Into<String>, run_id: impl Into<String>) -> Self {
        Self {
            repository_id: repository_id.into(),
            run_id: run_id.into(),
            root_parent: None,
            enabled: true,
        }
    }

    pub fn with_root_parent(
        repository_id: impl Into<String>,
        run_id: impl Into<String>,
        root_parent: Option<String>,
    ) -> Self {
        Self {
            repository_id: repository_id.into(),
            run_id: run_id.into(),
            root_parent,
            enabled: true,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn create_event(
        &self,
        node: impl Into<String>,
        parent: Option<&str>,
        role: OrchestrationRole,
        kind: OrchestrationEventKind,
        payload: Value,
    ) -> Result<OrchestrationEvent, OrchestrationEventError> {
        self.create_event_at(SystemTime::now(), node, parent, role, kind, payload)
    }

    pub fn append(
        &mut self,
        writer: &mut ArtifactRunWriter,
        node: impl Into<String>,
        parent: Option<&str>,
        role: OrchestrationRole,
        kind: OrchestrationEventKind,
        payload: Value,
    ) -> Result<(), OrchestrationEventError> {
        if !self.enabled {
            return Ok(());
        }
        let result = self
            .create_event(node, parent, role, kind, payload)
            .and_then(|event| {
                run_append_fault()?;
                writer
                    .append_json_line(
                        ORCHESTRATION_EVENT_PATH,
                        &event,
                        ArtifactFileDisposition::PrivateEvidence,
                    )
                    .map(|_| ())
                    .map_err(|error| OrchestrationEventError::ArtifactAppend(format!("{error:#}")))
            });
        if result.is_err() {
            self.enabled = false;
        }
        result
    }

    pub fn append_arbitration_outcome(
        &mut self,
        writer: &mut ArtifactRunWriter,
        parent: Option<&str>,
        role: OrchestrationRole,
        details: ArbitrationOutcomeDetails,
    ) -> Result<(), OrchestrationEventError> {
        if !self.enabled {
            return Ok(());
        }
        details
            .validate()
            .map_err(OrchestrationEventError::InvalidArbitration)?;
        let kind = details.outcome.event_kind();
        let node = details.arbiter_id.clone();
        let payload = match serde_json::to_value(details) {
            Ok(payload) => payload,
            Err(error) => {
                self.enabled = false;
                return Err(OrchestrationEventError::PayloadEncode(error));
            }
        };
        self.append(writer, node, parent, role, kind, payload)
    }

    fn create_event_at(
        &self,
        timestamp: SystemTime,
        node: impl Into<String>,
        parent: Option<&str>,
        role: OrchestrationRole,
        kind: OrchestrationEventKind,
        payload: Value,
    ) -> Result<OrchestrationEvent, OrchestrationEventError> {
        let node = node.into();
        let parent = parent.map(str::to_owned).or_else(|| {
            (role == OrchestrationRole::Supervisor && node == self.run_id)
                .then(|| self.root_parent.clone())
                .flatten()
        });
        Ok(OrchestrationEvent {
            ts: format_rfc3339_utc(timestamp)?,
            repo: self.repository_id.clone(),
            run: self.run_id.clone(),
            node,
            parent,
            role,
            kind,
            payload,
        })
    }
}

pub fn append_external_orchestration_event(
    repo: impl AsRef<Path>,
    run_id: RunId,
    node: &str,
    parent: Option<&str>,
    role: OrchestrationRole,
    kind: OrchestrationEventKind,
    payload: ExternalOrchestrationPayload,
) -> anyhow::Result<OrchestrationEvent> {
    if role == OrchestrationRole::Supervisor {
        bail!("external orchestration events cannot claim the supervisor role");
    }
    if !matches!(
        kind,
        OrchestrationEventKind::Spawn
            | OrchestrationEventKind::Status
            | OrchestrationEventKind::Journal
    ) {
        bail!("external orchestration events support only spawn, status, or journal kinds");
    }
    payload.validate()?;
    let node = normalize_orchestration_node_id(node)?;
    let parent = parent.map(normalize_orchestration_node_id).transpose()?;
    let repo = discover_repo_root(repo.as_ref())?;
    let auth_writer = repository_auth_writer(&repo)?;
    let repository_id = auth_writer.authenticator().binding().repository_id.clone();
    let event = OrchestrationEventJournal::new(&repository_id, run_id.as_str())
        .create_event(
            node,
            parent.as_deref(),
            role,
            kind,
            serde_json::to_value(payload)
                .context("failed to encode external orchestration event payload")?,
        )
        .context("failed to create external orchestration event")?;
    let encoded = encode_event_line(&event)
        .context("failed to encode external orchestration event journal record")?;
    if encoded.len() > MAX_EXTERNAL_EVENT_LINE_BYTES {
        bail!(
            "external orchestration event exceeds its {MAX_EXTERNAL_EVENT_LINE_BYTES}-byte line limit"
        );
    }

    let events_root = SafeRoot::open_or_create_managed(
        repo.join(EXTERNAL_EVENT_RUN_ROOT)
            .join(run_id.as_str())
            .join(EXTERNAL_EVENT_DIRECTORY),
    )
    .context("failed to open the external orchestration event directory")?;
    let lock = KernelStateLock::acquire_direct(&events_root, EXTERNAL_EVENT_LOCK)
        .context("failed to lock the external orchestration event journal")?;
    let mut journal = if events_root.direct_child_exists(EXTERNAL_EVENT_JOURNAL)? {
        BoundedRegularReader::read_direct(
            &events_root,
            EXTERNAL_EVENT_JOURNAL,
            MAX_EXTERNAL_EVENT_JOURNAL_BYTES,
        )
        .context("failed to read the external orchestration event journal")?
    } else {
        Vec::new()
    };
    let record_count = validate_external_event_journal(&journal, &repository_id, run_id.as_str())?;
    if record_count >= MAX_EXTERNAL_EVENT_RECORDS {
        bail!(
            "external orchestration event journal exceeds its {MAX_EXTERNAL_EVENT_RECORDS}-record limit"
        );
    }
    let proposed_bytes = journal
        .len()
        .checked_add(encoded.len())
        .context("external orchestration event journal byte count overflowed")?;
    if u64::try_from(proposed_bytes).unwrap_or(u64::MAX) > MAX_EXTERNAL_EVENT_JOURNAL_BYTES {
        bail!(
            "external orchestration event journal exceeds its {MAX_EXTERNAL_EVENT_JOURNAL_BYTES}-byte limit"
        );
    }
    journal.extend_from_slice(&encoded);
    AtomicStateWriter::scavenge_direct_temps(&events_root, EXTERNAL_EVENT_JOURNAL)?;
    AtomicStateWriter::write_direct_fenced(&events_root, EXTERNAL_EVENT_JOURNAL, &journal, || {
        lock.verify_direct_binding(&events_root)
    })
    .context("failed to commit the external orchestration event journal")?;
    auth_writer.verify()?;
    Ok(event)
}

fn validate_external_event_journal(
    journal: &[u8],
    repository_id: &str,
    run_id: &str,
) -> anyhow::Result<usize> {
    if journal.is_empty() {
        return Ok(0);
    }
    if journal.last() != Some(&b'\n') {
        bail!("external orchestration event journal ends with an incomplete record");
    }

    let mut record_count = 0_usize;
    for line in journal[..journal.len() - 1].split(|byte| *byte == b'\n') {
        if line.is_empty() {
            bail!("external orchestration event journal contains an empty record");
        }
        if line.len() > MAX_EXTERNAL_EVENT_LINE_BYTES {
            bail!(
                "external orchestration event journal line exceeds its {MAX_EXTERNAL_EVENT_LINE_BYTES}-byte limit"
            );
        }
        record_count = record_count
            .checked_add(1)
            .context("external orchestration event record count overflowed")?;
        if record_count > MAX_EXTERNAL_EVENT_RECORDS {
            bail!(
                "external orchestration event journal exceeds its {MAX_EXTERNAL_EVENT_RECORDS}-record limit"
            );
        }
        let raw: Value = serde_json::from_slice(line)
            .context("external orchestration event journal contains invalid JSON")?;
        let object = raw
            .as_object()
            .context("external orchestration event journal record must be an object")?;
        let expected_fields = [
            "ts", "repo", "run", "node", "parent", "role", "kind", "payload",
        ];
        if object.len() != expected_fields.len()
            || expected_fields
                .iter()
                .any(|field| !object.contains_key(*field))
        {
            bail!("external orchestration event journal record has an invalid field set");
        }
        let event: OrchestrationEvent = serde_json::from_value(raw)
            .context("external orchestration event journal record violates the event schema")?;
        if event.repo != repository_id || event.run != run_id {
            bail!(
                "external orchestration event journal record does not match its repository and run binding"
            );
        }
        if !is_canonical_event_timestamp(&event.ts) {
            bail!("external orchestration event journal record has an invalid timestamp");
        }
        if normalize_orchestration_node_id(&event.node)? != event.node {
            bail!("external orchestration event journal node id is not canonical");
        }
        if let Some(parent) = &event.parent {
            if normalize_orchestration_node_id(parent)? != *parent {
                bail!("external orchestration event journal parent id is not canonical");
            }
        }
    }
    Ok(record_count)
}

fn is_canonical_event_timestamp(timestamp: &str) -> bool {
    let bytes = timestamp.as_bytes();
    bytes.len() == 20
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.get(19) == Some(&b'Z')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

pub fn encode_event_line(event: &OrchestrationEvent) -> Result<Vec<u8>, serde_json::Error> {
    let mut line = serde_json::to_vec(event)?;
    line.push(b'\n');
    Ok(line)
}

fn format_rfc3339_utc(timestamp: SystemTime) -> Result<String, OrchestrationEventError> {
    let elapsed = timestamp.duration_since(UNIX_EPOCH)?;
    let total_seconds = elapsed.as_secs();
    let days = i64::try_from(total_seconds / 86_400)
        .map_err(|_| OrchestrationEventError::TimestampOutOfRange)?;
    let seconds_in_day = total_seconds % 86_400;
    let (year, month, day) = civil_date_from_unix_days(days);
    if !(0..=9_999).contains(&year) {
        return Err(OrchestrationEventError::TimestampOutOfRange);
    }

    let hour = seconds_in_day / 3_600;
    let minute = (seconds_in_day % 3_600) / 60;
    let second = seconds_in_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_date_from_unix_days(days: i64) -> (i64, i64, i64) {
    let shifted_days = days + 719_468;
    let era = if shifted_days >= 0 {
        shifted_days
    } else {
        shifted_days - 146_096
    } / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = month_position + if month_position < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
pub(crate) fn set_orchestration_event_append_fault() {
    APPEND_FAULT.with(|fault| fault.set(true));
}

#[cfg(test)]
fn run_append_fault() -> Result<(), OrchestrationEventError> {
    if APPEND_FAULT.with(|fault| fault.replace(false)) {
        return Err(OrchestrationEventError::InjectedAppend);
    }
    Ok(())
}

#[cfg(not(test))]
fn run_append_fault() -> Result<(), OrchestrationEventError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use crate::artifacts::RunArtifactFamily;
    use crate::orchestrator::RunId;
    use git2::{Repository, Signature};
    use serde_json::{json, Value};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn formats_utc_rfc3339_timestamp() {
        assert_eq!(
            format_rfc3339_utc(UNIX_EPOCH).expect("format epoch"),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(951_782_400))
                .expect("format leap day"),
            "2000-02-29T00:00:00Z"
        );
    }

    #[test]
    fn encodes_schema_conforming_json_line() {
        let journal = OrchestrationEventJournal::new("repo-id", "run-1");
        let event = journal
            .create_event_at(
                UNIX_EPOCH,
                "worker-1",
                Some("orchestrator-1"),
                OrchestrationRole::Worker,
                OrchestrationEventKind::Spawn,
                json!({"attempt": 1, "thread_id": "thread-1"}),
            )
            .expect("create event");
        let line = encode_event_line(&event).expect("encode event line");
        assert_eq!(line.last(), Some(&b'\n'));
        let record: Value = serde_json::from_slice(&line).expect("valid JSON record");
        let object = record.as_object().expect("event object");
        assert_eq!(object.len(), 8);
        for field in [
            "ts", "repo", "run", "node", "parent", "role", "kind", "payload",
        ] {
            assert!(object.contains_key(field), "missing {field}");
        }
        assert_eq!(record["ts"], "1970-01-01T00:00:00Z");
        assert_eq!(record["repo"], "repo-id");
        assert_eq!(record["run"], "run-1");
        assert_eq!(record["node"], "worker-1");
        assert_eq!(record["parent"], "orchestrator-1");
        assert_eq!(record["role"], "worker");
        assert_eq!(record["kind"], "spawn");
        assert_eq!(record["payload"]["attempt"], 1);
        assert_eq!(record["payload"]["thread_id"], "thread-1");
    }

    #[test]
    fn escalation_payload_keeps_origin_distinct_from_tree_parent() {
        let journal = OrchestrationEventJournal::new("repo-id", "run-1");
        let event = journal
            .create_event_at(
                UNIX_EPOCH,
                "peer-task",
                Some("run-1"),
                OrchestrationRole::Supervisor,
                OrchestrationEventKind::Escalate,
                json!({"origin": "worker-7", "reason": "cross-cutting follow-up"}),
            )
            .expect("create escalation event");
        assert_eq!(event.parent.as_deref(), Some("run-1"));
        assert_eq!(event.payload["origin"], "worker-7");
        assert_ne!(event.payload["origin"], event.parent.unwrap());
    }

    #[test]
    fn arbitration_outcomes_append_exact_typed_events() {
        let (_temp, repo_path) = committed_repo();
        let mut writer = ArtifactRunWriter::reserve(
            &repo_path,
            RunArtifactFamily::Supervise,
            RunId::new("arbitration-outcomes").expect("run id"),
            "supervise",
        )
        .expect("reserve artifact writer");
        let mut journal = OrchestrationEventJournal::new("repo-id", "run-1");

        for (outcome, expected_kind, candidate_status) in [
            (
                ArbitrationOutcome::Accepted,
                OrchestrationEventKind::Accept,
                ValidationStatus::Passed,
            ),
            (
                ArbitrationOutcome::Rejected,
                OrchestrationEventKind::Reject,
                ValidationStatus::Failed,
            ),
            (
                ArbitrationOutcome::Escalated,
                OrchestrationEventKind::Escalate,
                ValidationStatus::NotRun,
            ),
        ] {
            journal
                .append_arbitration_outcome(
                    &mut writer,
                    Some("merge-controller"),
                    OrchestrationRole::Worker,
                    arbitration_details(outcome, candidate_status),
                )
                .expect("append arbitration outcome");
            assert_eq!(outcome.event_kind(), expected_kind);
        }

        let records = read_event_records(&writer);
        assert_eq!(records.len(), 3);
        for (index, (expected_outcome, expected_kind, expected_status)) in [
            ("accepted", "accept", "passed"),
            ("rejected", "reject", "failed"),
            ("escalated", "escalate", "not_run"),
        ]
        .into_iter()
        .enumerate()
        {
            let record = &records[index];
            let expected_binding = if expected_status == "not_run" {
                Value::Null
            } else {
                json!({
                    "version": 1,
                    "agent_id": "neutral-arbiter",
                    "primary_head": null,
                    "agent_head": null,
                    "merge_base": null,
                    "diff_oid": "1111111111111111111111111111111111111111"
                })
            };
            assert_eq!(record["node"], "neutral-arbiter");
            assert_eq!(record["parent"], "merge-controller");
            assert_eq!(record["role"], "worker");
            assert_eq!(record["kind"], expected_kind);
            assert_eq!(
                record["payload"],
                json!({
                    "outcome": expected_outcome,
                    "arbiter_id": "neutral-arbiter",
                    "sides": [
                        {"kind": "agent", "id": "agent-a"},
                        {"kind": "primary"}
                    ],
                    "candidate_binding": expected_binding,
                    "candidate_status": expected_status,
                    "rationale_report": "reports/arbitration.json",
                    "rationale_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
                    "reason": "collision arbitration completed"
                })
            );
        }
    }

    #[test]
    fn arbitration_append_failure_disables_the_journal_without_writing() {
        let (_temp, repo_path) = committed_repo();
        let mut writer = ArtifactRunWriter::reserve(
            &repo_path,
            RunArtifactFamily::Supervise,
            RunId::new("arbitration-append-failure").expect("run id"),
            "supervise",
        )
        .expect("reserve artifact writer");
        let mut journal = OrchestrationEventJournal::new("repo-id", "run-1");
        set_orchestration_event_append_fault();

        let error = journal
            .append_arbitration_outcome(
                &mut writer,
                Some("merge-controller"),
                OrchestrationRole::Worker,
                arbitration_details(ArbitrationOutcome::Accepted, ValidationStatus::Passed),
            )
            .expect_err("injected append failure");
        assert!(matches!(error, OrchestrationEventError::InjectedAppend));
        assert!(!journal.is_enabled());
        assert!(!writer.run_dir().join(ORCHESTRATION_EVENT_PATH).exists());

        journal
            .append_arbitration_outcome(
                &mut writer,
                Some("merge-controller"),
                OrchestrationRole::Worker,
                arbitration_details(ArbitrationOutcome::Rejected, ValidationStatus::Failed),
            )
            .expect("disabled journal is a no-op");
        assert!(!writer.run_dir().join(ORCHESTRATION_EVENT_PATH).exists());
    }

    #[test]
    fn arbitration_outcome_invariants_fail_before_append_without_disabling_journal() {
        let (_temp, repo_path) = committed_repo();
        let mut writer = ArtifactRunWriter::reserve(
            &repo_path,
            RunArtifactFamily::Supervise,
            RunId::new("arbitration-invariants").expect("run id"),
            "supervise",
        )
        .expect("reserve artifact writer");
        let mut journal = OrchestrationEventJournal::new("repo-id", "run-1");
        let mut invalid =
            arbitration_details(ArbitrationOutcome::Accepted, ValidationStatus::Passed);
        invalid.sides[1] = invalid.sides[0].clone();

        let error = journal
            .append_arbitration_outcome(
                &mut writer,
                Some("merge-controller"),
                OrchestrationRole::Worker,
                invalid,
            )
            .expect_err("duplicate sides must fail");

        assert!(matches!(
            error,
            OrchestrationEventError::InvalidArbitration(_)
        ));
        assert!(journal.is_enabled());
        assert!(!writer.run_dir().join(ORCHESTRATION_EVENT_PATH).exists());

        let mut invalid =
            arbitration_details(ArbitrationOutcome::Accepted, ValidationStatus::Passed);
        invalid.candidate_status = ValidationStatus::Failed;
        assert!(invalid.validate().is_err());

        let mut invalid =
            arbitration_details(ArbitrationOutcome::Rejected, ValidationStatus::Failed);
        invalid
            .candidate_binding
            .as_mut()
            .expect("binding")
            .agent_id = "different-arbiter".to_string();
        assert!(invalid.validate().is_err());

        let mut invalid =
            arbitration_details(ArbitrationOutcome::Accepted, ValidationStatus::Passed);
        invalid.rationale_sha256 = Some("not-a-sha256".to_string());
        assert!(invalid.validate().is_err());

        let mut invalid =
            arbitration_details(ArbitrationOutcome::Accepted, ValidationStatus::Passed);
        invalid.rationale_report = Some("/tmp/arbitration.json".to_string());
        assert!(invalid.validate().is_err());

        let mut invalid =
            arbitration_details(ArbitrationOutcome::Escalated, ValidationStatus::NotRun);
        invalid.candidate_binding = Some(CandidateValidationBinding {
            version: 1,
            agent_id: "neutral-arbiter".to_string(),
            primary_head: None,
            agent_head: None,
            merge_base: None,
            diff_oid: "1111111111111111111111111111111111111111".to_string(),
        });
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn every_supported_role_and_kind_uses_the_normalized_name() {
        let roles = [
            (OrchestrationRole::Root, "root"),
            (OrchestrationRole::Supervisor, "supervisor"),
            (OrchestrationRole::Orchestrator, "orchestrator"),
            (OrchestrationRole::Worker, "worker"),
            (OrchestrationRole::Auditor, "auditor"),
        ];
        for (role, expected) in roles {
            assert_eq!(
                serde_json::to_value(role).expect("serialize role"),
                expected
            );
            assert_eq!(
                serde_json::from_value::<OrchestrationRole>(json!(expected))
                    .expect("deserialize role"),
                role
            );
        }

        let kinds = [
            (OrchestrationEventKind::Spawn, "spawn"),
            (OrchestrationEventKind::Status, "status"),
            (OrchestrationEventKind::Journal, "journal"),
            (OrchestrationEventKind::Accept, "accept"),
            (OrchestrationEventKind::Reject, "reject"),
            (OrchestrationEventKind::Escalate, "escalate"),
            (OrchestrationEventKind::Gate, "gate"),
            (OrchestrationEventKind::Claim, "claim"),
        ];
        for (kind, expected) in kinds {
            assert_eq!(
                serde_json::to_value(kind).expect("serialize event kind"),
                expected
            );
            assert_eq!(
                serde_json::from_value::<OrchestrationEventKind>(json!(expected))
                    .expect("deserialize event kind"),
                kind
            );
        }

        let field_guide_kinds = [
            (FieldGuideEventKind::AppendMutation, "append_mutation"),
            (
                FieldGuideEventKind::DeterministicCuration,
                "deterministic_curation",
            ),
            (
                FieldGuideEventKind::PromptInjectionEvidence,
                "prompt_injection_evidence",
            ),
        ];
        for (kind, expected) in field_guide_kinds {
            assert_eq!(
                serde_json::to_value(kind).expect("serialize field-guide event kind"),
                expected
            );
            assert_eq!(
                serde_json::from_value::<FieldGuideEventKind>(json!(expected))
                    .expect("deserialize field-guide event kind"),
                kind
            );
        }
    }

    #[test]
    fn old_and_root_event_wire_records_round_trip() {
        let old_record = json!({
            "ts": "2026-08-11T01:02:03Z",
            "repo": "repo-id",
            "run": "old-run",
            "node": "old-run",
            "parent": null,
            "role": "supervisor",
            "kind": "status",
            "payload": {"status": "running"}
        });
        let old_event: OrchestrationEvent =
            serde_json::from_value(old_record.clone()).expect("deserialize old event");
        assert_eq!(old_event.role, OrchestrationRole::Supervisor);
        assert_eq!(
            serde_json::to_value(old_event).expect("serialize old event"),
            old_record
        );

        let root_record = json!({
            "ts": "2026-08-11T01:02:04Z",
            "repo": "repo-id",
            "run": "driver-run",
            "node": "driver-root",
            "parent": null,
            "role": "root",
            "kind": "spawn",
            "payload": {"runtime": "claude-code"}
        });
        let root_event: OrchestrationEvent =
            serde_json::from_value(root_record.clone()).expect("deserialize root event");
        assert_eq!(root_event.role, OrchestrationRole::Root);
        assert_eq!(
            serde_json::to_value(root_event).expect("serialize root event"),
            root_record
        );
    }

    #[test]
    fn legacy_closed_role_reader_rejects_the_new_root_variant() {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum LegacyRole {
            Supervisor,
            Orchestrator,
            Worker,
            Auditor,
        }

        assert!(serde_json::from_value::<LegacyRole>(json!("root")).is_err());
        assert!(serde_json::from_value::<LegacyRole>(json!("supervisor")).is_ok());
    }

    #[test]
    fn configured_root_parent_is_applied_only_to_the_root_supervisor_node() {
        let journal = OrchestrationEventJournal::with_root_parent(
            "repo-id",
            "supervise-run",
            Some("driver-root".to_string()),
        );
        let root = journal
            .create_event_at(
                UNIX_EPOCH,
                "supervise-run",
                None,
                OrchestrationRole::Supervisor,
                OrchestrationEventKind::Status,
                json!({"status": "running"}),
            )
            .expect("create root supervisor event");
        let peer = journal
            .create_event_at(
                UNIX_EPOCH,
                "peer-supervisor",
                None,
                OrchestrationRole::Supervisor,
                OrchestrationEventKind::Status,
                json!({"status": "running"}),
            )
            .expect("create peer supervisor event");

        assert_eq!(root.parent.as_deref(), Some("driver-root"));
        assert!(peer.parent.is_none());
    }

    #[test]
    fn external_payload_schema_rejects_prompt_content_and_unknown_fields() {
        let error = serde_json::from_value::<ExternalOrchestrationPayload>(json!({
            "runtime": "codex",
            "prompt": "private task contents"
        }))
        .expect_err("prompt field must be rejected");
        assert!(error.to_string().contains("unknown field"));
        assert!(ExternalOrchestrationPayload {
            runtime: ExternalAgentRuntime::Human,
            status: Some("running".to_string()),
        }
        .validate()
        .is_ok());
        assert!(ExternalOrchestrationPayload {
            runtime: ExternalAgentRuntime::Other,
            status: Some("not safe to disclose".to_string()),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn external_events_append_to_one_validated_atomic_journal() {
        let (_temp, repo_path) = committed_repo();
        let run_id = RunId::new("driver-session").expect("run id");
        let root = append_external_orchestration_event(
            &repo_path,
            run_id.clone(),
            "driver-root",
            None,
            OrchestrationRole::Root,
            OrchestrationEventKind::Spawn,
            ExternalOrchestrationPayload {
                runtime: ExternalAgentRuntime::ClaudeCode,
                status: Some("running".to_string()),
            },
        )
        .expect("append root event");
        let child = append_external_orchestration_event(
            &repo_path,
            run_id,
            "direct-worker",
            Some("driver-root"),
            OrchestrationRole::Worker,
            OrchestrationEventKind::Status,
            ExternalOrchestrationPayload {
                runtime: ExternalAgentRuntime::Codex,
                status: Some("completed".to_string()),
            },
        )
        .expect("append child event");

        assert_eq!(root.role, OrchestrationRole::Root);
        assert_eq!(child.parent.as_deref(), Some("driver-root"));
        let journal_path = repo_path
            .join(EXTERNAL_EVENT_RUN_ROOT)
            .join("driver-session")
            .join(EXTERNAL_EVENT_DIRECTORY)
            .join(EXTERNAL_EVENT_JOURNAL);
        let records = fs::read_to_string(journal_path)
            .expect("read external journal")
            .lines()
            .map(|line| serde_json::from_str::<OrchestrationEvent>(line).expect("event record"))
            .collect::<Vec<_>>();
        assert_eq!(records, vec![root, child]);
    }

    #[test]
    fn external_append_refuses_a_corrupt_existing_stream_without_replacing_it() {
        let (_temp, repo_path) = committed_repo();
        let run_id = RunId::new("corrupt-driver-session").expect("run id");
        append_external_orchestration_event(
            &repo_path,
            run_id.clone(),
            "driver-root",
            None,
            OrchestrationRole::Root,
            OrchestrationEventKind::Spawn,
            ExternalOrchestrationPayload {
                runtime: ExternalAgentRuntime::Human,
                status: None,
            },
        )
        .expect("append initial event");
        let journal_path = repo_path
            .join(EXTERNAL_EVENT_RUN_ROOT)
            .join(run_id.as_str())
            .join(EXTERNAL_EVENT_DIRECTORY)
            .join(EXTERNAL_EVENT_JOURNAL);
        fs::write(&journal_path, b"{not-json}\n").expect("inject corrupt journal");

        let error = append_external_orchestration_event(
            &repo_path,
            run_id,
            "direct-worker",
            Some("driver-root"),
            OrchestrationRole::Worker,
            OrchestrationEventKind::Status,
            ExternalOrchestrationPayload {
                runtime: ExternalAgentRuntime::Codex,
                status: Some("running".to_string()),
            },
        )
        .expect_err("corrupt journal must fail closed");
        assert!(error.to_string().contains("invalid JSON"));
        assert_eq!(
            fs::read(journal_path).expect("read corrupt journal"),
            b"{not-json}\n"
        );
    }

    #[test]
    fn field_guide_journal_example_uses_only_redacted_metadata() {
        let journal = OrchestrationEventJournal::new("repo-id", "run-1");
        let field_guide_kinds = [
            FieldGuideEventKind::AppendMutation,
            FieldGuideEventKind::DeterministicCuration,
            FieldGuideEventKind::PromptInjectionEvidence,
        ];

        for field_guide_kind in field_guide_kinds {
            let event = journal
                .create_event_at(
                    UNIX_EPOCH,
                    "orchestrator-1",
                    Some("run-1"),
                    OrchestrationRole::Orchestrator,
                    OrchestrationEventKind::Journal,
                    json!({
                        "field_guide_event_kind": field_guide_kind,
                        "entry_count": 2,
                        "line_count": 4,
                        "rendered_bytes": 128,
                    }),
                )
                .expect("create redacted field-guide event");

            let payload = event.payload.as_object().expect("metadata object");
            assert_eq!(event.kind, OrchestrationEventKind::Journal);
            assert!(payload.contains_key("field_guide_event_kind"));
            assert!(payload.keys().all(|key| matches!(
                key.as_str(),
                "field_guide_event_kind" | "entry_count" | "line_count" | "rendered_bytes"
            )));
            for forbidden in ["finding", "context", "secret", "path", "local_path"] {
                assert!(
                    !payload.contains_key(forbidden),
                    "field-guide journal payload leaked forbidden field {forbidden}"
                );
            }
        }
    }

    fn arbitration_details(
        outcome: ArbitrationOutcome,
        candidate_status: ValidationStatus,
    ) -> ArbitrationOutcomeDetails {
        let candidate_binding =
            (candidate_status != ValidationStatus::NotRun).then(|| CandidateValidationBinding {
                version: 1,
                agent_id: "neutral-arbiter".to_string(),
                primary_head: None,
                agent_head: None,
                merge_base: None,
                diff_oid: "1111111111111111111111111111111111111111".to_string(),
            });
        ArbitrationOutcomeDetails {
            outcome,
            arbiter_id: "neutral-arbiter".to_string(),
            sides: [
                ArbitrationSide::Agent {
                    id: "agent-a".to_string(),
                },
                ArbitrationSide::Primary,
            ],
            candidate_binding,
            candidate_status,
            rationale_report: Some("reports/arbitration.json".to_string()),
            rationale_sha256: Some(
                "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            ),
            reason: "collision arbitration completed".to_string(),
        }
    }

    fn read_event_records(writer: &ArtifactRunWriter) -> Vec<Value> {
        fs::read(writer.run_dir().join(ORCHESTRATION_EVENT_PATH))
            .expect("read event journal")
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("valid event record"))
            .collect()
    }

    fn committed_repo() -> (TempDir, PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("initialize repository");
        fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
        let repo = crate::git_repository::open(&repo_path).expect("open repository");
        let mut index = repo.index().expect("open index");
        index
            .add_path(Path::new("README.md"))
            .expect("stage README");
        index.write().expect("write index");
        let tree_id = index.write_tree().expect("write tree");
        let tree = repo.find_tree(tree_id).expect("find tree");
        let signature =
            Signature::now("maco test", "maco-test@example.invalid").expect("signature");
        repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
            .expect("commit repository");
        drop(tree);
        drop(repo);
        (temp, repo_path)
    }
}
