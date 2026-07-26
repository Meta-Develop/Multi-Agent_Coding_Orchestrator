use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};

use crate::artifacts::{ArtifactFileDisposition, ArtifactRunWriter};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const ORCHESTRATION_EVENT_PATH: &str = "events/orchestration.jsonl";

#[cfg(test)]
thread_local! {
    static APPEND_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrchestrationRole {
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
    enabled: bool,
}

impl OrchestrationEventJournal {
    pub fn new(repository_id: impl Into<String>, run_id: impl Into<String>) -> Self {
        Self {
            repository_id: repository_id.into(),
            run_id: run_id.into(),
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

    fn create_event_at(
        &self,
        timestamp: SystemTime,
        node: impl Into<String>,
        parent: Option<&str>,
        role: OrchestrationRole,
        kind: OrchestrationEventKind,
        payload: Value,
    ) -> Result<OrchestrationEvent, OrchestrationEventError> {
        Ok(OrchestrationEvent {
            ts: format_rfc3339_utc(timestamp)?,
            repo: self.repository_id.clone(),
            run: self.run_id.clone(),
            node: node.into(),
            parent: parent.map(str::to_owned),
            role,
            kind,
            payload,
        })
    }
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
    use std::time::Duration;

    use serde_json::{json, Value};

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
    fn every_supported_role_and_kind_uses_the_normalized_name() {
        let roles = [
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
}
