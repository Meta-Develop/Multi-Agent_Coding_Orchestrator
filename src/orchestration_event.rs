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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationCandidateStatus {
    NotRun,
    Passed,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArbitrationCandidateBinding {
    pub version: u32,
    pub agent_id: String,
    pub primary_head: Option<String>,
    pub agent_head: Option<String>,
    pub merge_base: Option<String>,
    pub diff_oid: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArbitrationOutcomeDetails {
    pub outcome: ArbitrationOutcome,
    pub arbiter_id: String,
    pub sides: [ArbitrationSide; 2],
    pub candidate_binding: Option<ArbitrationCandidateBinding>,
    pub candidate_status: ArbitrationCandidateStatus,
    pub rationale_report: Option<String>,
    pub rationale_sha256: Option<String>,
    pub reason: String,
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
                ArbitrationCandidateStatus::Passed,
            ),
            (
                ArbitrationOutcome::Rejected,
                OrchestrationEventKind::Reject,
                ArbitrationCandidateStatus::Failed,
            ),
            (
                ArbitrationOutcome::Escalated,
                OrchestrationEventKind::Escalate,
                ArbitrationCandidateStatus::NotRun,
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
                    "candidate_binding": {
                        "version": 1,
                        "agent_id": "neutral-arbiter",
                        "primary_head": null,
                        "agent_head": null,
                        "merge_base": null,
                        "diff_oid": "candidate-diff"
                    },
                    "candidate_status": expected_status,
                    "rationale_report": "reports/arbitration.json",
                    "rationale_sha256": "rationale-digest",
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
                arbitration_details(
                    ArbitrationOutcome::Accepted,
                    ArbitrationCandidateStatus::Passed,
                ),
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
                arbitration_details(
                    ArbitrationOutcome::Rejected,
                    ArbitrationCandidateStatus::Failed,
                ),
            )
            .expect("disabled journal is a no-op");
        assert!(!writer.run_dir().join(ORCHESTRATION_EVENT_PATH).exists());
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
        }
    }

    fn arbitration_details(
        outcome: ArbitrationOutcome,
        candidate_status: ArbitrationCandidateStatus,
    ) -> ArbitrationOutcomeDetails {
        ArbitrationOutcomeDetails {
            outcome,
            arbiter_id: "neutral-arbiter".to_string(),
            sides: [
                ArbitrationSide::Agent {
                    id: "agent-a".to_string(),
                },
                ArbitrationSide::Primary,
            ],
            candidate_binding: Some(ArbitrationCandidateBinding {
                version: 1,
                agent_id: "neutral-arbiter".to_string(),
                primary_head: None,
                agent_head: None,
                merge_base: None,
                diff_oid: "candidate-diff".to_string(),
            }),
            candidate_status,
            rationale_report: Some("reports/arbitration.json".to_string()),
            rationale_sha256: Some("rationale-digest".to_string()),
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
        let repo = Repository::open(&repo_path).expect("open repository");
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
