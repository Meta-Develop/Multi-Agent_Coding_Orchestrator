use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const ORCHESTRATION_EVENT_PATH: &str = "events/orchestration.jsonl";

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
    #[error("failed to create orchestration event directory {path}: {source}")]
    CreateDirectory { path: PathBuf, source: io::Error },
    #[error("failed to serialize orchestration event: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to open orchestration event journal {path}: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error("failed to append orchestration event journal {path}: {source}")]
    Append { path: PathBuf, source: io::Error },
}

#[derive(Clone, Debug)]
pub struct OrchestrationEventJournal {
    directory: PathBuf,
    path: PathBuf,
    repository_id: String,
    run_id: String,
}

impl OrchestrationEventJournal {
    pub fn new(
        run_dir: impl AsRef<Path>,
        repository_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        let run_dir = run_dir.as_ref();
        let directory = run_dir.join("events");
        Self {
            path: run_dir.join(ORCHESTRATION_EVENT_PATH),
            directory,
            repository_id: repository_id.into(),
            run_id: run_id.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
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
        &self,
        node: impl Into<String>,
        parent: Option<&str>,
        role: OrchestrationRole,
        kind: OrchestrationEventKind,
        payload: Value,
    ) -> Result<(), OrchestrationEventError> {
        let event = self.create_event(node, parent, role, kind, payload)?;
        let line = encode_event_line(&event)?;
        self.append_line(&line)
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

    fn append_line(&self, line: &[u8]) -> Result<(), OrchestrationEventError> {
        fs::create_dir_all(&self.directory).map_err(|source| {
            OrchestrationEventError::CreateDirectory {
                path: self.directory.clone(),
                source,
            }
        })?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|source| OrchestrationEventError::Open {
                path: self.path.clone(),
                source,
            })?;
        file.write_all(line)
            .map_err(|source| OrchestrationEventError::Append {
                path: self.path.clone(),
                source,
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
mod tests {
    use std::{fs, time::Duration};

    use serde_json::{json, Value};
    use tempfile::tempdir;

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
    fn writer_appends_schema_conforming_json_lines() {
        let temp = tempdir().expect("temporary directory");
        let run_dir = temp.path().join("run-1");
        let journal = OrchestrationEventJournal::new(&run_dir, "repo-id", "run-1");

        journal
            .append(
                "worker-1",
                Some("orchestrator-1"),
                OrchestrationRole::Worker,
                OrchestrationEventKind::Spawn,
                json!({"attempt": 1, "thread_id": "thread-1"}),
            )
            .expect("append spawn event");
        journal
            .append(
                "worker-1",
                None,
                OrchestrationRole::Auditor,
                OrchestrationEventKind::Accept,
                json!({"accepted": true}),
            )
            .expect("append accept event");

        assert_eq!(
            journal.path(),
            run_dir.join(ORCHESTRATION_EVENT_PATH).as_path()
        );
        let contents = fs::read_to_string(journal.path()).expect("read event journal");
        let records = contents
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("valid JSON record"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["repo"], "repo-id");
        assert_eq!(records[0]["run"], "run-1");
        assert_eq!(records[0]["node"], "worker-1");
        assert_eq!(records[0]["parent"], "orchestrator-1");
        assert_eq!(records[0]["role"], "worker");
        assert_eq!(records[0]["kind"], "spawn");
        assert_eq!(records[0]["payload"]["attempt"], 1);
        assert_eq!(records[0]["payload"]["thread_id"], "thread-1");
        assert_eq!(records[1]["parent"], Value::Null);
        assert_eq!(records[1]["role"], "auditor");
        assert_eq!(records[1]["kind"], "accept");
        for record in records {
            let object = record.as_object().expect("event object");
            assert_eq!(object.len(), 8);
            for field in [
                "ts", "repo", "run", "node", "parent", "role", "kind", "payload",
            ] {
                assert!(object.contains_key(field), "missing {field}");
            }
            let timestamp = object["ts"].as_str().expect("timestamp string");
            assert_eq!(timestamp.len(), 20);
            assert!(timestamp.ends_with('Z'));
        }
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
        ];
        for (kind, expected) in kinds {
            assert_eq!(
                serde_json::to_value(kind).expect("serialize event kind"),
                expected
            );
        }
    }
}
