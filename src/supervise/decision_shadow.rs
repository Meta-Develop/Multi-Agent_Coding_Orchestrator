//! Shadow-mode decision provider consultation (#970, second slice).
//!
//! Shadow mode consults the operator-configured decision-model provider only
//! when the operator sets `MACO_DECISION_PROVIDER_CONFIG`, records what the
//! provider would have chosen as run evidence, and never changes the binding:
//! the deterministic choice stays binding until calibration (#971).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::decision_provider::{consult_decision_provider, DecisionProviderConfig};
use crate::selection::decision_proposal::{decision_question, DecisionAdoption, DecisionQuestion};
use crate::selection::DecisionStatus;
use crate::supervise::{AgentRole, SupervisorSelectionEvent, SupervisorSelectionEventCause};

pub(super) const DECISION_PROVIDER_CONFIG_ENV: &str = "MACO_DECISION_PROVIDER_CONFIG";
pub(super) const DECISION_PROPOSAL_DIR: &str = "decision-proposals";
const MAX_DECISION_PROVIDER_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ShadowDecisionRecord {
    pub version: u32,
    pub mode: String,
    pub applied_to_binding: bool,
    pub role: AgentRole,
    pub assignment_id: Option<String>,
    pub attempt: usize,
    pub endpoint: String,
    pub question: DecisionQuestion,
    pub adoption: DecisionAdoption,
}

pub(super) fn load_decision_provider_config(
    value: Option<&OsStr>,
) -> Result<Option<DecisionProviderConfig>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let path = Path::new(value);
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(anyhow!(
            "MACO_DECISION_PROVIDER_CONFIG must be an absolute path"
        ));
    }
    let metadata = std::fs::metadata(path).with_context(|| {
        format!(
            "failed to stat MACO_DECISION_PROVIDER_CONFIG path {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "MACO_DECISION_PROVIDER_CONFIG must be a regular file: {}",
            path.display()
        ));
    }
    if metadata.len() > MAX_DECISION_PROVIDER_CONFIG_BYTES {
        return Err(anyhow!(
            "MACO_DECISION_PROVIDER_CONFIG file {} is larger than {} bytes",
            path.display(),
            MAX_DECISION_PROVIDER_CONFIG_BYTES
        ));
    }
    let contents = std::fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read MACO_DECISION_PROVIDER_CONFIG file {}",
            path.display()
        )
    })?;
    let config = serde_json::from_str(&contents).with_context(|| {
        format!(
            "failed to parse MACO_DECISION_PROVIDER_CONFIG file {}",
            path.display()
        )
    })?;
    Ok(Some(config))
}

pub(super) fn decision_provider_from_env() -> Result<Option<DecisionProviderConfig>> {
    load_decision_provider_config(std::env::var_os(DECISION_PROVIDER_CONFIG_ENV).as_deref())
}

pub(super) fn shadow_decision_records(
    config: &DecisionProviderConfig,
    task_text: &str,
    events: &[SupervisorSelectionEvent],
) -> Vec<ShadowDecisionRecord> {
    events
        .iter()
        .filter(|event| {
            event.role == AgentRole::Worker
                && event.primary_cause == SupervisorSelectionEventCause::Initial
                && event.provenance.status == DecisionStatus::Selected
        })
        .map(|event| ShadowDecisionRecord {
            version: 1,
            mode: "shadow".to_string(),
            applied_to_binding: false,
            role: event.role,
            assignment_id: event.assignment_id.clone(),
            attempt: event.attempt,
            endpoint: config.endpoint.clone(),
            question: decision_question(task_text, &event.provenance),
            adoption: consult_decision_provider(
                config,
                &decision_question(task_text, &event.provenance),
            ),
        })
        .collect()
}

pub(super) fn shadow_record_path(record: &ShadowDecisionRecord) -> PathBuf {
    let assignment = record.assignment_id.as_deref().unwrap_or("initial");
    Path::new(DECISION_PROPOSAL_DIR).join(format!(
        "{}.{}.attempt-{}.json",
        record.role.as_str(),
        assignment,
        record.attempt
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::SelectionProvenance;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    use crate::selection::decision_proposal::DecisionAdoptionOutcome;

    fn provenance() -> SelectionProvenance {
        let mut provenance =
            crate::selection::select(&crate::selection::selection_test_base_input())
                .expect("base input selects");
        let template = provenance
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.eligible)
            .expect("an eligible candidate")
            .clone();
        let mut first = template.clone();
        first.candidate.model = "model-a".to_string();
        let mut second = template.clone();
        second.candidate.model = "model-b".to_string();
        provenance.candidate_set = vec![first, second];
        if let Some(choice) = provenance.choice.as_mut() {
            choice.candidate = provenance.candidate_set[0].candidate.clone();
        }
        provenance
    }

    fn event(
        role: AgentRole,
        cause: SupervisorSelectionEventCause,
        provenance: SelectionProvenance,
    ) -> SupervisorSelectionEvent {
        SupervisorSelectionEvent {
            assignment_id: None,
            attempt: 0,
            role,
            primary_cause: cause,
            provenance,
        }
    }

    fn config(endpoint: String) -> DecisionProviderConfig {
        DecisionProviderConfig {
            endpoint,
            model: "decider-v1".to_string(),
            threshold_basis_points: 6000,
            timeout_ms: 5000,
            max_task_text_chars: None,
        }
    }

    fn fake_endpoint(response: &str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let address = listener.local_addr().expect("local address");
        let response = response.to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept one connection");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut captured = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        captured.extend_from_slice(&buffer[..count]);
                        let Some(end) = find_subslice(&captured, b"\r\n\r\n") else {
                            continue;
                        };
                        let headers = String::from_utf8_lossy(&captured[..end]).to_lowercase();
                        let complete = headers
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .is_some_and(|length| captured.len() >= end + 4 + length);
                        if complete {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            stream
                .write_all(response.as_bytes())
                .expect("write fake response");
        });
        (format!("http://127.0.0.1:{}", address.port()), handle)
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn config_loading_is_disabled_by_default_and_strict() {
        assert_eq!(
            load_decision_provider_config(None).expect("none loads"),
            None
        );
        let relative = std::ffi::OsStr::new("relative/config.json");
        let error = load_decision_provider_config(Some(relative))
            .expect_err("relative path rejected")
            .to_string();
        assert!(error.contains("must be an absolute path"), "{error}");
        let error = load_decision_provider_config(Some(std::ffi::OsStr::new("")))
            .expect_err("empty value rejected")
            .to_string();
        assert!(error.contains("must be an absolute path"), "{error}");
        let missing = std::ffi::OsStr::new("/nonexistent/decision-provider.json");
        assert!(load_decision_provider_config(Some(missing)).is_err());
        let directory = tempfile::tempdir().expect("tempdir");
        assert!(load_decision_provider_config(Some(directory.path().as_os_str())).is_err());
        let file = directory.path().join("config.json");
        let unknown = r#"{"endpoint":"http://127.0.0.1:1","model":"m","threshold_basis_points":100,"timeout_ms":1000,"unknown":true}"#;
        std::fs::write(&file, unknown).expect("write unknown-field config");
        assert!(load_decision_provider_config(Some(file.as_os_str())).is_err());
        let expected = DecisionProviderConfig {
            endpoint: "http://127.0.0.1:1".to_string(),
            model: "m".to_string(),
            threshold_basis_points: 100,
            timeout_ms: 1000,
            max_task_text_chars: None,
        };
        let valid = serde_json::to_string(&expected).expect("serialize config");
        std::fs::write(&file, valid).expect("write valid config");
        assert_eq!(
            load_decision_provider_config(Some(file.as_os_str())).expect("valid config loads"),
            Some(expected)
        );
    }

    #[test]
    fn shadow_records_cover_only_initial_automatic_worker_decisions() {
        let selected = provenance();
        let mut fail_closed = provenance();
        fail_closed.status = DecisionStatus::FailClosed;
        let events = vec![
            event(
                AgentRole::Worker,
                SupervisorSelectionEventCause::Initial,
                selected.clone(),
            ),
            event(
                AgentRole::Worker,
                SupervisorSelectionEventCause::DebugOverride,
                selected.clone(),
            ),
            event(
                AgentRole::Auditor,
                SupervisorSelectionEventCause::Initial,
                selected.clone(),
            ),
            event(
                AgentRole::Worker,
                SupervisorSelectionEventCause::Initial,
                fail_closed,
            ),
        ];
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("local address").port();
        drop(listener);
        let records = shadow_decision_records(
            &config(format!("http://127.0.0.1:{port}")),
            "sample task",
            &events,
        );
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.version, 1);
        assert_eq!(record.mode, "shadow");
        assert!(!record.applied_to_binding);
        assert_eq!(record.role, AgentRole::Worker);
        assert_eq!(
            record.adoption.outcome,
            DecisionAdoptionOutcome::ProviderError
        );
        assert_eq!(
            record.adoption.final_choice,
            selected.choice.clone().map(|c| c.candidate)
        );
        assert_eq!(events[0].provenance, selected);
    }

    #[test]
    fn shadow_record_carries_the_provider_proposal_without_binding_it() {
        let selected = provenance();
        let deterministic = selected.choice.clone().map(|c| c.candidate);
        let body = r#"{"model":"decider-v1","answers":{"binding":{"type":"choice","choice":"option-2","confidence":0.6,"probabilities":{"option-1":0.2,"option-2":0.8}}}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (endpoint, handle) = fake_endpoint(&response);
        let records = shadow_decision_records(
            &config(endpoint),
            "sample task",
            &[event(
                AgentRole::Worker,
                SupervisorSelectionEventCause::Initial,
                selected.clone(),
            )],
        );
        handle.join().expect("join fake endpoint");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.adoption.outcome, DecisionAdoptionOutcome::Adopted);
        assert_eq!(
            record.adoption.final_choice,
            Some(record.question.options[1].candidate.clone())
        );
        assert_ne!(record.adoption.final_choice, deterministic);
        assert!(!record.applied_to_binding);
        assert_eq!(selected.choice.clone().map(|c| c.candidate), deterministic);
    }

    #[test]
    fn shadow_record_path_and_round_trip() {
        let selected = provenance();
        let (endpoint, handle) =
            fake_endpoint("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let records = shadow_decision_records(
            &config(endpoint),
            "sample task",
            &[event(
                AgentRole::Worker,
                SupervisorSelectionEventCause::Initial,
                selected,
            )],
        );
        handle.join().expect("join fake endpoint");
        let record = &records[0];
        let path = shadow_record_path(record);
        assert_eq!(
            path,
            Path::new(DECISION_PROPOSAL_DIR).join(format!(
                "{}.initial.attempt-0.json",
                AgentRole::Worker.as_str()
            ))
        );
        let json = serde_json::to_string(record).expect("serialize record");
        let round_trip: ShadowDecisionRecord =
            serde_json::from_str(&json).expect("round trip record");
        assert_eq!(round_trip, *record);
        let mut value = serde_json::to_value(record).expect("record value");
        let object = value.as_object_mut().expect("record object");
        object.insert("unknown".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<ShadowDecisionRecord>(value).is_err());
    }
}
