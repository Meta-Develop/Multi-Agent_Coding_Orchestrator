//! Process-boundary nested-worker usage observation.
//!
//! Nested terminal workers are launched by an enclosing runtime, not as separate MACO-owned
//! processes. This module makes their usage observable across that process boundary:
//! the parent stamps a journal path and span identity, the child (or in-process Fake writer)
//! appends role-tagged JSONL records, and the parent harvests the same inode after the child
//! returns. Incomplete provider data is marked incomplete; missing tokens and cost are never
//! invented.
//!
//! Durable ledger types are reused read-only when reconciling harvested records into a
//! [`RollingBudgetUsage`] projection. This module does not append to the workspace budget
//! journal.

use crate::budget_ledger::RollingBudgetUsage;
use crate::llm::Usage;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use super::{read_bounded_regular_file_nofollow, EnvironmentMode};

pub const MACO_NESTED_USAGE_JOURNAL_ENV: &str = "MACO_NESTED_USAGE_JOURNAL";
pub const MACO_PARENT_SPAN_ID_ENV: &str = "MACO_PARENT_SPAN_ID";
pub const NESTED_USAGE_SCHEMA_V1: &str = "maco.nested_usage.v1";

const MAX_NESTED_USAGE_JOURNAL_BYTES: usize = 64 * 1024;
const MAX_NESTED_USAGE_RECORDS: usize = 256;
const MAX_NESTED_USAGE_IDENTIFIER_BYTES: usize = 256;
const MAX_NESTED_USAGE_REASON_BYTES: usize = 1024;

/// Absolute journal path and parent span stamped into a child environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedUsageRequest {
    pub journal_path: PathBuf,
    pub parent_span_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NestedUsageRuntimeKind {
    Fake,
    Codex,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NestedWorkerUsageRecord {
    pub schema: String,
    pub parent_span_id: String,
    pub child_span_id: String,
    pub role: String,
    pub runtime: NestedUsageRuntimeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NestedUsageCompleteness {
    ProcessObserved,
    Incomplete { reason: String },
    Missing { reason: String },
}

impl NestedUsageCompleteness {
    pub const fn is_process_observed(&self) -> bool {
        matches!(self, Self::ProcessObserved)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NestedUsageObservation {
    pub parent_span_id: String,
    pub journal_path: PathBuf,
    pub records: Vec<NestedWorkerUsageRecord>,
    pub completeness: NestedUsageCompleteness,
}

/// Read-only projection onto durable rolling-budget usage. Callers that persist this into the
/// workspace ledger live outside process_runner.
#[derive(Debug, Clone, PartialEq)]
pub struct NestedUsageReconciliation {
    pub rolling: RollingBudgetUsage,
    pub completeness: NestedUsageCompleteness,
}

pub fn parent_span_id(run_id: &str, task_id: &str) -> String {
    format!("{run_id}/{task_id}")
}

pub fn stamp_nested_usage_environment(
    environment: &mut EnvironmentMode,
    request: &NestedUsageRequest,
) {
    if matches!(environment, EnvironmentMode::Inherit) {
        *environment = EnvironmentMode::InheritAndSet(Default::default());
    }
    let values = match environment {
        EnvironmentMode::InheritAndSet(values) | EnvironmentMode::ClearAndSet(values) => values,
        EnvironmentMode::Inherit => return,
    };
    values.insert(
        MACO_NESTED_USAGE_JOURNAL_ENV.to_string(),
        request.journal_path.to_string_lossy().into_owned(),
    );
    values.insert(
        MACO_PARENT_SPAN_ID_ENV.to_string(),
        request.parent_span_id.clone(),
    );
}

/// Exclusive-create an owner-only empty journal so the child can append without replacing the
/// path with a symlink.
pub fn prepare_nested_usage_journal(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nested usage journal path must be absolute",
        ));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

pub fn harvest_nested_usage_journal(
    path: &Path,
    expected_parent_span_id: &str,
) -> NestedUsageObservation {
    match read_bounded_regular_file_nofollow(path, MAX_NESTED_USAGE_JOURNAL_BYTES) {
        Ok(bytes) => parse_nested_usage_journal(path, expected_parent_span_id, &bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => NestedUsageObservation {
            parent_span_id: expected_parent_span_id.to_string(),
            journal_path: path.to_path_buf(),
            records: Vec::new(),
            completeness: NestedUsageCompleteness::Missing {
                reason: format!(
                    "nested usage journal was not present after process return: {}",
                    error
                ),
            },
        },
        Err(error) => NestedUsageObservation {
            parent_span_id: expected_parent_span_id.to_string(),
            journal_path: path.to_path_buf(),
            records: Vec::new(),
            completeness: NestedUsageCompleteness::Incomplete {
                reason: format!("nested usage journal could not be read: {error}"),
            },
        },
    }
}

pub fn reconcile_nested_usage(observation: &NestedUsageObservation) -> NestedUsageReconciliation {
    let mut tokens = 0usize;
    let mut cost_usd = Some(0.0);
    for record in &observation.records {
        if let Some(usage) = record.usage {
            tokens = tokens.saturating_add(usage.total_tokens);
        }
        cost_usd = match (cost_usd, record.cost_usd) {
            (Some(total), Some(cost)) if cost.is_finite() && cost >= 0.0 => {
                let total = total + cost;
                total.is_finite().then_some(total)
            }
            _ => None,
        };
    }
    if !matches!(
        observation.completeness,
        NestedUsageCompleteness::ProcessObserved
    ) {
        cost_usd = None;
    }
    NestedUsageReconciliation {
        rolling: RollingBudgetUsage {
            tokens,
            cost_usd,
            rate_limited_pools: Vec::new(),
        },
        completeness: observation.completeness.clone(),
    }
}

pub fn encode_nested_usage_record(record: &NestedWorkerUsageRecord) -> io::Result<String> {
    serde_json::to_string(record).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn parse_nested_usage_journal(
    path: &Path,
    expected_parent_span_id: &str,
    bytes: &[u8],
) -> NestedUsageObservation {
    let mut records = Vec::new();
    let mut problems = Vec::new();
    if bytes.len() > MAX_NESTED_USAGE_JOURNAL_BYTES {
        return incomplete(
            path,
            expected_parent_span_id,
            records,
            "nested usage journal exceeds its safety bound",
        );
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            return incomplete(
                path,
                expected_parent_span_id,
                records,
                "nested usage journal is not valid UTF-8",
            );
        }
    };
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if records.len() >= MAX_NESTED_USAGE_RECORDS {
            problems.push("nested usage journal exceeded its record limit".to_string());
            break;
        }
        match parse_nested_usage_line(line, expected_parent_span_id) {
            Ok(record) => {
                if !record.complete {
                    problems.push(format!(
                        "record {} is explicitly incomplete{}",
                        index + 1,
                        record
                            .incomplete_reason
                            .as_deref()
                            .map(|reason| format!(": {reason}"))
                            .unwrap_or_default()
                    ));
                }
                records.push(record);
            }
            Err(reason) => problems.push(format!("record {}: {reason}", index + 1)),
        }
    }
    if records.is_empty() && problems.is_empty() {
        return NestedUsageObservation {
            parent_span_id: expected_parent_span_id.to_string(),
            journal_path: path.to_path_buf(),
            records,
            completeness: NestedUsageCompleteness::Incomplete {
                reason: "nested usage journal contained no process-observed records".to_string(),
            },
        };
    }
    if problems.is_empty() {
        NestedUsageObservation {
            parent_span_id: expected_parent_span_id.to_string(),
            journal_path: path.to_path_buf(),
            records,
            completeness: NestedUsageCompleteness::ProcessObserved,
        }
    } else {
        incomplete(path, expected_parent_span_id, records, problems.join("; "))
    }
}

fn parse_nested_usage_line(
    line: &str,
    expected_parent_span_id: &str,
) -> Result<NestedWorkerUsageRecord, String> {
    let record: NestedWorkerUsageRecord = serde_json::from_str(line)
        .map_err(|error| format!("nested usage record is malformed: {error}"))?;
    if record.schema != NESTED_USAGE_SCHEMA_V1 {
        return Err(format!(
            "nested usage schema '{}' is not {NESTED_USAGE_SCHEMA_V1}",
            record.schema
        ));
    }
    validate_identifier("parent_span_id", &record.parent_span_id)?;
    validate_identifier("child_span_id", &record.child_span_id)?;
    validate_identifier("role", &record.role)?;
    if let Some(model) = &record.model {
        validate_identifier("model", model)?;
    }
    if let Some(reason) = &record.incomplete_reason {
        if reason.is_empty() || reason.len() > MAX_NESTED_USAGE_REASON_BYTES {
            return Err("incomplete_reason is empty or exceeds its safety bound".to_string());
        }
    }
    if record.parent_span_id != expected_parent_span_id {
        return Err(format!(
            "parent_span_id '{}' does not match the stamped parent span",
            record.parent_span_id
        ));
    }
    if let Some(cost) = record.cost_usd {
        if !cost.is_finite() || cost < 0.0 {
            return Err("cost_usd must be finite and non-negative when present".to_string());
        }
    }
    if let Some(usage) = record.usage {
        let summed = usage.input_tokens.saturating_add(usage.output_tokens);
        if usage.total_tokens != summed {
            return Err(
                "usage.total_tokens must equal input_tokens + output_tokens when present"
                    .to_string(),
            );
        }
    }
    if record.complete {
        if record.usage.is_none() {
            return Err("complete records must include process-observed usage".to_string());
        }
        if record.incomplete_reason.is_some() {
            return Err("complete records must not carry an incomplete_reason".to_string());
        }
    } else if record.incomplete_reason.is_none() {
        return Err("incomplete records must name the missing observation".to_string());
    }
    Ok(record)
}

fn validate_identifier(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_NESTED_USAGE_IDENTIFIER_BYTES {
        return Err(format!("{field} is empty or exceeds its safety bound"));
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '/' | '.')
    }) {
        return Err(format!(
            "{field} may only contain ASCII letters, digits, '.', '_', '-', and '/'"
        ));
    }
    Ok(())
}

fn incomplete(
    path: &Path,
    expected_parent_span_id: &str,
    records: Vec<NestedWorkerUsageRecord>,
    reason: impl Into<String>,
) -> NestedUsageObservation {
    NestedUsageObservation {
        parent_span_id: expected_parent_span_id.to_string(),
        journal_path: path.to_path_buf(),
        records,
        completeness: NestedUsageCompleteness::Incomplete {
            reason: reason.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_record(
        parent: &str,
        child: &str,
        runtime: NestedUsageRuntimeKind,
        input: usize,
        output: usize,
        cost_usd: f64,
    ) -> NestedWorkerUsageRecord {
        NestedWorkerUsageRecord {
            schema: NESTED_USAGE_SCHEMA_V1.to_string(),
            parent_span_id: parent.to_string(),
            child_span_id: child.to_string(),
            role: "worker".to_string(),
            runtime,
            model: Some("gpt-5.6-sol".to_string()),
            usage: Some(Usage {
                input_tokens: input,
                output_tokens: output,
                total_tokens: input + output,
            }),
            cost_usd: Some(cost_usd),
            duration_ms: Some(12),
            complete: true,
            incomplete_reason: None,
        }
    }

    #[test]
    fn harvest_correlates_fake_and_cli_spans_and_reconciles_observed_cost() {
        let parent = "run-1/child-orchestrator";
        let journal = parse_nested_usage_journal(
            Path::new("/tmp/nested-usage.jsonl"),
            parent,
            format!(
                "{}\n{}\n",
                encode_nested_usage_record(&complete_record(
                    parent,
                    "worker-fake",
                    NestedUsageRuntimeKind::Fake,
                    10,
                    5,
                    0.01,
                ))
                .expect("encode fake"),
                encode_nested_usage_record(&complete_record(
                    parent,
                    "worker-codex",
                    NestedUsageRuntimeKind::Codex,
                    20,
                    7,
                    0.02,
                ))
                .expect("encode cli"),
            )
            .as_bytes(),
        );

        assert!(journal.completeness.is_process_observed());
        assert_eq!(journal.records.len(), 2);
        assert!(journal
            .records
            .iter()
            .all(|record| record.parent_span_id == parent));
        assert_eq!(journal.records[0].runtime, NestedUsageRuntimeKind::Fake);
        assert_eq!(journal.records[1].runtime, NestedUsageRuntimeKind::Codex);

        let reconciled = reconcile_nested_usage(&journal);
        assert_eq!(reconciled.rolling.tokens, 42);
        assert_eq!(reconciled.rolling.cost_usd, Some(0.03));
        assert!(reconciled.rolling.rate_limited_pools.is_empty());
    }

    #[test]
    fn incomplete_provider_data_is_marked_and_cost_is_not_guessed() {
        let parent = "run-1/child-orchestrator";
        let mut incomplete_record = complete_record(
            parent,
            "worker-codex",
            NestedUsageRuntimeKind::Codex,
            4,
            1,
            0.0,
        );
        incomplete_record.complete = false;
        incomplete_record.usage = None;
        incomplete_record.cost_usd = None;
        incomplete_record.incomplete_reason = Some("provider omitted token usage".to_string());
        let journal = parse_nested_usage_journal(
            Path::new("/tmp/nested-usage.jsonl"),
            parent,
            format!(
                "{}\n{}\n",
                encode_nested_usage_record(&complete_record(
                    parent,
                    "worker-fake",
                    NestedUsageRuntimeKind::Fake,
                    3,
                    1,
                    0.004,
                ))
                .expect("encode fake"),
                encode_nested_usage_record(&incomplete_record).expect("encode incomplete"),
            )
            .as_bytes(),
        );

        assert!(matches!(
            journal.completeness,
            NestedUsageCompleteness::Incomplete { .. }
        ));
        let reconciled = reconcile_nested_usage(&journal);
        assert_eq!(reconciled.rolling.tokens, 4);
        assert_eq!(
            reconciled.rolling.cost_usd, None,
            "cost must not be guessed when any nested record is incomplete"
        );
    }

    #[test]
    fn missing_journal_is_an_explicit_marker_not_zero_usage() {
        let observation = harvest_nested_usage_journal(
            Path::new("/tmp/maco-missing-nested-usage-journal.jsonl"),
            "run-1/task-1",
        );
        assert!(matches!(
            observation.completeness,
            NestedUsageCompleteness::Missing { .. }
        ));
        let reconciled = reconcile_nested_usage(&observation);
        assert_eq!(reconciled.rolling.tokens, 0);
        assert_eq!(reconciled.rolling.cost_usd, None);
    }

    #[test]
    fn mismatched_parent_span_does_not_attribute_foreign_usage() {
        let parent = "run-1/child-orchestrator";
        let foreign = complete_record(
            "other-run/other-child",
            "worker-fake",
            NestedUsageRuntimeKind::Fake,
            99,
            1,
            1.0,
        );
        let journal = parse_nested_usage_journal(
            Path::new("/tmp/nested-usage.jsonl"),
            parent,
            encode_nested_usage_record(&foreign)
                .expect("encode")
                .as_bytes(),
        );
        assert!(journal.records.is_empty());
        assert!(matches!(
            journal.completeness,
            NestedUsageCompleteness::Incomplete { .. }
        ));
        assert_eq!(reconcile_nested_usage(&journal).rolling.tokens, 0);
    }
}
