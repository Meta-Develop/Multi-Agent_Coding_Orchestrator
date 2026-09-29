//! Descriptor-byte parser for a parent continuation envelope.
//! A parsed final report stays untrusted: this module does not accept it,
//! invent workers, journals, runtime, or usage, or grant another launch.

use super::*;
use serde::Deserialize;

/// Immutable view of the supervisor-owned continuation contract.
/// Production code fills this only from [`ParentContinuationLaunch`].
struct ExpectedParentContinuationBinding<'a> {
    run_id: &'a str,
    parent_id: &'a str,
    source_parent_attempt: usize,
    parent_attempt: usize,
    completed_worker_ids: &'a [String],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentContinuationEnvelope {
    version: u64,
    run_id: String,
    parent_id: String,
    source_parent_attempt: u64,
    parent_attempt: u64,
    completed_worker_ids: Vec<String>,
    turn: ParentContinuationTurn,
}

#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum ParentContinuationTurn {
    YieldWorkers {
        #[allow(dead_code)]
        requests: Vec<YieldWorkerRequestWire>,
    },
    FinalReport {
        report: Box<OrchestratorReviewReport>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct YieldWorkerRequestWire {
    #[allow(dead_code)]
    request_id: String,
    #[allow(dead_code)]
    worker_id: String,
}

pub(super) fn read_parent_continuation_final_report(
    contents: Option<&[u8]>,
    display_path: &Path,
    continuation: &ParentContinuationLaunch<'_>,
) -> Result<ParsedReport<OrchestratorReviewReport>> {
    let (run_id, parent_id, source_parent_attempt, parent_attempt) = continuation.binding();
    read_parent_continuation_final_report_bound(
        contents,
        display_path,
        &ExpectedParentContinuationBinding {
            run_id,
            parent_id,
            source_parent_attempt,
            parent_attempt,
            completed_worker_ids: continuation.worker_ids(),
        },
    )
}

fn read_parent_continuation_final_report_bound(
    contents: Option<&[u8]>,
    display_path: &Path,
    expected: &ExpectedParentContinuationBinding<'_>,
) -> Result<ParsedReport<OrchestratorReviewReport>> {
    let contents =
        contents.context("parent continuation did not capture a descriptor-held final report")?;
    if contents.len() > MAX_SUPERVISOR_REPORT_BYTES {
        bail!(
            "parent continuation response exceeds {MAX_SUPERVISOR_REPORT_BYTES} bytes: {}",
            display_path.display()
        );
    }
    let contents = std::str::from_utf8(contents).with_context(|| {
        format!(
            "descriptor-held parent continuation response is not UTF-8: {}",
            display_path.display()
        )
    })?;
    let envelope: ParentContinuationEnvelope =
        serde_json::from_str(contents).with_context(|| {
            format!(
                "failed to parse parent continuation response {}",
                display_path.display()
            )
        })?;
    if envelope.version != 1 {
        bail!(
            "parent continuation version is not 1: {}",
            display_path.display()
        );
    }
    if envelope.run_id != expected.run_id
        || envelope.parent_id != expected.parent_id
        || !same_attempt(
            envelope.source_parent_attempt,
            expected.source_parent_attempt,
        )
        || !same_attempt(envelope.parent_attempt, expected.parent_attempt)
    {
        bail!(
            "parent continuation binding does not match the held parent launch: {}",
            display_path.display()
        );
    }
    if worker_ids_repeat(&envelope.completed_worker_ids)
        || envelope.completed_worker_ids != expected.completed_worker_ids
    {
        bail!(
            "parent continuation completed_worker_ids differ from the exact completed worker order: {}",
            display_path.display()
        );
    }
    let report = match envelope.turn {
        ParentContinuationTurn::YieldWorkers { .. } => {
            bail!(
                "parent continuation turn requested yield_workers; a further Worker turn is not a final report and grants no launch authority: {}",
                display_path.display()
            );
        }
        ParentContinuationTurn::FinalReport { report } => *report,
    };
    if report.role != AgentRole::ChildOrchestrator {
        bail!(
            "parent continuation report {} declared non-child role {:?}",
            display_path.display(),
            report.role
        );
    }
    if report.id != expected.parent_id {
        bail!(
            "parent continuation report id {} does not match parent {}",
            report.id,
            expected.parent_id
        );
    }
    Ok(ParsedReport {
        report,
        recovered: false,
    })
}

fn same_attempt(wire: u64, expected: usize) -> bool {
    usize::try_from(wire).ok() == Some(expected)
}

fn worker_ids_repeat(ids: &[String]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    ids.iter().any(|id| !seen.insert(id.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workers() -> Vec<String> {
        vec!["w1".to_string(), "w2".to_string()]
    }

    fn report_value() -> serde_json::Value {
        serde_json::json!({
            "id": "parent",
            "role": "child_orchestrator",
            "accepted": true,
            "rejected": false,
            "status": "succeeded",
            "remaining_risk": "untrusted model text",
            "next_safe_action": "run normal acceptance",
        })
    }

    fn envelope(report: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "run_id": "run",
            "parent_id": "parent",
            "source_parent_attempt": 1,
            "parent_attempt": 2,
            "completed_worker_ids": ["w1", "w2"],
            "turn": {"outcome": "final_report", "report": report},
        })
    }

    fn parse_bytes(
        bytes: &[u8],
        completed: &[String],
    ) -> Result<ParsedReport<OrchestratorReviewReport>> {
        read_parent_continuation_final_report_bound(
            Some(bytes),
            Path::new("continuation.json"),
            &ExpectedParentContinuationBinding {
                run_id: "run",
                parent_id: "parent",
                source_parent_attempt: 1,
                parent_attempt: 2,
                completed_worker_ids: completed,
            },
        )
    }

    fn parse_value(
        value: serde_json::Value,
        completed: &[String],
    ) -> Result<ParsedReport<OrchestratorReviewReport>> {
        parse_bytes(&serde_json::to_vec(&value).unwrap(), completed)
    }

    #[test]
    fn exact_binding_preserves_report_and_is_not_recovered() {
        let report = report_value();
        let completed = workers();
        let parsed = parse_value(envelope(report.clone()), &completed).unwrap();
        let expected: OrchestratorReviewReport = serde_json::from_value(report).unwrap();
        assert!(!parsed.recovered);
        assert_eq!(parsed.report, expected);
        assert!(parsed.report.accepted);
        assert_eq!(parsed.report.id, "parent");
        assert_eq!(parsed.report.role, AgentRole::ChildOrchestrator);
    }

    #[test]
    fn rejects_missing_oversize_utf8_json_and_trailing_prose() {
        let completed = workers();
        let missing = read_parent_continuation_final_report_bound(
            None,
            Path::new("continuation.json"),
            &ExpectedParentContinuationBinding {
                run_id: "run",
                parent_id: "parent",
                source_parent_attempt: 1,
                parent_attempt: 2,
                completed_worker_ids: &completed,
            },
        );
        assert!(missing.unwrap_err().to_string().contains("did not capture"));

        let mut huge = vec![b' '; MAX_SUPERVISOR_REPORT_BYTES + 1];
        huge[0] = b'{';
        let oversized = parse_bytes(&huge, &completed).unwrap_err().to_string();
        assert!(oversized.contains("exceeds"));

        let utf8 = parse_bytes(&[0xff, 0xfe], &completed)
            .unwrap_err()
            .to_string();
        assert!(utf8.contains("not UTF-8"));

        let json = parse_bytes(b"{", &completed).unwrap_err().to_string();
        assert!(json.contains("failed to parse"));

        let mut prose = serde_json::to_vec(&envelope(report_value())).unwrap();
        prose.extend_from_slice(b" trailing prose");
        let trailing = parse_bytes(&prose, &completed).unwrap_err().to_string();
        assert!(trailing.contains("failed to parse"));
    }

    #[test]
    fn rejects_binding_version_workers_shape_role_and_id_mutations() {
        let completed = workers();
        let good = envelope(report_value());

        let mut version = good.clone();
        version["version"] = serde_json::json!(2);
        assert!(parse_value(version, &completed)
            .unwrap_err()
            .to_string()
            .contains("version"));

        for (field, replacement) in [
            ("run_id", serde_json::json!("other-run")),
            ("parent_id", serde_json::json!("other-parent")),
            ("source_parent_attempt", serde_json::json!(9)),
            ("parent_attempt", serde_json::json!(9)),
        ] {
            let mut mutated = good.clone();
            mutated[field] = replacement;
            let error = parse_value(mutated, &completed).unwrap_err().to_string();
            assert!(error.contains("binding"), "{field}: {error}");
        }

        let mut reordered = good.clone();
        reordered["completed_worker_ids"] = serde_json::json!(["w2", "w1"]);
        assert!(parse_value(reordered, &completed)
            .unwrap_err()
            .to_string()
            .contains("completed_worker_ids"));

        let mut duplicated = good.clone();
        duplicated["completed_worker_ids"] = serde_json::json!(["w1", "w1"]);
        assert!(parse_value(duplicated, &completed)
            .unwrap_err()
            .to_string()
            .contains("completed_worker_ids"));

        let mut missing_worker = good.clone();
        missing_worker["completed_worker_ids"] = serde_json::json!(["w1"]);
        assert!(parse_value(missing_worker, &completed)
            .unwrap_err()
            .to_string()
            .contains("completed_worker_ids"));

        let mut unknown_envelope = good.clone();
        unknown_envelope["extra"] = serde_json::json!(true);
        assert!(parse_value(unknown_envelope, &completed)
            .unwrap_err()
            .to_string()
            .contains("failed to parse"));

        let mut unknown_turn = good.clone();
        unknown_turn["turn"]["note"] = serde_json::json!("x");
        assert!(parse_value(unknown_turn, &completed)
            .unwrap_err()
            .to_string()
            .contains("failed to parse"));

        let mut wrong_outcome = good.clone();
        wrong_outcome["turn"] = serde_json::json!({"outcome": "done", "report": report_value()});
        assert!(parse_value(wrong_outcome, &completed)
            .unwrap_err()
            .to_string()
            .contains("failed to parse"));

        let mut yield_turn = good.clone();
        yield_turn["turn"] = serde_json::json!({
            "outcome": "yield_workers",
            "requests": [{"request_id": "r1", "worker_id": "w1"}],
        });
        let yielded = parse_value(yield_turn, &completed).unwrap_err().to_string();
        assert!(yielded.contains("yield_workers"));
        assert!(yielded.contains("no launch authority"));

        let mut wrong_role = report_value();
        wrong_role["role"] = serde_json::json!("worker");
        assert!(parse_value(envelope(wrong_role), &completed)
            .unwrap_err()
            .to_string()
            .contains("non-child"));

        let mut wrong_id = report_value();
        wrong_id["id"] = serde_json::json!("not-the-parent");
        assert!(parse_value(envelope(wrong_id), &completed)
            .unwrap_err()
            .to_string()
            .contains("does not match parent"));
    }
}
