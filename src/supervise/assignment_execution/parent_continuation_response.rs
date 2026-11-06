//! Descriptor-byte parser for a parent continuation envelope.
//! A parsed final report stays untrusted: this module does not accept it,
//! invent workers, journals, runtime, or usage, or grant another launch.

use super::*;
use serde::{Deserialize, Serialize};

pub(in crate::supervise) const PARENT_CONTINUATION_VERSION: u64 = 2;

/// Digest of the exact descriptor-held final-message bytes, not reserialized JSON.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::supervise) struct WorkerReportReference {
    pub assignment_id: String,
    pub capture_sha256: String,
}

impl WorkerReportReference {
    pub(in crate::supervise) fn from_capture(assignment_id: &str, bytes: &[u8]) -> Self {
        Self {
            assignment_id: assignment_id.to_string(),
            capture_sha256: crate::artifacts::state_auth::sha256_hex(bytes),
        }
    }
}

struct ExpectedWorkerCapture<'a> {
    reference: WorkerReportReference,
    report: &'a WorkerReport,
}

/// Immutable view of the supervisor-owned continuation contract.
/// Production code fills this only from [`ParentContinuationLaunch`].
struct ExpectedParentContinuationBinding<'a> {
    run_id: &'a str,
    parent_id: &'a str,
    source_parent_attempt: usize,
    parent_attempt: usize,
    completed_worker_ids: &'a [String],
    captures: &'a [ExpectedWorkerCapture<'a>],
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
    // Check the version before decoding the version-specific turn. Old recorded
    // echo envelopes must get an explicit refusal, never a compatibility fallback.
    turn: Box<serde_json::value::RawValue>,
}

#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum ParentContinuationTurn {
    YieldWorkers {
        #[allow(dead_code)]
        requests: Vec<YieldWorkerRequestWire>,
    },
    FinalReport {
        report: Box<ParentContinuationReport>,
        worker_report_refs: Vec<WorkerReportReference>,
    },
}

/// Intercept the forbidden field before it can deserialize any Worker payload.
/// Flattening preserves the ordinary report deserializer's duplicate-field checks.
#[derive(Deserialize)]
struct ParentContinuationReport {
    #[serde(
        rename = "worker_reports",
        default,
        deserialize_with = "refuse_worker_payload"
    )]
    _worker_reports: (),
    #[serde(flatten)]
    report: OrchestratorReviewReport,
}

fn refuse_worker_payload<'de, D: serde::Deserializer<'de>>(
    _: D,
) -> std::result::Result<(), D::Error> {
    Err(serde::de::Error::custom("parent continuation report must omit worker_reports; return only worker_report_refs naming the supervisor-held captures"))
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
    let captures = continuation
        .authored_worker_captures()?
        .into_iter()
        .map(|evidence| {
            let bytes = evidence
                .run()
                .output_last_message()
                .context("continuation lost its held Worker capture")?;
            // Keep the source-of-truth report tied to the exact bytes being named.
            if read_worker_report(Some(bytes), &evidence.artifacts().raw_report_relative)?.report
                != *evidence.report()
            {
                bail!("continuation Worker report differs from its held capture");
            }
            Ok(ExpectedWorkerCapture {
                reference: WorkerReportReference::from_capture(&evidence.report().id, bytes),
                report: evidence.report(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    read_parent_continuation_final_report_bound(
        contents,
        display_path,
        &ExpectedParentContinuationBinding {
            run_id,
            parent_id,
            source_parent_attempt,
            parent_attempt,
            completed_worker_ids: continuation.worker_ids(),
            captures: &captures,
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
    if envelope.version != PARENT_CONTINUATION_VERSION {
        bail!(
            "parent continuation version {} is unsupported; expected version {PARENT_CONTINUATION_VERSION} with worker_report_refs; reconcile the old attempt and start a new run rather than replaying an echo report: {}",
            envelope.version,
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
    let turn: ParentContinuationTurn = serde_json::from_str(envelope.turn.get())
        .map_err(|error| anyhow::anyhow!("failed to parse parent continuation turn; final_report requires report and ordered worker_report_refs: {error}"))?;
    let mut report: OrchestratorReviewReport = match turn {
        ParentContinuationTurn::YieldWorkers { .. } => {
            bail!(
                "parent continuation turn requested yield_workers; a further Worker turn is not a final report and grants no launch authority: {}",
                display_path.display()
            );
        }
        ParentContinuationTurn::FinalReport {
            report,
            worker_report_refs,
        } => {
            verify_worker_report_references(&worker_report_refs, expected.captures)?;
            report.report
        }
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
    // No parent-authored WorkerReport is deserialized into the accepted report.
    report.worker_reports = expected
        .captures
        .iter()
        .map(|capture| capture.report.clone())
        .collect();
    Ok(ParsedReport {
        report,
        recovered: false,
    })
}

fn verify_worker_report_references(
    supplied: &[WorkerReportReference],
    captures: &[ExpectedWorkerCapture<'_>],
) -> Result<()> {
    if supplied.len() != captures.len() {
        bail!("parent continuation worker_report_refs has {} entries; expected {} (one per authored Worker, no missing or extra entries)", supplied.len(), captures.len());
    }
    let mut seen = BTreeSet::new();
    for (index, (reference, capture)) in supplied.iter().zip(captures).enumerate() {
        if !seen.insert(&reference.assignment_id) {
            bail!("parent continuation worker_report_refs duplicates Worker '{}'; name each authored Worker exactly once", reference.assignment_id);
        }
        if reference.assignment_id != capture.reference.assignment_id {
            bail!("parent continuation worker_report_refs entry {} names '{}'; expected '{}' in authored order", index + 1, reference.assignment_id, capture.reference.assignment_id);
        }
        if reference.capture_sha256 != capture.reference.capture_sha256 {
            bail!("parent continuation worker_report_refs digest mismatch for Worker '{}'; copy capture_sha256 from the supervisor-supplied reference", reference.assignment_id);
        }
    }
    Ok(())
}

fn same_attempt(wire: u64, expected: usize) -> bool {
    usize::try_from(wire).ok() == Some(expected)
}

fn worker_ids_repeat(ids: &[String]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    ids.iter().any(|id| !seen.insert(id.as_str()))
}

/// Offline parents copy only the references actually supplied in their prompt.
#[cfg(test)]
pub(in crate::supervise) fn final_turn_for_test(
    command: &ExternalAgentCommand,
    report: &OrchestratorReviewReport,
) -> serde_json::Value {
    let prompt = fs::read_to_string(&command.prompt).unwrap();
    let references = prompt
        .split("Worker report references in authored order (copy into turn.worker_report_refs):\n")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let references: serde_json::Value = serde_json::from_str(references).unwrap();
    let mut report = serde_json::to_value(report).unwrap();
    report.as_object_mut().unwrap().remove("worker_reports");
    serde_json::json!({"outcome":"final_report", "report":report, "worker_report_refs":references})
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

    fn worker_reports() -> Vec<WorkerReport> {
        workers()
            .iter()
            .map(|id| {
                serde_json::from_value(serde_json::json!({
                    "id": id, "role": "worker", "accepted": true, "rejected": false,
                    "status": "succeeded", "no_further_delegation": true,
                }))
                .unwrap()
            })
            .collect()
    }

    fn references() -> Vec<WorkerReportReference> {
        worker_reports()
            .iter()
            .map(|report| {
                WorkerReportReference::from_capture(
                    &report.id,
                    &serde_json::to_vec(report).unwrap(),
                )
            })
            .collect()
    }

    fn envelope(report: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "version": 2,
            "run_id": "run",
            "parent_id": "parent",
            "source_parent_attempt": 1,
            "parent_attempt": 2,
            "completed_worker_ids": ["w1", "w2"],
            "turn": {"outcome": "final_report", "report": report, "worker_report_refs": references()},
        })
    }

    fn parse_bytes(
        bytes: &[u8],
        completed: &[String],
    ) -> Result<ParsedReport<OrchestratorReviewReport>> {
        let workers = worker_reports();
        let captures = workers
            .iter()
            .map(|report| ExpectedWorkerCapture {
                reference: WorkerReportReference::from_capture(
                    &report.id,
                    &serde_json::to_vec(report).unwrap(),
                ),
                report,
            })
            .collect::<Vec<_>>();
        read_parent_continuation_final_report_bound(
            Some(bytes),
            Path::new("continuation.json"),
            &ExpectedParentContinuationBinding {
                run_id: "run",
                parent_id: "parent",
                source_parent_attempt: 1,
                parent_attempt: 2,
                completed_worker_ids: completed,
                captures: &captures,
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
        let mut expected: OrchestratorReviewReport = serde_json::from_value(report).unwrap();
        expected.worker_reports = worker_reports();
        assert!(!parsed.recovered);
        assert_eq!(parsed.report, expected);
        assert!(parsed.report.accepted);
        assert_eq!(parsed.report.id, "parent");
        assert_eq!(parsed.report.role, AgentRole::ChildOrchestrator);
    }

    #[test]
    fn refuses_wrong_digest_swapped_missing_extra_and_duplicate_references() {
        let completed = workers();
        for (case, expected) in [
            ("digest", "digest mismatch for Worker 'w1'"),
            ("swapped", "expected 'w1' in authored order"),
            ("missing", "expected 2"),
            ("extra", "expected 2"),
            ("duplicate", "duplicates Worker 'w1'"),
        ] {
            let mut value = envelope(report_value());
            let refs = value["turn"]["worker_report_refs"].as_array_mut().unwrap();
            match case {
                "digest" => refs[0]["capture_sha256"] = serde_json::json!("0".repeat(64)),
                "swapped" => refs.swap(0, 1),
                "missing" => {
                    refs.pop();
                }
                "extra" => refs.push(refs[0].clone()),
                "duplicate" => refs[1] = refs[0].clone(),
                _ => unreachable!(),
            }
            let error = parse_value(value, &completed).unwrap_err().to_string();
            assert!(error.contains(expected), "{case}: {error}");
        }
    }

    #[test]
    fn refuses_parent_payloads_and_legacy_echo_envelopes() {
        for payload in [
            serde_json::json!([]),
            serde_json::json!([{"id":"forged"}]),
            serde_json::Value::Null,
        ] {
            let mut value = envelope(report_value());
            value["turn"]["report"]["worker_reports"] = payload;
            assert!(parse_value(value, &workers())
                .unwrap_err()
                .to_string()
                .contains("must omit worker_reports"));
        }
        let mut value = envelope(report_value());
        value["turn"]["worker_report_refs"][0]["worker_report"] =
            serde_json::json!({"id":"forged"});
        assert!(parse_value(value, &workers())
            .unwrap_err()
            .to_string()
            .contains("failed to parse"));
        let mut legacy = envelope(report_value());
        legacy["version"] = serde_json::json!(1);
        legacy["turn"]
            .as_object_mut()
            .unwrap()
            .remove("worker_report_refs");
        legacy["turn"]["report"]["worker_reports"] = serde_json::json!(worker_reports());
        let error = parse_value(legacy, &workers()).unwrap_err().to_string();
        assert!(error.contains("version 1 is unsupported"), "{error}");
        assert!(error.contains("start a new run"), "{error}");
    }

    #[test]
    fn refuses_duplicate_fields_in_turn_reference_and_parent_report() {
        let good = serde_json::to_string(&envelope(report_value())).unwrap();
        for mutated in [
            good.replace(
                "\"outcome\":\"final_report\"",
                "\"outcome\":\"final_report\",\"outcome\":\"final_report\"",
            ),
            good.replace(
                "\"assignment_id\":\"w1\"",
                "\"assignment_id\":\"w1\",\"assignment_id\":\"w1\"",
            ),
            good.replace("\"accepted\":true", "\"accepted\":true,\"accepted\":true"),
        ] {
            assert_ne!(mutated, good);
            assert!(parse_bytes(mutated.as_bytes(), &workers()).is_err());
        }
    }

    #[test]
    fn capture_digest_binds_raw_bytes_including_whitespace() {
        let compact = serde_json::to_vec(&worker_reports()[0]).unwrap();
        let mut spaced = compact.clone();
        spaced.push(b'\n');
        assert_ne!(
            WorkerReportReference::from_capture("w1", &compact),
            WorkerReportReference::from_capture("w1", &spaced)
        );
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
                captures: &[],
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
        version["version"] = serde_json::json!(1);
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
