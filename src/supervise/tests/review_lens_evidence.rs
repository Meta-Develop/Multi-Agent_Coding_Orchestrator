use super::*;

fn readme_review_fixture() -> Result<(AuditorReport, CommandRunRecord)> {
    // The real one-line README review was 1,316 bytes before collection
    // appended a process record with 32,768 bytes of captured runtime JSON.
    let mut report: AuditorReport =
        serde_json::from_str(include_str!("fixtures/review-lens-readme-auditor.json"))?;
    let events = serde_json::to_string(&serde_json::json!({
        "method": "item/started",
        "params": {
            "item": {
                "type": "userMessage",
                "content": [{"type": "text", "text": "Review the README diff.\n".repeat(12_000)}]
            }
        }
    }))?;
    let parent: CommandRunRecord = serde_json::from_value(serde_json::json!({
        "command": ["codex", "app-server"],
        "cwd": "<child-worktree>",
        "exit_code": 0,
        "status": "succeeded",
        "timeout_seconds": 1800,
        "duration_ms": 50_000,
        "timed_out": false,
        "stdout": events.chars().take(32 * 1024).collect::<String>(),
        "stderr": "WARNING: runtime diagnostic\n".repeat(40).chars().take(844).collect::<String>()
    }))?;
    report.commands_run.push(parent.clone());
    Ok((report, parent))
}

fn verdict(report: &AuditorReport, parent: &CommandRunRecord) -> Result<ReviewLensVerdict> {
    let lens = crate::supervise::tests::single_parent_acceptance_review_lenses().remove(0);
    let request = crate::review::build_review_lens_request(
        &lens,
        ReviewLensRequestSources {
            child_transcript: "Worker appended the requested README line.",
            diff: "+Hello from MACO\n",
            output_report: "Worker report accepted.",
        },
    )?;
    review_lens_verdict_from_auditor(&lens, &request, &report.id, report, parent, None, false)
}

#[test]
fn trivial_review_fits_with_realistic_parent_runtime_output() -> Result<()> {
    let (report, parent) = readme_review_fixture()?;
    let original = report.clone();
    assert_eq!(parent.stdout.len(), 32 * 1024);
    assert!(serde_json::to_vec(&report)?.len() > 32 * 1024);
    let content = review_lens_auditor_evidence(&report, &parent)?;
    assert!(content.len() < 32 * 1024);
    let value: serde_json::Value = serde_json::from_str(&content)?;
    let mut authored_report = report.clone();
    authored_report.commands_run.pop();
    assert_eq!(
        value["auditor_report"],
        serde_json::to_value(authored_report)?
    );
    let process_bytes = serde_json::to_vec(&parent)?;
    assert_eq!(
        value["parent_process_record"]["serialized_bytes"],
        process_bytes.len()
    );
    assert_eq!(
        value["parent_process_record"]["sha256"],
        crate::artifacts::state_auth::sha256_hex(&process_bytes)
    );
    let verdict = verdict(&report, &parent)?;
    assert_eq!(verdict.verdict, ReviewLensVerdictStatus::Accept);
    assert_eq!(verdict.evidence.len(), 1);
    assert_eq!(report, original);
    Ok(())
}

#[test]
fn evidence_binds_complete_parent_record_and_auditor_findings() -> Result<()> {
    let (report, parent) = readme_review_fixture()?;
    let original = verdict(&report, &parent)?.evidence.remove(0).binding;
    let mut changed_stdout = parent.clone();
    changed_stdout.stdout.push_str("late runtime event");
    let mut changed_stderr = parent.clone();
    changed_stderr.stderr.push_str("late diagnostic");
    let mut changed_metadata = parent.clone();
    changed_metadata.duration_ms += 1;
    for changed in [changed_stdout, changed_stderr, changed_metadata] {
        let mut changed_report = report.clone();
        *changed_report
            .commands_run
            .last_mut()
            .expect("parent record") = changed.clone();
        assert_ne!(
            verdict(&changed_report, &changed)?.evidence[0].binding,
            original
        );
    }
    let mut changed_report = report.clone();
    changed_report.findings[0]
        .message
        .push_str("Updated review.");
    assert_ne!(
        verdict(&changed_report, &parent)?.evidence[0].binding,
        original
    );
    Ok(())
}

#[test]
fn oversized_auditor_authored_evidence_is_still_refused() -> Result<()> {
    let (report, parent) = readme_review_fixture()?;
    let mut large_finding = report.clone();
    large_finding.findings[0].message = "r".repeat(32 * 1024 + 1);
    let mut large_authored_command = report.clone();
    let mut authored_command = parent.clone();
    authored_command.stdout = "r".repeat(32 * 1024 + 1);
    large_authored_command
        .commands_run
        .insert(0, authored_command);
    for oversized in [large_finding, large_authored_command] {
        assert_eq!(
            verdict(&oversized, &parent)
                .expect_err("oversized review must fail")
                .to_string(),
            "review lens evidence content exceeds its 32768 byte limit"
        );
    }
    Ok(())
}

#[test]
fn evidence_refuses_to_replace_an_auditor_authored_command() -> Result<()> {
    let (mut report, parent) = readme_review_fixture()?;
    report.commands_run[0].command = vec!["git".to_string(), "diff".to_string()];
    assert_eq!(
        verdict(&report, &parent)
            .expect_err("parent record must match")
            .to_string(),
        "review lens auditor report lacks its appended parent process record"
    );
    Ok(())
}
