use super::*;
#[cfg(target_os = "linux")]
use crate::agent_lifecycle::{AgentListFilter, AgentRegistry};
use crate::process_runner::{
    ContainmentBackend, ProcessFailureEvidence, SideEffectConfinementProfileKind,
};

#[test]
fn codex_runtime_model_catalog_parser_is_bounded_unique_and_slug_strict() {
    let catalog = parse_codex_runtime_model_catalog(
            br#"{"models":[{"slug":"gpt-5.6-sol","visibility":"list"},{"slug":"provider/hidden:model_1","visibility":"hide"}]}"#,
        )
        .expect("valid runtime model catalog");
    assert!(catalog.contains("gpt-5.6-sol"));
    assert!(catalog.contains("provider/hidden:model_1"));
    assert!(!catalog.contains("missing-model"));

    for (fixture, expected) in [
        (br#"{"models":[]}"#.as_slice(), "at least one model"),
        (
            br#"{"models":[{"slug":"same"},{"slug":"same"}]}"#.as_slice(),
            "duplicate slug",
        ),
        (
            br#"{"models":[{"slug":"bad slug"}]}"#.as_slice(),
            "contain only ASCII",
        ),
        (
            br#"{"models":[{"display_name":"missing"}]}"#.as_slice(),
            "string slug",
        ),
        (br#"{"models":"not-an-array"}"#.as_slice(), "models array"),
        (br#"not-json"#.as_slice(), "not valid JSON"),
    ] {
        let error =
            parse_codex_runtime_model_catalog(fixture).expect_err("catalog must fail closed");
        assert!(
            format!("{error:#}").contains(expected),
            "unexpected error for {fixture:?}: {error:#}"
        );
    }
}

#[derive(Default)]
struct RecordingPreActionJournal {
    records: Vec<PreActionJournalRecord>,
    fail: bool,
}

impl PreActionJournalSink for RecordingPreActionJournal {
    fn append(&mut self, record: &PreActionJournalRecord) -> Result<()> {
        if self.fail {
            bail!("injected journal failure");
        }
        self.records.push(record.clone());
        Ok(())
    }
}

fn test_review_context() -> ReviewContext {
    ReviewContext::new(
        "issue28-test",
        "worker-a",
        "review bounded changes",
        [crate::pre_action_review::RepoPathRule::exact("README.md").expect("claim")],
        std::iter::empty::<crate::pre_action_review::RepoPathRule>(),
    )
    .expect("review context")
}

#[test]
fn production_adapter_fails_closed_for_incomplete_file_and_command_manifests() {
    let context = test_review_context();
    let mut journal = RecordingPreActionJournal::default();
    let mut reviewer = DuplexApprovalReviewer {
        context: &context,
        review_session_id: "review-test",
        journal: &mut journal,
        reviewer: PreActionReviewer::default(),
        observed_denials: Vec::new(),
        workspace: Path::new("/workspace"),
    };
    let file_response = codex_app_server::ApprovalReviewer::review(
        &mut reviewer,
        codex_app_server::ApprovalRequest {
            kind: codex_app_server::ApprovalKind::FileChange,
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            item_id: "file-1".to_string(),
            command: None,
            cwd: Some("/workspace".to_string()),
            reason: Some("missing changes".to_string()),
            ceiling_expansion_requested: false,
            item: serde_json::json!({
                "id": "file-1",
                "type": "fileChange",
                "status": "inProgress"
            }),
            raw_params: serde_json::json!({}),
        },
    )
    .expect("file review");
    assert_eq!(
        file_response.decision,
        codex_app_server::ApprovalDecision::Decline
    );

    let command_response = codex_app_server::ApprovalReviewer::review(
        &mut reviewer,
        codex_app_server::ApprovalRequest {
            kind: codex_app_server::ApprovalKind::CommandExecution,
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            item_id: "command-1".to_string(),
            command: Some("sed -n 1p /workspace/README.md".to_string()),
            cwd: Some("/workspace".to_string()),
            reason: None,
            ceiling_expansion_requested: false,
            item: serde_json::json!({
                "id": "command-1",
                "type": "commandExecution",
                "status": "inProgress",
                "command": "sed -n 1p /workspace/README.md",
                "cwd": "/workspace",
                "commandActions": [{
                    "type": "read",
                    "command": "sed",
                    "name": "README.md",
                    "path": "/workspace/README.md"
                }]
            }),
            raw_params: serde_json::json!({}),
        },
    )
    .expect("command review");
    assert_eq!(
        command_response.decision,
        codex_app_server::ApprovalDecision::Decline
    );
    drop(reviewer);

    assert_eq!(journal.records.len(), 2);
    for record in &journal.records {
        let request = record.request.as_ref().expect("redacted request");
        assert!(!request.action.access_manifest_complete);
        assert_eq!(record.decision_source, Some(DecisionSource::Classifier));
        assert_eq!(record.allowed, Some(false));
    }
    assert_eq!(
        journal.records[1]
            .request
            .as_ref()
            .expect("command request")
            .action
            .accesses[0]
            .mode(),
        PathAccessMode::Read
    );
}

#[test]
fn strict_journal_failure_prevents_an_allow_response() {
    let context = test_review_context();
    let mut journal = RecordingPreActionJournal {
        records: Vec::new(),
        fail: true,
    };
    let mut reviewer = DuplexApprovalReviewer {
        context: &context,
        review_session_id: "review-test",
        journal: &mut journal,
        reviewer: PreActionReviewer::default(),
        observed_denials: Vec::new(),
        workspace: Path::new("/workspace"),
    };
    let result = codex_app_server::ApprovalReviewer::review(
        &mut reviewer,
        codex_app_server::ApprovalRequest {
            kind: codex_app_server::ApprovalKind::FileChange,
            thread_id: "thread-1".to_string(),
            turn_id: "turn-1".to_string(),
            item_id: "file-allow".to_string(),
            command: None,
            cwd: Some("/workspace".to_string()),
            reason: None,
            ceiling_expansion_requested: false,
            item: serde_json::json!({
                "id": "file-allow",
                "type": "fileChange",
                "status": "inProgress",
                "changes": [{
                    "path": "README.md",
                    "kind": {"type": "update"},
                    "diff": "bounded"
                }]
            }),
            raw_params: serde_json::json!({}),
        },
    );
    assert!(result.is_err_and(|message| message.contains("journal append failed")));
}

#[test]
fn current_protocol_refuses_writable_production_release() {
    let error =
        validate_universal_pre_action_coverage().expect_err("coverage gap must fail closed");
    assert!(error
        .to_string()
        .contains("does not guarantee a blocking MACO callback"));
}

#[test]
fn local_executor_forwards_the_concrete_reviewed_runner_once_without_changing_its_run() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let spec = ExternalAgentCommand::codex(
        "/bin/false",
        "/workspace",
        "/workspace/prompt.md",
        "/workspace/events.jsonl",
        "/workspace/last-message.txt",
        Duration::from_secs(7),
    );
    let cancellation = ProcessCancellation::new();
    let context = test_review_context();
    let mut journal = RecordingPreActionJournal::default();
    let calls = AtomicUsize::new(0);
    let journal_record = terminal_turn_journal_record(
        context.run_id(),
        "forwarding-test",
        &codex_app_server::AppServerOutcome {
            thread_id: "thread-forwarded".to_string(),
            turn_id: "turn-forwarded".to_string(),
            status: codex_app_server::TurnTerminalStatus::Completed,
            completed_items: 0,
            item_outcomes: Vec::new(),
            refused_ceiling_expansions: 0,
            gate_denials: Vec::new(),
            final_message: Some("forwarded".to_string()),
            auto_reviews: Vec::new(),
            duplex_fallback_required: false,
            messages_received: 1,
            bytes_received: 1,
        },
        None,
    );
    let expected = failed_external_run(
        &spec,
        Instant::now(),
        vec!["sentinel-command".to_string()],
        true,
        "sentinel-error".to_string(),
    );
    let runner = |command: &ExternalAgentCommand,
                  forwarded_cancellation: &ProcessCancellation,
                  review_runtime: Option<ExternalPreActionReviewRuntime<'_>>| {
        calls.fetch_add(1, Ordering::SeqCst);
        assert!(std::ptr::eq(command, &spec));
        assert!(std::ptr::eq(forwarded_cancellation, &cancellation));
        let review_runtime = review_runtime.expect("borrowed review runtime forwarded");
        assert!(std::ptr::eq(review_runtime.context, &context));
        review_runtime
            .journal
            .append(&journal_record)
            .expect("forwarded journal remains usable");
        expected.clone()
    };

    let actual = forward_local_external_agent_run(
        &runner,
        &spec,
        &cancellation,
        Some(ExternalPreActionReviewRuntime {
            context: &context,
            journal: &mut journal,
        }),
    );

    assert_eq!(actual, expected);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(journal.records, vec![journal_record]);
}

#[test]
fn writable_app_server_accepts_only_the_exact_audited_codex_version() {
    validate_duplex_app_server_version(EnvironmentVersion::new(0, 144, 4))
        .expect("audited Codex app-server version");
    for version in [
        EnvironmentVersion::new(0, 144, 3),
        EnvironmentVersion::new(0, 144, 5),
        EnvironmentVersion::new(0, 145, 0),
    ] {
        let error = validate_duplex_app_server_version(version)
            .expect_err("unaudited app-server version must fail closed");
        assert!(error
            .to_string()
            .contains("does not match the audited writable app-server protocol version"));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn repeated_retention_bound_writable_refusal_leaves_no_child_or_staging_residue() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    create_mandatory_control_roots(temp.path())?;
    let marker = temp.path().join("child-process-started");
    let agent = temp.path().join("must-not-start.sh");
    fs::write(&agent, format!("#!/bin/sh\ntouch '{}'\n", marker.display()))?;
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
    let prompt = temp.path().join("prompt.md");
    fs::write(&prompt, "writable child must remain disabled\n")?;
    let incoming = temp.path().join("incoming");
    fs::create_dir(&incoming)?;
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
    let agents = temp.path().join(".agents");
    fs::set_permissions(&agents, fs::Permissions::from_mode(0o700))?;
    let mut spec = ExternalAgentCommand::codex(
        &agent,
        temp.path(),
        &prompt,
        incoming.join("events.jsonl"),
        incoming.join("last-message.txt"),
        Duration::from_secs(5),
    );
    let unused_retention_config = temp.path().join("must-not-open-retention.json");
    spec.machine_global_retention = Some(ExternalMachineGlobalRetentionBinding {
        config: unused_retention_config.clone(),
        root_id: "runtime".to_string(),
        owner: "retention-bound-refusal".to_string(),
        correction_correlation_id: "coverage-gate-refusal".to_string(),
    });
    let would_be_materialized_control = agents.join("must-not-materialize.md");
    spec.worktree_control_exceptions = vec![PathBuf::from(".agents/must-not-materialize.md")];
    let context = test_review_context();
    let mut journal = RecordingPreActionJournal::default();
    let runtime_root = crate::process_runner::trusted_linux_runtime_root()?;
    let staging_prefix = format!(".maco-external-output-{}-", std::process::id());
    let staging_roots = || -> Result<BTreeSet<OsString>> {
        let mut roots = BTreeSet::new();
        for entry in fs::read_dir(&runtime_root)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(&staging_prefix)
            {
                roots.insert(entry.file_name());
            }
        }
        Ok(roots)
    };
    let before = staging_roots()?;

    for iteration in 0..32 {
        let review_runtime = (iteration % 2 == 1).then_some(ExternalPreActionReviewRuntime {
            context: &context,
            journal: &mut journal,
        });
        let report = run_external_agent_cancellable_reviewed(
            &spec,
            &ProcessCancellation::new(),
            review_runtime,
        );

        assert!(!marker.exists());
        assert!(!would_be_materialized_control.exists());
        assert!(!report.stdout.target_launch_attempted);
        assert_eq!(report.process_tree, None);
        assert_eq!(report.side_effects, None);
        assert!(report.environment_blocked());
        let expected_refusal = if iteration % 2 == 0 {
            "requires a duplex MACO pre-action reviewer"
        } else {
            "writable Codex failed closed before launch"
        };
        assert!(report
            .error
            .as_deref()
            .is_some_and(|error| error.contains(expected_refusal)));
    }
    assert_eq!(staging_roots()?, before);
    assert!(!unused_retention_config.exists());
    assert!(!would_be_materialized_control.exists());
    assert!(journal.records.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn production_writable_path_refuses_before_starting_any_child_process() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    create_mandatory_control_roots(temp.path())?;
    let marker = temp.path().join("child-process-started");
    let agent = temp.path().join("must-not-start.sh");
    fs::write(&agent, format!("#!/bin/sh\ntouch '{}'\n", marker.display()))?;
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
    let prompt = temp.path().join("prompt.md");
    fs::write(&prompt, "writable child must remain disabled\n")?;
    let incoming = temp.path().join("incoming");
    fs::create_dir(&incoming)?;
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
    let spec = ExternalAgentCommand::codex(
        &agent,
        temp.path(),
        &prompt,
        incoming.join("events.jsonl"),
        incoming.join("last-message.txt"),
        Duration::from_secs(5),
    );
    let context = test_review_context();
    let mut journal = RecordingPreActionJournal::default();

    let report = run_external_agent_cancellable_reviewed(
        &spec,
        &ProcessCancellation::new(),
        Some(ExternalPreActionReviewRuntime {
            context: &context,
            journal: &mut journal,
        }),
    );

    assert!(!marker.exists());
    assert!(!report.stdout.target_launch_attempted);
    assert_eq!(report.process_tree, None);
    assert_eq!(report.side_effects, None);
    assert!(report.environment_blocked());
    assert!(report
        .error
        .as_deref()
        .is_some_and(|error| error.contains("writable Codex failed closed before launch")));
    assert!(journal.records.is_empty());
    Ok(())
}

fn contained_fake_app_server(
    mode: &str,
    journal: &mut RecordingPreActionJournal,
    containment: crate::process_runner::ContainmentPolicy,
) -> std::result::Result<
    (
        InteractiveProcessOutput<codex_app_server::AppServerOutcome>,
        ReviewMetricSnapshot,
        Vec<GateDenial>,
        PathBuf,
    ),
    ProcessRunError,
> {
    let temp = tempfile::tempdir().expect("tempdir");
    let workspace = temp.keep();
    let marker = workspace.join("post-approval-action");
    let python = [
        PathBuf::from("/run/current-system/sw/bin/python3"),
        PathBuf::from("/usr/bin/python3"),
        PathBuf::from("/bin/python3"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("trusted python3");
    let script = r#"
import json, pathlib, sys
mode, marker = sys.argv[1], pathlib.Path(sys.argv[2])
def receive():
    line = sys.stdin.readline()
    assert line, "unexpected client EOF"
    return json.loads(line)
def send(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()
initialize = receive()
assert initialize["method"] == "initialize"
send({"id": initialize["id"], "result": {}})
assert receive()["method"] == "initialized"
thread_start = receive()
assert thread_start["method"] == "thread/start"
assert thread_start["params"]["approvalsReviewer"] == "user"
send({"id": thread_start["id"], "result": {
    "thread": {"id": "thread-contained"},
    "approvalPolicy": "on-request",
    "approvalsReviewer": "user",
    "activePermissionProfile": {"id": "maco_external_codex"},
    "cwd": sys.argv[3]
}})
turn_start = receive()
assert turn_start["method"] == "turn/start"
assert turn_start["params"]["approvalsReviewer"] == "user"
send({"id": turn_start["id"], "result": {
    "turn": {"id": "turn-contained", "status": "inProgress"}
}})
send({"method": "turn/started", "params": {
    "threadId": "thread-contained",
    "turn": {"id": "turn-contained", "status": "inProgress"}
}})
item = {"id": "item-contained", "type": "fileChange", "status": "inProgress"}
if mode in ("accept", "fallback_required"):
    item["changes"] = [{
        "path": "README.md",
        "kind": {"type": "update"},
        "diff": "bounded"
    }]
send({"method": "item/started", "params": {
    "threadId": "thread-contained",
    "turnId": "turn-contained",
    "item": item
}})
send({"id": 77, "method": "item/fileChange/requestApproval", "params": {
    "threadId": "thread-contained",
    "turnId": "turn-contained",
    "itemId": "item-contained",
    "startedAtMs": 1,
    "reason": "incomplete manifest"
}})
first = receive()
def send_auto_review(status):
    send({"method": "item/autoApprovalReview/started", "params": {
        "threadId": "thread-contained",
        "turnId": "turn-contained",
        "reviewId": "review-contained",
        "targetItemId": "item-contained",
        "startedAtMs": 1,
        "action": {"type": "applyPatch"},
        "review": {"status": "inProgress"}
    }})
    send({"method": "item/autoApprovalReview/completed", "params": {
        "threadId": "thread-contained",
        "turnId": "turn-contained",
        "reviewId": "review-contained",
        "targetItemId": "item-contained",
        "startedAtMs": 1,
        "completedAtMs": 2,
        "action": {"type": "applyPatch"},
        "decisionSource": "agent",
        "review": {
            "status": status,
            "rationale": "bounded fixture decision",
            "riskLevel": "low",
            "userAuthorization": "low"
        }
    }})
if mode in ("decline", "protocol_loss"):
    assert first["method"] == "turn/steer"
    assert first["params"]["threadId"] == "thread-contained"
    assert first["params"]["expectedTurnId"] == "turn-contained"
    assert "turnId" not in first["params"]
    assert first["params"]["input"][0]["text"].startswith("MACO_GATE_DENIAL_V1\n")
    send({"id": first["id"], "result": {}})
    decision = receive()
    assert decision["id"] == 77
    assert decision["result"]["decision"] == "decline"
    if decision["result"]["decision"] == "accept":
        marker.touch()
    if mode == "protocol_loss":
        sys.exit(0)
    send_auto_review("denied")
    send({"method": "item/completed", "params": {
        "threadId": "thread-contained",
        "turnId": "turn-contained",
        "completedAtMs": 2,
        "item": {"id": "item-contained", "type": "fileChange", "status": "declined"}
    }})
    send({"method": "turn/completed", "params": {
        "threadId": "thread-contained",
        "turn": {"id": "turn-contained", "status": "completed", "items": []}
    }})
elif mode in ("accept", "fallback_required"):
    assert first["id"] == 77
    assert first["result"]["decision"] == "accept"
    marker.touch()
    if mode == "accept":
        send_auto_review("approved")
    send({"method": "item/completed", "params": {
        "threadId": "thread-contained",
        "turnId": "turn-contained",
        "completedAtMs": 2,
        "item": {"id": "item-contained", "type": "fileChange", "status": "completed"}
    }})
    send({"method": "turn/completed", "params": {
        "threadId": "thread-contained",
        "turn": {"id": "turn-contained", "status": "completed", "items": []}
    }})
else:
    assert first["id"] == 77
    assert first["result"]["decision"] == "cancel"
    if first["result"]["decision"] == "accept":
        marker.touch()
"#;
    let script_path = workspace.join("fake-app-server.py");
    fs::write(&script_path, script).expect("write contained fake app-server fixture");
    let process_spec = ProcessSpec::direct(
        "contained fake app-server",
        &python,
        [
            script_path.as_os_str().to_os_string(),
            OsString::from(mode),
            marker.as_os_str().to_os_string(),
            workspace.as_os_str().to_os_string(),
        ],
        &workspace,
        256 * 1024,
    )
    .with_stdin_limit(256 * 1024)
    .with_timeout(Some(Duration::from_secs(5)))
    .with_containment(containment);
    let spec = ExternalAgentCommand::codex(
        &python,
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        workspace.join("report.json"),
        Duration::from_secs(5),
    );
    let context = test_review_context();
    let mut runtime = ExternalPreActionReviewRuntime {
        context: &context,
        journal,
    };
    let attempt = run_duplex_app_server_process(
        process_spec,
        &ProcessCancellation::new(),
        &spec,
        "bounded task".to_string(),
        &mut runtime,
    );
    Ok((
        attempt.process?,
        attempt.metrics,
        attempt.gate_denials,
        marker,
    ))
}

fn nonpublishable_trusted_compatibility_fake_app_server(
    mode: &str,
    journal: &mut RecordingPreActionJournal,
) -> (
    InteractiveProcessOutput<codex_app_server::AppServerOutcome>,
    ReviewMetricSnapshot,
    Vec<GateDenial>,
    PathBuf,
) {
    contained_fake_app_server(
        mode,
        journal,
        crate::process_runner::ContainmentPolicy::TrustedBestEffort,
    )
    .expect("trusted compatibility fake app-server process")
}

#[test]
fn nonpublishable_trusted_compatibility_fake_delivers_denial_before_decline() {
    let mut journal = RecordingPreActionJournal::default();
    let (result, metrics, gate_denials, marker) =
        nonpublishable_trusted_compatibility_fake_app_server("decline", &mut journal);

    if let Err(error) = &result.interaction {
        panic!(
            "completed duplex outcome: {error}; child stderr: {:?}",
            result.process.stderr.summarize_chars(2048)
        );
    }
    let outcome = result.interaction.expect("completed duplex outcome");
    assert_eq!(outcome.thread_id, "thread-contained");
    assert_eq!(outcome.turn_id, "turn-contained");
    assert_eq!(outcome.gate_denials.len(), 1);
    assert_eq!(gate_denials, outcome.gate_denials);
    assert!(!marker.exists());
    assert!(result.process.status.is_some_and(|status| status.success()));
    assert!(matches!(
        result.process.process_tree,
        ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
    ));
    assert_eq!(journal.records.len(), 3);
    assert_eq!(
        journal
            .records
            .iter()
            .map(|record| record.phase)
            .collect::<Vec<_>>(),
        vec![
            PreActionJournalPhase::ReviewDecision,
            PreActionJournalPhase::TurnTerminal,
            PreActionJournalPhase::ProcessTerminal
        ]
    );
    assert!(journal
        .records
        .windows(2)
        .all(|pair| pair[0].run_id == pair[1].run_id
            && pair[0].review_session_id == pair[1].review_session_id));
    assert!(journal.records[0].decision_latency_ms.is_some());
    assert_eq!(
        journal.records[0].rationale,
        PreActionJournalRationale::ClassifierFailClosed
    );
    assert_eq!(metrics.reviewed_action_denials.denominator, 1);
    assert_eq!(metrics.reviewed_action_denials.numerator, 1);
}

#[test]
fn nonpublishable_trusted_compatibility_fake_journals_before_marker() {
    let mut journal = RecordingPreActionJournal::default();
    let (result, metrics, gate_denials, marker) =
        nonpublishable_trusted_compatibility_fake_app_server("accept", &mut journal);

    let outcome = result.interaction.expect("completed duplex outcome");
    assert!(outcome.gate_denials.is_empty());
    assert!(gate_denials.is_empty());
    assert!(marker.exists());
    assert!(result.process.status.is_some_and(|status| status.success()));
    assert!(matches!(
        result.process.process_tree,
        ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
    ));
    assert_eq!(journal.records.len(), 3);
    assert_eq!(
        journal.records[0].phase,
        PreActionJournalPhase::ReviewDecision
    );
    assert_eq!(journal.records[0].allowed, Some(true));
    assert_eq!(
        journal.records[0].rationale,
        PreActionJournalRationale::DeterministicPolicyAllow
    );
    assert!(journal.records[0].decision_latency_ms.is_some());
    assert_eq!(metrics.reviewed_action_denials.denominator, 1);
    assert_eq!(metrics.reviewed_action_denials.numerator, 0);
}

#[test]
fn production_duplex_consumer_refuses_fallback_required_child_with_typed_denial() {
    let mut journal = RecordingPreActionJournal::default();
    let (result, metrics, gate_denials, marker) =
        nonpublishable_trusted_compatibility_fake_app_server("fallback_required", &mut journal);

    assert!(result
        .interaction
        .as_ref()
        .is_err_and(|error| error.contains("mandatory duplex pre-action fallback was required")));
    assert!(
        marker.exists(),
        "fixture must prove the child path was exercised"
    );
    assert!(result.process.status.is_some_and(|status| status.success()));
    assert_eq!(gate_denials.len(), 1);
    assert!(matches!(
        gate_denials[0].reason,
        crate::gate_denial::GateDenialReason::ApprovalReview {
            denial: crate::gate_denial::ApprovalReviewDenial::DuplexFallbackRequired
        }
    ));
    assert_eq!(
        gate_denials[0].retryability,
        crate::gate_denial::GateRetryability::NotRetryable
    );
    assert_eq!(
        gate_denials[0].next_safe_operation,
        crate::gate_denial::NextSafeOperation::RestorePreActionReviewService
    );
    assert_eq!(journal.records.len(), 3);
    assert_eq!(
        journal.records[1].rationale,
        PreActionJournalRationale::DuplexFallbackRequired
    );
    assert_eq!(journal.records[1].allowed, Some(false));
    assert_eq!(journal.records[1].denial.as_ref(), Some(&gate_denials[0]));
    assert_eq!(metrics.reviewed_action_denials.denominator, 1);
}

#[test]
fn nonpublishable_trusted_compatibility_fake_journal_failure_cancels() {
    let mut journal = RecordingPreActionJournal {
        records: Vec::new(),
        fail: true,
    };
    let (result, metrics, gate_denials, marker) =
        nonpublishable_trusted_compatibility_fake_app_server("cancel", &mut journal);

    assert!(result.interaction.is_err());
    assert!(!marker.exists());
    assert!(result.process.status.is_some_and(|status| status.success()));
    assert!(matches!(
        result.process.process_tree,
        ProcessTreeEvidence::TrustedBestEffort(ContainmentBackend::UnixProcessGroup)
    ));
    assert!(journal.records.is_empty());
    assert_eq!(gate_denials.len(), 1);
    assert_eq!(metrics.reviewed_action_denials.denominator, 1);
}

#[test]
fn nonpublishable_trusted_compatibility_protocol_loss_retains_evidence() {
    let mut journal = RecordingPreActionJournal::default();
    let (result, metrics, gate_denials, marker) =
        nonpublishable_trusted_compatibility_fake_app_server("protocol_loss", &mut journal);

    assert!(result.interaction.is_err());
    assert!(!marker.exists());
    assert_eq!(gate_denials.len(), 1);
    assert_eq!(
        journal
            .records
            .iter()
            .map(|record| record.phase)
            .collect::<Vec<_>>(),
        vec![
            PreActionJournalPhase::ReviewDecision,
            PreActionJournalPhase::ProcessTerminal
        ]
    );
    assert_eq!(
        journal.records[0].review_session_id,
        journal.records[1].review_session_id
    );
    assert_eq!(journal.records[0].run_id, journal.records[1].run_id);
    assert!(journal.records[1].thread_id.is_none());
    assert!(journal.records[1].turn_id.is_none());
    assert!(!journal.records[1].review_session_id.is_empty());

    let temp = tempfile::tempdir().expect("tempdir");
    let spec = ExternalAgentCommand::codex(
        "codex",
        temp.path(),
        temp.path().join("prompt"),
        temp.path().join("events"),
        temp.path().join("report"),
        Duration::from_secs(1),
    );
    let mut report = failed_external_run(
        &spec,
        Instant::now(),
        vec!["codex".to_string()],
        false,
        "protocol loss".to_string(),
    );
    report.stdout.run_metadata.gate_denials = gate_denials.clone();
    report.stdout.run_metadata.pre_action_review_metrics = Some(metrics.clone());
    let serialized = serde_json::to_vec(&report).expect("serialize retained review evidence");
    let restored: ExternalAgentRun =
        serde_json::from_slice(&serialized).expect("deserialize retained review evidence");
    assert_eq!(restored.gate_denials(), gate_denials);
    assert_eq!(restored.pre_action_review_metrics(), Some(&metrics));
}

#[cfg(target_os = "linux")]
#[test]
fn verified_contained_fake_app_server_proves_duplex_ordering_and_confinement() {
    skip_without_containment!();
    let mut allow_journal = RecordingPreActionJournal::default();
    let (allow, allow_metrics, allow_denials, allow_marker) = match contained_fake_app_server(
        "accept",
        &mut allow_journal,
        crate::process_runner::ContainmentPolicy::Required,
    ) {
        Ok(result) => result,
        Err(ProcessRunError::ContainmentUnavailable { .. }) => return,
        Err(error) => panic!("verified fake app-server capability probe failed: {error:?}"),
    };
    assert!(allow.process.safety_evidence_verified());
    assert!(allow.process.process_tree.is_verified_empty());
    assert!(allow.process.side_effects.is_verified());
    assert!(allow.interaction.is_ok());
    assert!(allow_marker.exists());
    assert!(allow_denials.is_empty());
    assert_eq!(allow_journal.records[0].allowed, Some(true));
    assert_eq!(allow_metrics.reviewed_action_denials.denominator, 1);

    let mut decline_journal = RecordingPreActionJournal::default();
    let (decline, decline_metrics, decline_denials, decline_marker) = contained_fake_app_server(
        "decline",
        &mut decline_journal,
        crate::process_runner::ContainmentPolicy::Required,
    )
    .expect("verified denial fake app-server");
    assert!(decline.process.safety_evidence_verified());
    assert!(decline.process.process_tree.is_verified_empty());
    assert!(decline.process.side_effects.is_verified());
    let decline_outcome = decline.interaction.expect("denial protocol outcome");
    assert_eq!(decline_outcome.gate_denials, decline_denials);
    assert_eq!(decline_denials.len(), 1);
    assert!(!decline_marker.exists());
    assert_eq!(decline_journal.records[0].allowed, Some(false));
    assert_eq!(decline_metrics.reviewed_action_denials.numerator, 1);

    let mut failed_journal = RecordingPreActionJournal {
        records: Vec::new(),
        fail: true,
    };
    let (cancel, cancel_metrics, cancel_denials, cancel_marker) = contained_fake_app_server(
        "cancel",
        &mut failed_journal,
        crate::process_runner::ContainmentPolicy::Required,
    )
    .expect("verified journal-failure fake app-server");
    assert!(cancel.process.safety_evidence_verified());
    assert!(cancel.process.process_tree.is_verified_empty());
    assert!(cancel.process.side_effects.is_verified());
    assert!(cancel.interaction.is_err());
    assert_eq!(cancel_denials.len(), 1);
    assert!(!cancel_marker.exists());
    assert!(failed_journal.records.is_empty());
    assert_eq!(cancel_metrics.reviewed_action_denials.denominator, 1);

    let mut loss_journal = RecordingPreActionJournal::default();
    let (loss, loss_metrics, loss_denials, loss_marker) = contained_fake_app_server(
        "protocol_loss",
        &mut loss_journal,
        crate::process_runner::ContainmentPolicy::Required,
    )
    .expect("verified protocol-loss fake app-server");
    assert!(loss.process.safety_evidence_verified());
    assert!(loss.process.process_tree.is_verified_empty());
    assert!(loss.process.side_effects.is_verified());
    assert!(loss.interaction.is_err());
    assert_eq!(loss_denials.len(), 1);
    assert!(!loss_marker.exists());
    assert_eq!(loss_metrics.reviewed_action_denials.numerator, 1);
    assert_eq!(
        loss_journal
            .records
            .iter()
            .map(|record| record.phase)
            .collect::<Vec<_>>(),
        vec![
            PreActionJournalPhase::ReviewDecision,
            PreActionJournalPhase::ProcessTerminal
        ]
    );
}

fn create_mandatory_control_roots(workspace: &Path) -> Result<()> {
    fs::create_dir_all(workspace)?;
    fs::create_dir_all(workspace.join(".git"))?;
    for root in PERMANENT_CONTROL_ROOTS.iter().chain(POLICY_CONTROL_ROOTS) {
        fs::create_dir_all(workspace.join(root))?;
    }
    Ok(())
}

#[test]
fn environment_preflight_requirements_are_bounded_and_canonical() {
    let cargo = EnvironmentRequirement::executable(
        EnvironmentExecutable::Cargo,
        Some(EnvironmentVersionConstraint::at_least(
            EnvironmentVersion::new(1, 89, 0),
        )),
    );
    assert!(validate_environment_requirements(std::slice::from_ref(&cargo)).is_ok());
    assert!(validate_environment_requirements(&[cargo.clone(), cargo])
        .expect_err("duplicate executable requirement must fail")
        .to_string()
        .contains("duplicate executable requirement"));

    let empty_range = EnvironmentRequirement::executable(
        EnvironmentExecutable::Rustc,
        Some(EnvironmentVersionConstraint {
            minimum_inclusive: None,
            maximum_exclusive: None,
        }),
    );
    assert!(validate_environment_requirements(&[empty_range])
        .expect_err("empty range must fail")
        .to_string()
        .contains("at least one bound"));

    let reversed_range = EnvironmentRequirement::executable(
        EnvironmentExecutable::Rustc,
        Some(EnvironmentVersionConstraint::bounded(
            EnvironmentVersion::new(2, 0, 0),
            EnvironmentVersion::new(1, 0, 0),
        )),
    );
    assert!(validate_environment_requirements(&[reversed_range])
        .expect_err("reversed range must fail")
        .to_string()
        .contains("below its exclusive maximum"));

    let oversized = (0..=MAX_ENVIRONMENT_REQUIREMENTS)
        .map(|_| EnvironmentRequirement::network(EnvironmentNetworkAccess::Disabled))
        .collect::<Vec<_>>();
    assert!(validate_environment_requirements(&oversized)
        .expect_err("oversized list must fail before probing")
        .to_string()
        .contains("fixed limit"));
    assert!(validate_environment_requirements(&[
        EnvironmentRequirement::network(EnvironmentNetworkAccess::Disabled),
        EnvironmentRequirement::network(EnvironmentNetworkAccess::Enabled),
    ])
    .expect_err("conflicting network requirements must fail")
    .to_string()
    .contains("one canonical network requirement"));
    let configuration =
        EnvironmentRequirement::configuration(EnvironmentConfiguration::CodexAuthFile);
    assert!(
        validate_environment_requirements(&[configuration.clone(), configuration,])
            .expect_err("duplicate configuration requirement must fail")
            .to_string()
            .contains("duplicate configuration requirement")
    );
}

#[test]
fn environment_failure_category_spellings_are_stable() -> Result<()> {
    let categories = [
        (
            EnvironmentFailureCategory::MissingExecutable,
            "missing_executable",
        ),
        (
            EnvironmentFailureCategory::VersionMismatch,
            "version_mismatch",
        ),
        (
            EnvironmentFailureCategory::MissingCredential,
            "missing_credential",
        ),
        (
            EnvironmentFailureCategory::NetworkForbidden,
            "network_forbidden",
        ),
        (
            EnvironmentFailureCategory::SandboxUnavailable,
            "sandbox_unavailable",
        ),
        (EnvironmentFailureCategory::ProbeFailed, "probe_failed"),
        (
            EnvironmentFailureCategory::RuntimeModelCatalogUnavailable,
            "runtime_model_catalog_unavailable",
        ),
    ];
    for (category, spelling) in categories {
        assert_eq!(serde_json::to_value(category)?, spelling);
    }
    Ok(())
}

#[test]
fn runtime_model_catalog_rejects_custom_executable_with_typed_failure() {
    let failure = load_codex_runtime_model_catalog(
        Path::new("/tmp/untrusted-custom-codex"),
        Path::new("."),
        Duration::from_secs(1),
    )
    .expect_err("custom executable must not acquire runtime catalog auth or network access");

    assert_eq!(
        failure.category,
        EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
    );
    assert!(failure.requirement.is_none());
    assert!(failure
        .summary
        .contains("explicit custom executables receive no auth or provider network access"));
    assert!(!failure.remediation.is_empty());
}

#[test]
fn typed_preparation_failure_pairs_named_requirement_with_blocked_result() {
    let command = ExternalAgentCommand::codex(
        "codex",
        ".",
        "prompt",
        "events",
        "report",
        Duration::from_secs(1),
    );
    let requirement =
        EnvironmentRequirement::sandbox(EnvironmentSandboxCapability::VerifiedExternalCodex);
    let run = failed_external_environment_run(
        &command,
        Instant::now(),
        vec!["codex".to_string()],
        false,
        EnvironmentFailureCategory::SandboxUnavailable,
        Some(requirement.clone()),
        "sandbox preparation failed".to_string(),
    );
    assert_eq!(run.environment_failures().len(), 1);
    assert_eq!(run.environment_preflight_results().len(), 1);
    assert_eq!(
        run.environment_preflight_results()[0],
        EnvironmentPreflightResult {
            requirement,
            status: EnvironmentPreflightStatus::Blocked,
            observation: None,
        }
    );
}

#[test]
fn target_process_classification_types_only_environment_capability_failures() {
    let setup_timeout = ProcessRunError::SetupTimeout {
        label: "external agent".to_string(),
        command: "codex exec".to_string(),
        phase: "target setup",
        source: std::io::Error::other("injected setup timeout"),
    };
    let cancellation = ProcessRunError::Cancelled {
        label: "external agent".to_string(),
        command: "codex exec".to_string(),
        phase: "target runtime",
        evidence: None,
    };
    let containment = ProcessRunError::ContainmentUnavailable {
        label: "external agent".to_string(),
        command: "codex exec".to_string(),
        source: std::io::Error::other("injected containment refusal"),
    };
    let environment = ProcessRunError::EnvironmentFailure {
        label: "external agent".to_string(),
        command: "/tmp/maco-target/debug/probe".to_string(),
        failure: Box::new(EnvironmentFailure::sandbox_unavailable(
            "PrivateTmp hides /tmp/maco-target/debug/probe".to_string(),
        )),
        target_process_started: false,
    };

    assert_eq!(target_process_environment_failure(&setup_timeout), None);
    assert_eq!(target_process_environment_failure(&cancellation), None);
    assert_eq!(
        target_process_environment_failure(&containment),
        Some((
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(EnvironmentRequirement::sandbox(
                EnvironmentSandboxCapability::VerifiedExternalCodex,
            )),
        ))
    );
    assert_eq!(
        target_process_environment_failure(&environment),
        Some((
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(EnvironmentRequirement::sandbox(
                EnvironmentSandboxCapability::VerifiedExternalCodex,
            )),
        ))
    );
    assert!(process_run_error_definitely_before_process_start(
        &environment
    ));
}

#[test]
fn environment_preflight_wire_is_presence_only_and_backward_compatible() -> Result<()> {
    let secret = "DO_NOT_SERIALIZE_environment_secret";
    let environment = BTreeMap::from([("OPENAI_API_KEY".to_string(), secret.to_string())]);
    assert!(credential_present(
        EnvironmentCredential::OpenAiApiKey,
        &environment
    ));
    let config_requirement =
        EnvironmentRequirement::configuration(EnvironmentConfiguration::CodexAuthFile);
    let config_wire = serde_json::to_string(&config_requirement)?;
    assert_eq!(
        config_wire,
        r#"{"kind":"configuration","configuration":"codex_auth_file"}"#
    );
    assert!(!config_wire.contains(secret));

    let command = ExternalAgentCommand::codex(
        "codex",
        ".",
        "prompt",
        "events",
        "report",
        Duration::from_secs(1),
    );
    let requirement = EnvironmentRequirement::credential(EnvironmentCredential::OpenAiApiKey);
    let mut run = failed_external_run(
        &command,
        Instant::now(),
        vec!["codex".to_string()],
        false,
        "environment blocked".to_string(),
    );
    run.stdout
        .run_metadata
        .environment_preflight_results
        .push(EnvironmentPreflightResult {
            requirement: requirement.clone(),
            status: EnvironmentPreflightStatus::Blocked,
            observation: None,
        });
    run.stdout
        .run_metadata
        .environment_failures
        .push(environment_failure(
            EnvironmentFailureCategory::MissingCredential,
            Some(requirement),
            "required credential source is absent".to_string(),
        ));

    assert!(!run.stdout.target_launch_attempted);
    assert!(run.scratch_quiescence_verified());
    let serialized = serde_json::to_string(&run)?;
    let debug = format!("{run:?}");
    assert!(!serialized.contains(secret));
    assert!(!debug.contains(secret));
    assert!(serialized.contains("\"environment_failures\""));
    assert!(serialized.contains("\"missing_credential\""));

    let restored: ExternalAgentRun = serde_json::from_str(&serialized)?;
    assert!(restored.environment_blocked());
    assert!(!restored.scratch_quiescence_verified());
    assert_eq!(
        restored.environment_preflight_results(),
        run.environment_preflight_results()
    );
    assert_eq!(restored.environment_failures(), run.environment_failures());

    let mut legacy_process_state = serde_json::to_value(&run)?;
    legacy_process_state
        .as_object_mut()
        .context("serialized external run must be an object")?
        .remove("environment_preflight_process_started");
    let restored_process_state: ExternalAgentRun = serde_json::from_value(legacy_process_state)?;
    assert!(restored_process_state.environment_blocked());
    assert!(!restored_process_state.environment_preflight_quiescence_verified());
    assert!(!restored_process_state.scratch_quiescence_verified());

    let mut verified_legacy_process_state = serde_json::to_value(&run)?;
    let verified_legacy_object = verified_legacy_process_state
        .as_object_mut()
        .context("serialized external run must be an object")?;
    verified_legacy_object.remove("environment_preflight_process_started");
    verified_legacy_object.insert(
        "process_tree".to_string(),
        serde_json::to_value(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService,
        ))?,
    );
    verified_legacy_object.insert(
        "side_effects".to_string(),
        serde_json::to_value(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::ExternalCodex,
        ))?,
    );
    let restored_verified_legacy: ExternalAgentRun =
        serde_json::from_value(verified_legacy_process_state)?;
    assert!(restored_verified_legacy.environment_preflight_quiescence_verified());
    assert!(restored_verified_legacy.scratch_quiescence_verified());

    let mut legacy = serde_json::to_value(&run)?;
    let object = legacy
        .as_object_mut()
        .context("serialized external run must be an object")?;
    object.remove("environment_preflight_results");
    object.remove("environment_failures");
    let restored_legacy: ExternalAgentRun = serde_json::from_value(legacy)?;
    assert!(restored_legacy.environment_preflight_results().is_empty());
    assert!(restored_legacy.environment_failures().is_empty());
    assert!(!restored_legacy.environment_blocked());
    Ok(())
}

#[test]
fn credential_redaction_covers_reports_json_logs_and_materialized_auth_values() -> Result<()> {
    let environment_secret = r#"environment-secret-"quoted"-31"#;
    let auth_secret = "materialized-auth-token-secret-31";
    let environment =
        BTreeMap::from([("OPENAI_API_KEY".to_string(), environment_secret.to_string())]);
    let auth_bytes = serde_json::to_vec(&serde_json::json!({
        "tokens": {"access_token": auth_secret}
    }))?;
    let auth = ValidatedCodexAuth {
        path: PathBuf::from("/private/auth.json"),
        length: auth_bytes.len() as u64,
        modified: None,
        #[cfg(unix)]
        device: 1,
        #[cfg(unix)]
        inode: 2,
        bytes: auth_bytes,
    };
    let redactor = CredentialRedactor::from_runtime(&environment, Some(&auth))?;
    let output = format!(
        "raw={environment_secret} escaped={} auth={auth_secret}",
        serde_json::to_string(environment_secret)?
    );
    let redacted = redactor.redact_string(&output);
    assert!(!redacted.contains(environment_secret));
    assert!(!redacted.contains(auth_secret));
    assert!(redacted.contains("[REDACTED]"));
    assert!(!format!("{redactor:?}").contains(environment_secret));

    let temp = tempfile::tempdir()?;
    let root = temp.path().join("redacted-log");
    let mut reservation =
        SecureOutputRoot::open_or_create(&root)?.reserve(OsStr::new("events.jsonl"))?;
    write_redacted_json_log(&mut reservation, output.as_bytes(), &redactor)?;
    let persisted = String::from_utf8(reservation.read_bounded(OUTPUT_TEE_LIMIT_BYTES)?)?;
    assert!(!persisted.contains(environment_secret));
    assert!(!persisted.contains(auth_secret));
    assert!(persisted.contains("[REDACTED]"));

    let oversized_values = (0..=MAX_CREDENTIAL_REDACTION_PATTERNS)
        .map(|index| format!("distinct-credential-pattern-{index:04}-31"))
        .collect::<Vec<_>>();
    let oversized_bytes = serde_json::to_vec(&oversized_values)?;
    let oversized_auth = ValidatedCodexAuth {
        path: PathBuf::from("/private/oversized-auth.json"),
        length: oversized_bytes.len() as u64,
        modified: None,
        #[cfg(unix)]
        device: 1,
        #[cfg(unix)]
        inode: 3,
        bytes: oversized_bytes,
    };
    assert!(
        CredentialRedactor::from_runtime(&BTreeMap::new(), Some(&oversized_auth))
            .expect_err("oversized redaction pattern set must fail closed")
            .to_string()
            .contains("fixed count or aggregate-byte safety bound")
    );
    let short_auth_bytes = serde_json::to_vec(&serde_json::json!({"access_token": "too-short"}))?;
    let short_auth = ValidatedCodexAuth {
        path: PathBuf::from("/private/short-auth.json"),
        length: short_auth_bytes.len() as u64,
        modified: None,
        #[cfg(unix)]
        device: 1,
        #[cfg(unix)]
        inode: 4,
        bytes: short_auth_bytes,
    };
    assert!(
        CredentialRedactor::from_runtime(&BTreeMap::new(), Some(&short_auth))
            .expect_err("short credential-bearing auth value must fail closed")
            .to_string()
            .contains("shorter than the safe redaction bound")
    );
    let opaque_bytes = vec![b'x'; MAX_CREDENTIAL_BYTES + 1];
    let opaque_auth = ValidatedCodexAuth {
        path: PathBuf::from("/private/opaque-auth.json"),
        length: opaque_bytes.len() as u64,
        modified: None,
        #[cfg(unix)]
        device: 1,
        #[cfg(unix)]
        inode: 5,
        bytes: opaque_bytes,
    };
    assert!(
        CredentialRedactor::from_runtime(&BTreeMap::new(), Some(&opaque_auth))
            .expect_err("opaque oversized auth must fail closed")
            .to_string()
            .contains("not valid JSON for bounded redaction")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn private_output_staging_redacts_atomic_publication_and_cleans_up() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let runtime_root = temp.path().join("private-runtime");
    let destination_root = temp.path().join("destination");
    for path in [&workspace, &runtime_root, &destination_root] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let destination_path = destination_root.join("report.json");
    let mut destination = reserve_external_output(&destination_path)?;
    let secret = "private-staging-secret-value-31";
    let redactor = CredentialRedactor::from_runtime(
        &BTreeMap::from([("OPENAI_API_KEY".to_string(), secret.to_string())]),
        None,
    )?;

    let mut staging = ExternalOutputStaging::create_under(&runtime_root, &workspace)?;
    let staging_root = staging.root_path().to_path_buf();
    let staging_path = staging.path()?.to_path_buf();
    assert!(staging_root.starts_with(&runtime_root));
    assert!(!staging_root.starts_with(&workspace));
    assert_eq!(
        fs::metadata(&staging_root)?.permissions().mode() & 0o777,
        0o700
    );
    staging
        .reservation_mut()?
        .write_bytes_atomic(secret.as_bytes(), OUTPUT_TEE_LIMIT_BYTES)?;
    assert_eq!(destination.read_bounded(OUTPUT_TEE_LIMIT_BYTES)?, b"");

    let published =
        capture_redacted_staged_output(staging.reservation()?, &mut destination, &redactor)?;
    assert_eq!(published, CREDENTIAL_REDACTION);
    assert_eq!(
        destination.read_bounded(OUTPUT_TEE_LIMIT_BYTES)?,
        CREDENTIAL_REDACTION
    );
    assert_eq!(
        staging
            .reservation()?
            .read_bounded(OUTPUT_TEE_LIMIT_BYTES)?,
        secret.as_bytes()
    );

    staging.cleanup()?;
    assert!(!staging_path.exists());
    assert!(!staging_root.exists());

    let dropped_root = {
        let mut staging = ExternalOutputStaging::create_under(&runtime_root, &workspace)?;
        staging
            .reservation_mut()?
            .write_bytes_atomic(secret.as_bytes(), OUTPUT_TEE_LIMIT_BYTES)?;
        staging.root_path().to_path_buf()
    };
    assert!(!dropped_root.exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn machine_global_claim_refuses_real_output_staging_cleanup_and_drop_preserves() -> Result<()> {
    use crate::gate_denial::{DestructiveTargetDenial, GateDenialReason};
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let runtime_root = temp.path().join("private-runtime");
    let state_root = temp.path().join("machine-global-state");
    for path in [&workspace, &runtime_root, &state_root] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let config = temp.path().join("machine-global.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "state_root": state_root,
            "roots": [{
                "id": "runtime",
                "path": runtime_root,
                "protected_paths": [],
                "quarantine_grace_seconds": 60
            }]
        }))?,
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;

    let binding = ExternalMachineGlobalRetentionBinding {
        config: config.clone(),
        root_id: "runtime".to_string(),
        owner: "cleanup-agent".to_string(),
        correction_correlation_id: "cleanup-correlation".to_string(),
    };
    let mut staging = ExternalOutputStaging::create_under_with_retention(
        &runtime_root,
        &workspace,
        Some(binding),
    )?;
    staging
        .reservation_mut()?
        .write_bytes_atomic(b"irrecoverable", OUTPUT_TEE_LIMIT_BYTES)?;
    let staging_root = staging.root_path().to_path_buf();
    let staging_path = staging.path()?.to_path_buf();

    let repair_store = MachineGlobalStore::open_config(&config)?;
    let coordinate = repair_store.coordinate_for_existing_directory("runtime", &staging_root)?;
    let claim = repair_store.claim(
        "repair-agent",
        "repair-correlation",
        vec![coordinate.clone()],
    )?;
    assert!(matches!(claim, GateOutcome::Allowed(_)));

    let denial = match staging.cleanup()? {
        ExternalOutputCleanup::Denied(denial) => denial,
        ExternalOutputCleanup::Quarantined(_) => {
            panic!("active repair claim must prevent staging quarantine")
        }
        ExternalOutputCleanup::Bypassed(_) => {
            panic!("bound staging cleanup must not bypass the gate")
        }
    };
    assert!(matches!(
        denial.reason,
        GateDenialReason::DestructiveTarget {
            denial
        } if matches!(
            denial.as_ref(),
            DestructiveTargetDenial::ActiveClaimIntersection {
                target,
                active_claim
            } if target == &coordinate && active_claim == &coordinate
        )
    ));
    assert_eq!(fs::read(&staging_path)?, b"irrecoverable");
    assert!(staging_root.exists());
    assert!(repair_store.status()?.retention_operations.is_empty());

    drop(staging);
    assert!(staging_root.exists(), "Drop must not bypass a gate denial");
    assert_eq!(fs::read(staging_path)?, b"irrecoverable");
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn unbound_output_staging_cleanup_is_attributed_in_run_wire() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let runtime_root = temp.path().join("private-runtime");
    for path in [&workspace, &runtime_root] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let mut staging = ExternalOutputStaging::create_under(&runtime_root, &workspace)?;
    let attribution = match staging.cleanup()? {
        ExternalOutputCleanup::Bypassed(attribution) => attribution,
        ExternalOutputCleanup::Quarantined(_) | ExternalOutputCleanup::Denied(_) => {
            panic!("unbound cleanup must report its cooperative bypass")
        }
    };
    assert_eq!(
        attribution,
        MachineGlobalBypassAttribution {
            actor: "maco-external-agent".to_string(),
            operation: "delete_private_output_staging".to_string(),
            process_attribution: "not_process_observable".to_string(),
            reason: "no explicit machine-global config/root binding was supplied".to_string(),
        }
    );

    create_mandatory_control_roots(&workspace)?;
    let agent = workspace.join("fake-agent.sh");
    fs::write(
        &agent,
        r#"#!/bin/sh
while IFS= read -r _line; do
    :
done
printf '{"type":"done"}\n'
"#,
    )?;
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o755))?;
    let prompt = workspace.join("prompt");
    fs::write(&prompt, b"exercise unbound staging cleanup\n")?;
    let output = workspace.join("output");
    fs::create_dir(&output)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    let command = ExternalAgentCommand::codex(
        agent,
        &workspace,
        prompt,
        output.join("run.jsonl"),
        output.join("last-message"),
        Duration::from_secs(3),
    );
    let report = run_external_agent_nonpublishable_simulation(&command);
    assert_eq!(report.exit_code, Some(0), "{report:?}");
    assert_eq!(report.error, None, "{report:?}");
    assert_eq!(
        report.machine_global_bypasses(),
        std::slice::from_ref(&attribution)
    );

    let restored: ExternalAgentRun = serde_json::from_slice(&serde_json::to_vec(&report)?)?;
    assert_eq!(restored.machine_global_bypasses(), &[attribution]);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn allowed_output_staging_quarantine_persists_private_purge_receipt() -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let runtime_root = temp.path().join("private-runtime");
    let state_root = temp.path().join("machine-global-state");
    let artifact_root = temp.path().join("private-artifacts");
    for path in [&workspace, &runtime_root, &state_root, &artifact_root] {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let config = temp.path().join("machine-global.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "state_root": state_root,
            "roots": [{
                "id": "runtime",
                "path": runtime_root,
                "protected_paths": [],
                "quarantine_grace_seconds": 60
            }]
        }))?,
    )?;
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;
    let binding = ExternalMachineGlobalRetentionBinding {
        config: config.clone(),
        root_id: "runtime".to_string(),
        owner: "cleanup-agent".to_string(),
        correction_correlation_id: "cleanup-correlation".to_string(),
    };
    let mut staging = ExternalOutputStaging::create_under_with_retention(
        &runtime_root,
        &workspace,
        Some(binding),
    )?;
    let staging_root = staging.root_path().to_path_buf();
    staging
        .reservation_mut()?
        .write_bytes_atomic(b"private", OUTPUT_TEE_LIMIT_BYTES)?;

    let operation = match staging.cleanup()? {
        ExternalOutputCleanup::Quarantined(operation) => operation,
        ExternalOutputCleanup::Denied(_) | ExternalOutputCleanup::Bypassed(_) => {
            panic!("unclaimed bound staging must be recoverably quarantined")
        }
    };
    assert!(!staging_root.exists());
    let json_log = artifact_root.join("run.jsonl");
    persist_machine_global_retention_receipt(&json_log, &operation)?;
    let receipt_path = artifact_root.join(format!(
        "machine-global-retention-{}.private.json",
        operation.id.get()
    ));
    let metadata = fs::metadata(&receipt_path)?;
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    let restored: RetentionOperation = serde_json::from_slice(&fs::read(receipt_path)?)?;
    assert_eq!(restored, operation);
    assert_eq!(
        MachineGlobalStore::open_config(config)?
            .status()?
            .retention_operations
            .len(),
        1
    );
    Ok(())
}

#[test]
fn environment_preflight_parses_fixed_tool_versions_without_weakening_codex_marker() {
    assert_eq!(
        parse_environment_version(
            EnvironmentExecutable::Bash,
            "warning: helper 99.98.97\nGNU bash, version 5.3.9(1)-release"
        ),
        Some(EnvironmentVersion::new(5, 3, 9))
    );
    assert_eq!(
        parse_environment_version(
            EnvironmentExecutable::Git,
            "warning: helper 99.98.97\ngit version 2.51.0"
        ),
        Some(EnvironmentVersion::new(2, 51, 0))
    );
    assert_eq!(
        parse_environment_version(
            EnvironmentExecutable::Node,
            "warning: helper 99.98.97\nv22.17.0"
        ),
        Some(EnvironmentVersion::new(22, 17, 0))
    );
    assert_eq!(parse_codex_version("unrelated-tool 0.142.0"), None);
    assert_eq!(parse_codex_version("codex-cli 0.142.0"), Some((0, 142, 0)));
    assert_eq!(
        parse_codex_version("warning: helper 99.98.97\ncodex-cli 0.142.0"),
        Some((0, 142, 0))
    );
    assert_eq!(
        parse_codex_version("warning 99.98.97 before codex-cli 0.142.0"),
        None
    );
    assert_eq!(
        parse_environment_version(EnvironmentExecutable::Cargo, "cargo 99.98.97\ncargo 1.89.0"),
        None
    );
    assert_eq!(
        parse_environment_version(EnvironmentExecutable::Node, "99.98.97\n22.17.0"),
        None
    );
    assert_eq!(
        parse_codex_version("codex 99.98.97\ncodex-cli 0.142.0"),
        None
    );
}

#[test]
fn environment_preflight_uses_the_target_runtime_context() {
    let environment = BTreeMap::from([
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("PATH".to_string(), TRUSTED_PATH.to_string()),
    ]);
    let profile =
        SideEffectConfinementProfile::ExternalCodex(ExternalCodexProfile::read_only("/workspace"));
    let lifecycle = AgentLaunchMetadata {
        role: "worker".to_string(),
        run_id: "run-31".to_string(),
        task_id: "task-31".to_string(),
        repo: PathBuf::from("/registry"),
    };
    let prepared = with_external_runtime_context(
        ProcessSpec::direct(
            "fixed probe",
            "/run/current-system/sw/bin/true",
            std::iter::empty::<&str>(),
            "/workspace",
            128,
        ),
        environment.clone(),
        profile.clone(),
        None,
        Some(&lifecycle),
    );

    let mut expected_environment = environment;
    expected_environment.insert(MACO_RUN_ID_ENV.to_string(), "run-31".to_string());
    expected_environment.insert(MACO_TASK_ID_ENV.to_string(), "task-31".to_string());
    assert_eq!(
        prepared.environment,
        EnvironmentMode::ClearAndSet(expected_environment)
    );
    assert_eq!(prepared.agent_lifecycle, Some(lifecycle));
    assert_eq!(prepared.side_effects, profile);
    assert!(prepared.private_runtime_home);
    assert!(prepared.private_runtime_codex_home);
}

#[test]
fn environment_preflight_classifies_static_blockers_without_launching_probes() {
    let cancellation = ProcessCancellation::new();
    let environment = BTreeMap::new();
    let wrong_profile = SideEffectConfinementProfile::StrictOfflineWorkspace(
        StrictOfflineWorkspaceProfile::read_only("/workspace"),
    );
    let cases = [
        (
            EnvironmentRequirement::credential(EnvironmentCredential::OpenAiApiKey),
            None,
            None,
            EnvironmentFailureCategory::MissingCredential,
        ),
        (
            EnvironmentRequirement::network(EnvironmentNetworkAccess::Enabled),
            Some(EnvironmentVersion::new(0, 142, 0)),
            Some(SideEffectConfinementProfileKind::ExternalCodex),
            EnvironmentFailureCategory::NetworkForbidden,
        ),
        (
            EnvironmentRequirement::sandbox(EnvironmentSandboxCapability::VerifiedExternalCodex),
            Some(EnvironmentVersion::new(0, 142, 0)),
            None,
            EnvironmentFailureCategory::SandboxUnavailable,
        ),
        (
            EnvironmentRequirement::executable(
                EnvironmentExecutable::Codex,
                Some(EnvironmentVersionConstraint::at_least(
                    EnvironmentVersion::new(1, 0, 0),
                )),
            ),
            Some(EnvironmentVersion::new(0, 142, 0)),
            Some(SideEffectConfinementProfileKind::ExternalCodex),
            EnvironmentFailureCategory::VersionMismatch,
        ),
    ];

    for (requirement, codex_version, verified_confinement, expected_category) in cases {
        let mut process_evidence = EnvironmentPreflightProcessEvidence::default();
        let (result, failure, timed_out) = evaluate_environment_requirement(
            &requirement,
            Path::new("/workspace"),
            Duration::from_secs(1),
            &cancellation,
            &environment,
            &wrong_profile,
            None,
            codex_version,
            verified_confinement,
            None,
            &mut process_evidence,
        );
        assert_eq!(result.status, EnvironmentPreflightStatus::Blocked);
        assert_eq!(
            failure.map(|failure| failure.category),
            Some(expected_category)
        );
        assert!(!timed_out);
    }

    let disabled_network = EnvironmentRequirement::network(EnvironmentNetworkAccess::Disabled);
    let mut process_evidence = EnvironmentPreflightProcessEvidence::default();
    let (result, failure, _) = evaluate_environment_requirement(
        &disabled_network,
        Path::new("/workspace"),
        Duration::from_secs(1),
        &cancellation,
        &environment,
        &wrong_profile,
        None,
        Some(EnvironmentVersion::new(0, 142, 0)),
        None,
        None,
        &mut process_evidence,
    );
    assert_eq!(result.status, EnvironmentPreflightStatus::Blocked);
    assert_eq!(
        failure.map(|failure| failure.category),
        Some(EnvironmentFailureCategory::SandboxUnavailable)
    );
}

#[test]
fn executable_remediation_separates_project_and_persistent_nixos_changes() {
    let remediations = environment_remediation(EnvironmentFailureCategory::MissingExecutable);
    assert_eq!(remediations.len(), 2);
    assert_eq!(
        remediations[0].scope,
        EnvironmentRemediationScope::ProjectLocal
    );
    assert_eq!(
        remediations[1].scope,
        EnvironmentRemediationScope::PersistentNixosHostSoftware
    );
    let text = remediations
        .iter()
        .map(|remediation| remediation.guidance.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(text.contains("dev shell"));
    assert!(text.contains("declarative nixos"));
    assert!(!text.contains("apt"));
    assert!(!text.contains("dnf"));
    assert!(!text.contains("auto-install"));
}

#[test]
fn absent_model_selection_preserves_the_exact_hardened_codex_argv() {
    let command = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(1),
    );
    let actual = command_argv(&command)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let expected = vec![
            "-a",
            "never",
            "exec",
            "--strict-config",
            "--ignore-user-config",
            "--ignore-rules",
            "--ephemeral",
            "--cd",
            "/workspace",
            "-c",
            "default_permissions=\"maco_external_codex\"",
            "-c",
            "permissions.maco_external_codex.network={enabled=false}",
            "-c",
            "permissions.maco_external_codex.filesystem={\":minimal\"=\"read\",\":workspace_roots\"={\".\"=\"write\"},\"/run\"=\"write\"}",
            "-c",
            "shell_environment_policy.inherit=\"none\"",
            "-c",
            "shell_environment_policy.set={PATH=\"/run/current-system/sw/bin:/usr/bin:/bin\"}",
            "-c",
            "web_search=\"disabled\"",
            "--disable",
            "apps",
            "--disable",
            "plugins",
            "--disable",
            "hooks",
            "--disable",
            "in_app_browser",
            "--disable",
            "browser_use",
            "--disable",
            "browser_use_full_cdp_access",
            "--disable",
            "browser_use_external",
            "--disable",
            "computer_use",
            "--disable",
            "image_generation",
            "--enable",
            "goals",
            "--enable",
            "multi_agent",
            "--json",
            "--output-last-message",
            "/run/report.json",
            "-",
        ];
    assert_eq!(actual, expected);
}

#[test]
fn codex_argv_applies_primary_model_selection_safely() {
    let command = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(1),
    )
    .with_model_selection(
        Some("planner-model".to_string()),
        Some("high\"\nweb_search=\"live".to_string()),
    );
    let actual = command_argv(&command)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert!(actual
        .windows(2)
        .any(|arguments| arguments == ["-m", "planner-model"]));
    assert!(actual.windows(2).any(|arguments| {
        arguments
            == [
                "-c",
                "model_reasoning_effort=\"high\\\"\\nweb_search=\\\"live\"",
            ]
    }));
    assert!(!actual
        .iter()
        .any(|argument| argument == "web_search=\"live\""));
}

#[test]
fn runtime_adapter_argv_propagates_render_failure() {
    let mut command = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(1),
    )
    .with_runtime_adapter(
        RuntimeId::Grok,
        RuntimeAdapterConfig::defaults(RuntimeId::Grok),
    );
    // with_runtime_adapter copies program into config.binary — force empty after:
    if let Some(config) = command.runtime_adapter.as_mut() {
        config.binary = Some(PathBuf::new());
    }
    let error = runtime_adapter_argv(&command).unwrap_err();
    assert!(error
        .to_string()
        .contains("runtime adapter binary is not configured"));
}

#[test]
fn codex_app_server_argv_preserves_the_external_codex_ceiling() {
    let command = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(1),
    );
    let controls =
        protected_worktree_controls(&command).unwrap_or_else(|_| ProtectedWorktreeControls {
            writable_artifact_root: Some(PathBuf::from("/run")),
            ..ProtectedWorktreeControls::default()
        });
    let actual = codex_app_server_argv(&command, &controls)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        actual
            .get(0..3)
            .map(|arguments| arguments.iter().map(String::as_str).collect::<Vec<_>>()),
        Some(vec!["app-server", "--stdio", "--strict-config"])
    );
    for required in [
            "approval_policy=\"on-request\"",
            "approvals_reviewer=\"user\"",
            "default_permissions=\"maco_external_codex\"",
            "permissions.maco_external_codex.network={enabled=false}",
            "permissions.maco_external_codex.filesystem={\":minimal\"=\"read\",\":workspace_roots\"={\".\"=\"write\"},\"/run\"=\"write\"}",
            "shell_environment_policy.inherit=\"none\"",
            "web_search=\"disabled\"",
            "project_doc_max_bytes=0",
        ] {
            assert!(
                actual.iter().any(|argument| argument == required),
                "missing bounded app-server argument {required}"
            );
        }
    assert!(!actual.iter().any(|argument| {
        argument.contains("enabled=true")
            || argument.contains("danger-full-access")
            || argument == "--add-dir"
    }));
}

#[test]
fn app_server_capability_uses_the_existing_external_codex_profile() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    let incoming = temp.path().join("incoming");
    fs::create_dir_all(&incoming)?;
    let command = ExternalAgentCommand::codex(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join(".maco/events.jsonl"),
        incoming.join("report.json"),
        Duration::from_secs(1),
    );
    let controls = protected_worktree_controls(&command)?;
    let profile = external_side_effect_profile(
        &command,
        Path::new("/run/current-system/sw/bin/codex"),
        ExternalProgramTrust::TrustedSystemCodex,
        &controls,
    )?;

    assert_eq!(
        profile.kind(),
        SideEffectConfinementProfileKind::ExternalCodex
    );
    Ok(())
}

#[test]
fn codex_usage_parser_sums_only_valid_completed_turns() -> Result<()> {
    let usage = codex_usage_from_jsonl(
        br#"{"type":"thread.started","thread_id":"thread-a"}
{"type":"turn.completed","usage":{"input_tokens":120,"cached_input_tokens":20,"output_tokens":30}}
{"type":"item.completed","item":{"type":"agent_message"}}
{"type":"turn.completed","usage":{"input_tokens":80,"cached_input_tokens":0,"output_tokens":20}}
"#,
    )?
    .context("completed usage")?;
    assert_eq!(
        usage,
        Usage {
            input_tokens: 200,
            output_tokens: 50,
            total_tokens: 250,
        }
    );
    assert!(codex_usage_from_jsonl(br#"{"type":"thread.started"}"#)?.is_none());
    assert!(codex_usage_from_jsonl(
        b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1}}\n"
    )
    .is_err());
    assert!(codex_usage_from_jsonl(b"{malformed}\n").is_err());
    Ok(())
}

#[test]
fn external_errors_are_composed_and_success_requires_verified_empty_containment() {
    assert_eq!(
        append_external_error(
            Some("cleanup evidence".to_string()),
            Some("exit status 7".to_string())
        ),
        Some("cleanup evidence; exit status 7".to_string())
    );

    let mut report = ExternalAgentRun {
        command: vec!["fake".to_string()],
        cwd: PathBuf::from("."),
        timeout_seconds: 1,
        exit_code: Some(0),
        duration_ms: 1,
        timed_out: false,
        process_tree: None,
        side_effects: None,
        publishable: false,
        program_trust: ExternalProgramTrust::ExplicitCustom,
        codex_permissions: None,
        stdout: CapturedOutput::default(),
        stderr: CapturedOutput::default(),
        error: None,
        output_last_message: None,
    };
    assert!(!report.succeeded());
    report.process_tree = Some(ProcessTreeEvidence::TrustedBestEffort(
        ContainmentBackend::UnixProcessGroup,
    ));
    assert!(!report.succeeded());
    report.process_tree = Some(ProcessTreeEvidence::Unverified(
        ContainmentBackend::SystemdUserService,
    ));
    assert!(!report.succeeded());
    report.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
        ContainmentBackend::SystemdUserService,
    ));
    report.side_effects = Some(SideEffectConfinementEvidence::Verified(
        SideEffectConfinementProfileKind::ExternalCodex,
    ));
    report.publishable = true;
    report.program_trust = ExternalProgramTrust::TrustedSystemCodex;
    report.codex_permissions = Some(CodexPermissionEvidence {
        codex_version: "0.142.3".to_string(),
        minimum_version: "0.138.0".to_string(),
        permission_profile: "maco_external_codex".to_string(),
        workspace_access: WorkspaceAccess::ReadWrite,
        network_enabled: false,
        argv_digest: "digest".to_string(),
        executable_identity: "identity".to_string(),
    });
    assert!(report.succeeded());
}

#[cfg(target_os = "linux")]
#[test]
fn fake_provider_lifecycle_is_listed_in_supervisor_repo_and_gc_after_exit() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let supervisor_repo = temp.path().join("supervisor-repo");
    let child_repo = temp.path().join("child-worktree");
    git2::Repository::init(&supervisor_repo)?;
    git2::Repository::init(&child_repo)?;
    create_mandatory_control_roots(&child_repo)?;

    let provider = child_repo.join("fake-provider.sh");
    fs::write(
            &provider,
            "#!/bin/sh\nroot=${0%/*}\nprintf '%s\\n%s\\n' \"$MACO_RUN_ID\" \"$MACO_TASK_ID\" > \"$root/lifecycle-env\"\n: > \"$root/provider-started\"\nwhile [ ! -f \"$root/provider-release\" ]; do sleep 0.01; done\n",
        )?;
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700))?;
    let prompt = child_repo.join("prompt.md");
    fs::write(&prompt, "offline fake provider lifecycle test\n")?;
    let incoming = child_repo.join("incoming");
    fs::create_dir(&incoming)?;
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;

    let command = ExternalAgentCommand::codex(
        &provider,
        &child_repo,
        &prompt,
        incoming.join("events.jsonl"),
        incoming.join("last-message.txt"),
        Duration::from_secs(10),
    )
    .with_agent_lifecycle(
        &supervisor_repo,
        "child_orchestrator",
        "supervise-run",
        "assignment-a",
    );
    let registry = AgentRegistry::open(&supervisor_repo)?;
    let runner = std::thread::spawn(move || run_external_agent_nonpublishable_simulation(&command));

    let deadline = Instant::now() + Duration::from_secs(5);
    let observed = (|| -> Result<Option<_>> {
        loop {
            if let Some(record) = registry
                .list(&AgentListFilter::default())?
                .into_iter()
                .next()
            {
                return Ok(Some(record));
            }
            if runner.is_finished() || Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();

    fs::write(child_repo.join("provider-release"), b"")?;
    let report = runner
        .join()
        .map_err(|_| anyhow::anyhow!("fake provider runner thread panicked"))?;
    let record =
        observed?.context("fake provider lifecycle registration was not observable before exit")?;

    assert!(
        report.simulation_succeeded(),
        "unexpected report: {report:#?}"
    );
    assert_eq!(record.role, "child_orchestrator");
    assert_eq!(record.run_id, "supervise-run");
    assert_eq!(record.task_id, "assignment-a");
    assert_eq!(record.repo, supervisor_repo);
    assert!(record.argv.iter().any(|argument| argument == "exec"));
    assert_eq!(
        fs::read_to_string(child_repo.join("lifecycle-env"))?,
        "supervise-run\nassignment-a\n"
    );
    assert!(registry.list(&AgentListFilter::default())?.is_empty());
    assert!(registry.registry_path().is_file());
    assert!(!child_repo.join(".maco/agents/registry.json").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn verified_nonzero_target_retains_permission_and_containment_evidence() -> Result<()> {
    use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
    use std::process::ExitStatus;

    let temp = tempfile::tempdir()?;
    create_mandatory_control_roots(temp.path())?;
    let incoming = temp.path().join("incoming");
    fs::create_dir(&incoming)?;
    fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
    let prompt = temp.path().join("prompt.md");
    fs::write(&prompt, "run a failing child\n")?;
    let output_path = incoming.join("report.json");
    let command = ExternalAgentCommand::codex(
        "codex",
        temp.path(),
        &prompt,
        incoming.join("events.jsonl"),
        &output_path,
        Duration::from_secs(5),
    );
    let staged_output_path = incoming.join("staged-output.raw");
    let mut staged_output = reserve_external_output(&staged_output_path)?;
    let mut output_reservation = reserve_external_output(&output_path)?;
    let mut json_log_reservation = reserve_external_output(&command.json_log)?;
    let credential_redactor = CredentialRedactor::default();
    let identity_path = temp.path().join("trusted-codex-identity");
    fs::write(&identity_path, b"identity")?;
    let program_identity = external_program_identity(&identity_path)?;
    let mut report = ExternalAgentRun {
        command: vec!["codex".to_string()],
        cwd: command.cwd.clone(),
        timeout_seconds: command.timeout.as_secs(),
        exit_code: None,
        duration_ms: 0,
        timed_out: false,
        process_tree: None,
        side_effects: None,
        publishable: false,
        program_trust: ExternalProgramTrust::TrustedSystemCodex,
        codex_permissions: None,
        stdout: CapturedOutput::default(),
        stderr: CapturedOutput::default(),
        error: None,
        output_last_message: None,
    };
    let output = ProcessOutput {
        status: Some(ExitStatus::from_raw(7 << 8)),
        duration: Duration::from_millis(2),
        timed_out: false,
        process_tree: ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService),
        side_effects: SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::ExternalCodex,
        ),
        stdout: CapturedBytes::default(),
        stderr: CapturedBytes::default(),
        process_error: None,
        stdin_error: None,
    };
    let protected_controls = protected_worktree_controls(&command)?;

    record_completed_target(
        &mut report,
        output,
        &mut staged_output,
        &mut output_reservation,
        &mut json_log_reservation,
        &credential_redactor,
        CompletedTargetContext {
            runtime: ExternalExecutionRuntime::Verified,
            codex_version: Some((0, 142, 3)),
            spec: &command,
            protected_controls: &protected_controls,
            argv_digest: "verified-argv-digest",
            program_identity: &program_identity,
        },
    );

    assert_eq!(report.exit_code, Some(7));
    assert_eq!(
        report.process_tree,
        Some(ProcessTreeEvidence::VerifiedEmpty(
            ContainmentBackend::SystemdUserService
        ))
    );
    assert_eq!(
        report.side_effects,
        Some(SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::ExternalCodex
        ))
    );
    assert!(report.codex_permissions.is_some());
    assert!(report
        .error
        .as_deref()
        .is_some_and(|error| error.contains("exited with status 7")));
    assert!(!report.publishable);
    assert!(!report.safely_executed());
    assert!(!report.succeeded());
    assert!(!report.environment_blocked());
    Ok(())
}

#[test]
fn scratch_quiescence_distinguishes_preflight_refusal_from_unverified_launch() {
    let command = ExternalAgentCommand::codex(
        "codex",
        ".",
        "prompt",
        "log",
        "output",
        Duration::from_secs(1),
    );
    let mut report = failed_external_run(
        &command,
        Instant::now(),
        vec!["codex".to_string()],
        false,
        "preflight refused".to_string(),
    );
    assert!(report.scratch_quiescence_verified());

    report
        .stdout
        .run_metadata
        .environment_preflight_process_started = true;
    report.process_tree = Some(ProcessTreeEvidence::Unverified(
        ContainmentBackend::SystemdUserService,
    ));
    report.side_effects = Some(SideEffectConfinementEvidence::Unverified(
        SideEffectConfinementProfileKind::ExternalCodex,
    ));
    assert!(!report.scratch_quiescence_verified());
    report.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
        ContainmentBackend::SystemdUserService,
    ));
    assert!(!report.scratch_quiescence_verified());
    report.side_effects = Some(SideEffectConfinementEvidence::Verified(
        SideEffectConfinementProfileKind::ExternalCodex,
    ));
    assert!(report.scratch_quiescence_verified());

    report.process_tree = None;
    report.side_effects = None;
    report.stdout.target_launch_attempted = true;
    assert!(!report.scratch_quiescence_verified());
    report.process_tree = Some(ProcessTreeEvidence::Unverified(
        ContainmentBackend::SystemdUserService,
    ));
    assert!(!report.scratch_quiescence_verified());
    report.process_tree = Some(ProcessTreeEvidence::VerifiedEmpty(
        ContainmentBackend::SystemdUserService,
    ));
    assert!(!report.scratch_quiescence_verified());
    report.side_effects = Some(SideEffectConfinementEvidence::Verified(
        SideEffectConfinementProfileKind::ExternalCodex,
    ));
    assert!(report.scratch_quiescence_verified());
}

#[test]
fn environment_preflight_process_errors_retain_fail_closed_containment_evidence() {
    fn unverified_evidence() -> ProcessFailureEvidence {
        ProcessFailureEvidence {
            stdout: CapturedBytes::default(),
            stderr: CapturedBytes::default(),
            process_tree: ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService),
            side_effects: SideEffectConfinementEvidence::Unverified(
                SideEffectConfinementProfileKind::ExternalCodex,
            ),
            process_error: Some("cleanup could not be verified".to_string()),
            stdin_error: None,
        }
    }

    let errors = vec![
        ProcessRunError::Wait {
            label: "codex version preflight".to_string(),
            command: "codex --version".to_string(),
            evidence: Box::new(unverified_evidence()),
            source: std::io::Error::other("injected wait failure"),
        },
        ProcessRunError::Cancelled {
            label: "codex version preflight".to_string(),
            command: "codex --version".to_string(),
            phase: "injected cancellation",
            evidence: Some(Box::new(unverified_evidence())),
        },
        ProcessRunError::OpenTee {
            label: "codex version preflight".to_string(),
            stream: "stdout",
            path: PathBuf::from("injected-tee"),
            source: std::io::Error::other("injected tee failure"),
        },
        ProcessRunError::TeeConflict {
            label: "codex version preflight".to_string(),
            stdout: PathBuf::from("injected-stdout"),
            stderr: PathBuf::from("injected-stderr"),
        },
        ProcessRunError::Spawn {
            label: "codex version preflight".to_string(),
            command: "codex --version".to_string(),
            current_dir: PathBuf::from("."),
            source: std::io::Error::other("injected ambiguous spawn failure"),
        },
        ProcessRunError::SetupTimeout {
            label: "codex version preflight".to_string(),
            command: "codex --version".to_string(),
            phase: "injected post-spawn setup",
            source: std::io::Error::other("injected setup timeout"),
        },
        ProcessRunError::ProcessOwnership {
            label: "codex version preflight".to_string(),
            command: "codex --version".to_string(),
            source: std::io::Error::other("injected ownership failure"),
        },
        ProcessRunError::IoSetup {
            label: "codex version preflight".to_string(),
            command: "codex --version".to_string(),
            source: std::io::Error::other("injected post-spawn I/O failure"),
        },
    ];

    for error in errors {
        assert!(!process_run_error_definitely_before_process_start(&error));
        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        evidence.record_error(&error);
        assert!(evidence.started);
        assert!(evidence
            .process_tree
            .is_some_and(|process_tree| !process_tree.is_verified_empty()));
        assert!(evidence
            .side_effects
            .is_some_and(|side_effects| !side_effects.is_verified()));

        let command = ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        );
        let mut report = failed_external_run(
            &command,
            Instant::now(),
            vec!["codex".to_string(), "--version".to_string()],
            false,
            "environment preflight failed".to_string(),
        );
        retain_environment_preflight_process_evidence(&mut report, &evidence);
        record_environment_failure(
            &mut report,
            EnvironmentFailureCategory::ProbeFailed,
            Some(codex_environment_requirement()),
            "version probe failed".to_string(),
        );
        assert!(report.environment_blocked());
        assert!(!report.environment_preflight_quiescence_verified());
    }

    let pre_spawn_errors = vec![
        ProcessRunError::Cancelled {
            label: "codex version preflight".to_string(),
            command: "codex --version".to_string(),
            phase: "injected pre-spawn cancellation",
            evidence: None,
        },
        ProcessRunError::ContainmentUnavailable {
            label: "codex version preflight".to_string(),
            command: "codex --version".to_string(),
            source: std::io::Error::other("injected containment setup failure"),
        },
        ProcessRunError::StdinTooLarge {
            label: "codex version preflight".to_string(),
            limit: 0,
            actual: 1,
        },
    ];
    for error in pre_spawn_errors {
        assert!(process_run_error_definitely_before_process_start(&error));
        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        evidence.record_error(&error);
        assert!(!evidence.started);
        assert!(evidence.process_tree.is_none());
        assert!(evidence.side_effects.is_none());
    }

    let mut verified = EnvironmentPreflightProcessEvidence::default();
    verified.record(
        ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService),
        SideEffectConfinementEvidence::Verified(SideEffectConfinementProfileKind::ExternalCodex),
        true,
    );
    verified.record_error(&ProcessRunError::IoSetup {
        label: "codex version preflight".to_string(),
        command: "codex --version".to_string(),
        source: std::io::Error::other("injected later unverified I/O failure"),
    });
    assert!(verified
        .process_tree
        .is_some_and(|process_tree| !process_tree.is_verified_empty()));
    assert!(verified
        .side_effects
        .is_some_and(|side_effects| !side_effects.is_verified()));

    let mut safely_verified = EnvironmentPreflightProcessEvidence::default();
    safely_verified.record(
        ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService),
        SideEffectConfinementEvidence::Verified(SideEffectConfinementProfileKind::ExternalCodex),
        true,
    );
    let command = ExternalAgentCommand::codex(
        "codex",
        ".",
        "prompt",
        "log",
        "output",
        Duration::from_secs(1),
    );
    let mut report = failed_external_run(
        &command,
        Instant::now(),
        vec!["codex".to_string(), "--version".to_string()],
        false,
        "credential missing".to_string(),
    );
    retain_environment_preflight_process_evidence(&mut report, &safely_verified);
    record_environment_failure(
        &mut report,
        EnvironmentFailureCategory::MissingCredential,
        Some(EnvironmentRequirement::credential(
            EnvironmentCredential::OpenAiApiKey,
        )),
        "required credential source is absent".to_string(),
    );
    assert!(report.environment_preflight_quiescence_verified());
}

#[test]
fn explicit_custom_environment_never_receives_provider_credentials() {
    let environment = allowed_env(
        ExternalAgentInvocation::CodexSupervisor,
        ExternalProgramTrust::ExplicitCustom,
    );
    for name in ["OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_ACCESS_TOKEN"] {
        assert!(
            !environment.contains_key(name),
            "custom environment exposed {name}"
        );
    }
}

#[test]
fn explicit_custom_cannot_construct_provider_network_profile() {
    let spec = ExternalAgentCommand::codex(
        "/tmp/custom-codex",
        "/tmp",
        "/tmp/prompt",
        "/tmp/log",
        "/tmp/report",
        Duration::from_secs(1),
    );
    let error = external_side_effect_profile(
        &spec,
        Path::new("/tmp/custom-codex"),
        ExternalProgramTrust::ExplicitCustom,
        &ProtectedWorktreeControls::default(),
    )
    .expect_err("custom program must not receive provider-network authority");
    assert!(error.to_string().contains("trusted system Codex"));
}

#[test]
fn mandatory_controls_must_exist_while_policy_files_remain_optional() -> Result<()> {
    let temp = tempfile::tempdir()?;
    for missing in [".git", ".maco", ".maco-cache", ".codex", ".agents"] {
        let workspace = temp.path().join(missing.trim_start_matches('.'));
        create_mandatory_control_roots(&workspace)?;
        fs::remove_dir(workspace.join(missing))?;

        let error = protected_worktree_controls_for(&workspace, &[])
            .expect_err("missing mandatory control must fail closed");
        let message = error.to_string();
        assert!(message.contains(missing), "unexpected error: {message}");
        assert!(!message.contains(&workspace.display().to_string()));
        assert!(message.len() < 256);
    }

    let workspace = temp.path().join("optional-policy-files");
    create_mandatory_control_roots(&workspace)?;
    let controls = protected_worktree_controls_for(&workspace, &[])?;
    assert!(controls.iter().all(|control| {
        !POLICY_CONTROL_FILES
            .iter()
            .any(|policy| control.relative() == Path::new(policy))
    }));
    Ok(())
}

#[test]
fn artifact_parent_allows_only_designated_maco_incoming_layouts() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::write(workspace.join(".cursorignore"), "ignored\n")?;
    let incoming = workspace.join("incoming");
    fs::create_dir(&incoming)?;

    for output in [
        workspace.join(".git/report.json"),
        workspace.join(".git/nested/report.json"),
        workspace.join(".maco/report.json"),
        workspace.join(".maco/state/report.json"),
        workspace.join(".maco/control/report.json"),
        workspace.join(".maco/consult/report.json"),
        workspace.join(".maco/consult/runs/report.json"),
        workspace.join(".maco/consult/runs/test/report.json"),
        workspace.join(".maco/consult/runs/test/capture/report.json"),
        workspace.join(".maco/consult/runs/test/incoming-extra/report.json"),
        workspace.join(".maco/consult/runs/test/incoming/nested/report.json"),
        workspace.join(".maco/consult/runs/invalid run/incoming/report.json"),
        workspace.join(".maco/o2/runs/test/incoming/report.json"),
        workspace.join(".maco/o2/runs/test/capture/report.json"),
        workspace.join(".maco/o2/runs/test/incoming-assignment-1-attempt-01/report.json"),
        workspace.join(".maco/o2/runs/test/incoming-assignment-0001-attempt-1/report.json"),
        workspace.join(".maco/o2/runs/test/incoming-assignment-0001-worker/report.json"),
        workspace.join(".maco/autopilot/runs/test/incoming/report.json"),
        workspace.join(".maco-cache/report.json"),
        workspace.join(".maco-cache/nested/report.json"),
        workspace.join(".codex/report.json"),
        workspace.join(".codex/nested/report.json"),
        workspace.join(".agents/report.json"),
        workspace.join(".agents/docs/report.json"),
        workspace.join(".cursorignore/report.json"),
        workspace.join("report.json"),
    ] {
        let command = ExternalAgentCommand::codex_read_only_consultant(
            "codex",
            &workspace,
            workspace.join("prompt.md"),
            workspace.join("events.jsonl"),
            output,
            Duration::from_secs(1),
        );
        let error = protected_worktree_controls(&command)
            .expect_err("protected artifact overlap must fail closed");
        let message = error.to_string();
        assert_eq!(
            message,
            "external-agent output parent overlaps a protected worktree control"
        );
        assert!(!message.contains(&workspace.display().to_string()));
    }

    let maco_incoming = workspace.join(".maco/consult/runs/test/incoming");
    fs::create_dir_all(&maco_incoming)?;
    let supervisor_command = ExternalAgentCommand::codex(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        maco_incoming.join("report.json"),
        Duration::from_secs(1),
    );
    let error = protected_worktree_controls(&supervisor_command)
        .expect_err("supervisor invocation must not receive the consult carve-out");
    assert_eq!(
        error.to_string(),
        "external-agent output parent overlaps a protected worktree control"
    );

    let command = ExternalAgentCommand::codex_read_only_consultant(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        maco_incoming.join("report.json"),
        Duration::from_secs(1),
    );
    let controls = protected_worktree_controls(&command)?;
    assert_eq!(
        controls.writable_artifact_root.as_deref(),
        Some(maco_incoming.as_path())
    );
    assert!(controls
        .read_only_roots
        .iter()
        .any(|control| control.relative() == Path::new(".maco")));
    let profile = external_side_effect_profile(
        &command,
        &workspace.join("codex"),
        ExternalProgramTrust::TrustedSystemCodex,
        &controls,
    )?;
    let SideEffectConfinementProfile::ExternalCodex(profile) = profile else {
        bail!("expected external Codex profile");
    };
    assert_eq!(profile.writable_artifact_roots(), &[maco_incoming]);

    let command = ExternalAgentCommand::codex(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        incoming.join("report.json"),
        Duration::from_secs(1),
    );
    let controls = protected_worktree_controls(&command)?;
    let permissions = codex_filesystem_permissions(&command, &controls);
    assert!(permissions.contains("\"incoming\"=\"write\""));
    let profile = external_side_effect_profile(
        &command,
        &workspace.join("codex"),
        ExternalProgramTrust::TrustedSystemCodex,
        &controls,
    )?;
    let SideEffectConfinementProfile::ExternalCodex(profile) = profile else {
        bail!("expected external Codex profile");
    };
    assert_eq!(profile.writable_artifact_roots(), &[incoming]);
    Ok(())
}

#[test]
fn protected_worktree_controls_use_exact_descendant_exceptions() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace)?;
    fs::write(
        workspace.join(".git"),
        "gitdir: ../primary/.git/worktrees/child\n",
    )?;
    for root in [".maco", ".maco-cache", ".codex", ".agents"] {
        fs::create_dir(workspace.join(root))?;
    }
    fs::create_dir(workspace.join(".agents/docs"))?;
    fs::write(workspace.join(".agents/docs/worker.md"), "worker policy\n")?;
    for file in POLICY_CONTROL_FILES {
        fs::write(workspace.join(file), "protected\n")?;
    }
    let command = ExternalAgentCommand::codex(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        workspace.join("incoming/report.json"),
        Duration::from_secs(1),
    )
    .with_worktree_control_exception(".agents/docs/worker.md");

    let controls = protected_worktree_controls(&command)?;
    let roots = controls
        .read_only_roots
        .iter()
        .map(ProtectedWorktreeControl::relative)
        .collect::<BTreeSet<_>>();
    let files = controls
        .read_only_files
        .iter()
        .map(ProtectedWorktreeControl::relative)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        roots,
        BTreeSet::from([
            Path::new(".agents"),
            Path::new(".codex"),
            Path::new(".maco"),
            Path::new(".maco-cache"),
        ])
    );
    assert_eq!(
        files,
        BTreeSet::from([
            Path::new(".codexignore"),
            Path::new(".cursorignore"),
            Path::new(".cursorindexingignore"),
            Path::new(".dockerignore"),
            Path::new(".git"),
            Path::new(".gitattributes"),
            Path::new(".gitignore"),
            Path::new(".ignore"),
            Path::new(".rgignore"),
            Path::new("AGENTS.md"),
            Path::new("CLAUDE.md"),
        ])
    );
    assert_eq!(
        controls
            .read_write_files
            .iter()
            .map(ProtectedWorktreeControl::relative)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([Path::new(".agents/docs/worker.md")])
    );

    let profile = external_side_effect_profile(
        &command,
        &workspace.join("codex"),
        ExternalProgramTrust::TrustedSystemCodex,
        &controls,
    )?;
    let SideEffectConfinementProfile::ExternalCodex(profile) = profile else {
        bail!("expected external Codex profile");
    };
    assert!(profile
        .visible_read_only_roots()
        .contains(&workspace.join(".maco-cache")));
    assert!(profile
        .visible_read_only_roots()
        .contains(&workspace.join(".agents")));
    assert_eq!(
        profile.visible_read_write_files(),
        &[workspace.join(".agents/docs/worker.md")]
    );
    assert!(!profile
        .visible_read_write_roots()
        .contains(&workspace.join(".agents")));
    assert!(!profile
        .visible_read_write_files()
        .contains(&workspace.join(".agents")));
    Ok(())
}

#[test]
fn absent_exact_policy_exceptions_materialize_only_regular_files() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::create_dir_all(workspace.join(".agents/docs"))?;
    let exceptions = [
        PathBuf::from(".agents/docs/new-policy.md"),
        PathBuf::from(".gitignore"),
        PathBuf::from("AGENTS.md"),
    ];

    let controls = protected_worktree_controls_for(&workspace, &exceptions)?;

    assert!(controls.read_write_roots.is_empty());
    assert_eq!(
        controls
            .read_write_files
            .iter()
            .map(|control| control.relative().to_path_buf())
            .collect::<BTreeSet<_>>(),
        exceptions.iter().cloned().collect()
    );
    for relative in &exceptions {
        let metadata = fs::symlink_metadata(workspace.join(relative))?;
        assert!(metadata.is_file(), "{} was not a file", relative.display());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.len(), 0);
    }
    #[cfg(unix)]
    assert!(controls
        .read_write_files
        .iter()
        .all(|control| control.held_file.is_some()));

    let repeated = protected_worktree_controls_for(&workspace, &exceptions)?;
    assert_eq!(
        repeated
            .read_write_files
            .iter()
            .map(|control| control.relative().to_path_buf())
            .collect::<BTreeSet<_>>(),
        exceptions.iter().cloned().collect()
    );
    #[cfg(unix)]
    assert!(repeated
        .read_write_files
        .iter()
        .all(|control| control.held_file.is_some()));
    Ok(())
}

#[test]
fn absent_policy_exception_rejects_raced_existing_file() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::create_dir_all(workspace.join(".agents/docs"))?;
    let relative = PathBuf::from(".agents/docs/raced-policy.md");
    let target = validate_control_exception_target(&workspace, &relative)?;
    assert_eq!(target.kind, ControlExceptionKind::AbsentRegularFile);
    fs::write(workspace.join(&relative), "raced file\n")?;

    let mut controls = ProtectedWorktreeControls::default();
    let error = collect_control_exception(&workspace, &relative, target, &mut controls)
        .expect_err("EEXIST race must fail closed");
    assert!(error
        .to_string()
        .contains("failed to materialize exact worktree control exception"));
    assert!(controls.read_write_files.is_empty());
    assert!(controls.read_write_roots.is_empty());
    Ok(())
}

#[cfg(unix)]
#[test]
fn preexisting_policy_file_capability_rejects_replacement_after_classification() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::create_dir_all(workspace.join(".agents/docs"))?;
    let incoming = workspace.join("incoming");
    fs::create_dir(&incoming)?;
    let relative = PathBuf::from(".agents/docs/existing-policy.md");
    let exception = workspace.join(&relative);
    fs::write(&exception, "original policy\n")?;
    let command = ExternalAgentCommand::codex(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        incoming.join("report.json"),
        Duration::from_secs(1),
    )
    .with_worktree_control_exception(&relative);

    let controls = protected_worktree_controls(&command)?;
    assert!(controls
        .read_write_files
        .iter()
        .all(|control| control.held_file.is_some()));

    fs::rename(&exception, workspace.join("classified-policy.md"))?;
    fs::write(&exception, "replacement policy\n")?;

    let error = external_side_effect_profile(
        &command,
        &workspace.join("codex"),
        ExternalProgramTrust::TrustedSystemCodex,
        &controls,
    )
    .expect_err("replacement must not inherit the held writable capability");
    assert!(
        error
            .to_string()
            .contains("held worktree control changed before sandbox admission"),
        "unexpected replacement rejection: {error:#}"
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn materialized_policy_exception_rejects_post_create_hardlink_and_replacement() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::create_dir_all(workspace.join(".agents/docs"))?;

    let linked_relative = PathBuf::from(".agents/docs/linked-policy.md");
    let linked_path = workspace.join(&linked_relative);
    let alias = workspace.join(".agents/docs/linked-policy-alias.md");
    let error = materialize_control_exception_file_with_hook(&workspace, &linked_relative, || {
        fs::hard_link(&linked_path, &alias)
    })
    .expect_err("post-create hard link must fail closed");
    assert!(error.to_string().contains("single-link"));

    let replaced_relative = PathBuf::from(".agents/docs/replaced-policy.md");
    let replaced_path = workspace.join(&replaced_relative);
    let attacker = workspace.join(".agents/docs/replacement.md");
    fs::write(&attacker, "replacement\n")?;
    fs::set_permissions(&attacker, fs::Permissions::from_mode(0o600))?;
    let error =
        materialize_control_exception_file_with_hook(&workspace, &replaced_relative, || {
            fs::rename(&attacker, &replaced_path)
        })
        .expect_err("post-create replacement must fail closed");
    assert!(error.to_string().contains("single-link"));
    assert_eq!(fs::read_to_string(replaced_path)?, "replacement\n");
    Ok(())
}

#[cfg(unix)]
#[test]
fn replaced_materialized_policy_file_is_rejected_before_outer_exception() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::create_dir_all(workspace.join(".agents/docs"))?;
    let incoming = workspace.join("incoming");
    fs::create_dir(&incoming)?;
    let relative = PathBuf::from(".agents/docs/new-policy.md");
    let exception = workspace.join(&relative);
    let command = ExternalAgentCommand::codex(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        incoming.join("report.json"),
        Duration::from_secs(1),
    )
    .with_worktree_control_exception(&relative);
    let controls = protected_worktree_controls(&command)?;
    let accepted = external_side_effect_profile(
        &command,
        &workspace.join("codex"),
        ExternalProgramTrust::TrustedSystemCodex,
        &controls,
    )?;
    let SideEffectConfinementProfile::ExternalCodex(accepted) = accepted else {
        bail!("expected external Codex profile");
    };
    assert_eq!(
        accepted.visible_read_write_files(),
        std::slice::from_ref(&exception)
    );

    fs::remove_file(&exception)?;
    fs::write(&exception, "replacement\n")?;
    fs::set_permissions(&exception, fs::Permissions::from_mode(0o600))?;

    let error = external_side_effect_profile(
        &command,
        &workspace.join("codex"),
        ExternalProgramTrust::TrustedSystemCodex,
        &controls,
    )
    .expect_err("replacement must fail before exact outer exception admission");
    assert!(error
        .to_string()
        .contains("held worktree control changed before sandbox admission"));
    Ok(())
}

#[test]
fn absent_policy_exception_rejects_missing_and_nondirectory_parents() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::write(workspace.join(".agents/not-a-directory"), "policy\n")?;

    for relative in [
        PathBuf::from(".agents/missing/new-policy.md"),
        PathBuf::from(".agents/not-a-directory/new-policy.md"),
    ] {
        let error = protected_worktree_controls_for(&workspace, std::slice::from_ref(&relative))
            .expect_err("unsafe parent chain must fail closed");
        assert!(
            error.to_string().contains("parent chain"),
            "unexpected error for {}: {error}",
            relative.display()
        );
        assert!(!workspace.join(relative).exists());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn absent_policy_exception_rejects_symlinked_parent_and_workspace() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let outside = temp.path().join("outside");
    create_mandatory_control_roots(&workspace)?;
    fs::create_dir(&outside)?;
    symlink(&outside, workspace.join(".agents/link"))?;

    let relative = PathBuf::from(".agents/link/new-policy.md");
    let error = protected_worktree_controls_for(&workspace, &[relative])
        .expect_err("symlinked parent must fail closed");
    assert!(error.to_string().contains("symlink"));
    assert!(!outside.join("new-policy.md").exists());

    let workspace_alias = temp.path().join("workspace-alias");
    symlink(&workspace, &workspace_alias)?;
    let error = protected_worktree_controls_for(&workspace_alias, &[PathBuf::from(".gitignore")])
        .expect_err("symlinked workspace must fail closed");
    assert!(error.to_string().contains("non-symlink directory"));
    assert!(!workspace.join(".gitignore").exists());
    Ok(())
}

#[test]
fn control_exceptions_reject_invalid_permanent_symlink_and_ambiguous_paths() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace)?;
    for root in [".git", ".maco", ".maco-cache", ".codex", ".agents"] {
        fs::create_dir(workspace.join(root))?;
    }
    fs::create_dir(workspace.join(".agents/docs"))?;
    fs::write(workspace.join(".agents/docs/policy.md"), "policy\n")?;
    fs::write(workspace.join(".gitignore"), "target\n")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        workspace.join(".agents/docs"),
        workspace.join(".agents/link"),
    )?;

    for paths in [
        vec![PathBuf::from("/absolute")],
        vec![PathBuf::from("../AGENTS.md")],
        vec![PathBuf::from(".")],
        vec![PathBuf::from("src")],
        vec![PathBuf::from(".git")],
        vec![PathBuf::from(".maco")],
        vec![PathBuf::from(".maco-cache")],
        vec![PathBuf::from(".codex")],
        vec![PathBuf::from(".agents")],
        vec![PathBuf::from(".agents/link")],
        vec![
            PathBuf::from(".agents/docs"),
            PathBuf::from(".agents/docs/policy.md"),
        ],
    ] {
        assert!(
            protected_worktree_controls_for(&workspace, &paths).is_err(),
            "invalid exception set was accepted: {paths:?}"
        );
    }
    Ok(())
}

#[test]
fn policy_controls_include_non_git_ignores_and_construct_deterministically() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::create_dir_all(workspace.join(".agents/docs"))?;
    fs::write(workspace.join(".agents/docs/policy.md"), "policy\n")?;
    fs::write(workspace.join(".cursorignore"), "ignored\n")?;
    fs::write(workspace.join(".rgignore"), "ignored\n")?;

    let forward = protected_worktree_controls_for(
        &workspace,
        &[
            PathBuf::from(".agents/docs/policy.md"),
            PathBuf::from(".cursorignore"),
        ],
    )?;
    let reverse = protected_worktree_controls_for(
        &workspace,
        &[
            PathBuf::from(".cursorignore"),
            PathBuf::from(".agents/docs/policy.md"),
        ],
    )?;

    assert_eq!(forward, reverse);
    assert_eq!(
        forward
            .read_only_files
            .iter()
            .map(ProtectedWorktreeControl::relative)
            .collect::<Vec<_>>(),
        vec![Path::new(".rgignore")]
    );
    assert_eq!(
        forward
            .read_write_files
            .iter()
            .map(ProtectedWorktreeControl::relative)
            .collect::<Vec<_>>(),
        vec![
            Path::new(".agents/docs/policy.md"),
            Path::new(".cursorignore")
        ]
    );
    Ok(())
}

#[test]
fn structured_failed_command_denials_are_typed_deduplicated_and_redacted() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    fs::write(workspace.join("AGENTS.md"), "policy\n")?;
    let command = ExternalAgentCommand::codex(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        workspace.join("incoming/report.json"),
        Duration::from_secs(1),
    );
    let controls = protected_worktree_controls(&command)?;
    let absolute = workspace.join("AGENTS.md");
    let event = serde_json::json!({
        "type": "item.completed",
        "item": {
            "id": "item-1",
            "type": "command_execution",
            "command": format!("touch '{}'", absolute.display()),
            "aggregated_output": format!("touch: cannot touch '{}': Read-only file system", absolute.display()),
            "exit_code": 1,
            "status": "failed"
        }
    });
    let jsonl = format!("{event}\n{event}\n");
    let denials = sandbox_denials_from_codex_jsonl(&controls, jsonl.as_bytes());
    assert_eq!(
        denials,
        vec![SandboxDenialEvidence {
            boundary: SandboxDenialBoundary::InnerCodex,
            policy_id: INNER_CODEX_POLICY_ID.to_string(),
            operation: SandboxDeniedOperation::Write,
            path: Some(PathBuf::from("AGENTS.md")),
            retryability: SandboxDenialRetryability::RequiresDeclaredException,
        }]
    );
    let serialized = serde_json::to_string(&denials)?;
    assert!(!serialized.contains(&workspace.display().to_string()));

    for noise in [
            br#"{"type":"item.completed","item":{"id":"item-1","type":"agent_message","text":"AGENTS.md: permission denied"}}"#.as_slice(),
            br#"{"type":"item.completed","item":{"id":"item-1","type":"command_execution","command":"touch AGENTS.md","aggregated_output":"permission denied","exit_code":0,"status":"completed"}}"#.as_slice(),
            br#"arbitrary agent prose says AGENTS.md permission denied"#.as_slice(),
            br#"{"type":"item.completed","item":{"id":"item-1","type":"command_execution","command":"touch AGENTS.md.bak","aggregated_output":"permission denied","exit_code":1,"status":"failed"}}"#.as_slice(),
        ] {
            assert!(sandbox_denials_from_codex_jsonl(&controls, noise).is_empty());
        }
    Ok(())
}

#[test]
fn codex_inner_permissions_keep_exact_reads_writes_and_toml_escaping() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    let incoming = temp.path().join("incoming");
    fs::create_dir(&workspace)?;
    fs::create_dir(&incoming)?;
    fs::write(
        workspace.join(".git"),
        "gitdir: ../primary/.git/worktrees/child\n",
    )?;
    for root in [".maco", ".maco-cache", ".codex", ".agents"] {
        fs::create_dir(workspace.join(root))?;
    }
    let exception = PathBuf::from(".agents/policy\"quoted.md");
    fs::write(workspace.join(&exception), "policy\n")?;
    fs::write(workspace.join(".gitattributes"), "* text=auto\n")?;
    fs::write(workspace.join(".cursorignore"), "ignored\n")?;
    fs::write(workspace.join(".codexignore"), "ignored\n")?;
    let command = ExternalAgentCommand::codex(
        "codex",
        &workspace,
        workspace.join("prompt.md"),
        workspace.join("events.jsonl"),
        incoming.join("report.json"),
        Duration::from_secs(1),
    )
    .with_worktree_control_exception(&exception);
    let controls = protected_worktree_controls(&command)?;
    let permissions = codex_filesystem_permissions(&command, &controls);

    assert!(permissions.contains("\":minimal\"=\"read\""));
    assert!(permissions.contains("\":workspace_roots\"={\".\"=\"write\"}"));
    for path in [
        ".git",
        ".maco",
        ".maco-cache",
        ".codex",
        ".agents",
        ".gitattributes",
        ".cursorignore",
        ".codexignore",
    ] {
        assert!(
            permissions.contains(&format!("{}=\"read\"", toml_basic_string(path))),
            "missing exact read entry for {path}: {permissions}"
        );
    }
    assert!(permissions.contains("\".agents/policy\\\"quoted.md\"=\"write\""));
    assert!(!permissions.contains("\".agents\"=\"write\""));
    assert!(!permissions.contains("\".maco-cache\"=\"write\""));
    assert!(permissions.contains(&format!(
        "{}=\"write\"",
        toml_basic_string(incoming.to_str().context("UTF-8 incoming path")?)
    )));
    Ok(())
}

#[test]
fn stored_denial_evidence_round_trips_and_old_json_defaults_empty() -> Result<()> {
    let command = ExternalAgentCommand::codex(
        "codex",
        "/workspace",
        "/run/prompt.md",
        "/run/events.jsonl",
        "/run/report.json",
        Duration::from_secs(1),
    );
    let mut report = failed_external_run(
        &command,
        Instant::now(),
        vec!["codex".to_string()],
        false,
        "external agent exited with status 1".to_string(),
    );
    report.stdout.run_metadata.sandbox_denials = vec![SandboxDenialEvidence {
        boundary: SandboxDenialBoundary::InnerCodex,
        policy_id: INNER_CODEX_POLICY_ID.to_string(),
        operation: SandboxDeniedOperation::Write,
        path: Some(PathBuf::from("AGENTS.md")),
        retryability: SandboxDenialRetryability::RequiresDeclaredException,
    }];
    report = report.with_external_side_effect_state(ExternalSideEffectState::Completed);
    assert_eq!(
        report.external_side_effect_state(),
        Some(ExternalSideEffectState::Completed)
    );
    let value = serde_json::to_value(&report)?;
    assert!(value.get("external_side_effect_state").is_none());
    let decoded: ExternalAgentRun = serde_json::from_value(value.clone())?;
    assert_eq!(decoded.sandbox_denials(), report.sandbox_denials());
    assert_eq!(decoded.external_side_effect_state(), None);

    let mut forged = value.clone();
    forged["external_side_effect_state"] = serde_json::json!("completed");
    let forged_decoded: ExternalAgentRun = serde_json::from_value(forged)?;
    assert_eq!(forged_decoded.external_side_effect_state(), None);

    let mut old = value;
    old.as_object_mut()
        .context("run serialization must be an object")?
        .remove("sandbox_denials");
    let old_decoded: ExternalAgentRun = serde_json::from_value(old)?;
    assert!(old_decoded.sandbox_denials().is_empty());
    Ok(())
}

#[test]
fn outer_denial_evidence_uses_only_typed_process_errors() {
    let typed = ProcessRunError::ContainmentUnavailable {
        label: "external agent".to_string(),
        command: "codex exec".to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "systemd refused boundary",
        ),
    };
    assert_eq!(
        sandbox_denial_from_process_error(&typed),
        Some(SandboxDenialEvidence {
            boundary: SandboxDenialBoundary::OuterSystemd,
            policy_id: OUTER_SYSTEMD_POLICY_ID.to_string(),
            operation: SandboxDeniedOperation::EstablishBoundary,
            path: None,
            retryability: SandboxDenialRetryability::NotRetryable,
        })
    );
    let prose_only = ProcessRunError::Spawn {
        label: "external agent".to_string(),
        command: "codex exec".to_string(),
        current_dir: PathBuf::from("/workspace"),
        source: std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "required process containment is unavailable",
        ),
    };
    assert_eq!(sandbox_denial_from_process_error(&prose_only), None);
    let environment = ProcessRunError::EnvironmentFailure {
        label: "external agent".to_string(),
        command: "/tmp/maco-target/debug/probe".to_string(),
        failure: Box::new(EnvironmentFailure::sandbox_unavailable(
            "PrivateTmp hides /tmp/maco-target/debug/probe".to_string(),
        )),
        target_process_started: false,
    };
    assert_eq!(sandbox_denial_from_process_error(&environment), None);
    assert!(!crate::process_runner::is_verified_backend_unavailable(
        &environment
    ));
}

#[test]
fn external_profile_exposes_only_incoming_output_root_as_writable() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let workspace = temp.path().join("workspace");
    create_mandatory_control_roots(&workspace)?;
    let container = temp.path().join("run");
    let trusted = container.join("trusted");
    let incoming = container.join("incoming");
    let spec = ExternalAgentCommand::codex(
        workspace.join("codex"),
        &workspace,
        trusted.join("prompt.md"),
        trusted.join("events.jsonl"),
        incoming.join("report.json"),
        Duration::from_secs(1),
    );
    let profile = external_side_effect_profile(
        &spec,
        &workspace.join("codex"),
        ExternalProgramTrust::TrustedSystemCodex,
        &protected_worktree_controls(&spec)?,
    )?;
    let SideEffectConfinementProfile::ExternalCodex(profile) = profile else {
        bail!("expected external Codex profile");
    };
    assert_eq!(profile.writable_artifact_roots(), &[incoming]);
    assert!(profile
        .writable_artifact_roots()
        .iter()
        .all(|root| !root.starts_with(&trusted)));
    Ok(())
}

#[test]
fn descriptor_captured_output_is_never_serialized() -> Result<()> {
    let mut report = failed_external_run(
        &ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        ),
        Instant::now(),
        vec!["codex".to_string()],
        false,
        "failed".to_string(),
    );
    report.output_last_message = Some(b"DO_NOT_DEBUG_private_descriptor_bytes".to_vec());
    report.stdout.bytes = b"DO_NOT_DEBUG_private_stdout_bytes\0\xff".to_vec();
    let debug = format!("{report:?}");
    assert!(!debug.contains("DO_NOT_DEBUG_private_stdout_bytes"));
    assert!(!debug.contains("DO_NOT_DEBUG_private_descriptor_bytes"));
    assert!(!debug.contains("target_launch_attempted"));
    assert!(debug.contains(&format!(
        "bytes: <redacted:{} bytes>",
        report.stdout.bytes.len()
    )));
    assert!(debug.contains(&format!(
        "output_last_message: Some(<redacted:{} bytes>)",
        report.output_last_message().context("held output")?.len()
    )));
    let value = serde_json::to_value(&report)?;
    assert!(value.get("output_last_message").is_none());
    assert!(value
        .get("stdout")
        .and_then(|stdout| stdout.get("bytes"))
        .is_none());
    assert!(value
        .get("stdout")
        .and_then(|stdout| stdout.get("target_launch_attempted"))
        .is_none());
    let decoded: ExternalAgentRun = serde_json::from_value(value)?;
    assert_eq!(decoded.output_last_message(), None);
    assert_eq!(decoded.stdout_bytes(), b"");
    assert!(!decoded.scratch_quiescence_verified());
    Ok(())
}

#[cfg(unix)]
#[test]
fn codex_argv_and_digest_preserve_non_utf8_paths_without_collision() -> Result<()> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let raw_component = OsString::from_vec(b"repo-\xff".to_vec());
    let mut raw_root = PathBuf::from("/tmp");
    raw_root.push(raw_component);
    let replacement_root = PathBuf::from("/tmp/repo-\u{fffd}");
    let raw_report = raw_root.join("report-\u{fffd}.json");
    let raw_schema = raw_root.join(OsString::from_vec(b"schema-\xfe.json".to_vec()));
    let mut raw = ExternalAgentCommand::codex(
        "codex",
        &raw_root,
        raw_root.join("prompt.md"),
        raw_root.join("events.jsonl"),
        &raw_report,
        Duration::from_secs(1),
    );
    raw.output_schema = Some(raw_schema.clone());
    let replacement = ExternalAgentCommand::codex(
        "codex",
        &replacement_root,
        replacement_root.join("prompt.md"),
        replacement_root.join("events.jsonl"),
        replacement_root.join("report-\u{fffd}.json"),
        Duration::from_secs(1),
    );

    let raw_argv = command_argv(&raw);
    let replacement_argv = command_argv(&replacement);
    let cd_index = raw_argv
        .iter()
        .position(|argument| argument == "--cd")
        .context("--cd argument")?;
    assert_eq!(
        raw_argv[cd_index + 1].as_bytes(),
        raw_root.as_os_str().as_bytes()
    );
    assert!(raw_argv
        .iter()
        .any(|argument| argument.as_bytes() == raw_report.as_os_str().as_bytes()));
    assert!(raw_argv
        .iter()
        .any(|argument| argument.as_bytes() == raw_schema.as_os_str().as_bytes()));
    assert_ne!(argv_digest(&raw_argv)?, argv_digest(&replacement_argv)?);
    let rendered = command_display(Path::new("codex"), &raw_argv);
    assert!(rendered
        .iter()
        .any(|argument| argument.starts_with("<non-unicode-argv:")));
    assert!(!rendered
        .iter()
        .any(|argument| argument == &raw_root.to_string_lossy()));
    Ok(())
}

include!("tests_part2.rs");
