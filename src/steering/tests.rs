use super::{control_plane::validate_loopback_bind, *};
use crate::{
    hierarchy_ledger::RoleCategory,
    llm::{
        prompt::{Prompt, PromptSection},
        provider::{LlmRequest, WorkProposal},
        FakeProvider,
    },
    process_runner::ProcessCancellation,
    runtime_adapter::{AdapterId, LaunchContext, RuntimeAdapterConfig},
    supervise::ModelCapabilityClass,
};
use git2::Repository;
use serde_json::json;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::Duration,
};

fn repo() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    Repository::init(temp.path()).expect("init repository");
    let path = temp.path().to_path_buf();
    (temp, path)
}

fn worker_binding(run_id: &str, assignment_id: &str) -> AssignmentBinding {
    AssignmentBinding {
        run_id: run_id.to_string(),
        assignment_id: assignment_id.to_string(),
        role_category: RoleCategory::NonDelegatingTerminalWorker,
        model_capability: Some(ModelCapabilityClass::WeakMechanical),
        parent_agent_id: Some("o1-1".to_string()),
        kind: AssignmentKind::Execution,
    }
}

fn coordinator_binding(run_id: &str, assignment_id: &str) -> AssignmentBinding {
    AssignmentBinding {
        run_id: run_id.to_string(),
        assignment_id: assignment_id.to_string(),
        role_category: RoleCategory::DelegatingCoordinator,
        model_capability: Some(ModelCapabilityClass::GeneralJudgment),
        parent_agent_id: Some("o2-1".to_string()),
        kind: AssignmentKind::Execution,
    }
}

fn operator_inject(
    run_id: &str,
    assignment_id: &str,
    action_id: &str,
    now: u64,
) -> SteeringRequest {
    SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: action_id.to_string(),
        run_id: run_id.to_string(),
        assignment_id: assignment_id.to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::InjectCorrectiveInput {
            message: "stop editing src/cli.rs".to_string(),
        },
        deadline_unix_ms: now + 30_000,
    }
}

#[test]
fn unauthenticated_request_is_refused_and_not_steered() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let request = operator_inject("run-1", "task-1", "act-1", now);
    let mut signed = plane.sign(&request).expect("sign");
    signed.mac = "0".repeat(64);
    let decision = plane.submit_signed(signed, now).expect("submit");
    assert_eq!(decision.refused(), Some(SteeringRefusal::Unauthenticated));
    assert!(!decision.ack().steered);
}

#[test]
fn ill_typed_request_is_refused() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let mut request = operator_inject("run-1", "task-1", "act-1", now);
    request.version = 99;
    let decision = plane.submit(request, now).expect("submit");
    assert_eq!(decision.refused(), Some(SteeringRefusal::IllTyped));
    assert!(!decision.ack().steered);
}

#[test]
fn weak_model_cannot_steer_a_coordinator() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(coordinator_binding("run-1", "o1-child"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let request = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-weak".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "o1-child".to_string(),
        actor: SteeringActor::ParentCoordinator {
            agent_id: "o2-1".to_string(),
            role_category: RoleCategory::DelegatingCoordinator,
            model_capability: ModelCapabilityClass::WeakMechanical,
        },
        action: SteeringAction::Pause,
        deadline_unix_ms: now + 5_000,
    };
    let decision = plane.submit(request, now).expect("submit");
    assert_eq!(
        decision.refused(),
        Some(SteeringRefusal::WeakModelCannotSteerCoordinator)
    );
    assert!(!decision.ack().steered);
}

#[test]
fn merge_gate_cannot_be_steered() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(AssignmentBinding {
            run_id: "run-1".to_string(),
            assignment_id: "merge-1".to_string(),
            role_category: RoleCategory::DelegatingCoordinator,
            model_capability: Some(ModelCapabilityClass::CriticalJudgment),
            parent_agent_id: None,
            kind: AssignmentKind::MergeGate,
        })
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let request = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-merge".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "merge-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::HitlDecision {
            tool_call_id: "tool-1".to_string(),
            decision: HitlDecisionKind::Approve,
            replacement: None,
        },
        deadline_unix_ms: now + 5_000,
    };
    let decision = plane.submit(request, now).expect("submit");
    assert_eq!(decision.refused(), Some(SteeringRefusal::MergeBypass));
}

#[test]
fn inject_is_acked_by_fake_session_and_recorded() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let request = operator_inject("run-1", "task-1", "act-inject", now);
    let decision = plane.submit(request, now).expect("submit");
    assert_eq!(decision.ack().outcome, SteeringOutcome::Delivered);
    assert!(!decision.ack().steered);

    let mut provider = FakeProvider::new("fake", "fake-model");
    provider.push_response("req-1", WorkProposal::summary("ok"));
    let mut session = SteerableFakeSession::new(plane.clone(), "run-1", "task-1", provider);
    let prompt = Prompt {
        sections: vec![PromptSection {
            title: "task".to_string(),
            body: "implement the feature".to_string(),
        }],
        redactions: Default::default(),
    };
    let response = session
        .complete(LlmRequest::new("req-1", "fake-model", prompt), now)
        .expect("complete");
    assert!(
        response
            .transcript
            .turns
            .iter()
            .any(|turn| turn.content.contains("steering_corrective_input")),
        "corrective input must be applied to the in-flight Fake prompt"
    );
    assert_eq!(session.injected().len(), 0);
    let evidence = plane.evidence("run-1").expect("evidence");
    assert!(evidence
        .iter()
        .any(|record| record.event == "ack" && record.steered));
    assert!(
        crate::steering::evidence::checkpoint_namespace_untouched(&path).expect("checkpoint probe")
    );
}

#[test]
fn pause_resume_and_narrow_scope_are_applied() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let pause = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-pause".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::Pause,
        deadline_unix_ms: now + 5_000,
    };
    assert_eq!(
        plane.submit(pause, now).expect("pause").ack().outcome,
        SteeringOutcome::Delivered
    );
    let mut provider = FakeProvider::new("fake", "fake-model");
    provider.push_response("req-1", WorkProposal::summary("ok"));
    let mut session = SteerableFakeSession::new(plane.clone(), "run-1", "task-1", provider);
    let prompt = Prompt {
        sections: vec![PromptSection {
            title: "task".to_string(),
            body: "work".to_string(),
        }],
        redactions: Default::default(),
    };
    let paused = session
        .complete(LlmRequest::new("req-1", "fake-model", prompt.clone()), now)
        .expect_err("paused");
    assert!(paused.to_string().contains("paused"));

    let resume = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-resume".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::Resume,
        deadline_unix_ms: now + 5_000,
    };
    plane.submit(resume, now).expect("resume");
    let narrow = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-narrow".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::NarrowScope {
            allowed_paths: vec!["src/steering.rs".to_string()],
        },
        deadline_unix_ms: now + 5_000,
    };
    plane.submit(narrow, now).expect("narrow");
    session.apply_inbox(now).expect("apply");
    assert!(!session.paused());
    assert_eq!(
        session.allowed_paths(),
        Some(["src/steering.rs".to_string()].as_slice())
    );
}

#[test]
fn fake_cancel_is_provider_neutral() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let cancellation = ProcessCancellation::new();
    plane
        .register_live_cancellation("run-1", "task-1", cancellation.clone())
        .expect("register cancel handle");
    let now = plane.current_unix_ms().expect("clock");
    let request = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-cancel".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::CancelAssignment {
            reason: "operator abort".to_string(),
        },
        deadline_unix_ms: now + 5_000,
    };
    let decision = plane.submit(request, now).expect("cancel");
    assert!(cancellation.is_cancelled());
    assert_eq!(decision.ack().outcome, SteeringOutcome::Acknowledged);
    assert!(decision.ack().steered);
}

#[test]
fn cursor_adapter_launch_is_cancelled_through_the_neutral_handle() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "cursor-task"))
        .expect("bind");
    let mut config = RuntimeAdapterConfig::defaults_for(AdapterId::Cursor);
    config.binary = Some(PathBuf::from("cursor-agent"));
    let prompt = path.join("prompt.txt");
    std::fs::write(&prompt, "do not talk to a live cursor binary").expect("prompt");
    let output = path.join("output.txt");
    let spec = config
        .render(&LaunchContext {
            prompt: &prompt,
            model: Some("unused-model"),
            effort: None,
            cwd: &path,
            output: &output,
        })
        .expect("render cursor launch");
    assert_eq!(spec.program, PathBuf::from("cursor-agent"));
    assert!(spec.argv.iter().any(|arg| arg == "--trust"));

    let cancellation = ProcessCancellation::new();
    plane
        .register_live_cancellation("run-1", "cursor-task", cancellation.clone())
        .expect("register");
    let now = plane.current_unix_ms().expect("clock");
    let request = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-cursor-cancel".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "cursor-task".to_string(),
        actor: SteeringActor::ParentCoordinator {
            agent_id: "o1-1".to_string(),
            role_category: RoleCategory::DelegatingCoordinator,
            model_capability: ModelCapabilityClass::GeneralJudgment,
        },
        action: SteeringAction::CancelAssignment {
            reason: "narrowed by parent".to_string(),
        },
        deadline_unix_ms: now + 5_000,
    };
    let decision = plane.submit(request, now).expect("cancel");
    assert!(cancellation.is_cancelled());
    assert_eq!(decision.ack().outcome, SteeringOutcome::Acknowledged);
}

#[test]
fn timeout_does_not_leave_an_unacknowledged_steered_state() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let request = operator_inject("run-1", "task-1", "act-late", now);
    plane.submit(request, now).expect("submit");
    let reports = plane.sweep("run-1", now + 60_000).expect("sweep");
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].outcome, SteeringOutcome::TimedOut);
    assert!(!reports[0].steered);
    let ack = plane
        .acknowledge("run-1", "task-1", "act-late", now + 60_000)
        .expect("late ack");
    assert_eq!(ack.outcome, SteeringOutcome::TimedOut);
    assert!(!ack.steered);
}

#[test]
fn control_plane_http_refuses_bad_mac_and_accepts_signed_submit() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_plane = plane.clone();
    let server = thread::spawn(move || serve_listener(listener, server_plane, server_shutdown));

    let now = plane.current_unix_ms().expect("clock");
    let request = operator_inject("run-1", "task-1", "act-http", now);
    let mut signed = plane.sign(&request).expect("sign");
    signed.mac = "ab".repeat(32);
    let denied = http_post(
        address,
        "/api/steering/submit",
        &serde_json::to_vec(&signed).expect("json"),
    );
    assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");
    assert!(denied.contains("unauthenticated"));

    let signed = plane.sign(&request).expect("sign");
    let accepted = http_post(
        address,
        "/api/steering/submit",
        &serde_json::to_vec(&signed).expect("json"),
    );
    assert!(accepted.starts_with("HTTP/1.1 200"), "{accepted}");
    assert!(accepted.contains("delivered"));

    let ill_typed = http_post(
        address,
        "/api/steering/submit",
        serde_json::to_string(&json!({"unknown": true}))
            .expect("json")
            .as_bytes(),
    );
    assert!(ill_typed.starts_with("HTTP/1.1 400"), "{ill_typed}");

    shutdown.store(true, std::sync::atomic::Ordering::Release);
    thread::sleep(Duration::from_millis(50));
    drop(server);
}

#[test]
fn review_gate_cannot_be_steered() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(AssignmentBinding {
            run_id: "run-1".to_string(),
            assignment_id: "review-1".to_string(),
            role_category: RoleCategory::ReadOnlyReviewAuditor,
            model_capability: Some(ModelCapabilityClass::CriticalJudgment),
            parent_agent_id: None,
            kind: AssignmentKind::ReviewGate,
        })
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let request = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-review".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "review-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::HitlDecision {
            tool_call_id: "tool-1".to_string(),
            decision: HitlDecisionKind::Approve,
            replacement: None,
        },
        deadline_unix_ms: now + 5_000,
    };
    let decision = plane.submit(request, now).expect("submit");
    assert_eq!(decision.refused(), Some(SteeringRefusal::MergeBypass));
    assert!(!decision.ack().steered);
}

#[test]
fn unknown_target_and_expired_deadline_fail_closed() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    let now = plane.current_unix_ms().expect("clock");
    let missing = plane
        .submit(
            operator_inject("run-missing", "task-1", "act-missing", now),
            now,
        )
        .expect("missing");
    assert_eq!(missing.refused(), Some(SteeringRefusal::UnknownTarget));
    assert!(!missing.ack().steered);

    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let mut expired = operator_inject("run-1", "task-1", "act-expired", now);
    expired.deadline_unix_ms = now.saturating_sub(1);
    let decision = plane.submit(expired, now).expect("expired");
    assert_eq!(decision.refused(), Some(SteeringRefusal::DeadlineExpired));
    assert!(!decision.ack().steered);
}

#[test]
fn duplicate_action_id_with_a_different_payload_is_refused() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let first = operator_inject("run-1", "task-1", "act-dup", now);
    assert_eq!(
        plane
            .submit(first.clone(), now)
            .expect("first")
            .ack()
            .outcome,
        SteeringOutcome::Delivered
    );
    let mut second = first;
    second.action = SteeringAction::InjectCorrectiveInput {
        message: "a different correction".to_string(),
    };
    let decision = plane.submit(second, now).expect("second");
    assert_eq!(decision.refused(), Some(SteeringRefusal::DuplicateAction));
    assert!(!decision.ack().steered);
}

#[test]
fn parent_authority_and_foreign_child_fail_closed() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let leaf_parent = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-leaf".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::ParentCoordinator {
            agent_id: "o1-1".to_string(),
            role_category: RoleCategory::NonDelegatingTerminalWorker,
            model_capability: ModelCapabilityClass::GeneralJudgment,
        },
        action: SteeringAction::Pause,
        deadline_unix_ms: now + 5_000,
    };
    assert_eq!(
        plane.submit(leaf_parent, now).expect("leaf").refused(),
        Some(SteeringRefusal::InsufficientAuthority)
    );

    let foreign = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-foreign".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::ParentCoordinator {
            agent_id: "o1-other".to_string(),
            role_category: RoleCategory::DelegatingCoordinator,
            model_capability: ModelCapabilityClass::GeneralJudgment,
        },
        action: SteeringAction::Pause,
        deadline_unix_ms: now + 5_000,
    };
    assert_eq!(
        plane.submit(foreign, now).expect("foreign").refused(),
        Some(SteeringRefusal::InsufficientAuthority)
    );

    let allowed = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-parent".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::ParentCoordinator {
            agent_id: "o1-1".to_string(),
            role_category: RoleCategory::DelegatingCoordinator,
            model_capability: ModelCapabilityClass::GeneralJudgment,
        },
        action: SteeringAction::Pause,
        deadline_unix_ms: now + 5_000,
    };
    assert_eq!(
        plane.submit(allowed, now).expect("allowed").ack().outcome,
        SteeringOutcome::Delivered
    );
}

#[test]
fn hitl_edit_requires_replacement_and_survives_reopen() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let now = plane.current_unix_ms().expect("clock");
    let missing_replacement = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-bad-edit".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::HitlDecision {
            tool_call_id: "tool-1".to_string(),
            decision: HitlDecisionKind::Edit,
            replacement: None,
        },
        deadline_unix_ms: now + 5_000,
    };
    assert_eq!(
        plane
            .submit(missing_replacement, now)
            .expect("ill typed")
            .refused(),
        Some(SteeringRefusal::IllTyped)
    );

    let reject = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-reject".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::HitlDecision {
            tool_call_id: "tool-1".to_string(),
            decision: HitlDecisionKind::Reject,
            replacement: None,
        },
        deadline_unix_ms: now + 5_000,
    };
    assert_eq!(
        plane.submit(reject, now).expect("reject").ack().outcome,
        SteeringOutcome::Delivered
    );

    let reopened = SteeringPlane::open(&path).expect("reopen");
    let inbox = reopened.inbox("run-1", "task-1").expect("inbox");
    assert!(inbox.iter().any(|directive| matches!(
        directive.action,
        SteeringAction::HitlDecision {
            decision: HitlDecisionKind::Reject,
            ..
        }
    )));
    assert!(
        crate::steering::evidence::checkpoint_namespace_untouched(&path).expect("checkpoint probe")
    );

    let mut provider = FakeProvider::new("fake", "fake-model");
    provider.push_response("req-1", WorkProposal::summary("ok"));
    let mut session = SteerableFakeSession::new(reopened.clone(), "run-1", "task-1", provider);
    let prompt = Prompt {
        sections: vec![PromptSection {
            title: "task".to_string(),
            body: "work".to_string(),
        }],
        redactions: Default::default(),
    };
    let paused = session
        .complete(LlmRequest::new("req-1", "fake-model", prompt.clone()), now)
        .expect_err("rejected tool must pause");
    assert!(paused.to_string().contains("paused"));
    assert_eq!(
        session.hitl_decisions(),
        &[("tool-1".to_string(), HitlDecisionKind::Reject)]
    );

    let approve = SteeringRequest {
        version: STEERING_REQUEST_VERSION,
        action_id: "act-approve".to_string(),
        run_id: "run-1".to_string(),
        assignment_id: "task-1".to_string(),
        actor: SteeringActor::Operator {
            agent_id: "operator".to_string(),
        },
        action: SteeringAction::HitlDecision {
            tool_call_id: "tool-1".to_string(),
            decision: HitlDecisionKind::Approve,
            replacement: None,
        },
        deadline_unix_ms: now + 5_000,
    };
    reopened.submit(approve, now).expect("approve");
    session.apply_inbox(now).expect("resume");
    assert!(!session.paused());
}

#[test]
fn loopback_bind_is_required() {
    assert!(validate_loopback_bind("0.0.0.0:0").is_err());
    assert!(validate_loopback_bind("192.0.2.1:7878").is_err());
    let accepted = validate_loopback_bind("127.0.0.1:0").expect("loopback");
    assert!(accepted.ip().is_loopback());
}

#[test]
fn http_ack_and_sweep_fail_closed_without_a_mac() {
    let (_temp, path) = repo();
    let plane = SteeringPlane::open(&path).expect("open plane");
    plane
        .register_assignment(worker_binding("run-1", "task-1"))
        .expect("bind");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_plane = plane.clone();
    let server = thread::spawn(move || serve_listener(listener, server_plane, server_shutdown));

    let now = plane.current_unix_ms().expect("clock");
    let request = operator_inject("run-1", "task-1", "act-http-ack", now);
    let signed = plane.sign(&request).expect("sign");
    let accepted = http_post(
        address,
        "/api/steering/submit",
        &serde_json::to_vec(&signed).expect("json"),
    );
    assert!(accepted.starts_with("HTTP/1.1 200"), "{accepted}");

    let unsigned_ack = http_post(
        address,
        "/api/steering/ack",
        serde_json::to_string(&json!({
            "run_id": "run-1",
            "assignment_id": "task-1",
            "action_id": "act-http-ack"
        }))
        .expect("json")
        .as_bytes(),
    );
    assert!(unsigned_ack.starts_with("HTTP/1.1 400"), "{unsigned_ack}");

    let mut forged = plane
        .sign_ack("run-1", "task-1", "act-http-ack")
        .expect("sign ack");
    forged.mac = "ab".repeat(32);
    let denied = http_post(
        address,
        "/api/steering/ack",
        &serde_json::to_vec(&forged).expect("json"),
    );
    assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");

    let signed_ack = plane
        .sign_ack("run-1", "task-1", "act-http-ack")
        .expect("sign ack");
    let acked = http_post(
        address,
        "/api/steering/ack",
        &serde_json::to_vec(&signed_ack).expect("json"),
    );
    assert!(acked.starts_with("HTTP/1.1 200"), "{acked}");
    assert!(acked.contains("acknowledged"));

    let unsigned_sweep = http_post(
        address,
        "/api/steering/sweep",
        serde_json::to_string(&json!({"run_id": "run-1"}))
            .expect("json")
            .as_bytes(),
    );
    assert!(
        unsigned_sweep.starts_with("HTTP/1.1 400"),
        "{unsigned_sweep}"
    );

    shutdown.store(true, std::sync::atomic::Ordering::Release);
    thread::sleep(Duration::from_millis(50));
    drop(server);
}

fn http_post(address: std::net::SocketAddr, path: &str, body: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).expect("write header");
    stream.write_all(body).expect("write body");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}
