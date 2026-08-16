use super::{
    types::{
        derive_collection_key, derive_control_key, derive_execution_key, derive_query_key,
        derive_wait_key,
    },
    *,
};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

#[derive(Debug)]
enum Script {
    Stage(TransportCall<StageTransportReceipt>),
    Launch(TransportCall<LaunchReceipt>),
    Status(TransportCall<StatusReceipt>),
    Wait(TransportCall<WaitReceipt>),
    Control(TransportCall<ControlReceipt>),
    Collect(TransportCall<CollectionReceipt>),
    Cleanup(TransportCall<CleanupReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestRecord {
    Stage(StageTransportRequest),
    Launch(LaunchTransportRequest),
    Status(StatusTransportRequest),
    Wait(WaitTransportRequest),
    Control(ControlTransportRequest),
    Collect(CollectionTransportRequest),
    Cleanup(CleanupTransportRequest),
}

#[derive(Debug)]
struct ScriptedTransport {
    script: Mutex<VecDeque<Script>>,
    requests: Mutex<Vec<RequestRecord>>,
}

impl ScriptedTransport {
    fn new(script: Vec<Script>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, request: RequestRecord) {
        self.requests.lock().expect("requests mutex").push(request);
    }

    fn pop(&self) -> Script {
        self.script
            .lock()
            .expect("script mutex")
            .pop_front()
            .expect("scripted response")
    }

    fn requests(&self) -> Vec<RequestRecord> {
        self.requests.lock().expect("requests mutex").clone()
    }

    fn assert_consumed(&self) {
        assert!(self.script.lock().expect("script mutex").is_empty());
    }
}

impl SshTransport for ScriptedTransport {
    fn stage(&self, request: StageTransportRequest) -> TransportCall<StageTransportReceipt> {
        self.record(RequestRecord::Stage(request));
        match self.pop() {
            Script::Stage(response) => response,
            other => panic!("expected stage response, got {other:?}"),
        }
    }

    fn launch(&self, request: LaunchTransportRequest) -> TransportCall<LaunchReceipt> {
        self.record(RequestRecord::Launch(request));
        match self.pop() {
            Script::Launch(response) => response,
            other => panic!("expected launch response, got {other:?}"),
        }
    }

    fn status(&self, request: StatusTransportRequest) -> TransportCall<StatusReceipt> {
        self.record(RequestRecord::Status(request));
        match self.pop() {
            Script::Status(response) => response,
            other => panic!("expected status response, got {other:?}"),
        }
    }

    fn wait(&self, request: WaitTransportRequest) -> TransportCall<WaitReceipt> {
        self.record(RequestRecord::Wait(request));
        match self.pop() {
            Script::Wait(response) => response,
            other => panic!("expected wait response, got {other:?}"),
        }
    }

    fn control(&self, request: ControlTransportRequest) -> TransportCall<ControlReceipt> {
        self.record(RequestRecord::Control(request));
        match self.pop() {
            Script::Control(response) => response,
            other => panic!("expected control response, got {other:?}"),
        }
    }

    fn collect(&self, request: CollectionTransportRequest) -> TransportCall<CollectionReceipt> {
        self.record(RequestRecord::Collect(request));
        match self.pop() {
            Script::Collect(response) => response,
            other => panic!("expected collect response, got {other:?}"),
        }
    }

    fn cleanup(&self, request: CleanupTransportRequest) -> TransportCall<CleanupReceipt> {
        self.record(RequestRecord::Cleanup(request));
        match self.pop() {
            Script::Cleanup(response) => response,
            other => panic!("expected cleanup response, got {other:?}"),
        }
    }
}

fn target() -> SshTargetConfig {
    serde_json::from_str(
        r#"{
            "host_id":"home-lxc-a",
            "endpoint":"lxc-a.internal",
            "user":"maco-runner",
            "port":2222,
            "helper":"/opt/maco/bin/remote-helper",
            "root":"/srv/maco/workspaces"
        }"#,
    )
    .expect("valid target")
}

fn assignment() -> AssignmentIdentity {
    AssignmentIdentity::new(
        HostId::new("home-lxc-a").expect("host"),
        RunId::new("run-41").expect("run"),
        AssignmentId::new("worker-2").expect("assignment"),
        Nonce::new("nonce-fresh-9").expect("nonce"),
    )
}

fn path(value: &str) -> LogicalPath {
    LogicalPath::new(value).expect("logical path")
}

fn manifest() -> InputManifest {
    InputManifest::new(vec![
        ManifestEntry::input_file(
            path("input/prompt.txt"),
            ManifestPurpose::Prompt,
            b"perform the assignment".to_vec(),
        )
        .expect("prompt entry"),
        ManifestEntry::input_file(
            path("workspace/src/lib.rs"),
            ManifestPurpose::WorkspaceInput,
            b"pub fn initial() {}".to_vec(),
        )
        .expect("workspace entry"),
        ManifestEntry::output_path(
            path("output/final.txt"),
            ManifestPurpose::FinalMessageOutput,
            1024,
        )
        .expect("final output"),
        ManifestEntry::output_path(
            path("output/events.jsonl"),
            ManifestPurpose::JsonLogOutput,
            4096,
        )
        .expect("JSON log output"),
        ManifestEntry::output_path(
            path("artifacts/log.txt"),
            ManifestPurpose::DeclaredOutput,
            64,
        )
        .expect("declared output"),
    ])
    .expect("manifest")
}

fn stage_request() -> StageRequest {
    StageRequest::new(assignment(), manifest())
}

fn stage_receipt(request: &StageRequest) -> StageTransportReceipt {
    StageTransportReceipt::from_wire(
        EXECUTOR_PROTOCOL_VERSION,
        request.key().clone(),
        request.identity().clone(),
        request.manifest().digest().clone(),
        SessionId::new("session-1").expect("session"),
        WorkspaceId::new("workspace-1").expect("workspace"),
    )
}

fn staged() -> StagedAssignment {
    let manifest = manifest();
    StagedAssignment {
        identity: assignment(),
        staged_digest: manifest.digest().clone(),
        session_id: SessionId::new("session-1").expect("session"),
        workspace_id: WorkspaceId::new("workspace-1").expect("workspace"),
        manifest,
    }
}

fn argv() -> TypedArgv {
    TypedArgv::new(vec![
        TypedArg::Literal(BoundedLiteral::new("exec").expect("literal")),
        TypedArg::Literal(BoundedLiteral::new("--output-last-message").expect("literal")),
        TypedArg::ManifestPath(path("output/final.txt")),
        TypedArg::Literal(BoundedLiteral::new("--json-log").expect("literal")),
        TypedArg::ManifestPath(path("output/events.jsonl")),
        TypedArg::ManifestPath(path("workspace/src/lib.rs")),
        TypedArg::FinalStdinMarker,
    ])
    .expect("typed argv")
}

fn launch_spec(deadline_ms: u64) -> LaunchSpec {
    LaunchSpec::new(
        argv(),
        path("input/prompt.txt"),
        BoundedMillis::new(deadline_ms).expect("deadline"),
    )
}

fn execution(staged: &StagedAssignment, spec: &LaunchSpec) -> ExecutionIdentity {
    let submitted = SubmittedLaunchIdentity::for_launch(staged, spec);
    ExecutionIdentity::from_wire(
        submitted.assignment.host_id.clone(),
        submitted.assignment.run_id.clone(),
        submitted.assignment.assignment_id.clone(),
        submitted.assignment.nonce.clone(),
        submitted.staged_digest.clone(),
        submitted.session_id.clone(),
        submitted.workspace_id.clone(),
        submitted.launch_spec_digest.clone(),
        4321,
        4321,
        StartToken::new("boot-8-start-9001").expect("start token"),
        submitted.launch_key.clone(),
    )
    .expect("execution identity")
}

fn launch_fixture(deadline_ms: u64) -> (LaunchRequest, SubmittedLaunchIdentity, ExecutionIdentity) {
    let staged = staged();
    let spec = launch_spec(deadline_ms);
    let submitted = SubmittedLaunchIdentity::for_launch(&staged, &spec);
    let identity = execution(&staged, &spec);
    (LaunchRequest::new(staged, spec), submitted, identity)
}

fn launch_receipt(identity: &ExecutionIdentity) -> LaunchReceipt {
    LaunchReceipt::from_wire(
        EXECUTOR_PROTOCOL_VERSION,
        identity.launch_key().clone(),
        identity.clone(),
    )
}

fn output_policy(patch_max: u64, output_max: u64) -> OutputPolicy {
    OutputPolicy::new(
        patch_max,
        16,
        vec![path("src")],
        vec![
            DeclaredOutput::new(path("artifacts/log.txt"), "text/plain", output_max)
                .expect("declared output"),
        ],
        output_max,
    )
    .expect("output policy")
}

fn patch_for(path: &str) -> Vec<u8> {
    format!("diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n")
        .into_bytes()
}

fn collection_receipt(
    identity: &ExecutionIdentity,
    policy: &OutputPolicy,
    changed_paths: Vec<String>,
    patch_bytes: Vec<u8>,
) -> CollectionReceipt {
    let key = derive_collection_key(identity, policy.digest());
    let limits = TransportReadLimits::for_policy(policy).expect("transport limits");
    let patch =
        CollectedBlob::checksummed(patch_bytes, limits.patch_max_bytes).expect("bounded patch");
    let outputs = policy
        .declared_outputs()
        .first()
        .map(|declared| {
            let blob = CollectedBlob::checksummed(b"ok".to_vec(), declared.max_bytes())
                .expect("bounded output");
            CollectedOutputEnvelope::from_wire(
                declared.path().to_string(),
                declared.media_type().to_string(),
                blob,
            )
            .expect("output envelope")
        })
        .into_iter()
        .collect::<Vec<_>>();
    let manifest_digest = CollectionReceipt::canonical_manifest_digest(
        EXECUTOR_PROTOCOL_VERSION,
        &key,
        identity,
        policy.digest(),
        &patch,
        &changed_paths,
        &outputs,
    );
    CollectionReceipt::from_wire_bounded(
        EXECUTOR_PROTOCOL_VERSION,
        key,
        identity.clone(),
        policy.digest().clone(),
        patch,
        changed_paths,
        outputs,
        manifest_digest,
        &limits,
    )
    .expect("bounded collection receipt")
}

fn cleanup_receipt(identity: &ExecutionIdentity, removed: bool) -> CleanupReceipt {
    CleanupReceipt::from_wire(
        EXECUTOR_PROTOCOL_VERSION,
        derive_execution_key("cleanup", identity),
        identity.clone(),
        identity.workspace_id().clone(),
        removed,
    )
}

#[test]
fn sha256_matches_known_and_padding_boundary_vectors() {
    let vectors = [
        (
            Vec::new(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".to_vec(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            vec![b'a'; 55],
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        ),
        (
            vec![b'a'; 56],
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        ),
        (
            vec![b'a'; 63],
            "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
        ),
        (
            vec![b'a'; 64],
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        ),
        (
            vec![b'a'; 65],
            "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
        ),
    ];
    for (bytes, expected) in vectors {
        assert_eq!(Digest::for_bytes(&bytes).as_str(), expected);
    }
}

#[test]
fn config_is_strict_credential_free_and_remote_paths_are_unambiguous() {
    let parsed = target();
    assert_eq!(parsed.host_id.as_str(), "home-lxc-a");
    assert_eq!(parsed.endpoint.as_str(), "lxc-a.internal");
    assert_eq!(parsed.helper.as_str(), "/opt/maco/bin/remote-helper");
    for extra in ["private_key", "password", "credential", "token"] {
        let value = format!(
            "{{\"host_id\":\"home-lxc-a\",\"endpoint\":\"lxc-a.internal\",\"user\":\"runner\",\"port\":22,\"helper\":\"/opt/maco/helper\",\"root\":\"/srv/maco/runs\",\"{extra}\":\"secret\"}}"
        );
        assert!(serde_json::from_str::<SshTargetConfig>(&value).is_err());
    }
    for remote in [
        "/srv/maco/%2e%2e/runs",
        "/srv/maco runs",
        "/srv//runs",
        "/srv/maco/../runs",
        "/srv/maco\\runs",
    ] {
        assert!(
            RemoteAbsolutePath::new(remote).is_err(),
            "accepted {remote}"
        );
    }
}

#[test]
fn logical_paths_literals_and_argv_fail_closed_on_path_spellings() {
    for raw in [
        "/etc/passwd",
        "../outside",
        "src/../outside",
        "C:\\Windows\\system32",
        "src/%2e%2e/outside",
        "src//lib.rs",
    ] {
        assert!(LogicalPath::new(raw).is_err(), "accepted {raw}");
    }
    for literal in [
        "/etc/passwd",
        "src/lib.rs",
        "C:\\temp",
        "C:temp",
        "..",
        "%2f",
    ] {
        assert!(BoundedLiteral::new(literal).is_err(), "accepted {literal}");
    }
    assert!(TypedArgv::new(vec![
        TypedArg::FinalStdinMarker,
        TypedArg::Literal(BoundedLiteral::new("late").expect("literal")),
    ])
    .is_err());
}

#[test]
fn manifest_rejects_wrong_direction_per_file_and_aggregate_bounds() {
    assert!(ManifestEntry::input_file(
        path("output/x"),
        ManifestPurpose::DeclaredOutput,
        Vec::new(),
    )
    .is_err());
    assert!(ManifestEntry::output_path(path("input/x"), ManifestPurpose::Prompt, 1).is_err());
    assert!(ManifestEntry::input_file(
        path("input/huge"),
        ManifestPurpose::WorkspaceInput,
        vec![0; 8 * 1024 * 1024 + 1],
    )
    .is_err());

    let mut entries = Vec::new();
    for index in 0..4 {
        entries.push(
            ManifestEntry::input_file(
                path(&format!("workspace/chunk-{index}")),
                ManifestPurpose::WorkspaceInput,
                vec![index as u8; 8 * 1024 * 1024],
            )
            .expect("bounded chunk"),
        );
    }
    entries.push(
        ManifestEntry::input_file(
            path("workspace/overflow"),
            ManifestPurpose::WorkspaceInput,
            vec![0],
        )
        .expect("small overflow chunk"),
    );
    assert!(matches!(
        InputManifest::new(entries),
        Err(ExecutorError::LimitExceeded {
            what: "staged input aggregate bytes",
            ..
        })
    ));

    let declared = vec![
        DeclaredOutput::new(path("artifacts/a"), "text/plain", 3).expect("output a"),
        DeclaredOutput::new(path("artifacts/b"), "text/plain", 3).expect("output b"),
    ];
    assert!(matches!(
        OutputPolicy::new(64, 4, vec![path("src")], declared, 5),
        Err(ExecutorError::LimitExceeded {
            what: "declared output aggregate bounds",
            limit: 5,
        })
    ));
}

#[test]
fn stage_defensively_rejects_tampered_entry_digest_and_key_before_transport() {
    let mut request = stage_request();
    request.manifest.tamper_first_input_digest_for_test();
    let executor = SshExecutor::new(target(), ScriptedTransport::new(Vec::new()));
    assert!(matches!(
        executor.stage(request),
        Err(ExecutorError::ChecksumMismatch { .. })
    ));
    assert!(executor.transport().requests().is_empty());

    let mut request = stage_request();
    request.tamper_key_for_test(IdempotencyKey::new("0".repeat(64)).expect("key"));
    assert!(matches!(
        executor.stage(request),
        Err(ExecutorError::InvalidField {
            field: "stage idempotency key",
            ..
        })
    ));
    assert!(executor.transport().requests().is_empty());
}

#[test]
fn stage_rejects_mismatched_host_and_wrong_receipt_identity() {
    let foreign = StageRequest::new(
        AssignmentIdentity::new(
            HostId::new("foreign").expect("host"),
            RunId::new("run").expect("run"),
            AssignmentId::new("assignment").expect("assignment"),
            Nonce::new("nonce").expect("nonce"),
        ),
        manifest(),
    );
    let executor = SshExecutor::new(target(), ScriptedTransport::new(Vec::new()));
    assert!(executor.stage(foreign).is_err());
    assert!(executor.transport().requests().is_empty());

    let request = stage_request();
    let bad = StageTransportReceipt::from_wire(
        EXECUTOR_PROTOCOL_VERSION,
        request.key().clone(),
        AssignmentIdentity::new(
            request.identity().host_id.clone(),
            RunId::new("wrong-run").expect("run"),
            request.identity().assignment_id.clone(),
            request.identity().nonce.clone(),
        ),
        request.manifest().digest().clone(),
        SessionId::new("session-1").expect("session"),
        WorkspaceId::new("workspace-1").expect("workspace"),
    );
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![Script::Stage(TransportCall::Response(bad))]),
    );
    assert!(matches!(
        executor.stage(request),
        Err(ExecutorError::MalformedReceipt {
            operation: Operation::Stage,
            ..
        })
    ));
}

#[test]
fn stage_uncertainty_has_operator_only_bound_lookup() {
    let request = stage_request();
    let expected_key = request.key().clone();
    let expected_digest = request.manifest().digest().clone();
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![Script::Stage(TransportCall::LostResponse {
            detail: "response lost".to_string(),
        })]),
    );
    let uncertain = match executor.stage(request).expect("stage uncertainty") {
        Effect::Uncertain(value) => value,
        Effect::Confirmed(value) => panic!("unexpected stage confirmation: {value:?}"),
    };
    assert_eq!(uncertain.key, expected_key);
    assert!(matches!(
        uncertain.reconciliation,
        ReconciliationTarget::StageOperator(StageLookup {
            manifest_digest,
            operator_only: true,
            ..
        }) if manifest_digest == expected_digest
    ));
}

#[test]
fn launch_and_collection_keys_change_with_complete_payloads() {
    let (_, submitted_a, identity_a) = launch_fixture(1_000);
    let (_, submitted_b, _) = launch_fixture(2_000);
    assert_ne!(
        submitted_a.launch_spec_digest(),
        submitted_b.launch_spec_digest()
    );
    assert_ne!(submitted_a.launch_key(), submitted_b.launch_key());

    let policy_a = output_policy(1024, 64);
    let policy_b = output_policy(2048, 64);
    assert_ne!(policy_a.digest(), policy_b.digest());
    assert_ne!(
        derive_collection_key(&identity_a, policy_a.digest()),
        derive_collection_key(&identity_a, policy_b.digest())
    );
    assert_ne!(
        derive_wait_key("wait", &identity_a, BoundedMillis::new(10).expect("wait")),
        derive_wait_key("wait", &identity_a, BoundedMillis::new(11).expect("wait"))
    );
}

#[test]
fn scripted_success_records_and_matches_complete_typed_envelopes() {
    let stage = stage_request();
    let expected_stage = StageTransportRequest {
        target: target(),
        stage: stage.clone(),
    };
    let staged_value = staged();
    let spec = launch_spec(30_000);
    let submitted = SubmittedLaunchIdentity::for_launch(&staged_value, &spec);
    let identity = execution(&staged_value, &spec);
    let expected_launch = LaunchTransportRequest {
        target: target(),
        submitted: submitted.clone(),
        argv: spec.argv().clone(),
        stdin: spec.stdin().clone(),
        deadline: spec.deadline(),
    };
    let query = ExecutionQuery::Known(identity.clone());
    let status_key = derive_query_key("status", &query);
    let expected_status = StatusTransportRequest {
        target: target(),
        key: status_key.clone(),
        query: query.clone(),
    };
    let max_wait = BoundedMillis::new(1_000).expect("wait");
    let wait_key = derive_wait_key("wait", &identity, max_wait);
    let expected_wait = WaitTransportRequest {
        target: target(),
        key: wait_key.clone(),
        identity: identity.clone(),
        max_wait,
    };
    let policy = output_policy(1024, 64);
    let collect_key = derive_collection_key(&identity, policy.digest());
    let expected_collect = CollectionTransportRequest {
        target: target(),
        key: collect_key.clone(),
        identity: identity.clone(),
        policy: policy.clone(),
        policy_digest: policy.digest().clone(),
        read_limits: TransportReadLimits::for_policy(&policy).expect("transport limits"),
    };
    let expected_cleanup = CleanupTransportRequest {
        target: target(),
        key: derive_execution_key("cleanup", &identity),
        identity: identity.clone(),
        workspace_id: identity.workspace_id().clone(),
    };
    let transport = ScriptedTransport::new(vec![
        Script::Stage(TransportCall::Response(stage_receipt(&stage))),
        Script::Launch(TransportCall::Response(launch_receipt(&identity))),
        Script::Status(TransportCall::Response(StatusReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            status_key,
            query.clone(),
            ExecutionStatus::Running(identity.clone()),
        ))),
        Script::Wait(TransportCall::Response(WaitReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            wait_key,
            identity.clone(),
            WaitOutcome::Exited { code: 0 },
        ))),
        Script::Collect(TransportCall::Response(collection_receipt(
            &identity,
            &policy,
            vec!["src/lib.rs".to_string()],
            patch_for("src/lib.rs"),
        ))),
        Script::Cleanup(TransportCall::Response(cleanup_receipt(&identity, true))),
    ]);
    let executor = SshExecutor::new(target(), transport);
    let object_safe: &dyn AgentExecutor = &executor;
    let staged_result = match object_safe.stage(stage).expect("stage") {
        Effect::Confirmed(value) => value,
        Effect::Uncertain(value) => panic!("unexpected uncertainty: {value:?}"),
    };
    let launched = match object_safe
        .launch(LaunchRequest::new(staged_result, launch_spec(30_000)))
        .expect("launch")
    {
        Effect::Confirmed(value) => value,
        Effect::Uncertain(value) => panic!("unexpected uncertainty: {value:?}"),
    };
    assert!(matches!(
        object_safe
            .status(StatusRequest {
                query: ExecutionQuery::Known(launched.identity().clone()),
            })
            .expect("status"),
        ExecutionStatus::Running(_)
    ));
    assert_eq!(
        object_safe
            .wait(WaitRequest::new(
                launched.identity().clone(),
                WaitSpec::new(max_wait),
            ))
            .expect("wait"),
        WaitOutcome::Exited { code: 0 }
    );
    let collected = match object_safe
        .collect(CollectRequest::new(launched.identity().clone(), policy))
        .expect("collect")
    {
        Effect::Confirmed(value) => value,
        Effect::Uncertain(value) => panic!("unexpected uncertainty: {value:?}"),
    };
    assert!(collected.is_candidate_evidence_only());
    assert!(matches!(collected.cleanup(), Effect::Confirmed(_)));
    assert_eq!(
        executor.transport().requests(),
        vec![
            RequestRecord::Stage(expected_stage),
            RequestRecord::Launch(expected_launch),
            RequestRecord::Status(expected_status),
            RequestRecord::Wait(expected_wait),
            RequestRecord::Collect(expected_collect),
            RequestRecord::Cleanup(expected_cleanup),
        ]
    );
    executor.transport().assert_consumed();
}

#[test]
fn nonzero_exit_and_timeout_are_process_outcomes() {
    let (_, _, identity) = launch_fixture(1_000);
    let max_wait = BoundedMillis::new(500).expect("wait");
    let transport = ScriptedTransport::new(vec![Script::Wait(TransportCall::Response(
        WaitReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            derive_wait_key("wait", &identity, max_wait),
            identity.clone(),
            WaitOutcome::Exited { code: 17 },
        ),
    ))]);
    let executor = SshExecutor::new(target(), transport);
    assert_eq!(
        executor
            .wait(WaitRequest::new(identity, WaitSpec::new(max_wait)))
            .expect("nonzero process outcome"),
        WaitOutcome::Exited { code: 17 }
    );
}

#[test]
fn timeout_uses_payload_bound_term_wait_kill_wait_sequence() {
    let (_, _, identity) = launch_fixture(1_000);
    let initial = BoundedMillis::new(10).expect("wait");
    let policy = TerminationPolicy::new(
        BoundedMillis::new(50).expect("term grace"),
        BoundedMillis::new(60).expect("kill wait"),
    );
    let term_key = derive_control_key("terminate-term", &identity, ControlSignal::Term, &policy);
    let grace_key = derive_wait_key("terminate-grace-wait", &identity, policy.term_grace);
    let kill_key = derive_control_key("terminate-kill", &identity, ControlSignal::Kill, &policy);
    let kill_wait_key = derive_wait_key("terminate-kill-wait", &identity, policy.kill_wait);
    let transport = ScriptedTransport::new(vec![
        Script::Wait(TransportCall::Response(WaitReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            derive_wait_key("wait", &identity, initial),
            identity.clone(),
            WaitOutcome::TimedOut,
        ))),
        Script::Control(TransportCall::Response(ControlReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            term_key,
            identity.clone(),
            ControlSignal::Term,
        ))),
        Script::Wait(TransportCall::Response(WaitReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            grace_key,
            identity.clone(),
            WaitOutcome::RunningAtDeadline,
        ))),
        Script::Control(TransportCall::Response(ControlReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            kill_key,
            identity.clone(),
            ControlSignal::Kill,
        ))),
        Script::Wait(TransportCall::Response(WaitReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            kill_wait_key,
            identity.clone(),
            WaitOutcome::Signaled {
                signal: ControlSignal::Kill,
            },
        ))),
    ]);
    let executor = SshExecutor::new(target(), transport);
    assert_eq!(
        executor
            .wait(WaitRequest::new(identity.clone(), WaitSpec::new(initial),))
            .expect("timeout"),
        WaitOutcome::TimedOut
    );
    let receipt = match executor
        .terminate(TerminateRequest::new(identity, policy))
        .expect("terminate")
    {
        Effect::Confirmed(value) => value,
        Effect::Uncertain(value) => panic!("unexpected uncertainty: {value:?}"),
    };
    assert!(receipt.kill.is_some());
    assert!(matches!(
        executor.transport().requests().as_slice(),
        [
            RequestRecord::Wait(_),
            RequestRecord::Control(ControlTransportRequest {
                signal: ControlSignal::Term,
                ..
            }),
            RequestRecord::Wait(_),
            RequestRecord::Control(ControlTransportRequest {
                signal: ControlSignal::Kill,
                ..
            }),
            RequestRecord::Wait(_),
        ]
    ));
}

#[test]
fn wrong_control_signal_receipt_is_rejected_without_kill() {
    let (_, _, identity) = launch_fixture(1_000);
    let policy = TerminationPolicy::new(
        BoundedMillis::new(50).expect("term grace"),
        BoundedMillis::new(50).expect("kill wait"),
    );
    let key = derive_control_key("terminate-term", &identity, ControlSignal::Term, &policy);
    let transport = ScriptedTransport::new(vec![Script::Control(TransportCall::Response(
        ControlReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            key,
            identity.clone(),
            ControlSignal::Kill,
        ),
    ))]);
    let executor = SshExecutor::new(target(), transport);
    assert!(matches!(
        executor.terminate(TerminateRequest::new(identity, policy)),
        Err(ExecutorError::MalformedReceipt {
            operation: Operation::TerminateTerm,
            ..
        })
    ));
    assert_eq!(executor.transport().requests().len(), 1);
}

#[test]
fn lost_launch_reconciles_status_only_and_never_duplicates_launch() {
    let (request, submitted, identity) = launch_fixture(1_000);
    let query = ExecutionQuery::Submitted(submitted.clone());
    let status_key = derive_query_key("status", &query);
    let expected_launch = LaunchTransportRequest {
        target: target(),
        submitted: submitted.clone(),
        argv: request.spec().argv().clone(),
        stdin: request.spec().stdin().clone(),
        deadline: request.spec().deadline(),
    };
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![
            Script::Launch(TransportCall::LostResponse {
                detail: "connection closed after write".to_string(),
            }),
            Script::Status(TransportCall::Response(StatusReceipt::from_wire(
                EXECUTOR_PROTOCOL_VERSION,
                status_key.clone(),
                query.clone(),
                ExecutionStatus::Running(identity.clone()),
            ))),
        ]),
    );
    let uncertain = match executor.launch(request).expect("uncertain launch") {
        Effect::Uncertain(value) => value,
        Effect::Confirmed(value) => panic!("unexpected launch confirmation: {value:?}"),
    };
    assert_eq!(uncertain.key, submitted.launch_key().clone());
    assert_eq!(
        uncertain.reconciliation,
        ReconciliationTarget::Execution(query.clone())
    );
    assert_eq!(
        executor
            .status(StatusRequest {
                query: query.clone(),
            })
            .expect("status-only reconciliation"),
        ExecutionStatus::Running(identity)
    );
    assert_eq!(
        executor.transport().requests(),
        vec![
            RequestRecord::Launch(expected_launch),
            RequestRecord::Status(StatusTransportRequest {
                target: target(),
                key: status_key,
                query,
            }),
        ]
    );
    executor.transport().assert_consumed();
}

#[test]
fn malformed_launch_receipt_identity_and_protocol_are_rejected() {
    let (request, _, identity) = launch_fixture(1_000);
    let mut receipt = launch_receipt(&identity);
    receipt.set_protocol_version_for_test(EXECUTOR_PROTOCOL_VERSION + 1);
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![Script::Launch(TransportCall::Response(receipt))]),
    );
    assert!(matches!(
        executor.launch(request),
        Err(ExecutorError::MalformedReceipt {
            operation: Operation::Launch,
            ..
        })
    ));
}

#[test]
fn wrong_status_receipt_key_is_rejected() {
    let (_, _, identity) = launch_fixture(1_000);
    let query = ExecutionQuery::Known(identity.clone());
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![Script::Status(TransportCall::Response(
            StatusReceipt::from_wire(
                EXECUTOR_PROTOCOL_VERSION,
                IdempotencyKey::new("0".repeat(64)).expect("wrong key"),
                query.clone(),
                ExecutionStatus::Running(identity),
            ),
        ))]),
    );
    assert!(matches!(
        executor.status(StatusRequest { query }),
        Err(ExecutorError::MalformedReceipt {
            operation: Operation::Status,
            ..
        })
    ));
}

#[test]
fn collection_rejects_safe_manifest_with_escaping_patch_and_still_cleans_up() {
    let (_, _, identity) = launch_fixture(1_000);
    let policy = output_policy(2048, 64);
    let malicious = b"diff --git a/src/lib.rs b/src/lib.rs\n--- ../../etc/passwd\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-x\n+y\n".to_vec();
    let receipt = collection_receipt(
        &identity,
        &policy,
        vec!["src/lib.rs".to_string()],
        malicious,
    );
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![
            Script::Collect(TransportCall::Response(receipt)),
            Script::Cleanup(TransportCall::Response(cleanup_receipt(&identity, true))),
        ]),
    );
    match executor.collect(CollectRequest::new(identity, policy)) {
        Err(ExecutorError::CollectionRejected { cleanup, .. }) => {
            assert!(matches!(*cleanup, Effect::Confirmed(_)));
        }
        other => panic!("unexpected collection result: {other:?}"),
    }
    assert!(matches!(
        executor.transport().requests().as_slice(),
        [RequestRecord::Collect(_), RequestRecord::Cleanup(_)]
    ));
}

#[test]
fn patch_parser_rejects_quoted_backslash_mismatch_and_unsafe_null_headers() {
    let bad_patches = [
        b"diff --git \"a/src/lib.rs\" \"b/src/lib.rs\"\n--- a/src/lib.rs\n+++ b/src/lib.rs\n"
            .to_vec(),
        b"diff --git a/src/lib.rs b/src\\escape.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n".to_vec(),
        b"diff --git a/src/lib.rs b/src/lib.rs\n--- /dev/null\n+++ /dev/null\n".to_vec(),
        patch_for("src/other.rs"),
    ];
    for patch in bad_patches {
        let (_, _, identity) = launch_fixture(1_000);
        let policy = output_policy(2048, 64);
        let receipt = collection_receipt(&identity, &policy, vec!["src/lib.rs".to_string()], patch);
        let executor = SshExecutor::new(
            target(),
            ScriptedTransport::new(vec![
                Script::Collect(TransportCall::Response(receipt)),
                Script::Cleanup(TransportCall::Response(cleanup_receipt(&identity, true))),
            ]),
        );
        assert!(matches!(
            executor.collect(CollectRequest::new(identity, policy)),
            Err(ExecutorError::CollectionRejected { .. })
        ));
    }
}

#[test]
fn safe_add_patch_allows_dev_null_on_old_side_only() {
    let (_, _, identity) = launch_fixture(1_000);
    let policy = output_policy(2048, 64);
    let patch = b"diff --git a/src/new.rs b/src/new.rs\n--- /dev/null\n+++ b/src/new.rs\n@@ -0,0 +1 @@\n+new\n".to_vec();
    let receipt = collection_receipt(&identity, &policy, vec!["src/new.rs".to_string()], patch);
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![
            Script::Collect(TransportCall::Response(receipt)),
            Script::Cleanup(TransportCall::Response(cleanup_receipt(&identity, true))),
        ]),
    );
    assert!(matches!(
        executor
            .collect(CollectRequest::new(identity, policy))
            .expect("safe add patch"),
        Effect::Confirmed(_)
    ));
}

#[test]
fn collection_manifest_digest_checksum_and_size_tampering_are_rejected_with_cleanup() {
    let (_, _, identity) = launch_fixture(1_000);
    let policy = output_policy(2048, 64);
    let mut receipt = collection_receipt(
        &identity,
        &policy,
        vec!["src/lib.rs".to_string()],
        patch_for("src/lib.rs"),
    );
    receipt
        .patch_mut_for_test()
        .set_digest_for_test(Digest::for_bytes(b"wrong"));
    receipt.recompute_manifest_digest_for_test();
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![
            Script::Collect(TransportCall::Response(receipt)),
            Script::Cleanup(TransportCall::Response(cleanup_receipt(&identity, false))),
        ]),
    );
    match executor.collect(CollectRequest::new(identity, policy)) {
        Err(ExecutorError::CollectionRejected { cleanup, .. }) => match *cleanup {
            Effect::Confirmed(receipt) => assert!(!receipt.workspace_removed()),
            other => panic!("unexpected cleanup result: {other:?}"),
        },
        other => panic!("unexpected collection result: {other:?}"),
    }
}

#[test]
fn aggregate_manifest_and_output_checksum_or_size_tampering_are_rejected() {
    enum Tamper {
        Aggregate,
        OutputDigest,
        OutputSize,
    }
    for tamper in [Tamper::Aggregate, Tamper::OutputDigest, Tamper::OutputSize] {
        let (_, _, identity) = launch_fixture(1_000);
        let policy = output_policy(2048, 64);
        let mut receipt = collection_receipt(
            &identity,
            &policy,
            vec!["src/lib.rs".to_string()],
            patch_for("src/lib.rs"),
        );
        match tamper {
            Tamper::Aggregate => receipt
                .patch_mut_for_test()
                .set_digest_for_test(Digest::for_bytes(b"aggregate-stale")),
            Tamper::OutputDigest => {
                receipt.outputs_mut_for_test()[0]
                    .blob_mut_for_test()
                    .set_digest_for_test(Digest::for_bytes(b"wrong-output"));
                receipt.recompute_manifest_digest_for_test();
            }
            Tamper::OutputSize => {
                receipt.outputs_mut_for_test()[0]
                    .blob_mut_for_test()
                    .set_declared_size_for_test(1);
                receipt.recompute_manifest_digest_for_test();
            }
        }
        let executor = SshExecutor::new(
            target(),
            ScriptedTransport::new(vec![
                Script::Collect(TransportCall::Response(receipt)),
                Script::Cleanup(TransportCall::Response(cleanup_receipt(&identity, true))),
            ]),
        );
        match executor.collect(CollectRequest::new(identity, policy)) {
            Err(ExecutorError::CollectionRejected { cleanup, .. }) => {
                assert!(matches!(*cleanup, Effect::Confirmed(_)));
            }
            other => panic!("unexpected collection result: {other:?}"),
        }
    }
}

#[test]
fn collection_rejects_unsorted_duplicate_outside_and_undeclared_paths() {
    for changed in [
        vec!["src/z.rs".to_string(), "src/a.rs".to_string()],
        vec!["src/lib.rs".to_string(), "src/lib.rs".to_string()],
        vec!["docs/outside.md".to_string()],
        vec!["../outside".to_string()],
    ] {
        let (_, _, identity) = launch_fixture(1_000);
        let policy = output_policy(4096, 64);
        let mut receipt = collection_receipt(
            &identity,
            &policy,
            vec!["src/lib.rs".to_string()],
            patch_for("src/lib.rs"),
        );
        receipt.set_changed_paths_for_test(changed);
        receipt.recompute_manifest_digest_for_test();
        let executor = SshExecutor::new(
            target(),
            ScriptedTransport::new(vec![
                Script::Collect(TransportCall::Response(receipt)),
                Script::Cleanup(TransportCall::Response(cleanup_receipt(&identity, true))),
            ]),
        );
        assert!(matches!(
            executor.collect(CollectRequest::new(identity, policy)),
            Err(ExecutorError::CollectionRejected { .. })
        ));
    }

    let (_, _, identity) = launch_fixture(1_000);
    let policy = output_policy(2048, 64);
    let mut receipt = collection_receipt(
        &identity,
        &policy,
        vec!["src/lib.rs".to_string()],
        patch_for("src/lib.rs"),
    );
    receipt.outputs_mut_for_test()[0].set_path_for_test("artifacts/secret.txt");
    receipt.recompute_manifest_digest_for_test();
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![
            Script::Collect(TransportCall::Response(receipt)),
            Script::Cleanup(TransportCall::Response(cleanup_receipt(&identity, true))),
        ]),
    );
    assert!(matches!(
        executor.collect(CollectRequest::new(identity, policy)),
        Err(ExecutorError::CollectionRejected { .. })
    ));
}

#[test]
fn bounded_wire_types_reject_patch_output_and_aggregate_overruns() {
    assert!(matches!(
        CollectedBlob::from_wire_bounded(vec![0; 11], 11, Digest::for_bytes(&vec![0; 11]), 10,),
        Err(ExecutorError::LimitExceeded { .. })
    ));

    let (_, _, identity) = launch_fixture(1_000);
    let policy = OutputPolicy::new(
        64,
        4,
        vec![path("src")],
        vec![
            DeclaredOutput::new(path("artifacts/a"), "text/plain", 3).expect("a"),
            DeclaredOutput::new(path("artifacts/b"), "text/plain", 3).expect("b"),
        ],
        6,
    )
    .expect("policy");

    let receipt_limits = TransportReadLimits {
        receipt_max_bytes: 10,
        ..TransportReadLimits::for_policy(&policy).expect("transport limits")
    };
    let receipt_key = derive_collection_key(&identity, policy.digest());
    let receipt_patch = CollectedBlob::checksummed(vec![0; 11], 64).expect("receipt patch");
    let receipt_digest = CollectionReceipt::canonical_manifest_digest(
        EXECUTOR_PROTOCOL_VERSION,
        &receipt_key,
        &identity,
        policy.digest(),
        &receipt_patch,
        &[],
        &[],
    );
    assert!(matches!(
        CollectionReceipt::from_wire_bounded(
            EXECUTOR_PROTOCOL_VERSION,
            receipt_key,
            identity.clone(),
            policy.digest().clone(),
            receipt_patch,
            Vec::new(),
            Vec::new(),
            receipt_digest,
            &receipt_limits,
        ),
        Err(ExecutorError::LimitExceeded {
            what: "transport receipt bytes",
            limit: 10,
        })
    ));

    let limits = TransportReadLimits {
        output_aggregate_max_bytes: 5,
        ..TransportReadLimits::for_policy(&policy).expect("transport limits")
    };
    let key = derive_collection_key(&identity, policy.digest());
    let patch = CollectedBlob::checksummed(Vec::new(), 64).expect("patch");
    let outputs = vec![
        CollectedOutputEnvelope::from_wire(
            "artifacts/a".to_string(),
            "text/plain".to_string(),
            CollectedBlob::checksummed(vec![0; 3], 3).expect("a blob"),
        )
        .expect("a envelope"),
        CollectedOutputEnvelope::from_wire(
            "artifacts/b".to_string(),
            "text/plain".to_string(),
            CollectedBlob::checksummed(vec![0; 3], 3).expect("b blob"),
        )
        .expect("b envelope"),
    ];
    let digest = CollectionReceipt::canonical_manifest_digest(
        EXECUTOR_PROTOCOL_VERSION,
        &key,
        &identity,
        policy.digest(),
        &patch,
        &[],
        &outputs,
    );
    assert!(matches!(
        CollectionReceipt::from_wire_bounded(
            EXECUTOR_PROTOCOL_VERSION,
            key,
            identity,
            policy.digest().clone(),
            patch,
            Vec::new(),
            outputs,
            digest,
            &limits,
        ),
        Err(ExecutorError::LimitExceeded {
            what: "transport output aggregate bytes",
            limit: 5,
        })
    ));
}

#[test]
fn near_maximum_path_metadata_fits_checked_receipt_budget() {
    let policy = OutputPolicy::new(64, 4096, vec![path("src")], Vec::new(), 1)
        .expect("maximum changed-path policy");
    let limits = TransportReadLimits::for_policy(&policy).expect("derived transport limits");
    let old_fixed_allowance = policy
        .patch_max_bytes()
        .checked_add(policy.output_aggregate_max_bytes())
        .and_then(|value| value.checked_add(1024 * 1024))
        .expect("old allowance arithmetic");
    assert!(limits.receipt_max_bytes() > old_fixed_allowance);

    let changed_paths = (0..4096)
        .map(|index| {
            let prefix = format!("src/{index:04}/");
            format!("{prefix}{}", "a".repeat(512 - prefix.len()))
        })
        .collect::<Vec<_>>();
    assert!(changed_paths
        .iter()
        .all(|value| value.len() == 512 && LogicalPath::new(value.as_str()).is_ok()));

    let (_, _, identity) = launch_fixture(1_000);
    let key = derive_collection_key(&identity, policy.digest());
    let patch =
        CollectedBlob::checksummed(Vec::new(), limits.patch_max_bytes()).expect("empty patch");
    let digest = CollectionReceipt::canonical_manifest_digest(
        EXECUTOR_PROTOCOL_VERSION,
        &key,
        &identity,
        policy.digest(),
        &patch,
        &changed_paths,
        &[],
    );
    CollectionReceipt::from_wire_bounded(
        EXECUTOR_PROTOCOL_VERSION,
        key,
        identity,
        policy.digest().clone(),
        patch,
        changed_paths,
        Vec::new(),
        digest,
        &limits,
    )
    .expect("near-maximum path metadata remains within the derived receipt limit");

    let short_output_policy = OutputPolicy::new(
        64,
        1,
        vec![path("src")],
        vec![DeclaredOutput::new(path("a"), "a", 1).expect("short output")],
        1,
    )
    .expect("short metadata policy");
    let long_output_policy = OutputPolicy::new(
        64,
        1,
        vec![path("src")],
        vec![DeclaredOutput::new(path(&"a".repeat(512)), "a".repeat(128), 1).expect("long output")],
        1,
    )
    .expect("long metadata policy");
    let short_limit = TransportReadLimits::for_policy(&short_output_policy)
        .expect("short metadata limit")
        .receipt_max_bytes();
    let long_limit = TransportReadLimits::for_policy(&long_output_policy)
        .expect("long metadata limit")
        .receipt_max_bytes();
    assert_eq!(long_limit - short_limit, (512 - 1) + (128 - 1));
}

mod external_consumer {
    use super::super::{ControlReceipt, ControlSignal, ExecutionIdentity, SubmittedLaunchIdentity};

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct SubmittedCheckpoint {
        pub values: [String; 9],
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct ExecutionCheckpoint {
        pub values: [String; 10],
        pub pid: u32,
        pub pgid: u32,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct ControlCheckpoint {
        pub protocol_version: u32,
        pub key: String,
        pub identity: ExecutionCheckpoint,
        pub signal: ControlSignal,
    }

    pub(super) fn submitted_checkpoint(submitted: &SubmittedLaunchIdentity) -> SubmittedCheckpoint {
        let assignment = submitted.assignment();
        SubmittedCheckpoint {
            values: [
                assignment.host_id().as_str().to_string(),
                assignment.run_id().as_str().to_string(),
                assignment.assignment_id().as_str().to_string(),
                assignment.nonce().as_str().to_string(),
                submitted.staged_digest().as_str().to_string(),
                submitted.session_id().as_str().to_string(),
                submitted.workspace_id().as_str().to_string(),
                submitted.launch_spec_digest().as_str().to_string(),
                submitted.launch_key().as_str().to_string(),
            ],
        }
    }

    pub(super) fn execution_checkpoint(identity: &ExecutionIdentity) -> ExecutionCheckpoint {
        ExecutionCheckpoint {
            values: [
                identity.host_id().as_str().to_string(),
                identity.run_id().as_str().to_string(),
                identity.assignment_id().as_str().to_string(),
                identity.nonce().as_str().to_string(),
                identity.staged_digest().as_str().to_string(),
                identity.session_id().as_str().to_string(),
                identity.workspace_id().as_str().to_string(),
                identity.launch_spec_digest().as_str().to_string(),
                identity.start_token().as_str().to_string(),
                identity.launch_key().as_str().to_string(),
            ],
            pid: identity.pid(),
            pgid: identity.pgid(),
        }
    }

    pub(super) fn control_checkpoint(receipt: &ControlReceipt) -> ControlCheckpoint {
        ControlCheckpoint {
            protocol_version: receipt.protocol_version(),
            key: receipt.key().as_str().to_string(),
            identity: execution_checkpoint(receipt.identity()),
            signal: receipt.signal(),
        }
    }
}

#[test]
fn external_consumer_can_checkpoint_full_typed_identity_without_forgeable_fields() {
    let (_, submitted, identity) = launch_fixture(1_000);
    let submitted_checkpoint = external_consumer::submitted_checkpoint(&submitted);
    assert_eq!(
        &submitted_checkpoint.values[..4],
        ["home-lxc-a", "run-41", "worker-2", "nonce-fresh-9"]
    );
    assert_eq!(
        submitted_checkpoint.values[4],
        identity.staged_digest().as_str()
    );
    assert_eq!(submitted_checkpoint.values[5], "session-1");
    assert_eq!(submitted_checkpoint.values[6], "workspace-1");
    assert_eq!(
        submitted_checkpoint.values[7],
        identity.launch_spec_digest().as_str()
    );
    assert_eq!(
        submitted_checkpoint.values[8],
        identity.launch_key().as_str()
    );

    let control_key = IdempotencyKey::new("a".repeat(64)).expect("typed control key");
    let control = ControlReceipt::from_wire(
        EXECUTOR_PROTOCOL_VERSION,
        control_key.clone(),
        identity.clone(),
        ControlSignal::Term,
    );
    let checkpoint = external_consumer::control_checkpoint(&control);
    assert_eq!(checkpoint.protocol_version, EXECUTOR_PROTOCOL_VERSION);
    assert_eq!(checkpoint.key, control_key.as_str());
    assert_eq!(checkpoint.identity.values[0], "home-lxc-a");
    assert_eq!(checkpoint.identity.values[1], "run-41");
    assert_eq!(checkpoint.identity.values[2], "worker-2");
    assert_eq!(checkpoint.identity.values[3], "nonce-fresh-9");
    assert_eq!(
        checkpoint.identity.values[4],
        identity.staged_digest().as_str()
    );
    assert_eq!(checkpoint.identity.values[5], "session-1");
    assert_eq!(checkpoint.identity.values[6], "workspace-1");
    assert_eq!(
        checkpoint.identity.values[7],
        identity.launch_spec_digest().as_str()
    );
    assert_eq!(checkpoint.identity.values[8], "boot-8-start-9001");
    assert_eq!(
        checkpoint.identity.values[9],
        identity.launch_key().as_str()
    );
    assert_eq!(
        (checkpoint.identity.pid, checkpoint.identity.pgid),
        (4321, 4321)
    );
    assert_eq!(checkpoint.signal, ControlSignal::Term);

    assert!(matches!(
        ExecutionIdentity::from_wire(
            identity.host_id().clone(),
            identity.run_id().clone(),
            identity.assignment_id().clone(),
            identity.nonce().clone(),
            identity.staged_digest().clone(),
            identity.session_id().clone(),
            identity.workspace_id().clone(),
            identity.launch_spec_digest().clone(),
            0,
            identity.pgid(),
            identity.start_token().clone(),
            identity.launch_key().clone(),
        ),
        Err(ExecutorError::InvalidField {
            field: "execution identity",
            ..
        })
    ));
}

#[test]
fn invalid_collection_preserves_workspace_bound_uncertain_cleanup() {
    let (_, _, identity) = launch_fixture(1_000);
    let policy = output_policy(2048, 64);
    let mut receipt = collection_receipt(
        &identity,
        &policy,
        vec!["src/lib.rs".to_string()],
        patch_for("src/lib.rs"),
    );
    receipt.patch_mut_for_test().set_declared_size_for_test(1);
    receipt.recompute_manifest_digest_for_test();
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![
            Script::Collect(TransportCall::Response(receipt)),
            Script::Cleanup(TransportCall::LostResponse {
                detail: "cleanup response lost".to_string(),
            }),
        ]),
    );
    match executor.collect(CollectRequest::new(identity.clone(), policy)) {
        Err(ExecutorError::CollectionRejected { cleanup, .. }) => match *cleanup {
            Effect::Uncertain(uncertain) => assert!(matches!(
                uncertain.reconciliation,
                ReconciliationTarget::Cleanup(CleanupLookup {
                    identity: found,
                    workspace_id,
                    ..
                }) if found == identity && workspace_id == *identity.workspace_id()
            )),
            other => panic!("unexpected cleanup result: {other:?}"),
        },
        other => panic!("unexpected collection result: {other:?}"),
    }
}

#[test]
fn lost_term_is_uncertain_and_never_escalates_blindly() {
    let (_, _, identity) = launch_fixture(1_000);
    let policy = TerminationPolicy::new(
        BoundedMillis::new(50).expect("term grace"),
        BoundedMillis::new(50).expect("kill wait"),
    );
    let executor = SshExecutor::new(
        target(),
        ScriptedTransport::new(vec![Script::Control(TransportCall::LostResponse {
            detail: "TERM response lost".to_string(),
        })]),
    );
    let outcome = executor
        .terminate(TerminateRequest::new(identity.clone(), policy))
        .expect("uncertain control");
    assert!(matches!(
        outcome,
        Effect::Uncertain(value)
            if value.operation == Operation::TerminateTerm
                && value.reconciliation
                    == ReconciliationTarget::Execution(ExecutionQuery::Known(identity))
    ));
    assert_eq!(executor.transport().requests().len(), 1);
    executor.transport().assert_consumed();
}

#[test]
fn local_compatibility_adapter_forwards_borrowed_callback_once_only() {
    #[derive(Debug)]
    struct Review<'a>(&'a str);
    let calls = AtomicUsize::new(0);
    let runner = |command: &String, cancellation: &u64, review: Option<Review<'_>>| {
        calls.fetch_add(1, Ordering::SeqCst);
        format!(
            "{command}:{cancellation}:{}",
            review.expect("review forwarded").0
        )
    };
    let result = LocalExecutor.forward_existing_run(
        &runner,
        &"command".to_string(),
        &7,
        Some(Review("borrowed")),
    );
    assert_eq!(result, "command:7:borrowed");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
