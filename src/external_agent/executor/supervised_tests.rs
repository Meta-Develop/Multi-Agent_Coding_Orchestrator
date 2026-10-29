use super::*;
use crate::executor::{ExecutorLimits, SshConfig, SshConfigInput};
use crate::process_runner::ProcessCancellation;
use std::{
    collections::VecDeque,
    fs,
    num::NonZeroU32,
    path::Path,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;

#[derive(Default)]
struct Observed {
    stages: Vec<StageTransportRequest>,
    launches: Vec<LaunchTransportRequest>,
    statuses: Vec<StatusTransportRequest>,
    waits: Vec<WaitTransportRequest>,
    controls: Vec<ControlTransportRequest>,
    collections: Vec<CollectionTransportRequest>,
    cleanups: usize,
    identity: Option<ExecutionIdentity>,
    lost_stage: bool,
    lost_launch: bool,
    lost_collect: bool,
    lost_control: bool,
    lost_wait: bool,
    not_found: usize,
    foreign_status: bool,
    outside_scope: bool,
    outcomes: VecDeque<WaitOutcome>,
}

#[derive(Clone, Default)]
struct FakeTransport(Arc<Mutex<Observed>>);

impl SshTransport for FakeTransport {
    fn stage(&self, request: StageTransportRequest) -> TransportCall<StageTransportReceipt> {
        let mut state = self.0.lock().unwrap();
        state.stages.push(request.clone());
        if state.lost_stage {
            return lost();
        }
        TransportCall::Response(StageTransportReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            request.stage.key().clone(),
            request.stage.identity().clone(),
            request.stage.manifest().digest().clone(),
            SessionId::new("session-3").unwrap(),
            WorkspaceId::new("workspace-3").unwrap(),
        ))
    }

    fn launch(&self, request: LaunchTransportRequest) -> TransportCall<LaunchReceipt> {
        let mut state = self.0.lock().unwrap();
        let submitted = &request.submitted;
        let assignment = submitted.assignment();
        let identity = ExecutionIdentity::from_wire(
            assignment.host_id().clone(),
            assignment.run_id().clone(),
            assignment.assignment_id().clone(),
            assignment.nonce().clone(),
            submitted.staged_digest().clone(),
            submitted.session_id().clone(),
            submitted.workspace_id().clone(),
            submitted.launch_spec_digest().clone(),
            submitted.collection_authority().clone(),
            41,
            41,
            StartToken::new("start-41").unwrap(),
            submitted.launch_key().clone(),
        )
        .unwrap();
        state.identity = Some(identity.clone());
        state.launches.push(request);
        if state.lost_launch {
            return lost();
        }
        TransportCall::Response(LaunchReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            identity.launch_key().clone(),
            identity,
        ))
    }

    fn status(&self, request: StatusTransportRequest) -> TransportCall<StatusReceipt> {
        let mut state = self.0.lock().unwrap();
        state.statuses.push(request.clone());
        let status = if state.not_found > 0 {
            state.not_found -= 1;
            ExecutionStatus::NotFound
        } else {
            let mut identity = state.identity.clone().unwrap();
            if state.foreign_status {
                identity.host_id = HostId::new("foreign").unwrap();
            }
            ExecutionStatus::Running(identity)
        };
        TransportCall::Response(StatusReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            request.key,
            request.query,
            status,
        ))
    }

    fn wait(&self, request: WaitTransportRequest) -> TransportCall<WaitReceipt> {
        let mut state = self.0.lock().unwrap();
        state.waits.push(request.clone());
        if std::mem::take(&mut state.lost_wait) {
            return lost();
        }
        let outcome = state
            .outcomes
            .pop_front()
            .unwrap_or(WaitOutcome::Exited { code: 0 });
        TransportCall::Response(WaitReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            request.key,
            request.identity,
            outcome,
        ))
    }

    fn control(&self, request: ControlTransportRequest) -> TransportCall<ControlReceipt> {
        let mut state = self.0.lock().unwrap();
        state.controls.push(request.clone());
        if std::mem::take(&mut state.lost_control) {
            return lost();
        }
        TransportCall::Response(ControlReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            request.key,
            request.identity,
            request.signal,
        ))
    }

    fn collect(&self, request: CollectionTransportRequest) -> TransportCall<CollectionReceipt> {
        let mut state = self.0.lock().unwrap();
        state.collections.push(request.clone());
        if std::mem::take(&mut state.lost_collect) {
            return lost();
        }
        let path = if state.outside_scope {
            "workspace/other.rs"
        } else {
            "workspace/src/lib.rs"
        };
        let patch = CollectedBlob::checksummed(
            format!(
                "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"
            )
            .into_bytes(),
            request.read_limits.patch_max_bytes(),
        )
        .unwrap();
        let paths = vec![path.to_string()];
        let outputs = vec![CollectedOutputEnvelope::from_wire(
            "output/result.json".into(),
            "application/json".into(),
            CollectedBlob::checksummed(b"{\"status\":\"candidate\"}".to_vec(), 1024).unwrap(),
        )
        .unwrap()];
        let digest = CollectionReceipt::canonical_manifest_digest(
            EXECUTOR_PROTOCOL_VERSION,
            &request.key,
            &request.identity,
            &request.policy_digest,
            &patch,
            &paths,
            &outputs,
        );
        TransportCall::Response(
            CollectionReceipt::from_wire_bounded(
                EXECUTOR_PROTOCOL_VERSION,
                request.key,
                request.identity,
                request.policy_digest,
                patch,
                paths,
                outputs,
                digest,
                &request.read_limits,
            )
            .unwrap(),
        )
    }

    fn cleanup(&self, _request: CleanupTransportRequest) -> TransportCall<CleanupReceipt> {
        self.0.lock().unwrap().cleanups += 1;
        panic!("the attempt bridge must never authorize cleanup");
    }
}

fn lost<T>() -> TransportCall<T> {
    TransportCall::LostResponse {
        detail: "injected lost reply".into(),
    }
}

fn target() -> SshTargetConfig {
    serde_json::from_value(serde_json::json!({
        "host_id": "test-host", "endpoint": "test.invalid", "user": "runner", "port": 2222,
        "helper": "/opt/maco/helper", "root": "/srv/maco/workspaces"
    }))
    .unwrap()
}

fn trust(temp: &TempDir) -> SshConfig {
    let identity_file = temp.path().join("identity");
    let known_hosts_file = temp.path().join("known_hosts");
    fs::write(&identity_file, b"offline fake identity").unwrap();
    fs::write(&known_hosts_file, b"offline fake host key").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&identity_file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&known_hosts_file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let target = target();
    SshConfig::new(SshConfigInput {
        host_id: target.host_id.as_str().into(),
        host: target.endpoint.as_str().into(),
        user: target.user.as_str().into(),
        port: target.port.get(),
        identity_file,
        known_hosts_file,
        remote_root: target.root.as_str().into(),
        helper_path: target.helper.as_str().into(),
        limits: ExecutorLimits {
            max_workspace_entries: 16,
            max_workspace_bytes: 4096,
            max_file_bytes: 2048,
            max_stdout_bytes: 4096,
            max_stderr_bytes: 4096,
            max_event_count: 16,
            max_event_bytes: 2048,
            max_request_bytes: 16 * 1024,
            max_receipt_bytes: 16 * 1024,
            connect_timeout_millis: 500,
            execution_timeout_millis: 60_000,
            cancellation_grace_millis: 500,
            poll_interval_millis: 10,
        },
    })
    .unwrap()
}

fn configured(temp: &TempDir, transport: &FakeTransport) -> SupervisedSshExecutor<FakeTransport> {
    SupervisedSshExecutor::configure(
        &ExecutorSelection::ssh(target()),
        Some(trust(temp)),
        |config| {
            assert_eq!(config.host(), "test.invalid");
            Ok(transport.clone())
        },
    )
    .unwrap()
}

fn binding(attempt: u32) -> SupervisedAttemptId {
    SupervisedAttemptId {
        run_id: RunId::new("run-7").unwrap(),
        assignment_id: AssignmentId::new("assignment-4").unwrap(),
        attempt: NonZeroU32::new(attempt).unwrap(),
        nonce: Nonce::new("coordinator-nonce").unwrap(),
    }
}

fn payload(root: &Path) -> (InputManifest, LaunchSpec, OutputPolicy) {
    let paths = SupervisedPaths::new(root.to_path_buf()).unwrap();
    let prompt = root.join("input/prompt.txt");
    let schema = root.join("input/schema.json");
    let output = root.join("output/result.json");
    let manifest = InputManifest::new(vec![
        paths
            .input(
                &prompt,
                ManifestPurpose::Prompt,
                b"edit the source".to_vec(),
            )
            .unwrap(),
        paths
            .input(&schema, ManifestPurpose::Schema, b"{}".to_vec())
            .unwrap(),
        paths
            .input(
                &root.join("workspace/src/lib.rs"),
                ManifestPurpose::WorkspaceInput,
                b"old\n".to_vec(),
            )
            .unwrap(),
        paths
            .output(&output, ManifestPurpose::DeclaredOutput, 1024)
            .unwrap(),
    ])
    .unwrap();
    let launch = LaunchSpec::new(
        TypedArgv::new(vec![
            TypedArg::Literal(BoundedLiteral::new("codex").unwrap()),
            TypedArg::Literal(BoundedLiteral::new("--output-schema").unwrap()),
            paths.argument(&schema).unwrap(),
            TypedArg::Literal(BoundedLiteral::new("--output-last-message").unwrap()),
            paths.argument(&output).unwrap(),
            TypedArg::FinalStdinMarker,
        ])
        .unwrap(),
        paths.logical(&prompt).unwrap(),
        BoundedMillis::new(60_000).unwrap(),
    );
    let policy = OutputPolicy::new(
        4096,
        8,
        vec![LogicalPath::new("workspace/src").unwrap()],
        vec![
            DeclaredOutput::new(paths.logical(&output).unwrap(), "application/json", 1024).unwrap(),
        ],
        1024,
    )
    .unwrap();
    (manifest, launch, policy)
}

fn attempt<'a>(
    owner: &'a SupervisedSshExecutor<FakeTransport>,
    temp: &TempDir,
    cancellation: ProcessCancellation,
) -> SupervisedSshAttempt<'a, FakeTransport> {
    let (manifest, launch, policy) = payload(&temp.path().join("staged"));
    owner
        .prepare(
            binding(3),
            manifest,
            launch,
            policy,
            cancellation,
            TerminationPolicy::new(
                BoundedMillis::new(20).unwrap(),
                BoundedMillis::new(30).unwrap(),
            ),
        )
        .unwrap()
}

fn launch(attempt: &mut SupervisedSshAttempt<'_, FakeTransport>) {
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Staged(Effect::Confirmed(_))
    ));
    assert!(matches!(
        attempt.execution_query(),
        Some(ExecutionQuery::Submitted(_))
    ));
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Launched(Effect::Confirmed(_))
    ));
}

#[test]
fn selected_transport_binds_host_attempt_and_paths() {
    let temp = TempDir::new().unwrap();
    let fake = FakeTransport::default();
    let owner = configured(&temp, &fake);
    let mut attempt = attempt(&owner, &temp, ProcessCancellation::new());
    assert_eq!(attempt.binding(), &binding(3));
    launch(&mut attempt);
    assert_eq!(
        attempt.advance().unwrap(),
        SupervisedEvent::Waited(WaitOutcome::Exited { code: 0 })
    );
    let SupervisedEvent::Collected(Effect::Confirmed(result)) = attempt.advance().unwrap() else {
        panic!("expected candidate");
    };
    assert!(result.is_candidate_evidence_only());
    assert_eq!(
        result.changed_paths(),
        &[LogicalPath::new("workspace/src/lib.rs").unwrap()]
    );
    assert_eq!(result.outputs()[0].bytes(), b"{\"status\":\"candidate\"}");
    let state = fake.0.lock().unwrap();
    assert_eq!(state.stages[0].target, target());
    let staged = &state.stages[0].stage;
    assert_eq!(staged.identity().run_id(), &binding(3).run_id);
    assert_eq!(staged.identity().assignment_id(), &binding(3).assignment_id);
    assert!(staged.identity().nonce().as_str().starts_with("attempt-3-"));
    assert_eq!(state.launches[0].stdin.as_str(), "input/prompt.txt");
    assert_eq!(
        state.launches[0].argv.arguments()[2],
        TypedArg::ManifestPath(LogicalPath::new("input/schema.json").unwrap())
    );
    assert_eq!(
        state.collections[0].key,
        *staged.collection_authority().collection_key()
    );
    assert_eq!(state.waits[0].max_wait.get(), 100);
    assert_eq!(state.cleanups, 0);
}

#[test]
fn unavailable_or_mismatched_trust_never_constructs_transport() {
    let temp = TempDir::new().unwrap();
    let selection = ExecutorSelection::ssh(target());
    assert!(
        SupervisedSshExecutor::<FakeTransport>::configure(&selection, None, |_| {
            panic!("factory must not run")
        })
        .is_err()
    );
    assert!(SupervisedSshExecutor::<FakeTransport>::configure(
        &ExecutorSelection::Local,
        Some(trust(&temp)),
        |_| panic!("factory must not run")
    )
    .is_err());
    for field in ["host_id", "endpoint", "user", "port", "helper", "root"] {
        let mut raw = serde_json::to_value(target()).unwrap();
        raw[field] = match field {
            "port" => serde_json::json!(2223),
            "helper" | "root" => serde_json::json!("/different/path"),
            _ => serde_json::json!("different"),
        };
        let selection = ExecutorSelection::ssh(serde_json::from_value(raw).unwrap());
        assert!(
            SupervisedSshExecutor::<FakeTransport>::configure(
                &selection,
                Some(trust(&temp)),
                |_| panic!("factory must not run")
            )
            .is_err(),
            "{field}"
        );
    }
}

#[test]
fn revoked_trust_refuses_before_stage() {
    for after_stage in [false, true] {
        let temp = TempDir::new().unwrap();
        let fake = FakeTransport::default();
        let owner = configured(&temp, &fake);
        let mut attempt = attempt(&owner, &temp, ProcessCancellation::new());
        if after_stage {
            attempt.advance().unwrap();
        }
        fs::remove_file(temp.path().join("known_hosts")).unwrap();
        assert!(attempt.advance().is_err());
        let state = fake.0.lock().unwrap();
        assert_eq!(state.stages.len(), usize::from(after_stage));
        assert!(state.launches.is_empty());
    }
}

#[test]
fn translated_paths_refuse_escape_and_attempt_keys_are_distinct() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("staged");
    let paths = SupervisedPaths::new(root.clone()).unwrap();
    for path in [
        root.clone(),
        root.join("../outside"),
        root.join("input/./schema.json"),
        temp.path().join("elsewhere"),
        "relative".into(),
    ] {
        assert!(paths.logical(&path).is_err(), "{}", path.display());
    }
    let fake = FakeTransport::default();
    let owner = configured(&temp, &fake);
    let first = attempt(&owner, &temp, ProcessCancellation::new());
    let (manifest, launch, policy) = payload(&root);
    let second = owner
        .prepare(
            binding(4),
            manifest,
            launch,
            policy,
            ProcessCancellation::new(),
            TerminationPolicy::new(
                BoundedMillis::new(20).unwrap(),
                BoundedMillis::new(30).unwrap(),
            ),
        )
        .unwrap();
    assert_ne!(first.stage_request().key(), second.stage_request().key());
    assert_ne!(
        first
            .stage_request()
            .collection_authority()
            .collection_key(),
        second
            .stage_request()
            .collection_authority()
            .collection_key()
    );
    assert!(fake.0.lock().unwrap().stages.is_empty());
}

#[test]
fn cancellation_before_launch_never_spawns() {
    for after_stage in [false, true] {
        let temp = TempDir::new().unwrap();
        let fake = FakeTransport::default();
        let owner = configured(&temp, &fake);
        let parent = ProcessCancellation::new();
        let mut attempt = attempt(&owner, &temp, parent.child_scope());
        if after_stage {
            attempt.advance().unwrap();
        }
        parent.cancel();
        assert_eq!(
            attempt.advance().unwrap(),
            SupervisedEvent::CancelledBeforeLaunch
        );
        assert_eq!(
            attempt.advance().unwrap(),
            SupervisedEvent::CancelledBeforeLaunch
        );
        let state = fake.0.lock().unwrap();
        assert_eq!(state.stages.len(), usize::from(after_stage));
        assert!(state.launches.is_empty());
        assert_eq!(state.cleanups, 0);
    }
}

#[test]
fn lost_launch_reconciles_before_cancellation_without_relaunch() {
    let temp = TempDir::new().unwrap();
    let fake = FakeTransport::default();
    {
        let mut state = fake.0.lock().unwrap();
        state.lost_launch = true;
        state.not_found = 1;
    }
    let owner = configured(&temp, &fake);
    let parent = ProcessCancellation::new();
    let mut attempt = attempt(&owner, &temp, parent.child_scope());
    attempt.advance().unwrap();
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Launched(Effect::Uncertain(_))
    ));
    parent.cancel();
    assert_eq!(
        attempt.advance().unwrap(),
        SupervisedEvent::Reconciled(ExecutionStatus::NotFound)
    );
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Reconciled(ExecutionStatus::Running(_))
    ));
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Terminated(Effect::Confirmed(_))
    ));
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Collected(Effect::Confirmed(_))
    ));
    let state = fake.0.lock().unwrap();
    assert_eq!(state.launches.len(), 1);
    assert_eq!(state.statuses.len(), 2);
    assert_eq!(state.controls.len(), 1);
    assert_eq!(
        state.controls[0].identity,
        *state.identity.as_ref().unwrap()
    );
    assert_eq!(state.cleanups, 0);
}

#[test]
fn cancellation_keeps_custody_until_terminal_proof() {
    let temp = TempDir::new().unwrap();
    let fake = FakeTransport::default();
    {
        let mut state = fake.0.lock().unwrap();
        state.lost_control = true;
        state.lost_wait = true;
        state.outcomes = [
            WaitOutcome::RunningAtDeadline,
            WaitOutcome::RunningAtDeadline,
            WaitOutcome::Exited { code: 137 },
        ]
        .into();
    }
    let owner = configured(&temp, &fake);
    let cancel = ProcessCancellation::new();
    let mut attempt = attempt(&owner, &temp, cancel.clone());
    launch(&mut attempt);
    assert!(matches!(
        attempt.advance(),
        Err(ExecutorError::TransportLost { .. })
    ));
    cancel.cancel();
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Terminated(Effect::Uncertain(_))
    ));
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Terminated(Effect::Confirmed(_))
    ));
    assert!(fake.0.lock().unwrap().collections.is_empty());
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Terminated(Effect::Confirmed(_))
    ));
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Collected(Effect::Confirmed(_))
    ));
    let state = fake.0.lock().unwrap();
    assert_eq!(state.controls[0].key, state.controls[1].key);
    assert_eq!(state.controls[1].signal, ControlSignal::Term);
    assert_eq!(state.controls[2].signal, ControlSignal::Kill);
    assert_eq!(state.controls[3].key, state.controls[0].key);
    assert_eq!(state.cleanups, 0);
}

#[test]
fn lost_collection_reuses_exact_key_and_never_cleans_up() {
    let temp = TempDir::new().unwrap();
    let fake = FakeTransport::default();
    fake.0.lock().unwrap().lost_collect = true;
    let owner = configured(&temp, &fake);
    let mut attempt = attempt(&owner, &temp, ProcessCancellation::new());
    launch(&mut attempt);
    attempt.advance().unwrap();
    assert!(matches!(
        attempt.advance().unwrap(),
        SupervisedEvent::Collected(Effect::Uncertain(_))
    ));
    let confirmed = attempt.advance().unwrap();
    assert!(matches!(
        confirmed,
        SupervisedEvent::Collected(Effect::Confirmed(_))
    ));
    assert_eq!(attempt.advance().unwrap(), confirmed);
    let state = fake.0.lock().unwrap();
    assert_eq!(state.collections.len(), 2);
    assert_eq!(state.collections[0], state.collections[1]);
    assert_eq!(state.launches.len(), 1);
    assert_eq!(state.cleanups, 0);
}

#[test]
fn uncertain_stage_and_foreign_status_never_advance_to_collection() {
    let temp = TempDir::new().unwrap();
    let fake = FakeTransport::default();
    fake.0.lock().unwrap().lost_stage = true;
    let owner = configured(&temp, &fake);
    let mut attempt = attempt(&owner, &temp, ProcessCancellation::new());
    let first = attempt.advance().unwrap();
    assert!(matches!(
        first,
        SupervisedEvent::Staged(Effect::Uncertain(_))
    ));
    assert_eq!(attempt.advance().unwrap(), first);
    assert_eq!(fake.0.lock().unwrap().stages.len(), 1);
    assert!(fake.0.lock().unwrap().launches.is_empty());

    let fake = FakeTransport::default();
    {
        let mut state = fake.0.lock().unwrap();
        state.lost_launch = true;
        state.foreign_status = true;
    }
    let owner = configured(&temp, &fake);
    let mut second = self::attempt(&owner, &temp, ProcessCancellation::new());
    second.advance().unwrap();
    second.advance().unwrap();
    assert!(second.advance().is_err());
    assert!(fake.0.lock().unwrap().collections.is_empty());
    assert_eq!(fake.0.lock().unwrap().launches.len(), 1);
}

#[test]
fn rejected_candidate_remains_remote_without_import_or_cleanup() {
    let temp = TempDir::new().unwrap();
    let fake = FakeTransport::default();
    fake.0.lock().unwrap().outside_scope = true;
    let owner = configured(&temp, &fake);
    let mut attempt = attempt(&owner, &temp, ProcessCancellation::new());
    launch(&mut attempt);
    attempt.advance().unwrap();
    assert!(matches!(
        attempt.advance(),
        Err(ExecutorError::CollectionRejected { .. })
    ));
    assert_eq!(fake.0.lock().unwrap().cleanups, 0);
    assert!(!temp.path().join("staged/workspace/src/lib.rs").exists());
}
