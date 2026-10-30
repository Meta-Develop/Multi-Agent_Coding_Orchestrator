use super::*;
use crate::executor::{ExecutorLimits, SshConfig, SshConfigInput};
use crate::external_agent::executor::*;
use std::collections::VecDeque;
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
    cleanup_keys: Vec<IdempotencyKey>,
    lost_cleanup: bool,
    cancel_on_wait: Option<ProcessCancellation>,
    cancel_on_stage: Option<ProcessCancellation>,
    identity: Option<ExecutionIdentity>,
    lost_stage: bool,
    lost_launch: bool,
    fail_launch_receipt_write: bool,
    lost_collect: bool,
    lost_control: bool,
    lost_wait: bool,
    not_found: usize,
    outside_scope: bool,
    outcomes: VecDeque<WaitOutcome>,
}

#[derive(Clone, Default)]
struct FakeTransport(Arc<Mutex<Observed>>);

impl SshTransport for FakeTransport {
    fn stage(&self, request: StageTransportRequest) -> TransportCall<StageTransportReceipt> {
        let mut state = self.0.lock().unwrap();
        state.stages.push(request.clone());
        if let Some(cancellation) = state.cancel_on_stage.take() {
            cancellation.cancel();
        }
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
        if std::mem::take(&mut state.fail_launch_receipt_write) {
            FAIL_PHASE.with(|slot| slot.replace(Some("receipt".into())));
        }
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
            ExecutionStatus::Running(state.identity.clone().unwrap())
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
        if let Some(cancellation) = state.cancel_on_wait.take() {
            cancellation.cancel();
            return TransportCall::Response(WaitReceipt::from_wire(
                EXECUTOR_PROTOCOL_VERSION,
                request.key,
                request.identity,
                WaitOutcome::RunningAtDeadline,
            ));
        }
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

    fn cleanup(&self, request: CleanupTransportRequest) -> TransportCall<CleanupReceipt> {
        let mut state = self.0.lock().unwrap();
        state.cleanups += 1;
        state.cleanup_keys.push(request.key.clone());
        if std::mem::take(&mut state.lost_cleanup) {
            return lost();
        }
        TransportCall::Response(CleanupReceipt::from_wire(
            EXECUTOR_PROTOCOL_VERSION,
            request.key,
            request.identity,
            request.workspace_id,
            true,
        ))
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
    trust_with_grace(temp, 500)
}

fn trust_with_grace(temp: &TempDir, grace: u64) -> SshConfig {
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
            cancellation_grace_millis: grace,
            poll_interval_millis: 10,
        },
    })
    .unwrap()
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

#[derive(Default)]
struct CaptureState {
    imports: usize,
    recaptures: usize,
    fail_import_after_effect: bool,
    fail_recapture: bool,
}

struct Coordinator {
    repo: PathBuf,
    state: Mutex<CaptureState>,
}

impl SupervisedSshCoordinator for Coordinator {
    fn prepare(&self, command: &ExternalAgentCommand) -> Result<SupervisedSshInputs> {
        let (manifest, launch, outputs) = payload(&command.cwd);
        Ok(SupervisedSshInputs {
            manifest,
            launch,
            outputs,
        })
    }

    fn import_candidate(
        &self,
        command: &ExternalAgentCommand,
        result: &CollectedResult,
    ) -> Result<()> {
        let phases = phases(&self.repo);
        assert!(phases.contains(&"collection_committed".into()));
        assert_eq!(phases.last().unwrap(), "before_import");
        assert!(result.is_candidate_evidence_only());
        assert_eq!(
            result.changed_paths(),
            &[LogicalPath::new("workspace/src/lib.rs")?]
        );
        let path = command.cwd.join("src/lib.rs");
        let observed = fs::read(&path)?;
        assert!(observed == b"old\n" || observed == b"new\n");
        if observed == b"old\n" {
            fs::write(path, b"new\n")?;
        }
        let mut state = self.state.lock().unwrap();
        state.imports += 1;
        if std::mem::take(&mut state.fail_import_after_effect) {
            bail!("injected import reply loss");
        }
        Ok(())
    }

    fn recapture(
        &self,
        command: &ExternalAgentCommand,
        result: &CollectedResult,
    ) -> Result<ExternalAgentRun> {
        assert_eq!(fs::read(command.cwd.join("src/lib.rs"))?, b"new\n");
        assert!(!result.patch().is_empty());
        let mut state = self.state.lock().unwrap();
        state.recaptures += 1;
        if std::mem::take(&mut state.fail_recapture) {
            bail!("injected local recapture failure");
        }
        // A remote report never acquires native runtime/containment authority.
        let mut run = crate::external_agent::refused_external_run_before_launch(
            command,
            "offline candidate capture only".into(),
        );
        run.duration_ms = 17;
        Ok(run)
    }
}

fn phases(repo: &Path) -> Vec<String> {
    let root = repo
        .join(".git/maco/state")
        .join(RemoteJournalSpec::ROOT_NAME);
    let entries = fs::read_dir(root).unwrap();
    let mut records = Vec::new();
    for instance in entries {
        let instance = instance.unwrap().path();
        if !instance.is_dir() {
            continue;
        }
        for entry in fs::read_dir(instance).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap().to_string_lossy().starts_with('.') {
                continue;
            }
            let value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            if let (Some(sequence), Some(phase)) =
                (value["sequence"].as_u64(), value["phase"].as_str())
            {
                records.push((sequence, phase.to_string()));
            }
        }
    }
    records.sort();
    records.into_iter().map(|(_, phase)| phase).collect()
}

struct Fixture {
    _temp: TempDir,
    repo: PathBuf,
    command: ExternalAgentCommand,
    transport: FakeTransport,
    coordinator: Arc<Coordinator>,
    host: SupervisedSshHost,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        Repository::init(&repo).unwrap();
        let cwd = temp.path().join("candidate");
        fs::create_dir_all(cwd.join("src")).unwrap();
        fs::write(cwd.join("src/lib.rs"), b"old\n").unwrap();
        let command = ExternalAgentCommand::codex(
            "codex",
            &cwd,
            cwd.join("prompt"),
            cwd.join("log"),
            cwd.join("result"),
            Duration::from_secs(60),
        );
        let transport = FakeTransport::default();
        let coordinator = Arc::new(Coordinator {
            repo: repo.clone(),
            state: Mutex::new(CaptureState::default()),
        });
        let host = SupervisedSshHost::configure(
            ExecutorSelection::ssh(target()),
            Some(trust(&temp)),
            |_| Ok(transport.clone()),
            coordinator.clone(),
        )
        .unwrap();
        Self {
            _temp: temp,
            repo,
            command,
            transport,
            coordinator,
            host,
        }
    }

    fn identity(&self) -> SshDispatchIdentity {
        SshDispatchIdentity {
            run_id: "run-7".into(),
            assignment_id: "assignment-4".into(),
            worker_id: None,
            attempt: NonZeroU32::new(3).unwrap(),
        }
    }

    fn dispatch(&self, cancellation: &ProcessCancellation) -> Result<ExternalAgentRun> {
        self.host.dispatch(
            &self.repo,
            self.identity(),
            &[PathBuf::from("src")],
            &self.command,
            cancellation,
        )
    }

    fn journal(&self) -> RemoteJournal {
        let id = crate::artifacts::state_auth::sha256_hex(
            &serde_json::to_vec(&self.identity()).unwrap(),
        );
        RemoteJournal::open_or_initialize(
            repository_auth_writer(&self.repo)
                .unwrap()
                .into_authenticator()
                .unwrap(),
            &id,
        )
        .unwrap()
    }
}

#[test]
fn cancelled_prelaunch_checkpoint_survives_lost_receipt_without_speculative_intent() {
    for staged in [false, true] {
        let fixture = Fixture::new();
        let cancellation = ProcessCancellation::new();
        if staged {
            fixture.transport.0.lock().unwrap().cancel_on_stage = Some(cancellation.clone());
        } else {
            cancellation.cancel();
        }
        FAIL_PHASE.with(|slot| slot.replace(Some("cancelled_receipt".into())));
        let error = fixture.dispatch(&cancellation).unwrap_err();
        assert!(!launch_may_have_started(&error));
        {
            let journal = fixture.journal();
            let last = journal.records().last().unwrap();
            assert_eq!(last.phase, if staged { "before_effect" } else { "intent" });
            assert_eq!(last.payload["checkpoint"]["state"], "Cancelled");
            if staged {
                assert_eq!(last.payload["cancelled"], true);
            }
        }
        let error = fixture.dispatch(&ProcessCancellation::new()).unwrap_err();
        assert!(!launch_may_have_started(&error));
        assert!(error.to_string().contains("cancelled before launch"));
        let state = fixture.transport.0.lock().unwrap();
        assert_eq!(state.stages.len(), usize::from(staged));
        assert!(state.launches.is_empty());
        assert!(state.statuses.is_empty());
        assert_eq!(state.cleanups, 0);
    }
}

#[test]
fn prelaunch_refusals_have_no_launch_custody_but_lost_launch_does() {
    let fixture = Fixture::new();
    let error = fixture
        .host
        .dispatch(
            &fixture.repo,
            fixture.identity(),
            &[PathBuf::from("outside")],
            &fixture.command,
            &ProcessCancellation::new(),
        )
        .unwrap_err();
    assert!(!launch_may_have_started(&error));
    assert!(fixture.transport.0.lock().unwrap().stages.is_empty());
    fixture.transport.0.lock().unwrap().lost_stage = true;
    let error = fixture.dispatch(&ProcessCancellation::new()).unwrap_err();
    assert!(!launch_may_have_started(&error));
    let error = fixture.dispatch(&ProcessCancellation::new()).unwrap_err();
    assert!(!launch_may_have_started(&error));
    let fixture = Fixture::new();
    fixture.transport.0.lock().unwrap().lost_launch = true;
    let error = fixture.dispatch(&ProcessCancellation::new()).unwrap_err();
    assert!(launch_may_have_started(&error));
}

#[test]
fn termination_policy_is_frozen_from_trusted_limits_across_resume() {
    let fixture = Fixture::new();
    let cancellation = ProcessCancellation::new();
    {
        let mut state = fixture.transport.0.lock().unwrap();
        state.cancel_on_wait = Some(cancellation.clone());
        state.lost_control = true;
    }
    assert!(fixture.dispatch(&cancellation).is_err());
    {
        let journal = fixture.journal();
        assert_eq!(
            journal.records()[0].payload["termination"]["term_grace_ms"],
            500
        );
        assert_eq!(
            journal.records()[0].payload["termination"]["kill_wait_ms"],
            500
        );
    }
    let host = SupervisedSshHost::configure(
        ExecutorSelection::ssh(target()),
        Some(trust_with_grace(&fixture._temp, 777)),
        |_| Ok(fixture.transport.clone()),
        fixture.coordinator.clone(),
    )
    .unwrap();
    host.dispatch(
        &fixture.repo,
        fixture.identity(),
        &[PathBuf::from("src")],
        &fixture.command,
        &ProcessCancellation::new(),
    )
    .unwrap();
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.controls.len(), 2);
    assert_eq!(state.controls[0].key, state.controls[1].key);
    assert!(state.waits.iter().any(|wait| wait.max_wait.get() == 500));
    assert!(state.waits.iter().all(|wait| wait.max_wait.get() != 777));
}

#[test]
fn finished_resume_recaptures_without_growing_the_journal() {
    let fixture = Fixture::new();
    fixture.dispatch(&ProcessCancellation::new()).unwrap();
    let count = fixture.journal().records().len();
    for _ in 0..8 {
        fixture.dispatch(&ProcessCancellation::new()).unwrap();
        assert_eq!(fixture.journal().records().len(), count);
    }
    assert_eq!(fixture.transport.0.lock().unwrap().cleanups, 1);
    assert_eq!(fixture.coordinator.state.lock().unwrap().recaptures, 9);
}

#[test]
fn lost_reply_restart_never_duplicates_launch() {
    let fixture = Fixture::new();
    fixture.transport.0.lock().unwrap().lost_launch = true;
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    let mut state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.launches.len(), 1);
    state.not_found = 1;
    drop(state);
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    let run = fixture.dispatch(&ProcessCancellation::new()).unwrap();
    assert!(!run.publishable);
    assert!(run.process_tree.is_none());
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.stages.len(), 1);
    assert_eq!(state.launches.len(), 1);
    assert_eq!(state.statuses.len(), 2);
    assert_eq!(state.cleanups, 1);
}

#[test]
fn lost_launch_receipt_publication_never_relaunches() {
    let fixture = Fixture::new();
    fixture
        .transport
        .0
        .lock()
        .unwrap()
        .fail_launch_receipt_write = true;
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    fixture.dispatch(&ProcessCancellation::new()).unwrap();
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.launches.len(), 1);
    assert_eq!(state.statuses.len(), 1);
    assert!(matches!(
        state.statuses[0].query,
        ExecutionQuery::Submitted(_)
    ));
}

#[test]
fn recapture_receipt_is_required_before_cleanup() {
    let fixture = Fixture::new();
    FAIL_PHASE.with(|slot| slot.replace(Some("candidate_recaptured".into())));
    let run = fixture.dispatch(&ProcessCancellation::new()).unwrap();
    assert!(!run.publishable);
    assert_eq!(run.duration_ms, 17);
    assert!(run.error.unwrap().contains("candidate_recaptured"));
    assert_eq!(fixture.transport.0.lock().unwrap().cleanups, 0);
    fixture.dispatch(&ProcessCancellation::new()).unwrap();
    assert_eq!(fixture.transport.0.lock().unwrap().cleanups, 1);
    let capture = fixture.coordinator.state.lock().unwrap();
    assert_eq!(capture.imports, 1);
    assert_eq!(capture.recaptures, 2);
}

#[test]
fn cleanup_requires_persisted_imported_collection() {
    let fixture = Fixture::new();
    FAIL_PHASE.with(|slot| slot.replace(Some("collection_committed".into())));
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    assert_eq!(fixture.coordinator.state.lock().unwrap().imports, 0);
    assert_eq!(fixture.transport.0.lock().unwrap().cleanups, 0);
    fixture.coordinator.state.lock().unwrap().fail_recapture = true;
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    assert_eq!(fixture.transport.0.lock().unwrap().cleanups, 0);
    fixture.dispatch(&ProcessCancellation::new()).unwrap();
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.launches.len(), 1);
    assert_eq!(state.collections.len(), 2);
    assert_eq!(state.collections[0].key, state.collections[1].key);
    assert_eq!(state.cleanups, 1);
    let capture = fixture.coordinator.state.lock().unwrap();
    assert_eq!(capture.imports, 1);
    assert_eq!(capture.recaptures, 2);
    let phases = phases(&fixture.repo);
    let at = |phase: &str| phases.iter().position(|item| item == phase).unwrap();
    assert!(at("collection_committed") < at("before_import"));
    assert!(at("candidate_imported") < at("candidate_recaptured"));
    assert!(at("candidate_recaptured") < at("before_cleanup"));
    assert!(at("before_cleanup") < at("cleanup_receipt"));
}

#[test]
fn lost_collection_and_import_replies_resume_exact_collection() {
    let fixture = Fixture::new();
    fixture.transport.0.lock().unwrap().lost_collect = true;
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    fixture
        .coordinator
        .state
        .lock()
        .unwrap()
        .fail_import_after_effect = true;
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    assert_eq!(fixture.transport.0.lock().unwrap().cleanups, 0);
    fixture.dispatch(&ProcessCancellation::new()).unwrap();
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.launches.len(), 1);
    assert_eq!(state.collections.len(), 2);
    assert_eq!(state.collections[0].key, state.collections[1].key);
    assert_eq!(fixture.coordinator.state.lock().unwrap().imports, 2);
    assert_eq!(state.cleanups, 1);
}

#[test]
fn import_receipt_failure_and_lost_cleanup_preserve_output() {
    let fixture = Fixture::new();
    FAIL_PHASE.with(|slot| slot.replace(Some("candidate_imported".into())));
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    assert_eq!(fixture.transport.0.lock().unwrap().cleanups, 0);
    fixture.transport.0.lock().unwrap().lost_cleanup = true;
    let run = fixture.dispatch(&ProcessCancellation::new()).unwrap();
    assert!(!run.publishable);
    assert_eq!(run.duration_ms, 17);
    assert!(run.error.unwrap().contains("cleanup is uncertain"));
    fixture.dispatch(&ProcessCancellation::new()).unwrap();
    // A completed cleanup is never repeated on another resume.
    fixture.dispatch(&ProcessCancellation::new()).unwrap();
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.collections.len(), 1);
    assert_eq!(state.cleanups, 2);
    assert_eq!(state.cleanup_keys[0], state.cleanup_keys[1]);
    assert_eq!(fixture.coordinator.state.lock().unwrap().imports, 2);
}

#[test]
fn uncertain_stage_and_changed_identity_refuse_without_effects() {
    let fixture = Fixture::new();
    fixture.transport.0.lock().unwrap().lost_stage = true;
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    let mut command = fixture.command.clone();
    command.model = Some("different-model".into());
    assert!(fixture
        .host
        .dispatch(
            &fixture.repo,
            fixture.identity(),
            &[PathBuf::from("src")],
            &command,
            &ProcessCancellation::new()
        )
        .is_err());
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.stages.len(), 1);
    assert!(state.launches.is_empty());
    assert_eq!(state.cleanups, 0);
}

#[test]
fn tampered_checkpoint_never_replays_or_cleans_up() {
    let fixture = Fixture::new();
    fixture.coordinator.state.lock().unwrap().fail_recapture = true;
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    let root = fixture
        .repo
        .join(".git/maco/state")
        .join(RemoteJournalSpec::ROOT_NAME);
    let instance = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .unwrap();
    fs::write(instance.join(".head.json"), b"{}").unwrap();
    assert!(fixture.dispatch(&ProcessCancellation::new()).is_err());
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.stages.len(), 1);
    assert_eq!(state.launches.len(), 1);
    assert_eq!(state.collections.len(), 1);
    assert_eq!(state.cleanups, 0);
}

#[test]
fn cancellation_survives_lost_control_reply_and_restart() {
    let fixture = Fixture::new();
    let cancellation = ProcessCancellation::new();
    {
        let mut state = fixture.transport.0.lock().unwrap();
        state.cancel_on_wait = Some(cancellation.clone());
        state.lost_control = true;
    }
    assert!(fixture.dispatch(&cancellation).is_err());
    fixture.dispatch(&ProcessCancellation::new()).unwrap();
    let state = fixture.transport.0.lock().unwrap();
    assert_eq!(state.launches.len(), 1);
    assert_eq!(state.controls.len(), 2);
    assert_eq!(state.controls[0].key, state.controls[1].key);
    assert_eq!(state.cleanups, 1);
}

#[test]
fn selected_supervisor_dispatch_requires_explicit_trust_and_keeps_local_default() {
    let fixture = Fixture::new();
    let local = |command: &ExternalAgentCommand,
                 _: &ProcessCancellation,
                 _: Option<ExternalPreActionReviewRuntime<'_>>| {
        crate::external_agent::refused_external_run_before_launch(
            command,
            "local default observed".into(),
        )
    };
    let mut metadata = AssignmentMetadata::new();
    let run_id = crate::orchestrator::RunId::new("run-7").unwrap();
    let dispatch = |metadata: &AssignmentMetadata, runner: &CancellableExternalRunner<'_>| {
        assignment_executor::dispatch_assignment_external(
            metadata,
            &fixture.repo,
            &run_id,
            "assignment-4",
            None,
            3,
            &[PathBuf::from("src")],
            &fixture.command,
            &ProcessCancellation::new(),
            None,
            runner,
        )
    };
    assert!(dispatch(&metadata, &local)
        .unwrap()
        .error
        .unwrap()
        .contains("local default"));
    metadata.executors.insert(
        ("assignment-4".into(), None),
        fixture.host.selection().clone(),
    );
    assert!(assignment_executor::validate_assignment_executors_pre_dispatch(&metadata).is_err());
    let never_local = |_: &ExternalAgentCommand,
                       _: &ProcessCancellation,
                       _: Option<ExternalPreActionReviewRuntime<'_>>|
     -> ExternalAgentRun { panic!("SSH must never fall back to Local") };
    assert!(dispatch(&metadata, &never_local).is_err());
    let _binding = bind_supervised_ssh_hosts(vec![fixture.host.clone()]).unwrap();
    assignment_executor::parse_assignment_executor(
        &json!({"executor": fixture.host.selection()}),
        "assignment-4",
        None,
        &mut metadata,
    )
    .unwrap();
    assignment_executor::validate_assignment_executors_pre_dispatch(&metadata).unwrap();
    let run = dispatch(&metadata, &never_local).unwrap();
    assert!(!run.publishable);
    assert_eq!(fixture.transport.0.lock().unwrap().launches.len(), 1);
    assert!(SupervisedSshHost::configure::<FakeTransport>(
        ExecutorSelection::ssh(target()),
        None,
        |_| panic!("missing trust must not construct a transport"),
        fixture.coordinator.clone()
    )
    .is_err());
}
