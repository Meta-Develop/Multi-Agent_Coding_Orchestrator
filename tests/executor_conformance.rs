use multi_agent_coding_orchestrator::executor::{
    AgentExecutor, BoundedExecutor, CancellationToken, CandidateArtifact, CapturedOutput,
    CleanupStatus, EffectReconciliation, ExecutionSemantics, ExecutionStatus, ExecutorKind,
    ExecutorLifecycleEvent, ExecutorLimits, ExecutorRequest, ExecutorUsage, OpenSshTransport,
    RecoveryTarget, RemoteExecutionReply, RemoteExecutionRequest, RemoteProcessIdentity, SshConfig,
    SshConfigInput, SshExecutor, SshTransport, TransportFailure, TransportFailureKind,
    TransportStage,
};
use multi_agent_coding_orchestrator::runtime_adapter::{
    adapter_for, AdapterId, LaunchContext, OutputCaptureMode, RuntimeAdapterConfig, RuntimeId,
    SideEffectConfinement, TypedRuntime,
};
use std::fs;
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn limits() -> ExecutorLimits {
    ExecutorLimits {
        max_workspace_entries: 16,
        max_workspace_bytes: 4096,
        max_file_bytes: 2048,
        max_stdout_bytes: 4,
        max_stderr_bytes: 4,
        max_event_count: 16,
        max_event_bytes: 2048,
        max_request_bytes: 16 * 1024,
        max_receipt_bytes: 16 * 1024,
        connect_timeout_millis: 500,
        execution_timeout_millis: 5_000,
        cancellation_grace_millis: 500,
        poll_interval_millis: 10,
    }
}

fn write_trust_files(directory: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let identity = directory.join("identity");
    let known_hosts = directory.join("known_hosts");
    fs::write(&identity, b"test-only-key\n").expect("write identity fixture");
    fs::write(&known_hosts, b"host ssh-ed25519 test-only-key\n")
        .expect("write known-hosts fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o600))
            .expect("restrict identity fixture");
    }
    (identity, known_hosts)
}

fn config(directory: &Path) -> SshConfig {
    config_with_limits(directory, limits())
}

fn config_with_limits(directory: &Path, limits: ExecutorLimits) -> SshConfig {
    let (identity_file, known_hosts_file) = write_trust_files(directory);
    SshConfig::new(SshConfigInput {
        host_id: "fixture-host".to_string(),
        host: "127.0.0.1".to_string(),
        user: "runner".to_string(),
        port: 22,
        identity_file,
        known_hosts_file,
        remote_root: "/var/tmp/maco-executor".to_string(),
        helper_path: "/usr/libexec/maco-executor-helper".to_string(),
        limits,
    })
    .expect("valid explicit SSH fixture config")
}

#[derive(Debug, Clone, Copy)]
enum FakeMode {
    Scenario,
    PreflightFailure,
    LaunchLoss,
    TransportFailure(TransportStage, TransportFailureKind),
    OversizedTransportFailure(TransportStage, TransportFailureKind),
    ExactReceipt,
    OversizedReceipt,
    OversizedStdout,
    OversizedStderr,
    OversizedEvents,
    UsageMismatch,
    WrongIdentity,
    WrongRecoveryIdentity,
    WrongRecoveryDigest,
    InvalidRecoveryProcess,
    MismatchedRecoveryTargets,
    MismatchedRecoveryProcesses,
    IncoherentUsage,
    IncoherentCleanupEvent,
    CancelledWithoutProof,
    TimedOutWithoutProof,
    ArtifactDigestMismatch,
    ArtifactPathSetMismatch,
    ArtifactPathEscape,
    OversizedArtifact,
    CleanupResidual,
    CleanupResidualWithProcess,
    HostileLifecycle(LifecycleForgery),
    FinalWorkspace(FinalWorkspaceCase),
}

#[derive(Debug, Clone, Copy)]
enum LifecycleForgery {
    ExitedMissingReconciled,
    ExitedDuplicateCollected,
    ExitedStageLaunchOutOfOrder,
    CancelledMissingRequest,
    CancelledControlOutOfOrder,
    TimedOutMissingTerm,
    TimedOutControlOutOfOrder,
    UncertainMissingCleanupResidual,
    UncertainCleanupNotTerminal,
    ReconciledMissingCollected,
    CleanupCompleteNotTerminal,
    FailedMissingCollectionAndReconciliation,
}

#[derive(Debug, Clone, Copy)]
enum FinalWorkspaceCase {
    AddFileBeyondEntries,
    AddDirectoryBeyondEntries,
    AddFileBeyondBytes,
    ModifyBeyondAggregate,
    ModifyBeyondPerFile,
    DeleteThenCreate,
    ReplaceEntryTypes,
    DeleteDirectoryWithChild,
    RetypeDirectoryWithChild,
    ExactFinalLimits,
}

#[derive(Debug)]
struct FakeTransport {
    mode: FakeMode,
    calls: AtomicUsize,
    requests: Mutex<Vec<RemoteExecutionRequest>>,
}

impl FakeTransport {
    fn new(mode: FakeMode) -> Self {
        Self {
            mode,
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn request(&self, index: usize) -> RemoteExecutionRequest {
        self.requests
            .lock()
            .expect("lock fake requests")
            .get(index)
            .expect("captured request")
            .clone()
    }
}

impl SshTransport for FakeTransport {
    fn execute(
        &self,
        config: &SshConfig,
        request: &RemoteExecutionRequest,
        cancellation: &CancellationToken,
    ) -> Result<RemoteExecutionReply, TransportFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("lock fake requests")
            .push(request.clone());
        match self.mode {
            FakeMode::PreflightFailure => Err(TransportFailure::new(
                TransportStage::Preflight,
                TransportFailureKind::Authentication,
                "explicit identity rejected",
            )),
            FakeMode::LaunchLoss => Err(TransportFailure::new(
                TransportStage::Launch,
                TransportFailureKind::Io,
                "transport lost after submission",
            )),
            FakeMode::TransportFailure(stage, kind) => Err(TransportFailure::new(
                stage,
                kind,
                format!("injected {stage:?}/{kind:?} transport failure"),
            )),
            FakeMode::OversizedTransportFailure(stage, kind) => {
                let lossy_invalid = String::from_utf8_lossy(&[0xff]).into_owned();
                let reason = format!(
                    "hostile\0{lossy_invalid}\"\\reason\n{}\u{7}",
                    "雪".repeat(config.limits().max_receipt_bytes.saturating_add(1))
                );
                Err(TransportFailure::new(stage, kind, reason))
            }
            FakeMode::Scenario
            | FakeMode::ExactReceipt
            | FakeMode::OversizedReceipt
            | FakeMode::OversizedStdout
            | FakeMode::OversizedStderr
            | FakeMode::OversizedEvents
            | FakeMode::UsageMismatch
            | FakeMode::WrongIdentity
            | FakeMode::WrongRecoveryIdentity
            | FakeMode::WrongRecoveryDigest
            | FakeMode::InvalidRecoveryProcess
            | FakeMode::MismatchedRecoveryTargets
            | FakeMode::MismatchedRecoveryProcesses
            | FakeMode::IncoherentUsage
            | FakeMode::IncoherentCleanupEvent
            | FakeMode::CancelledWithoutProof
            | FakeMode::TimedOutWithoutProof
            | FakeMode::ArtifactDigestMismatch
            | FakeMode::ArtifactPathSetMismatch
            | FakeMode::ArtifactPathEscape
            | FakeMode::OversizedArtifact
            | FakeMode::CleanupResidual
            | FakeMode::CleanupResidualWithProcess
            | FakeMode::HostileLifecycle(_)
            | FakeMode::FinalWorkspace(_) => {
                let mut reply = scenario_reply(request, cancellation);
                if matches!(
                    self.mode,
                    FakeMode::ExactReceipt | FakeMode::OversizedReceipt
                ) {
                    let target = request.limits.max_receipt_bytes
                        + usize::from(matches!(self.mode, FakeMode::OversizedReceipt));
                    resize_failed_receipt(&mut reply, target);
                }
                if matches!(self.mode, FakeMode::OversizedStdout) {
                    reply.semantics.stdout.bytes = vec![b'x'; request.limits.max_stdout_bytes + 1];
                    reply.semantics.usage.stdout_bytes = reply.semantics.stdout.bytes.len();
                }
                if matches!(self.mode, FakeMode::OversizedStderr) {
                    reply.semantics.stderr.bytes = vec![b'x'; request.limits.max_stderr_bytes + 1];
                    reply.semantics.usage.stderr_bytes = reply.semantics.stderr.bytes.len();
                }
                if matches!(self.mode, FakeMode::OversizedEvents) {
                    reply.semantics.events =
                        vec![ExecutorLifecycleEvent::Validated; request.limits.max_event_count + 1];
                    reply.semantics.usage.event_count = reply.semantics.events.len();
                }
                if matches!(self.mode, FakeMode::UsageMismatch) {
                    reply.semantics.usage.workspace_bytes += 1;
                }
                if matches!(self.mode, FakeMode::WrongIdentity) {
                    reply.executor_run_id.push_str("-wrong");
                }
                if matches!(
                    self.mode,
                    FakeMode::WrongRecoveryIdentity
                        | FakeMode::WrongRecoveryDigest
                        | FakeMode::InvalidRecoveryProcess
                        | FakeMode::MismatchedRecoveryTargets
                        | FakeMode::MismatchedRecoveryProcesses
                ) {
                    let mut recovery = recovery_target(request);
                    if matches!(self.mode, FakeMode::WrongRecoveryIdentity) {
                        recovery.host_id.push_str("-wrong");
                    }
                    if matches!(self.mode, FakeMode::WrongRecoveryDigest) {
                        recovery.staged_input_digest = format!("sha256:{}", "0".repeat(64));
                    }
                    if matches!(
                        self.mode,
                        FakeMode::InvalidRecoveryProcess | FakeMode::MismatchedRecoveryProcesses
                    ) {
                        recovery.remote_process = Some(RemoteProcessIdentity {
                            session_id: "session-1".to_string(),
                            pid: if matches!(self.mode, FakeMode::InvalidRecoveryProcess) {
                                0
                            } else {
                                4101
                            },
                            pgid: 4101,
                            start_token: "start-1".to_string(),
                        });
                    }
                    reply.semantics.status = ExecutionStatus::Uncertain {
                        reason: "remote state is uncertain".to_string(),
                        recovery: recovery.clone(),
                    };
                    reply.semantics.effects = EffectReconciliation::Uncertain {
                        recovery: recovery.clone(),
                    };
                    reply.semantics.cleanup = CleanupStatus::Residual {
                        recovery: recovery.clone(),
                    };
                    reply.semantics.events = vec![
                        ExecutorLifecycleEvent::Validated,
                        ExecutorLifecycleEvent::Staged,
                        ExecutorLifecycleEvent::Launched,
                        ExecutorLifecycleEvent::CleanupResidual,
                    ];
                    reply.semantics.usage.event_count = reply.semantics.events.len();
                    reply.semantics.usage.complete = false;
                    if matches!(self.mode, FakeMode::MismatchedRecoveryTargets) {
                        let mut mismatched = recovery.clone();
                        mismatched.executor_run_id.push_str("-other");
                        reply.semantics.effects = EffectReconciliation::Uncertain {
                            recovery: mismatched,
                        };
                    }
                    if matches!(self.mode, FakeMode::MismatchedRecoveryProcesses) {
                        let mut mismatched = recovery.clone();
                        mismatched.remote_process = Some(RemoteProcessIdentity {
                            session_id: "session-1".to_string(),
                            pid: 4102,
                            pgid: 4101,
                            start_token: "start-1".to_string(),
                        });
                        reply.semantics.effects = EffectReconciliation::Uncertain {
                            recovery: mismatched,
                        };
                    }
                }
                if matches!(self.mode, FakeMode::IncoherentUsage) {
                    reply.semantics.usage.complete = true;
                }
                if matches!(self.mode, FakeMode::IncoherentCleanupEvent) {
                    let recovery = recovery_target(request);
                    reply.semantics.status = ExecutionStatus::Uncertain {
                        reason: "cleanup event is inconsistent".to_string(),
                        recovery: recovery.clone(),
                    };
                    reply.semantics.effects = EffectReconciliation::Uncertain {
                        recovery: recovery.clone(),
                    };
                    reply.semantics.cleanup = CleanupStatus::Residual { recovery };
                    reply.semantics.usage.complete = false;
                }
                if matches!(self.mode, FakeMode::CancelledWithoutProof) {
                    reply.semantics.status = ExecutionStatus::Cancelled;
                }
                if matches!(self.mode, FakeMode::TimedOutWithoutProof) {
                    reply.semantics.status = ExecutionStatus::TimedOut;
                    reply.semantics.usage.complete = false;
                }
                if matches!(
                    self.mode,
                    FakeMode::ArtifactDigestMismatch
                        | FakeMode::ArtifactPathSetMismatch
                        | FakeMode::ArtifactPathEscape
                        | FakeMode::OversizedArtifact
                ) {
                    let mut artifact =
                        CandidateArtifact::file("out.txt", b"candidate".to_vec(), false)
                            .expect("construct candidate artifact fixture");
                    let mut changed_paths = vec![artifact.path.clone()];
                    if matches!(self.mode, FakeMode::ArtifactDigestMismatch) {
                        artifact.digest = Some(format!("sha256:{}", "0".repeat(64)));
                    }
                    if matches!(self.mode, FakeMode::ArtifactPathSetMismatch) {
                        changed_paths[0] = "different.txt".to_string();
                    }
                    if matches!(self.mode, FakeMode::ArtifactPathEscape) {
                        artifact.path = "../escape".to_string();
                        changed_paths[0] = artifact.path.clone();
                    }
                    if matches!(self.mode, FakeMode::OversizedArtifact) {
                        artifact = CandidateArtifact::file(
                            "out.txt",
                            vec![b'x'; request.limits.max_file_bytes + 1],
                            false,
                        )
                        .expect("construct oversized candidate artifact fixture");
                        changed_paths[0] = artifact.path.clone();
                    }
                    reply.semantics.effects = EffectReconciliation::CandidateArtifacts {
                        changed_paths,
                        artifacts: vec![artifact],
                    };
                }
                if matches!(
                    self.mode,
                    FakeMode::CleanupResidual | FakeMode::CleanupResidualWithProcess
                ) {
                    let mut recovery = recovery_target(request);
                    if matches!(self.mode, FakeMode::CleanupResidualWithProcess) {
                        recovery.remote_process = Some(RemoteProcessIdentity {
                            session_id: "session-accepted".to_string(),
                            pid: 4201,
                            pgid: 4201,
                            start_token: "start-accepted".to_string(),
                        });
                    }
                    reply.semantics.status = ExecutionStatus::Uncertain {
                        reason: "remote cleanup could not be proven".to_string(),
                        recovery: recovery.clone(),
                    };
                    reply.semantics.effects = EffectReconciliation::Uncertain {
                        recovery: recovery.clone(),
                    };
                    reply.semantics.cleanup = CleanupStatus::Residual {
                        recovery: recovery.clone(),
                    };
                    reply.semantics.events = vec![
                        ExecutorLifecycleEvent::Validated,
                        ExecutorLifecycleEvent::Staged,
                        ExecutorLifecycleEvent::Launched,
                        ExecutorLifecycleEvent::Collected,
                        ExecutorLifecycleEvent::CleanupResidual,
                    ];
                    reply.semantics.usage.event_count = reply.semantics.events.len();
                    reply.semantics.usage.complete = false;
                }
                if let FakeMode::HostileLifecycle(forgery) = self.mode {
                    forge_lifecycle(&mut reply, request, forgery);
                }
                if let FakeMode::FinalWorkspace(case) = self.mode {
                    reply.semantics.effects = final_workspace_effects(case, request);
                }
                Ok(reply)
            }
        }
    }
}

fn final_workspace_effects(
    case: FinalWorkspaceCase,
    request: &RemoteExecutionRequest,
) -> EffectReconciliation {
    let artifacts = match case {
        FinalWorkspaceCase::AddFileBeyondEntries => {
            vec![CandidateArtifact::file("new-file", b"x".to_vec(), false)
                .expect("construct added-file fixture")]
        }
        FinalWorkspaceCase::AddDirectoryBeyondEntries => {
            vec![CandidateArtifact::directory("new-directory")]
        }
        FinalWorkspaceCase::AddFileBeyondBytes => {
            vec![CandidateArtifact::file("new-file", b"x".to_vec(), false)
                .expect("construct byte-overflow fixture")]
        }
        FinalWorkspaceCase::ModifyBeyondAggregate => {
            vec![
                CandidateArtifact::file("grow.txt", b"123456".to_vec(), false)
                    .expect("construct aggregate-growth fixture"),
            ]
        }
        FinalWorkspaceCase::ModifyBeyondPerFile => vec![CandidateArtifact::file(
            "grow.txt",
            vec![b'x'; request.limits.max_file_bytes + 1],
            false,
        )
        .expect("construct per-file-growth fixture")],
        FinalWorkspaceCase::DeleteThenCreate => vec![
            CandidateArtifact::file("new.txt", b"123456".to_vec(), false)
                .expect("construct capacity-replacement fixture"),
            CandidateArtifact::deleted("old.txt"),
        ],
        FinalWorkspaceCase::ReplaceEntryTypes => vec![
            CandidateArtifact::file("dir-node", b"xy".to_vec(), false)
                .expect("construct directory-to-file fixture"),
            CandidateArtifact::directory("file-node"),
        ],
        FinalWorkspaceCase::DeleteDirectoryWithChild => {
            vec![CandidateArtifact::deleted("tree")]
        }
        FinalWorkspaceCase::RetypeDirectoryWithChild => {
            vec![
                CandidateArtifact::file("tree", b"replacement".to_vec(), false)
                    .expect("construct invalid directory-retype fixture"),
            ]
        }
        FinalWorkspaceCase::ExactFinalLimits => vec![
            CandidateArtifact::directory("added-dir"),
            CandidateArtifact::file("added-file", b"123456".to_vec(), false)
                .expect("construct exact-limit file fixture"),
        ],
    };
    EffectReconciliation::CandidateArtifacts {
        changed_paths: artifacts
            .iter()
            .map(|artifact| artifact.path.clone())
            .collect(),
        artifacts,
    }
}

fn forge_lifecycle(
    reply: &mut RemoteExecutionReply,
    request: &RemoteExecutionRequest,
    forgery: LifecycleForgery,
) {
    reply.semantics.status = ExecutionStatus::Exited { code: Some(0) };
    reply.semantics.stdout = empty_capture();
    reply.semantics.stderr = empty_capture();
    reply.semantics.effects = EffectReconciliation::CandidateOnly {
        changed_paths: Vec::new(),
    };
    reply.semantics.cleanup = CleanupStatus::Complete;
    reply.semantics.events = terminal_events(false);

    match forgery {
        LifecycleForgery::ExitedMissingReconciled => {
            reply
                .semantics
                .events
                .retain(|event| *event != ExecutorLifecycleEvent::Reconciled);
        }
        LifecycleForgery::ExitedDuplicateCollected => {
            let collected = reply
                .semantics
                .events
                .iter()
                .position(|event| *event == ExecutorLifecycleEvent::Collected)
                .expect("base lifecycle contains collection");
            reply
                .semantics
                .events
                .insert(collected + 1, ExecutorLifecycleEvent::Collected);
        }
        LifecycleForgery::ExitedStageLaunchOutOfOrder => {
            reply.semantics.events.swap(1, 2);
        }
        LifecycleForgery::CancelledMissingRequest => {
            reply.semantics.status = ExecutionStatus::Cancelled;
            reply.semantics.events = terminal_events(true);
            reply
                .semantics
                .events
                .retain(|event| *event != ExecutorLifecycleEvent::CancelRequested);
        }
        LifecycleForgery::CancelledControlOutOfOrder => {
            reply.semantics.status = ExecutionStatus::Cancelled;
            reply.semantics.events = terminal_events(true);
            reply.semantics.events.swap(3, 4);
        }
        LifecycleForgery::TimedOutMissingTerm | LifecycleForgery::TimedOutControlOutOfOrder => {
            reply.semantics.status = ExecutionStatus::TimedOut;
            reply.semantics.events = vec![
                ExecutorLifecycleEvent::Validated,
                ExecutorLifecycleEvent::Staged,
                ExecutorLifecycleEvent::Launched,
                ExecutorLifecycleEvent::TimeoutExpired,
                ExecutorLifecycleEvent::TermSent,
                ExecutorLifecycleEvent::Collected,
                ExecutorLifecycleEvent::Reconciled,
                ExecutorLifecycleEvent::CleanupComplete,
            ];
            if matches!(forgery, LifecycleForgery::TimedOutMissingTerm) {
                reply
                    .semantics
                    .events
                    .retain(|event| *event != ExecutorLifecycleEvent::TermSent);
            } else {
                reply.semantics.events.swap(3, 4);
            }
        }
        LifecycleForgery::UncertainMissingCleanupResidual
        | LifecycleForgery::UncertainCleanupNotTerminal => {
            let recovery = recovery_target(request);
            reply.semantics.status = ExecutionStatus::Uncertain {
                reason: "forged uncertain lifecycle".to_string(),
                recovery: recovery.clone(),
            };
            reply.semantics.effects = EffectReconciliation::Uncertain {
                recovery: recovery.clone(),
            };
            reply.semantics.cleanup = CleanupStatus::Residual { recovery };
            reply.semantics.events = vec![
                ExecutorLifecycleEvent::Validated,
                ExecutorLifecycleEvent::Staged,
                ExecutorLifecycleEvent::Launched,
                ExecutorLifecycleEvent::Collected,
                ExecutorLifecycleEvent::CleanupResidual,
            ];
            if matches!(forgery, LifecycleForgery::UncertainMissingCleanupResidual) {
                reply.semantics.events.pop();
            } else {
                reply.semantics.events.swap(3, 4);
            }
        }
        LifecycleForgery::ReconciledMissingCollected => {
            let artifact = CandidateArtifact::file("out.txt", b"candidate".to_vec(), false)
                .expect("construct reconciled artifact fixture");
            reply.semantics.effects = EffectReconciliation::CandidateArtifacts {
                changed_paths: vec![artifact.path.clone()],
                artifacts: vec![artifact],
            };
            reply
                .semantics
                .events
                .retain(|event| *event != ExecutorLifecycleEvent::Collected);
        }
        LifecycleForgery::CleanupCompleteNotTerminal => {
            reply.semantics.events.swap(4, 5);
        }
        LifecycleForgery::FailedMissingCollectionAndReconciliation => {
            reply.semantics.status = ExecutionStatus::Failed {
                reason: "forged remote failure".to_string(),
            };
            reply.semantics.events = vec![
                ExecutorLifecycleEvent::Validated,
                ExecutorLifecycleEvent::Staged,
                ExecutorLifecycleEvent::Launched,
                ExecutorLifecycleEvent::CleanupComplete,
            ];
        }
    }
    reply.semantics.usage.stdout_bytes = reply.semantics.stdout.bytes.len();
    reply.semantics.usage.stderr_bytes = reply.semantics.stderr.bytes.len();
    reply.semantics.usage.event_count = reply.semantics.events.len();
    reply.semantics.usage.complete = !matches!(
        reply.semantics.status,
        ExecutionStatus::TimedOut | ExecutionStatus::Uncertain { .. }
    );
}

fn recovery_target(request: &RemoteExecutionRequest) -> RecoveryTarget {
    RecoveryTarget {
        assignment_id: request.assignment_id.clone(),
        executor_run_id: request.executor_run_id.clone(),
        host_id: request.host_id.clone(),
        workspace: request.remote_root.clone(),
        staged_input_digest: request.staged_input_digest.clone(),
        remote_process: None,
    }
}

fn resize_failed_receipt(reply: &mut RemoteExecutionReply, target: usize) {
    reply.semantics.status = ExecutionStatus::Failed {
        reason: "x".to_string(),
    };
    reply.semantics.stdout = empty_capture();
    reply.semantics.stderr = empty_capture();
    reply.semantics.events = terminal_events(false);
    reply.semantics.effects = EffectReconciliation::CandidateOnly {
        changed_paths: Vec::new(),
    };
    reply.semantics.cleanup = CleanupStatus::Complete;
    reply.semantics.usage.stdout_bytes = 0;
    reply.semantics.usage.stderr_bytes = 0;
    reply.semantics.usage.event_count = reply.semantics.events.len();
    reply.semantics.usage.complete = true;

    let encoded = serde_json::to_vec(reply).expect("measure fake receipt");
    let padding = target
        .checked_sub(encoded.len())
        .expect("configured receipt boundary fits base reply");
    let ExecutionStatus::Failed { reason } = &mut reply.semantics.status else {
        panic!("fake receipt must remain failed");
    };
    reason.push_str(&"x".repeat(padding));
    assert_eq!(
        serde_json::to_vec(reply)
            .expect("measure resized fake receipt")
            .len(),
        target
    );
}

fn scenario_reply(
    request: &RemoteExecutionRequest,
    cancellation: &CancellationToken,
) -> RemoteExecutionReply {
    let (status, stdout, stderr, events) = match request.assignment_id.as_str() {
        "success" => (
            ExecutionStatus::Exited { code: Some(0) },
            CapturedOutput {
                bytes: b"alph".to_vec(),
                truncated: true,
            },
            CapturedOutput {
                bytes: b"beta".to_vec(),
                truncated: false,
            },
            terminal_events(false),
        ),
        "truncate-stream" => (
            ExecutionStatus::Exited { code: Some(0) },
            CapturedOutput {
                bytes: vec![0; request.limits.max_stdout_bytes],
                truncated: true,
            },
            empty_capture(),
            terminal_events(false),
        ),
        "nonzero" => (
            ExecutionStatus::Exited { code: Some(7) },
            empty_capture(),
            empty_capture(),
            terminal_events(false),
        ),
        "workspace" | "effects" => (
            ExecutionStatus::Exited { code: Some(0) },
            empty_capture(),
            empty_capture(),
            terminal_events(false),
        ),
        "cancel-running" => {
            while !cancellation.is_cancelled() {
                thread::sleep(Duration::from_millis(5));
            }
            (
                ExecutionStatus::Cancelled,
                empty_capture(),
                empty_capture(),
                terminal_events(true),
            )
        }
        "timeout-running" => (
            ExecutionStatus::TimedOut,
            empty_capture(),
            empty_capture(),
            vec![
                ExecutorLifecycleEvent::Validated,
                ExecutorLifecycleEvent::Staged,
                ExecutorLifecycleEvent::Launched,
                ExecutorLifecycleEvent::TimeoutExpired,
                ExecutorLifecycleEvent::TermSent,
                ExecutorLifecycleEvent::Collected,
                ExecutorLifecycleEvent::Reconciled,
                ExecutorLifecycleEvent::CleanupComplete,
            ],
        ),
        other => panic!("unexpected fake scenario {other}"),
    };
    let workspace_bytes = request
        .workspace
        .entries
        .iter()
        .map(|entry| entry.contents.len())
        .sum();
    let usage = ExecutorUsage {
        workspace_entries: request.workspace.entries.len(),
        workspace_bytes,
        stdout_bytes: stdout.bytes.len(),
        stderr_bytes: stderr.bytes.len(),
        event_count: events.len(),
        complete: !stdout.truncated
            && !stderr.truncated
            && !matches!(
                &status,
                ExecutionStatus::TimedOut | ExecutionStatus::Uncertain { .. }
            ),
    };
    let effects = if request.assignment_id == "effects" {
        EffectReconciliation::CandidateArtifacts {
            changed_paths: vec![
                "delete.txt".to_string(),
                "modify.txt".to_string(),
                "new.txt".to_string(),
                "newdir".to_string(),
            ],
            artifacts: vec![
                CandidateArtifact::deleted("delete.txt"),
                CandidateArtifact::file("modify.txt", b"after".to_vec(), false)
                    .expect("construct modified-file artifact fixture"),
                CandidateArtifact::file("new.txt", b"new".to_vec(), true)
                    .expect("construct new-file artifact fixture"),
                CandidateArtifact::directory("newdir"),
            ],
        }
    } else {
        EffectReconciliation::CandidateOnly {
            changed_paths: Vec::new(),
        }
    };
    RemoteExecutionReply {
        protocol: "maco-executor-v1".to_string(),
        assignment_id: request.assignment_id.clone(),
        executor_run_id: request.executor_run_id.clone(),
        host_id: request.host_id.clone(),
        semantics: ExecutionSemantics {
            status,
            stdout,
            stderr,
            usage,
            events,
            effects,
            cleanup: CleanupStatus::Complete,
        },
    }
}

fn terminal_events(cancelled: bool) -> Vec<ExecutorLifecycleEvent> {
    let mut events = vec![
        ExecutorLifecycleEvent::Validated,
        ExecutorLifecycleEvent::Staged,
        ExecutorLifecycleEvent::Launched,
    ];
    if cancelled {
        events.push(ExecutorLifecycleEvent::CancelRequested);
        events.push(ExecutorLifecycleEvent::TermSent);
    }
    events.extend([
        ExecutorLifecycleEvent::Collected,
        ExecutorLifecycleEvent::Reconciled,
        ExecutorLifecycleEvent::CleanupComplete,
    ]);
    events
}

fn longest_terminal_events(timed_out: bool) -> Vec<ExecutorLifecycleEvent> {
    vec![
        ExecutorLifecycleEvent::Validated,
        ExecutorLifecycleEvent::Staged,
        ExecutorLifecycleEvent::Launched,
        if timed_out {
            ExecutorLifecycleEvent::TimeoutExpired
        } else {
            ExecutorLifecycleEvent::CancelRequested
        },
        ExecutorLifecycleEvent::TermSent,
        ExecutorLifecycleEvent::KillSent,
        ExecutorLifecycleEvent::Collected,
        ExecutorLifecycleEvent::Reconciled,
        ExecutorLifecycleEvent::CleanupComplete,
    ]
}

fn minimum_event_capacity() -> (usize, usize) {
    let cancellation = longest_terminal_events(false);
    let timeout = longest_terminal_events(true);
    (
        cancellation.len().max(timeout.len()),
        serde_json::to_vec(&cancellation)
            .expect("measure longest cancellation lifecycle")
            .len()
            .max(
                serde_json::to_vec(&timeout)
                    .expect("measure longest timeout lifecycle")
                    .len(),
            ),
    )
}

fn empty_capture() -> CapturedOutput {
    CapturedOutput {
        bytes: Vec::new(),
        truncated: false,
    }
}

#[cfg(unix)]
#[test]
fn unchanged_semantic_suite_matches_local_and_fake_ssh() {
    struct Scenario {
        assignment_id: &'static str,
        argv: &'static [&'static str],
        cancel_after_millis: Option<u64>,
        execution_timeout_millis: Option<u64>,
    }
    let scenarios = [
        Scenario {
            assignment_id: "success",
            argv: &["/bin/sh", "-c", "printf alpha; printf beta >&2"],
            cancel_after_millis: None,
            execution_timeout_millis: None,
        },
        Scenario {
            assignment_id: "nonzero",
            argv: &["/bin/sh", "-c", "exit 7"],
            cancel_after_millis: None,
            execution_timeout_millis: None,
        },
        Scenario {
            assignment_id: "truncate-stream",
            argv: &[
                "/bin/sh",
                "-c",
                "dd if=/dev/zero bs=131072 count=1 2>/dev/null || exit 91",
            ],
            cancel_after_millis: None,
            execution_timeout_millis: None,
        },
        Scenario {
            assignment_id: "cancel-running",
            argv: &["/bin/sh", "-c", "sleep 2"],
            cancel_after_millis: Some(100),
            execution_timeout_millis: None,
        },
        Scenario {
            assignment_id: "timeout-running",
            argv: &["/bin/sh", "-c", "sleep 2"],
            cancel_after_millis: None,
            execution_timeout_millis: Some(100),
        },
    ];

    for scenario in scenarios {
        let request = ExecutorRequest {
            assignment_id: scenario.assignment_id.to_string(),
            argv: scenario
                .argv
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            working_directory: None,
        };
        let mut scenario_limits = limits();
        if let Some(timeout) = scenario.execution_timeout_millis {
            scenario_limits.execution_timeout_millis = timeout;
            scenario_limits.connect_timeout_millis = timeout;
        }
        let local = run_with_optional_cancel(
            &multi_agent_coding_orchestrator::executor::LocalExecutor,
            &request,
            scenario.cancel_after_millis,
            &scenario_limits,
        );

        let fixture = TempDir::new().expect("SSH fixture tempdir");
        let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
        let ssh = SshExecutor::with_transport(
            config_with_limits(fixture.path(), scenario_limits.clone()),
            fake.clone(),
        )
        .expect("configured fake SSH executor");
        let remote = run_with_optional_cancel(
            &ssh,
            &request,
            scenario.cancel_after_millis,
            &scenario_limits,
        );

        assert_eq!(local.kind, ExecutorKind::Local);
        assert_eq!(remote.kind, ExecutorKind::Ssh);
        assert_eq!(local.assignment_id, remote.assignment_id);
        assert_eq!(
            local.semantics, remote.semantics,
            "{}",
            scenario.assignment_id
        );
        assert_eq!(fake.calls(), 1);
        if scenario.assignment_id == "success" {
            assert_eq!(
                local.semantics.stdout.bytes.len(),
                limits().max_stdout_bytes
            );
            assert!(local.semantics.stdout.truncated);
            assert_eq!(
                local.semantics.stderr.bytes.len(),
                limits().max_stderr_bytes
            );
            assert!(!local.semantics.stderr.truncated);
            assert!(!local.semantics.usage.complete);
        }
    }
}

#[cfg(unix)]
fn run_with_optional_cancel(
    executor: &dyn BoundedExecutor,
    request: &ExecutorRequest,
    cancel_after_millis: Option<u64>,
    execution_limits: &ExecutorLimits,
) -> multi_agent_coding_orchestrator::executor::ExecutionReport {
    let cancellation = CancellationToken::new();
    let cancel_thread = cancel_after_millis.map(|delay| {
        let cancellation = cancellation.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(delay));
            cancellation.cancel();
        })
    });
    let report = executor
        .execute_bounded(request, &cancellation, execution_limits)
        .expect("bounded executor scenario");
    if let Some(cancel_thread) = cancel_thread {
        cancel_thread.join().expect("cancellation thread");
    }
    report
}

#[test]
fn compatibility_admission_is_backend_neutral_and_invalid_input_never_reaches_transport() {
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let local = multi_agent_coding_orchestrator::executor::LocalExecutor;
    let executors: [&dyn AgentExecutor; 2] = [&local, &ssh];
    let valid = ExecutorRequest {
        assignment_id: "success".to_string(),
        argv: vec!["unused".to_string()],
        working_directory: None,
    };
    let outcomes = executors
        .iter()
        .map(|executor| executor.execute(&valid).expect("valid admission"))
        .collect::<Vec<_>>();
    assert_eq!(outcomes[0].assignment_id, outcomes[1].assignment_id);
    assert_eq!(outcomes[0].status, outcomes[1].status);
    assert_eq!(outcomes[0].kind, ExecutorKind::Local);
    assert_eq!(outcomes[1].kind, ExecutorKind::Ssh);
    assert_eq!(fake.calls(), 1);

    let invalid_requests = [
        ExecutorRequest {
            assignment_id: "invalid-empty".to_string(),
            argv: Vec::new(),
            working_directory: None,
        },
        ExecutorRequest {
            assignment_id: "invalid-nul".to_string(),
            argv: vec!["tool\0argument".to_string()],
            working_directory: None,
        },
    ];
    for invalid in invalid_requests {
        for executor in executors {
            assert!(
                executor.execute(&invalid).is_err(),
                "{:?} accepted invalid argv {:?}",
                executor.kind(),
                invalid.argv
            );
        }
    }
    assert_eq!(
        fake.calls(),
        1,
        "invalid admission must not reach transport"
    );
}

#[cfg(unix)]
#[test]
fn exact_output_event_and_receipt_limits_are_accepted() {
    let (minimum_event_count, minimum_event_bytes) = minimum_event_capacity();
    let mut exact_limits = limits();
    exact_limits.max_event_count = minimum_event_count;
    exact_limits.max_event_bytes = minimum_event_bytes;
    let request = ExecutorRequest {
        assignment_id: "success".to_string(),
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf alpha; printf beta >&2".to_string(),
        ],
        working_directory: None,
    };
    let local = run_with_optional_cancel(
        &multi_agent_coding_orchestrator::executor::LocalExecutor,
        &request,
        None,
        &exact_limits,
    );
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(
        config_with_limits(fixture.path(), exact_limits.clone()),
        fake,
    )
    .expect("configured fake SSH executor");
    let remote = run_with_optional_cancel(&ssh, &request, None, &exact_limits);
    assert_eq!(local.semantics, remote.semantics);
    assert_eq!(
        remote.semantics.stdout.bytes.len(),
        exact_limits.max_stdout_bytes
    );
    assert_eq!(
        remote.semantics.stderr.bytes.len(),
        exact_limits.max_stderr_bytes
    );
    assert!(remote.semantics.events.len() <= exact_limits.max_event_count);
    assert!(
        serde_json::to_vec(&remote.semantics.events)
            .expect("measure accepted event boundary")
            .len()
            <= exact_limits.max_event_bytes
    );
    assert_eq!(exact_limits.max_event_count, minimum_event_count);
    assert_eq!(exact_limits.max_event_bytes, minimum_event_bytes);

    let fixture = TempDir::new().expect("receipt fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::ExactReceipt));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let report = ssh
        .execute_bounded(&request, &CancellationToken::new(), &limits())
        .expect("exact-bound receipt");
    assert!(matches!(
        report.semantics.status,
        ExecutionStatus::Failed { .. }
    ));
    assert_eq!(fake.calls(), 1);
}

#[cfg(unix)]
#[test]
fn insufficient_event_capacity_is_rejected_before_spawn_or_transport() {
    let (minimum_event_count, minimum_event_bytes) = minimum_event_capacity();
    let mut count_limited = limits();
    count_limited.max_event_count = minimum_event_count - 1;
    let mut byte_limited = limits();
    byte_limited.max_event_bytes = minimum_event_bytes - 1;

    for (case, execution_limits) in [("count", count_limited), ("bytes", byte_limited)] {
        let workspace = TempDir::new().expect("local event-capacity workspace");
        let marker = workspace.path().join(format!("spawned-{case}"));
        let request = ExecutorRequest {
            assignment_id: format!("event-capacity-{case}"),
            argv: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!("printf spawned > spawned-{case}"),
            ],
            working_directory: Some(workspace.path().to_path_buf()),
        };
        let error = multi_agent_coding_orchestrator::executor::LocalExecutor
            .execute_bounded(&request, &CancellationToken::new(), &execution_limits)
            .expect_err("insufficient event capacity must reject before local spawn");
        assert!(
            format!("{error:#}").contains("event"),
            "unexpected local event-capacity error: {error:#}"
        );
        assert!(!marker.exists(), "local process spawned for {case} limit");

        let fixture = TempDir::new().expect("SSH fixture tempdir");
        let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
        let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
            .expect("configured fake SSH executor");
        let error = ssh
            .execute_bounded(&request, &CancellationToken::new(), &execution_limits)
            .expect_err("insufficient event capacity must reject before SSH transport");
        assert!(
            format!("{error:#}").contains("event"),
            "unexpected SSH event-capacity error: {error:#}"
        );
        assert_eq!(fake.calls(), 0, "transport invoked for {case} limit");
    }
}

#[cfg(unix)]
#[test]
fn nonempty_workspace_staging_has_identical_typed_semantics() {
    let workspace = TempDir::new().expect("workspace tempdir");
    fs::create_dir(workspace.path().join("nested")).expect("create nested directory");
    fs::write(workspace.path().join("a.txt"), b"abc").expect("write root fixture");
    fs::write(workspace.path().join("nested/b.txt"), b"def").expect("write nested fixture");
    let request = ExecutorRequest {
        assignment_id: "workspace".to_string(),
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 0".to_string(),
        ],
        working_directory: Some(workspace.path().to_path_buf()),
    };
    let local = run_with_optional_cancel(
        &multi_agent_coding_orchestrator::executor::LocalExecutor,
        &request,
        None,
        &limits(),
    );
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let remote = run_with_optional_cancel(&ssh, &request, None, &limits());
    assert_eq!(local.semantics, remote.semantics);
    assert_eq!(remote.semantics.usage.workspace_entries, 3);
    assert_eq!(remote.semantics.usage.workspace_bytes, 6);
    assert_eq!(
        fake.request(0)
            .workspace
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["a.txt", "nested", "nested/b.txt"]
    );
}

#[cfg(unix)]
#[test]
fn workspace_mutations_have_identical_bounded_artifact_semantics() {
    let local_workspace = TempDir::new().expect("local workspace tempdir");
    let remote_workspace = TempDir::new().expect("remote workspace tempdir");
    for workspace in [&local_workspace, &remote_workspace] {
        fs::write(workspace.path().join("modify.txt"), b"before")
            .expect("write modified-file fixture");
        fs::write(workspace.path().join("delete.txt"), b"gone")
            .expect("write deleted-file fixture");
    }
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "printf after > modify.txt; printf new > new.txt; chmod 700 new.txt; rm delete.txt; mkdir newdir"
            .to_string(),
    ];
    let local_request = ExecutorRequest {
        assignment_id: "effects".to_string(),
        argv: argv.clone(),
        working_directory: Some(local_workspace.path().to_path_buf()),
    };
    let remote_request = ExecutorRequest {
        assignment_id: "effects".to_string(),
        argv,
        working_directory: Some(remote_workspace.path().to_path_buf()),
    };
    let local = run_with_optional_cancel(
        &multi_agent_coding_orchestrator::executor::LocalExecutor,
        &local_request,
        None,
        &limits(),
    );

    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let remote = run_with_optional_cancel(&ssh, &remote_request, None, &limits());

    let expected_effects = EffectReconciliation::CandidateArtifacts {
        changed_paths: vec![
            "delete.txt".to_string(),
            "modify.txt".to_string(),
            "new.txt".to_string(),
            "newdir".to_string(),
        ],
        artifacts: vec![
            CandidateArtifact::deleted("delete.txt"),
            CandidateArtifact::file("modify.txt", b"after".to_vec(), false)
                .expect("construct expected modified-file artifact"),
            CandidateArtifact::file("new.txt", b"new".to_vec(), true)
                .expect("construct expected new-file artifact"),
            CandidateArtifact::directory("newdir"),
        ],
    };
    assert_eq!(local.semantics, remote.semantics);
    assert_eq!(local.semantics.effects, expected_effects);
    assert_eq!(local.semantics.usage.workspace_entries, 2);
    assert_eq!(local.semantics.usage.workspace_bytes, 10);
    assert_eq!(fake.calls(), 1);
    assert_eq!(fake.request(0).workspace.entries.len(), 2);
}

#[derive(Clone, Copy)]
enum WorkspaceFixture<'a> {
    File(&'a [u8]),
    Directory,
}

fn populate_workspace(root: &Path, entries: &[(&str, WorkspaceFixture<'_>)]) {
    for (logical, entry) in entries {
        let path = root.join(logical);
        match entry {
            WorkspaceFixture::File(contents) => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).expect("create workspace fixture parent");
                }
                fs::write(path, contents).expect("write workspace fixture file");
            }
            WorkspaceFixture::Directory => {
                fs::create_dir_all(path).expect("create workspace fixture directory");
            }
        }
    }
}

#[cfg(unix)]
fn assert_final_workspace_rejected_for_both_backends(
    case: FinalWorkspaceCase,
    execution_limits: ExecutorLimits,
    initial: &[(&str, WorkspaceFixture<'_>)],
    command: &str,
) {
    let local_workspace = TempDir::new().expect("local final-workspace fixture");
    let remote_workspace = TempDir::new().expect("remote final-workspace fixture");
    populate_workspace(local_workspace.path(), initial);
    populate_workspace(remote_workspace.path(), initial);
    let local_request = ExecutorRequest {
        assignment_id: "workspace".to_string(),
        argv: vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()],
        working_directory: Some(local_workspace.path().to_path_buf()),
    };
    let local = multi_agent_coding_orchestrator::executor::LocalExecutor
        .execute_bounded(&local_request, &CancellationToken::new(), &execution_limits)
        .expect("local final-workspace overflow must remain typed");
    let local_recovery = match &local.semantics.status {
        ExecutionStatus::Uncertain { recovery, .. } => recovery,
        status => panic!("local final-workspace overflow was not uncertain: {status:?}"),
    };
    assert_eq!(
        local.semantics.effects,
        EffectReconciliation::Uncertain {
            recovery: local_recovery.clone(),
        }
    );
    assert_eq!(
        local.semantics.cleanup,
        CleanupStatus::Residual {
            recovery: local_recovery.clone(),
        }
    );

    assert_invalid_receipt_request(
        FakeMode::FinalWorkspace(case),
        execution_limits,
        ExecutorRequest {
            assignment_id: "workspace".to_string(),
            argv: vec!["unused".to_string()],
            working_directory: Some(remote_workspace.path().to_path_buf()),
        },
    );
}

#[cfg(unix)]
fn assert_final_workspace_accepted_with_parity(
    case: FinalWorkspaceCase,
    execution_limits: ExecutorLimits,
    initial: &[(&str, WorkspaceFixture<'_>)],
    command: &str,
) -> ExecutionSemantics {
    let local_workspace = TempDir::new().expect("local final-workspace fixture");
    let remote_workspace = TempDir::new().expect("remote final-workspace fixture");
    populate_workspace(local_workspace.path(), initial);
    populate_workspace(remote_workspace.path(), initial);
    let local_request = ExecutorRequest {
        assignment_id: "workspace".to_string(),
        argv: vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()],
        working_directory: Some(local_workspace.path().to_path_buf()),
    };
    let local = run_with_optional_cancel(
        &multi_agent_coding_orchestrator::executor::LocalExecutor,
        &local_request,
        None,
        &execution_limits,
    );
    let fixture = TempDir::new().expect("SSH final-workspace fixture");
    let fake = Arc::new(FakeTransport::new(FakeMode::FinalWorkspace(case)));
    let ssh = SshExecutor::with_transport(
        config_with_limits(fixture.path(), execution_limits.clone()),
        fake.clone(),
    )
    .expect("configured final-workspace fake SSH executor");
    let remote = run_with_optional_cancel(
        &ssh,
        &ExecutorRequest {
            assignment_id: "workspace".to_string(),
            argv: vec!["unused".to_string()],
            working_directory: Some(remote_workspace.path().to_path_buf()),
        },
        None,
        &execution_limits,
    );
    assert_eq!(local.semantics, remote.semantics);
    assert_eq!(fake.calls(), 1);
    local.semantics
}

#[cfg(unix)]
#[test]
fn final_workspace_overflow_is_typed_for_local_and_remote_without_replay() {
    let mut entry_limits = limits();
    entry_limits.max_workspace_entries = 2;
    entry_limits.max_workspace_bytes = 16;
    entry_limits.max_file_bytes = 8;
    let entry_full = [
        ("a.txt", WorkspaceFixture::File(&b"a"[..])),
        ("b.txt", WorkspaceFixture::File(&b"b"[..])),
    ];
    assert_final_workspace_rejected_for_both_backends(
        FinalWorkspaceCase::AddFileBeyondEntries,
        entry_limits.clone(),
        &entry_full,
        "printf x > new-file",
    );
    assert_final_workspace_rejected_for_both_backends(
        FinalWorkspaceCase::AddDirectoryBeyondEntries,
        entry_limits,
        &entry_full,
        "mkdir new-directory",
    );

    let mut byte_limits = limits();
    byte_limits.max_workspace_entries = 4;
    byte_limits.max_workspace_bytes = 10;
    byte_limits.max_file_bytes = 10;
    assert_final_workspace_rejected_for_both_backends(
        FinalWorkspaceCase::AddFileBeyondBytes,
        byte_limits.clone(),
        &[("full.txt", WorkspaceFixture::File(&b"1234567890"[..]))],
        "printf x > new-file",
    );
    assert_final_workspace_rejected_for_both_backends(
        FinalWorkspaceCase::ModifyBeyondAggregate,
        byte_limits,
        &[
            ("grow.txt", WorkspaceFixture::File(&b"12345"[..])),
            ("keep.txt", WorkspaceFixture::File(&b"67890"[..])),
        ],
        "printf 123456 > grow.txt",
    );

    let mut file_limits = limits();
    file_limits.max_workspace_entries = 2;
    file_limits.max_workspace_bytes = 10;
    file_limits.max_file_bytes = 5;
    assert_final_workspace_rejected_for_both_backends(
        FinalWorkspaceCase::ModifyBeyondPerFile,
        file_limits,
        &[("grow.txt", WorkspaceFixture::File(&b"12345"[..]))],
        "printf 123456 > grow.txt",
    );
}

#[cfg(unix)]
#[test]
fn capacity_release_type_replacement_and_exact_final_limits_preserve_parity() {
    let mut replacement_limits = limits();
    replacement_limits.max_workspace_entries = 2;
    replacement_limits.max_workspace_bytes = 10;
    replacement_limits.max_file_bytes = 6;
    let released = assert_final_workspace_accepted_with_parity(
        FinalWorkspaceCase::DeleteThenCreate,
        replacement_limits,
        &[
            ("keep.txt", WorkspaceFixture::File(&b"keep"[..])),
            ("old.txt", WorkspaceFixture::File(&b"123456"[..])),
        ],
        "rm old.txt; printf 123456 > new.txt",
    );
    assert_eq!(released.status, ExecutionStatus::Exited { code: Some(0) });
    assert!(matches!(
        released.effects,
        EffectReconciliation::CandidateArtifacts { .. }
    ));

    let mut type_limits = limits();
    type_limits.max_workspace_entries = 2;
    type_limits.max_workspace_bytes = 2;
    type_limits.max_file_bytes = 2;
    let replaced = assert_final_workspace_accepted_with_parity(
        FinalWorkspaceCase::ReplaceEntryTypes,
        type_limits,
        &[
            ("dir-node", WorkspaceFixture::Directory),
            ("file-node", WorkspaceFixture::File(&b"x"[..])),
        ],
        "rmdir dir-node; printf xy > dir-node; rm file-node; mkdir file-node",
    );
    assert_eq!(replaced.status, ExecutionStatus::Exited { code: Some(0) });
    assert!(matches!(
        replaced.effects,
        EffectReconciliation::CandidateArtifacts { .. }
    ));

    let mut exact_limits = limits();
    exact_limits.max_workspace_entries = 3;
    exact_limits.max_workspace_bytes = 10;
    exact_limits.max_file_bytes = 6;
    let exact = assert_final_workspace_accepted_with_parity(
        FinalWorkspaceCase::ExactFinalLimits,
        exact_limits,
        &[("base.txt", WorkspaceFixture::File(&b"base"[..]))],
        "mkdir added-dir; printf 123456 > added-file",
    );
    assert_eq!(exact.status, ExecutionStatus::Exited { code: Some(0) });
    assert_eq!(exact.usage.workspace_entries, 1);
    assert_eq!(exact.usage.workspace_bytes, 4);
    assert!(matches!(
        exact.effects,
        EffectReconciliation::CandidateArtifacts { .. }
    ));
}

#[test]
fn directory_delete_or_retype_cannot_orphan_existing_children() {
    for case in [
        FinalWorkspaceCase::DeleteDirectoryWithChild,
        FinalWorkspaceCase::RetypeDirectoryWithChild,
    ] {
        let workspace = TempDir::new().expect("directory-child workspace fixture");
        populate_workspace(
            workspace.path(),
            &[
                ("tree", WorkspaceFixture::Directory),
                ("tree/child.txt", WorkspaceFixture::File(&b"child"[..])),
            ],
        );
        assert_invalid_receipt_request(
            FakeMode::FinalWorkspace(case),
            limits(),
            ExecutorRequest {
                assignment_id: "workspace".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: Some(workspace.path().to_path_buf()),
            },
        );
    }
}

#[cfg(unix)]
#[test]
fn local_post_execution_file_limit_plus_one_is_typed_uncertain() {
    let workspace = TempDir::new().expect("workspace tempdir");
    let execution_limits = limits();
    let oversized_bytes = execution_limits.max_file_bytes + 1;
    let request = ExecutorRequest {
        assignment_id: "local-post-limit".to_string(),
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("dd if=/dev/zero of=oversized.bin bs={oversized_bytes} count=1 2>/dev/null"),
        ],
        working_directory: Some(workspace.path().to_path_buf()),
    };
    let report = multi_agent_coding_orchestrator::executor::LocalExecutor
        .execute_bounded(&request, &CancellationToken::new(), &execution_limits)
        .expect("post-execution reconciliation failure must remain typed");
    let recovery = match &report.semantics.status {
        ExecutionStatus::Uncertain { recovery, .. } => recovery,
        status => panic!("post-execution limit+1 must be uncertain, got {status:?}"),
    };
    assert_eq!(recovery.assignment_id, request.assignment_id);
    assert_eq!(recovery.host_id, "local");
    assert!(recovery.staged_input_digest.starts_with("sha256:"));
    assert!(!recovery.has_authenticated_process_identity());
    assert_eq!(
        recovery.workspace,
        workspace.path().to_string_lossy().to_string()
    );
    assert_eq!(
        report.semantics.effects,
        EffectReconciliation::Uncertain {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.cleanup,
        CleanupStatus::Residual {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.events.last(),
        Some(&ExecutorLifecycleEvent::CleanupResidual)
    );
    assert!(!report.semantics.usage.complete);
}

#[test]
fn cancellation_before_launch_is_identical_and_never_calls_transport() {
    let request = ExecutorRequest {
        assignment_id: "cancel-before".to_string(),
        argv: vec!["unused".to_string()],
        working_directory: None,
    };
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let local = multi_agent_coding_orchestrator::executor::LocalExecutor
        .execute_bounded(&request, &cancellation, &limits())
        .expect("local pre-launch cancellation");

    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let remote = ssh
        .execute_bounded(&request, &cancellation, &limits())
        .expect("remote pre-launch cancellation");
    assert_eq!(local.semantics, remote.semantics);
    assert_eq!(fake.calls(), 0);
}

#[cfg(unix)]
#[test]
fn local_cancellation_contains_term_ignoring_descendants() {
    let workspace = TempDir::new().expect("cancellation workspace");
    let marker = workspace.path().join("leaked");
    let request = ExecutorRequest {
        assignment_id: "contain-cancel".to_string(),
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "trap '' TERM; (trap '' TERM; sleep 1; printf leaked > leaked) & wait".to_string(),
        ],
        working_directory: Some(workspace.path().to_path_buf()),
    };
    let report = run_with_optional_cancel(
        &multi_agent_coding_orchestrator::executor::LocalExecutor,
        &request,
        Some(100),
        &limits(),
    );
    assert_eq!(report.semantics.status, ExecutionStatus::Cancelled);
    assert_eq!(report.semantics.cleanup, CleanupStatus::Complete);
    assert!(
        report
            .semantics
            .events
            .contains(&ExecutorLifecycleEvent::KillSent),
        "TERM-ignoring process group should require bounded KILL cleanup"
    );
    thread::sleep(Duration::from_millis(1_100));
    assert!(
        !marker.exists(),
        "a cancelled descendant survived long enough to mutate the workspace"
    );
}

#[cfg(unix)]
#[test]
fn local_cancellation_does_not_treat_direct_child_exit_as_group_cleanup() {
    let workspace = TempDir::new().expect("cancellation workspace");
    let marker = workspace.path().join("leaked");
    let request = ExecutorRequest {
        assignment_id: "contain-cancel-child-exit".to_string(),
        argv: vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "trap 'exit 0' TERM; (trap '' TERM; sleep 1; printf leaked > leaked) & wait"
                .to_string(),
        ],
        working_directory: Some(workspace.path().to_path_buf()),
    };
    let report = run_with_optional_cancel(
        &multi_agent_coding_orchestrator::executor::LocalExecutor,
        &request,
        Some(100),
        &limits(),
    );
    assert_eq!(report.semantics.status, ExecutionStatus::Cancelled);
    assert_eq!(report.semantics.cleanup, CleanupStatus::Complete);
    thread::sleep(Duration::from_millis(1_100));
    assert!(
        !marker.exists(),
        "direct-child exit was mistaken for process-group cleanup"
    );
}

#[test]
fn host_only_constructor_and_invalid_trust_fail_before_transport() {
    let request = ExecutorRequest {
        assignment_id: "closed".to_string(),
        argv: vec!["unused".to_string()],
        working_directory: None,
    };
    let executor = SshExecutor::new("host-only").expect("host-only seam");
    let error = executor
        .execute(&request)
        .expect_err("host-only constructor must stay closed");
    assert!(error.to_string().contains("explicit authentication"));

    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let (identity_file, known_hosts_file) = write_trust_files(fixture.path());
    let missing = SshConfig::new(SshConfigInput {
        identity_file: fixture.path().join("missing"),
        known_hosts_file,
        host_id: "fixture-host".to_string(),
        host: "127.0.0.1".to_string(),
        user: "runner".to_string(),
        port: 22,
        remote_root: "/var/tmp/maco".to_string(),
        helper_path: "/usr/libexec/maco-helper".to_string(),
        limits: limits(),
    })
    .expect_err("missing identity must fail");
    assert!(missing.to_string().contains("identity_file"));

    #[cfg(unix)]
    {
        let link = fixture.path().join("identity-link");
        std::os::unix::fs::symlink(identity_file, &link).expect("create identity symlink");
        let (_, known_hosts_file) = write_trust_files(fixture.path());
        let error = SshConfig::new(SshConfigInput {
            host_id: "fixture-host".to_string(),
            host: "127.0.0.1".to_string(),
            user: "runner".to_string(),
            port: 22,
            identity_file: link,
            known_hosts_file,
            remote_root: "/var/tmp/maco".to_string(),
            helper_path: "/usr/libexec/maco-helper".to_string(),
            limits: limits(),
        })
        .expect_err("symlink identity must fail");
        assert!(error.to_string().contains("non-symlink"));
    }
}

#[cfg(unix)]
#[test]
fn trust_files_reject_symlinks_mutable_known_hosts_and_openssh_expansion_tokens() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let (identity_file, known_hosts_file) = write_trust_files(fixture.path());
    let base = SshConfigInput {
        host_id: "fixture-host".to_string(),
        host: "127.0.0.1".to_string(),
        user: "runner".to_string(),
        port: 22,
        identity_file: identity_file.clone(),
        known_hosts_file: known_hosts_file.clone(),
        remote_root: "/var/tmp/maco".to_string(),
        helper_path: "/usr/libexec/maco-helper".to_string(),
        limits: limits(),
    };

    let known_hosts_link = fixture.path().join("known-hosts-link");
    std::os::unix::fs::symlink(&known_hosts_file, &known_hosts_link)
        .expect("create known-hosts symlink");
    let mut symlinked = base.clone();
    symlinked.known_hosts_file = known_hosts_link;
    assert!(SshConfig::new(symlinked)
        .expect_err("known-hosts symlink must fail")
        .to_string()
        .contains("non-symlink"));

    fs::set_permissions(&known_hosts_file, fs::Permissions::from_mode(0o666))
        .expect("make known-hosts fixture mutable");
    assert!(SshConfig::new(base.clone())
        .expect_err("mutable known-hosts file must fail")
        .to_string()
        .contains("known_hosts_file"));
    fs::set_permissions(&known_hosts_file, fs::Permissions::from_mode(0o600))
        .expect("restore known-hosts fixture permissions");

    let expanding_known_hosts = fixture.path().join("known-%h");
    fs::write(&expanding_known_hosts, b"host ssh-ed25519 test-only-key\n")
        .expect("write expansion-token fixture");
    let mut expanding = base;
    expanding.known_hosts_file = expanding_known_hosts;
    assert!(SshConfig::new(expanding)
        .expect_err("OpenSSH path expansion tokens must fail")
        .to_string()
        .contains("known_hosts_file"));
}

#[cfg(unix)]
#[test]
fn openssh_trust_snapshot_failures_preserve_distinct_typed_classification() {
    use std::os::unix::fs::PermissionsExt;

    for (field, expected_kind) in [
        ("identity", TransportFailureKind::Authentication),
        ("known-hosts", TransportFailureKind::HostKey),
    ] {
        let fixture = TempDir::new().expect("OpenSSH trust-snapshot fixture");
        let marker = fixture.path().join("invoked");
        let fake_ssh = fixture.path().join("fake-ssh");
        fs::write(
            &fake_ssh,
            format!("#!/bin/sh\nprintf invoked > '{}'\n", marker.display()),
        )
        .expect("write trust-snapshot fake OpenSSH executable");
        fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700))
            .expect("make trust-snapshot fixture runnable");
        let config = config(fixture.path());
        let invalidated_path = if field == "identity" {
            config.identity_file().to_path_buf()
        } else {
            config.known_hosts_file().to_path_buf()
        };
        let ssh = SshExecutor::with_openssh(config, fake_ssh)
            .expect("configure trust-snapshot OpenSSH executor");
        fs::remove_file(invalidated_path).expect("invalidate configured trust snapshot input");

        let report = ssh
            .execute_bounded(
                &ExecutorRequest {
                    assignment_id: format!("trust-snapshot-{field}"),
                    argv: vec!["unused".to_string()],
                    working_directory: None,
                },
                &CancellationToken::new(),
                &limits(),
            )
            .expect("trust snapshot failure must remain typed");
        assert!(matches!(
            report.semantics.status,
            ExecutionStatus::TransportFailed {
                stage: TransportStage::Preflight,
                kind,
                recovery: None,
                ..
            } if kind == expected_kind
        ));
        assert_eq!(report.semantics.cleanup, CleanupStatus::NotStarted);
        assert_eq!(
            report.semantics.events,
            vec![ExecutorLifecycleEvent::Validated]
        );
        assert!(!marker.exists(), "invalid {field} trust spawned transport");
    }
}

#[test]
fn configuration_rejects_option_shaped_and_shell_shaped_values() {
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let (identity_file, known_hosts_file) = write_trust_files(fixture.path());
    let base = SshConfigInput {
        host_id: "fixture-host".to_string(),
        host: "-ProxyCommand=evil".to_string(),
        user: "runner".to_string(),
        port: 22,
        identity_file: identity_file.clone(),
        known_hosts_file: known_hosts_file.clone(),
        remote_root: "/var/tmp/maco".to_string(),
        helper_path: "/usr/libexec/maco-helper".to_string(),
        limits: limits(),
    };
    assert!(SshConfig::new(base).is_err());
    assert!(SshConfig::new(SshConfigInput {
        host: "host".to_string(),
        user: "-oProxyCommand".to_string(),
        host_id: "fixture-host".to_string(),
        port: 22,
        identity_file: identity_file.clone(),
        known_hosts_file: known_hosts_file.clone(),
        remote_root: "/var/tmp/maco".to_string(),
        helper_path: "/usr/libexec/maco-helper".to_string(),
        limits: limits(),
    })
    .is_err());
    assert!(SshConfig::new(SshConfigInput {
        host: "host".to_string(),
        user: "runner".to_string(),
        host_id: "fixture-host".to_string(),
        port: 22,
        identity_file,
        known_hosts_file,
        remote_root: "/var/tmp/maco".to_string(),
        helper_path: "/usr/libexec/helper;touch-pwned".to_string(),
        limits: limits(),
    })
    .is_err());
    assert!(SshConfig::new(SshConfigInput {
        host: "host".to_string(),
        user: "runner".to_string(),
        host_id: "fixture-host".to_string(),
        port: 22,
        identity_file: fixture.path().join("identity"),
        known_hosts_file: fixture.path().join("known_hosts"),
        remote_root: "/".to_string(),
        helper_path: "/usr/libexec/maco-helper".to_string(),
        limits: limits(),
    })
    .is_err());
}

#[cfg(unix)]
#[test]
fn openssh_argv_disables_ambient_auth_trust_and_forwarding() {
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let config = config(fixture.path());
    let executable = std::env::current_exe().expect("resolve current test executable");
    let transport = OpenSshTransport::new(executable).expect("explicit executable fixture");
    let arguments: Vec<String> = transport
        .command_arguments(&config)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let joined = arguments.join("\n");
    for required in [
        "BatchMode=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "StrictHostKeyChecking=yes",
        "VerifyHostKeyDNS=no",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "PermitLocalCommand=no",
        "ProxyCommand=none",
        "ProxyJump=none",
        "ConnectTimeout=1",
        "ConnectionAttempts=1",
    ] {
        assert!(joined.contains(required), "missing {required}: {joined}");
    }
    assert!(joined.contains("UserKnownHostsFile="));
    assert!(joined.contains("GlobalKnownHostsFile=/dev/null"));
    assert_eq!(
        arguments.last().expect("helper argument"),
        config.helper_path()
    );
    assert_eq!(
        arguments
            .iter()
            .filter(|argument| argument.as_str() == config.helper_path())
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn openssh_transport_execution_timeout_is_bounded_without_network() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = TempDir::new().expect("OpenSSH timeout fixture");
    let fake_ssh = fixture.path().join("fake-ssh");
    fs::write(&fake_ssh, b"#!/bin/sh\ntrap '' TERM\nwhile :; do :; done\n")
        .expect("write fake OpenSSH executable");
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700))
        .expect("make fake OpenSSH executable runnable");
    let mut timeout_limits = limits();
    timeout_limits.connect_timeout_millis = 100;
    timeout_limits.execution_timeout_millis = 100;
    timeout_limits.cancellation_grace_millis = 100;
    let ssh = SshExecutor::with_openssh(
        config_with_limits(fixture.path(), timeout_limits.clone()),
        fake_ssh,
    )
    .expect("configured production OpenSSH transport");
    let started = Instant::now();
    let report = ssh
        .execute_bounded(
            &ExecutorRequest {
                assignment_id: "timeout-openssh".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: None,
            },
            &CancellationToken::new(),
            &timeout_limits,
        )
        .expect("bounded OpenSSH timeout outcome");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "production transport ignored its execution deadline"
    );
    let ExecutionStatus::TransportFailed {
        stage: TransportStage::Control,
        kind: TransportFailureKind::TimedOut,
        reason,
        recovery: Some(recovery),
    } = report.semantics.status
    else {
        panic!("transport timeout must preserve an uncertain recovery target")
    };
    assert!(
        reason.contains("deadline"),
        "unexpected timeout reason: {reason}"
    );
    assert_eq!(recovery.host_id, "fixture-host");
    assert!(recovery.workspace.starts_with("/var/tmp/maco-executor/"));
    assert!(recovery.staged_input_digest.starts_with("sha256:"));
    assert!(!recovery.has_authenticated_process_identity());
    assert!(matches!(
        report.semantics.cleanup,
        CleanupStatus::Residual { .. }
    ));
}

#[cfg(unix)]
#[test]
fn openssh_pipe_holding_descendant_cleanup_is_bounded_and_typed_without_network() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;

    let fixture = TempDir::new().expect("OpenSSH descendant fixture");
    let fake_ssh = fixture.path().join("fake-ssh-descendant");
    let process_group_file = fixture.path().join("process-group");
    let process_group_path = process_group_file.to_string_lossy();
    assert!(!process_group_path.contains('\''));
    fs::write(
        &fake_ssh,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$$\" > '{process_group_path}'\n(\n  trap '' TERM\n  while :; do sleep 1; done\n) &\nexit 0\n"
        ),
    )
    .expect("write descendant-holding OpenSSH fixture");
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700))
        .expect("make descendant-holding fixture runnable");
    let mut cleanup_limits = limits();
    cleanup_limits.connect_timeout_millis = 100;
    cleanup_limits.execution_timeout_millis = 100;
    cleanup_limits.cancellation_grace_millis = 100;
    let ssh = SshExecutor::with_openssh(
        config_with_limits(fixture.path(), cleanup_limits.clone()),
        fake_ssh,
    )
    .expect("configured fake-executable OpenSSH transport");

    let guard_done = Arc::new(AtomicBool::new(false));
    let guard = {
        let guard_done = guard_done.clone();
        let process_group_file = process_group_file.clone();
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !guard_done.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if guard_done.load(Ordering::Acquire) {
                return;
            }
            let Ok(raw) = fs::read_to_string(process_group_file) else {
                return;
            };
            let Ok(process_group) = raw.trim().parse::<i32>() else {
                return;
            };
            // SAFETY: the fixture records the isolated process-group leader
            // created by OpenSshTransport; this watchdog runs only if the
            // bounded operation itself failed to return within three seconds.
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
        })
    };
    let started = Instant::now();
    let report = ssh
        .execute_bounded(
            &ExecutorRequest {
                assignment_id: "openssh-descendant-cleanup".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: None,
            },
            &CancellationToken::new(),
            &cleanup_limits,
        )
        .expect("pipe-holding descendant failure must remain typed");
    guard_done.store(true, Ordering::Release);
    guard.join().expect("descendant fixture watchdog");
    let process_group = fs::read_to_string(&process_group_file)
        .expect("read descendant process-group fixture")
        .trim()
        .parse::<i32>()
        .expect("parse descendant process-group fixture");
    let absence_deadline = Instant::now() + Duration::from_millis(500);
    loop {
        // SAFETY: signal zero only observes the isolated fixture group.
        let present = unsafe { libc::kill(-process_group, 0) } == 0;
        if !present {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH),
                "could not prove fixture process-group absence"
            );
            break;
        }
        if Instant::now() >= absence_deadline {
            // SAFETY: cleanup after a failed assertion remains scoped to the
            // recorded isolated fixture process group.
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
            panic!("OpenSSH transport returned with a live fixture process group");
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "pipe-holding OpenSSH descendant exceeded its finite cleanup bound"
    );
    let recovery = match &report.semantics.status {
        ExecutionStatus::TransportFailed {
            stage: TransportStage::Cleanup,
            recovery: Some(recovery),
            ..
        } => recovery,
        status => panic!("descendant cleanup must be uncertain, got {status:?}"),
    };
    assert_eq!(
        report.semantics.effects,
        EffectReconciliation::Uncertain {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.cleanup,
        CleanupStatus::Residual {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.events.last(),
        Some(&ExecutorLifecycleEvent::CleanupResidual)
    );
}

#[cfg(unix)]
#[test]
fn openssh_escaped_pipe_holder_is_bounded_and_typed_without_network() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::AtomicBool;

    let fixture = TempDir::new().expect("OpenSSH escaped-descendant fixture");
    let fake_ssh = fixture.path().join("fake-ssh-escaped-descendant");
    let escaped_group_file = fixture.path().join("escaped-process-group");
    let escaped_group_path = escaped_group_file.to_string_lossy();
    assert!(!escaped_group_path.contains('\''));
    fs::write(
        &fake_ssh,
        format!(
            "#!/bin/sh\nsetsid /bin/sh -c 'trap \"\" TERM; while :; do sleep 1; done' &\nprintf '%s\\n' \"$!\" > '{escaped_group_path}'\nexit 0\n"
        ),
    )
    .expect("write escaped descendant OpenSSH fixture");
    fs::set_permissions(&fake_ssh, fs::Permissions::from_mode(0o700))
        .expect("make escaped descendant fixture runnable");
    let mut cleanup_limits = limits();
    cleanup_limits.connect_timeout_millis = 100;
    cleanup_limits.execution_timeout_millis = 100;
    cleanup_limits.cancellation_grace_millis = 100;
    let ssh = SshExecutor::with_openssh(
        config_with_limits(fixture.path(), cleanup_limits.clone()),
        fake_ssh,
    )
    .expect("configured escaped-descendant OpenSSH transport");

    let guard_done = Arc::new(AtomicBool::new(false));
    let guard = {
        let guard_done = guard_done.clone();
        let escaped_group_file = escaped_group_file.clone();
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while !guard_done.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if guard_done.load(Ordering::Acquire) {
                return;
            }
            let Ok(raw) = fs::read_to_string(escaped_group_file) else {
                return;
            };
            let Ok(process_group) = raw.trim().parse::<i32>() else {
                return;
            };
            // SAFETY: watchdog cleanup is scoped to the deliberately escaped
            // process group recorded by this test fixture.
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
        })
    };
    let started = Instant::now();
    let report = ssh
        .execute_bounded(
            &ExecutorRequest {
                assignment_id: "openssh-escaped-descendant".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: None,
            },
            &CancellationToken::new(),
            &cleanup_limits,
        )
        .expect("escaped pipe-holder failure must remain typed");
    guard_done.store(true, Ordering::Release);
    guard.join().expect("escaped descendant fixture watchdog");
    let escaped_group = fs::read_to_string(&escaped_group_file)
        .expect("read escaped process-group fixture")
        .trim()
        .parse::<i32>()
        .expect("parse escaped process-group fixture");
    // SAFETY: the escaped fixture cannot be controlled by OpenSshTransport;
    // explicit test teardown targets only its recorded session leader.
    unsafe {
        libc::kill(-escaped_group, libc::SIGKILL);
    }

    assert!(
        started.elapsed() < Duration::from_secs(2),
        "escaped pipe-holding descendant exceeded the transport bound"
    );
    let recovery = match &report.semantics.status {
        ExecutionStatus::TransportFailed {
            stage: TransportStage::Cleanup,
            kind: TransportFailureKind::Io,
            recovery: Some(recovery),
            ..
        } => recovery,
        status => panic!("escaped descendant must yield typed cleanup uncertainty: {status:?}"),
    };
    assert!(!recovery.has_authenticated_process_identity());
    assert_eq!(
        report.semantics.effects,
        EffectReconciliation::Uncertain {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.cleanup,
        CleanupStatus::Residual {
            recovery: recovery.clone(),
        }
    );
}

#[test]
fn arbitrary_argv_is_preserved_only_in_the_framed_request() {
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let argv = vec![
        "tool".to_string(),
        "space value".to_string(),
        "'\";$()`\n雪".to_string(),
        "--leading-option".to_string(),
    ];
    let request = ExecutorRequest {
        assignment_id: "success".to_string(),
        argv: argv.clone(),
        working_directory: None,
    };
    ssh.execute_bounded(&request, &CancellationToken::new(), &limits())
        .expect("fake SSH execution");
    assert_eq!(fake.request(0).argv, argv);
}

#[test]
fn oversized_serialized_request_is_rejected_before_transport() {
    let mut request_limits = limits();
    request_limits.max_request_bytes = 1;
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(
        config_with_limits(fixture.path(), request_limits.clone()),
        fake.clone(),
    )
    .expect("configured fake SSH executor");
    let error = ssh
        .execute_bounded(
            &ExecutorRequest {
                assignment_id: "success".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: None,
            },
            &CancellationToken::new(),
            &request_limits,
        )
        .expect_err("oversized serialized request must fail before transport");
    assert!(format!("{error:#}").contains("request"));
    assert_eq!(fake.calls(), 0);
}

#[cfg(unix)]
#[test]
fn workspace_staging_rejects_links_special_files_and_symlink_roots_for_both_backends() {
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let workspace = TempDir::new().expect("workspace tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let assert_rejected = |working_directory: &Path, expected: &str| {
        let request = ExecutorRequest {
            assignment_id: "success".to_string(),
            argv: vec!["unused".to_string()],
            working_directory: Some(working_directory.to_path_buf()),
        };
        let local_error = multi_agent_coding_orchestrator::executor::LocalExecutor
            .execute_bounded(&request, &CancellationToken::new(), &limits())
            .expect_err("unsafe local workspace must fail staging");
        assert!(
            format!("{local_error:#}").contains(expected),
            "unexpected local staging error: {local_error:#}"
        );
        let remote_error = ssh
            .execute_bounded(&request, &CancellationToken::new(), &limits())
            .expect_err("unsafe remote workspace must fail staging");
        assert!(
            format!("{remote_error:#}").contains(expected),
            "unexpected remote staging error: {remote_error:#}"
        );
        assert_eq!(fake.calls(), 0, "unsafe staging must precede transport");
    };

    let file = workspace.path().join("file");
    fs::write(&file, b"content").expect("write workspace file");
    let hardlink = workspace.path().join("hardlink");
    fs::hard_link(&file, &hardlink).expect("create hard link");
    assert_rejected(workspace.path(), "hard-linked");

    fs::remove_file(hardlink).expect("remove hard-link fixture");
    fs::remove_file(file).expect("remove original fixture");
    let nested_link = workspace.path().join("link");
    std::os::unix::fs::symlink("missing", &nested_link).expect("create symlink fixture");
    assert_rejected(workspace.path(), "symlink");
    fs::remove_file(nested_link).expect("remove symlink fixture");

    let socket_path = workspace.path().join("socket");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket_path).expect("create special-file fixture");
    assert_rejected(workspace.path(), "not a regular file or directory");
    drop(listener);

    let root_parent = TempDir::new().expect("symlink-root parent");
    let actual_root = root_parent.path().join("actual");
    fs::create_dir(&actual_root).expect("create actual root");
    let linked_root = root_parent.path().join("linked");
    std::os::unix::fs::symlink(&actual_root, &linked_root).expect("create root symlink");
    assert_rejected(&linked_root, "non-symlink directory");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_working_directory_staging_is_explicitly_fail_closed() {
    let workspace = TempDir::new().expect("non-Linux workspace fixture");
    fs::write(workspace.path().join("input.txt"), b"candidate")
        .expect("write non-Linux workspace fixture");
    let request = ExecutorRequest {
        assignment_id: "non-linux-workspace".to_string(),
        argv: vec!["unused".to_string()],
        working_directory: Some(workspace.path().to_path_buf()),
    };
    let local_error = multi_agent_coding_orchestrator::executor::LocalExecutor
        .execute_bounded(&request, &CancellationToken::new(), &limits())
        .expect_err("non-Linux local workspace staging must fail closed");
    assert!(format!("{local_error:#}").contains("requires Linux"));

    let fixture = TempDir::new().expect("non-Linux SSH fixture");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured non-Linux fake SSH executor");
    let remote_error = ssh
        .execute_bounded(&request, &CancellationToken::new(), &limits())
        .expect_err("non-Linux remote workspace staging must fail closed");
    assert!(format!("{remote_error:#}").contains("requires Linux"));
    assert_eq!(fake.calls(), 0);
}

#[test]
fn transport_failures_and_invalid_receipts_are_typed_without_replay() {
    let (preflight, fake) = execute_fake(FakeMode::PreflightFailure, limits());
    assert!(matches!(
        preflight.semantics.status,
        ExecutionStatus::TransportFailed {
            stage: TransportStage::Preflight,
            kind: TransportFailureKind::Authentication,
            recovery: None,
            ..
        }
    ));
    assert_eq!(
        preflight.semantics.events,
        vec![ExecutorLifecycleEvent::Validated]
    );
    assert_eq!(preflight.semantics.cleanup, CleanupStatus::NotStarted);
    assert!(matches!(
        preflight.semantics.effects,
        EffectReconciliation::CandidateOnly { .. }
    ));
    assert_eq!(fake.calls(), 1);

    let (launch, fake) = execute_fake(FakeMode::LaunchLoss, limits());
    assert!(matches!(
        launch.semantics.status,
        ExecutionStatus::TransportFailed {
            stage: TransportStage::Launch,
            kind: TransportFailureKind::Io,
            recovery: Some(_),
            ..
        }
    ));
    assert_eq!(fake.calls(), 1);
    for mode in [
        FakeMode::OversizedReceipt,
        FakeMode::OversizedStdout,
        FakeMode::OversizedStderr,
        FakeMode::OversizedEvents,
        FakeMode::UsageMismatch,
        FakeMode::WrongIdentity,
        FakeMode::WrongRecoveryIdentity,
        FakeMode::WrongRecoveryDigest,
        FakeMode::InvalidRecoveryProcess,
        FakeMode::MismatchedRecoveryTargets,
        FakeMode::MismatchedRecoveryProcesses,
        FakeMode::IncoherentUsage,
        FakeMode::IncoherentCleanupEvent,
        FakeMode::CancelledWithoutProof,
        FakeMode::TimedOutWithoutProof,
        FakeMode::ArtifactDigestMismatch,
        FakeMode::ArtifactPathSetMismatch,
        FakeMode::ArtifactPathEscape,
        FakeMode::OversizedArtifact,
    ] {
        assert_invalid_receipt(mode, limits());
    }
}

#[test]
fn hostile_lifecycle_receipts_are_rejected_without_replay() {
    for forgery in [
        LifecycleForgery::ExitedMissingReconciled,
        LifecycleForgery::ExitedDuplicateCollected,
        LifecycleForgery::ExitedStageLaunchOutOfOrder,
        LifecycleForgery::CancelledMissingRequest,
        LifecycleForgery::CancelledControlOutOfOrder,
        LifecycleForgery::TimedOutMissingTerm,
        LifecycleForgery::TimedOutControlOutOfOrder,
        LifecycleForgery::UncertainMissingCleanupResidual,
        LifecycleForgery::UncertainCleanupNotTerminal,
        LifecycleForgery::ReconciledMissingCollected,
        LifecycleForgery::CleanupCompleteNotTerminal,
        LifecycleForgery::FailedMissingCollectionAndReconciliation,
    ] {
        assert_invalid_receipt(FakeMode::HostileLifecycle(forgery), limits());
    }
}

#[test]
fn every_transport_stage_and_kind_is_typed_and_event_bounded_without_replay() {
    let (minimum_event_count, minimum_event_bytes) = minimum_event_capacity();
    let mut exact_limits = limits();
    exact_limits.max_event_count = minimum_event_count;
    exact_limits.max_event_bytes = minimum_event_bytes;
    let stages = [
        TransportStage::Preflight,
        TransportStage::Stage,
        TransportStage::Launch,
        TransportStage::Control,
        TransportStage::Collect,
        TransportStage::Cleanup,
    ];
    let kinds = [
        TransportFailureKind::Authentication,
        TransportFailureKind::HostKey,
        TransportFailureKind::Io,
        TransportFailureKind::Protocol,
        TransportFailureKind::Cancelled,
        TransportFailureKind::TimedOut,
        TransportFailureKind::TransportRejected,
    ];

    for stage in stages {
        for kind in kinds {
            let (report, fake) = execute_fake(
                FakeMode::TransportFailure(stage, kind),
                exact_limits.clone(),
            );
            let (actual_stage, actual_kind, recovery) = match &report.semantics.status {
                ExecutionStatus::TransportFailed {
                    stage,
                    kind,
                    recovery,
                    ..
                } => (*stage, *kind, recovery),
                status => panic!("{stage:?}/{kind:?} lost typed transport evidence: {status:?}"),
            };
            assert_eq!(actual_stage, stage);
            assert_eq!(actual_kind, kind);
            assert!(report.semantics.events.len() <= exact_limits.max_event_count);
            assert!(
                serde_json::to_vec(&report.semantics.events)
                    .expect("measure synthesized transport lifecycle")
                    .len()
                    <= exact_limits.max_event_bytes
            );
            if stage == TransportStage::Preflight {
                assert_eq!(recovery, &None);
                assert_eq!(report.semantics.cleanup, CleanupStatus::NotStarted);
                assert!(matches!(
                    report.semantics.effects,
                    EffectReconciliation::CandidateOnly { .. }
                ));
            } else {
                let expected = recovery_target(&fake.request(0));
                assert!(
                    !expected.has_authenticated_process_identity(),
                    "locally synthesized transport failure overclaimed process identity"
                );
                assert_eq!(recovery, &Some(expected.clone()));
                assert_eq!(
                    report.semantics.effects,
                    EffectReconciliation::Uncertain {
                        recovery: expected.clone(),
                    }
                );
                assert_eq!(
                    report.semantics.cleanup,
                    CleanupStatus::Residual { recovery: expected }
                );
            }
            assert_eq!(fake.calls(), 1, "transport failure must not replay");
        }
    }
    assert_invalid_receipt(FakeMode::WrongIdentity, exact_limits);
}

#[test]
fn oversized_transport_reasons_are_sanitized_and_whole_report_bounded() {
    let fixture = TempDir::new().expect("SSH fixed-result-capacity fixture");
    let fake = Arc::new(FakeTransport::new(FakeMode::OversizedTransportFailure(
        TransportStage::Control,
        TransportFailureKind::TimedOut,
    )));
    let mut insufficient_limits = limits();
    insufficient_limits.max_receipt_bytes = 1;
    let ssh = SshExecutor::with_transport(
        config_with_limits(fixture.path(), insufficient_limits.clone()),
        fake.clone(),
    )
    .expect("configured fixed-result-capacity fake SSH executor");
    let error = ssh
        .execute_bounded(
            &ExecutorRequest {
                assignment_id: "result-capacity".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: None,
            },
            &CancellationToken::new(),
            &insufficient_limits,
        )
        .expect_err("insufficient fixed result capacity must reject before transport");
    let message = format!("{error:#}");
    assert!(
        message.contains("receipt") || message.contains("result"),
        "unexpected fixed result-capacity error: {message}"
    );
    assert_eq!(fake.calls(), 0);

    let mut result_limits = limits();
    result_limits.max_receipt_bytes = 4096;
    for (stage, kind) in [
        (
            TransportStage::Preflight,
            TransportFailureKind::Authentication,
        ),
        (TransportStage::Control, TransportFailureKind::TimedOut),
        (TransportStage::Cleanup, TransportFailureKind::Io),
    ] {
        let mut observed_reasons = Vec::new();
        for _ in 0..2 {
            let (report, fake) = execute_fake(
                FakeMode::OversizedTransportFailure(stage, kind),
                result_limits.clone(),
            );
            let reason = match &report.semantics.status {
                ExecutionStatus::TransportFailed {
                    stage: actual_stage,
                    kind: actual_kind,
                    reason,
                    recovery,
                } => {
                    assert_eq!(*actual_stage, stage);
                    assert_eq!(*actual_kind, kind);
                    if stage == TransportStage::Preflight {
                        assert_eq!(recovery, &None);
                    } else {
                        let expected = recovery_target(&fake.request(0));
                        assert_eq!(recovery, &Some(expected));
                    }
                    reason.clone()
                }
                status => panic!("oversized transport reason lost typed evidence: {status:?}"),
            };
            assert!(reason.ends_with("[truncated]"));
            assert!(reason.is_ascii());
            assert!(!reason.contains(['"', '\\']));
            assert!(
                !reason.chars().any(char::is_control),
                "sanitized reason retained control characters"
            );
            assert!(
                serde_json::to_vec(&report)
                    .expect("measure bounded synthesized execution report")
                    .len()
                    <= result_limits.max_receipt_bytes,
                "synthesized execution report exceeded its result/receipt cap"
            );
            assert_eq!(fake.calls(), 1, "oversized failure reason replayed work");
            observed_reasons.push(reason);
        }
        assert_eq!(
            observed_reasons[0], observed_reasons[1],
            "reason sanitization is not deterministic for {stage:?}/{kind:?}"
        );
    }
}

fn execute_fake(
    mode: FakeMode,
    execution_limits: ExecutorLimits,
) -> (
    multi_agent_coding_orchestrator::executor::ExecutionReport,
    Arc<FakeTransport>,
) {
    execute_fake_request(
        mode,
        execution_limits,
        ExecutorRequest {
            assignment_id: "success".to_string(),
            argv: vec!["unused".to_string()],
            working_directory: None,
        },
    )
}

fn execute_fake_request(
    mode: FakeMode,
    execution_limits: ExecutorLimits,
    request: ExecutorRequest,
) -> (
    multi_agent_coding_orchestrator::executor::ExecutionReport,
    Arc<FakeTransport>,
) {
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(mode));
    let ssh = SshExecutor::with_transport(
        config_with_limits(fixture.path(), execution_limits.clone()),
        fake.clone(),
    )
    .expect("configured fake SSH executor");
    let report = ssh
        .execute_bounded(&request, &CancellationToken::new(), &execution_limits)
        .expect("typed fake transport outcome");
    (report, fake)
}

fn assert_invalid_receipt(mode: FakeMode, execution_limits: ExecutorLimits) {
    assert_invalid_receipt_request(
        mode,
        execution_limits,
        ExecutorRequest {
            assignment_id: "success".to_string(),
            argv: vec!["unused".to_string()],
            working_directory: None,
        },
    );
}

fn assert_invalid_receipt_request(
    mode: FakeMode,
    execution_limits: ExecutorLimits,
    request_to_execute: ExecutorRequest,
) {
    let expected_limits = execution_limits.clone();
    let (report, fake) = execute_fake_request(mode, execution_limits, request_to_execute);
    let request = fake.request(0);
    let recovery = match &report.semantics.status {
        ExecutionStatus::TransportFailed {
            stage: TransportStage::Collect,
            kind: TransportFailureKind::Protocol,
            recovery: Some(recovery),
            ..
        } => recovery,
        status => panic!("{mode:?} must yield a typed uncertain result, got {status:?}"),
    };
    assert_eq!(recovery.assignment_id, request.assignment_id);
    assert_eq!(recovery.executor_run_id, request.executor_run_id);
    assert_eq!(recovery.host_id, request.host_id);
    assert_eq!(recovery.workspace, request.remote_root);
    assert_eq!(recovery.staged_input_digest, request.staged_input_digest);
    assert!(!recovery.has_authenticated_process_identity());
    assert_eq!(
        report.semantics.effects,
        EffectReconciliation::Uncertain {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.cleanup,
        CleanupStatus::Residual {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.events.last(),
        Some(&ExecutorLifecycleEvent::CleanupResidual)
    );
    assert!(report.semantics.events.len() <= expected_limits.max_event_count);
    assert!(
        serde_json::to_vec(&report.semantics.events)
            .expect("measure synthesized invalid-receipt lifecycle")
            .len()
            <= expected_limits.max_event_bytes
    );
    assert!(!report.semantics.usage.complete);
    assert_eq!(fake.calls(), 1, "invalid or uncertain work must not replay");
}

#[test]
fn coherent_cleanup_residual_preserves_the_bound_recovery_target() {
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::CleanupResidual));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let report = ssh
        .execute_bounded(
            &ExecutorRequest {
                assignment_id: "success".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: None,
            },
            &CancellationToken::new(),
            &limits(),
        )
        .expect("cleanup residual reply");
    let expected = fake.request(0);
    let recovery = recovery_target(&expected);
    assert_eq!(
        report.semantics.status,
        ExecutionStatus::Uncertain {
            reason: "remote cleanup could not be proven".to_string(),
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.effects,
        EffectReconciliation::Uncertain {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.cleanup,
        CleanupStatus::Residual { recovery }
    );
}

#[test]
fn authenticated_remote_process_identity_is_optional_but_consistent_when_present() {
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::CleanupResidualWithProcess));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    let report = ssh
        .execute_bounded(
            &ExecutorRequest {
                assignment_id: "success".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: None,
            },
            &CancellationToken::new(),
            &limits(),
        )
        .expect("authenticated process identity receipt");
    let recovery = match &report.semantics.status {
        ExecutionStatus::Uncertain { recovery, .. } => recovery,
        status => panic!("expected accepted uncertain receipt, got {status:?}"),
    };
    assert!(recovery.has_authenticated_process_identity());
    assert_eq!(
        recovery.remote_process,
        Some(RemoteProcessIdentity {
            session_id: "session-accepted".to_string(),
            pid: 4201,
            pgid: 4201,
            start_token: "start-accepted".to_string(),
        })
    );
    assert_eq!(
        report.semantics.effects,
        EffectReconciliation::Uncertain {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(
        report.semantics.cleanup,
        CleanupStatus::Residual {
            recovery: recovery.clone(),
        }
    );
    assert_eq!(fake.calls(), 1);
}

#[test]
fn staged_input_digest_is_deterministic_and_binds_workspace_bytes() {
    let first_workspace = TempDir::new().expect("first digest workspace");
    let second_workspace = TempDir::new().expect("second digest workspace");
    fs::write(first_workspace.path().join("input.txt"), b"alpha")
        .expect("write first digest fixture");
    fs::write(second_workspace.path().join("input.txt"), b"alpha")
        .expect("write second digest fixture");
    let fixture = TempDir::new().expect("SSH fixture tempdir");
    let fake = Arc::new(FakeTransport::new(FakeMode::Scenario));
    let ssh = SshExecutor::with_transport(config(fixture.path()), fake.clone())
        .expect("configured fake SSH executor");
    for workspace in [&first_workspace, &second_workspace] {
        ssh.execute_bounded(
            &ExecutorRequest {
                assignment_id: "workspace".to_string(),
                argv: vec!["unused".to_string()],
                working_directory: Some(workspace.path().to_path_buf()),
            },
            &CancellationToken::new(),
            &limits(),
        )
        .expect("deterministic digest staging");
    }
    let first = fake.request(0);
    let second = fake.request(1);
    assert_eq!(first.staged_input_digest, second.staged_input_digest);
    assert!(first.staged_input_digest.starts_with("sha256:"));
    assert_eq!(first.staged_input_digest.len(), "sha256:".len() + 64);

    fs::write(second_workspace.path().join("input.txt"), b"beta")
        .expect("change second digest fixture");
    ssh.execute_bounded(
        &ExecutorRequest {
            assignment_id: "workspace".to_string(),
            argv: vec!["unused".to_string()],
            working_directory: Some(second_workspace.path().to_path_buf()),
        },
        &CancellationToken::new(),
        &limits(),
    )
    .expect("changed digest staging");
    assert_ne!(
        first.staged_input_digest,
        fake.request(2).staged_input_digest
    );
    assert_eq!(fake.calls(), 3);
}

#[test]
fn grok_46_xhigh_writable_capability_requires_the_bounded_leaf_contract() {
    let workspace = TempDir::new().expect("typed Grok workspace");
    let prompt = workspace.path().join("prompt.txt");
    let output = workspace.path().join("output.jsonl");
    let context = LaunchContext {
        prompt: &prompt,
        model: Some("grok-4.6"),
        effort: Some("xhigh"),
        cwd: workspace.path(),
        output: &output,
    };
    let config = RuntimeAdapterConfig::defaults(RuntimeId::Grok);
    let contract = config
        .typed_runtime_contract(AdapterId::Grok, &context)
        .expect("canonical Grok 4.6/xhigh contract");

    assert_eq!(contract.runtime(), TypedRuntime::Grok46Xhigh);
    assert!(contract.has_bounded_cwd());
    assert!(contract.has_bounded_output());
    assert!(contract.subagents_disabled());
    let mut expected_capabilities = AdapterId::Grok.capabilities();
    expected_capabilities.side_effect_confinement = SideEffectConfinement::Verified;
    assert_eq!(contract.capabilities(), expected_capabilities);
    assert_eq!(
        contract.capabilities().side_effect_confinement,
        SideEffectConfinement::Verified
    );
    assert!(contract.capabilities().admits_worktree_writable());
    assert!(!contract.capabilities().admits_writable_release());
    assert_eq!(
        adapter_for(AdapterId::Grok).capabilities_for_launch(&context),
        contract.capabilities()
    );

    let launch = config.render(&context).expect("render typed Grok launch");
    assert_eq!(launch.cwd, workspace.path());
    assert_eq!(launch.output_capture, OutputCaptureMode::Stdout);
    assert!(launch
        .argv
        .windows(2)
        .any(|pair| { pair[0] == "--cwd" && pair[1] == workspace.path().display().to_string() }));
    assert_eq!(
        launch
            .argv
            .iter()
            .filter(|argument| argument.as_str() == "--no-subagents")
            .count(),
        1
    );

    let valid = b"{\"type\":\"end\",\"stopReason\":\"stop\",\"sessionId\":\"session\",\"requestId\":\"request\"}\n";
    assert!(contract.parse_output(valid).is_ok());
    let oversized = vec![b'x'; 8 * 1024 * 1024 + 1];
    let error = contract
        .parse_output(&oversized)
        .expect_err("oversized Grok stream must fail closed");
    assert!(format!("{error:#}").contains("byte limit"));
}

#[test]
fn grok_capability_elevation_fails_closed_and_other_runtimes_do_not_change() {
    let workspace = TempDir::new().expect("typed Grok refusal workspace");
    let prompt = workspace.path().join("prompt.txt");
    let output = workspace.path().join("output.jsonl");
    let canonical = RuntimeAdapterConfig::defaults(RuntimeId::Grok);

    for (model, effort) in [
        (Some("grok-4.5"), Some("xhigh")),
        (Some("grok-4.6"), Some("high")),
        (None, Some("xhigh")),
        (Some("grok-4.6"), None),
    ] {
        let launch = LaunchContext {
            prompt: &prompt,
            model,
            effort,
            cwd: workspace.path(),
            output: &output,
        };
        assert!(canonical
            .typed_runtime_contract(AdapterId::Grok, &launch)
            .is_none());
        assert_eq!(
            canonical.capabilities_for_launch(AdapterId::Grok, &launch),
            AdapterId::Grok.capabilities()
        );
    }

    let exact = LaunchContext {
        prompt: &prompt,
        model: Some("grok-4.6"),
        effort: Some("xhigh"),
        cwd: workspace.path(),
        output: &output,
    };
    let relative_cwd = LaunchContext {
        cwd: Path::new("relative-worktree"),
        ..exact.clone()
    };
    assert!(canonical
        .typed_runtime_contract(AdapterId::Grok, &relative_cwd)
        .is_none());

    let mut mutations = Vec::new();
    let mut missing_no_subagents = canonical.clone();
    missing_no_subagents
        .argument_template
        .retain(|argument| argument != "--no-subagents");
    mutations.push(missing_no_subagents);
    let mut unbounded_output = canonical.clone();
    unbounded_output.output_capture = OutputCaptureMode::OutputFile;
    mutations.push(unbounded_output);
    let mut altered_cwd = canonical.clone();
    let cwd_value = altered_cwd
        .argument_template
        .iter_mut()
        .find(|argument| argument.as_str() == "{cwd}")
        .expect("canonical cwd placeholder");
    *cwd_value = "/tmp/unbounded".to_string();
    mutations.push(altered_cwd);
    let mut altered_environment = canonical.clone();
    altered_environment.env_passthrough.push("PATH".into());
    mutations.push(altered_environment);
    let mut altered_stdin = canonical.clone();
    altered_stdin.feed_prompt_on_stdin = true;
    mutations.push(altered_stdin);
    let mut duplicate_cwd = canonical.clone();
    duplicate_cwd.working_dir_flag = Some("--cwd".into());
    mutations.push(duplicate_cwd);

    for mutation in mutations {
        assert!(mutation
            .typed_runtime_contract(AdapterId::Grok, &exact)
            .is_none());
        assert!(!mutation
            .capabilities_for_launch(AdapterId::Grok, &exact)
            .admits_worktree_writable());
    }

    let mut alternate_binary = canonical.clone();
    alternate_binary.binary = Some("/tmp/operator-grok".into());
    assert!(alternate_binary
        .typed_runtime_contract(AdapterId::Grok, &exact)
        .is_some());
    assert!(alternate_binary
        .capabilities_for_launch(AdapterId::Grok, &exact)
        .admits_worktree_writable());

    for adapter in [
        AdapterId::Codex,
        AdapterId::Fake,
        AdapterId::Cursor,
        AdapterId::ClaudeCode,
        AdapterId::GeminiCli,
    ] {
        let config = RuntimeAdapterConfig::defaults_for(adapter);
        assert!(config.typed_runtime_contract(adapter, &exact).is_none());
        assert_eq!(
            config.capabilities_for_launch(adapter, &exact),
            adapter.capabilities(),
            "{adapter} capability row changed"
        );
    }
}
