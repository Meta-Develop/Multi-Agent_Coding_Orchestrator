use super::*;
use crate::artifacts::{repository_authenticator_key_only, RunArtifactFamily};
use crate::messaging::transport::{ENV_MESSAGE_ENDPOINT, ENV_MESSAGE_TOKEN};
use crate::supervise::messaging_bridge::worker_requests::WorkerRequestStatus;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

struct FreshFixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    writer: ArtifactRunWriter,
    plan: SupervisorPlan,
}

impl FreshFixture {
    fn new() -> Result<Self> {
        Self::with_parent(json!({
            "id":"parent", "phase":"execution", "role":"child_orchestrator",
            "worker_assignments":[{"id":"worker", "role":"worker"},
                                  {"id":"other", "role":"worker"}]
        }))
    }

    fn with_parent(parent: Value) -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().to_path_buf();
        git2::Repository::init(&repo)?;
        let plan = serde_json::from_value(json!({"assignments":[parent, {
            "id":"second-parent", "phase":"execution", "role":"child_orchestrator",
            "worker_assignments":[{"id":"second-worker", "role":"worker"}]
        }]}))?;
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            RunId::new("run")?,
            "fresh-worker-admission-test",
        )?;
        initialize_supervisor_messaging_session(
            &mut writer,
            &plan,
            &SupervisorPlanMetadata::default(),
        )?;
        Ok(Self {
            _temp: temp,
            repo,
            writer,
            plan,
        })
    }

    fn claim(&self) -> Result<WorkerRequestBinding> {
        with_supervisor_messaging_session(self.writer.run_dir(), |factory| {
            factory.claim_fresh_worker_request_binding(
                &RunId::new("run")?,
                &self.plan.assignments[0],
                1,
                SupervisorRuntime::Codex,
            )
        })
    }
}

impl Drop for FreshFixture {
    fn drop(&mut self) {
        run_sessions().lock().unwrap().remove(self.writer.run_dir());
    }
}

#[test]
fn fresh_worker_admission_claims_once_with_stable_authenticated_generation() -> Result<()> {
    let fixture = FreshFixture::new()?;
    let binding = fixture.claim()?;
    let original = serde_json::to_value(&binding)?;
    assert_eq!(original["run"], "run");
    assert_eq!(original["parent"], "parent");
    assert_eq!(original["attempt"], 1);
    assert!(!original["generation"].as_str().unwrap().is_empty());
    with_supervisor_messaging_session(fixture.writer.run_dir(), |factory| {
        assert_eq!(
            original["state_instance"],
            factory.persistent.as_ref().unwrap().state_instance_id()
        );
        binding.verify_session(factory, "parent")?;
        assert!(factory
            .claim_fresh_worker_request_binding(
                &RunId::new("run")?,
                &fixture.plan.assignments[1],
                1,
                SupervisorRuntime::Codex
            )
            .is_err());
        Ok(())
    })?;
    assert!(fixture.claim().is_err());
    let foreign = FreshFixture::new()?;
    with_supervisor_messaging_session(foreign.writer.run_dir(), |factory| {
        assert!(binding.verify_session(factory, "parent").is_err());
        Ok(())
    })?;
    recover_supervisor_messaging_session(fixture.writer.run_dir())?;
    with_supervisor_messaging_session(fixture.writer.run_dir(), |factory| {
        binding.verify_session(factory, "parent")
    })?;
    assert_eq!(original, serde_json::to_value(binding)?);
    assert!(fixture.claim().is_err());
    Ok(())
}

#[test]
fn fresh_worker_admission_concurrent_claims_have_one_winner() -> Result<()> {
    let fixture = FreshFixture::new()?;
    with_supervisor_messaging_session(fixture.writer.run_dir(), |factory| {
        let run = RunId::new("run")?;
        let parent = &fixture.plan.assignments[0];
        let barrier = std::sync::Barrier::new(2);
        let claim = || {
            barrier.wait();
            factory.claim_fresh_worker_request_binding(&run, parent, 1, SupervisorRuntime::Codex)
        };
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(claim);
            let second = scope.spawn(claim);
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        Ok(())
    })
}

#[test]
fn fresh_worker_admission_invalid_claim_burns_authority_before_retry() -> Result<()> {
    for mutation in 0..8 {
        let fixture = FreshFixture::new()?;
        let mut parent = fixture.plan.assignments[0].clone();
        let mut attempt = 1;
        let mut runtime = SupervisorRuntime::Codex;
        let mut run = RunId::new("run")?;
        match mutation {
            0 => run = RunId::new("foreign-run")?,
            1 => parent.id = "foreign-parent".into(),
            2 => attempt = 0,
            3 => attempt = 2,
            4 => runtime = SupervisorRuntime::Grok,
            5 => parent.worker_assignments[0].id = "second-worker".into(),
            6 => parent.worker_assignments.reverse(),
            7 => parent.assigned_paths.push(PathBuf::from("widened")),
            _ => unreachable!(),
        }
        with_supervisor_messaging_session(fixture.writer.run_dir(), |factory| {
            assert!(
                factory
                    .claim_fresh_worker_request_binding(&run, &parent, attempt, runtime)
                    .is_err(),
                "mutation {mutation}"
            );
            Ok(())
        })?;
        assert!(fixture.claim().is_err(), "retry after mutation {mutation}");
    }
    Ok(())
}

#[test]
fn fresh_worker_admission_refuses_ineligible_authored_parent() -> Result<()> {
    for parent in [
        json!({"id":"parent", "phase":"execution", "role":"child_orchestrator", "runtime":"grok", "worker_assignments":[{"id":"worker","role":"worker"}]}),
        json!({"id":"parent", "phase":"planning", "role":"child_orchestrator", "worker_assignments":[{"id":"worker","role":"worker"}]}),
        json!({"id":"parent", "phase":"execution", "role":"worker"}),
        json!({"id":"parent", "phase":"execution", "role":"child_orchestrator"}),
    ] {
        let fixture = FreshFixture::with_parent(parent)?;
        assert!(fixture.claim().is_err());
        assert!(fixture.claim().is_err());
    }
    Ok(())
}

#[test]
fn fresh_worker_admission_refuses_reopened_recovered_and_refreshed_sessions() -> Result<()> {
    for mode in 0..8 {
        let mut fixture = FreshFixture::new()?;
        match mode {
            0 => with_supervisor_messaging_session(fixture.writer.run_dir(), |factory| {
                drop(factory.open_or_create()?);
                Ok(())
            })?,
            1 => recover_supervisor_messaging_session(fixture.writer.run_dir())?,
            2 => initialize_supervisor_messaging_session(
                &mut fixture.writer,
                &fixture.plan,
                &SupervisorPlanMetadata::default(),
            )?,
            3 => {
                forget_supervisor_messaging_session_for_test(fixture.writer.run_dir())?;
                recover_supervisor_messaging_session(fixture.writer.run_dir())?;
            }
            4 => {
                forget_supervisor_messaging_session_for_test(fixture.writer.run_dir())?;
                initialize_supervisor_messaging_session(
                    &mut fixture.writer,
                    &fixture.plan,
                    &SupervisorPlanMetadata::default(),
                )?;
            }
            5 => {
                let mut invalid_plan = fixture.plan.clone();
                invalid_plan
                    .assignments
                    .push(invalid_plan.assignments[0].clone());
                assert!(initialize_supervisor_messaging_session(
                    &mut fixture.writer,
                    &invalid_plan,
                    &SupervisorPlanMetadata::default()
                )
                .is_err());
            }
            6 => {
                let descriptor = fixture
                    .writer
                    .run_dir()
                    .join(MESSAGING_SESSION_DESCRIPTOR_NAME);
                let held = fixture.writer.run_dir().join("held-descriptor");
                fs::rename(&descriptor, &held)?;
                assert!(recover_supervisor_messaging_session(fixture.writer.run_dir()).is_err());
                fs::rename(&held, &descriptor)?;
            }
            7 => {
                let mut empty_plan = fixture.plan.clone();
                empty_plan.assignments.clear();
                initialize_supervisor_messaging_session(
                    &mut fixture.writer,
                    &empty_plan,
                    &SupervisorPlanMetadata::default(),
                )?;
            }
            _ => unreachable!(),
        }
        assert!(fixture.claim().is_err(), "mode {mode}");
        assert!(fixture.claim().is_err(), "retry mode {mode}");
    }
    Ok(())
}

#[test]
fn fresh_worker_admission_authentication_failure_cannot_be_repaired_into_retry() -> Result<()> {
    let fixture = FreshFixture::new()?;
    let descriptor = fixture
        .writer
        .run_dir()
        .join(MESSAGING_SESSION_DESCRIPTOR_NAME);
    let held = fixture.writer.run_dir().join("held-descriptor");
    fs::rename(&descriptor, &held)?;
    assert!(fixture.claim().is_err());
    fs::rename(&held, &descriptor)?;
    assert!(fixture.claim().is_err());
    Ok(())
}

#[test]
fn fresh_worker_admission_downstream_failure_and_journal_recovery_never_remint() -> Result<()> {
    let fixture = FreshFixture::new()?;
    let binding = fixture.claim()?;
    let mut inbox = WorkerRequestInbox::create(
        repository_authenticator_key_only(&fixture.repo)?,
        binding.clone(),
    )?;
    inbox.submit("request", "worker")?;
    // Simulate downstream failure after the binding has escaped: even dropping all
    // handles or recovering a valid journal cannot produce another fresh identity.
    drop(inbox);
    assert!(WorkerRequestInbox::create(
        repository_authenticator_key_only(&fixture.repo)?,
        binding.clone()
    )
    .is_err());
    assert!(fixture.claim().is_err());
    let mut recovered =
        WorkerRequestInbox::recover(repository_authenticator_key_only(&fixture.repo)?, binding)?;
    assert!(recovered.requires_reconciliation());
    assert!(recovered.submit("request", "worker").is_err());
    assert!(fixture.claim().is_err());
    Ok(())
}

#[test]
fn fresh_worker_admission_staged_binding_cannot_authorize_existing_session() -> Result<()> {
    let fixture = Fixture::new()?;
    drop(fixture.inbox(false)?);
    with_supervisor_messaging_session(&fixture.directory, |factory| {
        assert!(factory
            .claim_fresh_worker_request_binding(
                &RunId::new("run")?,
                &fixture.parent,
                1,
                SupervisorRuntime::Codex
            )
            .is_err());
        Ok(())
    })
}

struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    directory: PathBuf,
    parent: OrchestratorAssignment,
    binding: WorkerRequestBinding,
}

impl Fixture {
    fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().to_path_buf();
        git2::Repository::init(&repo)?;
        let parent: OrchestratorAssignment = serde_json::from_value(json!({
            "id":"parent", "phase":"execution", "role":"child_orchestrator",
            "worker_assignments":[{"id":"worker", "role":"worker"},
                                  {"id":"other", "role":"worker"}]
        }))?;
        let identities = vec![
            LaunchedMessagingIdentity::from_orchestrator(&parent),
            LaunchedMessagingIdentity::from_worker(&parent.worker_assignments[0]),
            LaunchedMessagingIdentity::from_worker(&parent.worker_assignments[1]),
            LaunchedMessagingIdentity::new("peer", RoleCategory::DelegatingCoordinator),
        ];
        let mut hierarchy = HierarchyLedgerSnapshot::default();
        for identity in &identities {
            hierarchy
                .effective_categories
                .insert(identity.agent_id.clone(), identity.role_category);
        }
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            RunId::new("run")?,
            "worker-ipc-test",
        )?;
        let directory = writer.run_dir().to_path_buf();
        let (persistent, fresh) =
            PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        assert!(fresh);
        let factory =
            SupervisorMessagingSessionFactory::from_persistent_binding(&directory, persistent)?;
        drop(factory.create_initial_persistent_broker()?);
        let binding =
            factory.worker_request_binding(&RunId::new("run")?, &parent, 1, "generation")?;
        run_sessions()
            .lock()
            .unwrap()
            .insert(directory.clone(), factory);
        Ok(Self {
            _temp: temp,
            repo,
            directory,
            parent,
            binding,
        })
    }

    fn inbox(&self, recover: bool) -> Result<WorkerRequestInbox<RepositoryAuthenticator>> {
        let auth = repository_authenticator_key_only(&self.repo)?;
        if recover {
            WorkerRequestInbox::recover(auth, self.binding.clone())
        } else {
            WorkerRequestInbox::create(auth, self.binding.clone())
        }
    }

    fn start(
        &self,
        recover: bool,
        cancel: ProcessCancellation,
    ) -> Result<AssignmentMessagingServer> {
        start_assignment_messaging_with_worker_inbox(
            &self.directory,
            "run",
            "parent",
            Arc::new(WorkerRequestIpc::new(
                self.inbox(recover)?,
                self.binding.clone(),
                cancel,
            )),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        run_sessions().lock().unwrap().remove(&self.directory);
    }
}

fn exchange(
    server: &AssignmentMessagingServer,
    request: Value,
    valid_token: bool,
) -> Result<Value> {
    exchange_launch(&server.launch(), request, valid_token)
}

fn exchange_launch(
    launch: &crate::messaging::transport::AssignmentMessagingLaunch,
    request: Value,
    valid_token: bool,
) -> Result<Value> {
    let env: BTreeMap<_, _> = launch
        .environment_for("run", "parent")?
        .into_iter()
        .collect();
    let token = if valid_token {
        env[ENV_MESSAGE_TOKEN].as_str()
    } else {
        "forged"
    };
    let mut stream = TcpStream::connect(&env[ENV_MESSAGE_ENDPOINT])?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    writeln!(stream, "{}", json!({"bearer":token, "request":request}))?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    Ok(serde_json::from_str(&response)?)
}

fn submit() -> Value {
    json!({"operation":"submit_worker_request", "request_id":"request", "worker_id":"worker"})
}

fn status() -> Value {
    json!({"operation":"worker_request_status", "request_id":"request"})
}

#[test]
fn worker_ipc_durable_submit_retry_and_status_over_authenticated_socket() -> Result<()> {
    let fixture = Fixture::new()?;
    let server = fixture.start(false, ProcessCancellation::new())?;
    let queued = exchange(&server, submit(), true)?;
    assert_eq!(
        queued,
        json!({"ok":true,"result":{
            "request_id":"request","worker_id":"worker","status":"queued"
        }})
    );
    assert_eq!(exchange(&server, submit(), true)?, queued);
    let observed = exchange(&server, status(), true)?;
    assert_eq!(observed["result"]["record"], queued["result"]);
    assert_eq!(observed["result"]["requires_reconciliation"], false);
    // The existing broker operations continue to work on this same endpoint.
    assert_eq!(
        exchange(&server, json!({"operation":"receive_next"}), true)?["ok"],
        true
    );
    drop(server);
    let recovered = fixture.inbox(true)?;
    assert_eq!(recovered.requests()?.len(), 1);
    assert_eq!(
        recovered.status("request")?.status,
        WorkerRequestStatus::Queued
    );
    assert!(recovered.requires_reconciliation());
    Ok(())
}

#[test]
fn worker_ipc_rejects_forged_fields_tokens_foreign_ids_and_state_transitions() -> Result<()> {
    let fixture = Fixture::new()?;
    let server = fixture.start(false, ProcessCancellation::new())?;
    assert_eq!(exchange(&server, submit(), false)?["ok"], false);
    for field in [
        "run_id",
        "parent_id",
        "task_id",
        "attempt",
        "generation",
        "state_instance",
        "command",
        "assigned_paths",
        "role",
        "status",
        "accepted",
    ] {
        let mut request = submit();
        request[field] = json!("forged");
        assert_eq!(exchange(&server, request, true)?["ok"], false, "{field}");
    }
    for request in [
        json!({"operation":"reserve_worker_request","request_id":"request"}),
        json!({"operation":"complete_worker_request","request_id":"request"}),
        json!({"operation":"submit_worker_request","request_id":"request","worker_id":"peer"}),
        json!({"operation":"submit_worker_request","request_id":"request","worker_id":"Worker"}),
        json!({"operation":"submit_worker_request","request_id":"../escape","worker_id":"worker"}),
        json!({"operation":"worker_request_status","request_id":"unknown"}),
        json!({"operation":"worker_request_status","request_id":"request","parent_id":"peer"}),
    ] {
        assert_eq!(exchange(&server, request, true)?["ok"], false);
    }
    drop(server);
    assert!(fixture.inbox(true)?.requests()?.is_empty());
    Ok(())
}

#[test]
fn worker_ipc_duplicate_worker_or_rebound_request_cannot_enqueue_again() -> Result<()> {
    let fixture = Fixture::new()?;
    let server = fixture.start(false, ProcessCancellation::new())?;
    assert_eq!(exchange(&server, submit(), true)?["ok"], true);
    for request in [
        json!({"operation":"submit_worker_request","request_id":"second","worker_id":"worker"}),
        json!({"operation":"submit_worker_request","request_id":"request","worker_id":"other"}),
    ] {
        assert_eq!(exchange(&server, request, true)?["ok"], false);
    }
    drop(server);
    assert_eq!(fixture.inbox(true)?.requests()?.len(), 1);
    Ok(())
}

#[test]
fn worker_ipc_recovery_is_inspection_only_even_for_idempotent_retries() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut inbox = fixture.inbox(false)?;
    inbox.submit("request", "worker")?;
    inbox.submit("uncertain", "other")?;
    inbox.transition("uncertain", WorkerRequestStatus::Reserved)?;
    drop(inbox);
    let server = fixture.start(true, ProcessCancellation::new())?;
    let response = exchange(&server, status(), true)?;
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["requires_reconciliation"], true);
    assert_eq!(response["result"]["record"]["status"], "queued");
    let response = exchange(
        &server,
        json!({"operation":"worker_request_status","request_id":"uncertain"}),
        true,
    )?;
    assert_eq!(response["result"]["record"]["status"], "recovery_required");
    assert_eq!(exchange(&server, submit(), true)?["ok"], false);
    assert_eq!(
        exchange(
            &server,
            json!({"operation":"submit_worker_request","request_id":"new","worker_id":"other"}),
            true
        )?["ok"],
        false
    );
    Ok(())
}

#[test]
fn worker_ipc_binding_refuses_wrong_attempt_generation_parent_worker_set_and_repository(
) -> Result<()> {
    for mutation in 0..7 {
        let fixture = Fixture::new()?;
        let mut parent = fixture.parent.clone();
        let (mut attempt, mut generation) = (1, "generation");
        match mutation {
            0 => attempt = 2,
            1 => generation = "replacement",
            2 => parent.id = "peer".into(),
            3 => {
                parent.worker_assignments.pop();
            }
            4 => parent.worker_assignments[0].id = "foreign".into(),
            5 => parent.role = crate::supervise::AgentRole::Worker,
            _ => {}
        }
        let expected = with_supervisor_messaging_session(&fixture.directory, |factory| {
            factory.worker_request_binding(&RunId::new("run")?, &parent, attempt, generation)
        });
        if mutation == 4 || mutation == 5 {
            assert!(expected.is_err());
            continue;
        }
        let inbox = if mutation == 6 {
            let other = Fixture::new()?;
            let auth = repository_authenticator_key_only(&other.repo)?;
            // Keep the other repository alive until the binding check completes.
            let inbox = WorkerRequestInbox::create(auth, fixture.binding.clone())?;
            let result = start_assignment_messaging_with_worker_inbox(
                &fixture.directory,
                "run",
                "parent",
                Arc::new(WorkerRequestIpc::new(
                    inbox,
                    expected?,
                    ProcessCancellation::new(),
                )),
            );
            assert!(result.is_err());
            continue;
        } else {
            fixture.inbox(false)?
        };
        assert!(start_assignment_messaging_with_worker_inbox(
            &fixture.directory,
            "run",
            "parent",
            Arc::new(WorkerRequestIpc::new(
                inbox,
                expected?,
                ProcessCancellation::new()
            ))
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn worker_ipc_unattached_foreign_run_and_foreign_endpoint_are_refused() -> Result<()> {
    let fixture = Fixture::new()?;
    let ordinary = start_assignment_messaging(&fixture.directory, "run", "parent")?;
    assert_eq!(exchange(&ordinary, submit(), true)?["ok"], false);
    assert_eq!(exchange(&ordinary, status(), true)?["ok"], false);
    drop(ordinary);
    for (run, task) in [("wrong-run", "parent"), ("run", "worker"), ("run", "peer")] {
        let case = Fixture::new()?;
        assert!(start_assignment_messaging_with_worker_inbox(
            &case.directory,
            run,
            task,
            Arc::new(WorkerRequestIpc::new(
                case.inbox(false)?,
                case.binding.clone(),
                ProcessCancellation::new()
            ))
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn worker_ipc_cancellation_and_live_persistence_tamper_fail_closed() -> Result<()> {
    for mutation in 0..3 {
        let fixture = Fixture::new()?;
        let cancellation = ProcessCancellation::new();
        let server = fixture.start(false, cancellation.child_scope())?;
        assert_eq!(exchange(&server, submit(), true)?["ok"], true);
        match mutation {
            0 => cancellation.cancel(),
            1 => fs::write(
                fixture
                    .directory
                    .join(PersistentMessagingBinding::DESCRIPTOR_NAME),
                b"forged",
            )?,
            _ => {
                let root = repository_authenticator_key_only(&fixture.repo)?
                    .state_root()
                    .path()
                    .join("supervisor-messaging-v1");
                let journal = fs::read_dir(root)?
                    .filter_map(|entry| entry.ok())
                    .find(|entry| {
                        let name = entry.file_name();
                        let name = name.to_string_lossy();
                        name.starts_with("worker-inbox-") && name.ends_with(".jsonl")
                    })
                    .context("inbox journal")?
                    .path();
                fs::OpenOptions::new()
                    .append(true)
                    .open(journal)?
                    .write_all(b"tampered\n")?;
            }
        }
        assert_eq!(exchange(&server, status(), true)?["ok"], false);
        assert_eq!(exchange(&server, submit(), true)?["ok"], false);
    }
    Ok(())
}

#[test]
fn worker_ipc_endpoint_shutdown_preserves_supervisor_owned_live_inbox() -> Result<()> {
    let fixture = Fixture::new()?;
    let service = Arc::new(WorkerRequestIpc::new(
        fixture.inbox(false)?,
        fixture.binding.clone(),
        ProcessCancellation::new(),
    ));
    let server = start_assignment_messaging_with_worker_inbox(
        &fixture.directory,
        "run",
        "parent",
        Arc::clone(&service),
    )?;
    assert_eq!(exchange(&server, submit(), true)?["ok"], true);
    drop(server);
    let service =
        Arc::try_unwrap(service).map_err(|_| anyhow::anyhow!("endpoint still owns inbox"))?;
    let mut inbox = service.into_inbox()?;
    assert!(!inbox.requires_reconciliation());
    assert_eq!(inbox.requests()?.len(), 1);
    assert_eq!(
        inbox.submit("request", "worker")?.status,
        WorkerRequestStatus::Queued
    );
    Ok(())
}

#[test]
fn worker_ipc_foreign_state_instance_and_pre_cancelled_attachment_are_refused() -> Result<()> {
    let fixture = Fixture::new()?;
    let foreign = WorkerRequestBinding::new(
        "foreign-instance",
        &RunId::new("run")?,
        &fixture.parent,
        1,
        "generation",
    )?;
    let inbox = WorkerRequestInbox::create(
        repository_authenticator_key_only(&fixture.repo)?,
        foreign.clone(),
    )?;
    // Even matching expected/inbox values cannot substitute the authenticated state instance.
    assert!(start_assignment_messaging_with_worker_inbox(
        &fixture.directory,
        "run",
        "parent",
        Arc::new(WorkerRequestIpc::new(
            inbox,
            foreign,
            ProcessCancellation::new()
        ))
    )
    .is_err());
    let cancelled = ProcessCancellation::new();
    cancelled.cancel();
    assert!(fixture.start(false, cancelled).is_err());
    Ok(())
}

#[test]
fn worker_ipc_inflight_submit_is_frozen_only_after_shutdown_join() -> Result<()> {
    use std::{sync::mpsc, thread};

    // Timeouts are deadlock guards, not scheduling assumptions. Channels determine
    // exactly when cancellation/drop occur relative to the real submit handler.
    const GUARD: Duration = Duration::from_secs(10);
    for boundary in [
        SubmitBoundary::BeforeAdmission,
        SubmitBoundary::BeforeAppend,
    ] {
        let fixture = Fixture::new()?;
        let cancellation = ProcessCancellation::new();
        let mut inbox = fixture.inbox(false)?;
        let baseline = inbox.submit("already-committed", "other")?;
        let mut service =
            WorkerRequestIpc::new(inbox, fixture.binding.clone(), cancellation.child_scope());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (committed_tx, committed_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        service.submit_observer = Some(Box::new(move |observed| {
            if observed == SubmitBoundary::AfterAppend {
                committed_tx.send(())?;
            }
            if observed == boundary {
                entered_tx.send(())?;
                release_rx.lock().unwrap().recv_timeout(GUARD)?;
            }
            Ok(())
        }));
        let service = Arc::new(service);
        let mut server = start_assignment_messaging_with_worker_inbox(
            &fixture.directory,
            "run",
            "parent",
            Arc::clone(&service),
        )?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        server.shutdown_observer = Some(shutdown_tx);
        let launch = server.launch();
        let client = thread::spawn(move || exchange_launch(&launch, submit(), true));
        entered_rx.recv_timeout(GUARD)?;
        // The authenticated request is now paused inside submit, holding the inbox.
        cancellation.cancel();
        let (joined_tx, joined_rx) = mpsc::channel();
        let dropper = thread::spawn(move || {
            drop(server);
            // Sample at Drop return, before the test can inspect the live inbox.
            joined_tx.send(committed_rx.try_recv().is_ok()).unwrap();
        });
        shutdown_rx.recv_timeout(GUARD)?;
        assert!(matches!(
            joined_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(
            service.inbox.try_lock().is_err(),
            "in-flight submit still owns inbox"
        );
        release_tx.send(())?;
        assert_eq!(
            joined_rx.recv_timeout(GUARD)?,
            boundary == SubmitBoundary::BeforeAppend
        );
        dropper.join().expect("dropper panicked");
        let response = client.join().expect("IPC client panicked");

        let service = Arc::try_unwrap(service)
            .map_err(|_| anyhow::anyhow!("joined endpoint still owns inbox"))?;
        let inbox = service.into_inbox()?;
        assert!(!inbox.requires_reconciliation());
        let frozen = inbox.requests()?;
        let mut expected = vec![baseline];
        if boundary == SubmitBoundary::BeforeAppend {
            expected.push(super::super::worker_requests::WorkerRequestRecord {
                request_id: "request".into(),
                worker_id: "worker".into(),
                status: WorkerRequestStatus::Queued,
            });
        }
        assert_eq!(frozen, expected, "{boundary:?}");
        // Shutdown can discard the reply after a durable append. A lost reply is
        // not proof of refusal; the frozen journal is the authoritative outcome.
        if let Ok(response) = response {
            assert_eq!(response["ok"], boundary == SubmitBoundary::BeforeAppend);
        }
        drop(inbox);
        let recovered = fixture.inbox(true)?;
        assert_eq!(
            recovered.requests()?,
            frozen,
            "durable replay differs at {boundary:?}"
        );
        assert!(recovered.requires_reconciliation());
    }
    Ok(())
}
