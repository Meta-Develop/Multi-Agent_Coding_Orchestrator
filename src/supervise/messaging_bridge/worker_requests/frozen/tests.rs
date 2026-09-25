use super::*;
use crate::supervise::messaging_bridge::{
    persistence::PersistentMessagingBinding, run_sessions, worker_request_ipc::SubmitBoundary,
    LaunchedMessagingIdentity, SupervisorMessagingSessionFactory,
};
use crate::{
    artifacts::{ArtifactRunWriter, RunArtifactFamily},
    hierarchy_ledger::HierarchyLedgerSnapshot,
    messaging::transport::{ENV_MESSAGE_ENDPOINT, ENV_MESSAGE_TOKEN},
    worktree::WorktreeCreateOptions,
};
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    path::PathBuf,
    sync::{mpsc, Mutex},
    thread,
    time::Duration,
};

struct Fixture {
    _temp: tempfile::TempDir,
    repo: PathBuf,
    directory: PathBuf,
    parent: OrchestratorAssignment,
    lease: ManagedWorktreeWriteLease,
    claims: SyncStore,
    claim: PathClaim,
    binding: WorkerRequestBinding,
}

impl Fixture {
    fn new() -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        WorktreeManager::init_repository(&repo, "main")?;
        let git = crate::git_repository::open(&repo)?;
        std::fs::create_dir(repo.join("src"))?;
        std::fs::write(repo.join("src/lib.rs"), "pub fn selected() {}\n")?;
        let mut index = git.index()?;
        index.add_path(Path::new("src/lib.rs"))?;
        index.write()?;
        let tree = git.find_tree(index.write_tree()?)?;
        let signature = git2::Signature::now("test", "test@example.com")?;
        git.commit(Some("HEAD"), &signature, &signature, "base", &tree, &[])?;
        let parent: OrchestratorAssignment = serde_json::from_value(json!({
            "id":"parent", "phase":"execution", "role":"child_orchestrator",
            "assigned_paths":["src"],
            "worker_assignments":[
                {"id":"worker", "role":"worker", "assigned_paths":["src/lib.rs"]},
                {"id":"other", "role":"worker", "assigned_paths":["src/other.rs"]}
            ]
        }))?;
        let manager = WorktreeManager::new(&repo);
        manager.create(WorktreeCreateOptions {
            agent_id: parent.id.clone(),
            branch: None,
            base: None,
            worktree_root: Some(temp.path().join("worktrees")),
        })?;
        let lease = manager.acquire_write_execution_lease(&parent.id)?;
        let claims = SyncStore::open(&repo)?;
        let run = RunId::new("run")?;
        let claim = claims.claim_paths_for_run(&run, &parent.id, &parent.assigned_paths)?;
        let identities = vec![
            LaunchedMessagingIdentity::from_orchestrator(&parent),
            LaunchedMessagingIdentity::from_worker(&parent.worker_assignments[0]),
            LaunchedMessagingIdentity::from_worker(&parent.worker_assignments[1]),
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
            run.clone(),
            "frozen-inbox-test",
        )?;
        let directory = writer.run_dir().to_path_buf();
        let (persistent, fresh) =
            PersistentMessagingBinding::prepare(&mut writer, &hierarchy, &identities)?;
        assert!(fresh);
        let factory =
            SupervisorMessagingSessionFactory::from_persistent_binding(&directory, persistent)?;
        drop(factory.create_initial_persistent_broker()?);
        let binding = factory.worker_request_binding(&run, &parent, 1, "generation")?;
        run_sessions()
            .lock()
            .unwrap()
            .insert(directory.clone(), factory);
        Ok(Self {
            _temp: temp,
            repo,
            directory,
            parent,
            lease,
            claims,
            claim,
            binding,
        })
    }

    fn resources(&self) -> WorkerInboxResources<'_> {
        WorkerInboxResources {
            repo: &self.repo,
            parent: &self.parent,
            lease: &self.lease,
            claim: &self.claim,
            claims: &self.claims,
        }
    }

    fn turn(&self) -> Result<WorkerInboxTurn<'_>> {
        WorkerInboxTurn::new(self.binding.clone(), 1, self.resources())
    }

    fn inbox(&self, recover: bool) -> Result<WorkerRequestInbox<RepositoryAuthenticator>> {
        let auth = repository_authenticator_key_only(&self.repo)?;
        if recover {
            WorkerRequestInbox::recover(auth, self.binding.clone())
        } else {
            WorkerRequestInbox::create(auth, self.binding.clone())
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        run_sessions().lock().unwrap().remove(&self.directory);
    }
}

fn submit(launch: &AssignmentMessagingLaunch, request: &str, worker: &str) -> Result<Value> {
    let env: BTreeMap<_, _> = launch
        .environment_for("run", "parent")?
        .into_iter()
        .collect();
    let mut stream = TcpStream::connect(&env[ENV_MESSAGE_ENDPOINT])?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    writeln!(
        stream,
        "{}",
        json!({"bearer":env[ENV_MESSAGE_TOKEN], "request":{
            "operation":"submit_worker_request", "request_id":request, "worker_id":worker
        }})
    )?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    Ok(serde_json::from_str(&response)?)
}

#[test]
fn frozen_inbox_exact_order_watermark_and_duplicate_refusal() -> Result<()> {
    let fixture = Fixture::new()?;
    let turn = fixture.turn()?;
    let claims_before = fixture.claims.status_snapshot()?;
    let endpoint = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?;
    let launch = endpoint.launch();
    for (id, worker, accepted) in [
        ("z-first", "worker", true),
        ("z-first", "worker", true),
        ("duplicate", "worker", false),
        ("z-first", "other", false),
        ("unknown", "foreign", false),
        ("a-second", "other", true),
    ] {
        assert_eq!(submit(&launch, id, worker)?["ok"], accepted);
    }
    let frozen = endpoint.shutdown()?;
    let view = frozen.view(&turn)?;
    assert_eq!(view.binding, &fixture.binding);
    assert_eq!(view.turn, 1);
    assert_eq!(
        view.requests
            .iter()
            .map(|r| r.request_id.as_str())
            .collect::<Vec<_>>(),
        ["z-first", "a-second"]
    );
    assert_eq!(view.watermark.last_sequence, 2);
    assert!(!view.watermark.journal_instance.is_empty());
    assert_eq!(fixture.claims.status_snapshot()?, claims_before);
    assert_eq!(
        WorktreeManager::new(&fixture.repo)
            .list_managed_verified()?
            .len(),
        1
    );
    assert!(TcpStream::connect(
        launch
            .environment_for("run", "parent")?
            .into_iter()
            .collect::<BTreeMap<_, _>>()[ENV_MESSAGE_ENDPOINT]
            .as_str()
    )
    .is_err());
    Ok(())
}

#[test]
fn frozen_inbox_consumer_requires_exact_parent_resources_and_launch() -> Result<()> {
    let fixture = Fixture::new()?;
    let turn = fixture.turn()?;
    let run = RunId::new("run")?;
    turn.verify_parent_resources(&run, 1, fixture.resources())?;
    assert!(turn
        .verify_parent_resources(&run, 2, fixture.resources())
        .is_err());
    assert!(turn
        .verify_parent_resources(&RunId::new("foreign")?, 1, fixture.resources())
        .is_err());
    let mut different_parent = fixture.parent.clone();
    // The worker ID set is unchanged, but the authored instruction is not.
    different_parent.worker_assignments[0].task = Some("substituted task".into());
    let mut different = fixture.resources();
    different.parent = &different_parent;
    assert!(turn.verify_parent_resources(&run, 1, different).is_err());
    let endpoint = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?;
    let launch = endpoint.launch();
    let frozen = endpoint.shutdown()?;
    frozen.verify_parent_launch(&fixture.directory, &launch)?;
    assert!(frozen
        .verify_parent_launch(&fixture.directory.join("foreign"), &launch)
        .is_err());
    Ok(())
}

#[test]
fn frozen_inbox_refuses_each_substituted_watermark_component() -> Result<()> {
    let fixture = Fixture::new()?;
    let turn = fixture.turn()?;
    let mut frozen = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?
    .shutdown()?;
    frozen.view(&turn)?;
    frozen.watermark.last_sequence += 1;
    assert!(frozen.view(&turn).is_err());
    frozen.watermark.last_sequence -= 1;
    let digest = std::mem::replace(&mut frozen.watermark.journal_digest, "foreign".into());
    assert!(frozen.view(&turn).is_err());
    frozen.watermark.journal_digest = digest;
    frozen.watermark.journal_instance = "foreign".into();
    assert!(frozen.view(&turn).is_err());
    Ok(())
}

#[test]
fn frozen_inbox_rejects_foreign_instance_generation_attempt_and_turn_owner() -> Result<()> {
    let fixture = Fixture::new()?;
    let turn = fixture.turn()?;
    let frozen = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?
    .shutdown()?;
    for label in [
        "instance",
        "generation",
        "attempt",
        "turn",
        "same-labels-new-owner",
    ] {
        let mut binding = fixture.binding.clone();
        let mut number = 1;
        match label {
            "instance" => binding.state_instance = "foreign".into(),
            "generation" => binding.generation = "foreign".into(),
            "attempt" => binding.attempt = 2,
            "turn" => number = 2,
            _ => (),
        }
        let foreign = WorkerInboxTurn::new(binding, number, fixture.resources())?;
        assert!(frozen.view(&foreign).is_err(), "{label}");
    }
    assert!(WorkerInboxTurn::new(fixture.binding.clone(), 0, fixture.resources()).is_err());
    Ok(())
}

#[test]
fn frozen_inbox_refuses_recovered_and_previously_reserved_records() -> Result<()> {
    for status in [
        WorkerRequestStatus::Queued,
        WorkerRequestStatus::Reserved,
        WorkerRequestStatus::Completed,
        WorkerRequestStatus::Failed,
    ] {
        let fixture = Fixture::new()?;
        let turn = fixture.turn()?;
        let mut inbox = fixture.inbox(false)?;
        inbox.submit("request", "worker")?;
        if status != WorkerRequestStatus::Queued {
            inbox.transition("request", WorkerRequestStatus::Reserved)?;
            if status != WorkerRequestStatus::Reserved {
                inbox.transition("request", status)?;
            }
        }
        assert!(
            WorkerInboxEndpoint::start(
                &fixture.directory,
                &turn,
                inbox,
                ProcessCancellation::new()
            )
            .is_err(),
            "pre-turn record {status:?}"
        );
        let recovered = fixture.inbox(true)?;
        let fresh_turn = fixture.turn()?;
        assert!(WorkerInboxEndpoint::start(
            &fixture.directory,
            &fresh_turn,
            recovered,
            ProcessCancellation::new()
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn frozen_inbox_refuses_substituted_and_revoked_resources() -> Result<()> {
    let fixture = Fixture::new()?;
    let foreign = Fixture::new()?;
    for kind in ["repo", "lease", "store", "claim", "parent", "run"] {
        let mut resources = fixture.resources();
        let mut claim = fixture.claim.clone();
        claim.token = crate::sync::ClaimToken::from_u64(claim.token.get() + 1);
        let mut parent = fixture.parent.clone();
        parent.assigned_paths.push(PathBuf::from("widened"));
        let mut binding = fixture.binding.clone();
        match kind {
            "repo" => resources.repo = &foreign.repo,
            "lease" => resources.lease = &foreign.lease,
            "store" => resources.claims = &foreign.claims,
            "claim" => resources.claim = &claim,
            "parent" => resources.parent = &parent,
            "run" => binding.run = "foreign".into(),
            _ => unreachable!(),
        }
        assert!(
            WorkerInboxTurn::new(binding, 1, resources).is_err(),
            "{kind}"
        );
    }
    let turn = fixture.turn()?;
    let frozen = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?
    .shutdown()?;
    fixture.claims.release(fixture.claim.token)?;
    assert!(frozen.view(&turn).is_err());
    // A new claim for identical paths must not resurrect the old token.
    fixture.claims.claim_paths_for_run(
        &RunId::new("run")?,
        "parent",
        &fixture.parent.assigned_paths,
    )?;
    assert!(frozen.view(&turn).is_err());
    Ok(())
}

#[test]
fn frozen_inbox_refuses_journal_tamper_and_reuse_of_turn() -> Result<()> {
    let fixture = Fixture::new()?;
    let turn = fixture.turn()?;
    let endpoint = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?;
    let frozen = endpoint.shutdown()?;
    // Test the one-shot guard using the same live handle, accessible only inside
    // this module's tests. Production exposes no unfreeze/into_inbox operation.
    let FrozenWorkerInbox { inbox, .. } = frozen;
    assert!(WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        inbox,
        ProcessCancellation::new()
    )
    .is_err());

    let fixture = Fixture::new()?;
    let turn = fixture.turn()?;
    let frozen = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?
    .shutdown()?;
    let path = frozen.inbox.root.direct_child(&frozen.inbox.file_name)?;
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)?
        .write_all(b"{}\n")?;
    assert!(frozen.view(&turn).is_err());
    Ok(())
}

#[test]
fn frozen_inbox_refuses_revocation_at_transfer_and_lost_session_after_transfer() -> Result<()> {
    let fixture = Fixture::new()?;
    let turn = fixture.turn()?;
    let endpoint = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?;
    assert_eq!(submit(&endpoint.launch(), "request", "worker")?["ok"], true);
    fixture.claims.release(fixture.claim.token)?;
    assert!(endpoint.shutdown().is_err());
    let recovered = fixture.inbox(true)?;
    assert_eq!(recovered.requests()?.len(), 1);
    assert!(recovered.requires_reconciliation());

    let fixture = Fixture::new()?;
    let turn = fixture.turn()?;
    let frozen = WorkerInboxEndpoint::start(
        &fixture.directory,
        &turn,
        fixture.inbox(false)?,
        ProcessCancellation::new(),
    )?
    .shutdown()?;
    run_sessions().lock().unwrap().remove(&fixture.directory);
    assert!(frozen.view(&turn).is_err());
    Ok(())
}

#[test]
fn frozen_inbox_shutdown_race_includes_exactly_durable_submissions() -> Result<()> {
    const GUARD: Duration = Duration::from_secs(10);
    for boundary in [
        SubmitBoundary::BeforeAdmission,
        SubmitBoundary::BeforeAppend,
    ] {
        let fixture = Fixture::new()?;
        let turn = fixture.turn()?;
        let cancellation = ProcessCancellation::new();
        let inbox = fixture.inbox(false)?;
        let mut service =
            WorkerRequestIpc::new(inbox, fixture.binding.clone(), cancellation.child_scope());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let armed = Arc::new(AtomicBool::new(false));
        let observer_armed = Arc::clone(&armed);
        service.submit_observer = Some(Box::new(move |at| {
            if at == boundary && observer_armed.load(Ordering::Acquire) {
                entered_tx.send(())?;
                release_rx.lock().unwrap().recv_timeout(GUARD)?;
            }
            Ok(())
        }));
        let mut endpoint = WorkerInboxEndpoint::start_service(&fixture.directory, &turn, service)?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        endpoint.server.shutdown_observer = Some(shutdown_tx);
        let launch = endpoint.launch();
        assert_eq!(submit(&launch, "baseline", "other")?["ok"], true);
        let baseline = WorkerRequestRecord {
            request_id: "baseline".into(),
            worker_id: "other".into(),
            status: WorkerRequestStatus::Queued,
        };
        armed.store(true, Ordering::Release);
        let client = thread::spawn(move || submit(&launch, "request", "worker"));
        entered_rx.recv_timeout(GUARD)?;
        cancellation.cancel();
        let frozen = thread::scope(|scope| -> Result<_> {
            let (done_tx, done_rx) = mpsc::channel();
            let join = scope.spawn(move || {
                let result = endpoint.shutdown();
                done_tx.send(()).unwrap();
                result
            });
            shutdown_rx.recv_timeout(GUARD)?;
            assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
            release_tx.send(())?;
            done_rx.recv_timeout(GUARD)?;
            join.join().expect("shutdown panicked")
        })?;
        let response = client.join().expect("client panicked");
        let view = frozen.view(&turn)?;
        let expected_count = if boundary == SubmitBoundary::BeforeAppend {
            2
        } else {
            1
        };
        assert_eq!(view.requests.len(), expected_count);
        assert_eq!(view.requests[0], baseline);
        assert_eq!(view.watermark.last_sequence, expected_count);
        if expected_count == 2 {
            assert_eq!(view.requests[1].request_id, "request");
            assert_eq!(view.requests[1].worker_id, "worker");
            assert_eq!(view.requests[1].status, WorkerRequestStatus::Queued);
        }
        if let Ok(response) = response {
            assert_eq!(response["ok"], expected_count == 2);
        }
        let exact = view.requests.to_vec();
        drop(frozen);
        let recovered = fixture.inbox(true)?;
        assert_eq!(recovered.requests()?, exact);
        assert!(recovered.requires_reconciliation());
    }
    Ok(())
}
