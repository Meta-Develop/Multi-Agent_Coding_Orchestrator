//! Acceptance tests: env-bound assignment messaging IPC from a confined external-agent child.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use git2::Repository;
use serde_json::{json, Value};

use super::super::{
    default_supervisor_review_lenses, initialize_orchestration_event_journal, AgentRole,
    AssignmentBudgetPolicy, AssignmentMetadata, AssignmentPhase, AssignmentScheduleEntry,
    AssignmentSelectionSource, AutonomyKpiCollector, CodexRuntimeModelCatalog,
    OrchestratorAssignment, PathClaim, ReviewAggregationPolicy, RoleCategory, RoleModelSelection,
    RunBudgetLedger, RunBudgetLimits, RunDirs, RunId, RuntimeModelCatalog,
    SemanticCoordinationMode, SemanticIntentStore, SupervisorBudgetConfig,
    SupervisorConsultantPlan, SupervisorExecutionRuntime, SupervisorFieldGuidePrompt,
    SupervisorPlan, SupervisorPlanMetadata, SupervisorRunOptions, SupervisorRuntime,
    SupervisorWorktreeCreation, SyncStore, UnavailableModelFallback, WorktreeManager,
    SUPERVISOR_SCHEMA_VERSION,
};
use super::*;
use crate::account_authority::ManagedGrokAccountSelectionEvidence;
#[cfg(target_os = "linux")]
use crate::account_authority::{activate_cam_grok_test_harness, build_cam_grok_test_harness};
use crate::supervise::messaging_bridge::{
    initialize_supervisor_messaging_session, recover_supervisor_messaging_session,
    with_supervisor_messaging_session,
};
use crate::{
    artifacts::{state_auth::random_identifier, ArtifactRunWriter, RunArtifactFamily},
    external_agent::{
        run_external_agent_cancellable_reviewed, run_external_agent_nonpublishable_simulation,
        ExternalAgentCommand, ExternalAgentRun,
    },
    messaging::transport::{ENV_MESSAGE_ENDPOINT, ENV_MESSAGE_TOKEN},
    process_runner::{
        run_process, ContainmentPolicy, EnvironmentMode, ProcessCancellation, ProcessSpec,
        StdinMode, StreamCapture, WorkspaceAccess,
    },
    worktree::WorktreeRecord,
};

const CHILD_ENV: &str = "MACO_TEST_ASSIGNMENT_MESSAGING_CHILD";
/// Parent fixture process: runs `assignment_messaging_ipc_acceptance` in an isolated helper (not the IPC child probe).
const FIXTURE_HELPER_ENV: &str = "MACO_TEST_ASSIGNMENT_MESSAGING_FIXTURE_HELPER";
const VERIFIED_COMPLETION_MARKER: &str =
    "verified assignment IPC and disposable-peer isolation completed";
const PHASE_ENV: &str = "MACO_TEST_MESSAGING_PHASE";
const RESULT_ENV: &str = "MACO_TEST_RESULT_FILE";
const CHILD_PROBE_FILE: &str = "maco-messaging-child-probe";
/// Writable probe JSON outputs (assigned path); `.maco` stays read-only for the confined child.
const IPC_PROBE_RESULTS_DIR: &str = "ipc-probe-results";
const FIXTURE_MANIFEST_REL: &str = ".maco/assignment-messaging-fixture.env";
const FIXTURE_MANIFEST_EMBED: &str = "@@MACO_ASSIGNMENT_MESSAGING_FIXTURE_MANIFEST@@";
const FIXTURE_STREAM_EMBED: &str = "@@MACO_ASSIGNMENT_MESSAGING_FIXTURE_STREAM@@";
const DISPOSABLE_PEER_PID_ENV: &str = "MACO_TEST_DISPOSABLE_PEER_PID";
const DISPOSABLE_PEER_SECRET_ENV: &str = "MACO_TEST_DUMMY_PEER_SECRET";
const EXACT_FILTER_SIMULATED: &str =
    "supervise::assignment_execution::messaging_ipc_tests::assignment_messaging_ipc_at_least_once_from_simulated_grok_child";
const EXACT_FILTER_VERIFIED: &str =
    "supervise::assignment_execution::messaging_ipc_tests::assignment_messaging_grok_verified_process_peer_isolation_and_ipc";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessagingIpcLaunchKind {
    /// `ExternalExecutionRuntime::NonpublishableSimulation` — exercises fixture + TCP IPC only.
    Simulated,
    /// `ExternalExecutionRuntime::Verified` — host systemd ExternalGrok profile (production path).
    Verified,
}

const COORD_ID: &str = "child-coord";
const WORKER_ID: &str = "messaging-worker";
const CHANNEL_ID: &str = "assignment-ipc-test";
const RUN_SLUG: &str = "assignment-messaging-ipc";

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/runtime_adapter/grok")
}

fn fixture_helper_process_active() -> bool {
    std::env::var_os(FIXTURE_HELPER_ENV).as_deref() == Some(std::ffi::OsStr::new("1"))
}

#[cfg(target_os = "linux")]
fn run_messaging_ipc_fixture_helper_subprocess(
    exact_test_name: &str,
    require_verified_completion_marker: bool,
) -> Result<()> {
    const HELPER_STDERR_MAX_BYTES: usize = 64 * 1024;
    const HELPER_STDOUT_MAX_BYTES: usize = 64 * 1024;

    let mut environment = BTreeMap::from([(FIXTURE_HELPER_ENV.to_string(), "1".to_string())]);
    for ambient_auth_override in ["GROK_AUTH_PATH", "MACO_GROK_AUTH_PATH", "GROK_HOME"] {
        if std::env::var_os(ambient_auth_override).is_some() {
            environment.insert(ambient_auth_override.to_string(), String::new());
        }
    }

    let output = run_process(
        ProcessSpec::direct(
            "exact assignment messaging IPC fixture helper test",
            std::env::current_exe().context("current test executable")?,
            [
                "--exact",
                exact_test_name,
                "--nocapture",
                "--test-threads=1",
            ],
            std::env::current_dir().context("current directory")?,
            HELPER_STDERR_MAX_BYTES,
        )
        .with_environment(EnvironmentMode::InheritAndSet(environment))
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(Duration::from_secs(180)))
        .with_stdout(StreamCapture::bounded(HELPER_STDOUT_MAX_BYTES))
        .with_stderr(StreamCapture::bounded(HELPER_STDERR_MAX_BYTES)),
    )
    .context("spawn exact assignment messaging IPC fixture helper test")?;

    let stderr = String::from_utf8_lossy(output.stderr.as_bytes());
    let stdout = String::from_utf8_lossy(output.stdout.as_bytes());
    if !output
        .status
        .as_ref()
        .is_some_and(|status| status.success())
        || output.timed_out
        || output.process_error.is_some()
        || output.stdin_error.is_some()
    {
        bail!(
            "assignment messaging IPC fixture helper failed; stderr:\n{stderr}\nstdout:\n{stdout}"
        );
    }
    if require_verified_completion_marker && !stdout.contains(VERIFIED_COMPLETION_MARKER) {
        bail!(
            "verified assignment messaging fixture helper missing completion marker; stderr:\n{stderr}\nstdout:\n{stdout}"
        );
    }
    if require_verified_completion_marker {
        println!("{VERIFIED_COMPLETION_MARKER}");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_messaging_ipc_fixture_helper_subprocess(
    _exact_test_name: &str,
    _require_verified_completion_marker: bool,
) -> Result<()> {
    bail!("assignment messaging IPC fixture helper requires Linux");
}

fn ipc_exchange(endpoint: &str, bearer: &str, request: Value) -> Result<Value> {
    let mut stream =
        TcpStream::connect(endpoint).context("confined child connect to assignment messaging")?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let line = serde_json::to_string(&json!({ "bearer": bearer, "request": request }))?;
    stream.write_all(line.as_bytes())?;
    stream.write_all(b"\n")?;
    let response = read_ndjson_line(&mut stream)?;
    serde_json::from_slice(&response).context("assignment messaging response JSON")
}

fn read_ndjson_line(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut byte = [0_u8; 1];
    while buffer.len() < 64 * 1024 {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buffer.push(byte[0]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
    if buffer.is_empty() {
        bail!("assignment messaging response was empty");
    }
    Ok(buffer)
}

fn external_run_succeeded(kind: MessagingIpcLaunchKind, report: &ExternalAgentRun) -> bool {
    match kind {
        MessagingIpcLaunchKind::Simulated => report.simulation_succeeded(),
        MessagingIpcLaunchKind::Verified => {
            report.exit_code == Some(0)
                && report.error.is_none()
                && !report.timed_out
                && report
                    .side_effects
                    .as_ref()
                    .is_some_and(|evidence| evidence.is_verified())
                && report
                    .process_tree
                    .as_ref()
                    .is_some_and(|evidence| evidence.is_verified_empty())
        }
    }
}

fn assert_external_run(
    label: &str,
    kind: MessagingIpcLaunchKind,
    report: &ExternalAgentRun,
    expected_verified_cam_binding: Option<&ManagedGrokAccountSelectionEvidence>,
) {
    if external_run_succeeded(kind, report) {
        if kind == MessagingIpcLaunchKind::Verified {
            let expected = expected_verified_cam_binding
                .expect("verified IPC fixture must specify its selected-account binding");
            assert_eq!(
                report.managed_grok_selection_evidence(),
                Some(expected),
                "{label}: verified Grok run must retain fixture selected-account evidence"
            );
        }
        return;
    }
    let launch = match kind {
        MessagingIpcLaunchKind::Simulated => "nonpublishable_simulation",
        MessagingIpcLaunchKind::Verified => "verified_external_agent",
    };
    panic!(
        "{label} ({launch}): exit_code={:?} timed_out={} error={:?} command={:?} cwd={:?} process_tree={:?} side_effects={:?} stdout_redacted={:?} stderr_redacted={:?}",
        report.exit_code,
        report.timed_out,
        report.error,
        report.command,
        report.cwd,
        report.process_tree,
        report.side_effects,
        report.stdout.text,
        report.stderr.text,
    );
}

fn run_external_agent_for_ipc_kind(
    kind: MessagingIpcLaunchKind,
    command: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    review: Option<ExternalPreActionReviewRuntime<'_>>,
) -> ExternalAgentRun {
    match kind {
        MessagingIpcLaunchKind::Simulated => run_external_agent_nonpublishable_simulation(command),
        MessagingIpcLaunchKind::Verified => {
            run_external_agent_cancellable_reviewed(command, cancellation, review)
        }
    }
}

fn refuse_disposable_peer_environ_exfiltration(peer_pid: u32) -> Result<()> {
    let environ = format!("/proc/{}/environ", peer_pid);
    match fs::read(&environ) {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "disposable peer process {} is not visible to the confined child",
                peer_pid
            )
        }
        Err(error) => bail!("unexpected read of {}: {error}", environ),
        Ok(bytes) => bail!(
            "confined child must not read disposable peer environ (observed {} bytes)",
            bytes.len()
        ),
    }
}

fn launch_environment(environment: &BTreeMap<String, String>) -> Result<(String, String)> {
    let endpoint = environment
        .get(ENV_MESSAGE_ENDPOINT)
        .context("missing MACO_MESSAGE_ENDPOINT in child environment")?
        .clone();
    let bearer = environment
        .get(ENV_MESSAGE_TOKEN)
        .context("missing MACO_MESSAGE_TOKEN in child environment")?
        .clone();
    Ok((endpoint, bearer))
}

fn confined_child_probe() -> Result<()> {
    let phase = std::env::var(PHASE_ENV).context("missing messaging child phase")?;
    let result_path = PathBuf::from(std::env::var(RESULT_ENV).context("missing result file")?);
    if let Ok(peer_pid) = std::env::var(DISPOSABLE_PEER_PID_ENV) {
        let peer_pid = peer_pid
            .parse::<u32>()
            .context("disposable peer pid must be a decimal process id")?;
        refuse_disposable_peer_environ_exfiltration(peer_pid)?;
    }
    let environment = std::env::vars().collect::<BTreeMap<_, _>>();
    let (endpoint, bearer) = launch_environment(&environment)?;
    let mut outcome = json!({ "phase": phase });

    match phase.as_str() {
        "receive_record_no_ack" => {
            let response =
                ipc_exchange(&endpoint, &bearer, json!({ "operation": "receive_next" }))?;
            let message_id = response
                .get("result")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .context("receive_next result id")?;
            outcome["message_id"] = json!(message_id);
            outcome["ok"] = json!(response.get("ok") == Some(&Value::Bool(true)));
        }
        "receive_ack_suppresses" => {
            let first = ipc_exchange(&endpoint, &bearer, json!({ "operation": "receive_next" }))?;
            let message_id = first
                .get("result")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .context("first receive id")?;
            let ack = ipc_exchange(
                &endpoint,
                &bearer,
                json!({ "operation": "acknowledge", "message_id": message_id }),
            )?;
            let second = ipc_exchange(&endpoint, &bearer, json!({ "operation": "receive_next" }))?;
            outcome["message_id"] = json!(message_id);
            outcome["ack_ok"] = json!(ack.get("ok") == Some(&Value::Bool(true)));
            outcome["second_empty"] = json!(second.get("result").is_some_and(Value::is_null));
        }
        "send_direct_and_channel" => {
            let direct = ipc_exchange(
                &endpoint,
                &bearer,
                json!({
                    "operation": "send_direct",
                    "recipient_id": COORD_ID,
                    "payload": { "from": WORKER_ID, "kind": "direct" }
                }),
            )?;
            let channel = ipc_exchange(
                &endpoint,
                &bearer,
                json!({
                    "operation": "receive_next_from_channel",
                    "channel_id": CHANNEL_ID
                }),
            )?;
            outcome["direct_ok"] = json!(direct.get("ok") == Some(&Value::Bool(true)));
            outcome["channel_ok"] = json!(channel.get("ok") == Some(&Value::Bool(true)));
        }
        "refuse_wrong_bearer" => {
            let response = ipc_exchange(
                &endpoint,
                "definitely-not-the-assignment-messaging-bearer-token",
                json!({ "operation": "receive_next" }),
            )?;
            outcome["refused"] = json!(response.get("ok") == Some(&Value::Bool(false)));
            outcome["error"] = response.get("error").cloned().unwrap_or(Value::Null);
        }
        other => bail!("unknown messaging child phase {:?}", other),
    }

    fs::write(&result_path, serde_json::to_vec(&outcome)?)?;
    Ok(())
}

fn commit_fixture_repository(path: &Path) {
    let repo = Repository::open(path).expect("open fixture repository");
    let mut index = repo.index().expect("fixture index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage fixture README");
    index.write().expect("write fixture index");
    let tree_id = index.write_tree().expect("write fixture tree");
    let tree = repo.find_tree(tree_id).expect("read fixture tree");
    let signature =
        git2::Signature::now("maco test", "maco-test@example.invalid").expect("fixture signature");
    repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
        .expect("commit fixture");
}

fn messaging_plan_and_metadata() -> (SupervisorPlan, SupervisorPlanMetadata) {
    let coord = OrchestratorAssignment {
        id: COORD_ID.to_string(),
        phase: AssignmentPhase::Execution,
        runtime: None,
        role: AgentRole::ChildOrchestrator,
        role_category: None,
        selection_source: None,
        assigned_paths: vec![PathBuf::from("README.md")],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: None,
        worker_assignments: Vec::new(),
        environment_requirements: Vec::new(),
        licensed_breakage: None,
        notes: None,
        decision_refs: Vec::new(),
    };
    let worker = OrchestratorAssignment {
        id: WORKER_ID.to_string(),
        phase: AssignmentPhase::Execution,
        runtime: None,
        role: AgentRole::Worker,
        role_category: Some(RoleCategory::NonDelegatingTerminalWorker),
        selection_source: Some(AssignmentSelectionSource::Automatic),
        assigned_paths: vec![
            PathBuf::from("README.md"),
            PathBuf::from(IPC_PROBE_RESULTS_DIR),
        ],
        semantic_symbols: Vec::new(),
        semantic_modules: Vec::new(),
        task: None,
        worker_assignments: Vec::new(),
        environment_requirements: Vec::new(),
        licensed_breakage: None,
        notes: None,
        decision_refs: Vec::new(),
    };
    let mut plan = SupervisorPlan {
        version: SUPERVISOR_SCHEMA_VERSION,
        task: "assignment messaging ipc".to_string(),
        task_file: None,
        max_depth: 2,
        max_child_assignments: 2,
        max_child_retries: 0,
        max_gate_corrections: 0,
        child_timeout_seconds: 30,
        semantic_coordination: SemanticCoordinationMode::Off,
        role_models: BTreeMap::new(),
        model_pricing: BTreeMap::new(),
        review_lenses: default_supervisor_review_lenses(),
        review_lens_correlation: Default::default(),
        review_aggregation_policy: ReviewAggregationPolicy::AllMustAccept,
        assignments: vec![coord, worker],
    };
    plan.role_models.insert(
        AgentRole::Worker,
        RoleModelSelection {
            model: Some("grok-4.6".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let metadata = SupervisorPlanMetadata {
        assignment_schedule: vec![
            AssignmentScheduleEntry {
                assignment_id: COORD_ID.to_string(),
                parent_assignment_id: None,
                depth: 1,
                flattened_index: 0,
            },
            AssignmentScheduleEntry {
                assignment_id: WORKER_ID.to_string(),
                parent_assignment_id: None,
                depth: 1,
                flattened_index: 1,
            },
        ],
        ..SupervisorPlanMetadata::default()
    };
    (plan, metadata)
}

fn seed_direct_coord_to_worker(run_directory: &Path) -> Result<String> {
    with_supervisor_messaging_session(run_directory, |factory| {
        let coordinator = factory.capability_for(COORD_ID)?;
        let mut broker = factory.open_or_create()?;
        let direct = broker.send_direct(
            &coordinator,
            WORKER_ID,
            json!({ "kind": "direct", "probe": "ipc-acceptance" }),
        )?;
        Ok(direct.id.to_string())
    })
}

fn seed_exchange_channel_message(run_directory: &Path) -> Result<()> {
    with_supervisor_messaging_session(run_directory, |factory| {
        let coordinator = factory.capability_for(COORD_ID)?;
        let mut broker = factory.open_or_create()?;
        broker.create_channel(&coordinator, CHANNEL_ID, [COORD_ID, WORKER_ID], [COORD_ID])?;
        broker.publish_channel(
            &coordinator,
            CHANNEL_ID,
            json!({ "kind": "broadcast", "probe": "ipc-exchange" }),
        )?;
        Ok(())
    })
}

fn receive_worker_message_id(run_directory: &Path) -> Result<String> {
    with_supervisor_messaging_session(run_directory, |factory| {
        let worker = factory.capability_for(WORKER_ID)?;
        let mut broker = factory.open_or_create()?;
        let envelope = broker
            .receive_next(&worker)?
            .context("worker durable queue must still hold the unacknowledged message")?;
        Ok(envelope.id.to_string())
    })
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn messaging_fixture_manifest_path(worktree: &Path) -> PathBuf {
    worktree.join(FIXTURE_MANIFEST_REL)
}

fn probe_result_path(worktree: &Path, phase_slug: &str) -> PathBuf {
    worktree
        .join(IPC_PROBE_RESULTS_DIR)
        .join(format!("{phase_slug}.json"))
}

struct MessagingGrokWritableAdmissionBinding {
    runtime: SupervisorRuntime,
    worktree_record: WorktreeRecord,
    claim: PathClaim,
}

struct MessagingAdmittedGrokWorkerAssignment<'a> {
    repo: &'a Path,
    run_id: &'a RunId,
    assignment: &'a OrchestratorAssignment,
    policy: &'a AssignmentBudgetPolicy,
    plan: &'a SupervisorPlan,
    options: &'a SupervisorRunOptions,
    catalog: &'a RuntimeModelCatalog,
}

struct MessagingAdmittedGrokWorkerPaths<'a> {
    primary: &'a Path,
    worktree: &'a WorktreeRecord,
    claim: &'a PathClaim,
    authenticated_claims: &'a [PathClaim],
    prompt: &'a Path,
    incoming: &'a Path,
    provider: &'a Path,
    worker_schema_path: &'a Path,
}

struct MessagingGrokChildProbeFixture<'a> {
    fixture_manifest: &'a Path,
    exact_filter: &'a str,
    phase: &'a str,
    result_file: &'a Path,
    child_probe_binary: &'a Path,
    disposable_peer_pid: Option<u32>,
}

/// Parent-owned secure-output targets must be unique per external-agent launch; re-reserving the
/// same `incoming/report.json` fails simulation after the first phase. Writable Grok confinement
/// proof snapshots those paths, so admission must be re-sealed on the final command each phase.
fn rebind_grok_phase_launch_and_writable_admission(
    command: &mut ExternalAgentCommand,
    incoming: &Path,
    phase_slug: &str,
    assignment: &OrchestratorAssignment,
    binding: &MessagingGrokWritableAdmissionBinding,
) -> Result<()> {
    let phase_incoming = incoming.join(phase_slug);
    fs::create_dir_all(&phase_incoming)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&phase_incoming, fs::Permissions::from_mode(0o700))?;
    }
    command.json_log = phase_incoming.join("events.jsonl");
    command.output_last_message = phase_incoming.join("report.json");
    bind_grok_fixture_writable_admission(command, assignment, binding)
}

fn bind_grok_fixture_writable_admission(
    command: &mut ExternalAgentCommand,
    assignment: &OrchestratorAssignment,
    binding: &MessagingGrokWritableAdmissionBinding,
) -> Result<()> {
    let admission = super::worktree_writable_admission_record(
        &assignment.id,
        &assignment.assigned_paths,
        1,
        &binding.worktree_record,
        &binding.claim,
        std::slice::from_ref(&binding.claim),
        command,
        binding.runtime,
        assignment.phase,
    )?
    .context("rebind writable Grok admission for messaging IPC phase")?;
    *command = command
        .clone()
        .with_worktree_writable_confinement(admission);
    Ok(())
}

fn write_messaging_fixture_manifest(
    manifest: &Path,
    probe_binary: &Path,
    exact_filter: &str,
    phase: &str,
    result_file: &Path,
    disposable_peer_pid: Option<u32>,
) -> Result<()> {
    if let Some(parent) = manifest.parent() {
        fs::create_dir_all(parent)?;
    }
    let peer = disposable_peer_pid
        .map(|pid| pid.to_string())
        .unwrap_or_default();
    let body = format!(
        "PROBE_BINARY={}\nEXACT_FILTER={}\nPHASE={}\nRESULT_FILE={}\nDISPOSABLE_PEER_PID={}\n",
        shell_single_quote(
            probe_binary
                .to_str()
                .context("probe binary path is not UTF-8")?
        ),
        shell_single_quote(exact_filter),
        shell_single_quote(phase),
        shell_single_quote(
            result_file
                .to_str()
                .context("result file path is not UTF-8")?
        ),
        shell_single_quote(&peer),
    );
    fs::write(manifest, body)?;
    Ok(())
}

fn install_confined_child_probe_binary(worktree: &Path) -> Result<PathBuf> {
    let probe = worktree.join(CHILD_PROBE_FILE);
    fs::copy(
        std::env::current_exe().context("current test executable")?,
        &probe,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o700))?;
    }
    Ok(probe)
}

struct DisposablePeerProcess {
    child: std::process::Child,
    dummy_secret: String,
}

impl DisposablePeerProcess {
    fn spawn() -> Result<Self> {
        use std::process::{Command, Stdio};
        let dummy_secret = random_identifier().context("disposable peer dummy secret")?;
        let child = Command::new("sh")
            .arg("-c")
            .arg("exec sleep 300")
            .env_clear()
            .env(DISPOSABLE_PEER_SECRET_ENV, &dummy_secret)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn env-cleared disposable peer sleeper")?;
        Ok(Self {
            child,
            dummy_secret,
        })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn assert_secret_not_in_captured_output(&self, report: &ExternalAgentRun) {
        assert!(
            !report.stdout.text.contains(&self.dummy_secret),
            "stdout must not leak disposable peer dummy secret"
        );
        assert!(
            !report.stderr.text.contains(&self.dummy_secret),
            "stderr must not leak disposable peer dummy secret"
        );
    }
}

impl Drop for DisposablePeerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn install_grok_provider_fixture(fixture_manifest: &Path) -> Result<(tempfile::TempDir, PathBuf)> {
    let temp = tempfile::tempdir()?;
    let fixture_dir = fixture_root();
    let provider = fixture_dir.join("assignment-messaging-provider.sh");
    let stream = fixture_dir.join("assignment-messaging-provider.streaming-json");
    let installed = temp.path().join("grok");
    let manifest_embed = shell_single_quote(
        fixture_manifest
            .to_str()
            .context("assignment messaging fixture manifest path is not UTF-8")?,
    );
    // The exact executable is visible; its sibling data files intentionally are not.
    let stream_embed = shell_single_quote(&fs::read_to_string(&stream)?.replace("\r\n", "\n"));
    // Windows checkouts may use CRLF; the Linux shebang must end with LF.
    fs::write(
        &installed,
        fs::read_to_string(&provider)?
            .replace("\r\n", "\n")
            .replace(FIXTURE_MANIFEST_EMBED, &manifest_embed)
            .replace(FIXTURE_STREAM_EMBED, &stream_embed),
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755))?;
    }
    Ok((temp, installed))
}

fn set_grok_bin(program: &Path) {
    // SAFETY: test-only MACO_GROK_BIN mutation.
    unsafe {
        std::env::set_var("MACO_GROK_BIN", program);
    }
}

fn build_admitted_grok_worker_command(
    assignment: &MessagingAdmittedGrokWorkerAssignment<'_>,
    paths: &MessagingAdmittedGrokWorkerPaths<'_>,
) -> Result<(ExternalAgentCommand, MessagingGrokWritableAdmissionBinding)> {
    let managed_child = &paths.worktree.path;
    set_grok_bin(paths.provider);
    let initial_command = ExternalAgentCommand::codex(
        "unused-codex",
        managed_child,
        paths.prompt,
        paths.incoming.join("events.jsonl"),
        paths.incoming.join("report.json"),
        Duration::from_secs(20),
    )
    .with_hidden_root(paths.primary)
    .with_agent_lifecycle(
        assignment.repo,
        AgentRole::Worker.as_str(),
        assignment.run_id.as_str(),
        WORKER_ID,
    );
    let (runtime, mut command) = bind_selected_assignment_launch_for_test(
        initial_command,
        assignment.assignment,
        assignment.policy,
        assignment.plan,
        assignment.options,
        assignment.catalog,
    )?;
    command.cwd = paths.primary.to_path_buf();
    command.workspace_access = WorkspaceAccess::ReadOnly;
    let command =
        bind_runtime_output_schema(command, SupervisorRuntime::Grok, paths.worker_schema_path)?;
    let command = bind_selected_grok_execution_workspace(
        command,
        assignment.assignment,
        runtime,
        managed_child,
        true,
    )?;
    let admission = worktree_writable_admission_record(
        &assignment.assignment.id,
        &assignment.assignment.assigned_paths,
        1,
        paths.worktree,
        paths.claim,
        paths.authenticated_claims,
        &command,
        runtime,
        assignment.assignment.phase,
    )?
    .context("writable Grok admission for messaging IPC fixture")?;
    let binding = MessagingGrokWritableAdmissionBinding {
        runtime,
        worktree_record: paths.worktree.clone(),
        claim: paths.claim.clone(),
    };
    Ok((
        command.with_worktree_writable_confinement(admission),
        binding,
    ))
}

fn run_grok_child_phase(
    launch_kind: MessagingIpcLaunchKind,
    incoming: &Path,
    phase_slug: &str,
    admission_binding: &MessagingGrokWritableAdmissionBinding,
    context: &AssignmentExecutionContext<'_, '_>,
    probe: &MessagingGrokChildProbeFixture<'_>,
    command: &mut ExternalAgentCommand,
) -> Result<ExternalAgentRun> {
    rebind_grok_phase_launch_and_writable_admission(
        command,
        incoming,
        phase_slug,
        context.assignment,
        admission_binding,
    )?;
    write_messaging_fixture_manifest(
        probe.fixture_manifest,
        probe.child_probe_binary,
        probe.exact_filter,
        probe.phase,
        probe.result_file,
        probe.disposable_peer_pid,
    )?;
    let server = bind_assignment_messaging_for_external_child_launch(context, WORKER_ID, command)?;
    let report = run_external_agent_for_ipc_kind(launch_kind, command, &context.cancellation, None);
    drop(server);
    Ok(report)
}

fn assert_token_absent_from_artifacts(command: &ExternalAgentCommand, token: &str) -> Result<()> {
    let prompt = fs::read_to_string(&command.prompt)?;
    assert!(
        !prompt.contains(token),
        "prompt must not persist the messaging bearer"
    );
    if command.json_log.exists() {
        let log = fs::read_to_string(&command.json_log)?;
        assert!(!log.contains(token), "json log leaked messaging bearer");
    }
    Ok(())
}

fn messaging_ipc_simulated_external_runner(
    command: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    review: Option<ExternalPreActionReviewRuntime<'_>>,
) -> ExternalAgentRun {
    run_external_agent_for_ipc_kind(
        MessagingIpcLaunchKind::Simulated,
        command,
        cancellation,
        review,
    )
}

fn messaging_ipc_verified_external_runner(
    command: &ExternalAgentCommand,
    cancellation: &ProcessCancellation,
    review: Option<ExternalPreActionReviewRuntime<'_>>,
) -> ExternalAgentRun {
    run_external_agent_for_ipc_kind(
        MessagingIpcLaunchKind::Verified,
        command,
        cancellation,
        review,
    )
}

fn bail_assignment_execution_completed(
    stage: &str,
    outcome: &AssignmentExecutionOutcome,
) -> Result<()> {
    let findings = outcome
        .findings
        .iter()
        .map(|finding| format!("{:?}: {}", finding.severity, finding.message))
        .collect::<Vec<_>>()
        .join("; ");
    let health = outcome
        .health_signals
        .iter()
        .map(|signal| format!("{signal:?}"))
        .collect::<Vec<_>>()
        .join("; ");
    bail!(
        "{stage}: assignment execution completed early; assignment_failed={} fatal_error={:?} findings=[{findings}] health=[{health}]",
        outcome.assignment_failed,
        outcome.fatal_error,
    );
}

fn messaging_token_from_command(command: &ExternalAgentCommand) -> Result<String> {
    let launch = command
        .assignment_messaging_launch()
        .context("messaging launch must be bound on command")?;
    let identity = command
        .agent_lifecycle
        .as_ref()
        .context("lifecycle identity")?;
    launch
        .environment_for(&identity.run_id, &identity.task_id)?
        .into_iter()
        .find(|(key, _)| key == ENV_MESSAGE_TOKEN)
        .map(|(_, value)| value)
        .context("missing MACO_MESSAGE_TOKEN in launch environment")
}

fn assignment_messaging_ipc_acceptance(
    launch_kind: MessagingIpcLaunchKind,
    exact_filter: &'static str,
    disposable_peer: Option<DisposablePeerProcess>,
    expected_verified_cam_binding: Option<&ManagedGrokAccountSelectionEvidence>,
) -> Result<()> {
    let (plan, metadata) = messaging_plan_and_metadata();
    let temp = tempfile::tempdir()?;
    let repo = temp.path().join("repo");
    Repository::init(&repo)?;
    fs::write(repo.join("README.md"), "baseline\n")?;
    commit_fixture_repository(&repo);

    let run_id = RunId::new(RUN_SLUG)?;
    let mut artifact_writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "assignment-messaging-ipc",
    )?;
    let run_dir = artifact_writer.run_dir().to_path_buf();
    let dirs = RunDirs::for_writer(&artifact_writer);
    initialize_supervisor_messaging_session(&mut artifact_writer, &plan, &metadata)?;

    seed_direct_coord_to_worker(&run_dir)?;

    let primary = temp.path().join("primary");
    let incoming = temp.path().join("incoming");
    fs::create_dir_all(&primary)?;
    fs::create_dir_all(&incoming)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&primary, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
    }
    let manager = WorktreeManager::new(&repo);

    let machine_state = temp.path().join("machine-global-state");
    let machine_runtime = temp.path().join("machine-runtime");
    for directory in [&machine_state, &machine_runtime] {
        fs::create_dir(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
    }
    let machine_config = temp.path().join("machine-global.json");
    fs::write(
        &machine_config,
        serde_json::to_vec(&json!({
            "version": 1,
            "state_root": machine_state,
            "roots": [{"id": "runtime", "path": machine_runtime,
                       "protected_paths": [], "quarantine_grace_seconds": 60}]
        }))?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&machine_config, fs::Permissions::from_mode(0o600))?;
    }
    crate::machine_global::MachineGlobalStore::open_config(&machine_config)?;

    let options = SupervisorRunOptions {
        repo: repo.clone(),
        plan_file: temp.path().join("plan.json"),
        run_id,
        parent_node: None,
        codex_bin: PathBuf::from("unused-codex"),
        runtime: SupervisorRuntime::Codex,
        allow_dirty_primary: false,
        allow_live_run_collision: false,
        admission_overrides: crate::supervise::SupervisorAdmissionConfig::default(),
        budget_overrides: RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: Some(crate::machine_global::MachineGlobalRetentionBinding {
            config: machine_config,
            root_id: "runtime".to_string(),
            owner: "maco-supervise".to_string(),
            correction_correlation_id: RUN_SLUG.to_string(),
        }),
    };

    let assignment = plan
        .assignments
        .iter()
        .find(|assignment| assignment.id == WORKER_ID)
        .context("worker assignment")?;
    let mut budget_policy = AssignmentBudgetPolicy::default();
    budget_policy.set_selector_binding_for_test(
        AgentRole::Worker,
        SupervisorRuntime::Grok,
        RoleModelSelection {
            model: Some("grok-4.6".to_string()),
            reasoning_effort: Some("xhigh".to_string()),
            unavailable_model_fallback: UnavailableModelFallback::FailClosed,
        },
    );
    let launch_plan = budget_policy.apply(&plan);
    let runtime_model_catalog =
        RuntimeModelCatalog::Codex(CodexRuntimeModelCatalog::from_slugs(["gpt-5.6-codex"])?);
    let worker_schema_path = dirs.schemas.join("worker-report.schema.json");
    let schema_path = dirs.schemas.join("orchestrator-review-report.schema.json");
    let auditor_schema_path = dirs.schemas.join("auditor-report.schema.json");
    fs::create_dir_all(&dirs.schemas)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dirs.schemas, fs::Permissions::from_mode(0o700))?;
    }
    fs::copy(
        fixture_root().join("writable-managed-child.schema.json"),
        &worker_schema_path,
    )?;
    fs::write(&schema_path, "{\"type\":\"object\"}\n")?;
    fs::write(&auditor_schema_path, "{\"type\":\"object\"}\n")?;

    let sync_store = SyncStore::open(&repo)?;
    let assignment_schedule = metadata.assignment_schedule.clone();
    let field_guide = SupervisorFieldGuidePrompt::empty()?;
    let budget_ledger = RunBudgetLedger::new(RunBudgetLimits::default())?;
    let cancellation = ProcessCancellation::new();
    let mut journal = initialize_orchestration_event_journal(
        &repo,
        &options.run_id,
        options.parent_node.as_deref(),
    );
    let mut autonomy_kpis = AutonomyKpiCollector::default();
    let artifacts = Mutex::new(SharedSupervisorArtifacts {
        writer: &mut artifact_writer,
        journal: &mut journal,
        autonomy_kpis: &mut autonomy_kpis,
        checkpoint: None,
    });
    let budget_config = SupervisorBudgetConfig::default();
    let consultant = SupervisorConsultantPlan::default();
    let assignment_metadata = AssignmentMetadata::new();
    let semantic_store = SemanticIntentStore::open(&repo)?;
    let execution_runtime = match launch_kind {
        MessagingIpcLaunchKind::Simulated => SupervisorExecutionRuntime::NonpublishableSimulation,
        MessagingIpcLaunchKind::Verified => SupervisorExecutionRuntime::Verified,
    };
    let context = AssignmentExecutionContext {
        index: 1,
        concurrent_mode: false,
        plan: &launch_plan,
        requested_plan: &launch_plan,
        execution_target: None,
        budget_config: &budget_config,
        consultant: &consultant,
        assignment_metadata: &assignment_metadata,
        assignment,
        evidence_only_reaudit: None,
        options: &options,
        repo: &repo,
        run_dir: &run_dir,
        dirs: &dirs,
        execution_runtime,
        worktree_creation: SupervisorWorktreeCreation::TestOnly,
        manager: &manager,
        reused: false,
        sync_store: &sync_store,
        semantic_store: &semantic_store,
        prepared_semantic_token: None,
        prepared_semantic_findings: &[],
        prepared_semantic_signals: &[],
        prepared_semantic_failed: false,
        assignment_schedule: &assignment_schedule,
        field_guide: &field_guide,
        serial_semantic_warn_intents: None,
        semantic_block_order: None,
        semantic_block_gate: None,
        artifacts: &artifacts,
        budget_ledger: &budget_ledger,
        budget_policy,
        admission_commit: None,
        runtime_model_catalog: &runtime_model_catalog,
        cancellation,
        external_runner: match launch_kind {
            MessagingIpcLaunchKind::Simulated => &messaging_ipc_simulated_external_runner,
            MessagingIpcLaunchKind::Verified => &messaging_ipc_verified_external_runner,
        },
    };
    let mut outcome = AssignmentExecutionOutcome {
        gate_tracker: Some(GateCorrectionTracker::new(launch_plan.max_gate_corrections)),
        ..AssignmentExecutionOutcome::default()
    };
    let preflight = match prepare_assignment_execution(&context, &mut outcome)? {
        AssignmentExecutionDisposition::Continue(preflight) => preflight,
        AssignmentExecutionDisposition::Complete => {
            return bail_assignment_execution_completed("initial assignment preflight", &outcome);
        }
    };
    let worktree_root = preflight.worktree.path.clone();
    for protected_root in [".maco", ".maco-cache", ".codex", ".agents"] {
        fs::create_dir_all(worktree_root.join(protected_root))?;
    }
    let probe_results_dir = worktree_root.join(IPC_PROBE_RESULTS_DIR);
    fs::create_dir_all(&probe_results_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&probe_results_dir, fs::Permissions::from_mode(0o700))?;
    }
    let child_probe_binary = install_confined_child_probe_binary(&worktree_root)?;
    let fixture_manifest = messaging_fixture_manifest_path(&worktree_root);
    let (provider_temp, provider) = install_grok_provider_fixture(&fixture_manifest)?;
    let peer_pid = disposable_peer.as_ref().map(DisposablePeerProcess::pid);
    let prompt = worktree_root.join("prompt.md");
    fs::write(
        &prompt,
        crate::external_agent::render_prompt_with_assignment_messaging_protocol_appendix(
            "Exercise assignment messaging from a confined Grok child.\n".to_string(),
        )?,
    )?;
    let authenticated_claims = sync_store.snapshot()?;
    let grok_assignment = MessagingAdmittedGrokWorkerAssignment {
        repo: &repo,
        run_id: &options.run_id,
        assignment,
        policy: &context.budget_policy,
        plan: &launch_plan,
        options: &options,
        catalog: &runtime_model_catalog,
    };
    let grok_paths = MessagingAdmittedGrokWorkerPaths {
        primary: &primary,
        worktree: &preflight.worktree,
        claim: &preflight.claim,
        authenticated_claims: &authenticated_claims,
        prompt: &prompt,
        incoming: &incoming,
        provider: &provider,
        worker_schema_path: &worker_schema_path,
    };
    let (mut command, grok_admission_binding) =
        build_admitted_grok_worker_command(&grok_assignment, &grok_paths)?;

    let result_first = probe_result_path(&worktree_root, "first-receive");
    let first_probe = MessagingGrokChildProbeFixture {
        fixture_manifest: &fixture_manifest,
        exact_filter,
        phase: "receive_record_no_ack",
        result_file: &result_first,
        child_probe_binary: &child_probe_binary,
        disposable_peer_pid: peer_pid,
    };
    let first_report = run_grok_child_phase(
        launch_kind,
        &incoming,
        "phase-receive-record-no-ack",
        &grok_admission_binding,
        &context,
        &first_probe,
        &mut command,
    )?;
    assert_external_run(
        "grok child must complete first receive",
        launch_kind,
        &first_report,
        expected_verified_cam_binding,
    );
    if let Some(peer) = disposable_peer.as_ref() {
        peer.assert_secret_not_in_captured_output(&first_report);
    }
    let first_payload: Value =
        serde_json::from_slice(&fs::read(&result_first)?).context("first child result")?;
    let child_observed_id = first_payload
        .get("message_id")
        .and_then(Value::as_str)
        .context("child recorded message id")?;

    let parent_observed_id = receive_worker_message_id(&run_dir)?;
    assert_eq!(
        parent_observed_id, child_observed_id,
        "durable at-least-once queue must retain the same message id after child exit"
    );

    recover_supervisor_messaging_session(&run_dir)?;
    let result_second = probe_result_path(&worktree_root, "ack-suppresses");
    let second_probe = MessagingGrokChildProbeFixture {
        fixture_manifest: &fixture_manifest,
        exact_filter,
        phase: "receive_ack_suppresses",
        result_file: &result_second,
        child_probe_binary: &child_probe_binary,
        disposable_peer_pid: peer_pid,
    };
    let second_report = run_grok_child_phase(
        launch_kind,
        &incoming,
        "phase-receive-ack-suppresses",
        &grok_admission_binding,
        &context,
        &second_probe,
        &mut command,
    )?;
    assert_external_run(
        "grok child ack phase",
        launch_kind,
        &second_report,
        expected_verified_cam_binding,
    );
    let second_payload: Value = serde_json::from_slice(&fs::read(&result_second)?)?;
    assert_eq!(
        second_payload.get("message_id").and_then(Value::as_str),
        Some(child_observed_id)
    );
    assert_eq!(second_payload.get("second_empty"), Some(&json!(true)));

    seed_exchange_channel_message(&run_dir)?;
    let result_exchange = probe_result_path(&worktree_root, "send-exchange");
    let exchange_probe = MessagingGrokChildProbeFixture {
        fixture_manifest: &fixture_manifest,
        exact_filter,
        phase: "send_direct_and_channel",
        result_file: &result_exchange,
        child_probe_binary: &child_probe_binary,
        disposable_peer_pid: peer_pid,
    };
    let exchange_report = run_grok_child_phase(
        launch_kind,
        &incoming,
        "phase-send-direct-and-channel",
        &grok_admission_binding,
        &context,
        &exchange_probe,
        &mut command,
    )?;
    assert_external_run(
        "grok child exchange phase",
        launch_kind,
        &exchange_report,
        expected_verified_cam_binding,
    );
    let exchange_payload: Value = serde_json::from_slice(&fs::read(&result_exchange)?)?;
    assert_eq!(exchange_payload.get("direct_ok"), Some(&json!(true)));
    assert_eq!(exchange_payload.get("channel_ok"), Some(&json!(true)));

    let mut token_probe = command.clone();
    let _server =
        bind_assignment_messaging_for_external_child_launch(&context, WORKER_ID, &mut token_probe)?;
    let token = messaging_token_from_command(&token_probe)?;
    assert_token_absent_from_artifacts(&token_probe, &token)?;

    let result_refusal = probe_result_path(&worktree_root, "wrong-bearer");
    let refusal_probe = MessagingGrokChildProbeFixture {
        fixture_manifest: &fixture_manifest,
        exact_filter,
        phase: "refuse_wrong_bearer",
        result_file: &result_refusal,
        child_probe_binary: &child_probe_binary,
        disposable_peer_pid: peer_pid,
    };
    let refusal_report = run_grok_child_phase(
        launch_kind,
        &incoming,
        "phase-refuse-wrong-bearer",
        &grok_admission_binding,
        &context,
        &refusal_probe,
        &mut command,
    )?;
    assert_external_run(
        "grok child wrong-bearer phase",
        launch_kind,
        &refusal_report,
        expected_verified_cam_binding,
    );
    let refusal_payload: Value = serde_json::from_slice(&fs::read(&result_refusal)?)?;
    assert_eq!(refusal_payload.get("refused"), Some(&json!(true)));
    assert!(
        refusal_payload
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|error| !error.contains(&token)),
        "refusal must not echo bearer"
    );

    let mut prepared = match prepare_child_attempt(
        &context,
        &mut outcome,
        &context.budget_policy,
        &preflight,
        options.run_id.as_str(),
        1,
        1,
        &None,
        &schema_path,
        &worker_schema_path,
        &auditor_schema_path,
    )? {
        AssignmentExecutionDisposition::Continue(prepared) => prepared,
        AssignmentExecutionDisposition::Complete => {
            return bail_assignment_execution_completed(
                "prepare_child_attempt for dispatch",
                &outcome,
            );
        }
    };
    assert!(prepared.command.assignment_messaging_launch().is_none());
    let dispatch_result = probe_result_path(&worktree_root, "dispatch-child");
    if launch_kind == MessagingIpcLaunchKind::Simulated {
        // Simulation does not persist production writable admission. Use the same
        // authenticated claim without changing production-created artifact paths.
        bind_grok_fixture_writable_admission(
            &mut prepared.command,
            assignment,
            &grok_admission_binding,
        )?;
    }
    // This command has not launched yet. Keep the production-created report root,
    // journal paths and writable admission together for the actual dispatch.
    write_messaging_fixture_manifest(
        &fixture_manifest,
        &child_probe_binary,
        exact_filter,
        "receive_record_no_ack",
        &dispatch_result,
        peer_pid,
    )?;
    seed_direct_coord_to_worker(&run_dir)?;
    let scratch_paths = [
        prepared.incoming_scratch.path().to_path_buf(),
        prepared.capture_scratch.path().to_path_buf(),
    ];
    let collected = dispatch_and_collect_child_attempt(
        &context,
        &mut outcome,
        &preflight,
        options.run_id.as_str(),
        1,
        prepared,
    );
    match launch_kind {
        MessagingIpcLaunchKind::Verified => {
            let collected = collected?;
            assert_external_run(
                "dispatch external runner must succeed",
                launch_kind,
                &collected.external_run,
                expected_verified_cam_binding,
            );
            if let Some(peer) = disposable_peer.as_ref() {
                peer.assert_secret_not_in_captured_output(&collected.external_run);
            }
            assert_eq!(
                collected.external_run.command.first().map(String::as_str),
                provider.to_str(),
                "dispatch must launch the installed confined provider fixture"
            );
        }
        MessagingIpcLaunchKind::Simulated => {
            let error = match collected {
                Err(error) => error,
                Ok(_) => bail!("simulation must not claim verified process quiescence"),
            };
            assert!(
                error.to_string().contains(
                    "refusing to discard invocation artifact scratches without verified process quiescence"
                ),
                "simulation must reach the strict scratch-retention gate: {error:#}"
            );
            for path in scratch_paths {
                assert!(
                    path.is_dir(),
                    "unverified scratch must be retained: {}",
                    path.display()
                );
            }
        }
    }
    let dispatch_payload: Value =
        serde_json::from_slice(&fs::read(&dispatch_result)?).context("dispatch child result")?;
    assert!(dispatch_payload
        .get("message_id")
        .and_then(Value::as_str)
        .is_some());

    drop(provider_temp);
    Ok(())
}

#[test]
fn assignment_messaging_ipc_at_least_once_from_simulated_grok_child() -> Result<()> {
    if std::env::var_os(CHILD_ENV).is_some() {
        return confined_child_probe();
    }
    if fixture_helper_process_active() {
        return assignment_messaging_ipc_acceptance(
            MessagingIpcLaunchKind::Simulated,
            EXACT_FILTER_SIMULATED,
            None,
            None,
        );
    }
    run_messaging_ipc_fixture_helper_subprocess(EXACT_FILTER_SIMULATED, false)
}

#[test]
fn assignment_messaging_grok_verified_process_peer_isolation_and_ipc() -> Result<()> {
    if std::env::var_os(CHILD_ENV).is_some() {
        return confined_child_probe();
    }
    if fixture_helper_process_active() {
        #[cfg(not(target_os = "linux"))]
        {
            bail!("verified assignment messaging fixture requires Linux");
        }
        #[cfg(target_os = "linux")]
        {
            if crate::test_containment::skip_current()? {
                bail!("verified assignment messaging fixture requires containment");
            }
            let (cam_harness, _managed_grok_home, expected_cam_binding) =
                build_cam_grok_test_harness("account-a")?;
            let _cam_guard = activate_cam_grok_test_harness(cam_harness);
            let disposable_peer = DisposablePeerProcess::spawn()?;
            assignment_messaging_ipc_acceptance(
                MessagingIpcLaunchKind::Verified,
                EXACT_FILTER_VERIFIED,
                Some(disposable_peer),
                Some(&expected_cam_binding),
            )?;
            println!("{VERIFIED_COMPLETION_MARKER}");
        }
        return Ok(());
    }
    run_messaging_ipc_fixture_helper_subprocess(EXACT_FILTER_VERIFIED, true)
}
