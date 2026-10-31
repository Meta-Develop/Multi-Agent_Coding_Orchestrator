#![cfg(target_os = "linux")]
use multi_agent_coding_orchestrator::{
    executor::ExecutorLimits,
    external_agent::executor::{
        lifecycle::{LifecycleSshClient, OperatorTrust},
        *,
    },
    process_runner::ProcessCancellation,
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::TempDir;

struct Fixture {
    temp: TempDir,
    trust_path: PathBuf,
    trust: Arc<OperatorTrust>,
    client: LifecycleSshClient,
    target: SshTargetConfig,
    program: PathBuf,
}

fn write(path: &Path, bytes: impl AsRef<[u8]>, mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

impl Fixture {
    fn new(program: &str, loss: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("remote");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let helper = PathBuf::from(env!("CARGO_BIN_EXE_maco"));
        let target: SshTargetConfig = serde_json::from_value(serde_json::json!({
            "host_id":"offline", "endpoint":"offline.invalid", "user":"runner", "port":2222,
            "helper":helper, "root":root,
        }))
        .unwrap();
        let fake = temp.path().join("ssh");
        // All network execution is replaced by the real helper as a local process.
        let script = format!(
            r#"#!/bin/bash
set -eu
printf '%s\n' "$@" >> '{dir}/options'
if [ -e '{dir}/replace-trust-after-validation' ]; then
  printf changed > '{dir}/identity-placeholder'
  printf changed > '{dir}/known-placeholder'
fi
previous=
for value in "$@"; do
  if [ "$previous" = -i ]; then
    [ "$(cat -- "$value")" = 'offline metadata fixture' ]
  fi
  case "$value" in
    UserKnownHostsFile=*) [ "$(cat -- "${{value#UserKnownHostsFile=}}")" = 'offline metadata fixture' ] ;;
  esac
  previous=$value
done
while [ "$1" != -- ]; do shift; done
shift
shift
helper=$1; shift
request=$(mktemp '{dir}/request.XXXXXX')
reply=$(mktemp '{dir}/reply.XXXXXX')
cat > "$request"
systemd-run --user --scope --quiet -p Delegate=yes "$helper" "$@" < "$request" > "$reply"
if grep -aq '"operation":"{loss}"' "$request" && [ ! -e '{dir}/lost' ]; then
  touch '{dir}/lost'
  exit 255
fi
cat "$reply"
"#,
            dir = temp.path().display(),
            loss = loss
        );
        write(&fake, script, 0o700);
        let identity = temp.path().join("identity-placeholder");
        let known = temp.path().join("known-placeholder");
        // Inert fixtures, not keys. The loader snapshots these synthetic bytes.
        write(&identity, "offline metadata fixture", 0o600);
        write(&known, "offline metadata fixture", 0o600);
        let limits = ExecutorLimits {
            max_workspace_entries: 1024,
            max_workspace_bytes: 16 * 1024 * 1024,
            max_file_bytes: 1024 * 1024,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 65536,
            max_event_count: 1024,
            max_event_bytes: 1024 * 1024,
            max_request_bytes: 16 * 1024 * 1024,
            max_receipt_bytes: 16 * 1024 * 1024,
            connect_timeout_millis: 1000,
            execution_timeout_millis: 5000,
            cancellation_grace_millis: 500,
            poll_interval_millis: 10,
        };
        let trust_path = temp.path().join("trust.json");
        write(&trust_path, serde_json::to_vec(&serde_json::json!({"version":1,"ssh_binary":fake,"targets":[{
            "target":target,"identity_file":identity,"known_hosts_file":known,"limits":limits
        }]})).unwrap(), 0o600);
        let trust = OperatorTrust::load(&trust_path).unwrap();
        let client = LifecycleSshClient::new(trust.clone(), &trust.targets()[0].1).unwrap();
        let executable = temp.path().join("workload");
        write(
            &executable,
            format!("#!/bin/bash\nset -eu\n{program}\n"),
            0o700,
        );
        Self {
            temp,
            trust_path,
            trust,
            client,
            target,
            program: executable,
        }
    }

    fn payload(&self) -> (InputManifest, LaunchSpec, OutputPolicy) {
        let logical = |s| LogicalPath::new(s).unwrap();
        let manifest = InputManifest::new(vec![
            ManifestEntry::input_file(
                logical("input/workload"),
                ManifestPurpose::Schema,
                fs::read(&self.program).unwrap(),
            )
            .unwrap(),
            ManifestEntry::input_file(
                logical("input/prompt"),
                ManifestPurpose::Prompt,
                b"edit".to_vec(),
            )
            .unwrap(),
            ManifestEntry::input_file(
                logical("workspace/a.txt"),
                ManifestPurpose::WorkspaceInput,
                b"old\n".to_vec(),
            )
            .unwrap(),
            ManifestEntry::output_path(
                logical("output/result"),
                ManifestPurpose::DeclaredOutput,
                1024,
            )
            .unwrap(),
        ])
        .unwrap();
        let launch = LaunchSpec::new(
            TypedArgv::new(vec![
                TypedArg::Literal(BoundedLiteral::new("bash").unwrap()),
                TypedArg::ManifestPath(logical("input/workload")),
                TypedArg::ManifestPath(logical("output/result")),
                TypedArg::FinalStdinMarker,
            ])
            .unwrap(),
            logical("input/prompt"),
            BoundedMillis::new(30_000).unwrap(),
        );
        let outputs = OutputPolicy::new(
            65536,
            8,
            vec![logical("workspace/a.txt")],
            vec![DeclaredOutput::new(logical("output/result"), "application/json", 1024).unwrap()],
            1024,
        )
        .unwrap();
        (manifest, launch, outputs)
    }

    fn executor(&self) -> SupervisedSshExecutor<LifecycleSshClient> {
        SupervisedSshExecutor::configure(
            &ExecutorSelection::ssh(self.target.clone()),
            Some(self.trust.targets()[0].1.clone()),
            |_| Ok(self.client.clone()),
        )
        .unwrap()
    }

    fn binding(&self) -> SupervisedAttemptId {
        SupervisedAttemptId {
            run_id: RunId::new("run").unwrap(),
            assignment_id: AssignmentId::new("assignment").unwrap(),
            attempt: 1.try_into().unwrap(),
            nonce: Nonce::new("nonce").unwrap(),
        }
    }

    fn diagnostics(&self) -> String {
        fs::read_dir(self.temp.path().join("remote"))
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|e| fs::read_to_string(e.path().join("runner-error.json")).ok())
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn count_requests(&self, operation: &str) -> usize {
        fs::read_dir(self.temp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("request."))
            .filter(|e| {
                fs::read(e.path())
                    .unwrap()
                    .windows(operation.len())
                    .any(|w| w == operation.as_bytes())
            })
            .count()
    }
}

const COMPLETE: &str = "printf 'new\\n' > a.txt; printf '{\"candidate\":true}' > \"$1\"";

#[test]
fn completion_and_exact_cleanup_over_real_local_helper() {
    let f = Fixture::new(COMPLETE, "none");
    let executor = f.executor();
    let (manifest, launch, outputs) = f.payload();
    let mut attempt = executor
        .prepare(
            f.binding(),
            manifest,
            launch,
            outputs,
            ProcessCancellation::new(),
            TerminationPolicy::new(
                BoundedMillis::new(200).unwrap(),
                BoundedMillis::new(200).unwrap(),
            ),
        )
        .unwrap();
    let start = Instant::now();
    let result = loop {
        assert!(start.elapsed() < Duration::from_secs(15));
        if let SupervisedEvent::Collected(Effect::Confirmed(result)) = attempt
            .advance()
            .unwrap_or_else(|e| panic!("{e:?}; {}", f.diagnostics()))
        {
            break result;
        }
    };
    assert!(result.is_candidate_evidence_only());
    assert_eq!(
        result.changed_paths(),
        &[LogicalPath::new("workspace/a.txt").unwrap()]
    );
    assert!(String::from_utf8_lossy(result.patch()).contains("+new"));
    // Simulate the embedding coordinator's durable import barrier, then explicit cleanup.
    write(
        &f.temp.path().join("persisted-patch"),
        result.patch(),
        0o600,
    );
    assert!(
        matches!(SshExecutor::new(f.target.clone(), f.client.clone()).cleanup(CleanupRequest::new(result.identity().clone())).unwrap(), Effect::Confirmed(r) if r.workspace_removed())
    );
    let args = fs::read_to_string(f.temp.path().join("options")).unwrap();
    for option in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "ForwardAgent=no",
        "RequestTTY=no",
        "ProxyCommand=none",
        "UserKnownHostsFile=",
        "-i\n",
        "-F\n",
    ] {
        assert!(args.contains(option), "missing {option}");
    }
    assert!(args.contains("UserKnownHostsFile=/proc/"));
    assert!(args.contains("-i\n/proc/"));
    assert!(!args.contains("identity-placeholder"));
    assert!(!args.contains("known-placeholder"));
    assert_eq!(f.count_requests("\"operation\":\"launch\""), 1);
}

#[test]
fn lost_launch_and_collection_replies_reuse_identity_without_relaunch() {
    for loss in ["launch", "collect"] {
        let f = Fixture::new(COMPLETE, loss);
        let executor = f.executor();
        let (manifest, launch, outputs) = f.payload();
        let mut attempt = executor
            .prepare(
                f.binding(),
                manifest,
                launch,
                outputs,
                ProcessCancellation::new(),
                TerminationPolicy::new(
                    BoundedMillis::new(200).unwrap(),
                    BoundedMillis::new(200).unwrap(),
                ),
            )
            .unwrap();
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(15));
            if matches!(
                attempt
                    .advance()
                    .unwrap_or_else(|e| panic!("{e:?}; {}", f.diagnostics())),
                SupervisedEvent::Collected(Effect::Confirmed(_))
            ) {
                break;
            }
        }
        assert_eq!(f.count_requests("\"operation\":\"launch\""), 1);
        if loss == "launch" {
            assert!(f.count_requests("\"operation\":\"status\"") >= 1);
        }
        if loss == "collect" {
            let requests: Vec<serde_json::Value> = fs::read_dir(f.temp.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("request."))
                .filter_map(|e| {
                    let bytes = fs::read(e.path()).unwrap();
                    serde_json::from_slice(&bytes[16..]).ok()
                })
                .filter(|v: &serde_json::Value| v["operation"] == "collect")
                .collect();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0], requests[1]);
        }
    }
}

#[test]
fn cancellation_controls_owned_process_and_collects_terminal_evidence() {
    let f = Fixture::new("printf '{}' > \"$1\"; sleep 20", "none");
    let executor = f.executor();
    let (manifest, launch, outputs) = f.payload();
    let cancel = ProcessCancellation::new();
    let mut attempt = executor
        .prepare(
            f.binding(),
            manifest,
            launch,
            outputs,
            cancel.clone(),
            TerminationPolicy::new(
                BoundedMillis::new(500).unwrap(),
                BoundedMillis::new(500).unwrap(),
            ),
        )
        .unwrap();
    assert!(matches!(
        attempt
            .advance()
            .unwrap_or_else(|e| panic!("{e:?}; {}", f.diagnostics())),
        SupervisedEvent::Staged(_)
    ));
    assert!(matches!(
        attempt
            .advance()
            .unwrap_or_else(|e| panic!("{e:?}; {}", f.diagnostics())),
        SupervisedEvent::Launched(_)
    ));
    let ready = Instant::now();
    loop {
        let exists = fs::read_dir(f.temp.path().join("remote"))
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.path().join("files/output/result").exists());
        if exists {
            break;
        }
        assert!(
            ready.elapsed() < Duration::from_secs(15),
            "{}",
            f.diagnostics()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    cancel.cancel();
    let start = Instant::now();
    loop {
        assert!(start.elapsed() < Duration::from_secs(15));
        if matches!(
            attempt
                .advance()
                .unwrap_or_else(|e| panic!("{e:?}; {}", f.diagnostics())),
            SupervisedEvent::Collected(Effect::Confirmed(_))
        ) {
            break;
        }
    }
    assert!(f.count_requests("\"operation\":\"control\"") > 0);
    assert_eq!(f.count_requests("\"operation\":\"launch\""), 1);
}

#[test]
fn trust_tamper_permissions_replacement_and_target_mismatch_refuse() {
    let f = Fixture::new(COMPLETE, "none");
    fs::set_permissions(&f.trust_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(OperatorTrust::load(&f.trust_path).is_err());
    fs::set_permissions(&f.trust_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(f.trust.validate().is_err());
    let f = Fixture::new(COMPLETE, "none");
    let data = fs::read(&f.trust_path).unwrap();
    fs::remove_file(&f.trust_path).unwrap();
    write(&f.trust_path, data, 0o600);
    assert!(f.trust.validate().is_err());
    let f = Fixture::new(COMPLETE, "none");
    write(
        &f.temp.path().join("identity-placeholder"),
        "replacement",
        0o600,
    );
    assert!(f.trust.validate().is_err());
    let f = Fixture::new(COMPLETE, "none");
    let mut target = f.target.clone();
    target.host_id = HostId::new("different").unwrap();
    assert!(SupervisedSshExecutor::configure(
        &ExecutorSelection::ssh(target),
        Some(f.trust.targets()[0].1.clone()),
        |_| Ok(f.client.clone())
    )
    .is_err());
    assert!(SupervisedSshExecutor::<LifecycleSshClient>::configure(
        &ExecutorSelection::ssh(f.target.clone()),
        None,
        |_| panic!("plan data must not install transport")
    )
    .is_err());
    assert!(SupervisedSshExecutor::<LifecycleSshClient>::configure(
        &ExecutorSelection::default(),
        Some(f.trust.targets()[0].1.clone()),
        |_| panic!("local must not construct SSH")
    )
    .is_err());
}

#[test]
fn cli_configured_dispatch_persists_candidate_and_keeps_native_gate() {
    cli_dispatch_case(false);
}

#[test]
fn review_absent_delegation_is_actionable_and_retryable() {
    if std::env::var_os("MACO_I717L_DELEGATION_PROBE").is_none() {
        let status = std::process::Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "-p", "Delegate=no"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "review_absent_delegation_is_actionable_and_retryable",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("MACO_I717L_DELEGATION_PROBE", "1")
            .status()
            .unwrap();
        assert!(
            status.success(),
            "isolated delegation regression failed: {status}"
        );
        return;
    }
    cli_dispatch_case(true);
}

fn cli_dispatch_case(deny_delegation: bool) {
    use multi_agent_coding_orchestrator::{
        external_agent::ExternalAgentCommand,
        supervise::{remote_cli::operator_ssh_hosts, remote_execution::SshDispatchIdentity},
    };
    let f = Fixture::new(
        r#"
result=
while [ "$#" -gt 0 ]; do
  if [ "$1" = --output-last-message ]; then shift; result=$1; fi
  shift
done
printf 'new\n' > a.txt
printf '{"candidate":true}' > "$result"
"#,
        "none",
    );
    let bin = f.temp.path().join("remote/bin");
    fs::create_dir(&bin).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    write(
        &bin.join("i717l-offline"),
        fs::read(&f.program).unwrap(),
        0o700,
    );
    let repo_path = f.temp.path().join("coordinator");
    let repo = git2::Repository::init(&repo_path).unwrap();
    write(&repo_path.join("a.txt"), "old\n", 0o600);
    let mut index = repo.index().unwrap();
    index.add_path(Path::new("a.txt")).unwrap();
    index.write().unwrap();
    let tree_id = index.write_tree().unwrap();
    let signature = git2::Signature::now("test", "test@invalid").unwrap();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "base",
        &repo.find_tree(tree_id).unwrap(),
        &[],
    )
    .unwrap();
    let prompt = f.temp.path().join("prompt");
    write(&prompt, "edit a.txt", 0o600);
    let command = ExternalAgentCommand::codex(
        "i717l-offline",
        &repo_path,
        prompt,
        f.temp.path().join("events"),
        f.temp.path().join("result"),
        Duration::from_secs(30),
    );
    let hosts = operator_ssh_hosts(&f.trust_path).unwrap();
    if deny_delegation {
        // Change only this disposable subprocess scope, never the shared lane.
        struct RestorePermissions(PathBuf, fs::Permissions);
        impl Drop for RestorePermissions {
            fn drop(&mut self) {
                fs::set_permissions(&self.0, self.1.clone()).unwrap();
            }
        }
        let membership = fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .unwrap();
        let cgroup = Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'));
        let restore =
            RestorePermissions(cgroup.clone(), fs::metadata(&cgroup).unwrap().permissions());
        fs::set_permissions(&cgroup, fs::Permissions::from_mode(0o555)).unwrap();
        let (manifest, launch, policy) = f.payload();
        let stage = StageRequest::new(
            AssignmentIdentity::new(
                f.target.host_id.clone(),
                RunId::new("local-refusal").unwrap(),
                AssignmentId::new("local-refusal").unwrap(),
                Nonce::new("local-refusal").unwrap(),
            ),
            manifest,
            launch,
            policy,
        )
        .unwrap();
        let direct = f.client.stage(StageTransportRequest {
            target: f.target.clone(),
            stage,
        });
        assert!(
            matches!(direct, TransportCall::NotStarted(_)),
            "pre-spawn refusal must prove no effect: {direct:?}"
        );
        let error = hosts[0]
            .dispatch(
                &repo_path,
                SshDispatchIdentity {
                    run_id: "candidate-run".into(),
                    assignment_id: "candidate".into(),
                    worker_id: None,
                    attempt: 1.try_into().unwrap(),
                },
                &[PathBuf::from("a.txt")],
                &command,
                &ProcessCancellation::new(),
            )
            .unwrap_err();
        drop(restore);
        let detail = format!("{error:#}");
        assert!(
            detail.contains("delegated local cgroup") && detail.contains("Delegate=yes"),
            "operator-visible error must name the remedy: {detail}"
        );
        assert_eq!(f.count_requests("\"operation\":\"stage\""), 0);
        assert!(
            !f.temp.path().join("options").exists(),
            "no SSH process may start"
        );
        let journal = repo.path().join("maco/state/supervised-ssh-v1");
        if journal.exists() {
            for dir in fs::read_dir(journal)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_dir())
            {
                for file in fs::read_dir(dir.path()).unwrap().filter_map(Result::ok) {
                    if !file.file_name().to_string_lossy().starts_with('.') {
                        panic!(
                            "local prerequisite failure recorded stage intent: {:?}",
                            file.file_name()
                        );
                    }
                }
            }
        }
    }
    let error = hosts[0]
        .dispatch(
            &repo_path,
            SshDispatchIdentity {
                run_id: "candidate-run".into(),
                assignment_id: "candidate".into(),
                worker_id: None,
                attempt: 1.try_into().unwrap(),
            },
            &[PathBuf::from("a.txt")],
            &command,
            &ProcessCancellation::new(),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("native runtime recapture/import is not implemented"));
    assert_eq!(f.count_requests("\"operation\":\"launch\""), 1);
    assert_eq!(f.count_requests("\"operation\":\"cleanup\""), 0);
    assert_eq!(fs::read(repo_path.join("a.txt")).unwrap(), b"old\n");
    let journal = repo.path().join("maco/state/supervised-ssh-v1");
    let mut committed = false;
    for dir in fs::read_dir(journal)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
    {
        for file in fs::read_dir(dir.path()).unwrap().filter_map(Result::ok) {
            if file.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(file.path()).unwrap()).unwrap();
            committed |= value["phase"] == "collection_committed";
        }
    }
    assert!(committed, "candidate must be durable before import refusal");
}

#[test]
fn review_binary_same_second_rewrite_must_revoke_trust() {
    use std::os::unix::fs::MetadataExt;
    let mut observed = false;
    for _ in 0..5 {
        let f = Fixture::new(COMPLETE, "none");
        let binary = f.temp.path().join("ssh");
        let before = fs::metadata(&binary).unwrap();
        let old = fs::read_to_string(&binary).unwrap();
        let changed = old.replacen("set -eu", "set +eu", 1);
        assert_ne!(old, changed);
        assert_eq!(old.len(), changed.len());
        fs::write(&binary, changed).unwrap();
        let after = fs::metadata(&binary).unwrap();
        if before.mtime() != after.mtime() || before.ctime() != after.ctime() {
            continue;
        }
        observed = true;
        assert!(
            f.trust.validate().is_err(),
            "same-second rewrite accepted: before ns {} / {}, after ns {} / {}",
            before.mtime_nsec(),
            before.ctime_nsec(),
            after.mtime_nsec(),
            after.ctime_nsec()
        );
        break;
    }
    assert!(observed, "could not schedule a same-second rewrite");
}

#[test]
fn review_ssh_binary_symlink_ancestor_must_refuse() {
    let f = Fixture::new(COMPLETE, "none");
    let real = f.temp.path().join("real-bin");
    fs::create_dir(&real).unwrap();
    fs::copy(f.temp.path().join("ssh"), real.join("ssh")).unwrap();
    let alias = f.temp.path().join("alias-bin");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.trust_path).unwrap()).unwrap();
    document["ssh_binary"] = serde_json::json!(alias.join("ssh"));
    write(&f.trust_path, serde_json::to_vec(&document).unwrap(), 0o600);
    assert!(
        OperatorTrust::load(&f.trust_path).is_err(),
        "SSH binary symlink ancestor accepted"
    );
}

fn review_pipe_probe(script: &str) -> Duration {
    pipe_probe(script, false)
}

fn pipe_probe(script: &str, large_input: bool) -> Duration {
    let f = Fixture::new(COMPLETE, "none");
    let descendant = f.temp.path().join("descendant.pid");
    let script = script.replace(
        "sleep 2 &",
        &format!("sleep 2 &\nprintf '%s' \"$!\" > '{}'", descendant.display()),
    );
    write(&f.temp.path().join("ssh"), script, 0o700);
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.trust_path).unwrap()).unwrap();
    document["targets"][0]["limits"]["execution_timeout_millis"] = serde_json::json!(200);
    document["targets"][0]["limits"]["connect_timeout_millis"] = serde_json::json!(100);
    write(&f.trust_path, serde_json::to_vec(&document).unwrap(), 0o600);
    let trust = OperatorTrust::load(&f.trust_path).unwrap();
    let client = LifecycleSshClient::new(trust.clone(), &trust.targets()[0].1).unwrap();
    let (manifest, launch, outputs) = f.payload();
    let manifest = if large_input {
        InputManifest::new(
            manifest
                .entries()
                .iter()
                .map(|entry| {
                    if entry.purpose() == ManifestPurpose::Prompt {
                        ManifestEntry::input_file(
                            entry.path().clone(),
                            entry.purpose(),
                            vec![0; 64 * 1024],
                        )
                        .unwrap()
                    } else {
                        entry.clone()
                    }
                })
                .collect(),
        )
        .unwrap()
    } else {
        manifest
    };
    let stage = StageRequest::new(
        AssignmentIdentity::new(
            f.target.host_id.clone(),
            RunId::new("probe").unwrap(),
            AssignmentId::new("probe").unwrap(),
            Nonce::new("probe").unwrap(),
        ),
        manifest,
        launch,
        outputs,
    )
    .unwrap();
    let start = Instant::now();
    let result = client.stage(StageTransportRequest {
        target: f.target.clone(),
        stage,
    });
    assert!(matches!(result, TransportCall::LostResponse { .. }));
    let elapsed = start.elapsed();
    let pid = fs::read_to_string(descendant).expect("the pipe-holding descendant started");
    if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
        assert_eq!(
            stat.rsplit_once(')').unwrap().1.split_whitespace().next(),
            Some("Z"),
            "pipe-holding descendant survived transport cleanup"
        );
    }
    elapsed
}

#[test]
fn review_transport_exit_must_not_disable_pipe_deadline() {
    let elapsed = review_pipe_probe("#!/bin/bash\ncat >/dev/null\nsleep 2 &\nexit 0\n");
    assert!(
        elapsed < Duration::from_secs(1),
        "200 ms deadline took {elapsed:?} after transport exit"
    );
}

#[test]
fn review_transport_kill_must_not_block_on_escaped_pipe_owner() {
    let elapsed = review_pipe_probe("#!/bin/bash\ncat >/dev/null\nsetsid sleep 2 &\nsleep 5\n");
    assert!(
        elapsed < Duration::from_secs(1),
        "200 ms deadline took {elapsed:?} after transport kill"
    );
}

#[test]
fn review_trust_must_reject_openssh_environment_expansion_paths() {
    let mut accepted = Vec::new();
    for field in ["identity_file", "known_hosts_file"] {
        for token in ["${REVIEW_VARIABLE}", "%h", "~"] {
            let f = Fixture::new(COMPLETE, "none");
            let literal = f.temp.path().join(format!("{token}-placeholder"));
            write(&literal, "inert metadata fixture", 0o600);
            let mut document: serde_json::Value =
                serde_json::from_slice(&fs::read(&f.trust_path).unwrap()).unwrap();
            document["targets"][0][field] = serde_json::json!(literal);
            write(&f.trust_path, serde_json::to_vec(&document).unwrap(), 0o600);
            if OperatorTrust::load(&f.trust_path).is_ok() {
                accepted.push(format!("{field}: {token}"));
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "OpenSSH environment expansion accepted in {accepted:?}"
    );
}

#[test]
fn blocked_stdin_and_escaped_pipe_owner_share_one_deadline() {
    let elapsed = pipe_probe("#!/bin/bash\nsetsid sleep 2 &\nexit 0\n", true);
    assert!(
        elapsed < Duration::from_secs(1),
        "blocked stdin exceeded the single deadline: {elapsed:?}"
    );
}

#[test]
fn consumer_reads_validated_trust_bytes_after_source_replacement() {
    let f = Fixture::new(COMPLETE, "none");
    write(
        &f.temp.path().join("replace-trust-after-validation"),
        b"",
        0o600,
    );
    let (manifest, launch, policy) = f.payload();
    let stage = StageRequest::new(
        AssignmentIdentity::new(
            f.target.host_id.clone(),
            RunId::new("snapshot").unwrap(),
            AssignmentId::new("snapshot").unwrap(),
            Nonce::new("snapshot").unwrap(),
        ),
        manifest,
        launch,
        policy,
    )
    .unwrap();
    assert!(
        matches!(
            f.client.stage(StageTransportRequest {
                target: f.target.clone(),
                stage
            }),
            TransportCall::Response(_)
        ),
        "consumer must read the original snapshots"
    );
    assert_eq!(
        fs::read(f.temp.path().join("identity-placeholder")).unwrap(),
        b"changed"
    );
    assert_eq!(
        fs::read(f.temp.path().join("known-placeholder")).unwrap(),
        b"changed"
    );
    assert!(
        f.trust.validate().is_err(),
        "replacement revokes future calls"
    );
}

#[test]
fn trust_revocation_is_a_bounded_local_refusal() {
    let f = Fixture::new(COMPLETE, "none");
    write(&f.temp.path().join("known-placeholder"), b"changed", 0o600);
    let error = f.client.preflight().unwrap_err();
    assert!(matches!(error, ExecutorError::NotStarted(_)));
    assert!(error.to_string().contains("reload required"));
    assert!(error.to_string().len() < 4200);
    assert!(!f.temp.path().join("options").exists());
}

#[test]
fn review_large_executable_validation_respects_deadline() {
    let f = Fixture::new(COMPLETE, "none");
    let binary = f.temp.path().join("ssh");
    let mut image = fs::read(&binary).unwrap();
    image.extend_from_slice(b"\n#");
    image.resize(64 * 1024 * 1024, b'x');
    write(&binary, image, 0o700);
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&f.trust_path).unwrap()).unwrap();
    document["targets"][0]["limits"]["execution_timeout_millis"] = serde_json::json!(200);
    document["targets"][0]["limits"]["connect_timeout_millis"] = serde_json::json!(100);
    write(&f.trust_path, serde_json::to_vec(&document).unwrap(), 0o600);
    let trust = OperatorTrust::load(&f.trust_path).unwrap();
    let client = LifecycleSshClient::new(trust.clone(), &trust.targets()[0].1).unwrap();
    let (manifest, launch, outputs) = f.payload();
    let stage = StageRequest::new(
        AssignmentIdentity::new(
            f.target.host_id.clone(),
            RunId::new("hash-deadline").unwrap(),
            AssignmentId::new("hash-deadline").unwrap(),
            Nonce::new("hash-deadline").unwrap(),
        ),
        manifest,
        launch,
        outputs,
    )
    .unwrap();
    let start = Instant::now();
    let result = client.stage(StageTransportRequest {
        target: f.target.clone(),
        stage,
    });
    let elapsed = start.elapsed();
    eprintln!("200 ms timeout, 64 MiB executable validation: {elapsed:?}, {result:?}");
    assert!(matches!(result, TransportCall::NotStarted(_)));
    assert!(!f.temp.path().join("options").exists());
    assert!(
        elapsed < Duration::from_secs(1),
        "200 ms deadline took {elapsed:?} validating executable"
    );
    let start = Instant::now();
    let result = client.preflight();
    let elapsed = start.elapsed();
    eprintln!("200 ms preflight, 64 MiB executable validation: {elapsed:?}, {result:?}");
    assert!(matches!(result, Err(ExecutorError::NotStarted(_))));
    assert!(
        elapsed < Duration::from_secs(1),
        "preflight deadline took {elapsed:?}"
    );
    assert!(!f.temp.path().join("options").exists());
}
