use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use coding_agent_manager_lib::account_authority::StoredAccountRegistry;
use coding_agent_manager_lib::error::Error as CamError;
use coding_agent_manager_lib::providers::launch_lifecycle::{
    CredentialEnvironmentInput, LaunchLifecycleHandle, LaunchPhase,
};

use super::*;
use crate::account_authority::authority_socket_config::CamAuthoritySocketTestGuard;
use crate::account_authority::grok::{
    acquire_guarded_grok_launch_authority, activate_cam_grok_test_harness,
    build_cam_grok_test_harness, CamGrokTestGuard, GrokLaunchAuthority,
};
use crate::external_agent::{
    insert_admitted_grok_home_environment, run_grok_acp_external_process, AdmittedGrokCredentials,
    ExternalAgentCommand,
};
use crate::process_runner::{
    run_process_cancellable, ContainmentBackend, ContainmentPolicy, EnvironmentMode,
    ProcessFailureEvidence, ProcessSpec, ProcessTreeEvidence, SideEffectConfinementEvidence,
    SideEffectConfinementProfileKind, StdinMode,
};

fn fixture() -> (CamGrokTestGuard, GrokLaunchAuthority, StoredAccountRegistry) {
    let (harness, _, _) = build_cam_grok_test_harness("account-a").unwrap();
    let registry = StoredAccountRegistry::new(harness.registry.metadata_path());
    let guard = activate_cam_grok_test_harness(harness);
    let authority = acquire_guarded_grok_launch_authority(
        None,
        "lifecycle-run",
        "lifecycle-operation",
        Instant::now() + Duration::from_secs(120),
        &mut None,
    )
    .unwrap();
    (guard, authority, registry)
}

fn construct(
    authority: &mut GrokLaunchAuthority,
) -> (AdmittedGrokCredentials, LaunchLifecycleHandle) {
    let credentials = authority
        .construct_material(AdmittedGrokCredentials::from_managed_grok_home)
        .unwrap();
    (credentials, authority.launch_lifecycle().unwrap())
}

fn assert_busy(registry: &StoredAccountRegistry) {
    assert!(matches!(
        registry.begin_delete("grok-cli", "account-a"),
        Err(CamError::AccountAuthorityBusy { .. })
    ));
    assert!(matches!(
        registry.select_complete("grok-cli", "account-b"),
        Err(CamError::AccountAuthorityBusy { .. })
    ));
}

fn assert_released(registry: &StoredAccountRegistry) {
    registry.select_complete("grok-cli", "account-b").unwrap();
    registry.begin_delete("grok-cli", "account-a").unwrap();
}

fn child_spec(directory: &Path, environment: BTreeMap<String, String>) -> ProcessSpec {
    ProcessSpec::direct(
        "declared lifecycle fixture",
        "/bin/sh",
        [
            "-c",
            "test -z \"${XAI_API_KEY+x}\" && test -z \"${GROK_AUTH_PATH+x}\" || exit 90; test -n \"$GROK_HOME\" || exit 91; touch ready; while [ ! -e release ]; do sleep 0.01; done; read code < release; exit \"$code\"",
        ],
        directory,
        4096,
    )
    .with_environment(EnvironmentMode::ClearAndSet(environment))
    .with_stdin(StdinMode::Null)
    .with_timeout(Some(Duration::from_secs(45)))
}

// This fixture has no child-spawning code. Its runner supplies synthetic
// direct-child empty-tree evidence only after waiting for that exact child.
// It exercises lifecycle mapping without claiming strict backend qualification.
#[test]
fn lifecycle_child_fixture() {
    let Some(directory) = std::env::var_os("MACO_LIFECYCLE_CHILD_DIRECTORY") else {
        return;
    };
    assert!(std::env::var_os("XAI_API_KEY").is_none());
    assert!(std::env::var_os("GROK_AUTH_PATH").is_none());
    assert!(std::env::var_os("GROK_HOME").is_some());
    let directory = std::path::PathBuf::from(directory);
    fs::write(directory.join("ready"), b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(45);
    while !directory.join("release").exists() {
        assert!(Instant::now() < deadline, "fixture release timed out");
        thread::sleep(Duration::from_millis(10));
    }
    if fs::read_to_string(directory.join("release"))
        .unwrap()
        .trim()
        != "0"
    {
        panic!("synthetic nonzero exit");
    }
}

fn run_fixture_child(spec: ProcessSpec, cancellation: &ProcessCancellation) -> ProcessOutput {
    let EnvironmentMode::ClearAndSet(mut environment) = spec.environment else {
        panic!("fixture requires an explicit environment");
    };
    environment.insert(
        "MACO_LIFECYCLE_CHILD_DIRECTORY".into(),
        spec.current_dir.to_string_lossy().into_owned(),
    );
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "external_agent::executor::launch_lifecycle::tests::lifecycle_child_fixture",
        ])
        .current_dir(&spec.current_dir)
        .env_clear()
        .envs(environment)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if cancellation.is_cancelled() || started.elapsed() > Duration::from_secs(45) {
            child.kill().unwrap();
            break child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(10));
    };
    ProcessOutput {
        status: Some(status),
        duration: started.elapsed(),
        timed_out: false,
        process_tree: ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
        side_effects: SideEffectConfinementEvidence::TrustedBestEffort(
            SideEffectConfinementProfileKind::TrustedCompatibility,
        ),
        stdout: Default::default(),
        stderr: Default::default(),
        process_error: None,
        stdin_error: None,
    }
}

#[test]
fn production_launch_lifecycle_tracks_child_exit() {
    exercise_launch_paths(false);
}

#[test]
#[ignore = "requires a qualified delegated Linux user manager and strict containment backend"]
fn production_launch_lifecycle_strict_runner_tracks_child_exit() {
    exercise_launch_paths(true);
}

fn exercise_launch_paths(strict: bool) {
    let _socket = CamAuthoritySocketTestGuard::install(None);
    for terminal in ["normal", "nonzero", "cancel"] {
        let (_guard, mut authority, registry) = fixture();
        let (credentials, handle) = construct(&mut authority);
        let mut environment = BTreeMap::from([
            (
                "PATH".into(),
                "/usr/bin:/bin:/run/current-system/sw/bin".into(),
            ),
            ("XAI_API_KEY".into(), "FAKE-inherited-input".into()),
            ("GROK_AUTH_PATH".into(), "FAKE-inherited-path".into()),
        ]);
        insert_admitted_grok_home_environment(&mut environment, &credentials).unwrap();
        authority.apply_launch_environment(&mut environment);
        assert!(!environment.contains_key("XAI_API_KEY"));
        let directory = tempfile::tempdir().unwrap();
        let spec = child_spec(directory.path(), environment);
        let cancellation = ProcessCancellation::new();
        let child_cancellation = cancellation.clone();
        let runner = thread::spawn(move || {
            let result = execute(
                authority.launch_custody().as_deref_mut(),
                &child_cancellation,
                || {
                    if strict {
                        run_process_cancellable(spec, &child_cancellation)
                    } else {
                        Ok(run_fixture_child(spec, &child_cancellation))
                    }
                },
                |output| output,
            );
            (authority, credentials, result)
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        while !directory.path().join("ready").exists() && !runner.is_finished() {
            assert!(
                Instant::now() < deadline,
                "fixture did not reach its child barrier"
            );
            thread::sleep(Duration::from_millis(10));
        }
        if !directory.path().join("ready").exists() {
            let (_, _, result) = runner.join().unwrap();
            panic!("child failed before barrier: {result:?}");
        }
        assert_eq!(handle.snapshot().phase, LaunchPhase::Running);
        assert_busy(&registry);
        assert!(handle.revoke_before_spawn().is_err());
        if terminal == "cancel" {
            cancellation.cancel();
        } else {
            fs::write(
                directory.path().join("release.pending"),
                if terminal == "normal" { "0\n" } else { "7\n" },
            )
            .unwrap();
            fs::rename(
                directory.path().join("release.pending"),
                directory.path().join("release"),
            )
            .unwrap();
        }
        let (authority, credentials, result) = runner.join().unwrap();
        let output = result.unwrap();
        assert!(output.process_tree.is_verified_empty());
        let expected = match terminal {
            "normal" => LaunchFinalization::Exited,
            "nonzero" => LaunchFinalization::AbnormalExit,
            _ => LaunchFinalization::Cancelled,
        };
        assert_eq!(handle.snapshot().phase, LaunchPhase::Finalized(expected));
        // Reobserving a terminal result cannot change the first finalization.
        observe_output(authority.launch_custody().as_deref_mut(), &output, true);
        assert_eq!(handle.snapshot().phase, LaunchPhase::Finalized(expected));
        assert!(credentials.grok_home_environment().is_ok());
        assert_busy(&registry);
        let metadata = crate::secret_lifecycle::ProviderLaunchMetadata::from(handle.snapshot());
        let serialized = serde_json::to_string(&metadata).unwrap();
        for private in [
            "FAKE-managed-refresh",
            "FAKE-inherited-input",
            "FAKE-inherited-path",
            "GROK_HOME",
            "auth.json",
        ] {
            assert!(!serialized.contains(private));
        }
        assert_eq!(metadata.run_id, "lifecycle-run");
        assert_eq!(
            metadata.binding.account_incarnation,
            authority.binding().account_incarnation
        );
        assert!(metadata
            .environment
            .contains(&CredentialEnvironmentInput::Removed("XAI_API_KEY".into())));
        drop(credentials);
        assert_busy(&registry);
        drop(authority);
        assert_released(&registry);
    }
}

fn pre_release_error(kind: &str) -> ProcessRunError {
    match kind {
        "setup-timeout" => ProcessRunError::SetupTimeout {
            label: "lifecycle fixture".into(),
            command: "fixture".into(),
            phase: "containment setup before release",
            source: std::io::Error::new(std::io::ErrorKind::TimedOut, "synthetic setup timeout"),
        },
        "tee-conflict" => ProcessRunError::TeeConflict {
            label: "lifecycle fixture".into(),
            stdout: "fixture-tee".into(),
            stderr: "fixture-tee".into(),
        },
        _ => panic!("unknown fixture refusal"),
    }
}

#[test]
fn production_launch_lifecycle_pre_release_refusals_release_custody() {
    let _socket = CamAuthoritySocketTestGuard::install(None);
    for kind in ["setup-timeout", "tee-conflict"] {
        let (_guard, mut authority, registry) = fixture();
        let (credentials, handle) = construct(&mut authority);
        {
            let mut custody = authority.launch_custody().unwrap();
            custody.begin_spawn().unwrap();
            assert_eq!(handle.snapshot().phase, LaunchPhase::Running);
            observe_error(Some(&mut custody), &pre_release_error(kind));
        }
        assert_eq!(
            handle.snapshot().phase,
            LaunchPhase::Finalized(LaunchFinalization::Refused)
        );
        assert_busy(&registry);
        drop(credentials);
        drop(authority);
        assert_released(&registry);
    }
}

#[test]
fn production_launch_lifecycle_preflight_refusals_preserve_live_child_evidence() {
    use crate::external_agent::EnvironmentPreflightProcessEvidence;

    let _socket = CamAuthoritySocketTestGuard::install(None);
    for kind in ["setup-timeout", "tee-conflict"] {
        for earlier_verified in [None, Some(true), Some(false)] {
            let earlier_live_child = earlier_verified == Some(false);
            let (_guard, mut authority, registry) = fixture();
            let (credentials, handle) = construct(&mut authority);
            let mut evidence = EnvironmentPreflightProcessEvidence::default();
            if let Some(verified) = earlier_verified {
                evidence.record(
                    if verified {
                        ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::SystemdUserService)
                    } else {
                        ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService)
                    },
                    if verified {
                        SideEffectConfinementEvidence::Verified(
                            SideEffectConfinementProfileKind::ExternalGrok,
                        )
                    } else {
                        SideEffectConfinementEvidence::Unverified(
                            SideEffectConfinementProfileKind::ExternalGrok,
                        )
                    },
                    verified,
                );
            }
            evidence.record_error(&pre_release_error(kind));
            assert!(evidence.started);
            assert_eq!(
                evidence.process_tree,
                Some(ProcessTreeEvidence::Unverified(
                    ContainmentBackend::SystemdUserService
                ))
            );
            assert!(evidence
                .side_effects
                .is_some_and(|effects| !effects.is_verified()));
            assert_eq!(evidence.may_have_live_child(), earlier_live_child);
            if evidence.may_have_live_child() {
                authority.launch_custody().unwrap().exit_unknown();
            }
            drop(credentials);
            drop(authority);
            if earlier_live_child {
                assert_eq!(handle.snapshot().phase, LaunchPhase::ExitUnknown);
                assert_busy(&registry);
            } else {
                assert_eq!(
                    handle.snapshot().phase,
                    LaunchPhase::Finalized(LaunchFinalization::Refused)
                );
                assert_released(&registry);
            }
        }
    }
}

#[test]
fn production_launch_lifecycle_refuses_expired_revoked_and_failed_construction() {
    let _socket = CamAuthoritySocketTestGuard::install(None);
    for refusal in [
        "expired",
        "construction",
        "revoked",
        "spawn",
        "acp-contract",
        "drop",
    ] {
        let (_guard, mut authority, registry) = fixture();
        if matches!(refusal, "expired" | "construction") {
            let mut constructed = false;
            let mut handle = authority.launch_lifecycle();
            let result = if refusal == "expired" {
                acquire_guarded_grok_launch_authority(
                    None,
                    "expired-run",
                    "expired-operation",
                    Instant::now(),
                    &mut handle,
                )
                .map(|_| ())
            } else {
                authority.construct_material(|_| {
                    constructed = true;
                    assert_busy(&registry);
                    anyhow::bail!("synthetic construction refusal")
                })
            };
            assert!(result.is_err());
            assert_eq!(constructed, refusal == "construction");
            drop(authority);
            assert_eq!(
                handle.unwrap().snapshot().phase,
                LaunchPhase::Finalized(LaunchFinalization::Refused)
            );
        } else {
            let (_credentials, handle) = construct(&mut authority);
            if refusal == "revoked" {
                handle.revoke_before_spawn().unwrap();
                let result: Result<ProcessOutput, _> = execute(
                    authority.launch_custody().as_deref_mut(),
                    &ProcessCancellation::new(),
                    || panic!("revoked admission must not invoke the runner"),
                    |output| output,
                );
                assert!(result.is_err());
            } else if refusal == "spawn" {
                let error = std::process::Command::new("/missing-lifecycle-fixture/program")
                    .spawn()
                    .unwrap_err();
                let result: Result<ProcessOutput, _> = execute(
                    authority.launch_custody().as_deref_mut(),
                    &ProcessCancellation::new(),
                    || {
                        Err(ProcessRunError::Spawn {
                            label: "fixture".into(),
                            command: "fixture".into(),
                            current_dir: Path::new("/").into(),
                            source: error,
                        })
                    },
                    |output| output,
                );
                assert!(result.is_err());
            } else if refusal == "acp-contract" {
                let directory = tempfile::tempdir().unwrap();
                let command = ExternalAgentCommand::codex(
                    "unused-provider",
                    directory.path(),
                    directory.path().join("prompt"),
                    directory.path().join("events"),
                    directory.path().join("message"),
                    Duration::from_secs(60),
                );
                let result = run_grok_acp_external_process(
                    child_spec(directory.path(), BTreeMap::new()),
                    &ProcessCancellation::new(),
                    &command,
                    "fixture".into(),
                    Duration::from_secs(60),
                    authority.launch_custody().as_deref_mut(),
                );
                assert!(matches!(result, Err(ProcessRunError::IoSetup { .. })));
                assert_eq!(handle.snapshot().phase, LaunchPhase::Constructing);
            }
            drop(authority);
            let expected = if refusal == "spawn" {
                LaunchFinalization::SpawnFailed
            } else {
                LaunchFinalization::Refused
            };
            assert_eq!(handle.snapshot().phase, LaunchPhase::Finalized(expected));
        }
        assert_released(&registry);
    }
}

#[test]
fn production_launch_lifecycle_retains_unknown_exit_custody() {
    let _socket = CamAuthoritySocketTestGuard::install(None);
    for failure in ["wait", "cancel", "preflight", "abandoned"] {
        let (_guard, mut authority, registry) = fixture();
        let (_credentials, handle) = construct(&mut authority);
        let mut custody = authority.launch_custody().unwrap();
        if failure != "preflight" {
            custody.begin_spawn().unwrap();
        }
        if matches!(failure, "wait" | "cancel") {
            let evidence = Box::new(ProcessFailureEvidence {
                stdout: Default::default(),
                stderr: Default::default(),
                process_tree: ProcessTreeEvidence::Unverified(
                    ContainmentBackend::SystemdUserService,
                ),
                side_effects: SideEffectConfinementEvidence::Unverified(
                    SideEffectConfinementProfileKind::ExternalGrok,
                ),
                process_error: None,
                stdin_error: None,
            });
            let error = if failure == "wait" {
                ProcessRunError::Wait {
                    label: "fixture".into(),
                    command: "fixture".into(),
                    evidence,
                    source: std::io::Error::other("synthetic wait failure"),
                }
            } else {
                ProcessRunError::Cancelled {
                    label: "fixture".into(),
                    command: "fixture".into(),
                    phase: "synthetic cleanup",
                    evidence: Some(evidence),
                }
            };
            observe_error(Some(&mut custody), &error);
        } else if failure == "preflight" {
            custody.exit_unknown();
        }
        drop(custody);
        drop(authority);
        assert_eq!(handle.snapshot().phase, LaunchPhase::ExitUnknown);
        assert_busy(&registry);
    }
}

#[test]
fn production_launch_lifecycle_best_effort_exit_does_not_confirm_cleanup() {
    let _socket = CamAuthoritySocketTestGuard::install(None);
    let (_guard, mut authority, registry) = fixture();
    let (_credentials, handle) = construct(&mut authority);
    let directory = tempfile::tempdir().unwrap();
    let spec = ProcessSpec::direct(
        "unverified fixture",
        "/bin/sh",
        ["-c", "exit 0"],
        directory.path(),
        1024,
    )
    .with_containment(ContainmentPolicy::TrustedBestEffort)
    .with_environment(EnvironmentMode::ClearAndSet(BTreeMap::new()))
    .with_stdin(StdinMode::Null);
    let output = execute(
        authority.launch_custody().as_deref_mut(),
        &ProcessCancellation::new(),
        || run_process_cancellable(spec, &ProcessCancellation::new()),
        |output| output,
    )
    .unwrap();
    assert!(output.status.unwrap().success());
    assert_eq!(handle.snapshot().phase, LaunchPhase::ExitUnknown);
    drop(authority);
    assert_busy(&registry);
}
