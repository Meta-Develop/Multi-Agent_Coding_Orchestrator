use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use crate::external_agent::executor::launch_lifecycle::execute;
use crate::process_runner::{
    ContainmentBackend, ProcessCancellation, ProcessOutput, ProcessRunError, ProcessTreeEvidence,
    SideEffectConfinementEvidence, SideEffectConfinementProfileKind,
};
use coding_agent_manager_lib::error::Error as CamError;
use coding_agent_manager_lib::providers::launch_lifecycle::{LaunchFinalization, LaunchPhase};

pub(crate) const SCENARIOS: [&str; 9] = [
    "normal",
    "nonzero",
    "cancel",
    "expired",
    "revoked",
    "construction",
    "drop",
    "spawn",
    "unknown",
];

// This exact child never spawns descendants. Its parent supplies direct-child
// empty-tree evidence only after waiting for it; this is no sandbox qualification.
#[test]
fn selected_lifecycle_child_fixture() {
    let Some(directory) = std::env::var_os("MACO_SELECTED_LIFECYCLE_CHILD") else {
        return;
    };
    assert_eq!(
        std::env::var("SYNTHETIC_SELECTED").unwrap(),
        "synthetic-lifecycle-material"
    );
    assert_eq!(
        std::env::var("SYNTHETIC_INHERITED").unwrap(),
        "synthetic-inherited-value"
    );
    let directory = std::path::PathBuf::from(directory);
    fs::write(directory.join("ready"), b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !directory.join("release").exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(fs::read(directory.join("release")).unwrap(), b"0");
}

pub(crate) fn exercise<A: Send + 'static>(
    registry: &StoredAccountRegistry,
    provider: &str,
    scenario: &str,
    construct: impl FnOnce(LaunchAdmission<'_>) -> Result<(A, String)>,
    launch: impl Fn(&A) -> &SelectedLaunch + Send + 'static,
) {
    let mut handle = None;
    let result = construct(LaunchAdmission {
        run_id: "selected-lifecycle-run",
        operation_id: "selected-lifecycle-operation",
        deadline: Instant::now()
            + if scenario == "expired" {
                Duration::ZERO
            } else {
                Duration::from_secs(60)
            },
        handle: &mut handle,
    });
    let handle = handle.expect("admission must remain observable even on construction refusal");
    if scenario == "expired" {
        assert!(result.is_err());
        assert_eq!(
            handle.snapshot().phase,
            LaunchPhase::Finalized(LaunchFinalization::Refused)
        );
        registry.select_complete(provider, "work").unwrap();
        return;
    }
    let (authority, material) = result.unwrap_or_else(|error| panic!("{error:#}"));
    assert_eq!(material, "synthetic-lifecycle-material");
    let busy = || {
        assert!(matches!(
            registry.begin_delete(provider, "work"),
            Err(CamError::AccountAuthorityBusy { .. })
        ))
    };
    busy();
    if matches!(
        scenario,
        "drop" | "construction" | "revoked" | "unknown" | "spawn"
    ) {
        match scenario {
            "construction" => {
                let result: Result<()> = launch(&authority)
                    .construct(|| anyhow::bail!("synthetic construction refusal"));
                assert!(result.is_err());
            }
            "revoked" => {
                handle.revoke_before_spawn().unwrap();
                assert!(launch(&authority)
                    .construct(|| -> Result<()> { panic!("revoked material was read") })
                    .is_err());
                let result: std::result::Result<ProcessOutput, _> = execute(
                    Some(&mut launch(&authority).custody()),
                    &ProcessCancellation::new(),
                    || panic!("revoked launch ran"),
                    |output| output,
                );
                assert!(result.is_err());
            }
            "unknown" => {
                launch(&authority).custody().begin_spawn().unwrap();
                launch(&authority).custody().exit_unknown();
            }
            "spawn" => {
                let result: std::result::Result<ProcessOutput, _> = execute(
                    Some(&mut launch(&authority).custody()),
                    &ProcessCancellation::new(),
                    || {
                        Err(ProcessRunError::Spawn {
                            label: "synthetic".into(),
                            command: "synthetic".into(),
                            current_dir: Path::new("/").into(),
                            source: std::io::Error::from(std::io::ErrorKind::NotFound),
                        })
                    },
                    |output| output,
                );
                assert!(result.is_err());
            }
            _ => {}
        }
        drop(authority);
        if scenario == "unknown" {
            assert_eq!(handle.snapshot().phase, LaunchPhase::ExitUnknown);
            busy();
            return;
        }
        let reason = if scenario == "spawn" {
            LaunchFinalization::SpawnFailed
        } else {
            LaunchFinalization::Refused
        };
        assert_eq!(handle.snapshot().phase, LaunchPhase::Finalized(reason));
        registry.select_complete(provider, "work").unwrap();
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let child_directory = directory.path().to_path_buf();
    let environment = BTreeMap::from([
        ("SYNTHETIC_SELECTED".to_string(), material),
        (
            "SYNTHETIC_INHERITED".to_string(),
            "synthetic-inherited-value".into(),
        ),
    ]);
    launch(&authority)
        .custody()
        .declare_inherited_environment(environment.keys());
    let cancellation = ProcessCancellation::new();
    let child_cancel = cancellation.clone();
    let runner = thread::spawn(move || {
        let result = execute(
            Some(&mut launch(&authority).custody()),
            &child_cancel,
            || {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "account_authority::selected_launch::tests::selected_lifecycle_child_fixture"])
                .env_clear().envs(environment).env("MACO_SELECTED_LIFECYCLE_CHILD", &child_directory)
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                .spawn().unwrap();
                let started = Instant::now();
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if child_cancel.is_cancelled() || started.elapsed() > Duration::from_secs(30) {
                        child.kill().unwrap();
                        break child.wait().unwrap();
                    }
                    thread::sleep(Duration::from_millis(5));
                };
                Ok(ProcessOutput {
                    status: Some(status),
                    duration: started.elapsed(),
                    timed_out: false,
                    process_tree: ProcessTreeEvidence::VerifiedEmpty(
                        ContainmentBackend::DirectChild,
                    ),
                    side_effects: SideEffectConfinementEvidence::TrustedBestEffort(
                        SideEffectConfinementProfileKind::TrustedCompatibility,
                    ),
                    stdout: Default::default(),
                    stderr: Default::default(),
                    process_error: None,
                    stdin_error: None,
                })
            },
            |output| output,
        );
        (authority, result)
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    while !directory.path().join("ready").exists() && !runner.is_finished() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        directory.path().join("ready").exists(),
        "child never reached the material barrier"
    );
    assert_eq!(handle.snapshot().phase, LaunchPhase::Running);
    busy();
    assert!(handle.revoke_before_spawn().is_err());
    if scenario == "cancel" {
        cancellation.cancel();
    } else {
        fs::write(
            directory.path().join("release.pending"),
            if scenario == "normal" { b"0" } else { b"7" },
        )
        .unwrap();
        fs::rename(
            directory.path().join("release.pending"),
            directory.path().join("release"),
        )
        .unwrap();
    }
    let (authority, output) = runner.join().unwrap();
    output.unwrap();
    let reason = match scenario {
        "normal" => LaunchFinalization::Exited,
        "cancel" => LaunchFinalization::Cancelled,
        _ => LaunchFinalization::AbnormalExit,
    };
    assert_eq!(handle.snapshot().phase, LaunchPhase::Finalized(reason));
    busy(); // The outer authority still protects report teardown after child finalization.
    let metadata = crate::secret_lifecycle::ProviderLaunchMetadata::from(handle.snapshot());
    let encoded = serde_json::to_string(&metadata).unwrap();
    assert!(encoded.contains("SYNTHETIC_INHERITED"));
    assert!(!encoded.contains("synthetic-inherited-value"));
    assert!(!encoded.contains("synthetic-lifecycle-material"));
    drop(authority);
    registry.select_complete(provider, "work").unwrap();
}
